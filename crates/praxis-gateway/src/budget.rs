//! Budget grants: the share of each pool a private policy delegates to each
//! consumer, and how much of it the consumer has used, served to it in
//! percent of the whole window.
//!
//! Providers report a window's utilization for the whole account, not per
//! caller. Each injected response carries the current reading, and the
//! rise since the previous one is charged to the consumer whose request it
//! answered, until the window resets. Use between two brokered requests,
//! such as the operator's own unbrokered use, so lands on the next one,
//! which overcounts and holds early, never late. Mistral has no window: its
//! grant is a share of a weekly list-price cap, from the spend meter.
use crate::usage::Provider;
use serde::{Deserialize, Serialize};
use std::{collections::BTreeMap, io::ErrorKind, path::Path};

const GRANT_SCHEMA: &str = "praxis-broker-grant/v1";
/// The short windows, which are unpaced; and how old a reading may be
/// before it is stale.
pub const FIVE_HOURS: u64 = 5 * 3600;
pub const WEEK: u64 = 7 * 24 * 3600;
/// How far a paced allowance runs ahead of an even pace, as a fraction of
/// the window.
const LEAD: f64 = 0.1;
/// The name of Mistral's only window in a grant.
const MISTRAL_WINDOW: &str = "spend_7d";

/// Whose a request is, as the rule that admitted it says.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, PartialOrd, Ord, Deserialize, Serialize)]
#[serde(rename_all = "lowercase")]
pub enum Consumer {
    /// The use the public board budgets.
    Public,
    /// Everything else: unproven runs, unbrokered use, and any rule that
    /// names no consumer.
    #[default]
    Private,
}

impl Consumer {
    pub fn parse(name: &str) -> Option<Self> {
        match name {
            "public" => Some(Self::Public),
            "private" => Some(Self::Private),
            _ => None,
        }
    }

    pub fn index(self) -> usize {
        self as usize
    }
}

/// What one response said of one window, for the whole account.
#[derive(Clone, Copy, Debug, PartialEq)]
pub struct Reading {
    pub used_percent: f64,
    pub resets_at: u64,
    pub window_secs: u64,
}

/// A window's latest reading and what each consumer used of it since it
/// last reset, in percent of the window.
#[derive(Clone, Debug, PartialEq)]
pub struct Attributed {
    reading: Reading,
    observed_at: u64,
    /// The gateway first read this window part-way used, so whose that use
    /// was is unknown until it resets: it keeps nothing across a restart
    /// (#35). Each consumer is charged all of it meanwhile.
    restored: bool,
    used: [f64; 2],
}

impl Attributed {
    /// The window after `reading`, taken at `now` from a response to
    /// `consumer`'s request, follows `previous`.
    pub fn charge(previous: Option<&Self>, reading: Reading, consumer: Consumer, now: u64) -> Self {
        let mut used = [0.0; 2];
        let restored = match previous {
            Some(previous) if now < previous.reading.resets_at => {
                used = previous.used;
                let rise = reading.used_percent - previous.reading.used_percent;
                used[consumer.index()] += rise.max(0.0);
                previous.restored
            }
            // Reset since the previous reading: all of it is since then.
            Some(_) => {
                used[consumer.index()] = reading.used_percent;
                false
            }
            None => {
                used = [reading.used_percent; 2];
                reading.used_percent > 0.0
            }
        };
        Self {
            reading,
            observed_at: now,
            restored,
            used,
        }
    }
}

/// The deployment's budget policy, `budget.yaml`.
#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct BudgetFile {
    /// Each consumer's share of each pool, in percent of every window.
    shares: BTreeMap<Consumer, BTreeMap<Provider, f64>>,
    /// The week's cap of Mistral's list-price spend, in USD, of which its
    /// shares are taken.
    mistral_weekly_usd: Option<f64>,
}

#[derive(Debug, PartialEq)]
pub struct Budget {
    shares: BTreeMap<Consumer, BTreeMap<Provider, f64>>,
    mistral_weekly_usd: Option<f64>,
}

/// One consumer's grant: `GET /usage/grant`.
#[derive(Debug, PartialEq, Serialize)]
pub struct Grant {
    schema: &'static str,
    consumer: Consumer,
    observed_at: u64,
    hold: bool,
    pools: BTreeMap<Provider, PoolGrant>,
}

#[derive(Debug, Default, PartialEq, Serialize)]
struct PoolGrant {
    hold: bool,
    stale: bool,
    windows: BTreeMap<&'static str, WindowGrant>,
}

#[derive(Debug, PartialEq, Serialize)]
struct WindowGrant {
    share_percent: f64,
    allowed_percent: f64,
    used_percent: f64,
    resets_at: Option<u64>,
    hold: bool,
}

/// A window of a pool, for the grant: what started it, its length, its
/// reset, and whether its reading is stale.
struct Window {
    used_percent: f64,
    start: u64,
    secs: u64,
    resets_at: Option<u64>,
    stale: bool,
}

impl Window {
    /// Paced if longer than the short windows: the share times the
    /// fraction of the window elapsed plus the lead, up to the share.
    fn grant(&self, share: f64, now: u64) -> WindowGrant {
        let allowed = if self.secs > FIVE_HOURS {
            let elapsed = now.saturating_sub(self.start) as f64 / self.secs as f64;
            share * (elapsed + LEAD).min(1.0)
        } else {
            share
        };
        let hold = self.stale || self.used_percent > allowed;
        // Figures for people; `hold` is decided before rounding.
        let round = |n: f64| (n * 100.0).round() / 100.0;
        WindowGrant {
            share_percent: share,
            allowed_percent: round(allowed),
            used_percent: round(self.used_percent),
            resets_at: self.resets_at,
            hold,
        }
    }
}

/// What a consumer spent on Mistral over the trailing week, and when the
/// spend meter began.
#[derive(Clone, Copy, Debug)]
pub struct MistralSpend {
    pub micros: u64,
    pub since: u64,
}

impl Budget {
    /// The budget in the file at `path`, or `None` if there is no such
    /// file: then nothing is granted.
    ///
    /// # Errors
    ///
    /// Returns what is wrong with a file that can't be read or isn't valid.
    pub fn load(path: &Path) -> Result<Option<Self>, String> {
        let text = match std::fs::read_to_string(path) {
            Ok(text) => text,
            Err(e) if e.kind() == ErrorKind::NotFound => return Ok(None),
            Err(e) => return Err(format!("{}: {e}", path.display())),
        };
        Self::parse(&text)
            .map(Some)
            .map_err(|e| format!("{}: {e}", path.display()))
    }

    pub(crate) fn parse(text: &str) -> Result<Self, String> {
        let file: BudgetFile = serde_yaml::from_str(text).map_err(|e| e.to_string())?;
        let mut totals = BTreeMap::<Provider, f64>::new();
        for pools in file.shares.values() {
            for (pool, share) in pools {
                if !(0.0..=100.0).contains(share) {
                    return Err(format!("{pool:?}: a share is 0 to 100 percent"));
                }
                *totals.entry(*pool).or_default() += share;
            }
        }
        // Shares that add up to more than the pool would let the consumers
        // together use more of it than there is, each within its grant.
        if let Some((pool, total)) = totals.iter().find(|(_, total)| **total > 100.0) {
            return Err(format!(
                "{pool:?}: the shares add up to {total} percent, more than the whole"
            ));
        }
        let mistral_cap = file.mistral_weekly_usd;
        if mistral_cap.is_some_and(|cap| !(cap.is_finite() && cap > 0.0)) {
            return Err("mistral_weekly_usd must be positive".to_owned());
        }
        if totals.contains_key(&Provider::Mistral) && mistral_cap.is_none() {
            return Err("a share of mistral needs mistral_weekly_usd".to_owned());
        }
        Ok(Self {
            shares: file.shares,
            mistral_weekly_usd: mistral_cap,
        })
    }

    /// `consumer`'s grant at `now`, from the windows the gateway has read
    /// and its Mistral spend, if metered. A pool it has a share of but
    /// nothing read of is left out, and holds.
    pub fn grant(
        &self,
        consumer: Consumer,
        windows: &[(Provider, &'static str, Option<&Attributed>)],
        mistral: Option<MistralSpend>,
        now: u64,
    ) -> Grant {
        let mut grant = Grant {
            schema: GRANT_SCHEMA,
            consumer,
            observed_at: now,
            hold: false,
            pools: BTreeMap::new(),
        };
        let Some(shares) = self.shares.get(&consumer) else {
            grant.hold = true;
            return grant;
        };
        for (&pool, &share) in shares {
            let mut read = Vec::new();
            if pool == Provider::Mistral {
                if let (Some(cap), Some(spend)) = (self.mistral_weekly_usd, mistral) {
                    // The trailing week has no reset: it is paced from when
                    // metering began, so it covers a whole week after one.
                    read.push((
                        MISTRAL_WINDOW,
                        Window {
                            used_percent: spend.micros as f64 / (cap * 1e6) * 100.0,
                            start: spend.since,
                            secs: WEEK,
                            resets_at: None,
                            stale: false,
                        },
                    ));
                }
            }
            for (_, name, window) in windows.iter().filter(|(p, ..)| *p == pool) {
                let Some(window) = window else {
                    continue;
                };
                let reading = window.reading;
                read.push((
                    name,
                    Window {
                        used_percent: window.used[consumer.index()],
                        start: reading.resets_at.saturating_sub(reading.window_secs),
                        secs: reading.window_secs,
                        resets_at: Some(reading.resets_at),
                        stale: window.restored
                            || now.saturating_sub(window.observed_at) > FIVE_HOURS,
                    },
                ));
            }
            if read.is_empty() {
                grant.hold = true;
                continue;
            }
            let mut pool_grant = PoolGrant::default();
            for (name, window) in read {
                let window_grant = window.grant(share, now);
                pool_grant.stale |= window.stale;
                pool_grant.hold |= window_grant.hold;
                pool_grant.windows.insert(name, window_grant);
            }
            grant.hold |= pool_grant.hold;
            grant.pools.insert(pool, pool_grant);
        }
        grant
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    const HOUR: u64 = 3600;
    /// Some hour, with a week's window ending a week later.
    const T0: u64 = 1_000_000 * HOUR;

    fn reading(used_percent: f64, resets_at: u64) -> Reading {
        Reading {
            used_percent,
            resets_at,
            window_secs: WEEK,
        }
    }

    /// Each step is a reading of one window taken at `t` from a response to
    /// `consumer`, and what each consumer has been charged after it,
    /// `[public, private]`.
    #[test]
    fn rises_are_charged_to_the_consumer_whose_response_carried_them() {
        use Consumer::{Private, Public};
        let reset = T0 + WEEK;
        let next_reset = reset + WEEK;
        #[rustfmt::skip]
        let steps = [
            ("first read, unused", T0, 0.0, reset, Public, [0.0, 0.0]),
            ("public uses 5", T0 + 1, 5.0, reset, Public, [5.0, 0.0]),
            ("private uses 3", T0 + 2, 8.0, reset, Private, [5.0, 3.0]),
            ("public uses 2", T0 + 3, 10.0, reset, Public, [7.0, 3.0]),
            // 4 of unbrokered use, which no response reports, then 1 of
            // public's: public is charged both.
            ("a gap of unbrokered use", T0 + 5, 15.0, reset, Public, [12.0, 3.0]),
            // A reading lower than the last charges nobody.
            ("lower", T0 + 6, 14.5, reset, Private, [12.0, 3.0]),
            ("private again", T0 + 7, 16.5, reset, Private, [12.0, 5.0]),
            // After the reset, what is used is all the requester's.
            ("reset", reset, 1.0, next_reset, Private, [0.0, 1.0]),
            ("public after the reset", reset + 1, 3.0, next_reset, Public, [2.0, 1.0]),
        ];
        let mut window: Option<Attributed> = None;
        for (name, t, used, resets_at, consumer, want) in steps {
            let next = Attributed::charge(window.as_ref(), reading(used, resets_at), consumer, t);
            assert_eq!((next.used, next.restored), (want, false), "{name}");
            window = Some(next);
        }
    }

    #[test]
    fn a_window_first_read_part_way_is_restored_until_it_resets() {
        let reset = T0 + WEEK;
        let first = Attributed::charge(None, reading(20.0, reset), Consumer::Private, T0);
        // Each consumer is charged all of it, and it holds.
        assert_eq!((first.used, first.restored), ([20.0; 2], true));
        let later =
            Attributed::charge(Some(&first), reading(25.0, reset), Consumer::Public, T0 + 1);
        assert_eq!((later.used, later.restored), ([25.0, 20.0], true));
        let after = Attributed::charge(
            Some(&later),
            reading(1.0, reset + WEEK),
            Consumer::Public,
            reset,
        );
        assert_eq!((after.used, after.restored), ([1.0, 0.0], false));
    }

    fn budget() -> Budget {
        Budget::parse(
            "shares:\n  public: {anthropic: 70, codex: 70, mistral: 70}\n  private: {anthropic: 30, codex: 30, mistral: 30}\nmistral_weekly_usd: 100\n",
        )
        .unwrap()
    }

    #[test]
    fn budget_files_are_validated() {
        let cases = [
            ("shares: {public: {anthropic: 70}}", true),
            ("shares: {}", true),
            (
                "shares: {public: {mistral: 50}}\nmistral_weekly_usd: 20",
                true,
            ),
            ("shares: {public: {mistral: 50}}", false),
            (
                "shares: {public: {mistral: 50}}\nmistral_weekly_usd: 0",
                false,
            ),
            ("shares: {public: {anthropic: 101}}", false),
            ("shares: {public: {anthropic: -1}}", false),
            ("shares: {public: {anthropic: .nan}}", false),
            (
                "shares: {public: {anthropic: 70}, private: {anthropic: 31}}",
                false,
            ),
            ("shares: {public: {gemini: 70}}", false),
            ("shares: {board: {anthropic: 70}}", false),
            ("shares: {public: {anthropic: 70}}\nlead: 5", false),
            ("{}", false),
        ];
        for (text, ok) in cases {
            assert_eq!(
                Budget::parse(text).is_ok(),
                ok,
                "{text}: {:?}",
                Budget::parse(text)
            );
        }
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("budget.yaml");
        assert_eq!(Budget::load(&path), Ok(None));
        std::fs::write(&path, "shares: [").unwrap();
        assert!(Budget::load(&path).unwrap_err().contains("budget.yaml"));
    }

    /// A week's window as read at `observed_at` and charged `used`, and
    /// started at `T0`.
    fn week(used: [f64; 2], observed_at: u64, restored: bool) -> Attributed {
        Attributed {
            reading: reading(used[0] + used[1], T0 + WEEK),
            observed_at,
            restored,
            used,
        }
    }

    fn five_hours(used: [f64; 2], observed_at: u64) -> Attributed {
        Attributed {
            reading: Reading {
                used_percent: used[0] + used[1],
                resets_at: observed_at + HOUR,
                window_secs: FIVE_HOURS,
            },
            observed_at,
            restored: false,
            used,
        }
    }

    fn anthropic_grant(window: &Attributed, now: u64) -> serde_json::Value {
        let grant = budget().grant(
            Consumer::Public,
            &[(Provider::Anthropic, "unified_7d", Some(window))],
            None,
            now,
        );
        serde_json::to_value(&grant.pools[&Provider::Anthropic].windows["unified_7d"]).unwrap()
    }

    /// The allowance of a week's window at its start, part-way and at its
    /// end: the share times the fraction elapsed plus a tenth, up to the
    /// share.
    #[test]
    fn a_weeks_window_is_paced_with_a_lead() {
        let cases = [
            ("start", 0, 7.0),
            ("a tenth", WEEK / 10, 14.0),
            ("the sample's", WEEK * 35 / 100, 31.5),
            ("middle", WEEK / 2, 42.0),
            ("past the lead's end", WEEK * 95 / 100, 70.0),
            ("end", WEEK, 70.0),
            ("after", 2 * WEEK, 70.0),
        ];
        for (name, elapsed, allowed) in cases {
            let now = T0 + elapsed;
            let under = anthropic_grant(&week([allowed - 0.5, 0.0], now, false), now);
            assert_eq!(under["allowed_percent"], allowed, "{name}");
            assert_eq!(under["hold"], false, "{name}");
            let over = anthropic_grant(&week([allowed + 0.5, 0.0], now, false), now);
            assert_eq!(over["hold"], true, "{name}");
        }
    }

    #[test]
    fn stale_and_restored_readings_hold() {
        let now = T0 + WEEK / 2;
        let cases = [
            ("fresh", week([1.0, 0.0], now, false), false),
            (
                "five hours old",
                week([1.0, 0.0], now - FIVE_HOURS, false),
                false,
            ),
            ("older", week([1.0, 0.0], now - FIVE_HOURS - 1, false), true),
            ("restored", week([1.0, 0.0], now, true), true),
        ];
        for (name, window, hold) in cases {
            let grant = budget().grant(
                Consumer::Public,
                &[
                    (Provider::Anthropic, "unified_7d", Some(&window)),
                    (
                        Provider::Anthropic,
                        "unified_5h",
                        Some(&five_hours([1.0, 0.0], now)),
                    ),
                ],
                None,
                now,
            );
            let pool = &grant.pools[&Provider::Anthropic];
            assert_eq!(
                (pool.stale, pool.hold, grant.hold),
                (hold, hold, true),
                "{name}"
            );
            assert_eq!(pool.windows["unified_7d"].hold, hold, "{name}");
            assert!(!pool.windows["unified_5h"].hold, "{name}");
        }
    }

    #[test]
    fn a_grant_has_its_consumers_figures_and_no_one_elses() {
        let now = T0 + WEEK * 35 / 100;
        // The other consumer's figures, all distinct from the public's.
        let anthropic_7d = week([18.2, 61.3], now, false);
        let anthropic_5h = five_hours([12.0, 23.4], now);
        let codex = five_hours([2.0, 44.4], now);
        let windows = [
            (Provider::Anthropic, "unified_7d", Some(&anthropic_7d)),
            (Provider::Anthropic, "unified_5h", Some(&anthropic_5h)),
            (Provider::Codex, "primary", Some(&codex)),
            (Provider::Codex, "secondary", None),
        ];
        let mistral = MistralSpend {
            micros: 400_000,
            since: T0,
        };
        let grant = budget().grant(Consumer::Public, &windows, Some(mistral), now);
        let window = |share: f64, allowed: f64, used: f64, resets_at: Option<u64>| json!({"share_percent": share, "allowed_percent": allowed, "used_percent": used, "resets_at": resets_at, "hold": false});
        let pool = |windows| json!({"hold": false, "stale": false, "windows": windows});
        assert_eq!(
            serde_json::to_value(&grant).unwrap(),
            json!({
                "schema": "praxis-broker-grant/v1",
                "consumer": "public",
                "observed_at": now,
                "hold": false,
                "pools": {
                    "anthropic": pool(json!({
                        "unified_7d": window(70.0, 31.5, 18.2, Some(T0 + WEEK)),
                        "unified_5h": window(70.0, 70.0, 12.0, Some(now + HOUR)),
                    })),
                    "codex": pool(json!({"primary": window(70.0, 70.0, 2.0, Some(now + HOUR))})),
                    "mistral": pool(json!({"spend_7d": window(70.0, 31.5, 0.4, None)})),
                },
            })
        );
        let text = serde_json::to_string(&grant).unwrap();
        for other in ["61.3", "23.4", "44.4", "30.0"] {
            assert!(!text.contains(other), "{other} in {text}");
        }
    }

    #[test]
    fn a_consumer_missing_from_the_policy_or_a_pool_unread_holds() {
        let now = T0;
        let window = week([0.0, 0.0], now, false);
        let windows = [(Provider::Anthropic, "unified_7d", Some(&window))];
        let only_private = Budget::parse("shares: {private: {anthropic: 100}}").unwrap();
        let grant = only_private.grant(Consumer::Public, &windows, None, now);
        assert!(grant.hold);
        assert!(grant.pools.is_empty());
        // Codex and Mistral (no spend metered) unread: left out, and held.
        let grant = budget().grant(Consumer::Public, &windows, None, now);
        assert!(grant.hold);
        assert_eq!(
            grant.pools.keys().collect::<Vec<_>>(),
            [&Provider::Anthropic]
        );
        assert!(!grant.pools[&Provider::Anthropic].hold);
    }
}
