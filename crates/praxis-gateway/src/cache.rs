//! Prompt-cache hit rates: the share of injected requests' input that the
//! provider read from its prompt cache (cached ÷ input), by provider and
//! model over the last hour and day, and for the busiest sessions.
//!
//! A session is the requests whose body names the same `prompt_cache_key`,
//! as Codex sends it. It is known only by the first 12 hex digits of the
//! key's SHA-256, the hash credential-proxy logs, so the two can be matched
//! and neither holds the key. Every count here is bounded: at most
//! `MAX_ROUTES` provider and model pairs, each a day of five-minute slots,
//! and `MAX_SESSIONS` sessions, each forgotten a day after its last request.
use crate::{runs::Usage, usage::Provider};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::{
    borrow::Cow,
    collections::{BTreeMap, HashMap, VecDeque},
};
use tracing::warn;

const SLOT_SECS: u64 = 300;
const HOUR_SLOTS: u64 = 3600 / SLOT_SECS;
const DAY_SLOTS: u64 = 24 * HOUR_SLOTS;
/// Provider and model pairs counted apart; the rest are counted together
/// under `OTHER_MODEL`, as is a model with a longer name than `MAX_MODEL`.
const MAX_ROUTES: usize = 64;
const MAX_MODEL: usize = 64;
const OTHER_MODEL: &str = "(other)";
const MAX_SESSIONS: usize = 1024;
/// How long a session is remembered after its last request.
const SESSION_SECS: u64 = 24 * 3600;
/// Sessions listed, those with the most requests.
const HOTTEST: usize = 10;
/// The request from which on a session's hit rate is judged.
const WARN_FROM_REQUEST: u64 = 3;
/// Bytes of the key's SHA-256 a session is named by, as credential-proxy
/// logs it.
const KEY_HASH_BYTES: usize = 6;
/// The longest key hashed, as credential-proxy's `MAX_TOKEN`.
const MAX_KEY: usize = 64;

/// The hash of the top-level `prompt_cache_key` of a JSON object request
/// body, if that is a key credential-proxy hashes too: 1 to `MAX_KEY` ASCII
/// letters, digits, `-`, `_`, `.` or `:`, such as the UUID Codex sends.
pub(crate) fn key_hash(body: &[u8]) -> Option<String> {
    #[derive(Deserialize)]
    struct Keyed<'a> {
        #[serde(borrow)]
        prompt_cache_key: Option<Cow<'a, str>>,
    }
    // A struct also deserializes from an array, by position.
    if body.trim_ascii_start().first() != Some(&b'{') {
        return None;
    }
    let key = serde_json::from_slice::<Keyed<'_>>(body)
        .ok()?
        .prompt_cache_key
        .filter(|key| {
            (1..=MAX_KEY).contains(&key.len())
                && key
                    .bytes()
                    .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'-' | b'_' | b'.' | b':'))
        })?;
    Some(hex::encode(
        &Sha256::digest(key.as_bytes())[..KEY_HASH_BYTES],
    ))
}

/// Responses with usage, and their input. `input` includes `cached`.
#[derive(Clone, Copy, Debug, Default, PartialEq)]
struct Tally {
    requests: u64,
    input: u64,
    cached: u64,
}

impl Tally {
    fn of(usage: &Usage) -> Self {
        let cached = usage.tokens.cache_read;
        Self {
            requests: 1,
            input: usage.tokens.input.saturating_add(cached),
            cached,
        }
    }

    fn add(&mut self, other: Tally) {
        self.requests = self.requests.saturating_add(other.requests);
        self.input = self.input.saturating_add(other.input);
        self.cached = self.cached.saturating_add(other.cached);
    }

    fn below_half(&self) -> bool {
        self.cached.saturating_mul(2) < self.input
    }
}

#[derive(Clone, Debug, PartialEq, Serialize)]
struct Rate {
    requests: u64,
    input: u64,
    cached: u64,
    /// `cached ÷ input`, to four places; null without input.
    hit_rate: Option<f64>,
}

impl From<Tally> for Rate {
    fn from(tally: Tally) -> Self {
        Self {
            requests: tally.requests,
            input: tally.input,
            cached: tally.cached,
            hit_rate: (tally.input > 0)
                .then(|| (tally.cached as f64 / tally.input as f64 * 1e4).round() / 1e4),
        }
    }
}

/// A day of five-minute slots, oldest first, each the slot's number since
/// the Unix epoch and what it counted.
#[derive(Debug, Default)]
struct Day(VecDeque<(u64, Tally)>);

impl Day {
    fn add(&mut self, slot: u64, tally: Tally) {
        while self.0.front().is_some_and(|(s, _)| s + DAY_SLOTS <= slot) {
            self.0.pop_front();
        }
        // A clock that steps back counts in the latest slot, as spend does.
        match self.0.back_mut() {
            Some((last, sum)) if *last >= slot => sum.add(tally),
            _ => self.0.push_back((slot, tally)),
        }
    }

    /// What the `slots` ending with `slot` counted.
    fn sum(&self, slot: u64, slots: u64) -> Tally {
        let mut sum = Tally::default();
        for (_, tally) in self.0.iter().filter(|(s, _)| s + slots > slot) {
            sum.add(*tally);
        }
        sum
    }
}

#[derive(Debug)]
struct Session {
    requests: u64,
    first_input: u64,
    /// From the second request on, once the first has warmed the cache.
    later: Tally,
    last_seen: u64,
    warned: bool,
}

#[derive(Debug)]
pub(crate) struct CacheStats {
    /// Unix seconds when counting began.
    since: u64,
    routes: BTreeMap<(Provider, String), Day>,
    sessions: HashMap<(Provider, String), Session>,
}

#[derive(Clone, Debug, PartialEq, Serialize)]
struct RouteView {
    provider: Provider,
    model: String,
    last_hour: Rate,
    last_day: Rate,
}

#[derive(Clone, Debug, PartialEq, Serialize)]
struct SessionView {
    cache_key: String,
    provider: Provider,
    requests: u64,
    first_input: u64,
    later: Rate,
    last_seen: u64,
}

#[derive(Clone, Debug, PartialEq, Serialize)]
pub(crate) struct CacheView {
    since: u64,
    routes: Vec<RouteView>,
    sessions: Vec<SessionView>,
}

impl CacheStats {
    pub(crate) fn new(now: u64) -> Self {
        Self {
            since: now,
            routes: BTreeMap::new(),
            sessions: HashMap::new(),
        }
    }

    /// Count a response from `provider` with `usage`, to the session
    /// `cache_key` names if there is one. Logs a warning, once per session,
    /// when from its third request on less than half of its input since
    /// the first was cached; returns whether it did.
    pub(crate) fn settle(
        &mut self,
        provider: Provider,
        cache_key: Option<&str>,
        usage: &Usage,
        now: u64,
    ) -> bool {
        let slot = now / SLOT_SECS;
        let tally = Tally::of(usage);
        let model = usage
            .model
            .as_deref()
            .filter(|model| model.len() <= MAX_MODEL)
            .unwrap_or(OTHER_MODEL);
        let mut route = (provider, model.to_owned());
        if !self.routes.contains_key(&route) {
            if self.routes.len() >= MAX_ROUTES {
                self.routes
                    .retain(|_, day| day.sum(slot, DAY_SLOTS).requests > 0);
            }
            if self.routes.len() >= MAX_ROUTES {
                route.1 = OTHER_MODEL.to_owned();
            }
        }
        self.routes.entry(route).or_default().add(slot, tally);

        let Some(cache_key) = cache_key else {
            return false;
        };
        let key = (provider, cache_key.to_owned());
        if !self.sessions.contains_key(&key) && self.sessions.len() >= MAX_SESSIONS {
            self.sessions
                .retain(|_, session| session.last_seen + SESSION_SECS > now);
            if self.sessions.len() >= MAX_SESSIONS
                && let Some(oldest) = self
                    .sessions
                    .iter()
                    .min_by_key(|(_, session)| session.last_seen)
                    .map(|(key, _)| key.clone())
            {
                self.sessions.remove(&oldest);
            }
        }
        let session = self.sessions.entry(key).or_insert(Session {
            requests: 0,
            first_input: tally.input,
            later: Tally::default(),
            last_seen: now,
            warned: false,
        });
        if session.requests > 0 {
            session.later.add(tally);
        }
        session.requests = session.requests.saturating_add(1);
        session.last_seen = session.last_seen.max(now);
        if session.warned || session.requests < WARN_FROM_REQUEST || !session.later.below_half() {
            return false;
        }
        session.warned = true;
        warn!(
            provider = provider.as_str(),
            cache_key,
            requests = session.requests,
            first_input = session.first_input,
            later_input = session.later.input,
            later_cached = session.later.cached,
            "prompt cache: under half of a session's input after its first request was cached"
        );
        true
    }

    pub(crate) fn view(&self, now: u64) -> CacheView {
        let slot = now / SLOT_SECS;
        let routes = self
            .routes
            .iter()
            .map(|((provider, model), day)| RouteView {
                provider: *provider,
                model: model.clone(),
                last_hour: day.sum(slot, HOUR_SLOTS).into(),
                last_day: day.sum(slot, DAY_SLOTS).into(),
            })
            .filter(|route| route.last_day.requests > 0)
            .collect();
        let mut sessions: Vec<_> = self
            .sessions
            .iter()
            .filter(|(_, session)| session.last_seen + SESSION_SECS > now)
            .collect();
        sessions.sort_by(|(a_key, a), (b_key, b)| {
            (b.requests, b.last_seen, a_key).cmp(&(a.requests, a.last_seen, b_key))
        });
        let sessions = sessions
            .into_iter()
            .take(HOTTEST)
            .map(|((provider, cache_key), session)| SessionView {
                cache_key: cache_key.clone(),
                provider: *provider,
                requests: session.requests,
                first_input: session.first_input,
                later: session.later.into(),
                last_seen: session.last_seen,
            })
            .collect();
        CacheView {
            since: self.since,
            routes,
            sessions,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::runs::Tokens;
    use serde_json::json;

    const NOW: u64 = 1_800_000_000;

    fn usage(model: &str, uncached: u64, cached: u64) -> Usage {
        Usage {
            tokens: Tokens {
                input: uncached,
                cache_read: cached,
                ..Tokens::default()
            },
            model: Some(model.to_owned()),
            cache_write: 0,
        }
    }

    fn view(stats: &CacheStats, now: u64) -> serde_json::Value {
        serde_json::to_value(stats.view(now)).unwrap()
    }

    #[test]
    fn only_a_string_key_at_the_top_is_hashed_as_credential_proxy_logs_it() {
        // credential-proxy's `upstream usage` line names this key so.
        assert_eq!(
            key_hash(br#"{"model":"m","prompt_cache_key":"0f8a3c52-7d14-4b6e-9a21-c5e3d8f07b49"}"#)
                .unwrap(),
            hex::encode(&Sha256::digest(b"0f8a3c52-7d14-4b6e-9a21-c5e3d8f07b49")[..6])
        );
        for body in [
            &br#"{"model":"m"}"#[..],
            br#"{"prompt_cache_key":""}"#,
            br#"{"prompt_cache_key":null}"#,
            br#"{"prompt_cache_key":42}"#,
            br#"{"prompt_cache_key":"has space"}"#,
            br#"{"prompt_cache_key":"user@example.com"}"#,
            br#"{"input":{"prompt_cache_key":"nested"}}"#,
            br#"["prompt_cache_key"]"#,
            b"not json",
        ] {
            assert_eq!(key_hash(body), None, "{}", String::from_utf8_lossy(body));
        }
        let key = |key: &str| key_hash(json!({ "prompt_cache_key": key }).to_string().as_bytes());
        assert!(key(&"k".repeat(MAX_KEY)).is_some());
        assert_eq!(key(&"k".repeat(MAX_KEY + 1)), None);
    }

    #[test]
    fn routes_are_rated_over_the_last_hour_and_day() {
        let mut stats = CacheStats::new(NOW);
        stats.settle(Provider::Codex, None, &usage("gpt", 60, 40), NOW - 2 * 3600);
        stats.settle(Provider::Codex, None, &usage("gpt", 10, 90), NOW - 60);
        stats.settle(Provider::Anthropic, None, &usage("claude", 0, 0), NOW);
        stats.settle(Provider::Codex, None, &usage("old", 1, 0), NOW - 25 * 3600);
        assert_eq!(
            view(&stats, NOW)["routes"],
            json!([
                {"provider": "anthropic", "model": "claude",
                 "last_hour": {"requests": 1, "input": 0, "cached": 0, "hit_rate": null},
                 "last_day": {"requests": 1, "input": 0, "cached": 0, "hit_rate": null}},
                {"provider": "codex", "model": "gpt",
                 "last_hour": {"requests": 1, "input": 100, "cached": 90, "hit_rate": 0.9},
                 "last_day": {"requests": 2, "input": 200, "cached": 130, "hit_rate": 0.65}},
            ])
        );
    }

    #[test]
    fn models_past_the_bound_are_counted_together() {
        let mut stats = CacheStats::new(NOW);
        for i in 0..MAX_ROUTES + 3 {
            stats.settle(Provider::Mistral, None, &usage(&format!("m{i}"), 1, 0), NOW);
        }
        stats.settle(
            Provider::Mistral,
            None,
            &usage(&"x".repeat(MAX_MODEL + 1), 1, 0),
            NOW,
        );
        assert_eq!(stats.routes.len(), MAX_ROUTES + 1);
        let other = &stats.routes[&(Provider::Mistral, OTHER_MODEL.to_owned())];
        assert_eq!(other.sum(NOW / SLOT_SECS, DAY_SLOTS).requests, 4);
        // Once the day has passed, new models take the place of old ones.
        let later = NOW + 24 * 3600;
        stats.settle(Provider::Mistral, None, &usage("new", 1, 0), later);
        assert!(
            stats
                .routes
                .contains_key(&(Provider::Mistral, "new".to_owned()))
        );
        assert_eq!(view(&stats, later)["routes"].as_array().unwrap().len(), 1);
    }

    #[test]
    fn a_session_is_rated_from_its_second_request_and_warned_of_once() {
        let mut stats = CacheStats::new(NOW);
        let cold = usage("gpt", 1000, 0);
        assert!(!stats.settle(Provider::Codex, Some("aaaa"), &cold, NOW));
        assert!(!stats.settle(Provider::Codex, Some("aaaa"), &usage("gpt", 700, 300), NOW));
        // The third request leaves the hit rate since the first at 40%.
        assert!(stats.settle(Provider::Codex, Some("aaaa"), &usage("gpt", 500, 500), NOW));
        assert!(!stats.settle(Provider::Codex, Some("aaaa"), &cold, NOW));
        // Another session, well cached, is never warned of.
        for _ in 0..3 {
            assert!(!stats.settle(
                Provider::Codex,
                Some("bbbb"),
                &usage("gpt", 100, 900),
                NOW + 1
            ));
        }
        // Nor is a session whose rate falls below half only after its third.
        let mut good = CacheStats::new(NOW);
        for cached in [0, 900, 900] {
            assert!(!good.settle(
                Provider::Codex,
                Some("cccc"),
                &usage("gpt", 1000 - cached, cached),
                NOW
            ));
        }
        assert!(good.settle(Provider::Codex, Some("cccc"), &usage("gpt", 3000, 0), NOW));
        assert_eq!(
            view(&stats, NOW + 1)["sessions"],
            json!([
                {"cache_key": "aaaa", "provider": "codex", "requests": 4, "first_input": 1000,
                 "later": {"requests": 3, "input": 3000, "cached": 800, "hit_rate": 0.2667},
                 "last_seen": NOW},
                {"cache_key": "bbbb", "provider": "codex", "requests": 3, "first_input": 1000,
                 "later": {"requests": 2, "input": 2000, "cached": 1800, "hit_rate": 0.9},
                 "last_seen": NOW + 1},
            ])
        );
    }

    #[test]
    fn sessions_are_bounded_and_only_the_hottest_listed() {
        let mut stats = CacheStats::new(NOW);
        for i in 0..MAX_SESSIONS as u64 + 5 {
            let key = format!("{i:012x}");
            let requests = if i < HOTTEST as u64 + 2 { 2 } else { 1 };
            for _ in 0..requests {
                stats.settle(Provider::Codex, Some(&key), &usage("gpt", 1, 0), NOW + i);
            }
        }
        assert_eq!(stats.sessions.len(), MAX_SESSIONS);
        // The least recently seen made room.
        assert!(
            !stats
                .sessions
                .contains_key(&(Provider::Codex, format!("{:012x}", 0)))
        );
        let listed = view(&stats, NOW + 2000)["sessions"].clone();
        let keys: Vec<_> = listed
            .as_array()
            .unwrap()
            .iter()
            .map(|s| s["cache_key"].as_str().unwrap().to_owned())
            .collect();
        // Two requests each, the latest first.
        let expected: Vec<_> = (5..HOTTEST as u64 + 2)
            .rev()
            .map(|i| format!("{i:012x}"))
            .collect();
        assert_eq!(keys[..expected.len()], expected[..]);
        assert_eq!(keys.len(), HOTTEST);
        // A day after their last request, sessions are no longer listed.
        assert_eq!(
            view(&stats, NOW + 2000 + SESSION_SECS)["sessions"],
            json!([])
        );
    }
}
