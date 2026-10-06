//! Bounded broker totals and latest subscription-window response headers.
use crate::runs::{Tokens, Usage};
use http::HeaderMap;
use serde::Serialize;
use std::{
    collections::HashMap,
    sync::{Arc, LazyLock, Mutex, PoisonError},
    time::{SystemTime, UNIX_EPOCH},
};

#[derive(Clone, Copy)]
pub(crate) enum Provider {
    Anthropic,
    Codex,
}

impl Provider {
    pub(crate) fn for_cluster(cluster: Option<&str>) -> Option<Self> {
        match cluster? {
            "anthropic" => Some(Self::Anthropic),
            "inference-backend" => Some(Self::Codex),
            _ => None,
        }
    }
}

#[derive(Clone, Default, Serialize)]
struct Counts {
    requests: u64,
    unmetered: u64,
    tokens: Tokens,
}

#[derive(Clone, Copy, Debug, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
enum Status {
    Allowed,
    AllowedWarning,
    Rejected,
}

#[derive(Clone, Debug, PartialEq, Serialize)]
struct AnthropicWindow {
    utilization: Option<f64>,
    reset: Option<u64>,
    status: Option<Status>,
    observed_at: u64,
}

#[derive(Clone, Debug, PartialEq, Serialize)]
struct CodexWindow {
    used_percent: Option<f64>,
    window_minutes: Option<u64>,
    reset_after_seconds: Option<u64>,
    observed_at: u64,
}

#[derive(Clone, Default, Serialize)]
struct Anthropic {
    counts: Counts,
    unified_5h: Option<AnthropicWindow>,
    unified_7d: Option<AnthropicWindow>,
}

#[derive(Clone, Default, Serialize)]
struct Codex {
    counts: Counts,
    primary: Option<CodexWindow>,
    secondary: Option<CodexWindow>,
}

#[derive(Clone, Serialize)]
pub(crate) struct Snapshot {
    schema: &'static str,
    started_at: u64,
    anthropic: Anthropic,
    codex: Codex,
}

impl Default for Snapshot {
    fn default() -> Self {
        Self {
            schema: "praxis-broker-usage/v1",
            started_at: unix_time(),
            anthropic: Anthropic::default(),
            codex: Codex::default(),
        }
    }
}

#[derive(Default)]
pub(crate) struct BrokerUsage(Mutex<Snapshot>);

// Like the run registry, configuration reloads retain the named state. Each
// registry has exactly two counters and four window slots, never per-client keys.
static REGISTRIES: LazyLock<Mutex<HashMap<String, Arc<BrokerUsage>>>> =
    LazyLock::new(Mutex::default);

fn unix_time() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs()
}

impl BrokerUsage {
    pub(crate) fn named(name: &str) -> Arc<Self> {
        Arc::clone(
            REGISTRIES
                .lock()
                .unwrap_or_else(PoisonError::into_inner)
                .entry(name.to_owned())
                .or_default(),
        )
    }

    pub(crate) fn snapshot(&self) -> Snapshot {
        self.0
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .clone()
    }

    pub(crate) fn settle(&self, provider: Provider, usage: Option<&Usage>, success: bool) {
        let mut state = self.0.lock().unwrap_or_else(PoisonError::into_inner);
        let counts = match provider {
            Provider::Anthropic => &mut state.anthropic.counts,
            Provider::Codex => &mut state.codex.counts,
        };
        if let Some(usage) = usage {
            counts.requests = counts.requests.saturating_add(1);
            counts.tokens.add(&usage.tokens);
        } else if success {
            counts.unmetered = counts.unmetered.saturating_add(1);
        }
    }

    pub(crate) fn capture(&self, provider: Provider, headers: &HeaderMap) {
        self.capture_at(provider, headers, unix_time());
    }

    fn capture_at(&self, provider: Provider, headers: &HeaderMap, now: u64) {
        let mut state = self.0.lock().unwrap_or_else(PoisonError::into_inner);
        match provider {
            Provider::Anthropic => {
                if let Some(window) = anthropic_window(headers, "5h", now) {
                    state.anthropic.unified_5h = Some(window);
                }
                if let Some(window) = anthropic_window(headers, "7d", now) {
                    state.anthropic.unified_7d = Some(window);
                }
            }
            Provider::Codex => {
                let Codex {
                    primary, secondary, ..
                } = &mut state.codex;
                for (slot, name) in [(primary, "primary"), (secondary, "secondary")] {
                    match codex_window(headers, name, now) {
                        // A window the plan does not have comes as zeros.
                        Some(window) if window.window_minutes == Some(0) => *slot = None,
                        Some(window) => *slot = Some(window),
                        None => {}
                    }
                }
            }
        }
    }
}

fn text<'a>(headers: &'a HeaderMap, name: &str) -> Option<&'a str> {
    let mut values = headers.get_all(name).iter();
    let value = values.next()?;
    if values.next().is_some() {
        return None;
    }
    value.to_str().ok()
}

fn number<T: std::str::FromStr>(headers: &HeaderMap, name: &str) -> Option<T> {
    text(headers, name)?.parse().ok()
}

fn percent(headers: &HeaderMap, name: &str, max: f64) -> Option<f64> {
    number::<f64>(headers, name).filter(|n| n.is_finite() && (0.0..=max).contains(n))
}

fn anthropic_window(headers: &HeaderMap, window: &str, now: u64) -> Option<AnthropicWindow> {
    let prefix = format!("anthropic-ratelimit-unified-{window}");
    let utilization = percent(headers, &format!("{prefix}-utilization"), 1.0);
    let reset = number(headers, &format!("{prefix}-reset"));
    let status = match text(headers, &format!("{prefix}-status")) {
        Some("allowed") => Some(Status::Allowed),
        Some("allowed_warning") => Some(Status::AllowedWarning),
        Some("rejected") => Some(Status::Rejected),
        _ => None,
    };
    (utilization.is_some() || reset.is_some() || status.is_some()).then_some(AnthropicWindow {
        utilization,
        reset,
        status,
        observed_at: now,
    })
}

fn codex_window(headers: &HeaderMap, window: &str, now: u64) -> Option<CodexWindow> {
    let prefix = format!("x-codex-{window}");
    let used_percent = percent(headers, &format!("{prefix}-used-percent"), 100.0);
    let window_minutes = number(headers, &format!("{prefix}-window-minutes"));
    let reset_after_seconds = number(headers, &format!("{prefix}-reset-after-seconds"));
    (used_percent.is_some() || window_minutes.is_some() || reset_after_seconds.is_some()).then_some(
        CodexWindow {
            used_percent,
            window_minutes,
            reset_after_seconds,
            observed_at: now,
        },
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    fn fixture(provider: &str) -> HeaderMap {
        let fixtures: serde_json::Value =
            serde_json::from_str(include_str!("../testdata/usage-headers.json")).unwrap();
        fixtures[provider]
            .as_object()
            .unwrap()
            .iter()
            .map(|(name, value)| {
                (
                    http::HeaderName::try_from(name.as_str()).unwrap(),
                    http::HeaderValue::try_from(value.as_str().unwrap()).unwrap(),
                )
            })
            .collect()
    }

    #[test]
    fn fixtures_capture_only_typed_windows_and_update_independently() {
        let usage = BrokerUsage::default();
        usage.capture_at(Provider::Anthropic, &fixture("anthropic"), 10);
        usage.capture_at(Provider::Codex, &fixture("codex"), 20);
        let snapshot = usage.snapshot();
        let five = snapshot.anthropic.unified_5h.unwrap();
        assert_eq!(five.utilization, Some(0.42));
        assert_eq!(five.reset, Some(1791115200));
        assert_eq!(five.status, Some(Status::Allowed));
        assert_eq!(five.observed_at, 10);
        assert_eq!(
            snapshot.anthropic.unified_7d.unwrap().status,
            Some(Status::AllowedWarning)
        );
        let primary = snapshot.codex.primary.unwrap();
        assert_eq!(primary.used_percent, Some(42.5));
        assert_eq!(primary.window_minutes, Some(300));
        assert_eq!(primary.reset_after_seconds, Some(1200));
        assert_eq!(primary.observed_at, 20);
        let secondary = snapshot.codex.secondary.unwrap();
        assert_eq!(secondary.window_minutes, Some(10080));
        assert_eq!(secondary.reset_after_seconds, Some(345600));
        let serialized = serde_json::to_string(&usage.snapshot()).unwrap();
        assert!(!serialized.contains("SYNTHETIC"));
        let mut update = HeaderMap::new();
        update.insert("x-codex-primary-used-percent", "55".parse().unwrap());
        usage.capture_at(Provider::Codex, &update, 30);
        assert_eq!(usage.snapshot().codex.primary.unwrap().observed_at, 30);
        assert_eq!(usage.snapshot().codex.secondary.unwrap(), secondary);
        usage.capture_at(Provider::Codex, &HeaderMap::new(), 40);
        assert_eq!(usage.snapshot().codex.primary.unwrap().observed_at, 30);
        // As chatgpt.com answered on 2026-10-05, for a plan whose only
        // window is the weekly one.
        let mut weekly_only = HeaderMap::new();
        for (name, value) in [
            ("x-codex-primary-used-percent", "19"),
            ("x-codex-primary-window-minutes", "10080"),
            ("x-codex-primary-reset-after-seconds", "575839"),
            ("x-codex-secondary-used-percent", "0"),
            ("x-codex-secondary-window-minutes", "0"),
            ("x-codex-secondary-reset-after-seconds", "0"),
        ] {
            weekly_only.insert(name, value.parse().unwrap());
        }
        usage.capture_at(Provider::Codex, &weekly_only, 50);
        let codex = usage.snapshot().codex;
        assert_eq!(codex.primary.unwrap().window_minutes, Some(10080));
        assert_eq!(codex.secondary, None);
    }

    #[test]
    fn malformed_nonfinite_out_of_range_and_duplicate_values_are_ignored() {
        for value in ["NaN", "inf", "-1", "101", "secret"] {
            let mut headers = HeaderMap::new();
            headers.insert("x-codex-primary-used-percent", value.parse().unwrap());
            headers.insert(
                "anthropic-ratelimit-unified-5h-utilization",
                value.parse().unwrap(),
            );
            headers.insert(
                "anthropic-ratelimit-unified-5h-status",
                value.parse().unwrap(),
            );
            headers.insert("x-codex-primary-window-minutes", "-1".parse().unwrap());
            assert!(codex_window(&headers, "primary", 1).is_none());
            assert!(anthropic_window(&headers, "5h", 1).is_none());
        }
        let mut headers = HeaderMap::new();
        headers.append("x-codex-primary-used-percent", "1".parse().unwrap());
        headers.append("x-codex-primary-used-percent", "2".parse().unwrap());
        assert!(codex_window(&headers, "primary", 1).is_none());
    }

    #[test]
    fn named_state_survives_reload_and_counts_saturate() {
        let usage = BrokerUsage::named("usage-unit-test");
        let reported = Usage {
            tokens: Tokens {
                total: u64::MAX,
                ..Tokens::default()
            },
            model: None,
        };
        usage.settle(Provider::Codex, Some(&reported), true);
        usage.settle(Provider::Codex, Some(&reported), true);
        usage.settle(Provider::Codex, None, true);
        usage.settle(Provider::Codex, None, false);
        let snapshot = BrokerUsage::named("usage-unit-test").snapshot();
        assert_eq!(snapshot.codex.counts.requests, 2);
        assert_eq!(snapshot.codex.counts.unmetered, 1);
        assert_eq!(snapshot.codex.counts.tokens.total, u64::MAX);
        assert_eq!(snapshot.anthropic.counts.requests, 0);
        assert_eq!(
            BrokerUsage::named("usage-unit-other")
                .snapshot()
                .codex
                .counts
                .requests,
            0
        );
    }
}
