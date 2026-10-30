//! Bounded broker totals and latest subscription-window response headers.
use crate::{
    budget::{Attributed, Budget, Consumer, FIVE_HOURS, Grant, MistralSpend, Reading, WEEK},
    runs::{Tokens, Usage},
};
use http::HeaderMap;
use serde::{Deserialize, Serialize};
use std::{
    collections::{BTreeMap, BTreeSet, HashMap, VecDeque},
    io::Write,
    path::{Path, PathBuf},
    sync::{Arc, Condvar, LazyLock, Mutex, OnceLock, PoisonError},
    time::{Duration, SystemTime, UNIX_EPOCH},
};
use tracing::warn;

/// A provider, and its pool in a budget.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Deserialize, Serialize)]
#[serde(rename_all = "lowercase")]
pub(crate) enum Provider {
    Anthropic,
    Codex,
    Mistral,
}

impl Provider {
    /// The provider whose credential the broker injects for `cluster`.
    pub(crate) fn for_cluster(cluster: Option<&str>) -> Option<Self> {
        match cluster? {
            "anthropic" => Some(Self::Anthropic),
            "inference-backend" => Some(Self::Codex),
            "mistral" => Some(Self::Mistral),
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

impl Counts {
    fn settle(&mut self, usage: Option<&Usage>, success: bool) {
        if let Some(usage) = usage {
            self.requests = self.requests.saturating_add(1);
            self.tokens.add(&usage.tokens);
        } else if success {
            self.unmetered = self.unmetered.saturating_add(1);
        }
    }
}

/// The runs registered without proof, all together.
#[derive(Clone, Default, Serialize)]
struct UnprovenRuns {
    /// Registrations admitted.
    registered: u64,
    /// Registrations refused because their quota was used up.
    refused: u64,
    #[serde(flatten)]
    counts: Counts,
}

#[derive(Clone, Copy, Debug, PartialEq, Deserialize, Serialize)]
#[serde(rename_all = "snake_case")]
enum Status {
    Allowed,
    AllowedWarning,
    Rejected,
}

#[derive(Clone, Debug, PartialEq, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct AnthropicWindow {
    utilization: Option<f64>,
    reset: Option<u64>,
    status: Option<Status>,
    observed_at: u64,
    /// Loaded from the usage state file, and not read since.
    #[serde(default, skip_serializing_if = "std::ops::Not::not")]
    restored: bool,
}

#[derive(Clone, Debug, PartialEq, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct CodexWindow {
    used_percent: Option<f64>,
    window_minutes: Option<u64>,
    reset_after_seconds: Option<u64>,
    observed_at: u64,
    /// Loaded from the usage state file, and not read since.
    #[serde(default, skip_serializing_if = "std::ops::Not::not")]
    restored: bool,
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

/// No header of Mistral's responses is known to say how much of a plan is
/// used, so there is no window to observe, only what the broker counted.
#[derive(Clone, Default, Serialize)]
struct Mistral {
    counts: Counts,
}

#[derive(Clone, Serialize)]
pub(crate) struct Snapshot {
    schema: &'static str,
    started_at: u64,
    anthropic: Anthropic,
    codex: Codex,
    mistral: Mistral,
    /// What each operator token used, by its operator's name. Its provider's
    /// `counts` include it.
    operators: BTreeMap<String, Counts>,
    /// What the runs registered without proof used, if the deployment
    /// admits them. Its provider's `counts` include it.
    #[serde(skip_serializing_if = "Option::is_none")]
    unproven_runs: Option<UnprovenRuns>,
    /// The list-price spend of the trailing week, if the deployment meters
    /// it. Filled in when the snapshot is taken.
    #[serde(skip_serializing_if = "Option::is_none")]
    spend: Option<SpendView>,
    /// The windows of `WINDOWS`, as charged to each consumer, for grants.
    #[serde(skip)]
    attributed: [Option<Attributed>; 4],
    /// The listed operators whose consumer is public.
    #[serde(skip)]
    public_operators: BTreeSet<String>,
}

impl Default for Snapshot {
    fn default() -> Self {
        Self {
            schema: "praxis-broker-usage/v1",
            started_at: unix_time(),
            anthropic: Anthropic::default(),
            codex: Codex::default(),
            mistral: Mistral::default(),
            operators: BTreeMap::new(),
            unproven_runs: None,
            spend: None,
            attributed: Default::default(),
            public_operators: BTreeSet::new(),
        }
    }
}

/// The windows a grant has, by their names in `/usage`.
const WINDOWS: [(Provider, &str); 4] = [
    (Provider::Anthropic, "unified_5h"),
    (Provider::Anthropic, "unified_7d"),
    (Provider::Codex, "primary"),
    (Provider::Codex, "secondary"),
];

/// Hours of spend kept: the week the board's budget is set for.
const SPEND_HOURS: u64 = 7 * 24;

/// What one settled response adds to spend.
#[derive(Clone, Copy, Debug)]
enum Charge {
    /// Millionths of a USD.
    Priced(u64),
    /// A response with usage whose model the price table has no price for.
    Unpriced,
    /// A successful response whose usage never arrived, as `unmetered`
    /// counts it.
    Unmetered,
}

/// Spend, and the responses it leaves out.
#[derive(Clone, Copy, Debug, Default, PartialEq)]
struct Tally {
    /// Millionths of a USD.
    micros: u64,
    unpriced: u64,
    unmetered: u64,
}

impl Tally {
    fn add(&mut self, other: &Tally) {
        self.micros = self.micros.saturating_add(other.micros);
        self.unpriced = self.unpriced.saturating_add(other.unpriced);
        self.unmetered = self.unmetered.saturating_add(other.unmetered);
    }
}

/// What the injected requests settled in one hour cost at list price.
#[derive(Clone, Copy, Debug, PartialEq)]
struct Bucket {
    /// Hours since the Unix epoch.
    hour: u64,
    tally: Tally,
}

/// One payer's spend over the trailing week, hour by hour, oldest first: at
/// most `SPEND_HOURS` buckets, so it rolls an hour at a time rather than
/// resetting. These buckets are what a restart would need to keep (#35).
#[derive(Clone, Debug, Default)]
struct Week(VecDeque<Bucket>);

impl Week {
    fn add(&mut self, hour: u64, charge: Charge) {
        self.expire(hour);
        // A clock that steps back charges the latest hour, so the buckets
        // stay in order and never outnumber the hours of the week.
        let bucket = match self.0.back_mut() {
            Some(last) if last.hour >= hour => last,
            _ => {
                self.0.push_back(Bucket {
                    hour,
                    tally: Tally::default(),
                });
                self.0.back_mut().expect("just pushed")
            }
        };
        let tally = &mut bucket.tally;
        match charge {
            Charge::Priced(micros) => tally.micros = tally.micros.saturating_add(micros),
            Charge::Unpriced => tally.unpriced = tally.unpriced.saturating_add(1),
            Charge::Unmetered => tally.unmetered = tally.unmetered.saturating_add(1),
        }
    }

    /// Drop the hours that are no longer in the week ending with `hour`.
    fn expire(&mut self, hour: u64) {
        while self
            .0
            .front()
            .is_some_and(|bucket| bucket.hour + SPEND_HOURS <= hour)
        {
            self.0.pop_front();
        }
    }

    /// What was settled in the week ending with `hour`.
    fn sum(&self, hour: u64) -> Tally {
        let mut sum = Tally::default();
        for bucket in self.0.iter().filter(|b| b.hour + SPEND_HOURS > hour) {
            sum.add(&bucket.tally);
        }
        sum
    }
}

/// List-price spend: the runs' together, apart from each operator's,
/// because the board's budget is for its runs and an operator's
/// interactive use is not.
#[derive(Debug)]
struct Spend {
    /// Unix seconds when metering began: before a week has passed since,
    /// the figures cover less than the week.
    since: u64,
    /// By consumer.
    runs: [Week; 2],
    /// Only the operators the snapshot lists, so it is bounded as they are.
    operators: BTreeMap<String, Week>,
    /// Mistral's part of all of the above, by consumer, for its grants.
    mistral: [Week; 2],
}

/// A payer's spend, or all of it.
#[derive(Clone, Debug, PartialEq, Serialize)]
struct Spent {
    /// USD.
    total: f64,
    /// Responses with usage that no price is counted for; `total` is low by
    /// what they cost.
    unpriced_requests: u64,
    /// Successful responses whose usage never arrived; `total` is low by
    /// what they cost too.
    unmetered_requests: u64,
}

impl From<Tally> for Spent {
    fn from(tally: Tally) -> Self {
        Self {
            // Exact to the cent below $2^53 / 10^6, far beyond any week.
            total: tally.micros as f64 / 1e6,
            unpriced_requests: tally.unpriced,
            unmetered_requests: tally.unmetered,
        }
    }
}

#[derive(Clone, Debug, PartialEq, Serialize)]
struct SpendView {
    currency: &'static str,
    /// API list prices, whatever the credential is billed: what the
    /// requests would have cost on a metered key.
    basis: &'static str,
    /// The date of the price table.
    prices: &'static str,
    window_days: u64,
    since: u64,
    /// The runs' and every operator's.
    #[serde(flatten)]
    all: Spent,
    runs: Spent,
    by_operator: BTreeMap<String, Spent>,
}

impl Spend {
    /// The spend of the week ending with `hour`; only the public
    /// consumer's if `public_operators`, the operators it has, is given.
    fn view(&self, hour: u64, public_operators: Option<&BTreeSet<String>>) -> SpendView {
        let mut runs = self.runs[Consumer::Public.index()].sum(hour);
        if public_operators.is_none() {
            runs.add(&self.runs[Consumer::Private.index()].sum(hour));
        }
        let mut all = runs;
        let mut by_operator = BTreeMap::new();
        for (name, week) in &self.operators {
            if public_operators.is_some_and(|public| !public.contains(name)) {
                continue;
            }
            let tally = week.sum(hour);
            all.add(&tally);
            by_operator.insert(name.clone(), tally.into());
        }
        SpendView {
            currency: "USD",
            basis: "list",
            prices: crate::prices::PRICES,
            window_days: SPEND_HOURS / 24,
            since: self.since,
            all: all.into(),
            runs: runs.into(),
            by_operator,
        }
    }
}

/// Whom a settled response's spend is charged to.
#[derive(Clone, Copy, Debug)]
pub(crate) struct Payer<'a> {
    /// The operator named, or else the runs.
    pub operator: Option<&'a str>,
    pub consumer: Consumer,
    /// The provider that answered, if its usage is counted.
    pub provider: Option<Provider>,
}

/// The counts, and the spend if it is metered. Always lock the counts first.
#[derive(Default)]
pub(crate) struct BrokerUsage(Mutex<Snapshot>, Mutex<Option<Spend>>);

// Like the run registry, configuration reloads retain the named state. Each
// registry has exactly three counters and four window slots, a counter per
// operator a tokens file named and one for all runs registered without
// proof, never per-client keys; and, if spend is metered, a week of hourly
// buckets for the runs and one for each of those operators.
static REGISTRIES: LazyLock<Mutex<HashMap<String, Arc<BrokerUsage>>>> =
    LazyLock::new(Mutex::default);

/// Operators a snapshot lists: those of a few generations of tokens file.
const MAX_LISTED_OPERATORS: usize = 4 * crate::operators::MAX_OPERATORS;

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
                .or_insert_with(|| {
                    let usage = Self::default();
                    let restored = RESTORED
                        .lock()
                        .unwrap_or_else(PoisonError::into_inner)
                        .remove(name);
                    if let Some(windows) = restored {
                        usage.restore(windows);
                    }
                    Arc::new(usage)
                }),
        )
    }

    /// The windows the usage state file keeps.
    fn windows(&self) -> Windows {
        let state = self.0.lock().unwrap_or_else(PoisonError::into_inner);
        Windows {
            unified_5h: state.anthropic.unified_5h.clone(),
            unified_7d: state.anthropic.unified_7d.clone(),
            primary: state.codex.primary.clone(),
            secondary: state.codex.secondary.clone(),
            attributed: state.attributed.clone(),
        }
    }

    /// Take up `windows` from the usage state file, as restored until a
    /// response reads them again.
    fn restore(&self, windows: Windows) {
        let mut state = self.0.lock().unwrap_or_else(PoisonError::into_inner);
        let anthropic = |window: Option<AnthropicWindow>| {
            window.map(|window| AnthropicWindow {
                restored: true,
                ..window
            })
        };
        let codex = |window: Option<CodexWindow>| {
            window.map(|window| CodexWindow {
                restored: true,
                ..window
            })
        };
        state.anthropic.unified_5h = anthropic(windows.unified_5h);
        state.anthropic.unified_7d = anthropic(windows.unified_7d);
        state.codex.primary = codex(windows.primary);
        state.codex.secondary = codex(windows.secondary);
        state.attributed = windows
            .attributed
            .map(|window| window.map(Attributed::restore));
    }

    /// The snapshot `/usage` serves. Once a budget grants shares, its spend
    /// is only the public consumer's, which is the board's to read.
    pub(crate) fn snapshot(&self, granted: bool) -> Snapshot {
        self.snapshot_at(unix_time(), granted)
    }

    fn snapshot_at(&self, now: u64, granted: bool) -> Snapshot {
        let mut snapshot = self
            .0
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .clone();
        let public = granted.then_some(&snapshot.public_operators);
        snapshot.spend = self
            .1
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .as_ref()
            .map(|spend| spend.view(now / 3600, public));
        snapshot
    }

    /// `consumer`'s grant under `budget`.
    pub(crate) fn grant(&self, budget: &Budget, consumer: Consumer) -> Grant {
        self.grant_at(budget, consumer, unix_time())
    }

    fn grant_at(&self, budget: &Budget, consumer: Consumer, now: u64) -> Grant {
        let attributed = self
            .0
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .attributed
            .clone();
        let mistral = self
            .1
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .as_ref()
            .map(|spend| MistralSpend {
                micros: spend.mistral[consumer.index()].sum(now / 3600).micros,
                since: spend.since,
            });
        let windows: Vec<_> = WINDOWS
            .iter()
            .zip(&attributed)
            .map(|(&(provider, name), window)| (provider, name, window.as_ref()))
            .collect();
        budget.grant(consumer, &windows, mistral, now)
    }

    /// Meter list-price spend from now on, if it is not metered already. It
    /// is off unless the deployment turns it on: `/usage` is readable by
    /// anyone who reaches the listener, and a figure in dollars is only as
    /// true as the price table's date, so the deployment that budgets on it
    /// opts in. Nothing turns it off again before a restart, so that a
    /// filter without `spend` sharing the registry never wipes the week.
    pub(crate) fn meter_spend(&self) {
        self.meter_spend_at(unix_time());
    }

    fn meter_spend_at(&self, now: u64) {
        let state = self.0.lock().unwrap_or_else(PoisonError::into_inner);
        let mut spend = self.1.lock().unwrap_or_else(PoisonError::into_inner);
        spend.get_or_insert_with(|| Spend {
            since: now,
            runs: Default::default(),
            operators: state
                .operators
                .keys()
                .map(|name| (name.clone(), Week::default()))
                .collect(),
            mistral: Default::default(),
        });
    }

    /// Charge what a response from `provider` cost at list price to the
    /// runs, or to the operator named, and to `consumer`, if spend is
    /// metered and the operator listed. A successful response without
    /// usage is counted as unmetered.
    pub(crate) fn settle_spend(&self, payer: Payer<'_>, usage: Option<&Usage>, success: bool) {
        self.settle_spend_at(payer, usage, success, unix_time());
    }

    fn settle_spend_at(&self, payer: Payer<'_>, usage: Option<&Usage>, success: bool, now: u64) {
        // As `Counts::settle` counts them.
        let charge = match usage {
            Some(usage) => crate::prices::cost(usage).map_or(Charge::Unpriced, Charge::Priced),
            None if success => Charge::Unmetered,
            None => return,
        };
        let mut spend = self.1.lock().unwrap_or_else(PoisonError::into_inner);
        let Some(spend) = spend.as_mut() else {
            return;
        };
        let consumer = payer.consumer.index();
        let week = match payer.operator {
            None => &mut spend.runs[consumer],
            Some(operator) => match spend.operators.get_mut(operator) {
                Some(week) => week,
                None => return,
            },
        };
        week.add(now / 3600, charge);
        if payer.provider == Some(Provider::Mistral) {
            spend.mistral[consumer].add(now / 3600, charge);
        }
    }

    pub(crate) fn settle(&self, provider: Provider, usage: Option<&Usage>, success: bool) {
        let mut state = self.0.lock().unwrap_or_else(PoisonError::into_inner);
        let counts = match provider {
            Provider::Anthropic => &mut state.anthropic.counts,
            Provider::Codex => &mut state.codex.counts,
            Provider::Mistral => &mut state.mistral.counts,
        };
        counts.settle(usage, success);
    }

    /// List `operator` in the snapshot, at zero until it uses something.
    /// Operators removed from the tokens file stay listed until a restart,
    /// so the map never outgrows `MAX_LISTED_OPERATORS`. Its `consumer` is
    /// the one it was last declared with.
    pub(crate) fn declare_operator(&self, operator: &str, consumer: Consumer) {
        let mut state = self.0.lock().unwrap_or_else(PoisonError::into_inner);
        if !state.operators.contains_key(operator) {
            if state.operators.len() >= MAX_LISTED_OPERATORS {
                warn!(
                    operator,
                    "too many operators since the gateway started; this one's usage is not counted by name"
                );
                return;
            }
            state
                .operators
                .insert(operator.to_owned(), Counts::default());
            if let Some(spend) = self
                .1
                .lock()
                .unwrap_or_else(PoisonError::into_inner)
                .as_mut()
            {
                spend.operators.insert(operator.to_owned(), Week::default());
            }
        }
        if consumer == Consumer::Public {
            state.public_operators.insert(operator.to_owned());
        } else {
            state.public_operators.remove(operator);
        }
    }

    /// Count a response to a declared operator's request.
    pub(crate) fn settle_operator(&self, operator: &str, usage: Option<&Usage>, success: bool) {
        let mut state = self.0.lock().unwrap_or_else(PoisonError::into_inner);
        if let Some(counts) = state.operators.get_mut(operator) {
            counts.settle(usage, success);
        }
    }

    /// List the runs registered without proof in the snapshot, at zero: the
    /// deployment admits them. A reload that stops admitting them leaves
    /// what they used listed until a restart.
    pub(crate) fn declare_unproven(&self) {
        let mut state = self.0.lock().unwrap_or_else(PoisonError::into_inner);
        state.unproven_runs.get_or_insert_default();
    }

    /// Count a registration without proof: admitted, or refused for quota.
    pub(crate) fn unproven_registration(&self, admitted: bool) {
        let mut state = self.0.lock().unwrap_or_else(PoisonError::into_inner);
        let runs = state.unproven_runs.get_or_insert_default();
        let count = if admitted {
            &mut runs.registered
        } else {
            &mut runs.refused
        };
        *count = count.saturating_add(1);
    }

    /// Count a response to a request of a run registered without proof.
    pub(crate) fn settle_unproven(&self, usage: Option<&Usage>, success: bool) {
        let mut state = self.0.lock().unwrap_or_else(PoisonError::into_inner);
        let runs = state.unproven_runs.get_or_insert_default();
        runs.counts.settle(usage, success);
    }

    /// Keep the windows a response to `consumer`'s request reports, and
    /// charge `consumer` what they rose by.
    pub(crate) fn capture(&self, provider: Provider, consumer: Consumer, headers: &HeaderMap) {
        self.capture_at(provider, consumer, headers, unix_time());
    }

    fn capture_at(&self, provider: Provider, consumer: Consumer, headers: &HeaderMap, now: u64) {
        let mut state = self.0.lock().unwrap_or_else(PoisonError::into_inner);
        // By index in `WINDOWS`: a complete reading, or None for a window
        // the plan does not have.
        let mut read = Vec::new();
        let mut changed = false;
        match provider {
            Provider::Anthropic => {
                let Anthropic {
                    unified_5h,
                    unified_7d,
                    ..
                } = &mut state.anthropic;
                for (index, slot, name, window_secs) in [
                    (0, unified_5h, "5h", FIVE_HOURS),
                    (1, unified_7d, "7d", WEEK),
                ] {
                    if let Some(window) = anthropic_window(headers, name, now) {
                        if let (Some(utilization), Some(resets_at)) =
                            (window.utilization, window.reset)
                        {
                            read.push((
                                index,
                                Some(Reading {
                                    used_percent: utilization * 100.0,
                                    resets_at,
                                    window_secs,
                                }),
                            ));
                        }
                        *slot = Some(window);
                        changed = true;
                    }
                }
            }
            Provider::Codex => {
                let Codex {
                    primary, secondary, ..
                } = &mut state.codex;
                for (index, slot, name) in [(2, primary, "primary"), (3, secondary, "secondary")] {
                    match codex_window(headers, name, now) {
                        // A window the plan does not have comes as zeros.
                        Some(window) if window.window_minutes == Some(0) => {
                            *slot = None;
                            read.push((index, None));
                            changed = true;
                        }
                        Some(window) => {
                            if let (Some(used_percent), Some(minutes), Some(after)) = (
                                window.used_percent,
                                window.window_minutes,
                                window.reset_after_seconds,
                            ) {
                                read.push((
                                    index,
                                    Some(Reading {
                                        used_percent,
                                        resets_at: now.saturating_add(after),
                                        window_secs: minutes.saturating_mul(60),
                                    }),
                                ));
                            }
                            *slot = Some(window);
                            changed = true;
                        }
                        None => {}
                    }
                }
            }
            Provider::Mistral => {}
        }
        for (index, reading) in read {
            let window = &mut state.attributed[index];
            *window =
                reading.map(|reading| Attributed::charge(window.as_ref(), reading, consumer, now));
        }
        drop(state);
        if let (true, Some(file)) = (changed, STATE_FILE.get()) {
            file.changed();
        }
    }
}

/// The schema of the usage state file.
const STATE_SCHEMA: &str = "praxis-broker-usage-state/v1";

/// How long a change waits for others before the state file is written:
/// the windows change on every response.
const STATE_INTERVAL: Duration = Duration::from_secs(5);

/// One registry's windows, as the usage state file keeps them. Nothing
/// else is kept, so `started_at` and the counts are the running process's.
#[derive(Debug, Default, PartialEq, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct Windows {
    unified_5h: Option<AnthropicWindow>,
    unified_7d: Option<AnthropicWindow>,
    primary: Option<CodexWindow>,
    secondary: Option<CodexWindow>,
    /// The windows of `WINDOWS`, as charged to each consumer.
    attributed: [Option<Attributed>; 4],
}

#[derive(Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct StateFile {
    schema: String,
    registries: BTreeMap<String, Windows>,
}

/// The windows loaded from the state file, by registry, until it is named.
static RESTORED: Mutex<BTreeMap<String, Windows>> = Mutex::new(BTreeMap::new());

/// The usage state file, if the gateway keeps one.
static STATE_FILE: OnceLock<StateWriter> = OnceLock::new();

/// Writes the state file as the windows change, at most once an interval.
struct StateWriter {
    path: PathBuf,
    dirty: Mutex<bool>,
    wake: Condvar,
}

impl StateWriter {
    fn new(path: PathBuf) -> Self {
        Self {
            path,
            dirty: Mutex::new(false),
            wake: Condvar::new(),
        }
    }

    fn changed(&self) {
        *self.dirty.lock().unwrap_or_else(PoisonError::into_inner) = true;
        self.wake.notify_one();
    }

    /// Wait for a change, then `interval` more, and write `windows()` as
    /// they are then: every change meanwhile is in that one write, and the
    /// newest state is always written.
    fn write_next(
        &self,
        interval: Duration,
        windows: impl FnOnce() -> BTreeMap<String, Windows>,
    ) -> Result<(), String> {
        let mut dirty = self.dirty.lock().unwrap_or_else(PoisonError::into_inner);
        while !*dirty {
            dirty = self
                .wake
                .wait(dirty)
                .unwrap_or_else(PoisonError::into_inner);
        }
        drop(dirty);
        std::thread::sleep(interval);
        // Before reading the windows, so that a change after is written
        // next time.
        *self.dirty.lock().unwrap_or_else(PoisonError::into_inner) = false;
        write_state(&self.path, windows())
    }
}

/// Every registry's windows.
fn all_windows() -> BTreeMap<String, Windows> {
    REGISTRIES
        .lock()
        .unwrap_or_else(PoisonError::into_inner)
        .iter()
        .map(|(name, usage)| (name.clone(), usage.windows()))
        .collect()
}

/// Replace the state file at `path` with `registries`, through a
/// temporary file beside it, so a reader sees the old file or the new one.
fn write_state(path: &Path, registries: BTreeMap<String, Windows>) -> Result<(), String> {
    let file = StateFile {
        schema: STATE_SCHEMA.to_owned(),
        registries,
    };
    let text = serde_json::to_vec(&file).map_err(|e| e.to_string())?;
    let mut temporary = path.as_os_str().to_owned();
    temporary.push(".tmp");
    let temporary = PathBuf::from(temporary);
    let write = || -> std::io::Result<()> {
        let mut file = std::fs::File::create(&temporary)?;
        file.write_all(&text)?;
        file.sync_all()?;
        std::fs::rename(&temporary, path)
    };
    write().map_err(|e| format!("{}: {e}", path.display()))
}

/// The windows in the state file at `path`, by registry.
fn read_state(path: &Path) -> Result<BTreeMap<String, Windows>, String> {
    let read = || -> Result<_, String> {
        let text = std::fs::read(path).map_err(|e| e.to_string())?;
        let file: StateFile = serde_json::from_slice(&text).map_err(|e| e.to_string())?;
        if file.schema != STATE_SCHEMA {
            return Err(format!("schema {:?}, not {STATE_SCHEMA:?}", file.schema));
        }
        Ok(file.registries)
    };
    read().map_err(|e| format!("{}: {e}", path.display()))
}

/// Keep the windows in the state file at `path` across restarts: take up
/// what it has, and rewrite it as they change. A file that is missing or
/// not valid is no reading, never a reason not to start. Call it once,
/// before any filter is built.
pub(crate) fn keep_state(path: PathBuf) {
    let registries = read_state(&path).unwrap_or_else(|e| {
        warn!("usage state not loaded, so no window has a reading: {e}");
        BTreeMap::new()
    });
    *RESTORED.lock().unwrap_or_else(PoisonError::into_inner) = registries;
    let Ok(()) = STATE_FILE.set(StateWriter::new(path)) else {
        return;
    };
    let writer = STATE_FILE.get().expect("just set");
    std::thread::spawn(move || {
        loop {
            if let Err(e) = writer.write_next(STATE_INTERVAL, all_windows) {
                warn!("usage state not written: {e}");
            }
        }
    });
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
        restored: false,
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
            restored: false,
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
        usage.capture_at(
            Provider::Anthropic,
            Consumer::Private,
            &fixture("anthropic"),
            10,
        );
        usage.capture_at(Provider::Codex, Consumer::Private, &fixture("codex"), 20);
        let snapshot = usage.snapshot(false);
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
        let serialized = serde_json::to_string(&usage.snapshot(false)).unwrap();
        assert!(!serialized.contains("SYNTHETIC"));
        let mut update = HeaderMap::new();
        update.insert("x-codex-primary-used-percent", "55".parse().unwrap());
        usage.capture_at(Provider::Codex, Consumer::Private, &update, 30);
        assert_eq!(usage.snapshot(false).codex.primary.unwrap().observed_at, 30);
        assert_eq!(usage.snapshot(false).codex.secondary.unwrap(), secondary);
        usage.capture_at(Provider::Codex, Consumer::Private, &HeaderMap::new(), 40);
        assert_eq!(usage.snapshot(false).codex.primary.unwrap().observed_at, 30);
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
        usage.capture_at(Provider::Codex, Consumer::Private, &weekly_only, 50);
        let codex = usage.snapshot(false).codex;
        assert_eq!(codex.primary.unwrap().window_minutes, Some(10080));
        assert_eq!(codex.secondary, None);
    }

    /// Each injected cluster of praxis.yaml is counted under its own
    /// provider, and nothing else is counted at all.
    #[test]
    fn each_injected_cluster_is_counted_under_its_own_provider() {
        let cases = [
            (Some("anthropic"), Some((Provider::Anthropic, "anthropic"))),
            (Some("inference-backend"), Some((Provider::Codex, "codex"))),
            (Some("mistral"), Some((Provider::Mistral, "mistral"))),
            (Some("anthropic-pass-through"), None),
            (Some("run-endpoints"), None),
            (Some("Mistral"), None),
            (None, None),
        ];
        let reported = Usage {
            tokens: Tokens {
                input: 24,
                output: 20,
                total: 44,
                ..Tokens::default()
            },
            model: None,
            cache_write: 0,
        };
        let counts = |requests: u64, unmetered: u64, tokens: [u64; 3]| {
            serde_json::json!({
                "requests": requests,
                "unmetered": unmetered,
                "tokens": {"input": tokens[0], "cache_read": 0, "output": tokens[1], "reasoning": 0, "total": tokens[2]},
            })
        };
        for (cluster, want) in cases {
            let provider = Provider::for_cluster(cluster);
            assert_eq!(provider, want.map(|(provider, _)| provider), "{cluster:?}");
            let Some((provider, field)) = want else {
                continue;
            };
            let usage = BrokerUsage::default();
            usage.settle(provider, Some(&reported), true);
            usage.settle(provider, None, true);
            usage.settle(provider, None, false);
            // Every provider's response headers, which only its own windows
            // may come from.
            let mut headers = fixture("anthropic");
            headers.extend(fixture("codex"));
            usage.capture_at(provider, Consumer::Private, &headers, 10);
            let snapshot = serde_json::to_value(usage.snapshot(false)).unwrap();
            for other in ["anthropic", "codex", "mistral"] {
                let want = if other == field {
                    counts(1, 1, [24, 20, 44])
                } else {
                    counts(0, 0, [0; 3])
                };
                assert_eq!(snapshot[other]["counts"], want, "{cluster:?}: {other}");
            }
            assert_eq!(
                (
                    snapshot["anthropic"]["unified_5h"].is_null(),
                    snapshot["codex"]["primary"].is_null(),
                ),
                (provider != Provider::Anthropic, provider != Provider::Codex),
                "{cluster:?}"
            );
            // Mistral has counts and nothing else.
            assert_eq!(snapshot["mistral"].as_object().unwrap().len(), 1);
        }
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
    fn operators_are_counted_by_name_once_declared() {
        let usage = BrokerUsage::default();
        let reported = Usage {
            tokens: Tokens {
                input: 3,
                total: 3,
                ..Tokens::default()
            },
            model: None,
            cache_write: 0,
        };
        usage.declare_operator("me", Consumer::Private);
        usage.settle_operator("me", Some(&reported), true);
        usage.settle_operator("me", None, true);
        usage.settle_operator("me", None, false);
        // Declaring again keeps the counts; an undeclared name is not kept.
        usage.declare_operator("me", Consumer::Private);
        usage.settle_operator("stranger", Some(&reported), true);
        for i in 0..2 * MAX_LISTED_OPERATORS {
            usage.declare_operator(&format!("o{i}"), Consumer::Private);
        }
        let snapshot = serde_json::to_value(usage.snapshot(false)).unwrap();
        let operators = snapshot["operators"].as_object().unwrap();
        assert_eq!(operators.len(), MAX_LISTED_OPERATORS);
        assert!(!operators.contains_key("stranger"));
        assert_eq!(
            operators["me"],
            serde_json::json!({
                "requests": 1,
                "unmetered": 1,
                "tokens": {"input": 3, "cache_read": 0, "output": 0, "reasoning": 0, "total": 3},
            })
        );
        assert_eq!(snapshot["codex"]["counts"]["requests"], 0);
    }

    #[test]
    fn unproven_runs_are_listed_only_once_admitted_and_counted_together() {
        let usage = BrokerUsage::default();
        let reported = Usage {
            tokens: Tokens {
                output: 4,
                total: 4,
                ..Tokens::default()
            },
            model: None,
            cache_write: 0,
        };
        let snapshot = serde_json::to_value(usage.snapshot(false)).unwrap();
        assert!(snapshot.get("unproven_runs").is_none());
        usage.declare_unproven();
        assert_eq!(
            serde_json::to_value(usage.snapshot(false)).unwrap()["unproven_runs"],
            serde_json::json!({
                "registered": 0,
                "refused": 0,
                "requests": 0,
                "unmetered": 0,
                "tokens": {"input": 0, "cache_read": 0, "output": 0, "reasoning": 0, "total": 0},
            })
        );
        // (admitted, refused) registrations, then one response of each kind.
        for admitted in [true, true, false] {
            usage.unproven_registration(admitted);
        }
        usage.settle_unproven(Some(&reported), true);
        usage.settle_unproven(None, true);
        usage.settle_unproven(None, false);
        // Declaring again, as a reload does, keeps the counts.
        usage.declare_unproven();
        let snapshot = serde_json::to_value(usage.snapshot(false)).unwrap();
        assert_eq!(
            snapshot["unproven_runs"],
            serde_json::json!({
                "registered": 2,
                "refused": 1,
                "requests": 1,
                "unmetered": 1,
                "tokens": {"input": 0, "cache_read": 0, "output": 4, "reasoning": 0, "total": 4},
            })
        );
        assert_eq!(snapshot["codex"]["counts"]["requests"], 0);
    }

    fn priced(model: &str, input: u64) -> Usage {
        Usage {
            tokens: Tokens {
                input,
                total: input,
                ..Tokens::default()
            },
            model: Some(model.to_owned()),
            cache_write: 0,
        }
    }

    fn spend(usage: &BrokerUsage, now: u64) -> serde_json::Value {
        serde_json::to_value(usage.snapshot_at(now, false)).unwrap()["spend"].clone()
    }

    const RUNS: Payer<'static> = Payer {
        operator: None,
        consumer: Consumer::Private,
        provider: None,
    };

    fn operator(name: &str) -> Payer<'_> {
        Payer {
            operator: Some(name),
            ..RUNS
        }
    }

    /// Once grants exist, `/usage` has only the public consumer's spend,
    /// and Mistral's is kept by consumer for their grants.
    #[test]
    fn granted_spend_is_the_public_consumers() {
        use Consumer::{Private, Public};
        let usage = BrokerUsage::default();
        usage.meter_spend_at(0);
        usage.declare_operator("board", Public);
        usage.declare_operator("me", Private);
        let dollars = |n: u64| priced("claude-opus-5-5", n * 250_000);
        let mistral = Some(Provider::Mistral);
        for (operator, consumer, provider, n) in [
            (None, Public, None, 1),
            (None, Private, None, 2),
            (None, Public, mistral, 4),
            (Some("board"), Public, mistral, 8),
            (Some("me"), Private, mistral, 16),
        ] {
            let payer = Payer {
                operator,
                consumer,
                provider,
            };
            usage.settle_spend_at(payer, Some(&dollars(n)), true, 0);
        }
        let all = serde_json::to_value(usage.snapshot_at(0, false)).unwrap();
        assert_eq!(all["spend"]["total"], 31.0);
        assert_eq!(all["spend"]["runs"]["total"], 7.0);
        let public = serde_json::to_value(usage.snapshot_at(0, true)).unwrap();
        assert_eq!(public["spend"]["total"], 13.0);
        assert_eq!(public["spend"]["runs"]["total"], 5.0);
        assert_eq!(
            public["spend"]["by_operator"]
                .as_object()
                .unwrap()
                .keys()
                .collect::<Vec<_>>(),
            ["board"]
        );
        // Declared again as private, as a reload does, it is left out.
        usage.declare_operator("board", Private);
        let public = serde_json::to_value(usage.snapshot_at(0, true)).unwrap();
        assert_eq!(public["spend"]["by_operator"], serde_json::json!({}));
        let spend = usage.1.lock().unwrap();
        let mistral = &spend.as_ref().unwrap().mistral;
        assert_eq!(mistral[Public.index()].sum(0).micros, 12_000_000);
        assert_eq!(mistral[Private.index()].sum(0).micros, 16_000_000);
    }

    /// The windows of the fixtures are charged to the consumer whose
    /// response carried them, by the names `/usage` gives them.
    #[test]
    fn captured_windows_are_charged_to_the_requests_consumer() {
        use Consumer::{Private, Public};
        let budget = Budget::parse(
            "shares: {public: {anthropic: 50, codex: 50}, private: {anthropic: 50, codex: 50}}",
        )
        .unwrap();
        // Before the fixture's 5-hour window resets.
        let now = 1_791_110_000;
        let usage = BrokerUsage::default();
        usage.capture_at(Provider::Anthropic, Public, &fixture("anthropic"), now);
        usage.capture_at(Provider::Codex, Public, &fixture("codex"), now);
        let used = |consumer| {
            let grant = serde_json::to_value(usage.grant_at(&budget, consumer, now)).unwrap();
            let window = |pool: &str, name: &str| {
                let window = &grant["pools"][pool]["windows"][name];
                (
                    window["used_percent"].as_f64().unwrap(),
                    window["resets_at"].as_u64().unwrap(),
                )
            };
            [
                window("anthropic", "unified_5h"),
                window("anthropic", "unified_7d"),
                window("codex", "primary"),
                window("codex", "secondary"),
            ]
        };
        // Read part-way through, each window is charged to both in full.
        let first = [
            (42.0, 1_791_115_200),
            (81.0, 1_791_676_800),
            (42.5, now + 1200),
            (81.0, now + 345_600),
        ];
        assert_eq!(used(Public), first);
        assert_eq!(used(Private), first);
        let mut rise = HeaderMap::new();
        rise.insert(
            "anthropic-ratelimit-unified-5h-utilization",
            "0.5".parse().unwrap(),
        );
        rise.insert(
            "anthropic-ratelimit-unified-5h-reset",
            "1791115200".parse().unwrap(),
        );
        usage.capture_at(Provider::Anthropic, Private, &rise, now);
        assert_eq!(used(Public)[0].0, 42.0);
        assert_eq!(used(Private)[0].0, 50.0);
        // A plan without the window clears it.
        let mut weekly_only = HeaderMap::new();
        weekly_only.insert("x-codex-secondary-window-minutes", "0".parse().unwrap());
        usage.capture_at(Provider::Codex, Private, &weekly_only, now);
        assert!(usage.0.lock().unwrap().attributed[3].is_none());
    }

    #[test]
    fn spend_is_off_until_enabled_and_keeps_runs_and_operators_apart() {
        let usage = BrokerUsage::default();
        usage.declare_operator("me", Consumer::Private);
        // $4 per million input.
        let dollars = |n: u64| priced("claude-opus-5-5", n * 250_000);
        usage.settle_spend_at(RUNS, Some(&dollars(1)), true, 0);
        assert_eq!(spend(&usage, 0), serde_json::Value::Null);
        usage.meter_spend_at(100);
        usage.declare_operator("you", Consumer::Private);
        usage.settle_spend_at(RUNS, Some(&dollars(3)), true, 100);
        usage.settle_spend_at(operator("me"), Some(&dollars(5)), true, 100);
        usage.settle_spend_at(operator("you"), Some(&dollars(7)), true, 100);
        usage.settle_spend_at(operator("stranger"), Some(&dollars(11)), true, 100);
        usage.settle_spend_at(operator("me"), Some(&priced("claude-test", 1)), true, 100);
        // Without usage, a success is unmetered and a failure not counted.
        usage.settle_spend_at(RUNS, None, true, 100);
        usage.settle_spend_at(RUNS, None, false, 100);
        usage.settle_spend_at(operator("you"), None, true, 100);
        // Enabling again, as a reload or another filter does, keeps what
        // was metered and when it began.
        usage.meter_spend_at(200);
        let spent = |total: f64, unpriced: u64, unmetered: u64| {
            serde_json::json!({
                "total": total,
                "unpriced_requests": unpriced,
                "unmetered_requests": unmetered,
            })
        };
        assert_eq!(
            spend(&usage, 100),
            serde_json::json!({
                "currency": "USD",
                "basis": "list",
                "prices": crate::prices::PRICES,
                "window_days": 7,
                "since": 100,
                "total": 15.0,
                "unpriced_requests": 1,
                "unmetered_requests": 2,
                "runs": spent(3.0, 0, 1),
                "by_operator": {"me": spent(5.0, 1, 0), "you": spent(7.0, 0, 1)},
            })
        );
    }

    #[test]
    fn spend_rolls_off_an_hour_at_a_time_after_a_week() {
        let usage = BrokerUsage::default();
        let hour = 3600;
        let start = 1_000_000 * hour;
        usage.meter_spend_at(start);
        // $1 in each of the week's hours and two more, and an unpriced and
        // an unmetered response in the first.
        let dollar = priced("claude-opus-5-5", 250_000);
        usage.settle_spend_at(RUNS, Some(&priced("claude-test", 1)), true, start);
        usage.settle_spend_at(RUNS, None, true, start);
        assert_eq!(spend(&usage, start + 59)["runs"]["unpriced_requests"], 1);
        assert_eq!(spend(&usage, start + 59)["runs"]["unmetered_requests"], 1);
        for h in 0..SPEND_HOURS + 2 {
            usage.settle_spend_at(RUNS, Some(&dollar), true, start + h * hour);
        }
        let at = |h: u64| spend(&usage, start + h * hour + 59);
        let buckets = || usage.1.lock().unwrap().as_ref().unwrap().runs[1].0.len() as u64;
        assert_eq!(buckets(), SPEND_HOURS);
        let now = SPEND_HOURS + 1;
        assert_eq!(at(now)["runs"]["total"], 168.0);
        assert_eq!(at(now)["runs"]["unpriced_requests"], 0);
        assert_eq!(at(now)["runs"]["unmetered_requests"], 0);
        // Each hour without spend drops the oldest hour's.
        assert_eq!(at(now + 1)["runs"]["total"], 167.0);
        assert_eq!(at(now + 100)["runs"]["total"], 68.0);
        assert_eq!(at(now + SPEND_HOURS)["runs"]["total"], 0.0);
        // A clock that steps back charges the latest hour.
        usage.settle_spend_at(RUNS, Some(&dollar), true, start);
        assert_eq!(at(now)["runs"]["total"], 169.0);
        assert_eq!(buckets(), SPEND_HOURS);
    }

    /// The fixtures' windows as read at `now`, and the usage that read them.
    fn read_fixtures(now: u64) -> BrokerUsage {
        let usage = BrokerUsage::default();
        usage.capture_at(
            Provider::Anthropic,
            Consumer::Public,
            &fixture("anthropic"),
            now,
        );
        usage.capture_at(Provider::Codex, Consumer::Public, &fixture("codex"), now);
        usage
    }

    fn round_trip(usage: &BrokerUsage, path: &Path) -> BrokerUsage {
        let registries = BTreeMap::from([("default".to_owned(), usage.windows())]);
        write_state(path, registries).unwrap();
        let restored = BrokerUsage::default();
        restored.restore(read_state(path).unwrap().remove("default").unwrap());
        restored
    }

    #[test]
    fn windows_round_trip_restored_with_their_observed_at() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("usage-state.json");
        let usage = read_fixtures(20);
        usage.settle(Provider::Codex, None, true);
        let restored = round_trip(&usage, &path);
        let (before, after) = (usage.snapshot(false), restored.snapshot(false));
        let five = after.anthropic.unified_5h.clone().unwrap();
        assert_eq!((five.observed_at, five.restored), (20, true));
        assert_eq!(
            five,
            AnthropicWindow {
                restored: true,
                ..before.anthropic.unified_5h.unwrap()
            }
        );
        assert_eq!(after.codex.secondary.as_ref().unwrap().observed_at, 20);
        // The windows only: the counts are the running process's.
        assert_eq!(after.codex.counts.unmetered, 0);
        let json = serde_json::to_value(&after).unwrap();
        assert_eq!(json["codex"]["primary"]["restored"], true);
        // A live response replaces a restored window.
        let mut update = HeaderMap::new();
        update.insert("x-codex-primary-used-percent", "55".parse().unwrap());
        restored.capture_at(Provider::Codex, Consumer::Public, &update, 30);
        let json = serde_json::to_value(restored.snapshot(false)).unwrap();
        assert!(json["codex"]["primary"].get("restored").is_none());
        assert_eq!(json["codex"]["secondary"]["restored"], true);
    }

    /// A restored Codex window resets when its stored `observed_at` and
    /// `reset_after_seconds` say, however much later it is loaded; and its
    /// grant is a reading, attributed as it was, until then.
    #[test]
    fn a_restored_window_is_granted_on_until_its_reset() {
        let budget = Budget::parse(
            "shares: {public: {anthropic: 50, codex: 50}, private: {anthropic: 50, codex: 50}}",
        )
        .unwrap();
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("usage-state.json");
        let read_at = 1_791_100_000;
        let usage = read_fixtures(read_at);
        // The fixtures were first read part-way: whose use it was is
        // unknown, so a reading from zero stands in for one attributed.
        usage.0.lock().unwrap().attributed[2] = Some(Attributed::charge(
            None,
            Reading {
                used_percent: 0.0,
                resets_at: read_at + 1200,
                window_secs: FIVE_HOURS,
            },
            Consumer::Public,
            read_at,
        ));
        let mut rise = HeaderMap::new();
        rise.insert("x-codex-primary-used-percent", "10".parse().unwrap());
        rise.insert("x-codex-primary-window-minutes", "300".parse().unwrap());
        rise.insert(
            "x-codex-primary-reset-after-seconds",
            "1200".parse().unwrap(),
        );
        usage.capture_at(Provider::Codex, Consumer::Private, &rise, read_at);
        let restored = round_trip(&usage, &path);
        let codex = |now| {
            let grant = restored.grant_at(&budget, Consumer::Private, now);
            serde_json::to_value(&grant).unwrap()["pools"]["codex"].clone()
        };
        let now = read_at + 1000;
        let primary = &codex(now)["windows"]["primary"];
        assert_eq!(primary["resets_at"], read_at + 1200);
        assert_eq!(primary["used_percent"], 10.0);
        assert_eq!(primary["hold"], false);
        // The secondary window, first read part-way, still holds.
        assert_eq!(codex(now)["windows"]["secondary"]["hold"], true);
        // Past its reset it is no reading.
        assert!(codex(read_at + 1200)["windows"].get("primary").is_none());
    }

    #[test]
    fn a_missing_corrupt_or_wrong_schema_file_is_no_reading() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("usage-state.json");
        let cases = [
            None,
            Some("{\"schema\": \"praxis-broker-usage-state/v1\", \"regis"),
            Some("{\"schema\": \"praxis-broker-usage-state/v2\", \"registries\": {}}"),
            Some(
                "{\"schema\": \"praxis-broker-usage-state/v1\", \"registries\": {\"default\": {\"primary\": 7}}}",
            ),
        ];
        for text in cases {
            if let Some(text) = text {
                std::fs::write(&path, text).unwrap();
            }
            let e = read_state(&path).unwrap_err();
            assert!(e.contains("usage-state.json"), "{text:?}: {e}");
        }
        std::fs::write(&path, "{\"schema\": \"praxis-broker-usage-state/v1\", \"registries\": {\"default\": {\"unified_5h\": null, \"unified_7d\": null, \"primary\": null, \"secondary\": null, \"attributed\": [null, null, null, null]}}}").unwrap();
        assert_eq!(read_state(&path).unwrap()["default"], Windows::default());
    }

    /// A burst of changes is one write, of the newest windows.
    #[test]
    fn a_burst_of_changes_is_coalesced_into_one_write() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("usage-state.json");
        let writer = Arc::new(StateWriter::new(path.clone()));
        let usage = Arc::new(BrokerUsage::default());
        let writes = Arc::new(Mutex::new(0));
        let thread = {
            let (writer, usage, writes) = (writer.clone(), usage.clone(), writes.clone());
            std::thread::spawn(move || {
                writer
                    .write_next(Duration::from_millis(300), || {
                        *writes.lock().unwrap() += 1;
                        BTreeMap::from([("default".to_owned(), usage.windows())])
                    })
                    .unwrap()
            })
        };
        for percent in 1..=50 {
            let mut headers = HeaderMap::new();
            headers.insert(
                "x-codex-primary-used-percent",
                percent.to_string().parse().unwrap(),
            );
            usage.capture_at(Provider::Codex, Consumer::Public, &headers, percent);
            writer.changed();
        }
        thread.join().unwrap();
        assert_eq!(*writes.lock().unwrap(), 1);
        assert!(!*writer.dirty.lock().unwrap());
        let written = read_state(&path).unwrap().remove("default").unwrap();
        assert_eq!(written.primary.unwrap().used_percent, Some(50.0));
    }

    /// A reader never finds the file half-written, however often it is
    /// replaced.
    #[test]
    fn a_write_replaces_the_file_whole() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("usage-state.json");
        let usage = read_fixtures(20);
        // Large enough that a write in place could be seen part-done.
        let registries = || {
            (0..200)
                .map(|i| (format!("registry-{i}"), usage.windows()))
                .collect::<BTreeMap<_, _>>()
        };
        write_state(&path, registries()).unwrap();
        let done = Arc::new(std::sync::atomic::AtomicBool::new(false));
        let reader = {
            let (path, done) = (path.clone(), done.clone());
            std::thread::spawn(move || {
                let mut reads = 0;
                while !done.load(std::sync::atomic::Ordering::Relaxed) {
                    assert_eq!(read_state(&path).unwrap().len(), 200);
                    reads += 1;
                }
                reads
            })
        };
        for _ in 0..50 {
            write_state(&path, registries()).unwrap();
        }
        done.store(true, std::sync::atomic::Ordering::Relaxed);
        assert!(reader.join().unwrap() > 0);
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
            cache_write: 0,
        };
        usage.settle(Provider::Codex, Some(&reported), true);
        usage.settle(Provider::Codex, Some(&reported), true);
        usage.settle(Provider::Codex, None, true);
        usage.settle(Provider::Codex, None, false);
        let snapshot = BrokerUsage::named("usage-unit-test").snapshot(false);
        assert_eq!(snapshot.codex.counts.requests, 2);
        assert_eq!(snapshot.codex.counts.unmetered, 1);
        assert_eq!(snapshot.codex.counts.tokens.total, u64::MAX);
        assert_eq!(snapshot.anthropic.counts.requests, 0);
        assert_eq!(
            BrokerUsage::named("usage-unit-other")
                .snapshot(false)
                .codex
                .counts
                .requests,
            0
        );
    }
}
