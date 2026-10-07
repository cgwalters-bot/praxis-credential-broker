//! Registered runs: their bearer tokens, lifetimes, concurrency and usage
//! records.
//!
//! A run's token cap is not enforced here: `run_token` publishes each
//! request's run as its authenticated identity, and a `token_rate_limit`
//! rule keyed on it caps the run. This module only records what each run
//! used, for the job to read back.
use serde::Serialize;
use sha2::{Digest, Sha256};
use std::{
    collections::{BTreeMap, HashMap},
    sync::{Arc, LazyLock, Mutex, MutexGuard, PoisonError},
    time::{Duration, Instant, SystemTime, UNIX_EPOCH},
};
use tracing::{info, warn};

pub const RECORD_SCHEMA: &str = "praxis-run-usage/v2";
pub const TOKEN_PREFIX: &str = "praxis-run-";
/// Registrations kept at once, finished and expired ones included.
const MAX_RUNS: usize = 4096;
/// How long a run is remembered after it expires, so it cannot register again.
const RETENTION: Duration = Duration::from_secs(24 * 3600);
/// Models a record keeps totals for; usage of any further model only counts
/// in the run's totals.
const MAX_MODELS: usize = 16;

/// Token counts in the shape of an agent run summary's `tokens`: `input` is
/// the uncached part, `reasoning` is included in `output`, and `total` is
/// what caps are charged.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Serialize)]
pub struct Tokens {
    pub input: u64,
    pub cache_read: u64,
    pub output: u64,
    pub reasoning: u64,
    pub total: u64,
}

impl Tokens {
    pub(crate) fn add(&mut self, other: &Tokens) {
        self.input = self.input.saturating_add(other.input);
        self.cache_read = self.cache_read.saturating_add(other.cache_read);
        self.output = self.output.saturating_add(other.output);
        self.reasoning = self.reasoning.saturating_add(other.reasoning);
        self.total = self.total.saturating_add(other.total);
    }
}

/// What one response used, as `token_count` reported it.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct Usage {
    pub tokens: Tokens,
    /// The model upstream says served the response.
    pub model: Option<String>,
}

/// The limits a run is registered with.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Limits {
    pub ttl: Duration,
    pub concurrency: usize,
}

/// A GitHub Actions job in a run attempt, as its verified OIDC token names
/// it, and that token's unique id.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct RunIdentity {
    pub repository: String,
    pub repository_id: u64,
    pub run_id: u64,
    pub run_attempt: u64,
    /// Tells the jobs of one run apart, such as a matrix's.
    pub check_run_id: Option<u64>,
    pub jti: String,
    pub workflow_ref: String,
}

impl RunIdentity {
    fn key(&self) -> RunKey {
        RunKey {
            repository_id: self.repository_id,
            run_id: self.run_id,
            run_attempt: self.run_attempt,
            check_run_id: self.check_run_id,
        }
    }
}

#[derive(Clone, Copy, Debug, Hash, PartialEq, Eq)]
pub struct RunKey {
    repository_id: u64,
    run_id: u64,
    run_attempt: u64,
    check_run_id: Option<u64>,
}

impl RunKey {
    /// The run as an authenticated subject, which budgets are keyed on. It
    /// names the job by ids only, so it is stable and unique per job.
    pub fn subject(&self) -> String {
        let Self {
            repository_id,
            run_id,
            run_attempt,
            check_run_id,
        } = self;
        match check_run_id {
            Some(check_run_id) => {
                format!("github-run:{repository_id}/{run_id}/{run_attempt}/{check_run_id}")
            }
            None => format!("github-run:{repository_id}/{run_id}/{run_attempt}"),
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum RunState {
    Active,
    Finished,
    Expired,
}

#[derive(Debug, PartialEq, Eq)]
pub enum Refusal {
    /// The run finished or expired since the token was presented.
    Closed,
    Busy,
}

#[derive(Debug, PartialEq, Eq)]
pub enum RegisterError {
    AlreadyRegistered,
    Full,
}

/// A run's usage record, returned to its job and logged when it ends. It
/// holds identifiers, model names and numbers only, so it can go in a run
/// footer as is.
#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
pub struct RunRecord {
    pub schema: &'static str,
    pub repository: String,
    pub repository_id: u64,
    pub run_id: u64,
    pub run_attempt: u64,
    pub check_run_id: Option<u64>,
    pub workflow_ref: String,
    pub state: RunState,
    pub registered_at_unix: u64,
    pub expires_at_unix: u64,
    pub finished_at_unix: Option<u64>,
    /// Responses whose usage `token_count` reported.
    pub requests: u64,
    /// Successful responses whose usage never arrived, as when the client
    /// left mid-stream. The run's `token_rate_limit` rule keeps what it
    /// reserved for them.
    pub unmetered: u64,
    pub tokens: Tokens,
    /// `tokens`, by the model upstream says served each response.
    pub models: BTreeMap<String, Tokens>,
}

impl RunRecord {
    fn add(&mut self, usage: Usage) {
        self.requests += 1;
        self.tokens.add(&usage.tokens);
        let Some(model) = usage.model else {
            return;
        };
        if let Some(tokens) = self.models.get_mut(&model) {
            tokens.add(&usage.tokens);
        } else if self.models.len() < MAX_MODELS {
            self.models.insert(model, usage.tokens);
        }
    }
}

struct Run {
    record: RunRecord,
    token_hash: [u8; 32],
    /// The id of the OIDC token that registered the run, which may register
    /// it again to replace a token whose response was lost.
    jti: String,
    concurrency: usize,
    expires: Instant,
    retain_until: Instant,
    in_flight: usize,
}

#[derive(Default)]
struct State {
    runs: HashMap<RunKey, Run>,
    tokens: HashMap<[u8; 32], RunKey>,
}

/// The runs registered with this process, shared by every chain whose
/// `run_token` filter names the same registry.
#[derive(Default)]
pub struct Runs {
    state: Mutex<State>,
}

/// Registries by name. They outlive the filters, which a config reload
/// rebuilds, so runs survive a reload.
static REGISTRIES: LazyLock<Mutex<HashMap<String, Arc<Runs>>>> = LazyLock::new(Mutex::default);

fn lock<T>(mutex: &Mutex<T>) -> MutexGuard<'_, T> {
    mutex.lock().unwrap_or_else(PoisonError::into_inner)
}

fn token_hash(token: &str) -> [u8; 32] {
    Sha256::digest(token.as_bytes()).into()
}

pub fn unix_now() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_or(0, |d| d.as_secs())
}

fn log_record(record: &RunRecord) {
    match serde_json::to_string(record) {
        Ok(json) => info!(record = %json, "run usage"),
        Err(_) => info!(run_id = record.run_id, "run usage unavailable"),
    }
}

impl Runs {
    /// The registry called `name`, created on first use.
    pub fn named(name: &str) -> Arc<Self> {
        Arc::clone(lock(&REGISTRIES).entry(name.to_owned()).or_default())
    }

    fn state(&self, now: Instant) -> MutexGuard<'_, State> {
        let mut state = lock(&self.state);
        state.prune(now);
        state
    }

    /// Register a job's run, once, and mint its bearer token. The same OIDC
    /// token (by `jti`) registering an active run again gets a new token for
    /// it, replacing the old one, so a job whose response was lost can retry;
    /// the run keeps its usage and limits.
    pub fn register(
        &self,
        identity: RunIdentity,
        limits: Limits,
        now: Instant,
    ) -> Result<(String, RunRecord), RegisterError> {
        let mut state = self.state(now);
        let key = identity.key();
        let token = format!("{TOKEN_PREFIX}{}", hex::encode(rand::random::<[u8; 32]>()));
        let hash = token_hash(&token);
        if let Some(run) = state.runs.get_mut(&key) {
            if run.jti != identity.jti || run.record.state != RunState::Active {
                return Err(RegisterError::AlreadyRegistered);
            }
            let old = std::mem::replace(&mut run.token_hash, hash);
            let record = run.record.clone();
            state.tokens.remove(&old);
            state.tokens.insert(hash, key);
            info!(run_id = record.run_id, "run token replaced");
            return Ok((token, record));
        }
        if state.runs.len() >= MAX_RUNS {
            return Err(RegisterError::Full);
        }
        let registered = unix_now();
        let record = RunRecord {
            schema: RECORD_SCHEMA,
            repository: identity.repository,
            repository_id: identity.repository_id,
            run_id: identity.run_id,
            run_attempt: identity.run_attempt,
            check_run_id: identity.check_run_id,
            workflow_ref: identity.workflow_ref,
            state: RunState::Active,
            registered_at_unix: registered,
            expires_at_unix: registered.saturating_add(limits.ttl.as_secs()),
            finished_at_unix: None,
            requests: 0,
            unmetered: 0,
            tokens: Tokens::default(),
            models: BTreeMap::new(),
        };
        info!(
            run_id = record.run_id,
            run_attempt = record.run_attempt,
            repository = %record.repository,
            ttl_secs = limits.ttl.as_secs(),
            "run registered"
        );
        state.tokens.insert(hash, key);
        state.runs.insert(
            key,
            Run {
                record: record.clone(),
                token_hash: hash,
                jti: identity.jti,
                concurrency: limits.concurrency,
                expires: now + limits.ttl,
                retain_until: now + limits.ttl + RETENTION,
                in_flight: 0,
            },
        );
        Ok((token, record))
    }

    /// The run a bearer token belongs to. A finished or expired run's token
    /// still reads its record, so the job gets it even if the agent finished
    /// the run first, but admits no requests.
    pub fn authenticate(&self, token: &str, now: Instant) -> Option<RunKey> {
        self.state(now).tokens.get(&token_hash(token)).copied()
    }

    pub fn record(&self, key: &RunKey, now: Instant) -> Option<RunRecord> {
        self.state(now).runs.get(key).map(|run| run.record.clone())
    }

    /// End a run: it admits no more requests and its record is final, apart
    /// from requests still in flight. Finishing it again returns the record.
    pub fn finish(&self, key: &RunKey, now: Instant) -> Option<RunRecord> {
        let mut state = self.state(now);
        let run = state.runs.get_mut(key)?;
        if run.record.state == RunState::Active {
            run.record.state = RunState::Finished;
            run.record.finished_at_unix = Some(unix_now());
            log_record(&run.record);
        }
        Some(run.record.clone())
    }

    /// Admit a request of an active run within its concurrency.
    pub fn admit(self: &Arc<Self>, key: &RunKey, now: Instant) -> Result<Admission, Refusal> {
        let mut state = self.state(now);
        let run = state.runs.get_mut(key).ok_or(Refusal::Closed)?;
        if run.record.state != RunState::Active {
            return Err(Refusal::Closed);
        }
        if run.in_flight >= run.concurrency {
            return Err(Refusal::Busy);
        }
        run.in_flight += 1;
        Ok(Admission {
            runs: Arc::clone(self),
            key: *key,
            success: false,
            usage_free: false,
            settled: false,
        })
    }

    fn settle(&self, key: &RunKey, outcome: Outcome) {
        let mut state = lock(&self.state);
        let Some(run) = state.runs.get_mut(key) else {
            return;
        };
        run.in_flight = run.in_flight.saturating_sub(1);
        match outcome {
            Outcome::Metered(usage) => run.record.add(usage),
            Outcome::Unmetered => run.record.unmetered += 1,
            Outcome::Failed => {}
        }
    }
}

enum Outcome {
    Metered(Usage),
    Unmetered,
    /// No tokens used: upstream answered with an error, or the request
    /// uses none, like counting tokens.
    Failed,
}

impl State {
    /// Expire runs past their deadline and forget old ones.
    fn prune(&mut self, now: Instant) {
        let Self { runs, tokens } = self;
        for run in runs.values_mut() {
            if run.record.state == RunState::Active && now >= run.expires {
                run.record.state = RunState::Expired;
                log_record(&run.record);
            }
        }
        runs.retain(|_, run| {
            let keep = now < run.retain_until;
            if !keep {
                tokens.remove(&run.token_hash);
            }
            keep
        });
    }
}

/// A request admitted for its run, holding one of its concurrency slots
/// until its response ends. Dropped unsettled, as when the client goes away
/// mid-stream, a successful response counts as unmetered.
pub struct Admission {
    runs: Arc<Runs>,
    key: RunKey,
    /// Upstream answered with a success status.
    pub success: bool,
    /// The request uses no tokens, like counting them, whatever upstream
    /// reports or however its response ends.
    pub usage_free: bool,
    settled: bool,
}

impl Admission {
    /// Record what upstream reported for the response.
    pub fn settle(mut self, reported: Option<Usage>) {
        self.settled = true;
        let outcome = match reported {
            _ if self.usage_free => Outcome::Failed,
            Some(usage) => Outcome::Metered(usage),
            None if self.success => {
                warn!("successful response without usage");
                Outcome::Unmetered
            }
            None => Outcome::Failed,
        };
        self.runs.settle(&self.key, outcome);
    }
}

impl Drop for Admission {
    fn drop(&mut self) {
        if self.settled {
            return;
        }
        let outcome = if self.success && !self.usage_free {
            warn!("response ended before its usage");
            Outcome::Unmetered
        } else {
            Outcome::Failed
        };
        self.runs.settle(&self.key, outcome);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn limits() -> Limits {
        Limits {
            ttl: Duration::from_secs(600),
            concurrency: 2,
        }
    }

    fn identity(run_id: u64) -> RunIdentity {
        RunIdentity {
            repository: "owner/repo".into(),
            repository_id: 7,
            run_id,
            run_attempt: 1,
            check_run_id: None,
            jti: format!("jti-{run_id}"),
            workflow_ref: "owner/repo/.github/workflows/agent.yml@refs/heads/main".into(),
        }
    }

    fn used(total: u64, model: Option<&str>) -> Option<Usage> {
        Some(Usage {
            tokens: Tokens {
                input: total,
                total,
                ..Tokens::default()
            },
            model: model.map(str::to_owned),
        })
    }

    fn register(runs: &Runs, run_id: u64, now: Instant) -> (String, RunKey) {
        let (token, _) = runs.register(identity(run_id), limits(), now).unwrap();
        let key = runs.authenticate(&token, now).unwrap();
        (token, key)
    }

    #[test]
    fn registries_are_shared_by_name() {
        let a = Runs::named("runs-test-shared");
        let now = Instant::now();
        let (token, key) = register(&a, 1, now);
        assert_eq!(
            Runs::named("runs-test-shared").authenticate(&token, now),
            Some(key)
        );
        assert_eq!(
            Runs::named("runs-test-other").authenticate(&token, now),
            None
        );
    }

    #[test]
    fn subjects_name_each_job_apart() {
        let runs = Runs::default();
        let now = Instant::now();
        let mut matrix = identity(1);
        matrix.check_run_id = Some(99);
        let mut retry = identity(1);
        retry.run_attempt = 2;
        let subjects: Vec<String> = [identity(1), matrix, retry, identity(2)]
            .into_iter()
            .map(|identity| {
                let (token, _) = runs.register(identity, limits(), now).unwrap();
                runs.authenticate(&token, now).unwrap().subject()
            })
            .collect();
        assert_eq!(
            subjects,
            [
                "github-run:7/1/1",
                "github-run:7/1/1/99",
                "github-run:7/1/2",
                "github-run:7/2/1"
            ]
        );
    }

    #[test]
    fn a_run_registers_once_and_its_token_authenticates_it() {
        let runs = Runs::default();
        let now = Instant::now();
        let (token, record) = runs.register(identity(1), limits(), now).unwrap();
        assert!(token.starts_with(TOKEN_PREFIX) && token.len() == TOKEN_PREFIX.len() + 64);
        assert_eq!(record.expires_at_unix - record.registered_at_unix, 600);
        assert_eq!(record.state, RunState::Active);
        assert!(runs.authenticate(&token, now).is_some());
        assert!(runs.authenticate("praxis-run-guess", now).is_none());
        // Another OIDC token for the same job can't register it again.
        let mut other_token = identity(1);
        other_token.jti = "another".into();
        assert_eq!(
            runs.register(other_token, limits(), now),
            Err(RegisterError::AlreadyRegistered)
        );
    }

    #[test]
    fn the_same_oidc_token_replaces_a_lost_run_token() {
        let runs = Arc::new(Runs::default());
        let now = Instant::now();
        let (lost, key) = register(&runs, 1, now);
        runs.admit(&key, now).unwrap().settle(used(300, None));
        // Other limits in the retry are ignored: the run keeps its own.
        let shorter = Limits {
            ttl: Duration::from_secs(1),
            ..limits()
        };
        let (token, record) = runs.register(identity(1), shorter, now).unwrap();
        assert_ne!(token, lost);
        assert_eq!(
            (
                record.expires_at_unix - record.registered_at_unix,
                record.tokens.total
            ),
            (600, 300)
        );
        assert_eq!(runs.authenticate(&token, now), Some(key));
        assert_eq!(runs.authenticate(&lost, now), None);
        // Not once the run has ended.
        runs.finish(&key, now);
        assert_eq!(
            runs.register(identity(1), limits(), now),
            Err(RegisterError::AlreadyRegistered)
        );
    }

    #[test]
    fn usage_is_recorded_per_model() {
        let runs = Arc::new(Runs::default());
        let now = Instant::now();
        let (_, key) = register(&runs, 1, now);
        for (total, model) in [(100, Some("a")), (20, Some("b")), (3, Some("a")), (4, None)] {
            runs.admit(&key, now).unwrap().settle(used(total, model));
        }
        // More models than a record keeps count only in the totals.
        for i in 0..MAX_MODELS {
            let model = format!("extra-{i}");
            runs.admit(&key, now).unwrap().settle(used(1, Some(&model)));
        }
        let record = runs.record(&key, now).unwrap();
        assert_eq!(
            (record.requests, record.tokens.total),
            (4 + MAX_MODELS as u64, 127 + MAX_MODELS as u64)
        );
        assert_eq!(record.models.len(), MAX_MODELS);
        assert_eq!(
            (record.models["a"].total, record.models["b"].total),
            (103, 20)
        );
    }

    #[test]
    fn run_concurrency_is_limited_and_dropped_admissions_release() {
        let runs = Arc::new(Runs::default());
        let now = Instant::now();
        let (_, key) = register(&runs, 1, now);
        let a = runs.admit(&key, now).unwrap();
        let _b = runs.admit(&key, now).unwrap();
        assert_eq!(runs.admit(&key, now).err(), Some(Refusal::Busy));
        drop(a);
        let c = runs.admit(&key, now).unwrap();
        drop(c);
        let record = runs.record(&key, now).unwrap();
        assert_eq!((record.requests, record.unmetered), (0, 0));
    }

    #[test]
    fn successful_responses_without_usage_are_unmetered() {
        let runs = Arc::new(Runs::default());
        let now = Instant::now();
        let (_, key) = register(&runs, 1, now);
        // (upstream answered with success, settled or dropped)
        for (success, settled) in [(false, true), (true, true), (false, false), (true, false)] {
            let mut admission = runs.admit(&key, now).unwrap();
            admission.success = success;
            if settled {
                admission.settle(None);
            } else {
                drop(admission);
            }
        }
        // A request that uses no tokens counts as neither, even if
        // upstream reported some or the response ended early.
        for settled in [true, false] {
            let mut admission = runs.admit(&key, now).unwrap();
            (admission.success, admission.usage_free) = (true, true);
            if settled {
                admission.settle(used(5, None));
            } else {
                drop(admission);
            }
        }
        let record = runs.record(&key, now).unwrap();
        assert_eq!(
            (record.requests, record.unmetered, record.tokens.total),
            (0, 2, 0)
        );
        assert_eq!(lock(&runs.state).runs[&key].in_flight, 0);
    }

    #[test]
    fn finished_and_expired_runs_admit_nothing_and_block_reregistration() {
        let runs = Arc::new(Runs::default());
        let now = Instant::now();
        let (token, key) = register(&runs, 1, now);
        let in_flight = runs.admit(&key, now).unwrap();
        let record = runs.finish(&key, now).unwrap();
        assert_eq!(record.state, RunState::Finished);
        assert!(record.finished_at_unix.is_some());
        assert_eq!(runs.finish(&key, now).unwrap(), record);
        // The token still names the run, for its record, but admits nothing.
        assert_eq!(runs.authenticate(&token, now), Some(key));
        assert_eq!(runs.admit(&key, now).err(), Some(Refusal::Closed));
        // A request admitted before the finish is still recorded.
        in_flight.settle(used(5, None));
        assert_eq!(runs.record(&key, now).unwrap().tokens.total, 5);
        assert_eq!(
            runs.register(identity(1), limits(), now),
            Err(RegisterError::AlreadyRegistered)
        );

        let (token, key) = register(&runs, 2, now);
        let expired = now + Duration::from_secs(600);
        assert_eq!(runs.authenticate(&token, expired), Some(key));
        assert_eq!(runs.record(&key, expired).unwrap().state, RunState::Expired);
        assert_eq!(runs.admit(&key, expired).err(), Some(Refusal::Closed));
        // Forgotten after the retention period, so the registry stays bounded.
        let forgotten = expired + RETENTION;
        assert!(runs.authenticate(&token, forgotten).is_none());
        assert!(runs.record(&key, forgotten).is_none());
        assert!(lock(&runs.state).tokens.is_empty());
    }
}
