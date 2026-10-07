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
    collections::{BTreeMap, HashMap, VecDeque},
    net::IpAddr,
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
/// Runs registered without proof that are kept at once, so that they can
/// never fill the registry and keep proven runs out.
pub const MAX_UNPROVEN_RUNS: usize = MAX_RUNS / 4;
/// The longest identifier a run registered without proof may choose.
pub const MAX_RUN_NAME: usize = 128;
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
        RunKey::Github {
            repository_id: self.repository_id,
            run_id: self.run_id,
            run_attempt: self.run_attempt,
            check_run_id: self.check_run_id,
        }
    }
}

/// The identifier of a run registered without proof, which its caller
/// chose: nothing vouches for it. It is short and of letters, digits, `.`,
/// `_` and `-` only, so it can go in a log line or a subject as it is.
#[derive(Clone, Debug, Hash, PartialEq, Eq, Serialize)]
pub struct RunName(String);

impl RunName {
    pub fn new(name: &str) -> Option<Self> {
        let valid = !name.is_empty()
            && name.len() <= MAX_RUN_NAME
            && name
                .bytes()
                .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'.' | b'_' | b'-'));
        valid.then(|| Self(name.to_owned()))
    }
}

/// How many runs may register without proof: `max` in any `window`, from
/// all callers together.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Quota {
    pub max: usize,
    pub window: Duration,
}

impl Quota {
    /// The most runs registered within this quota that are remembered at
    /// once, when each lasts `ttl`. A quota that keeps this within
    /// `MAX_UNPROVEN_RUNS` never finds the registry full.
    pub fn most_remembered(&self, ttl: Duration) -> usize {
        let remembered = (ttl + RETENTION).as_nanos();
        let windows = remembered.div_ceil(self.window.as_nanos().max(1));
        usize::try_from(windows)
            .unwrap_or(usize::MAX)
            .saturating_mul(self.max)
    }
}

#[derive(Clone, Debug, Hash, PartialEq, Eq)]
pub enum RunKey {
    /// A job its GitHub Actions OIDC token named.
    Github {
        repository_id: u64,
        run_id: u64,
        run_attempt: u64,
        check_run_id: Option<u64>,
    },
    /// A run registered without proof, by the name its caller chose.
    Unproven(RunName),
}

impl RunKey {
    /// The run as an authenticated subject, which budgets are keyed on. A
    /// proven run's names the job by ids only, so it is stable and unique
    /// per job. The prefix tells the two kinds apart wherever a subject is
    /// logged, and keeps a chosen name from ever being a proven run's.
    pub fn subject(&self) -> String {
        match self {
            Self::Github {
                repository_id,
                run_id,
                run_attempt,
                check_run_id: Some(check_run_id),
            } => format!("github-run:{repository_id}/{run_id}/{run_attempt}/{check_run_id}"),
            Self::Github {
                repository_id,
                run_id,
                run_attempt,
                check_run_id: None,
            } => format!("github-run:{repository_id}/{run_id}/{run_attempt}"),
            Self::Unproven(RunName(name)) => format!("unproven-run:{name}"),
        }
    }

    pub fn is_unproven(&self) -> bool {
        matches!(self, Self::Unproven(_))
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
    /// The quota of registrations without proof is used up for now.
    OverQuota,
}

/// What a run registered with, and so which run a record is of.
#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
#[serde(tag = "proof", rename_all = "kebab-case")]
pub enum Proof {
    /// A verified GitHub Actions OIDC token, whose claims these are.
    GithubOidc {
        repository: String,
        repository_id: u64,
        run_id: u64,
        run_attempt: u64,
        check_run_id: Option<u64>,
        workflow_ref: String,
    },
    /// Nothing: `run` is whatever the caller said.
    #[serde(rename = "none")]
    Unproven { run: RunName },
}

/// A run's usage record, returned to its job and logged when it ends. It
/// holds identifiers, model names and numbers only, so it can go in a run
/// footer as is.
#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
pub struct RunRecord {
    pub schema: &'static str,
    /// `proof` and, beside it, what names the run.
    #[serde(flatten)]
    pub proof: Proof,
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
    /// it again to replace a token whose response was lost. A run
    /// registered without proof has none: nothing could tell its caller
    /// from another, so it never registers again.
    jti: Option<String>,
    concurrency: usize,
    expires: Instant,
    retain_until: Instant,
    in_flight: usize,
}

#[derive(Default)]
struct State {
    runs: HashMap<RunKey, Run>,
    tokens: HashMap<[u8; 32], RunKey>,
    /// When each registration without proof still inside its quota's
    /// window was admitted, oldest first.
    unproven: VecDeque<Instant>,
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
        Err(_) => info!(run = ?record.proof, "run usage unavailable"),
    }
}

fn new_token() -> (String, [u8; 32]) {
    let token = format!("{TOKEN_PREFIX}{}", hex::encode(rand::random::<[u8; 32]>()));
    let hash = token_hash(&token);
    (token, hash)
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
        let (token, hash) = new_token();
        if let Some(run) = state.runs.get_mut(&key) {
            if run.jti.as_deref() != Some(identity.jti.as_str())
                || run.record.state != RunState::Active
            {
                return Err(RegisterError::AlreadyRegistered);
            }
            let old = std::mem::replace(&mut run.token_hash, hash);
            let record = run.record.clone();
            state.tokens.remove(&old);
            state.tokens.insert(hash, key);
            info!(run_id = identity.run_id, "run token replaced");
            return Ok((token, record));
        }
        if state.runs.len() >= MAX_RUNS {
            return Err(RegisterError::Full);
        }
        info!(
            run_id = identity.run_id,
            run_attempt = identity.run_attempt,
            repository = %identity.repository,
            ttl_secs = limits.ttl.as_secs(),
            "run registered"
        );
        let proof = Proof::GithubOidc {
            repository: identity.repository,
            repository_id: identity.repository_id,
            run_id: identity.run_id,
            run_attempt: identity.run_attempt,
            check_run_id: identity.check_run_id,
            workflow_ref: identity.workflow_ref,
        };
        let record = state.insert(key, proof, Some(identity.jti), hash, limits, now);
        Ok((token, record))
    }

    /// Register a run nothing vouches for, under the name its caller chose,
    /// within `quota`. A name registers once: a second registration is
    /// refused while the first is remembered, whoever sends it, so no
    /// caller can take over or re-arm another's run by naming it.
    pub fn register_unproven(
        &self,
        name: RunName,
        client: Option<IpAddr>,
        limits: Limits,
        quota: Quota,
        now: Instant,
    ) -> Result<(String, RunRecord), RegisterError> {
        let mut state = self.state(now);
        let key = RunKey::Unproven(name.clone());
        if state.runs.contains_key(&key) {
            return Err(RegisterError::AlreadyRegistered);
        }
        while let Some(oldest) = state.unproven.front()
            && now.saturating_duration_since(*oldest) >= quota.window
        {
            state.unproven.pop_front();
        }
        if state.unproven.len() >= quota.max {
            return Err(RegisterError::OverQuota);
        }
        let kept = state.runs.keys().filter(|key| key.is_unproven()).count();
        if kept >= MAX_UNPROVEN_RUNS || state.runs.len() >= MAX_RUNS {
            return Err(RegisterError::Full);
        }
        state.unproven.push_back(now);
        info!(
            run = %key.subject(),
            client = ?client,
            ttl_secs = limits.ttl.as_secs(),
            "unproven run registered"
        );
        let (token, hash) = new_token();
        let record = state.insert(key, Proof::Unproven { run: name }, None, hash, limits, now);
        Ok((token, record))
    }

    /// The run a bearer token belongs to. A finished or expired run's token
    /// still reads its record, so the job gets it even if the agent finished
    /// the run first, but admits no requests.
    pub fn authenticate(&self, token: &str, now: Instant) -> Option<RunKey> {
        self.state(now).tokens.get(&token_hash(token)).cloned()
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
            key: key.clone(),
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
    /// Add a run that starts now, and return its record.
    fn insert(
        &mut self,
        key: RunKey,
        proof: Proof,
        jti: Option<String>,
        token_hash: [u8; 32],
        limits: Limits,
        now: Instant,
    ) -> RunRecord {
        let registered = unix_now();
        let record = RunRecord {
            schema: RECORD_SCHEMA,
            proof,
            state: RunState::Active,
            registered_at_unix: registered,
            expires_at_unix: registered.saturating_add(limits.ttl.as_secs()),
            finished_at_unix: None,
            requests: 0,
            unmetered: 0,
            tokens: Tokens::default(),
            models: BTreeMap::new(),
        };
        self.tokens.insert(token_hash, key.clone());
        self.runs.insert(
            key,
            Run {
                record: record.clone(),
                token_hash,
                jti,
                concurrency: limits.concurrency,
                expires: now + limits.ttl,
                retain_until: now + limits.ttl + RETENTION,
                in_flight: 0,
            },
        );
        record
    }

    /// Expire runs past their deadline and forget old ones.
    fn prune(&mut self, now: Instant) {
        let Self { runs, tokens, .. } = self;
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
    /// Whether the run registered without proof.
    pub fn is_unproven(&self) -> bool {
        self.key.is_unproven()
    }

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
    use serde_json::json;

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
        assert_eq!(runs.authenticate(&token, now).as_ref(), Some(&key));
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
        assert_eq!(runs.authenticate(&token, now).as_ref(), Some(&key));
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
        assert_eq!(runs.authenticate(&token, expired).as_ref(), Some(&key));
        assert_eq!(runs.record(&key, expired).unwrap().state, RunState::Expired);
        assert_eq!(runs.admit(&key, expired).err(), Some(Refusal::Closed));
        // Forgotten after the retention period, so the registry stays bounded.
        let forgotten = expired + RETENTION;
        assert!(runs.authenticate(&token, forgotten).is_none());
        assert!(runs.record(&key, forgotten).is_none());
        assert!(lock(&runs.state).tokens.is_empty());
    }

    const QUOTA: Quota = Quota {
        max: 2,
        window: Duration::from_secs(60),
    };

    fn unproven(runs: &Runs, name: &str, now: Instant) -> Result<String, RegisterError> {
        let name = RunName::new(name).unwrap();
        runs.register_unproven(name, None, limits(), QUOTA, now)
            .map(|(token, _)| token)
    }

    #[test]
    fn a_chosen_run_name_is_short_and_plain() {
        let longest = "a".repeat(MAX_RUN_NAME);
        let too_long = "a".repeat(MAX_RUN_NAME + 1);
        let cases = [
            ("job-1", true),
            ("37530692561.1_retry", true),
            (longest.as_str(), true),
            ("", false),
            (too_long.as_str(), false),
            ("a b", false),
            ("a/b", false),
            ("a:b", false),
            ("a\nb", false),
            ("a\"b", false),
            ("\u{e9}", false),
        ];
        for (name, valid) in cases {
            assert_eq!(RunName::new(name).is_some(), valid, "{name:?}");
        }
    }

    #[test]
    fn an_unproven_run_is_a_run_like_any_other_under_a_subject_of_its_own_kind() {
        let runs = Arc::new(Runs::default());
        let now = Instant::now();
        let token = unproven(&runs, "7", now).unwrap();
        let key = runs.authenticate(&token, now).unwrap();
        // Never the subject of a proven run, whatever name is chosen.
        assert_eq!(key.subject(), "unproven-run:7");
        assert!(key.is_unproven());
        let (_, proven) = register(&runs, 7, now);
        assert!(!proven.is_unproven());
        // The same lifetime, concurrency and metering as a proven run.
        let a = runs.admit(&key, now).unwrap();
        let b = runs.admit(&key, now).unwrap();
        assert_eq!(runs.admit(&key, now).err(), Some(Refusal::Busy));
        a.settle(used(100, Some("m")));
        b.settle(used(20, None));
        let record = runs.finish(&key, now).unwrap();
        assert_eq!(runs.admit(&key, now).err(), Some(Refusal::Closed));
        assert_eq!(
            (record.state, record.requests, record.tokens.total),
            (RunState::Finished, 2, 120)
        );
        assert_eq!(record.expires_at_unix - record.registered_at_unix, 600);
        // A record says which kind of run it is of.
        let json = serde_json::to_value(&record).unwrap();
        assert_eq!(
            (&json["proof"], &json["run"]),
            (&json!("none"), &json!("7"))
        );
        assert!(json.get("repository").is_none() && json.get("run_id").is_none());
        let json = serde_json::to_value(runs.record(&proven, now).unwrap()).unwrap();
        assert_eq!(
            (&json["proof"], &json["run_id"], &json["repository"]),
            (&json!("github-oidc"), &json!(7), &json!("owner/repo"))
        );
        assert!(json.get("run").is_none());
    }

    #[test]
    fn a_chosen_run_name_registers_once_while_it_is_remembered() {
        let runs = Arc::new(Runs::default());
        let now = Instant::now();
        let token = unproven(&runs, "job", now).unwrap();
        let key = runs.authenticate(&token, now).unwrap();
        // Unlike a proven run's, a lost token is not replaced: nothing
        // tells the caller that lost it from any other.
        assert_eq!(
            unproven(&runs, "job", now),
            Err(RegisterError::AlreadyRegistered)
        );
        assert_eq!(runs.authenticate(&token, now), Some(key.clone()));
        runs.finish(&key, now);
        assert_eq!(
            unproven(&runs, "job", now),
            Err(RegisterError::AlreadyRegistered)
        );
        // Refused registrations used none of the quota.
        let token = unproven(&runs, "other", now).unwrap();
        let other = runs.authenticate(&token, now).unwrap();
        let expired = now + Duration::from_secs(600);
        assert_eq!(
            runs.record(&other, expired).unwrap().state,
            RunState::Expired
        );
        assert_eq!(
            unproven(&runs, "other", expired),
            Err(RegisterError::AlreadyRegistered)
        );
        // Once forgotten, the name is free again.
        assert!(unproven(&runs, "job", expired + RETENTION).is_ok());
    }

    #[test]
    fn a_quota_says_how_many_of_its_runs_are_remembered_at_once() {
        let hour = Duration::from_secs(3600);
        // (registrations, their window, a run's lifetime, runs remembered)
        let cases = [
            // A day's retention and six hours' life: thirty windows.
            (8, hour, 6 * hour, 240),
            (34, hour, 6 * hour, 1020),
            (35, hour, 6 * hour, 1050),
            // A window in progress counts whole.
            (1, 7 * hour, 6 * hour, 5),
            (1, 31 * hour, 6 * hour, 1),
            (8, Duration::from_secs(60), 6 * hour, 14400),
            (usize::MAX, hour, hour, usize::MAX),
        ];
        for (max, window, ttl, remembered) in cases {
            let quota = Quota { max, window };
            assert_eq!(quota.most_remembered(ttl), remembered, "{quota:?}");
        }
    }

    #[test]
    fn unproven_registrations_are_limited_per_window_and_proven_ones_are_not() {
        // By name, as each filter a reload builds finds the registry: the
        // quota is the registry's, so a reload does not refill it.
        let registry = || Runs::named("runs-test-quota");
        let start = Instant::now();
        // (seconds since the start, name, admitted)
        let steps = [
            (0, "a", true),
            (10, "b", true),
            (20, "c", false),
            (59, "c", false),
            // "a" has left the window.
            (60, "c", true),
            (61, "d", false),
            (70, "d", true),
            (71, "e", false),
        ];
        for (secs, name, admitted) in steps {
            let now = start + Duration::from_secs(secs);
            let expected = if admitted {
                Ok(())
            } else {
                Err(RegisterError::OverQuota)
            };
            assert_eq!(
                unproven(&registry(), name, now).map(drop),
                expected,
                "{name}"
            );
            assert!(registry().register(identity(secs), limits(), now).is_ok());
        }
    }

    #[test]
    fn unproven_runs_never_fill_the_registry() {
        let runs = Runs::default();
        let now = Instant::now();
        let quota = Quota {
            max: usize::MAX,
            window: Duration::from_secs(60),
        };
        let register = |i: usize| {
            let name = RunName::new(&format!("run-{i}")).unwrap();
            runs.register_unproven(name, None, limits(), quota, now)
                .map(drop)
        };
        for i in 0..MAX_UNPROVEN_RUNS {
            assert_eq!(register(i), Ok(()), "{i}");
        }
        assert_eq!(register(MAX_UNPROVEN_RUNS), Err(RegisterError::Full));
        assert!(runs.register(identity(1), limits(), now).is_ok());
    }
}
