//! The `run_token` filter: per-run bearer tokens, and the credential mode of
//! each route.
//!
//! On a chain with `registration` configured it serves the run endpoints:
//!
//! - `POST /v1/runs`, authenticated by an Actions OIDC token of GitHub or of
//!   another issuer the policy names, registers the job's run and returns
//!   its bearer token and usage record. If the
//!   policy has `unproven`, off by default, a request with no
//!   `Authorization` registers the run its `x-run-id` names instead, with
//!   no proof of who sends it;
//! - `GET /v1/runs/self` returns the calling run's usage record;
//! - `DELETE /v1/runs/self` finishes the run and returns its final record.
//!
//! It runs after the router, and `credentials` gives the [`CredentialMode`]
//! of every cluster the router may pick, the same key `credential_injection`
//! uses, so whether a request needs a run token and whose credential goes
//! upstream are decided by one choice. A cluster with no mode is refused.
//!
//! - `injected`: the broker supplies the upstream credential, so every
//!   request must carry a run token in the first of `token_headers` it has.
//!   It is admitted against the run's lifetime and concurrency, and the run
//!   becomes the request's [`AuthenticatedIdentity`], so that a
//!   `token_rate_limit` rule later in the chain (`key:
//!   authenticated_subject`) caps each run's tokens. With `operators`
//!   configured, an operator token (see [`crate::operators`]) in that
//!   header is admitted instead, for the clusters its entry names, as an
//!   identity of its own.
//! - `pass-through`: the caller's own `Authorization` goes upstream as it
//!   is, and no run token is needed or looked for.
//!
//! Either way the token headers are removed before the request goes
//! upstream, and once the response ends its usage, as `token_count`
//! recorded it, is logged and charged to the run's record, unless the path
//! is one of `usage_free_paths`, such as counting tokens. `token_count`
//! must come after this filter in the chain, so that it sees each response
//! chunk first.
//!
//! Requests with more than one `Authorization` header are refused: the
//! router matches a header against any of its values, conditions against the
//! first, and the two must agree on which route a request takes.
use crate::{
    oidc::{
        AnyWorkflow, CalledWorkflow, ClaimSet, DEFAULT_AUDIENCE, DEFAULT_MAX_TOKEN_AGE_SECS,
        GITHUB_JWKS, GITHUB_NAME, Oidc, OidcError, Policy, TokenIssuer, TrustedIssuer, present,
    },
    operators::{self, Operators},
    runs::{
        Admission, Limits, MAX_UNPROVEN_RUNS, Quota, Refusal, RegisterError, RunKey, RunName, Runs,
        TOKEN_PREFIX, Tokens, Usage,
    },
    usage::{BrokerUsage, Provider},
};
use async_trait::async_trait;
use bytes::Bytes;
use http::{HeaderMap, HeaderName, HeaderValue, Method, header};
use praxis_ai_filters::{
    META_TOKEN_CACHE_READ, META_TOKEN_INPUT, META_TOKEN_MODEL, META_TOKEN_OUTPUT,
    META_TOKEN_REASONING, META_TOKEN_STATUS, META_TOKEN_TOTAL,
};
use praxis_filter::{
    AuthenticatedIdentity, BodyAccess, FilterAction, FilterError, HttpFilter, HttpFilterContext,
    Rejection, Request, TerminalResponse, parse_filter_config,
};
use serde::Deserialize;
use std::{
    collections::{HashMap, HashSet},
    io::ErrorKind,
    iter,
    net::IpAddr,
    path::{Path, PathBuf},
    sync::{Arc, Mutex},
    time::Duration,
    time::Instant,
};
use tracing::{debug, info, warn};

pub const FILTER_NAME: &str = "run_token";
const RUNS_PATH: &str = "/v1/runs";
const RUN_SELF_PATH: &str = "/v1/runs/self";
const USAGE_PATH: &str = "/usage";
/// Where the review dashboard is served from.
const DEFAULT_USAGE_ORIGIN: &str = "https://cgwalters-forge.github.io";
const USAGE_METHODS: HeaderValue = HeaderValue::from_static("GET, OPTIONS");
/// How long a browser may reuse a preflight answer, in seconds.
const PREFLIGHT_MAX_AGE: HeaderValue = HeaderValue::from_static("600");
/// Private Network Access: a public page asks before it reads a private
/// address, and proceeds only if told it may.
const REQUEST_PRIVATE_NETWORK: HeaderName =
    HeaderName::from_static("access-control-request-private-network");
const ALLOW_PRIVATE_NETWORK: HeaderName =
    HeaderName::from_static("access-control-allow-private-network");
/// The name a run registered without proof chooses for itself. A header,
/// and not one a web page may send unasked, so that a browser on the
/// deployment's network preflights the registration, which nothing allows.
const RUN_ID: HeaderName = HeaderName::from_static("x-run-id");
/// What a browser adds to a page's request, and a page cannot remove. A
/// page is same-origin, and so asks nothing first, once its own host name
/// resolves to the gateway (DNS rebinding); these still give it away.
const SEC_FETCH_SITE: HeaderName = HeaderName::from_static("sec-fetch-site");
const BROWSER_HEADERS: [HeaderName; 2] = [header::ORIGIN, SEC_FETCH_SITE];
/// The window of the quota of registrations without proof, unless the
/// policy gives one.
const DEFAULT_UNPROVEN_WINDOW_SECS: u64 = 3600;
const DEFAULT_REGISTRY: &str = "default";
const DEFAULT_MAX_SECS: u64 = 6 * 3600;
const DEFAULT_CONCURRENCY: usize = 4;
/// The longest a run may last; also keeps deadlines far from overflowing.
const MAX_SECS: u64 = 30 * 24 * 3600;
/// The only event that may register runs unless `events` says otherwise.
const DEFAULT_EVENT: &str = "workflow_dispatch";
/// Beside only the entries that have events of their own, a reader would
/// take these for a limit on them, which they are not.
const NARROWS_WORKFLOWS_ONLY: &str = "events and entry_workflows apply to `workflows` only; give called_workflows and any_workflow their own events";

fn default_registry() -> String {
    DEFAULT_REGISTRY.to_owned()
}

fn default_usage_origins() -> HashSet<String> {
    HashSet::from([DEFAULT_USAGE_ORIGIN.to_owned()])
}

fn default_token_headers() -> Vec<String> {
    vec![header::AUTHORIZATION.as_str().to_owned()]
}

/// Whose credential a route sends upstream.
#[derive(Clone, Copy, Debug, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "kebab-case")]
pub enum CredentialMode {
    /// The broker's own, added by `credential_injection` or
    /// credential-proxy; only for requests of a registered run.
    Injected,
    /// The caller's own, forwarded and never stored.
    PassThrough,
}

impl CredentialMode {
    fn as_str(self) -> &'static str {
        match self {
            Self::Injected => "injected",
            Self::PassThrough => "pass-through",
        }
    }
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct Config {
    /// Chains whose filters name the same registry share its runs.
    #[serde(default = "default_registry")]
    registry: String,
    /// Where requests carry their run token: a bearer token in
    /// `authorization`, or the bare token in any other header. The first of
    /// these headers a request has is the one that must hold its token, so
    /// a client that needs `authorization` for itself (Claude Code) can put
    /// the run token in another one listed before it.
    #[serde(default = "default_token_headers")]
    token_headers: Vec<String>,
    /// Exact paths that need no run token, such as a health check.
    #[serde(default)]
    public_paths: HashSet<String>,
    /// Exact paths whose responses use no tokens, such as counting them:
    /// their requests are admitted like any other, but a run is charged
    /// nothing for them, and they count as neither metered nor unmetered.
    #[serde(default)]
    usage_free_paths: HashSet<String>,
    /// The credential mode of each cluster the router may pick.
    credentials: HashMap<String, CredentialMode>,
    /// The origins, each exactly as a browser sends it in `Origin`, whose
    /// pages may read `/usage`. Anything else that can reach the listener
    /// can read it too; this only decides which web pages a browser lets.
    #[serde(default = "default_usage_origins")]
    usage_cors_origins: HashSet<String>,
    /// Serve the run endpoints on this chain.
    registration: Option<RegistrationConfig>,
    /// Admit operator tokens to injected routes.
    operators: Option<OperatorsConfig>,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct OperatorsConfig {
    /// Who holds an operator token, and for which clusters (see
    /// [`crate::operators`]). Without this file there are none.
    tokens_file: PathBuf,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct RegistrationConfig {
    /// Which jobs may register runs (a [`PolicyFile`]). Without this file
    /// nothing can register, so every request needing a run token is
    /// refused: the deployment is simply not in run-token mode.
    policy_file: PathBuf,
}

/// The registration policy, kept in a file of its own so that it is the only
/// part of the configuration each deployment writes. Its entries for
/// tokens (`workflows` and the keys that narrow it, `called_workflows`,
/// `any_workflow`), with `audience` and `jwks_url`, are GitHub's; any other
/// issuer has an entry of `issuers` with its own.
#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct PolicyFile {
    #[serde(default = "default_audience")]
    audience: String,
    #[serde(default = "default_jwks_url")]
    jwks_url: String,
    /// Issuers besides GitHub whose tokens may register runs, each under
    /// rules of its own. Off unless present.
    #[serde(default)]
    issuers: Vec<IssuerEntry>,
    /// Exact `job_workflow_ref` claims that may register runs. None, with
    /// `unproven`, means no run registers by proof.
    #[serde(default)]
    workflows: HashSet<String>,
    #[serde(default)]
    repository_ids: HashSet<u64>,
    #[serde(default)]
    owner_ids: HashSet<u64>,
    /// Entry workflows (`workflow_ref`) that may call the job's workflow;
    /// by default only the job's own.
    entry_workflows: Option<HashSet<String>>,
    /// Events that may start a workflow of `workflows`; `workflow_dispatch`
    /// if left out.
    #[serde(default, deserialize_with = "present")]
    events: Option<HashSet<String>>,
    /// Workflows admitted wherever they run, such as a reusable workflow
    /// called from another repository. Off unless present.
    #[serde(default)]
    called_workflows: Vec<CalledWorkflow>,
    /// Admit every workflow of some repositories, or of all. Off unless
    /// present.
    #[serde(default, deserialize_with = "present")]
    any_workflow: Option<AnyWorkflow>,
    /// How long a run lasts. The window of the `token_rate_limit` rule that
    /// caps runs must be at least this long.
    #[serde(default = "default_max_secs")]
    max_secs: u64,
    #[serde(default = "default_concurrency")]
    concurrency: usize,
    /// Also register runs that prove nothing. Off unless present.
    unproven: Option<UnprovenConfig>,
}

/// An issuer besides GitHub, such as a Forgejo instance, and the rules for
/// its tokens: the keys GitHub has at the top level of the file, read the
/// same way, and matched against this issuer's tokens only.
#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct IssuerEntry {
    /// What the runs of this issuer are keyed, metered and recorded under,
    /// so that its ids are never taken for another issuer's.
    name: String,
    /// The `iss` claim of its tokens, exactly.
    issuer: String,
    jwks_url: String,
    /// Accept plaintext `http://` for `issuer` and `jwks_url`. Whoever can
    /// answer for that host name on the network then chooses the keys.
    #[serde(default)]
    allow_http: bool,
    /// Which claims its tokens carry. Never guessed.
    claims: ClaimSet,
    #[serde(default = "default_audience")]
    audience: String,
    /// The oldest a token may be, by its `iat`, whatever its `exp`.
    #[serde(default = "default_max_token_age_secs")]
    max_token_age_secs: u64,
    #[serde(default)]
    workflows: HashSet<String>,
    #[serde(default)]
    repository_ids: HashSet<u64>,
    #[serde(default)]
    owner_ids: HashSet<u64>,
    entry_workflows: Option<HashSet<String>>,
    #[serde(default, deserialize_with = "present")]
    events: Option<HashSet<String>>,
    #[serde(default)]
    called_workflows: Vec<CalledWorkflow>,
    #[serde(default, deserialize_with = "present")]
    any_workflow: Option<AnyWorkflow>,
}

/// The entries for one issuer's tokens, as the policy file has them.
struct Entries {
    workflows: HashSet<String>,
    repository_ids: HashSet<u64>,
    owner_ids: HashSet<u64>,
    entry_workflows: Option<HashSet<String>>,
    events: Option<HashSet<String>>,
    called_workflows: Vec<CalledWorkflow>,
    any_workflow: Option<AnyWorkflow>,
}

impl Entries {
    /// Whether a key that narrows `workflows`, and no other entry, is
    /// written.
    fn narrows_workflows(&self) -> bool {
        self.events.is_some() || self.entry_workflows.is_some()
    }

    /// The policy these make for tokens of `audience`.
    fn policy(self, audience: String) -> Policy {
        Policy {
            audience,
            workflows: self.workflows,
            repository_ids: self.repository_ids,
            owner_ids: self.owner_ids,
            entry_workflows: self.entry_workflows,
            events: self.events.unwrap_or_else(default_events),
            called_workflows: self.called_workflows,
            any_workflow: self.any_workflow,
        }
    }
}

/// Registration without an identity token: whatever can reach the listener
/// may register a run under a name it chooses, and so use the broker's
/// credentials within a run's caps. The gateway cannot tell a job from its
/// agent or from any other peer, so the network is the only gate, and the
/// quota is all that bounds how many fresh per-run caps a caller mints.
#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct UnprovenConfig {
    /// Registrations admitted in any window, from all callers together.
    max_registrations: usize,
    #[serde(default = "default_unproven_window_secs")]
    window_secs: u64,
}

impl UnprovenConfig {
    /// The quota this asks for, for runs that each last `ttl`. One whose
    /// runs could outnumber what the registry remembers is refused, so
    /// that no quota a gateway starts with can find the registry full and
    /// stall every registration until old runs are forgotten.
    fn quota(&self, ttl: Duration) -> Result<Quota, String> {
        if self.max_registrations == 0 {
            return Err("unproven.max_registrations must be positive".into());
        }
        if !(1..=MAX_SECS).contains(&self.window_secs) {
            return Err(format!("unproven.window_secs must be from 1 to {MAX_SECS}"));
        }
        let quota = Quota {
            max: self.max_registrations,
            window: Duration::from_secs(self.window_secs),
        };
        let remembered = quota.most_remembered(ttl);
        if remembered > MAX_UNPROVEN_RUNS {
            return Err(format!(
                "unproven: at this rate up to {remembered} runs would be remembered at once, and at most {MAX_UNPROVEN_RUNS} are; lower max_registrations or lengthen window_secs"
            ));
        }
        Ok(quota)
    }
}

fn default_unproven_window_secs() -> u64 {
    DEFAULT_UNPROVEN_WINDOW_SECS
}
fn default_audience() -> String {
    DEFAULT_AUDIENCE.to_owned()
}
fn default_jwks_url() -> String {
    GITHUB_JWKS.to_owned()
}
fn default_max_token_age_secs() -> u64 {
    DEFAULT_MAX_TOKEN_AGE_SECS
}
fn default_events() -> HashSet<String> {
    HashSet::from([DEFAULT_EVENT.to_owned()])
}
fn default_max_secs() -> u64 {
    DEFAULT_MAX_SECS
}
fn default_concurrency() -> usize {
    DEFAULT_CONCURRENCY
}

/// Refusals of one issuer and kind logged per [`REFUSAL_LOG_WINDOW`]; the
/// rest are counted, and the count is logged with the next that is.
const REFUSALS_LOGGED_PER_WINDOW: u32 = 5;
const REFUSAL_LOG_WINDOW: Duration = Duration::from_secs(60);

/// Why a registration that claimed proof was refused, as logged.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
enum RefusalKind {
    /// No issuer is trusted: the policy registers only without proof.
    NoIssuers,
    /// No bearer token in `Authorization`.
    NoToken,
    Malformed,
    /// A bad signature, audience, issuer, age or validity period.
    Invalid,
    /// Verified, but no entry of its issuer's policy admits it.
    NotAllowed,
    AlreadyRegistered,
}

impl RefusalKind {
    fn as_str(self) -> &'static str {
        match self {
            Self::NoIssuers => "no_issuers",
            Self::NoToken => "no_token",
            Self::Malformed => "malformed",
            Self::Invalid => "invalid",
            Self::NotAllowed => "not_allowed",
            Self::AlreadyRegistered => "already_registered",
        }
    }
}

/// Logs refused registrations, a few per issuer and kind in each window,
/// so that a wrong `iss` can be told from a policy that admits nothing,
/// and a flood of bad tokens does not flood the log. Every unknown issuer
/// shares one budget, whatever `iss` it claims, so the keys are bounded by
/// the policy's issuers, and a flood of one kind hides nothing of another
/// kind or of another trusted issuer.
#[derive(Default)]
struct RefusalLog {
    windows: Mutex<HashMap<(Option<String>, RefusalKind), RefusalWindow>>,
}

struct RefusalWindow {
    started: Instant,
    logged: u32,
    /// Refusals not logged since the last that was.
    suppressed: u64,
}

impl RefusalLog {
    fn refused(&self, issuer: &TokenIssuer, kind: RefusalKind, now: Instant) {
        let Some(suppressed) = self.admit(issuer, kind, now) else {
            return;
        };
        info!(
            issuer = issuer.name(),
            // A str, so quoted: escaping alone leaves spaces, and with
            // them `iss` could pass for more fields.
            claimed_iss = issuer.claimed(),
            kind = kind.as_str(),
            suppressed,
            "run registration refused"
        );
    }

    /// Whether to log this refusal, and if so how many went unlogged
    /// before it.
    fn admit(&self, issuer: &TokenIssuer, kind: RefusalKind, now: Instant) -> Option<u64> {
        let key = match issuer {
            TokenIssuer::Known(name) => Some(name.clone()),
            TokenIssuer::Unknown(_) => None,
        };
        let mut windows = self.windows.lock().unwrap_or_else(|e| e.into_inner());
        let window = windows.entry((key, kind)).or_insert(RefusalWindow {
            started: now,
            logged: 0,
            suppressed: 0,
        });
        if now.saturating_duration_since(window.started) >= REFUSAL_LOG_WINDOW {
            window.started = now;
            window.logged = 0;
        }
        if window.logged >= REFUSALS_LOGGED_PER_WINDOW {
            window.suppressed += 1;
            return None;
        }
        window.logged += 1;
        Some(std::mem::take(&mut window.suppressed))
    }
}

/// Verifies registrations against the policy.
struct Registrar {
    /// None if the policy admits no issuer's tokens: only `unproven`
    /// registers.
    oidc: Option<Oidc>,
    /// The quota of registrations without proof, if the policy admits them.
    unproven: Option<Quota>,
    limits: Limits,
    refusals: RefusalLog,
}

/// The run endpoints of a chain.
enum RunEndpoints {
    /// Not served on this chain.
    Absent,
    /// Served, but with no policy file nothing may register.
    Unconfigured,
    Serving(Box<Registrar>),
}

pub struct RunTokenFilter {
    runs: Arc<Runs>,
    usage: Arc<BrokerUsage>,
    token_headers: Vec<HeaderName>,
    public_paths: HashSet<String>,
    usage_free_paths: HashSet<String>,
    credentials: HashMap<String, CredentialMode>,
    usage_cors_origins: HashSet<String>,
    endpoints: RunEndpoints,
    operators: Operators,
}

/// Who an injected request was admitted for. Either holds one of its
/// holder's concurrency slots until the response ends.
enum Caller {
    Run(Admission),
    Operator(operators::Slot),
}

/// What a request was admitted as, for its usage once the response ends.
struct Metered {
    mode: CredentialMode,
    provider: Option<Provider>,
    success: bool,
    /// Whose request it is, unless it is pass-through.
    caller: Option<Caller>,
}

impl RunTokenFilter {
    /// Build the filter from its YAML config.
    ///
    /// # Errors
    ///
    /// Returns an error for an invalid config, or a policy file that can't
    /// be read or would trust repositories by name only.
    pub fn from_config(config: &serde_yaml::Value) -> Result<Box<dyn HttpFilter>, FilterError> {
        let config: Config = parse_filter_config(FILTER_NAME, config)?;
        let token_headers = config
            .token_headers
            .into_iter()
            .map(HeaderName::try_from)
            .collect::<Result<Vec<_>, _>>()
            .map_err(|e| format!("{FILTER_NAME}: invalid token_headers: {e}"))?;
        if token_headers.is_empty() {
            return Err(format!("{FILTER_NAME}: token_headers must name a header").into());
        }
        if config.credentials.is_empty() {
            return Err(format!("{FILTER_NAME}: credentials must name a cluster").into());
        }
        let endpoints = match config.registration {
            None => RunEndpoints::Absent,
            Some(registration) => match Registrar::load(&registration.policy_file)? {
                Some(registrar) => RunEndpoints::Serving(Box::new(registrar)),
                None => RunEndpoints::Unconfigured,
            },
        };
        let injected = config
            .credentials
            .iter()
            .filter(|(_, mode)| **mode == CredentialMode::Injected)
            .map(|(cluster, _)| cluster.as_str())
            .collect();
        let operators = match &config.operators {
            None => Operators::default(),
            Some(operators) => Operators::load(&operators.tokens_file, &injected)
                .map_err(|e| format!("{FILTER_NAME}: {e}"))?,
        };
        let usage = BrokerUsage::named(&config.registry);
        if let RunEndpoints::Serving(registrar) = &endpoints
            && registrar.unproven.is_some()
        {
            usage.declare_unproven();
        }
        for operator in operators.names() {
            usage.declare_operator(operator);
        }
        Ok(Box::new(Self {
            runs: Runs::named(&config.registry),
            usage,
            token_headers,
            public_paths: config.public_paths,
            usage_free_paths: config.usage_free_paths,
            credentials: config.credentials,
            usage_cors_origins: config.usage_cors_origins,
            endpoints,
            operators,
        }))
    }

    /// The run token a request carries, if any, and its header.
    fn token<'a>(&self, headers: &'a HeaderMap) -> Option<(&HeaderName, &'a str)> {
        let (name, value) = self
            .token_headers
            .iter()
            .find_map(|name| Some((name, headers.get(name)?)))?;
        let value = value.to_str().ok()?;
        let token = if *name == header::AUTHORIZATION {
            value.strip_prefix("Bearer ")?
        } else {
            value
        };
        Some((name, token))
    }

    fn run_of(&self, headers: &HeaderMap, now: Instant) -> Option<RunKey> {
        self.runs.authenticate(self.token(headers)?.1, now)
    }

    /// Admit an injected request for `cluster` by the token it carries: an
    /// operator's, or else an active run's. The subject is who it is for.
    fn admit(&self, headers: &HeaderMap, cluster: &str) -> Result<(String, Caller), FilterAction> {
        let unauthenticated = || reject(401, "client authentication required\n");
        let (_, token) = self.token(headers).ok_or_else(unauthenticated)?;
        if let Some(operator) = self.operators.authenticate(token) {
            return match operator.admit(cluster) {
                Ok(slot) => Ok((operator.subject(), Caller::Operator(slot))),
                Err(operators::Refusal::Forbidden) => {
                    Err(reject(403, "this operator token is not for this route\n"))
                }
                Err(operators::Refusal::Busy) => Err(reject(
                    429,
                    "too many requests in flight for this operator\n",
                )),
            };
        }
        let now = Instant::now();
        let key = self
            .runs
            .authenticate(token, now)
            .ok_or_else(unauthenticated)?;
        match self.runs.admit(&key, now) {
            Ok(admission) => Ok((key.subject(), Caller::Run(admission))),
            Err(Refusal::Closed) => Err(unauthenticated()),
            Err(Refusal::Busy) => Err(reject(429, "too many requests in flight for this run\n")),
        }
    }

    /// Answer `/usage`: the broker's usage, or the preflight a browser sends
    /// before it lets a page read it. Only an allowed origin gets the CORS
    /// headers, and never the one for credentials: the read needs none.
    fn serve_usage(&self, request: &Request) -> FilterAction {
        let origin = request.headers.get(header::ORIGIN).filter(|origin| {
            origin
                .to_str()
                .is_ok_and(|origin| self.usage_cors_origins.contains(origin))
        });
        // Either answer depends on who asks.
        let mut headers =
            HeaderMap::from_iter([(header::VARY, HeaderValue::from_static("origin"))]);
        if let Some(origin) = origin {
            headers.insert(header::ACCESS_CONTROL_ALLOW_ORIGIN, origin.clone());
        }
        match request.method {
            Method::GET => json_with(200, &self.usage.snapshot(), headers),
            Method::OPTIONS if origin.is_some() => {
                headers.insert(header::ACCESS_CONTROL_ALLOW_METHODS, USAGE_METHODS);
                headers.insert(header::ACCESS_CONTROL_MAX_AGE, PREFLIGHT_MAX_AGE);
                if request.headers.contains_key(REQUEST_PRIVATE_NETWORK) {
                    headers.insert(ALLOW_PRIVATE_NETWORK, HeaderValue::from_static("true"));
                }
                FilterAction::TerminalResponse(Box::new(
                    TerminalResponse::new(204).with_headers(headers),
                ))
            }
            Method::OPTIONS => reject(403, "origin not allowed\n"),
            _ => reject(405, "method not allowed\n"),
        }
    }

    async fn serve_runs(
        &self,
        registrar: Option<&Registrar>,
        request: &Request,
        client: Option<IpAddr>,
    ) -> FilterAction {
        let now = Instant::now();
        match (request.uri.path(), &request.method) {
            (RUNS_PATH, &Method::POST) => match registrar {
                Some(registrar) => self.register(registrar, &request.headers, client).await,
                None => reject(503, "run registration is not configured\n"),
            },
            (RUN_SELF_PATH, &Method::GET) => {
                match self
                    .run_of(&request.headers, now)
                    .and_then(|key| self.runs.record(&key, now))
                {
                    Some(record) => json(200, &record),
                    None => reject(401, "client authentication required\n"),
                }
            }
            (RUN_SELF_PATH, &Method::DELETE) => {
                match self
                    .run_of(&request.headers, now)
                    .and_then(|key| self.runs.finish(&key, now))
                {
                    Some(record) => json(200, &record),
                    None => reject(401, "client authentication required\n"),
                }
            }
            (RUNS_PATH | RUN_SELF_PATH, _) => reject(405, "method not allowed\n"),
            _ => reject(404, "not found\n"),
        }
    }

    async fn register(
        &self,
        registrar: &Registrar,
        headers: &HeaderMap,
        client: Option<IpAddr>,
    ) -> FilterAction {
        // Anything in Authorization is a claim of proof, checked as one.
        if let Some(quota) = registrar.unproven
            && !headers.contains_key(header::AUTHORIZATION)
        {
            return self.register_unproven(quota, registrar.limits, headers, client);
        }
        let jwt = headers
            .get(header::AUTHORIZATION)
            .and_then(|v| v.to_str().ok())
            .and_then(|v| v.strip_prefix("Bearer "));
        // Logged under the issuer the token claims, and nothing else of it.
        let refused = |kind, status, message| {
            let issuer = match (&registrar.oidc, jwt) {
                (Some(oidc), Some(jwt)) => oidc.issuer_of(jwt),
                (None, Some(jwt)) => TokenIssuer::unknown(jwt),
                (_, None) => TokenIssuer::Unknown(None),
            };
            registrar.refusals.refused(&issuer, kind, Instant::now());
            reject(status, message)
        };
        let Some(oidc) = &registrar.oidc else {
            return refused(
                RefusalKind::NoIssuers,
                403,
                "workflow may not register runs\n",
            );
        };
        let Ok(_permit) = oidc.registrations.try_acquire() else {
            return reject(429, "too many registrations\n");
        };
        let Some(jwt) = jwt else {
            return refused(RefusalKind::NoToken, 401, "OIDC token required\n");
        };
        let identity = match oidc.verify(jwt).await {
            Ok(identity) => identity,
            Err(OidcError::Unavailable) => return reject(503, "OIDC keys unavailable\n"),
            Err(OidcError::WorkflowNotAllowed) => {
                return refused(
                    RefusalKind::NotAllowed,
                    403,
                    "workflow may not register runs\n",
                );
            }
            Err(OidcError::Malformed) => {
                return refused(RefusalKind::Malformed, 401, "invalid OIDC token\n");
            }
            Err(OidcError::Invalid) => {
                return refused(RefusalKind::Invalid, 401, "invalid OIDC token\n");
            }
        };
        match self
            .runs
            .register(identity, registrar.limits, Instant::now())
        {
            Ok((token, usage)) => json(201, &serde_json::json!({ "token": token, "usage": usage })),
            Err(RegisterError::AlreadyRegistered) => refused(
                RefusalKind::AlreadyRegistered,
                409,
                "run already registered\n",
            ),
            Err(RegisterError::Full | RegisterError::OverQuota) => reject(503, "too many runs\n"),
        }
    }

    /// Register the run `x-run-id` names, on the caller's word alone.
    fn register_unproven(
        &self,
        quota: Quota,
        limits: Limits,
        headers: &HeaderMap,
        client: Option<IpAddr>,
    ) -> FilterAction {
        if BROWSER_HEADERS
            .iter()
            .any(|name| headers.contains_key(name))
        {
            return reject(403, "a web page may not register a run\n");
        }
        let mut names = headers.get_all(RUN_ID).iter();
        let (Some(name), None) = (names.next(), names.next()) else {
            return reject(400, "one x-run-id header required\n");
        };
        let Some(name) = name.to_str().ok().and_then(RunName::new) else {
            return reject(400, "invalid x-run-id\n");
        };
        match self
            .runs
            .register_unproven(name, client, limits, quota, Instant::now())
        {
            Ok((token, usage)) => {
                self.usage.unproven_registration(true);
                json(201, &serde_json::json!({ "token": token, "usage": usage }))
            }
            Err(RegisterError::AlreadyRegistered) => reject(409, "run already registered\n"),
            // Counted in /usage rather than logged at a level a deployment
            // keeps: any client can cause as many of these as it likes.
            Err(RegisterError::OverQuota) => {
                self.usage.unproven_registration(false);
                debug!(client = ?client, "unproven run registration refused: over quota");
                reject(429, "too many unproven registrations\n")
            }
            Err(RegisterError::Full) => reject(503, "too many runs\n"),
        }
    }
}

impl Registrar {
    /// The registrar for the policy in `path`, or `None` if there is no such
    /// file.
    fn load(path: &Path) -> Result<Option<Self>, FilterError> {
        let path_error = |e: &dyn std::fmt::Display| {
            FilterError::from(format!("{FILTER_NAME}: {}: {e}", path.display()))
        };
        let text = match std::fs::read_to_string(path) {
            Ok(text) => text,
            Err(e) if e.kind() == ErrorKind::NotFound => {
                warn!(policy_file = %path.display(), "no run registration policy; runs can't register");
                return Ok(None);
            }
            Err(e) => return Err(path_error(&e)),
        };
        let file: PolicyFile = serde_yaml::from_str(&text).map_err(|e| path_error(&e))?;
        let github = Entries {
            workflows: file.workflows,
            repository_ids: file.repository_ids,
            owner_ids: file.owner_ids,
            entry_workflows: file.entry_workflows,
            events: file.events,
            called_workflows: file.called_workflows,
            any_workflow: file.any_workflow,
        };
        let narrows_workflows = github.narrows_workflows();
        let policy = github.policy(file.audience);
        // A policy for other issuers only, or for registration without
        // proof only, has no entry that admits a token of GitHub's, and
        // then nothing about one either.
        let proves = policy.proves();
        let others = !file.issuers.is_empty();
        if proves || !(others || file.unproven.is_some()) {
            policy.validate().map_err(|e| path_error(&e))?;
        }
        if (proves || others) && !policy.names_workflows() && narrows_workflows {
            return Err(path_error(&NARROWS_WORKFLOWS_ONLY));
        }
        let mut issuers = Vec::new();
        if proves {
            warn_of_wide_entries(path, GITHUB_NAME, &policy);
            issuers.push(TrustedIssuer::github(file.jwks_url, policy));
        }
        for entry in file.issuers {
            let allow_http = entry.allow_http;
            let entries = Entries {
                workflows: entry.workflows,
                repository_ids: entry.repository_ids,
                owner_ids: entry.owner_ids,
                entry_workflows: entry.entry_workflows,
                events: entry.events,
                called_workflows: entry.called_workflows,
                any_workflow: entry.any_workflow,
            };
            let narrows_workflows = entries.narrows_workflows();
            let name = entry.name;
            let trusted = TrustedIssuer {
                name: Some(name.clone()),
                issuer: entry.issuer,
                jwks_url: entry.jwks_url,
                claims: entry.claims,
                max_token_age_secs: Some(entry.max_token_age_secs),
                policy: entries.policy(entry.audience),
            };
            trusted.validate(allow_http).map_err(|e| path_error(&e))?;
            if !trusted.policy.names_workflows() && narrows_workflows {
                return Err(path_error(&format!(
                    "issuers: {name}: {NARROWS_WORKFLOWS_ONLY}"
                )));
            }
            // Two entries of one name would share runs, and two of one
            // issuer would register each of its runs twice.
            let repeated = |other: &TrustedIssuer| {
                other.name == trusted.name || other.issuer == trusted.issuer
            };
            if issuers.iter().any(repeated) {
                return Err(path_error(&format!(
                    "issuers: {name}: each name and each issuer may have one entry"
                )));
            }
            warn!(
                policy_file = %path.display(),
                issuer = %name,
                iss = %trusted.issuer,
                jwks_url = %trusted.jwks_url,
                claims = ?trusted.claims,
                allow_http,
                max_token_age_secs = entry.max_token_age_secs,
                "runs register for tokens of an issuer besides GitHub"
            );
            warn_of_wide_entries(path, &name, &trusted.policy);
            issuers.push(trusted);
        }
        if file.max_secs == 0 || file.concurrency == 0 {
            return Err(path_error(&"max_secs and concurrency must be positive"));
        }
        if file.max_secs > MAX_SECS {
            return Err(path_error(&format!("max_secs may be at most {MAX_SECS}")));
        }
        let limits = Limits {
            ttl: Duration::from_secs(file.max_secs),
            concurrency: file.concurrency,
        };
        let unproven = file
            .unproven
            .map(|unproven| unproven.quota(limits.ttl))
            .transpose()
            .map_err(|e| path_error(&e))?;
        if let Some(quota) = unproven {
            warn!(
                policy_file = %path.display(),
                max_registrations = quota.max,
                window_secs = quota.window.as_secs(),
                "runs register WITHOUT PROOF: any client that reaches the listener can use the broker's credentials"
            );
        }
        let oidc = (!issuers.is_empty())
            .then(|| Oidc::new(issuers))
            .transpose()
            .map_err(|e| format!("{FILTER_NAME}: {e}"))?;
        Ok(Some(Self {
            oidc,
            unproven,
            limits,
            refusals: RefusalLog::default(),
        }))
    }
}

/// Say at startup which entries of `issuer`'s policy admit more than the
/// workflows it lists.
fn warn_of_wide_entries(path: &Path, issuer: &str, policy: &Policy) {
    for called in &policy.called_workflows {
        warn!(
            policy_file = %path.display(),
            issuer,
            workflow = %called.workflow,
            git_ref = called.git_ref.as_deref().unwrap_or_default(),
            sha = called.sha.as_deref().unwrap_or_default(),
            any_caller = called.callers.any,
            "runs register for a workflow called from other repositories"
        );
    }
    if let Some(any) = &policy.any_workflow {
        warn!(
            policy_file = %path.display(),
            issuer,
            any_repository = any.repositories.any,
            owner_ids = ?any.repositories.owner_ids,
            repository_ids = ?any.repositories.repository_ids,
            "runs register for ANY WORKFLOW of the admitted repositories"
        );
    }
}

fn reject(status: u16, message: &'static str) -> FilterAction {
    FilterAction::Reject(
        Rejection::status(status)
            .with_header(header::CONTENT_TYPE.as_str(), "text/plain")
            .with_body(message),
    )
}

fn json(status: u16, value: &impl serde::Serialize) -> FilterAction {
    json_with(status, value, HeaderMap::new())
}

/// A JSON response with `headers` besides its content type.
fn json_with(status: u16, value: &impl serde::Serialize, mut headers: HeaderMap) -> FilterAction {
    let body = match serde_json::to_vec(value) {
        Ok(body) => body,
        Err(_) => return reject(500, "internal error\n"),
    };
    headers.insert(
        header::CONTENT_TYPE,
        HeaderValue::from_static("application/json"),
    );
    FilterAction::TerminalResponse(Box::new(
        TerminalResponse::new(status)
            .with_headers(headers)
            .with_body(body),
    ))
}

/// The usage `token_count` recorded for this response, if it did.
fn reported_usage(ctx: &HttpFilterContext<'_>) -> Option<Usage> {
    let count = |key| ctx.get_metadata(key).and_then(|v| v.parse::<u64>().ok());
    if ctx.get_metadata(META_TOKEN_STATUS).is_some() {
        // Usage was there but too large to capture.
        return None;
    }
    let input = count(META_TOKEN_INPUT)?;
    let output = count(META_TOKEN_OUTPUT)?;
    let cache_read = count(META_TOKEN_CACHE_READ).unwrap_or(0).min(input);
    Some(Usage {
        tokens: Tokens {
            input: input - cache_read,
            cache_read,
            output,
            reasoning: count(META_TOKEN_REASONING).unwrap_or(0),
            total: count(META_TOKEN_TOTAL)
                .unwrap_or(0)
                .max(input.saturating_add(output)),
        },
        model: ctx.get_metadata(META_TOKEN_MODEL).map(str::to_owned),
    })
}

/// One line per response that names no credential, so that every request is
/// metered, whoever's credential it used.
fn log_usage(ctx: &HttpFilterContext<'_>, mode: CredentialMode, usage: Option<&Usage>) {
    let subject = ctx
        .extensions
        .get::<AuthenticatedIdentity>()
        .map(AuthenticatedIdentity::subject_id);
    let cluster = ctx.cluster.as_deref().unwrap_or("-");
    match usage {
        Some(usage) => info!(
            credential = mode.as_str(),
            cluster,
            run = subject.unwrap_or("-"),
            model = usage.model.as_deref().unwrap_or("-"),
            input = usage.tokens.input,
            cache_read = usage.tokens.cache_read,
            output = usage.tokens.output,
            total = usage.tokens.total,
            "request usage"
        ),
        None => info!(
            credential = mode.as_str(),
            cluster,
            run = subject.unwrap_or("-"),
            "request without usage"
        ),
    }
}

#[async_trait]
impl HttpFilter for RunTokenFilter {
    fn name(&self) -> &'static str {
        FILTER_NAME
    }

    fn produces_terminal_response(&self) -> bool {
        true
    }

    fn response_body_access(&self) -> BodyAccess {
        BodyAccess::ReadOnly
    }

    async fn on_request(
        &self,
        ctx: &mut HttpFilterContext<'_>,
    ) -> Result<FilterAction, FilterError> {
        let path = ctx.request.uri.path();
        if path == USAGE_PATH {
            return Ok(self.serve_usage(ctx.request));
        }
        let usage_free = self.usage_free_paths.contains(path);
        if path == RUNS_PATH || path.starts_with("/v1/runs/") {
            return Ok(match &self.endpoints {
                RunEndpoints::Absent => reject(404, "not found\n"),
                RunEndpoints::Unconfigured => {
                    self.serve_runs(None, ctx.request, ctx.client_addr).await
                }
                RunEndpoints::Serving(registrar) => {
                    self.serve_runs(Some(registrar.as_ref()), ctx.request, ctx.client_addr)
                        .await
                }
            });
        }
        if ctx
            .request
            .headers
            .get_all(header::AUTHORIZATION)
            .iter()
            .nth(1)
            .is_some()
        {
            return Ok(reject(400, "more than one Authorization header\n"));
        }
        if self.public_paths.contains(path) {
            ctx.request_headers_to_remove
                .extend(self.token_headers.iter().cloned());
            return Ok(FilterAction::Continue);
        }
        let Some((cluster, mode)) = ctx.cluster.as_deref().and_then(|cluster| {
            let mode = self.credentials.get(cluster)?;
            Some((cluster, *mode))
        }) else {
            warn!(cluster = ?ctx.cluster, "no credential mode for this route");
            return Ok(reject(500, "internal error\n"));
        };
        let remove = self.token_headers.iter().filter(|name| {
            // A pass-through caller's Authorization is its upstream credential.
            !(mode == CredentialMode::PassThrough && **name == header::AUTHORIZATION)
        });
        ctx.request_headers_to_remove.extend(remove.cloned());
        let caller = match mode {
            CredentialMode::PassThrough => {
                // Never send a run or operator token to the provider as a
                // credential, in any spelling of the scheme.
                let authorization = ctx
                    .request
                    .headers
                    .get(header::AUTHORIZATION)
                    .map(|v| v.as_bytes().to_ascii_lowercase())
                    .unwrap_or_default();
                let holds = |prefix: &str| {
                    authorization
                        .windows(prefix.len())
                        .any(|w| w == prefix.as_bytes())
                };
                if holds(TOKEN_PREFIX) {
                    return Ok(reject(400, "a run token belongs in x-run-token here\n"));
                }
                if holds(operators::TOKEN_PREFIX) {
                    return Ok(reject(
                        400,
                        "an operator token is not a provider credential\n",
                    ));
                }
                None
            }
            CredentialMode::Injected => {
                let (subject, mut caller) = match self.admit(&ctx.request.headers, cluster) {
                    Ok(admitted) => admitted,
                    Err(refusal) => return Ok(refusal),
                };
                let identity = AuthenticatedIdentity::new(
                    subject,
                    iter::empty(),
                    iter::empty(),
                    iter::empty(),
                )
                .ok_or_else(|| format!("{FILTER_NAME}: empty subject"))?;
                ctx.extensions.insert(identity);
                match &mut caller {
                    Caller::Run(admission) => admission.usage_free = usage_free,
                    Caller::Operator(slot) => slot.usage_free = usage_free,
                }
                Some(caller)
            }
        };
        let provider = if mode == CredentialMode::Injected && !usage_free {
            Provider::for_cluster(ctx.cluster.as_deref())
        } else {
            None
        };
        ctx.extensions.insert(Metered {
            mode,
            provider,
            success: false,
            caller,
        });
        Ok(FilterAction::Continue)
    }

    async fn on_response(
        &self,
        ctx: &mut HttpFilterContext<'_>,
    ) -> Result<FilterAction, FilterError> {
        let success = ctx
            .response_header
            .as_ref()
            .is_some_and(|r| r.status.is_success());
        if let Some(metered) = ctx.extensions.get_mut::<Metered>() {
            metered.success = success;
            if let Some(Caller::Run(admission)) = metered.caller.as_mut() {
                admission.success = success;
            }
            if let Some(provider) = metered.provider
                && let Some(response) = ctx.response_header.as_ref()
            {
                self.usage.capture(provider, &response.headers);
            }
        }
        Ok(FilterAction::Continue)
    }

    fn on_response_body(
        &self,
        ctx: &mut HttpFilterContext<'_>,
        _body: &mut Option<Bytes>,
        end_of_stream: bool,
    ) -> Result<FilterAction, FilterError> {
        if end_of_stream && let Some(metered) = ctx.extensions.remove::<Metered>() {
            let reported = reported_usage(ctx);
            if reported.is_none() && ctx.get_metadata(META_TOKEN_STATUS).is_some() {
                warn!("response usage too large for token_count to capture");
            }
            log_usage(ctx, metered.mode, reported.as_ref());
            if let Some(provider) = metered.provider {
                self.usage
                    .settle(provider, reported.as_ref(), metered.success);
            }
            match metered.caller {
                Some(Caller::Run(admission)) => {
                    if admission.is_unproven() && !admission.usage_free {
                        self.usage
                            .settle_unproven(reported.as_ref(), metered.success);
                    }
                    admission.settle(reported);
                }
                Some(Caller::Operator(slot)) if !slot.usage_free => self.usage.settle_operator(
                    slot.operator().name(),
                    reported.as_ref(),
                    metered.success,
                ),
                Some(Caller::Operator(_)) | None => {}
            }
        }
        Ok(FilterAction::Continue)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn every_route_needs_a_credential_mode_spelled_out() {
        let cases = [
            ("credentials: {a: injected, b: pass-through}", true),
            ("credentials: {}", false),
            ("{}", false),
            ("credentials: {a: passthrough}", false),
            ("credentials: {a: pass_through}", false),
            // No tokens file, no operators; nor is anything else there.
            (
                "{credentials: {a: injected}, operators: {tokens_file: /nonexistent/tokens}}",
                true,
            ),
            ("{credentials: {a: injected}, operators: {}}", false),
            (
                "{credentials: {a: injected}, operators: {tokens_file: /dev/null, tokens: []}}",
                false,
            ),
        ];
        for (yaml, ok) in cases {
            let config: serde_yaml::Value = serde_yaml::from_str(yaml).unwrap();
            assert_eq!(RunTokenFilter::from_config(&config).is_ok(), ok, "{yaml}");
        }
    }

    #[test]
    fn policy_files_are_validated_and_a_missing_one_disables_registration() {
        // For the registrar's HTTP client.
        praxis_ai::install_crypto_provider();
        let dir = tempfile::tempdir().unwrap();
        let valid = r#"{"workflows": ["o/r/.github/workflows/a.yml@refs/heads/main"], "repository_ids": [7]}"#;
        // An entry of `issuers` for a Forgejo instance reached in
        // plaintext, with `more` keys after its own, and policies with it.
        let forge = |more: &str| {
            format!(
                r#"{{"name": "forge", "issuer": "http://forge.test/api/actions", "jwks_url": "http://forge.test/api/actions/.well-known/keys", "claims": "forgejo", "workflows": ["o/r/.forgejo/workflows/a.yml@refs/heads/main"], "repository_ids": [7]{more}}}"#
            )
        };
        let plaintext = forge(r#", "allow_http": true"#);
        let issuers = |entries: &[&str]| format!(r#"{{"issuers": [{}]}}"#, entries.join(", "));
        let with_issuer =
            |more: &str| issuers(&[forge(&format!(r#", "allow_http": true{more}"#)).as_str()]);
        let https = r#"{"issuers": [{"name": "forge", "issuer": "https://forge.test/api/actions", "jwks_url": "https://forge.test/api/actions/.well-known/keys", "claims": "forgejo", "any_workflow": {"repositories": {"owner_ids": [1]}}}]}"#;
        let beside_github =
            format!(r#"{{"workflows": ["w"], "owner_ids": [7], "issuers": [{plaintext}]}}"#);
        let beside_unproven =
            format!(r#"{{"unproven": {{"max_registrations": 8}}, "issuers": [{plaintext}]}}"#);
        let under_github_events = format!(r#"{{"events": ["push"], "issuers": [{plaintext}]}}"#);
        let half_of_github = format!(r#"{{"workflows": ["w"], "issuers": [{plaintext}]}}"#);
        let issuer_cases = [
            // Another issuer, alone, beside GitHub's entries and beside
            // registration without proof.
            ("issuers only", with_issuer(""), true),
            ("an https issuer", https.to_owned(), true),
            ("an issuer beside github", beside_github, true),
            ("an issuer and unproven", beside_unproven, true),
            // Plaintext is an entry's own choice, never the default.
            ("an http issuer unasked", issuers(&[forge("").as_str()]), false),
            (
                "an http issuer, refused outright",
                issuers(&[forge(r#", "allow_http": false"#).as_str()]),
                false,
            ),
            (
                "an http issuer, allow_http with nothing under it",
                issuers(&[forge(r#", "allow_http": null"#).as_str()]),
                false,
            ),
            // What an entry must say: nothing about it is guessed.
            (
                "an issuer with no claims",
                r#"{"issuers": [{"name": "forge", "issuer": "https://forge.test/api/actions", "jwks_url": "https://forge.test/keys", "workflows": ["w"], "repository_ids": [7]}]}"#.to_owned(),
                false,
            ),
            (
                "an issuer with claims of no kind",
                r#"{"issuers": [{"name": "forge", "issuer": "https://forge.test/api/actions", "jwks_url": "https://forge.test/keys", "claims": "gitlab", "workflows": ["w"], "repository_ids": [7]}]}"#.to_owned(),
                false,
            ),
            (
                "an issuer with no keys",
                r#"{"issuers": [{"name": "forge", "issuer": "https://forge.test/api/actions", "claims": "forgejo", "workflows": ["w"], "repository_ids": [7]}]}"#.to_owned(),
                false,
            ),
            (
                "an issuer with no name",
                r#"{"issuers": [{"issuer": "https://forge.test/api/actions", "jwks_url": "https://forge.test/keys", "claims": "forgejo", "workflows": ["w"], "repository_ids": [7]}]}"#.to_owned(),
                false,
            ),
            (
                "an issuer with no rules",
                r#"{"issuers": [{"name": "forge", "issuer": "https://forge.test/api/actions", "jwks_url": "https://forge.test/keys", "claims": "forgejo"}]}"#.to_owned(),
                false,
            ),
            (
                "an issuer trusted by name only",
                r#"{"issuers": [{"name": "forge", "issuer": "https://forge.test/api/actions", "jwks_url": "https://forge.test/keys", "claims": "forgejo", "workflows": ["w"]}]}"#.to_owned(),
                false,
            ),
            (
                "an issuer, unknown field",
                with_issuer(r#", "discovery": true"#),
                false,
            ),
            ("no issuers", r#"{"issuers": []}"#.to_owned(), false),
            ("issuers of nothing", "issuers:\n".to_owned(), false),
            // Its own audience, events and age limit.
            (
                "an issuer with settings of its own",
                with_issuer(r#", "audience": "forge", "events": ["push"], "max_token_age_secs": 3600"#),
                true,
            ),
            (
                "an issuer whose tokens may be any age",
                with_issuer(r#", "max_token_age_secs": 0"#),
                false,
            ),
            (
                "an issuer whose tokens may be older than an hour",
                with_issuer(r#", "max_token_age_secs": 3601"#),
                false,
            ),
            (
                "an issuer with no events",
                with_issuer(r#", "events": []"#),
                false,
            ),
            // Rules that need a claim Forgejo's tokens lack.
            (
                "a forgejo issuer with entry workflows",
                with_issuer(r#", "entry_workflows": ["w"]"#),
                false,
            ),
            (
                "a forgejo issuer with a called workflow",
                with_issuer(
                    r#", "called_workflows": [{"workflow": "o/r/w.yml", "ref": "refs/heads/main", "callers": {"any": true}}]"#,
                ),
                false,
            ),
            // Each issuer's ids are its own, so GitHub's rules stay at the
            // top level and no two entries share a name or an issuer.
            (
                "github as an issuer",
                r#"{"issuers": [{"name": "gh", "issuer": "https://token.actions.githubusercontent.com", "jwks_url": "https://token.actions.githubusercontent.com/.well-known/jwks", "claims": "github", "workflows": ["w"], "repository_ids": [7]}]}"#.to_owned(),
                false,
            ),
            (
                "the same issuer twice",
                issuers(&[plaintext.as_str(), plaintext.replace(r#""name": "forge""#, r#""name": "forge-2""#).as_str()]),
                false,
            ),
            (
                "two issuers of one name",
                issuers(&[plaintext.as_str(), plaintext.replace("forge.test", "other.test").as_str()]),
                false,
            ),
            (
                "two issuers",
                issuers(&[
                    plaintext.as_str(),
                    plaintext
                        .replace("forge.test", "other.test")
                        .replace(r#""name": "forge""#, r#""name": "other""#)
                        .as_str(),
                ]),
                true,
            ),
            // GitHub's keys beside an issuer's entry are not that issuer's.
            ("an issuer under github's events", under_github_events, false),
            ("an issuer beside half of github's policy", half_of_github, false),
        ];
        let issuer_cases = issuer_cases.iter().map(|(name, contents, valid)| {
            (
                *name,
                Some(contents.as_str()),
                valid.then_some(true).ok_or(()),
            )
        });
        let cases = [
            ("valid", Some(valid), Ok(true)),
            ("missing", None, Ok(false)),
            ("not yaml", Some("workflows: ["), Err(())),
            (
                "unknown field",
                Some(r#"{"workflows": [], "max_tokens": 5}"#),
                Err(()),
            ),
            (
                "no workflows",
                Some(r#"{"workflows": [], "repository_ids": [7]}"#),
                Err(()),
            ),
            (
                "names only",
                Some(r#"{"workflows": ["o/r/.github/workflows/a.yml@refs/heads/main"]}"#),
                Err(()),
            ),
            (
                "no events",
                Some(r#"{"workflows": ["w"], "owner_ids": [7], "events": []}"#),
                Err(()),
            ),
            (
                "too long",
                Some(r#"{"workflows": ["w"], "owner_ids": [7], "max_secs": 2592001}"#),
                Err(()),
            ),
            (
                "no concurrency",
                Some(r#"{"workflows": ["w"], "owner_ids": [7], "concurrency": 0}"#),
                Err(()),
            ),
            // Registration without proof, beside a proving policy or alone.
            (
                "unproven too",
                Some(
                    r#"{"workflows": ["w"], "owner_ids": [7], "unproven": {"max_registrations": 8}}"#,
                ),
                Ok(true),
            ),
            (
                "unproven only",
                Some(r#"{"unproven": {"max_registrations": 8, "window_secs": 7200}}"#),
                Ok(true),
            ),
            ("nothing at all", Some("{}"), Err(())),
            (
                "unproven without a quota",
                Some(r#"{"unproven": {}}"#),
                Err(()),
            ),
            (
                "unproven, no registrations",
                Some(r#"{"unproven": {"max_registrations": 0}}"#),
                Err(()),
            ),
            // Thirty hourly windows of a six-hour run are remembered at
            // once, and 1024 runs.
            (
                "unproven, as many as are remembered",
                Some(r#"{"unproven": {"max_registrations": 34}}"#),
                Ok(true),
            ),
            (
                "unproven, more than are remembered",
                Some(r#"{"unproven": {"max_registrations": 35}}"#),
                Err(()),
            ),
            (
                "unproven, more than are remembered of longer runs",
                Some(r#"{"max_secs": 43200, "unproven": {"max_registrations": 34}}"#),
                Err(()),
            ),
            (
                "unproven, too short a window",
                Some(r#"{"unproven": {"max_registrations": 8, "window_secs": 60}}"#),
                Err(()),
            ),
            (
                "unproven, no window",
                Some(r#"{"unproven": {"max_registrations": 8, "window_secs": 0}}"#),
                Err(()),
            ),
            (
                "unproven, unknown field",
                Some(r#"{"unproven": {"max_registrations": 8, "enabled": true}}"#),
                Err(()),
            ),
            (
                "unproven as a flag",
                Some(r#"{"workflows": ["w"], "owner_ids": [7], "unproven": true}"#),
                Err(()),
            ),
            // Half of a proving policy is still refused beside it.
            (
                "unproven, ids without workflows",
                Some(r#"{"repository_ids": [7], "unproven": {"max_registrations": 8}}"#),
                Err(()),
            ),
            (
                "unproven, names only",
                Some(r#"{"workflows": ["w"], "unproven": {"max_registrations": 8}}"#),
                Err(()),
            ),
            // The entries that are off unless present, alone, beside
            // `workflows` and beside registration without proof.
            (
                "any workflow of an owner",
                Some(r#"{"any_workflow": {"repositories": {"owner_ids": [7]}}}"#),
                Ok(true),
            ),
            (
                "any workflow and a named one",
                Some(
                    r#"{"workflows": ["w"], "owner_ids": [7], "any_workflow": {"repositories": {"any": true}}}"#,
                ),
                Ok(true),
            ),
            (
                "a called workflow and unproven",
                Some(
                    r#"{"called_workflows": [{"workflow": "o/r/w.yml", "ref": "refs/heads/main", "callers": {"any": true}}], "unproven": {"max_registrations": 8}}"#,
                ),
                Ok(true),
            ),
            (
                "any workflow of nobody",
                Some(r#"{"any_workflow": {"repositories": {}}}"#),
                Err(()),
            ),
            (
                "any workflow, unknown field",
                Some(r#"{"any_workflow": {"repositories": {"any": true}, "owner_ids": [7]}}"#),
                Err(()),
            ),
            (
                "a called workflow at no ref",
                Some(
                    r#"{"called_workflows": [{"workflow": "o/r/w.yml", "callers": {"any": true}}]}"#,
                ),
                Err(()),
            ),
            // An entry that is wrong is refused beside ones that are not.
            (
                "unproven, any workflow of nobody",
                Some(
                    r#"{"any_workflow": {"repositories": {}}, "unproven": {"max_registrations": 8}}"#,
                ),
                Err(()),
            ),
            (
                "a named workflow, a called one at no ref",
                Some(
                    r#"{"workflows": ["w"], "owner_ids": [7], "called_workflows": [{"workflow": "o/r/w.yml", "callers": {"any": true}}]}"#,
                ),
                Err(()),
            ),
            // Nor do they stand in for the ids `workflows` needs.
            (
                "names only, any workflow",
                Some(
                    r#"{"workflows": ["w"], "any_workflow": {"repositories": {"owner_ids": [7]}}}"#,
                ),
                Err(()),
            ),
            (
                "no called workflows",
                Some(r#"{"called_workflows": []}"#),
                Err(()),
            ),
            // The events beside `workflows` are its own, and are refused
            // where they would be taken for a limit on another entry.
            (
                "any workflow under the events of workflows",
                Some(
                    r#"{"any_workflow": {"repositories": {"owner_ids": [7]}}, "events": ["workflow_dispatch"]}"#,
                ),
                Err(()),
            ),
            (
                "a called workflow under entry workflows",
                Some(
                    r#"{"called_workflows": [{"workflow": "o/r/w.yml", "ref": "refs/heads/main", "callers": {"any": true}}], "entry_workflows": ["w"]}"#,
                ),
                Err(()),
            ),
            (
                "each entry with events of its own",
                Some(
                    r#"{"workflows": ["w"], "owner_ids": [7], "events": ["push"], "any_workflow": {"repositories": {"owner_ids": [8]}, "events": ["workflow_dispatch"]}}"#,
                ),
                Ok(true),
            ),
            // A key with nothing under it is not the wider setting.
            ("any workflow of nothing", Some("any_workflow:\n"), Err(())),
            (
                "no events at all",
                Some("workflows: [w]\nowner_ids: [7]\nevents:\n"),
                Err(()),
            ),
        ];
        for (name, contents, expected) in cases.into_iter().chain(issuer_cases) {
            let path = dir.path().join(name);
            if let Some(contents) = contents {
                std::fs::write(&path, contents).unwrap();
            }
            let loaded = Registrar::load(&path).map(|r| r.is_some()).map_err(|_| ());
            assert_eq!(loaded, expected, "{name}");
        }
        let registrar = Registrar::load(&dir.path().join("valid")).unwrap().unwrap();
        assert_eq!(
            registrar.limits,
            Limits {
                ttl: Duration::from_secs(DEFAULT_MAX_SECS),
                concurrency: DEFAULT_CONCURRENCY,
            }
        );
        // (policy, verifies OIDC tokens, quota of registrations without proof)
        let hour = |max| Quota {
            max,
            window: Duration::from_secs(DEFAULT_UNPROVEN_WINDOW_SECS),
        };
        let two_hours = Quota {
            max: 8,
            window: Duration::from_secs(7200),
        };
        for (name, proves, unproven) in [
            ("valid", true, None),
            ("unproven too", true, Some(hour(8))),
            ("unproven only", false, Some(two_hours)),
            ("any workflow of an owner", true, None),
            ("a called workflow and unproven", true, Some(hour(8))),
            ("issuers only", true, None),
            ("an issuer beside github", true, None),
            ("an issuer and unproven", true, Some(hour(8))),
        ] {
            let registrar = Registrar::load(&dir.path().join(name)).unwrap().unwrap();
            assert_eq!(
                (registrar.oidc.is_some(), registrar.unproven),
                (proves, unproven),
                "{name}"
            );
        }
    }

    /// A log sink a test can read back.
    #[derive(Clone, Default)]
    struct Captured(Arc<Mutex<Vec<u8>>>);

    impl std::io::Write for Captured {
        fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
            self.0.lock().unwrap().extend_from_slice(buf);
            Ok(buf.len())
        }
        fn flush(&mut self) -> std::io::Result<()> {
            Ok(())
        }
    }

    impl Captured {
        /// The refusals logged since the last call.
        fn lines(&self) -> Vec<String> {
            let text = String::from_utf8(std::mem::take(&mut *self.0.lock().unwrap())).unwrap();
            text.lines()
                .filter(|line| line.contains("run registration refused"))
                .map(str::to_owned)
                .collect()
        }
    }

    // Current-thread, so the subscriber set for this thread sees it all.
    #[tokio::test]
    async fn each_refused_registration_is_logged_without_the_token() {
        use crate::oidc::testing::{REPOSITORY_ID, TEST_JWKS, WORKFLOW, jwt};
        use serde_json::json;
        praxis_ai::install_crypto_provider();
        let captured = Captured::default();
        let subscriber = tracing_subscriber::fmt()
            .with_writer({
                let captured = captured.clone();
                move || captured.clone()
            })
            .with_ansi(false)
            .with_max_level(tracing::Level::INFO)
            .finish();
        let _guard = tracing::subscriber::set_default(subscriber);

        let listener = tokio::net::TcpListener::bind(("127.0.0.1", 0))
            .await
            .unwrap();
        let address = listener.local_addr().unwrap();
        let router = axum::Router::new().route("/jwks", axum::routing::get(|| async { TEST_JWKS }));
        tokio::spawn(async move { axum::serve(listener, router).await.unwrap() });
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("policy");
        let policy = json!({
            "jwks_url": format!("http://{address}/jwks"),
            "workflows": [WORKFLOW],
            "repository_ids": [REPOSITORY_ID],
        });
        std::fs::write(&path, policy.to_string()).unwrap();
        let registrar = Registrar::load(&path).unwrap().unwrap();
        let registry = format!("test-{}", hex::encode(rand::random::<[u8; 8]>()));
        let filter = RunTokenFilter {
            runs: Runs::named(&registry),
            usage: BrokerUsage::named(&registry),
            token_headers: vec![header::AUTHORIZATION],
            public_paths: HashSet::new(),
            usage_free_paths: HashSet::new(),
            credentials: HashMap::new(),
            usage_cors_origins: HashSet::new(),
            endpoints: RunEndpoints::Absent,
            operators: Operators::default(),
        };
        let register = async |token: Option<&str>| {
            let mut headers = HeaderMap::new();
            if let Some(token) = token {
                let value = format!("Bearer {token}");
                headers.insert(header::AUTHORIZATION, value.parse().unwrap());
            }
            match filter.register(&registrar, &headers, None).await {
                FilterAction::Reject(rejection) => rejection.status,
                _ => 201,
            }
        };
        captured.lines();

        // A claimed `iss` is escaped and cut short: it cannot add a line,
        // nor make one long.
        let hostile = format!("https://forge.test/\n kind=not_allowed {}", "x".repeat(300));
        let tokens = [
            (jwt(1, &json!({"iss": hostile})), 401, "unknown", "invalid"),
            ("not.a.jwt".to_owned(), 401, "unknown", "malformed"),
            (
                jwt(1, &json!({"aud": "other"})),
                401,
                GITHUB_NAME,
                "invalid",
            ),
            (
                jwt(1, &json!({"event_name": "push"})),
                403,
                GITHUB_NAME,
                "not_allowed",
            ),
        ];
        for (token, status, issuer, kind) in &tokens {
            assert_eq!(register(Some(token)).await, *status, "{kind}");
            let lines = captured.lines();
            assert_eq!(lines.len(), 1, "{lines:?}");
            let line = &lines[0];
            assert!(line.contains(&format!("issuer=\"{issuer}\"")), "{line}");
            assert!(line.contains(&format!("kind=\"{kind}\"")), "{line}");
            // Nothing of the token but the issuer it claims.
            for part in token.split('.').filter(|p| p.len() > 8) {
                assert!(!line.contains(part), "{line}");
            }
            if token.starts_with("ey") {
                let claims = crate::oidc::testing::claims_of(token);
                for claim in ["jti", "repository", "workflow_ref", "aud"] {
                    let value = claims[claim].as_str().unwrap();
                    assert!(!line.contains(value), "{claim}: {line}");
                }
            }
        }
        // Quoted, and so no more than the one field.
        assert_eq!(register(Some(&tokens[0].0)).await, 401);
        let line = captured.lines().remove(0);
        let quoted = format!(
            r#"claimed_iss="https://forge.test/\\n kind=not_allowed {}...""#,
            "x".repeat(100 - "https://forge.test/\n kind=not_allowed ".len())
        );
        assert!(line.contains(&quoted), "{line}");
        assert_eq!(line.matches("kind=").count(), 2, "{line}");
        assert!(line.contains(r#"kind="invalid""#), "{line}");

        // No token at all, and a run registered twice.
        assert_eq!(register(None).await, 401);
        let lines = captured.lines();
        assert!(lines[0].contains("kind=\"no_token\""), "{lines:?}");
        let token = jwt(2, &json!({}));
        assert_eq!(register(Some(&token)).await, 201);
        let other = jwt(2, &json!({}));
        assert_eq!(register(Some(&other)).await, 409);
        let lines = captured.lines();
        assert_eq!(lines.len(), 1, "{lines:?}");
        assert!(
            lines[0].contains("kind=\"already_registered\""),
            "{lines:?}"
        );
        assert!(!lines[0].contains(&other[..other.len() / 2]), "{lines:?}");

        // A flood of one kind is cut to a few lines, and leaves the
        // others alone.
        for _ in 0..50 {
            assert_eq!(register(Some(&tokens[0].0)).await, 401);
        }
        let flood = captured.lines();
        assert_eq!(
            flood.len(),
            REFUSALS_LOGGED_PER_WINDOW as usize - 2,
            "{flood:?}"
        );
        assert_eq!(register(Some(&tokens[3].0)).await, 403);
        assert_eq!(captured.lines().len(), 1);

        // With no issuer to hold it to, a token is refused under the
        // issuer it claims, escaped the same way.
        let path = dir.path().join("unproven");
        std::fs::write(&path, r#"{"unproven": {"max_registrations": 8}}"#).unwrap();
        let unproven = Registrar::load(&path).unwrap().unwrap();
        assert!(unproven.oidc.is_none());
        let mut headers = HeaderMap::new();
        let value = format!("Bearer {}", tokens[0].0);
        headers.insert(header::AUTHORIZATION, value.parse().unwrap());
        match filter.register(&unproven, &headers, None).await {
            FilterAction::Reject(rejection) => assert_eq!(rejection.status, 403),
            _ => panic!("registered with no issuer"),
        }
        let lines = captured.lines();
        assert_eq!(lines.len(), 1, "{lines:?}");
        assert!(lines[0].contains(r#"kind="no_issuers""#), "{lines:?}");
        assert!(lines[0].contains(r#"issuer="unknown""#), "{lines:?}");
        assert!(
            lines[0].contains(r#"claimed_iss="https://forge.test/\\n"#),
            "{lines:?}"
        );
    }

    #[test]
    fn refusals_beyond_a_few_a_window_are_counted_and_the_count_logged() {
        let log = RefusalLog::default();
        let start = Instant::now();
        let unknown = |iss: &str| TokenIssuer::Unknown(Some(iss.to_owned()));
        let github = TokenIssuer::Known(GITHUB_NAME.to_owned());
        let budget = u64::from(REFUSALS_LOGGED_PER_WINDOW);
        // Varying the claimed issuer buys no more lines.
        for n in 0..budget {
            let admitted = log.admit(&unknown(&n.to_string()), RefusalKind::Invalid, start);
            assert_eq!(admitted, Some(0));
        }
        for n in 0..10 {
            let admitted = log.admit(&unknown(&n.to_string()), RefusalKind::Invalid, start);
            assert_eq!(admitted, None);
        }
        // Another issuer or kind has a budget of its own.
        assert_eq!(log.admit(&github, RefusalKind::Invalid, start), Some(0));
        assert_eq!(
            log.admit(&unknown("a"), RefusalKind::Malformed, start),
            Some(0)
        );
        // The next window logs again, with what was left out.
        let next = start + REFUSAL_LOG_WINDOW;
        assert_eq!(
            log.admit(&unknown("a"), RefusalKind::Invalid, next),
            Some(10)
        );
        assert_eq!(
            log.admit(&unknown("a"), RefusalKind::Invalid, next),
            Some(0)
        );
    }
}
