//! Actions OIDC tokens as the authority to register a run: GitHub's, and
//! those of any other issuer the policy names.
//!
//! A verified token from an allowed repository, workflow and event proves
//! the caller runs in that job. It does not prove the caller is the job's
//! supervisor rather than its agent: GitHub puts the request credentials
//! (`ACTIONS_ID_TOKEN_REQUEST_URL` and `_TOKEN`) in the environment of every
//! step of a job with `id-token: write`, and every process a step starts
//! inherits them. Forgejo does the same for a job with
//! `enable-openid-connect: true`, and its request token is the job's
//! `ACTIONS_RUNTIME_TOKEN`. The harness must keep them out of the agent's
//! sandbox; whoever holds them can register runs of that job.
//!
//! Which verified tokens register is the policy's: [`Policy`] has three
//! forms of entry, and a token registers if any one of them admits it.
//!
//! Each [`TrustedIssuer`] has a key set, an audience and a [`Policy`] of its
//! own, and a token is held to those of the issuer that signed it and to no
//! other's: nothing one issuer says is matched against another's rules.
//! The ids in a token (repository, owner, run) are the issuer's own
//! numbering, so a run is named by its issuer too (see
//! [`crate::runs::RunKey`]).
use crate::runs::{Admitted, RunIdentity, unix_now};
use base64::{Engine, engine::general_purpose::URL_SAFE_NO_PAD};
use jsonwebtoken::{Algorithm, DecodingKey, Validation, decode, decode_header, jwk::JwkSet};
use reqwest::{Client, redirect};
use serde::Deserialize;
use std::{
    collections::{HashMap, HashSet},
    sync::LazyLock,
    time::{Duration, Instant},
};
use tokio::{
    sync::{Mutex, Semaphore},
    time::timeout,
};
use tracing::warn;

pub const GITHUB_ISSUER: &str = "https://token.actions.githubusercontent.com";
pub const GITHUB_JWKS: &str = "https://token.actions.githubusercontent.com/.well-known/jwks";
pub const DEFAULT_AUDIENCE: &str = "praxis-credential-broker";
/// Registrations being verified at once.
const REGISTRATION_CONCURRENCY: usize = 4;
const JWKS_TTL: Duration = Duration::from_secs(3600);
/// When refetching fails, cached keys stay trusted this long, and no longer,
/// so a key GitHub withdrew doesn't stay trusted while fetches fail.
const JWKS_MAX_STALE: Duration = Duration::from_secs(24 * 3600);
/// Unknown key ids refetch the key set, but no more often than this.
const JWKS_MIN_REFETCH: Duration = Duration::from_secs(60);
const JWKS_TIMEOUT: Duration = Duration::from_secs(5);
const MAX_JWKS_BYTES: usize = 64 * 1024;
const MAX_JWT_BYTES: usize = 8 * 1024;
const LEEWAY_SECS: u64 = 60;
const MAX_JTI: usize = 128;
/// How old a token of an entry of `issuers` may be, unless the entry says.
/// As long as GitHub's tokens live.
pub const DEFAULT_MAX_TOKEN_AGE_SECS: u64 = 300;
/// The most an entry may say: far less than the day a run is remembered
/// after it ends, so no token outlives the record of the run it registered.
pub const MAX_TOKEN_AGE_SECS: u64 = 3600;
/// The longest name an entry of `issuers` may have.
const MAX_ISSUER_NAME: usize = 32;
/// What logs call GitHub, which no entry of `issuers` may be named.
pub const GITHUB_NAME: &str = "github";
const HTTPS: &str = "https://";
const HTTP: &str = "http://";
/// The length of a commit id, as `job_workflow_sha` gives one.
const SHA_HEX_LEN: usize = 40;
/// What a `ref` of the policy starts with, as in `job_workflow_ref`.
const REF_PREFIX: &str = "refs/";
/// How much of a refused token's unvouched-for `iss` is logged, escaped.
const MAX_LOGGED_ISS: usize = 100;

/// Registrations live in memory, so tokens issued before this process
/// started could otherwise register a run a second time.
static ISSUED_AFTER: LazyLock<u64> = LazyLock::new(|| unix_now().saturating_sub(LEEWAY_SECS));

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum OidcError {
    /// Not a well-formed token, or missing claims.
    Malformed,
    /// Bad signature, audience, issuer or validity period.
    Invalid,
    /// Valid, but from a repository, workflow or event that may not
    /// register runs.
    WorkflowNotAllowed,
    /// The key set could not be fetched.
    Unavailable,
}

/// A token's claims as its issuer wrote them. Those not every issuer
/// writes are optional here; [`ClaimSet::read`] says which an issuer's
/// tokens must have.
#[derive(Deserialize)]
struct TokenClaims {
    iat: u64,
    jti: Option<String>,
    repository: String,
    repository_id: String,
    repository_owner_id: String,
    run_id: String,
    run_attempt: String,
    check_run_id: Option<String>,
    job_workflow_ref: Option<String>,
    job_workflow_sha: Option<String>,
    workflow_ref: String,
    event_name: String,
    actor: Option<String>,
}

/// Which claims an issuer's tokens carry, and so what a policy's
/// `workflows` are matched against and what keeps a token from registering
/// a run twice.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ClaimSet {
    /// GitHub's: `job_workflow_ref` names the workflow that runs the job
    /// and `jti` the token. Both are required.
    Github,
    /// Forgejo's, which has neither. `workflow_ref`, the workflow the run
    /// started from, is matched in place of `job_workflow_ref`: nothing
    /// tells a reusable workflow's job from its caller's, so
    /// `called_workflows` and `entry_workflows` are refused in the policy.
    /// With no `jti`, a run registers once and never again, and the
    /// issuer's `max_token_age_secs` bounds how long an unused token
    /// stays good. Nor is there a `check_run_id`: all the jobs of a run
    /// are one run here, and the first to register is the only one.
    Forgejo,
}

impl ClaimSet {
    /// The claims a policy is matched against, or `Malformed` for a token
    /// without the ones this set requires. What a set does not define is
    /// dropped even if the token has it.
    fn read(self, token: TokenClaims) -> Result<Claims, OidcError> {
        let (jti, job_workflow_ref, job_workflow_sha, check_run_id) = match self {
            Self::Github => (
                Some(token.jti.ok_or(OidcError::Malformed)?),
                token.job_workflow_ref.ok_or(OidcError::Malformed)?,
                token.job_workflow_sha,
                token.check_run_id,
            ),
            Self::Forgejo => (None, token.workflow_ref.clone(), None, None),
        };
        Ok(Claims {
            jti,
            repository: token.repository,
            repository_id: token.repository_id,
            repository_owner_id: token.repository_owner_id,
            run_id: token.run_id,
            run_attempt: token.run_attempt,
            check_run_id,
            job_workflow_ref,
            job_workflow_sha,
            workflow_ref: token.workflow_ref,
            event_name: token.event_name,
            actor: token.actor,
        })
    }
}

/// A verified token's claims as its issuer's [`ClaimSet`] reads them.
struct Claims {
    /// None if the issuer's tokens have no `jti`.
    jti: Option<String>,
    repository: String,
    repository_id: String,
    repository_owner_id: String,
    run_id: String,
    run_attempt: String,
    /// The job's own check run; absent from tokens older than 2025.
    check_run_id: Option<String>,
    /// The workflow that runs the job, reusable or not. For an issuer
    /// without the claim, `workflow_ref`.
    job_workflow_ref: String,
    /// The commit `job_workflow_ref`'s file was read at.
    job_workflow_sha: Option<String>,
    /// The workflow the run started from, which calls a reusable one.
    workflow_ref: String,
    event_name: String,
    /// The account that started the run.
    actor: Option<String>,
}

/// The repositories a run may be in, by the `repository_id` and
/// `repository_owner_id` claims, which are the issuer's own numbering. For
/// a job of a reusable workflow those name the repository that called it,
/// not the one that holds it.
#[derive(Clone, Debug, Default, PartialEq, Eq, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Repositories {
    /// Every repository of the issuer: all of GitHub, or all of a forge.
    /// Said outright, never implied by an empty list.
    #[serde(default)]
    pub any: bool,
    /// Every repository of these owners.
    #[serde(default)]
    pub owner_ids: HashSet<u64>,
    /// These repositories, besides those of `owner_ids`.
    #[serde(default)]
    pub repository_ids: HashSet<u64>,
}

impl Repositories {
    fn validate(&self, field: &str) -> Result<(), String> {
        let listed = !(self.owner_ids.is_empty() && self.repository_ids.is_empty());
        match (self.any, listed) {
            (true, true) => Err(format!(
                "{field}: `any: true` admits every repository; remove it or the ids"
            )),
            (false, false) => Err(format!(
                "{field} needs owner_ids or repository_ids, or `any: true` for every repository on GitHub"
            )),
            _ => Ok(()),
        }
    }

    fn contains(&self, repository_id: u64, owner_id: u64) -> bool {
        self.any
            || self.owner_ids.contains(&owner_id)
            || self.repository_ids.contains(&repository_id)
    }
}

/// `event_name` claims an entry admits; None admits any.
type Events = Option<HashSet<String>>;

/// An optional key that, when written, must have a value: a key left with
/// nothing under it (a YAML null) is refused rather than read as absent,
/// which for these keys would mean the wider setting.
pub(crate) fn present<'de, D, T>(deserializer: D) -> Result<Option<T>, D::Error>
where
    D: serde::Deserializer<'de>,
    T: Deserialize<'de>,
{
    T::deserialize(deserializer).map(Some)
}

fn validate_events(events: &Events, field: &str) -> Result<(), String> {
    match events {
        Some(events) if events.is_empty() => Err(format!(
            "{field}.events must name at least one event; leave it out for any"
        )),
        _ => Ok(()),
    }
}

fn event_allowed(events: &Events, event: &str) -> bool {
    events.as_ref().is_none_or(|events| events.contains(event))
}

/// Admits every workflow of `repositories`: nothing about the workflow
/// file, its ref or what called it is checked.
#[derive(Clone, Debug, PartialEq, Eq, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AnyWorkflow {
    pub repositories: Repositories,
    #[serde(default, deserialize_with = "present")]
    pub events: Events,
}

impl AnyWorkflow {
    fn validate(&self) -> Result<(), String> {
        self.repositories.validate("any_workflow.repositories")?;
        validate_events(&self.events, "any_workflow")
    }

    fn allows(&self, claims: &Claims, repository_id: u64, owner_id: u64) -> bool {
        self.repositories.contains(repository_id, owner_id)
            && event_allowed(&self.events, &claims.event_name)
    }
}

/// Admits the jobs of one workflow file whatever repository runs them,
/// which is how a reusable workflow called from another repository
/// registers: `job_workflow_ref` and `job_workflow_sha` name the called
/// workflow, and `callers` the repositories that may run it.
#[derive(Clone, Debug, PartialEq, Eq, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CalledWorkflow {
    /// `OWNER/REPO/PATH`, the part of `job_workflow_ref` before its `@`.
    pub workflow: String,
    /// The ref after that `@`, such as `refs/heads/main`.
    #[serde(default, rename = "ref", deserialize_with = "present")]
    pub git_ref: Option<String>,
    /// The `job_workflow_sha` claim: the exact commit of the workflow.
    #[serde(default, deserialize_with = "present")]
    pub sha: Option<String>,
    pub callers: Repositories,
    #[serde(default, deserialize_with = "present")]
    pub events: Events,
}

impl CalledWorkflow {
    fn validate(&self) -> Result<(), String> {
        let workflow = &self.workflow;
        let field = format!("called_workflows: {workflow}");
        // The owner, the repository and a path within it.
        let plain = workflow.splitn(3, '/').filter(|s| !s.is_empty()).count() == 3
            && !workflow.contains('@');
        if !plain {
            return Err(format!(
                "{field}: workflow must be OWNER/REPO/PATH, without the @ref"
            ));
        }
        if self.git_ref.is_none() && self.sha.is_none() {
            return Err(format!("{field} needs a ref or a sha"));
        }
        if let Some(git_ref) = &self.git_ref
            && !git_ref.starts_with(REF_PREFIX)
        {
            return Err(format!(
                "{field}: ref must be a full ref such as refs/heads/main; pin a commit with sha"
            ));
        }
        if let Some(sha) = &self.sha
            && !(sha.len() == SHA_HEX_LEN
                && sha.bytes().all(|b| matches!(b, b'0'..=b'9' | b'a'..=b'f')))
        {
            return Err(format!(
                "{field}: sha must be a full commit id, {SHA_HEX_LEN} lowercase hex digits"
            ));
        }
        self.callers.validate(&format!("{field}: callers"))?;
        validate_events(&self.events, &field)
    }

    fn allows(&self, claims: &Claims, repository_id: u64, owner_id: u64) -> bool {
        let Some(at_ref) = claims.job_workflow_ref.strip_prefix(&self.workflow) else {
            return false;
        };
        let Some(called_ref) = at_ref.strip_prefix('@') else {
            return false;
        };
        let ref_allowed = match (&self.git_ref, &self.sha) {
            (Some(git_ref), _) => called_ref == git_ref,
            // Whatever ref the caller named resolved to the pinned commit.
            // A file name has no `/`, so what follows the `@` is the ref
            // itself and not the rest of a longer file name.
            (None, Some(sha)) => called_ref == sha || called_ref.starts_with(REF_PREFIX),
            (None, None) => false,
        };
        let sha_allowed = self
            .sha
            .as_ref()
            .is_none_or(|sha| claims.job_workflow_sha.as_ref() == Some(sha));
        ref_allowed
            && sha_allowed
            && self.callers.contains(repository_id, owner_id)
            && event_allowed(&self.events, &claims.event_name)
    }
}

/// Which jobs may register runs: those any one of three forms of entry
/// admits. `workflows` with the fields beside it is one entry, which names
/// a workflow in its own repository; `called_workflows` and `any_workflow`
/// are off unless present. Repositories are pinned by numeric id, since a
/// renamed or deleted owner's name can be taken by someone else.
#[derive(Clone, Debug, Default)]
pub struct Policy {
    pub audience: String,
    /// Exact `job_workflow_ref` claims, such as
    /// `owner/repo/.github/workflows/agent.yml@refs/heads/main`.
    pub workflows: HashSet<String>,
    /// `repository_id` claims; empty means any.
    pub repository_ids: HashSet<u64>,
    /// `repository_owner_id` claims; empty means any.
    pub owner_ids: HashSet<u64>,
    /// `workflow_ref` claims of the entry workflow. None allows only runs
    /// started by the job's own workflow, so no `workflow_call`.
    pub entry_workflows: Option<HashSet<String>>,
    /// `event_name` claims, such as `workflow_dispatch`.
    pub events: HashSet<String>,
    pub called_workflows: Vec<CalledWorkflow>,
    pub any_workflow: Option<AnyWorkflow>,
}

impl Policy {
    /// Whether `workflows` or one of the ids that narrow it is set.
    pub fn names_workflows(&self) -> bool {
        !(self.workflows.is_empty() && self.repository_ids.is_empty() && self.owner_ids.is_empty())
    }

    /// Whether any entry could admit an OIDC token.
    pub fn proves(&self) -> bool {
        self.names_workflows() || self.any_workflow.is_some() || !self.called_workflows.is_empty()
    }

    /// Refuse a policy that admits nothing, would trust repositories by
    /// name only, or has an entry that does not say what it admits.
    pub fn validate(&self) -> Result<(), String> {
        if self.names_workflows() || !self.proves() {
            if self.workflows.is_empty() {
                return Err("the policy needs workflows".into());
            }
            if self.repository_ids.is_empty() && self.owner_ids.is_empty() {
                return Err("the policy needs repository_ids or owner_ids".into());
            }
            if self.events.is_empty() {
                return Err("the policy's events must name at least one event".into());
            }
        }
        for called in &self.called_workflows {
            called.validate()?;
        }
        self.any_workflow
            .as_ref()
            .map_or(Ok(()), AnyWorkflow::validate)
    }

    /// The `workflows` entry: a workflow in its own repository.
    fn workflows_allow(&self, claims: &Claims, repository_id: u64, owner_id: u64) -> bool {
        // For a reusable workflow, job_workflow_ref names the called
        // workflow whatever repository called it; only its own counts.
        let workflow_repository = claims
            .job_workflow_ref
            .splitn(3, '/')
            .take(2)
            .collect::<Vec<_>>()
            .join("/");
        let entry_allowed = match &self.entry_workflows {
            Some(allowed) => allowed.contains(&claims.workflow_ref),
            None => claims.workflow_ref == claims.job_workflow_ref,
        };
        self.workflows.contains(&claims.job_workflow_ref)
            && claims.repository == workflow_repository
            && (self.repository_ids.is_empty() || self.repository_ids.contains(&repository_id))
            && (self.owner_ids.is_empty() || self.owner_ids.contains(&owner_id))
            && entry_allowed
            && self.events.contains(&claims.event_name)
    }

    /// The entry that admits the token, the narrowest first, so that a
    /// run's record names the least permissive setting that covers it.
    fn admits(&self, claims: &Claims, repository_id: u64, owner_id: u64) -> Option<Admitted> {
        let called = || {
            self.called_workflows
                .iter()
                .any(|called| called.allows(claims, repository_id, owner_id))
        };
        let any = || {
            self.any_workflow
                .as_ref()
                .is_some_and(|any| any.allows(claims, repository_id, owner_id))
        };
        if self.workflows_allow(claims, repository_id, owner_id) {
            Some(Admitted::Workflows)
        } else if called() {
            Some(Admitted::CalledWorkflows)
        } else if any() {
            Some(Admitted::AnyWorkflow)
        } else {
            None
        }
    }
}

#[derive(Default)]
struct KeyCache {
    keys: HashMap<String, DecodingKey>,
    fetched: Option<Instant>,
    attempted: Option<Instant>,
}

/// An issuer whose tokens may register runs, and what it holds them to.
#[derive(Clone, Debug)]
pub struct TrustedIssuer {
    /// What the policy calls it, which its runs are keyed and recorded
    /// under. None for GitHub, whose rules are the policy file's top level.
    pub name: Option<String>,
    /// The `iss` claim of its tokens, exactly.
    pub issuer: String,
    pub jwks_url: String,
    pub claims: ClaimSet,
    /// A token issued longer ago than this is refused, whatever its `exp`.
    /// None for GitHub, whose tokens live five minutes.
    pub max_token_age_secs: Option<u64>,
    /// Its audience and the entries that admit its tokens.
    pub policy: Policy,
}

impl TrustedIssuer {
    /// GitHub, as the top level of a policy file configures it.
    pub fn github(jwks_url: String, policy: Policy) -> Self {
        Self {
            name: None,
            issuer: GITHUB_ISSUER.to_owned(),
            jwks_url,
            claims: ClaimSet::Github,
            max_token_age_secs: None,
            policy,
        }
    }

    /// Refuse an entry of `issuers` that has no usable name, would be
    /// reached in plaintext without `allow_http` saying so, or whose rules
    /// admit nothing or need claims its tokens lack.
    pub fn validate(&self, allow_http: bool) -> Result<(), String> {
        let name = self.name.as_deref().unwrap_or_default();
        // A name goes into subjects and logs as it is, where GitHub's own
        // runs are already called that.
        let named = (1..=MAX_ISSUER_NAME).contains(&name.len())
            && name != GITHUB_NAME
            && name
                .bytes()
                .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'-');
        if !named {
            return Err(format!(
                "issuers: name {name:?} must be 1 to {MAX_ISSUER_NAME} lowercase letters, digits or `-`, and not {GITHUB_NAME:?}"
            ));
        }
        let field = format!("issuers: {name}");
        if self.issuer == GITHUB_ISSUER {
            return Err(format!(
                "{field}: GitHub's rules are the keys beside `issuers`, not an entry of it"
            ));
        }
        for (key, url) in [("issuer", &self.issuer), ("jwks_url", &self.jwks_url)] {
            let plaintext = url.starts_with(HTTP);
            if !(plaintext || url.starts_with(HTTPS)) || reqwest::Url::parse(url).is_err() {
                return Err(format!(
                    "{field}: {key} must be an https:// URL, or http:// with `allow_http: true`"
                ));
            }
            if plaintext && !allow_http {
                return Err(format!(
                    "{field}: {key} is plaintext http, so whoever can answer for that host on the network chooses the keys; `allow_http: true` accepts that"
                ));
            }
        }
        if self.policy.audience.is_empty() {
            return Err(format!("{field}: audience must not be empty"));
        }
        if !self
            .max_token_age_secs
            .is_some_and(|age| (1..=MAX_TOKEN_AGE_SECS).contains(&age))
        {
            return Err(format!(
                "{field}: max_token_age_secs must be from 1 to {MAX_TOKEN_AGE_SECS}"
            ));
        }
        let needs_job_workflow =
            self.policy.entry_workflows.is_some() || !self.policy.called_workflows.is_empty();
        if self.claims == ClaimSet::Forgejo && needs_job_workflow {
            return Err(format!(
                "{field}: entry_workflows and called_workflows need the job_workflow_ref claim, which forgejo tokens lack"
            ));
        }
        // An entry that admits nothing is refused as a policy that does.
        self.policy.validate().map_err(|e| format!("{field}: {e}"))
    }
}

/// The issuer a token claims, read before anything vouches for it. It only
/// chooses whose keys and rules the token is then held to: the signature is
/// checked with that issuer's keys and the signed `iss` must be that
/// issuer's, so a token gains nothing by naming an issuer that did not sign
/// it.
fn claimed_issuer(jwt: &str) -> Result<String, OidcError> {
    #[derive(Deserialize)]
    struct Unverified {
        iss: Option<String>,
    }
    let payload = jwt.split('.').nth(1).ok_or(OidcError::Malformed)?;
    let payload = URL_SAFE_NO_PAD
        .decode(payload)
        .map_err(|_| OidcError::Malformed)?;
    let claims: Unverified = serde_json::from_slice(&payload).map_err(|_| OidcError::Malformed)?;
    claims.iss.ok_or(OidcError::Invalid)
}

/// Whose rules a refused token was held to, for the log: never more of
/// the token than this.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum TokenIssuer {
    /// The policy's name for the issuer it claims: [`GITHUB_NAME`], or an
    /// entry of `issuers`.
    Known(String),
    /// No issuer the policy trusts, with the `iss` the token claims, if it
    /// has one, escaped to printable ASCII and cut to
    /// [`MAX_LOGGED_ISS`] characters: anyone can write it.
    Unknown(Option<String>),
}

impl TokenIssuer {
    /// The issuer a token claims, if nothing trusts it.
    pub fn unknown(jwt: &str) -> Self {
        Self::Unknown(claimed_issuer_bounded(jwt).ok().map(|iss| escape_iss(&iss)))
    }

    /// What it is logged under: unknown issuers share one name.
    pub fn name(&self) -> &str {
        match self {
            Self::Known(name) => name,
            Self::Unknown(_) => "unknown",
        }
    }

    /// The `iss` a token of an unknown issuer claims, as logged.
    pub fn claimed(&self) -> Option<&str> {
        match self {
            Self::Known(_) => None,
            Self::Unknown(iss) => iss.as_deref(),
        }
    }
}

/// The first `MAX_LOGGED_ISS` characters of `iss`, marked `...` if there
/// were more, with anything but printable ASCII escaped so it cannot break
/// a log line.
fn escape_iss(iss: &str) -> String {
    let mut chars = iss.chars();
    let mut out: String = chars
        .by_ref()
        .take(MAX_LOGGED_ISS)
        .flat_map(char::escape_default)
        .collect();
    if chars.next().is_some() {
        out.push_str("...");
    }
    out
}

/// [`claimed_issuer`] of a token no longer than `verify` reads.
fn claimed_issuer_bounded(jwt: &str) -> Result<String, OidcError> {
    if jwt.len() > MAX_JWT_BYTES {
        return Err(OidcError::Malformed);
    }
    claimed_issuer(jwt)
}

/// Verifies tokens of the issuers the policy trusts.
pub struct Oidc {
    issuers: Vec<Issuer>,
    /// Bounds registrations being verified at once.
    pub registrations: Semaphore,
}

impl Oidc {
    /// Fetch keys with a client of its own, which follows no redirect: a
    /// `jwks_url` is checked for https (or `allow_http`) and is trusted for
    /// its host, so neither may change on the way to the keys.
    pub fn new(issuers: Vec<TrustedIssuer>) -> Result<Self, String> {
        let client = Client::builder()
            .redirect(redirect::Policy::none())
            .build()
            .map_err(|e| format!("OIDC key client: {e}"))?;
        LazyLock::force(&ISSUED_AFTER);
        let issuer = |trusted| Issuer {
            client: client.clone(),
            trusted,
            cache: Mutex::default(),
        };
        Ok(Self {
            issuers: issuers.into_iter().map(issuer).collect(),
            registrations: Semaphore::new(REGISTRATION_CONCURRENCY),
        })
    }

    /// Verify a job's token and return the run it names, if the policy of
    /// the issuer that signed it lets it register runs.
    pub async fn verify(&self, jwt: &str) -> Result<RunIdentity, OidcError> {
        if jwt.len() > MAX_JWT_BYTES {
            return Err(OidcError::Malformed);
        }
        let header = decode_header(jwt).map_err(|_| OidcError::Malformed)?;
        if header.alg != Algorithm::RS256 {
            return Err(OidcError::Invalid);
        }
        let kid = header.kid.ok_or(OidcError::Malformed)?;
        let claimed = claimed_issuer(jwt)?;
        let issuer = self
            .issuers
            .iter()
            .find(|issuer| issuer.trusted.issuer == claimed)
            .ok_or(OidcError::Invalid)?;
        issuer.verify(jwt, &kid).await
    }

    /// The issuer `jwt` claims, as a refusal of it is logged. Nothing in
    /// it is verified: a token can claim a trusted issuer it does not have
    /// the keys of, and is then logged under that issuer's name.
    pub fn issuer_of(&self, jwt: &str) -> TokenIssuer {
        let Ok(claimed) = claimed_issuer_bounded(jwt) else {
            return TokenIssuer::Unknown(None);
        };
        match self.issuers.iter().find(|i| i.trusted.issuer == claimed) {
            Some(issuer) => TokenIssuer::Known(
                issuer
                    .trusted
                    .name
                    .clone()
                    .unwrap_or_else(|| GITHUB_NAME.to_owned()),
            ),
            None => TokenIssuer::Unknown(Some(escape_iss(&claimed))),
        }
    }

    /// Pretend the key sets were fetched `by` earlier than they were.
    #[cfg(test)]
    pub async fn age_keys(&self, by: Duration) {
        for issuer in &self.issuers {
            let mut cache = issuer.cache.lock().await;
            cache.fetched = cache.fetched.and_then(|t| t.checked_sub(by));
            cache.attempted = cache.attempted.and_then(|t| t.checked_sub(by));
        }
    }
}

/// One trusted issuer and the keys fetched for it.
struct Issuer {
    client: Client,
    trusted: TrustedIssuer,
    cache: Mutex<KeyCache>,
}

impl Issuer {
    /// Verify a token that claims this issuer, signed with its key `kid`.
    async fn verify(&self, jwt: &str, kid: &str) -> Result<RunIdentity, OidcError> {
        let trusted = &self.trusted;
        let key = self.key(kid).await?;
        let mut validation = Validation::new(Algorithm::RS256);
        validation.set_audience(&[&trusted.policy.audience]);
        validation.set_issuer(&[&trusted.issuer]);
        // `iat` is required by TokenClaims itself.
        validation.set_required_spec_claims(&["exp", "nbf", "iss", "aud"]);
        validation.validate_nbf = true;
        validation.leeway = LEEWAY_SECS;
        let token = decode::<TokenClaims>(jwt, &key, &validation)
            .map_err(|error| match error.kind() {
                jsonwebtoken::errors::ErrorKind::Json(_) => OidcError::Malformed,
                _ => OidcError::Invalid,
            })?
            .claims;
        if token.iat < *ISSUED_AFTER {
            return Err(OidcError::Invalid);
        }
        // An age limit means nothing for a token dated ahead of the clock.
        let now = unix_now();
        let aged = |max_age: u64| {
            token.iat > now.saturating_add(LEEWAY_SECS) || now.saturating_sub(token.iat) > max_age
        };
        if trusted.max_token_age_secs.is_some_and(aged) {
            return Err(OidcError::Invalid);
        }
        let claims = trusted.claims.read(token)?;
        let number = |s: &str| s.parse::<u64>().map_err(|_| OidcError::Malformed);
        let repository_id = number(&claims.repository_id)?;
        let owner_id = number(&claims.repository_owner_id)?;
        let Some(admitted_by) = trusted.policy.admits(&claims, repository_id, owner_id) else {
            return Err(OidcError::WorkflowNotAllowed);
        };
        if claims
            .jti
            .as_ref()
            .is_some_and(|jti| jti.is_empty() || jti.len() > MAX_JTI)
        {
            return Err(OidcError::Malformed);
        }
        Ok(RunIdentity {
            issuer: trusted.name.clone(),
            repository_id,
            run_id: number(&claims.run_id)?,
            run_attempt: number(&claims.run_attempt)?,
            check_run_id: claims.check_run_id.as_deref().map(number).transpose()?,
            jti: claims.jti,
            repository: claims.repository,
            repository_owner_id: owner_id,
            workflow_ref: claims.job_workflow_ref,
            workflow_sha: claims.job_workflow_sha,
            entry_workflow_ref: claims.workflow_ref,
            event_name: claims.event_name,
            actor: claims.actor,
            admitted_by,
        })
    }

    async fn key(&self, kid: &str) -> Result<DecodingKey, OidcError> {
        let mut cache = self.cache.lock().await;
        let fresh = cache.fetched.is_some_and(|t| t.elapsed() < JWKS_TTL);
        if fresh && let Some(key) = cache.keys.get(kid) {
            return Ok(key.clone());
        }
        if cache
            .attempted
            .is_none_or(|t| t.elapsed() >= JWKS_MIN_REFETCH)
        {
            cache.attempted = Some(Instant::now());
            match self.fetch().await {
                Ok(keys) => {
                    cache.keys = keys;
                    cache.fetched = Some(Instant::now());
                }
                Err(error) => {
                    // Debug, escaped: the error can quote the body the
                    // issuer's host served.
                    warn!(jwks_url = %self.trusted.jwks_url, ?error, "OIDC key set unavailable");
                }
            }
        }
        if cache.fetched.is_none_or(|t| t.elapsed() >= JWKS_MAX_STALE) {
            return Err(OidcError::Unavailable);
        }
        cache.keys.get(kid).cloned().ok_or(OidcError::Invalid)
    }

    /// The key set at `jwks_url`, or why it could not be had.
    async fn fetch(&self) -> Result<HashMap<String, DecodingKey>, String> {
        let body = timeout(JWKS_TIMEOUT, async {
            let mut response = self
                .client
                .get(&self.trusted.jwks_url)
                .send()
                .await
                .map_err(|e| format!("request failed: {e}"))?;
            let status = response.status();
            if status.is_redirection() {
                return Err(format!(
                    "answered {status}, a redirect, which is not followed; set jwks_url to where the keys are"
                ));
            }
            if !status.is_success() {
                return Err(format!("answered {status}"));
            }
            let mut body = Vec::new();
            while let Some(chunk) = response
                .chunk()
                .await
                .map_err(|e| format!("reading the body failed: {e}"))?
            {
                if body.len() + chunk.len() > MAX_JWKS_BYTES {
                    return Err(format!("the key set is over {MAX_JWKS_BYTES} bytes"));
                }
                body.extend_from_slice(&chunk);
            }
            Ok(body)
        })
        .await
        .map_err(|_| format!("no answer within {JWKS_TIMEOUT:?}"))??;
        let set: JwkSet =
            serde_json::from_slice(&body).map_err(|e| format!("not a key set: {e}"))?;
        Ok(set
            .keys
            .iter()
            .filter_map(|jwk| {
                let kid = jwk.common.key_id.clone()?;
                let key = DecodingKey::from_jwk(jwk).ok()?;
                Some((kid, key))
            })
            .collect())
    }
}

/// Test OIDC tokens, signed with a throwaway key nothing else trusts.
#[cfg(test)]
pub(crate) mod testing {
    use super::{
        ClaimSet, DEFAULT_AUDIENCE, DEFAULT_MAX_TOKEN_AGE_SECS, GITHUB_ISSUER, Policy,
        TrustedIssuer,
    };
    use jsonwebtoken::{EncodingKey, Header};
    use serde_json::{Value, json};
    use std::collections::HashSet;

    pub const TEST_KEY: &str = include_str!("../testdata/oidc-test-key.pem");
    pub const TEST_JWKS: &str = include_str!("../testdata/oidc-test-jwks.json");
    pub const TEST_KID: &str = "praxis-test-key";
    pub const AUDIENCE: &str = DEFAULT_AUDIENCE;
    pub const WORKFLOW: &str = "owner/repo/.github/workflows/agent.yml@refs/heads/main";
    pub const REPOSITORY_ID: u64 = 7;
    pub const OWNER_ID: u64 = 70;
    /// A reusable workflow in a repository of another owner, the commit it
    /// is at, and the workflow of the test repository that calls it.
    pub const CALLED: &str = "lib/agentic/.github/workflows/job.yml";
    pub const CALLED_SHA: &str = "0123456789abcdef0123456789abcdef01234567";
    pub const CALLER: &str = "owner/repo/.github/workflows/caller.yml@refs/heads/main";
    /// A second issuer, a Forgejo instance, with a throwaway key of its own
    /// that nothing else trusts either. Its test repository has the ids
    /// GitHub's has, as two issuers' numberings may.
    pub const FORGE_KEY: &str = include_str!("../testdata/oidc-test-forge-key.pem");
    pub const FORGE_JWKS: &str = include_str!("../testdata/oidc-test-forge-jwks.json");
    pub const FORGE_KID: &str = "praxis-test-forge-key";
    pub const FORGE: &str = "forge";
    pub const FORGE_ISSUER: &str = "http://forge.test/api/actions";
    pub const FORGE_WORKFLOW: &str = "owner/repo/.forgejo/workflows/agent.yml@refs/heads/main";

    /// The claims of a job of `CALLED` at `git_ref`, called from the test
    /// repository, as overrides for `jwt`.
    pub fn called_at(git_ref: &str) -> Value {
        json!({
            "job_workflow_ref": format!("{CALLED}@{git_ref}"),
            "job_workflow_sha": CALLED_SHA,
            "workflow_ref": CALLER,
            "actor": "someone",
        })
    }

    /// `base` with `more` merged over it.
    pub fn with(mut base: Value, more: &Value) -> Value {
        for (name, value) in more.as_object().unwrap() {
            base[name] = value.clone();
        }
        base
    }

    pub fn policy() -> Policy {
        Policy {
            audience: AUDIENCE.into(),
            workflows: HashSet::from([WORKFLOW.to_owned()]),
            repository_ids: HashSet::from([REPOSITORY_ID]),
            owner_ids: HashSet::from([OWNER_ID]),
            entry_workflows: None,
            events: HashSet::from(["workflow_dispatch".to_owned()]),
            ..Policy::default()
        }
    }

    /// The test forge as an entry of `issuers`, its keys at `jwks_url`,
    /// admitting its test workflow when dispatched.
    pub fn forge(jwks_url: String) -> TrustedIssuer {
        TrustedIssuer {
            name: Some(FORGE.to_owned()),
            issuer: FORGE_ISSUER.to_owned(),
            jwks_url,
            claims: ClaimSet::Forgejo,
            max_token_age_secs: Some(DEFAULT_MAX_TOKEN_AGE_SECS),
            policy: Policy {
                workflows: HashSet::from([FORGE_WORKFLOW.to_owned()]),
                owner_ids: HashSet::new(),
                ..policy()
            },
        }
    }

    /// `claims` with `overrides` merged over them; a null removes a claim.
    fn overridden(mut claims: Value, overrides: &Value) -> Value {
        for (name, value) in overrides.as_object().unwrap() {
            if value.is_null() {
                claims.as_object_mut().unwrap().remove(name);
            } else {
                claims[name] = value.clone();
            }
        }
        claims
    }

    /// A token for run `run_id` with the claims Forgejo 16 writes: no
    /// `jti`, no `job_workflow_ref`, no `check_run_id`, and good for an
    /// hour. `overrides` are merged into its claims; a null removes one.
    pub fn forge_jwt(run_id: u64, overrides: &Value) -> String {
        let now = crate::runs::unix_now();
        let claims = json!({
            "iss": FORGE_ISSUER,
            "aud": AUDIENCE,
            "sub": "repo:owner-70/repo-7:ref:refs/heads/main",
            "iat": now,
            "nbf": now,
            "exp": now + 3600,
            "actor": "someone",
            "actor_id": "1",
            "base_ref": "",
            "event_name": "workflow_dispatch",
            "head_ref": "",
            "ref": "refs/heads/main",
            "ref_protected": "false",
            "ref_type": "branch",
            "repository": "owner/repo",
            "repository_id": REPOSITORY_ID.to_string(),
            "repository_owner": "owner",
            "repository_owner_id": OWNER_ID.to_string(),
            "run_attempt": "1",
            "run_id": run_id.to_string(),
            "run_number": "1",
            "sha": CALLED_SHA,
            "workflow": "agent.yml",
            "workflow_ref": FORGE_WORKFLOW,
        });
        sign_with(
            FORGE_KEY,
            &overridden(claims, overrides),
            jsonwebtoken::Algorithm::RS256,
            Some(FORGE_KID),
        )
    }

    /// A GitHub-style OIDC token for run `run_id`, with `overrides` merged
    /// into its claims; a null removes a claim.
    pub fn jwt(run_id: u64, overrides: &Value) -> String {
        let now = crate::runs::unix_now();
        let claims = json!({
            "iss": GITHUB_ISSUER,
            "aud": AUDIENCE,
            "iat": now,
            "nbf": now,
            "exp": now + 300,
            "jti": hex::encode(rand::random::<[u8; 16]>()),
            "repository": "owner/repo",
            "repository_id": REPOSITORY_ID.to_string(),
            "repository_owner_id": OWNER_ID.to_string(),
            "run_id": run_id.to_string(),
            "run_attempt": "1",
            "job_workflow_ref": WORKFLOW,
            "workflow_ref": WORKFLOW,
            "event_name": "workflow_dispatch",
        });
        let claims = overridden(claims, overrides);
        sign(&claims, jsonwebtoken::Algorithm::RS256, Some(TEST_KID))
    }

    /// Sign `claims` with the test key, or for HS256 with the public key set
    /// as the HMAC secret, the classic algorithm-confusion forgery.
    pub fn sign(claims: &Value, alg: jsonwebtoken::Algorithm, kid: Option<&str>) -> String {
        sign_with(TEST_KEY, claims, alg, kid)
    }

    /// `sign` with the RSA key `pem` instead of GitHub's test key.
    pub fn sign_with(
        pem: &str,
        claims: &Value,
        alg: jsonwebtoken::Algorithm,
        kid: Option<&str>,
    ) -> String {
        let mut header = Header::new(alg);
        header.kid = kid.map(str::to_owned);
        let key = match alg {
            jsonwebtoken::Algorithm::HS256 => EncodingKey::from_secret(TEST_JWKS.as_bytes()),
            _ => EncodingKey::from_rsa_pem(pem.as_bytes()).unwrap(),
        };
        jsonwebtoken::encode(&header, claims, &key).unwrap()
    }

    /// The claims of a token `jwt()` made.
    pub fn claims_of(token: &str) -> Value {
        use base64::Engine;
        let payload = token.split('.').nth(1).unwrap();
        let bytes = base64::engine::general_purpose::URL_SAFE_NO_PAD
            .decode(payload)
            .unwrap();
        serde_json::from_slice(&bytes).unwrap()
    }
}

#[cfg(test)]
mod tests {
    use super::{testing::*, *};
    use axum::{Router, extract::State, http::StatusCode, routing::get};
    use serde_json::{Value, json};
    use std::sync::{
        Arc,
        atomic::{AtomicBool, Ordering},
    };

    /// Verify against the test policy.
    async fn serve_jwks() -> (Oidc, Arc<AtomicBool>) {
        serve_jwks_for(policy()).await
    }

    /// Serve the test key set, until `down` is set, to verify GitHub's
    /// tokens against `policy`.
    async fn serve_jwks_for(policy: Policy) -> (Oidc, Arc<AtomicBool>) {
        serve_issuers(|jwks| vec![TrustedIssuer::github(jwks.to_owned(), policy)]).await
    }

    /// Serve GitHub's test key set at `/jwks` until `down` is set, the
    /// test forge's beside it, and a redirect to the first at
    /// `/redirect`, to verify against the issuers `trusted` makes of the
    /// first's URL.
    async fn serve_issuers(
        trusted: impl FnOnce(&str) -> Vec<TrustedIssuer>,
    ) -> (Oidc, Arc<AtomicBool>) {
        praxis_ai::install_crypto_provider();
        let down = Arc::new(AtomicBool::new(false));
        let jwks = |State(down): State<Arc<AtomicBool>>| async move {
            if down.load(Ordering::SeqCst) {
                Err(StatusCode::SERVICE_UNAVAILABLE)
            } else {
                Ok(TEST_JWKS)
            }
        };
        let router = Router::new()
            .route("/jwks", get(jwks))
            .route("/forge-jwks", get(|| async { FORGE_JWKS }))
            .route(
                "/redirect",
                get(|| async { axum::response::Redirect::temporary("/jwks") }),
            )
            .with_state(Arc::clone(&down));
        let listener = tokio::net::TcpListener::bind(("127.0.0.1", 0))
            .await
            .unwrap();
        let address = listener.local_addr().unwrap();
        tokio::spawn(async move { axum::serve(listener, router).await.unwrap() });
        let issuers = trusted(&format!("http://{address}/jwks"));
        (Oidc::new(issuers).unwrap(), down)
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn oidc_tokens_must_be_valid_and_from_an_allowed_workflow() {
        let (oidc, _) = serve_jwks().await;
        let now = unix_now();
        let alg_none = {
            use base64::Engine;
            let encode =
                |v: &Value| base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(v.to_string());
            let header = encode(&json!({"alg": "none", "typ": "JWT", "kid": TEST_KID}));
            format!("{header}.{}.", encode(&claims_of(&jwt(1, &json!({})))))
        };
        let valid = jwt(1, &json!({}));
        let spliced = {
            let mut parts: Vec<&str> = valid.split('.').collect();
            let other = jwt(2, &json!({}));
            parts[1] = other.split('.').nth(1).unwrap();
            parts.join(".")
        };
        let (invalid, malformed, forbidden) = (
            Err(OidcError::Invalid),
            Err(OidcError::Malformed),
            Err(OidcError::WorkflowNotAllowed),
        );
        let cases = [
            ("garbage", "not.a.jwt".to_owned(), malformed.clone()),
            (
                "audience",
                jwt(1, &json!({"aud": "someone-else"})),
                invalid.clone(),
            ),
            (
                "issuer",
                jwt(1, &json!({"iss": "https://example.com"})),
                invalid.clone(),
            ),
            (
                "expired",
                jwt(
                    1,
                    &json!({"exp": now - 600, "iat": now - 900, "nbf": now - 900}),
                ),
                invalid.clone(),
            ),
            (
                "not yet valid",
                jwt(1, &json!({"nbf": now + 600})),
                invalid.clone(),
            ),
            (
                "run id",
                jwt(1, &json!({"run_id": "one"})),
                malformed.clone(),
            ),
            ("no iat", jwt(1, &json!({"iat": null})), malformed.clone()),
            ("no jti", jwt(1, &json!({"jti": null})), malformed.clone()),
            ("alg none", alg_none, malformed.clone()),
            (
                "HS256 keyed with the public key",
                sign(
                    &claims_of(&valid),
                    jsonwebtoken::Algorithm::HS256,
                    Some(TEST_KID),
                ),
                invalid.clone(),
            ),
            (
                "unknown kid",
                sign(
                    &claims_of(&valid),
                    jsonwebtoken::Algorithm::RS256,
                    Some("other-key"),
                ),
                invalid.clone(),
            ),
            ("spliced claims", spliced, invalid.clone()),
            (
                "array audience without ours",
                jwt(1, &json!({"aud": ["someone-else", "another"]})),
                invalid.clone(),
            ),
            (
                "issued before the proxy started",
                jwt(1, &json!({"iat": now - 300, "nbf": now - 300})),
                invalid.clone(),
            ),
            (
                "squatted repository name",
                jwt(1, &json!({"repository_id": "8"})),
                forbidden.clone(),
            ),
            (
                "squatted owner name",
                jwt(1, &json!({"repository_owner_id": "71"})),
                forbidden.clone(),
            ),
            (
                "event",
                jwt(1, &json!({"event_name": "pull_request_target"})),
                forbidden.clone(),
            ),
            (
                "called by another workflow",
                jwt(
                    1,
                    &json!({"workflow_ref": "owner/repo/.github/workflows/other.yml@refs/heads/main"}),
                ),
                forbidden.clone(),
            ),
            (
                "called from another repository",
                jwt(1, &json!({"repository": "evil/repo"})),
                forbidden.clone(),
            ),
            (
                "workflow",
                jwt(
                    1,
                    &json!({"job_workflow_ref": "owner/repo/.github/workflows/devspace.yml@refs/heads/main"}),
                ),
                forbidden.clone(),
            ),
            (
                "workflow ref",
                jwt(
                    1,
                    &json!({"job_workflow_ref": "owner/repo/.github/workflows/agent.yml@refs/heads/evil"}),
                ),
                forbidden,
            ),
        ];
        for (name, token, expected) in cases {
            assert_eq!(oidc.verify(&token).await.map(|_| ()), expected, "{name}");
        }
        let identity = oidc.verify(&valid).await.unwrap();
        assert_eq!(
            (identity.run_id, identity.repository_id),
            (1, REPOSITORY_ID)
        );
        // An audience list that includes ours is fine.
        let listed = jwt(3, &json!({"aud": ["someone-else", AUDIENCE]}));
        assert!(oidc.verify(&listed).await.is_ok());
    }

    /// The entries of a policy file that are off unless present.
    #[derive(Deserialize)]
    #[serde(deny_unknown_fields)]
    struct Entries {
        #[serde(default)]
        called_workflows: Vec<CalledWorkflow>,
        any_workflow: Option<AnyWorkflow>,
    }

    /// A policy with the entries `yaml` has and nothing else.
    fn entries(yaml: &str) -> Policy {
        let entries: Entries = serde_yaml::from_str(yaml).unwrap();
        let policy = Policy {
            audience: AUDIENCE.into(),
            called_workflows: entries.called_workflows,
            any_workflow: entries.any_workflow,
            ..Policy::default()
        };
        policy.validate().unwrap();
        policy
    }

    #[test]
    fn an_entry_must_say_what_it_admits() {
        // What `workflows` and its ids need is unchanged beside the others.
        let named = |policy: Policy| Policy {
            workflows: HashSet::from([WORKFLOW.to_owned()]),
            ..policy
        };
        let cases = [
            ("{}", false),
            ("{any_workflow: {repositories: {owner_ids: [70]}}}", true),
            (
                "{any_workflow: {repositories: {repository_ids: [7]}}}",
                true,
            ),
            ("{any_workflow: {repositories: {any: true}}}", true),
            (
                "{any_workflow: {repositories: {any: true}, events: [push]}}",
                true,
            ),
            // Every repository is never what an empty entry means.
            ("{any_workflow: {repositories: {}}}", false),
            ("{any_workflow: {repositories: {any: false}}}", false),
            ("{any_workflow: {repositories: {owner_ids: []}}}", false),
            (
                "{any_workflow: {repositories: {any: true, owner_ids: [70]}}}",
                false,
            ),
            (
                "{any_workflow: {repositories: {any: true}, events: []}}",
                false,
            ),
            (
                "{called_workflows: [{workflow: o/r/w.yml, ref: refs/heads/main, callers: {any: true}}]}",
                true,
            ),
            (
                "{called_workflows: [{workflow: o/r/w.yml, sha: 0123456789abcdef0123456789abcdef01234567, callers: {owner_ids: [70]}}]}",
                true,
            ),
            (
                "{called_workflows: [{workflow: o/r/w.yml, ref: refs/tags/v1, sha: 0123456789abcdef0123456789abcdef01234567, callers: {repository_ids: [7]}, events: [push]}]}",
                true,
            ),
            // A ref or a commit with nothing under it reads as a name, and
            // is refused as one, not taken for a key left out.
            (
                "{called_workflows: [{workflow: o/r/w.yml, ref: null, sha: 0123456789abcdef0123456789abcdef01234567, callers: {any: true}}]}",
                false,
            ),
            (
                "{called_workflows: [{workflow: o/r/w.yml, ref: , sha: 0123456789abcdef0123456789abcdef01234567, callers: {any: true}}]}",
                false,
            ),
            (
                "{called_workflows: [{workflow: o/r/w.yml, ref: refs/heads/main, sha: null, callers: {any: true}}]}",
                false,
            ),
            // Neither a ref nor a commit, or one that is not whole.
            (
                "{called_workflows: [{workflow: o/r/w.yml, callers: {any: true}}]}",
                false,
            ),
            (
                "{called_workflows: [{workflow: o/r/w.yml, ref: main, callers: {any: true}}]}",
                false,
            ),
            (
                "{called_workflows: [{workflow: o/r/w.yml, sha: 0123456, callers: {any: true}}]}",
                false,
            ),
            (
                "{called_workflows: [{workflow: o/r/w.yml, sha: 0123456789ABCDEF0123456789abcdef01234567, callers: {any: true}}]}",
                false,
            ),
            (
                "{called_workflows: [{workflow: o/r/w.yml@refs/heads/main, ref: refs/heads/main, callers: {any: true}}]}",
                false,
            ),
            (
                "{called_workflows: [{workflow: o/r, ref: refs/heads/main, callers: {any: true}}]}",
                false,
            ),
            (
                "{called_workflows: [{workflow: o//w.yml, ref: refs/heads/main, callers: {any: true}}]}",
                false,
            ),
            (
                "{called_workflows: [{workflow: o/r/w.yml, ref: refs/heads/main, callers: {}}]}",
                false,
            ),
            (
                "{called_workflows: [{workflow: o/r/w.yml, ref: refs/heads/main, callers: {any: true}, events: []}]}",
                false,
            ),
        ];
        for (yaml, valid) in cases {
            let entries: Entries = serde_yaml::from_str(yaml).unwrap();
            let policy = Policy {
                called_workflows: entries.called_workflows,
                any_workflow: entries.any_workflow,
                ..Policy::default()
            };
            assert_eq!(policy.validate().is_ok(), valid, "{yaml}");
            // Beside `workflows` with no id, nothing is valid.
            assert!(named(policy).validate().is_err(), "{yaml}");
        }
        // Unknown keys and missing ones do not parse, nor does a key with
        // nothing under it, which must not read as the wider setting.
        for yaml in [
            "{any_workflow: {repositories: {any: true}, events: null}}",
            "{any_workflow: {repositories: null}}",
            "{any_workflow: {repositories: {any: null}}}",
            "{called_workflows: [{workflow: o/r/w.yml, ref: refs/heads/main, callers: {any: true}, events: null}]}",
            "{called_workflows: [{workflow: o/r/w.yml, ref: refs/heads/main, callers: null}]}",
            "{any_workflow: {}}",
            "{any_workflow: true}",
            "{any_workflow: {repositories: {any: true}, workflows: [w]}}",
            "{any_workflow: {repositories: {owners: [cgwalters]}}}",
            "{called_workflows: [{ref: refs/heads/main, callers: {any: true}}]}",
            "{called_workflows: [{workflow: o/r/w.yml, ref: refs/heads/main}]}",
            "{called_workflows: [{workflow: o/r/w.yml, ref: refs/heads/main, callers: any}]}",
            "{called_workflows: [{workflow: o/r/w.yml, ref: refs/heads/main, callers: {any: true}, entry_workflows: []}]}",
        ] {
            assert!(serde_yaml::from_str::<Entries>(yaml).is_err(), "{yaml}");
        }
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn each_form_of_entry_admits_what_it_names_and_nothing_else() {
        let now = unix_now();
        let main = "refs/heads/main";
        let owners = "{any_workflow: {repositories: {owner_ids: [70]}}}";
        let anyone = "{any_workflow: {repositories: {any: true}}}";
        let dispatched =
            "{any_workflow: {repositories: {repository_ids: [7]}, events: [workflow_dispatch]}}";
        let by_ref = "{called_workflows: [{workflow: lib/agentic/.github/workflows/job.yml, ref: refs/heads/main, callers: {owner_ids: [70]}}]}";
        let by_sha = "{called_workflows: [{workflow: lib/agentic/.github/workflows/job.yml, sha: 0123456789abcdef0123456789abcdef01234567, callers: {any: true}}]}";
        let by_both = "{called_workflows: [{workflow: lib/agentic/.github/workflows/job.yml, ref: refs/tags/v1, sha: 0123456789abcdef0123456789abcdef01234567, callers: {repository_ids: [7]}, events: [workflow_dispatch]}]}";
        let both_forms = "{any_workflow: {repositories: {owner_ids: [70]}}, called_workflows: [{workflow: lib/agentic/.github/workflows/job.yml, ref: refs/heads/main, callers: {any: true}}]}";
        let elsewhere =
            json!({"repository": "evil/repo", "repository_id": "8", "repository_owner_id": "71"});
        let fork = json!({
            "job_workflow_ref": format!("evil/agentic/.github/workflows/job.yml@{main}"),
        });
        let other_sha = json!({"job_workflow_sha": "f".repeat(40)});
        let (any, called) = (Ok(Admitted::AnyWorkflow), Ok(Admitted::CalledWorkflows));
        let refused = Err(OidcError::WorkflowNotAllowed);
        // (policy, what the token says beyond the test workflow's own run, outcome)
        let cases = [
            // Any workflow of the listed owners: the workflow, its ref, what
            // called it and the event are all unchecked.
            (owners, json!({}), any.clone()),
            (
                owners,
                json!({"job_workflow_ref": "owner/other/.github/workflows/x.yml@refs/heads/topic", "workflow_ref": "owner/other/.github/workflows/x.yml@refs/heads/topic", "repository": "owner/other", "repository_id": "9", "event_name": "push"}),
                any.clone(),
            ),
            (owners, called_at(main), any.clone()),
            (
                owners,
                json!({"job_workflow_sha": null, "actor": null}),
                any.clone(),
            ),
            (
                owners,
                json!({"repository_owner_id": "71"}),
                refused.clone(),
            ),
            // A fork is another owner's repository, whatever its name says.
            (
                owners,
                json!({"repository": "owner/repo", "repository_id": "8", "repository_owner_id": "71"}),
                refused.clone(),
            ),
            // The listed owner's reusable workflow, called from elsewhere.
            (
                owners,
                with(
                    elsewhere.clone(),
                    &json!({"workflow_ref": "evil/repo/.github/workflows/c.yml@refs/heads/main"}),
                ),
                refused.clone(),
            ),
            (anyone, elsewhere.clone(), any.clone()),
            (anyone, with(called_at(main), &elsewhere), any.clone()),
            (dispatched, json!({}), any.clone()),
            (
                dispatched,
                json!({"event_name": "pull_request_target"}),
                refused.clone(),
            ),
            (dispatched, json!({"repository_id": "8"}), refused.clone()),
            // A named workflow, called at the named ref from a listed owner.
            (by_ref, called_at(main), called.clone()),
            (
                by_ref,
                with(
                    called_at(main),
                    &json!({"event_name": "push", "repository_id": "9"}),
                ),
                called.clone(),
            ),
            (by_ref, with(called_at(main), &other_sha), called.clone()),
            (by_ref, called_at("refs/heads/topic"), refused.clone()),
            (by_ref, called_at("refs/heads/main2"), refused.clone()),
            (by_ref, called_at(CALLED_SHA), refused.clone()),
            (by_ref, with(called_at(main), &fork), refused.clone()),
            (
                by_ref,
                with(
                    called_at(main),
                    &json!({"job_workflow_ref": format!("lib/agentic/.github/workflows/other.yml@{main}")}),
                ),
                refused.clone(),
            ),
            (
                by_ref,
                with(
                    called_at(main),
                    &json!({"job_workflow_ref": format!("{CALLED}x@{main}")}),
                ),
                refused.clone(),
            ),
            (by_ref, with(called_at(main), &elsewhere), refused.clone()),
            // Not the test workflow, which the entry does not name.
            (by_ref, json!({}), refused.clone()),
            // A commit, whatever ref the caller reached it by and whoever calls.
            (by_sha, called_at(main), called.clone()),
            (by_sha, called_at("refs/tags/v1"), called.clone()),
            (by_sha, called_at(CALLED_SHA), called.clone()),
            (by_sha, with(called_at(main), &elsewhere), called.clone()),
            // Run in its own repository, which `callers` admits like any other.
            (
                by_sha,
                json!({"job_workflow_ref": format!("{CALLED}@{main}"), "job_workflow_sha": CALLED_SHA, "workflow_ref": format!("{CALLED}@{main}"), "repository": "lib/agentic", "repository_id": "5", "repository_owner_id": "50"}),
                called.clone(),
            ),
            (
                by_ref,
                json!({"job_workflow_ref": format!("{CALLED}@{main}"), "workflow_ref": format!("{CALLED}@{main}"), "repository": "lib/agentic", "repository_id": "5", "repository_owner_id": "50"}),
                refused.clone(),
            ),
            (by_sha, with(called_at(main), &other_sha), refused.clone()),
            (
                by_sha,
                with(called_at(main), &json!({"job_workflow_sha": null})),
                refused.clone(),
            ),
            (by_sha, with(called_at(main), &fork), refused.clone()),
            // Another file of that commit whose name starts with this one's.
            (
                by_sha,
                with(
                    called_at(main),
                    &json!({"job_workflow_ref": format!("{CALLED}@evil.yml@{main}")}),
                ),
                refused.clone(),
            ),
            // Both the ref and the commit, a listed repository and event.
            (by_both, called_at("refs/tags/v1"), called.clone()),
            (by_both, called_at(main), refused.clone()),
            (
                by_both,
                with(called_at("refs/tags/v1"), &other_sha),
                refused.clone(),
            ),
            (
                by_both,
                with(called_at("refs/tags/v1"), &json!({"repository_id": "9"})),
                refused.clone(),
            ),
            (
                by_both,
                with(called_at("refs/tags/v1"), &json!({"event_name": "push"})),
                refused.clone(),
            ),
            // A token both forms admit is recorded under the narrower.
            (both_forms, called_at(main), called.clone()),
            (both_forms, called_at("refs/heads/topic"), any.clone()),
            (
                both_forms,
                with(called_at(main), &elsewhere),
                called.clone(),
            ),
            (
                both_forms,
                with(called_at("refs/heads/topic"), &elsewhere),
                refused.clone(),
            ),
        ];
        let mut verifiers = HashMap::new();
        for (run, (policy, claims, expected)) in cases.into_iter().enumerate() {
            if !verifiers.contains_key(policy) {
                verifiers.insert(policy, serve_jwks_for(entries(policy)).await.0);
            }
            let outcome = verifiers[policy]
                .verify(&jwt(u64::try_from(run).unwrap(), &claims))
                .await
                .map(|identity| identity.admitted_by);
            assert_eq!(outcome, expected, "{policy}: {claims}");
        }
        // Whatever the policy admits, the token itself is verified first:
        // even every repository on GitHub means GitHub's signature, this
        // audience and a token that is current.
        let invalid = [
            ("issuer", json!({"iss": "https://example.com"})),
            ("audience", json!({"aud": "someone-else"})),
            (
                "expired",
                json!({"exp": now - 600, "iat": now - 900, "nbf": now - 900}),
            ),
            ("not yet valid", json!({"nbf": now + 600})),
            (
                "issued before the proxy started",
                json!({"iat": now - 300, "nbf": now - 300}),
            ),
        ];
        for (policy, oidc) in &verifiers {
            for (name, claims) in &invalid {
                let token = jwt(1000, &with(called_at(main), claims));
                assert_eq!(
                    oidc.verify(&token).await.err(),
                    Some(OidcError::Invalid),
                    "{policy}: {name}"
                );
            }
            let forged = sign(
                &claims_of(&jwt(1000, &called_at(main))),
                jsonwebtoken::Algorithm::HS256,
                Some(TEST_KID),
            );
            assert_eq!(
                oidc.verify(&forged).await.err(),
                Some(OidcError::Invalid),
                "{policy}"
            );
            let no_ids = jwt(
                1000,
                &with(called_at(main), &json!({"repository_owner_id": "owner"})),
            );
            assert_eq!(
                oidc.verify(&no_ids).await.err(),
                Some(OidcError::Malformed),
                "{policy}"
            );
        }
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn an_identity_carries_the_claims_it_was_admitted_on() {
        let policy = Policy {
            called_workflows: entries("{called_workflows: [{workflow: lib/agentic/.github/workflows/job.yml, ref: refs/heads/main, callers: {owner_ids: [70]}}]}").called_workflows,
            ..policy()
        };
        let (oidc, _) = serve_jwks_for(policy).await;
        let identity = oidc
            .verify(&jwt(1, &called_at("refs/heads/main")))
            .await
            .unwrap();
        assert_eq!(
            (
                identity.workflow_ref.as_str(),
                identity.workflow_sha.as_deref(),
                identity.entry_workflow_ref.as_str(),
                identity.repository.as_str(),
                identity.repository_owner_id,
                identity.event_name.as_str(),
                identity.actor.as_deref(),
                identity.admitted_by,
            ),
            (
                "lib/agentic/.github/workflows/job.yml@refs/heads/main",
                Some(CALLED_SHA),
                CALLER,
                "owner/repo",
                OWNER_ID,
                "workflow_dispatch",
                Some("someone"),
                Admitted::CalledWorkflows,
            )
        );
        // The policy's own workflow is still admitted as that.
        let identity = oidc.verify(&jwt(2, &json!({}))).await.unwrap();
        assert_eq!(
            (identity.admitted_by, identity.workflow_sha, identity.actor),
            (Admitted::Workflows, None, None)
        );
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn stale_oidc_keys_are_trusted_for_a_day_at_most() {
        let (oidc, down) = serve_jwks().await;
        assert!(oidc.verify(&jwt(1, &json!({}))).await.is_ok());
        // Refetching fails: the cached keys still verify for a while.
        down.store(true, Ordering::SeqCst);
        oidc.age_keys(Duration::from_secs(2 * 3600)).await;
        assert!(oidc.verify(&jwt(2, &json!({}))).await.is_ok());
        // But not once they are a day old.
        oidc.age_keys(Duration::from_secs(23 * 3600)).await;
        assert_eq!(
            oidc.verify(&jwt(3, &json!({}))).await.err(),
            Some(OidcError::Unavailable)
        );
        down.store(false, Ordering::SeqCst);
        oidc.age_keys(Duration::from_secs(3600)).await;
        assert!(oidc.verify(&jwt(3, &json!({}))).await.is_ok());
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn a_refusal_names_the_issuer_a_token_claims_and_no_more() {
        let (oidc, _) = serve_issuers(|jwks| {
            let forge = forge(jwks.replace("/jwks", "/forge-jwks"));
            vec![TrustedIssuer::github(jwks.to_owned(), policy()), forge]
        })
        .await;
        let known = |name: &str| TokenIssuer::Known(name.to_owned());
        let unknown = |iss: Option<&str>| TokenIssuer::Unknown(iss.map(str::to_owned));
        let long = format!("https://forge.test/{}", "a".repeat(200));
        let cases = [
            (jwt(1, &json!({})), known(GITHUB_NAME)),
            (forge_jwt(1, &json!({})), known(FORGE)),
            (
                jwt(1, &json!({"iss": "https://forge.test/\"\u{1b}\n"})),
                unknown(Some(r#"https://forge.test/\"\u{1b}\n"#)),
            ),
            // Cut before escaping, so never inside an escape.
            (
                jwt(1, &json!({"iss": "\n".repeat(MAX_LOGGED_ISS + 1)})),
                unknown(Some(&format!("{}...", r"\n".repeat(MAX_LOGGED_ISS)))),
            ),
            (
                jwt(1, &json!({"iss": long})),
                unknown(Some(&format!("{}...", &long[..MAX_LOGGED_ISS]))),
            ),
            (jwt(1, &json!({"iss": null})), unknown(None)),
            ("not.a.jwt".to_owned(), unknown(None)),
            ("x".repeat(MAX_JWT_BYTES + 1), unknown(None)),
        ];
        for (token, expected) in cases {
            assert_eq!(oidc.issuer_of(&token), expected, "{expected:?}");
        }
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn a_redirected_key_fetch_is_refused() {
        // The redirect leads to the very keys that sign the token, so only
        // not following it makes the keys unavailable.
        let (oidc, _) = serve_issuers(|jwks| {
            vec![TrustedIssuer::github(
                jwks.replace("/jwks", "/redirect"),
                policy(),
            )]
        })
        .await;
        assert_eq!(
            oidc.verify(&jwt(1, &json!({}))).await.err(),
            Some(OidcError::Unavailable)
        );
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn each_issuer_is_held_to_its_own_keys_audience_rules_and_claims() {
        const FORGE_AUDIENCE: &str = "praxis-forge";
        const FORGE_MAX_AGE: u64 = 30;
        let other_owner = "{any_workflow: {repositories: {owner_ids: [71]}}}";
        // GitHub admits its test workflow and anything of owner 71; the
        // forge its own test workflow only, for another audience, from
        // tokens at most half a minute old.
        let (oidc, _) = serve_issuers(|jwks| {
            let github = Policy {
                any_workflow: entries(other_owner).any_workflow,
                ..policy()
            };
            let forge = forge(jwks.replace("/jwks", "/forge-jwks"));
            let forge = TrustedIssuer {
                max_token_age_secs: Some(FORGE_MAX_AGE),
                policy: Policy {
                    audience: FORGE_AUDIENCE.into(),
                    ..forge.policy
                },
                ..forge
            };
            vec![TrustedIssuer::github(jwks.to_owned(), github), forge]
        })
        .await;
        let now = unix_now();
        let rs256 = jsonwebtoken::Algorithm::RS256;
        let github = |claims: Value| jwt(1, &claims);
        let forge = |claims: Value| forge_jwt(1, &with(json!({"aud": FORGE_AUDIENCE}), &claims));
        let aged = |secs: u64| json!({"iat": now - secs, "nbf": now - secs});
        // Who an admitted token's run belongs to, and by which entry.
        let (by_github, by_forge) = (
            Ok((None, Admitted::Workflows)),
            Ok((Some(FORGE.to_owned()), Admitted::Workflows)),
        );
        let (invalid, malformed, refused) = (
            Err(OidcError::Invalid),
            Err(OidcError::Malformed),
            Err(OidcError::WorkflowNotAllowed),
        );
        let cases = [
            // GitHub is as it was beside another issuer.
            ("github", github(json!({})), by_github.clone()),
            (
                "github, any workflow of the other owner",
                github(json!({"repository_owner_id": "71"})),
                Ok((None, Admitted::AnyWorkflow)),
            ),
            (
                "github without jti",
                github(json!({"jti": null})),
                malformed.clone(),
            ),
            (
                "github without job_workflow_ref",
                github(json!({"job_workflow_ref": null})),
                malformed.clone(),
            ),
            (
                "github, event",
                github(json!({"event_name": "push"})),
                refused.clone(),
            ),
            // No age limit of its own: only `exp` and the start of the
            // process bound a GitHub token.
            (
                "github, older than the forge allows",
                github(aged(FORGE_MAX_AGE + 15)),
                by_github.clone(),
            ),
            // The forge's tokens have neither claim and register all the same.
            ("forge", forge(json!({})), by_forge.clone()),
            (
                "forge, as old as allowed",
                forge(aged(FORGE_MAX_AGE - 15)),
                by_forge.clone(),
            ),
            // Unexpired, since a forge token is good for an hour, but older
            // than this issuer's tokens may be.
            (
                "forge, too old",
                forge(aged(FORGE_MAX_AGE + 15)),
                invalid.clone(),
            ),
            // Nor does dating a token ahead of the clock get around that,
            // though it is valid already.
            (
                "forge, issued in the future",
                forge(json!({"iat": now + 600})),
                invalid.clone(),
            ),
            (
                "forge, expired",
                forge(json!({"exp": now - 600, "iat": now - 900, "nbf": now - 900})),
                invalid.clone(),
            ),
            (
                "forge, not yet valid",
                forge(json!({"nbf": now + 600})),
                invalid.clone(),
            ),
            (
                "forge without iat",
                forge(json!({"iat": null})),
                malformed.clone(),
            ),
            // Each issuer has its own audience.
            (
                "forge, another audience",
                forge(json!({"aud": "someone-else"})),
                invalid.clone(),
            ),
            (
                "forge, github's audience",
                forge(json!({"aud": AUDIENCE})),
                invalid.clone(),
            ),
            (
                "github, the forge's audience",
                github(json!({"aud": FORGE_AUDIENCE})),
                invalid.clone(),
            ),
            // An issuer nothing names, whoever signed for it.
            (
                "unknown issuer, forge key",
                forge(json!({"iss": "http://other.test/api/actions"})),
                invalid.clone(),
            ),
            (
                "unknown issuer, github key",
                github(json!({"iss": "https://example.com"})),
                invalid.clone(),
            ),
            (
                "a prefix of the forge's issuer",
                forge(json!({"iss": "http://forge.test/api"})),
                invalid.clone(),
            ),
            (
                "the forge's issuer with a trailing slash",
                forge(json!({"iss": format!("{FORGE_ISSUER}/")})),
                invalid.clone(),
            ),
            ("no issuer", forge(json!({"iss": null})), invalid.clone()),
            // One issuer's key signs nothing for the other, under either
            // key id.
            (
                "the forge's key signing as github",
                forge(with(
                    claims_of(&github(json!({}))),
                    &json!({"aud": AUDIENCE}),
                )),
                invalid.clone(),
            ),
            (
                "the forge's key signing as github, under github's key id",
                sign_with(
                    FORGE_KEY,
                    &claims_of(&github(json!({}))),
                    rs256,
                    Some(TEST_KID),
                ),
                invalid.clone(),
            ),
            (
                "github's key signing as the forge",
                sign(&claims_of(&forge(json!({}))), rs256, Some(TEST_KID)),
                invalid.clone(),
            ),
            (
                "github's key signing as the forge, under the forge's key id",
                sign(&claims_of(&forge(json!({}))), rs256, Some(FORGE_KID)),
                invalid.clone(),
            ),
            // A rule admits only the tokens of the issuer it is written
            // under: the forge has no rule for GitHub's workflow or for
            // owner 71, nor GitHub one for the forge's workflow.
            (
                "forge token, github's workflow",
                forge(json!({"workflow_ref": WORKFLOW})),
                refused.clone(),
            ),
            (
                "forge token, the owner github admits",
                forge(json!({"repository_owner_id": "71", "repository_id": "8"})),
                refused.clone(),
            ),
            (
                "github token, the forge's workflow",
                github(json!({"job_workflow_ref": FORGE_WORKFLOW, "workflow_ref": FORGE_WORKFLOW})),
                refused.clone(),
            ),
            // What the forge's own rule checks.
            (
                "forge, another ref",
                forge(
                    json!({"workflow_ref": "owner/repo/.forgejo/workflows/agent.yml@refs/heads/topic"}),
                ),
                refused.clone(),
            ),
            (
                "forge, squatted repository name",
                forge(json!({"repository_id": "8"})),
                refused.clone(),
            ),
            (
                "forge, a workflow of another repository",
                forge(json!({"repository": "evil/repo"})),
                refused.clone(),
            ),
            (
                "forge, event",
                forge(json!({"event_name": "push"})),
                refused.clone(),
            ),
            (
                "forge, ids that are not numbers",
                forge(json!({"repository_id": "repo"})),
                malformed.clone(),
            ),
            // Claims the forge's set does not define count for nothing:
            // the rule is matched on `workflow_ref` whatever else is there.
            (
                "forge, with github's claims too",
                forge(
                    json!({"jti": "x", "check_run_id": "5", "job_workflow_ref": WORKFLOW, "job_workflow_sha": CALLED_SHA}),
                ),
                by_forge.clone(),
            ),
            (
                "forge, github's claim naming the forge's workflow",
                forge(json!({"workflow_ref": WORKFLOW, "job_workflow_ref": FORGE_WORKFLOW})),
                refused.clone(),
            ),
        ];
        for (name, token, expected) in cases {
            let outcome = oidc
                .verify(&token)
                .await
                .map(|identity| (identity.issuer, identity.admitted_by));
            assert_eq!(outcome, expected, "{name}");
        }
        // The same ids from each issuer are runs apart, and only GitHub's
        // has a token id for a retry to show.
        let github = oidc.verify(&jwt(1, &json!({}))).await.unwrap();
        let forge = oidc
            .verify(&forge(json!({"jti": "x", "check_run_id": "5"})))
            .await
            .unwrap();
        assert_eq!(
            (github.repository_id, github.run_id, github.run_attempt),
            (forge.repository_id, forge.run_id, forge.run_attempt)
        );
        assert_eq!(
            (github.issuer.as_deref(), github.jti.is_some()),
            (None, true)
        );
        assert_eq!(
            (
                forge.issuer.as_deref(),
                forge.jti,
                forge.check_run_id,
                forge.workflow_sha,
                forge.workflow_ref.as_str(),
                forge.entry_workflow_ref.as_str(),
            ),
            (
                Some(FORGE),
                None,
                None,
                None,
                FORGE_WORKFLOW,
                FORGE_WORKFLOW
            )
        );
    }

    #[test]
    fn an_entry_of_issuers_must_be_named_reached_safely_and_admit_something() {
        let https = "https://forge.test/api/actions";
        let entry = |edit: &dyn Fn(&mut TrustedIssuer)| {
            let mut trusted = TrustedIssuer {
                issuer: https.to_owned(),
                ..forge(format!("{https}/.well-known/keys"))
            };
            edit(&mut trusted);
            trusted
        };
        let plaintext = |edit: &dyn Fn(&mut TrustedIssuer)| {
            let mut trusted = forge(format!("{FORGE_ISSUER}/.well-known/keys"));
            edit(&mut trusted);
            trusted
        };
        let called: Vec<CalledWorkflow> = entries("{called_workflows: [{workflow: o/r/w.yml, ref: refs/heads/main, callers: {any: true}}]}").called_workflows;
        // (what the entry says, allow_http, valid)
        let cases = [
            ("https", entry(&|_| {}), false, true),
            ("https, allowing http", entry(&|_| {}), true, true),
            // Plaintext is never the default.
            ("http", plaintext(&|_| {}), false, false),
            ("http, allowed", plaintext(&|_| {}), true, true),
            (
                "https issuer, http keys",
                entry(&|t| t.jwks_url = "http://forge.test/keys".into()),
                false,
                false,
            ),
            (
                "http issuer, https keys",
                entry(&|t| t.issuer = FORGE_ISSUER.into()),
                false,
                false,
            ),
            (
                "keys at no URL",
                entry(&|t| t.jwks_url = "forge.test/keys".into()),
                true,
                false,
            ),
            (
                "keys in a file",
                entry(&|t| t.jwks_url = "file:///etc/keys".into()),
                true,
                false,
            ),
            (
                "no issuer",
                entry(&|t| t.issuer = String::new()),
                true,
                false,
            ),
            // GitHub is not an entry: its runs would register twice.
            (
                "github",
                entry(&|t| t.issuer = GITHUB_ISSUER.into()),
                false,
                false,
            ),
            ("no name", entry(&|t| t.name = None), false, false),
            (
                "empty name",
                entry(&|t| t.name = Some(String::new())),
                false,
                false,
            ),
            // A name is part of a subject, where `:` and `/` divide.
            (
                "a name with a colon",
                entry(&|t| t.name = Some("forge:7".into())),
                false,
                false,
            ),
            (
                "a name with a slash",
                entry(&|t| t.name = Some("forge/7".into())),
                false,
                false,
            ),
            (
                "the name github's runs have",
                entry(&|t| t.name = Some(GITHUB_NAME.into())),
                false,
                false,
            ),
            (
                "a name in capitals",
                entry(&|t| t.name = Some("Forge".into())),
                false,
                false,
            ),
            (
                "a long name",
                entry(&|t| t.name = Some("f".repeat(MAX_ISSUER_NAME + 1))),
                false,
                false,
            ),
            (
                "the longest name",
                entry(&|t| t.name = Some("f".repeat(MAX_ISSUER_NAME))),
                false,
                true,
            ),
            (
                "no audience",
                entry(&|t| t.policy.audience = String::new()),
                false,
                false,
            ),
            // A token's age is always bounded, and by less than a day.
            (
                "no age limit",
                entry(&|t| t.max_token_age_secs = None),
                false,
                false,
            ),
            (
                "an age limit of nothing",
                entry(&|t| t.max_token_age_secs = Some(0)),
                false,
                false,
            ),
            (
                "the longest age limit",
                entry(&|t| t.max_token_age_secs = Some(MAX_TOKEN_AGE_SECS)),
                false,
                true,
            ),
            (
                "too long an age limit",
                entry(&|t| t.max_token_age_secs = Some(MAX_TOKEN_AGE_SECS + 1)),
                false,
                false,
            ),
            // Rules as GitHub's must be: something admitted, pinned by id.
            (
                "no rules",
                entry(&|t| {
                    t.policy = Policy {
                        audience: AUDIENCE.into(),
                        ..Policy::default()
                    };
                }),
                false,
                false,
            ),
            (
                "names only",
                entry(&|t| t.policy.repository_ids.clear()),
                false,
                false,
            ),
            (
                "any workflow of an owner",
                entry(&|t| t.policy = entries("{any_workflow: {repositories: {owner_ids: [1]}}}")),
                false,
                true,
            ),
            // Rules that need a claim the forge's tokens lack.
            (
                "forgejo, entry workflows",
                entry(&|t| t.policy.entry_workflows = Some(HashSet::from([FORGE_WORKFLOW.into()]))),
                false,
                false,
            ),
            (
                "forgejo, called workflows",
                entry(&|t| t.policy.called_workflows = called.clone()),
                false,
                false,
            ),
            (
                "github claims, called workflows",
                entry(&|t| {
                    t.claims = ClaimSet::Github;
                    t.policy.called_workflows = called.clone();
                }),
                false,
                true,
            ),
        ];
        for (name, trusted, allow_http, valid) in cases {
            assert_eq!(trusted.validate(allow_http).is_ok(), valid, "{name}");
        }
    }
}
