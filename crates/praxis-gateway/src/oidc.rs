//! GitHub Actions OIDC tokens as the authority to register a run.
//!
//! A verified token from an allowed repository, workflow and event proves
//! the caller runs in that job. It does not prove the caller is the job's
//! supervisor rather than its agent: GitHub puts the request credentials
//! (`ACTIONS_ID_TOKEN_REQUEST_URL` and `_TOKEN`) in the environment of every
//! step of a job with `id-token: write`, and every process a step starts
//! inherits them. The harness must keep them out of the agent's sandbox;
//! whoever holds them can register runs of that job.
//!
//! Which verified tokens register is the policy's: [`Policy`] has three
//! forms of entry, and a token registers if any one of them admits it.
use crate::runs::{Admitted, RunIdentity, unix_now};
use jsonwebtoken::{Algorithm, DecodingKey, Validation, decode, decode_header, jwk::JwkSet};
use reqwest::Client;
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
/// The length of a commit id, as `job_workflow_sha` gives one.
const SHA_HEX_LEN: usize = 40;
/// What a `ref` of the policy starts with, as in `job_workflow_ref`.
const REF_PREFIX: &str = "refs/";

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

#[derive(Deserialize)]
struct Claims {
    iat: u64,
    jti: String,
    repository: String,
    repository_id: String,
    repository_owner_id: String,
    run_id: String,
    run_attempt: String,
    /// The job's own check run; absent from tokens older than 2025.
    check_run_id: Option<String>,
    /// The workflow that runs the job, reusable or not.
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
/// `repository_owner_id` claims. For a job of a reusable workflow those
/// name the repository that called it, not the one that holds it.
#[derive(Clone, Debug, Default, PartialEq, Eq, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Repositories {
    /// Every repository on GitHub. Said outright, never implied by an
    /// empty list.
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

pub struct GithubOidc {
    client: Client,
    jwks_url: String,
    policy: Policy,
    /// Bounds registrations being verified at once.
    pub registrations: Semaphore,
    cache: Mutex<KeyCache>,
}

impl GithubOidc {
    pub fn new(client: Client, jwks_url: String, policy: Policy) -> Self {
        LazyLock::force(&ISSUED_AFTER);
        Self {
            client,
            jwks_url,
            policy,
            registrations: Semaphore::new(REGISTRATION_CONCURRENCY),
            cache: Mutex::default(),
        }
    }

    /// Verify a job's token and return the run it names, if the policy lets
    /// it register runs.
    pub async fn verify(&self, jwt: &str) -> Result<RunIdentity, OidcError> {
        if jwt.len() > MAX_JWT_BYTES {
            return Err(OidcError::Malformed);
        }
        let header = decode_header(jwt).map_err(|_| OidcError::Malformed)?;
        if header.alg != Algorithm::RS256 {
            return Err(OidcError::Invalid);
        }
        let kid = header.kid.ok_or(OidcError::Malformed)?;
        let key = self.key(&kid).await?;
        let mut validation = Validation::new(Algorithm::RS256);
        validation.set_audience(&[&self.policy.audience]);
        validation.set_issuer(&[GITHUB_ISSUER]);
        // `iat` is required by Claims itself.
        validation.set_required_spec_claims(&["exp", "nbf", "iss", "aud"]);
        validation.validate_nbf = true;
        validation.leeway = LEEWAY_SECS;
        let claims = decode::<Claims>(jwt, &key, &validation)
            .map_err(|error| match error.kind() {
                jsonwebtoken::errors::ErrorKind::Json(_) => OidcError::Malformed,
                _ => OidcError::Invalid,
            })?
            .claims;
        if claims.iat < *ISSUED_AFTER {
            return Err(OidcError::Invalid);
        }
        let number = |s: &str| s.parse::<u64>().map_err(|_| OidcError::Malformed);
        let repository_id = number(&claims.repository_id)?;
        let owner_id = number(&claims.repository_owner_id)?;
        let Some(admitted_by) = self.policy.admits(&claims, repository_id, owner_id) else {
            return Err(OidcError::WorkflowNotAllowed);
        };
        if claims.jti.is_empty() || claims.jti.len() > MAX_JTI {
            return Err(OidcError::Malformed);
        }
        Ok(RunIdentity {
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
                Err(()) => warn!("OIDC key set unavailable"),
            }
        }
        if cache.fetched.is_none_or(|t| t.elapsed() >= JWKS_MAX_STALE) {
            return Err(OidcError::Unavailable);
        }
        cache.keys.get(kid).cloned().ok_or(OidcError::Invalid)
    }

    /// Pretend the key set was fetched `by` earlier than it was.
    #[cfg(test)]
    pub async fn age_keys(&self, by: Duration) {
        let mut cache = self.cache.lock().await;
        cache.fetched = cache.fetched.and_then(|t| t.checked_sub(by));
        cache.attempted = cache.attempted.and_then(|t| t.checked_sub(by));
    }

    async fn fetch(&self) -> Result<HashMap<String, DecodingKey>, ()> {
        let body = timeout(JWKS_TIMEOUT, async {
            let mut response = self
                .client
                .get(&self.jwks_url)
                .send()
                .await
                .map_err(|_| ())?
                .error_for_status()
                .map_err(|_| ())?;
            let mut body = Vec::new();
            while let Some(chunk) = response.chunk().await.map_err(|_| ())? {
                if body.len() + chunk.len() > MAX_JWKS_BYTES {
                    return Err(());
                }
                body.extend_from_slice(&chunk);
            }
            Ok(body)
        })
        .await
        .map_err(|_| ())??;
        let set: JwkSet = serde_json::from_slice(&body).map_err(|_| ())?;
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
    use super::{DEFAULT_AUDIENCE, GITHUB_ISSUER, Policy};
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

    /// A GitHub-style OIDC token for run `run_id`, with `overrides` merged
    /// into its claims; a null removes a claim.
    pub fn jwt(run_id: u64, overrides: &Value) -> String {
        let now = crate::runs::unix_now();
        let mut claims = json!({
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
        for (name, value) in overrides.as_object().unwrap() {
            if value.is_null() {
                claims.as_object_mut().unwrap().remove(name);
            } else {
                claims[name] = value.clone();
            }
        }
        sign(&claims, jsonwebtoken::Algorithm::RS256, Some(TEST_KID))
    }

    /// Sign `claims` with the test key, or for HS256 with the public key set
    /// as the HMAC secret, the classic algorithm-confusion forgery.
    pub fn sign(claims: &Value, alg: jsonwebtoken::Algorithm, kid: Option<&str>) -> String {
        let mut header = Header::new(alg);
        header.kid = kid.map(str::to_owned);
        let key = match alg {
            jsonwebtoken::Algorithm::HS256 => EncodingKey::from_secret(TEST_JWKS.as_bytes()),
            _ => EncodingKey::from_rsa_pem(TEST_KEY.as_bytes()).unwrap(),
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
    async fn serve_jwks() -> (GithubOidc, Arc<AtomicBool>) {
        serve_jwks_for(policy()).await
    }

    /// Serve the test key set, until `down` is set, to verify against
    /// `policy`.
    async fn serve_jwks_for(policy: Policy) -> (GithubOidc, Arc<AtomicBool>) {
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
            .with_state(Arc::clone(&down));
        let listener = tokio::net::TcpListener::bind(("127.0.0.1", 0))
            .await
            .unwrap();
        let address = listener.local_addr().unwrap();
        tokio::spawn(async move { axum::serve(listener, router).await.unwrap() });
        let oidc = GithubOidc::new(Client::new(), format!("http://{address}/jwks"), policy);
        (oidc, down)
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
}
