//! GitHub Actions OIDC tokens as the authority to register a run.
//!
//! A verified token from an allowed repository, workflow and event proves
//! the caller runs in that job. It does not prove the caller is the job's
//! supervisor rather than its agent: GitHub puts the request credentials
//! (`ACTIONS_ID_TOKEN_REQUEST_URL` and `_TOKEN`) in the environment of every
//! step of a job with `id-token: write`, and every process a step starts
//! inherits them. The harness must keep them out of the agent's sandbox;
//! whoever holds them can register runs of that job.
use crate::runs::{RunIdentity, unix_now};
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
    /// The workflow the run started from, which calls a reusable one.
    workflow_ref: String,
    event_name: String,
}

/// Which jobs may register runs. Identities are pinned by numeric id, since
/// a renamed or deleted owner's name can be taken by someone else.
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
}

impl Policy {
    /// Refuse a policy that would trust repositories by name only.
    pub fn validate(&self) -> Result<(), &'static str> {
        if self.workflows.is_empty() {
            return Err("the policy needs workflows");
        }
        if self.repository_ids.is_empty() && self.owner_ids.is_empty() {
            return Err("the policy needs repository_ids or owner_ids");
        }
        if self.events.is_empty() {
            return Err("the policy's events must name at least one event");
        }
        Ok(())
    }

    fn allows(&self, claims: &Claims, repository_id: u64, owner_id: u64) -> bool {
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
        if !self.policy.allows(&claims, repository_id, owner_id) {
            return Err(OidcError::WorkflowNotAllowed);
        }
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
            workflow_ref: claims.job_workflow_ref,
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

    pub fn policy() -> Policy {
        Policy {
            audience: AUDIENCE.into(),
            workflows: HashSet::from([WORKFLOW.to_owned()]),
            repository_ids: HashSet::from([REPOSITORY_ID]),
            owner_ids: HashSet::from([OWNER_ID]),
            entry_workflows: None,
            events: HashSet::from(["workflow_dispatch".to_owned()]),
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

    /// Serve the test key set, until `down` is set.
    async fn serve_jwks() -> (GithubOidc, Arc<AtomicBool>) {
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
        let oidc = GithubOidc::new(Client::new(), format!("http://{address}/jwks"), policy());
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
