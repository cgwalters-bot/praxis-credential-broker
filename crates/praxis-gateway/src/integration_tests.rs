//! The broker's Praxis end to end: this repository's praxis.yaml served by
//! Praxis with our registry, in front of a fake upstream that also serves
//! the test OIDC key set. Usage is metered by praxis-ai's own
//! `token_count`, and capped per provider window and, on the run-token
//! listener, per run by its `token_rate_limit`, keyed on the run that
//! `run_token` authenticates.
use crate::{
    oidc::{self, GithubOidc, OidcError, Policy},
    runs::RECORD_SCHEMA,
};
use axum::{
    Router,
    body::Body,
    extract::State,
    http::{HeaderMap, Response, StatusCode, header},
    routing::{get, post},
};
use jsonwebtoken::{EncodingKey, Header};
use praxis_test_utils::{ProxyGuard, free_port, start_proxy_with_registry, test_subrequest_client};
use reqwest::{Client, Method};
use serde_json::{Value, json};
use serde_yaml::Value as Yaml;
use std::{
    collections::HashSet,
    sync::{
        Arc, Mutex,
        atomic::{AtomicBool, AtomicUsize, Ordering},
    },
    time::Duration,
};
use tokio::net::TcpListener;

const PRAXIS_YAML: &str = include_str!("../../../praxis.yaml");
/// A throwaway RSA key made for these tests; nothing else trusts it.
const TEST_KEY: &str = include_str!("../testdata/oidc-test-key.pem");
const TEST_JWKS: &str = include_str!("../testdata/oidc-test-jwks.json");
const TEST_KID: &str = "praxis-test-key";
const AUDIENCE: &str = oidc::DEFAULT_AUDIENCE;
const WORKFLOW: &str = "owner/repo/.github/workflows/agent.yml@refs/heads/main";
const REPOSITORY_ID: u64 = 7;
const OWNER_ID: u64 = 70;
/// The per-run cap the tests set, and what each request reserves against it.
const RUN_MAX_TOKENS: u64 = 250;
const RUN_RESERVED_TOKENS: u64 = 10;
const CLAUDE_OAUTH: &str = "Bearer claude-oauth-token";

/// Usage the fake upstream reports, and what a run record makes of it.
const RESPONSES_USAGE: &str = r#"{"input_tokens":70,"input_tokens_details":{"cached_tokens":30},"output_tokens":30,"output_tokens_details":{"reasoning_tokens":5},"total_tokens":100}"#;
const RESPONSES_TOTAL: u64 = 100;
const MESSAGES_TOTAL: u64 = 90;

#[derive(Default)]
struct Upstream {
    calls: AtomicUsize,
    jwks_down: AtomicBool,
    /// The headers of each inference request.
    seen: Mutex<Vec<HeaderMap>>,
}

impl Upstream {
    fn saw(&self, headers: &HeaderMap) {
        self.calls.fetch_add(1, Ordering::SeqCst);
        self.seen.lock().unwrap().push(headers.clone());
    }

    /// Header `name` of each inference request.
    fn seen(&self, name: &str) -> Vec<Option<String>> {
        let seen = self.seen.lock().unwrap();
        seen.iter()
            .map(|headers| headers.get(name).map(|v| v.to_str().unwrap().to_owned()))
            .collect()
    }
}

fn sse(events: Vec<String>) -> Response<Body> {
    let stream = async_stream::stream! {
        for event in events {
            // Each event its own chunk, slowly enough for a client to leave.
            tokio::time::sleep(Duration::from_millis(50)).await;
            yield Ok::<_, std::io::Error>(bytes::Bytes::from(event));
        }
    };
    Response::builder()
        .header(header::CONTENT_TYPE, "text/event-stream")
        .body(Body::from_stream(stream))
        .unwrap()
}

fn json_response(value: &Value) -> Response<Body> {
    Response::builder()
        .header(header::CONTENT_TYPE, "application/json")
        .body(Body::from(value.to_string()))
        .unwrap()
}

async fn fake_responses(
    State(upstream): State<Arc<Upstream>>,
    headers: HeaderMap,
    body: bytes::Bytes,
) -> Response<Body> {
    upstream.saw(&headers);
    let request: Value = serde_json::from_slice(&body).unwrap_or_default();
    let usage: Value = serde_json::from_str(RESPONSES_USAGE).unwrap();
    if request["stream"] != true {
        return json_response(
            &json!({"id": "r", "object": "response", "model": "gpt-test", "usage": usage}),
        );
    }
    let mut events = vec![
        "event: response.created\ndata: {\"type\":\"response.created\",\"response\":{\"model\":\"gpt-test\"}}\n\n".to_owned(),
    ];
    // A long stream for a client to leave in the middle of.
    let deltas = if request["input"] == "long" { 40 } else { 1 };
    for _ in 0..deltas {
        events.push("event: response.output_text.delta\ndata: {\"type\":\"response.output_text.delta\",\"delta\":\"hello\"}\n\n".to_owned());
    }
    let completed =
        json!({"type": "response.completed", "response": {"model": "gpt-test", "usage": usage}});
    events.push(format!("event: response.completed\ndata: {completed}\n\n"));
    sse(events)
}

async fn fake_messages(
    State(upstream): State<Arc<Upstream>>,
    headers: HeaderMap,
) -> Response<Body> {
    upstream.saw(&headers);
    let start = json!({"type": "message_start", "message": {"id": "m", "model": "claude-test", "usage": {"input_tokens": 40, "cache_read_input_tokens": 20, "output_tokens": 1}}});
    let delta = json!({"type": "content_block_delta", "index": 0, "delta": {"type": "text_delta", "text": "hi"}});
    let end = json!({"type": "message_delta", "delta": {"stop_reason": "end_turn"}, "usage": {"output_tokens": 30}});
    sse(vec![
        format!("event: message_start\ndata: {start}\n\n"),
        format!("event: content_block_delta\ndata: {delta}\n\n"),
        format!("event: message_delta\ndata: {end}\n\n"),
        "event: message_stop\ndata: {\"type\":\"message_stop\"}\n\n".to_owned(),
    ])
}

async fn serve_upstream() -> (String, Arc<Upstream>) {
    let upstream = Arc::new(Upstream::default());
    let jwks = |State(upstream): State<Arc<Upstream>>| async move {
        if upstream.jwks_down.load(Ordering::SeqCst) {
            Err(StatusCode::SERVICE_UNAVAILABLE)
        } else {
            Ok(TEST_JWKS)
        }
    };
    let router = Router::new()
        .route("/v1/responses", post(fake_responses))
        .route("/v1/messages", post(fake_messages))
        .route("/healthz", get(|| async { "ready\n" }))
        .route("/jwks", get(jwks))
        .with_state(Arc::clone(&upstream));
    let listener = TcpListener::bind(("127.0.0.1", 0)).await.unwrap();
    let address = listener.local_addr().unwrap().to_string();
    tokio::spawn(async move { axum::serve(listener, router).await.unwrap() });
    (address, upstream)
}

/// The filter entries of every chain in a Praxis config.
fn filters_mut(config: &mut Yaml) -> impl Iterator<Item = &mut Yaml> {
    config["filter_chains"]
        .as_sequence_mut()
        .unwrap()
        .iter_mut()
        .flat_map(|chain| chain["filters"].as_sequence_mut().unwrap().iter_mut())
}

/// `value` as YAML. JSON is YAML; going through text keeps numbers numbers
/// when serde_json has `arbitrary_precision`, as some workspace members turn
/// on.
fn yaml(value: &Value) -> Yaml {
    serde_yaml::from_str(&value.to_string()).unwrap()
}

struct Harness {
    /// The listener without run tokens.
    plain: String,
    /// The run-token listener.
    runs: String,
    http: Client,
    upstream: Arc<Upstream>,
    _policy: tempfile::TempDir,
    _proxy: ProxyGuard,
}

/// A rule of the `token_rate_limit` filter `filter` is.
fn rule_named<'a>(filter: &'a mut Yaml, name: &str) -> Option<&'a mut Yaml> {
    if filter["filter"] != "token_rate_limit" {
        return None;
    }
    filter["rules"]
        .as_sequence_mut()
        .unwrap()
        .iter_mut()
        .find(|rule| rule["name"] == name)
}

impl Harness {
    /// Serve praxis.yaml with its listeners on free ports, every cluster
    /// pointed at the fake upstream, run_token filters on a registry of
    /// their own, the test registration policy if `with_policy`, a per-run
    /// cap of `RUN_MAX_TOKENS`, and `tweak` applied to each filter.
    async fn start(with_policy: bool, tweak: impl Fn(&mut Yaml)) -> Self {
        praxis_ai::install_crypto_provider();
        let _ = tracing_subscriber::fmt()
            .with_env_filter(tracing_subscriber::EnvFilter::from_default_env())
            .with_test_writer()
            .try_init();
        let (upstream_address, upstream) = serve_upstream().await;
        let policy = tempfile::tempdir().unwrap();
        let policy_file = policy.path().join("run-token-policy.yaml");
        if with_policy {
            let policy = json!({
                "jwks_url": format!("http://{upstream_address}/jwks"),
                "workflows": [WORKFLOW],
                "repository_ids": [REPOSITORY_ID],
                "owner_ids": [OWNER_ID],
                "concurrency": 2,
            });
            std::fs::write(&policy_file, policy.to_string()).unwrap();
        }
        let registry = format!("test-{}", hex::encode(rand::random::<[u8; 8]>()));
        let mut config: Yaml = serde_yaml::from_str(PRAXIS_YAML).unwrap();
        let mut addresses = Vec::new();
        for listener in config["listeners"].as_sequence_mut().unwrap() {
            let address = format!("127.0.0.1:{}", free_port());
            listener["address"] = Yaml::from(address.clone());
            addresses.push(format!("http://{address}"));
        }
        for filter in filters_mut(&mut config) {
            if let Some(clusters) = filter.get_mut("clusters").and_then(Yaml::as_sequence_mut) {
                for cluster in clusters {
                    cluster["endpoints"] = yaml(&json!([upstream_address]));
                    cluster.as_mapping_mut().unwrap().remove("tls");
                }
            }
            if filter["filter"] == "run_token" {
                filter["registry"] = Yaml::from(registry.clone());
                if filter.get("registration").is_some() {
                    filter["registration"]["policy_file"] =
                        Yaml::from(policy_file.to_str().unwrap());
                }
            }
            if let Some(rule) = rule_named(filter, "run") {
                rule["capacity"] = Yaml::from(RUN_MAX_TOKENS);
                rule["reserved_tokens"] = Yaml::from(RUN_RESERVED_TOKENS);
            }
            tweak(filter);
        }
        let config =
            praxis_core::config::Config::from_yaml(&serde_yaml::to_string(&config).unwrap())
                .unwrap();
        let registry = crate::registry(&test_subrequest_client()).unwrap();
        let proxy =
            tokio::task::spawn_blocking(move || start_proxy_with_registry(&config, &registry))
                .await
                .unwrap();
        Self {
            plain: addresses[0].clone(),
            runs: addresses[1].clone(),
            http: Client::new(),
            upstream,
            _policy: policy,
            _proxy: proxy,
        }
    }

    /// Serve praxis.yaml with the test registration policy.
    async fn run_token() -> Self {
        Self::start(true, |_| {}).await
    }

    fn upstream_calls(&self) -> usize {
        self.upstream.calls.load(Ordering::SeqCst)
    }

    async fn call(
        &self,
        method: Method,
        url: String,
        headers: &[(&str, &str)],
        body: Option<Value>,
    ) -> reqwest::Response {
        let mut request = self.http.request(method, url);
        for (name, value) in headers {
            request = request.header(*name, *value);
        }
        if let Some(body) = body {
            request = request
                .header(header::CONTENT_TYPE, "application/json")
                .body(body.to_string());
        }
        request.send().await.unwrap()
    }

    async fn runs(&self, method: Method, path: &str, bearer: &str) -> (StatusCode, Value) {
        let auth = format!("Bearer {bearer}");
        let response = self
            .call(
                method,
                format!("{}{path}", self.runs),
                &[("authorization", &auth)],
                None,
            )
            .await;
        let status = response.status();
        let body = response.bytes().await.unwrap();
        (status, serde_json::from_slice(&body).unwrap_or(Value::Null))
    }

    async fn register(&self, jwt: &str) -> (StatusCode, Value) {
        self.runs(Method::POST, "/v1/runs", jwt).await
    }

    /// Register run `run_id` and return its token.
    async fn run(&self, run_id: u64) -> String {
        let (status, body) = self.register(&jwt(run_id, &json!({}))).await;
        assert_eq!(status, StatusCode::CREATED, "{body}");
        body["token"].as_str().unwrap().to_owned()
    }

    async fn usage(&self, token: &str) -> Value {
        let (status, usage) = self.runs(Method::GET, "/v1/runs/self", token).await;
        assert_eq!(status, StatusCode::OK);
        usage
    }

    /// A Responses request with `input`, streamed or not, to the run-token
    /// listener.
    async fn respond(
        &self,
        token: Option<&str>,
        input: &str,
        stream: bool,
    ) -> (StatusCode, String) {
        self.respond_at(&self.runs, token, input, stream).await
    }

    async fn respond_at(
        &self,
        base: &str,
        token: Option<&str>,
        input: &str,
        stream: bool,
    ) -> (StatusCode, String) {
        let auth = token.map(|t| format!("Bearer {t}"));
        let mut headers = vec![("accept-encoding", "gzip")];
        if let Some(auth) = &auth {
            headers.push(("authorization", auth));
        }
        let body = json!({"model": "gpt-test", "input": input, "stream": stream});
        let response = self
            .call(
                Method::POST,
                format!("{base}/v1/responses"),
                &headers,
                Some(body),
            )
            .await;
        let status = response.status();
        (status, response.text().await.unwrap())
    }

    /// A streamed Messages request to the run-token listener, carrying
    /// Claude's own OAuth token and the run token in its own header.
    async fn message(&self, token: Option<&str>) -> (StatusCode, String) {
        self.message_at(&self.runs, token).await
    }

    async fn message_at(&self, base: &str, token: Option<&str>) -> (StatusCode, String) {
        let mut headers = vec![
            ("authorization", CLAUDE_OAUTH),
            ("anthropic-version", "2023-06-01"),
            ("accept-encoding", "gzip"),
        ];
        if let Some(token) = token {
            headers.push(("x-run-token", token));
        }
        let body = json!({
            "model": "claude-test",
            "max_tokens": 64,
            "stream": true,
            "messages": [{"role": "user", "content": "hi"}],
        });
        let response = self
            .call(
                Method::POST,
                format!("{base}/v1/messages"),
                &headers,
                Some(body),
            )
            .await;
        let status = response.status();
        (status, response.text().await.unwrap())
    }
}

/// A GitHub-style OIDC token for run `run_id`, with `overrides` merged into
/// its claims.
fn jwt(run_id: u64, overrides: &Value) -> String {
    let now = crate::runs::unix_now();
    let mut claims = json!({
        "iss": oidc::GITHUB_ISSUER,
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
fn sign(claims: &Value, alg: jsonwebtoken::Algorithm, kid: Option<&str>) -> String {
    let mut header = Header::new(alg);
    header.kid = kid.map(str::to_owned);
    let key = match alg {
        jsonwebtoken::Algorithm::HS256 => EncodingKey::from_secret(TEST_JWKS.as_bytes()),
        _ => EncodingKey::from_rsa_pem(TEST_KEY.as_bytes()).unwrap(),
    };
    jsonwebtoken::encode(&header, claims, &key).unwrap()
}

/// The claims of a token `jwt()` made.
fn claims_of(token: &str) -> Value {
    use base64::Engine;
    let payload = token.split('.').nth(1).unwrap();
    let bytes = base64::engine::general_purpose::URL_SAFE_NO_PAD
        .decode(payload)
        .unwrap();
    serde_json::from_slice(&bytes).unwrap()
}

#[tokio::test(flavor = "multi_thread")]
async fn streamed_responses_and_messages_are_metered_by_token_count_and_capped_per_run() {
    let h = Harness::run_token().await;
    let token = h.run(1).await;

    let (status, body) = h.respond(Some(&token), "", true).await;
    assert_eq!(status, StatusCode::OK, "{body}");
    assert!(body.contains("\"delta\":\"hello\"") && body.contains("response.completed"));
    let (status, body) = h.message(Some(&token)).await;
    assert_eq!(status, StatusCode::OK, "{body}");
    assert!(body.contains("message_stop"));
    // Upstream never got the run token, only Claude's own OAuth token on
    // the Messages API, and no compression that would hide the usage.
    assert_eq!(
        h.upstream.seen("authorization"),
        [None, Some(CLAUDE_OAUTH.into())]
    );
    assert_eq!(h.upstream.seen("x-run-token"), [None, None]);
    assert_eq!(h.upstream.seen("accept-encoding"), [None, None]);

    let usage = h.usage(&token).await;
    assert_eq!(usage["schema"], RECORD_SCHEMA);
    assert_eq!(
        (&usage["state"], &usage["requests"], &usage["unmetered"]),
        (&json!("active"), &json!(2), &json!(0))
    );
    // Responses: 70 in (30 cached), 30 out (5 reasoning). Messages: 40 in
    // plus 20 cache reads, 30 out.
    assert_eq!(
        usage["tokens"],
        json!({"input": 80, "cache_read": 50, "output": 60, "reasoning": 5, "total": RESPONSES_TOTAL + MESSAGES_TOTAL})
    );
    // By the model upstream named, from token_count's token.model.
    assert_eq!(
        (
            &usage["models"]["gpt-test"]["total"],
            &usage["models"]["claude-test"]["total"]
        ),
        (&json!(RESPONSES_TOTAL), &json!(MESSAGES_TOTAL))
    );

    // 190 of 250 used: one more request fits, and overshoots the cap, which
    // token_rate_limit then enforces on both APIs.
    let (status, _) = h.respond(Some(&token), "", false).await;
    assert_eq!(status, StatusCode::OK);
    let calls = h.upstream_calls();
    let (status, body) = h.respond(Some(&token), "", true).await;
    assert_eq!(status, StatusCode::TOO_MANY_REQUESTS, "{body}");
    let (status, _) = h.message(Some(&token)).await;
    assert_eq!(status, StatusCode::TOO_MANY_REQUESTS);
    assert_eq!(
        h.upstream_calls(),
        calls,
        "refused requests reached upstream"
    );
    let usage = h.usage(&token).await;
    assert_eq!(usage["requests"], 3);
    assert_eq!(
        usage["tokens"]["total"],
        2 * RESPONSES_TOTAL + MESSAGES_TOTAL
    );
    // The cap is the run's own: another run is not refused.
    let other = h.run(2).await;
    let (status, _) = h.message(Some(&other)).await;
    assert_eq!(status, StatusCode::OK);

    // Finishing returns the final record; the token then admits nothing but
    // still reads it.
    let (status, finished) = h.runs(Method::DELETE, "/v1/runs/self", &token).await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(finished["state"], "finished");
    assert!(finished["finished_at_unix"].is_u64());
    assert_eq!(h.usage(&token).await, finished);
    let (status, _) = h.message(Some(&token)).await;
    assert_eq!(status, StatusCode::UNAUTHORIZED);
}

/// Praxis AI's own startup validation, which the test harness skips,
/// accepts praxis.yaml; it refuses, say, conditions on security filters.
#[test]
fn praxis_yaml_passes_praxis_validation() {
    praxis_ai::install_crypto_provider();
    let config = praxis_core::config::Config::from_yaml(PRAXIS_YAML).unwrap();
    let client = test_subrequest_client();
    let registry = crate::registry(&client).unwrap();
    praxis_ai::resolve_pipelines(
        &config,
        &registry,
        &praxis_core::health::HealthRegistry::default(),
        &praxis_core::kv::KvStoreRegistry::new(),
        &client,
    )
    .unwrap();
}

#[tokio::test(flavor = "multi_thread")]
async fn requests_without_a_registered_run_are_refused() {
    let h = Harness::run_token().await;
    let jwt = jwt(1, &json!({}));
    for token in [None, Some("praxis-run-0000"), Some(jwt.as_str())] {
        let (status, _) = h.respond(token, "", true).await;
        assert_eq!(status, StatusCode::UNAUTHORIZED, "{token:?}");
        let (status, _) = h.message(token).await;
        assert_eq!(status, StatusCode::UNAUTHORIZED, "{token:?}");
    }
    // x-run-token, when present, is the one that must hold the token, even
    // if Authorization holds a valid one.
    let token = h.run(1).await;
    let auth = format!("Bearer {token}");
    let response = h
        .call(
            Method::POST,
            format!("{}/v1/responses", h.runs),
            &[("authorization", &auth), ("x-run-token", "praxis-run-0000")],
            Some(json!({"model": "gpt-test", "input": ""})),
        )
        .await;
    assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
    assert_eq!(h.upstream_calls(), 0);
    // The health check needs no token.
    let response = h
        .call(Method::GET, format!("{}/healthz", h.runs), &[], None)
        .await;
    assert_eq!(response.status(), StatusCode::OK);
    assert_eq!(h.upstream_calls(), 0);
}

#[tokio::test(flavor = "multi_thread")]
async fn without_a_policy_file_no_run_can_register() {
    let h = Harness::start(false, |_| {}).await;
    let (status, _) = h.register(&jwt(1, &json!({}))).await;
    assert_eq!(status, StatusCode::SERVICE_UNAVAILABLE);
    let (status, _) = h.respond(None, "", true).await;
    assert_eq!(status, StatusCode::UNAUTHORIZED);
    let response = h
        .call(Method::GET, format!("{}/healthz", h.runs), &[], None)
        .await;
    assert_eq!(response.status(), StatusCode::OK);
    // The plain listener needs no run token.
    let (status, body) = h.respond_at(&h.plain, None, "", true).await;
    assert_eq!(status, StatusCode::OK, "{body}");
}

#[tokio::test(flavor = "multi_thread")]
async fn registration_is_once_per_job_with_retries_for_a_lost_reply() {
    let h = Harness::run_token().await;
    let valid = jwt(1, &json!({}));
    let (status, body) = h.register(&valid).await;
    assert_eq!(status, StatusCode::CREATED);
    let lost = body["token"].as_str().unwrap().to_owned();
    assert!(lost.starts_with("praxis-run-"));
    let usage = &body["usage"];
    assert_eq!(
        (&usage["run_id"], &usage["workflow_ref"]),
        (&json!(1), &json!(WORKFLOW))
    );
    // The same OIDC token gets a new token, revoking the old one.
    let (status, body) = h.register(&valid).await;
    assert_eq!(status, StatusCode::CREATED);
    let token = body["token"].as_str().unwrap();
    assert_ne!(token, lost);
    assert_eq!(
        h.runs(Method::GET, "/v1/runs/self", &lost).await.0,
        StatusCode::UNAUTHORIZED
    );
    assert_eq!(
        h.runs(Method::GET, "/v1/runs/self", token).await.0,
        StatusCode::OK
    );
    // Another OIDC token for the same job may not.
    assert_eq!(
        h.register(&jwt(1, &json!({}))).await.0,
        StatusCode::CONFLICT
    );
    // Matrix jobs of one run register apart.
    assert_eq!(
        h.register(&jwt(1, &json!({"check_run_id": "99"}))).await.0,
        StatusCode::CREATED
    );
    // Bad and disallowed tokens.
    assert_eq!(h.register("not.a.jwt").await.0, StatusCode::UNAUTHORIZED);
    let other = jwt(2, &json!({"event_name": "pull_request_target"}));
    assert_eq!(h.register(&other).await.0, StatusCode::FORBIDDEN);
    let response = h
        .call(Method::POST, format!("{}/v1/runs", h.runs), &[], None)
        .await;
    assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
    let response = h
        .call(Method::PUT, format!("{}/v1/runs", h.runs), &[], None)
        .await;
    assert_eq!(response.status(), StatusCode::METHOD_NOT_ALLOWED);
}

#[tokio::test(flavor = "multi_thread")]
async fn a_request_the_client_leaves_keeps_its_reservation_against_the_run() {
    // Room for one request's reservation, but not for a second while the
    // first one's stays.
    let reserved = RUN_MAX_TOKENS / 2 + 1;
    let h = Harness::start(true, move |filter| {
        if let Some(rule) = rule_named(filter, "run") {
            rule["reserved_tokens"] = Yaml::from(reserved);
        }
    })
    .await;
    let token = h.run(1).await;
    let auth = format!("Bearer {token}");
    let mut response = h
        .call(
            Method::POST,
            format!("{}/v1/responses", h.runs),
            &[("authorization", &auth)],
            Some(json!({"model": "gpt-test", "input": "long", "stream": true})),
        )
        .await;
    assert_eq!(response.status(), StatusCode::OK);
    assert!(response.chunk().await.unwrap().is_some());
    drop(response);
    // Praxis notices when it next writes to the client.
    let mut usage = Value::Null;
    for _ in 0..100 {
        usage = h.usage(&token).await;
        if usage["unmetered"] == 1 {
            break;
        }
        tokio::time::sleep(Duration::from_millis(50)).await;
    }
    assert_eq!(
        (
            &usage["requests"],
            &usage["unmetered"],
            &usage["tokens"]["total"]
        ),
        (&json!(0), &json!(1), &json!(0)),
        "{usage}"
    );
    // token_rate_limit still holds what it reserved for the request.
    let (status, _) = h.respond(Some(&token), "", true).await;
    assert_eq!(status, StatusCode::TOO_MANY_REQUESTS);
}

#[tokio::test(flavor = "multi_thread")]
async fn token_rate_limit_caps_each_provider_window() {
    // Room for one request's reservation, but not for another's on top of
    // what the first one used.
    let h = Harness::start(false, |filter| {
        if let Some(rule) = rule_named(filter, "window") {
            let reserved = rule["reserved_tokens"].as_u64().unwrap();
            rule["capacity"] = Yaml::from(reserved + MESSAGES_TOTAL.min(RESPONSES_TOTAL) - 1);
        }
    })
    .await;
    let (status, body) = h.respond_at(&h.plain, None, "", true).await;
    assert_eq!(status, StatusCode::OK, "{body}");
    let (status, _) = h.respond_at(&h.plain, None, "", true).await;
    assert_eq!(status, StatusCode::TOO_MANY_REQUESTS);
    // The Messages API has a window of its own.
    let (status, body) = h.message_at(&h.plain, None).await;
    assert_eq!(status, StatusCode::OK, "{body}");
    let (status, _) = h.message_at(&h.plain, None).await;
    assert_eq!(status, StatusCode::TOO_MANY_REQUESTS);
    assert_eq!(h.upstream_calls(), 2);
    // Both APIs ask for uncompressed responses, which token_count reads,
    // and only Messages requests go to Anthropic's authority.
    assert_eq!(h.upstream.seen("accept-encoding"), [None, None]);
    assert_eq!(
        h.upstream
            .seen("host")
            .iter()
            .map(|h| h.as_deref() == Some("api.anthropic.com"))
            .collect::<Vec<_>>(),
        [false, true]
    );
    // The health check is not metered.
    for _ in 0..3 {
        let response = h
            .call(Method::GET, format!("{}/healthz", h.plain), &[], None)
            .await;
        assert_eq!(response.status(), StatusCode::OK);
    }
}

fn policy() -> Policy {
    Policy {
        audience: AUDIENCE.into(),
        workflows: HashSet::from([WORKFLOW.to_owned()]),
        repository_ids: HashSet::from([REPOSITORY_ID]),
        owner_ids: HashSet::from([OWNER_ID]),
        entry_workflows: None,
        events: HashSet::from(["workflow_dispatch".to_owned()]),
    }
}

#[tokio::test(flavor = "multi_thread")]
async fn oidc_tokens_must_be_valid_and_from_an_allowed_workflow() {
    praxis_ai::install_crypto_provider();
    let (upstream_address, _) = serve_upstream().await;
    let oidc = GithubOidc::new(
        Client::new(),
        format!("http://{upstream_address}/jwks"),
        policy(),
    );
    let now = crate::runs::unix_now();
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
    praxis_ai::install_crypto_provider();
    let (upstream_address, upstream) = serve_upstream().await;
    let oidc = GithubOidc::new(
        Client::new(),
        format!("http://{upstream_address}/jwks"),
        policy(),
    );
    assert!(oidc.verify(&jwt(1, &json!({}))).await.is_ok());
    // Refetching fails: the cached keys still verify for a while.
    upstream.jwks_down.store(true, Ordering::SeqCst);
    oidc.age_keys(Duration::from_secs(2 * 3600)).await;
    assert!(oidc.verify(&jwt(2, &json!({}))).await.is_ok());
    // But not once they are a day old.
    oidc.age_keys(Duration::from_secs(23 * 3600)).await;
    assert_eq!(
        oidc.verify(&jwt(3, &json!({}))).await.err(),
        Some(OidcError::Unavailable)
    );
    upstream.jwks_down.store(false, Ordering::SeqCst);
    oidc.age_keys(Duration::from_secs(3600)).await;
    assert!(oidc.verify(&jwt(3, &json!({}))).await.is_ok());
}
