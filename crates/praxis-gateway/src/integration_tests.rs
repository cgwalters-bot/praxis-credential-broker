//! The broker's Praxis end to end: this repository's praxis.yaml served by
//! Praxis with our registry, every cluster in front of a fake upstream of
//! its own, one of which also serves the test OIDC key set. Usage is metered
//! by praxis-ai's own `token_count`, and injected requests are capped per
//! provider window and per run by its `token_rate_limit`, keyed on the run
//! that `run_token` authenticates.
use crate::{
    oidc::testing::{OWNER_ID, REPOSITORY_ID, TEST_JWKS, WORKFLOW, jwt},
    runs::RECORD_SCHEMA,
};
use axum::{
    Router,
    body::Body,
    extract::State,
    http::{HeaderMap, Response, StatusCode, header},
    routing::{get, post},
};
use praxis_test_utils::{ProxyGuard, free_port, start_proxy_with_registry, test_subrequest_client};
use reqwest::{Client, Method};
use serde_json::{Value, json};
use serde_yaml::Value as Yaml;
use std::{
    sync::{Arc, Mutex},
    time::Duration,
};
use tokio::net::TcpListener;

const PRAXIS_YAML: &str = include_str!("../../../praxis.yaml");
/// The per-run cap the tests set, and what each request reserves against it.
const RUN_MAX_TOKENS: u64 = 150;
const RUN_RESERVED_TOKENS: u64 = 10;
const PLACEHOLDER: &str = "Bearer praxis-substitute:anthropic";
/// The broker's Claude token, as the tests configure credential_injection.
const BROKER_TOKEN: &str = "sk-ant-oat01-SYNTHETIC-BROKER-TOKEN";
const BROKER_AUTHORIZATION: &str = "Bearer sk-ant-oat01-SYNTHETIC-BROKER-TOKEN";
/// A Claude Code that is logged in itself, for pass-through.
const CALLER_OAUTH: &str = "Bearer sk-ant-oat01-SYNTHETIC-CALLER-OAUTH";

const RESPONSES: &str = "inference-backend";
const INJECTED: &str = "anthropic";
const PASS_THROUGH: &str = "anthropic-pass-through";
const CLUSTERS: [&str; 4] = [RESPONSES, INJECTED, PASS_THROUGH, "run-endpoints"];

/// Usage the fake upstream reports, and what a run record makes of it.
const RESPONSES_USAGE: &str = r#"{"input_tokens":70,"input_tokens_details":{"cached_tokens":30},"output_tokens":30,"output_tokens_details":{"reasoning_tokens":5},"total_tokens":100}"#;
const RESPONSES_TOTAL: u64 = 100;
const MESSAGES_TOTAL: u64 = 90;

/// What the fake upstreams received, in order.
#[derive(Default)]
struct Upstream {
    seen: Mutex<Vec<(&'static str, HeaderMap)>>,
}

impl Upstream {
    fn saw(&self, cluster: &'static str, headers: &HeaderMap) {
        self.seen.lock().unwrap().push((cluster, headers.clone()));
    }

    fn calls(&self) -> usize {
        self.seen.lock().unwrap().len()
    }

    /// The cluster of each request.
    fn clusters(&self) -> Vec<&'static str> {
        self.seen.lock().unwrap().iter().map(|(c, _)| *c).collect()
    }

    /// Header `name` of each request.
    fn seen(&self, name: &str) -> Vec<Option<String>> {
        let seen = self.seen.lock().unwrap();
        seen.iter()
            .map(|(_, headers)| headers.get(name).map(|v| v.to_str().unwrap().to_owned()))
            .collect()
    }
}

#[derive(Clone)]
struct Fake {
    upstream: Arc<Upstream>,
    cluster: &'static str,
}

fn sse(events: Vec<String>) -> Response<Body> {
    let stream = async_stream::stream! {
        for event in events {
            // Each event its own chunk, slowly enough for a client to leave.
            tokio::time::sleep(Duration::from_millis(50)).await;
            yield Ok::<_, std::io::Error>(bytes::Bytes::from(event));
        }
    };
    window_headers(
        Response::builder()
            .header(header::CONTENT_TYPE, "text/event-stream")
            .body(Body::from_stream(stream))
            .unwrap(),
    )
}

fn json_response(value: &Value) -> Response<Body> {
    window_headers(
        Response::builder()
            .header(header::CONTENT_TYPE, "application/json")
            .body(Body::from(value.to_string()))
            .unwrap(),
    )
}

fn window_headers(mut response: Response<Body>) -> Response<Body> {
    let fixtures: Value =
        serde_json::from_str(include_str!("../testdata/usage-headers.json")).unwrap();
    for provider in ["anthropic", "codex"] {
        for (name, value) in fixtures[provider].as_object().unwrap() {
            if name.starts_with("anthropic-ratelimit-unified-") || name.starts_with("x-codex-") {
                response.headers_mut().insert(
                    http::HeaderName::try_from(name.as_str()).unwrap(),
                    value.as_str().unwrap().parse().unwrap(),
                );
            }
        }
    }
    response
}

async fn fake_responses(
    State(fake): State<Fake>,
    headers: HeaderMap,
    body: bytes::Bytes,
) -> Response<Body> {
    fake.upstream.saw(fake.cluster, &headers);
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

async fn fake_messages(State(fake): State<Fake>, headers: HeaderMap) -> Response<Body> {
    fake.upstream.saw(fake.cluster, &headers);
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

async fn fake_count_tokens(State(fake): State<Fake>, headers: HeaderMap) -> Response<Body> {
    fake.upstream.saw(fake.cluster, &headers);
    json_response(&json!({"input_tokens": 12}))
}

/// A fake upstream for `cluster`, recording into `upstream`; every one also
/// serves the test OIDC key set.
async fn serve_upstream(upstream: &Arc<Upstream>, cluster: &'static str) -> String {
    let router = Router::new()
        .route("/v1/responses", post(fake_responses))
        .route("/v1/messages", post(fake_messages))
        .route("/v1/messages/count_tokens", post(fake_count_tokens))
        .route("/healthz", get(|| async { "ready\n" }))
        .route("/jwks", get(|| async { TEST_JWKS }))
        .with_state(Fake {
            upstream: Arc::clone(upstream),
            cluster,
        });
    let listener = TcpListener::bind(("127.0.0.1", 0)).await.unwrap();
    let address = listener.local_addr().unwrap().to_string();
    tokio::spawn(async move { axum::serve(listener, router).await.unwrap() });
    address
}

/// The filter entries of every chain in a Praxis config.
fn filters_mut(config: &mut Yaml) -> impl Iterator<Item = &mut Yaml> {
    config["filter_chains"]
        .as_sequence_mut()
        .unwrap()
        .iter_mut()
        .flat_map(|chain| chain["filters"].as_sequence_mut().unwrap().iter_mut())
}

/// The rules named `name` of the `token_rate_limit` filter `filter` is.
fn rules_named<'a>(filter: &'a mut Yaml, name: &'a str) -> impl Iterator<Item = &'a mut Yaml> {
    let rules = if filter["filter"] == "token_rate_limit" {
        filter["rules"].as_sequence_mut()
    } else {
        None
    };
    rules
        .into_iter()
        .flatten()
        .filter(move |rule| rule["name"] == name)
}

/// The broker's token where praxis.yaml reads it from the environment, which
/// tests can't safely set.
fn inline_broker_token(filter: &mut Yaml) {
    if filter["filter"] != "credential_injection" {
        return;
    }
    for cluster in filter["clusters"].as_sequence_mut().unwrap() {
        let cluster = cluster.as_mapping_mut().unwrap();
        assert!(cluster.remove("env_var").is_some());
        cluster.insert("value".into(), BROKER_TOKEN.into());
    }
}

struct Harness {
    base: String,
    http: Client,
    upstream: Arc<Upstream>,
    _policy: tempfile::TempDir,
    _proxy: ProxyGuard,
}

impl Harness {
    /// Serve praxis.yaml on a free port, every cluster pointed at a fake
    /// upstream of its own, run_token on a registry of its own, the test
    /// registration policy if `with_policy`, a per-run cap of
    /// `RUN_MAX_TOKENS`, and `tweak` applied to each filter.
    async fn start(with_policy: bool, tweak: impl Fn(&mut Yaml)) -> Self {
        praxis_ai::install_crypto_provider();
        let _ = tracing_subscriber::fmt()
            .with_env_filter(tracing_subscriber::EnvFilter::from_default_env())
            .with_test_writer()
            .try_init();
        let upstream = Arc::new(Upstream::default());
        let mut endpoints = std::collections::HashMap::new();
        for cluster in CLUSTERS {
            endpoints.insert(cluster, serve_upstream(&upstream, cluster).await);
        }
        let policy = tempfile::tempdir().unwrap();
        let policy_file = policy.path().join("run-token-policy.yaml");
        if with_policy {
            let policy = json!({
                "jwks_url": format!("http://{}/jwks", endpoints[RESPONSES]),
                "workflows": [WORKFLOW],
                "repository_ids": [REPOSITORY_ID],
                "owner_ids": [OWNER_ID],
                "concurrency": 2,
            });
            std::fs::write(&policy_file, policy.to_string()).unwrap();
        }
        let registry = format!("test-{}", hex::encode(rand::random::<[u8; 8]>()));
        let mut config: Yaml = serde_yaml::from_str(PRAXIS_YAML).unwrap();
        let listeners = config["listeners"].as_sequence_mut().unwrap();
        assert_eq!(listeners.len(), 1, "praxis.yaml has one listener");
        let address = format!("127.0.0.1:{}", free_port());
        listeners[0]["address"] = Yaml::from(address.clone());
        for filter in filters_mut(&mut config) {
            if filter["filter"] == "load_balancer" {
                for cluster in filter["clusters"].as_sequence_mut().unwrap() {
                    let name = cluster["name"].as_str().unwrap();
                    let endpoint = endpoints
                        .get(name)
                        .unwrap_or_else(|| panic!("no fake upstream for cluster {name}"));
                    cluster["endpoints"] = Yaml::Sequence(vec![endpoint.as_str().into()]);
                    cluster.as_mapping_mut().unwrap().remove("tls");
                }
            }
            if filter["filter"] == "run_token" {
                filter["registry"] = Yaml::from(registry.clone());
                filter["registration"]["policy_file"] = Yaml::from(policy_file.to_str().unwrap());
            }
            for rule in rules_named(filter, "run") {
                rule["capacity"] = Yaml::from(RUN_MAX_TOKENS);
                rule["reserved_tokens"] = Yaml::from(RUN_RESERVED_TOKENS);
            }
            inline_broker_token(filter);
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
            base: format!("http://{address}"),
            http: Client::new(),
            upstream,
            _policy: policy,
            _proxy: proxy,
        }
    }

    /// Serve praxis.yaml with the test registration policy.
    async fn with_policy() -> Self {
        Self::start(true, |_| {}).await
    }

    async fn call(
        &self,
        method: Method,
        path: &str,
        headers: &[(&str, &str)],
        body: Option<Value>,
    ) -> reqwest::Response {
        let mut request = self.http.request(method, format!("{}{path}", self.base));
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
            .call(method, path, &[("authorization", &auth)], None)
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

    /// A Responses request with `input`, streamed or not, with a run token
    /// as its bearer token.
    async fn respond(
        &self,
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
            .call(Method::POST, "/v1/responses", &headers, Some(body))
            .await;
        let status = response.status();
        (status, response.text().await.unwrap())
    }

    /// A streamed Messages request under /anthropic with `authorization`,
    /// and the run token, if any, in x-run-token, as Claude Code sends them.
    async fn message(&self, authorization: &str, token: Option<&str>) -> (StatusCode, String) {
        let mut headers = vec![
            ("authorization", authorization),
            ("anthropic-version", "2023-06-01"),
            ("accept-encoding", "gzip"),
            ("x-api-key", "sk-ant-api03-client"),
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
            .call(Method::POST, "/anthropic/v1/messages", &headers, Some(body))
            .await;
        let status = response.status();
        (status, response.text().await.unwrap())
    }

    /// An injected Messages request: the placeholder and a run token.
    async fn injected(&self, token: Option<&str>) -> (StatusCode, String) {
        self.message(PLACEHOLDER, token).await
    }
}

#[tokio::test(flavor = "multi_thread")]
async fn broker_usage_is_local_and_only_observes_injected_inference() {
    let h = Harness::start(false, |_| {}).await;
    let response = h.call(Method::GET, "/usage", &[], None).await;
    assert_eq!(response.status(), StatusCode::OK);
    let empty: Value = serde_json::from_slice(&response.bytes().await.unwrap()).unwrap();
    assert_eq!(empty["schema"], "praxis-broker-usage/v1");
    assert!(empty["anthropic"]["unified_5h"].is_null());
    assert!(empty["codex"]["primary"].is_null());
    for (method, path, status) in [
        (Method::POST, "/usage", StatusCode::METHOD_NOT_ALLOWED),
        (Method::GET, "/usage/", StatusCode::NOT_FOUND),
        (Method::GET, "/usagex", StatusCode::NOT_FOUND),
    ] {
        assert_eq!(h.call(method, path, &[], None).await.status(), status);
    }
    assert_eq!(h.upstream.calls(), 0);
    assert_eq!(h.message(CALLER_OAUTH, None).await.0, StatusCode::OK);
    let response = h.call(Method::GET, "/usage", &[], None).await;
    let after: Value = serde_json::from_slice(&response.bytes().await.unwrap()).unwrap();
    assert_eq!(after, empty);

    let h = Harness::with_policy().await;
    let token = h.run(42).await;
    let count = h
        .call(
            Method::POST,
            "/anthropic/v1/messages/count_tokens",
            &[("authorization", PLACEHOLDER), ("x-run-token", &token)],
            Some(json!({})),
        )
        .await;
    assert_eq!(count.status(), StatusCode::OK);
    count.bytes().await.unwrap();
    let response = h.call(Method::GET, "/usage", &[], None).await;
    let after: Value = serde_json::from_slice(&response.bytes().await.unwrap()).unwrap();
    assert!(after["anthropic"]["unified_5h"].is_null());
    assert_eq!(after["anthropic"]["counts"]["requests"], 0);
    assert_eq!(h.respond(Some(&token), "", false).await.0, StatusCode::OK);
    assert_eq!(h.injected(Some(&token)).await.0, StatusCode::OK);
    let calls = h.upstream.calls();
    let response = h.call(Method::GET, "/usage?ignored=true", &[], None).await;
    let after: Value = serde_json::from_slice(&response.bytes().await.unwrap()).unwrap();
    assert_eq!(h.upstream.calls(), calls);
    assert_eq!(after["anthropic"]["counts"]["requests"], 1);
    assert_eq!(
        after["anthropic"]["counts"]["tokens"]["total"],
        MESSAGES_TOTAL
    );
    assert_eq!(after["codex"]["counts"]["requests"], 1);
    assert_eq!(after["codex"]["counts"]["tokens"]["total"], RESPONSES_TOTAL);
    assert_eq!(after["anthropic"]["unified_5h"]["utilization"], 0.42);
    assert_eq!(
        after["anthropic"]["unified_7d"]["status"],
        "allowed_warning"
    );
    assert_eq!(after["codex"]["primary"]["used_percent"], 42.5);
    assert_eq!(after["codex"]["secondary"]["window_minutes"], 10080);
    assert!(after["codex"]["primary"]["observed_at"].as_u64().unwrap() > 0);
    let serialized = after.to_string();
    for secret in [
        token.as_str(),
        BROKER_TOKEN,
        CALLER_OAUTH,
        "SYNTHETIC-SECRET",
        "SYNTHETIC-PROMPT",
    ] {
        assert!(!serialized.contains(secret));
    }
}

#[tokio::test(flavor = "multi_thread")]
async fn streamed_responses_and_messages_are_metered_and_capped_per_run() {
    let h = Harness::with_policy().await;
    let token = h.run(1).await;

    let (status, body) = h.respond(Some(&token), "", true).await;
    assert_eq!(status, StatusCode::OK, "{body}");
    assert!(body.contains("\"delta\":\"hello\"") && body.contains("response.completed"));
    let (status, body) = h.injected(Some(&token)).await;
    assert_eq!(status, StatusCode::OK, "{body}");
    assert!(body.contains("message_stop"));
    // Upstream never got the run token or the client's credentials, only
    // the broker's own on the Messages API (credential-proxy adds Codex's),
    // and no compression that would hide the usage.
    assert_eq!(h.upstream.clusters(), [RESPONSES, INJECTED]);
    assert_eq!(
        h.upstream.seen("authorization"),
        [None, Some(BROKER_AUTHORIZATION.into())]
    );
    assert_eq!(h.upstream.seen("x-run-token"), [None, None]);
    assert_eq!(h.upstream.seen("x-api-key"), [None, None]);
    assert_eq!(h.upstream.seen("accept-encoding"), [None, None]);
    assert_eq!(
        h.upstream.seen("anthropic-beta"),
        [None, Some("oauth-2025-04-20".into())]
    );

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

    // Each API caps the run on its own. One more request of each fits and
    // overshoots the cap, which token_rate_limit then enforces.
    let (status, _) = h.respond(Some(&token), "", false).await;
    assert_eq!(status, StatusCode::OK);
    let (status, _) = h.injected(Some(&token)).await;
    assert_eq!(status, StatusCode::OK);
    let calls = h.upstream.calls();
    let (status, body) = h.respond(Some(&token), "", true).await;
    assert_eq!(status, StatusCode::TOO_MANY_REQUESTS, "{body}");
    let (status, _) = h.injected(Some(&token)).await;
    assert_eq!(status, StatusCode::TOO_MANY_REQUESTS);
    assert_eq!(
        h.upstream.calls(),
        calls,
        "refused requests reached upstream"
    );
    let usage = h.usage(&token).await;
    assert_eq!(usage["requests"], 4);
    assert_eq!(
        usage["tokens"]["total"],
        2 * (RESPONSES_TOTAL + MESSAGES_TOTAL)
    );
    // The cap is the run's own: another run is not refused.
    let other = h.run(2).await;
    let (status, _) = h.injected(Some(&other)).await;
    assert_eq!(status, StatusCode::OK);
    let (status, _) = h.respond(Some(&other), "", true).await;
    assert_eq!(status, StatusCode::OK);

    // Finishing returns the final record; the token then admits nothing but
    // still reads it.
    let (status, finished) = h.runs(Method::DELETE, "/v1/runs/self", &token).await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(finished["state"], "finished");
    assert!(finished["finished_at_unix"].is_u64());
    assert_eq!(h.usage(&token).await, finished);
    let (status, _) = h.injected(Some(&other)).await;
    assert_eq!(status, StatusCode::OK);
    let (status, _) = h.injected(Some(&token)).await;
    assert_eq!(status, StatusCode::UNAUTHORIZED);
}

#[tokio::test(flavor = "multi_thread")]
async fn pass_through_forwards_the_callers_credential_and_is_only_metered() {
    let h = Harness::with_policy().await;
    // No run token needed, and no run cap: more than one run's worth goes
    // through, every one metered by token_count on the way.
    let n = RUN_MAX_TOKENS / MESSAGES_TOTAL + 2;
    for _ in 0..n {
        let (status, body) = h.message(CALLER_OAUTH, None).await;
        assert_eq!(status, StatusCode::OK, "{body}");
        assert!(body.contains("message_stop"));
    }
    // A run token the caller sends anyway is removed, and the caller's own
    // Authorization goes upstream as it is, never the broker's.
    let token = h.run(1).await;
    let (status, _) = h.message(CALLER_OAUTH, Some(&token)).await;
    assert_eq!(status, StatusCode::OK);
    let n = usize::try_from(n).unwrap() + 1;
    assert_eq!(h.upstream.clusters(), vec![PASS_THROUGH; n]);
    assert_eq!(
        h.upstream.seen("authorization"),
        vec![Some(CALLER_OAUTH.to_owned()); n]
    );
    assert_eq!(h.upstream.seen("x-run-token"), vec![None; n]);
    assert_eq!(h.upstream.seen("x-api-key"), vec![None; n]);
    assert_eq!(h.upstream.seen("anthropic-beta"), vec![None; n]);
    assert_eq!(
        h.upstream.seen("host"),
        vec![Some("api.anthropic.com".to_owned()); n]
    );
    // Pass-through is not charged to the run.
    assert_eq!(h.usage(&token).await["requests"], 0);
    // A run token as the provider credential would leak it; refused.
    let auth = format!("Bearer {token}");
    let (status, _) = h.message(&auth, None).await;
    assert_eq!(status, StatusCode::BAD_REQUEST);
    assert_eq!(h.upstream.calls(), n);
}

/// Praxis AI's own startup validation, which the test harness skips,
/// accepts praxis.yaml; it refuses, say, conditions on security filters.
#[test]
fn praxis_yaml_passes_praxis_validation() {
    praxis_ai::install_crypto_provider();
    let mut config: Yaml = serde_yaml::from_str(PRAXIS_YAML).unwrap();
    filters_mut(&mut config).for_each(inline_broker_token);
    let config =
        praxis_core::config::Config::from_yaml(&serde_yaml::to_string(&config).unwrap()).unwrap();
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
async fn injected_requests_without_a_valid_run_token_are_refused() {
    let h = Harness::with_policy().await;
    let jwt = jwt(1, &json!({}));
    for token in [None, Some("praxis-run-0000"), Some(jwt.as_str())] {
        let (status, _) = h.respond(token, "", true).await;
        assert_eq!(status, StatusCode::UNAUTHORIZED, "{token:?}");
        let (status, _) = h.injected(token).await;
        assert_eq!(status, StatusCode::UNAUTHORIZED, "{token:?}");
    }
    // x-run-token, when present, is the one that must hold the token, even
    // if Authorization holds a valid one.
    let token = h.run(1).await;
    let auth = format!("Bearer {token}");
    let response = h
        .call(
            Method::POST,
            "/v1/responses",
            &[("authorization", &auth), ("x-run-token", "praxis-run-0000")],
            Some(json!({"model": "gpt-test", "input": ""})),
        )
        .await;
    assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
    // A second Authorization header is refused, whichever comes first: the
    // router and the conditions would disagree about the route.
    for headers in [[PLACEHOLDER, CALLER_OAUTH], [CALLER_OAUTH, PLACEHOLDER]] {
        let response = h
            .call(
                Method::POST,
                "/anthropic/v1/messages",
                &[
                    ("authorization", headers[0]),
                    ("authorization", headers[1]),
                    ("x-run-token", &token),
                ],
                Some(json!({"model": "claude-test", "max_tokens": 1, "messages": [{"role": "user", "content": "hi"}]})),
            )
            .await;
        assert_eq!(response.status(), StatusCode::BAD_REQUEST, "{headers:?}");
    }
    assert_eq!(h.upstream.calls(), 0);
    // The health check needs no token (and the fake doesn't record it).
    let response = h.call(Method::GET, "/healthz", &[], None).await;
    assert_eq!(response.status(), StatusCode::OK);
}

#[tokio::test(flavor = "multi_thread")]
async fn without_a_policy_file_only_pass_through_is_served() {
    let h = Harness::start(false, |_| {}).await;
    let (status, _) = h.register(&jwt(1, &json!({}))).await;
    assert_eq!(status, StatusCode::SERVICE_UNAVAILABLE);
    let (status, _) = h.respond(None, "", true).await;
    assert_eq!(status, StatusCode::UNAUTHORIZED);
    let (status, _) = h.injected(None).await;
    assert_eq!(status, StatusCode::UNAUTHORIZED);
    let response = h.call(Method::GET, "/healthz", &[], None).await;
    assert_eq!(response.status(), StatusCode::OK);
    let (status, body) = h.message(CALLER_OAUTH, None).await;
    assert_eq!(status, StatusCode::OK, "{body}");
    assert_eq!(h.upstream.clusters(), [PASS_THROUGH]);
}

#[tokio::test(flavor = "multi_thread")]
async fn registration_is_once_per_job_with_retries_for_a_lost_reply() {
    let h = Harness::with_policy().await;
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
    let response = h.call(Method::POST, "/v1/runs", &[], None).await;
    assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
    let response = h.call(Method::PUT, "/v1/runs", &[], None).await;
    assert_eq!(response.status(), StatusCode::METHOD_NOT_ALLOWED);
    let response = h.call(Method::GET, "/v1/runs/other", &[], None).await;
    assert_eq!(response.status(), StatusCode::NOT_FOUND);
    // run_token answered all of them; the placeholder cluster behind
    // /v1/runs is never connected to.
    assert_eq!(h.upstream.calls(), 0);
}

#[tokio::test(flavor = "multi_thread")]
async fn a_request_the_client_leaves_keeps_its_reservation_against_the_run() {
    // Room for one request's reservation, but not for a second while the
    // first one's stays.
    let reserved = RUN_MAX_TOKENS / 2 + 1;
    let h = Harness::start(true, move |filter| {
        for rule in rules_named(filter, "run") {
            rule["reserved_tokens"] = Yaml::from(reserved);
        }
    })
    .await;
    let token = h.run(1).await;
    let auth = format!("Bearer {token}");
    let mut response = h
        .call(
            Method::POST,
            "/v1/responses",
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
async fn token_rate_limit_caps_each_providers_window_for_injected_requests() {
    // Room for one request's reservation, but not for another's on top of
    // what the first one used.
    let h = Harness::start(true, |filter| {
        for rule in rules_named(filter, "window") {
            let reserved = rule["reserved_tokens"].as_u64().unwrap();
            rule["capacity"] = Yaml::from(reserved + MESSAGES_TOTAL.min(RESPONSES_TOTAL) - 1);
        }
    })
    .await;
    // Each request from a run of its own, so no run cap gets in the way.
    let mut run_id = 0;
    let mut token = async || {
        run_id += 1;
        h.run(run_id).await
    };
    let (status, body) = h.respond(Some(&token().await), "", true).await;
    assert_eq!(status, StatusCode::OK, "{body}");
    let (status, _) = h.respond(Some(&token().await), "", true).await;
    assert_eq!(status, StatusCode::TOO_MANY_REQUESTS);
    // The Messages API has a window of its own.
    let (status, body) = h.injected(Some(&token().await)).await;
    assert_eq!(status, StatusCode::OK, "{body}");
    let (status, _) = h.injected(Some(&token().await)).await;
    assert_eq!(status, StatusCode::TOO_MANY_REQUESTS);
    // Pass-through spends the caller's own subscription, not the window.
    for _ in 0..2 {
        let (status, _) = h.message(CALLER_OAUTH, None).await;
        assert_eq!(status, StatusCode::OK);
    }
    assert_eq!(
        h.upstream.clusters(),
        [RESPONSES, INJECTED, PASS_THROUGH, PASS_THROUGH]
    );
    // The health check is not metered.
    for _ in 0..3 {
        let response = h.call(Method::GET, "/healthz", &[], None).await;
        assert_eq!(response.status(), StatusCode::OK);
    }
}

#[tokio::test(flavor = "multi_thread")]
async fn every_spelling_of_an_injected_request_is_capped_and_counting_tokens_is_free() {
    let h = Harness::with_policy().await;
    let token = h.run(1).await;
    let headers = [
        ("authorization", PLACEHOLDER),
        ("x-run-token", token.as_str()),
    ];
    let body = json!({"model": "claude-test", "max_tokens": 1, "messages": [{"role": "user", "content": "hi"}]});
    // More count_tokens calls than the cap has room for reservations: they
    // are forwarded, but neither capped nor charged to the run.
    let n = RUN_MAX_TOKENS / RUN_RESERVED_TOKENS + 1;
    for _ in 0..n {
        let response = h
            .call(
                Method::POST,
                "/anthropic/v1/messages/count_tokens",
                &headers,
                Some(body.clone()),
            )
            .await;
        assert_eq!(response.status(), StatusCode::OK);
    }
    let usage = h.usage(&token).await;
    assert_eq!(
        (
            &usage["requests"],
            &usage["unmetered"],
            &usage["tokens"]["total"]
        ),
        (&json!(0), &json!(0), &json!(0)),
        "{usage}"
    );
    // Use up the run's Messages cap, then try the other spellings that the
    // router sends to the same cluster.
    for _ in 0..2 {
        let (status, _) = h.injected(Some(&token)).await;
        assert_eq!(status, StatusCode::OK);
    }
    let calls = h.upstream.calls();
    let lowercase = Method::from_bytes(b"post").unwrap();
    for (method, path) in [
        (Method::POST, "/anthropic/v1/messages"),
        (lowercase.clone(), "/anthropic/v1/messages"),
        (Method::POST, "/anthropic/v1/messages?beta=true"),
        (lowercase, "/anthropic/v1/messages?beta=true"),
    ] {
        let response = h
            .call(method.clone(), path, &headers, Some(body.clone()))
            .await;
        assert_eq!(
            response.status(),
            StatusCode::TOO_MANY_REQUESTS,
            "{method} {path}"
        );
    }
    assert_eq!(
        h.upstream.calls(),
        calls,
        "refused requests reached upstream"
    );
}
