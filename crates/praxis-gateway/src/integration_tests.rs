//! The gateway end to end: this repository's praxis.yaml served by Praxis
//! with our registry, in front of a fake upstream. Usage is metered by
//! praxis-ai's own `token_count` and capped per window by its
//! `token_rate_limit`.
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
    sync::{
        Arc, Mutex,
        atomic::{AtomicUsize, Ordering},
    },
    time::Duration,
};
use tokio::net::TcpListener;

const PRAXIS_YAML: &str = include_str!("../../../praxis.yaml");
const CLAUDE_OAUTH: &str = "Bearer claude-oauth-token";

/// Usage the fake upstream reports.
const RESPONSES_USAGE: &str = r#"{"input_tokens":70,"input_tokens_details":{"cached_tokens":30},"output_tokens":30,"output_tokens_details":{"reasoning_tokens":5},"total_tokens":100}"#;
const RESPONSES_TOTAL: u64 = 100;
const MESSAGES_TOTAL: u64 = 90;

#[derive(Default)]
struct Upstream {
    calls: AtomicUsize,
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
            // Each event its own chunk.
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
    events.push("event: response.output_text.delta\ndata: {\"type\":\"response.output_text.delta\",\"delta\":\"hello\"}\n\n".to_owned());
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
    let router = Router::new()
        .route("/v1/responses", post(fake_responses))
        .route("/v1/messages", post(fake_messages))
        .route("/healthz", get(|| async { "ready\n" }))
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
    base: String,
    http: Client,
    upstream: Arc<Upstream>,
    _proxy: ProxyGuard,
}

impl Harness {
    /// Serve `config` with its listener on a free port, every cluster
    /// pointed at the fake upstream, and `tweak` applied to each filter.
    async fn start(config: &str, tweak: impl Fn(&mut Yaml)) -> Self {
        praxis_ai::install_crypto_provider();
        let _ = tracing_subscriber::fmt()
            .with_env_filter(tracing_subscriber::EnvFilter::from_default_env())
            .with_test_writer()
            .try_init();
        let (upstream_address, upstream) = serve_upstream().await;
        let mut config: Yaml = serde_yaml::from_str(config).unwrap();
        let address = format!("127.0.0.1:{}", free_port());
        config["listeners"][0]["address"] = Yaml::from(address.clone());
        for filter in filters_mut(&mut config) {
            if let Some(clusters) = filter.get_mut("clusters").and_then(Yaml::as_sequence_mut) {
                for cluster in clusters {
                    cluster["endpoints"] = yaml(&json!([upstream_address]));
                    cluster.as_mapping_mut().unwrap().remove("tls");
                }
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
            base: format!("http://{address}"),
            http: Client::new(),
            upstream,
            _proxy: proxy,
        }
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

    /// A Responses request, streamed or not.
    async fn respond(&self, stream: bool) -> (StatusCode, String) {
        let body = json!({"model": "gpt-test", "input": "", "stream": stream});
        let response = self
            .call(
                Method::POST,
                format!("{}/v1/responses", self.base),
                &[("accept-encoding", "gzip")],
                Some(body),
            )
            .await;
        let status = response.status();
        (status, response.text().await.unwrap())
    }

    /// A streamed Messages request, carrying Claude's own OAuth token.
    async fn message(&self) -> (StatusCode, String) {
        let headers = [
            ("authorization", CLAUDE_OAUTH),
            ("anthropic-version", "2023-06-01"),
            ("accept-encoding", "gzip"),
        ];
        let body = json!({
            "model": "claude-test",
            "max_tokens": 64,
            "stream": true,
            "messages": [{"role": "user", "content": "hi"}],
        });
        let response = self
            .call(
                Method::POST,
                format!("{}/v1/messages", self.base),
                &headers,
                Some(body),
            )
            .await;
        let status = response.status();
        (status, response.text().await.unwrap())
    }
}

#[tokio::test(flavor = "multi_thread")]
async fn token_rate_limit_caps_each_provider_window() {
    // Room for one request's reservation, but not for another's on top of
    // what the first one used.
    let h = Harness::start(PRAXIS_YAML, |filter| {
        if filter["filter"] == "token_rate_limit" {
            let reserved = filter["rules"][0]["reserved_tokens"].as_u64().unwrap();
            filter["rules"][0]["capacity"] =
                Yaml::from(reserved + MESSAGES_TOTAL.min(RESPONSES_TOTAL) - 1);
        }
    })
    .await;
    let (status, body) = h.respond(true).await;
    assert_eq!(status, StatusCode::OK, "{body}");
    let (status, _) = h.respond(true).await;
    assert_eq!(status, StatusCode::TOO_MANY_REQUESTS);
    // The Messages API has a window of its own.
    let (status, body) = h.message().await;
    assert_eq!(status, StatusCode::OK, "{body}");
    let (status, _) = h.message().await;
    assert_eq!(status, StatusCode::TOO_MANY_REQUESTS);
    assert_eq!(h.upstream_calls(), 2);
    // Both APIs ask for uncompressed responses, which token_count reads,
    // and only Messages requests go to Anthropic's authority.
    assert_eq!(h.upstream.seen("accept-encoding"), [None, None]);
    assert_eq!(
        h.upstream
            .seen("host")
            .iter()
            .map(|host| host.as_deref() == Some("api.anthropic.com"))
            .collect::<Vec<_>>(),
        [false, true]
    );
    // The health check is not metered.
    for _ in 0..3 {
        let response = h
            .call(Method::GET, format!("{}/healthz", h.base), &[], None)
            .await;
        assert_eq!(response.status(), StatusCode::OK);
    }
}
