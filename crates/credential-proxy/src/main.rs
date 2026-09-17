//! Generic credential egress proxy. It has no provider SDK or writable auth volume.
use axum::{
    Router,
    body::Body,
    extract::State,
    http::{HeaderName, Method, Request, StatusCode, header},
    response::Response,
    routing::get,
};
use credential_protocol::{
    Operation, Request as AgentRequest, Response as AgentResponse, VERSION, decode, encode,
    read_frame, request_mac, response_mac, valid_mac, validate_response,
};
use futures_util::StreamExt;
use reqwest::Client;
use sha2::{Digest, Sha256};
use std::{
    collections::HashSet,
    env, io,
    os::unix::fs::{FileTypeExt, MetadataExt},
    sync::Arc,
    time::Duration,
};
use subtle::ConstantTimeEq;
use tokio::{io::AsyncWriteExt, net::UnixStream, sync::Semaphore, time::timeout};
use tracing::warn;

const UPSTREAM: &str = "https://chatgpt.com/backend-api/codex/responses";
const MAX_BODY: usize = 10 * 1024 * 1024;
const MIN_KEY: usize = 32;
const AGENT_PROFILE: &str = "codex";
const AGENT_AUDIENCE: &str = "codex";
const AGENT_SOCKET: &str = "/run/praxis-credentials/agent.sock";
const CHANNEL_SECRET: &str = "/run/secrets/channel/agent-channel-key";
const RESPONSE_HEADER_TIMEOUT: Duration = Duration::from_secs(10);
const REQUEST_BODY_TIMEOUT: Duration = Duration::from_secs(10);

#[derive(Clone)]
struct App {
    client: Client,
    client_auth: ClientAuth,
    channel_key: Vec<u8>,
    max_bytes: usize,
    idle: Duration,
    concurrency: Arc<Semaphore>,
}
#[derive(Clone)]
struct Key([u8; 32]);
impl Key {
    #[cfg(test)]
    fn read_from_value(value: &str) -> Self {
        Self(Sha256::digest(value.as_bytes()).into())
    }
    fn read(path: &str) -> io::Result<Self> {
        let s = std::fs::read_to_string(path)?;
        let s = s.trim();
        if s.len() < MIN_KEY {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "client key must be at least 32 bytes",
            ));
        }
        Ok(Self(Sha256::digest(s.as_bytes()).into()))
    }
    fn accepts(&self, value: Option<&http::HeaderValue>) -> bool {
        value
            .and_then(|v| v.to_str().ok())
            .and_then(|v| v.strip_prefix("Bearer "))
            .map(|v| {
                Sha256::digest(v.as_bytes())
                    .as_slice()
                    .ct_eq(&self.0)
                    .into()
            })
            .unwrap_or(false)
    }
}

#[derive(Clone)]
enum ClientAuth {
    Required(Key),
    Disabled,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum ClientAuthMode {
    Required,
    Disabled,
}

impl ClientAuthMode {
    fn parse(value: Option<&str>) -> Result<Self, &'static str> {
        match value.unwrap_or("required") {
            "required" => Ok(Self::Required),
            "disabled" => Ok(Self::Disabled),
            _ => Err("CLIENT_AUTH_MODE must be exactly 'required' or 'disabled'"),
        }
    }
}

impl ClientAuth {
    fn load(mode: ClientAuthMode) -> io::Result<Self> {
        match mode {
            ClientAuthMode::Required => Key::read(
                &env::var("CLIENT_AUTH_FILE")
                    .unwrap_or_else(|_| "/run/secrets/client/client-api-key".into()),
            )
            .map(Self::Required),
            ClientAuthMode::Disabled => Ok(Self::Disabled),
        }
    }

    fn accepts(&self, authorization: Option<&http::HeaderValue>) -> bool {
        match self {
            Self::Required(key) => key.accepts(authorization),
            Self::Disabled => true,
        }
    }
}

#[tokio::main]
async fn main() {
    tracing_subscriber::fmt()
        .json()
        .with_env_filter(env::var("RUST_LOG").unwrap_or_else(|_| "info".into()))
        .init();
    let client_auth_mode = ClientAuthMode::parse(env::var("CLIENT_AUTH_MODE").ok().as_deref())
        .unwrap_or_else(|error| panic!("{error}"));
    let client_auth =
        ClientAuth::load(client_auth_mode).expect("client secret unavailable or weak");
    let channel_key =
        std::fs::read_to_string(CHANNEL_SECRET).expect("agent channel secret unavailable");
    if channel_key.trim().len() < MIN_KEY {
        panic!("agent channel secret is weaker than 32 bytes")
    }
    let app = App {
        client: Client::builder()
            .connect_timeout(Duration::from_secs(10))
            .build()
            .unwrap(),
        client_auth,
        channel_key: channel_key.trim().as_bytes().to_vec(),
        max_bytes: env_num("MAX_RESPONSE_BYTES", 64 * 1024 * 1024, 1024 * 1024 * 1024),
        idle: Duration::from_secs(env_num("CHUNK_IDLE_SECS", 30, 300) as u64),
        concurrency: Arc::new(Semaphore::new(env_num("CONCURRENCY", 16, 128))),
    };
    let listener = tokio::net::TcpListener::bind(("0.0.0.0", 8080))
        .await
        .unwrap();
    axum::serve(
        listener,
        Router::new()
            .route("/healthz", get(health))
            .fallback(route)
            .with_state(app),
    )
    .with_graceful_shutdown(shutdown())
    .await
    .unwrap();
}
fn env_num(name: &str, default: usize, max: usize) -> usize {
    env::var(name)
        .ok()
        .and_then(|v| v.parse().ok())
        .unwrap_or(default)
        .clamp(1, max)
}
fn request_body_timeout() -> Duration {
    if cfg!(test) {
        Duration::from_millis(50)
    } else {
        REQUEST_BODY_TIMEOUT
    }
}
async fn shutdown() {
    let _ = tokio::signal::ctrl_c().await;
}

async fn agent(app: &App, op: Operation) -> Result<Vec<(String, String)>, ()> {
    let parent = std::fs::symlink_metadata("/run/praxis-credentials").map_err(|_| ())?;
    let socket = std::fs::symlink_metadata(AGENT_SOCKET).map_err(|_| ())?;
    // SAFETY: geteuid has no preconditions and only reads the process identity.
    let uid = unsafe { libc::geteuid() };
    if !parent.is_dir()
        || (parent.uid() != uid && parent.uid() != 0)
        || parent.mode() & 0o002 != 0
        || socket.file_type().is_symlink()
        || !socket.file_type().is_socket()
        || socket.uid() != uid
        || socket.mode() & 0o007 != 0
    {
        return Err(());
    }
    let stream = timeout(Duration::from_secs(3), UnixStream::connect(AGENT_SOCKET))
        .await
        .map_err(|_| ())?
        .map_err(|_| ())?;
    let (mut read, mut write) = stream.into_split();
    let nonce = hex::encode(rand::random::<[u8; 32]>());
    let mut request = AgentRequest {
        version: VERSION,
        operation: op,
        profile: AGENT_PROFILE.into(),
        audience: AGENT_AUDIENCE.into(),
        nonce,
        mac: String::new(),
    };
    request.mac = request_mac(&app.channel_key, &request);
    let frame = encode(&request).map_err(|_| ())?;
    timeout(Duration::from_secs(3), write.write_all(&frame))
        .await
        .map_err(|_| ())?
        .map_err(|_| ())?;
    let line = timeout(Duration::from_secs(3), read_frame(&mut read))
        .await
        .map_err(|_| ())?
        .map_err(|_| ())?;
    let response: AgentResponse = decode(&line).map_err(|_| ())?;
    if !validate_response(&response, &request.nonce)
        || !response.ok
        || !valid_mac(&response.mac, &response_mac(&app.channel_key, &response))
    {
        return Err(());
    }
    if response.headers.iter().any(|(n, v)| {
        n.len() > 128
            || v.len() > credential_protocol::MAX_VALUE
            || !matches!(n.as_str(), "authorization" | "chatgpt-account-id")
    }) {
        return Err(());
    }
    Ok(response.headers)
}

async fn health(State(app): State<App>) -> (StatusCode, &'static str) {
    if agent(&app, Operation::Ping).await.is_ok() {
        (StatusCode::OK, "ready\n")
    } else {
        (StatusCode::SERVICE_UNAVAILABLE, "not ready\n")
    }
}
async fn route(State(app): State<App>, req: Request<Body>) -> Response<Body> {
    if req.method() != Method::POST
        || req.uri().path() != "/v1/responses"
        || req.uri().query().is_some()
    {
        return simple(StatusCode::NOT_FOUND, "not found\n");
    }
    if !app
        .client_auth
        .accepts(req.headers().get(header::AUTHORIZATION))
    {
        return simple(StatusCode::UNAUTHORIZED, "client authentication required\n");
    }
    let permit = match app.concurrency.clone().try_acquire_owned() {
        Ok(p) => p,
        Err(_) => return simple(StatusCode::TOO_MANY_REQUESTS, "proxy busy\n"),
    };
    let (parts, body) = req.into_parts();
    let body = match timeout(request_body_timeout(), axum::body::to_bytes(body, MAX_BODY)).await {
        Ok(Ok(b)) => b,
        Ok(Err(_)) => return simple(StatusCode::PAYLOAD_TOO_LARGE, "request too large\n"),
        Err(_) => return simple(StatusCode::REQUEST_TIMEOUT, "request body timeout\n"),
    };
    let body = match normalize_codex_request(body) {
        Ok(body) => body,
        Err(error) => return normalization_error_response(error),
    };
    let mut recovered = false;
    loop {
        let credentials = match agent(&app, Operation::Acquire).await {
            Ok(h) => h,
            Err(_) => {
                return simple(
                    StatusCode::SERVICE_UNAVAILABLE,
                    "credential agent unavailable\n",
                );
            }
        };
        let response = match send(&app, &parts, &body, credentials).await {
            Ok(r) => r,
            Err(_) => {
                warn!("upstream request failed");
                return simple(StatusCode::BAD_GATEWAY, "upstream unavailable\n");
            }
        };
        if response.status() == StatusCode::UNAUTHORIZED && !recovered {
            recovered = true;
            if agent(&app, Operation::UnauthorizedRecovery).await.is_ok() {
                continue;
            }
            return simple(
                StatusCode::SERVICE_UNAVAILABLE,
                "credential recovery unavailable\n",
            );
        }
        return forward(response, permit, app.max_bytes, app.idle);
    }
}

/// Apply compatibility rules for the fixed Codex Responses profile.
///
/// The Codex backend does not accept OpenAI's `max_output_tokens` request
/// field.  Parse only after the existing body limit has been enforced, and
/// rewrite just the top-level object so nested tool/input data is untouched.
#[derive(Debug)]
enum CodexNormalizationError {
    InvalidJson,
    NonObject,
    Serialization,
}

fn normalize_codex_request(body: bytes::Bytes) -> Result<bytes::Bytes, CodexNormalizationError> {
    let mut value: serde_json::Value =
        serde_json::from_slice(&body).map_err(|_| CodexNormalizationError::InvalidJson)?;
    let object = value
        .as_object_mut()
        .ok_or(CodexNormalizationError::NonObject)?;
    object.remove("max_output_tokens");
    serde_json::to_vec(&value)
        .map(bytes::Bytes::from)
        .map_err(|_| CodexNormalizationError::Serialization)
}

fn normalization_error_response(error: CodexNormalizationError) -> Response<Body> {
    let message = match error {
        CodexNormalizationError::InvalidJson => "request body must be valid JSON\n",
        CodexNormalizationError::NonObject => "request body must be a JSON object\n",
        CodexNormalizationError::Serialization => "request body cannot be normalized\n",
    };
    simple(StatusCode::BAD_REQUEST, message)
}

async fn send(
    app: &App,
    parts: &http::request::Parts,
    body: &bytes::Bytes,
    credentials: Vec<(String, String)>,
) -> Result<reqwest::Response, ()> {
    let url = if cfg!(feature = "synthetic-test") {
        "http://127.0.0.1:18081/backend-api/codex/responses"
    } else {
        UPSTREAM
    };
    let connection = parts
        .headers
        .get_all(header::CONNECTION)
        .iter()
        .filter_map(|v| v.to_str().ok())
        .flat_map(|v| v.split(','))
        .filter_map(|v| HeaderName::from_bytes(v.trim().as_bytes()).ok())
        .collect::<HashSet<_>>();
    let mut request = app.client.post(url).body(body.clone());
    for (name, value) in &parts.headers {
        if !connection.contains(name)
            && matches!(
                name.as_str(),
                "content-type" | "accept" | "accept-encoding" | "user-agent"
            )
        {
            request = request.header(name, value)
        }
    }
    for (name, value) in credentials {
        request = request.header(name, value)
    }
    timeout(RESPONSE_HEADER_TIMEOUT, request.send())
        .await
        .map_err(|_| ())
        .and_then(|r| r.map_err(|_| ()))
}
fn forward(
    response: reqwest::Response,
    permit: tokio::sync::OwnedSemaphorePermit,
    max: usize,
    idle: Duration,
) -> Response<Body> {
    let status = response.status();
    let mut b = Response::builder().status(status);
    for (n, v) in response.headers() {
        if !hop(n) && n != header::SET_COOKIE {
            b = b.header(n, v)
        }
    }
    let mut stream = response.bytes_stream();
    let body = async_stream::stream! { let mut total=0; let _permit=permit; loop { match timeout(idle, stream.next()).await { Ok(Some(Ok(chunk))) => { total += chunk.len(); if total > max { yield Err(io::Error::other("response limit exceeded")); break } yield Ok(chunk) }, Ok(Some(Err(_))) => { yield Err(io::Error::other("upstream stream failed")); break }, Ok(None) => break, Err(_) => { yield Err(io::Error::other("upstream idle timeout")); break } } } };
    b.body(Body::from_stream(body))
        .unwrap_or_else(|_| simple(StatusCode::BAD_GATEWAY, "response error\n"))
}
fn hop(n: &HeaderName) -> bool {
    matches!(
        n.as_str(),
        "connection"
            | "keep-alive"
            | "proxy-authenticate"
            | "proxy-authorization"
            | "te"
            | "trailer"
            | "transfer-encoding"
            | "upgrade"
            | "host"
            | "cookie"
            | "authorization"
            | "chatgpt-account-id"
    )
}
fn simple(status: StatusCode, text: &'static str) -> Response<Body> {
    Response::builder()
        .status(status)
        .header(header::CONTENT_TYPE, "text/plain")
        .body(Body::from(text))
        .unwrap()
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn client_key_requires_bearer_and_is_constant_time_compared() {
        let value = "abcdefghijklmnopqrstuvwxyz012345";
        let key = Key::read_from_value(value);
        assert!(!key.accepts(Some(&"Bearer abc".parse().unwrap())));
        let header = format!("Bearer {value}").parse().unwrap();
        assert!(key.accepts(Some(&header)));
    }

    #[test]
    fn client_auth_mode_defaults_to_required_and_rejects_unknown_modes() {
        assert_eq!(ClientAuthMode::parse(None), Ok(ClientAuthMode::Required));
        assert_eq!(
            ClientAuthMode::parse(Some("disabled")),
            Ok(ClientAuthMode::Disabled)
        );
        assert!(matches!(
            ClientAuthMode::parse(Some("")),
            Err("CLIENT_AUTH_MODE must be exactly 'required' or 'disabled'")
        ));
        assert!(matches!(
            ClientAuthMode::parse(Some("optional")),
            Err("CLIENT_AUTH_MODE must be exactly 'required' or 'disabled'")
        ));
    }

    #[test]
    fn required_and_disabled_client_auth_have_explicit_behavior() {
        let key = Key::read_from_value("abcdefghijklmnopqrstuvwxyz012345");
        let required = ClientAuth::Required(key);
        let correct = "Bearer abcdefghijklmnopqrstuvwxyz012345".parse().unwrap();
        assert!(!required.accepts(None));
        assert!(!required.accepts(Some(&"Bearer wrong".parse().unwrap())));
        assert!(required.accepts(Some(&correct)));
        assert!(ClientAuth::Disabled.accepts(None));
        assert!(ClientAuth::Disabled.accepts(Some(&correct)));
    }
    #[test]
    fn sensitive_and_hop_headers_are_not_forwarded() {
        for name in [
            "authorization",
            "cookie",
            "connection",
            "proxy-authorization",
            "host",
            "chatgpt-account-id",
        ] {
            assert!(hop(&HeaderName::from_bytes(name.as_bytes()).unwrap()));
        }
        assert!(!hop(&HeaderName::from_static("content-type")));
    }
    #[test]
    fn upstream_path_is_not_client_selectable() {
        assert!(UPSTREAM.ends_with("/responses"));
        assert!(!UPSTREAM.contains("{"));
    }

    #[test]
    fn codex_normalization_removes_only_top_level_max_output_tokens() {
        let body = br#"{"model":"gpt-6-astra","max_output_tokens":42,"input":{"max_output_tokens":7},"tools":[{"max_output_tokens":9}]}"#;
        let normalized = normalize_codex_request(bytes::Bytes::from_static(body)).unwrap();
        let value: serde_json::Value = serde_json::from_slice(&normalized).unwrap();

        assert_eq!(value["model"], "gpt-6-astra");
        assert!(value.get("max_output_tokens").is_none());
        assert_eq!(value["input"]["max_output_tokens"], 7);
        assert_eq!(value["tools"][0]["max_output_tokens"], 9);
    }

    #[test]
    fn codex_normalization_rejects_malformed_json() {
        assert!(matches!(
            normalize_codex_request(bytes::Bytes::from_static(b"{not-json")),
            Err(CodexNormalizationError::InvalidJson)
        ));
    }

    #[test]
    fn codex_normalization_rejects_non_object_json() {
        assert!(matches!(
            normalize_codex_request(bytes::Bytes::from_static(b"[]")),
            Err(CodexNormalizationError::NonObject)
        ));
    }

    #[tokio::test]
    async fn slow_request_body_times_out_and_releases_permit() {
        let app = App {
            client: Client::new(),
            client_auth: ClientAuth::Required(Key::read_from_value(
                "abcdefghijklmnopqrstuvwxyz012345",
            )),
            channel_key: vec![b'c'; MIN_KEY],
            max_bytes: MAX_BODY,
            idle: Duration::from_secs(1),
            concurrency: Arc::new(Semaphore::new(1)),
        };
        let delayed = || {
            let stream = async_stream::stream! {
                tokio::time::sleep(Duration::from_millis(200)).await;
                yield Ok::<_, io::Error>(bytes::Bytes::from_static(b"{}"));
            };
            Request::builder()
                .method(Method::POST)
                .uri("/v1/responses")
                .header(
                    header::AUTHORIZATION,
                    "Bearer abcdefghijklmnopqrstuvwxyz012345",
                )
                .body(Body::from_stream(stream))
                .unwrap()
        };
        let response = route(State(app.clone()), delayed()).await;
        assert_eq!(response.status(), StatusCode::REQUEST_TIMEOUT);
        assert_eq!(app.concurrency.available_permits(), 1);
        let response = route(State(app.clone()), delayed()).await;
        assert_eq!(response.status(), StatusCode::REQUEST_TIMEOUT);
        assert_eq!(app.concurrency.available_permits(), 1);
    }
}
