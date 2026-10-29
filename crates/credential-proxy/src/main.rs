//! Generic credential egress proxy. It has no provider SDK or writable auth volume.
use axum::{
    Router,
    body::Body,
    extract::State,
    http::{HeaderMap, HeaderName, HeaderValue, Method, Request, StatusCode, header},
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
use tracing::{info, warn};

const UPSTREAM: &str = "https://chatgpt.com/backend-api/codex/responses";
const MAX_BODY: usize = 10 * 1024 * 1024;
const MIN_KEY: usize = 32;
const AGENT_PROFILE: &str = "codex";
const AGENT_AUDIENCE: &str = "codex";
const AGENT_SOCKET: &str = "/run/praxis-credentials/agent.sock";
const CHANNEL_SECRET: &str = "/run/secrets/channel/agent-channel-key";
const RESPONSE_HEADER_TIMEOUT: Duration = Duration::from_secs(10);
const REQUEST_BODY_TIMEOUT: Duration = Duration::from_secs(10);
/// What a successful Codex response is when it does not say: the backend
/// streams its events with no `content-type` at all, and Praxis's
/// `token_count` reads the usage only of a response that names its type.
const UNNAMED_RESPONSE_TYPE: &str = "text/event-stream";
/// The headers Codex clients route the prompt cache by. Without them the
/// backend keeps only the start of the prompt that every session shares warm.
const SESSION_ID: HeaderName = HeaderName::from_static("session_id");
const CLIENT_REQUEST_ID: HeaderName = HeaderName::from_static("x-client-request-id");
/// The longest `model` or `prompt_cache_key` the proxy logs or copies into a
/// header; Codex's cache key is a 36-character UUID.
const MAX_TOKEN: usize = 64;
/// The most of one event (or of a response that is not an event stream) held
/// to read its usage from; a larger one is forwarded but logged without usage.
const MAX_USAGE_EVENT: usize = 1024 * 1024;
/// The only headers the credential agent may inject. No client header that
/// [`canonical`]ly names one goes upstream, nor comes back from it.
const INJECTED: [&str; 2] = ["authorization", "chatgpt-account-id"];

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
    // Only Praxis, in the same pod network namespace, connects. Loopback keeps
    // the proxy, which adds the Codex credential, unreachable from anything
    // else even if the pod's network is shared or a port is published.
    let listener = tokio::net::TcpListener::bind(("127.0.0.1", 8080))
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
        n.len() > 128 || v.len() > credential_protocol::MAX_VALUE || !INJECTED.contains(&n.as_str())
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
    let (mut parts, body) = req.into_parts();
    let body = match timeout(request_body_timeout(), axum::body::to_bytes(body, MAX_BODY)).await {
        Ok(Ok(b)) => b,
        Ok(Err(_)) => return simple(StatusCode::PAYLOAD_TOO_LARGE, "request too large\n"),
        Err(_) => return simple(StatusCode::REQUEST_TIMEOUT, "request body timeout\n"),
    };
    let codex = match normalize_codex_request(body) {
        Ok(codex) => codex,
        Err(error) => return normalization_error_response(error),
    };
    let trace = Trace::new(parts.uri.path(), &parts.headers, &codex);
    backstop_cache_routing(&mut parts.headers, &codex);
    let body = codex.body;
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
            drop(UsageTap::new(trace.clone(), response.status(), false));
            if agent(&app, Operation::UnauthorizedRecovery).await.is_ok() {
                continue;
            }
            return simple(
                StatusCode::SERVICE_UNAVAILABLE,
                "credential recovery unavailable\n",
            );
        }
        return forward(response, permit, app.max_bytes, app.idle, trace);
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

/// A normalized Codex request, with the top-level fields the proxy routes and
/// logs by when each is a short token (see [`token`]).
struct CodexRequest {
    body: bytes::Bytes,
    model: Option<String>,
    prompt_cache_key: Option<String>,
}

fn normalize_codex_request(body: bytes::Bytes) -> Result<CodexRequest, CodexNormalizationError> {
    let mut value: serde_json::Value =
        serde_json::from_slice(&body).map_err(|_| CodexNormalizationError::InvalidJson)?;
    let object = value
        .as_object_mut()
        .ok_or(CodexNormalizationError::NonObject)?;
    object.remove("max_output_tokens");
    let model = token(object.get("model"));
    let prompt_cache_key = token(object.get("prompt_cache_key"));
    let body = serde_json::to_vec(&value)
        .map(bytes::Bytes::from)
        .map_err(|_| CodexNormalizationError::Serialization)?;
    Ok(CodexRequest {
        body,
        model,
        prompt_cache_key,
    })
}

/// A string of 1 to [`MAX_TOKEN`] ASCII letters, digits, `-`, `_`, `.` or
/// `:`, so that it is always a valid header value and cannot spread a log line.
fn token(value: Option<&serde_json::Value>) -> Option<String> {
    let value = value?.as_str()?;
    let valid = (1..=MAX_TOKEN).contains(&value.len())
        && value
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'-' | b'_' | b'.' | b':'));
    valid.then(|| value.to_owned())
}

/// Route the prompt cache for a client that names the session only in the
/// body: with neither routing header, both are set from `prompt_cache_key`.
fn backstop_cache_routing(headers: &mut HeaderMap, codex: &CodexRequest) {
    if headers.contains_key(SESSION_ID) || headers.contains_key(CLIENT_REQUEST_ID) {
        return;
    }
    let Some(value) = codex
        .prompt_cache_key
        .as_deref()
        .and_then(|key| HeaderValue::from_str(key).ok())
    else {
        return;
    };
    headers.insert(SESSION_ID, value.clone());
    headers.insert(CLIENT_REQUEST_ID, value);
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
    let headers = upstream_headers(&parts.headers, credentials)?;
    let request = app.client.post(url).headers(headers).body(body.clone());
    timeout(RESPONSE_HEADER_TIMEOUT, request.send())
        .await
        .map_err(|_| ())
        .and_then(|r| r.map_err(|_| ()))
}

/// The client's headers that go upstream, with the injected credentials in
/// place of any the client sent under the same names.
fn upstream_headers(
    client: &HeaderMap,
    credentials: Vec<(String, String)>,
) -> Result<HeaderMap, ()> {
    let connection = client
        .get_all(header::CONNECTION)
        .iter()
        .filter_map(|v| v.to_str().ok())
        .flat_map(|v| v.split(','))
        .map(|v| canonical(v.trim()))
        .collect::<HashSet<_>>();
    let mut headers: HeaderMap = client
        .iter()
        .filter(|(n, _)| !connection.contains(&canonical(n.as_str())) && !denied(n))
        .map(|(n, v)| (n.clone(), v.clone()))
        .collect();
    for (name, value) in credentials {
        let name = HeaderName::from_bytes(name.as_bytes()).map_err(|_| ())?;
        let value = HeaderValue::from_str(&value).map_err(|_| ())?;
        headers.insert(name, value);
    }
    Ok(headers)
}

/// A client request header that never goes upstream: besides [`hop`], the
/// proxy headers, the ones that would select another account for the
/// broker's credential, the ones that describe the client's connection
/// rather than the request, and `accept-encoding`. The proxy cannot
/// decompress, so a compressed response would hide its usage from
/// [`UsageTap`]; without it the backend answers uncompressed.
///
/// Names are compared [`canonical`]ly, since many backends read `_` as `-`.
fn denied(n: &HeaderName) -> bool {
    let n = canonical(n.as_str());
    hop_canonical(&n)
        || n.starts_with("proxy-")
        || n.starts_with("x-forwarded-")
        || matches!(
            n.as_str(),
            "content-length"
                | "forwarded"
                | "x-real-ip"
                | "openai-organization"
                | "openai-project"
                | "accept-encoding"
        )
}

/// A header name as backends that treat `_` and `-` alike read it.
fn canonical(name: &str) -> String {
    name.to_ascii_lowercase().replace('_', "-")
}

fn forward(
    response: reqwest::Response,
    permit: tokio::sync::OwnedSemaphorePermit,
    max: usize,
    idle: Duration,
    trace: Trace,
) -> Response<Body> {
    let status = response.status();
    let headers = response_headers(status, response.headers());
    let events = headers
        .get(header::CONTENT_TYPE)
        .and_then(|v| v.to_str().ok())
        .is_some_and(|v| v.starts_with(UNNAMED_RESPONSE_TYPE));
    let mut b = Response::builder().status(status);
    for (n, v) in &headers {
        b = b.header(n, v)
    }
    let mut tap = UsageTap::new(trace, status, events);
    let mut stream = response.bytes_stream();
    let body = async_stream::stream! { let mut total=0; let _permit=permit; loop { match timeout(idle, stream.next()).await { Ok(Some(Ok(chunk))) => { total += chunk.len(); if total > max { yield Err(io::Error::other("response limit exceeded")); break } tap.feed(&chunk); yield Ok(chunk) }, Ok(Some(Err(_))) => { yield Err(io::Error::other("upstream stream failed")); break }, Ok(None) => break, Err(_) => { yield Err(io::Error::other("upstream idle timeout")); break } } } };
    b.body(Body::from_stream(body))
        .unwrap_or_else(|_| simple(StatusCode::BAD_GATEWAY, "response error\n"))
}
/// The headers of an upstream response that go back to the client.
fn response_headers(status: StatusCode, upstream: &http::HeaderMap) -> http::HeaderMap {
    let mut headers: http::HeaderMap = upstream
        .iter()
        .filter(|(n, _)| !hop(n) && *n != header::SET_COOKIE)
        .map(|(n, v)| (n.clone(), v.clone()))
        .collect();
    if status.is_success() && !headers.contains_key(header::CONTENT_TYPE) {
        headers.insert(
            header::CONTENT_TYPE,
            http::HeaderValue::from_static(UNNAMED_RESPONSE_TYPE),
        );
    }
    headers
}
/// A hop-by-hop header, or one that carries a credential, in either direction.
fn hop(n: &HeaderName) -> bool {
    hop_canonical(&canonical(n.as_str()))
}
fn hop_canonical(n: &str) -> bool {
    INJECTED.contains(&n)
        || matches!(
            n,
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
        )
}
fn simple(status: StatusCode, text: &'static str) -> Response<Body> {
    Response::builder()
        .status(status)
        .header(header::CONTENT_TYPE, "text/plain")
        .body(Body::from(text))
        .unwrap()
}

/// What an upstream request is logged with. Of what the client sent it keeps
/// only whether the cache-routing headers were there and a hash of the cache
/// key, never a value, so the log holds no IDs, prompt or credential.
#[derive(Clone, Debug)]
struct Trace {
    route: String,
    model: Option<String>,
    session_id: bool,
    client_request_id: bool,
    cache_key: Option<String>,
}

impl Trace {
    fn new(route: &str, headers: &HeaderMap, codex: &CodexRequest) -> Self {
        Self {
            route: route.to_owned(),
            model: codex.model.clone(),
            session_id: headers.contains_key(SESSION_ID),
            client_request_id: headers.contains_key(CLIENT_REQUEST_ID),
            cache_key: codex
                .prompt_cache_key
                .as_ref()
                .map(|key| hex::encode(&Sha256::digest(key.as_bytes())[..6])),
        }
    }
}

/// The token counts a response reports. `input` includes `cached`, as
/// OpenAI counts it.
#[derive(Debug, Default, PartialEq)]
struct Tokens {
    input: u64,
    cached: u64,
    cache_write: u64,
    output: u64,
}

impl Tokens {
    /// The usage of a response or one of its events: OpenAI's under
    /// `response` in a stream, Anthropic's under `message` when it starts.
    fn of(event: &serde_json::Value) -> Option<Self> {
        let usage = ["/response/usage", "/message/usage", "/usage"]
            .iter()
            .find_map(|p| event.pointer(p).filter(|u| u.is_object()))?;
        let count = |p: &str| usage.pointer(p).and_then(|v| v.as_u64()).unwrap_or(0);
        Some(Self {
            input: count("/input_tokens"),
            cached: count("/input_tokens_details/cached_tokens")
                .saturating_add(count("/cache_read_input_tokens")),
            cache_write: count("/cache_creation_input_tokens"),
            output: count("/output_tokens"),
        })
    }

    /// Anthropic reports usage in more than one event, each count growing.
    fn merge(&mut self, other: Self) {
        self.input = self.input.max(other.input);
        self.cached = self.cached.max(other.cached);
        self.cache_write = self.cache_write.max(other.cache_write);
        self.output = self.output.max(other.output);
    }
}

/// Reads the usage out of a response as it is forwarded, and logs one line
/// for it when dropped, however the response ended.
struct UsageTap {
    trace: Trace,
    status: StatusCode,
    /// Whether the response is an event stream, read an event (line) at a
    /// time, rather than one document.
    events: bool,
    pending: Vec<u8>,
    /// Whether the event or document being read was too large to hold.
    skipping: bool,
    usage: Option<Tokens>,
}

impl UsageTap {
    fn new(trace: Trace, status: StatusCode, events: bool) -> Self {
        Self {
            trace,
            status,
            events,
            pending: Vec::new(),
            skipping: false,
            usage: None,
        }
    }

    fn feed(&mut self, chunk: &[u8]) {
        let lines: Box<dyn Iterator<Item = &[u8]>> = if self.events {
            Box::new(chunk.split_inclusive(|b| *b == b'\n'))
        } else {
            Box::new(std::iter::once(chunk))
        };
        for line in lines {
            if self.pending.len() + line.len() > MAX_USAGE_EVENT {
                self.skipping = true;
                self.pending = Vec::new();
            } else if !self.skipping {
                self.pending.extend_from_slice(line);
            }
            if self.events && line.ends_with(b"\n") {
                self.scan();
            }
        }
    }

    /// Take the usage, if any, from the event or document read so far.
    fn scan(&mut self) {
        let pending = std::mem::take(&mut self.pending);
        if std::mem::take(&mut self.skipping)
            || !pending.windows(b"usage".len()).any(|w| w == b"usage")
        {
            return;
        }
        let text = pending.trim_ascii();
        let data = text.strip_prefix(b"data:").unwrap_or(text);
        let Some(tokens) = serde_json::from_slice(data)
            .ok()
            .as_ref()
            .and_then(Tokens::of)
        else {
            return;
        };
        match &mut self.usage {
            Some(usage) => usage.merge(tokens),
            None => self.usage = Some(tokens),
        }
    }
}

impl Drop for UsageTap {
    fn drop(&mut self) {
        self.scan();
        let t = &self.trace;
        let model = t.model.as_deref().unwrap_or("-");
        let cache_key = t.cache_key.as_deref().unwrap_or("-");
        match &self.usage {
            Some(usage) => info!(
                route = t.route.as_str(),
                status = self.status.as_u16(),
                model,
                input = usage.input,
                cached = usage.cached,
                cache_write = usage.cache_write,
                output = usage.output,
                session_id = t.session_id,
                client_request_id = t.client_request_id,
                cache_key,
                "upstream usage"
            ),
            None => info!(
                route = t.route.as_str(),
                status = self.status.as_u16(),
                model,
                session_id = t.session_id,
                client_request_id = t.client_request_id,
                cache_key,
                "upstream request without usage"
            ),
        }
    }
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

    fn headers(pairs: &[(&'static str, &'static str)]) -> HeaderMap {
        pairs
            .iter()
            .map(|(n, v)| (HeaderName::from_static(n), HeaderValue::from_static(v)))
            .collect()
    }

    const CODEX_KEY: &str = "0f8a3c52-7d14-4b6e-9a21-c5e3d8f07b49";

    fn codex(body: &'static str) -> CodexRequest {
        normalize_codex_request(bytes::Bytes::from_static(body.as_bytes())).unwrap()
    }

    #[test]
    fn sensitive_hop_and_connection_headers_are_not_forwarded() {
        let client = headers(&[
            ("authorization", "Bearer client-secret-value"),
            ("cookie", "session=client-cookie-value"),
            ("chatgpt-account-id", "client-account"),
            ("openai-organization", "client-org"),
            ("connection", "keep-alive, x-hop-named"),
            ("x-hop-named", "1"),
            ("keep-alive", "timeout=5"),
            ("te", "trailers"),
            ("proxy-authorization", "Basic client"),
            ("proxy-connection", "keep-alive"),
            ("host", "client.example"),
            ("content-length", "2"),
            ("forwarded", "for=192.0.2.1"),
            ("x-forwarded-for", "192.0.2.1"),
            ("x-real-ip", "192.0.2.1"),
            ("content-type", "application/json"),
            ("accept", "text/event-stream"),
            ("originator", "codex_exec"),
            ("session_id", CODEX_KEY),
            ("x-client-request-id", CODEX_KEY),
        ]);
        let upstream = upstream_headers(&client, Vec::new()).unwrap();
        let mut names: Vec<_> = upstream.keys().map(HeaderName::as_str).collect();
        names.sort();
        assert_eq!(
            names,
            [
                "accept",
                "content-type",
                "originator",
                "session_id",
                "x-client-request-id"
            ]
        );
        assert_eq!(upstream[SESSION_ID], CODEX_KEY);
        assert_eq!(upstream[CLIENT_REQUEST_ID], CODEX_KEY);
    }

    #[test]
    fn denied_headers_are_not_forwarded_in_any_spelling() {
        for name in [
            "chatgpt_account_id",
            "Chatgpt_Account_ID",
            "openai-project",
            "openai_project",
            "openai_organization",
            "x-forwarded-host",
            "x_forwarded_host",
            "proxy_authorization",
            "transfer_encoding",
            "accept-encoding",
            "accept_encoding",
        ] {
            let name = HeaderName::from_bytes(name.as_bytes()).unwrap();
            let client = HeaderMap::from_iter([(name.clone(), HeaderValue::from_static("x"))]);
            let upstream = upstream_headers(&client, Vec::new()).unwrap();
            assert!(upstream.is_empty(), "{name}");
        }
        // Each name the agent may inject is denied, so the client's spelling
        // cannot ride alongside the injected one.
        for name in INJECTED {
            let client_spelling = name.replace('-', "_").to_ascii_uppercase();
            let client = HeaderMap::from_iter([(
                HeaderName::from_bytes(client_spelling.as_bytes()).unwrap(),
                HeaderValue::from_static("client"),
            )]);
            let upstream = upstream_headers(&client, vec![(name.into(), "injected".into())]);
            let values: Vec<_> = upstream.unwrap().into_iter().map(|(_, v)| v).collect();
            assert_eq!(values, ["injected"], "{name}");
        }
        // `Connection` names its headers in any spelling too.
        let client = headers(&[("connection", "X_Hop"), ("x-hop", "1")]);
        assert!(upstream_headers(&client, Vec::new()).unwrap().is_empty());
    }

    #[test]
    fn injected_credentials_replace_client_headers_of_the_same_name() {
        let client = headers(&[("authorization", "Bearer client-secret-value")]);
        // Even a header the denylist would keep is replaced, not added to.
        let client_kept = headers(&[("x-injected", "client"), ("x-injected", "client-2")]);
        for (client, name) in [(client, "authorization"), (client_kept, "x-injected")] {
            let upstream =
                upstream_headers(&client, vec![(name.into(), "injected".into())]).unwrap();
            let values: Vec<_> = upstream.get_all(name).iter().collect();
            assert_eq!(values, ["injected"], "{name}");
        }
        let invalid = vec![("bad name".into(), "v".into())];
        assert!(upstream_headers(&HeaderMap::new(), invalid).is_err());
    }

    #[test]
    fn cache_routing_headers_are_set_from_the_cache_key_only_when_both_are_absent() {
        let request = codex(
            r#"{"model":"gpt-6.1-sol","prompt_cache_key":"0f8a3c52-7d14-4b6e-9a21-c5e3d8f07b49"}"#,
        );
        let mut neither = headers(&[("content-type", "application/json")]);
        backstop_cache_routing(&mut neither, &request);
        assert_eq!(neither[SESSION_ID], CODEX_KEY);
        assert_eq!(neither[CLIENT_REQUEST_ID], CODEX_KEY);

        let mut one = headers(&[("session_id", "client-session")]);
        backstop_cache_routing(&mut one, &request);
        assert_eq!(one[SESSION_ID], "client-session");
        assert!(!one.contains_key(CLIENT_REQUEST_ID));

        for body in [
            r#"{"prompt_cache_key":""}"#,
            r#"{"prompt_cache_key":"has space"}"#,
            r#"{"prompt_cache_key":"line\nbreak"}"#,
            r#"{"prompt_cache_key":"ключ"}"#,
            r#"{"prompt_cache_key":42}"#,
            r#"{"input":{"prompt_cache_key":"nested"}}"#,
        ] {
            let mut none = HeaderMap::new();
            backstop_cache_routing(&mut none, &codex(body));
            assert!(none.is_empty(), "{body}");
        }
        let long = format!(r#"{{"prompt_cache_key":"{}"}}"#, "k".repeat(MAX_TOKEN + 1));
        let long = normalize_codex_request(long.into()).unwrap();
        assert_eq!(long.prompt_cache_key, None);
    }

    #[test]
    fn usage_is_read_from_openai_and_anthropic_responses() {
        let tokens = |[input, cached, cache_write, output]: [u64; 4]| {
            Some(Tokens {
                input,
                cached,
                cache_write,
                output,
            })
        };
        let cases: [(&str, bool, &[&str], Option<Tokens>); 4] = [
            (
                "openai stream",
                true,
                &[
                    "event: response.created\n\
                     data: {\"type\":\"response.created\",\"response\":{\"usage\":null}}\n\n",
                    "event: response.completed\n\
                     data: {\"type\":\"response.completed\",\"response\":{\"usage\":{",
                    "\"input_tokens\":70,\"input_tokens_details\":{\"cached_tokens\":30},\
                     \"output_tokens\":30}}}\n\n",
                ],
                tokens([70, 30, 0, 30]),
            ),
            (
                "anthropic stream",
                true,
                &[
                    "data: {\"type\":\"message_start\",\"message\":{\"usage\":{\
                     \"input_tokens\":40,\"cache_read_input_tokens\":20,\
                     \"cache_creation_input_tokens\":5,\"output_tokens\":1}}}\n",
                    "data: {\"type\":\"message_delta\",\"usage\":{\"output_tokens\":30}}",
                ],
                tokens([40, 20, 5, 30]),
            ),
            (
                "json",
                false,
                &["{\"usage\":\n{\"input_tokens\":3,", "\"output_tokens\":4}}"],
                tokens([3, 0, 0, 4]),
            ),
            ("error", false, &["{\"detail\":\"Unauthorized\"}"], None),
        ];
        for (name, events, chunks, expected) in cases {
            let mut tap = UsageTap::new(trace(), StatusCode::OK, events);
            for chunk in chunks {
                tap.feed(chunk.as_bytes());
            }
            tap.scan();
            assert_eq!(tap.usage, expected, "{name}");
        }

        // An event too large to hold is skipped, and the next one read.
        let mut tap = UsageTap::new(trace(), StatusCode::OK, true);
        tap.feed(&vec![b'x'; MAX_USAGE_EVENT + 1]);
        tap.feed(b"\"usage\":{\"input_tokens\":1}}\ndata: {\"usage\":{\"input_tokens\":2}}\n");
        assert_eq!(tap.usage, tokens([2, 0, 0, 0]));
    }

    fn trace() -> Trace {
        let request = codex(
            r#"{"model":"gpt-6.1-sol","input":"prompt-content-value",
                "prompt_cache_key":"0f8a3c52-7d14-4b6e-9a21-c5e3d8f07b49"}"#,
        );
        let client = headers(&[("x-client-request-id", "client-request-value")]);
        Trace::new("/v1/responses", &client, &request)
    }

    #[derive(Clone, Default)]
    struct Captured(Arc<std::sync::Mutex<Vec<u8>>>);

    impl io::Write for Captured {
        fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
            self.0.lock().unwrap().extend_from_slice(buf);
            Ok(buf.len())
        }

        fn flush(&mut self) -> io::Result<()> {
            Ok(())
        }
    }

    #[test]
    fn each_upstream_request_logs_its_cache_use_and_no_values() {
        let captured = Captured::default();
        let writer = captured.clone();
        let subscriber = tracing_subscriber::fmt()
            .json()
            .with_writer(move || writer.clone())
            .finish();
        tracing::subscriber::with_default(subscriber, || {
            let mut tap = UsageTap::new(trace(), StatusCode::OK, true);
            tap.feed(
                b"data: {\"response\":{\"usage\":{\"input_tokens\":70,\
                  \"input_tokens_details\":{\"cached_tokens\":30},\"output_tokens\":30}}}\n",
            );
            drop(tap);
            drop(UsageTap::new(trace(), StatusCode::UNAUTHORIZED, false));
        });
        let logged = String::from_utf8(captured.0.lock().unwrap().clone()).unwrap();
        let lines: Vec<serde_json::Value> = logged
            .lines()
            .map(|l| serde_json::from_str(l).unwrap())
            .collect();
        let hash = hex::encode(&Sha256::digest(CODEX_KEY.as_bytes())[..6]);
        assert_eq!(
            lines[0]["fields"],
            serde_json::json!({
                "message": "upstream usage",
                "route": "/v1/responses",
                "status": 200,
                "model": "gpt-6.1-sol",
                "input": 70,
                "cached": 30,
                "cache_write": 0,
                "output": 30,
                "session_id": false,
                "client_request_id": true,
                "cache_key": hash,
            })
        );
        assert_eq!(
            lines[1]["fields"]["message"],
            "upstream request without usage"
        );
        assert_eq!(lines[1]["fields"]["status"], 401);
        assert_eq!(lines.len(), 2);
        for secret in [CODEX_KEY, "client-request-value", "prompt-content-value"] {
            assert!(!logged.contains(secret), "{secret}");
        }
    }
    #[test]
    fn a_successful_response_that_names_no_type_is_an_event_stream() {
        // As chatgpt.com answered a streamed request on 2026-10-05: the
        // subscription windows and no content-type.
        let recorded = http::HeaderMap::from_iter([
            (
                HeaderName::from_static("x-codex-primary-used-percent"),
                http::HeaderValue::from_static("19"),
            ),
            (header::SET_COOKIE, http::HeaderValue::from_static("a=b")),
            (
                header::TRANSFER_ENCODING,
                http::HeaderValue::from_static("chunked"),
            ),
        ]);
        let json = http::HeaderMap::from_iter([(
            header::CONTENT_TYPE,
            http::HeaderValue::from_static("application/json"),
        )]);
        let cases = [
            (StatusCode::OK, &recorded, Some(UNNAMED_RESPONSE_TYPE)),
            (StatusCode::OK, &json, Some("application/json")),
            (StatusCode::TOO_MANY_REQUESTS, &recorded, None),
        ];
        for (status, upstream, expected) in cases {
            let headers = response_headers(status, upstream);
            assert_eq!(
                headers
                    .get(header::CONTENT_TYPE)
                    .map(|v| v.to_str().unwrap()),
                expected,
                "{status}"
            );
            assert!(!headers.contains_key(header::SET_COOKIE));
            assert!(!headers.contains_key(header::TRANSFER_ENCODING));
        }
        assert_eq!(
            response_headers(StatusCode::OK, &recorded)["x-codex-primary-used-percent"],
            "19"
        );
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
        let value: serde_json::Value = serde_json::from_slice(&normalized.body).unwrap();

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
