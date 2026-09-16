//! The only image allowed to mount CODEX_HOME. No credential value is logged.
#[cfg(not(feature = "synthetic-test"))]
use codex_http_client::{HttpClientFactory, OutboundProxyPolicy};
#[cfg(not(feature = "synthetic-test"))]
use codex_login::{
    AuthCredentialsStoreMode, AuthKeyringBackendKind, AuthManager, AuthRouteConfig, CodexAuth,
    ServerOptions, run_device_code_login,
};
use credential_protocol::{
    Operation, Request, Response, VERSION, decode, encode, read_frame, request_mac, response_mac,
    valid_mac, validate_request,
};
#[cfg(not(feature = "synthetic-test"))]
use fs2::FileExt;
#[cfg(not(feature = "synthetic-test"))]
use std::fs::File;
#[cfg(not(feature = "synthetic-test"))]
use std::io::Write;
#[cfg(feature = "synthetic-test")]
use std::sync::{
    Arc,
    atomic::{AtomicUsize, Ordering},
};
#[cfg(not(feature = "synthetic-test"))]
use std::{
    env,
    fs::OpenOptions,
    os::unix::fs::OpenOptionsExt,
    path::PathBuf,
    time::{SystemTime, UNIX_EPOCH},
};
use std::{
    fs, io,
    os::unix::fs::{FileTypeExt, MetadataExt, PermissionsExt},
    path::Path,
    time::Duration,
};
#[cfg(feature = "synthetic-test")]
use tokio::{io::AsyncReadExt, net::TcpListener};
use tokio::{
    io::AsyncWriteExt,
    net::{UnixListener, UnixStream},
    time::timeout,
};

const PROFILE: &str = "codex";
const AUDIENCE: &str = "codex";
const SOCKET: &str = "/run/praxis-credentials/agent.sock";
const CHANNEL_SECRET: &str = "/run/secrets/channel/agent-channel-key";
#[cfg(not(feature = "synthetic-test"))]
const HOME: &str = "/codex-home";
const FRAME_TIMEOUT: Duration = Duration::from_secs(3);
#[cfg(feature = "synthetic-test")]
const SYNTHETIC_COUNTERS: &str = "0.0.0.0:19090";

#[tokio::main]
async fn main() {
    #[cfg(not(feature = "synthetic-test"))]
    if env::args().nth(1).as_deref() == Some("login") {
        if let Err(e) = login().await {
            eprintln!("device login failed: {e}");
            std::process::exit(1)
        }
        return;
    }
    let secret = read_secret().expect("agent channel secret unavailable or weak");
    #[cfg(feature = "synthetic-test")]
    return serve_synthetic(secret).await;
    #[cfg(not(feature = "synthetic-test"))]
    {
        let home = PathBuf::from(env::var("CODEX_HOME").unwrap_or_else(|_| HOME.into()));
        let _lock = lock_home(&home).expect("CODEX_HOME lock/ownership validation failed");
        cleanup_staging(&home).expect("unsafe stale staging entry");
        validate_home(&home).expect("CODEX_HOME validation failed");
        let route = AuthRouteConfig::from_http_client_factory(HttpClientFactory::new(
            OutboundProxyPolicy::ReqwestDefault,
        ));
        let manager = std::sync::Arc::new(
            AuthManager::new(
                home,
                false,
                AuthCredentialsStoreMode::File,
                None,
                None,
                AuthKeyringBackendKind::default(),
                route,
            )
            .await,
        );
        serve_real(secret, manager).await
    }
}
fn read_secret() -> io::Result<Vec<u8>> {
    let s = fs::read_to_string(CHANNEL_SECRET)?;
    let s = s.trim();
    if s.len() < 32 {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "channel secret must be at least 32 bytes",
        ));
    }
    Ok(s.as_bytes().to_vec())
}
fn current_uid() -> u32 {
    // SAFETY: geteuid has no preconditions and only reads the process identity.
    unsafe { libc::geteuid() }
}
fn secure_dir(path: &Path) -> io::Result<()> {
    let m = fs::symlink_metadata(path)?;
    if !m.is_dir() || (m.uid() != current_uid() && m.uid() != 0) || m.mode() & 0o002 != 0 {
        return Err(io::Error::new(
            io::ErrorKind::PermissionDenied,
            "path is not a private owned directory",
        ));
    }
    Ok(())
}
fn prepare_socket() -> io::Result<()> {
    let p = Path::new(SOCKET).parent().unwrap();
    secure_dir(p)?;
    match fs::symlink_metadata(SOCKET) {
        Ok(m)
            if m.file_type().is_symlink()
                || !m.file_type().is_socket()
                || m.uid() != current_uid()
                || m.mode() & 0o007 != 0 =>
        {
            Err(io::Error::new(
                io::ErrorKind::PermissionDenied,
                "socket path is unsafe",
            ))
        }
        Ok(_) => fs::remove_file(SOCKET),
        Err(e) if e.kind() == io::ErrorKind::NotFound => Ok(()),
        Err(e) => Err(e),
    }
}
#[cfg(feature = "synthetic-test")]
async fn serve_synthetic(secret: Vec<u8>) {
    let stats = Arc::new(SyntheticStats::default());
    let counter_stats = stats.clone();
    tokio::spawn(async move { serve_counters(counter_stats).await });
    prepare_socket().expect("socket path validation failed");
    let listener = UnixListener::bind(SOCKET).expect("bind agent socket");
    fs::set_permissions(SOCKET, fs::Permissions::from_mode(0o660)).unwrap();
    loop {
        let (s, _) = listener.accept().await.unwrap();
        let k = secret.clone();
        let stats = stats.clone();
        tokio::spawn(async move {
            let _ = handle_synthetic(s, k, stats).await;
        });
    }
}
#[cfg(feature = "synthetic-test")]
#[derive(Default)]
struct SyntheticStats {
    acquire: AtomicUsize,
    recover: AtomicUsize,
}
#[cfg(feature = "synthetic-test")]
async fn serve_counters(stats: Arc<SyntheticStats>) {
    let listener = TcpListener::bind(SYNTHETIC_COUNTERS)
        .await
        .expect("bind synthetic counters");
    loop {
        let (mut stream, _) = listener.accept().await.expect("accept synthetic counters");
        let stats = stats.clone();
        tokio::spawn(async move {
            let mut request = [0u8; 512];
            let _ = timeout(FRAME_TIMEOUT, stream.read(&mut request)).await;
            let body = format!(
                "{{\"acquire\":{},\"recover\":{}}}",
                stats.acquire.load(Ordering::Relaxed),
                stats.recover.load(Ordering::Relaxed)
            );
            let response = format!(
                "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}",
                body.len(),
                body
            );
            let _ = stream.write_all(response.as_bytes()).await;
        });
    }
}
#[cfg(feature = "synthetic-test")]
async fn handle_synthetic(
    stream: UnixStream,
    key: Vec<u8>,
    stats: Arc<SyntheticStats>,
) -> io::Result<()> {
    let (mut r, mut w) = stream.into_split();
    let frame = timeout(FRAME_TIMEOUT, read_frame(&mut r)).await??;
    let q: Request = decode(&frame).map_err(|_| io::Error::other("malformed request"))?;
    if !validate_request(&q, PROFILE, AUDIENCE) || !valid_mac(&request_mac(&key, &q), &q.mac) {
        return Ok(());
    };
    let mut out = Response {
        version: VERSION,
        ok: true,
        nonce: q.nonce,
        mac: String::new(),
        headers: match q.operation {
            Operation::Ping => vec![],
            Operation::UnauthorizedRecovery => {
                stats.recover.fetch_add(1, Ordering::Relaxed);
                vec![]
            }
            Operation::Acquire => vec![
                (
                    "authorization".into(),
                    "Bearer synthetic-agent-token".into(),
                ),
                ("chatgpt-account-id".into(), "synthetic-account".into()),
            ],
        },
    };
    if q.operation == Operation::Acquire {
        stats.acquire.fetch_add(1, Ordering::Relaxed);
    }
    out.mac = response_mac(&key, &out);
    timeout(FRAME_TIMEOUT, w.write_all(&encode(&out).unwrap())).await??;
    Ok(())
}
#[cfg(not(feature = "synthetic-test"))]
async fn serve_real(secret: Vec<u8>, manager: std::sync::Arc<AuthManager>) {
    prepare_socket().expect("socket path validation failed");
    let listener = UnixListener::bind(SOCKET).expect("bind agent socket");
    fs::set_permissions(SOCKET, fs::Permissions::from_mode(0o660)).unwrap();
    loop {
        let (s, _) = listener.accept().await.unwrap();
        let k = secret.clone();
        let m = manager.clone();
        tokio::spawn(async move {
            let _ = handle_real(s, k, m).await;
        });
    }
}
#[cfg(not(feature = "synthetic-test"))]
async fn handle_real(
    stream: UnixStream,
    key: Vec<u8>,
    manager: std::sync::Arc<AuthManager>,
) -> io::Result<()> {
    let (mut r, mut w) = stream.into_split();
    let frame = timeout(FRAME_TIMEOUT, read_frame(&mut r)).await??;
    let q: Request = decode(&frame).map_err(|_| io::Error::other("malformed request"))?;
    if !validate_request(&q, PROFILE, AUDIENCE) || !valid_mac(&request_mac(&key, &q), &q.mac) {
        return Ok(());
    };
    let mut out = match q.operation {
        Operation::Ping => Response {
            version: VERSION,
            ok: true,
            nonce: q.nonce,
            mac: String::new(),
            headers: vec![],
        },
        Operation::Acquire => acquire(&manager, q.nonce).await,
        Operation::UnauthorizedRecovery => recover(&manager, q.nonce).await,
    };
    out.mac = response_mac(&key, &out);
    timeout(
        FRAME_TIMEOUT,
        w.write_all(&encode(&out).map_err(|_| io::Error::other("response too large"))?),
    )
    .await??;
    Ok(())
}
#[cfg(not(feature = "synthetic-test"))]
async fn acquire(m: &AuthManager, nonce: String) -> Response {
    match m.auth().await {
        Some(a @ (CodexAuth::Chatgpt(_) | CodexAuth::ChatgptAuthTokens(_))) => {
            match a.get_token() {
                Ok(t) => Response {
                    version: VERSION,
                    ok: true,
                    nonce,
                    mac: String::new(),
                    headers: vec![
                        ("authorization".into(), format!("Bearer {t}")),
                        (
                            "chatgpt-account-id".into(),
                            a.get_account_id().unwrap_or_default(),
                        ),
                    ],
                },
                Err(_) => bad(nonce),
            }
        }
        _ => bad(nonce),
    }
}
#[cfg(not(feature = "synthetic-test"))]
async fn recover(m: &std::sync::Arc<AuthManager>, nonce: String) -> Response {
    let mut r = m.unauthorized_recovery();
    while r.has_next() {
        if r.next().await.is_err() {
            return bad(nonce);
        }
    }
    Response {
        version: VERSION,
        ok: true,
        nonce,
        mac: String::new(),
        headers: vec![],
    }
}
#[cfg(not(feature = "synthetic-test"))]
fn bad(nonce: String) -> Response {
    Response {
        version: VERSION,
        ok: false,
        nonce,
        mac: String::new(),
        headers: vec![],
    }
}

#[cfg(not(feature = "synthetic-test"))]
fn lock_home(home: &Path) -> io::Result<File> {
    fs::create_dir_all(home)?;
    secure_dir(home)?;
    let lock = home.join(".broker.lock");
    if let Ok(m) = fs::symlink_metadata(&lock) {
        if !m.is_file() || m.file_type().is_symlink() || m.uid() != current_uid() {
            return Err(io::Error::new(
                io::ErrorKind::PermissionDenied,
                "auth lock path is unsafe",
            ));
        }
    }
    let f = OpenOptions::new()
        .create(true)
        .read(true)
        .write(true)
        .mode(0o600)
        .custom_flags(libc::O_NOFOLLOW)
        .open(lock)?;
    let m = f.metadata()?;
    if !m.is_file() || m.uid() != current_uid() || m.mode() & 0o077 != 0 {
        return Err(io::Error::new(
            io::ErrorKind::PermissionDenied,
            "CODEX_HOME lock must be a private file owned by the current user",
        ));
    }
    f.try_lock_exclusive()
        .map_err(|_| io::Error::new(io::ErrorKind::WouldBlock, "CODEX_HOME is already locked"))?;
    Ok(f)
}
#[cfg(not(feature = "synthetic-test"))]
fn validate_home(home: &Path) -> io::Result<()> {
    secure_dir(home)?;
    if let Ok(m) = fs::symlink_metadata(home.join("auth.json")) {
        if !m.is_file()
            || m.uid() != current_uid()
            || m.mode() & 0o007 != 0
            || m.mode() & 0o077 != 0
            || m.len() > 16 * 1024 * 1024
        {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "auth.json is unsafe",
            ));
        };
        let data = fs::read(home.join("auth.json"))?;
        validate_auth_json(&data)?;
    }
    Ok(())
}
#[cfg(not(feature = "synthetic-test"))]
fn validate_auth_json(data: &[u8]) -> io::Result<()> {
    let value: serde_json::Value = serde_json::from_slice(data).map_err(|_| {
        io::Error::new(io::ErrorKind::InvalidData, "auth.json is not complete JSON")
    })?;
    let tokens = value
        .get("tokens")
        .and_then(serde_json::Value::as_object)
        .ok_or_else(|| {
            io::Error::new(io::ErrorKind::InvalidData, "auth.json has no token object")
        })?;
    for name in ["access_token", "refresh_token"] {
        if tokens
            .get(name)
            .and_then(serde_json::Value::as_str)
            .is_none_or(str::is_empty)
        {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "auth.json has incomplete tokens",
            ));
        }
    }
    Ok(())
}
#[cfg(not(feature = "synthetic-test"))]
fn cleanup_staging(home: &Path) -> io::Result<()> {
    for e in fs::read_dir(home)? {
        let e = e?;
        if e.file_name()
            .to_string_lossy()
            .starts_with(".auth-staging-")
        {
            let m = fs::symlink_metadata(e.path())?;
            if !m.is_dir() || m.file_type().is_symlink() || m.uid() != current_uid() {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidData,
                    "staging entry is unsafe",
                ));
            };
            fs::remove_dir_all(e.path())?
        }
    }
    Ok(())
}
#[cfg(not(feature = "synthetic-test"))]
async fn login() -> io::Result<()> {
    let home = PathBuf::from(env::var("CODEX_HOME").unwrap_or_else(|_| HOME.into()));
    fs::create_dir_all(&home)?;
    secure_dir(&home)?;
    let _lock = lock_home(&home)?;
    cleanup_staging(&home)?;
    validate_home(&home)?;
    let n = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_nanos();
    let staging = home.join(format!(".auth-staging-{n}"));
    fs::create_dir(&staging)?;
    fs::set_permissions(&staging, fs::Permissions::from_mode(0o700))?;
    let route = AuthRouteConfig::from_http_client_factory(HttpClientFactory::new(
        OutboundProxyPolicy::ReqwestDefault,
    ));
    let opts = ServerOptions::new(
        staging.clone(),
        codex_login::CLIENT_ID.to_string(),
        None,
        AuthCredentialsStoreMode::File,
        AuthKeyringBackendKind::default(),
        route,
    );
    let result = tokio::select! {r=run_device_code_login(opts)=>r.map_err(|e|io::Error::other(e.to_string())),_=signal()=>Err(io::Error::new(io::ErrorKind::Interrupted,"device login interrupted"))};
    if result.is_err() {
        let _ = fs::remove_dir_all(&staging);
        return result.map(|_| ());
    };
    let src = staging.join("auth.json");
    let install = (|| {
        let data = fs::read(&src)?;
        validate_auth_json(&data)?;
        let f = OpenOptions::new().write(true).append(true).open(&src)?;
        f.sync_all()?;
        io::Result::Ok(())
    })();
    if let Err(e) = install {
        let _ = fs::remove_dir_all(&staging);
        return Err(e);
    }
    let result = install_auth(&home, &src, None);
    let _ = fs::remove_dir_all(&staging);
    result
}

#[cfg(not(feature = "synthetic-test"))]
#[cfg_attr(not(test), allow(dead_code))]
#[derive(Clone, Copy)]
enum InstallFailure {
    AfterBackupSync,
    AfterActiveReplacement,
    AfterActiveSync,
}

#[cfg(not(feature = "synthetic-test"))]
fn install_auth(home: &Path, staged: &Path, failure: Option<InstallFailure>) -> io::Result<()> {
    let auth = home.join("auth.json");
    let backup = home.join("auth.json.backup");
    let old = match fs::symlink_metadata(&auth) {
        Ok(m) => {
            if !m.is_file()
                || m.file_type().is_symlink()
                || m.uid() != current_uid()
                || m.mode() & 0o077 != 0
            {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidData,
                    "existing auth.json is unsafe",
                ));
            }
            Some(fs::read(&auth)?)
        }
        Err(e) if e.kind() == io::ErrorKind::NotFound => None,
        Err(e) => return Err(e),
    };
    let new = fs::read(staged)?;
    validate_auth_json(&new)?;
    let staged_metadata = fs::symlink_metadata(staged)?;
    if !staged_metadata.is_file()
        || staged_metadata.file_type().is_symlink()
        || staged_metadata.uid() != current_uid()
    {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "staged auth.json is unsafe",
        ));
    }
    fs::set_permissions(staged, fs::Permissions::from_mode(0o600))?;
    if let Some(old) = old {
        atomic_write(&backup, &old)?;
        sync_parent(
            home,
            "backup",
            matches!(failure, Some(InstallFailure::AfterBackupSync)),
        )?;
    }
    fs::rename(staged, &auth)?;
    if matches!(failure, Some(InstallFailure::AfterActiveReplacement)) {
        return Err(io::Error::other(
            "injected failure after active replacement",
        ));
    }
    sync_parent(
        home,
        "auth replacement",
        matches!(failure, Some(InstallFailure::AfterActiveSync)),
    )?;
    Ok(())
}

#[cfg(not(feature = "synthetic-test"))]
fn atomic_write(path: &Path, data: &[u8]) -> io::Result<()> {
    let parent = path
        .parent()
        .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidInput, "file has no parent"))?;
    let name = path
        .file_name()
        .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidInput, "file has no name"))?
        .to_string_lossy();
    let stamp = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_nanos();
    let tmp = parent.join(format!(".{name}.tmp-{}-{stamp}", std::process::id()));
    let mut f = OpenOptions::new()
        .create_new(true)
        .write(true)
        .mode(0o600)
        .custom_flags(libc::O_NOFOLLOW)
        .open(&tmp)?;
    if let Err(e) = f.write_all(data).and_then(|_| f.sync_all()) {
        let _ = fs::remove_file(&tmp);
        return Err(e);
    }
    drop(f);
    if let Err(e) = fs::rename(&tmp, path) {
        let _ = fs::remove_file(&tmp);
        return Err(e);
    }
    Ok(())
}

#[cfg(not(feature = "synthetic-test"))]
fn sync_parent(home: &Path, what: &str, injected_failure: bool) -> io::Result<()> {
    let sync = File::open(home).and_then(|d| d.sync_all());
    if injected_failure || sync.is_err() {
        return Err(io::Error::other(format!(
            "auth installation completed {what}, but parent-directory durability is uncertain; active auth may already be the new valid file and auth.json.backup remains available"
        )));
    }
    Ok(())
}
#[cfg(not(feature = "synthetic-test"))]
async fn signal() {
    #[cfg(unix)]
    {
        let mut s =
            tokio::signal::unix::signal(tokio::signal::unix::SignalKind::interrupt()).unwrap();
        let mut t =
            tokio::signal::unix::signal(tokio::signal::unix::SignalKind::terminate()).unwrap();
        tokio::select! {_=s.recv()=>{},_=t.recv()=>{}}
    }
    #[cfg(not(unix))]
    {
        let _ = tokio::signal::ctrl_c().await;
    }
}

#[cfg(all(test, not(feature = "synthetic-test")))]
mod tests {
    use super::*;
    use std::os::unix::fs::symlink;

    #[test]
    fn lock_is_exclusive_and_staging_is_reaped() {
        let d = tempfile::tempdir().unwrap();
        let first = lock_home(d.path()).unwrap();
        assert!(lock_home(d.path()).is_err());
        drop(first);
        fs::create_dir(d.path().join(".auth-staging-killed")).unwrap();
        cleanup_staging(d.path()).unwrap();
        assert!(!d.path().join(".auth-staging-killed").exists());
    }

    #[test]
    fn symlinked_home_and_lock_are_rejected() {
        let d = tempfile::tempdir().unwrap();
        let link = d.path().join("home-link");
        symlink(d.path(), &link).unwrap();
        assert!(secure_dir(&link).is_err());
        let lock = d.path().join(".broker.lock");
        symlink(d.path().join("real-lock"), &lock).unwrap();
        assert!(lock_home(d.path()).is_err());
    }

    #[test]
    fn malformed_or_insecure_auth_is_rejected() {
        let d = tempfile::tempdir().unwrap();
        fs::write(d.path().join("auth.json"), b"not-json").unwrap();
        assert!(validate_home(d.path()).is_err());
    }

    #[test]
    fn insecure_lock_mode_is_rejected() {
        let d = tempfile::tempdir().unwrap();
        let lock = d.path().join(".broker.lock");
        fs::write(&lock, b"").unwrap();
        fs::set_permissions(&lock, fs::Permissions::from_mode(0o640)).unwrap();
        assert!(lock_home(d.path()).is_err());
    }

    fn auth(token: &str) -> Vec<u8> {
        format!(r#"{{"tokens":{{"access_token":"{token}","refresh_token":"refresh"}}}}"#)
            .into_bytes()
    }

    #[test]
    fn replacement_keeps_old_auth_until_new_auth_is_ready() {
        let d = tempfile::tempdir().unwrap();
        let active = d.path().join("auth.json");
        let staged = d.path().join("staged-auth.json");
        fs::write(&active, auth("old")).unwrap();
        fs::set_permissions(&active, fs::Permissions::from_mode(0o600)).unwrap();
        fs::write(&staged, auth("new")).unwrap();
        assert!(install_auth(d.path(), &staged, Some(InstallFailure::AfterBackupSync)).is_err());
        assert_eq!(fs::read(&active).unwrap(), auth("old"));
        assert_eq!(
            fs::read(d.path().join("auth.json.backup")).unwrap(),
            auth("old")
        );
        fs::write(&staged, auth("new")).unwrap();
        assert!(install_auth(d.path(), &staged, None).is_ok());
        assert_eq!(fs::read(&active).unwrap(), auth("new"));
        assert_eq!(
            fs::read(d.path().join("auth.json.backup")).unwrap(),
            auth("old")
        );
        fs::write(&staged, auth("newer")).unwrap();
        assert!(
            install_auth(
                d.path(),
                &staged,
                Some(InstallFailure::AfterActiveReplacement)
            )
            .is_err()
        );
        validate_auth_json(&fs::read(&active).unwrap()).unwrap();
        validate_auth_json(&fs::read(d.path().join("auth.json.backup")).unwrap()).unwrap();
        fs::write(&staged, auth("newer")).unwrap();
        let result = install_auth(d.path(), &staged, Some(InstallFailure::AfterActiveSync));
        let error = result.unwrap_err().to_string();
        assert!(error.contains("durability is uncertain"));
        validate_auth_json(&fs::read(&active).unwrap()).unwrap();
        validate_auth_json(&fs::read(d.path().join("auth.json.backup")).unwrap()).unwrap();
        fs::write(&staged, auth("latest")).unwrap();
        install_auth(d.path(), &staged, None).unwrap();
        validate_auth_json(&fs::read(&active).unwrap()).unwrap();
        validate_auth_json(&fs::read(d.path().join("auth.json.backup")).unwrap()).unwrap();
        assert_eq!(fs::read(&active).unwrap(), auth("latest"));
    }
}
