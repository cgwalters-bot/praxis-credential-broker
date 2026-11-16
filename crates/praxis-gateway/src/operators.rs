//! Operator tokens: long-lived bearer tokens with which a person uses the
//! injected routes outside any registered run, such as an interactive
//! agent on a workstation.
//!
//! Unlike a run token, which a job earns with a verified OIDC token and
//! which ends with its run, an operator token is whatever the deployment's
//! tokens file names, for as long as it names it. The file holds only each
//! token's SHA-256, so the gateway keeps no operator secret, and says which
//! injected clusters the token may use. Its holder becomes the request's
//! authenticated identity under its own name, so the `token_rate_limit`
//! rule keyed on the identity caps it like a run, and `/usage` counts it
//! apart from the runs.
//!
//! With [`watch`] the file is read again whenever its content changes, so
//! that tokens are added and revoked without a restart, which would end
//! every run. Polling the content, rather than watching for events, also
//! sees a Kubernetes ConfigMap's `..data` symlink swapped.
use crate::budget::Consumer;
use serde::Deserialize;
use sha2::{Digest, Sha256};
use std::{
    collections::{HashMap, HashSet},
    io::ErrorKind,
    path::{Path, PathBuf},
    sync::{
        Arc, PoisonError, RwLock, Weak,
        atomic::{AtomicUsize, Ordering},
    },
    time::Duration,
};
use tracing::{info, warn};

pub const TOKEN_PREFIX: &str = "praxis-operator-";
/// Operators a tokens file may name, which bounds what `/usage` keeps.
pub const MAX_OPERATORS: usize = 16;
const MAX_NAME_LEN: usize = 64;
const DEFAULT_CONCURRENCY: usize = 8;

fn default_concurrency() -> usize {
    DEFAULT_CONCURRENCY
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct TokensFile {
    operators: Vec<Entry>,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct Entry {
    /// What `/usage` and the logs call the operator: lowercase letters,
    /// digits and `-`.
    name: String,
    /// The SHA-256 of the whole token, prefix included, in hex.
    token_sha256: String,
    /// The injected clusters the token may use.
    clusters: HashSet<String>,
    /// Requests of the operator in flight at once.
    #[serde(default = "default_concurrency")]
    concurrency: usize,
    /// Whose budget its use counts against.
    #[serde(default)]
    consumer: Consumer,
}

#[derive(Debug, PartialEq, Eq)]
pub enum Refusal {
    /// The token is not for this cluster.
    Forbidden,
    Busy,
}

#[derive(Debug)]
pub struct Operator {
    name: String,
    clusters: HashSet<String>,
    concurrency: usize,
    consumer: Consumer,
    /// Shared with the same token's operator in a reloaded set, so that
    /// requests in flight across a reload still count.
    in_flight: Arc<AtomicUsize>,
}

impl Operator {
    pub fn name(&self) -> &str {
        &self.name
    }

    pub fn consumer(&self) -> Consumer {
        self.consumer
    }

    /// The operator as an authenticated subject, which budgets are keyed
    /// on. No run's subject starts like it.
    pub fn subject(&self) -> String {
        format!("operator:{}", self.name)
    }

    /// Admit a request for `cluster` within the operator's concurrency.
    pub fn admit(self: &Arc<Self>, cluster: &str) -> Result<Slot, Refusal> {
        if !self.clusters.contains(cluster) {
            return Err(Refusal::Forbidden);
        }
        if self.in_flight.fetch_add(1, Ordering::AcqRel) >= self.concurrency {
            self.in_flight.fetch_sub(1, Ordering::AcqRel);
            return Err(Refusal::Busy);
        }
        Ok(Slot {
            operator: Arc::clone(self),
            usage_free: false,
        })
    }
}

/// A request admitted for an operator, holding one of its concurrency
/// slots until its response ends or the client leaves.
#[derive(Debug)]
pub struct Slot {
    operator: Arc<Operator>,
    /// The request uses no tokens, like counting them.
    pub usage_free: bool,
}

impl Slot {
    pub fn operator(&self) -> &Operator {
        &self.operator
    }
}

impl Drop for Slot {
    fn drop(&mut self) {
        self.operator.in_flight.fetch_sub(1, Ordering::AcqRel);
    }
}

/// The operators of a deployment, by the SHA-256 of their tokens.
#[derive(Debug, Default)]
pub struct Operators {
    by_hash: HashMap<[u8; 32], Arc<Operator>>,
}

impl Operators {
    /// The operators `text`, read from `path`, names; none without a file.
    /// `injected` are the clusters a token may be for. Those whose token
    /// `previous` also has share its in-flight count.
    fn from_text(
        path: &Path,
        text: Option<&str>,
        injected: &HashSet<&str>,
        previous: &Self,
    ) -> Result<Self, String> {
        let operators = match text {
            None => Self::default(),
            Some(text) => Self::parse(text, injected, previous)
                .map_err(|e| format!("{}: {e}", path.display()))?,
        };
        info!(
            tokens_file = %path.display(),
            operators = ?operators.names(),
            "operator tokens loaded"
        );
        Ok(operators)
    }

    fn parse(text: &str, injected: &HashSet<&str>, previous: &Self) -> Result<Self, String> {
        let file: TokensFile = serde_yaml::from_str(text).map_err(|e| e.to_string())?;
        if file.operators.len() > MAX_OPERATORS {
            return Err(format!("at most {MAX_OPERATORS} operators"));
        }
        let mut by_hash = HashMap::new();
        let mut names = HashSet::new();
        for entry in file.operators {
            let name = &entry.name;
            let named_well = !name.is_empty()
                && name.len() <= MAX_NAME_LEN
                && name
                    .bytes()
                    .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'-');
            if !named_well {
                return Err(format!(
                    "operator name {name:?} must be 1 to {MAX_NAME_LEN} of a-z, 0-9 and '-'"
                ));
            }
            let mut hash = [0; 32];
            hex::decode_to_slice(&entry.token_sha256, &mut hash)
                .map_err(|_| format!("{name}: token_sha256 must be 64 hex digits"))?;
            if entry.concurrency == 0 {
                return Err(format!("{name}: concurrency must be positive"));
            }
            if entry.clusters.is_empty() {
                return Err(format!("{name}: clusters must name a cluster"));
            }
            if let Some(cluster) = entry
                .clusters
                .iter()
                .find(|c| !injected.contains(c.as_str()))
            {
                return Err(format!("{name}: {cluster:?} is not an injected cluster"));
            }
            if !names.insert(name.clone()) {
                return Err(format!("{name}: named twice"));
            }
            let operator = Operator {
                name: entry.name,
                clusters: entry.clusters,
                concurrency: entry.concurrency,
                consumer: entry.consumer,
                in_flight: previous
                    .by_hash
                    .get(&hash)
                    .map(|old| Arc::clone(&old.in_flight))
                    .unwrap_or_default(),
            };
            if by_hash.insert(hash, Arc::new(operator)).is_some() {
                return Err("two operators share a token".to_owned());
            }
        }
        Ok(Self { by_hash })
    }

    /// The operators, sorted by name.
    pub fn sorted(&self) -> Vec<&Operator> {
        let mut operators: Vec<_> = self.by_hash.values().map(AsRef::as_ref).collect();
        operators.sort_unstable_by_key(|o| o.name());
        operators
    }

    /// The operators' names, sorted.
    pub fn names(&self) -> Vec<&str> {
        self.sorted().into_iter().map(Operator::name).collect()
    }

    /// The operator a bearer token belongs to.
    pub fn authenticate(&self, token: &str) -> Option<&Arc<Operator>> {
        if !token.starts_with(TOKEN_PREFIX) {
            return None;
        }
        let hash: [u8; 32] = Sha256::digest(token.as_bytes()).into();
        self.by_hash.get(&hash)
    }
}

/// The operators a filter admits, which [`watch`] replaces as a whole.
pub type Shared = RwLock<Arc<Operators>>;

/// The current operators of `shared`.
pub fn current(shared: &Shared) -> Arc<Operators> {
    Arc::clone(&shared.read().unwrap_or_else(PoisonError::into_inner))
}

/// The text of the file at `path`, or none if there is no such file.
fn read(path: &Path) -> Result<Option<String>, String> {
    match std::fs::read_to_string(path) {
        Ok(text) => Ok(Some(text)),
        Err(e) if e.kind() == ErrorKind::NotFound => Ok(None),
        Err(e) => Err(format!("{}: {e}", path.display())),
    }
}

/// The operators the file at `path` names, or none if there is no such
/// file, calling `loaded` with them. `injected` are the clusters a token
/// may be for. With `every`, the file is then read again at that interval,
/// as [`watch`] says.
///
/// # Errors
///
/// Returns what is wrong with a file that can't be read or isn't valid.
pub fn load_watched(
    path: &Path,
    injected: &HashSet<&str>,
    every: Option<Duration>,
    loaded: impl Fn(&Operators) + Send + 'static,
) -> Result<Arc<Shared>, String> {
    let text = read(path)?;
    let operators = Operators::from_text(path, text.as_deref(), injected, &Operators::default())?;
    loaded(&operators);
    let shared = Arc::new(RwLock::new(Arc::new(operators)));
    if let Some(every) = every {
        let injected = injected.iter().map(|&c| c.to_owned()).collect();
        watch(
            path.to_owned(),
            injected,
            every,
            text,
            Arc::downgrade(&shared),
            loaded,
        );
    }
    Ok(shared)
}

/// Every `every`, read the file at `path` again, and if its content
/// differs from `last`, replace the operators of `shared` with those it
/// names, calling `loaded` with them first. A file that can't be read or
/// isn't valid keeps the operators there were. Stops within an interval of
/// `shared` being dropped, as when a reload of `praxis.yaml` builds another
/// filter.
fn watch(
    path: PathBuf,
    injected: HashSet<String>,
    every: Duration,
    last: Option<String>,
    shared: Weak<Shared>,
    loaded: impl Fn(&Operators) + Send + 'static,
) {
    let mut last = Ok(last);
    let watcher = move || {
        let injected = injected.iter().map(String::as_str).collect();
        loop {
            std::thread::sleep(every);
            let Some(shared) = shared.upgrade() else {
                return;
            };
            let text = read(&path);
            if text == last {
                continue;
            }
            let operators = text.clone().and_then(|text| {
                Operators::from_text(&path, text.as_deref(), &injected, &current(&shared))
            });
            match operators {
                Ok(operators) => {
                    loaded(&operators);
                    *shared.write().unwrap_or_else(PoisonError::into_inner) = Arc::new(operators);
                }
                Err(error) => warn!(%error, "operator tokens not reloaded; keeping the old ones"),
            }
            last = text;
        }
    };
    if let Err(e) = std::thread::Builder::new()
        .name("operator-tokens".to_owned())
        .spawn(watcher)
    {
        warn!(error = %e, "operator tokens file not watched");
    }
}

#[cfg(test)]
pub(crate) mod testing {
    use std::{os::unix::fs::symlink, path::Path};

    /// Update `name` in `dir` as the kubelet updates a ConfigMap mounted as
    /// a directory: write version `n` into a directory of its own, and
    /// point `..data` at it by renaming a new link over the old one. `name`
    /// links into `..data`, and is replaced by such a link the first time.
    pub fn kubelet_update(dir: &Path, name: &str, n: u32, text: &str) {
        let version = format!("..v{n}");
        std::fs::create_dir(dir.join(&version)).unwrap();
        std::fs::write(dir.join(&version).join(name), text).unwrap();
        let replace = |target: &Path, link: &str| {
            let new = dir.join("..data_tmp");
            symlink(target, &new).unwrap();
            std::fs::rename(&new, dir.join(link)).unwrap();
        };
        replace(Path::new(&version), "..data");
        if !dir.join(name).is_symlink() {
            replace(&Path::new("..data").join(name), name);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::{testing::kubelet_update, *};

    const TOKEN: &str = "praxis-operator-0000";

    fn sha256(token: &str) -> String {
        hex::encode(Sha256::digest(token.as_bytes()))
    }

    fn injected() -> HashSet<&'static str> {
        HashSet::from(["codex", "claude"])
    }

    fn parse(text: &str) -> Result<Operators, String> {
        Operators::parse(text, &injected(), &Operators::default())
    }

    fn load(path: &Path) -> Result<Arc<Operators>, String> {
        load_watched(path, &injected(), None, |_| {}).map(|shared| current(&shared))
    }

    fn entry(name: &str, token: &str, rest: &str) -> String {
        format!(
            "{{name: {name:?}, token_sha256: {:?}, {rest}}}",
            sha256(token)
        )
    }

    #[test]
    fn tokens_files_are_validated() {
        let ok = entry("me", TOKEN, "clusters: [codex]");
        let other = entry("you", "praxis-operator-1111", "clusters: [codex, claude]");
        let too_many: Vec<_> = (0..=MAX_OPERATORS)
            .map(|i| entry(&format!("o{i}"), &format!("t{i}"), "clusters: [codex]"))
            .collect();
        let cases = [
            ("one", format!("operators: [{ok}]"), Some(vec!["me"])),
            (
                "two",
                format!("operators: [{ok}, {other}]"),
                Some(vec!["me", "you"]),
            ),
            ("none", "operators: []".to_owned(), Some(vec![])),
            (
                "a consumer",
                format!(
                    "operators: [{}]",
                    entry("me", TOKEN, "clusters: [codex], consumer: public")
                ),
                Some(vec!["me"]),
            ),
            (
                "no such consumer",
                format!(
                    "operators: [{}]",
                    entry("me", TOKEN, "clusters: [codex], consumer: board")
                ),
                None,
            ),
            ("not yaml", "operators: [".to_owned(), None),
            ("no list", "{}".to_owned(), None),
            (
                "unknown field",
                format!(
                    "operators: [{}]",
                    entry("me", TOKEN, "clusters: [codex], admin: true")
                ),
                None,
            ),
            (
                "the token itself",
                "operators: [{name: me, token_sha256: praxis-operator-0000, clusters: [codex]}]"
                    .to_owned(),
                None,
            ),
            (
                "short hash",
                "operators: [{name: me, token_sha256: abcd, clusters: [codex]}]".to_owned(),
                None,
            ),
            (
                "no clusters",
                format!("operators: [{}]", entry("me", TOKEN, "clusters: []")),
                None,
            ),
            (
                "a cluster that is not injected",
                format!("operators: [{}]", entry("me", TOKEN, "clusters: [pass]")),
                None,
            ),
            (
                "no concurrency",
                format!(
                    "operators: [{}]",
                    entry("me", TOKEN, "clusters: [codex], concurrency: 0")
                ),
                None,
            ),
            (
                "empty name",
                format!("operators: [{}]", entry("", TOKEN, "clusters: [codex]")),
                None,
            ),
            (
                "a name that could pass for a run",
                format!(
                    "operators: [{}]",
                    entry("github-run:1/2", TOKEN, "clusters: [codex]")
                ),
                None,
            ),
            (
                "long name",
                format!(
                    "operators: [{}]",
                    entry(&"a".repeat(MAX_NAME_LEN + 1), TOKEN, "clusters: [codex]")
                ),
                None,
            ),
            (
                "same name",
                format!(
                    "operators: [{ok}, {}]",
                    entry("me", "praxis-operator-1111", "clusters: [codex]")
                ),
                None,
            ),
            (
                "same token",
                format!(
                    "operators: [{ok}, {}]",
                    entry("you", TOKEN, "clusters: [codex]")
                ),
                None,
            ),
            (
                "too many",
                format!("operators: [{}]", too_many.join(", ")),
                None,
            ),
        ];
        for (case, text, expected) in cases {
            let parsed = parse(&text);
            assert_eq!(
                parsed.as_ref().ok().map(Operators::names),
                expected,
                "{case}: {:?}",
                parsed.as_ref().err()
            );
        }
    }

    #[test]
    fn a_missing_tokens_file_names_no_operators() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("operator-tokens.yaml");
        assert!(load(&path).unwrap().names().is_empty());
        std::fs::write(&path, "operators: [").unwrap();
        let error = load(&path).unwrap_err();
        assert!(error.contains("operator-tokens.yaml"), "{error}");
    }

    #[test]
    fn a_watched_tokens_file_is_swapped_whole_and_only_when_valid() {
        const OTHER: &str = "praxis-operator-1111";
        let me = entry("me", TOKEN, "clusters: [codex], concurrency: 1");
        let you = entry("you", OTHER, "clusters: [codex]");
        let dir = tempfile::tempdir().unwrap();
        let version = |n, text: &str| kubelet_update(dir.path(), "operator-tokens.yaml", n, text);
        version(1, &format!("operators: [{me}]"));
        let path = dir.path().join("operator-tokens.yaml");
        let declared = Arc::new(std::sync::Mutex::new(Vec::new()));
        let shared = {
            let declared = Arc::clone(&declared);
            load_watched(
                &path,
                &injected(),
                Some(Duration::from_millis(10)),
                move |loaded| declared.lock().unwrap().push(loaded.names().join(",")),
            )
            .unwrap()
        };
        let declared = || declared.lock().unwrap().clone();
        let until = |done: &dyn Fn() -> bool| {
            for _ in 0..500 {
                if done() {
                    return;
                }
                std::thread::sleep(Duration::from_millis(10));
            }
            panic!("not reloaded: {:?}", declared());
        };
        let slot = current(&shared)
            .authenticate(TOKEN)
            .unwrap()
            .admit("codex")
            .unwrap();

        // An added token is admitted, and one that stays keeps its requests
        // in flight.
        version(2, &format!("operators: [{me}, {you}]"));
        until(&|| current(&shared).authenticate(OTHER).is_some());
        let operators = current(&shared);
        let operator = operators.authenticate(TOKEN).unwrap();
        assert_eq!(operator.admit("codex").err(), Some(Refusal::Busy));
        drop(slot);
        drop(operator.admit("codex").unwrap());

        // A file that is not valid keeps them all, and is not read again
        // until it changes.
        version(3, &format!("operators: [{me}, {you}, {me}]"));
        version(4, "operators: [");
        std::thread::sleep(Duration::from_millis(100));
        assert_eq!(current(&shared).names(), ["me", "you"]);
        assert_eq!(declared(), ["me", "me,you"]);

        // A removed token is refused.
        version(5, &format!("operators: [{you}]"));
        until(&|| current(&shared).authenticate(TOKEN).is_none());
        assert_eq!(declared(), ["me", "me,you", "you"]);

        // The watcher keeps no filter's operators alive, so it stops with them.
        let watched = Arc::downgrade(&shared);
        drop(shared);
        assert!(watched.upgrade().is_none());
    }

    #[test]
    fn only_the_whole_token_authenticates_its_operator() {
        let text = format!("operators: [{}]", entry("me", TOKEN, "clusters: [codex]"));
        let operators = parse(&text).unwrap();
        let operator = operators.authenticate(TOKEN).unwrap();
        assert_eq!(operator.subject(), "operator:me");
        // A rule that names no consumer is the private one's.
        assert_eq!(operator.consumer(), Consumer::Private);
        for wrong in [
            "",
            "praxis-operator-",
            "praxis-operator-0001",
            &sha256(TOKEN),
        ] {
            assert!(operators.authenticate(wrong).is_none(), "{wrong}");
        }
        // A token without the prefix is never an operator's, even if the
        // file has its hash.
        let text = format!("operators: [{}]", entry("me", "bare", "clusters: [codex]"));
        let operators = parse(&text).unwrap();
        assert!(operators.authenticate("bare").is_none());
    }

    #[test]
    fn operators_are_admitted_for_their_clusters_within_their_concurrency() {
        let text = format!(
            "operators: [{}]",
            entry("me", TOKEN, "clusters: [codex], concurrency: 2")
        );
        let operators = parse(&text).unwrap();
        let operator = operators.authenticate(TOKEN).unwrap();
        assert_eq!(operator.admit("claude").err(), Some(Refusal::Forbidden));
        let a = operator.admit("codex").unwrap();
        let _b = operator.admit("codex").unwrap();
        assert_eq!(operator.admit("codex").err(), Some(Refusal::Busy));
        // A refusal takes no slot, and a dropped one is free again.
        drop(a);
        let c = operator.admit("codex").unwrap();
        assert_eq!(c.operator().name(), "me");
        assert_eq!(operator.admit("codex").err(), Some(Refusal::Busy));
    }
}
