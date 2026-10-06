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
use serde::Deserialize;
use sha2::{Digest, Sha256};
use std::{
    collections::{HashMap, HashSet},
    io::ErrorKind,
    path::Path,
    sync::{
        Arc,
        atomic::{AtomicUsize, Ordering},
    },
};
use tracing::info;

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
    in_flight: AtomicUsize,
}

impl Operator {
    pub fn name(&self) -> &str {
        &self.name
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
    /// The operators the file at `path` names, or none if there is no such
    /// file. `injected` are the clusters a token may be for.
    ///
    /// # Errors
    ///
    /// Returns what is wrong with a file that can't be read or isn't valid.
    pub fn load(path: &Path, injected: &HashSet<&str>) -> Result<Self, String> {
        let text = match std::fs::read_to_string(path) {
            Ok(text) => text,
            Err(e) if e.kind() == ErrorKind::NotFound => return Ok(Self::default()),
            Err(e) => return Err(format!("{}: {e}", path.display())),
        };
        let operators =
            Self::parse(&text, injected).map_err(|e| format!("{}: {e}", path.display()))?;
        info!(
            tokens_file = %path.display(),
            operators = ?operators.names(),
            "operator tokens loaded"
        );
        Ok(operators)
    }

    fn parse(text: &str, injected: &HashSet<&str>) -> Result<Self, String> {
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
                in_flight: AtomicUsize::new(0),
            };
            if by_hash.insert(hash, Arc::new(operator)).is_some() {
                return Err("two operators share a token".to_owned());
            }
        }
        Ok(Self { by_hash })
    }

    /// The operators' names, sorted.
    pub fn names(&self) -> Vec<&str> {
        let mut names: Vec<_> = self.by_hash.values().map(|o| o.name()).collect();
        names.sort_unstable();
        names
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

#[cfg(test)]
mod tests {
    use super::*;

    const TOKEN: &str = "praxis-operator-0000";

    fn sha256(token: &str) -> String {
        hex::encode(Sha256::digest(token.as_bytes()))
    }

    fn injected() -> HashSet<&'static str> {
        HashSet::from(["codex", "claude"])
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
            let parsed = Operators::parse(&text, &injected());
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
        assert!(
            Operators::load(&path, &injected())
                .unwrap()
                .names()
                .is_empty()
        );
        std::fs::write(&path, "operators: [").unwrap();
        let error = Operators::load(&path, &injected()).unwrap_err();
        assert!(error.contains("operator-tokens.yaml"), "{error}");
    }

    #[test]
    fn only_the_whole_token_authenticates_its_operator() {
        let text = format!("operators: [{}]", entry("me", TOKEN, "clusters: [codex]"));
        let operators = Operators::parse(&text, &injected()).unwrap();
        assert_eq!(
            operators.authenticate(TOKEN).unwrap().subject(),
            "operator:me"
        );
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
        let operators = Operators::parse(&text, &injected()).unwrap();
        assert!(operators.authenticate("bare").is_none());
    }

    #[test]
    fn operators_are_admitted_for_their_clusters_within_their_concurrency() {
        let text = format!(
            "operators: [{}]",
            entry("me", TOKEN, "clusters: [codex], concurrency: 2")
        );
        let operators = Operators::parse(&text, &injected()).unwrap();
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
