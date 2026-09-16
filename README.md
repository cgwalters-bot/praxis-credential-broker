# praxis-credential-broker (alpha architecture spike)

This repository is an intentionally local, security-focused spike. It places a
generic credential boundary behind stock Praxis:

```text
client -> stock Praxis -> credential-proxy -> provider-codex -> chatgpt.com
                                      \-> private versioned Unix socket
```

Only Praxis publishes `127.0.0.1:18080`; its image is pinned exactly to
`ghcr.io/praxis-proxy/ai@sha256:ccd46f8772eebcbde2f41ad35c3234d23463b8314a5865083e32baf31eddd1a8`.
The proxy has no Codex SDK, OAuth state, or writable credential volume. The
Codex agent exclusively owns `CODEX_HOME` and uses official `codex-login` at
`0dfb28edb9305fcae4ab006fb6b7b196cbdbac28`.

## Design and trust boundaries

`credential-protocol` is version 1 newline-delimited JSON, bounded to 16 KiB
during reads and writes, with authenticated `Ping`, `Acquire`, and
`UnauthorizedRecovery` operations. A dedicated 32-byte-minimum channel secret
authenticates both request and response with nonce/HMAC; the proxy supplies the
registered profile and audience; requests cannot select a URL, authority, or
profile. The agent validates all three before returning only sensitive headers.
The socket is a mode-0660 memory `emptyDir`, and both images run as UID/GID
65532 with read-only roots, no capabilities, and no privilege escalation.

The proxy requires a Podman secret bearer key of at least 32 bytes, strips
caller authorization, cookies, account and hop-by-hop/proxy headers, and
injects agent headers transiently. It forwards only POST `/v1/responses` to
the fixed HTTPS endpoint. An upstream 401 permits exactly one recovery call and
retry. Finite and SSE streams retain idle, byte, and concurrency limits;
`/healthz` uses side-effect-free `Ping` and says only `ready` or `not ready`.

`provider-codex` is the sole owner of the refresh volume. Login is intended to
run as a stopped-agent one-shot using official device login, with an advisory
lock and same-volume staging followed by atomic installation; cancellation
must leave the existing `auth.json` untouched. Never use real credentials in
the synthetic test pod.

## Run and test

Requires Podman and `just`. Put a private 32-byte minimum key at
`/tmp/praxis-credential-broker-client-auth` and a separate channel secret at
`/tmp/praxis-credential-broker-agent-channel` (both mode 0600), then run `just up`,
`just health`, and `just down`. `just login` runs the pinned device-login command
against the named auth volume while the provider is stopped; an existing lock
fails closed. `just test-pod` builds a synthetic agent and
mock upstream; it has no production OAuth and publishes only the test Praxis
listener on `127.0.0.1:18081`. Run `cargo fmt --all`, `cargo clippy --workspace
--all-targets --all-features --locked`, and `cargo test --workspace --locked`.

Codex client:

```toml
[model_providers.praxis]
name = "Local Praxis"
base_url = "http://127.0.0.1:18080/v1"
wire_api = "responses"
env_key = "PRAXIS_API_KEY"
[profiles.praxis]
model_provider = "praxis"
```

OpenCode:

```json
{"provider":{"praxis":{"options":{"baseURL":"http://127.0.0.1:18080/v1","apiKey":"{env:PRAXIS_API_KEY}"}}}}
```

Do not set `requires_openai_auth`; Praxis receives only the client key.
Future deployment may use tailnet-only Tailscale Serve and `svc:inference`.
There is deliberately no Funnel, public bind, or tailnet mutation here.

## Providers, advisories, and provenance

Adding a provider means adding an agent implementing this private protocol and
registering a profile/audience in the proxy configuration; the HTTP streaming
and client-auth core remains unchanged. This is an alpha spike, not a
production-ready service. `cargo-deny` keeps the exact Hickory advisories
`RUSTSEC-2026-0118` and `RUSTSEC-2026-0119` as hard deployment blockers; the
known unmaintained transitive advisories are listed in `deny.toml`/the prior
dependency review and are not blanket-hidden. Review the dependency graph
before deployment.

The project and directly consumed Codex sources are Apache-2.0; see `NOTICE`
for provenance. This spike exceeds the roughly 500 substantial-line
design-review threshold; independent security/design review is required before
GitHub publication or production use.
