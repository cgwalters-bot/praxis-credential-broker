# Internals

This document records implementation, security, operational, and development
details that are intentionally kept out of the [quick-start README](README.md).

## Architecture and trust boundaries

```text
client -> stock Praxis -> credential-proxy -> fixed chatgpt.com Codex endpoint
                             ^
                             | private versioned Unix socket (credentials only)
                       provider-codex
```

There are three credential classes:

1. The client API key authenticates a local client to Praxis and must be at
   least 32 bytes.
2. The internal channel key is a generated HMAC secret between the proxy and
   provider; it is not a client credential.
3. Provider-owned ChatGPT Codex OAuth tokens live in the provider's auth
   volume after device login.

The proxy has no Codex SDK, OAuth state, or writable credential volume. The
provider exclusively owns `CODEX_HOME`. OAuth headers pass transiently through
the proxy while it constructs an upstream request; auth state remains
provider-owned.

The proxy accepts only `POST /v1/responses`, strips caller authorization,
cookies, account, hop-by-hop, and proxy headers, and forwards to a fixed HTTPS
endpoint. The client cannot choose a URL, authority, or provider profile.

### Private protocol and hardening

`credential-protocol` version 1 is newline-delimited JSON, bounded to 16 KiB
for reads and writes. `Ping`, `Acquire`, and `UnauthorizedRecovery` are
authenticated with nonce/HMAC and a channel secret of at least 32 bytes. This
is a private, pod-local protocol, not a general credential API; its protection
depends on the Podman deployment and its shared secret.

The socket is in the private named volume
`praxis-credential-broker-socket`, is mode 0660, and is shared only by proxy
and provider. Both images run as UID/GID 65532 with read-only root filesystems,
no capabilities, and no privilege escalation. The proxy alone receives the
Podman client-key secret; Praxis receives neither secret. The provider's
separate writable auth volume is mounted only at `/codex-home`.

Finite and SSE streams have idle, byte, and concurrency limits. `/healthz`
uses a side-effect-free `Ping` and returns only `ready` or `not ready`.

## OAuth lifecycle and startup

The provider uses pinned `codex-login` with
`AuthCredentialsStoreMode::File` in its auth volume. Every request admitted
for upstream forwarding performs `Acquire`; `AuthManager::auth` refreshes
managed ChatGPT authentication when needed and persists rotated access and
refresh tokens. Only requests admitted for forwarding trigger `Acquire`.
There is no idle/background refresh timer.

An upstream 401 runs one `UnauthorizedRecovery` and retries once. The client
API key and channel key do not rotate automatically.

Device login runs while the provider is stopped. It uses an advisory lock,
same-volume staging, and atomic installation, so cancellation leaves an
existing `auth.json` unchanged. The health check verifies process and private
credential-channel readiness only; it does not acquire OAuth credentials. An
authenticated Responses request is required to verify the Codex login.

## Operations

`down` removes the production pod and socket volume but preserves the client
and channel secrets plus the Codex auth volume. Use the following destructive
or maintenance commands while observing their required stopped-pod state:

```sh
# Replace only the internal channel key; pod must be down.
bash scripts/native-pod.sh rotate-agent-secret

# Remove client and channel secrets; pod must be down.
RESET_SECRETS=RESET bash scripts/native-pod.sh reset-secrets

# Remove the OAuth auth volume (and stop/remove the pod).
RESET_AUTH=RESET bash scripts/native-pod.sh reset-auth

# Show production pod logs.
bash scripts/native-pod.sh logs
```

`scripts/init-secrets` can receive the client key interactively, through
`PRAXIS_API_KEY`, through `PRAXIS_API_KEY_COMMAND`, or on standard input. For
example, a password manager can provide it without creating a project file:

```sh
PRAXIS_API_KEY_COMMAND='password-manager read praxis/api-key' bash scripts/init-secrets
```

Environment variables, command strings, and command substitution can be
visible to local tooling or process inspection. Choose the input method based
on the host's threat model; Podman secret storage is not claimed to encrypt the
key at rest.

## Development and synthetic testing

`just check` runs formatting, clippy, and locked workspace tests. `just
test-pod` builds a synthetic provider and mock upstream, then runs the native
Podman integration checks. It always uses hardwired local synthetic images;
it does not read production image overrides or OAuth credentials. Never put
real credentials in that test pod.

The test pod exposes loopback-only ports: Praxis on `127.0.0.1:18081`, mock
counters on `127.0.0.1:18082`, and the synthetic provider counter on
`127.0.0.1:19090`. It verifies client authentication, 401 recovery, finite and
SSE responses, secret isolation, socket mode/label, hardening, and that secrets
do not appear in pod logs.

```sh
just check
just test-pod
```

Podman 5.8 cannot use pre-existing native secrets from `podman kube play`
secret volumes. The scripts therefore create pods with `podman pod create` and
containers with `podman create --secret`.

## Pinned dependencies and publishing

Stock Praxis is pinned to
`ghcr.io/praxis-proxy/ai@sha256:ccd46f8772eebcbde2f41ad35c3234d23463b8314a5865083e32baf31eddd1a8`.
The Codex provider uses the official `codex-login` source at
`0dfb28edb9305fcae4ab006fb6b7b196cbdbac28`.

GitHub Actions builds both production Containerfiles for pull requests. Pushes
to `main` and manual dispatches from `main` publish the proxy and Codex-provider
GHCR images with `main` and immutable full-commit-SHA tags using `GITHUB_TOKEN`.
Both production Containerfiles set the OCI `org.opencontainers.image.source`
label to this repository.

## Advisories, extension, and provenance

`cargo-deny` keeps `RUSTSEC-2026-0118` and `RUSTSEC-2026-0119` as hard
deployment blockers. Known unmaintained transitive advisories remain documented
in `deny.toml` and the prior dependency review rather than being blanket-hidden.
Review the dependency graph before deployment.

Adding a provider requires an agent that implements the private protocol and a
registered profile/audience; the HTTP streaming and client-auth core remain
unchanged. Tailscale support, if added, is limited to tailnet-only Serve and
`svc:inference`: this project deliberately provides no Funnel, public bind, or
tailnet mutation.

The project and directly consumed Codex sources are Apache-2.0; see `NOTICE`
for provenance. This spike exceeds the roughly 500 substantial-line
design-review threshold. Independent security and design review is required
before production use.
