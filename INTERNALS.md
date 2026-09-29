# Internals

This document records implementation, security, operational, and development
details that are intentionally kept out of the [quick-start README](README.md).

## Architecture and trust boundaries

```text
client -> praxis-gateway -> credential-proxy -> fixed chatgpt.com Codex endpoint
                                ^
                                | private versioned Unix socket (credentials only)
                          provider-codex
```

`praxis-gateway` (`crates/praxis-gateway`) is Praxis AI built from its
released source as a library, with its full filter registry plus this
repository's own filters. Its configuration is `praxis.yaml`.

There are three credential classes:

1. In the default `required` client-auth mode, the client API key
   authenticates a local client to Praxis and must be at least 32 bytes. In
   explicit `disabled` mode it is neither read nor mounted.
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
no capabilities, and no privilege escalation. In required mode the proxy alone
receives the Podman client-key secret; Praxis receives neither secret. In
disabled mode no container receives that secret. The provider's
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
upstream Responses request is required to verify the Codex login.

## Client authentication modes

`PRAXIS_CLIENT_AUTH_MODE` is strictly either `required` (the default) or
`disabled` for `up`; unknown values stop that operation before a pod is
created. It does not affect cleanup or maintenance operations. The proxy
receives the corresponding `CLIENT_AUTH_MODE` and rejects unknown values at
startup. There is no opportunistic authentication mode: an absent client secret
in required mode is a startup failure, not a downgrade.

Required mode retains the >=32-byte Podman client secret, constant-time bearer
comparison, and 401 response. Disabled mode admits requests without an
`Authorization` header but always removes caller authorization before adding
the provider credential upstream. The internal HMAC channel secret and the
provider-only OAuth auth volume remain mandatory in both modes.

Disabled mode is appropriate only when an intentionally managed access-control
boundary, such as a tailnet/Tailscale policy, protects access. The current
runtime remains loopback-only and does not configure Tailscale. Changing modes
requires stopping the pod and recreating it with the selected mode. Running
`init-secrets` in disabled mode creates/replaces only the channel secret and
does not prompt for, remove, or otherwise modify an existing client secret.

## Metering and the window cap

Subscription inference has no per-token bill, so without a cap only a job's
timeout bounds what an agent spends, and in disabled mode so does every peer
that can reach the port. The gateway therefore meters every response and
caps use, in every mode, with praxis-ai's own filters:

- **Metering.** `token_count` reads each response's usage: the Responses
  API's top-level `usage` or the `response.completed` event of a stream,
  and the `message_start`/`message_delta` usage of Messages. It records the
  counts in the request's filter metadata. A `headers` filter drops
  `accept-encoding`, so responses stay readable.
- **Window cap.** `token_rate_limit` reserves a fixed 10k tokens per
  request, refuses a request with 429 when that would exceed 100M tokens in
  a sliding 5-hour window (the Codex usage-limit window), and reconciles the
  reservation with the counts `token_count` recorded. Each API has its own
  window, since each is a different subscription with a limit of its own.
  Its callers are indistinguishable, so one of them can use up a window and
  lock out the others until it slides. A reservation still open after
  `reservation_timeout` (30 minutes, longer than any one response) is
  charged its estimate for good, as is one whose client left before the
  usage arrived.

Both APIs share one chain, whose Responses and Messages filters are
conditioned on the path (`/v1/responses`, `/v1/messages`). Messages
requests go straight to api.anthropic.com with the caller's own Claude
OAuth token; credential-proxy, and so the client API key of required mode,
is only on the Responses path.

Windows live in the gateway's memory: restarting it resets them.

## Operations

`down` removes the production pod and socket volume but preserves the client
and channel secrets plus the Codex auth volume. Use the following destructive
or maintenance commands while observing their required stopped-pod state:

```sh
# Replace only the internal channel key; pod must be down.
bash scripts/native-pod.sh rotate-agent-secret

# Remove the client secret if present and the mandatory channel secret; pod must be down.
RESET_SECRETS=RESET bash scripts/native-pod.sh reset-secrets

# Remove the OAuth auth volume (and stop/remove the pod).
RESET_AUTH=RESET bash scripts/native-pod.sh reset-auth

# Show production pod logs.
bash scripts/native-pod.sh logs
```

In required mode, `scripts/init-secrets` can receive the client key interactively, through
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

`just check` runs formatting, clippy, and locked workspace tests. Those
include the gateway's integration tests, which serve `praxis.yaml` with the
gateway's registry in front of a fake upstream, and check that streamed
Responses and Messages responses are metered and capped per window. `just
test-pod` builds a synthetic provider and mock upstream, then runs the native
Podman integration checks. It always uses hardwired local synthetic images;
it does not read production image overrides or OAuth credentials. Never put
real credentials in that test pod.

The test pod exposes loopback-only ports: Praxis on `127.0.0.1:18081`, mock
counters on `127.0.0.1:18082`, and the synthetic provider counter on
`127.0.0.1:19090`. It verifies required client authentication, 401 recovery,
finite and SSE responses, secret isolation, socket mode/label, hardening, and
that secrets do not appear in pod logs. It then recreates the synthetic pod in
disabled mode and verifies a no-Authorization request succeeds with provider
credentials, no client-secret mount, and a separate caller Authorization value
is replaced with the provider credential. It also checks idempotent removal of
absent synthetic secrets.

Codex 0.154.0 accepted the disabled provider with no `env_key` and
`requires_openai_auth = false`, resolving its top-level named profile. OpenCode
1.18.30 with `@ai-sdk/openai` rejects a missing `apiKey` before sending a
request; use a non-secret placeholder such as `unused`, which the proxy strips.

```sh
just check
just test-pod
```

Podman 5.8 cannot use pre-existing native secrets from `podman kube play`
secret volumes. The scripts therefore create pods with `podman pod create` and
containers with `podman create --secret`.

## Pinned dependencies and publishing

The gateway builds praxis-ai from its `v0.4.1` tag (commit
`b9d6016764888e02dc049ec088496b10b7e886c1`, locked in `Cargo.lock`), with
the `openai-responses` and experimental `token-rate-limit-filter` features;
`Containerfile.gateway` builds it like upstream's image, on Alpine. The
Codex provider uses the official `codex-login` source at
`0dfb28edb9305fcae4ab006fb6b7b196cbdbac28`.

GitHub Actions builds the three production Containerfiles for pull requests.
Pushes to `main` and manual dispatches from `main` publish the proxy,
Codex-provider and gateway GHCR images with `main` and immutable
full-commit-SHA tags using `GITHUB_TOKEN`. The production Containerfiles set
the OCI `org.opencontainers.image.source` label to this repository.

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
