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

## Anthropic Messages gateway

The optional Anthropic gateway (`PRAXIS_ANTHROPIC_GATEWAY=enabled`, strictly
`enabled` or `disabled`, default `disabled`) serves Claude Code in gateway
mode with a Claude subscription OAuth token from `claude setup-token`. It is
plain stock Praxis configuration, with no broker code involved:

```text
Claude Code (placeholder) -> stock Praxis (praxis-anthropic.yaml) -> api.anthropic.com
                               ^ token in this container's environment only
```

It runs as its own container, `praxis-credential-broker-anthropic`, from the
same pinned Praxis image, listening on 8090 in the pod and published on
`127.0.0.1:18090`. A separate container keeps the token out of the
Responses Praxis and leaves `praxis.yaml` alone. It has the same hardening as
the other containers.

### Token handling

`scripts/init-anthropic-token` stores the token as the Podman secret
`praxis-credential-broker-anthropic-oauth`. It reads only from the terminal
(without echo) or standard input, checks the `sk-ant-oat01-` shape, never
prints the input, and stores it without a trailing newline because Praxis
injects the value verbatim. Only the gateway container mounts the secret,
as a 0400 file. Core `credential_injection` reads credentials only from
environment variables, so `scripts/praxis-anthropic-entrypoint`, mounted
read-only into the stock image, exports it as `PRAXIS_ANTHROPIC_OAUTH_TOKEN`
and execs Praxis. Podman's `type=env` secrets would need no shim, but Podman 4
shows their values in `podman inspect`. The token is therefore in neither the
container configuration nor any command line, and the test checks that it is
in neither `podman inspect` nor Praxis's logs. It is in the gateway process's
environment, readable through `/proc` by the same UID inside that container
and by the host user that owns the pod. Without the secret, the container
exits at startup rather than forward anything.

Setup tokens are long-lived and are not refreshed: there is no
`UnauthorizedRecovery` equivalent. When one expires or is revoked, Claude Code
sees the upstream 401; store a new one with `init-anthropic-token` and
recreate the pod. `reset-secrets` removes this secret along with the others.

### Placeholder semantics and filter order

Clients send `Authorization: Bearer praxis-substitute:anthropic`. The
comparison is an exact, case-sensitive match of the whole header value:
`bearer`, an extra space, a different name, or a prefix or suffix are all
refused. HTTP parsing trims leading and trailing whitespace, so those variants
are accepted. Only `POST` is forwarded, so no other method (such as `TRACE`,
which an upstream might echo) carries the token. Only `Authorization` counts;
a placeholder in `x-api-key` alone is refused. With duplicate `Authorization`
headers, Praxis matches the first one, so another value first is refused, and
placeholder-first is forwarded with every client copy removed.

The order of the chain is security-critical, because conditions and router
header matches see the request as it is when each filter runs:

1. `static_response` answers 403 unless the request is a `POST` and
   `Authorization` is exactly the placeholder. It must come first: without
   it, a request that matched no credential would be forwarded with the
   client's own headers.
2. `router` routes only the exact paths `/v1/messages` and
   `/v1/messages/count_tokens` (any query string) with the placeholder, so
   the upstream and credential are bound to it and the client cannot choose
   either. Other paths get Praxis's 404 and are not forwarded. They must
   stay exact: Praxis forwards paths without normalizing them and
   api.anthropic.com resolves `..`, so with a prefix such as `/v1/`, a
   request for `/v1/../api/oauth/...` would spend the token on account
   endpoints.
3. `headers` removes every `authorization` and `x-api-key`, sets `Host` to
   `api.anthropic.com`, and appends `oauth-2025-04-20` to `anthropic-beta`
   (`request_add` joins it to the client's betas rather than replacing them).
4. `credential_injection` adds `Authorization: Bearer <token>`.
5. `load_balancer` connects to `api.anthropic.com:443` with TLS and SNI.

The 403 body is fixed JSON in the Messages error shape and carries neither
the token nor the beta. A client can name `Authorization`, `Host` or
`anthropic-beta` in `Connection`, which makes Praxis drop the injected value
as hop-by-hop. That fails closed: the request goes upstream without it.
Praxis is reloaded when the mounted config changes, so editing
`praxis-anthropic.yaml` in place changes the live policy.

`tests/anthropic_gateway.py` checks the chain's order and runs every case
above against a fake upstream; run it after any change to
`praxis-anthropic.yaml` or the Praxis pin.

### Client authentication

The placeholder is not authentication. It is public configuration, and
anyone who can reach the listener can spend the subscription.
`PRAXIS_CLIENT_AUTH_MODE` applies only to the Responses listener, whose
client key is checked by `credential-proxy`. Stock Praxis cannot also require
that key here: `basic_auth` takes over `Authorization`, which carries the
placeholder, and a header match on a key would mean writing the key into the
Praxis configuration and comparing it in non-constant time. So this listener
relies on the network boundary, like `disabled` mode: loopback-only by
default, and an intentionally managed boundary such as a tailnet policy, or
per-UID egress rules for a sandbox, if exposed further. Per-run client
authentication is better added as a filter in front of the chain that reads
its own header (for example `x-run-token`), leaving `Authorization` to the
placeholder.

### Risks

- **Undocumented behavior.** Anthropic documents gateways for API keys, and
  subscription use through a gateway only when the client holds the login.
  Injecting a subscription OAuth token at the gateway with the
  `oauth-2025-04-20` beta is undocumented and may stop working, for example
  if the beta is enforced differently. Make sure your use fits the
  subscription's terms.
- **Claude Code in gateway mode behaves differently.** Background tasks use
  the main model instead of Haiku, so they count against its limits, and the
  fast-mode and WebFetch safety checks bypass `ANTHROPIC_BASE_URL` and go to
  Anthropic directly. In a sandbox without egress those checks fail and the
  features degrade. Pin the Claude Code version and rerun a real request when
  upgrading, since the beta set changes between releases.
- **Client headers in logs.** On a malformed request Praxis logs the raw
  request bytes at error level, including the client's own `Authorization`.
  That is the placeholder for a correct client, never the broker's token,
  but a client that wrongly sends a real key that way would put it in the
  pod logs.
- **Shared spend.** All clients share the one subscription's rate limits, and
  there is no metering or cap in this chain.

## Operations

`down` removes the production pod and socket volume but preserves the client
and channel secrets plus the Codex auth volume. Use the following destructive
or maintenance commands while observing their required stopped-pod state:

```sh
# Replace only the internal channel key; pod must be down.
bash scripts/native-pod.sh rotate-agent-secret

# Remove the client, channel and Anthropic token secrets if present; pod must be down.
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

`just check` runs formatting, clippy, and locked workspace tests. `just
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

`just test-anthropic` runs `tests/anthropic_gateway.py`, which CI also runs.
It starts the pinned Praxis image (read from `scripts/native-pod.sh`) with
`praxis-anthropic.yaml`, rewriting only the listener address and the upstream
endpoint, which points at an in-process fake Anthropic upstream. It uses the
pod's entrypoint and a synthetic token in a Podman secret. It checks every
placeholder case, header stripping, Host and beta handling, byte-identical
bodies, unbuffered SSE, that denied requests never reach upstream, that the
token is in neither the logs nor `podman inspect`, and that the container
refuses to start without the token. It needs rootless Podman with host
networking.

```sh
just check
just test-anthropic
just test-pod
```

Podman 5.8 cannot use pre-existing native secrets from `podman kube play`
secret volumes. The scripts therefore create pods with `podman pod create` and
containers with `podman create --secret`.

## Pinned dependencies and publishing

Stock Praxis, for both the Responses and the Anthropic containers, is pinned to
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
