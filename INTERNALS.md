# Internals

This document records implementation, security, operational, and development
details that are intentionally kept out of the [quick-start README](README.md).

## Architecture and trust boundaries

```text
client -> Praxis (gateway image) -> credential-proxy -> fixed chatgpt.com Codex endpoint
                                       ^
                                       | private versioned Unix socket (credentials only)
                                 provider-codex
```

Praxis is the stock Praxis AI binary with this repository's routes baked into
the image; the optional Anthropic routes on the same listener are described
[below](#anthropic-messages-gateway).

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
receives the Podman client-key secret; Praxis receives neither secret, only
the Claude token when the Anthropic gateway is enabled. In
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
plain stock Praxis configuration, with no broker code involved, served by the
same Praxis listener as Responses and selected by path prefix:

```text
Codex client        -> /v1/responses       -> credential-proxy -> chatgpt.com
Claude Code         -> /anthropic/v1/...   -> api.anthropic.com (broker's token)
  (placeholder)
Claude Code         -> /v1/messages        -> api.anthropic.com (client's own OAuth)
  (own login)
```

### Gateway image and route table

`Containerfile.gateway` builds `ghcr.io/cgwalters-bot/praxis-credential-broker-gateway`
from the pinned stock Praxis image with `praxis.yaml`, `praxis-anthropic.yaml`
and `scripts/praxis-gateway-entrypoint` baked in, so a deployment needs the
image, its secrets and a published port, and nothing from a checkout. The
entrypoint runs `praxis.yaml` by default, or `praxis-anthropic.yaml` when
`PRAXIS_ANTHROPIC_GATEWAY=enabled`, and refuses any other value. Both listen
on pod port 8081, published as `127.0.0.1:18080`:

| Path | Method | Cluster | Upstream credential |
|------|--------|---------|---------------------|
| `/healthz`, `/v1/responses` (prefix) | any | `inference-backend` | Codex, added by credential-proxy |
| `/anthropic/v1/messages`, `/anthropic/v1/messages/count_tokens` (exact) | `POST` | `anthropic` | the broker's Claude token |
| `/v1/messages` (exact) | any | `anthropic-client-oauth` | the client's own, passed through |

The last two rows exist only with the gateway enabled; otherwise those paths
get 404. Upstream, `/anthropic/v1/...` is rewritten to `/v1/...` and the
query string is kept, so Claude Code uses
`ANTHROPIC_BASE_URL=http://host:18080/anthropic` and appends `/v1/messages`
itself. The `/v1/messages` route takes over the separate client-OAuth
listener that Xenon used to serve on port 18083; a host can keep that port by
publishing it to 8081 too.

### One process, two credential paths

Before, the Claude token lived in a Praxis container of its own, so a bug in
the Responses path could not reach it. Now the one Praxis process that
serves `/v1/responses` also has the token in its environment. The Codex
OAuth tokens are still in the provider, which only credential-proxy talks to,
so Praxis never holds them. What keeps the credentials apart is the
configuration, not a process boundary:

- `credential_injection` adds the token only for the `anthropic` cluster, and
  only the two exact `/anthropic` routes select it. The client-OAuth route has
  its own cluster, `anthropic-client-oauth`, for exactly this reason: sharing
  a cluster name would inject the token into it.
- `inference-backend` is `127.0.0.1:8080`, credential-proxy, which takes the
  Codex credential from the provider. Nothing on an Anthropic route reaches it.
- Every filter that acts on only one route is conditioned on that route's raw
  path, the same path the router matches.

The trade-off is a smaller blast radius for one deployment unit and one port.
If that matters more than the single port, run a second gateway container
from the same image with only `PRAXIS_ANTHROPIC_GATEWAY=enabled` and publish
it alone.

### Token handling

`scripts/init-anthropic-token` stores the token as the Podman secret
`praxis-credential-broker-anthropic-oauth`. It reads only from the terminal
(without echo) or standard input, checks the `sk-ant-oat01-` shape, never
prints the input, and stores it without a trailing newline because Praxis
injects the value verbatim. Only the Praxis container mounts the secret,
as a 0400 file, and only when the gateway is enabled. Core
`credential_injection` reads credentials only from environment variables, so
`scripts/praxis-gateway-entrypoint` exports it as
`PRAXIS_ANTHROPIC_OAUTH_TOKEN` and execs Praxis. Podman's `type=env` secrets
would need no shim, but Podman 4 shows their values in `podman inspect`. The
token is therefore in neither the container configuration nor any command
line, and the tests check that it is in neither `podman inspect` nor the
logs. It is in the Praxis process's environment, readable through `/proc`
by the same UID inside that container and by the host user that owns the
pod. With the gateway enabled and no secret, the container exits at startup
rather than serve.

Setup tokens are long-lived and are not refreshed: there is no
`UnauthorizedRecovery` equivalent. When one expires or is revoked, Claude Code
sees the upstream 401; store a new one with `init-anthropic-token` and
recreate the pod. `reset-secrets` removes this secret along with the others.

### Placeholder semantics and filter order

Clients send `Authorization: Bearer praxis-substitute:anthropic`. The
comparison is an exact, case-sensitive match of the whole header value:
`bearer`, an extra space, a different name, or a prefix or suffix are all
refused. HTTP/1.1 parsing trims leading and trailing whitespace, so those
variants are accepted there (HTTP/2, which the listener also speaks with
prior knowledge, refuses them). Only `POST` is forwarded, so no other method
(such as `TRACE`, which an upstream might echo) carries the token. Praxis
compares methods without regard to case, so `post` or `PoSt` is forwarded
too, as is, to the same fixed upstream; `trace` is still refused. Only `Authorization` counts;
a placeholder in `x-api-key` alone is refused. With duplicate `Authorization`
headers, Praxis matches the first one, so another value first is refused, and
placeholder-first is forwarded with every client copy removed.

The order of the chain in `praxis-anthropic.yaml` and its conditions are
security-critical, because conditions and router matches see the request as
it is when each filter runs, and all of them see the raw path:

1. `static_response` answers 403 for anything under `/anthropic` unless it is
   a `POST` and `Authorization` is exactly the placeholder. It must come
   before every other request filter: without it, a request that matched no
   credential would be forwarded with the client's own headers.
2. `static_response` answers 403 for the exact placeholder anywhere outside
   `/anthropic`, so a correctly configured client that points at the wrong
   path is refused rather than forwarded to credential-proxy or as a client
   OAuth token. This also covers spellings that skip step 1, such as
   `//anthropic/...`, `/ANTHROPIC/...` or `/anthropic%2f...`. Variants of
   the placeholder, such as `bearer praxis-substitute:anthropic`, are not
   matched there and are forwarded like any other client value; they are
   public and worthless upstream.
3. The Responses filter runs everywhere except the Anthropic paths, and the
   Messages validation filters only on `/v1/messages`. Their presence makes
   Praxis read every request body in full, on every path, before it runs any
   request filter, including steps 1 and 2; that is also why a malformed body
   on `/v1/messages` gets its 400 before any 403. No filter looks at an
   `/anthropic` body. The read is capped by `body_limits.max_request_bytes`,
   set to 32 MiB, the Messages API's own limit (larger requests get 413);
   Praxis's default of 10 MiB would refuse large Claude Code requests with
   images or PDFs. With the gateway enabled this also raises the cap on
   `/v1/responses` from 10 MiB, and anyone who can reach the port can make
   Praxis buffer that much per request before it is refused.
4. `router` routes the paths in the table above. The `/anthropic` routes also
   match the placeholder, so the upstream and credential are bound to it and
   the client cannot choose either. Other paths get Praxis's 404 and are not
   forwarded. The Anthropic routes must stay exact: Praxis forwards paths
   without normalizing them and api.anthropic.com resolves `..`, so with a
   prefix such as `/anthropic/v1/`, a request for
   `/anthropic/v1/../api/oauth/...` would spend the token on account
   endpoints.
5. `path_rewrite` strips `/anthropic`. It runs after the router, so the
   router still sees the prefix and `/anthropic/v1/messages` cannot collide
   with the client-OAuth `/v1/messages` route.
6. `headers` removes every `authorization` and `x-api-key`, sets `Host` to
   `api.anthropic.com`, and appends `oauth-2025-04-20` to `anthropic-beta`
   (`request_add` joins it to the client's betas rather than replacing
   them), for `/anthropic` only. A second `headers` filter, for
   `/v1/messages` only, removes `x-api-key` and sets `Host`, and leaves the
   client's `Authorization` alone.
7. `credential_injection` adds `Authorization: Bearer <token>` for the
   `anthropic` cluster.
8. `load_balancer` connects to `api.anthropic.com:443` with TLS and SNI, or to
   credential-proxy.

The 403 bodies are fixed JSON in the Messages error shape and carry neither
the token nor the beta. A client can name `Authorization`, `Host` or
`anthropic-beta` in `Connection`, which makes Praxis drop the injected value
as hop-by-hop. That fails closed: the request goes upstream without it.

### Paths are matched, not normalized

Praxis 0.5.4 has no `path_sanitize` filter to configure. Its path
sanitization is a helper that `path_rewrite` and `url_rewrite` apply to the
path they produce, which resolves `..`, `.`, `%2e%2e` and `//` (Praxis also
refuses to send a rewritten path that still contains `..`, which that
normalization already rules out). That cannot replace exact routes. Normalizing is the wrong defense here: the router could
be made to see a normalized path, but conditions always see the raw request
path, so a filter conditioned on `/anthropic` and a router matching the
normalized path would disagree about `/v1/../anthropic/v1/messages`. And
after a rewrite it makes traversal worse rather than better: with a prefix
route, `/anthropic/v1/messages/../../api/oauth/profile` would be rewritten
and normalized to `/api/oauth/profile` and sent with the token. So
everything here matches the raw path, the Anthropic routes are exact, and any
path that is not literally one of them, including every encoded or doubled
spelling, gets 403 or 404 without reaching an upstream.

A traversal that starts under `/v1/responses`, such as
`/v1/responses/../../anthropic/v1/messages` without the placeholder, matches
the Responses prefix route and goes to credential-proxy, as it did before
this listener served Anthropic. credential-proxy serves only the exact path
`/v1/responses` and its upstream URL is fixed, so it is refused there and
never reaches an Anthropic upstream.

Praxis is reloaded when its config file changes; the configuration in the
image changes only with a new image.

`tests/gateway.py` checks the chain's order and runs every case above,
including the cross-prefix and traversal ones, against fake upstreams; run it
after any change to `praxis-anthropic.yaml`, `praxis.yaml` or the Praxis pin.

### Client authentication

The placeholder is not authentication. It is public configuration, and
anyone who can reach the listener can spend the subscription.
`PRAXIS_CLIENT_AUTH_MODE` applies only to `/v1/responses`, whose
client key is checked by `credential-proxy`; the client-OAuth `/v1/messages`
route has no client authentication of its own either. Stock Praxis cannot
also require that key on `/anthropic`: `basic_auth` takes over `Authorization`, which carries the
placeholder, and a header match on a key would mean writing the key into the
Praxis configuration and comparing it in non-constant time. So the Anthropic
routes rely on the network boundary, like `disabled` mode: loopback-only by
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
- **The client key does not cover these routes.** With the gateway enabled,
  `/anthropic` and `/v1/messages` are served on the same port as
  `/v1/responses` without the client key, even in `required` mode. Before,
  they had a port of their own that could stay unpublished. Publishing
  18080 beyond loopback, as in the tailnet drop-in below, therefore exposes
  subscription spend to everything that can reach it; restrict it with the
  tailnet policy, or run a second gateway container with only the Anthropic
  routes and keep it on loopback.
- **The token holder follows a mutable tag.** The Quadlet units run
  `...-gateway:main` with `AutoUpdate=registry`, so whoever can push `:main`
  to this repository's GHCR packages controls the process that holds the
  token. Pin the gateway to a digest in a drop-in (which opts it out of
  auto-update) if that is not acceptable.

## Operations

### Quadlet

`contrib/quadlet/` has rootless Quadlet units for the same pod, with the same
pod, container, volume and secret names as `native-pod.sh up`, so they reuse
an existing Codex login and secrets. They run only published images and
mount nothing from a checkout. As committed they publish `127.0.0.1:18080`,
require client authentication, and leave the Anthropic gateway disabled.
Host-specific settings go in drop-ins next to them, which Quadlet merges; an
empty `Secret=` clears the list (Podman 5). For example, to enable the
gateway:

```ini
# ~/.config/containers/systemd/praxis-credential-broker-praxis.container.d/anthropic.conf
[Container]
Environment=PRAXIS_ANTHROPIC_GATEWAY=enabled
Secret=praxis-credential-broker-anthropic-oauth,target=/run/secrets/anthropic/oauth-token,uid=65532,gid=65532,mode=0400
```

to rely on a tailnet instead of the client key:

```ini
# praxis-credential-broker-proxy.container.d/client-auth-disabled.conf
[Container]
Environment=CLIENT_AUTH_MODE=disabled
Secret=
Secret=praxis-credential-broker-agent-channel,target=/run/secrets/channel/agent-channel-key,uid=65532,gid=65532,mode=0400
```

and to publish on the host's tailnet address as well, checked before the
pod binds it (use the address itself; these run on the host). With the
Anthropic gateway enabled this exposes the subscription to every peer that
can reach the port, whatever the client-auth mode; see the risks above:

```ini
# praxis-credential-broker.pod.d/tailnet.conf
[Pod]
PublishPort=100.64.0.1:18080:8081

[Service]
ExecStartPre=/usr/bin/tailscale wait --timeout=30s
ExecStartPre=/usr/bin/tailscale ip --4 --assert=100.64.0.1
```

Install by linking the units into `~/.config/containers/systemd/`, check
them with `QUADLET_UNIT_DIRS=~/.config/containers/systemd
/usr/libexec/podman/quadlet -dryrun -user`, then `systemctl --user
daemon-reload` and `systemctl --user start praxis-credential-broker-pod.service`.
Do not `systemctl enable` the generated service; `[Install]` attaches it to
`default.target`, and `loginctl enable-linger` keeps it running without a
login.

Every container has `AutoUpdate=registry`, so a deployment after a merge to
`main` is `podman auto-update` (or `podman pull` and `systemctl --user
restart praxis-credential-broker-pod.service`). Each unit names its image on
one `Image=` line. To pin a release tag or digest instead of `:main`, override
that line in a drop-in, such as `Image=ghcr.io/cgwalters-bot/praxis-credential-broker-gateway:<tag>`.
`podman auto-update` follows tags only, so a digest pin opts that container
out of it.

### Scripts

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

`just test-gateway` runs `tests/gateway.py`, which CI also runs. It builds
the gateway image and runs it with each baked-in configuration replaced by a
copy in which only the listener address and the upstream endpoints are
rewritten, each cluster to an in-process fake upstream of its own, with a
synthetic token in a Podman secret. It checks every placeholder case under
`/anthropic`, Responses and client-OAuth requests on the same listener, the
cross-prefix and traversal cases, which upstream each request reached and
with which credential, header stripping, Host and beta handling,
byte-identical bodies, unbuffered SSE, that the token is in neither the logs
nor `podman inspect`, that the container refuses to start without the token
or with an unknown mode, and that with the gateway disabled only Responses
is served. It needs rootless Podman with host networking.

`just test-pod` runs its first, required-mode pass with the Anthropic gateway
enabled, so the Responses checks also cover `praxis-anthropic.yaml`, and its
second, disabled-mode pass with `praxis.yaml`.

```sh
just check
just test-gateway
just test-pod
```

Podman 5.8 cannot use pre-existing native secrets from `podman kube play`
secret volumes. The scripts therefore create pods with `podman pod create` and
containers with `podman create --secret`.

## Pinned dependencies and publishing

Stock Praxis, the base of the gateway image, is pinned in `Containerfile.gateway` to
`ghcr.io/praxis-proxy/ai@sha256:ccd46f8772eebcbde2f41ad35c3234d23463b8314a5865083e32baf31eddd1a8`.
The Codex provider uses the official `codex-login` source at
`0dfb28edb9305fcae4ab006fb6b7b196cbdbac28`.

GitHub Actions builds the three production Containerfiles for pull requests.
Pushes to `main` and manual dispatches from `main` publish the proxy,
Codex-provider and gateway GHCR images with `main` and immutable
full-commit-SHA tags using `GITHUB_TOKEN`. There are no release tags yet;
deployments follow `:main`. All production Containerfiles set the OCI
`org.opencontainers.image.source` label to this repository.

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
