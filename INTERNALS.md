# Internals

This document records implementation, security, operational, and development
details that are intentionally kept out of the [quick-start README](README.md).

## Architecture and trust boundaries

```text
                                   +-> credential-proxy -> fixed chatgpt.com Codex endpoint
                                   |        ^
client -> Praxis (gateway image) --+        | private versioned Unix socket (credentials only)
          :18080, one listener     |   provider-codex
                                   |
                                   +---------------------> fixed api.anthropic.com Messages endpoint
```

Praxis is `praxis-gateway` (`crates/praxis-gateway`): Praxis AI built from
source as a library, with its full filter registry plus this repository's
one filter, `run_token`, and with this repository's routes (`praxis.yaml`)
baked into the image. It serves everything on one listener, pod port 8081,
published as `127.0.0.1:18080`:

| Path | Method | Cluster | Credential mode | Upstream credential |
|------|--------|---------|-----------------|---------------------|
| `/v1/responses` (prefix) | `POST` | `inference-backend` | injected | Codex, added by credential-proxy |
| `/healthz` (exact) | any | `inference-backend` | none needed | none |
| `/anthropic/v1/messages`, `/anthropic/v1/messages/count_tokens` (exact), with the placeholder | `POST` | `anthropic` | injected | the broker's Claude token |
| the same paths, with any other `Authorization` | `POST` | `anthropic-pass-through` | pass-through | the caller's own |
| `/v1/runs` (prefix) | see [run tokens](#run-tokens) | answered by `run_token` | | |
| `/usage` (exact) | `GET` | answered locally by `run_token` | none needed | none |

Any other path gets 404. Upstream, `/anthropic/v1/...` is rewritten to
`/v1/...` and the query string is kept, so Claude Code uses
`ANTHROPIC_BASE_URL=http://host:18080/anthropic` and appends `/v1/messages`
itself.

There are these credentials:

1. **Run tokens** authenticate a CI run's requests to Praxis. A job's
   supervisor gets one by registering its run with the job's GitHub Actions
   OIDC token; see [run tokens](#run-tokens). Every injected request needs
   one.
2. The internal **channel key** is a generated HMAC secret between the proxy
   and provider; it is not a client credential.
3. Provider-owned **ChatGPT Codex OAuth tokens** live in the provider's auth
   volume after device login.
4. The broker's **Claude subscription token**, from `claude setup-token`, is a
   Podman secret that only the Praxis container mounts; see
   [token handling](#token-handling).
5. A pass-through caller's **own Claude credential** passes transiently
   through Praxis to Anthropic and is neither stored nor refreshed by the
   pod.

The proxy has no Codex SDK, OAuth state, or writable credential volume. The
provider exclusively owns `CODEX_HOME`. OAuth headers pass transiently through
the proxy while it constructs an upstream request; auth state remains
provider-owned.

The proxy accepts only `POST /v1/responses`, strips caller authorization,
cookies, account, hop-by-hop, and proxy headers, and forwards to a fixed HTTPS
endpoint. The client cannot choose a URL, authority, or provider profile. It
runs with `CLIENT_AUTH_MODE=disabled`: Praxis has already authenticated the
run, and the proxy listens only on the pod's loopback, where only Praxis
connects; the pod publishes only Praxis's port. Its `required` mode, a static client API key,
is no longer used by the scripts or the Quadlet units: the key would sit in
`Authorization`, where Codex sends the run token.

### Private protocol and hardening

`credential-protocol` version 1 is newline-delimited JSON, bounded to 16 KiB
for reads and writes. `Ping`, `Acquire`, and `UnauthorizedRecovery` are
authenticated with nonce/HMAC and a channel secret of at least 32 bytes. This
is a private, pod-local protocol, not a general credential API; its protection
depends on the Podman deployment and its shared secret.

The socket is in the private named volume
`praxis-credential-broker-socket`, is mode 0660, and is shared only by proxy
and provider. All images run as UID/GID 65532 with read-only root
filesystems, no capabilities, and no privilege escalation. Praxis receives
only the Claude token secret and the run registration policy, which holds no
secrets. The provider's separate writable auth volume is mounted only at
`/codex-home`.

Finite and SSE streams have idle, byte, and concurrency limits. `/healthz`
uses a side-effect-free `Ping` and returns only `ready` or `not ready`.

## OAuth lifecycle and startup

The provider uses pinned `codex-login` with
`AuthCredentialsStoreMode::File` in its auth volume. Every request admitted
for upstream forwarding performs `Acquire`; `AuthManager::auth` refreshes
managed ChatGPT authentication when needed and persists rotated access and
refresh tokens. Only requests admitted for forwarding trigger `Acquire`.
There is no idle/background refresh timer.

An upstream 401 runs one `UnauthorizedRecovery` and retries once. The
channel key does not rotate automatically.

Device login runs while the provider is stopped. It uses an advisory lock,
same-volume staging, and atomic installation, so cancellation leaves an
existing `auth.json` unchanged. The health check verifies process and private
credential-channel readiness only; it does not acquire OAuth credentials. An
upstream request is required to verify either login.

## Credential modes

`run_token` runs right after the router, and its `credentials` setting
gives the mode of every cluster the router may pick, keyed on the cluster
like `credential_injection` is. So one choice, the router's, decides both
whether a request needs a run token and whose credential goes upstream; a
cluster with no mode is refused with 500.

- **injected** (`inference-backend`, `anthropic`): the request must carry the
  token of an active registered run. The broker's credential goes upstream:
  credential-proxy adds the Codex one, and `credential_injection` adds the
  Claude one for the `anthropic` cluster only. Injected requests are capped
  per run and per window (see [metering and caps](#metering-and-caps)),
  except `count_tokens`, which uses no tokens: `run_token` admits it for the
  run (`usage_free_paths`) but charges it nothing. So a run can call it
  without a cap, as fast as its concurrency allows, on the broker's Claude
  token; that can use up the account's request rate limit for every other
  run. This is accepted for now: a request-rate limit keyed on the run would
  close it.
- **pass-through** (`anthropic-pass-through`): no run token is needed or looked
  for, and the caller's `Authorization` goes upstream unchanged. A caller's
  run token in `x-run-token` is removed, and a run token as the bearer token
  in `Authorization` is refused with 400 rather than sent to Anthropic.
  Pass-through requests are metered but not capped: they spend the
  caller's own subscription.

The two Messages paths have one route per mode. The more specific route,
which also matches `Authorization: Bearer praxis-substitute:anthropic`,
selects `anthropic`; any other `Authorization`, or none, selects
`anthropic-pass-through`. That cluster exists so that the token can never be
injected there: `credential_injection` is keyed by cluster.

### Placeholder semantics and filter order

The placeholder comparison is an exact, case-sensitive match of the whole
header value: `bearer`, an extra space, a different name, or a prefix or
suffix all select pass-through, and are forwarded as the caller's own
credential (they are public and worthless upstream). HTTP/1.1 parsing trims
leading and trailing whitespace, so those variants select the placeholder
there (HTTP/2, which the listener also speaks with prior knowledge, does
not). Only `Authorization` counts; a placeholder in `x-api-key` alone is
pass-through, and `x-api-key` is removed on both Anthropic routes. A request
with more than one `Authorization` header is refused with 400 by
`run_token`, because the router matches a header against any of its values
and conditions against the first one, and the two must agree about the mode.

The order of the chain in `praxis.yaml` and its conditions are
security-critical, because conditions and router matches see the request as
it is when each filter runs, and all of them see the raw path:

1. `static_response` answers 403 for anything under `/anthropic` that is not
   a `POST`, so no other method (such as `TRACE`, which an upstream might
   echo) is forwarded with a credential. Praxis compares methods without
   regard to case, so `post` or `PoSt` is forwarded too, as is, to the same
   fixed upstream; `trace` is still refused. Another one answers 405 for
   anything but a `POST` under `/v1/responses`, which credential-proxy
   would refuse anyway, so that every injected request the caps let through
   is one they count, `count_tokens` aside.
2. `static_response` answers 403 for the exact placeholder anywhere outside
   `/anthropic`, so a correctly configured client that points at the wrong
   path is refused rather than forwarded to credential-proxy. This also
   covers spellings that skip step 1, such as `//anthropic/...`,
   `/ANTHROPIC/...` or `/anthropic%2f...`.
3. The Responses filter runs on `/v1/responses`, and the Messages validation
   filters on `/anthropic/v1/messages`. Their presence makes Praxis read
   every request body in full, on every path, before it runs any request
   filter, including steps 1 and 2; that is also why a malformed Messages
   body gets its 400 before any 403. The read is capped by
   `body_limits.max_request_bytes`, set to 32 MiB, the Messages API's own
   limit (larger requests get 413); Praxis's default of 10 MiB would refuse
   large Claude Code requests with images or PDFs. Anyone who can reach the
   port can make Praxis buffer that much per request before it is refused.
4. `router` routes the paths in the table above. Other paths get Praxis's
   404 and are not forwarded. The Anthropic routes must stay exact: Praxis
   forwards paths without normalizing them and api.anthropic.com resolves
   `..`, so with a prefix such as `/anthropic/v1/`, a request for
   `/anthropic/v1/../api/oauth/...` would spend the token on account
   endpoints.
5. `run_token` answers `/v1/runs` and `/usage`, refuses duplicate `Authorization`
   headers, applies the cluster's credential mode, and removes the run token
   headers (`x-run-token`, and `Authorization` unless the mode is
   pass-through).
6. `token_rate_limit`, four instances: the per-run caps and the windows, for
   injected requests of each API. Then `token_count`, one per API, for both
   modes. Response filters run in reverse order, so each `token_rate_limit`
   comes before the `token_count` whose counts it reconciles with, and
   `run_token` before them all, so it sees the counts last.
7. `path_rewrite` strips `/anthropic`. It runs after the router, so the
   router still sees the prefix.
8. `headers` removes `accept-encoding` everywhere, so `token_count` can read
   responses. For injected Messages, another `headers` filter removes every
   `authorization` and `x-api-key`, sets `Host` to `api.anthropic.com`, and
   appends `oauth-2025-04-20` to `anthropic-beta` (`request_add` joins it
   to the client's betas rather than replacing them). For pass-through
   Messages, a third removes `x-api-key` and sets `Host`, and leaves the
   caller's `Authorization` alone. Both are conditioned on the placeholder,
   the same match the router made.
9. `credential_injection` adds `Authorization: Bearer <token>` for the
   `anthropic` cluster.
10. `load_balancer` connects to `api.anthropic.com:443` with TLS and SNI, or
    to credential-proxy. The `run-endpoints` cluster, which only exists so
    that the router routes `/v1/runs` and `/usage` to `run_token`, is never connected
    to.

The 403 bodies are fixed JSON in the Messages error shape and carry neither
the token nor the beta. A client can name `Authorization`, `Host` or
`anthropic-beta` in `Connection`, which makes Praxis drop the injected value
as hop-by-hop. That fails closed: the request goes upstream without it.

### Paths are matched, not normalized

Praxis has no `path_sanitize` filter to configure. Its path sanitization is
a helper that `path_rewrite` and `url_rewrite` apply to the path they
produce, which resolves `..`, `.`, `%2e%2e` and `//` (Praxis also refuses to
send a rewritten path that still contains `..`, which that normalization
already rules out). That cannot replace exact routes. Normalizing is the
wrong defense here: the router could be made to see a normalized path, but
conditions always see the raw request path, so a filter conditioned on
`/anthropic` and a router matching the normalized path would disagree about
`/v1/../anthropic/v1/messages`. And after a rewrite it makes traversal worse
rather than better: with a prefix route,
`/anthropic/v1/messages/../../api/oauth/profile` would be rewritten and
normalized to `/api/oauth/profile` and sent with the token. So everything
here matches the raw path, the Anthropic routes are exact, and any path that
is not literally one of them, including every encoded or doubled spelling,
gets 403 or 404 without reaching an upstream, in either mode.

A traversal that starts under `/v1/responses`, such as
`/v1/responses/../../anthropic/v1/messages`, matches the Responses prefix
route: it needs a run token, and goes to credential-proxy, which serves only
the exact path `/v1/responses` and whose upstream URL is fixed, so it is
refused there and never reaches an Anthropic upstream.

`tests/gateway.py` checks the chain's order and runs every case above,
including the cross-prefix and traversal ones, against fake upstreams; run it
after any change to `praxis.yaml` or the Praxis pins.

### One process, two credential paths

The one Praxis process that serves `/v1/responses` also has the Claude token
in its environment. The Codex OAuth tokens are still in the provider, which
only credential-proxy talks to, so Praxis never holds them. What keeps the
credentials apart is the configuration, not a process boundary:

- `credential_injection` adds the token only for the `anthropic` cluster, and
  only the two exact `/anthropic` routes with the placeholder select it.
- `inference-backend` is `127.0.0.1:8080`, credential-proxy, which takes the
  Codex credential from the provider. Nothing on an Anthropic route reaches
  it.
- Every filter that acts on only one route is conditioned on that route's raw
  path, and on the placeholder where it acts on one mode only.

If that matters more than the single port, run a second gateway container
from the same image and publish only its `/anthropic` routes.

### Token handling

`scripts/init-anthropic-token` stores the token as the Podman secret
`praxis-credential-broker-anthropic-oauth`. It reads only from the terminal
(without echo) or standard input, checks the `sk-ant-oat01-` shape, never
prints the input, and stores it without a trailing newline because Praxis
injects the value verbatim. Only the Praxis container mounts the secret, as a
0400 file. Core `credential_injection` reads credentials only from
environment variables, so `scripts/praxis-gateway-entrypoint` exports it as
`PRAXIS_ANTHROPIC_OAUTH_TOKEN` and execs Praxis. Podman's `type=env`
secrets would need no shim, but Podman 4 shows their values in `podman
inspect`. The token is therefore in neither the container configuration nor
any command line, and the tests check that it is in neither `podman inspect`
nor the logs. It is in the Praxis process's environment, readable through
`/proc` by the same UID inside that container and by the host user that owns
the pod. Without the secret, the container exits at startup rather than
serve.

Setup tokens are long-lived and are not refreshed: there is no
`UnauthorizedRecovery` equivalent. When one expires or is revoked, Claude Code
sees the upstream 401; store a new one with `init-anthropic-token` and
recreate the pod. `reset-secrets` removes this secret along with the others.

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
  For a pass-through caller that is its own Claude credential, so the pod
  logs need the same care as the credentials. A well-formed request's
  headers are not logged; the tests check that neither the broker's token,
  a pass-through credential nor a run token reaches the logs.
- **Pass-through is an open relay to Anthropic** for anyone who can reach
  the port and holds a Claude credential. That spends only their own
  subscription, but it is metered on the broker and comes from the broker's
  address.
- **The token holder follows a mutable tag.** The Quadlet units run
  `...-gateway:main` with `AutoUpdate=registry`, so whoever can push `:main`
  to this repository's GHCR packages controls the process that holds the
  token. Pin the gateway to a digest in a drop-in (which opts it out of
  auto-update) if that is not acceptable.

## Run tokens

Every injected request must carry the token of an active registered run, in
`x-run-token` if it has that header and otherwise in `Authorization:
Bearer`. Codex sends it as its API key; Claude Code, whose `Authorization`
carries the placeholder, sets `x-run-token` with `ANTHROPIC_CUSTOM_HEADERS`.
`run_token` removes the header that held the token before forwarding.

`run_token` admits a request if its run is active and has fewer than
`concurrency` requests in flight, and publishes the run as the request's
authenticated identity. When a response ends, it adds what `token_count`
recorded to the run's usage record.

The gateway reads which jobs may register from
`/etc/praxis-credential-broker/run-token-policy.yaml`, a copy of
`run-token-policy.yaml` that the deployment mounts there
(`PRAXIS_RUN_TOKEN_POLICY` for `native-pod.sh up`, a drop-in for Quadlet).
Without that file no run can register: `POST /v1/runs` gets 503, every
injected request 401, and only pass-through requests are served.

### Registering a run

A job registers its run with a GitHub Actions OIDC token for the gateway's
audience:

```sh
curl -X POST -H "Authorization: Bearer $OIDC_TOKEN" http://PRAXIS/v1/runs
# 201 {"token": "praxis-run-...", "usage": {...}}
```

At most four registrations are verified at once (more get 429). The gateway
verifies the token's RS256 signature against GitHub's published key set
(cached for an hour, refetched at most once a minute for an unknown key id,
and no longer trusted a day after the last successful fetch), its issuer,
audience and validity period, and that it was issued after the gateway
started. Then the policy file:

| Field | Claim | Default |
|-------|-------|---------|
| `audience` | `aud` | `praxis-credential-broker` |
| `workflows` (required) | `job_workflow_ref`, exact | none |
| `repository_ids` | `repository_id` | any |
| `owner_ids` | `repository_owner_id` | any |
| `entry_workflows` | `workflow_ref`, exact | must equal `job_workflow_ref` |
| `events` | `event_name` | `workflow_dispatch` |

`repository` must also be the workflow's own. The run's limits are
`max_secs` (default 6 hours, the longest GitHub Actions job; the per-run
caps' window must be at least this long) and `concurrency` (default 4). Its
token caps are the `run` rules in `praxis.yaml`.

- **Ids, not names.** Names in `job_workflow_ref` can be taken over once an
  owner renames or deletes its account, so the gateway refuses to start
  unless `repository_ids` or `owner_ids` pins the numeric ids
  (`gh api repos/OWNER/REPO --jq '.id, .owner.id'`).
- **Reusable workflows.** For a job of a reusable workflow,
  `job_workflow_ref` names the called workflow while `repository` and
  `workflow_ref` name the caller. Requiring `repository` to be the
  workflow's own refuses callers from other repositories. By default
  `workflow_ref` must equal `job_workflow_ref`, which refuses
  `workflow_call` altogether, including from another workflow of the same
  repository that someone with less review could add. Allow entry
  workflows explicitly with `entry_workflows`.
- **Events.** Every trigger of an allowed workflow at that ref can register.
  `pull_request_target`, `issue_comment` and `workflow_run` run the default
  branch's workflow for events outsiders can cause, so allowing them lets
  outsiders start runs that spend. The default admits only
  `workflow_dispatch`, which needs write access.

Each job's run (repository, run id, attempt and, when the token has one,
the job's `check_run_id`, so the jobs of a matrix register apart) registers
once, and is remembered for a day after it expires, so another OIDC token
for the same job can't mint a second budget. The same OIDC token (by `jti`)
may register an active run again: it gets a new token for the same run,
with the same usage and limits, and the old token stops working, so a job
whose 201 was lost can retry. The gateway keeps only the SHA-256 of a
token.

### Who holds what

The run token is for the agent; the OIDC credentials must stay with the
job's supervisor. GitHub gives every step of a job with `id-token: write`
`ACTIONS_ID_TOKEN_REQUEST_URL` and `ACTIONS_ID_TOKEN_REQUEST_TOKEN` in its
environment, and every process a step starts inherits them, so they do not
by themselves stay out of the agent's reach: **the harness must start the
agent's sandbox without them**, and without any file or socket they can be
read from. Whoever holds them can register the job's runs (once each, by
the rules above) and mint OIDC tokens for any audience. In
cgwalters-devspace-sandbox the agent runs as `runner-sandbox` through a
`run0` wrapper that passes no environment through, which is what keeps them
out; a harness that starts the agent another way must scrub them itself.

With that, the agent can't register a run, raise its cap or extend its
lifetime; its token admits no requests once the run is finished or
expires, and another run's token is useless to it once that run ends. A
tailnet peer without a registered run's token can't use the broker's
credentials at all.

### Usage records

`GET /v1/runs/self` with the run token returns the run's usage record;
`DELETE /v1/runs/self` finishes the run, so its token admits no more
requests, and returns the final record, which is also logged (`run usage`)
when a run finishes or expires. Both keep working after the run ends, so
the job gets the record even if the agent finished the run itself. The
record (`praxis-run-usage/v2`) holds only identifiers, model names and
numbers, fit for a run footer: the repository, run id, attempt and check
run id, workflow ref, `state` (`active`, `finished` or `expired`), Unix
times registered, expiring and finished, the number of metered `requests`
and of `unmetered` ones (successful responses whose usage never arrived,
as when the client left mid-stream; the cap keeps their reservation),
`tokens` (`input` uncached, `cache_read`, `output`, `reasoning` within
output, and `total`, which the caps count), and `models`, the same
`tokens` by the model upstream named.

## Metering and caps

### Broker usage endpoint

`GET /usage` is an **unauthenticated read** on the existing gateway listener:
anyone who can reach it can read aggregate broker usage and subscription limits.
It returns `praxis-broker-usage/v1` JSON without contacting a provider or admitting
a run. Other methods get 405; `/usage/` and other nonexact paths get 404.
The existing placeholder-deny filter still applies before this local route.

`anthropic.counts` and `codex.counts` contain cumulative `requests` with reported
usage, `unmetered` successful completed responses without usage, and `tokens` in
the run-record shape. Counts use the same `reported_usage` from `token_count` as
run records, for injected inference only. Pass-through, health checks, local
endpoints and `count_tokens` do not contribute. Incomplete/disconnected responses
are not settled here; these are observed totals, not rate-limit reservations.

Response headers from injected inference (including upstream errors) update
`anthropic.unified_5h`, `anthropic.unified_7d`, `codex.primary` and `codex.secondary`.
Each window is initially null and holds its latest valid observation plus
`observed_at` (Unix seconds). Anthropic fields are `utilization` (0–1), `reset`
(Unix seconds) and allowlisted `status` (`allowed`, `allowed_warning`, `rejected`);
Codex fields are `used_percent` (0–100), `window_minutes` and
`reset_after_seconds`. Only the corresponding unified-5h/7d and primary/secondary
header names are parsed. Missing or invalid fields are null in a new observation;
an entirely absent/invalid window leaves the prior observation and timestamp
intact. Windows update independently and may be stale; these passive observations
are neither a fresh provider query nor the broker's configured caps.

The bounded state has two counters and four window slots per named run registry,
survives configuration reloads, and resets on process restart (`started_at` names
the start of that state). It stores no credentials, arbitrary headers, prompt
content, model dimensions or run identifiers. Header fixtures in testdata use
synthetic values in the provider header shapes.

Subscription inference has no per-token bill, so without a cap only a job's
timeout bounds what an agent spends. The gateway therefore meters every
response and caps injected use with praxis-ai's own filters:

- **Metering.** `token_count` reads each response's usage: the Responses
  API's top-level `usage` or the `response.completed` event of a stream,
  and the `message_start`/`message_delta` usage of Messages. It records the
  counts and the model that served the response (`token.model`) in the
  request's filter metadata, for both credential modes, and `run_token`
  logs one line per response with the mode, cluster, run, model and
  counts, and nothing that names a credential: `request usage`, or
  `request without usage` for a response that reports none, such as an
  error or `count_tokens`. `token_count` only reads a response whose
  `content-type` says it is JSON or an event stream, and the Codex backend
  streams its events without one, so credential-proxy names a successful
  response that has no type `text/event-stream`. The recorded stream in
  `crates/praxis-gateway/testdata` pins the real event shape, and
  `just test-pod`'s mock omits the header as the backend does.
- **Per-run caps.** A `token_rate_limit` rule keyed on the run
  (`key: authenticated_subject`) caps each run at 20M tokens over a 6-hour
  window, which spans a whole run. There is one per API, because a
  condition can't select "injected" across both: so a run that uses both
  APIs gets the cap on each, though a run normally uses one. It reserves
  10k tokens per request, refuses with 429 before anything goes upstream,
  and reconciles with what `token_count` recorded: a response's `total`,
  which counts cached input in full. A run can overshoot its cap by the
  output of its requests in flight.
- **Windows.** Another `token_rate_limit` per API caps all injected use at
  100M tokens in a sliding 5-hour window, the providers' usage-limit window:
  each is a subscription with a limit of its own. One run can use up a
  window and lock out the others until it slides.

A reservation still open after `reservation_timeout` (30 minutes, longer
than any one response) is charged its estimate for good, as is one whose
client left before the usage arrived: Praxis stops reading upstream when the
client disconnects, so the usage never arrives.

Runs and caps live in the gateway's memory: restarting it forgets
registrations and resets the caps. Reloading `praxis.yaml` resets the caps
too, but runs survive it. Filters that pre-read the body (step 3 above) see
a request before `run_token` authenticates it; this is Praxis's phase order.

### Praxis forks

The gateway builds Praxis from forks in cgwalters-forge, pinned by commit,
until their changes are upstream:

- [cgwalters-forge/praxis](https://github.com/cgwalters-forge/praxis)
  (Praxis core, through `[patch.crates-io]`): a public
  `AuthenticatedIdentity` constructor, so that `run_token` can publish the
  run as the request's identity for `token_rate_limit` to key on.
- [cgwalters-forge/ai](https://github.com/cgwalters-forge/ai) (praxis-ai):
  public `token.*` metadata keys, which `run_token` reads; `token.model`,
  for the records' per-model totals; and a `token_rate_limit` fix without
  which the per-run cap and the window on the same request would overwrite
  each other's reservations.

## Operations

### Quadlet

`contrib/quadlet/` has rootless Quadlet units for the pod, with the same
pod, container, volume and secret names as `native-pod.sh up`, so they reuse
an existing Codex login and secrets. They run only published images and
mount nothing from a checkout. As committed they publish `127.0.0.1:18080`
and need the channel secret and the Claude token secret. Host-specific
settings go in drop-ins next to them, which Quadlet merges. The run
registration policy is one:

```ini
# ~/.config/containers/systemd/praxis-credential-broker-praxis.container.d/run-token-policy.conf
[Container]
Volume=%h/.config/praxis-credential-broker/run-token-policy.yaml:/etc/praxis-credential-broker/run-token-policy.yaml:ro,Z
```

and publishing on the host's tailnet address as well is another, checked
before the pod binds it. These commands run on the host, before Podman binds
the address; they deliberately avoid a dependency on `tailscaled.service`,
since user services and the system Tailscale daemon have no safe ordering
relationship. Use the address itself, not a DNS name: `PublishPort` binds
and `--assert` checks an address, and that is the boundary.

```ini
# praxis-credential-broker.pod.d/tailnet.conf
[Pod]
PublishPort=100.64.0.1:18080:8081

[Service]
ExecStartPre=/usr/bin/tailscale wait --timeout=30s
ExecStartPre=/usr/bin/tailscale ip --4 --assert=100.64.0.1
```

Every tailnet peer that can reach the port can then use pass-through and
register runs if it holds an allowed job's OIDC token, and nothing else;
restrict the port with the tailnet policy anyway.

Upgrading units from before the run tokens: the gateway now refuses to
start without the Claude token secret, which the committed unit mounts, and
the proxy unit no longer takes the client API key; drop any drop-ins that
set `PRAXIS_ANTHROPIC_GATEWAY` or `CLIENT_AUTH_MODE`, and add the policy
drop-in, or only pass-through is served.

Install by linking the units into `~/.config/containers/systemd/`, check
them with `QUADLET_UNIT_DIRS=~/.config/containers/systemd
/usr/libexec/podman/quadlet -dryrun -user`, then `loginctl enable-linger`,
`systemctl --user daemon-reload` and `systemctl --user start
praxis-credential-broker-pod.service`. Do not `systemctl enable` the
generated service; `[Install]` attaches it to `default.target`, and
lingering keeps the user manager running at boot and without a login. Each
container restarts after an unexpected exit, and the pod retries a failed
start, such as a failed Tailscale precheck. Operate the deployment with
`systemctl --user start`, `stop` or `restart
praxis-credential-broker-pod.service`, not `native-pod.sh up` or `down`;
stopping it keeps the volumes and secrets. From a toolbox without the user
bus, reach the host's user manager with `flatpak-spawn --host systemctl
--user --machine=USER@.host ...`.

Every container has `AutoUpdate=registry`, so a deployment after a merge to
`main` is `podman auto-update` (or `podman pull` and `systemctl --user
restart praxis-credential-broker-pod.service`). Each unit names its image on
one `Image=` line. To pin a release tag or digest instead of `:main`, override
that line in a drop-in, such as `Image=ghcr.io/cgwalters-bot/praxis-credential-broker-gateway:<tag>`.
`podman auto-update` follows tags only, so a digest pin opts that container
out of it. The gateway container runs with `--no-healthcheck`: Podman 5.8
cannot create a container with a scheduled health check without a systemd
user bus.

### Xenon

Xenon, the operator's broker host, runs these units with two drop-ins: the
tailnet one above for its address `100.121.0.115`, and the run registration
policy. Tailnet clients use its MagicDNS name, `xenon.tailf2eb8.ts.net`, on
port 18080: `http://xenon.tailf2eb8.ts.net:18080/v1` for Codex and
`http://xenon.tailf2eb8.ts.net:18080/anthropic` for Claude Code. It used to
also publish a pass-through Claude listener on port 18083, from a
`praxis.yaml` bind-mounted out of a checkout, and an injecting gateway on
18090 from a pod started by hand; both are replaced by the `/anthropic`
routes on 18080.

### Scripts

`native-pod.sh up` refuses the old `PRAXIS_CLIENT_AUTH_MODE` and
`PRAXIS_ANTHROPIC_GATEWAY` settings, so a stale environment is noticed
rather than ignored. `health` reports `/healthz`, that the Anthropic routes
are served, and whether runs can register.

`down` removes the production pod and socket volume but preserves the
secrets plus the Codex auth volume. Use the following destructive or
maintenance commands while observing their required stopped-pod state:

```sh
# Replace only the internal channel key; pod must be down.
bash scripts/native-pod.sh rotate-agent-secret

# Remove the channel and Anthropic token secrets, and the client secret of
# older versions, if present; pod must be down.
RESET_SECRETS=RESET bash scripts/native-pod.sh reset-secrets

# Remove the OAuth auth volume (and stop/remove the pod).
RESET_AUTH=RESET bash scripts/native-pod.sh reset-auth

# Show production pod logs.
bash scripts/native-pod.sh logs
```

Podman secret storage is not claimed to encrypt secrets at rest.

## Development and synthetic testing

`just check` runs formatting, clippy, and locked workspace tests. Those
include the gateway's integration tests, which serve `praxis.yaml` with
the gateway's registry in front of a fake upstream per cluster and the
test-only OIDC key set (`crates/praxis-gateway/testdata`), and cover run
registration, both credential modes, the metering of streamed Responses and
Messages responses by `token_count`, the run and window caps, and a client
that leaves mid-stream.

`just test-gateway` runs `tests/gateway.py`, which CI also runs. It builds
the gateway image and runs it with its configuration replaced by a copy in
which only the listener address and the upstream endpoints are rewritten,
each cluster to an in-process fake upstream of its own, with a synthetic
token in a Podman secret and a registration policy that trusts the test
key. It registers a run, then checks every placeholder and pass-through case
under `/anthropic`, Responses next to it, the cross-prefix and traversal
cases, which upstream each request reached and with which credential,
header stripping, Host and beta handling, byte-identical bodies, unbuffered
SSE, h2c, that every metered request is logged without its credential, that
neither the token nor a pass-through credential nor the run token is in the
logs or `podman inspect`, and that the container refuses to start without
the token. It needs rootless Podman with host networking.

`just test-pod` builds a synthetic provider and mock upstream, then runs the
native Podman integration checks. It always uses hardwired local synthetic
images; it does not read production image overrides or OAuth credentials.
Never put real credentials in that test pod. It exposes loopback-only
ports: Praxis on `127.0.0.1:18081`, mock counters on `127.0.0.1:18082`, and
the synthetic provider counter on `127.0.0.1:19090`. Its first pass runs
the routes baked into the image, with a test policy that trusts the test key
set the mock serves: it checks secret isolation, socket mode and label,
hardening, that requests without a run token are refused, run registration
and its retry rules, finite and SSE Responses through credential-proxy with
401 recovery, the usage record, that finishing the run revokes its token,
and that no secret or token reaches the logs. Its second pass sets a per-run
cap of 150 tokens and checks that the request after the cap is refused with
429. It also checks idempotent removal of absent synthetic secrets.

```sh
just check
just test-gateway
just test-pod
```

Podman 5.8 cannot use pre-existing native secrets from `podman kube play`
secret volumes. The scripts therefore create pods with `podman pod create` and
containers with `podman create --secret`.

## Pinned dependencies and publishing

The gateway builds Praxis AI from cgwalters-forge/ai and Praxis core from
cgwalters-forge/praxis, both pinned by commit in `Cargo.toml` and locked in
`Cargo.lock` (see [Praxis forks](#praxis-forks)), with the
`openai-responses` and experimental `token-rate-limit-filter` features.
`Containerfile.gateway` builds it like upstream's own image, on Alpine; it
needs Rust 1.96 or newer, cmake and OpenSSL. The Codex provider uses the
official `codex-login` source at `0dfb28edb9305fcae4ab006fb6b7b196cbdbac28`.

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
registered profile/audience; the HTTP streaming core remains unchanged. The
runtime can bind to the host's tailnet address but does not configure
Tailscale. Any future Serve integration is limited to tailnet-only Serve and
`svc:inference`: this project deliberately provides no Funnel, public bind, or
tailnet mutation.

The project and directly consumed Codex sources are Apache-2.0; see `NOTICE`
for provenance. This spike exceeds the roughly 500 substantial-line
design-review threshold. Independent security and design review is required
before production use.
