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

`praxis-gateway` (`crates/praxis-gateway`) is Praxis AI built from source
as a library, with its full filter registry plus this repository's one
filter, `run_token`. Its configuration is `praxis.yaml` in every mode; in
run-token mode the pod publishes its run-token listener and mounts the
registration policy next to it.

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

`PRAXIS_CLIENT_AUTH_MODE` is strictly `required` (the default), `disabled`
or `run-token` (see below) for `up`; unknown values stop that operation before a pod is
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
boundary, such as a tailnet/Tailscale policy, protects access, and even then
every peer it admits can spend up to the window cap; prefer run-token mode
for agent jobs. The current
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
  counts and the model that served the response (`token.model`) in the
  request's filter metadata. A `headers` filter drops `accept-encoding`, so
  responses stay readable.
- **Window cap.** `token_rate_limit` reserves a fixed 10k tokens per
  request, refuses a request with 429 when that would exceed 100M tokens in
  a sliding 5-hour window (the Codex usage-limit window), and reconciles the
  reservation with the counts `token_count` recorded. Each API has its own
  window, since each is a different subscription with a limit of its own.
  Outside run-token mode its callers are indistinguishable, so one of them
  can use up a window and lock out the others until it slides. A
  reservation still open after `reservation_timeout` (30 minutes, longer
  than any one response) is charged its estimate for good, as is one whose
  client left before the usage arrived.

Both APIs share one chain, whose Responses and Messages filters are
conditioned on the path (`/v1/responses`, `/v1/messages`). Messages
requests go straight to api.anthropic.com with the caller's own Claude
OAuth token; credential-proxy, and so the client API key of required mode,
is only on the Responses path.

Windows live in the gateway's memory: restarting it resets them.

## Run tokens

`run-token` mode adds a cap per CI job's run. The pod then publishes
`praxis.yaml`'s `run-token-gateway` listener, whose chain starts with the
gateway's `run_token` filter, the one filter this repository implements.
Praxis then authenticates clients, and the proxy runs with
`CLIENT_AUTH_MODE=disabled`, as nothing outside the pod can reach it (the
pod publishes only the run-token listener). Every
request must carry the token of an active registered run, in
`x-run-token` if it has that header and otherwise in `Authorization:
Bearer`. Claude Code, whose `Authorization` carries its own OAuth token,
sets `x-run-token` with `ANTHROPIC_CUSTOM_HEADERS`. `run_token` removes the
header that held the token before forwarding.

`run_token` admits a request if its run is active and has fewer than
`concurrency` requests in flight, and publishes the run as the request's
authenticated identity. A `token_rate_limit` rule keyed on that identity
(`key: authenticated_subject`) caps each run at 20M tokens over a 6-hour
window, which spans a whole run, across both APIs: it reserves 10k tokens
per request, refuses with 429 before anything goes upstream, and
reconciles with what `token_count` recorded, like the window cap. A run
can overshoot its cap by the output of its requests in flight. When a
response ends, `run_token` adds what `token_count` recorded to the run's
usage record.

`native-pod.sh up` in run-token mode mounts `PRAXIS_RUN_TOKEN_POLICY`, a
copy of `run-token-policy.yaml` naming the jobs that may register, at
`/etc/praxis/run-token-policy.yaml`. Without that file the listener lets
no run register, so it refuses everything but `/healthz`.

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
cap's window must be at least this long) and `concurrency` (default 4). Its
token cap is the `run` rule in `praxis.yaml`.

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
expires, and another run's token is useless to it once that run ends. Any
tailnet peer without a registered run token is refused, so run-token mode
also closes the gap disabled mode leaves open.

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

Runs and caps live in the gateway's memory: restarting it forgets
registrations and resets the caps. Reloading `praxis.yaml` resets the caps
too, but runs survive it.

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

One gap remains: Praxis stops reading upstream when the client
disconnects, so such a request is charged its reservation rather than the
usage upstream would have reported.

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
include the gateway's integration tests, which serve `praxis.yaml` with
the gateway's registry in front of a fake upstream and OIDC key set, and
cover run registration, the metering of streamed Responses and Messages
responses by `token_count`, the run and window caps, and a client that
leaves mid-stream. `just
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
is replaced with the provider credential. Finally it recreates the pod in
run-token mode, publishing the run-token listener with a test policy
that trusts the test-only OIDC key set the mock serves
(`crates/praxis-gateway/testdata`): it registers a run with a token signed
by that key, and checks that unregistered and wrong-workflow callers are
refused, that responses are metered and the run cap refuses the next
request, that finishing the run revokes its token, and that neither token
reaches the logs. It also checks idempotent removal of absent synthetic
secrets.

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

The gateway builds praxis-ai and Praxis core from the cgwalters-forge
forks at the commits `crates/praxis-gateway/Cargo.toml` and the workspace
`Cargo.toml` pin (see [Praxis forks](#praxis-forks)), with the
`openai-responses` and experimental `token-rate-limit-filter` features;
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
