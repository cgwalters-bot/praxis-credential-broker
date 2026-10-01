# Internals

This document records implementation, security, operational, and development
details that are intentionally kept out of the [quick-start README](README.md).

## Architecture and trust boundaries

```text
Codex client -> stock Praxis -> credential-proxy -> fixed chatgpt.com Codex endpoint
                                    ^
                                    | private versioned Unix socket (credentials only)
                              provider-codex
Claude Code -> stock Praxis ----------------------> fixed api.anthropic.com Messages endpoint
```

There are four credential classes:

1. In the default `required` client-auth mode, the client API key
   authenticates a Codex client to the credential proxy and must be at least
   32 bytes. In explicit `disabled` mode it is neither read nor mounted.
2. The internal channel key is a generated HMAC secret between the proxy and
   provider; it is not a client credential.
3. Provider-owned ChatGPT Codex OAuth tokens live in the provider's auth
   volume after device login.
4. Claude Code owns its subscription OAuth credential on the host. It passes
   transiently through Praxis to Anthropic and is neither stored nor refreshed
   by the pod.

The proxy has no Codex SDK, OAuth state, or writable credential volume. The
provider exclusively owns `CODEX_HOME`. OAuth headers pass transiently through
the proxy while it constructs an upstream request; auth state remains
provider-owned.

The proxy accepts only `POST /v1/responses`, strips caller authorization,
cookies, account, hop-by-hop, and proxy headers, and forwards to a fixed HTTPS
endpoint. The client cannot choose a URL, authority, or provider profile.

Praxis exposes Anthropic Messages separately on host port `18083` (pod port
`8082`). Its native Anthropic filters run on a listener separate from the Codex
Responses listener on `18080`/`8081`. The Anthropic chain routes only the exact
path `/v1/messages` to `api.anthropic.com:443`, with TLS SNI and `Host` fixed to
that name. It preserves Claude Code's `Authorization`,
`anthropic-version`, and `anthropic-beta` headers, while removing `x-api-key`
to prevent ambiguous API-key and subscription-OAuth authentication.

Production publishes both Claude and Codex on loopback and on the single IPv4
address assigned to Xenon's `tailscale0`. Before creating the pod, the launcher
parses `ip -j -4 addr show dev tailscale0` and requires exactly one address
belonging to `100.64.0.0/10`. A missing interface, zero or multiple IPv4
addresses, or an address outside that range aborts startup; the address cannot
be overridden by an environment variable. It never publishes a wildcard or LAN
binding, and it does not mutate or make claims about Tailscale configuration or
access policy. Loopback remains available for local clients.

Tailnet clients use Xenon's MagicDNS FQDN: `xenon.tailf2eb8.ts.net` (port
`18080` for Codex Responses and `18083` for Claude Messages). The numeric
address remains deliberately in the Quadlet `PublishPort` entries and the
`tailscale ip --assert=100.121.0.115` precheck: those bind and assert an IPv4
address, not a DNS name, and establish the trusted-tailnet boundary.

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
is only the Codex Responses listener's endpoint: it uses a side-effect-free
`Ping` and returns only `ready` or `not ready`. The `health` script command also
checks that the separate Claude listener rejects a malformed Messages request
with 400. Checks exercise both loopback and published tailnet bindings; neither
forwards a request nor validates upstream authentication.

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
existing `auth.json` unchanged. Claude Code login occurs outside the pod and
does not require a Codex login to start a Claude-only pod. An upstream request
is required to verify either login.

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

Disabled mode relies on the tailnet as its sole Codex client-auth boundary:
every tailnet peer permitted to connect to port 18080 can make requests using
the provider's stored Codex OAuth credential. Tailnet ACLs must restrict that
port to trusted peers. The launcher neither configures nor verifies those ACLs,
so disabled mode is unsafe for a tailnet containing untrusted peers. Changing
modes requires stopping the pod and recreating it with the selected mode.
Running `init-secrets` in disabled mode creates/replaces only the channel secret
and does not prompt for, remove, or otherwise modify an existing client secret.

The Claude listener has no broker client-auth filter: Claude Code's OAuth is
forwarded to Anthropic. Its loopback and tailnet-only host bindings are
therefore critical boundaries; any process able to reach either binding and
obtain a Claude Code authorization header can submit requests through it. Tailnet
ACLs should explicitly restrict which peers may connect to this port; this
alpha design does not claim protection from untrusted local users or processes.

## Operations

### Xenon rootless Quadlet

`quadlet/` contains the deployed rootless units. It targets Podman 5.8.4
and uses one `.pod`, three `.container`, and two `.volume` definitions. Its
container and volume names deliberately match the native deployment so the
existing `praxis-credential-broker-auth` volume and
`praxis-credential-broker-agent-channel` Podman secret are preserved. The
client-auth secret is deliberately not mounted: Xenon is configured with
`CLIENT_AUTH_MODE=disabled` and must remain accessible only to trusted tailnet
peers.

The pod publishes `18080` and `18083` on loopback and fixed Xenon tailnet
address `100.121.0.115`. Before Podman creates the pod, its user service runs
`tailscale wait --timeout=30s` and `tailscale ip --4 --assert=100.121.0.115` on the host.
These are host prechecks, not container commands. They intentionally avoid a
dependency on a Tailscale systemd unit, which could introduce a user/system
unit ordering cycle. Quadlet links containers to the pod declaratively; the
explicit `[Unit]` links use generated `.service` names rather than source-file
`.container` names.

The Praxis configuration mount is intentionally fixed to
`%h/src/github/cgwalters-bot/praxis-credential-broker/praxis.yaml`, the
checkout path on Xenon. `%h` keeps the source usable by the rootless account
without embedding that account's absolute home directory. The Praxis image
digest is the existing pinned runtime image verified in local Podman metadata;
the proxy and provider retain this repository's published `:main` images.

Validate the sources before installation:

```sh
bash -n scripts/native-pod.sh scripts/init-secrets scripts/create-agent-secret
shellcheck scripts/native-pod.sh scripts/init-secrets scripts/create-agent-secret
QUADLET_UNIT_DIRS="$PWD/quadlet" /usr/lib/systemd/system-generators/podman-system-generator --user --dryrun
git diff --check
```

The generator command validates the actual host generator without installing
units. Inspect its generated services to confirm the host `tailscale` prechecks,
all four explicit bindings, `ExitPolicy=continue`, hardening options, and
volume/secret ownership before any production action.

The deployed installation is a directory symlink, so edits to the sources take
effect after a daemon reload. Stop the old native pod before the first Quadlet
start: both use the same names and ports. Run these commands on the host:

```sh
mkdir -p ~/.config/containers/systemd
ln -s "$PWD/quadlet" ~/.config/containers/systemd/praxis-credential-broker
loginctl enable-linger "$USER"
systemctl --user daemon-reload
systemctl --user start praxis-credential-broker-pod.service
bash scripts/native-pod.sh health
```

Quadlet's `[Install]` section attaches the pod to `default.target`; do not
`systemctl enable` the generated service. Lingering keeps the user manager
available at boot and after logout. Each application container restarts after
an unexpected exit; the pod retries startup after a failed Tailscale precheck.
Local checks verified a whole-pod restart and recovery after killing the proxy
container. A reboot has not been tested.

Operate the persistent deployment with `systemctl --user start`, `stop`, or
`restart praxis-credential-broker-pod.service`, not `native-pod.sh up/down`.
Stopping it preserves both named volumes and the Podman secrets. From a toolbox
with an inaccessible user bus, use `flatpak-spawn --host systemctl --user
--machine=sandbox-walters@.host ...` to reach Xenon's user manager.

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

`just check` runs formatting, clippy, and locked workspace tests. `just
test-pod` builds a synthetic provider and mock upstream, then runs the native
Podman integration checks. It always uses hardwired local synthetic images;
it does not read production image overrides or OAuth credentials. Never put
real credentials in that test pod.

The synthetic test pod deliberately exposes loopback-only ports: Codex Praxis
on `127.0.0.1:18081`, mock counters on `127.0.0.1:18082`, the Claude listener on
`127.0.0.1:18084`, and the synthetic provider counter on `127.0.0.1:19090`.
It verifies required client authentication, 401 recovery,
finite and SSE responses, secret isolation, socket mode/label, hardening, and
that secrets do not appear in pod logs. It then recreates the synthetic pod in
disabled mode and verifies a no-Authorization request succeeds with provider
credentials, no client-secret mount, and a separate caller Authorization value
is replaced with the provider credential. It also checks idempotent removal of
absent synthetic secrets. The Claude-listener test is readiness-only: it sends
a malformed Messages request and expects local validation to return 400. It
does not contact Anthropic, authenticate Claude OAuth, or establish that the
header-forwarding boundary is safe for untrusted local processes.

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
unchanged. The runtime binds directly to the host's tailnet IPv4, but does not
configure Tailscale. Any future Serve integration is limited to tailnet-only
Serve and `svc:inference`: this project deliberately provides no Funnel, public
bind, or tailnet mutation.

The project and directly consumed Codex sources are Apache-2.0; see `NOTICE`
for provenance. This spike exceeds the roughly 500 substantial-line
design-review threshold. Independent security and design review is required
before production use.
