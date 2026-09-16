> **Disclaimer: All code in this repository is LLM-generated. See [LLMs](https://github.com/cgwalters/cgwalters#llms).**

# praxis-credential-broker (alpha architecture spike)

This is a reference implementation for using stock
[Praxis AI](https://github.com/praxis-proxy/ai) as the client-facing proxy for
the OpenAI/ChatGPT Codex **Responses** endpoint, while OAuth credentials stay
in a separate provider agent. It is specifically for the ChatGPT Codex backend
authenticated by `codex login`; it makes no claim to be a general proxy for the
public OpenAI API.

## Run published images

Requires Podman, `curl`, and this repository's scripts. The default production
images are:

```text
ghcr.io/cgwalters-bot/praxis-credential-broker-proxy:main
ghcr.io/cgwalters-bot/praxis-credential-broker-provider-codex:main
```

Each main build also publishes immutable full-commit-SHA tags. Pulling from
GHCR may require `podman login ghcr.io` when package visibility or access policy
requires authentication.

There are three distinct credentials:

1. The **client API key** authenticates a local client to Praxis. It must be at
   least 32 bytes.
2. The **internal channel key** is a generated HMAC secret between the proxy and
   provider. It is never a client credential.
3. The provider-owned **ChatGPT Codex OAuth tokens** live only in its auth
   volume after device login. They are never exposed to the client; the proxy
   receives them only transiently when constructing an upstream request.

Initialize the first two secrets, run device login, then start and check the
pod. The hidden read is followed by a newline, and exporting the key makes the
same client key available to Codex and OpenCode in this shell.

```sh
read -r -s PRAXIS_API_KEY
printf '\n'
export PRAXIS_API_KEY
bash scripts/init-secrets
bash scripts/native-pod.sh login
bash scripts/native-pod.sh up
bash scripts/native-pod.sh health
# later
bash scripts/native-pod.sh down
```

`login` uses the official device flow while the provider is stopped. `down`
preserves the OAuth auth volume and both Podman secrets for restart. A password
manager can provide the client key without creating a secret file:

```sh
PRAXIS_API_KEY="$(password-manager read praxis/api-key)" bash scripts/init-secrets
```

Environment variables and command substitution may be visible to local tooling
or process inspection. Treat either input method accordingly.

To use immutable tags or a compatible private mirror, set both image references
explicitly before every runtime command that needs one:

```sh
export PRAXIS_PROXY_IMAGE=ghcr.io/cgwalters-bot/praxis-credential-broker-proxy:<commit-sha>
export PRAXIS_PROVIDER_CODEX_IMAGE=ghcr.io/cgwalters-bot/praxis-credential-broker-provider-codex:<commit-sha>
bash scripts/native-pod.sh login
bash scripts/native-pod.sh up
```

## Build from source for development

`just` is only for build, development, and test conveniences. Build local
images, then override both runtime image references explicitly before using the
same scripts:

```sh
just build
export PRAXIS_PROXY_IMAGE=localhost/praxis-credential-proxy:dev
export PRAXIS_PROVIDER_CODEX_IMAGE=localhost/praxis-provider-codex:dev
bash scripts/native-pod.sh login
bash scripts/native-pod.sh up
```

The secret initialization and client-key export from the published-image
workflow apply here as well. Run `just test-pod` only for synthetic tests; it
always uses hardwired local synthetic images and never reads production image
overrides or OAuth credentials. Run `just check` for formatting, clippy, and
workspace tests.

## Configure and launch clients

Only Praxis publishes `127.0.0.1:18080`. It accepts native `POST
/v1/responses`; the proxy also normalizes Codex compatibility details before
forwarding to the fixed ChatGPT Codex endpoint. Use the exported
`PRAXIS_API_KEY`, never a ChatGPT OAuth credential.

Codex configuration:

```toml
[model_providers.praxis]
name = "Local Praxis"
base_url = "http://127.0.0.1:18080/v1"
wire_api = "responses"
env_key = "PRAXIS_API_KEY"

[profiles.praxis]
model_provider = "praxis"
```

OpenCode configuration uses the OpenAI AI SDK adapter, an explicit model map,
the local base URL, and the same client key:

```json
{
  "provider": {
    "praxis": {
      "npm": "@ai-sdk/openai",
      "options": {
        "baseURL": "http://127.0.0.1:18080/v1",
        "apiKey": "{env:PRAXIS_API_KEY}"
      },
      "models": {
        "gpt-6-astra": {
          "name": "gpt-6-astra"
        }
      }
    }
  }
}
```

Do not set `requires_openai_auth`. Launch either configured client with:

```sh
codex --profile praxis
opencode run --model praxis/gpt-6-astra
```

## Operations, token rotation, and testing

`AuthManager` from pinned `codex-login` is configured with
`AuthCredentialsStoreMode::File` on the provider's writable `CODEX_HOME` auth
volume. Every authenticated request admitted for upstream forwarding performs
`Acquire`; its `AuthManager::auth` call proactively refreshes managed ChatGPT
auth when needed and persists the rotated access/refresh tokens in that
provider-owned volume. An upstream 401 performs one `UnauthorizedRecovery` and
retries once. Thus forwarded requests drive OAuth rotation, while an idle
service has no background refresh timer.
Neither the client API key nor the internal channel key rotates automatically.

`bash scripts/native-pod.sh rotate-agent-secret` explicitly replaces only the
channel key while the pod is down. `RESET_SECRETS=RESET bash
scripts/native-pod.sh reset-secrets` removes only the client and channel
secrets. `RESET_AUTH=RESET bash scripts/native-pod.sh reset-auth` is the
separate destructive OAuth-volume operation. `bash scripts/native-pod.sh logs`
shows pod logs.

`just test-pod` builds a synthetic provider and mock upstream. Never use real
credentials in that pod. It publishes only loopback test ports: Praxis on
`127.0.0.1:18081`, mock counters on `127.0.0.1:18082`, and the synthetic-agent
counter on `127.0.0.1:19090`. Podman 5.8 cannot use pre-existing native secrets
from `podman kube play` secret volumes, so pods are intentionally constructed
with `podman pod create` and `podman create --secret`.

## Architecture and trust boundaries

```text
client -> stock Praxis -> credential-proxy -> fixed chatgpt.com Codex endpoint
                            ^
                            | private versioned Unix socket (credentials only)
                      provider-codex
```

Stock Praxis is pinned exactly to
`ghcr.io/praxis-proxy/ai@sha256:ccd46f8772eebcbde2f41ad35c3234d23463b8314a5865083e32baf31eddd1a8`.
The proxy has no Codex SDK, OAuth state, or writable credential volume. The
Codex agent exclusively owns `CODEX_HOME` and uses official `codex-login` at
`0dfb28edb9305fcae4ab006fb6b7b196cbdbac28`.

`credential-protocol` is version-1 newline-delimited JSON, bounded to 16 KiB
for reads and writes. Authenticated `Ping`, `Acquire`, and
`UnauthorizedRecovery` use a 32-byte-minimum channel secret with nonce/HMAC.
The proxy supplies the registered profile and audience, so a request cannot
select a URL, authority, or profile. The agent validates those values before
returning only sensitive headers.

The socket is in the private named Podman volume
`praxis-credential-broker-socket` and is mode 0660. Both images run as UID/GID
65532 with read-only roots, no capabilities, and no privilege escalation. The
proxy requires the Podman client-key secret, strips caller authorization,
cookies, account, hop-by-hop, and proxy headers, and injects agent headers
transiently. It forwards only `POST /v1/responses` to a fixed HTTPS endpoint.
Finite and SSE streams have idle, byte, and concurrency limits; `/healthz`
performs side-effect-free `Ping` and reports only `ready` or `not ready`.

The provider alone owns the refresh volume. Device login uses an advisory lock,
same-volume staging, and atomic installation; cancellation leaves existing
`auth.json` untouched. A successful process startup without OAuth is reported
as OAuth-not-initialized when health returns the expected upstream 502; refused
connections, exited containers, and other statuses fail closed.

## Status, publishing, advisories, and provenance

This is an alpha spike, not a production-ready service. Adding a provider
requires an agent implementing the private protocol and a registered
profile/audience; the HTTP streaming and client-auth core remain unchanged.
Future deployment may use tailnet-only Tailscale Serve and `svc:inference`;
there is deliberately no Funnel, public bind, or tailnet mutation here.

GitHub Actions builds both production Containerfiles on pull requests. Main
pushes and manual dispatch from main publish the two GHCR images with `main`
and full-commit-SHA tags using `GITHUB_TOKEN`; OCI source labels associate them
with this repository.

`cargo-deny` keeps the exact Hickory advisories `RUSTSEC-2026-0118` and
`RUSTSEC-2026-0119` as hard deployment blockers. Known unmaintained transitive
advisories remain listed in `deny.toml` and the prior dependency review rather
than being blanket-hidden. Review the dependency graph before deployment.

The project and directly consumed Codex sources are Apache-2.0; see `NOTICE`
for provenance. This spike exceeds the roughly 500 substantial-line
design-review threshold; independent security and design review is required
before production use.
