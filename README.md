> **Disclaimer: All code in this repository is LLM-generated. See [LLMs](https://github.com/cgwalters/cgwalters#llms).**

# praxis-credential-broker

> **Alpha:** this is an architecture spike, not a production-ready service. See
> [INTERNALS.md](INTERNALS.md) for architecture, security, operations, and
> development details.

A reference implementation for using stock [Praxis AI](https://github.com/praxis-proxy/ai)
with the ChatGPT Codex Responses endpoint, authenticated through `codex login`,
and Claude Code's subscription OAuth for Anthropic Messages.

## Start the pod with published images

Requires Podman, `curl`, and this repository's scripts. The default images are:

```text
ghcr.io/cgwalters-bot/praxis-credential-broker-proxy:main
ghcr.io/cgwalters-bot/praxis-credential-broker-provider-codex:main
```

For Codex, two distinct credentials are involved: `PRAXIS_API_KEY` authenticates
the local client to the credential proxy, while `codex login` stores the ChatGPT
OAuth credential used upstream. Client API-key authentication is required by
default. Create and export a client API key (at least 32 bytes), initialize the
Podman secrets, then complete the Codex device login and start the pod:

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

`down` preserves the client secrets and Codex login for a later restart. The
host binds both Claude and Codex to loopback and Xenon's `tailscale0` IPv4
address. Neither is published on a wildcard or LAN address. At startup the
script discovers exactly one `tailscale0` IPv4 address. It must be in the
tailnet CGNAT range (`100.64.0.0/10`); missing, ambiguous, or other
addresses abort startup. This does not configure Tailscale or any access policy.
GHCR access policies may require `podman login ghcr.io`.

The published image tags provide the proxy and Codex-provider images. The
runtime script bind-mounts this checkout's `praxis.yaml`, so the local
configuration script—not the published `:main` image tag—enables the Claude
listener described below.

To rely on the tailnet as the Codex client-auth boundary, disable Codex client
authentication before initialization. In this mode, **every peer permitted to
connect to Xenon's tailnet address can use the stored Codex OAuth credential**.
Restrict the port with tailnet ACLs; this script does not configure those ACLs.

```sh
export PRAXIS_CLIENT_AUTH_MODE=disabled
bash scripts/init-secrets # creates only the mandatory internal channel secret
bash scripts/native-pod.sh login
bash scripts/native-pod.sh up
```

To use a full-commit-SHA tag or a compatible private mirror, override both
images before `login` and `up`:

```sh
export PRAXIS_PROXY_IMAGE=ghcr.io/cgwalters-bot/praxis-credential-broker-proxy:<commit-sha>
export PRAXIS_PROVIDER_CODEX_IMAGE=ghcr.io/cgwalters-bot/praxis-credential-broker-provider-codex:<commit-sha>
bash scripts/native-pod.sh login
bash scripts/native-pod.sh up
```

## Build from source for development

`just` is for build and development conveniences only. Build local images and
explicitly select them for the runtime scripts:

```sh
just build
export PRAXIS_PROXY_IMAGE=localhost/praxis-credential-proxy:dev
export PRAXIS_PROVIDER_CODEX_IMAGE=localhost/praxis-provider-codex:dev
bash scripts/native-pod.sh login
bash scripts/native-pod.sh up
```

Use the same secret setup above before starting local images.

## Configure and launch clients

Praxis exposes Codex on `http://127.0.0.1:18080` and, for tailnet clients,
`http://xenon.tailf2eb8.ts.net:18080`; it accepts `POST /v1/responses`. In the
default required mode, use `PRAXIS_API_KEY`, not a ChatGPT credential.

Codex required-mode configuration uses a provider definition in
`~/.codex/config.toml`:

```toml
[model_providers.praxis]
name = "Local Praxis"
base_url = "http://127.0.0.1:18080/v1"
wire_api = "responses"
env_key = "PRAXIS_API_KEY"
```

and a named profile in `~/.codex/praxis.config.toml`:

```toml
model_provider = "praxis"
```

In disabled mode, replace the provider definition with this keyless variant;
the profile is unchanged:

```toml
[model_providers.praxis]
name = "Local Praxis"
base_url = "http://127.0.0.1:18080/v1"
wire_api = "responses"
requires_openai_auth = false
```

OpenCode required-mode configuration:

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

In disabled mode, replace `"{env:PRAXIS_API_KEY}"` with `"unused"`. It is a
non-secret placeholder required by OpenCode's AI SDK; the broker strips it
before upstream forwarding. Launch either configured client with:

```sh
codex --profile praxis
opencode run --model praxis/gpt-6-astra
```

## Use Claude Code subscription OAuth

Claude Code's subscription OAuth is separate from both Codex credentials.
Complete `claude auth login` on the host, outside the pod; Claude Code retains
and refreshes that credential. For Claude-only use, initialize the mandatory
internal channel secret and start the pod without a Codex device login:

```sh
export PRAXIS_CLIENT_AUTH_MODE=disabled
bash scripts/init-secrets
bash scripts/native-pod.sh up
```

The Codex provider still starts, but a Codex login is not required for Claude
requests. This mode disables client authentication on the **Codex** listener;
the Claude listener does not have broker client authentication in either mode.

Point Claude Code at the separate Anthropic Messages listener. It forwards the
OAuth `Authorization`, `anthropic-version`, and `anthropic-beta` headers to the
fixed `https://api.anthropic.com` upstream, while removing `x-api-key` so
API-key and subscription credentials cannot be combined.

```sh
export ANTHROPIC_BASE_URL=http://127.0.0.1:18083
claude -p 'Reply with exactly: OK' --model haiku
```

For a tailnet client, set `ANTHROPIC_BASE_URL` to
`http://xenon.tailf2eb8.ts.net:18083` instead. Codex is also available at its
tailnet FQDN in both client-auth modes. Neither listener is published to the
LAN or all host interfaces. Do not export OAuth tokens or set
`ANTHROPIC_API_KEY` or `ANTHROPIC_AUTH_TOKEN`; Claude Code owns and refreshes
the subscription OAuth credential.

`bash scripts/native-pod.sh health` checks loopback and tailnet readiness for
both listeners: the Codex `/healthz` endpoint and a deliberately malformed
Claude Messages request. It does not authenticate to either upstream or
validate either OAuth login.

For operational procedures, security properties, test topology, publishing,
and provenance, read [INTERNALS.md](INTERNALS.md).

## Xenon rootless Quadlet

`quadlet/` contains the rootless Podman 5.8.4 source for the current Xenon
deployment. It runs with disabled Codex client authentication and exposes both
listeners only on `127.0.0.1` and trusted tailnet address `100.121.0.115`.
The numeric address is intentionally retained for Quadlet `PublishPort` and
the Tailscale address assertion: they bind and validate an address, not DNS,
and define the trusted-tailnet boundary. Clients use the FQDN above.
This is intentionally distinct from `native-pod.sh`, which remains the
interactive/development launcher.

The operator must first create the mandatory internal channel secret and
complete the Codex device login if Codex requests are needed. The persisted
`praxis-credential-broker-auth` volume is retained by the Quadlet source.
The units are installed under `~/.config/containers/systemd/` and started by
the host user manager; lingering is enabled for boot/logout persistence. Use
`systemctl --user restart praxis-credential-broker-pod.service` to restart the
deployment, then `bash scripts/native-pod.sh health` to check readiness.
See [INTERNALS.md](INTERNALS.md) for installation and toolbox commands.
