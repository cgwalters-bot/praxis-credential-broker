> **Disclaimer: All code in this repository is LLM-generated. See [LLMs](https://github.com/cgwalters/cgwalters#llms).**

# praxis-credential-broker

> **Alpha:** this is an architecture spike, not a production-ready service. See
> [INTERNALS.md](INTERNALS.md) for architecture, security, operations, and
> development details.

A reference implementation for using stock [Praxis AI](https://github.com/praxis-proxy/ai)
with the ChatGPT Codex Responses endpoint, authenticated through `codex login`.

## Run published images

Requires Podman, `curl`, and this repository's scripts. The default images are:

```text
ghcr.io/cgwalters-bot/praxis-credential-broker-proxy:main
ghcr.io/cgwalters-bot/praxis-credential-broker-provider-codex:main
ghcr.io/cgwalters-bot/praxis-credential-broker-gateway:main
```

The gateway image is stock Praxis with this repository's routes built in.

Client API-key authentication is required by default. Create and export a
client API key (at least 32 bytes), initialize the Podman secrets, then
complete the Codex device login and start the pod:

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

`down` preserves the client secrets and Codex login for a later restart. GHCR
access policies may require `podman login ghcr.io`.

To deliberately rely on another access-control boundary, such as a tailnet
policy, disable client authentication before initialization. The service still
binds loopback-only; this does not configure Tailscale.

```sh
export PRAXIS_CLIENT_AUTH_MODE=disabled
bash scripts/init-secrets # creates only the mandatory internal channel secret
bash scripts/native-pod.sh login
bash scripts/native-pod.sh up
```

To use a full-commit-SHA tag or a compatible private mirror, override the
images before `login` and `up`:

```sh
export PRAXIS_PROXY_IMAGE=ghcr.io/cgwalters-bot/praxis-credential-broker-proxy:<commit-sha>
export PRAXIS_PROVIDER_CODEX_IMAGE=ghcr.io/cgwalters-bot/praxis-credential-broker-provider-codex:<commit-sha>
export PRAXIS_GATEWAY_IMAGE=ghcr.io/cgwalters-bot/praxis-credential-broker-gateway:<commit-sha>
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
export PRAXIS_GATEWAY_IMAGE=localhost/praxis-gateway:dev
bash scripts/native-pod.sh login
bash scripts/native-pod.sh up
```

Use the same secret setup above before starting local images.

## Configure and launch clients

Praxis listens on `127.0.0.1:18080` and accepts `POST /v1/responses`. In the
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

## Claude Code through the Anthropic gateway

Optionally, the same listener also serves Anthropic Messages for Claude Code
under `/anthropic`. The broker holds a Claude subscription OAuth token and
Claude Code holds only a fixed placeholder, so a sandboxed client never sees
the token. This is meant for your own CI and agents on your own subscription.

**These routes have no client authentication.** The placeholder is public
configuration, not a secret, and `PRAXIS_CLIENT_AUTH_MODE` does not apply to
them: anything that can reach `127.0.0.1:18080` can spend the subscription.
They rely on the network boundary, as `disabled` mode does. See
[INTERNALS.md](INTERNALS.md#anthropic-messages-gateway) for the risks.

Create a long-lived token with `claude setup-token` on a trusted machine and
store it as a Podman secret. The script reads it from the terminal without
echo, or from standard input, for example from a password manager:

```sh
bash scripts/init-anthropic-token
# or
password-manager read claude/oauth-token | bash scripts/init-anthropic-token
```

Then start the pod with the gateway enabled, alongside the usual secrets:

```sh
export PRAXIS_ANTHROPIC_GATEWAY=enabled
bash scripts/native-pod.sh up
bash scripts/native-pod.sh health
```

Point Claude Code at the `/anthropic` prefix with exactly this placeholder.
Claude Code appends `/v1/messages` to the base URL:

```sh
export ANTHROPIC_BASE_URL=http://127.0.0.1:18080/anthropic
export ANTHROPIC_AUTH_TOKEN=praxis-substitute:anthropic
unset ANTHROPIC_API_KEY CLAUDE_CODE_OAUTH_TOKEN
claude
```

Any other `Authorization` value, including a real Anthropic key or token, is
refused with 403 and never forwarded.

With the gateway enabled, `POST /v1/messages` (without the prefix) is also
forwarded to Anthropic with the client's own `Authorization`, for a Claude
Code that is logged in itself: set only `ANTHROPIC_BASE_URL=http://127.0.0.1:18080`.
The broker's token is never added there, and the placeholder is refused
there.

## Run under systemd

`contrib/quadlet/` has rootless Quadlet units for the same pod that run the
published images and mount nothing from a checkout; see
[INTERNALS.md](INTERNALS.md#quadlet).

For operational procedures, security properties, test topology, publishing,
and provenance, read [INTERNALS.md](INTERNALS.md).
