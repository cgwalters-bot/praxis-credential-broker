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
```

Create and export a client API key (at least 32 bytes), initialize the Podman
secrets, then complete the Codex device login and start the pod:

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

Praxis listens on `127.0.0.1:18080` and accepts `POST /v1/responses`. Use
`PRAXIS_API_KEY`, not a ChatGPT credential.

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

Known-working OpenCode configuration:

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

For operational procedures, security properties, test topology, publishing,
and provenance, read [INTERNALS.md](INTERNALS.md).
