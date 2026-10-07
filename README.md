> **Disclaimer: All code in this repository is LLM-generated. See [LLMs](https://github.com/cgwalters/cgwalters#llms).**

# praxis-credential-broker

> **Alpha:** this is an architecture spike, not a production-ready service. See
> [INTERNALS.md](INTERNALS.md) for architecture, security, operations, and
> development details.

A credential broker built on [Praxis AI](https://github.com/praxis-proxy/ai).
One listener serves the ChatGPT Codex Responses API, authenticated through
`codex login`, under `/v1`, and the Anthropic Messages API under
`/anthropic/v1`. Every route has a credential mode:

- **injected**: the broker supplies its own credential (the Codex login, or a
  Claude subscription token), and only for requests that carry the token of
  a registered CI run. This is how agent runs use the broker: they never see
  a real credential, and each run is capped.
- **pass-through**: the caller's own Claude credential is forwarded to
  Anthropic, never stored, and only metered. This is for interactive Claude
  Code on your own subscription.

Every request that reaches a provider is metered.

## Run published images

Requires Podman, `curl`, and this repository's scripts. The default images are:

```text
ghcr.io/cgwalters-bot/praxis-credential-broker-proxy:main
ghcr.io/cgwalters-bot/praxis-credential-broker-provider-codex:main
ghcr.io/cgwalters-bot/praxis-credential-broker-gateway:main
```

The gateway image is Praxis AI, built from source with this repository's
filters, and with its routes built in.

Create the internal channel secret, store the Claude subscription token the
broker injects (from `claude setup-token` on a trusted machine; the script
reads it from the terminal without echo, or from standard input), complete
the Codex device login, and start the pod:

```sh
bash scripts/init-secrets
bash scripts/init-anthropic-token
# or: password-manager read claude/oauth-token | bash scripts/init-anthropic-token
bash scripts/native-pod.sh login
export PRAXIS_RUN_TOKEN_POLICY=$HOME/run-token-policy.yaml  # see below
bash scripts/native-pod.sh up
bash scripts/native-pod.sh health
# later
bash scripts/native-pod.sh down
```

`down` preserves the secrets and Codex login for a later restart. GHCR access
policies may require `podman login ghcr.io`.

Which CI jobs may register runs, and so use the broker's credentials, is a
policy file: copy `run-token-policy.yaml`, name the workflows and the
repository ids that may register, and point `PRAXIS_RUN_TOKEN_POLICY` at the
copy. Without it no run can register, and only pass-through requests are
served.

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

## Agent runs: injected credentials

Praxis listens on `127.0.0.1:18080`. A CI job's supervisor registers its run
with the job's GitHub Actions OIDC token, for the audience
`praxis-credential-broker`, and hands only the returned run token to the
agent:

```sh
curl -X POST -H "Authorization: Bearer $OIDC_TOKEN" http://127.0.0.1:18080/v1/runs
# 201 {"token": "praxis-run-...", "usage": {...}}
```

The agent's sandbox must not get the job's `ACTIONS_ID_TOKEN_REQUEST_*`
variables; see [INTERNALS.md](INTERNALS.md#run-tokens). When the job ends,
`DELETE /v1/runs/self` with the run token finishes the run and returns its
usage record.

Codex sends the run token as its API key, from a provider definition in
`~/.codex/config.toml`:

```toml
[model_providers.praxis]
name = "Local Praxis"
base_url = "http://127.0.0.1:18080/v1"
wire_api = "responses"
env_key = "PRAXIS_RUN_TOKEN"
```

and a named profile in `~/.codex/praxis.config.toml`:

```toml
model_provider = "praxis"
```

OpenCode takes it as its `apiKey`:

```json
{
  "provider": {
    "praxis": {
      "npm": "@ai-sdk/openai",
      "options": {
        "baseURL": "http://127.0.0.1:18080/v1",
        "apiKey": "{env:PRAXIS_RUN_TOKEN}"
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

```sh
codex --profile praxis
opencode run --model praxis/gpt-6-astra
```

Claude Code sends a fixed placeholder as its credential, which selects the
broker's Claude token, and the run token in a header of its own. It appends
`/v1/messages` to the base URL:

```sh
export ANTHROPIC_BASE_URL=http://127.0.0.1:18080/anthropic
export ANTHROPIC_AUTH_TOKEN=praxis-substitute:anthropic
export ANTHROPIC_CUSTOM_HEADERS="x-run-token: $PRAXIS_RUN_TOKEN"
unset ANTHROPIC_API_KEY CLAUDE_CODE_OAUTH_TOKEN
claude
```

A request with the placeholder but without a valid run token is refused with
401. Each run is capped (20M tokens per API by default), and a request over
its run's cap gets 429. Injecting a subscription token at a gateway is
undocumented by Anthropic; read the risks in
[INTERNALS.md](INTERNALS.md#risks) first.

### More workflows than a list

The policy's `workflows` names each workflow that may register, in its own
repository and at one ref. Two entries, off unless the policy file has
them, admit more: `any_workflow` every workflow of the repositories or
owners it lists (or of all of GitHub), and `called_workflows` a named
workflow wherever it runs, which is what a reusable workflow called from
another repository needs.

```yaml
any_workflow:
  repositories:
    owner_ids: [333055778]     # every repository of this owner
called_workflows:
  - workflow: OWNER/REPO/.github/workflows/FILE.yml
    ref: refs/heads/main       # or sha: the commit callers pin
    callers:
      repository_ids: [1372023819]
```

The token is still verified in full and the job still proves it is a job,
so its agent, which holds no identity token, cannot register a run of its
own by asking. The run has the same caps and usage record, which says
which entry admitted it. **Either entry widens who can spend the broker's
credentials** to whoever can push a workflow to an admitted repository,
which includes an agent that holds a GitHub credential able to. Read
[INTERNALS.md](INTERNALS.md#admitting-more-workflows) first: it says which
claims each form checks, and has the exact text for this deployment.

### Runs without proof

A job with no GitHub Actions identity to show, or a deployment that trusts
its private network, can have runs register on their word alone. This is
off unless the policy file has `unproven`:

```yaml
unproven:
  max_registrations: 8   # in any hour, from all callers together
```

Then a request with no `Authorization` registers the run it names (letters,
digits, `.`, `_` and `-`, at most 128), and gets a run token with the same
caps, lifetime and usage record as any other:

```sh
curl -X POST -H "x-run-id: $RUN_NAME" http://127.0.0.1:18080/v1/runs
# 201 {"token": "praxis-run-...", "usage": {"proof": "none", "run": "...", ...}}
```

**Whatever can reach the port can then spend the broker's credentials**,
the agent of a job included, which can register a run of its own for a
fresh cap. Read [INTERNALS.md](INTERNALS.md#registering-a-run-without-proof)
for what that gives up, the exact steps to turn it on and how to turn it
off.

## Interactive agents: operator tokens

A person's own agent, such as an interactive OpenCode or Codex on a
workstation, has no CI job to register a run with. The deployment can name
operators instead, each with a long-lived token that is admitted wherever a
run token is, for the injected clusters its entry lists:

```sh
bash scripts/create-operator-token me inference-backend
# writes ~/.config/praxis-credential-broker/operator-token-me (mode 0600) and
# prints the entry, with only the token's SHA-256, for operator-tokens.yaml
```

Put that entry in your copy of `operator-tokens.yaml`, point
`PRAXIS_OPERATOR_TOKENS` at it for `native-pod.sh up` (under Quadlet, a
[drop-in](INTERNALS.md#quadlet) mounts it), and restart the pod. The client sends the token as its API key; OpenCode can read it
from the file, so the token is in no configuration:

```json
"options": {
  "baseURL": "http://127.0.0.1:18080/v1",
  "apiKey": "{file:~/.config/praxis-credential-broker/operator-token-me}"
}
```

An operator is capped like a run (20M tokens per API in a sliding 6 hours),
and `GET /usage` counts what it used under `operators`, by its name. See
[INTERNALS.md](INTERNALS.md#operator-tokens) for what the token can do.

## Interactive Claude Code: pass-through

A Claude Code that is logged in itself (`claude auth login`) can use the
same prefix: any `Authorization` other than the placeholder is forwarded to
`https://api.anthropic.com` as it is, and never stored. No run token is
needed, and the broker's token is never added. The broker meters these
requests but does not cap them; your own subscription's limits apply.

```sh
export ANTHROPIC_BASE_URL=http://127.0.0.1:18080/anthropic
unset ANTHROPIC_AUTH_TOKEN ANTHROPIC_API_KEY
claude
```

From another tailnet host, use the broker host's MagicDNS name instead, such
as `http://xenon.tailf2eb8.ts.net:18080/anthropic`, once the pod is published
on the tailnet (see [INTERNALS.md](INTERNALS.md#quadlet)). The old
`/v1/messages` route without the prefix, and the separate listener on port
18083, are gone.

## Run under systemd

`contrib/quadlet/` has rootless Quadlet units for the same pod that run the
published images and mount nothing from a checkout; see
[INTERNALS.md](INTERNALS.md#quadlet).

For operational procedures, security properties, test topology, publishing,
and provenance, read [INTERNALS.md](INTERNALS.md).
