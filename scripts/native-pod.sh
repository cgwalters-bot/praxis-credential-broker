#!/usr/bin/env bash
set -euo pipefail

root=$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)
mode=${1:?usage: native-pod.sh login|up|health|logs|down|rotate-agent-secret|reset-secrets|reset-auth|test}
pod=praxis-credential-broker
socket_volume=praxis-credential-broker-socket
client_secret=praxis-credential-broker-client-auth
channel_secret=praxis-credential-broker-agent-channel
anthropic_secret=praxis-credential-broker-anthropic-oauth
proxy_image=${PRAXIS_PROXY_IMAGE-ghcr.io/cgwalters-bot/praxis-credential-broker-proxy:main}
provider_codex_image=${PRAXIS_PROVIDER_CODEX_IMAGE-ghcr.io/cgwalters-bot/praxis-credential-broker-provider-codex:main}
gateway_image=${PRAXIS_GATEWAY_IMAGE-ghcr.io/cgwalters-bot/praxis-credential-broker-gateway:main}

# Where the gateway reads the run registration policy (run-token-policy.yaml).
policy_target=/etc/praxis-credential-broker/run-token-policy.yaml
policy=
# And who holds an operator token (operator-tokens.yaml), if anyone.
operators_target=/etc/praxis-credential-broker/operator-tokens.yaml
operators=
if [[ $mode == up ]]; then
    for old in PRAXIS_CLIENT_AUTH_MODE PRAXIS_ANTHROPIC_GATEWAY; do
        if [[ -n ${!old+set} ]]; then
            echo "$old is no longer used: Praxis authenticates runs, and always serves /anthropic; see INTERNALS.md" >&2
            exit 2
        fi
    done
    policy=${PRAXIS_RUN_TOKEN_POLICY-}
    operators=${PRAXIS_OPERATOR_TOKENS-}
    for mounted in "PRAXIS_RUN_TOKEN_POLICY run-token-policy.yaml $policy" \
        "PRAXIS_OPERATOR_TOKENS operator-tokens.yaml $operators"; do
        read -r variable example file <<<"$mounted"
        [[ -n $file ]] || continue
        [[ -f $file ]] || { echo "$variable must name your copy of $example" >&2; exit 2; }
        # The gateway runs as 65532, which reads it as "other".
        [[ $(stat -L -c %A "$file") == ???????r?? ]] || {
            echo "$variable must be world-readable (chmod 0644); it holds no secrets" >&2
            exit 2
        }
    done
fi

mounts() {
    podman inspect "$1" | python3 -c 'import json,sys; print("\n".join(m["Destination"] for m in (json.load(sys.stdin)[0]["Mounts"] or [])))'
}

secret_names() {
    podman inspect "$1" | python3 -c 'import json,sys; print("\n".join(s["Name"] for s in (json.load(sys.stdin)[0]["Config"].get("Secrets") or [])))'
}

check_secret() {
    podman inspect "$1" | python3 -c 'import json,sys; x=json.load(sys.stdin)[0]; name,target=sys.argv[1:]; found=[s for s in (x["Config"].get("Secrets") or []) if s["Name"] == name]; assert len(found) == 1 and found[0]["UID"] == 65532 and found[0]["GID"] == 65532 and found[0]["Mode"] == 0o400; assert any(target in arg for arg in x["Config"]["CreateCommand"])' "$2" "$3"
}

check_hardening() {
    podman inspect "$1" | python3 -c 'import json,sys; x=json.load(sys.stdin)[0]; assert x["Config"]["User"] == "65532:65532" and x["HostConfig"]["ReadonlyRootfs"] and "no-new-privileges" in x["HostConfig"]["SecurityOpt"] and len(x["HostConfig"]["CapDrop"]) >= 1'
}

# The routes come from the image, never from a mounted checkout.
check_no_config_mount() {
    podman inspect "$1" | python3 -c 'import json,sys; mounts=json.load(sys.stdin)[0]["Mounts"] or []; assert not any(m["Destination"].rstrip("/") == "/etc/praxis" or m["Destination"].startswith("/etc/praxis/") for m in mounts), mounts'
}

# A GET for /anthropic gets 403 from the first deny filter, without reaching
# any upstream, which shows that the Anthropic routes are served. (Not for
# /anthropic/v1/messages, whose body validation would answer first.)
anthropic_status() {
    curl --silent --output /dev/null --write-out '%{http_code}' --max-time 2 \
        "http://127.0.0.1:$1/anthropic/v1/messages/count_tokens"
}

# POST /v1/runs without an OIDC token: 401 when runs can register, 503
# without a policy file, and 400 (for the missing x-run-id) when the policy
# has `unproven`, so that a run registers without one.
runs_status() {
    curl --silent --output /dev/null --write-out '%{http_code}' --max-time 2 \
        --request POST "http://127.0.0.1:$1/v1/runs"
}

remove_pod() {
    podman pod rm -f "$1" >/dev/null 2>&1 || true
}

remove_socket() {
    podman volume rm "$1" >/dev/null 2>&1 || true
}

production_down() {
    remove_pod "$pod"
    remove_socket "$socket_volume"
}

remove_secrets() {
    podman secret rm --ignore "$@" >/dev/null
}

require_stopped_pod() {
    if podman pod exists "$pod" >/dev/null 2>&1; then
        echo "production pod is running; run '$0 down' first" >&2
        exit 1
    fi
}

case "$mode" in
    down)
        production_down
        exit 0
        ;;
    health)
        curl --fail --silent http://127.0.0.1:18080/healthz
        printf '\n'
        [[ $(anthropic_status 18080) == 403 ]] || { echo 'Anthropic routes: not ready' >&2; exit 1; }
        echo 'Anthropic routes: ready'
        case $(runs_status 18080) in
            401) echo 'run registration: ready' ;;
            400) echo 'run registration: ready, and OPEN: the policy has "unproven", so any client that reaches the port registers runs without proof' ;;
            503) echo 'run registration: no policy, so only pass-through requests are served' ;;
            *) echo 'run registration: not ready' >&2; exit 1 ;;
        esac
        exit 0
        ;;
    logs)
        podman pod logs "$pod"
        exit 0
        ;;
    login)
        [[ -n $provider_codex_image ]] || { echo 'PRAXIS_PROVIDER_CODEX_IMAGE must not be empty' >&2; exit 2; }
        require_stopped_pod
        podman run --rm -it --network=host -v praxis-credential-broker-auth:/codex-home:Z \
            -e CODEX_HOME=/codex-home -- "$provider_codex_image" login
        exit 0
        ;;
    rotate-agent-secret)
        require_stopped_pod
        bash "$root/scripts/create-agent-secret" "$channel_secret"
        exit 0
        ;;
    reset-secrets)
        test "${RESET_SECRETS:-}" = RESET
        require_stopped_pod
        # The client secret is only removed: Praxis authenticates runs now.
        remove_secrets "$client_secret" "$channel_secret" "$anthropic_secret"
        exit 0
        ;;
    reset-auth)
        test "${RESET_AUTH:-}" = RESET
        production_down
        podman volume rm praxis-credential-broker-auth
        exit 0
        ;;
    up|test)
        ;;
    *)
        echo "unknown mode: $mode" >&2
        exit 2
        ;;
esac

if [[ $mode == up ]]; then
    [[ -n $proxy_image ]] || { echo 'PRAXIS_PROXY_IMAGE must not be empty' >&2; exit 2; }
    [[ -n $provider_codex_image ]] || { echo 'PRAXIS_PROVIDER_CODEX_IMAGE must not be empty' >&2; exit 2; }
    [[ -n $gateway_image ]] || { echo 'PRAXIS_GATEWAY_IMAGE must not be empty' >&2; exit 2; }
    podman secret exists "$channel_secret" || { echo "missing Podman secret: $channel_secret (run 'bash scripts/init-secrets')" >&2; exit 1; }
    podman secret exists "$anthropic_secret" || { echo "missing Podman secret: $anthropic_secret (run 'bash scripts/init-anthropic-token')" >&2; exit 1; }
    if podman pod exists "$pod" >/dev/null 2>&1; then
        echo "pod $pod already exists; run 'bash scripts/native-pod.sh down' before starting it again" >&2
        exit 1
    fi
    podman volume create "$socket_volume" >/dev/null
    # shellcheck disable=SC2317
    cleanup() { remove_pod "$pod"; remove_socket "$socket_volume"; }
    trap cleanup EXIT INT TERM
    podman pod create --name "$pod" --publish 127.0.0.1:18080:8081 >/dev/null
    common=(--pod "$pod" --user 65532:65532 --read-only --cap-drop=ALL --security-opt=no-new-privileges)
    # Praxis authenticates clients, by run token, and the proxy behind it is
    # reachable only in the pod, so it admits what Praxis forwards.
    podman create "${common[@]}" --name praxis-credential-broker-proxy \
        --env CLIENT_AUTH_MODE=disabled \
        --secret "$channel_secret,target=/run/secrets/channel/agent-channel-key,uid=65532,gid=65532,mode=0400" \
        --volume "$socket_volume:/run/praxis-credentials:Z" \
        --tmpfs /tmp:rw,noexec,nosuid,nodev,size=64m \
        -- "$proxy_image" >/dev/null
    podman create "${common[@]}" --name praxis-credential-broker-provider-codex \
        --env CODEX_HOME=/codex-home --volume praxis-credential-broker-auth:/codex-home:Z \
        --volume "$socket_volume:/run/praxis-credentials:Z" \
        --secret "$channel_secret,target=/run/secrets/channel/agent-channel-key,uid=65532,gid=65532,mode=0400" \
        --tmpfs /tmp:rw,noexec,nosuid,nodev,size=64m \
        -- "$provider_codex_image" >/dev/null
    # The gateway image carries its own routes; only this container holds
    # the Claude token. Without a policy no run can register.
    policy_mount=()
    if [[ -n $policy ]]; then
        policy_mount=(--volume "$(realpath "$policy"):$policy_target:ro,Z")
    fi
    if [[ -n $operators ]]; then
        policy_mount+=(--volume "$(realpath "$operators"):$operators_target:ro,Z")
    fi
    podman create "${common[@]}" --name praxis-credential-broker-praxis --no-healthcheck \
        --secret "$anthropic_secret,target=/run/secrets/anthropic/oauth-token,uid=65532,gid=65532,mode=0400" \
        "${policy_mount[@]}" --tmpfs /tmp:rw,noexec,nosuid,nodev,size=64m \
        -- "$gateway_image" >/dev/null
    expected=(praxis-credential-broker-proxy praxis-credential-broker-provider-codex praxis-credential-broker-praxis)
    diagnostics() {
        echo "native pod startup failed; redacted container status:" >&2
        podman ps --filter label=io.podman.pod.name="$pod" --format '{{.Names}} {{.Status}}' >&2 || true
    }
    fail_startup() { diagnostics; exit 1; }
    podman pod start "$pod" >/dev/null || fail_startup
    for _ in {1..30}; do
        all_running=true
        for c in "${expected[@]}"; do
            if ! podman container exists "$c" || ! podman inspect "$c" | python3 -c 'import json,sys; raise SystemExit(0 if json.load(sys.stdin)[0]["State"]["Running"] else 1)'; then
                all_running=false
                break
            fi
        done
        [[ $all_running == true ]] && break
        sleep 1
    done
    [[ $all_running == true ]] || fail_startup
    health_ready=false
    for _ in {1..30}; do
        if curl --fail --silent --show-error --max-time 2 http://127.0.0.1:18080/healthz >/dev/null; then
            health_ready=true
            break
        fi
        sleep 1
        all_running=true
        for c in "${expected[@]}"; do
            podman inspect "$c" | python3 -c 'import json,sys; raise SystemExit(0 if json.load(sys.stdin)[0]["State"]["Running"] else 1)' || all_running=false
        done
        [[ $all_running == true ]] || fail_startup
    done
    [[ $health_ready == true ]] || { echo 'native pod startup timed out waiting for healthz' >&2; fail_startup; }
    [[ $(anthropic_status 18080) == 403 ]] || { echo 'native pod started without its Anthropic routes' >&2; fail_startup; }
    echo 'Started praxis-credential-broker; healthz is ready.'
    trap - EXIT INT TERM
    exit 0
fi


[[ $mode == test ]] || { echo "unknown mode: $mode" >&2; exit 2; }
# Wait up to a minute each for Praxis to report healthy and for the mock
# upstream, which starts on its own schedule, to answer.
wait_ready() {
    local url i
    for url in http://127.0.0.1:18081/healthz http://127.0.0.1:18082/counters; do
        i=0; while [ "$i" -lt 60 ]; do curl --fail --silent "$url" >/dev/null && break; sleep 1; i=$((i + 1)); done; test "$i" -lt 60
    done
}
http_status() {
    curl --silent --output /dev/null --write-out '%{http_code}' "$@"
}
# Whether one line of $logs has every argument. Each grep reads to the end:
# in long logs, one that left at its first match would end the pipe under
# its writer, which pipefail takes for a failure, and a check that the logs
# lack something would pass on it.
logged() {
    local lines=$logs word
    for word; do lines=$(grep -F -- "$word" <<<"$lines") || return 1; done
}
test_pod=praxis-credential-broker-test
test_socket=praxis-credential-broker-test-socket
test_client=praxis-credential-broker-test-client
test_channel=praxis-credential-broker-test-channel
test_anthropic=praxis-credential-broker-test-pod-anthropic
test_anthropic_token=sk-ant-oat01-SYNTHETIC-POD-TOKEN-0123456789abcdef
test_dir=$(mktemp -d)
cleanup() {
    remove_pod "$test_pod"
    remove_socket "$test_socket"
    remove_secrets "$test_client" "$test_channel" "$test_anthropic"
    rm -rf "$test_dir"
}
trap cleanup EXIT INT TERM
remove_secrets "$test_client" "$test_channel" "$test_anthropic"
printf '%s' 'synthetic-reset-check' | podman secret create --replace "$test_client" - >/dev/null
remove_secrets "$test_client"
printf '%s' 'synthetic-agent-channel-012345678901234567890123' | podman secret create --replace "$test_channel" - >/dev/null
printf '%s' "$test_anthropic_token" | podman secret create --replace "$test_anthropic" - >/dev/null

# The registration policy for a test workflow, whose OIDC tokens are signed
# by the test-only key whose key set the mock serves, and for the second
# pass praxis.yaml with a per-run cap of 150 tokens and that policy with
# `unproven`, admitting two registrations without proof, and with the
# entries that admit a reusable workflow called from the test owner's
# repositories and any workflow of another owner's.
test_workflow=owner/repo/.github/workflows/agent.yml@refs/heads/main
called_workflow=lib/agentic/.github/workflows/job.yml
caller=owner/repo/.github/workflows/caller.yml@refs/heads/main
called_claims="{\"job_workflow_ref\": \"$called_workflow@refs/heads/main\", \"workflow_ref\": \"$caller\"}"
python3 - "$root/praxis.yaml" "$test_dir" "$test_workflow" "$called_workflow" <<'PY'
import json, sys
source, target, workflow, called = sys.argv[1:]
config = open(source).read()
old = 'capacity: 20000000\n            reserved_tokens: 10000'
assert config.count(old) == 2, old
open(f'{target}/praxis.yaml', 'w').write(config.replace(old, 'capacity: 150\n            reserved_tokens: 10'))
policy = {'workflows': [workflow], 'repository_ids': [7], 'jwks_url': 'http://127.0.0.1:18081/jwks'}
open(f'{target}/run-token-policy.yaml', 'w').write(json.dumps(policy))
policy['unproven'] = {'max_registrations': 2}
policy['called_workflows'] = [{'workflow': called, 'ref': 'refs/heads/main', 'callers': {'owner_ids': [70]}}]
policy['any_workflow'] = {'repositories': {'owner_ids': [71]}}
open(f'{target}/unproven-policy.yaml', 'w').write(json.dumps(policy))
PY
chmod 0755 "$test_dir"
chmod 0644 "$test_dir"/*
# An OIDC token of run $1 of workflow $2, with the claims of the JSON
# object $3, if any, over its own.
test_jwt() {
    local header payload signature claims=${3:-}
    [[ -n $claims ]] || claims='{}'
    b64url() { python3 -c 'import base64,sys; print(base64.urlsafe_b64encode(sys.stdin.buffer.read()).rstrip(b"=").decode())'; }
    header=$(printf '{"alg":"RS256","typ":"JWT","kid":"praxis-test-key"}' | b64url)
    payload=$(python3 -c 'import json,sys,time,uuid; now=int(time.time()); print(json.dumps({"iss": "https://token.actions.githubusercontent.com", "aud": "praxis-credential-broker", "iat": now, "nbf": now, "exp": now + 300, "jti": str(uuid.uuid4()), "repository": "owner/repo", "repository_id": "7", "repository_owner_id": "70", "run_id": sys.argv[1], "run_attempt": "1", "job_workflow_ref": sys.argv[2], "workflow_ref": sys.argv[2], "event_name": "workflow_dispatch", **json.loads(sys.argv[3])}))' "$1" "$2" "$claims" | tr -d '\n' | b64url)
    signature=$(printf '%s.%s' "$header" "$payload" | openssl dgst -sha256 -sign "$root/crates/praxis-gateway/testdata/oidc-test-key.pem" -binary | b64url)
    printf '%s.%s.%s' "$header" "$payload" "$signature"
}
# The pod as `up` creates it, with the synthetic provider and the mock
# upstream and $test_policy as its registration policy; extra arguments go
# to the Praxis container.
test_policy=run-token-policy.yaml
start_test_pod() {
    remove_pod "$test_pod"
    remove_socket "$test_socket"
    podman volume create "$test_socket" >/dev/null
    podman pod create --name "$test_pod" \
        --publish 127.0.0.1:18081:8081 --publish 127.0.0.1:18082:18081 --publish 127.0.0.1:19090:19090 >/dev/null
    common=(--pod "$test_pod" --user 65532:65532 --read-only --cap-drop=ALL --security-opt=no-new-privileges)
    podman create "${common[@]}" --name "$test_pod-proxy" --env CLIENT_AUTH_MODE=disabled \
        --secret "$test_channel,target=/run/secrets/channel/agent-channel-key,uid=65532,gid=65532,mode=0400" \
        --volume "$test_socket:/run/praxis-credentials:Z" --tmpfs /tmp:rw,noexec,nosuid,nodev,size=64m \
        localhost/praxis-credential-proxy:test >/dev/null
    podman create "${common[@]}" --name "$test_pod-agent" \
        --secret "$test_channel,target=/run/secrets/channel/agent-channel-key,uid=65532,gid=65532,mode=0400" \
        --volume "$test_socket:/run/praxis-credentials:Z" \
        localhost/praxis-provider-codex:synthetic >/dev/null
    podman create "${common[@]}" --name "$test_pod-praxis" --no-healthcheck \
        --secret "$test_anthropic,target=/run/secrets/anthropic/oauth-token,uid=65532,gid=65532,mode=0400" \
        --volume "$test_dir/$test_policy:$policy_target:ro,Z" "$@" \
        localhost/praxis-gateway:test >/dev/null
    podman create "${common[@]}" --name "$test_pod-mock" localhost/praxis-mock-upstream:dev >/dev/null
    podman pod start "$test_pod" >/dev/null
}
mock_counters() {
    python3 -c 'import json,sys,urllib.request; x=json.load(urllib.request.urlopen("http://127.0.0.1:18082/counters")); assert x == json.loads(sys.argv[1]), x' "$1"
}

# First pass: the routes baked into the image, as `up` runs them.
start_test_pod
proxy=$test_pod-proxy
agent=$test_pod-agent
check_secret "$proxy" "$test_channel" /run/secrets/channel/agent-channel-key
check_secret "$agent" "$test_channel" /run/secrets/channel/agent-channel-key
check_secret "$test_pod-praxis" "$test_anthropic" /run/secrets/anthropic/oauth-token
[[ $(secret_names "$test_pod-praxis") == "$test_anthropic" ]]
for c in "$proxy" "$agent"; do secret_names "$c" | grep -qx "$test_anthropic" && exit 1; done
secret_names "$test_pod-mock" | grep -q . && exit 1
for c in "$proxy" "$agent" "$test_pod-praxis" "$test_pod-mock"; do check_hardening "$c"; done
check_no_config_mount "$test_pod-praxis"
socket_dir=$(podman volume inspect "$test_socket" | python3 -c 'import json,sys; print(json.load(sys.stdin)[0]["Mountpoint"])')
for _ in {1..30}; do [[ -S "$socket_dir/agent.sock" ]] && break; sleep 1; done
[[ -S "$socket_dir/agent.sock" ]]
[[ $(stat -c '%a' "$socket_dir/agent.sock") == 660 ]]
socket_label=$(ls -Zd "$socket_dir/agent.sock")
[[ $socket_label != *' ? '* ]]
wait_ready
[[ $(anthropic_status 18081) == 403 ]]
[[ $(runs_status 18081) == 401 ]]
# Nor does naming a run register it: the policy has no `unproven`.
test "$(http_status -X POST -H 'x-run-id: pod-run' http://127.0.0.1:18081/v1/runs)" = 401
curl --fail --silent http://127.0.0.1:18081/usage | grep -Fq unproven && exit 1
curl --fail --silent http://127.0.0.1:18082/reset >/dev/null
# Injected routes refuse requests without a registered run's token.
test "$(http_status -H 'Content-Type: application/json' --data '{}' http://127.0.0.1:18081/v1/responses)" = 401
test "$(http_status -H 'Authorization: Bearer caller-value-must-not-reach-upstream' -H 'Content-Type: application/json' --data '{}' http://127.0.0.1:18081/v1/responses)" = 401
test "$(http_status -H 'Authorization: Bearer praxis-substitute:anthropic' -H 'Content-Type: application/json' --data '{}' http://127.0.0.1:18081/anthropic/v1/messages/count_tokens)" = 401
mock_counters '{"calls": 0, "observed": []}'
test "$(http_status -X POST -H "Authorization: Bearer $(test_jwt 1 owner/repo/.github/workflows/devspace.yml@refs/heads/main)" http://127.0.0.1:18081/v1/runs)" = 403
# Nor may a reusable workflow called from the test repository, or a
# workflow of another repository: the policy has neither `called_workflows`
# nor `any_workflow`.
test "$(http_status -X POST -H "Authorization: Bearer $(test_jwt 1 "$test_workflow" "$called_claims")" http://127.0.0.1:18081/v1/runs)" = 403
test "$(http_status -X POST -H "Authorization: Bearer $(test_jwt 1 "$test_workflow" '{"repository_id": "80", "repository_owner_id": "71"}')" http://127.0.0.1:18081/v1/runs)" = 403
jwt=$(test_jwt 1 "$test_workflow")
registration=$(curl --fail --silent -X POST -H "Authorization: Bearer $jwt" http://127.0.0.1:18081/v1/runs)
run_token=$(python3 -c 'import json,sys; x=json.loads(sys.argv[1]); assert x["usage"]["run_id"] == 1, x; print(x["token"])' "$registration")
# A retry with the same OIDC token replaces the run token; another OIDC
# token for the same run is refused.
lost_token=$run_token
registration=$(curl --fail --silent -X POST -H "Authorization: Bearer $jwt" http://127.0.0.1:18081/v1/runs)
run_token=$(python3 -c 'import json,sys; x=json.loads(sys.argv[1]); assert x["token"] != sys.argv[2], x; print(x["token"])' "$registration" "$lost_token")
test "$(http_status -H "Authorization: Bearer $lost_token" http://127.0.0.1:18081/v1/runs/self)" = 401
test "$(http_status -X POST -H "Authorization: Bearer $(test_jwt 1 "$test_workflow")" http://127.0.0.1:18081/v1/runs)" = 409
# Through credential-proxy, which replaces the run token with the provider
# credentials and recovers from the mock's first 401.
body=$(curl --fail --silent -H "Authorization: Bearer $run_token" -H 'Content-Type: application/json' --data '{"model":"synthetic"}' http://127.0.0.1:18081/v1/responses); python3 -c 'import json,sys; assert json.loads(sys.argv[1])["id"] == "synthetic"' "$body"
mock_counters '{"calls": 2, "observed": [[true, true]]}'
python3 -c 'import json,urllib.request; x=json.load(urllib.request.urlopen("http://127.0.0.1:19090/counters")); assert x["recover"] == 1 and x["acquire"] == 2, x'
sleep 1
python3 -c 'import json,urllib.request; assert json.load(urllib.request.urlopen("http://127.0.0.1:18082/counters"))["calls"] == 2'
stream=$(curl --fail --silent -H "Authorization: Bearer $run_token" -H 'Accept: text/event-stream' -H 'Content-Type: application/json' --data '{"model":"synthetic"}' http://127.0.0.1:18081/v1/responses); case "$stream" in *response.output_text.delta*function_call_arguments.delta*response.completed*) ;; *) exit 1;; esac
usage=$(curl --fail --silent -H "Authorization: Bearer $run_token" http://127.0.0.1:18081/v1/runs/self)
python3 -c 'import json,sys; x=json.loads(sys.argv[1]); assert (x["state"], x["requests"], x["unmetered"], x["tokens"]["total"]) == ("active", 2, 0, 200), x' "$usage"
usage=$(curl --fail --silent -X DELETE -H "Authorization: Bearer $run_token" http://127.0.0.1:18081/v1/runs/self)
python3 -c 'import json,sys; x=json.loads(sys.argv[1]); assert x["state"] == "finished" and x["tokens"]["total"] == 200, x' "$usage"
test "$(http_status -H "Authorization: Bearer $run_token" -H 'Content-Type: application/json' --data '{}' http://127.0.0.1:18081/v1/responses)" = 401
logs=$(podman pod logs "$test_pod")
for secret in synthetic-agent-channel-012345678901234567890123 caller-value-must-not-reach-upstream "$test_anthropic_token" "$run_token" "$lost_token" "$jwt"; do
    logged "$secret" && exit 1
done
logged 'run usage' 'finished'
logged 'request usage' injected
logged unproven && exit 1
logged 'ANY WORKFLOW' && exit 1
logged 'called from other repositories' && exit 1
podman inspect "$test_pod-praxis" | grep -Fq "$test_anthropic_token" && exit 1

# Second pass: a per-run cap of 150 tokens, which the second response
# overshoots and the third is refused, under the policy with `unproven`.
test_policy=unproven-policy.yaml
start_test_pod --volume "$test_dir/praxis.yaml:/etc/praxis/praxis.yaml:ro,Z"
wait_ready
[[ $(runs_status 18081) == 400 ]]
curl --fail --silent http://127.0.0.1:18082/reset >/dev/null
registration=$(curl --fail --silent -X POST -H "Authorization: Bearer $(test_jwt 2 "$test_workflow")" http://127.0.0.1:18081/v1/runs)
run_token=$(python3 -c 'import json,sys; print(json.loads(sys.argv[1])["token"])' "$registration")
for _ in 1 2; do
    stream=$(curl --fail --silent -H "Authorization: Bearer $run_token" -H 'Accept: text/event-stream' -H 'Content-Type: application/json' --data '{"model":"synthetic"}' http://127.0.0.1:18081/v1/responses); case "$stream" in *response.completed*) ;; *) exit 1;; esac
done
test "$(http_status -H "Authorization: Bearer $run_token" -H 'Content-Type: application/json' --data '{"model":"synthetic"}' http://127.0.0.1:18081/v1/responses)" = 429
mock_counters '{"calls": 4, "observed": [[true, true], [true, true]]}'
# A run registered without proof: once per name, within the quota of two,
# with a cap of its own, metered under its name and ended like any other.
registration=$(curl --fail --silent -X POST -H 'x-run-id: pod-run' http://127.0.0.1:18081/v1/runs)
unproven_token=$(python3 -c 'import json,sys; x=json.loads(sys.argv[1]); assert (x["usage"]["proof"], x["usage"]["run"]) == ("none", "pod-run"), x; print(x["token"])' "$registration")
test "$(http_status -X POST -H 'x-run-id: pod-run' http://127.0.0.1:18081/v1/runs)" = 409
test "$(http_status -X POST -H 'x-run-id: pod-run-2' http://127.0.0.1:18081/v1/runs)" = 201
test "$(http_status -X POST -H 'x-run-id: pod-run-3' http://127.0.0.1:18081/v1/runs)" = 429
test "$(http_status -X POST -H "Authorization: Bearer $(test_jwt 3 "$test_workflow")" http://127.0.0.1:18081/v1/runs)" = 201
for _ in 1 2; do
    stream=$(curl --fail --silent -H "Authorization: Bearer $unproven_token" -H 'Accept: text/event-stream' -H 'Content-Type: application/json' --data '{"model":"synthetic"}' http://127.0.0.1:18081/v1/responses); case "$stream" in *response.completed*) ;; *) exit 1;; esac
done
test "$(http_status -H "Authorization: Bearer $unproven_token" -H 'Content-Type: application/json' --data '{"model":"synthetic"}' http://127.0.0.1:18081/v1/responses)" = 429
usage=$(curl --fail --silent -X DELETE -H "Authorization: Bearer $unproven_token" http://127.0.0.1:18081/v1/runs/self)
python3 -c 'import json,sys; x=json.loads(sys.argv[1]); assert (x["proof"], x["run"], x["state"], x["requests"], x["tokens"]["total"]) == ("none", "pod-run", "finished", 2, 200), x' "$usage"
test "$(http_status -H "Authorization: Bearer $unproven_token" -H 'Content-Type: application/json' --data '{}' http://127.0.0.1:18081/v1/responses)" = 401
usage=$(curl --fail --silent http://127.0.0.1:18081/usage)
python3 -c 'import json,sys; x=json.loads(sys.argv[1]); u=x["unproven_runs"]; assert (u["registered"], u["refused"], u["requests"], u["tokens"]["total"]) == (2, 1, 2, 200), u; assert x["codex"]["counts"]["requests"] == 4, x' "$usage"
# The policy's other entries: the called workflow registers from the test
# repository and any workflow of owner 71, each a run with a cap of its own
# whose record says what admitted it; a token no entry admits gets 403.
registration=$(curl --fail --silent -X POST -H "Authorization: Bearer $(test_jwt 4 "$test_workflow" "$called_claims")" http://127.0.0.1:18081/v1/runs)
called_token=$(python3 -c 'import json,sys; x=json.loads(sys.argv[1]); u=x["usage"]; assert (u["proof"], u["admitted_by"], u["workflow_ref"], u["entry_workflow_ref"], u["repository"]) == ("github-oidc", "called_workflows", sys.argv[2] + "@refs/heads/main", sys.argv[3], "owner/repo"), u; print(x["token"])' "$registration" "$called_workflow" "$caller")
registration=$(curl --fail --silent -X POST -H "Authorization: Bearer $(test_jwt 5 other/tool/.github/workflows/ci.yml@refs/heads/topic '{"repository": "other/tool", "repository_id": "80", "repository_owner_id": "71", "event_name": "push"}')" http://127.0.0.1:18081/v1/runs)
python3 -c 'import json,sys; u=json.loads(sys.argv[1])["usage"]; assert (u["admitted_by"], u["repository_owner_id"], u["event_name"]) == ("any_workflow", 71, "push"), u' "$registration"
for claims in \
    "{\"job_workflow_ref\": \"$called_workflow@refs/heads/topic\", \"workflow_ref\": \"$caller\"}" \
    "{\"job_workflow_ref\": \"evil/agentic/.github/workflows/job.yml@refs/heads/main\", \"workflow_ref\": \"$caller\"}" \
    "{\"job_workflow_ref\": \"$called_workflow@refs/heads/main\", \"workflow_ref\": \"$caller\", \"repository_owner_id\": \"72\"}" \
    '{"repository_id": "90", "repository_owner_id": "72"}'; do
    test "$(http_status -X POST -H "Authorization: Bearer $(test_jwt 6 "$test_workflow" "$claims")" http://127.0.0.1:18081/v1/runs)" = 403
done
for _ in 1 2; do
    stream=$(curl --fail --silent -H "Authorization: Bearer $called_token" -H 'Accept: text/event-stream' -H 'Content-Type: application/json' --data '{"model":"synthetic"}' http://127.0.0.1:18081/v1/responses); case "$stream" in *response.completed*) ;; *) exit 1;; esac
done
test "$(http_status -H "Authorization: Bearer $called_token" -H 'Content-Type: application/json' --data '{"model":"synthetic"}' http://127.0.0.1:18081/v1/responses)" = 429
usage=$(curl --fail --silent -X DELETE -H "Authorization: Bearer $called_token" http://127.0.0.1:18081/v1/runs/self)
python3 -c 'import json,sys; x=json.loads(sys.argv[1]); assert (x["admitted_by"], x["state"], x["requests"], x["tokens"]["total"]) == ("called_workflows", "finished", 2, 200), x' "$usage"
test "$(http_status -H "Authorization: Bearer $called_token" -H 'Content-Type: application/json' --data '{}' http://127.0.0.1:18081/v1/responses)" = 401
# They are no runs without proof: that count is as it was.
python3 -c 'import json,sys,urllib.request; x=json.load(urllib.request.urlopen("http://127.0.0.1:18081/usage")); assert (x["unproven_runs"]["registered"], x["unproven_runs"]["requests"], x["codex"]["counts"]["requests"]) == (2, 2, 6), x'
logs=$(podman pod logs "$test_pod")
for secret in "$run_token" "$unproven_token" "$called_token"; do
    logged "$secret" && exit 1
done
logged 'WITHOUT PROOF'
logged 'ANY WORKFLOW'
logged 'called from other repositories'
logged 'run registered' 'github-run:7/4/1' called_workflows "$called_workflow@refs/heads/main" "$caller"
logged 'request usage' 'github-run:7/4/1'
logged 'unproven run registered' 'unproven-run:pod-run'
logged 'request usage' 'unproven-run:pod-run'
logged 'run usage' 'pod-run' 'finished'
echo 'Synthetic native Podman pod checks passed.'
