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
# without a policy file.
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
# by the test-only key whose key set the mock serves, and praxis.yaml with a
# per-run cap of 150 tokens for the second pass.
test_workflow=owner/repo/.github/workflows/agent.yml@refs/heads/main
python3 - "$root/praxis.yaml" "$test_dir" "$test_workflow" <<'PY'
import json, sys
source, target, workflow = sys.argv[1:]
config = open(source).read()
old = 'capacity: 20000000\n            reserved_tokens: 10000'
assert config.count(old) == 2, old
open(f'{target}/praxis.yaml', 'w').write(config.replace(old, 'capacity: 150\n            reserved_tokens: 10'))
policy = {'workflows': [workflow], 'repository_ids': [7], 'jwks_url': 'http://127.0.0.1:18081/jwks'}
open(f'{target}/run-token-policy.yaml', 'w').write(json.dumps(policy))
PY
chmod 0755 "$test_dir"
chmod 0644 "$test_dir"/*
test_jwt() {
    local header payload signature
    b64url() { python3 -c 'import base64,sys; print(base64.urlsafe_b64encode(sys.stdin.buffer.read()).rstrip(b"=").decode())'; }
    header=$(printf '{"alg":"RS256","typ":"JWT","kid":"praxis-test-key"}' | b64url)
    payload=$(python3 -c 'import json,sys,time,uuid; now=int(time.time()); print(json.dumps({"iss": "https://token.actions.githubusercontent.com", "aud": "praxis-credential-broker", "iat": now, "nbf": now, "exp": now + 300, "jti": str(uuid.uuid4()), "repository": "owner/repo", "repository_id": "7", "repository_owner_id": "70", "run_id": sys.argv[1], "run_attempt": "1", "job_workflow_ref": sys.argv[2], "workflow_ref": sys.argv[2], "event_name": "workflow_dispatch"}))' "$1" "$2" | tr -d '\n' | b64url)
    signature=$(printf '%s.%s' "$header" "$payload" | openssl dgst -sha256 -sign "$root/crates/praxis-gateway/testdata/oidc-test-key.pem" -binary | b64url)
    printf '%s.%s.%s' "$header" "$payload" "$signature"
}
# The pod as `up` creates it, with the synthetic provider and the mock
# upstream; extra arguments go to the Praxis container.
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
        --volume "$test_dir/run-token-policy.yaml:$policy_target:ro,Z" "$@" \
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
curl --fail --silent http://127.0.0.1:18082/reset >/dev/null
# Injected routes refuse requests without a registered run's token.
test "$(http_status -H 'Content-Type: application/json' --data '{}' http://127.0.0.1:18081/v1/responses)" = 401
test "$(http_status -H 'Authorization: Bearer caller-value-must-not-reach-upstream' -H 'Content-Type: application/json' --data '{}' http://127.0.0.1:18081/v1/responses)" = 401
test "$(http_status -H 'Authorization: Bearer praxis-substitute:anthropic' -H 'Content-Type: application/json' --data '{}' http://127.0.0.1:18081/anthropic/v1/messages/count_tokens)" = 401
mock_counters '{"calls": 0, "observed": []}'
test "$(http_status -X POST -H "Authorization: Bearer $(test_jwt 1 owner/repo/.github/workflows/devspace.yml@refs/heads/main)" http://127.0.0.1:18081/v1/runs)" = 403
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
    printf '%s' "$logs" | grep -Fq "$secret" && exit 1
done
printf '%s' "$logs" | grep -F 'run usage' | grep -Fq 'finished'
printf '%s' "$logs" | grep -F 'request usage' | grep -Fq injected
podman inspect "$test_pod-praxis" | grep -Fq "$test_anthropic_token" && exit 1

# Second pass: a per-run cap of 150 tokens, which the second response
# overshoots and the third is refused.
start_test_pod --volume "$test_dir/praxis.yaml:/etc/praxis/praxis.yaml:ro,Z"
wait_ready
curl --fail --silent http://127.0.0.1:18082/reset >/dev/null
registration=$(curl --fail --silent -X POST -H "Authorization: Bearer $(test_jwt 2 "$test_workflow")" http://127.0.0.1:18081/v1/runs)
run_token=$(python3 -c 'import json,sys; print(json.loads(sys.argv[1])["token"])' "$registration")
for _ in 1 2; do
    stream=$(curl --fail --silent -H "Authorization: Bearer $run_token" -H 'Accept: text/event-stream' -H 'Content-Type: application/json' --data '{"model":"synthetic"}' http://127.0.0.1:18081/v1/responses); case "$stream" in *response.completed*) ;; *) exit 1;; esac
done
test "$(http_status -H "Authorization: Bearer $run_token" -H 'Content-Type: application/json' --data '{"model":"synthetic"}' http://127.0.0.1:18081/v1/responses)" = 429
mock_counters '{"calls": 4, "observed": [[true, true], [true, true]]}'
logs=$(podman pod logs "$test_pod"); printf '%s' "$logs" | grep -Fq "$run_token" && exit 1
echo 'Synthetic native Podman pod checks passed.'
