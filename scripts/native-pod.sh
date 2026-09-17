#!/usr/bin/env bash
set -euo pipefail

root=$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)
mode=${1:?usage: native-pod.sh login|up|health|logs|down|rotate-agent-secret|reset-secrets|reset-auth|test}
pod=praxis-credential-broker
socket_volume=praxis-credential-broker-socket
client_secret=praxis-credential-broker-client-auth
channel_secret=praxis-credential-broker-agent-channel
proxy_image=${PRAXIS_PROXY_IMAGE-ghcr.io/cgwalters-bot/praxis-credential-broker-proxy:main}
provider_codex_image=${PRAXIS_PROVIDER_CODEX_IMAGE-ghcr.io/cgwalters-bot/praxis-credential-broker-provider-codex:main}

client_auth_mode=
if [[ $mode == up ]]; then
    client_auth_mode=${PRAXIS_CLIENT_AUTH_MODE-required}
    case "$client_auth_mode" in
        required|disabled) ;;
        *)
            echo "PRAXIS_CLIENT_AUTH_MODE must be exactly 'required' or 'disabled'" >&2
            exit 2
            ;;
    esac
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

check_config_mount() {
    podman inspect "$1" | python3 -c 'import json,sys; mounts=json.load(sys.stdin)[0]["Mounts"]; assert any(m["Destination"] == "/etc/praxis/praxis.yaml" and not m["RW"] for m in mounts)'
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
        remove_secrets "$client_secret" "$channel_secret"
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
    if [[ $client_auth_mode == required ]]; then
        podman secret exists "$client_secret" || { echo "missing Podman secret: $client_secret (run 'bash scripts/init-secrets')" >&2; exit 1; }
    fi
    podman secret exists "$channel_secret" || { echo "missing Podman secret: $channel_secret (run 'bash scripts/init-secrets')" >&2; exit 1; }
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
    proxy_client_secret=()
    if [[ $client_auth_mode == required ]]; then
        proxy_client_secret=(--secret "$client_secret,target=/run/secrets/client/client-api-key,uid=65532,gid=65532,mode=0400")
    fi
    podman create "${common[@]}" --name praxis-credential-broker-proxy \
        --env "CLIENT_AUTH_MODE=$client_auth_mode" "${proxy_client_secret[@]}" \
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
    podman create "${common[@]}" --name praxis-credential-broker-praxis \
        --volume "$root/praxis.yaml:/etc/praxis/praxis.yaml:ro,Z" \
        --tmpfs /tmp:rw,noexec,nosuid,nodev,size=64m \
        ghcr.io/praxis-proxy/ai@sha256:ccd46f8772eebcbde2f41ad35c3234d23463b8314a5865083e32baf31eddd1a8 \
        --config /etc/praxis/praxis.yaml >/dev/null
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
    health_state=starting
    for _ in {1..30}; do
        health=$(curl --silent --show-error --max-time 2 --write-out $'\n%{http_code}' http://127.0.0.1:18080/healthz || true)
        health_code=${health##*$'\n'}
        health_body=${health%$'\n'*}
        if [[ $health_code == 200 ]]; then
            health_state=ready
            break
        elif [[ $health_code == 502 && $health_body == *'Upstream connection refused'* ]]; then
            health_state=oauth-not-initialized
            break
        elif [[ $health_code != 000 ]]; then
            sleep 1
        else
            sleep 1
        fi
        all_running=true
        for c in "${expected[@]}"; do
            podman inspect "$c" | python3 -c 'import json,sys; raise SystemExit(0 if json.load(sys.stdin)[0]["State"]["Running"] else 1)' || all_running=false
        done
        [[ $all_running == true ]] || fail_startup
    done
    [[ $health_state != starting ]] || { echo 'native pod startup timed out waiting for healthz' >&2; fail_startup; }
    if [[ $health_state == oauth-not-initialized ]]; then
        echo 'Started praxis-credential-broker; processes are running but OAuth is not initialized (healthz: 502 upstream connection refused).'
    else
        echo 'Started praxis-credential-broker; healthz is ready.'
    fi
    trap - EXIT INT TERM
    exit 0
fi

[[ $mode == test ]] || { echo "unknown mode: $mode" >&2; exit 2; }
test_pod=praxis-credential-broker-test
test_socket=praxis-credential-broker-test-socket
test_client=praxis-credential-broker-test-client
test_channel=praxis-credential-broker-test-channel
cleanup() {
    remove_pod "$test_pod"
    remove_socket "$test_socket"
    remove_secrets "$test_client" "$test_channel"
}
trap cleanup EXIT INT TERM
remove_secrets "$test_client" "$test_channel"
printf '%s' 'synthetic-reset-check' | podman secret create --replace "$test_client" - >/dev/null
remove_secrets "$test_client" "$test_channel"
printf '%s' 'synthetic-client-key-012345678901234567890123' | podman secret create --replace "$test_client" - >/dev/null
printf '%s' 'synthetic-agent-channel-012345678901234567890123' | podman secret create --replace "$test_channel" - >/dev/null
podman volume create "$test_socket" >/dev/null
podman pod create --name "$test_pod" \
    --publish 127.0.0.1:18081:8081 --publish 127.0.0.1:18082:18081 --publish 127.0.0.1:19090:19090 >/dev/null
common=(--pod "$test_pod" --user 65532:65532 --read-only --cap-drop=ALL --security-opt=no-new-privileges)
podman create "${common[@]}" --name "$test_pod-proxy" \
    --secret "$test_client,target=/run/secrets/client/client-api-key,uid=65532,gid=65532,mode=0400" \
    --secret "$test_channel,target=/run/secrets/channel/agent-channel-key,uid=65532,gid=65532,mode=0400" \
    --volume "$test_socket:/run/praxis-credentials:Z" --tmpfs /tmp:rw,noexec,nosuid,nodev,size=64m \
    localhost/praxis-credential-proxy:test >/dev/null
podman create "${common[@]}" --name "$test_pod-agent" \
    --secret "$test_channel,target=/run/secrets/channel/agent-channel-key,uid=65532,gid=65532,mode=0400" \
    --volume "$test_socket:/run/praxis-credentials:Z" \
    localhost/praxis-provider-codex:synthetic >/dev/null
podman create "${common[@]}" --name "$test_pod-praxis" --volume "$root/praxis.yaml:/etc/praxis/praxis.yaml:ro,Z" \
    ghcr.io/praxis-proxy/ai@sha256:ccd46f8772eebcbde2f41ad35c3234d23463b8314a5865083e32baf31eddd1a8 \
    --config /etc/praxis/praxis.yaml >/dev/null
podman create "${common[@]}" --name "$test_pod-mock" localhost/praxis-mock-upstream:dev >/dev/null
podman pod start "$test_pod" >/dev/null
proxy=$test_pod-proxy
agent=$test_pod-agent
check_secret "$proxy" "$test_client" /run/secrets/client/client-api-key
check_secret "$proxy" "$test_channel" /run/secrets/channel/agent-channel-key
check_secret "$agent" "$test_channel" /run/secrets/channel/agent-channel-key
secret_names "$agent" | grep -qx "$test_client" && exit 1
for c in "$test_pod-praxis" "$test_pod-mock"; do secret_names "$c" | grep -q . && exit 1; done
for c in "$proxy" "$agent" "$test_pod-praxis" "$test_pod-mock"; do check_hardening "$c"; done
check_config_mount "$test_pod-praxis"
socket_dir=$(podman volume inspect "$test_socket" | python3 -c 'import json,sys; print(json.load(sys.stdin)[0]["Mountpoint"])')
for _ in {1..30}; do [[ -S "$socket_dir/agent.sock" ]] && break; sleep 1; done
[[ -S "$socket_dir/agent.sock" ]]
[[ $(stat -c '%a' "$socket_dir/agent.sock") == 660 ]]
socket_label=$(ls -Zd "$socket_dir/agent.sock")
[[ $socket_label != *' ? '* ]]
i=0; while [ "$i" -lt 60 ]; do curl --fail --silent http://127.0.0.1:18081/healthz >/dev/null && break; sleep 1; i=$((i + 1)); done; test "$i" -lt 60
status=$(curl --silent --output /dev/null --write-out '%{http_code}' --request POST --data '{}' http://127.0.0.1:18081/v1/responses); test "$status" = 401
curl --fail --silent http://127.0.0.1:18082/reset >/dev/null
body=$(curl --fail --silent -H 'Authorization: Bearer synthetic-client-key-012345678901234567890123' -H 'Content-Type: application/json' --data '{}' http://127.0.0.1:18081/v1/responses); python3 -c 'import json,sys; assert json.loads(sys.argv[1])["id"] == "synthetic"' "$body"
python3 -c 'import json,urllib.request; x=json.load(urllib.request.urlopen("http://127.0.0.1:18082/counters")); assert x == {"calls": 2, "observed": [[True, True]]}, x'
python3 -c 'import json,urllib.request; x=json.load(urllib.request.urlopen("http://127.0.0.1:19090/counters")); assert x["recover"] == 1 and x["acquire"] == 2, x'
sleep 1
python3 -c 'import json,urllib.request; assert json.load(urllib.request.urlopen("http://127.0.0.1:18082/counters"))["calls"] == 2'
stream=$(curl --fail --silent -H 'Authorization: Bearer synthetic-client-key-012345678901234567890123' -H 'Accept: text/event-stream' -H 'Content-Type: application/json' --data '{}' http://127.0.0.1:18081/v1/responses); case "$stream" in *response.output_text.delta*function_call_arguments.delta*) ;; *) exit 1;; esac
logs=$(podman pod logs "$test_pod"); printf '%s' "$logs" | grep -Fq 'synthetic-client-key-012345678901234567890123' && exit 1; printf '%s' "$logs" | grep -Fq 'synthetic-agent-channel-012345678901234567890123' && exit 1
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
podman create "${common[@]}" --name "$test_pod-praxis" --volume "$root/praxis.yaml:/etc/praxis/praxis.yaml:ro,Z" \
    ghcr.io/praxis-proxy/ai@sha256:ccd46f8772eebcbde2f41ad35c3234d23463b8314a5865083e32baf31eddd1a8 \
    --config /etc/praxis/praxis.yaml >/dev/null
podman create "${common[@]}" --name "$test_pod-mock" localhost/praxis-mock-upstream:dev >/dev/null
podman pod start "$test_pod" >/dev/null
proxy=$test_pod-proxy
secret_names "$proxy" | grep -qx "$test_client" && exit 1
check_secret "$proxy" "$test_channel" /run/secrets/channel/agent-channel-key
for c in "$proxy" "$test_pod-agent" "$test_pod-praxis" "$test_pod-mock"; do check_hardening "$c"; done
i=0; while [ "$i" -lt 60 ]; do curl --fail --silent http://127.0.0.1:18081/healthz >/dev/null && break; sleep 1; i=$((i + 1)); done; test "$i" -lt 60
curl --fail --silent http://127.0.0.1:18082/reset >/dev/null
body=$(curl --fail --silent -H 'Content-Type: application/json' --data '{}' http://127.0.0.1:18081/v1/responses); python3 -c 'import json,sys; assert json.loads(sys.argv[1])["id"] == "synthetic"' "$body"
python3 -c 'import json,urllib.request; x=json.load(urllib.request.urlopen("http://127.0.0.1:18082/counters")); assert x == {"calls": 2, "observed": [[True, True]]}, x'
body=$(curl --fail --silent -H 'Authorization: Bearer caller-value-must-not-reach-upstream' -H 'Content-Type: application/json' --data '{}' http://127.0.0.1:18081/v1/responses); python3 -c 'import json,sys; assert json.loads(sys.argv[1])["id"] == "synthetic"' "$body"
python3 -c 'import json,urllib.request; x=json.load(urllib.request.urlopen("http://127.0.0.1:18082/counters")); assert x == {"calls": 4, "observed": [[True, True], [True, True]]}, x'
python3 -c 'import json,urllib.request; x=json.load(urllib.request.urlopen("http://127.0.0.1:19090/counters")); assert x["recover"] == 2 and x["acquire"] == 4, x'
logs=$(podman pod logs "$test_pod"); printf '%s' "$logs" | grep -Fq 'synthetic-client-key-012345678901234567890123' && exit 1; printf '%s' "$logs" | grep -Fq 'caller-value-must-not-reach-upstream' && exit 1
echo 'Synthetic native Podman pod checks passed.'
