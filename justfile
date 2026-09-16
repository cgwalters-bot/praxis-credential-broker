build:
    podman build --pull=missing -f Containerfile.proxy -t localhost/praxis-credential-proxy:dev .
    podman build --pull=missing -f Containerfile.codex -t localhost/praxis-provider-codex:dev .

up: build
    bash scripts/native-pod.sh up

init-secrets:
    bash scripts/init-secrets

rotate-agent-secret:
    @set -eu; podman pod exists praxis-credential-broker >/dev/null 2>&1 && { echo 'production pod is running; run `just down` before rotation' >&2; exit 1; } || true; bash scripts/create-agent-secret praxis-credential-broker-agent-channel

reset-secrets:
    @set -eu; test "$RESET_SECRETS" = RESET; podman pod exists praxis-credential-broker >/dev/null 2>&1 && { echo 'production pod is running; run `just down` first' >&2; exit 1; } || true; podman secret rm praxis-credential-broker-client-auth praxis-credential-broker-agent-channel >/dev/null

test-pod:
    podman build --pull=missing -f Containerfile.proxy --build-arg CARGO_FEATURES=synthetic-test -t localhost/praxis-credential-proxy:test .
    podman build --pull=missing -f Containerfile.synthetic-agent -t localhost/praxis-provider-codex:synthetic .
    podman build --pull=missing -f Containerfile.mock -t localhost/praxis-mock-upstream:dev .
    bash scripts/native-pod.sh test

login:
    @set -eu; podman pod exists praxis-credential-broker >/dev/null 2>&1 && { echo 'production pod is running; run `just down` before login' >&2; exit 1; } || true; podman build --pull=missing -f Containerfile.codex -t localhost/praxis-provider-codex:dev .; podman run --rm -it --network=host -v praxis-credential-broker-auth:/codex-home:Z -e CODEX_HOME=/codex-home localhost/praxis-provider-codex:dev login
health:
    curl --fail --silent http://127.0.0.1:18080/healthz
logs:
    podman pod logs praxis-credential-broker
down:
    bash scripts/native-pod.sh down
reset-auth:
    @set -eu; test "$RESET_AUTH" = RESET; bash scripts/native-pod.sh down; podman volume rm praxis-credential-broker-auth
