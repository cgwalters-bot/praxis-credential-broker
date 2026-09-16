build:
    podman build --pull=missing -f Containerfile.proxy -t localhost/praxis-credential-proxy:dev .
    podman build --pull=missing -f Containerfile.codex -t localhost/praxis-provider-codex:dev .
up: build
    python3 -c 'from pathlib import Path; import base64; c=Path("/tmp/praxis-credential-broker-client-auth"); a=Path("/tmp/praxis-credential-broker-agent-channel"); output=Path("/tmp/praxis-credential-broker-pod.yaml"); text=Path("pod.yaml").read_text()+"\n---\napiVersion: v1\nkind: Secret\nmetadata:\n  name: praxis-credential-broker-client-auth\ntype: Opaque\ndata:\n  client-api-key: "+base64.b64encode(c.read_bytes()).decode()+"\n---\napiVersion: v1\nkind: Secret\nmetadata:\n  name: praxis-credential-broker-agent-channel\ntype: Opaque\ndata:\n  agent-channel-key: "+base64.b64encode(a.read_bytes()).decode()+"\n"; output.write_text(text); output.chmod(0o600)'
    podman kube play --replace /tmp/praxis-credential-broker-pod.yaml; status=$$?; rm -f /tmp/praxis-credential-broker-pod.yaml; exit $$status
test-pod:
    #!/usr/bin/env bash
    set -eu
    cleanup() {
        podman kube down pod-test.yaml >/dev/null 2>&1 || true
        podman pod rm -f praxis-credential-broker-test >/dev/null 2>&1 || true
        podman volume ls --filter name=praxis-credential-broker-test- --quiet | while read -r id; do podman volume rm "$id" >/dev/null 2>&1 || true; done
        podman secret ls --filter name=praxis-credential-broker-test- --quiet | while read -r id; do podman secret rm "$id" >/dev/null 2>&1 || true; done
    }
    trap cleanup EXIT
    trap 'exit 130' INT TERM
    podman build --pull=missing -f Containerfile.proxy --build-arg CARGO_FEATURES=synthetic-test -t localhost/praxis-credential-proxy:test .
    podman build --pull=missing -f Containerfile.synthetic-agent -t localhost/praxis-provider-codex:synthetic .
    podman build --pull=missing -f Containerfile.mock -t localhost/praxis-mock-upstream:dev .
    podman kube play --replace pod-test.yaml
    i=0; while [ $i -lt 60 ]; do if curl --fail --silent http://127.0.0.1:18081/healthz >/dev/null; then break; fi; sleep 1; i=$((i + 1)); done; test $i -lt 60
    status=$(curl --silent --output /dev/null --write-out '%{http_code}' --request POST --data '{}' http://127.0.0.1:18081/v1/responses); test "$status" = 401
    curl --fail --silent http://127.0.0.1:18082/reset >/dev/null
    body=$(curl --fail --silent -H 'Authorization: Bearer synthetic-client-key-012345678901234567890123' -H 'Content-Type: application/json' --data '{}' http://127.0.0.1:18081/v1/responses); python3 -c 'import json,sys; assert json.loads(sys.argv[1])["id"] == "synthetic"' "$body"
    python3 -c 'import json,urllib.request; x=json.load(urllib.request.urlopen("http://127.0.0.1:18082/counters")); assert x == {"calls": 2, "observed": [[True, True]]}, x'
    python3 -c 'import json,urllib.request; x=json.load(urllib.request.urlopen("http://127.0.0.1:19090/counters")); assert x["recover"] == 1 and x["acquire"] == 2, x'
    sleep 1
    python3 -c 'import json,urllib.request; assert json.load(urllib.request.urlopen("http://127.0.0.1:18082/counters"))["calls"] == 2'
    stream=$(curl --fail --silent -H 'Authorization: Bearer synthetic-client-key-012345678901234567890123' -H 'Accept: text/event-stream' -H 'Content-Type: application/json' --data '{}' http://127.0.0.1:18081/v1/responses); case "$stream" in *response.output_text.delta*function_call_arguments.delta*) ;; *) exit 1;; esac
login:
    if podman pod exists praxis-credential-broker >/dev/null 2>&1; then echo 'production pod is running; run `just down` before login' >&2; exit 1; fi
    podman build --pull=missing -f Containerfile.codex -t localhost/praxis-provider-codex:dev .
    podman run --rm -it --network=host -v praxis-credential-broker-auth:/codex-home:Z -e CODEX_HOME=/codex-home localhost/praxis-provider-codex:dev login
health:
    curl --fail --silent http://127.0.0.1:18080/healthz
logs:
    podman pod logs praxis-credential-broker
down:
    podman kube down pod.yaml
reset-auth:
    @read -r answer; test "$$answer" = RESET; podman kube down pod.yaml; podman volume rm praxis-credential-broker-auth
test-down:
    podman kube down pod-test.yaml || true
    podman pod rm -f praxis-credential-broker-test >/dev/null 2>&1 || true
    podman volume ls --filter name=praxis-credential-broker-test- --quiet | while read -r id; do podman volume rm "$id" >/dev/null 2>&1 || true; done
    podman secret ls --filter name=praxis-credential-broker-test- --quiet | while read -r id; do podman secret rm "$id" >/dev/null 2>&1 || true; done
