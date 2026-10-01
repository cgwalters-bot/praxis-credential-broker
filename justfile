build:
    podman build --pull=missing -f Containerfile.proxy -t localhost/praxis-credential-proxy:dev .
    podman build --pull=missing -f Containerfile.codex -t localhost/praxis-provider-codex:dev .
    podman build --pull=missing -f Containerfile.gateway -t localhost/praxis-gateway:dev .

test-pod:
    podman build --pull=missing -f Containerfile.proxy --build-arg CARGO_FEATURES=synthetic-test -t localhost/praxis-credential-proxy:test .
    podman build --pull=missing -f Containerfile.synthetic-agent -t localhost/praxis-provider-codex:synthetic .
    podman build --pull=missing -f Containerfile.mock -t localhost/praxis-mock-upstream:dev .
    podman build --pull=missing -f Containerfile.gateway -t localhost/praxis-gateway:test .
    bash scripts/native-pod.sh test

# The gateway image's Anthropic routes against a fake upstream; no real token.
test-anthropic:
    python3 tests/anthropic_gateway.py

check:
    cargo fmt --all --check
    cargo clippy --workspace --all-targets --all-features --locked
    cargo test --workspace --locked
