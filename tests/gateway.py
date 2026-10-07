#!/usr/bin/env python3
"""Check the gateway image's routes against fake upstreams.

Builds the gateway image (Containerfile.gateway) and runs it with the pod's
container hardening, a synthetic Claude OAuth token delivered as a Podman
secret file, and a run registration policy that trusts a test-only OIDC key.
The configuration baked into the image is replaced by a copy in which only
the listener address and the upstream endpoints are rewritten, so the filter
order and conditions under test are the ones that ship. Each cluster gets a
fake upstream of its own, so every case also checks which upstream a request
reached, and with which credential. No real credential is used or needed.

Usage: python3 tests/gateway.py
"""

import base64
import hashlib
import json
import re
import socket
import subprocess
import sys
import tempfile
import threading
import time
import uuid
from http.client import HTTPConnection
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
CONTAINERFILE = ROOT / "Containerfile.gateway"
POD_SCRIPT = ROOT / "scripts" / "native-pod.sh"
CONFIG = ROOT / "praxis.yaml"
TESTDATA = ROOT / "crates" / "praxis-gateway" / "testdata"
OIDC_KEY = TESTDATA / "oidc-test-key.pem"
OIDC_JWKS = TESTDATA / "oidc-test-jwks.json"

IMAGE = "localhost/praxis-gateway:test"
CONTAINER = "praxis-credential-broker-test-gateway"
SECRET = "praxis-credential-broker-test-anthropic-oauth"
TOKEN_FILE = "/run/secrets/anthropic/oauth-token"
POLICY_FILE = "/etc/praxis-credential-broker/run-token-policy.yaml"
OPERATORS_FILE = "/etc/praxis-credential-broker/operator-tokens.yaml"
# The one operator of the test tokens file, for Responses only.
OPERATOR_TOKEN = "praxis-operator-SYNTHETIC-OPERATOR-TOKEN-0123456789abcdef"
TOKEN = "sk-ant-oat01-SYNTHETIC-TEST-TOKEN-0123456789abcdef"
PLACEHOLDER = "Bearer praxis-substitute:anthropic"
INJECTED = ["Bearer " + TOKEN]
OAUTH_BETA = "oauth-2025-04-20"
CLIENT_BETA = "claude-code-20250219,interleaved-thinking-2025-05-14"
CLIENT_OAUTH = "Bearer sk-ant-oat01-SYNTHETIC-CALLER-OAUTH"
WORKFLOW = "owner/repo/.github/workflows/agent.yml@refs/heads/main"
# Replaced by the registered run's token in each request.
RUN_TOKEN = "RUN-TOKEN"
SSE_DELAY = 0.3
MAX_REQUEST_BYTES = 33554432

# The fake upstream that stands in for each cluster of the load_balancer.
RESPONSES, ANTHROPIC, PASS = "inference-backend", "anthropic", "anthropic-pass-through"
RUNS = "run-endpoints"
CLUSTERS = (RESPONSES, ANTHROPIC, PASS, RUNS)

# The deny filters must come first, and the router before run_token and
# anything that changes the request. A reordering is a security change, not
# a refactor.
FILTERS = [
    "static_response", "static_response", "static_response", "openai_responses_proxy", "anthropic_messages_format",
    "anthropic_validate", "anthropic_messages_protocol", "router", "run_token", "token_rate_limit",
    "token_rate_limit", "token_rate_limit", "token_rate_limit", "token_count", "token_count",
    "path_rewrite", "headers", "headers", "headers", "credential_injection", "load_balancer",
]

P = ("Authorization", PLACEHOLDER)
R = ("x-run-token", RUN_TOKEN)
C = ("Authorization", CLIENT_OAUTH)
B = ("Authorization", "Bearer " + RUN_TOKEN)
O = ("Authorization", "Bearer " + OPERATOR_TOKEN)

# (name, method, path, request headers as pairs, expected status, cluster)
# A request for a cluster must reach that cluster's upstream exactly once and
# no other; a request with cluster None must reach no upstream at all.
#
# On the /anthropic prefix: the placeholder with a run token is injected,
# any other Authorization is passed through, and nothing but the exact
# placeholder ever gets the broker's token.
ANTHROPIC_CASES = [
    ("injected", "/v1/messages", [P, R], 200, ANTHROPIC),
    ("injected, lowercase header name", "/v1/messages", [("authorization", PLACEHOLDER), R], 200, ANTHROPIC),
    ("injected, trailing whitespace trimmed by HTTP", "/v1/messages", [("Authorization", PLACEHOLDER + " "), R], 200, ANTHROPIC),
    ("injected plus x-api-key", "/v1/messages", [P, R, ("x-api-key", "sk-ant-api03-client")], 200, ANTHROPIC),
    ("injected plus client Host", "/v1/messages", [P, R, ("Host", "evil.example")], 200, ANTHROPIC),
    ("injected count_tokens", "/v1/messages/count_tokens", [P, R], 200, ANTHROPIC),
    ("placeholder without a run token", "/v1/messages", [P], 401, None),
    ("placeholder with an unknown run token", "/v1/messages", [P, ("x-run-token", "praxis-run-0000")], 401, None),
    ("placeholder with the run token as Authorization", "/v1/messages", [P, B], 400, None),
    ("duplicate Authorization, placeholder first", "/v1/messages", [P, C, R], 400, None),
    ("duplicate Authorization, other value first", "/v1/messages", [C, P, R], 400, None),
    ("pass-through", "/v1/messages", [C], 200, PASS),
    ("pass-through count_tokens", "/v1/messages/count_tokens", [C], 200, PASS),
    ("pass-through with a run token", "/v1/messages", [C, R], 200, PASS),
    ("pass-through plus x-api-key", "/v1/messages", [C, ("x-api-key", "sk-ant-api03-client")], 200, PASS),
    ("pass-through of a run token as Authorization", "/v1/messages", [B], 400, None),
    ("pass-through of a run token, scheme case: bearer", "/v1/messages",
     [("Authorization", "bearer " + RUN_TOKEN)], 400, None),
    ("pass-through of a run token, scheme case: BEARER", "/v1/messages",
     [("Authorization", "BEARER " + RUN_TOKEN)], 400, None),
    ("pass-through of a run token, double space", "/v1/messages",
     [("Authorization", "Bearer  " + RUN_TOKEN)], 400, None),
    ("pass-through of a run token, no scheme", "/v1/messages", [("Authorization", RUN_TOKEN)], 400, None),
    ("no Authorization", "/v1/messages", [], 200, PASS),
    ("unknown placeholder", "/v1/messages", [("Authorization", "Bearer praxis-substitute:nope")], 200, PASS),
    ("placeholder only in x-api-key", "/v1/messages", [("x-api-key", "praxis-substitute:anthropic"), R], 200, PASS),
    ("Bearer placeholder only in x-api-key", "/v1/messages", [("x-api-key", PLACEHOLDER), R], 200, PASS),
    ("scheme case: bearer", "/v1/messages", [("Authorization", "bearer praxis-substitute:anthropic"), R], 200, PASS),
    ("scheme case: BEARER", "/v1/messages", [("Authorization", "BEARER praxis-substitute:anthropic"), R], 200, PASS),
    ("name case: ANTHROPIC", "/v1/messages", [("Authorization", "Bearer praxis-substitute:ANTHROPIC"), R], 200, PASS),
    ("double space after Bearer", "/v1/messages", [("Authorization", "Bearer  praxis-substitute:anthropic"), R], 200, PASS),
    ("no scheme", "/v1/messages", [("Authorization", "praxis-substitute:anthropic"), R], 200, PASS),
    ("placeholder as a prefix", "/v1/messages", [("Authorization", PLACEHOLDER + "x"), R], 200, PASS),
    ("placeholder inside another value", "/v1/messages", [("Authorization", "Bearer sk-real praxis-substitute:anthropic"), R], 200, PASS),
    ("Basic scheme", "/v1/messages", [("Authorization", "Basic cHJheGlzLXN1YnN0aXR1dGU6YW50aHJvcGlj"), R], 200, PASS),
    ("placeholder outside /v1/", "/api/oauth/profile", [P, R], 404, None),
    ("pass-through outside /v1/", "/api/oauth/profile", [C], 404, None),
    ("other /v1/ endpoint", "/v1/models", [P, R], 404, None),
    ("/v1 without a slash", "/v1", [P, R], 404, None),
    ("dot-dot out of /v1/", "/v1/../api/oauth/profile", [P, R], 404, None),
    ("dot-dot out of /v1/messages", "/v1/messages/../../api/oauth/profile", [P, R], 404, None),
    ("pass-through dot-dot out of /v1/messages", "/v1/messages/../../api/oauth/profile", [C], 404, None),
    ("encoded dot-dot", "/v1/messages/%2e%2e/%2e%2e/api/oauth/profile", [P, R], 404, None),
    ("prefix of messages path", "/v1/messagesx", [P, R], 404, None),
    ("run endpoints under the prefix", "/v1/runs", [P, R], 404, None),
]
ANTHROPIC_CASES = [(f"/anthropic: {name}", "POST", "/anthropic" + path, *rest)
                   for name, path, *rest in ANTHROPIC_CASES] + [
    ("/anthropic: GET with placeholder", "GET", "/anthropic/v1/messages", [P, R], 403, None),
    ("/anthropic: TRACE with placeholder", "TRACE", "/anthropic/v1/messages", [P, R], 403, None),
    ("/anthropic: DELETE with placeholder", "DELETE", "/anthropic/v1/messages", [P, R], 403, None),
    ("/anthropic: GET with client OAuth", "GET", "/anthropic/v1/messages", [C], 403, None),
    ("/anthropic: TRACE with client OAuth", "TRACE", "/anthropic/v1/messages", [C], 403, None),
    # Methods are case-sensitive in HTTP, but Praxis's method condition is
    # not, and the router has no method match, so these are forwarded as is.
    # The upstream is fixed, and TRACE cannot be spelled this way.
    ("/anthropic: lowercase post", "post", "/anthropic/v1/messages", [P, R], 200, ANTHROPIC),
    ("/anthropic: mixed-case PoSt", "PoSt", "/anthropic/v1/messages", [P, R], 200, ANTHROPIC),
    ("/anthropic: lowercase trace", "trace", "/anthropic/v1/messages", [P, R], 403, None),
]

# Responses and the run endpoints next to /anthropic, and every way found to
# cross from one prefix into another.
SHARED_CASES = [
    ("local usage without authentication", "GET", "/usage", [], 200, None),
    ("local usage wrong method", "POST", "/usage", [], 405, None),
    ("usage route is exact", "GET", "/usage/", [], 404, None),
    ("Responses with a run token", "POST", "/v1/responses", [B], 200, RESPONSES),
    ("Responses with a run token in x-run-token", "POST", "/v1/responses", [R], 200, RESPONSES),
    ("Responses without a run token", "POST", "/v1/responses", [], 401, None),
    ("Responses with an operator token", "POST", "/v1/responses", [O], 200, RESPONSES),
    ("Responses with an operator token in x-run-token", "POST", "/v1/responses",
     [("x-run-token", OPERATOR_TOKEN)], 200, RESPONSES),
    ("Responses with an operator token nobody holds", "POST", "/v1/responses",
     [("authorization", "Bearer " + OPERATOR_TOKEN + "0")], 401, None),
    ("operator token as a pass-through credential", "POST", "/anthropic/v1/messages", [O], 400, None),
    ("Responses with another bearer token", "POST", "/v1/responses", [C], 401, None),
    ("Responses with a query string", "POST", "/v1/responses?stream=true", [B], 200, RESPONSES),
    ("Responses keeps a client anthropic-beta and x-api-key", "POST", "/v1/responses",
     [B, ("anthropic-beta", CLIENT_BETA), ("x-api-key", "client")], 200, RESPONSES),
    ("Responses with two Authorization headers", "POST", "/v1/responses", [B, C], 400, None),
    ("healthz", "GET", "/healthz", [], 200, RESPONSES),
    ("healthz with a run token, which is removed", "GET", "/healthz", [B, R], 200, RESPONSES),
    ("under healthz", "GET", "/healthz/x", [], 404, None),
    ("GET Responses", "GET", "/v1/responses", [B], 405, None),
    ("DELETE Responses", "DELETE", "/v1/responses", [B], 405, None),
    ("placeholder on /v1/responses", "POST", "/v1/responses", [P, R], 403, None),
    ("placeholder on /healthz", "GET", "/healthz", [P], 403, None),
    ("run registration without an OIDC token", "POST", "/v1/runs", [], 401, None),
    ("run registration without proof, which the policy does not admit", "POST", "/v1/runs",
     [("x-run-id", "job-1")], 401, None),
    ("run registration, wrong method", "GET", "/v1/runs", [], 405, None),
    ("the old /v1/messages pass-through route", "POST", "/v1/messages", [C], 404, None),
    ("placeholder on /v1/messages", "POST", "/v1/messages", [P, R], 403, None),
    ("/v1 dot-dot into /anthropic, placeholder", "POST", "/v1/../anthropic/v1/messages", [P, R], 403, None),
    ("/v1 dot-dot into /anthropic, client OAuth", "POST", "/v1/../anthropic/v1/messages", [C], 404, None),
    ("/v1/responses dot-dot into /anthropic, placeholder", "POST",
     "/v1/responses/../../anthropic/v1/messages", [P, R], 403, None),
    # Forwarded as is to credential-proxy, which serves only the exact path
    # /v1/responses; never to an Anthropic upstream.
    ("/v1/responses dot-dot into /anthropic, run token", "POST",
     "/v1/responses/../../anthropic/v1/messages", [B], 200, RESPONSES),
    ("/anthropic dot-dot into /v1/responses, placeholder", "POST", "/anthropic/../v1/responses", [P, R], 404, None),
    ("/anthropic dot-dot into /v1/responses, run token", "POST", "/anthropic/../v1/responses", [B], 404, None),
    ("/anthropic dot-dot into /v1/messages, client OAuth", "POST", "/anthropic/../v1/messages", [C], 404, None),
    ("/anthropic/v1 dot-dot into /v1/responses", "POST", "/anthropic/v1/../../v1/responses", [P, R], 404, None),
    ("/anthropic encoded dot-dot into /v1/responses", "POST", "/anthropic/%2e%2e/v1/responses", [P, R], 404, None),
    ("/anthropic mixed encoded dot-dot", "POST", "/anthropic/v1/messages/.%2e/count_tokens", [P, R], 404, None),
    ("/anthropic encoded slashes", "POST", "/anthropic%2fv1%2fmessages", [P, R], 403, None),
    ("/anthropic encoded slashes, client OAuth", "POST", "/anthropic%2fv1%2fmessages", [C], 404, None),
    ("/anthropic encoded slash after the prefix", "POST", "/anthropic/v1%2fmessages", [P, R], 404, None),
    ("leading double slash", "POST", "//anthropic/v1/messages", [P, R], 403, None),
    ("leading double slash, client OAuth", "POST", "//anthropic/v1/messages", [C], 404, None),
    ("double slash after the prefix", "POST", "/anthropic//v1/messages", [P, R], 404, None),
    ("dot segment after the prefix", "POST", "/anthropic/./v1/messages", [P, R], 404, None),
    ("prefix case: ANTHROPIC", "POST", "/ANTHROPIC/v1/messages", [P, R], 403, None),
    ("prefix as a word prefix", "POST", "/anthropicx/v1/messages", [P, R], 403, None),
    ("trailing slash", "POST", "/anthropic/v1/messages/", [P, R], 404, None),
    ("bare prefix", "POST", "/anthropic", [P, R], 404, None),
    ("bare prefix with a slash", "POST", "/anthropic/", [P, R], 404, None),
    ("Responses under the prefix", "POST", "/anthropic/v1/responses", [P, R], 404, None),
    ("healthz under the prefix", "POST", "/anthropic/healthz", [P, R], 404, None),
]

# Registrations in order against a policy whose `unproven` admits two an
# hour: the name, the headers, the status and the body of a refusal.
UNPROVEN_CASES = [
    ("without a run id", [], 400, "one x-run-id header required\n"),
    ("with a run id that is not plain", [("x-run-id", "job 1")], 400, "invalid x-run-id\n"),
    ("with an Authorization that proves nothing", [("x-run-id", "job-1"), C], 401, "invalid OIDC token\n"),
    ("from a web page", [("x-run-id", "job-1"), ("Origin", "http://rebound.example")], 403,
     "a web page may not register a run\n"),
    ("of a first run", [("x-run-id", "job-1")], 201, None),
    ("under a name that is taken", [("x-run-id", "job-1")], 409, "run already registered\n"),
    ("of a second run", [("x-run-id", "job-2")], 201, None),
    ("over the quota", [("x-run-id", "job-3")], 429, "too many unproven registrations\n"),
]

# A reusable workflow of another owner's repository and the commit it is at,
# which the test repository's caller.yml calls, and an owner the first
# policy does not name.
CALLED = "lib/agentic/.github/workflows/job.yml"
CALLED_SHA = "0123456789abcdef0123456789abcdef01234567"
CALLER = "owner/repo/.github/workflows/caller.yml@refs/heads/main"
OTHER_OWNER = {"repository": "other/tool", "repository_id": "80", "repository_owner_id": "71",
               "job_workflow_ref": "other/tool/.github/workflows/ci.yml@refs/heads/topic",
               "workflow_ref": "other/tool/.github/workflows/ci.yml@refs/heads/topic", "event_name": "push"}
# An actor's name that would end its log line's field, add one of its own
# and start a line, if the gateway logged it as it came.
FORGING = 'mallory" admitted_by="workflows\nFORGED LINE'
FORBIDDEN = "workflow may not register runs\n"
INVALID = "invalid OIDC token\n"


def called(ref="refs/heads/main", **claims):
    """What a token of a job of CALLED at `ref` says, called from the test
    repository."""
    return {"job_workflow_ref": f"{CALLED}@{ref}", "job_workflow_sha": CALLED_SHA, "workflow_ref": CALLER,
            "actor": "someone", **claims}


# The entries a policy has only if its operator adds them: CALLED at one
# commit from the test owner's repositories, and any workflow of another
# owner's.
PERMISSIVE = {
    "called_workflows": [{"workflow": CALLED, "sha": CALLED_SHA, "callers": {"owner_ids": [70]}}],
    "any_workflow": {"repositories": {"owner_ids": [71]}},
}
# Registrations by OIDC token: the name, what the token says beyond the
# test workflow's own run, and what the policy as committed answers and
# what one with PERMISSIVE does: a status, and the entry that admitted the
# run or the body of the refusal.
OIDC_CASES = [
    ("the named workflow", {}, (201, "workflows"), (201, "workflows")),
    ("a reusable workflow called from the test repository", called(), (403, FORBIDDEN), (201, "called_workflows")),
    ("the same, reached by a tag", called("refs/tags/v1"), (403, FORBIDDEN), (201, "called_workflows")),
    ("any workflow of another owner", OTHER_OWNER, (403, FORBIDDEN), (201, "any_workflow")),
    ("a workflow of that owner whose names would forge a log line",
     {**OTHER_OWNER, "repository_id": "81", "actor": FORGING}, (403, FORBIDDEN), (201, "any_workflow")),
    ("the reusable workflow at another commit", called(job_workflow_sha="f" * 40), (403, FORBIDDEN),
     (403, FORBIDDEN)),
    ("a fork of the reusable workflow",
     called(job_workflow_ref="evil/agentic/.github/workflows/job.yml@refs/heads/main"),
     (403, FORBIDDEN), (403, FORBIDDEN)),
    ("the reusable workflow called by an owner nothing lists",
     called(repository="third/tool", repository_id="90", repository_owner_id="72"), (403, FORBIDDEN), (403, FORBIDDEN)),
    ("a workflow of an owner nothing lists", {**OTHER_OWNER, "repository_id": "90", "repository_owner_id": "72"},
     (403, FORBIDDEN), (403, FORBIDDEN)),
    ("the named workflow on another event", {"event_name": "pull_request_target"}, (403, FORBIDDEN),
     (403, FORBIDDEN)),
    ("another issuer", {**OTHER_OWNER, "iss": "https://example.com"}, (401, INVALID), (401, INVALID)),
    ("another audience", called(aud="someone-else"), (401, INVALID), (401, INVALID)),
    ("an expired token", {**OTHER_OWNER, "expired": True}, (401, INVALID), (401, INVALID)),
]

DENY_BODIES = {
    "/anthropic": {"type": "error", "error": {"type": "permission_error", "message": "only POST is forwarded"}},
    "elsewhere": {"type": "error", "error": {"type": "permission_error",
                                             "message": "praxis placeholder credential outside /anthropic"}},
}

# What each fake Messages upstream reports, which token_count meters.
MESSAGES_USAGE = {"input_tokens": 40, "cache_read_input_tokens": 20, "output_tokens": 30}
USAGE_HEADERS = json.loads((TESTDATA / "usage-headers.json").read_text())


class Upstream(BaseHTTPRequestHandler):
    """Records what the gateway forwards and answers like the Messages API."""

    protocol_version = "HTTP/1.1"

    def end_headers(self):
        provider = "codex" if self.server.cluster == RESPONSES else "anthropic"
        for name, value in USAGE_HEADERS[provider].items():
            if name.startswith(("anthropic-ratelimit-unified-", "x-codex-")):
                self.send_header(name, value)
        super().end_headers()

    def do_POST(self):
        body = self.rfile.read(int(self.headers.get("content-length") or 0))
        self.server.seen.append({"cluster": self.server.cluster, "path": self.path,
                                 "headers": list(self.headers.items()),
                                 "body_sha256": hashlib.sha256(body).hexdigest()})
        try:
            stream = json.loads(body).get("stream") is True
        except ValueError:
            stream = False
        if not stream:
            out = json.dumps({"id": "msg_synthetic", "type": "message", "model": "claude-synthetic",
                              "content": [{"type": "text", "text": "OK"}], "usage": MESSAGES_USAGE}).encode()
            self.send_response(200)
            self.send_header("content-type", "application/json")
            self.send_header("content-length", str(len(out)))
            self.end_headers()
            self.wfile.write(out)
            return
        self.send_response(200)
        self.send_header("content-type", "text/event-stream")
        self.send_header("transfer-encoding", "chunked")
        self.end_headers()
        events = [
            ("message_start", {"message": {"id": "m", "model": "claude-synthetic",
                                           "usage": {**MESSAGES_USAGE, "output_tokens": 1}}}),
            ("content_block_delta", {"index": 0, "delta": {"type": "text_delta", "text": "O"}}),
            ("content_block_delta", {"index": 0, "delta": {"type": "text_delta", "text": "K"}}),
            ("message_delta", {"delta": {"stop_reason": "end_turn"},
                               "usage": {"output_tokens": MESSAGES_USAGE["output_tokens"]}}),
            ("message_stop", {}),
        ]
        for event, data in events:
            chunk = f"event: {event}\ndata: {json.dumps({'type': event, **data})}\n\n".encode()
            self.wfile.write(b"%x\r\n%s\r\n" % (len(chunk), chunk))
            self.wfile.flush()
            time.sleep(SSE_DELAY)
        self.wfile.write(b"0\r\n\r\n")
        self.wfile.flush()

    do_GET = do_POST

    def __getattr__(self, name):
        # Any other method spelling that reaches an upstream, such as "post".
        if name.startswith("do_"):
            return self.do_POST
        raise AttributeError(name)

    def log_message(self, *_):
        pass


class Jwks(BaseHTTPRequestHandler):
    """Serves the test OIDC key set that the registration policy trusts."""

    def do_GET(self):
        body = OIDC_JWKS.read_bytes()
        self.send_response(200 if self.path == "/jwks" else 404)
        self.send_header("content-type", "application/json")
        self.send_header("content-length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def log_message(self, *_):
        pass


def podman(*args, check=True, stdin=None):
    proc = subprocess.run(["podman", *args], input=stdin, capture_output=True, text=True)
    if check and proc.returncode != 0:
        raise SystemExit(f"podman {args[0]} {args[1] if len(args) > 1 else ''} failed: {proc.stderr.strip()}")
    return proc


def free_port():
    with socket.socket() as s:
        s.bind(("127.0.0.1", 0))
        return s.getsockname()[1]


def b64url(data):
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode()


def oidc_token(run_id, claims=None):
    """A GitHub Actions OIDC token for the test workflow's run, signed with
    the test-only key, with `claims` over its own; `expired` makes it one
    whose validity ended."""
    claims = dict(claims or {})
    now = int(time.time()) - (900 if claims.pop("expired", False) else 0)
    header = b64url(json.dumps({"alg": "RS256", "typ": "JWT", "kid": "praxis-test-key"}).encode())
    payload = b64url(json.dumps({
        "iss": "https://token.actions.githubusercontent.com", "aud": "praxis-credential-broker",
        "iat": now, "nbf": now, "exp": now + 300, "jti": str(uuid.uuid4()),
        "repository": "owner/repo", "repository_id": "7", "repository_owner_id": "70",
        "run_id": str(run_id), "run_attempt": "1", "job_workflow_ref": WORKFLOW,
        "workflow_ref": WORKFLOW, "event_name": "workflow_dispatch", **claims}).encode())
    signature = subprocess.run(["openssl", "dgst", "-sha256", "-sign", str(OIDC_KEY), "-binary"],
                               input=f"{header}.{payload}".encode(), capture_output=True, check=True).stdout
    return f"{header}.{payload}.{b64url(signature)}"


def build_image():
    """The image under test, built from this checkout."""
    pins = set(re.findall(r"ghcr\.io/praxis-proxy/ai@sha256:[0-9a-f]{64}", POD_SCRIPT.read_text()))
    if pins:
        raise SystemExit(f"{POD_SCRIPT.name} must run the gateway image, not stock Praxis: {sorted(pins)}")
    podman("build", "--quiet", "--pull=missing", "--file", str(CONTAINERFILE), "--tag", IMAGE, str(ROOT))


def replace_once(path, text, old, new):
    if text.count(old) != 1:
        raise SystemExit(f"{path.name}: expected exactly one occurrence of {old!r}")
    return text.replace(old, new)


def rewrite_cluster(path, text, name, port):
    """Point one load_balancer cluster at a local fake, dropping its TLS."""
    pattern = re.compile(rf'(          - name: {re.escape(name)}\n            endpoints: )\[[^\]]*\]\n'
                         r'(?:            tls:\n              sni: "[^"]*"\n)?')
    text, count = pattern.subn(rf'\g<1>["127.0.0.1:{port}"]\n', text)
    if count != 1:
        raise SystemExit(f"{path.name}: expected exactly one load_balancer cluster named {name}")
    return text


def test_config(praxis_port, upstreams):
    text = CONFIG.read_text()
    text = replace_once(CONFIG, text, 'address: "0.0.0.0:8081"', f'address: "127.0.0.1:{praxis_port}"')
    for name, server in upstreams.items():
        text = rewrite_cluster(CONFIG, text, name, server.server_address[1])
    return text


def check_filter_order(check):
    filters = re.findall(r"^\s+- filter: (\S+)", CONFIG.read_text(), re.MULTILINE)
    check.report(f"{CONFIG.name} filter order", {
        f"filters are {filters}": filters == FILTERS,
    })


def container_args(config_path, policy_path, with_secret=True):
    """The praxis container's settings in native-pod.sh, on the host network,
    with the operator tokens file next to the policy if there is one."""
    operators_path = policy_path.with_name("operator-tokens.yaml")
    args = ["--network", "host", "--user", "65532:65532", "--read-only", "--cap-drop=ALL",
            "--security-opt=no-new-privileges", "--tmpfs", "/tmp:rw,noexec,nosuid,nodev,size=64m",
            "--no-healthcheck",
            "--volume", f"{config_path}:/etc/praxis/praxis.yaml:ro,Z",
            "--volume", f"{policy_path}:{POLICY_FILE}:ro,Z"]
    if operators_path.exists():
        args += ["--volume", f"{operators_path}:{OPERATORS_FILE}:ro,Z"]
    if with_secret:
        args += ["--secret", f"{SECRET},target={TOKEN_FILE},uid=65532,gid=65532,mode=0400"]
    return args + [IMAGE]


def request(port, path, headers, body=b"{}", method="POST"):
    conn = HTTPConnection("127.0.0.1", port, timeout=20)
    conn.putrequest(method, path, skip_host=any(k.lower() == "host" for k, _ in headers))
    for name, value in [("content-type", "application/json"), ("content-length", str(len(body)))] + headers:
        conn.putheader(name, value)
    conn.endheaders(body)
    return conn.getresponse()


def header_map(pairs):
    out = {}
    for name, value in pairs:
        out.setdefault(name.lower(), []).append(value.strip())
    return out


class Checker:
    def __init__(self):
        self.failed = 0
        # Strings that must never appear in a response or the logs.
        self.secrets = [TOKEN, CLIENT_OAUTH.removeprefix("Bearer ")]

    def leaks(self, text):
        return [s for s in self.secrets + [OAUTH_BETA] if s in text]

    def report(self, name, checks):
        bad = [k for k, ok in checks.items() if not ok]
        self.failed += bool(bad)
        print(f"[{'FAIL' if bad else 'PASS'}] {name}" + (f": {', '.join(bad)}" if bad else ""))


def forwarded_checks(cluster, path, headers, body, hit, run_token):
    """What each cluster's upstream must and must not receive."""
    sent, up = header_map(headers), header_map(hit["headers"])
    checks = {
        "body changed": hit["body_sha256"] == hashlib.sha256(body).hexdigest(),
        "token sent to the wrong upstream": cluster == ANTHROPIC or TOKEN not in str(hit["headers"]),
        "run token forwarded": run_token not in str(hit["headers"]),
        "operator token forwarded": OPERATOR_TOKEN not in str(hit["headers"]),
        "x-run-token forwarded": "x-run-token" not in up,
    }
    if cluster == ANTHROPIC:
        return checks | {
            "upstream Authorization is not the single injected token": up.get("authorization") == INJECTED,
            "x-api-key forwarded": "x-api-key" not in up,
            "anthropic-beta not added": up.get("anthropic-beta") == [OAUTH_BETA],
            "Host not rewritten": up.get("host") == ["api.anthropic.com"],
            "prefix not stripped": hit["path"] == path.removeprefix("/anthropic"),
        }
    checks |= {"OAuth beta added": OAUTH_BETA not in str(up.get("anthropic-beta"))}
    if cluster == PASS:
        return checks | {
            "client Authorization not passed through": up.get("authorization") == sent.get("authorization"),
            "x-api-key forwarded": "x-api-key" not in up,
            "Host not rewritten": up.get("host") == ["api.anthropic.com"],
            "prefix not stripped": hit["path"] == path.removeprefix("/anthropic"),
        }
    return checks | {
        "path changed": hit["path"] == path,
        "Authorization forwarded to credential-proxy": "authorization" not in up,
        "client x-api-key changed": up.get("x-api-key") == sent.get("x-api-key"),
        "client anthropic-beta changed": up.get("anthropic-beta") == sent.get("anthropic-beta"),
        "Host rewritten to Anthropic": up.get("host") != ["api.anthropic.com"],
    }


def with_run_token(headers, run_token):
    return [(k, v.replace(RUN_TOKEN, run_token)) for k, v in headers]


def run_cases(port, seen, check, run_token, cases):
    body = json.dumps({"model": "claude-synthetic", "max_tokens": 1,
                       "messages": [{"role": "user", "content": "hi"}]}).encode()
    for name, method, path, headers, want_status, cluster in cases:
        headers = with_run_token(headers, run_token)
        before = len(seen)
        resp = request(port, path, headers, body, method)
        text = resp.read().decode(errors="replace")
        hits = seen[before:]
        checks = {f"status {resp.status} != {want_status}": resp.status == want_status,
                  "token, client credential or beta in response": not check.leaks(text + str(resp.getheaders()))}
        if cluster:
            checks[f"upstreams hit: {[h['cluster'] for h in hits]}"] = [h["cluster"] for h in hits] == [cluster]
            if len(hits) == 1:
                checks |= forwarded_checks(cluster, path, headers, body, hits[0], run_token)
        else:
            checks[f"upstreams hit: {[h['cluster'] for h in hits]}"] = not hits
        if want_status == 403:
            prefix = "/anthropic" if path.startswith("/anthropic/") else "elsewhere"
            checks["unexpected 403 body"] = json.loads(text) == DENY_BODIES[prefix]
        check.report(name, checks)


def run_stream(port, seen, check, run_token):
    """Claude Code's shape: streaming, its own betas, a query string."""
    body = ('{"stream":true,  "model":"claude-synthetic","max_tokens":5,\n'
            '"messages":[{"role":"user","content":"h\\u00e9llo ☃ 1.0e0"}],"zzz":1}').encode()
    for name, headers, cluster, want_auth, want_beta in [
        ("/anthropic: injected streaming request with client betas",
         [P, ("x-run-token", run_token), ("anthropic-beta", CLIENT_BETA)], ANTHROPIC, INJECTED,
         [f"{CLIENT_BETA},{OAUTH_BETA}"]),
        ("/anthropic: pass-through streaming request with client betas",
         [C, ("anthropic-beta", CLIENT_BETA)], PASS, [CLIENT_OAUTH], [CLIENT_BETA]),
    ]:
        before = len(seen)
        start = time.monotonic()
        resp = request(port, "/anthropic/v1/messages?beta=true", headers, body)
        arrivals = []
        while chunk := resp.read1(65536):
            arrivals += [time.monotonic() - start] * chunk.count(b"\n\n")
        hits = seen[before:]
        up = header_map(hits[0]["headers"]) if len(hits) == 1 else {}
        check.report(name, {
            "status": resp.status == 200,
            "upstreams hit": [h["cluster"] for h in hits] == [cluster],
            "upstream Authorization": up.get("authorization") == want_auth,
            "anthropic-beta": up.get("anthropic-beta") == want_beta,
            "query or path changed": len(hits) == 1 and hits[0]["path"] == "/v1/messages?beta=true",
            "body not byte-identical": len(hits) == 1 and hits[0]["body_sha256"] == hashlib.sha256(body).hexdigest(),
            "events not delivered incrementally": len(arrivals) == 5 and arrivals[-1] - arrivals[0] > 2 * SSE_DELAY,
        })


def run_usage(port, seen, check, run_token):
    """The local snapshot exposes broker totals and typed window observations."""
    before = len(seen)
    resp = request(port, "/usage", [], b"", method="GET")
    text = resp.read().decode()
    usage = json.loads(text)
    check.report("local broker usage snapshot", {
        "status": resp.status == 200,
        "upstream contacted": len(seen) == before,
        "schema": usage["schema"] == "praxis-broker-usage/v1",
        "no Anthropic counts": usage["anthropic"]["counts"]["tokens"]["total"] > 0,
        "Anthropic 5h": usage["anthropic"]["unified_5h"]["utilization"] == 0.42,
        "Anthropic 7d": usage["anthropic"]["unified_7d"]["status"] == "allowed_warning",
        "Codex primary": usage["codex"]["primary"]["used_percent"] == 42.5,
        "Codex secondary": usage["codex"]["secondary"]["window_minutes"] == 10080,
        "observation time": usage["codex"]["primary"]["observed_at"] > 0,
        # Its two successful Responses requests, and no other caller's.
        "operator not counted by name": {name: counts["requests"] + counts["unmetered"]
                                         for name, counts in usage["operators"].items()} == {"interactive": 2},
        "secret in snapshot": not check.leaks(text) and run_token not in text and "SYNTHETIC" not in text,
    })
    for path, headers in [
        ("/anthropic/v1/messages", [C]),
        ("/anthropic/v1/messages/count_tokens", [P, ("x-run-token", run_token)]),
    ]:
        resp = request(port, path, headers,
                       b'{"model":"claude-synthetic","max_tokens":1,"messages":[{"role":"user","content":"hi"}]}')
        resp.read()
    resp = request(port, "/usage", [], b"", method="GET")
    check.report("pass-through and count_tokens leave broker usage unchanged", {
        "snapshot changed": json.loads(resp.read()) == usage,
    })


def run_body_limits(port, seen, check, run_token):
    """Bodies up to the Messages API limit are forwarded, larger ones are not."""
    head = b'{"model":"claude-synthetic","max_tokens":1,"messages":[{"role":"user","content":"'
    tail = b'"}]}'
    for name, size, want_status, clusters in [
        ("/anthropic: 11 MiB body, above Praxis's default limit", 11 << 20, 200, [ANTHROPIC]),
        ("/anthropic: body over the configured limit", MAX_REQUEST_BYTES + 1, 413, []),
    ]:
        body = head + b"x" * (size - len(head) - len(tail)) + tail
        before = len(seen)
        resp = request(port, "/anthropic/v1/messages", [P, ("x-run-token", run_token)], body)
        resp.read()
        hits = seen[before:]
        check.report(name, {
            f"status {resp.status} != {want_status}": resp.status == want_status,
            f"upstreams hit: {[h['cluster'] for h in hits]}": [h["cluster"] for h in hits] == clusters,
            "body changed": all(h["body_sha256"] == hashlib.sha256(body).hexdigest() for h in hits),
        })


def run_h2c(port, seen, check, run_token):
    """The listener also speaks HTTP/2 with prior knowledge; route it the same."""
    rt = f"x-run-token: {run_token}"
    for name, path, headers, want_status, clusters, want_auth in [
        ("h2c: injected", "/anthropic/v1/messages", [f"Authorization: {PLACEHOLDER}", rt], 200, [ANTHROPIC], INJECTED),
        ("h2c: placeholder without a run token", "/anthropic/v1/messages", [f"Authorization: {PLACEHOLDER}"],
         401, [], None),
        ("h2c: pass-through", "/anthropic/v1/messages", [f"Authorization: {CLIENT_OAUTH}"], 200, [PASS],
         [CLIENT_OAUTH]),
        ("h2c: /v1 dot-dot into /anthropic", "/v1/../anthropic/v1/messages", [f"Authorization: {PLACEHOLDER}", rt],
         403, [], None),
        ("h2c: /anthropic dot-dot into /v1/responses", "/anthropic/../v1/responses",
         [f"Authorization: Bearer {run_token}"], 404, [], None),
    ]:
        before = len(seen)
        args = []
        for header in headers:
            args += ["--header", header]
        proc = subprocess.run(["curl", "--silent", "--http2-prior-knowledge", "--path-as-is",
                               "--output", "/dev/null", "--write-out", "%{http_code} %{http_version}",
                               *args, "--header", "content-type: application/json",
                               "--data", '{"model":"claude-synthetic","max_tokens":1,'
                                         '"messages":[{"role":"user","content":"hi"}]}',
                               f"http://127.0.0.1:{port}{path}"],
                              capture_output=True, text=True, timeout=30)
        status, _, version = proc.stdout.partition(" ")
        hits = seen[before:]
        up = header_map(hits[0]["headers"]) if len(hits) == 1 else {}
        check.report(name, {
            f"not HTTP/2: {version}": version == "2",
            f"status {status} != {want_status}": status == str(want_status),
            f"upstreams hit: {[h['cluster'] for h in hits]}": [h["cluster"] for h in hits] == clusters,
            "upstream Authorization": not clusters or up.get("authorization") == want_auth,
        })


def wait_ready(port, name):
    for _ in range(100):
        try:
            # Not /anthropic/v1/messages, whose validation would answer first.
            resp = request(port, "/anthropic/v1/messages/count_tokens", [], b"", method="GET")
            resp.read()
            if resp.status == 403:
                return
        except OSError:
            pass
        state = podman("inspect", "--format", "{{.State.Running}}", name, check=False).stdout.strip()
        if state == "false":
            break
        time.sleep(0.2)
    print(podman("logs", name, check=False).stderr, file=sys.stderr)
    raise SystemExit("Praxis did not become ready")


def register_run(port, run_id):
    resp = request(port, "/v1/runs", [("Authorization", f"Bearer {oidc_token(run_id)}")], b"")
    body = resp.read()
    if resp.status != 201:
        raise SystemExit(f"run registration failed: {resp.status} {body!r}")
    return json.loads(body)["token"]


def run_oidc(port, seen, check, permissive):
    """Which OIDC tokens register, under the policy as committed or with
    PERMISSIVE: the same statuses either way for a token no entry admits."""
    policy = "a permissive policy" if permissive else "the default policy"
    before = len(seen)
    admitted = {}
    for number, (name, claims, default, with_entries) in enumerate(OIDC_CASES):
        want_status, want = with_entries if permissive else default
        # Runs of their own, in each repository: 1 to 3 are the other checks'.
        resp = request(port, "/v1/runs", [("Authorization", f"Bearer {oidc_token(100 + number, claims)}")], b"")
        text = resp.read().decode()
        checks = {f"status {resp.status} != {want_status}": resp.status == want_status}
        if resp.status == 201:
            registered = json.loads(text)
            check.secrets.append(registered["token"])
            admitted[name] = registered
            by = registered["usage"].get("admitted_by")
            checks[f"admitted by {by}"] = by == want
        else:
            checks[f"body {text!r}"] = text == want
        check.report(f"{policy}: registration of {name}", checks)
    check.report(f"{policy}: registration reaches no upstream", {"upstreams hit": len(seen) == before})
    return admitted


def run_admitted(port, seen, check, admitted):
    """A run one of PERMISSIVE's entries admitted is a run like any other,
    and its record and the logs say whose it is."""
    registered = admitted.get("a reusable workflow called from the test repository")
    if registered is None:
        check.report("a called workflow's run is metered, recorded and ended", {"registered": False})
        return
    token = registered["token"]
    body = b'{"model":"claude-synthetic","max_tokens":1,"messages":[{"role":"user","content":"hi"}]}'
    before = len(seen)
    resp = request(port, "/anthropic/v1/messages", [P, ("x-run-token", token)], body)
    resp.read()
    record = json.loads(request(port, "/v1/runs/self", [("x-run-token", token)], b"", method="DELETE").read())
    after = request(port, "/anthropic/v1/messages", [P, ("x-run-token", token)], body)
    after.read()
    who = {name: record.get(name) for name in (
        "proof", "admitted_by", "repository", "repository_id", "repository_owner_id", "workflow_ref", "workflow_sha",
        "entry_workflow_ref", "event_name", "actor")}
    run = record.get("run_id")
    check.report("a called workflow's run is metered, recorded and ended", {
        f"status {resp.status}": resp.status == 200,
        "upstreams hit": [h["cluster"] for h in seen[before:]] == [ANTHROPIC],
        f"record {who}": who == {
            "proof": "github-oidc", "admitted_by": "called_workflows", "repository": "owner/repo",
            "repository_id": 7, "repository_owner_id": 70, "workflow_ref": f"{CALLED}@refs/heads/main",
            "workflow_sha": CALLED_SHA, "entry_workflow_ref": CALLER, "event_name": "workflow_dispatch",
            "actor": "someone"},
        f"usage {record.get('requests')}, {record.get('tokens')}": (
            record.get("requests"), record.get("tokens", {}).get("total"), record.get("state")) == (1, 90, "finished"),
        f"status {after.status} after the end": after.status == 401,
    })
    logs = container_logs(CONTAINER)
    lines = [line for line in logs.splitlines() if "run registered" in line and f"github-run:7/{run}/1" in line]
    check.report("the new entries are announced, and a registration logged with what admitted it", {
        "no warning at startup": "ANY WORKFLOW" in logs and "called from other repositories" in logs,
        f"registration: {lines}": len(lines) == 1 and all(
            part in lines[0] for part in ("called_workflows", f"{CALLED}@refs/heads/main", CALLED_SHA, CALLER,
                                          "owner/repo", "someone")),
        "request not logged under its run": any(f"github-run:7/{run}/1" in line for line in logs.splitlines()
                                                if "request usage" in line),
        # Names the admitted party chose are quoted and escaped, on the
        # registration's own line.
        "a claim forged a log line": [json.dumps(FORGING)[1:-1] in line and "run registered" in line
                                      and "github-run:81/" in line
                                      for line in logs.splitlines() if "FORGED LINE" in line] == [True],
        f"in logs: {check.leaks(logs)}": not [s for s in check.secrets if s in logs],
    })


def container_logs(name):
    logs = podman("logs", name)
    return re.sub(r"\x1b\[[0-9;]*m", "", logs.stdout + logs.stderr)


def run_unproven(port, seen, check):
    """A policy with `unproven` registers runs on the caller's word: within
    its quota, once per name, and as runs like any other."""
    tokens = {}
    for name, headers, want_status, want_body in UNPROVEN_CASES:
        resp = request(port, "/v1/runs", headers, b"")
        text = resp.read().decode()
        checks = {f"status {resp.status} != {want_status}": resp.status == want_status}
        if want_body is None:
            registered = json.loads(text)
            run = dict(headers)["x-run-id"]
            tokens[run] = registered["token"]
            checks["record"] = (registered["usage"]["proof"], registered["usage"]["run"]) == ("none", run)
        else:
            checks[f"body {text!r}"] = text == want_body
        check.report(f"registration without proof {name}", checks)
    check.secrets += tokens.values()
    token = tokens["job-1"]
    proven = register_run(port, 2)
    check.secrets.append(proven)
    body = b'{"model":"claude-synthetic","max_tokens":1,"messages":[{"role":"user","content":"hi"}]}'
    before = len(seen)
    statuses = []
    for run_token in (token, proven):
        resp = request(port, "/anthropic/v1/messages", [P, ("x-run-token", run_token)], body)
        resp.read()
        statuses.append(resp.status)
    record = json.loads(request(port, "/v1/runs/self", [("x-run-token", token)], b"", method="GET").read())
    usage = json.loads(request(port, "/usage", [], b"", method="GET").read())
    finished = json.loads(request(port, "/v1/runs/self", [("x-run-token", token)], b"", method="DELETE").read())
    after = request(port, "/anthropic/v1/messages", [P, ("x-run-token", token)], body)
    after.read()
    counts = usage.get("unproven_runs", {})
    check.report("a run registered without proof is metered, counted apart and ended", {
        f"statuses {statuses}": statuses == [200, 200],
        "upstreams hit": [h["cluster"] for h in seen[before:]] == [ANTHROPIC, ANTHROPIC],
        "run token or placeholder upstream": all(
            header_map(h["headers"]).get("authorization") == INJECTED
            and "x-run-token" not in header_map(h["headers"]) for h in seen[before:]),
        f"record {record}": (record["proof"], record["run"], record["requests"], record["tokens"]["total"])
        == ("none", "job-1", 1, 90),
        # Both runs' requests are Anthropic's; only the unproven run's are counted apart.
        f"usage {counts}": (counts.get("registered"), counts.get("refused"), counts.get("requests"),
                            counts.get("tokens", {}).get("total")) == (2, 1, 1, 90),
        "provider counts": usage["anthropic"]["counts"]["requests"] == 2,
        "run names in /usage": "job-1" not in json.dumps(usage),
        "not finished": finished["state"] == "finished" and finished["run"] == "job-1",
        f"status {after.status} after the end": after.status == 401,
    })
    logs = container_logs(CONTAINER)
    check.report("registration without proof is announced and logged apart", {
        "no warning at startup": "WITHOUT PROOF" in logs,
        "registration not logged": "unproven run registered" in logs and "unproven-run:job-1" in logs,
        "request not logged under its kind": any("unproven-run:job-1" in line for line in logs.splitlines()
                                                  if "request usage" in line),
        "proven run logged as unproven": "unproven-run:2" not in logs and "github-run:7/2/1" in logs,
        f"in logs: {check.leaks(logs)}": not [s for s in check.secrets if s in logs],
    })


def check_refuses_start(check, name, config_path, policy_path):
    """Startup must fail rather than serve without the broker's token."""
    container = CONTAINER + "-nostart"
    try:
        proc = subprocess.run(["podman", "run", "--rm", "--name", container,
                               *container_args(config_path, policy_path, with_secret=False)],
                              capture_output=True, text=True, timeout=60)
        check.report(name, {
            "Praxis started": proc.returncode != 0,
            "error does not explain why": TOKEN_FILE in proc.stdout + proc.stderr,
        })
    except subprocess.TimeoutExpired:
        check.report(name, {"Praxis started": False})
    finally:
        podman("rm", "-f", container, check=False)


def main():
    check = Checker()
    check_filter_order(check)
    build_image()
    seen = []
    upstreams = {}
    for cluster in CLUSTERS:
        server = ThreadingHTTPServer(("127.0.0.1", free_port()), Upstream)
        server.seen, server.cluster = seen, cluster
        threading.Thread(target=server.serve_forever, daemon=True).start()
        upstreams[cluster] = server
    jwks = ThreadingHTTPServer(("127.0.0.1", free_port()), Jwks)
    threading.Thread(target=jwks.serve_forever, daemon=True).start()
    with tempfile.TemporaryDirectory() as tmp:
        Path(tmp).chmod(0o755)
        praxis_port = free_port()
        config_path = Path(tmp) / "praxis.yaml"
        config_path.write_text(test_config(praxis_port, upstreams))
        policy_path = Path(tmp) / "run-token-policy.yaml"
        policy = {"workflows": [WORKFLOW], "repository_ids": [7],
                  "jwks_url": f"http://127.0.0.1:{jwks.server_address[1]}/jwks"}
        policy_path.write_text(json.dumps(policy))
        operators_path = Path(tmp) / "operator-tokens.yaml"
        operators_path.write_text(json.dumps({"operators": [{
            "name": "interactive", "token_sha256": hashlib.sha256(OPERATOR_TOKEN.encode()).hexdigest(),
            "clusters": [RESPONSES]}]}))
        for path in (config_path, policy_path, operators_path):
            path.chmod(0o644)
        # Podman 4 (Ubuntu's, in CI) has no secret create --replace.
        podman("secret", "rm", "--ignore", SECRET, check=False)
        podman("secret", "create", SECRET, "-", stdin=TOKEN)
        podman("rm", "-f", CONTAINER, check=False)
        try:
            podman("run", "--detach", "--name", CONTAINER, *container_args(config_path, policy_path))
            wait_ready(praxis_port, CONTAINER)
            run_token = register_run(praxis_port, 1)
            check.secrets += [run_token, OPERATOR_TOKEN]
            run_cases(praxis_port, seen, check, run_token, ANTHROPIC_CASES + SHARED_CASES)
            run_stream(praxis_port, seen, check, run_token)
            run_body_limits(praxis_port, seen, check, run_token)
            run_h2c(praxis_port, seen, check, run_token)
            run_usage(praxis_port, seen, check, run_token)
            run_oidc(praxis_port, seen, check, permissive=False)
            logs = container_logs(CONTAINER)
            inspect = podman("inspect", CONTAINER).stdout
            usage = [line for line in logs.splitlines() if "request usage" in line]
            check.report("no credential in logs or inspect; every request metered", {
                f"in logs: {check.leaks(logs)}": not [s for s in check.secrets if s in logs],
                "token in podman inspect": TOKEN not in inspect,
                "no metered injected request": any(re.search(r"\binjected\b.*\btotal\W+90\b", line)
                                                   for line in usage),
                "no metered pass-through request": any(re.search(r"\bpass-through\b.*\btotal\W+90\b", line)
                                                       for line in usage),
            })
            check_refuses_start(check, "startup fails without the token", config_path, policy_path)
            # The setting is off unless the policy says otherwise.
            usage = json.loads(request(praxis_port, "/usage", [], b"", method="GET").read())
            check.report("registration without proof is off by default", {
                "announced in the logs": "WITHOUT PROOF" not in logs and "unproven" not in logs,
                "listed in /usage": "unproven_runs" not in usage,
            })
            check.report("the permissive entries are off by default", {
                "announced in the logs": "ANY WORKFLOW" not in logs and "called from other" not in logs,
            })
            policy["unproven"] = {"max_registrations": 2}
            policy.update(PERMISSIVE)
            policy_path.write_text(json.dumps(policy))
            podman("rm", "-f", CONTAINER)
            podman("run", "--detach", "--name", CONTAINER, *container_args(config_path, policy_path))
            wait_ready(praxis_port, CONTAINER)
            run_unproven(praxis_port, seen, check)
            run_admitted(praxis_port, seen, check, run_oidc(praxis_port, seen, check, permissive=True))
        finally:
            podman("rm", "-f", CONTAINER, check=False)
            podman("secret", "rm", "--ignore", SECRET, check=False)
            for server in [*upstreams.values(), jwks]:
                server.shutdown()
    print("Gateway checks " + ("failed" if check.failed else "passed") + ".")
    return 1 if check.failed else 0


if __name__ == "__main__":
    sys.exit(main())
