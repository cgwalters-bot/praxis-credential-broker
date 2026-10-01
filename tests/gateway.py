#!/usr/bin/env python3
"""Check the gateway image's routes against fake upstreams.

Builds the gateway image (Containerfile.gateway) and runs it with the pod's
container hardening and a synthetic Claude OAuth token delivered as a Podman
secret file. Each configuration baked into the image is replaced by a copy in
which only the listener address and the upstream endpoints are rewritten, so
the filter order and conditions under test are the ones that ship. Each
cluster gets a fake upstream of its own, so every case also checks which
upstream a request reached. No real credential is used or needed.

Usage: python3 tests/gateway.py
"""

import hashlib
import json
import re
import socket
import subprocess
import sys
import tempfile
import threading
import time
from http.client import HTTPConnection
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
CONTAINERFILE = ROOT / "Containerfile.gateway"
POD_SCRIPT = ROOT / "scripts" / "native-pod.sh"
PLAIN_CONFIG = ROOT / "praxis.yaml"
ANTHROPIC_CONFIG = ROOT / "praxis-anthropic.yaml"

IMAGE = "localhost/praxis-gateway:test"
CONTAINER = "praxis-credential-broker-test-gateway"
SECRET = "praxis-credential-broker-test-anthropic-oauth"
TOKEN_FILE = "/run/secrets/anthropic/oauth-token"
TOKEN = "sk-ant-oat01-SYNTHETIC-TEST-TOKEN-0123456789abcdef"
PLACEHOLDER = "Bearer praxis-substitute:anthropic"
INJECTED = ["Bearer " + TOKEN]
OAUTH_BETA = "oauth-2025-04-20"
CLIENT_BETA = "claude-code-20250219,interleaved-thinking-2025-05-14"
CLIENT_OAUTH = "Bearer sk-ant-oat01-client"
CLIENT_KEY = "Bearer client-api-key-for-credential-proxy"
SSE_DELAY = 0.3
MAX_REQUEST_BYTES = 33554432

# The fake upstream that stands in for each cluster of the load_balancer.
RESPONSES, ANTHROPIC, CLIENT = "inference-backend", "anthropic", "anthropic-client-oauth"
CLUSTERS = (RESPONSES, ANTHROPIC, CLIENT)

# The deny filters must come first and the router before anything that
# changes the request. A reordering is a security change, not a refactor.
ANTHROPIC_FILTERS = [
    "static_response", "static_response", "openai_responses_proxy", "anthropic_messages_format",
    "anthropic_validate", "anthropic_messages_protocol", "router", "path_rewrite", "headers",
    "headers", "credential_injection", "load_balancer",
]

P = ("Authorization", PLACEHOLDER)
C = ("Authorization", CLIENT_OAUTH)
K = ("Authorization", CLIENT_KEY)

# (name, method, path, request headers as pairs, expected status, cluster)
# A request for a cluster must reach that cluster's upstream exactly once and
# no other; a request with cluster None must reach no upstream at all.
#
# PR #5's placeholder cases, on the /anthropic prefix.
ANTHROPIC_CASES = [
    ("placeholder", "/v1/messages", [P], 200, ANTHROPIC),
    ("placeholder, lowercase header name", "/v1/messages", [("authorization", PLACEHOLDER)], 200, ANTHROPIC),
    ("placeholder, trailing whitespace trimmed by HTTP", "/v1/messages", [("Authorization", PLACEHOLDER + " ")], 200, ANTHROPIC),
    ("placeholder plus x-api-key", "/v1/messages", [P, ("x-api-key", "sk-ant-api03-client")], 200, ANTHROPIC),
    ("placeholder plus client Host", "/v1/messages", [P, ("Host", "evil.example")], 200, ANTHROPIC),
    ("count_tokens", "/v1/messages/count_tokens", [P], 200, ANTHROPIC),
    ("duplicate Authorization, placeholder first", "/v1/messages", [P, C], 200, ANTHROPIC),
    ("no Authorization", "/v1/messages", [], 403, None),
    ("unknown placeholder", "/v1/messages", [("Authorization", "Bearer praxis-substitute:nope")], 403, None),
    ("client's own OAuth token", "/v1/messages", [C], 403, None),
    ("placeholder only in x-api-key", "/v1/messages", [("x-api-key", "praxis-substitute:anthropic")], 403, None),
    ("Bearer placeholder only in x-api-key", "/v1/messages", [("x-api-key", PLACEHOLDER)], 403, None),
    ("scheme case: bearer", "/v1/messages", [("Authorization", "bearer praxis-substitute:anthropic")], 403, None),
    ("scheme case: BEARER", "/v1/messages", [("Authorization", "BEARER praxis-substitute:anthropic")], 403, None),
    ("name case: ANTHROPIC", "/v1/messages", [("Authorization", "Bearer praxis-substitute:ANTHROPIC")], 403, None),
    ("double space after Bearer", "/v1/messages", [("Authorization", "Bearer  praxis-substitute:anthropic")], 403, None),
    ("no scheme", "/v1/messages", [("Authorization", "praxis-substitute:anthropic")], 403, None),
    ("placeholder as a prefix", "/v1/messages", [("Authorization", PLACEHOLDER + "x")], 403, None),
    ("placeholder inside another value", "/v1/messages", [("Authorization", "Bearer sk-real praxis-substitute:anthropic")], 403, None),
    ("duplicate Authorization, other value first", "/v1/messages", [C, P], 403, None),
    ("Basic scheme", "/v1/messages", [("Authorization", "Basic cHJheGlzLXN1YnN0aXR1dGU6YW50aHJvcGlj")], 403, None),
    ("placeholder outside /v1/", "/api/oauth/profile", [P], 404, None),
    ("other /v1/ endpoint", "/v1/models", [P], 404, None),
    ("/v1 without a slash", "/v1", [P], 404, None),
    ("dot-dot out of /v1/", "/v1/../api/oauth/profile", [P], 404, None),
    ("dot-dot out of /v1/messages", "/v1/messages/../../api/oauth/profile", [P], 404, None),
    ("encoded dot-dot", "/v1/messages/%2e%2e/%2e%2e/api/oauth/profile", [P], 404, None),
    ("prefix of messages path", "/v1/messagesx", [P], 404, None),
]
ANTHROPIC_CASES = [(f"/anthropic: {name}", "POST", "/anthropic" + path, *rest)
                   for name, path, *rest in ANTHROPIC_CASES] + [
    ("/anthropic: GET with placeholder", "GET", "/anthropic/v1/messages", [P], 403, None),
    ("/anthropic: TRACE with placeholder", "TRACE", "/anthropic/v1/messages", [P], 403, None),
    ("/anthropic: DELETE with placeholder", "DELETE", "/anthropic/v1/messages", [P], 403, None),
    # Methods are case-sensitive in HTTP, but Praxis's method condition is
    # not, and the router has no method match, so these are forwarded as is.
    # The upstream is fixed, and TRACE cannot be spelled this way.
    ("/anthropic: lowercase post", "post", "/anthropic/v1/messages", [P], 200, ANTHROPIC),
    ("/anthropic: mixed-case PoSt", "PoSt", "/anthropic/v1/messages", [P], 200, ANTHROPIC),
    ("/anthropic: lowercase trace", "trace", "/anthropic/v1/messages", [P], 403, None),
]

# Responses and client-OAuth Messages next to /anthropic, and every way found
# to cross from one prefix into another.
SHARED_CASES = [
    ("Responses with the client key", "POST", "/v1/responses", [K], 200, RESPONSES),
    ("Responses without Authorization", "POST", "/v1/responses", [], 200, RESPONSES),
    ("Responses with a query string", "POST", "/v1/responses?stream=true", [K], 200, RESPONSES),
    ("Responses keeps a client anthropic-beta and x-api-key", "POST", "/v1/responses",
     [K, ("anthropic-beta", CLIENT_BETA), ("x-api-key", "client")], 200, RESPONSES),
    ("healthz", "GET", "/healthz", [], 200, RESPONSES),
    ("placeholder on /v1/responses", "POST", "/v1/responses", [P], 403, None),
    ("placeholder on /healthz", "GET", "/healthz", [P], 403, None),
    ("client OAuth on /v1/messages", "POST", "/v1/messages", [C], 200, CLIENT),
    ("client OAuth plus x-api-key on /v1/messages", "POST", "/v1/messages",
     [C, ("x-api-key", "sk-ant-api03-client")], 200, CLIENT),
    ("placeholder on /v1/messages", "POST", "/v1/messages", [P], 403, None),
    ("client OAuth count_tokens without the prefix", "POST", "/v1/messages/count_tokens", [C], 404, None),
    ("client OAuth dot-dot out of /v1/messages", "POST", "/v1/messages/../../api/oauth/profile", [C], 404, None),
    ("/v1 dot-dot into /anthropic, placeholder", "POST", "/v1/../anthropic/v1/messages", [P], 403, None),
    ("/v1 dot-dot into /anthropic, client OAuth", "POST", "/v1/../anthropic/v1/messages", [C], 404, None),
    ("/v1/responses dot-dot into /anthropic, placeholder", "POST",
     "/v1/responses/../../anthropic/v1/messages", [P], 403, None),
    # Forwarded as is to credential-proxy, which serves only the exact path
    # /v1/responses; never to an Anthropic upstream.
    ("/v1/responses dot-dot into /anthropic, client key", "POST",
     "/v1/responses/../../anthropic/v1/messages", [K], 200, RESPONSES),
    ("/anthropic dot-dot into /v1/responses, placeholder", "POST", "/anthropic/../v1/responses", [P], 404, None),
    ("/anthropic dot-dot into /v1/responses, client key", "POST", "/anthropic/../v1/responses", [K], 403, None),
    ("/anthropic dot-dot into /v1/messages, client OAuth", "POST", "/anthropic/../v1/messages", [C], 403, None),
    ("/anthropic/v1 dot-dot into /v1/responses", "POST", "/anthropic/v1/../../v1/responses", [P], 404, None),
    ("/anthropic encoded dot-dot into /v1/responses", "POST", "/anthropic/%2e%2e/v1/responses", [P], 404, None),
    ("/anthropic mixed encoded dot-dot", "POST", "/anthropic/v1/messages/.%2e/count_tokens", [P], 404, None),
    ("/anthropic encoded slashes", "POST", "/anthropic%2fv1%2fmessages", [P], 403, None),
    ("/anthropic encoded slash after the prefix", "POST", "/anthropic/v1%2fmessages", [P], 404, None),
    ("leading double slash", "POST", "//anthropic/v1/messages", [P], 403, None),
    ("double slash after the prefix", "POST", "/anthropic//v1/messages", [P], 404, None),
    ("dot segment after the prefix", "POST", "/anthropic/./v1/messages", [P], 404, None),
    ("prefix case: ANTHROPIC", "POST", "/ANTHROPIC/v1/messages", [P], 403, None),
    ("prefix as a word prefix", "POST", "/anthropicx/v1/messages", [P], 403, None),
    ("trailing slash", "POST", "/anthropic/v1/messages/", [P], 404, None),
    ("bare prefix", "POST", "/anthropic", [P], 404, None),
    ("bare prefix with a slash", "POST", "/anthropic/", [P], 404, None),
    ("Responses under the prefix", "POST", "/anthropic/v1/responses", [P], 404, None),
    ("healthz under the prefix", "POST", "/anthropic/healthz", [P], 404, None),
]

# With the gateway disabled, the image serves praxis.yaml: Responses only.
DISABLED_CASES = [
    ("disabled: Responses with the client key", "POST", "/v1/responses", [K], 200, RESPONSES),
    ("disabled: healthz", "GET", "/healthz", [], 200, RESPONSES),
    ("disabled: /anthropic with placeholder", "POST", "/anthropic/v1/messages", [P], 404, None),
    ("disabled: client OAuth on /v1/messages", "POST", "/v1/messages", [C], 404, None),
]

DENY_BODIES = {
    "/anthropic": {"type": "error", "error": {"type": "permission_error",
                                              "message": "missing or unknown praxis placeholder credential"}},
    "elsewhere": {"type": "error", "error": {"type": "permission_error",
                                             "message": "praxis placeholder credential outside /anthropic"}},
}


class Upstream(BaseHTTPRequestHandler):
    """Records what the gateway forwards and answers like the Messages API."""

    protocol_version = "HTTP/1.1"

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
            out = b'{"id":"msg_synthetic","type":"message","content":[{"type":"text","text":"OK"}]}'
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
        for event in ("message_start", "content_block_delta", "content_block_delta", "message_stop"):
            chunk = f'event: {event}\ndata: {{"type":"{event}"}}\n\n'.encode()
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


def podman(*args, check=True, stdin=None):
    proc = subprocess.run(["podman", *args], input=stdin, capture_output=True, text=True)
    if check and proc.returncode != 0:
        raise SystemExit(f"podman {args[0]} {args[1] if len(args) > 1 else ''} failed: {proc.stderr.strip()}")
    return proc


def free_port():
    with socket.socket() as s:
        s.bind(("127.0.0.1", 0))
        return s.getsockname()[1]


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


def test_config(path, praxis_port, upstreams):
    text = path.read_text()
    text = replace_once(path, text, 'address: "0.0.0.0:8081"', f'address: "127.0.0.1:{praxis_port}"')
    for name, server in upstreams.items():
        if f"- name: {name}\n" in text:
            text = rewrite_cluster(path, text, name, server.server_address[1])
    return text


def check_filter_order(check):
    filters = re.findall(r"^\s+- filter: (\S+)", ANTHROPIC_CONFIG.read_text(), re.MULTILINE)
    check.report(f"{ANTHROPIC_CONFIG.name} filter order", {
        f"filters are {filters}": filters == ANTHROPIC_FILTERS,
    })


def container_args(config_path, mode, with_secret=True):
    """The praxis container's settings in native-pod.sh, on the host network."""
    target = ANTHROPIC_CONFIG.name if mode == "enabled" else PLAIN_CONFIG.name
    args = ["--network", "host", "--user", "65532:65532", "--read-only", "--cap-drop=ALL",
            "--security-opt=no-new-privileges", "--tmpfs", "/tmp:rw,noexec,nosuid,nodev,size=64m",
            "--no-healthcheck", "--env", f"PRAXIS_ANTHROPIC_GATEWAY={mode}",
            "--volume", f"{config_path}:/etc/praxis/{target}:ro,Z"]
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


def leaks(text):
    return [s for s in (TOKEN, OAUTH_BETA) if s in text]


class Checker:
    def __init__(self):
        self.failed = 0

    def report(self, name, checks):
        bad = [k for k, ok in checks.items() if not ok]
        self.failed += bool(bad)
        print(f"[{'FAIL' if bad else 'PASS'}] {name}" + (f": {', '.join(bad)}" if bad else ""))


def forwarded_checks(cluster, path, headers, body, hit):
    """What each cluster's upstream must and must not receive."""
    sent, up = header_map(headers), header_map(hit["headers"])
    checks = {
        "body changed": hit["body_sha256"] == hashlib.sha256(body).hexdigest(),
        "token sent to the wrong upstream": cluster == ANTHROPIC or TOKEN not in str(hit["headers"]),
    }
    if cluster == ANTHROPIC:
        return checks | {
            "upstream Authorization is not the single injected token": up.get("authorization") == INJECTED,
            "x-api-key forwarded": "x-api-key" not in up,
            "anthropic-beta not added": up.get("anthropic-beta") == [OAUTH_BETA],
            "Host not rewritten": up.get("host") == ["api.anthropic.com"],
            "prefix not stripped": hit["path"] == path.removeprefix("/anthropic"),
        }
    checks |= {"OAuth beta added": OAUTH_BETA not in str(up.get("anthropic-beta")),
               "path changed": hit["path"] == path}
    if cluster == CLIENT:
        return checks | {
            "client Authorization not passed through": up.get("authorization") == sent.get("authorization"),
            "x-api-key forwarded": "x-api-key" not in up,
            "Host not rewritten": up.get("host") == ["api.anthropic.com"],
        }
    return checks | {
        "client Authorization changed": up.get("authorization") == sent.get("authorization"),
        "client x-api-key changed": up.get("x-api-key") == sent.get("x-api-key"),
        "client anthropic-beta changed": up.get("anthropic-beta") == sent.get("anthropic-beta"),
        "Host rewritten to Anthropic": up.get("host") != ["api.anthropic.com"],
    }


def run_cases(port, seen, check, cases):
    body = json.dumps({"model": "claude-synthetic", "max_tokens": 1,
                       "messages": [{"role": "user", "content": "hi"}]}).encode()
    for name, method, path, headers, want_status, cluster in cases:
        before = len(seen)
        resp = request(port, path, headers, body, method)
        text = resp.read().decode(errors="replace")
        hits = seen[before:]
        checks = {f"status {resp.status} != {want_status}": resp.status == want_status,
                  "token or beta in response": not leaks(text + str(resp.getheaders()))}
        if cluster:
            checks[f"upstreams hit: {[h['cluster'] for h in hits]}"] = [h["cluster"] for h in hits] == [cluster]
            if len(hits) == 1:
                checks |= forwarded_checks(cluster, path, headers, body, hits[0])
        else:
            checks[f"upstreams hit: {[h['cluster'] for h in hits]}"] = not hits
        if want_status == 403:
            prefix = "/anthropic" if path.startswith("/anthropic/") else "elsewhere"
            checks["unexpected 403 body"] = json.loads(text) == DENY_BODIES[prefix]
        check.report(name, checks)


def run_stream(port, seen, check):
    """Claude Code's shape: streaming, its own betas, a query string."""
    body = ('{"stream":true,  "model":"claude-synthetic","max_tokens":5,\n'
            '"messages":[{"role":"user","content":"h\\u00e9llo ☃ 1.0e0"}],"zzz":1}').encode()
    before = len(seen)
    start = time.monotonic()
    resp = request(port, "/anthropic/v1/messages?beta=true", [P, ("anthropic-beta", CLIENT_BETA)], body)
    arrivals = []
    while chunk := resp.read1(65536):
        arrivals += [time.monotonic() - start] * chunk.count(b"\n\n")
    hits = seen[before:]
    up = header_map(hits[0]["headers"]) if len(hits) == 1 else {}
    check.report("/anthropic: streaming request with client betas", {
        "status": resp.status == 200,
        "upstreams hit": [h["cluster"] for h in hits] == [ANTHROPIC],
        "upstream Authorization is not the single injected token": up.get("authorization") == INJECTED,
        "OAuth beta not appended to the client's": up.get("anthropic-beta") == [f"{CLIENT_BETA},{OAUTH_BETA}"],
        "query or path changed": len(hits) == 1 and hits[0]["path"] == "/v1/messages?beta=true",
        "body not byte-identical": len(hits) == 1 and hits[0]["body_sha256"] == hashlib.sha256(body).hexdigest(),
        "events not delivered incrementally": len(arrivals) == 4 and arrivals[-1] - arrivals[0] > 2 * SSE_DELAY,
    })


def run_body_limits(port, seen, check):
    """Bodies up to the Messages API limit are forwarded, larger ones are not."""
    for name, size, want_status, clusters in [
        ("/anthropic: 11 MiB body, above Praxis's default limit", 11 << 20, 200, [ANTHROPIC]),
        ("/anthropic: body over the configured limit", MAX_REQUEST_BYTES + 1, 413, []),
    ]:
        body = b'{"model":"claude-synthetic","max_tokens":1,"pad":"' + b"x" * (size - 51) + b'"}'
        before = len(seen)
        resp = request(port, "/anthropic/v1/messages", [P], body)
        resp.read()
        hits = seen[before:]
        check.report(name, {
            f"status {resp.status} != {want_status}": resp.status == want_status,
            f"upstreams hit: {[h['cluster'] for h in hits]}": [h["cluster"] for h in hits] == clusters,
            "body changed": all(h["body_sha256"] == hashlib.sha256(body).hexdigest() for h in hits),
        })


def run_h2c(port, seen, check):
    """The listener also speaks HTTP/2 with prior knowledge; route it the same."""
    for name, path, auth, want_status, clusters in [
        ("h2c: placeholder", "/anthropic/v1/messages", PLACEHOLDER, 200, [ANTHROPIC]),
        ("h2c: no placeholder", "/anthropic/v1/messages", CLIENT_OAUTH, 403, []),
        ("h2c: /v1 dot-dot into /anthropic", "/v1/../anthropic/v1/messages", PLACEHOLDER, 403, []),
        ("h2c: /anthropic dot-dot into /v1/responses", "/anthropic/../v1/responses", CLIENT_KEY, 403, []),
    ]:
        before = len(seen)
        proc = subprocess.run(["curl", "--silent", "--http2-prior-knowledge", "--path-as-is",
                               "--output", "/dev/null", "--write-out", "%{http_code} %{http_version}",
                               "--header", f"Authorization: {auth}", "--header", "content-type: application/json",
                               "--data", "{}", f"http://127.0.0.1:{port}{path}"],
                              capture_output=True, text=True, timeout=30)
        status, _, version = proc.stdout.partition(" ")
        hits = seen[before:]
        up = header_map(hits[0]["headers"]) if len(hits) == 1 else {}
        check.report(name, {
            f"not HTTP/2: {version}": version == "2",
            f"status {status} != {want_status}": status == str(want_status),
            f"upstreams hit: {[h['cluster'] for h in hits]}": [h["cluster"] for h in hits] == clusters,
            "upstream Authorization is not the single injected token":
                not clusters or up.get("authorization") == INJECTED,
        })


def wait_ready(port, name, path, want):
    for _ in range(100):
        try:
            resp = request(port, path, [])
            resp.read()
            if resp.status == want:
                return
        except OSError:
            pass
        state = podman("inspect", "--format", "{{.State.Running}}", name, check=False).stdout.strip()
        if state == "false":
            break
        time.sleep(0.2)
    print(podman("logs", name, check=False).stderr, file=sys.stderr)
    raise SystemExit("Praxis did not become ready")


def check_refuses_start(check, name, config_path, mode, with_secret, expect):
    """Startup must fail rather than serve with a missing or unknown setting."""
    container = CONTAINER + "-nostart"
    try:
        proc = subprocess.run(["podman", "run", "--rm", "--name", container,
                               *container_args(config_path, mode, with_secret)],
                              capture_output=True, text=True, timeout=60)
        check.report(name, {
            "Praxis started": proc.returncode != 0,
            "error does not explain why": expect in proc.stdout + proc.stderr,
        })
    except subprocess.TimeoutExpired:
        check.report(name, {"Praxis started": False})
    finally:
        podman("rm", "-f", container, check=False)


def run_gateway(tmp, check, mode, upstreams, seen, body):
    praxis_port = free_port()
    config = ANTHROPIC_CONFIG if mode == "enabled" else PLAIN_CONFIG
    config_path = Path(tmp) / f"{mode}-{config.name}"
    config_path.write_text(test_config(config, praxis_port, upstreams))
    config_path.chmod(0o644)
    podman("rm", "-f", CONTAINER, check=False)
    try:
        podman("run", "--detach", "--name", CONTAINER, *container_args(config_path, mode, mode == "enabled"))
        if mode == "enabled":
            wait_ready(praxis_port, CONTAINER, "/anthropic/v1/messages", 403)
        else:
            wait_ready(praxis_port, CONTAINER, "/anthropic/v1/messages", 404)
        body(praxis_port)
        logs = podman("logs", CONTAINER)
        inspect = podman("inspect", CONTAINER).stdout
        check.report(f"{mode}: no token in logs or inspect", {
            "token in logs": TOKEN not in logs.stdout + logs.stderr,
            "token in podman inspect": TOKEN not in inspect,
        })
    finally:
        podman("rm", "-f", CONTAINER, check=False)
    return config_path


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
    with tempfile.TemporaryDirectory() as tmp:
        Path(tmp).chmod(0o755)
        # Podman 4 (Ubuntu's, in CI) has no secret create --replace.
        podman("secret", "rm", "--ignore", SECRET, check=False)
        podman("secret", "create", SECRET, "-", stdin=TOKEN)
        try:
            def enabled(port):
                run_cases(port, seen, check, ANTHROPIC_CASES + SHARED_CASES)
                run_stream(port, seen, check)
                run_body_limits(port, seen, check)
                run_h2c(port, seen, check)
            config_path = run_gateway(tmp, check, "enabled", upstreams, seen, enabled)
            check_refuses_start(check, "enabled: startup fails without the token", config_path,
                                "enabled", False, TOKEN_FILE)
            check_refuses_start(check, "startup fails with an unknown mode", config_path,
                                "Enabled", True, "must be exactly")
            run_gateway(tmp, check, "disabled", upstreams, seen,
                        lambda port: run_cases(port, seen, check, DISABLED_CASES))
        finally:
            podman("rm", "-f", CONTAINER, check=False)
            podman("secret", "rm", "--ignore", SECRET, check=False)
            for server in upstreams.values():
                server.shutdown()
    print("Gateway checks " + ("failed" if check.failed else "passed") + ".")
    return 1 if check.failed else 0


if __name__ == "__main__":
    sys.exit(main())
