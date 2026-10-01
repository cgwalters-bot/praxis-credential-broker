#!/usr/bin/env python3
"""Check praxis-anthropic.yaml against a fake Anthropic upstream.

Builds the gateway image (Containerfile.gateway) and runs it with the pod's
container hardening and a synthetic OAuth token delivered as a Podman secret
file. The configuration baked into the image is replaced by a copy in which
only the listener address and the upstream endpoint are rewritten, so the
filter order under test is the one that ships. No real credential is used or
needed.

Usage: python3 tests/anthropic_gateway.py
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
CONFIG = ROOT / "praxis-anthropic.yaml"
CONTAINERFILE = ROOT / "Containerfile.gateway"
POD_SCRIPT = ROOT / "scripts" / "native-pod.sh"

IMAGE = "localhost/praxis-gateway:test"
CONTAINER = "praxis-credential-broker-test-anthropic"
SECRET = "praxis-credential-broker-test-anthropic-oauth"
TOKEN_FILE = "/run/secrets/anthropic/oauth-token"
TOKEN = "sk-ant-oat01-SYNTHETIC-TEST-TOKEN-0123456789abcdef"
PLACEHOLDER = "Bearer praxis-substitute:anthropic"
INJECTED = ["Bearer " + TOKEN]
OAUTH_BETA = "oauth-2025-04-20"
CLIENT_BETA = "claude-code-20250219,interleaved-thinking-2025-05-14"
SSE_DELAY = 0.3

# Production values that the test rewrites; each must occur exactly once.
PROD_LISTENER = 'address: "0.0.0.0:8090"'
PROD_ENDPOINT = """            endpoints: ["api.anthropic.com:443"]
            tls:
              sni: "api.anthropic.com"
"""

# (name, method, path, request headers as pairs, expected status, forwarded?)
# Forwarded requests must reach upstream exactly once with only the injected
# Authorization; denied ones must never reach it.
CASES = [
    ("placeholder", "/v1/messages", [("Authorization", PLACEHOLDER)], 200, True),
    ("placeholder, lowercase header name", "/v1/messages", [("authorization", PLACEHOLDER)], 200, True),
    ("placeholder, trailing whitespace trimmed by HTTP", "/v1/messages", [("Authorization", PLACEHOLDER + " ")], 200, True),
    ("placeholder plus x-api-key", "/v1/messages", [("Authorization", PLACEHOLDER), ("x-api-key", "sk-ant-api03-client")], 200, True),
    ("placeholder plus client Host", "/v1/messages", [("Authorization", PLACEHOLDER), ("Host", "evil.example")], 200, True),
    ("count_tokens", "/v1/messages/count_tokens", [("Authorization", PLACEHOLDER)], 200, True),
    ("duplicate Authorization, placeholder first", "/v1/messages",
     [("Authorization", PLACEHOLDER), ("Authorization", "Bearer sk-ant-oat01-client")], 200, True),
    ("no Authorization", "/v1/messages", [], 403, False),
    ("unknown placeholder", "/v1/messages", [("Authorization", "Bearer praxis-substitute:nope")], 403, False),
    ("client's own OAuth token", "/v1/messages", [("Authorization", "Bearer sk-ant-oat01-client")], 403, False),
    ("placeholder only in x-api-key", "/v1/messages", [("x-api-key", "praxis-substitute:anthropic")], 403, False),
    ("Bearer placeholder only in x-api-key", "/v1/messages", [("x-api-key", PLACEHOLDER)], 403, False),
    ("scheme case: bearer", "/v1/messages", [("Authorization", "bearer praxis-substitute:anthropic")], 403, False),
    ("scheme case: BEARER", "/v1/messages", [("Authorization", "BEARER praxis-substitute:anthropic")], 403, False),
    ("name case: ANTHROPIC", "/v1/messages", [("Authorization", "Bearer praxis-substitute:ANTHROPIC")], 403, False),
    ("double space after Bearer", "/v1/messages", [("Authorization", "Bearer  praxis-substitute:anthropic")], 403, False),
    ("no scheme", "/v1/messages", [("Authorization", "praxis-substitute:anthropic")], 403, False),
    ("placeholder as a prefix", "/v1/messages", [("Authorization", PLACEHOLDER + "x")], 403, False),
    ("placeholder inside another value", "/v1/messages", [("Authorization", "Bearer sk-real praxis-substitute:anthropic")], 403, False),
    ("duplicate Authorization, other value first", "/v1/messages",
     [("Authorization", "Bearer sk-ant-oat01-client"), ("Authorization", PLACEHOLDER)], 403, False),
    ("Basic scheme", "/v1/messages", [("Authorization", "Basic cHJheGlzLXN1YnN0aXR1dGU6YW50aHJvcGlj")], 403, False),
    ("placeholder outside /v1/", "/api/oauth/profile", [("Authorization", PLACEHOLDER)], 404, False),
    ("other /v1/ endpoint", "/v1/models", [("Authorization", PLACEHOLDER)], 404, False),
    ("/v1 without a slash", "/v1", [("Authorization", PLACEHOLDER)], 404, False),
    ("dot-dot out of /v1/", "/v1/../api/oauth/profile", [("Authorization", PLACEHOLDER)], 404, False),
    ("dot-dot out of /v1/messages", "/v1/messages/../../api/oauth/profile", [("Authorization", PLACEHOLDER)], 404, False),
    ("encoded dot-dot", "/v1/messages/%2e%2e/%2e%2e/api/oauth/profile", [("Authorization", PLACEHOLDER)], 404, False),
    ("prefix of messages path", "/v1/messagesx", [("Authorization", PLACEHOLDER)], 404, False),
]
CASES = [(name, "POST", *rest) for name, *rest in CASES] + [
    ("GET with placeholder", "GET", "/v1/messages", [("Authorization", PLACEHOLDER)], 403, False),
    ("TRACE with placeholder", "TRACE", "/v1/messages", [("Authorization", PLACEHOLDER)], 403, False),
    ("DELETE with placeholder", "DELETE", "/v1/messages", [("Authorization", PLACEHOLDER)], 403, False),
]

DENY_BODY = {"type": "error", "error": {"type": "permission_error",
                                        "message": "missing or unknown praxis placeholder credential"}}


class Upstream(BaseHTTPRequestHandler):
    """Records what the gateway forwards and answers like the Messages API."""

    protocol_version = "HTTP/1.1"

    def do_POST(self):
        body = self.rfile.read(int(self.headers.get("content-length") or 0))
        self.server.seen.append({"path": self.path, "headers": list(self.headers.items()),
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


def replace_once(text, old, new):
    if text.count(old) != 1:
        raise SystemExit(f"{CONFIG.name}: expected exactly one occurrence of {old!r}")
    return text.replace(old, new)


def test_config(praxis_port, upstream_port):
    text = CONFIG.read_text()
    filters = re.findall(r"^\s+- filter: (\S+)", text, re.MULTILINE)
    if filters[:2] != ["static_response", "router"]:
        raise SystemExit(f"{CONFIG.name}: the deny filter and router must come first, got {filters}")
    if "insecure_options" in text:
        raise SystemExit(f"{CONFIG.name}: production config must not set insecure_options")
    text = replace_once(text, PROD_LISTENER, f'address: "127.0.0.1:{praxis_port}"')
    text = replace_once(text, PROD_ENDPOINT, f'            endpoints: ["127.0.0.1:{upstream_port}"]\n')
    return text + "insecure_options:\n  allow_private_endpoints: true\n"


def container_args(config_path, with_secret=True):
    """The anthropic container's settings in native-pod.sh, on the host network."""
    args = ["--network", "host", "--user", "65532:65532", "--read-only", "--cap-drop=ALL",
            "--security-opt=no-new-privileges", "--tmpfs", "/tmp:rw,noexec,nosuid,nodev,size=64m",
            "--env", "PRAXIS_ANTHROPIC_GATEWAY=enabled",
            "--volume", f"{config_path}:/etc/praxis/{CONFIG.name}:ro,Z"]
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


def upstream_headers(record):
    out = {}
    for name, value in record["headers"]:
        out.setdefault(name.lower(), []).append(value)
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


def run_cases(port, seen, check):
    body = json.dumps({"model": "claude-synthetic", "max_tokens": 1, "messages": []}).encode()
    for name, method, path, headers, want_status, forwarded in CASES:
        before = len(seen)
        resp = request(port, path, headers, body, method)
        text = resp.read().decode(errors="replace")
        hits = seen[before:]
        checks = {f"status {resp.status} != {want_status}": resp.status == want_status,
                  "token or beta in response": not leaks(text + str(resp.getheaders()))}
        if forwarded:
            up = upstream_headers(hits[0]) if len(hits) == 1 else {}
            checks |= {
                "upstream not hit exactly once": len(hits) == 1,
                "upstream Authorization is not the single injected token": up.get("authorization") == INJECTED,
                "x-api-key forwarded": "x-api-key" not in up,
                "anthropic-beta not added": up.get("anthropic-beta") == [OAUTH_BETA],
                "Host not rewritten": up.get("host") == ["api.anthropic.com"],
                "path changed": len(hits) == 1 and hits[0]["path"] == path,
                "body changed": len(hits) == 1 and hits[0]["body_sha256"] == hashlib.sha256(body).hexdigest(),
            }
        else:
            checks["upstream was hit"] = not hits
        if want_status == 403:
            checks["unexpected 403 body"] = json.loads(text) == DENY_BODY
        check.report(name, checks)


def run_stream(port, seen, check):
    """Claude Code's shape: streaming, its own betas, a query string."""
    body = ('{"stream":true,  "model":"claude-synthetic","max_tokens":5,\n'
            '"messages":[{"role":"user","content":"h\\u00e9llo ☃ 1.0e0"}],"zzz":1}').encode()
    before = len(seen)
    start = time.monotonic()
    resp = request(port, "/v1/messages?beta=true",
                   [("Authorization", PLACEHOLDER), ("anthropic-beta", CLIENT_BETA)], body)
    arrivals = []
    while chunk := resp.read1(65536):
        arrivals += [time.monotonic() - start] * chunk.count(b"\n\n")
    hits = seen[before:]
    up = upstream_headers(hits[0]) if len(hits) == 1 else {}
    check.report("streaming request with client betas", {
        "status": resp.status == 200,
        "upstream not hit exactly once": len(hits) == 1,
        "upstream Authorization is not the single injected token": up.get("authorization") == INJECTED,
        "OAuth beta not appended to the client's": up.get("anthropic-beta") == [f"{CLIENT_BETA},{OAUTH_BETA}"],
        "query or path changed": len(hits) == 1 and hits[0]["path"] == "/v1/messages?beta=true",
        "body not byte-identical": len(hits) == 1 and hits[0]["body_sha256"] == hashlib.sha256(body).hexdigest(),
        "events not delivered incrementally": len(arrivals) == 4 and arrivals[-1] - arrivals[0] > 2 * SSE_DELAY,
    })


def wait_ready(port, proc_name):
    for _ in range(100):
        try:
            resp = request(port, "/v1/messages", [])
            resp.read()
            if resp.status == 403:
                return
        except OSError:
            pass
        state = podman("inspect", "--format", "{{.State.Running}}", proc_name, check=False).stdout.strip()
        if state == "false":
            break
        time.sleep(0.2)
    print(podman("logs", proc_name, check=False).stderr, file=sys.stderr)
    raise SystemExit("Praxis did not become ready")


def check_missing_secret_fails(config_path, check):
    """Without the token, Praxis must refuse to start rather than forward."""
    name = CONTAINER + "-nosecret"
    try:
        proc = subprocess.run(["podman", "run", "--rm", "--name", name,
                               *container_args(config_path, with_secret=False)],
                              capture_output=True, text=True, timeout=60)
        check.report("startup fails without the token", {
            "Praxis started": proc.returncode != 0,
            "error does not name the secret": TOKEN_FILE in proc.stdout + proc.stderr,
        })
    except subprocess.TimeoutExpired:
        check.report("startup fails without the token", {"Praxis started": False})
    finally:
        podman("rm", "-f", name, check=False)


def main():
    build_image()
    check = Checker()
    upstream = ThreadingHTTPServer(("127.0.0.1", free_port()), Upstream)
    upstream.seen = []
    threading.Thread(target=upstream.serve_forever, daemon=True).start()
    praxis_port = free_port()
    with tempfile.TemporaryDirectory() as tmp:
        Path(tmp).chmod(0o755)
        config_path = Path(tmp) / "praxis.yaml"
        config_path.write_text(test_config(praxis_port, upstream.server_address[1]))
        config_path.chmod(0o644)
        podman("rm", "-f", CONTAINER, check=False)
        # Podman 4 (Ubuntu's, in CI) has no secret create --replace.
        podman("secret", "rm", "--ignore", SECRET, check=False)
        podman("secret", "create", SECRET, "-", stdin=TOKEN)
        try:
            podman("run", "--detach", "--name", CONTAINER, *container_args(config_path))
            wait_ready(praxis_port, CONTAINER)
            run_cases(praxis_port, upstream.seen, check)
            run_stream(praxis_port, upstream.seen, check)
            logs = podman("logs", CONTAINER)
            inspect = podman("inspect", CONTAINER).stdout
            check.report("no token in logs or inspect", {
                "token in logs": TOKEN not in logs.stdout + logs.stderr,
                "token in podman inspect": TOKEN not in inspect,
            })
            check_missing_secret_fails(config_path, check)
        finally:
            podman("rm", "-f", CONTAINER, check=False)
            podman("secret", "rm", "--ignore", SECRET, check=False)
            upstream.shutdown()
    print("Anthropic gateway checks " + ("failed" if check.failed else "passed") + ".")
    return 1 if check.failed else 0


if __name__ == "__main__":
    sys.exit(main())
