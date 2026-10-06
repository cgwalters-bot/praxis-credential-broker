from http.server import BaseHTTPRequestHandler, HTTPServer
import json

# Usage the gateway meters: 100 tokens per response.
USAGE = b'"usage":{"input_tokens":70,"input_tokens_details":{"cached_tokens":30},"output_tokens":30,"total_tokens":100}'
COMPLETED = b'event: response.completed\ndata: {"type":"response.completed","response":{"model":"synthetic",' + USAGE + b'}}\n\n'

class Handler(BaseHTTPRequestHandler):
    def do_POST(self):
        length = int(self.headers.get('content-length', '0'))
        self.rfile.read(length)
        self.server.calls += 1
        if self.server.calls % 2 == 1:
            self.send_response(401)
            self.end_headers()
            return
        # Record only whether the broker replaced caller values with the
        # synthetic credentials; never record credential strings themselves.
        present = [self.headers.get('authorization') == 'Bearer synthetic-agent-token',
                   self.headers.get('chatgpt-account-id') == 'synthetic-account']
        self.server.observed.append(present)
        self.send_response(200)
        streaming = self.headers.get('accept') == 'text/event-stream'
        # Like the Codex backend, the stream does not say what it is.
        if not streaming:
            self.send_header('content-type', 'application/json')
        self.end_headers()
        self.wfile.write((b'event: response.output_text.delta\ndata: {"delta":"synthetic"}\n\nevent: response.function_call_arguments.delta\ndata: {"item_id":"call_synthetic","delta":"{}"}\n\n' + COMPLETED if streaming else b'{"id":"synthetic",' + USAGE + b'}'))
    def do_GET(self):
        if self.path == '/reset':
            self.server.calls = 0
            self.server.observed.clear()
            self.send_response(204)
            self.end_headers()
            return
        if self.path == '/counters':
            body = json.dumps({'calls': self.server.calls, 'observed': self.server.observed}).encode()
            self.send_response(200)
            self.send_header('content-type', 'application/json')
            self.send_header('content-length', str(len(body)))
            self.end_headers()
            self.wfile.write(body)
            return
        if self.path == '/jwks':
            # The test-only OIDC key set the run-token test pod trusts.
            with open('/jwks.json', 'rb') as f:
                body = f.read()
            self.send_response(200)
            self.send_header('content-type', 'application/json')
            self.send_header('content-length', str(len(body)))
            self.end_headers()
            self.wfile.write(body)
            return
        if self.path != '/seen': self.send_error(404); return
        self.send_response(200); self.end_headers()
        self.wfile.write(json.dumps(self.server.observed).encode())
    def log_message(self, *_): pass

server = HTTPServer(('0.0.0.0', 18081), Handler)
server.observed = []
server.calls = 0
server.serve_forever()
