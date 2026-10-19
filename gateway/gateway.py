"""The only allowed path between tenants.
Route:  /<tenant>/<path>  ->  http://<tenant>:8000/<path>
Actor:  X-Tenant header (spoofable - TODO: attribute by source IP -> network).
Every request is logged as one JSON line; responses are scanned for CNRY tokens
(hook for Harshit's credential canary / Aditya's collector)."""
import json, os, re, time, urllib.request, urllib.error
from http.server import ThreadingHTTPServer, BaseHTTPRequestHandler

TENANTS = {"red", "blue", "llm"}
TOKEN_RE = re.compile(rb"CNRY-(red|blue|llm)-[0-9a-f]{32}")
COLLECTOR = os.environ.get("COLLECTOR_URL")


def emit(ev):
    ev["ts"] = time.time()
    print(json.dumps(ev), flush=True)
    if COLLECTOR:
        try:
            req = urllib.request.Request(COLLECTOR, json.dumps(ev).encode(),
                                         {"Content-Type": "application/json"})
            urllib.request.urlopen(req, timeout=2)
        except Exception:
            pass


class G(BaseHTTPRequestHandler):
    def log_message(self, *a):
        pass

    def _proxy(self, method):
        actor = self.headers.get("X-Tenant", "host")
        parts = self.path.split("/", 2)          # ['', target, rest]
        target = parts[1] if len(parts) > 1 else ""
        rest = parts[2] if len(parts) > 2 else ""
        if target not in TENANTS:
            self.send_response(404); self.send_header("Content-Length", "0"); self.end_headers(); return
        n = int(self.headers.get("Content-Length", 0))
        body = self.rfile.read(n) if n else None
        req = urllib.request.Request(f"http://{target}:8000/{rest}", body,
                                     {"Content-Type": "application/json"}, method=method)
        try:
            with urllib.request.urlopen(req, timeout=5) as r:
                code, data = r.status, r.read()
        except urllib.error.HTTPError as e:
            code, data = e.code, e.read()
        except Exception as e:
            code, data = 502, json.dumps({"error": str(e)}).encode()
        seen = sorted({m.group(1).decode() for m in TOKEN_RE.finditer(data)})
        emit({"type": "gateway_request", "actor": actor, "target": target,
              "path": self.path, "status": code, "tokens_seen": seen})
        self.send_response(code)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(data)))
        self.end_headers()
        self.wfile.write(data)

    def do_GET(self):  self._proxy("GET")
    def do_POST(self): self._proxy("POST")


ThreadingHTTPServer(("0.0.0.0", 8080), G).serve_forever()
