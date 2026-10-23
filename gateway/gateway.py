"""The only allowed path between tenants.
Route:  /<tenant>/<path>  ->  http://<tenant>:8000/<path>
Actor:  derived from the connection SOURCE IP (cannot be forged by a tenant).
        The X-Tenant header is only logged as "claimed" to expose spoofing attempts.
Every request is logged as one JSON line; responses are scanned for CNRY tokens
(reported to the security layer through COLLECTOR_URL, see collector_events)."""
import json, os, re, socket, time, urllib.request, urllib.error
from http.server import ThreadingHTTPServer, BaseHTTPRequestHandler

TENANTS = {"red", "blue", "llm"}
TOKEN_RE = re.compile(rb"CNRY-(red|blue|llm)-[0-9a-f]{32}")
COLLECTOR = os.environ.get("COLLECTOR_URL")


def actor_from_ip(ip):
    """Docker DNS answers 'red' with the IPs red has on networks shared with the
    gateway. If a tenant is moved onto another network (break-it demo), it still
    resolves to all its IPs, so attribution stays correct."""
    for t in TENANTS:
        try:
            if ip in socket.gethostbyname_ex(t)[2]:
                return t
        except OSError:
            pass
    return "host"          # not a tenant IP -> request came from the host via mgmt


CONTRACT_NAMES = {"red": "red-team", "blue": "blue-team", "llm": "client-llm"}


def collector_events(ev):
    """Security-layer events for one gateway log line (pure, unit-tested).

    Only tenant-to-tenant traffic is reported here: when a response delivered to a
    tenant carries another tenant's canary token. Requests from the host / core API
    are covered by the core path calling app.security.scan_text(), so reporting them
    here too would duplicate the alert.
    """
    actor = ev.get("actor")
    if actor not in CONTRACT_NAMES:
        return []
    return [
        {
            "tenant": CONTRACT_NAMES[owner],
            "event_type": "credential_canary_trip",
            "canary_type": "credential",
            "details": {
                "actor": CONTRACT_NAMES[actor],
                "evidence": f"token of {CONTRACT_NAMES[owner]} seen in gateway response to {CONTRACT_NAMES[actor]}",
                "source": "gateway",
                "path": ev.get("path"),
            },
        }
        for owner in ev.get("tokens_seen", [])
        if owner != actor
    ]


def emit(ev):
    ev["ts"] = time.time()
    print(json.dumps(ev), flush=True)
    token = os.environ.get("INTERNAL_EVENT_TOKEN", "")
    if not (COLLECTOR and token):
        return
    for event in collector_events(ev):
        try:
            req = urllib.request.Request(COLLECTOR, json.dumps(event).encode(),
                                         {"Content-Type": "application/json", "X-Internal-Token": token})
            urllib.request.urlopen(req, timeout=2)
        except Exception as exc:
            print(json.dumps({"type": "collector_error", "error": str(exc)}), flush=True)


class G(BaseHTTPRequestHandler):
    def log_message(self, *a):
        pass

    def _proxy(self, method):
        actor = actor_from_ip(self.client_address[0])
        claimed = self.headers.get("X-Tenant")
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
        ev = {"type": "gateway_request", "actor": actor, "target": target,
              "path": self.path, "status": code, "tokens_seen": seen}
        if claimed and claimed != actor:
            ev["spoof_claimed"] = claimed      # header lied about identity
        emit(ev)
        self.send_response(code)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(data)))
        self.end_headers()
        self.wfile.write(data)

    def do_GET(self):  self._proxy("GET")
    def do_POST(self): self._proxy("POST")


if __name__ == "__main__":
    ThreadingHTTPServer(("0.0.0.0", 8080), G).serve_forever()
