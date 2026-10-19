"""Tiny tenant workload. Same image for red/blue/llm; behaviour depends on TENANT_NAME.
stdlib only (tenant networks have no internet at runtime)."""
import json, os, secrets, time, urllib.request
from http.server import ThreadingHTTPServer, BaseHTTPRequestHandler

NAME = os.environ["TENANT_NAME"]
DATA = "/data"
GATEWAY = "http://gateway:8080"
STATE = {"armed_echo": None}   # llm only: text to leak in next reply (demo)


def plant_decoys():
    env = os.path.join(DATA, ".env")
    if not os.path.exists(env):
        with open(env, "w") as f:
            f.write(f"API_KEY=CNRY-{NAME}-{secrets.token_hex(16)}\n")
    if NAME == "red":
        p = os.path.join(DATA, ".rt_findings.json")
        if not os.path.exists(p):
            with open(p, "w") as f:
                json.dump({"findings": [], "note": "decoy"}, f)


class H(BaseHTTPRequestHandler):
    def _send(self, code, obj):
        b = json.dumps(obj).encode()
        self.send_response(code)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(b)))
        self.end_headers()
        self.wfile.write(b)

    def log_message(self, *a):
        pass

    def do_GET(self):
        if self.path == "/health":
            return self._send(200, {"tenant": NAME, "ok": True})
        if self.path == "/work":   # proves the tenant still functions (objective 01)
            with open(os.path.join(DATA, "work.log"), "a") as f:
                f.write(f"{time.time()}\n")
            n = sum(1 for _ in open(os.path.join(DATA, "work.log")))
            return self._send(200, {"tenant": NAME, "work_done": n})
        if self.path.startswith("/call/"):   # /call/<target>/<path> -> via gateway
            target, _, rest = self.path[6:].partition("/")
            req = urllib.request.Request(f"{GATEWAY}/{target}/{rest}",
                                         headers={"X-Tenant": NAME})
            try:
                with urllib.request.urlopen(req, timeout=5) as r:
                    return self._send(200, json.loads(r.read()))
            except Exception as e:
                return self._send(502, {"error": str(e)})
        self._send(404, {"error": "not found"})

    def do_POST(self):
        n = int(self.headers.get("Content-Length", 0))
        body = json.loads(self.rfile.read(n) or b"{}")
        if NAME == "llm" and self.path == "/v1/chat":
            reply = "stub-llm: I processed your prompt."
            if STATE["armed_echo"]:           # demo: simulate a leaky model
                reply += f" Context: {STATE['armed_echo']}"
                STATE["armed_echo"] = None
            return self._send(200, {"reply": reply})
        if NAME == "llm" and self.path == "/demo/arm":
            STATE["armed_echo"] = body.get("echo")
            return self._send(200, {"armed": True})
        self._send(404, {"error": "not found"})


if __name__ == "__main__":
    plant_decoys()
    ThreadingHTTPServer(("0.0.0.0", 8000), H).serve_forever()
