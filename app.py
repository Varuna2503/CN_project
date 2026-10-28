#!/usr/bin/env python3
"""Local web UI for NetCfg-AI. Run:  python app.py [port]   then open http://localhost:8000
No third-party packages needed (standard library only).

Endpoints:
  GET  /             the single-page UI (index.html)
  GET  /api/health   backend status (LLM endpoint configured or offline rule parser)
  POST /api/generate {"request": str, "inject_fault": bool, "options": {device, hostname, base, dns}}
  POST /api/audit    {"config": str, "repair": bool}
"""
import json, os, sys
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from netcfg_ai import run_audit, run_pipeline

HERE = os.path.dirname(os.path.abspath(__file__))
MAX_BODY = 512 * 1024


class H(BaseHTTPRequestHandler):
    def _send(self, code, body, ctype):
        self.send_response(code)
        self.send_header("Content-Type", ctype)
        self.send_header("Content-Length", str(len(body)))
        self.send_header("Cache-Control", "no-store")
        self.end_headers()
        self.wfile.write(body)

    def _json(self, code, obj):
        self._send(code, json.dumps(obj).encode(), "application/json")

    def do_GET(self):
        if self.path in ("/", "/index.html"):
            self._send(200, open(os.path.join(HERE, "index.html"), "rb").read(), "text/html; charset=utf-8")
        elif self.path == "/api/health":
            self._json(200, {"ok": True, "llm": bool(os.environ.get("LLM_BASE_URL")),
                             "model": os.environ.get("LLM_MODEL", "llama3") if os.environ.get("LLM_BASE_URL") else None})
        else:
            self._send(404, b"not found", "text/plain")

    def do_POST(self):
        if self.path not in ("/api/generate", "/api/audit"):
            return self._send(404, b"not found", "text/plain")
        try:
            n = int(self.headers.get("Content-Length", 0))
            if n > MAX_BODY:
                raise ValueError("Request too large.")
            data = json.loads(self.rfile.read(n) or b"{}")
            if self.path == "/api/audit":
                out = run_audit(str(data.get("config") or ""), bool(data.get("repair", True)))
            else:
                req = (data.get("request") or "").strip()
                if not req:
                    raise ValueError("Please describe the network you need.")
                opts = {k: str(v).strip() for k, v in (data.get("options") or {}).items() if v}
                out = run_pipeline(req[:1000], bool(data.get("inject_fault")), opts)
        except ValueError as ex:
            return self._json(400, {"error": str(ex)})
        except Exception as ex:  # surface unexpected failures to the UI instead of dropping the connection
            return self._json(500, {"error": f"Internal error: {ex}"})
        self._json(200, out)

    def log_message(self, *a):
        pass


if __name__ == "__main__":
    port = int(sys.argv[1]) if len(sys.argv) > 1 else int(os.environ.get("PORT", 8000))
    print(f"NetCfg-AI running at http://localhost:{port}  (Ctrl+C to stop)")
    ThreadingHTTPServer(("127.0.0.1", port), H).serve_forever()
