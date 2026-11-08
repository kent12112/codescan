"""HTTP wrapper around the CONTAINED agentic analyst.

POST /analyze {"code":..., "requirements":..., "injection_warning":...}
     -> {"findings":[...], "raw":..., "note":...}   (code reasoning + CVE lookup)
POST /audit   {"requirements":...}  -> dependency-only audit (back-compat)
GET  /healthz -> {"ok": true}
"""
import json
import os
import re
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

from codescan.cve_agent import analyze, analyze_dependencies


def _extract_array(text):
    if not isinstance(text, str):
        return None
    fenced = re.search(r"```(?:json)?\s*(.*?)```", text, re.DOTALL)
    candidate = fenced.group(1) if fenced else text
    m = re.search(r"\[.*\]", candidate, re.DOTALL)
    for chunk in (candidate, m.group(0) if m else None):
        if not chunk:
            continue
        try:
            parsed = json.loads(chunk)
            if isinstance(parsed, list):
                return parsed
        except (json.JSONDecodeError, TypeError):
            continue
    return None


def _parse(result):
    arr = _extract_array(result)
    return (arr, None) if arr is not None else ([], "could not extract a JSON array from the agent output")


class Handler(BaseHTTPRequestHandler):
    def _send(self, code, payload):
        body = json.dumps(payload).encode()
        try:
            self.send_response(code)
            self.send_header("Content-Type", "application/json")
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)
        except (BrokenPipeError, ConnectionResetError):
            pass

    def do_GET(self):
        self._send(200, {"ok": True}) if self.path == "/healthz" else self._send(404, {"error": "not found"})

    def _read_json(self):
        length = int(self.headers.get("Content-Length", 0))
        return json.loads(self.rfile.read(length) if length else b"{}")

    def do_POST(self):
        try:
            data = self._read_json()
        except (json.JSONDecodeError, TypeError):
            self._send(400, {"error": "invalid JSON body"})
            return
        try:
            if self.path == "/analyze":
                result = analyze(data.get("code", ""),
                                 data.get("requirements", ""),
                                 data.get("injection_warning", ""))
            elif self.path == "/audit":
                result = analyze_dependencies(data.get("requirements", ""))
            else:
                self._send(404, {"error": "not found"})
                return
        except Exception as exc:
            self._send(500, {"error": f"agent raised: {exc!r}"})
            return
        findings, note = _parse(result)
        self._send(200, {"findings": findings, "raw": result, "note": note})

    def log_message(self, *args):
        pass


if __name__ == "__main__":
    port = int(os.environ.get("PORT", "9000"))
    print(f"cve-agent server listening on :{port}", flush=True)
    ThreadingHTTPServer(("0.0.0.0", port), Handler).serve_forever()
