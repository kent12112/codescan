"""HTTP wrapper around the contained CVE agent.

POST /audit  {"requirements": "<pip freeze text>"}  -> {"findings": [...], "raw": "...", "note": null}
GET  /healthz -> {"ok": true}

analyze_dependencies() runs IN THIS POD, so all containment (NetworkPolicy,
egress proxy, seccomp, Tetragon) still applies to its work.
"""
import json
import os
import re
from http.server import BaseHTTPRequestHandler, HTTPServer

from codescan.cve_agent import analyze_dependencies


def _extract_array(text):
    """The model sometimes wraps its JSON array in prose or ```json fences.
    Pull the array out so a verbose answer still parses."""
    if not isinstance(text, str):
        return None
    fenced = re.search(r"```(?:json)?\s*(.*?)```", text, re.DOTALL)
    candidate = fenced.group(1) if fenced else text
    for chunk in (candidate, re.search(r"\[.*\]", candidate, re.DOTALL) and re.search(r"\[.*\]", candidate, re.DOTALL).group(0)):
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
    if arr is not None:
        return arr, None
    return [], "could not extract a JSON array from the agent output"


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
            pass  # client (often the readiness probe) hung up early

    def do_GET(self):
        self._send(200, {"ok": True}) if self.path == "/healthz" else self._send(404, {"error": "not found"})

    def do_POST(self):
        if self.path != "/audit":
            self._send(404, {"error": "not found"})
            return
        length = int(self.headers.get("Content-Length", 0))
        raw = self.rfile.read(length) if length else b""
        try:
            requirements = json.loads(raw)["requirements"]
        except (json.JSONDecodeError, KeyError, TypeError):
            self._send(400, {"error": "expected JSON body with a 'requirements' string"})
            return
        try:
            result = analyze_dependencies(requirements)
        except Exception as exc:  # never die on one bad request
            self._send(500, {"error": f"agent raised: {exc!r}"})
            return
        findings, note = _parse(result)
        self._send(200, {"findings": findings, "raw": result, "note": note})

    def log_message(self, *args):
        pass


if __name__ == "__main__":
    port = int(os.environ.get("PORT", "9000"))
    print(f"cve-agent server listening on :{port}", flush=True)
    HTTPServer(("0.0.0.0", port), Handler).serve_forever()
