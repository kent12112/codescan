"""A deliberately vulnerable demo app — OUR OWN test target for DAST.
Do not deploy. The command-injection bug is intentional."""
import subprocess
from http.server import BaseHTTPRequestHandler, HTTPServer
from urllib.parse import urlparse, parse_qs


class Handler(BaseHTTPRequestHandler):
    def do_GET(self):
        params = parse_qs(urlparse(self.path).query)
        host = params.get("host", ["localhost"])[0]
        # VULN: user input flows into a shell command (the runtime form of B602)
        result = subprocess.run(
            f"ping -c1 {host}", shell=True,
            capture_output=True, text=True, timeout=5,
        )
        self.send_response(200)
        self.end_headers()
        self.wfile.write((result.stdout + result.stderr).encode())

    def log_message(self, *args):
        pass  # keep the output clean


if __name__ == "__main__":
    print("target listening on :8000")
    HTTPServer(("0.0.0.0", 8000), Handler).serve_forever()
