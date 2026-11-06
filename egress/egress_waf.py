"""mitmproxy egress WAF: destination allowlist + decrypted request-body inspection.

This TERMINATES TLS for intercepted hosts, so it can read the request body and
block secrets being smuggled out — even to an allowlisted destination. The LLM
host (api.anthropic.com) is raw-tunneled via --ignore-hosts (not intercepted).
'A WAF turned to face outbound, filtering to the request body.'
"""
import re
from mitmproxy import http

ALLOWLIST = {"api.osv.dev"}
SECRET_PATTERNS = [
    re.compile(rb"internal-api-key", re.I),
    re.compile(rb"sk-[A-Za-z0-9]{16,}"),
    re.compile(rb"-----BEGIN [A-Z ]*PRIVATE KEY-----"),
    re.compile(rb"[A-Za-z0-9+/]{120,}={0,2}"),
]


def request(flow: http.HTTPFlow):
    host = flow.request.pretty_host

    if host not in ALLOWLIST:
        flow.response = http.Response.make(403, b"blocked: host not allowlisted")
        print(f"[WAF] BLOCKED host: {host}")
        return

    body = flow.request.raw_content or b""     # decrypted plaintext body
    for pat in SECRET_PATTERNS:
        if pat.search(body):
            flow.response = http.Response.make(403, b"blocked: sensitive data in request body")
            print(f"[WAF] BLOCKED exfil to {host}: body matches /{pat.pattern.decode()}/")
            return

    print(f"[WAF] ALLOWED {flow.request.method} {host}{flow.request.path} ({len(body)}B body)")
