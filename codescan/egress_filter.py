"""Egress content inspection: scan outbound tool-request bodies for data exfiltration.

Destination allowlisting stops calls to the WRONG host; this stops the RIGHT host
being used to smuggle data out. It inspects the request body (before encryption)
for secrets and encoded blobs. This is 'filter on the body, not just the
destination', placed at the tool's egress boundary.
"""
import re

SECRET_PATTERNS = [
    re.compile(r"internal-api-key", re.I),            # our known secret marker
    re.compile(r"sk-[A-Za-z0-9]{16,}"),               # API-key-shaped tokens
    re.compile(r"-----BEGIN [A-Z ]*PRIVATE KEY-----"),
    re.compile(r"[A-Za-z0-9+/]{120,}={0,2}"),         # long base64 blob (encoded exfil)
]


def egress_check(body: str):
    """Return (allowed, reason). Blocks if the outbound body looks like it carries secrets."""
    for pat in SECRET_PATTERNS:
        if pat.search(body):
            return False, f"outbound body matches sensitive pattern /{pat.pattern}/"
    return True, "ok"
