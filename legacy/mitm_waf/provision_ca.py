"""Generate a dedicated inspection CA; output files must never enter an image/repo."""
from pathlib import Path
import sys
from mitmproxy.certs import CertStore
import certifi

output = Path(sys.argv[1])
CertStore.from_store(output, 'mitmproxy', 2048)
# Clients need only this public trust bundle, never the signing key.
public_ca = (output / 'mitmproxy-ca-cert.pem').read_bytes()
if b'PRIVATE KEY' in public_ca:
    raise RuntimeError('refusing to publish a signing key in the trust bundle')
(output / 'ca-bundle.pem').write_bytes(Path(certifi.where()).read_bytes() + b'\n' + public_ca)
