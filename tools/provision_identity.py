"""Create/renew local workload certificates; root key is never mounted into workloads."""
from pathlib import Path
from datetime import datetime, timedelta, timezone
import ipaddress
import sys
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.x509.oid import NameOID, ExtendedKeyUsageOID

root = Path(sys.argv[1])
now = datetime.now(timezone.utc)


def save_key(key, path):
    path.write_bytes(key.private_bytes(serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8,
                                       serialization.NoEncryption()))
    path.chmod(0o600)


if (root / 'ca.key').exists():
    ca_key = serialization.load_pem_private_key((root / 'ca.key').read_bytes(), password=None)
    ca = x509.load_pem_x509_certificate((root / 'ca.crt').read_bytes())
    if ca.not_valid_after_utc < now + timedelta(days=100):
        raise RuntimeError('internal CA expires too soon; plan an explicit CA rotation')
else:
    ca_key = ec.generate_private_key(ec.SECP256R1())
    name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, 'CodeScan internal workload CA')])
    ca = (x509.CertificateBuilder().subject_name(name).issuer_name(name).public_key(ca_key.public_key())
        .serial_number(x509.random_serial_number()).not_valid_before(now - timedelta(minutes=5))
        .not_valid_after(now + timedelta(days=3650))
        .add_extension(x509.BasicConstraints(ca=True, path_length=0), critical=True)
        .add_extension(x509.SubjectKeyIdentifier.from_public_key(ca_key.public_key()), critical=False)
        .add_extension(x509.AuthorityKeyIdentifier.from_issuer_public_key(ca_key.public_key()), critical=False)
        .add_extension(x509.KeyUsage(False, False, False, False, False, True, True, False, False), critical=True)
        .sign(ca_key, hashes.SHA256()))
    save_key(ca_key, root / 'ca.key')
    (root / 'ca.crt').write_bytes(ca.public_bytes(serialization.Encoding.PEM))
for role, host in [('scanner', None), ('analyst', 'cve-agent'), ('gateway', 'llm-gateway'), ('osv-broker', 'egress-proxy')]:
    directory = root / role
    directory.mkdir(exist_ok=True)
    key = ec.generate_private_key(ec.SECP256R1())
    names = [x509.UniformResourceIdentifier('spiffe://codescan.local/' + role)]
    if host:
        names += [x509.DNSName(value) for value in [host, host + '.scanner.svc', host + '.scanner.svc.cluster.local', 'localhost']]
        names.append(x509.IPAddress(ipaddress.ip_address('127.0.0.1')))
    usages = [ExtendedKeyUsageOID.CLIENT_AUTH]
    if host:
        usages.append(ExtendedKeyUsageOID.SERVER_AUTH)
    certificate = (x509.CertificateBuilder()
        .subject_name(x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, role)]))
        .issuer_name(ca.subject).public_key(key.public_key()).serial_number(x509.random_serial_number())
        .not_valid_before(now - timedelta(minutes=5)).not_valid_after(now + timedelta(days=90))
        .add_extension(x509.BasicConstraints(ca=False, path_length=None), critical=True)
        .add_extension(x509.SubjectKeyIdentifier.from_public_key(key.public_key()), critical=False)
        .add_extension(x509.AuthorityKeyIdentifier.from_issuer_public_key(ca_key.public_key()), critical=False)
        .add_extension(x509.KeyUsage(True, False, False, False, False, False, False, False, False), critical=True)
        .add_extension(x509.ExtendedKeyUsage(usages), critical=True)
        .add_extension(x509.SubjectAlternativeName(names), critical=False)
        .sign(ca_key, hashes.SHA256()))
    save_key(key, directory / 'tls.key')
    (directory / 'tls.crt').write_bytes(certificate.public_bytes(serialization.Encoding.PEM))
    (directory / 'ca.crt').write_bytes(ca.public_bytes(serialization.Encoding.PEM))
