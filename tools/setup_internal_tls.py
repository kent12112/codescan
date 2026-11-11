"""Issue workload identities. --rotate renews leaves using the existing root CA."""
import argparse
import base64
import json
import os
from pathlib import Path
import subprocess
import tempfile

NAMES = ['scanner-tls', 'analyst-tls', 'llm-gateway-tls', 'osv-broker-tls']


def run(*args, **kwargs):
    return subprocess.run(args, check=True, **kwargs)


def get(name):
    result = run('kubectl', 'get', 'secret', name, '-n', 'scanner', '--ignore-not-found',
                 '-o', 'json', capture_output=True, text=True)
    return json.loads(result.stdout) if result.stdout.strip() else None


def save(name, data, immutable=False, update=False):
    manifest = {'apiVersion': 'v1', 'kind': 'Secret', 'type': 'Opaque',
        'metadata': {'name': name, 'namespace': 'scanner'}, 'immutable': immutable,
        'data': {key: base64.b64encode(value).decode() for key, value in data.items()}}
    if update:
        manifest['metadata']['resourceVersion'] = update
    command = ['kubectl', 'replace' if update else 'create', '-f', '-']
    run(*command, input=json.dumps(manifest), text=True, capture_output=True)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--rotate', action='store_true')
    args = parser.parse_args()
    existing = get('codescan-internal-ca')
    leaves = [get(name) for name in NAMES]
    if existing and all(leaves) and not args.rotate:
        print('Existing internal workload identities retained.')
        return
    if not existing and any(leaves):
        raise RuntimeError('leaf identities exist without their CA; restore the original CA')
    with tempfile.TemporaryDirectory(prefix='codescan-identities-') as directory:
        root = Path(directory)
        if existing:
            for name in ['ca.key', 'ca.crt']:
                path = root / name
                path.write_bytes(base64.b64decode(existing['data'][name]))
                path.chmod(0o600)
        run('docker', 'run', '--rm', '--pull=never', '--network', 'none', '--read-only',
            '--cap-drop', 'ALL', '--security-opt', 'no-new-privileges',
            '--user', f'{os.getuid()}:{os.getgid()}', '--tmpfs', '/tmp',
            '-v', directory + ':/output', '--entrypoint', 'python',
            'codescan-identity:team-v1', '/provision_identity.py', '/output', capture_output=True)
        if not existing:
            save('codescan-internal-ca', {name: (root / name).read_bytes() for name in ['ca.crt', 'ca.key']}, immutable=True)
        for role, name, previous in zip(['scanner', 'analyst', 'gateway', 'osv-broker'], NAMES, leaves):
            save(name, {key: (root / role / key).read_bytes() for key in ['tls.crt', 'tls.key', 'ca.crt']}, update=previous['metadata']['resourceVersion'] if previous else None)
    print('Workload identities issued; provider credentials were not accessed.')


if __name__ == '__main__':
    main()
