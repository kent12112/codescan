"""Provision the analyst proxy's CA once. Existing CAs are never silently rotated."""
import json
import os
from pathlib import Path
import subprocess
import tempfile

IMAGE = 'codescan-proxy:osv-waf-v2'


def run(*command, **kwargs):
    return subprocess.run(command, check=True, **kwargs)


def exists(kind, name):
    result = run('kubectl', 'get', kind, name, '-n', 'scanner', '--ignore-not-found',
                 '-o', 'name', capture_output=True, text=True)
    return bool(result.stdout.strip())


def main():
    secret = exists('secret', 'egress-waf-ca')
    public = exists('configmap', 'egress-waf-trust')
    if secret and public:
        print('Existing inspection CA retained.')
        return
    if secret or public:
        raise RuntimeError('Incomplete CA setup; restore the matching Secret/ConfigMap before continuing')
    created = []
    with tempfile.TemporaryDirectory(prefix='codescan-ca-') as directory:
        run('docker', 'run', '--rm', '--pull=never', '--network', 'none', '--read-only',
            '--cap-drop', 'ALL', '--security-opt', 'no-new-privileges',
            '--user', f'{os.getuid()}:{os.getgid()}', '--tmpfs', '/tmp',
            '-v', directory + ':/output', '--entrypoint', 'python', IMAGE,
            '/provision_ca.py', '/output', capture_output=True)
        try:
            for kind, name, key, filename in [
                ('secret', 'egress-waf-ca', 'mitmproxy-ca.pem', 'mitmproxy-ca.pem'),
                ('configmap', 'egress-waf-trust', 'ca-bundle.pem', 'ca-bundle.pem')]:
                command = ['kubectl', 'create', kind]
                if kind == 'secret':
                    command.append('generic')
                result = run(*command, name, '-n', 'scanner',
                             '--from-file=' + key + '=' + str(Path(directory, filename)),
                             '--dry-run=client', '-o', 'json', capture_output=True, text=True)
                manifest = json.loads(result.stdout)
                manifest['immutable'] = True
                run('kubectl', 'create', '-f', '-', input=json.dumps(manifest),
                    capture_output=True, text=True)
                created.append((kind, name))
        except BaseException:
            for kind, name in reversed(created):
                run('kubectl', 'delete', kind, name, '-n', 'scanner',
                    '--ignore-not-found', capture_output=True)
            raise
    print('Created inspection CA Secret and public client trust bundle.')


if __name__ == '__main__':
    main()
