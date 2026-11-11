"""Host-side Kubernetes orchestration. Never import the scanning pipeline here."""
import argparse
import base64
import io
import json
import os
from pathlib import Path
import stat
import signal
import subprocess
import sys
import tarfile
import time
import uuid
from urllib.parse import urlsplit

try:
    from tools.reports import extract_report, save_and_render, save_failure
except ModuleNotFoundError:
    from reports import extract_report, save_and_render, save_failure

ROOT = Path(__file__).resolve().parents[1]
SKIP = {'.git', '.venv', 'venv', '__pycache__', 'node_modules', 'dist', 'build',
        '.next', 'vendor', '.ssh', '.aws', '.kube'}
MAX_PAYLOAD = 700 * 1024  # Keep base64 + object metadata below ConfigMap's 1 MiB limit.


def kubectl(*args, **kwargs):
    return subprocess.run(['kubectl', *args], check=True, **kwargs)


def bundle_source(source):
    """Copy only ordinary files; exclude credentials, links and generated trees."""
    buffer = io.BytesIO()
    total = count = 0
    with tarfile.open(fileobj=buffer, mode='w:gz') as archive:
        for directory, dirs, files in os.walk(source, followlinks=False):
            dirs[:] = sorted(d for d in dirs if d not in SKIP
                             and not Path(directory, d).is_symlink())
            for name in sorted(files):
                if name == '.env' or name.startswith('.env.') or name in {
                    'agent_audit.jsonl', 'revoked_tokens.txt'}:
                    continue
                path = Path(directory, name)
                if not stat.S_ISREG(path.lstat().st_mode):
                    continue
                descriptor = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
                with os.fdopen(descriptor, 'rb') as stream:
                    info = os.fstat(stream.fileno())
                    if not stat.S_ISREG(info.st_mode):
                        raise ValueError('source changed while packaging')
                    total += info.st_size
                    count += 1
                    if total > 128 * 1024 * 1024 or count > 10000:
                        raise ValueError('local input exceeds 128 MiB or 10000 files')
                    member = tarfile.TarInfo(path.relative_to(source).as_posix())
                    member.size, member.mode = info.st_size, 0o644
                    archive.addfile(member, stream)
                if buffer.tell() > MAX_PAYLOAD:
                    raise ValueError('local bundle too large; use an HTTPS repository URL')
    data = buffer.getvalue()
    if len(data) > MAX_PAYLOAD:
        raise ValueError('local bundle too large; use an HTTPS repository URL')
    return data


def make_job(name, source, payload):
    job = json.loads((ROOT / 'k8s/scanner-job.yaml').read_text())
    job['metadata']['name'] = name
    spec = job['spec']['template']['spec']
    container = spec['containers'][0]
    container['args'] = [source]
    if payload:
        spec['volumes'].append({'name': 'input', 'configMap': {'name': name}})
        container['volumeMounts'].append({'name': 'input', 'mountPath': '/input', 'readOnly': True})
    for key, env in [('repo.tar.gz', 'SCAN_BUNDLE'), ('dast-report.txt', 'DAST_REPORT')]:
        if key in payload:
            container['env'].append({'name': env, 'value': '/input/' + key})
    return job


def main():
    signal.signal(signal.SIGTERM, lambda *_: sys.exit(143))
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('source', help='local directory or HTTPS GitHub repository URL')
    parser.add_argument('--dast-report', type=Path)
    parser.add_argument('--report-dir', type=Path, default=ROOT / 'reports')
    args = parser.parse_args()
    payload = {}
    path = Path(args.source)
    if path.is_dir():
        payload['repo.tar.gz'] = bundle_source(path.resolve())
        source = '/input/source'
    else:
        url = urlsplit(args.source)
        if (url.scheme != 'https' or url.hostname != 'github.com'
                or url.username or url.password or url.port not in (None, 443)):
            parser.error('use a local directory or an HTTPS github.com repository URL')
        source = args.source
    if args.dast_report:
        with args.dast_report.open('rb') as report:
            payload['dast-report.txt'] = report.read(MAX_PAYLOAD + 1)
    if sum(map(len, payload.values())) > MAX_PAYLOAD:
        parser.error('combined input exceeds 700 KiB compressed')
    name = 'codescan-' + uuid.uuid4().hex[:12]
    job = make_job(name, source, payload)
    config_created = job_created = False
    try:
        # Install restrictions before any scanner Pod is created.
        kubectl('apply', '-f', str(ROOT / 'k8s/scanner-netpol.yaml'))
        kubectl('apply', '-f', str(ROOT / 'k8s/scanner-proxy.yaml'))
        kubectl('rollout', 'status', 'deployment/scanner-proxy', '-n', 'scanner', '--timeout=120s')
        if payload:
            config = {'apiVersion': 'v1', 'kind': 'ConfigMap',
                      'metadata': {'name': name, 'namespace': 'scanner'},
                      'immutable': True,
                      'binaryData': {k: base64.b64encode(v).decode() for k, v in payload.items()}}
            kubectl('create', '-f', '-', input=json.dumps(config), text=True, capture_output=True)
            config_created = True
        created = kubectl('create', '-f', '-', '-o', 'json', input=json.dumps(job),
                          text=True, capture_output=True)
        job_created = True
        if config_created:
            metadata = json.loads(created.stdout)['metadata']
            owner = {'apiVersion': 'batch/v1', 'kind': 'Job', 'name': name,
                     'uid': metadata['uid']}
            kubectl('patch', 'configmap', name, '-n', 'scanner', '--type=merge',
                    '-p', json.dumps({'metadata': {'ownerReferences': [owner]}}),
                    capture_output=True)
        print('Launched ' + name, flush=True)
        deadline = time.monotonic() + 900
        while time.monotonic() < deadline:
            result = kubectl('get', 'job', name, '-n', 'scanner', '-o', 'json', capture_output=True, text=True)
            status = json.loads(result.stdout).get('status', {})
            if status.get('succeeded') or status.get('failed'):
                logs = kubectl('logs', 'job/' + name, '-n', 'scanner', '--pod-running-timeout=10s', '--limit-bytes=2097152', capture_output=True, text=True)
                if not status.get('succeeded'):
                    # Exception traces can include untrusted text; do not print raw logs.
                    save_failure(logs.stdout, name, args.report_dir)
                    raise RuntimeError('scanner Job failed: ' + name)
                save_and_render(extract_report(logs.stdout), name, args.report_dir)
                return
            time.sleep(2)
        logs = kubectl('logs', 'job/' + name, '-n', 'scanner',
                       '--pod-running-timeout=10s', '--limit-bytes=2097152',
                       capture_output=True, text=True)
        save_failure(logs.stdout, name, args.report_dir)
        raise TimeoutError('scanner Job timed out')
    finally:
        # Tear down the Pod (and its secret environment) before removing its input.
        if job_created:
            kubectl('delete', 'job', name, '-n', 'scanner', '--ignore-not-found', '--wait=false')
        if config_created:
            kubectl('delete', 'configmap', name, '-n', 'scanner', '--ignore-not-found')


if __name__ == '__main__':
    main()
