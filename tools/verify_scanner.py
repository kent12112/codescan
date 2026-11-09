"""Check real scanner isolation in a short-lived Job with no API key."""
import json
import time
import uuid
from scan_job import ROOT, kubectl, make_job


def main():
    name = 'scanner-probe-' + uuid.uuid4().hex[:8]
    job = make_job(name, '', {})
    job['spec']['activeDeadlineSeconds'] = 120
    container = job['spec']['template']['spec']['containers'][0]
    container['env'] = [e for e in container['env'] if e['name'] != 'ANTHROPIC_API_KEY']
    container['command'] = ['python', '-u', '-c']
    container['args'] = [(ROOT / 'tests/isolation_probe.py').read_text()]
    kubectl('apply', '-f', str(ROOT / 'k8s/scanner-netpol.yaml'))
    kubectl('apply', '-f', str(ROOT / 'k8s/scanner-proxy.yaml'))
    kubectl('rollout', 'status', 'deployment/scanner-proxy', '-n', 'scanner', '--timeout=120s')
    kubectl('create', '-f', '-', input=json.dumps(job), text=True)
    try:
        deadline = time.monotonic() + 120
        while time.monotonic() < deadline:
            output = kubectl('get', 'job', name, '-n', 'scanner', '-o', 'json',
                             capture_output=True, text=True)
            status = json.loads(output.stdout).get('status', {})
            if status.get('succeeded') or status.get('failed'):
                kubectl('logs', 'job/' + name, '-n', 'scanner')
                if not status.get('succeeded'):
                    raise RuntimeError('isolation probe failed')
                return
            time.sleep(2)
        raise TimeoutError('isolation probe timed out')
    finally:
        kubectl('delete', 'job', name, '-n', 'scanner', '--wait=false')


if __name__ == '__main__':
    main()
