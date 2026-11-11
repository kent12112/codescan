"""Keep the allowlist frontend and local OSV inspector alive as one service."""
import os
from pathlib import Path
import shutil
import signal
import socket
import subprocess
import sys
import time


def main():
    root = Path(__file__).resolve().parent
    directory = Path(os.environ.get('WAF_CONF_DIR', '/tmp/mitmproxy'))
    port = int(os.environ.get('WAF_MITM_PORT', '8081'))
    directory.mkdir(mode=0o700, exist_ok=True)
    shutil.copyfile(os.environ.get('WAF_CA_FILE', '/etc/mitm-ca/mitmproxy-ca.pem'), directory / 'mitmproxy-ca.pem')
    (directory / 'mitmproxy-ca.pem').chmod(0o600)
    ready = directory / 'waf-ready'
    ready.unlink(missing_ok=True)
    processes = []
    def stop(*_):
        raise SystemExit(0)
    signal.signal(signal.SIGTERM, stop)
    signal.signal(signal.SIGINT, stop)
    try:
        inspector = subprocess.Popen([
            str(Path(sys.executable).with_name('mitmdump')), '--listen-host', '127.0.0.1', '--listen-port', str(port),
            '--set', 'confdir=' + str(directory), '--set', 'connection_strategy=lazy',
            '--set', 'upstream_cert=false', '--set', 'ssl_insecure=false',
            '--set', 'body_size_limit=2m', '--set', 'flow_detail=0',
            '--set', 'termlog_verbosity=warn', '-s', str(root / 'egress_waf.py')],
            env={**os.environ, 'WAF_READY_FILE': str(ready)})
        processes.append(inspector)
        deadline = time.monotonic() + 30
        while True:
            if inspector.poll() is not None or time.monotonic() > deadline:
                raise RuntimeError('OSV inspector failed to start')
            try:
                with socket.create_connection(('127.0.0.1', port), timeout=1):
                    if ready.exists():
                        break
            except OSError:
                pass
            time.sleep(.2)
        environment = {**os.environ, 'OSV_MITM_PROXY': '127.0.0.1:' + str(port),
                       'EGRESS_HOSTS': os.environ.get('EGRESS_HOSTS', 'api.osv.dev,api.anthropic.com')}
        processes.append(subprocess.Popen([sys.executable, str(root.parents[1] / 'egress' / 'proxy.py')], env=environment))
        while all(process.poll() is None for process in processes):
            time.sleep(.2)
        raise RuntimeError('proxy component exited; refusing uninspected OSV traffic')
    finally:
        for process in processes:
            if process.poll() is None:
                process.terminate()
        for process in processes:
            try:
                process.wait(timeout=5)
            except subprocess.TimeoutExpired:
                process.kill()
                process.wait()


if __name__ == '__main__':
    main()
