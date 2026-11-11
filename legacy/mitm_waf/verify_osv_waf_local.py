"""Exercise real TLS interception locally using a disposable CA; no API keys."""
import importlib.util
import os
from pathlib import Path
import socket
import signal
import subprocess
import sys
import tempfile
import time
import certifi

HERE = Path(__file__).resolve().parent


def free_port():
    with socket.socket() as connection:
        connection.bind(('127.0.0.1', 0))
        return connection.getsockname()[1]


def main():
    spec = importlib.util.spec_from_file_location('osv_probe', HERE / 'osv_waf_probe.py')
    probe = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(probe)
    with tempfile.TemporaryDirectory(prefix='codescan-waf-test-') as directory:
        root = Path(directory)
        ca = root / 'ca'
        ca.mkdir()
        subprocess.run([sys.executable, str(HERE / 'provision_ca.py'), str(ca)], check=True)
        port, inner_port = free_port(), free_port()
        environment = {**os.environ, 'WAF_CA_FILE': str(ca / 'mitmproxy-ca.pem'),
            'WAF_CONF_DIR': str(root / 'runtime'), 'WAF_MITM_PORT': str(inner_port),
            'EGRESS_BIND': '127.0.0.1', 'EGRESS_PORT': str(port), 'PYTHONUNBUFFERED': '1'}
        with (root / 'proxy.log').open('w+') as log:
            process = subprocess.Popen([sys.executable, str(HERE / 'run_proxy.py')],
                                       env=environment, stdout=log, stderr=subprocess.STDOUT)
            try:
                deadline = time.monotonic() + 30
                while True:
                    if process.poll() is not None or time.monotonic() > deadline:
                        raise RuntimeError('proxy failed to start')
                    try:
                        with socket.create_connection(('127.0.0.1', port), timeout=1):
                            break
                    except OSError:
                        time.sleep(.2)
                probe.verify('http://127.0.0.1:' + str(port), str(ca / 'ca-bundle.pem'), certifi.where())
                # Target only the inspector created by this disposable test.
                children = subprocess.check_output(
                    ['pgrep', '-P', str(process.pid), '-f', 'mitmdump'], text=True).splitlines()
                assert len(children) == 1, children
                os.kill(int(children[0]), signal.SIGTERM)
                assert process.wait(timeout=10) != 0
                try:
                    with socket.create_connection(('127.0.0.1', port), timeout=1):
                        raise AssertionError('frontend survived inspector failure')
                except OSError:
                    pass
                print('PASS: inspector failure stops frontend; no uninspected fallback', flush=True)
            except BaseException:
                log.seek(0)
                print(log.read())
                raise
            finally:
                process.terminate()
                try:
                    process.wait(timeout=10)
                except subprocess.TimeoutExpired:
                    process.kill()
                    process.wait()


if __name__ == '__main__':
    main()
