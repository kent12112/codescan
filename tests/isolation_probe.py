"""Run inside a scanner-shaped Pod without a Secret; no model calls."""
import os
from pathlib import Path
import socket
import urllib.request
from scanner_entry import wait_for_isolation

wait_for_isolation()

assert os.getuid() == 1000
assert not Path('/var/run/secrets/kubernetes.io/serviceaccount/token').exists()
assert not Path('/home/ubuntu').exists()
try:
    Path('/home/scanner/write-probe').write_text('should fail')
except OSError:
    pass
else:
    raise AssertionError('root filesystem is writable')
Path('/tmp/write-probe').write_text('scratch works')
print('PASS: non-root, read-only root, writable scratch, no host home or API token', flush=True)
for address in [('1.1.1.1', 443), ('kubernetes.default.svc', 443)]:
    try:
        connection = socket.create_connection(address, timeout=3)
    except OSError:
        print('PASS: direct network blocked:', address, flush=True)
    else:
        connection.close()
        raise AssertionError('unexpected direct egress: ' + str(address))

connection = socket.create_connection(('scanner-proxy', 8080), timeout=5)
connection.sendall(b'CONNECT example.com:443 HTTP/1.1\r\nHost: example.com:443\r\n\r\n')
assert b'403' in connection.recv(1024)
connection.close()
print('PASS: proxy rejects unapproved destination', flush=True)
connection = socket.create_connection(('scanner-proxy', 8080), timeout=5)
connection.sendall(b'CONNECT github.com:444 HTTP/1.1\r\nHost: github.com:444\r\n\r\n')
assert b'403' in connection.recv(1024)
connection.close()
print('PASS: proxy rejects unapproved port', flush=True)
opener = urllib.request.build_opener(urllib.request.ProxyHandler({}))
assert opener.open('http://cve-agent:9000/healthz', timeout=5).status == 200
print('PASS: contained analyst reachable', flush=True)
# Also verify cloning can use the allowed HTTPS destination without model usage.
import subprocess
subprocess.run(['/bin/sh', '-c', 'true'], check=True, timeout=5)
print('PASS: trusted scanner subprocesses are permitted', flush=True)
result = subprocess.run(['git', 'ls-remote', 'https://github.com/kent12112/codescan.git', 'HEAD'],
                        check=True, capture_output=True, text=True, timeout=30)
assert result.stdout.strip()
print('PASS: GitHub reachable through scanner proxy', flush=True)
