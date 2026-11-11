"""Real HTTPS checks. Sends public dependency queries and synthetic markers only."""
import json
import os
import socket
import ssl
import urllib.error
import urllib.request
from pathlib import Path


def verify(proxy, ca_bundle, public_roots=None):
    context = ssl.create_default_context(cafile=ca_bundle)
    opener = urllib.request.build_opener(urllib.request.ProxyHandler({'https': proxy}),
                                         urllib.request.HTTPSHandler(context=context))
    query = {'package': {'name': 'requests', 'ecosystem': 'PyPI'}, 'version': '2.19.0'}
    body = json.dumps(query).encode()
    def call(data, path='/v1/query', method='POST', extra=None):
        request = urllib.request.Request('https://api.osv.dev' + path, data=data,
            headers={'Content-Type': 'application/json', **(extra or {})}, method=method)
        try:
            with opener.open(request, timeout=20) as response:
                return response.status, response.read()
        except urllib.error.HTTPError as error:
            return error.code, error.read()
    status, response = call(body)
    assert status == 200, (status, response[:100])
    assert isinstance(json.loads(response).get('vulns', []), list)
    print('PASS: valid OSV query succeeds with verified TLS', flush=True)
    tests = [
        ('extra JSON field', json.dumps({**query, 'secret': 'internal-api-key-waf-test'}).encode(), '/v1/query', 'POST', None),
        ('escaped secret marker', body.replace(b'requests', b'internal-api-k\\u0065y'), '/v1/query', 'POST', None),
        ('unapproved path', body, '/v1/query?data=test', 'POST', None),
        ('unapproved method', None, '/v1/query', 'GET', None),
        ('authorization header', body, '/v1/query', 'POST', {'Authorization': 'synthetic-test'}),
        ('encoded body', body, '/v1/query', 'POST', {'Content-Encoding': 'gzip'}),
        ('host mismatch', body, '/v1/query', 'POST', {'Host': 'example.com'}),
    ]
    for label, data, path, method, extra in tests:
        status, response = call(data, path, method, extra)
        assert status == 403 and response == b'blocked by OSV egress policy', (label, status)
        print('PASS: WAF blocks ' + label, flush=True)
    if os.environ.get('REQUIRE_GATEWAY') == '1':
        from urllib.parse import urlsplit
        endpoint = urlsplit(proxy)
        with socket.create_connection((endpoint.hostname, endpoint.port), timeout=5) as connection:
            connection.sendall(b'CONNECT api.anthropic.com:443 HTTP/1.1\r\nHost: api.anthropic.com:443\r\n\r\n')
            assert b'403' in connection.recv(1024)
        print('PASS: direct Anthropic access is blocked; authenticated gateway is required', flush=True)
    else:
        # Trust public roots only here. A certificate signed by our inspection CA
        # would fail, so this also verifies that Anthropic is not TLS-intercepted.
        public_roots = public_roots or ssl.get_default_verify_paths().openssl_cafile
        if not public_roots or not Path(public_roots).is_file():
            raise RuntimeError('public system CA store not available for passthrough verification')
        public = urllib.request.build_opener(urllib.request.ProxyHandler({'https': proxy}),
            urllib.request.HTTPSHandler(context=ssl.create_default_context(cafile=public_roots)))
        try:
            with public.open('https://api.anthropic.com/v1/messages', timeout=20) as response:
                status = response.status
        except urllib.error.HTTPError as error:
            status = error.code
            error.close()
        assert status in {200, 400, 401, 404, 405}, status
        print('PASS: Anthropic public certificate validates without inspection CA (no API key sent)', flush=True)
    from urllib.parse import urlsplit
    endpoint = urlsplit(proxy)
    with socket.create_connection((endpoint.hostname, endpoint.port), timeout=5) as connection:
        connection.sendall(b'CONNECT example.com:443 HTTP/1.1\r\nHost: example.com:443\r\n\r\n')
        assert b'403' in connection.recv(1024)
    print('PASS: outer proxy blocks unapproved CONNECT destination', flush=True)


if __name__ == '__main__':
    verify(os.environ['HTTPS_PROXY'], os.environ['SSL_CERT_FILE'])
