import json
import unittest
from service.osv_policy import check_body, check_headers, MAX_BODY


class OSVPolicyTests(unittest.TestCase):
    def query(self, **changes):
        data = {'package': {'name': 'requests', 'ecosystem': 'PyPI'}, 'version': '2.19.0'}
        data.update(changes)
        return json.dumps(data).encode()

    def test_known_dependency_query_passes(self):
        self.assertIsNone(check_body(self.query()))
        self.assertIsNone(check_headers('POST', 'https', 'api.osv.dev', 443, '/v1/query',
            [('Content-Type', 'application/json'), ('Content-Length', '80')]))

    def test_extra_fields_and_wrong_types_are_rejected(self):
        for body in [self.query(secret='test'), self.query(version={'nested': '2.0'}),
                     self.query(package={'name': 'x', 'ecosystem': 'PyPI', 'extra': 'data'}),
                     self.query(package={'name': 'x', 'ecosystem': 'npm'}), b'[]', b'NaN',
                     b'{"package":{},"version":"1","version":"2"}']:
            with self.subTest(body=body):
                self.assertIsNotNone(check_body(body))

    def test_secret_markers_and_unicode_escape_bypass_are_rejected(self):
        for body in [self.query(version='internal-api-key-test'),
                     self.query(package={'name': 'sk-' + 'a' * 20, 'ecosystem': 'PyPI'}),
                     self.query().replace(b'requests', b'internal-api-k\\u0065y')]:
            self.assertIsNotNone(check_body(body))

    def test_invalid_paths_methods_encodings_and_metadata_are_rejected(self):
        headers = [('Content-Type', 'application/json'), ('Content-Length', '80')]
        for method, scheme, host, port, path, extra in [
            ('GET', 'https', 'api.osv.dev', 443, '/v1/query', []),
            ('POST', 'http', 'api.osv.dev', 443, '/v1/query', []),
            ('POST', 'https', 'evil.example', 443, '/v1/query', []),
            ('POST', 'https', 'api.osv.dev', 444, '/v1/query', []),
            ('POST', 'https', 'api.osv.dev', 443, '/v1/query?secret=test', []),
            ('POST', 'https', 'api.osv.dev', 443, '/v1/query', [('Authorization', 'test')]),
            ('POST', 'https', 'api.osv.dev', 443, '/v1/query', [('Content-Encoding', 'gzip')]),
            ('POST', 'https', 'api.osv.dev', 443, '/v1/query', [('Transfer-Encoding', 'chunked')]),
            ('POST', 'https', 'api.osv.dev', 443, '/v1/query', [('Content-Length', '80')])]:
            with self.subTest(method=method, path=path, extra=extra):
                self.assertIsNotNone(check_headers(method, scheme, host, port, path, headers + extra))

    def test_bad_or_oversized_bodies_fail_closed(self):
        for body in [b'', b'\xff', b'{', b'x' * (MAX_BODY + 1)]:
            self.assertIsNotNone(check_body(body))
