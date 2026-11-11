import unittest
from types import SimpleNamespace
from unittest.mock import patch
try:
    from mitmproxy import http
    from legacy.mitm_waf import egress_waf
except ImportError:
    http = None


@unittest.skipUnless(http, 'mitmproxy is installed only in the dedicated WAF environment')
class WAFHookTests(unittest.TestCase):
    def flow(self):
        request = http.Request.make('POST', 'https://api.osv.dev/v1/query',
            b'{"package":{"name":"requests","ecosystem":"PyPI"},"version":"2.19.0"}',
            {'Content-Type': 'application/json', 'User-Agent': 'caller-controlled'})
        return SimpleNamespace(request=request, response=None,
                               server_conn=SimpleNamespace(address=('api.osv.dev', 443)))

    def test_unexpected_header_exception_blocks_request(self):
        flow = self.flow()
        with patch.object(egress_waf, 'check_headers', side_effect=RuntimeError('test')):
            egress_waf.requestheaders(flow)
        self.assertEqual(flow.response.status_code, 403)

    def test_unexpected_body_exception_blocks_request(self):
        flow = self.flow()
        with patch.object(egress_waf, 'check_body', side_effect=RuntimeError('test')):
            egress_waf.request(flow)
        self.assertEqual(flow.response.status_code, 403)

    def test_valid_request_replaces_caller_metadata(self):
        flow = self.flow()
        egress_waf.request(flow)
        self.assertIsNone(flow.response)
        self.assertEqual(flow.request.headers['User-Agent'], 'codescan-osv/1')

    def test_pathological_content_length_is_rejected(self):
        flow = self.flow()
        flow.request.headers['Content-Length'] = '9' * 5000
        egress_waf.requestheaders(flow)
        self.assertEqual(flow.response.status_code, 403)
