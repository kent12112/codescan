import concurrent.futures
import json
from pathlib import Path
import tempfile
import unittest
from types import SimpleNamespace
from unittest.mock import patch
import httpx
from service.analyst import create_app as agent_app
from service.gateway import create_app as gateway_app
from service.gateway_policy import validate, MODEL
from service.quota import Quota
from service.findings import parse_findings


def identity(role):
    return {'gunicorn.socket': SimpleNamespace(getpeercert=lambda: {'subjectAltName': [('URI', 'spiffe://codescan.local/' + role)]})}


def message():
    return {'model': MODEL, 'max_tokens': 128, 'messages': [{'role': 'user', 'content': 'test'}]}


class TeamServiceTests(unittest.TestCase):
    def test_gateway_refuses_unauthenticated_and_spoofed_headers(self):
        with tempfile.TemporaryDirectory() as directory:
            app = gateway_app(upstream=object(), quota=Quota(Path(directory)/'db'), key_file=Path(directory)/'key')
            client = app.test_client()
            response = client.post('/v1/messages', json=message(), headers={'X-Forwarded-Client-Cert': 'scanner'})
            self.assertEqual(response.status_code, 403)
            self.assertEqual(client.post('/v1/messages', json=message(), environ_overrides=identity('gateway')).status_code, 403)

    def test_gateway_owns_key_and_does_not_forward_client_credentials(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory); (root/'key').write_text('synthetic-provider-key')
            calls = []
            def handler(request):
                calls.append(request)
                self.assertEqual(request.headers['x-api-key'], 'synthetic-provider-key')
                self.assertEqual(str(request.url), 'https://api.anthropic.com/v1/messages')
                self.assertNotIn('authorization', request.headers)
                return httpx.Response(200, json={'type': 'message', 'content': []})
            upstream = httpx.Client(transport=httpx.MockTransport(handler))
            app = gateway_app(upstream=upstream, quota=Quota(root/'db', daily=1), key_file=root/'key')
            client = app.test_client()
            response = client.post('/v1/messages', json=message(), environ_overrides=identity('scanner'), headers={'x-api-key': 'attacker-key', 'Authorization': 'attacker-token'})
            self.assertEqual(response.status_code, 200)
            self.assertNotIn(b'synthetic-provider-key', response.data)
            self.assertEqual(client.post('/v1/messages', json=message(), environ_overrides=identity('scanner')).status_code, 429)
            self.assertEqual(len(calls), 1)

    def test_policy_rejects_unbounded_or_unexpected_provider_operations(self):
        for change in [{'model': 'other-model'}, {'max_tokens': 999999}, {'max_tokens': True},
                       {'stream': True}, {'metadata': {'user_id': 'x'}},
                       {'messages': [{'role': 'user', 'content': [{'type': 'image', 'source': {'url': 'https://example.com'}}]}]},
                       {'tools': [{'name': 'run_shell'}]}]:
            with self.subTest(change=change), self.assertRaises(ValueError):
                validate({**message(), **change}, 'scanner')

    def test_quota_is_atomic_and_survives_reopening(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory)/'quota'
            quota = Quota(path, daily=3, minute=3)
            with concurrent.futures.ThreadPoolExecutor(max_workers=10) as pool:
                results = list(pool.map(lambda _: quota.reserve('scanner', now=100000), range(12)))
            self.assertEqual(sum(results), 3)
            self.assertFalse(Quota(path, daily=3, minute=3).reserve('scanner', now=100100))
            self.assertTrue(quota.reserve('analyst', now=100000))

    def test_agent_requires_scanner_identity_and_rejects_malformed_output(self):
        invoked = []
        app = agent_app(lambda *args: invoked.append(args) or 'not JSON', lambda _: '[]')
        client = app.test_client()
        self.assertEqual(client.post('/analyze', json={'code': 'x'}).status_code, 403)
        self.assertEqual(client.post('/analyze', json={'code': 'x'}, environ_overrides=identity('analyst')).status_code, 403)
        response = client.post('/analyze', json={'code': 'x'}, environ_overrides=identity('scanner'))
        self.assertEqual(response.status_code, 502)
        self.assertEqual(len(invoked), 1)
        self.assertNotIn(b'not JSON', response.data)

    def test_agent_bounds_input_before_analysis_and_hides_exceptions(self):
        def failure(*args):
            raise RuntimeError('synthetic-secret-must-not-leak')
        app = agent_app(failure, lambda _: '[]'); client = app.test_client()
        self.assertEqual(client.post('/analyze', json={'code': 'x'*80001}, environ_overrides=identity('scanner')).status_code, 400)
        self.assertEqual(client.post('/analyze', data=b'x'*(256*1024+1), content_type='application/json', environ_overrides=identity('scanner')).status_code, 413)
        response = client.post('/analyze', json={'code':'x'}, environ_overrides=identity('scanner'))
        self.assertEqual(response.status_code, 500)
        self.assertNotIn(b'synthetic-secret', response.data)

    def test_agent_duplicate_keys_and_extra_fields_fail_before_work(self):
        app=agent_app(lambda *args: self.fail('must not analyze'), lambda _: self.fail())
        client=app.test_client()
        for body in [b'{"code":"x","code":"y"}', b'{"code":"x","role":"admin"}']:
            self.assertEqual(client.post('/analyze', data=body, content_type='application/json', environ_overrides=identity('scanner')).status_code, 400)

    def test_malformed_model_output_is_not_a_clean_result(self):
        for text in ['broken', '{}', '[{"severity":"HIGH"}]']:
            with self.assertRaises((ValueError, KeyError)):
                parse_findings(text)
        self.assertEqual(parse_findings('[]'), [])

    @patch.dict('os.environ', {'REQUIRE_GATEWAY': '1'}, clear=True)
    def test_provider_client_fails_without_gateway(self):
        from codescan.llm_client import make_client
        with self.assertRaisesRegex(RuntimeError, 'gateway is required'):
            make_client()

    @patch.dict('os.environ', {'LLM_GATEWAY_URL': 'https://llm-gateway:8443', 'ANTHROPIC_API_KEY': 'synthetic-key'}, clear=True)
    def test_provider_key_is_rejected_in_workload_clients(self):
        from codescan.llm_client import make_client
        with self.assertRaisesRegex(RuntimeError, 'must not be present'):
            make_client()
