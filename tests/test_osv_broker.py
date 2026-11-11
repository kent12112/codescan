import json
import unittest
import httpx
from service.osv_broker import create_app
from tests_identity import identity


class BrokerTests(unittest.TestCase):
    def test_body_policy_is_independent_of_agent_process(self):
        calls=[]
        def handler(request):
            calls.append(request)
            self.assertEqual(str(request.url),'https://api.osv.dev/v1/query')
            self.assertNotIn('authorization',request.headers)
            return httpx.Response(200,json={'vulns':[{'id':'TEST'}]})
        app=create_app(httpx.Client(transport=httpx.MockTransport(handler)))
        client=app.test_client()
        query={'package':{'name':'requests','ecosystem':'PyPI'},'version':'2.19.0'}
        self.assertEqual(client.post('/v1/query',json=query,environ_overrides=identity('analyst')).status_code,200)
        self.assertEqual(client.post('/v1/query',json={**query,'secret':'internal-api-key-test'},environ_overrides=identity('analyst')).status_code,400)
        self.assertEqual(client.post('/v1/query?extra=test',json=query,environ_overrides=identity('analyst')).status_code,400)
        self.assertEqual(client.post('/v1/query',json=query,headers={'Authorization':'synthetic'},environ_overrides=identity('analyst')).status_code,400)
        self.assertEqual(len(calls),1)

    def test_scanner_or_spoofed_header_cannot_query(self):
        app=create_app(object()); client=app.test_client()
        self.assertEqual(client.post('/v1/query',json={},environ_overrides=identity('scanner')).status_code,403)
        self.assertEqual(client.post('/v1/query',json={},headers={'X-Forwarded-Client-Cert':'analyst'}).status_code,403)
