"""Run in the analyst Pod; no paid model calls and no provider key access."""
import json
import os
from pathlib import Path
import socket
import ssl
import urllib.request
import urllib.error
from codescan.llm_client import workload_context

assert not os.environ.get('ANTHROPIC_API_KEY')
assert not Path('/etc/provider-key').exists()
context=workload_context()
opener=urllib.request.build_opener(urllib.request.ProxyHandler({}),urllib.request.HTTPSHandler(context=context))


def call(url,data=None,extra=None):
    body=json.dumps(data).encode() if data is not None else None
    req=urllib.request.Request(url,data=body,headers={'Content-Type':'application/json',**(extra or {})})
    try:
        with opener.open(req,timeout=20) as response: return response.status,json.loads(response.read())
    except urllib.error.HTTPError as error: return error.code,json.loads(error.read())


assert call('https://llm-gateway:8443/healthz')[0]==200
assert call('https://egress-proxy:8443/healthz')[0]==200
print('PASS: analyst identity authenticates gateway and OSV broker',flush=True)
query={'package':{'name':'requests','ecosystem':'PyPI'},'version':'2.19.0'}
assert call('https://egress-proxy:8443/v1/query',query)[0]==200
assert call('https://egress-proxy:8443/v1/query',{**query,'secret':'internal-api-key-test'})[0]==400
assert call('https://egress-proxy:8443/v1/query',query,{'Authorization':'synthetic'})[0]==400
assert call('https://egress-proxy:8443/v1/query?bad=test',query)[0]==400
print('PASS: OSV broker independently rejects secret markers, metadata and unapproved paths',flush=True)
assert call('https://127.0.0.1:9000/analyze',{'code':'test'},{'X-Forwarded-Client-Cert':'scanner'})[0]==403
print('PASS: analyst certificate cannot impersonate scanner identity',flush=True)
assert call('https://llm-gateway:8443/v1/messages',{'model':'not-allowed'})[0]==400
print('PASS: gateway refuses unauthorized model requests before provider access',flush=True)
for host in ['api.anthropic.com','api.osv.dev']:
    try:
        connection=socket.create_connection((host,443),timeout=2)
    except OSError:
        pass
    else:
        connection.close(); raise AssertionError('direct provider egress allowed')
print('PASS: no provider key and no direct provider network access',flush=True)
