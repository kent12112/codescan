"""Use a workload-authenticated gateway; direct provider credentials are dev-only."""
import os
import ssl
from urllib.parse import urlsplit
import anthropic
import httpx
# The gateway only admits this model, so clients take it from the same policy.
from service.gateway_policy import MODEL  # noqa: F401  (re-exported)


def workload_context():
    directory = os.environ.get('WORKLOAD_TLS_DIR', '/etc/workload-tls')
    context = ssl.create_default_context(cafile=directory + '/ca.crt')
    context.minimum_version = ssl.TLSVersion.TLSv1_2
    context.load_cert_chain(directory + '/tls.crt', directory + '/tls.key')
    return context


def make_client():
    gateway = os.environ.get('LLM_GATEWAY_URL')
    if gateway:
        url = urlsplit(gateway)
        if url.scheme != 'https' or not url.hostname or url.username or url.password or url.query or url.fragment:
            raise RuntimeError('gateway requires an authenticated HTTPS endpoint')
        if os.environ.get('ANTHROPIC_API_KEY'):
            raise RuntimeError('provider key must not be present in gateway clients')
        transport = httpx.Client(verify=workload_context(), trust_env=False, timeout=120,
                                 limits=httpx.Limits(max_connections=2))
        return anthropic.Anthropic(api_key='gateway-managed', base_url=gateway,
                                   http_client=transport, max_retries=0)
    if os.environ.get('REQUIRE_GATEWAY') == '1':
        raise RuntimeError('LLM gateway is required')
    return anthropic.Anthropic(max_retries=0)
