"""Legacy mitmproxy addon, retained for the earlier lab demo.

The active team deployment uses service/osv_broker.py and has no mitmproxy dependency.
"""
from mitmproxy import http
import os
from pathlib import Path
import sys
# mitmdump loads this addon by file path; make the repository's policy importable.
sys.path.insert(0, str(Path(__file__).resolve().parents[2]))
from service.osv_policy import check_headers, check_body


def block(flow, reason):
    flow.response = http.Response.make(403, b'blocked by OSV egress policy',
                                       {'Content-Type': 'text/plain'})
    # Never log bodies, headers, package names, or credential-shaped matches.
    print('[OSV WAF] BLOCKED: ' + reason, flush=True)


def running():
    # The supervisor opens its frontend only after the addon is loaded.
    marker = os.environ.get('WAF_READY_FILE')
    if marker:
        Path(marker).write_text('ready\n')


def _requestheaders(flow):
    if flow.server_conn.address != ('api.osv.dev', 443):
        block(flow, 'upstream destination not allowed')
        return
    request = flow.request
    reason = check_headers(request.method, request.scheme, request.host,
                           request.port, request.path, list(request.headers.items(multi=True)))
    if reason:
        block(flow, reason)


def requestheaders(flow):
    try:
        _requestheaders(flow)
    except Exception:
        block(flow, 'header inspection failed')


def _request(flow):
    if flow.response is not None:
        return
    requestheaders(flow)
    if flow.response is not None:
        return
    body = flow.request.raw_content or b''
    if len(body) != int(flow.request.headers['content-length']):
        block(flow, 'body length mismatch')
        return
    reason = check_body(body)
    if reason:
        block(flow, reason)
        return
    # Drop caller-controlled metadata before forwarding a validated request.
    flow.request.headers.clear()
    flow.request.headers['Host'] = 'api.osv.dev'
    flow.request.headers['Content-Type'] = 'application/json'
    flow.request.headers['Content-Length'] = str(len(body))
    flow.request.headers['Accept'] = 'application/json'
    flow.request.headers['User-Agent'] = 'codescan-osv/1'
    print('[OSV WAF] ALLOWED: dependency query', flush=True)


def request(flow):
    try:
        _request(flow)
    except Exception:
        block(flow, 'body inspection failed')
