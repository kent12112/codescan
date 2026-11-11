"""Only authenticated PyPI dependency queries may reach OSV."""
import json
import os
import httpx
from flask import Flask, request, abort
from service.common import peer_role, configure_errors
from service.osv_policy import check_body, MAX_BODY


def create_app(upstream=None):
    app=Flask(__name__)
    app.config['MAX_CONTENT_LENGTH']=MAX_BODY
    configure_errors(app)
    client=upstream or httpx.Client(timeout=httpx.Timeout(15,connect=5),trust_env=False,
        follow_redirects=False,proxy=os.environ.get('OSV_UPSTREAM_PROXY','http://osv-egress-proxy:8080'),
        limits=httpx.Limits(max_connections=4,max_keepalive_connections=4))

    @app.get('/healthz')
    def health():
        peer_role({'analyst'})
        return {'ok':True}

    @app.post('/v1/query')
    def query():
        peer_role({'analyst'})
        if request.query_string or request.mimetype!='application/json' or request.headers.get('Content-Encoding'):
            abort(400)
        if request.content_length is None or not 0<request.content_length<=MAX_BODY:
            abort(413)
        allowed={'host','content-length','content-type','user-agent','accept','accept-encoding','connection'}
        if any(key.lower() not in allowed for key in request.headers.keys()):
            abort(400)
        body=request.get_data()
        if check_body(body):
            abort(400)
        try:
            with client.stream('POST','https://api.osv.dev/v1/query',content=body,
                headers={'Content-Type':'application/json','User-Agent':'codescan-osv/2'}) as response:
                if response.status_code!=200:
                    return {'error':'OSV unavailable'},502
                chunks=[]; size=0
                for chunk in response.iter_bytes():
                    size+=len(chunk)
                    if size>2*1024*1024:
                        return {'error':'OSV response too large'},502
                    chunks.append(chunk)
                data=json.loads(b''.join(chunks))
                if not isinstance(data,dict) or not isinstance(data.get('vulns',[]),list):
                    return {'error':'invalid OSV response'},502
                return data
        except (httpx.HTTPError, ValueError):
            return {'error':'OSV unavailable'},502
    return app
