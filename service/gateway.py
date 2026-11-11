"""Credential-owning, mutually authenticated, bounded Anthropic gateway."""
import json
import os
from pathlib import Path
import threading
import time
import uuid
import httpx
from flask import Flask, request, abort
from service.common import peer_role, bounded_json, configure_errors
from service.gateway_policy import validate, MAX_BODY, MAX_RESPONSE
from service.quota import Quota


def create_app(upstream=None, quota=None, key_file=None):
    app = Flask(__name__)
    app.config['MAX_CONTENT_LENGTH'] = MAX_BODY
    configure_errors(app)
    quota = quota or Quota(os.environ.get('QUOTA_DB', '/state/quota.sqlite'),
                           int(os.environ.get('DAILY_REQUEST_LIMIT', '200')),
                           int(os.environ.get('MINUTE_REQUEST_LIMIT', '30')))
    slots = threading.BoundedSemaphore(4)
    client = upstream or httpx.Client(timeout=httpx.Timeout(120, connect=10),
        limits=httpx.Limits(max_connections=4, max_keepalive_connections=4),
        trust_env=False, follow_redirects=False,
        proxy=os.environ.get('LLM_UPSTREAM_PROXY', 'http://llm-egress-proxy:8080'))
    key_path = Path(key_file or os.environ.get('ANTHROPIC_KEY_FILE', '/etc/provider-key/api-key'))

    @app.get('/healthz')
    def health():
        peer_role({'scanner', 'analyst'})
        return {'ok': True}

    @app.post('/v1/messages')
    def messages():
        role = peer_role({'scanner', 'analyst'})
        if request.query_string:
            abort(400)
        data = bounded_json()
        try:
            validate(data, role)
        except ValueError:
            abort(400)
        if not slots.acquire(blocking=False):
            abort(503)
        started, request_id = time.monotonic(), uuid.uuid4().hex
        try:
            if not quota.reserve(role):
                abort(429)
            key = key_path.read_text().strip()
            if not key or '\n' in key or '\r' in key:
                raise RuntimeError('provider credential unavailable')
            try:
                # Destination and authentication are never taken from client input.
                with client.stream('POST', 'https://api.anthropic.com/v1/messages',
                    headers={'x-api-key': key, 'anthropic-version': '2023-06-01', 'content-type': 'application/json'},
                    content=json.dumps(data).encode()) as response:
                    if response.status_code != 200:
                        return {'error': 'provider request failed', 'request_id': request_id}, 502
                    chunks, length = [], 0
                    for chunk in response.iter_bytes():
                        length += len(chunk)
                        if length > MAX_RESPONSE:
                            return {'error': 'provider response too large'}, 502
                        chunks.append(chunk)
                    body = b''.join(chunks)
                    try:
                        parsed = json.loads(body)
                    except ValueError:
                        return {'error': 'invalid provider response'}, 502
                    if not isinstance(parsed, dict) or parsed.get('type') != 'message':
                        return {'error': 'invalid provider response'}, 502
                    return app.response_class(body, mimetype='application/json')
            except httpx.HTTPError:
                return {'error': 'provider unavailable', 'request_id': request_id}, 502
        finally:
            slots.release()
            app.logger.warning('gateway_request id=%s role=%s elapsed_ms=%d',
                request_id, role, int((time.monotonic() - started) * 1000))
    return app
