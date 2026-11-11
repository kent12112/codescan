"""Mutually authenticated, size/concurrency-bounded analyst API."""
import threading
from flask import Flask, request, abort
from service.common import peer_role, bounded_json, configure_errors
from service.findings import parse_findings


def create_app(analyst=None, auditor=None):
    if analyst is None or auditor is None:
        from codescan.analyst_agent import analyze, analyze_dependencies
        analyst, auditor = analyst or analyze, auditor or analyze_dependencies
    app = Flask(__name__)
    app.config['MAX_CONTENT_LENGTH'] = 256 * 1024
    configure_errors(app)
    slots = threading.BoundedSemaphore(1)

    @app.get('/healthz')
    def health():
        peer_role({'scanner'})
        return {'ok': True}

    @app.post('/analyze')
    @app.post('/audit')
    def analyze_request():
        peer_role({'scanner'})
        if request.query_string:
            abort(400)
        data = bounded_json()
        allowed = {'code', 'requirements', 'injection_warning'} if request.path == '/analyze' else {'requirements'}
        if not isinstance(data, dict) or set(data) - allowed or not data:
            abort(400)
        limits = {'code': 80000, 'requirements': 16000, 'injection_warning': 16000}
        if any(not isinstance(value, str) or len(value) > limits[key] for key, value in data.items()):
            abort(400)
        if not slots.acquire(blocking=False):
            abort(429)
        try:
            result = (analyst(data.get('code', ''), data.get('requirements', ''), data.get('injection_warning', ''))
                      if request.path == '/analyze' else auditor(data.get('requirements', '')))
            try:
                findings = parse_findings(result, dependency=request.path == '/audit')
            except (ValueError, KeyError, TypeError):
                return {'error': 'analyst returned an invalid result'}, 502
            return {'findings': findings}
        finally:
            slots.release()
    return app
