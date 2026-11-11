"""Fail-closed workload identity and bounded JSON handling."""
from flask import request, abort
from service import strict_json

TRUST_DOMAIN = 'spiffe://codescan.local/'


def peer_role(allowed):
    transport = request.environ.get('gunicorn.socket')
    if transport is None or not hasattr(transport, 'getpeercert'):
        abort(403)
    try:
        cert = transport.getpeercert()
        identities = [value for kind, value in cert.get('subjectAltName', []) if kind == 'URI']
    except (OSError, AttributeError):
        abort(403)
    if len(identities) != 1 or identities[0] not in {TRUST_DOMAIN + role for role in allowed}:
        abort(403)
    return identities[0].removeprefix(TRUST_DOMAIN)


def bounded_json():
    if request.mimetype != 'application/json' or request.headers.get('Content-Encoding'):
        abort(415)
    if request.content_length is None or request.content_length <= 0:
        abort(411)
    try:
        return strict_json.loads(request.get_data())
    except (UnicodeError, ValueError, RecursionError):
        abort(400)


def configure_errors(app):
    from werkzeug.exceptions import HTTPException
    @app.errorhandler(HTTPException)
    def controlled(error):
        return {'error': error.name}, error.code
    @app.errorhandler(Exception)
    def unexpected(error):
        # Never reflect exception text or request values to clients or logs.
        app.logger.error('Unhandled service error: %s', type(error).__name__)
        return {'error': 'internal service error'}, 500
