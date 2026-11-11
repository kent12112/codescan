"""Narrow, dependency-free policy for the analyst's OSV query tool."""
import json
import re
from service import strict_json

MAX_BODY = 4096
HEADERS = {'host', 'content-type', 'content-length', 'user-agent', 'accept',
           'accept-encoding', 'connection'}
PACKAGE = re.compile(r'[A-Za-z0-9](?:[A-Za-z0-9._-]{0,126}[A-Za-z0-9])?\Z')
VERSION = re.compile(r'v?[0-9][A-Za-z0-9.!+_-]{0,63}\Z')
SECRET_PATTERNS = [
    re.compile(rb'internal-api-key', re.I),
    re.compile(rb'sk-[A-Za-z0-9]{16,}'),
    re.compile(rb'-----BEGIN [A-Z ]*PRIVATE KEY-----'),
    re.compile(rb'[A-Za-z0-9+/]{120,}={0,2}'),
]


def check_headers(method, scheme, host, port, path, headers):
    if (method, scheme, host, port, path) != ('POST', 'https', 'api.osv.dev', 443, '/v1/query'):
        return 'endpoint not allowed'
    pairs = [(key.lower(), value) for key, value in headers]
    if any(key not in HEADERS for key, _ in pairs):
        return 'header not allowed'
    if len({key for key, _ in pairs}) != len(pairs):
        return 'duplicate header'
    fields = dict(pairs)
    if fields.get('host', 'api.osv.dev') not in {'api.osv.dev', 'api.osv.dev:443'}:
        return 'host header not allowed'
    if fields.get('content-type', '').lower() not in {'application/json', 'application/json; charset=utf-8'}:
        return 'JSON content type required'
    length = fields.get('content-length', '')
    if len(length) > 4 or not length.isascii() or not length.isdecimal() or not 0 < int(length) <= MAX_BODY:
        return 'invalid or oversized body length'
    return None


def check_body(body):
    if not 0 < len(body) <= MAX_BODY:
        return 'invalid body size'
    if any(pattern.search(body) for pattern in SECRET_PATTERNS):
        return 'sensitive body pattern'
    try:
        data = strict_json.loads(body.decode('utf-8'))
    except (UnicodeError, ValueError, RecursionError):
        return 'invalid JSON'
    if not isinstance(data, dict) or set(data) != {'package', 'version'}:
        return 'unexpected query fields'
    package = data['package']
    if not isinstance(package, dict) or set(package) != {'name', 'ecosystem'}:
        return 'unexpected package fields'
    if package['ecosystem'] != 'PyPI':
        return 'ecosystem not allowed'
    if not isinstance(package['name'], str) or not PACKAGE.fullmatch(package['name']):
        return 'invalid package name'
    if not isinstance(data['version'], str) or not VERSION.fullmatch(data['version']):
        return 'invalid exact version'
    # Check decoded values too, so JSON unicode escapes cannot hide a marker.
    decoded = json.dumps(data, ensure_ascii=False).encode('utf-8')
    if any(pattern.search(decoded) for pattern in SECRET_PATTERNS):
        return 'sensitive body pattern'
    return None
