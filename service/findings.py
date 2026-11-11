"""Treat model output as bounded data; malformed output is never a clean report."""
import json
import re
from service.strict_json import unique_object


def validate_findings(value):
    if not isinstance(value, list) or len(value) > 100:
        raise ValueError('invalid findings array')
    for finding in value:
        if not isinstance(finding, dict) or set(finding) - {'kind', 'title', 'severity', 'file', 'line', 'summary'}:
            raise ValueError('invalid finding fields')
        if finding.get('severity') not in {'HIGH', 'MEDIUM', 'LOW'} or finding.get('kind') not in {'code', 'dependency'}:
            raise ValueError('invalid finding classification')
        for key, maximum in [('title', 200), ('summary', 8192)]:
            if not isinstance(finding.get(key), str) or not 0 < len(finding[key]) <= maximum:
                raise ValueError('invalid finding text')
        path = finding.get('file')
        line = finding.get('line')
        if path is not None and (not isinstance(path, str) or len(path) > 1024):
            raise ValueError('invalid finding path')
        if line is not None and (type(line) is not int or not 1 <= line <= 100000000):
            raise ValueError('invalid finding line')
    return value


def parse_findings(text, dependency=False):
    if not isinstance(text, str) or len(text.encode()) > 1024 * 1024:
        raise ValueError('invalid analyst output')
    fenced = re.search(r'```(?:json)?\s*(.*?)```', text, re.DOTALL)
    candidate = fenced.group(1) if fenced else text
    value = json.loads(candidate, object_pairs_hook=unique_object)
    if dependency:
        if not isinstance(value, list) or len(value) > 100:
            raise ValueError('invalid dependency result')
        value = [{'kind': 'dependency', 'title': f"{f['package']} {f['version']}",
                  'severity': f['severity'], 'summary': f['summary'], 'file': None, 'line': None}
                 for f in value]
    return validate_findings(value)
