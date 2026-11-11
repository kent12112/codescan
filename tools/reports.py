"""Validate, persist privately and safely render the scanner's final JSON record."""
import json
import os
from pathlib import Path
import unicodedata


def extract_report(logs):
    records = [line[len('CODESCAN_REPORT='):] for line in logs.splitlines() if line.startswith('CODESCAN_REPORT=')]
    if len(records) != 1 or len(records[0]) > 2 * 1024 * 1024:
        raise ValueError('missing, duplicate or oversized final report')
    data = json.loads(records[0])
    if not isinstance(data, dict) or data.get('schema_version') != 1 or not isinstance(data.get('findings'), list) or len(data['findings']) > 1000:
        raise ValueError('invalid final report')
    for finding in data['findings']:
        if not isinstance(finding, dict) or finding.get('severity') not in {'HIGH','MEDIUM','LOW','INFO'}:
            raise ValueError('invalid report severity')
        if not isinstance(finding.get('title'), str) or len(finding['title']) > 200 or not isinstance(finding.get('summary'), str) or len(finding['summary']) > 8192:
            raise ValueError('invalid report text')
        if finding.get('confidence') not in {'confirmed','single-source'} or not isinstance(finding.get('sources'), list) or not all(isinstance(s,str) and len(s)<100 for s in finding['sources']):
            raise ValueError('invalid report sources')
    return data


def safe_text(text):
    return ''.join(character for character in text if not unicodedata.category(character).startswith('C'))


def save_and_render(data, name, directory):
    root = Path(directory)
    root.mkdir(mode=0o700, parents=True, exist_ok=True)
    path = root / (name + '.json')
    descriptor = os.open(path, os.O_CREAT | os.O_EXCL | os.O_WRONLY, 0o600)
    with os.fdopen(descriptor, 'w') as stream:
        json.dump(data, stream, ensure_ascii=True, indent=2)
        stream.write('\n')
    for finding in data['findings']:
        print(f"[{finding['severity']}] {safe_text(finding['title'])} ({finding['confidence']})")
        print('    ' + safe_text(finding['summary']))
    print('Report saved: ' + str(path))
    return path


def save_failure(logs, name, directory):
    root = Path(directory)
    root.mkdir(mode=0o700, parents=True, exist_ok=True)
    path = root / (name + '.failed.log')
    descriptor = os.open(path, os.O_CREAT | os.O_EXCL | os.O_WRONLY, 0o600)
    with os.fdopen(descriptor, 'w') as stream:
        stream.write(logs[:2 * 1024 * 1024])
    print('Private failure log saved: ' + str(path))
    return path
