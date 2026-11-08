"""Normalize an OWASP ZAP report (JSON file, or the scan's stdout text) into the
pipeline's finding shape, so DAST findings fold into the unified report."""
import json
import re
from pathlib import Path

_JSON_SEV = {3: "HIGH", 2: "MEDIUM", 1: "LOW", 0: "LOW"}
_TEXT_SEV = {"FAIL": "HIGH", "WARN": "MEDIUM", "INFO": "LOW", "IGNORE": "LOW"}
_LINE = re.compile(r'^(FAIL|WARN|INFO)-NEW:\s+(.*?)\s+\[(\d+)\]', re.MULTILINE)


def _from_json(data):
    out = []
    for site in data.get("site", []):
        host = site.get("@name", "")
        for a in site.get("alerts", []):
            try:
                risk = int(a.get("riskcode", 0))
            except (TypeError, ValueError):
                risk = 0
            out.append({"tool": "zap-dast", "rule": a.get("pluginid", "ZAP"),
                        "title": (a.get("name", "ZAP finding") or "ZAP finding")[:80],
                        "severity": _JSON_SEV.get(risk, "LOW"), "file": host or None, "line": None,
                        "message": (a.get("desc", "") or "").replace("<p>", " ").replace("</p>", " ").strip()[:500]})
    return out


def _from_text(text):
    out = []
    for m in _LINE.finditer(text):
        sev_kw, title, pid = m.group(1), m.group(2).strip(), m.group(3)
        out.append({"tool": "zap-dast", "rule": pid, "title": title[:80],
                    "severity": _TEXT_SEV.get(sev_kw, "LOW"), "file": None, "line": None,
                    "message": f"ZAP dynamic scan flagged: {title} (plugin {pid})"})
    return out


def dast_findings(report_path):
    p = Path(report_path)
    if not p.is_file():
        return []
    text = p.read_text(errors="replace")
    try:
        return _from_json(json.loads(text))
    except (json.JSONDecodeError, TypeError):
        return _from_text(text)
