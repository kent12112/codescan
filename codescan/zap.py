"""Normalize OWASP ZAP (DAST) findings into the scanner's shared finding shape."""
import json
from pathlib import Path

# ZAP riskcode -> our severity
RISK = {"3": "HIGH", "2": "MEDIUM", "1": "LOW", "0": "INFO"}


def load_zap_findings(report_path="dast/zap/report.json") -> list[dict]:
    data = json.loads(Path(report_path).read_text())
    findings = []
    for site in data.get("site", []):
        for a in site.get("alerts", []):
            instances = a.get("instances", [])
            loc = instances[0].get("uri") if instances else site.get("@name")
            param = instances[0].get("param", "") if instances else ""
            findings.append({
                "tool": "zap",
                "rule": f"ZAP-{a.get('pluginid')}",
                "title": a.get("alert"),
                "severity": RISK.get(a.get("riskcode"), "INFO"),
                "file": None,
                "line": None,
                "message": f"{a.get('riskdesc')} at {loc}"
                           + (f" (param: {param})" if param else ""),
            })
    return findings
