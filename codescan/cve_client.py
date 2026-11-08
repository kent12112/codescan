"""Client for the CONTAINED cve-agent pod.

Reads a repo's Python dependencies, POSTs them to the agent over HTTP, and
normalizes the results into the pipeline's finding shape. The pipeline never
imports the agent — it only talks to it over the network, so the agent's work
stays inside its pod (NetworkPolicy, egress proxy, seccomp, Tetragon).
"""
import json
import os
import sys
import urllib.request
import urllib.error
from pathlib import Path

AGENT_URL = os.environ.get("CVE_AGENT_URL", "http://localhost:9000/audit")
_SEV = {"HIGH", "MEDIUM", "LOW"}
# talk to localhost directly, never through any HTTP(S)_PROXY in the shell env
_opener = urllib.request.build_opener(urllib.request.ProxyHandler({}))


def _find_requirements(repo_path):
    root = Path(repo_path)
    direct = root / "requirements.txt"
    if direct.is_file():
        return direct
    for p in root.rglob("requirements*.txt"):
        if p.is_file():
            return p
    return None


def cve_findings_via_agent(repo_path, url=AGENT_URL, timeout=180):
    req_file = _find_requirements(repo_path)
    if req_file is None:
        return []                      # nothing to audit
    payload = json.dumps({"requirements": req_file.read_text(errors="replace")}).encode()
    request = urllib.request.Request(
        url, data=payload, headers={"Content-Type": "application/json"}, method="POST")
    try:
        with _opener.open(request, timeout=timeout) as resp:
            data = json.loads(resp.read())
    except (urllib.error.URLError, OSError, json.JSONDecodeError) as exc:
        print(f"[warning] cve-agent unreachable ({exc}); skipping dependency audit. "
              f"Is the pod running and port-forwarded at {url}?", file=sys.stderr)
        return []

    findings = []
    for v in data.get("findings", []):
        sev = v.get("severity", "MEDIUM")
        pkg, ver = v.get("package", "?"), v.get("version", "?")
        findings.append({
            "tool": "cve-agent",
            "rule": "CVE",
            "title": f"{pkg} {ver}: known vulnerabilities"[:80],
            "severity": sev if sev in _SEV else "MEDIUM",
            "file": req_file.name,
            "line": None,
            "message": v.get("summary", ""),
        })
    return findings
