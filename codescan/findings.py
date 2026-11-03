"""Run deterministic scanners over a workspace and collect structured findings."""
import json
import subprocess
from pathlib import Path


def run_bandit(root: Path) -> list[dict]:
    """Run Bandit on `root`, return a normalized list of findings."""
    proc = subprocess.run(
        ["bandit", "-r", str(root), "-f", "json"],
        capture_output=True, text=True,
    )
    # Bandit exits non-zero when it finds issues; that's normal, so we parse anyway.
    try:
        data = json.loads(proc.stdout)
    except json.JSONDecodeError:
        return []

    findings = []
    for r in data.get("results", []):
        findings.append({
            "tool": "bandit",
            "rule": r.get("test_id"),
            "title": r.get("test_name"),
            "severity": r.get("issue_severity"),
            "confidence": r.get("issue_confidence"),
            "file": str(Path(r["filename"]).name),
            "line": r.get("line_number"),
            "message": r.get("issue_text"),
        })
    return findings
