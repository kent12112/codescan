"""Run Semgrep (multi-language rules) and normalize into the shared finding shape."""
import json
import subprocess
import sys
from pathlib import Path

SEV = {"ERROR": "HIGH", "WARNING": "MEDIUM", "INFO": "LOW"}


def run_semgrep(root, config="p/default"):
    """Run Semgrep on `root`; return normalized findings. Warns (not silent) on failure."""
    proc = subprocess.run(
        ["semgrep", "scan", "--config", config, "--json", "--quiet",
         "--metrics=off", str(root)],
        capture_output=True, text=True,
    )
    try:
        data = json.loads(proc.stdout)
    except json.JSONDecodeError:
        print(f"[warning] semgrep did not run (exit {proc.returncode}): "
              f"{proc.stderr.strip()[:200]}", file=sys.stderr)
        return []

    if data.get("errors"):
        print(f"[warning] semgrep reported {len(data['errors'])} error(s); "
              f"results may be incomplete", file=sys.stderr)

    findings = []
    for r in data.get("results", []):
        extra = r.get("extra", {})
        findings.append({
            "tool": "semgrep",
            "rule": (r.get("check_id", "") or "").split(".")[-1],
            "title": (extra.get("message", "") or r.get("check_id", ""))[:80],
            "severity": SEV.get(extra.get("severity", "INFO"), "LOW"),
            "file": Path(r.get("path", "")).name,
            "line": r.get("start", {}).get("line"),
            "message": extra.get("message", ""),
        })
    return findings
