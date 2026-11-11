"""Run Semgrep (multi-language rules) and normalize into the shared finding shape."""
import json
import subprocess
import sys
import os
from pathlib import Path

SEV = {"ERROR": "HIGH", "WARNING": "MEDIUM", "INFO": "LOW"}


def run_semgrep(root, config=None):
    """Run Semgrep on `root`; return normalized findings. Warns (not silent) on failure."""
    config = config or os.environ.get("SEMGREP_CONFIG", "p/default")
    if os.environ.get('SEMGREP_CORE'):
        from codescan.native_semgrep import run
        data = run(root, config)
        return normalize(data)
    try:
        proc = subprocess.run(
            ["semgrep", "scan", "--config", config, "--json", "--quiet",
             "--metrics=off", str(root)],
            capture_output=True, text=True, timeout=300,
        )
    except subprocess.TimeoutExpired:
        if os.environ.get("STRICT_SCAN") == "1":
            raise RuntimeError("Semgrep timed out; scan incomplete")
        print("[warning] semgrep timed out", file=sys.stderr)
        return []
    try:
        data = json.loads(proc.stdout)
    except json.JSONDecodeError:
        if os.environ.get("STRICT_SCAN") == "1":
            raise RuntimeError(f"Semgrep failed (exit {proc.returncode}); scan incomplete")
        print(f"[warning] semgrep did not run (exit {proc.returncode}): "
              f"{proc.stderr.strip()[:200]}", file=sys.stderr)
        return []

    if os.environ.get("STRICT_SCAN") == "1" and (proc.returncode != 0 or data.get("errors")):
        raise RuntimeError("Semgrep reported errors; scan incomplete")
    if data.get("errors"):
        print(f"[warning] semgrep reported {len(data['errors'])} error(s); "
              f"results may be incomplete", file=sys.stderr)

    return normalize(data)


def normalize(data):
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
