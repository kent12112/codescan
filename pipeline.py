"""codescan — unified analysis pipeline.

Runs the deterministic detectors (Bandit + injection) and the LLM analyst over a
repo, then the synthesis agent (with its authority backstop) merges everything
into one ranked, de-duplicated report. If a DAST report (dast/zap/report.json)
exists, those findings are folded in too.
"""
import sys
from pathlib import Path
from codescan.workspace import throwaway_copy
from codescan.findings import run_bandit
from codescan.injection import find_injections
from codescan.analyst import analyze_code
from codescan.synthesize import synthesize
from codescan.zap import load_zap_findings


def scan(source):
    with throwaway_copy(source) as work:
        findings = run_bandit(work) + find_injections(work)
    findings += analyze_code(source)
    zap_report = Path("dast/zap/report.json")
    if zap_report.exists():
        findings += load_zap_findings(str(zap_report))
    return synthesize(findings)


def main():
    source = sys.argv[1] if len(sys.argv) > 1 else "dast/target"
    print(f"scanning {source} ...\n")
    for m in scan(source):
        srcs = ", ".join(m.get("sources", []))
        flag = "  [recovered by authority]" if m.get("recovered_by_authority") else ""
        print(f"[{m['severity']}] {m['title']}  ({m.get('confidence')}; via {srcs}){flag}")
        print(f"    {m.get('summary', '')}")


if __name__ == "__main__":
    main()
