"""Run the full deterministic layer over a repo and return combined findings."""
from codescan.workspace import throwaway_copy
from codescan.findings import run_bandit
from codescan.injection import find_injections


def scan_repo(source: str) -> dict:
    """Scan `source` in a throwaway sandbox; return a combined report dict."""
    with throwaway_copy(source) as work:
        findings = run_bandit(work) + find_injections(work)

    # sort most-severe first so the report leads with what matters
    order = {"HIGH": 0, "MEDIUM": 1, "LOW": 2}
    findings.sort(key=lambda f: order.get(f.get("severity"), 9))

    return {
        "target": source,
        "total": len(findings),
        "findings": findings,
    }
