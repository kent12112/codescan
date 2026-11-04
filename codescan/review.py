"""Combine deterministic findings with LLM triage, keeping rules authoritative.

Verdicts are matched to findings BY POSITION — not by any key the model echoes,
because the model can't be trusted to copy keys back faithfully. If the counts
don't line up we fail loudly rather than risk misaligning a verdict.
"""
from codescan.scan import scan_repo
from codescan.triage import triage

AUTHORITATIVE_TOOLS = {"injection-scan"}  # LLM may annotate, never downgrade


def review_repo(source: str, client=None) -> dict:
    report = scan_repo(source)
    findings = report["findings"]
    verdicts = triage(findings, client=client)

    if len(verdicts) != len(findings):
        raise ValueError(
            f"triage returned {len(verdicts)} verdicts for "
            f"{len(findings)} findings — refusing to misalign"
        )

    reviewed = []
    for f, v in zip(findings, verdicts):
        model_verdict = v.get("verdict", "needs_review")
        model_sev = v.get("severity", f["severity"])
        reason = v.get("reason", "")

        if f["tool"] in AUTHORITATIVE_TOOLS:
            verdict = "real"
            severity = f["severity"]
            note = (f"PINNED by deterministic layer. "
                    f"(model wanted {model_verdict}/{model_sev}: {reason})")
        else:
            verdict = model_verdict
            severity = model_sev
            note = reason

        reviewed.append({
            "tool": f["tool"], "rule": f["rule"],
            "file": f["file"], "line": f["line"],
            "verdict": verdict, "severity": severity, "note": note,
        })

    order = {"HIGH": 0, "MEDIUM": 1, "LOW": 2}
    reviewed.sort(key=lambda r: order.get(r["severity"], 9))
    return {"target": source, "total": len(reviewed), "findings": reviewed}
