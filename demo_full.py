"""Full capstone demo: SAST + injection + DAST, unified through LLM triage."""
from codescan.scan import scan_repo
from codescan.zap import load_zap_findings
from codescan.triage import triage

AUTHORITATIVE_TOOLS = {"injection-scan"}  # model may annotate, never downgrade


def main():
    sast = scan_repo("dast/target")["findings"]   # static view: read the code
    dast = load_zap_findings()                     # dynamic view: ZAP probed it running
    findings = sast + dast

    verdicts = triage(findings)
    if len(verdicts) != len(findings):
        raise SystemExit(f"triage mismatch: {len(verdicts)} vs {len(findings)}")

    rows = []
    for f, v in zip(findings, verdicts):
        if f["tool"] in AUTHORITATIVE_TOOLS:
            verdict, sev = "real", f["severity"]
        else:
            verdict = v.get("verdict", "needs_review")
            sev = v.get("severity", f["severity"])
        rows.append((sev, f["tool"], f["rule"], verdict, f["title"], v.get("reason", "")))

    order = {"HIGH": 0, "MEDIUM": 1, "LOW": 2, "INFO": 3}
    rows.sort(key=lambda r: order.get(r[0], 9))
    for sev, tool, rule, verdict, title, reason in rows:
        print(f"[{sev}] {tool}:{rule} {verdict} — {title}")
        if reason:
            print(f"    {reason}")


if __name__ == "__main__":
    main()
