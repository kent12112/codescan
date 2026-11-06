"""Collect findings from all static detectors and synthesize one clean report."""
from codescan.workspace import throwaway_copy
from codescan.findings import run_bandit
from codescan.injection import find_injections
from codescan.analyst import analyze_code
from codescan.synthesize import synthesize


def main():
    with throwaway_copy("dast/target") as w:
        bandit = run_bandit(w)
        injection = find_injections(w)
    analyst = analyze_code("dast/target")

    all_findings = bandit + injection + analyst
    print(f"  {len(all_findings)} raw findings from "
          f"{len(bandit)} bandit + {len(injection)} injection + {len(analyst)} analyst\n")

    for m in synthesize(all_findings):
        srcs = ", ".join(m.get("sources", []))
        print(f"[{m['severity']}] {m['title']}  ({m.get('confidence')}; via {srcs})")
        print(f"    {m.get('summary', '')}")
