"""codescan — scan any repo and print a unified report.

Static (inside the scanner Job): Semgrep + injection scan.
Agentic analyst (contained pod, over HTTP): code reasoning + dependency CVEs.
Dynamic (optional): if DAST_REPORT points to a ZAP JSON report, its findings
fold into the same synthesis. Everything merged by synthesis + authority backstop.
"""
import os, sys, subprocess, tempfile, shutil, json
from contextlib import contextmanager
from codescan.workspace import throwaway_copy
from codescan.semgrep_scan import run_semgrep
from codescan.injection import find_injections
from codescan.analyst_client import analyze_via_agent
from codescan.zap_report import dast_findings
from codescan.synthesize import synthesize


@contextmanager
def fetch(source):
    is_url = source.startswith(("http://", "https://", "git@")) or source.endswith(".git")
    if not is_url:
        yield source
        return
    d = tempfile.mkdtemp(prefix="repo-")
    try:
        print(f"cloning {source} ...")
        subprocess.run(["git", "clone", "--depth", "1", source, d],
                       check=True, capture_output=True, text=True)
        yield d
    finally:
        shutil.rmtree(d, ignore_errors=True)


def scan(path):
    with throwaway_copy(path) as work:
        semgrep_findings = run_semgrep(work)
        injection_findings = find_injections(work)
        findings = semgrep_findings + injection_findings
        findings += analyze_via_agent(work, injection_flags=injection_findings)
    dast_report = os.environ.get("DAST_REPORT")
    if dast_report:
        findings += dast_findings(dast_report)      # fold in dynamic findings
    return synthesize(findings)


def main():
    if len(sys.argv) < 2:
        print("usage: python pipeline.py <repo-url-or-path>")
        return
    with fetch(sys.argv[1]) as path:
        print(f"scanning {path} ...\n")
        results = scan(path)
        if not results:
            print("no findings — clean, or no supported source files.")
        # One escaped JSON record; human rendering happens in the trusted runner.
        print('CODESCAN_REPORT=' + json.dumps({'schema_version': 1, 'findings': results}, ensure_ascii=True))


if __name__ == "__main__":
    main()
