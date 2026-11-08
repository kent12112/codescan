"""codescan — scan any repo (URL or local path) and print a unified report.

Deterministic layer (local, sandboxed): Semgrep + injection scan (run once).
Agentic analyst (contained pod, over HTTP): reasons over the code AND looks up
dependency CVEs with a tool. Synthesis + authority backstop merge everything.
"""
import sys, subprocess, tempfile, shutil
from contextlib import contextmanager
from codescan.workspace import throwaway_copy
from codescan.semgrep_scan import run_semgrep
from codescan.injection import find_injections
from codescan.cve_client import analyze_via_agent
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
        injection_findings = find_injections(work)        # run ONCE
    findings = semgrep_findings + injection_findings
    findings += analyze_via_agent(path, injection_flags=injection_findings)  # reuse
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
        for m in results:
            srcs = ", ".join(m.get("sources", []))
            flag = "  [recovered by authority]" if m.get("recovered_by_authority") else ""
            print(f"[{m['severity']}] {m['title']}  ({m.get('confidence')}; via {srcs}){flag}")
            print(f"    {m.get('summary', '')}")


if __name__ == "__main__":
    main()
