"""Eval: per-class P/R/F1, a Semgrep (rules) baseline, and an LLM consistency check."""
import json, tempfile, shutil, sys
from pathlib import Path
from collections import defaultdict
from benchmark.baseline_analyst import analyze_code
from codescan.semgrep_scan import run_semgrep

SAMPLES = Path("benchmark/samples")
LABELS = json.load(open("benchmark/labels.json"))

TAG_KEYWORDS = {
    "command-injection":     ["command injection", "os command", "shell command", "shell=true"],
    "sql-injection":         ["sql injection", "sqli", "tainted sql", "sql statement"],
    "code-injection":        ["code injection", "eval(", "eval()", "use of eval", "exec("],
    "deserialization":       ["deserializ", "pickle"],
    "broken-access-control": ["access control", "authoriz", "x-admin", "client header", "client-supplied"],
    "idor":                  ["idor", "insecure direct object", "object reference", "ownership"],
}


def _tags(findings):
    out = set()
    for f in findings:
        text = (f.get("title", "") + " " + f.get("message", "")).lower()
        for tag, kws in TAG_KEYWORDS.items():
            if any(k in text for k in kws):
                out.add(tag)
    return out


def _analyst_one(path):
    d = tempfile.mkdtemp()
    try:
        shutil.copy(path, Path(d) / path.name)
        return _tags(analyze_code(str(d)))
    finally:
        shutil.rmtree(d, ignore_errors=True)


def semgrep_by_file():
    by_file = defaultdict(list)
    for f in run_semgrep(SAMPLES):          # ONE pass over all samples
        by_file[f.get("file")].append(f)
    return {fn: _tags(by_file.get(fn, [])) for fn in LABELS}


def analyst_by_file():
    return {fn: _analyst_one(SAMPLES / fn) for fn in LABELS}


def score(tags_by_file):
    classes = sorted(TAG_KEYWORDS)
    tp = defaultdict(int); fp = defaultdict(int); fn = defaultdict(int); diffs = []
    for fname, expected in LABELS.items():
        expected = set(expected); detected = tags_by_file.get(fname, set())
        for c in classes:
            if c in expected and c in detected: tp[c] += 1
            elif c in expected: fn[c] += 1
            elif c in detected: fp[c] += 1
        if detected != expected:
            diffs.append((fname, expected, detected))
    TP, FP, FN = sum(tp.values()), sum(fp.values()), sum(fn.values())
    P = TP / (TP + FP) if TP + FP else 0.0
    R = TP / (TP + FN) if TP + FN else 0.0
    F1 = 2 * P * R / (P + R) if P + R else 0.0
    return P, R, F1, TP, FP, FN, diffs


def show(name, tags_by_file):
    P, R, F1, TP, FP, FN, diffs = score(tags_by_file)
    print(f"\n### {name}")
    print(f"    precision={P:.2f}  recall={R:.2f}  f1={F1:.2f}   (TP={TP} FP={FP} FN={FN})")
    for fname, exp, det in diffs:
        kind = "FN (missed)" if exp - det else "FP (over-flag)"
        print(f"    {kind:14} {fname:20} exp={sorted(exp) or ['safe']} got={sorted(det) or ['none']}")


def consistency(runs=3):
    print(f"\n### consistency — analyst, {runs} runs")
    vuln = {f: set(t) for f, t in LABELS.items() if t}
    hits = defaultdict(int)
    for _ in range(runs):
        for fname, expected in vuln.items():
            det = _analyst_one(SAMPLES / fname)
            for tag in expected:
                hits[(fname, tag)] += (tag in det)
    for fname, expected in vuln.items():
        for tag in expected:
            n = hits[(fname, tag)]
            print(f"    {fname:20} {tag:22} [{'#'*n}{'.'*(runs-n)}] {n}/{runs}")


def main():
    if len(sys.argv) > 1 and sys.argv[1] == "consistency":
        consistency(3)
    else:
        print("running semgrep (one pass)...")
        show("Semgrep (rules only)", semgrep_by_file())
        print("\nrunning analyst (per file, ~8 calls)...")
        show("LLM analyst", analyst_by_file())


if __name__ == "__main__":
    main()
