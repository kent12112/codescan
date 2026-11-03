"""Flag prompt-injection-style text hidden in a repo BEFORE the model sees it."""
import re
import tokenize
from io import BytesIO
from pathlib import Path

# Phrases that look like instructions aimed at an AI reviewer, not normal code/docs.
SUSPICIOUS = [
    r"ignore (all |your |previous )?(instructions|prompts?)",
    r"disregard (the |all |previous )?(above|instructions|rules|findings)",
    r"you are now",
    r"system prompt",
    r"mark (this|it|the repo\w*) (as )?(safe|clean|approved)",
    r"report (this|it|the repo\w*) as (safe|clean|approved)",
    r"do not (report|mention|flag)",
    r"new instructions",
    r"act as",
]
PATTERNS = [re.compile(p, re.IGNORECASE) for p in SUSPICIOUS]


def scan_text(text: str) -> list[str]:
    """Return every suspicious phrase found in a blob of text."""
    hits = []
    for pat in PATTERNS:
        hits += [m.group(0) for m in pat.finditer(text)]
    return hits


def comments_and_strings(py_path: Path):
    """Yield (lineno, text) for each comment and string literal in a .py file."""
    try:
        toks = tokenize.tokenize(BytesIO(py_path.read_bytes()).readline)
        for tok in toks:
            if tok.type in (tokenize.COMMENT, tokenize.STRING):
                yield tok.start[0], tok.string
    except (tokenize.TokenError, SyntaxError):
        return


def find_injections(root: Path) -> list[dict]:
    findings = []
    # 1. prose files — scan the whole file
    for p in root.rglob("*"):
        if p.is_file() and p.suffix.lower() in {".md", ".txt", ".rst"}:
            for phrase in scan_text(p.read_text(errors="ignore")):
                findings.append({
                    "tool": "injection-scan", "rule": "INJ001",
                    "title": "possible prompt injection in prose",
                    "severity": "HIGH", "file": p.name, "line": None,
                    "message": f"instruction-like text: {phrase!r}",
                })
    # 2. python comments + string literals
    for p in root.rglob("*.py"):
        for lineno, text in comments_and_strings(p):
            for phrase in scan_text(text):
                findings.append({
                    "tool": "injection-scan", "rule": "INJ002",
                    "title": "possible prompt injection in comment/string",
                    "severity": "HIGH", "file": p.name, "line": lineno,
                    "message": f"instruction-like text: {phrase!r}",
                })
    return findings
