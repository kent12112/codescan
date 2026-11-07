"""Copy a target repo into a throwaway workspace so scanning never touches the original."""
import shutil
import tempfile
from pathlib import Path
from contextlib import contextmanager

# code file types the scanner reads — the LLM analyst is language-agnostic
CODE_EXTS = {".py", ".js", ".jsx", ".ts", ".tsx", ".go", ".java", ".rb", ".php",
             ".c", ".cc", ".cpp", ".h", ".hpp", ".cs", ".rs", ".kt", ".swift", ".scala"}
SKIP = {".git", ".venv", "venv", "__pycache__", "node_modules", "dist", "build", ".next", "vendor"}


@contextmanager
def throwaway_copy(source: str):
    """Copy `source` into a fresh temp dir, yield its path, delete it afterwards."""
    src = Path(source).resolve()
    work = Path(tempfile.mkdtemp(prefix="codescan-"))
    try:
        dest = work / src.name
        shutil.copytree(src, dest)
        yield dest
    finally:
        shutil.rmtree(work, ignore_errors=True)


def source_files(root: Path, exts=CODE_EXTS):
    """All source files under root across supported languages (skipping junk dirs)."""
    for p in sorted(root.rglob("*")):
        if p.is_file() and p.suffix.lower() in exts and not any(part in SKIP for part in p.parts):
            yield p
