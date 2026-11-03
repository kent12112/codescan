"""Copy a target repo into a throwaway workspace so scanning never touches the original."""
import shutil
import tempfile
from pathlib import Path
from contextlib import contextmanager


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


def source_files(root: Path, suffix=".py"):
    """All source files under root (skipping virtualenvs, .git, caches)."""
    skip = {".git", ".venv", "__pycache__", "node_modules"}
    for p in sorted(root.rglob(f"*{suffix}")):
        if not any(part in skip for part in p.parts):
            yield p
