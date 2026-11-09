"""Unpack a bounded data-only local source bundle, then run the scanner."""
import os
import shutil
import sys
import tarfile
import tempfile
import socket
import time
from pathlib import Path, PurePosixPath

MAX_SOURCE_BYTES = 128 * 1024 * 1024
MAX_FILES = 10000


def wait_for_isolation():
    """Do not read hostile input during an asynchronous policy-controller rollout."""
    for _ in range(15):
        reachable = False
        for address in [('1.1.1.1', 443), ('kubernetes.default.svc', 443)]:
            try:
                connection = socket.create_connection(address, timeout=1)
            except OSError:
                continue
            connection.close()
            reachable = True
        if not reachable:
            return
        time.sleep(2)
    raise RuntimeError('Direct egress is still possible; refusing to read scan input')


def unpack(bundle, destination):
    """Reject links, special files and traversal; never restore ownership/modes."""
    total = 0
    with tarfile.open(bundle, "r:gz") as archive:
        for count, member in enumerate(archive, 1):
            name = PurePosixPath(member.name)
            if (count > MAX_FILES or name.is_absolute() or ".." in name.parts
                    or not name.parts or not member.isfile()):
                raise ValueError("invalid source bundle member")
            total += member.size
            if total > MAX_SOURCE_BYTES:
                raise ValueError("source bundle exceeds 128 MiB")
            target = Path(destination).joinpath(*name.parts)
            target.parent.mkdir(parents=True, exist_ok=True)
            with archive.extractfile(member) as source, target.open("xb") as output:
                shutil.copyfileobj(source, output)


def main():
    # This runs before importing the pipeline or unpacking/cloning any source.
    wait_for_isolation()
    import pipeline
    bundle = os.environ.get("SCAN_BUNDLE")
    if bundle:
        with tempfile.TemporaryDirectory(prefix="input-") as directory:
            unpack(bundle, directory)
            sys.argv = ["pipeline.py", directory]
            pipeline.main()
    else:
        pipeline.main()


if __name__ == "__main__":
    main()
