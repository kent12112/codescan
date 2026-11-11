"""Pin local k3s manifests to the built/imported immutable image contents."""
import re
import subprocess
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
TAGS={'scanner':'team-v1','agent':'team-v1','gateway':'team-v1','proxy':'team-v1'}


def main():
    output=subprocess.run(['sudo','k3s','ctr','images','ls'],check=True,capture_output=True,text=True).stdout
    images={fields[0]:fields[2] for line in output.splitlines() if len(fields:=line.split())>=3 and fields[2].startswith('sha256:')}
    replacements={}
    for name,tag in TAGS.items():
        repository='docker.io/library/codescan-'+name
        source=repository+':'+tag
        digest=images.get(source)
        if not digest or not re.fullmatch(r'sha256:[a-f0-9]{64}',digest):
            raise RuntimeError('build and import image first: '+source)
        target=repository+'@'+digest
        if target not in images:
            subprocess.run(['sudo','k3s','ctr','images','tag',source,target],check=True,capture_output=True)
        replacements[repository]=target
    pattern=re.compile(r'docker\.io/library/codescan-(?:scanner|agent|gateway|proxy)(?::[A-Za-z0-9_.-]+|@sha256:[a-f0-9]{64})')
    for path in (ROOT/'k8s').glob('*.yaml'):
        text=path.read_text()
        updated=pattern.sub(lambda match: replacements[match.group().split('@')[0].split(':')[0]],text)
        if updated!=text:
            path.write_text(updated)
    print('Manifests pinned to imported content digests.')


if __name__=='__main__':
    main()
