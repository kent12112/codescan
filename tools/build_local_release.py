"""Build, audit and import a local release; only then pin Kubernetes manifests."""
import argparse
from pathlib import Path
import subprocess
import tempfile
import sys

ROOT=Path(__file__).resolve().parents[1]
TAGS={name:'team-v1' for name in ['proxy','gateway','agent','scanner','identity']}
BOOTSTRAP={
    'gateway': 'COPY requirements-service.txt /tmp/runtime.lock\nRUN pip install --no-cache-dir -r /tmp/runtime.lock',
    'proxy': 'COPY requirements-service.txt /tmp/runtime.lock\nRUN pip install --no-cache-dir -r /tmp/runtime.lock',
    'agent': 'COPY requirements-service.txt /tmp/runtime.lock\nRUN pip install --no-cache-dir -r /tmp/runtime.lock anthropic==0.125.0',
    'scanner': 'COPY requirements.txt /tmp/runtime.lock\nRUN pip install --no-cache-dir -r /tmp/runtime.lock',
    'identity': 'RUN pip install --no-cache-dir cryptography==50.0.2',
}


def run(*args,**kwargs):
    return subprocess.run(args,check=True,cwd=ROOT,**kwargs)


def build(refresh=False):
    for name,tag in TAGS.items():
        source=(ROOT/'docker'/('Dockerfile.'+name)).read_text()
        with tempfile.NamedTemporaryFile('w',prefix='codescan-build-',suffix='.Dockerfile') as temporary:
            if refresh:
                marker='COPY dependencies/'+name+'.lock /tmp/runtime.lock\nRUN pip install --no-cache-dir --require-hashes -r /tmp/runtime.lock'
                if marker not in source:
                    raise RuntimeError('unsupported bootstrap Dockerfile: '+name)
                source=source.replace(marker,BOOTSTRAP[name],1)
            temporary.write(source); temporary.flush()
            run('docker','build','-f',temporary.name,'-t','codescan-'+name+':'+tag,'.')


def main():
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--refresh-locks',action='store_true')
    args=parser.parse_args()
    if args.refresh_locks:
        build(refresh=True)
        run(sys.executable,'tools/lock_dependencies.py')
    build()
    run('docker','run','--rm','--network','none','--read-only','--cap-drop','ALL',
        '--tmpfs','/tmp','-v',str(ROOT/'dast/target')+':/target:ro',
        '-v',str(ROOT/'tools/verify_native_image.py')+':/verify_native_image.py:ro',
        '--entrypoint','python','codescan-scanner:team-v1','/verify_native_image.py')
    run('docker','build','-f','docker/Dockerfile.audit','-t','codescan-auditor:local','.')
    run('docker','run','--rm','--read-only','--cap-drop','ALL','--security-opt','no-new-privileges',
        '--tmpfs','/tmp','-v',str(ROOT/'dependencies')+':/locks:ro','codescan-auditor:local')
    # Existing deployments use immutable content references; failed builds/audits
    # never change their references or import replacement tags into Kubernetes.
    with tempfile.TemporaryDirectory(prefix='codescan-images-') as directory:
        path=Path(directory)/'release.tar'
        run('docker','save','-o',str(path),*[f'codescan-{name}:{tag}' for name,tag in TAGS.items()])
        run('sudo','k3s','ctr','images','import',str(path))
    run(sys.executable,'tools/pin_local_images.py')
    print('Release built, dependency-audited and pinned. Run tools/enable_team.sh to deploy.')


if __name__=='__main__':
    main()
