"""Lock the tested Linux image dependency graph to PyPI artifact SHA-256 hashes."""
import concurrent.futures
import json
from pathlib import Path
import re
import subprocess
import urllib.parse
import urllib.request

IMAGES={'scanner':'team-v1','agent':'team-v1','gateway':'team-v1','proxy':'team-v1','identity':'team-v1'}
ROOT=Path(__file__).resolve().parents[1]


def package_hashes(pair):
    name,version=pair
    url='https://pypi.org/pypi/'+urllib.parse.quote(name,safe='')+'/'+urllib.parse.quote(version,safe='')+'/json'
    with urllib.request.urlopen(url,timeout=30) as response:
        raw=response.read(4*1024*1024+1)
    if len(raw)>4*1024*1024:
        raise ValueError('oversized package metadata')
    data=json.loads(raw)
    hashes=sorted({entry['digests']['sha256'] for entry in data['urls']
                   if entry.get('packagetype') in {'sdist','bdist_wheel'}})
    if not hashes or any(not re.fullmatch('[a-f0-9]{64}',value) for value in hashes):
        raise ValueError('missing package hashes: '+name)
    return name+'=='+version+' \\\n'+ ' \\\n'.join('    --hash=sha256:'+value for value in hashes)+'\n'


def main():
    graphs={}
    for name,tag in IMAGES.items():
        result=subprocess.run(['docker','run','--rm','--network','none','--entrypoint','python',
            'codescan-'+name+':'+tag,'-m','pip','freeze','--all'],check=True,capture_output=True,text=True)
        pairs=[]
        for line in result.stdout.splitlines():
            if not line or line.startswith('pip=='):
                continue
            if not re.fullmatch(r'[A-Za-z0-9._-]+==[A-Za-z0-9+.!_-]+',line):
                raise ValueError('unsupported dependency source in '+name)
            pairs.append(tuple(line.split('==',1)))
        graphs[name]=sorted(pairs,key=lambda pair:pair[0].lower())
    unique=sorted(set(pair for graph in graphs.values() for pair in graph))
    with concurrent.futures.ThreadPoolExecutor(max_workers=4) as pool:
        contents=dict(zip(unique,pool.map(package_hashes,unique)))
    directory=ROOT/'dependencies'
    directory.mkdir(exist_ok=True)
    for name,pairs in graphs.items():
        (directory/(name+'.lock')).write_text('# Tested Linux/Python 3.12 image graph; regenerate with tools/lock_dependencies.py\n'+''.join(contents[pair] for pair in pairs))
    print('Wrote runtime hash-locked runtime dependency graphs.')


if __name__=='__main__':
    main()
