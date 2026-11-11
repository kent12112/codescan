"""Pinned Semgrep native-engine adapter; no Python CLI/telemetry in runtime."""
import json
import os
from pathlib import Path
import subprocess
import tempfile
from codescan.workspace import SKIP

LANGUAGES={
    '.py':'python','.js':'javascript','.jsx':'javascript','.ts':'typescript','.tsx':'typescript',
    '.go':'go','.java':'java','.rb':'ruby','.php':'php','.c':'c','.h':'c','.cc':'cpp','.cpp':'cpp',
    '.hpp':'cpp','.cs':'csharp','.rs':'rust','.kt':'kotlin','.swift':'swift','.scala':'scala',
    '.sh':'bash','.bash':'bash','.json':'json','.yaml':'yaml','.yml':'yaml','.html':'html',
    '.htm':'html','.tf':'terraform','.vue':'vue','.xml':'xml','.sol':'solidity'}


def targets(root):
    root=Path(root).resolve()
    result=[]
    for directory,dirs,files in os.walk(root,followlinks=False):
        dirs[:]=sorted(name for name in dirs if name not in SKIP and not Path(directory,name).is_symlink())
        for name in sorted(files):
            path=Path(directory,name)
            if path.is_symlink() or not path.is_file(): continue
            language='dockerfile' if name.lower().startswith('dockerfile') else LANGUAGES.get(path.suffix.lower())
            if path.stat().st_size>1024*1024:
                raise RuntimeError('Semgrep input file exceeds the supported 1 MiB limit')
            with path.open('rb') as source:
                binary=b'\0' in source.read(8192)
            if binary:
                if language: raise RuntimeError('unsupported binary source encoding')
                continue
            for analyzer in dict.fromkeys(([language] if language else [])+['generic','regex']):
                result.append(['CodeTarget',{'path':{'fpath':str(path),'ppath':'/'+path.relative_to(root).as_posix()},
                                             'analyzer':analyzer,'products':['sast']}])
    return ['Targets',result]


def run(root, config, timeout=300):
    plan=targets(root)
    if not plan[1]: return {'results':[],'errors':[]}
    with tempfile.NamedTemporaryFile('w',suffix='.json',prefix='semgrep-targets-') as stream:
        json.dump(plan,stream); stream.flush()
        process=subprocess.run([os.environ.get('SEMGREP_CORE','/usr/local/bin/semgrep-core'),
            '-rules',config,'-targets',stream.name,'-json_nodots','-j','2','-timeout','10','-timeout_threshold','3'],
            capture_output=True,text=True,timeout=timeout)
    try: data=json.loads(process.stdout)
    except ValueError: raise RuntimeError('native Semgrep did not return a valid report') from None
    if process.returncode or data.get('errors'):
        raise RuntimeError('native Semgrep reported errors; scan incomplete')
    metadata_path=Path(config).with_name('rule-info.json')
    if not metadata_path.is_file():
        raise RuntimeError('native rule metadata missing')
    metadata=json.loads(metadata_path.read_text())
    for result in data.get('results',[]):
        info=metadata.get(result['check_id'])
        if info is None:
            raise RuntimeError('unrecognized native rule result')
        extra=result.setdefault('extra',{})
        extra['severity']=info['severity']
        extra.setdefault('message',info['message'])
    return data
