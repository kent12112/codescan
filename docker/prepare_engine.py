"""Build-only rule validation and metadata extraction; never run on hostile repos."""
import hashlib
import json
from pathlib import Path
import subprocess
import urllib.request
from ruamel.yaml import YAML

root=Path('/opt/rules'); root.mkdir(parents=True,exist_ok=True)
with urllib.request.urlopen('https://semgrep.dev/c/p/default',timeout=30) as response:
    data=response.read(32*1024*1024+1)
if len(data)>32*1024*1024: raise ValueError('rule snapshot too large')
(root/'default.yaml').write_bytes(data)
subprocess.run(['semgrep','scan','--validate','--config',str(root/'default.yaml'),'--metrics=off'],check=True)
rules=YAML(typ='safe').load(data)['rules']
(root/'rule-info.json').write_text(json.dumps({rule['id']:{'severity':rule['severity'],'message':rule['message']} for rule in rules}))
(root/'SHA256SUMS').write_text(hashlib.sha256(data).hexdigest()+'  default.yaml\n')
(root/'engine-version').write_text('1.184.0\n')
