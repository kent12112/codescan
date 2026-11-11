"""Real mutual-TLS integration with synthetic provider credentials and no model API calls."""
import json
import os
from pathlib import Path
import socket
import ssl
import subprocess
import sys
import tempfile
import time
import urllib.request
import urllib.error

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))


def port():
    with socket.socket() as connection:
        connection.bind(('127.0.0.1', 0))
        return connection.getsockname()[1]


def main():
    with tempfile.TemporaryDirectory(prefix='codescan-team-test-') as directory:
        root = Path(directory)
        subprocess.run([sys.executable, str(ROOT/'tools/provision_identity.py'), str(root)], check=True)
        (root/'provider-key').write_text('synthetic-provider-key-not-real')
        (root/'fixture.py').write_text('''
import os, json, httpx
from pathlib import Path
from service.gateway import create_app
from service.analyst import create_app as agent_app
from service.quota import Quota
from service.gateway_policy import MODEL

def upstream(request):
    assert str(request.url) == 'https://api.anthropic.com/v1/messages'
    assert request.headers['x-api-key'] == 'synthetic-provider-key-not-real'
    assert 'authorization' not in request.headers
    return httpx.Response(200, json={'id':'msg_test', 'type':'message', 'role':'assistant',
      'model':MODEL, 'content':[{'type':'text','text':'[]'}], 'stop_reason':'end_turn',
      'stop_sequence':None, 'usage':{'input_tokens':1,'output_tokens':1}})

gateway = create_app(upstream=httpx.Client(transport=httpx.MockTransport(upstream)),
    quota=Quota(os.environ['QUOTA_DB'], daily=2), key_file=os.environ['ANTHROPIC_KEY_FILE'])
agent = agent_app(lambda code,*args: 'malformed' if code == 'malformed' else '[]', lambda _: '[]')
''')
        processes, logs = [], []
        def start(role, app, number):
            log=(root/(role+'.log')).open('a+'); logs.append(log)
            env={**os.environ, 'PYTHONPATH': str(ROOT)+os.pathsep+str(root),
                 'SERVICE_BIND': '127.0.0.1:'+str(number),
                 'TLS_CERT_FILE': str(root/role/'tls.crt'), 'TLS_KEY_FILE': str(root/role/'tls.key'),
                 'TLS_CA_FILE': str(root/'ca.crt'), 'QUOTA_DB': str(root/'quota.sqlite'),
                 'ANTHROPIC_KEY_FILE': str(root/'provider-key')}
            env.pop('ANTHROPIC_API_KEY', None)
            process=subprocess.Popen([str(Path(sys.executable).with_name('gunicorn')),
                '-c', str(ROOT/'service/gunicorn_config.py'), 'fixture:'+app], env=env,
                stdout=log, stderr=subprocess.STDOUT)
            processes.append(process)
            deadline=time.monotonic()+20
            while time.monotonic()<deadline:
                if process.poll() is not None:
                    raise RuntimeError('test service exited')
                try:
                    with socket.create_connection(('127.0.0.1',number), timeout=1):
                        return process
                except OSError:
                    time.sleep(.1)
            raise TimeoutError('test service startup')
        def context(role=None):
            ctx=ssl.create_default_context(cafile=str(root/'ca.crt'))
            if role:
                ctx.load_cert_chain(str(root/role/'tls.crt'),str(root/role/'tls.key'))
            return ctx
        def call(number, path, data=None, role='scanner', extra=None):
            opener=urllib.request.build_opener(urllib.request.ProxyHandler({}),
                urllib.request.HTTPSHandler(context=context(role)))
            body=json.dumps(data).encode() if data is not None else None
            request=urllib.request.Request(f'https://127.0.0.1:{number}'+path, data=body,
                headers={'Content-Type':'application/json', **(extra or {})})
            try:
                with opener.open(request,timeout=5) as response:
                    return response.status, json.loads(response.read())
            except urllib.error.HTTPError as error:
                return error.code, json.loads(error.read())
        def stop(process):
            if process.poll() is None:
                process.terminate(); process.wait(timeout=10)
        gateway_port, agent_port=port(),port()
        try:
            gateway=start('gateway','gateway',gateway_port)
            start('analyst','agent',agent_port)
            assert call(gateway_port, '/healthz')[0] == 200
            try:
                call(gateway_port,'/healthz', role=None)
                raise AssertionError('missing client certificate accepted')
            except (urllib.error.URLError, ssl.SSLError, ConnectionError):
                pass
            print('PASS: TLS rejects clients without a certificate',flush=True)
            assert call(agent_port,'/analyze',{'code':'test'},role='analyst',extra={'X-Forwarded-Client-Cert':'scanner'})[0]==403
            assert call(agent_port,'/analyze',{'code':'test'}) == (200, {'findings':[]})
            assert call(agent_port,'/analyze',{'code':'malformed'})[0]==502
            print('PASS: analyst API authenticates scanner identity and fails malformed output',flush=True)
            from service.gateway_policy import MODEL
            payload={'model':MODEL,'max_tokens':128,'messages':[{'role':'user','content':'synthetic test'}]}
            assert call(gateway_port,'/v1/messages',{**payload,'model':'not-allowed'})[0]==400
            previous={key:os.environ.get(key) for key in ['LLM_GATEWAY_URL','WORKLOAD_TLS_DIR','ANTHROPIC_API_KEY']}
            try:
                os.environ['LLM_GATEWAY_URL']=f'https://127.0.0.1:{gateway_port}'
                os.environ['WORKLOAD_TLS_DIR']=str(root/'scanner')
                os.environ.pop('ANTHROPIC_API_KEY',None)
                from codescan.llm_client import make_client
                with make_client() as client:
                    response=client.messages.create(**payload)
                    assert response.content[0].text=='[]'
            finally:
                for key,value in previous.items():
                    if value is None: os.environ.pop(key,None)
                    else: os.environ[key]=value
            print('PASS: real Anthropic SDK uses mTLS gateway; only synthetic provider key reaches stub',flush=True)
            assert call(gateway_port,'/v1/messages',payload,extra={'x-api-key':'attacker-key'})[0]==200
            assert call(gateway_port,'/v1/messages',payload)[0]==429
            stop(gateway)
            gateway=start('gateway','gateway',gateway_port)
            assert call(gateway_port,'/v1/messages',payload)[0]==429
            print('PASS: quota survives service restart and cannot be bypassed by client credentials',flush=True)
        except BaseException:
            for log in logs:
                log.seek(0); print(log.read())
            raise
        finally:
            for process in processes:
                stop(process)
            for log in logs:
                log.close()


if __name__=='__main__':
    main()
