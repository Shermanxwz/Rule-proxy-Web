"""Controlled browser compatibility diagnosis, with proxy policy unchanged."""
import http.server
import json
import os
from pathlib import Path
import secrets
import subprocess
import sys
import tempfile
import threading
import traceback

ROOT=Path(__file__).resolve().parent.parent
sys.path.insert(0,str(ROOT));sys.path.insert(0,str(Path(__file__).resolve().parent))
from ruleproxy import windows_runtime as runtime
from ruleproxy.launcher import prepare_app
from windows_native_validation import free_port,start_core,host_info


def main():
    output=Path('native-results');output.mkdir(exist_ok=True)
    report={'host':host_info(),'cases':[]};nonce=secrets.token_hex(10);requests=[]
    class Handler(http.server.BaseHTTPRequestHandler):
        def log_message(self,*args):pass
        def do_GET(self):
            requests.append(self.path)
            body=('<html><body>'+nonce+'</body></html>').encode()
            self.send_response(200);self.send_header('Content-Length',str(len(body)));self.end_headers();self.wfile.write(body)
    server=http.server.ThreadingHTTPServer(('127.0.0.1',0),Handler)
    worker=threading.Thread(target=server.serve_forever,daemon=True);worker.start()
    try:
        edge=Path(os.environ['ProgramFiles(x86)'])/'Microsoft/Edge/Application/msedge.exe'
        executable=ROOT/'bin/windows-amd64/wxc-exec.exe'
        with tempfile.TemporaryDirectory(prefix='browser-diagnosis-',ignore_cleanup_errors=True) as temporary:
            folder=Path(temporary);proxy=free_port();core,log=start_core(folder,proxy)
            try:
                cases=[('host','container',[],False),('container','container',[],False),
                       ('desktop','desktop',[],False),('windows-files','container',[],True),
                       ('renderer-feature','container',['--disable-features=RendererAppContainer'],False),
                       ('network-feature','container',['--disable-features=NetworkServiceSandbox'],False),
                       ('crashpad','container',['--disable-breakpad'],False)]
                for name,ui,flags,windows_files in cases:
                    profile=folder/name;profile.mkdir()
                    url=f'http://127.0.0.1:{server.server_port}/{name}'
                    command,env,_=prepare_app({'id':name,'label':'Diagnosis','path':str(edge),'adapter':'chromium',
                                             'args':['--headless=new','--disable-gpu','--dump-dom',*flags,url]},proxy,folder)
                    path=profile/'output.log';stream=path.open('wb');process=None
                    entry={'name':name,'ui':ui,'flags':flags}
                    try:
                        if name=='host':
                            process=subprocess.Popen(command,env=runtime._profile_environment(env,profile),stdout=stream,stderr=subprocess.STDOUT)
                        else:
                            policy=runtime.build_policy(command,env,profile,proxy)
                            policy['process']['commandLine']=subprocess.list2cmdline(command)
                            policy['processContainer']['ui']['isolation']=ui
                            if windows_files:policy['filesystem']['readonlyPaths'].append(os.environ['WINDIR'])
                            config=profile/'policy.json';config.write_text(json.dumps(policy),encoding='ascii')
                            runtime._probe_request(executable,policy)
                            process=subprocess.Popen([str(executable),'--config',str(config)],stdout=stream,stderr=subprocess.STDOUT)
                        try:entry['exit']=process.wait(25)
                        except subprocess.TimeoutExpired:
                            entry['timeout']=True
                            if name=='host':process.terminate();process.wait(10)
                            else:runtime.stop(process)
                    except Exception:entry['error']=traceback.format_exc()
                    finally:
                        if process is not None and process.poll() is None:
                            if name=='host':process.terminate();process.wait(10)
                            else:runtime.stop(process)
                        stream.close()
                    text=path.read_text(encoding='utf-8',errors='replace')
                    entry.update(rendered=nonce in text,requested='/'+name in requests,log_tail=text[-4000:])
                    report['cases'].append(entry)
            finally:core.terminate();core.wait(10);log.close()
    except Exception:report['error']=traceback.format_exc()
    finally:
        server.shutdown();server.server_close();worker.join(2)
        (output/'browser-diagnosis.json').write_text(json.dumps(report,ensure_ascii=False,indent=2),encoding='utf-8')
        print(json.dumps(report,ensure_ascii=True,indent=2),flush=True)
    return 0 if 'error' not in report else 1
if __name__=='__main__':raise SystemExit(main())
