"""Real Windows negative startup and lifecycle acceptance; no real node secrets."""
from __future__ import annotations
import argparse
import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import time
import traceback

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))
sys.path.insert(0, str(Path(__file__).resolve().parent))
from ruleproxy import windows_runtime as runtime
from windows_native_validation import Listener, free_port, host_info, start_core

APP = r'''
import json, os, socket, subprocess, sys, time
from pathlib import Path
profile=Path(sys.argv[1])
child=subprocess.Popen([sys.executable,'-I','-S','-c','import time; time.sleep(120)'])
pending=profile/'started.pending'
pending.write_text(json.dumps({'app':os.getpid(),'child':child.pid}),encoding='ascii')
os.replace(pending,profile/'started.json')
while not (profile/'core-dead').is_file(): time.sleep(.05)
try:
    with socket.create_connection(('1.1.1.1',443),timeout=2): pass
    value={'connected':True}
except OSError as error:
    value={'connected':False,'winerror':getattr(error,'winerror',None)}
pending=profile/'after-core-death.pending'
pending.write_text(json.dumps(value),encoding='ascii')
os.replace(pending,profile/'after-core-death.json')
time.sleep(120)
'''


def wait_file(path, process, seconds=15):
    deadline=time.monotonic()+seconds
    while time.monotonic()<deadline:
        if path.is_file(): return json.loads(path.read_text(encoding='ascii'))
        if process.poll() is not None: break
        time.sleep(.05)
    raise RuntimeError('Application did not produce '+path.name)


def main():
    parser=argparse.ArgumentParser(); parser.add_argument('--output',type=Path,required=True)
    args=parser.parse_args(); args.output.mkdir(parents=True,exist_ok=True)
    report={'host':host_info(),'mocked':False}; code=1
    executable=ROOT/'bin/windows-amd64/wxc-exec.exe'
    sentinel=None
    try:
        report['probe']=runtime.probe(str(executable))
        if not report['probe']['supported']:
            report['verdict']='unsupported-host-refused'; code=0; return code
        with tempfile.TemporaryDirectory(prefix='故障验收 ',ignore_cleanup_errors=True) as temporary:
            folder=Path(temporary)
            sentinel=subprocess.Popen([sys.executable,'-I','-S','-c','import time;time.sleep(180)'])
            fake=Listener(b'bad-proxy')
            profile=folder/'bad-proxy'; profile.mkdir()
            marker=profile/'marker'
            command=[sys.executable,'-I','-S','-c',"from pathlib import Path;import sys;Path(sys.argv[1]).write_text('unsafe')",str(marker)]
            try:
                try:
                    process,resource=runtime.launch(command,{},profile,fake.port,str(executable))
                except runtime.UnsupportedRuntimeError as error:
                    report['bad_proxy']={'refused':True,'app_started':marker.exists(),'error':str(error)}
                else:
                    runtime.stop(process);resource.close()
                    raise RuntimeError('Broken proxy was accepted')
                if marker.exists(): raise RuntimeError('Application ran before a successful proxy check')
            finally: fake.close()
            lifecycle=[]
            for mode in ('normal-stop','wrapper-crash','core-crash'):
                case=folder/mode;case.mkdir()
                core,log=start_core(case,free_port())
                # The mixed port is read from the fixture configuration itself.
                proxy=int((case/'mihomo.yaml').read_text().splitlines()[0].split(':')[1])
                profile=case/'app';profile.mkdir()
                script=profile/'application.py';script.write_text(APP,encoding='ascii')
                process=resource=None;handles=[]
                api=runtime._WinProcessApi()
                try:
                    process,resource=runtime.launch([sys.executable,'-I','-S',str(script),str(profile)],{},profile,proxy,str(executable),proxy_process=core)
                    pids=wait_file(profile/'started.json',process)
                    for pid in pids.values():
                        handle=api.kernel32.OpenProcess(api.SYNCHRONIZE|api.PROCESS_QUERY_LIMITED_INFORMATION,False,pid)
                        if not handle: raise RuntimeError('Could not retain a workload process handle')
                        handles.append(handle)
                    item={'mode':mode,'pids':pids}
                    if mode=='wrapper-crash':
                        # Deliberate fault injection into this test's own runtime,
                        # never an operation exposed by the production launcher.
                        process.kill();process.wait(10)
                    elif mode=='core-crash':
                        core.kill();core.wait(10)
                        (profile/'core-dead').write_text('probe',encoding='ascii')
                        value=wait_file(profile/'after-core-death.json',process)
                        item['after_core_death']=value
                        if value.get('winerror')!=10013: raise RuntimeError('Direct egress was not denied after proxy failure')
                        runtime.stop(process)
                    else: runtime.stop(process)
                    item['all_descendants_exited']=all(api.wait(handle,3000) for handle in handles)
                    item['unrelated_host_process_alive']=sentinel.poll() is None
                    if not item['all_descendants_exited'] or not item['unrelated_host_process_alive']:
                        raise RuntimeError('Lifecycle acceptance failed: '+json.dumps(item))
                    lifecycle.append(item)
                finally:
                    for handle in handles: api.close(handle)
                    if process is not None: runtime.stop(process)
                    if resource is not None: resource.close()
                    if core.poll() is None: core.terminate();core.wait(10)
                    log.close()
            report['lifecycle']=lifecycle
            report['verdict']='negative-startup-and-lifecycle-pass';code=0
    except Exception: report['error']=traceback.format_exc()
    finally:
        if sentinel is not None: sentinel.terminate();sentinel.wait(10)
        (args.output/'fault-report.json').write_text(json.dumps(report,ensure_ascii=False,indent=2),encoding='utf-8')
        print(json.dumps(report,ensure_ascii=True,indent=2),flush=True)
    return code

if __name__=='__main__':
    for stream in (sys.stdout,sys.stderr):
        if stream is not None and hasattr(stream,'reconfigure'):stream.reconfigure(encoding='utf-8',errors='replace')
    raise SystemExit(main())
