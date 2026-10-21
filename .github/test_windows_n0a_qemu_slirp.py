"""Opt-in paused packaged-QEMU mapped-file provenance gate; no guest execution."""
import argparse
import importlib.util
import json
from pathlib import Path
import shutil
import subprocess
import sys
import tempfile
import time

ROOT=Path(__file__).resolve().parents[1]
RETAINED_OWNERS=[]

def load(name,path):
    spec=importlib.util.spec_from_file_location(name,path)
    module=importlib.util.module_from_spec(spec); sys.modules[name]=module; spec.loader.exec_module(module)
    return module

def command(binary,root):
    return [binary,'-S','-machine','q35','-accel','tcg','-m','64','-nodefaults',
            '-display','none','-monitor','none','-serial','none','-no-reboot',
            '-qmp',f'unix:{root / "qmp.sock"},server=on,wait=off',
            '-netdev','user,id=vmnet,restrict=on,ipv6=on','-device','e1000,netdev=vmnet']

def run():
    deadline=time.monotonic()+45
    facts={'schema_version':1,'passed':False,'qemu_8_2_2':False,'paused_observed':False,
           'provenance':None,'process_exit_observed':False,'forced_kill':False,
           'control_closed':False,'work_removed':False,'cleanup_confirmed':False,
           'guest_executed':False,'packet_egress_tested':False,'failure':False}
    root=None; process=None; observer=None; control=None; owned=None; module=None
    try:
        binary=shutil.which('qemu-system-x86_64')
        if not binary: raise ValueError('missing')
        root=Path(tempfile.mkdtemp(prefix='n0a-slirp-')); root.chmod(0o700)
        old=load('slirp_existing_qmp',ROOT/'.github/test_windows_n0a_capture_qemu.py')
        module=load('slirp_provenance',ROOT/'.github/windows_n0a_qemu_slirp.py')
        owned=module.new_process_record();owned['spawn_attempted']=True
        try:
            process=subprocess.Popen(command(binary,root),stdin=subprocess.DEVNULL,stdout=subprocess.DEVNULL,stderr=subprocess.DEVNULL)
            owned['process']=process
        except Exception:
            owned['uncertain']=True
            raise
        control=old.GateQmp(); control.connect(root/'qmp.sock',min(deadline-10,time.monotonic()+5))
        version=control.execute('query-version')
        facts['qemu_8_2_2']=version.get('qemu')=={'major':8,'minor':2,'micro':2}
        state=control.execute('query-status')
        facts['paused_observed']=state.get('running') is False and state.get('status') in ('prelaunch','paused')
        if not facts['qemu_8_2_2'] or not facts['paused_observed']: raise ValueError('qemu_contract')
        observer=module.MappedQemu(process=process,expected_executable=binary,deadline=deadline-10)
        if not observer.admit() or not observer.recheck_before_stop(): raise ValueError('provenance')
        facts['passed']=True
    except Exception:
        facts['failure']=True
    finally:
        if control is not None:
            try: control.close(); facts['control_closed']=True
            except Exception: facts['failure']=True
        else: facts['control_closed']=True
        process_clean=True
        if owned is not None:
            if process is not None:
                module.observe_process(owned)
                if not owned['exit_observed']:
                    try: process.terminate()
                    except Exception: owned['uncertain']=True
                    try:
                        process.wait(timeout=max(0.0,min(5,deadline-time.monotonic())))
                        owned['exit_observed']=True
                    except subprocess.TimeoutExpired: facts['forced_kill']=True
                    except Exception: owned['uncertain']=True
                module.observe_process(owned)
                if not owned['exit_observed']: facts['forced_kill']=True
            process_clean=module.stop_process(owned,deadline)
            facts['process_exit_observed']=owned['exit_observed']
        else: facts['process_exit_observed']=True
        fd_closed=True
        if observer is not None:
            try: fd_closed=observer.close(cleanup_deadline=deadline)
            except Exception: fd_closed=False;facts['failure']=True
            try: facts['provenance']=observer.snapshot()
            except Exception: fd_closed=False;facts['failure']=True
        clean=process_clean and facts['process_exit_observed'] and facts['control_closed'] and fd_closed
        if root is not None and clean:
            try:
                # Only our fresh root and the fixed QMP socket can be removed.
                entries=list(root.iterdir())
                if any(p.name!='qmp.sock' or p.is_symlink() for p in entries): raise ValueError('unexpected_entry')
                for p in entries: p.unlink()
                root.rmdir(); facts['work_removed']=True
            except Exception: facts['failure']=True
        elif root is None: facts['work_removed']=True
        facts['cleanup_confirmed']=clean and facts['work_removed']
        if not facts['cleanup_confirmed']:
            RETAINED_OWNERS.append({'root':root,'process':process,'record':owned,'observer':observer,'control':control})
        facts['passed']=facts['passed'] and facts['cleanup_confirmed'] and not facts['failure'] and not facts['forced_kill']
    return facts

if __name__=='__main__':
    parser=argparse.ArgumentParser(); parser.add_argument('--run-actual-qemu',action='store_true'); args=parser.parse_args()
    if not args.run_actual_qemu: raise SystemExit(2)
    try: result=run(); print(json.dumps(result,sort_keys=True)); raise SystemExit(0 if result['passed'] else 1)
    except Exception: print('{"schema_version":1,"passed":false,"failure":true}'); raise SystemExit(1)
