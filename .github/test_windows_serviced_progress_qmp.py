"""Opt-in tiny TCG firmware execution: dual-monitor advisory failure isolation.

No Windows, installation media, networking or KVM. This intentionally executes
packaged default firmware briefly via cont/stop; it is not the paused optical gate.
Malformed/timeout cases inject faults at the diagnostic recv boundary while an
actual second QMP connection exists. No claim that QEMU emits malformed JSON.
"""
import argparse
import importlib.util
import json
import os
from pathlib import Path
import shutil
import subprocess
import tempfile
import threading
import time

ROOT=Path(__file__).resolve().parents[1]
MAX_SECONDS=30

def command(binary,work):
    return [binary,'-S','-machine','q35','-accel','tcg','-m','64','-nodefaults','-nic','none',
        '-display','none','-monitor','none','-no-reboot',
        '-chardev','ringbuf,id=serialbuf,size=65536','-serial','chardev:serialbuf',
        '-chardev','ringbuf,id=progressbuf,size=65536','-serial','chardev:progressbuf',
        '-qmp',f'unix:{work / "qmp.sock"},server=on,wait=off',
        '-qmp',f'unix:{work / "diag-qmp.sock"},server=on,wait=off']

class FaultSocket:
    def __init__(self,owned,mode):self.owned=owned;self.mode=mode
    def __getattr__(self,name):return getattr(self.owned,name)
    def recv(self,maximum):
        if self.mode=='timeout':raise TimeoutError('synthetic diagnostic timeout')
        return b'{malformed\n'

def control_roundtrip(control):
    control.execute('cont')
    control.execute('stop')
    value=control.execute('query-status')
    if value.get('running') is not False:raise ValueError('authoritative stop failed')
    control.execute('ringbuf-write',{'device':'serialbuf','data':'CONTROL\n'})
    if control.execute('ringbuf-read',{'device':'serialbuf','size':65536})!='CONTROL\n':
        raise ValueError('authoritative serial altered')

def exercise(host,control,work,result):
    diagnostics=[]
    try:
        diagnostic=host.ProgressQmp(work/'diag-qmp.sock',work);diagnostics.append(diagnostic)
        payload=b'RPS2 {"v":1,"s":"system","p":"entry","m":null,"n":null,"f":null}\n'
        control.execute('ringbuf-write',{'device':'progressbuf','data':payload[:19].decode('ascii')})
        parser=host.ProgressSerial();parser.feed(diagnostic.read())
        if parser.records:raise ValueError('fragment admitted')
        control.execute('ringbuf-write',{'device':'progressbuf','data':(payload[19:]+payload).decode('ascii')})
        parser.feed(diagnostic.read())
        if parser.accepted!=2 or parser.rejected:raise ValueError('production parser mismatch')
        if control.execute('ringbuf-read',{'device':'serialbuf','size':65536})!='':raise ValueError('COM channels crossed')
        result['fragment_burst_verified']=True
        diagnostic.close();control_roundtrip(control)
        result['diagnostic_close_isolated']=True
        for mode in ('malformed','timeout'):
            diagnostic=host.ProgressQmp(work/'diag-qmp.sock',work);diagnostics.append(diagnostic)
            diagnostic.socket=FaultSocket(diagnostic.socket,mode)
            try:diagnostic.read()
            except (ValueError,TimeoutError):pass
            else:raise ValueError('diagnostic fault not rejected')
            if not diagnostic.closed or diagnostic.socket.fileno()!=-1:raise ValueError('diagnostic socket not closed')
            control_roundtrip(control)
            result[mode+'_isolated']=True
    finally:
        result['diagnostic_sockets_closed']=False
        clean=True
        for diagnostic in diagnostics:
            try:diagnostic.close()
            except Exception:clean=False
        result['diagnostic_sockets_closed']=clean and all(d.closed and d.socket.fileno()==-1 for d in diagnostics)

def cleanup_gate(result,work,process,control,watchdog,expired):
    if process is not None:
        try:
            if process.poll() is None:process.kill()
            process.wait(timeout=5);result['process_exited']=process.poll() is not None
        except Exception:pass
    else:result['process_exited']=True
    result['watchdog_stopped']=watchdog is None
    if watchdog is not None:
        try:
            watchdog.cancel();watchdog.join(timeout=1)
            result['watchdog_stopped']=not watchdog.is_alive()
        except Exception:result['watchdog_stopped']=False
    result['watchdog_expired']=expired.is_set()
    if control is not None:
        try:control.close()
        except Exception:pass
        try:control.socket.close()
        except Exception:pass
        try:result['control_closed']=getattr(getattr(control,'file',None),'closed',False) and control.socket.fileno()==-1
        except Exception:result['control_closed']=False
    else:result['control_closed']=True
    if work is not None and all(result[k] for k in ('process_exited','control_closed','diagnostic_sockets_closed','watchdog_stopped')):
        try:shutil.rmtree(work);result['work_removed']=not work.exists()
        except Exception:pass
    elif work is None:result['work_removed']=True
    result['passed']=result['passed'] and not result['watchdog_expired'] and all(result[k] for k in ('process_exited','control_closed','diagnostic_sockets_closed','work_removed','watchdog_stopped'))

def run_actual():
    result={'schema':1,'test_kind':'tiny_tcg_firmware_dual_monitor','passed':False,'runtime_acceptance':False,
        'firmware_execution_allowed':True,'failure_class':'none','process_exited':False,'control_closed':False,
        'diagnostic_sockets_closed':True,'work_removed':False,'watchdog_expired':False}
    work=process=control=watchdog=None;expired=threading.Event()
    try:
        binary=shutil.which('qemu-system-x86_64')
        if os.name!='posix' or not binary:raise RuntimeError('Linux QEMU required')
        spec=importlib.util.spec_from_file_location('progress_gate_host',ROOT/'.github/windows_identity_serviced_stage0.py')
        host=importlib.util.module_from_spec(spec);spec.loader.exec_module(host)
        media=host.load('progress_gate_media',ROOT/'.github/windows_vm_test.py')
        work=Path(tempfile.mkdtemp(prefix='ruleproxy-progress-qmp-'));work.chmod(0o700)
        process=subprocess.Popen(command(binary,work),stdin=subprocess.DEVNULL,stdout=subprocess.DEVNULL,stderr=subprocess.DEVNULL)
        def expire():
            expired.set()
            try:
                if process.poll() is None:process.kill()
            except OSError:pass
        watchdog=threading.Timer(MAX_SECONDS,expire);watchdog.start()
        until=time.monotonic()+5
        while not all((work/name).exists() for name in ('qmp.sock','diag-qmp.sock')):
            if process.poll() is not None or time.monotonic()>=until:raise TimeoutError('monitor startup')
            time.sleep(.02)
        control=media.Qmp.__new__(media.Qmp);control.__init__(work/'qmp.sock')
        version=control.execute('query-version').get('qemu',{})
        if any(type(version.get(k)) is not int or not 0<=version[k]<=65535 for k in ('major','minor','micro')):
            raise ValueError('bounded QEMU version required')
        result['qemu_version']={k:version[k] for k in ('major','minor','micro')}
        if version['major']!=8 or version['minor']!=2:raise ValueError('QEMU8.2 required')
        exercise(host,control,work,result)
        result['passed']=True
    except Exception as exc:
        kind=type(exc).__name__;result['failure_class']=kind if kind in ('ValueError','RuntimeError','TimeoutError','OSError','EOFError','BrokenPipeError') else 'other'
    finally:
        cleanup_gate(result,work,process,control,watchdog,expired)
    return result

def main(argv=None):
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--run-actual-qemu',action='store_true');parser.add_argument('--output',type=Path,required=True)
    args=parser.parse_args(argv)
    if not args.run_actual_qemu:parser.error('explicit actual QEMU opt-in required')
    result=run_actual();args.output.parent.mkdir(parents=True,exist_ok=True)
    args.output.write_text(json.dumps(result,indent=2)+'\n',encoding='ascii')
    print(json.dumps(result,sort_keys=True))
    return 0 if result['passed'] else 1
if __name__=='__main__':raise SystemExit(main())
