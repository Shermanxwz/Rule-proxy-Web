"""Default-off descendant UDP adapter; original Stage0 and direct UDP unchanged."""
import argparse
import ctypes
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import shutil
import subprocess
import sys
import time
ROOT=Path(__file__).resolve().parents[1]
def load(name,file):
    if name not in sys.modules:
        spec=importlib.util.spec_from_file_location(name,ROOT/'.github'/file);module=importlib.util.module_from_spec(spec);sys.modules[name]=module;spec.loader.exec_module(module)
    return sys.modules[name]
flow=load('parent_udp_guest_flow','windows_n0a_udp_parent_flow.py');engine=flow.engine()
base=load('parent_udp_guest_dependency','windows_n0a_udp_guest.py')
CONFIG_KEYS={'enabled','case_nonce','runner_port','parent_sha256','parent_manifest_sha256','parent_source_sha256','child_sha256','child_manifest_sha256','child_source_sha256','identity_source_sha256','executor_sha256'}
def configuration(path):
    if os.name!='nt' or str(Path(path))!=r'C:\RuleProxyCI\ruleproxy-vm-config.json':raise ValueError('fixed Windows config')
    whole=engine.parse(base.bounded_bytes(path,16384));v=whole.get('n0a_udp_parent')
    if type(v) is not dict or set(v)!=CONFIG_KEYS or v['enabled'] is not True or 'n0a' in whole or 'n0a_udp' in whole:raise ValueError('parent opt-in')
    if not engine.hex_value(v['case_nonce'],32) or not engine.integer(v['runner_port'],1025,65535):raise ValueError('case')
    if any(not engine.hex_value(v[k],64) for k in CONFIG_KEYS-{'enabled','case_nonce','runner_port'}):raise ValueError('pin')
    return v

def verify_production(config,parent,parent_manifest,child,child_manifest):
    for executable,manifest,role in ((parent,parent_manifest,'parent'),(child,child_manifest,'child')):
        raw=base.bounded_bytes(manifest,8192)
        if hashlib.sha256(raw).hexdigest()!=config[role+'_manifest_sha256']:raise ValueError('manifest pin')
        value=engine.parse(raw)
        expected=dict(schemaVersion=1,testOnly=False,deployable=True,compileOnly=True,identitySourceSha256=config['identity_source_sha256'],executableSha256=config[role+'_sha256'])
        if role=='parent':expected.update(parentSourceSha256=config['parent_source_sha256'],childActorSourceSha256=config['child_source_sha256'])
        else:expected.update(actorSourceSha256=config['child_source_sha256'])
        if type(value) is not dict or set(value)!=set(expected) or any(type(value[k]) is not type(v) or value[k]!=v for k,v in expected.items()):raise ValueError('production manifest')
        data=base.bounded_bytes(executable,8*1024*1024)
        if len(data)<512 or hashlib.sha256(data).hexdigest()!=config[role+'_sha256']:raise ValueError('production binary')

def qpc_now(frequency):
    now=ctypes.c_longlong();actual=ctypes.c_longlong();kernel=ctypes.WinDLL('kernel32',use_last_error=True)
    if not kernel.QueryPerformanceFrequency(ctypes.byref(actual)) or actual.value!=frequency or not kernel.QueryPerformanceCounter(ctypes.byref(now)):raise ValueError('QPC')
    return now.value

class WindowsExecution(base.WindowsExecution):
    def __init__(self,binding,parent,child,executor,environment,work,deadline,deadline_qpc,frequency,*,approved=False):
        if os.name!='nt' or not engine.EXECUTION_ENABLED or not approved or not isinstance(binding,engine.ParentUDPBinding) or not binding.valid():raise PermissionError('parent inactive')
        self.binding=binding;self.actor=Path(parent);self.child=Path(child);self.executor=Path(executor);self.environment=list(environment)
        self.work=Path(work);self.deadline=deadline;self.deadline_qpc=deadline_qpc;self.frequency=frequency
        self.inputs=self.actor.parent;self.owned=[];self.cases={};self.sequence=0;self.snapshots={}
        for v in [self.actor,self.child,self.executor,self.work,*self.environment]:base.base.engine.safe_argument(v)
        if not self.work.is_dir() or self.child.name!='windows_n0a_udp_actor.exe' or self.child.parent!=self.actor.parent:raise ValueError('sibling child')
    def pin(self):
        for path,expected,maximum in ((self.actor,self.binding.parent_sha256,8*1024*1024),(self.child,self.binding.child_sha256,8*1024*1024),(self.executor,self.binding.executor_sha256,32*1024*1024)):
            if hashlib.sha256(base.bounded_bytes(path,maximum)).hexdigest()!=expected:raise ValueError('binary changed')
    def phase_deadline(self,phase):
        now=qpc_now(self.frequency);limit=15 if phase in ('sample','contained') else 5
        deadline=min(self.deadline_qpc,now+limit*self.frequency)
        if deadline<=now:raise TimeoutError('parent deadline')
        return deadline
    def write_policy(self,case,deadline):
        policy=engine.udp().tcp_helpers().proof_helpers().policy(self.inputs,case['profile'],self.actor,self.binding.nonce,required_environment=self.environment)
        policy['process']['commandLine']=subprocess.list2cmdline(engine.command(self.actor,case['profile']/'parent.json',self.child,case['profile']/'child.json',self.binding,'contained',deadline,self.frequency))
        with case['policy'].open('w',encoding='utf-8') as stream:json.dump(policy,stream)
    def endpoint_case(self,endpoint,port):
        if endpoint!='runner' or port!=self.binding.runner_port:raise ValueError('runner')
        if endpoint not in self.cases:
            directory=self.work/'runner';directory.mkdir();profile=directory/'profile';profile.mkdir()
            case=dict(directory=directory,profile=profile,policy=directory/'policy.json',probe=None,probe_exit=None)
            self.cases[endpoint]=case;self.write_policy(case,self.deadline_qpc)
        return self.cases[endpoint]
    def start(self,role,phase,endpoint,port):
        if role!='ordinary' or phase!='sample':raise ValueError('sample')
        case=self.endpoint_case(endpoint,port);report=case['directory']/'sample-parent.json';child_report=case['directory']/'sample-child.json'
        if report.exists() or child_report.exists():raise ValueError('fresh report')
        deadline=self.phase_deadline(phase)
        owned=self.spawn(engine.command(self.actor,report,self.child,child_report,self.binding,phase,deadline,self.frequency),case['directory'],role,phase,endpoint,report=report)
        owned['child_report']=child_report;return owned
    def invoke(self,role,phase,endpoint,port,timeout):
        case=self.endpoint_case(endpoint,port);deadline=self.phase_deadline(phase)
        if role=='contained' and phase=='contained':
            report=case['profile']/'parent.json';child_report=case['profile']/'child.json';audit=case['directory']/'audit.private'
            if report.exists() or child_report.exists() or audit.exists():raise ValueError('fresh contained')
            self.write_policy(case,deadline) # Captured before G creation, never renewed by native.
            with audit.open('xb'):pass
            state=audit.stat();owned=self.spawn([self.executor,'--config',case['policy'],'--debug','--log-file',audit],case['directory'],role,phase,endpoint,report=report,audit=audit)
            owned['audit_identity']=(state.st_dev,state.st_ino)
        elif role=='ordinary' and phase in ('before','after'):
            report=case['directory']/(phase+'-parent.json');child_report=case['directory']/(phase+'-child.json')
            if report.exists() or child_report.exists():raise ValueError('fresh ordinary')
            owned=self.spawn(engine.command(self.actor,report,self.child,child_report,self.binding,phase,deadline,self.frequency),case['directory'],role,phase,endpoint,report=report)
        else:raise ValueError('phase')
        owned['child_report']=child_report;return self.wait(owned,timeout)
    def envelope(self,owned,code):
        case=self.cases[owned['endpoint']]
        result=dict(nonce=self.binding.nonce,parent_sha256=self.binding.parent_sha256,child_sha256=self.binding.child_sha256,executor_sha256=self.binding.executor_sha256,build=self.binding.build,ubr=self.binding.ubr,
            parent=None,child=None,parent_exit_code=None,pid_verified=False,pid_binding='unavailable',probe=case['probe'],probe_exit_code=case['probe_exit'],actual_tiers=[],timed_out=owned['timed_out'],harness_error=not owned['cleanup'] or owned.get('wait_error',False),child_snapshot=None)
        try:
            self.pin();parent,ps=flow.read_snapshot(owned['report'],8192);child,cs=flow.read_snapshot(owned['child_report'])
            self.snapshots[id(parent)]=ps;self.snapshots[id(child)]=cs;result.update(parent=parent,child=child,child_snapshot=cs)
            if owned['role']=='ordinary':result.update(pid_verified=type(parent.get('pid')) is int and parent['pid']==owned['process'].pid,pid_binding='ordinary_handle',parent_exit_code=code)
            else:
                audit=owned['audit'];state=audit.lstat()
                if audit.is_symlink() or getattr(state,'st_file_attributes',0)&0x400 or (state.st_dev,state.st_ino)!=owned['audit_identity']:raise ValueError('audit')
                event=base.base.engine.audit_exit(base.bounded_bytes(audit,base.base.engine.MAX_AUDIT),parent.get('pid'),owned['process'].pid)
                if event is not None:result.update(pid_verified=event['pid_verified'],pid_binding=event['pid_binding'],parent_exit_code=event['child_exit_code'],actual_tiers=['base-container'])
        except Exception:result['harness_error']=True
        return result

def prepare_flow(config,capture,binding,cases,execution,deadline):
    if execution is None or capture is None or time.monotonic()>=deadline:return False
    try:
        raw=flow.build_bundle({'capture':capture,'n0a_udp_parent':config},binding,cases,execution.snapshots)
        if time.monotonic()>=deadline:return False
        with (ROOT/'private-parent-udp/runner-flow.json').open('xb') as stream:stream.write(raw)
        return True
    except Exception:return False

def run(path,deadline_qpc,frequency):
    if not engine.EXECUTION_ENABLED:return None
    deadline=base.qpc_budget(deadline_qpc,frequency);config=configuration(path);capture=base.capture_configuration(path)
    parent=ROOT/'parent/actor.exe';child=ROOT/'udp/actor.exe'
    verify_production(config,parent,ROOT/'parent/build-manifest.json',child,ROOT/'udp/build-manifest.json')
    execution=None;binding=None;cases={};failed=False;cleanup=False;phase='binding'
    try:
        binding=engine.verify_binding(parent,config['parent_sha256'],child,config['child_sha256'],ROOT/'g/wxc-exec.exe',ROOT/'g/build-manifest.json',config['case_nonce'],config['runner_port'])
        if binding.executor_sha256!=config['executor_sha256']:raise ValueError('executor config')
        environment=engine.udp().tcp_helpers().proof_helpers().observe_required_environment()
        work=ROOT/'private-parent-udp';work.mkdir();inputs=work/'inputs';inputs.mkdir()
        staged_parent=inputs/'windows_n0a_udp_parent.exe';staged_child=inputs/'windows_n0a_udp_actor.exe';executor=inputs/'wxc-exec.exe'
        for src,dst in ((parent,staged_parent),(child,staged_child),(ROOT/'g/wxc-exec.exe',executor)):shutil.copyfile(src,dst)
        execution=WindowsExecution(binding,staged_parent,staged_child,executor,environment,work,deadline,deadline_qpc,frequency,approved=True)
        phase='runner';cases=engine.run_endpoint(execution,binding,deadline,approved=True);phase='completed'
    except Exception:failed=True
    finally:
        if execution is not None:cleanup=execution.finish()
    if binding is None:return None
    cases['cleanup_confirmed']=cases.get('cleanup_confirmed') is True and cleanup;cases['driver_error']=cases.get('driver_error') is not False or failed
    result=engine.evaluate(cases,binding);prepare_flow(config,capture,binding,cases,execution,deadline)
    return dict(schema_version=1,binding=dict(case_nonce=binding.nonce,parent_sha256=binding.parent_sha256,child_sha256=binding.child_sha256,executor_sha256=binding.executor_sha256,build=binding.build,ubr=binding.ubr),result=result,execution=dict(phase=phase,failed=failed,cleanup_confirmed=cleanup))
def main(argv=None):
    p=argparse.ArgumentParser();p.add_argument('--configuration',type=Path,required=True);p.add_argument('--output',type=Path,required=True);p.add_argument('--deadline-qpc',type=int,required=True);p.add_argument('--qpc-frequency',type=int,required=True);args=p.parse_args(argv)
    if args.output!=ROOT/'public-n0a-udp-parent.json' or args.output.exists():raise ValueError('fresh output')
    value=None
    try:value=run(args.configuration,args.deadline_qpc,args.qpc_frequency)
    except Exception:pass
    raw=flow.encode(value)
    if len(raw)>4096:raw=b'null';value=None
    with args.output.open('xb') as stream:stream.write(raw)
    return 0 if value is not None and not value['execution']['failed'] else 1
if __name__=='__main__':raise SystemExit(main())
