"""Opt-in runner-only UDP6 guest diagnostic; never substitutes for Stage0."""
from __future__ import annotations
import argparse
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import shutil
import sys
import time
ROOT=Path(__file__).resolve().parents[1]
def load(name,file):
    if name not in sys.modules:
        spec=importlib.util.spec_from_file_location(name,ROOT/'.github'/file)
        module=importlib.util.module_from_spec(spec);sys.modules[name]=module;spec.loader.exec_module(module)
    return sys.modules[name]
base=load('n0a_udp6_guest_base','windows_n0a_guest.py')
engine=load('n0a_udp6_guest_flow','windows_n0a_udp6_flow.py').engine()
bounded_bytes=base.bounded_bytes
qpc_budget=base.qpc_budget
CONFIG_KEYS=base.CONFIG_KEYS
MANIFEST_KEYS={'schemaVersion','testOnly','deployable','compileOnly','actorSourceSha256','identitySourceSha256','executableSha256'}


def configuration(path):
    if os.name!='nt':raise PermissionError('Windows guest only')
    if str(Path(path))!=r'C:\RuleProxyCI\ruleproxy-vm-config.json':raise ValueError('fixed seed configuration required')
    value=json.loads(bounded_bytes(path,16384).decode('utf-8'),object_pairs_hook=base.engine.unique_object)
    if type(value) is dict and any(type(value.get(k)) is dict and value[k].get('enabled') is True for k in ('n0a','n0a_udp','n0a_udp_parent')):
        raise ValueError('exclusive UDP6 configuration required')
    value=value.get('n0a_udp6') if type(value) is dict else None
    if type(value) is not dict or set(value)!=CONFIG_KEYS or value['enabled'] is not True:raise ValueError('explicit N0a configuration required')
    if type(value['case_nonce']) is not str or not base.engine.NONCE.fullmatch(value['case_nonce']):raise ValueError('case nonce')
    if not engine.integer(value['runner_port'],1025,65535):raise ValueError('runner port')
    for key in CONFIG_KEYS-{'enabled','case_nonce','runner_port'}:
        if type(value[key]) is not str or not base.engine.HASH.fullmatch(value[key]):raise ValueError('pinned configuration required')
    return value

def flow_helpers():
    return load('n0a_udp6_guest_flow','windows_n0a_udp6_flow.py')


def capture_configuration(path):
    value=json.loads(bounded_bytes(path,16384).decode('utf-8'),object_pairs_hook=base.engine.unique_object)
    if type(value) is not dict or 'capture' not in value:return None
    value=value['capture']
    if type(value) is not dict or set(value)!={'enabled','run_nonce','source_commit','vm_mac'} or value['enabled'] is not True:raise ValueError('capture configuration')
    for key,size in (('run_nonce',32),('source_commit',40),('vm_mac',12)):
        if not flow_helpers().hex_value(value[key],size):raise ValueError('capture binding')
    if int(value['vm_mac'][:2],16)&1 or value['vm_mac']=='0'*12:raise ValueError('capture MAC')
    return value

def verify_production(config,actor,manifest):
    raw=bounded_bytes(manifest,8192)
    if hashlib.sha256(raw).hexdigest()!=config['manifest_sha256']:raise ValueError('manifest pin')
    value=json.loads(raw.decode('utf-8'),object_pairs_hook=base.engine.unique_object)
    expected={'schemaVersion':1,'testOnly':False,'deployable':True,'compileOnly':True,
              'actorSourceSha256':config['actor_source_sha256'],'identitySourceSha256':config['identity_source_sha256'],
              'executableSha256':config['actor_sha256']}
    if type(value) is not dict or set(value)!=MANIFEST_KEYS:raise ValueError('UDP manifest shape')
    if any(type(value[k]) is not type(v) or value[k]!=v for k,v in expected.items()):raise ValueError('UDP production manifest differs')
    data=bounded_bytes(actor,8*1024*1024)
    if len(data)<512 or hashlib.sha256(data).hexdigest()!=config['actor_sha256']:raise ValueError('production executable pin')
    return value


class WindowsExecution(base.WindowsExecution):
    def __init__(self,binding,actor,executor,required_environment,work,deadline,*,approved=False,capture=False):
        if os.name!='nt' or not engine.EXECUTION_ENABLED or not approved:raise PermissionError('N0a execution inactive')
        self.binding=binding;self.actor=Path(actor);self.executor=Path(executor)
        self.environment=list(required_environment);self.work=Path(work);self.deadline=deadline
        self.inputs=self.actor.parent;self.owned=[];self.cases={};self.sequence=0
        self.capture=capture;self.snapshots={}
        for value in [self.actor,self.executor,self.work,*self.environment]:base.engine.safe_argument(value)
        if not self.work.is_dir() or not binding.valid():raise ValueError('fresh owned case root required')

    def endpoint_case(self,endpoint,port):
        if endpoint!='runner-v6' or port!=self.binding.runner_port:raise ValueError('bound UDP runner required')
        if endpoint not in self.cases:
            directory=self.work/endpoint;directory.mkdir(exist_ok=False)
            profile=directory/'profile';profile.mkdir(exist_ok=False)
            policy=engine.contained_policy(self.inputs,profile,self.actor,self.binding,self.environment)
            policy_path=directory/'policy.json'
            with policy_path.open('x',encoding='utf-8') as stream:json.dump(policy,stream)
            self.cases[endpoint]={'directory':directory,'profile':profile,'policy':policy_path,'probe':None,'probe_exit':None}
        return self.cases[endpoint]


    def close_owned(self,owned):
        # Independent observations: one failed operation must not skip subsequent cleanup.
        process=owned.get('process');exited=process is None or owned.get('process_exit_observed',False)
        # A registered record without a held process cannot prove spawn never occurred.
        uncertain=owned.get('cleanup_uncertain',False) or process is None
        if process is not None and not exited:
            try:exited=process.poll() is not None;owned['exit_observed']=exited
            except Exception:uncertain=True
            if not exited:
                try:process.kill()
                except Exception:uncertain=True
                remaining=self.deadline-time.monotonic()
                if remaining>0:
                    try:process.wait(timeout=min(2,remaining))
                    except Exception:uncertain=True
                try:exited=process.poll() is not None;owned['exit_observed']=exited
                except Exception:uncertain=True
        owned['process_exit_observed']=exited
        if process is not None and not owned.get('handle_close_attempted',False):
            handle=None
            try:handle=getattr(process,'_handle',None)
            except Exception:uncertain=True
            if exited and handle is not None and not owned.get('handle_close_attempted',False):
                owned['handle_close_attempted']=True
                try:handle.Close()
                except Exception:uncertain=True
        for key in ('out','err'):
            stream=owned.get(key)
            if stream is not None and not owned.get(key+'_close_attempted',False):
                owned[key+'_close_attempted']=True
                try:stream.close()
                except Exception:uncertain=True
            if stream is not None:
                try:
                    if stream.closed is not True:uncertain=True
                except Exception:uncertain=True
        owned['cleanup_uncertain']=uncertain or not exited
        owned['cleanup']=exited and not owned['cleanup_uncertain']
        return owned['cleanup']


    def start(self,role,phase,endpoint,port):
        case=self.endpoint_case(endpoint,port)
        if role!='ordinary' or phase!='sample':raise ValueError('only owned UDP sampler asynchronous')
        report=case['directory']/'sample.json'
        if report.exists():raise ValueError('fresh sampler report required')
        return self.spawn(engine.command(self.actor,report,self.binding,phase),case['directory'],role,phase,endpoint,report=report)


    def envelope(self,owned,code):
        endpoint=owned['endpoint'];case=self.cases[endpoint]
        result={'nonce':self.binding.nonce,'actor_sha256':self.binding.actor_sha256,
                'executor_sha256':self.binding.executor_sha256,'build':self.binding.build,'ubr':self.binding.ubr,
                'exit_code':code,'timed_out':owned['timed_out'],'harness_error':not owned['cleanup'] or owned.get('wait_error',False),
                'actor':None,'pid_verified':False,'pid_binding':'unavailable','child_exit_code':None,
                'probe':case['probe'],'probe_exit_code':case['probe_exit'],'actual_tiers':[]}
        owned['report_presence']='unavailable'
        owned['report_state']='pin'
        try:
            self.pin()
            owned['report_state']='read'
            if self.capture:
                actor,snapshot=flow_helpers().read_snapshot(owned['report']);self.snapshots[id(actor)]=snapshot
            else:actor=base.engine.read_report(owned['report'])
            owned['report_presence']='object'
            owned['report_state']='parsed'
            result['actor']=actor
            if actor.get('nonce')!=self.binding.nonce or actor.get('mode')!='actor-n0a-udp6':raise ValueError('fresh actor required')
            owned['report_state']='binding'
            if owned['role']=='ordinary':
                result['pid_verified']=type(actor.get('pid')) is int and actor['pid']==owned['process'].pid
                result['pid_binding']='ordinary_handle';result['child_exit_code']=code
            else:
                owned['report_state']='audit'
                audit=owned['audit'];state=audit.lstat()
                if (audit.is_symlink() or getattr(state,'st_file_attributes',0)&0x400
                        or (state.st_dev,state.st_ino)!=owned['audit_identity']):raise ValueError('audit binding changed')
                event=base.engine.audit_exit(bounded_bytes(audit,base.engine.MAX_AUDIT),actor.get('pid'),owned['process'].pid)
                if event is not None:
                    result.update(event)
                    # Tier is an actual-runner field of the dedicated event
                    # emitted only after its owned native child handle wait.
                    result['actual_tiers']=['base-container']
            owned['report_state']='complete'
        except Exception as exc:
            result['harness_error']=True
            if owned['report_state']=='read':owned['report_presence']='missing' if isinstance(exc,FileNotFoundError) else 'unreadable'
        owned['envelope_returned']=True
        return result

    def invoke(self,role,phase,endpoint,port,timeout):
        case=self.endpoint_case(endpoint,port)
        if role=='contained' and phase=='contained':
            report=case['profile']/'actor.json';audit=case['directory']/'audit.private'
            if report.exists() or audit.exists():raise ValueError('fresh contained files required')
            with audit.open('xb'):pass
            state=audit.stat()
            args=[self.executor,'--config',case['policy'],'--debug','--log-file',audit]
            owned=self.spawn(args,case['directory'],role,phase,endpoint,report=report,audit=audit)
            owned['audit_identity']=(state.st_dev,state.st_ino)
        elif role=='ordinary' and phase in ('before','after'):
            report=case['directory']/(phase+'.json')
            if report.exists():raise ValueError('fresh control report required')
            owned=self.spawn(engine.command(self.actor,report,self.binding,phase),case['directory'],role,phase,endpoint,report=report)
        else:raise ValueError('fixed UDP invocation required')
        return self.wait(owned,timeout)


def execution_observations(execution):
    result={}
    if execution is None:return result
    for owned in execution.owned:
        phase=owned.get('pattern')
        if phase not in engine.PHASES or owned.get('role') not in ('ordinary','contained'):continue
        result[phase]=dict(owned=True,handle=owned.get('process') is not None,
            exit=owned.get('exit_observed') if owned.get('process') is not None and type(owned.get('exit_observed')) is bool else None,
            envelope=owned.get('envelope_returned') is True,report_state=owned.get('report_state','unavailable'),report_presence=owned.get('report_presence','unavailable'))
    return result


def prepare_flow(config,capture,binding,cases,execution,deadline):
    if capture is None or execution is None or time.monotonic()>=deadline:return False
    try:
        raw=flow_helpers().build_bundle({'capture':capture,'n0a_udp6':config},binding,cases,execution.snapshots)
        if time.monotonic()>=deadline:return False
        with (ROOT/'private-udp6/runner-flow.json').open('xb') as stream:stream.write(raw)
        return True
    except Exception:return False


def run(configuration_path,deadline_qpc,frequency):
    if not engine.EXECUTION_ENABLED:return None
    deadline=qpc_budget(deadline_qpc,frequency)
    config=configuration(configuration_path)
    try:capture=capture_configuration(configuration_path)
    except Exception:capture=None
    actor=ROOT/'udp6/actor.exe';manifest=ROOT/'udp6/build-manifest.json'
    verify_production(config,actor,manifest)
    execution=None;binding=None;cases={};phase='binding';failed=False;cleanup=False
    try:
        binding=engine.verify_binding(actor,config['actor_sha256'],ROOT/'g/wxc-exec.exe',ROOT/'g/build-manifest.json',
                                      config['case_nonce'],config['runner_port'])
        environment=base.engine.proof_helpers().observe_required_environment()
        base.engine.clipped_timeout(deadline,1)
        work=ROOT/'private-udp6';work.mkdir(exist_ok=False);inputs=work/'inputs';inputs.mkdir()
        staged_actor=inputs/'actor.exe';staged_executor=inputs/'wxc-exec.exe'
        shutil.copyfile(actor,staged_actor);shutil.copyfile(ROOT/'g/wxc-exec.exe',staged_executor)
        execution=WindowsExecution(binding,staged_actor,staged_executor,environment,work,deadline,approved=True,capture=capture is not None)
        phase='runner';cases=engine.run_endpoint(execution,binding,deadline,approved=True)
        phase='completed'
    except Exception:failed=True
    finally:
        if execution is not None:cleanup=execution.finish()
    if binding is None:return None
    cases['cleanup_confirmed']=cases.get('cleanup_confirmed') is True and cleanup
    cases['driver_error']=cases.get('driver_error') is not False or failed
    cases['execution_observations']=execution_observations(execution)
    result=engine.evaluate(cases,binding)
    prepare_flow(config,capture,binding,cases,execution,deadline)
    return {'schema_version':1,'binding':{'case_nonce':binding.nonce,'actor_sha256':binding.actor_sha256,
             'executor_sha256':binding.executor_sha256,'build':binding.build,'ubr':binding.ubr},
            'result':result,'execution':{'phase':phase,'failed':failed,'cleanup_confirmed':cleanup}}


def main(argv=None):
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--configuration',type=Path,required=True);parser.add_argument('--output',type=Path,required=True)
    parser.add_argument('--deadline-qpc',type=int,required=True);parser.add_argument('--qpc-frequency',type=int,required=True)
    args=parser.parse_args(argv)
    if args.output!=ROOT/'public-n0a-udp6.json' or args.output.exists():raise ValueError('fresh fixed UDP output required')
    value=None
    try:value=run(args.configuration,args.deadline_qpc,args.qpc_frequency)
    except Exception:pass
    data=json.dumps(value,ensure_ascii=True,separators=(',',':'))
    if len(data.encode('ascii'))>base.engine.MAX_N0A_REPORT:data='null';value=None
    with args.output.open('x',encoding='ascii') as stream:stream.write(data)
    return 0 if value is not None and not value['execution']['failed'] else 1

if __name__=='__main__':raise SystemExit(main())
