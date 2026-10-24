"""Explicit opt-in N0a guest adapter; private reports never become Stage0 proof."""
from __future__ import annotations
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
spec=importlib.util.spec_from_file_location('n0a_guest_engine',ROOT/'.github/windows_n0a_control.py')
engine=importlib.util.module_from_spec(spec);sys.modules[spec.name]=engine;spec.loader.exec_module(engine)
CONFIG_KEYS={'enabled','case_nonce','runner_port','actor_sha256','manifest_sha256','actor_source_sha256','identity_source_sha256'}
MANIFEST_KEYS={'schemaVersion','sourceSha256','identitySourceSha256','executableSha256','targetArchitecture',
               'staticCrt','httpCompiled','rawTcpCompiled','compileOnly','testOnly','actorRole','builtAtUtc'}


def bounded_bytes(path, maximum):
    path=Path(path);state=path.lstat()
    if path.is_symlink() or getattr(state,'st_file_attributes',0)&0x400 or not path.is_file(): raise ValueError('bounded regular input required')
    with path.open('rb') as stream:data=stream.read(maximum+1)
    if not 0<len(data)<=maximum:raise ValueError('input bound')
    return data


def configuration(path):
    if os.name!='nt':raise PermissionError('Windows guest only')
    if str(Path(path))!=r'C:\RuleProxyCI\ruleproxy-vm-config.json':raise ValueError('fixed seed configuration required')
    value=json.loads(bounded_bytes(path,16384).decode('utf-8'),object_pairs_hook=engine.unique_object)
    value=value.get('n0a') if type(value) is dict else None
    if type(value) is not dict or set(value)!=CONFIG_KEYS or value['enabled'] is not True:raise ValueError('explicit N0a configuration required')
    if type(value['case_nonce']) is not str or not engine.NONCE.fullmatch(value['case_nonce']):raise ValueError('case nonce')
    if not engine.integer(value['runner_port'],1025,65535):raise ValueError('runner port')
    for key in CONFIG_KEYS-{'enabled','case_nonce','runner_port'}:
        if type(value[key]) is not str or not engine.HASH.fullmatch(value[key]):raise ValueError('pinned configuration required')
    return value


def flow_helpers():
    name='n0a_guest_flow'
    if name not in sys.modules:
        spec=importlib.util.spec_from_file_location(name,ROOT/'.github/windows_n0a_flow.py')
        module=importlib.util.module_from_spec(spec);sys.modules[name]=module;spec.loader.exec_module(module)
    return sys.modules[name]


def capture_configuration(path):
    value=json.loads(bounded_bytes(path,16384).decode('utf-8'),object_pairs_hook=engine.unique_object)
    if type(value) is not dict or 'capture' not in value:return None
    value=value['capture']
    if type(value) is not dict or set(value)!={'enabled','run_nonce','source_commit','vm_mac'} or value['enabled'] is not True:raise ValueError('capture configuration')
    for key,size in (('run_nonce',32),('source_commit',40),('vm_mac',12)):
        if not flow_helpers().hex_value(value[key],size):raise ValueError('capture binding')
    if int(value['vm_mac'][:2],16)&1 or value['vm_mac']=='0'*12:raise ValueError('capture MAC')
    return value


def prepare_flow(config,capture,binding,cases,execution,deadline):
    # Capture-only preparation cannot replace the already computed connect result.
    if capture is None or execution is None or time.monotonic()>=deadline:return False
    try:
        raw=flow_helpers().build_bundle({'capture':capture,'n0a':config},binding,cases['runner'],execution.snapshots)
        if time.monotonic()>=deadline:return False
        with (ROOT/'private-n0a/runner-flow.json').open('xb') as stream:stream.write(raw)
        return True
    except Exception:return False


def verify_production(config, actor, manifest):
    raw=bounded_bytes(manifest,8192)
    if hashlib.sha256(raw).hexdigest()!=config['manifest_sha256']:raise ValueError('manifest pin')
    value=json.loads(raw.decode('utf-8'),object_pairs_hook=engine.unique_object)
    if type(value) is not dict or set(value)!=MANIFEST_KEYS:raise ValueError('manifest shape')
    expected={'schemaVersion':1,'sourceSha256':config['actor_source_sha256'],
              'identitySourceSha256':config['identity_source_sha256'],'executableSha256':config['actor_sha256'],
              'targetArchitecture':'x64','staticCrt':True,'httpCompiled':False,'rawTcpCompiled':True,
              'compileOnly':True,'testOnly':False,'actorRole':'n0a-tcp'}
    if any(type(value[k]) is not type(v) or value[k]!=v for k,v in expected.items()):raise ValueError('production manifest differs')
    if type(value['builtAtUtc']) is not str or not 1<=len(value['builtAtUtc'])<=64:raise ValueError('manifest timestamp bound')
    data=bounded_bytes(actor,8*1024*1024)
    if len(data)<512 or hashlib.sha256(data).hexdigest()!=config['actor_sha256']:raise ValueError('production executable pin')
    return value


def qpc_budget(deadline_qpc, frequency):
    if os.name!='nt' or not engine.integer(deadline_qpc,1) or not engine.integer(frequency,1,10**9):raise ValueError('same guest QPC deadline required')
    monotonic_before=time.monotonic()
    kernel=ctypes.WinDLL('kernel32',use_last_error=True)
    tick=ctypes.c_int64();observed=ctypes.c_int64()
    for name in ('QueryPerformanceCounter','QueryPerformanceFrequency'):
        function=getattr(kernel,name);function.argtypes=[ctypes.POINTER(ctypes.c_int64)];function.restype=ctypes.c_int
    if not kernel.QueryPerformanceFrequency(ctypes.byref(observed)) or observed.value!=frequency:raise ValueError('QPC frequency differs')
    if not kernel.QueryPerformanceCounter(ctypes.byref(tick)):raise OSError('QPC unavailable')
    remaining=(deadline_qpc-tick.value)/frequency
    if not 0<remaining<=120:raise TimeoutError('original guest work budget exhausted')
    return monotonic_before+remaining  # Conservative same-guest mapping; no sampling-delay renewal.


class WindowsExecution:
    def __init__(self,binding,actor,executor,required_environment,work,deadline,*,approved=False,capture=False):
        if os.name!='nt' or not engine.EXECUTION_ENABLED or not approved:raise PermissionError('N0a execution inactive')
        self.binding=binding;self.actor=Path(actor);self.executor=Path(executor)
        self.environment=list(required_environment);self.work=Path(work);self.deadline=deadline
        self.inputs=self.actor.parent;self.owned=[];self.cases={};self.sequence=0
        self.capture=capture;self.snapshots={}
        for value in [self.actor,self.executor,self.work,*self.environment]:engine.safe_argument(value)
        if not self.work.is_dir() or not binding.valid():raise ValueError('fresh owned case root required')

    def remaining(self,limit):return engine.clipped_timeout(self.deadline,limit)

    def pin(self):
        if hashlib.sha256(bounded_bytes(self.actor,8*1024*1024)).hexdigest()!=self.binding.actor_sha256:raise ValueError('actor changed')
        if hashlib.sha256(bounded_bytes(self.executor,32*1024*1024)).hexdigest()!=self.binding.executor_sha256:raise ValueError('executor changed')

    def endpoint_case(self,endpoint,port):
        if endpoint not in engine.ENDPOINTS or port!=self.binding.ports[tuple(engine.ENDPOINTS).index(endpoint)]:raise ValueError('bound endpoint required')
        if endpoint not in self.cases:
            directory=self.work/endpoint;directory.mkdir(exist_ok=False)
            profile=directory/'profile';profile.mkdir(exist_ok=False)
            policy=engine.contained_policy(self.inputs,profile,self.actor,self.binding,endpoint,port,self.environment)
            policy_path=directory/'policy.json'
            with policy_path.open('x',encoding='utf-8') as stream:json.dump(policy,stream)
            self.cases[endpoint]={'directory':directory,'profile':profile,'policy':policy_path,'probe':None,'probe_exit':None}
        return self.cases[endpoint]

    def spawn(self,args,directory,role,pattern,endpoint,report=None,audit=None):
        self.remaining(1);self.pin();self.sequence+=1
        args=[engine.safe_argument(arg) for arg in args]
        owned={'process':None,'out':None,'err':None,'role':role,'pattern':pattern,'endpoint':endpoint,
               'report':report,'audit':audit,'timed_out':False,'cleanup':False}
        self.owned.append(owned) # Register files/partial setup before any spawn.
        try:
            owned['out_path']=directory/f'output-{self.sequence}.private'
            owned['err_path']=directory/f'error-{self.sequence}.private'
            owned['out']=owned['out_path'].open('xb');owned['err']=owned['err_path'].open('xb')
            owned['process']=subprocess.Popen(args,stdin=subprocess.DEVNULL,stdout=owned['out'],stderr=owned['err'],shell=False)
            return owned
        except Exception:
            self.close_owned(owned);raise

    def close_owned(self,owned):
        okay=True;process=owned.get('process');exited=process is None
        if process is not None:
            try:
                if process.poll() is None:
                    process.kill();process.wait(timeout=max(.001,min(2,self.deadline-time.monotonic())))
                exited=process.poll() is not None
                if not exited:okay=False
            except Exception:okay=False
            # Retain the exact process handle while exit is unknown, so final
            # cleanup can still observe/stop it; never replace with name-kill.
            handle=getattr(process,'_handle',None)
            if exited and handle is not None:
                try:handle.Close()
                except Exception:okay=False
        for key in ('out','err'):
            stream=owned.get(key)
            if stream is not None:
                try:stream.close()
                except Exception:okay=False
        owned['cleanup']=okay and exited
        return owned['cleanup']

    def completed(self,owned,timeout):
        process=owned['process']
        try:process.wait(timeout=min(timeout,self.remaining(timeout)))
        except subprocess.TimeoutExpired:owned['timed_out']=True
        except Exception:owned['wait_error']=True
        finally:self.close_owned(owned)
        # A later wait/cleanup failure must not erase already written native
        # report + dedicated exit-event evidence of an attributed connection.
        return process.returncode

    def probe(self,endpoint,port,timeout):
        case=self.endpoint_case(endpoint,port)
        owned=self.spawn([self.executor,'--probe','--config',case['policy']],case['directory'],'probe','single',endpoint)
        code=self.completed(owned,timeout)
        if not owned['cleanup'] or owned['timed_out']:raise TimeoutError('probe unavailable')
        value=json.loads(bounded_bytes(owned['out_path'],engine.MAX_AUDIT).decode('utf-8'),object_pairs_hook=engine.unique_object)
        if not engine.proof_helpers().smoke.base_container_selected(value,code):raise ValueError('BaseContainer not selected')
        case['probe']=value;case['probe_exit']=code

    def start(self,role,pattern,endpoint,port):
        case=self.endpoint_case(endpoint,port)
        if role!='ordinary' or pattern!='sample':raise ValueError('only owned ordinary sampler asynchronous')
        report=case['directory']/'sample.json'
        if report.exists():raise ValueError('fresh sampler report required')
        return self.spawn(engine.command(self.actor,report,self.binding,endpoint,port,role,pattern),
                          case['directory'],role,pattern,endpoint,report=report)

    def envelope(self,owned,code):
        endpoint=owned['endpoint'];case=self.cases[endpoint]
        result={'nonce':self.binding.nonce,'actor_sha256':self.binding.actor_sha256,
                'executor_sha256':self.binding.executor_sha256,'build':self.binding.build,'ubr':self.binding.ubr,
                'exit_code':code,'timed_out':owned['timed_out'],'harness_error':not owned['cleanup'] or owned.get('wait_error',False),
                'actor':None,'pid_verified':False,'pid_binding':'unavailable','child_exit_code':None,
                'probe':case['probe'],'probe_exit_code':case['probe_exit'],'actual_tiers':[]}
        try:
            self.pin()
            if self.capture:
                actor,snapshot=flow_helpers().read_snapshot(owned['report']);self.snapshots[id(actor)]=snapshot
            else:actor=engine.read_report(owned['report'])
            result['actor']=actor
            if actor.get('nonce')!=self.binding.nonce or actor.get('mode')!='actor-n0a':raise ValueError('fresh actor required')
            if owned['role']=='ordinary':
                result['pid_verified']=type(actor.get('pid')) is int and actor['pid']==owned['process'].pid
                result['pid_binding']='ordinary_handle';result['child_exit_code']=code
            else:
                audit=owned['audit'];state=audit.lstat()
                if (audit.is_symlink() or getattr(state,'st_file_attributes',0)&0x400
                        or (state.st_dev,state.st_ino)!=owned['audit_identity']):raise ValueError('audit binding changed')
                event=engine.audit_exit(bounded_bytes(audit,engine.MAX_AUDIT),actor.get('pid'),owned['process'].pid)
                if event is not None:
                    result.update(event)
                    # Tier is an actual-runner field of the dedicated event
                    # emitted only after its owned native child handle wait.
                    result['actual_tiers']=['base-container']
        except Exception:result['harness_error']=True
        return result

    def wait(self,owned,timeout):return self.envelope(owned,self.completed(owned,timeout))

    def invoke(self,role,pattern,endpoint,port,timeout):
        case=self.endpoint_case(endpoint,port)
        if role=='contained':
            report=case['profile']/'actor.json';audit=case['directory']/'audit.private'
            if report.exists() or audit.exists():raise ValueError('fresh contained files required')
            with audit.open('xb'):pass
            state=audit.stat()
            args=[self.executor,'--config',case['policy'],'--debug','--log-file',audit]
            owned=self.spawn(args,case['directory'],role,pattern,endpoint,report=report,audit=audit)
            owned['audit_identity']=(state.st_dev,state.st_ino)
        elif role=='ordinary' and pattern=='single':
            report=case['directory']/f'control-{self.sequence}.json'
            if report.exists():raise ValueError('fresh control report required')
            owned=self.spawn(engine.command(self.actor,report,self.binding,endpoint,port,role,pattern),
                             case['directory'],role,pattern,endpoint,report=report)
        else:raise ValueError('fixed invocation required')
        return self.wait(owned,timeout)

    def finish(self):
        return all([self.close_owned(owned) for owned in self.owned])


def run(configuration_path,deadline_qpc,frequency):
    if not engine.EXECUTION_ENABLED: return None
    deadline=qpc_budget(deadline_qpc,frequency)
    config=configuration(configuration_path)
    try:capture=capture_configuration(configuration_path)
    except Exception:capture=None
    actor=ROOT/'n0a/actor.exe';manifest=ROOT/'n0a/build-manifest.json'
    verify_production(config,actor,manifest)
    endpoint=None;execution=None;binding=None;cases={};phase='binding';failed=False;cleanup=False
    try:
        # Source binding observation occurs before any endpoint/socket creation.
        preliminary=engine.verify_binding(actor,config['actor_sha256'],ROOT/'g/wxc-exec.exe',ROOT/'g/build-manifest.json',
                                           config['case_nonce'],(config['runner_port'],config['runner_port']))
        environment=engine.proof_helpers().observe_required_environment()
        phase='endpoint';engine.clipped_timeout(deadline,1)
        endpoint=engine.NonceEndpoint(config['case_nonce'],'guest',deadline);guest_port=endpoint.start()
        binding=engine.Binding(preliminary.nonce,preliminary.actor_sha256,preliminary.executor_sha256,preliminary.agentic_sid,
                               (guest_port,config['runner_port']),preliminary.controller_compartment,
                               preliminary.controller_elevated,preliminary.controller_appcontainer)
        work=ROOT/'private-n0a';work.mkdir(exist_ok=False);inputs=work/'inputs';inputs.mkdir()
        staged_actor=inputs/'actor.exe';staged_executor=inputs/'wxc-exec.exe'
        shutil.copyfile(actor,staged_actor);shutil.copyfile(ROOT/'g/wxc-exec.exe',staged_executor)
        execution=WindowsExecution(binding,staged_actor,staged_executor,environment,work,deadline,approved=True,capture=capture is not None)
        for name,port in zip(engine.ENDPOINTS,binding.ports):
            phase=name
            cases[name]=engine.run_endpoint(execution,binding,name,port,deadline,approved=True)
        phase='completed'
    except Exception:failed=True
    finally:
        if execution is not None:cleanup=execution.finish()
        receiver=endpoint.finish() if endpoint is not None else {'socket_cleanup_confirmed':True,'endpoint_error':False,'receiver_counts':None}
        cleanup=cleanup and receiver['socket_cleanup_confirmed']
    if binding is None:return None
    result=engine.evaluate(cases,binding)
    prepare_flow(config,capture,binding,cases,execution,deadline)
    if result['status']!='connect_succeeded' and (failed or not cleanup or receiver['endpoint_error']):
        result['status']='inconclusive'
        for row in result['endpoints'].values():
            if row['status']=='observed_connect_denial':row['status']='inconclusive'
    return {'schema_version':1,'binding':{'case_nonce':binding.nonce,'actor_sha256':binding.actor_sha256,
             'executor_sha256':binding.executor_sha256,'build':binding.build,'ubr':binding.ubr},
            'result':result,'execution':{'phase':phase,'failed':failed,'cleanup_confirmed':cleanup},'receiver':receiver}


def main(argv=None):
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--configuration',type=Path,required=True);parser.add_argument('--output',type=Path,required=True)
    parser.add_argument('--deadline-qpc',type=int,required=True);parser.add_argument('--qpc-frequency',type=int,required=True)
    args=parser.parse_args(argv)
    if args.output!=ROOT/'public-n0a.json' or args.output.exists():raise ValueError('fresh fixed N0a output required')
    value=None
    try:value=run(args.configuration,args.deadline_qpc,args.qpc_frequency)
    except Exception:pass # Private binding unavailable: only closed null is emitted.
    data=json.dumps(value,ensure_ascii=True,separators=(',',':'))
    if len(data.encode('ascii'))>engine.MAX_N0A_REPORT:data='null';value=None
    with args.output.open('x',encoding='ascii') as stream:stream.write(data)
    return 0 if value is not None and not value['execution']['failed'] else 1

if __name__=='__main__':raise SystemExit(main())
