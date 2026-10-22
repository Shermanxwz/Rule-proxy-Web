"""Explicit hosted-only two-process anonymous-pipe mechanics; never a proxy.

Import and pure tests make no Windows calls. The runtime entry is separately
approved: no socket, AppContainer profile, ACL, token substitution, or fallback.
"""
from __future__ import annotations
import argparse
import ctypes as C
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import re
import secrets
import shutil
import stat
import subprocess
import sys

ROOT=Path(__file__).resolve().parents[1]
MAX_ACTOR=8*1024*1024
MAX_NATIVE=8192
MAX_PRIVATE=128*1024
MAX_PUBLIC=4096
PLANNING_LIMIT=128*1024*1024
CASES=('success','mismatched_case','withheld_relay_resume')
FAILURES=('configuration','capacity','identity','setup','create','assign','image','close','resume','deadline','report','cleanup','internal')
NATIVE_FAILURES=(None,'configuration','identity','qpc','pipe_type','inheritance','pipe_read','pipe_write','eof','close','core','report')
RETAINED=[]


def _load(name):
    path=Path(__file__).with_name(name+'.py')
    spec=importlib.util.spec_from_file_location('_proxy_pipe_'+name,path)
    module=importlib.util.module_from_spec(spec);spec.loader.exec_module(module)
    return module


launcher=_load('windows_identity_ordinary_launcher')
pipe_helpers=_load('windows_identity_pipe_probe')


def integer(value,minimum=0,maximum=0xffffffff):
    return type(value) is int and minimum<=value<=maximum


def digest(value):
    return type(value) is str and re.fullmatch('[0-9a-f]{64}',value) is not None


def nonce(value):
    return type(value) is str and re.fullmatch('[0-9a-f]{32}',value) is not None


def unique(pairs):
    value={}
    for key,item in pairs:
        if key in value:raise ValueError('report')
        value[key]=item
    return value


def bounded_json(path,limit,inside=None):
    path=launcher.checked_path(path,inside=inside)
    raw=pipe_helpers.read_bounded_file(path,limit)
    value=json.loads(raw.decode('utf-8'),object_pairs_hook=unique,
                     parse_constant=lambda _:(_ for _ in ()).throw(ValueError('report')))
    if type(value) is not dict:raise ValueError('report')
    return value,raw


def current_identity(value):
    return (type(value) is dict and type(value.get('sid')) is str and
            launcher.SID_PATTERN.fullmatch(value['sid']) is not None and
            value.get('appcontainer') is False and value.get('appcontainer_sid') is None and
            type(value.get('elevated')) is bool and value.get('token_type')==1 and
            integer(value.get('token_type'),1,1) and integer(value.get('session_id')) and
            integer(value.get('capability_count'),0,0))


def same_hosted_identity(value,parent):
    return (current_identity(value) and launcher.same_identity(value,parent) and
            value['elevated'] is parent['elevated'])


def validate_native(value,*,role,run_id,case_id,pid,identity,frequency,start,end):
    keys={'schema_version','stage','role','run_id','case_id','pid','identity','qpc','pipe','core',
          'synthetic_http','failure','win32_error','network_tested','proxy_tested','product_acceptance'}
    if (type(value) is not dict or set(value)!=keys or not integer(value['schema_version'],1,1) or
            value['stage']!='bridge-pipe-test' or value['role']!=role or value['run_id']!=run_id or
            value['case_id']!=case_id or not integer(value['pid'],1) or value['pid']!=pid or
            any(value[k] is not False for k in ('network_tested','proxy_tested','product_acceptance'))):
        raise ValueError('report')
    identity_keys={'schemaVersion','mode','nonce','pid','tokenUserSid','tokenIsAppContainer',
                   'tokenAppContainerSid','tokenElevated','isProcessInJob','tokenCapabilities','queriesSucceeded','errors'}
    v=value['identity']
    if (type(v) is not dict or set(v)!=identity_keys or not integer(v['schemaVersion'],1,1) or
            v['mode']!='actor' or v['nonce']!=run_id or not integer(v['pid'],1) or v['pid']!=pid or
            v['tokenUserSid']!=identity['sid'] or v['tokenElevated'] is not identity['elevated'] or
            v['tokenIsAppContainer'] is not False or v['tokenAppContainerSid'] is not None or
            v['isProcessInJob'] is not True or v['tokenCapabilities']!=[] or
            v['queriesSucceeded'] is not True or v['errors']!=[]):raise ValueError('report')
    q=value['qpc']
    if (type(q) is not list or len(q)!=4 or any(not integer(x,0,0x7fffffffffffffff) for x in q) or
            q[:3]!=[frequency,start,end] or q[3]!=0 and not start<=q[3]):raise ValueError('report')
    p=value['pipe'];front=role=='pipe-front'
    if type(p) is not dict or set(p)!={'read_bytes','write_bytes','read_frames','write_frames','inheritance_cleared',
                                     'eof_observed','reader_close','writer_close','requires_controller_timeout'}:raise ValueError('report')
    for key,maximum in (('read_bytes',97 if front else 145),('write_bytes',144 if front else 96),
                        ('read_frames',2 if front else 3),('write_frames',3 if front else 2)):
        if not integer(p[key],0,maximum):raise ValueError('report')
    if (any(type(p[k]) is not bool for k in ('inheritance_cleared','eof_observed')) or
            p['requires_controller_timeout'] is not True or
            any(p[k] not in ('not_attempted','confirmed','uncertain') for k in ('reader_close','writer_close')) or
            p['read_frames']*48>p['read_bytes'] or p['write_frames']*48>p['write_bytes']):raise ValueError('report')
    core=value['core'];owned=7 if front else 56;observed=177 if front else 78
    if type(core) is not dict or set(core)!={'failure','observations','requested','confirmed','uncertain'}:raise ValueError('report')
    if (not integer(core['failure'],0,11) or not integer(core['observations'],0,255) or core['observations']&~observed or
            any(not integer(core[k],0,63) or core[k]&~owned for k in ('requested','confirmed','uncertain')) or
            core['confirmed']&core['uncertain'] or (core['confirmed']|core['uncertain'])&~core['requested']):raise ValueError('report')
    synthetic=value['synthetic_http']
    if (type(synthetic) is not dict or set(synthetic)!={'request_checked','response_checked','client_sink_checked'} or
            any(type(x) is not bool for x in synthetic.values()) or value['failure'] not in NATIVE_FAILURES or
            value['win32_error'] is not None and not integer(value['win32_error'])):raise ValueError('report')
    return value


def successful_native(value):
    front=value['role']=='pipe-front';p=value['pipe'];c=value['core'];s=value['synthetic_http']
    return (value['failure'] is None and value['win32_error'] is None and value['qpc'][3]<value['qpc'][2] and
            c=={'failure':0,'observations':177 if front else 78,'requested':7 if front else 56,
                'confirmed':7 if front else 56,'uncertain':0} and
            [p[k] for k in ('read_bytes','write_bytes','read_frames','write_frames')]==([96,144,2,3] if front else [144,96,3,2]) and
            p['inheritance_cleared'] and p['eof_observed'] and p['reader_close']=='confirmed' and p['writer_close']=='confirmed' and
            s==({'request_checked':True,'response_checked':True,'client_sink_checked':True} if front else
                {'request_checked':True,'response_checked':True,'client_sink_checked':False}))


class WindowsAPI:
    """Minimal exact-two-handle construction; no ordinary-token gate weakening."""
    def __init__(self):
        self.native=launcher.NativeAPI();self.k=self.native.k;self.proc=self.native.proc
        H,D=C.c_void_p,C.c_uint32
        self.k.CreatePipe.argtypes=[C.POINTER(H),C.POINTER(H),H,D];self.k.CreatePipe.restype=C.c_int
    def __getattr__(self,name):return getattr(self.native,name)
    def identity_owned(self,owners,process=None):
        token=self.native.current_token() if process is None else self.native.token_for_process(process)
        owners.add(token)
        # Keep query tokens owned until this ledger's finalizer; early close can
        # permit numeric HANDLE reuse before the second child's token acquisition.
        return self.native.identity(token)
    def owned_job(self,owners):
        job=self.k.CreateJobObjectW(None,None)
        self.native.check(job,'CreateJobObjectW');owners.add(job)
        limits=self.proc._JobExtendedLimitInfo();limits.BasicLimitInformation.LimitFlags=launcher.KILL_ON_JOB_CLOSE
        self.native.check(self.k.SetInformationJobObject(job,9,C.byref(limits),C.sizeof(limits)),'SetInformationJobObject')
        actual=self.proc._JobExtendedLimitInfo()
        self.native.check(self.k.QueryInformationJobObject(job,9,C.byref(actual),C.sizeof(actual),None),'QueryInformationJobObject')
        if actual.BasicLimitInformation.LimitFlags!=launcher.KILL_ON_JOB_CLOSE:raise ValueError('setup')
        return job
    def owned_pipe(self,owners):
        read,write=C.c_void_p(),C.c_void_p()
        sa=launcher.SecurityAttributes(C.sizeof(launcher.SecurityAttributes),None,True)
        try:
            ok=self.k.CreatePipe(C.byref(read),C.byref(write),C.byref(sa),4096)
            code=C.get_last_error() if not ok else 0
        finally:
            if read.value:owners.add(read.value)
            if write.value:owners.add(write.value)
        if not ok:raise launcher.NativeFailure('CreatePipe',code)
        return read.value,write.value
    def owned_create(self,info,command,work,data_handles,owners,state):
        H=C.c_void_p;size=C.c_size_t()
        self.k.InitializeProcThreadAttributeList(None,1,0,C.byref(size))
        if not 1<=size.value<=65536:raise ValueError('setup')
        attrs=C.create_string_buffer(size.value)
        self.native.check(self.k.InitializeProcThreadAttributeList(attrs,1,0,C.byref(size)),'InitializeProcThreadAttributeList')
        try:
            handles=(H*2)(*data_handles)
            self.native.check(self.k.UpdateProcThreadAttribute(attrs,0,0x20002,handles,C.sizeof(handles),None,None),'UpdateProcThreadAttribute')
            startup=self.proc._StartupInfoEx();startup.StartupInfo.cb=C.sizeof(startup);startup.lpAttributeList=C.cast(attrs,H)
            # No STARTF_USESTDHANDLES, SECURITY_CAPABILITIES or third inherited handle.
            env=C.create_unicode_buffer(self.native.environment(work))
            def create():
                ok=self.k.CreateProcessW(command[0],C.create_unicode_buffer(subprocess.list2cmdline(command)),None,None,True,
                    self.proc._CREATE_SUSPENDED|self.proc._CREATE_UNICODE_ENVIRONMENT|self.proc._EXTENDED_STARTUPINFO_PRESENT,
                    env,str(work),C.byref(startup),C.byref(info))
                return ok,(C.get_last_error() if not ok else 0)
            def check(result):
                if not result[0]:raise launcher.NativeFailure('CreateProcessW',result[1])
            pipe_helpers.create_suspended_owned(create,check,info,owners,state)
        finally:self.k.DeleteProcThreadAttributeList(attrs)


def _case_public(index):
    return {'case':index,'admitted':False,'created':0,'resumed':0,'exit_observed':0,'identity_verified':0,
            'parent_data_closed':False,'reports_bound':0,'observations':[0,0],'core_failure':[None,None],
            'pipe_eof':[False,False],'native_close':[False,False],'cleanup_confirmed':False,
            'job_empty':False,'watchdog_stop':False,'expected_outcome':False,'failure':None}


def _require(budget,cutoff):budget.require_ms(cutoff)


def _cleanup(api,budget,job,children,owners):
    uncertain=False;job_stop=False
    # Exact observed exits first, then one shared Job termination if needed.
    for child in children:
        if child['attempted'] and not child['info'].hProcess:uncertain=True
        if child['info'].hProcess:
            try:child['exited']=api.wait(child['info'].hProcess,0)
            except BaseException:uncertain=True
    if job is not None and any(c['info'].hProcess and not c['exited'] for c in children):
        try:api.terminate_job(job);job_stop=True
        except BaseException:uncertain=True
    # Unassigned partial creates are not covered by the Job. Attempt exact stop.
    for child in children:
        process=child['info'].hProcess
        if process and not child['exited'] and (not child['assigned'] or not job_stop):
            try:api.terminate_process(process)
            except BaseException:uncertain=True
    for child in children:
        process=child['info'].hProcess
        if process:
            try:
                remaining=budget.remaining_ms(budget.deadline,5000)
                child['exited']=api.wait(process,remaining) or child['exited']
                if child['exited']:child['exit_code']=api.exit_code(process)
                if budget.read()>=budget.deadline:uncertain=True
            except BaseException:uncertain=True
    empty=False
    if job is not None:
        try:
            while budget.remaining_ms(budget.deadline,5000)>0:
                if api.job_empty(job):empty=True;break
                api.sleep_ms(min(10,budget.remaining_ms(budget.deadline,10)))
            if budget.read()>=budget.deadline:uncertain=True
        except BaseException:uncertain=True
    else:empty=not any(c['attempted'] for c in children)
    # Preserve handles until exit observation; unknown exact owners remain retained.
    protected={c['info'].hProcess for c in children if c['info'].hProcess and not c['exited']}
    for handle in tuple(owners.pending):
        if handle in protected:continue
        try:owners.close(handle)
        except BaseException:uncertain=True
    confirmed=(not uncertain and owners.confirmed_closed and empty and
               all(not c['attempted'] or c['info'].hProcess and c['exited'] for c in children))
    if not confirmed:RETAINED.append((api,owners,children,job))
    return confirmed,empty,job_stop


def run_case(api,budget,root,actor,actor_hash,parent,run_id,case_id,index):
    retained_start=(len(pipe_helpers._RETAINED_FILES),len(launcher._RETAINED_PRIVATE_STREAMS))
    result=_case_public(index);private=[];owners=pipe_helpers.OneShotHandles(api.close)
    children=[{'info':api.process_info(),'attempted':False,'assigned':False,'exited':False,'exit_code':None} for _ in range(2)]
    job=None;data=[];work=root/str(index);start=end=None;watchdog=False;job_stop=False
    def fail(label):
        if result['failure'] is None:result['failure']=label
    try:
        _require(budget,budget.cutoff(30));work.mkdir();(work/'temp').mkdir()
        if shutil.disk_usage(work).free<actor.stat().st_size+2*MAX_NATIVE:raise ValueError('capacity')
        exe=work/'windows_identity_proxy_pipe_actor.exe'
        raw=pipe_helpers.read_bounded_file(actor,MAX_ACTOR)
        if hashlib.sha256(raw).hexdigest()!=actor_hash:raise ValueError('image')
        launcher.write_private_bytes(exe,raw);pipe_helpers.verify_copied_actor(exe,actor_hash)
        job=api.owned_job(owners)
        front_read,relay_write=api.owned_pipe(owners);relay_read,front_write=api.owned_pipe(owners)
        data=[front_read,relay_write,relay_read,front_write]
        start=budget.read();end=start+10*budget.frequency
        if end>0x7fffffffffffffff or end>budget.cutoff(30):raise ValueError('deadline')
        result['admitted']=True
        cases=[case_id,('0' if case_id[0]!='0' else '1')+case_id[1:] if index==1 else case_id]
        for role,child in enumerate(children):
            _require(budget,end)
            mode=('pipe-front','pipe-relay')[role];handles=(front_read,front_write) if role==0 else (relay_read,relay_write)
            report=work/(('front','relay')[role]+'.json')
            command=[str(exe),mode,run_id,cases[role],str(report),str(handles[0]),str(handles[1]),str(start),str(budget.frequency),str(end),parent['sid'],'none','1' if parent['elevated'] else '0']
            state={'creation_attempted':False}
            try:api.owned_create(child['info'],command,work,handles,owners,state)
            finally:
                child['attempted']=state['creation_attempted']
                if child['info'].hProcess:result['created']|=1<<role
            api.assign_job(job,child['info'].hProcess);child['assigned']=True
            api.verify_job(job,child['info'].hProcess);api.verify_image(child['info'].hProcess,exe)
            observed=api.identity_owned(owners,child['info'].hProcess)
            if not same_hosted_identity(observed,parent):raise ValueError('identity')
            pipe_helpers.verify_copied_actor(exe,actor_hash)
            result['identity_verified']|=1<<role
        # Attempt every parent data close even if one is uncertain. Never resume then.
        for handle in data:
            try:owners.close(handle)
            except BaseException:fail('close')
        result['parent_data_closed']=not owners.uncertain and all(h in owners.attempted for h in data)
        if not result['parent_data_closed']:raise ValueError('close')
        for role,child in enumerate(children):
            if index==2 and role==1:continue
            _require(budget,end);api.resume(child['info'].hThread);result['resumed']|=1<<role
        for role,child in enumerate(children):
            if index==2 and role==1:continue
            while budget.remaining_ms(end,100)>0:
                if api.wait(child['info'].hProcess,budget.remaining_ms(end,100)):
                    child['exited']=True;child['exit_code']=api.exit_code(child['info'].hProcess);break
            late=budget.read()>=end
            if index==2 and role==0:watchdog=late and not child['exited']
            elif late or not child['exited']:fail('deadline')
    except BaseException as exc:
        fail(str(exc) if type(exc) is ValueError and str(exc) in FAILURES else 'setup')
    finally:
        try:result['cleanup_confirmed'],result['job_empty'],job_stop=_cleanup(api,budget,job,children,owners)
        except BaseException:RETAINED.append((api,owners,children,job));fail('cleanup')
        result['watchdog_stop']=watchdog and job_stop
        result['exit_observed']=sum(1<<i for i,c in enumerate(children) if c['exited'])
        if not result['cleanup_confirmed']:fail('cleanup')
    # No native report is trusted before the exact held process exit was observed.
    image_stable=False
    if start is not None:
        try:
            pipe_helpers.verify_copied_actor(work/'windows_identity_proxy_pipe_actor.exe',actor_hash);image_stable=True
        except BaseException:fail('image')
    if start is not None and image_stable:
        cases=[case_id,('0' if case_id[0]!='0' else '1')+case_id[1:] if index==1 else case_id]
        for role,child in enumerate(children):
            if not child['exited'] or not result['identity_verified']&(1<<role):continue
            try:
                _require(budget,budget.deadline)
                value,raw=bounded_json(work/(('front','relay')[role]+'.json'),MAX_NATIVE,inside=work)
                value=validate_native(value,role=('pipe-front','pipe-relay')[role],run_id=run_id,case_id=cases[role],
                    pid=int(child['info'].dwProcessId),identity=parent,frequency=budget.frequency,start=start,end=end)
                private.append({'role':role,'sha256':hashlib.sha256(raw).hexdigest(),'bytes':len(raw),'report':value})
                result['reports_bound']|=1<<role;result['observations'][role]=value['core']['observations']
                result['core_failure'][role]=value['core']['failure'];result['pipe_eof'][role]=value['pipe']['eof_observed']
                result['native_close'][role]=all(value['pipe'][k]=='confirmed' for k in ('reader_close','writer_close'))
            except BaseException:
                if index!=2:fail('report')
        if index==0:
            result['expected_outcome']=(len(private)==2 and all(successful_native(v['report']) for v in private) and all(c['exit_code']==0 for c in children))
        elif index==1:
            bound={v['role']:v['report'] for v in private}
            front,relay=bound.get(0),bound.get(1)
            result['expected_outcome']=(result['reports_bound']==3 and
                front['failure']=='core' and front['win32_error'] is None and front['core']['failure']==2 and
                relay['failure']=='pipe_read' and relay['win32_error']==109 and relay['core']['failure']==0 and
                front['core']['observations']==0 and relay['core']['observations']==0 and
                [front['pipe'][k] for k in ('read_bytes','write_bytes','read_frames','write_frames')]==[48,0,0,0] and
                [relay['pipe'][k] for k in ('read_bytes','write_bytes','read_frames','write_frames')]==[0,48,0,1] and
                all(v['pipe']['inheritance_cleared'] and all(v['pipe'][k]=='confirmed' for k in ('reader_close','writer_close')) for v in (front,relay)) and
                all(c['exit_code']==5 for c in children))
        else:
            result['expected_outcome']=(result['watchdog_stop'] and result['resumed']==1 and result['created']==3 and result['exit_observed']==3 and
                result['reports_bound'] in (0,1) and (not private or result['core_failure'][0]==9))
        result['expected_outcome'] &= result['failure'] is None and result['cleanup_confirmed'] and result['parent_data_closed'] and result['identity_verified']==3
    if retained_start!=(len(pipe_helpers._RETAINED_FILES),len(launcher._RETAINED_PRIVATE_STREAMS)):
        result['cleanup_confirmed']=False;result['expected_outcome']=False;fail('cleanup')
    return result,private


def verify_artifact(actor,manifest,manifest_hash):
    actor=launcher.checked_path(actor);manifest=launcher.checked_path(manifest)
    if actor.name!='windows_identity_proxy_pipe_actor.exe' or manifest.name!='identity-proxy-pipe-manifest.json' or actor.parent!=manifest.parent or not digest(manifest_hash):raise ValueError('configuration')
    value,raw=bounded_json(manifest,MAX_NATIVE)
    if hashlib.sha256(raw).hexdigest()!=manifest_hash:raise ValueError('configuration')
    keys={'schemaVersion','compileOnly','runtimeAcceptance','actorSourceSha256','identitySourceSha256','coreSha256','executableSha256'}
    if (set(value)!=keys or not integer(value['schemaVersion'],1,1) or value['compileOnly'] is not True or value['runtimeAcceptance'] is not False):raise ValueError('configuration')
    for key,path in (('actorSourceSha256','.github/native/windows_identity_proxy_pipe_actor.cpp'),
                     ('identitySourceSha256','.github/native/windows_identity_actor.cpp'),
                     ('coreSha256','.github/native/windows_identity_proxy_bridge_core.hpp')):
        if not digest(value[key]) or hashlib.sha256(pipe_helpers.read_bounded_file(ROOT/path,MAX_ACTOR)).hexdigest()!=value[key]:raise ValueError('configuration')
    if not digest(value['executableSha256']):raise ValueError('configuration')
    pipe_helpers.verify_copied_actor(actor,value['executableSha256'])
    return actor,value['executableSha256']


def run_suite(api,actor,manifest,manifest_hash,work,*,ids=secrets.token_hex,artifact_verifier=verify_artifact):
    frequency=api.qpc_frequency();initial=api.qpc()
    if not integer(frequency,1,1000000000) or not integer(initial,0,0x7fffffffffffffff-60*frequency):raise ValueError('deadline')
    budget=launcher.QpcBudget(api,initial+60*frequency,frequency)
    public={'schema_version':1,'stage':'native-proxy-pipe-mechanics','network_tested':False,'proxy_tested':False,
            'product_acceptance':False,'synthetic_http_only':True,'controller_elevated':None,'actor_sha256':None,
            'cases':[_case_public(i) for i in range(3)],'suite_complete':False,'cleanup_confirmed':False,'failure':None}
    retained_start=(len(pipe_helpers._RETAINED_FILES),len(launcher._RETAINED_PRIVATE_STREAMS))
    owners=pipe_helpers.OneShotHandles(api.close);private=[];root=None
    try:
        actor,actor_hash=artifact_verifier(actor,manifest,manifest_hash);public['actor_sha256']=actor_hash
        _require(budget,budget.cutoff(30))
        parent=api.identity_owned(owners)
        if not current_identity(parent):raise ValueError('identity')
        public['controller_elevated']=parent['elevated']
        root=Path(work)
        if not root.is_absolute() or root.exists() or root.parent.resolve(strict=True)!=root.parent:raise ValueError('configuration')
        measured_sources=sum((ROOT/name).stat().st_size for name in (
            '.github/windows_identity_proxy_pipe_probe.py','.github/native/windows_identity_proxy_pipe_actor.cpp',
            '.github/build_windows_identity_proxy_pipe_actor.ps1','tests/test_windows_identity_proxy_pipe_probe.py',
            'docs/validation/2026-10-22-native-proxy-pipe-mechanics.md'))
        required=3*actor.stat().st_size+6*MAX_NATIVE+MAX_PRIVATE+MAX_PUBLIC+measured_sources
        if required>PLANNING_LIMIT or shutil.disk_usage(root.parent).free<required:raise ValueError('capacity')
        root.mkdir();run_id=ids(16)
        if not nonce(run_id):raise ValueError('configuration')
        seen={run_id}
        for index in range(3):
            case_id=ids(16)
            if not nonce(case_id) or case_id in seen:raise ValueError('configuration')
            seen.add(case_id)
            result,reports=run_case(api,budget,root,actor,actor_hash,parent,run_id,case_id,index)
            public['cases'][index]=result;private.append({'case':index,'run_id':run_id,'case_id':case_id,'reports':reports})
            if not result['cleanup_confirmed']:break
            if budget.read()>=budget.cutoff(30):break
        public['cleanup_confirmed']=owners.confirmed_closed and all(c['cleanup_confirmed'] for c in public['cases'])
        public['suite_complete']=public['cleanup_confirmed'] and all(c['expected_outcome'] for c in public['cases'])
        raw=(json.dumps(private,separators=(',',':'))+'\n').encode('utf-8')
        if len(raw)>MAX_PRIVATE:raise ValueError('report')
        _require(budget,budget.deadline)
        launcher.write_private_bytes(root/'private.json',raw)
        _require(budget,budget.deadline)
    except BaseException as exc:
        public['failure']=str(exc) if type(exc) is ValueError and str(exc) in FAILURES else 'internal'
        public['suite_complete']=False
    finally:
        for handle in tuple(owners.pending):
            try:owners.close(handle)
            except BaseException:public['cleanup_confirmed']=False;public['suite_complete']=False
        if not owners.confirmed_closed:RETAINED.append((api,owners))
        public['cleanup_confirmed']=owners.confirmed_closed and all(c['cleanup_confirmed'] for c in public['cases'])
        public['suite_complete']=public['failure'] is None and public['cleanup_confirmed'] and all(c['expected_outcome'] for c in public['cases'])
    raw=(json.dumps(public,separators=(',',':'))+'\n').encode('ascii')
    if len(raw)>MAX_PUBLIC:raise ValueError('report')
    try:
        _require(budget,budget.deadline)
    except BaseException:
        public['suite_complete']=False;public['failure']='deadline'
    if retained_start!=(len(pipe_helpers._RETAINED_FILES),len(launcher._RETAINED_PRIVATE_STREAMS)):
        public['cleanup_confirmed']=False;public['suite_complete']=False;public['failure']='cleanup'
    # Only stdout may publish this final receipt; no earlier public file exists.
    return public


def public_bytes(value):
    raw=(json.dumps(value,separators=(',',':'))+'\n').encode('ascii')
    if len(raw)>MAX_PUBLIC:raise ValueError('report')
    return raw


def emit_public(value,stream):
    """One bounded write and flush; delivery/EOF is the future owner's evidence."""
    try:
        raw=public_bytes(value)
        if stream.write(raw)!=len(raw):return False
        stream.flush()
        return True
    except BaseException:return False


def accept_public(raw,exit_code,eof_observed):
    """Pure future-owner boundary, not a process launch or delivery simulation."""
    if (type(raw) is not bytes or not 1<=len(raw)<=MAX_PUBLIC or type(exit_code) is not int or
            exit_code!=0 or eof_observed is not True or not raw.endswith(b'\n')):return False
    line=raw[:-2] if raw.endswith(b'\r\n') else raw[:-1]
    if b'\r' in line or b'\n' in line:return False
    try:
        value=json.loads(line.decode('ascii'),object_pairs_hook=unique,
                         parse_constant=lambda _:(_ for _ in ()).throw(ValueError('report')))
        if (type(value) is not dict or set(value)!={'schema_version','stage','network_tested','proxy_tested',
             'product_acceptance','synthetic_http_only','controller_elevated','actor_sha256','cases',
             'suite_complete','cleanup_confirmed','failure'} or not integer(value['schema_version'],1,1) or
             value['stage']!='native-proxy-pipe-mechanics' or value['suite_complete'] is not True or
             value['cleanup_confirmed'] is not True or value['failure'] is not None or
             value['synthetic_http_only'] is not True or type(value['controller_elevated']) is not bool or
             not digest(value['actor_sha256']) or any(value[k] is not False for k in ('network_tested','proxy_tested','product_acceptance')) or
             type(value['cases']) is not list or len(value['cases'])!=3):return False
        for index,case in enumerate(value['cases']):
            if type(case) is not dict or set(case)!=set(_case_public(index)) or not integer(case['case'],index,index):return False
            for key in ('admitted','parent_data_closed','cleanup_confirmed','job_empty','expected_outcome'):
                if case[key] is not True:return False
            for key in ('watchdog_stop',):
                if type(case[key]) is not bool:return False
            for key in ('created','resumed','exit_observed','identity_verified','reports_bound'):
                if not integer(case[key],0,3):return False
            for key in ('pipe_eof','native_close'):
                if type(case[key]) is not list or len(case[key])!=2 or any(type(x) is not bool for x in case[key]):return False
            if (type(case['observations']) is not list or len(case['observations'])!=2 or
                    any(not integer(x,0,255) for x in case['observations']) or
                    type(case['core_failure']) is not list or len(case['core_failure'])!=2 or
                    any(x is not None and not integer(x,0,11) for x in case['core_failure']) or case['failure'] is not None):return False
            if any(case[key]!=3 for key in ('created','exit_observed','identity_verified')):return False
            if case['resumed']!=(1 if index==2 else 3) or case['watchdog_stop']!=(index==2):return False
            if index<2 and (case['reports_bound']!=3 or case['native_close']!=[True,True]):return False
            if index==0 and (case['observations']!=[177,78] or case['core_failure']!=[0,0] or case['pipe_eof']!=[True,True]):return False
            if index==1 and (case['observations']!=[0,0] or case['core_failure']!=[2,0] or case['pipe_eof']!=[False,False]):return False
            if index==2:
                if case['reports_bound'] not in (0,1):return False
                for slot in (0,1):
                    if not case['reports_bound']&(1<<slot):
                        if (case['observations'][slot]!=0 or case['core_failure'][slot] is not None or
                                case['pipe_eof'][slot] is not False or case['native_close'][slot] is not False):return False
                if case['reports_bound']==1 and (case['core_failure'][0]!=9 or case['observations'][0]&~177):return False
        return True
    except (ValueError,UnicodeError,RecursionError,TypeError):return False


def main(argv=None):
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--run-native-pipe',action='store_true')
    parser.add_argument('--actor',type=Path);parser.add_argument('--manifest',type=Path)
    parser.add_argument('--expected-manifest-sha256');parser.add_argument('--work',type=Path)
    args=parser.parse_args(argv)
    if not args.run_native_pipe or os.name!='nt' or any(x is None for x in (args.actor,args.manifest,args.expected_manifest_sha256,args.work)):
        raise SystemExit('explicit approved Windows mechanics invocation required')
    try:result=run_suite(WindowsAPI(),args.actor,args.manifest,args.expected_manifest_sha256,args.work)
    except BaseException:
        result={'schema_version':1,'stage':'native-proxy-pipe-mechanics','suite_complete':False,'failure':'internal','product_acceptance':False}
    emitted=emit_public(result,sys.stdout.buffer)
    return 0 if emitted and result['suite_complete'] else 1


if __name__=='__main__':raise SystemExit(main())
