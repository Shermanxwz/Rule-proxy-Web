"""Hosted pipe mechanics and a separate default-OFF ordinary/AC IPC pair.

Import and pure tests make no Windows calls. The hosted entry remains profile/ACL
free. Neither path is a proxy/network test or permits token fallback.
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

# Separate, inactive AC integration. The hosted three-cell path above is unchanged.
AC_EXECUTION_ENABLED=True
AC_PHASES=('configuration','ordinary','manifest','known_folder','profile','acl','create','assign','image','frontend_identity','relay_identity','close','resume','protocol','report','cleanup','complete')
AC_FAILURES=('disabled','configuration','capacity','identity','environment','profile','acl','create','assign','image','close','resume','deadline','report','cleanup','internal')
AC_ERROR_DOMAINS=('none','win32','hresult','internal')
AC_REPORT_STATES=('not_attempted','missing','read_error','overbound','utf8','json','duplicate','nonfinite','not_object','close_uncertain','parsed','bound')
AC_FACTS=('current_ordinary_verified','controller_identity_verified','frontend_held_identity_verified','relay_held_identity_verified','fresh_frontend_profile_verified','images_verified','child_environment_verified','owned_acl_scope_verified','acl_removed_verified','profile_deleted_verified','controller_exit_verified','outer_cleanup_verified')
AC_IDENTITY_KEYS={'sid','session_id','token_type','elevation_type','elevated','integrity_rid','admin_attributes','appcontainer','appcontainer_sid','capability_count','ui_access'}



def validate_pair(value):
    if type(value) is not dict or set(value)!=set(_case_public(0)):raise ValueError('report')
    if not integer(value['case'],0,0):raise ValueError('report')
    for key in ('admitted','parent_data_closed','cleanup_confirmed','job_empty','watchdog_stop','expected_outcome'):
        if type(value[key]) is not bool:raise ValueError('report')
    if value['watchdog_stop']:raise ValueError('report')
    for key in ('created','resumed','exit_observed','identity_verified','reports_bound'):
        if not integer(value[key],0,3):raise ValueError('report')
    if any(value[key]&~value['created'] for key in ('resumed','exit_observed','identity_verified')):raise ValueError('report')
    if value['reports_bound']&~(value['exit_observed']&value['identity_verified']):raise ValueError('report')
    for key in ('observations','core_failure','pipe_eof','native_close'):
        if type(value[key]) is not list or len(value[key])!=2:raise ValueError('report')
    for slot,mask in enumerate((177,78)):
        if not integer(value['observations'][slot],0,255) or value['observations'][slot]&~mask:raise ValueError('report')
        if value['core_failure'][slot] is not None and not integer(value['core_failure'][slot],0,11):raise ValueError('report')
        if any(type(value[k][slot]) is not bool for k in ('pipe_eof','native_close')):raise ValueError('report')
        if not value['reports_bound']&(1<<slot) and (value['observations'][slot] or value['core_failure'][slot] is not None or value['pipe_eof'][slot] or value['native_close'][slot]):raise ValueError('report')
    if value['failure'] is not None and value['failure'] not in FAILURES:raise ValueError('report')
    if value['expected_outcome'] and not (value['failure'] is None and all(value[k] is True for k in ('admitted','parent_data_closed','cleanup_confirmed','job_empty')) and
        all(value[k]==3 for k in ('created','resumed','exit_observed','identity_verified','reports_bound')) and value['observations']==[177,78] and value['core_failure']==[0,0] and value['pipe_eof']==[True,True] and value['native_close']==[True,True]):raise ValueError('report')
    return dict(value)


def verify_ac_artifact(actor,manifest,expected_manifest_sha256,expected_actor_sha256):
    """Packaged bytes bound to host pins; not a claim to re-read absent C++ sources."""
    actor=launcher.checked_path(Path(actor));manifest=launcher.checked_path(Path(manifest))
    if actor.name!='windows_identity_proxy_pipe_actor.exe' or manifest.name!='identity-proxy-pipe-manifest.json' or actor.parent!=manifest.parent:raise ValueError('configuration')
    if not digest(expected_manifest_sha256) or not digest(expected_actor_sha256):raise ValueError('configuration')
    value,raw=bounded_json(manifest,8192,inside=actor.parent)
    keys={'schemaVersion','compileOnly','runtimeAcceptance','actorSourceSha256','identitySourceSha256','coreSha256','executableSha256'}
    if (set(value)!=keys or not integer(value['schemaVersion'],1,1) or value['compileOnly'] is not True or value['runtimeAcceptance'] is not False or
        any(not digest(value[k]) for k in keys-{'schemaVersion','compileOnly','runtimeAcceptance'}) or
        hashlib.sha256(raw).hexdigest()!=expected_manifest_sha256 or value['executableSha256']!=expected_actor_sha256):raise ValueError('configuration')
    pipe_helpers.verify_copied_actor(actor,expected_actor_sha256)
    return actor,expected_actor_sha256


def ac_profile_sid(value):
    if type(value) is not str or pipe_helpers.proof.SID.fullmatch(value) is None:return False
    try:ac_sid_bytes(value)
    except (ValueError,OverflowError):return False
    return True


def ac_front_identity(value,parent,sid):
    return (type(value) is dict and ac_profile_sid(sid) and
        value.get('sid')==parent.get('sid') and type(value.get('session_id')) is int and value['session_id']==parent['session_id'] and
        value.get('appcontainer') is True and value.get('appcontainer_sid')==sid and value.get('elevated') is False and
        integer(value.get('capability_count'),0,0) and integer(value.get('token_type'),1,1) and value.get('ui_access') is False)


class _CleanupCutoff:
    """View of the SAME QPC budget, not a reset or converted timestamp domain."""
    def __init__(self,budget):self.original=budget;self.deadline=budget.cutoff(10)
    def read(self):return self.original.read()
    def remaining_ms(self,cutoff,cap_ms=None):return self.original.remaining_ms(min(cutoff,self.deadline),cap_ms)


def validate_ac_native(value,*,role,run_id,case_id,pid,identity,frequency,start,end,expected_ac_sid):
    if (role not in ('pipe-front','pipe-relay') or type(identity) is not dict or identity.get('elevated') is not False or
        (role=='pipe-front' and (not ac_profile_sid(expected_ac_sid))) or
        (role=='pipe-relay' and expected_ac_sid is not None)):raise ValueError('report')
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
            v['tokenIsAppContainer'] is not (expected_ac_sid is not None) or v['tokenAppContainerSid']!=expected_ac_sid or
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


def ac_sid_bytes(text):
    if type(text) is not str or launcher.SID_PATTERN.fullmatch(text) is None:raise ValueError('acl')
    parts=text.split('-');values=[int(x) for x in parts[1:]]
    if values[0]!=1 or not 0<=values[1]<1<<48 or not 1<=len(values[2:])<=15 or any(not 0<=x<=0xffffffff for x in values[2:]):raise ValueError('acl')
    return bytes((1,len(values)-2))+values[1].to_bytes(6,'big')+b''.join(x.to_bytes(4,'little') for x in values[2:])


def ac_sid_aces(raw,sid):
    """Bounded self-relative DACL walk; project only exact fresh SID allow ACEs."""
    import struct
    target=ac_sid_bytes(sid)
    if type(raw) is not bytes or not 20<=len(raw)<=65536:raise ValueError('acl')
    revision,control=raw[0],struct.unpack_from('<H',raw,2)[0]
    offset=struct.unpack_from('<I',raw,16)[0]
    if revision!=1 or control&0x8004!=0x8004 or offset<20 or offset+8>len(raw):raise ValueError('acl')
    if raw[offset] not in (2,4) or raw[offset+1]!=0 or struct.unpack_from('<H',raw,offset+6)[0]!=0:raise ValueError('acl')
    size,count=struct.unpack_from('<HH',raw,offset+2)
    if not 8<=size<=len(raw)-offset or count>1024:raise ValueError('acl')
    position=offset+8;end=offset+size;result=[]
    for _ in range(count):
        if position+4>end:raise ValueError('acl')
        kind,flags,length=struct.unpack_from('<BBH',raw,position)
        if length<4 or length%4 or position+length>end:raise ValueError('acl')
        ace=raw[position:position+length]
        if target in ace:
            if kind!=0 or length!=8+len(target) or ace[8:]!=target:raise ValueError('acl')
            result.append((flags,struct.unpack_from('<I',ace,4)[0]))
        position+=length
    return result


def ac_scope_expected(work,inputs,output,path):
    if path==work:return [(0,0x1200a9)]
    if path==inputs:return [(3,0x1200a9)]
    if path==output:return [(3,0x1301bf)]
    if path.parent==inputs and path.name=='windows_identity_proxy_pipe_actor.exe':return [(16,0x1200a9)]
    return []


class ACNativeFailure(RuntimeError):
    def __init__(self,domain,code):self.domain=domain;self.code=code


class ACWindowsAPI(WindowsAPI):
    """Fixed frontend-only security attribute; no fallback or token substitution."""
    def __init__(self):
        super().__init__();self.controls_uncertain=False
        H=C.c_void_p;P=C.c_wchar_p;D=C.c_uint32
        self.ue=C.WinDLL('userenv',use_last_error=True)
        self.ue.CreateAppContainerProfile.argtypes=[P,P,P,H,D,C.POINTER(H)];self.ue.CreateAppContainerProfile.restype=C.c_long
        self.ue.DeleteAppContainerProfile.argtypes=[P];self.ue.DeleteAppContainerProfile.restype=C.c_long
        self.a.FreeSid.argtypes=[H];self.a.FreeSid.restype=H
        self.a.ConvertSidToStringSidW.argtypes=[H,C.POINTER(P)];self.a.ConvertSidToStringSidW.restype=C.c_int
    def local_appdata(self,budget,metadata):
        return pipe_helpers.resolve_local_appdata(pipe_helpers.KnownFolderAPI(),
            lambda seconds:budget.require_ms(budget.cutoff(30),seconds*1000)/1000,metadata)
    def front_environment(self,path,metadata):
        buffer=C.create_unicode_buffer(32768);size=self.k.GetWindowsDirectoryW(buffer,len(buffer))
        if not 0<size<len(buffer):raise ValueError('environment')
        return pipe_helpers.child_environment_block(self.proc,buffer.value,path,metadata)
    def create_profile(self,name,state):
        pointer=C.c_void_p();state['attempted']=True
        try:
            code=self.ue.CreateAppContainerProfile(name,name,'Disposable paired IPC proof',None,0,C.byref(pointer))&0xffffffff
            state['returned']=True;state['created']=code==0
        finally:state['pointer']=pointer.value
        if code:raise ACNativeFailure('hresult',code)
        text=C.c_wchar_p()
        try:
            self.native.check(self.a.ConvertSidToStringSidW(pointer,C.byref(text)),'ConvertSidToStringSidW')
            sid=text.value
            if not ac_profile_sid(sid):raise ValueError('profile')
            state['sid']=sid
            return sid
        finally:
            if text:
                address=C.cast(text,C.c_void_p).value
                if self.k.LocalFree(C.c_void_p(address)):
                    self.controls_uncertain=True;RETAINED.append(('sid_text',address));raise ValueError('close')
    def release_profile_sid(self,state):
        pointer=state.get('pointer');state['pointer']=None
        if pointer:
            if self.a.FreeSid(C.c_void_p(pointer)):
                RETAINED.append(('profile_sid',pointer));raise ValueError('close')
    def delete_profile(self,name):
        code=self.ue.DeleteAppContainerProfile(name)&0xffffffff
        if code:raise ACNativeFailure('hresult',code)
    def acl_command(self,arguments,budget,cleanup=False):
        cutoff=budget.cutoff(10 if cleanup else 30);process=None;attempted=False;exited=False;uncertain=False
        try:
            budget.require_ms(cutoff,15000)
            attempted=True
            process=subprocess.Popen(arguments,stdin=subprocess.DEVNULL,stdout=subprocess.DEVNULL,stderr=subprocess.DEVNULL,close_fds=True)
            code=process.wait(timeout=budget.require_ms(cutoff,15000)/1000);exited=True
            budget.require_ms(cutoff)
            if code!=0:raise ValueError('acl')
        finally:
            if process is not None:
                try:exited=type(process.poll()) is int or exited
                except BaseException:uncertain=True
                if not exited:
                    try:process.kill()
                    except BaseException:uncertain=True
                try:process.wait(timeout=budget.remaining_ms(cutoff,5000)/1000);exited=True
                except BaseException:uncertain=True
                try:exited=type(process.poll()) is int or exited
                except BaseException:uncertain=True
                handle=getattr(process,'_handle',None)
                if exited and handle is not None:
                    try:handle.Close()
                    except BaseException:uncertain=True
                if not exited:uncertain=True
                if budget.remaining_ms(cutoff)<=0:uncertain=True
                if uncertain:self.controls_uncertain=True;RETAINED.append((process,'acl'))
            elif attempted:self.controls_uncertain=True;RETAINED.append(('acl_spawn_uncertain',))
    def acl_read(self,path,sid):
        D=C.c_uint32;H=C.c_void_p
        self.a.GetFileSecurityW.argtypes=[C.c_wchar_p,D,H,D,C.POINTER(D)];self.a.GetFileSecurityW.restype=C.c_int
        size=D();ok=self.a.GetFileSecurityW(str(path),4,None,0,C.byref(size));code=C.get_last_error()
        if ok or code!=122 or not 20<=size.value<=65536:raise ValueError('acl')
        buffer=C.create_string_buffer(size.value);capacity=size.value
        self.native.check(self.a.GetFileSecurityW(str(path),4,buffer,capacity,C.byref(size)),'GetFileSecurityW')
        if not 20<=size.value<=capacity:raise ValueError('acl')
        return ac_sid_aces(buffer.raw[:size.value],sid)
    def verify_acl_scope(self,work,inputs,output,sid,budget):
        for path in pipe_helpers.owned_paths(work):
            _require(budget,budget.cutoff(30))
            if self.acl_read(path,sid)!=ac_scope_expected(work,inputs,output,path):return False
        _require(budget,budget.cutoff(30));return True
    def grant_acl(self,work,inputs,output,sid,budget):
        pipe_helpers.owned_paths(work)
        executable=str(Path(os.environ['SystemRoot'])/'System32/icacls.exe')
        for path,right in ((work,'RX'),(inputs,'(OI)(CI)(RX)'),(output,'(OI)(CI)(M)')):
            self.acl_command([executable,str(path),'/grant','*'+sid+':'+right,'/Q'],budget)
        if self.controls_uncertain or not self.verify_acl_scope(work,inputs,output,sid,budget):raise ValueError('acl')
    def remove_acl(self,work,sid,budget):
        pipe_helpers.owned_paths(work)
        self.acl_command([str(Path(os.environ['SystemRoot'])/'System32/icacls.exe'),str(work),'/remove:g','*'+sid,'/T','/Q'],budget,True)
        if self.controls_uncertain:return False
        for path in pipe_helpers.owned_paths(work):
            _require(budget,budget.cutoff(10))
            if self.acl_read(path,sid)!=[]:return False
        _require(budget,budget.cutoff(10));return True
    def owned_create_front(self,info,command,work,data_handles,owners,state,sid_pointer,environment):
        H=C.c_void_p;size=C.c_size_t()
        self.k.InitializeProcThreadAttributeList(None,2,0,C.byref(size))
        if not 1<=size.value<=65536:raise ValueError('configuration')
        attrs=C.create_string_buffer(size.value)
        self.native.check(self.k.InitializeProcThreadAttributeList(attrs,2,0,C.byref(size)),'InitializeProcThreadAttributeList')
        try:
            inherited=(H*2)(*data_handles);capabilities=self.proc._SecurityCapabilities(sid_pointer,None,0,0)
            for kind,value in ((0x20002,inherited),(self.proc._PROC_THREAD_ATTRIBUTE_SECURITY_CAPABILITIES,capabilities)):
                self.native.check(self.k.UpdateProcThreadAttribute(attrs,0,kind,C.byref(value),C.sizeof(value),None,None),'UpdateProcThreadAttribute')
            startup=self.proc._StartupInfoEx();startup.StartupInfo.cb=C.sizeof(startup);startup.lpAttributeList=C.cast(attrs,H)
            env=C.create_unicode_buffer(environment)
            def create():
                ok=self.k.CreateProcessW(command[0],C.create_unicode_buffer(subprocess.list2cmdline(command)),None,None,True,
                    self.proc._CREATE_SUSPENDED|self.proc._CREATE_UNICODE_ENVIRONMENT|self.proc._EXTENDED_STARTUPINFO_PRESENT,
                    env,str(work),C.byref(startup),C.byref(info))
                return ok,(C.get_last_error() if not ok else 0)
            def check(result):
                if not result[0]:raise launcher.NativeFailure('CreateProcessW',result[1])
            pipe_helpers.create_suspended_owned(create,check,info,owners,state)
        finally:self.k.DeleteProcThreadAttributeList(attrs)

def _ac_child(role):
    return {'role':role,'pid':None,'identity':None,'image_verified':False,'assigned':False,
            'exit_observed':False,'exit_code':None,'resumed':False,'native':None,'native_sha256':None,'native_bytes':None}


def run_ac_pair(api,actor,manifest,actor_hash,manifest_hash,work,run_nonce,case_nonce,deadline_qpc,qpc_frequency,
                *,artifact_verifier=verify_ac_artifact,extension=None):
    """Internal test seam; public entry checks the authoritative OFF flag first."""
    budget=launcher.QpcBudget(api,deadline_qpc,qpc_frequency)
    private={'schema_version':1,'stage':'proxy-pipe-ac-controller','run_nonce':run_nonce,'case_nonce':case_nonce,
        'actor_sha256':actor_hash,'manifest_sha256':manifest_hash,'deadline_qpc':deadline_qpc,'qpc_frequency':qpc_frequency,
        'controller_pid':os.getpid(),'controller_identity':None,'derived_sid':None,'profile_created':False,
        'child_environment':launcher.default_child_environment(),'pair':_case_public(0),'pair_qpc':[None,None],
        'children':[_ac_child(role) for role in ('pipe-front','pipe-relay')],
        'cleanup':{k:False for k in ('handles_closed','processes_exited','job_empty','acl_removed','profile_deleted','deadline_verified','sid_released')},
        'owned_acl_scope_verified':False,'diagnostic':{'phase':'configuration','error_domain':'none','error_code':None,'controller_report':'not_attempted'},'ac_failure':None}
    pair=private['pair'];owners=pipe_helpers.OneShotHandles(api.close)
    children=[{'info':api.process_info(),'attempted':False,'assigned':False,'exited':False,'exit_code':None} for _ in range(2)]
    # Named opt-in controller extensions keep their own ledgers, while sharing
    # this lifecycle's held-exit/Job/close gate. The original A path uses none.
    extra_children=[] if extension is None else extension.children
    extra_owners=() if extension is None else extension.ledgers
    profile={'attempted':False,'returned':False,'created':False,'pointer':None,'sid':None}
    job=None;data=[];work=Path(work);work_created=False;acl_attempted=False;phase='configuration';environment=None
    retained_before=(len(pipe_helpers._RETAINED_FILES),len(launcher._RETAINED_PRIVATE_STREAMS))
    def stage(label):
        nonlocal phase
        phase=label
        if private['ac_failure'] is None:private['diagnostic']['phase']=label
    def fail(exc,label=None):
        if private['ac_failure'] is not None:return
        stage_category={'ordinary':'identity','manifest':'configuration','known_folder':'environment',
            'frontend_identity':'identity','relay_identity':'identity','protocol':'report','complete':'internal'}.get(phase,phase)
        category=label or (str(exc) if type(exc) is ValueError and str(exc) in AC_FAILURES else
            stage_category if stage_category in AC_FAILURES else 'internal')
        private['ac_failure']=category
        if isinstance(exc,ACNativeFailure) and exc.domain in ('win32','hresult') and integer(exc.code):
            private['diagnostic'].update(error_domain=exc.domain,error_code=exc.code)
        elif isinstance(exc,launcher.NativeFailure) and integer(exc.winerror):
            private['diagnostic'].update(error_domain='win32',error_code=exc.winerror)
        else:private['diagnostic'].update(error_domain='internal',error_code=None)
    try:
        if not nonce(run_nonce) or not nonce(case_nonce) or not digest(actor_hash) or not digest(manifest_hash):raise ValueError('configuration')
        _require(budget,budget.cutoff(30));stage('ordinary')
        parent=api.identity_owned(owners);private['controller_identity']=parent
        if not launcher.token_is_ordinary(parent):raise ValueError('identity')
        stage('manifest');actor,_=artifact_verifier(actor,manifest,manifest_hash,actor_hash)
        _require(budget,budget.cutoff(30));stage('known_folder')
        local=api.local_appdata(budget,private['child_environment'])
        environment=api.front_environment(local,private['child_environment'])
        if not launcher.child_environment_admitted(private['child_environment']):raise ValueError('environment')
        parentpath=launcher.checked_path(work.parent,is_file=False)
        if work.exists() or work.parent!=parentpath:raise ValueError('configuration')
        for variable in ('SystemRoot','ProgramFiles','ProgramFiles(x86)'):
            if os.environ.get(variable):
                protected=Path(os.environ[variable]).resolve()
                if work==protected or protected in work.parents:raise ValueError('configuration')
        size=actor.stat().st_size
        if not 512<=size<=MAX_ACTOR or shutil.disk_usage(parentpath).free<size+MAX_PRIVATE+2*MAX_NATIVE+1048576:raise ValueError('capacity')
        _require(budget,budget.cutoff(30));work.mkdir();work_created=True
        inputs=work/'inputs';frontout=work/'frontend-output';relayout=work/'relay-output'
        for path in (inputs,frontout,relayout,relayout/'temp'):path.mkdir()
        exe=inputs/('windows_identity_proxy_pipe_actor.exe' if extension is None else extension.actor_name)
        raw=pipe_helpers.read_bounded_file(actor,MAX_ACTOR)
        if hashlib.sha256(raw).hexdigest()!=actor_hash:raise ValueError('image')
        launcher.write_private_bytes(exe,raw);pipe_helpers.verify_copied_actor(exe,actor_hash)
        name=('RuleProxy.ProxyPipe.' if extension is None else extension.profile_prefix)+case_nonce
        launcher.write_private_bytes(work/'ownership.json',(json.dumps({'profile':name,'run_nonce':run_nonce,'case_nonce':case_nonce},separators=(',',':'))+'\n').encode())
        stage('profile');_require(budget,budget.cutoff(30))
        private['derived_sid']=api.create_profile(name,profile);private['profile_created']=profile['created']
        if not profile['created']:raise ValueError('profile')
        _require(budget,budget.cutoff(30))
        launcher.write_private_bytes(work/'profile-created.json',(json.dumps({'profile':name,'sid':private['derived_sid']},separators=(',',':'))+'\n').encode())
        stage('acl');acl_attempted=True
        api.grant_acl(work,inputs,frontout,private['derived_sid'],budget);private['owned_acl_scope_verified']=True
        _require(budget,budget.cutoff(30));job=api.owned_job(owners)
        if extension is not None:
            extension.setup(api,budget,work,exe,job,parent,run_nonce,case_nonce,actor_hash)
        front_read,relay_write=api.owned_pipe(owners);relay_read,front_write=api.owned_pipe(owners)
        data=[front_read,relay_write,relay_read,front_write]
        start=budget.read();end=start+10*budget.frequency
        if end>0x7fffffffffffffff or end>budget.cutoff(30):raise ValueError('deadline')
        private['pair_qpc']=[start,end];pair['admitted']=True
        for role,child in enumerate(children):
            stage('create');_require(budget,end)
            row=private['children'][role];handles=(front_read,front_write) if role==0 else (relay_read,relay_write)
            output=frontout if role==0 else relayout
            command=[str(exe),row['role'],run_nonce,case_nonce,str(output/'actor.json'),str(handles[0]),str(handles[1]),
                     str(start),str(budget.frequency),str(end),parent['sid'],private['derived_sid'] if role==0 else 'none','0']
            if extension is not None:command.extend(extension.arguments())
            state={'creation_attempted':False}
            try:
                if role==0:api.owned_create_front(child['info'],command,output,handles,owners,state,profile['pointer'],environment)
                else:api.owned_create(child['info'],command,output,handles,owners,state)
            finally:
                child['attempted']=state['creation_attempted']
                if child['info'].hProcess:pair['created']|=1<<role;row['pid']=int(child['info'].dwProcessId)
            stage('assign');api.assign_job(job,child['info'].hProcess);child['assigned']=True;row['assigned']=True
            api.verify_job(job,child['info'].hProcess)
            stage('image');api.verify_image(child['info'].hProcess,exe);pipe_helpers.verify_copied_actor(exe,actor_hash);row['image_verified']=True
            stage('frontend_identity' if role==0 else 'relay_identity')
            row['identity']=api.identity_owned(owners,child['info'].hProcess)
            valid=ac_front_identity(row['identity'],parent,private['derived_sid']) if role==0 else launcher.token_is_ordinary(row['identity']) and launcher.same_identity(row['identity'],parent)
            if not valid:raise ValueError('identity')
            pair['identity_verified']|=1<<role
        stage('close')
        for handle in data:
            try:owners.close(handle)
            except BaseException as exc:fail(exc,'close')
        pair['parent_data_closed']=not owners.uncertain and all(h in owners.attempted for h in data)
        if not pair['parent_data_closed']:raise ValueError('close')
        stage('resume')
        for role,child in enumerate(children):
            _require(budget,end);api.resume(child['info'].hThread);pair['resumed']|=1<<role;private['children'][role]['resumed']=True
        stage('protocol')
        for child in children:
            while budget.remaining_ms(end,100)>0:
                if api.wait(child['info'].hProcess,budget.remaining_ms(end,100)):
                    child['exited']=True;child['exit_code']=api.exit_code(child['info'].hProcess);break
            if budget.read()>=end or not child['exited']:raise ValueError('deadline')
        if extension is not None:extension.await_completion(api,budget,end)
    except BaseException as exc:fail(exc)
    finally:
        private['profile_created']=profile['created']
        stage('cleanup')
        try:pair['cleanup_confirmed'],pair['job_empty'],_= _cleanup(api,_CleanupCutoff(budget),job,children+extra_children,owners if extension is None else extension.cleanup_ledger(owners))
        except BaseException as exc:RETAINED.append((api,owners,children,job,extra_owners));fail(exc,'cleanup')
        pair['exit_observed']=sum(1<<i for i,c in enumerate(children) if c['exited'])
        for index,child in enumerate(children):
            row=private['children'][index];row['exit_observed']=child['exited'];row['exit_code']=child['exit_code']
        private['cleanup'].update(handles_closed=owners.confirmed_closed and all(x.confirmed_closed for x in extra_owners),job_empty=pair['job_empty'],
            processes_exited=all(not c['attempted'] or c['info'].hProcess and c['exited'] for c in children+extra_children))
        if not pair['cleanup_confirmed']:fail(ValueError('cleanup'))
        # Read only exact fresh files after held exit, retaining earlier observations.
        if private['pair_qpc'][0] is not None:
            for role,child in enumerate(children):
                row=private['children'][role]
                if not child['exited'] or not pair['identity_verified']&(1<<role):continue
                try:
                    _require(budget,budget.cutoff(10));pipe_helpers.verify_copied_actor(exe,actor_hash)
                    value,raw=bounded_json((frontout if role==0 else relayout)/'actor.json',MAX_NATIVE,inside=work)
                    if extension is not None:
                        value,raw=extension.project_native(value,raw,role=row['role'],run_id=run_nonce,case_id=case_nonce,
                            pid=row['pid'],identity=row['identity'],frequency=budget.frequency,start=start,end=end,
                            expected_ac_sid=private['derived_sid'] if role==0 else None)
                    value=validate_ac_native(value,role=row['role'],run_id=run_nonce,case_id=case_nonce,pid=row['pid'],identity=row['identity'],
                        frequency=budget.frequency,start=start,end=end,expected_ac_sid=private['derived_sid'] if role==0 else None)
                    row.update(native=value,native_sha256=hashlib.sha256(raw).hexdigest(),native_bytes=len(raw))
                    pair['reports_bound']|=1<<role;pair['observations'][role]=value['core']['observations'];pair['core_failure'][role]=value['core']['failure']
                    pair['pipe_eof'][role]=value['pipe']['eof_observed'];pair['native_close'][role]=all(value['pipe'][k]=='confirmed' for k in ('reader_close','writer_close'))
                except BaseException as exc:fail(exc,'report')
        if profile['created'] and pair['cleanup_confirmed'] and private['cleanup']['handles_closed'] and private['cleanup']['processes_exited'] and pair['job_empty'] and not getattr(api,'controls_uncertain',False):
            try:
                _require(budget,budget.cutoff(10))
                private['cleanup']['acl_removed']=not acl_attempted or api.remove_acl(work,profile['sid'],budget)
                if private['cleanup']['acl_removed']:
                    _require(budget,budget.cutoff(10));api.delete_profile(name);private['cleanup']['profile_deleted']=True
            except BaseException as exc:fail(exc,'cleanup')
        elif profile['attempted'] and not profile['returned']:
            RETAINED.append(('profile_creation_unknown',profile,work));fail(ValueError('cleanup'))
        try:api.release_profile_sid(profile);private['cleanup']['sid_released']=True
        except BaseException as exc:fail(exc,'cleanup')
        try:_require(budget,budget.cutoff(10));private['cleanup']['deadline_verified']=True
        except BaseException as exc:fail(exc,'deadline')
        if getattr(api,'controls_uncertain',False) or retained_before!=(len(pipe_helpers._RETAINED_FILES),len(launcher._RETAINED_PRIVATE_STREAMS)):
            pair['cleanup_confirmed']=False;private['cleanup']['handles_closed']=False;fail(ValueError('cleanup'))
    pair['expected_outcome']=(pair['reports_bound']==3 and pair['cleanup_confirmed'] and pair['parent_data_closed'] and
        pair['identity_verified']==3 and all(c['exit_code']==0 and successful_native(c['native']) for c in private['children']))
    if private['ac_failure'] is not None:pair['failure']=private['ac_failure'] if private['ac_failure'] in FAILURES else 'setup';pair['expected_outcome']=False
    if private['ac_failure'] is None:stage('complete')
    _require(budget,budget.cutoff(5))
    if work_created:
        raw=(json.dumps(private,separators=(',',':'))+'\n').encode('utf-8')
        if len(raw)>MAX_PRIVATE:raise ValueError('report')
        launcher.write_private_bytes(work/'private-ac.json',raw)
        _require(budget,budget.cutoff(5))
    return private

def validate_private_report(value,expected):
    expected_keys={'run_nonce','case_nonce','actor_sha256','manifest_sha256','deadline_qpc','qpc_frequency','controller_pid','controller_sid','controller_session'}
    if type(expected) is not dict or set(expected)!=expected_keys:raise ValueError('report')
    if type(expected['controller_sid']) is not str or launcher.SID_PATTERN.fullmatch(expected['controller_sid']) is None or not integer(expected['controller_session']):raise ValueError('report')
    keys={'schema_version','stage','run_nonce','case_nonce','actor_sha256','manifest_sha256','deadline_qpc','qpc_frequency',
        'controller_pid','controller_identity','derived_sid','profile_created','child_environment','pair','pair_qpc','children',
        'cleanup','owned_acl_scope_verified','diagnostic','ac_failure'}
    if type(value) is not dict or set(value)!=keys or not integer(value['schema_version'],1,1) or value['stage']!='proxy-pipe-ac-controller':raise ValueError('report')
    for key in ('run_nonce','case_nonce','actor_sha256','manifest_sha256','deadline_qpc','qpc_frequency','controller_pid'):
        if type(value[key]) is not type(expected[key]) or value[key]!=expected[key]:raise ValueError('report')
    if (not all(nonce(value[k]) for k in ('run_nonce','case_nonce')) or not all(digest(value[k]) for k in ('actor_sha256','manifest_sha256')) or
        not integer(value['deadline_qpc'],1,0x7fffffffffffffff) or not integer(value['qpc_frequency'],1,1000000000) or not integer(value['controller_pid'],1)):raise ValueError('report')
    parent=value['controller_identity']
    if type(parent) is not dict or set(parent)!=AC_IDENTITY_KEYS or not launcher.token_is_ordinary(parent) or parent['sid']!=expected['controller_sid'] or parent['session_id']!=expected['controller_session']:raise ValueError('report')
    if type(value['profile_created']) is not bool or type(value['owned_acl_scope_verified']) is not bool:raise ValueError('report')
    sid=value['derived_sid']
    if sid is not None and (not ac_profile_sid(sid) or not value['profile_created']):raise ValueError('report')
    environment=launcher.validate_child_environment(value['child_environment'])
    pair=validate_pair(value['pair']);qpc=value['pair_qpc']
    if value['owned_acl_scope_verified'] and not (value['profile_created'] and sid is not None):raise ValueError('report')
    if pair['admitted'] and not (value['owned_acl_scope_verified'] and launcher.child_environment_admitted(environment)):raise ValueError('report')
    if type(qpc) is not list or len(qpc)!=2:raise ValueError('report')
    if qpc!=[None,None]:
        if (not all(integer(x,1,0x7fffffffffffffff) for x in qpc) or qpc[1]!=qpc[0]+10*value['qpc_frequency'] or
            qpc[1]>value['deadline_qpc']-30*value['qpc_frequency']):raise ValueError('report')
    elif pair['created'] or pair['admitted']:raise ValueError('report')
    cleanup=value['cleanup'];cleanup_keys={'handles_closed','processes_exited','job_empty','acl_removed','profile_deleted','deadline_verified','sid_released'}
    if type(cleanup) is not dict or set(cleanup)!=cleanup_keys or any(type(x) is not bool for x in cleanup.values()):raise ValueError('report')
    if cleanup['profile_deleted'] and not (value['profile_created'] and cleanup['acl_removed'] and cleanup['processes_exited'] and cleanup['job_empty'] and cleanup['handles_closed'] and pair['cleanup_confirmed']):raise ValueError('report')
    diagnostic=value['diagnostic']
    if (type(diagnostic) is not dict or set(diagnostic)!={'phase','error_domain','error_code','controller_report'} or
        diagnostic['phase'] not in AC_PHASES or diagnostic['error_domain'] not in AC_ERROR_DOMAINS or diagnostic['controller_report'] not in AC_REPORT_STATES or
        diagnostic['error_code'] is not None and not integer(diagnostic['error_code']) or
        diagnostic['error_domain'] in ('none','internal') and diagnostic['error_code'] is not None):raise ValueError('report')
    if value['ac_failure'] is not None and value['ac_failure'] not in AC_FAILURES:raise ValueError('report')
    rows=value['children'];held=[False,False];native_good=[False,False]
    if type(rows) is not list or len(rows)!=2:raise ValueError('report')
    for role,row in enumerate(rows):
        if type(row) is not dict or set(row)!=set(_ac_child(('pipe-front','pipe-relay')[role])) or row['role']!=('pipe-front','pipe-relay')[role]:raise ValueError('report')
        for key in ('image_verified','assigned','exit_observed','resumed'):
            if type(row[key]) is not bool:raise ValueError('report')
        if row['pid'] is not None and not integer(row['pid'],1):raise ValueError('report')
        if row['exit_code'] is not None and (not integer(row['exit_code']) or not row['exit_observed']):raise ValueError('report')
        if bool(pair['created']&(1<<role))!=(row['pid'] is not None) or bool(pair['resumed']&(1<<role))!=row['resumed'] or bool(pair['exit_observed']&(1<<role))!=row['exit_observed']:raise ValueError('report')
        observed=row['identity']
        if observed is not None:
            if type(observed) is not dict or set(observed)!=AC_IDENTITY_KEYS:raise ValueError('report')
            held[role]=(ac_front_identity(observed,parent,sid) if role==0 else launcher.token_is_ordinary(observed) and launcher.same_identity(observed,parent))
        if bool(pair['identity_verified']&(1<<role))!=(held[role] and row['image_verified'] and row['assigned']):raise ValueError('report')
        native=row['native']
        if native is None:
            if row['native_sha256'] is not None or row['native_bytes'] is not None or pair['reports_bound']&(1<<role):raise ValueError('report')
        else:
            if not held[role] or not row['exit_observed'] or not row['image_verified'] or not row['assigned'] or not digest(row['native_sha256']) or not integer(row['native_bytes'],1,8192):raise ValueError('report')
            validate_ac_native(native,role=row['role'],run_id=value['run_nonce'],case_id=value['case_nonce'],pid=row['pid'],identity=observed,
                frequency=value['qpc_frequency'],start=qpc[0],end=qpc[1],expected_ac_sid=sid if role==0 else None)
            if not pair['reports_bound']&(1<<role) or pair['observations'][role]!=native['core']['observations'] or pair['core_failure'][role]!=native['core']['failure'] or pair['pipe_eof'][role]!=native['pipe']['eof_observed'] or pair['native_close'][role]!=all(native['pipe'][k]=='confirmed' for k in ('reader_close','writer_close')):raise ValueError('report')
            native_good[role]=successful_native(native) and row['exit_code']==0
    if pair['cleanup_confirmed'] and not all(cleanup[k] for k in ('handles_closed','processes_exited','job_empty')):raise ValueError('report')
    if pair['expected_outcome'] and not all(native_good):raise ValueError('report')
    facts={k:False for k in AC_FACTS}
    facts.update(current_ordinary_verified=True,controller_identity_verified=True,
        frontend_held_identity_verified=held[0],relay_held_identity_verified=held[1],
        fresh_frontend_profile_verified=value['profile_created'] and sid is not None,
        images_verified=all(row['image_verified'] for row in rows),child_environment_verified=launcher.child_environment_admitted(environment),
        owned_acl_scope_verified=value['owned_acl_scope_verified'],acl_removed_verified=cleanup['acl_removed'],profile_deleted_verified=cleanup['profile_deleted'])
    failure=value['ac_failure']
    if failure is None and not (all(cleanup.values()) and pair['cleanup_confirmed']):failure='cleanup'
    return {'diagnostic':dict(diagnostic,controller_report='bound'),'facts':facts,'pair':pair,'ac_failure':failure}


def ac_main(argv=None):
    # This guard precedes parsing paths, loading native APIs and owned setup.
    if not AC_EXECUTION_ENABLED or os.name!='nt':return 2
    parser=argparse.ArgumentParser(description='Inactive fixed ordinary/AC anonymous-pipe pair')
    parser.add_argument('--run-ac-pair',action='store_true')
    for name in ('actor','manifest','work'):parser.add_argument('--'+name,type=Path,required=True)
    for name in ('expected-actor-sha256','expected-manifest-sha256','run-nonce','case-nonce'):parser.add_argument('--'+name,required=True)
    parser.add_argument('--deadline-qpc',type=int,required=True);parser.add_argument('--qpc-frequency',type=int,required=True)
    args=parser.parse_args(argv)
    try:
        api=ACWindowsAPI()
        value=run_ac_pair(api,args.actor,args.manifest,args.expected_actor_sha256,args.expected_manifest_sha256,
            args.work,args.run_nonce,args.case_nonce,args.deadline_qpc,args.qpc_frequency)
        return 0 if value['ac_failure'] is None and value['pair']['expected_outcome'] and all(value['cleanup'].values()) else 1
    except BaseException:return 1


def main(argv=None):
    if '--run-ac-pair' in (sys.argv[1:] if argv is None else argv):return ac_main(argv)

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
