"""Opt-in standalone LPAC DNS mechanism, never a PSEC or proxy qualification.

The existing native07 actor is not modified. A fresh LPAC is constructed with
exact AgenticAppContainer + PNCS and OPT_OUT, then TokenInformationClass46 is
read from its held primary token before resume and GO. No capability fallback,
ancestor ACL, rule, resolver, NRPT, route, or firewall-profile change is allowed.
Only explicit --run-local-lpac-dns plus a source/device/artifact-bound plan can
spawn. Default preflight is read-only. All safety-state residue is retained.
"""
from __future__ import annotations
import argparse
import ctypes as C
import importlib.util
import os
from pathlib import Path
import secrets
import subprocess
import sys
import time

ROOT=Path(__file__).resolve().parents[1]
def load(name,file):
    s=importlib.util.spec_from_file_location(name,Path(__file__).with_name(file))
    m=importlib.util.module_from_spec(s);s.loader.exec_module(m);return m
live=load('lpac_live','windows_identity_model2_live.py')
contracts=load('lpac_native_contracts','windows_identity_model2_controller.py')
local,launcher,helpers,ac=live.local,live.launcher,live.helpers,live.ac
require,sha,encode,decode=live.require,live.sha,live.encode,live.decode
MODULE='.github/windows_identity_lpac_dns_local.py'
SOURCES=tuple(dict.fromkeys((*live.SOURCES,MODULE)))
SCOPE='standalone-lpac-standard53-dns-mechanism-v1'
PROFILE='agentic-pncs'
JOB_LIST=0x2000d
SECURITY_CAPABILITIES=0x20009
ALL_APPLICATION_PACKAGES_POLICY=0x2000f
OPT_OUT=1
LPAC_INFORMATION_CLASS=46
PORTS={'proxy':50101,'wrong_port':50102,'origin':50103} # Binary binding only; no listener on these ports.
NONCES=('run','selected_boot','selected_admission','health_boot','health_admission','before_case','selected_case','after_case','inventory_run')
CHECKS=('ordinary','sources','artifact','plan','guard','worker_exit','outer_cleanup','worker_bound',
    'selected_lpac_held','ordinary_before','ordinary_after','natural_exits','fixture_cleanup',
    'workload_cleanup','acl_removed','cleanup_tools','profile_deleted','sid_released')
MAX_REPORT=512*1024

def snapshot(root=ROOT):
    files={n:local.bounded(launcher.checked_path(root/n,inside=root),256*1024) for n in SOURCES}
    hashes={n:sha(raw) for n,raw in files.items()};return files,hashes,sha(encode(hashes))

def durable_private(path,raw):
    require(type(raw) is bytes and len(raw)<=MAX_REPORT,'durable_bound')
    launcher.checked_path(path.parent,is_file=False)
    with path.open('xb') as stream:
        require(stream.write(raw)==len(raw),'durable_write');stream.flush();os.fsync(stream.fileno())
    require(sha(local.bounded(path,MAX_REPORT))==sha(raw),'durable_readback')

def validate_failure_detail(value):
    if value is None:return None
    require(type(value) is dict and set(value)=={'type','message','operation'}
        and type(value['type']) is str and 1<=len(value['type'])<=64
        and type(value['message']) is str and len(value['message'])<=512
        and (value['operation'] is None or type(value['operation']) is str and 1<=len(value['operation'])<=128)
        and len(encode(value))<=8192,'private_failure_detail')
    return value

def private_failure_detail(exc,operation=None):
    # Private diagnostic data only. Never copy this object into public output.
    try:message=str(exc)
    except BaseException:message='<exception message unavailable>'
    try:operation=operation or getattr(exc,'operation',None)
    except BaseException:operation=None
    return validate_failure_detail(dict(type=type(exc).__name__[:64],message=message[:512],
        operation=operation[:128] if type(operation) is str and operation else None))

def plan(value,*,device,source,actor,manifest):
    keys={'schema_version','scope','device_sha256','source_sha256','actor_sha256','manifest_sha256',
        'standard53_impact_acknowledged','fresh_lpac_acl_profile_acknowledged','residue_review_acknowledged','recovery_reference'}
    require(type(value) is dict and set(value)==keys and type(value['schema_version']) is int and value['schema_version']==1
        and value['scope']==SCOPE,'plan')
    for key,expected in (('device_sha256',device),('source_sha256',source),('actor_sha256',actor),('manifest_sha256',manifest)):
        require(ac.digest(expected) and value[key]==expected,'plan_binding')
    require(all(value[k] is True for k in ('standard53_impact_acknowledged','fresh_lpac_acl_profile_acknowledged','residue_review_acknowledged'))
        and type(value['recovery_reference']) is str and 1<=len(value['recovery_reference'])<=512,'plan_impact')
    return value

def blank(mode):
    return dict(schema_version=1,stage='standalone-lpac-dns-local',scope=SCOPE,mode=mode,status='inconclusive',failure=None,
        comparison='standalone-launcher-and-environment-no-causal-psec-comparison',
        source_sha256=None,actor_sha256=None,manifest_sha256=None,recovery_plan_sha256=None,
        checks=dict.fromkeys(CHECKS,False),selected_api=None,selected_wire_query_observed=False,
        network_tested=False,observation_complete=False,access_denial_observed=False,tree_retained=False,recovery_required=False,
        g_psec_tested=False,proxy_tested=False,product_acceptance=False,default_resolver_tested=False,
        dns_isolation_qualified=False,broker_pid_attributed=False,broker_cancellation_proven=False)

def validate_public(v):
    b=blank(v.get('mode') if type(v) is dict else None)
    require(type(v) is dict and set(v)==set(b) and v['mode'] in ('preflight','runtime'),'public_schema')
    for k in ('schema_version','stage','scope','comparison','g_psec_tested','proxy_tested','product_acceptance','default_resolver_tested',
            'dns_isolation_qualified','broker_pid_attributed','broker_cancellation_proven'):
        require(type(v[k]) is type(b[k]) and v[k]==b[k],'public_scope')
    require(v['status'] in ('ready','observed','failed','inconclusive') and (v['failure'] is None or type(v['failure']) is str
        and v['failure'] in ('inputs','identity','plan','staging','worker','report','deadline','setup','inventory','protocol','cleanup')),'public_state')
    require(type(v['checks']) is dict and set(v['checks'])==set(CHECKS) and all(type(x) is bool for x in v['checks'].values()),'public_checks')
    for k in ('selected_wire_query_observed','network_tested','observation_complete','access_denial_observed','tree_retained','recovery_required'):
        require(type(v[k]) is bool,'public_boolean')
    for k in ('source_sha256','actor_sha256','manifest_sha256','recovery_plan_sha256'):require(v[k] is None or ac.digest(v[k]),'public_digest')
    if v['selected_api'] is not None:
        require(type(v['selected_api']) is dict and set(v['selected_api'])=={'called','completed','pending','api_status','query_status',
            'query_status_success_verified','answer_match','within_deadline','record_count','records_released','context_retained','timely_verified'},'api_public')
        for k in ('called','completed','pending','query_status_success_verified','answer_match','within_deadline','records_released','context_retained','timely_verified'):
            require(type(v['selected_api'][k]) is bool,'api_public')
        for k in ('api_status','query_status'):require(live.integer(v['selected_api'][k]),'api_public')
        require(live.integer(v['selected_api']['record_count'],0,16),'api_public')
        # Raw QueryStatus remains observed for non-PENDING returns, as in the
        # official sample. The frozen header has no writeback sentinel; this
        # profile conservatively verifies success only with BOTH statuses zero.
        require(v['selected_api']['query_status_success_verified']==(v['selected_api']['called'] and v['selected_api']['completed']
            and not v['selected_api']['pending'] and v['selected_api']['api_status']==v['selected_api']['query_status']==0),'api_status_valid')
    for check,key in (('sources','source_sha256'),('artifact','actor_sha256'),('artifact','manifest_sha256'),('plan','recovery_plan_sha256')):
        require(not v['checks'][check] or ac.digest(v[key]),'public_commitment')
    api=v['selected_api']
    attempted=bool(api and api['called']) or v['checks']['ordinary_before'] or v['checks']['ordinary_after'] or v['selected_wire_query_observed']
    require(not attempted or v['network_tested'],'public_attempted')
    require(not v['selected_wire_query_observed'] or v['network_tested'] and v['status']=='failed','sticky_wire')
    require(not v['observation_complete'] or v['mode']=='runtime' and all(v['checks'].values()) and not v['recovery_required']
        and v['tree_retained'] and v['network_tested'] and api is not None and api['called'],'observation_gate')
    require(not v['access_denial_observed'] or v['observation_complete'] and not v['selected_wire_query_observed'] and api is not None
        and api['called'] and api['completed'] and not api['pending'] and api['within_deadline'] and api['timely_verified']
        and api['records_released'] and not api['context_retained'] and api['api_status']==5 and not api['answer_match']
        and api['record_count']==0 and not api['query_status_success_verified'],'access_gate')
    require((v['status']=='observed')==(v['access_denial_observed'] and v['failure'] is None),'observed_gate')
    if v['mode']=='preflight':
        require(v['selected_api'] is None and not any(v[k] for k in ('selected_wire_query_observed','network_tested','observation_complete',
            'access_denial_observed','tree_retained','recovery_required')) and not any(v['checks'][k] for k in CHECKS if k not in ('ordinary','sources','artifact','plan')),'preflight_no_runtime')
        require(v['status']!='ready' or v['failure'] is None and all(v['checks'][k] for k in ('ordinary','sources','artifact','plan')),'preflight_ready')
    require(len(encode(v))<=8192,'public_bound');return v

def preflight(actor,manifest,ah,mh,parent_path,plan_path,*,api=None,root=ROOT):
    v=blank('preflight');phase='inputs'
    try:
        require(os.name=='nt','platform');api=api or local.LocalNativeAPI();require(api.windows_x64(),'platform')
        phase='identity';local.ordinary(api);v['checks']['ordinary']=True
        phase='inputs';_,_,closure=snapshot(root);v['source_sha256']=closure;v['checks']['sources']=True
        live.verify_actor(actor,manifest,ah,mh,root=root);v.update(actor_sha256=ah,manifest_sha256=mh);v['checks']['artifact']=True
        p=launcher.checked_path(parent_path,inside=root/'private',is_file=False);require(p.is_dir(),'work_parent')
        phase='plan';raw=local.bounded(plan_path,8192);plan(decode(raw),device=api.device_sha256(),source=closure,actor=ah,manifest=mh)
        v['recovery_plan_sha256']=sha(raw);v['checks']['plan']=True;v['status']='ready'
    except BaseException:v['failure']=phase
    return validate_public(v)

class LPACAPI(live.LiveNativeAPI):
    """Real fixed constructor. All children are atomically in the inner Job.

    The worker is already held in the guard Job. No inheritable Job handle and
    no create/assign race is accepted; unsupported JOB_LIST is a hard failure.
    """
    def lpac_flag(self,token):
        value=self.native.scalar(token,LPAC_INFORMATION_CLASS,'TokenIsLessPrivilegedAppContainer')
        require(type(value) is int and value in (0,1),'lpac_scalar');return value

    def atomic_spawn(self,info,argv,cwd,job,owners,state,*,environment,stdio=(),profile_pointer=None,catalog=None):
        # Observation only: attempted/ownership/cleanup policy is unchanged.
        state.update(create_status='not_entered',create_winerror=None,create_information='not_observed',create_exception_detail=None)
        require(type(environment) is str and environment.endswith('\0\0') and len(stdio) in (0,3),'constructor')
        lpac=profile_pointer is not None
        if lpac:
            require(not stdio and catalog is not None and catalog['privateNetworkClientServer']==live.PNCS
                and live.proof.canonical_capability_sid(catalog['AgenticAppContainer']),'constructor_caps')
        H=C.c_void_p;size=C.c_size_t();count=1+bool(stdio)+(2 if lpac else 0)
        self.k.InitializeProcThreadAttributeList(None,count,0,C.byref(size))
        require(1<=size.value<=65536,'attributes');attrs=C.create_string_buffer(size.value)
        self.native.check(self.k.InitializeProcThreadAttributeList(attrs,count,0,C.byref(size)),'InitializeProcThreadAttributeList')
        sid_pointers=[]
        try:
            jobs=(H*1)(job)
            self.native.check(self.k.UpdateProcThreadAttribute(attrs,0,JOB_LIST,jobs,C.sizeof(jobs),None,None),'UpdateProcThreadAttribute(JobList)')
            keep=[jobs]
            if lpac:
                self.a.ConvertStringSidToSidW.argtypes=[C.c_wchar_p,C.POINTER(H)];self.a.ConvertStringSidToSidW.restype=C.c_int
                for name in ('AgenticAppContainer','privateNetworkClientServer'):
                    pointer=H()
                    try:self.native.check(self.a.ConvertStringSidToSidW(catalog[name],C.byref(pointer)),'ConvertStringSidToSidW(capability)')
                    finally:
                        if pointer.value:sid_pointers.append(pointer)
                    require(bool(pointer.value),'capability_pointer')
                entries=(launcher.SIDAndAttributes*2)(*(launcher.SIDAndAttributes(p,4) for p in sid_pointers))
                capabilities=self.proc._SecurityCapabilities(profile_pointer,C.cast(entries,H),2,0)
                policy=C.c_uint32(OPT_OUT);keep += [entries,capabilities,policy]
                for kind,value in ((SECURITY_CAPABILITIES,capabilities),(ALL_APPLICATION_PACKAGES_POLICY,policy)):
                    self.native.check(self.k.UpdateProcThreadAttribute(attrs,0,kind,C.byref(value),C.sizeof(value),None,None),'UpdateProcThreadAttribute(LPAC)')
            startup=self.proc._StartupInfoEx();startup.StartupInfo.cb=C.sizeof(startup);startup.lpAttributeList=C.cast(attrs,H)
            if stdio:
                handles=(H*3)(*stdio);keep.append(handles)
                self.native.check(self.k.UpdateProcThreadAttribute(attrs,0,0x20002,handles,C.sizeof(handles),None,None),'UpdateProcThreadAttribute(stdio)')
                startup.StartupInfo.dwFlags=0x100
                startup.StartupInfo.hStdInput,startup.StartupInfo.hStdOutput,startup.StartupInfo.hStdError=stdio
            commandline=C.create_unicode_buffer(subprocess.list2cmdline(argv));env=C.create_unicode_buffer(environment)
            def create():
                try:
                    ok=self.k.CreateProcessW(argv[0],commandline,None,None,bool(stdio),
                        self.proc._CREATE_SUSPENDED|self.proc._CREATE_UNICODE_ENVIRONMENT|self.proc._EXTENDED_STARTUPINFO_PRESENT|0x08000000,
                        env,str(cwd),C.byref(startup),C.byref(info))
                except BaseException as exc:
                    state.update(create_status='exception',create_exception_detail=private_failure_detail(exc,'CreateProcessW(atomic-LPAC)'));raise
                code=C.get_last_error() if not ok else 0
                information='all_zero' if not any((info.hProcess,info.hThread,info.dwProcessId,info.dwThreadId)) else 'nonzero'
                state.update(create_status='returned_true' if ok else 'returned_false',create_winerror=None if ok else code,
                    create_information=information)
                return ok,code
            def check(result):
                if not result[0]:raise launcher.NativeFailure('CreateProcessW(atomic-LPAC)',result[1])
            helpers.create_suspended_owned(create,check,info,owners,state)
        finally:
            uncertain=False
            try:self.k.DeleteProcThreadAttributeList(attrs)
            except BaseException:uncertain=True
            for pointer in sid_pointers:
                try:
                    if self.k.LocalFree(pointer):uncertain=True
                except BaseException:uncertain=True
            if uncertain:self.controls_uncertain=True;raise ValueError('capability_close')

    def verify_outer(self,name,process):
        self.k.OpenJobObjectW.argtypes=[C.c_uint32,C.c_int,C.c_wchar_p];self.k.OpenJobObjectW.restype=C.c_void_p
        h=self.k.OpenJobObjectW(4,False,name);self.native.check(h,'OpenJobObjectW(exact_outer)')
        try:self.native.verify_job(h,process)
        finally:
            try:self.native.close(h)
            except BaseException:
                self.controls_uncertain=True
                launcher._RETAINED_SCOPED_OWNERS.append((self,'outer_query_close_uncertain'))
                raise

def held_identity(api,row,parent,catalog,sid,lpac):
    identity=api.identity(row['token']);caps=[{'sid':s,'attributes':a} for s,a in api.groups(row['token'],30,'TokenCapabilities')]
    if lpac:
        live.selected_identity(identity,caps,parent,PROFILE,catalog)
        flag=api.lpac_flag(row['token'])
        require(identity['appcontainer_sid']==sid and identity['integrity_rid']==4096 and flag==1,'held_lpac')
    else:
        # Non-AppContainer identity already excludes LPAC. Class46 is not a
        # supported ordinary-token prerequisite on this host (actual ERROR87).
        # Keep null to mean NOT QUERIED; never invent a successful zero readback.
        require(launcher.token_is_ordinary(identity) and launcher.same_identity(identity,parent) and caps==[],'held_ordinary')
        flag=None
    if row.get('identity') is not None:require(identity==row['identity'] and caps==row['capabilities'],'held_token_changed')
    return identity,caps,flag

def capability_catalog(value):
    require(type(value) is dict and set(value)=={'AgenticAppContainer','privateNetworkClientServer'}
        and value['privateNetworkClientServer']==live.PNCS
        and live.proof.canonical_capability_sid(value['AgenticAppContainer'])
        and value['AgenticAppContainer']!=live.PNCS,'trusted_capability_catalog')
    return value

def fixed_catalog():
    observed=live.proof.WindowsCapabilityObserver().catalog()
    return capability_catalog({name:observed[name] for name in ('AgenticAppContainer','privateNetworkClientServer')})

def expected_acl(root,path):
    if path==root:return [(0,0x1200a9)]
    for name,mask in (('inputs',0x1200a9),('lpac-report',0x1301bf),('lpac-control',0x1200a9)):
        directory=root/name
        if path==directory:return [(3,mask)]
        if directory in path.parents:return [(19 if path.is_dir() else 16,mask)]
    return []

def owned_tree(root):
    # The historical A helper is limited to 32 nodes. This new staged closure
    # uses C's already bounded larger traversal, retaining its no-reparse gate.
    return contracts.owned_tree(root,max_nodes=256,max_depth=12,max_bytes=16*1024*1024)

def known_no_child(row,*,start):
    """A failed API call receipt, never a process-exit or cancellation receipt."""
    observation=row['create_observation']
    return (row['attempted'] and observation['status']=='returned_false' and live.integer(observation['winerror'],1)
        and observation['process_information']=='all_zero'
        and live.integer(observation['returned_qpc'],start,observation['work_cutoff']-1)
        and not any(row[k] for k in ('process_returned','assigned','admitted','resumed','exited'))
        and all(row[k] is None for k in ('pid','created','identity','capabilities','lpac','exit_code','admission_qpc','resume_qpc'))
        and row['go_qpc']==[])

class Owner:
    def __init__(self,root,c,parent,api,budget,*,fixture_factory=None):
        self.root,self.c,self.parent,self.api,self.budget=root,c,parent,api,budget
        self.factory=fixture_factory or live.dns.fixture.DnsCasesFixture
        self.owners=helpers.OneShotHandles(api.close);self.job=None;self.children=[];self.tasks={};self.fixture=None
        self.profile=dict(attempted=False,returned=False,created=False,pointer=None,sid=None)
        self.catalog=None;self.inventory=None;self.selected_wire=False;self.selected_environment=None
        self.j=dict(schema_version=1,stage='standalone-lpac-dns-worker-result',failure=None,failure_detail=None,selected_wire_query_observed=False,
            profile_name='ruleproxy-lpac-'+c['run'],profile_sid=None,profile_created=False,acl_attempted=False,
            selected_lpac_held=False,child_environment=launcher.default_child_environment(),inventory=None,inventory_gates=[],go=[],native=[],fixture_final=None,
            ordinary_before=False,ordinary_after=False,natural_exits=False,selected_access_denial=False,
            workload_cleanup=False,workload_job_empty=False,workload_stop=False,acl_removed=False,cleanup_tools=False,
            profile_deleted=False,sid_released=False,fixture_cleanup=True,tasks=[],cleanup_tasks=[])

    def journal(self,label):
        # CREATE_NEW receipts precede profile/ACL/process/GO actions; never rewrite recovery intent.
        path=self.root/'journal';path.mkdir(exist_ok=True)
        require(len(list(path.iterdir()))<48,'journal_bound')
        durable_private(path/('%02d-%s.json'%(len(list(path.iterdir())),label)),encode(dict(run=self.c['run'],frequency=self.c['frequency'],
            deadline=self.c['deadline_qpc'],source_sha256=self.c['source_sha256'],qpc=self.budget.read(),action=label)))

    def task(self,name,argv,work,*,lpac=False,stdio=False,owners=None,children=None,job=None,cleanup=False):
        work_cutoff=self.budget.cutoff(3 if cleanup else 25);self.budget.require_ms(work_cutoff)
        owners=self.owners if owners is None else owners;children=self.children if children is None else children;job=self.job if job is None else job
        image=launcher.checked_path(argv[0]);image_hash=sha(local.bounded(image,8*1024*1024))
        if name in ('selected','health'):require(image_hash==self.c['actor_sha256'],'actor_changed')
        info=self.api.process_info();row=dict(info=info,attempted=False,assigned=False,exited=False,exit_code=None,pid=None,created=None,
            process_returned=False,
            create_observation=dict(status='not_entered',winerror=None,process_information='not_observed',returned_qpc=None,work_cutoff=work_cutoff,exception_detail=None),
            token=None,identity=None,capabilities=None,lpac=None,lpac_expected=lpac,resumed=False,admitted=False,
            image_sha256=image_hash,admission_qpc=None,resume_qpc=None,go_qpc=[],name=name)
        children.append(row)
        if not cleanup:self.tasks[name]=row
        state=dict(creation_attempted=False);stdio_owners=helpers.OneShotHandles(self.api.close);handles=[]
        self.journal('spawn-'+name)
        try:
            if stdio:
                for label in ('stdin','stdout','stderr'):
                    handle=self.api.open_stdio_file(work/label,read=label=='stdin');stdio_owners.add(handle);handles.append(handle)
            if lpac:
                require(launcher.child_environment_admitted(self.j['child_environment']) and self.selected_environment is not None,'lpac_environment')
                environment=self.selected_environment
            else:environment=self.api.native.environment(self.root/'health')
            try:self.api.atomic_spawn(info,argv,work,job,owners,state,environment=environment,
                stdio=handles,profile_pointer=self.profile['pointer'] if lpac else None,catalog=self.catalog)
            finally:
                row['attempted']=state['creation_attempted'];row['process_returned']=bool(info.hProcess)
                if info.dwProcessId:row['pid']=int(info.dwProcessId)
                row['create_observation']=dict(status=state.get('create_status','not_entered'),winerror=state.get('create_winerror'),
                    process_information=state.get('create_information','not_observed'),returned_qpc=None,work_cutoff=work_cutoff,
                    exception_detail=state.get('create_exception_detail'))
                if row['create_observation']['status'] in ('returned_false','returned_true'):
                    try:row['create_observation']['returned_qpc']=self.budget.read()
                    except BaseException:pass # No trustworthy return clock => cannot become known-no-child.
        finally:
            uncertain=False
            for h in tuple(stdio_owners.pending):
                try:stdio_owners.close(h)
                except BaseException:uncertain=True
            if uncertain or not stdio_owners.confirmed_closed:
                self.api.controls_uncertain=True
                launcher._RETAINED_SCOPED_OWNERS.append((self.api,stdio_owners))
                raise ValueError('stdio_close')
        require(bool(info.hProcess) and bool(info.hThread),'partial_create')
        row['pid']=int(info.dwProcessId);row['created']=self.api.creation_time(info.hProcess)
        self.api.verify_job(job,info.hProcess);row['assigned']=True
        self.api.verify_outer(self.c['guard_job_name'],info.hProcess)
        self.api.verify_image(info.hProcess,image);require(sha(local.bounded(image,8*1024*1024))==image_hash,'image_changed')
        row['token']=self.api.token_for_process(info.hProcess);owners.add(row['token'])
        row['identity'],row['capabilities'],row['lpac']=held_identity(self.api,row,self.parent,self.catalog,self.profile['sid'],lpac)
        row['admission_qpc']=self.budget.read();row['admitted']=True
        if lpac:self.j['selected_lpac_held']=True
        return row

    def alive(self,row):
        self.budget.require_ms(self.budget.cutoff(3))
        require(row['admitted'] and not self.api.wait(row['info'].hProcess,0)
            and self.api.creation_time(row['info'].hProcess)==row['created'],'held_generation')
        self.api.verify_job(self.job,row['info'].hProcess);self.api.verify_outer(self.c['guard_job_name'],row['info'].hProcess)
        identity,caps,flag=held_identity(self.api,row,self.parent,self.catalog,self.profile['sid'],row['lpac_expected'])
        require(flag==row['lpac'],'held_lpac_changed')

    def resume(self,row):
        self.alive(row);require(not row['resumed'],'resume_once')
        self.api.resume(row['info'].hThread);row['resumed']=True;row['resume_qpc']=self.budget.read()

    def wait(self,row,end,code=0):
        row['exited']=self.api.wait(row['info'].hProcess,self.budget.require_ms(end)) is True
        if row['exited']:row['exit_code']=self.api.exit_code(row['info'].hProcess)
        require(row['exited'] and (code is None or row['exit_code']==code),'natural_exit')

    def tool(self,argv,label,*,cleanup=False,owners=None,children=None,job=None):
        work=self.root/'tools'/label;work.mkdir(parents=True);(work/'temp').mkdir()
        row=self.task(label,argv,work,stdio=True,cleanup=cleanup,owners=owners,children=children,job=job)
        if cleanup:
            # Generic held admission is complete; exact cleanup job is separate from stopped workload job.
            require(row['admitted'] and not row['resumed'],'cleanup_resume');self.api.resume(row['info'].hThread);row['resumed']=True;row['resume_qpc']=self.budget.read()
        else:self.resume(row)
        self.wait(row,self.budget.cutoff(3 if cleanup else 25));return row

    def fixed_tool(self,relative):
        env=dict(v.split('=',1) for v in self.api.native.environment(self.root).rstrip('\0').split('\0'))
        return launcher.checked_path(Path(env['SystemRoot'])/'System32'/relative)

    def scope_acl(self,removed=False):
        for path in owned_tree(self.root):
            self.budget.require_ms(self.budget.cutoff(3 if removed else 25))
            require(self.api.acl_read(path,self.profile['sid'])==([] if removed else expected_acl(self.root,path)),'acl_scope')

    def setup(self):
        owned_tree(self.root)
        # Reuse the existing known-folder/COM/path/exact-two-key contract. This
        # is resolved once under the original budget, before profile/ACL setup;
        # no caller environment inheritance or guessed profile path is used.
        self.budget.require_ms(self.budget.cutoff(30))
        verified_local=self.api.local_appdata(self.budget,self.j['child_environment'])
        self.selected_environment=self.api.front_environment(verified_local,self.j['child_environment'])
        require(launcher.child_environment_admitted(self.j['child_environment']),'lpac_environment')
        self.job=self.api.owned_job(self.owners);self.catalog=self.api.catalog()
        require({name:self.catalog[name] for name in ('AgenticAppContainer','privateNetworkClientServer')}==self.c['capability_catalog'],'worker_capability_catalog')
        self.journal('profile-create');self.api.create_profile(self.j['profile_name'],self.profile)
        require(self.profile['created'] and self.api.derive_profile_sid(self.j['profile_name'])==self.profile['sid'],'fresh_profile')
        self.j.update(profile_created=True,profile_sid=self.profile['sid'])
        for p in owned_tree(self.root):require(self.api.acl_read(p,self.profile['sid'])==[],'fresh_sid_acl')
        self.j['acl_attempted']=True;self.journal('acl-grant')
        icacls=str(self.fixed_tool('icacls.exe'))
        for name,right in (('', 'RX'),('inputs','(OI)(CI)(RX)'),('lpac-report','(OI)(CI)(M)'),('lpac-control','(OI)(CI)(RX)')):
            self.tool([icacls,str(self.root/name),'/grant','*'+self.profile['sid']+':'+right,'/Q'],'grant-'+(name or 'root'))
        self.scope_acl()

    def native(self,role,name,boot,admission,profile):
        reports=self.root/('lpac-report' if name=='selected' else 'health');control=self.root/('lpac-control' if name=='selected' else 'health-control')
        argv=live.selected_command(self.root/'inputs'/live.ACTOR,role,self.c['run'],boot,reports/'ready.json',reports,control,
            self.c['start_qpc'],self.c['frequency'],self.c['deadline_qpc'],PORTS,self.parent['sid'],profile,admission)
        row=self.task(name,argv,self.root/'inputs',lpac=name=='selected');self.resume(row)
        value,raw=contracts.read_when_closed(self.api,self.budget,reports/'ready.json',row['info'].hProcess,self.budget.cutoff(35))
        contracts.ready_client(value,row,self.c,role=role,boot=boot,admission=admission,profile=profile)
        self.record_native(name+'/ready.json',raw);return row

    def record_native(self,name,raw):
        # Preserve exact raw bytes as ASCII text plus hash, never canonicalize and call it raw.
        require(type(raw) is bytes and len(raw)<=16384,'native_raw')
        self.j['native'].append(dict(path=name,text=raw.decode('ascii'),sha256=sha(raw)))

    def inventory_gate(self,label):
        now=self.budget.read();row=self.tasks['inventory']
        live.dns.inventory(self.inventory,run=self.c['inventory_run'],pid=row['pid'],frequency=self.c['frequency'],start=self.c['start_qpc'],
            deadline=self.c['deadline_qpc'],now=now)
        self.j['inventory_gates'].append(dict(label=label,qpc=now));return now

    def start_fixture(self):
        work=self.root/'tools'/'inventory';work.mkdir(parents=True);(work/'temp').mkdir()
        script=launcher.checked_path(self.root/live.dns.INVENTORY,inside=self.root)
        require(sha(local.bounded(script,256*1024))==self.c['source_hashes'][live.dns.INVENTORY],'inventory_source')
        argv=[str(self.fixed_tool('WindowsPowerShell/v1.0/powershell.exe')),'-NoProfile','-NonInteractive','-ExecutionPolicy','Bypass','-File',str(script),
            '-Run',self.c['inventory_run'],'-Frequency',str(self.c['frequency']),'-StartQpc',str(self.c['start_qpc']),'-DeadlineQpc',str(self.c['deadline_qpc'])]
        row=self.task('inventory',argv,work,stdio=True);self.resume(row);self.wait(row,min(self.budget.read()+10*self.c['frequency'],self.budget.cutoff(30)))
        raw=local.bounded(work/'stdout',32768);require(not local.bounded(work/'stderr',32768),'inventory_stderr')
        self.inventory=decode(raw);self.j['inventory']=dict(text=raw.decode('ascii'),sha256=sha(raw),pid=row['pid'])
        self.inventory_gate('bind')
        self.fixture=self.factory({k:self.c[k+'_case'] for k in ('before','selected','after')},
            deadline=time.monotonic()+self.budget.remaining_ms(self.budget.cutoff(20))/1000)
        require(self.fixture.bind_address=='127.0.0.1' and self.fixture.bind_port==53,'fixture_fixed')
        require(self.fixture.start()==53,'fixture_bind')

    def sticky(self):
        if self.fixture is not None:self.selected_wire |= self.fixture.query_observed.is_set()
        self.j['selected_wire_query_observed']=self.selected_wire

    def phase(self,row,label,sequence):
        c=self.c;selected=label=='selected';self.alive(row);self.alive(self.tasks['selected']);self.alive(self.tasks['health'])
        end=min(self.budget.read()+2*c['frequency'],self.budget.cutoff(25));self.budget.require_ms(end)
        name='selected' if selected else 'health';boot=c[name+'_boot'];admission=c[name+'_admission'];case=c[label+'_case']
        self.journal('go-'+label)
        fields=dict(run=c['run'],case=case,sequence=sequence,opcode=6,frequency=c['frequency'],deadline=c['deadline_qpc'],
            fixed_ports=PORTS,admission=admission,phase_deadline=end)
        self.alive(row);issued=self.inventory_gate(label) # final held/token/Job + same once-inventory gate immediately before publish.
        control=self.root/('lpac-control' if selected else 'health-control');rawgo=live.go_record(**fields)
        digest=live.publish_go(control,budget=self.budget,**fields);row['go_qpc'].append(issued)
        self.j['go'].append(dict(role=name,label=label,fields=fields,sha256=digest,issued_qpc=issued))
        require(digest==sha(rawgo),'go_hash')
        reports=self.root/('lpac-report' if selected else 'health')
        self.sticky()
        try:value,raw=contracts.read_when_closed(self.api,self.budget,reports/('phase-%04d.json'%sequence),row['info'].hProcess,min(end+c['frequency'],self.budget.cutoff(20)))
        finally:self.sticky()
        self.record_native(name+'/phase-%04d.json'%sequence,raw)
        result=live.dns.phase(value,row,{**c,'dns_extension':{'profile':live.dns.PROFILE}},role='selected-client' if selected else 'health-client',
            boot=boot,admission=admission,sequence=sequence,case=case,phase_deadline=end,identity_check=contracts.native_identity)
        return result

    def finish(self,row,name,sequence,count):
        self.alive(row);c=self.c;control=self.root/('lpac-control' if name=='selected' else 'health-control')
        fields=dict(run=c['run'],case=c[name+'_boot'],sequence=sequence,opcode=255,frequency=c['frequency'],deadline=c['deadline_qpc'],
            fixed_ports=PORTS,admission=c[name+'_admission'],phase_deadline=self.budget.cutoff(20))
        self.journal('finish-'+name);digest=live.publish_go(control,budget=self.budget,**fields)
        self.j['go'].append(dict(role=name,label='finish',fields=fields,sha256=digest,issued_qpc=self.budget.read()))
        self.wait(row,self.budget.cutoff(15));reports=self.root/('lpac-report' if name=='selected' else 'health')
        raw=local.bounded(reports/'final.json',16384);value=decode(raw)
        contracts.client_final(value,row,c,role='selected-client' if name=='selected' else 'health-client',boot=c[name+'_boot'],
            profile=PROFILE if name=='selected' else 'ordinary',count=count)
        self.record_native(name+'/final.json',raw)

    def execute(self):
        selected=None
        try:
            self.setup()
            selected=self.native('selected-client','selected',self.c['selected_boot'],self.c['selected_admission'],PROFILE)
            self.j['selected_lpac_held']=True
            health=self.native('health-client','health',self.c['health_boot'],self.c['health_admission'],'ordinary')
            self.start_fixture()
            before=self.phase(health,'before',1);snap=live.dns.receiver(self.fixture.snapshot())
            require(live.dns.positive(before) and live.dns.case_positive(snap,'before'),'ordinary_before');self.j['ordinary_before']=True
            selected_phase=self.phase(selected,'selected',1)
            after=self.phase(health,'after',2);snap=live.dns.receiver(self.fixture.snapshot())
            require(live.dns.positive(after) and live.dns.case_positive(snap,'after'),'ordinary_after');self.j['ordinary_after']=True
            self.j['selected_access_denial']=live.dns.access_denial(selected_phase)
            self.finish(selected,'selected',2,1);self.finish(health,'health',3,2);self.j['natural_exits']=True
        except BaseException as exc:
            self.j['failure']='inventory' if type(exc) is ValueError and str(exc).startswith('dns_inventory') else 'protocol' if self.j['selected_lpac_held'] else 'setup'
            last=self.tasks.get(next(reversed(self.tasks),None))
            captured=None if last is None else last['create_observation']['exception_detail']
            self.j['failure_detail']=captured if captured is not None else private_failure_detail(exc)
        finally:self.cleanup()
        self.j['tasks']=[task_projection(r) for r in self.children]
        return self.j

    def cleanup(self):
        try:self.sticky()
        except BaseException:self.j['failure']=self.j['failure'] or 'cleanup'
        if self.fixture is not None:
            try:
                self.j['fixture_final']=live.dns.receiver(self.fixture.finish(deadline=time.monotonic()+self.budget.remaining_ms(self.budget.cutoff(3))/1000),final=True)
                self.selected_wire |= self.j['fixture_final']['selected_query_observed'];self.j['fixture_cleanup']=self.j['fixture_final']['cleanup_confirmed']
            except BaseException:self.j['fixture_cleanup']=False
            finally:
                try:self.sticky()
                except BaseException:self.j['fixture_cleanup']=False
        try:
            cleanup_children=[row for row in self.children if not known_no_child(row,start=self.c['start_qpc'])]
            clean,empty,stop=ac._cleanup(self.api,live.CleanupView(self.budget,self.budget.cutoff(8)),self.job,cleanup_children,self.owners)
            self.j.update(workload_cleanup=clean,workload_job_empty=empty,workload_stop=stop)
        except BaseException:clean=False
        if clean and self.j['fixture_cleanup'] and not self.api.controls_uncertain:
            if self.profile['created']:
                toolowners=helpers.OneShotHandles(self.api.close);children=[];job=None
                try:
                    job=self.api.owned_job(toolowners);self.journal('acl-remove')
                    self.tool([str(self.fixed_tool('icacls.exe')),str(self.root),'/remove:g','*'+self.profile['sid'],'/T','/Q'],
                        'remove',cleanup=True,owners=toolowners,children=children,job=job)
                    self.scope_acl(removed=True);self.j['acl_removed']=True
                except BaseException:pass
                finally:
                    try:self.j['cleanup_tools']=ac._cleanup(self.api,live.CleanupView(self.budget,self.budget.cutoff(3)),job,
                        [row for row in children if not known_no_child(row,start=self.c['start_qpc'])],toolowners)[0]
                    except BaseException:self.j['cleanup_tools']=False
                    self.j['cleanup_tasks']=[task_projection(r) for r in children]
                if self.j['acl_removed'] and self.j['cleanup_tools'] and not self.api.controls_uncertain:
                    try:self.journal('profile-delete');self.api.delete_profile(self.j['profile_name']);self.j['profile_deleted']=True
                    except BaseException:pass
            elif not self.profile['attempted']:
                self.j.update(acl_removed=True,cleanup_tools=True,profile_deleted=True)
        try:self.api.release_profile_sid(self.profile);self.j['sid_released']=True
        except BaseException:pass
        self.j['selected_wire_query_observed']=self.selected_wire
        if not all(self.j[k] for k in ('workload_cleanup','fixture_cleanup','acl_removed','cleanup_tools','profile_deleted','sid_released')):
            self.j['failure']=self.j['failure'] or 'cleanup'

def task_projection(r):
    return {k:r[k] for k in ('name','attempted','assigned','exited','exit_code','pid','created','identity','capabilities','lpac','lpac_expected',
        'resumed','admitted','image_sha256','admission_qpc','resume_qpc','go_qpc','process_returned','create_observation')}

def config_validate(c):
    keys={'schema_version','scope',*NONCES,'start_qpc','frequency','root_deadline_qpc','deadline_qpc','guard_job_name','source_hashes',
        'source_sha256','device_sha256','actor_sha256','manifest_sha256','recovery_plan_sha256','capability_catalog'}
    require(type(c) is dict and set(c)==keys and c['schema_version']==1 and type(c['schema_version']) is int and c['scope']==SCOPE,'config')
    require(all(ac.nonce(c[n]) for n in NONCES) and len({c[n] for n in NONCES})==len(NONCES),'config_nonce')
    live.clock_record(c['start_qpc'],c['frequency'],c['root_deadline_qpc'])
    require(c['root_deadline_qpc']==c['start_qpc']+120*c['frequency'] and c['deadline_qpc']==c['root_deadline_qpc']-5*c['frequency']
        and c['guard_job_name']=='Local\\RuleProxy.LocalGuard.'+c['run'],'config_clock')
    require(type(c['source_hashes']) is dict and set(c['source_hashes'])==set(SOURCES) and all(ac.digest(v) for v in c['source_hashes'].values())
        and sha(encode(c['source_hashes']))==c['source_sha256'],'config_source')
    require(all(ac.digest(c[k]) for k in ('source_sha256','device_sha256','actor_sha256','manifest_sha256','recovery_plan_sha256')),'config_digest')
    capability_catalog(c['capability_catalog'])
    return c

def validate_result(j,c):
    keys={'schema_version','stage','failure','failure_detail','selected_wire_query_observed','profile_name','profile_sid','profile_created','acl_attempted',
        'selected_lpac_held','child_environment','inventory','inventory_gates','go','native','fixture_final','ordinary_before','ordinary_after','natural_exits',
        'selected_access_denial','workload_cleanup','workload_job_empty','workload_stop','acl_removed','cleanup_tools','profile_deleted',
        'sid_released','fixture_cleanup','tasks','cleanup_tasks'}
    require(type(j) is dict and set(j)==keys and type(j['schema_version']) is int and j['schema_version']==1
        and j['stage']=='standalone-lpac-dns-worker-result' and j['failure'] in (None,'setup','protocol','inventory','cleanup')
        and j['profile_name']=='ruleproxy-lpac-'+c['run'],'result_schema')
    validate_failure_detail(j['failure_detail']);require(j['failure'] is not None or j['failure_detail'] is None,'success_failure_detail')
    launcher.validate_child_environment(j['child_environment'])
    booleans=keys-{'schema_version','stage','failure','failure_detail','profile_name','profile_sid','child_environment','inventory','inventory_gates','go','native','fixture_final','tasks','cleanup_tasks'}
    require(all(type(j[k]) is bool for k in booleans) and (j['profile_sid'] is None or ac.ac_profile_sid(j['profile_sid']))
        and (not j['profile_created'] or ac.ac_profile_sid(j['profile_sid'])),'result_facts')
    rowkeys={'name','attempted','assigned','exited','exit_code','pid','created','identity','capabilities','lpac','lpac_expected',
        'resumed','admitted','image_sha256','admission_qpc','resume_qpc','go_qpc','process_returned','create_observation'}
    tasks={}
    for field,allowed in (('tasks',{'grant-root','grant-inputs','grant-lpac-report','grant-lpac-control','selected','health','inventory'}),('cleanup_tasks',{'remove'})):
        rows=j[field];require(type(rows) is list and len(rows)<=len(allowed),'task_bound')
        names=set()
        for row in rows:
            require(type(row) is dict and set(row)==rowkeys and row['name'] in allowed and row['name'] not in names,'task_schema');names.add(row['name'])
            for k in ('attempted','assigned','exited','lpac_expected','resumed','admitted','process_returned'):require(type(row[k]) is bool,'task_bool')
            observation=row['create_observation']
            require(type(observation) is dict and set(observation)=={'status','winerror','process_information','returned_qpc','work_cutoff','exception_detail'}
                and observation['status'] in ('not_entered','exception','returned_false','returned_true'),'create_observation')
            require((observation['status']=='not_entered')==(not row['attempted']),'create_attempt_observation')
            require(live.integer(observation['winerror']) if observation['status']=='returned_false' else observation['winerror'] is None,'create_error_observation')
            require(observation['process_information'] in ('not_observed','all_zero','nonzero')
                and ((observation['process_information']=='not_observed')==(observation['status'] in ('not_entered','exception'))),'create_information_observation')
            require(type(observation['work_cutoff']) is int and observation['work_cutoff']==c['deadline_qpc']-(3 if field=='cleanup_tasks' else 25)*c['frequency']
                and (observation['returned_qpc'] is None or live.integer(observation['returned_qpc'],c['start_qpc'],live.MAX_SIGNED)),'create_clock_observation')
            require(observation['status'] not in ('not_entered','exception') or observation['returned_qpc'] is None,'create_unreturned_clock')
            validate_failure_detail(observation['exception_detail'])
            require((observation['exception_detail'] is not None)==(observation['status']=='exception'),'create_exception_detail')
            require(row['lpac_expected']==(row['name']=='selected') and ac.digest(row['image_sha256']),'task_image')
            require(not row['lpac_expected'] or not row['attempted'] or launcher.child_environment_admitted(j['child_environment']),'task_environment')
            require(row['lpac'] is None or type(row['lpac']) is int and row['lpac'] in (0,1),'task_lpac')
            require(row['lpac_expected'] or row['lpac'] is None,'ordinary_lpac_not_queried')
            for k in ('pid','created','admission_qpc','resume_qpc'):
                require(row[k] is None or live.integer(row[k],1,live.MAX_SIGNED),'task_integer')
            require(row['exit_code'] is None or live.integer(row['exit_code']),'task_exit')
            require(type(row['go_qpc']) is list and len(row['go_qpc'])<=2 and all(live.integer(x,c['start_qpc'],c['deadline_qpc']-1) for x in row['go_qpc']),'task_go')
            require(not row['resumed'] or row['admitted'] and row['assigned'] and row['admission_qpc']<=row['resume_qpc']<c['deadline_qpc'],'task_resume_gate')
            require(not row['admitted'] or row['attempted'] and row['pid'] is not None and row['created'] is not None
                and row['identity'] is not None and row['capabilities'] is not None
                and observation['status']=='returned_true' and observation['process_information']=='nonzero'
                and (row['lpac']==1 if row['name']=='selected' else row['lpac'] is None),'task_admission')
            if row['admitted'] and row['name'] in ('selected','health'):
                require(row['image_sha256']==c['actor_sha256'],'actor_task')
                if row['name']=='selected':
                    require(row['identity']['appcontainer_sid']==j['profile_sid'] and row['identity']['integrity_rid']==4096
                        and row['identity']['appcontainer'] is True and row['identity']['capability_count']==2
                        and row['identity']['token_type']==1 and row['identity']['elevated'] is False and row['identity']['ui_access'] is False
                        and j['profile_created'] and j['acl_attempted'],'task_lpac_binding')
                    live.capability_set(row['capabilities'],PROFILE,capability_catalog(c['capability_catalog']))
                else:require(launcher.token_is_ordinary(row['identity']) and row['capabilities']==[],'task_ordinary')
            if field=='tasks':tasks[row['name']]=row
        if j['workload_cleanup'] and field=='tasks' or j['cleanup_tools'] and field=='cleanup_tasks':
            require(all(not r['attempted'] or known_no_child(r,start=c['start_qpc'])
                or r['process_returned'] and r['exited'] and r['exit_code'] is not None for r in rows),'cleanup_task_exit')
    require(not j['selected_lpac_held'] or 'selected' in tasks and tasks['selected']['admitted'] and tasks['selected']['lpac']==1,'selected_held')
    require(not j['workload_cleanup'] or j['workload_job_empty'],'cleanup_job')
    if j['natural_exits']:
        require(not j['workload_stop'] and all(n in tasks and tasks[n]['exited'] and tasks[n]['exit_code']==0 for n in ('selected','health')),'natural_exits')
    if j['inventory'] is not None:
        r=j['inventory'];require(type(r) is dict and set(r)=={'text','sha256','pid'} and type(r['text']) is str
            and sha(r['text'].encode('ascii'))==r['sha256'] and r['pid']==tasks['inventory']['pid'],'inventory_raw')
        inv=decode(r['text'].encode('ascii'))
    else:inv=None
    gates=j['inventory_gates'];require(type(gates) is list and len(gates)<=4,'inventory_gate_count')
    require([r['label'] for r in gates]==['bind','before','selected','after'][:len(gates)],'inventory_gate_order')
    for r in gates:
        require(type(r) is dict and set(r)=={'label','qpc'} and inv is not None,'inventory_gate')
        live.dns.inventory(inv,run=c['inventory_run'],pid=tasks['inventory']['pid'],frequency=c['frequency'],start=c['start_qpc'],deadline=c['deadline_qpc'],now=r['qpc'])
    expected=[('health','before',1,6),('selected','selected',1,6),('health','after',2,6),('selected','finish',2,255),('health','finish',3,255)]
    require(type(j['go']) is list and len(j['go'])<=5,'go_bound')
    phase_tickets={}
    for r,(role,label,sequence,opcode) in zip(j['go'],expected):
        require(type(r) is dict and set(r)=={'role','label','fields','sha256','issued_qpc'} and r['role']==role and r['label']==label,'go_order')
        f=r['fields'];require(type(f) is dict and set(f)=={'run','case','sequence','opcode','frequency','deadline','fixed_ports','admission','phase_deadline'},'go_fields')
        require(f['run']==c['run'] and f['case']==c[role+'_boot' if label=='finish' else label+'_case'] and f['sequence']==sequence
            and f['opcode']==opcode and f['frequency']==c['frequency'] and f['deadline']==c['deadline_qpc'] and f['fixed_ports']==PORTS
            and f['admission']==c[role+'_admission'] and sha(live.go_record(**f))==r['sha256'],'go_binding')
        row=tasks[role];require(row['resumed'] and row['resume_qpc']<=r['issued_qpc']<f['phase_deadline']<=c['deadline_qpc'],'go_held_before')
        if opcode==6:
            gate=next((x for x in gates if x['label']==label),None)
            require(gate is not None and gate['qpc']==r['issued_qpc'] and r['issued_qpc'] in row['go_qpc'],'go_inventory_held')
            phase_tickets[(role,sequence)]=(f,r['issued_qpc'])
    native={};require(type(j['native']) is list and len(j['native'])<=7,'native_count')
    validnames={'selected/ready.json','selected/phase-0001.json','selected/final.json','health/ready.json','health/phase-0001.json','health/phase-0002.json','health/final.json'}
    for r in j['native']:
        require(type(r) is dict and set(r)=={'path','text','sha256'} and r['path'] in validnames and r['path'] not in native
            and type(r['text']) is str,'native_schema')
        raw=r['text'].encode('ascii');require(1<=len(raw)<=16384 and sha(raw)==r['sha256'],'native_digest')
        value=decode(raw);role,name=r['path'].split('/');task=tasks[role]
        kw=dict(role='selected-client' if role=='selected' else 'health-client',boot=c[role+'_boot'])
        if name=='ready.json':contracts.ready_client(value,task,c,**kw,admission=c[role+'_admission'],profile=PROFILE if role=='selected' else 'ordinary')
        elif name=='final.json':contracts.client_final(value,task,c,**kw,profile=PROFILE if role=='selected' else 'ordinary',count=1 if role=='selected' else 2)
        else:
            sequence=int(name[6:10]);f,issued=phase_tickets[(role,sequence)]
            live.dns.phase(value,task,{**c,'dns_extension':{'profile':live.dns.PROFILE}},**kw,admission=c[role+'_admission'],sequence=sequence,
                case=f['case'],phase_deadline=f['phase_deadline'],identity_check=contracts.native_identity)
            require(value['phase_qpc'][0]>=issued,'phase_before_issued_go')
        native[r['path']]=value
    if j['fixture_final'] is not None:
        receiver=live.dns.receiver(j['fixture_final'],final=True)
        require(not receiver['selected_query_observed'] or j['selected_wire_query_observed'],'fixture_sticky')
        require(j['fixture_cleanup']==receiver['cleanup_confirmed'],'fixture_cleanup')
    else:receiver=None
    for label,role,sequence in (('before','health',1),('after','health',2)):
        if j['ordinary_'+label]:
            require(role+'/phase-%04d.json'%sequence in native and live.dns.positive(native[role+'/phase-%04d.json'%sequence]),'ordinary_api_positive')
            if receiver is not None:require(live.dns.case_positive(receiver,label),'ordinary_receiver_positive')
    require(not j['selected_access_denial'] or 'selected/phase-0001.json' in native
        and live.dns.access_denial(native['selected/phase-0001.json']),'selected_access')
    if j['failure'] is None:
        require(len(j['go'])==5 and len(native)==7 and j['ordinary_before'] and j['ordinary_after'] and j['natural_exits'] and receiver is not None
            and j['profile_created'] and j['acl_attempted']
            and launcher.child_environment_admitted(j['child_environment'])
            and all(j[k] for k in ('selected_lpac_held','workload_cleanup','fixture_cleanup','acl_removed','cleanup_tools','profile_deleted','sid_released')),'complete_result')
    return j

def public_result(j,c,v):
    # First carry the separately observed event through a malformed native
    # report or journal-validation failure; a bound positive cannot wash green.
    require(type(j) is dict and type(j.get('selected_wire_query_observed')) is bool,'result_sticky')
    if j['selected_wire_query_observed']:
        v.update(selected_wire_query_observed=True,network_tested=True,status='failed')
    validate_result(j,c)
    # Native raw observations are independently parsed and bound below. These never override receiver positivity.
    hit=j['selected_wire_query_observed'];require(type(hit) is bool,'result_sticky')
    v['selected_wire_query_observed']=hit
    v['network_tested']=hit or any(decode(r['text'].encode('ascii')).get('dns',{}).get('result',{}).get('called') is True for r in j['native'])
    for out,key in (('selected_lpac_held','selected_lpac_held'),('ordinary_before','ordinary_before'),('ordinary_after','ordinary_after'),
        ('natural_exits','natural_exits'),('fixture_cleanup','fixture_cleanup'),('workload_cleanup','workload_cleanup'),
        ('acl_removed','acl_removed'),('cleanup_tools','cleanup_tools'),('profile_deleted','profile_deleted'),('sid_released','sid_released')):
        require(type(j[key]) is bool,'result_boolean');v['checks'][out]=j[key]
    cleanup=all(v['checks'][k] for k in ('guard','worker_exit','outer_cleanup','worker_bound','fixture_cleanup','workload_cleanup','acl_removed','cleanup_tools','profile_deleted','sid_released'))
    v['recovery_required']=not cleanup
    selected_phase=None
    for row in j['native']:
        require(type(row) is dict and set(row)=={'path','text','sha256'} and type(row['text']) is str,'raw_report')
        raw=row['text'].encode('ascii');require(len(raw)<=16384 and sha(raw)==row['sha256'],'raw_hash')
        value=decode(raw)
        if row['path']=='selected/phase-0001.json':selected_phase=value
    if selected_phase is not None:
        r=live.dns.api_result(selected_phase['dns']['result'])
        v['selected_api']={k:r[k] for k in ('called','completed','pending','api_status','query_status','answer_match','within_deadline',
            'record_count','records_released','context_retained')}
        v['selected_api']['timely_verified']=live.dns.timely(selected_phase)
        v['selected_api']['query_status_success_verified']=r['called'] and r['completed'] and not r['pending'] and r['api_status']==r['query_status']==0
    v['failure']=j['failure']
    v['observation_complete']=all(v['checks'].values()) and j['failure'] is None and selected_phase is not None
    v['access_denial_observed']=v['observation_complete'] and not hit and live.dns.access_denial(selected_phase)
    if hit:v['status']='failed'
    elif v['access_denial_observed']:v['status']='observed'
    else:v['status']='inconclusive';v['failure']=v['failure'] or 'protocol'
    return v

def worker(config_path):
    require(launcher.checked_path(config_path,inside=ROOT)==ROOT/'worker-config.json','worker_path')
    c=config_validate(decode(local.bounded(config_path,MAX_REPORT)))
    require(ROOT.name=='local-lpac-'+c['run'],'worker_stage')
    api=LPACAPI();parent=local.ordinary(api);require(api.qpc_frequency()==c['frequency'],'worker_frequency')
    budget=launcher.QpcBudget(api,c['deadline_qpc'],c['frequency']);budget.require_ms(budget.cutoff(45))
    files,hashes,source=snapshot();require(hashes==c['source_hashes'] and source==c['source_sha256'],'worker_sources')
    require(local.LocalNativeAPI.device_sha256(api.native)==c['device_sha256'],'worker_device')
    raw=local.bounded(ROOT/'recovery-plan.json',8192);require(sha(raw)==c['recovery_plan_sha256'],'worker_plan')
    plan(decode(raw),device=c['device_sha256'],source=source,actor=c['actor_sha256'],manifest=c['manifest_sha256'])
    local.LocalNativeAPI.verify_private_directory(api.native,ROOT,'D:P(A;OICI;FA;;;SY)(A;OICI;FA;;;'+parent['sid']+')')
    local.verify_guard_job(api.native,c['guard_job_name'])
    live.verify_actor(ROOT/'inputs'/live.ACTOR,ROOT/'inputs'/live.MANIFEST,c['actor_sha256'],c['manifest_sha256'],root=ROOT)
    result=Owner(ROOT,c,parent,api,budget).execute()
    report=dict(schema_version=1,stage='standalone-lpac-worker',config=c,worker_pid=os.getpid(),worker_identity=parent,result=result)
    budget.require_ms(budget.cutoff(1));durable_private(ROOT/'worker-report.json',encode(report));return 0

def run_local(actor,manifest,ah,mh,parent_path,plan_path,*,approved=False,root=ROOT):
    v=blank('runtime');phase='inputs';launched=False;stage=None
    try:
        require(approved and os.name=='nt','explicit_opt_in');api=local.LocalNativeAPI();require(api.windows_x64(),'platform')
        frequency=api.qpc_frequency();start=api.qpc();deadline=start+120*frequency
        budget=launcher.QpcBudget(api,deadline,frequency)
        check=preflight(actor,manifest,ah,mh,parent_path,plan_path,api=api,root=root)
        for k in ('source_sha256','actor_sha256','manifest_sha256','recovery_plan_sha256'):v[k]=check[k]
        v['checks'].update(check['checks']);require(check['status']=='ready','preflight')
        parent=local.ordinary(api);files,hashes,closure=snapshot(root);require(closure==v['source_sha256'],'source_changed')
        c=dict(schema_version=1,scope=SCOPE,**{n:secrets.token_hex(16) for n in NONCES},start_qpc=start,frequency=frequency,
            root_deadline_qpc=deadline,deadline_qpc=deadline-5*frequency,source_hashes=hashes,source_sha256=closure,
            device_sha256=api.device_sha256(),actor_sha256=ah,manifest_sha256=mh,recovery_plan_sha256=v['recovery_plan_sha256'],
            capability_catalog=fixed_catalog())
        c['guard_job_name']='Local\\RuleProxy.LocalGuard.'+c['run'];config_validate(c)
        phase='staging';budget.require_ms(budget.cutoff(45));p=launcher.checked_path(parent_path,inside=root/'private',is_file=False)
        stage=p/('local-lpac-'+c['run']);require(not stage.exists() and not stage.is_symlink(),'fresh_stage')
        api.private_directory(stage,parent['sid']);v['tree_retained']=True
        for name,raw in files.items():
            path=stage/name;path.parent.mkdir(parents=True,exist_ok=True);launcher.write_private_bytes(path,raw)
            require(sha(local.bounded(path,256*1024))==hashes[name],'staged_source')
        for name in ('inputs','lpac-report','lpac-control','health','health-control','tools','guard'):(stage/name).mkdir()
        for name in ('lpac-report','health','guard'):(stage/name/'temp').mkdir()
        for src in (Path(actor),Path(manifest)):launcher.write_private_bytes(stage/'inputs'/src.name,local.bounded(src,8*1024*1024))
        live.verify_actor(stage/'inputs'/live.ACTOR,stage/'inputs'/live.MANIFEST,ah,mh,root=stage)
        launcher.write_private_bytes(stage/'worker-config.json',encode(c))
        raw=local.bounded(plan_path,8192);require(sha(raw)==c['recovery_plan_sha256'],'plan_changed');launcher.write_private_bytes(stage/'recovery-plan.json',raw)
        api.worker_job_name=c['guard_job_name'];api.worker_sid=parent['sid']
        python=launcher.checked_path(sys.executable,inside=launcher.checked_path(sys.base_prefix,is_file=False));require(python.name.casefold()=='python.exe','python')
        command=[str(python),'-I','-S','-B',str(stage/MODULE),'--worker',str(stage/'worker-config.json')]
        phase='worker';launched=True
        launch=launcher.launch_owned(api,command,stage/'guard',parent,parent,qpc_budget=budget,work_cutoff=budget.cutoff(3),cleanup_cutoff=deadline)
        v['checks']['guard']=api.atomic_job_requested and launch.get('native_identity_verified_before_resume') is True
        v['checks']['worker_exit']=launch.get('cleanup',{}).get('process_exit_confirmed') is True
        v['checks']['outer_cleanup']=local.guest.cleanup_verified(launch)
        phase='report';require(v['checks']['worker_exit'] and launch.get('started') is True,'unknown_worker')
        report=decode(local.bounded(stage/'worker-report.json',MAX_REPORT))
        require(type(report) is dict and set(report)=={'schema_version','stage','config','worker_pid','worker_identity','result'} and report['schema_version']==1
            and report['stage']=='standalone-lpac-worker' and report['config']==c and report['worker_pid']==launch['child_pid'] and report['worker_identity']==parent,'worker_binding')
        v['checks']['worker_bound']=True
        v=public_result(report['result'],c,v)
        require(launch.get('resumed') is True and launch.get('timed_out') is not True and launch.get('exit_code')==0 and 'error' not in launch,'worker_launch')
        phase='deadline';budget.require_ms(deadline)
    except BaseException:
        v['failure']=phase
        if launched and not all(v['checks'][k] for k in ('guard','worker_exit','outer_cleanup','worker_bound','fixture_cleanup',
                'workload_cleanup','acl_removed','cleanup_tools','profile_deleted','sid_released')):v['recovery_required']=True
        if stage is not None and not launched:v['recovery_required']=True
        if v['status']=='observed':v['status']='inconclusive';v['access_denial_observed']=False;v['observation_complete']=False
    if v['selected_wire_query_observed']:v['status']='failed'
    return validate_public(v)

def main(argv=None):
    p=argparse.ArgumentParser(description=__doc__);p.add_argument('--worker',help=argparse.SUPPRESS)
    p.add_argument('--run-local-lpac-dns',action='store_true');p.add_argument('--actor',type=Path);p.add_argument('--manifest',type=Path)
    p.add_argument('--actor-sha256');p.add_argument('--manifest-sha256');p.add_argument('--work-parent',type=Path,default=ROOT/'private')
    p.add_argument('--recovery-plan',type=Path);p.add_argument('--output',type=Path);args=p.parse_args(argv)
    if args.worker:
        require(not args.run_local_lpac_dns and not any((args.actor,args.manifest,args.actor_sha256,args.manifest_sha256,args.recovery_plan,args.output))
            and args.work_parent==ROOT/'private','worker_arguments')
        return worker(Path(args.worker))
    if any(x is None for x in (args.actor,args.manifest,args.actor_sha256,args.manifest_sha256,args.recovery_plan)):
        v=blank('runtime' if args.run_local_lpac_dns else 'preflight');v['failure']='inputs'
    else:
        fn=run_local if args.run_local_lpac_dns else preflight
        kw={'approved':True} if args.run_local_lpac_dns else {}
        v=fn(args.actor,args.manifest,args.actor_sha256,args.manifest_sha256,args.work_parent,args.recovery_plan,**kw)
    raw=encode(validate_public(v))
    if args.output:launcher.write_private_bytes(args.output,raw)
    sys.stdout.buffer.write(raw);sys.stdout.buffer.flush();return 0 if v['status'] in ('ready','observed') else 1
if __name__=='__main__':raise SystemExit(main())
