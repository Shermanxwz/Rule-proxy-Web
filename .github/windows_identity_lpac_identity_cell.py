"""Matched AC/LPAC held identity cell, supervised by the separate local guard.

Both actor processes remain suspended for their entire lifetime. Only fixed
ordinary ACL tools resume. AccessCheck matrices qualify this identity-only
observation after ownership cleanup; they prove no network or proxy property.
Importing this module does not load a native DLL or run an experiment.
"""
from __future__ import annotations
import ctypes as C
import importlib.util
from pathlib import Path
import subprocess

ROOT=Path(__file__).resolve().parents[1]
def load(name,file):
    spec=importlib.util.spec_from_file_location(name,Path(__file__).with_name(file))
    module=importlib.util.module_from_spec(spec);spec.loader.exec_module(module);return module
owner=load('identity_cell_owner06','windows_identity_lpac_dns_local.py')
access=load('identity_cell_access02','windows_identity_lpac_accesscheck.py')
launcher,helpers,live=owner.launcher,owner.helpers,owner.live
require,sha,encode=owner.require,owner.sha,owner.encode
SCOPE='one-local-matched-ac-lpac-semantic-identity-no-network-v1'
NETWORK_AUTHORIZED=False
POLICIES={'ac':0,'lpac':1}
NONCES=('run','ac_nonce','lpac_nonce')
LOCAL_MODULE='.github/windows_identity_lpac_identity_local.py'

def api_version():return 1
MODULE='.github/windows_identity_lpac_identity_cell.py'
SOURCES=tuple(dict.fromkeys((*owner.SOURCES,'.github/windows_identity_lpac_accesscheck.py',MODULE)))

def validate_plan(value,*,device,source,actor,manifest):
    keys={'schema_version','scope','device_sha256','source_sha256','actor_sha256','manifest_sha256',
        'fresh_profile_owned_acl_acknowledged','never_resume_acknowledged','semantics_only_acknowledged','recovery_reference'}
    require(type(value) is dict and set(value)==keys and type(value['schema_version']) is int and value['schema_version']==1
        and value['scope']==SCOPE,'identity_plan')
    for key,expected in (('device_sha256',device),('source_sha256',source),('actor_sha256',actor),('manifest_sha256',manifest)):
        require(owner.ac.digest(expected) and value[key]==expected,'identity_plan_binding')
    require(all(value[key] is True for key in ('fresh_profile_owned_acl_acknowledged','never_resume_acknowledged','semantics_only_acknowledged'))
        and type(value['recovery_reference']) is str and 1<=len(value['recovery_reference'])<=512,'identity_plan_acknowledgement')
    return value

class NativeCellAPI(owner.LPACAPI):
    """Narrow actor constructor; ordinary tools retain the existing resume API.

    CellOwner is the only arm caller and never resumes either arm. The separate
    ordinary helper path uses the existing held token/image/Job admission.
    """
    def access_api(self):return access.NativeAPI()

    def create_matched_suspended(self,info,actor,cwd,environment,job,owners,state,*,profile_pointer,catalog,policy,budget,cutoff):
        require(type(policy) is int and policy in (0,1) and profile_pointer and job,'matched_constructor')
        require(type(environment) is str and environment.endswith('\0\0'),'matched_environment')
        pairs=environment.rstrip('\0').split('\0')
        require(len(pairs)==2 and {value.split('=',1)[0] for value in pairs}=={'SystemRoot','LOCALAPPDATA'},'matched_environment_keys')
        owner.capability_catalog({name:catalog[name] for name in ('AgenticAppContainer','privateNetworkClientServer')})
        require(Path(actor).name==live.ACTOR,'matched_actor')
        budget.require_ms(cutoff)
        state.update(create_status='not_entered',create_winerror=None,create_information='not_observed',create_exception_detail=None,returned_qpc=None)
        size=C.c_size_t();self.k.InitializeProcThreadAttributeList(None,3,0,C.byref(size))
        require(1<=size.value<=65536,'matched_attributes');attrs=C.create_string_buffer(size.value)
        self.native.check(self.k.InitializeProcThreadAttributeList(attrs,3,0,C.byref(size)),'InitializeProcThreadAttributeList')
        sid_pointers=[]
        try:
            jobs=(C.c_void_p*1)(job)
            self.native.check(self.k.UpdateProcThreadAttribute(attrs,0,owner.JOB_LIST,jobs,C.sizeof(jobs),None,None),'UpdateProcThreadAttribute(JobList)')
            self.a.ConvertStringSidToSidW.argtypes=[C.c_wchar_p,C.POINTER(C.c_void_p)]
            self.a.ConvertStringSidToSidW.restype=C.c_int
            for name in ('AgenticAppContainer','privateNetworkClientServer'):
                pointer=C.c_void_p()
                try:self.native.check(self.a.ConvertStringSidToSidW(catalog[name],C.byref(pointer)),'ConvertStringSidToSidW(capability)')
                finally:
                    if pointer.value:
                        if any(p.value==pointer.value for p in sid_pointers):
                            self.controls_uncertain=True
                            raise ValueError('matched_capability_alias')
                        sid_pointers.append(pointer)
                require(pointer.value,'matched_capability_pointer')
            entries=(launcher.SIDAndAttributes*2)(*(launcher.SIDAndAttributes(pointer,4) for pointer in sid_pointers))
            capabilities=self.proc._SecurityCapabilities(profile_pointer,C.cast(entries,C.c_void_p),2,0)
            value=C.c_uint32(policy)
            for attribute,record in ((owner.SECURITY_CAPABILITIES,capabilities),(owner.ALL_APPLICATION_PACKAGES_POLICY,value)):
                self.native.check(self.k.UpdateProcThreadAttribute(attrs,0,attribute,C.byref(record),C.sizeof(record),None,None),'UpdateProcThreadAttribute(matched)')
            startup=self.proc._StartupInfoEx();startup.StartupInfo.cb=C.sizeof(startup);startup.lpAttributeList=C.cast(attrs,C.c_void_p)
            # Identical one-argument command lines. An accidental resume would
            # fail native07 argument validation, but resume remains prohibited.
            command=C.create_unicode_buffer(subprocess.list2cmdline([str(actor)]));env=C.create_unicode_buffer(environment)
            def create():
                try:
                    ok=self.k.CreateProcessW(str(actor),command,None,None,False,
                        self.proc._CREATE_SUSPENDED|self.proc._CREATE_UNICODE_ENVIRONMENT|self.proc._EXTENDED_STARTUPINFO_PRESENT|0x08000000,
                        env,str(cwd),C.byref(startup),C.byref(info))
                except BaseException as error:
                    state.update(create_status='exception',create_exception_detail=owner.private_failure_detail(error,'CreateProcessW(matched-identity)'));raise
                error=C.get_last_error() if not ok else 0
                state.update(create_status='returned_true' if ok else 'returned_false',create_winerror=None if ok else error,
                    create_information='all_zero' if not any((info.hProcess,info.hThread,info.dwProcessId,info.dwThreadId)) else 'nonzero')
                return ok,error
            def checked(result):
                if not result[0]:raise launcher.NativeFailure('CreateProcessW(matched-identity)',result[1])
            budget.require_ms(cutoff);helpers.create_suspended_owned(create,checked,info,owners,state)
        finally:
            uncertain=False
            try:self.k.DeleteProcThreadAttributeList(attrs)
            except BaseException:uncertain=True
            for pointer in sid_pointers:
                try:
                    if self.k.LocalFree(pointer):uncertain=True
                except BaseException:uncertain=True
            if state['create_status'] in ('returned_true','returned_false'):
                try:state['returned_qpc']=budget.read()
                except BaseException:state['returned_qpc']=None
            if uncertain:self.controls_uncertain=True;raise ValueError('matched_capability_close')

def capture_primary(api,token,parent,catalog,profile_sid,budget,cutoff):
    """OWNER-side snapshot from an already held QUERY token, before observer.

    This uses the original owner's independent token readers, not the
    AccessCheck library's observed identity or its expected-mask result.
    """
    budget.require_ms(cutoff);identity=api.identity(token)
    caps=sorted((dict(sid=sid,attributes=attributes) for sid,attributes in api.groups(token,30,'TokenCapabilities')),key=lambda row:row['sid'])
    live.selected_identity(identity,caps,parent,'agentic-pncs',catalog)
    require(identity['appcontainer_sid']==profile_sid and identity['integrity_rid']==4096,'matched_primary_identity')
    raw,size=api.native.query(token,10,'TokenStatistics');require(size==C.sizeof(access.TOKEN_STATISTICS),'matched_statistics_width')
    statistics=C.cast(raw,C.POINTER(access.TOKEN_STATISTICS))[0]
    require(statistics.TokenType==identity['token_type']==1,'matched_primary_type')
    luid=lambda value:value.LowPart|((value.HighPart&0xffffffff)<<32)
    snapshot=dict(sid=identity['sid'],session_id=identity['session_id'],token_type=1,impersonation_level=None,
        appcontainer=identity['appcontainer'],appcontainer_sid=identity['appcontainer_sid'],integrity_rid=identity['integrity_rid'],
        elevated=identity['elevated'],ui_access=identity['ui_access'],capabilities=caps,
        token_id=luid(statistics.TokenId),authentication_id=luid(statistics.AuthenticationId))
    access.identity(snapshot,primary=True);budget.require_ms(cutoff);return snapshot

def verify_held_arm(api,row,common,budget,cutoff):
    require(set(row)=={'role','policy','process','thread','token','pid','creation','expected_primary','common_sha256'},'matched_arm_schema')
    require(row['role'] in POLICIES and type(row['policy']) is int and row['policy']==POLICIES[row['role']],'matched_arm_policy')
    require(all(access.integer(row[key],1,0xffffffffffffffff) for key in ('process','thread','token','pid','creation')),'matched_arm_handles')
    require(row['common_sha256']==sha(encode(common)),'matched_common_binding');budget.require_ms(cutoff)
    require(not api.wait(row['process'],0) and api.process_id(row['process'])==row['pid'] and api.creation_time(row['process'])==row['creation'],'matched_held_generation')
    api.verify_job(common['inner_job'],row['process']);api.verify_outer(common['outer_job'],row['process'])
    api.verify_image(row['process'],common['actor_path'])
    require(sha(owner.local.bounded(Path(common['actor_path']),8*1024*1024))==common['actor_sha256'],'matched_held_image_hash')
    expected=capture_primary(api,row['token'],common['parent'],common['catalog'],common['profile_sid'],budget,cutoff)
    require(expected==row['expected_primary'],'matched_primary_changed');return expected


IdentityAPI=NativeCellAPI

def config_validate(c,*,source_names=None):
    keys={'schema_version','scope',*NONCES,'start_qpc','frequency','root_deadline_qpc','deadline_qpc','guard_job_name',
        'source_hashes','source_sha256','device_sha256','actor_sha256','manifest_sha256','recovery_plan_sha256','capability_catalog'}
    require(type(c) is dict and set(c)==keys and type(c['schema_version']) is int and c['schema_version']==1 and c['scope']==SCOPE,'identity_config')
    require(all(owner.ac.nonce(c[n]) for n in NONCES) and len({c[n] for n in NONCES})==3,'identity_nonces')
    live.clock_record(c['start_qpc'],c['frequency'],c['root_deadline_qpc'])
    require(c['root_deadline_qpc']==c['start_qpc']+120*c['frequency']
        and c['deadline_qpc']==c['root_deadline_qpc']-5*c['frequency']
        and c['guard_job_name']=='Local\\RuleProxy.LocalGuard.'+c['run'],'identity_clock')
    names=tuple(dict.fromkeys((*SOURCES,LOCAL_MODULE))) if source_names is None else tuple(source_names)
    require(type(c['source_hashes']) is dict and set(c['source_hashes'])==set(names)
        and all(owner.ac.digest(v) for v in c['source_hashes'].values())
        and sha(encode(c['source_hashes']))==c['source_sha256'],'identity_sources')
    require(all(owner.ac.digest(c[k]) for k in ('source_sha256','device_sha256','actor_sha256','manifest_sha256','recovery_plan_sha256')),'identity_digests')
    owner.capability_catalog(c['capability_catalog']);return c

def expected_acl(root,path):
    if path==root:return [(0,0x1200a9)]
    directory=root/'inputs'
    if path==directory:return [(3,0x1200a9)]
    if directory in path.parents:return [(19 if path.is_dir() else 16,0x1200a9)]
    return []

EXTRA_KEYS={'role','policy','arm_nonce','expected_primary','common_sha256','held_checks'}
TASK_KEYS={'name','attempted','assigned','exited','exit_code','pid','created','identity','capabilities','lpac','lpac_expected',
    'resumed','admitted','image_sha256','admission_qpc','resume_qpc','go_qpc','process_returned','create_observation'}
BOOL_KEYS=('profile_created','acl_attempted','common_inputs_verified','observer_attempted','observer_resources_cleanup_verified',
    'workload_cleanup','workload_job_empty','workload_stop','acl_removed','cleanup_tools','profile_deleted','sid_released')
COMMON_KEYS={'actor_path','actor_sha256','cwd','environment_sha256','profile_sid','parent','catalog','inner_job','outer_job',
    'frequency','start_qpc','root_deadline_qpc','deadline_qpc'}

def projection(row):
    value=owner.task_projection(row)
    value.update({k:row.get(k,[] if k=='held_checks' else None) for k in EXTRA_KEYS})
    return value

class CellOwner(owner.Owner):
    """Own both suspended actors and reuse only fixed ordinary helper seams."""
    def __init__(self,root,c,parent,api,budget):
        self.root,self.c,self.parent,self.api,self.budget=root,c,parent,api,budget
        self.owners=helpers.OneShotHandles(api.close);self.job=None;self.children=[];self.tasks={}
        self.profile=dict(attempted=False,returned=False,created=False,pointer=None,sid=None)
        self.catalog=None;self.selected_environment=None;self.common=None;self.phase='setup'
        self.j=dict(schema_version=1,stage='matched-ac-lpac-identity-result',scope=SCOPE,config_sha256=sha(encode(c)),
            failure=None,failure_detail=None,profile_name='ruleproxy-identity-'+c['run'],profile_sid=None,
            profile_state=dict(attempted=False,returned=False,created=False,sid_pointer_returned=False),
            child_environment=launcher.default_child_environment(),common=None,intents=[],proofs=[],tasks=[],cleanup_tasks=[],
            token_class46_queried=False,actor_resumed=False,network_tested=False,dns_tested=False,g_psec_tested=False,
            proxy_tested=False,product_acceptance=False,**dict.fromkeys(BOOL_KEYS,False))
        # With no observer call, there are no observer resources to close.
        self.j['observer_resources_cleanup_verified']=True

    def journal(self,label):
        allowed={'profile-create','acl-grant','spawn-grant-root','spawn-grant-inputs','spawn-ac','spawn-lpac',
            'observe-ac','observe-lpac','workload-stop','acl-remove','spawn-remove','profile-delete'}
        require(label in allowed and len(self.j['intents'])<16,'identity_intent')
        directory=self.root/'journal';directory.mkdir(exist_ok=True)
        raw=encode(dict(schema_version=1,scope=SCOPE,run=self.c['run'],config_sha256=sha(encode(self.c)),
            frequency=self.c['frequency'],deadline_qpc=self.c['deadline_qpc'],qpc=self.budget.read(),action=label))
        name='%02d-%s.json'%(len(self.j['intents']),label)
        owner.durable_private(directory/name,raw)
        self.j['intents'].append(dict(name=name,text=raw.decode('ascii'),sha256=sha(raw)))

    def scope_acl(self,removed=False):
        for path in owner.owned_tree(self.root):
            self.budget.require_ms(self.budget.cutoff(3 if removed else 25))
            require(self.api.acl_read(path,self.profile['sid'])==([] if removed else expected_acl(self.root,path)),'identity_acl_scope')

    def task(self,name,argv,work,*,lpac=False,stdio=False,owners=None,children=None,job=None,cleanup=False):
        """Fixed ordinary icacls tools, with an existing per-tool TEMP/TMP.

        This narrow seam avoids the DNS owner's unrelated health directory.
        Atomic Job construction and held ordinary admission stay unchanged.
        """
        require(name in ('grant-root','grant-inputs','remove') and not lpac and stdio
            and cleanup==(name=='remove'),'identity_ordinary_tool')
        sid='*'+self.profile['sid'];executable=str(self.fixed_tool('icacls.exe'))
        expected=([executable,str(self.root),'/remove:g',sid,'/T','/Q'] if cleanup else
            [executable,str(self.root/('inputs' if name=='grant-inputs' else '')),'/grant',
                sid+(':(OI)(CI)(RX)' if name=='grant-inputs' else ':RX'),'/Q'])
        require(argv==expected and work==self.root/'tools'/name and (work/'temp').is_dir(),'identity_fixed_tool_command')
        cutoff=self.budget.cutoff(3 if cleanup else 25);self.budget.require_ms(cutoff)
        owners=self.owners if owners is None else owners;children=self.children if children is None else children
        job=self.job if job is None else job;image=launcher.checked_path(argv[0]);image_hash=sha(owner.local.bounded(image,8*1024*1024))
        info=self.api.process_info();row=dict(info=info,name=name,attempted=False,assigned=False,exited=False,exit_code=None,
            pid=None,created=None,process_returned=False,create_observation=dict(status='not_entered',winerror=None,
            process_information='not_observed',returned_qpc=None,work_cutoff=cutoff,exception_detail=None),token=None,
            identity=None,capabilities=None,lpac=None,lpac_expected=False,resumed=False,admitted=False,image_sha256=image_hash,
            admission_qpc=None,resume_qpc=None,go_qpc=[])
        children.append(row)
        if not cleanup:self.tasks[name]=row
        state=dict(creation_attempted=False);stdio_owners=helpers.OneShotHandles(self.api.close);handles=[];self.journal('spawn-'+name)
        try:
            for label in ('stdin','stdout','stderr'):
                handle=self.api.open_stdio_file(work/label,read=label=='stdin');stdio_owners.add(handle);handles.append(handle)
            environment=self.api.native.environment(work)
            pairs=dict(value.split('=',1) for value in environment.rstrip('\0').split('\0'))
            require(environment.endswith('\0\0') and set(pairs)=={'SystemRoot','WINDIR','TEMP','TMP'}
                and pairs['SystemRoot']==pairs['WINDIR'] and pairs['TEMP']==pairs['TMP']==str(work/'temp'),'identity_tool_environment')
            try:self.api.atomic_spawn(info,argv,work,job,owners,state,environment=environment,stdio=handles,profile_pointer=None,catalog=self.catalog)
            finally:
                row.update(attempted=state['creation_attempted'],process_returned=bool(info.hProcess))
                if info.dwProcessId:row['pid']=int(info.dwProcessId)
                row['create_observation']=dict(status=state.get('create_status','not_entered'),winerror=state.get('create_winerror'),
                    process_information=state.get('create_information','not_observed'),returned_qpc=None,work_cutoff=cutoff,
                    exception_detail=state.get('create_exception_detail'))
                if row['create_observation']['status'] in ('returned_false','returned_true'):
                    try:row['create_observation']['returned_qpc']=self.budget.read()
                    except BaseException:pass
        finally:
            uncertain=False
            for handle in tuple(stdio_owners.pending):
                try:stdio_owners.close(handle)
                except BaseException:uncertain=True
            if uncertain or not stdio_owners.confirmed_closed:
                self.api.controls_uncertain=True;launcher._RETAINED_SCOPED_OWNERS.append((self.api,stdio_owners));raise ValueError('identity_stdio_close')
        self.budget.require_ms(cutoff);require(info.hProcess and info.hThread and info.dwProcessId,'identity_partial_tool')
        row['created']=self.api.creation_time(info.hProcess);self.api.verify_job(job,info.hProcess);row['assigned']=True
        self.api.verify_outer(self.c['guard_job_name'],info.hProcess);self.api.verify_image(info.hProcess,image)
        require(sha(owner.local.bounded(image,8*1024*1024))==image_hash,'identity_tool_image_changed')
        row['token']=self.api.token_for_process(info.hProcess);owners.add(row['token'])
        row['identity'],row['capabilities'],row['lpac']=owner.held_identity(self.api,row,self.parent,self.catalog,self.profile['sid'],False)
        row['admission_qpc']=self.budget.read();self.budget.require_ms(cutoff);row['admitted']=True
        return row

    def setup(self):
        owner.owned_tree(self.root);self.budget.require_ms(self.budget.cutoff(30))
        verified=self.api.local_appdata(self.budget,self.j['child_environment'])
        self.selected_environment=self.api.front_environment(verified,self.j['child_environment'])
        require(launcher.child_environment_admitted(self.j['child_environment']),'identity_environment')
        self.job=self.api.owned_job(self.owners);catalog=self.api.catalog()
        self.catalog=owner.capability_catalog({name:catalog[name] for name in ('AgenticAppContainer','privateNetworkClientServer')})
        require(self.catalog==self.c['capability_catalog'],'identity_catalog')
        self.journal('profile-create')
        try:self.api.create_profile(self.j['profile_name'],self.profile)
        finally:
            self.j['profile_state']={k:self.profile[k] for k in ('attempted','returned','created')}
            self.j['profile_state']['sid_pointer_returned']=bool(self.profile['pointer'])
            # Keep a successfully converted SID even if later readback fails.
            self.j['profile_sid']=self.profile['sid']
        require(self.profile['created'] and self.api.derive_profile_sid(self.j['profile_name'])==self.profile['sid'],'identity_fresh_profile')
        self.j.update(profile_created=True,profile_sid=self.profile['sid'])
        for path in owner.owned_tree(self.root):require(self.api.acl_read(path,self.profile['sid'])==[],'identity_fresh_acl')
        self.j['acl_attempted']=True;self.journal('acl-grant');tool=str(self.fixed_tool('icacls.exe'))
        for name,right in (('','RX'),('inputs','(OI)(CI)(RX)')):
            self.tool([tool,str(self.root/name),'/grant','*'+self.profile['sid']+':'+right,'/Q'],'grant-'+(name or 'root'))
        self.scope_acl()
        self.common=dict(actor_path=str(self.root/'inputs'/live.ACTOR),actor_sha256=self.c['actor_sha256'],cwd=str(self.root/'inputs'),
            environment_sha256=sha(self.selected_environment.encode('utf-16-le')),profile_sid=self.profile['sid'],parent=self.parent,
            catalog=self.catalog,inner_job=self.job,outer_job=self.c['guard_job_name'],frequency=self.c['frequency'],
            start_qpc=self.c['start_qpc'],root_deadline_qpc=self.c['root_deadline_qpc'],deadline_qpc=self.c['deadline_qpc'])
        self.j['common']=self.common

    def resume(self,row):
        require(row['name'] in ('grant-root','grant-inputs') and not row.get('role'),'identity_actor_resume_forbidden')
        return super().resume(row)

    def arm(self,role):
        self.phase='construct';cutoff=self.budget.cutoff(25);self.budget.require_ms(cutoff)
        actor=launcher.checked_path(self.root/'inputs'/live.ACTOR,inside=self.root)
        require(sha(owner.local.bounded(actor,8*1024*1024))==self.c['actor_sha256'],'identity_actor_hash')
        info=self.api.process_info();row=dict(info=info,name=role,attempted=False,assigned=False,exited=False,exit_code=None,pid=None,
            created=None,process_returned=False,create_observation=dict(status='not_entered',winerror=None,process_information='not_observed',
            returned_qpc=None,work_cutoff=cutoff,exception_detail=None),token=None,identity=None,capabilities=None,lpac=None,
            lpac_expected=False,resumed=False,admitted=False,image_sha256=self.c['actor_sha256'],admission_qpc=None,resume_qpc=None,go_qpc=[],
            role=role,policy=POLICIES[role],arm_nonce=self.c[role+'_nonce'],expected_primary=None,common_sha256=sha(encode(self.common)),held_checks=[])
        self.children.append(row);self.tasks[role]=row;state=dict(creation_attempted=False);self.journal('spawn-'+role)
        try:self.api.create_matched_suspended(info,actor,self.root/'inputs',self.selected_environment,self.job,self.owners,state,
            profile_pointer=self.profile['pointer'],catalog=self.catalog,policy=POLICIES[role],budget=self.budget,cutoff=cutoff)
        finally:
            row.update(attempted=state['creation_attempted'],process_returned=bool(info.hProcess))
            if info.dwProcessId:row['pid']=int(info.dwProcessId)
            row['create_observation']=dict(status=state.get('create_status','not_entered'),winerror=state.get('create_winerror'),
                process_information=state.get('create_information','not_observed'),returned_qpc=state.get('returned_qpc'),
                work_cutoff=cutoff,exception_detail=state.get('create_exception_detail'))
        self.phase='admission';self.budget.require_ms(cutoff)
        require(bool(info.hProcess) and bool(info.hThread) and info.dwProcessId,'identity_partial_create')
        row['created']=self.api.creation_time(info.hProcess)
        self.api.verify_job(self.job,info.hProcess);row['assigned']=True
        self.api.verify_outer(self.c['guard_job_name'],info.hProcess);self.api.verify_image(info.hProcess,actor)
        require(sha(owner.local.bounded(actor,8*1024*1024))==self.c['actor_sha256'],'identity_image_changed')
        row['token']=self.api.token_for_process(info.hProcess);self.owners.add(row['token'])
        row['expected_primary']=capture_primary(self.api,row['token'],self.parent,self.catalog,self.profile['sid'],self.budget,cutoff)
        row['identity']=self.api.identity(row['token']);row['capabilities']=row['expected_primary']['capabilities']
        self.check_arm(row)
        row['admission_qpc']=self.budget.read();self.budget.require_ms(cutoff);row['admitted']=True
        return row

    def check_arm(self,row):
        require(row['role'] in POLICIES and not row['resumed'] and row['resume_qpc'] is None and row['go_qpc']==[],'identity_never_resumed')
        held=dict(role=row['role'],policy=row['policy'],process=row['info'].hProcess,thread=row['info'].hThread,token=row['token'],
            pid=row['pid'],creation=row['created'],expected_primary=row['expected_primary'],common_sha256=row['common_sha256'])
        verify_held_arm(self.api,held,self.common,self.budget,self.budget.cutoff(25))
        row['held_checks'].append(self.budget.read())

    def execute(self):
        try:
            self.setup();arms=[self.arm(role) for role in ('ac','lpac')]
            require(arms[0]['expected_primary']['authentication_id']==arms[1]['expected_primary']['authentication_id'],'identity_authentication')
            for row in arms:self.check_arm(row)
            self.j['common_inputs_verified']=True;self.phase='accesscheck'
            probe=self.api.access_api()
            for row in arms:
                for held in arms:self.check_arm(held)
                self.journal('observe-'+row['role']);self.j['observer_attempted']=True
                self.j['observer_resources_cleanup_verified']=False
                proof=access.observe_held(probe,row['info'].hProcess,row['expected_primary'],expected_pid=row['pid'],
                    expected_creation=row['created'],expected_role=row['role'],frequency=self.c['frequency'],deadline=self.budget.cutoff(25))
                self.j['proofs'].append(proof)
                self.j['observer_resources_cleanup_verified']=all(p['resource_cleanup_verified'] for p in self.j['proofs'])
                if not self.j['observer_resources_cleanup_verified']:self.api.controls_uncertain=True
                for held in arms:self.check_arm(held)
                require(proof['qualified'],'identity_matrix')
        except BaseException as error:
            self.j['failure']=self.phase
            last=self.tasks.get(next(reversed(self.tasks),None));detail=None if last is None else last['create_observation']['exception_detail']
            self.j['failure_detail']=detail or owner.private_failure_detail(error)
            if self.j['observer_attempted'] and not self.j['observer_resources_cleanup_verified']:self.api.controls_uncertain=True
        finally:self.cleanup()
        self.j['tasks']=[projection(row) for row in self.children];return self.j

    def cleanup(self):
        clean=False
        try:
            # Durable intent precedes the sole held workload Job stop. It is
            # expected that suspended actors exit by this stop, never exit0.
            if any(r['info'].hProcess and not r['exited'] for r in self.children):self.journal('workload-stop')
            rows=[row for row in self.children if not owner.known_no_child(row,start=self.c['start_qpc'])]
            clean,empty,stop=owner.ac._cleanup(self.api,live.CleanupView(self.budget,self.budget.cutoff(8)),self.job,rows,self.owners)
            self.j.update(workload_cleanup=clean,workload_job_empty=empty,workload_stop=stop)
        except BaseException:pass
        if clean and self.j['observer_resources_cleanup_verified'] and not self.api.controls_uncertain:
            if self.profile['created']:
                toolowners=helpers.OneShotHandles(self.api.close);children=[];job=None
                try:
                    job=self.api.owned_job(toolowners);self.journal('acl-remove')
                    self.tool([str(self.fixed_tool('icacls.exe')),str(self.root),'/remove:g','*'+self.profile['sid'],'/T','/Q'],
                        'remove',cleanup=True,owners=toolowners,children=children,job=job)
                    self.scope_acl(removed=True);self.j['acl_removed']=True
                except BaseException:pass
                finally:
                    try:self.j['cleanup_tools']=owner.ac._cleanup(self.api,live.CleanupView(self.budget,self.budget.cutoff(3)),job,
                        [row for row in children if not owner.known_no_child(row,start=self.c['start_qpc'])],toolowners)[0]
                    except BaseException:pass
                    self.j['cleanup_tasks']=[projection(row) for row in children]
                if self.j['acl_removed'] and self.j['cleanup_tools'] and not self.api.controls_uncertain:
                    try:self.journal('profile-delete');self.api.delete_profile(self.j['profile_name']);self.j['profile_deleted']=True
                    except BaseException:pass
            elif not self.profile['attempted']:
                self.j.update(acl_removed=True,cleanup_tools=True,profile_deleted=True)
        try:self.api.release_profile_sid(self.profile);self.j['sid_released']=True
        except BaseException:pass
        if not all(self.j[k] for k in ('workload_cleanup','workload_job_empty','observer_resources_cleanup_verified',
                'acl_removed','cleanup_tools','profile_deleted','sid_released')):self.j['failure']=self.j['failure'] or 'cleanup'

def execute(root,c,parent,api,budget):
    config_validate(c);require(launcher.token_is_ordinary(parent),'identity_parent')
    require(budget.frequency==c['frequency'] and budget.deadline==c['deadline_qpc'],'identity_budget')
    return CellOwner(root,c,parent,api,budget).execute()

def validate_result(j,c,*,parent):
    config_validate(c);require(launcher.token_is_ordinary(parent),'identity_external_parent')
    keys={'schema_version','stage','scope','config_sha256','failure','failure_detail','profile_name','profile_sid','profile_state','child_environment',
        'common','intents','proofs','tasks','cleanup_tasks','token_class46_queried','actor_resumed','network_tested','dns_tested',
        'g_psec_tested','proxy_tested','product_acceptance',*BOOL_KEYS}
    require(type(j) is dict and set(j)==keys and type(j['schema_version']) is int and j['schema_version']==1
        and j['stage']=='matched-ac-lpac-identity-result' and j['scope']==SCOPE and j['config_sha256']==sha(encode(c))
        and j['failure'] in (None,'setup','construct','admission','accesscheck','cleanup')
        and j['profile_name']=='ruleproxy-identity-'+c['run'],'identity_result')
    require(all(type(j[k]) is bool for k in BOOL_KEYS),'identity_result_boolean')
    for key in ('token_class46_queried','actor_resumed','network_tested','dns_tested','g_psec_tested','proxy_tested','product_acceptance'):
        require(j[key] is False,'identity_result_scope')
    owner.validate_failure_detail(j['failure_detail']);require(j['failure'] is not None or j['failure_detail'] is None,'identity_failure_detail')
    launcher.validate_child_environment(j['child_environment'])
    require(j['profile_sid'] is None or owner.ac.ac_profile_sid(j['profile_sid']),'identity_profile_sid')
    require(not j['profile_created'] or owner.ac.ac_profile_sid(j['profile_sid']),'identity_created_profile')
    state=j['profile_state']
    require(type(state) is dict and set(state)=={'attempted','returned','created','sid_pointer_returned'}
        and all(type(v) is bool for v in state.values()) and (not state['returned'] or state['attempted'])
        and (not state['created'] or state['returned']) and (not j['profile_created'] or state['created']),'identity_profile_state')
    intents=j['intents'];require(type(intents) is list and len(intents)<=16,'identity_intents')
    actions=[];last=c['start_qpc']
    allowed={'profile-create','acl-grant','spawn-grant-root','spawn-grant-inputs','spawn-ac','spawn-lpac','observe-ac','observe-lpac',
        'workload-stop','acl-remove','spawn-remove','profile-delete'}
    for index,row in enumerate(intents):
        require(type(row) is dict and set(row)=={'name','text','sha256'} and type(row['text']) is str,'identity_intent_schema')
        raw=row['text'].encode('ascii');require(1<=len(raw)<=4096 and sha(raw)==row['sha256'],'identity_intent_hash')
        r=owner.decode(raw)
        require(type(r) is dict and set(r)=={'schema_version','scope','run','config_sha256','frequency','deadline_qpc','qpc','action'}
            and type(r['schema_version']) is int and r['schema_version']==1 and r['scope']==SCOPE and r['run']==c['run']
            and r['config_sha256']==sha(encode(c)) and r['frequency']==c['frequency'] and r['deadline_qpc']==c['deadline_qpc']
            and r['action'] in allowed and row['name']=='%02d-%s.json'%(index,r['action'])
            and live.integer(r['qpc'],last,c['deadline_qpc']-1) and r['action'] not in actions,'identity_intent_binding')
        last=r['qpc'];actions.append(r['action'])
    require(not j['profile_created'] or 'profile-create' in actions,'identity_profile_intent')
    require(not state['attempted'] or 'profile-create' in actions,'identity_profile_attempt_intent')
    require(not j['acl_attempted'] or j['profile_created'] and 'acl-grant' in actions,'identity_acl_intent')
    common=j['common']
    if common is not None:
        require(type(common) is dict and set(common)==COMMON_KEYS and common['actor_sha256']==c['actor_sha256']
            and type(common['actor_path']) is str and Path(common['actor_path']).name==live.ACTOR
            and type(common['cwd']) is str and Path(common['actor_path']).parent==Path(common['cwd'])
            and Path(common['cwd']).name=='inputs' and owner.ac.digest(common['environment_sha256'])
            and common['profile_sid']==j['profile_sid'] and common['parent']==parent
            and common['catalog']==c['capability_catalog'] and access.integer(common['inner_job'],1,0xffffffffffffffff)
            and common['outer_job']==c['guard_job_name'] and all(common[k]==c[k] for k in
                ('frequency','start_qpc','root_deadline_qpc','deadline_qpc')),'identity_common_binding')
        require(j['profile_created'] and j['acl_attempted'] and launcher.child_environment_admitted(j['child_environment']),'identity_common_setup')
    tasks={}
    for field,names in (('tasks',('grant-root','grant-inputs','ac','lpac')),('cleanup_tasks',('remove',))):
        rows=j[field];require(type(rows) is list and len(rows)<=len(names) and [row.get('name') for row in rows]==list(names[:len(rows)]),'identity_task_order')
        for row in rows:
            require(type(row) is dict and set(row)==TASK_KEYS|EXTRA_KEYS,'identity_task_schema')
            for key in ('attempted','assigned','exited','lpac_expected','resumed','admitted','process_returned'):
                require(type(row[key]) is bool,'identity_task_boolean')
            require(row['lpac_expected'] is False and row['lpac'] is None and owner.ac.digest(row['image_sha256']),'identity_class46_not_queried')
            for key in ('pid','created','admission_qpc','resume_qpc'):
                require(row[key] is None or live.integer(row[key],1,live.MAX_SIGNED),'identity_task_integer')
            require(row['exit_code'] is None or live.integer(row['exit_code']),'identity_task_exit')
            require(row['go_qpc']==[],'identity_no_go')
            observation=row['create_observation']
            require(type(observation) is dict and set(observation)=={'status','winerror','process_information','returned_qpc','work_cutoff','exception_detail'}
                and observation['status'] in ('not_entered','exception','returned_false','returned_true')
                and observation['process_information'] in ('not_observed','all_zero','nonzero')
                and observation['work_cutoff']==c['deadline_qpc']-(3 if field=='cleanup_tasks' else 25)*c['frequency'],'identity_create_schema')
            require(observation['winerror'] is None or live.integer(observation['winerror']),'identity_create_error')
            require(observation['status']=='returned_false' or observation['winerror'] is None,'identity_create_error_kind')
            require(observation['status']!='returned_false' or live.integer(observation['winerror']),'identity_false_error')
            require(observation['returned_qpc'] is None or live.integer(observation['returned_qpc'],c['start_qpc'],live.MAX_SIGNED),'identity_create_clock')
            owner.validate_failure_detail(observation['exception_detail'])
            require((observation['exception_detail'] is not None)==(observation['status']=='exception'),'identity_create_exception')
            if observation['status'] in ('not_entered','exception'):
                require(observation['process_information']=='not_observed' and observation['returned_qpc'] is None,'identity_unreturned_create')
            else:require(row['attempted'] and observation['process_information']!='not_observed','identity_returned_create')
            require(not row['process_returned'] or row['attempted'] and observation['process_information']=='nonzero','identity_process_returned')
            require(not row['assigned'] or row['process_returned'] and row['pid'] is not None and row['created'] is not None,'identity_assigned')
            require(not row['exited'] or row['process_returned'] and row['exit_code'] is not None,'identity_exited')
            if row['admitted']:
                require(row['assigned'] and observation['status']=='returned_true' and observation['process_information']=='nonzero'
                    and live.integer(observation['returned_qpc'],c['start_qpc'],observation['work_cutoff']-1)
                    and live.integer(row['admission_qpc'],observation['returned_qpc'],observation['work_cutoff']-1)
                    and row['identity'] is not None and type(row['capabilities']) is list,'identity_task_admitted')
            require(not row['resumed'] or row['admitted'] and live.integer(row['resume_qpc'],row['admission_qpc'],observation['work_cutoff']-1),'identity_resume_gate')
            arm=row['name'] in POLICIES
            if arm:
                role=row['name']
                require(row['role']==role and type(row['policy']) is int and row['policy']==POLICIES[role]
                    and row['arm_nonce']==c[role+'_nonce'] and not row['resumed'] and row['resume_qpc'] is None
                    and row['image_sha256']==c['actor_sha256'] and common is not None
                    and row['common_sha256']==sha(encode(common)),'identity_arm_binding')
                require(type(row['held_checks']) is list and len(row['held_checks'])<=16
                    and all(live.integer(t,c['start_qpc'],c['deadline_qpc']-25*c['frequency']-1) for t in row['held_checks'])
                    and row['held_checks']==sorted(row['held_checks']),'identity_held_checks')
                if row['expected_primary'] is not None:
                    prior=access.identity(row['expected_primary'],primary=True)
                    require(prior['sid']==parent['sid'] and prior['session_id']==parent['session_id'] and prior['appcontainer_sid']==j['profile_sid'],'identity_prior_parent')
                    live.capability_set(prior['capabilities'],'agentic-pncs',c['capability_catalog'])
                require(not row['admitted'] or j['profile_created'] and j['acl_attempted'] and row['expected_primary'] is not None
                    and row['identity']['appcontainer_sid']==j['profile_sid'] and row['identity']['integrity_rid']==4096
                    and row['capabilities']==row['expected_primary']['capabilities'] and len(row['held_checks'])>=1,'identity_arm_admitted')
                if row['identity'] is not None:
                    live.selected_identity(row['identity'],row['capabilities'],parent,'agentic-pncs',c['capability_catalog'])
                    prior=row['expected_primary'];require(prior is not None and all(row['identity'][k]==prior[k] for k in
                        ('sid','session_id','token_type','appcontainer','appcontainer_sid','integrity_rid','elevated','ui_access')),'identity_prior_snapshot')
            else:
                require(all(row[key] is None for key in EXTRA_KEYS-{'held_checks'}) and row['held_checks']==[],'identity_ordinary_metadata')
                if row['identity'] is not None:require(launcher.token_is_ordinary(row['identity']) and launcher.same_identity(row['identity'],parent)
                    and row['capabilities']==[],'identity_ordinary')
            require(not row['attempted'] or 'spawn-'+row['name'] in actions,'identity_spawn_intent')
            if field=='tasks':tasks[row['name']]=row
        if j['workload_cleanup'] and field=='tasks' or j['cleanup_tools'] and field=='cleanup_tasks':
            require(all(not row['attempted'] or owner.known_no_child(row,start=c['start_qpc'])
                or row['process_returned'] and row['exited'] and row['exit_code'] is not None for row in rows),'identity_cleanup_exits')
    arms=[tasks[role] for role in ('ac','lpac') if role in tasks]
    if j['common_inputs_verified']:
        require(len(arms)==2 and all(row['admitted'] for row in arms) and arms[0]['pid']!=arms[1]['pid']
            and arms[0]['expected_primary']['token_id']!=arms[1]['expected_primary']['token_id']
            and arms[0]['expected_primary']['authentication_id']==arms[1]['expected_primary']['authentication_id']
            and all(name in tasks and tasks[name]['admitted'] and tasks[name]['resumed'] and tasks[name]['exited']
                and tasks[name]['exit_code']==0 for name in ('grant-root','grant-inputs')),'identity_matched_inputs')
    require(type(j['proofs']) is list and len(j['proofs'])<=2,'identity_proofs')
    for proof,role in zip(j['proofs'],('ac','lpac')):
        require(role in tasks and tasks[role]['admitted'] and j['common_inputs_verified'] and 'observe-'+role in actions,'identity_proof_admission')
        row=tasks[role];access.validate_proof(proof,expected_primary_identity=row['expected_primary'],expected_role=role,
            expected_pid=row['pid'],expected_creation=row['created'],frequency=c['frequency'],deadline=c['deadline_qpc']-25*c['frequency'])
        if proof['qualified']:
            require(len(row['held_checks'])>=3 and any(t<=proof['start_qpc'] for t in row['held_checks'])
                and any(t>=proof['end_qpc'] for t in row['held_checks']),'identity_proof_held_bracket')
    observer_count=sum(action.startswith('observe-') for action in actions)
    require(j['observer_attempted']==bool(observer_count) and len(j['proofs'])<=observer_count,'identity_observer_attempt')
    require(not j['observer_resources_cleanup_verified'] or len(j['proofs'])==observer_count
        and all(p['resource_cleanup_verified'] for p in j['proofs']),'identity_observer_cleanup')
    require(not j['workload_cleanup'] or j['workload_job_empty'],'identity_job_empty')
    if state['created'] and j['acl_removed']:
        require(j['workload_cleanup'] and j['observer_resources_cleanup_verified'] and 'acl-remove' in actions
            and len(j['cleanup_tasks'])==1 and all(j['cleanup_tasks'][0][key] for key in ('admitted','resumed','exited'))
            and j['cleanup_tasks'][0]['exit_code']==0,'identity_remove_order')
    if state['created'] and j['profile_deleted']:
        require(j['acl_removed'] and j['cleanup_tools'] and 'profile-delete' in actions,'identity_delete_order')
    if j['failure'] is None:
        require(j['profile_created'] and j['acl_attempted'] and j['common_inputs_verified'] and len(j['proofs'])==2
            and all(p['qualified'] for p in j['proofs']) and all(j[k] for k in ('observer_resources_cleanup_verified','workload_cleanup',
                'workload_job_empty','acl_removed','cleanup_tools','profile_deleted','sid_released')),'identity_complete_result')
    require(len(encode(j))<=owner.MAX_REPORT,'identity_result_bound');return j

def project(j,c,*,parent):
    validate_result(j,c,parent=parent);tasks={row['name']:row for row in j['tasks']};proofs={p['expected_role']:p for p in j['proofs']}
    value=dict(failure=j['failure'],common_inputs_verified=j['common_inputs_verified'],never_resumed=True,
        **{key:j[key] for key in ('observer_resources_cleanup_verified','workload_cleanup','workload_job_empty','acl_removed',
            'cleanup_tools','profile_deleted','sid_released')})
    for role in ('ac','lpac'):
        row=tasks.get(role);proof=proofs.get(role)
        value[role+'_held_verified']=bool(row and row['admitted'] and row['held_checks'])
        value[role+'_accesscheck_verified']=bool(proof and proof['qualified'])
        value[role+'_granted_access']=None if proof is None or len(proof['calls'])!=4 or any(x['api_success'] is not True for x in proof['calls']) else [x['granted_access'] for x in proof['calls']]
    value['inner_complete']=j['failure'] is None and all(value[key] for key in ('ac_held_verified','lpac_held_verified','common_inputs_verified',
        'ac_accesscheck_verified','lpac_accesscheck_verified','observer_resources_cleanup_verified','never_resumed','workload_cleanup',
        'workload_job_empty','acl_removed','cleanup_tools','profile_deleted','sid_released'))
    return value
