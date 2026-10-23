"""One cooperative zero-cap LPAC pipe frontend and held ordinary origin.

Only the new guarded entry owns execution. Imported owners are not run and no
imported globals are changed. The ordinary lifecycle/cleanup and B protocol
validators remain immutable dependencies, not LPAC qualification on their own.
"""
from __future__ import annotations
import ctypes as C
import importlib.util
from pathlib import Path
import subprocess

ROOT=Path(__file__).resolve().parents[1]
def load(name,file):
    s=importlib.util.spec_from_file_location(name,Path(__file__).with_name(file));m=importlib.util.module_from_spec(s);s.loader.exec_module(m);return m
zero=load('lpac_pipe_zero_primitives','windows_identity_lpac_loopback.py')
origin=load('lpac_pipe_origin_validators','windows_identity_proxy_origin_probe.py')
base,cell,access=zero.base,zero.identity_cell,zero.access
launcher,helpers,live,local=zero.launcher,zero.helpers,zero.live,zero.local
require,sha,encode,decode=zero.require,zero.sha,zero.encode,zero.decode
SCOPE='one-local-semantic-lpac-held-ipc-relay-origin-v1'
PROFILE='zero-cap-lpac-fixed-pipe-origin-mechanism-v1'
MODULE='.github/windows_identity_lpac_pipe_origin.py';LOCAL_MODULE='.github/windows_identity_lpac_pipe_origin_local.py'
ACTOR='windows_identity_lpac_pipe_front_actor.exe';MANIFEST='identity-lpac-pipe-front-manifest.json'
ACTUAL_READY=True
NONCES=('run','case');ROLES=('lpac-pipe-front','ordinary-pipe-relay','ordinary-origin-fixture')
NATIVE_SOURCES={'actorSourceSha256':'.github/native/windows_identity_lpac_pipe_front_actor.cpp',
    'pipeActorSha256':'.github/native/windows_identity_proxy_pipe_actor.cpp',
    'identitySourceSha256':'.github/native/windows_identity_actor.cpp','coreSha256':'.github/native/windows_identity_proxy_bridge_core.hpp'}
SOURCES=tuple(dict.fromkeys((*zero.SOURCES,*origin.SOURCES,*NATIVE_SOURCES.values(),MODULE,LOCAL_MODULE)))
MAX_REPORT=768*1024;MAX_NATIVE=16384
FALSE_CLAIMS=('arbitrary_application_adapter','browser_integration','selected_proxy_qualification','psec_or_g_support',
    'psec_network_preservation_proven','direct_network_denial','dns_isolation','service_broker_isolation','all_protocol_isolation',
    'ipv6_tested','udp_tested','hostile_same_sid_authentication','kernel_tcp_snapshot_observed','linux_equivalence','product_acceptance',
    'selected_socket_api_tested','selected_dns_api_tested','class46_queried')
ACKS=('fresh_profile_owned_acl_acknowledged','zero_capabilities_no_fallback_acknowledged','trusted_actor_mechanism_only_acknowledged',
    'cooperative_fixed_frame_mapping_acknowledged','inherited_pipe_authority_acknowledged','residue_review_acknowledged')
CLEAN_KEYS=('workload_cleanup','workload_job_empty','parent_pipe_handles_closed','pipe_allocation_known',
    'observer_resources_cleanup_verified','labels_restored','acl_removed','cleanup_tools','profile_deleted','sid_released')
GRANTS=(('root','','RX'),('inputs','inputs','(OI)(CI)(RX)'),('selected-report','selected-report','(OI)(CI)(M)'))
REPORT_PATHS={'ready':'origin-report/ready.json','selected':'selected-report/actor.json','relay':'relay-report/actor.json','origin':'origin-report/actor.json'}
def api_version():return 1
def stage_name(run):return 'local-lpac-pipe-origin-'+run
def work_cutoff(c):return c['root_deadline_qpc']-35*c['frequency']
def owned_tree(root):return base.contracts.owned_tree(root,max_nodes=512,max_depth=16,max_bytes=24*1024*1024)
def config_validate(c,*,source_names=SOURCES):
    keys={'schema_version','scope','profile',*NONCES,'frequency','start_qpc','root_deadline_qpc','deadline_qpc','guard_job_name',
        'source_hashes','source_sha256','device_sha256','actor_sha256','manifest_sha256','origin_actor_sha256','origin_manifest_sha256','recovery_plan_sha256'}
    require(type(c) is dict and set(c)==keys and type(c['schema_version']) is int and c['schema_version']==1 and c['scope']==SCOPE and c['profile']==PROFILE,'ipc_config')
    require(all(base.ac.nonce(c[k]) for k in NONCES) and c['run']!=c['case'],'ipc_nonces')
    live.clock_record(c['start_qpc'],c['frequency'],c['root_deadline_qpc'])
    require(c['root_deadline_qpc']==c['start_qpc']+120*c['frequency'] and c['deadline_qpc']==c['root_deadline_qpc']-5*c['frequency']
        and c['guard_job_name']=='Local\\RuleProxy.LocalGuard.'+c['run'],'ipc_epoch')
    require(type(c['source_hashes']) is dict and set(c['source_hashes'])==set(source_names) and all(base.ac.digest(v) for v in c['source_hashes'].values())
        and sha(encode(c['source_hashes']))==c['source_sha256'],'ipc_source')
    require(all(base.ac.digest(c[k]) for k in keys if k.endswith('_sha256')),'ipc_digest');return c
def validate_plan(p,*,device,source,actor,manifest,origin_actor,origin_manifest):
    keys={'schema_version','scope','profile',*NONCES,'device_sha256','source_sha256','actor_sha256','manifest_sha256','origin_actor_sha256','origin_manifest_sha256','recovery_reference',*ACKS}
    require(type(p) is dict and set(p)==keys and type(p['schema_version']) is int and p['schema_version']==1 and p['scope']==SCOPE and p['profile']==PROFILE,'ipc_plan')
    require(all(p[k] is True for k in ACKS) and all(base.ac.nonce(p[k]) for k in NONCES) and p['run']!=p['case'],'ipc_plan_ack')
    require([p[k] for k in ('device_sha256','source_sha256','actor_sha256','manifest_sha256','origin_actor_sha256','origin_manifest_sha256')]
        ==[device,source,actor,manifest,origin_actor,origin_manifest],'ipc_plan_binding')
    require(type(p['recovery_reference']) is str and 1<=len(p['recovery_reference'])<=512 and not any(x in p['recovery_reference'] for x in '\r\n\0'),'ipc_recovery_reference');return p
def verify_actor(actor,manifest,ah,mh,*,root):
    actor=launcher.checked_path(actor);manifest=launcher.checked_path(manifest);require(actor.name==ACTOR and manifest.name==MANIFEST and actor.parent==manifest.parent,'ipc_artifact_name')
    raw=local.bounded(manifest,8192);v=decode(raw);keys={'schemaVersion','compileOnly','runtimeAcceptance','interfaceVersion','executableSha256',*NATIVE_SOURCES}
    require(type(v) is dict and set(v)==keys and type(v['schemaVersion']) is int and v['schemaVersion']==1 and type(v['interfaceVersion']) is int and v['interfaceVersion']==1
        and v['compileOnly'] is True and v['runtimeAcceptance'] is False and v['executableSha256']==ah and sha(raw)==mh,'ipc_manifest')
    require(base.ac.digest(ah) and base.ac.digest(mh) and sha(local.bounded(actor,8*1024*1024))==ah,'ipc_actor_hash')
    for k,name in NATIVE_SOURCES.items():require(v[k]==sha(local.bounded(launcher.checked_path(Path(root)/name,inside=root),256*1024)),'ipc_native_pin')
    return actor
def verify_artifacts(c,root):
    verify_actor(root/'inputs'/ACTOR,root/'inputs'/MANIFEST,c['actor_sha256'],c['manifest_sha256'],root=root)
    origin.verify_artifact(root/'inputs'/origin.ACTOR,root/'inputs'/origin.MANIFEST,c['origin_manifest_sha256'],c['origin_actor_sha256'],source_root=root)
def expected_acl(root,path):
    if path==root:return [(0,0x1200a9)]
    if path==root/'inputs':return [(3,0x1200a9)]
    if (root/'inputs') in path.parents:return [(16,0x1200a9)]
    if path==root/'selected-report':return [(3,0x1301bf)]
    if (root/'selected-report') in path.parents:return [(16,0x1301bf)]
    return []
def info_values(info):return [int(info.hProcess or 0),int(info.hThread or 0),int(info.dwProcessId),int(info.dwThreadId)]
def handle_list(value,pending):
    require(type(value) in (list,tuple) and len(value)==2 and all(type(h) is int and 0<h<1<<64 for h in value) and value[0]!=value[1]
        and all(h in pending for h in value),'ipc_exact_two_handles');return tuple(value)

class API(zero.API):
    """Narrow new constructor. No caller gets socket/process/token authority."""
    def pipe_descriptor(self,sid):
        require(launcher.SID_PATTERN.fullmatch(sid) is not None,'ipc_pipe_user')
        expected='D:P(A;;FA;;;SY)(A;;FA;;;'+sid+')';pointer=C.c_void_p()
        self.a.ConvertStringSecurityDescriptorToSecurityDescriptorW.argtypes=[C.c_wchar_p,C.c_uint32,C.POINTER(C.c_void_p),C.c_void_p]
        self.a.ConvertStringSecurityDescriptorToSecurityDescriptorW.restype=C.c_int
        try:ok=self.a.ConvertStringSecurityDescriptorToSecurityDescriptorW(expected,1,C.byref(pointer),None)
        except BaseException:
            # Failed/exceptional allocation outputs are not free authority.
            self.controls_uncertain=True
            raise
        if not ok or not pointer.value:self.controls_uncertain=True;raise ValueError('ipc_pipe_descriptor_unknown')
        return pointer.value,expected
    def pipe_sddl(self,handle):
        sd,text=C.c_void_p(),C.c_wchar_p();owned_sd=owned_text=None
        self.a.GetSecurityInfo.argtypes=[C.c_void_p,C.c_int,C.c_uint32,C.c_void_p,C.c_void_p,C.c_void_p,C.c_void_p,C.POINTER(C.c_void_p)];self.a.GetSecurityInfo.restype=C.c_uint32
        self.a.ConvertSecurityDescriptorToStringSecurityDescriptorW.argtypes=[C.c_void_p,C.c_uint32,C.c_uint32,C.POINTER(C.c_wchar_p),C.c_void_p];self.a.ConvertSecurityDescriptorToStringSecurityDescriptorW.restype=C.c_int
        try:
            status=self.a.GetSecurityInfo(handle,6,4,None,None,None,None,C.byref(sd))
            if status!=0 or not sd.value:self.controls_uncertain=True;raise ValueError('ipc_pipe_sd_read_unknown')
            owned_sd=sd.value
            ok=self.a.ConvertSecurityDescriptorToStringSecurityDescriptorW(sd,1,4,C.byref(text),None)
            if not ok or not C.cast(text,C.c_void_p).value:self.controls_uncertain=True;raise ValueError('ipc_pipe_sd_text_unknown')
            value=C.cast(text,C.c_void_p).value
            if value==owned_sd:self.controls_uncertain=True;raise ValueError('ipc_pipe_readback_allocation_alias')
            owned_text=value
            return text.value
        except BaseException:
            self.controls_uncertain=True
            raise
        finally:
            uncertain=False
            for value in (owned_text,owned_sd):
                if value:
                    try:require(not self.k.LocalFree(value),'ipc_pipe_readback_free')
                    except BaseException:uncertain=True
            if uncertain:self.controls_uncertain=True;raise ValueError('ipc_pipe_readback_close')
    def pipe_flags(self,h):
        flags=C.c_uint32();self.k.GetHandleInformation.argtypes=[C.c_void_p,C.POINTER(C.c_uint32)];self.k.GetHandleInformation.restype=C.c_int
        self.native.check(self.k.GetHandleInformation(h,C.byref(flags)),'GetHandleInformation(pipe)');return flags.value
    def pipe_type(self,h):
        self.k.GetFileType.argtypes=[C.c_void_p];self.k.GetFileType.restype=C.c_uint32
        return self.k.GetFileType(h)
    def allocate_pipe(self,owners,other_pending,sid,state,budget,end):
        state.update(attempted=False,returned=False,api_success=None,error=None,raw_outputs=None,unknown=False,adopted=False,readback=False,return_qpc=None)
        budget.require_ms(end);rd,wr=C.c_void_p(),C.c_void_p();sd,expected=self.pipe_descriptor(sid)
        try:
            sa=launcher.SecurityAttributes(C.sizeof(launcher.SecurityAttributes),sd,True);state['attempted']=True
            try:ok=self.k.CreatePipe(C.byref(rd),C.byref(wr),C.byref(sa),4096)
            except BaseException:state.update(unknown=True,raw_outputs=[int(rd.value or 0),int(wr.value or 0)]);raise
            error=0 if ok else C.get_last_error();state.update(returned=True,api_success=bool(ok),error=None if ok else error,raw_outputs=[int(rd.value or 0),int(wr.value or 0)])
            if not ok:
                # Failed outputs are indeterminate even when both happen to be
                # zero. Never add/close these raw numbers or retry allocation.
                state['unknown']=True
                try:state['return_qpc']=budget.read()
                except BaseException:pass
                raise launcher.NativeFailure('CreatePipe',error)
            values=(int(rd.value or 0),int(wr.value or 0));pending=set(owners.pending)|set(other_pending)
            if not all(values) or values[0]==values[1] or any(h in pending for h in values):state['unknown']=True;raise ValueError('ipc_pipe_output_alias')
            for h in values:owners.add(h)
            state['adopted']=True
            state['return_qpc']=budget.read()
            for h in values:
                require(self.pipe_sddl(h)==expected and self.pipe_flags(h)&1==1,'ipc_pipe_security_or_inherit')
                require(self.pipe_type(h)==3,'ipc_pipe_type')
            budget.require_ms(end);state['readback']=True;return values
        finally:
            p,sd=sd,None
            try:require(not self.k.LocalFree(p),'ipc_pipe_descriptor_free')
            except BaseException:self.controls_uncertain=True;raise
    def pair_spawn(self,info,argv,cwd,environment,job,owners,state,*,ends,pipe_pending,profile_pointer,budget,end,on_return):
        ends=handle_list(ends,pipe_pending);selected=profile_pointer is not None
        require(Path(argv[0]).name==(ACTOR if selected else origin.ACTOR) and argv[1]==('pipe-front' if selected else 'pipe-relay') and job,'ipc_constructor_role')
        require(type(environment) is str and environment.endswith('\0\0'),'ipc_constructor_environment')
        if selected:require({v.split('=',1)[0] for v in environment.rstrip('\0').split('\0')}=={'SystemRoot','LOCALAPPDATA'},'ipc_selected_environment')
        for h in ends:require(self.pipe_flags(h)&1==1 and self.pipe_type(h)==3,'ipc_constructor_pipe')
        state.update(create_status='not_entered',create_winerror=None,create_information='not_observed',create_exception_detail=None,returned_qpc=None)
        count=4 if selected else 2;size=C.c_size_t();self.k.InitializeProcThreadAttributeList(None,count,0,C.byref(size));require(1<=size.value<=65536,'ipc_attribute_size')
        attrs=C.create_string_buffer(size.value);self.native.check(self.k.InitializeProcThreadAttributeList(attrs,count,0,C.byref(size)),'InitializeProcThreadAttributeList(pipe)')
        try:
            jobs=(C.c_void_p*1)(job);handles=(C.c_void_p*2)(*ends);values=[(base.JOB_LIST,jobs),(0x20002,handles)]
            if selected:
                caps=self.proc._SecurityCapabilities(profile_pointer,None,0,0);aap=C.c_uint32(1)
                values.extend(((base.SECURITY_CAPABILITIES,caps),(base.ALL_APPLICATION_PACKAGES_POLICY,aap)))
            for kind,value in values:self.native.check(self.k.UpdateProcThreadAttribute(attrs,0,kind,C.byref(value),C.sizeof(value),None,None),'UpdateProcThreadAttribute(pipe)')
            startup=self.proc._StartupInfoEx();startup.StartupInfo.cb=C.sizeof(startup);startup.lpAttributeList=C.cast(attrs,C.c_void_p)
            command=C.create_unicode_buffer(subprocess.list2cmdline(argv));env=C.create_unicode_buffer(environment);raw_info=self.process_info()
            budget.require_ms(end);state['creation_attempted']=True;physical_error=None;clock_error=None;receipt_error=None
            try:
                ok=self.k.CreateProcessW(argv[0],command,None,None,True,self.proc._CREATE_SUSPENDED|self.proc._CREATE_UNICODE_ENVIRONMENT|self.proc._EXTENDED_STARTUPINFO_PRESENT|0x08000000,env,str(cwd),C.byref(startup),C.byref(raw_info))
                error=0 if ok else C.get_last_error()
                state.update(create_status='returned_true' if ok else 'returned_false',create_winerror=None if ok else error,raw_return=int(ok),raw_error=None if ok else error)
            except BaseException as e:
                physical_error=e;state.update(create_status='exception',raw_return=None,raw_error=None,create_exception_detail=base.private_failure_detail(e,'CreateProcessW(lpac-pipe)'))
            state['raw_pi']=info_values(raw_info);state['create_information']='nonzero' if any(state['raw_pi']) else 'all_zero'
            try:state['returned_qpc']=budget.read()
            except BaseException as e:clock_error=e
            # The raw return/PI receipt is attempted before interpretation or
            # adoption. A failed receipt cannot erase known TRUE cleanup rights.
            try:on_return(state.copy())
            except BaseException as e:receipt_error=e;self.controls_uncertain=True
            v=state['raw_pi'];known_success=(physical_error is None and state['raw_return']!=0 and len(v)==4 and all(v)
                and v[0]!=v[1] and all(type(x) is int and 0<x<(1<<64 if i<2 else 1<<32) for i,x in enumerate(v))
                and not any(h in set(owners.pending)|set(pipe_pending) for h in v[:2]))
            timely=clock_error is None and isinstance(state['returned_qpc'],int) and state['returned_qpc']<end
            known_none=(physical_error is None and state['raw_return']==0 and type(state['raw_error']) is int and state['raw_error']>0 and not any(v) and timely)
            state['creation_unknown']=not known_success and not known_none
            if known_success:
                info.hProcess,info.hThread,info.dwProcessId,info.dwThreadId=v
                owners.add(v[0]);owners.add(v[1])
            if physical_error is not None:raise physical_error
            if clock_error is not None:raise clock_error
            if receipt_error is not None:raise receipt_error
            if state['raw_return']==0:raise launcher.NativeFailure('CreateProcessW(lpac-pipe)',state['raw_error'])
            require(known_success,'ipc_unknown_process_outputs');budget.require_ms(end)
        finally:
            try:self.k.DeleteProcThreadAttributeList(attrs)
            except BaseException:self.controls_uncertain=True;raise

def task_projection(row):
    v=base.task_projection(row)
    v.update({k:row.get(k) for k in ('role','command','expected_primary','held_checks','ends','receipt','resume_intent_qpc','exit_observed_qpc')});return v

class Owner(cell.CellOwner):
    """Only the new coordination seam; existing owners never execute."""
    def __init__(self,root,c,parent,api,budget):
        super().__init__(root,c,parent,api,budget);self.pipes=helpers.OneShotHandles(api.close);self.port=None
        self.j=dict(schema_version=1,stage='lpac-pipe-origin-result',scope=SCOPE,profile=PROFILE,config_sha256=sha(encode(c)),failure=None,failure_detail=None,
            profile_name='ruleproxy-lpac-pipe-'+c['run'],profile_sid=None,profile_state=dict(attempted=False,returned=False,created=False,sid_pointer_returned=False),
            child_environment=launcher.default_child_environment(),intents=[],pair=None,pipe_allocations=[],pipe_allocation_unknown=False,creation_unknown=False,parent_pipe_close_attempts=[],
            tasks=[],cleanup_tasks=[],proof=None,observer_attempted=False,labels=[],
            reports={k:None for k in REPORT_PATHS},report_status={k:'unavailable' for k in REPORT_PATHS},origin_start=None,port=None,
            selected_ipc_observed=False,relay_connect_observed=False,origin_accepted_observed=False,origin_request_observed=False,origin_response_observed=False,
            mechanism_verified=False,natural_exits=False,completion_qpc=None,workload_stop=False,**dict.fromkeys(CLEAN_KEYS,False),**dict.fromkeys(FALSE_CLAIMS,False))
        self.j['observer_resources_cleanup_verified']=True;self.j['labels_restored']=True;self.phase='setup'
    def journal(self,label,**extra):
        allowed={'profile-create','acl-grant','label-lower','label-restore','acl-remove','profile-delete','workload-stop','pair-epoch','observe-lpac',
            'allocate-response','allocate-request','parent-pipe-close','resume-authorized','spawn-grant-root','spawn-grant-inputs','spawn-grant-selected-report','spawn-remove',
            *(('spawn-'+role) for role in ROLES)}
        require(label in allowed and len(self.j['intents'])<32,'ipc_intent')
        v=dict(schema_version=1,scope=SCOPE,run=self.c['run'],config_sha256=sha(encode(self.c)),frequency=self.c['frequency'],deadline_qpc=self.c['deadline_qpc'],qpc=self.budget.read(),action=label,extra=extra)
        raw=encode(v);p=self.root/'journal'/('%02d-%s.json'%(len(self.j['intents']),label));base.durable_private(p,raw)
        row=dict(name=p.name,text=raw.decode('ascii'),sha256=sha(raw));self.j['intents'].append(row);return v['qpc']
    def acl_command(self,name):
        tool=str(self.fixed_tool('icacls.exe'));sid='*'+self.profile['sid']
        if name=='remove':return [tool,str(self.root),'/remove:g',sid,'/T','/Q']
        rows=[r for r in GRANTS if 'grant-'+r[0]==name];require(len(rows)==1,'ipc_grant_name');_,path,right=rows[0]
        return [tool,str(self.root/path),'/grant',sid+':'+right,'/Q']
    def task(self,name,argv,work,**kw):
        require(name in (*('grant-'+r[0] for r in GRANTS),'remove') and argv==self.acl_command(name) and work==self.root/'tools'/name
            and kw.get('stdio') is True and not kw.get('lpac',False) and bool(kw.get('cleanup',False))==(name=='remove'),'ipc_fixed_ordinary_tool')
        # The inherited ordinary seam uses this explicit existing owned TEMP.
        require((self.root/'health/temp').is_dir(),'ipc_tool_temp');return base.Owner.task(self,name,argv,work,**kw)
    def scope_acl(self,removed=False):
        for p in owned_tree(self.root):
            self.budget.require_ms(self.budget.cutoff(3) if removed else work_cutoff(self.c))
            require(self.api.acl_read(p,self.profile['sid'])==([] if removed else expected_acl(self.root,p)),'ipc_exact_acl')
    def setup(self):
        owned_tree(self.root);self.budget.require_ms(work_cutoff(self.c));self.catalog={}
        folder=self.api.local_appdata(self.budget,self.j['child_environment']);self.selected_environment=self.api.front_environment(folder,self.j['child_environment'])
        require(launcher.child_environment_admitted(self.j['child_environment']),'ipc_admitted_environment');self.job=self.api.owned_job(self.owners)
        self.journal('profile-create')
        try:self.api.create_profile(self.j['profile_name'],self.profile)
        finally:self.j['profile_state']={k:self.profile[k] for k in ('attempted','returned','created')};self.j['profile_state']['sid_pointer_returned']=bool(self.profile['pointer']);self.j['profile_sid']=self.profile['sid']
        require(self.profile['created'] and self.api.derive_profile_sid(self.j['profile_name'])==self.profile['sid'],'ipc_fresh_profile')
        for p in owned_tree(self.root):require(self.api.acl_read(p,self.profile['sid'])==[],'ipc_fresh_acl')
        self.journal('acl-grant')
        for label,_,_ in GRANTS:self.tool(self.acl_command('grant-'+label),'grant-'+label)
        self.scope_acl();p=self.root/'selected-report';before=self.api.label_read(p);require(before is None,'ipc_initial_label_absence')
        row=dict(name='selected-report',before=None,attempted=False,lowered=False,restored=False);self.j['labels'].append(row);self.journal('label-lower');row['attempted']=True;self.j['labels_restored']=False
        try:self.api.label_set(p,zero.LOW_LABEL);require(self.api.label_read(p)==zero.LOW_LABEL,'ipc_low_label_readback');row['lowered']=True
        except BaseException:self.api.controls_uncertain=True;raise
    def held(self,row,end):
        self.budget.require_ms(end);h=row['info'].hProcess
        require(row['created'] is not None and not self.api.wait(h,0) and self.api.process_id(h)==row['pid'] and self.api.creation_time(h)==row['created'],'ipc_held_generation')
        self.api.verify_job(self.job,h);self.api.verify_outer(self.c['guard_job_name'],h);self.api.verify_image(h,Path(row['command'][0]))
        require(sha(local.bounded(Path(row['command'][0]),8*1024*1024))==row['image_sha256'],'ipc_held_image')
        current=zero.capture_primary(self.api,row['token'],self.parent,self.profile['sid'],self.budget,end,row['role']=='lpac-pipe-front')
        require(current==row['expected_primary'],'ipc_primary_changed')
        row['held_checks'].append(dict(qpc=self.budget.read(),pid=row['pid'],created=row['created'],image_sha256=row['image_sha256'],primary=current,inner_job=True,outer_job=True));self.budget.require_ms(end)
    def spawn(self,role,argv,end,ends=()):
        selected=role=='lpac-pipe-front';image=launcher.checked_path(argv[0],inside=self.root);expected=self.c['actor_sha256' if selected else 'origin_actor_sha256']
        require(sha(local.bounded(image,8*1024*1024))==expected,'ipc_spawn_image');info=self.api.process_info()
        row=dict(name=role,role=role,info=info,attempted=False,assigned=False,exited=False,exit_code=None,pid=None,created=None,token=None,identity=None,capabilities=None,lpac=None,
            lpac_expected=selected,process_returned=False,resumed=False,admitted=False,image_sha256=expected,admission_qpc=None,resume_qpc=None,go_qpc=[],command=argv,
            expected_primary=None,held_checks=[],ends=list(ends),receipt=None,resume_intent_qpc=None,exit_observed_qpc=None,create_observation=dict(status='not_entered',winerror=None,process_information='not_observed',returned_qpc=None,work_cutoff=end,exception_detail=None))
        self.children.append(row);self.tasks[role]=row;state=dict(creation_attempted=False);self.journal('spawn-'+role)
        def record_return(s):
            observation=dict(status=s.get('create_status','not_entered'),winerror=s.get('create_winerror'),process_information=s.get('create_information','not_observed'),
                returned_qpc=s.get('returned_qpc'),work_cutoff=end,exception_detail=s.get('create_exception_detail'))
            raw=encode(dict(schema_version=1,scope=SCOPE,config_sha256=sha(encode(self.c)),role=role,observation=observation,
                raw_return=s.get('raw_return'),raw_error=s.get('raw_error'),pi=s.get('raw_pi',info_values(info))))
            p=self.root/'returns'/(role+'.json');base.durable_private(p,raw);row['receipt']=dict(name=p.name,text=raw.decode('ascii'),sha256=sha(raw))
        try:
            if role=='ordinary-origin-fixture':self.api.atomic_spawn(info,argv,self.root/'origin-report',self.job,self.owners,state,environment=self.api.native.environment(self.root/'origin-report'),stdio=(),profile_pointer=None,catalog=None)
            else:self.api.pair_spawn(info,argv,self.root/'inputs',self.selected_environment if selected else self.api.native.environment(self.root/'relay-report'),self.job,self.owners,state,
                ends=ends,pipe_pending=self.pipes.pending,profile_pointer=self.profile['pointer'] if selected else None,budget=self.budget,end=end,on_return=record_return)
        finally:
            row.update(attempted=state['creation_attempted'],process_returned=bool(info.hProcess));row['pid']=int(info.dwProcessId) if info.dwProcessId else None
            tick=state.get('returned_qpc')
            if role=='ordinary-origin-fixture' and tick is None and state.get('create_status') in ('returned_true','returned_false'):
                try:tick=self.budget.read()
                except BaseException:pass
            if role=='ordinary-origin-fixture':state['returned_qpc']=tick
            row['create_observation']=dict(status=state.get('create_status','not_entered'),winerror=state.get('create_winerror'),process_information=state.get('create_information','not_observed'),returned_qpc=tick,work_cutoff=end,exception_detail=state.get('create_exception_detail'))
            if state.get('creation_unknown'):self.j['creation_unknown']=True
            try:
                if row['receipt'] is None and not state.get('raw_pi'):record_return(state)
            except BaseException:self.api.controls_uncertain=True;raise
        require(info.hProcess and info.hThread and row['pid'],'ipc_partial_create');self.budget.require_ms(end)
        row['created']=self.api.creation_time(info.hProcess);self.api.verify_job(self.job,info.hProcess);row['assigned']=True;self.api.verify_outer(self.c['guard_job_name'],info.hProcess);self.api.verify_image(info.hProcess,image)
        row['token']=self.api.token_for_process(info.hProcess);self.owners.add(row['token']);row['identity']=self.api.identity(row['token'])
        row['expected_primary']=zero.capture_primary(self.api,row['token'],self.parent,self.profile['sid'],self.budget,end,selected);row['capabilities']=[]
        self.held(row,end);row['admission_qpc']=self.budget.read();self.budget.require_ms(end);row['admitted']=True;return row
    def resume(self,row):
        if row.get('role') not in ROLES:return base.Owner.resume(self,row)
        end=self.j['pair']['end'] if row['role']!='ordinary-origin-fixture' else work_cutoff(self.c)
        self.held(row,end);require(row['admitted'] and not row['resumed'],'ipc_resume_once')
        if row['role']!='ordinary-origin-fixture':
            require(self.j['parent_pipe_handles_closed'] and not self.j['pipe_allocation_unknown'] and self.pipes.confirmed_closed and self.j['proof'] is not None and self.j['proof']['qualified']
                and self.j['observer_resources_cleanup_verified'] and all(self.tasks[k]['admitted'] for k in ROLES),'ipc_pair_resume_gate')
        row['resume_intent_qpc']=self.journal('resume-authorized',role=row['role']);self.budget.require_ms(end)
        self.api.resume(row['info'].hThread);row['resumed']=True;row['resume_qpc']=self.budget.read()
    def native(self,key):
        path=self.root/REPORT_PATHS[key];raw=local.bounded(path,MAX_NATIVE)
        self.j['reports'][key]=dict(text=raw.decode('ascii'),sha256=sha(raw));self.j['report_status'][key]='invalid'
        v=decode(raw);self.j['tasks']=[task_projection(r) for r in self.children]
        validate_native(key,v,self.j,self.c,self.parent);self.j['report_status'][key]='valid';return v
    def wait(self,row,end,code=0):
        if row.get('role') not in ROLES:return base.Owner.wait(self,row,end,code)
        base.Owner.wait(self,row,end,code);row['exit_observed_qpc']=self.budget.read();self.budget.require_ms(end)
    def origin_ready(self,row):
        p=self.root/REPORT_PATHS['ready'];end=work_cutoff(self.c)
        while not p.exists():
            self.budget.require_ms(end);require(not self.api.wait(row['info'].hProcess,0),'ipc_origin_exited_before_ready');self.api.sleep_ms(self.budget.require_ms(end,10))
        # The only concurrent report is ready; honor the existing share-zero
        # close protocol and the same absolute cutoff, never reopen a hot GO.
        while True:
            try:raw=local.bounded(p,MAX_NATIVE);break
            except OSError as e:
                if getattr(e,'winerror',None)!=32:raise
                self.api.sleep_ms(self.budget.require_ms(end,10))
        v=decode(raw);origin.validate_ready(v,run=self.c['run'],case=self.c['case'],pid=row['pid'],frequency=self.c['frequency'],deadline=end)
        self.j['reports']['ready']=dict(text=raw.decode('ascii'),sha256=sha(raw));self.j['report_status']['ready']='valid';self.port=self.j['port']=v['port'];self.held(row,end)
    def run(self):
        self.setup();c=self.c;self.phase='origin';self.j['origin_start']=self.budget.read()
        argv=[str(self.root/'inputs'/origin.ACTOR),'origin-fixture',c['run'],c['case'],str(self.root/REPORT_PATHS['origin']),str(self.root/REPORT_PATHS['ready']),str(c['frequency']),str(work_cutoff(c)),self.parent['sid']]
        fixture=self.spawn('ordinary-origin-fixture',argv,work_cutoff(c));self.resume(fixture);self.origin_ready(fixture)
        self.phase='pair';start=self.budget.read();end=start+10*c['frequency'];require(end<=work_cutoff(c),'ipc_pair_reserve');self.j['pair']=dict(start=start,end=end,frequency=c['frequency'])
        self.journal('pair-epoch',start=start,end=end)
        pairs=[]
        for label in ('response','request'):
            state=dict(name=label,receipt=None);self.j['pipe_allocations'].append(state);self.journal('allocate-'+label)
            try:pairs.append(self.api.allocate_pipe(self.pipes,self.owners.pending,self.parent['sid'],state,self.budget,end))
            finally:
                if state.get('unknown') or state.get('attempted') and not state.get('api_success'):self.j['pipe_allocation_unknown']=True
                raw=encode(dict(schema_version=1,scope=SCOPE,config_sha256=sha(encode(c)),pipe=label,observation={k:v for k,v in state.items() if k not in ('name','receipt')}))
                try:
                    p=self.root/'returns'/('pipe-'+label+'.json');base.durable_private(p,raw);state['receipt']=dict(name=p.name,text=raw.decode('ascii'),sha256=sha(raw))
                except BaseException:self.api.controls_uncertain=True;raise
        (front_read,relay_write),(relay_read,front_write)=pairs
        frontargs=[str(self.root/'inputs'/ACTOR),'pipe-front',c['run'],c['case'],str(self.root/REPORT_PATHS['selected']),str(front_read),str(front_write),str(start),str(c['frequency']),str(end),self.parent['sid'],self.profile['sid'],'0',str(self.port)]
        relayargs=[str(self.root/'inputs'/origin.ACTOR),'pipe-relay',c['run'],c['case'],str(self.root/REPORT_PATHS['relay']),str(relay_read),str(relay_write),str(start),str(c['frequency']),str(end),self.parent['sid'],'none','0',str(self.port)]
        front=self.spawn('lpac-pipe-front',frontargs,end,(front_read,front_write));relay=self.spawn('ordinary-pipe-relay',relayargs,end,(relay_read,relay_write))
        for row in (front,relay,fixture):self.held(row,end)
        self.phase='accesscheck';self.journal('observe-lpac');self.j['observer_attempted']=True;self.j['observer_resources_cleanup_verified']=False
        self.j['proof']=zero.observe_held(self.api.access_api(),front['info'].hProcess,front['expected_primary'],expected_pid=front['pid'],expected_creation=front['created'],expected_role='lpac',frequency=c['frequency'],deadline=end)
        self.j['observer_resources_cleanup_verified']=self.j['proof']['resource_cleanup_verified']
        if not self.j['observer_resources_cleanup_verified']:self.api.controls_uncertain=True
        require(self.j['proof']['qualified'],'ipc_lpac_proof')
        for row in (front,relay,fixture):self.held(row,end)
        self.journal('parent-pipe-close');uncertain=False
        for h in (front_read,relay_write,relay_read,front_write):
            entry=dict(handle=h,attempted=True,confirmed=False);self.j['parent_pipe_close_attempts'].append(entry)
            try:self.pipes.close(h);entry['confirmed']=True
            except BaseException:uncertain=True
        self.j['parent_pipe_handles_closed']=not uncertain and self.pipes.confirmed_closed
        require(self.j['parent_pipe_handles_closed'],'ipc_parent_close');self.phase='protocol';self.resume(relay);self.resume(front)
        for row in (front,relay):self.wait(row,end)
        # Do not substitute a zero-time cleanup poll for healthy fixture exit.
        self.wait(fixture,end);self.j['natural_exits']=True
        for key in ('selected','relay','origin'):self.native(key);self.budget.require_ms(end)
        self.j['completion_qpc']=self.budget.read();self.budget.require_ms(end)
        self.j['mechanism_verified']=positive(self.j,c,self.parent)
        require(self.j['mechanism_verified'],'ipc_positive')
    def restore_labels(self):
        if not any(r['attempted'] for r in self.j['labels']):self.j['labels_restored']=True;return
        self.journal('label-restore')
        for r in self.j['labels']:
            require(r['name']=='selected-report' and r['before'] is None,'ipc_label_restore_scope')
            if not r['attempted']:continue
            p=self.root/r['name']
            for x in sorted(owned_tree(p),key=lambda q:len(q.parts),reverse=True):self.budget.require_ms(self.budget.cutoff(5));self.api.label_set(x,None)
            for x in owned_tree(p):require(self.api.label_read(x) is None,'ipc_label_absence_readback')
            r['restored']=True
        self.j['labels_restored']=all(not r['attempted'] or r['restored'] for r in self.j['labels'])
    def cleanup(self):
        clean=False
        try:
            if any(r['info'].hProcess and not r['exited'] for r in self.children):self.journal('workload-stop')
            rows=[r for r in self.children if not base.known_no_child(r,start=self.c['start_qpc'])]
            clean,empty,stop=base.ac._cleanup(self.api,live.CleanupView(self.budget,self.budget.cutoff(12)),self.job,rows,origin.CombinedLedgers(self.owners,self.pipes))
            self.j.update(workload_cleanup=clean,workload_job_empty=empty,workload_stop=stop)
        except BaseException:pass
        self.j['parent_pipe_handles_closed']=self.pipes.confirmed_closed
        self.j['pipe_allocation_known']=not self.j['pipe_allocation_unknown']
        # Harvest each independently bound peer's positive facts after known
        # held exit even when a different peer/report failed. Invalid raw only
        # gets a commitment; it never substitutes for a successful report.
        for key,role in (('selected','lpac-pipe-front'),('relay','ordinary-pipe-relay'),('origin','ordinary-origin-fixture')):
            row=self.tasks.get(role)
            if row and row['exited'] and (self.root/REPORT_PATHS[key]).exists():
                try:self.native(key)
                except BaseException:pass
        self.j['tasks']=[task_projection(r) for r in self.children];harvest(self.j,self.c,self.parent)
        if clean and self.j['pipe_allocation_known'] and not self.j['creation_unknown'] and self.j['observer_resources_cleanup_verified'] and not self.api.controls_uncertain:
            try:self.restore_labels()
            except BaseException:pass
            if self.j['labels_restored'] and self.profile['created']:
                ledger=helpers.OneShotHandles(self.api.close);children=[];job=None
                try:
                    job=self.api.owned_job(ledger);self.journal('acl-remove');self.tool(self.acl_command('remove'),'remove',cleanup=True,owners=ledger,children=children,job=job)
                    self.scope_acl(True);self.j['acl_removed']=True
                except BaseException:pass
                finally:
                    try:self.j['cleanup_tools']=base.ac._cleanup(self.api,live.CleanupView(self.budget,self.budget.cutoff(3)),job,[r for r in children if not base.known_no_child(r,start=self.c['start_qpc'])],ledger)[0]
                    except BaseException:pass
                    self.j['cleanup_tasks']=[task_projection(r) for r in children]
                if self.j['acl_removed'] and self.j['cleanup_tools'] and not self.api.controls_uncertain:
                    try:self.journal('profile-delete');self.api.delete_profile(self.j['profile_name']);self.j['profile_deleted']=True
                    except BaseException:pass
            elif not self.profile['attempted']:self.j.update(acl_removed=True,cleanup_tools=True,profile_deleted=True)
        try:self.api.release_profile_sid(self.profile);self.j['sid_released']=True
        except BaseException:pass
        if not all(self.j[k] for k in CLEAN_KEYS):self.j['failure']=self.j['failure'] or 'cleanup'
    def execute(self):
        try:self.run()
        except BaseException as e:self.j['failure']=self.phase;self.j['failure_detail']=base.private_failure_detail(e)
        finally:self.cleanup()
        self.j['tasks']=[task_projection(r) for r in self.children];return self.j

def record_value(record,*,root=None,path=None,limit=MAX_NATIVE):
    require(type(record) is dict and set(record)=={'text','sha256'} and type(record['text']) is str and base.ac.digest(record['sha256']),'ipc_raw_record')
    raw=record['text'].encode('ascii');require(0<len(raw)<=limit and sha(raw)==record['sha256'],'ipc_raw_commitment')
    if root is not None:require(local.bounded(launcher.checked_path(Path(root)/path,inside=root),limit)==raw,'ipc_physical_record')
    return decode(raw)
def actor_rows(j):return {r['role']:r for r in j['tasks'] if r['role'] in ROLES}
def expected_argv(role,j,c,root,parent):
    p=Path(root);port=j['port'];pair=j['pair'];rows=actor_rows(j)
    if role=='ordinary-origin-fixture':return [str(p/'inputs'/origin.ACTOR),'origin-fixture',c['run'],c['case'],str(p/REPORT_PATHS['origin']),str(p/REPORT_PATHS['ready']),str(c['frequency']),str(work_cutoff(c)),parent['sid']]
    handles=rows[role]['ends'];selected=role=='lpac-pipe-front'
    return [str(p/'inputs'/(ACTOR if selected else origin.ACTOR)),'pipe-front' if selected else 'pipe-relay',c['run'],c['case'],str(p/REPORT_PATHS['selected' if selected else 'relay']),
        *(str(h) for h in handles),str(pair['start']),str(c['frequency']),str(pair['end']),parent['sid'],j['profile_sid'] if selected else 'none','0',str(port)]
def validate_native(key,v,j,c,parent):
    rows=actor_rows(j);require(key in REPORT_PATHS,'ipc_report_key')
    if key=='ready':
        r=rows['ordinary-origin-fixture'];origin.validate_ready(v,run=c['run'],case=c['case'],pid=r['pid'],frequency=c['frequency'],deadline=work_cutoff(c));require(v['port']==j['port'],'ipc_ready_port');return v
    pair=j['pair'];require(pair is not None and base.ac.integer(j['port'],49153,65535),'ipc_report_epoch')
    role={'selected':'lpac-pipe-front','relay':'ordinary-pipe-relay','origin':'ordinary-origin-fixture'}[key];r=rows[role]
    if key=='origin':
        origin.validate_fixture(v,run=c['run'],case=c['case'],pid=r['pid'],held=r['identity'],frequency=c['frequency'],deadline=work_cutoff(c),start_min=j['origin_start'],port=j['port'])
        require(r['resume_intent_qpc'] is not None and v['qpc'][3]>=r['resume_intent_qpc'],'ipc_origin_resume_causality');return v
    expected=dict(role='pipe-front' if key=='selected' else 'pipe-relay',run_id=c['run'],case_id=c['case'],pid=r['pid'],identity=r['identity'],frequency=c['frequency'],
        start=pair['start'],end=pair['end'],expected_ac_sid=j['profile_sid'] if key=='selected' else None)
    if key=='relay':
        origin.validate_native(v,port=j['port'],**expected)
        require(r['resume_intent_qpc'] is not None and v['ipc_mechanics']['qpc'][3]>=r['resume_intent_qpc'],'ipc_relay_resume_causality');return v
    keys={'schema_version','stage','role','run_id','case_id','pid','ipc_mechanics','admitted_qpc','read_handle_inherit_cleared','write_handle_inherit_cleared','identity_basis',
        'network_tested','proxy_tested','product_acceptance'}
    require(type(v) is dict and set(v)==keys and type(v['schema_version']) is int and v['schema_version']==1 and v['stage']=='lpac-ipc-origin-selected'
        and v['role']=='lpac-pipe-front' and v['run_id']==c['run'] and v['case_id']==c['case'] and type(v['pid']) is int and v['pid']==r['pid']
        and v['identity_basis']=='external-held-four-descriptor-required' and all(v[k] is False for k in ('network_tested','proxy_tested','product_acceptance')),'ipc_selected_wrapper')
    require(all(type(v[k]) is bool for k in ('read_handle_inherit_cleared','write_handle_inherit_cleared')),'ipc_flag_readback_type')
    origin.a.validate_ac_native(v['ipc_mechanics'],**expected)
    t=v['admitted_qpc'];last=v['ipc_mechanics']['qpc'][3]
    require(r['resume_intent_qpc'] is not None and last>=r['resume_intent_qpc'],'ipc_selected_resume_causality')
    require(t is None or base.ac.integer(t,r['resume_intent_qpc'],last),'ipc_native_resume_causality')
    require(t is not None or v['ipc_mechanics']['failure'] is not None,'ipc_missing_admitted_tick');return v
def mechanics_passed(v,front):
    p=v['pipe'];co=v['core'];counts=[96,144,2,3] if front else [144,96,3,2];mask=7 if front else 56
    return (v['failure'] is None and v['win32_error'] is None and v['qpc'][3]<v['qpc'][2] and p['inheritance_cleared'] and p['eof_observed']
        and [p[k] for k in ('read_bytes','write_bytes','read_frames','write_frames')]==counts and all(p[k]=='confirmed' for k in ('reader_close','writer_close'))
        and co==dict(failure=0,observations=177 if front else 78,requested=mask,confirmed=mask,uncertain=0)
        and v['synthetic_http']==dict(request_checked=True,response_checked=True,client_sink_checked=front))
def validated_reports(j,c,parent):
    out={}
    for key,raw in j['reports'].items():
        if raw is not None and j['report_status'][key]=='valid':out[key]=validate_native(key,record_value(raw),j,c,parent)
    return out
def harvest(j,c,parent):
    # All facts are monotonic. A malformed other report cannot erase a bound
    # origin/relay event. These events do not independently qualify the cell.
    for key in ('selected','relay','origin'):
        if j['reports'][key] is None or j['report_status'][key]!='valid':continue
        try:v=validate_native(key,record_value(j['reports'][key]),j,c,parent)
        except BaseException:continue
        if key=='selected':j['selected_ipc_observed']|=bool(v['ipc_mechanics']['pipe']['read_bytes'] or v['ipc_mechanics']['pipe']['write_bytes'])
        elif key=='relay':j['relay_connect_observed']|=v['origin']['connect_completed']
        else:
            j['origin_accepted_observed']|=v['socket']['accepted'];j['origin_request_observed']|=v['socket']['request_bytes']>0;j['origin_response_observed']|=v['socket']['response_bytes']>0
def positive(j,c,parent):
    try:
        rows=actor_rows(j);reports=validated_reports(j,c,parent);require(set(rows)==set(ROLES) and set(reports)==set(REPORT_PATHS),'ipc_positive_reports')
        state=j['profile_state'];require(all(state.values()) and base.ac.ac_profile_sid(j['profile_sid']) and len(j['labels'])==1 and j['labels'][0]['name']=='selected-report'
            and j['labels'][0]['attempted'] and j['labels'][0]['lowered'],'ipc_positive_owned_profile_label')
        grants={r['name']:r for r in j['tasks'] if r['role'] not in ROLES}
        require(set(grants)=={'grant-'+r[0] for r in GRANTS} and all(r['attempted'] and r['process_returned'] and r['assigned'] and r['admitted'] and r['resumed'] and r['exited'] and r['exit_code']==0 for r in grants.values()),'ipc_positive_grant_ledgers')
        require(all(r['receipt'] is not None and r['create_observation']['status']=='returned_true' for r in rows.values()),'ipc_positive_create_receipts')
        require(j['proof'] is not None and j['proof']['qualified'] and j['observer_resources_cleanup_verified'] and j['parent_pipe_handles_closed'] and not j['pipe_allocation_unknown'] and not j['creation_unknown'],'ipc_positive_resources')
        require(len(j['pipe_allocations'])==2 and all(r['receipt'] is not None and r['adopted'] and r['readback'] and base.ac.integer(r['return_qpc'],j['pair']['start'],j['pair']['end']-1) for r in j['pipe_allocations']),'ipc_positive_pipe_receipts')
        selected=reports['selected'];relay=reports['relay'];fixture=reports['origin']
        require(selected['read_handle_inherit_cleared'] and selected['write_handle_inherit_cleared'] and selected['admitted_qpc'] is not None
            and mechanics_passed(selected['ipc_mechanics'],True) and mechanics_passed(relay['ipc_mechanics'],False) and origin.relay_passed(relay['origin'],c['case'])
            and origin.fixture_passed(fixture,c['case']),'ipc_positive_protocol')
        require(relay['origin']['local_port']==fixture['socket']['peer_port'] and relay['origin']['peer_port']==fixture['socket']['port']==j['port'],'ipc_peer_tuple')
        require(j['natural_exits'] and all(r['admitted'] and r['resumed'] and r['exited'] and r['exit_code']==0 for r in rows.values())
            and base.ac.integer(j['completion_qpc'],j['pair']['start'],j['pair']['end']-1) and fixture['qpc'][3]<j['pair']['end'],'ipc_positive_epoch')
        final_ticks=[selected['ipc_mechanics']['qpc'][3],relay['ipc_mechanics']['qpc'][3],fixture['qpc'][3],j['proof']['end_qpc']]
        native_final={'lpac-pipe-front':selected['ipc_mechanics']['qpc'][3],'ordinary-pipe-relay':relay['ipc_mechanics']['qpc'][3],'ordinary-origin-fixture':fixture['qpc'][3]}
        for role,r in rows.items():
            end=work_cutoff(c) if role=='ordinary-origin-fixture' else j['pair']['end']
            require(base.ac.integer(r['resume_qpc'],r['resume_intent_qpc'],end-1) and base.ac.integer(r['exit_observed_qpc'],r['resume_intent_qpc'],j['pair']['end']-1),'ipc_positive_resume_exit_clock')
            require(r['exit_observed_qpc']>=max(native_final[role],r['resume_qpc']),'ipc_positive_held_exit_causality')
            final_ticks.extend((r['resume_qpc'],r['exit_observed_qpc']))
        require(j['completion_qpc']>=max(final_ticks),'ipc_positive_completion_causality')
        return True
    except (ValueError,KeyError,TypeError):return False

TASK_KEYS={'name','attempted','assigned','exited','exit_code','pid','created','identity','capabilities','lpac','lpac_expected','resumed','admitted','image_sha256','admission_qpc','resume_qpc','go_qpc','process_returned','create_observation',
    'role','command','expected_primary','held_checks','ends','receipt','resume_intent_qpc','exit_observed_qpc'}
RESULT_KEYS={'schema_version','stage','scope','profile','config_sha256','failure','failure_detail','profile_name','profile_sid','profile_state','child_environment','intents','pair','pipe_allocations','pipe_allocation_unknown','creation_unknown','parent_pipe_close_attempts',
    'tasks','cleanup_tasks','proof','observer_attempted','observer_resources_cleanup_verified','labels','labels_restored','reports','report_status','origin_start','port','selected_ipc_observed','relay_connect_observed','origin_accepted_observed','origin_request_observed','origin_response_observed',
    'mechanism_verified','natural_exits','completion_qpc','workload_stop',*CLEAN_KEYS,*FALSE_CLAIMS}
def validate_result(j,c,*,parent,root=None):
    config_validate(c);require(launcher.token_is_ordinary(parent),'ipc_parent')
    require(type(j) is dict and set(j)==RESULT_KEYS and type(j['schema_version']) is int and j['schema_version']==1 and j['stage']=='lpac-pipe-origin-result'
        and j['scope']==SCOPE and j['profile']==PROFILE and j['config_sha256']==sha(encode(c)) and j['profile_name']=='ruleproxy-lpac-pipe-'+c['run'],'ipc_result')
    require(j['failure'] is None or j['failure'] in ('setup','origin','pair','accesscheck','protocol','cleanup'),'ipc_failure');base.validate_failure_detail(j['failure_detail'])
    launcher.validate_child_environment(j['child_environment']);require(all(j[k] is False for k in FALSE_CLAIMS),'ipc_fixed_false')
    bools={'pipe_allocation_unknown','creation_unknown','observer_attempted','selected_ipc_observed','relay_connect_observed','origin_accepted_observed','origin_request_observed','origin_response_observed','mechanism_verified','natural_exits','workload_stop',*CLEAN_KEYS}
    require(all(type(j[k]) is bool for k in bools),'ipc_bool_facts')
    state=j['profile_state'];require(type(state) is dict and set(state)=={'attempted','returned','created','sid_pointer_returned'} and all(type(v) is bool for v in state.values())
        and (not state['created'] or state['attempted'] and state['returned']) and (j['profile_sid'] is None or base.ac.ac_profile_sid(j['profile_sid'])),'ipc_profile_ownership')
    pair=j['pair']
    if pair is not None:require(type(pair) is dict and set(pair)=={'start','end','frequency'} and pair['frequency']==c['frequency'] and base.ac.integer(pair['start'],c['start_qpc'],work_cutoff(c))
        and pair['end']==pair['start']+10*c['frequency'] and pair['end']<=work_cutoff(c),'ipc_pair_clock')
    require(type(j['intents']) is list and len(j['intents'])<=32,'ipc_intent_list');actions=[];ticks=[]
    for i,r in enumerate(j['intents']):
        require(type(r) is dict and set(r)=={'name','text','sha256'} and r['name'].startswith('%02d-'%i) and '/' not in r['name'] and '\\' not in r['name'],'ipc_intent_name')
        v=record_value({k:r[k] for k in ('text','sha256')},root=root,path='journal/'+r['name'],limit=4096)
        require(set(v)=={'schema_version','scope','run','config_sha256','frequency','deadline_qpc','qpc','action','extra'} and v['schema_version']==1 and type(v['schema_version']) is int
            and v['scope']==SCOPE and v['run']==c['run'] and v['config_sha256']==sha(encode(c)) and v['frequency']==c['frequency'] and v['deadline_qpc']==c['deadline_qpc']
            and base.ac.integer(v['qpc'],c['start_qpc'],c['root_deadline_qpc']) and type(v['extra']) is dict,'ipc_intent_binding')
        require(r['name']=='%02d-%s.json'%(i,v['action']),'ipc_intent_exact_name');actions.append(v);ticks.append(v['qpc'])
    require(ticks==sorted(ticks),'ipc_intent_order')
    require(type(j['tasks']) is list and type(j['cleanup_tasks']) is list and len(j['tasks'])<=6 and len(j['cleanup_tasks'])<=1,'ipc_task_bounds')
    rows={}
    for r in (*j['tasks'],*j['cleanup_tasks']):
        require(type(r) is dict and set(r)==TASK_KEYS and r['name'] not in rows and r['name'] in (*ROLES,*('grant-'+g[0] for g in GRANTS),'remove'),'ipc_task_schema');rows[r['name']]=r
        require(all(type(r[k]) is bool for k in ('attempted','assigned','exited','resumed','admitted','lpac_expected','process_returned')) and r['lpac'] is None and r['go_qpc']==[],'ipc_task_flags')
        require(r['exit_code'] is None or base.ac.integer(r['exit_code'],0,0xffffffff),'ipc_exit_code')
        require(not r['resumed'] or r['admitted'] and r['process_returned'] and r['assigned'],'ipc_task_resume_gate')
        require(not r['exited'] or r['process_returned'] and r['exit_code'] is not None,'ipc_task_exit')
        require((r['pid'] is None or base.ac.integer(r['pid'],1,0xffffffff)) and (r['created'] is None or base.ac.integer(r['created'],1,0x7fffffffffffffff)),'ipc_task_generation')
        o=r['create_observation'];require(type(o) is dict and set(o)=={'status','winerror','process_information','returned_qpc','work_cutoff','exception_detail'} and o['status'] in ('not_entered','exception','returned_false','returned_true')
            and o['process_information'] in ('not_observed','all_zero','nonzero') and (o['winerror'] is None or base.ac.integer(o['winerror'],0,0xffffffff))
            and base.ac.integer(o['work_cutoff'],c['start_qpc'],c['deadline_qpc']) and (o['returned_qpc'] is None or base.ac.integer(o['returned_qpc'],c['start_qpc'],c['root_deadline_qpc'])),'ipc_create_observation')
        base.validate_failure_detail(o['exception_detail'])
        require(not r['admitted'] or r['assigned'] and r['process_returned'] and r['attempted'] and r['identity'] is not None and r['capabilities']==[]
            and r['created'] is not None and base.ac.integer(r['admission_qpc'],c['start_qpc'],o['work_cutoff']-1),'ipc_admission_clock')
        if r['role'] in ROLES:
            role=r['role'];require(r['name']==role and r['lpac_expected']==(role=='lpac-pipe-front'),'ipc_role')
            require(o['work_cutoff']==(work_cutoff(c) if role=='ordinary-origin-fixture' else pair['end']),'ipc_role_cutoff')
            require(r['exit_observed_qpc'] is None or r['exited'] and base.ac.integer(r['exit_observed_qpc'],c['start_qpc'],c['root_deadline_qpc']),'ipc_exit_observation')
            if r['expected_primary'] is not None:
                p=r['expected_primary'];zero.identity_shape(p)
                require(p['token_type']==1 and p['impersonation_level'] is None and p['capabilities']==[] and p['sid']==parent['sid'] and p['session_id']==parent['session_id']
                    and p['elevated'] is p['ui_access'] is False and p['appcontainer']==(role=='lpac-pipe-front') and p['appcontainer_sid']==(j['profile_sid'] if role=='lpac-pipe-front' else None),'ipc_primary_role')
                if role=='lpac-pipe-front':zero.identity(p,primary=True)
                else:require(p['integrity_rid']==parent['integrity_rid'],'ipc_ordinary_il')
            require(type(r['held_checks']) is list and len(r['held_checks'])<=12,'ipc_held_snapshots')
            for h in r['held_checks']:
                require(type(h) is dict and set(h)=={'qpc','pid','created','image_sha256','primary','inner_job','outer_job'} and h['pid']==r['pid'] and h['created']==r['created']
                    and h['image_sha256']==r['image_sha256'] and h['primary']==r['expected_primary'] and h['inner_job'] is h['outer_job'] is True
                    and base.ac.integer(h['qpc'],c['start_qpc'],(pair['end'] if pair and role!='ordinary-origin-fixture' else work_cutoff(c))-1),'ipc_held_snapshot')
            if r['admitted']:
                require(r['expected_primary'] is not None and r['held_checks'] and r['identity'] is not None,'ipc_admitted_external_identity')
                require(base.ac.integer(o['returned_qpc'],c['start_qpc'] if role=='ordinary-origin-fixture' else pair['start'],r['admission_qpc'])
                    and r['held_checks'][0]['qpc']>=o['returned_qpc'] and r['held_checks'][0]['qpc']<=r['admission_qpc']
                    and [h['qpc'] for h in r['held_checks']]==sorted(h['qpc'] for h in r['held_checks']),'ipc_admission_return_causality')
                require(all(r['identity'][k]==r['expected_primary'][k] for k in ('sid','session_id','token_type','appcontainer','appcontainer_sid','integrity_rid','elevated','ui_access'))
                    and r['identity']['capability_count']==0,'ipc_external_identity_consistency')
            require(type(r['command']) is list and all(type(a) is str for a in r['command']),'ipc_command_shape')
            command_root=Path(root) if root is not None else Path(r['command'][0]).parent.parent
            require(r['command']==expected_argv(role,j,c,command_root,parent) and r['image_sha256']==c['actor_sha256' if role=='lpac-pipe-front' else 'origin_actor_sha256'],'ipc_closed_argv')
            receipt=r['receipt']
            if receipt is not None:
                require(set(receipt)=={'name','text','sha256'} and receipt['name']==role+'.json','ipc_create_receipt_name')
                v=record_value({k:receipt[k] for k in ('text','sha256')},root=root,path='returns/'+receipt['name'])
                require(set(v)=={'schema_version','scope','config_sha256','role','observation','raw_return','raw_error','pi'} and v['schema_version']==1 and type(v['schema_version']) is int
                    and v['scope']==SCOPE and v['config_sha256']==sha(encode(c)) and v['role']==role and v['observation']==r['create_observation']
                    and type(v['pi']) is list and len(v['pi'])==4 and all(base.ac.integer(x,0,(1<<64)-1 if i<2 else 0xffffffff) for i,x in enumerate(v['pi'])),'ipc_raw_pi_receipt')
                if r['process_returned']:require(v['observation']['status']=='returned_true' and all(v['pi']) and v['pi'][0]!=v['pi'][1] and v['pi'][2]==r['pid'],'ipc_trusted_pi_only_success')
                if role!='ordinary-origin-fixture' and r['attempted']:
                    require(v['raw_return'] is None or base.ac.integer(v['raw_return'],0,0x7fffffff),'ipc_pair_raw_bool')
                    require(v['raw_error'] is None or base.ac.integer(v['raw_error'],0,0xffffffff),'ipc_pair_raw_error')
                    if r['admitted']:require(v['raw_return'] is not None and v['raw_return']!=0 and v['raw_error'] is None,'ipc_admitted_true_api_return')
                    known_success=v['raw_return'] is not None and v['raw_return']!=0 and v['observation']['status']=='returned_true' and all(v['pi']) and v['pi'][0]!=v['pi'][1]
                    known_none=base.known_no_child(r,start=c['start_qpc'])
                    require(not (not known_success and not known_none) or j['creation_unknown'],'ipc_unknown_creation_sticky')
            if r['resumed']:
                entries=[a for a in actions if a['action']=='resume-authorized' and a['extra']=={'role':role}]
                require(len(entries)==1 and r['resume_intent_qpc']==entries[0]['qpc'] and r['resume_qpc']>=r['resume_intent_qpc'],'ipc_resume_physical_intent')
            if r['admitted']:require(receipt is not None,'ipc_admitted_return_receipt')
    require(type(j['pipe_allocations']) is list and len(j['pipe_allocations'])<=2,'ipc_pipe_allocations')
    allocated=[]
    for i,r in enumerate(j['pipe_allocations']):
        keys={'name','receipt','attempted','returned','api_success','error','raw_outputs','unknown','adopted','readback','return_qpc'}
        require(type(r) is dict and set(r)==keys and r['name']==('response','request')[i] and all(type(r[k]) is bool for k in ('attempted','returned','unknown','adopted','readback')),'ipc_pipe_state')
        if r['attempted'] and not r['api_success']:require(r['unknown'] and j['pipe_allocation_unknown'] and not r['adopted'],'ipc_failed_pipe_indeterminate')
        if r['adopted']:
            require(r['api_success'] is True and r['returned'] and type(r['raw_outputs']) is list and len(r['raw_outputs'])==2 and all(base.ac.integer(h,1,(1<<64)-1) for h in r['raw_outputs'])
                and len(set((*allocated,*r['raw_outputs'])))==len(allocated)+2,'ipc_adopted_pipe_pair');allocated+=r['raw_outputs']
            require(r['receipt'] is not None and base.ac.integer(r['return_qpc'],pair['start'],c['root_deadline_qpc']),'ipc_pipe_owned_return_receipt')
        if r['readback']:require(r['adopted'] and base.ac.integer(r['return_qpc'],pair['start'],pair['end']-1),'ipc_pipe_readback_clock')
        if r['receipt'] is not None:
            receipt=r['receipt'];needname='pipe-'+r['name']+'.json';require(receipt['name']==needname,'ipc_pipe_receipt_name')
            v=record_value({k:receipt[k] for k in ('text','sha256')},root=root,path='returns/'+needname)
            require(v==dict(schema_version=1,scope=SCOPE,config_sha256=sha(encode(c)),pipe=r['name'],observation={k:v for k,v in r.items() if k not in ('name','receipt')}),'ipc_pipe_return_binding')
    closes=j['parent_pipe_close_attempts'];require(type(closes) is list and len(closes)<=4 and all(type(r) is dict and set(r)=={'handle','attempted','confirmed'} and r['handle'] in allocated
        and r['attempted'] is True and type(r['confirmed']) is bool for r in closes) and len({r['handle'] for r in closes})==len(closes),'ipc_parent_closes')
    if any(r['resumed'] for r in j['tasks'] if r['role'] in ('lpac-pipe-front','ordinary-pipe-relay')):
        require(len(allocated)==4 and len(closes)==4 and all(r['confirmed'] for r in closes) and all(r['readback'] for r in j['pipe_allocations']) and not j['pipe_allocation_unknown']
            and j['proof'] is not None and j['proof']['qualified'] and j['observer_resources_cleanup_verified'],'ipc_pair_resume_proof_and_closes')
    if len(allocated)==4:
        for role,ends in (('lpac-pipe-front',[allocated[0],allocated[3]]),('ordinary-pipe-relay',[allocated[2],allocated[1]])):
            if role in rows:require(rows[role]['ends']==ends,'ipc_pipe_direction')
    if j['proof'] is not None:
        front=rows['lpac-pipe-front'];zero.validate_proof(j['proof'],expected_primary_identity=front['expected_primary'],expected_role='lpac',expected_pid=front['pid'],expected_creation=front['created'],frequency=c['frequency'],deadline=pair['end'])
        require(j['observer_attempted'] and j['observer_resources_cleanup_verified']==j['proof']['resource_cleanup_verified'],'ipc_proof_resources')
        observe=[a for a in actions if a['action']=='observe-lpac'];require(len(observe)==1,'ipc_single_observer_intent')
        if j['proof']['start_qpc'] is not None:require(front['admission_qpc']<=observe[0]['qpc']<=j['proof']['start_qpc'],'ipc_observer_causality')
        for role in ('lpac-pipe-front','ordinary-pipe-relay'):
            if rows.get(role,{}).get('resumed'):
                close=[a for a in actions if a['action']=='parent-pipe-close'];require(len(close)==1 and j['proof']['end_qpc']<=close[0]['qpc']<=rows[role]['resume_intent_qpc'],'ipc_proof_before_pair_resume')
    require(type(j['reports']) is dict and set(j['reports'])==set(REPORT_PATHS) and type(j['report_status']) is dict and set(j['report_status'])==set(REPORT_PATHS),'ipc_native_slots')
    for key,r in j['reports'].items():
        require(j['report_status'][key] in ('unavailable','valid','invalid') and (r is None)==(j['report_status'][key]=='unavailable'),'ipc_report_availability')
        if r is not None:
            raw=r['text'].encode('ascii');require(len(raw)<=MAX_NATIVE and sha(raw)==r['sha256'],'ipc_native_raw')
            if root is not None:require(local.bounded(launcher.checked_path(Path(root)/REPORT_PATHS[key],inside=root),MAX_NATIVE)==raw,'ipc_native_physical')
            if j['report_status'][key]=='valid':validate_native(key,decode(raw),j,c,parent)
    require(type(j['labels']) is list and len(j['labels'])<=1,'ipc_label_scope')
    for r in j['labels']:require(type(r) is dict and set(r)=={'name','before','attempted','lowered','restored'} and r['name']=='selected-report' and r['before'] is None
        and all(type(r[k]) is bool for k in ('attempted','lowered','restored')) and (not r['lowered'] or r['attempted']) and (not r['restored'] or r['attempted']),'ipc_label_state')
    require(not j['labels_restored'] or all(not r['attempted'] or r['restored'] for r in j['labels']),'ipc_label_restore')
    require(not j['pipe_allocation_known'] or not j['pipe_allocation_unknown'],'ipc_allocation_known')
    require(not j['profile_deleted'] or all(j[k] for k in ('workload_cleanup','workload_job_empty','parent_pipe_handles_closed','pipe_allocation_known','observer_resources_cleanup_verified','labels_restored','acl_removed','cleanup_tools'))
        and not j['creation_unknown'],'ipc_profile_delete_gate')
    if state['created'] and j['cleanup_tools'] and j['acl_removed']:
        require(len(j['cleanup_tasks'])==1 and j['cleanup_tasks'][0]['name']=='remove' and all(j['cleanup_tasks'][0][k] for k in ('attempted','process_returned','assigned','admitted','resumed','exited'))
            and j['cleanup_tasks'][0]['exit_code']==0,'ipc_cleanup_tool_ledger')
    copy=dict(j);harvest(copy,c,parent)
    require(all(not copy[k] or j[k] for k in ('selected_ipc_observed','relay_connect_observed','origin_accepted_observed','origin_request_observed','origin_response_observed')),'ipc_sticky_facts')
    require(not j['mechanism_verified'] or positive(j,c,parent),'ipc_mechanism_recomputed')
    if j['failure'] is None:require(j['mechanism_verified'] and all(j[k] for k in CLEAN_KEYS) and not j['creation_unknown'],'ipc_complete_result')
    return j
def project(j,c,*,parent,root=None):
    validate_result(j,c,parent=parent,root=root)
    complete=j['failure'] is None and j['mechanism_verified'] and all(j[k] for k in CLEAN_KEYS) and not j['creation_unknown']
    return dict(schema_version=1,stage='lpac-pipe-origin-observation',scope=SCOPE,profile=PROFILE,mechanism_verified=complete,
        selected_ipc_observed=j['selected_ipc_observed'],semantic_lpac_verified=j['proof'] is not None and j['proof']['qualified'],
        network_tested=j['relay_connect_observed'] or j['origin_accepted_observed'],network_scope='ordinary-relay-to-owned-origin-only',
        relay_connect_observed=j['relay_connect_observed'],origin_accepted_observed=j['origin_accepted_observed'],origin_request_observed=j['origin_request_observed'],origin_response_observed=j['origin_response_observed'],
        native_report_status=dict(j['report_status']),cleanup_known=all(j[k] for k in CLEAN_KEYS) and not j['creation_unknown'],failure=j['failure'],
        http_boundary='generated-lpac-request-and-sink-fixed-frame-mapping-ordinary-relay-real-owned-origin',**{k:j[k] for k in CLEAN_KEYS},**dict.fromkeys(FALSE_CLAIMS,False))
def execute(root,c,parent,api,budget):return Owner(root,c,parent,api,budget).execute()
