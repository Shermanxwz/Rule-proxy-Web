"""One bounded inherited binary stream from a genuine zero-cap LPAC.

The previous fixed-frame mapping remains an immutable dependency for its
qualified resource and held-token primitives. This owner has a separate native
protocol, independently pinned challenges and file-only sink validators.
"""
from __future__ import annotations
import ctypes as C
import importlib.util
from pathlib import Path
import subprocess
ROOT=Path(__file__).resolve().parents[1]
def load(name,file):
    s=importlib.util.spec_from_file_location(name,Path(__file__).with_name(file));m=importlib.util.module_from_spec(s);s.loader.exec_module(m);return m
legacy=load('lpac_stream_resource_primitives','windows_identity_lpac_pipe_origin.py')
zero,base,cell,access=legacy.zero,legacy.base,legacy.cell,legacy.access
launcher,helpers,live,local=legacy.launcher,legacy.helpers,legacy.live,legacy.local
require,sha,encode,decode=legacy.require,legacy.sha,legacy.encode,legacy.decode
SCOPE='one-local-semantic-lpac-inherited-stream-origin-v1'
PROFILE='zero-cap-lpac-bounded-byte-stream-mechanism-v1'
MODULE='.github/windows_identity_lpac_stream_origin.py';LOCAL_MODULE='.github/windows_identity_lpac_stream_origin_local.py'
ACTOR='windows_identity_lpac_stream_front_actor.exe';MANIFEST='identity-lpac-stream-front-manifest.json'
NETWORK_ACTOR='windows_identity_lpac_stream_network_actor.exe';NETWORK_MANIFEST='identity-lpac-stream-network-manifest.json'
ACTUAL_READY=True
NONCES=('run','case');ROLES=legacy.ROLES
NATIVE_SOURCES={
 'actorSourceSha256':'.github/native/windows_identity_lpac_stream_front_actor.cpp',
 'streamContractSha256':'.github/native/windows_identity_lpac_stream_contract.hpp',
 'identitySourceSha256':'.github/native/windows_identity_actor.cpp'}
NETWORK_SOURCES=NATIVE_SOURCES|{'actorSourceSha256':'.github/native/windows_identity_lpac_stream_network_actor.cpp'}
SOURCES=tuple(dict.fromkeys((*legacy.SOURCES,*NATIVE_SOURCES.values(),*NETWORK_SOURCES.values(),MODULE,LOCAL_MODULE)))
MAX_REPORT=1024*1024;MAX_NATIVE=32768
FALSE_CLAIMS=tuple(dict.fromkeys((*legacy.FALSE_CLAIMS,'transparent_transport','sustained_or_concurrent_streams','core_mihomo_integration','payload_seed_supplied','global_configuration_unchanged_proven')))
ACKS=('fresh_profile_owned_acl_acknowledged','zero_capabilities_no_fallback_acknowledged','trusted_actor_mechanism_only_acknowledged',
 'cooperative_bounded_stream_acknowledged','independent_unpredictable_binary_challenges_acknowledged','inherited_pipe_authority_acknowledged','residue_review_acknowledged')
CLEAN_KEYS=legacy.CLEAN_KEYS
GRANTS=(('root','','RX'),('inputs','inputs','(OI)(CI)(RX)'),('selected-inputs','selected-inputs','(OI)(CI)(RX)'),('selected-report','selected-report','(OI)(CI)(M)'))
REPORT_PATHS=legacy.REPORT_PATHS
CHALLENGE_PATHS={'request':'selected-inputs/request.bin','response':'ordinary-inputs/response.bin'}
SINK_PATHS={'selected_response':'selected-report/response.raw','relay_request':'relay-report/request-sent.raw',
 'relay_response':'relay-report/response-received.raw','origin_request':'origin-report/request.raw','origin_response':'origin-report/response-sent.raw'}
info_values,handle_list,task_projection=legacy.info_values,legacy.handle_list,legacy.task_projection
actor_rows=legacy.actor_rows
work_cutoff,owned_tree=legacy.work_cutoff,legacy.owned_tree

def record_value(record,*,root=None,path=None,limit=MAX_NATIVE):return legacy.record_value(record,root=root,path=path,limit=limit)
def api_version():return 1
def stage_name(run):return 'local-lpac-stream-origin-'+run

def challenge_meta(value):
    require(type(value) is dict and set(value)=={'request','response'},'stream_challenge_schema')
    for key,size in (('request',8193),('response',12289)):
        v=value[key];require(type(v) is dict and set(v)=={'bytes','sha256'} and type(v['bytes']) is int and v['bytes']==size and base.ac.digest(v['sha256']),'stream_challenge_pin')
    require(value['request']['sha256']!=value['response']['sha256'],'stream_independent_challenges');return value

def challenge_inputs(request,response,expected=None):
    rows={}
    for key,path,size in (('request',request,8193),('response',response,12289)):
        path=launcher.checked_path(path);raw=local.bounded(path,65536)
        require(len(raw)==size and set(raw)==set(range(256)) and b'RPS1' in raw,'stream_binary_challenge')
        rows[key]=dict(bytes=len(raw),sha256=sha(raw))
    challenge_meta(rows)
    if expected is not None:require(rows==challenge_meta(expected),'stream_challenge_changed')
    return rows

def request_before_pair_resume(path,expected):
    # The ordinary origin already holds response.bin with share=0 after READY.
    # Its input was pinned before its resume and is independently rehashed after
    # held exit. Only the not-yet-resumed selected input can be reopened here.
    expected=challenge_meta(expected)['request'];raw=local.bounded(launcher.checked_path(path),65536)
    require(len(raw)==8193 and set(raw)==set(range(256)) and b'RPS1' in raw and dict(bytes=len(raw),sha256=sha(raw))==expected,'stream_selected_input_changed')
    return expected

def config_validate(c,*,source_names=SOURCES):
    keys={'schema_version','scope','profile',*NONCES,'frequency','start_qpc','root_deadline_qpc','deadline_qpc','guard_job_name','source_hashes','source_sha256','device_sha256',
      'actor_sha256','manifest_sha256','network_actor_sha256','network_manifest_sha256','recovery_plan_sha256','challenges'}
    require(type(c) is dict and set(c)==keys and type(c['schema_version']) is int and c['schema_version']==1 and c['scope']==SCOPE and c['profile']==PROFILE,'stream_config')
    require(all(base.ac.nonce(c[k]) for k in NONCES) and c['run']!=c['case'],'stream_nonces');live.clock_record(c['start_qpc'],c['frequency'],c['root_deadline_qpc'])
    require(c['root_deadline_qpc']==c['start_qpc']+120*c['frequency'] and c['deadline_qpc']==c['root_deadline_qpc']-5*c['frequency'] and c['guard_job_name']==r'Local\RuleProxy.LocalGuard.'+c['run'],'stream_epoch')
    require(type(c['source_hashes']) is dict and set(c['source_hashes'])==set(source_names) and all(base.ac.digest(v) for v in c['source_hashes'].values()) and sha(encode(c['source_hashes']))==c['source_sha256'],'stream_sources')
    require(all(base.ac.digest(c[k]) for k in keys if k.endswith('_sha256')),'stream_digest');challenge_meta(c['challenges']);return c

def validate_plan(p,*,device,source,actor,manifest,network_actor,network_manifest,challenges):
    keys={'schema_version','scope','profile',*NONCES,'device_sha256','source_sha256','actor_sha256','manifest_sha256','network_actor_sha256','network_manifest_sha256','recovery_reference','challenges',*ACKS}
    require(type(p) is dict and set(p)==keys and type(p['schema_version']) is int and p['schema_version']==1 and p['scope']==SCOPE and p['profile']==PROFILE,'stream_plan')
    require(all(p[k] is True for k in ACKS) and all(base.ac.nonce(p[k]) for k in NONCES) and p['run']!=p['case'],'stream_plan_ack')
    require([p[k] for k in ('device_sha256','source_sha256','actor_sha256','manifest_sha256','network_actor_sha256','network_manifest_sha256')]==[device,source,actor,manifest,network_actor,network_manifest],'stream_plan_binding')
    require(p['challenges']==challenge_meta(challenges),'stream_plan_challenges')
    require(type(p['recovery_reference']) is str and 1<=len(p['recovery_reference'])<=512 and not any(x in p['recovery_reference'] for x in '\r\n\0'),'stream_recovery_reference');return p

def verify_actor(actor,manifest,ah,mh,*,root,network=False):
    name,man,sources=(NETWORK_ACTOR,NETWORK_MANIFEST,NETWORK_SOURCES) if network else (ACTOR,MANIFEST,NATIVE_SOURCES)
    actor=launcher.checked_path(actor);manifest=launcher.checked_path(manifest);require(actor.name==name and manifest.name==man and actor.parent==manifest.parent,'stream_artifact_name')
    raw=local.bounded(manifest,8192);v=decode(raw.removeprefix(b'\xef\xbb\xbf'));keys={'schemaVersion','compileOnly','runtimeAcceptance','interfaceVersion','executableSha256',*sources}
    require(type(v) is dict and set(v)==keys and type(v['schemaVersion']) is int and v['schemaVersion']==1 and type(v['interfaceVersion']) is int and v['interfaceVersion']==1 and v['compileOnly'] is True and v['runtimeAcceptance'] is False and v['executableSha256']==ah and sha(raw)==mh,'stream_manifest')
    require(base.ac.digest(ah) and base.ac.digest(mh) and sha(local.bounded(actor,8*1024*1024))==ah,'stream_artifact_hash')
    for k,file in sources.items():require(v[k]==sha(local.bounded(launcher.checked_path(Path(root)/file,inside=root),256*1024)),'stream_native_pin')
    return actor

def verify_artifacts(c,root):
    verify_actor(root/'inputs'/ACTOR,root/'inputs'/MANIFEST,c['actor_sha256'],c['manifest_sha256'],root=root)
    verify_actor(root/'inputs'/NETWORK_ACTOR,root/'inputs'/NETWORK_MANIFEST,c['network_actor_sha256'],c['network_manifest_sha256'],root=root,network=True)
    challenge_inputs(root/CHALLENGE_PATHS['request'],root/CHALLENGE_PATHS['response'],c['challenges'])

def expected_acl(root,path):
    if path==root:return [(0,0x1200a9)]
    for name in ('inputs','selected-inputs'):
        if path==root/name:return [(3,0x1200a9)]
        if root/name in path.parents:return [(16,0x1200a9)]
    if path==root/'selected-report':return [(3,0x1301bf)]
    if root/'selected-report' in path.parents:return [(16,0x1301bf)]
    return []

class API(legacy.API):
    # allocate_pipe/descriptor operations retain the qualified immutable policy.
    def pair_spawn(self,info,argv,cwd,environment,job,owners,state,*,ends,pipe_pending,profile_pointer,budget,end,on_return):
        ends=handle_list(ends,pipe_pending);selected=profile_pointer is not None
        require(Path(argv[0]).name==(ACTOR if selected else NETWORK_ACTOR) and argv[1]==('stream-front' if selected else 'stream-relay') and job,'ipc_constructor_role')
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


class Owner(legacy.Owner):
    """A separate coordinator using immutable held/ordinary resource adapters."""
    def __init__(self,root,c,parent,api,budget):
        super().__init__(root,c,parent,api,budget)
        self.j.update(stage='lpac-stream-origin-result',scope=SCOPE,profile=PROFILE,profile_name='ruleproxy-lpac-stream-'+c['run'],physical_sinks={},challenges=c['challenges'])
        self.j.update(dict.fromkeys(FALSE_CLAIMS,False))
    def journal(self,label,**extra):
        allowed={'profile-create','acl-grant','label-lower','label-restore','acl-remove','profile-delete','workload-stop','pair-epoch','observe-lpac',
            'allocate-response','allocate-request','parent-pipe-close','resume-authorized','spawn-grant-root','spawn-grant-inputs','spawn-grant-selected-inputs','spawn-grant-selected-report','spawn-remove',
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

    def spawn(self,role,argv,end,ends=()):
        selected=role=='lpac-pipe-front';image=launcher.checked_path(argv[0],inside=self.root);expected=self.c['actor_sha256' if selected else 'network_actor_sha256']
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

    # Held generation/token/image/dual Jobs, before-resume proof gate, known
    # post-wait deadline sampling and exact label restoration are unchanged.
    held=legacy.Owner.held
    resume=legacy.Owner.resume
    wait=legacy.Owner.wait
    restore_labels=legacy.Owner.restore_labels
    execute=legacy.Owner.execute

    def native(self,key):
        path=self.root/REPORT_PATHS[key];raw=local.bounded(path,MAX_NATIVE)
        self.j['reports'][key]=dict(text=raw.decode('ascii'),sha256=sha(raw));self.j['report_status'][key]='invalid'
        v=decode(raw);self.j['tasks']=[task_projection(r) for r in self.children]
        validate_native(key,v,self.j,self.c,self.parent);self.j['report_status'][key]='valid';return v
    def origin_ready(self,row):
        path=self.root/REPORT_PATHS['ready'];end=work_cutoff(self.c)
        while not path.exists():
            self.budget.require_ms(end);require(not self.api.wait(row['info'].hProcess,0),'stream_origin_exited_before_ready');self.api.sleep_ms(self.budget.require_ms(end,10))
        while True:
            try:raw=local.bounded(path,MAX_NATIVE);break
            except OSError as e:
                if getattr(e,'winerror',None)!=32:raise
                self.api.sleep_ms(self.budget.require_ms(end,10))
        v=decode(raw);self.port=self.j['port']=v.get('port');self.j['tasks']=[task_projection(r) for r in self.children]
        validate_native('ready',v,self.j,self.c,self.parent);self.j['reports']['ready']=dict(text=raw.decode('ascii'),sha256=sha(raw));self.j['report_status']['ready']='valid';self.held(row,end)
    def sink_evidence(self):
        # Only called after held workload cleanup/exit. The normal path also
        # calls this before qualification, after all three natural held exits.
        self.j['physical_sinks']={}
        for key,name in SINK_PATHS.items():
            path=self.root/name
            if path.exists():
                raw=local.bounded(launcher.checked_path(path,inside=self.root),65536)
                self.j['physical_sinks'][key]=dict(path=name,bytes=len(raw),sha256=sha(raw))
    def run(self):
        self.setup();c=self.c;self.phase='origin';self.j['origin_start']=self.budget.read()
        challenge_inputs(self.root/CHALLENGE_PATHS['request'],self.root/CHALLENGE_PATHS['response'],c['challenges'])
        n=c['challenges'];argv=[str(self.root/'inputs'/NETWORK_ACTOR),'stream-origin',c['run'],c['case'],str(self.root/REPORT_PATHS['origin']),str(self.root/REPORT_PATHS['ready']),
            str(c['start_qpc']),str(c['frequency']),str(work_cutoff(c)),self.parent['sid'],str(n['request']['bytes']),str(n['response']['bytes'])]
        fixture=self.spawn('ordinary-origin-fixture',argv,work_cutoff(c));self.resume(fixture);self.origin_ready(fixture)
        self.phase='pair';start=self.budget.read();end=start+10*c['frequency'];require(end<=work_cutoff(c),'stream_pair_reserve');self.j['pair']=dict(start=start,end=end,frequency=c['frequency'])
        self.journal('pair-epoch',start=start,end=end);pairs=[]
        for label in ('response','request'):
            state=dict(name=label,receipt=None);self.j['pipe_allocations'].append(state);self.journal('allocate-'+label)
            try:pairs.append(self.api.allocate_pipe(self.pipes,self.owners.pending,self.parent['sid'],state,self.budget,end))
            finally:
                if state.get('unknown') or state.get('attempted') and not state.get('api_success'):self.j['pipe_allocation_unknown']=True
                raw=encode(dict(schema_version=1,scope=SCOPE,config_sha256=sha(encode(c)),pipe=label,observation={k:v for k,v in state.items() if k not in ('name','receipt')}))
                try:
                    path=self.root/'returns'/('pipe-'+label+'.json');base.durable_private(path,raw);state['receipt']=dict(name=path.name,text=raw.decode('ascii'),sha256=sha(raw))
                except BaseException:self.api.controls_uncertain=True;raise
        (front_read,relay_write),(relay_read,front_write)=pairs
        def args(selected,ends):
            return [str(self.root/'inputs'/(ACTOR if selected else NETWORK_ACTOR)),'stream-front' if selected else 'stream-relay',c['run'],c['case'],
                str(self.root/REPORT_PATHS['selected' if selected else 'relay']),*(str(h) for h in ends),str(start),str(c['frequency']),str(end),self.parent['sid'],
                self.profile['sid'] if selected else 'none',str(n['request']['bytes']),str(n['response']['bytes']),str(self.port)]
        front=self.spawn('lpac-pipe-front',args(True,(front_read,front_write)),end,(front_read,front_write))
        relay=self.spawn('ordinary-pipe-relay',args(False,(relay_read,relay_write)),end,(relay_read,relay_write))
        for row in (front,relay,fixture):self.held(row,end)
        self.phase='accesscheck';self.journal('observe-lpac');self.j['observer_attempted']=True;self.j['observer_resources_cleanup_verified']=False
        self.j['proof']=zero.observe_held(self.api.access_api(),front['info'].hProcess,front['expected_primary'],expected_pid=front['pid'],expected_creation=front['created'],expected_role='lpac',frequency=c['frequency'],deadline=end)
        self.j['observer_resources_cleanup_verified']=self.j['proof']['resource_cleanup_verified']
        if not self.j['observer_resources_cleanup_verified']:self.api.controls_uncertain=True
        require(self.j['proof']['qualified'],'stream_lpac_proof')
        for row in (front,relay,fixture):self.held(row,end)
        request_before_pair_resume(self.root/CHALLENGE_PATHS['request'],c['challenges'])
        self.journal('parent-pipe-close');uncertain=False
        for h in (front_read,relay_write,relay_read,front_write):
            entry=dict(handle=h,attempted=True,confirmed=False);self.j['parent_pipe_close_attempts'].append(entry)
            try:self.pipes.close(h);entry['confirmed']=True
            except BaseException:uncertain=True
        self.j['parent_pipe_handles_closed']=not uncertain and self.pipes.confirmed_closed
        require(self.j['parent_pipe_handles_closed'],'stream_parent_close');self.phase='protocol';self.resume(relay);self.resume(front)
        for row in (front,relay,fixture):self.wait(row,end)
        self.j['natural_exits']=True
        for key in ('selected','relay','origin'):self.native(key);self.budget.require_ms(end)
        self.sink_evidence();self.j['completion_qpc']=self.budget.read();self.budget.require_ms(end)
        self.j['mechanism_verified']=positive(self.j,c,self.parent);require(self.j['mechanism_verified'],'stream_positive')
    def cleanup(self):
        clean=False
        try:
            if any(r['info'].hProcess and not r['exited'] for r in self.children):self.journal('workload-stop')
            rows=[r for r in self.children if not base.known_no_child(r,start=self.c['start_qpc'])]
            clean,empty,stop=base.ac._cleanup(self.api,live.CleanupView(self.budget,self.budget.cutoff(12)),self.job,rows,legacy.origin.CombinedLedgers(self.owners,self.pipes))
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
        self.j['tasks']=[task_projection(r) for r in self.children]
        try:self.sink_evidence()
        except BaseException:pass
        harvest(self.j,self.c,self.parent)
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


# This validator deliberately consumes the new stream ABI, not a fabricated
# legacy RPB1 record. Integer/shape gates do not imply transport success.
NATIVE_FAILURES=(None,'configuration','identity','qpc','deadline','pipe_type','inheritance','pipe_read','pipe_write','pipe_eof','file_open','file_read','file_write','file_flush','file_close','socket_setup','connect','send','receive','shutdown','peer','close','protocol','report')
CODEC_FAILURES=(None,'config','frame','order','bound','credit','eof','peer_reset','external')
STREAM_FLAGS=('opened','local_fin_sent','peer_fin_received','peer_fin_handled','peer_pipe_eof','writer_closed','protocol_complete')
STREAM_COUNTS=('tx_frames','rx_frames','tx_payload_bytes','rx_payload_bytes','local_source_bytes','local_sink_bytes','tx_credit_received','rx_credit_sent','tx_outstanding','rx_outstanding','tx_window_available','local_buffered','peer_buffered','partial_frame_bytes','pending_frame_bytes')
NETWORK_FLAGS=('wsa_startup','wsa_cleanup','socket_created','connect_attempted','connect_completed','peer_loopback','send_shutdown','receive_eof','listener_created','exclusive','bind_loopback','accepted')
CLOSE_VALUES=('not_attempted','confirmed','uncertain')

def expected_argv(role,j,c,root,parent):
    p=Path(root);n=c['challenges']
    if role=='ordinary-origin-fixture':return [str(p/'inputs'/NETWORK_ACTOR),'stream-origin',c['run'],c['case'],str(p/REPORT_PATHS['origin']),str(p/REPORT_PATHS['ready']),str(c['start_qpc']),str(c['frequency']),str(work_cutoff(c)),parent['sid'],str(n['request']['bytes']),str(n['response']['bytes'])]
    pair=j['pair'];row=actor_rows(j)[role];selected=role=='lpac-pipe-front'
    return [str(p/'inputs'/(ACTOR if selected else NETWORK_ACTOR)),'stream-front' if selected else 'stream-relay',c['run'],c['case'],str(p/REPORT_PATHS['selected' if selected else 'relay']),*(str(h) for h in row['ends']),str(pair['start']),str(c['frequency']),str(pair['end']),parent['sid'],j['profile_sid'] if selected else 'none',str(n['request']['bytes']),str(n['response']['bytes']),str(j['port'])]

def native_identity(v,row,c,selected):
    keys={'schemaVersion','mode','nonce','pid','tokenUserSid','tokenIsAppContainer','tokenAppContainerSid','tokenElevated','isProcessInJob','tokenCapabilities','queriesSucceeded','errors'}
    require(type(v) is dict and set(v)==keys and type(v['schemaVersion']) is int and v['schemaVersion']==1 and v['mode']=='actor' and v['nonce']==c['run'] and type(v['pid']) is int and v['pid']==row['pid'],'stream_native_identity')
    require(v['tokenUserSid']==row['identity']['sid'] and v['tokenIsAppContainer'] is selected and v['tokenAppContainerSid']==row['identity']['appcontainer_sid'] and v['tokenElevated'] is False and v['isProcessInJob'] is True and v['tokenCapabilities']==[] and v['queriesSucceeded'] is True and v['errors']==[],'stream_native_vs_held')

def file_record(v,*,maximum):
    require(type(v) is dict and set(v)=={'attempted','opened','bytes','flushed','close'} and all(type(v[k]) is bool for k in ('attempted','opened','flushed')) and base.ac.integer(v['bytes'],0,maximum) and v['close'] in CLOSE_VALUES,'stream_file_record')
    require(not v['opened'] or v['attempted'],'stream_file_open_order');require(not v['flushed'] or v['opened'],'stream_file_flush_order');require(not v['bytes'] or v['opened'],'stream_file_bytes_order');return v

def validate_native(key,v,j,c,parent):
    require(key in REPORT_PATHS,'stream_report_slot');rows=actor_rows(j);n=c['challenges']
    if key=='ready':
        row=rows['ordinary-origin-fixture'];keys={'schema_version','stage','run_id','case_id','pid','port','qpc_frequency','start_qpc','deadline_qpc','loopback_ipv4'}
        require(type(v) is dict and set(v)==keys and type(v['schema_version']) is int and v['schema_version']==1 and v['stage']=='lpac-stream-origin-ready' and v['run_id']==c['run'] and v['case_id']==c['case'] and type(v['pid']) is int and v['pid']==row['pid'] and v['qpc_frequency']==c['frequency'] and v['start_qpc']==c['start_qpc'] and v['deadline_qpc']==work_cutoff(c) and v['loopback_ipv4'] is True and base.ac.integer(v['port'],49153,65535) and v['port']==j['port'] and all(base.ac.integer(v[k],1,0x7fffffffffffffff) for k in ('qpc_frequency','start_qpc','deadline_qpc')),'stream_ready');return v
    role={'selected':'lpac-pipe-front','relay':'ordinary-pipe-relay','origin':'ordinary-origin-fixture'}[key];row=rows[role];selected=key=='selected'
    keys={'schema_version','stage','role','run_id','case_id','pid','identity','qpc','limits','files','stream','pipe','network','admitted_qpc','read_handle_inherit_cleared','write_handle_inherit_cleared','failure','win32_error','wsa_error','selected_socket_api_tested','network_tested','proxy_tested','product_acceptance'}
    require(type(v) is dict and set(v)==keys and type(v['schema_version']) is int and v['schema_version']==1 and v['stage']=='lpac-stream-actor' and v['role']=={'selected':'stream-front','relay':'stream-relay','origin':'stream-origin'}[key] and v['run_id']==c['run'] and v['case_id']==c['case'] and type(v['pid']) is int and v['pid']==row['pid'],'stream_native_wrapper')
    require(v['failure'] in NATIVE_FAILURES and all(v[k] is False for k in ('selected_socket_api_tested','proxy_tested','product_acceptance')) and type(v['network_tested']) is bool and all(type(v[k]) is bool for k in ('read_handle_inherit_cleared','write_handle_inherit_cleared')),'stream_native_status')
    for k in ('win32_error','wsa_error'):require(v[k] is None or base.ac.integer(v[k],0,0xffffffff),'stream_native_error')
    native_identity(v['identity'],row,c,selected)
    q=v['qpc'];start,end=(c['start_qpc'],work_cutoff(c)) if key=='origin' else (j['pair']['start'],j['pair']['end'])
    require(type(q) is list and len(q)==4 and all(base.ac.integer(t,0,0x7fffffffffffffff) for t in q) and q[:3]==[c['frequency'],start,end] and (q[3]==0 or start<=q[3]<=c['root_deadline_qpc']+c['frequency']),'stream_native_clock')
    require(row['resume_intent_qpc'] is not None and (q[3]==0 and v['failure'] is not None or q[3]>=row['resume_intent_qpc']),'stream_native_after_resume')
    require(v['admitted_qpc'] is None or base.ac.integer(v['admitted_qpc'],row['resume_intent_qpc'],q[3]),'stream_admitted_clock')
    require(type(v['limits']) is dict and all(type(x) is int for x in v['limits'].values()) and v['limits']==dict(payload_max=1024,window=4096,total_max=65536,frames_max=256,request_bytes=n['request']['bytes'],response_bytes=n['response']['bytes']),'stream_native_limits')
    f=v['files'];require(type(f) is dict and set(f)=={'source','request_sink','response_sink'},'stream_native_file_slots')
    used={'selected':('source','response_sink'),'relay':('request_sink','response_sink'),'origin':('source','request_sink','response_sink')}[key]
    for k,value in f.items():
        if k not in used:require(value is None,'stream_unused_file_slot')
        else:file_record(value,maximum=65536)
    if key=='origin':require(v['stream'] is None and v['pipe'] is None and v['admitted_qpc'] is None and v['read_handle_inherit_cleared'] is v['write_handle_inherit_cleared'] is False,'stream_origin_no_pipes')
    else:
        st=v['stream'];require(type(st) is dict and set(st)=={*STREAM_FLAGS,*STREAM_COUNTS,'failure'} and all(type(st[k]) is bool for k in STREAM_FLAGS) and st['failure'] in CODEC_FAILURES,'stream_state_shape')
        for k in STREAM_COUNTS:
            bound=256 if k in ('tx_frames','rx_frames') else 4096 if k in ('tx_outstanding','rx_outstanding','tx_window_available','local_buffered','peer_buffered') else 1088 if k in ('partial_frame_bytes','pending_frame_bytes') else 65536
            require(base.ac.integer(st[k],0,bound),'stream_state_count')
        pipe=v['pipe'];require(type(pipe) is dict and set(pipe)=={'read_bytes','write_bytes','read_calls','write_calls','peek_calls','eof_observed','reader_close','writer_close','inheritance_cleared'} and type(pipe['eof_observed']) is bool and type(pipe['inheritance_cleared']) is bool and all(pipe[k] in CLOSE_VALUES for k in ('reader_close','writer_close')),'stream_pipe_shape')
        for k in ('read_bytes','write_bytes'):require(base.ac.integer(pipe[k],0,81920),'stream_pipe_bound')
        for k in ('read_calls','write_calls','peek_calls'):require(base.ac.integer(pipe[k],0,0xffffffff),'stream_pipe_calls')
    net=v['network']
    if selected:require(net is None and v['network_tested'] is False and v['wsa_error'] is None,'stream_selected_no_network')
    else:
        require(type(net) is dict and set(net)=={*NETWORK_FLAGS,'port','local_port','peer_port','bytes_sent','bytes_received','socket_close','listener_close'} and all(type(net[k]) is bool for k in NETWORK_FLAGS) and net['port']==j['port'] and all(net[k] in CLOSE_VALUES for k in ('socket_close','listener_close')),'stream_network_shape')
        for k in ('local_port','peer_port'):require(net[k] is None or base.ac.integer(net[k],1,65535),'stream_observed_ports')
        for k in ('bytes_sent','bytes_received'):require(base.ac.integer(net[k],0,65536),'stream_network_bytes')
        require(not net['connect_completed'] or net['connect_attempted'] and net['socket_created'],'stream_connect_order')
        require(not net['accepted'] or net['listener_created'] and net['socket_created'],'stream_accept_order')
        if key=='relay':require(not any(net[k] for k in ('listener_created','exclusive','bind_loopback','accepted')) and net['listener_close']=='not_attempted','stream_relay_not_listener')
        else:require(not net['connect_attempted'] and not net['connect_completed'],'stream_origin_not_client')
        require(v['network_tested']==(net['connect_attempted'] if key=='relay' else net['accepted']),'stream_network_tested_boundary')
    return v

def validated_reports(j,c,parent):
    return {k:validate_native(k,record_value(r),j,c,parent) for k,r in j['reports'].items() if r is not None and j['report_status'][k]=='valid'}

def harvest(j,c,parent):
    for key in ('selected','relay','origin'):
        if j['reports'][key] is None or j['report_status'][key]!='valid':continue
        try:v=validate_native(key,record_value(j['reports'][key]),j,c,parent)
        except (ValueError,KeyError,TypeError):continue
        if key=='selected':j['selected_ipc_observed']|=bool(v['pipe']['read_bytes'] or v['pipe']['write_bytes'])
        elif key=='relay':j['relay_connect_observed']|=v['network']['connect_completed']
        else:
            j['origin_accepted_observed']|=v['network']['accepted'];j['origin_request_observed']|=v['files']['request_sink']['bytes']>0;j['origin_response_observed']|=v['files']['response_sink']['bytes']>0

def validate_sinks(j,c,*,root=None):
    require(j['challenges']==c['challenges'],'stream_challenges_binding');rows=j['physical_sinks']
    require(type(rows) is dict and set(rows)<=set(SINK_PATHS),'stream_sink_slots')
    for key,v in rows.items():
        require(type(v) is dict and set(v)=={'path','bytes','sha256'} and v['path']==SINK_PATHS[key] and base.ac.integer(v['bytes'],0,65536) and base.ac.digest(v['sha256']),'stream_sink_meta')
        if root is not None:
            raw=local.bounded(launcher.checked_path(Path(root)/v['path'],inside=root),65536);require(dict(bytes=len(raw),sha256=sha(raw))=={k:v[k] for k in ('bytes','sha256')},'stream_physical_sink')
    if root is not None:challenge_inputs(Path(root)/CHALLENGE_PATHS['request'],Path(root)/CHALLENGE_PATHS['response'],c['challenges'])
    return rows

def payloads_passed(j,c,parent):
    try:
        rows=validate_sinks(j,c);require(set(rows)==set(SINK_PATHS),'stream_all_sinks')
        for key,v in rows.items():
            expected=c['challenges']['request' if key in ('relay_request','origin_request') else 'response'];require({k:v[k] for k in ('bytes','sha256')}==expected,'stream_end_to_end_bytes')
        r=validated_reports(j,c,parent)
        fields=(('selected','source','request'),('selected','response_sink','response'),('relay','request_sink','request'),('relay','response_sink','response'),('origin','source','response'),('origin','request_sink','request'),('origin','response_sink','response'))
        for role,slot,kind in fields:
            f=r[role]['files'][slot];require(f['attempted'] and f['opened'] and f['close']=='confirmed' and f['bytes']==c['challenges'][kind]['bytes'] and f['flushed']==(slot!='source'),'stream_file_completed')
        return True
    except (ValueError,KeyError,TypeError):return False

def protocol_passed(v,selected,c):
    tx,rx=(c['challenges']['request']['bytes'],c['challenges']['response']['bytes']) if selected else (c['challenges']['response']['bytes'],c['challenges']['request']['bytes'])
    p,st=v['pipe'],v['stream']
    return (v['failure'] is None and v['win32_error'] is None and v['wsa_error'] is None and v['qpc'][3]<v['qpc'][2] and v['admitted_qpc'] is not None and v['read_handle_inherit_cleared'] and v['write_handle_inherit_cleared'] and all(st[k] for k in STREAM_FLAGS) and st['failure'] is None and st['tx_payload_bytes']==st['local_source_bytes']==st['tx_credit_received']==tx and st['rx_payload_bytes']==st['local_sink_bytes']==st['rx_credit_sent']==rx and st['tx_outstanding']==st['rx_outstanding']==st['local_buffered']==st['peer_buffered']==st['partial_frame_bytes']==st['pending_frame_bytes']==0 and st['tx_window_available']==4096 and st['tx_frames']>=3 and st['rx_frames']>=3 and p['inheritance_cleared'] and p['eof_observed'] and p['reader_close']==p['writer_close']=='confirmed')

def positive(j,c,parent):
    try:
        rows=actor_rows(j);reports=validated_reports(j,c,parent);require(set(rows)==set(ROLES) and set(reports)==set(REPORT_PATHS),'stream_positive_reports')
        state=j['profile_state'];require(all(state.values()) and base.ac.ac_profile_sid(j['profile_sid']) and len(j['labels'])==1 and j['labels'][0]['name']=='selected-report' and j['labels'][0]['attempted'] and j['labels'][0]['lowered'],'stream_positive_profile')
        grants={r['name']:r for r in j['tasks'] if r['role'] not in ROLES}
        require(set(grants)=={'grant-'+r[0] for r in GRANTS} and all(r['attempted'] and r['process_returned'] and r['assigned'] and r['admitted'] and r['resumed'] and r['exited'] and r['exit_code']==0 for r in grants.values()),'stream_positive_grants')
        require(all(r['receipt'] is not None and r['create_observation']['status']=='returned_true' for r in rows.values()),'stream_positive_returns')
        require(j['proof'] is not None and j['proof']['qualified'] and j['observer_resources_cleanup_verified'] and j['parent_pipe_handles_closed'] and not j['pipe_allocation_unknown'] and not j['creation_unknown'],'stream_positive_resources')
        require(len(j['pipe_allocations'])==2 and all(r['receipt'] is not None and r['adopted'] and r['readback'] and base.ac.integer(r['return_qpc'],j['pair']['start'],j['pair']['end']-1) for r in j['pipe_allocations']),'stream_positive_pipes')
        front,relay,fixture=(reports[k] for k in ('selected','relay','origin'))
        require(protocol_passed(front,True,c) and protocol_passed(relay,False,c) and payloads_passed(j,c,parent),'stream_positive_bytes_protocol')
        for a,b in (('read_bytes','write_bytes'),('write_bytes','read_bytes')):require(front['pipe'][a]==relay['pipe'][b],'stream_pipe_cross_bytes')
        for a,b in (('tx_frames','rx_frames'),('rx_frames','tx_frames'),('tx_payload_bytes','rx_payload_bytes'),('rx_payload_bytes','tx_payload_bytes')):require(front['stream'][a]==relay['stream'][b],'stream_peer_cross_counts')
        for v in (front,relay):
            require(v['pipe']['write_bytes']==v['stream']['tx_frames']*64+v['stream']['tx_payload_bytes'] and v['pipe']['read_bytes']==v['stream']['rx_frames']*64+v['stream']['rx_payload_bytes'],'stream_wire_bytes')
        rn,on=relay['network'],fixture['network'];req,res=(c['challenges'][k]['bytes'] for k in ('request','response'))
        require(all(rn[k] for k in ('wsa_startup','wsa_cleanup','socket_created','connect_attempted','connect_completed','peer_loopback','send_shutdown','receive_eof')) and rn['socket_close']=='confirmed' and rn['listener_close']=='not_attempted' and rn['bytes_sent']==req and rn['bytes_received']==res and rn['peer_port']==j['port'],'stream_relay_socket')
        require(fixture['failure'] is None and fixture['win32_error'] is fixture['wsa_error'] is None and fixture['qpc'][3]<fixture['qpc'][2] and all(on[k] for k in ('wsa_startup','wsa_cleanup','listener_created','exclusive','bind_loopback','accepted','peer_loopback','send_shutdown','receive_eof')) and on['socket_close']==on['listener_close']=='confirmed' and on['bytes_sent']==res and on['bytes_received']==req,'stream_origin_socket')
        require(rn['local_port']==on['peer_port'] and rn['peer_port']==on['local_port']==on['port']==j['port'],'stream_native_tuple')
        require(j['natural_exits'] and all(r['admitted'] and r['resumed'] and r['exited'] and r['exit_code']==0 for r in rows.values()) and base.ac.integer(j['completion_qpc'],j['pair']['start'],j['pair']['end']-1),'stream_positive_epoch')
        final_ticks=[v['qpc'][3] for v in (front,relay,fixture)]+[j['proof']['end_qpc']]
        for role,r in rows.items():
            end=work_cutoff(c) if role=='ordinary-origin-fixture' else j['pair']['end'];v=reports[{'lpac-pipe-front':'selected','ordinary-pipe-relay':'relay','ordinary-origin-fixture':'origin'}[role]]
            require(base.ac.integer(r['resume_qpc'],r['resume_intent_qpc'],end-1) and base.ac.integer(r['exit_observed_qpc'],r['resume_intent_qpc'],j['pair']['end']-1) and r['exit_observed_qpc']>=max(v['qpc'][3],r['resume_qpc']),'stream_held_exit_causal')
            final_ticks.extend((r['resume_qpc'],r['exit_observed_qpc']))
        require(j['completion_qpc']>=max(final_ticks),'stream_completion_causal');return True
    except (ValueError,KeyError,TypeError):return False

TASK_KEYS=legacy.TASK_KEYS
RESULT_KEYS=legacy.RESULT_KEYS|{'physical_sinks','challenges',*FALSE_CLAIMS}
def validate_result(j,c,*,parent,root=None):
    config_validate(c);require(launcher.token_is_ordinary(parent),'ipc_parent')
    require(type(j) is dict and set(j)==RESULT_KEYS and type(j['schema_version']) is int and j['schema_version']==1 and j['stage']=='lpac-stream-origin-result'
        and j['scope']==SCOPE and j['profile']==PROFILE and j['config_sha256']==sha(encode(c)) and j['profile_name']=='ruleproxy-lpac-stream-'+c['run'],'ipc_result')
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
    require(type(j['tasks']) is list and type(j['cleanup_tasks']) is list and len(j['tasks'])<=7 and len(j['cleanup_tasks'])<=1,'ipc_task_bounds')
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
            require(r['command']==expected_argv(role,j,c,command_root,parent) and r['image_sha256']==c['actor_sha256' if role=='lpac-pipe-front' else 'network_actor_sha256'],'ipc_closed_argv')
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
    validate_sinks(j,c,root=root)
    copy=dict(j);harvest(copy,c,parent)
    require(all(not copy[k] or j[k] for k in ('selected_ipc_observed','relay_connect_observed','origin_accepted_observed','origin_request_observed','origin_response_observed')),'ipc_sticky_facts')
    require(not j['mechanism_verified'] or positive(j,c,parent),'ipc_mechanism_recomputed')
    if j['failure'] is None:require(j['mechanism_verified'] and all(j[k] for k in CLEAN_KEYS) and not j['creation_unknown'],'ipc_complete_result')
    return j

def project(j,c,*,parent,root=None):
    validate_result(j,c,parent=parent,root=root);complete=j['failure'] is None and j['mechanism_verified'] and all(j[k] for k in CLEAN_KEYS) and not j['creation_unknown']
    return dict(schema_version=1,stage='lpac-stream-origin-observation',scope=SCOPE,profile=PROFILE,mechanism_verified=complete,
        selected_stream_observed=j['selected_ipc_observed'],semantic_lpac_verified=j['proof'] is not None and j['proof']['qualified'],network_tested=j['relay_connect_observed'] or j['origin_accepted_observed'],network_scope='ordinary-relay-to-owned-origin-only',
        relay_connect_observed=j['relay_connect_observed'],origin_accepted_observed=j['origin_accepted_observed'],origin_request_observed=j['origin_request_observed'],origin_response_observed=j['origin_response_observed'],payloads_verified=payloads_passed(j,c,parent),
        native_report_status=dict(j['report_status']),cleanup_known=all(j[k] for k in CLEAN_KEYS) and not j['creation_unknown'],failure=j['failure'],http_boundary='actual-file-provided-binary-bytes-through-one-inherited-stream-to-owned-origin',**{k:j[k] for k in CLEAN_KEYS},**dict.fromkeys(FALSE_CLAIMS,False))
def execute(root,c,parent,api,budget):return Owner(root,c,parent,api,budget).execute()

