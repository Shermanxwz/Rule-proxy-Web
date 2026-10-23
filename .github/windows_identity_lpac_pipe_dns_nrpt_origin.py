"""Same held zero-cap semantic LPAC IPC plus finite explicit DNS. WORK candidate."""
from __future__ import annotations
import ctypes as C
import importlib.util
import subprocess
import time
from pathlib import Path
ROOT=Path(__file__).resolve().parents[1]
def load(name,file):
 s=importlib.util.spec_from_file_location(name,Path(__file__).with_name(file));m=importlib.util.module_from_spec(s);s.loader.exec_module(m);return m
ipc=load('pipe_dns_immutable_ipc','windows_identity_lpac_pipe_origin.py')
base,zero,cell,origin,access=ipc.base,ipc.zero,ipc.cell,ipc.origin,ipc.access
launcher,helpers,live,local=ipc.launcher,ipc.helpers,ipc.live,ipc.local
require,sha,encode,decode=ipc.require,ipc.sha,ipc.encode,ipc.decode
dns=live.dns
policy=load('pipe_dns_nrpt_policy','windows_identity_dns_exact_nrpt_inventory.py')
POLICY_MODULE='.github/windows_identity_dns_exact_nrpt_inventory.py';INVENTORY=policy.INVENTORY;POLICY_MODE=policy.POLICY_MODE
SCOPE='one-local-same-zero-cap-lpac-pipe-origin-explicit-dns-exact-nrpt-nonmatch-v1'
PROFILE='same-process-zero-cap-lpac-ipc-standard53-exact-nrpt-nonmatch-v1'
MODULE='.github/windows_identity_lpac_pipe_dns_nrpt_origin.py';LOCAL_MODULE='.github/windows_identity_lpac_pipe_dns_nrpt_origin_local.py'
ACTOR='windows_identity_lpac_pipe_dns_front_actor.exe';MANIFEST='identity-lpac-pipe-dns-front-manifest.json'
CONTROL_ACTOR='windows_identity_dns_standard_actor.exe';CONTROL_MANIFEST='identity-dns-standard-manifest.json'
ACTUAL_READY=True
NONCES=('run','case','dns_before_case','dns_selected_case','dns_after_case','inventory_run')
ROLES=ipc.ROLES;REPORT_PATHS=ipc.REPORT_PATHS;MAX_NATIVE=16384;MAX_REPORT=1024*1024
NATIVE_SOURCES={'actorSourceSha256':'.github/native/windows_identity_lpac_pipe_dns_front_actor.cpp','controlHeaderSha256':'.github/native/windows_identity_lpac_pipe_dns_contract.hpp',
 'pipeActorSha256':'.github/native/windows_identity_proxy_pipe_actor.cpp','identitySourceSha256':'.github/native/windows_identity_actor.cpp','coreSha256':'.github/native/windows_identity_proxy_bridge_core.hpp','dnsProbeSha256':'.github/native/windows_identity_dns_standard_probe.hpp'}
CONTROL_SOURCES={'actorSourceSha256':'.github/native/windows_identity_dns_standard_actor.cpp','identitySourceSha256':'.github/native/windows_identity_actor.cpp','dnsProbeSha256':'.github/native/windows_identity_dns_standard_probe.hpp'}
SOURCES=tuple(dict.fromkeys((*ipc.SOURCES,*CONTROL_SOURCES.values(),*NATIVE_SOURCES.values(),MODULE,LOCAL_MODULE,POLICY_MODULE,INVENTORY)))
CLEAN_KEYS=ipc.CLEAN_KEYS
FALSE_CLAIMS=tuple(dict.fromkeys((*(k for k in ipc.FALSE_CLAIMS if k!='selected_dns_api_tested'),'default_resolver_tested','broker_pid_attributed','broker_cancellation_proven','dns_isolation_qualified')))
ACKS=(*ipc.ACKS,'standard53_impact_acknowledged','same_process_dns_acknowledged','nrpt_nonmatching_policy_acknowledged')
GRANTS=ipc.GRANTS
handle_list,info_values,owned_tree,expected_acl=ipc.handle_list,ipc.info_values,ipc.owned_tree,ipc.expected_acl
api_version=lambda:1
work_cutoff=ipc.work_cutoff
def stage_name(run):return 'local-lpac-pipe-dns-nrpt-origin-'+run

def config_validate(c,*,source_names=SOURCES):
 keys={'schema_version','scope','profile','policy_mode',*NONCES,'frequency','start_qpc','root_deadline_qpc','deadline_qpc','guard_job_name','source_hashes','source_sha256','device_sha256','actor_sha256','manifest_sha256','origin_actor_sha256','origin_manifest_sha256','control_actor_sha256','control_manifest_sha256','recovery_plan_sha256'}
 require(type(c) is dict and set(c)==keys and type(c['schema_version']) is int and c['schema_version']==1 and c['scope']==SCOPE and c['profile']==PROFILE and c['policy_mode']==POLICY_MODE,'pipe_dns_config')
 require(all(base.ac.nonce(c[k]) for k in NONCES) and len({c[k] for k in NONCES})==6,'pipe_dns_nonces');live.clock_record(c['start_qpc'],c['frequency'],c['root_deadline_qpc'])
 require(c['root_deadline_qpc']==c['start_qpc']+120*c['frequency'] and c['deadline_qpc']==c['root_deadline_qpc']-5*c['frequency'] and c['guard_job_name']=='Local\\RuleProxy.LocalGuard.'+c['run'],'pipe_dns_epoch')
 require(type(c['source_hashes']) is dict and set(c['source_hashes'])==set(source_names) and all(base.ac.digest(v) for v in c['source_hashes'].values()) and sha(encode(c['source_hashes']))==c['source_sha256'],'pipe_dns_sources')
 require(all(base.ac.digest(c[k]) for k in keys if k.endswith('_sha256')),'pipe_dns_digests');return c

def validate_plan(p,*,device,source,actor,manifest,origin_actor,origin_manifest,control_actor,control_manifest):
 keys={'schema_version','scope','profile','policy_mode',*NONCES,'device_sha256','source_sha256','actor_sha256','manifest_sha256','origin_actor_sha256','origin_manifest_sha256','control_actor_sha256','control_manifest_sha256','recovery_reference',*ACKS}
 require(type(p) is dict and set(p)==keys and type(p['schema_version']) is int and p['schema_version']==1 and p['scope']==SCOPE and p['profile']==PROFILE and p['policy_mode']==POLICY_MODE,'pipe_dns_plan')
 require(all(p[k] is True for k in ACKS) and all(base.ac.nonce(p[k]) for k in NONCES) and len({p[k] for k in NONCES})==6,'pipe_dns_plan_ack')
 require([p[k] for k in ('device_sha256','source_sha256','actor_sha256','manifest_sha256','origin_actor_sha256','origin_manifest_sha256','control_actor_sha256','control_manifest_sha256')]==[device,source,actor,manifest,origin_actor,origin_manifest,control_actor,control_manifest],'pipe_dns_plan_binding')
 require(type(p['recovery_reference']) is str and 1<=len(p['recovery_reference'])<=512 and not any(x in p['recovery_reference'] for x in '\r\n\0'),'pipe_dns_recovery');return p

def verify_actor(actor,manifest,ah,mh,*,root,control=False):
 actor=launcher.checked_path(actor);manifest=launcher.checked_path(manifest);pins=CONTROL_SOURCES if control else NATIVE_SOURCES
 require(actor.name==(CONTROL_ACTOR if control else ACTOR) and manifest.name==(CONTROL_MANIFEST if control else MANIFEST) and actor.parent==manifest.parent,'pipe_dns_artifact_name')
 raw=local.bounded(manifest,8192);v=decode(raw.removeprefix(b'\xef\xbb\xbf'));keys={'schemaVersion','compileOnly','runtimeAcceptance','executableSha256',*pins}
 if not control:keys.add('interfaceVersion')
 require(type(v) is dict and set(v)==keys and type(v['schemaVersion']) is int and v['schemaVersion']==1 and v['compileOnly'] is True and v['runtimeAcceptance'] is False and v['executableSha256']==ah and sha(raw)==mh,'pipe_dns_manifest')
 if not control:require(type(v['interfaceVersion']) is int and v['interfaceVersion']==1,'pipe_dns_interface')
 require(base.ac.digest(ah) and base.ac.digest(mh) and sha(local.bounded(actor,8*1024*1024))==ah,'pipe_dns_artifact')
 for k,n in pins.items():require(v[k]==sha(local.bounded(launcher.checked_path(Path(root)/n,inside=root),256*1024)),'pipe_dns_native_pin')
 return actor

def verify_artifacts(c,root):
 verify_actor(root/'inputs'/ACTOR,root/'inputs'/MANIFEST,c['actor_sha256'],c['manifest_sha256'],root=root)
 verify_actor(root/'inputs'/CONTROL_ACTOR,root/'inputs'/CONTROL_MANIFEST,c['control_actor_sha256'],c['control_manifest_sha256'],root=root,control=True)
 origin.verify_artifact(root/'inputs'/origin.ACTOR,root/'inputs'/origin.MANIFEST,c['origin_manifest_sha256'],c['origin_actor_sha256'],source_root=root)

def ticket(c,pair,operation,phase_deadline):
 require(operation in (6,255) and type(phase_deadline) is int and c['start_qpc']<phase_deadline<=pair['end'] and (operation!=255 or phase_deadline==pair['end']),'pipe_dns_ticket')
 raw=bytearray(128);raw[:6]=b'LPD1'+bytes([1,operation]);raw[8:12]=(1 if operation==6 else 2).to_bytes(4,'little');raw[16:32]=bytes.fromhex(c['run']);raw[32:48]=bytes.fromhex(c['dns_selected_case'] if operation==6 else c['case']);raw[48:56]=c['frequency'].to_bytes(8,'little');raw[56:64]=pair['end'].to_bytes(8,'little');raw[72:88]=bytes.fromhex(c['case']);raw[88:96]=phase_deadline.to_bytes(8,'little');return bytes(raw)
def publish(path,raw,budget,end):
 path=Path(path);tmp=path.with_name(path.name+'.pending');budget.require_ms(end);base.durable_private(tmp,raw);require(local.bounded(tmp,128)==raw,'pipe_dns_pending_readback');budget.require_ms(end);require(not path.exists(),'pipe_dns_fresh_go');tmp.rename(path);budget.require_ms(end)

class API(ipc.API):
    def pair_spawn(self,info,argv,cwd,environment,job,owners,state,*,ends,pipe_pending,profile_pointer,budget,end,on_return):
        ends=handle_list(ends,pipe_pending);selected=profile_pointer is not None
        require(Path(argv[0]).name==(ACTOR if selected else origin.ACTOR) and argv[1]==('pipe-dns-front' if selected else 'pipe-relay') and job and len(argv)==(19 if selected else 14),'ipc_constructor_role')
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

STATISTICS_KEYS={'token_id','authentication_id','modified_id','expiration_time','token_type','dynamic_charged','dynamic_available','group_count','privilege_count'}
def validate_statistics(v,primary=None):
    require(type(v) is dict and set(v)==STATISTICS_KEYS and all(base.ac.integer(v[k],0,(1<<64)-1) for k in ('token_id','authentication_id','modified_id'))
        and base.ac.integer(v['expiration_time'],-(1<<63),(1<<63)-1) and all(base.ac.integer(v[k],0,0xffffffff) for k in ('token_type','dynamic_charged','dynamic_available','group_count','privilege_count')) and v['token_type']==1,'pipe_dns_token_statistics')
    if primary is not None:require(all(v[k]==primary[k] for k in ('token_id','authentication_id','token_type')),'pipe_dns_statistics_primary')
    return v
def capture_statistics(api,token,budget,end):
    budget.require_ms(end);raw,size=api.native.query(token,10,'TokenStatistics');require(size==C.sizeof(access.TOKEN_STATISTICS),'pipe_dns_statistics_size');v=C.cast(raw,C.POINTER(access.TOKEN_STATISTICS))[0]
    luid=lambda x:x.LowPart|((x.HighPart&0xffffffff)<<32)
    result=dict(token_id=luid(v.TokenId),authentication_id=luid(v.AuthenticationId),modified_id=luid(v.ModifiedId),expiration_time=v.ExpirationTime,token_type=v.TokenType,
        dynamic_charged=v.DynamicCharged,dynamic_available=v.DynamicAvailable,group_count=v.GroupCount,privilege_count=v.PrivilegeCount)
    validate_statistics(result);budget.require_ms(end);return result

def task_projection(row):
    v=base.task_projection(row)
    v.update({k:row.get(k) for k in ('role','command','expected_primary','expected_statistics','held_checks','ends','receipt','resume_intent_qpc','exit_observed_qpc')});return v

class Owner(ipc.Owner):
    def __init__(self,root,c,parent,api,budget,fixture_factory=None):
        super().__init__(root,c,parent,api,budget);self.factory=fixture_factory or dns.fixture.DnsCasesFixture;self.fixture=None;self.selected_wire=False;self.inventory=None
        self.j.update(stage='lpac-pipe-dns-nrpt-result',scope=SCOPE,profile=PROFILE,profile_name='ruleproxy-lpac-pipe-dns-nrpt-'+c['run'],**dict.fromkeys(FALSE_CLAIMS,False))
        self.j.update(policy_mode=POLICY_MODE,policy_inventory=policy.unknown_inventory(),policy_decisions=[],inventory=None,inventory_gates=[],fixture_attempted=False,fixture_ready=False,fixture_final=None,fixture_cleanup=False,ordinary_reports={},dns_go=[],dns_report=None,dns_report_status='unavailable',dns_final=None,dns_final_status='unavailable',dns_proof=None,selected_wire_query_observed=False,api_lifecycle_unknown=False)
    def journal(self,label,**extra):
        require(type(label) is str and label.replace('-','').isalnum() and len(self.j['intents'])<48,'pipe_dns_intent')
        value=dict(schema_version=1,scope=SCOPE,run=self.c['run'],config_sha256=sha(encode(self.c)),frequency=self.c['frequency'],deadline_qpc=self.c['deadline_qpc'],qpc=self.budget.read(),action=label,extra=extra)
        raw=encode(value);p=self.root/'journal'/('%02d-%s.json'%(len(self.j['intents']),label));base.durable_private(p,raw);self.j['intents'].append(dict(name=p.name,text=raw.decode('ascii'),sha256=sha(raw)));return value['qpc']
    def task(self,name,argv,work,**kw):
        if name in ('inventory','dns-before','dns-after'):
            require(not kw.get('lpac') and kw.get('stdio') is True and work==self.root/'tools'/name,'pipe_dns_ordinary_task')
            if name.startswith('dns-'):require(len(argv)==4 and Path(argv[0])==self.root/'inputs'/CONTROL_ACTOR and argv[1]==self.c['dns_'+name[4:]+'_case'] and argv[2]==str(self.c['frequency']) and argv[3].isdigit(),'pipe_dns_control_closed_argv')
            else:require(argv==[str(self.fixed_tool('WindowsPowerShell/v1.0/powershell.exe')),'-NoProfile','-NonInteractive','-ExecutionPolicy','Bypass','-File',str(self.root/INVENTORY),'-Run',self.c['inventory_run'],'-Frequency',str(self.c['frequency']),'-StartQpc',str(self.c['start_qpc']),'-DeadlineQpc',str(self.c['deadline_qpc'])],'pipe_dns_inventory_closed_argv')
            row=base.Owner.task(self,name,argv,work,**kw);row['command']=list(argv);return row
        return ipc.Owner.task(self,name,argv,work,**kw)
    def spawn(self,role,argv,end,ends=()):
        selected=role=='lpac-pipe-front';image=launcher.checked_path(argv[0],inside=self.root);expected=self.c['actor_sha256' if selected else 'origin_actor_sha256']
        require(sha(local.bounded(image,8*1024*1024))==expected,'ipc_spawn_image');info=self.api.process_info()
        row=dict(name=role,role=role,info=info,attempted=False,assigned=False,exited=False,exit_code=None,pid=None,created=None,token=None,identity=None,capabilities=None,lpac=None,
            lpac_expected=selected,process_returned=False,resumed=False,admitted=False,image_sha256=expected,admission_qpc=None,resume_qpc=None,go_qpc=[],command=argv,
            expected_primary=None,expected_statistics=None,held_checks=[],ends=list(ends),receipt=None,resume_intent_qpc=None,exit_observed_qpc=None,create_observation=dict(status='not_entered',winerror=None,process_information='not_observed',returned_qpc=None,work_cutoff=end,exception_detail=None))
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
        row['expected_primary']=zero.capture_primary(self.api,row['token'],self.parent,self.profile['sid'],self.budget,end,selected);row['capabilities']=[];row['expected_statistics']=capture_statistics(self.api,row['token'],self.budget,end);validate_statistics(row['expected_statistics'],row['expected_primary'])
        self.held(row,end);row['admission_qpc']=self.budget.read();self.budget.require_ms(end);row['admitted']=True;return row
    def held(self,row,end):
        self.budget.require_ms(end);h=row['info'].hProcess
        require(row['created'] is not None and not self.api.wait(h,0) and self.api.process_id(h)==row['pid'] and self.api.creation_time(h)==row['created'],'ipc_held_generation')
        self.api.verify_job(self.job,h);self.api.verify_outer(self.c['guard_job_name'],h);self.api.verify_image(h,Path(row['command'][0]))
        require(sha(local.bounded(Path(row['command'][0]),8*1024*1024))==row['image_sha256'],'ipc_held_image')
        current=zero.capture_primary(self.api,row['token'],self.parent,self.profile['sid'],self.budget,end,row['role']=='lpac-pipe-front');statistics=capture_statistics(self.api,row['token'],self.budget,end)
        require(current==row['expected_primary'] and statistics==row['expected_statistics'],'pipe_dns_primary_statistics_changed')
        row['held_checks'].append(dict(qpc=self.budget.read(),pid=row['pid'],created=row['created'],image_sha256=row['image_sha256'],primary=current,token_statistics=statistics,inner_job=True,outer_job=True));self.budget.require_ms(end)
    def wait(self,row,end,code=0):
        if row.get('role') in ROLES:return ipc.Owner.wait(self,row,end,code)
        base.Owner.wait(self,row,end,code)
        if row['name'] in ('inventory','dns-before','dns-after'):
            row['exit_observed_qpc']=self.budget.read();self.budget.require_ms(end)
    def native(self,key):
        p=self.root/REPORT_PATHS[key];raw=local.bounded(p,MAX_NATIVE);self.j['reports'][key]=dict(text=raw.decode('ascii'),sha256=sha(raw));self.j['report_status'][key]='invalid';self.j['tasks']=[task_projection(r) for r in self.children]
        v=validate_native(key,decode(raw),self.j,self.c,self.parent);self.j['report_status'][key]='valid';return v
    def sticky(self):
        if self.fixture is not None:self.selected_wire |= self.fixture.query_observed.is_set()
        self.j['selected_wire_query_observed']=self.selected_wire
    def ordinary(self,name,argv,end):
        work=self.root/'tools'/name;work.mkdir();(work/'temp').mkdir();row=self.task(name,argv,work,stdio=True);self.resume(row);self.wait(row,end);return row
    def inventory_gate(self,label):
        prior_phase=self.phase;self.phase='inventory';row=self.tasks['inventory'];now=self.budget.read()
        reviewed=review_inventory_record(self.j['inventory'],self.c,row['pid'],now,root=self.root)
        self.inventory=reviewed['raw'];projection=policy.inventory_public(reviewed['projection'])
        self.j['policy_decisions'].append(dict(label=label,qpc=now,projection=projection));self.j['policy_inventory']=dict(projection)
        require(policy.inventory_safe(projection),'pipe_dns_policy_inventory_safe')
        self.j['inventory_gates'].append(dict(label=label,qpc=now));self.phase=prior_phase;return now
    def fixture_start(self):
        c=self.c;script=launcher.checked_path(self.root/INVENTORY,inside=self.root);require(sha(local.bounded(script,256*1024))==c['source_hashes'][INVENTORY],'pipe_dns_inventory_pin')
        argv=[str(self.fixed_tool('WindowsPowerShell/v1.0/powershell.exe')),'-NoProfile','-NonInteractive','-ExecutionPolicy','Bypass','-File',str(script),'-Run',c['inventory_run'],'-Frequency',str(c['frequency']),'-StartQpc',str(c['start_qpc']),'-DeadlineQpc',str(c['deadline_qpc'])]
        row=self.ordinary('inventory',argv,min(self.budget.read()+10*c['frequency'],work_cutoff(c)-12*c['frequency']));raw=local.bounded(self.root/'tools/inventory/stdout',policy.MAX_INVENTORY);require(not local.bounded(self.root/'tools/inventory/stderr',policy.MAX_INVENTORY),'pipe_dns_inventory_stderr');self.j['inventory']=dict(text=raw.decode('utf-8','strict'),sha256=sha(raw),pid=row['pid']);self.inventory_gate('bind')
        self.j['fixture_attempted']=True;self.fixture=self.factory({k:c['dns_'+k+'_case'] for k in ('before','selected','after')},deadline=time.monotonic()+self.budget.remaining_ms(work_cutoff(c))/1000)
        require(self.fixture.bind_address=='127.0.0.1' and self.fixture.bind_port==53 and self.fixture.start()==53,'pipe_dns_fixture');self.j['fixture_ready']=True
    def control(self,label,end):
        c=self.c;name='dns-'+label;phase_end=min(self.budget.read()+2*c['frequency'],end);argv=[str(self.root/'inputs'/CONTROL_ACTOR),c['dns_'+label+'_case'],str(c['frequency']),str(phase_end)]
        work=self.root/'tools'/name;work.mkdir();(work/'temp').mkdir();row=self.task(name,argv,work,stdio=True);issued=self.inventory_gate(label);self.resume(row);self.wait(row,phase_end)
        raw=local.bounded(work/'stdout',16384);require(not local.bounded(work/'stderr',16384),'pipe_dns_control_stderr');record=dict(text=raw.decode('ascii'),sha256=sha(raw),phase_deadline=phase_end,issued_qpc=issued);self.j['ordinary_reports'][label]=record
        value=control_report(decode(raw),row,c,label,issued,phase_end);snap=dns.receiver(self.fixture.snapshot(deadline=time.monotonic()+self.budget.remaining_ms(end)/1000));require(api_positive(value['result']) and exact_case(snap,label),'pipe_dns_ordinary_'+label)
    def closed_report(self,path,row,end):
        while True:
            self.budget.require_ms(end)
            try:return local.bounded(path,MAX_NATIVE)
            except OSError as e:
                if getattr(e,'winerror',None) not in (2,32):raise
                require(not self.api.wait(row['info'].hProcess,0),'pipe_dns_no_report');self.api.sleep_ms(self.budget.require_ms(end,10))
    def run(self):
        self.setup();c=self.c;self.phase='origin';self.j['origin_start']=self.budget.read()
        args=[str(self.root/'inputs'/origin.ACTOR),'origin-fixture',c['run'],c['case'],str(self.root/REPORT_PATHS['origin']),str(self.root/REPORT_PATHS['ready']),str(c['frequency']),str(work_cutoff(c)),self.parent['sid']]
        fixture=self.spawn('ordinary-origin-fixture',args,work_cutoff(c));self.resume(fixture);self.origin_ready(fixture)
        self.phase='inventory';self.fixture_start();self.control('before',work_cutoff(c)-10*c['frequency'])
        self.phase='pair';start=self.budget.read();end=start+10*c['frequency'];require(end<=work_cutoff(c),'pipe_dns_pair_reserve');self.j['pair']=dict(start=start,end=end,frequency=c['frequency']);self.journal('pair-epoch',start=start,end=end)
        pairs=[]
        for label in ('response','request'):
            state=dict(name=label,receipt=None);self.j['pipe_allocations'].append(state);self.journal('allocate-'+label)
            try:pairs.append(self.api.allocate_pipe(self.pipes,self.owners.pending,self.parent['sid'],state,self.budget,end))
            finally:
                if state.get('unknown') or state.get('attempted') and not state.get('api_success'):self.j['pipe_allocation_unknown']=True
                raw=encode(dict(schema_version=1,scope=SCOPE,config_sha256=sha(encode(c)),pipe=label,observation={k:v for k,v in state.items() if k not in ('name','receipt')}));p=self.root/'returns'/('pipe-'+label+'.json');base.durable_private(p,raw);state['receipt']=dict(name=p.name,text=raw.decode('ascii'),sha256=sha(raw))
        (fr,rw),(rr,fw)=pairs
        front=self.spawn('lpac-pipe-front',[str(self.root/'inputs'/ACTOR),'pipe-dns-front',c['run'],c['case'],str(self.root/REPORT_PATHS['selected']),str(fr),str(fw),str(start),str(c['frequency']),str(end),self.parent['sid'],self.profile['sid'],'0',str(self.port),c['dns_selected_case'],str(self.root/'inputs/dns-go.bin'),str(self.root/'selected-report/dns.json'),str(self.root/'inputs/finish-go.bin'),str(self.root/'selected-report/final.json')],end,(fr,fw))
        relay=self.spawn('ordinary-pipe-relay',[str(self.root/'inputs'/origin.ACTOR),'pipe-relay',c['run'],c['case'],str(self.root/REPORT_PATHS['relay']),str(rr),str(rw),str(start),str(c['frequency']),str(end),self.parent['sid'],'none','0',str(self.port)],end,(rr,rw))
        self.phase='accesscheck';self.journal('observe-lpac');self.j['observer_attempted']=True;self.j['observer_resources_cleanup_verified']=False
        self.j['proof']=zero.observe_held(self.api.access_api(),front['info'].hProcess,front['expected_primary'],expected_pid=front['pid'],expected_creation=front['created'],expected_role='lpac',frequency=c['frequency'],deadline=end);self.j['observer_resources_cleanup_verified']=self.j['proof']['resource_cleanup_verified'];require(self.j['proof']['qualified'] and self.j['observer_resources_cleanup_verified'],'pipe_dns_first_proof')
        self.journal('parent-pipe-close');uncertain=False
        for h in (fr,rw,rr,fw):
            row=dict(handle=h,attempted=True,confirmed=False);self.j['parent_pipe_close_attempts'].append(row)
            try:self.pipes.close(h);row['confirmed']=True
            except BaseException:uncertain=True
        self.j['parent_pipe_handles_closed']=not uncertain and self.pipes.confirmed_closed;require(self.j['parent_pipe_handles_closed'],'pipe_dns_parent_close');self.resume(relay);self.resume(front)
        self.phase='protocol';self.closed_report(self.root/REPORT_PATHS['selected'],front,end);self.native('selected');self.wait(relay,end);self.wait(fixture,end);self.native('relay');self.native('origin');require(interim_positive(self.j,c,self.parent),'pipe_dns_interim')
        self.held(front,end);self.journal('observe-dns-lpac');prior_closed=self.j['observer_resources_cleanup_verified'];self.j['observer_resources_cleanup_verified']=False
        try:
            self.j['dns_proof']=zero.observe_held(self.api.access_api(),front['info'].hProcess,front['expected_primary'],expected_pid=front['pid'],expected_creation=front['created'],expected_role='lpac',frequency=c['frequency'],deadline=end)
            zero.validate_proof(self.j['dns_proof'],expected_primary_identity=front['expected_primary'],expected_role='lpac',expected_pid=front['pid'],expected_creation=front['created'],frequency=c['frequency'],deadline=end)
            self.j['observer_resources_cleanup_verified']=prior_closed and self.j['dns_proof']['resource_cleanup_verified']
        except BaseException:self.api.controls_uncertain=True;raise
        require(self.j['dns_proof']['qualified'] and self.j['observer_resources_cleanup_verified'],'pipe_dns_second_proof')
        self.held(front,end);issued=self.inventory_gate('selected');phase_end=min(issued+2*c['frequency'],end);raw=ticket(c,self.j['pair'],6,phase_end);self.journal('dns-query-go');self.j['api_lifecycle_unknown']=True;publish(self.root/'inputs/dns-go.bin',raw,self.budget,end);self.j['dns_go'].append(dict(sequence=1,operation=6,issued_qpc=issued,phase_deadline=phase_end,sha256=sha(raw)))
        query_error=None
        try:
            self.sticky();raw=self.closed_report(self.root/'selected-report/dns.json',front,min(phase_end+c['frequency']//5,end));self.j['dns_report']=dict(text=raw.decode('ascii'),sha256=sha(raw));self.j['dns_report_status']='invalid';v=dns_report(decode(raw),self.j,c,self.parent);self.j['dns_report_status']='valid';self.j['api_lifecycle_unknown']=v['dns']['result']['pending'] or v['dns']['result']['called'] and not v['dns']['result']['completed'];self.j['selected_dns_api_tested'] |= v['dns']['result']['called'];self.held(front,end)
        except BaseException as e:query_error=e
        finally:self.sticky()
        self.control('after',end);self.sticky()
        if query_error is not None:raise query_error
        require(not self.j['api_lifecycle_unknown'],'pipe_dns_unknown_API');self.held(front,end);issued=self.journal('dns-finish-go');raw=ticket(c,self.j['pair'],255,end);publish(self.root/'inputs/finish-go.bin',raw,self.budget,end);self.j['dns_go'].append(dict(sequence=2,operation=255,issued_qpc=issued,phase_deadline=end,sha256=sha(raw)))
        self.wait(front,end);raw=local.bounded(self.root/'selected-report/final.json',MAX_NATIVE);self.j['dns_final']=dict(text=raw.decode('ascii'),sha256=sha(raw));self.j['dns_final_status']='invalid';final_report(decode(raw),self.j,c,self.parent);self.j['dns_final_status']='valid';self.j['natural_exits']=True;self.j['completion_qpc']=self.budget.read();self.budget.require_ms(end)
        self.j['tasks']=[task_projection(r) for r in self.children];self.j['mechanism_verified']=positive(self.j,c,self.parent)
        require(self.j['mechanism_verified'],'pipe_dns_IPC_final')
    def cleanup(self):
        try:self.sticky()
        except BaseException:self.j['api_lifecycle_unknown']=True
        if self.fixture is not None:
            try:
                self.j['fixture_final']=dns.receiver(self.fixture.finish(deadline=time.monotonic()+self.budget.remaining_ms(self.budget.cutoff(3))/1000),final=True);self.j['fixture_cleanup']=self.j['fixture_final']['cleanup_confirmed']
            except BaseException:self.j['fixture_cleanup']=False
            finally:
                try:self.sticky()
                except BaseException:self.j['fixture_cleanup']=False
        # Unknown DNS/context or receiver resources must not permit profile cleanup.
        if self.j['api_lifecycle_unknown'] or self.j['fixture_attempted'] and not self.j['fixture_cleanup']:self.api.controls_uncertain=True
        ipc.Owner.cleanup(self)
        self.j['tasks']=[task_projection(r) for r in self.children];harvest(self.j,self.c,self.parent)
        row=self.tasks.get('lpac-pipe-front')
        if row and row['exited']:
            for key,name in (('dns_report','dns.json'),('dns_final','final.json')):
                p=self.root/'selected-report'/name
                if p.exists():
                    try:
                        raw=local.bounded(p,MAX_NATIVE);self.j[key]=dict(text=raw.decode('ascii'),sha256=sha(raw));self.j[key+'_status']='invalid'
                        (dns_report if key=='dns_report' else final_report)(decode(raw),self.j,self.c,self.parent);self.j[key+'_status']='valid'
                    except BaseException:pass
        if self.j['dns_report'] is not None:
            try:self.j['selected_dns_api_tested'] |= dns_report(record_value(self.j['dns_report']),self.j,self.c,self.parent)['dns']['result']['called']
            except BaseException:pass
    def execute(self):
        result=ipc.Owner.execute(self);result['tasks']=[task_projection(r) for r in self.children]
        for row in result['cleanup_tasks']:row['expected_statistics']=None
        if result['failure'] is None and not diagnostic(result,self.c,self.parent):result['failure']='protocol'
        return result

def record_value(record,*,root=None,path=None,limit=MAX_NATIVE):
    require(type(record) is dict and set(record)=={'text','sha256'} and type(record['text']) is str and base.ac.digest(record['sha256']),'ipc_raw_record')
    raw=record['text'].encode('ascii');require(0<len(raw)<=limit and sha(raw)==record['sha256'],'ipc_raw_commitment')
    if root is not None:require(local.bounded(launcher.checked_path(Path(root)/path,inside=root),limit)==raw,'ipc_physical_record')
    return decode(raw)

def query_names(c):return tuple(c['dns_'+key+'_case']+'.n0a.invalid' for key in ('before','selected','after'))

def inventory_raw(record,*,root=None):
 require(type(record) is dict and set(record)=={'text','sha256','pid'} and type(record['text']) is str and base.ac.digest(record['sha256']) and base.ac.integer(record['pid'],1,0xffffffff),'pipe_dns_policy_record')
 raw=record['text'].encode('utf-8','strict');require(0<len(raw)<=policy.MAX_INVENTORY and sha(raw)==record['sha256'],'pipe_dns_policy_raw_commitment')
 if root is not None:require(local.bounded(launcher.checked_path(Path(root)/'tools/inventory/stdout',inside=root),policy.MAX_INVENTORY)==raw,'pipe_dns_policy_physical_stdout')
 return raw

def review_inventory_record(record,c,pid,now,*,root=None):
 raw=inventory_raw(record,root=root);require(record['pid']==pid,'pipe_dns_policy_held_pid')
 return policy.review_raw(raw,run=c['inventory_run'],pid=pid,frequency=c['frequency'],start=c['start_qpc'],deadline=c['deadline_qpc'],now=now,raw_sha256=record['sha256'],queries=query_names(c))

def actor_rows(j):return {r['role']:r for r in j['tasks'] if r['role'] in ROLES}

def mechanics_passed(v,front):
    p=v['pipe'];co=v['core'];counts=[96,144,2,3] if front else [144,96,3,2];mask=7 if front else 56
    return (v['failure'] is None and v['win32_error'] is None and v['qpc'][3]<v['qpc'][2] and p['inheritance_cleared'] and p['eof_observed']
        and [p[k] for k in ('read_bytes','write_bytes','read_frames','write_frames')]==counts and all(p[k]=='confirmed' for k in ('reader_close','writer_close'))
        and co==dict(failure=0,observations=177 if front else 78,requested=mask,confirmed=mask,uncertain=0)
        and v['synthetic_http']==dict(request_checked=True,response_checked=True,client_sink_checked=front))

def expected_argv(role,j,c,root,parent):
 p=Path(root);pair=j['pair'];handles=actor_rows(j)[role]['ends']
 if role=='ordinary-origin-fixture':return ipc.expected_argv(role,j,c,root,parent)
 if role=='ordinary-pipe-relay':return ipc.expected_argv(role,j,c,root,parent)
 return [str(p/'inputs'/ACTOR),'pipe-dns-front',c['run'],c['case'],str(p/REPORT_PATHS['selected']),*(str(h) for h in handles),str(pair['start']),str(c['frequency']),str(pair['end']),parent['sid'],j['profile_sid'],'0',str(j['port']),c['dns_selected_case'],str(p/'inputs/dns-go.bin'),str(p/'selected-report/dns.json'),str(p/'inputs/finish-go.bin'),str(p/'selected-report/final.json')]

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
        'network_tested','proxy_tested','product_acceptance','dns_case_id'}
    require(type(v) is dict and set(v)==keys and type(v['schema_version']) is int and v['schema_version']==1 and v['stage']=='lpac-pipe-dns-ipc-complete' and v['dns_case_id']==c['dns_selected_case']
        and v['role']=='lpac-pipe-front' and v['run_id']==c['run'] and v['case_id']==c['case'] and type(v['pid']) is int and v['pid']==r['pid']
        and v['identity_basis']=='external-held-four-descriptor-required' and all(v[k] is False for k in ('network_tested','proxy_tested','product_acceptance')),'ipc_selected_wrapper')
    require(all(type(v[k]) is bool for k in ('read_handle_inherit_cleared','write_handle_inherit_cleared')),'ipc_flag_readback_type')
    origin.a.validate_ac_native(v['ipc_mechanics'],**expected)
    t=v['admitted_qpc'];last=v['ipc_mechanics']['qpc'][3]
    require(r['resume_intent_qpc'] is not None and last>=r['resume_intent_qpc'],'ipc_selected_resume_causality')
    require(t is None or base.ac.integer(t,r['resume_intent_qpc'],last),'ipc_native_resume_causality')
    require(t is not None or v['ipc_mechanics']['failure'] is not None,'ipc_missing_admitted_tick');return v

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
        grants={r['name']:r for r in j['tasks'] if r['name'].startswith('grant-')}
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

def interim_positive(j,c,parent):
 try:
  values=validated_reports(j,c,parent);require(set(values)==set(REPORT_PATHS),'pipe_dns_interim_reports');s,r,o=values['selected'],values['relay'],values['origin'];rows=actor_rows(j)
  require(mechanics_passed(s['ipc_mechanics'],True) and mechanics_passed(r['ipc_mechanics'],False) and origin.relay_passed(r['origin'],c['case']) and origin.fixture_passed(o,c['case']),'pipe_dns_interim_bytes')
  require(s['read_handle_inherit_cleared'] and s['write_handle_inherit_cleared'] and j['proof']['qualified'] and j['observer_resources_cleanup_verified'] and j['parent_pipe_handles_closed'],'pipe_dns_interim_authority')
  require(r['origin']['local_port']==o['socket']['peer_port'] and r['origin']['peer_port']==o['socket']['port']==j['port'],'pipe_dns_interim_tuple')
  require(all(rows[k]['exited'] and rows[k]['exit_code']==0 for k in ('ordinary-pipe-relay','ordinary-origin-fixture')) and not rows['lpac-pipe-front']['exited'],'pipe_dns_interim_live_selected');return True
 except (ValueError,TypeError,KeyError):return False

def api_timely(r,end):return r['configured'] and r['called'] and r['completed'] and not r['pending'] and r['records_released'] and not r['context_retained'] and r['within_deadline'] and r['start_qpc']<=r['end_qpc']<end

def api_positive(r):return api_timely(r,(1<<63)-1) and r['api_status']==r['query_status']==0 and r['answer_match'] and r['record_count']==1

def exact_case(v,label):
 return (v['counts'] is not None and v['error']=='none' and v['case_query_observed'][label] and v['cases'][label]==dict(matched_queries=1,answers_sent=1,rejected=0,send_failed=0))

def control_report(v,row,c,label,issued,end):
 keys={'schema_version','stage','identity','server_constructor','qpc_frequency','deadline_qpc','result'}
 require(type(v) is dict and set(v)==keys and type(v['schema_version']) is int and v['schema_version']==1 and v['stage']=='dns-standard-native' and v['server_constructor']=='official-v1-zero-port' and type(v['qpc_frequency']) is int and v['qpc_frequency']==c['frequency'] and type(v['deadline_qpc']) is int and v['deadline_qpc']==end,'pipe_dns_control_schema')
 i=v['identity'];expected={'schemaVersion','mode','nonce','pid','tokenUserSid','tokenIsAppContainer','tokenAppContainerSid','tokenElevated','isProcessInJob','tokenCapabilities','queriesSucceeded','errors'}
 require(type(i) is dict and set(i)==expected and type(i['schemaVersion']) is int and i['schemaVersion']==1 and i['mode']=='actor' and i['nonce']==c['dns_'+label+'_case'] and type(i['pid']) is int and i['pid']==row['pid'] and i['tokenUserSid']==row['identity']['sid'] and i['tokenIsAppContainer'] is False and i['tokenAppContainerSid'] is None and i['tokenElevated'] is False and i['isProcessInJob'] is True and i['tokenCapabilities']==[] and i['queriesSucceeded'] is True and i['errors']==[],'pipe_dns_control_identity')
 r=dns.api_result(v['result']);require(not r['within_deadline'] or issued<=r['start_qpc']<=r['end_qpc']<end,'pipe_dns_control_clock');return v

def dns_report(v,j,c,parent):
 keys={'schema_version','stage','role','run_id','http_case_id','dns_case_id','pid','sequence','pair_qpc','phase_qpc','command_close_verified','identity','dns','failure','selected_socket_api_tested','proxy_tested','product_acceptance'}
 row=actor_rows(j)['lpac-pipe-front'];pair=j['pair'];go=next(g for g in j['dns_go'] if g['operation']==6)
 require(type(v) is dict and set(v)==keys and type(v['schema_version']) is int and v['schema_version']==1 and v['stage']=='lpac-pipe-dns-dns-result' and v['role']=='lpac-pipe-front' and v['run_id']==c['run'] and v['http_case_id']==c['case'] and v['dns_case_id']==c['dns_selected_case'] and type(v['pid']) is int and v['pid']==row['pid'] and type(v['sequence']) is int and v['sequence']==1,'pipe_dns_native_dns')
 require(all(v[k] is False for k in ('selected_socket_api_tested','proxy_tested','product_acceptance')) and v['command_close_verified'] is True and v['failure'] in (None,'identity','dns-config','dns-pending','qpc','deadline') and v['pair_qpc']==[c['frequency'],pair['start'],pair['end']] and all(type(x) is int for x in v['pair_qpc']),'pipe_dns_native_dns_fixed')
 i=v['identity'];
 try:native_dns_identity(i,row,c,j)
 except ValueError:
  require(v['failure']=='identity' and type(i) is dict and set(i)=={'schemaVersion','mode','nonce','pid','tokenUserSid','tokenIsAppContainer','tokenAppContainerSid','tokenElevated','isProcessInJob','tokenCapabilities','queriesSucceeded','errors'} and i['pid']==row['pid'] and type(i['errors']) is list and len(i['errors'])<=16,'pipe_dns_native_identity_failure')
 q=v['phase_qpc'];require(type(q) is list and len(q)==3 and all(base.ac.integer(x,0,(1<<63)-1) for x in q) and go['issued_qpc']<=q[0] and (q[2]==0 or q[2]>=q[0]) and q[1]==go['phase_deadline']<=pair['end'],'pipe_dns_phase_clock')
 d=v['dns'];expected=dict(server_constructor='official-v1-zero-port',server_address='127.0.0.1',server_port=53,query_name=c['dns_selected_case']+'.n0a.invalid',query_type=1,query_options=dns.OPTIONS)
 require(type(d) is dict and set(d)=={*expected,'result'} and all(type(d[k]) is type(x) and d[k]==x for k,x in expected.items()),'pipe_dns_request');r=dns.api_result(d['result']);require(r['called'] or v['failure'] is not None,'pipe_dns_uncalled_typed_failure');require(v['failure']!='identity' or not r['called'] and not r['configured'] and not r['completed'] and not r['pending'] and r['record_count']==0 and not r['answer_match'],'pipe_dns_identity_no_API')
 require(not r['within_deadline'] or q[0]<=r['start_qpc']<=r['end_qpc']<=q[2] and r['end_qpc']<q[1],'pipe_dns_API_clock');return v

def native_dns_identity(i,row,c,j):
 expected={'schemaVersion','mode','nonce','pid','tokenUserSid','tokenIsAppContainer','tokenAppContainerSid','tokenElevated','isProcessInJob','tokenCapabilities','queriesSucceeded','errors'}
 require(type(i) is dict and set(i)==expected and type(i['schemaVersion']) is int and i['schemaVersion']==1 and i['mode']=='actor' and i['nonce']==c['run'] and type(i['pid']) is int and i['pid']==row['pid'] and i['tokenUserSid']==row['identity']['sid'] and i['tokenIsAppContainer'] is True and i['tokenAppContainerSid']==j['profile_sid'] and i['tokenElevated'] is False and i['isProcessInJob'] is True and i['tokenCapabilities']==[] and i['queriesSucceeded'] is True and i['errors']==[],'pipe_dns_same_native_identity')

def final_report(v,j,c,parent):
 keys={'schema_version','stage','role','run_id','http_case_id','dns_case_id','pid','pair_qpc','last_qpc','ipc_report_sha256','dns_report_sha256','dns_called','dns_pending','finish_admitted','command_close_verified','failure','selected_socket_api_tested','proxy_tested','product_acceptance'}
 row=actor_rows(j)['lpac-pipe-front'];go=next((g for g in j['dns_go'] if g['operation']==255),None);phase=dns_report(record_value(j['dns_report']),j,c,parent)
 require(type(v) is dict and set(v)==keys and type(v['schema_version']) is int and v['schema_version']==1 and v['stage']=='lpac-pipe-dns-final' and v['role']=='lpac-pipe-front' and v['run_id']==c['run'] and v['http_case_id']==c['case'] and v['dns_case_id']==c['dns_selected_case'] and type(v['pid']) is int and v['pid']==row['pid'],'pipe_dns_final_identity')
 require(v['pair_qpc']==[c['frequency'],j['pair']['start'],j['pair']['end']] and all(type(x) is int for x in v['pair_qpc']) and v['ipc_report_sha256']==j['reports']['selected']['sha256'] and v['dns_report_sha256']==j['dns_report']['sha256'],'pipe_dns_final_original_hashes')
 require(v['dns_called'] is phase['dns']['result']['called'] and v['dns_pending'] is phase['dns']['result']['pending'] and type(v['finish_admitted']) is type(v['command_close_verified']) is bool and v['failure'] in (None,'control','identity','dns-config','dns-pending','qpc','deadline') and all(v[k] is False for k in ('selected_socket_api_tested','proxy_tested','product_acceptance')),'pipe_dns_final_types')
 require(base.ac.integer(v['last_qpc'],0,c['root_deadline_qpc']),'pipe_dns_final_clock');require(not row['exited'] or v['last_qpc']==0 or v['last_qpc']<=row['exit_observed_qpc'],'pipe_dns_final_before_held_exit');require(not v['finish_admitted'] or go is not None and v['last_qpc']>=max(go['issued_qpc'],phase['phase_qpc'][2]),'pipe_dns_final_finish_cause');return v

def diagnostic(j,c,parent):
 if j.get('policy_mode')!=POLICY_MODE or len(j.get('policy_decisions',[]))!=4 or not policy.inventory_safe(j.get('policy_inventory',policy.unknown_inventory())):return False
 try:
  require(positive(j,c,parent) and len(j['dns_go'])==2 and not j['selected_wire_query_observed'] and not j['api_lifecycle_unknown'] and j['dns_report_status']==j['dns_final_status']=='valid','pipe_dns_combined_prerequisite')
  require(j['fixture_final'] is not None and j['fixture_cleanup'],'pipe_dns_receiver_complete');receiver=dns.receiver(j['fixture_final'],final=True);require(receiver['cleanup_confirmed'] and receiver['error']=='none' and receiver['counts'] is not None and receiver['cases']['selected']['matched_queries']==0 and not receiver['selected_query_observed'],'pipe_dns_selected_absence_bounded')
  for label in ('before','after'):
   rec=j['ordinary_reports'][label];row=next(r for r in j['tasks'] if r['name']=='dns-'+label);v=control_report(record_value({k:rec[k] for k in ('text','sha256')}),row,c,label,rec['issued_qpc'],rec['phase_deadline']);require(api_positive(v['result']) and exact_case(receiver,label),'pipe_dns_control_qualified')
  v=dns_report(record_value(j['dns_report']),j,c,parent);r=v['dns']['result'];require(v['failure'] is None and v['phase_qpc'][2]<v['phase_qpc'][1] and api_timely(r,v['phase_qpc'][1]) and r['api_status']==5 and not r['answer_match'] and r['record_count']==0,'pipe_dns_typed_API5')
  final=final_report(record_value(j['dns_final']),j,c,parent);require(final['failure'] is None and final['finish_admitted'] and final['command_close_verified'],'pipe_dns_final_success');return True
 except (ValueError,TypeError,KeyError,StopIteration):return False

TASK_KEYS=ipc.TASK_KEYS|{'expected_statistics'}
DNS_KEYS={'policy_mode','policy_inventory','policy_decisions','inventory','inventory_gates','fixture_attempted','fixture_ready','fixture_final','fixture_cleanup','ordinary_reports','dns_go','dns_report','dns_report_status','dns_final','dns_final_status','dns_proof','selected_wire_query_observed','api_lifecycle_unknown'}
RESULT_KEYS=ipc.RESULT_KEYS|DNS_KEYS|set(FALSE_CLAIMS)
def validate_result(j,c,*,parent,root=None):
    config_validate(c);require(launcher.token_is_ordinary(parent),'ipc_parent')
    require(type(j) is dict and set(j)==RESULT_KEYS and type(j['schema_version']) is int and j['schema_version']==1 and j['stage']=='lpac-pipe-dns-nrpt-result'
        and j['scope']==SCOPE and j['profile']==PROFILE and j['policy_mode']==POLICY_MODE and j['config_sha256']==sha(encode(c)) and j['profile_name']=='ruleproxy-lpac-pipe-dns-nrpt-'+c['run'],'ipc_result')
    require(j['failure'] is None or j['failure'] in ('setup','origin','pair','accesscheck','protocol','cleanup','inventory'),'ipc_failure');base.validate_failure_detail(j['failure_detail'])
    launcher.validate_child_environment(j['child_environment']);require(all(j[k] is False for k in FALSE_CLAIMS),'ipc_fixed_false')
    bools={'pipe_allocation_unknown','creation_unknown','observer_attempted','selected_ipc_observed','relay_connect_observed','origin_accepted_observed','origin_request_observed','origin_response_observed','mechanism_verified','natural_exits','workload_stop','selected_dns_api_tested',*CLEAN_KEYS}
    require(all(type(j[k]) is bool for k in bools),'ipc_bool_facts')
    state=j['profile_state'];require(type(state) is dict and set(state)=={'attempted','returned','created','sid_pointer_returned'} and all(type(v) is bool for v in state.values())
        and (not state['created'] or state['attempted'] and state['returned']) and (j['profile_sid'] is None or base.ac.ac_profile_sid(j['profile_sid'])),'ipc_profile_ownership')
    pair=j['pair']
    if pair is not None:require(type(pair) is dict and set(pair)=={'start','end','frequency'} and pair['frequency']==c['frequency'] and base.ac.integer(pair['start'],c['start_qpc'],work_cutoff(c))
        and pair['end']==pair['start']+10*c['frequency'] and pair['end']<=work_cutoff(c),'ipc_pair_clock')
    require(type(j['intents']) is list and len(j['intents'])<=48,'ipc_intent_list');actions=[];ticks=[]
    for i,r in enumerate(j['intents']):
        require(type(r) is dict and set(r)=={'name','text','sha256'} and r['name'].startswith('%02d-'%i) and '/' not in r['name'] and '\\' not in r['name'],'ipc_intent_name')
        v=record_value({k:r[k] for k in ('text','sha256')},root=root,path='journal/'+r['name'],limit=4096)
        require(set(v)=={'schema_version','scope','run','config_sha256','frequency','deadline_qpc','qpc','action','extra'} and v['schema_version']==1 and type(v['schema_version']) is int
            and v['scope']==SCOPE and v['run']==c['run'] and v['config_sha256']==sha(encode(c)) and v['frequency']==c['frequency'] and v['deadline_qpc']==c['deadline_qpc']
            and base.ac.integer(v['qpc'],c['start_qpc'],c['root_deadline_qpc']) and type(v['extra']) is dict,'ipc_intent_binding')
        require(r['name']=='%02d-%s.json'%(i,v['action']),'ipc_intent_exact_name');actions.append(v);ticks.append(v['qpc'])
    require(ticks==sorted(ticks),'ipc_intent_order')
    require(type(j['tasks']) is list and type(j['cleanup_tasks']) is list and len(j['tasks'])<=9 and len(j['cleanup_tasks'])<=1,'ipc_task_bounds')
    rows={}
    for r in (*j['tasks'],*j['cleanup_tasks']):
        require(type(r) is dict and set(r)==TASK_KEYS and r['name'] not in rows and r['name'] in (*ROLES,*('grant-'+g[0] for g in GRANTS),'remove','inventory','dns-before','dns-after'),'ipc_task_schema');rows[r['name']]=r
        require(all(type(r[k]) is bool for k in ('attempted','assigned','exited','resumed','admitted','lpac_expected','process_returned')) and r['lpac'] is None and r['go_qpc']==[],'ipc_task_flags')
        if r['role'] not in ROLES:require(r['expected_statistics'] is None,'pipe_dns_nonactor_statistics')
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
            if r['expected_statistics'] is not None:validate_statistics(r['expected_statistics'],r['expected_primary'])
            if r['expected_primary'] is not None:
                p=r['expected_primary'];zero.identity_shape(p)
                require(p['token_type']==1 and p['impersonation_level'] is None and p['capabilities']==[] and p['sid']==parent['sid'] and p['session_id']==parent['session_id']
                    and p['elevated'] is p['ui_access'] is False and p['appcontainer']==(role=='lpac-pipe-front') and p['appcontainer_sid']==(j['profile_sid'] if role=='lpac-pipe-front' else None),'ipc_primary_role')
                if role=='lpac-pipe-front':zero.identity(p,primary=True)
                else:require(p['integrity_rid']==parent['integrity_rid'],'ipc_ordinary_il')
            require(type(r['held_checks']) is list and len(r['held_checks'])<=12 and (not r['held_checks'] or r['expected_statistics'] is not None),'ipc_held_snapshots')
            for h in r['held_checks']:
                require(type(h) is dict and set(h)=={'qpc','pid','created','image_sha256','primary','token_statistics','inner_job','outer_job'} and h['pid']==r['pid'] and h['created']==r['created']
                    and h['image_sha256']==r['image_sha256'] and h['primary']==r['expected_primary'] and h['token_statistics']==r['expected_statistics'] and h['inner_job'] is h['outer_job'] is True
                    and base.ac.integer(h['qpc'],c['start_qpc'],(pair['end'] if pair and role!='ordinary-origin-fixture' else work_cutoff(c))-1),'ipc_held_snapshot')
            if r['admitted']:
                require(r['expected_primary'] is not None and r['expected_statistics'] is not None and r['held_checks'] and r['identity'] is not None,'ipc_admitted_external_identity')
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
            and j['proof'] is not None and j['proof']['qualified'] and j['proof']['resource_cleanup_verified'],'ipc_pair_resume_proof_and_closes')
    if len(allocated)==4:
        for role,ends in (('lpac-pipe-front',[allocated[0],allocated[3]]),('ordinary-pipe-relay',[allocated[2],allocated[1]])):
            if role in rows:require(rows[role]['ends']==ends,'ipc_pipe_direction')
    if j['proof'] is not None:
        front=rows['lpac-pipe-front'];zero.validate_proof(j['proof'],expected_primary_identity=front['expected_primary'],expected_role='lpac',expected_pid=front['pid'],expected_creation=front['created'],frequency=c['frequency'],deadline=pair['end'])
        require(j['observer_attempted'] and (not j['observer_resources_cleanup_verified'] or j['proof']['resource_cleanup_verified']),'ipc_proof_resources')
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
    validate_dns_ledger(j,c,parent,root=root)
    return j

def validate_dns_ledger(j,c,parent,*,root=None):
 require(all(type(j[k]) is bool for k in ('fixture_attempted','fixture_ready','fixture_cleanup','selected_wire_query_observed','api_lifecycle_unknown')),'pipe_dns_ledger_bools')
 require(type(j['ordinary_reports']) is dict and set(j['ordinary_reports'])<={'before','after'} and type(j['inventory_gates']) is list and len(j['inventory_gates'])<=4 and type(j['dns_go']) is list and len(j['dns_go'])<=2,'pipe_dns_ledger_bounds')
 rows={r['name']:r for r in (*j['tasks'],*j['cleanup_tasks'])}
 inventory=None
 if j['inventory'] is not None:
  r=j['inventory'];require(type(r) is dict and set(r)=={'text','sha256','pid'} and 'inventory' in rows and r['pid']==rows['inventory']['pid'],'pipe_dns_inventory_row')
  inventory=inventory_raw(r,root=root)
  task=rows['inventory'];require(all(task[k] for k in ('attempted','process_returned','assigned','admitted','resumed','exited')) and task['exit_code']==0 and base.ac.digest(task['image_sha256']),'pipe_dns_policy_inventory_held_natural_exit')
  cut=task['create_observation']['work_cutoff'];require(cut<=c['deadline_qpc'] and base.ac.integer(task['admission_qpc'],c['start_qpc'],cut-1)
   and base.ac.integer(task['resume_qpc'],task['admission_qpc'],cut-1) and base.ac.integer(task['exit_observed_qpc'],task['resume_qpc'],(min(cut,work_cutoff(c)-12*c['frequency']))-1),'pipe_dns_policy_inventory_task_clock')
  argv=task['command'];require(type(argv) is list and len(argv)==15 and all(type(x) is str for x in argv) and tuple(Path(argv[0]).parts[-4:])==('System32','WindowsPowerShell','v1.0','powershell.exe'),'pipe_dns_policy_inventory_command')
  script=Path(root)/INVENTORY if root is not None else Path(argv[6]);require(argv[1:]==['-NoProfile','-NonInteractive','-ExecutionPolicy','Bypass','-File',str(script),'-Run',c['inventory_run'],'-Frequency',str(c['frequency']),'-StartQpc',str(c['start_qpc']),'-DeadlineQpc',str(c['deadline_qpc'])],'pipe_dns_policy_inventory_closed_command')
  if root is not None:require(sha(local.bounded(launcher.checked_path(script,inside=root),256*1024))==c['source_hashes'][INVENTORY] and not local.bounded(launcher.checked_path(Path(root)/'tools/inventory/stderr',inside=root),policy.MAX_INVENTORY),'pipe_dns_policy_inventory_script_stdio')
 policy.inventory_public(j['policy_inventory']);require(type(j['policy_decisions']) is list and len(j['policy_decisions'])<=4,'pipe_dns_policy_decisions')
 decision_labels=[];accepted=[]
 for index,decision in enumerate(j['policy_decisions']):
  require(type(decision) is dict and set(decision)=={'label','qpc','projection'} and inventory is not None and decision['label']==('bind','before','selected','after')[index],'pipe_dns_policy_decision_order')
  reviewed=review_inventory_record(j['inventory'],c,rows['inventory']['pid'],decision['qpc'],root=root);value=reviewed['projection'];require(value==decision['projection'] and reviewed['raw']['end_qpc']<=rows['inventory']['exit_observed_qpc']<=decision['qpc'],'pipe_dns_policy_decision_recomputed')
  if policy.inventory_safe(value):accepted.append(dict(label=decision['label'],qpc=decision['qpc']))
  else:require(index==len(j['policy_decisions'])-1,'pipe_dns_policy_unsafe_is_terminal')
  decision_labels.append(decision['label'])
 require(j['policy_inventory']==(j['policy_decisions'][-1]['projection'] if j['policy_decisions'] else policy.unknown_inventory()) and j['inventory_gates']==accepted,'pipe_dns_policy_projection_and_authorization')
 for name,row in rows.items():
  if name in ('inventory','dns-before','dns-after') and row['admitted']:require(launcher.token_is_ordinary(row['identity']) and row['identity']['sid']==parent['sid'] and row['identity']['session_id']==parent['session_id'] and row['capabilities']==[],'pipe_dns_ordinary_held_identity')
 labels=[];ticks=[]
 for gate in j['inventory_gates']:
  require(type(gate) is dict and set(gate)=={'label','qpc'} and gate['label'] in ('bind','before','selected','after') and gate['label'] not in labels and inventory is not None,'pipe_dns_inventory_gate')
  require(policy.inventory_safe(review_inventory_record(j['inventory'],c,rows['inventory']['pid'],gate['qpc'],root=root)['projection']),'pipe_dns_policy_authorized_gate');labels.append(gate['label']);ticks.append(gate['qpc'])
 require(labels==[k for k in ('bind','before','selected','after') if k in labels] and ticks==sorted(ticks),'pipe_dns_inventory_order')
 for label,r in j['ordinary_reports'].items():
  require(type(r) is dict and set(r)=={'text','sha256','phase_deadline','issued_qpc'} and label in labels and 'dns-'+label in rows and r['issued_qpc']==j['inventory_gates'][labels.index(label)]['qpc'],'pipe_dns_ordinary_gate')
  row=rows['dns-'+label];raw=record_value({k:r[k] for k in ('text','sha256')},root=root,path='tools/dns-'+label+'/stdout');control_report(raw,row,c,label,r['issued_qpc'],r['phase_deadline'])
  limit=j['pair']['end'] if label=='after' else work_cutoff(c)-10*c['frequency']
  require(base.ac.integer(r['phase_deadline'],r['issued_qpc']+1,limit) and r['phase_deadline']-r['issued_qpc']<=2*c['frequency'] and base.ac.integer(row['exit_observed_qpc'],r['issued_qpc'],r['phase_deadline']-1),'pipe_dns_control_original_deadline')
  if raw['result']['within_deadline']:require(row['exit_observed_qpc']>=raw['result']['end_qpc'],'pipe_dns_control_held_exit_cause')
  if label=='before' and j['pair'] is not None:require(row['exit_observed_qpc']<=j['pair']['start'],'pipe_dns_before_precedes_pair')
  if label=='after' and j['dns_report_status']=='valid':
   require(r['issued_qpc']>=dns_report(record_value(j['dns_report']),j,c,parent)['phase_qpc'][2],'pipe_dns_after_follows_selected')
  require(row['command']==[str(Path(root)/'inputs'/CONTROL_ACTOR),c['dns_'+label+'_case'],str(c['frequency']),str(r['phase_deadline'])] if root is not None else Path(row['command'][0]).name==CONTROL_ACTOR,'pipe_dns_control_argv')
  require(row['admitted'] and row['resumed'] and row['exited'] and row['exit_code']==0 and row['image_sha256']==c['control_actor_sha256'],'pipe_dns_control_held')
 second_attempted=any(decode(r['text'].encode('ascii'))['action']=='observe-dns-lpac' for r in j['intents'])
 require(j['dns_proof'] is None or second_attempted,'pipe_dns_second_observer_intent')
 require(not second_attempted or j['dns_proof'] is not None or not j['observer_resources_cleanup_verified'],'pipe_dns_second_observer_unknown_resources')
 if j['dns_proof'] is not None:
  row=rows['lpac-pipe-front'];zero.validate_proof(j['dns_proof'],expected_primary_identity=row['expected_primary'],expected_role='lpac',expected_pid=row['pid'],expected_creation=row['created'],frequency=c['frequency'],deadline=j['pair']['end'])
  require(not j['observer_resources_cleanup_verified'] or j['dns_proof']['resource_cleanup_verified'],'pipe_dns_second_observer_cleanup')
 for index,g in enumerate(j['dns_go']):
  require(type(g) is dict and set(g)=={'sequence','operation','issued_qpc','phase_deadline','sha256'} and g['sequence']==index+1 and g['operation']==(6 if index==0 else 255) and base.ac.integer(g['issued_qpc'],j['pair']['start'],j['pair']['end']-1),'pipe_dns_go_schema')
  raw=ticket(c,j['pair'],g['operation'],g['phase_deadline']);require(sha(raw)==g['sha256'],'pipe_dns_go_bytes')
  if index==1:require('after' in j['ordinary_reports'] and g['issued_qpc']>=rows['dns-after']['exit_observed_qpc'],'pipe_dns_finish_after_control_exit')
  if root is not None:require(local.bounded(launcher.checked_path(Path(root)/('inputs/dns-go.bin' if index==0 else 'inputs/finish-go.bin'),inside=root),128)==raw,'pipe_dns_go_physical')
  if index==0:
   require('selected' in labels and g['issued_qpc']==j['inventory_gates'][labels.index('selected')]['qpc'] and j['dns_proof'] is not None and j['dns_proof']['qualified'] and j['observer_resources_cleanup_verified'] and j['dns_proof']['end_qpc']<=g['issued_qpc'],'pipe_dns_GO_held_proof_inventory')
   require(g['phase_deadline']-g['issued_qpc']<=2*c['frequency'],'pipe_dns_phase_bound')
   front=rows['lpac-pipe-front'];require(j['report_status']['selected']=='valid' and j['dns_proof']['start_qpc']>=validate_native('selected',record_value(j['reports']['selected']),j,c,parent)['ipc_mechanics']['qpc'][3] and all(rows[k]['exited'] and rows[k]['exit_observed_qpc']<=j['dns_proof']['start_qpc'] for k in ('ordinary-pipe-relay','ordinary-origin-fixture')),'pipe_dns_IPC_and_peer_exit_before_DNS_proof')
   require(any(j['dns_proof']['end_qpc']<=h['qpc']<=g['issued_qpc'] for h in front['held_checks']),'pipe_dns_fresh_same_token_before_GO')
   before=j['ordinary_reports'].get('before');require(before is not None and api_positive(control_report(record_value({k:before[k] for k in ('text','sha256')}),rows['dns-before'],c,'before',before['issued_qpc'],before['phase_deadline'])['result']),'pipe_dns_before_native_required')
 value=None
 for key,name in (('dns_report','dns.json'),('dns_final','final.json')):
  status=j[key+'_status'];require(status in ('unavailable','valid','invalid') and (j[key] is None)==(status=='unavailable'),'pipe_dns_raw_status')
  if j[key] is not None:
   record=j[key];raw=record['text'].encode('ascii');require(set(record)=={'text','sha256'} and len(raw)<=MAX_NATIVE and sha(raw)==record['sha256'],'pipe_dns_raw_original')
   if root is not None:require(local.bounded(launcher.checked_path(Path(root)/'selected-report'/name,inside=root),MAX_NATIVE)==raw,'pipe_dns_raw_physical')
   if status=='valid':
    if key=='dns_report':value=dns_report(decode(raw),j,c,parent);require(not value['dns']['result']['called'] or j['selected_dns_api_tested'],'pipe_dns_API_called_sticky')
    else:final_report(decode(raw),j,c,parent)
 require(not j['dns_go'] or value is not None and (not value['dns']['result']['called'] or value['dns']['result']['completed'] and not value['dns']['result']['pending']) or j['api_lifecycle_unknown'],'pipe_dns_API_unknown_sticky')
 if j['fixture_final'] is not None:
  v=dns.receiver(j['fixture_final'],final=True);require(not v['selected_query_observed'] or j['selected_wire_query_observed'],'pipe_dns_receiver_sticky');require(j['fixture_cleanup']==v['cleanup_confirmed'],'pipe_dns_receiver_cleanup')
 require(not j['fixture_cleanup'] or j['fixture_final'] is not None,'pipe_dns_fixture_final_required')
 if j['failure'] is None:require(diagnostic(j,c,parent) and not j['selected_wire_query_observed'] and not j['api_lifecycle_unknown'] and j['dns_report_status']==j['dns_final_status']=='valid' and labels==['bind','before','selected','after'],'pipe_dns_complete_negative')
 return j

def project(j,c,*,parent,root=None):
 # Harvest independent receiver positivity before any fallible parsing.
 hit=bool(j.get('selected_wire_query_observed'))
 f=j.get('fixture_final')
 if type(f) is dict:hit |= f.get('selected_query_observed') is True or type(f.get('case_query_observed')) is dict and f['case_query_observed'].get('selected') is True
 validate_result(j,c,parent=parent,root=root)
 result=None
 if j['dns_report_status']=='valid':
  v=dns_report(record_value(j['dns_report']),j,c,parent);r=v['dns']['result'];result={k:r[k] for k in ('called','completed','pending','api_status','query_status','answer_match','record_count','records_released','context_retained','within_deadline')};result['query_status_success_verified']=r['called'] and r['completed'] and not r['pending'] and r['api_status']==r['query_status']==0
 clean=all(j[k] for k in CLEAN_KEYS) and (not j['fixture_attempted'] or j['fixture_cleanup']) and not j['creation_unknown']
 complete=j['failure'] is None and diagnostic(j,c,parent) and clean
 return dict(schema_version=1,stage='lpac-pipe-dns-nrpt-observation',scope=SCOPE,profile=PROFILE,policy_mode=POLICY_MODE,policy_inventory=policy.inventory_public(j['policy_inventory']),ipc_mechanism_verified=j['mechanism_verified'],semantic_lpac_verified=j['proof'] is not None and j['proof']['qualified'],same_selected_process_verified=j['dns_proof'] is not None and j['dns_proof']['qualified'],
  selected_api=result,selected_dns_api_tested=j['selected_dns_api_tested'],selected_wire_query_observed=hit,access_denial_observed=complete,observation_complete=complete,cleanup_known=clean,api_lifecycle_unknown=j['api_lifecycle_unknown'],ordinary_before='before' in j['ordinary_reports'] and api_positive(record_value({k:j['ordinary_reports']['before'][k] for k in ('text','sha256')})['result']),ordinary_after='after' in j['ordinary_reports'] and api_positive(record_value({k:j['ordinary_reports']['after'][k] for k in ('text','sha256')})['result']),
  network_tested=bool(j['relay_connect_observed'] or j['origin_accepted_observed'] or j['ordinary_reports'] or result and result['called'] or hit),failure=j['failure'],**{k:j[k] for k in CLEAN_KEYS},**dict.fromkeys(FALSE_CLAIMS,False))

def execute(root,c,parent,api,budget):return Owner(root,c,parent,api,budget).execute()

PROJECTION_KEYS={'schema_version','stage','scope','profile','policy_mode','policy_inventory','ipc_mechanism_verified','selected_dns_api_tested','semantic_lpac_verified','same_selected_process_verified','selected_api','selected_wire_query_observed','access_denial_observed','observation_complete','cleanup_known','api_lifecycle_unknown','ordinary_before','ordinary_after','network_tested','failure',*CLEAN_KEYS,*FALSE_CLAIMS}
def validate_projection(v):
 require(type(v) is dict and set(v)==PROJECTION_KEYS and type(v['schema_version']) is int and v['schema_version']==1 and v['stage']=='lpac-pipe-dns-nrpt-observation' and v['scope']==SCOPE and v['profile']==PROFILE and v['policy_mode']==POLICY_MODE,'pipe_dns_safe_schema')
 require(all(type(v[k]) is bool for k in PROJECTION_KEYS-{'schema_version','stage','scope','profile','policy_mode','policy_inventory','selected_api','failure'}) and all(v[k] is False for k in FALSE_CLAIMS),'pipe_dns_safe_bool');policy.inventory_public(v['policy_inventory'])
 require(v['failure'] is None or v['failure'] in ('setup','origin','pair','accesscheck','protocol','cleanup','inventory'),'pipe_dns_safe_failure')
 api=v['selected_api']
 if api is not None:
  bs={'called','completed','pending','answer_match','records_released','context_retained','within_deadline','query_status_success_verified'}
  require(type(api) is dict and set(api)==bs|{'api_status','query_status','record_count'} and all(type(api[k]) is bool for k in bs) and all(base.ac.integer(api[k],0,0xffffffff) for k in ('api_status','query_status')) and base.ac.integer(api['record_count'],0,16),'pipe_dns_safe_API')
  require(api['query_status_success_verified']==(api['called'] and api['completed'] and not api['pending'] and api['api_status']==api['query_status']==0),'pipe_dns_safe_API_success')
 require(not v['cleanup_known'] or all(v[k] for k in CLEAN_KEYS),'pipe_dns_safe_cleanup')
 require(not v['selected_wire_query_observed'] or v['network_tested'] and not v['access_denial_observed'] and not v['observation_complete'],'pipe_dns_safe_wire')
 require(v['access_denial_observed']==v['observation_complete'],'pipe_dns_safe_observed')
 if v['access_denial_observed']:
  require(policy.inventory_safe(v['policy_inventory']) and v['failure'] is None and v['ipc_mechanism_verified'] and v['semantic_lpac_verified'] and v['same_selected_process_verified'] and v['ordinary_before'] and v['ordinary_after'] and v['cleanup_known'] and not v['api_lifecycle_unknown'] and api is not None and api['called'] and api['completed'] and not api['pending'] and api['within_deadline'] and api['records_released'] and not api['context_retained'] and api['api_status']==5 and api['record_count']==0 and not api['answer_match'],'pipe_dns_safe_denial')
 return v
