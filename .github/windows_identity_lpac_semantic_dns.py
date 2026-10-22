"""Standalone semantic-LPAC DNS with independently held AccessCheck admission.

The old class46 entry remains unchanged. This scope never queries or invents
class46. A prior owner-held primary snapshot and the four AccessCheck controls
are repeated before selected resume and every selected/DNS GO. DNS receiver
positivity remains independent and sticky. Importing this module is inert.
"""
from __future__ import annotations
import importlib.util
from pathlib import Path
import time

ROOT=Path(__file__).resolve().parents[1]
def load(name,file):
    spec=importlib.util.spec_from_file_location(name,Path(__file__).with_name(file))
    module=importlib.util.module_from_spec(spec);spec.loader.exec_module(module);return module
identity=load('semantic_lpac_identity_core','windows_identity_lpac_identity_cell.py')
base=identity.owner
live,contracts,local,launcher,helpers,ac=base.live,base.contracts,base.local,base.launcher,base.helpers,base.ac
access=identity.access
require,sha,encode,decode=base.require,base.sha,base.encode,base.decode
validate_failure_detail=base.validate_failure_detail
known_no_child=base.known_no_child
MODULE='.github/windows_identity_lpac_semantic_dns.py'
LOCAL_MODULE='.github/windows_identity_lpac_semantic_dns_local.py'
SOURCES=tuple(dict.fromkeys((*identity.SOURCES,MODULE)))
SCOPE='standalone-lpac-accesscheck-standard53-dns-mechanism-v1'
IDENTITY_BASIS='held-accesscheck-matrix-v1'
PROFILE=base.PROFILE
PORTS=base.PORTS
NONCES=base.NONCES
CHECKS=tuple('selected_semantic_held' if key=='selected_lpac_held' else key for key in base.CHECKS)+('semantic_resources_cleanup','semantic_resume_go_verified')
MAX_REPORT=base.MAX_REPORT

def api_version():return 1

def capability_catalog(value):return base.capability_catalog(value)
def fixed_catalog():return base.fixed_catalog()

def plan(value,*,device,source,actor,manifest):
    keys={'schema_version','scope','device_sha256','source_sha256','actor_sha256','manifest_sha256',
        'identity_basis','semantic_identity_acknowledged','standard53_impact_acknowledged','fresh_lpac_acl_profile_acknowledged','residue_review_acknowledged','recovery_reference'}
    require(type(value) is dict and set(value)==keys and type(value['schema_version']) is int and value['schema_version']==1
        and value['scope']==SCOPE and value['identity_basis']==IDENTITY_BASIS,'plan')
    for key,expected in (('device_sha256',device),('source_sha256',source),('actor_sha256',actor),('manifest_sha256',manifest)):
        require(ac.digest(expected) and value[key]==expected,'plan_binding')
    require(all(value[k] is True for k in ('semantic_identity_acknowledged','standard53_impact_acknowledged','fresh_lpac_acl_profile_acknowledged','residue_review_acknowledged'))
        and type(value['recovery_reference']) is str and 1<=len(value['recovery_reference'])<=512,'plan_impact')
    return value

def blank(mode):
    return dict(identity_basis=IDENTITY_BASIS,token_class46_queried=False,semantic_check_count=0,selected_semantic_matrix=None,
        schema_version=1,stage='standalone-semantic-lpac-dns-local',scope=SCOPE,mode=mode,status='inconclusive',failure=None,
        comparison='standalone-accesscheck-semantics-no-causal-psec-comparison',
        source_sha256=None,actor_sha256=None,manifest_sha256=None,recovery_plan_sha256=None,
        checks=dict.fromkeys(CHECKS,False),selected_api=None,selected_wire_query_observed=False,
        network_tested=False,observation_complete=False,access_denial_observed=False,tree_retained=False,recovery_required=False,
        g_psec_tested=False,proxy_tested=False,product_acceptance=False,default_resolver_tested=False,
        dns_isolation_qualified=False,broker_pid_attributed=False,broker_cancellation_proven=False)

def validate_public(v):
    b=blank(v.get('mode') if type(v) is dict else None)
    require(type(v) is dict and set(v)==set(b) and v['mode'] in ('preflight','runtime'),'public_schema')
    for k in ('schema_version','stage','scope','comparison','identity_basis','token_class46_queried','g_psec_tested','proxy_tested','product_acceptance','default_resolver_tested',
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
    require(live.integer(v['semantic_check_count'],0,32),'semantic_public_count')
    require(v['selected_semantic_matrix'] is None or type(v['selected_semantic_matrix']) is list
        and v['selected_semantic_matrix']==[2,0,0,2] and all(type(x) is int for x in v['selected_semantic_matrix']),'semantic_public_matrix')
    require(not v['checks']['selected_semantic_held'] or v['semantic_check_count']>0 and v['selected_semantic_matrix']==[2,0,0,2],'semantic_public_admitted')
    if v['mode']=='preflight':require(v['semantic_check_count']==0 and v['selected_semantic_matrix'] is None,'semantic_preflight_inert')
    require(len(encode(v))<=8192,'public_bound');return v

class IdentityAPI(identity.IdentityAPI):
    """Original fixed OPT_OUT constructor; semantic admission never calls46."""
    pass

def config_validate(c,*,source_names=None):
    keys={'schema_version','scope','identity_basis',*NONCES,'start_qpc','frequency','root_deadline_qpc','deadline_qpc','guard_job_name',
        'source_hashes','source_sha256','device_sha256','actor_sha256','manifest_sha256','recovery_plan_sha256','capability_catalog'}
    require(type(c) is dict and set(c)==keys and type(c['schema_version']) is int and c['schema_version']==1
        and c['scope']==SCOPE and c['identity_basis']==IDENTITY_BASIS,'semantic_config')
    require(all(ac.nonce(c[n]) for n in NONCES) and len({c[n] for n in NONCES})==len(NONCES),'semantic_nonces')
    live.clock_record(c['start_qpc'],c['frequency'],c['root_deadline_qpc'])
    require(c['root_deadline_qpc']==c['start_qpc']+120*c['frequency'] and c['deadline_qpc']==c['root_deadline_qpc']-5*c['frequency']
        and c['guard_job_name']=='Local\\RuleProxy.LocalGuard.'+c['run'],'semantic_clock')
    names=tuple(dict.fromkeys((*SOURCES,LOCAL_MODULE))) if source_names is None else tuple(source_names)
    require(type(c['source_hashes']) is dict and set(c['source_hashes'])==set(names) and all(ac.digest(v) for v in c['source_hashes'].values())
        and sha(encode(c['source_hashes']))==c['source_sha256'],'semantic_sources')
    require(all(ac.digest(c[k]) for k in ('source_sha256','device_sha256','actor_sha256','manifest_sha256','recovery_plan_sha256')),'semantic_digest')
    capability_catalog(c['capability_catalog']);return c

class Owner(base.Owner):
    """Reuse ordinary DNS lifecycle, replacing only selected identity admission.

    Class46 is never called or populated. Ordinary paths retain the original
    non-AppContainer/zero-capability admission. All semantic proof resources
    must close before a selected resume/GO or profile deletion is authorized.
    """
    def __init__(self,*args,**kwargs):
        super().__init__(*args,**kwargs);self.primary=None;self.probe=None
        self.j.update(identity_basis=IDENTITY_BASIS,token_class46_queried=False,selected_primary=None,
            semantic_checks=[],semantic_authorizations=[],semantic_resources_cleanup=True,semantic_resume_go_verified=False)
        self.j['profile_name']='ruleproxy-semantic-lpac-'+self.c['run']

    def task(self,name,argv,work,*,lpac=False,**kwargs):
        if not lpac:return super().task(name,argv,work,lpac=False,**kwargs)
        require(name=='selected' and not kwargs,'semantic_selected_role')
        cutoff=self.budget.cutoff(25);self.budget.require_ms(cutoff)
        require(launcher.child_environment_admitted(self.j['child_environment']) and self.selected_environment is not None,'semantic_environment')
        image=launcher.checked_path(argv[0]);image_hash=sha(local.bounded(image,8*1024*1024))
        require(image==self.root/'inputs'/live.ACTOR and image_hash==self.c['actor_sha256'],'semantic_image')
        info=self.api.process_info();row=dict(info=info,name=name,attempted=False,assigned=False,exited=False,exit_code=None,pid=None,
            created=None,process_returned=False,create_observation=dict(status='not_entered',winerror=None,process_information='not_observed',
            returned_qpc=None,work_cutoff=cutoff,exception_detail=None),token=None,identity=None,capabilities=None,lpac=None,
            lpac_expected=True,resumed=False,admitted=False,image_sha256=image_hash,admission_qpc=None,resume_qpc=None,go_qpc=[])
        self.children.append(row);self.tasks[name]=row;state=dict(creation_attempted=False);self.journal('spawn-selected')
        try:self.api.atomic_spawn(info,argv,work,self.job,self.owners,state,environment=self.selected_environment,
            stdio=(),profile_pointer=self.profile['pointer'],catalog=self.catalog)
        finally:
            row.update(attempted=state['creation_attempted'],process_returned=bool(info.hProcess))
            if info.dwProcessId:row['pid']=int(info.dwProcessId)
            row['create_observation']=dict(status=state.get('create_status','not_entered'),winerror=state.get('create_winerror'),
                process_information=state.get('create_information','not_observed'),returned_qpc=None,work_cutoff=cutoff,
                exception_detail=state.get('create_exception_detail'))
            if row['create_observation']['status'] in ('returned_false','returned_true'):
                try:row['create_observation']['returned_qpc']=self.budget.read()
                except BaseException:pass
        self.budget.require_ms(cutoff);require(info.hProcess and info.hThread and info.dwProcessId,'semantic_partial_create')
        row['created']=self.api.creation_time(info.hProcess);self.api.verify_job(self.job,info.hProcess);row['assigned']=True
        self.api.verify_outer(self.c['guard_job_name'],info.hProcess);self.api.verify_image(info.hProcess,image)
        require(sha(local.bounded(image,8*1024*1024))==image_hash,'semantic_image_changed')
        row['token']=self.api.token_for_process(info.hProcess);self.owners.add(row['token'])
        # This independent QUERY-token snapshot precedes the observer opening
        # its distinct QUERY|DUP source. Never adapt expectations to a proof.
        self.primary=identity.capture_primary(self.api,row['token'],self.parent,self.catalog,self.profile['sid'],self.budget,cutoff)
        self.j['selected_primary']=self.primary;row['identity']=self.api.identity(row['token']);row['capabilities']=self.primary['capabilities']
        self.semantic(row,'admission');row['admission_qpc']=self.budget.read();self.budget.require_ms(cutoff);row['admitted']=True
        self.j['selected_lpac_held']=True;return row

    def verify_selected(self,row):
        cutoff=self.budget.cutoff(25);self.budget.require_ms(cutoff)
        require(row is self.tasks.get('selected') and row['assigned'] and row['lpac'] is None
            and not self.api.wait(row['info'].hProcess,0) and self.api.process_id(row['info'].hProcess)==row['pid']
            and self.api.creation_time(row['info'].hProcess)==row['created'],'semantic_held_generation')
        self.api.verify_job(self.job,row['info'].hProcess);self.api.verify_outer(self.c['guard_job_name'],row['info'].hProcess)
        image=self.root/'inputs'/live.ACTOR;self.api.verify_image(row['info'].hProcess,image)
        require(sha(local.bounded(image,8*1024*1024))==self.c['actor_sha256'],'semantic_held_image')
        prior=identity.capture_primary(self.api,row['token'],self.parent,self.catalog,self.profile['sid'],self.budget,cutoff)
        require(prior==self.primary,'semantic_primary_changed');return self.budget.read()

    def semantic(self,row,purpose):
        require(purpose in ('admission','resume','held','dns-go','finish') and len(self.j['semantic_checks'])<32,'semantic_purpose')
        before=self.verify_selected(row);number=len(self.j['semantic_checks'])+1
        intent=dict(schema_version=1,scope=SCOPE,identity_basis=IDENTITY_BASIS,run=self.c['run'],sequence=number,purpose=purpose,
            config_sha256=sha(encode(self.c)),pid=row['pid'],creation=row['created'],primary_sha256=sha(encode(self.primary)),
            frequency=self.c['frequency'],deadline_qpc=self.c['deadline_qpc'],proof_deadline_qpc=self.budget.cutoff(25),qpc=before)
        raw=encode(intent);directory=self.root/'semantic-intents';directory.mkdir(exist_ok=True)
        base.durable_private(directory/('%04d.json'%number),raw)
        record=dict(sequence=number,purpose=purpose,intent_text=raw.decode('ascii'),intent_sha256=sha(raw),
            held_before_qpc=before,held_after_qpc=None,proof=None)
        self.j['semantic_checks'].append(record);self.j['semantic_resources_cleanup']=False
        try:
            if self.probe is None:self.probe=self.api.access_api()
            record['proof']=access.observe_held(self.probe,row['info'].hProcess,self.primary,expected_pid=row['pid'],
                expected_creation=row['created'],expected_role='lpac',frequency=self.c['frequency'],deadline=self.budget.cutoff(25))
            record['held_after_qpc']=self.verify_selected(row)
            require(record['proof']['qualified'],'semantic_matrix')
        finally:
            self.j['semantic_resources_cleanup']=all(r['proof'] is not None and r['proof']['resource_cleanup_verified'] for r in self.j['semantic_checks'])
            if not self.j['semantic_resources_cleanup']:self.api.controls_uncertain=True
        return number

    def alive(self,row):
        if row['name']=='selected':
            require(row['admitted'],'semantic_admitted');return self.semantic(row,'held')
        return super().alive(row)

    def authorize(self,kind,label,proof,issued,go_sha=None):
        self.j['semantic_authorizations'].append(dict(kind=kind,label=label,proof_sequence=proof,issued_qpc=issued,go_sha256=go_sha))

    def resume(self,row):
        if row['name']!='selected':return super().resume(row)
        require(row['admitted'] and not row['resumed'],'semantic_resume_once');proof=self.semantic(row,'resume')
        self.authorize('resume','selected',proof,self.budget.read())
        self.api.resume(row['info'].hThread);row['resumed']=True;row['resume_qpc']=self.budget.read()

    def phase(self,row,label,sequence):
        c=self.c;selected=label=='selected';self.alive(row);self.alive(self.tasks['selected']);self.alive(self.tasks['health'])
        end=min(self.budget.read()+2*c['frequency'],self.budget.cutoff(25));self.budget.require_ms(end)
        name='selected' if selected else 'health';boot=c[name+'_boot'];admission=c[name+'_admission'];case=c[label+'_case']
        self.journal('go-'+label)
        fields=dict(run=c['run'],case=case,sequence=sequence,opcode=6,frequency=c['frequency'],deadline=c['deadline_qpc'],
            fixed_ports=PORTS,admission=admission,phase_deadline=end)
        self.alive(row);proof=self.semantic(self.tasks['selected'],'dns-go');self.alive(self.tasks['health'])
        issued=self.inventory_gate(label) # Same once-inventory, original epoch, <=5F; no refresh or renewal.
        control=self.root/('lpac-control' if selected else 'health-control');digest=live.publish_go(control,budget=self.budget,**fields)
        row['go_qpc'].append(issued);self.authorize('dns-go',label,proof,issued,digest)
        self.j['go'].append(dict(role=name,label=label,fields=fields,sha256=digest,issued_qpc=issued))
        reports=self.root/('lpac-report' if selected else 'health');self.sticky()
        try:value,raw=contracts.read_when_closed(self.api,self.budget,reports/('phase-%04d.json'%sequence),
            row['info'].hProcess,min(end+c['frequency'],self.budget.cutoff(20)))
        finally:self.sticky()
        self.record_native(name+'/phase-%04d.json'%sequence,raw)
        return live.dns.phase(value,row,{**c,'dns_extension':{'profile':live.dns.PROFILE}},
            role='selected-client' if selected else 'health-client',boot=boot,admission=admission,sequence=sequence,
            case=case,phase_deadline=end,identity_check=contracts.native_identity)

    def finish(self,row,name,sequence,count):
        if name!='selected':return super().finish(row,name,sequence,count)
        require(row is self.tasks.get('selected') and row['admitted'],'semantic_finish_role');proof=self.semantic(row,'finish')
        c=self.c;fields=dict(run=c['run'],case=c['selected_boot'],sequence=sequence,opcode=255,frequency=c['frequency'],
            deadline=c['deadline_qpc'],fixed_ports=PORTS,admission=c['selected_admission'],phase_deadline=self.budget.cutoff(20))
        self.journal('finish-selected');digest=live.publish_go(self.root/'lpac-control',budget=self.budget,**fields);issued=self.budget.read()
        self.authorize('finish','selected',proof,issued,digest)
        self.j['go'].append(dict(role='selected',label='finish',fields=fields,sha256=digest,issued_qpc=issued))
        self.wait(row,self.budget.cutoff(15));raw=local.bounded(self.root/'lpac-report/final.json',16384);value=decode(raw)
        contracts.client_final(value,row,c,role='selected-client',boot=c['selected_boot'],profile=PROFILE,count=count)
        self.record_native('selected/final.json',raw)

    def execute(self):
        j=super().execute();j['stage']='standalone-semantic-lpac-dns-worker-result'
        j['selected_semantic_held']=j.pop('selected_lpac_held')
        expected=[('resume','selected'),('dns-go','before'),('dns-go','selected'),('dns-go','after'),('finish','selected')]
        j['semantic_resume_go_verified']=(j['failure'] is None and [(r['kind'],r['label']) for r in j['semantic_authorizations']]==expected)
        return j

def execute(root,c,parent,api,budget):
    config_validate(c);require(launcher.token_is_ordinary(parent) and budget.frequency==c['frequency']
        and budget.deadline==c['deadline_qpc'],'semantic_parent_budget')
    return Owner(root,c,parent,api,budget).execute()

def validate_semantic_ledger(j,c,*,parent,tasks):
    primary=j['selected_primary'];selected=tasks.get('selected');checks=j['semantic_checks'];authorizations=j['semantic_authorizations']
    if primary is not None:
        access.identity(primary,primary=True)
        require(selected is not None and primary['sid']==parent['sid'] and primary['session_id']==parent['session_id']
            and primary['appcontainer_sid']==j['profile_sid'],'semantic_external_primary')
        live.capability_set(primary['capabilities'],PROFILE,c['capability_catalog'])
        require(selected['identity'] is not None and selected['capabilities']==primary['capabilities']
            and all(selected['identity'][k]==primary[k] for k in ('sid','session_id','token_type','appcontainer','appcontainer_sid',
                'integrity_rid','elevated','ui_access')),'semantic_owner_snapshot')
        live.selected_identity(selected['identity'],selected['capabilities'],parent,PROFILE,c['capability_catalog'])
    require(type(checks) is list and len(checks)<=32 and type(authorizations) is list and len(authorizations)<=5,'semantic_ledger_bound')
    closed=[];last=c['start_qpc'];deadline=c['deadline_qpc']-25*c['frequency']
    for index,row in enumerate(checks,1):
        require(type(row) is dict and set(row)=={'sequence','purpose','intent_text','intent_sha256','held_before_qpc','held_after_qpc','proof'}
            and type(row['sequence']) is int and row['sequence']==index and row['purpose'] in ('admission','resume','held','dns-go','finish')
            and primary is not None and selected is not None,'semantic_check_schema')
        require(live.integer(row['held_before_qpc'],last,deadline-1),'semantic_check_clock')
        require(type(row['intent_text']) is str,'semantic_intent_text');raw=row['intent_text'].encode('ascii')
        require(1<=len(raw)<=4096 and sha(raw)==row['intent_sha256'],'semantic_intent_digest');intent=decode(raw)
        require(type(intent) is dict and set(intent)=={'schema_version','scope','identity_basis','run','sequence','purpose','config_sha256',
            'pid','creation','primary_sha256','frequency','deadline_qpc','proof_deadline_qpc','qpc'}
            and type(intent['schema_version']) is int and intent['schema_version']==1 and intent['scope']==SCOPE
            and intent['identity_basis']==IDENTITY_BASIS and intent['run']==c['run'] and intent['sequence']==index
            and intent['purpose']==row['purpose'] and intent['config_sha256']==sha(encode(c)) and intent['pid']==selected['pid']
            and intent['creation']==selected['created'] and intent['primary_sha256']==sha(encode(primary))
            and intent['frequency']==c['frequency'] and intent['deadline_qpc']==c['deadline_qpc']
            and intent['proof_deadline_qpc']==deadline and intent['qpc']==row['held_before_qpc'],'semantic_intent_binding')
        proof=row['proof']
        if proof is None:
            require(row['held_after_qpc'] is None,'semantic_unknown_observer');closed.append(False);last=row['held_before_qpc'];continue
        access.validate_proof(proof,expected_primary_identity=primary,expected_role='lpac',expected_pid=selected['pid'],
            expected_creation=selected['created'],frequency=c['frequency'],deadline=deadline)
        if proof['start_qpc'] is not None:require(live.integer(proof['start_qpc'],row['held_before_qpc'],deadline-1),'semantic_proof_start')
        if row['held_after_qpc'] is not None:
            require(live.integer(row['held_after_qpc'],row['held_before_qpc'],deadline-1)
                and (proof['end_qpc'] is None or proof['end_qpc']<=row['held_after_qpc']),'semantic_held_after')
        closed.append(proof['resource_cleanup_verified']);last=row['held_after_qpc'] or row['held_before_qpc']
    require(j['semantic_resources_cleanup']==all(closed),'semantic_resource_cleanup_exact')
    admission=(bool(checks) and checks[0]['purpose']=='admission' and checks[0]['proof'] is not None
        and checks[0]['proof']['qualified'] and checks[0]['held_after_qpc'] is not None)
    require(not j['selected_semantic_held'] or selected is not None and selected['admitted'] and admission,'semantic_admission')
    require(selected is None or not selected['admitted'] or j['selected_semantic_held'] and admission,'semantic_selected_admission')
    expected=[('resume','selected'),('dns-go','before'),('dns-go','selected'),('dns-go','after'),('finish','selected')]
    last_proof=0
    for row,(kind,label) in zip(authorizations,expected):
        require(type(row) is dict and set(row)=={'kind','label','proof_sequence','issued_qpc','go_sha256'}
            and row['kind']==kind and row['label']==label and live.integer(row['proof_sequence'],last_proof+1,len(checks)),
            'semantic_authorization_schema')
        proofrow=checks[row['proof_sequence']-1];proof=proofrow['proof']
        require(proofrow['purpose']==('resume' if kind=='resume' else 'dns-go' if kind=='dns-go' else 'finish')
            and proof is not None and proof['qualified'] and proofrow['held_after_qpc'] is not None
            and live.integer(row['issued_qpc'],proofrow['held_after_qpc'],deadline-1),'semantic_authorization_proof')
        if kind=='resume':
            require(row['go_sha256'] is None and selected['admitted']
                and (not selected['resumed'] or row['issued_qpc']<=selected['resume_qpc']),'semantic_resume_binding')
        else:
            ticket=next((r for r in j['go'] if r['label']==(label if kind=='dns-go' else 'finish')
                and (kind=='dns-go' or r['role']=='selected')),None)
            require(ticket is not None and ticket['sha256']==row['go_sha256'] and ticket['issued_qpc']==row['issued_qpc'],
                'semantic_go_binding')
        last_proof=row['proof_sequence']
    require(not selected or not selected['resumed'] or bool(authorizations) and authorizations[0]['kind']=='resume','semantic_no_unadmitted_resume')
    required_go=[r for r in j['go'] if r['fields']['opcode']==6 or r['role']=='selected']
    require(len(authorizations)>=(1 if selected and selected['resumed'] else 0)+len(required_go),'semantic_go_authorization_count')
    complete=(j['failure'] is None and [(r['kind'],r['label']) for r in authorizations]==expected)
    require(j['semantic_resume_go_verified']==complete,'semantic_authorizations_complete')
    if j['failure'] is None:require(j['semantic_resources_cleanup'] and complete and admission,'semantic_complete')


def validate_result(j,c,*,parent):
    config_validate(c);require(launcher.token_is_ordinary(parent),'semantic_external_parent')
    keys={'identity_basis','token_class46_queried','selected_primary','semantic_checks','semantic_authorizations','semantic_resources_cleanup','semantic_resume_go_verified','schema_version','stage','failure','failure_detail','selected_wire_query_observed','profile_name','profile_sid','profile_created','acl_attempted',
        'selected_semantic_held','child_environment','inventory','inventory_gates','go','native','fixture_final','ordinary_before','ordinary_after','natural_exits',
        'selected_access_denial','workload_cleanup','workload_job_empty','workload_stop','acl_removed','cleanup_tools','profile_deleted',
        'sid_released','fixture_cleanup','tasks','cleanup_tasks'}
    require(type(j) is dict and set(j)==keys and type(j['schema_version']) is int and j['schema_version']==1
        and j['stage']=='standalone-semantic-lpac-dns-worker-result' and j['failure'] in (None,'setup','protocol','inventory','cleanup')
        and j['profile_name']=='ruleproxy-semantic-lpac-'+c['run'] and j['identity_basis']==IDENTITY_BASIS and j['token_class46_queried'] is False,'result_schema')
    validate_failure_detail(j['failure_detail']);require(j['failure'] is not None or j['failure_detail'] is None,'success_failure_detail')
    launcher.validate_child_environment(j['child_environment'])
    booleans=keys-{'identity_basis','token_class46_queried','selected_primary','semantic_checks','semantic_authorizations','schema_version','stage','failure','failure_detail','profile_name','profile_sid','child_environment','inventory','inventory_gates','go','native','fixture_final','tasks','cleanup_tasks'}
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
            require(row['lpac'] is None,'class46_not_queried')
            require(row['lpac_expected'] or row['lpac'] is None,'ordinary_lpac_not_queried')
            for k in ('pid','created','admission_qpc','resume_qpc'):
                require(row[k] is None or live.integer(row[k],1,live.MAX_SIGNED),'task_integer')
            require(row['exit_code'] is None or live.integer(row['exit_code']),'task_exit')
            require(type(row['go_qpc']) is list and len(row['go_qpc'])<=2 and all(live.integer(x,c['start_qpc'],c['deadline_qpc']-1) for x in row['go_qpc']),'task_go')
            require(not row['resumed'] or row['admitted'] and row['assigned'] and row['admission_qpc']<=row['resume_qpc']<c['deadline_qpc'],'task_resume_gate')
            require(not row['admitted'] or row['attempted'] and row['pid'] is not None and row['created'] is not None
                and row['identity'] is not None and row['capabilities'] is not None
                and observation['status']=='returned_true' and observation['process_information']=='nonzero'
                and row['lpac'] is None,'task_admission')
            if row['admitted'] and row['name'] in ('selected','health'):
                require(row['image_sha256']==c['actor_sha256'],'actor_task')
                if row['name']=='selected':
                    require(row['identity']['appcontainer_sid']==j['profile_sid'] and row['identity']['integrity_rid']==4096
                        and row['identity']['appcontainer'] is True and row['identity']['capability_count']==2
                        and row['identity']['token_type']==1 and row['identity']['elevated'] is False and row['identity']['ui_access'] is False
                        and j['profile_created'] and j['acl_attempted'],'task_lpac_binding')
                    live.capability_set(row['capabilities'],PROFILE,capability_catalog(c['capability_catalog']))
                else:require(launcher.token_is_ordinary(row['identity']) and launcher.same_identity(row['identity'],parent) and row['capabilities']==[],'task_ordinary')
            if field=='tasks':tasks[row['name']]=row
        if j['workload_cleanup'] and field=='tasks' or j['cleanup_tools'] and field=='cleanup_tasks':
            require(all(not r['attempted'] or known_no_child(r,start=c['start_qpc'])
                or r['process_returned'] and r['exited'] and r['exit_code'] is not None for r in rows),'cleanup_task_exit')
    require(not j['selected_semantic_held'] or 'selected' in tasks and tasks['selected']['admitted'] and tasks['selected']['lpac'] is None,'selected_held')
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
    validate_semantic_ledger(j,c,parent=parent,tasks=tasks)
    if j['failure'] is None:
        require(len(j['go'])==5 and len(native)==7 and j['ordinary_before'] and j['ordinary_after'] and j['natural_exits'] and receiver is not None
            and j['profile_created'] and j['acl_attempted']
            and launcher.child_environment_admitted(j['child_environment'])
            and j['semantic_resources_cleanup'] and j['semantic_resume_go_verified']
            and all(j[k] for k in ('selected_semantic_held','workload_cleanup','fixture_cleanup','acl_removed','cleanup_tools','profile_deleted','sid_released')),'complete_result')
    return j

def public_result(j,c,v,*,parent):
    # First carry the separately observed event through a malformed native
    # report or journal-validation failure; a bound positive cannot wash green.
    require(type(j) is dict,'result_sticky')
    independent_hit=False
    try:
        receiver=live.dns.receiver(j.get('fixture_final'),final=True)
        independent_hit=receiver['selected_query_observed'] is True
    except Exception:pass # Unknown/malformed fixture data never implies a hit.
    if j.get('selected_wire_query_observed') is True or independent_hit:
        v.update(selected_wire_query_observed=True,network_tested=True,status='failed')
    require(type(j.get('selected_wire_query_observed')) is bool,'result_sticky')
    validate_result(j,c,parent=parent)
    # Native raw observations are independently parsed and bound below. These never override receiver positivity.
    hit=j['selected_wire_query_observed'];require(type(hit) is bool,'result_sticky')
    v['selected_wire_query_observed']=hit
    v['network_tested']=hit or any(decode(r['text'].encode('ascii')).get('dns',{}).get('result',{}).get('called') is True for r in j['native'])
    for out,key in (('selected_semantic_held','selected_semantic_held'),('ordinary_before','ordinary_before'),('ordinary_after','ordinary_after'),
        ('natural_exits','natural_exits'),('fixture_cleanup','fixture_cleanup'),('workload_cleanup','workload_cleanup'),
        ('acl_removed','acl_removed'),('cleanup_tools','cleanup_tools'),('profile_deleted','profile_deleted'),('sid_released','sid_released')):
        require(type(j[key]) is bool,'result_boolean');v['checks'][out]=j[key]
    v['checks']['semantic_resources_cleanup']=j['semantic_resources_cleanup']
    v['checks']['semantic_resume_go_verified']=j['semantic_resume_go_verified']
    v['semantic_check_count']=len(j['semantic_checks'])
    v['selected_semantic_matrix']=[2,0,0,2] if j['selected_semantic_held'] else None
    cleanup=all(v['checks'][k] for k in ('guard','worker_exit','outer_cleanup','worker_bound','fixture_cleanup','workload_cleanup','acl_removed','cleanup_tools','profile_deleted','sid_released','semantic_resources_cleanup'))
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
