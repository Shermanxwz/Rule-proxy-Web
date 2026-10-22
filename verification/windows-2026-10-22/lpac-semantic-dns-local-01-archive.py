"""Read-only, source-bound identity-cell evidence reader and archive builder.

Required inputs identify an existing original public file and immutable source
commit. Nothing is inferred from a directory's recency. All 35 staged source
files must equal Git blobs before any source validator is imported. Imports
are used only for pure parsing/validation/projection. The only subprocesses
are read-only Git queries; no native API, actor, recovery, network, security
mutation, CI or experiment process is invoked. --archive is an explicit file
publication step; without it the script only validates existing evidence.
"""
from __future__ import annotations
import argparse
import ast
import copy
import hashlib
import importlib.util
import json
from pathlib import Path, PurePosixPath
import re
import stat
import subprocess

BASE=Path(__file__).resolve().parent;REPO=BASE/'Rule-proxy-Web';OUT=REPO/'verification/windows-2026-10-22'
MODULE='.github/windows_identity_lpac_semantic_dns_local.py'
SCOPE='standalone-lpac-accesscheck-standard53-dns-mechanism-v1'
SOURCE_NAMES=(
    '.github/native/windows_identity_actor.cpp','.github/native/windows_identity_dns_raw_udp.hpp',
    '.github/native/windows_identity_dns_standard_probe.hpp','.github/native/windows_identity_proxy_bridge_core.hpp',
    '.github/native/windows_identity_proxy_c_actor.cpp','.github/native/windows_identity_proxy_c_contract.hpp',
    '.github/native/windows_identity_proxy_origin_actor.cpp','.github/native/windows_identity_proxy_origin_transport.hpp',
    '.github/native/windows_identity_proxy_pipe_actor.cpp','.github/windows_dns_fixture.py',
    '.github/windows_identity_dns_cases_fixture.py','.github/windows_identity_dns_standard_inventory.ps1',
    '.github/windows_identity_lpac_dns_local.py','.github/windows_identity_model2_controller.py',
    '.github/windows_identity_model2_dns.py','.github/windows_identity_model2_dns_raw.py',
    '.github/windows_identity_model2_firewall.ps1','.github/windows_identity_model2_live.py',
    '.github/windows_identity_model2_local.py','.github/windows_identity_model2_local_probe.py',
    '.github/windows_identity_model2_maintenance.py','.github/windows_identity_ordinary_launcher.py',
    '.github/windows_identity_pipe_probe.py','.github/windows_identity_proof.py',
    '.github/windows_identity_proxy_origin_probe.py','.github/windows_identity_proxy_pipe_ac_guest.py',
    '.github/windows_identity_proxy_pipe_ac_local.py','.github/windows_identity_proxy_pipe_probe.py',
    '.github/windows_psec_compartment_smoke.py','ruleproxy/windows_app_process.py','ruleproxy/windows_runtime_pins.py',
    '.github/windows_identity_lpac_accesscheck.py','.github/windows_identity_lpac_identity_cell.py','.github/windows_identity_lpac_semantic_dns.py',MODULE)
NATIVE={
    'actorSourceSha256':'.github/native/windows_identity_proxy_c_actor.cpp',
    'originActorSha256':'.github/native/windows_identity_proxy_origin_actor.cpp',
    'identitySourceSha256':'.github/native/windows_identity_actor.cpp',
    'coreSha256':'.github/native/windows_identity_proxy_bridge_core.hpp',
    'pipeHelperSha256':'.github/native/windows_identity_proxy_pipe_actor.cpp',
    'originTransportSha256':'.github/native/windows_identity_proxy_origin_transport.hpp',
    'liveContractSha256':'.github/native/windows_identity_proxy_c_contract.hpp',
    'dnsStandardProbeSha256':'.github/native/windows_identity_dns_standard_probe.hpp',
    'dnsRawUdpSha256':'.github/native/windows_identity_dns_raw_udp.hpp'}
DIGEST=re.compile('[0-9a-f]{64}')
sha=lambda raw:hashlib.sha256(raw).hexdigest()
canonical=lambda value:(json.dumps(value,sort_keys=True,separators=(',',':'),ensure_ascii=True,allow_nan=False)+'\n').encode('ascii')
encode=lambda value:(json.dumps(value,sort_keys=True,indent=2,ensure_ascii=True,allow_nan=False)+'\n').encode('ascii')

def require(ok,code):
    if not ok:raise ValueError(code)
def digest(value):return type(value) is str and DIGEST.fullmatch(value) is not None
def metadata(raw):return dict(bytes=len(raw),sha256=sha(raw))
def checked(path,*,directory=False):
    path=Path(path).absolute()
    for part in (*reversed(path.parents),path):
        info=part.lstat();require(not stat.S_ISLNK(info.st_mode) and not getattr(info,'st_file_attributes',0)&0x400,'no_reparse_path')
    info=path.lstat();require(stat.S_ISDIR(info.st_mode) if directory else stat.S_ISREG(info.st_mode),'path_kind')
    return path.resolve(strict=True)
def bounded(path,limit=1024*1024):
    path=checked(path);size=path.stat().st_size;require(0<=size<=limit,'file_bound')
    raw=path.read_bytes();require(len(raw)==size and len(raw)<=limit,'stable_bounded_read');return raw
def decode(raw):
    def pairs(items):
        out={}
        for key,value in items:require(key not in out,'duplicate_json_key');out[key]=value
        return out
    def constant(value):raise ValueError('nonfinite_json')
    return json.loads(raw,object_pairs_hook=pairs,parse_constant=constant)
def read_git(commit,name):
    require(re.fullmatch('[0-9a-f]{40}',commit) is not None and name in SOURCE_NAMES,'git_query_input')
    result=subprocess.run(['git','show',commit+':'+name],cwd=REPO,capture_output=True)
    require(result.returncode==0 and 0<len(result.stdout)<=256*1024,'source_git_blob')
    return result.stdout
def tree(root):
    root=checked(root,directory=True);seen=[];total=0
    def visit(path,depth):
        nonlocal total
        require(depth<=12 and len(seen)<256,'owned_tree_bound');seen.append(path)
        info=path.lstat();require(not stat.S_ISLNK(info.st_mode) and not getattr(info,'st_file_attributes',0)&0x400,'owned_tree_reparse')
        if stat.S_ISDIR(info.st_mode):
            for child in sorted(path.iterdir()):visit(child,depth+1)
        else:
            require(stat.S_ISREG(info.st_mode),'owned_tree_kind');total+=info.st_size;require(total<=16*1024*1024,'owned_tree_bytes')
    visit(root,0);return seen
def locate_stage(public):
    private=checked(REPO/'private',directory=True);matches=[];entries=list(private.iterdir())
    require(len(entries)<=2048,'private_stage_inventory_bound')
    for path in entries:
        if not path.name.startswith('local-lpac-semantic-dns-'):continue
        checked(path,directory=True)
        plan=path/'recovery-plan.json'
        if plan.exists() and sha(bounded(plan,8192))==public['recovery_plan_sha256']:matches.append(path)
    require(len(matches)==1,'exactly_one_recovery_plan_bound_stage');return matches[0]

def proof_projection(proof,arm,config,access):
    # The source-bound core has already validated this against the owner's
    # independently held primary-token snapshot and generation.
    access.validate_proof(proof,expected_primary_identity=arm['expected_primary'],expected_role=arm['role'],expected_pid=arm['pid'],
        expected_creation=arm['created'],frequency=config['frequency'],deadline=config['deadline_qpc']-25*config['frequency'])
    calls=[]
    symbols={access.WORLD:'World',access.AAP:'AllApplicationPackages',access.ARAP:'AllRestrictedApplicationPackages',access.SYSTEM:'LocalSystem'}
    for call in proof['calls']:
        descriptor=call['descriptor'];symbolic=None
        if descriptor is not None:
            symbolic=dict(bytes=descriptor['bytes'],sha256=descriptor['sha256'],owner=symbols.get(descriptor['owner'],'unrecognized'),
                group=symbols.get(descriptor['group'],'unrecognized'),
                aces=[dict(principal=symbols.get(ace['sid'],'unrecognized'),type=ace['type'],flags=ace['flags'],mask=ace['mask']) for ace in descriptor['aces']])
        calls.append(dict(label=call['label'],descriptor=symbolic,descriptor_verified=call['descriptor_verified'],attempted=call['attempted'],
            api_success=call['api_success'],win32_error=call['win32_error'],access_status=call['access_status'],granted_access=call['granted_access'],
            privilege_count=call['privilege_count'],within_deadline=call['within_deadline']))
    resources=[{key:row[key] for key in ('name','kind','attempted','creation_returned','returned','close_attempted','close_confirmed','close_uncertain','alias')} for row in proof['resources']]
    return dict(role=arm['role'],canonical_private_proof_sha256=sha(canonical(proof)),generation_before=proof['generation_before'],generation_after=proof['generation_after'],
        source_primary_bound=proof['source_identity_bound'],duplicate_identification_bound=proof['duplicate_identity_bound'],
        calls=calls,resources=resources,resource_cleanup_verified=proof['resource_cleanup_verified'],observation_complete=proof['observation_complete'],
        qualified=proof['qualified'],classification=proof['classification'],failure=proof['failure'],
        error_present=proof['error'] is not None,win32_error=None if proof['error'] is None else proof['error']['win32_error'],
        token_class46_queried=proof['token_class46_queried'],process_or_thread_impersonation_applied=proof['process_or_thread_impersonation_applied'],
        network_tested=proof['network_tested'],dns_tested=proof['dns_tested'],product_acceptance=proof['product_acceptance'])

def prepare(args):
    require(digest(args.public_sha256) and re.fullmatch('[0-9a-f]{40}',args.source_commit) is not None,'explicit_input_pins')
    require(re.fullmatch('lpac-semantic-dns-[a-z0-9-]{1,64}',args.name) is not None,'archive_name')
    public_path=checked(args.public);require(OUT.resolve() in public_path.parents,'original_public_location')
    raw_public=bounded(public_path,8192);require(sha(raw_public)==args.public_sha256,'original_public_sha256')
    public=decode(raw_public);require(type(public) is dict and digest(public.get('recovery_plan_sha256')),'public_plan_commitment')
    stage=locate_stage(public);paths=tree(stage)
    raw_config=bounded(stage/'worker-config.json',512*1024);raw_report=bounded(stage/'worker-report.json',512*1024)
    config,report=decode(raw_config),decode(raw_report)
    require(type(config) is dict and type(config.get('source_hashes')) is dict and set(config['source_hashes'])==set(SOURCE_NAMES),'closed35_source_names')
    require(len(SOURCE_NAMES)==35 and config.get('scope')==SCOPE and config.get('source_sha256')==sha(canonical(config['source_hashes'])),'source_closure')
    require(type(report) is dict and set(report)=={'schema_version','stage','config','worker_pid','worker_identity','result'}
        and type(report['schema_version']) is int and report['schema_version']==1 and report['stage']=='standalone-lpac-semantic-dns-worker'
        and report['config']==config and type(report['worker_pid']) is int and report['worker_pid']>0
        and stage.name=='local-lpac-semantic-dns-'+config['run'],'private_report_config_binding')
    sources=[]
    for name in sorted(SOURCE_NAMES):
        relative=PurePosixPath(name);require(not relative.is_absolute() and '..' not in relative.parts and '\\' not in name,'source_relative_path')
        raw=bounded(stage/name,256*1024);git_raw=read_git(args.source_commit,name)
        require(raw==git_raw and sha(raw)==config['source_hashes'][name] and b'\r' not in raw,'source_exact_git_lf_bytes')
        sources.append(dict(path=name,bytes=len(raw),sha256=sha(raw),git_blob=hashlib.sha1(b'blob '+str(len(raw)).encode('ascii')+b'\0'+raw).hexdigest()))
    for path in paths:
        if path.is_file() and path.suffix.lower() in ('.py','.pyc','.pyd','.dll'):
            require(path.relative_to(stage).as_posix() in SOURCE_NAMES,'unexpected_importable_staged_file')
    # Imports below are source-pinned pure validators only. Never instantiate
    # IdentityAPI/NativeAPI, call preflight/run_local/worker or touch a socket.
    spec=importlib.util.spec_from_file_location('archive_semantic_dns_pure',stage/MODULE)
    m=importlib.util.module_from_spec(spec);spec.loader.exec_module(m)
    require(set(m.SOURCES)==set(SOURCE_NAMES) and len(m.SOURCES)==35 and m.SCOPE==SCOPE and m.core.api_version()==1,'source_bound_interface')
    files,hashes,closure=m.snapshot(stage);require(hashes==config['source_hashes'] and closure==config['source_sha256'],'source_import_readback')
    m.core.config_validate(config,source_names=m.SOURCES);m.core.validate_public(public)
    parent=report['worker_identity'];require(m.launcher.token_is_ordinary(parent),'ordinary_worker_identity')
    private=m.core.validate_result(report['result'],config,parent=parent)
    require(public['mode']=='runtime' and public['checks']['worker_bound'] and public['checks']['worker_exit'],'original_report_was_held_bound')
    require(config['root_deadline_qpc']==config['start_qpc']+120*config['frequency']
        and config['deadline_qpc']==config['root_deadline_qpc']-5*config['frequency'],'original120_115_clock')
    for key in ('source_sha256','actor_sha256','manifest_sha256','recovery_plan_sha256'):
        require(public[key]==config[key] and digest(config[key]),'original_public_config_commitment')
    plan_raw=bounded(stage/'recovery-plan.json',8192);require(sha(plan_raw)==config['recovery_plan_sha256'],'recovery_plan_raw_binding')
    m.core.plan(decode(plan_raw),device=config['device_sha256'],source=closure,actor=config['actor_sha256'],manifest=config['manifest_sha256'])
    actor_raw=bounded(stage/'inputs'/m.live.ACTOR,8*1024*1024);manifest_raw=bounded(stage/'inputs'/m.live.MANIFEST,8192);manifest=decode(manifest_raw)
    require(sha(actor_raw)==config['actor_sha256'] and actor_raw[:2]==b'MZ' and sha(manifest_raw)==config['manifest_sha256'],'native_artifact_bytes')
    require(set(manifest)=={'schemaVersion','compileOnly','runtimeAcceptance','executableSha256',*NATIVE}
        and type(manifest['schemaVersion']) is int and manifest['schemaVersion']==1 and manifest['compileOnly'] is True
        and manifest['runtimeAcceptance'] is False and manifest['executableSha256']==config['actor_sha256'],'closed13_native_manifest')
    require(m.live.NATIVE_SOURCES==NATIVE and all(manifest[key]==hashes[name] for key,name in NATIVE.items()),'native9_source_pins')
    preflight_path=Path(args.preflight) if args.preflight else public_path.with_name(public_path.name.removesuffix('-public.json')+'-preflight.json')
    preflight_raw=bounded(preflight_path,8192);preflight=m.core.validate_public(decode(preflight_raw))
    require(preflight['mode']=='preflight' and preflight['status']=='ready'
        and all(preflight[key]==public[key] for key in ('source_sha256','actor_sha256','manifest_sha256','recovery_plan_sha256')),'original_preflight_binding')

    # Retain original outer held observations without inventing a launch row.
    # Re-run the core projection completely, then apply only the exact source
    # outer-except transformation when the original public records that path.
    derived=m.core.blank('runtime')
    for key in ('source_sha256','actor_sha256','manifest_sha256','recovery_plan_sha256','tree_retained'):derived[key]=public[key]
    for key in ('ordinary','sources','artifact','plan','guard','worker_exit','outer_cleanup','worker_bound'):derived['checks'][key]=public['checks'][key]
    m.core.public_result(copy.deepcopy(private),config,derived,parent=parent)
    outer_exception=False
    if derived!=public:
        require(public['failure'] in ('report','deadline') and not public['observation_complete'] and not public['access_denial_observed'],'known_outer_exception_projection_only')
        outer_exception=True;derived['failure']=public['failure'];derived['observation_complete']=False;derived['access_denial_observed']=False
        if derived['status']=='observed':derived['status']='inconclusive'
        if derived['selected_wire_query_observed']:derived['status']='failed'
        if not all(derived['checks'][key] for key in m.RESOURCE_CHECKS):derived['recovery_required']=True
    require(m.core.validate_public(derived)==public,'complete_original_public_reprojection')

    tasks=private['tasks']+private['cleanup_tasks'];by_name={row['name']:row for row in tasks};selected=by_name.get('selected')
    tickets={(row['role'],row['fields']['sequence']):row for row in private['go']};native=[];known_native=set()
    report_directories={'selected':'lpac-report','health':'health'}
    accepted_basenames={'ready.json','phase-0001.json','phase-0002.json','final.json'}
    for row in private['native']:
        role,name=row['path'].split('/');require(role in report_directories and name in accepted_basenames,'fixed_native_report_name')
        raw=bounded(stage/report_directories[role]/name,16384)
        require(raw==row['text'].encode('ascii') and sha(raw)==row['sha256'],'native_original_text_hash_disk_binding')
        value=decode(raw);task=by_name[role];native_role='selected-client' if role=='selected' else 'health-client';boot=config[role+'_boot']
        common=dict(role=native_role,boot=boot)
        projected=dict(role=role,report=name,bytes=len(raw),sha256=sha(raw),disk_raw_bytes_equal_worker_text=True,parsed_and_bound=True)
        if name=='ready.json':m.core.contracts.ready_client(value,task,config,**common,admission=config[role+'_admission'],profile=m.core.PROFILE if role=='selected' else 'ordinary')
        elif name=='final.json':m.core.contracts.client_final(value,task,config,**common,profile=m.core.PROFILE if role=='selected' else 'ordinary',count=1 if role=='selected' else 2)
        else:
            sequence=int(name[6:10]);ticket=tickets[(role,sequence)];fields=ticket['fields']
            m.live.dns.phase(value,task,{**config,'dns_extension':{'profile':m.live.dns.PROFILE}},**common,admission=config[role+'_admission'],
                sequence=sequence,case=fields['case'],phase_deadline=fields['phase_deadline'],identity_check=m.core.contracts.native_identity)
            require(value['phase_qpc'][0]>=ticket['issued_qpc'],'phase_begins_after_issued_go')
            api=m.live.dns.api_result(value['dns']['result'])
            projected.update(label=ticket['label'],failure=value['failure'],command_closed=value['command_close_verified'],
                root_clock_and_phase_deadline_bound=True,case_nonce_and_query_name_bound=True,server_constructor=value['dns']['server_constructor'],
                server_address=value['dns']['server_address'],server_port=value['dns']['server_port'],query_type=value['dns']['query_type'],
                query_options=value['dns']['query_options'],api={key:api[key] for key in (*m.live.dns.API_BOOLS,'api_status','query_status','record_count')},
                timely=m.live.dns.timely(value),exact_positive=m.live.dns.positive(value),typed_access_observation=m.live.dns.access_denial(value))
        native.append(projected);known_native.add((role,name))
    unbound_native=[]
    for role,directory in report_directories.items():
        for path in sorted((stage/directory).iterdir()):
            if path.is_dir():require(path.name=='temp','unexpected_native_subdirectory');continue
            require(path.name in accepted_basenames,'unexpected_native_report_basename')
            if (role,path.name) not in known_native:
                require(private['failure'] is not None,'unbound_native_not_a_complete_success')
                unbound_native.append(dict(role=role,report=path.name,**metadata(bounded(path,16384)),parsed_and_bound=False,
                    disposition='raw hash retained only; absent from validated worker native ledger, never filled in as a successful report'))
    go=[];known_go=set();control_directories={'selected':'lpac-control','health':'health-control'}
    for row in private['go']:
        role=row['role'];fields=row['fields'];name='phase-%04d.bin'%fields['sequence'];raw=bounded(stage/control_directories[role]/name,128)
        require(len(raw)==128 and sha(raw)==row['sha256'] and raw==m.live.go_record(**fields),'go128_exact_disk_binary_nonce_clock_binding')
        go.append(dict(role=role,label=row['label'],sequence=fields['sequence'],opcode=fields['opcode'],bytes=128,sha256=sha(raw),
            nonce_admission_ports_original_clock_bound=True,semantic_authorization_bound=role=='selected' or fields['opcode']==6))
        known_go.add((role,name))
    unbound_go=[]
    for role,directory in control_directories.items():
        for path in sorted((stage/directory).iterdir()):
            require(path.is_file() and re.fullmatch('phase-000[123]\\.bin',path.name) is not None,'fixed_control_member')
            if (role,path.name) not in known_go:
                require(private['failure'] is not None,'unbound_go_not_a_complete_success')
                unbound_go.append(dict(role=role,command=path.name,**metadata(bounded(path,128)),validated_ledger_ticket=False))

    inventory=None;gates=[]
    if private['inventory'] is not None:
        row=private['inventory'];raw=row['text'].encode('ascii');require(sha(raw)==row['sha256'] and raw==bounded(stage/'tools/inventory/stdout',32768),'inventory_original_stdout_hash')
        value=decode(raw);require(row['pid']==by_name['inventory']['pid'],'inventory_held_helper_binding')
        inventory=dict(raw_stdout=metadata(raw),held_ordinary_helper_bound=True,read_only=value['read_only'],dns_server_count=len(value['dns_servers']),
            effective_nrpt_count=value['effective_nrpt_count'],udp53_count=value['udp53_count'],tcp53_count=value['tcp53_count'],addresses_published=False)
        for gate in private['inventory_gates']:
            m.live.dns.inventory(value,run=config['inventory_run'],pid=by_name['inventory']['pid'],frequency=config['frequency'],start=config['start_qpc'],deadline=config['deadline_qpc'],now=gate['qpc'])
            gates.append(dict(label=gate['label'],original_epoch_bound=True,maximum_age_seconds=5,
                observed_age_milliseconds=round((gate['qpc']-value['end_qpc'])*1000/config['frequency'],6),fresh=True))
    else:require(private['inventory_gates']==[],'no_synthetic_inventory_gates')
    receiver=None
    if private['fixture_final'] is not None:
        receiver=copy.deepcopy(m.live.dns.receiver(private['fixture_final'],final=True))
        require(not receiver['selected_query_observed'] or private['selected_wire_query_observed'],'independent_receiver_sticky_binding')
    require(not private['selected_wire_query_observed'] or public['selected_wire_query_observed'] and public['status']=='failed','receiver_positive_never_reclassified')

    semantic=[];semantic_directory=stage/'semantic-intents';known_semantic=set()
    for row in private['semantic_checks']:
        name='%04d.json'%row['sequence'];raw=bounded(semantic_directory/name,4096)
        require(raw==row['intent_text'].encode('ascii') and sha(raw)==row['intent_sha256'],'semantic_intent_original_disk_text_hash')
        proof=None
        if row['proof'] is not None:
            require(selected is not None and private['selected_primary'] is not None,'semantic_proof_prior')
            arm=dict(role='lpac',expected_primary=private['selected_primary'],pid=selected['pid'],created=selected['created'])
            proof=proof_projection(row['proof'],arm,config,m.core.access)
        semantic.append(dict(sequence=row['sequence'],purpose=row['purpose'],intent=metadata(raw),held_before_available=True,
            held_after_verified=row['held_after_qpc'] is not None,proof=proof))
        known_semantic.add(name)
    unbound_semantic=[]
    if semantic_directory.exists():
        for path in sorted(checked(semantic_directory,directory=True).iterdir()):
            require(path.is_file() and re.fullmatch('[0-9]{4}\\.json',path.name) is not None,'fixed_semantic_intent_member')
            if path.name not in known_semantic:
                require(private['failure'] is not None,'unbound_semantic_not_a_complete_success')
                unbound_semantic.append(dict(sequence=int(path.stem),**metadata(bounded(path,4096)),validated_observer_record=False))
    authorizations=[dict(kind=row['kind'],label=row['label'],proof_sequence=row['proof_sequence'],go_sha256=row['go_sha256'],
        prior_qualified_held_proof_bound=True,original_issue_clock_bound=True) for row in private['semantic_authorizations']]
    intents=[];journal=stage/'journal';last=config['start_qpc'];actions=[]
    allowed={'profile-create','acl-grant','spawn-grant-root','spawn-grant-inputs','spawn-grant-lpac-report','spawn-grant-lpac-control',
        'spawn-selected','spawn-health','spawn-inventory','go-before','go-selected','go-after','finish-selected','finish-health','acl-remove','spawn-remove','profile-delete'}
    stored=[] if not journal.exists() else sorted(checked(journal,directory=True).iterdir());require(len(stored)<=48,'journal_bound')
    for index,path in enumerate(stored):
        raw=bounded(path,4096);value=decode(raw)
        require(type(value) is dict and set(value)=={'run','frequency','deadline','source_sha256','qpc','action'}
            and value['run']==config['run'] and value['frequency']==config['frequency'] and value['deadline']==config['deadline_qpc']
            and value['source_sha256']==closure and value['action'] in allowed and value['action'] not in actions
            and path.name=='%02d-%s.json'%(index,value['action']) and type(value['qpc']) is int and last<=value['qpc']<config['deadline_qpc'],'ordinary_ownership_intent_binding')
        last=value['qpc'];actions.append(value['action']);intents.append(dict(action=value['action'],**metadata(raw)))
    require(not private['profile_created'] or 'profile-create' in actions,'profile_intent_present')
    require(not private['acl_attempted'] or 'acl-grant' in actions,'acl_intent_present')
    require(not private['profile_created'] or not private['profile_deleted'] or 'profile-delete' in actions,'delete_intent_present')
    streams=[]
    for component,names,required in [('guard',('controller.stdin','controller.stdout','controller.stderr'),True),
            *[('tools/'+row['name'],('stdin','stdout','stderr'),row['attempted'] or row['process_returned']) for row in tasks if row['name'] not in ('selected','health')]]:
        for name in names:
            path=stage/component/name
            if path.exists():streams.append(dict(component=component,stream=name,observed=True,**metadata(bounded(path,256*1024))))
            else:require(not required,'missing_attempted_tool_stdio');streams.append(dict(component=component,stream=name,observed=False,bytes=None,sha256=None))
    task_projection=[]
    for row in tasks:
        observation=row['create_observation']
        task_projection.append(dict(role=row['name'],constructor_attempted=row['attempted'],create_return=observation['status'],create_win32_error=observation['winerror'],
            process_information=observation['process_information'],create_return_timely=type(observation['returned_qpc']) is int
                and config['start_qpc']<=observation['returned_qpc']<observation['work_cutoff'],
            process_returned=row['process_returned'],generation_available=row['pid'] is not None and row['created'] is not None,
            assigned=row['assigned'],held_admitted=row['admitted'],resumed=row['resumed'],exited=row['exited'],exit_code=row['exit_code'],
            natural_exit=bool(row['resumed'] and row['exited'] and row['exit_code']==0),known_no_child=m.base.known_no_child(row,start=config['start_qpc']),
            image_sha256=row['image_sha256'],capability_count=None if row['capabilities'] is None else len(row['capabilities']),
            class46_queried=False,lpac_readback=row['lpac']))
    global_projection=dict(observed=False,before=None,after=None,raw_bytes_identical=None,whole_json_objects_equal=None,
        comparison_scope='Optional separate point-in-time four-configuration-object capture; no current-state, NRPT, isolation or broker assertion.')
    require(bool(args.before_global)==bool(args.after_global),'paired_global_inputs')
    if args.before_global:
        before=bounded(Path(args.before_global),262144);after=bounded(Path(args.after_global),262144)
        before_value,after_value=decode(before),decode(after);require(type(before_value) is dict and type(after_value) is dict,'global_objects')
        global_projection.update(observed=True,before=metadata(before),after=metadata(after),raw_bytes_identical=before==after,whole_json_objects_equal=before_value==after_value)
    private_values=[config[name] for name in m.NONCES]+[config['device_sha256'],private['profile_name'],private['profile_sid'],parent['sid'],str(stage),*config['capability_catalog'].values()]
    for detail in [private['failure_detail'],*(row['create_observation']['exception_detail'] for row in tasks)]:
        if detail is not None and len(detail['message'])>=16:private_values.append(detail['message'])
    raw_ids=[report['worker_pid'],*(row['pid'] for row in tasks if row['pid'] is not None)]
    def safe(raw):
        require(all(value.encode('utf8') not in raw for value in private_values if type(value) is str and value),'private_identifier_in_projection')
        text=raw.decode('utf8');require(not re.search(r'\bS-\d+(?:-\d+){2,}\b',text,re.I),'raw_sid_in_projection')
        require(not re.search(r'(?i)\b[A-Z]:[\\/]',text),'machine_absolute_path_in_projection')
        require(all(not re.search(r'(?<![A-Za-z0-9])'+str(value)+r'(?![A-Za-z0-9])',text) for value in raw_ids),'raw_process_id_in_projection')
    planned={}
    def add(suffix,value,*,raw=False):
        path=OUT/(args.name+'-'+suffix);data=value if raw else encode(value);safe(data);planned[path]=data;return path
    add('public.json',raw_public,raw=True);add('preflight.json',preflight_raw,raw=True)
    if args.runner:add('runner.py',bounded(Path(args.runner),128*1024),raw=True)
    for option,suffix in ((args.global_capture,'after-global-capture.ps1'),(args.global_expanded,'after-global-expanded.ps1')):
        if option:add(suffix,bounded(Path(option),128*1024),raw=True)
    add('archive.py',bounded(Path(__file__),128*1024),raw=True)
    detail=private['failure_detail'];detail_projection=dict(present=detail is not None,canonical_private_sha256=None if detail is None else sha(canonical(detail)),raw_type_operation_message_published=False)
    snapshot_contract_error=False
    expected_snapshot_message="{}.{}() missing {} required keyword-only argument: {!r}".format('DnsCasesFixture','snapshot',1,'deadline')
    if detail is not None and detail['type']=='TypeError' and detail['message']==expected_snapshot_message:
        owner_ast=ast.parse(files['.github/windows_identity_lpac_dns_local.py'].decode('utf8'))
        fixture_ast=ast.parse(files['.github/windows_identity_dns_cases_fixture.py'].decode('utf8'))
        execute=next(node for cls in owner_ast.body if isinstance(cls,ast.ClassDef) and cls.name=='Owner'
            for node in cls.body if isinstance(node,ast.FunctionDef) and node.name=='execute')
        missing_calls=[node for node in ast.walk(execute) if isinstance(node,ast.Call) and isinstance(node.func,ast.Attribute)
            and node.func.attr=='snapshot' and isinstance(node.func.value,ast.Attribute) and node.func.value.attr=='fixture'
            and isinstance(node.func.value.value,ast.Name) and node.func.value.value.id=='self' and not node.args and not node.keywords]
        snapshot=next(node for cls in fixture_ast.body if isinstance(cls,ast.ClassDef) and cls.name=='DnsCasesFixture'
            for node in cls.body if isinstance(node,ast.FunctionDef) and node.name=='snapshot')
        required_deadline=any(arg.arg=='deadline' and default is None for arg,default in zip(snapshot.args.kwonlyargs,snapshot.args.kw_defaults))
        require(bool(missing_calls) and required_deadline,'typed_snapshot_error_matches_pinned_source_contract')
        snapshot_contract_error=True
    detail_projection.update(snapshot_required_deadline_typeerror_observed=snapshot_contract_error,
        pinned_call_and_keyword_only_contract_checked=snapshot_contract_error)
    before_native_positive=any(row.get('label')=='before' and row.get('exact_positive') is True for row in native)
    before_receiver_positive=receiver is not None and m.live.dns.case_positive(receiver,'before')
    after_native_positive=any(row.get('label')=='after' and row.get('exact_positive') is True for row in native)
    after_receiver_positive=receiver is not None and m.live.dns.case_positive(receiver,'after')
    selected_dns_phase_present=any(row.get('label')=='selected' for row in native)
    cleanup=all(public['checks'][key] for key in m.RESOURCE_CHECKS)
    add('component-projection.json',dict(schema_version=1,stage='standalone-semantic-lpac-dns-private-safe-projection',scope=SCOPE,identity_basis=config['identity_basis'],
        source_commit=args.source_commit,source_sha256=closure,source_files_verified=35,source_files=sources,native_source_pin_count=9,manifest_key_count=13,
        private_config=metadata(raw_config),private_worker_report=metadata(raw_report),private_recovery_plan=metadata(plan_raw),
        raw_source_bytes_equal_git=True,public_completely_reprojected=True,known_outer_exception_projection=outer_exception,
        outer_binding_limit='Outer held image/token/Job/exit checks are retained from the source-bound original public. No synthetic outer launch ledger is created.',
        task_observations=task_projection,ordinary_intents=intents,semantic_checks=semantic,semantic_authorizations=authorizations,
        native_reports=native,go_commands=go,inventory=inventory,inventory_gates=gates,receiver=receiver,
        ordinary_before_bound_native_positive=before_native_positive,ordinary_before_independent_receiver_positive=before_receiver_positive,
        original_ordinary_before_flag=private['ordinary_before'],original_flags_never_filled_from_later_analysis=True,
        receiver_binding='Independent in-process fixture counters/events use the three fixed config nonce cases; no raw packet capture or sender-PID attribution is asserted.',
        unbound_native_reports=unbound_native,unbound_go_files=unbound_go,unbound_semantic_intents=unbound_semantic,
        missing_or_invalid_facts_never_filled=True,stdio_files=streams,failure_detail=detail_projection,
        environment_metadata=private['child_environment'],environment_values_or_paths_published=False,
        original_root_seconds=120,worker_seconds=115,original_cleanup_confirmed=cleanup,original_recovery_required=public['recovery_required'],
        raw_proofs_worker_logs_or_private_identity_published=False,token_class46_queried=False,
        dns_isolation_qualified=False,g_psec_tested=False,proxy_tested=False,product_acceptance=False,broker_pid_attributed=False,broker_cancellation_proven=False))
    add('global-projection.json',global_projection)
    add('summary.json',dict(schema_version=1,stage='standalone-semantic-lpac-dns-actual01-summary',scope=SCOPE,identity_basis=config['identity_basis'],attempt=1,
        source_commit=args.source_commit,source_sha256=closure,source_files_verified=35,source_git_blob_bytes_verified=True,
        actor_sha256=config['actor_sha256'],manifest_sha256=config['manifest_sha256'],native_source_pin_count=9,manifest_key_count=13,
        original_public=metadata(raw_public),private_worker_report=metadata(raw_report),private_config=metadata(raw_config),
        original_status=public['status'],original_failure=public['failure'],observation_complete=public['observation_complete'],
        selected_semantic_held=public['checks']['selected_semantic_held'],semantic_check_count=public['semantic_check_count'],
        selected_semantic_matrix=public['selected_semantic_matrix'],selected_api=public['selected_api'],
        selected_wire_query_observed=public['selected_wire_query_observed'],network_tested=public['network_tested'],access_denial_observed=public['access_denial_observed'],
        ordinary_before_verified=public['checks']['ordinary_before'],ordinary_after_verified=public['checks']['ordinary_after'],
        ordinary_before_bound_native_positive=before_native_positive,ordinary_before_independent_receiver_positive=before_receiver_positive,
        ordinary_after_bound_native_positive=after_native_positive,ordinary_after_independent_receiver_positive=after_receiver_positive,
        original_ordinary_before_flag=private['ordinary_before'],original_ordinary_after_flag=private['ordinary_after'],
        snapshot_required_deadline_typeerror_observed=snapshot_contract_error,original_flags_never_filled_from_later_analysis=True,
        selected_dns_phase_present=selected_dns_phase_present,original_selected_api=public['selected_api'],
        actors_exited_from_owned_cleanup=sum(row['name'] in ('selected','health') and row['exited'] and private['workload_stop'] for row in tasks),
        actors_natural_exit_zero=sum(row['name'] in ('selected','health') and row['resumed'] and row['exited'] and row['exit_code']==0 for row in tasks),
        inventory_gate_count=len(gates),native_report_count=len(native),expected_full_native_report_count=7,go_count=len(go),expected_full_go_count=5,
        receiver_counts_available=receiver is not None and receiver['counts'] is not None,receiver=receiver,
        automatic_cleanup_confirmed=cleanup,recovery_required=public['recovery_required'],separate_recovery_not_inferred=True,
        global_after_capture_available=global_projection['observed'],global_configuration_byte_equal=global_projection['raw_bytes_identical'],
        token_class46_queried=False,no_earlier_attempt_reinterpretation=True,no_psec_repair_or_causal_dns_claim=True,
        g_psec_tested=False,proxy_tested=False,product_acceptance=False,dns_isolation_qualified=False,default_resolver_tested=False,
        broker_pid_attributed=False,broker_cancellation_proven=False))
    indexed=[dict(path=path.relative_to(REPO).as_posix(),**metadata(raw)) for path,raw in planned.items()]
    add('evidence-index.json',dict(schema_version=1,stage='standalone-semantic-lpac-dns-actual01-evidence-index',scope=SCOPE,
        source_commit=args.source_commit,source_sha256=closure,original_public_sha256=args.public_sha256,files=indexed,index_self_hash_excluded=True,
        private_stage_or_logs_published=False,archive_process_experiment_run=False,native_api_instantiated=False,network_operation_run=False,policy_or_recovery_run=False))
    require(bounded(public_path,8192)==raw_public and bounded(stage/'worker-report.json',512*1024)==raw_report
        and bounded(stage/'worker-config.json',512*1024)==raw_config,'original_evidence_unchanged')
    return planned,dict(verified=True,source_commit=args.source_commit,source_files_verified=35,native_source_pin_count=9,manifest_key_count=13,
        original_status=public['status'],observation_complete=public['observation_complete'],selected_wire_query_observed=public['selected_wire_query_observed'],
        semantic_check_count=len(semantic),native_report_count=len(native),go_count=len(go),cleanup_confirmed=cleanup,recovery_required=public['recovery_required'],
        global_after_capture_available=global_projection['observed'],native_api_or_experiment_run=False)

def main(argv=None):
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--public',type=Path,required=True);parser.add_argument('--public-sha256',required=True);parser.add_argument('--source-commit',required=True)
    parser.add_argument('--name',default='lpac-semantic-dns-local-01');parser.add_argument('--preflight',type=Path);parser.add_argument('--runner',type=Path)
    parser.add_argument('--before-global',type=Path);parser.add_argument('--after-global',type=Path)
    parser.add_argument('--global-capture',type=Path);parser.add_argument('--global-expanded',type=Path);parser.add_argument('--archive',action='store_true')
    args=parser.parse_args(argv);planned,result=prepare(args)
    if args.archive:
        checked(OUT,directory=True)
        for path,raw in planned.items():
            if path.exists():require(bounded(path,4*1024*1024)==raw,'refuse_changed_existing_archive')
        for path,raw in planned.items():
            if not path.exists():
                with path.open('xb') as stream:require(stream.write(raw)==len(raw),'archive_write')
                require(bounded(path,4*1024*1024)==raw,'archive_readback')
        path=BASE/'stage_lpac_semantic_dns_01_paths.txt';raw=''.join(p.relative_to(REPO).as_posix()+'\n' for p in planned).encode('ascii')
        if path.exists():require(bounded(path)==raw,'existing_explicit_path_list')
        else:
            with path.open('xb') as stream:require(stream.write(raw)==len(raw),'explicit_path_list')
    print(json.dumps(result|dict(archive_written=args.archive,archive_files=len(planned)),sort_keys=True))
if __name__=='__main__':main()

