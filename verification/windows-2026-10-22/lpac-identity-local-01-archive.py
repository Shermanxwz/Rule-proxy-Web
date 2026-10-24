"""Read-only, source-bound identity-cell evidence reader and archive builder.

Required inputs identify an existing original public file and immutable source
commit. Nothing is inferred from a directory's recency. All 34 staged source
files must equal Git blobs before any source validator is imported. Imports
are used only for pure parsing/validation/projection. The only subprocesses
are read-only Git queries; no native API, actor, recovery, network, security
mutation, CI or experiment process is invoked. --archive is an explicit file
publication step; without it the script only validates existing evidence.
"""
from __future__ import annotations
import argparse
import copy
import hashlib
import importlib.util
import json
from pathlib import Path, PurePosixPath
import re
import stat
import subprocess

BASE=Path(__file__).resolve().parent;REPO=BASE/'Rule-proxy-Web';OUT=REPO/'verification/windows-2026-10-22'
MODULE='.github/windows_identity_lpac_identity_local.py'
SCOPE='one-local-matched-ac-lpac-semantic-identity-no-network-v1'
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
    '.github/windows_identity_lpac_accesscheck.py','.github/windows_identity_lpac_identity_cell.py',MODULE)
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
        if not path.name.startswith('local-lpac-identity-'):continue
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
            symbolic=dict(bytes=descriptor['bytes'],sha256=descriptor['sha256'],owner='LocalSystem',group='LocalSystem',
                aces=[dict(principal=symbols[ace['sid']],type=ace['type'],flags=ace['flags'],mask=ace['mask']) for ace in descriptor['aces']])
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
    require(re.fullmatch('lpac-identity-[a-z0-9-]{1,64}',args.name) is not None,'archive_name')
    public_path=checked(args.public);require(OUT.resolve() in public_path.parents,'original_public_location')
    raw_public=bounded(public_path,8192);require(sha(raw_public)==args.public_sha256,'original_public_sha256')
    public=decode(raw_public);require(type(public) is dict and digest(public.get('recovery_plan_sha256')),'public_plan_commitment')
    stage=locate_stage(public);paths=tree(stage)
    raw_config=bounded(stage/'worker-config.json',512*1024);raw_report=bounded(stage/'worker-report.json',512*1024)
    config,report=decode(raw_config),decode(raw_report)
    require(type(config) is dict and type(config.get('source_hashes')) is dict and set(config['source_hashes'])==set(SOURCE_NAMES),'closed34_source_names')
    require(config.get('scope')==SCOPE and config.get('source_sha256')==sha(canonical(config['source_hashes'])),'source_closure')
    require(type(report) is dict and set(report)=={'schema_version','stage','config','worker_pid','worker_identity','result'}
        and type(report['schema_version']) is int and report['schema_version']==1 and report['stage']=='matched-ac-lpac-identity-worker'
        and report['config']==config and type(report['worker_pid']) is int and report['worker_pid']>0
        and stage.name=='local-lpac-identity-'+config['run'],'private_report_config_binding')
    sources=[]
    for name in sorted(SOURCE_NAMES):
        relative=PurePosixPath(name);require(not relative.is_absolute() and '..' not in relative.parts and '\\' not in name,'source_relative_path')
        raw=bounded(stage/name,256*1024);git_raw=read_git(args.source_commit,name)
        require(raw==git_raw and sha(raw)==config['source_hashes'][name] and b'\r' not in raw,'source_exact_git_lf_bytes')
        blob=hashlib.sha1(b'blob '+str(len(raw)).encode('ascii')+b'\0'+raw).hexdigest()
        sources.append(dict(path=name,bytes=len(raw),sha256=sha(raw),git_blob=blob))
    # No unpinned Python/importable binary may enter the validator import tree.
    for path in paths:
        if path.is_file() and path.suffix.lower() in ('.py','.pyc','.pyd','.dll'):
            require(path.relative_to(stage).as_posix() in SOURCE_NAMES,'unexpected_importable_staged_file')
    spec=importlib.util.spec_from_file_location('archive_matched_identity_pure',stage/MODULE)
    m=importlib.util.module_from_spec(spec);spec.loader.exec_module(m)
    require(set(m.SOURCES)==set(SOURCE_NAMES) and len(m.SOURCES)==34 and m.SCOPE==SCOPE and m.core.api_version()==1,'source_bound_interface')
    files,hashes,closure=m.snapshot(stage);require(hashes==config['source_hashes'] and closure==config['source_sha256'],'source_import_readback')
    m.core.config_validate(config,source_names=m.SOURCES);m.validate_public(public)
    parent=report['worker_identity'];require(m.launcher.token_is_ordinary(parent),'ordinary_worker_identity')
    private=m.core.validate_result(report['result'],config,parent=parent);projected=m.core.project(copy.deepcopy(private),config,parent=parent)
    m.validate_observation(projected)
    require(public['mode']=='runtime' and public['identity_observation']==projected
        and public['checks']['inner_complete']==projected['inner_complete'],'independent_identity_projection')
    require(public['checks']['worker_bound'] and public['checks']['worker_exit'],'original_report_was_held_bound')
    require(config['root_deadline_qpc']==config['start_qpc']+120*config['frequency']
        and config['deadline_qpc']==config['root_deadline_qpc']-5*config['frequency'],'original120_115_clock')
    for key in ('source_sha256','actor_sha256','manifest_sha256','recovery_plan_sha256'):
        require(public[key]==config[key] and digest(config[key]),'original_public_config_commitment')
    plan_raw=bounded(stage/'recovery-plan.json',8192);require(sha(plan_raw)==config['recovery_plan_sha256'],'recovery_plan_raw_binding')
    m.core.validate_plan(decode(plan_raw),device=config['device_sha256'],source=closure,actor=config['actor_sha256'],manifest=config['manifest_sha256'])
    actor_raw=bounded(stage/'inputs'/m.live.ACTOR,8*1024*1024);manifest_raw=bounded(stage/'inputs'/m.live.MANIFEST,8192);manifest=decode(manifest_raw)
    require(sha(actor_raw)==config['actor_sha256'] and actor_raw[:2]==b'MZ' and sha(manifest_raw)==config['manifest_sha256'],'native_artifact_bytes')
    require(set(manifest)=={'schemaVersion','compileOnly','runtimeAcceptance','executableSha256',*NATIVE}
        and type(manifest['schemaVersion']) is int and manifest['schemaVersion']==1 and manifest['compileOnly'] is True
        and manifest['runtimeAcceptance'] is False and manifest['executableSha256']==config['actor_sha256'],'closed13_native_manifest')
    require(m.live.NATIVE_SOURCES==NATIVE and all(manifest[key]==hashes[name] for key,name in NATIVE.items()),'native9_source_pins')
    preflight_path=Path(args.preflight) if args.preflight else public_path.with_name(public_path.name.removesuffix('-public.json')+'-preflight.json')
    preflight_raw=bounded(preflight_path,8192);preflight=m.validate_public(decode(preflight_raw))
    require(preflight['mode']=='preflight' and preflight['status']=='ready'
        and all(preflight[key]==public[key] for key in ('source_sha256','actor_sha256','manifest_sha256','recovery_plan_sha256')),'original_preflight_binding')
    tasks=private['tasks']+private['cleanup_tasks'];by_name={row['name']:row for row in tasks};arms={role:by_name[role] for role in ('ac','lpac') if role in by_name}
    require(all(not row['resumed'] and row['resume_qpc'] is None and row['go_qpc']==[] for row in arms.values()),'both_actors_remained_suspended')
    proofs=[proof_projection(proof,arms[proof['expected_role']],config,m.core.access) for proof in private['proofs']]
    intents=[];journal=stage/'journal';stored=[] if not journal.exists() else sorted(checked(journal,directory=True).iterdir())
    require([path.name for path in stored]==[row['name'] for row in private['intents']],'exact_disk_journal_members')
    for path,row in zip(stored,private['intents']):
        raw=bounded(path,4096);require(raw==row['text'].encode('ascii') and sha(raw)==row['sha256'],'intent_raw_text_hash_readback')
        value=decode(raw);intents.append(dict(action=value['action'],bytes=len(raw),sha256=sha(raw)))
    streams=[]
    for component,names,required in [('guard',('controller.stdin','controller.stdout','controller.stderr'),True),
            *[('tools/'+row['name'],('stdin','stdout','stderr'),row['attempted'] or row['process_returned']) for row in tasks if row['name'] not in ('ac','lpac')]]:
        for name in names:
            path=stage/component/name
            if path.exists():raw=bounded(path,256*1024);streams.append(dict(component=component,stream=name,observed=True,**metadata(raw)))
            else:require(not required,'missing_attempted_tool_stdio');streams.append(dict(component=component,stream=name,observed=False,bytes=None,sha256=None))
    task_projection=[]
    for row in tasks:
        arm=row['name'] in ('ac','lpac');observation=row['create_observation']
        task_projection.append(dict(role=row['name'],constructor_attempted=row['attempted'],create_return=observation['status'],create_win32_error=observation['winerror'],
            process_information=observation['process_information'],create_return_timely=type(observation['returned_qpc']) is int
                and config['start_qpc']<=observation['returned_qpc']<observation['work_cutoff'],
            process_returned=row['process_returned'],generation_available=row['pid'] is not None and row['created'] is not None,
            assigned=row['assigned'],held_admitted=row['admitted'],resumed=row['resumed'],exited=row['exited'],exit_code=row['exit_code'],
            natural_exit=bool(not arm and row['resumed'] and row['exited'] and row['exit_code']==0),
            cleanup_stop_exit=bool(arm and row['exited'] and private['workload_stop']),known_no_child=m.base.known_no_child(row,start=config['start_qpc']),
            image_sha256=row['image_sha256'],capability_count=None if row['capabilities'] is None else len(row['capabilities']),
            class46_queried=False,lpac_readback=row['lpac'],held_generation_checks=len(row['held_checks']),
            policy=None if not arm else row['policy']))
    cleanup=all(public['checks'][key] for key in ('guard','worker_exit','outer_cleanup','worker_bound')) and all(projected[key] for key in
        ('observer_resources_cleanup_verified','workload_cleanup','workload_job_empty','acl_removed','cleanup_tools','profile_deleted','sid_released'))
    require(public['recovery_required']==(not cleanup),'cleanup_public_reprojection')
    expected_complete=all(public['checks'].values()) and public['failure'] is None and cleanup
    require(public['observation_complete']==expected_complete,'completion_public_reprojection')
    global_projection=dict(observed=False,before=None,after=None,raw_bytes_identical=None,whole_json_objects_equal=None,
        comparison_scope='Optional separate point-in-time four-configuration-object capture; no current-state or NRPT/isolation assertion.')
    require(bool(args.before_global)==bool(args.after_global),'paired_global_inputs')
    if args.before_global:
        before=bounded(Path(args.before_global),262144);after=bounded(Path(args.after_global),262144)
        before_value,after_value=decode(before),decode(after);require(type(before_value) is dict and type(after_value) is dict,'global_objects')
        require(set(before_value)==set(after_value)=={'schema_version','stage','firewall_profiles','dns','routes','user_proxy'},'global_closed_four_objects')
        global_projection.update(observed=True,before=metadata(before),after=metadata(after),raw_bytes_identical=before==after,whole_json_objects_equal=before_value==after_value)
        global_projection['nrpt_in_snapshot']=False
    private_values=[config[name] for name in m.NONCES]+[config['device_sha256'],private['profile_name'],private['profile_sid'],parent['sid'],str(stage),*config['capability_catalog'].values()]
    raw_ids=[report['worker_pid'],*(row['pid'] for row in tasks if row['pid'] is not None)]
    def safe(raw):
        require(all(value.encode('utf8') not in raw for value in private_values if type(value) is str and value),'private_identifier_in_projection')
        text=raw.decode('utf8');require(not re.search(r'\bS-\d+(?:-\d+){2,}\b',text,re.I),'raw_sid_in_projection')
        require(not re.search(r'(?i)\b[A-Z]:[\\/]',text),'machine_absolute_path_in_projection')
        require(all(not re.search(r'(?<![A-Za-z0-9])'+str(value)+r'(?![A-Za-z0-9])',text) for value in raw_ids),'raw_process_id_in_projection')
    planned={}
    def add(suffix,value,*,raw=False):
        path=OUT/(args.name+'-'+suffix);data=value if raw else encode(value);safe(data);planned[path]=data;return path
    # Keep the original public bytes, never canonicalize them into a new claim.
    add('public.json',raw_public,raw=True);add('preflight.json',preflight_raw,raw=True)
    if args.runner:add('runner.py',bounded(Path(args.runner),128*1024),raw=True)
    require(bool(args.global_capture)==bool(args.global_expanded),'paired_capture_scripts')
    if args.global_capture:
        require(global_projection['observed'],'capture_scripts_require_snapshot')
        add('after-global-capture.ps1',bounded(Path(args.global_capture),32768),raw=True)
        add('after-global-expanded.ps1',bounded(Path(args.global_expanded),32768),raw=True)
    add('archive.py',bounded(Path(__file__),128*1024),raw=True)
    detail=private['failure_detail'];detail_projection=dict(present=detail is not None,canonical_private_sha256=None if detail is None else sha(canonical(detail)),raw_type_operation_message_published=False)
    add('component-projection.json',dict(schema_version=1,stage='matched-ac-lpac-identity-private-safe-projection',scope=SCOPE,
        source_commit=args.source_commit,source_sha256=closure,source_files_verified=34,source_files=sources,native_source_pin_count=9,manifest_key_count=13,
        private_config=metadata(raw_config),private_worker_report=metadata(raw_report),private_recovery_plan=metadata(plan_raw),
        raw_source_bytes_equal_git=True,identity_observation=projected,task_observations=task_projection,proofs=proofs,intents=intents,stdio_files=streams,
        failure_detail=detail_projection,environment_metadata=private['child_environment'],environment_values_or_paths_published=False,
        profile_state=private['profile_state'],original_root_seconds=120,worker_seconds=115,original_cleanup_confirmed=cleanup,
        public_identity_projection_independently_recomputed=True,public_cleanup_and_completion_recomputed=True,
        original_outer_held_checks_preserved=True,independent_outer_launch_ledger_available=False,
        outer_binding_limit='Outer held image/token/Job/exit claims are source-bound original public checks. No synthetic launch ledger is created to replay them.',
        raw_proofs_worker_logs_or_private_identity_published=False,actor_resumed=False,token_class46_queried=False,
        dns_tested=False,network_tested=False,g_psec_tested=False,proxy_tested=False,product_acceptance=False))
    add('global-projection.json',global_projection)
    add('summary.json',dict(schema_version=1,stage='matched-ac-lpac-identity-actual01-summary',scope=SCOPE,attempt=1,
        source_commit=args.source_commit,source_sha256=closure,source_files_verified=34,source_git_blob_bytes_verified=True,
        actor_sha256=config['actor_sha256'],manifest_sha256=config['manifest_sha256'],native_source_pin_count=9,manifest_key_count=13,
        original_public=metadata(raw_public),private_worker_report=metadata(raw_report),private_config=metadata(raw_config),
        original_status=public['status'],original_failure=public['failure'],identity_observation=projected,
        observation_complete=public['observation_complete'],original_recovery_required=public['recovery_required'],automatic_cleanup_confirmed=cleanup,
        both_actor_roles_observed=len(arms)==2,held_pair_proof_count=len(proofs),actor_resumed=False,actor_code_executed=False,token_class46_queried=False,
        ordinary_tools_natural_exit_zero=sum(row['name'] not in ('ac','lpac') and row['resumed'] and row['exited'] and row['exit_code']==0 for row in tasks),
        global_after_capture_available=global_projection['observed'],global_configuration_byte_equal=global_projection['raw_bytes_identical'],
        separate_recovery_not_inferred=True,no_earlier_attempt_reinterpretation=True,no_network_or_psec_repair_or_causal_dns_claim=True,
        dns_tested=False,network_tested=False,g_psec_tested=False,proxy_tested=False,product_acceptance=False,dns_isolation_qualified=False,
        broker_pid_attributed=False,broker_cancellation_proven=False))
    indexed=[dict(path=path.relative_to(REPO).as_posix(),**metadata(raw)) for path,raw in planned.items()]
    add('evidence-index.json',dict(schema_version=1,stage='matched-ac-lpac-identity-actual01-evidence-index',scope=SCOPE,
        source_commit=args.source_commit,source_sha256=closure,original_public_sha256=args.public_sha256,files=indexed,
        index_self_hash_excluded=True,private_stage_or_logs_published=False,
        archive_process_experiment_run=False,native_api_instantiated=False,network_operation_run=False,policy_or_recovery_run=False))
    require(bounded(public_path,8192)==raw_public and bounded(stage/'worker-report.json',512*1024)==raw_report
        and bounded(stage/'worker-config.json',512*1024)==raw_config,'original_evidence_unchanged')
    return planned,dict(verified=True,source_commit=args.source_commit,source_files_verified=34,native_source_pin_count=9,manifest_key_count=13,
        original_status=public['status'],observation_complete=public['observation_complete'],proof_count=len(proofs),cleanup_confirmed=cleanup,
        recovery_required=public['recovery_required'],global_after_capture_available=global_projection['observed'],native_api_or_experiment_run=False)

def main(argv=None):
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--public',type=Path,required=True);parser.add_argument('--public-sha256',required=True);parser.add_argument('--source-commit',required=True)
    parser.add_argument('--name',default='lpac-identity-local-01');parser.add_argument('--preflight',type=Path);parser.add_argument('--runner',type=Path)
    parser.add_argument('--before-global',type=Path);parser.add_argument('--after-global',type=Path);parser.add_argument('--archive',action='store_true')
    parser.add_argument('--global-capture',type=Path);parser.add_argument('--global-expanded',type=Path)
    args=parser.parse_args(argv);planned,result=prepare(args)
    if args.archive:
        checked(OUT,directory=True)
        for path,raw in planned.items():
            if path.exists():require(bounded(path,4*1024*1024)==raw,'refuse_changed_existing_archive')
        for path,raw in planned.items():
            if not path.exists():
                with path.open('xb') as stream:require(stream.write(raw)==len(raw),'archive_write')
                require(bounded(path,4*1024*1024)==raw,'archive_readback')
        path=BASE/'stage_lpac_identity_01_paths.txt';raw=''.join(p.relative_to(REPO).as_posix()+'\n' for p in planned).encode('ascii')
        if path.exists():require(bounded(path)==raw,'existing_explicit_path_list')
        else:
            with path.open('xb') as stream:require(stream.write(raw)==len(raw),'explicit_path_list')
    print(json.dumps(result|dict(archive_written=args.archive,archive_files=len(planned)),sort_keys=True))
if __name__=='__main__':main()
