"""File-only PSEC deny-all bootstrap matched-SC three-held identity attempt01 reader.

All runtime36 and bridge37 source bytes must match the explicit Git commit
before importing their pure validators. The only subprocess is read-only Git.
No DLL mapping, native API, actor, trace, network, security or recovery runs.
Nothing is written unless all bindings pass and --archive is supplied.
Unknown opaque outcomes and partial failures are preserved as original facts.
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
import sys
sys.dont_write_bytecode=True

BASE=Path(__file__).resolve().parent
REPO=BASE/'Rule-proxy-Web'
OUT=REPO/'verification/windows-2026-10-22'
MODULE='.github/windows_identity_psec_lpac_matchedcaps_bridge_local.py'
SCOPE='one-local-cpse-deny-all-outer-guarded-matched-secaps-identity-v1'
CONSTRUCTOR_POLICY='bootstrap-held-primary-matched-security-capabilities-aap-only-v1'
VARIANT='identity-only-deny-all-v1'
SOURCE_SHA256='f77fdff1de75ba53d6dca04d65659deb43fd6bdc91c2feaf1c6a03ade7c008db'
ACTUAL_SOURCE_COMMIT='ec45dffb66cc88bb48578101afb93ce7044a6521'
ACTUAL_PUBLIC_SHA256='6acc10b614f5c35c56ed2adf4e648a7b0f4ea3a74ddbdf3f3e7fb595c9a103b4'
ACTUAL_PUBLIC_BYTES=2658
INDEPENDENT_REVIEW='psec-lpac-matchedcaps-identity-actual-01-independent-review.json'
INDEPENDENT_REVIEW_SHA256='cbb62758368cb3e3e67ba6bd96619f2774c9c179e0d11ca2d771cc6032a45f52'
INDEPENDENT_REVIEW_BYTES=83295
SOURCE_NAMES=('.github/native/windows_identity_actor.cpp', '.github/native/windows_identity_dns_raw_udp.hpp', '.github/native/windows_identity_dns_standard_probe.hpp', '.github/native/windows_identity_proxy_bridge_core.hpp', '.github/native/windows_identity_proxy_c_actor.cpp', '.github/native/windows_identity_proxy_c_contract.hpp', '.github/native/windows_identity_proxy_origin_actor.cpp', '.github/native/windows_identity_proxy_origin_transport.hpp', '.github/native/windows_identity_proxy_pipe_actor.cpp', '.github/windows_dns_fixture.py', '.github/windows_identity_dns_cases_fixture.py', '.github/windows_identity_dns_standard_inventory.ps1', '.github/windows_identity_lpac_dns_local.py', '.github/windows_identity_model2_controller.py', '.github/windows_identity_model2_dns.py', '.github/windows_identity_model2_dns_raw.py', '.github/windows_identity_model2_firewall.ps1', '.github/windows_identity_model2_live.py', '.github/windows_identity_model2_local.py', '.github/windows_identity_model2_local_probe.py', '.github/windows_identity_model2_maintenance.py', '.github/windows_identity_ordinary_launcher.py', '.github/windows_identity_pipe_probe.py', '.github/windows_identity_proof.py', '.github/windows_identity_proxy_origin_probe.py', '.github/windows_identity_proxy_pipe_ac_guest.py', '.github/windows_identity_proxy_pipe_ac_local.py', '.github/windows_identity_proxy_pipe_probe.py', '.github/windows_psec_compartment_smoke.py', 'ruleproxy/windows_app_process.py', 'ruleproxy/windows_runtime_pins.py', '.github/windows_identity_lpac_accesscheck.py', '.github/windows_identity_lpac_identity_cell.py', '.github/windows_identity_psec_spec.py', '.github/windows_identity_psec_lpac_matchedcaps_bridge.py', '.github/windows_identity_psec_lpac_matchedcaps_bridge_local.py')
NATIVE={'actorSourceSha256': '.github/native/windows_identity_proxy_c_actor.cpp', 'originActorSha256': '.github/native/windows_identity_proxy_origin_actor.cpp', 'identitySourceSha256': '.github/native/windows_identity_actor.cpp', 'coreSha256': '.github/native/windows_identity_proxy_bridge_core.hpp', 'pipeHelperSha256': '.github/native/windows_identity_proxy_pipe_actor.cpp', 'originTransportSha256': '.github/native/windows_identity_proxy_origin_transport.hpp', 'liveContractSha256': '.github/native/windows_identity_proxy_c_contract.hpp', 'dnsStandardProbeSha256': '.github/native/windows_identity_dns_standard_probe.hpp', 'dnsRawUdpSha256': '.github/native/windows_identity_dns_raw_udp.hpp'}
BRIDGE_SOURCES=('.github/native/windows_psec_lpac_matchedcaps_bridge.cpp', '.github/native/windows_psec_lpac_matchedcaps_bridge.hpp', '.github/native/windows_psec_lpac_matchedcaps_bridge_core.hpp', '.github/native/windows_psec_lpac_bridge_spec.hpp', 'generated/ProcessSecurityEnvironment_generated.h', 'vendor/windows-sdk/ProcessSecurityEnvironment.fbs')
BRIDGE_DEPENDENCIES=('vendor/flatbuffers/LICENSE', 'vendor/flatbuffers/include/flatbuffers/allocator.h', 'vendor/flatbuffers/include/flatbuffers/array.h', 'vendor/flatbuffers/include/flatbuffers/base.h', 'vendor/flatbuffers/include/flatbuffers/buffer.h', 'vendor/flatbuffers/include/flatbuffers/buffer_ref.h', 'vendor/flatbuffers/include/flatbuffers/code_generator.h', 'vendor/flatbuffers/include/flatbuffers/code_generators.h', 'vendor/flatbuffers/include/flatbuffers/default_allocator.h', 'vendor/flatbuffers/include/flatbuffers/detached_buffer.h', 'vendor/flatbuffers/include/flatbuffers/file_manager.h', 'vendor/flatbuffers/include/flatbuffers/flatbuffer_builder.h', 'vendor/flatbuffers/include/flatbuffers/flatbuffers.h', 'vendor/flatbuffers/include/flatbuffers/flatc.h', 'vendor/flatbuffers/include/flatbuffers/flex_flat_util.h', 'vendor/flatbuffers/include/flatbuffers/flexbuffers.h', 'vendor/flatbuffers/include/flatbuffers/grpc.h', 'vendor/flatbuffers/include/flatbuffers/hash.h', 'vendor/flatbuffers/include/flatbuffers/idl.h', 'vendor/flatbuffers/include/flatbuffers/minireflect.h', 'vendor/flatbuffers/include/flatbuffers/reflection.h', 'vendor/flatbuffers/include/flatbuffers/reflection_generated.h', 'vendor/flatbuffers/include/flatbuffers/registry.h', 'vendor/flatbuffers/include/flatbuffers/stl_emulation.h', 'vendor/flatbuffers/include/flatbuffers/string.h', 'vendor/flatbuffers/include/flatbuffers/struct.h', 'vendor/flatbuffers/include/flatbuffers/table.h', 'vendor/flatbuffers/include/flatbuffers/util.h', 'vendor/flatbuffers/include/flatbuffers/vector.h', 'vendor/flatbuffers/include/flatbuffers/vector_downward.h', 'vendor/flatbuffers/include/flatbuffers/verifier.h')
GIT_NAMES=set(SOURCE_NAMES)|set(BRIDGE_SOURCES)|set(BRIDGE_DEPENDENCIES)

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
    require(re.fullmatch('[0-9a-f]{40}',commit) is not None and name in GIT_NAMES,'git_query_input')
    result=subprocess.run(['git','show',commit+':'+name],cwd=REPO,capture_output=True)
    require(result.returncode==0 and 0<len(result.stdout)<=256*1024,'source_git_blob')
    return result.stdout
def tree(root):
    root=checked(root,directory=True);seen=[];total=0
    def visit(path,depth):
        nonlocal total
        require(depth<=12 and len(seen)<384,'owned_tree_bound');seen.append(path)
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
        if not path.name.startswith('local-psec-lpac-matchedcaps-identity-'):continue
        checked(path,directory=True)
        plan=path/'recovery-plan.json'
        if plan.exists() and sha(bounded(plan,8192))==public['recovery_plan_sha256']:matches.append(path)
    require(len(matches)==1,'exactly_one_recovery_plan_bound_stage');return matches[0]

def proof_projection(proof,arm,config,access):
    # The source-bound core has already validated this against the owner's
    # independently held primary-token snapshot and generation.
    access.validate_proof(proof,expected_primary_identity=arm['expected_primary'],expected_role=arm['name'],expected_pid=arm['pid'],
        expected_creation=arm['created'],frequency=config['frequency'],deadline=config['root_deadline_qpc']-35*config['frequency'])
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
    value=dict(role=arm['name'],canonical_private_proof_sha256=sha(canonical(proof)),generation_before=proof['generation_before'],generation_after=proof['generation_after'],
        source_primary_bound=proof['source_identity_bound'],duplicate_identification_bound=proof['duplicate_identity_bound'],
        calls=calls,resources=resources,resource_cleanup_verified=proof['resource_cleanup_verified'],observation_complete=proof['observation_complete'],
        qualified=proof['qualified'],classification=proof['classification'],failure=proof['failure'],
        error_present=proof['error'] is not None,win32_error=None if proof['error'] is None else proof['error']['win32_error'],
        token_class46_queried=proof['token_class46_queried'],process_or_thread_impersonation_applied=proof['process_or_thread_impersonation_applied'],
        network_tested=proof['network_tested'],dns_tested=proof['dns_tested'],product_acceptance=proof['product_acceptance'])
    observed=[row for row in calls if row['attempted']]
    complete=len(calls)==4 and all(row['attempted'] and row['api_success'] is True for row in calls)
    value.update(attempted_call_count=len(observed),observed_calls=observed,
        unattempted_call_labels=[label for label in access.LABELS if not any(row['label']==label and row['attempted'] for row in calls)],
        complete_four_call_observation=complete,observed_matrix=[row['granted_access'] for row in calls] if complete else None,
        expected_matrix=[3,0,1,2] if arm['name']=='ac' else [2,0,0,2],
        partial_observation_preserved=not complete,unattempted_calls_not_filled=True)
    return value


def source_records(stage,names,commit,expected):
    records=[]
    require(set(expected)==set(names),'closed_source_pin_names')
    for name in sorted(names):
        part=PurePosixPath(name)
        require(not part.is_absolute() and '..' not in part.parts and '\\' not in name,'source_relative_path')
        raw=bounded(stage/name,512*1024);git_raw=read_git(commit,name)
        require(raw==git_raw and b'\r' not in raw and sha(raw)==expected[name],'source_exact_git_lf_bytes')
        records.append(dict(path=name,bytes=len(raw),sha256=sha(raw),
            git_blob=hashlib.sha1(b'blob '+str(len(raw)).encode()+b'\0'+raw).hexdigest()))
    return records


def launch_validate(value,m,parent=None):
    required={'started','resumed','timed_out','nested_resource_cleanup_incomplete','cleanup','diagnostic_execution'}
    allowed=required|{'child_pid','child_identity','native_identity_verified_before_resume','exit_code','error'}
    require(type(value) is dict and required<=set(value)<=allowed,'outer_launch_closed_schema')
    require(all(type(value[k]) is bool for k in ('started','resumed','timed_out','nested_resource_cleanup_incomplete')),'outer_launch_booleans')
    cleanup=value['cleanup']
    require(type(cleanup) is dict and set(cleanup)=={'errors','job_closed','handles_closed','job_empty','process_exit_confirmed','close_uncertain'}
        and all(type(cleanup[k]) is bool for k in cleanup if k!='errors') and type(cleanup['errors']) is list
        and len(cleanup['errors'])<=32,'outer_launch_cleanup_schema')
    m.launcher.validate_execution(value['diagnostic_execution'])
    for name in ('child_pid','exit_code'):
        require(name not in value or type(value[name]) is int and 0<=value[name]<1<<32,'outer_launch_number')
    require('native_identity_verified_before_resume' not in value or type(value['native_identity_verified_before_resume']) is bool,'outer_launch_identity_flag')
    require(not value['resumed'] or value['started'] and value.get('native_identity_verified_before_resume') is True,'outer_launch_held_before_resume')
    if value.get('native_identity_verified_before_resume'):
        child=value.get('child_identity')
        if parent is not None:require(child==m.launcher.safe_identity(parent,parent),'outer_launch_ordinary_identity')
        else:
            require(type(child) is dict and set(child)=={'session_id','token_type','elevation_type','elevated','integrity_rid',
                'admin_attributes','appcontainer','capability_count','ui_access','appcontainer_sid_absent','same_user','same_session'}
                and type(child['session_id']) is int and child['session_id']>=0 and child['token_type']==1
                and child['elevation_type']==3 and child['elevated'] is False and child['integrity_rid']==8192
                and child['appcontainer'] is False and child['capability_count']==0 and child['ui_access'] is False
                and child['appcontainer_sid_absent'] is child['same_user'] is child['same_session'] is True,'outer_launch_safe_ordinary_identity')
    return value


def native_projection(row,c):
    value=row['native']
    result=dict(operation=row['label'],receipt_available=value is not None,returned_function_status=row['return_status'],
        durable_returned_receipt_available=row['receipt'] is not None,
        durable_returned_receipt=None if row['receipt'] is None else metadata(row['receipt']['text'].encode('ascii')),
        exception_recorded=row['exception'] is not None,
        private_exception_sha256=None if row['exception'] is None else sha(canonical(row['exception'])))
    if value is None:return result
    result.update(wrapper_status=value['wrapper_status'],api_entered=bool(value['api_entered']),api_returned=bool(value['api_returned']),
        hresult_valid=bool(value['hresult_valid']),hresult=value['hresult'] if value['hresult_valid'] else None,
        win32_error=value['win32_error'],within_deadline=bool(value['within_deadline']),environment_state=value['environment_state'],
        opaque_outcome_unknown=bool(value['opaque_outcome_unknown']),close_invoked_once=bool(value['close_invoked_once']),
        close_returned_normally=bool(value['close_returned_normally']),module_close_attempted=bool(value['module_close_attempted']),
        module_close_confirmed=bool(value['module_close_confirmed']),support_flags=value['support_flags'],
        schema_major_available=bool(value['schema_major_available']),schema_minor=value['schema_minor'])
    result['duration_milliseconds']=None if not (value['before_qpc'] and value['after_qpc']>=value['before_qpc']) else round(
        1000*(value['after_qpc']-value['before_qpc'])/c['frequency'],6)
    return result


def returned_frame(raw,c,intent,m):
    """Pure structural/config check; this never establishes held API ownership."""
    value=decode(raw)
    keys={'schema_version','scope','constructor_policy','run','config_sha256','action','intent_sha256','frequency','deadline_qpc','return_status','native','pi','security_capabilities_sha256'}
    require(type(value) is dict and set(value)==keys and type(value['schema_version']) is int and value['schema_version']==1
        and value['scope']==SCOPE and value['constructor_policy']==CONSTRUCTOR_POLICY and value['run']==c['run'] and value['config_sha256']==sha(canonical(c))
        and value['action']==intent['action'] and value['intent_sha256']==sha(intent['raw'])
        and value['frequency']==c['frequency'] and value['deadline_qpc']==c['deadline_qpc']
        and type(value['return_status']) is int and 0<=value['return_status']<=10,'returned_frame_binding')
    m.core.validate_native(value['native'],value['action'],c)
    pi=value['pi']
    if value['action'] in ('bootstrap','ac','lpac'):
        require(type(pi) is dict and set(pi)=={'process','thread','process_id','thread_id'}
            and all(type(pi[k]) is int and 0<=pi[k]<(1<<64 if k in ('process','thread') else 1<<32) for k in pi),'returned_frame_pi')
    else:require(pi is None,'returned_frame_no_pi')
    require(digest(value['security_capabilities_sha256']) if value['action'] in ('ac','lpac')
        else value['security_capabilities_sha256'] is None,'returned_sc_input_digest_kind')
    return value



def job_admissions_projection(stage,tasks,j,c,m,*,source_commit,result_validated):
    """Project only source-validated, held-worker-bound admission observations.

    Independently present physical files never establish admission, API return,
    exact Job membership or cleanup. Their bytes/SHA remain available as
    unvalidated forensic metadata without publishing their private JSON.
    """
    expected={}
    for arm in tasks:
        for entry in arm['job_admissions']:
            receipt=entry['receipt']
            if receipt is not None:
                require(receipt['name'] not in expected,'unique_job_admission_receipt')
                expected[receipt['name']]=(arm,entry)
    directory=stage/'job-admissions'
    disk=[] if not directory.exists() else sorted(checked(directory,directory=True).iterdir())
    require(len(disk)<=48,'physical_job_admission_count_bound')
    require(set(expected)<=set(path.name for path in disk),'every_claimed_job_admission_on_disk')
    disk_raw={};physical=[]
    for path in disk:
        require(re.fullmatch(r'(?:bootstrap|ac|lpac)-(?:0[1-9]|1[0-6])\.json',path.name) is not None,'job_admission_filename')
        raw=bounded(path,16384);disk_raw[path]=raw;record=expected.get(path.name)
        if record is not None:
            arm,entry=record;receipt=entry['receipt']
            require(raw==receipt['text'].encode('ascii') and sha(raw)==receipt['sha256'],'disk_job_admission_exact_text_digest')
            operation=next(op for op in j['operations'] if op['label']==arm['name'])
            require(operation['receipt'] is not None and decode(raw)==m.core.job_admission_value(entry,arm,c,j['common']['child']['job'],
                operation['receipt']['sha256']),'disk_job_admission_config_generation_pi_binding')
        physical.append(dict(role=None if record is None else record[0]['name'],sequence=None if record is None else record[1]['sequence'],
            **metadata(raw),bound_to_validated_held_worker_result=record is not None,
            unvalidated_or_incomplete_forensic_only=record is None,raw_private_text_published=False,
            independent_physical_file_establishes_admission=False))
    def exception(value):
        return dict(recorded=value is not None,private_sha256=None if value is None else sha(canonical(value)),message_published=False)
    def generation(value,arm):
        if value is None:return None
        return dict(available=True,alive=value['alive'],image_verified=value['image_verified'],within_original_work_deadline=value['within_deadline'],
            pid_and_creation_match_held_arm=bool(value['pid'] is not None and value['created'] is not None
                and value['pid']==arm['pid'] and value['created']==arm['created']),
            held_generation_verified=m.core.generation_passed(value,arm,c),exception=exception(value['exception']))
    def query_call(value):
        if value is None:return None
        return dict(attempted=value['attempted'],returned=value['returned'],api_success=value['api_success'],membership=value['membership'],
            immediate_win32_error=value['win32_error'],within_original_work_deadline=value['within_deadline'],
            exception=exception(value['exception']))
    observations=[]
    for arm in tasks:
        for entry in arm['job_admissions']:
            query=entry['query'];resource=None if query is None else query['outer_resource'];receipt=entry['receipt']
            observations.append(dict(role=arm['name'],sequence=entry['sequence'],purpose=entry['purpose'],
                generation_before=generation(entry['before'],arm),generation_after=generation(entry['after'],arm),
                inner_query=query_call(None if query is None else query['inner']),outer_query=query_call(None if query is None else query['outer']),
                exact_inner_and_outer_membership_verified=m.core.job_query_passed(query),
                query_resources=None if resource is None else dict(open_attempted=resource['open_attempted'],open_returned=resource['open_returned'],
                    handle_available=resource['handle_value'] is not None,immediate_open_win32_error=resource['open_win32_error'],
                    open_within_original_work_deadline=resource['open_within_deadline'],close_attempted=resource['close_attempted'],
                    close_returned=resource['close_returned'],close_api_success=resource['close_api_success'],
                    immediate_close_win32_error=resource['close_win32_error'],close_within_original_work_deadline=resource['close_within_deadline'],
                    close_uncertain=resource['close_uncertain'],protected_handle_alias=resource['alias'],
                    one_shot_close_source_bound=bool(resource['close_attempted'] and not resource['alias']),
                    cleanup_verified=query['resource_cleanup_verified'],exception=exception(resource['exception'])),
                original_disk_receipt=None if receipt is None else metadata(receipt['text'].encode('ascii')),
                receipt_available=receipt is not None,decision_tick_recorded=entry['decision_qpc'] is not None,
                decision_within_original_work_deadline=bool(type(entry['decision_qpc']) is int
                    and c['start_qpc']<=entry['decision_qpc']<m.core.work_cutoff(c)),
                admission_verified=m.core.job_admission_passed(entry,arm,c),exception=exception(entry['exception']),
                raw_handles_pid_sid_job_name_creation_or_qpc_published=False))
    projection=dict(schema_version=1,stage='psec-matchedcaps-exact-job-admissions-private-safe-projection',scope=SCOPE,constructor_policy=CONSTRUCTOR_POLICY,attempt=1,
        source_commit=source_commit,source_sha256=c['source_sha256'],worker_result_validated=result_validated,
        held_worker_result_available=j is not None,records=observations,physical_receipts=physical,
        job_admission_record_count=len(observations),physical_receipt_count=len(physical),
        held_bound_physical_receipt_count=len(expected),
        query_resource_cleanup_verified=None if j is None else j['job_query_resources_cleanup_verified'],
        api_success_does_not_imply_membership=True,original_dual_exact_membership_admission_gate_unchanged=True,
        scoped_query_handle_one_shot_source_invariant=True,inner_job_is_borrowed_and_not_closed_by_query=True,
        unbound_files_used_for_qualification=False,missing_receipt_or_membership_synthesized=False,
        raw_handles_pid_sid_job_name_creation_or_qpc_published=False,api_or_experiment_run_by_reader=False)
    return projection,disk_raw


def transfers_projection(stage,tasks,j,c,m,*,source_commit,result_validated):
    """Physical pretransfer/intent/return bytes; no raw private identifiers."""
    expected={}
    for arm in tasks:
        transfer=arm['transfer'];guard=transfer['guard']
        if guard is not None and guard['receipt'] is not None:expected[('pretransfer',guard['receipt']['name'])]=(arm,'guard',guard['receipt'])
        for kind in ('intent','receipt'):
            if transfer[kind] is not None:expected[('transfers',transfer[kind]['name'])]=(arm,kind,transfer[kind])
    physical=[];physical_raw={};found=set()
    for directory,limit,maximum in (('pretransfer',16384,3),('transfers',8192,6)):
        root=stage/directory;paths=[] if not root.exists() else sorted(checked(root,directory=True).iterdir())
        require(len(paths)<=maximum,'physical_transfer_receipt_count_bound')
        for path in paths:
            expression=r'(?:bootstrap|ac|lpac)-guard\.json' if directory=='pretransfer' else r'(?:bootstrap|ac|lpac)-assign-(?:intent|returned)\.json'
            require(re.fullmatch(expression,path.name) is not None,'transfer_receipt_filename')
            raw=bounded(path,limit);physical_raw[path]=raw;key=(directory,path.name);found.add(key);record=expected.get(key)
            if record is not None:
                arm,kind,receipt=record;transfer=arm['transfer']
                require(raw==receipt['text'].encode('ascii') and sha(raw)==receipt['sha256'],'disk_transfer_exact_text_digest')
                operation=next(row for row in j['operations'] if row['label']==arm['name']);require(operation['receipt'] is not None,'transfer_pi_returned_receipt')
                inner=j['common']['child']['job'];pi_sha=operation['receipt']['sha256']
                if kind=='guard':value=m.core.job_admission_value(transfer['guard'],arm,c,inner,pi_sha)
                elif kind=='intent':value=m.core.transfer_intent_value(transfer,arm,c,inner,pi_sha,decode(raw)['qpc'])
                else:value=m.core.transfer_return_value(transfer,arm,c,inner,pi_sha)
                require(decode(raw)==value,'disk_transfer_constructor_config_generation_pi_intent_binding')
            physical.append(dict(role=None if record is None else record[0]['name'],kind=None if record is None else record[1],directory=directory,
                **metadata(raw),bound_to_validated_held_worker_result=record is not None,
                unvalidated_or_incomplete_forensic_only=record is None,raw_private_text_published=False,used_for_independent_qualification=False))
    require(set(expected)<=found,'every_claimed_transfer_receipt_on_disk')
    def exception(value):return dict(recorded=value is not None,private_sha256=None if value is None else sha(canonical(value)),message_published=False)
    def generation(value,arm):
        if value is None:return None
        return dict(alive=value['alive'],image_verified=value['image_verified'],within_original_work_deadline=value['within_deadline'],
            held_generation_verified=m.core.generation_passed(value,arm,c),exception=exception(value['exception']))
    def query_call(value):
        return dict(attempted=value['attempted'],returned=value['returned'],api_success=value['api_success'],membership=value['membership'],
            immediate_win32_error=value['win32_error'],within_original_work_deadline=value['within_deadline'],exception=exception(value['exception']))
    records=[]
    for arm in tasks:
        transfer=arm['transfer'];guard=transfer['guard'];query=None if guard is None else guard['query'];raw=transfer['raw']
        resource=None if query is None else query['outer_resource']
        records.append(dict(role=arm['name'],constructor_policy=CONSTRUCTOR_POLICY,
            pretransfer_guard=None if guard is None else dict(sequence=guard['sequence'],purpose=guard['purpose'],
                generation_before=generation(guard['before'],arm),generation_after=generation(guard['after'],arm),
                inner_query=None if query is None else query_call(query['inner']),outer_query=None if query is None else query_call(query['outer']),
                exact_outer_true_inner_false_verified=m.core.guard_passed(guard,arm,c),
                query_resources=None if resource is None else dict(open_attempted=resource['open_attempted'],open_returned=resource['open_returned'],
                    immediate_open_win32_error=resource['open_win32_error'],close_attempted=resource['close_attempted'],close_returned=resource['close_returned'],
                    close_api_success=resource['close_api_success'],immediate_close_win32_error=resource['close_win32_error'],
                    close_within_original_work_deadline=resource['close_within_deadline'],protected_handle_alias=resource['alias'],close_uncertain=resource['close_uncertain'],
                    one_shot_close_source_bound=bool(resource['close_attempted'] and not resource['alias']),cleanup_verified=query['resource_cleanup_verified']),
                original_disk_receipt=None if guard['receipt'] is None else metadata(guard['receipt']['text'].encode('ascii')),
                exception=exception(guard['exception'])),
            original_assignment_intent=None if transfer['intent'] is None else metadata(transfer['intent']['text'].encode('ascii')),
            original_assignment_returned_receipt=None if transfer['receipt'] is None else metadata(transfer['receipt']['text'].encode('ascii')),
            raw_assign_observation=None if raw is None else dict(attempted=raw['attempted'],returned=raw['returned'],return_value=raw['return_value'],
                api_success=raw['api_success'],immediate_win32_error=raw['win32_error'],within_original_work_deadline=raw['within_deadline'],
                call_once_source_bound=raw['attempted'],exception=exception(raw['exception'])),
            transfer_verified=m.core.transfer_passed(transfer,arm,c),
            decision_within_original_work_deadline=bool(type(transfer['decision_qpc']) is int and c['start_qpc']<=transfer['decision_qpc']<m.core.work_cutoff(c)),
            post_assignment_job_observation_count=len(arm['job_admissions']),
            all_recorded_post_assignment_exact_jobs_verified=bool(arm['job_admissions'] and all(m.core.job_admission_passed(entry,arm,c) for entry in arm['job_admissions'])),
            primary_identity_admitted=arm['admitted'],never_resumed=not arm['resumed'],exception=exception(transfer['exception'])))
    value=dict(schema_version=1,stage='psec-matchedcaps-inner-transfers-private-safe-projection',scope=SCOPE,constructor_policy=CONSTRUCTOR_POLICY,
        source_commit=source_commit,source_sha256=c['source_sha256'],worker_result_validated=result_validated,held_worker_result_available=j is not None,
        records=records,physical_receipts=physical,physical_receipt_count=len(physical),held_bound_physical_receipt_count=len(expected),
        pretransfer_record_count=sum(row['transfer']['guard'] is not None for row in tasks),
        assign_attempted_count=sum(bool(row['transfer']['raw'] and row['transfer']['raw']['attempted']) for row in tasks),
        verified_transfer_count=sum(m.core.transfer_passed(row['transfer'],row,c) for row in tasks),
        raw_handles_pid_sid_job_name_creation_or_qpc_published=False,unbound_files_used_for_qualification=False,
        missing_assignment_or_membership_synthesized=False,atomic_inner_creation_proven=False,
        continuous_outer_supervision_proven=False,creation_transfer_crash_gap_resolved=False,api_or_experiment_run_by_reader=False)
    return value,physical_raw

def security_capabilities_projection(stage,tasks,j,c,m,*,source_commit,result_validated):
    """SC input fact projection; no raw SID, token, PID, path, handle or clock."""
    state=None if j is None else j['security_capabilities']
    expected=None if state is None else state['receipt']
    directory=stage/'security-capabilities'
    disk=[] if not directory.exists() else sorted(checked(directory,directory=True).iterdir())
    require(len(disk)<=1 and all(path.name=='held-bootstrap.json' for path in disk),'sc_physical_closed_members')
    originals={};physical=[]
    for path in disk:
        raw=bounded(path,16384);originals[path]=raw
        bound=expected is not None
        if bound:
            require(path.name==expected['name'] and raw==expected['text'].encode('ascii')
                and sha(raw)==expected['sha256'],'sc_original_disk_text_digest')
            require(j is not None and m.core.validate_security_capabilities_state(state,j,c)==state,'sc_original_state_binding')
        physical.append(dict(**metadata(raw),bound_to_validated_held_worker_result=bound,
            unvalidated_forensic_only=not bound,raw_private_text_published=False,used_for_independent_qualification=False))
    require(expected is None or len(disk)==1,'sc_claimed_physical_receipt_present')
    bootstrap=next((row for row in tasks if row['name']=='bootstrap'),None)
    value=None if state is None else state['value']
    inputs=[]
    if value is not None:
        m.core.validate_security_capabilities(value,c['capability_catalog'])
        for label,key in (('held-bootstrap-AppContainer','package_sid'),('AgenticAppContainer','agentic_sid'),
                          ('privateNetworkClientServer','pncs_sid')):
            raw=bytes.fromhex(value[key])
            inputs.append(dict(principal=label,**metadata(raw),attributes=None if key=='package_sid' else value[
                'agentic_attributes' if key=='agentic_sid' else 'pncs_attributes'],raw_bytes_or_sid_published=False))
    measured=[]
    for row in tasks:
        if row['name']=='bootstrap':continue
        tick=row['bootstrap_before_create_check_qpc'];token_tick=row['bootstrap_before_token_check_qpc']
        native=row['native']
        measured.append(dict(role=row['name'],constructor_attempted=row['attempted'],
            input_sha256=row['security_capabilities_sha256'],
            same_frozen_sc_input=None if state is None else row['security_capabilities_sha256']==state['raw_sha256'],
            bootstrap_rechecked_before_create=bool(bootstrap and tick in bootstrap['held_checks'] and native is not None
                and state['decision_qpc'] is not None and state['decision_qpc']<=tick<=native['before_qpc']),
            bootstrap_rechecked_before_primary=bool(bootstrap and token_tick in bootstrap['held_checks']
                and row['primary_observation_qpc'] is not None and row['job_admissions']
                and row['job_admissions'][0]['decision_qpc']<=token_tick<=row['primary_observation_qpc']),
            primary_snapshot_available=row['expected_primary'] is not None,held_admitted=row['admitted'],
            never_resumed=not row['resumed'],raw_generation_or_qpc_published=False))
    same=None if j is None else bool(state['raw_sha256'] is not None and measured
        and all(row['same_frozen_sc_input'] for row in measured))
    value=dict(schema_version=1,stage='psec-matchedcaps-held-bootstrap-security-capabilities-safe-projection',attempt=1,
        scope=SCOPE,constructor_policy=CONSTRUCTOR_POLICY,source_commit=source_commit,source_sha256=c['source_sha256'],
        worker_result_validated=result_validated,held_worker_result_available=j is not None,
        security_capabilities_verified=None if j is None else j['security_capabilities_verified'],
        bootstrap_record_available=bootstrap is not None,bootstrap_held_admitted=None if bootstrap is None else bootstrap['admitted'],
        bootstrap_primary_available=None if bootstrap is None else bootstrap['expected_primary'] is not None,
        external_held_primary_source_bound=None if state is None or state['value'] is None else bool(bootstrap and bootstrap['expected_primary'] is not None
            and state['value']==m.core.security_capabilities_value(bootstrap['expected_primary'],c['capability_catalog'])),
        exact_os_catalog_count=2,required_capability_attributes=4,capability_profile='AgenticAppContainer+privateNetworkClientServer',
        abi_library_version=3,abi_security_input_bytes=64,abi_security_input_version=3,
        canonical_pointer_free_input_sha256=None if state is None else state['raw_sha256'],
        input_sid_byte_metadata=inputs,physical_receipts=physical,physical_receipt_count=len(physical),
        physical_held_bound_receipt_count=sum(row['bound_to_validated_held_worker_result'] for row in physical),
        freeze_decision_tick_recorded=None if state is None else state['decision_qpc'] is not None,
        freeze_decision_within_original_work_deadline=None if state is None or state['decision_qpc'] is None else
            c['start_qpc']<=state['decision_qpc']<m.core.work_cutoff(c),
        exception_recorded=None if state is None else state['exception'] is not None,
        private_exception_sha256=None if state is None or state['exception'] is None else sha(canonical(state['exception'])),
        exception_message_published=False,measured_arms=measured,same_input_for_all_recorded_measured_arms=same,
        complete_two_measured_inputs_recorded=len(measured)==2,
        unbound_files_used_for_qualification=False,raw_sid_capability_bytes_pid_handle_path_or_qpc_published=False,
        bootstrap_self_report_or_actor_execution_used=False,actor_never_resume_source_invariant=True,
        security_capabilities_input_does_not_prove_psec_policy_preservation=True,psec_network_preservation_proven=False,
        atomic_inner_creation_proven=False,continuous_outer_supervision_proven=False,creation_transfer_crash_gap_resolved=False,
        linux_equivalence_proven=False,network_tested=False,dns_tested=False,proxy_tested=False,product_acceptance=False,
        api_or_experiment_run_by_reader=False)
    return value,originals


def prepare(args):
    require(type(ACTUAL_SOURCE_COMMIT) is str and digest(ACTUAL_PUBLIC_SHA256) and type(ACTUAL_PUBLIC_BYTES) is int
        and digest(INDEPENDENT_REVIEW_SHA256) and type(INDEPENDENT_REVIEW_BYTES) is int,'actual_pins_pending_no_archive')
    require(digest(args.public_sha256) and re.fullmatch('[0-9a-f]{40}',args.source_commit) is not None,'explicit_input_pins')
    require(args.source_commit==ACTUAL_SOURCE_COMMIT and args.public_sha256==ACTUAL_PUBLIC_SHA256,'matchedcaps_actual01_source_public_pins')
    require(re.fullmatch('psec-lpac-matchedcaps-identity-local-01',args.name) is not None,'archive_name')
    public_path=checked(args.public);require(OUT.resolve() in public_path.parents,'original_public_location')
    raw_public=bounded(public_path,8192);require(len(raw_public)==ACTUAL_PUBLIC_BYTES and sha(raw_public)==args.public_sha256,'original_public_bytes_sha256')
    public=decode(raw_public);require(type(public) is dict and digest(public.get('recovery_plan_sha256')),'public_plan_commitment')
    raw_review=bounded(BASE/INDEPENDENT_REVIEW,1024*1024)
    require(len(raw_review)==INDEPENDENT_REVIEW_BYTES and sha(raw_review)==INDEPENDENT_REVIEW_SHA256,'original_independent_actual_review_pin')
    review=decode(raw_review);require(review['source_commit']==ACTUAL_SOURCE_COMMIT,'independent_actual_review_source')
    old_public_path=OUT/'psec-lpac-identity-local-01-public.json';old_public_raw=bounded(old_public_path,8192);old_public=decode(old_public_raw)
    require(sha(old_public_raw)=='cc562d1b045fea336c4257051faa52e63aa415d91556a4ea84f18aa363652f9c'
        and old_public['broker_outcome_unknown'] is old_public['recovery_required'] is True,'original_atomic_attempt01_unknown_unchanged')
    stage=locate_stage(public);paths=tree(stage)
    raw_config=bounded(stage/'worker-config.json',512*1024);c=decode(raw_config)
    require(type(c) is dict and c.get('scope')==SCOPE and c.get('variant')==VARIANT and c.get('constructor_policy')==CONSTRUCTOR_POLICY
        and type(c.get('source_hashes')) is dict and set(c['source_hashes'])==set(SOURCE_NAMES),'closed36_source_names')
    require(c.get('source_sha256')==SOURCE_SHA256==sha(canonical(c['source_hashes'])) and stage.name=='local-psec-lpac-matchedcaps-identity-'+c['run'],'source_closure_stage_binding')
    sources=source_records(stage,SOURCE_NAMES,args.source_commit,c['source_hashes'])
    inputs=stage/'inputs'
    raw_dll_manifest=bounded(inputs/'psec-lpac-matchedcaps-bridge-manifest.json',256*1024);dm=decode(raw_dll_manifest)
    require(type(dm) is dict and type(dm.get('sources')) is dict and set(dm['sources'])==set(BRIDGE_SOURCES)
        and type(dm.get('dependencies')) is dict and set(dm['dependencies'])==set(BRIDGE_DEPENDENCIES),'closed37_bridge_pin_names')
    bridge_pins={**dm['sources'],**dm['dependencies']}
    bridge_sources=source_records(stage,tuple(bridge_pins),args.source_commit,bridge_pins)
    for path in paths:
        if path.is_file() and path.suffix.casefold() in ('.py','.pyc','.pyd','.dll'):
            require(path.relative_to(stage).as_posix() in {*SOURCE_NAMES,'inputs/windows_psec_lpac_matchedcaps_bridge.dll'},'unexpected_importable_staged_file')
    # Source files are now Git/LF/digest bound; these imports are pure only.
    loader=importlib.util.spec_from_file_location('archive_psec_identity_pure',stage/MODULE)
    m=importlib.util.module_from_spec(loader);loader.loader.exec_module(m)
    require(set(m.SOURCES)==set(SOURCE_NAMES) and len(m.SOURCES)==36 and m.SCOPE==SCOPE
        and m.core.VARIANT==VARIANT and m.core.CONSTRUCTOR_POLICY==CONSTRUCTOR_POLICY and m.core.api_version()==3,'source_bound_interface')
    _,hashes,closure=m.snapshot(stage);require(hashes==c['source_hashes'] and closure==c['source_sha256'],'source_import_readback')
    m.core.config_validate(c);m.validate_public(public)
    require(all(public[key] is False for key in ('atomic_inner_creation_proven','continuous_outer_supervision_proven',
        'creation_transfer_crash_gap_resolved','psec_network_preservation_proven','linux_equivalence_proven')),'original_unproven_claims_remain_false')
    require(public['mode']=='runtime' and c['root_deadline_qpc']==c['start_qpc']+120*c['frequency']
        and c['deadline_qpc']==c['root_deadline_qpc']-5*c['frequency'],'original120_115_clock')
    commitments=('source','actor','manifest','dll','dll_manifest','processmodel','spec','recovery_plan')
    for name in commitments:require(digest(c[name+'_sha256']) and public[name+'_sha256']==c[name+'_sha256'],'public_config_commitment')
    raw_plan=bounded(stage/'recovery-plan.json',8192);raw_spec=bounded(stage/'spec.bin',65536)
    require(sha(raw_plan)==c['recovery_plan_sha256'] and sha(raw_spec)==c['spec_sha256'],'plan_spec_original_bytes')
    if args.original_plan:require(bounded(args.original_plan,8192)==raw_plan,'original_plan_staging_copy')
    if args.original_spec:require(bounded(args.original_spec,65536)==raw_spec,'original_spec_staging_copy')
    plan=decode(raw_plan);require(all(plan.get(k)==c[k] for k in m.core.NONCES),'plan_nonce_binding')
    m.core.validate_plan(plan,device=c['device_sha256'],source=closure,actor=c['actor_sha256'],manifest=c['manifest_sha256'],
        dll=c['dll_sha256'],dll_manifest=c['dll_manifest_sha256'],processmodel=c['processmodel_sha256'],inputs=inputs)
    spec_observation=m.core.spec.verify(raw_spec,str(inputs));require(spec_observation['sha256']==c['spec_sha256'],'spec_independent_decoder')
    raw_actor=bounded(inputs/m.live.ACTOR,8*1024*1024);raw_actor_manifest=bounded(inputs/m.live.MANIFEST,8192)
    raw_dll=bounded(inputs/m.core.DLL,8*1024*1024)
    require(sha(raw_actor)==c['actor_sha256'] and sha(raw_actor_manifest)==c['manifest_sha256']
        and sha(raw_dll)==c['dll_sha256'] and sha(raw_dll_manifest)==c['dll_manifest_sha256'],'binary_manifest_commitments')
    m.live.verify_actor(inputs/m.live.ACTOR,inputs/m.live.MANIFEST,c['actor_sha256'],c['manifest_sha256'],root=stage)
    actor_manifest=decode(raw_actor_manifest)
    require(set(actor_manifest)=={'schemaVersion','compileOnly','runtimeAcceptance','executableSha256',*NATIVE}
        and m.live.NATIVE_SOURCES==NATIVE and all(actor_manifest[k]==hashes[n] for k,n in NATIVE.items()),'native07_exact9_source_binding')
    m.core.verify_manifest(inputs/m.core.DLL,inputs/m.core.DLL_MANIFEST,c['dll_sha256'],c['dll_manifest_sha256'],root=stage)
    imports,exports=m.core.pe_linkage(raw_dll)
    build=checked(args.build_directory,directory=True)
    require(bounded(build/m.core.DLL,8*1024*1024)==raw_dll and bounded(build/m.core.DLL_MANIFEST,256*1024)==raw_dll_manifest,'immutable_build_artifact_bytes')
    raw_snapshot=bounded(build/'input-snapshot.json',128*1024);snapshot=decode(raw_snapshot)
    require(type(snapshot) is dict and set(snapshot)=={'SchemaVersion','SnapshotBeforeCompile','SourcesAndDependencies','NativeFreezeSha256','DllLoaded','CpseCalled','ActorExecuted','ConstructorPolicy','LibraryAbiVersion','PayloadVersion'}
        and type(snapshot['SchemaVersion']) is int and snapshot['SchemaVersion']==1 and snapshot['SnapshotBeforeCompile'] is True
        and snapshot['NativeFreezeSha256']=='7e702eac67a463682878c9d40ee1d8665d30a2f596a9ebf1edf1b2801de3fc1f'
        and snapshot['ConstructorPolicy']==CONSTRUCTOR_POLICY and snapshot['LibraryAbiVersion']==3 and snapshot['PayloadVersion']==1
        and snapshot['DllLoaded'] is snapshot['CpseCalled'] is snapshot['ActorExecuted'] is False,'build_before_input_snapshot')
    records=snapshot['SourcesAndDependencies'];require(type(records) is list and len(records)==37,'build_snapshot_count')
    seen=set()
    for row in records:
        require(type(row) is dict and set(row)=={'Path','Sha256','Kind'} and row['Path'] in bridge_pins
            and row['Path'] not in seen and row['Sha256']==bridge_pins[row['Path']]
            and row['Kind']==('source' if row['Path'] in BRIDGE_SOURCES else 'dependency'),'build_snapshot_pin')
        seen.add(row['Path']);require(bounded(build/'src'/row['Path'],512*1024)==bounded(stage/row['Path'],512*1024),'immutable_build_source_bytes')
    require(seen==set(bridge_pins),'build_snapshot_closure')
    preflight_path=Path(args.preflight) if args.preflight else public_path.with_name(public_path.name.removesuffix('-public.json')+'-preflight.json')
    raw_preflight=bounded(preflight_path,8192);preflight=m.validate_public(decode(raw_preflight))
    require(preflight['mode']=='preflight' and preflight['status']=='ready'
        and all(preflight[k+'_sha256']==c[k+'_sha256'] for k in commitments),'preflight_commitments')
    raw_launch=bounded(stage/'outer-launch-report.json',512*1024) if (stage/'outer-launch-report.json').exists() else None
    require((public['outer_launch_sha256'] is None)==(raw_launch is None),'outer_launch_presence_commitment')
    if raw_launch is not None:require(sha(raw_launch)==public['outer_launch_sha256'],'outer_launch_raw_digest')
    raw_report=bounded(stage/'worker-report.json',m.core.MAX_REPORT) if (stage/'worker-report.json').exists() else None
    forensic_path=stage/'worker-result-forensic.json'
    raw_forensic=bounded(forensic_path,m.core.MAX_REPORT) if forensic_path.exists() else None
    forensic_json=False
    if raw_forensic is not None:
        try:decode(raw_forensic);forensic_json=True
        except (ValueError,UnicodeError):pass
    report=decode(raw_report) if raw_report is not None else None
    parent=None;j=None;obs=None;result_validated=False
    if report is not None:
        require(type(report) is dict and set(report)=={'schema_version','stage','config','worker_pid','worker_identity','result'}
            and type(report['schema_version']) is int and report['schema_version']==1 and report['stage']=='cpse-matchedcaps-three-held-identity-worker'
            and report['config']==c and type(report['worker_pid']) is int and report['worker_pid']>0,'worker_report_closed_header')
        parent=report['worker_identity'];require(m.launcher.token_is_ordinary(parent),'ordinary_worker_identity')
        j=m.core.validate_result(report['result'],c,parent=parent,root=stage);obs=m.core.project(copy.deepcopy(j),c,parent=parent,root=stage)
        m.validate_observation(obs);result_validated=True
        # Source02 writes this before the final validator. The valid report must
        # contain exactly that original result; the forensic file alone is never
        # passed to result/project or used as an alternate held worker report.
        require(raw_forensic is not None and raw_forensic==m.encode(report['result'])
            and decode(raw_forensic)==report['result'],'forensic_equals_original_valid_result')
    launch=launch_validate(decode(raw_launch),m,parent) if raw_launch is not None else None
    if launch is not None:
        require(public['checks']['worker_exit']==launch['cleanup']['process_exit_confirmed']
            and public['checks']['outer_cleanup']==m.local.guest.cleanup_verified(launch),'outer_cleanup_reprojection')
        require(not public['checks']['guard'] or launch.get('native_identity_verified_before_resume') is True,'outer_guard_held_receipt')
    else:require(not any(public['checks'][k] for k in ('worker_bound','inner_complete')),'no_launch_no_runtime_binding')
    if public['checks']['worker_bound']:
        require(report is not None and launch is not None,'held_report_originals_present')
        reproduced=copy.deepcopy(public);m.bind_report(report,c,parent,launch,reproduced,root=stage)
        require(reproduced['identity_observation']==public['identity_observation'] and reproduced['checks']==public['checks']
            and reproduced['recovery_required']==public['recovery_required']
            and reproduced['broker_outcome_unknown']==public['broker_outcome_unknown'],'public_identity_cleanup_projection')
    else:
        require(public['identity_observation'] is None and not public['observation_complete']
            and public['recovery_required'] and public['broker_outcome_unknown'],'unbound_worker_remains_unknown')
    launch_normal=bool(launch and launch.get('started') is True and launch.get('resumed') is True
        and launch.get('native_identity_verified_before_resume') is True and launch.get('timed_out') is False
        and launch.get('exit_code')==0 and 'error' not in launch)
    require(not public['observation_complete'] or launch_normal and obs is not None and obs['inner_complete'],'completion_requires_normal_bound_worker')
    if public['observation_complete']:require(public['failure'] is None and all(public['checks'].values()),'complete_public_checks')
    # A valid, held-bound partial report is projected as-is. Never synthesize a
    # missing arm, proof, API return, VOID return, or environment absence fact.
    trusted_result=j if public['checks']['worker_bound'] else None
    tasks=[] if trusted_result is None else trusted_result['tasks']
    arms={row['name']:row for row in tasks}
    proofs=[] if trusted_result is None else [proof_projection(p,arms[p['expected_role']],c,m.core.access) for p in trusted_result['proofs']]
    operations=[] if trusted_result is None else [native_projection(row,c) for row in trusted_result['operations']]
    task_projection=[]
    for row in tasks:
        prior=row['expected_primary'];native=row['native']
        task_projection.append(dict(role=row['name'],constructor_attempted=row['attempted'],native_receipt_available=native is not None,
            policy=1 if row['name']=='lpac' else 0,process_information={key:bool(value) for key,value in row['pi'].items()},
            process_and_thread_distinct=bool(row['pi']['process'] and row['pi']['thread'] and row['pi']['process']!=row['pi']['thread']),
            generation_available=row['pid'] is not None and row['created'] is not None,assigned=row['assigned'],held_admitted=row['admitted'],
            never_resumed=not row['resumed'],exited=row['exited'],exit_code=row['exit_code'],known_no_child=m.core.known_no_child(row,c),
            held_generation_checks=len(row['held_checks']),primary_snapshot_available=prior is not None,
            same_user=None if prior is None else prior['sid']==parent['sid'],same_session=None if prior is None else prior['session_id']==parent['session_id'],
            exact_catalog=None if prior is None else sorted(prior['capabilities'],key=lambda x:x['sid'])==sorted(
                [dict(sid=sid,attributes=4) for sid in c['capability_catalog'].values()],key=lambda x:x['sid']),
            integrity_rid=None if prior is None else prior['integrity_rid'],token_type=None if prior is None else prior['token_type'],
            elevated=None if prior is None else prior['elevated'],ui_access=None if prior is None else prior['ui_access']))
    intents=[];journal=stage/'journal';stored=[] if not journal.exists() else sorted(checked(journal,directory=True).iterdir())
    raw_intents={}
    if trusted_result is not None:
        require([p.name for p in stored]==[row['name'] for row in trusted_result['intents']],'exact_disk_journal_members')
        for path,row in zip(stored,trusted_result['intents']):
            raw=bounded(path,4096);require(raw==row['text'].encode('ascii') and sha(raw)==row['sha256'],'intent_original_text_digest')
            raw_intents[path.name]=dict(action=row['action'],raw=raw)
            intents.append(dict(action=row['action'],bytes=len(raw),sha256=sha(raw)))
    else:
        require(len(stored)<=10,'unbound_journal_bound')
        actions=[];last=c['start_qpc']
        for index,path in enumerate(stored):
            raw=bounded(path,4096);value=decode(raw)
            require(type(value) is dict and set(value)=={'schema_version','scope','constructor_policy','run','config_sha256','action','frequency','deadline_qpc','qpc'}
                and type(value['schema_version']) is int and value['schema_version']==1 and value['scope']==SCOPE
                and value['constructor_policy']==CONSTRUCTOR_POLICY and value['run']==c['run'] and value['config_sha256']==sha(canonical(c))
                and value['action'] in (*m.core.OPS,'observe-ac','observe-lpac','stop') and value['action'] not in actions
                and value['frequency']==c['frequency'] and value['deadline_qpc']==c['deadline_qpc']
                and type(value['qpc']) is int and last<=value['qpc']<=m.live.MAX_SIGNED
                and path.name=='%02d-%s.json'%(index,value['action']),'partial_intent_config_clock_binding')
            last=value['qpc'];actions.append(value['action'])
            raw_intents[path.name]=dict(action=value['action'],raw=raw)
            intents.append(dict(action=value['action'],bytes=len(raw),sha256=sha(raw),
                intent_only=True,within_original_root_deadline=value['qpc']<c['root_deadline_qpc'],
                held_bound_api_entry_or_return_receipt_available=False))
    receipt_dir=stage/'receipts'
    disk_receipts=[] if not receipt_dir.exists() else sorted(checked(receipt_dir,directory=True).iterdir())
    require(len(disk_receipts)<=7,'returned_receipt_count_bound')
    returned=[];returned_raw={}
    expected_receipts={} if trusted_result is None else {row['receipt']['name']:row for row in trusted_result['operations'] if row['receipt'] is not None}
    require(set(expected_receipts)<=set(path.name for path in disk_receipts),'every_claimed_returned_receipt_on_disk')
    for path in disk_receipts:
        require(re.fullmatch(r'0[0-9]-(?:bind|create|bootstrap|ac|lpac|close|unbind)-returned\.json',path.name) is not None,'returned_receipt_filename')
        raw=bounded(path,32768);returned_raw[path]=raw
        intent_name=path.name.removesuffix('-returned.json')+'.json';intent=raw_intents.get(intent_name)
        frame=None
        if intent is not None:
            try:frame=returned_frame(raw,c,intent,m)
            except (ValueError,UnicodeError,KeyError,TypeError):pass
        record=expected_receipts.get(path.name)
        if record is not None:
            require(raw==record['receipt']['text'].encode('ascii') and sha(raw)==record['receipt']['sha256'],'disk_returned_original_text_digest')
            require(frame is not None and frame['return_status']==record['return_status'] and frame['native']==record['native'],'disk_returned_original_function_tuple')
            arm=arms.get(record['label'])
            require(frame['pi']==(None if arm is None else arm['pi']),'disk_returned_original_pi')
            require(frame['security_capabilities_sha256']==(None if record['label'] not in ('ac','lpac') else trusted_result['security_capabilities']['raw_sha256']),'disk_returned_original_sc_input')
        returned.append(dict(operation=None if intent is None else intent['action'],**metadata(raw),
            frame_config_intent_bound=frame is not None,bound_to_validated_held_worker_result=record is not None,
            unvalidated_or_incomplete_forensic_only=record is None,raw_pi_or_ids_published=False,
            used_for_public_qualification=False))
    secaps,sc_receipt_raw=security_capabilities_projection(stage,tasks,trusted_result,c,m,source_commit=args.source_commit,result_validated=result_validated)
    jobs,job_receipt_raw=job_admissions_projection(stage,tasks,trusted_result,c,m,source_commit=args.source_commit,result_validated=result_validated)
    transfers,transfer_receipt_raw=transfers_projection(stage,tasks,trusted_result,c,m,source_commit=args.source_commit,result_validated=result_validated)
    streams=[]
    for name in ('controller.stdin','controller.stdout','controller.stderr'):
        path=stage/'guard'/name
        if path.exists():streams.append(dict(stream=name,observed=True,**metadata(bounded(path,256*1024))))
        else:require(not (launch and launch.get('started')),'started_worker_stdio_present');streams.append(dict(stream=name,observed=False,bytes=None,sha256=None))
    commitments=review['private_commitments']
    require(type(commitments) is dict and set(commitments)=={'config','plan','spec','worker_report','forensic','outer_launch',
        'stdout','stderr','driver','security_capabilities'},'independent_private_commitments_closed')
    for label,raw in dict(config=raw_config,plan=raw_plan,spec=raw_spec,worker_report=raw_report,forensic=raw_forensic,outer_launch=raw_launch).items():
        require(commitments[label]==(None if raw is None else metadata(raw)),'private_original_matches_independent_review_commitment')
    sc_commitment=commitments.get('security_capabilities')
    require(sc_commitment==(None if not sc_receipt_raw else metadata(next(iter(sc_receipt_raw.values())))),'private_sc_matches_independent_review_commitment')
    require(bool(args.runner)==(commitments['driver'] is not None),'original_driver_presence')
    if args.runner:require(metadata(bounded(args.runner,128*1024))==commitments['driver'],'original_driver_bytes_commitment')
    for label in ('stdout','stderr'):
        require(metadata(bounded(stage/'guard'/('controller.'+label),256*1024))==commitments[label],'private_stdio_matches_independent_review_commitment')
    global_projection=dict(observed=False,before=None,after=None,raw_bytes_identical=None,whole_json_objects_equal=None,
        nrpt_in_snapshot=False,scope='Separate four-object point-in-time capture, not policy enforcement or external environment absence.')
    require(bool(args.before_global)==bool(args.after_global),'paired_global_inputs')
    if args.before_global:
        before=bounded(args.before_global,262144);after=bounded(args.after_global,262144);bv,av=decode(before),decode(after)
        require(type(bv) is dict and type(av) is dict and set(bv)==set(av)=={'schema_version','stage','firewall_profiles','dns','routes','user_proxy'},'global_closed_four_objects')
        global_projection.update(observed=True,before=metadata(before),after=metadata(after),raw_bytes_identical=before==after,whole_json_objects_equal=bv==av)
    private_values=[c[k] for k in m.core.NONCES]+[c['device_sha256'],str(stage),*c['capability_catalog'].values()]
    raw_ids=[]
    if parent is not None:private_values.append(parent['sid']);raw_ids.append(report['worker_pid'])
    if j is not None:
        private_values.extend((j['first_appcontainer_sid'],c['guard_job_name']))
        raw_ids.extend(row['pid'] for row in j['tasks'] if row['pid'] is not None)
    def safe(raw):
        require(all(value.encode('utf8') not in raw for value in private_values if type(value) is str and value),'private_identifier_in_projection')
        text=raw.decode('utf8');require(not re.search(r'\bS-\d+(?:-\d+){2,}\b',text,re.I),'raw_sid_in_projection')
        require(not re.search(r'(?i)\b[A-Z]:[\\/]',text),'machine_absolute_path_in_projection')
        require(all(not re.search(r'(?<![A-Za-z0-9])'+str(value)+r'(?![A-Za-z0-9])',text) for value in raw_ids),'raw_process_id_in_projection')
    planned={}
    def add(suffix,value,*,raw=False):
        path=OUT/(args.name+'-'+suffix);data=value if raw else encode(value);safe(data);planned[path]=data
    add('public.json',raw_public,raw=True);add('preflight.json',raw_preflight,raw=True)
    if args.runner:add('runner.py',bounded(args.runner,128*1024),raw=True)
    add('bridge-manifest.json',raw_dll_manifest,raw=True);add('actor-manifest.json',raw_actor_manifest,raw=True)
    add('compile-input-snapshot.json',raw_snapshot,raw=True)
    add('archive.py',bounded(Path(__file__),128*1024),raw=True)
    require(bool(args.global_capture)==bool(args.global_expanded),'paired_capture_scripts')
    if args.global_capture:
        require(global_projection['observed'],'capture_scripts_require_snapshot')
        add('after-global-capture.ps1',bounded(args.global_capture,32768),raw=True)
        add('after-global-expanded.ps1',bounded(args.global_expanded,32768),raw=True)
    cleanup_confirmed=bool(public['checks']['worker_bound'] and not public['recovery_required'] and not public['broker_outcome_unknown'])
    close_ops=[row for row in operations if row['operation']=='close']
    close_invoked=None if trusted_result is None else sum(row.get('close_invoked_once',False) for row in close_ops)
    close_returned=None if trusted_result is None else sum(row.get('close_returned_normally',False) for row in close_ops)
    detail=None if trusted_result is None else trusted_result['failure_detail']
    component=dict(schema_version=1,stage='psec-matchedcaps-deny-all-matched-identity-private-safe-projection',attempt=args.attempt,scope=SCOPE,variant=VARIANT,constructor_policy=CONSTRUCTOR_POLICY,
        source_commit=args.source_commit,source_sha256=closure,runtime_source_count=36,runtime_sources=sources,
        independent_actual_review=metadata(raw_review),
        prior_atomic01_original_public=metadata(old_public_raw),prior_atomic01_broker_unknown_preserved=True,prior_atomic01_recovery_required_preserved=True,
        bridge_source_count=6,bridge_dependency_count=31,bridge_sources_and_dependencies=bridge_sources,
        actor_native_source_count=9,actor_manifest_key_count=13,bridge_manifest_key_count=15,bridge_library_abi_version=3,bridge_payload_version=1,
        private_config=metadata(raw_config),private_worker_report=None if raw_report is None else metadata(raw_report),
        private_forensic_result=None if raw_forensic is None else metadata(raw_forensic),
        forensic_result=dict(record_available=raw_forensic is not None,json_parseable=forensic_json,
            equals_original_validated_report_result=None if report is None else True,
            standalone_unvalidated=True,used_for_public_qualification=False,
            absent_worker_report_filled_from_forensic=False),
        private_recovery_plan=metadata(raw_plan),private_original_spec=metadata(raw_spec),private_outer_launch=None if raw_launch is None else metadata(raw_launch),
        source_git_lf_verified=True,build_snapshot_before_compile_verified=True,build_input_snapshot=metadata(raw_snapshot),
        dll_metadata=dict(sha256=sha(raw_dll),bytes=len(raw_dll),architecture='amd64',imports=imports,exports=exports,binary_published=False),
        actor_sha256=c['actor_sha256'],processmodel_recorded_sha256=c['processmodel_sha256'],spec_observation=spec_observation,
        worker_report_available=report is not None,worker_result_validated=result_validated,worker_report_held_bound=public['checks']['worker_bound'],
        identity_observation=public['identity_observation'],task_observations=task_projection,proofs=proofs,operations=operations,intents=intents,
        returned_receipt_files=returned,returned_receipt_count=len(returned),
        validated_held_bound_returned_receipt_count=sum(row['bound_to_validated_held_worker_result'] for row in returned),stdio_files=streams,
        job_admission_record_count=jobs['job_admission_record_count'],physical_job_admission_receipt_count=jobs['physical_receipt_count'],
        job_query_resources_cleanup_verified=jobs['query_resource_cleanup_verified'],
        security_capabilities=secaps,
        inner_assignment_observations=transfers['records'],physical_assignment_and_pretransfer_receipt_count=transfers['physical_receipt_count'],
        partial_proof_count=sum(proof['partial_observation_preserved'] for proof in proofs),
        observed_accesscheck_call_count=sum(proof['attempted_call_count'] for proof in proofs),
        failure_detail=dict(record_available=trusted_result is not None,present=None if trusted_result is None else detail is not None,
            private_sha256=None if detail is None else sha(canonical(detail)),message_published=False),
        child_environment=None if trusted_result is None else trusted_result['child_environment'],child_environment_values_published=False,
        outer_launch=dict(available=launch is not None,started=None if launch is None else launch['started'],resumed=None if launch is None else launch['resumed'],
            timed_out=None if launch is None else launch['timed_out'],native_identity_verified_before_resume=None if launch is None else launch.get('native_identity_verified_before_resume',False),
            ordinary_worker_identity_bound=bool(launch and parent and launch.get('child_identity')==m.launcher.safe_identity(parent,parent)),
            exit_code=None if launch is None else launch.get('exit_code'),normal_zero_exit=launch_normal,
            cleanup=None if launch is None else {key:launch['cleanup'][key] for key in ('job_closed','handles_closed','job_empty','process_exit_confirmed','close_uncertain')},
            cleanup_error_count=None if launch is None else len(launch['cleanup']['errors']),arbitrary_errors_or_raw_identity_published=False),
        private_stage_binding='Fresh run path, exact plan/config/source commitments and source-bound worker admission; no new ACL/token query by this reader.',
        intent_records_do_not_prove_api_return=True,worker_report_absence_preserved=report is None,
        original_root_seconds=120,worker_seconds=115,native_operation_receipts_available=any(row['receipt_available'] for row in operations),
        close_operation_receipt_count=len(close_ops),void_close_invoked_count=close_invoked,
        void_close_returned_normally_count=close_returned,close_is_void_no_hresult=True,automatic_cleanup_confirmed=cleanup_confirmed,
        original_recovery_required=public['recovery_required'],original_broker_outcome_unknown=public['broker_outcome_unknown'],
        external_environment_absence_verified=False,broker_cancellation_proven=False,actor_resumed=False,token_class46_queried=False,
        missing_arm_or_proof_synthesized=False,unknown_opaque_reinterpreted_as_closed=False,raw_private_identity_or_logs_published=False,
        atomic_inner_creation_proven=False,continuous_outer_supervision_proven=False,creation_transfer_crash_gap_resolved=False,
        network_tested=False,dns_tested=False,proxy_tested=False,product_acceptance=False,model2_policy_compared=False,psec_network_preservation_proven=False,linux_equivalence_proven=False)
    add('component-projection.json',component);add('global-projection.json',global_projection)
    add('job-admissions-projection.json',jobs)
    add('inner-transfers-projection.json',transfers)
    add('security-capabilities-projection.json',secaps)
    add('summary.json',dict(schema_version=1,stage='psec-matchedcaps-deny-all-matched-identity-actual-summary',scope=SCOPE,variant=VARIANT,constructor_policy=CONSTRUCTOR_POLICY,attempt=args.attempt,
        source_commit=args.source_commit,source_sha256=closure,runtime_source_count=36,bridge_source_count=6,bridge_dependency_count=31,
        independent_actual_review=metadata(raw_review),
        prior_atomic01_original_public=metadata(old_public_raw),prior_atomic01_broker_unknown_preserved=True,prior_atomic01_recovery_required_preserved=True,
        original_public=metadata(raw_public),original_status=public['status'],original_failure=public['failure'],
        observation_complete=public['observation_complete'],identity_observation=public['identity_observation'],
        task_record_count=len(tasks),attempted_arm_count=None if trusted_result is None else len(tasks),
        held_admitted_arm_count=None if trusted_result is None else sum(row['admitted'] for row in tasks),proof_count=len(proofs),
        opaque_environment_create_calls=None if trusted_result is None else sum(row['operation']=='create' and row.get('api_entered',False) for row in operations),
        void_close_invoked_count=close_invoked,void_close_normal_return_count=close_returned,
        forensic_result_available=raw_forensic is not None,forensic_used_for_qualification=False,
        returned_receipt_file_count=len(returned),validated_held_bound_returned_receipt_count=sum(row['bound_to_validated_held_worker_result'] for row in returned),
        automatic_cleanup_confirmed=cleanup_confirmed,original_recovery_required=public['recovery_required'],original_broker_outcome_unknown=public['broker_outcome_unknown'],
        job_admission_record_count=jobs['job_admission_record_count'],physical_job_admission_receipt_count=jobs['physical_receipt_count'],
        job_query_resources_cleanup_verified=jobs['query_resource_cleanup_verified'],
        pretransfer_record_count=transfers['pretransfer_record_count'],assign_attempted_count=transfers['assign_attempted_count'],
        verified_transfer_count=transfers['verified_transfer_count'],physical_assignment_and_pretransfer_receipt_count=transfers['physical_receipt_count'],
        qualified_proof_count=sum(proof['qualified'] for proof in proofs),partial_proof_count=sum(proof['partial_observation_preserved'] for proof in proofs),
        observed_accesscheck_call_count=sum(proof['attempted_call_count'] for proof in proofs),
        security_capabilities_verified=None if trusted_result is None else trusted_result['security_capabilities_verified'],
        measured_input_digest_same=None if trusted_result is None else secaps['same_input_for_all_recorded_measured_arms'],
        security_capabilities_physical_receipt_count=secaps['physical_receipt_count'],
        observed_matrices={proof['role']:proof['observed_matrix'] for proof in proofs},lpac_partial_calls_not_completed=True,
        global_after_capture_available=global_projection['observed'],global_configuration_byte_equal=global_projection['raw_bytes_identical'],
        all_recorded_actors_never_resumed=None if trusted_result is None else all(not row['resumed'] for row in tasks),
        complete_three_actor_set_recorded=None if trusted_result is None else len(tasks)==3,
        actor_never_resume_source_invariant=True,actor_code_executed=False,token_class46_queried=False,
        comparison='Independent deny-all CPSE bootstrap plus externally held primary matched SECURITY_CAPABILITIES; measured arms differ only AAP0/1. This is neither the original atomic constructor nor the existing proxy policy; SC input does not prove PSEC network-policy preservation.',
        no_earlier_failure_reinterpretation=True,separate_recovery_not_inferred=True,external_environment_absence_verified=False,
        atomic_inner_creation_proven=False,continuous_outer_supervision_proven=False,creation_transfer_crash_gap_resolved=False,
        broker_cancellation_proven=False,network_tested=False,dns_tested=False,proxy_tested=False,product_acceptance=False,model2_policy_compared=False,psec_network_preservation_proven=False,linux_equivalence_proven=False))
    add('evidence-index.json',dict(schema_version=1,stage='psec-matchedcaps-deny-all-matched-identity-evidence-index',scope=SCOPE,
        source_commit=args.source_commit,source_sha256=closure,original_public_sha256=args.public_sha256,
        files=[dict(path=path.relative_to(REPO).as_posix(),**metadata(raw)) for path,raw in planned.items()],index_self_hash_excluded=True,
        archive_process_experiment_run=False,native_api_instantiated=False,dll_loaded=False,network_operation_run=False,policy_or_recovery_run=False,
        raw_compile_logs_published=False,dll_binary_published=False,raw_private_reports_published=False))
    # Do not publish a race-mixed report, artifact, plan, source or public.
    stable={public_path:raw_public,stage/'worker-config.json':raw_config,stage/'recovery-plan.json':raw_plan,stage/'spec.bin':raw_spec,
        inputs/m.live.ACTOR:raw_actor,inputs/m.live.MANIFEST:raw_actor_manifest,inputs/m.core.DLL:raw_dll,inputs/m.core.DLL_MANIFEST:raw_dll_manifest}
    stable[BASE/INDEPENDENT_REVIEW]=raw_review
    stable[old_public_path]=old_public_raw
    if raw_report is not None:stable[stage/'worker-report.json']=raw_report
    if raw_launch is not None:stable[stage/'outer-launch-report.json']=raw_launch
    if raw_forensic is not None:stable[forensic_path]=raw_forensic
    stable.update(returned_raw);stable.update(job_receipt_raw);stable.update(transfer_receipt_raw);stable.update(sc_receipt_raw)
    stable.update({journal/name:value['raw'] for name,value in raw_intents.items()})
    require(all(bounded(path,8*1024*1024)==raw for path,raw in stable.items()),'original_evidence_unchanged')
    for row in (*sources,*bridge_sources):require(sha(bounded(stage/row['path'],512*1024))==row['sha256'],'staged_source_unchanged')
    return planned,dict(security_capabilities_verified=secaps['security_capabilities_verified'],security_capabilities_physical_receipts=secaps['physical_receipt_count'],verified=True,source_commit=args.source_commit,runtime_source_count=36,bridge_pin_count=37,
        status=public['status'],observation_complete=public['observation_complete'],proof_count=len(proofs),
        recovery_required=public['recovery_required'],broker_outcome_unknown=public['broker_outcome_unknown'],
        worker_result_validated=result_validated,forensic_used_for_qualification=False,
        returned_receipt_files=len(returned),job_admission_records=jobs['job_admission_record_count'],
        physical_job_admission_receipts=jobs['physical_receipt_count'],native_api_or_experiment_run=False)


def main(argv=None):
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--public',type=Path,required=True);parser.add_argument('--public-sha256',required=True);parser.add_argument('--source-commit',required=True)
    parser.add_argument('--name',default='psec-lpac-matchedcaps-identity-local-01');parser.add_argument('--attempt',type=int,default=1)
    parser.add_argument('--preflight',type=Path);parser.add_argument('--runner',type=Path)
    parser.add_argument('--build-directory',type=Path,default=BASE/'psec-lpac-matchedcaps-bridge-compile-01')
    parser.add_argument('--original-plan',type=Path);parser.add_argument('--original-spec',type=Path)
    parser.add_argument('--before-global',type=Path);parser.add_argument('--after-global',type=Path)
    parser.add_argument('--global-capture',type=Path);parser.add_argument('--global-expanded',type=Path)
    parser.add_argument('--archive',action='store_true');args=parser.parse_args(argv)
    require(args.attempt==1,'matchedcaps_attempt01_only');planned,result=prepare(args)
    if args.archive:
        checked(OUT,directory=True)
        for path,raw in planned.items():
            if path.exists():require(bounded(path,4*1024*1024)==raw,'refuse_changed_existing_archive')
        for path,raw in planned.items():
            if not path.exists():
                with path.open('xb') as stream:require(stream.write(raw)==len(raw),'archive_write')
                require(bounded(path,4*1024*1024)==raw,'archive_readback')
        path=BASE/('stage_'+args.name.replace('-','_')+'_paths.txt')
        raw=''.join(p.relative_to(REPO).as_posix()+'\n' for p in planned).encode('ascii')
        if path.exists():require(bounded(path)==raw,'existing_explicit_path_list')
        else:
            with path.open('xb') as stream:require(stream.write(raw)==len(raw),'explicit_path_list')
    print(json.dumps(result|dict(archive_written=args.archive,archive_files=len(planned)),sort_keys=True))
if __name__=='__main__':main()

