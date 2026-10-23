"""WORK-only file reader. Never creates a backend, process, socket or ACL.

Source/public commitments must come from the operator after the single actual
attempt. Missing reports remain missing; a forensic result is not a public or
qualification fallback. Only a fresh WORK receipt is written after validation.
"""
import argparse
import copy
import hashlib
import importlib.util
import json
from pathlib import Path
import re
import stat
import subprocess
import sys

sys.dont_write_bytecode=True
W=Path(__file__).resolve().parent
R=W/'Rule-proxy-Web'
PREFIX='registry-read-loopback-local-01'
SOURCE_SHA='069d9f2702e235f03603d11b5962f320fe0f077cd81ccfabafefd48cbd11dfb6'
GLOBAL_SHA='f05d91ee76ee8a97ae5ab3bfa092167a8ee560c083255f142e6c453f2edf7ab3'
# The capture script is authored by the operator; its actual SHA is mandatory CLI input.
ACTOR_SHA='ff5ce2453d91902b516eed4d9266735579c3ee7fd936b4fbdf915ce086b531f0'
MANIFEST_SHA='72679ffee1c1e110730207b9cae747385afb8a0f4a6a65f5fe78e6b2b76758a1'
NATIVE_SHA={'.github/native/windows_identity_lpac_registry_loopback_actor.cpp':'e585646ff2ddc3b29b987e8191455acea96bfc0a347129a6f57936e4ac1ca079',
            '.github/native/windows_identity_lpac_registry_loopback_contract.hpp':'842658f2771a34722276805948cb2b65123a9407f7f323c94ea46f56a53ca966'}


def require(value,label):
    if not value:raise ValueError(label)


def sha(raw):return hashlib.sha256(raw).hexdigest()
def desc(raw):return dict(bytes=len(raw),sha256=sha(raw))
def encode(value):return (json.dumps(value,sort_keys=True,separators=(',',':'),ensure_ascii=True)+'\n').encode('ascii')


def checked(path,inside):
    path=Path(path).absolute();inside=Path(inside).absolute()
    require(path.is_relative_to(inside),'audit_path_outside_root')
    relative=path.relative_to(inside);cursor=inside
    for part in (None,*relative.parts):
        if part is not None:cursor=cursor/part
        value=cursor.lstat()
        require(not stat.S_ISLNK(value.st_mode) and not getattr(value,'st_file_attributes',0)&0x400,'audit_reparse')
    require(stat.S_ISREG(path.lstat().st_mode),'audit_regular_file');return path


def read(path,limit=1024*1024,*,inside=R):
    path=checked(path,inside);size=path.stat().st_size
    require(0<=size<=limit,'audit_bounded_file');raw=path.read_bytes()
    require(len(raw)==size and len(raw)<=limit,'audit_file_changed');return raw


def unique(pairs):
    result={}
    for key,value in pairs:
        require(key not in result,'audit_duplicate_key');result[key]=value
    return result


def json_file(path,limit=1024*1024,*,inside=R):
    raw=read(path,limit,inside=inside);return json.loads(raw,object_pairs_hook=unique),raw


def safe_error(error):
    label=str(error)
    return dict(type=type(error).__name__,label=label if re.fullmatch(r'[A-Za-z0-9_-]{1,128}',label) else None)


def optional_file(path,limit=1024*1024):
    return None if not path.exists() else desc(read(path,limit))


def globals_review(capture_sha256):
    capture=read(W/'registry_read_loopback_capture_01.ps1',65536,inside=W)
    require(sha(capture)==capture_sha256,'audit_readonly_capture_pin')
    names={'original':'model2-first-01-global-baseline.json',
           'before':'registry-read-loopback-before-registry01-global-snapshot.json',
           'after':'registry-read-loopback-after-registry01-global-snapshot.json'}
    values={};raws={}
    for label,name in names.items():values[label],raws[label]=json_file(R/'private'/name,256*1024)
    require(desc(raws['original'])==dict(bytes=7378,sha256=GLOBAL_SHA),'audit_original_global_pin')
    keys=('firewall_profiles','dns','routes','user_proxy')
    require(all(set(value)==set(values['original']) and all(key in value for key in keys) for value in values.values()),'audit_global_schema')
    equality={key:all(values['original'][key]==values[label][key] for label in ('before','after')) for key in keys}
    expanded={}
    for phase in ('before-registry01','after-registry01'):
        path=W/('registry_read_loopback_'+phase+'_expanded.ps1')
        if path.exists():expanded[phase]=desc(read(path,128*1024,inside=W))
    return dict(raw_snapshots={label:desc(raws[label]) for label in names},objects_equal=equality,
                all_four_objects_equal=all(equality.values()),all_json_objects_equal=values['original']==values['before']==values['after'],
                before_after_byte_equal=raws['before']==raws['after'],all_bytes_equal=raws['original']==raws['before']==raws['after'],
                capture=desc(capture),expanded_scripts=expanded,nrpt_included=False,
                no_mutation_or_api_executed_by_this_reader=True)


def audit(args):
    require(re.fullmatch(r'[0-9a-f]{40}',args.source_commit) is not None,'audit_source_commit')
    require(all(re.fullmatch(r'[0-9a-f]{64}',value) is not None for value in (args.source_sha256,args.public_sha256))
            and 0<args.public_bytes<=16384,'audit_operator_commitments')
    commit=subprocess.check_output(['git','rev-parse','--verify',args.source_commit+'^{commit}'],cwd=R).strip().decode('ascii')
    require(commit==args.source_commit,'audit_exact_source_commit')
    def git(name):
        require(type(name) is str and re.fullmatch(r'[A-Za-z0-9_./-]+',name) is not None and '..' not in name.split('/'),'audit_source_name')
        return subprocess.check_output(['git','show',commit+':'+name],cwd=R)
    pub,pubraw=json_file(R/'verification/windows-2026-10-22'/(PREFIX+'-public.json'),16384)
    pre,preraw=json_file(R/'verification/windows-2026-10-22'/(PREFIX+'-preflight.json'),16384)
    require(desc(pubraw)==dict(bytes=args.public_bytes,sha256=args.public_sha256),'audit_original_public')
    require(pub['source_sha256']==pre['source_sha256']==args.source_sha256,'audit_public_source')
    require(args.source_sha256==SOURCE_SHA,'audit_frozen_registry_source')
    plan,planraw=json_file(R/'private/registry-read-loopback-recovery-plan-01.json',8192)
    require(sha(planraw)==pub['recovery_plan_sha256'] and re.fullmatch(r'[0-9a-f]{32}',plan.get('run','')) is not None,'audit_original_plan')
    stage=R/'private'/('local-registry-read-same-sid-loopback-'+plan['run'])
    c,configraw=json_file(stage/'worker-config.json',256*1024)
    require(c['source_sha256']==args.source_sha256 and c['recovery_plan_sha256']==sha(planraw),'audit_config_binding')
    require(type(c['source_hashes']) is dict and 1<=len(c['source_hashes'])<=64 and sha(encode(c['source_hashes']))==args.source_sha256,'audit_source_closure')
    source_rows=[]
    for name,digest in c['source_hashes'].items():
        actual_blob=git(name)
        raw=read(stage/name,512*1024);require(sha(raw)==digest and raw==actual_blob and b'\r' not in raw,'audit_source_git_lf')
        source_rows.append(dict(path=name,**desc(raw)))
    # The source/config/artifact readers below are all pure file validators.
    # Import occurs only after every staged runtime source equals actual Git.
    spec=importlib.util.spec_from_file_location('registry_read_actual01_file_reader',stage/'.github/windows_identity_lpac_registry_loopback_local.py')
    m=importlib.util.module_from_spec(spec);spec.loader.exec_module(m)
    require(set(c['source_hashes'])==set(m.SOURCES),'audit_actual_source_names')
    m.core.config_validate(c);m.validate_public(pub);m.validate_public(pre)
    require(pre['status']=='ready' and pre['mode']=='preflight' and pub['mode']=='runtime','audit_preflight_ready')
    require(read(stage/'recovery-plan.json',8192)==planraw,'audit_staged_original_plan')
    m.core.validate_plan(plan,device=c['device_sha256'],source=args.source_sha256,actor=c['actor_sha256'],manifest=c['manifest_sha256'])
    require(all(plan[key]==c[key] for key in (*m.core.NONCES,'ports')),'audit_plan_nonce_binding')
    require(len({c[key] for key in m.core.NONCES})==8 and c['root_deadline_qpc']==c['start_qpc']+120*c['frequency']
            and c['deadline_qpc']==c['root_deadline_qpc']-5*c['frequency'],'audit_nonce_original_clock')
    manifest,manifest_raw=json_file(stage/'inputs'/m.core.MANIFEST,65536)
    m.core.verify_actor(stage/'inputs'/m.core.ACTOR,stage/'inputs'/m.core.MANIFEST,c['actor_sha256'],c['manifest_sha256'],root=stage)
    require(pub['actor_sha256']==pre['actor_sha256']==c['actor_sha256'] and pub['manifest_sha256']==pre['manifest_sha256']==c['manifest_sha256'],'audit_public_artifacts')
    require(c['actor_sha256']==ACTOR_SHA and c['manifest_sha256']==MANIFEST_SHA,'audit_predeclared_compile01_artifacts')
    require({name:c['source_hashes'][name] for name in m.core.NATIVE_SOURCES}==NATIVE_SHA,'audit_frozen_native_two_sources')
    outer=None;outer_raw=None;outer_path=stage/'outer-launch-report.json'
    if outer_path.exists():
        outer,outer_raw=json_file(outer_path,256*1024)
        require(sha(outer_raw)==pub['outer_launch_report_sha256'],'audit_raw_outer_launch')
    else:require(pub['outer_launch_report_sha256'] is None,'audit_absent_outer_not_reconstructed')
    report_path=stage/'worker-report.json';forensic_path=stage/'worker-result-forensic.json'
    report_valid=False;error=None;projection_equal=False;task_rows=[];proof_rows=[];native_rows=[];go_rows=[];tcp_rows=[];intent_rows=[]
    j=None;report_raw=None;referenced=set()
    if report_path.exists():
        report,report_raw=json_file(report_path,m.MAX_REPORT)
        require(type(report) is dict and set(report)=={'schema_version','stage','config','worker_pid','worker_identity','result'}
                and report['schema_version']==1 and type(report['schema_version']) is int
                and report['stage']=='registry-read-same-sid-loopback-worker' and report['config']==c,'audit_worker_report')
        require(outer is not None and outer.get('started') is True and outer.get('resumed') is True
                and outer.get('native_identity_verified_before_resume') is True
                and outer.get('cleanup',{}).get('process_exit_confirmed') is True
                and type(report['worker_pid']) is int and report['worker_pid']==outer.get('child_pid'),'audit_held_worker_pid')
        parent=report['worker_identity'];require(m.launcher.token_is_ordinary(parent),'audit_ordinary_worker')
        require(outer.get('child_identity')==m.launcher.safe_identity(parent,parent),'audit_held_worker_safe_identity')
        j=report['result']
        try:m.core.validate_result(j,c,parent=parent,root=stage);report_valid=True
        except BaseException as exc:error=safe_error(exc)
        if report_valid:
            require(read(forensic_path,m.MAX_REPORT)==m.encode(report),'audit_forensic_original_report')
            derived=copy.deepcopy(pub);derived['loopback_observation']=None;derived['checks']['worker_bound']=False
            derived['checks']['reachability']=False;derived['failure']=None;derived['recovery_required']=True
            m.bind_report(report,c,parent,outer,derived,root=stage)
            for key in ('loopback_observation','recovery_required'):
                require(derived[key]==pub[key],'audit_recomputed_public')
            require(derived['checks']['worker_bound']==pub['checks']['worker_bound'] and
                    derived['checks']['reachability']==pub['checks']['reachability'],'audit_recomputed_checks')
            projection_equal=derived==pub
            if not projection_equal:
                require(pub['status']=='inconclusive' and pub['observation_complete'] is False and pub['failure'] is not None,'audit_outer_downgrade_only')
            for row in j['intents']:
                path=stage/'journal'/row['name'];raw=read(path,4096)
                require(raw==row['text'].encode('ascii') and sha(raw)==row['sha256'],'audit_physical_intent')
                value=m.decode(raw);intent_rows.append(dict(action=value['action'],**desc(raw)));referenced.add(path)
            for row in (*j['tasks'],*j['cleanup_tasks']):
                actor=row.get('role') in m.core.ROLES
                task_rows.append(dict(name=row['name'],actor=actor,attempted=row['attempted'],process_returned=row['process_returned'],
                    assigned=row['assigned'],admitted=row['admitted'],resumed=row['resumed'],exited=row['exited'],exit_code=row['exit_code'],
                    remained_suspended_before_cleanup=actor and row['admitted'] and not row['resumed'],
                    natural_exit_zero=row['resumed'] and row['exited'] and row['exit_code']==0,
                    nonzero_exit=row['exited'] and row['exit_code'] is not None and row['exit_code']!=0,
                    source_bound_typed_exit5=actor and row['resumed'] and row['exited'] and row['exit_code']==5
                        and any(v['role']==row['role'] and v['kind']=='final' and v['value']['failure'] is not None for v in j['native']),
                    known_suspended_cleanup_exit1=actor and row['admitted'] and not row['resumed'] and row['exited'] and row['exit_code']==1,
                    job_termination_inferred_from_nonzero_alone=False,
                    held_check_count=len(row.get('held_checks',[])),class46_not_queried=row['lpac'] is None,
                    declared_role_capability_count=None if not actor else len(m.core.role_capabilities(row['role'])),
                    capabilities_match_declared_role=None if not actor else row.get('capabilities')==m.core.role_capabilities(row['role']),
                    selected_registry_read_attribute4_verified=None if row.get('role')!='selected-client' else row.get('capabilities')==m.core.role_capabilities('selected-client')))
            for proof in j['proofs']:
                proof_rows.append(dict(role=proof['expected_role'],qualified=proof['qualified'],observation_complete=proof['observation_complete'],
                    generation_before=proof['generation_before'],generation_after=proof['generation_after'],
                    source_primary_bound=proof['source_identity_bound'],duplicate_bound=proof['duplicate_identity_bound'],
                    resources_closed=proof['resource_cleanup_verified'],proof_sha256=sha(m.encode(proof)),
                    calls=[{key:call[key] for key in ('label','attempted','api_success','win32_error','access_status',
                                                      'granted_access','privilege_count','within_deadline')} for call in proof['calls']]))
            for row in j['native']:
                path=stage/m.core.ACTOR_DIRS[row['role']][0]/row['name'];raw=read(path,65536)
                require(raw==row['text'].encode('ascii') and sha(raw)==row['sha256'],'audit_physical_native')
                value=row['value'];safe={key:value[key] for key in ('failure','network_tested','product_acceptance')}
                for key in ('wsa_error','win32_error','request_bytes','response_bytes','request_exact','request_eof',
                            'response_complete','response_exact','response_eof','connect_attempted','connect_completed',
                            'send_attempted','send_shutdown','response_withheld','socket_held','release_verified','within_deadline',
                            'socket_close','connection_close','wsa_started','wsa_cleanup','listening_verified','listen_close',
                            'socket_resources_closed','accepted_count','receipt_count','phase_count','token_close_confirmed','control_close_verified'):
                    if key in value:safe[key]=value[key]
                native_rows.append(dict(role=row['role'],kind=row['kind'],name=row['name'],sequence=row['sequence'],**desc(raw),facts=safe))
                referenced.add(path)
            for row in j['go']:
                raw=bytes.fromhex(row['hex']);path=stage/m.core.ACTOR_DIRS[row['role']][1]/row['name']
                require(read(path,128)==raw and sha(raw)==row['sha256'],'audit_physical_go')
                require(raw==m.core.control(c,row['role'],row['sequence'],row['case'],row['issued'],row['end'],release=row['release']),'audit_canonical_go')
                go_rows.append(dict(role=row['role'],sequence=row['sequence'],release=row['release'],**desc(raw),
                    phase_within_original_reserve=row['end']<=m.core.work_cutoff(c),phase_ticks=row['end']-row['issued']))
                referenced.add(path)
            byrole={row['name']:row for row in j['tasks']}
            for row in j['tcp']:
                path=stage/'tcp-observations'/row['name'];raw=read(path,1048576)
                require(len(raw)==row['raw_bytes'] and sha(raw)==row['raw_sha256'],'audit_physical_tcp')
                value=m.core.exact_tcp(raw,byrole['front-listener']['pid'],c['ports']['frontend'],
                    client_pid=byrole['selected-client']['pid'] if row['kind']=='withheld' else None,
                    client_port=row['value']['client']['local_port'] if row['kind']=='withheld' else None)
                require(value==row['value'],'audit_independent_tcp_decode')
                tcp_rows.append(dict(kind=row['kind'],**desc(raw),listener_exact=True,
                    both_held_pid_tuple_exact=row['kind']=='withheld',client_state=None if value['client'] is None else value['client']['state'],
                    server_state=None if value['server'] is None else value['server']['state']))
                referenced.add(path)
    else:
        require(pub['checks']['worker_bound'] is False and pub['loopback_observation'] is None
                and pub['observation_complete'] is False and pub['recovery_required'] is True,'audit_missing_report_unknown')
    unreferenced=[]
    for directory in ('journal','tcp-observations',*(pair[0] for pair in m.core.ACTOR_DIRS.values()),*(pair[1] for pair in m.core.ACTOR_DIRS.values())):
        root=stage/directory
        if not root.exists():continue
        for path in sorted(root.rglob('*')):
            require(not path.is_symlink() and not getattr(path.lstat(),'st_file_attributes',0)&0x400,'audit_evidence_reparse')
            if path.is_file() and path not in referenced:unreferenced.append(dict(directory=directory,name=path.name,**desc(read(path,1048576))))
    globals_value=globals_review(args.capture_sha256)
    driver=read(W/'run_registry_read_loopback_01.py',128*1024,inside=W)
    private_commitments=dict(config=desc(configraw),plan=desc(planraw),
        worker_report=None if report_raw is None else desc(report_raw),forensic=optional_file(forensic_path,m.MAX_REPORT),
        outer_launch=None if outer_raw is None else desc(outer_raw),
        stdout=optional_file(stage/'guard/controller.stdout',2*1024*1024),
        stderr=optional_file(stage/'guard/controller.stderr',2*1024*1024),driver=desc(driver))
    return dict(schema_version=1,stage='registry-read-loopback-actual-01-file-review',bindings_validated=True,
        source_commit=commit,source_sha256=args.source_sha256,source_count=len(source_rows),sources=source_rows,
        scope=pub['scope'],profile=pub['profile'],selected_capability=pub['selected_capability'],capability_effect=pub['capability_effect'],
        selected_declared_capability_count=1,selected_declared_capability_attributes=4,front_declared_capability_count=0,ordinary_declared_capability_count=0,
        control_magic='RCL1',packet_magic='RLP1',all_broad_claims_remain_source_fixed_false=True,
        public=desc(pubraw),preflight=desc(preraw),plan=desc(planraw),config=desc(configraw),private_commitments=private_commitments,
        actor=desc(read(stage/'inputs'/m.core.ACTOR,8*1024*1024)),manifest=desc(manifest_raw),native_source_count=2,
        public_status=pub['status'],public_failure=pub['failure'],original_recovery_required=pub['recovery_required'],
        original_observation_complete=pub['observation_complete'],public_observation=pub['loopback_observation'],
        worker_report_present=report_path.exists(),worker_report=None if report_raw is None else desc(report_raw),
        forensic=optional_file(forensic_path,m.MAX_REPORT),worker_result_valid=report_valid,result_validation_error=error,
        public_projection_exact=projection_equal,outer_launch=None if outer_raw is None else desc(outer_raw),
        outer_facts=None if outer is None else dict(started=outer.get('started'),resumed=outer.get('resumed'),
            exit_code=outer.get('exit_code'),timed_out=outer.get('timed_out'),cleanup=outer.get('cleanup')),
        intents=intent_rows,held_tasks=task_rows,accesscheck_proofs=proof_rows,native_reports=native_rows,
        commands=go_rows,tcp_observations=tcp_rows,unreferenced_raw_evidence=unreferenced,
        label_state=None if not report_valid else j['labels'],
        cleanup=None if not report_valid else {key:j[key] for key in m.core.CLEAN_KEYS},
        workload_stop=None if not report_valid else j['workload_stop'],
        labels_scope='only two fresh owned output subtrees; absence restored after held workload cleanup; no ancestor label changes inferred',
        globals=globals_value,fixed_false_claims={key:pub[key] for key in m.core.FALSE_CLAIMS},
        reader_scope=dict(file_only=True,actor_executed=False,backend_constructed=False,cleanup_called=False,
                          network_called=False,acl_or_label_changed=False),
        limitations=['Native network_tested means connect-attempt/accepted-flow, not whether socket/bind/listen APIs were called.',
                     'Unreferenced/forensic originals are hash-only, not qualification fallback.',
                     'Natural zero, source-bound typed exit5 and suspended cleanup exit1 are separate; nonzero alone never proves Job termination.',
                     'This fixed trusted-actor cell proves no same-SID tamper, injection, pipe theft, proxy or product boundary.',
                     'Selected has only registryRead attributes4; front and ordinary controls have zero capabilities. This is not a matched-capabilities or AAP-only comparison.',
                     'registryRead may permit reads of other existing same-capability-ACE registry objects, not only the Winsock catalog.',
                     'Winsock initialization, socket creation, connect/send, independent tuple and bytes are separate facts; no error or success is presupposed.'])


def main():
    parser=argparse.ArgumentParser(description=__doc__)
    for name in ('source-commit','source-sha256','public-sha256'):parser.add_argument('--'+name,required=True)
    parser.add_argument('--public-bytes',required=True,type=int)
    parser.add_argument('--capture-sha256',required=True)
    parser.add_argument('--output',type=Path,default=W/'registry-read-loopback-actual-01-independent-review.json')
    args=parser.parse_args();require(args.output.absolute().is_relative_to(W.absolute()),'audit_work_output_only')
    require(re.fullmatch(r'[0-9a-f]{64}',args.capture_sha256) is not None,'audit_capture_operator_commitment')
    value=audit(args);raw=(json.dumps(value,sort_keys=True,indent=2)+'\n').encode('ascii')
    require(not args.output.exists(),'audit_fresh_output')
    with args.output.open('xb') as output:output.write(raw)
    print(json.dumps(dict(bindings_validated=True,review_bytes=len(raw),review_sha256=sha(raw),
                         worker_result_valid=value['worker_result_valid'],original_status=value['public_status']),sort_keys=True))


if __name__=='__main__':main()
