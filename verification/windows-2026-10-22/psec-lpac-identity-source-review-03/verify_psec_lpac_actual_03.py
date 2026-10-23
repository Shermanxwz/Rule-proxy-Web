"""Actual03 file-only independent audit; never constructs a native backend.

The operator must supply the actual SOURCE commit and original public digest.
No outcome, raw Job value, receipt count or child PID is assumed in advance.
Only a new WORK receipt is written, after source/artifact/plan/raw bindings.
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
SOURCE_SHA='cf09c9c86adf9f7af3fb3d71bdde6cd1fd4fa7000a8eb01cc5ebc71b3ea5d682'
FREEZE_SHA='0fafbd55ebe54ea9ed13ac7705dec0b7baa8e0cc26f7971290219f8f6683c00d'
DLL_SHA='9574f93eb562a858b207412f9f538b15bfbf329b1df284b3266496b4c2cf2ba5'
MANIFEST_SHA='9b9ab93826c99bbde32c18cca3a32389d75086c3b1f7abbc453a2dda98d09209'
GLOBAL_SHA='f05d91ee76ee8a97ae5ab3bfa092167a8ee560c083255f142e6c453f2edf7ab3'
OLD_PUBLIC={
    '01':'cc562d1b045fea336c4257051faa52e63aa415d91556a4ea84f18aa363652f9c',
    '02':'100dc78f9af83445829a9f8ddf03ebe1f6bb5fc3af8f1a694e43bb78229daba2'}

def require(value,label):
    if not value:raise ValueError(label)
def sha(raw):return hashlib.sha256(raw).hexdigest()
def blob(raw):return hashlib.sha1(b'blob '+str(len(raw)).encode()+b'\0'+raw).hexdigest()
def checked(path,inside):
    path=Path(path).absolute();inside=Path(inside).absolute()
    require(path.is_relative_to(inside),'audit_path_outside_root')
    for item in (inside,*reversed(path.relative_to(inside).parents)):
        target=item if item==inside else inside/item
        if target==inside or target.exists():
            value=target.lstat();require(not stat.S_ISLNK(value.st_mode) and not getattr(value,'st_file_attributes',0)&0x400,'audit_reparse_ancestor')
    value=path.lstat();require(stat.S_ISREG(value.st_mode) and not getattr(value,'st_file_attributes',0)&0x400,'audit_not_regular')
    return path
def raw_file(path,limit=1024*1024,*,inside=R):
    path=checked(path,inside);value=path.stat();require(0<=value.st_size<=limit,'audit_file_size')
    raw=path.read_bytes();require(len(raw)==value.st_size and len(raw)<=limit,'audit_file_changed');return raw
def descriptor(raw):return dict(bytes=len(raw),sha256=sha(raw))
def json_file(path,limit=1024*1024,*,inside=R):
    def unique(pairs):
        value={}
        for key,item in pairs:
            require(key not in value,'audit_duplicate_json_key');value[key]=item
        return value
    raw=raw_file(path,limit,inside=inside);return json.loads(raw,object_pairs_hook=unique),raw
def safe_label(error):
    value=str(error)
    return dict(type=type(error).__name__,label=value if re.fullmatch(r'[a-zA-Z0-9_-]{1,128}',value) else None)
def typed_call(row):
    return {key:row[key] for key in ('attempted','returned','api_success','membership','win32_error','within_deadline')}
def qpc_delta(first,last,frequency):
    return None if first is None or last is None else round((last-first)*1000/frequency,6)

def audit(args):
    require(re.fullmatch(r'[0-9a-f]{40}',args.source_commit) is not None,'audit_source_commit')
    require(re.fullmatch(r'[0-9a-f]{64}',args.public_sha256) is not None and args.public_bytes>0,'audit_public_commitment')
    commit=subprocess.check_output(['git','rev-parse','--verify',args.source_commit+'^{commit}'],cwd=R).strip().decode('ascii')
    require(commit==args.source_commit,'audit_source_commit_alias')
    def git(name):return subprocess.check_output(['git','show',commit+':'+name],cwd=R)

    pubpath=R/'verification/windows-2026-10-22/psec-lpac-identity-local-03-public.json'
    prepath=pubpath.with_name('psec-lpac-identity-local-03-preflight.json')
    pub,pubraw=json_file(pubpath);pre,preraw=json_file(prepath)
    require(descriptor(pubraw)==dict(bytes=args.public_bytes,sha256=args.public_sha256),'audit_original_public_bytes')
    freeze,freezeraw=json_file(W/'psec-lpac-python-diagnostic-freeze-03.json',256*1024,inside=W)
    require(sha(freezeraw)==FREEZE_SHA and freeze['source_count']==36 and freeze['source_sha256']==SOURCE_SHA,'audit_diagnostic_freeze')

    planpath=R/'private/psec-lpac-identity-recovery-plan-03.json';plan,planraw=json_file(planpath,64*1024)
    require(sha(planraw)==pub['recovery_plan_sha256'],'audit_plan_public_digest')
    require(type(plan.get('run')) is str and re.fullmatch(r'[0-9a-f]{32}',plan['run']) is not None,'audit_plan_run')
    stage=R/'private'/('local-psec-lpac-identity-'+plan['run'])
    configpath=stage/'worker-config.json';c,configraw=json_file(configpath,128*1024)
    require(c['source_sha256']==pub['source_sha256']==SOURCE_SHA and c['source_hashes']==freeze['source_hashes'],'audit_source_closure')
    require(len(c['source_hashes'])==36 and c['recovery_plan_sha256']==sha(planraw),'audit_config_plan_digest')
    sources=[]
    for name,digest in c['source_hashes'].items():
        raw=raw_file(stage/name,512*1024)
        require(sha(raw)==digest and raw==git(name) and b'\r' not in raw,'audit_source_git_lf')
        sources.append(dict(path=name,bytes=len(raw),sha256=digest,git_blob=blob(raw)))
    # No project import occurs before every staged runtime source is pinned to
    # the operator's exact source commit and the diagnostic freeze closure.
    loader=importlib.util.spec_from_file_location('cpse_actual03_file_audit',stage/'.github/windows_identity_psec_lpac_bridge_local.py')
    m=importlib.util.module_from_spec(loader);loader.loader.exec_module(m)
    m.core.config_validate(c);m.validate_public(pub);m.validate_public(pre)
    require(sha(m.encode(c['source_hashes']))==SOURCE_SHA and pre['source_sha256']==SOURCE_SHA and pre['status']=='ready','audit_preflight_source')
    require(raw_file(stage/'recovery-plan.json',64*1024)==planraw,'audit_staged_plan')
    require(all(plan[key]==c[key] for key in m.core.NONCES),'audit_plan_nonces')
    m.core.validate_plan(plan,device=c['device_sha256'],source=SOURCE_SHA,actor=c['actor_sha256'],manifest=c['manifest_sha256'],
        dll=c['dll_sha256'],dll_manifest=c['dll_manifest_sha256'],processmodel=c['processmodel_sha256'],inputs=stage/'inputs')
    specraw=raw_file(stage/'spec.bin',m.core.spec.MAX_BYTES)
    m.core.spec.verify(specraw,str(stage/'inputs'))
    require(sha(specraw)==pub['spec_sha256']==plan['spec_sha256']==c['spec_sha256'],'audit_raw_spec_digest')
    require(raw_file(R/'private/psec-lpac-identity-spec-03.bin',m.core.spec.MAX_BYTES)==specraw,'audit_original_spec_bytes')
    for key in ('actor','manifest','dll','dll_manifest','processmodel'):
        require(pub[key+'_sha256']==c[key+'_sha256']==plan[key+'_sha256'],'audit_artifact_plan_binding')

    manifest,manifestraw=json_file(stage/'inputs'/m.core.DLL_MANIFEST,256*1024)
    require(sha(manifestraw)==MANIFEST_SHA==pub['dll_manifest_sha256'] and pub['dll_sha256']==DLL_SHA,'audit_frozen_compile02')
    native=[];pins={**manifest['sources'],**manifest['dependencies']}
    require(pins==freeze['native_pins'] and len(manifest['sources'])==6 and len(manifest['dependencies'])==31 and len(pins)==37,'audit_native_closure')
    for name,digest in pins.items():
        raw=raw_file(stage/name,512*1024);require(sha(raw)==digest and raw==git(name),'audit_native_git_bytes')
        native.append(dict(path=name,bytes=len(raw),sha256=digest,git_blob=blob(raw)))
    m.core.verify_manifest(stage/'inputs'/m.core.DLL,stage/'inputs'/m.core.DLL_MANIFEST,DLL_SHA,MANIFEST_SHA,root=stage)
    m.live.verify_actor(stage/'inputs'/m.live.ACTOR,stage/'inputs'/m.live.MANIFEST,pub['actor_sha256'],pub['manifest_sha256'],root=stage)

    outerpath=stage/'outer-launch-report.json'
    outer=None;outerraw=None
    if outerpath.exists():
        outer,outerraw=json_file(outerpath,256*1024)
        require(sha(outerraw)==pub['outer_launch_sha256'],'audit_original_outer_launch')
    else:require(pub['outer_launch_sha256'] is None,'audit_missing_committed_outer_launch')
    reportpath=stage/'worker-report.json';forensicpath=stage/'worker-result-forensic.json'
    report=None;report_raw=None;j=None;result_valid=False;result_error=None;projection_equal=False
    intents=[];returns=[];job_admissions=[];unreferenced=[];observed_proofs=[];task_view=[]
    if reportpath.exists():
        report,report_raw=json_file(reportpath,m.core.MAX_REPORT)
        require(type(report) is dict and set(report)=={'schema_version','stage','config','worker_pid','worker_identity','result'}
            and type(report['schema_version']) is int and report['schema_version']==1 and report['stage']=='cpse-matched-identity-worker'
            and report['config']==c,'audit_worker_report_binding')
        require(outer is not None and outer.get('started') is True and outer.get('resumed') is True
            and outer.get('native_identity_verified_before_resume') is True and outer.get('cleanup',{}).get('process_exit_confirmed') is True
            and type(report['worker_pid']) is int and report['worker_pid']>0 and report['worker_pid']==outer.get('child_pid'),'audit_held_worker_binding')
        parent=report['worker_identity'];require(m.launcher.token_is_ordinary(parent),'audit_ordinary_worker_identity')
        j=report['result']
        try:m.core.validate_result(j,c,parent=parent);result_valid=True
        except BaseException as error:result_error=safe_label(error)
        if result_valid:
            require(forensicpath.exists() and raw_file(forensicpath,m.core.MAX_REPORT)==m.encode(j),'audit_forensic_original_result')
            v=copy.deepcopy(pub);v.update(identity_observation=None,recovery_required=True,broker_outcome_unknown=True,failure=None)
            v['checks'].update(worker_bound=False,inner_complete=False)
            m.bind_report(report,c,parent,outer,v)
            # Outer failure can downgrade a bound result, but may never be
            # reconstructed as a successful runtime from an incomplete tuple.
            for key in ('identity_observation','recovery_required','broker_outcome_unknown'):
                require(v[key]==pub[key],'audit_derived_public_observation')
            require(v['checks']['worker_bound']==pub['checks']['worker_bound'] and v['checks']['inner_complete']==pub['checks']['inner_complete'],
                'audit_derived_public_checks')
            projection_equal=v==pub
            if not projection_equal:
                require(pub['status']=='inconclusive' and pub['observation_complete'] is False and pub['failure'] is not None,'audit_outer_downgrade_only')
            referenced={name:set() for name in ('journal','receipts','job-admissions')}
            for intent in j['intents']:
                path=stage/'journal'/intent['name'];raw=raw_file(path,4096)
                require(raw==intent['text'].encode('ascii') and sha(raw)==intent['sha256'],'audit_intent_physical_bytes')
                intents.append(dict(action=intent['action'],**descriptor(raw)));referenced['journal'].add(path.name)
            operations={operation['label']:operation for operation in j['operations']}
            tasks={row['name']:row for row in j['tasks']}
            for operation in j['operations']:
                receipt=operation['receipt']
                if receipt is None:continue
                path=stage/'receipts'/receipt['name'];raw=raw_file(path,32768)
                require(raw==receipt['text'].encode('ascii') and sha(raw)==receipt['sha256'],'audit_return_physical_bytes')
                value=m.decode(raw);require(value['native']==operation['native'] and value['return_status']==operation['return_status'],'audit_returned_native_tuple')
                if operation['label'] in tasks:require(value['pi']==tasks[operation['label']]['pi'],'audit_returned_pi_tuple')
                returns.append(dict(action=operation['label'],**descriptor(raw),return_status=operation['return_status'],
                    native_result_validated=True,exception_present=operation['exception'] is not None))
                referenced['receipts'].add(path.name)
            for row in j['tasks']:
                entries=row['job_admissions'];operation=operations[row['name']]
                m.core.validate_job_admissions(row,j,c,operation)
                for entry in entries:
                    q=entry['query'];receipt=entry['receipt'];physical=None
                    if receipt is not None:
                        path=stage/'job-admissions'/receipt['name'];raw=raw_file(path,16384)
                        require(raw==receipt['text'].encode('ascii') and sha(raw)==receipt['sha256'],'audit_job_receipt_physical_bytes')
                        value=m.decode(raw)
                        expected=m.core.job_admission_value(entry,row,c,j['common']['child']['job'],operation['receipt']['sha256'])
                        require(value==expected and value['admission_decision_recorded'] is False,'audit_job_raw_before_decision')
                        require(value['pi_receipt_sha256']==operation['receipt']['sha256'] and value['source_sha256']==SOURCE_SHA
                            and value['config_sha256']==sha(m.encode(c)) and value['run']==c['run'] and value['role']==row['name']
                            and value['pid']==row['pid'] and value['created']==row['created'] and value['process']==row['pi']['process'],
                            'audit_job_generation_pi_commitment')
                        physical=descriptor(raw);referenced['job-admissions'].add(path.name)
                    safe=dict(role=row['name'],sequence=entry['sequence'],purpose=entry['purpose'],physical_receipt=physical,
                        admission_passed=m.core.job_admission_passed(entry,row,c),exception_present=entry['exception'] is not None,
                        decision_after_durable_as_reported=entry['decision_qpc'] is not None,
                        decision_before_original_work_cutoff=entry['decision_qpc'] is not None and entry['decision_qpc']<m.core.work_cutoff(c))
                    if q is not None:
                        m.core.validate_job_query(q,c,process=row['pi']['process'],inner=j['common']['child']['job'])
                        r=q['outer_resource'];protected=q['protected_handles']
                        require(row['pi']['process'] in protected and row['pi']['thread'] in protected
                            and j['common']['child']['job'] in protected,'audit_live_owned_handles_in_protection_set')
                        before,after=entry['before'],entry['after']
                        safe.update(inner=typed_call(q['inner']),outer=typed_call(q['outer']),
                            resource_cleanup_verified=q['resource_cleanup_verified'],
                            outer_query_resource=dict(open_attempted=r['open_attempted'],open_returned=r['open_returned'],
                                handle_present=r['handle_value'] is not None,open_win32_error=r['open_win32_error'],
                                open_within_deadline=r['open_within_deadline'],alias_of_recorded_live_owner=r['alias'],
                                close_attempted=r['close_attempted'],close_returned=r['close_returned'],close_api_success=r['close_api_success'],
                                close_win32_error=r['close_win32_error'],close_uncertain=r['close_uncertain'],close_within_deadline=r['close_within_deadline']),
                            before_generation_matches=m.core.generation_passed(before,row,c) if before is not None else False,
                            after_generation_matches=m.core.generation_passed(after,row,c) if after is not None else False,
                            raw_held_image_generation_brackets_validated=True,
                            query_interval_ms=qpc_delta(q['inner']['before_qpc'],r['close_after_qpc'],c['frequency']))
                    else:safe['raw_job_query_available']=False
                    job_admissions.append(safe)
                task_view.append(dict(role=row['name'],assigned=row['assigned'],admitted=row['admitted'],resumed=row['resumed'],
                    exited=row['exited'],exit_code=row['exit_code'],complete_pi=all(row['pi'].values()),
                    expected_primary_available=row['expected_primary'] is not None,job_observation_count=len(entries),held_check_count=len(row['held_checks'])))
            for directory,names in referenced.items():
                path=stage/directory
                if not path.exists():require(not names,'audit_missing_evidence_directory');continue
                for file in path.iterdir():
                    raw=raw_file(file,65536)
                    if file.name not in names:unreferenced.append(dict(directory=directory,name=file.name,**descriptor(raw),qualification=False))
            for proof in j['proofs']:
                observed_proofs.append(dict(role=proof['expected_role'],qualified=proof['qualified'],resource_cleanup_verified=proof['resource_cleanup_verified'],
                    granted_access=[row['granted_access'] for row in proof['calls']] if len(proof['calls'])==4 and all(row['api_success'] for row in proof['calls']) else None))
        else:
            # Invalid reports remain original, source-bound private bytes. They
            # are not silently replaced by a forensic result or synthetic row.
            require(pub['status']=='inconclusive' and pub['observation_complete'] is False,'audit_invalid_report_not_qualified')
    else:
        require(pub['status']=='inconclusive' and pub['observation_complete'] is False and pub['recovery_required'] is True
            and pub['broker_outcome_unknown'] is True,'audit_absent_report_unknown_preserved')

    physical_files=[]
    if not result_valid:
        for directory in ('journal','receipts','job-admissions'):
            path=stage/directory
            if path.exists():
                for file in path.iterdir():physical_files.append(dict(directory=directory,name=file.name,**descriptor(raw_file(file,65536)),qualification=False))
    private=dict(plan=descriptor(planraw),config=descriptor(configraw),spec=descriptor(specraw),
        worker_report=None if report_raw is None else descriptor(report_raw),outer_launch=None if outerraw is None else descriptor(outerraw),
        forensic=descriptor(raw_file(forensicpath,m.core.MAX_REPORT)) if forensicpath.exists() else None,
        stdout=descriptor(raw_file(stage/'guard/controller.stdout',256*1024)),stderr=descriptor(raw_file(stage/'guard/controller.stderr',256*1024)))
    before_path=R/'private/psec-lpac-identity-before03-global-snapshot.json';after_path=R/'private/psec-lpac-identity-after03-global-snapshot.json'
    before=raw_file(before_path,64*1024);after=raw_file(after_path,64*1024)
    original=raw_file(R/'private/psec-lpac-identity-before01-global-snapshot.json',64*1024)
    require(descriptor(before)==descriptor(after)==descriptor(original)==dict(bytes=7378,sha256=GLOBAL_SHA)
        and before==after==original,'audit_global_snapshot_exact_original')
    old=[]
    for number,digest in OLD_PUBLIC.items():
        value,raw=json_file(R/('verification/windows-2026-10-22/psec-lpac-identity-local-'+number+'-public.json'))
        require(sha(raw)==digest,'audit_old_actual_unchanged')
        require(value['recovery_required'] is (number=='01') and value['broker_outcome_unknown'] is (number=='01'),'audit_old_outcomes_preserved')
        old.append(dict(attempt=number,**descriptor(raw),recovery_required=value['recovery_required'],broker_outcome_unknown=value['broker_outcome_unknown'],unchanged=True))

    out=dict(schema_version=1,stage='cpse-lpac-identity-actual03-independent-file-only-review',source_commit=commit,
        original_public=descriptor(pubraw),preflight=descriptor(preraw),private_commitments=private,
        source=dict(count=36,sha256=SOURCE_SHA,staged_git_lf_bytes_equal=True,diagnostic_freeze_sha256=FREEZE_SHA,files=sources),
        native=dict(source_count=6,dependency_count=31,staged_git_bytes_equal=True,files=native,
            dll=descriptor(raw_file(stage/'inputs'/m.core.DLL,8*1024*1024)),manifest=descriptor(manifestraw),
            actor=descriptor(raw_file(stage/'inputs'/m.live.ACTOR,8*1024*1024)),actor_manifest=descriptor(raw_file(stage/'inputs'/m.live.MANIFEST,256*1024))),
        observed=dict(original_status=pub['status'],original_failure=pub['failure'],original_observation_complete=pub['observation_complete'],
            original_recovery_required=pub['recovery_required'],original_broker_outcome_unknown=pub['broker_outcome_unknown'],
            original_public_identity_observation=pub['identity_observation'],worker_report_available=report is not None,
            result_validated=result_valid,result_validation_error=result_error,complete_public_projection_equal=projection_equal,
            outer_worker_exit_code=None if outer is None else outer.get('exit_code'),outer_cleanup_as_reported=None if outer is None else outer.get('cleanup'),
            inner_failure=None if not result_valid else j['failure'],
            failure_detail=None if not result_valid or j['failure_detail'] is None else {
                key:value if value is None or re.fullmatch(r'[a-zA-Z0-9_-]{1,128}',value) else None for key,value in j['failure_detail'].items()},
            tasks=task_view,proofs=observed_proofs,journal_intents=intents,returned_receipts=returns,job_admissions=job_admissions,
            unreferenced_physical_files=unreferenced,unvalidated_partial_physical_files=physical_files,
            job_query_resources_cleanup_verified=None if not result_valid else j['job_query_resources_cleanup_verified'],
            actor_resumed=False if result_valid and j['actor_resumed'] is False else None,
            network_tested=False,dns_tested=False,proxy_tested=False,product_acceptance=False),
        interpretation=[
            'Source-bound raw receipts are independently compared with their physical files and held worker report. No native API is replayed by this auditor.',
            'IsProcessInJob API-success and membership are separate recorded facts. API-false output is not interpreted, and no raw HANDLE value alone proves Job membership.',
            'The inner handle is bound to the same native Child.job argument; the outer name is bound to exact config. These observations do not establish atomic retention or fix a creation-transfer crash gap.',
            'A physical Job-admission receipt records admission_decision_recorded=false. The later decision QPC is a separate report field checked against the original work cutoff; its ordering follows the pinned source.',
            'Temporary outer QUERY handles are scoped once-close resources in the pinned source. Returned close facts are preserved; uncertain or aliased outputs do not qualify or authorize retry.',
            'A normal opaque VOID-close return only closes the caller API obligation. Job empty, module unbind, or source inference cannot prove external environment absence or broker cancellation.',
            'Missing/invalid worker reports and forensic-only records do not supply qualification, missing PIDs, or invented per-call returns. Original unknown/recovery flags remain original.',
            'This no-network identity diagnostic does not establish G/PSEC proxy or DNS isolation or any product acceptance.'
        ],
        prior_actuals=old,global_snapshot=dict(before=descriptor(before),after=descriptor(after),original=descriptor(original),
            bytes_equal=True,limited_to_four_captured_configuration_objects=True),
        actions=dict(file_hashes_git_reads=True,pure_staged_validators_imported_after_pins=True,native_api_constructed=False,
            dll_loaded=False,cpse_called=False,actor_or_network_executed=False,kernel_inventory_performed=False,
            cleanup_or_recovery_executed=False,main_or_original_evidence_modified=False))
    return out

def main():
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--source-commit',required=True)
    parser.add_argument('--public-sha256',required=True)
    parser.add_argument('--public-bytes',required=True,type=int)
    parser.add_argument('--output',type=Path,default=W/'psec-lpac-identity-actual-03-independent-review.json')
    args=parser.parse_args();require(args.output.absolute().parent==W,'audit_output_outside_work')
    require(not args.output.exists(),'audit_output_exists')
    out=audit(args)
    raw=(json.dumps(out,ensure_ascii=True,sort_keys=True,indent=2)+'\n').encode('ascii')
    # No write precedes every source/artifact/plan/raw binding and global check.
    with args.output.open('xb') as stream:stream.write(raw)
    print(json.dumps(dict(review='actual03-file-only',bytes=len(raw),sha256=sha(raw),source_count=36,
        native_pin_count=37,typed_job_receipts=len(out['observed']['job_admissions']),
        worker_report_available=out['observed']['worker_report_available'],result_validated=out['observed']['result_validated'])))

if __name__=='__main__':
    try:main()
    except SystemExit:raise
    except BaseException as error:
        print(json.dumps(dict(audit_completed=False,error=safe_label(error))))
        raise SystemExit(1)
