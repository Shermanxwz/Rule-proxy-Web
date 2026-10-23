"""Matched-capabilities three-held actual01 file-only independent audit; never constructs a native backend.

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
SOURCE_SHA='f77fdff1de75ba53d6dca04d65659deb43fd6bdc91c2feaf1c6a03ade7c008db'
FREEZE_SHA='dfdfcf9a9afd67fc9f15e0a252fdfcd672f3bcfd07417ba3a23e259a4537e762'
GLOBAL_SHA='f05d91ee76ee8a97ae5ab3bfa092167a8ee560c083255f142e6c453f2edf7ab3'
OLD_PUBLIC={
    '01':'cc562d1b045fea336c4257051faa52e63aa415d91556a4ea84f18aa363652f9c',
    '02':'100dc78f9af83445829a9f8ddf03ebe1f6bb5fc3af8f1a694e43bb78229daba2',
    '03':'75f3198b40afc5b9919fd862b66ab14b023b4b30e4ab979b742cf3e315e734f6'}

PRIOR_EVIDENCE={'psec-lpac-postassign-identity-local-01-public.json': '3862644d9d75b0e44a52c4bf2e0be063314dd6418e9e2fff6d5acca1fdaf0bd0', 'model2-dns-01-public.json': '51d8c38a9acd79c8dee629782b1e091a56bb7ccd6d2209cf28852396401b08b5', 'model2-raw-dns-02-public.json': '50e9142854e8738fafa768a4c72d4a6b489c2710f269ca4bac6e73efd2302d40', 'lpac-semantic-dns-local-02-public.json': '757ad3b8c48f7f4d6e4d6aab9feaef4915dc54b39cf1977484eed6119fcc744f'}

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
    return dict(type=type(error).__name__,label=value if re.fullmatch(r'(?:audit|cpse|bridge|guard|postassign|secaps|worker)_[a-zA-Z0-9_-]{1,120}',value) else None)
def typed_call(row):
    return {key:row[key] for key in ('attempted','returned','api_success','membership','win32_error','within_deadline')}
def qpc_delta(first,last,frequency):
    return None if first is None or last is None else round((last-first)*1000/frequency,6)


def safe_cleanup(value):
    if type(value) is not dict:return None
    return {**{key:value.get(key) if type(value.get(key)) is bool else None for key in
        ('process_exit_confirmed','job_closed','job_empty','handles_closed','close_uncertain')},
        'reported_error_count':len(value['errors']) if type(value.get('errors')) is list else None}

def transfer_observation(m,row,j,c,operation,stage,referenced):
    transfer=m.core.validate_transfer(row['transfer'],row,j,c,operation)
    guard=transfer['guard'];safe=dict(role=row['name'],transfer_passed=m.core.transfer_passed(transfer,row,c),
        exception_present=transfer['exception'] is not None,guard=None,intent=None,returned=None,
        assignment_raw=None,decision_available=transfer['decision_qpc'] is not None,
        decision_before_original_cutoff=transfer['decision_qpc'] is not None and transfer['decision_qpc']<m.core.work_cutoff(c))
    if guard is not None:
        view=dict(passed=m.core.guard_passed(guard,row,c),exception_present=guard['exception'] is not None,
            decision_available=guard['decision_qpc'] is not None,physical_receipt=None,
            before_generation_matches=m.core.generation_passed(guard['before'],row,c) if guard['before'] is not None else False,
            after_generation_matches=m.core.generation_passed(guard['after'],row,c) if guard['after'] is not None else False)
        if guard['query'] is not None:
            query=guard['query'];resource=query['outer_resource']
            view.update(inner=typed_call(query['inner']),outer=typed_call(query['outer']),
                query_resource_cleanup_verified=query['resource_cleanup_verified'],
                outer_query_close_attempted=resource['close_attempted'],outer_query_close_returned=resource['close_returned'],
                outer_query_close_api_success=resource['close_api_success'],outer_query_close_win32_error=resource['close_win32_error'],
                outer_query_close_uncertain=resource['close_uncertain'])
        if guard['receipt'] is not None:
            receipt=guard['receipt'];raw=raw_file(stage/'pretransfer'/receipt['name'],16384)
            require(raw==receipt['text'].encode('ascii') and sha(raw)==receipt['sha256'],'audit_pretransfer_physical_bytes')
            value=m.decode(raw)
            expected=m.core.job_admission_value(guard,row,c,j['common']['child']['job'],operation['receipt']['sha256'])
            require(value==expected and value['constructor_policy']==m.core.CONSTRUCTOR_POLICY and value['admission_decision_recorded'] is False,
                'audit_pretransfer_original_binding')
            view['physical_receipt']=descriptor(raw);referenced['pretransfer'].add(receipt['name'])
        safe['guard']=view
    for key,name in (('intent','intent'),('receipt','returned')):
        receipt=transfer[key]
        if receipt is None:continue
        raw=raw_file(stage/'transfers'/receipt['name'],8192)
        require(raw==receipt['text'].encode('ascii') and sha(raw)==receipt['sha256'],'audit_transfer_physical_bytes')
        value=m.decode(raw)
        require(value['scope']==c['scope'] and value['constructor_policy']==c['constructor_policy']==m.core.CONSTRUCTOR_POLICY
            and value['config_sha256']==sha(m.encode(c)) and value['source_sha256']==SOURCE_SHA
            and value['pi_receipt_sha256']==operation['receipt']['sha256'] and value['process']==row['pi']['process']
            and value['pid']==row['pid'] and value['created']==row['created'] and value['role']==row['name']
            and value['frequency']==c['frequency'] and value['root_deadline_qpc']==c['root_deadline_qpc']
            and value['deadline_qpc']==c['deadline_qpc'] and value['inner_job']==j['common']['child']['job']
            and value['outer_job']==c['guard_job_name'] and value['guard_receipt_sha256']==guard['receipt']['sha256'],
            'audit_transfer_original_pi_policy_clock_binding')
        if key=='receipt':
            require(value['intent_sha256']==transfer['intent']['sha256'] and value['raw']==transfer['raw']
                and value['admission_decision_recorded'] is False,'audit_transfer_original_return_tuple')
        safe[name]=descriptor(raw);referenced['transfers'].add(receipt['name'])
    if transfer['raw'] is not None:
        value=m.core.validate_assign(transfer['raw'],c)
        safe['assignment_raw']={**{key:value[key] for key in ('attempted','returned','return_value','api_success','win32_error','within_deadline')},
            'exception_present':value['exception'] is not None,
            'call_interval_ms':qpc_delta(value['before_qpc'],value['after_qpc'],c['frequency'])}
    return safe

def audit(args):
    require(re.fullmatch(r'[0-9a-f]{40}',args.source_commit) is not None,'audit_source_commit')
    require(re.fullmatch(r'[0-9a-f]{64}',args.public_sha256) is not None and args.public_bytes>0,'audit_public_commitment')
    commit=subprocess.check_output(['git','rev-parse','--verify',args.source_commit+'^{commit}'],cwd=R,stderr=subprocess.PIPE).strip().decode('ascii')
    require(commit==args.source_commit,'audit_source_commit_alias')
    def git(name):return subprocess.check_output(['git','show',commit+':'+name],cwd=R,stderr=subprocess.PIPE)

    pubpath=R/'verification/windows-2026-10-22/psec-lpac-matchedcaps-identity-local-01-public.json'
    prepath=pubpath.with_name('psec-lpac-matchedcaps-identity-local-01-preflight.json')
    pub,pubraw=json_file(pubpath);pre,preraw=json_file(prepath)
    require(descriptor(pubraw)==dict(bytes=args.public_bytes,sha256=args.public_sha256),'audit_original_public_bytes')
    freeze,freezeraw=json_file(W/'psec-lpac-matchedcaps-python-candidate-freeze-03.json',256*1024,inside=W)
    require(sha(freezeraw)==FREEZE_SHA and freeze['runtime_source_count']==36 and freeze['source_sha256']==SOURCE_SHA,'audit_diagnostic_freeze')

    planpath=R/'private/psec-lpac-matchedcaps-identity-recovery-plan-01.json';plan,planraw=json_file(planpath,64*1024)
    require(sha(planraw)==pub['recovery_plan_sha256'],'audit_plan_public_digest')
    require(type(plan.get('run')) is str and re.fullmatch(r'[0-9a-f]{32}',plan['run']) is not None,'audit_plan_run')
    stage=R/'private'/('local-psec-lpac-matchedcaps-identity-'+plan['run'])
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
    loader=importlib.util.spec_from_file_location('cpse_matchedcaps_actual01_file_audit',stage/'.github/windows_identity_psec_lpac_matchedcaps_bridge_local.py')
    m=importlib.util.module_from_spec(loader);loader.loader.exec_module(m)
    m.core.config_validate(c);m.validate_public(pub);m.validate_public(pre)
    require(m.core.api_version()==3 and c['scope']=='one-local-cpse-deny-all-outer-guarded-matched-secaps-identity-v1'
        and c['constructor_policy']=='bootstrap-held-primary-matched-security-capabilities-aap-only-v1','audit_matchedcaps_scope_abi3')
    require(pub['psec_network_preservation_proven'] is pre['psec_network_preservation_proven'] is False
        and not any(pub[key] for key in ('network_tested','dns_tested','proxy_tested','product_acceptance','model2_policy_compared',
            'atomic_inner_creation_proven','continuous_outer_supervision_proven','creation_transfer_crash_gap_resolved','linux_equivalence_proven')),
        'audit_no_network_or_continuity_promotion')
    require(sha(m.encode(c['source_hashes']))==SOURCE_SHA and pre['source_sha256']==SOURCE_SHA and pre['status']=='ready','audit_preflight_source')
    require(raw_file(stage/'recovery-plan.json',64*1024)==planraw,'audit_staged_plan')
    require(all(plan[key]==c[key] for key in m.core.NONCES),'audit_plan_nonces')
    m.core.validate_plan(plan,device=c['device_sha256'],source=SOURCE_SHA,actor=c['actor_sha256'],manifest=c['manifest_sha256'],
        dll=c['dll_sha256'],dll_manifest=c['dll_manifest_sha256'],processmodel=c['processmodel_sha256'],inputs=stage/'inputs')
    specraw=raw_file(stage/'spec.bin',m.core.spec.MAX_BYTES)
    m.core.spec.verify(specraw,str(stage/'inputs'))
    require(sha(specraw)==pub['spec_sha256']==plan['spec_sha256']==c['spec_sha256'],'audit_raw_spec_digest')
    require(raw_file(R/'private/psec-lpac-matchedcaps-identity-spec-01.bin',m.core.spec.MAX_BYTES)==specraw,'audit_original_spec_bytes')
    for key in ('actor','manifest','dll','dll_manifest','processmodel'):
        require(pub[key+'_sha256']==c[key+'_sha256']==plan[key+'_sha256'],'audit_artifact_plan_binding')

    manifest,manifestraw=json_file(stage/'inputs'/m.core.DLL_MANIFEST,256*1024)
    require(sha(manifestraw)==pub['dll_manifest_sha256'],'audit_frozen_matchedcaps_compile01')
    DLL_SHA=pub['dll_sha256'];MANIFEST_SHA=pub['dll_manifest_sha256']
    build=W/'psec-lpac-matchedcaps-bridge-compile-01'
    require(raw_file(build/m.core.DLL_MANIFEST,256*1024,inside=W)==manifestraw,'audit_compile_manifest_original_bytes')
    require(raw_file(build/m.core.DLL,8*1024*1024,inside=W)==raw_file(stage/'inputs'/m.core.DLL,8*1024*1024),'audit_compile_dll_original_bytes')
    native=[];pins={**manifest['sources'],**manifest['dependencies']}
    require(pins==freeze['native_pins'] and len(manifest['sources'])==6 and len(manifest['dependencies'])==31 and len(pins)==37,'audit_native_closure')
    for name,digest in pins.items():
        raw=raw_file(stage/name,512*1024);require(sha(raw)==digest and raw==git(name),'audit_native_git_bytes')
        require(raw==raw_file(W/'psec-lpac-matchedcaps-bridge-compile-01/src'/name,512*1024,inside=W),'audit_native_immutable_compile')
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
    intents=[];returns=[];job_admissions=[];transfers=[];unreferenced=[];observed_proofs=[];task_view=[];sc_observation=None;scraw=None
    if reportpath.exists():
        report_raw=raw_file(reportpath,m.core.MAX_REPORT)
        try:
            report,_=json_file(reportpath,m.core.MAX_REPORT)
        except BaseException as error:
            result_error=safe_label(error);report=None
    if report is not None:
        try:
            require(type(report) is dict and set(report)=={'schema_version','stage','config','worker_pid','worker_identity','result'}
                and type(report['schema_version']) is int and report['schema_version']==1 and report['stage']=='cpse-matchedcaps-three-held-identity-worker'
                and report['config']==c,'audit_worker_report_binding')
            require(outer is not None and outer.get('started') is True and outer.get('resumed') is True
                and outer.get('native_identity_verified_before_resume') is True and outer.get('cleanup',{}).get('process_exit_confirmed') is True
                and type(report['worker_pid']) is int and report['worker_pid']>0 and report['worker_pid']==outer.get('child_pid'),'audit_held_worker_binding')
            parent=report['worker_identity'];require(m.launcher.token_is_ordinary(parent),'audit_ordinary_worker_identity')
            j=report['result']
            m.core.validate_result(j,c,parent=parent,root=stage);result_valid=True
        except BaseException as error:result_error=safe_label(error)
        if result_valid:
            require(forensicpath.exists() and raw_file(forensicpath,m.core.MAX_REPORT)==m.encode(j),'audit_forensic_original_result')
            v=copy.deepcopy(pub);v.update(identity_observation=None,recovery_required=True,broker_outcome_unknown=True,failure=None)
            v['checks'].update(worker_bound=False,inner_complete=False)
            m.bind_report(report,c,parent,outer,v,root=stage)
            # Outer failure can downgrade a bound result, but may never be
            # reconstructed as a successful runtime from an incomplete tuple.
            for key in ('identity_observation','recovery_required','broker_outcome_unknown'):
                require(v[key]==pub[key],'audit_derived_public_observation')
            require(v['checks']['worker_bound']==pub['checks']['worker_bound'] and v['checks']['inner_complete']==pub['checks']['inner_complete'],
                'audit_derived_public_checks')
            projection_equal=v==pub
            if not projection_equal:
                require(pub['status']=='inconclusive' and pub['observation_complete'] is False and pub['failure'] is not None,'audit_outer_downgrade_only')
            referenced={name:set() for name in ('journal','receipts','job-admissions','pretransfer','transfers','security-capabilities')}
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
                    native_result_validated=True,exception_present=operation['exception'] is not None,
                    api_entered=operation['native']['api_entered'],api_returned=operation['native']['api_returned'],
                    win32_error=operation['native']['win32_error'],within_deadline=bool(operation['native']['within_deadline']),
                    precreate_failed_before_create=operation['return_status']==10,
                    security_capabilities_input_bound=value['security_capabilities_sha256']==(j['security_capabilities']['raw_sha256'] if operation['label'] in ('ac','lpac') else None)))
                referenced['receipts'].add(path.name)
            for row in j['tasks']:
                transfers.append(transfer_observation(m,row,j,c,operations[row['name']],stage,referenced))
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
                    expected_primary_available=row['expected_primary'] is not None,job_observation_count=len(entries),held_check_count=len(row['held_checks']),
                    known_no_child=m.core.known_no_child(row,c),precreate_failed_before_create=row['return_status']==10,
                    api_entered=None if row['native'] is None else row['native']['api_entered'],
                    api_returned=None if row['native'] is None else row['native']['api_returned'],
                    native_return_status=row['return_status'],
                    bootstrap_before_create_check_recorded=row['bootstrap_before_create_check_qpc'] is not None,
                    bootstrap_before_token_check_recorded=row['bootstrap_before_token_check_qpc'] is not None,
                    matched_sc_input_used=row['name'] in ('ac','lpac') and row['security_capabilities_sha256']==j['security_capabilities']['raw_sha256']))
            state=m.core.validate_security_capabilities_state(j['security_capabilities'],j,c)
            sc_observation=dict(verified=j['security_capabilities_verified'],input_available=state['value'] is not None,
                input_sha256=state['raw_sha256'],physical_receipt=None,exception_present=state['exception'] is not None,
                decision_available=state['decision_qpc'] is not None,
                decision_before_original_cutoff=state['decision_qpc'] is not None and state['decision_qpc']<m.core.work_cutoff(c),
                bootstrap_external_primary_bound=False,bootstrap_pi_receipt_bound=False,bootstrap_held_job_receipt_bound=False,
                exact_capability_catalog_and_attributes=False,encoding='canonical-sid-reconstruction')
            if state['value'] is not None:
                bootstrap=tasks['bootstrap'];value=state['value']
                require(value==m.core.security_capabilities_value(bootstrap['expected_primary'],c['capability_catalog']),'audit_sc_external_primary')
                require(sha(m.core.security_capabilities_bytes(value,c['capability_catalog']))==state['raw_sha256'],'audit_sc_canonical_sid_bytes')
                sc_observation['exact_capability_catalog_and_attributes']=True
                sc_observation['bootstrap_external_primary_bound']=True
            if state['receipt'] is not None:
                receipt=state['receipt'];scraw=raw_file(stage/'security-capabilities'/receipt['name'],16384)
                require(scraw==receipt['text'].encode('ascii') and sha(scraw)==receipt['sha256'],'audit_sc_physical_bytes')
                value=m.decode(scraw);bootstrap=tasks['bootstrap'];operation=operations['bootstrap']
                expected=m.core.security_capabilities_binding(state,j,c)
                require(all(value[key]==item for key,item in expected.items()) and value['bootstrap_primary']==bootstrap['expected_primary']
                    and value['bootstrap_pi_receipt_sha256']==operation['receipt']['sha256'],'audit_sc_bootstrap_source_identity')
                require(value['bootstrap_held_check_qpc'] in bootstrap['held_checks'] and any(entry['receipt'] is not None
                    and entry['receipt']['sha256']==value['bootstrap_job_receipt_sha256'] and m.core.job_admission_passed(entry,bootstrap,c)
                    for entry in bootstrap['job_admissions']),'audit_sc_live_bootstrap_job_binding')
                sc_observation.update(physical_receipt=descriptor(scraw),bootstrap_pi_receipt_bound=True,bootstrap_held_job_receipt_bound=True)
                referenced['security-capabilities'].add(receipt['name'])
            for directory,names in referenced.items():
                path=stage/directory
                if not path.exists():require(not names,'audit_missing_evidence_directory');continue
                for file in path.iterdir():
                    raw=raw_file(file,65536)
                    if file.name not in names:unreferenced.append(dict(directory=directory,name_commitment=sha(file.name.encode('utf-8')),**descriptor(raw),qualification=False))
            for proof in j['proofs']:
                observed_proofs.append(dict(role=proof['expected_role'],qualified=proof['qualified'],resource_cleanup_verified=proof['resource_cleanup_verified'],
                    failure=proof['failure'],complete=proof['observation_complete'],classification=proof['classification'],call_count=len(proof['calls']),
                    granted_access=[row['granted_access'] for row in proof['calls']] if len(proof['calls'])==4 and all(row['api_success'] for row in proof['calls']) else None,
                    calls=[dict(label=call['label'],attempted=call['attempted'],api_success=call['api_success'],win32_error=call['win32_error'],
                        access_status=call['access_status'],granted_access=call['granted_access'],privilege_count=call['privilege_count'],
                        within_deadline=call['within_deadline'],descriptor_verified=call['descriptor_verified'],
                        descriptor=None if call['descriptor'] is None else {key:call['descriptor'][key] for key in ('bytes','sha256')}) for call in proof['calls']]))
        else:
            # Invalid reports remain original, source-bound private bytes. They
            # are not silently replaced by a forensic result or synthetic row.
            require(pub['status']=='inconclusive' and pub['observation_complete'] is False,'audit_invalid_report_not_qualified')
    else:
        require(pub['status']=='inconclusive' and pub['observation_complete'] is False and pub['recovery_required'] is True
            and pub['broker_outcome_unknown'] is True,'audit_absent_report_unknown_preserved')

    physical_files=[]
    if not result_valid:
        for directory in ('journal','receipts','job-admissions','pretransfer','transfers','security-capabilities'):
            path=stage/directory
            if path.exists():
                for file in path.iterdir():physical_files.append(dict(directory=directory,name_commitment=sha(file.name.encode('utf-8')),**descriptor(raw_file(file,65536)),qualification=False))
    private=dict(plan=descriptor(planraw),config=descriptor(configraw),spec=descriptor(specraw),
        worker_report=None if report_raw is None else descriptor(report_raw),outer_launch=None if outerraw is None else descriptor(outerraw),
        forensic=descriptor(raw_file(forensicpath,m.core.MAX_REPORT)) if forensicpath.exists() else None,
        security_capabilities=None if scraw is None else descriptor(scraw),
        driver=descriptor(raw_file(W/'run_psec_lpac_matchedcaps_identity_01.py',128*1024,inside=W)),
        stdout=descriptor(raw_file(stage/'guard/controller.stdout',256*1024)),stderr=descriptor(raw_file(stage/'guard/controller.stderr',256*1024)))
    before_path=R/'private/psec-lpac-matchedcaps-identity-before-matchedcaps01-global-snapshot.json';after_path=R/'private/psec-lpac-matchedcaps-identity-after-matchedcaps01-global-snapshot.json'
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
    prior_evidence=[]
    for name,digest in PRIOR_EVIDENCE.items():
        path=R/'verification/windows-2026-10-22'/name;value,raw=json_file(path)
        require(sha(raw)==digest and raw==git('verification/windows-2026-10-22/'+name),'audit_prior_dns_and_postassign_evidence_unchanged')
        require(value.get('product_acceptance') is False,'audit_prior_evidence_not_product_acceptance')
        prior_evidence.append(dict(name=name,**descriptor(raw),status=value.get('status'),failure=value.get('failure'),
            product_acceptance=False,unchanged=True))

    out=dict(schema_version=1,stage='cpse-lpac-matchedcaps-identity-actual01-independent-file-only-review',source_commit=commit,
        original_public=descriptor(pubraw),preflight=descriptor(preraw),private_commitments=private,
        source=dict(count=36,sha256=SOURCE_SHA,staged_git_lf_bytes_equal=True,promotion_freeze_sha256=FREEZE_SHA,files=sources),
        native=dict(source_count=6,dependency_count=31,staged_git_bytes_equal=True,files=native,
            dll=descriptor(raw_file(stage/'inputs'/m.core.DLL,8*1024*1024)),manifest=descriptor(manifestraw),
            actor=descriptor(raw_file(stage/'inputs'/m.live.ACTOR,8*1024*1024)),actor_manifest=descriptor(raw_file(stage/'inputs'/m.live.MANIFEST,256*1024))),
        observed=dict(original_status=pub['status'],original_failure=pub['failure'],original_observation_complete=pub['observation_complete'],
            original_recovery_required=pub['recovery_required'],original_broker_outcome_unknown=pub['broker_outcome_unknown'],
            original_public_identity_observation=pub['identity_observation'],worker_report_available=report is not None,
            worker_report_file_present=report_raw is not None,
            result_validated=result_valid,result_validation_error=result_error,complete_public_projection_equal=projection_equal,
            outer_worker_exit_code=None if outer is None else outer.get('exit_code'),outer_cleanup_as_reported=None if outer is None else safe_cleanup(outer.get('cleanup')),
            inner_failure=None if not result_valid else j['failure'],
            failure_detail=None if not result_valid or j['failure_detail'] is None else dict(type=j['failure_detail']['type'],operation_present=j['failure_detail']['operation'] is not None),
            tasks=task_view,proofs=observed_proofs,security_capabilities=sc_observation,journal_intents=intents,returned_receipts=returns,job_admissions=job_admissions,transfers=transfers,
            unreferenced_physical_files=unreferenced,unvalidated_partial_physical_files=physical_files,
            job_query_resources_cleanup_verified=None if not result_valid else j['job_query_resources_cleanup_verified'],
            actor_resumed=False if result_valid and j['actor_resumed'] is False else None,
            network_tested=False,dns_tested=False,proxy_tested=False,product_acceptance=False,psec_network_preservation_proven=False),
        interpretation=[
            'Source-bound raw receipts are independently compared with their physical files and held worker report. No native API is replayed by this auditor.',
            'IsProcessInJob API-success and membership are separate recorded facts. API-false output is not interpreted, and no raw HANDLE value alone proves Job membership.',
            'The separate policy deliberately omits JOB_LIST. Durable pretransfer outer-true/inner-false and the original Assign BOOL/error/clock are distinct from the subsequent exact two-Job identity admission.',
            'No finite membership snapshot or successful identity matrix establishes continuous supervision from creation or a resolved transfer crash gap.',
            'A physical Job-admission receipt records admission_decision_recorded=false. The later decision QPC is a separate report field checked against the original work cutoff; its ordering follows the pinned source.',
            'Temporary outer QUERY handles are scoped once-close resources in the pinned source. Returned close facts are preserved; uncertain or aliased outputs do not qualify or authorize retry.',
            'A normal opaque VOID-close return only closes the caller API obligation. Job empty, module unbind, or source inference cannot prove external environment absence or broker cancellation.',
            'Missing/invalid worker reports and forensic-only records do not supply qualification, missing PIDs, or invented per-call returns. Original unknown/recovery flags remain original.',
            'Bootstrap is an external held-primary source, never a comparison AccessCheck arm. Measured AC/LPAC use identical canonical SID bytes and attributes; only AAP0/1 differs in the pinned constructor.',
            'Typed precreate status10 means the source reports attributes setup/update failure before Create, API-entered0/returned0 and PI empty. It is not a failed Create return, and late/partial/unknown cases never qualify.',
            'A partial proof is retained as its actual calls; an incomplete or failed matrix is never filled into a synthetic four-mask vector.',
            'This no-network deny-all identity diagnostic does not establish preservation of CPSE network policy or G/PSEC proxy/DNS isolation or product acceptance.'
        ],
        prior_actuals=old,prior_evidence=prior_evidence,global_snapshot=dict(before=descriptor(before),after=descriptor(after),original=descriptor(original),
            bytes_equal=True,limited_to_four_captured_configuration_objects=True),
        actions=dict(file_hashes_git_reads=True,pure_staged_validators_imported_after_pins=True,native_api_constructed=False,
            dll_loaded=False,cpse_called=False,actor_or_network_executed=False,kernel_inventory_performed=False,
            cleanup_or_recovery_executed=False,main_or_original_evidence_modified=False))
    out['constructor_policy']=m.core.CONSTRUCTOR_POLICY
    out['atomic_inner_creation_proven']=False
    out['continuous_outer_supervision_proven']=False
    out['creation_transfer_crash_gap_resolved']=False
    out['psec_network_preservation_proven']=False
    return out

def main():
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--source-commit',required=True)
    parser.add_argument('--public-sha256',required=True)
    parser.add_argument('--public-bytes',required=True,type=int)
    parser.add_argument('--output',type=Path,default=W/'psec-lpac-matchedcaps-identity-actual-01-independent-review.json')
    args=parser.parse_args();require(args.output.absolute().parent==W,'audit_output_outside_work')
    require(not args.output.exists(),'audit_output_exists')
    out=audit(args)
    raw=(json.dumps(out,ensure_ascii=True,sort_keys=True,indent=2)+'\n').encode('ascii')
    # No write precedes every source/artifact/plan/raw binding and global check.
    with args.output.open('xb') as stream:stream.write(raw)
    print(json.dumps(dict(review='matchedcaps-actual01-file-only',bytes=len(raw),sha256=sha(raw),source_count=36,
        native_pin_count=37,typed_job_receipts=len(out['observed']['job_admissions']),
        worker_report_available=out['observed']['worker_report_available'],result_validated=out['observed']['result_validated'])))

if __name__=='__main__':
    try:main()
    except SystemExit:raise
    except BaseException as error:
        print(json.dumps(dict(audit_completed=False,error=safe_label(error))))
        raise SystemExit(1)
        raise SystemExit(1)
