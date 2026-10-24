"""File-only partial actual audit; no native/CPSE/cleanup API is constructed."""
import hashlib
import importlib.util
import json
from pathlib import Path
import re
import subprocess

W=Path(__file__).resolve().parent
R=W/'Rule-proxy-Web'
COMMIT='1c83029245e889b2c950ca5dbaa0da675a287c09'
def sha(raw):return hashlib.sha256(raw).hexdigest()
def blob(raw):return hashlib.sha1(b'blob '+str(len(raw)).encode()+b'\0'+raw).hexdigest()
def record(path):
    raw=path.read_bytes();return dict(bytes=len(raw),sha256=sha(raw))
def read(path):return json.loads(path.read_bytes())
def git(name):return subprocess.check_output(['git','show',COMMIT+':'+name],cwd=R)
pubpath=R/'verification/windows-2026-10-22/psec-lpac-identity-local-01-public.json'
prepath=pubpath.with_name('psec-lpac-identity-local-01-preflight.json')
pub=read(pubpath);pre=read(prepath)
assert record(pubpath)==dict(bytes=1660,sha256='cc562d1b045fea336c4257051faa52e63aa415d91556a4ea84f18aa363652f9c')
assert pub['broker_outcome_unknown'] is pub['recovery_required'] is True
assert pub['status']=='inconclusive' and pub['failure']=='report' and pub['identity_observation'] is None
assert pub['observation_complete'] is False and pub['checks']['worker_bound'] is False
planpath=R/'private/psec-lpac-identity-recovery-plan-01.json'
plan=read(planpath);assert record(planpath)['sha256']==pub['recovery_plan_sha256']
stage=R/'private'/('local-psec-lpac-identity-'+plan['run'])
configpath=stage/'worker-config.json';c=read(configpath)
assert c['source_sha256']==pub['source_sha256']=='7dd12aaf5c8727c325e184f69393072e13e0b1772aa1be03318adf7e1d77951a'
assert c['recovery_plan_sha256']==record(planpath)['sha256'] and len(c['source_hashes'])==36
sources=[]
for name,digest in c['source_hashes'].items():
    raw=(stage/name).read_bytes();original=git(name)
    assert raw==original and sha(raw)==digest
    sources.append(dict(path=name,bytes=len(raw),sha256=digest,git_blob=blob(raw)))
# All 36 source bytes have been checked against the specified Git commit before
# these API-free definitions/validators are imported. No NativeAPI is instantiated.
loader=importlib.util.spec_from_file_location('cpse_actual01_file_audit',stage/'.github/windows_identity_psec_lpac_bridge_local.py')
module=importlib.util.module_from_spec(loader);loader.loader.exec_module(module)
module.core.config_validate(c);module.validate_public(pub);module.validate_public(pre)
assert module.sha(module.encode(c['source_hashes']))==c['source_sha256']
assert all(plan[k]==c[k] for k in module.core.NONCES)
assert not (stage/'worker-report.json').exists()
assert (stage/'recovery-plan.json').read_bytes()==planpath.read_bytes()
specraw=(stage/'spec.bin').read_bytes();module.core.spec.verify(specraw,str(stage/'inputs'))
assert sha(specraw)==pub['spec_sha256']==plan['spec_sha256']
manifest=read(stage/'inputs'/module.core.DLL_MANIFEST)
native=[]
for name,digest in {**manifest['sources'],**manifest['dependencies']}.items():
    raw=(stage/name).read_bytes();original=git(name)
    assert raw==original and sha(raw)==digest
    native.append(dict(path=name,bytes=len(raw),sha256=digest,git_blob=blob(raw)))
assert len(native)==37 and len(manifest['sources'])==6 and len(manifest['dependencies'])==31
module.core.verify_manifest(stage/'inputs'/module.core.DLL,stage/'inputs'/module.core.DLL_MANIFEST,
    pub['dll_sha256'],pub['dll_manifest_sha256'],root=stage)
module.live.verify_actor(stage/'inputs'/module.live.ACTOR,stage/'inputs'/module.live.MANIFEST,
    pub['actor_sha256'],pub['manifest_sha256'],root=stage)
outerpath=stage/'outer-launch-report.json';outer=read(outerpath)
assert record(outerpath)['sha256']==pub['outer_launch_sha256']
assert outer['started'] is outer['resumed'] is outer['native_identity_verified_before_resume'] is True
assert outer['exit_code']==1 and outer['timed_out'] is False
assert outer['cleanup']==dict(close_uncertain=False,errors=[],handles_closed=True,job_closed=True,job_empty=True,process_exit_confirmed=True)
worker_identity=outer['child_identity']
assert set(worker_identity)=={'admin_attributes','appcontainer','appcontainer_sid_absent','capability_count','elevated',
    'elevation_type','integrity_rid','same_session','same_user','session_id','token_type','ui_access'}
assert worker_identity['appcontainer'] is worker_identity['elevated'] is worker_identity['ui_access'] is False
assert worker_identity['appcontainer_sid_absent'] is worker_identity['same_session'] is worker_identity['same_user'] is True
assert worker_identity['token_type']==1 and worker_identity['capability_count']==0 and worker_identity['integrity_rid']==8192
assert pub['checks']['guard'] is pub['checks']['worker_exit'] is pub['checks']['outer_cleanup'] is True
expected_actions=['bind','create','ac','stop','close','unbind']
journal=[];last=c['start_qpc']
for index,path in enumerate(sorted((stage/'journal').iterdir())):
    row=read(path);action=expected_actions[index]
    assert path.name=='%02d-%s.json'%(index,action)
    assert set(row)=={'schema_version','scope','run','config_sha256','action','frequency','deadline_qpc','qpc'}
    assert row==dict(schema_version=1,scope=c['scope'],run=c['run'],config_sha256=sha(module.encode(c)),
        action=action,frequency=c['frequency'],deadline_qpc=c['deadline_qpc'],qpc=row['qpc'])
    assert type(row['qpc']) is int and last<=row['qpc']<c['deadline_qpc'];last=row['qpc']
    if action in ('bind','create','ac'):assert row['qpc']<module.core.work_cutoff(c)
    journal.append(dict(action=action,**record(path),intent_only=True))
assert len(journal)==6
stderrpath=stage/'guard/controller.stderr';stderr=stderrpath.read_bytes()
assert len(stderr)<=65536
text=stderr.decode('utf-8','strict')
assert text.splitlines()[-1]=='ValueError: cpse_task_number'
frames=[]
for name,line,function in re.findall(r'File "([^"]+)", line (\d+), in ([A-Za-z_][A-Za-z_0-9]*)',text):
    frames.append(dict(source_file=Path(name).name,line=int(line),function=function))
assert frames[-2:]==[dict(source_file='windows_identity_psec_lpac_bridge.py',line=441,function='validate_result'),
    dict(source_file='windows_identity_model2_live.py',line=64,function='require')]
assert (stage/'guard/controller.stdout').read_bytes()==b'' and (stage/'guard/controller.stdin').read_bytes()==b''
core_source=(stage/'.github/windows_identity_psec_lpac_bridge.py').read_text()
live_source=(stage/'.github/windows_identity_model2_live.py').read_text()
assert "for key in ('pid','created','exit_code'):require(row[key] is None or live.integer(row[key],0 if key=='exit_code' else 1),'cpse_task_number')" in core_source
assert 'def integer(value, minimum=0, maximum=0xffffffff):' in live_source
assert core_source.index('finally:self.cleanup()')<core_source.index("self.j['tasks']=[")
before=R/'private/psec-lpac-identity-before01-global-snapshot.json'
after=R/'private/psec-lpac-identity-after01-global-snapshot.json'
assert before.read_bytes()==after.read_bytes() and before.stat().st_size==7378
assert record(before)['sha256']=='f05d91ee76ee8a97ae5ab3bfa092167a8ee560c083255f142e6c453f2edf7ab3'
out=dict(schema_version=1,stage='cpse-lpac-identity-actual01-independent-partial-review',source_commit=COMMIT,
    conclusion='Original inconclusive/unknown/recovery-required result is retained. The report validator failed after inner execute/cleanup, and no raw final worker result exists.',
    public=record(pubpath),preflight=record(prepath),private_commitments=dict(plan=record(planpath),config=record(configpath),
        spec=record(stage/'spec.bin'),outer_launch=record(outerpath),stdout=record(stage/'guard/controller.stdout'),
        stdin=record(stage/'guard/controller.stdin'),stderr=record(stderrpath)),
    source=dict(count=36,sha256=c['source_sha256'],staged_git_bytes_equal=True,files=sources),
    native=dict(source_count=6,dependency_count=31,staged_git_bytes_equal=True,files=native,
        dll=record(stage/'inputs'/module.core.DLL),manifest=record(stage/'inputs'/module.core.DLL_MANIFEST),
        actor=record(stage/'inputs'/module.live.ACTOR),actor_manifest=record(stage/'inputs'/module.live.MANIFEST)),
    original_result=dict(status='inconclusive',failure='report',worker_bound=False,identity_observation=None,
        observation_complete=False,broker_outcome_unknown=True,recovery_required=True,external_environment_absence_verified=False,
        broker_cancellation_proven=False,network_tested=False,dns_tested=False,proxy_tested=False,product_acceptance=False),
    observed_raw_file_facts=dict(final_worker_report_present=False,ordinary_worker_started_resumed_and_held_admitted=True,
        worker_exit_code=1,outer_timed_out=False,outer_process_exit_and_job_empty_and_handles_closed=True,
        journal_actions=expected_actions,journal_intents=journal,stderr_failure=dict(exception_type='ValueError',safe_label='cpse_task_number',frames=frames),
        stdout_empty=True,stdin_empty=True,raw_final_api_results_available=False,raw_final_child_rows_available=False,
        raw_accesscheck_proofs_available=False,lpac_intent_present=False,observer_intent_present=False),
    report_defect=dict(confirmed_code_defect='created FILETIME is validated using live.integer default maximum0xffffffff',
        actual_exception='cpse_task_number',phase='post-execute final private-result validation',
        scope='The reported serialization/validation failure is known. It does not establish the earlier reason why the inner AC arm stopped before the LPAC intent.'),
    source_controlflow_inferences=[
        dict(id='ac_after_environment_admission',basis='Exact committed execute path only enters arm after the bind and create predicates pass.',
            interpretation='The AC intent is source-derived evidence of reaching those prior predicates; it is not a separately saved raw HRESULT or opaque-handle receipt.'),
        dict(id='stop_after_known_process_output',basis='The stop intent is emitted when an owned row has a non-null process output and has not been observed exited.',
            interpretation='At least one process output participated in cleanup; no full child identity, token, creation-time value or admission result can be reconstructed from the intent alone.'),
        dict(id='close_preconditions_reached',basis='The close call is only entered after owner child/resource cleanup and inner Job-empty gates in this source.',
            interpretation='This is control-flow inference; absent final result prevents independent revalidation of those inner values.'),
        dict(id='unbind_after_void_close_gate',basis='The unbind intent can only follow a returned close result accepted for invoked_once/returned_normally/no-opaque-unknown in this source.',
            interpretation='This supports a source-control-flow inference that the close gate passed. It is not a durable raw close return, an unbind return receipt, external absence or broker cancellation.'),
        dict(id='no_second_arm_or_observer_path',basis='No LPAC/observe intent exists, while every such mutation is preceded by CREATE_NEW durable intent.',
            interpretation='No evidence supports a completed pair or AccessCheck classification. The never-resume/no-network source path is retained; no wire-negative experiment was performed.')
    ],
    reconciliation=dict(file_only=True,new_kernel_or_api_inventory_performed=False,
        source_bound_outer_cleanup_receipt_verified=True,source_bound_unbind_intent_verified=True,
        original_opaque_resource_reopened=False,original_opaque_close_retried=False,
        original_environment_absence_verified=False,original_recovery_requirement_cleared=False,
        supported_opaque_reopen_or_reconcile_api_identified=False),
    conditional_next_independent_diagnostic=dict(reasonable_to_proceed_under_explicit_parent_policy=True,
        original_unknown_must_remain=True,conditions=[
            'Archive original public/preflight/raw commitments and all six intent files without creating a synthetic worker report or API/child/proof results.',
            'Keep original recovery_required and broker_outcome_unknown true; later reconciliation must be separately dated and must not rewrite this result.',
            'Use separately reviewed and committed source with FILETIME/HANDLE widths and partial-report preservation fixed; expose any earlier AC admission failure honestly.',
            'Use a fresh plan, fresh run/nonces, fresh private stage and corresponding fresh canonical spec bytes; create at most one new environment with the same declared independent deny-all semantics.',
            'Do not reopen, reuse, numerically replay or retry-close the original opaque value; no supported such recovery API is established.',
            'Retain original120/115s clock, atomic Jobs, both never-resumed arms, held identity and fixed capability gates, and VOID close ordering; no fallback or capability/spec relaxation.',
            'No network, standalone profile/ACL workaround, driver, service restart or global settings change. Any new unknown is preserved and does not trigger automatic retry.',
            'The new run is independent diagnostic evidence, not proof the old broker resource is absent or that a Model2 proxy policy is repaired.'
        ]),
    global_snapshot=dict(before=record(before),after=record(after),bytes_equal=True,
        interpretation='Only the four captured configuration objects at these snapshots are compared; this is not a complete or continuous global-state absence proof.'),
    checks=dict(public_hash_and_original_unknown_preserved=True,source36_and_native37_git_bytes_equal=True,
        spec_plan_config_and_intent_bindings_equal=True,outer_raw_sha_matches_public=True,stderr_source_location_verified=True,
        final_worker_report_not_fabricated=True,no_actual_api_or_token_values_in_this_projection=True),
    actions=dict(file_hash_git_blob_reads=True,pure_staged_validators_imported_after_pins=True,native_api_constructed=False,
        dll_loaded=False,cpse_called=False,actor_or_network_executed=False,kernel_inventory_performed=False,
        cleanup_or_recovery_executed=False,main_or_original_evidence_modified=False))
path=W/'psec-lpac-identity-actual-01-independent-review.json';assert not path.exists()
raw=(json.dumps(out,sort_keys=True,indent=2)+'\n').encode();path.write_bytes(raw)
print(json.dumps(dict(review='partial-original-unknown-preserved',bytes=len(raw),sha256=sha(raw),source_count=36,native_closure_count=37,journal_intents=6)))
