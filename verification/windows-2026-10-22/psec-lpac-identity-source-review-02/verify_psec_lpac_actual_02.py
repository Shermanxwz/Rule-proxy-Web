"""Independent actual02 file-only audit. Never constructs a native backend."""
import copy
import hashlib
import importlib.util
import json
from pathlib import Path
import subprocess

W=Path(__file__).resolve().parent
R=W/'Rule-proxy-Web'
COMMIT='b269c78eef15b6f71bdae5a5ee631a4e8a34ce9e'
def sha(raw):return hashlib.sha256(raw).hexdigest()
def blob(raw):return hashlib.sha1(b'blob '+str(len(raw)).encode()+b'\0'+raw).hexdigest()
def record(path):
    raw=path.read_bytes();return dict(bytes=len(raw),sha256=sha(raw))
def read(path):return json.loads(path.read_bytes())
def git(name):return subprocess.check_output(['git','show',COMMIT+':'+name],cwd=R)
pubpath=R/'verification/windows-2026-10-22/psec-lpac-identity-local-02-public.json'
prepath=pubpath.with_name('psec-lpac-identity-local-02-preflight.json')
pub=read(pubpath)
assert record(pubpath)==dict(bytes=2083,sha256='100dc78f9af83445829a9f8ddf03ebe1f6bb5fc3af8f1a694e43bb78229daba2')
planpath=R/'private/psec-lpac-identity-recovery-plan-02.json';p=read(planpath)
assert record(planpath)['sha256']==pub['recovery_plan_sha256']
stage=R/'private'/('local-psec-lpac-identity-'+p['run']);configpath=stage/'worker-config.json';c=read(configpath)
assert c['source_sha256']==pub['source_sha256']=='7de9968d0984cc7304951ba220d806fea74e998c0a623beddd870a0eb1e0f0ba'
assert len(c['source_hashes'])==36 and c['recovery_plan_sha256']==record(planpath)['sha256']
sources=[]
for name,digest in c['source_hashes'].items():
    raw=(stage/name).read_bytes();assert sha(raw)==digest and raw==git(name)
    sources.append(dict(path=name,bytes=len(raw),sha256=digest,git_blob=blob(raw)))
loader=importlib.util.spec_from_file_location('cpse_actual02_file_audit',stage/'.github/windows_identity_psec_lpac_bridge_local.py')
m=importlib.util.module_from_spec(loader);loader.loader.exec_module(m)
m.core.config_validate(c);m.validate_public(pub);m.validate_public(read(prepath))
assert sha(m.encode(c['source_hashes']))==c['source_sha256']
assert all(p[k]==c[k] for k in m.core.NONCES)
assert (stage/'recovery-plan.json').read_bytes()==planpath.read_bytes()
specraw=(stage/'spec.bin').read_bytes();m.core.spec.verify(specraw,str(stage/'inputs'));assert sha(specraw)==pub['spec_sha256']==p['spec_sha256']
manifest=read(stage/'inputs'/m.core.DLL_MANIFEST);native=[]
for name,digest in {**manifest['sources'],**manifest['dependencies']}.items():
    raw=(stage/name).read_bytes();assert sha(raw)==digest and raw==git(name)
    native.append(dict(path=name,bytes=len(raw),sha256=digest,git_blob=blob(raw)))
assert len(native)==37
m.core.verify_manifest(stage/'inputs'/m.core.DLL,stage/'inputs'/m.core.DLL_MANIFEST,pub['dll_sha256'],pub['dll_manifest_sha256'],root=stage)
m.live.verify_actor(stage/'inputs'/m.live.ACTOR,stage/'inputs'/m.live.MANIFEST,pub['actor_sha256'],pub['manifest_sha256'],root=stage)
reportpath=stage/'worker-report.json';report=read(reportpath);j=report['result']
assert record(reportpath)==dict(bytes=19223,sha256='925929988a216d9a700dc63d44af86e32cf1806aa011ee93eb291264ac53e658')
assert set(report)=={'schema_version','stage','config','worker_pid','worker_identity','result'} and report['config']==c
forensicpath=stage/'worker-result-forensic.json';assert forensicpath.read_bytes()==m.encode(j)
parent=report['worker_identity'];m.core.validate_result(j,c,parent=parent)
outerpath=stage/'outer-launch-report.json';outer=read(outerpath);assert record(outerpath)['sha256']==pub['outer_launch_sha256']
assert report['worker_pid']==outer['child_pid']
assert outer['started'] is outer['resumed'] is outer['native_identity_verified_before_resume'] is True
assert outer['exit_code']==0 and outer['timed_out'] is False
assert outer['cleanup']==dict(close_uncertain=False,errors=[],handles_closed=True,job_closed=True,job_empty=True,process_exit_confirmed=True)
v=copy.deepcopy(pub);v.update(identity_observation=None,recovery_required=True,broker_outcome_unknown=True,failure=None)
v['checks'].update(worker_bound=False,inner_complete=False)
m.bind_report(report,c,parent,outer,v);assert v==pub
assert j['failure']=='admission' and j['failure_detail']==dict(type='GateFailure',operation=None,message='child_not_in_owned_job')
assert j['common_inputs_verified'] is False and j['proofs']==[] and len(j['tasks'])==1
task=j['tasks'][0]
assert task['name']=='ac' and task['assigned'] is task['admitted'] is task['resumed'] is False
assert task['expected_primary'] is None and task['exited'] is True and task['exit_code']==1
assert task['created']>0xffffffff and task['created']<=0xffffffffffffffff and all(task['pi'].values())
assert len(j['operations'])==5 and [x['label'] for x in j['operations']]==['bind','create','ac','close','unbind']
ops={x['label']:x for x in j['operations']}
assert all(m.core.native_ok(x['native']) and x['return_status']==0 and x['exception'] is None for x in j['operations'])
assert ops['bind']['native']['hresult']==0 and ops['bind']['native']['support_flags']==15 and ops['bind']['native']['schema_minor']==1
assert ops['create']['native']['hresult']==0 and ops['create']['native']['environment_state']==2
assert ops['close']['native']['hresult_valid']==0 and ops['close']['native']['close_invoked_once']==ops['close']['native']['close_returned_normally']==1
assert ops['unbind']['native']['module_close_attempted']==ops['unbind']['native']['module_close_confirmed']==1
actions=['bind','create','ac','stop','close','unbind'];assert [x['action'] for x in j['intents']]==actions
journals=[];receipts=[]
for intent in j['intents']:
    path=stage/'journal'/intent['name'];assert path.read_bytes()==intent['text'].encode('ascii') and record(path)['sha256']==intent['sha256']
    journals.append(dict(action=intent['action'],**record(path)))
for op in j['operations']:
    receipt=op['receipt'];path=stage/'receipts'/receipt['name']
    assert path.read_bytes()==receipt['text'].encode('ascii') and record(path)['sha256']==receipt['sha256']
    raw=read(path);assert raw['native']==op['native'] and raw['return_status']==op['return_status']
    if op['label']=='ac':assert raw['pi']==task['pi']
    receipts.append(dict(action=op['label'],**record(path),native_result_validated=True))
assert len(list((stage/'journal').iterdir()))==6 and len(list((stage/'receipts').iterdir()))==5
assert all(j[k] is True for k in ('observer_resources_cleanup_verified','child_resources_cleanup','workload_cleanup','workload_job_empty','api_obligations_closed','module_unbound'))
assert j['opaque_outcome_unknown'] is False and pub['recovery_required'] is pub['broker_outcome_unknown'] is False
assert (stage/'guard/controller.stdout').read_bytes()==(stage/'guard/controller.stderr').read_bytes()==b''
before=R/'private/psec-lpac-identity-before02-global-snapshot.json';after=R/'private/psec-lpac-identity-after02-global-snapshot.json'
assert before.read_bytes()==after.read_bytes() and record(before)==dict(bytes=7378,sha256='f05d91ee76ee8a97ae5ab3bfa092167a8ee560c083255f142e6c453f2edf7ab3')
oldpath=R/'verification/windows-2026-10-22/psec-lpac-identity-local-01-public.json';old=read(oldpath)
assert record(oldpath)['sha256']=='cc562d1b045fea336c4257051faa52e63aa415d91556a4ea84f18aa363652f9c'
assert old['recovery_required'] is old['broker_outcome_unknown'] is True
source=(stage/'.github/windows_identity_psec_lpac_bridge.py').read_text()
assert "self.api.verify_job(self.job,process);self.api.verify_outer(self.c['guard_job_name'],process);row['assigned']=True" in source
shared=(stage/'.github/windows_identity_ordinary_launcher.py').read_text()
assert 'if not value.value:' in shared and 'raise GateFailure("child_not_in_owned_job")' in shared
out=dict(schema_version=1,stage='cpse-lpac-identity-actual02-independent-file-only-review',source_commit=COMMIT,
    conclusion='Source-bound API/resource cleanup is verified, but the first arm failed a Job membership gate before token/admission. The tested Job cannot be distinguished from this record.',
    public=record(pubpath),preflight=record(prepath),private_commitments=dict(plan=record(planpath),config=record(configpath),spec=record(stage/'spec.bin'),
        worker_report=record(reportpath),worker_result_forensic=record(forensicpath),outer_launch=record(outerpath),
        stdout=record(stage/'guard/controller.stdout'),stderr=record(stage/'guard/controller.stderr')),
    source=dict(count=36,sha256=c['source_sha256'],staged_git_bytes_equal=True,files=sources),
    native=dict(source_count=6,dependency_count=31,staged_git_bytes_equal=True,files=native,dll=record(stage/'inputs'/m.core.DLL),
        manifest=record(stage/'inputs'/m.core.DLL_MANIFEST),actor=record(stage/'inputs'/m.live.ACTOR),actor_manifest=record(stage/'inputs'/m.live.MANIFEST)),
    observed=dict(status='inconclusive',failure='admission',safe_failure_type='GateFailure',safe_failure_label='child_not_in_owned_job',
        complete_private_report_validated=True,forensic_exact_value_and_bytes_equal=True,public_projection_equal=True,
        worker_bound=True,worker_exit_code=0,outer_cleanup_verified=True,bind_hresult=0,support_flags=15,schema_version=[1,1],
        environment_create_hresult=0,environment_state_after_create='owned-known',first_constructor_return_status=0,
        first_constructor_complete_pi=True,first_task_assigned=False,first_task_admitted=False,first_primary_observation_available=False,
        creation_time_fits_u64_and_exceeds_u32=True,first_task_exited=True,first_task_exit_code=1,
        second_arm_attempted=False,accesscheck_proof_count=0,actor_resumed=False,
        journal_actions=actions,journal_intents=journals,returned_receipts=receipts,
        opaque_void_close_invoked_once=True,opaque_void_close_returned_normally=True,module_unbind_returned_normally=True,
        known_resources_cleanup_verified=True,recovery_required=False,opaque_outcome_unknown=False,
        external_environment_absence_verified=False,broker_cancellation_proven=False,
        network_tested=False,dns_tested=False,proxy_tested=False,product_acceptance=False),
    job_failure_boundary=dict(isprocessinjob_call_succeeded_but_result_false=True,
        failed_job='unknown-inner-or-named-outer',both_jobs_use_same_error_label=True,
        assigned_flag_set_only_after_both_checks=True,no_separate_membership_results_saved=True,
        interpretation='The first failed membership output may be the inner Job; if inner succeeded the named outer Job may instead have failed. No recorded tuple distinguishes them. No Job assignment is waived.'),
    cleanup_interpretation=[
        'The raw task reports held exit code1 and all owner resource cleanup flags are true; the raw outer report records worker exit0 and Job/handle cleanup.',
        'Source cleanup treats assigned=False as an unassigned partial owner and requests exact held-process stop in addition to Job cleanup. The individual stop API return is not separately persisted.',
        'VOID close and unbind have their own original returned raw receipts; these settle known caller API obligations, not external environment absence or broker cancellation.',
        'If a child were outside both Jobs, an outer Job kill alone would not prove that child stopped on caller crash. This actual normal cleanup does not establish that untested crash property.'
    ],
    old_actual01=dict(public=record(oldpath),broker_outcome_unknown=True,recovery_required=True,unchanged=True),
    global_snapshot=dict(before=record(before),after=record(after),bytes_equal=True,limited_to_four_captured_configuration_objects=True),
    next_observation_boundary=[
        'Preserve per-Job IsProcessInJob API success, output membership and immediate error separately for exact inner and named outer Jobs before admission.',
        'Bind each observation to original config/source/native-returned PI commitment, held generation/image, original F/T0/D and once-closed temporary query handle.',
        'Collect both read-only Job observations even if the first is false, then retain the exact same all-true admission gate; no post-create auto-assignment, resume, fallback or capability relaxation.',
        'Do not assume parent Job inheritance across a security-environment/broker path, and do not assume TERMINATE_ON_CLOSE or caller death closes the external environment without primary semantics and a separate qualified mechanism.',
        'Any future actual must first address the possible creation-to-external-owner crash gap if atomic Job coverage is not established; normal exact-process cleanup is insufficient evidence of that property.'
    ],
    actions=dict(file_hashes_git_reads=True,pure_staged_validators_imported_after_pins=True,native_api_constructed=False,
        dll_loaded=False,cpse_called=False,actor_or_network_executed=False,kernel_inventory_performed=False,
        cleanup_or_recovery_executed=False,main_or_original_evidence_modified=False))
path=W/'psec-lpac-identity-actual-02-independent-review.json';assert not path.exists()
raw=(json.dumps(out,sort_keys=True,indent=2)+'\n').encode();path.write_bytes(raw)
print(json.dumps(dict(review='actual02-failed-job-gate-cleanup-known',bytes=len(raw),sha256=sha(raw),sources=36,native_closure=37,intents=6,returns=5)))
