"""Narrow immutable source02 review; no wrapper/native/API execution."""
import hashlib
import importlib.util
import json
from pathlib import Path
import subprocess

W=Path(__file__).resolve().parent
C=W/'psec-lpac-identity-bridge-candidate-02'
R=W/'Rule-proxy-Web'
BASELINE='1c83029245e889b2c950ca5dbaa0da675a287c09'
def sha(raw):return hashlib.sha256(raw).hexdigest()
def record(path):
    raw=path.read_bytes();return dict(bytes=len(raw),sha256=sha(raw))
freeze=W/'psec-lpac-python-candidate-freeze-02.json'
assert record(freeze)['sha256']=='41b431c5001fe393a395c18024f2fc15dd89458b07e9d1c038d62d763e9fe96e'
f=json.loads(freeze.read_bytes());assert f['baseline_commit']==BASELINE
rows=[]
for name,row in f['files'].items():
    assert record(C/name)==row;rows.append(dict(path=name,**row))
assert len(rows)==4
patch=W/f['patch']['name'];assert record(patch)=={k:f['patch'][k] for k in ('bytes','sha256')}
log=W/f['pure']['log'];assert record(log)==dict(bytes=f['pure']['log_bytes'],sha256=f['pure']['log_sha256'])
assert b'Ran 33 tests' in log.read_bytes() and log.read_bytes().rstrip().endswith(b'OK')
loader=importlib.util.spec_from_file_location('source02_file_review',C/'.github/windows_identity_psec_lpac_bridge_local.py')
m=importlib.util.module_from_spec(loader);loader.loader.exec_module(m)
files,hashes,closure=m.snapshot(C)
assert len(files)==36 and closure==f['source_sha256']=='7de9968d0984cc7304951ba220d806fea74e998c0a623beddd870a0eb1e0f0ba'
changed={'.github/windows_identity_psec_lpac_bridge.py','.github/windows_identity_psec_lpac_bridge_local.py'}
for name,raw in files.items():
    if name not in changed:assert raw==subprocess.check_output(['git','show',BASELINE+':'+name],cwd=R)
manifest_path=W/'psec-lpac-bridge-compile-02/psec-lpac-bridge-manifest.json'
manifest=json.loads(manifest_path.read_bytes())
for name,digest in {**manifest['sources'],**manifest['dependencies']}.items():
    raw=(C/name).read_bytes();assert sha(raw)==digest
    assert raw==(W/'psec-lpac-bridge-compile-02/src'/name).read_bytes()
    assert raw==subprocess.check_output(['git','show',BASELINE+':'+name],cwd=R)
oldpub=R/'verification/windows-2026-10-22/psec-lpac-identity-local-01-public.json'
assert record(oldpub)==dict(bytes=1660,sha256='cc562d1b045fea336c4257051faa52e63aa415d91556a4ea84f18aa363652f9c')
old=json.loads(oldpub.read_bytes());assert old['broker_outcome_unknown'] is old['recovery_required'] is True
wrapper=W/'run_psec_lpac_identity_02.py';text=wrapper.read_text()
for token in ('psec-lpac-bridge-compile02-actual02','psec-lpac-identity-spec-02.bin','psec-lpac-identity-recovery-plan-02.json',
              'psec-lpac-identity-local-02-preflight.json','psec-lpac-identity-local-02-public.json',
              "secrets.token_hex(16)","head==sys.argv[1]","with path.open('xb')"):
    assert token in text
assert 'recovery-plan-01' not in text and 'local-01-public' not in text
out=dict(schema_version=1,stage='cpse-lpac-source02-independent-incremental-review',baseline_commit=BASELINE,
    scope=m.SCOPE,variant=m.core.VARIANT,conclusion='No remaining blocker found in the frozen four-file increment. Parent owns integrated regression, commit and a single independent fresh diagnostic.',
    review_complete=True,remaining_blockers=[],actual_executed=False,runtime_acceptance=False,
    freeze=record(freeze),patch=record(patch),files=rows,source=dict(count=36,sha256=closure,unchanged_source_files_equal_baseline_git=34),
    native=dict(source_count=6,dependency_count=31,unchanged_from_baseline_and_immutable_compile02=True,
        manifest=record(manifest_path),dll=record(W/'psec-lpac-bridge-compile-02/windows_psec_lpac_bridge.dll')),
    author_pure=dict(log=record(log),reported_tests=33,reported_failures=0,reported_errors=0,reported_skips=0,rerun_by_reviewer=False),
    actual_wrapper=dict(**record(wrapper),reviewed_file_only=True,executed=False),
    checks=dict(
        filetime_created_and_process_thread_job_handles_u64=True,pid_tid_exitcode_u32=True,
        original_return_status_native_snapshot_and_pi_preserved_before_validation=True,
        returned_receipt_binds_intent_sha_config_sha_original_f_and_d=True,
        final_unvalidated_forensic_saved_before_final_validator=True,
        forensic_material_not_an_acceptance_fallback=True,
        complete_result_requires_all_six_durable_receipts_without_exception=True,
        true_unknown_output_sticky_in_call_and_validator=True,
        known_returned_ownership_cleanup_authority_retained_on_write_error=True,
        no_second_close_or_old_opaque_replay=True,
        deadline_failure_never_promoted=True,
        original_clock_jobs_identity_capability_and_never_resume_gates_unchanged=True,
        original_actual01_public_unknown_recovery_true_unchanged=True,
        new_wrapper_has_fresh_nonces_stage_spec_plan_artifact_and_public_names=True,
        native37_and_dll_unchanged=True),
    original_actual01=dict(public=record(oldpub),independent_partial_audit=record(W/'psec-lpac-identity-actual-01-independent-review.json'),
        broker_outcome_unknown=True,recovery_required=True,external_environment_absence_verified=False,old_unknown_cleared=False),
    policy=[
        'Source02 repairs reporting widths and durable evidence. It does not prove the earlier AC admission failure was solely the reporter defect or that CPSE plus LPAC is supported.',
        'The next run is a fresh independent diagnostic with exactly one new environment and fresh plan/nonces/stage/spec; original01 unknown/recovery remains separate and retained.',
        'No original opaque environment reuse, reopen, numerical replay or retry-close; no native/spec/capability fallback.',
        'Known returned S_OK-owned or normal VOID-return observations may support conservative cleanup even if a subsequent receipt write fails; they never qualify a failed/late observation.',
        'Raw receipts and worker-result-forensic are explicitly unvalidated material until their normal validators succeed; there is no qualification fallback.',
        'No environment absence, broker cancellation, network/DNS/proxy test or Model2 policy comparison is claimed.'
    ],
    actions=dict(file_hashes_git_reads_and_pure_snapshot_only=True,tests_rerun=False,wrapper_or_preflight_run=False,
        native_dll_loaded=False,cpse_called=False,native_actor_or_network_executed=False,cleanup_or_recovery_executed=False,
        main_or_original_evidence_modified=False))
path=W/'psec-lpac-source02-independent-review-01.json';assert not path.exists()
raw=(json.dumps(out,sort_keys=True,indent=2)+'\n').encode();path.write_bytes(raw)
print(json.dumps(dict(review='frozen-increment-no-blocker',bytes=len(raw),sha256=sha(raw),source_sha256=closure,actual_executed=False)))
