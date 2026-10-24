"""File-only independent source03 commitments. No native API or runtime."""
import hashlib
import importlib.util
import json
from pathlib import Path
import subprocess

W=Path(__file__).resolve().parent
C=W/'psec-lpac-python-diagnostic-03-candidate'
R=W/'Rule-proxy-Web'
BASELINE='b269c78eef15b6f71bdae5a5ee631a4e8a34ce9e'
COMMIT='4c5878ba0ffa6f4b938e26bf5c8c016b7042b333'
def sha(raw):return hashlib.sha256(raw).hexdigest()
def record(path):
    raw=path.read_bytes();return dict(bytes=len(raw),sha256=sha(raw))
def git(rev,name):return subprocess.check_output(['git','show',rev+':'+name],cwd=R)
freeze=W/'psec-lpac-python-diagnostic-freeze-03.json'
assert record(freeze)==dict(bytes=15196,sha256='0fafbd55ebe54ea9ed13ac7705dec0b7baa8e0cc26f7971290219f8f6683c00d')
f=json.loads(freeze.read_bytes());assert f['baseline_commit']==BASELINE
rows=[]
for name,value in f['files'].items():
    assert record(C/name)==value and (C/name).read_bytes()==(R/name).read_bytes()==git(COMMIT,name)
    rows.append(dict(path=name,**value))
assert len(rows)==2
patch=W/f['patch']['name'];assert record(patch)=={k:f['patch'][k] for k in ('bytes','sha256')}
abi=W/f['abi']['name'];assert record(abi)=={k:f['abi'][k] for k in ('bytes','sha256')}
log=W/f['pure']['log'];assert record(log)==dict(bytes=f['pure']['log_bytes'],sha256=f['pure']['log_sha256'])
assert b'Ran 42 tests in 6.219s' in log.read_bytes() and log.read_bytes().rstrip().endswith(b'OK')
full=W/'psec-lpac-main-pure-03.log'
assert b'Ran 872 tests in 50.703s' in full.read_bytes() and b'OK (skipped=2)' in full.read_bytes()
# Module import and snapshot execute only pure source/file validators, no API construction.
loader=importlib.util.spec_from_file_location('source03_file_review',C/'.github/windows_identity_psec_lpac_bridge_local.py')
m=importlib.util.module_from_spec(loader);loader.loader.exec_module(m)
files,hashes,closure=m.snapshot(C)
assert len(files)==36 and hashes==f['source_hashes']
assert closure==f['source_sha256']=='cf09c9c86adf9f7af3fb3d71bdde6cd1fd4fa7000a8eb01cc5ebc71b3ea5d682'
for name,raw in files.items():
    assert raw==(R/name).read_bytes()==git(COMMIT,name)
    if name!='.github/windows_identity_psec_lpac_bridge.py':assert raw==git(BASELINE,name)
manifest_path=W/'psec-lpac-bridge-compile-02/psec-lpac-bridge-manifest.json'
manifest=json.loads(manifest_path.read_bytes())
pins={**manifest['sources'],**manifest['dependencies']}
assert pins==f['native_pins'] and len(pins)==37
for name,digest in pins.items():
    raw=(C/name).read_bytes()
    assert sha(raw)==digest and raw==(R/name).read_bytes()==git(COMMIT,name)==git(BASELINE,name)
    assert raw==(W/'psec-lpac-bridge-compile-02/src'/name).read_bytes()
assert record(manifest_path)['sha256']==f['native_manifest_sha256']
old=[]
for number,size,digest in (
    ('01',1660,'cc562d1b045fea336c4257051faa52e63aa415d91556a4ea84f18aa363652f9c'),
    ('02',2083,'100dc78f9af83445829a9f8ddf03ebe1f6bb5fc3af8f1a694e43bb78229daba2')):
    path=R/('verification/windows-2026-10-22/psec-lpac-identity-local-'+number+'-public.json')
    assert record(path)==dict(bytes=size,sha256=digest)
    value=json.loads(path.read_bytes())
    if number=='01':assert value['broker_outcome_unknown'] is value['recovery_required'] is True
    else:assert value['broker_outcome_unknown'] is value['recovery_required'] is False and value['failure']=='admission'
    old.append(dict(number=number,public=record(path),broker_outcome_unknown=value['broker_outcome_unknown'],recovery_required=value['recovery_required']))
out=dict(schema_version=1,stage='cpse-lpac-source03-independent-read-only-review',
    baseline_commit=BASELINE,reviewed_commit=COMMIT,review_complete=True,remaining_blockers=[],
    conclusion='No remaining blocker found in the frozen two-file diagnostic increment. Original exact inner and named outer Job membership gates remain mandatory; no containment fix or successful CPSE identity observation is inferred.',
    freeze=record(freeze),patch=record(patch),abi=record(abi),files=rows,
    source=dict(count=36,sha256=closure,all_equal_reviewed_commit=True,unchanged_runtime_files_equal_baseline=35),
    native=dict(source_count=6,dependency_count=31,all_equal_baseline_reviewed_commit_and_immutable_compile02=True,
        manifest=record(manifest_path),dll=record(W/'psec-lpac-bridge-compile-02/windows_psec_lpac_bridge.dll')),
    tests=dict(author_log=record(log),author_tests=42,author_failures=0,author_errors=0,author_skips=0,
        original_log_wall_seconds=6.219,freeze_reported_wall_seconds=6.218,
        integrated_log=record(full),integrated_tests=872,integrated_failures=0,integrated_errors=0,
        integrated_skips=2,integrated_wall_seconds=50.703,reviewer_reran_tests=False),
    checks=dict(
        real_native_query_method_tested_via_api_shaped_fakes=True,
        two_job_api_success_and_membership_observations_kept_distinct=True,
        both_queries_run_after_a_known_false_or_api_error=True,
        immediate_last_error_captured_before_qpc_or_other_calls=True,
        exact_outer_query_rights_only_noninherited_temporary_handle=True,
        protected_live_handle_alias_rejected_without_blind_close=True,
        per_observation_once_close_ledger_avoids_numeric_reuse_collision=True,
        unreturned_open_or_unconfirmed_close_remains_sticky_unknown=True,
        known_query_handle_consumed_once_even_after_late_clock_failure=True,
        held_generation_image_and_hash_bracket_queries=True,
        durable_raw_job_receipt_bound_to_constructor_return_config_source_and_original_clock=True,
        durable_raw_receipt_precedes_token_and_admission=True,
        post_write_original_cutoff_rechecked_before_decision=True,
        initial_job_failure_stops_before_token_next_arm_and_proofs=True,
        later_job_failure_uses_derived_exact_process_cleanup_without_rewriting_history=True,
        query_resource_unknown_blocks_api_obligations_closed_and_complete=True,
        all_original_both_true_never_resume_identity_and_opaque_cleanup_gates_preserved=True,
        no_assign_fallback_or_job_gate_waiver_added=True,
        prior_actual_public_commitments_unchanged=True),
    prior_actuals=old,
    limits=[
        'The diagnostic can distinguish each Job API outcome and membership only when a new actual observation supplies its durable evidence. It does not retrospectively identify which Job failed in actual02.',
        'No new runtime, CPSE call, DLL load, environment creation, child launch, cleanup or recovery was performed by the reviewer.',
        'Original actual01 opaque outcome and recovery obligation remain retained independently; source03 cannot clear them.',
        'A fresh source-bound diagnostic requires new nonces, stage, spec and plan. No old opaque handle replay, retry-close or fallback is authorized by this review.',
        'Known returned ownership may support one conservative close; neither a Job stop nor a normal VOID return proves external environment absence or broker cancellation.',
        'The original log reports 6.219 seconds for the 42-test author run; freeze metadata lists 6.218. Both are preserved here without rewriting either input.',
        'Neither compile-only and fake regression nor source review proves CPSE plus LPAC, network isolation or Linux equivalence.'
    ],
    actions=dict(file_hashes_git_reads_pure_import_snapshot_only=True,tests_rerun=False,
        wrapper_or_preflight_executed=False,native_dll_loaded=False,cpse_or_os_security_api_called=False,
        native_actor_or_network_executed=False,cleanup_or_recovery_executed=False,
        main_candidate_or_original_evidence_modified=False),actual_executed=False,runtime_acceptance=False)
path=W/'psec-lpac-source03-independent-review-01.json';assert not path.exists()
raw=(json.dumps(out,sort_keys=True,indent=2)+'\n').encode();path.write_bytes(raw)
print(json.dumps(dict(verdict='frozen-diagnostic-no-blocker',receipt=path.name,bytes=len(raw),sha256=sha(raw),source_sha256=closure)))
