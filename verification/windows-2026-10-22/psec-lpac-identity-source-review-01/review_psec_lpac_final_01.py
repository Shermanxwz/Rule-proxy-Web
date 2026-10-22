"""Independent final source/log review. File reads and pure Python imports only."""
import hashlib
import importlib.util
import json
from pathlib import Path

W=Path(__file__).resolve().parent
C=W/'psec-lpac-identity-bridge-candidate'
R=W/'Rule-proxy-Web'
def sha(raw):return hashlib.sha256(raw).hexdigest()
def record(path):
    raw=path.read_bytes();return dict(bytes=len(raw),sha256=sha(raw))
def read(path):return json.loads(path.read_bytes())
pf=W/'psec-lpac-python-candidate-freeze-01.json'
p=read(pf)
assert record(pf)['sha256']=='03d8de46610ef1e699b69f260a465caff6197a8b8f341a1193c73da754540047'
nf=W/'psec-lpac-native-candidate-freeze-03.json'
n=read(nf)
python=[]
for name,row in p['files'].items():
    assert record(C/name)==row and (R/name).read_bytes()==(C/name).read_bytes()
    python.append(dict(path=name,**row))
native=[]
for name,digest in n['files'].items():
    row=record(C/name);assert row['sha256']==digest and (R/name).read_bytes()==(C/name).read_bytes()
    native.append(dict(path=name,**row))
entry=C/'.github/windows_identity_psec_lpac_bridge_local.py'
loader=importlib.util.spec_from_file_location('final_cpse_file_review',entry)
module=importlib.util.module_from_spec(loader);loader.loader.exec_module(module)
# The imported modules define API adapters but do not construct them. snapshot
# only bounds-checks and hashes the already reviewed dependency source files.
files,hashes,closure=module.snapshot(C)
assert len(hashes)==p['source_count']==36 and closure==p['source_sha256']
assert module.core.ACTUAL_READY is True
for name,raw in files.items():assert (R/name).read_bytes()==raw
manifest_path=W/'psec-lpac-bridge-compile-02/psec-lpac-bridge-manifest.json'
manifest=read(manifest_path)
for name,digest in {**manifest['sources'],**manifest['dependencies']}.items():
    assert record(C/name)['sha256']==digest and (R/name).read_bytes()==(C/name).read_bytes()
abi=W/'psec-lpac-identity-bridge-abi-01.json'
assert record(abi)['sha256']==n['abi_sha256']
pylog=W/p['pure']['log'];assert record(pylog)==dict(bytes=p['pure']['log_bytes'],sha256=p['pure']['log_sha256'])
assert b'Ran 27 tests' in pylog.read_bytes() and pylog.read_bytes().rstrip().endswith(b'OK')
natlog=W/Path(n['pure_tests']['log']).name
assert record(natlog)['sha256']==n['pure_tests']['log_sha256']
assert b'Ran 3 tests' in natlog.read_bytes() and b'PSEC_BRIDGE_FAKE_CHECKS 327' in natlog.read_bytes()
fullog=W/'psec-lpac-main-pure-01.log'
full=fullog.read_bytes();assert b'Ran 857 tests' in full and b'OK (skipped=2)' in full
wrapper=W/'run_psec_lpac_identity_01.py'
out=dict(schema_version=1,stage='cpse-lpac-final-independent-read-only-review',scope=module.SCOPE,variant=module.core.VARIANT,
    conclusion='No remaining code or evidence-binding blocker found within the reviewed no-network matched identity scope. Parent owns commit and any source-bound actual run.',
    review_complete=True,remaining_blockers=[],runnable_backend_present=True,runtime_acceptance=False,
    python_freeze=record(pf),native_freeze=record(nf),abi=record(abi),python_files=python,native_files=native,
    source=dict(count=36,sha256=closure,all_candidate_and_integrated_main_bytes_equal=True),
    dll_manifest=record(manifest_path),dll=record(W/'psec-lpac-bridge-compile-02/windows_psec_lpac_bridge.dll'),
    native_dependency_count=31,native_source_count=6,
    prior_native_review=record(W/'psec-lpac-native-independent-review-01.json'),
    dependency_primary_review=record(W/'psec-lpac-dependency-independent-review-01.json'),
    author_test_evidence=dict(
        python=dict(log=record(pylog),reported_tests=27,reported_failures=0,reported_errors=0,reported_skips=0),
        native=dict(log=record(natlog),reported_tests=3,reported_failures=0,reported_errors=0,reported_skips=0,reported_portable_assertions=327,reported_cross_language_checks=4),
        integrated=dict(log=record(fullog),reported_tests=857,reported_failures=0,reported_errors=0,reported_existing_windows_symlink_skips=2),
        reviewer_reran_tests=False),
    actual_wrapper=dict(**record(wrapper),reviewed=True,executed_by_reviewer=False),
    resolved_findings=[
        dict(id='separate_native_result_boolean_names',status='fixed',fact='Native scalar flags and private journal booleans have distinct global names; the same imported production validators are covered together.'),
        dict(id='native_success_tuple_closed',status='fixed',fact='Success requires entered/returned, exact typed status, operation-specific environment state and HRESULT validity; bind also requires actual support/version fields.'),
        dict(id='opaque_unknown_sticky',status='fixed',fact='A create/close missing receipt, exception or native opaque-unknown result cannot be projected with a false private unknown flag.'),
        dict(id='borrowed_job_lifetime',status='fixed-and-covered',fact='The exact inner Job stays live through child/token/proof closure, native empty readback, opaque VOID close and processmodel unbind; only then is its handle consumed.'),
        dict(id='known_late_cleanup_vs_admission',status='clarified-and-covered',fact='A returned known opaque value may close once even when late, but original deadline failure remains disqualified. Late close/unbind normal return may settle known resources while forcing cleanup failure, never observation completion.'),
        dict(id='raw_spec_cross_language_gate',status='covered',fact='The plan-bound canonical Python bytes pass the compiled official generated C++ verifier without rebuilding the passed buffer; CPSE receives that original buffer.'),
        dict(id='worker_plan_nonce_binding',status='fixed-and-covered',fact='All three plan/config nonces match before entering the inner CPSE owner.'),
        dict(id='private_outer_launch_evidence',status='added',fact='The actual outer launch report is durably saved privately and its SHA is required by the public worker-bound predicate.')
    ],
    checks=dict(
        six_python_file_bytes_match_author_freeze_and_integrated_main=True,
        six_native_sources_unchanged_from_immutable_compile02=True,
        native03_only_test_rename_and_cross_language_coverage=True,
        source36_exact_snapshot_equal=True,
        exact_schema_generated_header_dependency_manifest_equal=True,
        independent_canonical_spec_and_plan_sha_preserved=True,
        no_preflight_dll_or_cpse_load_path=True,
        explicit_opt_in_exact_source_device_artifact_spec_plan_required=True,
        worker_private_dacl_named_outer_job_and_source_gates_precede_core=True,
        both_arms_suspended_and_no_resume_or_network_path=True,
        exactly_one_environment_same_inputs_job_two_aap_values=True,
        no_security_capabilities_second_identity_source=True,
        held_primary_generation_image_double_jobs_caps_and_first_sid_match=True,
        fixed_accesscheck_matrices_and_resource_counts_closed=True,
        returned_partial_pi_retained_before_validation=True,
        known_nochild_distinct_from_observed_exit=True,
        unknown_child_observer_close_or_missing_worker_prevents_green_cleanup=True,
        create_or_close_unknown_sticky=True,
        no_blind_close_of_unspecified_failure_opaque_value=True,
        void_close_consume_before_once_and_no_hresult_claim=True,
        private_report_and_public_safe_projection_bound=True,
        original_qpc_deadlines_reserves_and_late_disqualification_preserved=True,
        partial_private_tree_failure_retained_before_directory_creation=True,
        actual_wrapper_exact_head_git_bytes_and_no_retry=True),
    observation_limits=[
        'This reviews an independent deny-all identity-only PSEC spec, not Model2 proxy/peer service, DNS isolation, or Linux equivalence.',
        'A normal VOID close return closes the caller API obligation; environment absence and broker cancellation remain permanently unproven.',
        'Unreturned create/close, malformed unknown output, worker crash or missing final report retain unknown/recovery. Job cleanup cannot replace these receipts.',
        'Known returned late ownership may be cleaned, but never promoted to timely observation completion.',
        'Compile and fake tests are not runtime API/OS-combination evidence. The reviewer did not execute the wrapper, preflight, native DLL or actors.',
        'The ordinary shell prior test run lacked cl.exe; that original failed log is preserved. The final Python and developer-shell native runs are separately pinned.',
        'Two integrated Windows symlink skips are reported as skips, not passed negative cases.'
    ],
    actions=dict(file_hashes_and_log_reads=True,pure_definition_import_and_file_snapshot=True,
        tests_rerun=False,native_compiler_or_flatc_executed=False,native_dll_loaded=False,processmodel_called=False,
        native_actor_executed=False,wrapper_or_preflight_run=False,security_or_network_changed=False,main_source_modified=False))
path=W/'psec-lpac-final-independent-review-01.json';assert not path.exists()
raw=(json.dumps(out,sort_keys=True,indent=2)+'\n').encode();path.write_bytes(raw)
print(json.dumps(dict(review='complete-no-blocker',bytes=len(raw),sha256=sha(raw),source_count=len(hashes),source_sha256=closure,actual_executed=False)))
