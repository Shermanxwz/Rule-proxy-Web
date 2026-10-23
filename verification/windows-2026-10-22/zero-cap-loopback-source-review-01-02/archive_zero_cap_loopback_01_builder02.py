"""File-only, opt-in safe archive for zero-cap loopback attempt01.

No result is assumed. All actual source/public/reader commitments are supplied
after the single run. Forensic files and missing reports are hash-only. This
script never constructs a backend, launches a process actor or changes an ACL,
label, profile, session, firewall or network setting. Only read-only Git runs.
Default validates and previews filenames; --archive alone writes fresh public
archive files. Existing runtime public evidence and prior failures stay intact.
"""
from __future__ import annotations
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
W=Path(__file__).resolve().parent;R=W/'Rule-proxy-Web';OUT=R/'verification/windows-2026-10-22'
NAME='zero-cap-loopback-local-01'
SCOPE='one-local-zero-cap-same-sid-loopback-v1'
PROFILE='same-sid-zero-cap-loopback-mechanism-v1'
MODULE='.github/windows_identity_lpac_loopback_local.py'
GLOBAL_SHA='f05d91ee76ee8a97ae5ab3bfa092167a8ee560c083255f142e6c453f2edf7ab3'
ACTOR_SHA='5015367a6edeaefd1830f5a6584024894070926ea5012c343534e43054b0461d'
MANIFEST_SHA='0c371e646873d3970bb3aea2e05ba05a10bb1b3e0b4c02c84963f7f265537a52'
NATIVE={'.github/native/windows_identity_lpac_loopback_actor.cpp':'c3744801ef26fd42a3f1b1712a7d0b7c8e49369ae7e4d655ab46d8eb3f188985',
    '.github/native/windows_identity_lpac_loopback_contract.hpp':'a5e46a18c25211d34fd33c21a6e640dd7a6a3e3e02ec67fe03c30f010f9f9dce'}
PRIOR={
 'psec-lpac-identity-local-01-public.json':'cc562d1b045fea336c4257051faa52e63aa415d91556a4ea84f18aa363652f9c',
 'model2-dns-01-public.json':'51d8c38a9acd79c8dee629782b1e091a56bb7ccd6d2209cf28852396401b08b5',
 'model2-raw-dns-02-public.json':'50e9142854e8738fafa768a4c72d4a6b489c2710f269ca4bac6e73efd2302d40'}

def require(ok,label):
    if not ok:raise ValueError(label)
def sha(raw):return hashlib.sha256(raw).hexdigest()
def meta(raw):return dict(bytes=len(raw),sha256=sha(raw))
def encode(value):return (json.dumps(value,sort_keys=True,ensure_ascii=True,indent=2,allow_nan=False)+'\n').encode('ascii')
def canonical(value):return (json.dumps(value,sort_keys=True,ensure_ascii=True,separators=(',',':'),allow_nan=False)+'\n').encode('ascii')
def unique(pairs):
    out={}
    for k,v in pairs:require(k not in out,'duplicate_json_key');out[k]=v
    return out
def decode(raw):
    def bad(value):raise ValueError('nonfinite_json')
    return json.loads(raw,object_pairs_hook=unique,parse_constant=bad)
def checked(path,*,inside):
    path=Path(path).absolute();inside=Path(inside).absolute();require(path.is_relative_to(inside),'archive_path_scope')
    cursor=inside
    for part in (None,*path.relative_to(inside).parts):
        if part is not None:cursor=cursor/part
        st=cursor.lstat();require(not stat.S_ISLNK(st.st_mode) and not getattr(st,'st_file_attributes',0)&0x400,'archive_reparse')
    require(stat.S_ISREG(path.lstat().st_mode),'archive_regular');return path
def read(path,limit=1024*1024,*,inside=R):
    path=checked(path,inside=inside);n=path.stat().st_size;require(0<=n<=limit,'archive_file_bound')
    raw=path.read_bytes();require(len(raw)==n,'archive_file_stable');return raw
def optional(path,limit=1024*1024):return None if not path.exists() else read(path,limit)
def descriptor(raw):return None if raw is None else meta(raw)
def source_name(name):return type(name) is str and re.fullmatch(r'(?:\.github|ruleproxy)/[A-Za-z0-9_./-]+',name) and '..' not in name.split('/')
def git_blob(commit,name):
    require(source_name(name),'archive_source_name')
    result=subprocess.run(['git','show',commit+':'+name],cwd=R,capture_output=True)
    require(result.returncode==0 and len(result.stdout)<=256*1024,'archive_git_blob');return result.stdout

def safe_prior():
    rows=[]
    for name,digest in PRIOR.items():
        raw=read(OUT/name,16384);require(sha(raw)==digest,'prior_original_public_pin');v=decode(raw)
        location='result' if name.startswith('model2-') else 'top';body=v['result'] if location=='result' else v
        require(type(body) is dict,'prior_original_schema')
        fields={k:dict(present=k in body,recorded_value=body.get(k)) for k in ('product_acceptance','broker_outcome_unknown','recovery_required')}
        rows.append(dict(path='verification/windows-2026-10-22/'+name,**meta(raw),qualification_field_location=location,original_fields=fields,
            this_attempt_does_not_reinterpret_or_recover_prior_state=True))
    atomic=decode(read(OUT/'psec-lpac-identity-local-01-public.json',16384))
    require(atomic['broker_outcome_unknown'] is True and atomic['recovery_required'] is True,'prior_unknown_preserved')
    return rows

def safe_proofs(j,core):
    rows=[]
    for p in j['proofs']:
        calls=[]
        for call in p['calls']:
            d=call['descriptor']
            calls.append(dict(**{k:call[k] for k in ('label','attempted','api_success','win32_error','access_status','granted_access','privilege_count','within_deadline')},
                descriptor_verified=call['descriptor_verified'],descriptor=None if d is None else {k:d[k] for k in ('bytes','sha256')}))
        complete=len(calls)==4 and all(c['attempted'] and c['api_success'] is True for c in calls)
        rows.append(dict(role=p['expected_role'],qualified=p['qualified'],failure=p['failure'],classification=p['classification'],
            source_primary_bound=p['source_identity_bound'],duplicate_identification_bound=p['duplicate_identity_bound'],
            generation_before=p['generation_before'],generation_after=p['generation_after'],observation_complete=p['observation_complete'],
            resource_cleanup_verified=p['resource_cleanup_verified'],proof_sha256=sha(core.encode(p)),calls=calls,
            observed_matrix=[c['granted_access'] for c in calls] if complete else None,
            expected_matrix=list(core.EXPECTED[p['expected_role']]),unattempted_call_labels=[k for k in core.LABELS if not any(c['label']==k and c['attempted'] for c in calls)],
            resources=[dict(r) for r in p['resources']],unexecuted_calls_not_synthesized=True))
    return rows

def globals_view(review):
    names={'original':'model2-first-01-global-baseline.json','before':'zero-cap-loopback-before-zero01-global-snapshot.json',
        'after':'zero-cap-loopback-after-zero01-global-snapshot.json'}
    raw={k:read(R/'private'/n,256*1024) for k,n in names.items()};values={k:decode(v) for k,v in raw.items()}
    require(meta(raw['original'])==dict(bytes=7378,sha256=GLOBAL_SHA),'original_four_object_baseline')
    keys=('firewall_profiles','dns','routes','user_proxy');require(all(all(k in v for k in keys) for v in values.values()),'global_object_schema')
    require(review['globals']['raw_snapshots']=={k:meta(v) for k,v in raw.items()},'independent_global_commitments')
    return dict(schema_version=1,stage='zero-cap-loopback-four-object-global-comparison',
        raw_snapshots={k:meta(v) for k,v in raw.items()},objects_equal={k:values['original'][k]==values['before'][k]==values['after'][k] for k in keys},
        all_recorded_objects_equal=values['original']==values['before']==values['after'],raw_bytes_equal=raw['original']==raw['before']==raw['after'],
        nrpt_included=False,scope='Only the four recorded objects; no assertion about all machine configuration or orphan broker state.',
        raw_addresses_routes_proxy_values_not_published=True)

def source_history(actual_source):
    rows=[]
    for revision in (1,2,3):
        name='zero-cap-loopback-python-candidate-freeze-%02d.json'%revision
        raw=read(W/name,256*1024,inside=W);v=decode(raw)
        source=v.get('source_sha256') if revision==3 else v['runtime']['source_sha256']
        require(v['actual_ready'] is (revision==3),'source_revision_readiness')
        row=dict(revision=revision,freeze=meta(raw),source_sha256=source,actual_ready=v['actual_ready'],actual_execution_evidence=False)
        if revision in (1,2):
            log=read(W/('zero-cap-loopback-python-pure-%02d.log'%revision),256*1024,inside=W)
            require(meta(log)=={k:v['pure']['log'][k] for k in ('bytes','sha256')},'frozen_focused_test_log')
            row['focused_pure']={k:v['pure'][k] for k in ('test_count','seconds','failures','errors','skipped','test_method_counts')}
            row['focused_pure']['log']=meta(log)
            patch=read(W/v['patch']['path'],512*1024,inside=W);require(meta(patch)=={k:v['patch'][k] for k in ('bytes','sha256')},'frozen_original_patch')
            row['original_patch']=meta(patch)
        rows.append(row)
    first_raw=read(W/'zero-cap-loopback-python-independent-review-01.json',65536,inside=W)
    second_raw=read(W/'zero-cap-loopback-python-independent-review-02.json',65536,inside=W)
    require(decode(first_raw)['verdict']=='BLOCKED' and decode(second_raw)['verdict']=='GO-no-source-or-injected-backend-blocker','source_review_history_verdicts')
    integrated_raw=read(W/'zero-cap-loopback-integrated-pure-01.json',65536,inside=W);integrated=decode(integrated_raw)
    require(sha(integrated_raw)=='f20eac708a02e4e0a7a030573d518619656b0168be7a3d066e73b030d5607462'
        and integrated['source_sha256']==actual_source and integrated['failures']==integrated['errors']==0
        and integrated['actor_executed'] is False and integrated['network_tested'] is False,'integrated_pure_source_pin')
    full_log=read(W/'zero-cap-loopback-main-pure-01.log',2*1024*1024,inside=W)
    require(meta(full_log)==integrated['pure_log'],'integrated_pure_log_pin')
    return dict(schema_version=1,stage='zero-cap-loopback-source-review-history',revisions=rows,
        first_independent_review=meta(first_raw),first_verdict='BLOCKED',first_revision_blocked_not_used_for_actual=True,
        corrected_independent_review=meta(second_raw),corrected_verdict=decode(second_raw)['verdict'],original_blocked_and_failure_evidence_preserved=True,
        integrated_pure=dict(receipt=meta(integrated_raw),log=meta(full_log),**{k:integrated[k] for k in ('identity_tests','seconds','failures','errors','skipped','source_sha256')}),
        corrected_binding='Nonzero native flow start after original GO issue; release/received/response clocks causally ordered.',
        native_compile_not_repeated_by_this_archive=True,pure_or_compile_not_substituted_for_actual=True)

def prepare(a):
    require(re.fullmatch('[0-9a-f]{40}',a.source_commit) is not None,'actual_source_commit')
    for v in (a.source_sha256,a.public_sha256,a.review_sha256):require(re.fullmatch('[0-9a-f]{64}',v) is not None,'operator_hash')
    require(0<a.public_bytes<=16384 and 0<a.review_bytes<=2*1024*1024,'operator_bounds')
    public_raw=read(OUT/(NAME+'-public.json'),16384);pre_raw=read(OUT/(NAME+'-preflight.json'),16384)
    require(meta(public_raw)==dict(bytes=a.public_bytes,sha256=a.public_sha256),'actual_public_pin');public,pre=decode(public_raw),decode(pre_raw)
    review_raw=read(a.review,2*1024*1024,inside=W);require(meta(review_raw)==dict(bytes=a.review_bytes,sha256=a.review_sha256),'independent_actual_review_pin')
    review=decode(review_raw);require(review['stage']=='zero-cap-loopback-actual-01-file-review' and review['bindings_validated'] is True
        and review['source_commit']==a.source_commit and review['source_sha256']==a.source_sha256 and review['public']==meta(public_raw),'independent_review_scope')
    plan_raw=read(R/'private/zero-cap-loopback-recovery-plan-01.json',8192);plan=decode(plan_raw)
    require(sha(plan_raw)==public['recovery_plan_sha256'] and re.fullmatch('[0-9a-f]{32}',plan.get('run','')) is not None,'original_plan')
    stage=R/'private'/('local-zero-cap-same-sid-loopback-'+plan['run']);config_raw=read(stage/'worker-config.json',256*1024);c=decode(config_raw)
    require(c['scope']==SCOPE and c['profile']==PROFILE and len(c['source_hashes'])==37 and sha(canonical(c['source_hashes']))==a.source_sha256
        and c['source_sha256']==public['source_sha256']==pre['source_sha256']==a.source_sha256,'runtime_source_closure')
    sources=[]
    for name,digest in c['source_hashes'].items():
        raw=read(stage/name,256*1024);blob=git_blob(a.source_commit,name)
        require(raw==blob and b'\r' not in raw and sha(raw)==digest,'staged_git_lf_source')
        sources.append(dict(path=name,**meta(raw),git_blob_sha1=hashlib.sha1(b'blob '+str(len(raw)).encode()+b'\0'+raw).hexdigest()))
    s=importlib.util.spec_from_file_location('zero_cap_archive_source_bound',stage/MODULE);m=importlib.util.module_from_spec(s);s.loader.exec_module(m)
    require(set(m.SOURCES)==set(c['source_hashes']) and m.SCOPE==SCOPE and m.core.PROFILE==PROFILE,'actual_module_closure')
    m.core.config_validate(c);m.validate_public(public);m.validate_public(pre);require(pre['status']=='ready','actual_ready_preflight')
    require(read(stage/'recovery-plan.json',8192)==plan_raw,'staged_original_plan')
    m.core.validate_plan(plan,device=c['device_sha256'],source=a.source_sha256,actor=c['actor_sha256'],manifest=c['manifest_sha256'])
    require(all(plan[k]==c[k] for k in (*m.core.NONCES,'ports')),'plan_exact_nonce_ports')
    actor_raw=read(stage/'inputs'/m.core.ACTOR,8*1024*1024);manifest_raw=read(stage/'inputs'/m.core.MANIFEST,65536);manifest=decode(manifest_raw)
    require(sha(actor_raw)==c['actor_sha256']==ACTOR_SHA and sha(manifest_raw)==c['manifest_sha256']==MANIFEST_SHA,'actual_compiled_artifact_pins')
    m.core.verify_actor(stage/'inputs'/m.core.ACTOR,stage/'inputs'/m.core.MANIFEST,ACTOR_SHA,MANIFEST_SHA,root=stage)
    build=W/'zero-cap-loopback-compile-01'
    require(read(build/m.core.ACTOR,8*1024*1024,inside=W)==actor_raw and read(build/m.core.MANIFEST,65536,inside=W)==manifest_raw,'immutable_compile_artifact')
    for name,digest in NATIVE.items():require(c['source_hashes'][name]==digest and read(build/'src'/name,256*1024,inside=W)==git_blob(a.source_commit,name),'immutable_compile_source')
    paths={'config':stage/'worker-config.json','plan':stage/'recovery-plan.json','worker_report':stage/'worker-report.json',
        'forensic':stage/'worker-result-forensic.json','outer_launch':stage/'outer-launch-report.json',
        'stdout':stage/'guard/controller.stdout','stderr':stage/'guard/controller.stderr','driver':W/'run_zero_cap_loopback_01.py'}
    private_raw={k:(None if not p.exists() else read(p,2*1024*1024,inside=W if k=='driver' else R)) for k,p in paths.items()}
    commitments={k:descriptor(v) for k,v in private_raw.items()}
    require(set(review['private_commitments'])==set(paths) and review['private_commitments']==commitments,'independent_private_commitments')
    report=None;j=None;projection=None;validated=False;launch=decode(private_raw['outer_launch']) if private_raw['outer_launch'] is not None else None
    if private_raw['worker_report'] is not None and review['worker_result_valid'] is True:
        report=decode(private_raw['worker_report']);parent=report['worker_identity'];j=report['result']
        require(private_raw['forensic']==m.encode(report),'forensic_exact_but_not_fallback')
        require(launch is not None and launch['child_identity']==m.launcher.safe_identity(parent,parent),'external_held_worker_summary')
        m.core.validate_result(j,c,parent=parent,root=stage)
        derived=copy.deepcopy(public);m.bind_report(report,c,parent,launch,derived,root=stage)
        require(derived['loopback_observation']==public['loopback_observation'] and derived['recovery_required']==public['recovery_required'],'source_bound_public_projection')
        projection=m.observation(j,c,parent,root=stage);validated=True
    else:
        require(public['checks']['worker_bound'] is False and public['loopback_observation'] is None and public['observation_complete'] is False
            and public['recovery_required'] is True,'unvalidated_result_never_qualifies')
    require(validated==review['worker_result_valid'],'independent_worker_validation')
    require(all(public[k] is False for k in m.core.FALSE_CLAIMS),'fixed_false_claims')
    prior=safe_prior();global_projection=globals_view(review);planned={}
    def add(suffix,value,*,raw=False):
        name=NAME+'-'+suffix;path=OUT/name;require(path not in planned,'fresh_archive_name');planned[path]=value if raw else encode(value)
    add('runner.py',private_raw['driver'],raw=True)
    add('archive-reader.py',read(Path(__file__),512*1024,inside=W),raw=True)
    for name in ('zero_cap_loopback_capture_01.ps1','zero_cap_loopback_before-zero01_expanded.ps1','zero_cap_loopback_after-zero01_expanded.ps1'):
        require((W/name).exists(),'recorded_global_capture_script');add(name.replace('zero_cap_loopback_','global-'),read(W/name,128*1024,inside=W),raw=True)
    task_rows=[];native_rows=[];commands=[];tcp=[];proofs=[];label_rows=[];intents=[]
    if j is not None:
        for row in (*j['tasks'],*j['cleanup_tasks']):
            actor=row['name'] in m.core.ROLES;primary=row['expected_primary']
            task_rows.append(dict(name=row['name'],role=row['role'],**{k:row[k] for k in ('attempted','process_returned','assigned','admitted','resumed','exited','exit_code')},
                actor=actor,expected_aap_policy=row['policy'],held_check_count=len(row['held_checks']),go_count=len(row['go_qpc']),
                external_held_zero_cap_primary_verified=bool(actor and row['admitted'] and primary and primary['capabilities']==[]),
                remained_suspended=actor and row['admitted'] and not row['resumed'],natural_zero_exit=row['resumed'] and row['exited'] and row['exit_code']==0,
                class46_queried=False,create_observation={k:row['create_observation'][k] for k in ('status','winerror','process_information')},
                raw_constructor_exception_present=row['create_observation']['exception_detail'] is not None))
        for r in j['native']:
            v=r['value'];facts={k:v[k] for k in ('failure','network_tested','product_acceptance')}
            for k in ('wsa_error','win32_error','request_bytes','request_exact','request_eof','response_bytes','response_complete','response_exact','response_eof',
                'send_shutdown','response_withheld','socket_held','release_verified','connect_attempted','connect_completed','send_attempted','socket_close','wsa_cleanup',
                'within_deadline','control_close_verified','wsa_started','listening_verified','listen_close','socket_resources_closed','accepted_count','receipt_count','phase_count'):
                if k in v:facts[k]=v[k]
            native_rows.append(dict(role=r['role'],kind=r['kind'],name=r['name'],sequence=r['sequence'],**meta(r['text'].encode('ascii')),facts=facts))
        for g in j['go']:
            commands.append(dict(role=g['role'],sequence=g['sequence'],release=g['release'],bytes=128,sha256=g['sha256'],
                original_phase_deadline_retained=g['end']<=m.core.work_cutoff(c),phase_ticks=g['end']-g['issued']))
        for row in j['tcp']:
            tcp.append(dict(kind=row['kind'],bytes=row['raw_bytes'],sha256=row['raw_sha256'],physical_original_redecoded=True,
                exact_listener_pid_tuple_verified=True,exact_halfclosed_pair_verified=row['kind']=='withheld',
                client_state=None if row['value']['client'] is None else row['value']['client']['state'],server_state=None if row['value']['server'] is None else row['value']['server']['state']))
        label_rows=[dict(name=r['name'],baseline_mandatory_label_absent=r['before'] is None,**{k:r[k] for k in ('attempted','lowered','restored')}) for r in j['labels']]
        intents=[dict(action=m.decode(r['text'])['action'],**meta(r['text'].encode('ascii'))) for r in j['intents']]
        proofs=safe_proofs(j,m.core)
    component=dict(schema_version=1,stage='zero-cap-loopback-safe-component-projection',scope=SCOPE,profile=PROFILE,
        validated_worker_result_available=validated,private_commitments=commitments,public_projection=projection,
        held_tasks=task_rows,intents=intents,native_reports=native_rows,labels=label_rows,
        cleanup=None if j is None else {k:j[k] for k in m.core.CLEAN_KEYS},forensic_used_for_qualification=False,
        missing_report_tasks_or_returns_synthesized=False,raw_identity_paths_nonces_tokens_or_socket_ports_published=False,
        label_claim='Only mandatory-label ACE absence restored on the two fresh output subtrees; not original full SACL/SD byte restoration.',
        network_tested_claim='Native flag denotes connect-attempt/accepted-flow. False does not mean no socket/bind/listen API ran.')
    add('component-projection.json',component)
    add('accesscheck-projection.json',dict(schema_version=1,stage='zero-cap-loopback-safe-accesscheck',scope=SCOPE,proofs=proofs,
        finite_zero_cap_identity_only=True,unexecuted_calls_not_synthesized=True,raw_identity_not_published=True))
    add('protocol-projection.json',dict(schema_version=1,stage='zero-cap-loopback-safe-protocol',scope=SCOPE,commands=commands,tcp_observations=tcp,
        nonce_payload_64_bytes=True,command_128_bytes=True,raw_tcp_tables_not_published=True,raw_control_nonces_not_published=True,
        same_absolute_phase_deadline_no_renewal=True,phase_start_after_go_source_validator=True,release_response_causality_source_validator=True))
    add('global-projection.json',global_projection)
    add('source-history.json',source_history(a.source_sha256))
    # These unpublished earlier Python revisions are useful source history.
    # Exact safe patches, focused logs and review outcomes preserve the original
    # blocked revision rather than silently replacing it with the final code.
    for source,suffix in (
        ('zero-cap-loopback-python-candidate-01.patch','python-false01.patch'),
        ('zero-cap-loopback-python-candidate-freeze-01.json','python-false01-freeze.json'),
        ('zero-cap-loopback-python-pure-01.log','python-false01-pure.log'),
        ('zero-cap-loopback-python-independent-review-01.json','python-false01-review.json'),
        ('zero-cap-loopback-python-candidate-02.patch','python-false02.patch'),
        ('zero-cap-loopback-python-candidate-freeze-02.json','python-false02-freeze.json'),
        ('zero-cap-loopback-python-pure-02.log','python-false02-pure.log'),
        ('zero-cap-loopback-python-independent-review-02.json','python-false02-review.json'),
        ('zero-cap-loopback-python-candidate-freeze-03.json','python-ready03-freeze.json')):
        add(suffix,read(W/source,512*1024,inside=W),raw=True)
    static_raw=read(W/'zero-cap-loopback-compile-static-review-01.json',65536,inside=W);static=decode(static_raw)
    require(static['actor_sha256']==ACTOR_SHA and static['manifest_sha256']==MANIFEST_SHA and static['actor_executed'] is False,'compile_static_pins')
    add('source-review.json',dict(schema_version=1,stage='zero-cap-loopback-safe-source-review',source_commit=a.source_commit,source_sha256=a.source_sha256,
        runtime_source_count=37,sources=sources,native_source_count=2,native_sources=NATIVE,
        actor=meta(actor_raw),manifest=meta(manifest_raw),manifest_values=manifest,static_review=meta(static_raw),
        pe={k:static['pe'][k] for k in ('machine','dll','subsystem','imports','delay_imports')},
        compile_and_pure_are_not_actual_runtime_evidence=True,compiler_log_not_published=True,source_git_lf_equality_verified=True))
    selected_final=next((r['facts'] for r in native_rows if r['role']=='selected-client' and r['kind']=='final'),None)
    selected_control_sharing_failure=bool(selected_final is not None and selected_final.get('failure')=='control-open'
        and selected_final.get('win32_error')==32 and selected_final.get('wsa_started') is False and selected_final.get('network_tested') is False)
    add('summary.json',dict(schema_version=1,stage='zero-cap-same-sid-loopback-actual-summary',scope=SCOPE,profile=PROFILE,
        source_commit=a.source_commit,source_sha256=a.source_sha256,original_public=meta(public_raw),original_preflight=meta(pre_raw),
        independent_file_review=meta(review_raw),original_status=public['status'],original_failure=public['failure'],
        original_observation_complete=public['observation_complete'],original_recovery_required=public['recovery_required'],
        loopback_observation=public['loopback_observation'],validated_worker_result_available=validated,
        selected_final=selected_final,selected_control_sharing_failure_before_winsock=selected_control_sharing_failure,
        sharing_failure_is_network_denial=False if selected_control_sharing_failure else None,
        failure_interpretation=('A control-open Win32 32 sharing violation was observed before selected Winsock initialization. The source has a parent post-rename readback racing the native exclusive control read; this is a source-based explanation, not an independently traced scheduler event or a network rejection.'
            if selected_control_sharing_failure else 'No denial is inferred from a missing connection, timeout, setup failure or incomplete report.'),
        held_task_count=len(task_rows) if validated else None,observed_accesscheck_call_count=sum(c['attempted'] for p in proofs for c in p['calls']) if validated else None,
        native_report_count=len(native_rows) if validated else None,command_count=len(commands) if validated else None,tcp_table_count=len(tcp) if validated else None,
        global_four_recorded_objects_equal=global_projection['all_recorded_objects_equal'],global_snapshot_bytes_equal=global_projection['raw_bytes_equal'],
        old_atomic01_unknown_and_recovery_required_preserved=True,old_dns_leak_not_reinterpreted=True,prior_evidence=prior,
        worker_zero_exit_is_not_reachability_success=True,forensic_is_not_qualification_fallback=True,
        capability_absence_is_not_blanket_direct_egress_isolation=True,hostile_same_sid_peer_boundary_tested=False,
        **dict.fromkeys(m.core.FALSE_CLAIMS,False)))
    files=[dict(path=p.relative_to(R).as_posix(),**meta(raw)) for p,raw in planned.items()]
    files=[dict(path='verification/windows-2026-10-22/'+NAME+'-public.json',**meta(public_raw)),
        dict(path='verification/windows-2026-10-22/'+NAME+'-preflight.json',**meta(pre_raw)),*files]
    add('evidence-index.json',dict(schema_version=1,stage='zero-cap-loopback-actual-evidence-index',scope=SCOPE,profile=PROFILE,
        source_commit=a.source_commit,source_sha256=a.source_sha256,files=files,index_self_hash_excluded=True,
        actual_runtime_rerun_by_archive=False,native_API_or_backend_constructed_by_archive=False,network_or_cleanup_by_archive=False,
        raw_private_evidence_published=False,original_public_modified=False,prior_evidence_modified=False))
    # Closed projections must not contain the actual user's identity or any
    # runtime nonce, machine path, ephemeral PID/token/QPC value or socket table.
    secrets={c[n].encode() for n in m.core.NONCES};secrets.add(str(stage).encode());secrets.add(str(R).encode())
    if j is not None:
        if j['profile_sid'] is not None:secrets.add(j['profile_sid'].encode())
        if report:secrets.add(report['worker_identity']['sid'].encode())
    for path,raw in planned.items():
        require(not any(v and v in raw for v in secrets),'private_value_in_safe_archive')
        require(('S-'+'1-5-21-').encode() not in raw and ('C:'+chr(92)+'Users'+chr(92)).encode() not in raw
            and ('C:'+'/Users/').encode() not in raw,'private_identity_or_machine_path_in_archive')
    stable={OUT/(NAME+'-public.json'):public_raw,OUT/(NAME+'-preflight.json'):pre_raw,a.review:review_raw}
    stable.update({p:private_raw[k] for k,p in paths.items() if private_raw[k] is not None})
    require(all(read(p,8*1024*1024,inside=W if p==a.review or p==paths['driver'] else R)==raw for p,raw in stable.items()),'original_evidence_unchanged')
    return planned,dict(verified=True,source_commit=a.source_commit,source_sha256=a.source_sha256,
        original_status=public['status'],original_recovery_required=public['recovery_required'],worker_result_validated=validated,
        reachability_verified=None if projection is None else projection['reachability_verified'],archive_file_count=len(planned),
        native_API_network_or_cleanup_executed=False)

def main(argv=None):
    p=argparse.ArgumentParser(description=__doc__)
    for name in ('source-commit','source-sha256','public-sha256','review-sha256'):p.add_argument('--'+name,required=True)
    p.add_argument('--public-bytes',type=int,required=True);p.add_argument('--review-bytes',type=int,required=True)
    p.add_argument('--review',type=Path,default=W/'zero-cap-loopback-actual-01-independent-review.json');p.add_argument('--archive',action='store_true')
    a=p.parse_args(argv);planned,result=prepare(a)
    if a.archive:
        for path,raw in planned.items():
            if path.exists():require(read(path,2*1024*1024)==raw,'refuse_changed_existing_archive')
        for path,raw in planned.items():
            if not path.exists():
                with path.open('xb') as stream:require(stream.write(raw)==len(raw),'archive_write')
                require(read(path,2*1024*1024)==raw,'archive_readback')
        paths=W/'stage_zero_cap_loopback_local_01_paths.txt';raw=''.join(p.relative_to(R).as_posix()+'\n' for p in planned).encode()
        if paths.exists():require(read(paths,65536,inside=W)==raw,'existing_exact_path_list')
        else:
            with paths.open('xb') as stream:stream.write(raw)
    print(json.dumps(result|dict(archive_written=a.archive),sort_keys=True))
if __name__=='__main__':main()
