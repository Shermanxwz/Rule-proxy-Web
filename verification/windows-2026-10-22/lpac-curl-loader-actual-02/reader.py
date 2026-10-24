"""Root-invoked A3 file-only reader candidate; default is an inert preview.

No production backend, DLL export, process/object query, profile/ACL cleanup,
compiler or endpoint is called. Historical staged Git bytes are checked before
importing the new pure validators. Forensic bytes never replace worker-report
qualification. No runtime outcome or final source/Ready hash is preselected.
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
W=Path(__file__).resolve().parent
R=W/'Rule-proxy-Web'
PRIVATE=R/'private'
SCOPE='one-local-held-zero-cap-lpac-system-curl-loader-events-v1'
PROFILE='zero-cap-system-curl-loader-events-with-version-controls-v1'
ENTRY='.github/windows_identity_lpac_curl_loader_local.py'
CORE='.github/windows_identity_lpac_curl_loader.py'
BUILD=W/'lpac-curl-loader-native-build-01'
PINS_FILE=W/'lpac-curl-loader-artifact-pins-01.json'
PINS_META=dict(bytes=486,sha256='d65f99d3ae6b0a5729dcbe8c2561fa8c059cd401f418c7be2ab13890ad8ad47a')
COMPILE_REVIEW=W/'lpac-curl-loader-native-compile-independent-review-01.json'
COMPILE_REVIEW_META=dict(bytes=20693,sha256='b5b5492bdf80bf519eb90b0baa496d739ce27f1eacbfb267a19bbf53c13628aa')
GLOBAL_KEYS=('firewall_profiles','dns','routes','user_proxy')
CONTROL_ROLES=('before','after')
TASK_ROLES=('before','grant-root','grant-package','grant-output','selected','after')


def require(value,label):
    if not value:raise ValueError(label)
def sha(raw):return hashlib.sha256(raw).hexdigest()
def desc(raw):return dict(bytes=len(raw),sha256=sha(raw))
def digest(v,n=64):return type(v) is str and re.fullmatch('[0-9a-f]{%d}'%n,v) is not None
def unique(rows):
    value={}
    for key,item in rows:
        require(key not in value,'reader_duplicate_JSON');value[key]=item
    return value
def decode(raw):
    return json.loads(raw.removeprefix(b'\xef\xbb\xbf').decode('utf-8','strict'),object_pairs_hook=unique,
        parse_constant=lambda _:(_ for _ in ()).throw(ValueError('reader_nonfinite_JSON')))
def encode(v):return (json.dumps(v,sort_keys=True,separators=(',',':'))+'\n').encode('ascii')
def error(exc):
    gate=str(exc)
    return dict(type=type(exc).__name__,gate=gate if re.fullmatch(r'(?:reader|loader|curl_loader)_[A-Za-z0-9_]{1,80}',gate) else None)
def name(v):
    require(type(v) is str and re.fullmatch(r'[A-Za-z0-9_.-]{1,128}',v) is not None and Path(v).name==v,'reader_basename')
    return v
def read(path,maximum,*,inside=R):
    path=Path(path).absolute();anchor=Path(inside).absolute() if inside is not None else Path(path.anchor)
    require(path.is_relative_to(anchor),'reader_path_root');current=anchor
    for part in (None,*path.relative_to(anchor).parts):
        if part is not None:current=current/part
        info=current.lstat()
        require(not stat.S_ISLNK(info.st_mode) and not getattr(info,'st_file_attributes',0)&0x400,'reader_reparse')
    require(stat.S_ISREG(info.st_mode) and 0<=info.st_size<=maximum,'reader_file_bound')
    raw=path.read_bytes();require(len(raw)==info.st_size,'reader_stable_read');return raw
def json_file(path,maximum,*,inside=R):
    raw=read(path,maximum,inside=inside);return decode(raw),raw
def optional(path,maximum,*,inside=R):
    if not path.exists():return None
    return desc(read(path,maximum,inside=inside))
def physical(m,record,path):
    value=m.core.physical_record(record,path);raw=read(path,m.core.MAX_REPORT)
    return value,desc(raw)
def git_sources(commit,names):
    observed=subprocess.check_output(['git','-C',str(R),'rev-parse','--verify',commit+'^{commit}']).decode('ascii').strip()
    require(observed==commit,'reader_exact_historical_commit')
    raw=subprocess.run(['git','-C',str(R),'cat-file','--batch'],input=''.join(commit+':'+n+'\n' for n in names).encode('ascii'),
        stdout=subprocess.PIPE,stderr=subprocess.PIPE,check=True).stdout
    at=0;blobs={}
    for n in names:
        end=raw.index(b'\n',at);parts=raw[at:end].split();require(len(parts)==3 and parts[1]==b'blob','reader_Git_blob')
        count=int(parts[2]);at=end+1;blobs[n]=raw[at:at+count];at+=count
        require(raw[at:at+1]==b'\n','reader_Git_extent');at+=1
    require(at==len(raw),'reader_Git_complete_batch');return blobs


def bind_sources(a,pub,pre):
    ready,ready_raw=json_file(W/name(a.ready_freeze_name),512*1024,inside=W)
    require(sha(ready_raw)==a.ready_freeze_sha256 and ready['actual_ready'] is True
        and type(ready['source_count']) is int and 2<=ready['source_count']<=256
        and ready['source_sha256']==a.source_sha256,'reader_Ready')
    hashes=ready['source_hashes']
    require(type(hashes) is dict and len(hashes)==ready['source_count'] and ENTRY in hashes and CORE in hashes
        and all(digest(v) for v in hashes.values()) and sha(encode(hashes))==a.source_sha256,'reader_source_union')
    plan,plan_raw=json_file(PRIVATE/name(a.plan_name),16384)
    require(type(plan) is dict and plan['scope']==SCOPE and plan['profile']==PROFILE and digest(plan.get('run'),32)
        and sha(plan_raw)==pub['recovery_plan_sha256']==pre['recovery_plan_sha256'],'reader_plan_pin')
    stage=PRIVATE/name(a.private_parent_name)/('local-lpac-curl-loader-'+plan['run'])
    c,config_raw=json_file(stage/'worker-config.json',512*1024)
    require(c['source_hashes']==hashes and c['source_sha256']==a.source_sha256 and c['device_sha256']==a.device_sha256
        and c['recovery_plan_sha256']==sha(plan_raw) and read(stage/'recovery-plan.json',16384)==plan_raw
        and pub['source_sha256']==pre['source_sha256']==a.source_sha256,'reader_config_plan_source_device')
    names=sorted(hashes)
    require(all(type(n) is str and n.startswith(('.github/','ruleproxy/')) and re.fullmatch(r'[A-Za-z0-9_./-]+',n)
        and '..' not in n.split('/') and '\\' not in n for n in names),'reader_source_names')
    blobs=git_sources(a.source_commit,names)
    for n in names:
        raw=read(stage/n,256*1024)
        require(raw==blobs[n] and sha(raw)==hashes[n],'reader_staged_Git_source')
        require(n.startswith('.github/vendor/detours/') or b'\r' not in raw,'reader_repo_LF_vendor_raw')
    spec=importlib.util.spec_from_file_location('bound_curl_loader_pure_reader',stage/ENTRY)
    m=importlib.util.module_from_spec(spec);spec.loader.exec_module(m)
    require(m.SCOPE==SCOPE and m.core.PROFILE==PROFILE and m.core.api_version()==1 and m.core.ACTUAL_READY is True
        and set(m.SOURCES)==set(hashes) and len(m.SOURCES)==ready['source_count'],'reader_bound_new_interface')
    m.core.config_validate(c,source_names=m.SOURCES);m.validate_public(pub);m.validate_public(pre)
    require(pub['mode']=='runtime' and pre['mode']=='preflight' and pre['status']=='ready','reader_public_modes')
    m.core.validate_plan(plan,device=a.device_sha256,source=a.source_sha256,artifacts=c['artifacts'],curl_path=c['curl_path'])
    require(all(c[k]==plan[k] for k in m.core.NONCES) and len({c[k] for k in m.core.NONCES})==4
        and c['root_deadline_qpc']==c['start_qpc']+120*c['frequency'] and c['deadline_qpc']==c['start_qpc']+115*c['frequency'],
        'reader_original_root120_worker115')
    return m,stage,c,plan_raw,config_raw,ready,desc(ready_raw)


def artifacts(m,stage,c,pub,pre,ready):
    pins,pins_raw=json_file(PINS_FILE,8192,inside=W);require(desc(pins_raw)==PINS_META,'reader_fixed_artifact_pins')
    require(pins==c['artifacts']==pub['artifacts']==pre['artifacts']==ready['artifacts'],'reader_four_artifact_commitments')
    m.core.verify_artifacts(c,stage)
    out={}
    for key,path in m.core.artifact_paths(stage).items():
        raw=read(path,8*1024*1024);require(desc(raw)==pins[key] and raw==read(BUILD/path.name,8*1024*1024,inside=W),'reader_original_compiled_artifact')
        out[key]=desc(raw)
    curl=read(c['curl_path'],8*1024*1024,inside=None);require(desc(curl)==pins['curl'],'reader_external_curl_exact_bytes');out['curl']=desc(curl)
    manifest=m.core.verify_manifest(read(stage/'owner-inputs'/m.core.MANIFEST,65536),pins,source_root=stage)
    compile_value,compile_raw=json_file(BUILD/'compile-static-receipt.json',128*1024,inside=W)
    review,review_raw=json_file(COMPILE_REVIEW,65536,inside=W)
    require(desc(review_raw)==COMPILE_REVIEW_META and review['verdict']=='GO-compile-and-static-only' and review['blockers']==[], 'reader_compiled_PE_review')
    require(review['compile_receipt']==dict(name='lpac-curl-loader-native-build-01/compile-static-receipt.json',**desc(compile_raw))
        and compile_value['complete'] is True and compile_value['sources_unchanged'] is True,'reader_compile_receipt_binding')
    original=compile_value['source_pins_before'];require(len(original)==26 and original==compile_value['source_pins_after'],'reader_compile_input26')
    expected={**manifest['nativeSourceHashes'],**manifest['detoursSourceHashes']}
    require(set(expected)==set(original),'reader_runtime_manifest_compilation_inputs')
    for n,pin in original.items():
        raw=read(stage/n,256*1024)
        require(desc(raw)==pin and sha(raw)==expected[n]==c['source_hashes'][n]
            and raw==read(BUILD/'source'/n,256*1024,inside=W),'reader_original_snapshot26_not_reconstructed')
    return dict(artifacts=out,source_input_count=26,original_precompile_snapshot_exact=True,
        compile_receipt=desc(compile_raw),independent_static_review=desc(review_raw),
        wrapper_exports=review['artifacts']['wrapper']['PE']['exports'],marker_exports=review['artifacts']['marker']['PE']['exports'],
        ABI_export_machine_bytes=review['artifacts']['wrapper']['PE']['ABI_version_export_machine_bytes'],
        artifact_loaded_by_reader=False,warning_free=review['commands']['warning_free'],CFG_proven=False)


def parent_candidates(m,report,control,outer):
    rows=[]
    if type(report) is dict and type(report.get('worker_identity')) is dict:rows.append(('worker-envelope-commitment-only',report['worker_identity']))
    if type(control) is dict and type(control.get('task')) is dict and type(control['task'].get('identity')) is dict:
        rows.append(('control-ordinary-identity-matches-parent-commitment',control['task']['identity']))
    admitted=[]
    for source,parent in rows:
        try:
            if not m.launcher.token_is_ordinary(parent) or sha(encode(parent))!=control['parent_sha256']:continue
            if outer is not None and outer.get('child_identity')!=m.launcher.safe_identity(parent,parent):continue
            admitted.append((source,parent))
        except (ValueError,KeyError,TypeError):pass
    return admitted


def controls_review(m,stage,c,report,outer):
    result={};parents={}
    for role in CONTROL_ROLES:
        path=stage/('control-'+role+'.json')
        r=dict(status='missing',commitment=optional(path,m.MAX_REPORT),positive_independently_confirmed=False,
            validation_error=None,parent_basis=None,output=None,task=None)
        if not path.exists():result[role]=r;continue
        try:
            value,_=json_file(path,m.MAX_REPORT)
            require(type(value) is dict and value.get('scope')==SCOPE and value.get('role')==role
                and value.get('run')==c['run'] and value.get('case')==c[role+'_case']
                and value.get('config_sha256')==sha(encode(c)),'reader_control_scope')
            candidates=parent_candidates(m,report,value,outer)
            if not candidates:r['status']='unknown-parent';result[role]=r;continue
            last=None
            for basis,parent in candidates:
                try:m.core.validate_ordinary_control(value,c,role=role,parent=parent,root=stage)
                except Exception as exc:last=exc;continue
                r.update(status='valid',positive_independently_confirmed=value['positive'],parent_basis=basis,
                    output=value['output'],task=dict(admitted=value['task']['admitted'],resumed=value['task']['resumed'],
                        natural_exit=value['task']['natural_exit'],exit_code=value['task']['exit_code']))
                parents[role]=parent;break
            if r['status']!='valid':raise last if last is not None else ValueError('reader_control_unverified')
        except Exception as exc:r['status']='invalid';r['validation_error']=error(exc)
        result[role]=r
    return result,parents


def safe_proof(p):
    masks=[r['granted_access'] for r in p['calls']]
    return dict(qualified=p['qualified'],classification=p['classification'],observation_complete=p['observation_complete'],
        call_count=len(p['calls']),granted_access=masks,exact_LPAC_matrix=p['qualified'] and masks==[2,0,0,2],
        resource_cleanup_verified=p['resource_cleanup_verified'],resource_count=len(p['resources']),closed_resources=sum(r['close_confirmed'] for r in p['resources']),
        generation_before=p['generation_before'],generation_after=p['generation_after'],source_identity_bound=p['source_identity_bound'],duplicate_identity_bound=p['duplicate_identity_bound'],
        calls=[{k:r[k] for k in ('label','attempted','api_success','win32_error','access_status','granted_access','privilege_count','within_deadline')} for r in p['calls']])


def native_projection(m,stage,c,j):
    rows=[];window=j['window']
    for row in j['operations']:
        item=dict(operation=row['operation'],status=row['status'],returned=row['returned'],return_code=None,
            physical_receipt=None,raw_result=None,marker=None)
        if row['receipt'] is not None:_,item['physical_receipt']=physical(m,row['receipt'],stage/'returns'/row['receipt']['name'])
        if row['status']=='valid':
            raw=bytes.fromhex(row['raw']);p=m.core.result_record(raw,row['operation'],(window['start'],window['end']))
            item.update(return_code=p['result_class'],raw_result=desc(raw),return_clock_known=bool(p['return_clock_known']),
                within_original_window=bool(p['within_original_window']),validation_passed=bool(p['validation_passed']),
                update_entered=bool(p['update_entered']),update_returned=bool(p['update_returned']),raw_update_BOOL=p['raw_update_BOOL'],
                update_error_valid=bool(p['update_error_valid']),update_error=p['update_GetLastError'] if p['update_error_valid'] else None,
                copy_entered=bool(p['copy_entered']),copy_returned=bool(p['copy_returned']),copy_nonnull=bool(p['copy_nonnull']),
                copy_error_valid=bool(p['copy_error_valid']),copy_error=p['copy_GetLastError'] if p['copy_error_valid'] else None,
                remote_mutation_possible=bool(p['remote_mutation_possible']),remote_outcome_unknown=bool(p['remote_outcome_unknown']),
                marker_read_entered=bool(p['marker_read_entered']),marker_read_returned=bool(p['marker_read_returned']),
                marker_read_exact256=bool(p['marker_read_exact256']),coherent_snapshot=bool(p['coherent_snapshot']),
                read_error_valid=row['operation']=='read' and p['result_class'] in (12,13),
                read_error=p['read_GetLastError'] if row['operation']=='read' and p['result_class'] in (12,13) else None)
            if row['operation']=='read' and p['result_class']==7:
                raw_marker=bytes.fromhex(row['marker']);v=m.core.Marker256.from_buffer_copy(raw_marker);flags=int(v.progress_flags)
                item['marker']=dict(commitment=desc(raw_marker),coherent=True,progress_flags=flags,failure_stage=int(v.failure_stage),
                    restore_attempted=bool(flags&8),restore_returned=bool(flags&16),raw_restore_BOOL=int(v.raw_restore_BOOL) if flags&16 else None,
                    restore_error_valid=bool(flags&16 and not v.raw_restore_BOOL),restore_error=int(v.restore_GetLastError) if flags&16 and not v.raw_restore_BOOL else None,
                    entered_event_attempted=bool(flags&2),body_event_attempted=bool(flags&64),pre_return_intent=bool(flags&256),
                    raw_enter_event_BOOL=int(v.raw_SetEvent_entered_BOOL) if flags&2 else None,raw_body_event_BOOL=int(v.raw_SetEvent_body_BOOL) if flags&64 else None,
                    stable_sequence_even=int(v.even_stable_status_sequence)%2==0,
                    raw_original_tick_within_window=window['start']<=v.last_original_domain_qpc<window['end'],
                    DllMain_return_proven=False,curl_entry_proven=False,full_restore_proven=False)
        # Invalid/unreturned native content is committed by its return receipt;
        # it is not parsed as a valid Result/Marker or used as a success fallback.
        rows.append(item)
    inputs={}
    for n in ('native-plan.bin','native-marker.bin'):
        inputs[n]=optional(stage/n,256)
    return dict(operations=rows,raw_input_commitments=inputs,maximum_read_snapshots=4,
        event_does_not_prove_DllMain_return=True,mapping_does_not_prove_section_handle=True,full_restoration_proven=False)


def safe_result(m,stage,c,j):
    tasks=[]
    for t in (*j['tasks'],*j['cleanup_tasks']):
        if t['name'] not in (*TASK_ROLES,'remove'):continue
        h=t['held_checks'];r=dict(role=t['name'],attempted=t['attempted'],process_returned=t['process_returned'],admitted=t['admitted'],
            resumed=t['resumed'],exited=t['exited'],natural_exit=t['natural_exit'],exit_code=t['exit_code'],capabilities_empty=t['capabilities']==[],
            held_snapshot_count=len(h),all_held_primary_generation_image_both_jobs=bool(h) and all(x['primary']==t['expected_primary'] and x['pid']==t['pid']
                and x['created']==t['created'] and x['image_sha256']==t['image_sha256'] and x['inner_job'] is x['outer_job'] is True for x in h),
            parent_copies_closed=t['parent_copies_closed'],inherited_handle_count=len(t['inherited_handles']),raw_return_receipt=None)
        if t['receipt'] is not None:
            v,r['raw_return_receipt']=physical(m,t['receipt'],stage/'returns'/t['receipt']['name']);data=v['data'];pi=data.get('raw_pi')
            r['raw_return_observation']=dict(returned_true=data.get('create_status')=='returned_true',returned_false=data.get('create_status')=='returned_false',
                raw_error=data.get('raw_error') if type(data.get('raw_error')) is int and 0<=data['raw_error']<=0xffffffff else None,
                PI_four_present=type(pi) is list and len(pi)==4,PI_complete_nonaliased=type(pi) is list and len(pi)==4 and all(type(x) is int for x in pi)
                    and all(0<h<0xffffffffffffffff for h in pi[:2]) and pi[0]!=pi[1] and all(0<x<=0xffffffff for x in pi[2:]),
                PID_matches_held=type(pi) is list and len(pi)==4 and t['pid'] is not None and pi[2]==t['pid'])
        tasks.append(r)
    window=j['window']
    events=[dict(wait=s['wait'],entered=s['entered'],body=s['body'],process_exited=s['process_exited'],
        within_original_window=window is not None and window['start']<=s['qpc']<window['end']) for s in j['event_samples']]
    mapping=[]
    for f in j['mapping']:
        _,commit=physical(m,f['receipt'],stage/'returns'/f['receipt']['name'])
        mapping.append(dict(verified=f['verified'],query_closed=f['query_closed'],file_closed=f['file_closed'],error_present=f['error'] is not None,
            physical_receipt=commit,sampled_while_process_unexited=not j['event_samples'][f['sample_index']]['process_exited'],
            original_window_timely='qpc' in f and window is not None and window['start']<=f['qpc']<window['end'],
            path_retained_file_identity_correlation_only=True,direct_section_handle_proof=False))
    proofs=[dict(label=r['label'],proof=safe_proof(r['value'])) for r in j['proofs']]
    journals=[];returns=[]
    for group,out in (('intents',journals),('returns',returns)):
        for r in j[group]:
            v,commit=physical(m,r,stage/('journal' if group=='intents' else 'returns')/r['name'])
            out.append(dict(action=v['action'],commitment=commit))
    stdio={}
    for role,directory in (('before','ordinary-before'),('selected','selected-output'),('after','ordinary-after')):
        stdio[role]={n:optional(stage/directory/n,m.core.MAX_OUTPUT) for n in ('stdin','stdout','stderr')}
    return dict(tasks=tasks,proofs=proofs,native=native_projection(m,stage,c,j),events=events,mapping=mapping,stdio=stdio,
        selected_output=j['selected_output'],cleanup={k:j[k] for k in m.core.CLEAN_KEYS},labels=[{k:r[k] for k in ('attempted','lowered','restored')} for r in j['labels']],
        creation_unknown=j['creation_unknown'],context_bound=j['context_bound'],context_forgotten=j['context_forgotten'],
        selected_stop_attempted=j['selected_stop_attempted'],selected_exit_confirmed=j['selected_exit_confirmed'],
        journal=dict(intent_count=len(journals),return_count=len(returns),intents=journals,returns=returns,
            workload_stop_intent_observed=any(r['action']=='workload-stop' for r in journals)),
        epoch=dict(root120_worker115=True,original_work85=m.core.work_cutoff(c)==c['start_qpc']+85*c['frequency'],
            loader_window_declared=window is not None,window_is_original_max8=window is not None and window['end']==min(window['start']+8*c['frequency'],m.core.work_cutoff(c)),
            read_snapshot_count=sum(r['operation']=='read' for r in j['operations'])),
        token_class46_queried=j['token_class46_queried'],endpoint_created=j['endpoint_created'],dns_api_called=j['dns_api_called'],
        fixed_false_claims={k:j[k] for k in m.core.FALSE_CLAIMS})


def result_review(m,stage,c,pub,outer):
    path=stage/'worker-report.json';report=None;raw=None
    r=dict(worker_report_present=path.exists(),worker_envelope_valid=False,worker_result_valid=False,worker_binding_valid=False,
        public_projection_exact=False,safe_projection_complete=False,validation_error=None,binding_error=None,projection_error=None,
        ordinary_controls=None,observations=None)
    if path.exists():
        try:report,raw=json_file(path,m.MAX_REPORT)
        except Exception as exc:r['validation_error']=error(exc)
    controls,_=controls_review(m,stage,c,report,outer);r['ordinary_controls']=controls
    if report is None:
        require(not pub['checks']['worker_bound'] and pub['observation'] is None and not pub['observation_complete'],'reader_missing_or_malformed_worker_not_qualified')
        return r
    phase='validation'
    try:
        require(type(report) is dict and set(report)=={'schema_version','stage','config','worker_pid','worker_identity','result'}
            and type(report['schema_version']) is int and report['schema_version']==1 and report['stage']=='curl-loader-worker'
            and report['config']==c,'reader_worker_envelope')
        r['worker_envelope_valid']=True;parent=report['worker_identity'];j=report['result']
        m.core.validate_result(j,c,parent=parent,root=stage);r['worker_result_valid']=True
        phase='binding';require(outer is not None,'reader_outer_required')
        require(read(stage/'worker-result-forensic.json',m.MAX_REPORT)==raw,'reader_forensic_exact_not_fallback')
        rebound=copy.deepcopy(pub);m.bind_report(report,c,parent,outer,rebound,root=stage)
        # Reproduce the source's qualification clearing for an outer failure.
        # Child facts/ordinary physical receipts are preserved by that clearing.
        outer_ok=outer.get('resumed') is True and outer.get('timed_out') is not True and type(outer.get('exit_code')) is int and outer['exit_code']==0 and 'error' not in outer
        if not outer_ok or pub['failure']=='deadline':m.invalidate_complete(rebound)
        require(rebound['observation']==pub['observation'] and rebound['checks']['worker_bound']==pub['checks']['worker_bound']
            and rebound['checks']['mechanism']==pub['checks']['mechanism'],'reader_public_projection')
        require(outer.get('child_identity')==m.launcher.safe_identity(parent,parent)
            and pub['checks']['worker_exit']==(outer.get('cleanup',{}).get('process_exit_confirmed') is True)
            and pub['checks']['outer_cleanup']==m.local.guest.cleanup_verified(outer),'reader_outer_held_and_cleanup')
        independent={k:controls[k]['status']=='valid' and controls[k]['positive_independently_confirmed'] for k in CONTROL_ROLES}
        require(pub['ordinary_controls']==independent,'reader_public_independent_controls')
        if pub['observation_complete']:require(outer_ok and all(pub['checks'].values()),'reader_complete_outer_natural0')
        r.update(worker_binding_valid=True,public_projection_exact=True);phase='projection'
        r['observations']=safe_result(m,stage,c,j);r['safe_projection_complete']=True
    except Exception as exc:r[{'validation':'validation_error','binding':'binding_error','projection':'projection_error'}[phase]]=error(exc)
    return r


def globals_review(a):
    values={};commitments={}
    for key,basename,pin in (('baseline',a.baseline_name,a.baseline_sha256),('before',a.before_snapshot_name,a.before_sha256),('after',a.after_snapshot_name,a.after_sha256)):
        v,raw=json_file(PRIVATE/name(basename),256*1024)
        require(sha(raw)==pin and type(v) is dict and set(v)=={'schema_version','stage',*GLOBAL_KEYS}
            and type(v['schema_version']) is int and v['schema_version']==1,'reader_global_original_pins')
        commitments[key]=desc(raw);values[key]=v
    equal=lambda x,y:{k:encode(values[x][k])==encode(values[y][k]) for k in GLOBAL_KEYS}
    return dict(commitments=commitments,before_after_byte_equal=commitments['before']==commitments['after'],
        original_before_byte_equal=commitments['baseline']==commitments['before'],original_after_byte_equal=commitments['baseline']==commitments['after'],
        before_after_objects_equal=equal('before','after'),original_before_objects_equal=equal('baseline','before'),original_after_objects_equal=equal('baseline','after'),
        actual_counts={key:dict(firewall_profiles=len(v['firewall_profiles']),dns=len(v['dns']),routes=len(v['routes'])) for key,v in values.items()},
        equality_assumed=False,route_writer_or_time_attribution_proven=False,configuration_or_route_cleanup_called=False)


def audit(a):
    require(digest(a.source_commit,40) and all(digest(getattr(a,n)) for n in ('source_sha256','ready_freeze_sha256','device_sha256',
        'public_sha256','preflight_sha256','driver_sha256','capture_sha256','baseline_sha256','before_sha256','after_sha256')),'reader_operator_pins')
    require(type(a.public_bytes) is type(a.preflight_bytes) is int and 0<a.public_bytes<=65536 and 0<a.preflight_bytes<=65536,'reader_public_sizes')
    prefix=name(a.prefix);pub,public_raw=json_file(R/'verification/windows-2026-10-22'/(prefix+'-public.json'),65536)
    pre,pre_raw=json_file(R/'verification/windows-2026-10-22'/(prefix+'-preflight.json'),65536)
    require(desc(public_raw)==dict(bytes=a.public_bytes,sha256=a.public_sha256) and desc(pre_raw)==dict(bytes=a.preflight_bytes,sha256=a.preflight_sha256),'reader_public_preflight_pins')
    m,stage,c,plan_raw,config_raw,ready,ready_desc=bind_sources(a,pub,pre)
    built=artifacts(m,stage,c,pub,pre,ready)
    outer_path=stage/'outer-launch-report.json';outer,outer_raw=json_file(outer_path,m.MAX_REPORT) if outer_path.exists() else (None,None)
    require((None if outer_raw is None else sha(outer_raw))==pub['outer_launch_report_sha256'],'reader_raw_outer_commitment')
    driver=read(W/name(a.driver_name),256*1024,inside=W);capture=read(W/name(a.capture_name),65536,inside=W)
    require(sha(driver)==a.driver_sha256 and sha(capture)==a.capture_sha256,'reader_driver_capture_pins')
    groups={}
    for group in ('journal','returns'):
        directory=stage/group;paths=sorted(directory.iterdir()) if directory.exists() else []
        require(len(paths)<=64 and all(p.is_file() for p in paths),'reader_bounded_physical_receipts')
        groups[group]=[desc(read(p,m.core.MAX_REPORT)) for p in paths]
    reviewed=result_review(m,stage,c,pub,outer)
    return dict(schema_version=1,stage='lpac-curl-loader-actual-file-review',scope=SCOPE,profile=PROFILE,
        source_commit=a.source_commit,source_sha256=a.source_sha256,source_count=ready['source_count'],Ready=ready_desc,
        public=desc(public_raw),preflight=desc(pre_raw),original_status=pub['status'],original_failure=pub['failure'],
        original_observation_complete=pub['observation_complete'],original_recovery_required=pub['recovery_required'],
        original_safe_observation=pub['observation'],original_ordinary_controls=pub['ordinary_controls'],
        fixed_false_claims={k:pub[k] for k in m.core.FALSE_CLAIMS},compiled_artifacts=built,
        private_commitments=dict(plan=desc(plan_raw),config=desc(config_raw),outer_report=None if outer_raw is None else desc(outer_raw),
            worker_report=optional(stage/'worker-report.json',m.MAX_REPORT),forensic=optional(stage/'worker-result-forensic.json',m.MAX_REPORT),
            stdout=optional(stage/'guard/controller.stdout',2*1024*1024),stderr=optional(stage/'guard/controller.stderr',2*1024*1024),driver=desc(driver)),
        capture_source=desc(capture),physical_evidence_commitments=groups,result_review=reviewed,globals=globals_review(a),
        reader_actions=dict(file_only=True,production_backend_constructed=False,WinDLL_or_exports_called=False,object_or_process_queried=False,
            curl_or_target_started=False,compiler_or_CI_called=False,security_or_network_configuration_changed=False),
        limitations=['No actual result, successful matrix, native return class, version output, cleanup, or global equality is presupposed.',
            'Forensic is committed only; it never substitutes for missing/invalid worker-report qualification.',
            'Independent ordinary controls require their physical PI/stdio/task/parent commitment. If the original parent cannot be recovered from a matching commitment, their state is unknown, not inferred from raw stdout.',
            'Returned BOOL/error-zero, mutation possibility, event signals, coherent marker status, mapped path+retained-file identity correlation, and curl version output remain separate facts.',
            'Events and pre-return intent do not prove DllMain returned or curl entry. Mapping is not direct kernel section HANDLE proof. Helper TRUE does not prove full restoration/absence.',
            'Original source-bound root120/worker115/work85 and max8 loader window are checked. The outer final root-clock read is not a new separately journaled QPC observation in this reader.',
            'Inherited atomic outer constructor is source-bound; this does not retroactively add a new raw-PI hardening contract to legacy outer/tool constructors.',
            'No URL does not establish Winsock absence; no network adapter, DNS/PSEC/Linux or product qualification is made.',
            'Global snapshots are compared as files. Previous route drift and atomic unknown ownership history are not erased or attributed by this reader.'])


def main(argv=None):
    p=argparse.ArgumentParser(description=__doc__);p.add_argument('--verify-file-only',action='store_true')
    p.add_argument('--prefix',default='lpac-curl-loader-local-02');p.add_argument('--private-parent-name',default='lpac-curl-loader-a02')
    p.add_argument('--plan-name',default='lpac-curl-loader-recovery-plan-02.json')
    p.add_argument('--baseline-name',default='model2-first-01-global-baseline.json')
    p.add_argument('--before-snapshot-name',default='lpac-curl-loader-before-curl02-global-snapshot.json')
    p.add_argument('--after-snapshot-name',default='lpac-curl-loader-after-curl02-global-snapshot.json')
    names=('source-commit','source-sha256','ready-freeze-name','ready-freeze-sha256','device-sha256','public-sha256','preflight-sha256',
        'driver-name','driver-sha256','capture-name','capture-sha256','baseline-sha256','before-sha256','after-sha256')
    for k in names:p.add_argument('--'+k)
    p.add_argument('--public-bytes',type=int);p.add_argument('--preflight-bytes',type=int)
    p.add_argument('--output-name',default='lpac-curl-loader-actual-02-independent-review.json');a=p.parse_args(argv)
    if not a.verify_file_only:
        print(json.dumps(dict(stage='A3-file-reader-candidate-preview',scope=SCOPE,verification_executed=False,project_imported=False,
            actual_files_read=False,files_written=False,final_source_Ready_public_and_actual_operator_pins_required=True),sort_keys=True));return 0
    require(all(getattr(a,n.replace('-','_')) is not None for n in (*names,'public-bytes','preflight-bytes')),'reader_final_pins_required')
    output=W/name(a.output_name);require(not output.exists() and not output.is_symlink(),'reader_fresh_WORK_output')
    result=audit(a);raw=(json.dumps(result,sort_keys=True,indent=2)+'\n').encode('ascii')
    with output.open('xb') as out:require(out.write(raw)==len(raw),'reader_complete_output')
    print(json.dumps(dict(review=desc(raw),worker_result_valid=result['result_review']['worker_result_valid'],
        worker_binding_valid=result['result_review']['worker_binding_valid'],original_status=result['original_status']),sort_keys=True));return 0
if __name__=='__main__':raise SystemExit(main())
