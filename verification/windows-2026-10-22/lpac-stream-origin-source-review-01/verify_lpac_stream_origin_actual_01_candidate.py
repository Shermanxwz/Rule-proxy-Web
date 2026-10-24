"""WORK A-min file-only reader candidate; default only prints an inert preview.

Only exact staged Git sources are imported, after every source is byte/hash/LF
bound. Their pure validators are used; no NativeAPI/backend/actor/cleanup is
constructed or called. Imports may initialize libraries. Missing worker reports
stay unknown; forensic bytes are never qualification fallback. This candidate
contains no future actual source/public/Ready/driver facts.
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
W=Path(__file__).resolve().parent;R=W/'Rule-proxy-Web'
SCOPE='one-local-semantic-lpac-inherited-stream-origin-v1'
PROFILE='zero-cap-lpac-bounded-byte-stream-mechanism-v1'
ENTRY='.github/windows_identity_lpac_stream_origin_local.py'
BUILD=W/'lpac-stream-native-compile-01'
ARTIFACTS={
 'front':dict(actor='windows_identity_lpac_stream_front_actor.exe',manifest='identity-lpac-stream-front-manifest.json',
   actor_sha256='b7327db1d30f4d81f7806b449d191cf7d49e22563c1da0c734f85cd478c9ae2a',manifest_sha256='9a9df1de567bc4c6a9d0de334adeed4665fba2ade5ae5b62d26279d37134c4ba'),
 'network':dict(actor='windows_identity_lpac_stream_network_actor.exe',manifest='identity-lpac-stream-network-manifest.json',
   actor_sha256='074440e530ec26e149c90e1575261f930fadfdeaf156c4ceaf6b6f8f5fb9d1db',manifest_sha256='e7b090b9b2b24189ba5c202919a1b9fc27b1d6ecdf32b36087379f55b9d505a2')}
SNAPSHOT_SHA='1819823e18df4a58c3cb6e304f40141ad2172abd4846e97b6f63fa9365cba317'
PE_REVIEW_SHA='8388a661c10036a7676fc79b3b595a141905e2a87b734a777809878456cf5d35'
BASELINE_SHA='f05d91ee76ee8a97ae5ab3bfa092167a8ee560c083255f142e6c453f2edf7ab3'

def require(v,label):
    if not v:raise ValueError(label)
def sha(raw):return hashlib.sha256(raw).hexdigest()
def desc(raw):return dict(bytes=len(raw),sha256=sha(raw))
def encode(v):return (json.dumps(v,sort_keys=True,separators=(',',':'))+'\n').encode('ascii')
def digest(v,n=64):return type(v) is str and re.fullmatch('[0-9a-f]{%d}'%n,v) is not None
def error(e):
    label=str(e);return dict(type=type(e).__name__,label=label if re.fullmatch('[A-Za-z][A-Za-z0-9_]{0,100}',label) else None)
def work_name(v):
    require(type(v) is str and re.fullmatch('[A-Za-z0-9_.-]{1,128}',v) and Path(v).name==v,'reader_basename');return W/v
def checked(path,inside):
    path=Path(path).absolute();inside=Path(inside).absolute();require(path.is_relative_to(inside),'reader_scope')
    cursor=inside
    for part in (None,*path.relative_to(inside).parts):
        if part is not None:cursor=cursor/part
        s=cursor.lstat();require(not stat.S_ISLNK(s.st_mode) and not getattr(s,'st_file_attributes',0)&0x400,'reader_reparse')
    require(stat.S_ISREG(path.lstat().st_mode),'reader_regular');return path
def read(path,limit=1024*1024,*,inside=None):
    path=checked(path,R if inside is None else inside);n=path.stat().st_size;require(0<=n<=limit,'reader_bound')
    b=path.read_bytes();require(len(b)==n,'reader_changed');return b
def pairs(rows):
    result={}
    for k,v in rows:require(k not in result,'reader_duplicate');result[k]=v
    return result
def decode(b):return json.loads(b.decode('utf-8-sig','strict'),object_pairs_hook=pairs,parse_constant=lambda _:(_ for _ in ()).throw(ValueError('reader_nonfinite')))
def json_file(p,limit=1024*1024,*,inside=None):
    b=read(p,limit,inside=inside);return decode(b),b
def optional(p,limit=1024*1024):return desc(read(p,limit)) if p.exists() else None
def physical(row,path,limit=32768):
    b=read(path,limit);require(b==row['text'].encode('ascii') and sha(b)==row['sha256'],'reader_physical');return b,desc(b)

def bind_sources(a,pub,pre):
    f,raw=json_file(work_name(a.ready_freeze_name),512*1024,inside=W)
    require(sha(raw)==a.ready_freeze_sha256 and f['actual_ready'] is True and f['source_count']==45 and f['source_sha256']==a.source_sha256,'reader_ready')
    hashes=f['source_hashes'];require(type(hashes) is dict and len(hashes)==45 and sha(encode(hashes))==a.source_sha256,'reader_source_map')
    plan,praw=json_file(R/'private'/a.plan_name,16384);require(sha(praw)==pub['recovery_plan_sha256'] and digest(plan.get('run'),32),'reader_plan')
    stage=R/'private'/('local-lpac-stream-origin-'+plan['run']);c,craw=json_file(stage/'worker-config.json',512*1024)
    require(c['source_hashes']==hashes and c['source_sha256']==a.source_sha256 and c['recovery_plan_sha256']==sha(praw),'reader_config')
    require(pub['source_sha256']==pre['source_sha256']==a.source_sha256 and read(stage/'recovery-plan.json',16384)==praw,'reader_plan_source_relation')
    commit=subprocess.check_output(['git','rev-parse','--verify',a.source_commit+'^{commit}'],cwd=R).decode().strip();require(commit==a.source_commit,'reader_exact_commit')
    names=sorted(hashes)
    require(all(type(n) is str and re.fullmatch('[A-Za-z0-9_./-]+',n) and '..' not in n.split('/') for n in names),'reader_source_names')
    query=''.join(commit+':'+n+'\n' for n in names).encode()
    batch=subprocess.run(['git','cat-file','--batch'],cwd=R,input=query,capture_output=True,check=True).stdout;at=0
    for n in names:
        end=batch.index(b'\n',at);h=batch[at:end].split();require(len(h)==3 and h[1]==b'blob','reader_git_blob');size=int(h[2]);at=end+1
        git=batch[at:at+size];at+=size;require(batch[at:at+1]==b'\n','reader_git_extent');at+=1
        b=read(stage/n,256*1024);require(b==git and sha(b)==hashes[n] and b'\r' not in b,'reader_exact_Git_LF')
    require(at==len(batch) and ENTRY in hashes,'reader_git_complete')
    s=importlib.util.spec_from_file_location('exact_bound_stream_actual_reader',stage/ENTRY);m=importlib.util.module_from_spec(s);s.loader.exec_module(m)
    require(m.SCOPE==SCOPE and m.core.PROFILE==PROFILE and m.core.ACTUAL_READY is True and m.core.api_version()==1 and set(m.SOURCES)==set(hashes),'reader_interface')
    m.core.config_validate(c);m.validate_public(pub);m.validate_public(pre)
    require(pre['mode']=='preflight' and pre['status']=='ready' and pub['mode']=='runtime','reader_preflight_mode')
    m.core.validate_plan(plan,device=c['device_sha256'],source=c['source_sha256'],actor=c['actor_sha256'],manifest=c['manifest_sha256'],network_actor=c['network_actor_sha256'],network_manifest=c['network_manifest_sha256'],challenges=c['challenges'])
    require(all(c[k]==plan[k] for k in m.core.NONCES) and len({c[k] for k in m.core.NONCES})==2 and c['root_deadline_qpc']==c['start_qpc']+120*c['frequency'] and c['deadline_qpc']==c['root_deadline_qpc']-5*c['frequency'],'reader_epoch')
    return m,stage,c,praw,craw,desc(raw)

def artifacts(m,stage,c,pub,pre):
    m.core.verify_artifacts(c,stage);snapshot,sraw=json_file(BUILD/'input-snapshot.json',65536,inside=W)
    require(sha(sraw)==SNAPSHOT_SHA and len(snapshot)==4,'reader_compile_snapshot')
    review,rraw=json_file(W/'lpac-stream-native-compile-static-review-01.json',65536,inside=W);require(sha(rraw)==PE_REVIEW_SHA,'reader_PE_review')
    result={}
    for role,expected in ARTIFACTS.items():
        ar=read(stage/'inputs'/expected['actor'],8*1024*1024);mr=read(stage/'inputs'/expected['manifest'],8192)
        require(sha(ar)==expected['actor_sha256'] and sha(mr)==expected['manifest_sha256'] and ar==read(BUILD/expected['actor'],8*1024*1024,inside=W) and mr==read(BUILD/expected['manifest'],8192,inside=W),'reader_two_artifact_bytes')
        manifest=decode(mr);pins=m.core.NATIVE_SOURCES if role=='front' else m.core.NETWORK_SOURCES;require(len(pins)==3,'reader_three_pins_each')
        for field,name in pins.items():
            b=read(stage/name,256*1024);require(snapshot[name]==desc(b) and b==read(BUILD/'src'/Path(name).name,256*1024,inside=W) and manifest[field]==sha(b)==c['source_hashes'][name],'reader_three_compile_pins')
        for field,h in (('actor_sha256' if role=='front' else 'network_actor_sha256',sha(ar)),('manifest_sha256' if role=='front' else 'network_manifest_sha256',sha(mr))):require(c[field]==pub[field]==pre[field]==h,'reader_artifact_public_binding')
        require(review['artifacts'][role]['executable']==desc(ar) and review['artifacts'][role]['manifest']==desc(mr),'reader_PE_artifact_binding')
        result[role]=dict(actor=desc(ar),manifest=desc(mr),source_pins=3,immutable_snapshot_exact=True)
    return dict(artifacts=result,input_snapshot=desc(sraw),static_PE_review=desc(rraw),toolchain=desc(read(BUILD/'toolchain.json',65536,inside=W)))

def safe_proof(p):
    if p is None:return None
    masks=[r['granted_access'] for r in p['calls']]
    return dict(qualified=p['qualified'],call_count=len(p['calls']),granted_access=masks,exact_LPAC_matrix=p['qualified'] and masks==[2,0,0,2],
      observation_complete=p['observation_complete'],resource_cleanup_verified=p['resource_cleanup_verified'],generation_before=p['generation_before'],generation_after=p['generation_after'],
      source_identity_bound=p['source_identity_bound'],duplicate_identity_bound=p['duplicate_identity_bound'],resources=len(p['resources']),closed_resources=sum(r['close_confirmed'] for r in p['resources']),
      calls=[{k:r[k] for k in ('label','attempted','api_success','win32_error','access_status','granted_access','privilege_count','within_deadline')} for r in p['calls']])

def payloads(m,stage,c,j):
    m.core.validate_sinks(j,c,root=stage);inputs={};sinks={}
    for key,name in m.core.CHALLENGE_PATHS.items():
        b=read(stage/name,65536);require(desc(b)==c['challenges'][key],'reader_input_challenge');inputs[key]=desc(b)
    for key,row in j['physical_sinks'].items():
        b=read(stage/m.core.SINK_PATHS[key],65536);require(desc(b)=={k:row[k] for k in ('bytes','sha256')},'reader_sink_commitment')
        expected=inputs['request' if key in ('relay_request','origin_request') else 'response']
        sinks[key]=dict(**desc(b),full_declared_challenge_exact=desc(b)==expected)
    complete=set(sinks)==set(m.core.SINK_PATHS) and all(v['full_declared_challenge_exact'] for v in sinks.values())
    return dict(inputs=inputs,sinks=sinks,all_five_physical_sinks_exact=complete,native_hash_used=False)

def native_projection(m,stage,c,j,parent):
    result=[];valid={}
    for key,name in m.core.REPORT_PATHS.items():
        row=j['reports'][key];out=dict(slot=key,status=j['report_status'][key],commitment=optional(stage/name,m.core.MAX_NATIVE))
        if row is not None:
            b,commit=physical(row,stage/name,m.core.MAX_NATIVE);out.update(commitment=commit,embedded_equals_physical=True)
            # Authentic malformed JSON is committed partial evidence. Do not
            # decode it unless the exact source admitted that slot as valid.
            if j['report_status'][key]=='valid':valid[key]=m.core.validate_native(key,decode(b),j,c,parent)
        if key in valid and key!='ready':
            v=valid[key];out.update(failure=v['failure'],win32_error=v['win32_error'],wsa_error=v['wsa_error'],network_tested=v['network_tested'],selected_socket_api_tested=v['selected_socket_api_tested'],files=v['files'])
            if v['stream'] is not None:
                st=v['stream'];pipe=v['pipe'];out.update(stream=st,pipe=pipe,
                  complete_dynamic_wire_counts_verified=st['protocol_complete'] and pipe['write_bytes']==64*st['tx_frames']+st['tx_payload_bytes'] and pipe['read_bytes']==64*st['rx_frames']+st['rx_payload_bytes'])
            if v['network'] is not None:out['network']={k:value for k,value in v['network'].items() if k not in ('port','local_port','peer_port')}
        result.append(out)
    tuple_exact=None;cross=None
    if 'relay' in valid and 'origin' in valid:
        a,b=valid['relay']['network'],valid['origin']['network'];tuple_exact=a['local_port']==b['peer_port'] and a['peer_port']==b['local_port']==b['port']==j['port']
    if 'selected' in valid and 'relay' in valid:
        a,b=valid['selected'],valid['relay'];cross=all(a['stream'][x]==b['stream'][y] for x,y in (('tx_frames','rx_frames'),('rx_frames','tx_frames'),('tx_payload_bytes','rx_payload_bytes'),('rx_payload_bytes','tx_payload_bytes'))) and a['pipe']['read_bytes']==b['pipe']['write_bytes'] and a['pipe']['write_bytes']==b['pipe']['read_bytes']
    return dict(reports=result,reported_peer_tuple_exact=tuple_exact,dynamic_frames_and_payload_cross_equal=cross,kernel_TCP_snapshot_observed=False)

def result_review(m,stage,c,pub,outer):
    path=stage/'worker-report.json';result=dict(worker_report_present=path.exists(),worker_result_valid=False,worker_binding_valid=False,public_projection_exact=False,safe_projection_complete=False,validation_error=None,binding_error=None,projection_error=None,
      held_tasks=None,proof=None,payload_files=None,native=None,pipe=None,journal=None,epoch=None,three_natural_exit0=None,workload_stop=None,cleanup=None,ordinary_tool_exits=None)
    if not path.exists():
        require(pub['checks']['worker_bound'] is False and pub['observation'] is None and not pub['observation_complete'],'reader_missing_worker_unknown');return result
    phase='validation'
    try:
        report,raw=json_file(path,m.MAX_REPORT);parent=report['worker_identity'];j=report['result'];m.core.validate_result(j,c,parent=parent,root=stage);result['worker_result_valid']=True
        phase='binding';require(outer is not None,'reader_missing_outer');require(read(stage/'worker-result-forensic.json',m.MAX_REPORT)==raw,'reader_worker_forensic_same_bytes')
        rebound=copy.deepcopy(pub);m.bind_report(report,c,parent,outer,rebound,root=stage)
        require(rebound['observation']==pub['observation'] and rebound['checks']['worker_bound']==pub['checks']['worker_bound'] and rebound['checks']['mechanism']==pub['checks']['mechanism'],'reader_public_projection')
        require(outer['child_identity']==m.launcher.safe_identity(parent,parent),'reader_held_outer_identity')
        require(pub['checks']['worker_exit']==(outer.get('cleanup',{}).get('process_exit_confirmed') is True) and pub['checks']['outer_cleanup']==m.local.guest.cleanup_verified(outer),'reader_outer_cleanup_projection')
        if pub['observation_complete']:require(outer.get('resumed') is True and outer.get('timed_out') is not True and outer.get('exit_code')==0 and 'error' not in outer,'reader_observed_outer_normal_exit')
        result.update(worker_binding_valid=True,public_projection_exact=True);phase='projection';rows=m.core.actor_rows(j);tasks=[]
        for role,row in rows.items():
            tasks.append(dict(role=role,attempted=row['attempted'],created=row['process_returned'],admitted=row['admitted'],resumed=row['resumed'],exited=row['exited'],exit_code=row['exit_code'],
              held_snapshot_count=len(row['held_checks']),capabilities_empty=row['capabilities']==[],all_held_generation_image_dual_jobs=bool(row['held_checks']) and all(h['pid']==row['pid'] and h['created']==row['created'] and h['image_sha256']==row['image_sha256'] and h['inner_job'] is h['outer_job'] is True for h in row['held_checks']),
              raw_return_receipt=None if row['receipt'] is None else physical(row['receipt'],stage/'returns'/row['receipt']['name'])[1]))
        intents=[physical(r,stage/'journal'/r['name'],4096)[1] for r in j['intents']];allocated=[];returns=[]
        for row in j['pipe_allocations']:
            if row['adopted']:allocated.extend(row['raw_outputs'])
            if row['receipt'] is not None:returns.append(physical(row['receipt'],stage/'returns'/row['receipt']['name'])[1])
        closes=j['parent_pipe_close_attempts'];directions=None
        if len(allocated)==4 and all(k in rows for k in ('lpac-pipe-front','ordinary-pipe-relay')):directions=rows['lpac-pipe-front']['ends']==[allocated[0],allocated[3]] and rows['ordinary-pipe-relay']['ends']==[allocated[2],allocated[1]]
        pair=j['pair'];natural=set(rows)==set(m.core.ROLES) and all(r['exited'] and r['resumed'] and r['exit_code']==0 for r in rows.values())
        result.update(safe_projection_complete=True,held_tasks=tasks,proof=safe_proof(j['proof']),payload_files=payloads(m,stage,c,j),native=native_projection(m,stage,c,j,parent),
          pipe=dict(allocation_count=len(j['pipe_allocations']),allocation_unknown=j['pipe_allocation_unknown'],raw_return_receipts=returns,inherited_exact_two_each_direction=directions,parent_close_count=len(closes),parent_exact_four_closed=len(closes)==4 and {r['handle'] for r in closes}==set(allocated) and all(r['confirmed'] for r in closes)),
          journal=dict(intent_count=len(intents),commitments=intents),epoch=dict(root120_worker115=True,pair10=pair is not None and pair['end']==pair['start']+10*c['frequency'],pair_within_original_work85=pair is not None and pair['end']<=m.core.work_cutoff(c),completed_within_pair=j['completion_qpc'] is not None and pair is not None and j['completion_qpc']<pair['end']),
          three_natural_exit0=natural,workload_stop=j['workload_stop'],cleanup={k:j[k] for k in m.core.CLEAN_KEYS},
          ordinary_tool_exits=[dict(operation=r['name'],admitted=r['admitted'],resumed=r['resumed'],exited=r['exited'],exit_code=r['exit_code']) for r in (*j['tasks'],*j['cleanup_tasks']) if r['role'] not in m.core.ROLES])
    except Exception as e:result[{'validation':'validation_error','binding':'binding_error','projection':'projection_error'}[phase]]=error(e)
    return result

def globals_review(a):
    capture=read(work_name(a.capture_name),128*1024,inside=W);require(sha(capture)==a.capture_sha256,'reader_capture_pin')
    rows=[json_file(R/'private'/name,256*1024) for name in ('model2-first-01-global-baseline.json',a.before_snapshot_name,a.after_snapshot_name)]
    require(desc(rows[0][1])==dict(bytes=7378,sha256=BASELINE_SHA),'reader_original_global_baseline')
    keys=('firewall_profiles','dns','routes','user_proxy');require(all(all(k in v for k in keys) for v,_ in rows),'reader_four_global_objects')
    pairs_out={label:{k:rows[i][0][k]==rows[j][0][k] for k in keys} for label,i,j in (('original_before',0,1),('before_after',1,2),('original_after',0,2))}
    return dict(capture=desc(capture),snapshot_commitments=[desc(b) for _,b in rows],object_equalities=pairs_out,all_four_before_after_equal=all(pairs_out['before_after'].values()),
      whole_JSON_before_after_equal=rows[1][0]==rows[2][0],raw_bytes_before_after_equal=rows[1][1]==rows[2][1],route_difference_observed=not pairs_out['before_after']['routes'],
      route_writer_attribution_proven=False,route_difference_deleted_or_repaired=False,no_mutator_is_not_equality_proof=True,NRPT_included=False)

def audit(a):
    require(digest(a.source_commit,40) and all(digest(getattr(a,n)) for n in ('source_sha256','ready_freeze_sha256','public_sha256','preflight_sha256','driver_sha256','capture_sha256')),'reader_operator_pins')
    require(re.fullmatch('[a-z0-9-]{1,96}',a.prefix) and a.public_bytes>0 and a.preflight_bytes>0,'reader_public_pin_types')
    for n in ('plan_name','before_snapshot_name','after_snapshot_name'):work_name(getattr(a,n))
    pub,praw=json_file(R/'verification/windows-2026-10-22'/(a.prefix+'-public.json'),16384);pre,preraw=json_file(R/'verification/windows-2026-10-22'/(a.prefix+'-preflight.json'),16384)
    require(desc(praw)==dict(bytes=a.public_bytes,sha256=a.public_sha256) and desc(preraw)==dict(bytes=a.preflight_bytes,sha256=a.preflight_sha256),'reader_original_public_preflight_pins')
    m,stage,c,plan,config,ready=bind_sources(a,pub,pre);built=artifacts(m,stage,c,pub,pre)
    op=stage/'outer-launch-report.json';outer,oraw=json_file(op,m.MAX_REPORT) if op.exists() else (None,None)
    require((sha(oraw) if oraw is not None else None)==pub['outer_launch_report_sha256'],'reader_outer_physical_pin')
    driver=read(work_name(a.driver_name),256*1024,inside=W);require(sha(driver)==a.driver_sha256,'reader_driver_pin')
    groups={}
    for name in ('journal','returns'):
        directory=stage/name;files=sorted(directory.iterdir()) if directory.exists() else [];require(len(files)<=40,'reader_evidence_count');groups[name]=[desc(read(p,65536)) for p in files]
    result=result_review(m,stage,c,pub,outer)
    return dict(schema_version=1,stage='lpac-stream-origin-actual-file-review',scope=SCOPE,profile=PROFILE,source_commit=a.source_commit,source_sha256=a.source_sha256,source_count=45,Ready=ready,
      public=desc(praw),preflight=desc(preraw),original_status=pub['status'],original_failure=pub['failure'],original_observation_complete=pub['observation_complete'],original_recovery_required=pub['recovery_required'],original_safe_observation=pub['observation'],
      fixed_false_claims={k:pub[k] for k in m.core.FALSE_CLAIMS},compiled_artifacts=built,private_commitments=dict(plan=desc(plan),config=desc(config),outer_report=None if oraw is None else desc(oraw),worker_report=optional(stage/'worker-report.json',m.MAX_REPORT),forensic=optional(stage/'worker-result-forensic.json',m.MAX_REPORT),stdout=optional(stage/'guard/controller.stdout',2*1024*1024),stderr=optional(stage/'guard/controller.stderr',2*1024*1024),driver=desc(driver)),
      physical_evidence_commitments=groups,result_review=result,globals=globals_review(a),
      reader_actions=dict(file_only=True,production_backend_constructed=False,actor_or_cleanup_called=False,security_or_network_configuration_changed=False),
      limitations=['No missing/invalid report becomes denial or completion. Authentic malformed native bytes remain committed partials; valid peers retain independent observations.',
        'Forensic bytes never replace missing worker-report; when worker exists, exact forensic equality is independently required for binding.',
        'Raw outer launch report is the physical source-retained ledger; no separate raw outer PI or atomic flag receipt is invented.',
        'Reported peer tuple compares two source-bound ordinary native reports, not a kernel live TCP snapshot.',
        'Request-then-response finite binary challenge only. No general concurrent full-duplex deadlock or transparent socket semantics.',
        'No DNS, named-pipe acquisition/authentication, unmodified-app, real-Mihomo, PSEC/G, Linux or product acceptance.',
        'Global4 equality is observed per-object; prior or new route differences retain unknown writer attribution. No route cleanup is performed.'])

def main(argv=None):
    p=argparse.ArgumentParser(description=__doc__);p.add_argument('--verify-file-only',action='store_true');p.add_argument('--prefix',default='lpac-stream-origin-local-01')
    for n in ('source-commit','source-sha256','ready-freeze-name','ready-freeze-sha256','public-sha256','preflight-sha256','driver-name','driver-sha256','capture-name','capture-sha256','plan-name','before-snapshot-name','after-snapshot-name'):p.add_argument('--'+n)
    p.add_argument('--public-bytes',type=int);p.add_argument('--preflight-bytes',type=int);p.add_argument('--output-name',default='lpac-stream-origin-actual-01-independent-review.json')
    a=p.parse_args(argv)
    if not a.verify_file_only:
        print(json.dumps(dict(stage='lpac-stream-file-reader-candidate-preview',scope=SCOPE,verification_executed=False,repo_imported=False,files_written=False,final_operator_pins_required=True),sort_keys=True));return 0
    required=('source_commit','source_sha256','ready_freeze_name','ready_freeze_sha256','public_sha256','preflight_sha256','driver_name','driver_sha256','capture_name','capture_sha256','plan_name','before_snapshot_name','after_snapshot_name','public_bytes','preflight_bytes')
    require(all(getattr(a,n) is not None for n in required),'reader_final_pins_required');output=work_name(a.output_name);require(not output.exists(),'reader_fresh_output')
    value=audit(a);raw=(json.dumps(value,sort_keys=True,indent=2)+'\n').encode('ascii')
    with output.open('xb') as f:require(f.write(raw)==len(raw),'reader_exact_write')
    print(json.dumps(dict(review=desc(raw),worker_result_valid=value['result_review']['worker_result_valid'],original_status=value['original_status']),sort_keys=True));return 0
if __name__=='__main__':raise SystemExit(main())
