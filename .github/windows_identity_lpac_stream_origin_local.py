"""Separate guarded positive LPAC bounded byte-stream entry; default is read-only.

Inherited byte transport is a cooperative application-specific stream, not a
transparent proxy or network-denial mechanism. No source globals are patched.
"""
from __future__ import annotations
import argparse
import importlib.util
import os
from pathlib import Path
import sys

ROOT=Path(__file__).resolve().parents[1]
def load(name,file):
    s=importlib.util.spec_from_file_location(name,Path(__file__).with_name(file));m=importlib.util.module_from_spec(s);s.loader.exec_module(m);return m
core=load('lpac_stream_origin_owner','windows_identity_lpac_stream_origin.py')
base,local,launcher=core.base,core.local,core.launcher
require,sha,encode,decode=core.require,core.sha,core.encode,core.decode
SCOPE=core.SCOPE;MODULE=core.LOCAL_MODULE;SOURCES=core.SOURCES;MAX_REPORT=core.MAX_REPORT+64*1024
CHECKS=('ordinary','sources','artifact','plan','guard','worker_exit','outer_cleanup','worker_bound','mechanism')
FAILURES=('identity','inputs','plan','staging','worker','report','deadline','setup','origin','pair','accesscheck','protocol','cleanup')
def snapshot(root=ROOT):
    root=launcher.checked_path(root,is_file=False);files={}
    for name in SOURCES:
        raw=local.bounded(launcher.checked_path(root/name,inside=root),256*1024);require(b'\r' not in raw,'stream_source_lf');files[name]=raw
    hashes={name:sha(raw) for name,raw in files.items()};return files,hashes,sha(encode(hashes))
def blank(mode):
    return dict(schema_version=1,stage='local-lpac-stream-origin',scope=SCOPE,profile=core.PROFILE,mode=mode,status='inconclusive',failure=None,
        source_sha256=None,actor_sha256=None,manifest_sha256=None,network_actor_sha256=None,network_manifest_sha256=None,recovery_plan_sha256=None,outer_launch_report_sha256=None,challenges=None,
        checks=dict.fromkeys(CHECKS,False),observation=None,observation_complete=False,tree_retained=False,recovery_required=False,
        boundary='cooperative-bounded-binary-stream-lpac-ipc-only-ordinary-relay-owned-origin',**dict.fromkeys(core.FALSE_CLAIMS,False))
def validate_observation(v):
    keys={'schema_version','stage','scope','profile','mechanism_verified','selected_stream_observed','semantic_lpac_verified','network_tested','network_scope',
        'relay_connect_observed','origin_accepted_observed','origin_request_observed','origin_response_observed','payloads_verified','native_report_status','cleanup_known','failure','http_boundary',*core.CLEAN_KEYS,*core.FALSE_CLAIMS}
    require(type(v) is dict and set(v)==keys and type(v['schema_version']) is int and v['schema_version']==1 and v['stage']=='lpac-stream-origin-observation'
        and v['scope']==SCOPE and v['profile']==core.PROFILE and v['network_scope']=='ordinary-relay-to-owned-origin-only'
        and v['http_boundary']=='actual-file-provided-binary-bytes-through-one-inherited-stream-to-owned-origin','stream_public_observation')
    require((v['failure'] is None or v['failure'] in FAILURES) and all(type(v[k]) is bool for k in keys-{'schema_version','stage','scope','profile','network_scope','failure','http_boundary','native_report_status'}),'stream_observation_types')
    require(type(v['native_report_status']) is dict and set(v['native_report_status'])==set(core.REPORT_PATHS) and all(x in ('unavailable','valid','invalid') for x in v['native_report_status'].values()),'stream_public_report_status')
    require(all(v[k] is False for k in core.FALSE_CLAIMS) and v['network_tested']==(v['relay_connect_observed'] or v['origin_accepted_observed']),'stream_network_scope')
    require(not v['cleanup_known'] or all(v[k] for k in core.CLEAN_KEYS),'stream_public_cleanup')
    require(not v['mechanism_verified'] or v['failure'] is None and v['semantic_lpac_verified'] and v['selected_stream_observed'] and v['network_tested'] and v['origin_request_observed']
        and v['origin_response_observed'] and v['payloads_verified'] and v['cleanup_known'] and all(x=='valid' for x in v['native_report_status'].values()),'stream_public_positive');return v
def validate_public(v):
    t=blank(v.get('mode') if type(v) is dict else None)
    require(type(v) is dict and set(v)==set(t) and v['mode'] in ('preflight','runtime'),'stream_public_schema')
    for k in ('schema_version','stage','scope','profile','boundary',*core.FALSE_CLAIMS):require(type(v[k]) is type(t[k]) and v[k]==t[k],'stream_public_fixed')
    require(v['status'] in ('ready','inconclusive','observed') and (v['failure'] is None or v['failure'] in FAILURES),'stream_public_status')
    require(type(v['checks']) is dict and set(v['checks'])==set(CHECKS) and all(type(x) is bool for x in v['checks'].values()),'stream_public_checks')
    require(all(v[k] is None or base.ac.digest(v[k]) for k in t if k.endswith('_sha256')) and all(type(v[k]) is bool for k in ('observation_complete','tree_retained','recovery_required')),'stream_public_meta')
    for check,keys in (('sources',('source_sha256',)),('artifact',('actor_sha256','manifest_sha256','network_actor_sha256','network_manifest_sha256')),('plan',('recovery_plan_sha256',))):
        require(not v['checks'][check] or all(base.ac.digest(v[k]) for k in keys),'stream_public_commitment')
    require(not (v['checks']['guard'] or v['checks']['worker_bound']) or base.ac.digest(v['outer_launch_report_sha256']),'stream_outer_commitment')
    if v['challenges'] is not None:core.challenge_meta(v['challenges'])
    require(not v['checks']['artifact'] or v['challenges'] is not None,'stream_public_challenges')
    if v['observation'] is not None:validate_observation(v['observation']);require(v['checks']['worker_bound'] and v['checks']['mechanism']==v['observation']['mechanism_verified'],'stream_bound_observation')
    else:require(not v['checks']['worker_bound'] and not v['checks']['mechanism'],'stream_absent_observation')
    if v['mode']=='preflight':require(v['observation'] is None and not any(v['checks'][k] for k in CHECKS[4:]) and not v['observation_complete'] and not v['tree_retained'],'stream_readonly_preflight')
    if v['status']=='ready':require(v['mode']=='preflight' and all(v['checks'][k] for k in CHECKS[:4]) and v['failure'] is None,'stream_ready')
    require(v['observation_complete']==(v['status']=='observed'),'stream_observed_flag')
    if v['status']=='observed':require(v['mode']=='runtime' and v['failure'] is None and all(v['checks'].values()) and not v['recovery_required'] and v['observation']['mechanism_verified'],'stream_observed_gate')
    return v
def preflight(actor,manifest,actor_hash,manifest_hash,network_actor,network_manifest,network_hash,network_manifest_hash,request_path,response_path,parent_path,plan_path,*,api=None,root=ROOT):
    r=blank('preflight');phase='inputs'
    try:
        require(os.name=='nt' and core.api_version()==1,'stream_platform');api=api or local.LocalNativeAPI();require(api.windows_x64(),'stream_platform')
        phase='identity';local.ordinary(api);r['checks']['ordinary']=True
        phase='inputs';_,_,source=snapshot(root);r['source_sha256']=source;r['checks']['sources']=True
        core.verify_actor(actor,manifest,actor_hash,manifest_hash,root=root);core.verify_actor(network_actor,network_manifest,network_hash,network_manifest_hash,root=root,network=True)
        r.update(actor_sha256=actor_hash,manifest_sha256=manifest_hash,network_actor_sha256=network_hash,network_manifest_sha256=network_manifest_hash)
        challenges=core.challenge_inputs(request_path,response_path);r['challenges']=challenges;r['checks']['artifact']=True
        launcher.checked_path(parent_path,inside=root/'private',is_file=False);phase='plan';raw=local.bounded(plan_path,8192)
        core.validate_plan(decode(raw),device=api.device_sha256(),source=source,actor=actor_hash,manifest=manifest_hash,network_actor=network_hash,network_manifest=network_manifest_hash,challenges=challenges)
        r['recovery_plan_sha256']=sha(raw);r['checks']['plan']=True;r['status']='ready'
    except BaseException:r['failure']=phase
    return validate_public(r)
def bind_report(report,c,parent,launch,result,*,root):
    raw=encode(launch);require(sha(raw)==result['outer_launch_report_sha256'] and local.bounded(launcher.checked_path(Path(root)/'outer-launch-report.json',inside=root),MAX_REPORT)==raw,'stream_outer_physical')
    require(launch.get('started') is True and launch.get('resumed') is True and launch.get('native_identity_verified_before_resume') is True and launch.get('cleanup',{}).get('process_exit_confirmed') is True
        and type(launch.get('child_pid')) is int and launch['child_pid']>0 and launch.get('child_identity')==launcher.safe_identity(parent,parent),'stream_worker_held')
    require(type(report) is dict and set(report)=={'schema_version','stage','config','worker_pid','worker_identity','result'} and type(report['schema_version']) is int and report['schema_version']==1
        and report['stage']=='lpac-stream-origin-worker' and report['config']==c and report['worker_identity']==parent and type(report['worker_pid']) is int and report['worker_pid']==launch['child_pid'],'stream_worker_binding')
    observation=validate_observation(core.project(report['result'],c,parent=parent,root=root));result['observation']=observation;result['checks']['worker_bound']=True
    result['checks']['mechanism']=observation['mechanism_verified'];result['failure']=observation['failure']
    result['recovery_required']=not (all(result['checks'][k] for k in ('guard','worker_exit','outer_cleanup','worker_bound')) and observation['cleanup_known']);return result
def worker(config_path):
    require(launcher.checked_path(config_path,inside=ROOT)==ROOT/'worker-config.json','stream_worker_path');c=core.config_validate(decode(local.bounded(config_path,MAX_REPORT)),source_names=SOURCES)
    require(ROOT.name==core.stage_name(c['run']),'stream_worker_stage');_,hashes,source=snapshot()
    require(hashes==c['source_hashes'] and source==c['source_sha256'] and core.ACTUAL_READY,'stream_worker_source_ready')
    api=core.API();parent=local.ordinary(api);require(api.qpc_frequency()==c['frequency'],'stream_worker_frequency');budget=launcher.QpcBudget(api,c['deadline_qpc'],c['frequency']);budget.require_ms(core.work_cutoff(c))
    require(local.LocalNativeAPI.device_sha256(api.native)==c['device_sha256'],'stream_device')
    raw=local.bounded(ROOT/'recovery-plan.json',8192);require(sha(raw)==c['recovery_plan_sha256'],'stream_worker_plan')
    p=core.validate_plan(decode(raw),device=c['device_sha256'],source=source,actor=c['actor_sha256'],manifest=c['manifest_sha256'],network_actor=c['network_actor_sha256'],network_manifest=c['network_manifest_sha256'],challenges=c['challenges'])
    require(all(p[k]==c[k] for k in core.NONCES),'stream_worker_plan_nonces')
    local.LocalNativeAPI.verify_private_directory(api.native,ROOT,'D:P(A;OICI;FA;;;SY)(A;OICI;FA;;;'+parent['sid']+')');local.verify_guard_job(api.native,c['guard_job_name']);core.verify_artifacts(c,ROOT)
    private=core.execute(ROOT,c,parent,api,budget);report=dict(schema_version=1,stage='lpac-stream-origin-worker',config=c,worker_pid=os.getpid(),worker_identity=parent,result=private)
    base.durable_private(ROOT/'worker-result-forensic.json',encode(report));core.validate_result(private,c,parent=parent,root=ROOT);budget.require_ms(budget.cutoff(1));base.durable_private(ROOT/'worker-report.json',encode(report));return 0
def run_local(actor,manifest,actor_hash,manifest_hash,network_actor,network_manifest,network_hash,network_manifest_hash,request_path,response_path,parent_path,plan_path,*,approved=False,root=ROOT):
    r=blank('runtime');phase='inputs';launched=False;stage=None
    try:
        require(approved and core.ACTUAL_READY and os.name=='nt','stream_explicit_ready_optin');api=local.LocalNativeAPI();require(api.windows_x64(),'stream_platform')
        f=api.qpc_frequency();start=api.qpc();end=start+120*f;budget=launcher.QpcBudget(api,end,f)
        check=preflight(actor,manifest,actor_hash,manifest_hash,network_actor,network_manifest,network_hash,network_manifest_hash,request_path,response_path,parent_path,plan_path,api=api,root=root)
        for k in ('source_sha256','actor_sha256','manifest_sha256','network_actor_sha256','network_manifest_sha256','recovery_plan_sha256','challenges'):r[k]=check[k]
        r['checks'].update(check['checks']);require(check['status']=='ready','stream_preflight')
        parent=local.ordinary(api);files,hashes,source=snapshot(root);require(source==r['source_sha256'],'stream_source_changed')
        planraw=local.bounded(plan_path,8192);require(sha(planraw)==r['recovery_plan_sha256'],'stream_plan_changed')
        challenges=core.challenge_inputs(request_path,response_path,r['challenges'])
        p=core.validate_plan(decode(planraw),device=api.device_sha256(),source=source,actor=actor_hash,manifest=manifest_hash,network_actor=network_hash,network_manifest=network_manifest_hash,challenges=challenges)
        c=dict(schema_version=1,scope=SCOPE,profile=core.PROFILE,**{k:p[k] for k in core.NONCES},frequency=f,start_qpc=start,root_deadline_qpc=end,deadline_qpc=end-5*f,
            guard_job_name='Local\\RuleProxy.LocalGuard.'+p['run'],source_hashes=hashes,source_sha256=source,device_sha256=api.device_sha256(),
            actor_sha256=actor_hash,manifest_sha256=manifest_hash,network_actor_sha256=network_hash,network_manifest_sha256=network_manifest_hash,recovery_plan_sha256=r['recovery_plan_sha256'],challenges=challenges);core.config_validate(c)
        phase='staging';budget.require_ms(budget.cutoff(45));parent_path=launcher.checked_path(parent_path,inside=root/'private',is_file=False);stage=parent_path/core.stage_name(c['run'])
        require(not stage.exists() and not stage.is_symlink(),'stream_fresh_stage');r['tree_retained']=True;api.private_directory(stage,parent['sid'])
        for name,raw in files.items():
            path=stage/name;path.parent.mkdir(parents=True,exist_ok=True);launcher.write_private_bytes(path,raw);require(sha(local.bounded(path,256*1024))==hashes[name],'stream_staged_source')
        for name in ('inputs','tools','guard','journal','returns','health','selected-inputs','ordinary-inputs','selected-report','relay-report','origin-report'):(stage/name).mkdir()
        for name in ('guard','health','relay-report','origin-report'):(stage/name/'temp').mkdir()
        for src in (Path(actor),Path(manifest),Path(network_actor),Path(network_manifest)):launcher.write_private_bytes(stage/'inputs'/src.name,local.bounded(src,8*1024*1024))
        for key,source_path in (('request',request_path),('response',response_path)):launcher.write_private_bytes(stage/core.CHALLENGE_PATHS[key],local.bounded(source_path,65536))
        core.verify_artifacts(c,stage);base.durable_private(stage/'worker-config.json',encode(c));base.durable_private(stage/'recovery-plan.json',planraw)
        api.worker_job_name=c['guard_job_name'];api.worker_sid=parent['sid'];python=launcher.checked_path(sys.executable,inside=launcher.checked_path(sys.base_prefix,is_file=False));require(python.name.casefold()=='python.exe','stream_python')
        command=[str(python),'-I','-S','-B',str(stage/MODULE),'--worker',str(stage/'worker-config.json')];phase='worker';launched=True
        launch=launcher.launch_owned(api,command,stage/'guard',parent,parent,qpc_budget=budget,work_cutoff=budget.cutoff(3),cleanup_cutoff=end)
        base.durable_private(stage/'outer-launch-report.json',encode(launch));r['outer_launch_report_sha256']=sha(encode(launch))
        r['checks']['guard']=api.atomic_job_requested and launch.get('native_identity_verified_before_resume') is True;r['checks']['worker_exit']=launch.get('cleanup',{}).get('process_exit_confirmed') is True;r['checks']['outer_cleanup']=local.guest.cleanup_verified(launch)
        phase='report';require(r['checks']['worker_exit'] and launch.get('started') is True,'stream_unknown_worker')
        report=decode(local.bounded(stage/'worker-report.json',MAX_REPORT));bind_report(report,c,parent,launch,r,root=stage)
        require(launch.get('resumed') is True and launch.get('timed_out') is not True and launch.get('exit_code')==0 and 'error' not in launch,'stream_worker_launch');phase='deadline';budget.require_ms(end)
        r['observation_complete']=all(r['checks'].values()) and r['failure'] is None and not r['recovery_required']
        if r['observation_complete']:r['status']='observed'
    except BaseException:
        r['failure']=phase;r['status']='inconclusive';r['observation_complete']=False
        clean=all(r['checks'][k] for k in ('guard','worker_exit','outer_cleanup','worker_bound')) and r['observation'] is not None and r['observation']['cleanup_known']
        if launched and not clean or stage is not None and not launched:r['recovery_required']=True
    return validate_public(r)
def main(argv=None):
    p=argparse.ArgumentParser(description=__doc__);p.add_argument('--worker',help=argparse.SUPPRESS);p.add_argument('--run-local-lpac-stream-origin',action='store_true')
    for name in ('actor','manifest','network-actor','network-manifest','request','response','work-parent','recovery-plan','output'):p.add_argument('--'+name,type=Path)
    for name in ('actor-sha256','manifest-sha256','network-actor-sha256','network-manifest-sha256'):p.add_argument('--'+name)
    a=p.parse_args(argv)
    if a.worker:
        require(not a.run_local_lpac_stream_origin and not any(getattr(a,k) for k in ('actor','manifest','network_actor','network_manifest','request','response','work_parent','recovery_plan','output','actor_sha256','manifest_sha256','network_actor_sha256','network_manifest_sha256')),'stream_exact_worker_args');return worker(Path(a.worker))
    args=(a.actor,a.manifest,a.actor_sha256,a.manifest_sha256,a.network_actor,a.network_manifest,a.network_actor_sha256,a.network_manifest_sha256,a.request,a.response,a.work_parent,a.recovery_plan)
    if not all(args):r=blank('runtime' if a.run_local_lpac_stream_origin else 'preflight');r['failure']='inputs'
    else:r=(run_local(*args,approved=True) if a.run_local_lpac_stream_origin else preflight(*args))
    raw=encode(validate_public(r))
    if a.output:launcher.write_private_bytes(a.output,raw)
    print(raw.decode('ascii'),end='');return 0 if r['status'] in ('ready','observed') else 1
if __name__=='__main__':raise SystemExit(main())
