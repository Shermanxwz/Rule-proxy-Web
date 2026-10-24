"""Separate guarded same-process finite LPAC IPC/DNS entry; default is read-only.

Inherited pipe transport is a cooperative application-specific mapping, not a
transparent proxy or broad DNS/network-denial mechanism. No source globals are patched.
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
core=load('lpac_pipe_dns_nrpt_origin_owner','windows_identity_lpac_pipe_dns_nrpt_origin.py')
base,local,launcher=core.base,core.local,core.launcher
require,sha,encode,decode=core.require,core.sha,core.encode,core.decode
SCOPE=core.SCOPE;MODULE=core.LOCAL_MODULE;SOURCES=core.SOURCES;MAX_REPORT=core.MAX_REPORT+64*1024
CHECKS=('ordinary','sources','artifact','plan','guard','worker_exit','outer_cleanup','worker_bound','mechanism')
FAILURES=('identity','inputs','plan','staging','worker','report','deadline','setup','origin','pair','accesscheck','protocol','cleanup','inventory')
def snapshot(root=ROOT):
    root=launcher.checked_path(root,is_file=False);files={}
    for name in SOURCES:
        raw=local.bounded(launcher.checked_path(root/name,inside=root),256*1024);require(b'\r' not in raw,'ipc_source_lf');files[name]=raw
    hashes={name:sha(raw) for name,raw in files.items()};return files,hashes,sha(encode(hashes))
def blank(mode):
    return dict(schema_version=1,stage='local-lpac-pipe-dns-nrpt-origin',scope=SCOPE,profile=core.PROFILE,policy_mode=core.POLICY_MODE,policy_inventory=core.policy.unknown_inventory(),mode=mode,status='inconclusive',failure=None,
        source_sha256=None,actor_sha256=None,manifest_sha256=None,origin_actor_sha256=None,origin_manifest_sha256=None,control_actor_sha256=None,control_manifest_sha256=None,recovery_plan_sha256=None,outer_launch_report_sha256=None,
        checks=dict.fromkeys(CHECKS,False),observation=None,observation_complete=False,tree_retained=False,recovery_required=False,selected_wire_query_observed=False,selected_dns_api_tested=False,api_lifecycle_unknown=False,
        boundary='same-held-zero-cap-lpac-ipc-plus-finite-explicit-standard53-exact-nrpt-nonmatch',**dict.fromkeys(core.FALSE_CLAIMS,False))
def validate_observation(v):return core.validate_projection(v)

def validate_public(v):
    t=blank(v.get('mode') if type(v) is dict else None)
    require(type(v) is dict and set(v)==set(t) and v['mode'] in ('preflight','runtime'),'ipc_public_schema')
    for k in ('schema_version','stage','scope','profile','policy_mode','boundary',*core.FALSE_CLAIMS):require(type(v[k]) is type(t[k]) and v[k]==t[k],'ipc_public_fixed')
    core.policy.inventory_public(v['policy_inventory'])
    require(v['status'] in ('ready','inconclusive','observed','failed') and (v['failure'] is None or v['failure'] in FAILURES),'ipc_public_status')
    require(type(v['checks']) is dict and set(v['checks'])==set(CHECKS) and all(type(x) is bool for x in v['checks'].values()),'ipc_public_checks')
    require(all(v[k] is None or base.ac.digest(v[k]) for k in t if k.endswith('_sha256')) and all(type(v[k]) is bool for k in ('observation_complete','tree_retained','recovery_required','selected_wire_query_observed','selected_dns_api_tested','api_lifecycle_unknown')),'ipc_public_meta')
    for check,keys in (('sources',('source_sha256',)),('artifact',('actor_sha256','manifest_sha256','origin_actor_sha256','origin_manifest_sha256','control_actor_sha256','control_manifest_sha256')),('plan',('recovery_plan_sha256',))):
        require(not v['checks'][check] or all(base.ac.digest(v[k]) for k in keys),'ipc_public_commitment')
    require(not (v['checks']['guard'] or v['checks']['worker_bound']) or base.ac.digest(v['outer_launch_report_sha256']),'ipc_outer_commitment')
    if v['observation'] is not None:
        validate_observation(v['observation']);require(v['checks']['worker_bound'] and v['checks']['mechanism']==v['observation']['access_denial_observed'],'ipc_bound_observation')
        require(v['policy_inventory']==v['observation']['policy_inventory'],'pipe_dns_policy_public_binding')
        require(all(not v['observation'][k] or v[k] for k in ('selected_wire_query_observed','selected_dns_api_tested','api_lifecycle_unknown')),'pipe_dns_public_sticky')
    else:require(not v['checks']['worker_bound'] and not v['checks']['mechanism'] and v['policy_inventory']==core.policy.unknown_inventory(),'ipc_absent_observation')
    if v['mode']=='preflight':require(v['observation'] is None and not any(v['checks'][k] for k in CHECKS[4:]) and not v['observation_complete'] and not v['tree_retained'] and not v['selected_wire_query_observed'] and not v['selected_dns_api_tested'] and not v['api_lifecycle_unknown'],'ipc_readonly_preflight')
    if v['status']=='ready':require(v['mode']=='preflight' and all(v['checks'][k] for k in CHECKS[:4]) and v['failure'] is None,'ipc_ready')
    require(v['observation_complete']==(v['status']=='observed'),'ipc_observed_flag')
    require((v['status']=='failed')==v['selected_wire_query_observed'] and (not v['selected_wire_query_observed'] or not v['observation_complete']),'pipe_dns_outer_wire')
    if v['status']=='observed':require(v['mode']=='runtime' and v['failure'] is None and all(v['checks'].values()) and not v['recovery_required'] and v['observation']['access_denial_observed'],'ipc_observed_gate')
    return v
def preflight(actor,manifest,actor_hash,manifest_hash,origin_actor,origin_manifest,origin_hash,origin_manifest_hash,control_actor,control_manifest,control_hash,control_manifest_hash,parent_path,plan_path,*,api=None,root=ROOT):
    r=blank('preflight');phase='inputs'
    try:
        require(os.name=='nt' and core.api_version()==1,'ipc_platform');api=api or local.LocalNativeAPI();require(api.windows_x64(),'ipc_platform')
        phase='identity';local.ordinary(api);r['checks']['ordinary']=True
        phase='inputs';_,_,source=snapshot(root);r['source_sha256']=source;r['checks']['sources']=True
        core.verify_actor(actor,manifest,actor_hash,manifest_hash,root=root);core.origin.verify_artifact(origin_actor,origin_manifest,origin_manifest_hash,origin_hash,source_root=root);core.verify_actor(control_actor,control_manifest,control_hash,control_manifest_hash,root=root,control=True)
        r.update(actor_sha256=actor_hash,manifest_sha256=manifest_hash,origin_actor_sha256=origin_hash,origin_manifest_sha256=origin_manifest_hash,control_actor_sha256=control_hash,control_manifest_sha256=control_manifest_hash);r['checks']['artifact']=True
        launcher.checked_path(parent_path,inside=root/'private',is_file=False);phase='plan';raw=local.bounded(plan_path,8192)
        core.validate_plan(decode(raw),device=api.device_sha256(),source=source,actor=actor_hash,manifest=manifest_hash,origin_actor=origin_hash,origin_manifest=origin_manifest_hash,control_actor=control_hash,control_manifest=control_manifest_hash)
        r['recovery_plan_sha256']=sha(raw);r['checks']['plan']=True;r['status']='ready'
    except BaseException:r['failure']=phase
    return validate_public(r)
def bind_report(report,c,parent,launch,result,*,root):
    raw=encode(launch);require(sha(raw)==result['outer_launch_report_sha256'] and local.bounded(launcher.checked_path(Path(root)/'outer-launch-report.json',inside=root),MAX_REPORT)==raw,'ipc_outer_physical')
    require(launch.get('started') is True and launch.get('resumed') is True and launch.get('native_identity_verified_before_resume') is True and launch.get('cleanup',{}).get('process_exit_confirmed') is True
        and type(launch.get('child_pid')) is int and launch['child_pid']>0 and launch.get('child_identity')==launcher.safe_identity(parent,parent),'ipc_worker_held')
    require(type(report) is dict and set(report)=={'schema_version','stage','config','worker_pid','worker_identity','result'} and type(report['schema_version']) is int and report['schema_version']==1
        and report['stage']=='lpac-pipe-dns-nrpt-origin-worker' and report['config']==c and report['worker_identity']==parent and type(report['worker_pid']) is int and report['worker_pid']==launch['child_pid'],'ipc_worker_binding')
    j=report['result'];hit=type(j) is dict and j.get('selected_wire_query_observed') is True
    if type(j) is dict and type(j.get('fixture_final')) is dict:
        f=j['fixture_final'];hit |= f.get('selected_query_observed') is True or type(f.get('case_query_observed')) is dict and f['case_query_observed'].get('selected') is True
    result['selected_wire_query_observed'] |= hit;result['api_lifecycle_unknown'] |= type(j) is dict and j.get('api_lifecycle_unknown') is True
    if hit:result['status']='failed'
    observation=validate_observation(core.project(j,c,parent=parent,root=root));result['observation']=observation;result['policy_inventory']=dict(observation['policy_inventory']);result['checks']['worker_bound']=True
    result['checks']['mechanism']=observation['access_denial_observed'];result['selected_dns_api_tested'] |= observation['selected_dns_api_tested'];result['failure']=observation['failure'];result['api_lifecycle_unknown'] |= observation['api_lifecycle_unknown']
    result['recovery_required']=not (all(result['checks'][k] for k in ('guard','worker_exit','outer_cleanup','worker_bound')) and observation['cleanup_known']) or result['api_lifecycle_unknown'];return result
def worker(config_path):
    require(launcher.checked_path(config_path,inside=ROOT)==ROOT/'worker-config.json','ipc_worker_path');c=core.config_validate(decode(local.bounded(config_path,MAX_REPORT)),source_names=SOURCES)
    require(ROOT.name==core.stage_name(c['run']),'ipc_worker_stage');_,hashes,source=snapshot()
    require(hashes==c['source_hashes'] and source==c['source_sha256'] and core.ACTUAL_READY,'ipc_worker_source_ready')
    api=core.API();parent=local.ordinary(api);require(api.qpc_frequency()==c['frequency'],'ipc_worker_frequency');budget=launcher.QpcBudget(api,c['deadline_qpc'],c['frequency']);budget.require_ms(core.work_cutoff(c))
    require(local.LocalNativeAPI.device_sha256(api.native)==c['device_sha256'],'ipc_device')
    raw=local.bounded(ROOT/'recovery-plan.json',8192);require(sha(raw)==c['recovery_plan_sha256'],'ipc_worker_plan')
    p=core.validate_plan(decode(raw),device=c['device_sha256'],source=source,actor=c['actor_sha256'],manifest=c['manifest_sha256'],origin_actor=c['origin_actor_sha256'],origin_manifest=c['origin_manifest_sha256'],control_actor=c['control_actor_sha256'],control_manifest=c['control_manifest_sha256'])
    require(all(p[k]==c[k] for k in core.NONCES),'ipc_worker_plan_nonces')
    local.LocalNativeAPI.verify_private_directory(api.native,ROOT,'D:P(A;OICI;FA;;;SY)(A;OICI;FA;;;'+parent['sid']+')');local.verify_guard_job(api.native,c['guard_job_name']);core.verify_artifacts(c,ROOT)
    private=core.execute(ROOT,c,parent,api,budget);report=dict(schema_version=1,stage='lpac-pipe-dns-nrpt-origin-worker',config=c,worker_pid=os.getpid(),worker_identity=parent,result=private)
    base.durable_private(ROOT/'worker-result-forensic.json',encode(report));core.validate_result(private,c,parent=parent,root=ROOT);budget.require_ms(budget.cutoff(1));base.durable_private(ROOT/'worker-report.json',encode(report));return 0
def run_local(actor,manifest,actor_hash,manifest_hash,origin_actor,origin_manifest,origin_hash,origin_manifest_hash,control_actor,control_manifest,control_hash,control_manifest_hash,parent_path,plan_path,*,approved=False,root=ROOT):
    r=blank('runtime');phase='inputs';launched=False;stage=None
    try:
        require(approved and core.ACTUAL_READY and os.name=='nt','ipc_explicit_ready_optin');api=local.LocalNativeAPI();require(api.windows_x64(),'ipc_platform')
        f=api.qpc_frequency();start=api.qpc();end=start+120*f;budget=launcher.QpcBudget(api,end,f)
        check=preflight(actor,manifest,actor_hash,manifest_hash,origin_actor,origin_manifest,origin_hash,origin_manifest_hash,control_actor,control_manifest,control_hash,control_manifest_hash,parent_path,plan_path,api=api,root=root)
        for k in ('source_sha256','actor_sha256','manifest_sha256','origin_actor_sha256','origin_manifest_sha256','control_actor_sha256','control_manifest_sha256','recovery_plan_sha256'):r[k]=check[k]
        r['checks'].update(check['checks']);require(check['status']=='ready','ipc_preflight')
        parent=local.ordinary(api);files,hashes,source=snapshot(root);require(source==r['source_sha256'],'ipc_source_changed')
        planraw=local.bounded(plan_path,8192);require(sha(planraw)==r['recovery_plan_sha256'],'ipc_plan_changed')
        p=core.validate_plan(decode(planraw),device=api.device_sha256(),source=source,actor=actor_hash,manifest=manifest_hash,origin_actor=origin_hash,origin_manifest=origin_manifest_hash,control_actor=control_hash,control_manifest=control_manifest_hash)
        c=dict(schema_version=1,scope=SCOPE,profile=core.PROFILE,policy_mode=core.POLICY_MODE,**{k:p[k] for k in core.NONCES},frequency=f,start_qpc=start,root_deadline_qpc=end,deadline_qpc=end-5*f,
            guard_job_name='Local\\RuleProxy.LocalGuard.'+p['run'],source_hashes=hashes,source_sha256=source,device_sha256=api.device_sha256(),
            actor_sha256=actor_hash,manifest_sha256=manifest_hash,origin_actor_sha256=origin_hash,origin_manifest_sha256=origin_manifest_hash,control_actor_sha256=control_hash,control_manifest_sha256=control_manifest_hash,recovery_plan_sha256=r['recovery_plan_sha256']);core.config_validate(c)
        phase='staging';budget.require_ms(budget.cutoff(45));parent_path=launcher.checked_path(parent_path,inside=root/'private',is_file=False);stage=parent_path/core.stage_name(c['run'])
        require(not stage.exists() and not stage.is_symlink(),'ipc_fresh_stage');r['tree_retained']=True;api.private_directory(stage,parent['sid'])
        for name,raw in files.items():
            path=stage/name;path.parent.mkdir(parents=True,exist_ok=True);launcher.write_private_bytes(path,raw);require(sha(local.bounded(path,256*1024))==hashes[name],'ipc_staged_source')
        for name in ('inputs','tools','guard','journal','returns','health','selected-report','relay-report','origin-report'):(stage/name).mkdir()
        for name in ('guard','health','relay-report','origin-report'):(stage/name/'temp').mkdir()
        for src in (Path(actor),Path(manifest),Path(origin_actor),Path(origin_manifest),Path(control_actor),Path(control_manifest)):launcher.write_private_bytes(stage/'inputs'/src.name,local.bounded(src,8*1024*1024))
        core.verify_artifacts(c,stage);base.durable_private(stage/'worker-config.json',encode(c));base.durable_private(stage/'recovery-plan.json',planraw)
        api.worker_job_name=c['guard_job_name'];api.worker_sid=parent['sid'];python=launcher.checked_path(sys.executable,inside=launcher.checked_path(sys.base_prefix,is_file=False));require(python.name.casefold()=='python.exe','ipc_python')
        command=[str(python),'-I','-S','-B',str(stage/MODULE),'--worker',str(stage/'worker-config.json')];phase='worker';launched=True
        launch=launcher.launch_owned(api,command,stage/'guard',parent,parent,qpc_budget=budget,work_cutoff=budget.cutoff(3),cleanup_cutoff=end)
        base.durable_private(stage/'outer-launch-report.json',encode(launch));r['outer_launch_report_sha256']=sha(encode(launch))
        r['checks']['guard']=api.atomic_job_requested and launch.get('native_identity_verified_before_resume') is True;r['checks']['worker_exit']=launch.get('cleanup',{}).get('process_exit_confirmed') is True;r['checks']['outer_cleanup']=local.guest.cleanup_verified(launch)
        phase='report';require(r['checks']['worker_exit'] and launch.get('started') is True,'ipc_unknown_worker')
        report=decode(local.bounded(stage/'worker-report.json',MAX_REPORT));bind_report(report,c,parent,launch,r,root=stage)
        require(launch.get('resumed') is True and launch.get('timed_out') is not True and launch.get('exit_code')==0 and 'error' not in launch,'ipc_worker_launch');phase='deadline';budget.require_ms(end)
        r['observation_complete']=all(r['checks'].values()) and r['failure'] is None and not r['recovery_required']
        if r['observation_complete']:r['status']='observed'
        elif r['selected_wire_query_observed']:r['status']='failed'
    except BaseException:
        r['failure']=phase;r['status']='failed' if r['selected_wire_query_observed'] else 'inconclusive';r['observation_complete']=False;r['checks']['mechanism']=False
        if r['observation'] is not None:r['observation']['observation_complete']=False;r['observation']['access_denial_observed']=False
        clean=all(r['checks'][k] for k in ('guard','worker_exit','outer_cleanup','worker_bound')) and r['observation'] is not None and r['observation']['cleanup_known']
        if launched and not clean or stage is not None and not launched:r['recovery_required']=True
    return validate_public(r)
def main(argv=None):
    p=argparse.ArgumentParser(description=__doc__);p.add_argument('--worker',help=argparse.SUPPRESS);p.add_argument('--run-local-lpac-pipe-dns-nrpt-origin',action='store_true')
    for name in ('actor','manifest','origin-actor','origin-manifest','control-actor','control-manifest','work-parent','recovery-plan','output'):p.add_argument('--'+name,type=Path)
    for name in ('actor-sha256','manifest-sha256','origin-actor-sha256','origin-manifest-sha256','control-actor-sha256','control-manifest-sha256'):p.add_argument('--'+name)
    a=p.parse_args(argv)
    if a.worker:
        require(not a.run_local_lpac_pipe_dns_nrpt_origin and not any(getattr(a,k) for k in ('actor','manifest','origin_actor','origin_manifest','control_actor','control_manifest','work_parent','recovery_plan','output','actor_sha256','manifest_sha256','origin_actor_sha256','origin_manifest_sha256','control_actor_sha256','control_manifest_sha256')),'ipc_exact_worker_args');return worker(Path(a.worker))
    args=(a.actor,a.manifest,a.actor_sha256,a.manifest_sha256,a.origin_actor,a.origin_manifest,a.origin_actor_sha256,a.origin_manifest_sha256,a.control_actor,a.control_manifest,a.control_actor_sha256,a.control_manifest_sha256,a.work_parent,a.recovery_plan)
    if not all(args):r=blank('runtime' if a.run_local_lpac_pipe_dns_nrpt_origin else 'preflight');r['failure']='inputs'
    else:r=(run_local(*args,approved=True) if a.run_local_lpac_pipe_dns_nrpt_origin else preflight(*args))
    raw=encode(validate_public(r))
    if a.output:launcher.write_private_bytes(a.output,raw)
    print(raw.decode('ascii'),end='');return 0 if r['status'] in ('ready','observed') else 1
if __name__=='__main__':raise SystemExit(main())
