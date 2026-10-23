"""Guarded WORK prototype for a held zero-cap curl loader experiment.

Default entry never executes an actor or loads the wrapper. A future runtime
requires the separately promoted Ready flag, an explicit opt-in, and the exact
source, plan and artifact gates. Test injection never constructs a native API.
"""
from __future__ import annotations
import argparse
import importlib.util
import os
from pathlib import Path
import sys

ROOT=Path(__file__).resolve().parents[1]
def load(name,file):
    s=importlib.util.spec_from_file_location(name,Path(__file__).with_name(file))
    m=importlib.util.module_from_spec(s);s.loader.exec_module(m);return m
core=load('lpac_curl_loader_guard_core','windows_identity_lpac_curl_loader.py')
base,local,launcher=core.base,core.local,core.launcher
require,sha,encode,decode=core.require,core.sha,core.encode,core.decode
SCOPE=core.SCOPE;MODULE=core.LOCAL_MODULE;SOURCES=core.SOURCES
MAX_REPORT=core.MAX_REPORT+64*1024
CHECKS=('ordinary','sources','artifacts','plan','guard','worker_exit','outer_cleanup','worker_bound','mechanism')
FAILURES=('inputs','disabled','identity','plan','staging','worker','report','deadline',*core.FAILURES)
DIRS=('owner-inputs','package','selected-output','ordinary-before','ordinary-after','tools','guard','returns','journal')
TEMPS=('ordinary-before','ordinary-after','guard','tools/grant-root','tools/grant-package','tools/grant-output','tools/remove')
BOUNDARY='finite-no-URL-curl-loader-events-and-version-controls-only'

def snapshot(root=ROOT):
    root=launcher.checked_path(root,is_file=False);files={}
    for name in SOURCES:
        path=launcher.checked_path(root/name,inside=root)
        raw=local.bounded(path,256*1024)
        # Fixed upstream Detours blobs retain their original bytes, including
        # CR where present; never normalize vendor content into a new input.
        require(name.startswith('.github/vendor/detours/') or b'\r' not in raw,'curl_loader_source_lf');files[name]=raw
    hashes={k:sha(v) for k,v in files.items()}
    return files,hashes,sha(encode(hashes))

def blank(mode):
    return dict(schema_version=1,stage='local-lpac-curl-loader',scope=SCOPE,profile=core.PROFILE,mode=mode,
        status='inconclusive',failure=None,source_sha256=None,artifacts=None,recovery_plan_sha256=None,
        outer_launch_report_sha256=None,checks=dict.fromkeys(CHECKS,False),
        ordinary_controls=dict(before=False,after=False),observation=None,observation_complete=False,
        tree_retained=False,recovery_required=False,boundary=BOUNDARY,**dict.fromkeys(core.FALSE_CLAIMS,False))

def validate_observation(v):
    require(type(v) is dict and set(v)==core.OBS_KEYS,'curl_loader_public_observation')
    require(all(type(v[k]) is bool for k in (*core.OBS_BOOLS,*core.FALSE_CLAIMS)), 'curl_loader_public_observation_types')
    require(v['failure'] is None or v['failure'] in core.FAILURES,'curl_loader_public_failure')
    require(v['selected_exit_code'] is None or core.live.integer(v['selected_exit_code'],0,0xffffffff),'curl_loader_public_exit')
    require(all(v[k] is False for k in core.FALSE_CLAIMS),'curl_loader_public_false_claims')
    require(not v['selected_version_positive'] or v['selected_natural_exit'] and v['selected_exit_code']==0,'curl_loader_public_selected_version')
    require(not v['loader_mechanism_observed'] or all(v[k] for k in ('lpac_identity_verified','update_returned_true','payload_installed',
        'selected_resumed','entered_event_observed','body_event_observed','coherent_marker_observed','mapped_marker_correlated')),'curl_loader_public_loader')
    require(not v['version_behavior_observed'] or all(v[k] for k in ('ordinary_before_positive','ordinary_after_positive','selected_version_positive')),'curl_loader_public_version')
    require(not v['observation_complete'] or v['failure'] is None and v['loader_mechanism_observed'] and v['version_behavior_observed']
        and all(v[k] for k in core.CLEAN_KEYS),'curl_loader_public_complete')
    return v

def validate_public(v):
    t=blank(v.get('mode') if type(v) is dict else None)
    require(type(v) is dict and set(v)==set(t) and v['mode'] in ('preflight','runtime'),'curl_loader_public_schema')
    for k in ('schema_version','stage','scope','profile','boundary',*core.FALSE_CLAIMS):
        require(type(v[k]) is type(t[k]) and v[k]==t[k],'curl_loader_public_fixed')
    require(v['status'] in ('ready','inconclusive','observed') and (v['failure'] is None or v['failure'] in FAILURES),'curl_loader_public_status')
    require(type(v['checks']) is dict and set(v['checks'])==set(CHECKS) and all(type(x) is bool for x in v['checks'].values()),'curl_loader_public_checks')
    require(all(v[k] is None or base.ac.digest(v[k]) for k in ('source_sha256','recovery_plan_sha256','outer_launch_report_sha256')),'curl_loader_public_digests')
    require(all(type(v[k]) is bool for k in ('observation_complete','tree_retained','recovery_required')),'curl_loader_public_flags')
    require(type(v['ordinary_controls']) is dict and set(v['ordinary_controls'])=={'before','after'} and all(type(x) is bool for x in v['ordinary_controls'].values()),'curl_loader_public_controls')
    if v['artifacts'] is not None:core.validate_artifact_pins(v['artifacts'])
    for check,key in (('sources','source_sha256'),('artifacts','artifacts'),('plan','recovery_plan_sha256')):
        require(not v['checks'][check] or v[key] is not None,'curl_loader_public_commitment')
    require(not (v['checks']['guard'] or v['checks']['worker_bound']) or base.ac.digest(v['outer_launch_report_sha256']),'curl_loader_public_outer_commitment')
    if v['observation'] is None:
        require(not v['checks']['worker_bound'] and not v['checks']['mechanism'],'curl_loader_public_absent_observation')
    else:
        o=validate_observation(v['observation'])
        require(v['checks']['worker_bound'] and v['checks']['mechanism']==o['observation_complete'],'curl_loader_public_bound_observation')
        require((not o['ordinary_before_positive'] or v['ordinary_controls']['before']) and (not o['ordinary_after_positive'] or v['ordinary_controls']['after']),'curl_loader_public_control_binding')
    if v['mode']=='runtime' and v['tree_retained']:
        clean=all(v['checks'][k] for k in ('guard','worker_exit','outer_cleanup','worker_bound')) and v['observation'] is not None and all(v['observation'][k] for k in core.CLEAN_KEYS)
        require(clean or v['recovery_required'],'curl_loader_public_unknown_cleanup')
    if v['mode']=='preflight':
        require(not any(v['checks'][k] for k in CHECKS[4:]) and v['observation'] is None and not any(v['ordinary_controls'].values())
            and not v['tree_retained'] and not v['recovery_required'] and not v['observation_complete'],'curl_loader_readonly_preflight')
    if v['status']=='ready':require(v['mode']=='preflight' and all(v['checks'][k] for k in CHECKS[:4]) and v['failure'] is None,'curl_loader_public_ready')
    require(v['observation_complete']==(v['status']=='observed'),'curl_loader_public_complete_flag')
    if v['status']=='observed':
        require(v['mode']=='runtime' and v['failure'] is None and all(v['checks'].values()) and not v['recovery_required']
            and v['observation']['observation_complete'],'curl_loader_public_observed')
    return v

def inputs(wrapper,marker,manifest,curl_path,artifacts,*,root):
    core.validate_artifact_pins(artifacts)
    paths=dict(wrapper=wrapper,marker=marker,manifest=manifest,curl=curl_path)
    for k,path in paths.items():
        path=launcher.checked_path(path);raw=local.bounded(path,8*1024*1024)
        require(len(raw)==artifacts[k]['bytes'] and sha(raw)==artifacts[k]['sha256'],'curl_loader_input_pin')
    core.verify_input_artifacts(wrapper,marker,manifest,curl_path,artifacts,root=root)
    return paths

def plan_file(plan_path,*,source,artifacts,curl_path,device=None):
    raw=local.bounded(launcher.checked_path(plan_path),16384);p=decode(raw)
    declared=p.get('device_sha256') if type(p) is dict else None
    require(base.ac.digest(declared),'curl_loader_plan_device')
    core.validate_plan(p,device=declared if device is None else device,source=source,artifacts=artifacts,curl_path=str(curl_path))
    return raw,p

def preflight(wrapper,marker,manifest,curl_path,artifacts,parent_path,plan_path,*,api=None,root=ROOT):
    r=blank('preflight');phase='inputs'
    try:
        require(core.api_version()==1,'curl_loader_api_version')
        _,_,source=snapshot(root);r['source_sha256']=source;r['checks']['sources']=True
        inputs(wrapper,marker,manifest,curl_path,artifacts,root=root);r['artifacts']=artifacts;r['checks']['artifacts']=True
        launcher.checked_path(parent_path,inside=root/'private',is_file=False)
        phase='plan';raw,p=plan_file(plan_path,source=source,artifacts=artifacts,curl_path=curl_path)
        phase='disabled';require(api is not None or core.ACTUAL_READY,'curl_loader_preflight_disabled')
        api=api if api is not None else local.LocalNativeAPI()
        require(api.windows_x64(),'curl_loader_platform');phase='identity';local.ordinary(api);r['checks']['ordinary']=True
        core.verify_system_curl(api,curl_path)
        require(api.device_sha256()==p['device_sha256'],'curl_loader_device')
        r['recovery_plan_sha256']=sha(raw);r['checks']['plan']=True;r['failure']=None;r['status']='ready'
    except BaseException:r['failure']=phase
    return validate_public(r)

def harvest_controls(result,c,parent,*,root):
    # Each control is independently source/PI/stdio-bound by the pure core reader.
    # Failure of one control cannot erase a previously verified different one.
    try:
        controls=core.ordinary_controls(root,c,parent)
        require(type(controls) is dict and set(controls)=={'before','after'} and all(type(x) is bool for x in controls.values()),'curl_loader_control_shape')
        for k in controls:result['ordinary_controls'][k] |= controls[k]
    except (ValueError,KeyError,TypeError,OSError):pass
    return result

def bind_report(report,c,parent,launch,result,*,root):
    raw=encode(launch)
    require(sha(raw)==result['outer_launch_report_sha256'] and local.bounded(launcher.checked_path(Path(root)/'outer-launch-report.json',inside=root),MAX_REPORT)==raw,'curl_loader_outer_physical')
    require(launch.get('started') is True and launch.get('resumed') is True and launch.get('native_identity_verified_before_resume') is True
        and launch.get('cleanup',{}).get('process_exit_confirmed') is True and type(launch.get('child_pid')) is int and launch['child_pid']>0
        and launch.get('child_identity')==launcher.safe_identity(parent,parent),'curl_loader_worker_held')
    require(type(report) is dict and set(report)=={'schema_version','stage','config','worker_pid','worker_identity','result'} and type(report['schema_version']) is int and report['schema_version']==1
        and report['stage']=='curl-loader-worker' and report['config']==c and report['worker_identity']==parent
        and type(report['worker_pid']) is int and report['worker_pid']==launch['child_pid'],'curl_loader_worker_binding')
    core.validate_result(report['result'],c,parent=parent,root=root)
    observation=validate_observation(core.project(report['result'],c,parent=parent,root=root))
    harvest_controls(result,c,parent,root=root)
    require(not observation['ordinary_before_positive'] or result['ordinary_controls']['before'],'curl_loader_before_physical')
    require(not observation['ordinary_after_positive'] or result['ordinary_controls']['after'],'curl_loader_after_physical')
    result['observation']=observation;result['checks']['worker_bound']=True;result['checks']['mechanism']=observation['observation_complete']
    result['failure']=observation['failure']
    result['recovery_required']=not(all(result['checks'][k] for k in ('guard','worker_exit','outer_cleanup','worker_bound')) and all(observation[k] for k in core.CLEAN_KEYS))
    return result

def worker(config_path,*,api=None,root=ROOT):
    root=launcher.checked_path(root,is_file=False)
    require(launcher.checked_path(config_path,inside=root)==root/'worker-config.json','curl_loader_worker_path')
    c=core.config_validate(decode(local.bounded(config_path,MAX_REPORT)),source_names=SOURCES)
    require(root.name==core.stage_name(c['run']),'curl_loader_worker_stage')
    _,hashes,source=snapshot(root)
    require(hashes==c['source_hashes'] and source==c['source_sha256'] and core.ACTUAL_READY,'curl_loader_worker_source_ready')
    raw,p=plan_file(root/'recovery-plan.json',source=source,artifacts=c['artifacts'],curl_path=c['curl_path'],device=c['device_sha256'])
    require(sha(raw)==c['recovery_plan_sha256'] and all(p[k]==c[k] for k in core.NONCES),'curl_loader_worker_plan')
    core.verify_artifacts(c,root)
    # No backend constructor, including wrapper loading, precedes the file gates.
    api=api if api is not None else core.NativeAPI()
    parent=local.ordinary(api);require(api.qpc_frequency()==c['frequency'],'curl_loader_worker_frequency')
    budget=launcher.QpcBudget(api,c['deadline_qpc'],c['frequency']);budget.require_ms(core.work_cutoff(c))
    require(local.LocalNativeAPI.device_sha256(api.native)==c['device_sha256'],'curl_loader_worker_device')
    core.verify_system_curl(api,c['curl_path']);budget.require_ms(core.work_cutoff(c))
    descriptor='D:P(A;OICI;FA;;;SY)(A;OICI;FA;;;'+parent['sid']+')'
    local.LocalNativeAPI.verify_private_directory(api.native,root,descriptor);local.verify_guard_job(api.native,c['guard_job_name'])
    private=core.execute(root,c,parent,api,budget)
    report=dict(schema_version=1,stage='curl-loader-worker',config=c,worker_pid=os.getpid(),worker_identity=parent,result=private)
    base.durable_private(root/'worker-result-forensic.json',encode(report))
    core.validate_result(private,c,parent=parent,root=root);budget.require_ms(budget.cutoff(1))
    base.durable_private(root/'worker-report.json',encode(report));return 0

def invalidate_complete(result):
    result['observation_complete']=False;result['checks']['mechanism']=False
    if result['observation'] is not None:
        result['observation']['observation_complete']=False
        result['observation']['version_behavior_observed']=False

def run_local(wrapper,marker,manifest,curl_path,artifacts,parent_path,plan_path,*,approved=False,api=None,root=ROOT):
    r=blank('runtime');phase='disabled';stage=None;launched=False;c=parent=None
    try:
        require(approved and core.ACTUAL_READY,'curl_loader_explicit_ready_optin')
        require(api is not None or os.name=='nt','curl_loader_platform')
        api=api if api is not None else local.LocalNativeAPI();require(api.windows_x64(),'curl_loader_platform')
        f=api.qpc_frequency();start=api.qpc();end=start+120*f;budget=launcher.QpcBudget(api,end,f)
        check=preflight(wrapper,marker,manifest,curl_path,artifacts,parent_path,plan_path,api=api,root=root)
        for k in ('source_sha256','artifacts','recovery_plan_sha256'):r[k]=check[k]
        r['checks'].update(check['checks']);require(check['status']=='ready','curl_loader_preflight')
        phase='inputs';parent=local.ordinary(api);files,hashes,source=snapshot(root)
        require(source==r['source_sha256'],'curl_loader_sources_changed')
        inputs(wrapper,marker,manifest,curl_path,artifacts,root=root)
        phase='plan';planraw,p=plan_file(plan_path,source=source,artifacts=artifacts,curl_path=curl_path,device=api.device_sha256())
        require(sha(planraw)==r['recovery_plan_sha256'],'curl_loader_plan_changed')
        c=dict(schema_version=1,scope=SCOPE,profile=core.PROFILE,**{k:p[k] for k in core.NONCES},frequency=f,start_qpc=start,
            root_deadline_qpc=end,deadline_qpc=end-5*f,guard_job_name='Local\\RuleProxy.LocalGuard.'+p['run'],source_hashes=hashes,
            source_sha256=source,device_sha256=p['device_sha256'],recovery_plan_sha256=sha(planraw),artifacts=artifacts,curl_path=str(curl_path))
        core.config_validate(c,source_names=SOURCES)
        phase='staging';budget.require_ms(budget.cutoff(45))
        parent_path=launcher.checked_path(parent_path,inside=root/'private',is_file=False);stage=parent_path/core.stage_name(c['run'])
        require(not stage.exists() and not stage.is_symlink(),'curl_loader_fresh_stage')
        r['tree_retained']=True;api.private_directory(stage,parent['sid'])
        for name,raw in files.items():
            path=stage/name;path.parent.mkdir(parents=True,exist_ok=True);launcher.write_private_bytes(path,raw)
            require(sha(local.bounded(path,256*1024))==hashes[name],'curl_loader_staged_source')
        for name in DIRS:(stage/name).mkdir()
        for name in TEMPS:(stage/name/'temp').mkdir(parents=True)
        for key,src in (('wrapper',wrapper),('marker',marker),('manifest',manifest)):
            raw=local.bounded(src,8*1024*1024);require(len(raw)==artifacts[key]['bytes'] and sha(raw)==artifacts[key]['sha256'],'curl_loader_artifact_changed')
            launcher.write_private_bytes(core.artifact_paths(stage)[key],raw)
        core.verify_artifacts(c,stage)
        base.durable_private(stage/'worker-config.json',encode(c));base.durable_private(stage/'recovery-plan.json',planraw)
        api.worker_job_name=c['guard_job_name'];api.worker_sid=parent['sid']
        python=launcher.checked_path(sys.executable,inside=launcher.checked_path(sys.base_prefix,is_file=False))
        require(python.name.casefold()=='python.exe','curl_loader_python')
        command=[str(python),'-I','-S','-B',str(stage/MODULE),'--worker',str(stage/'worker-config.json')]
        phase='worker';launched=True
        launch=launcher.launch_owned(api,command,stage/'guard',parent,parent,qpc_budget=budget,work_cutoff=budget.cutoff(3),cleanup_cutoff=end)
        raw=encode(launch);base.durable_private(stage/'outer-launch-report.json',raw);r['outer_launch_report_sha256']=sha(raw)
        r['checks']['guard']=api.atomic_job_requested is True and launch.get('native_identity_verified_before_resume') is True
        r['checks']['worker_exit']=launch.get('cleanup',{}).get('process_exit_confirmed') is True
        r['checks']['outer_cleanup']=local.guest.cleanup_verified(launch)
        harvest_controls(r,c,parent,root=stage)
        phase='report';require(r['checks']['worker_exit'] and launch.get('started') is True,'curl_loader_unknown_worker')
        report=decode(local.bounded(stage/'worker-report.json',MAX_REPORT));bind_report(report,c,parent,launch,r,root=stage)
        require(launch.get('resumed') is True and launch.get('timed_out') is not True and type(launch.get('exit_code')) is int
            and launch['exit_code']==0 and 'error' not in launch,'curl_loader_worker_launch')
        phase='deadline';budget.require_ms(end)
        r['observation_complete']=all(r['checks'].values()) and r['failure'] is None and not r['recovery_required']
        if r['observation_complete']:r['status']='observed'
    except BaseException:
        r['failure']=phase;r['status']='inconclusive';invalidate_complete(r)
        if stage is not None and c is not None and parent is not None:harvest_controls(r,c,parent,root=stage)
        clean=all(r['checks'][k] for k in ('guard','worker_exit','outer_cleanup','worker_bound')) and r['observation'] is not None and all(r['observation'][k] for k in core.CLEAN_KEYS)
        if launched and not clean or stage is not None and not launched:r['recovery_required']=True
    return validate_public(r)

def main(argv=None):
    p=argparse.ArgumentParser(description=__doc__);p.add_argument('--worker',type=Path,help=argparse.SUPPRESS)
    p.add_argument('--run-local-lpac-curl-loader',action='store_true')
    for name in ('wrapper','marker','manifest','curl','artifact-pins','work-parent','recovery-plan','output'):p.add_argument('--'+name,type=Path)
    a=p.parse_args(argv)
    if a.worker:
        require(not a.run_local_lpac_curl_loader and not any(getattr(a,k) for k in ('wrapper','marker','manifest','curl','artifact_pins','work_parent','recovery_plan','output')),'curl_loader_exact_worker_args')
        return worker(a.worker)
    args=(a.wrapper,a.marker,a.manifest,a.curl,a.artifact_pins,a.work_parent,a.recovery_plan)
    r=blank('runtime' if a.run_local_lpac_curl_loader else 'preflight')
    if not all(args):r['failure']='inputs'
    else:
        try:artifacts=decode(local.bounded(a.artifact_pins,16384))
        except BaseException:r['failure']='inputs'
        else:
            fn=run_local if a.run_local_lpac_curl_loader else preflight
            kwargs=dict(approved=True) if a.run_local_lpac_curl_loader else {}
            r=fn(a.wrapper,a.marker,a.manifest,a.curl,artifacts,a.work_parent,a.recovery_plan,**kwargs)
    raw=encode(validate_public(r))
    if a.output:launcher.write_private_bytes(a.output,raw)
    print(raw.decode('ascii'),end='');return 0 if r['status'] in ('ready','observed') else 1
if __name__=='__main__':raise SystemExit(main())
