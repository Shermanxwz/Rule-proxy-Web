"""Opt-in CPSE deny-all matched identity mechanism; both arms never resume.

Default preflight reads files and ordinary host identity only. It never loads
the candidate DLL or processmodel. Runtime requires a predeclared fresh nonce,
original spec bytes and source/device/artifact-bound plan. Unknown opaque API
outcomes remain recovery obligations after the guard Job stops its worker.
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
core=load('cpse_guard_core','windows_identity_psec_lpac_bridge.py')
base,local,launcher,live=core.base,core.local,core.launcher,core.live
require,sha,encode,decode=core.require,core.sha,core.encode,core.decode
SOURCES=core.SOURCES
SCOPE=core.SCOPE
MODULE=core.LOCAL_MODULE
CHECKS=('ordinary','sources','artifact','dll','processmodel','spec','plan','guard','worker_exit','outer_cleanup','worker_bound','inner_complete')
OBS_BOOLS=('common_inputs_verified','observer_resources_cleanup_verified','workload_cleanup','workload_job_empty',
    'opaque_outcome_unknown','api_obligations_closed','module_unbound','ac_held_verified','lpac_held_verified',
    'ac_accesscheck_verified','lpac_accesscheck_verified','inner_complete')
FAILURES=('inputs','identity','plan','staging','worker','report','deadline','setup','bind','environment','construct','admission','accesscheck','cleanup')

def snapshot(root=ROOT):
    files={name:local.bounded(launcher.checked_path(root/name,inside=root),512*1024) for name in SOURCES}
    hashes={name:sha(raw) for name,raw in files.items()};return files,hashes,sha(encode(hashes))

def blank(mode):
    return dict(schema_version=1,stage='local-cpse-matched-ac-lpac-identity',scope=SCOPE,variant=core.VARIANT,mode=mode,
        status='inconclusive',failure=None,source_sha256=None,actor_sha256=None,manifest_sha256=None,dll_sha256=None,
        dll_manifest_sha256=None,processmodel_sha256=None,spec_sha256=None,recovery_plan_sha256=None,outer_launch_sha256=None,
        checks=dict.fromkeys(CHECKS,False),identity_observation=None,observation_complete=False,tree_retained=False,
        recovery_required=False,broker_outcome_unknown=False,actor_resume_authorized=False,token_class46_queried=False,
        external_environment_absence_verified=False,broker_cancellation_proven=False,network_tested=False,dns_tested=False,
        proxy_tested=False,product_acceptance=False,model2_policy_compared=False,
        comparison='same-cpse-deny-all-never-resumed-identity-only')

def validate_observation(v):
    require(type(v) is dict and set(v)=={'failure','ac_granted_access','lpac_granted_access',*OBS_BOOLS},'guard_observation_schema')
    require(v['failure'] in (None,'setup','bind','environment','construct','admission','accesscheck','cleanup')
        and all(type(v[k]) is bool for k in OBS_BOOLS),'guard_observation_values')
    for role,expected in (('ac',[3,0,1,2]),('lpac',[2,0,0,2])):
        masks=v[role+'_granted_access']
        require(masks is None or type(masks) is list and len(masks)==4 and all(live.integer(x) for x in masks),'guard_observation_masks')
        require(not v[role+'_accesscheck_verified'] or v[role+'_held_verified'] and masks==expected,'guard_observation_matrix')
    require(not v['inner_complete'] or v['failure'] is None and not v['opaque_outcome_unknown']
        and all(v[k] for k in OBS_BOOLS if k!='opaque_outcome_unknown'),'guard_observation_complete')
    return v

def validate_public(v):
    template=blank(v.get('mode') if type(v) is dict else None)
    require(type(v) is dict and set(v)==set(template) and v['mode'] in ('preflight','runtime'),'guard_public_schema')
    variable={'mode','status','failure','checks','identity_observation','observation_complete','tree_retained','recovery_required','broker_outcome_unknown'}
    for key in template:
        if key in variable or key.endswith('_sha256'):continue
        require(type(v[key]) is type(template[key]) and v[key]==template[key],'guard_public_scope')
    require(v['status'] in ('ready','observed','inconclusive') and v['failure'] in (None,*FAILURES),'guard_public_state')
    require(type(v['checks']) is dict and set(v['checks'])==set(CHECKS) and all(type(x) is bool for x in v['checks'].values()),'guard_public_checks')
    for key in template:
        if key.endswith('_sha256'):require(v[key] is None or base.ac.digest(v[key]),'guard_public_digest')
    for key in ('observation_complete','tree_retained','recovery_required','broker_outcome_unknown'):require(type(v[key]) is bool,'guard_public_boolean')
    for check,key in (('sources','source'),('artifact','actor'),('artifact','manifest'),('dll','dll'),('dll','dll_manifest'),
            ('processmodel','processmodel'),('spec','spec'),('plan','recovery_plan')):
        require(not v['checks'][check] or base.ac.digest(v[key+'_sha256']),'guard_public_commitment')
    require(not v['checks']['worker_bound'] or base.ac.digest(v['outer_launch_sha256']),'guard_public_launch_commitment')
    obs=v['identity_observation']
    if obs is not None:validate_observation(obs)
    require(v['checks']['inner_complete']==bool(obs and obs['inner_complete']),'guard_public_inner')
    require(not obs or not obs['opaque_outcome_unknown'] or v['broker_outcome_unknown'],'guard_public_unknown_sticky')
    require(not v['broker_outcome_unknown'] or v['recovery_required'],'guard_public_unknown_recovery')
    require(not v['observation_complete'] or v['mode']=='runtime' and v['failure'] is None and all(v['checks'].values())
        and v['tree_retained'] and not v['recovery_required'] and not v['broker_outcome_unknown'] and obs and obs['inner_complete'],'guard_public_complete')
    require((v['status']=='observed')==v['observation_complete'],'guard_public_observed')
    if v['mode']=='preflight':
        require(obs is None and v['outer_launch_sha256'] is None and not any(v[k] for k in ('tree_retained','recovery_required','broker_outcome_unknown','observation_complete'))
            and not any(v['checks'][k] for k in ('guard','worker_exit','outer_cleanup','worker_bound','inner_complete')),'guard_preflight_no_runtime')
        require(v['status']!='ready' or v['failure'] is None and all(v['checks'][k] for k in CHECKS[:7]),'guard_preflight_ready')
    else:require(v['status']!='ready','guard_runtime_state')
    require(len(encode(v))<=8192,'guard_public_bound');return v

def preflight(actor,manifest,ah,mh,dll,dll_manifest,dh,dmh,modelh,spec_path,plan_path,parent_path,*,api=None,root=ROOT):
    v=blank('preflight');phase='inputs'
    try:
        require(os.name=='nt' and core.api_version()==1,'guard_platform_interface');api=api or local.LocalNativeAPI()
        require(api.windows_x64(),'guard_x64');phase='identity';local.ordinary(api);v['checks']['ordinary']=True
        phase='inputs';_,_,source=snapshot(root);v['source_sha256']=source;v['checks']['sources']=True
        live.verify_actor(actor,manifest,ah,mh,root=root);v.update(actor_sha256=ah,manifest_sha256=mh);v['checks']['artifact']=True
        core.verify_manifest(dll,dll_manifest,dh,dmh,root=root);v.update(dll_sha256=dh,dll_manifest_sha256=dmh);v['checks']['dll']=True
        model=core.NativeAPI.processmodel_path(api);require(sha(local.bounded(model,8*1024*1024))==modelh,'guard_processmodel')
        core.pe_x64(local.bounded(model,8*1024*1024),dll=True);v['processmodel_sha256']=modelh;v['checks']['processmodel']=True
        parent_path=launcher.checked_path(parent_path,inside=root/'private',is_file=False)
        phase='plan';raw=local.bounded(plan_path,8192);p=decode(raw)
        require(type(p) is dict and base.ac.nonce(p.get('run')),'guard_plan_nonce')
        stage=parent_path/core.stage_name(p['run']);require(not stage.exists() and not stage.is_symlink(),'guard_fresh_stage')
        spec_raw=local.bounded(launcher.checked_path(spec_path,inside=root),core.spec.MAX_BYTES)
        core.spec.verify(spec_raw,str(stage/'inputs'));require(sha(spec_raw)==p.get('spec_sha256'),'guard_spec_commitment')
        v['spec_sha256']=sha(spec_raw);v['checks']['spec']=True
        core.validate_plan(p,device=api.device_sha256(),source=source,actor=ah,manifest=mh,dll=dh,dll_manifest=dmh,
            processmodel=modelh,inputs=stage/'inputs')
        v['recovery_plan_sha256']=sha(raw);v['checks']['plan']=True;v['status']='ready'
    except BaseException:v['failure']=phase
    return validate_public(v)

def bind_report(report,c,parent,launch,v):
    require(launch.get('started') is True and launch.get('resumed') is True and launch.get('native_identity_verified_before_resume') is True
        and launch.get('cleanup',{}).get('process_exit_confirmed') is True and type(launch.get('child_pid')) is int and launch['child_pid']>0,'guard_worker_not_held')
    require(type(report) is dict and set(report)=={'schema_version','stage','config','worker_pid','worker_identity','result'}
        and type(report['schema_version']) is int and report['schema_version']==1 and report['stage']=='cpse-matched-identity-worker'
        and report['config']==c and type(report['worker_pid']) is int and report['worker_pid']==launch['child_pid']
        and report['worker_identity']==parent,'guard_worker_binding')
    obs=core.project(report['result'],c,parent=parent);validate_observation(obs)
    v['checks']['worker_bound']=True;v['identity_observation']=obs;v['checks']['inner_complete']=obs['inner_complete'];v['failure']=obs['failure']
    v['broker_outcome_unknown']=obs['opaque_outcome_unknown']
    v['recovery_required']=not (all(v['checks'][k] for k in ('guard','worker_exit','outer_cleanup','worker_bound'))
        and all(obs[k] for k in ('observer_resources_cleanup_verified','workload_cleanup','workload_job_empty','api_obligations_closed','module_unbound'))
        and not obs['opaque_outcome_unknown'])
    return v

def worker(config_path):
    require(launcher.checked_path(config_path,inside=ROOT)==ROOT/'worker-config.json','guard_worker_path')
    c=core.config_validate(decode(local.bounded(config_path,core.MAX_REPORT)))
    require(ROOT.name==core.stage_name(c['run']),'guard_worker_stage');_,hashes,source=snapshot()
    require(hashes==c['source_hashes'] and source==c['source_sha256'] and core.ACTUAL_READY,'guard_worker_sources')
    api=core.NativeAPI();parent=local.ordinary(api);require(api.qpc_frequency()==c['frequency'],'guard_worker_frequency')
    budget=launcher.QpcBudget(api,c['deadline_qpc'],c['frequency']);budget.require_ms(core.work_cutoff(c))
    require(local.LocalNativeAPI.device_sha256(api.native)==c['device_sha256'],'guard_worker_device')
    local.LocalNativeAPI.verify_private_directory(api.native,ROOT,'D:P(A;OICI;FA;;;SY)(A;OICI;FA;;;'+parent['sid']+')')
    local.verify_guard_job(api.native,c['guard_job_name'])
    raw=local.bounded(ROOT/'recovery-plan.json',8192);require(sha(raw)==c['recovery_plan_sha256'],'guard_worker_plan')
    plan=decode(raw);require(all(plan.get(k)==c[k] for k in core.NONCES),'guard_worker_plan_nonces')
    core.validate_plan(plan,device=c['device_sha256'],source=source,actor=c['actor_sha256'],manifest=c['manifest_sha256'],
        dll=c['dll_sha256'],dll_manifest=c['dll_manifest_sha256'],processmodel=c['processmodel_sha256'],inputs=ROOT/'inputs')
    live.verify_actor(ROOT/'inputs'/live.ACTOR,ROOT/'inputs'/live.MANIFEST,c['actor_sha256'],c['manifest_sha256'],root=ROOT)
    core.verify_manifest(ROOT/'inputs'/core.DLL,ROOT/'inputs'/core.DLL_MANIFEST,c['dll_sha256'],c['dll_manifest_sha256'],root=ROOT)
    spec_raw=local.bounded(ROOT/'spec.bin',core.spec.MAX_BYTES);core.spec.verify(spec_raw,str(ROOT/'inputs'))
    require(sha(spec_raw)==c['spec_sha256'] and base.fixed_catalog()==c['capability_catalog'],'guard_worker_spec_catalog')
    result=core.execute(ROOT,c,parent,api,budget);core.validate_result(result,c,parent=parent)
    report=dict(schema_version=1,stage='cpse-matched-identity-worker',config=c,worker_pid=os.getpid(),worker_identity=parent,result=result)
    budget.require_ms(budget.cutoff(1));base.durable_private(ROOT/'worker-report.json',encode(report));return 0

def run_local(actor,manifest,ah,mh,dll,dll_manifest,dh,dmh,modelh,spec_path,plan_path,parent_path,*,approved=False,root=ROOT):
    v=blank('runtime');phase='inputs';launched=False;stage=None
    try:
        require(approved and os.name=='nt' and core.ACTUAL_READY,'guard_opt_in');api=local.LocalNativeAPI();require(api.windows_x64(),'guard_platform')
        f=api.qpc_frequency();start=api.qpc();deadline=start+120*f;budget=launcher.QpcBudget(api,deadline,f)
        args=(actor,manifest,ah,mh,dll,dll_manifest,dh,dmh,modelh,spec_path,plan_path,parent_path)
        check=preflight(*args,api=api,root=root)
        for key in v:
            if key.endswith('_sha256'):v[key]=check[key]
        v['checks'].update(check['checks']);require(check['status']=='ready','guard_preflight')
        parent=local.ordinary(api);files,hashes,source=snapshot(root);require(source==v['source_sha256'],'guard_source_changed')
        plan_raw=local.bounded(plan_path,8192);require(sha(plan_raw)==v['recovery_plan_sha256'],'guard_plan_changed');p=decode(plan_raw)
        c=dict(schema_version=1,scope=SCOPE,variant=core.VARIANT,**{k:p[k] for k in core.NONCES},frequency=f,start_qpc=start,
            root_deadline_qpc=deadline,deadline_qpc=deadline-5*f,guard_job_name='Local\\RuleProxy.LocalGuard.'+p['run'],
            source_hashes=hashes,source_sha256=source,device_sha256=api.device_sha256(),capability_catalog=base.fixed_catalog(),
            **{key:v[key] for key in ('actor_sha256','manifest_sha256','dll_sha256','dll_manifest_sha256','processmodel_sha256','spec_sha256','recovery_plan_sha256')})
        core.config_validate(c);phase='staging';budget.require_ms(core.work_cutoff(c))
        parent_path=launcher.checked_path(parent_path,inside=root/'private',is_file=False);stage=parent_path/core.stage_name(c['run'])
        require(not stage.exists() and not stage.is_symlink(),'guard_fresh_stage');v['tree_retained']=True;api.private_directory(stage,parent['sid'])
        native_manifest=decode(local.bounded(dll_manifest,256*1024))
        extra={**native_manifest['sources'],**native_manifest['dependencies']}
        for name in extra:
            path=launcher.checked_path(root/name,inside=root);raw=local.bounded(path,512*1024)
            require(sha(raw)==extra[name],'guard_native_changed')
            if name in files:require(files[name]==raw,'guard_source_alias')
            files[name]=raw
        for name,raw in files.items():
            target=stage/name;target.parent.mkdir(parents=True,exist_ok=True);base.durable_private(target,raw)
        for name in ('inputs','guard'):(stage/name).mkdir()
        (stage/'guard'/'temp').mkdir()
        for path in (Path(actor),Path(manifest),Path(dll),Path(dll_manifest)):
            base.durable_private(stage/'inputs'/path.name,local.bounded(path,8*1024*1024))
        raw=local.bounded(spec_path,core.spec.MAX_BYTES);core.spec.verify(raw,str(stage/'inputs'));require(sha(raw)==c['spec_sha256'],'guard_spec_changed')
        base.durable_private(stage/'spec.bin',raw);base.durable_private(stage/'recovery-plan.json',plan_raw)
        base.durable_private(stage/'worker-config.json',encode(c))
        live.verify_actor(stage/'inputs'/live.ACTOR,stage/'inputs'/live.MANIFEST,ah,mh,root=stage)
        core.verify_manifest(stage/'inputs'/core.DLL,stage/'inputs'/core.DLL_MANIFEST,dh,dmh,root=stage)
        api.worker_job_name=c['guard_job_name'];api.worker_sid=parent['sid']
        python=launcher.checked_path(sys.executable,inside=launcher.checked_path(sys.base_prefix,is_file=False));require(python.name.casefold()=='python.exe','guard_python')
        command=[str(python),'-I','-S','-B',str(stage/MODULE),'--worker',str(stage/'worker-config.json')]
        phase='worker';launched=True;v['broker_outcome_unknown']=True;v['recovery_required']=True
        launch=launcher.launch_owned(api,command,stage/'guard',parent,parent,qpc_budget=budget,work_cutoff=budget.cutoff(3),cleanup_cutoff=deadline)
        v['checks']['guard']=api.atomic_job_requested and launch.get('native_identity_verified_before_resume') is True
        v['checks']['worker_exit']=launch.get('cleanup',{}).get('process_exit_confirmed') is True;v['checks']['outer_cleanup']=local.guest.cleanup_verified(launch)
        budget.require_ms(deadline);launch_raw=encode(launch)
        base.durable_private(stage/'outer-launch-report.json',launch_raw);v['outer_launch_sha256']=sha(launch_raw)
        phase='report';require(v['checks']['worker_exit'] and launch.get('started') is True,'guard_unknown_worker')
        report=decode(local.bounded(stage/'worker-report.json',core.MAX_REPORT));bind_report(report,c,parent,launch,v)
        require(launch.get('resumed') is True and launch.get('timed_out') is not True and launch.get('exit_code')==0 and 'error' not in launch,'guard_worker_launch')
        phase='deadline';budget.require_ms(deadline)
        v['observation_complete']=all(v['checks'].values()) and v['failure'] is None and not v['recovery_required'] and not v['broker_outcome_unknown']
        if v['observation_complete']:v['status']='observed'
    except BaseException:
        v['failure']=phase;v['status']='inconclusive';v['observation_complete']=False
        if stage is not None and not launched:v['recovery_required']=True
    return validate_public(v)

def main(argv=None):
    parser=argparse.ArgumentParser(description=__doc__);parser.add_argument('--worker',help=argparse.SUPPRESS)
    parser.add_argument('--run-local-cpse-lpac-identity',action='store_true')
    for name in ('actor','manifest','dll','dll-manifest','spec','recovery-plan','output'):parser.add_argument('--'+name,type=Path)
    for name in ('actor-sha256','manifest-sha256','dll-sha256','dll-manifest-sha256','processmodel-sha256'):parser.add_argument('--'+name)
    parser.add_argument('--work-parent',type=Path,default=ROOT/'private');a=parser.parse_args(argv)
    if a.worker:
        require(not a.run_local_cpse_lpac_identity and a.work_parent==ROOT/'private'
            and all(value is None for key,value in vars(a).items() if key not in ('worker','run_local_cpse_lpac_identity','work_parent')),'guard_worker_arguments')
        return worker(Path(a.worker))
    values=(a.actor,a.manifest,a.actor_sha256,a.manifest_sha256,a.dll,a.dll_manifest,a.dll_sha256,a.dll_manifest_sha256,
        a.processmodel_sha256,a.spec,a.recovery_plan,a.work_parent)
    if any(value is None for value in values):v=blank('runtime' if a.run_local_cpse_lpac_identity else 'preflight');v['failure']='inputs'
    else:v=(run_local if a.run_local_cpse_lpac_identity else preflight)(*values,**({'approved':True} if a.run_local_cpse_lpac_identity else {}))
    raw=encode(validate_public(v))
    if a.output:base.durable_private(a.output,raw)
    sys.stdout.buffer.write(raw);sys.stdout.buffer.flush();return 0 if v['status'] in ('ready','observed') else 1
if __name__=='__main__':raise SystemExit(main())
