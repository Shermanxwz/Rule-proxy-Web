"""Opt-in local matched AC/LPAC identity semantics, with both actors suspended.

Default is read-only. Runtime requires a fresh source/device/artifact-bound
plan and an explicit flag. Only the ordinary worker and fixed cleanup tools
may resume. No DNS query, socket fixture, actor GO, PSEC or proxy experiment is
implemented. AccessCheck observations qualify only this matched identity cell.
"""
from __future__ import annotations
import argparse
import importlib.util
import os
from pathlib import Path
import secrets
import sys

ROOT=Path(__file__).resolve().parents[1]
def load(name,file):
    spec=importlib.util.spec_from_file_location(name,Path(__file__).with_name(file))
    module=importlib.util.module_from_spec(spec);spec.loader.exec_module(module);return module
core=load('matched_identity_cell','windows_identity_lpac_identity_cell.py')
base=core.owner
local,launcher,live,ac=base.local,base.launcher,base.live,base.ac
require,sha,encode,decode=base.require,base.sha,base.encode,base.decode
MODULE='.github/windows_identity_lpac_identity_local.py'
SOURCES=tuple(dict.fromkeys((*core.SOURCES,MODULE)))
SCOPE=core.SCOPE
NONCES=core.NONCES
MAX_REPORT=512*1024
CHECKS=('ordinary','sources','artifact','plan','guard','worker_exit','outer_cleanup','worker_bound','inner_complete')
OBSERVATION_BOOLS=('ac_held_verified','lpac_held_verified','common_inputs_verified','ac_accesscheck_verified','lpac_accesscheck_verified',
    'observer_resources_cleanup_verified','never_resumed','workload_cleanup','workload_job_empty','acl_removed','cleanup_tools',
    'profile_deleted','sid_released','inner_complete')
OBSERVATION_KEYS={'failure','ac_granted_access','lpac_granted_access',*OBSERVATION_BOOLS}
FAILURES=('inputs','identity','plan','staging','worker','report','deadline','setup','construct','admission','accesscheck','cleanup')

def snapshot(root=ROOT):
    files={name:local.bounded(launcher.checked_path(root/name,inside=root),256*1024) for name in SOURCES}
    hashes={name:sha(raw) for name,raw in files.items()}
    return files,hashes,sha(encode(hashes))

def validate_observation(value):
    require(type(value) is dict and set(value)==OBSERVATION_KEYS,'public_observation_schema')
    require(value['failure'] is None or value['failure'] in ('setup','construct','admission','accesscheck','cleanup'),'public_observation_failure')
    require(all(type(value[key]) is bool for key in OBSERVATION_BOOLS),'public_observation_boolean')
    for key in ('ac_granted_access','lpac_granted_access'):
        masks=value[key]
        require(masks is None or type(masks) is list and len(masks)==4 and all(live.integer(mask) for mask in masks),'public_observation_masks')
    for role,expected in (('ac',[3,0,1,2]),('lpac',[2,0,0,2])):
        require(not value[role+'_accesscheck_verified'] or value[role+'_held_verified'] and value[role+'_granted_access']==expected,'public_accesscheck_gate')
    require(not value['inner_complete'] or value['failure'] is None and all(value[key] for key in OBSERVATION_BOOLS),'public_inner_complete')
    return value

def blank(mode):
    return dict(schema_version=1,stage='local-matched-ac-lpac-identity',scope=SCOPE,mode=mode,status='inconclusive',failure=None,
        source_sha256=None,actor_sha256=None,manifest_sha256=None,recovery_plan_sha256=None,
        checks=dict.fromkeys(CHECKS,False),identity_observation=None,observation_complete=False,tree_retained=False,recovery_required=False,
        comparison='matched-identity-only-not-g-psec-or-dns-causal-comparison',actor_resume_authorized=False,
        dns_api_called=False,dns_fixture_bound=False,network_tested=False,g_psec_tested=False,proxy_tested=False,
        product_acceptance=False,dns_isolation_qualified=False,broker_pid_attributed=False,broker_cancellation_proven=False)

def validate_public(value):
    template=blank(value.get('mode') if type(value) is dict else None)
    require(type(value) is dict and set(value)==set(template) and value['mode'] in ('preflight','runtime'),'public_schema')
    for key in ('schema_version','stage','scope','comparison','actor_resume_authorized','dns_api_called','dns_fixture_bound','network_tested',
            'g_psec_tested','proxy_tested','product_acceptance','dns_isolation_qualified','broker_pid_attributed','broker_cancellation_proven'):
        require(type(value[key]) is type(template[key]) and value[key]==template[key],'public_scope')
    require(value['status'] in ('ready','observed','inconclusive') and (value['failure'] is None or value['failure'] in FAILURES),'public_state')
    require(type(value['checks']) is dict and set(value['checks'])==set(CHECKS) and all(type(x) is bool for x in value['checks'].values()),'public_checks')
    for key in ('source_sha256','actor_sha256','manifest_sha256','recovery_plan_sha256'):
        require(value[key] is None or ac.digest(value[key]),'public_digest')
    for key in ('observation_complete','tree_retained','recovery_required'):require(type(value[key]) is bool,'public_boolean')
    for check,key in (('sources','source_sha256'),('artifact','actor_sha256'),('artifact','manifest_sha256'),('plan','recovery_plan_sha256')):
        require(not value['checks'][check] or ac.digest(value[key]),'public_commitment')
    observation=value['identity_observation']
    if observation is not None:validate_observation(observation)
    require(value['checks']['inner_complete']==bool(observation is not None and observation['inner_complete']),'public_inner_binding')
    require(not value['observation_complete'] or value['mode']=='runtime' and value['failure'] is None and all(value['checks'].values())
        and value['tree_retained'] and not value['recovery_required'] and observation is not None and observation['inner_complete'],'public_complete')
    require((value['status']=='observed')==value['observation_complete'],'public_observed')
    if value['mode']=='preflight':
        require(observation is None and not any(value[key] for key in ('observation_complete','tree_retained','recovery_required'))
            and not any(value['checks'][key] for key in CHECKS if key not in ('ordinary','sources','artifact','plan')),'preflight_no_runtime')
        require(value['status']!='ready' or value['failure'] is None and all(value['checks'][key] for key in ('ordinary','sources','artifact','plan')),'preflight_ready')
    else:require(value['status']!='ready','runtime_not_preflight')
    require(len(encode(value))<=8192,'public_bound');return value

def preflight(actor,manifest,actor_hash,manifest_hash,parent_path,plan_path,*,api=None,root=ROOT):
    result=blank('preflight');phase='inputs'
    try:
        require(os.name=='nt' and core.api_version()==1,'platform_or_interface')
        api=api or local.LocalNativeAPI();require(api.windows_x64(),'platform')
        phase='identity';local.ordinary(api);result['checks']['ordinary']=True
        phase='inputs';_,_,source=snapshot(root);result['source_sha256']=source;result['checks']['sources']=True
        live.verify_actor(actor,manifest,actor_hash,manifest_hash,root=root)
        result.update(actor_sha256=actor_hash,manifest_sha256=manifest_hash);result['checks']['artifact']=True
        launcher.checked_path(parent_path,inside=root/'private',is_file=False)
        phase='plan';raw=local.bounded(plan_path,8192)
        core.validate_plan(decode(raw),device=api.device_sha256(),source=source,actor=actor_hash,manifest=manifest_hash)
        result['recovery_plan_sha256']=sha(raw);result['checks']['plan']=True;result['status']='ready'
    except BaseException:result['failure']=phase
    return validate_public(result)

def bind_report(report,config,parent,launch,result):
    require(launch.get('started') is True and launch.get('resumed') is True
        and launch.get('native_identity_verified_before_resume') is True
        and launch.get('cleanup',{}).get('process_exit_confirmed') is True
        and type(launch.get('child_pid')) is int and launch['child_pid']>0,'worker_not_held')
    require(type(report) is dict and set(report)=={'schema_version','stage','config','worker_pid','worker_identity','result'}
        and type(report['schema_version']) is int and report['schema_version']==1 and report['stage']=='matched-ac-lpac-identity-worker'
        and report['config']==config and type(report['worker_pid']) is int and report['worker_pid']==launch['child_pid']
        and report['worker_identity']==parent,'worker_binding')
    core.validate_result(report['result'],config,parent=parent)
    observation=core.project(report['result'],config,parent=parent);validate_observation(observation)
    result['checks']['worker_bound']=True;result['identity_observation']=observation
    result['checks']['inner_complete']=observation['inner_complete'];result['failure']=observation['failure']
    result['recovery_required']=not (all(result['checks'][key] for key in ('guard','worker_exit','outer_cleanup','worker_bound'))
        and all(observation[key] for key in ('observer_resources_cleanup_verified','workload_cleanup','workload_job_empty',
            'acl_removed','cleanup_tools','profile_deleted','sid_released')))
    return result

def worker(config_path):
    require(launcher.checked_path(config_path,inside=ROOT)==ROOT/'worker-config.json','worker_path')
    config=core.config_validate(decode(local.bounded(config_path,MAX_REPORT)),source_names=SOURCES)
    require(ROOT.name=='local-lpac-identity-'+config['run'],'worker_stage')
    files,hashes,source=snapshot();require(hashes==config['source_hashes'] and source==config['source_sha256'],'worker_sources')
    require(core.api_version()==1,'worker_interface');api=core.IdentityAPI();parent=local.ordinary(api)
    require(api.qpc_frequency()==config['frequency'],'worker_frequency')
    budget=launcher.QpcBudget(api,config['deadline_qpc'],config['frequency']);budget.require_ms(budget.cutoff(45))
    require(local.LocalNativeAPI.device_sha256(api.native)==config['device_sha256'],'worker_device')
    raw=local.bounded(ROOT/'recovery-plan.json',8192);require(sha(raw)==config['recovery_plan_sha256'],'worker_plan')
    core.validate_plan(decode(raw),device=config['device_sha256'],source=source,actor=config['actor_sha256'],manifest=config['manifest_sha256'])
    local.LocalNativeAPI.verify_private_directory(api.native,ROOT,'D:P(A;OICI;FA;;;SY)(A;OICI;FA;;;'+parent['sid']+')')
    local.verify_guard_job(api.native,config['guard_job_name'])
    live.verify_actor(ROOT/'inputs'/live.ACTOR,ROOT/'inputs'/live.MANIFEST,config['actor_sha256'],config['manifest_sha256'],root=ROOT)
    private=core.execute(ROOT,config,parent,api,budget)
    core.validate_result(private,config,parent=parent)
    report=dict(schema_version=1,stage='matched-ac-lpac-identity-worker',config=config,worker_pid=os.getpid(),worker_identity=parent,result=private)
    budget.require_ms(budget.cutoff(1));base.durable_private(ROOT/'worker-report.json',encode(report));return 0

def run_local(actor,manifest,actor_hash,manifest_hash,parent_path,plan_path,*,approved=False,root=ROOT):
    result=blank('runtime');phase='inputs';launched=False;stage=None
    try:
        require(approved and os.name=='nt','explicit_opt_in');api=local.LocalNativeAPI();require(api.windows_x64(),'platform')
        frequency=api.qpc_frequency();start=api.qpc();deadline=start+120*frequency
        budget=launcher.QpcBudget(api,deadline,frequency)
        check=preflight(actor,manifest,actor_hash,manifest_hash,parent_path,plan_path,api=api,root=root)
        for key in ('source_sha256','actor_sha256','manifest_sha256','recovery_plan_sha256'):result[key]=check[key]
        result['checks'].update(check['checks']);require(check['status']=='ready','preflight')
        parent=local.ordinary(api);files,hashes,source=snapshot(root);require(source==result['source_sha256'],'source_changed')
        config=dict(schema_version=1,scope=SCOPE,**{name:secrets.token_hex(16) for name in NONCES},start_qpc=start,frequency=frequency,
            root_deadline_qpc=deadline,deadline_qpc=deadline-5*frequency,source_hashes=hashes,source_sha256=source,
            device_sha256=api.device_sha256(),actor_sha256=actor_hash,manifest_sha256=manifest_hash,recovery_plan_sha256=result['recovery_plan_sha256'],
            capability_catalog=base.fixed_catalog())
        config['guard_job_name']='Local\\RuleProxy.LocalGuard.'+config['run'];core.config_validate(config,source_names=SOURCES)
        phase='staging';budget.require_ms(budget.cutoff(45));parent_path=launcher.checked_path(parent_path,inside=root/'private',is_file=False)
        stage=parent_path/('local-lpac-identity-'+config['run']);require(not stage.exists() and not stage.is_symlink(),'fresh_stage')
        # The directory may exist even when descriptor/readback/free fails.
        # Preserve possible residue before entering the native mkdir boundary.
        result['tree_retained']=True;api.private_directory(stage,parent['sid'])
        for name,raw in files.items():
            path=stage/name;path.parent.mkdir(parents=True,exist_ok=True);launcher.write_private_bytes(path,raw)
            require(sha(local.bounded(path,256*1024))==hashes[name],'staged_source')
        for name in ('inputs','tools','guard'):(stage/name).mkdir()
        (stage/'guard'/'temp').mkdir()
        for source_path in (Path(actor),Path(manifest)):
            launcher.write_private_bytes(stage/'inputs'/source_path.name,local.bounded(source_path,8*1024*1024))
        live.verify_actor(stage/'inputs'/live.ACTOR,stage/'inputs'/live.MANIFEST,actor_hash,manifest_hash,root=stage)
        base.durable_private(stage/'worker-config.json',encode(config))
        raw=local.bounded(plan_path,8192);require(sha(raw)==config['recovery_plan_sha256'],'plan_changed');base.durable_private(stage/'recovery-plan.json',raw)
        api.worker_job_name=config['guard_job_name'];api.worker_sid=parent['sid']
        python=launcher.checked_path(sys.executable,inside=launcher.checked_path(sys.base_prefix,is_file=False))
        require(python.name.casefold()=='python.exe','python')
        command=[str(python),'-I','-S','-B',str(stage/MODULE),'--worker',str(stage/'worker-config.json')]
        phase='worker';launched=True
        launch=launcher.launch_owned(api,command,stage/'guard',parent,parent,qpc_budget=budget,work_cutoff=budget.cutoff(3),cleanup_cutoff=deadline)
        result['checks']['guard']=api.atomic_job_requested and launch.get('native_identity_verified_before_resume') is True
        result['checks']['worker_exit']=launch.get('cleanup',{}).get('process_exit_confirmed') is True
        result['checks']['outer_cleanup']=local.guest.cleanup_verified(launch)
        phase='report';require(result['checks']['worker_exit'] and launch.get('started') is True,'unknown_worker')
        report=decode(local.bounded(stage/'worker-report.json',MAX_REPORT));bind_report(report,config,parent,launch,result)
        require(launch.get('resumed') is True and launch.get('timed_out') is not True and launch.get('exit_code')==0 and 'error' not in launch,'worker_launch')
        phase='deadline';budget.require_ms(deadline)
        result['observation_complete']=all(result['checks'].values()) and result['failure'] is None and not result['recovery_required']
        if result['observation_complete']:result['status']='observed'
    except BaseException:
        result['failure']=phase;result['observation_complete']=False;result['status']='inconclusive'
        observation=result['identity_observation']
        clean=(all(result['checks'][key] for key in ('guard','worker_exit','outer_cleanup','worker_bound')) and observation is not None
            and all(observation[key] for key in ('observer_resources_cleanup_verified','workload_cleanup','workload_job_empty','acl_removed','cleanup_tools','profile_deleted','sid_released')))
        if launched and not clean or stage is not None and not launched:result['recovery_required']=True
    return validate_public(result)

def main(argv=None):
    parser=argparse.ArgumentParser(description=__doc__);parser.add_argument('--worker',help=argparse.SUPPRESS)
    parser.add_argument('--run-local-lpac-identity',action='store_true');parser.add_argument('--actor',type=Path);parser.add_argument('--manifest',type=Path)
    parser.add_argument('--actor-sha256');parser.add_argument('--manifest-sha256');parser.add_argument('--work-parent',type=Path,default=ROOT/'private')
    parser.add_argument('--recovery-plan',type=Path);parser.add_argument('--output',type=Path);args=parser.parse_args(argv)
    if args.worker:
        require(not args.run_local_lpac_identity and not any((args.actor,args.manifest,args.actor_sha256,args.manifest_sha256,args.recovery_plan,args.output))
            and args.work_parent==ROOT/'private','worker_arguments')
        return worker(Path(args.worker))
    if any(value is None for value in (args.actor,args.manifest,args.actor_sha256,args.manifest_sha256,args.recovery_plan)):
        result=blank('runtime' if args.run_local_lpac_identity else 'preflight');result['failure']='inputs'
    else:
        function=run_local if args.run_local_lpac_identity else preflight
        result=function(args.actor,args.manifest,args.actor_sha256,args.manifest_sha256,args.work_parent,args.recovery_plan,**({'approved':True} if args.run_local_lpac_identity else {}))
    raw=encode(validate_public(result))
    if args.output:base.durable_private(args.output,raw)
    sys.stdout.buffer.write(raw);sys.stdout.buffer.flush();return 0 if result['status'] in ('ready','observed') else 1
if __name__=='__main__':raise SystemExit(main())
