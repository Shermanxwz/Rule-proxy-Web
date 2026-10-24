"""Explicit local DNS mechanism with held AccessCheck LPAC identity.

Default is read-only. The independent scope requires a fresh source/device/
artifact-bound standard53 impact plan. No TokenInformationClass46 result is
invented. Native07, the original class46 entry, G/PSEC and proxy qualifications
retain their original meaning. Only the separate guarded worker may set up
the owned profile/ACL, once inventory, loopback fixture and fixed DNS phases.
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
core=load('semantic_dns_guard_core','windows_identity_lpac_semantic_dns.py')
base=load('semantic_dns_guard_owner06','windows_identity_lpac_dns_local.py')
local,launcher,live=base.local,base.launcher,base.live
require,sha,encode,decode=base.require,base.sha,base.encode,base.decode
MODULE='.github/windows_identity_lpac_semantic_dns_local.py'
SOURCES=tuple(dict.fromkeys((*core.SOURCES,MODULE)))
SCOPE=core.SCOPE
IDENTITY_BASIS=core.IDENTITY_BASIS
NONCES=core.NONCES
MAX_REPORT=512*1024
RESOURCE_CHECKS=('guard','worker_exit','outer_cleanup','worker_bound','fixture_cleanup','workload_cleanup',
    'acl_removed','cleanup_tools','profile_deleted','sid_released','semantic_resources_cleanup')

def snapshot(root=ROOT):
    files={name:local.bounded(launcher.checked_path(root/name,inside=root),256*1024) for name in SOURCES}
    hashes={name:sha(raw) for name,raw in files.items()}
    return files,hashes,sha(encode(hashes))

def preflight(actor,manifest,actor_hash,manifest_hash,parent_path,plan_path,*,api=None,root=ROOT):
    result=core.blank('preflight');phase='inputs'
    try:
        require(os.name=='nt' and core.api_version()==1,'platform_or_interface')
        api=api or local.LocalNativeAPI();require(api.windows_x64(),'platform')
        phase='identity';local.ordinary(api);result['checks']['ordinary']=True
        phase='inputs';_,_,source=snapshot(root);result['source_sha256']=source;result['checks']['sources']=True
        live.verify_actor(actor,manifest,actor_hash,manifest_hash,root=root)
        result.update(actor_sha256=actor_hash,manifest_sha256=manifest_hash);result['checks']['artifact']=True
        launcher.checked_path(parent_path,inside=root/'private',is_file=False)
        phase='plan';raw=local.bounded(plan_path,8192)
        core.plan(decode(raw),device=api.device_sha256(),source=source,actor=actor_hash,manifest=manifest_hash)
        result['recovery_plan_sha256']=sha(raw);result['checks']['plan']=True;result['status']='ready'
    except BaseException:result['failure']=phase
    return core.validate_public(result)

def bind_report(report,config,parent,launch,result):
    require(launch.get('started') is True and launch.get('resumed') is True
        and launch.get('native_identity_verified_before_resume') is True
        and launch.get('cleanup',{}).get('process_exit_confirmed') is True
        and type(launch.get('child_pid')) is int and launch['child_pid']>0,'worker_not_held')
    require(type(report) is dict and set(report)=={'schema_version','stage','config','worker_pid','worker_identity','result'}
        and type(report['schema_version']) is int and report['schema_version']==1 and report['stage']=='standalone-lpac-semantic-dns-worker'
        and report['config']==config and type(report['worker_pid']) is int and report['worker_pid']==launch['child_pid']
        and report['worker_identity']==parent,'worker_binding')
    result['checks']['worker_bound']=True
    # The core carries the independent receiver event into result BEFORE its
    # strict private/native validation. Do not pre-validate and erase a hit.
    return core.public_result(report['result'],config,result,parent=parent)

def worker(config_path):
    require(launcher.checked_path(config_path,inside=ROOT)==ROOT/'worker-config.json','worker_path')
    config=core.config_validate(decode(local.bounded(config_path,MAX_REPORT)),source_names=SOURCES)
    require(ROOT.name=='local-lpac-semantic-dns-'+config['run'],'worker_stage')
    files,hashes,source=snapshot();require(hashes==config['source_hashes'] and source==config['source_sha256'],'worker_sources')
    require(core.api_version()==1,'worker_interface');api=core.IdentityAPI();parent=local.ordinary(api)
    require(api.qpc_frequency()==config['frequency'],'worker_frequency')
    budget=launcher.QpcBudget(api,config['deadline_qpc'],config['frequency']);budget.require_ms(budget.cutoff(45))
    require(local.LocalNativeAPI.device_sha256(api.native)==config['device_sha256'],'worker_device')
    raw=local.bounded(ROOT/'recovery-plan.json',8192);require(sha(raw)==config['recovery_plan_sha256'],'worker_plan')
    core.plan(decode(raw),device=config['device_sha256'],source=source,actor=config['actor_sha256'],manifest=config['manifest_sha256'])
    local.LocalNativeAPI.verify_private_directory(api.native,ROOT,'D:P(A;OICI;FA;;;SY)(A;OICI;FA;;;'+parent['sid']+')')
    local.verify_guard_job(api.native,config['guard_job_name'])
    live.verify_actor(ROOT/'inputs'/live.ACTOR,ROOT/'inputs'/live.MANIFEST,config['actor_sha256'],config['manifest_sha256'],root=ROOT)
    private=core.execute(ROOT,config,parent,api,budget)
    # Preserve exact private observations even if the outer pure validator will
    # reject a native/semantic report; independent receiver positivity survives.
    report=dict(schema_version=1,stage='standalone-lpac-semantic-dns-worker',config=config,worker_pid=os.getpid(),worker_identity=parent,result=private)
    budget.require_ms(budget.cutoff(1));base.durable_private(ROOT/'worker-report.json',encode(report));return 0

def run_local(actor,manifest,actor_hash,manifest_hash,parent_path,plan_path,*,approved=False,root=ROOT):
    result=core.blank('runtime');phase='inputs';launched=False;stage=None
    try:
        require(approved and os.name=='nt','explicit_opt_in');api=local.LocalNativeAPI();require(api.windows_x64(),'platform')
        frequency=api.qpc_frequency();start=api.qpc();deadline=start+120*frequency
        budget=launcher.QpcBudget(api,deadline,frequency)
        check=preflight(actor,manifest,actor_hash,manifest_hash,parent_path,plan_path,api=api,root=root)
        for key in ('source_sha256','actor_sha256','manifest_sha256','recovery_plan_sha256'):result[key]=check[key]
        result['checks'].update(check['checks']);require(check['status']=='ready','preflight')
        parent=local.ordinary(api);files,hashes,source=snapshot(root);require(source==result['source_sha256'],'source_changed')
        config=dict(schema_version=1,scope=SCOPE,identity_basis=IDENTITY_BASIS,**{name:secrets.token_hex(16) for name in NONCES},
            start_qpc=start,frequency=frequency,root_deadline_qpc=deadline,deadline_qpc=deadline-5*frequency,
            source_hashes=hashes,source_sha256=source,device_sha256=api.device_sha256(),actor_sha256=actor_hash,manifest_sha256=manifest_hash,
            recovery_plan_sha256=result['recovery_plan_sha256'],capability_catalog=base.fixed_catalog())
        config['guard_job_name']='Local\\RuleProxy.LocalGuard.'+config['run'];core.config_validate(config,source_names=SOURCES)
        phase='staging';budget.require_ms(budget.cutoff(45));parent_path=launcher.checked_path(parent_path,inside=root/'private',is_file=False)
        stage=parent_path/('local-lpac-semantic-dns-'+config['run']);require(not stage.exists() and not stage.is_symlink(),'fresh_stage')
        result['tree_retained']=True;api.private_directory(stage,parent['sid'])
        for name,raw in files.items():
            path=stage/name;path.parent.mkdir(parents=True,exist_ok=True);launcher.write_private_bytes(path,raw)
            require(sha(local.bounded(path,256*1024))==hashes[name],'staged_source')
        for name in ('inputs','lpac-report','lpac-control','health','health-control','tools','guard'):(stage/name).mkdir()
        for name in ('lpac-report','health','guard'):(stage/name/'temp').mkdir()
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
        report=decode(local.bounded(stage/'worker-report.json',MAX_REPORT));result=bind_report(report,config,parent,launch,result)
        require(launch.get('resumed') is True and launch.get('timed_out') is not True and launch.get('exit_code')==0 and 'error' not in launch,'worker_launch')
        phase='deadline';budget.require_ms(deadline)
    except BaseException:
        result['failure']=phase
        # A wire hit stays positive, but no outer failure can retain a claim
        # that the original worker/root-deadline observation completed.
        result['observation_complete']=False;result['access_denial_observed']=False
        if launched and not all(result['checks'][key] for key in RESOURCE_CHECKS):result['recovery_required']=True
        if stage is not None and not launched:result['recovery_required']=True
        if result['status']=='observed':result['status']='inconclusive'
    if result['selected_wire_query_observed']:result['status']='failed'
    return core.validate_public(result)

def main(argv=None):
    parser=argparse.ArgumentParser(description=__doc__);parser.add_argument('--worker',help=argparse.SUPPRESS)
    parser.add_argument('--run-local-lpac-semantic-dns',action='store_true');parser.add_argument('--actor',type=Path);parser.add_argument('--manifest',type=Path)
    parser.add_argument('--actor-sha256');parser.add_argument('--manifest-sha256');parser.add_argument('--work-parent',type=Path,default=ROOT/'private')
    parser.add_argument('--recovery-plan',type=Path);parser.add_argument('--output',type=Path);args=parser.parse_args(argv)
    if args.worker:
        require(not args.run_local_lpac_semantic_dns and not any((args.actor,args.manifest,args.actor_sha256,args.manifest_sha256,args.recovery_plan,args.output))
            and args.work_parent==ROOT/'private','worker_arguments')
        return worker(Path(args.worker))
    if any(value is None for value in (args.actor,args.manifest,args.actor_sha256,args.manifest_sha256,args.recovery_plan)):
        result=core.blank('runtime' if args.run_local_lpac_semantic_dns else 'preflight');result['failure']='inputs'
    else:
        function=run_local if args.run_local_lpac_semantic_dns else preflight
        result=function(args.actor,args.manifest,args.actor_sha256,args.manifest_sha256,args.work_parent,args.recovery_plan,**({'approved':True} if args.run_local_lpac_semantic_dns else {}))
    raw=encode(core.validate_public(result))
    if args.output:base.durable_private(args.output,raw)
    sys.stdout.buffer.write(raw);sys.stdout.buffer.flush();return 0 if result['status'] in ('ready','observed') else 1
if __name__=='__main__':raise SystemExit(main())
