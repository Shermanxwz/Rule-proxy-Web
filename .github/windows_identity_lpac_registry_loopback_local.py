"""Explicit local registryRead LPAC same-SID trusted-actor loopback mechanism.

Default performs read-only preflight. Selected gets only registryRead, which can
grant reads to other existing registry objects carrying its ACE. Frontend and
ordinary controls have zero capabilities. No Internet/PNCS, fallback, class46,
loopback exemption, WFP, proxy, resolver, routes or global policy changes.
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
core=load('registry_cap_same_sid_loopback','windows_identity_lpac_registry_loopback.py')
base,local,launcher,live=core.base,core.local,core.launcher,core.live
require,sha,encode,decode=core.require,core.sha,core.encode,core.decode
MODULE=core.LOCAL_MODULE
SOURCES=core.SOURCES
SCOPE=core.SCOPE
MAX_REPORT=core.MAX_REPORT+64*1024
CHECKS=('ordinary','sources','artifact','plan','guard','worker_exit','outer_cleanup','worker_bound','reachability')
FAILURES=('inputs','identity','plan','staging','worker','report','deadline',*(v for v in core.FAILURE_STAGES if v is not None))
SETUP_KEYS={'observed','failure','wsa_error','win32_error','wsa_started','listening_verified','listen_close','wsa_cleanup','socket_resources_closed'}
OBS_KEYS={'failure','ac_granted_access','lpac_granted_access','network_tested','frontend_setup',*core.OBS_BOOL_KEYS,*core.FALSE_CLAIMS}

def snapshot(root=ROOT):
    files={n:local.bounded(launcher.checked_path(root/n,inside=root),256*1024) for n in SOURCES}
    hashes={n:sha(v) for n,v in files.items()};return files,hashes,sha(encode(hashes))

def validate_observation(v):
    require(type(v) is dict and set(v)==OBS_KEYS and v['failure'] in core.FAILURE_STAGES,'zero_public_observation')
    for k in (*core.OBS_BOOL_KEYS,'network_tested',*core.FALSE_CLAIMS):require(type(v[k]) is bool,'zero_public_boolean')
    for k in core.FALSE_CLAIMS:require(v[k] is False,'zero_public_scope')
    for role,expected in (('ac',[3,0,1,2]),('lpac',[2,0,0,2])):
        masks=v[role+'_granted_access'];require(masks is None or type(masks) is list and len(masks)==4 and all(live.integer(x) for x in masks),'zero_public_masks')
        require(not v[role+'_accesscheck_verified'] or masks==expected,'zero_public_matrix')
    setup=v['frontend_setup'];require(type(setup) is dict and set(setup)==SETUP_KEYS,'zero_public_setup')
    for k in ('observed','wsa_started','listening_verified','socket_resources_closed'):require(type(setup[k]) is bool,'zero_public_setup_boolean')
    require(setup['failure'] in core.NATIVE_FAILURES and setup['listen_close'] in ('not-created','confirmed','uncertain')
        and setup['wsa_cleanup'] in ('not-started','confirmed','uncertain'),'zero_public_setup_state')
    for k in ('wsa_error','win32_error'):require(setup[k] is None or live.integer(setup[k]),'zero_public_setup_error')
    require(setup['observed'] or setup==empty_setup(),'zero_public_setup_unobserved')
    require(not v['reachability_verified'] or v['failure'] is None and all(v[k] for k in core.OBS_BOOL_KEYS),'zero_public_reachability')
    require(not v['reachability_verified'] or setup['observed'] and setup['failure'] is None and setup['wsa_error'] is None
        and setup['win32_error'] is None and setup['wsa_started'] and setup['listening_verified'] and setup['listen_close']=='confirmed'
        and setup['wsa_cleanup']=='confirmed' and setup['socket_resources_closed'],'zero_public_frontend_resources')
    return v

def empty_setup():return dict(observed=False,failure=None,wsa_error=None,win32_error=None,wsa_started=False,listening_verified=False,
    listen_close='not-created',wsa_cleanup='not-started',socket_resources_closed=False)

def observation(j,c,parent,*,root):
    v=core.project(j,c,parent=parent,root=root);v['frontend_setup']=empty_setup()
    finals=[r['value'] for r in j['native'] if r['role']=='front-listener' and r['kind']=='final']
    if finals:
        r=finals[0];v['frontend_setup']=dict(observed=True,**{k:r[k] for k in SETUP_KEYS-{'observed'}})
    return validate_observation(v)

def blank(mode):
    return dict(schema_version=1,stage='local-registry-read-same-sid-loopback',scope=SCOPE,profile=core.PROFILE,mode=mode,status='inconclusive',failure=None,
        source_sha256=None,actor_sha256=None,manifest_sha256=None,recovery_plan_sha256=None,outer_launch_report_sha256=None,checks=dict.fromkeys(CHECKS,False),
        loopback_observation=None,observation_complete=False,tree_retained=False,recovery_required=False,
        selected_capability='registryRead',capability_effect='existing-registryRead-ACE-objects-not-only-Winsock-catalog',
        boundary='fixed-trusted-actors-shared-principal-registry-read-selected-reachability-only',**dict.fromkeys(core.FALSE_CLAIMS,False))

def validate_public(v):
    t=blank(v.get('mode') if type(v) is dict else None)
    require(type(v) is dict and set(v)==set(t) and v['mode'] in ('preflight','runtime'),'zero_public_schema')
    for k in ('schema_version','stage','scope','profile','selected_capability','capability_effect','boundary',*core.FALSE_CLAIMS):
        require(type(v[k]) is type(t[k]) and v[k]==t[k],'zero_public_fixed')
    require(v['status'] in ('ready','observed','inconclusive') and (v['failure'] is None or v['failure'] in FAILURES),'zero_public_status')
    require(type(v['checks']) is dict and set(v['checks'])==set(CHECKS) and all(type(x) is bool for x in v['checks'].values()),'zero_public_checks')
    for k in ('source_sha256','actor_sha256','manifest_sha256','recovery_plan_sha256','outer_launch_report_sha256'):require(v[k] is None or base.ac.digest(v[k]),'zero_public_digest')
    require(not (v['checks']['guard'] or v['checks']['worker_bound']) or base.ac.digest(v['outer_launch_report_sha256']),'zero_public_outer_commitment')
    for check,key in (('sources','source_sha256'),('artifact','actor_sha256'),('artifact','manifest_sha256'),('plan','recovery_plan_sha256')):
        require(not v['checks'][check] or base.ac.digest(v[key]),'zero_public_commitment')
    for k in ('observation_complete','tree_retained','recovery_required'):require(type(v[k]) is bool,'zero_public_resource_bool')
    o=v['loopback_observation']
    if o is not None:validate_observation(o)
    require(v['checks']['reachability']==bool(o and o['reachability_verified']),'zero_public_projection')
    require(v['observation_complete']==(v['mode']=='runtime' and v['failure'] is None and all(v['checks'].values())
        and v['tree_retained'] and not v['recovery_required'] and o is not None and o['reachability_verified']),'zero_public_completed')
    require((v['status']=='observed')==v['observation_complete'],'zero_public_observed')
    if v['mode']=='preflight':
        require(o is None and v['outer_launch_report_sha256'] is None and not any(v[k] for k in ('tree_retained','recovery_required','observation_complete'))
            and not any(v['checks'][k] for k in CHECKS if k not in ('ordinary','sources','artifact','plan')),'zero_preflight_no_runtime')
        require(v['status']!='ready' or v['failure'] is None and all(v['checks'][k] for k in ('ordinary','sources','artifact','plan')),'zero_preflight_ready')
    else:require(v['status']!='ready','zero_runtime_no_ready')
    require(len(encode(v))<=12288,'zero_public_bound');return v

def preflight(actor,manifest,actor_hash,manifest_hash,parent_path,plan_path,*,api=None,root=ROOT):
    r=blank('preflight');phase='inputs'
    try:
        require(os.name=='nt' and core.api_version()==1,'zero_platform');api=api or local.LocalNativeAPI();require(api.windows_x64(),'zero_platform')
        phase='identity';local.ordinary(api);r['checks']['ordinary']=True
        phase='inputs';_,_,source=snapshot(root);r['source_sha256']=source;r['checks']['sources']=True
        core.verify_actor(actor,manifest,actor_hash,manifest_hash,root=root)
        r.update(actor_sha256=actor_hash,manifest_sha256=manifest_hash);r['checks']['artifact']=True
        launcher.checked_path(parent_path,inside=root/'private',is_file=False)
        phase='plan';raw=local.bounded(plan_path,8192);core.validate_plan(decode(raw),device=api.device_sha256(),source=source,actor=actor_hash,manifest=manifest_hash)
        r['recovery_plan_sha256']=sha(raw);r['checks']['plan']=True;r['status']='ready'
    except BaseException:r['failure']=phase
    return validate_public(r)

def bind_report(report,c,parent,launch,result,*,root):
    raw=encode(launch);require(sha(raw)==result['outer_launch_report_sha256']
        and local.bounded(launcher.checked_path(Path(root)/'outer-launch-report.json',inside=root),MAX_REPORT)==raw,'zero_outer_launch_physical')
    require(launch.get('started') is True and launch.get('resumed') is True and launch.get('native_identity_verified_before_resume') is True
        and launch.get('cleanup',{}).get('process_exit_confirmed') is True and type(launch.get('child_pid')) is int and launch['child_pid']>0,'zero_worker_held')
    require(type(report) is dict and set(report)=={'schema_version','stage','config','worker_pid','worker_identity','result'}
        and type(report['schema_version']) is int and report['schema_version']==1 and report['stage']=='registry-read-same-sid-loopback-worker'
        and report['config']==c and type(report['worker_pid']) is int and report['worker_pid']==launch['child_pid'] and report['worker_identity']==parent,'zero_worker_binding')
    o=observation(report['result'],c,parent,root=root)
    result['checks']['worker_bound']=True;result['loopback_observation']=o;result['checks']['reachability']=o['reachability_verified'];result['failure']=o['failure']
    result['recovery_required']=not (all(result['checks'][k] for k in ('guard','worker_exit','outer_cleanup','worker_bound')) and all(o[k] for k in core.CLEAN_KEYS))
    return result

def worker(config_path):
    require(launcher.checked_path(config_path,inside=ROOT)==ROOT/'worker-config.json','zero_worker_path')
    c=core.config_validate(decode(local.bounded(config_path,MAX_REPORT)),source_names=SOURCES);require(ROOT.name==core.stage_name(c['run']),'zero_worker_stage')
    _,hashes,source=snapshot();require(hashes==c['source_hashes'] and source==c['source_sha256'] and core.ACTUAL_READY,'zero_worker_sources')
    api=core.API();parent=local.ordinary(api);require(api.qpc_frequency()==c['frequency'],'zero_worker_frequency')
    budget=launcher.QpcBudget(api,c['deadline_qpc'],c['frequency']);budget.require_ms(core.work_cutoff(c))
    require(local.LocalNativeAPI.device_sha256(api.native)==c['device_sha256'],'zero_worker_device')
    raw=local.bounded(ROOT/'recovery-plan.json',8192);require(sha(raw)==c['recovery_plan_sha256'],'zero_worker_plan')
    p=core.validate_plan(decode(raw),device=c['device_sha256'],source=source,actor=c['actor_sha256'],manifest=c['manifest_sha256'])
    require(all(p[k]==c[k] for k in (*core.NONCES,'ports')),'zero_worker_plan_nonces')
    local.LocalNativeAPI.verify_private_directory(api.native,ROOT,'D:P(A;OICI;FA;;;SY)(A;OICI;FA;;;'+parent['sid']+')')
    local.verify_guard_job(api.native,c['guard_job_name'])
    core.verify_actor(ROOT/'inputs'/core.ACTOR,ROOT/'inputs'/core.MANIFEST,c['actor_sha256'],c['manifest_sha256'],root=ROOT)
    private=core.execute(ROOT,c,parent,api,budget)
    report=dict(schema_version=1,stage='registry-read-same-sid-loopback-worker',config=c,worker_pid=os.getpid(),worker_identity=parent,result=private)
    # Preserve the physical observations before strict result validation. This
    # forensic file is never a qualification fallback or a reconstructed ledger.
    base.durable_private(ROOT/'worker-result-forensic.json',encode(report))
    core.validate_result(private,c,parent=parent,root=ROOT);budget.require_ms(budget.cutoff(1))
    base.durable_private(ROOT/'worker-report.json',encode(report));return 0

def run_local(actor,manifest,actor_hash,manifest_hash,parent_path,plan_path,*,approved=False,root=ROOT):
    r=blank('runtime');phase='inputs';launched=False;stage=None
    try:
        require(approved and core.ACTUAL_READY and os.name=='nt','zero_explicit_reviewed_opt_in')
        api=local.LocalNativeAPI();require(api.windows_x64(),'zero_platform');f=api.qpc_frequency();start=api.qpc();end=start+120*f
        budget=launcher.QpcBudget(api,end,f)
        check=preflight(actor,manifest,actor_hash,manifest_hash,parent_path,plan_path,api=api,root=root)
        for k in ('source_sha256','actor_sha256','manifest_sha256','recovery_plan_sha256'):r[k]=check[k]
        r['checks'].update(check['checks']);require(check['status']=='ready','zero_preflight')
        parent=local.ordinary(api);files,hashes,source=snapshot(root);require(source==r['source_sha256'],'zero_source_changed')
        planraw=local.bounded(plan_path,8192);require(sha(planraw)==r['recovery_plan_sha256'],'zero_plan_changed')
        p=core.validate_plan(decode(planraw),device=api.device_sha256(),source=source,actor=actor_hash,manifest=manifest_hash)
        c=dict(schema_version=1,scope=SCOPE,profile=core.PROFILE,**{k:p[k] for k in (*core.NONCES,'ports')},frequency=f,start_qpc=start,
            root_deadline_qpc=end,deadline_qpc=end-5*f,source_hashes=hashes,source_sha256=source,device_sha256=api.device_sha256(),
            actor_sha256=actor_hash,manifest_sha256=manifest_hash,recovery_plan_sha256=r['recovery_plan_sha256'])
        c['guard_job_name']='Local\\RuleProxy.LocalGuard.'+c['run'];core.config_validate(c)
        phase='staging';budget.require_ms(budget.cutoff(45));parent_path=launcher.checked_path(parent_path,inside=root/'private',is_file=False)
        stage=parent_path/core.stage_name(c['run']);require(not stage.exists() and not stage.is_symlink(),'zero_fresh_stage')
        r['tree_retained']=True;api.private_directory(stage,parent['sid'])
        for name,raw in files.items():
            path=stage/name;path.parent.mkdir(parents=True,exist_ok=True);launcher.write_private_bytes(path,raw)
            require(sha(local.bounded(path,256*1024))==hashes[name],'zero_staged_source')
        for name in ('inputs','tools','guard',*(p for pair in core.ACTOR_DIRS.values() for p in pair)):(stage/name).mkdir()
        for name in ('guard','origin-report','ordinary-report'):(stage/name/'temp').mkdir()
        for src in (Path(actor),Path(manifest)):launcher.write_private_bytes(stage/'inputs'/src.name,local.bounded(src,8*1024*1024))
        core.verify_actor(stage/'inputs'/core.ACTOR,stage/'inputs'/core.MANIFEST,actor_hash,manifest_hash,root=stage)
        base.durable_private(stage/'worker-config.json',encode(c));base.durable_private(stage/'recovery-plan.json',planraw)
        api.worker_job_name=c['guard_job_name'];api.worker_sid=parent['sid']
        python=launcher.checked_path(sys.executable,inside=launcher.checked_path(sys.base_prefix,is_file=False));require(python.name.casefold()=='python.exe','zero_python')
        command=[str(python),'-I','-S','-B',str(stage/MODULE),'--worker',str(stage/'worker-config.json')]
        phase='worker';launched=True
        launch=launcher.launch_owned(api,command,stage/'guard',parent,parent,qpc_budget=budget,work_cutoff=budget.cutoff(3),cleanup_cutoff=end)
        base.durable_private(stage/'outer-launch-report.json',encode(launch))
        r['outer_launch_report_sha256']=sha(encode(launch))
        r['checks']['guard']=api.atomic_job_requested and launch.get('native_identity_verified_before_resume') is True
        r['checks']['worker_exit']=launch.get('cleanup',{}).get('process_exit_confirmed') is True;r['checks']['outer_cleanup']=local.guest.cleanup_verified(launch)
        phase='report';require(r['checks']['worker_exit'] and launch.get('started') is True,'zero_unknown_worker')
        report=decode(local.bounded(stage/'worker-report.json',MAX_REPORT));bind_report(report,c,parent,launch,r,root=stage)
        require(launch.get('resumed') is True and launch.get('timed_out') is not True and launch.get('exit_code')==0 and 'error' not in launch,'zero_worker_launch')
        phase='deadline';budget.require_ms(end)
        r['observation_complete']=all(r['checks'].values()) and r['failure'] is None and not r['recovery_required']
        if r['observation_complete']:r['status']='observed'
    except BaseException:
        r['failure']=phase;r['observation_complete']=False;r['status']='inconclusive';o=r['loopback_observation']
        clean=(all(r['checks'][k] for k in ('guard','worker_exit','outer_cleanup','worker_bound')) and o is not None and all(o[k] for k in core.CLEAN_KEYS))
        if launched and not clean or stage is not None and not launched:r['recovery_required']=True
    return validate_public(r)

def main(argv=None):
    p=argparse.ArgumentParser(description=__doc__);p.add_argument('--worker',help=argparse.SUPPRESS)
    p.add_argument('--run-local-registry-read-same-sid-loopback',action='store_true');p.add_argument('--actor',type=Path);p.add_argument('--manifest',type=Path)
    p.add_argument('--actor-sha256');p.add_argument('--manifest-sha256');p.add_argument('--work-parent',type=Path,default=ROOT/'private')
    p.add_argument('--recovery-plan',type=Path);p.add_argument('--output',type=Path);a=p.parse_args(argv)
    if a.worker:
        require(not a.run_local_registry_read_same_sid_loopback and not any((a.actor,a.manifest,a.actor_sha256,a.manifest_sha256,a.recovery_plan,a.output))
            and a.work_parent==ROOT/'private','zero_worker_arguments');return worker(Path(a.worker))
    if any(v is None for v in (a.actor,a.manifest,a.actor_sha256,a.manifest_sha256,a.recovery_plan)):
        r=blank('runtime' if a.run_local_registry_read_same_sid_loopback else 'preflight');r['failure']='inputs'
    else:
        function=run_local if a.run_local_registry_read_same_sid_loopback else preflight
        r=function(a.actor,a.manifest,a.actor_sha256,a.manifest_sha256,a.work_parent,a.recovery_plan,**({'approved':True} if a.run_local_registry_read_same_sid_loopback else {}))
    raw=encode(validate_public(r))
    if a.output:base.durable_private(a.output,raw)
    sys.stdout.buffer.write(raw);sys.stdout.buffer.flush();return 0 if r['status'] in ('ready','observed') else 1
if __name__=='__main__':raise SystemExit(main())
