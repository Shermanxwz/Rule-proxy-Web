"""Opt-in ordinary local outer guard for the first real Model 2 client chain.

Default preflight reads source/artifact/device/plan only. Actual execution may
create only the fresh owned profile, exact ACEs and journal-bound loopback rule
through the separately supervised maintenance role. No global network settings.
"""
from __future__ import annotations
import argparse
import importlib.util
import os
from pathlib import Path
import secrets
import shutil
import sys

ROOT=Path(__file__).resolve().parents[1]
def load(name):
    spec=importlib.util.spec_from_file_location('model2_outer_'+name,Path(__file__).with_name(name+'.py'))
    module=importlib.util.module_from_spec(spec);spec.loader.exec_module(module);return module
live=load('windows_identity_model2_live')
local=live.local;launcher=live.launcher;probe=live.probe;require=live.require
SCOPE='one-local-model2-pncs-first-chain-exact-rule-v1'
DIAGNOSTIC_SCOPE='one-local-model2-pncs-profiles-off-diagnostic-v1'
HELPER_DIAGNOSTIC_SCOPE='one-local-model2-pncs-profiles-off-held-conhost-diagnostic-v1'
CONFIG_KEYS={'schema_version','stage','run','boot_case','positive_case','direct_case','health_cases','admission_nonce',
    'maintenance_nonce','capability_profile','start_qpc','frequency','deadline_qpc','root_deadline_qpc',
    'source_hashes','source_sha256','actor_sha256','manifest_sha256','guard_job_name','device_sha256','recovery_plan_sha256'}
CHECKS=('windows_x64','ordinary','sources','artifacts','capacity','recovery_attested')
CLEANUP=('guard_job_verified','controller_held_verified','controller_exit_verified','outer_cleanup_verified','tree_retained','recovery_required')
def blank(mode,execution_mode='strict'):
    return dict(schema_version=1,stage='local-model2-first-owner',mode=mode,status='inconclusive',failure=None,
        source_sha256=None,actor_sha256=None,manifest_sha256=None,recovery_plan_sha256=None,device_bound=False,
        checks={key:False for key in CHECKS},cleanup={key:False for key in CLEANUP},result=live.blank(execution_mode))
def validate(value):
    template=blank(value.get('mode') if type(value) is dict else None)
    require(type(value) is dict and set(value)==set(template),'outer_schema')
    for key in ('schema_version','stage'):require(type(value[key]) is type(template[key]) and value[key]==template[key],'outer_scope')
    require(value['mode'] in ('preflight','runtime') and value['status'] in ('ready','inconclusive','observed','failed','passed','diagnostic-observed'),'outer_state')
    require(value['failure'] in (None,'platform','identity','inputs','plan','deadline','staging','worker','report','cleanup'),'outer_failure')
    require(type(value['device_bound']) is bool,'outer_types')
    for key in ('checks','cleanup'):
        require(type(value[key]) is dict and set(value[key])==set(template[key]) and all(type(x) is bool for x in value[key].values()),'outer_types')
    for key in ('source_sha256','actor_sha256','manifest_sha256','recovery_plan_sha256'):require(value[key] is None or live.ac.digest(value[key]),'outer_digest')
    r=live.validate_public(value['result'])
    for check,key in (('sources','source_sha256'),('artifacts','actor_sha256'),('artifacts','manifest_sha256')):
        require(not r['checks'][check] or r[key]==value[key],'outer_result_binding')
    if value['mode']=='preflight':
        require(not any(value['cleanup'].values()) and not any(v for key,v in r['checks'].items() if key not in ('sources','artifacts')) and r['run_sha256'] is None
            and not any(r['observations'].values()) and not any(r['violations'].values()),'outer_preflight')
    if value['status']=='ready':
        require(value['mode']=='preflight' and all(value['checks'].values()) and value['failure'] is None and value['device_bound']
            and r['status']=='ready' and all(live.ac.digest(value[key]) for key in ('source_sha256','actor_sha256','manifest_sha256','recovery_plan_sha256')),'outer_ready')
    if value['status'] in ('observed','passed','diagnostic-observed'):
        require(value['mode']=='runtime' and all(value['checks'].values()) and value['failure'] is None and value['device_bound']
            and all(value['cleanup'][key] for key in CLEANUP if key!='recovery_required') and not value['cleanup']['recovery_required']
            and r['status']==value['status'],'outer_observation')
    require(len(live.encode(value))<=12288,'outer_bound');return value
def plan(value,*,device,source,actor,manifest,execution_mode='strict',selected_admission=None):
    require(execution_mode in live.MODES,'execution_mode')
    keys={'schema_version','scope','device_sha256','source_sha256','actor_sha256',
        'manifest_sha256','residue_review_acknowledged','recovery_reference'}
    if execution_mode=='profiles-off-diagnostic':keys.add('execution_mode')
    scope=SCOPE if execution_mode=='strict' else DIAGNOSTIC_SCOPE
    if selected_admission is not None:
        require(execution_mode=='profiles-off-diagnostic','helper_diagnostic_only')
        live.validate_selected_admission(selected_admission);keys.add('selected_admission');scope=HELPER_DIAGNOSTIC_SCOPE
    require(type(value) is dict and set(value)==keys and live.execution_mode(value)==execution_mode,'plan_schema')
    if selected_admission is not None:require(value['selected_admission']==selected_admission,'helper_plan_binding')
    require(type(value['schema_version']) is int and value['schema_version']==1
        and value['scope']==scope
        and value['residue_review_acknowledged'] is True,'plan_scope')
    for key,expected in (('device_sha256',device),('source_sha256',source),('actor_sha256',actor),('manifest_sha256',manifest)):
        require(live.ac.digest(value[key]) and value[key]==expected,'plan_binding')
    require(type(value['recovery_reference']) is str and 1<=len(value['recovery_reference'])<=512
        and all(ord(x)>=32 for x in value['recovery_reference']),'plan_recovery')
    return value
def inputs(actor,manifest,ah,mh,bundle,runtime,work_parent,root=ROOT):
    files,hashes,closure=live.source_snapshot(root)
    actor=live.verify_actor(actor,manifest,ah,mh,root=root);manifest=launcher.checked_path(manifest)
    probe.verify_artifacts(bundle,runtime)
    bundle=launcher.checked_path(bundle);runtime=launcher.checked_path(runtime,is_file=False)
    parent=probe.admit_work_parent(work_parent,root=root)
    needed=sum(map(len,files.values()))+actor.stat().st_size+bundle.stat().st_size
    needed+=sum((runtime/name).stat().st_size for name in probe.MEMBERS)+16*live.MAX_PRIVATE+1048576
    require(needed<=local.MAX_STAGE and shutil.disk_usage(parent).free>=needed,'stage_capacity')
    return files,hashes,closure,actor,manifest,bundle,runtime,parent
def preflight(actor,manifest,ah,mh,bundle,runtime,work_parent,plan_path,*,api=None,root=ROOT,execution_mode='strict',allow_held_system_conhost=False):
    value=blank('preflight',execution_mode);phase='platform'
    try:
        require(type(allow_held_system_conhost) is bool and (not allow_held_system_conhost or execution_mode=='profiles-off-diagnostic'),'helper_diagnostic_only')
        require(os.name=='nt','windows_required');api=local.LocalNativeAPI() if api is None else api
        require(api.windows_x64(),'windows_x64');value['checks']['windows_x64']=True
        phase='identity';local.ordinary(api);value['checks']['ordinary']=True
        phase='inputs';_,_,closure,_,_,_,_,_=inputs(actor,manifest,ah,mh,bundle,runtime,work_parent,root)
        value.update(source_sha256=closure,actor_sha256=ah,manifest_sha256=mh)
        value['checks'].update(sources=True,artifacts=True,capacity=True)
        phase='plan';raw=local.bounded(plan_path,8192)
        admission=live.system_conhost_record(api) if allow_held_system_conhost else None
        plan(live.decode(raw),device=api.device_sha256(),source=closure,actor=ah,manifest=mh,execution_mode=execution_mode,selected_admission=admission)
        value.update(recovery_plan_sha256=live.sha(raw),device_bound=True);value['checks']['recovery_attested']=True
        value['result'].update(source_sha256=closure,actor_sha256=ah,manifest_sha256=mh,status='ready')
        value['result']['checks'].update(sources=True,artifacts=True);value['status']='ready'
    except BaseException:value['failure']=phase
    return validate(value)
def validate_config(config):
    mode=live.execution_mode(config)
    keys=CONFIG_KEYS | ({'execution_mode'} if mode=='profiles-off-diagnostic' else set())
    if type(config) is dict and 'selected_admission' in config:
        require(mode=='profiles-off-diagnostic','helper_diagnostic_only')
        live.validate_selected_admission(config['selected_admission']);keys=keys | {'selected_admission'}
    require(type(config) is dict and set(config)==keys and type(config['schema_version']) is int and config['schema_version']==1
        and config['stage']=='model2-first-owned-input' and config['capability_profile']=='agentic-pncs','worker_config')
    live.clock_record(config['start_qpc'],config['frequency'],config['root_deadline_qpc'])
    require(config['root_deadline_qpc']==config['start_qpc']+120*config['frequency']
        and config['deadline_qpc']==config['root_deadline_qpc']-5*config['frequency'],'worker_reserve')
    require(type(config['health_cases']) is list and len(config['health_cases'])==3,'health_nonces')
    nonces=[config[key] for key in ('run','boot_case','positive_case','direct_case','admission_nonce','maintenance_nonce')]+config['health_cases']
    require(all(live.ac.nonce(x) for x in nonces) and len(set(nonces))==len(nonces),'distinct_nonces')
    require(config['guard_job_name']=='Local\\RuleProxy.LocalGuard.'+config['run'],'guard_binding')
    require(type(config['source_hashes']) is dict and set(config['source_hashes'])==set(live.SOURCES)
        and all(live.ac.digest(x) for x in config['source_hashes'].values())
        and live.sha(live.encode(config['source_hashes']))==config['source_sha256'],'worker_sources')
    require(all(live.ac.digest(config[key]) for key in ('source_sha256','actor_sha256','manifest_sha256','device_sha256','recovery_plan_sha256')),'worker_digest')
    return config
def bind_controller(report,config,launch):
    keys={'schema_version','stage','run','controller_pid','frequency','start_qpc','deadline_qpc','source_sha256',
        'actor_sha256','manifest_sha256','ownership_journal_sha256','ownership_journal_bytes','public'}
    require(type(report) is dict and set(report)==keys and type(report['schema_version']) is int and report['schema_version']==1
        and report['stage']=='model2-first-controller' and report['run']==config['run']
        and type(report['controller_pid']) is int and report['controller_pid']==launch.get('child_pid'),'controller_binding')
    for key in ('frequency','start_qpc','deadline_qpc','source_sha256','actor_sha256','manifest_sha256'):
        require(type(report[key]) is type(config[key]) and report[key]==config[key],'controller_binding')
    require(live.ac.digest(report['ownership_journal_sha256']) and live.integer(report['ownership_journal_bytes'],1,live.MAX_PRIVATE),'journal_commitment')
    r=live.validate_public(report['public'])
    require(r['execution_mode']==live.execution_mode(config),'controller_execution_mode')
    for key,check in (('source_sha256','sources'),('actor_sha256','artifacts'),('manifest_sha256','artifacts')):
        require(r[key]==config[key] if r['checks'][check] else r[key] in (None,config[key]),'controller_result')
    run_hash=live.sha(config['run'].encode('ascii'))
    require((r['run_sha256']==run_hash if r['checks']['sources'] else r['run_sha256'] in (None,run_hash))
        and r['checks']['guard_held'] is False,'controller_guard')
    require(not r['local_c_qualified'] and not r['first_chain_verified']
        and not any(r['checks'][key] for key in ('wrong_port','wrong_peer','proxy_death')),'first_cell_scope')
    return r
def worker(config_path):
    root=Path(__file__).resolve().parents[1];config_path=launcher.checked_path(config_path,inside=root)
    require(config_path==root/'model2-config.json','config_path')
    config=validate_config(live.decode(local.bounded(config_path,live.MAX_PRIVATE)))
    api=local.LocalNativeAPI();local.ordinary(api);local.verify_guard_job(api,config['guard_job_name'])
    require(api.qpc_frequency()==config['frequency'] and api.device_sha256()==config['device_sha256'],'worker_host')
    budget=launcher.QpcBudget(api,config['deadline_qpc'],config['frequency']);budget.require_ms(budget.cutoff(30))
    _,hashes,closure=live.source_snapshot(root)
    require(hashes==config['source_hashes'] and closure==config['source_sha256'],'worker_copy')
    plan_raw=local.bounded(root/'recovery-plan.json',8192);require(live.sha(plan_raw)==config['recovery_plan_sha256'],'worker_plan')
    admission=config.get('selected_admission')
    if admission is not None:require(live.system_conhost_record(api)==admission,'helper_image_changed')
    plan(live.decode(plan_raw),device=config['device_sha256'],source=closure,actor=config['actor_sha256'],manifest=config['manifest_sha256'],execution_mode=live.execution_mode(config),selected_admission=admission)
    live.verify_actor(root/'inputs'/live.ACTOR,root/'inputs'/live.MANIFEST,config['actor_sha256'],config['manifest_sha256'],root=root)
    probe.verify_artifacts(root/'bundle.zip',root/'runtime')
    controller=load('windows_identity_model2_controller')
    report=controller.run_controller(config,root=root)
    # Never return the native raw evidence on inherited stdout.
    launcher.write_private_bytes(root/'model2-controller-report.json',live.encode(report))
    ready=live.first_ready if live.execution_mode(config)=='strict' else live.diagnostic_ready
    return 0 if ready(report['public'],require_guard=False) else 1
def run_local(actor,manifest,ah,mh,bundle,runtime,work_parent,plan_path,*,approved=False,api=None,root=ROOT,ids=secrets.token_hex,execution_mode='strict',allow_held_system_conhost=False):
    value=blank('runtime',execution_mode);phase='platform';launched=False
    try:
        require(approved and os.name=='nt','explicit_opt_in_required');api=local.LocalNativeAPI() if api is None else api
        frequency,start=api.qpc_frequency(),api.qpc();budget=launcher.QpcBudget(api,start+120*frequency,frequency)
        check=preflight(actor,manifest,ah,mh,bundle,runtime,work_parent,plan_path,api=api,root=root,execution_mode=execution_mode,allow_held_system_conhost=allow_held_system_conhost)
        for key in ('checks','source_sha256','actor_sha256','manifest_sha256','recovery_plan_sha256','device_bound'):value[key]=check[key]
        if check['status']!='ready':phase=check['failure'];raise ValueError('preflight')
        phase='inputs';files,hashes,closure,actor,manifest,bundle,runtime,parentpath=inputs(actor,manifest,ah,mh,bundle,runtime,work_parent,root)
        require(closure==value['source_sha256'],'source_changed');parent=local.ordinary(api)
        names=('run','boot_case','positive_case','direct_case','admission_nonce','maintenance_nonce')
        config={name:ids(16) for name in names};config['health_cases']=[ids(16) for _ in range(3)]
        config.update(schema_version=1,stage='model2-first-owned-input',capability_profile='agentic-pncs',start_qpc=start,frequency=frequency,
            deadline_qpc=budget.cutoff(5),root_deadline_qpc=budget.deadline,source_hashes=hashes,source_sha256=closure,
            actor_sha256=ah,manifest_sha256=mh,guard_job_name='Local\\RuleProxy.LocalGuard.'+config['run'],device_sha256=api.device_sha256(),
            recovery_plan_sha256=value['recovery_plan_sha256'])
        if execution_mode=='profiles-off-diagnostic':config['execution_mode']=execution_mode
        if allow_held_system_conhost:config['selected_admission']=live.system_conhost_record(api)
        validate_config(config)
        phase='deadline';budget.require_ms(budget.cutoff(45))
        phase='staging';stage=parentpath/('local-model2-'+config['run']);value['cleanup']['tree_retained']=True
        require(not stage.exists() and not stage.is_symlink(),'fresh_stage');api.private_directory(stage,parent['sid'])
        for name,raw in files.items():
            budget.require_ms(budget.cutoff(40));path=stage/name;path.parent.mkdir(parents=True,exist_ok=True)
            launcher.write_private_bytes(path,raw);require(live.sha(local.bounded(path,256*1024))==hashes[name],'source_copy')
        for name in ('inputs','runtime','guard'):(stage/name).mkdir()
        (stage/'guard/temp').mkdir()
        for source,target,limit in ((actor,stage/'inputs'/live.ACTOR,8*1024*1024),(manifest,stage/'inputs'/live.MANIFEST,8192),
                                   (bundle,stage/'bundle.zip',32*1024*1024)):
            launcher.write_private_bytes(target,local.bounded(source,limit))
        for name,limit in zip(probe.MEMBERS,probe.MEMBER_LIMITS):launcher.write_private_bytes(stage/'runtime'/name,local.bounded(runtime/name,limit))
        live.verify_actor(stage/'inputs'/live.ACTOR,stage/'inputs'/live.MANIFEST,ah,mh,root=stage)
        probe.verify_artifacts(stage/'bundle.zip',stage/'runtime')
        raw_plan=local.bounded(plan_path,8192);require(live.sha(raw_plan)==value['recovery_plan_sha256'],'plan_changed')
        launcher.write_private_bytes(stage/'recovery-plan.json',raw_plan);launcher.write_private_bytes(stage/'model2-config.json',live.encode(config))
        require(live.source_snapshot(root)[2]==closure,'source_changed');budget.require_ms(budget.cutoff(40))
        python=launcher.checked_path(sys.executable,inside=launcher.checked_path(sys.base_prefix,is_file=False));require(python.name.casefold()=='python.exe','python')
        api.worker_job_name=config['guard_job_name'];api.worker_sid=parent['sid']
        phase='worker';launched=True;value['cleanup']['recovery_required']=True
        launch=launcher.launch_owned(api,[str(python),'-I','-S','-B',str(stage/'.github/windows_identity_model2_local.py'),
            '--owned-worker','--config',str(stage/'model2-config.json')],stage/'guard',parent,parent,
            qpc_budget=budget,work_cutoff=budget.cutoff(3),cleanup_cutoff=budget.deadline)
        c=value['cleanup'];c.update(guard_job_verified=api.atomic_job_requested is True and launch.get('native_identity_verified_before_resume') is True,
            controller_held_verified=launch.get('native_identity_verified_before_resume') is True,
            controller_exit_verified=launch.get('cleanup',{}).get('process_exit_confirmed') is True,
            outer_cleanup_verified=local.guest.cleanup_verified(launch))
        phase='report';require(c['controller_exit_verified'],'unknown_worker')
        report=live.decode(local.bounded(stage/'model2-controller-report.json',live.MAX_PRIVATE))
        r=bind_controller(report,config,launch);value['result']=r
        journal_raw=local.bounded(stage/'model2-ownership-private.json',live.MAX_PRIVATE)
        require(len(journal_raw)==report['ownership_journal_bytes'] and live.sha(journal_raw)==report['ownership_journal_sha256'],'ownership_journal_binding')
        controller=load('windows_identity_model2_controller')
        journal=live.decode(journal_raw)
        controller.validate_ownership_journal(journal,config,controller_pid=launch['child_pid'])
        require(journal['public_sha256']==live.sha(live.encode(report['public'])),'ownership_public_binding')
        inner_clean=r['checks']['cleanup'];c['recovery_required']=not(inner_clean and c['outer_cleanup_verified'])
        r['checks']['guard_held']=c['guard_job_verified'] and c['controller_held_verified']
        r['checks']['cleanup']=inner_clean and c['outer_cleanup_verified'] and c['controller_exit_verified']
        normal=(launch.get('started') is True and launch.get('resumed') is True and launch.get('timed_out') is False
            and 'error' not in launch and type(launch.get('exit_code')) is int and launch['exit_code']==0)
        if not normal and r['failure'] is None:r['failure']='worker'
        value['result']=live.finalize_public(r)
        phase='cleanup';require(not c['recovery_required'],'cleanup')
        phase='worker';require(normal,'worker_exit')
        if r['status'] in ('observed','passed','diagnostic-observed'):value['status']=r['status']
        elif any(r['violations'].values()):value['status']='failed'
        phase='deadline';budget.require_ms(budget.deadline)
    except BaseException:
        value['failure']=phase;value['status']='failed' if any(value['result']['violations'].values()) else 'inconclusive'
        if value['result']['status'] in ('observed','passed','diagnostic-observed'):
            r=value['result'];r['status']=value['status']
            if r['failure'] is None:r['failure']=phase if phase in ('deadline','worker','report','cleanup') else 'worker'
            value['result']=live.finalize_public(r)
        if launched and not value['cleanup']['controller_exit_verified']:value['cleanup']['recovery_required']=True
    return validate(value)
def main(argv=None):
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--run-local-first-chain',action='store_true');parser.add_argument('--approved-local-security-test',action='store_true')
    parser.add_argument('--profiles-off-diagnostic',action='store_true',help='Explicit separate diagnostic; requires all effective firewall profiles disabled and never qualifies strict C.')
    parser.add_argument('--allow-held-system-conhost',action='store_true',help='Explicit diagnostic-only admission for one pinned and fully held system console helper.')
    parser.add_argument('--owned-worker',action='store_true',help=argparse.SUPPRESS);parser.add_argument('--config',help=argparse.SUPPRESS)
    for name in ('actor','manifest','actor-sha256','manifest-sha256','bundle','runtime-directory','work-parent','recovery-plan'):parser.add_argument('--'+name)
    args=parser.parse_args(argv)
    if args.owned_worker:
        try:return worker(args.config)
        except BaseException as exc:
            # Private bounded diagnostic survives early contract/setup failures;
            # never emit paths, SIDs, raw exceptions or traceback on stdout.
            try:
                if ROOT.name.startswith('local-model2-') and live.ac.nonce(ROOT.name[len('local-model2-'):]):
                    category=type(exc).__name__
                    if category not in ('ValueError','OSError','NativeFailure','GateFailure'):category='other'
                    code=getattr(exc,'winerror',None)
                    if not live.integer(code):code=None
                    launcher.write_private_bytes(ROOT/'model2-worker-error.json',live.encode(dict(schema_version=1,
                        stage='model2-worker-exception',category=category,winerror=code)))
            except BaseException:pass
            return 1
    require(args.config is None,'private_mode')
    values=(args.actor,args.manifest,args.actor_sha256,args.manifest_sha256,args.bundle,args.runtime_directory,args.work_parent,args.recovery_plan)
    mode='profiles-off-diagnostic' if args.profiles_off_diagnostic else 'strict'
    options=dict(execution_mode=mode)
    if args.allow_held_system_conhost:options['allow_held_system_conhost']=True
    value=run_local(*values,approved=args.approved_local_security_test,**options) if args.run_local_first_chain else preflight(*values,**options)
    sys.stdout.write(live.encode(value).decode('ascii'));return 0 if value['status'] in ('ready','observed','passed','diagnostic-observed') else 1
if __name__=='__main__':raise SystemExit(main())
