# ARCHIVE-SAFE REVIEW COPY, NOT EXECUTED BYTES. One private run nonce is redacted.
# This copy cannot recover the original attempt; use the executed SHA commitment for provenance.
"""Exact, separately supervised recovery of LPAC02 residue; never an experiment.

The historical attempt remains inconclusive with cleanup uncertainty. This
entry can only remove the original fresh SID's ACEs from its bounded private
tree, then delete its exact fresh profile. No actor, DNS, inventory, network,
firewall, resolver, route, capability, or ancestor ACL operation is allowed.
"""
import ctypes as C
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import secrets
import stat
import sys

ORIGINAL_RUN='REDACTED_PRIVATE_ORIGINAL_RUN'
ORIGINAL_REPORT='aca80fa868dad0d584000dc7680ae3ee203a7da143f7fff37f6998bd22e3aef3'
ORIGINAL_PUBLIC='648a28df4868236ecc179b1a410b8c8539290577bc9677e0aa78f1cb7abe3b91'
ORIGINAL_SOURCE='96e1b3c439c7b33c7b01820f65c411558b1e5685b994cc09c2cf174b14e483d1'
OWNER_SOURCE='e8c86c17a141dadfac7ead761b643985d44998b0419ceab0f3808efb6233f5a1'
ACTOR_SHA='0a9e867cce846b366693e8662034db8c0c4646bd312a6143c367da2c36fb557a'
MANIFEST_SHA='657c88ef59f8ba9d4c24f5e407696b27615f50c63d58adc5d8dd64f942104e92'
STAGE_NAME='local-lpac-'+ORIGINAL_RUN
FACTS=('source_verified','original_state_bound','old_outer_job_absent','old_tool_generations_exited',
    'unknown_create_atomic_job_suspended_proof','no_live_exact_staged_actor_observed_twice',
    'original_sid_ace_scope_verified','acl_remove_intent_durable','acl_remove_tool_held_identity_verified',
    'acl_remove_tool_outer_job_verified','acl_remove_tool_exit0','acl_remove_tool_cleanup_verified',
    'all_exact_sid_aces_absent','profile_delete_intent_durable','profile_delete_returned_success')

def require(test,reason):
    if not test:raise ValueError(reason)
def sha(raw):return hashlib.sha256(raw).hexdigest()
def encode(value):return (json.dumps(value,sort_keys=True,separators=(',',':'),allow_nan=False)+'\n').encode('ascii')
def bounded(path,limit):
    value=path.lstat()
    require(stat.S_ISREG(value.st_mode) and not getattr(value,'st_file_attributes',0)&0x400 and value.st_size<=limit,'bounded_file')
    with path.open('rb') as stream:raw=stream.read(limit+1)
    require(len(raw)==value.st_size and len(raw)<=limit,'bounded_read');return raw
def read(path,limit=512*1024):return json.loads(bounded(path,limit))
def durable(path,raw):
    require(type(raw) is bytes and len(raw)<=512*1024,'durable_bound')
    with path.open('xb') as stream:
        require(stream.write(raw)==len(raw),'durable_write');stream.flush();os.fsync(stream.fileno())
    require(bounded(path,512*1024)==raw,'durable_readback')
def safe_tree_path(stage,name):
    require(type(name) is str and not Path(name).is_absolute() and not Path(name).drive and '..' not in Path(name).parts,'source_path')
    path=stage/name
    for target in (stage,*(stage/p for p in reversed(path.relative_to(stage).parents[:-1]))):
        value=target.lstat();require(stat.S_ISDIR(value.st_mode) and not getattr(value,'st_file_attributes',0)&0x400,'source_parent')
    return path
def authenticated_load(stage):
    # Stdlib verifies every dependency BEFORE any staged source can execute.
    report_raw=bounded(stage/'worker-report.json',512*1024);require(sha(report_raw)==ORIGINAL_REPORT,'original_report_sha')
    report=json.loads(report_raw);config=read(stage/'worker-config.json')
    require(report['config']==config and config['run']==ORIGINAL_RUN,'original_config')
    hashes=config['source_hashes'];require(type(hashes) is dict and len(hashes)==31 and sha(encode(hashes))==ORIGINAL_SOURCE,'original_source_closure')
    require(hashes['.github/windows_identity_lpac_dns_local.py']==OWNER_SOURCE,'original_owner_source')
    for name,digest in hashes.items():require(sha(bounded(safe_tree_path(stage,name),256*1024))==digest,'original_source_byte_pin')
    spec=importlib.util.spec_from_file_location('lpac02_exact_recovery_source',stage/'.github/windows_identity_lpac_dns_local.py')
    module=importlib.util.module_from_spec(spec);spec.loader.exec_module(module)
    return module,report,config

def clock_start():
    kernel=C.WinDLL('kernel32.dll',use_last_error=True,winmode=0x800)
    for name in ('QueryPerformanceFrequency','QueryPerformanceCounter'):
        function=getattr(kernel,name);function.argtypes=[C.POINTER(C.c_int64)];function.restype=C.c_int
    frequency,start=C.c_int64(),C.c_int64()
    require(kernel.QueryPerformanceFrequency(C.byref(frequency)) and kernel.QueryPerformanceCounter(C.byref(start)),'recovery_qpc')
    require(1<=frequency.value<=1000000000 and start.value>0,'recovery_qpc_range')
    return int(frequency.value),int(start.value)

def absent_job(api,name):
    api.k.OpenJobObjectW.argtypes=[C.c_uint32,C.c_int,C.c_wchar_p];api.k.OpenJobObjectW.restype=C.c_void_p
    C.set_last_error(0);handle=api.k.OpenJobObjectW(4,False,name);error=C.get_last_error()
    if handle:
        api.close(handle);raise ValueError('old_exact_job_still_exists')
    require(error==2,'old_job_absence_unknown')

def exact_job(api,name,process):
    api.k.OpenJobObjectW.argtypes=[C.c_uint32,C.c_int,C.c_wchar_p];api.k.OpenJobObjectW.restype=C.c_void_p
    handle=api.k.OpenJobObjectW(4,False,name);api.check(handle,'OpenJobObjectW(recovery_outer_query)')
    try:api.verify_job(handle,process)
    finally:api.close(handle)

def old_generations(native,rows,budget):
    observations=[]
    for row in rows:
        budget.require_ms(budget.cutoff(25));C.set_last_error(0)
        handle=native.k.OpenProcess(0x101000,False,row['pid']);error=C.get_last_error()
        if not handle:
            require(error==87,'old_tool_query_unknown');observations.append(dict(name=row['name'],old_generation_live=False,process_absent=True));continue
        try:
            created=native.creation_time(handle);same=created==row['created']
            exited=native.wait(handle,0)
            require(not same or exited,'old_tool_generation_still_live')
            observations.append(dict(name=row['name'],old_generation_live=False,process_absent=False,reused_generation=not same,held_exit=exited))
        finally:native.close(handle)
    return observations

def actor_census(native,actor,budget):
    # Only read-query handles. A basename match whose image cannot be resolved
    # is UNKNOWN, never an absent process, and never PID-based kill authority.
    before=budget.read();budget.require_ms(budget.cutoff(25));native.parent_snapshot()
    rows=[];images=native.last_snapshot_images
    candidates=[pid for pid,name in images.items() if name.casefold()==actor.name.casefold()]
    require(len(candidates)<=32,'actor_census_bound')
    for pid in candidates:
        handle=native.open_query_process(pid)
        try:
            image=native.process_image(handle);created=native.creation_time(handle);exited=native.wait(handle,0)
            # Resolve Win32 path aliases for comparison; query failures remain
            # UNKNOWN. The resolved path is never used for process control.
            same=os.path.normcase(str(Path(image).resolve(strict=True)))==os.path.normcase(str(actor))
            require(not same or exited,'exact_staged_actor_still_live')
            rows.append(dict(pid=pid,created=created,exact_staged_image=same,held_exit=exited,query_closed=True))
        finally:native.close(handle)
    budget.require_ms(budget.cutoff(25))
    return dict(start_qpc=before,end_qpc=budget.read(),matching_basename_count=len(candidates),no_live_exact_staged_actor=True,rows=rows)

def original_state(m,report,config,public,parent):
    require(report['worker_identity']==parent,'original_worker_identity')
    require(config['source_sha256']==ORIGINAL_SOURCE and config['actor_sha256']==ACTOR_SHA and config['manifest_sha256']==MANIFEST_SHA,'original_artifacts')
    m.validate_public(public);m.config_validate(config);j=m.validate_result(report['result'],config)
    require(public['source_sha256']==ORIGINAL_SOURCE and public['actor_sha256']==ACTOR_SHA and public['manifest_sha256']==MANIFEST_SHA,'original_public_bind')
    require(all(public['checks'][k] for k in ('guard','worker_exit','outer_cleanup','worker_bound','fixture_cleanup','sid_released')),'original_outer_cleanup')
    require(public['recovery_required'] and not public['network_tested'] and not public['selected_wire_query_observed'],'original_no_network')
    require(j['profile_created'] and j['acl_attempted'] and not j['acl_removed'] and not j['profile_deleted']
        and not j['workload_cleanup'] and j['workload_job_empty'] and j['sid_released'] and j['failure']=='setup','original_residue')
    require(not j['selected_lpac_held'] and j['native']==[] and j['go']==[] and j['inventory'] is None
        and j['fixture_final'] is None and not j['selected_wire_query_observed'] and j['cleanup_tasks']==[],'original_no_actor_protocol')
    require([r['name'] for r in j['tasks']]==['grant-root','grant-inputs','grant-lpac-report','grant-lpac-control','selected'],'original_tasks')
    tools=j['tasks'][:4];unknown=j['tasks'][4]
    require(all(r['attempted'] and r['process_returned'] and r['assigned'] and r['admitted'] and r['resumed']
        and r['exited'] and r['exit_code']==0 and r['lpac'] is None for r in tools),'original_tool_exits')
    require(unknown['attempted'] and not unknown['process_returned'] and unknown['pid'] is None and unknown['created'] is None
        and not unknown['assigned'] and not unknown['admitted'] and not unknown['resumed'] and unknown['go_qpc']==[],'original_unknown_create')
    require(j['profile_name']=='ruleproxy-lpac-'+ORIGINAL_RUN and m.ac.ac_profile_sid(j['profile_sid']),'original_profile_binding')
    # This is a proof from the exact reviewed source, NOT a new claim that its
    # missing process handle or historical cleanup receipt has become known.
    require(m.JOB_LIST==0x2000d and m.launcher.KILL_ON_JOB_CLOSE==0x2000,'original_atomic_constants')
    return j,tools

def worker(config_path):
    config_path=Path(config_path).resolve();cfg=read(config_path,16384);recovery=config_path.parent
    require(sha(bounded(Path(__file__),256*1024))==cfg['worker_sha256'],'recovery_worker_sha')
    repo=Path(cfg['repo']);stage=Path(cfg['stage'])
    require(stage.parent==repo/'private' and stage.name==STAGE_NAME,'original_stage')
    m,old_report,old_config=authenticated_load(stage)
    api=m.local.LocalNativeAPI();parent=m.local.ordinary(api)
    m.local.verify_guard_job(api,cfg['guard_job'])
    require(api.device_sha256()==cfg['device_sha256']==old_config['device_sha256'],'recovery_device')
    require(api.qpc_frequency()==cfg['frequency'] and cfg['root_deadline']==cfg['start']+120*cfg['frequency']
        and cfg['deadline']==cfg['root_deadline']-5*cfg['frequency'],'recovery_clock_binding')
    budget=m.launcher.QpcBudget(api,cfg['deadline'],cfg['frequency']);budget.require_ms(budget.cutoff(30))
    require(sha(bounded(repo/'verification/windows-2026-10-22/lpac-dns-local-02-public.json',8192))==ORIGINAL_PUBLIC,'original_public_sha')
    public=read(repo/'verification/windows-2026-10-22/lpac-dns-local-02-public.json',8192)
    result=dict(schema_version=1,stage='lpac-dns-02-exact-recovery-worker',worker_pid=os.getpid(),config_sha256=sha(encode(cfg)),
        original_report_sha256=ORIGINAL_REPORT,original_public_sha256=ORIGINAL_PUBLIC,original_source_sha256=ORIGINAL_SOURCE,
        facts=dict.fromkeys(FACTS,False),failure=None,old_tasks=[],censuses=[],remove_launch=None,
        original_historical_cleanup_changed=False,network_actor_run=False,network_query_run=False)
    phase='original'
    try:
        plan_raw=bounded(stage/'recovery-plan.json',8192)
        require(sha(plan_raw)==old_config['recovery_plan_sha256']==public['recovery_plan_sha256'],'original_plan_sha')
        m.plan(json.loads(plan_raw),device=cfg['device_sha256'],source=ORIGINAL_SOURCE,actor=ACTOR_SHA,manifest=MANIFEST_SHA)
        j,old_tools=original_state(m,old_report,old_config,public,parent);result['facts'].update(source_verified=True,original_state_bound=True)
        require(sorted(p.name for p in (stage/'journal').iterdir())==['00-profile-create.json','01-acl-grant.json','02-spawn-grant-root.json',
            '03-spawn-grant-inputs.json','04-spawn-grant-lpac-report.json','05-spawn-grant-lpac-control.json','06-spawn-selected.json'],'original_journal')
        phase='old-job';absent_job(api,old_config['guard_job_name']);result['facts']['old_outer_job_absent']=True
        native=m.LPACAPI();sid,name=j['profile_sid'],j['profile_name']
        require(native.derive_profile_sid(name)==sid,'original_exact_profile_sid')
        actor=m.launcher.checked_path(stage/'inputs'/m.live.ACTOR,inside=stage)
        require(sha(bounded(actor,8*1024*1024))==ACTOR_SHA,'original_staged_actor')
        phase='old-process';result['old_tasks']=old_generations(native,old_tools,budget);result['facts']['old_tool_generations_exited']=True
        phase='census';result['censuses'].append(actor_census(native,actor,budget))
        api.sleep_ms(100);result['censuses'].append(actor_census(native,actor,budget))
        result['facts'].update(no_live_exact_staged_actor_observed_twice=True,unknown_create_atomic_job_suspended_proof=True)
        phase='scope';paths=m.owned_tree(stage)
        for path in paths:
            budget.require_ms(budget.cutoff(25));require(native.acl_read(path,sid)==m.expected_acl(stage,path),'original_exact_sid_scope')
        result['facts']['original_sid_ace_scope_verified']=True
        phase='remove-intent';durable(recovery/'remove-intent.json',encode(dict(schema_version=1,action='remove-only-original-profile-sid-aces',
            original_report_sha256=ORIGINAL_REPORT,original_source_sha256=ORIGINAL_SOURCE,profile_name=name,profile_sid=sid,
            root=str(stage),exact_original_scope_verified=True,unknown_creation_source_proof='atomic-job-list-and-create-suspended-no-resume',
            old_worker_exit_bound=True,old_inner_empty_receipt=True,two_no_live_exact_actor_censuses=True,qpc=budget.read(),deadline=cfg['deadline'])))
        result['facts']['acl_remove_intent_durable']=True
        class ToolAPI(m.local.LocalNativeAPI):
            outer_verified=False
            def assign_job(self,job,process):
                super().assign_job(job,process);exact_job(self,cfg['guard_job'],process);self.outer_verified=True
        tool=ToolAPI();require(m.local.ordinary(tool)==parent,'recovery_tool_parent')
        tool.worker_job_name='Local\\RuleProxy.LocalGuard.'+secrets.token_hex(16);tool.worker_sid=parent['sid']
        system=dict(v.split('=',1) for v in tool.environment(recovery).rstrip('\0').split('\0'))['SystemRoot']
        icacls=m.launcher.checked_path(Path(system)/'System32/icacls.exe')
        require(sha(bounded(icacls,8*1024*1024))==old_tools[0]['image_sha256'] and all(r['image_sha256']==old_tools[0]['image_sha256'] for r in old_tools),'fixed_icacls')
        work=recovery/'remove-tool';work.mkdir();(work/'temp').mkdir()
        phase='remove-tool';launch=m.launcher.launch_owned(tool,[str(icacls),str(stage),'/remove:g','*'+sid,'/T','/Q'],work,parent,parent,
            qpc_budget=budget,work_cutoff=budget.cutoff(20),cleanup_cutoff=budget.cutoff(15))
        result['remove_launch']=launch;durable(recovery/'remove-launch.json',encode(launch))
        result['facts']['acl_remove_tool_held_identity_verified']=launch.get('native_identity_verified_before_resume') is True
        result['facts']['acl_remove_tool_outer_job_verified']=tool.outer_verified
        result['facts']['acl_remove_tool_exit0']=launch.get('exit_code')==0 and launch.get('resumed') is True
        result['facts']['acl_remove_tool_cleanup_verified']=tool.atomic_job_requested and m.local.guest.cleanup_verified(launch)
        require(all(result['facts'][key] for key in ('acl_remove_tool_held_identity_verified','acl_remove_tool_outer_job_verified',
            'acl_remove_tool_exit0','acl_remove_tool_cleanup_verified')) and launch.get('timed_out') is False and 'error' not in launch,'remove_tool_not_clean')
        require(sha(bounded(icacls,8*1024*1024))==old_tools[0]['image_sha256'],'fixed_icacls_after')
        phase='readback'
        for path in m.owned_tree(stage):
            budget.require_ms(budget.cutoff(10));require(native.acl_read(path,sid)==[],'remaining_original_sid_ace')
        result['facts']['all_exact_sid_aces_absent']=True
        require(native.derive_profile_sid(name)==sid,'delete_profile_sid_rebind')
        phase='delete-intent';durable(recovery/'delete-intent.json',encode(dict(schema_version=1,action='delete-only-original-fresh-profile',
            original_report_sha256=ORIGINAL_REPORT,original_source_sha256=ORIGINAL_SOURCE,profile_name=name,profile_sid=sid,
            exact_sid_aces_absent=True,remove_tool_exit0_and_cleanup=True,qpc=budget.read(),deadline=cfg['deadline'])))
        result['facts']['profile_delete_intent_durable']=True
        phase='delete-profile';budget.require_ms(budget.cutoff(5));native.delete_profile(name);result['facts']['profile_delete_returned_success']=True
        phase='deadline';budget.require_ms(budget.cutoff(1))
    except BaseException as error:
        result['failure']=phase;result['error_private']=dict(type=type(error).__name__,message=str(error))
    durable(recovery/'worker-report.json',encode(result))
    if result['failure'] is None:
        require(all(result['facts'].values()),'complete_recovery')
        durable(stage/'exact-recovery-02-private.json',encode(result))
    return 0 if result['failure'] is None else 1

def guard():
    frequency,start=clock_start();base=Path(__file__).resolve().parent;repo=base/'Rule-proxy-Web';stage=repo/'private'/STAGE_NAME
    m,report,original=authenticated_load(stage);api=m.local.LocalNativeAPI();parent=m.local.ordinary(api)
    require(api.device_sha256()==original['device_sha256'] and api.qpc_frequency()==frequency,'recovery_guard_identity_clock')
    budget=m.launcher.QpcBudget(api,start+120*frequency,frequency);budget.require_ms(budget.cutoff(40))
    nonce=secrets.token_hex(16);recovery=repo/'private'/('lpac02-exact-recovery-'+nonce);api.private_directory(recovery,parent['sid'])
    raw=bounded(Path(__file__),256*1024);durable(recovery/'recovery.py',raw)
    cfg=dict(repo=str(repo),stage=str(stage),worker_sha256=sha(raw),device_sha256=api.device_sha256(),frequency=frequency,start=start,
        root_deadline=budget.deadline,deadline=budget.cutoff(5),guard_job='Local\\RuleProxy.LocalGuard.'+nonce)
    durable(recovery/'config.json',encode(cfg));work=recovery/'guard';work.mkdir();(work/'temp').mkdir()
    api.worker_job_name=cfg['guard_job'];api.worker_sid=parent['sid']
    python=m.launcher.checked_path(sys.executable,inside=m.launcher.checked_path(sys.base_prefix,is_file=False))
    require(python.name.casefold()=='python.exe','fixed_python')
    launch=m.launcher.launch_owned(api,[str(python),'-I','-S','-B',str(recovery/'recovery.py'),'--worker',str(recovery/'config.json')],
        work,parent,parent,qpc_budget=budget,work_cutoff=budget.cutoff(3),cleanup_cutoff=budget.deadline)
    durable(recovery/'launch.json',encode(launch));worker_report=None;report_bound=False
    try:
        worker_report=read(recovery/'worker-report.json')
        expected={'schema_version','stage','worker_pid','config_sha256','original_report_sha256','original_public_sha256','original_source_sha256',
            'facts','failure','old_tasks','censuses','remove_launch','original_historical_cleanup_changed','network_actor_run','network_query_run'}
        require(type(worker_report) is dict and set(worker_report)==expected and type(worker_report['schema_version']) is int and worker_report['schema_version']==1
            and worker_report['stage']=='lpac-dns-02-exact-recovery-worker' and type(worker_report['worker_pid']) is int and worker_report['worker_pid']==launch['child_pid']
            and worker_report['config_sha256']==sha(encode(cfg)) and worker_report['original_report_sha256']==ORIGINAL_REPORT
            and worker_report['original_public_sha256']==ORIGINAL_PUBLIC and worker_report['original_source_sha256']==ORIGINAL_SOURCE,'recovery_report_binding')
        require(type(worker_report['facts']) is dict and set(worker_report['facts'])==set(FACTS) and all(value is True for value in worker_report['facts'].values())
            and worker_report['failure'] is None and worker_report['original_historical_cleanup_changed'] is False
            and worker_report['network_actor_run'] is False and worker_report['network_query_run'] is False,'recovery_report_facts')
        require(type(worker_report['censuses']) is list and len(worker_report['censuses'])==2
            and all(row['no_live_exact_staged_actor'] is True for row in worker_report['censuses']),'recovery_report_censuses')
        report_bound=True
    except BaseException:report_bound=False
    clean=m.local.guest.cleanup_verified(launch)
    good=bool(report_bound and api.atomic_job_requested and launch.get('native_identity_verified_before_resume') is True
        and clean and launch.get('started') is True and launch.get('resumed') is True and launch.get('exit_code')==0
        and launch.get('timed_out') is False and 'error' not in launch)
    value=dict(schema_version=1,stage='lpac-dns-local-02-exact-recovery-public',passed=good,recovery_worker_source_sha256=sha(raw),
        original_public_sha256=ORIGINAL_PUBLIC,original_report_sha256=ORIGINAL_REPORT,original_source_sha256=ORIGINAL_SOURCE,
        worker_report_bound=report_bound,outer_cleanup_verified=clean,facts=worker_report['facts'] if report_bound else dict.fromkeys(FACTS,False),
        original_historical_cleanup_changed=False,network_actor_run=False,network_query_run=False)
    durable(repo/'verification/windows-2026-10-22/lpac-dns-local-02-recovery-public.json',encode(value))
    print(json.dumps(value,sort_keys=True));return 0 if good else 1

if __name__=='__main__':
    require(len(sys.argv)==1 or len(sys.argv)==3 and sys.argv[1]=='--worker','arguments')
    raise SystemExit(worker(sys.argv[2]) if len(sys.argv)==3 else guard())
