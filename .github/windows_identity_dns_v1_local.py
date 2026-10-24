"""Ordinary DNS VERSION1 mechanism; default is read-only source/artifact preflight.

One supervised worker owns one loopback fixture and one held ordinary native
caller. No AppContainer, firewall rule, default resolver, REQUEST3 or broker
isolation conclusion. Explicit actual opt-in and device-bound plan are required.
"""
from __future__ import annotations
import argparse
import hashlib
import importlib.util
import os
from pathlib import Path
import secrets
import sys
import time

ROOT=Path(__file__).resolve().parents[1]
def load(name):
    spec=importlib.util.spec_from_file_location('dns_v1_'+name,Path(__file__).with_name(name+'.py'))
    module=importlib.util.module_from_spec(spec);spec.loader.exec_module(module);return module
local=load('windows_identity_proxy_pipe_ac_local')
fixture_module=load('windows_dns_fixture')
launcher=local.launcher;a=local.controller
SOURCES=(*local.SOURCES,'.github/windows_dns_fixture.py','.github/windows_identity_dns_v1_local.py')
NATIVE={
    'actorSourceSha256':'.github/native/windows_identity_dns_v1_actor.cpp',
    'identitySourceSha256':'.github/native/windows_identity_actor.cpp',
    'dnsProbeSha256':'.github/native/windows_identity_dns_v1_probe.hpp'}
ACTOR='windows_identity_dns_v1_actor.exe'
MANIFEST='identity-dns-v1-manifest.json'
SCOPE='one-ordinary-dns-query-version1-owned-loopback-v1'
BOOLS=('configured','called','completed','pending','answer_match','records_released','context_retained','within_deadline')
CHECKS=('ordinary','device_plan','source_bound','artifact_bound','guard_atomic','worker_held','worker_exit',
        'outer_cleanup','worker_report_bound','actor_atomic','actor_held','actor_exit','actor_cleanup','fixture_cleanup')
def require(value):
    if not value:raise ValueError('dns_v1_contract')
def sha(raw):return hashlib.sha256(raw).hexdigest()
def encode(value):return local.encode(value)
def snapshot(root=ROOT):
    files={name:local.bounded(launcher.checked_path(root/name,inside=root),256*1024) for name in SOURCES}
    hashes={name:sha(raw) for name,raw in files.items()}
    return files,hashes,sha(encode(hashes))
def artifact(actor,manifest,ah,mh,root=ROOT):
    actor=launcher.checked_path(actor);manifest=launcher.checked_path(manifest)
    require(actor.name==ACTOR and manifest.name==MANIFEST and actor.parent==manifest.parent)
    value,raw=a.bounded_json(manifest,8192,inside=actor.parent)
    require(set(value)=={'schemaVersion','compileOnly','runtimeAcceptance','executableSha256',*NATIVE})
    require(type(value['schemaVersion']) is int and value['schemaVersion']==1 and value['compileOnly'] is True and value['runtimeAcceptance'] is False)
    require(a.digest(ah) and a.digest(mh) and sha(raw)==mh and value['executableSha256']==ah)
    a.pipe_helpers.verify_copied_actor(actor,ah)
    for key,name in NATIVE.items():require(value[key]==sha(local.bounded(root/name,256*1024)))
    return actor,manifest
def blank(mode):
    return dict(schema_version=1,stage='ordinary-dns-version1-local',mode=mode,status='inconclusive',failure=None,
        source_sha256=None,actor_sha256=None,manifest_sha256=None,recovery_plan_sha256=None,
        checks={key:False for key in CHECKS},api=None,fixture=None,network_tested=False,
        owned_query_observed=False,mechanism_passed=False,tree_retained=False,recovery_required=False,
        default_resolver_tested=False,selected_application_tested=False,broker_cancellation_proven=False,
        dns_isolation_qualified=False,product_acceptance=False)
def validate_api(api):
    require(type(api) is dict and set(api)=={*BOOLS,'api_status','query_status','record_count'})
    require(all(type(api[key]) is bool for key in BOOLS) and all(a.integer(api[key]) for key in ('api_status','query_status','record_count')))
    require(not api['completed'] or api['called'] and api['configured'] and not api['pending'])
    require(not api['pending'] or api['called'] and api['configured'] and not api['completed'] and api['context_retained'])
    require(not api['records_released'] or api['completed'])
    require(not api['answer_match'] or api['called'] and api['completed'] and not api['pending'] and api['api_status']==0 and api['query_status']==0 and api['record_count']==1)
    return api
def native_text(raw):
    if raw is None:return None,'missing',None
    require(type(raw) is bytes and len(raw)<=8192)
    try:return raw.decode('ascii','strict'),'ascii',sha(raw)
    except UnicodeDecodeError:return None,'non-ascii',sha(raw)
def receiver_projection(fixture):
    require(type(fixture) is dict and set(fixture)=={'ready','socket_closed','thread_stopped','cleanup_confirmed',
        'error','counts','query_observed','byte_count_is_observed_lower_bound','broker_cancellation_proven'})
    require(all(type(fixture[key]) is bool for key in ('ready','socket_closed','thread_stopped','cleanup_confirmed',
        'query_observed','byte_count_is_observed_lower_bound','broker_cancellation_proven')))
    require(fixture['broker_cancellation_proven'] is False and fixture['byte_count_is_observed_lower_bound'] is True)
    require(fixture['error'] in ('none','bound','deadline','receive','operation','send'))
    require(not fixture['cleanup_confirmed'] or fixture['socket_closed'] and fixture['thread_stopped'])
    counts=fixture['counts'];complete=counts is not None
    if complete:
        require(type(counts) is dict and set(counts)=={'datagrams','bytes','matched_queries','answers_sent','rejected','oversized','send_failed'})
        require(all(a.integer(counts[key],0,32) for key in counts if key!='bytes') and a.integer(counts['bytes'],0,65536))
        require(fixture['thread_stopped'] and fixture['query_observed']==(counts['matched_queries']>0))
    return dict(**{key:None if counts is None else counts[key] for key in ('matched_queries','answers_sent','rejected','send_failed')},
        query_observed=fixture['query_observed'],snapshot_complete=complete,error=fixture['error'])
def validate(value):
    template=blank(value.get('mode') if type(value) is dict else None)
    require(type(value) is dict and set(value)==set(template) and value['mode'] in ('preflight','runtime'))
    for key in ('schema_version','stage','default_resolver_tested','selected_application_tested',
                'broker_cancellation_proven','dns_isolation_qualified','product_acceptance'):
        require(type(value[key]) is type(template[key]) and value[key]==template[key])
    require(value['status'] in ('ready','inconclusive','passed') and value['failure'] in (None,'inputs','identity','plan','deadline','staging','worker','report','cleanup','mechanism'))
    require(type(value['checks']) is dict and set(value['checks'])==set(CHECKS) and all(type(v) is bool for v in value['checks'].values()))
    for key in ('network_tested','owned_query_observed','mechanism_passed','tree_retained','recovery_required'):require(type(value[key]) is bool)
    for key in ('source_sha256','actor_sha256','manifest_sha256','recovery_plan_sha256'):require(value[key] is None or a.digest(value[key]))
    api=value['api']
    if api is not None:validate_api(api)
    f=value['fixture']
    if f is not None:
        require(type(f) is dict and set(f)=={'matched_queries','answers_sent','rejected','send_failed','query_observed','snapshot_complete','error'})
        require(type(f['query_observed']) is bool and type(f['snapshot_complete']) is bool)
        require(all(a.integer(f[key],0,32) if f['snapshot_complete'] else f[key] is None for key in ('matched_queries','answers_sent','rejected','send_failed'))
            and f['error'] in ('none','bound','deadline','receive','operation','send'))
        require(not f['snapshot_complete'] or f['query_observed']==(f['matched_queries']>0))
    # API entry (including INVALID_PARAMETER) is distinct from actual wire.
    require(value['network_tested']==value['owned_query_observed'])
    require(value['owned_query_observed']==bool(f and f['query_observed']))
    if value['mode']=='preflight':
        require(api is None and f is None and not value['tree_retained'] and not value['recovery_required']
            and not any(value['checks'][key] for key in CHECKS if key not in ('ordinary','device_plan','source_bound','artifact_bound')))
        require(value['status']!='ready' or value['failure'] is None and all(value['checks'][key] for key in ('ordinary','device_plan','source_bound','artifact_bound')))
    success=(value['mode']=='runtime' and value['failure'] is None and all(value['checks'].values()) and api is not None
        and all(api[key] for key in ('configured','called','completed','answer_match','records_released','within_deadline'))
        and not api['pending'] and not api['context_retained'] and value['owned_query_observed'] and f['snapshot_complete'] and f['answers_sent']>0
        and f['send_failed']==0 and f['rejected']==0 and f['error']=='none' and not value['recovery_required'])
    require(value['mechanism_passed']==success and (value['status']=='passed')==success)
    require(len(encode(value))<=4096);return value
def preflight(actor,manifest,ah,mh,work_parent,plan_path,*,api=None):
    v=blank('preflight');phase='inputs'
    try:
        require(os.name=='nt');api=api or local.LocalNativeAPI();require(api.windows_x64())
        phase='identity';local.ordinary(api);v['checks']['ordinary']=True
        phase='inputs';_,_,closure=snapshot();v['source_sha256']=closure;v['checks']['source_bound']=True
        artifact(actor,manifest,ah,mh);v.update(actor_sha256=ah,manifest_sha256=mh);v['checks']['artifact_bound']=True
        parent=launcher.checked_path(work_parent,inside=ROOT/'private',is_file=False)
        require(parent.is_dir())
        phase='plan';raw=local.bounded(plan_path,8192);plan=local.guest.decode(raw)
        require(type(plan) is dict and set(plan)=={'schema_version','scope','device_sha256','actor_sha256','manifest_sha256','source_sha256','residue_review_acknowledged','recovery_reference'})
        require(type(plan['schema_version']) is int and plan['schema_version']==1 and plan['scope']==SCOPE and plan['residue_review_acknowledged'] is True)
        for key,expected in (('device_sha256',api.device_sha256()),('actor_sha256',ah),('manifest_sha256',mh),('source_sha256',closure)):require(plan[key]==expected)
        require(type(plan['recovery_reference']) is str and 1<=len(plan['recovery_reference'])<=512)
        v['recovery_plan_sha256']=sha(raw);v['checks']['device_plan']=True;v['status']='ready'
    except BaseException:v['failure']=phase
    return validate(v)
def native_projection(value,run,frequency,deadline,pid,sid):
    require(type(value) is dict and set(value)=={'schema_version','stage','identity','qpc_frequency','deadline_qpc','result'})
    require(type(value['schema_version']) is int and value['schema_version']==1 and value['stage']=='dns-v1-native'
        and value['qpc_frequency']==frequency and value['deadline_qpc']==deadline)
    identity=value['identity'];require(type(identity) is dict and set(identity)=={'schemaVersion','mode','nonce','pid','tokenUserSid',
        'tokenIsAppContainer','tokenAppContainerSid','tokenElevated','isProcessInJob','tokenCapabilities','queriesSucceeded','errors'})
    require(type(identity['schemaVersion']) is int and identity['schemaVersion']==1 and type(identity['pid']) is int
        and identity['pid']==pid and identity['tokenUserSid']==sid and identity['tokenAppContainerSid'] is None)
    require(identity['nonce']==run and identity['mode']=='actor' and identity['queriesSucceeded'] is True
        and identity['errors']==[] and identity['tokenElevated'] is False and identity['tokenIsAppContainer'] is False
        and identity['tokenCapabilities']==[] and identity['isProcessInJob'] is True)
    r=value['result'];require(set(r)=={*BOOLS,'api_status','query_status','record_count','start_qpc','end_qpc'})
    require(a.integer(r['start_qpc'],0,0x7fffffffffffffff) and a.integer(r['end_qpc'],0,0x7fffffffffffffff))
    require(not r['within_deadline'] or 0<r['start_qpc']<=r['end_qpc']<deadline)
    return validate_api({key:val for key,val in r.items() if key not in ('start_qpc','end_qpc')})
def launch_ok(value):
    return (type(value) is dict and value.get('started') is True and value.get('resumed') is True
        and value.get('timed_out') is False and 'error' not in value and type(value.get('exit_code')) is int
        and value['exit_code']==0 and value.get('native_identity_verified_before_resume') is True
        and local.guest.cleanup_verified(value))
def worker(config_path):
    stage=Path(__file__).resolve().parents[1];config_path=launcher.checked_path(config_path,inside=stage)
    require(config_path==stage/'dns-config.json');config=local.guest.decode(local.bounded(config_path,8192))
    require(set(config)=={'schema_version','run','actor_run','frequency','deadline','source_sha256','source_hashes','actor_sha256','manifest_sha256','device_sha256','guard_job_name'})
    api=local.LocalNativeAPI();parent=local.ordinary(api)
    local.verify_guard_job(api,config['guard_job_name'])
    require(config['device_sha256']==api.device_sha256());files,hashes,closure=snapshot(stage)
    require(closure==config['source_sha256'] and hashes==config['source_hashes'])
    actor,manifest=artifact(stage/'native'/ACTOR,stage/'native'/MANIFEST,config['actor_sha256'],config['manifest_sha256'],stage)
    frequency=config['frequency'];deadline=config['deadline'];require(frequency==api.qpc_frequency())
    budget=launcher.QpcBudget(api,deadline,frequency)
    budget.require_ms(budget.cutoff(30));run=config['actor_run'];require(a.nonce(run))
    fixture=None;fixture_result=None;launch=None;raw_native=None;failure=None
    try:
        # Translate once from original remaining QPC to fixture monotonic time;
        # the fixture has no independent renewal and stays inside worker budget.
        fixture=fixture_module.DnsFixture(run,deadline=time.monotonic()+budget.remaining_ms(budget.cutoff(10))/1000)
        port=fixture.start();require(49153<=port<=65535)
        work=stage/'actor';work.mkdir();(work/'temp').mkdir()
        api.worker_job_name='Local\\RuleProxy.LocalGuard.'+run;api.worker_sid=parent['sid']
        launch=launcher.launch_owned(api,[str(actor),run,str(frequency),str(budget.cutoff(15)),str(port)],work,parent,parent,
            qpc_budget=budget,work_cutoff=budget.cutoff(10),cleanup_cutoff=budget.cutoff(5))
        # Keep receiver positive observations even if output or cleanup fails.
        try:raw_native=local.bounded(work/'controller.stdout',8192)
        except BaseException:failure='report'
        try:
            if local.bounded(work/'controller.stderr',8192):failure='report'
        except BaseException:failure='report'
    except BaseException:failure='worker'
    finally:
        if fixture is not None:
            fixture_result=fixture.finish(deadline=time.monotonic()+budget.remaining_ms(budget.cutoff(2))/1000)
    text,status,digest=native_text(raw_native)
    if status=='non-ascii':failure='report'
    report=dict(schema_version=1,run=config['run'],actor_run=run,worker_pid=os.getpid(),worker_sid=parent['sid'],source_sha256=closure,frequency=frequency,
        deadline=deadline,failure=failure,launch=launch,fixture=fixture_result,
        native=text,native_status=status,native_sha256=digest,
        actor_atomic=api.atomic_job_requested is True)
    launcher.write_private_bytes(stage/'dns-worker-report.json',encode(report));return 0
def run_local(actor,manifest,ah,mh,work_parent,plan_path,*,approved=False):
    v=blank('runtime');phase='inputs';launched=False
    try:
        require(approved);api=local.LocalNativeAPI();f=api.qpc_frequency();start=api.qpc();budget=launcher.QpcBudget(api,start+120*f,f)
        pre=preflight(actor,manifest,ah,mh,work_parent,plan_path,api=api)
        for key in ('checks','source_sha256','actor_sha256','manifest_sha256','recovery_plan_sha256'):v[key]=pre[key]
        if pre['status']!='ready':phase=pre['failure'];raise ValueError('preflight')
        files,hashes,closure=snapshot();require(closure==v['source_sha256'])
        parent=local.ordinary(api);run=secrets.token_hex(16);actor_run=secrets.token_hex(16)
        stage=Path(work_parent)/('local-dns-v1-'+run);phase='staging';v['tree_retained']=True
        api.private_directory(stage,parent['sid'])
        for name,raw in files.items():
            path=stage/name;path.parent.mkdir(parents=True,exist_ok=True);launcher.write_private_bytes(path,raw)
        for name in NATIVE:
            path=stage/NATIVE[name];path.parent.mkdir(parents=True,exist_ok=True);launcher.write_private_bytes(path,local.bounded(ROOT/NATIVE[name],256*1024))
        native=stage/'native';native.mkdir();launcher.write_private_bytes(native/ACTOR,local.bounded(actor,8*1024*1024));launcher.write_private_bytes(native/MANIFEST,local.bounded(manifest,8192))
        artifact(native/ACTOR,native/MANIFEST,ah,mh,stage)
        api.worker_job_name='Local\\RuleProxy.LocalGuard.'+run;api.worker_sid=parent['sid']
        config=dict(schema_version=1,run=run,actor_run=actor_run,frequency=f,deadline=budget.cutoff(5),source_sha256=closure,
            source_hashes=hashes,actor_sha256=ah,manifest_sha256=mh,device_sha256=api.device_sha256(),guard_job_name=api.worker_job_name)
        launcher.write_private_bytes(stage/'dns-config.json',encode(config))
        plan_raw=local.bounded(plan_path,8192);require(sha(plan_raw)==v['recovery_plan_sha256'])
        launcher.write_private_bytes(stage/'recovery-plan.json',plan_raw)
        guard=stage/'guard';guard.mkdir();(guard/'temp').mkdir();phase='deadline';budget.require_ms(budget.cutoff(40))
        require(snapshot()[2]==closure);phase='worker';launched=True;v['recovery_required']=True
        launch=launcher.launch_owned(api,[sys.executable,'-I','-S','-B',str(stage/'.github/windows_identity_dns_v1_local.py'),
            '--owned-worker','--config',str(stage/'dns-config.json')],guard,parent,parent,qpc_budget=budget,
            work_cutoff=budget.cutoff(3),cleanup_cutoff=budget.deadline)
        c=v['checks'];c.update(guard_atomic=api.atomic_job_requested is True,worker_held=launch.get('native_identity_verified_before_resume') is True,
            worker_exit=launch.get('cleanup',{}).get('process_exit_confirmed') is True,outer_cleanup=local.guest.cleanup_verified(launch))
        require(c['worker_exit']);phase='report';report=local.guest.decode(local.bounded(stage/'dns-worker-report.json',128*1024))
        require(set(report)=={'schema_version','run','actor_run','worker_pid','worker_sid','source_sha256','frequency','deadline','failure','launch','fixture','native','native_status','native_sha256','actor_atomic'})
        require(type(report['schema_version']) is int and report['schema_version']==1 and report['run']==run and report['actor_run']==actor_run and report['source_sha256']==closure
            and report['frequency']==f and report['deadline']==config['deadline'] and type(report['worker_pid']) is int
            and report['worker_pid']==launch.get('child_pid') and report['worker_sid']==parent['sid']);c['worker_report_bound']=True
        fixture=report['fixture']
        if fixture is not None:
            observed=receiver_projection(fixture)
            c['fixture_cleanup']=fixture['cleanup_confirmed'] is True
            v['fixture']=observed
            # Sticky independent receiver positive precedes native parsing.
            v['owned_query_observed']=observed['query_observed']
            v['network_tested']=v['owned_query_observed']
        al=report['launch'];c['actor_atomic']=report['actor_atomic'] is True
        if al is not None:
            c.update(actor_held=al.get('native_identity_verified_before_resume') is True,
                actor_exit=al.get('cleanup',{}).get('process_exit_confirmed') is True,actor_cleanup=local.guest.cleanup_verified(al))
        v['recovery_required']=not(c['outer_cleanup'] and c['actor_cleanup'] and c['fixture_cleanup'])
        if report['native'] is not None:
            require(report['native_status']=='ascii' and report['native_sha256']==sha(report['native'].encode('ascii')))
            v['api']=native_projection(local.guest.decode(report['native'].encode('ascii')),actor_run,f,config['deadline']-15*f,
                None if al is None else al.get('child_pid'),parent['sid'])
        phase='cleanup';v['recovery_required']=not(c['outer_cleanup'] and c['actor_cleanup'] and c['fixture_cleanup'])
        require(not v['recovery_required'] and all(c.values()) and launch_ok(launch) and launch_ok(al) and report['failure'] is None)
        phase='mechanism';r=v['api'];require(r is not None and r['answer_match'] and r['within_deadline'] and r['records_released'] and not r['pending']
            and v['owned_query_observed'] and v['fixture']['answers_sent']>0 and v['fixture']['error']=='none')
        v.update(status='passed',mechanism_passed=True)
    except BaseException:
        v['failure']=phase
        if launched and not v['checks']['worker_report_bound']:v['recovery_required']=True
    return validate(v)
def main(argv=None):
    p=argparse.ArgumentParser(description=__doc__)
    p.add_argument('--run-local-mechanism',action='store_true');p.add_argument('--approved-local-security-test',action='store_true')
    p.add_argument('--owned-worker',action='store_true',help=argparse.SUPPRESS);p.add_argument('--config',help=argparse.SUPPRESS)
    for name in ('actor','manifest','actor-sha256','manifest-sha256','work-parent','recovery-plan'):p.add_argument('--'+name)
    args=p.parse_args(argv)
    if args.owned_worker:
        try:return worker(args.config)
        except BaseException:return 1
    values=(args.actor,args.manifest,args.actor_sha256,args.manifest_sha256,args.work_parent,args.recovery_plan)
    result=run_local(*values,approved=args.approved_local_security_test) if args.run_local_mechanism else preflight(*values)
    sys.stdout.write(encode(result).decode('ascii'));return 0 if result['status'] in ('ready','passed') else 1
if __name__=='__main__':raise SystemExit(main())
