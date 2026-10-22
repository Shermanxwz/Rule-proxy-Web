# ARCHIVE-SAFE REVIEW COPY. NOT THE EXECUTED BYTES.
# One private original-run nonce is redacted; this copy cannot perform the original recovery.
"""Exact LPAC01 profile recovery, only after no SID ACE and no old live tree."""
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
ORIGINAL_REPORT='993fd8e6c3200e69167eebb14ac4c95bdb7578ad99aa3adb464631101a149daa'
ORIGINAL_PUBLIC='a815d1b6a321e98c06048d95d983c845b7cc995e1fb216dfe1afe810ff2d75f6'
ORIGINAL_SOURCE='a1b924f5edee5b0e279fa14f35319ad9ee835c243696526e13e72a80b62bc792'
def sha(raw):return hashlib.sha256(raw).hexdigest()
def load(stage):
    # Authenticate every staged dependency using the fixed original receipt,
    # with stdlib only, BEFORE executing any staged Python source.
    report_raw=(stage/'worker-report.json').read_bytes();assert sha(report_raw)==ORIGINAL_REPORT
    report=json.loads(report_raw);config=json.loads((stage/'worker-config.json').read_bytes())
    assert report['config']==config and config['run']==ORIGINAL_RUN
    hashes=config['source_hashes'];assert type(hashes) is dict and len(hashes)==31
    assert sha((json.dumps(hashes,sort_keys=True,separators=(',',':'))+'\n').encode('ascii'))==ORIGINAL_SOURCE
    for name,digest in hashes.items():
        assert type(name) is str and not Path(name).is_absolute() and '..' not in Path(name).parts
        path=stage/name
        for item in (stage,*reversed(path.relative_to(stage).parents[:-1])):
            target=item if item==stage else stage/item
            value=target.lstat();assert not stat.S_ISLNK(value.st_mode) and not getattr(value,'st_file_attributes',0)&0x400
        value=path.lstat();assert stat.S_ISREG(value.st_mode) and not getattr(value,'st_file_attributes',0)&0x400 and value.st_size<=256*1024
        assert sha(path.read_bytes())==digest
    spec=importlib.util.spec_from_file_location('lpac01_recovery_source',stage/'.github/windows_identity_lpac_dns_local.py')
    module=importlib.util.module_from_spec(spec);spec.loader.exec_module(module);return module
def read(path):return json.loads(path.read_bytes())
def absent_job(api,name):
    api.k.OpenJobObjectW.argtypes=[C.c_uint32,C.c_int,C.c_wchar_p];api.k.OpenJobObjectW.restype=C.c_void_p
    C.set_last_error(0);handle=api.k.OpenJobObjectW(4,False,name);error=C.get_last_error()
    if handle:
        api.close(handle);raise ValueError('old Job still exists')
    assert error==2
def worker(config_path):
    config_path=Path(config_path).resolve();cfg=read(config_path);recovery=config_path.parent
    assert sha(Path(__file__).read_bytes())==cfg['worker_sha256']
    repo=Path(cfg['repo']);stage=Path(cfg['stage'])
    assert stage.parent==repo/'private' and stage.name=='local-lpac-'+ORIGINAL_RUN
    m=load(stage);api=m.local.LocalNativeAPI();parent=m.local.ordinary(api)
    m.local.verify_guard_job(api,cfg['guard_job'])
    assert cfg['device_sha256']==api.device_sha256() and cfg['frequency']==api.qpc_frequency()
    budget=m.launcher.QpcBudget(api,cfg['deadline'],cfg['frequency']);budget.require_ms(budget.cutoff(10))
    assert sha((stage/'worker-report.json').read_bytes())==ORIGINAL_REPORT
    report=read(stage/'worker-report.json');original=read(stage/'worker-config.json');j=report['result']
    assert report['config']==original and original['run']==ORIGINAL_RUN
    assert report['worker_identity']==parent and original['device_sha256']==cfg['device_sha256']
    _,hashes,closure=m.snapshot(stage)
    assert hashes==original['source_hashes'] and closure==original['source_sha256']==ORIGINAL_SOURCE
    assert original['actor_sha256']=='0a9e867cce846b366693e8662034db8c0c4646bd312a6143c367da2c36fb557a'
    assert original['manifest_sha256']=='657c88ef59f8ba9d4c24f5e407696b27615f50c63d58adc5d8dd64f942104e92'
    raw_public=(repo/'verification/windows-2026-10-22/lpac-dns-local-01-public.json').read_bytes()
    assert sha(raw_public)==ORIGINAL_PUBLIC;public=json.loads(raw_public)
    assert all(public['checks'][k] for k in ('guard','worker_exit','outer_cleanup','worker_bound','workload_cleanup','cleanup_tools','fixture_cleanup'))
    assert not public['network_tested'] and public['recovery_required']
    assert j['profile_created'] and j['acl_attempted'] and j['workload_cleanup'] and j['workload_job_empty'] and j['cleanup_tools']
    assert j['sid_released'] and not j['selected_lpac_held'] and j['native']==[] and j['go']==[]
    assert j['inventory'] is None and j['fixture_final'] is None and not j['selected_wire_query_observed']
    rows=j['tasks']+j['cleanup_tasks']
    assert [r['name'] for r in rows]==['grant-root','remove']
    assert all(r['attempted'] and r['process_returned'] and r['assigned'] and r['exited'] and r['exit_code']==1
        and not r['resumed'] and not r['admitted'] and r['resume_qpc'] is None for r in rows)
    assert sorted(p.name for p in (stage/'journal').iterdir())==[
        '00-profile-create.json','01-acl-grant.json','02-spawn-grant-root.json','03-acl-remove.json','04-spawn-remove.json']
    absent_job(api,original['guard_job_name'])
    native=m.LPACAPI();sid=j['profile_sid'];name=j['profile_name']
    assert name=='ruleproxy-lpac-'+ORIGINAL_RUN and native.derive_profile_sid(name)==sid
    for row in rows:
        handle=native.k.OpenProcess(0x101000,False,row['pid'])
        if handle:
            try:assert native.creation_time(handle)!=row['created'] or native.wait(handle,0)
            finally:native.close(handle)
        else:assert C.get_last_error()==87
    paths=m.owned_tree(stage)
    for path in paths:
        budget.require_ms(budget.cutoff(5));assert native.acl_read(path,sid)==[]
    intent=dict(schema_version=1,action='delete-exact-original-owned-profile',original_report_sha256=ORIGINAL_REPORT,
        original_source_sha256=closure,profile_name=name,profile_sid=sid,all_exact_sid_aces_absent=True,
        old_outer_job_absent=True,all_old_task_generations_exited=True,qpc=api.qpc(),deadline=cfg['deadline'])
    m.durable_private(recovery/'delete-intent.json',m.encode(intent))
    budget.require_ms(budget.cutoff(3));native.delete_profile(name)
    record=dict(schema_version=1,stage='lpac-dns-01-exact-profile-recovery',worker_pid=os.getpid(),
        original_report_sha256=ORIGINAL_REPORT,original_public_sha256=ORIGINAL_PUBLIC,original_source_sha256=closure,
        source_verified=True,old_outer_job_absent=True,all_old_task_generations_exited=True,
        no_original_tool_resumed=True,all_exact_sid_aces_absent=True,acl_remove_tool_needed=False,
        profile_delete_returned_success=True,network_actor_run=False,network_query_run=False)
    m.durable_private(recovery/'worker-report.json',m.encode(record))
    m.durable_private(stage/'exact-recovery-01-private.json',m.encode(record));budget.require_ms(cfg['deadline'])
    return 0
def guard():
    base=Path(__file__).resolve().parent;repo=base/'Rule-proxy-Web';stage=repo/'private'/('local-lpac-'+ORIGINAL_RUN)
    m=load(stage);api=m.local.LocalNativeAPI();parent=m.local.ordinary(api)
    original=read(stage/'worker-config.json');assert original['device_sha256']==api.device_sha256()
    f,start=api.qpc_frequency(),api.qpc();budget=m.launcher.QpcBudget(api,start+120*f,f)
    nonce=secrets.token_hex(16);recovery=repo/'private'/('lpac-exact-recovery-'+nonce);api.private_directory(recovery,parent['sid'])
    raw=Path(__file__).read_bytes();m.durable_private(recovery/'recovery.py',raw)
    cfg=dict(repo=str(repo),stage=str(stage),worker_sha256=sha(raw),device_sha256=api.device_sha256(),frequency=f,
        deadline=budget.cutoff(5),guard_job='Local\\RuleProxy.LocalGuard.'+nonce)
    m.durable_private(recovery/'config.json',m.encode(cfg));work=recovery/'guard';work.mkdir();(work/'temp').mkdir()
    api.worker_job_name=cfg['guard_job'];api.worker_sid=parent['sid']
    launch=m.launcher.launch_owned(api,[sys.executable,'-I','-S','-B',str(recovery/'recovery.py'),'--worker',str(recovery/'config.json')],
        work,parent,parent,qpc_budget=budget,work_cutoff=budget.cutoff(3),cleanup_cutoff=budget.deadline)
    m.durable_private(recovery/'launch.json',m.encode(launch))
    report=None
    if (recovery/'worker-report.json').is_file():
        report=read(recovery/'worker-report.json');assert report.pop('worker_pid')==launch['child_pid']
        expected=dict(schema_version=1,stage='lpac-dns-01-exact-profile-recovery',original_report_sha256=ORIGINAL_REPORT,
            original_public_sha256=ORIGINAL_PUBLIC,original_source_sha256=ORIGINAL_SOURCE,source_verified=True,
            old_outer_job_absent=True,all_old_task_generations_exited=True,no_original_tool_resumed=True,
            all_exact_sid_aces_absent=True,acl_remove_tool_needed=False,profile_delete_returned_success=True,
            network_actor_run=False,network_query_run=False)
        assert report==expected and all(type(report[k]) is type(value) for k,value in expected.items())
    good=bool(api.atomic_job_requested and m.local.guest.cleanup_verified(launch) and launch.get('native_identity_verified_before_resume')
        and launch.get('resumed') and launch.get('exit_code')==0 and launch.get('timed_out') is False and 'error' not in launch and report)
    value=dict(schema_version=1,stage='lpac-dns-local-01-exact-recovery-public',passed=good,worker_source_sha256=sha(raw),
        original_public_sha256=ORIGINAL_PUBLIC,outer_cleanup_verified=m.local.guest.cleanup_verified(launch),result=report)
    with (repo/'verification/windows-2026-10-22/lpac-dns-local-01-recovery-public.json').open('xb') as stream:stream.write(m.encode(value))
    print(json.dumps(value,sort_keys=True));return 0 if good else 1
if __name__=='__main__':raise SystemExit(worker(sys.argv[2]) if len(sys.argv)==3 and sys.argv[1]=='--worker' else guard())
