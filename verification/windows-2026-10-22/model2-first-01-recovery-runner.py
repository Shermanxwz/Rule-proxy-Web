"""Exact C01 profile/ACE recovery only. Never launches G or a network actor."""
import ctypes as C
import hashlib
import importlib.util
import json
from pathlib import Path
import secrets
import stat
import sys

def load(target):
    spec=importlib.util.spec_from_file_location('c01_exact_recovery_owner',target/'.github/windows_identity_model2_local.py')
    m=importlib.util.module_from_spec(spec);spec.loader.exec_module(m);return m
def digest(raw):return hashlib.sha256(raw).hexdigest()
def tree(root):
    pending=[root];result=[];size=0
    while pending:
        path=pending.pop();item=path.lstat()
        assert not stat.S_ISLNK(item.st_mode) and not getattr(item,'st_file_attributes',0)&0x400
        assert path==root or root in path.parents
        assert len(path.relative_to(root).parts)<=16
        result.append(path);assert len(result)<=512
        if stat.S_ISDIR(item.st_mode):pending.extend(path.iterdir())
        else:
            assert stat.S_ISREG(item.st_mode);size+=item.st_size;assert size<=128*1024*1024
    return result
def absent_job(api,name):
    api.k.OpenJobObjectW.argtypes=[C.c_uint32,C.c_int,C.c_wchar_p];api.k.OpenJobObjectW.restype=C.c_void_p
    C.set_last_error(0);handle=api.k.OpenJobObjectW(4,False,name);error=C.get_last_error()
    if handle:
        api.close(handle)
        raise RuntimeError('old Job still exists; refuse recovery')
    assert error==2
def worker(config_path):
    config_path=Path(config_path).resolve();recovery=config_path.parent
    cfg=json.loads(config_path.read_bytes());target=Path(cfg['target']);repo=Path(cfg['repo'])
    assert target.parent==repo/'private' and target.name=='local-model2-'+cfg['original_run']
    assert digest(Path(__file__).read_bytes())==cfg['worker_sha256']
    m=load(target);api=m.local.LocalNativeAPI();parent=m.local.ordinary(api)
    m.local.verify_guard_job(api,cfg['guard_job'])
    assert api.device_sha256()==cfg['device_sha256'] and cfg['frequency']==api.qpc_frequency()
    budget=m.launcher.QpcBudget(api,cfg['deadline'],cfg['frequency']);budget.require_ms(budget.cutoff(20))
    original=json.loads((target/'model2-config.json').read_bytes())
    _,hashes,closure=m.live.source_snapshot(target)
    assert hashes==original['source_hashes'] and closure==original['source_sha256']==cfg['original_closure']
    private_raw=(target/'model2-ownership-private.json').read_bytes();assert digest(private_raw)==cfg['journal_sha256']
    journal=json.loads(private_raw)
    assert journal['run']==original['run'] and journal['rules'] is None
    assert journal['cleanup']['all_workloads_exited'] and journal['cleanup']['workload_job_empty']
    assert journal['cleanup']['workload_cleanup_confirmed'] and journal['cleanup']['maintenance_cleanup_confirmed']
    assert journal['cleanup']['maintenance_handles_closed'] and journal['maintenance']['admitted']
    assert journal['maintenance']['exited'] and journal['maintenance']['exit_code']==0
    assert set(row['role'] for row in journal['tasks'])=={'origin','health','acl-root','acl-inputs','acl-front'}
    assert not list(target.glob('rule-*.json'))
    commands=[]
    for path in (target/'maintenance').glob('command-*.json'):
        commands.append(json.loads(path.read_bytes())['operation'])
    assert sorted(commands)==['admit','finish']
    absent_job(api,original['guard_job_name'])
    absent_job(api,'Local\\RuleProxy.LocalGuard.'+original['maintenance_nonce'])
    plan=json.loads((target/'maintenance-plan.json').read_bytes());assert len(plan['rules'])==1
    sid=plan['rules'][0]['package_sid'];name='RuleProxy.Model2.A.'+original['run']
    live_api=m.live.LiveNativeAPI();assert live_api.derive_profile_sid(name)==sid
    paths=tree(target)
    for path in paths:
        expected=([(0,0x1200a9)] if path==target else [(3,0x1200a9)] if path==target/'inputs'
            else [(3,0x1301bf)] if path==target/'front' else [(16,0x1200a9)] if path.parent==target/'inputs'
            else [(16,0x1301bf)] if target/'front' in path.parents else [])
        assert live_api.acl_read(path,sid)==expected
    # Only the exact owned package SID ACE is removed, within the verified tree.
    block=api.environment(recovery)
    env=dict(x.split('=',1) for x in block.rstrip('\0').split('\0'))
    exe=m.launcher.checked_path(Path(env['SystemRoot'])/'System32/icacls.exe')
    tool_hash=digest(m.local.bounded(exe,8*1024*1024))
    tool_api=m.local.LocalNativeAPI();tool_api.worker_job_name='Local\\RuleProxy.LocalGuard.'+cfg['tool_nonce'];tool_api.worker_sid=parent['sid']
    work=recovery/'tool';work.mkdir();(work/'temp').mkdir()
    launch=m.launcher.launch_owned(tool_api,[str(exe),str(target),'/remove:g','*'+sid,'/T','/Q'],work,parent,parent,
        qpc_budget=budget,work_cutoff=budget.cutoff(10),cleanup_cutoff=budget.cutoff(5))
    assert tool_api.atomic_job_requested and m.local.guest.cleanup_verified(launch)
    assert launch.get('native_identity_verified_before_resume') and launch.get('resumed') and launch.get('exit_code')==0
    assert launch.get('timed_out') is False and 'error' not in launch and digest(m.local.bounded(exe,8*1024*1024))==tool_hash
    for path in tree(target):
        budget.require_ms(budget.cutoff(3));assert live_api.acl_read(path,sid)==[]
    budget.require_ms(budget.cutoff(2));live_api.delete_profile(name)
    record=dict(schema_version=1,stage='model2-exact-profile-recovery',worker_pid=__import__('os').getpid(),
        original_journal_sha256=cfg['journal_sha256'],original_source_sha256=closure,
        source_verified=True,old_jobs_absent=True,no_rule_attempted=True,tool_held_and_clean=True,
        all_exact_sid_aces_absent=True,owned_profile_deleted=True,network_actor_run=False)
    m.launcher.write_private_bytes(recovery/'worker-report.json',m.live.encode(record))
    m.launcher.write_private_bytes(target/'exact-recovery-01-private.json',m.live.encode(record))
    return 0
def guard():
    base=Path(__file__).resolve().parent;repo=base/'Rule-proxy-Web'
    public=json.loads((repo/'verification/windows-2026-10-22/model2-first-01-public.json').read_bytes())
    assert public['cleanup']['outer_cleanup_verified'] and public['cleanup']['controller_exit_verified']
    stages=[]
    for target in (repo/'private').glob('local-model2-*'):
        path=target/'model2-config.json'
        if path.is_file():
            c=json.loads(path.read_bytes())
            if digest(c['run'].encode())==public['result']['run_sha256']:stages.append((target,c))
    assert len(stages)==1;target,original=stages[0]
    m=load(target);api=m.local.LocalNativeAPI();parent=m.local.ordinary(api)
    f,start=api.qpc_frequency(),api.qpc();budget=m.launcher.QpcBudget(api,start+120*f,f)
    run=secrets.token_hex(16);recovery=repo/'private'/('model2-exact-recovery-'+run)
    api.private_directory(recovery,parent['sid'])
    raw=Path(__file__).read_bytes();m.launcher.write_private_bytes(recovery/'recovery.py',raw)
    cfg=dict(repo=str(repo),target=str(target),original_run=original['run'],original_closure=original['source_sha256'],
        worker_sha256=digest(raw),journal_sha256=digest((target/'model2-ownership-private.json').read_bytes()),
        device_sha256=api.device_sha256(),frequency=f,deadline=budget.cutoff(5),guard_job='Local\\RuleProxy.LocalGuard.'+run,
        tool_nonce=secrets.token_hex(16))
    m.launcher.write_private_bytes(recovery/'config.json',m.live.encode(cfg));work=recovery/'guard';work.mkdir();(work/'temp').mkdir()
    api.worker_job_name=cfg['guard_job'];api.worker_sid=parent['sid']
    launch=m.launcher.launch_owned(api,[sys.executable,'-I','-S','-B',str(recovery/'recovery.py'),'--worker',str(recovery/'config.json')],
        work,parent,parent,qpc_budget=budget,work_cutoff=budget.cutoff(3),cleanup_cutoff=budget.deadline)
    good=api.atomic_job_requested and m.local.guest.cleanup_verified(launch) and launch.get('exit_code')==0 and not launch.get('timed_out') and 'error' not in launch
    report=None
    if (recovery/'worker-report.json').exists():
        report=json.loads((recovery/'worker-report.json').read_bytes());assert report.pop('worker_pid')==launch['child_pid']
    value=dict(schema_version=1,stage='model2-first-01-exact-recovery-public',passed=bool(good and report),
        worker_source_sha256=digest(raw),outer_cleanup_verified=m.local.guest.cleanup_verified(launch),result=report,
        original_result_sha256=digest((repo/'verification/windows-2026-10-22/model2-first-01-public.json').read_bytes()))
    with (repo/'verification/windows-2026-10-22/model2-first-01-recovery-public.json').open('xb') as out:out.write(m.live.encode(value))
    print(json.dumps(value,sort_keys=True));return 0 if value['passed'] else 1
if __name__=='__main__':
    raise SystemExit(worker(sys.argv[2]) if len(sys.argv)==3 and sys.argv[1]=='--worker' else guard())
