"""Candidate only: one ordinary read-only helper under the established Job guard.

Only helper-internal code excludes Winsock initialization. Importing the existing
parent guard's dependency chain may initialize CPython socket/WSA state; this
wrapper creates no SOCKET or network I/O and changes no global network policy.
"""
import hashlib
import importlib.util
import json
from pathlib import Path
import secrets
import subprocess
import sys
W=Path(__file__).resolve().parent;R=W/'Rule-proxy-Web'
EXPECTED_HELPER='73bba54b6fb35fe7e8f8d6008849dc21b4de9aa6a87cfcfd45c96431501e2e89'
HELPER='read_afd_device_dacl_readonly_01.py'
def need(ok,label):
    if not ok:raise ValueError(label)
def sha(raw):return hashlib.sha256(raw).hexdigest()
def put(p,raw):
    with p.open('xb') as f:need(f.write(raw)==len(raw),'fresh exact write')
def main():
    need(len(EXPECTED_HELPER)==64,'helper independent review pending')
    helper=W/HELPER;raw=helper.read_bytes();need(sha(raw)==EXPECTED_HELPER,'fixed reviewed helper')
    freeze=(W/'registry-read-loopback-python-candidate-freeze-02.json').read_bytes()
    need(sha(freeze)=='48f4f10b020b78754511e1ba6c0db8dca59f5257aab6ce5e78288f391be46bac','fixed source closure freeze')
    q=json.loads(freeze);need(len(q['source_hashes'])==37,'source closure37')
    source_commit='d309ae322cca84360923d6bc51013057991a4218'
    for name,digest in q['source_hashes'].items():
        b=(R/name).read_bytes();need(sha(b)==digest and b==subprocess.check_output(['git','show',source_commit+':'+name],cwd=R),'unchanged Git source before import')
    spec=importlib.util.spec_from_file_location('root_afd_readonly_guard',R/'.github/windows_identity_lpac_registry_loopback_local.py')
    m=importlib.util.module_from_spec(spec);spec.loader.exec_module(m)
    api=m.local.LocalNativeAPI();f=api.qpc_frequency();start=api.qpc();end=start+20*f;work_end=start+15*f
    budget=m.launcher.QpcBudget(api,end,f);parent=m.local.ordinary(api);budget.require_ms(work_end)
    stage=W/'afd-device-readonly-supervision-01';need(not stage.exists(),'fresh diagnostic supervision stage')
    api.private_directory(stage,parent['sid']);guard=stage/'guard';api.private_directory(guard,parent['sid']);(guard/'temp').mkdir()
    api.worker_job_name='Local\\RuleProxy.LocalGuard.'+secrets.token_hex(16);api.worker_sid=parent['sid']
    # Root replaces this argument list only after the helper CLI is frozen.
    command=[str(Path(sys.executable).resolve()),'-I','-S','-B',str(helper),'--query-afd-dacl','--deadline-qpc',str(work_end),'--frequency',str(f)]
    need('PENDING-CLI' not in command,'helper exact CLI review pending')
    launch=m.launcher.launch_owned(api,command,guard,parent,parent,qpc_budget=budget,work_cutoff=work_end,cleanup_cutoff=end)
    put(stage/'outer-launch-report.json',m.encode(launch))
    need(helper.read_bytes()==raw,'helper source unchanged after original process')
    for name,digest in q['source_hashes'].items():
        need(sha((R/name).read_bytes())==digest,'shared source unchanged after original process')
    observation_path=W/'afd-device-dacl-readonly-01.json'
    observation=None;observation_meta=None
    if observation_path.exists():
        need(not observation_path.is_symlink() and 0<observation_path.stat().st_size<=65536,'bounded diagnostic observation')
        observation_raw=observation_path.read_bytes();observation=json.loads(observation_raw)
        need(observation['helper_sha256']==EXPECTED_HELPER and observation['deadline_qpc']==work_end
            and observation['frequency']==f,'original helper and clock binding')
        observation_meta=dict(bytes=len(observation_raw),sha256=sha(observation_raw))
    result=dict(schema_version=1,stage='ordinary-afd-device-readonly-supervision',helper_sha256=EXPECTED_HELPER,
        source_commit=source_commit,source_sha256=q['source_sha256'],source_count=37,
        atomic_job_requested=api.atomic_job_requested,ordinary_identity_verified_before_resume=launch.get('native_identity_verified_before_resume') is True,
        started=launch.get('started'),resumed=launch.get('resumed'),exit_code=launch.get('exit_code'),timed_out=launch.get('timed_out'),
        original_budget_seconds=20,original_work_seconds=15,outer_cleanup=m.local.guest.cleanup_verified(launch),
        launch=launch,observation=observation,observation_meta=observation_meta,parent_dependency_import_may_initialize_WSA=True,no_SOCKET_or_network_IO_requested=True,
        global_network_policy_changed=False,application_isolation_test=False,product_acceptance=False,linux_equivalence_proven=False)
    out=m.encode(result);put(W/'afd-device-readonly-supervision-01.json',out)
    print(json.dumps(dict(report_bytes=len(out),report_sha256=sha(out),atomic_job_requested=result['atomic_job_requested'],
        ordinary_identity_verified_before_resume=result['ordinary_identity_verified_before_resume'],outer_cleanup=result['outer_cleanup'],
        exit_code=result['exit_code'],timed_out=result['timed_out'])))
if __name__=='__main__':main()
