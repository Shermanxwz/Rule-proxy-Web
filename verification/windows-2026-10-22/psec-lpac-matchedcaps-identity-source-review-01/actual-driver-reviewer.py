"""File-only runner/capture review. Do not import or execute the actual runner."""
import ast
import hashlib
import json
from pathlib import Path
import subprocess

BASE=Path(__file__).resolve().parent
ROOT=BASE/'Rule-proxy-Web'
COMMIT='ec45dffb66cc88bb48578101afb93ce7044a6521'


def need(ok,label):
    if not ok:raise ValueError(label)
def sha(raw):return hashlib.sha256(raw).hexdigest()
def pin(path):
    raw=path.read_bytes();return dict(name=path.name,bytes=len(raw),sha256=sha(raw))
def git(path):return subprocess.check_output(['git','show',COMMIT+':'+path],cwd=ROOT)


def main():
    driver=BASE/'run_psec_lpac_matchedcaps_identity_01.py';raw=driver.read_bytes()
    need(len(raw)==5733 and sha(raw)=='925ee06bf2f0e0e525e14c31a901166b471349158808315b42cba64b1b60579b','driver_pin')
    tree=ast.parse(raw);text=raw.decode()
    reference=next(ast.literal_eval(node.value) for node in ast.walk(tree) if isinstance(node,ast.Assign)
        and any(isinstance(target,ast.Name) and target.id=='reference' for target in node.targets))
    need(type(reference) is str and len(reference)==473,'473_reference')
    code=(ROOT/'.github/windows_identity_psec_lpac_matchedcaps_bridge.py').read_bytes()
    local=(ROOT/'.github/windows_identity_psec_lpac_matchedcaps_bridge_local.py').read_bytes()
    need(code==git('.github/windows_identity_psec_lpac_matchedcaps_bridge.py')
        and local==git('.github/windows_identity_psec_lpac_matchedcaps_bridge_local.py'),'committed_entries')
    need(b"NONCES=('run','bootstrap_nonce','ac_nonce','lpac_nonce')" in code
        and b"DLL='windows_psec_lpac_matchedcaps_bridge.dll'" in code
        and b"require(self.dll.pb_abi_version()==3" in code,'no_legacy_ABI_fallback')
    need("module.core.api_version()==3" in text and 'len(set(nonces.values()))==4' in text
        and 'bootstrap_security_capabilities_acknowledged=True,same_security_capabilities_acknowledged=True' in text,'ABI3_four_nonces_acks')
    freeze=json.loads((BASE/'psec-lpac-matchedcaps-python-candidate-freeze-03.json').read_bytes())
    for path,expected in freeze['source_hashes'].items():
        data=(ROOT/path).read_bytes();need(sha(data)==expected and git(path)==data,'source36_git_exact')
    manifest=json.loads((BASE/'psec-lpac-matchedcaps-bridge-compile-01/psec-lpac-matchedcaps-bridge-manifest.json').read_bytes())
    for path,expected in {**manifest['sources'],**manifest['dependencies']}.items():
        data=(ROOT/path).read_bytes();need(sha(data)==expected and git(path)==data
            and data==(BASE/'psec-lpac-matchedcaps-bridge-compile-01/src'/path).read_bytes(),'native37_git_exact')
    for literal in ('f77fdff1de75ba53d6dca04d65659deb43fd6bdc91c2feaf1c6a03ade7c008db',
        '91e9fdc092943ac3a3b47c9f5ad394f4aacb522d105aa802c47b74d5c4f702b1',
        'fbbb268bde396dbe7bbdf7247f062bd2e1892f537f5e553a5ee105d1b52566d7',
        '0a9e867cce846b366693e8662034db8c0c4646bd312a6143c367da2c36fb557a',
        '657c88ef59f8ba9d4c24f5e407696b27615f50c63d58adc5d8dd64f942104e92',
        '83d1a458fc056d4d20931019dffb384a33bcdfd1c6759070b0885c5577dd44db'):
        need(literal in text,'explicit_artifact_pin')
    need(text.count('module.run_local(*args,approved=True)')==1 and not any(isinstance(node,ast.While) for node in ast.walk(tree)),'one_call_no_retry')
    need('raw=module.core.spec.build(str(stage/\'inputs\'))' in text and 'spec_sha256=sha(raw)' in text
        and 'head==sys.argv[1]' in text and 'for name in module.SOURCES:' in text,'plan_source_spec_gate')
    need(b'start=api.qpc();deadline=start+120*f;budget=launcher.QpcBudget(api,deadline,f)' in local
        and b'root_deadline_qpc=deadline,deadline_qpc=deadline-5*f' in local,'original_120_115')
    capture=BASE/'psec_lpac_matchedcaps_identity_capture_01.ps1';cr=capture.read_bytes()
    need(sha(cr).startswith('5f40e082'),'capture_expected_prefix')
    baseline=BASE/'c_local_baseline.ps1';br=baseline.read_bytes();body=br.decode('utf-8-sig')
    for command in ('Get-NetFirewallProfile','Get-DnsClientServerAddress','Get-NetRoute','Get-ItemProperty'):
        need(command in body,'four_readonly_sources')
    need('NrptIncluded=$false' in cr.decode() and 'NRPT' not in body.upper()
        and all(x not in body for x in ('Set-Net','New-Net','Remove-Net','Set-ItemProperty','Remove-ItemProperty')),'no_NRPT_or_global_mutation')
    value=dict(schema_version=1,stage='matchedcaps-driver01-independent-file-review',verdict='GO for one explicitly source-bound identity-only run by root',
        source_commit=COMMIT,driver=pin(driver),reviewed_predecessor_driver=pin(BASE/'run_psec_lpac_postassign_identity_01.py'),
        capture=pin(capture),capture_baseline_reader=pin(baseline),
        facts=dict(runtime_source_count=36,native_compile_input_count=37,all_runtime_and_native_current_bytes_equal_Git=True,
            library_ABI=3,original_root_seconds=120,worker_seconds=115,fresh_nonces=4,new_explicit_acknowledgements=2,
            recovery_reference_characters=473,one_CPSE_run_local_call=True,no_retry_or_old_DLL_fallback=True,
            same_actor07=True,all_three_actor_never_resume=True,
            global_capture_configuration_objects=4,NRPT_in_global_capture=False),
        review='Compared full runner with the previously reviewed postassign driver. Changes bind new module/stage/artifacts/ABI3/runtime closure, four nonces, bootstrap and same-SC acknowledgements and finite hypothesis text. Original source/Git/spec/device/PE/plan/preflight/held owner and once-cleanup gates remain in source.',
        actions=dict(driver_executed=False,capture_executed=False,compiler_executed=False,DLL_loaded=False,native_API_called=False,network_executed=False,main_modified=False),
        limits='This is pre-execution readiness, not a successful identity observation. SC acceptance, LPAC masks, CPSE network/FS association and cleanup remain runtime facts; earlier failures/unknowns/DNS leak are not rewritten.')
    data=(json.dumps(value,sort_keys=True,ensure_ascii=False,indent=2)+'\n').encode()
    with (BASE/'psec-lpac-matchedcaps-driver-independent-review-01.json').open('xb') as stream:stream.write(data)
    print(json.dumps(dict(verdict='GO',bytes=len(data),sha256=sha(data),driver_executed=False)))


if __name__=='__main__':main()
