"""Synthetic file-only Python builder/official flatc interoperability check."""
import hashlib
import importlib.util
import json
from pathlib import Path
import subprocess

BASE=Path(__file__).resolve().parent
def need(ok,label):
    if not ok:raise ValueError(label)
def sha(raw):return hashlib.sha256(raw).hexdigest()
def main():
    candidate=BASE/'psec-lpac-identity-bridge-candidate'
    source=candidate/'.github/windows_identity_psec_spec.py';before=source.read_bytes()
    loader=importlib.util.spec_from_file_location('pure_spec_flatc_check',source)
    module=importlib.util.module_from_spec(loader);loader.loader.exec_module(module)
    tool=BASE/'psec-lpac-bridge-deps/flatc.exe';need(sha(tool.read_bytes())=='eddf0ca8ab85003151a895faabc99e9a7c02c8b4ea4d421fd5725a7a0c34ca8c','fixed_flatc')
    schema=candidate/'vendor/windows-sdk/ProcessSecurityEnvironment.fbs'
    need(sha(schema.read_bytes())=='736cacef37a6c97a0cb97c7132da462a3b51811fca8f1e4076cac51085dfa516','fixed_schema')
    output=BASE/'psec-python-spec-flatc-01';output.mkdir()
    path=r'C:\RuleProxyProof\synthetic\inputs';raw=module.build(path);proof=module.verify(raw,path)
    binary=output/'synthetic-spec.bin';binary.write_bytes(raw)
    command=[str(tool),'--json','--strict-json','--defaults-json','-o',str(output),str(schema),'--',str(binary)]
    result=subprocess.run(command,capture_output=True,timeout=30)
    (output/'flatc-stdout.bin').write_bytes(result.stdout);(output/'flatc-stderr.bin').write_bytes(result.stderr)
    need(result.returncode==0,'flatc_decode_exit')
    decoded=(output/'synthetic-spec.json').read_bytes();value=json.loads(decoded)
    expected=dict(version=dict(major=1,minor=1),capabilities='privateNetworkClientServer',disallow_win32k_system_calls=True,
        ui_restrictions=1023,fs_read_only=[path],network_policy=dict(egress=dict(default_action='deny'),
        ingress=dict(default_action='deny',host_loopback='deny')))
    need(value==expected,'official_decoded_semantics');need(source.read_bytes()==before,'builder_stable')
    receipt=dict(schema_version=1,stage='pure-python-spec-official-flatc-cross-language-file-decode',
        builder_sha256=sha(before),schema_sha256=sha(schema.read_bytes()),flatc_sha256=sha(tool.read_bytes()),
        flatc_version='25.12.19',raw_spec_bytes=len(raw),raw_spec_sha256=sha(raw),decoded_json_sha256=sha(decoded),
        decoded_semantics_match=True,python_independent_reader_accepted=bool(proof),flatc_exit_code=result.returncode,
        dll_loaded=False,processmodel_called=False,actor_executed=False,network_executed=False,
        limits='Synthetic path only. Tests byte-layout interoperability and schema decoding, not CPSE acceptance or policy enforcement.')
    report=(json.dumps(receipt,sort_keys=True,indent=2)+'\n').encode('ascii');(output/'receipt.json').write_bytes(report)
    print(json.dumps(receipt,sort_keys=True))
if __name__=='__main__':main()
