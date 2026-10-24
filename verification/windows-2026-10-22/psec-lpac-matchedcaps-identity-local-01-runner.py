"""One source-bound opt-in CPSE/LPAC held identity run. No automatic retry."""
import hashlib
import importlib.util
import json
from pathlib import Path
import secrets
import subprocess
import sys

BASE=Path(__file__).resolve().parent
REPO=BASE/'Rule-proxy-Web'
def need(ok,label):
    if not ok:raise ValueError(label)
def sha(raw):return hashlib.sha256(raw).hexdigest()
def write_new(path,raw):
    with path.open('xb') as stream:need(stream.write(raw)==len(raw),'write')
def git_blob(commit,name):return subprocess.check_output(['git','show',commit+':'+name],cwd=REPO)

def main():
    need(len(sys.argv)==2,'explicit_frozen_commit')
    head=subprocess.check_output(['git','rev-parse','HEAD'],cwd=REPO,text=True).strip()
    need(head==sys.argv[1] and len(head)==40,'exact_source_commit')
    entry='.github/windows_identity_psec_lpac_matchedcaps_bridge_local.py'
    need((REPO/entry).read_bytes()==git_blob(head,entry),'entry_git_bytes')
    loader=importlib.util.spec_from_file_location('cpse_matchedcaps_identity_actual01',REPO/entry)
    module=importlib.util.module_from_spec(loader);loader.loader.exec_module(module)
    need(module.core.ACTUAL_READY is True and len(module.SOURCES)==36,'reviewed_runtime_entry')
    for name in module.SOURCES:need((REPO/name).read_bytes()==git_blob(head,name),'runtime_git_bytes')
    _,_,closure=module.snapshot(REPO)
    need(closure=='f77fdff1de75ba53d6dca04d65659deb43fd6bdc91c2feaf1c6a03ade7c008db' and module.core.api_version()==3,'promoted_abi3_source_closure')
    build=BASE/'psec-lpac-matchedcaps-bridge-compile-01'
    dll=build/module.core.DLL;manifest=build/module.core.DLL_MANIFEST
    dh,mh=sha(dll.read_bytes()),sha(manifest.read_bytes())
    need(dh=='91e9fdc092943ac3a3b47c9f5ad394f4aacb522d105aa802c47b74d5c4f702b1','dll_hash')
    need(mh=='fbbb268bde396dbe7bbdf7247f062bd2e1892f537f5e553a5ee105d1b52566d7','dll_manifest_hash')
    manifest_value=module.decode(manifest.read_bytes())
    for name,digest in {**manifest_value['sources'],**manifest_value['dependencies']}.items():
        raw=(REPO/name).read_bytes();need(raw==git_blob(head,name) and sha(raw)==digest,'native_dependency_git_bytes')
        need(raw==(build/'src'/name).read_bytes(),'native_immutable_compile_bytes')
    artifact_dir=REPO/'private/psec-lpac-matchedcaps-bridge-compile01-actual01';artifact_dir.mkdir()
    for path in (dll,manifest):write_new(artifact_dir/path.name,path.read_bytes())
    dll,manifest=artifact_dir/dll.name,artifact_dir/manifest.name
    module.core.verify_manifest(dll,manifest,dh,mh,root=REPO)
    actor=BASE/'proxy-c-compile-07'/module.live.ACTOR
    actor_manifest=actor.with_name(module.live.MANIFEST)
    ah,amh=sha(actor.read_bytes()),sha(actor_manifest.read_bytes())
    need(ah=='0a9e867cce846b366693e8662034db8c0c4646bd312a6143c367da2c36fb557a','native07_actor')
    need(amh=='657c88ef59f8ba9d4c24f5e407696b27615f50c63d58adc5d8dd64f942104e92','native07_manifest')
    module.live.verify_actor(actor,actor_manifest,ah,amh,root=REPO)
    api=module.local.LocalNativeAPI();module.local.ordinary(api)
    model=module.core.NativeAPI.processmodel_path(api);modelh=sha(model.read_bytes())
    need(modelh=='83d1a458fc056d4d20931019dffb384a33bcdfd1c6759070b0885c5577dd44db','system32_processmodel')
    nonces={key:secrets.token_hex(16) for key in module.core.NONCES}
    need(len(set(nonces.values()))==4,'fresh_nonces')
    parent=REPO/'private';stage=parent/module.core.stage_name(nonces['run'])
    raw=module.core.spec.build(str(stage/'inputs'));module.core.spec.verify(raw,str(stage/'inputs'))
    spec_path=parent/'psec-lpac-matchedcaps-identity-spec-01.bin';write_new(spec_path,raw)
    reference='Three held actors in one CPSE; bootstrap primary supplies exact SID and Agentic/PNCS attrs4. Both measured arms use identical native-owned SECURITY_CAPABILITIES and same SE_ENV; only AAP0/1 differs. Each original PI requires outer-only guard, once inner Assign, then both Jobs before token. Never resume; all held through AccessCheck. Fixed120/115s, exact cleanup, VOID once. No network association/crash equivalence claim. Old01 unknown/DNS leak remain. No retry/fallback.'
    need(len(reference)<=512,'reference_bound')
    plan=dict(schema_version=1,scope=module.SCOPE,variant=module.core.VARIANT,**nonces,device_sha256=api.device_sha256(),
        source_sha256=closure,actor_sha256=ah,manifest_sha256=amh,dll_sha256=dh,dll_manifest_sha256=mh,
        constructor_policy=module.core.CONSTRUCTOR_POLICY,held_postassign_acknowledged=True,outer_guard_required_acknowledged=True,
        bootstrap_security_capabilities_acknowledged=True,same_security_capabilities_acknowledged=True,
        processmodel_sha256=modelh,spec_sha256=sha(raw),never_resume_acknowledged=True,
        deny_all_not_proxy_acknowledged=True,opaque_unknown_recovery_acknowledged=True,recovery_reference=reference)
    plan_path=parent/'psec-lpac-matchedcaps-identity-recovery-plan-01.json';write_new(plan_path,module.encode(plan))
    args=(actor,actor_manifest,ah,amh,dll,manifest,dh,mh,modelh,spec_path,plan_path,parent)
    evidence=REPO/'verification/windows-2026-10-22'
    pre=module.preflight(*args)
    write_new(evidence/'psec-lpac-matchedcaps-identity-local-01-preflight.json',module.encode(pre))
    need(pre['status']=='ready','preflight_'+str(pre['failure']))
    value=module.run_local(*args,approved=True)
    public=module.encode(value);write_new(evidence/'psec-lpac-matchedcaps-identity-local-01-public.json',public)
    print(json.dumps(dict(source_commit=head,source_sha256=closure,public_bytes=len(public),public_sha256=sha(public),result=value),sort_keys=True))
    return 0 if value['status']=='observed' else 1
if __name__=='__main__':raise SystemExit(main())
