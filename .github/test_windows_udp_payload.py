"""Inert ZIP writer fixtures, not authenticated or executable runtime artifacts."""
import argparse
import hashlib
import importlib.util
import io
import json
from pathlib import Path
import sys
import zipfile
from unittest.mock import patch
ROOT=Path(__file__).resolve().parents[1]
FORBIDDEN=('udp/TEST_ONLY.exe','capture.pcap','private-udp/runner-flow.json','.github/windows_n0a_udp_host.py')
PARENT_FORBIDDEN=('parent/TEST_ONLY.exe','capture.pcap','private-parent-udp/runner-flow.json','.github/windows_n0a_udp_parent_host.py')
def generate(root):
    root=Path(root)
    spec=importlib.util.spec_from_file_location('udp_payload_old_fixtures',ROOT/'tests/test_windows_client_n0a_host.py')
    old=importlib.util.module_from_spec(spec);spec.loader.exec_module(old)
    old.write_payload_fixtures(root) # Real production writer for unchanged 10/14/15 modes.
    host=old.host
    import install_runtime
    actor=root/'identity-fixture.exe';native=root/'udp-inert.exe';native.write_bytes(b'not-an-executable-udp-fixture'*32)
    manifest=root/'udp-manifest.json';manifest.write_text('{"testOnly":false,"fixture":true}',encoding='ascii')
    bundle=root/'bundle.zip';bundle_data=bundle.read_bytes()
    udp={'actor':native,'manifest':manifest,'config':{'actor_sha256':hashlib.sha256(native.read_bytes()).hexdigest(),
          'manifest_sha256':hashlib.sha256(manifest.read_bytes()).hexdigest()}}
    def extract(data,destination):
        with zipfile.ZipFile(io.BytesIO(data)) as archive:
            for name in ('wxc-exec.exe','MXC-LICENSE.md'):(destination/name).write_bytes(archive.read(name))
    target=root/'udp.zip'
    # Explicit authenticated-boundary substitutions only. No trust-pin-valid artifact claim.
    with patch.object(host,'verify_python',return_value=b'nonexecuted-python-fixture'),\
         patch.object(install_runtime,'_g_bundle_bytes',return_value=bundle_data),\
         patch.object(install_runtime,'_extract_g_bundle',side_effect=extract):
        digest=host.payload(root/'unused-python.zip',actor,hashlib.sha256(actor.read_bytes()).hexdigest(),bundle,target,udp=udp)
    if digest!=hashlib.sha256(target.read_bytes()).hexdigest():raise ValueError('fixture digest')
    with zipfile.ZipFile(root/'baseline.zip') as archive:base=set(archive.namelist())
    extra={'udp/actor.exe','udp/build-manifest.json',*('.github/'+n for n in ('windows_n0a_control.py','windows_n0a_guest.py',
           'windows_n0a_udp.py','windows_n0a_udp_guest.py','windows_n0a_udp_flow.py'))}
    with zipfile.ZipFile(target) as archive:
        entries={n:archive.read(n) for n in archive.namelist()}
        if len(archive.namelist())!=17 or set(entries)!=base|extra:raise ValueError('fixture membership')
        for name in extra:
            if name.startswith('.github/') and entries[name]!=(ROOT/name).read_bytes():raise ValueError('fixture source')
    for index,name in enumerate(FORBIDDEN):
        with zipfile.ZipFile(root/f'udp-bad-{index}.zip','w') as archive:
            for member,data in entries.items():archive.writestr(name if member=='.github/windows_n0a_udp_flow.py' else member,data)
    parent=root/'parent-inert.exe';parent.write_bytes(b'not-an-executable-parent-fixture'*32)
    parent_manifest=root/'parent-manifest.json';parent_manifest.write_text('{"testOnly":false,"fixture":true}',encoding='ascii')
    parent_udp={'parent':parent,'parent_manifest':parent_manifest,'child':native,'child_manifest':manifest,
                'config':{'parent_sha256':hashlib.sha256(parent.read_bytes()).hexdigest(),
                          'parent_manifest_sha256':hashlib.sha256(parent_manifest.read_bytes()).hexdigest(),
                          'child_sha256':hashlib.sha256(native.read_bytes()).hexdigest(),
                          'child_manifest_sha256':hashlib.sha256(manifest.read_bytes()).hexdigest()}}
    parent_target=root/'parent_udp.zip'
    with patch.object(host,'verify_python',return_value=b'nonexecuted-python-fixture'),\
         patch.object(install_runtime,'_g_bundle_bytes',return_value=bundle_data),\
         patch.object(install_runtime,'_extract_g_bundle',side_effect=extract):
        digest=host.payload(root/'unused-python.zip',actor,hashlib.sha256(actor.read_bytes()).hexdigest(),bundle,parent_target,parent_udp=parent_udp)
    if digest!=hashlib.sha256(parent_target.read_bytes()).hexdigest():raise ValueError('fixture digest')
    parent_extra={'parent/actor.exe','parent/build-manifest.json',*('.github/'+n for n in ('windows_n0a_udp_parent_control.py','windows_n0a_udp_parent_guest.py','windows_n0a_udp_parent_flow.py'))}
    with zipfile.ZipFile(parent_target) as archive:
        parent_entries={n:archive.read(n) for n in archive.namelist()}
        if len(archive.namelist())!=22 or set(parent_entries)!=set(entries)|parent_extra:raise ValueError('parent membership')
        for name in parent_extra:
            if name.startswith('.github/') and parent_entries[name]!=(ROOT/name).read_bytes():raise ValueError('parent source')
    for index,name in enumerate(PARENT_FORBIDDEN):
        with zipfile.ZipFile(root/f'parent_udp-bad-{index}.zip','w') as archive:
            for member,data in parent_entries.items():archive.writestr(name if member=='.github/windows_n0a_udp_parent_flow.py' else member,data)
    return {'schema_version':1,'members':[10,14,15,17,22],'negative_cases':8,'inert_boundary_mocks':True,'runtime_artifact':False}
def main():
    parser=argparse.ArgumentParser();parser.add_argument('--root',type=Path,required=True);args=parser.parse_args()
    try:result=generate(args.root)
    except Exception:
        print('{"schema_version":1,"failure":"payload_fixture"}');return 1
    print(json.dumps(result,separators=(',',':')));return 0
if __name__=='__main__':raise SystemExit(main())
