"""Verify official pins and extract only selected work-local dependencies."""
import hashlib
import json
from pathlib import Path, PurePosixPath
import stat
import struct
import zipfile

base=Path(__file__).resolve().parent;root=base/'psec-lpac-bridge-deps'
pins=json.loads((base/'flatbuffers-25.12.19-dependency-pins.json').read_bytes())
def pin(raw):return dict(bytes=len(raw),sha256=hashlib.sha256(raw).hexdigest())
def write(p,raw):
    assert p.resolve().is_relative_to(root.resolve())
    p.parent.mkdir(parents=True,exist_ok=True)
    if p.exists():
        assert p.is_file() and not p.is_symlink() and p.read_bytes()==raw
        return
    with p.open('xb') as stream:stream.write(raw)
flat=(root/'Windows.flatc.binary.zip').read_bytes()
assert pin(flat)=={k:pins['flatc_zip'][k] for k in ('bytes','sha256')}
with zipfile.ZipFile(root/'Windows.flatc.binary.zip') as z:
    assert z.namelist()==['flatc.exe'] and z.getinfo('flatc.exe').file_size<=8*1024*1024
    raw=z.read('flatc.exe');assert raw[:2]==b'MZ'
    offset=struct.unpack_from('<I',raw,60)[0];assert raw[offset:offset+4]==b'PE\0\0'
    assert struct.unpack_from('<H',raw,offset+4)[0]==0x8664
    flatc_pin=pin(raw);write(root/'flatc.exe',raw)
members=[]
with zipfile.ZipFile(root/'flatbuffers-source.zip') as z:
    prefixes={PurePosixPath(info.filename).parts[0] for info in z.infolist()}
    assert len(prefixes)==1 and len(z.infolist())<=10000
    prefix=next(iter(prefixes))+'/'
    ignored_symlinks=[]
    for info in z.infolist():
        path=PurePosixPath(info.filename)
        assert not path.is_absolute() and '..' not in path.parts and '\\' not in info.filename
        if stat.S_IFMT(info.external_attr>>16)==stat.S_IFLNK:ignored_symlinks.append(info.filename)
    for row in pins['source_members']:
        name=row['path'];info=z.getinfo(prefix+name);assert info.file_size==row['bytes']<=1024*1024
        assert stat.S_IFMT(info.external_attr>>16)!=stat.S_IFLNK
        raw=z.read(info);assert len(raw)==row['bytes']
        blob=hashlib.sha1(b'blob '+str(len(raw)).encode()+b'\0'+raw).hexdigest()
        assert blob==row['git_blob'],name
        write(root/'flatbuffers'/name,raw);members.append(dict(path=name,git_blob=blob,**pin(raw)))
result=dict(schema_version=1,stage='work-only-pinned-flatbuffers-dependencies',tag=pins['tag'],commit=pins['commit'],
    flatc_zip=pin(flat),flatc_x64_executable=flatc_pin,source_zip=pin((root/'flatbuffers-source.zip').read_bytes()),
    source_files=members,git_blob_members_verified=len(members),unselected_symlinks_not_extracted=len(ignored_symlinks),
    global_settings_changed=False,code_execution_by_this_verifier=False,flatc_previously_used_for_version_only=True,
    processmodel_loaded=False,native_actor_executed=False)
write(root/'verification.json',(json.dumps(result,sort_keys=True,indent=2)+'\n').encode())
print(json.dumps(dict(verified=True,members=len(members),flatc_x64=True,code_execution_by_this_verifier=False,global_settings_changed=False)))
