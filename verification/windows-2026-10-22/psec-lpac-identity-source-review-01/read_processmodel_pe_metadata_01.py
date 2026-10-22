"""Read fixed System32 processmodel.dll as bytes; never load or call the DLL."""
import hashlib
import json
import os
from pathlib import Path
import stat
import struct

BASE=Path(__file__).resolve().parent
def need(ok,why):
    if not ok:raise ValueError(why)
def digest(b):return hashlib.sha256(b).hexdigest()
def main():
    path=Path(os.environ['SystemRoot'])/'System32'/'processmodel.dll'
    for p in (path,*path.parents):
        s=p.lstat();need(not stat.S_ISLNK(s.st_mode) and not getattr(s,'st_file_attributes',0)&0x400,'no_reparse')
    s=path.lstat();need(stat.S_ISREG(s.st_mode) and 512<=s.st_size<=16*1024*1024,'file_bound')
    raw=path.read_bytes();need(len(raw)==s.st_size,'stable_size')
    def get(fmt,at):
        n=struct.calcsize(fmt);need(0<=at<=len(raw)-n,'pe_bounds');return struct.unpack_from(fmt,raw,at)
    need(raw[:2]==b'MZ','dos');pe=get('<I',0x3c)[0];need(raw[pe:pe+4]==b'PE\0\0','pe')
    machine,count,stamp,_,_,opt_size,flags=get('<HHIIIHH',pe+4);opt=pe+24
    need(machine==0x8664 and 1<=count<=32 and get('<H',opt)[0]==0x20b and opt_size>=240,'amd64_pe32plus')
    dirs=opt+112;need(get('<I',opt+108)[0]>=5,'directory_count')
    sections=[]
    for i in range(count):
        at=opt+opt_size+i*40;virtual_size,rva,file_size,file_at=get('<IIII',at+8)
        need(file_at+file_size<=len(raw),'section_bounds');sections.append((rva,virtual_size,file_at,file_size))
    def offset(rva,size=1):
        for start,vsize,file_at,file_size in sections:
            if start<=rva and rva+size<=start+max(vsize,file_size):
                at=file_at+rva-start;need(rva+size<=start+file_size and at+size<=len(raw),'rva_initialized_bytes');return at
        raise ValueError('rva_not_mapped')
    def string(rva):
        at=offset(rva);end=raw.find(b'\0',at,min(len(raw),at+512));need(end>=at,'export_string');return raw[at:end].decode('ascii')
    export_rva,export_size=get('<II',dirs);at=offset(export_rva,40)
    _,_,_,_,_,base,function_count,name_count,functions,names,ordinals=get('<IIHHIIIIIII',at)
    need(0<name_count<=function_count<=16384,'export_counts')
    required=('CreateProcessSecurityEnvironment','CloseProcessSecurityEnvironment','QueryProcessSecurityEnvironmentSupport','IsProcessSecurityEnvironmentVersionSupported')
    optional=('CancelProcessSecurityEnvironmentTerminateOnClose',)
    found={}
    for i in range(name_count):
        name=string(get('<I',offset(names+i*4,4))[0])
        ordinal=get('<H',offset(ordinals+i*2,2))[0];need(ordinal<function_count,'ordinal')
        address=get('<I',offset(functions+ordinal*4,4))[0]
        if name in (*required,*optional):
            forwarded=export_rva<=address<export_rva+export_size
            found[name]=dict(present=True,ordinal=base+ordinal,rva=address,forwarded=forwarded,
                forwarder=string(address) if forwarded else None)
    resource_rva,resource_size=get('<II',dirs+16);resource_at=offset(resource_rva,resource_size)
    def entries(relative):
        at=resource_at+relative;need(0<=relative<=resource_size-16,'resource_directory')
        named,ids=get('<HH',at+12);need(named+ids<=256 and relative+16+(named+ids)*8<=resource_size,'resource_entries')
        return [get('<II',at+16+i*8) for i in range(named+ids)]
    type_entry=[value for key,value in entries(0) if key==16];need(len(type_entry)==1 and type_entry[0]&0x80000000,'version_resource')
    versions=[]
    def visit(value,depth):
        need(depth<=3,'resource_depth')
        if value&0x80000000:
            for key,child in entries(value&0x7fffffff):visit(child,depth+1)
        else:
            need(value+16<=resource_size,'resource_data_entry')
            rva,size,codepage,reserved=get('<IIII',resource_at+value);need(reserved==0 and 92<=size<=65536,'version_size')
            start=offset(rva,size);block=raw[start:start+size];length,value_length,kind=struct.unpack_from('<HHH',block)
            key='VS_VERSION_INFO\0'.encode('utf-16-le');need(92<=length<=size and value_length==52 and block[6:6+len(key)]==key,'version_root')
            fixed=(6+len(key)+3)&~3;info=struct.unpack_from('<13I',block,fixed);need(info[0]==0xfeef04bd and info[1]==0x10000,'fixed_file_info')
            split=lambda ms,ls:[ms>>16,ms&0xffff,ls>>16,ls&0xffff]
            versions.append(dict(file_version=split(info[2],info[3]),product_version=split(info[4],info[5]),file_type=info[9],file_flags=info[7]))
    visit(type_entry[0],0);need(1<=len(versions)<=16 and all(v==versions[0] for v in versions),'version_consistency')
    certificate_at,certificate_size=get('<II',dirs+32)
    need(certificate_at+certificate_size<=len(raw),'certificate_table_bound')
    value=dict(schema_version=1,stage='read-only-system-processmodel-pe-metadata',target='System32/processmodel.dll',
        bytes=len(raw),sha256=digest(raw),pe_machine='AMD64',dll_characteristic=bool(flags&0x2000),
        file_version=versions[0]['file_version'],product_version=versions[0]['product_version'],version_resource_count=len(versions),
        version_file_type=versions[0]['file_type'],version_file_flags=versions[0]['file_flags'],
        required_exports={name:found.get(name,dict(present=False)) for name in required},
        optional_exports={name:found.get(name,dict(present=False)) for name in optional},named_export_count=name_count,
        certificate_table_present=bool(certificate_size),authenticode_signature_verified=False,
        imports_or_user_strings_published=False,absolute_machine_path_published=False,reader_sha256=digest(Path(__file__).read_bytes()),
        actions=dict(file_bytes_read=True,dll_loaded=False,native_api_called=False,CPSE_called=False,actor_or_process_experiment=False,network_executed=False,os_or_global_settings_changed=False),
        limits='PE export presence and static version/hash do not prove API-set availability, call success, CPSE+LPAC acceptance, resource recovery, policy enforcement or DLL signing validity.')
    data=(json.dumps(value,sort_keys=True,ensure_ascii=False,indent=2)+'\n').encode('utf-8')
    out=BASE/'processmodel-pe-static-metadata-01.json'
    if out.exists():need(out.read_bytes()==data,'immutable_metadata')
    else:
        with out.open('xb') as f:need(f.write(data)==len(data),'write')
    print(json.dumps(dict(verified_static_PE=True,metadata_bytes=len(data),metadata_sha256=digest(data),target_sha256=digest(raw),
        required_exports_present=all(name in found for name in required),dll_loaded=False,native_api_called=False),sort_keys=True))
if __name__=='__main__':main()
