"""Static bounded PE/source inspection only. Never load or execute the actor."""
from pathlib import Path
import hashlib
import json
import struct

BASE=Path(__file__).resolve().parent
BUILD=BASE/'zero-cap-loopback-compile-01'
CANDIDATE=BASE/'zero-cap-same-sid-loopback-candidate'
sha=lambda raw:hashlib.sha256(raw).hexdigest()


def require(value,label):
    if not value:raise ValueError(label)


def load(path):
    return json.loads(path.read_text(encoding='utf-8-sig'))


def metadata(raw):
    def integer(offset,fmt):
        size=struct.calcsize(fmt);require(0<=offset<=len(raw)-size,'PE integer range')
        return struct.unpack_from(fmt,raw,offset)[0]
    require(raw[:2]==b'MZ','DOS signature');pe=integer(60,'<I')
    require(raw[pe:pe+4]==b'PE\0\0','PE signature')
    machine=integer(pe+4,'<H');count=integer(pe+6,'<H');optional_size=integer(pe+20,'<H')
    characteristics=integer(pe+22,'<H');optional=pe+24
    require(machine==0x8664 and 1<=count<=32 and optional_size>=240,'AMD64 PE32+ header')
    require(integer(optional,'<H')==0x20b and not characteristics&0x2000,'executable PE32+ not DLL')
    require(integer(optional+68,'<H')==2,'Windows GUI subsystem')
    require(integer(optional+108,'<I')>=16,'data directories')
    sections=[]
    for index in range(count):
        off=optional+optional_size+40*index
        require(off+40<=len(raw),'section range')
        virtual_size=integer(off+8,'<I');virtual=integer(off+12,'<I')
        size=integer(off+16,'<I');file=integer(off+20,'<I')
        require(file<=len(raw) and size<=len(raw)-file,'section file range')
        sections.append((virtual,virtual_size,file,size))
    def rva(value,size):
        require(value>0 and size>0,'nonempty RVA')
        matches=[]
        for virtual,_virtual_size,file,length in sections:
            if value>=virtual and value-virtual<=length and size<=length-(value-virtual):
                matches.append(file+value-virtual)
        require(len(matches)==1,'unique bounded RVA');return matches[0]
    def name(value):
        offset=rva(value,1);result=bytearray()
        for index in range(128):
            pos=rva(value+index,1)
            require(pos==offset+index,'contiguous import string')
            byte=raw[pos]
            if byte==0:
                require(result and all(32<x<127 for x in result),'ASCII import name')
                return result.decode('ascii')
            result.append(byte)
        raise ValueError('unterminated import name')
    import_rva=integer(optional+112+8,'<I');import_bytes=integer(optional+112+12,'<I')
    require(import_rva and 20<=import_bytes<=8192,'bounded imports')
    imports=[];terminated=False
    for index in range(min(import_bytes//20,128)):
        offset=rva(import_rva+20*index,20);row=struct.unpack_from('<IIIII',raw,offset)
        if not any(row):terminated=True;break
        require(row[3]>0 and row[4]>0,'import descriptor')
        imports.append(name(row[3]))
    require(terminated and imports and len(set(x.lower() for x in imports))==len(imports),'closed import descriptors')
    require(set(x.lower() for x in imports)=={'kernel32.dll','advapi32.dll','ws2_32.dll'},'exact three imports; no UI loader')
    require(integer(optional+112+13*8,'<I')==0 and integer(optional+116+13*8,'<I')==0,'no delay imports')
    return {'machine':'AMD64','subsystem':'WINDOWS_GUI','dll':False,'imports':imports,'delay_imports':[],
            'section_count':count,'entrypoint_nonzero':integer(optional+16,'<I')>0}


def inspect():
    manifest_path=BUILD/'identity-lpac-loopback-manifest.json';manifest=load(manifest_path)
    require(set(manifest)=={'schemaVersion','compileOnly','runtimeAcceptance','interfaceVersion',
                          'executableSha256','actorSourceSha256','contractSourceSha256'},'manifest closure')
    require(type(manifest['schemaVersion']) is int and manifest['schemaVersion']==1 and
            manifest['compileOnly'] is True and manifest['runtimeAcceptance'] is False and
            type(manifest['interfaceVersion']) is int and manifest['interfaceVersion']==1,'compile-only manifest')
    before=load(BASE/'zero-cap-loopback-native-compile-input-01.json')
    snapshot=load(BUILD/'input-snapshot.json');require(snapshot==before,'before-compile snapshot exact')
    require(before['native_source_count']==2 and len(before['sources'])==2,'two-source closure')
    keys={'actorSourceSha256':'.github/native/windows_identity_lpac_loopback_actor.cpp',
          'contractSourceSha256':'.github/native/windows_identity_lpac_loopback_contract.hpp'}
    for field,name in keys.items():
        expected=before['sources'][name]
        for root in (CANDIDATE,BUILD/'src'):
            raw=(root/name).read_bytes();require(len(raw)==expected['bytes'] and sha(raw)==expected['sha256'],
                                                'immutable source snapshot')
            require(b'\r' not in raw,'LF native source')
        require(manifest[field]==expected['sha256'],'manifest source binding')
    actor=BUILD/'windows_identity_lpac_loopback_actor.exe';raw=actor.read_bytes()
    require(sha(raw)==manifest['executableSha256'],'actor manifest hash')
    pe=metadata(raw);toolchain=load(BUILD/'toolchain.json')
    require(toolchain['Runtime']=='MT' and toolchain['Architecture']=='amd64' and
            toolchain['CompileOnly'] is True and toolchain['ActorExecuted'] is False and
            toolchain['NetworkExecuted'] is False,'compile toolchain scope')
    log=(BUILD/'compile.log').read_bytes()
    text=log.decode('utf-8-sig',errors='replace')
    require('error C' not in text and 'warning C' not in text and 'fatal error' not in text,'warning-free compile log')
    return {'schema_version':1,'stage':'zero-cap-loopback-compile-static-review','passed':True,
            'actor_bytes':len(raw),'actor_sha256':sha(raw),'manifest_sha256':sha(manifest_path.read_bytes()),
            'input_snapshot_sha256':sha((BUILD/'input-snapshot.json').read_bytes()),
            'compile_log_bytes':len(log),'compile_log_sha256':sha(log),
            'toolchain_sha256':sha((BUILD/'toolchain.json').read_bytes()),'pe':pe,
            'native_sources':before['sources'],'actor_executed':False,'network_executed':False,
            'runtime_acceptance':False,'inspection_method':'file-only bounded PE parsing; no executable load'}


if __name__=='__main__':
    value=inspect();path=BASE/'zero-cap-loopback-compile-static-review-01.json'
    raw=(json.dumps(value,sort_keys=True,indent=2)+'\n').encode('ascii')
    with path.open('xb') as output:output.write(raw)
    print(json.dumps({'passed':True,'review_bytes':len(raw),'review_sha256':sha(raw),
                      'actor_sha256':value['actor_sha256'],'imports':value['pe']['imports']},sort_keys=True))
