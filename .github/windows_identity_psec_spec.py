"""Pure, bounded PSEC identity-only spec codec. No native or process API.

The serializer emits one canonical byte layout. The independent reader follows
FlatBuffer offsets and checks every permitted slot before comparing that layout.
No unrecognised extension, alternate path, proxy or peer is admitted.
"""
from __future__ import annotations
import hashlib
import ntpath
import struct

MAX_BYTES=65536
CAPABILITY='privateNetworkClientServer'
VARIANT='identity-only-deny-all-v1'
SCHEMA_SHA256='736cacef37a6c97a0cb97c7132da462a3b51811fca8f1e4076cac51085dfa516'

def require(condition,label):
    if not condition:raise ValueError(label)

def path(value):
    require(type(value) is str and 1<=len(value.encode('utf-16-le'))//2<=1024 and '\0' not in value,'spec_path')
    require(ntpath.isabs(value) and ntpath.splitdrive(value)[0] and not value.startswith('\\\\')
        and ntpath.normpath(value)==value and not value.endswith('\\') and '/' not in value,'spec_absolute_path')
    require(all(part not in ('.','..') and part and not part.endswith((' ','.')) for part in value[3:].split('\\')),'spec_path_component')
    return value

def build(inputs):
    """Produce canonical valid FlatBuffer bytes with only fixed deny-all fields."""
    path(inputs);data=bytearray(b'\0\0\0\0PSEC')
    def align(n):data.extend(b'\0'*((-len(data))%n))
    def table(slots,object_bytes,alignment=4):
        align(2);vtable=len(data);data.extend(struct.pack('<HH',4+2*len(slots),object_bytes))
        data.extend(struct.pack('<'+'H'*len(slots),*slots));align(alignment)
        position=len(data);data.extend(b'\0'*object_bytes);struct.pack_into('<i',data,position,position-vtable);return position
    def link(at,target):
        require(target>at,'spec_builder_direction');struct.pack_into('<I',data,at,target-at)
    def string(value):
        raw=value.encode('utf-8');align(4);position=len(data);data.extend(struct.pack('<I',len(raw))+raw+b'\0');return position
    root=table([4,8,12,16,0,24,0,28,0],32,8)
    struct.pack_into('<I',data,0,root);struct.pack_into('<HH',data,root+4,1,1)
    data[root+12]=1;struct.pack_into('<Q',data,root+16,1023)
    link(root+8,string(CAPABILITY))
    align(4);vector=len(data);data.extend(struct.pack('<II',1,0));link(root+24,vector)
    link(vector+4,string(inputs))
    network=table([0,4,0,8],12);link(root+28,network)
    egress=table([0,0,0],4);link(network+4,egress)
    ingress=table([0,0],4);link(network+8,ingress)
    require(len(data)<=MAX_BYTES,'spec_builder_bound');return bytes(data)

class Reader:
    def __init__(self,raw):
        require(type(raw) is bytes and 8<=len(raw)<=MAX_BYTES and raw[4:8]==b'PSEC','spec_buffer');self.raw=raw
    def read(self,fmt,offset):
        size=struct.calcsize(fmt);require(type(offset) is int and 0<=offset<=len(self.raw)-size,'spec_bounds')
        return struct.unpack_from(fmt,self.raw,offset)
    def offset(self,at):
        value=self.read('<I',at)[0];require(value>=4 and at+value<len(self.raw),'spec_offset');return at+value
    def table(self,position,count):
        delta=self.read('<i',position)[0];require(delta>0,'spec_vtable_direction');vtable=position-delta
        size,object_size=self.read('<HH',vtable)
        require(size==4+count*2 and 4<=object_size<=256 and position+object_size<=len(self.raw)
            and vtable+size<=position,'spec_table_layout')
        offsets=self.read('<'+'H'*count,vtable+4)
        require(all(value==0 or 4<=value<object_size for value in offsets),'spec_field_offset')
        require(len([v for v in offsets if v])==len(set(v for v in offsets if v)),'spec_field_alias')
        return [(None if value==0 else position+value) for value in offsets]
    def string(self,field):
        require(field is not None,'spec_required_string');position=self.offset(field);length=self.read('<I',position)[0]
        require(1<=length<=4096 and position+4+length<len(self.raw) and self.raw[position+4+length]==0,'spec_string_bound')
        value=self.raw[position+4:position+4+length].decode('utf-8','strict');require('\0' not in value,'spec_string_nul');return value
    def scalar(self,field,fmt,default=0):return default if field is None else self.read(fmt,field)[0]

def verify(raw,inputs):
    """Independently read fixed root/network slots, then reject noncanonical bytes."""
    path(inputs);r=Reader(raw);root=r.offset(0);fields=r.table(root,9)
    require(fields[0] is not None and r.read('<HH',fields[0])==(1,1),'spec_version')
    require(r.string(fields[1])==CAPABILITY and r.scalar(fields[2],'<B')==1
        and r.scalar(fields[3],'<Q')==1023,'spec_identity_policy')
    require(all(fields[index] is None for index in (4,6,8)),'spec_forbidden_filesystem')
    require(fields[5] is not None,'spec_read_only_required');vector=r.offset(fields[5])
    require(r.read('<I',vector)[0]==1 and r.string(vector+4)==inputs,'spec_exact_read_only')
    require(fields[7] is not None,'spec_network_required');network=r.table(r.offset(fields[7]),4)
    require(network[0] is None and network[2] is None and network[1] is not None and network[3] is not None,'spec_no_proxy_or_peer')
    egress=r.table(r.offset(network[1]),3);ingress=r.table(r.offset(network[3]),2)
    require(r.scalar(egress[0],'<b')==0 and egress[1:] == [None,None]
        and all(r.scalar(field,'<b')==0 for field in ingress),'spec_deny_all')
    require(raw==build(inputs),'spec_canonical_bytes')
    return dict(schema_version=[1,1],variant=VARIANT,capabilities=CAPABILITY,win32k_disabled=True,
        ui_restrictions=1023,read_only_count=1,proxy_present=False,peer_present=False,
        egress='deny',ingress='deny',host_loopback='deny',sha256=hashlib.sha256(raw).hexdigest())
