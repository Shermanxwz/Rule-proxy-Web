"""Single fixed-name ordinary-user AFD security read; default does no native call.

Root must review and supervise execution. The synchronous native calls cannot be
forcibly cancelled by this helper; the parent's absoluteQPC guard checks entry/return,
not a promise that a wedged kernel call is interruptible. No socket/EA/IOCTL,
profile, security write, privilege change, process creation or path fallback.
"""
from pathlib import Path
import argparse
import ctypes as C
import hashlib
import importlib.util
import json
import os
import re
import struct
import sys

W=Path(__file__).resolve().parent
R=W/'Rule-proxy-Web'
TARGET='\\Device\\Afd'
READ_CONTROL_SYNCHRONIZE=0x00120000
OPTIONS=0x00000060  # FILE_NON_DIRECTORY_FILE | FILE_SYNCHRONOUS_IO_NONALERT.
SECURITY_INFORMATION=7  # OWNER | GROUP | DACL; never SACL.
MAX_SD=65536
RETAINED=[]
P,D,N=C.c_void_p,C.c_uint32,C.c_int32
PINNED_SOURCES={
 '.github/windows_identity_ordinary_launcher.py':'a890f4740bc2869586278158edad65dd8c649e09afed8c7aab355d842301d4a0',
 'ruleproxy/windows_app_process.py':'8e62820f98d9dbe352d988501d211565aceecce84657200c2793b69404cbee33',
}
PRIMARY=[
 'https://learn.microsoft.com/en-us/windows/win32/api/winternl/nf-winternl-ntopenfile',
 'https://learn.microsoft.com/en-us/windows-hardware/drivers/ddi/wdm/nf-wdm-zwopenfile',
 'https://learn.microsoft.com/en-us/windows-hardware/drivers/ddi/wdm/nf-wdm-zwcreatefile',
 'https://learn.microsoft.com/en-us/windows-hardware/drivers/ddi/ntifs/nf-ntifs-ntquerysecurityobject',
 'https://learn.microsoft.com/en-us/windows/win32/api/ntdef/ns-ntdef-_unicode_string',
 'https://learn.microsoft.com/en-us/windows/win32/api/ntdef/ns-ntdef-_object_attributes',
 'https://learn.microsoft.com/en-us/windows-hardware/drivers/ddi/wdm/ns-wdm-_io_status_block',
 'https://learn.microsoft.com/en-us/windows/win32/api/sddl/nf-sddl-convertsecuritydescriptortostringsecuritydescriptorw',
 'https://learn.microsoft.com/en-us/windows/win32/secauthz/security-descriptors',
 'https://learn.microsoft.com/en-us/windows/win32/api/handleapi/nf-handleapi-closehandle',
 'https://learn.microsoft.com/en-us/windows/win32/api/profileapi/nf-profileapi-queryperformancecounter',
 'https://learn.microsoft.com/en-us/windows/win32/api/profileapi/nf-profileapi-queryperformancefrequency',
]

def require(v,label):
    if not v:raise ValueError(label)
def sha(raw):return hashlib.sha256(raw).hexdigest()
def ntstatus(value):
    u=int(value)&0xffffffff
    return dict(unsigned=u,hex='0x%08x'%u,success_exact=(u==0),pending=(u==0x103))
def sid_bytes(text):
    parts=text.split('-');rids=list(map(int,parts[3:]))
    return bytes([1,len(rids)])+int(parts[2]).to_bytes(6,'big')+struct.pack('<%dI'%len(rids),*rids)
KNOWN={sid_bytes(text):(name,text) for name,text in (
 ('world','S-1-1-0'),('local_system','S-1-5-18'),('builtin_administrators','S-1-5-32-544'),
 ('all_application_packages','S-1-15-2-1'),('all_restricted_application_packages','S-1-15-2-2'),
 ('internetClient','S-1-15-3-1'),('internetClientServer','S-1-15-3-2'),('privateNetworkClientServer','S-1-15-3-3'),
 ('registryRead','S-1-15-3-1024-1065365936-1281604716-3511738428-1654721687-432734479-3232135806-4053264122-3456934681'))}
def sid_at(raw,offset,end):
    require(0<=offset and offset+8<=end<=len(raw),'sid_header_bounds')
    require(raw[offset]==1 and raw[offset+1]<=15,'sid_header')
    size=8+4*raw[offset+1];require(offset+size<=end,'sid_extent')
    value=raw[offset:offset+size];known=KNOWN.get(value)
    return dict(principal=known[0] if known else 'other_sid',known_sid=known[1] if known else None,bytes=size)
def project_sd(raw):
    require(type(raw) is bytes and 20<=len(raw)<=MAX_SD,'sd_size')
    rev,reserved,control,owner,group,sacl,dacl=struct.unpack_from('<BBHIIII',raw)
    require(rev==1 and reserved==0 and control&0x8000 and sacl==0,'sd_relative_no_sacl')
    result=dict(revision=rev,control=control,owner=None,group=None,dacl_present=bool(control&4),null_dacl=False,aces=[])
    for name,offset in (('owner',owner),('group',group)):
        if offset:require(offset>=20,'sd_sid_offset');result[name]=sid_at(raw,offset,len(raw))
    if not control&4:require(dacl==0,'sd_absent_dacl_offset');return result
    if not dacl:result['null_dacl']=True;return result
    require(dacl>=20 and dacl+8<=len(raw),'acl_header_bounds')
    ar,az,size,count,az2=struct.unpack_from('<BBHHH',raw,dacl)
    require(ar in (2,4) and az==az2==0 and 8<=size<=MAX_SD and dacl+size<=len(raw) and count<=4096,'acl_header')
    pos=dacl+8;end=dacl+size
    for index in range(count):
        require(pos+4<=end,'ace_header_bounds')
        kind,flags,extent=struct.unpack_from('<BBH',raw,pos)
        require(extent>=4 and extent%4==0 and pos+extent<=end,'ace_extent')
        row=dict(index=index,type=kind,flags=flags,bytes=extent,mask=None,sid=None,supported_sid_layout=False)
        if kind in (0,1):
            require(extent>=16,'basic_ace_size');row['mask']='0x%08x'%struct.unpack_from('<I',raw,pos+4)[0]
            row['sid']=sid_at(raw,pos+8,pos+extent);require(8+row['sid']['bytes']==extent,'basic_ace_trailing')
            row['supported_sid_layout']=True
        # Unknown/object/callback ACEs are recorded as uninterpreted, not cast.
        result['aces'].append(row);pos+=extent
    require(pos<=end,'acl_end')
    result.update(acl_bytes=size,ace_count=count,all_ace_sid_layouts_supported=all(x['supported_sid_layout'] for x in result['aces']))
    return result

class UNICODE_STRING(C.Structure):
    _fields_=[('Length',C.c_uint16),('MaximumLength',C.c_uint16),('Buffer',P)]
class OBJECT_ATTRIBUTES(C.Structure):
    _fields_=[('Length',D),('RootDirectory',P),('ObjectName',C.POINTER(UNICODE_STRING)),('Attributes',D),('SecurityDescriptor',P),('SecurityQualityOfService',P)]
class IO_UNION(C.Union):
    _fields_=[('Status',N),('Pointer',P)]
class IO_STATUS_BLOCK(C.Structure):
    _fields_=[('u',IO_UNION),('Information',C.c_size_t)]

def source_admission():
    require(os.name=='nt' and C.sizeof(P)==8,'windows_x64_python_required')
    for name,digest in PINNED_SOURCES.items():
        path=R/name
        for item in (path,*path.parents):
            if item==R.parent:break
            require(not item.is_symlink() and not getattr(item.lstat(),'st_file_attributes',0)&0x400,'source_reparse')
        require(path.is_file() and 1<=path.stat().st_size<=512*1024 and sha(path.read_bytes())==digest,'source_hash')
    # LocalNativeAPI's identical read-only base, without local->smoke->socket
    # imports that would implicitly execute CPython's Windows WSAStartup.
    path=R/'.github/windows_identity_ordinary_launcher.py'
    spec=importlib.util.spec_from_file_location('afd_readonly_pinned_launcher',path)
    module=importlib.util.module_from_spec(spec);spec.loader.exec_module(module)
    require('socket' not in sys.modules and '_socket' not in sys.modules,'no_socket_module_import')
    return module

def main():
    args=argparse.ArgumentParser(description=__doc__)
    args.add_argument('--query-afd-dacl',action='store_true')
    args.add_argument('--deadline-qpc',type=int)
    args.add_argument('--frequency',type=int)
    options=args.parse_args()
    if not options.query_afd_dacl:
        print(json.dumps(dict(stage='afd-readonly-not-executed',native_api_called=False,target=TARGET,explicit_flag_required=True)));return
    output=W/'afd-device-dacl-readonly-01.json'
    require(not output.exists(),'fresh_output_required')
    require(type(options.deadline_qpc) is int and 1<=options.deadline_qpc<2**63
        and type(options.frequency) is int and 1<=options.frequency<2**63,'explicit_parent_qpc_required')
    report=dict(schema_version=1,stage='ordinary-afd-device-dacl-readonly',helper_sha256=sha(Path(__file__).read_bytes()),
        target=TARGET,desired_access='0x00120000',desired_access_names=['READ_CONTROL','SYNCHRONIZE'],share_access=7,
        open_options='0x00000060',object_attributes='0x00000040',security_information=7,max_sd_bytes=MAX_SD,
        primary_sources=PRIMARY,ordinary_identity_verified=False,ordinary_identity=None,identity_token_close_confirmed=False,
        open_attempted=False,open_status=None,open_handle_returned=False,open_outcome_unknown=False,
        query_statuses=[],descriptor=None,descriptor_sha256=None,descriptor_bytes=None,sddl_sha256=None,sddl_characters=None,
        sddl_close_confirmed=None,device_close_attempted=False,device_close_confirmed=None,cleanup_unknown=False,
        raw_sd_or_sddl_retained=False,source_hashes=PINNED_SOURCES,deadline_qpc=options.deadline_qpc,
        frequency=options.frequency,actual_frequency=None,first_qpc=None,last_qpc=None,qpc_samples=0,
        deadline_source='explicit-parent-absolute-qpc-not-renewed',
        identity_backend='pinned-ordinary-launcher-NativeAPI-readonly-base-of-LocalNativeAPI',
        observation_complete=False,within_original_deadline=False,failure=None,
        synchronous_call_internally_cancellable=False,external_process_watchdog_required=True,
        no_ea=True,no_ioctl=True,no_winsock_explicit_calls_in_helper=True,no_socket_api_or_endpoint_ea=True,
        parent_or_wrapper_winsock_activity_assessed=False,afd_internal_endpoint_absence_proven=False,
        no_security_write=True,no_profile_or_process_creation=True,
        held_lpac_effective_access_proven=False,unique_socket_failure_cause_proven=False,product_acceptance=False)
    api=None;device=None;token=None;counter=None
    def gate():
        require(counter is not None,'qpc_not_bound')
        value=C.c_int64();require(counter(C.byref(value)),'qpc_failed')
        report['qpc_samples']+=1;previous=report['last_qpc'];report['last_qpc']=value.value
        if report['first_qpc'] is None:report['first_qpc']=value.value
        require(value.value>=0 and (previous is None or value.value>=previous),'qpc_backwards')
        require(value.value<options.deadline_qpc,'original_readonly_deadline')
    try:
        require(os.name=='nt' and C.sizeof(P)==8,'windows_x64_python_required')
        clock=C.WinDLL('kernel32.dll',use_last_error=True,winmode=0x800)
        counter=clock.QueryPerformanceCounter;counter.argtypes=[C.POINTER(C.c_int64)];counter.restype=C.c_int
        frequency=clock.QueryPerformanceFrequency;frequency.argtypes=[C.POINTER(C.c_int64)];frequency.restype=C.c_int
        actual=C.c_int64();require(frequency(C.byref(actual)) and actual.value==options.frequency,'actual_qpc_frequency')
        report['actual_frequency']=actual.value
        gate();module=source_admission();gate();api=module.NativeAPI();gate()
        clock.IsWow64Process2.argtypes=[P,C.POINTER(C.c_uint16),C.POINTER(C.c_uint16)];clock.IsWow64Process2.restype=C.c_int
        pm,nm=C.c_uint16(),C.c_uint16()
        require(clock.IsWow64Process2(api.k.GetCurrentProcess(),C.byref(pm),C.byref(nm)) and pm.value==0 and nm.value==0x8664,'actual_windows_x64')
        require('socket' not in sys.modules and '_socket' not in sys.modules,'no_socket_module_import')
        token=api.current_token()
        try:
            observed=api.identity(token);require(module.token_is_ordinary(observed),'current_ordinary_required')
            report.update(ordinary_identity_verified=True,ordinary_identity=module.safe_identity(observed))
        finally:
            value,token=token,None
            try:api.close(value);report['identity_token_close_confirmed']=True
            except BaseException:report['cleanup_unknown']=True;raise
        gate()
        nt=C.WinDLL('ntdll.dll',use_last_error=True,winmode=0x800)
        nt.NtOpenFile.argtypes=[C.POINTER(P),D,C.POINTER(OBJECT_ATTRIBUTES),C.POINTER(IO_STATUS_BLOCK),D,D];nt.NtOpenFile.restype=N
        nt.NtQuerySecurityObject.argtypes=[P,D,P,D,C.POINTER(D)];nt.NtQuerySecurityObject.restype=N
        a,k=api.a,api.k
        a.IsValidSecurityDescriptor.argtypes=[P];a.IsValidSecurityDescriptor.restype=C.c_int
        a.GetSecurityDescriptorLength.argtypes=[P];a.GetSecurityDescriptorLength.restype=D
        a.ConvertSecurityDescriptorToStringSecurityDescriptorW.argtypes=[P,D,D,C.POINTER(P),C.POINTER(D)]
        a.ConvertSecurityDescriptorToStringSecurityDescriptorW.restype=C.c_int
        k.LocalFree.argtypes=[P];k.LocalFree.restype=P
        require(C.sizeof(UNICODE_STRING)==16 and C.sizeof(OBJECT_ATTRIBUTES)==48 and C.sizeof(IO_STATUS_BLOCK)==16,'native_x64_layout')
        name=C.create_unicode_buffer(TARGET);text=UNICODE_STRING(len(TARGET.encode('utf-16-le')),C.sizeof(name),C.cast(name,P))
        attr=OBJECT_ATTRIBUTES(C.sizeof(OBJECT_ATTRIBUTES),None,C.pointer(text),0x40,None,None)
        ios=IO_STATUS_BLOCK();handle=P();report['open_attempted']=True
        gate()
        try:status=nt.NtOpenFile(C.byref(handle),READ_CONTROL_SYNCHRONIZE,C.byref(attr),C.byref(ios),7,OPTIONS)
        except BaseException:
            report.update(open_outcome_unknown=True,cleanup_unknown=True)
            RETAINED.append((name,text,attr,ios,handle));raise
        report.update(open_status=ntstatus(status),open_handle_returned=bool(handle.value))
        if status!=0:
            if handle.value or (status&0xffffffff)==0x103:report.update(open_outcome_unknown=True,cleanup_unknown=True)
            # A pending/unexpected failed output is not an owned completed open.
            RETAINED.append((name,text,attr,ios,handle));raise ValueError('nt_open_not_success')
        if handle.value in (None,0,C.c_void_p(-1).value):
            report.update(open_outcome_unknown=True,cleanup_unknown=True);raise ValueError('nt_open_invalid_handle')
        # Nonpending NtOpenFile return is authoritative (IO_STATUS_BLOCK docs).
        device=handle.value;gate()
        needed=D()
        try:status=nt.NtQuerySecurityObject(device,SECURITY_INFORMATION,None,0,C.byref(needed))
        except BaseException:RETAINED.append(needed);report['cleanup_unknown']=True;raise
        report['query_statuses'].append(ntstatus(status))
        if (status&0xffffffff)==0x103:RETAINED.append(needed);report['cleanup_unknown']=True
        gate()
        require((status&0xffffffff)==0xc0000023 and 20<=needed.value<=MAX_SD,'nt_query_size_status_or_bound')
        capacity=needed.value;buffer=C.create_string_buffer(capacity);returned=D()
        gate()
        try:status=nt.NtQuerySecurityObject(device,SECURITY_INFORMATION,buffer,capacity,C.byref(returned))
        except BaseException:
            RETAINED.append((buffer,returned));report['cleanup_unknown']=True;raise
        report['query_statuses'].append(ntstatus(status))
        if (status&0xffffffff)==0x103:RETAINED.append((buffer,returned));report['cleanup_unknown']=True
        require(status==0 and 20<=returned.value<=capacity,'nt_query_not_success_or_extent');gate()
        raw=buffer.raw[:returned.value];report.update(descriptor_bytes=len(raw),descriptor_sha256=sha(raw),descriptor=project_sd(raw))
        require(a.IsValidSecurityDescriptor(buffer) and 20<=a.GetSecurityDescriptorLength(buffer)<=len(raw),'sdk_descriptor_readback')
        pointer=P();characters=D();gate()
        converted=bool(a.ConvertSecurityDescriptorToStringSecurityDescriptorW(buffer,1,SECURITY_INFORMATION,C.byref(pointer),C.byref(characters)))
        error=0 if converted else C.get_last_error()
        if not converted:
            if pointer.value:report['cleanup_unknown']=True;RETAINED.append(pointer)
            report['sddl_winerror']=error;raise ValueError('sddl_conversion_failed')
        require(pointer.value,'sddl_allocation_missing')
        if C.addressof(buffer)<=pointer.value<C.addressof(buffer)+capacity:
            report['cleanup_unknown']=True;RETAINED.append(pointer);raise ValueError('sddl_allocation_alias')
        allocation,pointer.value=pointer.value,None
        try:
            require(1<=characters.value<=262144,'sddl_characters_bound')
            sddl=C.wstring_at(allocation,characters.value);terminator=sddl.find('\0');require(terminator>=0,'sddl_terminator')
            report.update(sddl_sha256=sha(sddl[:terminator].encode('utf-16-le')),sddl_characters=terminator)
        finally:
            try:
                returned_free=k.LocalFree(allocation);report['sddl_close_confirmed']=not bool(returned_free)
                if returned_free:report['cleanup_unknown']=True
            except BaseException:
                report.update(sddl_close_confirmed=False,cleanup_unknown=True);raise
        gate();report['observation_complete']=True
    except BaseException as exc:
        label=str(exc) if type(exc) is ValueError and re.fullmatch('[a-z0-9_]{1,96}',str(exc)) else 'native_or_runtime_failure'
        report['failure']=dict(type=type(exc).__name__,label=label)
    finally:
        if token is not None:
            value,token=token,None
            try:api.close(value);report['identity_token_close_confirmed']=True
            except BaseException:report['cleanup_unknown']=True
        if device is not None:
            value,device=device,None;report['device_close_attempted']=True
            try:api.close(value);report['device_close_confirmed']=True
            except BaseException:report.update(device_close_confirmed=False,cleanup_unknown=True)
        try:gate();report['within_original_deadline']=True
        except BaseException:report['within_original_deadline']=False
        if not report['within_original_deadline'] or report['cleanup_unknown'] or report['device_close_confirmed'] is not True:
            report['observation_complete']=False
        raw=(json.dumps(report,sort_keys=True,indent=2,ensure_ascii=True)+'\n').encode('ascii')
        with output.open('xb') as stream:stream.write(raw);stream.flush();os.fsync(stream.fileno())
        print(json.dumps(dict(path=output.name,bytes=len(raw),sha256=sha(raw),observation_complete=report['observation_complete'],
            open_status=report['open_status'],failure=report['failure'],cleanup_unknown=report['cleanup_unknown'])))

if __name__=='__main__':main()
