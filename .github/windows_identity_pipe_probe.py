"""Stage 0b only: zero-capability AppContainer and two inherited pipe handles.

No TCP listener, loopback exemption, firewall rule, network capability, or
Mihomo. Passing this test proves only this bounded IPC transport on this host.
Run only on an explicitly approved disposable Windows Actions machine.
"""
from __future__ import annotations
import argparse
import ctypes as C
import hashlib
import importlib.util
import json
import ntpath
import os
from pathlib import Path
import re
import secrets
import shutil
import stat
import subprocess
import time

ROOT = Path(__file__).resolve().parents[1]
SPEC = importlib.util.spec_from_file_location('identity_proof_helpers', Path(__file__).with_name('windows_identity_proof.py'))
proof = importlib.util.module_from_spec(SPEC); SPEC.loader.exec_module(proof)



class ProbePhases:
    """Shrink old phase caps against original guest QPC, never renew its epoch."""
    def __init__(self, budget, api, frequency, clock=time.monotonic):
        self.budget, self.api, self.frequency, self.clock = budget, api, frequency, clock
        self.active = budget.cutoff(30) if budget else None
        self.cleanup = budget.cutoff(10) if budget else None

    def require(self, seconds, cleanup=False):
        if self.budget:
            return self.budget.require_ms(self.cleanup if cleanup else self.active,
                                          int(seconds*1000))/1000
        return seconds

    def limit(self, seconds, cleanup=False):
        self.require(seconds, cleanup)
        if self.budget:
            return min(self.cleanup if cleanup else self.active,
                       self.budget.read()+int(seconds*self.frequency))
        return self.clock()+seconds

    def remaining(self, limit):
        if self.budget:
            return self.budget.remaining_ms(limit)
        return max(0,int((limit-self.clock())*1000))


class OneShotHandles:
    """Exact ownership; failed close is uncertain, consumed, and never retried."""
    def __init__(self, close_api):
        self.close_api = close_api
        self.pending = set()
        self.attempted = set()
        self.uncertain = False

    def add(self, handle):
        if not handle or handle in self.pending or handle in self.attempted:
            raise RuntimeError('invalid or reused owned handle')
        self.pending.add(handle)
        return handle

    def close(self, handle):
        if handle not in self.pending:
            return
        self.pending.remove(handle)
        self.attempted.add(handle)  # Consume BEFORE calling an API that may fail.
        try:
            self.close_api(handle)
        except BaseException:
            self.uncertain = True
            raise

    @property
    def confirmed_closed(self):
        return not self.pending and not self.uncertain


def prepare_owned_files(work, inputs, output, actor, exe, digest, journal, state,
                        save, copy, require_time):
    """Called inside run's finalizer before the first owned filesystem mutation."""
    require_time(15)
    work.mkdir()
    state['created'] = True
    save(work/'ownership.json', journal)
    inputs.mkdir(); output.mkdir()
    require_time(15)
    copy(actor, exe)
    copied = verify_copied_actor(exe, digest)
    require_time(15)
    return copied


def wait_bounded(api, process, phases, cleanup=False):
    limit=phases.limit(5,cleanup)
    milliseconds=phases.remaining(limit)
    if milliseconds<=0: raise TimeoutError('process phase expired before wait')
    result=api.wait_process(process,milliseconds)
    late=phases.budget is not None and phases.remaining(limit)<=0
    return result,late


def stop_owned_child(api, process, job, assigned, wait_ms, wait_job_empty, errors, attempted=False, observed_wait=None, diagnostic_error=None):
    """Best-effort termination, but only observed waits establish quiescence."""
    process_stopped, job_empty = not bool(process) and not attempted, not bool(job)
    if process:
        try:
            if assigned: api.terminate_job(job)
            else: api.terminate_process(process)
        except Exception as exc:
            if diagnostic_error: diagnostic_error(exc,'job_terminate' if assigned else 'process_terminate')
            errors.append(proof.smoke.failure(exc))
        try:
            outcome,late=observed_wait(process) if observed_wait else (api.wait_process(process,wait_ms()),False)
            if outcome != 0: raise TimeoutError('cleanup process wait')
            process_stopped=True
            if late: errors.append({'operation':'observed_process_deadline'})
        except Exception as exc:
            if diagnostic_error: diagnostic_error(exc,'process_wait')
            errors.append(proof.smoke.failure(exc))
    if job:
        try:
            job_empty=wait_job_empty(job)
            if not job_empty: raise TimeoutError('cleanup Job drain')
        except Exception as exc:
            if diagnostic_error: diagnostic_error(exc,'job_query')
            errors.append(proof.smoke.failure(exc))
    return process_stopped, job_empty


_RETAINED_FILES = []


class FileCloseUncertain(RuntimeError):
    pass


def read_bounded_file(path, maximum, expected_size=None):
    """One bounded read; retain a failed-close object rather than retrying it."""
    stream=path.open('rb')
    try:
        data=stream.read(maximum+1)
    finally:
        try:
            stream.close()  # Exactly one explicit close attempt, including read failure.
        except BaseException:
            _RETAINED_FILES.append(stream)
            raise FileCloseUncertain('bounded reader close uncertain') from None
    if len(data)>maximum or expected_size is not None and len(data)!=expected_size:
        raise RuntimeError('bounded file length changed')
    return data


def create_suspended_owned(create, check, info, owners, state):
    state['creation_attempted']=True
    try:
        result=create()
    finally:
        # Preserve any returned ownership even if the API/check boundary raises.
        if info.hProcess: owners.add(info.hProcess)
        if info.hThread: owners.add(info.hThread)
    check(result)


def verify_copied_actor(exe, expected):
    info = exe.lstat()
    if (stat.S_ISLNK(info.st_mode) or getattr(info, 'st_file_attributes', 0) & 0x400
            or not stat.S_ISREG(info.st_mode) or not 512 <= info.st_size <= 8*1024*1024):
        raise RuntimeError('invalid copied actor')
    digest = hashlib.sha256(read_bounded_file(exe,8*1024*1024,info.st_size)).hexdigest()
    if digest != expected:
        raise RuntimeError('copied actor digest mismatch')
    return digest


def read_actor_report(path):
    info=path.lstat()
    if (not stat.S_ISREG(info.st_mode) or stat.S_ISLNK(info.st_mode)
            or getattr(info,'st_file_attributes',0)&0x400 or not 1<=info.st_size<=8192):
        raise RuntimeError('invalid native actor report')
    def pairs(values):
        out={}
        for key,value in values:
            if key in out: raise ValueError('duplicate native actor key')
            out[key]=value
        return out
    def invalid_constant(value):
        raise ValueError('invalid native actor constant')
    data=read_bounded_file(path,8192,info.st_size)
    value=json.loads(data.decode('utf-8'),object_pairs_hook=pairs,parse_constant=invalid_constant)
    if type(value) is not dict: raise ValueError('native actor report object required')
    return value


def verify_suspended_child(token_api, process, job, exe, expected_sid, read_sid, stage=None):
    """Read only the held process before the caller's single ResumeThread."""
    if stage: stage('image')
    token_api.verify_image(process, exe)
    if stage: stage('job')
    token_api.verify_job(job, process)
    if stage: stage('sid')
    observed_sid = read_sid(process)
    if observed_sid != expected_sid:
        raise RuntimeError('child identity mismatch before resume')
    return observed_sid



def admit_suspended(api, token_api, info, job, exe, digest, expected_sid,
                    read_sid, owners, child_handles, require_time, state, report, stage=None):
    """Single held-process admission; state survives every failure for cleanup."""
    require_time(5)
    if stage: stage('assign')
    api.assign_job(job, info.hProcess)
    state['assigned_to_job'] = True
    report['observed_child_sid'] = verify_suspended_child(
        token_api, info.hProcess, job, exe, expected_sid, read_sid, stage)
    report['image_verified_before_resume'] = True
    if stage: stage('input_copy')
    report['copied_actor_sha256'] = verify_copied_actor(exe, digest)
    for handle in child_handles:
        owners.close(handle)
    require_time(5)
    # api.resume_thread checks the actual prior suspend count equals exactly 1.
    if stage: stage('resume')
    api.resume_thread(info.hThread)
    owners.close(info.hThread)


def pipe_result_valid(value):
    return (type(value) is dict
            and value.get('attempted') is True
            and value.get('inheritanceCleared') is True
            and value.get('nonceMatched') is True
            and value.get('requiresControllerTimeout') is True
            and type(value.get('bytesRead')) is int and value['bytesRead'] == 32
            and type(value.get('bytesWritten')) is int and value['bytesWritten'] == 32
            and type(value.get('win32Error')) is int and value['win32Error'] == 0
            and 'failure' in value and value['failure'] is None)


def checks(report):
    report = report if type(report) is dict else {}
    actor = report.get('actor', {})
    actor = actor if type(actor) is dict else {}
    sid = report.get('derived_sid')
    cleanup = report.get('cleanup', {})
    cleanup = cleanup if type(cleanup) is dict else {}
    controller = report.get('controller_identity', {})
    controller = controller if type(controller) is dict else {}
    return {
        'profile_identity': isinstance(sid, str) and proof.SID.fullmatch(sid) is not None
                            and report.get('observed_child_sid') == sid,
        'child_identity': type(actor.get('schemaVersion')) is int and actor.get('schemaVersion') == 1
                          and type(actor.get('pid')) is int and actor.get('pid') == report.get('child_pid')
                          and type(report.get('child_pid')) is int and report['child_pid'] > 0
                          and actor.get('tokenUserSid') == controller.get('sid')
                          and isinstance(actor.get('tokenUserSid'),str)
                          and actor.get('tokenAppContainerSid') == sid and actor.get('tokenIsAppContainer') is True
                          and actor.get('tokenElevated') is False and actor.get('isProcessInJob') is True
                          and actor.get('queriesSucceeded') is True and actor.get('errors') == [],
        'fresh_actor': isinstance(report.get('nonce'), str) and proof.NONCE.fullmatch(report['nonce']) is not None
                       and actor.get('nonce') == report['nonce'] and actor.get('mode') == 'actor-pipe',
        'staged_image': report.get('copied_actor_sha256') == report.get('actor_sha256')
                        and isinstance(report.get('copied_actor_sha256'),str)
                        and re.fullmatch('[0-9a-f]{64}',report['copied_actor_sha256']) is not None
                        and report.get('image_verified_before_resume') is True,
        'transport': report.get('echo_matched') is True and type(report.get('exit_code')) is int
                     and report.get('exit_code') == 0
                     and report.get('pipe_eof_observed') is True and actor.get('pipeSucceeded') is True
                     and pipe_result_valid(actor.get('pipe')), 
        'no_network_capabilities': actor.get('tokenCapabilities') == [],
        'cleanup': cleanup.get('job_closed') is True and cleanup.get('profile_deleted') is True
                   and cleanup.get('handles_closed') is True and cleanup.get('owned_aces_removed') is True and cleanup.get('job_empty') is True
                   and cleanup.get('process_exit_confirmed') is True and cleanup.get('close_uncertain') is False
                   and type(cleanup.get('errors')) is list and cleanup['errors'] == [],
        'no_error': 'error' not in report,
    }



def owned_paths(work):
    """Bound before recursion and reject symlinks/junctions before ACL mutation."""
    pending=[Path(work)]; result=[]
    while pending:
        path=pending.pop(); info=path.lstat()
        if stat.S_ISLNK(info.st_mode) or getattr(info,'st_file_attributes',0)&0x400:
            raise RuntimeError('unexpected owned tree reparse point')
        result.append(path)
        if len(result)>32: raise RuntimeError('unexpected owned tree size')
        if stat.S_ISDIR(info.st_mode):
            with os.scandir(path) as entries:
                for entry in entries:
                    pending.append(Path(entry.path))
                    if len(pending)+len(result)>32: raise RuntimeError('unexpected owned tree size')
    return result


def verify_no_owned_ace(work, sid):
    """Read back DACLs on the bounded, fresh owned tree after exact-SID removal."""
    a=C.WinDLL('advapi32',use_last_error=True); k=C.WinDLL('kernel32',use_last_error=True)
    a.GetFileSecurityW.argtypes=[C.c_wchar_p,C.c_uint32,C.c_void_p,C.c_uint32,C.POINTER(C.c_uint32)]
    a.GetFileSecurityW.restype=C.c_int
    a.ConvertSecurityDescriptorToStringSecurityDescriptorW.argtypes=[C.c_void_p,C.c_uint32,C.c_uint32,C.POINTER(C.c_wchar_p),C.POINTER(C.c_uint32)]
    a.ConvertSecurityDescriptorToStringSecurityDescriptorW.restype=C.c_int
    k.LocalFree.argtypes=[C.c_void_p];k.LocalFree.restype=C.c_void_p
    paths=owned_paths(work)
    for path in paths:
        if path.is_symlink(): raise RuntimeError('unexpected owned tree alias')
        size=C.c_uint32(); a.GetFileSecurityW(str(path),4,None,0,C.byref(size))
        if not 1<=size.value<=65536: raise RuntimeError('unexpected DACL size')
        buf=C.create_string_buffer(size.value)
        if not a.GetFileSecurityW(str(path),4,buf,size,C.byref(size)): raise C.WinError(C.get_last_error())
        text=C.c_wchar_p()
        if not a.ConvertSecurityDescriptorToStringSecurityDescriptorW(buf,1,4,C.byref(text),None):
            raise C.WinError(C.get_last_error())
        try:
            if sid in text.value: return False
        finally:k.LocalFree(C.cast(text,C.c_void_p))
    return True


def checked_sid_pointer(buffer, returned):
    """Validate a TOKEN_APPCONTAINER_INFORMATION pointer before dereference."""
    if not C.sizeof(C.c_void_p) <= returned <= len(buffer):
        raise RuntimeError('invalid token SID returned length')
    pointer=C.c_void_p.from_buffer(buffer).value
    beginning=C.addressof(buffer)
    if not pointer or pointer < beginning or pointer+8 > beginning+returned:
        raise RuntimeError('token SID pointer outside returned buffer')
    revision=C.c_ubyte.from_address(pointer).value
    count=C.c_ubyte.from_address(pointer+1).value
    if revision!=1 or count>15 or pointer+8+count*4 > beginning+returned:
        raise RuntimeError('invalid token SID bytes')
    return pointer



class KnownFolderFailure(RuntimeError):
    """Fixed label only; HRESULT is carried separately in closed metadata."""


class _KnownFolderGuid(C.Structure):
    _fields_=[('Data1',C.c_uint32),('Data2',C.c_uint16),('Data3',C.c_uint16),
              ('Data4',C.c_ubyte*8)]


LOCAL_APPDATA_GUID=_KnownFolderGuid(0xF1B32785,0x6FBA,0x4FCF,
    (C.c_ubyte*8)(0x9D,0x55,0x7B,0x8E,0x7F,0x15,0x70,0x91))


class KnownFolderAPI:
    """Bind every cleanup ABI BEFORE obtaining COM state or an allocation."""
    def __init__(self):
        self.shell=C.WinDLL('shell32',use_last_error=True)
        self.ole=C.WinDLL('ole32',use_last_error=True)
        for owner,name,arguments,result in (
            (self.ole,'CoInitializeEx',[C.c_void_p,C.c_uint32],C.c_int32),
            (self.ole,'CoUninitialize',[],None),
            (self.ole,'CoTaskMemFree',[C.c_void_p],None),
            (self.shell,'SHGetKnownFolderPath',[C.POINTER(_KnownFolderGuid),C.c_uint32,
                                               C.c_void_p,C.POINTER(C.c_void_p)],C.c_int32)):
            function=getattr(owner,name);function.argtypes=arguments;function.restype=result

    def initialize(self):
        return self.ole.CoInitializeEx(None,2)  # Fixed STA; no retry/apartment fallback.

    def query(self,out):
        return self.shell.SHGetKnownFolderPath(C.byref(LOCAL_APPDATA_GUID),0,None,C.byref(out))

    def release(self,pointer):
        self.ole.CoTaskMemFree(pointer)

    def uninitialize(self):
        self.ole.CoUninitialize()


def hresult_uint32(value):
    if type(value) is not int or not -(2**31)<=value<2**31:
        raise KnownFolderFailure('invalid native HRESULT')
    return value & 0xffffffff


def bounded_utf16_path(pointer):
    if not pointer: raise KnownFolderFailure('known folder pointer missing')
    units=bytearray()
    for index in range(32768):
        value=C.c_uint16.from_address(pointer+index*2).value
        if value==0:
            if not units: raise KnownFolderFailure('known folder path empty')
            return bytes(units).decode('utf-16-le','strict')
        if index==32767: raise KnownFolderFailure('known folder path overbound')
        units.extend(value.to_bytes(2,'little'))
    raise KnownFolderFailure('known folder path unterminated')


def checked_local_appdata_path(value, lstat=None):
    """Existing local DOS directory only; snapshots are not continuous locks."""
    if (type(value) is not str or not value or len(value.encode('utf-16-le','strict'))//2>32767
            or any(ord(char)<32 or char in '/:*?"<>|%' for char in value[2:])):
        raise KnownFolderFailure('known folder path syntax')
    drive,tail=ntpath.splitdrive(value)
    if re.fullmatch('[A-Za-z]:',drive) is None or not tail.startswith('\\'):
        raise KnownFolderFailure('known folder path not local absolute')
    parts=tail[1:].split('\\')
    if not 1<=len(parts)<=32 or any(not part or part in ('.','..') or part.endswith((' ','.')) for part in parts):
        raise KnownFolderFailure('known folder path components')
    read=lstat if lstat is not None else lambda path:Path(path).lstat()
    current=drive+'\\'
    for part in [None]+parts:
        if part is not None:current=ntpath.join(current,part)
        info=read(current)
        if (not stat.S_ISDIR(info.st_mode) or stat.S_ISLNK(info.st_mode)
                or getattr(info,'st_file_attributes',0)&0x400):
            raise KnownFolderFailure('known folder directory not admitted')
    return value


def resolve_local_appdata(api, require_time, metadata):
    """One query; retain the first error while independently attempting cleanup."""
    pointer=C.c_void_p();initialized=False;path=None;primary=None
    require_time(5)
    try:
        metadata['com'][0]=True
        raw=api.initialize()
        metadata['com'][1]=hresult_uint32(raw)
        if metadata['com'][1] not in (0,1):
            raise KnownFolderFailure('COM initialization not admitted')
        initialized=True
        require_time(5)
        metadata['lookup_state']='api_failed'  # Entered call even if it raises.
        raw=api.query(pointer)
        metadata['hresult']=hresult_uint32(raw)
        if metadata['hresult']!=0:raise KnownFolderFailure('known folder lookup not S_OK')
        metadata['lookup_state']='path_rejected'
        require_time(5)
        path=checked_local_appdata_path(bounded_utf16_path(pointer.value))
        metadata['lookup_state']='ready'
    except BaseException as exc:
        primary=exc
    finally:
        if pointer.value:
            metadata['release_attempted']=True
            try:
                api.release(pointer)  # One attempt; void return is not readback.
                metadata['release_returned']=True
            except BaseException as exc:
                if primary is None:primary=exc
        if initialized:
            metadata['com'][2]=True
            try:
                api.uninitialize()  # Balance S_OK and S_FALSE once, never failures.
                metadata['com'][3]=True
            except BaseException as exc:
                if primary is None:primary=exc
        try:
            require_time(5)
            metadata['deadline_verified']=True
        except BaseException as exc:
            if primary is None:primary=exc
    if primary is not None:raise primary
    return path


def child_environment_block(proc, system_root, local_appdata, metadata):
    values={'SystemRoot':system_root,'LOCALAPPDATA':local_appdata}
    block=proc._environment_block(values)
    rows=block.split('\0')
    expected={key.upper():value for key,value in values.items()}
    actual={}
    valid=block.endswith('\0\0')
    for row in rows[:-2]:
        key,separator,value=row.partition('=')
        if not separator or key.upper() in actual:valid=False
        actual[key.upper()]=value
    metadata['exact_child_keyset']=valid and actual==expected
    if not metadata['exact_child_keyset']:
        raise KnownFolderFailure('child environment keyset mismatch')
    return block

def run(args, diagnostic=None, child_environment=None):
    # A record is supplied only by the new scoped main path; legacy callers do
    # not load diagnostics or gain an alternate execution/error path.
    helper=None
    if diagnostic is not None:
        helper=diagnostic_helpers()
    def stage(value):
        if helper: helper.diagnostic_stage(diagnostic,value)
    def failed(exc,operation=None):
        if helper:
            if operation is None:
                operation={'qpc':'qpc','initial_token':'token','identity':'token','sid':'token',
                           'create':'process_create','assign':'job_assign','image':'image',
                           'resume':'resume','pipes':'pipe','echo_write':'pipe','echo_read':'pipe',
                           'eof':'pipe','exit':'process_wait','profile_create':'profile',
                           'acl_grant':'acl'}.get(diagnostic[0],'other')
            helper.diagnostic_error(diagnostic,exc,operation)
    stage('arguments')
    if os.name != 'nt' or not args.disposable_ci or not args.approved_security_test:
        raise PermissionError('requires an approved disposable Windows security test')
    # Reuse the audited token readers, not the historical smoke helper's
    # looser SID/scalar decoding. This observes only the current controller.
    if helper:
        token_reader=helper
    else:
        token_spec=importlib.util.spec_from_file_location('identity_pipe_token_reader',
            Path(__file__).with_name('windows_identity_ordinary_launcher.py'))
        token_reader=importlib.util.module_from_spec(token_spec);token_spec.loader.exec_module(token_reader)
    stage('initial_token')
    token_api=token_reader.NativeAPI()
    stage('qpc')
    supplied=(getattr(args,'deadline_qpc',None),getattr(args,'qpc_frequency',None))
    if (supplied[0] is None) != (supplied[1] is None):
        raise ValueError('paired QPC deadline required')
    budget=token_reader.QpcBudget(token_api,*supplied) if supplied[0] is not None else None
    case_nonce=getattr(args,'case_nonce',None)
    if case_nonce is not None and (type(case_nonce) is not str or re.fullmatch('[0-9a-f]{32}',case_nonce) is None):
        raise ValueError('invalid case nonce')
    if (budget is not None) != (case_nonce is not None):
        raise ValueError('QPC integration requires all contract fields')
    phases=ProbePhases(budget,token_api,supplied[1])
    require_time,phase_limit,phase_remaining=phases.require,phases.limit,phases.remaining
    require_time(15)
    stage('initial_token')
    current=token_api.current_token()
    current_owner=OneShotHandles(token_api.close); current_owner.add(current)
    try:
        stage('identity')
        observed=token_api.identity(current)
        identity={'sid':observed['sid'],'pid':os.getpid(),'cid':token_api.compartment(),
                  'elevated':observed['elevated'],'appcontainer':observed['appcontainer']}
        if not token_reader.token_is_ordinary(observed):
            raise PermissionError('controller token is not an observed ordinary user')
    finally:current_owner.close(current)
    if identity['elevated'] or identity['appcontainer'] or identity['cid'] != 1:
        raise PermissionError('requires ordinary user outside AppContainer in default compartment')
    local_appdata=None
    if budget is not None:
        if child_environment is None: child_environment=token_reader.default_child_environment()
        stage('known_folder')
        local_appdata=resolve_local_appdata(KnownFolderAPI(),require_time,child_environment)
    # Reuse existing typed structures and Job owner, never its network exemption APIs.
    import sys
    sys.path.insert(0, str(ROOT))
    from ruleproxy import windows_app_process as proc
    api = proc._KernelAPI(); k, a = api.kernel, api.advapi
    H, D, P = C.c_void_p, C.c_uint32, C.c_wchar_p
    ue = C.WinDLL('userenv', use_last_error=True)
    for owner, name, types, result in (
        (ue,'CreateAppContainerProfile',[P,P,P,H,D,C.POINTER(H)],C.c_long),
        (ue,'DeleteAppContainerProfile',[P],C.c_long),
        (a,'FreeSid',[H],H), (a,'ConvertSidToStringSidW',[H,C.POINTER(P)],C.c_int),
        (k,'CreatePipe',[C.POINTER(H),C.POINTER(H),H,D],C.c_int),
        (k,'SetHandleInformation',[H,D,D],C.c_int),
        (k,'QueryInformationJobObject',[H,C.c_int,H,D,C.POINTER(D)],C.c_int),
        (k,'WriteFile',[H,H,D,C.POINTER(D),H],C.c_int),
        (k,'ReadFile',[H,H,D,C.POINTER(D),H],C.c_int),
        (k,'PeekNamedPipe',[H,H,D,C.POINTER(D),C.POINTER(D),C.POINTER(D)],C.c_int),
    ):
        fn=getattr(owner,name); fn.argtypes,fn.restype=types,result
    def wait_job_empty(job):
        class Accounting(C.Structure):
            _fields_=[('times',C.c_int64*4),('page_faults',D),('total',D),('active',D),('terminated',D)]
        deadline=phase_limit(5,True)
        while True:
            info=Accounting(); returned=D()
            api._check(k.QueryInformationJobObject(job,1,C.byref(info),C.sizeof(info),C.byref(returned)))
            if returned.value!=C.sizeof(info): raise RuntimeError('unexpected Job accounting size')
            if info.active==0:
                if budget and phase_remaining(deadline)<=0:
                    report['cleanup']['errors'].append({'operation':'observed_job_deadline'})
                return True
            if phase_remaining(deadline)<=0:return False
            time.sleep(min(.02,phase_remaining(deadline)/1000))
    def sid_text(sid):
        out=P(); api._check(a.ConvertSidToStringSidW(sid,C.byref(out)))
        try: return out.value
        finally: k.LocalFree(C.cast(out,H))
    def process_sid(handle):
        token=H(); api._check(a.OpenProcessToken(handle,8,C.byref(token)))
        owners.add(token.value)
        try:
            size=D(); C.set_last_error(0)
            success=a.GetTokenInformation(token,31,None,0,C.byref(size))
            error=C.get_last_error()
            if success: raise RuntimeError('unexpected token SID size probe success')
            if error!=122: raise C.WinError(error)
            if not C.sizeof(H) <= size.value <= 65536: raise RuntimeError('invalid token SID length')
            buf=C.create_string_buffer(size.value)
            api._check(a.GetTokenInformation(token,31,buf,len(buf),C.byref(size)))
            return sid_text(checked_sid_pointer(buf,size.value))
        finally: owners.close(token.value)
    stage('input_validation')
    actor=args.actor.resolve(strict=True)
    if actor.suffix.lower()!='.exe' or not 512 <= actor.stat().st_size <= 8*1024*1024:
        raise ValueError('expected bounded native actor')
    digest=verify_copied_actor(actor,args.actor_sha256)
    work=args.work.resolve()
    if work.exists(): raise ValueError('fresh work directory required')
    if args.report.resolve()!=work/'report.json': raise ValueError('report must be new WORK/report.json')
    for name in ('SystemRoot','ProgramFiles','ProgramFiles(x86)'):
        if os.environ.get(name):
            protected=Path(os.environ[name]).resolve()
            if protected==work or protected in work.parents: raise ValueError('protected work directory')
    inputs=work/'inputs'; output=work/'output'; exe=inputs/'actor.exe'
    nonce=case_nonce if case_nonce is not None else secrets.token_hex(16)
    name='RuleProxy.IdentityProof.'+nonce
    report={'schema_version':1,'stage':'0b','nonce':nonce,'actor_sha256':digest,'network_tested':False,
            'product_acceptance':False,'privacy_qualified':False,'controller_identity':identity,'cleanup':{'errors':[]}}
    if budget: report.update(deadline_qpc=supplied[0],qpc_frequency=supplied[1])
    owners=OneShotHandles(api.close_handle); job_owner=OneShotHandles(api.close_handle)
    handles=owners.pending; close=owners.close
    job=None; info=proc._ProcessInfo(); sid=H(); created=False; state={'assigned_to_job':False,'creation_attempted':False}
    work_state={'created':False}
    journal={'schema_version':1,'profile':name,'nonce':nonce,'profile_created':False,'derived_sid':None}
    try:
        stage('input_copy')
        report['copied_actor_sha256']=prepare_owned_files(
            work,inputs,output,actor,exe,digest,journal,work_state,
            proof.smoke.save,shutil.copyfile,require_time)
        stage('profile_create')
        code=ue.CreateAppContainerProfile(name,name,'Disposable identity pipe proof',None,0,C.byref(sid)) & 0xffffffff
        if code: raise OSError(code,'CreateAppContainerProfile (never reuse existing profile)')
        created=True; report['derived_sid']=sid_text(sid)
        journal.update(profile_created=True,derived_sid=report['derived_sid'])
        proof.smoke.save(work/'ownership.json',journal)
        # Grants on this fresh owned tree only. No ALL APPLICATION PACKAGES ACE.
        stage('acl_grant')
        for path,right in ((work,'RX'),(inputs,'(OI)(CI)(RX)'),(output,'(OI)(CI)(M)')):
            subprocess.run([str(Path(os.environ['SystemRoot'])/'System32/icacls.exe'),str(path),'/grant',
                            '*'+report['derived_sid']+':'+right,'/Q'],stdin=subprocess.DEVNULL,
                           capture_output=True,timeout=require_time(15),check=True)
        stage('pipes')
        class SA(C.Structure):
            _fields_=[('length',D),('security',H),('inherit',C.c_int)]
        sa=SA(C.sizeof(SA),None,True)
        child_read,parent_write,parent_read,child_write=H(),H(),H(),H()
        for read,write in ((child_read,parent_write),(parent_read,child_write)):
            api._check(k.CreatePipe(C.byref(read),C.byref(write),C.byref(sa),4096))
            owners.add(read.value); owners.add(write.value)
        for handle in (parent_write,parent_read): api._check(k.SetHandleInformation(handle,1,0))
        require_time(5)
        stage('job')
        job=api.create_job(); job_owner.add(job)
        api.configure_job(job,proc._JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE)
        size=C.c_size_t(); k.InitializeProcThreadAttributeList(None,2,0,C.byref(size))
        if not 1 <= size.value <= 65536: raise RuntimeError('invalid attribute size')
        attrs=C.create_string_buffer(size.value)
        api._check(k.InitializeProcThreadAttributeList(attrs,2,0,C.byref(size)))
        try:
            capabilities=proc._SecurityCapabilities(sid.value,None,0,0)
            inherited=(H*2)(child_read.value,child_write.value)
            for kind,value in ((proc._PROC_THREAD_ATTRIBUTE_SECURITY_CAPABILITIES,capabilities),(0x20002,inherited)):
                api._check(k.UpdateProcThreadAttribute(attrs,0,kind,C.byref(value),C.sizeof(value),None,None))
            startup=proc._StartupInfoEx(); startup.StartupInfo.cb=C.sizeof(startup); startup.lpAttributeList=C.cast(attrs,H)
            cmd=[str(exe),'actor-pipe',nonce,str(output/'actor.json'),str(child_read.value),str(child_write.value)]
            block=(child_environment_block(proc,os.environ['SystemRoot'],local_appdata,child_environment)
                   if budget is not None else proc._environment_block({'SystemRoot':os.environ['SystemRoot']}))
            environment=C.create_unicode_buffer(block)
            require_time(5)
            stage('create')
            create_suspended_owned(lambda:k.CreateProcessW(str(exe),C.create_unicode_buffer(subprocess.list2cmdline(cmd)),None,None,True,
                       proc._CREATE_SUSPENDED|proc._CREATE_UNICODE_ENVIRONMENT|proc._EXTENDED_STARTUPINFO_PRESENT,
                       environment,str(output),C.byref(startup),C.byref(info)),api._check,info,owners,state)
        finally: k.DeleteProcThreadAttributeList(attrs)
        report['child_pid']=int(info.dwProcessId)
        admit_suspended(api,token_api,info,job,exe,digest,report['derived_sid'],
                        process_sid,owners,(child_read.value,child_write.value),
                        require_time,state,report,stage)
        require_time(5)
        stage('echo_write')
        written=D(); payload=nonce.encode('ascii')
        api._check(k.WriteFile(parent_write,payload,len(payload),C.byref(written),None))
        if written.value!=len(payload): raise RuntimeError('partial pipe frame write')
        close(parent_write.value)
        stage('echo_read')
        deadline=phase_limit(5); available=D()
        while phase_remaining(deadline)>0:
            api._check(k.PeekNamedPipe(parent_read,None,0,None,C.byref(available),None))
            if available.value>=len(payload): break
            time.sleep(min(.02,phase_remaining(deadline)/1000))
        else: raise TimeoutError('bounded pipe echo deadline')
        buf=C.create_string_buffer(33); count=D()
        api._check(k.ReadFile(parent_read,buf,33,C.byref(count),None))
        report['echo_matched']=count.value==32 and buf.raw[:32]==payload
        stage('exit')
        wait_result,wait_late=wait_bounded(api,info.hProcess,phases)
        if wait_result!=0: raise TimeoutError('actor exit deadline')
        report['exit_code']=api.exit_code(info.hProcess)
        if wait_late: raise TimeoutError('observed actor exit after phase deadline')
        require_time(5)
        C.set_last_error(0)
        stage('eof')
        ok=k.ReadFile(parent_read,buf,1,C.byref(count),None)
        report['pipe_eof_observed']=not ok and C.get_last_error()==109
        require_time(5)
        stage('native_parse')
        report['actor']=read_actor_report(output/'actor.json')
        require_time(5)
    except Exception as exc:
        failed(exc)
        report['error']=proof.smoke.failure(exc)
        if isinstance(exc,FileCloseUncertain): report['reader_close_uncertain']=True
    finally:
        stage('cleanup')
        process_stopped,job_empty=stop_owned_child(
            api,info.hProcess,job,state['assigned_to_job'],
            lambda:int(require_time(5,True)*1000),wait_job_empty,report['cleanup']['errors'],
            attempted=state['creation_attempted'],
            observed_wait=lambda process:wait_bounded(api,process,phases,True),diagnostic_error=failed)
        report['cleanup']['job_empty']=job_empty
        for h in list(handles):
            try: close(h)
            except Exception as exc:
                failed(exc,'close')
                report['cleanup']['errors'].append(proof.smoke.failure(exc))
        report['cleanup']['handles_closed']=owners.confirmed_closed
        report['cleanup']['process_exit_confirmed']=process_stopped
        if job:
            try: job_owner.close(job); report['cleanup']['job_closed']=job_owner.confirmed_closed
            except Exception as exc:
                failed(exc,'close')
                report['cleanup']['errors'].append(proof.smoke.failure(exc))
        if sid:
            try:
                if a.FreeSid(sid): raise RuntimeError('FreeSid failed')
            except Exception as exc:
                failed(exc,'close')
                report['cleanup']['errors'].append(proof.smoke.failure(exc))
        if created and process_stopped and job_empty:
            try:
                owned_paths(work)
                subprocess.run([str(Path(os.environ['SystemRoot'])/'System32/icacls.exe'),str(work),
                                '/remove:g','*'+report['derived_sid'],'/T','/Q'],
                               stdin=subprocess.DEVNULL,capture_output=True,timeout=require_time(15,True),check=True)
                report['cleanup']['owned_aces_removed']=verify_no_owned_ace(work,report['derived_sid'])
            except Exception as exc:
                failed(exc,'acl')
                report['cleanup']['errors'].append(proof.smoke.failure(exc))
            if report['cleanup'].get('owned_aces_removed') is True:
                try:
                    require_time(5,True)
                    code=ue.DeleteAppContainerProfile(name)&0xffffffff
                    report['cleanup']['profile_deleted']=code==0
                    if code: report['cleanup']['errors'].append({'operation':'DeleteAppContainerProfile','code':code})
                except Exception as exc:
                    failed(exc,'profile')
                    report['cleanup']['errors'].append(proof.smoke.failure(exc))
            else:
                report['cleanup']['profile_retained_due_to_uncertain_acl_cleanup']=True
        elif created:
            report['cleanup']['profile_retained_due_to_uncertain_process_exit']=True
        report['cleanup']['close_uncertain']=(owners.uncertain or job_owner.uncertain
                                              or report.get('reader_close_uncertain') is True)
        if budget:
            try: require_time(1,True)
            except Exception as exc:
                failed(exc,'qpc')
                report['cleanup']['errors'].append(proof.smoke.failure(exc))
    if report['cleanup']['errors'] and helper:
        helper.diagnostic_error(diagnostic,RuntimeError('cleanup observation failed'),'other')
    if diagnostic is not None: report['diagnostic_execution']=list(diagnostic)
    if child_environment is not None: report['child_environment']=dict(child_environment,com=list(child_environment['com']))
    stage('report')
    journal['cleanup']=report['cleanup']
    if work_state['created']: proof.smoke.save(work/'ownership.json',journal)
    report['checks']=checks(report); report['stage0b_passed']=all(report['checks'].values())
    if work_state['created']: proof.smoke.save(args.report,report)
    stage('completed')
    return 0 if report['stage0b_passed'] else 1


_DIAGNOSTIC_HELPERS=None


def diagnostic_helpers():
    global _DIAGNOSTIC_HELPERS
    if _DIAGNOSTIC_HELPERS is not None: return _DIAGNOSTIC_HELPERS
    spec=importlib.util.spec_from_file_location('identity_pipe_diagnostic_helpers',
        Path(__file__).with_name('windows_identity_ordinary_launcher.py'))
    module=importlib.util.module_from_spec(spec);spec.loader.exec_module(module)
    _DIAGNOSTIC_HELPERS=module
    return module


def main(argv=None):
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--disposable-ci',action='store_true')
    parser.add_argument('--approved-security-test',action='store_true')
    for name in ('actor','work','report'): parser.add_argument('--'+name,type=Path,required=True)
    parser.add_argument('--actor-sha256',required=True)
    parser.add_argument('--deadline-qpc',type=int)
    parser.add_argument('--qpc-frequency',type=int)
    parser.add_argument('--case-nonce')
    args=parser.parse_args(argv)
    scoped=any(getattr(args,key,None) is not None for key in ('deadline_qpc','qpc_frequency','case_nonce'))
    if not scoped: return run(args)
    helper=diagnostic_helpers();diagnostic=helper.diagnostic_new()
    child_environment=helper.default_child_environment()
    try:
        return run(args,diagnostic,child_environment)
    except BaseException as exc:
        helper.diagnostic_error(diagnostic,exc)
        raise
    finally:
        helper.emit_scoped_diagnostic(args,diagnostic,child_environment=child_environment)

if __name__=='__main__': raise SystemExit(main())
