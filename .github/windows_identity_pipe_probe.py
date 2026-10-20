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


def checks(report):
    actor = report.get('actor', {})
    sid = report.get('derived_sid')
    cleanup = report.get('cleanup', {})
    return {
        'profile_identity': isinstance(sid, str) and proof.SID.fullmatch(sid) is not None
                            and report.get('observed_child_sid') == sid,
        'child_identity': actor.get('schemaVersion') == 1 and actor.get('pid') == report.get('child_pid')
                          and type(report.get('child_pid')) is int and report['child_pid'] > 0
                          and actor.get('tokenUserSid') == report.get('controller_identity',{}).get('sid')
                          and isinstance(actor.get('tokenUserSid'),str)
                          and actor.get('tokenAppContainerSid') == sid and actor.get('tokenIsAppContainer') is True
                          and actor.get('tokenElevated') is False and actor.get('isProcessInJob') is True
                          and actor.get('queriesSucceeded') is True and actor.get('errors') == [],
        'fresh_actor': isinstance(report.get('nonce'), str) and proof.NONCE.fullmatch(report['nonce']) is not None
                       and actor.get('nonce') == report['nonce'] and actor.get('mode') == 'actor-pipe',
        'transport': report.get('echo_matched') is True and report.get('exit_code') == 0
                     and report.get('pipe_eof_observed') is True and actor.get('pipeSucceeded') is True,
        'no_network_capabilities': actor.get('tokenCapabilities') == [],
        'cleanup': cleanup.get('job_closed') is True and cleanup.get('profile_deleted') is True
                   and cleanup.get('handles_closed') is True and cleanup.get('owned_aces_removed') is True and cleanup.get('job_empty') is True
                   and not cleanup.get('errors'),
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


def run(args):
    if os.name != 'nt' or not args.disposable_ci or not args.approved_security_test:
        raise PermissionError('requires an approved disposable Windows security test')
    # Reuse the audited token readers, not the historical smoke helper's
    # looser SID/scalar decoding. This observes only the current controller.
    token_spec=importlib.util.spec_from_file_location('identity_pipe_token_reader',
        Path(__file__).with_name('windows_identity_ordinary_launcher.py'))
    token_reader=importlib.util.module_from_spec(token_spec);token_spec.loader.exec_module(token_reader)
    token_api=token_reader.NativeAPI(); current=token_api.current_token()
    try:
        observed=token_api.identity(current)
        identity={'sid':observed['sid'],'pid':os.getpid(),'cid':token_api.compartment(),
                  'elevated':observed['elevated'],'appcontainer':observed['appcontainer']}
        if not token_reader.token_is_ordinary(observed):
            raise PermissionError('controller token is not an observed ordinary user')
    finally:token_api.close(current)
    if identity['elevated'] or identity['appcontainer'] or identity['cid'] != 1:
        raise PermissionError('requires ordinary user outside AppContainer in default compartment')
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
        deadline=time.monotonic()+5
        while True:
            info=Accounting(); returned=D()
            api._check(k.QueryInformationJobObject(job,1,C.byref(info),C.sizeof(info),C.byref(returned)))
            if returned.value!=C.sizeof(info): raise RuntimeError('unexpected Job accounting size')
            if info.active==0:return True
            if time.monotonic()>=deadline:return False
            time.sleep(.02)
    def sid_text(sid):
        out=P(); api._check(a.ConvertSidToStringSidW(sid,C.byref(out)))
        try: return out.value
        finally: k.LocalFree(C.cast(out,H))
    def process_sid(handle):
        token=H(); api._check(a.OpenProcessToken(handle,8,C.byref(token)))
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
        finally: api.close_handle(token.value)
    actor=args.actor.resolve(strict=True)
    if actor.suffix.lower()!='.exe' or not 512 <= actor.stat().st_size <= 8*1024*1024:
        raise ValueError('expected bounded native actor')
    digest=hashlib.sha256(actor.read_bytes()).hexdigest()
    if digest!=args.actor_sha256: raise ValueError('actor digest mismatch')
    work=args.work.resolve()
    if work.exists(): raise ValueError('fresh work directory required')
    if args.report.resolve()!=work/'report.json': raise ValueError('report must be new WORK/report.json')
    for name in ('SystemRoot','ProgramFiles','ProgramFiles(x86)'):
        if os.environ.get(name):
            protected=Path(os.environ[name]).resolve()
            if protected==work or protected in work.parents: raise ValueError('protected work directory')
    work.mkdir(parents=True); inputs=work/'inputs'; output=work/'output'; inputs.mkdir(); output.mkdir()
    exe=inputs/'actor.exe'; shutil.copyfile(actor,exe)
    nonce=secrets.token_hex(16); name='RuleProxy.IdentityProof.'+nonce
    report={'schema_version':1,'stage':'0b','nonce':nonce,'actor_sha256':digest,'network_tested':False,
            'product_acceptance':False,'privacy_qualified':False,'controller_identity':identity,'cleanup':{'errors':[]}}
    handles=set(); job=None; info=proc._ProcessInfo(); sid=H(); created=False; assigned_to_job=False
    def close(h):
        if h in handles: api.close_handle(h); handles.remove(h)
    journal={'schema_version':1,'profile':name,'nonce':nonce,'profile_created':False,'derived_sid':None}
    proof.smoke.save(work/'ownership.json',journal)
    try:
        code=ue.CreateAppContainerProfile(name,name,'Disposable identity pipe proof',None,0,C.byref(sid)) & 0xffffffff
        if code: raise OSError(code,'CreateAppContainerProfile (never reuse existing profile)')
        created=True; report['derived_sid']=sid_text(sid)
        journal.update(profile_created=True,derived_sid=report['derived_sid'])
        proof.smoke.save(work/'ownership.json',journal)
        # Grants on this fresh owned tree only. No ALL APPLICATION PACKAGES ACE.
        for path,right in ((work,'RX'),(inputs,'(OI)(CI)(RX)'),(output,'(OI)(CI)(M)')):
            subprocess.run([str(Path(os.environ['SystemRoot'])/'System32/icacls.exe'),str(path),'/grant',
                            '*'+report['derived_sid']+':'+right,'/Q'],stdin=subprocess.DEVNULL,
                           capture_output=True,timeout=15,check=True)
        class SA(C.Structure):
            _fields_=[('length',D),('security',H),('inherit',C.c_int)]
        sa=SA(C.sizeof(SA),None,True)
        child_read,parent_write,parent_read,child_write=H(),H(),H(),H()
        for read,write in ((child_read,parent_write),(parent_read,child_write)):
            api._check(k.CreatePipe(C.byref(read),C.byref(write),C.byref(sa),4096))
            handles.update((read.value,write.value))
        for handle in (parent_write,parent_read): api._check(k.SetHandleInformation(handle,1,0))
        job=api.create_job(); api.configure_job(job,proc._JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE)
        size=C.c_size_t(); k.InitializeProcThreadAttributeList(None,2,0,C.byref(size))
        attrs=C.create_string_buffer(size.value)
        api._check(k.InitializeProcThreadAttributeList(attrs,2,0,C.byref(size)))
        try:
            capabilities=proc._SecurityCapabilities(sid.value,None,0,0)
            inherited=(H*2)(child_read.value,child_write.value)
            for kind,value in ((proc._PROC_THREAD_ATTRIBUTE_SECURITY_CAPABILITIES,capabilities),(0x20002,inherited)):
                api._check(k.UpdateProcThreadAttribute(attrs,0,kind,C.byref(value),C.sizeof(value),None,None))
            startup=proc._StartupInfoEx(); startup.StartupInfo.cb=C.sizeof(startup); startup.lpAttributeList=C.cast(attrs,H)
            cmd=[str(exe),'actor-pipe',nonce,str(output/'actor.json'),str(child_read.value),str(child_write.value)]
            environment=C.create_unicode_buffer(proc._environment_block({'SystemRoot':os.environ['SystemRoot']}))
            api._check(k.CreateProcessW(str(exe),C.create_unicode_buffer(subprocess.list2cmdline(cmd)),None,None,True,
                       proc._CREATE_SUSPENDED|proc._CREATE_UNICODE_ENVIRONMENT|proc._EXTENDED_STARTUPINFO_PRESENT,
                       environment,str(output),C.byref(startup),C.byref(info)))
        finally: k.DeleteProcThreadAttributeList(attrs)
        report['child_pid']=int(info.dwProcessId)
        handles.update((info.hProcess,info.hThread))
        api.assign_job(job,info.hProcess)
        assigned_to_job=True
        report['observed_child_sid']=process_sid(info.hProcess)
        if report['observed_child_sid']!=report['derived_sid']: raise RuntimeError('child identity mismatch before resume')
        close(child_read.value); close(child_write.value)
        api.resume_thread(info.hThread); close(info.hThread)
        written=D(); payload=nonce.encode('ascii')
        api._check(k.WriteFile(parent_write,payload,len(payload),C.byref(written),None))
        if written.value!=len(payload): raise RuntimeError('partial pipe frame write')
        close(parent_write.value)
        deadline=time.monotonic()+5; available=D()
        while time.monotonic()<deadline:
            api._check(k.PeekNamedPipe(parent_read,None,0,None,C.byref(available),None))
            if available.value>=len(payload): break
            time.sleep(.02)
        else: raise TimeoutError('bounded pipe echo deadline')
        buf=C.create_string_buffer(33); count=D()
        api._check(k.ReadFile(parent_read,buf,33,C.byref(count),None))
        report['echo_matched']=count.value==32 and buf.raw[:32]==payload
        if api.wait_process(info.hProcess,5000)!=0: raise TimeoutError('actor exit deadline')
        report['exit_code']=api.exit_code(info.hProcess)
        C.set_last_error(0)
        ok=k.ReadFile(parent_read,buf,1,C.byref(count),None)
        report['pipe_eof_observed']=not ok and C.get_last_error()==109
        report['actor']=proof.smoke.read(output/'actor.json')
    except Exception as exc: report['error']=proof.smoke.failure(exc)
    finally:
        process_stopped=not bool(info.hProcess)
        job_empty=not bool(job)
        if info.hProcess and assigned_to_job:
            try: api.terminate_job(job)
            except Exception as exc: report['cleanup']['errors'].append(proof.smoke.failure(exc))
        elif info.hProcess:
            try: api.terminate_process(info.hProcess)
            except Exception as exc: report['cleanup']['errors'].append(proof.smoke.failure(exc))
        if info.hProcess:
            try:
                if api.wait_process(info.hProcess,5000)!=0: raise TimeoutError('cleanup process wait')
                process_stopped=True
            except Exception as exc: report['cleanup']['errors'].append(proof.smoke.failure(exc))
        if job:
            try:
                job_empty=wait_job_empty(job)
                report['cleanup']['job_empty']=job_empty
                if not job_empty: raise TimeoutError('cleanup Job drain')
            except Exception as exc: report['cleanup']['errors'].append(proof.smoke.failure(exc))
        for h in list(handles):
            try: close(h)
            except Exception as exc: report['cleanup']['errors'].append(proof.smoke.failure(exc))
        report['cleanup']['handles_closed']=not handles
        if job:
            try: api.close_handle(job); report['cleanup']['job_closed']=True
            except Exception as exc: report['cleanup']['errors'].append(proof.smoke.failure(exc))
        if sid: a.FreeSid(sid)
        if created and process_stopped and job_empty:
            try:
                owned_paths(work)
                subprocess.run([str(Path(os.environ['SystemRoot'])/'System32/icacls.exe'),str(work),
                                '/remove:g','*'+report['derived_sid'],'/T','/Q'],
                               stdin=subprocess.DEVNULL,capture_output=True,timeout=15,check=True)
                report['cleanup']['owned_aces_removed']=verify_no_owned_ace(work,report['derived_sid'])
            except Exception as exc: report['cleanup']['errors'].append(proof.smoke.failure(exc))
            code=ue.DeleteAppContainerProfile(name)&0xffffffff
            report['cleanup']['profile_deleted']=code==0
            if code: report['cleanup']['errors'].append({'operation':'DeleteAppContainerProfile','code':code})
        elif created:
            report['cleanup']['profile_retained_due_to_uncertain_process_exit']=True
    journal['cleanup']=report['cleanup']
    proof.smoke.save(work/'ownership.json',journal)
    report['checks']=checks(report); report['stage0b_passed']=all(report['checks'].values())
    proof.smoke.save(args.report,report)
    return 0 if report['stage0b_passed'] else 1


def main(argv=None):
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--disposable-ci',action='store_true')
    parser.add_argument('--approved-security-test',action='store_true')
    for name in ('actor','work','report'): parser.add_argument('--'+name,type=Path,required=True)
    parser.add_argument('--actor-sha256',required=True)
    return run(parser.parse_args(argv))

if __name__=='__main__': raise SystemExit(main())
