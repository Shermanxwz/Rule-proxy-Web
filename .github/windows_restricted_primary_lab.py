"""Disposable Windows SYSTEM experiment; not product code.

Owns a temporary standard account, private window station/desktop, and one
empty compartment. Never changes Windows/Program Files ACLs. Run using SYSTEM
scheduled task, pass the existing compartment lab and DNS probe paths.
"""
from __future__ import annotations
import argparse
import ctypes as C
from ctypes import wintypes as W
import importlib.util
import json
import os
from pathlib import Path
import secrets
import shutil
import subprocess
import sys
import threading
import time
import traceback

DNS_CASES = (
    ('getaddrinfo', 'standard'),
    ('DnsQuery_W', 'standard'), ('DnsQuery_W', 'wire'),
    ('DnsQueryEx', 'standard'), ('DnsQueryEx', 'wire'),
    ('Resolve-DnsName', 'standard'),
)

class SA(C.Structure):
    _fields_ = [('length', W.DWORD), ('descriptor', C.c_void_p), ('inherit', W.BOOL)]
class SIDATTR(C.Structure):
    _fields_ = [('sid', C.c_void_p), ('attributes', W.DWORD)]
class GROUPS(C.Structure):
    _fields_ = [('count', W.DWORD), ('groups', SIDATTR * 1)]
class PROFILE(C.Structure):
    _fields_ = [('size', W.DWORD), ('flags', W.DWORD), ('username', W.LPWSTR),
        ('profilepath', W.LPWSTR), ('defaultpath', W.LPWSTR), ('servername', W.LPWSTR),
        ('policy', W.LPWSTR), ('profile', W.HANDLE)]
class LUID(C.Structure):
    _fields_ = [('low', W.DWORD), ('high', W.LONG)]
class PRIVILEGES(C.Structure):
    _fields_ = [('count', W.DWORD), ('luid', LUID), ('attributes', W.DWORD)]


def bind(owner, name, args, result):
    f = getattr(owner, name); f.argtypes, f.restype = args, result; return f


class Experiment:
    def __init__(self, args, lab):
        self.args, self.lab = args, lab
        self.work = Path(args.work).resolve()
        for key in ['SystemRoot','ProgramFiles','ProgramFiles(x86)']:
            protected = os.environ.get(key)
            if protected and (self.work == Path(protected).resolve() or Path(protected).resolve() in self.work.parents):
                raise ValueError('work must be outside Windows and Program Files')
        if self.work.exists():
            raise ValueError('work must be a new disposable directory')
        self.work.mkdir(parents=True)
        self.n = lab.Native(); self.a, self.k = self.n.a, self.n.k
        self.report = {'started': time.time(), 'identity': self.n.token_user(),
            'scope': 'disposable primary-token compatibility experiment; no product qualification',
            'variants': {}, 'cleanup': {}, 'system_acl_changes': False}
        self.account = None; self.token = W.HANDLE(); self.loaded = None
        self.desktop = self.station = self.oldstation = None
        self.controller = self.fixture = self.direct = None
        self.bits_names = []
        self.allocated_sids = []
        self.custom = 'S-1-5-21-' + '-'.join(str(secrets.randbelow(2**31-1)+1) for _ in range(3)) + '-31337'
        P = C.c_void_p
        bind(self.a, 'ConvertStringSidToSidW', [W.LPCWSTR, C.POINTER(P)], W.BOOL)
        bind(self.a, 'ConvertStringSecurityDescriptorToSecurityDescriptorW', [W.LPCWSTR,W.DWORD,C.POINTER(P),C.POINTER(W.DWORD)],W.BOOL)
        bind(self.a, 'GetSecurityDescriptorDacl', [P,C.POINTER(W.BOOL),C.POINTER(P),C.POINTER(W.BOOL)],W.BOOL)
        bind(self.a, 'SetNamedSecurityInfoW', [W.LPWSTR,W.DWORD,W.DWORD,P,P,P,P],W.DWORD)
        bind(self.k, 'QueryInformationJobObject', [W.HANDLE,C.c_int,P,W.DWORD,C.POINTER(W.DWORD)],W.BOOL)
        bind(self.k, 'QueryFullProcessImageNameW', [W.HANDLE,W.DWORD,W.LPWSTR,C.POINTER(W.DWORD)],W.BOOL)
        bind(self.a, 'IsTokenRestricted', [W.HANDLE], W.BOOL)
        bind(self.a, 'CreateRestrictedToken', [W.HANDLE,W.DWORD,W.DWORD,P,W.DWORD,P,W.DWORD,C.POINTER(SIDATTR),C.POINTER(W.HANDLE)],W.BOOL)
        bind(self.a, 'SetTokenInformation', [W.HANDLE,C.c_int,P,W.DWORD],W.BOOL)
        bind(self.a, 'CreateProcessAsUserW', [W.HANDLE,W.LPCWSTR,W.LPWSTR,P,P,W.BOOL,W.DWORD,P,W.LPCWSTR,C.POINTER(lab.STARTUPINFOW),C.POINTER(lab.PROCESS_INFORMATION)],W.BOOL)
        self.u = C.WinDLL('user32',use_last_error=True)
        bind(self.u,'GetProcessWindowStation',[],W.HANDLE)
        bind(self.u,'SetProcessWindowStation',[W.HANDLE],W.BOOL)
        bind(self.u,'CreateWindowStationW',[W.LPCWSTR,W.DWORD,W.DWORD,C.POINTER(SA)],W.HANDLE)
        bind(self.u,'CreateDesktopW',[W.LPCWSTR,P,P,W.DWORD,W.DWORD,C.POINTER(SA)],W.HANDLE)
        bind(self.u,'CloseDesktop',[W.HANDLE],W.BOOL)
        bind(self.u,'CloseWindowStation',[W.HANDLE],W.BOOL)
        self.ue=C.WinDLL('userenv',use_last_error=True)
        bind(self.ue,'LoadUserProfileW',[W.HANDLE,C.POINTER(PROFILE)],W.BOOL)
        bind(self.ue,'UnloadUserProfile',[W.HANDLE,W.HANDLE],W.BOOL)
        bind(self.ue,'CreateEnvironmentBlock',[C.POINTER(P),W.HANDLE,W.BOOL],W.BOOL)
        bind(self.ue,'DestroyEnvironmentBlock',[P],W.BOOL)
        bind(self.ue,'DeleteProfileW',[W.LPCWSTR,W.LPCWSTR,W.LPCWSTR],W.BOOL)

    def check(self, ok, what):
        return self.n.check(ok,what)

    def save(self):
        self.lab.write_json(self.work/'report.json',self.report)

    def info(self, token, cls):
        size=W.DWORD(); self.a.GetTokenInformation(token,cls,None,0,C.byref(size))
        buf=C.create_string_buffer(max(size.value,64))
        self.check(self.a.GetTokenInformation(token,cls,buf,len(buf),C.byref(size)),'GetTokenInformation')
        return buf

    def sidtext(self,p):
        value=W.LPWSTR(); self.check(self.a.ConvertSidToStringSidW(p,C.byref(value)),'ConvertSid')
        try: return value.value
        finally: self.k.LocalFree(C.cast(value,C.c_void_p))

    def sid(self,text):
        p=C.c_void_p(); self.check(self.a.ConvertStringSidToSidW(text,C.byref(p)),'ParseSid')
        self.allocated_sids.append(p); return p

    def groups(self,token,cls):
        buf=self.info(token,cls); count=C.cast(buf,C.POINTER(W.DWORD))[0]
        rows=C.cast(C.addressof(buf)+GROUPS.groups.offset,C.POINTER(SIDATTR))
        return [{'sid':self.sidtext(rows[i].sid),'attributes':int(rows[i].attributes)} for i in range(count)]

    def sd(self,sids):
        text='D:'+''.join('(A;;GA;;;'+x+')' for x in dict.fromkeys(['SY',*sids]))
        p=C.c_void_p(); self.check(self.a.ConvertStringSecurityDescriptorToSecurityDescriptorW(text,1,C.byref(p),None),'ParseSD')
        return p

    def privileges(self):
        bind(self.a,'LookupPrivilegeValueW',[W.LPCWSTR,W.LPCWSTR,C.POINTER(LUID)],W.BOOL)
        bind(self.a,'AdjustTokenPrivileges',[W.HANDLE,W.BOOL,C.POINTER(PRIVILEGES),W.DWORD,C.c_void_p,C.c_void_p],W.BOOL)
        token=W.HANDLE(); self.check(self.a.OpenProcessToken(self.k.GetCurrentProcess(),0x28,C.byref(token)),'Open SYSTEM token')
        try:
            for name in ['SeAssignPrimaryTokenPrivilege','SeIncreaseQuotaPrivilege','SeBackupPrivilege','SeRestorePrivilege']:
                priv=PRIVILEGES();priv.count=1;priv.attributes=2
                self.check(self.a.LookupPrivilegeValueW(None,name,C.byref(priv.luid)),'LookupPrivilegeValue')
                C.set_last_error(0)
                self.check(self.a.AdjustTokenPrivileges(token,False,C.byref(priv),0,None,None),'AdjustTokenPrivileges')
                if C.get_last_error() == 1300:
                    raise OSError(1300, 'required SYSTEM privilege unavailable: ' + name)
        finally:self.k.CloseHandle(token)

    def make_user(self):
        net=C.WinDLL('netapi32',use_last_error=True)
        bind(net,'NetUserAdd',[W.LPCWSTR,W.DWORD,C.c_void_p,C.POINTER(W.DWORD)],W.DWORD)
        bind(net,'NetLocalGroupAddMembers',[W.LPCWSTR,W.LPCWSTR,W.DWORD,C.c_void_p,W.DWORD],W.DWORD)
        name='rprt'+secrets.token_hex(5);password=secrets.token_urlsafe(24)+'aA1!'
        info=self.lab.USER_INFO_1(name,password,0,1,None,'RuleProxy disposable restricted token lab',0x10201,None)
        parm=W.DWORD();code=int(net.NetUserAdd(None,1,C.byref(info),C.byref(parm)))
        if code:raise OSError(code,'NetUserAdd')
        self.account=name
        # Hosted Windows runners use the English local group name; record any failure.
        member=W.LPWSTR(name); group=int(net.NetLocalGroupAddMembers(None,'Users',3,C.byref(member),1))
        self.check(self.a.LogonUserW(name,'.',password,2,0,C.byref(self.token)),'LogonUser')
        self.user_sid=self.n.token_user(self.token)
        self.logon_sid=next(x['sid'] for x in self.groups(self.token,2) if x['attributes'] & 0xC0000000==0xC0000000)
        self.report['user']={'name':name,'sid':self.user_sid,'group_add_status':group,'logon_sid':self.logon_sid,'groups':self.groups(self.token,2)}
        self.grant(self.work,[self.user_sid,'S-1-5-12',self.custom,self.logon_sid])
        profile=PROFILE();profile.size=C.sizeof(profile);profile.flags=1;profile.username=name
        if self.ue.LoadUserProfileW(self.token,C.byref(profile)):
            self.loaded=profile.profile;self.report['user']['profile_loaded']=True
        else:
            self.report['user']['profile_load_error']=C.get_last_error()
            raise C.WinError(self.report['user']['profile_load_error'])

    def grant(self,path,sids):
        path = Path(path).resolve()
        if path != self.work and self.work not in path.parents:
            raise ValueError('ACL grants are restricted to this disposable work directory')
        # Pass numeric SIDs directly to the security APIs. icacls can reject an
        # otherwise valid custom restricting SID when account lookup fails.
        text = 'D:P(A;OICI;FA;;;SY)(A;OICI;FA;;;BA)' + ''.join(
            '(A;OICI;0x1301bf;;;' + sid + ')' for sid in dict.fromkeys(sids))
        descriptor = C.c_void_p()
        self.check(self.a.ConvertStringSecurityDescriptorToSecurityDescriptorW(
            text, 1, C.byref(descriptor), None), 'Parse private work DACL')
        try:
            present, defaulted, dacl = W.BOOL(), W.BOOL(), C.c_void_p()
            self.check(self.a.GetSecurityDescriptorDacl(descriptor, C.byref(present),
                C.byref(dacl), C.byref(defaulted)), 'Get private work DACL')
            code = int(self.a.SetNamedSecurityInfoW(str(path), 1, 4 | 0x80000000,
                                                   None, None, dacl, None))
            if code:
                raise OSError(code, 'Set private work DACL')
        finally:
            self.k.LocalFree(descriptor)

    def make_desktop(self):
        sd=self.sd([self.user_sid,self.logon_sid,self.custom,'S-1-5-12'])
        sa=SA(C.sizeof(SA),sd,False)
        station_name='RPRestricted'+secrets.token_hex(5)
        self.oldstation=self.u.GetProcessWindowStation()
        try:
            self.station=self.check(self.u.CreateWindowStationW(station_name,0,0xF037F,C.byref(sa)),'CreateWindowStation')
            self.check(self.u.SetProcessWindowStation(self.station),'SetProcessWindowStation')
            try:self.desktop=self.check(self.u.CreateDesktopW('default',None,None,0,0xF01FF,C.byref(sa)),'CreateDesktop')
            finally:self.check(self.u.SetProcessWindowStation(self.oldstation),'RestoreWindowStation')
        finally:self.k.LocalFree(sd)
        self.desktop_path=station_name+'\\default'
        self.report['desktop']={'name':self.desktop_path,'private_noninteractive':True}

    def copy_runtime(self):
        runtime=self.work/'runtime';runtime.mkdir()
        base=Path(sys.base_prefix)
        for path in base.iterdir():
            if path.is_file() and (path.suffix.lower() in {'.exe','.dll','.pyd','.zip','._pth'}):shutil.copy2(path,runtime/path.name)
        for name in ['DLLs','Lib']:
            source=base/name
            if source.is_dir():
                shutil.copytree(source,runtime/name,ignore=shutil.ignore_patterns('site-packages','__pycache__','test','tests','idlelib','tkinter','turtledemo'))
        target=runtime/Path(sys.executable).name
        if not target.exists():shutil.copy2(sys.executable,target)
        probe=self.work/'dns_probe.py';shutil.copy2(self.args.probe_script,probe)
        self.python,self.probe=target,probe
        self.broker_child=self.work/'broker_child.py'
        self.broker_child.write_text(self.lab.BROKER_CHILD,encoding='utf-8')
        self.report['runtime']={'source':str(base),'private':str(runtime),'executable':str(target)}

    def env(self,directory):
        pointer=C.c_void_p();env={}
        if self.ue.CreateEnvironmentBlock(C.byref(pointer),self.token,False):
            try:
                pos=0
                while True:
                    item=C.wstring_at(pointer.value+pos*C.sizeof(C.c_wchar))
                    if not item:break
                    pos+=len(item)+1
                    if '=' in item[1:]:
                        key,value=item.split('=',1);env[key]=value
            finally:self.ue.DestroyEnvironmentBlock(pointer)
        else:env=dict(os.environ)
        profile=directory/'profile';profile.mkdir(exist_ok=True)
        temp=directory/'tmp';temp.mkdir(exist_ok=True)
        for key in list(env):
            if key.upper().startswith(('MOZ_','PYTHON','CHROME','HTTP_PROXY','HTTPS_PROXY','ALL_PROXY','NO_PROXY')):del env[key]
        env.update(USERNAME=self.account,USERPROFILE=str(profile),APPDATA=str(profile/'Roaming'),LOCALAPPDATA=str(profile/'Local'),TEMP=str(temp),TMP=str(temp),HOMEDRIVE=str(profile.drive),HOMEPATH=str(profile)[len(profile.drive):])
        for name in ['Roaming','Local']:(profile/name).mkdir(exist_ok=True)
        return C.create_unicode_buffer('\0'.join(k+'='+v for k,v in sorted(env.items(),key=lambda pair:pair[0].upper()))+'\0\0')

    def restricted(self, flags, sids):
        entries=(SIDATTR*len(sids))(*(SIDATTR(self.sid(sid),0) for sid in sids))
        token=W.HANDLE()
        self.check(self.a.CreateRestrictedToken(self.token,flags,0,None,0,None,len(sids),entries if sids else None,C.byref(token)),'CreateRestrictedToken')
        sd=self.sd([self.user_sid,self.logon_sid,self.custom,'S-1-5-12'])
        try:
            present,defaulted=W.BOOL(),W.BOOL();dacl=C.c_void_p()
            self.check(self.a.GetSecurityDescriptorDacl(sd,C.byref(present),C.byref(dacl),C.byref(defaulted)),'GetDacl')
            self.check(self.a.SetTokenInformation(token,6,C.byref(dacl),C.sizeof(dacl)),'SetDefaultDacl')
        finally:self.k.LocalFree(sd)
        return token

    def sample_browser_tokens(self, job, destination, stop):
        seen = set()
        while not stop.is_set():
            buffer, needed = C.create_string_buffer(8 + 128 * C.sizeof(C.c_size_t)), W.DWORD()
            if self.k.QueryInformationJobObject(job, 3, buffer, len(buffer), C.byref(needed)):
                count = min(C.cast(C.addressof(buffer)+4,C.POINTER(W.DWORD))[0],128)
                pids = C.cast(C.addressof(buffer)+8,C.POINTER(C.c_size_t))
                for index in range(count):
                    pid = int(pids[index])
                    if pid in seen: continue
                    process = self.k.OpenProcess(0x1000,False,pid)
                    if not process: continue
                    token = W.HANDLE()
                    try:
                        self.check(self.a.OpenProcessToken(process,8,C.byref(token)),'Sample browser token')
                        integrity = self.info(token,25)
                        sid = self.sidtext(C.cast(integrity,C.POINTER(SIDATTR))[0].sid)
                        appcontainer = self.info(token,29)
                        destination.append({'pid':pid,'integrity_sid':sid,'integrity_rid':int(sid.rsplit('-',1)[1]),
                            'restricted':bool(self.a.IsTokenRestricted(token)),
                            'appcontainer':bool(C.cast(appcontainer,C.POINTER(W.DWORD))[0])})
                        seen.add(pid)
                    except Exception:
                        pass  # A short-lived child may exit during observation.
                    finally:
                        if token.value:self.k.CloseHandle(token)
                        self.k.CloseHandle(process)
            stop.wait(.05)

    def execute(self,token,job,argv,directory,log,timeout,browser=False):
        import msvcrt
        started=time.monotonic();result={'argv':[str(x) for x in argv]}
        si,pi=self.lab.STARTUPINFOW(),self.lab.PROCESS_INFORMATION();si.cb=C.sizeof(si)
        si.lpDesktop=self.desktop_path;si.dwFlags=0x100
        env=self.env(directory)
        with open(log,'wb') as stream,open(os.devnull,'rb') as null:
            h=msvcrt.get_osfhandle(stream.fileno());hin=msvcrt.get_osfhandle(null.fileno())
            for handle in [h,hin]:os.set_handle_inheritable(handle,True)
            si.hStdOutput=si.hStdError=h;si.hStdInput=hin
            try:
                ok=self.a.CreateProcessAsUserW(token,None,C.create_unicode_buffer(subprocess.list2cmdline(result['argv'])),None,None,True,0x4|0x400|0x08000000,env,str(directory),C.byref(si),C.byref(pi))
                if not ok:return dict(result,launch_error=C.get_last_error())
            finally:
                for handle in [h,hin]:os.set_handle_inheritable(handle,False)
        observer = None
        observation_stop = threading.Event()
        try:
            self.check(self.k.AssignProcessToJobObject(job,pi.hProcess),'AssignProcessToJobObject')
            if browser:
                result['browser_process_tokens'] = []
                observer = threading.Thread(target=self.sample_browser_tokens,
                    args=(job,result['browser_process_tokens'],observation_stop),daemon=True)
                observer.start()
            if self.k.ResumeThread(pi.hThread)==0xFFFFFFFF:raise C.WinError(C.get_last_error())
            result['pid']=int(pi.dwProcessId)
            result['exit_code'],result['timed_out']=self.n.wait(pi.hProcess,timeout);pi.hProcess=None
        except Exception as exc:result['error']=repr(exc)
        finally:
            observation_stop.set()
            if observer:observer.join(2)
            self.k.CloseHandle(pi.hThread)
            if pi.hProcess:self.k.TerminateProcess(pi.hProcess,1);self.k.CloseHandle(pi.hProcess)
            self.k.TerminateJobObject(job,1)
        result['seconds']=round(time.monotonic()-started,2)
        result['tail']=self.lab.read_tail(log,8000)
        result['rows']=[]
        for line in result['tail'].splitlines():
            try:result['rows'].append(json.loads(line))
            except ValueError:pass
        return result

    def dns_command(self, api, mode, name):
        if api != 'Resolve-DnsName':
            return [self.python, '-I', '-B', self.probe, '--api', api,
                    '--mode', mode, '--name', name]
        # Match the main lab's real PowerShell DNS entry point. The generated
        # hexadecimal name cannot introduce PowerShell syntax.
        powershell = Path(os.environ['SystemRoot']) / 'System32' / 'WindowsPowerShell' / 'v1.0' / 'powershell.exe'
        identity = "name='" + name + "';api='Resolve-DnsName';mode='standard';"
        command = ("$ErrorActionPreference='Stop'; try { $a=@(Resolve-DnsName -Name " + name
                   + " -Type A -DnsOnly -NoHostsFile -ErrorAction Stop | Select-Object -ExpandProperty IPAddress); "
                   + "@{" + identity + "completed=$true;addresses=$a;answer_matches=($a.Count -eq 1 -and $a[0] -eq '1.2.3.4')} "
                   + "| ConvertTo-Json -Compress } catch { @{" + identity
                   + "completed=$true;error=$_.Exception.Message} | ConvertTo-Json -Compress }")
        return [powershell, '-NoProfile', '-NonInteractive', '-Command', command]

    def dns_matrix(self, token, directory, destination, cid=None):
        # Outside controls and isolated variants use exactly the same APIs and
        # flags, each in a fresh process and with a fresh observable query name.
        for api, mode in DNS_CASES:
            label = api + '_' + mode
            query = secrets.token_hex(16) + '.1.2.3.4.sslip.io'
            row = {'api': api, 'mode': mode, 'name': query, 'outside_control': cid is None}
            destination[label] = row
            job = self.n.new_job()
            try:
                if cid is not None:
                    row['bind_status'] = int(self.n.i.SetJobCompartmentId(job, cid))
                if cid is None or row['bind_status'] == 0:
                    logfile = directory / (('outside_' if cid is None else '') + label + '.log')
                    row.update(self.execute(token, job, self.dns_command(api, mode, query),
                                            directory, logfile, self.args.dns_timeout))
            except Exception as exc:
                row['error'] = repr(exc)
            finally:
                self.k.CloseHandle(job)
            self.save()

    def broker_matrix(self, token, directory, destination, label_prefix, cid=None):
        powershell = Path(os.environ['SystemRoot'])/'System32'/'WindowsPowerShell'/'v1.0'/'powershell.exe'
        for broker in ('wmi','bits'):
            label = label_prefix+'_'+broker+'_'+secrets.token_hex(8)
            url = 'http://'+self.host_ip+':'+str(self.direct.port)+'/'+self.nonce+'/'+label
            row = {'label':label,'url':url,'outside_control':cid is None}
            destination[broker] = row
            child_result = directory/(label+'-child.json')
            if broker == 'wmi':
                command = subprocess.list2cmdline([str(self.python),'-I','-B',str(self.broker_child),
                    url,str(child_result),self.direct.marker(label)])
                script = self.lab.wmi_script(command)
            else:
                display_name = 'RuleProxyPrimary-'+self.nonce+'-'+label
                self.bits_names.append(display_name)
                script = self.lab.bits_script(url,directory/(label+'.html'),display_name,
                    self.direct.marker(label)).replace('AddSeconds(20)','AddSeconds(12)')
            job = self.n.new_job()
            try:
                if cid is not None:row['bind_status']=int(self.n.i.SetJobCompartmentId(job,cid))
                if cid is None or row['bind_status']==0:
                    row['execution']=self.execute(token,job,[powershell,'-NoProfile','-NonInteractive','-Command',script],
                        directory,directory/(label+'.log'),22)
                    rows=row['execution'].get('rows',[])
                    row['invocation']=rows[-1] if rows else None
                    if broker=='wmi' and isinstance(row['invocation'],dict) and row['invocation'].get('return_value')==0:
                        process=self.k.OpenProcess(0x100000|0x1000|1,False,int(row['invocation']['child_pid']))
                        if process:
                            try:
                                length,image=W.DWORD(32768),C.create_unicode_buffer(32768)
                                child_token=W.HANDLE()
                                self.check(self.k.QueryFullProcessImageNameW(process,0,image,C.byref(length)),'Identify WMI child')
                                self.check(self.a.OpenProcessToken(process,8,C.byref(child_token)),'Read WMI child identity')
                                try:child_sid=self.n.token_user(child_token)
                                finally:self.k.CloseHandle(child_token)
                                owned=(os.path.normcase(image.value)==os.path.normcase(str(self.python)) and child_sid==self.user_sid)
                                row['owned_child_handle_verified']=owned
                                if owned and self.k.WaitForSingleObject(process,10000)!=0:
                                    row['child_terminated_after_timeout']=bool(self.k.TerminateProcess(process,1))
                                    self.k.WaitForSingleObject(process,5000)
                            finally:self.k.CloseHandle(process)
                        row['child']=self.lab.read_json_optional(child_result)
            except Exception as exc:row['error']=repr(exc)
            finally:self.k.CloseHandle(job)
            row['fixture_hits']=self.direct.count(label)
            row['host_direct_request_observed']=row['fixture_hits']>0
            self.save()

    def browser_matrix(self,token,directory,destination,label_prefix,cid=None):
        proxy_port=self.fixture.port if cid is None else self.relay_port
        for family in self.args.browsers.split(','):
            program=self.lab.PROGRAMS.get(family)
            if not program or not program.exists():destination[family]={'missing':True};continue
            label=label_prefix+'_'+family;profile=directory/label;profile.mkdir()
            logfile=directory/(label+'.log')
            url='http://'+label+'.invalid/'+self.nonce+'/'+label;shot=None
            if family=='firefox':
                prefs={'network.proxy.type':1,'network.proxy.http':'127.0.0.1','network.proxy.http_port':proxy_port,'network.proxy.ssl':'127.0.0.1','network.proxy.ssl_port':proxy_port,'network.proxy.no_proxies_on':'','network.proxy.allow_hijacking_localhost':True,'network.manage-offline-status':False,'network.trr.mode':5,'browser.shell.checkDefaultBrowser':False,'datareporting.policy.dataSubmissionEnabled':False}
                (profile/'user.js').write_text(''.join('user_pref('+json.dumps(k)+', '+json.dumps(v)+');\n' for k,v in prefs.items()),encoding='utf-8')
                shot=directory/(label+'.png');argv=[program,'--headless','--no-remote','--profile',profile,'--screenshot',shot,url]
            else:argv=[program,*self.lab.CHROMIUM,'--user-data-dir='+str(profile),'--proxy-server=http://127.0.0.1:'+str(proxy_port),'--proxy-bypass-list=<-loopback>','--dump-dom',url]
            job=self.n.new_job()
            row={'outside_control':cid is None,'label':label,'proxy_port':proxy_port}
            destination[family]=row
            try:
                if cid is not None:row['bind_status']=int(self.n.i.SetJobCompartmentId(job,cid))
                if cid is None or row['bind_status']==0:
                    row.update(self.execute(token,job,argv,directory,logfile,self.args.browser_timeout,browser=True))
                row.update(fixture_hits=self.fixture.count(label),sandbox_disabled=False,
                    rendered=self.lab.png_valid(shot) if shot else self.fixture.marker(label) in self.lab.read_tail(logfile,65536))
                row['sandbox_child_token_observed']=any(item['pid']!=row.get('pid') and item['integrity_rid']<=4096
                    and (item['restricted'] or item['appcontainer']) for item in row.get('browser_process_tokens',[]))
                row['sandbox_observation_scope']='job child token integrity/restrictions; no full browser policy attestation'
            except Exception as exc:row['error']=repr(exc)
            finally:self.k.CloseHandle(job)
            self.save()

    def case(self,name,flags,sids,cid):
        directory=self.work/name;directory.mkdir()
        result={'flags':flags,'sids':sids,'dns':{},'browsers':{}};self.report['variants'][name]=result;self.save()
        token=self.restricted(flags,sids)
        try:
            result['token_user']=self.n.token_user(token);result['token_restricted_sids']=self.groups(token,11)
            if name == 'plain':
                result['outside_dns_control'] = {}
                self.dns_matrix(token, directory, result['outside_dns_control'])
                result['outside_broker_control'] = {}
                self.broker_matrix(token,directory,result['outside_broker_control'],'outside_plain')
                result['outside_browsers'] = {}
                self.browser_matrix(token,directory,result['outside_browsers'],'outside_plain')
            self.dns_matrix(token, directory, result['dns'], cid)
            result['brokers'] = {}
            self.broker_matrix(token,directory,result['brokers'],name,cid)
            self.browser_matrix(token,directory,result['browsers'],name,cid)
        finally:self.k.CloseHandle(token)

    def wait_loopback(self, cid):
        # Compartment creation can complete before its loopback addresses are
        # available. The main lab previously hid that delay behind DNS probes.
        # Observe actual local binding, without adding an interface or route.
        import socket
        row = {'ready': False, 'attempts': [], 'timeout_seconds': 20}
        self.report['loopback_readiness'] = row
        def probe():
            started = time.monotonic()
            row['thread_set'] = int(self.n.i.SetCurrentThreadCompartmentId(cid))
            row['thread_get'] = int(self.n.i.GetCurrentThreadCompartmentId())
            if row['thread_set'] or row['thread_get'] != cid:
                return
            try:
                while time.monotonic() - started < 20:
                    attempt = {'elapsed': round(time.monotonic() - started, 3)}
                    for key, family, host in (('ipv4', socket.AF_INET, '127.0.0.1'),
                                               ('ipv6', socket.AF_INET6, '::1')):
                        try:
                            with socket.socket(family, socket.SOCK_STREAM) as sock:
                                sock.bind((host, self.relay_port))
                                sock.listen(1)
                            attempt[key] = {'bound': True}
                        except OSError as error:
                            attempt[key] = {'bound': False, 'error': repr(error),
                                            'winerror': getattr(error, 'winerror', None)}
                    # The shared relay creates both families; do not start it
                    # while IPv6 socket creation can still abort its thread.
                    row['ready'] = attempt['ipv4']['bound'] and attempt['ipv6']['bound']
                    row['attempts'].append(attempt)
                    if row['ready']:
                        break
                    time.sleep(0.25)
            except Exception as error:
                row['error'] = repr(error)
            finally:
                row['elapsed'] = round(time.monotonic() - started, 3)
        thread = threading.Thread(target=probe, daemon=True)
        thread.start(); thread.join(23)
        row['worker_finished'] = not thread.is_alive()
        self.save()
        if not row['ready'] or not row['worker_finished']:
            raise RuntimeError('isolated loopback did not become bindable before its deadline')

    def run(self):
        try:
            if self.report['identity']!='S-1-5-18':raise RuntimeError('run controller as SYSTEM')
            self.privileges();self.make_user();self.make_desktop();self.copy_runtime()
            self.nonce=secrets.token_hex(12);self.fixture=self.lab.Fixture(self.nonce)
            self.direct=self.lab.Fixture(self.nonce,direct=True)
            self.host_ip=self.lab.host_ipv4()
            # Ephemeral loopback port, same on default and isolated compartment.
            import socket
            with socket.socket() as sock:sock.bind(('127.0.0.1',0));self.relay_port=sock.getsockname()[1]
            ca=argparse.Namespace(work=str(self.work),fixture_port=self.fixture.port,relay_port=self.relay_port)
            self.controller=self.lab.Controller(ca);created=self.controller.create('restricted-primary')
            self.report['compartment']=created
            if created['code']:raise OSError(created['code'],'CreateCompartment')
            cid=created['id'];self.wait_loopback(cid);self.controller.start_relay(cid)
            self.report['relay']=self.controller.relay
            if (self.controller.relay.get('listener_set') != 0
                    or self.controller.relay.get('listener_get') != cid
                    or not self.controller.relay.get('bound_127.0.0.1')):
                raise RuntimeError('isolated IPv4 relay did not start in the requested compartment')
            variants={'plain':(0,[]),'rc':(1,['S-1-5-12']),'custom':(1,[self.custom]),
                'custom_logon':(1,[self.custom,self.logon_sid]),'write_custom':(9,[self.custom]),
                'write_custom_logon':(9,[self.custom,self.logon_sid]),
                'write_rc_logon':(9,['S-1-5-12',self.logon_sid]),
                'write_custom_rc_logon':(9,[self.custom,'S-1-5-12',self.logon_sid])}
            for name in self.args.variants.split(','):
                flags,sids=variants[name]
                try:self.case(name,flags,sids,cid)
                except Exception as exc:self.report['variants'].setdefault(name,{})['error']=repr(exc);self.save()
        except Exception as exc:self.report['error']=repr(exc);self.report['traceback']=traceback.format_exc()
        finally:
            if self.controller:
                try:self.report['cleanup']['relay']=self.controller.stop_relay()
                except Exception as exc:self.report['cleanup']['relay_error']=repr(exc)
                try:self.report['cleanup']['compartment']=self.controller.delete('restricted-primary')
                except Exception as exc:self.report['cleanup']['compartment_error']=repr(exc)
            if self.fixture:self.fixture.close()
            if self.direct:self.direct.close()
            if self.bits_names:
                try:
                    names=','.join(self.lab.ps_literal(name) for name in self.bits_names)
                    self.report['cleanup']['bits']=self.lab.powershell(
                        'Import-Module BitsTransfer; $names=@('+names+'); Get-BitsTransfer -AllUsers -ErrorAction SilentlyContinue | '
                        'Where-Object { $names -contains $_.DisplayName } | '
                        'Remove-BitsTransfer -Confirm:$false -ErrorAction SilentlyContinue',timeout=20)
                except Exception as exc:self.report['cleanup']['bits_error']=repr(exc)
            if self.desktop:self.report['cleanup']['desktop_closed']=bool(self.u.CloseDesktop(self.desktop))
            if self.station:self.report['cleanup']['station_closed']=bool(self.u.CloseWindowStation(self.station))
            if self.loaded:
                self.report['cleanup']['profile_unloaded']=bool(self.ue.UnloadUserProfile(self.token,self.loaded))
                if self.report['cleanup']['profile_unloaded']:
                    self.report['cleanup']['profile_deleted']=bool(self.ue.DeleteProfileW(self.user_sid,None,None))
                    if not self.report['cleanup']['profile_deleted']:self.report['cleanup']['profile_delete_error']=C.get_last_error()
            if self.token.value:self.k.CloseHandle(self.token)
            for p in self.allocated_sids:self.k.LocalFree(p)
            if self.account:
                net=C.WinDLL('netapi32');bind(net,'NetUserDel',[W.LPCWSTR,W.LPCWSTR],W.DWORD)
                self.report['cleanup']['user_deleted']=int(net.NetUserDel(None,self.account))
            self.report['finished']=time.time();self.save()
        print(json.dumps({'report':str(self.work/'report.json'),'error':self.report.get('error')}),flush=True)
        return 1 if 'error' in self.report else 0


def main():
    parser=argparse.ArgumentParser()
    parser.add_argument('--lab-script',required=True);parser.add_argument('--probe-script',required=True)
    parser.add_argument('--work',required=True)
    parser.add_argument('--variants',default='plain,rc,custom,write_custom,write_custom_logon,write_rc_logon,write_custom_rc_logon')
    parser.add_argument('--browsers',default='edge,chrome,firefox')
    parser.add_argument('--dns-timeout',type=int,default=25);parser.add_argument('--browser-timeout',type=int,default=45)
    args=parser.parse_args()
    if os.name!='nt':raise RuntimeError('Windows only')
    spec=importlib.util.spec_from_file_location('compartment_lab',args.lab_script)
    lab=importlib.util.module_from_spec(spec);sys.modules[spec.name]=lab;spec.loader.exec_module(lab)
    return Experiment(args,lab).run()

if __name__=='__main__':raise SystemExit(main())
