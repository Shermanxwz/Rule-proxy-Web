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
import time
import traceback

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
        self.controller = self.fixture = None
        self.allocated_sids = []
        self.custom = 'S-1-5-21-' + '-'.join(str(secrets.randbelow(2**31-1)+1) for _ in range(3)) + '-31337'
        P = C.c_void_p
        bind(self.a, 'ConvertStringSidToSidW', [W.LPCWSTR, C.POINTER(P)], W.BOOL)
        bind(self.a, 'ConvertStringSecurityDescriptorToSecurityDescriptorW', [W.LPCWSTR,W.DWORD,C.POINTER(P),C.POINTER(W.DWORD)],W.BOOL)
        bind(self.a, 'GetSecurityDescriptorDacl', [P,C.POINTER(W.BOOL),C.POINTER(P),C.POINTER(W.BOOL)],W.BOOL)
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
                self.check(self.a.AdjustTokenPrivileges(token,False,C.byref(priv),0,None,None),'AdjustTokenPrivileges')
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
        else:self.report['user']['profile_load_error']=C.get_last_error()

    def grant(self,path,sids):
        for sid in sids:
            cp=subprocess.run(['icacls',str(path),'/grant','*'+sid+':(OI)(CI)M','/Q'],capture_output=True,text=True,timeout=60)
            if cp.returncode:raise RuntimeError('private ACL grant failed: '+cp.stdout+cp.stderr)

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
            if path.is_file() and (path.suffix.lower() in {'.exe','.dll','.zip','._pth'}):shutil.copy2(path,runtime/path.name)
        for name in ['DLLs','Lib']:
            source=base/name
            if source.is_dir():
                shutil.copytree(source,runtime/name,ignore=shutil.ignore_patterns('site-packages','__pycache__','test','tests','idlelib','tkinter','turtledemo'))
        target=runtime/Path(sys.executable).name
        if not target.exists():shutil.copy2(sys.executable,target)
        probe=self.work/'dns_probe.py';shutil.copy2(self.args.probe_script,probe)
        self.python,self.probe=target,probe
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

    def execute(self,token,job,argv,directory,log,timeout):
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
        try:
            self.check(self.k.AssignProcessToJobObject(job,pi.hProcess),'AssignProcessToJobObject')
            if self.k.ResumeThread(pi.hThread)==0xFFFFFFFF:raise C.WinError(C.get_last_error())
            result['pid']=int(pi.dwProcessId)
            result['exit_code'],result['timed_out']=self.n.wait(pi.hProcess,timeout);pi.hProcess=None
        except Exception as exc:result['error']=repr(exc)
        finally:
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

    def case(self,name,flags,sids,cid):
        directory=self.work/name;directory.mkdir()
        result={'flags':flags,'sids':sids,'dns':{},'browsers':{}};self.report['variants'][name]=result;self.save()
        token=self.restricted(flags,sids)
        try:
            result['token_user']=self.n.token_user(token);result['token_restricted_sids']=self.groups(token,11)
            if name == 'plain':
                result['outside_dns_control'] = {}
                for api in ['getaddrinfo','DnsQuery_W','DnsQueryEx']:
                    job=self.n.new_job()
                    try:
                        result['outside_dns_control'][api]=self.execute(token,job,[self.python,'-I','-B',self.probe,'--api',api,'--mode','wire' if api!='getaddrinfo' else 'standard'],directory,directory/('outside_'+api+'.log'),self.args.dns_timeout)
                    finally:self.k.CloseHandle(job)
                    self.save()
            for api,mode in [('getaddrinfo','standard'),('DnsQuery_W','wire'),('DnsQueryEx','wire')]:
                label=api+'_'+mode;job=self.n.new_job()
                try:
                    result['dns'][label]={'bind_status':int(self.n.i.SetJobCompartmentId(job,cid))}
                    if result['dns'][label]['bind_status']==0:
                        result['dns'][label].update(self.execute(token,job,[self.python,'-I','-B',self.probe,'--api',api,'--mode',mode],directory,directory/(label+'.log'),self.args.dns_timeout))
                finally:self.k.CloseHandle(job)
                self.save()
            for family in self.args.browsers.split(','):
                program=self.lab.PROGRAMS.get(family)
                if not program or not program.exists():result['browsers'][family]={'missing':True};continue
                label=name+'_'+family;profile=directory/family;profile.mkdir()
                url='http://'+label+'.invalid/'+self.nonce+'/'+label;shot=None
                if family=='firefox':
                    prefs={'network.proxy.type':1,'network.proxy.http':'127.0.0.1','network.proxy.http_port':self.relay_port,'network.proxy.ssl':'127.0.0.1','network.proxy.ssl_port':self.relay_port,'network.proxy.no_proxies_on':'','network.proxy.allow_hijacking_localhost':True,'network.manage-offline-status':False,'network.trr.mode':5,'browser.shell.checkDefaultBrowser':False,'datareporting.policy.dataSubmissionEnabled':False}
                    (profile/'user.js').write_text(''.join('user_pref('+json.dumps(k)+', '+json.dumps(v)+');\n' for k,v in prefs.items()),encoding='utf-8')
                    shot=directory/(family+'.png');argv=[program,'--headless','--no-remote','--profile',profile,'--screenshot',shot,url]
                else:argv=[program,*self.lab.CHROMIUM,'--user-data-dir='+str(profile),'--proxy-server=http://127.0.0.1:'+str(self.relay_port),'--proxy-bypass-list=<-loopback>','--dump-dom',url]
                job=self.n.new_job()
                try:
                    row={'bind_status':int(self.n.i.SetJobCompartmentId(job,cid))}
                    if row['bind_status']==0:row.update(self.execute(token,job,argv,directory,directory/(family+'.log'),self.args.browser_timeout))
                    row.update(fixture_hits=self.fixture.count(label),sandbox_disabled=False,
                        rendered=self.lab.png_valid(shot) if shot else self.fixture.marker(label) in self.lab.read_tail(directory/(family+'.log'),65536))
                    result['browsers'][family]=row
                finally:self.k.CloseHandle(job)
                self.save()
        finally:self.k.CloseHandle(token)

    def run(self):
        try:
            if self.report['identity']!='S-1-5-18':raise RuntimeError('run controller as SYSTEM')
            self.privileges();self.make_user();self.make_desktop();self.copy_runtime()
            self.nonce=secrets.token_hex(12);self.fixture=self.lab.Fixture(self.nonce)
            # Ephemeral loopback port, same on default and isolated compartment.
            import socket
            with socket.socket() as sock:sock.bind(('127.0.0.1',0));self.relay_port=sock.getsockname()[1]
            ca=argparse.Namespace(work=str(self.work),fixture_port=self.fixture.port,relay_port=self.relay_port)
            self.controller=self.lab.Controller(ca);created=self.controller.create('restricted-primary')
            self.report['compartment']=created
            if created['code']:raise OSError(created['code'],'CreateCompartment')
            cid=created['id'];self.controller.start_relay(cid)
            self.report['relay']=self.controller.relay
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
