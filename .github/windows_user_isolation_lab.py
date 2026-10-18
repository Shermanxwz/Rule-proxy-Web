"""Disposable Server experiment: per-user WFP filtering versus DNS brokers.

No product mode is enabled. No TUN, system proxy, DNS setting or firewall
profile is changed. A successful DNS lookup while socket filtering is active
is a No-Go for Linux-like isolation, even if every direct socket is blocked.
"""
from __future__ import annotations

import argparse
from contextlib import contextmanager
import ctypes as C
import hashlib
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
import importlib.util
import json
import os
from pathlib import Path
import re
import secrets
import shutil
import socket
import subprocess
import sys
import threading
import time
import uuid

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
SID_RE = re.compile(r'S-1-5-21-(?:[0-9]+-){3}[0-9]+')
ENVIRONMENT = {'SYSTEMROOT', 'WINDIR', 'PATH', 'TEMP', 'TMP', 'USERPROFILE', 'HOMEDRIVE',
               'HOMEPATH', 'APPDATA', 'LOCALAPPDATA', 'PROGRAMFILES', 'PROGRAMFILES(X86)',
               'PROGRAMW6432', 'SYSTEMDRIVE', 'COMSPEC'}

ACTOR = r'''
import ctypes as C
import json, os, socket, sys, urllib.request
from pathlib import Path
P, U = C.c_void_p, C.c_uint32
a, k = C.WinDLL('advapi32', use_last_error=True), C.WinDLL('kernel32', use_last_error=True)
k.GetCurrentProcess.restype=P
k.CloseHandle.argtypes=[P]
k.LocalFree.argtypes=[P]
a.OpenProcessToken.argtypes=[P,U,C.POINTER(P)]
a.GetTokenInformation.argtypes=[P,C.c_int,P,U,C.POINTER(U)]
a.ConvertSidToStringSidW.argtypes=[P,C.POINTER(C.c_wchar_p)]
t=P()
if not a.OpenProcessToken(k.GetCurrentProcess(),8,C.byref(t)): raise C.WinError(C.get_last_error())
try:
 n=U(); a.GetTokenInformation(t,1,None,0,C.byref(n))
 if not 0<n.value<=65536: raise RuntimeError('invalid token size')
 b=C.create_string_buffer(n.value)
 if not a.GetTokenInformation(t,1,b,len(b),C.byref(n)): raise C.WinError(C.get_last_error())
 text=C.c_wchar_p()
 if not a.ConvertSidToStringSidW(C.cast(b,C.POINTER(P))[0],C.byref(text)): raise C.WinError(C.get_last_error())
 try: sid=text.value
 finally: k.LocalFree(C.cast(text,P))
 elevated=U()
 if not a.GetTokenInformation(t,20,C.byref(elevated),4,C.byref(n)): raise C.WinError(C.get_last_error())
finally: k.CloseHandle(t)
c=json.loads(Path(sys.argv[1]).read_text(encoding='ascii'))
out={'sid':sid,'elevated':bool(elevated.value),'pid':os.getpid(),'phase':c['phase'],'rows':{}}
for key,entry in c['peers'].items():
 try:
  family=socket.AF_INET if entry['family']==4 else socket.AF_INET6
  kind=socket.SOCK_STREAM if entry['protocol']=='tcp' else socket.SOCK_DGRAM
  with socket.socket(family,kind) as s:
   s.settimeout(2)
   payload=(c['nonce']+':'+c['phase']+':'+key).encode('ascii')
   s.connect((entry['host'],entry['port']))
   s.sendall(payload)
   received=s.recv(1024)
  out['rows'][key]={'ok':received==payload,'response_hex':received.hex()}
 except Exception as e: out['rows'][key]={'ok':False,'error_type':type(e).__name__,'winerror':getattr(e,'winerror',None)}
try:
 values=sorted({x[4][0] for x in socket.getaddrinfo(c['dns_name'],443,socket.AF_INET,socket.SOCK_STREAM)})
 out['dns']={'ok':values==['1.2.3.4'],'addresses':values,'name':c['dns_name']}
except Exception as e: out['dns']={'ok':False,'name':c['dns_name'],'error_type':type(e).__name__}
try:
 target='http://'+c['phase']+'.invalid/'+c['nonce']+'/'+c['phase']
 opener=urllib.request.build_opener(urllib.request.ProxyHandler({'http':'http://127.0.0.1:'+str(c['proxy_port'])}))
 with opener.open(target,timeout=3) as response: body=json.loads(response.read(4096).decode('ascii'))
 out['proxy']={'ok':body=={'target':target,'nonce':c['nonce']},'target':target,'response':body}
except Exception as e: out['proxy']={'ok':False,'error_type':type(e).__name__}
Path(sys.argv[2]).write_text(json.dumps(out),encoding='ascii')
'''


@contextmanager
def clean_actor_environment():
    original = dict(os.environ)
    try:
        os.environ.clear()
        os.environ.update({key: value for key, value in original.items() if key.upper() in ENVIRONMENT})
        yield
    finally:
        os.environ.clear()
        os.environ.update(original)


def valid_receipt(value, sid, phase, pid, dns_name):
    try:
        return (isinstance(value, dict) and value.get('sid') == sid and value.get('elevated') is False
                and type(value.get('pid')) is int and value['pid'] == pid and value.get('phase') == phase
                and set(value.get('rows', {})) == {'tcp4', 'tcp6', 'udp4', 'udp6'}
                and all(isinstance(row, dict) and type(row.get('ok')) is bool for row in value['rows'].values())
                and value.get('dns', {}).get('name') == dns_name and type(value['dns'].get('ok')) is bool
                and type(value.get('proxy', {}).get('ok')) is bool)
    except (KeyError, TypeError, AttributeError):
        return False


def assess(phases, received, nonce):
    """A timeout without a measured positive never qualifies as isolation."""
    keys = ('tcp4', 'tcp6', 'udp4', 'udp6')
    controls = all(phases[label]['rows'][key]['ok'] is True and
                   f'{nonce}:{label}:{key}' in received for label in ('before', 'after') for key in keys)
    dns_controls = all(phases[label]['dns']['ok'] is True and phases[label]['dns'].get('addresses') == ['1.2.3.4']
                       for label in ('before', 'after'))
    names = [phases[label]['dns']['name'] for label in ('before', 'filtered', 'after')]
    unique_dns = len(set(names)) == 3 and all(re.fullmatch(r'[0-9a-f]{32}\.1\.2\.3\.4\.sslip\.io', name) for name in names)
    socket_blocked = all(phases['filtered']['rows'][key]['ok'] is False and
                         f'{nonce}:filtered:{key}' not in received for key in keys)
    proxy = all(phases[label]['proxy']['ok'] is True and phases[label]['proxy'].get('target') ==
                f'http://{label}.invalid/{nonce}/{label}' and f'http://{label}.invalid/{nonce}/{label}' in received
                for label in ('before', 'filtered', 'after'))
    dns_success = bool(phases['filtered']['dns'].get('addresses'))
    valid = bool(controls and dns_controls and unique_dns and proxy)
    dns_bypass = bool(valid and socket_blocked and dns_success)
    return {'valid_experiment': valid, 'positive_socket_controls': bool(controls),
            'unique_dns_positive_controls': bool(dns_controls and unique_dns),
            'filtered_sockets_blocked': bool(socket_blocked), 'proxy_fixture_verified': bool(proxy),
            'system_dns_success_with_filters': dns_success, 'dns_broker_bypass': dns_bypass,
            'linux_equivalent': False, 'product_qualified': False,
            'browser_tested': False, 'decision': ('no_go_dns_broker_bypass' if valid and dns_bypass else
                'inconclusive' if not valid else 'no_go_socket_filter_failed' if not socket_blocked else
                'socket_scope_only_requires_dns_broker_work')}


class UserInfo(C.Structure):
    _fields_ = [('name', C.c_wchar_p), ('password', C.c_wchar_p), ('age', C.c_uint32),
               ('privilege', C.c_uint32), ('home', C.c_wchar_p), ('comment', C.c_wchar_p),
               ('flags', C.c_uint32), ('script', C.c_wchar_p)]


class Account:
    def __init__(self, nonce):
        self.name, self.password, self.marker = 'rpuid' + nonce[:10], secrets.token_urlsafe(30) + 'aA1!', 'RuleProxy UID lab ' + nonce
        self.sid, self.created = None, False
        self.net = C.WinDLL('netapi32', use_last_error=True)
        for name, arguments in {
            'NetUserAdd': [C.c_wchar_p, C.c_uint32, C.c_void_p, C.POINTER(C.c_uint32)],
            'NetUserGetInfo': [C.c_wchar_p, C.c_wchar_p, C.c_uint32, C.POINTER(C.c_void_p)],
            'NetUserDel': [C.c_wchar_p, C.c_wchar_p], 'NetApiBufferFree': [C.c_void_p],
            'NetLocalGroupAddMembers': [C.c_wchar_p, C.c_wchar_p, C.c_uint32, C.c_void_p, C.c_uint32],
        }.items():
            function = getattr(self.net, name)
            function.argtypes, function.restype = arguments, C.c_uint32

    def lookup_sid(self):
        api, kernel = C.WinDLL('advapi32', use_last_error=True), C.WinDLL('kernel32', use_last_error=True)
        api.LookupAccountNameW.argtypes = [C.c_wchar_p, C.c_wchar_p, C.c_void_p, C.POINTER(C.c_uint32),
                                         C.c_wchar_p, C.POINTER(C.c_uint32), C.POINTER(C.c_uint32)]
        api.ConvertSidToStringSidW.argtypes = [C.c_void_p, C.POINTER(C.c_wchar_p)]
        kernel.LocalFree.argtypes = [C.c_void_p]
        size, domain_size, use = C.c_uint32(), C.c_uint32(), C.c_uint32()
        api.LookupAccountNameW(None, self.name, None, C.byref(size), None, C.byref(domain_size), C.byref(use))
        if not 1 <= size.value <= 4096 or domain_size.value > 4096:
            raise RuntimeError('Invalid account identity buffer')
        sid, domain = C.create_string_buffer(size.value), C.create_unicode_buffer(max(1, domain_size.value))
        if not api.LookupAccountNameW(None, self.name, sid, C.byref(size), domain, C.byref(domain_size), C.byref(use)):
            raise C.WinError(C.get_last_error())
        text = C.c_wchar_p()
        if not api.ConvertSidToStringSidW(sid, C.byref(text)):
            raise C.WinError(C.get_last_error())
        try:
            if use.value != 1 or not SID_RE.fullmatch(text.value): raise RuntimeError('Invalid account SID')
            return text.value
        finally:
            kernel.LocalFree(C.cast(text, C.c_void_p))

    def create(self):
        info = UserInfo(self.name, self.password, 0, 1, None, self.marker, 0x10201, None)
        error = C.c_uint32()
        code = self.net.NetUserAdd(None, 1, C.byref(info), C.byref(error))
        if code: raise RuntimeError(f'NetUserAdd failed: {code}')
        self.created = True
        self.sid = self.lookup_sid()
        member = C.c_wchar_p(self.name)
        # This experiment is restricted to the English hosted Server image.
        code = self.net.NetLocalGroupAddMembers(None, 'Users', 3, C.byref(member), 1)
        if code not in (0, 1378): raise RuntimeError(f'Add temporary Users membership failed: {code}')

    def remove(self):
        if not self.created: return True
        pointer = C.c_void_p()
        code = self.net.NetUserGetInfo(None, self.name, 1, C.byref(pointer))
        if code == 2221: return True
        if code: raise RuntimeError(f'Account cleanup query failed: {code}')
        try:
            info = C.cast(pointer, C.POINTER(UserInfo)).contents
            if info.name != self.name or info.comment != self.marker or (self.sid and self.lookup_sid() != self.sid):
                raise RuntimeError('Temporary account identity changed; removal refused')
        finally:
            self.net.NetApiBufferFree(pointer)
        code = self.net.NetUserDel(None, self.name)
        if code: raise RuntimeError(f'Temporary account removal failed: {code}')
        self.password = None
        return True


class UserRules:
    """Exact GUID/marker-owned disposable user rules, never a host catch-all."""
    def __init__(self, sid, port, marker, *, foreign=False):
        if (not isinstance(sid, str) or SID_RE.fullmatch(sid) is None
                or type(port) is not int or not 1025 <= port <= 65535
                or not isinstance(marker, str)
                or re.fullmatch(r'(?:RuleProxyUserLab|ForeignUidFixture):[0-9a-f]{32}', marker) is None):
            raise ValueError('Invalid disposable user filter identity')
        from ruleproxy import windows_global_guard as G
        self.G, self.sid, self.port, self.marker = G, sid, port, marker
        self.provider, self.sublayer = uuid.uuid4(), uuid.uuid4()
        self.plan = [(4, 'proxy')] if foreign else [(f, n) for f in (4, 6) for n in ('proxy', 'block')]
        self.keys = {item: uuid.uuid4() for item in self.plan}
        self.engine = G._Engine()

    def open(self):
        self.engine.__enter__()

    def snapshot(self):
        G = self.G
        result = []
        for (family, name), key in self.keys.items():
            with self.engine.get('Filter', key, G._Filter) as value:
                if value is None: continue
                if (value.display.description != self.marker or value.sublayer.text() != str(self.sublayer)
                        or not value.provider or value.provider.contents.text() != str(self.provider)
                        or value.layer.text() != G._LAYERS[family]
                        or value.action.type != (G._PERMIT if name == 'proxy' else G._BLOCK)):
                    raise RuntimeError('User lab filter identity changed; refusing removal')
                result.append(str(key))
        return sorted(result)

    def apply(self):
        G, engine = self.G, self.engine
        descriptor = G._descriptor('O:SYG:SYD:(A;;CC;;;' + self.sid + ')')
        with engine.transaction():
            provider = G._GUID.of(self.provider)
            p = G._Provider(); p.key = provider; p.display = G._Display('UID lab', self.marker)
            G._error(engine.api.FwpmProviderAdd0(engine.handle, C.byref(p), None), 'add lab provider')
            s = G._Sublayer(); s.key = G._GUID.of(self.sublayer); s.display = G._Display('UID lab', self.marker)
            s.provider, s.weight = C.pointer(provider), 65535
            G._error(engine.api.FwpmSubLayerAdd0(engine.handle, C.byref(s), None), 'add lab sublayer')
            for (family, name), key in self.keys.items():
                keep = []
                values = [('user', 14, descriptor)]
                if name == 'proxy':
                    remote = (3, 0x7f000001) if family == 4 else (11, socket.inet_pton(socket.AF_INET6, '::1'))
                    values += [('protocol', 1, 6), ('remote', *remote), ('remote_port', 2, self.port)]
                conditions = (G._Condition * len(values))(*[
                    G._Condition(G._GUID.of(G._FIELDS[field]), 0, G._value(kind, data, keep))
                    for field, kind, data in values])
                rule = G._Filter(); rule.key = G._GUID.of(key); rule.display = G._Display('UID lab ' + name, self.marker)
                rule.provider, rule.layer, rule.sublayer = C.pointer(provider), G._GUID.of(G._LAYERS[family]), G._GUID.of(self.sublayer)
                rule.weight = G._value(1, 15 if name == 'proxy' else 0, keep)
                rule.count, rule.conditions = len(values), conditions
                rule.action.type = G._PERMIT if name == 'proxy' else G._BLOCK
                number = G._U64()
                G._error(engine.api.FwpmFilterAdd0(engine.handle, C.byref(rule), None, C.byref(number)), 'add UID rule')
        if len(self.snapshot()) != len(self.plan): raise RuntimeError('UID rule readback incomplete')

    def remove(self):
        G = self.G
        present = set(self.snapshot())
        with self.engine.transaction():
            for key in self.keys.values():
                if str(key) in present:
                    G._error(self.engine.api.FwpmFilterDeleteByKey0(self.engine.handle, C.byref(G._GUID.of(key))), 'delete UID rule')
        if self.snapshot(): raise RuntimeError('UID rules survived cleanup')
        for kind, key, structure in (('SubLayer', self.sublayer, G._Sublayer), ('Provider', self.provider, G._Provider)):
            with self.engine.get(kind, key, structure) as value:
                if value is None: continue
                if value.display.description != self.marker: raise RuntimeError('UID metadata marker changed')
            function = getattr(self.engine.api, 'Fwpm' + kind + 'DeleteByKey0')
            function.argtypes, function.restype = [C.c_void_p, C.POINTER(G._GUID)], C.c_uint32
            G._error(function(self.engine.handle, C.byref(G._GUID.of(key))), 'delete UID metadata')

    def close(self):
        self.engine.__exit__(None, None, None)


def main():
    parser = argparse.ArgumentParser(); parser.add_argument('--work', type=Path, required=True)
    work = parser.parse_args().work.resolve()
    if os.name != 'nt' or os.environ.get('GITHUB_ACTIONS') != 'true' or not C.windll.shell32.IsUserAnAdmin():
        raise RuntimeError('Disposable Windows Actions administrator required')
    if work.exists(): raise RuntimeError('Refusing to reuse UID lab directory')
    work.mkdir(parents=True); (work / 'actors').mkdir()
    nonce = secrets.token_hex(16)
    report = {'schema_version': 1, 'scope': 'disposable per-user WFP CLI only', 'source_commit': os.environ.get('GITHUB_SHA'),
              'harness_sha256': hashlib.sha256(Path(__file__).read_bytes()).hexdigest(), 'phases': {},
              'product_qualified': False, 'linux_equivalent': False, 'browser_tested': False, 'cleanup_ok': False}
    resources, threads, received = [], [], []
    account, own, foreign, active = Account(nonce), None, None, None
    def echo(server, protocol):
        while True:
            try:
                if protocol == 'tcp':
                    connection, _ = server.accept()
                    with connection:
                        connection.settimeout(3); data = connection.recv(1024); received.append(data.decode('ascii')); connection.sendall(data)
                else:
                    data, peer = server.recvfrom(1024); received.append(data.decode('ascii')); server.sendto(data, peer)
            except OSError: return
    try:
        import importlib.util
        spec = importlib.util.spec_from_file_location('uid_acceptance', Path(__file__).with_name('windows_proxifyre_product_acceptance.py'))
        acceptance = importlib.util.module_from_spec(spec); spec.loader.exec_module(acceptance); acceptance.LAB = work
        account.create(); report['account'] = {'name': account.name, 'sid': account.sid, 'admin_membership_granted': False}
        for path, grant in ((work, '*S-1-5-32-545:(OI)(CI)(RX)'), (work / 'actors', '*S-1-5-32-545:(OI)(CI)(M)')):
            subprocess.run(['icacls.exe', str(path), '/grant', grant], capture_output=True, check=True, timeout=10)
        runtime = work / 'runtime'; runtime.mkdir()
        for pattern in ('python.exe', 'python*.dll', 'vcruntime*.dll'):
            for path in Path(sys.executable).parent.glob(pattern): shutil.copyfile(path, runtime / path.name)
        for name in ('DLLs', 'Lib'):
            shutil.copytree(Path(sys.base_prefix) / name, runtime / name,
                            ignore=shutil.ignore_patterns('site-packages', '__pycache__', 'test', 'idlelib', 'tkinter', 'ensurepip'))
        actor = work / 'actor.py'; actor.write_bytes(ACTOR.encode('ascii'))
        host4 = socket.gethostbyname(socket.gethostname())
        if not host4 or host4.startswith('127.'): raise RuntimeError('A physical IPv4 NIC positive control is required')
        peers = {}
        for family, host, version in ((socket.AF_INET, host4, 4), (socket.AF_INET6, '::1', 6)):
            for protocol, kind in (('tcp', socket.SOCK_STREAM), ('udp', socket.SOCK_DGRAM)):
                server = socket.socket(family, kind); server.bind((host, 0))
                if protocol == 'tcp': server.listen(8)
                resources.append(server); peers[protocol + str(version)] = {'family': version, 'protocol': protocol,
                    'host': host, 'port': server.getsockname()[1]}
                thread = threading.Thread(target=echo, args=(server, protocol), daemon=True); thread.start(); threads.append(thread)
        class Proxy(BaseHTTPRequestHandler):
            def log_message(self, *_): pass
            def do_GET(self):
                if self.path not in targets: self.send_error(403); return
                body = json.dumps({'target': self.path, 'nonce': nonce}).encode('ascii')
                self.send_response(200); self.send_header('Content-Length', str(len(body))); self.end_headers(); self.wfile.write(body)
                received.append(self.path)
        targets = {f'http://{label}.invalid/{nonce}/{label}' for label in ('before', 'filtered', 'after')}
        proxy = ThreadingHTTPServer(('127.0.0.1', 0), Proxy); resources.append(proxy)
        threading.Thread(target=proxy.serve_forever, daemon=True).start()
        report['peer_scope'] = {'ipv4': 'host physical NIC local receiver', 'ipv6': 'host loopback receiver; no public IPv6 claim'}
        report['peers'] = peers
        def phase(label):
            nonlocal active
            dns_name = secrets.token_hex(16) + '.1.2.3.4.sslip.io'
            source, output = work / 'actors' / (label + '.json'), work / 'actors' / (label + '-result.json')
            source.write_text(json.dumps({'phase': label, 'nonce': nonce, 'peers': peers, 'proxy_port': proxy.server_port,
                                          'dns_name': dns_name}), encoding='ascii')
            with clean_actor_environment():
                active = acceptance.launch_user([runtime / 'python.exe', '-I', '-S', actor, source, output],
                                                account.name, account.password, account.sid)
            try:
                code = active.wait(timeout=35)
                value = json.loads(output.read_text(encoding='ascii'))
                if code != 0 or not valid_receipt(value, account.sid, label, active.pid, dns_name):
                    raise RuntimeError('UID actor exit/token/receipt is invalid')
                report['phases'][label] = value
            finally:
                active.terminate(); active.wait(timeout=5); active.close(); active = None
        own = UserRules(account.sid, proxy.server_port, 'RuleProxyUserLab:' + nonce); own.open()
        foreign = UserRules(account.sid, proxy.server_port, 'ForeignUidFixture:' + nonce, foreign=True); foreign.open(); foreign.apply()
        foreign_before = foreign.snapshot()
        phase('before'); own.apply(); phase('filtered'); own.remove()
        report['foreign_preserved_after_owned_cleanup'] = foreign.snapshot() == foreign_before
        phase('after')
        report.update(assess(report['phases'], received, nonce))
    except Exception as error:
        report.update(error_type=type(error).__name__, error=str(error)[:300], valid_experiment=False)
    finally:
        errors = []
        if active is not None:
            try: active.terminate(); active.wait(timeout=5); active.close()
            except Exception as error: errors.append(type(error).__name__)
        for rules in (own, foreign):
            if rules is not None:
                try: rules.remove()
                except Exception as error: errors.append(type(error).__name__)
                finally: rules.close()
        try:
            account.remove()
            if account.sid:
                body = "$p=@(Get-CimInstance Win32_UserProfile -Filter \"SID='" + account.sid + "'\"); if($p){$p|Remove-CimInstance}; if(@(Get-CimInstance Win32_UserProfile -Filter \"SID='" + account.sid + "'\").Count){throw 'Temporary profile remains'}"
                subprocess.run(['powershell.exe', '-NoProfile', '-NonInteractive', '-Command', "$ErrorActionPreference='Stop'; " + body],
                               capture_output=True, check=True, timeout=20)
        except Exception as error: errors.append(type(error).__name__)
        for resource in resources:
            try:
                if isinstance(resource, ThreadingHTTPServer): resource.shutdown(); resource.server_close()
                else: resource.close()
            except OSError: pass
        report['cleanup_ok'] = not errors
        report['cleanup_error_types'] = errors
        report['received'] = list(received)
        report['passed'] = report.get('valid_experiment') is True and report['cleanup_ok'] and report.get('foreign_preserved_after_owned_cleanup') is True
        (work / 'report.json').write_text(json.dumps(report, indent=2) + '\n', encoding='ascii')
        print(json.dumps({key: report.get(key) for key in ('passed', 'decision', 'dns_broker_bypass', 'cleanup_ok')}), flush=True)
    return 0 if report['passed'] else 1


if __name__ == '__main__':
    raise SystemExit(main())
