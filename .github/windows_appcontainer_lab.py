"""Disposable AppContainer network-isolation lab for a Windows CI runner.

Question answered: can an ordinary Win32 process tree be confined like the
Linux namespace mode -- no direct network at all, only one loopback proxy port --
using an AppContainer without network capabilities plus our own WFP filters keyed
on the package SID?

Run elevated on a throwaway runner only. Filters use a dynamic WFP session so
they vanish with this process; the firewall, loopback exemption and profile are
restored in finally blocks. Gating assertions are listed in GATES; everything
else is recorded as information.

Sources:
https://learn.microsoft.com/windows/win32/api/userenv/nf-userenv-createappcontainerprofile
https://learn.microsoft.com/windows/win32/api/winnt/ns-winnt-security_capabilities
https://learn.microsoft.com/windows/win32/api/netfw/nf-netfw-networkisolationsetappcontainerconfig
https://learn.microsoft.com/windows/win32/fwp/filtering-condition-identifiers-
https://projectzero.google/2021/08/understanding-network-access-windows-app.html
"""
from __future__ import annotations

import argparse
import ctypes as C
from ctypes import wintypes as W
import ipaddress
import json
import msvcrt
import os
from pathlib import Path
import select
import shutil
import socket
import subprocess
import sys
import threading
import time
import uuid

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from ruleproxy import windows_global_guard as G  # noqa: E402  (lab reuses the guard's WFP structures)

PROFILE = 'RuleProxy.AppContainerLab'
PACKAGE_FIELD = '71bc78fa-f17c-4997-a602-6abb261f351c'  # FWPM_CONDITION_ALE_PACKAGE_ID
SUBLAYER = uuid.UUID('5d0b2a8e-3a57-4e4c-9a55-1f3c7f0b6a31')
EDGE = Path(r'C:\Program Files (x86)\Microsoft\Edge\Application\msedge.exe')
CURL = Path(os.environ.get('SystemRoot', r'C:\Windows')) / 'System32' / 'curl.exe'
PUBLIC_URL = 'https://example.com/'

kernel = C.WinDLL('kernel32', use_last_error=True)
advapi = C.WinDLL('advapi32', use_last_error=True)
userenv = C.WinDLL('userenv', use_last_error=True)
firewallapi = C.WinDLL('firewallapi', use_last_error=True)


class SID_AND_ATTRIBUTES(C.Structure):
    _fields_ = [('Sid', C.c_void_p), ('Attributes', W.DWORD)]


class SECURITY_CAPABILITIES(C.Structure):
    _fields_ = [('AppContainerSid', C.c_void_p), ('Capabilities', C.POINTER(SID_AND_ATTRIBUTES)),
                ('CapabilityCount', W.DWORD), ('Reserved', W.DWORD)]


class STARTUPINFOW(C.Structure):
    _fields_ = [('cb', W.DWORD), ('lpReserved', W.LPWSTR), ('lpDesktop', W.LPWSTR), ('lpTitle', W.LPWSTR),
                ('dwX', W.DWORD), ('dwY', W.DWORD), ('dwXSize', W.DWORD), ('dwYSize', W.DWORD),
                ('dwXCountChars', W.DWORD), ('dwYCountChars', W.DWORD), ('dwFillAttribute', W.DWORD),
                ('dwFlags', W.DWORD), ('wShowWindow', W.WORD), ('cbReserved2', W.WORD),
                ('lpReserved2', C.c_void_p), ('hStdInput', W.HANDLE), ('hStdOutput', W.HANDLE),
                ('hStdError', W.HANDLE)]


class STARTUPINFOEXW(C.Structure):
    _fields_ = [('StartupInfo', STARTUPINFOW), ('lpAttributeList', C.c_void_p)]


class PROCESS_INFORMATION(C.Structure):
    _fields_ = [('hProcess', W.HANDLE), ('hThread', W.HANDLE), ('dwProcessId', W.DWORD), ('dwThreadId', W.DWORD)]


userenv.CreateAppContainerProfile.argtypes = [W.LPCWSTR, W.LPCWSTR, W.LPCWSTR, C.c_void_p, W.DWORD, C.POINTER(C.c_void_p)]
userenv.CreateAppContainerProfile.restype = C.c_long
userenv.DeriveAppContainerSidFromAppContainerName.argtypes = [W.LPCWSTR, C.POINTER(C.c_void_p)]
userenv.DeriveAppContainerSidFromAppContainerName.restype = C.c_long
userenv.DeleteAppContainerProfile.argtypes = [W.LPCWSTR]
userenv.DeleteAppContainerProfile.restype = C.c_long
advapi.ConvertSidToStringSidW.argtypes = [C.c_void_p, C.POINTER(W.LPWSTR)]
advapi.GetLengthSid.argtypes = [C.c_void_p]
advapi.GetLengthSid.restype = W.DWORD
kernel.LocalFree.argtypes = [C.c_void_p]
kernel.InitializeProcThreadAttributeList.argtypes = [C.c_void_p, W.DWORD, W.DWORD, C.POINTER(C.c_size_t)]
kernel.UpdateProcThreadAttribute.argtypes = [C.c_void_p, W.DWORD, C.c_size_t, C.c_void_p, C.c_size_t, C.c_void_p, C.c_void_p]
kernel.DeleteProcThreadAttributeList.argtypes = [C.c_void_p]
kernel.CreateProcessW.argtypes = [W.LPCWSTR, W.LPWSTR, C.c_void_p, C.c_void_p, W.BOOL, W.DWORD, C.c_void_p,
                                  W.LPCWSTR, C.POINTER(STARTUPINFOEXW), C.POINTER(PROCESS_INFORMATION)]
kernel.WaitForSingleObject.argtypes = [W.HANDLE, W.DWORD]
kernel.WaitForSingleObject.restype = W.DWORD
kernel.GetExitCodeProcess.argtypes = [W.HANDLE, C.POINTER(W.DWORD)]
kernel.TerminateProcess.argtypes = [W.HANDLE, W.UINT]
kernel.CloseHandle.argtypes = [W.HANDLE]
firewallapi.NetworkIsolationGetAppContainerConfig.argtypes = [C.POINTER(W.DWORD), C.POINTER(C.POINTER(SID_AND_ATTRIBUTES))]
firewallapi.NetworkIsolationGetAppContainerConfig.restype = W.DWORD
firewallapi.NetworkIsolationSetAppContainerConfig.argtypes = [W.DWORD, C.POINTER(SID_AND_ATTRIBUTES)]
firewallapi.NetworkIsolationSetAppContainerConfig.restype = W.DWORD

PROC_THREAD_ATTRIBUTE_SECURITY_CAPABILITIES = 0x20009
EXTENDED_STARTUPINFO_PRESENT, CREATE_NO_WINDOW, CREATE_UNICODE_ENVIRONMENT = 0x80000, 0x08000000, 0x400
STARTF_USESTDHANDLES = 0x100


def sid_text(sid) -> str:
    text = W.LPWSTR()
    if not advapi.ConvertSidToStringSidW(sid, C.byref(text)):
        raise C.WinError(C.get_last_error())
    try:
        return text.value
    finally:
        kernel.LocalFree(C.cast(text, C.c_void_p))


def container_sid():
    sid = C.c_void_p()
    code = userenv.CreateAppContainerProfile(PROFILE, PROFILE, 'RuleProxy AppContainer lab', None, 0, C.byref(sid))
    if code & 0xFFFFFFFF == 0x800700B7:  # already exists
        code = userenv.DeriveAppContainerSidFromAppContainerName(PROFILE, C.byref(sid))
    if code:
        raise OSError(f'AppContainer profile failed 0x{code & 0xFFFFFFFF:08x}')
    return sid


def environment_block(env: dict[str, str]):
    text = ''.join(f'{k}={v}\0' for k, v in sorted(env.items(), key=lambda item: item[0].upper())) + '\0'
    return C.create_unicode_buffer(text, len(text))


def launch(sid, argv: list[str], *, contained: bool, cwd: Path, env: dict[str, str], log: Path,
           timeout: float) -> dict:
    """CreateProcessW, optionally inside the AppContainer with zero capabilities."""
    command = C.create_unicode_buffer(subprocess.list2cmdline(argv), 32768)
    info = STARTUPINFOEXW()
    info.StartupInfo.cb = C.sizeof(STARTUPINFOEXW)
    with open(log, 'wb') as sink:
        handle = msvcrt.get_osfhandle(sink.fileno())
        os.set_handle_inheritable(handle, True)
        info.StartupInfo.dwFlags = STARTF_USESTDHANDLES
        info.StartupInfo.hStdOutput = info.StartupInfo.hStdError = handle
        size = C.c_size_t()
        kernel.InitializeProcThreadAttributeList(None, 1, 0, C.byref(size))
        attributes = C.create_string_buffer(size.value)
        if not kernel.InitializeProcThreadAttributeList(attributes, 1, 0, C.byref(size)):
            raise C.WinError(C.get_last_error())
        capabilities = SECURITY_CAPABILITIES(sid.value, None, 0, 0)
        try:
            if contained and not kernel.UpdateProcThreadAttribute(
                    attributes, 0, PROC_THREAD_ATTRIBUTE_SECURITY_CAPABILITIES,
                    C.byref(capabilities), C.sizeof(capabilities), None, None):
                raise C.WinError(C.get_last_error())
            info.lpAttributeList = C.cast(attributes, C.c_void_p) if contained else None
            process = PROCESS_INFORMATION()
            block = environment_block(env)
            started = time.monotonic()
            if not kernel.CreateProcessW(None, command, None, None, True,
                                         EXTENDED_STARTUPINFO_PRESENT | CREATE_NO_WINDOW | CREATE_UNICODE_ENVIRONMENT,
                                         block, str(cwd), C.byref(info), C.byref(process)):
                return {'started': False, 'error': f'CreateProcessW {C.get_last_error()}'}
            try:
                timed_out = kernel.WaitForSingleObject(process.hProcess, int(timeout * 1000)) != 0
                if timed_out:
                    kernel.TerminateProcess(process.hProcess, 0xDEAD)
                    kernel.WaitForSingleObject(process.hProcess, 5000)
                code = W.DWORD()
                kernel.GetExitCodeProcess(process.hProcess, C.byref(code))
                return {'started': True, 'exit_code': code.value, 'timed_out': timed_out,
                        'seconds': round(time.monotonic() - started, 2)}
            finally:
                kernel.CloseHandle(process.hThread)
                kernel.CloseHandle(process.hProcess)
        finally:
            kernel.DeleteProcThreadAttributeList(attributes)
            os.set_handle_inheritable(handle, False)


# ---------------------------------------------------------------- host side services

def _banner_server(host: str, family=socket.AF_INET, banner=b'RPTARGET\n'):
    server = socket.socket(family, socket.SOCK_STREAM)
    server.bind((host, 0))
    server.listen(32)

    def serve():
        while True:
            try:
                peer, _ = server.accept()
            except OSError:
                return
            with peer:
                try:
                    peer.sendall(banner)
                except OSError:
                    pass
    threading.Thread(target=serve, daemon=True).start()
    return server


class ConnectProxy:
    """Minimal HTTP CONNECT proxy on 127.0.0.1, standing in for Mihomo's mixed port."""

    def __init__(self):
        self.server = socket.socket()
        self.server.bind(('127.0.0.1', 0))
        self.server.listen(64)
        self.port = self.server.getsockname()[1]
        self.tunnels = 0
        threading.Thread(target=self._accept, daemon=True).start()

    def _accept(self):
        while True:
            try:
                client, _ = self.server.accept()
            except OSError:
                return
            threading.Thread(target=self._handle, args=(client,), daemon=True).start()

    def _handle(self, client):
        with client:
            client.settimeout(15)
            head = b''
            while b'\r\n\r\n' not in head and len(head) < 8192:
                chunk = client.recv(4096)
                if not chunk:
                    return
                head += chunk
            parts = head.split(b'\r\n', 1)[0].split()
            if len(parts) < 2 or parts[0] != b'CONNECT':
                client.sendall(b'HTTP/1.1 405 Only CONNECT\r\n\r\n')
                return
            host, _, port = parts[1].decode().rpartition(':')
            try:
                upstream = socket.create_connection((host.strip('[]'), int(port)), timeout=10)
            except OSError:
                client.sendall(b'HTTP/1.1 502 Bad Gateway\r\n\r\n')
                return
            self.tunnels += 1
            with upstream:
                client.sendall(b'HTTP/1.1 200 Connection established\r\n\r\n')
                rest = head.split(b'\r\n\r\n', 1)[1]
                if rest:
                    upstream.sendall(rest)
                pair = [client, upstream]
                while True:
                    ready, _, _ = select.select(pair, [], [], 30)
                    if not ready:
                        return
                    for side in ready:
                        data = side.recv(65536)
                        if not data:
                            return
                        (upstream if side is client else client).sendall(data)

    def close(self):
        self.server.close()


def physical_ipv4() -> str:
    with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as probe:
        probe.connect(('192.0.2.1', 9))  # no packet is sent for UDP connect
        return probe.getsockname()[0]


# ---------------------------------------------------------------- loopback exemption

def exemption(sid, enable: bool) -> list[str]:
    """Add or remove only our SID; preserve every other exempt package."""
    count, entries = W.DWORD(), C.POINTER(SID_AND_ATTRIBUTES)()
    code = firewallapi.NetworkIsolationGetAppContainerConfig(C.byref(count), C.byref(entries))
    if code:
        raise OSError(f'NetworkIsolationGetAppContainerConfig {code}')
    ours = sid_text(sid)
    keep = [entries[i].Sid for i in range(count.value) if sid_text(entries[i].Sid) != ours]
    sids = keep + ([sid.value] if enable else [])
    array = (SID_AND_ATTRIBUTES * max(1, len(sids)))(*[SID_AND_ATTRIBUTES(s, 0) for s in sids])
    code = firewallapi.NetworkIsolationSetAppContainerConfig(len(sids), array)
    if code:
        raise OSError(f'NetworkIsolationSetAppContainerConfig {code}')
    return [sid_text(s) for s in sids]


# ---------------------------------------------------------------- package-SID WFP filters

class PackageFilters:
    """Dynamic-session filters: the package may reach only 127.0.0.1/::1 on the proxy port."""

    def __init__(self, sid, proxy_port: int):
        self.engine = G._Engine()
        self.sid, self.port, self.keep, self.ids = sid, proxy_port, [], []

    def field_supported(self) -> bool:
        with self.engine.get('Layer', G._LAYERS[4], G._Layer) as layer:
            return any(layer.fields[i].key and layer.fields[i].key.contents.text() == PACKAGE_FIELD
                       for i in range(layer.count))

    def _condition(self, field, kind, data):
        condition = G._Condition()
        condition.field = G._GUID.of(field)
        condition.match = 0
        if kind == 13:  # FWP_SID
            condition.value.type = 13
            condition.value.value.pointer = self.sid.value
        else:
            condition.value = G._value(kind, data, self.keep)
        return condition

    def _add(self, family, action, weight, extra):
        conditions = [self._condition(PACKAGE_FIELD, 13, None)] + [self._condition(*item) for item in extra]
        array = (G._Condition * len(conditions))(*conditions)
        self.keep.append(array)
        rule = G._Filter()
        rule.key = G._GUID.of(uuid.uuid4())
        rule.display = G._Display('RuleProxy AppContainer lab', None)
        rule.layer = G._GUID.of(G._LAYERS[family])
        rule.sublayer = G._GUID.of(SUBLAYER)
        rule.weight = G._value(1, weight, self.keep)
        rule.count = len(conditions)
        rule.conditions = C.cast(array, C.POINTER(G._Condition))
        rule.action.type = action
        number = G._U64()
        G._error(self.engine.api.FwpmFilterAdd0(self.engine.handle, C.byref(rule), None, C.byref(number)), '添加实验过滤')
        self.ids.append(number.value)

    def __enter__(self):
        session = G._Session()
        session.flags = 1  # FWPM_SESSION_FLAG_DYNAMIC: everything disappears with this handle
        session.timeout = 5000
        G._error(self.engine.api.FwpmEngineOpen0(None, 0xFFFFFFFF, None, C.byref(session),
                                                 C.byref(self.engine.handle)), '连接 WFP')
        with self.engine.transaction():
            sublayer = G._Sublayer()
            sublayer.key = G._GUID.of(SUBLAYER)
            sublayer.display = G._Display('RuleProxy AppContainer lab', None)
            sublayer.weight = 0xFFFF
            G._error(self.engine.api.FwpmSubLayerAdd0(self.engine.handle, C.byref(sublayer), None), '添加实验子层')
            fields = G._FIELDS
            self._add(4, G._PERMIT, 15, ((fields['protocol'], 1, 6), (fields['remote'], 3, 0x7F000001),
                                         (fields['remote_port'], 2, self.port)))
            self._add(6, G._PERMIT, 15, ((fields['protocol'], 1, 6),
                                         (fields['remote'], 11, ipaddress.IPv6Address('::1').packed),
                                         (fields['remote_port'], 2, self.port)))
            self._add(4, G._BLOCK, 0, ())
            self._add(6, G._BLOCK, 0, ())
        return self

    def __exit__(self, *_args):
        self.engine.__exit__()


# ---------------------------------------------------------------- probe (runs inside the container)

PROBE = r'''
import json, socket, subprocess, sys
cfg = json.loads(sys.argv[1])
out = {}
def attempt(name, fn):
    try:
        out[name] = {"ok": True, "detail": fn()}
    except Exception as exc:
        out[name] = {"ok": False, "detail": type(exc).__name__ + ": " + str(exc)[:160]}
def banner(host, port, family=socket.AF_INET):
    with socket.socket(family, socket.SOCK_STREAM) as s:
        s.settimeout(4)
        s.connect((host, port))
        return s.recv(64).decode(errors="replace").strip()
def via_proxy(port, host, target):
    with socket.create_connection(("127.0.0.1", port), timeout=4) as s:
        s.sendall(f"CONNECT {host}:{target} HTTP/1.1\r\nHost: {host}:{target}\r\n\r\n".encode())
        head = b""
        while b"\r\n\r\n" not in head:
            chunk = s.recv(1024)
            if not chunk:
                raise OSError("proxy closed")
            head += chunk
        if b" 200 " not in head.split(b"\r\n")[0]:
            raise OSError(head.split(b"\r\n")[0].decode())
        rest = head.split(b"\r\n\r\n", 1)[1]
        return (rest or s.recv(64)).decode(errors="replace").strip()
attempt("direct_physical_tcp", lambda: banner(cfg["host"], cfg["target"]))
def connect_only(host, port):
    with socket.create_connection((host, port), timeout=4):
        return "connected"
attempt("direct_internet_tcp", lambda: connect_only("1.1.1.1", 443))
attempt("loopback_other_v4", lambda: banner("127.0.0.1", cfg["local"]))
attempt("loopback_other_v6", lambda: banner("::1", cfg["local6"], socket.AF_INET6))
attempt("dns_resolve", lambda: socket.getaddrinfo("example.com", 443)[0][4][0])
def udp():
    with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as s:
        s.settimeout(3)
        s.sendto(b"x", (cfg["host"], cfg["udp"]))
        return s.recvfrom(64)[0].decode()
attempt("direct_physical_udp", udp)
attempt("proxy_to_physical", lambda: via_proxy(cfg["proxy"], cfg["host"], cfg["target"]))
def child():
    code = ("import socket,sys;s=socket.socket();s.settimeout(4);"
            f"s.connect(({cfg['host']!r},{cfg['target']}));print(s.recv(64))")
    run = subprocess.run([sys.executable, "-I", "-c", code], capture_output=True, text=True, timeout=20)
    if run.returncode:
        raise OSError((run.stderr.strip().splitlines() or ["exit " + str(run.returncode)])[-1][:160])
    return run.stdout.strip()
attempt("grandchild_direct_tcp", child)
print("RESULT " + json.dumps(out))
'''

# What each gated phase must show. True = must succeed, False = must fail.
CONFINED = {'direct_physical_tcp': False, 'direct_internet_tcp': False, 'loopback_other_v4': False,
            'loopback_other_v6': False, 'direct_physical_udp': False, 'grandchild_direct_tcp': False,
            'curl_direct': False}
GATES = {
    'control_uncontained': {'direct_physical_tcp': True, 'loopback_other_v4': True, 'direct_physical_udp': True},
    'confined_with_proxy': {**CONFINED, 'proxy_to_physical': True, 'curl_via_proxy': True},
    'confined_firewall_off': {**CONFINED, 'proxy_to_physical': True, 'curl_via_proxy': True},
    'confined_proxy_down': {**CONFINED, 'proxy_to_physical': False, 'curl_via_proxy': False},
}


def _udp_echo():
    server = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    server.bind((physical_ipv4(), 0))

    def serve():
        while True:
            try:
                data, peer = server.recvfrom(64)
                server.sendto(b'RPUDP', peer)
            except OSError:
                return
    threading.Thread(target=serve, daemon=True).start()
    return server


def firewall(enabled: bool | None = None):
    if enabled is not None:
        value = 'True' if enabled else 'False'
        subprocess.run(['powershell', '-NoProfile', '-Command',
                        f'Set-NetFirewallProfile -Profile Domain,Public,Private -Enabled {value}'],
                       check=True, capture_output=True, timeout=60)
    shown = subprocess.run(['powershell', '-NoProfile', '-Command',
                            '(Get-NetFirewallProfile | ForEach-Object { "$($_.Name)=$($_.Enabled)" }) -join ","; '
                            '(Get-Service mpssvc).Status'],
                           capture_output=True, text=True, timeout=60)
    return shown.stdout.strip().replace('\r', '').replace('\n', ' service=')


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument('--work', type=Path, required=True)
    args = parser.parse_args()
    work = args.work.resolve()
    if work.exists():
        shutil.rmtree(work)
    (work / 'tmp').mkdir(parents=True)
    report = {'schema_version': 1, 'windows': sys.getwindowsversion()[:4], 'phases': {}, 'notes': []}
    started = time.monotonic()
    sid = container_sid()
    package = sid_text(sid)
    report['package_sid'] = package
    host = physical_ipv4()
    target = _banner_server(host)
    local = _banner_server('127.0.0.1', banner=b'RPLOCAL\n')
    local6 = _banner_server('::1', socket.AF_INET6, b'RPLOCAL6\n')
    udp = _udp_echo()
    proxy = ConnectProxy()
    probe = work / 'probe.py'
    probe.write_text(PROBE, encoding='utf-8')
    # The container needs read/execute on the interpreter and the probe; write only on work.
    for path, right in ((Path(sys.base_prefix), '(OI)(CI)(RX)'), (work, '(OI)(CI)(M)')):
        grant = subprocess.run(['icacls', str(path), '/grant', f'*{package}:{right}', '/T', '/Q', '/C'],
                               capture_output=True, text=True, timeout=600)
        report['notes'].append(f'icacls {path.name or path}: exit {grant.returncode}')
    env = {k: v for k, v in os.environ.items() if k.upper() not in ('TEMP', 'TMP', 'HTTP_PROXY', 'HTTPS_PROXY',
                                                                      'ALL_PROXY', 'NO_PROXY')}
    env.update(TEMP=str(work / 'tmp'), TMP=str(work / 'tmp'))
    config = {'host': host, 'target': target.getsockname()[1], 'local': local.getsockname()[1],
              'local6': local6.getsockname()[1], 'udp': udp.getsockname()[1], 'proxy': proxy.port}
    report['config'] = config
    report['firewall_initial'] = firewall()

    def run_phase(name, contained=True, edge=False):
        log = work / f'{name}.probe.log'
        outcome = launch(sid, [sys.executable, '-I', str(probe), json.dumps(config)], contained=contained,
                         cwd=work, env=env, log=log, timeout=120)
        text = log.read_text(encoding='utf-8', errors='replace')
        results = {}
        for line in text.splitlines():
            if line.startswith('RESULT '):
                results = json.loads(line[7:])
        if not results:
            results['probe'] = {'ok': False, 'detail': (outcome, text[-400:])}
        for label, extra in (('curl_direct', []), ('curl_via_proxy', ['--proxy', f'http://127.0.0.1:{proxy.port}'])):
            curl_log = work / f'{name}.{label}.log'
            ran = launch(sid, [str(CURL), '-sS', '--ssl-no-revoke', '-o', 'NUL', '-w', '%{http_code}', '--max-time', '15', *extra,
                               PUBLIC_URL], contained=contained, cwd=work, env=env, log=curl_log, timeout=40)
            body = curl_log.read_text(encoding='utf-8', errors='replace').strip()
            results[label] = {'ok': ran.get('exit_code') == 0 and body.endswith('200'), 'detail': body[-160:]}
        if edge and EDGE.exists():
            for label, flags in (('edge_sandboxed', []), ('edge_no_sandbox', ['--no-sandbox'])):
                profile = work / ('edge-' + label)
                profile.mkdir(exist_ok=True)
                edge_log = work / f'{name}.{label}.log'
                ran = launch(sid, [str(EDGE), '--headless=new', '--disable-gpu', '--no-first-run',
                                   f'--user-data-dir={profile}', f'--proxy-server=http://127.0.0.1:{proxy.port}',
                                   *flags, '--dump-dom', PUBLIC_URL],
                             contained=contained, cwd=work, env=env, log=edge_log, timeout=60)
                body = edge_log.read_text(encoding='utf-8', errors='replace')
                results[label] = {'ok': 'Example Domain' in body, 'detail': {**ran, 'tail': body[-300:]}}
        report['phases'][name] = {'contained': contained, 'results': results,
                                  'proxy_tunnels_total': proxy.tunnels, 'firewall': firewall()}
        summary = ' '.join(f"{k}={'Y' if v['ok'] else 'n'}" for k, v in sorted(results.items()))
        print(f'::notice title=AppContainer lab {name}::{summary}', flush=True)

    firewall_changed = False
    try:
        run_phase('control_uncontained', contained=False)
        run_phase('container_only')                      # informational: built-in isolation, loopback blocked
        exemption(sid, True)
        run_phase('exempt_without_filters')              # informational: exemption opens every loopback port
        filters = PackageFilters(sid, proxy.port)
        report['package_field_in_connect_layer'] = None
        with filters:
            report['package_field_in_connect_layer'] = filters.field_supported()
            report['filter_ids'] = filters.ids
            run_phase('confined_with_proxy', edge=True)
            firewall_changed = True
            firewall(False)
            run_phase('confined_firewall_off')
            proxy.close()
            run_phase('confined_proxy_down')
        run_phase('firewall_off_exempt_no_filters')      # informational: what the OS alone keeps closed
    except Exception as exc:  # keep the evidence; the gates below then fail explicitly
        report['error'] = f'{type(exc).__name__}: {exc}'[:400]
        print(f"::error title=AppContainer lab error::{report['error']}", flush=True)
    finally:
        if firewall_changed:
            report['firewall_restored'] = firewall(True)
        try:
            report['exempt_after_cleanup'] = package in exemption(sid, False)
        except OSError as exc:
            report['notes'].append(f'exemption cleanup: {exc}')
        report['profile_deleted'] = userenv.DeleteAppContainerProfile(PROFILE) == 0
        report['seconds'] = round(time.monotonic() - started, 1)
    failures = []
    for phase, expected in GATES.items():
        results = report['phases'].get(phase, {}).get('results', {})
        for key, want in expected.items():
            got = results.get(key, {}).get('ok')
            if got is not want:
                failures.append(f'{phase}.{key}: expected {want}, got {got}')
    report['gate_failures'] = failures
    report['passed'] = not failures and 'error' not in report
    (work / 'report.json').write_text(json.dumps(report, ensure_ascii=False, indent=2), encoding='utf-8')
    print(f"::notice title=AppContainer lab verdict::passed={report['passed']} failures={len(failures)} "
          f"package_field={report.get('package_field_in_connect_layer')} seconds={report['seconds']}", flush=True)
    for failure in failures[:20]:
        print(f'::error title=AppContainer lab gate::{failure}', flush=True)
    return 0 if report['passed'] else 1


if __name__ == '__main__':
    raise SystemExit(main())
