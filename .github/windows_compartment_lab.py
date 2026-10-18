"""Disposable Windows experiment: Linux-netns-like isolation via TCP/IP compartments.

Question: can an ordinary process tree be placed in an otherwise empty TCP/IP
network compartment (the Windows analogue of a Linux network namespace) so
that direct sockets, system DNS and descendants cannot reach the network,
while a privileged relay exposes exactly one loopback proxy port inside it?

Roles (one CI job on a disposable hosted runner):
  driver      hosted runner account: fixtures, phases, browsers, report
  controller  LocalSystem through a one-shot scheduled task. It owns the
              compartments and the in-compartment relay, and binds Jobs that
              other processes created (handle duplication, as a service would)
  launcher    a temporary standard user repeating the product flow: create a
              Job, ask the controller to bind it, then start actors inside it
  actor       a short Python process started inside or outside a bound Job

The compartment routines are iphlpapi exports declared in the Windows SDK
10.0.10586 netioapi.h (CreateCompartment, SetJobCompartmentId, ...). Microsoft
Learn marks the thread/session variants "reserved", so every claim here rests
on this run's own positive and negative controls, not on documentation.
Nothing here enables a product mode or qualifies a product.
"""
from __future__ import annotations

import argparse
import ctypes as C
from ctypes import wintypes as W
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
import json
import os
from pathlib import Path
import secrets
import select
import socket
import struct
import subprocess
import sys
import threading
import time
import traceback
import uuid
import zlib

TASK = 'RuleProxyCompartmentLab'
CLEANUP_TASK = 'RuleProxyCompartmentLabCleanup'
WORK = Path(r'C:\RuleProxyCompartmentLab')
DESCRIPTION = 'RuleProxy compartment lab'
PROGRAMS = {
    'edge': Path(r'C:\Program Files (x86)\Microsoft\Edge\Application\msedge.exe'),
    'chrome': Path(r'C:\Program Files\Google\Chrome\Application\chrome.exe'),
    'firefox': Path(r'C:\Program Files\Mozilla Firefox\firefox.exe'),
}
CHROMIUM = ['--headless=new', '--disable-gpu', '--no-first-run', '--no-default-browser-check',
            '--disable-background-networking', '--enable-logging=stderr', '--v=0']

# ----------------------------------------------------------------------------- native


class GUID(C.Structure):
    _fields_ = [('Data1', C.c_uint32), ('Data2', C.c_uint16), ('Data3', C.c_uint16), ('Data4', C.c_ubyte * 8)]

    @classmethod
    def of(cls, value: uuid.UUID) -> 'GUID':
        result = cls()
        C.memmove(C.byref(result), value.bytes_le, 16)
        return result


class MIB_COMPARTMENT_ROW(C.Structure):
    # netioapi.h: GUID CompartmentGuid; NET_IF_COMPARTMENT_ID CompartmentId;
    # WCHAR Description[IF_MAX_STRING_SIZE + 1] with IF_MAX_STRING_SIZE 256.
    _fields_ = [('CompartmentGuid', GUID), ('CompartmentId', C.c_uint32), ('Description', C.c_wchar * 257)]


class STARTUPINFOW(C.Structure):
    _fields_ = [('cb', W.DWORD), ('lpReserved', W.LPWSTR), ('lpDesktop', W.LPWSTR), ('lpTitle', W.LPWSTR),
                ('dwX', W.DWORD), ('dwY', W.DWORD), ('dwXSize', W.DWORD), ('dwYSize', W.DWORD),
                ('dwXCountChars', W.DWORD), ('dwYCountChars', W.DWORD), ('dwFillAttribute', W.DWORD),
                ('dwFlags', W.DWORD), ('wShowWindow', W.WORD), ('cbReserved2', W.WORD),
                ('lpReserved2', C.c_void_p), ('hStdInput', W.HANDLE), ('hStdOutput', W.HANDLE),
                ('hStdError', W.HANDLE)]


class PROCESS_INFORMATION(C.Structure):
    _fields_ = [('hProcess', W.HANDLE), ('hThread', W.HANDLE), ('dwProcessId', W.DWORD), ('dwThreadId', W.DWORD)]


class JOBOBJECT_BASIC_LIMIT_INFORMATION(C.Structure):
    _fields_ = [('PerProcessUserTimeLimit', C.c_int64), ('PerJobUserTimeLimit', C.c_int64),
                ('LimitFlags', W.DWORD), ('MinimumWorkingSetSize', C.c_size_t),
                ('MaximumWorkingSetSize', C.c_size_t), ('ActiveProcessLimit', W.DWORD),
                ('Affinity', C.c_size_t), ('PriorityClass', W.DWORD), ('SchedulingClass', W.DWORD)]


class IO_COUNTERS(C.Structure):
    _fields_ = [(name, C.c_uint64) for name in ('a', 'b', 'c', 'd', 'e', 'f')]


class JOBOBJECT_EXTENDED_LIMIT_INFORMATION(C.Structure):
    _fields_ = [('BasicLimitInformation', JOBOBJECT_BASIC_LIMIT_INFORMATION), ('IoInfo', IO_COUNTERS),
                ('ProcessMemoryLimit', C.c_size_t), ('JobMemoryLimit', C.c_size_t),
                ('PeakProcessMemoryUsed', C.c_size_t), ('PeakJobMemoryUsed', C.c_size_t)]


class USER_INFO_1(C.Structure):
    _fields_ = [('name', W.LPWSTR), ('password', W.LPWSTR), ('age', W.DWORD), ('privilege', W.DWORD),
                ('home', W.LPWSTR), ('comment', W.LPWSTR), ('flags', W.DWORD), ('script', W.LPWSTR)]


class Native:
    def __init__(self):
        self.k = C.WinDLL('kernel32', use_last_error=True)
        self.a = C.WinDLL('advapi32', use_last_error=True)
        self.i = C.WinDLL('iphlpapi', use_last_error=True)
        P = C.c_void_p
        for owner, name, args, result in (
                (self.k, 'GetCurrentProcess', [], W.HANDLE),
                (self.k, 'OpenProcess', [W.DWORD, W.BOOL, W.DWORD], W.HANDLE),
                (self.k, 'DuplicateHandle', [W.HANDLE, W.HANDLE, W.HANDLE, C.POINTER(W.HANDLE), W.DWORD, W.BOOL,
                                             W.DWORD], W.BOOL),
                (self.k, 'CloseHandle', [W.HANDLE], W.BOOL),
                (self.k, 'CreateJobObjectW', [P, W.LPCWSTR], W.HANDLE),
                (self.k, 'SetInformationJobObject', [W.HANDLE, C.c_int, P, W.DWORD], W.BOOL),
                (self.k, 'AssignProcessToJobObject', [W.HANDLE, W.HANDLE], W.BOOL),
                (self.k, 'TerminateJobObject', [W.HANDLE, W.UINT], W.BOOL),
                (self.k, 'CreateProcessW', [W.LPCWSTR, W.LPWSTR, P, P, W.BOOL, W.DWORD, P, W.LPCWSTR,
                                            C.POINTER(STARTUPINFOW), C.POINTER(PROCESS_INFORMATION)], W.BOOL),
                (self.k, 'ResumeThread', [W.HANDLE], W.DWORD),
                (self.k, 'TerminateProcess', [W.HANDLE, W.UINT], W.BOOL),
                (self.k, 'WaitForSingleObject', [W.HANDLE, W.DWORD], W.DWORD),
                (self.k, 'GetExitCodeProcess', [W.HANDLE, C.POINTER(W.DWORD)], W.BOOL),
                (self.k, 'LocalFree', [P], P),
                (self.a, 'OpenProcessToken', [W.HANDLE, W.DWORD, C.POINTER(W.HANDLE)], W.BOOL),
                (self.a, 'GetTokenInformation', [W.HANDLE, C.c_int, P, W.DWORD, C.POINTER(W.DWORD)], W.BOOL),
                (self.a, 'ConvertSidToStringSidW', [P, C.POINTER(W.LPWSTR)], W.BOOL),
                (self.a, 'LogonUserW', [W.LPCWSTR, W.LPCWSTR, W.LPCWSTR, W.DWORD, W.DWORD, C.POINTER(W.HANDLE)], W.BOOL),
                (self.a, 'CreateProcessWithTokenW', [W.HANDLE, W.DWORD, W.LPCWSTR, W.LPWSTR, W.DWORD, P, W.LPCWSTR,
                                                     C.POINTER(STARTUPINFOW), C.POINTER(PROCESS_INFORMATION)], W.BOOL)):
            function = getattr(owner, name)
            function.argtypes, function.restype = args, result
        self.missing = []
        for name, args, result in (
                ('GetDefaultCompartmentId', [], C.c_uint32),
                ('GetCurrentThreadCompartmentId', [], C.c_uint32),
                ('SetCurrentThreadCompartmentId', [C.c_uint32], C.c_uint32),
                ('GetSessionCompartmentId', [C.c_uint32], C.c_uint32),
                ('GetJobCompartmentId', [W.HANDLE], C.c_uint32),
                ('SetJobCompartmentId', [W.HANDLE, C.c_uint32], C.c_uint32),
                ('InitializeCompartmentEntry', [C.POINTER(MIB_COMPARTMENT_ROW)], None),
                ('CreateCompartment', [C.POINTER(MIB_COMPARTMENT_ROW)], C.c_uint32),
                ('DeleteCompartment', [C.c_uint32], C.c_uint32)):
            try:
                function = getattr(self.i, name)
            except AttributeError:
                self.missing.append(name)
                continue
            function.argtypes, function.restype = args, result

    def check(self, ok, what):
        if not ok:
            error = C.get_last_error()
            raise OSError(error, f'{what} failed: {C.FormatError(error).strip()} ({error})')
        return ok

    def token_user(self, token=None):
        owned = token is None
        if owned:
            token = W.HANDLE()
            self.check(self.a.OpenProcessToken(self.k.GetCurrentProcess(), 8, C.byref(token)), 'OpenProcessToken')
        try:
            size = W.DWORD()
            self.a.GetTokenInformation(token, 1, None, 0, C.byref(size))
            buffer = C.create_string_buffer(max(size.value, 64))
            self.check(self.a.GetTokenInformation(token, 1, buffer, len(buffer), C.byref(size)), 'GetTokenInformation')
            text = W.LPWSTR()
            self.check(self.a.ConvertSidToStringSidW(C.cast(buffer, C.POINTER(C.c_void_p))[0], C.byref(text)),
                       'ConvertSidToStringSidW')
            try:
                return text.value
            finally:
                self.k.LocalFree(C.cast(text, C.c_void_p))
        finally:
            if owned:
                self.k.CloseHandle(token)

    def new_job(self):
        job = self.check(self.k.CreateJobObjectW(None, None), 'CreateJobObjectW')
        limits = JOBOBJECT_EXTENDED_LIMIT_INFORMATION()
        limits.BasicLimitInformation.LimitFlags = 0x2000  # KILL_ON_JOB_CLOSE, no breakaway allowed
        self.check(self.k.SetInformationJobObject(job, 9, C.byref(limits), C.sizeof(limits)), 'SetInformationJobObject')
        return job

    def spawn(self, argv, *, job=None, env=None, cwd=None, stdout=None):
        """Create suspended, join the Job before the first instruction, then resume."""
        import msvcrt
        info = STARTUPINFOW()
        info.cb = C.sizeof(info)
        inherit = False
        stream = handle = None
        if stdout is not None:
            stream = open(stdout, 'wb')
            handle = msvcrt.get_osfhandle(stream.fileno())
            os.set_handle_inheritable(handle, True)
            info.dwFlags = 0x100  # STARTF_USESTDHANDLES
            info.hStdOutput = info.hStdError = handle
            inherit = True
        process = PROCESS_INFORMATION()
        block = None
        if env is not None:
            block = C.create_unicode_buffer('\0'.join(f'{k}={v}' for k, v in sorted(env.items(), key=lambda x: x[0].upper())) + '\0\0')
        flags = 0x4 | 0x400 | 0x08000000  # CREATE_SUSPENDED | UNICODE_ENVIRONMENT | NO_WINDOW
        try:
            self.check(self.k.CreateProcessW(None, C.create_unicode_buffer(subprocess.list2cmdline([str(x) for x in argv])),
                                             None, None, inherit, flags, block, str(cwd) if cwd else None,
                                             C.byref(info), C.byref(process)), 'CreateProcessW')
        finally:
            if stream is not None:
                os.set_handle_inheritable(handle, False)
                stream.close()
        return self._start(process, job)

    def _start(self, process, job):
        try:
            if job is not None:
                self.check(self.k.AssignProcessToJobObject(job, process.hProcess), 'AssignProcessToJobObject')
            if self.k.ResumeThread(process.hThread) == 0xFFFFFFFF:
                self.check(False, 'ResumeThread')
        except BaseException:
            self.k.TerminateProcess(process.hProcess, 1)
            self.k.CloseHandle(process.hThread)
            self.k.CloseHandle(process.hProcess)
            raise
        self.k.CloseHandle(process.hThread)
        return process.hProcess, process.dwProcessId

    def wait(self, process, seconds):
        timed_out = self.k.WaitForSingleObject(process, int(seconds * 1000)) != 0
        if timed_out:
            self.k.TerminateProcess(process, 0xC0DE)
            self.k.WaitForSingleObject(process, 5000)
        code = W.DWORD()
        self.check(self.k.GetExitCodeProcess(process, C.byref(code)), 'GetExitCodeProcess')
        self.k.CloseHandle(process)
        return code.value, timed_out


def write_json(path: Path, value):
    temporary = path.with_name(path.name + '.tmp')
    temporary.write_text(json.dumps(value, indent=1, default=str), encoding='utf-8')
    os.replace(temporary, path)


# ----------------------------------------------------------------------------- actor
# argv: actor.py config.json result.json label depth. Labels containing
# 'inside' use the in-compartment relay port; all others use the fixture.

ACTOR = r'''
import ctypes as C, json, os, secrets, socket, struct, subprocess, sys, time, urllib.request
cfg = json.loads(open(sys.argv[1], encoding='utf-8').read())
result_path, label, depth = sys.argv[2], sys.argv[3], int(sys.argv[4])
inside = 'inside' in label
port = cfg['relay_port'] if inside else cfg['fixture_port']
out = {'label': label, 'pid': os.getpid(), 'depth': depth}
i = C.WinDLL('iphlpapi', use_last_error=True)
i.GetCurrentThreadCompartmentId.restype = C.c_uint32
i.SetCurrentThreadCompartmentId.argtypes = [C.c_uint32]; i.SetCurrentThreadCompartmentId.restype = C.c_uint32
i.SetJobCompartmentId.argtypes = [C.c_void_p, C.c_uint32]; i.SetJobCompartmentId.restype = C.c_uint32
k = C.WinDLL('kernel32', use_last_error=True); n = C.WinDLL('ntdll')
k.CreateJobObjectW.restype = C.c_void_p; k.CreateJobObjectW.argtypes = [C.c_void_p, C.c_wchar_p]
k.AssignProcessToJobObject.argtypes = [C.c_void_p, C.c_void_p]; n.NtResumeProcess.argtypes = [C.c_void_p]
out['compartment'] = int(i.GetCurrentThreadCompartmentId())
def error(e):
    return {'ok': False, 'type': type(e).__name__, 'winerror': getattr(e, 'winerror', None), 'errno': getattr(e, 'errno', None), 'text': str(e)[:160]}
def tcp(host, p, family=socket.AF_INET):
    try:
        with socket.socket(family, socket.SOCK_STREAM) as s:
            s.settimeout(3)
            payload = (cfg['nonce'] + ':' + label + ':tcp').encode()
            s.connect((host, p)); s.sendall(payload); data = s.recv(256)
        return {'ok': data == payload}
    except Exception as e:
        return error(e)
def connect_only(host, p, family=socket.AF_INET):
    try:
        with socket.socket(family, socket.SOCK_STREAM) as s:
            s.settimeout(3); s.connect((host, p))
            s.settimeout(1)
            try: banner = s.recv(64).decode('ascii', 'replace')
            except Exception: banner = ''
        return {'ok': True, 'banner': banner}
    except Exception as e:
        return error(e)
def udp(host, p, family=socket.AF_INET):
    try:
        with socket.socket(family, socket.SOCK_DGRAM) as s:
            s.settimeout(2)
            payload = (cfg['nonce'] + ':' + label + ':udp').encode()
            s.sendto(payload, (host, p)); data, _ = s.recvfrom(256)
        return {'ok': data == payload}
    except Exception as e:
        return error(e)
def dns_udp(server):
    try:
        name = secrets.token_hex(8) + '.example.com'
        query = struct.pack('!HHHHHH', 0x5250, 0x0100, 1, 0, 0, 0) + b''.join(bytes([len(x)]) + x.encode() for x in name.split('.')) + b'\0' + struct.pack('!HH', 1, 1)
        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as s:
            s.settimeout(3); s.sendto(query, (server, 53)); data, _ = s.recvfrom(2048)
        return {'ok': len(data) > 12 and data[:2] == b'\x52\x50'}
    except Exception as e:
        return error(e)
def system_dns():
    name = secrets.token_hex(16) + '.1.2.3.4.sslip.io'
    try:
        values = sorted({x[4][0] for x in socket.getaddrinfo(name, 443, socket.AF_INET, socket.SOCK_STREAM)})
        return {'ok': values == ['1.2.3.4'], 'addresses': values, 'name': name}
    except Exception as e:
        return dict(error(e), name=name)
def rows():
    r = {}
    r['tcp4_host_ip'] = tcp(cfg['host_ip'], cfg['echo_tcp'])
    r['tcp4_loopback'] = tcp('127.0.0.1', cfg['echo_tcp'])
    r['udp4_host_ip'] = udp(cfg['host_ip'], cfg['echo_udp'])
    r['udp4_loopback'] = udp('127.0.0.1', cfg['echo_udp'])
    r['tcp6_loopback'] = tcp('::1', cfg['echo_tcp6'], socket.AF_INET6)
    r['udp6_loopback'] = udp('::1', cfg['echo_udp6'], socket.AF_INET6)
    r['tcp4_public_1111_443'] = connect_only('1.1.1.1', 443)
    r['udp4_public_dns_8888'] = dns_udp('8.8.8.8')
    r['relay_port_loopback'] = connect_only('127.0.0.1', cfg['relay_port'])
    r['system_dns'] = system_dns()
    return r
def proxy_get():
    target = 'http://' + label + '.invalid/' + cfg['nonce'] + '/' + label
    try:
        opener = urllib.request.build_opener(urllib.request.ProxyHandler({'http': 'http://127.0.0.1:' + str(port)}))
        with opener.open(target, timeout=6) as response:
            body = response.read(4096).decode('ascii', 'replace')
        return {'ok': ('RuleProxyFixture:' + cfg['nonce'] + ':' + label) in body, 'port': port}
    except Exception as e:
        return dict(error(e), port=port)
def child(name, flags=0, job=None):
    path = result_path + '.' + name
    p = subprocess.Popen([sys.executable, '-I', '-B', sys.argv[0], sys.argv[1], path, name, str(depth + 1)],
                         creationflags=flags | (0x4 if job else 0))
    if job:
        ok = bool(k.AssignProcessToJobObject(job, int(p._handle)))
        if not ok:
            e = C.get_last_error(); p.kill(); p.wait(10)
            return {'assign_error': e}
        n.NtResumeProcess(int(p._handle))
    code = p.wait(120)
    try:
        value = json.loads(open(path, encoding='utf-8').read())
    except Exception as e:
        value = {'read_error': repr(e)}
    value['exit_code'] = code
    return value
if cfg.get('linger') == label:
    go = cfg['linger_go']
    deadline = time.time() + 180
    while time.time() < deadline and not os.path.exists(go):
        time.sleep(0.25)
    out['linger_released'] = os.path.exists(go)
    out['compartment_after'] = int(i.GetCurrentThreadCompartmentId())
out['rows'] = rows()
out['proxy'] = proxy_get()
if depth == 0:
    try:
        out['child'] = child(label + '-child')
    except Exception as e:
        out['child'] = {'spawn_error': repr(e)}
    try:
        p = subprocess.Popen([sys.executable, '-c', 'print(1)'], creationflags=0x01000000)
        out['breakaway'] = {'started': True, 'exit': p.wait(30)}
    except Exception as e:
        out['breakaway'] = dict(error(e), started=False)
    try:
        nested_job = k.CreateJobObjectW(None, None)
        out['nested'] = child(label + '-nested', job=nested_job)
    except Exception as e:
        out['nested'] = {'spawn_error': repr(e)}
    # Escape attempts that an uncooperative app could try from inside.
    escape = {}
    escape['thread_set_default'] = int(i.SetCurrentThreadCompartmentId(cfg['default_compartment']))
    escape['thread_after_set'] = int(i.GetCurrentThreadCompartmentId())
    escape['thread_tcp4_host_ip'] = tcp(cfg['host_ip'], cfg['echo_tcp'])
    i.SetCurrentThreadCompartmentId(out['compartment'])
    try:
        own_job = k.CreateJobObjectW(None, None)
        escape['job_set_default'] = int(i.SetJobCompartmentId(own_job, cfg['default_compartment']))
        if escape['job_set_default'] == 0:
            escape['job_child'] = child(label + '-escape', job=own_job)
    except Exception as e:
        escape['job_error'] = repr(e)
    out['escape'] = escape
write = open(result_path, 'w', encoding='utf-8'); write.write(json.dumps(out)); write.close()
'''

# The product-like flow for a temporary standard user: create a Job, ask the
# controller (as a SYSTEM service would be asked) to bind it, start actors.
LAUNCHER = r'''
import ctypes as C, json, os, subprocess, sys, time
from pathlib import Path
from ctypes import wintypes as W
cfg_path, userdir = sys.argv[1], Path(sys.argv[2])
k = C.WinDLL('kernel32', use_last_error=True); n = C.WinDLL('ntdll')
k.CreateJobObjectW.restype = C.c_void_p; k.CreateJobObjectW.argtypes = [C.c_void_p, C.c_wchar_p]
k.AssignProcessToJobObject.argtypes = [C.c_void_p, C.c_void_p]; n.NtResumeProcess.argtypes = [C.c_void_p]
out = {'pid': os.getpid()}
def run(label, job):
    path = str(userdir / ('actor-' + label + '.json'))
    p = subprocess.Popen([sys.executable, '-I', '-B', str(userdir.parent / 'actor.py'), cfg_path, path, label, '0'],
                         creationflags=0x4 if job else 0)
    if job:
        if not k.AssignProcessToJobObject(job, int(p._handle)):
            e = C.get_last_error(); p.kill(); p.wait(10)
            return {'assign_error': e}
        n.NtResumeProcess(int(p._handle))
    code = p.wait(240)
    try:
        value = json.loads(open(path, encoding='utf-8').read())
    except Exception as e:
        value = {'read_error': repr(e)}
    value['exit_code'] = code
    return value
try:
    job = k.CreateJobObjectW(None, None)
    out['job_created'] = bool(job)
    request = userdir / 'req-user.json'
    tmp = userdir / 'req-user.json.tmp'
    tmp.write_text(json.dumps({'op': 'bind', 'pid': os.getpid(), 'handle': int(job), 'compartment': 'A'}), encoding='utf-8')
    os.replace(tmp, request)
    response = userdir / 'resp-user.json'
    deadline = time.time() + 60
    while time.time() < deadline and not response.exists():
        time.sleep(0.2)
    out['bind'] = json.loads(response.read_text(encoding='utf-8')) if response.exists() else {'timeout': True}
    out['user-outside'] = run('user-outside', None)
    if out['bind'].get('code') == 0:
        out['user-inside'] = run('user-inside', job)
except Exception as e:
    out['error'] = repr(e)
tmp = userdir / 'launcher-result.json.tmp'
tmp.write_text(json.dumps(out), encoding='utf-8')
os.replace(tmp, userdir / 'launcher-result.json')
'''

# ----------------------------------------------------------------------------- controller


class Controller:
    def __init__(self, args):
        self.args = args
        self.work = Path(args.work)
        self.userdir = self.work / 'user'
        self.native = Native()
        self.i = self.native.i
        self.report = {'role': 'controller', 'started': time.time(), 'missing_exports': self.native.missing,
                       'identity': self.native.token_user(), 'requests': []}
        self.compartments = {}
        self.keep = set()
        self.jobs = []
        self.listeners, self.connections = [], []
        self.relay = {'accepted': 0, 'forward_errors': [], 'listener_errors': []}
        self.listening = threading.Event()
        self.stop = threading.Event()
        self.account = None
        self.default = int(self.i.GetDefaultCompartmentId())

    def create(self, name):
        row = MIB_COMPARTMENT_ROW()
        self.i.InitializeCompartmentEntry(C.byref(row))
        guid = uuid.uuid4()
        row.CompartmentGuid = GUID.of(guid)
        row.Description = DESCRIPTION + ' ' + name
        code = int(self.i.CreateCompartment(C.byref(row)))
        if code == 0:
            self.compartments[name] = int(row.CompartmentId)
        return {'code': code, 'id': int(row.CompartmentId), 'guid': str(guid)}

    def delete(self, name):
        cid = self.compartments.get(name)
        if cid is None:
            return {'code': None, 'missing': True}
        code = int(self.i.DeleteCompartment(cid))
        if code == 0:
            del self.compartments[name]
        return {'code': code, 'id': cid}

    def thread_probe(self, cid):
        probe = {}

        def body():
            probe['set'] = int(self.i.SetCurrentThreadCompartmentId(cid))
            probe['get'] = int(self.i.GetCurrentThreadCompartmentId())
            for key, (host, port) in {'public_1111_443': ('1.1.1.1', 443),
                                      'host_fixture_loopback': ('127.0.0.1', self.args.fixture_port)}.items():
                try:
                    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
                        s.settimeout(3)
                        s.connect((host, port))
                    probe[key] = {'ok': True}
                except OSError as e:
                    probe[key] = {'ok': False, 'winerror': getattr(e, 'winerror', None)}
            name = secrets.token_hex(16) + '.1.2.3.4.sslip.io'
            try:
                probe['dns'] = {'ok': True, 'addresses': sorted({x[4][0] for x in socket.getaddrinfo(name, 443, socket.AF_INET)})}
            except OSError as e:
                probe['dns'] = {'ok': False, 'errno': getattr(e, 'errno', None), 'text': str(e)[:120]}
        worker = threading.Thread(target=body)
        worker.start()
        worker.join(30)
        return probe

    def default_dns(self):
        name = secrets.token_hex(16) + '.1.2.3.4.sslip.io'
        try:
            return {'ok': True, 'addresses': sorted({x[4][0] for x in socket.getaddrinfo(name, 443, socket.AF_INET)})}
        except OSError as e:
            return {'ok': False, 'errno': getattr(e, 'errno', None), 'text': str(e)[:120]}

    # -- relay: listener bound inside compartment A, upstream in the default one
    def start_relay(self, cid):
        def pump(source, target):
            try:
                while True:
                    data = source.recv(65536)
                    if not data:
                        break
                    target.sendall(data)
            except OSError:
                pass
            finally:
                for s in (source, target):
                    try:
                        s.shutdown(socket.SHUT_RDWR)
                    except OSError:
                        pass

        def forward(accepted):
            upstream = None
            try:
                self.i.SetCurrentThreadCompartmentId(self.default)
                upstream = socket.create_connection(('127.0.0.1', self.args.fixture_port), timeout=5)
                self.connections.append(upstream)
                upstream.settimeout(None)
                accepted.settimeout(None)
                back = threading.Thread(target=pump, args=(upstream, accepted), daemon=True)
                back.start()
                pump(accepted, upstream)
                back.join(30)
            except OSError as e:
                self.relay['forward_errors'].append(str(e)[:160])
            finally:
                for s in (accepted, upstream):
                    if s is not None:
                        s.close()

        def listen():
            try:
                self.relay['listener_set'] = int(self.i.SetCurrentThreadCompartmentId(cid))
                self.relay['listener_get'] = int(self.i.GetCurrentThreadCompartmentId())
                for family, host in ((socket.AF_INET, '127.0.0.1'), (socket.AF_INET6, '::1')):
                    s = socket.socket(family, socket.SOCK_STREAM)
                    try:
                        s.bind((host, self.args.relay_port))
                        s.listen(64)
                        self.listeners.append(s)
                        self.relay['bound_' + host] = True
                    except OSError as e:
                        self.relay['listener_errors'].append(f'{host}: {e}'[:160])
                        s.close()
            finally:
                self.listening.set()
            while not self.stop.is_set():
                try:
                    ready, _, _ = select.select(self.listeners, [], [], 0.5)
                except (OSError, ValueError):
                    break
                for s in ready:
                    try:
                        accepted, _ = s.accept()
                    except OSError:
                        continue
                    self.relay['accepted'] += 1
                    self.connections.append(accepted)
                    threading.Thread(target=forward, args=(accepted,), daemon=True).start()

        threading.Thread(target=listen, daemon=True).start()
        self.listening.wait(10)

    def stop_relay(self):
        self.stop.set()
        time.sleep(0.8)
        closed = 0
        for s in self.listeners + self.connections:
            try:
                s.close()
                closed += 1
            except OSError:
                pass
        self.listeners, self.connections = [], []
        return {'closed': closed}

    def bind(self, request):
        """Duplicate a Job handle owned by another process and bind it, as a service would."""
        n, k = self.native, self.native.k
        cid = self.compartments.get(request.get('compartment', 'A'))
        if cid is None:
            return {'code': None, 'error': 'unknown compartment'}
        process = k.OpenProcess(0x0040 | 0x1000, False, int(request['pid']))  # DUP_HANDLE | QUERY_LIMITED
        if not process:
            return {'code': None, 'open_error': C.get_last_error()}
        try:
            duplicate = W.HANDLE()
            if not k.DuplicateHandle(process, W.HANDLE(int(request['handle'])), k.GetCurrentProcess(),
                                     C.byref(duplicate), 0, False, 2):
                return {'code': None, 'dup_error': C.get_last_error()}
        finally:
            k.CloseHandle(process)
        self.jobs.append(duplicate.value)
        code = int(self.i.SetJobCompartmentId(duplicate, cid))
        return {'code': code, 'job_compartment': int(self.i.GetJobCompartmentId(duplicate)), 'compartment_id': cid}

    def user_flow(self):
        """Create a temporary standard user and start the product-like launcher as that user."""
        net = C.WinDLL('netapi32')
        net.NetUserAdd.argtypes = [W.LPCWSTR, W.DWORD, C.c_void_p, C.POINTER(W.DWORD)]
        net.NetLocalGroupAddMembers.argtypes = [W.LPCWSTR, W.LPCWSTR, W.DWORD, C.c_void_p, W.DWORD]
        name, password = 'rpc' + secrets.token_hex(5), secrets.token_urlsafe(24) + 'aA1!'
        info = USER_INFO_1(name, password, 0, 1, None, 'RuleProxy compartment lab', 0x10201, None)
        failed = W.DWORD()
        code = net.NetUserAdd(None, 1, C.byref(info), C.byref(failed))
        if code:
            return {'user_add': code}
        self.account = name
        member = W.LPWSTR(name)
        group = net.NetLocalGroupAddMembers(None, 'Users', 3, C.byref(member), 1)
        self.userdir.mkdir(exist_ok=True)
        subprocess.run(['icacls', str(self.userdir), '/grant', f'{name}:(OI)(CI)M', '/Q'], capture_output=True, timeout=60)
        token = W.HANDLE()
        if not self.native.a.LogonUserW(name, '.', password, 2, 0, C.byref(token)):
            return {'user_add': 0, 'group': group, 'logon_error': C.get_last_error()}
        try:
            sid = self.native.token_user(token)
            launcher = self.work / 'launcher.py'
            command = subprocess.list2cmdline([sys.executable, '-I', '-B', str(launcher), str(self.work / 'actor.json'),
                                               str(self.userdir)])
            startup, process = STARTUPINFOW(), PROCESS_INFORMATION()
            startup.cb = C.sizeof(startup)
            if not self.native.a.CreateProcessWithTokenW(token, 1, None, C.create_unicode_buffer(command), 0x08000000,
                                                         None, str(self.userdir), C.byref(startup), C.byref(process)):
                return {'user_add': 0, 'group': group, 'create_error': C.get_last_error()}
            self.native.k.CloseHandle(process.hThread)
            self.native.k.CloseHandle(process.hProcess)
            return {'user_add': 0, 'group': group, 'sid': sid, 'pid': process.dwProcessId}
        finally:
            self.native.k.CloseHandle(token)

    def remove_user(self):
        if not self.account:
            return None
        net = C.WinDLL('netapi32')
        net.NetUserDel.argtypes = [W.LPCWSTR, W.LPCWSTR]
        return int(net.NetUserDel(None, self.account))

    def handle(self, request):
        op = request.get('op')
        if op == 'bind':
            return self.bind(request)
        if op == 'create':
            return self.create(request['name'])
        if op == 'delete':
            return self.delete(request['name'])
        if op == 'keep':
            self.keep.add(request['name'])
            return {'kept': request['name'], 'id': self.compartments.get(request['name'])}
        if op == 'stop_relay':
            return self.stop_relay()
        if op == 'user_flow':
            return self.user_flow()
        if op == 'exit':
            return {'exiting': True}
        return {'error': 'unknown op'}

    def serve(self):
        deadline = time.monotonic() + self.args.timeout
        while time.monotonic() < deadline:
            pending = sorted(self.work.glob('req-*.json')) + sorted(self.userdir.glob('req-*.json'))
            for path in pending:
                try:
                    request = json.loads(path.read_text(encoding='utf-8'))
                except (OSError, ValueError):
                    continue
                try:
                    response = self.handle(request)
                except Exception as e:
                    response = {'exception': f'{type(e).__name__}: {e}'[:300]}
                self.report['requests'].append({'request': request, 'response': response})
                write_json(path.with_name(path.name.replace('req-', 'resp-', 1)), response)
                path.unlink()
                if request.get('op') == 'exit':
                    return
            time.sleep(0.2)

    def run(self):
        try:
            created = self.create('A')
            self.report['create_A'] = created
            if created['code']:
                raise OSError(created['code'], 'CreateCompartment failed')
            cid = self.compartments['A']
            self.report['default_compartment'] = self.default
            self.report['thread_probe'] = self.thread_probe(cid)
            self.report['default_thread_dns'] = self.default_dns()
            self.start_relay(cid)
            self.report['relay'] = self.relay
            write_json(self.work / 'controller-ready.json', self.report)
            self.serve()
        except Exception as e:
            self.report['error'] = f'{type(e).__name__}: {e}'
            self.report['traceback'] = traceback.format_exc()[-3000:]
            write_json(self.work / 'controller-ready.json', self.report)
        finally:
            self.report['final_stop_relay'] = self.stop_relay()
            terminated = []
            for job in self.jobs:
                terminated.append(bool(self.native.k.TerminateJobObject(job, 1)))
                self.native.k.CloseHandle(job)
            self.report['terminated_jobs'] = terminated
            time.sleep(1.0)
            deletes = {}
            for name in [name for name in self.compartments if name not in self.keep]:
                codes = []
                for _ in range(8):
                    result = self.delete(name)
                    codes.append(result['code'])
                    if result['code'] == 0:
                        break
                    time.sleep(1.0)
                deletes[name] = codes
            self.report['final_deletes'] = deletes
            self.report['kept'] = {name: self.compartments.get(name) for name in self.keep}
            self.report['user_removed'] = self.remove_user()
            self.report['relay'] = self.relay
            self.report['finished'] = time.time()
            write_json(self.work / 'controller-final.json', self.report)


def cleanup(args) -> int:
    native = Native()
    result = {'identity': native.token_user(), 'deletes': {}}
    for cid in args.ids:
        result['deletes'][str(cid)] = int(native.i.DeleteCompartment(int(cid)))
    write_json(Path(args.out), result)
    return 0


# ----------------------------------------------------------------------------- driver fixtures


class Fixture:
    """Local HTTP endpoint: proxy mode answers absolute-URI GETs; direct mode plain paths."""

    def __init__(self, nonce, direct=False):
        self.nonce, self.direct = nonce, direct
        self.received, self.lock = [], threading.Lock()
        owner = self

        class Handler(BaseHTTPRequestHandler):
            def log_message(self, *_):
                pass

            def do_GET(self):
                path, label = self.path, None
                if owner.direct:
                    parts = path.strip('/').split('/')
                    if len(parts) == 2 and parts[0] == owner.nonce:
                        label = parts[1]
                elif path.startswith('http://'):
                    host, _, tail = path[len('http://'):].partition('/')
                    parts = tail.split('/')
                    if len(parts) == 2 and parts[0] == owner.nonce and host == parts[1] + '.invalid':
                        label = parts[1]
                if label is None:
                    self.send_error(403)
                    return
                with owner.lock:
                    owner.received.append(label)
                body = ('<!doctype html><html><head><title>RuleProxy fixture</title></head><body>'
                        + owner.marker(label) + '</body></html>').encode('ascii')
                self.send_response(200)
                self.send_header('Content-Type', 'text/html; charset=utf-8')
                self.send_header('Content-Length', str(len(body)))
                self.send_header('Cache-Control', 'no-store')
                self.end_headers()
                self.wfile.write(body)

            def do_CONNECT(self):
                with owner.lock:
                    owner.received.append('CONNECT ' + self.path)
                self.send_error(403)

        self.server = ThreadingHTTPServer(('0.0.0.0' if direct else '127.0.0.1', 0), Handler)
        self.server.daemon_threads = True
        self.port = self.server.server_port
        threading.Thread(target=self.server.serve_forever, daemon=True).start()

    def marker(self, label):
        return 'RuleProxyFixture:' + self.nonce + ':' + label

    def count(self, label):
        with self.lock:
            return self.received.count(label)

    def close(self):
        self.server.shutdown()
        self.server.server_close()


class Echo:
    def __init__(self):
        self.payloads, self.lock, self.sockets = [], threading.Lock(), []
        self.tcp4 = self._tcp(socket.AF_INET, '0.0.0.0')
        self.tcp6 = self._tcp(socket.AF_INET6, '::')
        self.udp4 = self._udp(socket.AF_INET, '0.0.0.0')
        self.udp6 = self._udp(socket.AF_INET6, '::')

    def _record(self, data):
        with self.lock:
            self.payloads.append(data[:128].decode('ascii', 'replace'))

    def _tcp(self, family, host):
        s = socket.socket(family, socket.SOCK_STREAM)
        if family == socket.AF_INET6:
            s.setsockopt(socket.IPPROTO_IPV6, socket.IPV6_V6ONLY, 1)
        s.bind((host, 0))
        s.listen(32)
        self.sockets.append(s)

        def serve():
            while True:
                try:
                    c, _ = s.accept()
                except OSError:
                    return
                try:
                    c.settimeout(3)
                    data = c.recv(256)
                    self._record(data)
                    c.sendall(data)
                except OSError:
                    pass
                finally:
                    c.close()
        threading.Thread(target=serve, daemon=True).start()
        return s.getsockname()[1]

    def _udp(self, family, host):
        s = socket.socket(family, socket.SOCK_DGRAM)
        if family == socket.AF_INET6:
            s.setsockopt(socket.IPPROTO_IPV6, socket.IPV6_V6ONLY, 1)
        s.bind((host, 0))
        self.sockets.append(s)

        def serve():
            while True:
                try:
                    data, peer = s.recvfrom(2048)
                except OSError:
                    return
                self._record(data)
                try:
                    s.sendto(data, peer)
                except OSError:
                    pass
        threading.Thread(target=serve, daemon=True).start()
        return s.getsockname()[1]

    def close(self):
        for s in self.sockets:
            s.close()


class Decoy:
    """A default-compartment listener on the relay port, to prove loopback separation."""

    def __init__(self, port):
        self.error = None
        self.socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        try:
            self.socket.bind(('127.0.0.1', port))
            self.socket.listen(16)
        except OSError as e:
            self.error = str(e)[:160]
            self.socket.close()
            self.socket = None
            return

        def serve():
            while True:
                try:
                    c, _ = self.socket.accept()
                except OSError:
                    return
                try:
                    c.sendall(b'RULEPROXY-DECOY\n')
                except OSError:
                    pass
                c.close()
        threading.Thread(target=serve, daemon=True).start()

    def close(self):
        if self.socket:
            self.socket.close()


def host_ipv4():
    with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as s:
        s.connect(('8.8.8.8', 53))
        return s.getsockname()[0]


def powershell(script, timeout=90):
    try:
        out = subprocess.run(['powershell', '-NoProfile', '-NonInteractive', '-Command',
                              "$ErrorActionPreference='Stop';[Console]::OutputEncoding=[Text.UTF8Encoding]::new($false);"
                              + script], capture_output=True, timeout=timeout)
        return {'code': out.returncode, 'stdout': out.stdout.decode('utf-8', 'replace')[-20000:],
                'stderr': out.stderr.decode('utf-8', 'replace')[-4000:]}
    except subprocess.TimeoutExpired:
        return {'code': None, 'timeout': True}


def png_valid(path: Path) -> bool:
    if not path.is_file() or not 33 <= path.stat().st_size <= 8 * 1024 * 1024:
        return False
    data = path.read_bytes()
    if data[:8] != b'\x89PNG\r\n\x1a\n':
        return False
    offset, image = 8, False
    while offset + 12 <= len(data):
        size = struct.unpack('!I', data[offset:offset + 4])[0]
        kind, end = data[offset + 4:offset + 8], offset + 12 + size
        if end > len(data) or zlib.crc32(data[offset + 4:end - 4]) != struct.unpack('!I', data[end - 4:end])[0]:
            return False
        image = image or (kind == b'IDAT' and size > 0)
        if kind == b'IEND':
            return image
        offset = end
    return False


def read_tail(path: Path, limit=6000):
    try:
        data = path.read_bytes()
    except OSError:
        return ''
    return data[-limit:].decode('utf-8', 'replace')


def safe_env(work: Path, label: str):
    keep = {'SYSTEMROOT', 'WINDIR', 'PATH', 'COMSPEC', 'PATHEXT', 'PROGRAMFILES', 'PROGRAMFILES(X86)',
            'PROGRAMW6432', 'COMMONPROGRAMFILES', 'COMMONPROGRAMFILES(X86)', 'COMMONPROGRAMW6432', 'OS',
            'NUMBER_OF_PROCESSORS', 'PROCESSOR_ARCHITECTURE', 'PROCESSOR_IDENTIFIER', 'PROCESSOR_LEVEL',
            'PROCESSOR_REVISION', 'SYSTEMDRIVE', 'PROGRAMDATA', 'ALLUSERSPROFILE', 'PUBLIC',
            'USERNAME', 'USERDOMAIN', 'COMPUTERNAME', 'HOMEDRIVE', 'HOMEPATH', 'USERPROFILE', 'APPDATA', 'LOCALAPPDATA'}
    env = {k: v for k, v in os.environ.items() if k.upper() in keep}
    temp = work / 'tmp' / label
    temp.mkdir(parents=True, exist_ok=True)
    env.update(TEMP=str(temp), TMP=str(temp))
    return env


class Requests:
    def __init__(self, work):
        self.work, self.sequence = work, 0

    def __call__(self, op, timeout=120, **fields):
        self.sequence += 1
        name = f'{self.sequence:03d}-{op}.json'
        write_json(self.work / ('req-' + name), {'op': op, **fields})
        response = self.work / ('resp-' + name)
        deadline = time.monotonic() + timeout
        while time.monotonic() < deadline and not response.exists():
            time.sleep(0.2)
        if not response.exists():
            return {'timeout': True}
        return json.loads(response.read_text(encoding='utf-8'))


def schedule_system(name, wrapper: Path):
    return powershell(
        f"$a=New-ScheduledTaskAction -Execute 'cmd.exe' -Argument '/c \"{wrapper}\"';"
        f"$p=New-ScheduledTaskPrincipal -UserId 'SYSTEM' -LogonType ServiceAccount -RunLevel Highest;"
        f"$s=New-ScheduledTaskSettingsSet -ExecutionTimeLimit (New-TimeSpan -Minutes 30) -AllowStartIfOnBatteries;"
        f"Register-ScheduledTask -TaskName '{name}' -Action $a -Principal $p -Settings $s -Force | Out-Null;"
        f"Start-ScheduledTask -TaskName '{name}'; 'started'")


def wait_file(path: Path, seconds):
    deadline = time.monotonic() + seconds
    while time.monotonic() < deadline and not path.exists():
        time.sleep(0.5)
    return path.exists()


def lab_compartments():
    value = powershell('@(Get-NetCompartment | Select-Object CompartmentId,CompartmentDescription) | ConvertTo-Json -Compress')
    try:
        rows = json.loads(value.get('stdout') or '[]')
    except ValueError:
        return value, []
    rows = rows if isinstance(rows, list) else [rows]
    return rows, [row['CompartmentId'] for row in rows if str(row.get('CompartmentDescription', '')).startswith(DESCRIPTION)]


# ----------------------------------------------------------------------------- driver


def driver(args) -> int:
    sys.stdout.reconfigure(encoding='utf-8', errors='backslashreplace')
    if os.name != 'nt' or os.environ.get('GITHUB_ACTIONS') != 'true':
        raise SystemExit('requires a disposable Windows Actions runner')
    work = WORK
    if work.exists():
        raise SystemExit('work directory already exists')
    work.mkdir(parents=True)
    (work / 'user').mkdir()
    out_dir = Path(args.out).resolve()
    out_dir.mkdir(parents=True, exist_ok=True)
    native = Native()
    nonce = secrets.token_hex(12)
    report = {'schema_version': 2, 'source_commit': os.environ.get('GITHUB_SHA'), 'nonce': nonce,
              'windows': list(sys.getwindowsversion()[:4]), 'identity': native.token_user(),
              'missing_exports': native.missing, 'phases': {}, 'browsers': {}, 'tools': {},
              'product_qualified': False}
    proxy, direct, echo = Fixture(nonce), Fixture(nonce, direct=True), Echo()
    relay_port = 18808
    decoy = None
    host_ip = host_ipv4()
    (work / 'actor.py').write_text(ACTOR, encoding='utf-8')
    (work / 'launcher.py').write_text(LAUNCHER, encoding='utf-8')
    config = {'nonce': nonce, 'host_ip': host_ip, 'echo_tcp': echo.tcp4, 'echo_udp': echo.udp4,
              'echo_tcp6': echo.tcp6, 'echo_udp6': echo.udp6, 'relay_port': relay_port, 'fixture_port': proxy.port,
              'default_compartment': 1, 'linger': 'linger-inside', 'linger_go': str(work / 'linger-go')}
    write_json(work / 'actor.json', config)
    report['before'] = lab_compartments()[0]
    request = Requests(work)
    task_ok = False
    jobs = {}
    try:
        wrapper = work / 'controller.cmd'
        wrapper.write_text(
            f'@"{sys.executable}" -I -B "{Path(__file__).resolve()}" controller --work "{work}" '
            f'--relay-port {relay_port} --fixture-port {proxy.port} --timeout 1500 '
            f'> "{work / "controller.log"}" 2>&1\r\n', encoding='ascii')
        report['task'] = schedule_system(TASK, wrapper)
        task_ok = report['task'].get('code') == 0
        if not wait_file(work / 'controller-ready.json', 90):
            raise RuntimeError('controller did not report readiness: ' + read_tail(work / 'controller.log'))
        ready = json.loads((work / 'controller-ready.json').read_text(encoding='utf-8'))
        report['controller_ready'] = ready
        print('::group::controller ready\n' + json.dumps(ready, indent=1)[:20000] + '\n::endgroup::', flush=True)
        if ready.get('error'):
            raise RuntimeError('controller failed: ' + ready['error'])
        config['default_compartment'] = ready['default_compartment']
        write_json(work / 'actor.json', config)
        report['net_config'] = {
            'interfaces': powershell('Get-NetIPInterface -IncludeAllCompartments | Select-Object ifIndex,InterfaceAlias,AddressFamily,CompartmentId | ConvertTo-Json -Compress'),
            'routes': powershell('Get-NetRoute -IncludeAllCompartments | Where-Object CompartmentId -ne 1 | Select-Object ifIndex,DestinationPrefix,NextHop,CompartmentId | ConvertTo-Json -Compress'),
        }
        decoy = Decoy(relay_port)
        report['decoy_bind_error'] = decoy.error

        def bound_job(name, compartment):
            job = native.new_job()
            jobs[name] = job
            result = request('bind', pid=os.getpid(), handle=int(job), compartment=compartment)
            result['driver_view'] = int(native.i.GetJobCompartmentId(job))
            report.setdefault('binds', {})[name] = result
            return job, result

        job_a, bind_a = bound_job('A', 'A')
        if bind_a.get('code') != 0:
            raise RuntimeError('job binding failed: ' + json.dumps(bind_a))

        def actor(label, job, timeout=300):
            result_path = work / f'actor-{label}.json'
            process, pid = native.spawn([sys.executable, '-I', '-B', work / 'actor.py', work / 'actor.json', result_path,
                                         label, '0'], job=job, env=safe_env(work, label), cwd=work,
                                        stdout=work / f'actor-{label}.log')
            return process, result_path

        def finish(label, process, result_path, timeout=300):
            code, timed_out = native.wait(process, timeout)
            try:
                value = json.loads(result_path.read_text(encoding='utf-8'))
            except (OSError, ValueError) as e:
                value = {'error': repr(e), 'log': read_tail(work / f'actor-{label}.log')}
            value['exit_code'], value['timed_out'] = code, timed_out
            report['phases'][label] = value
            print(f'::group::actor {label}\n' + json.dumps(value, indent=1)[:16000] + '\n::endgroup::', flush=True)
            return value

        finish('outside', *actor('outside', None))
        finish('inside', *actor('inside', job_a))

        def tool(label, argv, job, timeout=60):
            log = work / f'tool-{label}.log'
            process, pid = native.spawn(argv, job=job, env=safe_env(work, label), cwd=work, stdout=log)
            code, timed_out = native.wait(process, timeout)
            report['tools'][label] = {'exit_code': code, 'timed_out': timed_out, 'tail': read_tail(log, 3000)}

        system = Path(os.environ.get('SystemRoot', r'C:\Windows')) / 'System32'
        powershell_exe = system / 'WindowsPowerShell' / 'v1.0' / 'powershell.exe'
        tool('nslookup_inside', [system / 'nslookup.exe', secrets.token_hex(16) + '.1.2.3.4.sslip.io', '8.8.8.8'], job_a)
        for label, job in (('resolve_inside', job_a), ('resolve_outside', None)):
            tool(label, [powershell_exe, '-NoProfile', '-Command',
                         f'Resolve-DnsName -Name {secrets.token_hex(16)}.1.2.3.4.sslip.io -Type A -ErrorAction Stop | Select-Object -ExpandProperty IPAddress'], job)
        curl = system / 'curl.exe'
        for label, job in (('curl_direct_inside', job_a), ('curl_direct_outside', None)):
            tool(label, [curl, '-sS', '-m', '8', f'http://{host_ip}:{direct.port}/{nonce}/{label}'], job)
            report['tools'][label]['fixture_hits'] = direct.count(label)
        tool('curl_proxy_inside', [curl, '-sS', '-m', '8', '-x', f'http://127.0.0.1:{relay_port}',
                                   f'http://curl_proxy_inside.invalid/{nonce}/curl_proxy_inside'], job_a)
        report['tools']['curl_proxy_inside']['fixture_hits'] = proxy.count('curl_proxy_inside')
        for label, job in (('curl_public_inside', job_a), ('curl_public_outside', None)):
            tool(label, [curl, '-sS', '-m', '8', '-o', 'NUL', '-w', '%{http_code}', 'https://www.microsoft.com/'], job)

        def browser(family, variant, job):
            program = PROGRAMS[family]
            label = f'{family}_{variant}'
            if not program.exists():
                report['browsers'][label] = {'missing': True}
                return
            profile = work / 'profiles' / label
            profile.mkdir(parents=True)
            direct_variant = variant.startswith('direct')
            port = relay_port if job is not None else proxy.port
            url = (f'http://{host_ip}:{direct.port}/{nonce}/{label}' if direct_variant
                   else f'http://{label}.invalid/{nonce}/{label}')
            shot = None
            if family == 'firefox':
                prefs = {'network.proxy.type': 0 if direct_variant else 1, 'network.proxy.http': '127.0.0.1',
                         'network.proxy.http_port': port, 'network.proxy.ssl': '127.0.0.1', 'network.proxy.ssl_port': port,
                         'network.proxy.no_proxies_on': '', 'network.proxy.allow_hijacking_localhost': True,
                         'network.manage-offline-status': False, 'network.trr.mode': 5,
                         'browser.shell.checkDefaultBrowser': False, 'datareporting.policy.dataSubmissionEnabled': False,
                         'toolkit.startup.max_resumed_crashes': -1}
                (profile / 'user.js').write_text(''.join(f'user_pref("{k}", {json.dumps(v)});\n' for k, v in prefs.items()),
                                                 encoding='utf-8')
                shot = work / f'{label}.png'
                argv = [program, '--headless', '--no-remote', '--profile', profile, '--screenshot', shot, url]
            else:
                argv = [program, *CHROMIUM, f'--user-data-dir={profile}']
                argv += (['--no-proxy-server'] if direct_variant else
                         [f'--proxy-server=http://127.0.0.1:{port}', '--proxy-bypass-list=<-loopback>'])
                argv += ['--dump-dom', url]
            log = work / f'browser-{label}.log'
            started = time.monotonic()
            process, pid = native.spawn(argv, job=job, env=safe_env(work, label), cwd=program.parent, stdout=log)
            code, timed_out = native.wait(process, 60)
            time.sleep(1.5)
            body = read_tail(log, 60000)
            hits = (direct if direct_variant else proxy).count(label)
            rendered = png_valid(shot) if shot is not None else ('RuleProxyFixture:' + nonce + ':' + label) in body
            report['browsers'][label] = {'contained': job is not None, 'variant': variant, 'exit_code': code,
                                         'timed_out': timed_out, 'seconds': round(time.monotonic() - started, 2),
                                         'fixture_hits': hits, 'rendered': rendered,
                                         'sandbox_disabled': False, 'tail': body[-2500:]}
            print(f'::group::browser {label}\n' + json.dumps(report['browsers'][label], indent=1)[:8000] + '\n::endgroup::',
                  flush=True)

        for family in PROGRAMS:
            browser(family, 'control', None)
            browser(family, 'contained', job_a)
            browser(family, 'direct', job_a)
            browser(family, 'directcontrol', None)

        # Product-like flow under a temporary standard user.
        report['user_flow'] = request('user_flow')
        if wait_file(work / 'user' / 'launcher-result.json', 420):
            report['user_launcher'] = json.loads((work / 'user' / 'launcher-result.json').read_text(encoding='utf-8'))
        else:
            report['user_launcher'] = {'timeout': True}
        print('::group::user launcher\n' + json.dumps(report['user_launcher'], indent=1)[:20000] + '\n::endgroup::', flush=True)

        # Fail-open check: delete a compartment while a Job member is still alive.
        report['create_B'] = request('create', name='B')
        if report['create_B'].get('code') == 0:
            job_b, bind_b = bound_job('B', 'B')
            if bind_b.get('code') == 0:
                process, result_path = actor('linger-inside', job_b)
                time.sleep(4)
                report['delete_B_while_alive'] = request('delete', name='B')
                (work / 'linger-go').write_text('go', encoding='ascii')
                finish('linger-inside', process, result_path, 240)
                native.k.TerminateJobObject(job_b, 1)
                time.sleep(1)
                report['delete_B_after_exit'] = request('delete', name='B')
        # Orphan lifetime: keep compartment C past the controller and delete it from a new SYSTEM process.
        report['create_C'] = request('create', name='C')
        report['keep_C'] = request('keep', name='C')
        report['stop_relay'] = request('stop_relay')
        report['exit'] = request('exit')
    except Exception as e:
        report['error'] = f'{type(e).__name__}: {e}'
        report['traceback'] = traceback.format_exc()[-4000:]
    finally:
        if decoy:
            decoy.close()
        if not (work / 'controller-final.json').exists():
            write_json(work / 'req-999-exit.json', {'op': 'exit'})
        if wait_file(work / 'controller-final.json', 90):
            report['controller_final'] = json.loads((work / 'controller-final.json').read_text(encoding='utf-8'))
        for job in jobs.values():
            native.k.TerminateJobObject(job, 1)
            native.k.CloseHandle(job)
        report['controller_log'] = read_tail(work / 'controller.log', 6000)
        if task_ok:
            report['task_cleanup'] = powershell(f"Unregister-ScheduledTask -TaskName '{TASK}' -Confirm:$false; 'ok'")
        rows, leftovers = lab_compartments()
        report['after_controller'] = rows
        if leftovers:
            wrapper = work / 'cleanup.cmd'
            out = work / 'cleanup-result.json'
            wrapper.write_text(f'@"{sys.executable}" -I -B "{Path(__file__).resolve()}" cleanup --out "{out}" '
                               + ' '.join(str(x) for x in leftovers) + f' > "{work / "cleanup.log"}" 2>&1\r\n',
                               encoding='ascii')
            report['cleanup_task'] = schedule_system(CLEANUP_TASK, wrapper)
            if wait_file(out, 90):
                report['cleanup_result'] = json.loads(out.read_text(encoding='utf-8'))
            powershell(f"Unregister-ScheduledTask -TaskName '{CLEANUP_TASK}' -Confirm:$false; 'ok'")
        report['after_cleanup'] = lab_compartments()[0]
        proxy.close()
        direct.close()
        echo.close()
    report['echo_payloads'] = echo.payloads[-300:]
    report['proxy_received'] = proxy.received[-300:]
    report['direct_received'] = direct.received[-300:]
    report['assessment'] = assess(report)
    write_json(out_dir / 'compartment-report.json', report)
    print('::notice title=Compartment lab::' + json.dumps(report['assessment'], separators=(',', ':'))[:3800], flush=True)
    return 1 if report.get('error') else 0


ROW_KEYS = ('tcp4_host_ip', 'tcp4_loopback', 'udp4_host_ip', 'udp4_loopback', 'tcp6_loopback', 'udp6_loopback',
            'tcp4_public_1111_443', 'udp4_public_dns_8888', 'system_dns')


def summarize_actor(value):
    if not isinstance(value, dict):
        return value
    rows = value.get('rows', {})
    result = {'compartment': value.get('compartment'), 'exit': value.get('exit_code'),
              'rows': {key: rows.get(key, {}).get('ok') for key in ROW_KEYS},
              'relay_banner': rows.get('relay_port_loopback', {}).get('banner'),
              'proxy': value.get('proxy', {}).get('ok')}
    for key in ('child', 'nested'):
        if isinstance(value.get(key), dict):
            result[key] = summarize_actor(value[key])
    if 'escape' in value:
        escape = dict(value['escape'])
        if isinstance(escape.get('job_child'), dict):
            escape['job_child'] = summarize_actor(escape['job_child'])
        if isinstance(escape.get('thread_tcp4_host_ip'), dict):
            escape['thread_tcp4_host_ip'] = escape['thread_tcp4_host_ip'].get('ok')
        result['escape'] = escape
    if 'breakaway' in value:
        result['breakaway_started'] = value['breakaway'].get('started')
    for key in ('linger_released', 'compartment_after'):
        if key in value:
            result[key] = value[key]
    return result


def assess(report):
    ready = report.get('controller_ready', {})
    final = report.get('controller_final', {})
    user = report.get('user_launcher', {})
    return {
        'create_A': ready.get('create_A'), 'thread_probe': ready.get('thread_probe'),
        'default_thread_dns': ready.get('default_thread_dns'), 'relay': ready.get('relay'),
        'decoy_bind_error': report.get('decoy_bind_error'), 'binds': report.get('binds'),
        'outside': summarize_actor(report['phases'].get('outside')),
        'inside': summarize_actor(report['phases'].get('inside')),
        'user_bind': user.get('bind'), 'user_outside': summarize_actor(user.get('user-outside')),
        'user_inside': summarize_actor(user.get('user-inside')), 'user_error': user.get('error'),
        'user_flow': report.get('user_flow'),
        'tools': {k: {'exit': v.get('exit_code'), 'hits': v.get('fixture_hits'), 'tail': v.get('tail', '')[-160:]}
                  for k, v in report.get('tools', {}).items()},
        'browsers': {label: {'hits': value.get('fixture_hits'), 'rendered': value.get('rendered'),
                             'exit': value.get('exit_code')} for label, value in report.get('browsers', {}).items()},
        'delete_B_while_alive': report.get('delete_B_while_alive'),
        'linger': summarize_actor(report['phases'].get('linger-inside')),
        'delete_B_after_exit': report.get('delete_B_after_exit'),
        'final_deletes': final.get('final_deletes'), 'kept': final.get('kept'),
        'after_controller': report.get('after_controller'), 'cleanup_result': report.get('cleanup_result'),
        'after_cleanup': report.get('after_cleanup'),
        'error': report.get('error'), 'controller_error': ready.get('error') or final.get('error'),
    }


def main() -> int:
    parser = argparse.ArgumentParser()
    sub = parser.add_subparsers(dest='role', required=True)
    d = sub.add_parser('driver')
    d.add_argument('--out', required=True)
    c = sub.add_parser('controller')
    c.add_argument('--work', required=True)
    c.add_argument('--relay-port', type=int, required=True)
    c.add_argument('--fixture-port', type=int, required=True)
    c.add_argument('--timeout', type=int, default=1500)
    k = sub.add_parser('cleanup')
    k.add_argument('--out', required=True)
    k.add_argument('ids', nargs='*', type=int)
    args = parser.parse_args()
    if args.role == 'driver':
        return driver(args)
    if args.role == 'cleanup':
        return cleanup(args)
    Controller(args).run()
    return 0


if __name__ == '__main__':
    raise SystemExit(main())
