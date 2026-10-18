"""Disposable Windows experiment: Linux-netns-like isolation via TCP/IP compartments.

Question: can an ordinary process tree be placed in an otherwise empty TCP/IP
network compartment (the Windows analogue of a Linux network namespace) so
that direct sockets, system DNS and descendants cannot reach the network,
while a privileged relay exposes exactly one loopback proxy port inside it?

Roles (one CI job on a disposable hosted runner):
  driver      hosted runner account: fixtures, phases, browsers, report
  controller  LocalSystem through a one-shot scheduled task: compartment,
              named Job bound to the compartment, in-compartment relay
  actor       a short Python process started inside or outside the Job

APIs are the iphlpapi compartment routines declared in the Windows SDK
netioapi.h (CreateCompartment, SetJobCompartmentId, SetCurrentThreadCompartmentId).
Nothing here enables a product mode or qualifies a product; every isolation
claim requires a passing positive control in the same run.
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
import socketserver
import struct
import subprocess
import sys
import threading
import time
import traceback
import uuid
import zlib

TASK = 'RuleProxyCompartmentLab'
JOB_NAME = 'Global\\RuleProxyCompartmentLab'
WORK = Path(r'C:\RuleProxyCompartmentLab')
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


class SECURITY_ATTRIBUTES(C.Structure):
    _fields_ = [('nLength', W.DWORD), ('lpSecurityDescriptor', C.c_void_p), ('bInheritHandle', W.BOOL)]


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


class Native:
    def __init__(self):
        self.k = C.WinDLL('kernel32', use_last_error=True)
        self.a = C.WinDLL('advapi32', use_last_error=True)
        self.i = C.WinDLL('iphlpapi', use_last_error=True)
        P = C.c_void_p
        for owner, name, args, result in (
                (self.k, 'GetCurrentProcess', [], W.HANDLE),
                (self.k, 'CloseHandle', [W.HANDLE], W.BOOL),
                (self.k, 'CreateJobObjectW', [C.POINTER(SECURITY_ATTRIBUTES), W.LPCWSTR], W.HANDLE),
                (self.k, 'OpenJobObjectW', [W.DWORD, W.BOOL, W.LPCWSTR], W.HANDLE),
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
                (self.a, 'ConvertStringSecurityDescriptorToSecurityDescriptorW',
                 [W.LPCWSTR, W.DWORD, C.POINTER(P), C.POINTER(W.ULONG)], W.BOOL),
                (self.a, 'OpenProcessToken', [W.HANDLE, W.DWORD, C.POINTER(W.HANDLE)], W.BOOL),
                (self.a, 'GetTokenInformation', [W.HANDLE, C.c_int, P, W.DWORD, C.POINTER(W.DWORD)], W.BOOL),
                (self.a, 'ConvertSidToStringSidW', [P, C.POINTER(W.LPWSTR)], W.BOOL)):
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

    def token_user(self):
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
            self.k.CloseHandle(token)

    def kill_on_close(self, job):
        limits = JOBOBJECT_EXTENDED_LIMIT_INFORMATION()
        limits.BasicLimitInformation.LimitFlags = 0x2000
        self.check(self.k.SetInformationJobObject(job, 9, C.byref(limits), C.sizeof(limits)), 'SetInformationJobObject')

    def spawn(self, argv, *, job=None, env=None, cwd=None, stdout=None):
        """Create suspended, join the Job before the first instruction, then resume."""
        import msvcrt
        info = STARTUPINFOW()
        info.cb = C.sizeof(info)
        inherit = False
        stream = None
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


# ----------------------------------------------------------------------------- actor

ACTOR = r'''
import ctypes as C, json, os, socket, struct, subprocess, sys, time, urllib.request
cfg = json.loads(open(sys.argv[1], encoding='utf-8').read())
label = sys.argv[3]
out = {'label': label, 'pid': os.getpid()}
try:
    i = C.WinDLL('iphlpapi'); i.GetCurrentThreadCompartmentId.restype = C.c_uint32
    out['compartment'] = int(i.GetCurrentThreadCompartmentId())
except Exception as e:
    out['compartment_error'] = repr(e)
def error(e):
    return {'ok': False, 'type': type(e).__name__, 'winerror': getattr(e, 'winerror', None), 'errno': getattr(e, 'errno', None), 'text': str(e)[:160]}
def tcp(host, port, family):
    try:
        with socket.socket(family, socket.SOCK_STREAM) as s:
            s.settimeout(3)
            payload = (cfg['nonce'] + ':' + label + ':tcp').encode()
            s.connect((host, port)); s.sendall(payload); data = s.recv(256)
        return {'ok': data == payload, 'echo': data[:64].decode('ascii', 'replace')}
    except Exception as e:
        return error(e)
def connect_only(host, port, family=socket.AF_INET):
    try:
        with socket.socket(family, socket.SOCK_STREAM) as s:
            s.settimeout(3); s.connect((host, port))
            s.settimeout(1)
            try: banner = s.recv(64).decode('ascii', 'replace')
            except Exception: banner = ''
        return {'ok': True, 'banner': banner}
    except Exception as e:
        return error(e)
def udp(host, port, family):
    try:
        with socket.socket(family, socket.SOCK_DGRAM) as s:
            s.settimeout(2)
            payload = (cfg['nonce'] + ':' + label + ':udp').encode()
            s.sendto(payload, (host, port)); data, _ = s.recvfrom(256)
        return {'ok': data == payload}
    except Exception as e:
        return error(e)
def dns_udp(server):
    try:
        query = struct.pack('!HHHHHH', 0x5250, 0x0100, 1, 0, 0, 0) + b''.join(bytes([len(p)]) + p.encode() for p in cfg['dns_name_raw'].split('.')) + b'\0' + struct.pack('!HH', 1, 1)
        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as s:
            s.settimeout(3); s.sendto(query, (server, 53)); data, _ = s.recvfrom(2048)
        return {'ok': len(data) > 12 and data[:2] == b'\x52\x50', 'bytes': len(data)}
    except Exception as e:
        return error(e)
rows = {}
rows['tcp4_host_ip'] = tcp(cfg['host_ip'], cfg['echo_tcp'], socket.AF_INET)
rows['tcp4_loopback'] = tcp('127.0.0.1', cfg['echo_tcp'], socket.AF_INET)
rows['udp4_host_ip'] = udp(cfg['host_ip'], cfg['echo_udp'], socket.AF_INET)
rows['udp4_loopback'] = udp('127.0.0.1', cfg['echo_udp'], socket.AF_INET)
rows['tcp6_loopback'] = tcp('::1', cfg['echo_tcp6'], socket.AF_INET6)
rows['udp6_loopback'] = udp('::1', cfg['echo_udp6'], socket.AF_INET6)
rows['tcp4_public_1111_443'] = connect_only('1.1.1.1', 443)
rows['tcp4_public_8888_53'] = connect_only('8.8.8.8', 53)
rows['udp4_public_dns_8888'] = dns_udp('8.8.8.8')
rows['relay_port_loopback'] = connect_only('127.0.0.1', cfg['relay_port'])
out['rows'] = rows
try:
    values = sorted({x[4][0] for x in socket.getaddrinfo(cfg['dns_names'][label], 443, socket.AF_INET, socket.SOCK_STREAM)})
    out['dns'] = {'ok': values == ['1.2.3.4'], 'addresses': values, 'name': cfg['dns_names'][label]}
except Exception as e:
    out['dns'] = dict(error(e), name=cfg['dns_names'][label])
try:
    target = 'http://' + label + '.invalid/' + cfg['nonce'] + '/' + label
    opener = urllib.request.build_opener(urllib.request.ProxyHandler({'http': 'http://127.0.0.1:' + str(cfg['proxy_ports'][label])}))
    with opener.open(target, timeout=5) as response:
        body = response.read(4096).decode('ascii', 'replace')
    out['proxy'] = {'ok': ('RuleProxyFixture:' + cfg['nonce'] + ':' + label) in body, 'port': cfg['proxy_ports'][label]}
except Exception as e:
    out['proxy'] = dict(error(e), port=cfg['proxy_ports'][label])
if cfg.get('children', {}).get(label):
    child = cfg['children'][label]
    try:
        result = subprocess.run([sys.executable, '-I', '-B', sys.argv[0], sys.argv[1], sys.argv[2] + '.' + child, child], timeout=60)
        out['child_exit'] = result.returncode
        out['child'] = json.loads(open(sys.argv[2] + '.' + child, encoding='utf-8').read())
    except Exception as e:
        out['child_error'] = repr(e)
    try:
        p = subprocess.Popen([sys.executable, '-c', 'print(1)'], creationflags=0x01000000)
        out['breakaway'] = {'started': True, 'exit': p.wait(30)}
    except Exception as e:
        out['breakaway'] = dict(error(e), started=False)
if cfg.get('nested', {}).get(label):
    # Browsers put their own children into nested Jobs; the compartment must survive that.
    nested = cfg['nested'][label]
    try:
        k = C.WinDLL('kernel32', use_last_error=True); n = C.WinDLL('ntdll')
        k.CreateJobObjectW.restype = C.c_void_p; k.CreateJobObjectW.argtypes = [C.c_void_p, C.c_wchar_p]
        k.AssignProcessToJobObject.argtypes = [C.c_void_p, C.c_void_p]; n.NtResumeProcess.argtypes = [C.c_void_p]
        job = k.CreateJobObjectW(None, None)
        p = subprocess.Popen([sys.executable, '-I', '-B', sys.argv[0], sys.argv[1], sys.argv[2] + '.' + nested, nested],
                             creationflags=0x4)
        assigned = bool(k.AssignProcessToJobObject(job, int(p._handle)))
        out['nested_assign'] = {'ok': assigned, 'error': None if assigned else C.get_last_error()}
        n.NtResumeProcess(int(p._handle))
        out['nested_exit'] = p.wait(90)
        out['nested'] = json.loads(open(sys.argv[2] + '.' + nested, encoding='utf-8').read())
    except Exception as e:
        out['nested_error'] = repr(e)
open(sys.argv[2], 'w', encoding='utf-8').write(json.dumps(out))
'''

# ----------------------------------------------------------------------------- controller


def controller(args) -> int:
    work = Path(args.work)
    report = {'role': 'controller', 'started': time.time()}
    native = Native()
    report['missing_exports'] = native.missing
    report['identity'] = native.token_user()
    stop = threading.Event()
    relay_stats = {'accepted': 0, 'forward_errors': [], 'listener_errors': []}
    job = None
    compartment = None

    def write(name, value):
        temporary = work / (name + '.tmp')
        temporary.write_text(json.dumps(value, indent=1, default=str), encoding='utf-8')
        os.replace(temporary, work / name)

    try:
        i = native.i
        report['default_compartment'] = int(i.GetDefaultCompartmentId())
        report['thread_compartment'] = int(i.GetCurrentThreadCompartmentId())
        report['session0_compartment'] = int(i.GetSessionCompartmentId(0))
        row = MIB_COMPARTMENT_ROW()
        i.InitializeCompartmentEntry(C.byref(row))
        report['initialized_row'] = {'id': row.CompartmentId, 'guid': str(uuid.UUID(bytes_le=bytes(row.CompartmentGuid)))}
        guid = uuid.uuid4()
        row.CompartmentGuid = GUID.of(guid)
        row.Description = 'RuleProxy compartment lab'
        code = int(i.CreateCompartment(C.byref(row)))
        report['create'] = {'code': code, 'id': int(row.CompartmentId), 'guid': str(guid)}
        if code:
            raise OSError(code, f'CreateCompartment returned {code}')
        compartment = int(row.CompartmentId)

        # Probe this compartment from a dedicated thread before trusting it.
        probe = {}

        def thread_probe():
            probe['set'] = int(i.SetCurrentThreadCompartmentId(compartment))
            probe['get'] = int(i.GetCurrentThreadCompartmentId())
            for key, (family, host, port) in {'public_1111_443': (socket.AF_INET, '1.1.1.1', 443),
                                              'host_fixture_loopback': (socket.AF_INET, '127.0.0.1', args.fixture_port)}.items():
                try:
                    with socket.socket(family, socket.SOCK_STREAM) as s:
                        s.settimeout(3)
                        s.connect((host, port))
                    probe[key] = {'ok': True}
                except OSError as e:
                    probe[key] = {'ok': False, 'winerror': getattr(e, 'winerror', None), 'text': str(e)[:160]}
            try:
                with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
                    s.bind(('127.0.0.1', 0))
                    probe['bind_loopback4'] = {'ok': True, 'port': s.getsockname()[1]}
            except OSError as e:
                probe['bind_loopback4'] = {'ok': False, 'winerror': getattr(e, 'winerror', None), 'text': str(e)[:160]}
            try:
                values = sorted({x[4][0] for x in socket.getaddrinfo(args.dns_name, 443, socket.AF_INET, socket.SOCK_STREAM)})
                probe['dns'] = {'ok': True, 'addresses': values}
            except OSError as e:
                probe['dns'] = {'ok': False, 'winerror': getattr(e, 'winerror', None), 'text': str(e)[:160]}

        worker = threading.Thread(target=thread_probe)
        worker.start()
        worker.join(30)
        report['thread_probe'] = probe

        # A named Job that the driver may join processes to; kill-on-close so
        # every contained descendant ends with the controller.
        descriptor, size = C.c_void_p(), W.ULONG()
        native.check(native.a.ConvertStringSecurityDescriptorToSecurityDescriptorW(
            'D:P(A;;GA;;;SY)(A;;GA;;;BA)', 1, C.byref(descriptor), C.byref(size)), 'SDDL')
        attributes = SECURITY_ATTRIBUTES(C.sizeof(SECURITY_ATTRIBUTES), descriptor.value, False)
        job = native.check(native.k.CreateJobObjectW(C.byref(attributes), JOB_NAME), 'CreateJobObjectW')
        native.k.LocalFree(descriptor)
        native.kill_on_close(job)
        report['set_job'] = {'code': int(i.SetJobCompartmentId(job, compartment))}
        report['job_compartment'] = int(i.GetJobCompartmentId(job))

        # Relay: listener bound inside the compartment, upstream in the default one.
        listeners = []

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
            try:
                i.SetCurrentThreadCompartmentId(report['default_compartment'])
                upstream = socket.create_connection(('127.0.0.1', args.fixture_port), timeout=5)
                upstream.settimeout(None)
                accepted.settimeout(None)
                back = threading.Thread(target=pump, args=(upstream, accepted), daemon=True)
                back.start()
                pump(accepted, upstream)
                back.join(30)
                upstream.close()
            except OSError as e:
                relay_stats['forward_errors'].append(str(e)[:160])
            finally:
                accepted.close()

        def listen():
            try:
                relay_stats['listener_set'] = int(i.SetCurrentThreadCompartmentId(compartment))
                relay_stats['listener_get'] = int(i.GetCurrentThreadCompartmentId())
                for family, host in ((socket.AF_INET, '127.0.0.1'), (socket.AF_INET6, '::1')):
                    s = socket.socket(family, socket.SOCK_STREAM)
                    try:
                        s.bind((host, args.relay_port))
                        s.listen(64)
                        listeners.append(s)
                        relay_stats['bound_' + str(family.value if hasattr(family, 'value') else family)] = True
                    except OSError as e:
                        relay_stats['listener_errors'].append(f'{host}: {e}'[:160])
                        s.close()
                while not stop.is_set() and listeners:
                    ready, _, _ = select.select(listeners, [], [], 0.5)
                    for s in ready:
                        accepted, _ = s.accept()
                        relay_stats['accepted'] += 1
                        threading.Thread(target=forward, args=(accepted,), daemon=True).start()
            except Exception as e:
                relay_stats['listener_errors'].append(repr(e)[:200])

        relay = threading.Thread(target=listen, daemon=True)
        relay.start()
        time.sleep(1.0)
        report['relay'] = relay_stats
        write('controller-ready.json', report)
        deadline = time.monotonic() + args.timeout
        while time.monotonic() < deadline and not (work / 'driver-done').exists():
            time.sleep(0.5)
        report['driver_done_seen'] = (work / 'driver-done').exists()
    except Exception as e:
        report['error'] = f'{type(e).__name__}: {e}'
        report['traceback'] = traceback.format_exc()[-3000:]
        write('controller-ready.json', report)
    finally:
        stop.set()
        time.sleep(1.0)
        if job:
            report['terminate_job'] = bool(native.k.TerminateJobObject(job, 1))
            native.k.CloseHandle(job)
        if compartment is not None:
            deletes = []
            for _ in range(10):
                code = int(native.i.DeleteCompartment(compartment))
                deletes.append(code)
                if code == 0:
                    break
                time.sleep(1.0)
            report['delete'] = deletes
        report['relay'] = relay_stats
        report['finished'] = time.time()
        write('controller-final.json', report)
    return 0


# ----------------------------------------------------------------------------- driver fixtures


class Fixture:
    """Local HTTP proxy endpoint: answers only absolute-URI GETs for owned labels."""

    def __init__(self, nonce, port=0, direct=False):
        self.nonce, self.direct = nonce, direct
        self.received, self.lock = [], threading.Lock()
        owner = self

        class Handler(BaseHTTPRequestHandler):
            def log_message(self, *_):
                pass

            def do_GET(self):
                path = self.path
                label = None
                if owner.direct:
                    parts = path.strip('/').split('/')
                    if len(parts) == 2 and parts[0] == owner.nonce:
                        label = parts[1]
                else:
                    for candidate in ('http://',):
                        if path.startswith(candidate):
                            rest = path[len(candidate):]
                            host, _, tail = rest.partition('/')
                            parts = tail.split('/')
                            if host.endswith('.invalid') and len(parts) == 2 and parts[0] == owner.nonce \
                                    and host == parts[1] + '.invalid':
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

        self.server = ThreadingHTTPServer(('0.0.0.0' if direct else '127.0.0.1', port), Handler)
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
        self.payloads, self.lock = [], threading.Lock()
        self.sockets = []
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

    def seen(self, text):
        with self.lock:
            return sum(text in p for p in self.payloads)

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
                              '[Console]::OutputEncoding=[Text.UTF8Encoding]::new($false);' + script],
                             capture_output=True, timeout=timeout)
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


# ----------------------------------------------------------------------------- driver


def driver(args) -> int:
    sys.stdout.reconfigure(encoding='utf-8', errors='backslashreplace')
    if os.name != 'nt' or os.environ.get('GITHUB_ACTIONS') != 'true':
        raise SystemExit('requires a disposable Windows Actions runner')
    work = WORK
    if work.exists():
        raise SystemExit('work directory already exists')
    work.mkdir(parents=True)
    out_dir = Path(args.out).resolve()
    out_dir.mkdir(parents=True, exist_ok=True)
    native = Native()
    nonce = secrets.token_hex(12)
    report = {'schema_version': 1, 'source_commit': os.environ.get('GITHUB_SHA'), 'nonce': nonce,
              'windows': list(sys.getwindowsversion()[:4]), 'identity': native.token_user(),
              'missing_exports': native.missing, 'phases': {}, 'browsers': {}, 'tools': {},
              'product_qualified': False}
    proxy = Fixture(nonce)
    direct = Fixture(nonce, direct=True)
    echo = Echo()
    relay_port = 18808
    decoy = None
    host_ip = host_ipv4()
    report['host_ip_is_private'] = host_ip.startswith(('10.', '172.', '192.168.'))
    script = work / 'actor.py'
    script.write_text(ACTOR, encoding='utf-8')
    labels = ['outside', 'inside', 'inside-child', 'outside-child', 'inside-nested']
    dns_names = {label: secrets.token_hex(16) + '.1.2.3.4.sslip.io' for label in labels}
    proxy_ports = {'outside': proxy.port, 'outside-child': proxy.port, 'inside': relay_port, 'inside-child': relay_port,
                   'inside-nested': relay_port}
    config = {'nonce': nonce, 'host_ip': host_ip, 'echo_tcp': echo.tcp4, 'echo_udp': echo.udp4,
              'echo_tcp6': echo.tcp6, 'echo_udp6': echo.udp6, 'relay_port': relay_port,
              'dns_names': dns_names, 'dns_name_raw': secrets.token_hex(8) + '.example.com',
              'proxy_ports': proxy_ports, 'children': {'inside': 'inside-child', 'outside': 'outside-child'},
              'nested': {'inside': 'inside-nested'}}
    (work / 'actor.json').write_text(json.dumps(config), encoding='utf-8')
    report['before'] = powershell('Get-NetCompartment | Select-Object CompartmentId,CompartmentDescription,CompartmentGuid | ConvertTo-Json -Compress')
    task_ok = False
    job = None
    try:
        # One-shot LocalSystem controller through Task Scheduler.
        wrapper = work / 'controller.cmd'
        wrapper.write_text(
            f'@"{sys.executable}" -I -B "{Path(__file__).resolve()}" controller --work "{work}" '
            f'--relay-port {relay_port} --fixture-port {proxy.port} --dns-name {secrets.token_hex(16)}.1.2.3.4.sslip.io '
            f'--timeout 900 > "{work / "controller.log"}" 2>&1\r\n', encoding='ascii')
        registration = powershell(
            f"$a=New-ScheduledTaskAction -Execute 'cmd.exe' -Argument '/c \"{wrapper}\"';"
            f"$p=New-ScheduledTaskPrincipal -UserId 'SYSTEM' -LogonType ServiceAccount -RunLevel Highest;"
            f"$s=New-ScheduledTaskSettingsSet -ExecutionTimeLimit (New-TimeSpan -Minutes 20) -AllowStartIfOnBatteries;"
            f"Register-ScheduledTask -TaskName '{TASK}' -Action $a -Principal $p -Settings $s -Force | Out-Null;"
            f"Start-ScheduledTask -TaskName '{TASK}'; 'started'")
        report['task'] = registration
        task_ok = registration.get('code') == 0
        ready = work / 'controller-ready.json'
        deadline = time.monotonic() + 90
        while time.monotonic() < deadline and not ready.exists():
            time.sleep(0.5)
        if not ready.exists():
            raise RuntimeError('controller did not report readiness: ' + read_tail(work / 'controller.log'))
        controller_ready = json.loads(ready.read_text(encoding='utf-8'))
        report['controller_ready'] = controller_ready
        print('::group::controller ready\n' + json.dumps(controller_ready, indent=1)[:20000] + '\n::endgroup::', flush=True)
        if controller_ready.get('error'):
            raise RuntimeError('controller failed: ' + controller_ready['error'])
        report['net_config'] = {
            'compartments': powershell('Get-NetCompartment | Select-Object CompartmentId,CompartmentDescription | ConvertTo-Json -Compress'),
            'interfaces': powershell('Get-NetIPInterface -IncludeAllCompartments | Select-Object ifIndex,InterfaceAlias,AddressFamily,CompartmentId,ConnectionState | ConvertTo-Json -Compress'),
            'addresses': powershell('Get-NetIPAddress -IncludeAllCompartments | Select-Object ifIndex,InterfaceAlias,IPAddress,CompartmentId | ConvertTo-Json -Compress'),
            'routes': powershell('Get-NetRoute -IncludeAllCompartments | Select-Object ifIndex,DestinationPrefix,NextHop,CompartmentId | ConvertTo-Json -Compress'),
        }
        decoy = Decoy(relay_port)
        report['decoy_bind_error'] = decoy.error
        job = native.k.OpenJobObjectW(0x1F003F, False, JOB_NAME)
        report['open_job_error'] = None if job else C.get_last_error()
        if not job:
            raise RuntimeError('cannot open controller job')
        report['driver_view_job_compartment'] = int(native.i.GetJobCompartmentId(job))

        def actor(label, contained):
            result_path = work / f'actor-{label}.json'
            process, pid = native.spawn([sys.executable, '-I', '-B', script, work / 'actor.json', result_path, label],
                                        job=job if contained else None, env=safe_env(work, label), cwd=work,
                                        stdout=work / f'actor-{label}.log')
            code, timed_out = native.wait(process, 180)
            try:
                value = json.loads(result_path.read_text(encoding='utf-8'))
            except (OSError, ValueError) as e:
                value = {'error': repr(e), 'log': read_tail(work / f'actor-{label}.log')}
            value['exit_code'], value['timed_out'] = code, timed_out
            report['phases'][label] = value
            print(f'::group::actor {label}\n' + json.dumps(value, indent=1)[:12000] + '\n::endgroup::', flush=True)

        actor('outside', False)
        actor('inside', True)

        def tool(label, argv, contained, timeout=60):
            log = work / f'tool-{label}.log'
            process, pid = native.spawn(argv, job=job if contained else None, env=safe_env(work, label),
                                        cwd=work, stdout=log)
            code, timed_out = native.wait(process, timeout)
            report['tools'][label] = {'exit_code': code, 'timed_out': timed_out, 'tail': read_tail(log, 3000)}

        fresh = secrets.token_hex(16) + '.1.2.3.4.sslip.io'
        system = Path(os.environ.get('SystemRoot', r'C:\Windows')) / 'System32'
        tool('nslookup_inside', [system / 'nslookup.exe', fresh, '8.8.8.8'], True)
        tool('resolve_inside', [system / 'WindowsPowerShell' / 'v1.0' / 'powershell.exe', '-NoProfile', '-Command',
                                f'Resolve-DnsName -Name {secrets.token_hex(16)}.1.2.3.4.sslip.io -Type A -ErrorAction Stop | Select-Object -ExpandProperty IPAddress'], True)
        tool('resolve_outside', [system / 'WindowsPowerShell' / 'v1.0' / 'powershell.exe', '-NoProfile', '-Command',
                                 f'Resolve-DnsName -Name {secrets.token_hex(16)}.1.2.3.4.sslip.io -Type A -ErrorAction Stop | Select-Object -ExpandProperty IPAddress'], False)
        curl = system / 'curl.exe'
        tool('curl_direct_inside', [curl, '-sS', '-m', '8', f'http://{host_ip}:{direct.port}/{nonce}/curl_direct_inside'], True)
        tool('curl_direct_outside', [curl, '-sS', '-m', '8', f'http://{host_ip}:{direct.port}/{nonce}/curl_direct_outside'], False)
        tool('curl_proxy_inside', [curl, '-sS', '-m', '8', '-x', f'http://127.0.0.1:{relay_port}',
                                   f'http://curl_proxy_inside.invalid/{nonce}/curl_proxy_inside'], True)
        tool('curl_public_inside', [curl, '-sS', '-m', '8', '-o', 'NUL', '-w', '%{http_code}', 'https://www.microsoft.com/'], True)
        tool('curl_public_outside', [curl, '-sS', '-m', '8', '-o', 'NUL', '-w', '%{http_code}', 'https://www.microsoft.com/'], False)
        for name in ('curl_direct_inside', 'curl_direct_outside', 'curl_proxy_inside'):
            report['tools'][name]['fixture_hits'] = (direct if 'direct' in name else proxy).count(name)

        def browser(family, variant, contained):
            program = PROGRAMS[family]
            label = f'{family}_{variant}'
            if not program.exists():
                report['browsers'][label] = {'missing': True}
                return
            profile = work / 'profiles' / label
            profile.mkdir(parents=True)
            port = relay_port if contained else proxy.port
            url = f'http://{label}.invalid/{nonce}/{label}'
            shot = None
            if family == 'firefox':
                prefs = {'network.proxy.type': 1, 'network.proxy.http': '127.0.0.1', 'network.proxy.http_port': port,
                         'network.proxy.ssl': '127.0.0.1', 'network.proxy.ssl_port': port,
                         'network.proxy.no_proxies_on': '', 'network.proxy.allow_hijacking_localhost': True,
                         'network.manage-offline-status': False, 'network.trr.mode': 5,
                         'browser.shell.checkDefaultBrowser': False, 'datareporting.policy.dataSubmissionEnabled': False,
                         'toolkit.startup.max_resumed_crashes': -1}
                if variant == 'direct':
                    prefs['network.proxy.type'] = 0
                    url = f'http://{host_ip}:{direct.port}/{nonce}/{label}'
                (profile / 'user.js').write_text(''.join(f'user_pref("{k}", {json.dumps(v)});\n' for k, v in prefs.items()),
                                                 encoding='utf-8')
                shot = work / f'{label}.png'
                argv = [program, '--headless', '--no-remote', '--profile', profile, '--screenshot', shot, url]
            else:
                argv = [program, *CHROMIUM, f'--user-data-dir={profile}']
                if variant == 'direct':
                    url = f'http://{host_ip}:{direct.port}/{nonce}/{label}'
                    argv += ['--no-proxy-server']
                else:
                    argv += [f'--proxy-server=http://127.0.0.1:{port}', '--proxy-bypass-list=<-loopback>']
                argv += ['--dump-dom', url]
            log = work / f'browser-{label}.log'
            started = time.monotonic()
            process, pid = native.spawn(argv, job=job if contained else None, env=safe_env(work, label),
                                        cwd=program.parent, stdout=log)
            code, timed_out = native.wait(process, 60)
            time.sleep(1.5)
            body = read_tail(log, 60000)
            hits = (direct if variant == 'direct' else proxy).count(label)
            rendered = png_valid(shot) if shot is not None else ('RuleProxyFixture:' + nonce + ':' + label) in body
            report['browsers'][label] = {'contained': contained, 'variant': variant, 'exit_code': code,
                                         'timed_out': timed_out, 'seconds': round(time.monotonic() - started, 2),
                                         'fixture_hits': hits, 'rendered': rendered,
                                         'sandbox_disabled': False, 'tail': body[-2500:]}
            print(f'::group::browser {label}\n' + json.dumps(report['browsers'][label], indent=1)[:8000] + '\n::endgroup::',
                  flush=True)

        for family in PROGRAMS:
            browser(family, 'control', False)
            browser(family, 'contained', True)
            browser(family, 'direct', True)
            if family != 'firefox':
                browser(family, 'directcontrol', False)
    except Exception as e:
        report['error'] = f'{type(e).__name__}: {e}'
        report['traceback'] = traceback.format_exc()[-4000:]
    finally:
        if decoy:
            decoy.close()
        if job:
            native.k.CloseHandle(job)
        (work / 'driver-done').write_text('done', encoding='ascii')
        final = work / 'controller-final.json'
        deadline = time.monotonic() + 60
        while time.monotonic() < deadline and not final.exists():
            time.sleep(0.5)
        if final.exists():
            report['controller_final'] = json.loads(final.read_text(encoding='utf-8'))
        report['controller_log'] = read_tail(work / 'controller.log', 6000)
        if task_ok:
            report['task_cleanup'] = powershell(f"Unregister-ScheduledTask -TaskName '{TASK}' -Confirm:$false; 'ok'")
        report['after'] = powershell('Get-NetCompartment | Select-Object CompartmentId,CompartmentDescription | ConvertTo-Json -Compress')
        proxy.close()
        direct.close()
        echo.close()
    report['echo_payloads'] = echo.payloads[-200:]
    report['proxy_received'] = proxy.received[-200:]
    report['direct_received'] = direct.received[-200:]
    report['assessment'] = assess(report)
    (out_dir / 'compartment-report.json').write_text(json.dumps(report, indent=1, default=str), encoding='utf-8')
    summary = report['assessment']
    print('::notice title=Compartment lab::' + json.dumps(summary, separators=(',', ':'))[:3500], flush=True)
    return 0


def assess(report):
    phases = report.get('phases', {})
    outside, inside = phases.get('outside', {}), phases.get('inside', {})
    child = inside.get('child', {})
    nested = inside.get('nested', {})
    keys = ('tcp4_host_ip', 'tcp4_loopback', 'udp4_host_ip', 'udp4_loopback', 'tcp6_loopback', 'udp6_loopback',
            'tcp4_public_1111_443', 'tcp4_public_8888_53', 'udp4_public_dns_8888')

    def rows_ok(phase):
        return {key: phase.get('rows', {}).get(key, {}).get('ok') for key in keys}
    browsers = {label: {'hits': value.get('fixture_hits'), 'rendered': value.get('rendered'),
                        'exit': value.get('exit_code')} for label, value in report.get('browsers', {}).items()}
    ready = report.get('controller_ready', {})
    return {
        'create': ready.get('create'), 'set_job': ready.get('set_job'), 'job_compartment': ready.get('job_compartment'),
        'thread_probe': ready.get('thread_probe'), 'relay_errors': (ready.get('relay') or {}).get('listener_errors'),
        'decoy_bind_error': report.get('decoy_bind_error'),
        'outside_compartment': outside.get('compartment'), 'inside_compartment': inside.get('compartment'),
        'child_compartment': child.get('compartment'),
        'outside_rows': rows_ok(outside), 'inside_rows': rows_ok(inside), 'child_rows': rows_ok(child),
        'nested_compartment': nested.get('compartment'), 'nested_rows': rows_ok(nested),
        'nested_dns': nested.get('dns'), 'nested_proxy': nested.get('proxy', {}).get('ok'),
        'nested_assign': inside.get('nested_assign'), 'nested_error': inside.get('nested_error'),
        'outside_dns': outside.get('dns', {}).get('ok'), 'inside_dns': inside.get('dns'), 'child_dns': child.get('dns'),
        'outside_proxy': outside.get('proxy', {}).get('ok'), 'inside_proxy': inside.get('proxy', {}).get('ok'),
        'child_proxy': child.get('proxy', {}).get('ok'), 'inside_relay_banner': inside.get('rows', {}).get('relay_port_loopback'),
        'outside_relay_banner': outside.get('rows', {}).get('relay_port_loopback'),
        'breakaway': inside.get('breakaway'),
        'tools': {k: {'exit': v.get('exit_code'), 'hits': v.get('fixture_hits'), 'tail': v.get('tail', '')[-200:]}
                  for k, v in report.get('tools', {}).items()},
        'browsers': browsers, 'error': report.get('error'),
        'controller_error': ready.get('error') or report.get('controller_final', {}).get('error'),
        'delete': report.get('controller_final', {}).get('delete'),
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
    c.add_argument('--dns-name', required=True)
    c.add_argument('--timeout', type=int, default=900)
    args = parser.parse_args()
    return driver(args) if args.role == 'driver' else controller(args)


if __name__ == '__main__':
    raise SystemExit(main())
