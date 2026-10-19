"""One DNS API call per process, for launch by the compartment lab.

No machine settings are changed. Use a different random name for every call.
Parent harness should impose a process timeout and collect wire evidence: DNS
failure codes can still mean the DNS query was transmitted (e.g. NXDOMAIN).
"""
from __future__ import annotations
import argparse
import ctypes as C
import ctypes.wintypes as W
import json
import os
import secrets
import socket
import time

FLAGS = {
    'standard': 0,
    'bypass': 0x8,
    'wire': 0x100 | 0x40 | 0x20 | 0x80 | 0x800 | 0x1000,
    'tcp_wire': 0x2 | 0x100 | 0x40 | 0x20 | 0x80 | 0x800 | 0x1000,
    'addrconfig': 0x2000,
    'cache_only': 0x10,
}

class Request(C.Structure):
    _fields_ = [('Version', W.ULONG), ('QueryName', W.LPCWSTR),
                ('QueryType', W.WORD), ('QueryOptions', C.c_ulonglong),
                ('pDnsServerList', C.c_void_p), ('InterfaceIndex', W.ULONG),
                ('pQueryCompletionCallback', C.c_void_p), ('pQueryContext', C.c_void_p)]

class Result(C.Structure):
    _fields_ = [('Version', W.ULONG), ('QueryStatus', W.LONG),
                ('QueryOptions', C.c_ulonglong), ('pQueryRecords', C.c_void_p),
                ('Reserved', C.c_void_p)]

class SidAndAttributes(C.Structure):
    _fields_ = [('Sid', C.c_void_p), ('Attributes', W.DWORD)]


def impersonate_custom_restriction(sid_string):
    """Diagnostic only: thread impersonation is NOT a production boundary.

    Run in a fresh process before any DNS RPC binding is established. An app
    can revert its own impersonation; a real launcher must restrict its primary
    token and launch it with CreateProcessAsUser.
    """
    kernel = C.WinDLL('kernel32', use_last_error=True)
    advapi = C.WinDLL('advapi32', use_last_error=True)
    kernel.GetCurrentProcess.argtypes = []
    kernel.GetCurrentProcess.restype = W.HANDLE
    kernel.CloseHandle.argtypes = [W.HANDLE]
    kernel.CloseHandle.restype = W.BOOL
    kernel.LocalFree.argtypes = [C.c_void_p]
    kernel.LocalFree.restype = C.c_void_p
    advapi.OpenProcessToken.argtypes = [W.HANDLE, W.DWORD, C.POINTER(W.HANDLE)]
    advapi.OpenProcessToken.restype = W.BOOL
    advapi.ConvertStringSidToSidW.argtypes = [W.LPCWSTR, C.POINTER(C.c_void_p)]
    advapi.ConvertStringSidToSidW.restype = W.BOOL
    advapi.CreateRestrictedToken.argtypes = [W.HANDLE, W.DWORD, W.DWORD, C.c_void_p,
        W.DWORD, C.c_void_p, W.DWORD, C.POINTER(SidAndAttributes), C.POINTER(W.HANDLE)]
    advapi.CreateRestrictedToken.restype = W.BOOL
    advapi.ImpersonateLoggedOnUser.argtypes = [W.HANDLE]
    advapi.ImpersonateLoggedOnUser.restype = W.BOOL
    advapi.RevertToSelf.argtypes = []
    advapi.RevertToSelf.restype = W.BOOL
    token, restricted, sid = W.HANDLE(), W.HANDLE(), C.c_void_p()
    def check(ok):
        if not ok:
            raise C.WinError(C.get_last_error())
    try:
        check(advapi.OpenProcessToken(kernel.GetCurrentProcess(), 0x000A, C.byref(token)))
        check(advapi.ConvertStringSidToSidW(sid_string, C.byref(sid)))
        entry = SidAndAttributes(sid, 0)
        # No WRITE_RESTRICTED: all object access is checked, not just writes.
        check(advapi.CreateRestrictedToken(token, 1, 0, None, 0, None,
                                          1, C.byref(entry), C.byref(restricted)))
        check(advapi.ImpersonateLoggedOnUser(restricted))
        return advapi
    finally:
        if sid.value:
            kernel.LocalFree(sid)
        if restricted.value:
            kernel.CloseHandle(restricted)
        if token.value:
            kernel.CloseHandle(token)


class AppSettings(C.Structure):
    _fields_ = [('Version', W.ULONG), ('Flags', C.c_ulonglong)]


def run(args):
    if os.name != 'nt':
        raise RuntimeError('Windows only')
    ip = C.WinDLL('iphlpapi', use_last_error=True)
    ip.GetCurrentThreadCompartmentId.argtypes = []
    ip.GetCurrentThreadCompartmentId.restype = W.ULONG
    name = args.name or (secrets.token_hex(16) + '.' + args.suffix.strip('.'))
    report = {'pid': os.getpid(), 'name': name, 'api': args.api,
              'mode': args.mode, 'flags': FLAGS[args.mode], 'interface_index': args.interface,
              'compartment_id': int(ip.GetCurrentThreadCompartmentId())}
    dns = C.WinDLL('dnsapi', use_last_error=True)
    dns.DnsRecordListFree.argtypes = [C.c_void_p, C.c_int]
    dns.DnsRecordListFree.restype = None
    if args.exclusive_empty:
        # Optional diagnostic only; not a security boundary or an inherited policy.
        settings = AppSettings(1, 1)
        fn = dns.DnsSetApplicationSettings
        fn.argtypes = [W.DWORD, C.c_void_p, C.POINTER(AppSettings)]
        fn.restype = W.DWORD
        report['exclusive_empty_status'] = int(fn(0, None, C.byref(settings)))
    impersonation = None
    if args.impersonate_restricted:
        sid_string = args.restrict_sid or 'S-1-5-21-123456789-234567890-345678901-456789'
        impersonation = impersonate_custom_restriction(sid_string)
        report['impersonation_restricting_sid'] = sid_string
    print(json.dumps({'phase': 'begin', **report}), flush=True)
    start = time.monotonic()
    try:
        if args.api == 'getaddrinfo':
            report['addresses'] = sorted({v[4][0] for v in socket.getaddrinfo(name, 443, socket.AF_UNSPEC, socket.SOCK_STREAM)})
            report['status'] = 0
        elif args.api == 'DnsQuery_W':
            fn = dns.DnsQuery_W
            fn.argtypes = [W.LPCWSTR, W.WORD, W.DWORD, C.c_void_p, C.POINTER(C.c_void_p), C.c_void_p]
            fn.restype = W.LONG
            records = C.c_void_p()
            try:
                report['status'] = int(fn(name, 1, FLAGS[args.mode], None, C.byref(records), None))
                report['has_records'] = bool(records.value)
            finally:
                if records.value:
                    dns.DnsRecordListFree(records, 1) # DnsFreeRecordList
        else:
            fn = dns.DnsQueryEx
            fn.argtypes = [C.POINTER(Request), C.POINTER(Result), C.c_void_p]
            fn.restype = W.LONG
            request = Request(1, name, 1, FLAGS[args.mode], None, args.interface, None, None)
            result = Result()
            result.Version = 1
            try:
                report['status'] = int(fn(C.byref(request), C.byref(result), None))
                report['query_status'] = int(result.QueryStatus)
                report['has_records'] = bool(result.pQueryRecords)
            finally:
                if result.pQueryRecords:
                    dns.DnsRecordListFree(result.pQueryRecords, 1)
    except Exception as exc:
        report['error'] = str(exc)
        report['winerror'] = getattr(exc, 'winerror', None)
        report['errno'] = getattr(exc, 'errno', None)
    if impersonation is not None:
        if not impersonation.RevertToSelf():
            raise C.WinError(C.get_last_error())
    report['elapsed_seconds'] = time.monotonic() - start
    print(json.dumps({'phase': 'complete', **report}), flush=True)

if __name__ == '__main__':
    parser = argparse.ArgumentParser()
    parser.add_argument('--api', choices=['getaddrinfo', 'DnsQuery_W', 'DnsQueryEx'], required=True)
    parser.add_argument('--mode', choices=list(FLAGS), default='standard')
    parser.add_argument('--name')
    parser.add_argument('--suffix', default='1.2.3.4.sslip.io')
    parser.add_argument('--interface', type=int, default=0)
    parser.add_argument('--exclusive-empty', action='store_true')
    parser.add_argument('--impersonate-restricted', action='store_true')
    parser.add_argument('--restrict-sid')
    run(parser.parse_args())
