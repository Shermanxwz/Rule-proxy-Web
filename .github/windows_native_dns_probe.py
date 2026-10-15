"""Collect real default Windows resolver API observations, never denial claims.

Each synchronous native call runs in its own owned, held-HANDLE worker. The
controller gives its published entry lease four seconds, then terminates only
that worker if needed. Worker exit does not prove a brokered DNS request was
cancelled: outside wire controls and a complete NIC capture remain necessary.
No raw DNS datagram, explicit DNS server, host configuration or sandbox change
is made. Role labels are requested scopes; actual worker PID/PPID are recorded.
"""
from __future__ import annotations

import argparse
import ctypes
import json
import os
from pathlib import Path
import re
import shutil
import subprocess
import sys
import tempfile
import time

ROLES = ("outside_before", "parent", "child", "outside_after")
APIS = ("getaddrinfo", "dns_a", "dns_aaaa")
CALL_SECONDS = 4.0
STARTUP_SECONDS = 5.0
MAX_RECORD_BYTES = 16384
DNS_OPTIONS = 0x00000108  # WIRE_ONLY | BYPASS_CACHE; system server list is NULL.
DNS_REQUEST_PENDING = 9506


def error_facts(exc, stage, prefix=""):
    """Only fixed operation labels and numeric errors, never exception text."""
    observed = getattr(exc, "_ruleproxy_dns_stage", stage)
    if not isinstance(observed, str) or not re.fullmatch(r"[a-z_]{1,64}", observed):
        observed = stage
    value = {prefix + "error": type(exc).__name__[:64], prefix + "error_stage": observed}
    for key in ("errno", "winerror"):
        code = getattr(exc, key, None)
        value[prefix + key] = code if type(code) is int and -(1 << 31) <= code < (1 << 32) else None
    return value


def annotate_stage(exc, stage):
    # Keep OSError identity intact so missing-file polling remains unchanged.
    try:
        exc._ruleproxy_dns_stage = stage
    except (AttributeError, TypeError):
        pass


class DnsQueryRequest(ctypes.Structure):
    _fields_ = [("Version", ctypes.c_uint32), ("QueryName", ctypes.c_wchar_p),
                ("QueryType", ctypes.c_uint16), ("QueryOptions", ctypes.c_uint64),
                ("pDnsServerList", ctypes.c_void_p), ("InterfaceIndex", ctypes.c_uint32),
                ("pQueryCompletionCallback", ctypes.c_void_p), ("pQueryContext", ctypes.c_void_p)]


class DnsQueryResult(ctypes.Structure):
    _fields_ = [("Version", ctypes.c_uint32), ("QueryStatus", ctypes.c_int32),
                ("QueryOptions", ctypes.c_uint64), ("pQueryRecords", ctypes.c_void_p),
                ("Reserved", ctypes.c_void_p)]


class FileTime(ctypes.Structure):
    _fields_ = [("low", ctypes.c_uint32), ("high", ctypes.c_uint32)]


def qname(nonce, role, api):
    if not isinstance(nonce, str) or not re.fullmatch(r"[0-9a-f]{32}", nonce) or role not in ROLES or api not in APIS:
        raise ValueError("invalid fixed diagnostic identity")
    return f"{nonce}.{api.replace('_', '-')}.{role.replace('_', '-')}.ruleproxy-ci.example.com."


def write_json(path, value, *, stage="record"):
    operation = stage + "_encode"
    try:
        raw = json.dumps(value, ensure_ascii=True, separators=(",", ":")).encode("ascii")
        if len(raw) > MAX_RECORD_BYTES:
            raise ValueError("diagnostic record size limit")
        temporary = path.with_suffix(path.suffix + ".tmp")
        operation = stage + "_write_temp"
        temporary.write_bytes(raw)
        operation = stage + "_replace"
        os.replace(temporary, path)
    except Exception as exc:
        annotate_stage(exc, operation)
        raise


def read_json(path, *, stage="record"):
    operation = stage + "_open"
    try:
        with path.open("rb") as stream:
            operation = stage + "_read"
            raw = stream.read(MAX_RECORD_BYTES + 1)
        operation = stage + "_decode"
        if len(raw) > MAX_RECORD_BYTES:
            raise ValueError("diagnostic record size limit")
        value = json.loads(raw)
        if not isinstance(value, dict):
            raise ValueError("invalid diagnostic record")
        return value
    except Exception as exc:
        annotate_stage(exc, operation)
        raise


class ProcessIdentity:
    def __init__(self):
        self.k = ctypes.WinDLL("kernel32", use_last_error=True)
        self.k.GetCurrentProcess.argtypes, self.k.GetCurrentProcess.restype = [], ctypes.c_void_p
        self.k.GetProcessTimes.argtypes = [ctypes.c_void_p] + [ctypes.POINTER(FileTime)] * 4
        self.k.GetProcessTimes.restype = ctypes.c_int32
        self.k.WaitForSingleObject.argtypes = [ctypes.c_void_p, ctypes.c_uint32]
        self.k.WaitForSingleObject.restype = ctypes.c_uint32

    def created(self, handle):
        values = [FileTime() for _ in range(4)]
        if not self.k.GetProcessTimes(int(handle), *[ctypes.byref(item) for item in values]):
            raise ctypes.WinError(ctypes.get_last_error())
        return (values[0].high << 32) | values[0].low

    def current_created(self):
        return self.created(self.k.GetCurrentProcess())

    def exited(self, handle):
        status = self.k.WaitForSingleObject(int(handle), 0)
        if status not in (0, 258):
            raise ctypes.WinError(ctypes.get_last_error())
        return status == 0


class NativeResolver:
    """The system APIs themselves; no socket-based substitute is permitted."""
    def __init__(self):
        self.wsa = ctypes.WinDLL("ws2_32", use_last_error=True)
        self.wsa.WSAStartup.argtypes, self.wsa.WSAStartup.restype = [ctypes.c_uint16, ctypes.c_void_p], ctypes.c_int32
        self.wsa.WSACleanup.argtypes, self.wsa.WSACleanup.restype = [], ctypes.c_int32
        self.wsa.GetAddrInfoW.argtypes = [ctypes.c_wchar_p, ctypes.c_wchar_p, ctypes.c_void_p,
                                        ctypes.POINTER(ctypes.c_void_p)]
        self.wsa.GetAddrInfoW.restype = ctypes.c_int32
        self.wsa.FreeAddrInfoW.argtypes, self.wsa.FreeAddrInfoW.restype = [ctypes.c_void_p], None
        self.dns = ctypes.WinDLL("dnsapi", use_last_error=True)
        self.dns.DnsQueryEx.argtypes = [ctypes.POINTER(DnsQueryRequest), ctypes.POINTER(DnsQueryResult), ctypes.c_void_p]
        self.dns.DnsQueryEx.restype = ctypes.c_int32
        # DnsRecordListFree is a header macro for DnsFree(..., DnsFreeRecordList).
        self.dns.DnsFree.argtypes, self.dns.DnsFree.restype = [ctypes.c_void_p, ctypes.c_int32], None

    def invoke(self, api, name):
        if api == "getaddrinfo":
            startup = self.wsa.WSAStartup(0x0202, ctypes.create_string_buffer(512))
            if startup:
                return {"api_returned": False, "setup_error": "WSAStartup", "setup_code": int(startup)}
            result = ctypes.c_void_p()
            report = {"api_returned": False, "records_released": True, "query_options": 0}
            try:
                code = self.wsa.GetAddrInfoW(name, None, None, ctypes.byref(result))
                report = {"api_returned": True, "native_completion_proven": True,
                          "return_code": int(code), "records_present": bool(result.value),
                          "records_released": not bool(result.value), "query_options": 0}
            finally:
                if result.value:
                    self.wsa.FreeAddrInfoW(result)
                    report["records_released"] = True
                cleanup = self.wsa.WSACleanup()
            if cleanup:
                report["cleanup_error"] = "WSACleanup"
            return report
        request = DnsQueryRequest(Version=1, QueryName=name, QueryType=1 if api == "dns_a" else 28,
                                  QueryOptions=DNS_OPTIONS, pDnsServerList=None, InterfaceIndex=0,
                                  pQueryCompletionCallback=None, pQueryContext=None)
        result = DnsQueryResult(Version=1)
        code = self.dns.DnsQueryEx(ctypes.byref(request), ctypes.byref(result), None)
        if code == DNS_REQUEST_PENDING:
            # With no callback the documented path is synchronous. Preserve all
            # request/result references until the held worker is terminated.
            self.pending_buffers = (name, request, result)
            return {"api_returned": True, "return_code": int(code), "query_status": int(result.QueryStatus),
                    "native_completion_proven": False, "operation_pending": True, "query_options": DNS_OPTIONS}
        report = {"api_returned": True, "native_completion_proven": True,
                  "return_code": int(code), "query_status": int(result.QueryStatus),
                  "records_present": bool(result.pQueryRecords), "records_released": not bool(result.pQueryRecords),
                  "query_options": DNS_OPTIONS}
        if result.pQueryRecords:
            self.dns.DnsFree(result.pQueryRecords, 1)
            report["records_released"] = True
        return report


def worker(nonce, role, api, directory):
    name = qname(nonce, role, api)
    context = {"api": api, "qname": name, "requested_role": role, "pid": os.getpid(), "ppid": os.getppid(),
               "default_system_server_list": True, "server_list_override": False,
               "dns_blocked_proven": False, "acceptance_passed": False}
    stage = "worker_identity_init"
    try:
        identity = ProcessIdentity()
        stage = "worker_identity_created"
        context["process_created"] = identity.current_created()
        stage = "worker_resolver_init"
        resolver = NativeResolver()
        # The lease proves entry preparation, never actual packet transmission.
        stage = "worker_prepare_lease"
        write_json(directory / "lease.json", dict(context, state="native_call_prepared", monotonic=time.monotonic()), stage="lease")
        stage = "worker_invoke_api"
        observation = resolver.invoke(api, name)
        context.update(observation)
        stage = "worker_publish_result"
        write_json(directory / "result.json", context, stage="native_result")
        if observation.get("operation_pending"):
            while True:
                time.sleep(1)  # Keep native pointers alive for the controller.
        return 0
    except Exception as exc:
        context.update(api_returned=False, **error_facts(exc, stage))
        write_json(directory / "result.json", context, stage="worker_failure")
        return 1


def validate_context(value, process, created, nonce, role, api):
    if (value.get("api") != api or value.get("qname") != qname(nonce, role, api)
            or value.get("requested_role") != role or value.get("pid") != process.pid
            or value.get("ppid") != os.getpid() or value.get("process_created") != created
            or value.get("default_system_server_list") is not True or value.get("server_list_override") is not False
            or value.get("dns_blocked_proven") is not False or value.get("acceptance_passed") is not False):
        raise ValueError("native worker identity or resolver scope mismatch")


def collect_call(nonce, role, api, directory, identity):
    try:
        directory.mkdir()
    except Exception as exc:
        annotate_stage(exc, "prepare_worker_directory")
        raise
    process = None
    record = {"api": api, "qname": qname(nonce, role, api), "requested_role": role, "api_returned": False,
              "default_system_server_list": True, "server_list_override": False,
              "dns_blocked_proven": False, "acceptance_passed": False, "worker_cleanup_proven": False}
    stage = "launch_worker"
    try:
        process = subprocess.Popen([sys.executable, "-I", "-S", "-X", "utf8", str(Path(__file__).resolve()),
            "--worker", api, "--nonce", nonce, "--role", role, "--report", str(directory)],
            stdin=subprocess.DEVNULL, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
            shell=False, creationflags=getattr(subprocess, "CREATE_NO_WINDOW", 0))
        stage = "read_worker_generation"
        created = identity.created(process._handle)
        record.update(pid=process.pid, ppid=os.getpid(), process_created=created)
        start = time.monotonic()
        lease = None
        while time.monotonic() - start < STARTUP_SECONDS:
            try:
                stage = "read_entry_lease"
                lease = read_json(directory / "lease.json", stage="entry_lease")
                stage = "validate_entry_lease"
                validate_context(lease, process, created, nonce, role, api)
                break
            except FileNotFoundError:
                if process.poll() is not None:
                    break
                time.sleep(0.01)
        if lease is None:
            stage = "entry_lease_missing"
            raise RuntimeError("native entry lease missing")
        stage = "validate_entry_timestamp"
        stamp = lease.get("monotonic")
        if (lease.get("state") != "native_call_prepared" or type(stamp) not in (int, float)
                or not 0 <= time.monotonic() - stamp <= STARTUP_SECONDS):
            raise ValueError("invalid native entry lease timestamp")
        record["entry_lease_published"] = True
        try:
            stage = "wait_native_call"
            process.wait(timeout=max(0, stamp + CALL_SECONDS - time.monotonic()))
        except subprocess.TimeoutExpired:
            record.update(outcome="deadline", native_completion_proven=False)
        try:
            stage = "read_native_result"
            value = read_json(directory / "result.json", stage="native_result")
        except FileNotFoundError:
            if record.get("outcome") != "deadline":
                raise RuntimeError("native worker exited without its API result")
        else:
            stage = "validate_native_result"
            validate_context(value, process, created, nonce, role, api)
            record.update(value)
            stage = "check_native_completion"
            if process.returncode not in (None, 0) or value.get("api_returned") is not True or value.get("operation_pending"):
                raise RuntimeError("native API completion was not collected")
            record["outcome"] = "returned"
    except Exception as exc:
        # A worker failure is the original observation; rejection by its
        # controller must not replace its actual stage or Windows error.
        prefix = "controller_" if "error" in record else ""
        record.update(outcome="tool_error", **error_facts(exc, stage, prefix))
    finally:
        if process is not None:
            try:
                stage = "check_worker_exit"
                if not identity.exited(process._handle):
                    stage = "terminate_owned_worker"
                    process.kill()  # Popen's exact creation HANDLE, never a PID/name.
                    record["owned_worker_terminated"] = True
                stage = "wait_owned_worker_exit"
                process.wait(timeout=2)
                stage = "verify_worker_exit"
                if not identity.exited(process._handle):
                    raise RuntimeError("owned native worker remained alive")
                record["worker_exit_verified"] = True
                record["worker_exit_code"] = process.returncode
                stage = "close_worker_handle"
                process._handle.Close()
                record["worker_handle_closed"] = True
                record["worker_cleanup_proven"] = True
            except Exception as exc:
                record.update(recovery_directory=str(directory), **error_facts(exc, stage, "cleanup_"))
        else:
            record["no_process_started"] = True
            record["worker_cleanup_proven"] = True
    return record


def main(arguments=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--nonce", required=True)
    parser.add_argument("--role", required=True, choices=ROLES)
    parser.add_argument("--report", required=True, type=Path)
    parser.add_argument("--worker", choices=APIS)
    args = parser.parse_args(arguments)
    qname(args.nonce, args.role, "getaddrinfo")
    if args.worker:
        return worker(args.nonce, args.role, args.worker, args.report)
    result = {"status": "failed", "acceptance_passed": False, "real_node_passed": False,
              "dns_blocked_proven": False, "wire_observed": None, "default_system_server_list": True,
              "server_list_override": False, "requested_role": args.role, "calls": [], "cleanup_proven": True}
    args.report.parent.mkdir(parents=True, exist_ok=True)
    if os.name != "nt":
        result.update(status="unsupported", reason="Windows_required")
        write_json(args.report, result)
        return 3
    directory = None
    code = 1
    stage = "controller_identity_init"
    try:
        identity = ProcessIdentity()
        stage = "prepare_control_directory"
        directory = Path(tempfile.mkdtemp(prefix="ruleproxy-native-dns-"))
        for api in APIS:
            stage = "collect_native_call"
            value = collect_call(args.nonce, args.role, api, directory / api, identity)
            result["calls"].append(value)
            if value.get("cleanup_error") or value["worker_cleanup_proven"] is not True:
                result.update(cleanup_proven=False, cleanup_error="NativeWorkerCleanupUnproven",
                              recovery_directory=str(directory))
                result.update({key: value[key] for key in ("cleanup_error_stage", "cleanup_errno", "cleanup_winerror")
                               if key in value})
                break
        if result["cleanup_proven"] and len(result["calls"]) == len(APIS) and all(
                x["outcome"] in ("returned", "deadline") for x in result["calls"]):
            result["status"], code = "native_dns_probe_only", 0
    except Exception as exc:
        result.update(error_facts(exc, stage))
    finally:
        if directory is not None and result["cleanup_proven"]:
            try:
                shutil.rmtree(directory)
            except OSError as exc:
                result.update(status="failed", cleanup_proven=False, recovery_directory=str(directory),
                              **error_facts(exc, "cleanup_control_directory", "cleanup_"))
                code = 1
        write_json(args.report, result)
    return code


if __name__ == "__main__":
    raise SystemExit(main())
