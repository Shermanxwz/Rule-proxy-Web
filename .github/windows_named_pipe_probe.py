"""Isolated Windows IPC probe only; no socket, proxy, ACL, or policy changes.

Run this file as the contained helper under the existing three-deny PSEC policy.
Success proves only same-helper/child bidirectional named-pipe I/O, not networking.
"""
from __future__ import annotations
import ctypes
from ctypes import wintypes as W
import json
import os
from pathlib import Path
import re
import secrets
import subprocess
import sys
import threading
import time

PREFIX = "\\\\.\\pipe\\LOCAL\\RuleProxy-Probe-"
NAME_RE = re.compile(re.escape(PREFIX) + r"[0-9a-f]{32}-(self|child)\Z")
MAX_PACKET = 256
IO_SECONDS = 2.0
_PINNED = []  # Retain buffers until process exit if cancellation cannot be proved.
_CLEANUP_ERRORS = []

class ProbeError(Exception):
    def __init__(self, operation, code):
        self.operation, self.code = operation, int(code)
        super().__init__(operation)

class OVERLAPPED(ctypes.Structure):
    _fields_ = [("Internal", ctypes.c_size_t), ("InternalHigh", ctypes.c_size_t),
                ("Offset", W.DWORD), ("OffsetHigh", W.DWORD), ("hEvent", W.HANDLE)]

class PipeAPI:
    def __init__(self):
        self.k = ctypes.WinDLL("kernel32", use_last_error=True)
        signatures = {
            "CreateNamedPipeW": (W.HANDLE, [W.LPCWSTR, W.DWORD, W.DWORD, W.DWORD, W.DWORD, W.DWORD, W.DWORD, W.LPVOID]),
            "CreateFileW": (W.HANDLE, [W.LPCWSTR, W.DWORD, W.DWORD, W.LPVOID, W.DWORD, W.DWORD, W.HANDLE]),
            "CreateEventW": (W.HANDLE, [W.LPVOID, W.BOOL, W.BOOL, W.LPCWSTR]),
            "ConnectNamedPipe": (W.BOOL, [W.HANDLE, ctypes.POINTER(OVERLAPPED)]),
            "SetNamedPipeHandleState": (W.BOOL, [W.HANDLE, ctypes.POINTER(W.DWORD), W.LPVOID, W.LPVOID]),
            "ReadFile": (W.BOOL, [W.HANDLE, W.LPVOID, W.DWORD, ctypes.POINTER(W.DWORD), ctypes.POINTER(OVERLAPPED)]),
            "WriteFile": (W.BOOL, [W.HANDLE, W.LPCVOID, W.DWORD, ctypes.POINTER(W.DWORD), ctypes.POINTER(OVERLAPPED)]),
            "WaitForSingleObject": (W.DWORD, [W.HANDLE, W.DWORD]),
            "GetOverlappedResult": (W.BOOL, [W.HANDLE, ctypes.POINTER(OVERLAPPED), ctypes.POINTER(W.DWORD), W.BOOL]),
            "CancelIoEx": (W.BOOL, [W.HANDLE, ctypes.POINTER(OVERLAPPED)]),
            "DisconnectNamedPipe": (W.BOOL, [W.HANDLE]),
            "CloseHandle": (W.BOOL, [W.HANDLE]),
        }
        for name, (result, args) in signatures.items():
            fn = getattr(self.k, name)
            fn.restype, fn.argtypes = result, args
        self.invalid = ctypes.c_void_p(-1).value

    def handle(self, value, operation):
        if value is None or value == self.invalid:
            raise ProbeError(operation, ctypes.get_last_error())
        return value

    def server(self, name):
        # Default descriptor, no inherited handles, first instance, local clients.
        return self.handle(self.k.CreateNamedPipeW(name, 3 | 0x40000000 | 0x00080000,
            4 | 2 | 8, 1, 4096, 4096, 2000, None), "CreateNamedPipeW")

    def client(self, name):
        h = self.handle(self.k.CreateFileW(name, 0x80000000 | 0x40000000, 3,
            None, 3, 0x40000000, None), "CreateFileW")
        mode = W.DWORD(2)  # Firefox requires message read mode.
        if not self.k.SetNamedPipeHandleState(h, ctypes.byref(mode), None, None):
            code = ctypes.get_last_error()
            self.close(h)
            raise ProbeError("SetNamedPipeHandleState", code)
        return h

    def io(self, h, operation, packet=None):
        event = self.handle(self.k.CreateEventW(None, True, False, None), "CreateEventW")
        ov = OVERLAPPED(hEvent=event)
        done = W.DWORD()
        buffer = ctypes.create_string_buffer(packet if packet is not None else MAX_PACKET)
        pending = False
        keep = False
        try:
            if operation == "connect":
                ok = self.k.ConnectNamedPipe(h, ctypes.byref(ov))
            else:
                fn = self.k.WriteFile if operation == "write" else self.k.ReadFile
                count = len(packet) if packet is not None else MAX_PACKET
                ok = fn(h, buffer, count, ctypes.byref(done), ctypes.byref(ov))
            if not ok:
                code = ctypes.get_last_error()
                if operation == "connect" and code == 535:  # Client won the race.
                    return b""
                if code != 997:
                    raise ProbeError(operation, code)
                pending = True
                wait = self.k.WaitForSingleObject(event, int(IO_SECONDS * 1000))
                if wait != 0:
                    self.k.CancelIoEx(h, ctypes.byref(ov))
                    if self.k.WaitForSingleObject(event, 1000) != 0:
                        # Windows may still own OVERLAPPED and its buffer.
                        _PINNED.append((h, event, ov, buffer))
                        keep = True
                        raise ProbeError(operation + "_cleanup_unproven", 258)
                    pending = False
                    raise ProbeError(operation + "_timeout", 258)
                pending = False
                if not self.k.GetOverlappedResult(h, ctypes.byref(ov), ctypes.byref(done), False):
                    raise ProbeError(operation, ctypes.get_last_error())
            if operation == "write" and done.value != len(packet):
                raise ProbeError("short_write", 0)
            return buffer.raw[:done.value] if operation == "read" else b""
        finally:
            if pending and not keep:
                self.k.CancelIoEx(h, ctypes.byref(ov))
                if self.k.WaitForSingleObject(event, 1000) != 0:
                    _PINNED.append((h, event, ov, buffer))
                    keep = True
            if not keep:
                self.close(event)

    def close(self, h):
        if h is not None and not self.k.CloseHandle(h):
            _CLEANUP_ERRORS.append({"operation": "CloseHandle", "winerror": ctypes.get_last_error()})


def result(scope, ok, operation="", code=0):
    return {"scope": scope, "passed": bool(ok), "pid": os.getpid(),
            "ppid": os.getppid(), "operation": operation, "winerror": int(code),
            "cleanup_proven": not _PINNED and not _CLEANUP_ERRORS}


def client_probe(name, nonce, scope):
    if not NAME_RE.fullmatch(name) or not re.fullmatch(r"[0-9a-f]{32}", nonce):
        return result(scope, False, "invalid_probe_arguments")
    api = PipeAPI()
    h = None
    payload = b"RuleProxy-IPC-Probe:" + nonce.encode("ascii")
    expected = b"RuleProxy-IPC-Reply:" + nonce.encode("ascii")
    try:
        h = api.client(name)
        api.io(h, "write", payload)
        if api.io(h, "read") != expected:
            raise ProbeError("nonce_mismatch", 0)
        # Explicit application ACK prevents server-close racing the read.
        api.io(h, "write", b"ACK:" + nonce.encode("ascii"))
        item = result(scope, True)
    except ProbeError as exc:
        item = result(scope, False, exc.operation, exc.code)
    finally:
        api.close(h)
    item["cleanup_proven"] = not _PINNED and not _CLEANUP_ERRORS
    item["passed"] = item["passed"] and item["cleanup_proven"]
    return item


def roundtrip(scope):
    api = PipeAPI()
    name = PREFIX + secrets.token_hex(16) + "-" + scope
    nonce = secrets.token_hex(16)
    h = None
    thread = None
    child = None
    client_results = []
    parent_result = None
    try:
        h = api.server(name)
        if scope == "self":
            thread = threading.Thread(target=lambda: client_results.append(client_probe(name, nonce, scope)), daemon=True)
            thread.start()
        else:
            child = subprocess.Popen([sys.executable, "-I", "-S", "-X", "utf8", str(Path(__file__).resolve()),
                "--client", name, nonce], stdin=subprocess.DEVNULL, stdout=subprocess.PIPE,
                stderr=subprocess.DEVNULL, close_fds=True, shell=False)
        api.io(h, "connect")
        if api.io(h, "read") != b"RuleProxy-IPC-Probe:" + nonce.encode("ascii"):
            raise ProbeError("nonce_mismatch", 0)
        api.io(h, "write", b"RuleProxy-IPC-Reply:" + nonce.encode("ascii"))
        if api.io(h, "read") != b"ACK:" + nonce.encode("ascii"):
            raise ProbeError("ack_mismatch", 0)
        parent_result = result(scope, True)
    except ProbeError as exc:
        parent_result = result(scope, False, exc.operation, exc.code)
    except (OSError, subprocess.SubprocessError):
        parent_result = result(scope, False, "child_launch")
    finally:
        if h is not None:
            if not api.k.DisconnectNamedPipe(h):
                code = ctypes.get_last_error()
                if code != 233:  # ERROR_PIPE_NOT_CONNECTED after a failed client.
                    _CLEANUP_ERRORS.append({"operation": "DisconnectNamedPipe", "winerror": code})
            api.close(h)
        if thread is not None:
            thread.join(5)
            if thread.is_alive():
                parent_result = result(scope, False, "client_thread_timeout", 258)
                _CLEANUP_ERRORS.append({"operation": "client_thread_timeout", "winerror": 258})
        if child is not None:
            try:
                data = child.communicate(timeout=5)[0]
                if len(data) <= 2048:
                    item = json.loads(data)
                    if isinstance(item, dict):
                        client_results.append(item)
            except (subprocess.TimeoutExpired, ValueError) as exc:
                operation = "client_child_timeout" if isinstance(exc, subprocess.TimeoutExpired) else "invalid_client_result"
                parent_result = result(scope, False, operation, 258 if operation == "client_child_timeout" else 0)
                try:
                    if child.poll() is None:
                        child.kill()  # This diagnostic's own child only, never MXC/others.
                    child.communicate(timeout=2)
                except (OSError, subprocess.SubprocessError) as cleanup_exc:
                    _CLEANUP_ERRORS.append({"operation": "client_child_cleanup",
                                            "winerror": int(getattr(cleanup_exc, "winerror", None) or 258)})
    peer = client_results[0] if client_results else result(scope, False, "missing_client_result")
    expected_pid = os.getpid() if child is None else child.pid
    if (peer.get("passed") is not True or peer.get("cleanup_proven") is not True
            or peer.get("scope") != scope or peer.get("pid") != expected_pid
            or (child is not None and (peer.get("ppid") != os.getpid() or child.returncode != 0))):
        parent_result["passed"] = False
    parent_result["cleanup_proven"] = not _PINNED and not _CLEANUP_ERRORS
    parent_result["client"] = peer
    return parent_result


def main():
    if os.name != "nt":
        print(json.dumps({"status": "unsupported", "ipc_passed": False,
                          "acceptance_passed": False, "reason": "Windows_required"}))
        return 3
    if len(sys.argv) == 4 and sys.argv[1] == "--client":
        item = client_probe(sys.argv[2], sys.argv[3], "child")
        print(json.dumps(item, ensure_ascii=True, separators=(",", ":")))
        return 0 if item["passed"] else 1
    if len(sys.argv) != 1:
        return 2
    started = time.monotonic()
    checks = [roundtrip("self"), roundtrip("child")]
    clean = not _PINNED and not _CLEANUP_ERRORS
    passed = all(item["passed"] for item in checks) and clean
    report = {"status": "ipc_probe_only", "ipc_passed": passed, "acceptance_passed": False,
              "default_dacl": True, "network_policy_changed": False,
              "cleanup_proven": clean, "cleanup_errors": _CLEANUP_ERRORS[:8],
              "elapsed_seconds": round(time.monotonic() - started, 3),
              "checks": checks}
    print(json.dumps(report, ensure_ascii=True, separators=(",", ":")))
    return 0 if passed else 1

if __name__ == "__main__":
    raise SystemExit(main())
