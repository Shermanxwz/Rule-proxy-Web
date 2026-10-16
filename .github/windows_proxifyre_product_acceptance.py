"""Exercise the installed offline Windows product in a disposable VM.

The actual OS and independent evidence determine each qualification claim.
Ordinary actors use destination sockets; fixture SOCKS handshakes are health only.
"""
from __future__ import annotations

import sys

# Capture import/argument/bootstrap failures in the original ordinary process,
# before importing modules which could fail or loading its test specification.
if __name__ == "__main__" and "--ordinary-suite" in sys.argv:
    _ordinary_stdio = open(r"C:\RuleProxyProduct\actors\ordinary-stdio.log", "a",
                           encoding="utf-8", buffering=1)
    sys.stdout = sys.stderr = _ordinary_stdio
    print("ordinary bootstrap executable: " + sys.executable, flush=True)

import argparse
import base64
import ctypes
from ctypes import wintypes
import hashlib
import importlib.util
import json
import os
import platform
from pathlib import Path, PurePosixPath
import re
import secrets
import shutil
import socket
import struct
import subprocess
import time
import traceback
import urllib.error
import urllib.request
import zipfile

LAB = Path(r"C:\RuleProxyProduct")
INSTALLED = Path(os.environ.get("ProgramFiles", r"C:\Program Files")) / "RuleProxy-Web"


def write(path, value, *, replace_timeout=2.0):
    path = Path(path)
    path.parent.mkdir(parents=True, exist_ok=True)
    temporary = path.with_suffix(path.suffix + ".tmp")
    temporary.write_text(json.dumps(value, ensure_ascii=True, indent=2) + "\n", encoding="ascii")
    deadline = time.monotonic() + replace_timeout
    while True:
        try:
            os.replace(temporary, path)
            return
        except OSError as exc:
            # A controller/diagnostic reader can briefly deny delete sharing.
            # Retain atomic publication and surface persistent permissions or
            # locks after a short deadline; unrelated errors are never retried.
            if os.name != "nt" or getattr(exc, "winerror", None) not in {5, 32, 33}:
                raise
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                raise
            time.sleep(min(.02, remaining))


def digest(path):
    return hashlib.sha256(Path(path).read_bytes()).hexdigest()


def png_dimensions(path):
    with Path(path).open("rb") as stream:
        header = stream.read(33)
    if (len(header) != 33 or header[:8] != b"\x89PNG\r\n\x1a\n"
            or header[8:16] != b"\x00\x00\x00\rIHDR"):
        raise ValueError("Browser screenshot has no complete PNG IHDR")
    width, height = struct.unpack("!II", header[16:24])
    if not 1 <= width <= 16384 or not 1 <= height <= 16384:
        raise ValueError("Browser screenshot dimensions are invalid")
    return width, height


def module(path, name):
    spec = importlib.util.spec_from_file_location(name, path)
    value = importlib.util.module_from_spec(spec)
    sys.modules[name] = value
    spec.loader.exec_module(value)
    return value


def wait_for(function, timeout=30):
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        try:
            value = function()
            if value:
                return value
        except (OSError, ValueError, urllib.error.URLError):
            pass
        time.sleep(.2)
    raise TimeoutError("bounded product condition timed out")


def powershell(body, *, env=None, timeout=45):
    values = dict(os.environ, **(env or {}))
    values["PSModulePath"] = str(Path(values.get("SystemRoot", r"C:\Windows")) /
                                 "System32/WindowsPowerShell/v1.0/Modules")
    result = subprocess.run(["powershell.exe", "-NoLogo", "-NoProfile", "-NonInteractive", "-Command",
                             "$ErrorActionPreference='Stop'; " + body],
                            env=values, capture_output=True, timeout=timeout)
    return {"returncode": result.returncode,
            "stdout": result.stdout[-65536:].decode("utf-8-sig", errors="replace"),
            "stderr": result.stderr[-65536:].decode("utf-8-sig", errors="replace")}


def run_background_entry(command, *, cwd, log_path, timeout=30):
    # A background descendant can retain its launcher's stdout/stderr handles.
    # A file needs no EOF collection; PIPE capture can outlive the timeout on
    # Windows while subprocess.run drains inherited handles after killing cmd.
    with Path(log_path).open("wb") as output:
        return subprocess.run(command, cwd=cwd, stdin=subprocess.DEVNULL,
                              stdout=output, stderr=subprocess.STDOUT, timeout=timeout)


def execute_script(script, owner_sid, source=None):
    env = {"RULEPROXY_PRODUCT_SCRIPT": str(script), "RULEPROXY_PRODUCT_SID": owner_sid}
    tail = " -SourceRoot $env:RULEPROXY_PRODUCT_SOURCE -NoLaunch" if source else ""
    if source:
        env["RULEPROXY_PRODUCT_SOURCE"] = str(source)
    # Let this child PowerShell process propagate MSI reboot codes verbatim.
    return powershell("& $env:RULEPROXY_PRODUCT_SCRIPT -Elevated -OwnerSid $env:RULEPROXY_PRODUCT_SID" + tail,
                      env=env, timeout=1000)


def unpack_package(package_dir, destination):
    destination = Path(destination)
    packages = list(Path(package_dir).glob("*.zip"))
    if len(packages) != 1:
        raise ValueError("Expected exactly one final product ZIP")
    package = packages[0]
    expected = (Path(package_dir) / "SHA256SUMS.txt").read_text(encoding="ascii").split()
    if len(expected) != 2 or expected[1] != package.name or expected[0] != digest(package):
        raise ValueError("Final ZIP digest does not match SHA256SUMS")
    with zipfile.ZipFile(package) as archive:
        seen, size = set(), 0
        for item in archive.infolist():
            name = PurePosixPath(item.filename)
            size += item.file_size
            if (name.is_absolute() or ".." in name.parts or ":" in item.filename or "\\" in item.filename
                    or item.filename.casefold() in seen or (item.external_attr >> 16) & 0o170000 == 0o120000
                    or size > 512 * 1024**2):
                raise ValueError("Unsafe final ZIP member")
            seen.add(item.filename.casefold())
        archive.extractall(destination)
    roots = list(destination.glob("*/package-manifest.json"))
    if len(roots) != 1:
        raise ValueError("Final ZIP product layout mismatch")
    bundle = roots[0].parent
    manifest = json.loads(roots[0].read_text(encoding="utf-8"))
    for relative, expected_hash in manifest["files"].items():
        name = PurePosixPath(relative)
        if name.is_absolute() or ".." in name.parts or ":" in relative or "\\" in relative:
            raise ValueError("Unsafe manifest member")
        if digest(bundle / relative) != expected_hash:
            raise ValueError("Final product file hash mismatch: " + relative)
    return bundle, {"zip": package.name, "sha256": expected[0], "manifest_verified": True,
                    "files_verified": len(manifest["files"]), "product_version": manifest["version"]}


def receiver_evidence(phases, snapshot):
    """Cross-check only actor responses against independently owned receivers."""
    verified = []
    for phase in phases:
        token, expected = phase["token"], phase["expected_node"]
        matches = [row for row in snapshot["transactions"]
                   if row.get("evidence_role") == "actor"
                   and token in (row.get("request_target", "") + row.get("qname", ""))
                   and row.get("protocol") in ("tcp_http_response", "udp_dns")]
        counts = {node: sum(row.get("node") == node for row in matches) for node in ("A", "B")}
        attempts = len(phase["actor"]["rows"])
        ok = (counts[expected] >= attempts and counts[{"A": "B", "B": "A"}[expected]] == 0
              if expected else not matches)
        verified.append({"label": phase["label"], "token": token, "expected_node": expected,
                         "attempts": attempts, "receiver_node_counts": counts,
                         "matching_receiver_transactions": matches, "passed": bool(ok and attempts)})
    return verified


def native_proxy_receipt_valid(receipt, owner_sid, installed_root):
    """Bind the separate HTTP fixture to real ordinary tokens and installed code."""
    if (not isinstance(receipt, dict) or not isinstance(owner_sid, str)
            or re.fullmatch(r"S-1-[0-9]+(?:-[0-9]+)+", owner_sid) is None):
        return False
    try:
        expected_launcher = (Path(installed_root) / "ruleproxy/windows_app_process.py").resolve()
        parent, child, grandchild = (receipt[key] for key in ("parent_token", "child", "grandchild"))
        if (receipt.get("probe_scope") != "windows-native-launcher-child-grandchild-loopback"
                or type(receipt.get("exit_code")) is not int or receipt["exit_code"] != 0
                or type(receipt.get("proxy_port")) is not int or not 1025 <= receipt["proxy_port"] <= 65535
                or Path(receipt["launcher_file"]).resolve() != expected_launcher):
            return False
        actors = (parent, child, grandchild)
        if any(not isinstance(actor, dict) or actor.get("sid") != owner_sid
               or actor.get("elevated") is not False or type(actor.get("pid")) is not int
               or actor["pid"] <= 0 or "error" in actor for actor in actors):
            return False
        if (len({actor["pid"] for actor in actors}) != 3 or type(receipt.get("launched_pid")) is not int
                or child.get("pid") != receipt["launched_pid"] or type(child.get("ppid")) is not int
                or type(grandchild.get("ppid")) is not int or child["ppid"] != parent["pid"]
                or grandchild["ppid"] != child["pid"]
                or type(child.get("grandchild_exit_code")) is not int or child["grandchild_exit_code"] != 0):
            return False
        targets = receipt.get("expected_targets")
        if not isinstance(targets, list) or len(targets) != 2 or receipt.get("received_targets") != targets:
            return False
        first = re.fullmatch(r"http://([a-f0-9]{32})\.invalid/\1/child", targets[0])
        if first is None or targets[1] != f"http://{first[1]}.invalid/{first[1]}/grandchild":
            return False
        endpoint = f"http://127.0.0.1:{receipt['proxy_port']}"
        environment = {"HTTP_PROXY": endpoint, "HTTPS_PROXY": endpoint, "ALL_PROXY": endpoint,
                       "NO_PROXY": "localhost,127.0.0.1,::1", "NODE_USE_ENV_PROXY": "1"}
        for actor, target in zip((child, grandchild), targets):
            if (Path(actor["launcher_file"]).resolve() != expected_launcher
                    or actor.get("proxy_environment") != environment or actor.get("target") != target
                    or actor.get("response") != "proxy-fixture:" + first[1]):
                return False
        return True
    except (KeyError, TypeError, ValueError, OSError):
        return False


def native_proxy_environment_probe(spec):
    """Run the exact shared probe before any product panel or proxy core starts."""
    expected = spec.get("native_proxy_fixture_sha256", "")
    helper = LAB / "native-proxy-probe.py"
    if (not isinstance(expected, str) or re.fullmatch(r"[a-f0-9]{64}", expected) is None
            or digest(helper) != expected):
        raise RuntimeError("Native proxy fixture source differs from the checked controller copy")
    probe = module(helper, "product_native_proxy_probe")
    receipt = probe.native_launcher_proxy_probe(LAB / "actors")
    if (not native_proxy_receipt_valid(receipt, spec["owner_sid"], INSTALLED)
            or receipt["parent_token"]["pid"] != os.getpid()):
        raise RuntimeError("Native proxy fixture lacks ordinary token, installed launcher or receiver evidence")
    return {"passed": True, "fixture_sha256": expected, "receipt": receipt,
            "scope": "ordinary_installed_launcher_explicit_proxy_environment_only"}


class UserProcess:
    def __init__(self, handle, pid, kernel):
        self.handle, self.pid, self.kernel = handle, pid, kernel
        kernel.TerminateProcess.argtypes = [wintypes.HANDLE, wintypes.UINT]
        kernel.TerminateProcess.restype = wintypes.BOOL

    def poll(self):
        code = wintypes.DWORD()
        if not self.kernel.GetExitCodeProcess(self.handle, ctypes.byref(code)):
            raise ctypes.WinError(ctypes.get_last_error())
        return None if code.value == 259 else code.value

    def terminate(self):
        if self.poll() is None:
            if not self.kernel.TerminateProcess(self.handle, 125):
                raise ctypes.WinError(ctypes.get_last_error())

    def wait(self, timeout=None):
        self.kernel.WaitForSingleObject.argtypes = [wintypes.HANDLE, wintypes.DWORD]
        self.kernel.WaitForSingleObject.restype = wintypes.DWORD
        status = self.kernel.WaitForSingleObject(self.handle, 0xFFFFFFFF if timeout is None else int(timeout * 1000))
        if status == 258:
            raise subprocess.TimeoutExpired("retained Windows test process", timeout)
        if status != 0:
            raise ctypes.WinError(ctypes.get_last_error())
        return self.poll()

    def close(self):
        self.kernel.CloseHandle(self.handle)


def ordinary_exit_evidence(process, stdio_path):
    """Capture bounded diagnostics without masking a missing suite result."""
    code = process.poll()
    facts = {"exit_code": code,
             "exit_code_hex": None if code is None else f"0x{code & 0xFFFFFFFF:08X}",
             "stdio_tail": None}
    try:
        with Path(stdio_path).open("rb") as source:
            source.seek(0, 2)
            source.seek(max(0, source.tell() - 65536))
            facts["stdio_tail"] = source.read(65536).decode("utf-8", errors="replace")
    except OSError as exc:
        facts["stdio_read_error"] = {"type": type(exc).__name__, "errno": exc.errno}
    return facts


def token_user_sid(api, kernel, token):
    api.GetTokenInformation.argtypes = [wintypes.HANDLE, ctypes.c_int, wintypes.LPVOID,
                                       wintypes.DWORD, ctypes.POINTER(wintypes.DWORD)]
    api.ConvertSidToStringSidW.argtypes = [wintypes.LPVOID, ctypes.POINTER(wintypes.LPWSTR)]
    kernel.LocalFree.argtypes = [wintypes.HANDLE]
    kernel.LocalFree.restype = wintypes.HANDLE
    size, text = wintypes.DWORD(), wintypes.LPWSTR()
    api.GetTokenInformation(token, 1, None, 0, ctypes.byref(size))
    if not 1 <= size.value <= 65536:
        raise RuntimeError("Invalid Windows token identity size")
    value = ctypes.create_string_buffer(size.value)
    if not api.GetTokenInformation(token, 1, value, size, ctypes.byref(size)):
        raise ctypes.WinError(ctypes.get_last_error())
    sid = ctypes.cast(value, ctypes.POINTER(wintypes.LPVOID))[0]
    if not api.ConvertSidToStringSidW(sid, ctypes.byref(text)):
        raise ctypes.WinError(ctypes.get_last_error())
    try:
        return text.value
    finally:
        kernel.LocalFree(ctypes.cast(text, wintypes.HANDLE))


def launch_user(command, username, password, expected_sid):
    interactive = os.environ.get("RULEPROXY_TEST_INTERACTIVE_SESSION")
    if interactive is not None:
        helper = module(Path(__file__).with_name("windows_product_interactive_user.py"),
                        "product_interactive_user")
        return helper.launch_user(command, expected_sid, int(interactive), LAB)
    class Startup(ctypes.Structure):
        _fields_ = [("cb", wintypes.DWORD), ("reserved", wintypes.LPWSTR), ("desktop", wintypes.LPWSTR),
            ("title", wintypes.LPWSTR), *[(name, wintypes.DWORD) for name in
            ("x", "y", "xsize", "ysize", "xcount", "ycount", "fill", "flags")],
            ("show", wintypes.WORD), ("reserved_count", wintypes.WORD), ("reserved_data", wintypes.LPVOID),
            ("stdin", wintypes.HANDLE), ("stdout", wintypes.HANDLE), ("stderr", wintypes.HANDLE)]
    class Info(ctypes.Structure):
        _fields_ = [("process", wintypes.HANDLE), ("thread", wintypes.HANDLE),
                    ("pid", wintypes.DWORD), ("tid", wintypes.DWORD)]
    api, kernel = ctypes.WinDLL("advapi32", use_last_error=True), ctypes.WinDLL("kernel32", use_last_error=True)
    kernel.CloseHandle.argtypes = [wintypes.HANDLE]
    kernel.GetExitCodeProcess.argtypes = [wintypes.HANDLE, ctypes.POINTER(wintypes.DWORD)]
    kernel.TerminateProcess.argtypes = [wintypes.HANDLE, wintypes.UINT]
    kernel.GetCurrentProcess.restype = wintypes.HANDLE
    api.OpenProcessToken.argtypes = [wintypes.HANDLE, wintypes.DWORD, ctypes.POINTER(wintypes.HANDLE)]
    caller = wintypes.HANDLE()
    if not api.OpenProcessToken(kernel.GetCurrentProcess(), 8, ctypes.byref(caller)):
        raise ctypes.WinError(ctypes.get_last_error())
    try:
        caller_sid = token_user_sid(api, kernel, caller)
    finally:
        kernel.CloseHandle(caller)
    startup, info = Startup(), Info()
    startup.cb = ctypes.sizeof(startup)
    text = ctypes.create_unicode_buffer(subprocess.list2cmdline([str(item) for item in command]))
    if caller_sid == "S-1-5-18":
        # LocalSystem cannot use WithLogonW. Keep its authenticated token path;
        # the non-SYSTEM Server caller uses the previously exercised logon API.
        api.LogonUserW.argtypes = [wintypes.LPCWSTR, wintypes.LPCWSTR, wintypes.LPCWSTR,
                                  wintypes.DWORD, wintypes.DWORD, ctypes.POINTER(wintypes.HANDLE)]
        api.LogonUserW.restype = wintypes.BOOL
        api.CreateProcessWithTokenW.argtypes = [wintypes.HANDLE, wintypes.DWORD, wintypes.LPCWSTR,
            wintypes.LPWSTR, wintypes.DWORD, wintypes.LPVOID, wintypes.LPCWSTR,
            ctypes.POINTER(Startup), ctypes.POINTER(Info)]
        api.CreateProcessWithTokenW.restype = wintypes.BOOL
        token = wintypes.HANDLE()
        if not api.LogonUserW(username, ".", password, 2, 0, ctypes.byref(token)):
            raise ctypes.WinError(ctypes.get_last_error())
        try:
            if token_user_sid(api, kernel, token) != expected_sid:
                raise RuntimeError("Authenticated actor SID does not match the installation owner")
            if not api.CreateProcessWithTokenW(token, 1, str(command[0]), text, 0x08000000, None,
                                              str(LAB), ctypes.byref(startup), ctypes.byref(info)):
                raise ctypes.WinError(ctypes.get_last_error())
        finally:
            kernel.CloseHandle(token)
        method = "LogonUserW+CreateProcessWithTokenW"
    else:
        api.CreateProcessWithLogonW.argtypes = [wintypes.LPCWSTR, wintypes.LPCWSTR, wintypes.LPCWSTR,
            wintypes.DWORD, wintypes.LPCWSTR, wintypes.LPWSTR, wintypes.DWORD, wintypes.LPVOID,
            wintypes.LPCWSTR, ctypes.POINTER(Startup), ctypes.POINTER(Info)]
        api.CreateProcessWithLogonW.restype = wintypes.BOOL
        if not api.CreateProcessWithLogonW(username, ".", password, 1, str(command[0]), text,
                                          0x08000000, None, str(LAB), ctypes.byref(startup), ctypes.byref(info)):
            raise ctypes.WinError(ctypes.get_last_error())
        method = "CreateProcessWithLogonW"
    actual = wintypes.HANDLE()
    try:
        if not api.OpenProcessToken(info.process, 8, ctypes.byref(actual)):
            raise ctypes.WinError(ctypes.get_last_error())
        if token_user_sid(api, kernel, actual) != expected_sid:
            raise RuntimeError("Created actor SID does not match the installation owner")
    except Exception:
        kernel.TerminateProcess(info.process, 125)
        kernel.CloseHandle(info.process)
        raise
    finally:
        if actual:
            kernel.CloseHandle(actual)
        kernel.CloseHandle(info.thread)
    process = UserProcess(info.process, info.pid, kernel)
    process.launch_method, process.caller_sid = method, caller_sid
    return process


def alive(pid):
    kernel = ctypes.WinDLL("kernel32", use_last_error=True)
    kernel.OpenProcess.argtypes = [wintypes.DWORD, wintypes.BOOL, wintypes.DWORD]
    kernel.OpenProcess.restype = wintypes.HANDLE
    kernel.WaitForSingleObject.argtypes = [wintypes.HANDLE, wintypes.DWORD]
    kernel.CloseHandle.argtypes = [wintypes.HANDLE]
    handle = kernel.OpenProcess(0x100000, False, pid)
    if not handle:
        return False
    try:
        return kernel.WaitForSingleObject(handle, 0) == 258
    finally:
        kernel.CloseHandle(handle)


def process_elevated(pid, *, handle=None):
    kernel = ctypes.WinDLL("kernel32", use_last_error=True)
    api = ctypes.WinDLL("advapi32", use_last_error=True)
    kernel.OpenProcess.argtypes = [wintypes.DWORD, wintypes.BOOL, wintypes.DWORD]
    kernel.OpenProcess.restype = wintypes.HANDLE
    kernel.CloseHandle.argtypes = [wintypes.HANDLE]
    api.OpenProcessToken.argtypes = [wintypes.HANDLE, wintypes.DWORD, ctypes.POINTER(wintypes.HANDLE)]
    api.GetTokenInformation.argtypes = [wintypes.HANDLE, ctypes.c_int, wintypes.LPVOID,
                                       wintypes.DWORD, ctypes.POINTER(wintypes.DWORD)]
    process, token = handle or kernel.OpenProcess(0x1000, False, pid), wintypes.HANDLE()
    if not process:
        raise ctypes.WinError(ctypes.get_last_error())
    try:
        if not api.OpenProcessToken(process, 8, ctypes.byref(token)):
            raise ctypes.WinError(ctypes.get_last_error())
        elevation, size = wintypes.DWORD(), wintypes.DWORD()
        if not api.GetTokenInformation(token, 20, ctypes.byref(elevation), ctypes.sizeof(elevation), ctypes.byref(size)):
            raise ctypes.WinError(ctypes.get_last_error())
        return bool(elevation.value)
    finally:
        if token:
            kernel.CloseHandle(token)
        if handle is None:
            kernel.CloseHandle(process)


def observe_process(pid):
    """Retain the actual process object through a short browser lifetime."""
    kernel = ctypes.WinDLL("kernel32", use_last_error=True)
    kernel.OpenProcess.argtypes = [wintypes.DWORD, wintypes.BOOL, wintypes.DWORD]
    kernel.OpenProcess.restype = wintypes.HANDLE
    kernel.GetExitCodeProcess.argtypes = [wintypes.HANDLE, ctypes.POINTER(wintypes.DWORD)]
    kernel.TerminateProcess.argtypes = [wintypes.HANDLE, wintypes.UINT]
    kernel.CloseHandle.argtypes = [wintypes.HANDLE]
    kernel.QueryFullProcessImageNameW.argtypes = [wintypes.HANDLE, wintypes.DWORD,
        wintypes.LPWSTR, ctypes.POINTER(wintypes.DWORD)]
    handle = kernel.OpenProcess(0x1000 | 0x100000 | 1, False, pid)
    if not handle:
        raise ctypes.WinError(ctypes.get_last_error())
    process = UserProcess(handle, pid, kernel)
    try:
        process.is_elevated = process_elevated(pid, handle=handle)
        buffer, size = ctypes.create_unicode_buffer(32768), wintypes.DWORD(32768)
        if not kernel.QueryFullProcessImageNameW(handle, 0, buffer, ctypes.byref(size)):
            raise ctypes.WinError(ctypes.get_last_error())
        process.image_path = buffer.value
        return process
    except Exception:
        process.close()
        raise


def hold(report, child=False):
    result = {"pid": os.getpid(), "is_elevated": bool(ctypes.windll.shell32.IsUserAnAdmin())}
    if not child:
        helper = LAB / "runtime/helper.exe"
        process = subprocess.Popen([str(helper), "-I", "-S", str(Path(__file__).resolve()),
                                    "--hold", str(Path(report).with_suffix(".child.json")), "--child"])
        result["child_pid"] = process.pid
    write(report, result)
    while True:
        time.sleep(1)


def session_id(pid):
    kernel = ctypes.WinDLL("kernel32", use_last_error=True)
    kernel.ProcessIdToSessionId.argtypes = [wintypes.DWORD, ctypes.POINTER(wintypes.DWORD)]
    kernel.ProcessIdToSessionId.restype = wintypes.BOOL
    value = wintypes.DWORD()
    if not kernel.ProcessIdToSessionId(pid, ctypes.byref(value)):
        raise ctypes.WinError(ctypes.get_last_error())
    return value.value


def listener_pid(port):
    """Resolve the loopback panel through the unprivileged TCP owner table."""
    api = ctypes.WinDLL("iphlpapi", use_last_error=True)
    api.GetExtendedTcpTable.argtypes = [wintypes.LPVOID, ctypes.POINTER(wintypes.DWORD),
                                       wintypes.BOOL, wintypes.ULONG, ctypes.c_int, wintypes.ULONG]
    api.GetExtendedTcpTable.restype = wintypes.DWORD
    size = wintypes.DWORD()
    for _ in range(3):
        buffer = ctypes.create_string_buffer(size.value) if size.value else None
        status = api.GetExtendedTcpTable(buffer, ctypes.byref(size), False, socket.AF_INET, 3, 0)
        if status == 122:
            if not 4 <= size.value <= 2 * 1024**2:
                raise RuntimeError("TCP owner table exceeded the test bound")
            continue
        if status or buffer is None or size.value < 4:
            raise OSError(status, "Cannot inspect the loopback panel owner")
        count = struct.unpack_from("<I", buffer)[0]
        if count * 24 + 4 > min(size.value, len(buffer)):
            raise RuntimeError("Malformed Windows TCP owner table")
        rows = [struct.unpack_from("<IIIIII", buffer, 4 + index * 24) for index in range(count)]
        matches = [row[5] for row in rows if row[0] == 2 and row[1] == 0x0100007F
                   and socket.ntohs(row[2] & 0xFFFF) == port and row[5] > 0]
        if len(matches) != 1:
            raise RuntimeError("No unique ordinary loopback panel owner")
        return matches[0]
    raise RuntimeError("Windows TCP owner table kept changing")


def visible_window(pid):
    """Find and foreground only a visible top-level window of the owned actor."""
    user = ctypes.WinDLL("user32", use_last_error=True)
    callback_type = ctypes.WINFUNCTYPE(wintypes.BOOL, wintypes.HWND, wintypes.LPARAM)
    user.EnumWindows.argtypes = [callback_type, wintypes.LPARAM]
    user.IsWindowVisible.argtypes = [wintypes.HWND]
    user.GetWindowThreadProcessId.argtypes = [wintypes.HWND, ctypes.POINTER(wintypes.DWORD)]
    user.GetWindowRect.argtypes = [wintypes.HWND, ctypes.POINTER(wintypes.RECT)]
    user.GetWindowTextW.argtypes = [wintypes.HWND, wintypes.LPWSTR, ctypes.c_int]
    user.ShowWindow.argtypes = [wintypes.HWND, ctypes.c_int]
    user.SetForegroundWindow.argtypes = [wintypes.HWND]
    user.GetForegroundWindow.restype = wintypes.HWND
    found = []
    @callback_type
    def visit(window, _):
        owner, rectangle = wintypes.DWORD(), wintypes.RECT()
        user.GetWindowThreadProcessId(window, ctypes.byref(owner))
        if owner.value == pid and user.IsWindowVisible(window) and user.GetWindowRect(window, ctypes.byref(rectangle)):
            if rectangle.right - rectangle.left >= 64 and rectangle.bottom - rectangle.top >= 64:
                title = ctypes.create_unicode_buffer(2048)
                user.GetWindowTextW(window, title, len(title))
                found.append((window, title.value))
        return True
    user.EnumWindows(visit, 0)
    for window, title in found:
        user.ShowWindow(window, 9)
        user.SetForegroundWindow(window)
        if user.GetForegroundWindow() == window:
            return {"hwnd": int(window), "pid": pid, "title": title, "visible": True, "foreground": True}
    return None


def capture_visible_desktop(path):
    """Capture the disposable ordinary user's desktop using built-in GDI APIs."""
    observation = powershell(r"""
Add-Type -AssemblyName System.Drawing
Add-Type -AssemblyName System.Windows.Forms
$bounds = [Windows.Forms.Screen]::PrimaryScreen.Bounds
$bitmap = New-Object Drawing.Bitmap($bounds.Width, $bounds.Height)
$graphics = [Drawing.Graphics]::FromImage($bitmap)
try {
    $graphics.CopyFromScreen($bounds.Location, [Drawing.Point]::Empty, $bounds.Size)
    $bitmap.Save($env:RULEPROXY_VISIBLE_SCREENSHOT, [Drawing.Imaging.ImageFormat]::Png)
} finally { $graphics.Dispose(); $bitmap.Dispose() }
""", env={"RULEPROXY_VISIBLE_SCREENSHOT": str(path)})
    if observation["returncode"]:
        raise RuntimeError("Ordinary desktop screenshot failed: " + observation["stderr"])
    if not 33 < path.stat().st_size <= 2 * 1024**2:
        raise RuntimeError("Ordinary desktop screenshot exceeds its evidence bound")
    return {"screenshot_sha256": digest(path), "screenshot_bytes": path.stat().st_size,
            "dimensions": list(png_dimensions(path)),
            "screenshot_png_base64": base64.b64encode(path.read_bytes()).decode("ascii")}


def ordinary_suite(spec_path, result_path):
    spec = json.loads(Path(spec_path).read_text(encoding="ascii"))
    result = {"schema_version": 1, "status": "running", "checks": {}, "phases": [],
              "is_elevated": bool(ctypes.windll.shell32.IsUserAnAdmin()), "panel_runs_ordinary": True,
              "windows_11_verified": False, "gui_verified": False, "real_exit_ip_verified": False,
              "headless_browser_local_checks_passed": False,
              "system_dns_leak_prevention_tested": False}
    panel = None
    token = None
    port = spec["panel_port"]
    url = f"http://127.0.0.1:{port}"
    opener = urllib.request.build_opener(urllib.request.ProxyHandler({}))
    def api(path="/api/state", body=None, *, expected=200, method=None):
        data = None if body is None else json.dumps(body, ensure_ascii=True).encode("ascii")
        headers = {"Content-Type": "application/json", "Origin": url}
        if token:
            headers["X-RuleProxy-Token"] = token
        request = urllib.request.Request(url + path, data=data, headers=headers, method=method)
        try:
            with opener.open(request, timeout=50) as response:
                status, raw = response.status, response.read(2 * 1024**2)
        except urllib.error.HTTPError as exc:
            status, raw = exc.code, exc.read(65536)
        value = json.loads(raw)
        if status != expected:
            raise RuntimeError(f"Web API {path} returned {status}: {value}")
        return value
    def check(name, value):
        result["checks"][name] = bool(value)
        write(result_path, result)
        if not value:
            raise RuntimeError("Product check failed: " + name)
    def action(operation, **fields):
        request_id = secrets.token_hex(8)
        reply = LAB / "actors/admin-reply.json"
        write(LAB / "actors/admin-request.json", {"id": request_id, "op": operation, **fields,
                                                   "panel_pid": panel.pid if panel else None})
        return wait_for(lambda: json.loads(reply.read_text(encoding="ascii"))
                        if reply.is_file() and json.loads(reply.read_text(encoding="ascii")).get("id") == request_id else None)
    def start_panel():
        output = (LAB / "actors/panel-stdio.log").open("ab")
        process = subprocess.Popen([str(INSTALLED / "python/python.exe"), "-I", "-S", "-m", "ruleproxy",
            "--no-browser", "--state-dir", str(LAB / "actors/user-state"), "--port", str(port),
            "--proxy-port", str(spec["proxy_port"]), "--controller-port", str(spec["controller_port"])],
            cwd=INSTALLED, stdout=output, stderr=subprocess.STDOUT)
        output.close()
        try:
            wait_for(lambda: api(), timeout=45)
        except Exception:
            process.terminate()
            process.wait(timeout=10)
            raise
        return process
    def phase(name, exe="selected", node="A", protocol="tcp", connected=False):
        ident = secrets.token_hex(8)
        actor_spec = {"nonce": spec["nonce"], "token": ident, "role": name, "count": 2,
            "target": "1.1.1.1", "protocol": protocol, "family": "ipv4", "connected_udp": connected,
            "udp_ports": [39017] if protocol == "udp" else []}
        source = LAB / "actors" / (ident + ".spec.json")
        output = source.with_suffix(".result.json")
        write(source, actor_spec)
        execution = subprocess.run([str(LAB / "runtime" / (exe + ".exe")), "-I", "-S", str(LAB / "actor.py"),
            "--actor", str(source), "--actor-result", str(output)], capture_output=True, timeout=25)
        value = json.loads(output.read_text(encoding="ascii"))
        rows = value.get("rows", [])
        evidence = {"label": name, "token": ident, "expected_node": node, "actor": value}
        result["phases"].append(evidence)
        check(name, execution.returncode == 0 and value.get("is_elevated") is False and len(rows) == 2 and all(
            row.get("controlled_proxy_response") is True and row.get("node") == node if node else
            not row.get("controlled_proxy_response") and (row.get("connected") or row.get("response_received"))
            for row in rows))
        return evidence
    def launch_holder(app_id):
        report = LAB / "actors/holder.json"
        report.unlink(missing_ok=True)
        value = api("/api/apps/" + app_id + "/launch", {})
        holder = wait_for(lambda: json.loads(report.read_text()) if report.is_file() else None)
        check("holder_ordinary", holder.get("is_elevated") is False and holder["pid"] == value["pid"])
        return holder
    def browser_phase():
        candidates = [Path(os.environ.get(name, r"C:\Program Files")) /
                      "Microsoft/Edge/Application/msedge.exe" for name in ("ProgramFiles(x86)", "ProgramFiles")]
        browser = next((path for path in candidates if path.is_file()), None)
        result["browser"] = {"kind": "Microsoft Edge headless", "required": True,
                             "checked_paths": [str(path) for path in candidates], "visible_gui_verified": False,
                             "real_node_verified": False, "login_cookies_verified": False}
        check("system_edge_available", browser is not None)
        ident = secrets.token_hex(8)
        screenshot = LAB / "actors/edge-page.png"
        screenshot.unlink(missing_ok=True)
        arguments = ["--headless=new", "--disable-gpu", "--screenshot=" + str(screenshot),
            "http://1.1.1.1/ruleproxy-compare/" + spec["nonce"] + "/" + ident]
        state = api("/api/apps", {"label": "Real Microsoft Edge headless", "path": str(browser),
                                  "adapter": "chromium", "args": arguments})
        app = next(app for app in state["apps"] if os.path.normcase(app["path"]) == os.path.normcase(str(browser)))
        launched = api("/api/apps/" + app["id"] + "/launch", {})
        process = observe_process(launched["pid"])
        try:
            result["browser"].update(pid=process.pid, executable=str(browser), executable_sha256=digest(browser),
                actual_image_path=process.image_path, is_elevated=process.is_elevated,
                requested_args=arguments, explicit_proxy_configuration=False, sandbox_disabled=False)
            check("browser_ordinary", process.is_elevated is False)
            check("browser_system_image", os.path.normcase(process.image_path) == os.path.normcase(str(browser)))
            wait_for(lambda: process.poll() is not None, timeout=60)
            check("browser_natural_exit", process.poll() == 0)
            dimensions = png_dimensions(screenshot)
            result["browser"].update(screenshot=str(screenshot), screenshot_sha256=digest(screenshot),
                screenshot_bytes=screenshot.stat().st_size, dimensions=list(dimensions), exit_code=process.poll())
            check("browser_png_created", screenshot.stat().st_size > 33)
            result["phases"].append({"label": "real_edge_headless", "token": ident, "expected_node": "B",
                "actor": {"pid": process.pid, "is_elevated": process.is_elevated, "rows": [
                    {"token": ident, "protocol": "tcp", "application": "Microsoft Edge headless",
                     "response_marker_verification": "independent_receiver_required"}]}})
            result["headless_browser_local_checks_passed"] = True
        finally:
            process.close()
    def visible_browser_phase():
        browser = Path(result["browser"]["executable"])
        previous = next(app for app in api()["apps"] if os.path.normcase(app["path"]) == os.path.normcase(str(browser)))
        api("/api/apps/" + previous["id"], method="DELETE")
        ident = secrets.token_hex(8)
        arguments = ["--new-window", "--window-size=1000,700",
                     "http://1.1.1.1/ruleproxy-compare/" + spec["nonce"] + "/" + ident]
        state = api("/api/apps", {"label": "Real Microsoft Edge visible", "path": str(browser),
                                 "adapter": "chromium", "args": arguments})
        app = next(app for app in state["apps"] if os.path.normcase(app["path"]) == os.path.normcase(str(browser)))
        launched = api("/api/apps/" + app["id"] + "/launch", {})
        process = observe_process(launched["pid"])
        result["browser_visible"] = {"pid": process.pid, "actual_image_path": process.image_path,
            "is_elevated": process.is_elevated, "session_id": session_id(process.pid),
            "requested_args": arguments, "explicit_proxy_configuration": False, "sandbox_disabled": False,
            "real_node_verified": False, "login_cookies_verified": False}
        try:
            check("visible_browser_ordinary", process.is_elevated is False and
                  result["browser_visible"]["session_id"] == spec["interactive_session_id"])
            check("visible_browser_system_image", os.path.normcase(process.image_path) == os.path.normcase(str(browser)))
            window = wait_for(lambda: visible_window(process.pid), timeout=45)
            result["browser_visible"]["window"] = window
            check("visible_browser_window", window["visible"] and window["foreground"])
            check("visible_browser_response", action("wait_visible_receiver", token=ident)["ok"])
            time.sleep(1)
            screenshot = LAB / "actors/visible-edge.png"
            result["browser_visible"].update(capture_visible_desktop(screenshot))
            check("visible_browser_png_created", result["browser_visible"]["screenshot_bytes"] > 33)
            result["phases"].append({"label": "real_edge_visible", "token": ident, "expected_node": "B",
                "actor": {"pid": process.pid, "is_elevated": process.is_elevated, "rows": [
                    {"token": ident, "protocol": "tcp", "application": "Microsoft Edge visible",
                     "response_marker_verification": "independent_receiver_required"}]}})
            api("/api/apps/" + app["id"] + "/stop", {})
            check("visible_browser_job_stop", wait_for(lambda: process.poll() is not None))
            result["visible_gui_local_checks_passed"] = True
            result["gui_verified"] = True
        finally:
            process.close()
    def start_cmd_phase():
        nonlocal token
        command = [str(INSTALLED / "Start-Windows.cmd"), "--no-browser", "--state-dir",
                   str(LAB / "actors/user-state"), "--port", str(port), "--proxy-port", str(spec["proxy_port"]),
                   "--controller-port", str(spec["controller_port"])]
        shell = subprocess.list2cmdline([os.environ["COMSPEC"], "/d", "/s", "/c"])
        entry_log = LAB / "actors/start-cmd-stdio.log"
        execution = run_background_entry(shell + ' "' + subprocess.list2cmdline(command) + '"',
                                         cwd=INSTALLED, log_path=entry_log, timeout=30)
        with entry_log.open("rb") as output:
            output.seek(max(0, entry_log.stat().st_size - 4096))
            entry_output = output.read(4096).decode("utf-8", errors="replace")
        result["start_cmd"] = {"returncode": execution.returncode, "arguments": command,
                               "stdio_log": str(entry_log), "stdio_tail": entry_output}
        check("start_cmd_returned_success", execution.returncode == 0)
        state = wait_for(lambda: api(), timeout=45)
        token = state["token"]
        entry_panel = observe_process(listener_pid(port))
        try:
            result["start_cmd"].update(pid=entry_panel.pid, image_path=entry_panel.image_path,
                                      is_elevated=entry_panel.is_elevated)
            check("start_cmd_panel_ordinary", entry_panel.is_elevated is False and
                  os.path.normcase(entry_panel.image_path) == os.path.normcase(str(INSTALLED / "python/pythonw.exe")))
            check("start_cmd_preserves_import", state["imported"])
            api("/api/start", {})
            phase("start_cmd_saved_node", node="B")
            api("/api/stop", {})
            api("/api/quit", {})
            entry_panel.wait(timeout=10)
        finally:
            if entry_panel.poll() is None:
                entry_panel.terminate()
                entry_panel.wait(timeout=10)
            entry_panel.close()
    try:
        check("suite_ordinary", result["is_elevated"] is False)
        if spec.get("visible_gui_required"):
            result["interactive_session_id"] = session_id(os.getpid())
            check("suite_interactive_session", result["interactive_session_id"] == spec["interactive_session_id"]
                  and result["interactive_session_id"] > 0)
        sys.path.insert(0, str(INSTALLED))
        import ruleproxy
        result["loaded_package"] = str(Path(ruleproxy.__file__).resolve())
        check("installed_package_loaded", Path(ruleproxy.__file__).resolve().parent.parent == INSTALLED)
        result["loaded_manager_sha256"] = digest(INSTALLED / "ruleproxy/manager.py")
        result["native_proxy_environment"] = native_proxy_environment_probe(spec)
        check("native_proxy_environment_ordinary", result["native_proxy_environment"]["passed"])
        panel = start_panel()
        result["panel_pid"] = panel.pid
        result["panel_is_elevated"] = process_elevated(panel.pid)
        check("panel_ordinary", result["panel_is_elevated"] is False)
        state = api()
        token = state["token"]
        check("broker_available", state["protection"]["supported"])
        phase("unselected_before", exe="outside", node=None)
        api("/api/import", {"yaml": spec["yaml"]})
        selected = {"label": "Raw socket selected application", "path": str(LAB / "runtime/selected.exe"),
            "adapter": "environment", "args": [str(Path(__file__).resolve()), "--hold", str(LAB / "actors/holder.json")]}
        api("/api/apps", selected)
        state = api()
        selected_id = state["apps"][0]["id"]
        api("/api/start", {})
        phase("selected_raw_tcp")
        phase("same_path_second_instance")
        phase("selected_udp_39017", protocol="udp")
        phase("selected_udp_connected_39017", protocol="udp", connected=True)
        phase("different_helper_before", exe="helper", node=None)
        api("/api/apps/" + selected_id, method="DELETE")
        selected["related_paths"] = [str(LAB / "runtime/helper.exe")]
        state = api("/api/apps", selected)
        selected_id = state["apps"][0]["id"]
        check("related_paths_saved", state["apps"][0].get("related_paths") == selected["related_paths"])
        phase("explicit_helper_after", exe="helper")
        api("/api/node", {"name": "B"})
        phase("selected_node_b", node="B")
        phase("related_helper_node_b", exe="helper", node="B")
        phase("unselected_with_rules", exe="outside", node=None)
        api("/api/apps/" + selected_id, {"enabled": False})
        phase("disabled_path_direct", node=None)
        phase("disabled_helper_direct", exe="helper", node=None)
        api("/api/apps/" + selected_id, {"enabled": True})
        phase("reenabled_path_proxy", node="B")
        phase("reenabled_helper_proxy", exe="helper", node="B")
        holder = launch_holder(selected_id)
        api("/api/stop", {})
        check("stop_closes_owned_job", wait_for(lambda: not alive(holder["pid"]) and not alive(holder["child_pid"])))
        api("/api/start", {})
        holder = launch_holder(selected_id)
        check("kill_core_admin_action", action("kill_core")["ok"])
        check("core_loss_closes_owned_job", wait_for(lambda: not alive(holder["pid"]) and not alive(holder["child_pid"])))
        wait_for(lambda: not api()["running"])
        check("stop_broker_admin_action", action("stop_broker")["ok"])
        report_file = LAB / "actors/holder.json"
        report_file.unlink(missing_ok=True)
        failed_start = api("/api/start", {}, expected=400)
        value = api("/api/apps/" + selected_id + "/launch", {}, expected=400)
        check("service_failure_does_not_launch_app", bool(failed_start.get("error")) and
              bool(value.get("error")) and not report_file.exists() and not api()["running"])
        check("restart_broker_admin_action", action("start_broker")["ok"])
        api("/api/start", {})
        holder = launch_holder(selected_id)
        check("capture_core_before_crash", action("capture_core")["ok"])
        panel.kill()
        panel.wait(timeout=10)
        check("panel_crash_closes_owned_job", wait_for(lambda: not alive(holder["pid"]) and not alive(holder["child_pid"])))
        check("panel_crash_stops_engine", action("wait_engine_stopped")["ok"])
        check("panel_crash_closes_owned_core", action("wait_core_stopped")["ok"])
        panel = start_panel()
        state = api()
        token = state["token"]
        check("saved_state_preserved", state["imported"] and len(state["apps"]) == 1 and
              state["apps"][0].get("related_paths") == selected["related_paths"])
        api("/api/start", {})
        phase("restart_saved_node", node="B")
        browser_phase()
        if spec.get("visible_gui_required"):
            visible_browser_phase()
        api("/api/stop", {})
        api("/api/quit", {})
        panel.wait(timeout=10)
        start_cmd_phase()
        result["user_state_hashes"] = {name: digest(LAB / "actors/user-state" / name)
                                        for name in ("settings.json", "source.yaml")}
        result["status"] = "passed"
    except Exception as exc:
        result.update(status="failed", error=str(exc), traceback=traceback.format_exc()[-12000:])
    finally:
        if panel is not None and panel.poll() is None:
            try:
                panel.terminate()
                panel.wait(timeout=10)
            except Exception as exc:
                result["panel_cleanup_error"] = str(exc)
        write(result_path, result)
    return 0 if result["status"] == "passed" else 1


def controller(package_dir, output):
    output = Path(output).resolve()
    output.mkdir(parents=True, exist_ok=True)
    report = {"schema_version": 1, "status": "running", "qualification_scope": "Windows installed product from final offline ZIP; see actual_os",
        "windows_11_verified": False, "gui_verified": False, "product_release_eligible": False,
        "headless_browser_verified": False,
        "checks": {}, "installations": [], "actions": []}
    report_path = output / "product-report.json"
    hosts_path = Path(os.environ["SystemRoot"]) / "System32/drivers/etc/hosts"
    hosts_before = None
    fixture = process = None
    username = os.environ.pop("RULEPROXY_TEST_USER")
    password = os.environ.pop("RULEPROXY_TEST_PASSWORD")
    owner = os.environ.pop("RULEPROXY_TEST_SID")
    interactive = os.environ.get("RULEPROXY_TEST_INTERACTIVE_SESSION")
    interactive_session = int(interactive) if interactive is not None else None
    def checkpoint():
        write(report_path, report)
    try:
        if os.name != "nt" or not ctypes.windll.shell32.IsUserAnAdmin():
            raise RuntimeError("Disposable Windows administrator controller required")
        version = sys.getwindowsversion()
        report["actual_os"] = {"major": version.major, "minor": version.minor,
            "build": version.build, "platform": version.platform, "product_type": version.product_type,
            "architecture": platform.machine()}
        if interactive_session is not None and (interactive_session <= 0 or version.product_type != 1
                                                or platform.machine() != "AMD64"):
            raise RuntimeError("Interactive product qualification requires a Windows client x64 desktop")
        if LAB.exists():
            raise RuntimeError("Disposable product lab already exists")
        (LAB / "actors").mkdir(parents=True)
        for path, grant in ((LAB, '*S-1-5-32-545:(OI)(CI)(RX)'), (LAB / "actors", '*S-1-5-32-545:(OI)(CI)(M)')):
            cmd = ["icacls.exe", str(path), "/grant", grant]
            subprocess.run(cmd, capture_output=True, check=True)
        bundle, report["package"] = unpack_package(package_dir, LAB / "bundle")
        source_root = Path(__file__).resolve().parent.parent
        compared = ["manager.py", "server.py", "launcher.py", "windows_proxy_service.py", "windows_proxy_policy.py",
                    "windows_proxy_client.py", "windows_proxy_runtime.py", "windows_proxy_pins.py",
                    "windows_app_process.py", "windows_core_process.py"]
        report["source_matches_bundle"] = {name: digest(source_root / "ruleproxy" / name) == digest(bundle / "ruleproxy" / name)
                                             for name in compared}
        if not all(report["source_matches_bundle"].values()):
            raise RuntimeError("Source and final package implementations differ")
        proxy_helper = source_root / "tests/test_windows_native_proxy.py"
        proxy_helper_digest = digest(proxy_helper)
        shutil.copyfile(proxy_helper, LAB / "native-proxy-probe.py")
        if digest(LAB / "native-proxy-probe.py") != proxy_helper_digest:
            raise RuntimeError("Native proxy fixture copy differs from the checkout")
        report["native_proxy_fixture"] = {"source": "tests/test_windows_native_proxy.py",
                                          "sha256": proxy_helper_digest, "copy_verified": True}
        for iteration in range(2):
            install = execute_script(bundle / "scripts/windows-setup.ps1", owner, bundle)
            report["installations"].append(install)
            checkpoint()
            if install["returncode"] in (1641, 3010):
                report["reboot_required"] = True
                raise RuntimeError("Installer requested reboot; this run cannot qualify an unrebooted product")
            if install["returncode"]:
                raise RuntimeError("Product installation failed; see captured PowerShell and SCM diagnostics")
        report["checks"]["install_and_reinstall"] = True
        deployment = json.loads((INSTALLED / "deployment.json").read_text(encoding="utf-8-sig"))
        report["installed_deployment"] = {key: deployment[key] for key in
            ("schema_version", "owner_sid", "root", "proxifyre_root", "service_name", "pipe_name")}
        report["installed_file_hashes"] = {name: digest(INSTALLED / "ruleproxy" / name) for name in compared}
        if any(value != digest(bundle / "ruleproxy" / name) for name, value in report["installed_file_hashes"].items()):
            raise RuntimeError("Installed implementation differs from final ZIP")
        report["installed_services"] = powershell("Get-CimInstance Win32_Service|Where-Object {$_.Name -in @('RuleProxyControl','ProxiFyreService')}|Select-Object Name,State,StartMode,StartName,PathName|ConvertTo-Json -Compress")
        shared_body = "$vc=Get-ItemProperty 'HKLM:\\SOFTWARE\\Microsoft\\VisualStudio\\14.0\\VC\\Runtimes\\x64'; [ordered]@{driver_sha256=(Get-FileHash (Join-Path $env:SystemRoot 'System32\\drivers\\ndisrd.sys')).Hash; driver_signature=[string](Get-AuthenticodeSignature (Join-Path $env:SystemRoot 'System32\\drivers\\ndisrd.sys')).Status; vc_installed=$vc.Installed; vc_version=$vc.Version}|ConvertTo-Json -Compress"
        shared_before = powershell(shared_body)
        report["shared_dependencies_before"] = shared_before
        if shared_before["returncode"] or json.loads(shared_before["stdout"])["driver_signature"] != "Valid":
            raise RuntimeError("Installed signed shared dependencies could not be verified")
        report["installed_firewall_rules"] = powershell("Get-NetFirewallApplicationFilter -Program (Join-Path $env:ProgramFiles 'ProxiFyre\\ProxiFyre.exe') -ErrorAction SilentlyContinue|Get-NetFirewallRule|Select-Object Name,DisplayName,Enabled,Direction,Action|ConvertTo-Json -Compress")
        shutil.copytree(bundle / "python", LAB / "runtime")
        for name in ("selected", "helper", "outside"):
            shutil.copyfile(LAB / "runtime/python.exe", LAB / "runtime" / (name + ".exe"))
        shutil.copyfile(__file__, LAB / "acceptance.py")
        shutil.copyfile(Path(__file__).with_name("windows_proxy_compare.py"), LAB / "actor.py")
        fixture_module = module(Path(__file__).with_name("windows_proxy_compare_fixture.py"), "product_fixture")
        fixture = fixture_module.Fixture(INSTALLED / "bin/windows-amd64/mihomo.exe", output / "fixture")
        fixture.__enter__()
        report["fixture"] = fixture.facts()
        # The health-only core is separate from the product. Keep its receiver
        # listeners, but release the executable before product uninstall.
        report["fixture_health_core_stopped"] = fixture.stop_proxy()
        hosts_before = hosts_path.read_bytes()
        # Production deliberately ignores system hosts. Use a real DNS name
        # for these local synthetic upstreams, without changing product policy.
        hostname = "node-" + fixture.nonce + ".127.0.0.1.sslip.io"
        addresses = sorted({row[4][0] for row in socket.getaddrinfo(
            hostname, None, socket.AF_INET, socket.SOCK_STREAM)})
        report["fixture_dns"] = {"hostname": hostname, "resolved_ipv4": addresses,
            "expected_ipv4": "127.0.0.1", "third_party_dns_test_dependency": "sslip.io",
            "production_dependency": False, "hosts_modified": False,
            "hosts_before_sha256": hashlib.sha256(hosts_before).hexdigest()}
        checkpoint()
        if addresses != ["127.0.0.1"]:
            raise RuntimeError("Synthetic fixture DNS did not resolve exclusively to 127.0.0.1")
        proxies = [{"name": node, "type": "socks5", "server": hostname,
                    "port": fixture._listeners[node].getsockname()[1], "udp": True} for node in ("A", "B")]
        spec = {"nonce": fixture.nonce, "panel_port": 28879, "proxy_port": 20809, "controller_port": 29097,
                "owner_sid": owner, "native_proxy_fixture_sha256": proxy_helper_digest,
                "visible_gui_required": interactive_session is not None,
                "interactive_session_id": interactive_session,
                "yaml": json.dumps({"proxies": proxies, "proxy-groups": [{"name": "Select", "type": "select", "proxies": ["A", "B"]}],
                                     "rules": ["MATCH,Select"]})}
        spec_path, user_result = LAB / "suite-spec.json", LAB / "actors/user-suite.json"
        write(spec_path, spec)
        process = launch_user([INSTALLED / "python/python.exe", "-I", "-S", LAB / "acceptance.py",
                               "--ordinary-suite", spec_path, "--result", user_result], username, password, owner)
        report["ordinary_launcher"] = {"method": process.launch_method, "caller_sid": process.caller_sid,
                                        "expected_actor_sid": owner, "actual_actor_sid_verified": True}
        if interactive_session is not None:
            report["ordinary_launcher"]["session_id"] = process.session_id
        deadline = time.monotonic() + 900
        last_action = None
        captured_core = None
        while process.poll() is None and time.monotonic() < deadline:
            request_path = LAB / "actors/admin-request.json"
            if request_path.is_file():
                request = json.loads(request_path.read_text(encoding="ascii"))
                if request["id"] != last_action:
                    operation = request["op"]
                    actions = {"stop_broker": "Stop-Service RuleProxyControl; 'ok'",
                        "start_broker": "Start-Service RuleProxyControl; (Get-Service RuleProxyControl).WaitForStatus('Running',[TimeSpan]::FromSeconds(30)); 'ok'",
                        "wait_engine_stopped": "(Get-Service ProxiFyreService).WaitForStatus('Stopped',[TimeSpan]::FromSeconds(20)); 'ok'",
                        "capture_core": "$p=@(Get-CimInstance Win32_Process -Filter \"Name='mihomo.exe'\"|Where-Object {$_.ParentProcessId -eq [int]$env:RULEPROXY_PRODUCT_PANEL}); if($p.Count -ne 1){throw 'No unique owned product core'}; $p[0].ProcessId",
                        "wait_core_stopped": "$p=Get-Process -Id ([int]$env:RULEPROXY_PRODUCT_CORE) -ErrorAction SilentlyContinue; if($p){if(-not $p.WaitForExit(20000)){throw 'Owned core survived panel crash'}}; 'ok'",
                        "kill_core": "$p=@(Get-CimInstance Win32_Process -Filter \"Name='mihomo.exe'\"|Where-Object {$_.ParentProcessId -eq [int]$env:RULEPROXY_PRODUCT_PANEL}); if($p.Count -ne 1){throw 'No unique owned product core'}; Stop-Process -Id $p[0].ProcessId -Force; 'ok'"}
                    if operation == "wait_visible_receiver":
                        marker = request.get("token", "")
                        if not isinstance(marker, str) or len(marker) != 16 or any(
                                char not in "0123456789abcdef" for char in marker):
                            raise RuntimeError("Invalid visible-browser actor marker")
                        phase = {"label": "real_edge_visible", "token": marker,
                                 "expected_node": "B", "actor": {"rows": [{}]}}
                        evidence = wait_for(lambda: next((row for row in receiver_evidence(
                            [phase], fixture.snapshot()) if row["passed"]), None), timeout=20)
                        observation = {"returncode": 0, "stdout": json.dumps(evidence), "stderr": ""}
                    elif operation not in actions:
                        raise RuntimeError("Invalid bounded administrator test operation")
                    else:
                        observation = powershell(actions[operation], env={"RULEPROXY_PRODUCT_PANEL": str(request["panel_pid"]),
                                                                          "RULEPROXY_PRODUCT_CORE": str(captured_core or 0)})
                    if operation == "capture_core" and observation["returncode"] == 0:
                        captured_core = int(observation["stdout"].strip())
                    if operation == "wait_core_stopped" and captured_core is None:
                        observation = {"returncode": 1, "stdout": "", "stderr": "No captured owned core identity"}
                    report["actions"].append({"op": operation, **observation})
                    write(LAB / "actors/admin-reply.json", {"id": request["id"], "ok": observation["returncode"] == 0})
                    last_action = request["id"]
            if user_result.is_file():
                report["ordinary_suite"] = json.loads(user_result.read_text(encoding="ascii"))
            checkpoint()
            time.sleep(.5)
        if process.poll() is None:
            process.terminate()
            raise TimeoutError("Ordinary product suite exceeded 15 minutes")
        report["ordinary_process"] = ordinary_exit_evidence(process, LAB / "actors/ordinary-stdio.log")
        report["ordinary_process"]["suite_result_exists"] = user_result.is_file()
        if not report["ordinary_process"]["suite_result_exists"]:
            report["ordinary_process"]["failure_stage"] = "exited_before_suite_result"
        checkpoint()
        report["ordinary_suite"] = json.loads(user_result.read_text(encoding="ascii"))
        report["receiver_final"] = fixture.snapshot()
        proxy_evidence = report["ordinary_suite"].get("native_proxy_environment", {})
        report["native_proxy_environment_verified"] = (proxy_evidence.get("passed") is True
            and proxy_evidence.get("fixture_sha256") == proxy_helper_digest
            and native_proxy_receipt_valid(proxy_evidence.get("receipt"), owner, INSTALLED)
            and proxy_evidence["receipt"]["parent_token"]["pid"] == process.pid)
        if not report["native_proxy_environment_verified"]:
            raise RuntimeError("Ordinary installed launcher lacks independent explicit-proxy environment evidence")
        if process.poll() != 0 or report["ordinary_suite"]["status"] != "passed":
            raise RuntimeError("Installed ordinary-user product suite failed")
        report["receiver_phase_evidence"] = receiver_evidence(report["ordinary_suite"]["phases"], report["receiver_final"])
        if not report["receiver_phase_evidence"] or not all(row["passed"] for row in report["receiver_phase_evidence"]):
            raise RuntimeError("Transparent actor markers lack matching independent receiver evidence")
        if (report["ordinary_suite"].get("headless_browser_local_checks_passed") is not True or not any(
                row["label"] == "real_edge_headless" and row["passed"] for row in report["receiver_phase_evidence"])):
            raise RuntimeError("Required real browser lacks PNG/token/independent receiver evidence")
        report["headless_browser_verified"] = True
        if interactive_session is not None:
            if (report["ordinary_suite"].get("visible_gui_local_checks_passed") is not True
                    or report["ordinary_suite"].get("interactive_session_id") != interactive_session
                    or not any(row["label"] == "real_edge_visible" and row["passed"]
                               for row in report["receiver_phase_evidence"])):
                raise RuntimeError("Required interactive browser lacks visible-window/receiver evidence")
            report["gui_verified"] = True
        report["uninstall"] = execute_script(INSTALLED / "scripts/windows-uninstall.ps1", owner)
        if report["uninstall"]["returncode"]:
            raise RuntimeError("Product uninstall failed or requested an unverified reboot")
        for name, expected in report["ordinary_suite"]["user_state_hashes"].items():
            if digest(LAB / "actors/user-state" / name) != expected:
                raise RuntimeError("Uninstall changed user state")
        post = powershell("[ordered]@{control=@(Get-Service RuleProxyControl -ErrorAction SilentlyContinue).Count; "
            "engine=@(Get-Service ProxiFyreService -ErrorAction SilentlyContinue).Count; "
            "driver=@(Get-Service NDISRD -ErrorAction SilentlyContinue).Count; "
            "firewall=@(Get-NetFirewallApplicationFilter -Program (Join-Path $env:ProgramFiles 'ProxiFyre\\ProxiFyre.exe') -ErrorAction SilentlyContinue|Get-NetFirewallRule).Count} | ConvertTo-Json -Compress")
        report["uninstall_inspection"] = post
        observed = json.loads(post["stdout"])
        if observed != {"control": 0, "engine": 0, "driver": 1, "firewall": 0} or INSTALLED.exists():
            raise RuntimeError("Owned uninstall cleanup/shared-driver preservation failed")
        shared_after = powershell(shared_body)
        report["shared_dependencies_after"] = shared_after
        if shared_after["returncode"] or json.loads(shared_before["stdout"]) != json.loads(shared_after["stdout"]):
            raise RuntimeError("Uninstall changed signed shared NDIS/VC dependencies")
        report["checks"]["uninstall_preserves_user_state_and_shared_driver"] = True
        report["post_uninstall_reinstall"] = execute_script(bundle / "scripts/windows-setup.ps1", owner, bundle)
        if report["post_uninstall_reinstall"]["returncode"]:
            raise RuntimeError("Fresh reinstall after owned uninstall failed")
        report["post_reinstall_uninstall"] = execute_script(INSTALLED / "scripts/windows-uninstall.ps1", owner)
        if report["post_reinstall_uninstall"]["returncode"] or INSTALLED.exists():
            raise RuntimeError("Repeated uninstall after fresh reinstall failed")
        report["checks"]["uninstall_then_fresh_reinstall"] = True
        client_windows = (report["actual_os"]["product_type"] == 1
                          and report["actual_os"]["build"] >= 22000
                          and report["actual_os"]["architecture"] == "AMD64")
        report["windows_11_verified"] = client_windows
        report["status"] = ("passed_windows_11_product_qualification" if client_windows
                            else "passed_server_product_qualification")
    except Exception as exc:
        report.update(status="failed_or_incomplete", error=str(exc), traceback=traceback.format_exc()[-16000:])
    finally:
        if process is not None:
            try:
                process.terminate()
                process.close()
            except OSError:
                pass
        if fixture is not None:
            try:
                report["receiver_final"] = fixture.snapshot()
                fixture.close()
            except Exception as exc:
                report["fixture_cleanup_error"] = str(exc)
                report["status"] = "failed_or_incomplete"
        if hosts_before is not None:
            try:
                # No hosts changes were made. Preserve the existing byte/hash
                # evidence without rewriting a host setting for this fixture.
                report["hosts_modified"] = False
                report["hosts_restored"] = hosts_path.read_bytes() == hosts_before
                report["hosts_restored_sha256"] = digest(hosts_path)
            except Exception as exc:
                report["hosts_restored"] = False
                report["hosts_restore_error"] = str(exc)
        try:
            report["diagnostics"] = powershell("[ordered]@{services=@(Get-CimInstance Win32_Service|Where-Object {$_.Name -in @('RuleProxyControl','ProxiFyreService')}|Select-Object Name,State,ExitCode,PathName); "
                "events=@(Get-WinEvent -FilterHashtable @{LogName='System';ProviderName='Service Control Manager';StartTime=(Get-Date).AddMinutes(-45)} -ErrorAction SilentlyContinue|Select-Object -First 20 TimeCreated,Id,Message)}|ConvertTo-Json -Depth 6 -Compress")
        except Exception as exc:
            report["diagnostics_error"] = str(exc)
        for source in (LAB / "actors", Path(os.environ["ProgramData"]) / "RuleProxy-Web"):
            try:
                if source.is_dir():
                    shutil.copytree(source, output / source.name, dirs_exist_ok=True)
            except OSError as exc:
                report.setdefault("artifact_copy_errors", []).append(str(exc))
        checkpoint()
    return 0 if report["status"] in {"passed_server_product_qualification", "passed_windows_11_product_qualification"} and report.get("hosts_restored") else 1


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--package-dir", type=Path)
    parser.add_argument("--output", type=Path)
    parser.add_argument("--ordinary-suite", type=Path)
    parser.add_argument("--result", type=Path)
    parser.add_argument("--hold", type=Path)
    parser.add_argument("--child", action="store_true")
    args = parser.parse_args()
    if args.hold:
        hold(args.hold, args.child)
    if args.ordinary_suite:
        return ordinary_suite(args.ordinary_suite, args.result)
    if not args.package_dir or args.output is None:
        parser.error("package-dir and output are required")
    return controller(args.package_dir, args.output)


if __name__ == "__main__":
    raise SystemExit(main())
