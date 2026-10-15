"""Exercise the installed offline Windows product in a disposable VM.

This is Server product qualification, never a Windows 11 or real-exit-IP claim.
Ordinary actors use destination sockets; fixture SOCKS handshakes are health only.
"""
from __future__ import annotations

import argparse
import ctypes
from ctypes import wintypes
import hashlib
import importlib.util
import json
import os
import platform
from pathlib import Path, PurePosixPath
import secrets
import shutil
import struct
import subprocess
import sys
import time
import traceback
import urllib.error
import urllib.request
import zipfile

LAB = Path(r"C:\RuleProxyProduct")
INSTALLED = Path(os.environ.get("ProgramFiles", r"C:\Program Files")) / "RuleProxy-Web"


def write(path, value):
    path = Path(path)
    path.parent.mkdir(parents=True, exist_ok=True)
    temporary = path.with_suffix(path.suffix + ".tmp")
    temporary.write_text(json.dumps(value, ensure_ascii=True, indent=2) + "\n", encoding="ascii")
    os.replace(temporary, path)


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


class UserProcess:
    def __init__(self, handle, pid, kernel):
        self.handle, self.pid, self.kernel = handle, pid, kernel

    def poll(self):
        code = wintypes.DWORD()
        if not self.kernel.GetExitCodeProcess(self.handle, ctypes.byref(code)):
            raise ctypes.WinError(ctypes.get_last_error())
        return None if code.value == 259 else code.value

    def terminate(self):
        if self.poll() is None:
            self.kernel.TerminateProcess(self.handle, 125)

    def close(self):
        self.kernel.CloseHandle(self.handle)


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
    api.CreateProcessWithLogonW.argtypes = [wintypes.LPCWSTR, wintypes.LPCWSTR, wintypes.LPCWSTR,
        wintypes.DWORD, wintypes.LPCWSTR, wintypes.LPWSTR, wintypes.DWORD, wintypes.LPVOID,
        wintypes.LPCWSTR, ctypes.POINTER(Startup), ctypes.POINTER(Info)]
    api.CreateProcessWithLogonW.restype = wintypes.BOOL
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
        # LocalSystem has no logon SID and cannot use WithLogonW. Authenticate
        # the same ordinary account and launch its primary token with a profile.
        # https://learn.microsoft.com/windows/win32/api/winbase/nf-winbase-createprocesswithtokenw
        api.LogonUserW.argtypes = [wintypes.LPCWSTR, wintypes.LPCWSTR, wintypes.LPCWSTR,
                                  wintypes.DWORD, wintypes.DWORD, ctypes.POINTER(wintypes.HANDLE)]
        api.CreateProcessWithTokenW.argtypes = [wintypes.HANDLE, wintypes.DWORD, wintypes.LPCWSTR,
            wintypes.LPWSTR, wintypes.DWORD, wintypes.LPVOID, wintypes.LPCWSTR,
            ctypes.POINTER(Startup), ctypes.POINTER(Info)]
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
    handle = kernel.OpenProcess(0x1000 | 0x100000, False, pid)
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
    def api(path="/api/state", body=None, *, expected=200):
        data = None if body is None else json.dumps(body, ensure_ascii=True).encode("ascii")
        headers = {"Content-Type": "application/json", "Origin": url}
        if token:
            headers["X-RuleProxy-Token"] = token
        request = urllib.request.Request(url + path, data=data, headers=headers)
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
    def action(operation):
        request_id = secrets.token_hex(8)
        reply = LAB / "actors/admin-reply.json"
        write(LAB / "actors/admin-request.json", {"id": request_id, "op": operation,
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
    try:
        check("suite_ordinary", result["is_elevated"] is False)
        sys.path.insert(0, str(INSTALLED))
        import ruleproxy
        result["loaded_package"] = str(Path(ruleproxy.__file__).resolve())
        check("installed_package_loaded", Path(ruleproxy.__file__).resolve().parent.parent == INSTALLED)
        result["loaded_manager_sha256"] = digest(INSTALLED / "ruleproxy/manager.py")
        panel = start_panel()
        result["panel_pid"] = panel.pid
        result["panel_is_elevated"] = process_elevated(panel.pid)
        check("panel_ordinary", result["panel_is_elevated"] is False)
        state = api()
        token = state["token"]
        check("broker_available", state["protection"]["supported"])
        phase("unselected_before", exe="outside", node=None)
        api("/api/import", {"yaml": spec["yaml"]})
        api("/api/apps", {"label": "Raw socket selected application", "path": str(LAB / "runtime/selected.exe"),
            "adapter": "environment", "args": [str(Path(__file__).resolve()), "--hold", str(LAB / "actors/holder.json")]})
        state = api()
        selected_id = state["apps"][0]["id"]
        api("/api/start", {})
        phase("selected_raw_tcp")
        phase("same_path_second_instance")
        phase("selected_udp_39017", protocol="udp")
        phase("selected_udp_connected_39017", protocol="udp", connected=True)
        phase("different_helper_before", exe="helper", node=None)
        api("/api/apps", {"label": "Explicit related helper", "path": str(LAB / "runtime/helper.exe"),
                           "adapter": "environment", "args": []})
        phase("explicit_helper_after", exe="helper")
        api("/api/node", {"name": "B"})
        phase("selected_node_b", node="B")
        phase("unselected_with_rules", exe="outside", node=None)
        api("/api/apps/" + selected_id, {"enabled": False})
        phase("disabled_path_direct", node=None)
        api("/api/apps/" + selected_id, {"enabled": True})
        phase("reenabled_path_proxy", node="B")
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
        check("saved_state_preserved", state["imported"] and len(state["apps"]) == 2)
        api("/api/start", {})
        phase("restart_saved_node", node="B")
        browser_phase()
        api("/api/stop", {})
        api("/api/quit", {})
        panel.wait(timeout=10)
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
    report = {"schema_version": 1, "status": "running", "qualification_scope": "Windows Server 2025 final offline ZIP",
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
    def checkpoint():
        write(report_path, report)
    try:
        if os.name != "nt" or not ctypes.windll.shell32.IsUserAnAdmin():
            raise RuntimeError("Disposable Windows administrator controller required")
        version = sys.getwindowsversion()
        report["actual_os"] = {"major": version.major, "minor": version.minor,
            "build": version.build, "platform": version.platform, "product_type": version.product_type,
            "architecture": platform.machine()}
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
        hostname = "node-" + fixture.nonce + ".example.com"
        hosts_before = hosts_path.read_bytes()
        hosts_path.write_bytes(hosts_before + ("\r\n127.0.0.1 " + hostname + "\r\n").encode("ascii"))
        report["fixture_hosts_mapping"] = {"hostname": hostname, "address": "127.0.0.1",
                                            "before_sha256": hashlib.sha256(hosts_before).hexdigest()}
        proxies = [{"name": node, "type": "socks5", "server": hostname,
                    "port": fixture._listeners[node].getsockname()[1], "udp": True} for node in ("A", "B")]
        spec = {"nonce": fixture.nonce, "panel_port": 28879, "proxy_port": 20809, "controller_port": 29097,
                "yaml": json.dumps({"proxies": proxies, "proxy-groups": [{"name": "Select", "type": "select", "proxies": ["A", "B"]}],
                                     "rules": ["MATCH,Select"]})}
        spec_path, user_result = LAB / "suite-spec.json", LAB / "actors/user-suite.json"
        write(spec_path, spec)
        process = launch_user([INSTALLED / "python/python.exe", "-I", "-S", LAB / "acceptance.py",
                               "--ordinary-suite", spec_path, "--result", user_result], username, password, owner)
        report["ordinary_launcher"] = {"method": process.launch_method, "caller_sid": process.caller_sid,
                                        "expected_actor_sid": owner, "actual_actor_sid_verified": True}
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
                    if operation not in actions:
                        raise RuntimeError("Invalid bounded administrator test operation")
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
        report["ordinary_suite"] = json.loads(user_result.read_text(encoding="ascii"))
        report["receiver_final"] = fixture.snapshot()
        if process.poll() != 0 or report["ordinary_suite"]["status"] != "passed":
            raise RuntimeError("Installed ordinary-user product suite failed")
        report["receiver_phase_evidence"] = receiver_evidence(report["ordinary_suite"]["phases"], report["receiver_final"])
        if not report["receiver_phase_evidence"] or not all(row["passed"] for row in report["receiver_phase_evidence"]):
            raise RuntimeError("Transparent actor markers lack matching independent receiver evidence")
        if (report["ordinary_suite"].get("headless_browser_local_checks_passed") is not True or not any(
                row["label"] == "real_edge_headless" and row["passed"] for row in report["receiver_phase_evidence"])):
            raise RuntimeError("Required real browser lacks PNG/token/independent receiver evidence")
        report["headless_browser_verified"] = True
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
        report["status"] = "passed_server_product_qualification"
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
        if hosts_before is not None:
            try:
                hosts_path.write_bytes(hosts_before)
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
    return 0 if report["status"] == "passed_server_product_qualification" and report.get("hosts_restored") else 1


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
