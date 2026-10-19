"""Disposable CI only: fixed MXC Model 2 with a default-network control.

Run as SYSTEM with --disposable-ci --executor EXE --manifest JSON --work NEW_DIR
--report JSON [--browser CHROMIUM_EXE]. The executor and manifest must match the
existing G bundle pins. G's guarded Model-1 patch does not apply to Model 2.

Run a default-compartment baseline first, then the pre-bound compartment case.
The ordinary-user launcher and wxc-exec inherit an outer Job with no UI limits.
The existing MXC executor creates the PSEC environment and its own nested Job.
Only fixed HTTP fixture content is served; no external destination is dialed.
An optional browser renders that content with its native sandbox enabled.
This is a functionality experiment, not DNS/IPC/privacy qualification. It does
not change production settings, host networking, or any pre-existing ACL.
"""
from __future__ import annotations

import argparse
import ctypes as C
from ctypes import wintypes as W
import hashlib
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
import json
import os
from pathlib import Path
import platform
import re
import secrets
import shutil
import socket
import subprocess
import sys
import threading
import time
import uuid

ROOT = Path(__file__).resolve().parent.parent
HOST = "ruleproxy-psec-smoke.invalid"
MAX_JSON = 128 * 1024


def save(path, value):
    path = Path(path)
    data = json.dumps(value, ensure_ascii=True, indent=2).encode("ascii")
    if len(data) > MAX_JSON:
        raise ValueError("smoke report exceeded its size bound")
    temporary = path.with_suffix(".tmp")
    temporary.write_bytes(data)
    os.replace(temporary, path)


def read(path):
    with Path(path).open("rb") as stream:
        data = stream.read(MAX_JSON + 1)
    if len(data) > MAX_JSON:
        raise ValueError("smoke JSON exceeded its size bound")
    value = json.loads(data)
    if not isinstance(value, dict):
        raise ValueError("smoke JSON must be an object")
    return value


def failure(exc):
    return {"type": type(exc).__name__, "winerror": getattr(exc, "winerror", None),
            "errno": getattr(exc, "errno", None), "detail": str(exc)[:600]}


def verify_executor(executor, manifest):
    # This path deliberately accepts only the already pinned G artifact. It
    # does not install/download/rebuild MXC or accept a manifest's own new pin.
    sys.path.insert(0, str(ROOT))
    from ruleproxy import windows_runtime_pins as pins
    executor, manifest = Path(executor).resolve(strict=True), Path(manifest).resolve(strict=True)
    if executor.suffix.casefold() != ".exe" or executor.stat().st_size > 32 * 1024 * 1024:
        raise ValueError("expected the fixed native executor")
    value = read(manifest)
    digest = hashlib.sha256(executor.read_bytes()).hexdigest()
    if value != pins.MXC_G_BUILD_MANIFEST or digest != pins.MXC_G_EXECUTOR_SHA256:
        raise ValueError("executor or manifest differs from the fixed G artifact")
    return {"executor_sha256": digest, "upstream_commit": value["upstream_commit"],
            "g_patch_applies_to_model2": False}


def identity_snapshot():
    """Observe this process only; never replace/restrict/restore any token."""
    kernel, advapi, ip = (C.WinDLL(name, use_last_error=True)
                          for name in ("kernel32", "advapi32", "iphlpapi"))
    H, D, P = C.c_void_p, C.c_uint32, C.c_wchar_p
    for dll, name, args, result in (
        (kernel, "GetCurrentProcess", [], H), (kernel, "CloseHandle", [H], C.c_int),
        (kernel, "LocalFree", [H], H),
        (advapi, "OpenProcessToken", [H, D, C.POINTER(H)], C.c_int),
        (advapi, "GetTokenInformation", [H, C.c_int, H, D, C.POINTER(D)], C.c_int),
        (advapi, "ConvertSidToStringSidW", [H, C.POINTER(P)], C.c_int),
        (ip, "GetCurrentThreadCompartmentId", [], D),
    ):
        function = getattr(dll, name)
        function.argtypes, function.restype = args, result
    token = H()
    if not advapi.OpenProcessToken(kernel.GetCurrentProcess(), 8, C.byref(token)):
        raise C.WinError(C.get_last_error())
    try:
        size = D()
        advapi.GetTokenInformation(token, 1, None, 0, C.byref(size))
        if not 1 <= size.value <= 65536:
            raise OSError("invalid token identity size")
        buffer = C.create_string_buffer(size.value)
        if not advapi.GetTokenInformation(token, 1, buffer, size, C.byref(size)):
            raise C.WinError(C.get_last_error())
        text = P()
        if not advapi.ConvertSidToStringSidW(C.cast(buffer, C.POINTER(H))[0], C.byref(text)):
            raise C.WinError(C.get_last_error())
        try:
            result = {"sid": text.value, "pid": os.getpid(),
                      "cid": int(ip.GetCurrentThreadCompartmentId())}
        finally:
            kernel.LocalFree(C.cast(text, H))
        for name, kind in (("elevated", 20), ("appcontainer", 29)):
            value = D()
            if not advapi.GetTokenInformation(token, kind, C.byref(value), C.sizeof(value), C.byref(size)):
                raise C.WinError(C.get_last_error())
            result[name] = bool(value.value)
        return result
    finally:
        kernel.CloseHandle(token)


class FixedHTTPProxy:
    """A fixed local HTTP response source, never a forwarding/open proxy."""
    def __init__(self, markers):
        if (set(markers) != {"baseline", "combined"}
                or len(set(markers.values())) != 2
                or not all(re.fullmatch(r"[0-9a-f]{32}", marker) for marker in markers.values())):
            raise ValueError("fixture requires two distinct fixed case nonces")
        self.markers = dict(markers)
        self.requests = {case: {"outside": 0, "inside": 0, "browser": 0} for case in markers}
        self.rejected = 0
        self.lock = threading.Lock()
        owner = self
        expected = {f"http://{HOST}/{marker}/{phase}": (case, phase, marker)
                    for case, marker in self.markers.items() for phase in self.requests[case]}

        class Handler(BaseHTTPRequestHandler):
            def setup(self):
                super().setup()
                self.connection.settimeout(5)

            def do_GET(self):
                match = expected.get(self.path)
                with owner.lock:
                    if match is None:
                        owner.rejected += 1
                    else:
                        case, phase, marker = match
                        owner.requests[case][phase] += 1
                if match is None:
                    self.send_error(403)
                    return
                body = f"<!doctype html><title>RuleProxy smoke</title><p>{marker}</p>".encode("ascii")
                self.send_response(200)
                self.send_header("Content-Type", "text/html; charset=ascii")
                self.send_header("Content-Length", str(len(body)))
                self.send_header("Connection", "close")
                self.end_headers()
                self.wfile.write(body)

            def do_CONNECT(self):
                self.send_error(403)

            def log_message(self, *_):
                pass

        self.server = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
        self.server.daemon_threads = False
        self.port = self.server.server_port
        self.thread = threading.Thread(target=self.server.serve_forever, kwargs={"poll_interval": .05}, daemon=True)
        self.thread.start()

    def snapshot(self, case):
        with self.lock:
            return dict(self.requests[case])

    def close(self):
        self.server.shutdown()
        self.server.server_close()
        self.thread.join(2)
        if self.thread.is_alive():
            raise RuntimeError("fixture accept thread did not stop")


def proxy_get(port, marker, phase):
    import http.client
    connection = http.client.HTTPConnection("127.0.0.1", port, timeout=8)
    try:
        connection.request("GET", f"http://{HOST}/{marker}/{phase}")
        response = connection.getresponse()
        body = response.read(8192)
        return {"status": response.status, "marker_matched": marker.encode("ascii") in body,
                "body_bytes": len(body)}
    finally:
        connection.close()


def browser_command(executable, profile, port, marker):
    return [str(executable), "--headless=new", "--disable-gpu", "--no-first-run",
            "--no-default-browser-check", "--disable-background-networking",
            "--disable-component-update", "--disable-sync", "--metrics-recording-only",
            "--enable-logging=stderr", "--v=0", f"--user-data-dir={profile}",
            f"--proxy-server=http://127.0.0.1:{port}", "--proxy-bypass-list=<-loopback>",
            "--dump-dom", f"http://{HOST}/{marker}/browser"]


def actor(config, *, child=False):
    result = {"identity": identity_snapshot(), "marker": config["marker"]}
    if child:
        save(config["child_report"], result)
        return 0
    try:
        result["proxy"] = proxy_get(config["port"], config["marker"], "inside")
        child_run = subprocess.run([sys.executable, "-I", "-S", "-B", __file__,
                                    "--child", config["config_path"]],
                                   stdin=subprocess.DEVNULL, capture_output=True, timeout=20)
        result["child_exit_code"] = child_run.returncode
        if Path(config["child_report"]).is_file():
            result["child"] = read(config["child_report"])
        if config.get("browser"):
            command = browser_command(config["browser"], Path(config["profile"]) / "browser",
                                      config["port"], config["marker"])
            # stdout/stderr are private local diagnostics. Publish only bounded
            # marker/exit observations, never arbitrary browser log contents.
            with Path(config["profile"], "browser.stdout").open("wb") as output, \
                    Path(config["profile"], "browser.stderr").open("wb") as errors:
                process = subprocess.Popen(command, stdin=subprocess.DEVNULL, stdout=output, stderr=errors)
                try:
                    code = process.wait(timeout=40)
                    result["browser"] = {"exit_code": code, "timed_out": False,
                                         "sandbox_disabling_flags": False, "visible_ui_tested": False}
                except subprocess.TimeoutExpired:
                    process.kill()
                    process.wait(timeout=5)
                    result["browser"] = {"timed_out": True, "sandbox_disabling_flags": False,
                                         "visible_ui_tested": False}
            with Path(config["profile"], "browser.stdout").open("rb") as stream:
                result["browser"]["dom_marker_matched"] = config["marker"].encode("ascii") in stream.read(1024 * 1024)
    except Exception as exc:
        result["error"] = failure(exc)
    save(config["actor_report"], result)
    return 0 if result.get("proxy", {}).get("marker_matched") else 1


def build_policy(config, command):
    """The existing schema-1.0.0 Model 2 shape, with no direct egress allow."""
    read_only = [config["inputs"], config["runtime"]]
    if config.get("browser"):
        read_only.append(str(Path(config["browser"]).parent))
    return {"$schema": "https://github.com/microsoft/mxc/schemas/stable/mxc-config.schema.1.0.0.json",
            "version": "1.0.0", "containment": "processcontainer",
            "containerId": "ruleproxy-psec-smoke-" + config["marker"],
            "fallback": {"allowDaclMutation": False},
            "process": {"commandLine": subprocess.list2cmdline(command), "cwd": config["profile"],
                        "inheritDefaultEnv": True, "timeout": 90000},
            "filesystem": {"readonlyPaths": sorted(set(read_only)), "readwritePaths": [config["profile"]]},
            "ui": {"disable": False, "clipboard": "all"},
            "processContainer": {"ui": {"isolation": "container", "ime": True}},
            "network": {"egress": {"default": "deny"},
                        "ingress": {"default": "allow", "hostLoopback": "allow"}},
            "runtimeConfig": {"networkProxy": f"http://127.0.0.1:{config['port']}"}}


def base_container_selected(value, exit_code):
    return (exit_code == 0 and isinstance(value, dict) and value.get("error") is None
            and value.get("tier") == "base-container" and value.get("needsDaclAugmentation") is False
            and isinstance(value.get("probes"), dict)
            and value["probes"].get("baseContainerApiPresent") is True)


def executor_message_summary(message):
    """Return only closed categories, operation names and numeric codes."""
    categories = {
        "configuration": r"config|schema|unknown field|deserializ|json|policy",
        "permission": r"access.denied|permission.denied|privilege",
        "unsupported": r"unsupported|not.supported|unavailable|not.found",
        "job": r"job.object|assign.*job|nested.job|ui.limit",
        "process_creation": r"createprocess|process.creation|spawn|launch",
        "psec": r"processsecurity|security.environment|base.container|psec",
        "proxy": r"proxy|loopback|wfp|network",
    }
    operations = ("CreateProcessW", "CreateProcessAsUserW", "CreateProcessWithTokenW",
                  "AssignProcessToJobObject", "CreateJobObjectW", "SetInformationJobObject",
                  "CreateProcessSecurityEnvironment", "DeriveAppContainerSidFromAppContainerName",
                  "CreateAppContainerProfile", "UpdateProcThreadAttribute", "GetLastError",
                  "GetStdHandle", "SetHandleInformation", "ResumeThread")
    # Code labels are allowed; their surrounding text (paths, command lines,
    # environment values and any child logs) is deliberately not exported.
    numeric = re.findall(r"\b(?:HRESULT|WIN32(?:_ERROR)?|WINERROR|OS ERROR|ERROR(?: CODE)?|CODE)\s*[:=(]?\s*(0x[0-9a-f]{1,8}|-?[0-9]{1,10})\b",
                         message, flags=re.IGNORECASE)
    hex_codes = re.findall(r"\b0x[89c][0-9a-f]{7}\b", message, flags=re.IGNORECASE)
    return {"categories": [name for name, pattern in categories.items() if re.search(pattern, message, re.IGNORECASE)],
            "operations": [name for name in operations if name.casefold() in message.casefold()],
            "native_codes": sorted(set(value.lower() for value in numeric + hex_codes))[:16]}


def executor_error_envelopes(message):
    """Recognize the pinned one-shot CLI shape; never return its free text.

    MXC 7bf2102 core/mxc_common/script_runner.rs:102-118 emits only error
    code/message and optional extended_error. Its two codes come from
    models.rs:1328-1332. This is reported CLI output, not an authenticated
    observation of an API call or proof that the workload never started.
    """
    def unique_object(pairs):
        result = {}
        for key, value in pairs:
            if key in result:
                raise ValueError("duplicate JSON key")
            result[key] = value
        return result

    decoder = json.JSONDecoder(object_pairs_hook=unique_object)
    prefixes = {
        "psec_environment_create": "failed to create the process security environment:",
        "psec_environment_attach": "failed to attach the process security environment:",
        "child_environment": "failed to create a clean child environment:",
        "job_setup": "BaseContainer sandbox could not be placed in a job object,",
        "child_resume": "ResumeThread failed for the BaseContainer child:",
        "host_loopback_contract": "network.ingress.hostLoopback='allow' requires Process Security Environment contract version",
        "proxy_identity_conflict": "processContainer.network.allowedProxyPeer grants loopback access only to the",
    }
    envelopes = []
    # standard_err is printed without an added newline before the envelope;
    # accept a JSON object at a line's end even when preceded by that text.
    for match in re.finditer(r'\{\s*"error"\s*:', message[:65536]):
        try:
            value, end = decoder.raw_decode(message, match.start())
        except (ValueError, RecursionError):
            continue
        suffix = message[end:].split("\n", 1)[0]
        if suffix.strip() or not isinstance(value, dict) or set(value) != {"error"}:
            continue
        error = value["error"]
        if (not isinstance(error, dict) or not {"code", "message"} <= set(error)
                or set(error) - {"code", "message", "extended_error"}
                or not all(isinstance(item, str) for item in error.values())
                or error["code"] not in ("backend_error", "policy_validation")
                or any(len(item) > 8192 for item in error.values())):
            continue
        detail = error.get("extended_error", "")
        summary = {"code": error["code"],
                   "message_class": next((name for name, prefix in prefixes.items()
                                          if error["message"].startswith(prefix)), "unclassified"),
                   "message_sha256": hashlib.sha256(error["message"].encode("utf-8", errors="surrogatepass")).hexdigest(),
                   "has_extended_error": "extended_error" in error,
                   **executor_message_summary(error["message"] + "\n" + detail)}
        if "extended_error" in error:
            summary["extended_error_sha256"] = hashlib.sha256(detail.encode("utf-8", errors="surrogatepass")).hexdigest()
        if summary not in envelopes:
            envelopes.append(summary)
        if len(envelopes) == 4:
            break
    return envelopes


def executor_diagnostic(data):
    """Retain bounded structured diagnostics, never arbitrary executor output."""
    bounded = data[:65536]
    message = bounded.decode("utf-8", errors="replace")
    return {"bytes_observed": len(data), "inspection_truncated": len(data) > len(bounded),
            **executor_message_summary(message),
            "error_envelopes": executor_error_envelopes(message),
            "inspected_sha256": hashlib.sha256(bounded).hexdigest()}


def run_psec(config, runner=subprocess.run):
    result = {"identity": identity_snapshot(), "marker": config["marker"], "started": False}
    if (result["identity"]["sid"] != config["sid"] or result["identity"]["elevated"]
            or result["identity"]["appcontainer"] or result["identity"]["cid"] != config["cid"]):
        raise RuntimeError("ordinary launcher identity or pre-bound compartment differs")
    result["relay_control"] = proxy_get(config["port"], config["marker"], "outside")
    if not result["relay_control"]["marker_matched"]:
        raise RuntimeError("ordinary launcher could not read the fixed relay response")
    command = [sys.executable, "-I", "-S", "-B", __file__, "--actor", config["config_path"]]
    policy = build_policy(config, command)
    policy_path = Path(config["profile"]) / "policy.json"
    save(policy_path, policy)
    probe = runner([config["executor"], "--probe", "--config", str(policy_path)],
                   stdin=subprocess.DEVNULL, capture_output=True, timeout=30)
    result["probe_exit_code"] = probe.returncode
    result["probe_diagnostic"] = executor_diagnostic(probe.stderr)
    for name, data in (("stdout", probe.stdout), ("stderr", probe.stderr)):
        Path(config["profile"], "probe." + name).write_bytes(data[:MAX_JSON])
    try:
        facts = json.loads(probe.stdout)
    except (ValueError, TypeError):
        facts = {}
    if not isinstance(facts, dict):
        facts = {}
    result["probe"] = {key: facts.get(key) for key in ("tier", "needsDaclAugmentation", "probes", "error")}
    if not base_container_selected(facts, probe.returncode):
        result["status"] = "unsupported"
        return result
    with Path(config["profile"], "executor.stdout").open("wb") as output, \
            Path(config["profile"], "executor.stderr").open("wb") as errors:
        result["started"] = True
        try:
            completed = runner([config["executor"], "--config", str(policy_path)],
                               stdin=subprocess.DEVNULL, stdout=output, stderr=errors, timeout=110)
            result["exit_code"], result["timed_out"] = completed.returncode, False
        except subprocess.TimeoutExpired:
            result["exit_code"], result["timed_out"] = None, True
    for stream, key in (("stderr", "executor_diagnostic"), ("stdout", "executor_stdout_diagnostic")):
        with Path(config["profile"], "executor." + stream).open("rb") as output:
            result[key] = {"stream": stream, **executor_diagnostic(output.read(65537))}
    if Path(config["actor_report"]).is_file():
        result["actor"] = read(config["actor_report"])
    result["status"] = "observed"
    return result


def user_launcher(config):
    try:
        result = run_psec(config)
    except Exception as exc:
        result = {"error": failure(exc)}
    save(config["launcher_report"], result)
    return 0 if result.get("status") in ("unsupported", "observed") else 1


def copy_python(target):
    target.mkdir()
    base = Path(sys.base_prefix)
    for path in base.iterdir():
        if path.is_file() and path.suffix.casefold() in (".exe", ".dll", ".pyd", ".zip", "._pth"):
            shutil.copy2(path, target / path.name)
    for name in ("DLLs", "Lib"):
        if (base / name).is_dir():
            shutil.copytree(base / name, target / name, ignore=shutil.ignore_patterns(
                "site-packages", "__pycache__", "test", "tests", "idlelib", "tkinter", "ensurepip"))
    executable = target / Path(sys.executable).name
    if not executable.is_file():
        shutil.copy2(sys.executable, executable)
    return executable


class OrdinaryAccount:
    """Temporary normal account; no token restrictions or host ACL changes."""
    def __init__(self, native, lab):
        self.n, self.lab = native, lab
        self.name = "rpps" + secrets.token_hex(5)
        self.token, self.environment = W.HANDLE(), C.c_void_p()
        self.created, self.profile, self.desktop = False, None, None
        self.net, self.ue = C.WinDLL("netapi32"), C.WinDLL("userenv", use_last_error=True)
        for owner, name, args, ret in (
            (self.net, "NetUserAdd", [W.LPCWSTR, W.DWORD, C.c_void_p, C.POINTER(W.DWORD)], W.DWORD),
            (self.net, "NetUserDel", [W.LPCWSTR, W.LPCWSTR], W.DWORD),
            (self.net, "NetLocalGroupAddMembers", [W.LPCWSTR, W.LPCWSTR, W.DWORD, C.c_void_p, W.DWORD], W.DWORD),
            (self.ue, "LoadUserProfileW", [W.HANDLE, C.c_void_p], W.BOOL),
            (self.ue, "UnloadUserProfile", [W.HANDLE, W.HANDLE], W.BOOL),
            (self.ue, "CreateEnvironmentBlock", [C.POINTER(C.c_void_p), W.HANDLE, W.BOOL], W.BOOL),
            (self.ue, "DestroyEnvironmentBlock", [C.c_void_p], W.BOOL),
            (self.ue, "DeleteProfileW", [W.LPCWSTR, W.LPCWSTR, W.LPCWSTR], W.BOOL),
        ):
            function = getattr(owner, name)
            function.argtypes, function.restype = args, ret

    def start(self, work):
        password = secrets.token_urlsafe(24) + "aA1!"
        info = self.lab.USER_INFO_1(self.name, password, 0, 1, None, "RuleProxy disposable PSEC smoke", 0x10201, None)
        parameter = W.DWORD()
        code = int(self.net.NetUserAdd(None, 1, C.byref(info), C.byref(parameter)))
        if code:
            raise OSError(code, "NetUserAdd")
        self.created = True
        member = W.LPWSTR(self.name)
        status = int(self.net.NetLocalGroupAddMembers(None, "Users", 3, C.byref(member), 1))
        if status not in (0, 1378):
            raise OSError(status, "NetLocalGroupAddMembers Users")
        self.n.check(self.n.a.LogonUserW(self.name, ".", password, 2, 0, C.byref(self.token)), "LogonUserW")
        self.identity = self.n.token_identity(self.token)
        if self.identity["elevated"] or not self.identity["sid"].startswith("S-1-5-21-"):
            raise PermissionError("temporary account is not ordinary")
        # Only this new disposable tree is changed. Keep source/executor
        # readable and profile writable; no grants on Windows/Program Files.
        for path, rights in ((work, "RX"), (work / "user", "M")):
            subprocess.run(["icacls", str(path), "/grant", f"*{self.identity['sid']}:(OI)(CI)({rights})", "/Q"],
                           capture_output=True, timeout=20, check=True)

        class Profile(C.Structure):
            _fields_ = [("size", W.DWORD), ("flags", W.DWORD), ("username", W.LPWSTR),
                        ("path", W.LPWSTR), ("default", W.LPWSTR), ("server", W.LPWSTR),
                        ("policy", W.LPWSTR), ("handle", W.HANDLE)]
        profile = Profile()
        profile.size, profile.flags, profile.username = C.sizeof(profile), 1, self.name
        self.n.check(self.ue.LoadUserProfileW(self.token, C.byref(profile)), "LoadUserProfileW")
        self.profile = profile.handle
        self.n.check(self.ue.CreateEnvironmentBlock(C.byref(self.environment), self.token, False), "CreateEnvironmentBlock")
        self.desktop = self.lab.PrivateUserDesktop(self.n, self.identity["sid"])

    def launch(self, command, cwd, job):
        startup, process = self.lab.STARTUPINFOW(), self.lab.PROCESS_INFORMATION()
        startup.cb, startup.lpDesktop = C.sizeof(startup), self.desktop.path
        self.n.check(self.n.a.CreateProcessWithTokenW(self.token, 1, str(command[0]),
                     C.create_unicode_buffer(subprocess.list2cmdline([str(x) for x in command])),
                     0x08000000 | 0x400 | 4, self.environment, str(cwd),
                     C.byref(startup), C.byref(process)), "CreateProcessWithTokenW")
        return self.n._start(process, job)

    def close(self):
        facts = {}
        if self.desktop:
            if self.desktop.desktop:
                facts["desktop_closed"] = bool(self.desktop.u.CloseDesktop(self.desktop.desktop))
                self.desktop.desktop = None
            if self.desktop.station:
                facts["station_closed"] = bool(self.desktop.u.CloseWindowStation(self.desktop.station))
                self.desktop.station = None
        if self.environment:
            facts["environment_freed"] = bool(self.ue.DestroyEnvironmentBlock(self.environment))
        if self.profile:
            facts["profile_unloaded"] = bool(self.ue.UnloadUserProfile(self.token, self.profile))
        if self.token:
            facts["token_closed"] = bool(self.n.k.CloseHandle(self.token))
        if self.created:
            facts["account_delete_status"] = int(self.net.NetUserDel(None, self.name))
            if getattr(self, "identity", None):
                facts["profile_deleted"] = bool(self.ue.DeleteProfileW(self.identity["sid"], None, None))
        return facts


def enable_profile_privileges(native):
    """Enable the SYSTEM controller's existing profile-management privileges."""
    class Luid(C.Structure):
        _fields_ = [("low", C.c_uint32), ("high", C.c_int32)]

    class Privileges(C.Structure):
        _fields_ = [("count", C.c_uint32), ("luid", Luid), ("attributes", C.c_uint32)]

    native.a.LookupPrivilegeValueW.argtypes = [W.LPCWSTR, W.LPCWSTR, C.POINTER(Luid)]
    native.a.LookupPrivilegeValueW.restype = W.BOOL
    native.a.AdjustTokenPrivileges.argtypes = [W.HANDLE, W.BOOL, C.POINTER(Privileges), W.DWORD,
                                              C.c_void_p, C.c_void_p]
    native.a.AdjustTokenPrivileges.restype = W.BOOL
    token = W.HANDLE()
    native.check(native.a.OpenProcessToken(native.k.GetCurrentProcess(), 0x28, C.byref(token)), "Open SYSTEM token")
    try:
        for name in ("SeBackupPrivilege", "SeRestorePrivilege"):
            value = Privileges()
            value.count, value.attributes = 1, 2
            native.check(native.a.LookupPrivilegeValueW(None, name, C.byref(value.luid)), "Lookup profile privilege")
            C.set_last_error(0)
            native.check(native.a.AdjustTokenPrivileges(token, False, C.byref(value), 0, None, None), "Enable profile privilege")
            if C.get_last_error() == 1300:
                raise PermissionError("SYSTEM token lacks the required profile privilege")
    finally:
        native.k.CloseHandle(token)


def case_checks(report, *, combined):
    """The caller fixes the case semantics; never trust a report's mode flag."""
    launch = report.get("launcher", {})
    actor_value = launch.get("actor", {})
    expected = report.get("ordinary_identity", {}).get("sid")
    cid = report.get("cid")
    cid_valid = type(cid) is int and (cid > 1 if combined else cid == 1)
    outer = report.get("outer_job", {})
    marker = report.get("marker")
    cleanup = report.get("cleanup", {})

    def valid(value, appcontainer=None):
        return (cid_valid and isinstance(expected, str) and bool(expected)
                and value.get("sid") == expected and value.get("elevated") is False
                and type(value.get("cid")) is int and value.get("cid") == cid
                and type(value.get("appcontainer")) is bool
                and (appcontainer is None or value["appcontainer"] is appcontainer))

    result = {"compartment_id": cid_valid,
              # An unbound Job's raw compartment property is recorded, but
              # baseline membership is measured in the three real processes.
              "outer_job_configuration": (
                  type(outer.get("cid")) is int
                  and (outer["cid"] == cid if combined else outer["cid"] >= 0)
                  and outer.get("compartment_bound") is combined
                  and type(outer.get("ui_limits")) is int and outer["ui_limits"] == 0
                  and outer.get("kill_on_close") is True
                  and outer.get("breakaway") is False),
              "case_nonce": (isinstance(marker, str) and re.fullmatch(r"[0-9a-f]{32}", marker) is not None
                             and all(value.get("marker") == marker for value in (
                                 launch, actor_value, actor_value.get("child", {})))),
              "outside_fixture": report.get("fixture_control", {}).get("marker_matched") is True,
              "ordinary_relay_control": launch.get("relay_control", {}).get("marker_matched") is True,
              "ordinary_launcher_in_cid": valid(launch.get("identity", {}), False),
              # This gate measures functionality. Record the actual token's
              # AppContainer bit instead of making it a proxy for the complete
              # PSEC security contract; no isolation qualification is claimed.
              "psec_selected": (base_container_selected(launch.get("probe"), launch.get("probe_exit_code"))
                                and launch.get("started") is True),
              "psec_actor_in_cid": valid(actor_value.get("identity", {})),
              "psec_child_in_cid": valid(actor_value.get("child", {}).get("identity", {})),
              "proxy_request": actor_value.get("proxy", {}).get("marker_matched") is True
                               and report.get("fixture_requests", {}).get("inside", 0) > 0,
              "normal_exit": (report.get("launcher_exit_code") == 0
                              and report.get("launcher_timed_out") is False and launch.get("exit_code") == 0
                              and launch.get("timed_out") is False
                              and actor_value.get("child_exit_code") == 0 and "error" not in actor_value
                              and "error" not in report and "error" not in launch),
              "outer_job_empty": cleanup.get("job_empty") is True,
              "case_cleanup": (cleanup.get("job_closed") is True
                               and cleanup.get("ready_for_next_case") is True
                               and not any(key.endswith("_error") for key in cleanup)
                               and (cleanup.get("relay") is True if combined else "relay" not in cleanup))}
    if report.get("browser_requested"):
        browser = actor_value.get("browser", {})
        result["browser_render"] = (browser.get("dom_marker_matched") is True
                                    and browser.get("exit_code") == 0 and browser.get("timed_out") is False
                                    and report.get("fixture_requests", {}).get("browser", 0) > 0)
    return result


def baseline_checks(report):
    return case_checks(report, combined=False)


def checks(report):
    # Keep the main report's original fields as the combined case; baseline
    # success is recomputed independently, never taken from its claimed flag.
    result = case_checks(report, combined=True)
    baseline = report.get("baseline", {})
    account_cleanup = report.get("cleanup", {}).get("account", {})
    result["baseline_success"] = all(baseline_checks(baseline).values())
    result["case_independence"] = (
        report.get("case_id") == "combined" and baseline.get("case_id") == "baseline"
        and report.get("profile_id") == "combined" and baseline.get("profile_id") == "baseline"
        and report.get("marker") != baseline.get("marker")
        and report.get("fixture_port") == baseline.get("fixture_port")
        and type(report.get("fixture_port")) is int and 0 < report["fixture_port"] < 65536
        and report.get("ordinary_identity", {}).get("sid") == baseline.get("ordinary_identity", {}).get("sid")
        and report.get("browser_requested") is baseline.get("browser_requested"))
    result["account_cleanup"] = (isinstance(account_cleanup, dict)
                                 and account_cleanup.get("account_delete_status") == 0
                                 and all(account_cleanup.get(key) is True for key in (
                                     "environment_freed", "profile_unloaded", "profile_deleted", "token_closed",
                                     "desktop_closed", "station_closed")))
    result["fixture_cleanup"] = report.get("cleanup", {}).get("fixture") is True
    return result


def run_case(*, combined, native, api, account, fixture, work, python, executor, browser, job_limits_type):
    """Run one bounded case and release its Job/relay before returning."""
    name = "combined" if combined else "baseline"
    marker = fixture.markers[name]
    profile = work / "user" / name
    report = {"case_id": name, "profile_id": name, "marker": marker, "fixture_port": fixture.port,
              "ordinary_identity": dict(account.identity), "browser_requested": browser is not None,
              "cleanup": {}}
    job = process = relay = None
    try:
        profile.mkdir()  # A stale case profile/report must never be reused.
        report["fixture_control"] = proxy_get(fixture.port, marker, "outside")
        cid = api.create(str(uuid.uuid4()), "RuleProxy disposable PSEC smoke") if combined else 1
        report["cid"] = cid
        if type(cid) is not int or (cid <= 1 if combined else cid != 1):
            raise RuntimeError("combined compartment must have an integer CID greater than 1")
        if combined:
            inventory = api.inspect(cid)
            report["inventory"] = {key: inventory.get(key) for key in ("interfaces", "addresses", "routes")}
        job = native.new_job()
        if combined:
            duplicate = api.bind_job(os.getpid(), job, cid)
            api.close(duplicate)
        ui_limits, limits = W.DWORD(), job_limits_type()
        native.check(api.k.QueryInformationJobObject(job, 4, C.byref(ui_limits), C.sizeof(ui_limits), None),
                     "Query outer Job UI limits")
        native.check(api.k.QueryInformationJobObject(job, 9, C.byref(limits), C.sizeof(limits), None),
                     "Query outer Job lifetime limits")
        flags = limits.BasicLimitInformation.LimitFlags
        outer = report["outer_job"] = {"cid": int(native.i.GetJobCompartmentId(job)),
                                        "compartment_bound": combined, "ui_limits": ui_limits.value,
                                        "kill_on_close": bool(flags & 0x2000),
                                        "breakaway": bool(flags & (0x800 | 0x1000))}
        if (outer["ui_limits"] or not outer["kill_on_close"] or outer["breakaway"]
                or (combined and outer["cid"] != cid)):
            raise RuntimeError("outer Job compartment or lifetime/UI configuration differs")
        if combined:
            from ruleproxy.windows_compartment import _Relay
            relay = _Relay(api, cid, fixture.port, expected_core_pid=os.getpid(),
                           core_alive=lambda: fixture.thread.is_alive())
            report["relay_bound"] = relay.start()
        config_path = work / "inputs" / (name + ".json")
        config = {"config_path": str(config_path), "sid": account.identity["sid"], "cid": cid,
                  "executor": str(executor), "inputs": str(work / "inputs"), "runtime": str(work / "runtime"),
                  "profile": str(profile), "port": fixture.port, "marker": marker,
                  "actor_report": str(profile / "actor.json"), "child_report": str(profile / "child.json"),
                  "launcher_report": str(profile / "launcher.json"), "browser": str(browser) if browser else None}
        save(config_path, config)
        command = [python, "-I", "-S", "-B", work / "inputs" / "smoke.py", "--launcher", config_path]
        process, pid = account.launch(command, profile, job)
        report["launcher_pid"] = pid
        report["launcher_exit_code"], report["launcher_timed_out"] = native.wait(process, 155)
        process = None  # Native.wait closes the exact handle.
        if Path(config["launcher_report"]).is_file():
            report["launcher"] = read(config["launcher_report"])
    except Exception as exc:
        report["error"] = failure(exc)
    finally:
        if process:
            try:
                native.check(native.k.TerminateProcess(process, 125), "Terminate case launcher")
                if native.k.WaitForSingleObject(process, 5000) != 0:
                    raise RuntimeError("case launcher did not exit during cleanup")
            except Exception as exc:
                report["cleanup"]["process_error"] = failure(exc)
            finally:
                try:
                    native.check(native.k.CloseHandle(process), "Close case launcher handle")
                except Exception as exc:
                    report["cleanup"]["process_close_error"] = failure(exc)
        if job:
            try:
                api.terminate_job(job)
                report["cleanup"]["job_empty"] = api._active_processes(job) == 0
            except Exception as exc:
                report["cleanup"]["job_error"] = failure(exc)
            try:
                report["cleanup"]["job_closed"] = bool(native.k.CloseHandle(job))
            except Exception as exc:
                report["cleanup"]["job_close_error"] = failure(exc)
        if relay:
            report["relay"] = {"accepted": relay.accepted, "errors": list(relay.errors)}
            try:
                relay.stop()
                report["cleanup"]["relay"] = True
            except Exception as exc:
                report["cleanup"]["relay_error"] = failure(exc)
        if combined and type(report.get("cid")) is int and report["cid"] > 1:
            report["cleanup"]["compartment"] = "retained until disposable host reboot; allocated compartments are not deleted"
        cleanup = report["cleanup"]
        cleanup["ready_for_next_case"] = (not any(key.endswith("_error") for key in cleanup)
                                           and (job is None or (cleanup.get("job_empty") is True
                                                                and cleanup.get("job_closed") is True)))
        report["fixture_requests"] = fixture.snapshot(name)
    return report


def run_cases(**kwargs):
    """A failed baseline is still measured; only uncertain cleanup stops case 2."""
    baseline = run_case(combined=False, **kwargs)
    baseline["checks"] = baseline_checks(baseline)
    baseline["functionality_passed"] = all(baseline["checks"].values())
    if baseline.get("cleanup", {}).get("ready_for_next_case") is True:
        combined = run_case(combined=True, **kwargs)
    else:
        combined = {"cleanup": {}, "error": {"type": "BaselineCleanupIncomplete"}}
    combined["baseline"] = baseline
    return combined


def source_commit():
    commit = os.environ.get("GITHUB_SHA", "")
    return commit.lower() if re.fullmatch(r"[0-9a-fA-F]{40}", commit) else None


def host_facts():
    import winreg
    version = sys.getwindowsversion()
    with winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, r"SOFTWARE\Microsoft\Windows NT\CurrentVersion") as key:
        ubr = int(winreg.QueryValueEx(key, "UBR")[0])
    return {"source_commit": source_commit(),
            "os": {"build": version.build, "ubr": ubr, "architecture": platform.machine(),
                   "python_pointer_bits": C.sizeof(C.c_void_p) * 8}}


def controller(args):
    if os.name != "nt" or not args.disposable_ci:
        raise PermissionError("requires explicit disposable Windows CI invocation")
    sys.path.insert(0, str(ROOT))
    sys.path.insert(0, str(Path(__file__).resolve().parent))
    import windows_compartment_lab as lab
    from ruleproxy.windows_compartment import _CompartmentAPI
    native = lab.Native()
    if native.token_user() != "S-1-5-18":
        raise PermissionError("compartment controller must run as SYSTEM")
    enable_profile_privileges(native)
    provenance = verify_executor(args.executor, args.manifest)
    work = args.work.resolve()
    if work.exists():
        raise ValueError("work must be a new disposable directory")
    for variable in ("SystemRoot", "ProgramFiles", "ProgramFiles(x86)"):
        protected = Path(os.environ[variable]).resolve() if os.environ.get(variable) else None
        if protected and (work == protected or protected in work.parents):
            raise ValueError("work must not be in Windows or Program Files")
    report = {"schema_version": 1, "scope": "PSEC/compartment functional smoke only",
              "privacy_qualified": False, "product_acceptance": False, "provenance": provenance,
              "browser_requested": args.browser is not None, "cleanup": {}, **host_facts()}
    work.mkdir(parents=True)
    for name in ("user", "inputs"):
        (work / name).mkdir()
    account = fixture = None
    try:
        if int(native.i.GetCurrentThreadCompartmentId()) != 1:
            raise RuntimeError("controller must start in the default compartment")
        python = copy_python(work / "runtime")
        runtime_check = subprocess.run([str(python), "-I", "-S", "-c", "import ctypes, socket, ssl"],
                                       stdin=subprocess.DEVNULL, capture_output=True, timeout=20)
        report["runtime_import_exit_code"] = runtime_check.returncode
        if runtime_check.returncode:
            raise RuntimeError("copied Python cannot import its native networking extensions")
        shutil.copy2(__file__, work / "inputs" / "smoke.py")
        executor = work / "inputs" / "wxc-exec.exe"
        shutil.copy2(args.executor, executor)
        account = OrdinaryAccount(native, lab)
        account.start(work)
        report["ordinary_identity"] = account.identity
        fixture = FixedHTTPProxy({name: secrets.token_hex(16) for name in ("baseline", "combined")})
        api = _CompartmentAPI()
        browser = args.browser.resolve(strict=True) if args.browser else None
        report.update(run_cases(native=native, api=api, account=account, fixture=fixture, work=work,
                                python=python, executor=executor, browser=browser,
                                job_limits_type=lab.JOBOBJECT_EXTENDED_LIMIT_INFORMATION))
    except Exception as exc:
        report["error"] = failure(exc)
    finally:
        for name, owned, close in (("fixture", fixture, "close"), ("account", account, "close")):
            if owned:
                try:
                    report["cleanup"][name] = getattr(owned, close)() or True
                except Exception as exc:
                    report["cleanup"][name + "_error"] = failure(exc)
        report["checks"] = checks(report)
        report["functionality_passed"] = all(report["checks"].values()) and not any(
            name.endswith("_error") for name in report["cleanup"]) and "error" not in report
        args.report.parent.mkdir(parents=True, exist_ok=True)
        save(args.report, report)
    return 0 if report["functionality_passed"] else 1


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--disposable-ci", action="store_true")
    parser.add_argument("--executor", type=Path)
    parser.add_argument("--manifest", type=Path)
    parser.add_argument("--work", type=Path)
    parser.add_argument("--report", type=Path)
    parser.add_argument("--browser", type=Path)
    modes = parser.add_mutually_exclusive_group()
    for role in ("launcher", "actor", "child"):
        modes.add_argument("--" + role, type=Path)
    args = parser.parse_args(argv)
    if args.launcher:
        return user_launcher(read(args.launcher))
    if args.actor or args.child:
        return actor(read(args.actor or args.child), child=args.child is not None)
    if any(getattr(args, name) is None for name in ("executor", "manifest", "work", "report")):
        parser.error("controller requires --executor --manifest --work --report")
    try:
        return controller(args)
    except Exception as exc:
        args.report.parent.mkdir(parents=True, exist_ok=True)
        report = {"schema_version": 1, "scope": "PSEC/compartment functional smoke only",
                  "privacy_qualified": False, "product_acceptance": False,
                  "source_commit": source_commit(), "functionality_passed": False,
                  "preflight_error": failure(exc)}
        if os.name == "nt":
            try:
                report.update(host_facts())
            except Exception as facts_error:
                report["host_facts_error"] = failure(facts_error)
        save(args.report, report)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
