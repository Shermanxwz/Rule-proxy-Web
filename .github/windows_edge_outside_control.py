"""Source-only stock Edge health control outside PSEC, using an owned Windows job.

This deliberately uncontained diagnostic is NOT an application execution path.
Only the existing fixed HTTP browser fixture and a fresh private profile are
used. No user profile, sandbox flag, job breakaway or host setting is changed.
"""
from __future__ import annotations

import argparse
import ctypes
import hashlib
import importlib.util
import json
import math
import os
from pathlib import Path
import shutil
import subprocess
import sys
import tempfile
import time


ROOT = Path(__file__).resolve().parent.parent
SCOPE = "ordinary_windows_stock_edge_fixed_http_health"
_RECOVERY_OWNERS = []
KILL_ON_JOB_CLOSE = 0x2000
CREATE_SUSPENDED = 0x4
CREATE_NO_WINDOW = 0x08000000


class _BasicLimits(ctypes.Structure):
    _fields_ = [("process_user_time", ctypes.c_int64), ("job_user_time", ctypes.c_int64),
                ("flags", ctypes.c_uint32), ("minimum_working_set", ctypes.c_size_t),
                ("maximum_working_set", ctypes.c_size_t), ("active_process_limit", ctypes.c_uint32),
                ("affinity", ctypes.c_size_t), ("priority_class", ctypes.c_uint32),
                ("scheduling_class", ctypes.c_uint32)]


class _IOCounters(ctypes.Structure):
    _fields_ = [(name, ctypes.c_uint64) for name in
                ("read_ops", "write_ops", "other_ops", "read_bytes", "write_bytes", "other_bytes")]


class _ExtendedLimits(ctypes.Structure):
    _fields_ = [("basic", _BasicLimits), ("io", _IOCounters),
                ("process_memory", ctypes.c_size_t), ("job_memory", ctypes.c_size_t),
                ("peak_process_memory", ctypes.c_size_t), ("peak_job_memory", ctypes.c_size_t)]


class _Accounting(ctypes.Structure):
    _fields_ = [(name, ctypes.c_int64) for name in
                ("user_time", "kernel_time", "period_user_time", "period_kernel_time")] + [
                (name, ctypes.c_uint32) for name in
                ("page_faults", "total_processes", "active_processes", "terminated_processes")]


class WindowsJobApi:
    def __init__(self):
        if sys.platform != "win32":
            raise OSError("Windows job APIs are required")
        import _winapi
        self.process_api = _winapi
        self.kernel = ctypes.WinDLL("kernel32", use_last_error=True)
        handle, dword, boolean = ctypes.c_void_p, ctypes.c_uint32, ctypes.c_int32
        signatures = {
            "CreateJobObjectW": ([handle, ctypes.c_wchar_p], handle),
            "SetInformationJobObject": ([handle, ctypes.c_int32, handle, dword], boolean),
            "AssignProcessToJobObject": ([handle, handle], boolean),
            "QueryInformationJobObject": ([handle, ctypes.c_int32, handle, dword,
                                           ctypes.POINTER(dword)], boolean),
            "TerminateJobObject": ([handle, dword], boolean),
            "ResumeThread": ([handle], dword),
            "CloseHandle": ([handle], boolean),
        }
        for name, (arguments, result) in signatures.items():
            function = getattr(self.kernel, name)
            function.argtypes, function.restype = arguments, result

    @staticmethod
    def _checked(value):
        if not value:
            raise ctypes.WinError(ctypes.get_last_error())
        return value

    def create_job(self):
        # Unnamed, non-inheritable: children cannot keep the last job handle open.
        return self._checked(self.kernel.CreateJobObjectW(None, None))

    def set_limits(self, job):
        limits = _ExtendedLimits()
        limits.basic.flags = KILL_ON_JOB_CLOSE  # No UI limits, breakaway or policy changes.
        self._checked(self.kernel.SetInformationJobObject(job, 9, ctypes.byref(limits), ctypes.sizeof(limits)))

    def create_suspended(self, command, environment, cwd):
        # Popen closes its primary thread handle before returning. Keep both raw
        # CreateProcess handles, assign the still-suspended root, then resume.
        # CPython adds EXTENDED_STARTUPINFO_PRESENT / CREATE_UNICODE_ENVIRONMENT.
        startup = subprocess.STARTUPINFO()
        return self.process_api.CreateProcess(command[0], subprocess.list2cmdline(command),
            None, None, False, CREATE_SUSPENDED | CREATE_NO_WINDOW,
            environment, str(cwd), startup)

    def assign(self, job, process):
        self._checked(self.kernel.AssignProcessToJobObject(job, process))

    def resume(self, thread):
        previous = self.kernel.ResumeThread(thread)
        if previous == 0xffffffff:
            raise ctypes.WinError(ctypes.get_last_error())
        if previous != 1:
            raise RuntimeError("primary thread was not suspended exactly once")

    def wait(self, process, milliseconds):
        result = self.process_api.WaitForSingleObject(process, milliseconds)
        if result not in (0, 258):
            raise OSError("unexpected owned process wait result")
        return result == 0

    def exit_code(self, process):
        return self.process_api.GetExitCodeProcess(process) & 0xffffffff

    def active(self, job):
        info, returned = _Accounting(), ctypes.c_uint32()
        self._checked(self.kernel.QueryInformationJobObject(job, 1, ctypes.byref(info),
                      ctypes.sizeof(info), ctypes.byref(returned)))
        if returned.value != ctypes.sizeof(info):
            raise RuntimeError("owned job accounting length mismatch")
        return info.active_processes

    def terminate_job(self, job):
        self._checked(self.kernel.TerminateJobObject(job, 1))

    def terminate_suspended(self, process):
        # This fallback is only before successful job assignment: the suspended
        # process cannot have created children. Never terminate a PID by name.
        self.process_api.TerminateProcess(process, 1)

    def close(self, handle):
        self._checked(self.kernel.CloseHandle(handle))


class OwnedJobProcess:
    """Retain every handle until the owned tree is empty and close is verified."""
    def __init__(self, api=None):
        self.api = WindowsJobApi() if api is None else api
        self.job = self.process = self.thread = None
        self.pid = None
        self.assigned = self.resumed = self.natural_tree_exit = False
        self.forced_teardown = self.cleanup_proven = False
        self.stage = "job_create"

    def start(self, command, environment, cwd):
        if any(value is not None for value in (self.job, self.process, self.thread)):
            raise RuntimeError("owned job process was already started")
        self.job = self.api.create_job()
        self.stage = "job_limits"
        self.api.set_limits(self.job)
        self.stage = "process_create_suspended"
        self.process, self.thread, self.pid, _ = self.api.create_suspended(command, environment, cwd)
        self.stage = "job_assign"
        self.api.assign(self.job, self.process)
        self.assigned = True
        self.stage = "thread_resume"
        self.api.resume(self.thread)
        self.resumed = True
        self.stage = "thread_close"
        self.api.close(self.thread)
        self.thread = None

    def wait_natural(self, timeout):
        if not self.resumed or self.process is None or not 0 < timeout <= 90:
            raise ValueError("a bounded resumed owned process is required")
        self.stage = "natural_exit"
        deadline = time.monotonic() + timeout
        while time.monotonic() < deadline:
            if self.api.wait(self.process, 50):
                code = self.api.exit_code(self.process)
                if code or self.api.active(self.job) == 0:
                    self.natural_tree_exit = code == 0
                    return code
                time.sleep(0.05)
        raise TimeoutError("owned Edge job did not exit naturally within its budget")

    def close(self):
        self.cleanup_proven = False
        self.stage = "job_cleanup"
        if self.process is not None and not self.assigned and not self.api.wait(self.process, 0):
            self.api.terminate_suspended(self.process)
            self.forced_teardown = True
            if not self.api.wait(self.process, 2000):
                raise RuntimeError("unassigned suspended process exit was not proven")
        if self.job is not None and self.api.active(self.job):
            self.api.terminate_job(self.job)
            self.forced_teardown = True
            deadline = time.monotonic() + 5
            while self.api.active(self.job):
                if time.monotonic() >= deadline:
                    raise RuntimeError("owned job retained an active process")
                time.sleep(0.05)
        if self.process is not None and not self.api.wait(self.process, 0):
            raise RuntimeError("owned root process exit was not proven")
        # Clear only successfully closed handles, preserving failed ones for
        # explicit retry. The empty job stays owned until all close checks pass.
        for field in ("thread", "process", "job"):
            value = getattr(self, field)
            if value is not None:
                self.stage = field + "_handle_close"
                self.api.close(value)
                setattr(self, field, None)
        self.cleanup_proven = True


def browser_helpers():
    spec = importlib.util.spec_from_file_location("ruleproxy_outside_browser_helpers",
                                                ROOT / ".github/windows_browser_check.py")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def prepare_control(launcher, browser, profiles, proxy_port, phase, host):
    # Exact BrowserRun.run app/adapter/flags; only the owned profile and proxy
    # endpoint differ between an outside control and a contained launch.
    app = {"id": "browser", "label": "Real Edge fixture", "path": str(browser), "adapter": "chromium",
           "args": ["--headless=new", "--dump-dom", "--disable-gpu", "--no-default-browser-check",
                    f"http://{host}/phase/{phase}"]}
    return launcher.prepare_app(app, proxy_port, profiles)


def command_template_hash(command):
    values = ["<stock-edge>"]
    for argument in command[1:]:
        if argument.startswith("--user-data-dir="):
            argument = "--user-data-dir=<owned-private-profile>"
        elif argument.startswith("--proxy-server="):
            argument = "--proxy-server=http://127.0.0.1:<owned-proxy-port>"
        values.append(argument)
    return hashlib.sha256(json.dumps(values, separators=(",", ":")).encode("utf-8")).hexdigest()


def error_facts(error, stage):
    return {"stage": stage, "error_type": type(error).__name__,
            **{key: value if type(value := getattr(error, key, None)) is int else None
               for key in ("errno", "winerror")}}


def initial_result():
    return {"schema_version": 1, "status": "failed", "scope": SCOPE,
            "outside_headless_control_passed": False, "outside_psec": True, "source_only": True, "checks": [],
            "acceptance_passed": False, "full_acceptance_passed": False, "real_node_passed": False,
            "browser_fixture_passed": False, "browser_sandbox_weakened": False,
            "public_udp_proven": False, "system_dns_proven": False, "cleanup_proven": False,
            "host_network_unchanged": None,
            "limitations": ["Ordinary stock Edge health only; no PSEC isolation is exercised.",
                            "An owned cleanup job adds no UI limits; any pre-existing parent job is still inherited.",
                            "Failure alone cannot establish that host Edge is broken or exclude job compatibility issues.",
                            "Same prepared headless flags, with a new profile and an owned fixed HTTP fixture.",
                            "Only DOM acknowledgement, cookie persistence and natural exit are observed."]}


def main(arguments=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--root", type=Path, default=ROOT)
    parser.add_argument("--browser", type=Path)
    parser.add_argument("--report", type=Path, default=Path("windows-edge-outside.json"))
    parser.add_argument("--allow-emulated-x64", action="store_true")
    parser.add_argument("--timeout", type=float, default=45)
    args = parser.parse_args(arguments)
    if not math.isfinite(args.timeout) or not 10 <= args.timeout <= 90:
        parser.error("--timeout must be between 10 and 90 seconds")
    result, code, stage = initial_result(), 1, "platform"
    directory = fixture = owner = before = helpers = None
    cleanup = True
    try:
        browser_module = browser_helpers()
        helpers = browser_module.acceptance_helpers()
        facts = helpers.host_facts()
        result["host"] = facts
        if (sys.platform != "win32" or facts.get("windows_product_type") != 1
                or type(facts.get("windows_build")) is not int or facts["windows_build"] < 22000):
            result.update(status="unsupported", detail="Requires a Windows 11 workstation")
            return 3
        if facts.get("python_pe_machine") != 0x8664 or (facts.get("native_machine") != 0x8664
                and not (args.allow_emulated_x64 and facts.get("native_machine") == 0xAA64)):
            result.update(status="unsupported", detail="Requires x64 Python; ARM requires explicit emulation opt in")
            return 3
        stage = "ordinary_user"
        shell = ctypes.WinDLL("shell32", use_last_error=True)
        shell.IsUserAnAdmin.argtypes, shell.IsUserAnAdmin.restype = [], ctypes.c_int32
        if shell.IsUserAnAdmin():
            raise RuntimeError("outside health control requires an ordinary non-administrator")
        result["ordinary_user"] = True
        stage = "project_origin"
        root = args.root.resolve(strict=True)
        sys.path.insert(0, str(root))
        helpers.verify_project_origin(root)
        from ruleproxy import launcher, windows_runtime
        stage = "stock_edge"
        browser = browser_module.find_edge(args.browser)
        digest = hashlib.sha256()
        with browser.open("rb") as stream:
            for block in iter(lambda: stream.read(1024 * 1024), b""):
                digest.update(block)
        result["browser"] = {"executable_sha256": digest.hexdigest(),
                             "launcher_pe_machine": helpers.executable_machine(browser)}
        stage = "host_network_snapshot"
        before = helpers.network_snapshot()
        directory = Path(tempfile.mkdtemp(prefix="ruleproxy-edge-outside-"))
        fixture = browser_module.BrowserFixture()
        for phase in (1, 2):
            stage = "app_prepare"
            fixture.begin(phase)
            command, environment, _ = prepare_control(launcher, browser, directory / "profiles",
                                                       fixture.port, phase, browser_module.HOST)
            environment = windows_runtime._profile_environment(environment, directory / "profiles/browser")
            stage = "job_api"
            owner = OwnedJobProcess()
            stage = "owned_process"
            owner.start(command, environment, directory / "profiles/browser")
            codepoint = owner.wait_natural(args.timeout)
            record = {"phase": phase, "edge_exit_code": codepoint, "edge_exit_hex": f"0x{codepoint:08X}",
                      "command_template_sha256": command_template_hash(command),
                      "assigned_before_resume": owner.assigned and owner.resumed,
                      "natural_root_and_job_exit": owner.natural_tree_exit}
            result["checks"].append(record)
            if codepoint or not owner.natural_tree_exit:
                raise RuntimeError("outside stock Edge did not complete naturally")
            stage = "fixture_ack"
            fixture.check(phase)
            record.update(dom_nonce_via_page_ack=True, cookie_request_verified=True,
                          private_profile_reused=phase == 2)
            stage = "owned_process_cleanup"
            owner.close()
            record["owned_job_cleanup_proven"] = owner.cleanup_proven
            owner = None
        result.update(status="outside_control_only", outside_headless_control_passed=True)
        code = 0
    except Exception as error:
        operation = owner.stage if owner is not None and stage in {"owned_process", "owned_process_cleanup"} else stage
        result["failure"] = error_facts(error, operation)
    finally:
        if owner is not None:
            try:
                owner.close()
            except Exception as error:
                cleanup = False
                result["cleanup_failure"] = error_facts(error, owner.stage)
        if fixture is not None:
            try:
                fixture.close()
            except Exception as error:
                cleanup = False
                result["fixture_cleanup_failure"] = error_facts(error, "fixture_close")
        if before is not None:
            try:
                result["host_network_unchanged"] = before == helpers.network_snapshot()
                if not result["host_network_unchanged"]:
                    result["outside_headless_control_passed"] = False
            except Exception as error:
                result["failure"] = error_facts(error, "host_network_snapshot_after")
                result["outside_headless_control_passed"] = False
        if cleanup and directory is not None:
            try:
                shutil.rmtree(directory)
            except OSError as error:
                cleanup = False
                result["cleanup_failure"] = error_facts(error, "profile_cleanup")
        result["cleanup_proven"] = cleanup
        if not cleanup:
            _RECOVERY_OWNERS.append((owner, fixture, directory))
            result["recovery_retained"] = True
        if not cleanup or result["status"] == "failed" or not result["outside_headless_control_passed"]:
            result["outside_headless_control_passed"] = False
            if result["status"] != "unsupported":
                result["status"] = "failed"
                code = 1
        args.report.parent.mkdir(parents=True, exist_ok=True)
        args.report.write_text(json.dumps(result, ensure_ascii=True, indent=2) + "\n", encoding="utf-8")
        print(json.dumps(result, ensure_ascii=True), flush=True)
    return code


if __name__ == "__main__":
    raise SystemExit(main())
