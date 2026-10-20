"""Bounded Stage 0b launcher for an explicitly approved disposable Windows CI.

This does not manufacture an ordinary user. An elevated runner can use only its
existing, same-user/same-session linked limited token. Unsupported hosts stop:
no credentials, accounts, UAC changes, privilege adjustment, alternate logon
API, desktop ACL changes, token restriction, or integrity-level changes.

Only the checked-in Stage 0b script can be launched, using this Python runtime.
The linked-token path uses CreateProcessAsUserW. In particular, error 1314 is a
recorded blocker, NOT a reason to try a different process-creation API.
"""
from __future__ import annotations

import argparse
import ctypes as C
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import re
import stat
import subprocess
import sys

ROOT = Path(__file__).resolve().parents[1]
PROBE = ROOT / ".github/windows_identity_pipe_probe.py"
MAX_REPORT = 128 * 1024
# Covers Stage 0b's independently bounded ACL/echo/exit/cleanup phases. The
# process job is not evidence that AppContainer profile/ACL cleanup completed.
RUN_MILLISECONDS = 120_000
H, D, P = C.c_void_p, C.c_uint32, C.c_wchar_p
TOKEN_QUERY = 0x0008
TOKEN_ELEVATION_TYPE_DEFAULT = 1
TOKEN_ELEVATION_TYPE_FULL = 2
TOKEN_ELEVATION_TYPE_LIMITED = 3
MEDIUM_INTEGRITY = 8192
ADMIN_SID = "S-1-5-32-544"
GROUP_ENABLED = 0x00000004
GROUP_DENY_ONLY = 0x00000010
KILL_ON_JOB_CLOSE = 0x00002000
SID_PATTERN = re.compile(r"S-1-(?:[0-9]+-)*[0-9]+\Z")
DIGEST_PATTERN = re.compile(r"[0-9a-f]{64}\Z")


class NativeFailure(OSError):
    def __init__(self, operation, code):
        super().__init__(code, operation)
        self.operation = operation
        self.winerror = code


class GateFailure(RuntimeError):
    """A closed invariant name, never an unfiltered native diagnostic."""


def failure(exc):
    if isinstance(exc, NativeFailure):
        return {"operation": exc.operation, "winerror": exc.winerror}
    if isinstance(exc, GateFailure):
        return {"operation": "invariant", "reason": str(exc)}
    return {"operation": "launcher", "type": type(exc).__name__}


def token_is_ordinary(identity, *, require_limited=False):
    """Pure fail-closed gate over observations made by native token queries."""
    required = {"sid", "session_id", "token_type", "elevation_type", "elevated",
                "integrity_rid", "admin_attributes", "appcontainer", "appcontainer_sid",
                "capability_count", "ui_access"}
    if not isinstance(identity, dict) or not required.issubset(identity):
        return False
    user = identity.get("sid")
    admin = identity.get("admin_attributes")
    if not (isinstance(user, str) and SID_PATTERN.fullmatch(user)
            and type(identity.get("session_id")) is int and identity["session_id"] >= 0
            and identity.get("token_type") == 1 and type(identity.get("token_type")) is int
            and identity.get("elevated") is False
            and identity.get("appcontainer") is False
            and identity.get("appcontainer_sid") is None
            and type(identity.get("capability_count")) is int and identity["capability_count"] == 0
            and identity.get("ui_access") is False
            and type(identity.get("integrity_rid")) is int and identity["integrity_rid"] == MEDIUM_INTEGRITY
            and type(identity.get("elevation_type")) is int
            and identity["elevation_type"] in (TOKEN_ELEVATION_TYPE_DEFAULT, TOKEN_ELEVATION_TYPE_LIMITED)):
        return False
    if require_limited and identity["elevation_type"] != TOKEN_ELEVATION_TYPE_LIMITED:
        return False
    # A normal standard account need not contain the Administrators SID. A
    # linked limited administrator token MUST contain it as deny-only.
    if admin is None:
        return not require_limited
    return (type(admin) is int and admin >= 0
            and bool(admin & GROUP_DENY_ONLY) and not bool(admin & GROUP_ENABLED))


def same_identity(candidate, parent):
    return (candidate.get("sid") == parent.get("sid")
            and candidate.get("session_id") == parent.get("session_id"))


def choose_mode(parent, compartment):
    if type(compartment) is not int or compartment != 1:
        raise GateFailure("parent_not_default_compartment")
    if token_is_ordinary(parent):
        return "current_ordinary_token"
    if (parent.get("elevated") is True
            and type(parent.get("elevation_type")) is int
            and parent["elevation_type"] in (TOKEN_ELEVATION_TYPE_DEFAULT, TOKEN_ELEVATION_TYPE_FULL)
            and parent.get("appcontainer") is False and parent.get("appcontainer_sid") is None
            and type(parent.get("token_type")) is int and parent["token_type"] == 1):
        return "existing_linked_limited_token"
    raise GateFailure("parent_neither_ordinary_nor_split_token_elevated")


def validate_linked(linked, parent):
    if not token_is_ordinary(linked, require_limited=True):
        raise GateFailure("linked_token_not_ordinary_limited")
    if not same_identity(linked, parent):
        raise GateFailure("linked_token_user_or_session_mismatch")


def safe_identity(identity, parent=None):
    """Exclude account SIDs, usernames, local paths, and arbitrary strings."""
    fields = ("session_id", "token_type", "elevation_type", "elevated", "integrity_rid",
              "admin_attributes", "appcontainer", "capability_count", "ui_access")
    result = {key: identity[key] for key in fields}
    result["appcontainer_sid_absent"] = identity["appcontainer_sid"] is None
    if parent is not None:
        result["same_user"] = identity["sid"] == parent["sid"]
        result["same_session"] = identity["session_id"] == parent["session_id"]
    return result


def checked_path(path, *, inside=None, is_file=True):
    """Reject every existing alias/reparse component before resolving paths."""
    path = Path(os.path.abspath(path))
    for component in (path, *path.parents):
        info = component.lstat()
        if stat.S_ISLNK(info.st_mode) or getattr(info, "st_file_attributes", 0) & 0x400:
            raise GateFailure("reparse_or_symlink_path")
    resolved = path.resolve(strict=True)
    if inside is not None and resolved != inside and inside not in resolved.parents:
        raise GateFailure("path_outside_owned_root")
    if is_file and not resolved.is_file():
        raise GateFailure("expected_regular_file")
    if not is_file and not resolved.is_dir():
        raise GateFailure("expected_directory")
    return resolved


def validate_inputs(args):
    root = checked_path(ROOT, is_file=False)
    script = checked_path(PROBE, inside=root)
    # Fixed local dependencies, not imports selected through PATH/PYTHONPATH.
    for relative in (".github/windows_identity_proof.py", ".github/windows_psec_compartment_smoke.py",
                     "ruleproxy/windows_app_process.py"):
        checked_path(root / relative, inside=root)
    runtime = checked_path(sys.base_prefix, is_file=False)
    python = checked_path(sys.executable, inside=runtime)
    if python.name.casefold() != "python.exe":
        raise GateFailure("expected_existing_python_runtime")
    actor = checked_path(args.actor, inside=root)
    if actor.name != "windows_identity_actor.exe" or not 512 <= actor.stat().st_size <= 8 * 1024 * 1024:
        raise GateFailure("expected_bounded_native_identity_actor")
    if not isinstance(args.actor_sha256, str) or not DIGEST_PATTERN.fullmatch(args.actor_sha256):
        raise GateFailure("invalid_actor_sha256")
    with actor.open("rb") as stream:
        actor_bytes = stream.read(8 * 1024 * 1024 + 1)
    if not 512 <= len(actor_bytes) <= 8 * 1024 * 1024:
        raise GateFailure("native_actor_size_changed")
    if actor_bytes[:2] != b"MZ" or hashlib.sha256(actor_bytes).hexdigest() != args.actor_sha256:
        raise GateFailure("native_actor_digest_mismatch")
    # A single new directory within the checkout, never an arbitrary system or
    # pre-existing directory. Its existing parent must have no aliases.
    raw_work = Path(os.path.abspath(args.work))
    # First bind the report to the caller's exact fresh-work spelling. Resolve
    # only the existing parent after its no-reparse checks: Windows can expand
    # a legitimate 8.3 name into a different canonical long-path spelling.
    if Path(os.path.abspath(args.report)) != raw_work / "report.json":
        raise GateFailure("report_must_be_work_report_json")
    parent = checked_path(raw_work.parent, inside=root, is_file=False)
    work = parent / raw_work.name
    if root not in work.parents or work.exists() or work.is_symlink():
        raise GateFailure("fresh_owned_work_directory_required")
    return python, script, actor, work


def fixed_command(python, script, actor, digest, work):
    """No shell, -c argument, module name, or caller-supplied command."""
    return [str(python), "-I", "-S", "-B", str(script),
            "--disposable-ci", "--approved-security-test",
            "--actor", str(actor), "--actor-sha256", digest,
            "--work", str(work / "probe"), "--report", str(work / "probe/report.json")]


class SIDAndAttributes(C.Structure):
    _fields_ = [("Sid", H), ("Attributes", D)]


class TokenGroups(C.Structure):
    _fields_ = [("GroupCount", D), ("Groups", SIDAndAttributes * 1)]


class SecurityAttributes(C.Structure):
    _fields_ = [("length", D), ("security", H), ("inherit", C.c_int)]


class NativeAPI:
    """Loaded only inside the explicitly approved Windows runtime path."""

    def __init__(self):
        spec = importlib.util.spec_from_file_location("ordinary_launcher_process",
                                                     ROOT / "ruleproxy/windows_app_process.py")
        self.proc = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(self.proc)
        self.base = self.proc._KernelAPI()
        self.k, self.a = self.base.kernel, self.base.advapi
        self.ip = C.WinDLL("iphlpapi", use_last_error=True)
        for owner, name, args, result in (
            (self.a, "CreateProcessAsUserW",
             [H, P, P, H, H, C.c_int, D, H, P, H, C.POINTER(self.proc._ProcessInfo)], C.c_int),
            (self.a, "ConvertSidToStringSidW", [H, C.POINTER(P)], C.c_int),
            (self.k, "QueryFullProcessImageNameW", [H, D, P, C.POINTER(D)], C.c_int),
            (self.k, "IsProcessInJob", [H, H, C.POINTER(C.c_int)], C.c_int),
            (self.k, "GetWindowsDirectoryW", [P, D], D),
            (self.k, "CreateFileW", [P, D, D, H, D, D, H], H),
            (self.k, "QueryInformationJobObject", [H, C.c_int, H, D, C.POINTER(D)], C.c_int),
            (self.ip, "GetCurrentThreadCompartmentId", [], D),
        ):
            fn = getattr(owner, name)
            fn.argtypes, fn.restype = args, result

    @staticmethod
    def check(ok, operation):
        if not ok:
            raise NativeFailure(operation, C.get_last_error())

    def close(self, handle):
        self.check(self.k.CloseHandle(handle), "CloseHandle")

    def token_for_process(self, process):
        token = H()
        self.check(self.a.OpenProcessToken(process, TOKEN_QUERY, C.byref(token)), "OpenProcessToken")
        return token.value

    def current_token(self):
        return self.token_for_process(self.k.GetCurrentProcess())

    def compartment(self):
        return int(self.ip.GetCurrentThreadCompartmentId())

    def query(self, token, kind, name):
        size = D()
        C.set_last_error(0)
        ok = self.a.GetTokenInformation(token, kind, None, 0, C.byref(size))
        code = C.get_last_error()
        if ok or code != 122:
            raise NativeFailure("GetTokenInformation(" + name + ")", code)
        if not 1 <= size.value <= 65536:
            raise GateFailure("invalid_token_information_size")
        buffer = C.create_string_buffer(size.value)
        self.check(self.a.GetTokenInformation(token, kind, buffer, len(buffer), C.byref(size)),
                   "GetTokenInformation(" + name + ")")
        if size.value > len(buffer):
            raise GateFailure("token_information_length_changed")
        return buffer, size.value

    def scalar(self, token, kind, name):
        buffer, size = self.query(token, kind, name)
        if size != C.sizeof(D):
            raise GateFailure("invalid_token_scalar_size")
        return D.from_buffer(buffer).value

    def sid_text(self, pointer):
        text = P()
        self.check(self.a.ConvertSidToStringSidW(pointer, C.byref(text)), "ConvertSidToStringSidW")
        try:
            if not text.value or not SID_PATTERN.fullmatch(text.value):
                raise GateFailure("invalid_native_sid")
            return text.value
        finally:
            self.k.LocalFree(C.cast(text, H))

    def sid_field(self, token, kind, name, *, nullable=False):
        buffer, size = self.query(token, kind, name)
        if size < C.sizeof(H):
            raise GateFailure("invalid_sid_information_size")
        pointer = H.from_buffer(buffer).value
        if not pointer:
            if nullable:
                return None
            raise GateFailure("missing_native_sid")
        return self.sid_text(pointer)

    def groups(self, token, kind, name):
        buffer, size = self.query(token, kind, name)
        if size < C.sizeof(D):
            raise GateFailure("invalid_token_groups_size")
        count = D.from_buffer(buffer).value
        start = TokenGroups.Groups.offset
        if count > 1024 or (count and start + count * C.sizeof(SIDAndAttributes) > size):
            raise GateFailure("invalid_token_groups_count")
        entries = []
        for index in range(count):
            group = SIDAndAttributes.from_buffer(buffer, start + index * C.sizeof(SIDAndAttributes))
            entries.append((self.sid_text(group.Sid), group.Attributes))
        return entries

    def identity(self, token):
        groups = self.groups(token, 2, "TokenGroups")
        administrators = [attributes for sid, attributes in groups if sid == ADMIN_SID]
        if len(administrators) > 1:
            raise GateFailure("duplicate_administrators_group")
        integrity = self.sid_field(token, 25, "TokenIntegrityLevel")
        if not re.fullmatch(r"S-1-16-[0-9]+", integrity):
            raise GateFailure("unexpected_integrity_sid")
        result = {
            "sid": self.sid_field(token, 1, "TokenUser"),
            "session_id": self.scalar(token, 12, "TokenSessionId"),
            "token_type": self.scalar(token, 8, "TokenType"),
            "elevation_type": self.scalar(token, 18, "TokenElevationType"),
            "integrity_rid": int(integrity.rsplit("-", 1)[1]),
            "admin_attributes": administrators[0] if administrators else None,
            "appcontainer_sid": self.sid_field(token, 31, "TokenAppContainerSid", nullable=True),
            "capability_count": len(self.groups(token, 30, "TokenCapabilities")),
        }
        for key, kind, name in (("elevated", 20, "TokenElevation"),
                                ("appcontainer", 29, "TokenIsAppContainer"), ("ui_access", 26, "TokenUIAccess")):
            value = self.scalar(token, kind, name)
            if value not in (0, 1):
                raise GateFailure("invalid_token_boolean")
            result[key] = bool(value)
        return result

    def linked_token(self, token):
        # This API returns an existing owned token handle. Never duplicate,
        # restrict, fabricate, adjust, or set fields on either token.
        linked, size = H(), D()
        self.check(self.a.GetTokenInformation(token, 19, C.byref(linked), C.sizeof(linked), C.byref(size)),
                   "GetTokenInformation(TokenLinkedToken)")
        if not linked.value:
            raise GateFailure("missing_existing_linked_token")
        if size.value != C.sizeof(linked):
            self.close(linked.value)
            raise GateFailure("invalid_linked_token_size")
        return linked.value

    def process_info(self):
        return self.proc._ProcessInfo()

    def create_job(self):
        job = self.k.CreateJobObjectW(None, None)
        self.check(job, "CreateJobObjectW")
        try:
            limits = self.proc._JobExtendedLimitInfo()
            limits.BasicLimitInformation.LimitFlags = KILL_ON_JOB_CLOSE
            self.check(self.k.SetInformationJobObject(job, 9, C.byref(limits), C.sizeof(limits)),
                       "SetInformationJobObject")
            actual = self.proc._JobExtendedLimitInfo()
            self.check(self.k.QueryInformationJobObject(job, 9, C.byref(actual), C.sizeof(actual), None),
                       "QueryInformationJobObject")
            if actual.BasicLimitInformation.LimitFlags != KILL_ON_JOB_CLOSE:
                raise GateFailure("job_not_kill_on_close_non_breakaway")
            return job
        except BaseException:
            self.close(job)
            raise

    def open_stdio_file(self, path, *, read=False):
        sa = SecurityAttributes(C.sizeof(SecurityAttributes), None, True)
        # CREATE_NEW; no sharing. Only these fresh, owned files are inherited.
        handle = self.k.CreateFileW(str(path), 0x80000000 if read else 0x40000000,
                                   0, C.byref(sa), 1, 0x80, None)
        if handle == H(-1).value:
            raise NativeFailure("CreateFileW(owned_stdio)", C.get_last_error())
        return handle

    def environment(self, work):
        buffer = C.create_unicode_buffer(32768)
        size = self.k.GetWindowsDirectoryW(buffer, len(buffer))
        if not 0 < size < len(buffer):
            raise GateFailure("native_windows_directory_unavailable")
        return self.proc._environment_block({
            "SystemRoot": buffer.value, "WINDIR": buffer.value,
            "TEMP": str(work / "temp"), "TMP": str(work / "temp"),
        })

    def create_suspended(self, info, command, work, stdio, token):
        size = C.c_size_t()
        self.k.InitializeProcThreadAttributeList(None, 1, 0, C.byref(size))
        if not 1 <= size.value <= 65536:
            raise GateFailure("invalid_process_attribute_size")
        attributes = C.create_string_buffer(size.value)
        self.check(self.k.InitializeProcThreadAttributeList(attributes, 1, 0, C.byref(size)),
                   "InitializeProcThreadAttributeList")
        try:
            handles = (H * 3)(*stdio)
            self.check(self.k.UpdateProcThreadAttribute(attributes, 0, 0x20002, handles,
                                                        C.sizeof(handles), None, None),
                       "UpdateProcThreadAttribute(handle_list)")
            startup = self.proc._StartupInfoEx()
            startup.StartupInfo.cb = C.sizeof(startup)
            startup.StartupInfo.dwFlags = 0x100  # STARTF_USESTDHANDLES
            startup.StartupInfo.hStdInput, startup.StartupInfo.hStdOutput, startup.StartupInfo.hStdError = stdio
            startup.lpAttributeList = C.cast(attributes, H)
            # No desktop selection or ACL fallback. No breakaway flag.
            flags = (self.proc._CREATE_SUSPENDED | self.proc._CREATE_UNICODE_ENVIRONMENT
                     | self.proc._EXTENDED_STARTUPINFO_PRESENT | 0x08000000)  # CREATE_NO_WINDOW
            commandline = C.create_unicode_buffer(subprocess.list2cmdline(command))
            env = C.create_unicode_buffer(self.environment(work))
            arguments = (command[0], commandline, None, None, True, flags,
                         env, str(work), C.byref(startup), C.byref(info))
            if token is None:
                self.check(self.k.CreateProcessW(*arguments), "CreateProcessW")
            else:
                self.check(self.a.CreateProcessAsUserW(token, *arguments), "CreateProcessAsUserW")
        finally:
            self.k.DeleteProcThreadAttributeList(attributes)

    def assign_job(self, job, process):
        self.check(self.k.AssignProcessToJobObject(job, process), "AssignProcessToJobObject")

    def verify_job(self, job, process):
        value = C.c_int()
        self.check(self.k.IsProcessInJob(process, job, C.byref(value)), "IsProcessInJob")
        if not value.value:
            raise GateFailure("child_not_in_owned_job")

    def child_identity(self, process):
        token = self.token_for_process(process)
        try:
            return self.identity(token)
        finally:
            self.close(token)

    def verify_image(self, process, expected):
        buffer, size = C.create_unicode_buffer(32768), D(32768)
        self.check(self.k.QueryFullProcessImageNameW(process, 0, buffer, C.byref(size)),
                   "QueryFullProcessImageNameW")
        if os.path.normcase(buffer.value) != os.path.normcase(str(expected)):
            raise GateFailure("child_image_not_fixed_python")

    def resume(self, thread):
        result = self.k.ResumeThread(thread)
        if result == 0xFFFFFFFF:
            raise NativeFailure("ResumeThread", C.get_last_error())
        if result != 1:
            raise GateFailure("unexpected_thread_suspend_count")

    def wait(self, process, milliseconds):
        value = self.k.WaitForSingleObject(process, milliseconds)
        if value not in (0, 258):
            raise NativeFailure("WaitForSingleObject", C.get_last_error())
        return value == 0

    def exit_code(self, process):
        value = D()
        self.check(self.k.GetExitCodeProcess(process, C.byref(value)), "GetExitCodeProcess")
        return value.value

    def terminate_job(self, job):
        self.check(self.k.TerminateJobObject(job, 1), "TerminateJobObject")

    def terminate_process(self, process):
        self.check(self.k.TerminateProcess(process, 1), "TerminateProcess")


def launch_owned(api, command, work, expected, parent, *, token=None):
    """Single lifecycle with testable failure cleanup, including pre-assignment."""
    info, job, stdio, assigned = api.process_info(), None, [], False
    result = {"started": False, "resumed": False, "timed_out": False,
              "nested_resource_cleanup_incomplete": False,
              "cleanup": {"errors": [], "job_closed": False, "handles_closed": False}}
    try:
        job = api.create_job()
        for filename in ("controller.stdin", "controller.stdout", "controller.stderr"):
            stdio.append(api.open_stdio_file(work / filename, read=filename.endswith("stdin")))
        api.create_suspended(info, command, work, stdio, token)
        result.update(started=True, child_pid=int(info.dwProcessId))
        api.assign_job(job, info.hProcess)
        assigned = True
        api.verify_job(job, info.hProcess)
        api.verify_image(info.hProcess, command[0])
        child = api.child_identity(info.hProcess)
        if not token_is_ordinary(child, require_limited=token is not None) or not same_identity(child, expected):
            raise GateFailure("child_token_mismatch_before_resume")
        result["child_identity"] = safe_identity(child, parent)
        result["native_identity_verified_before_resume"] = True
        # Mark uncertainty before the call: an unexpected suspend count can
        # mean that a thread ran even if ResumeThread did not return 1.
        result["nested_resource_cleanup_incomplete"] = True
        api.resume(info.hThread)
        result["resumed"] = True
        if not api.wait(info.hProcess, RUN_MILLISECONDS):
            result["timed_out"] = True
            raise GateFailure("bounded_probe_deadline")
        result["exit_code"] = api.exit_code(info.hProcess)
    except Exception as exc:
        result["error"] = failure(exc)
    finally:
        cleanup = result["cleanup"]

        def attempt(operation):
            try:
                operation()
                return True
            except Exception as exc:
                cleanup["errors"].append(failure(exc))
                return False

        if info.hProcess:
            if assigned:
                attempt(lambda: api.terminate_job(job))
                # Closing the owned job is also the fail-safe when termination
                # reports an error; never leave a live child with only a PID.
                if job and attempt(lambda: api.close(job)):
                    cleanup["job_closed"] = True
                    job = None
            else:
                attempt(lambda: api.terminate_process(info.hProcess))

            def await_exit():
                if not api.wait(info.hProcess, 5000):
                    raise GateFailure("cleanup_process_wait_deadline")
            attempt(await_exit)
        if job and attempt(lambda: api.close(job)):
            cleanup["job_closed"] = True
        closed = True
        for handle in (info.hThread, info.hProcess, *reversed(stdio)):
            if handle:
                closed = attempt(lambda handle=handle: api.close(handle)) and closed
        cleanup["handles_closed"] = closed
    return result


def read_probe(path):
    checked_path(path, inside=path.parent)
    with path.open("rb") as stream:
        raw = stream.read(MAX_REPORT + 1)
    if len(raw) > MAX_REPORT:
        raise GateFailure("probe_report_too_large")
    value = json.loads(raw)
    if not isinstance(value, dict):
        raise GateFailure("probe_report_not_object")
    return value


def save_report(path, report):
    # Private paths and raw subprocess diagnostics never reach stdout.
    data = (json.dumps(report, ensure_ascii=True, indent=2) + "\n").encode("ascii")
    if len(data) > MAX_REPORT:
        raise GateFailure("launcher_report_too_large")
    with path.open("xb") as stream:
        stream.write(data)


def run(args):
    if os.name != "nt" or not args.disposable_ci or not args.approved_security_test:
        raise PermissionError("requires an explicitly approved disposable Windows security test")
    python, script, actor, work = validate_inputs(args)
    work.mkdir()
    (work / "temp").mkdir()
    report = {"schema_version": 1, "stage": "ordinary-user-stage0b-launcher",
              "network_tested": False, "product_acceptance": False, "privacy_qualified": False,
              "actor_sha256": args.actor_sha256, "probe_report": "probe/report.json",
              "stage0b_passed": False, "launcher_passed": False,
              "nested_resource_cleanup_incomplete": False,
              "cleanup": {"token_handles_closed": False, "errors": []}}
    api, current, linked = None, None, None
    try:
        api = NativeAPI()
        current = api.current_token()
        parent = api.identity(current)
        mode = choose_mode(parent, api.compartment())
        report.update(mode=mode, parent_identity=safe_identity(parent), parent_compartment=1)
        expected = parent
        if mode == "existing_linked_limited_token":
            linked = api.linked_token(current)
            expected = api.identity(linked)
            validate_linked(expected, parent)
            report["linked_identity"] = safe_identity(expected, parent)
        command = fixed_command(python, script, actor, args.actor_sha256, work)
        report["launch"] = launch_owned(api, command, work, expected, parent, token=linked)
        launch = report["launch"]
        report["nested_resource_cleanup_incomplete"] = launch["nested_resource_cleanup_incomplete"]
        if launch.get("resumed") is True and launch.get("timed_out") is False:
            value = read_probe(work / "probe/report.json")
            # Re-evaluate the existing Stage 0b evidence; never trust its boolean
            # alone and never remove or relax its ordinary-user entry gate.
            spec = importlib.util.spec_from_file_location("ordinary_stage0b_verifier", PROBE)
            probe = importlib.util.module_from_spec(spec)
            spec.loader.exec_module(probe)
            identity = value.get("controller_identity", {})
            same_controller = (
                identity.get("sid") == expected["sid"]
                and identity.get("pid") == launch.get("child_pid")
                and identity.get("elevated") is False and identity.get("appcontainer") is False
                and type(identity.get("cid")) is int and identity["cid"] == 1)
            checks = probe.checks(value)
            if same_controller and checks["cleanup"] is True:
                report["nested_resource_cleanup_incomplete"] = False
                launch["nested_resource_cleanup_incomplete"] = False
            report["stage0b_passed"] = (
                "error" not in launch and launch.get("exit_code") == 0
                and launch.get("native_identity_verified_before_resume") is True
                and value.get("stage0b_passed") is True and all(checks.values())
                and same_controller)
    except Exception as exc:
        report["error"] = failure(exc)
    finally:
        for handle in (linked, current):
            if handle:
                try:
                    api.close(handle)
                except Exception as exc:
                    report["cleanup"]["errors"].append(failure(exc))
        report["cleanup"]["token_handles_closed"] = not report["cleanup"]["errors"]
    launch = report.get("launch", {})
    cleanup = launch.get("cleanup", {})
    report["launcher_passed"] = (
        report["stage0b_passed"] and "error" not in report and "error" not in launch
        and cleanup.get("job_closed") is True and cleanup.get("handles_closed") is True
        and not cleanup.get("errors") and report["cleanup"]["token_handles_closed"])
    report["status"] = "passed" if report["launcher_passed"] else "blocked_or_failed"
    save_report(work / "report.json", report)
    return 0 if report["launcher_passed"] else 1


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--disposable-ci", action="store_true")
    parser.add_argument("--approved-security-test", action="store_true")
    for name in ("actor", "work", "report"):
        parser.add_argument("--" + name, type=Path, required=True)
    parser.add_argument("--actor-sha256", required=True)
    return run(parser.parse_args(argv))


if __name__ == "__main__":
    raise SystemExit(main())
