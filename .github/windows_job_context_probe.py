"""Observe the actual test-app wrapper's immediate job, then run stock Edge.

Copy this stdlib-only file into the existing test profile. Querying NULL returns
the caller's immediate job, not all ancestors or an independently verified PSEC
job. No job, token, filesystem grant, sandbox flag or network setting is changed.
The owned PSEC guardian supplies the outer timeout and cleanup; this wrapper
waits for Edge naturally and never terminates a process.
"""
from __future__ import annotations

import argparse
import ctypes
import importlib.util
import json
import ntpath
import os
from pathlib import Path
import re
import subprocess
import sys
import tempfile

MAX_CONFIG_BYTES = 32768
MAX_REPORT_BYTES = 8192
SCOPE = "actual_test_app_wrapper_innermost_job"
FLAGS = frozenset({"--headless=new", "--dump-dom", "--disable-gpu", "--new-window",
    "--no-default-browser-check", "--disable-quic", "--disable-background-networking",
    "--force-webrtc-ip-handling-policy=disable_non_proxied_udp", "--no-first-run", "--restore-last-session"})
FAILURE_STAGES = frozenset({"read_config", "validate_schema", "validate_profile_exists", "validate_profile_resolve",
    "validate_report_parent", "validate_report_identity", "validate_report_reparse", "validate_command",
    "validate_executable", "validate_user_data_dir", "validate_proxy_server", "validate_proxy_bypass",
    "validate_argument", "validate_required_arguments", "query_job", "publish_initial", "launch",
    "publish_started", "wait", "publish_result", "validate_directory_close"}) | frozenset(
    f"{role}_{operation}" for role in ("validate_profile", "validate_config_parent", "validate_report_parent",
                                      "validate_report_file", "validate_config_file", "validate_script_file",
                                      "validate_user_data_dir")
    for operation in ("open", "attributes", "identity", "opened_name"))


def failure_facts(exc, stage):
    stage = getattr(exc, "_job_context_stage", stage)
    if stage not in FAILURE_STAGES:
        stage = "validate_schema"
    cause = exc.__cause__ if isinstance(exc.__cause__, OSError) else exc
    facts = {"stage": stage, "errno": None, "winerror": None, "class": type(cause).__name__[:80]}
    for key in ("errno", "winerror"):
        code = getattr(cause, key, None)
        if type(code) is int and -0x80000000 <= code <= 0xffffffff:
            facts[key] = code
    return facts


def publish_failure(exc, stage):
    print(json.dumps(failure_facts(exc, stage), ensure_ascii=True, separators=(",", ":")), flush=True)


class BasicUIRestrictions(ctypes.Structure):
    _fields_ = [("UIRestrictionsClass", ctypes.c_uint32)]


class FileAttributeTagInfo(ctypes.Structure):
    _fields_ = [("attributes", ctypes.c_uint32), ("reparse_tag", ctypes.c_uint32)]


class FileIdInfo(ctypes.Structure):
    _fields_ = [("volume", ctypes.c_uint64), ("file_id", ctypes.c_ubyte * 16)]


class WindowsPathIdentities:
    """Compare held objects without normalized-name queries or parent grants."""
    def __init__(self, kernel=None, last_error=None, error_factory=None):
        self.kernel = kernel if kernel is not None else ctypes.WinDLL("kernel32", use_last_error=True)
        self.last_error = last_error if last_error is not None else ctypes.get_last_error
        self.error_factory = error_factory if error_factory is not None else ctypes.WinError
        self.handles = []
        self.kernel.CreateFileW.argtypes = [ctypes.c_wchar_p, ctypes.c_uint32, ctypes.c_uint32, ctypes.c_void_p,
                                           ctypes.c_uint32, ctypes.c_uint32, ctypes.c_void_p]
        self.kernel.CreateFileW.restype = ctypes.c_void_p
        self.kernel.GetFileInformationByHandleEx.argtypes = [ctypes.c_void_p, ctypes.c_int32,
                                                           ctypes.c_void_p, ctypes.c_uint32]
        self.kernel.GetFileInformationByHandleEx.restype = ctypes.c_int32
        self.kernel.CloseHandle.argtypes, self.kernel.CloseHandle.restype = [ctypes.c_void_p], ctypes.c_int32

    def __enter__(self):
        return self

    def __exit__(self, kind, error, traceback):
        failure = None
        for handle in list(self.handles):
            if self.kernel.CloseHandle(handle):
                self.handles.remove(handle)
            elif failure is None:
                failure = self.error_factory(self.last_error())
                failure._job_context_stage = "validate_directory_close"
        if failure is not None:
            if error is not None:
                publish_failure(failure, "validate_directory_close")
            else:
                raise failure

    def identity(self, path, role, *, directory=True):
        operation = role + "_open"
        try:
            if not path.is_absolute() or len(self.handles) >= 8:
                raise ValueError("invalid bounded owned path identity request")
            # FILE_READ_ATTRIBUTES; all share modes; no inheritance; existing
            # object; directories supported; open the reparse object itself.
            handle = self.kernel.CreateFileW(str(path), 0x80, 7, None, 3, 0x02000000 | 0x00200000, None)
            if handle in (None, 0, -1, ctypes.c_void_p(-1).value):
                raise self.error_factory(self.last_error())
            self.handles.append(handle)
            operation = role + "_attributes"
            attributes = FileAttributeTagInfo()
            if not self.kernel.GetFileInformationByHandleEx(handle, 9, ctypes.byref(attributes), ctypes.sizeof(attributes)):
                raise self.error_factory(self.last_error())
            if attributes.attributes & 0x400 or bool(attributes.attributes & 0x10) != directory:
                raise ValueError("owned path identity has a reparse point or incorrect object kind")
            operation = role + "_identity"
            info = FileIdInfo()
            if not self.kernel.GetFileInformationByHandleEx(handle, 18, ctypes.byref(info), ctypes.sizeof(info)):
                raise self.error_factory(self.last_error())
            if not any(info.file_id):
                raise ValueError("owned path identity was not available")
            # Equality is the held volume/FileId128 pair, with reparse and
            # object kind checked above. No Mount Manager/name query is needed.
            return info.volume, bytes(info.file_id)
        except Exception as exc:
            exc._job_context_stage = operation
            raise


def use_windows_path_identities():
    return os.name == "nt" and sys.platform == "win32"


def _query_job_context(kernel=None, last_error=None):
    result = {"status": "incomplete", "is_process_in_job": None, "is_process_in_job_error": None,
              "ui_restrictions": None, "query_ui_restrictions_error": None, "query_return_length": None}
    if kernel is None:
        if os.name != "nt":
            return result
        kernel = ctypes.WinDLL("kernel32", use_last_error=True)
    last_error = ctypes.get_last_error if last_error is None else last_error
    kernel.GetCurrentProcess.argtypes, kernel.GetCurrentProcess.restype = [], ctypes.c_void_p
    kernel.IsProcessInJob.argtypes = [ctypes.c_void_p, ctypes.c_void_p, ctypes.POINTER(ctypes.c_int32)]
    kernel.IsProcessInJob.restype = ctypes.c_int32
    kernel.QueryInformationJobObject.argtypes = [ctypes.c_void_p, ctypes.c_int32, ctypes.c_void_p,
                                                ctypes.c_uint32, ctypes.POINTER(ctypes.c_uint32)]
    kernel.QueryInformationJobObject.restype = ctypes.c_int32
    inside = ctypes.c_int32()
    if kernel.IsProcessInJob(kernel.GetCurrentProcess(), None, ctypes.byref(inside)):
        result["is_process_in_job"] = bool(inside.value)
    else:
        result["is_process_in_job_error"] = int(last_error())
    info, length = BasicUIRestrictions(), ctypes.c_uint32()
    if kernel.QueryInformationJobObject(None, 4, ctypes.byref(info), ctypes.sizeof(info), ctypes.byref(length)):
        result["query_return_length"] = int(length.value)
        if result["is_process_in_job"] is True and length.value == ctypes.sizeof(info):
            result.update(status="observed", ui_restrictions=int(info.UIRestrictionsClass))
    else:
        result["query_ui_restrictions_error"] = int(last_error())
    return result


def query_job_context(kernel=None, last_error=None):
    try:
        return _query_job_context(kernel, last_error)
    except Exception as exc:
        return {"status": "incomplete", "is_process_in_job": None, "is_process_in_job_error": None,
                "ui_restrictions": None, "query_ui_restrictions_error": None, "query_return_length": None,
                "error": type(exc).__name__}


def unique_object(pairs):
    value = {}
    for key, item in pairs:
        if key in value:
            raise ValueError("duplicate diagnostic field")
        value[key] = item
    return value


def read_configuration(path):
    path = Path(path)
    attributes = path.lstat()
    if path.is_symlink() or getattr(attributes, "st_file_attributes", 0) & 0x400:
        raise ValueError("configuration must be a regular file")
    with path.open("rb") as source:
        raw = source.read(MAX_CONFIG_BYTES + 1)
    if len(raw) > MAX_CONFIG_BYTES:
        raise ValueError("configuration size limit")
    return json.loads(raw, object_pairs_hook=unique_object)


def validate_configuration(value, command_file, report_file):
    stage = "validate_schema"
    stages = []
    try:
        if use_windows_path_identities():
            with WindowsPathIdentities() as identities:
                return _validate_configuration(value, command_file, report_file, lambda label: stages.append(label), identities)
        return _validate_configuration(value, command_file, report_file, lambda label: stages.append(label))
    except Exception as exc:
        if not hasattr(exc, "_job_context_stage"):
            exc._job_context_stage = stages[-1] if stages else stage
        raise


def _validate_configuration(value, command_file, report_file, progress, identities=None):
    if (not isinstance(value, dict) or set(value) != {"schema_version", "nonce", "command", "proxy_port", "profile"}
            or type(value["schema_version"]) is not int or value["schema_version"] != 1
            or not isinstance(value["nonce"], str) or not re.fullmatch(r"[0-9a-f]{64}", value["nonce"])
            or type(value["proxy_port"]) is not int or not 1 <= value["proxy_port"] <= 65535
            or not isinstance(value["profile"], str) or "\0" in value["profile"]):
        raise ValueError("invalid fixed diagnostic configuration")
    progress("validate_profile_exists")
    profile = Path(value["profile"])
    if not profile.is_absolute() or not profile.is_dir():
        raise ValueError("an existing absolute test profile is required")
    progress("validate_profile_resolve")
    reference = identities.identity(profile, "validate_profile") if identities is not None else profile.resolve(strict=True)
    if identities is None:
        profile = reference
    command_file, report_file = Path(command_file), Path(report_file)
    progress("validate_report_parent")
    if identities is not None:
        same_parent = (identities.identity(command_file.parent, "validate_config_parent") == reference
                       and identities.identity(report_file.parent, "validate_report_parent") == reference)
    else:
        same_parent = command_file.parent.resolve(strict=True) == profile and report_file.parent.resolve(strict=True) == profile
    if not same_parent:
        raise ValueError("configuration and report must stay in the test profile")
    progress("validate_report_identity")
    if identities is not None:
        reserved = (":" in report_file.name or ntpath.normcase(report_file.name) in {
            ntpath.normcase(command_file.name), ntpath.normcase(Path(__file__).name)})
        if report_file.exists() and not reserved:
            report_identity = identities.identity(report_file, "validate_report_file", directory=False)
            reserved = (report_identity == identities.identity(command_file, "validate_config_file", directory=False)
                        or report_identity == identities.identity(Path(__file__), "validate_script_file", directory=False))
    else:
        reserved = command_file.resolve() == report_file.resolve() or report_file.resolve() == Path(__file__).resolve()
    if reserved or report_file.suffix != ".json":
        raise ValueError("configuration and report must stay in the test profile")
    progress("validate_report_reparse")
    if report_file.exists() and (report_file.is_symlink() or getattr(report_file.lstat(), "st_file_attributes", 0) & 0x400):
        raise ValueError("report cannot be a reparse point")
    progress("validate_command")
    command = value["command"]
    if (not isinstance(command, list) or not 5 <= len(command) <= 128
            or any(not isinstance(arg, str) or not arg or "\0" in arg for arg in command)
            or sum(map(len, command)) > 16384):
        raise ValueError("invalid bounded Edge command")
    progress("validate_executable")
    executable = Path(command[0])
    if not executable.is_absolute() or executable.name.casefold() != "msedge.exe" or not executable.is_file():
        raise ValueError("the stock Edge executable is required")
    enforced = {"--user-data-dir": str(profile), "--proxy-server": f"http://127.0.0.1:{value['proxy_port']}",
                "--proxy-bypass-list": "<-loopback>"}
    seen = set()
    pages = []
    for argument in command[1:]:
        option, separator, data = argument.partition("=")
        if option in enforced:
            progress({"--user-data-dir": "validate_user_data_dir", "--proxy-server": "validate_proxy_server",
                      "--proxy-bypass-list": "validate_proxy_bypass"}[option])
            matches = data == enforced[option]
            if option == "--user-data-dir":
                try:
                    location = Path(data)
                    actual = (identities.identity(location, "validate_user_data_dir") if identities is not None
                              else location.resolve(strict=True)) if location.is_absolute() else None
                    matches = actual == reference
                except (OSError, ValueError) as exc:
                    failure = ValueError("prepared profile or proxy was overridden")
                    if hasattr(exc, "_job_context_stage"):
                        failure._job_context_stage = exc._job_context_stage
                    raise failure from exc
            if not separator or option in seen or not matches:
                raise ValueError("prepared profile or proxy was overridden")
            seen.add(option)
        elif argument in FLAGS:
            continue
        elif re.fullmatch(r"http://ruleproxy-browser-fixture\.invalid/phase/[12]", argument):
            pages.append(argument)
        else:
            # This diagnostic accepts only the fixed source-test command, not
            # user switches, launcher hooks, other destinations or shells.
            progress("validate_argument")
            raise ValueError("a command argument is outside the fixed Edge fixture")
    progress("validate_required_arguments")
    if seen != set(enforced) or len(pages) != 1:
        raise ValueError("prepared profile, proxy and fixed fixture page are required")
    return list(command)


def write_report(path, value):
    raw = json.dumps(value, ensure_ascii=True, separators=(",", ":")).encode("ascii")
    if len(raw) > MAX_REPORT_BYTES:
        raise ValueError("diagnostic report size limit")
    temporary = None
    try:
        with tempfile.NamedTemporaryFile(dir=path.parent, prefix=".job-context-", delete=False) as output:
            temporary = Path(output.name)
            output.write(raw)
            output.flush()
            os.fsync(output.fileno())
        os.replace(temporary, path)
    finally:
        if temporary is not None:
            temporary.unlink(missing_ok=True)


def signed_exit_code(value):
    """Keep Windows' DWORD bits when Python SystemExit accepts a signed int."""
    if type(value) is not int or not -(1 << 31) <= value <= 0xFFFFFFFF:
        raise ValueError("invalid Windows process exit code")
    unsigned = value & 0xFFFFFFFF
    return unsigned if unsigned < 0x80000000 else unsigned - 0x100000000


def incomplete_edge_identity(*, source_unavailable=False):
    return {"status": "incomplete", "scope": "borrowed_popen_edge_process_handle", "pid": None,
        "process_created": None, "image_sha256": None, "held_handle_verified": False,
        "error": {"stage": "identity_source" if source_unavailable else "identity_handle",
                  "error_type": "SourceUnavailable" if source_unavailable else "RuntimeError",
                  "errno": None, "winerror": None}}


def capture_edge_identity(process, expected_edge):
    """Load only our adjacent copied source helper, never sys.path or Eventlog."""
    try:
        source = Path(__file__).with_name("ruleproxy-edge-crash-evidence.py")
        if not source.is_absolute():
            return incomplete_edge_identity(source_unavailable=True)
        spec = importlib.util.spec_from_file_location("ruleproxy_contained_edge_generation", source)
        if spec is None or spec.loader is None:
            return incomplete_edge_identity(source_unavailable=True)
        helper = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(helper)
        return helper.validate_identity(helper.capture_held_edge_identity(process, expected_edge))
    except Exception:
        # Identity diagnostics must not replace the actual Edge/Job outcome.
        # No foreign PID is reopened and the borrowed Popen HANDLE is untouched.
        return incomplete_edge_identity(source_unavailable=True)


def main(arguments=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--command", required=True, type=Path)
    parser.add_argument("--report", required=True, type=Path)
    args = parser.parse_args(arguments)
    stage = "read_config"
    try:
        value = read_configuration(args.command)
        stage = "validate_schema"
        command = validate_configuration(value, args.command, args.report)
    except Exception as exc:
        publish_failure(exc, stage)
        return 1
    stage = "query_job"
    try:
        context = query_job_context()
        if context.get("status") == "incomplete":
            code = context.get("query_ui_restrictions_error")
            if code is None:
                code = context.get("is_process_in_job_error")
            if "error" in context or code is not None:
                print(json.dumps({"stage": "query_job", "errno": None, "winerror": code,
                    "class": context.get("error", "Win32ApiFailure")}, ensure_ascii=True, separators=(",", ":")),
                    file=sys.stderr, flush=True)
        report = {"schema_version": 1, "nonce": value["nonce"], "scope": SCOPE,
            "pid": os.getpid(), "parent_pid": os.getppid(), "job_context": context,
            "edge_launched": False, "edge_exit_code": None, "edge_exit_code_hex": None, "edge_launch_error": None,
            "edge_identity": incomplete_edge_identity(),
            "acceptance_passed": False, "browser_sandbox_weakened": False}
        stage = "publish_initial"
        write_report(args.report, report)
    except Exception as exc:
        publish_failure(exc, stage)
        return 1
    if os.name != "nt":
        return 3
    try:
        stage = "launch"
        process = subprocess.Popen(command, shell=False, stdin=subprocess.DEVNULL, close_fds=True)
        report["edge_launched"] = True
        report["edge_identity"] = capture_edge_identity(process, command[0])
        stage = "publish_started"
        write_report(args.report, report)
        stage = "wait"
        code = process.wait()  # The existing PSEC guardian owns timeout/cleanup.
        report.update(edge_exit_code=code & 0xFFFFFFFF, edge_exit_code_hex=f"0x{code & 0xffffffff:08X}")
        result = signed_exit_code(code)
    except Exception as exc:
        publish_failure(exc, stage)
        report["edge_launch_error"] = type(exc).__name__
        result = 1
    try:
        write_report(args.report, report)
    except Exception as exc:
        publish_failure(exc, "publish_result")
        return 1
    return result


if __name__ == "__main__":
    raise SystemExit(main())
