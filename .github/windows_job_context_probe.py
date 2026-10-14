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
import json
import os
from pathlib import Path
import re
import subprocess
import tempfile

MAX_CONFIG_BYTES = 32768
MAX_REPORT_BYTES = 8192
SCOPE = "actual_test_app_wrapper_innermost_job"
FLAGS = frozenset({"--headless=new", "--dump-dom", "--disable-gpu", "--new-window",
    "--no-default-browser-check", "--disable-quic", "--disable-background-networking",
    "--force-webrtc-ip-handling-policy=disable_non_proxied_udp", "--no-first-run", "--restore-last-session"})


class BasicUIRestrictions(ctypes.Structure):
    _fields_ = [("UIRestrictionsClass", ctypes.c_uint32)]


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
    if (not isinstance(value, dict) or set(value) != {"schema_version", "nonce", "command", "proxy_port", "profile"}
            or type(value["schema_version"]) is not int or value["schema_version"] != 1
            or not isinstance(value["nonce"], str) or not re.fullmatch(r"[0-9a-f]{64}", value["nonce"])
            or type(value["proxy_port"]) is not int or not 1 <= value["proxy_port"] <= 65535
            or not isinstance(value["profile"], str) or "\0" in value["profile"]):
        raise ValueError("invalid fixed diagnostic configuration")
    profile = Path(value["profile"])
    if not profile.is_absolute() or not profile.is_dir():
        raise ValueError("an existing absolute test profile is required")
    profile = profile.resolve(strict=True)
    command_file, report_file = Path(command_file), Path(report_file)
    if (command_file.parent.resolve(strict=True) != profile or report_file.parent.resolve(strict=True) != profile
            or command_file.resolve() == report_file.resolve() or report_file.resolve() == Path(__file__).resolve()
            or report_file.suffix != ".json"):
        raise ValueError("configuration and report must stay in the test profile")
    if report_file.exists() and (report_file.is_symlink() or getattr(report_file.lstat(), "st_file_attributes", 0) & 0x400):
        raise ValueError("report cannot be a reparse point")
    command = value["command"]
    if (not isinstance(command, list) or not 5 <= len(command) <= 128
            or any(not isinstance(arg, str) or not arg or "\0" in arg for arg in command)
            or sum(map(len, command)) > 16384):
        raise ValueError("invalid bounded Edge command")
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
            matches = data == enforced[option]
            if option == "--user-data-dir":
                try:
                    location = Path(data)
                    matches = location.is_absolute() and location.resolve(strict=True) == profile
                except (OSError, ValueError):
                    matches = False
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
            raise ValueError("a command argument is outside the fixed Edge fixture")
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


def main(arguments=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--command", required=True, type=Path)
    parser.add_argument("--report", required=True, type=Path)
    args = parser.parse_args(arguments)
    try:
        value = read_configuration(args.command)
        command = validate_configuration(value, args.command, args.report)
    except Exception as exc:
        print(f"Job context diagnostic rejected input ({type(exc).__name__})", flush=True)
        return 1
    report = {"schema_version": 1, "nonce": value["nonce"], "scope": SCOPE,
        "pid": os.getpid(), "parent_pid": os.getppid(), "job_context": query_job_context(),
        "edge_launched": False, "edge_exit_code": None, "edge_exit_code_hex": None, "edge_launch_error": None,
        "acceptance_passed": False, "browser_sandbox_weakened": False}
    write_report(args.report, report)
    if os.name != "nt":
        return 3
    try:
        process = subprocess.Popen(command, shell=False, stdin=subprocess.DEVNULL, close_fds=True)
        report["edge_launched"] = True
        write_report(args.report, report)
        code = process.wait()  # The existing PSEC guardian owns timeout/cleanup.
        report.update(edge_exit_code=code & 0xFFFFFFFF, edge_exit_code_hex=f"0x{code & 0xffffffff:08X}")
        result = signed_exit_code(code)
    except Exception as exc:
        report["edge_launch_error"] = type(exc).__name__
        result = 1
    write_report(args.report, report)
    return result


if __name__ == "__main__":
    raise SystemExit(main())
