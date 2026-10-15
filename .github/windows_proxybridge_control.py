"""Narrow native-VM probe for the official ProxyBridge 4.1.1 Windows release.

This is diagnostic orchestration, not a product backend.  It installs only the
fixed upstream installer, then speaks the v4.1.1 GUI/service named-pipe protocol
as the ordinary test user.  It never changes host proxy, DNS, firewall, or routes.
"""
from __future__ import annotations

import argparse
import ctypes
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import re
import shutil
import subprocess
import sys
import threading
import time
import urllib.request

BACKEND = "proxybridge"
TAG = "v4.1.1"
COMMIT = "1825f4cbdc3d24bc54fa3def4bce2947f97a18fe"
INSTALLER_NAME = "ProxyBridge-Setup-4.1.1.exe"
INSTALLER_URL = (
    "https://github.com/InterceptSuite/ProxyBridge/releases/download/v4.1.1/"
    "ProxyBridge-Setup-4.1.1.exe"
)
INSTALLER_SIZE = 799792
INSTALLER_SHA256 = "754f45fb31f3953b9b81005090f9a479f89827adb628cf2c76bc4139f673a152"
BUNDLE_FILES = ({
    "name": INSTALLER_NAME,
    "url": INSTALLER_URL,
    "size": INSTALLER_SIZE,
    "sha256": INSTALLER_SHA256,
},)
MAX_REPORT_BYTES = 128 * 1024
MAX_FIXTURE_BYTES = 16 * 1024
PROTOCOL_VERSION = 1
PIPE_CTL = r"\\.\pipe\ProxyBridgeCtl"
PBOP_HELLO = 1
PBOP_ADD_PROXY = 2
PBOP_ADD_RULE = 6
PBOP_SET_LOCALHOST = 13
PBOP_START = 16
PBOP_STOP = 17


def _json_bytes(value: object) -> bytes:
    return (json.dumps(value, sort_keys=True, separators=(",", ":")) + "\n").encode("utf-8")


def _write_report(path: Path, value: dict) -> None:
    data = _json_bytes(value)
    if len(data) > MAX_REPORT_BYTES:
        raise ValueError("Diagnostic report exceeds size bound")
    path.parent.mkdir(parents=True, exist_ok=True)
    temp = path.with_name(path.name + ".tmp")
    temp.write_bytes(data)
    os.replace(temp, path)


def _read_json(path: Path, limit: int) -> dict:
    st = path.lstat()
    if not path.is_file() or path.is_symlink() or getattr(st, "st_file_attributes", 0) & 0x400:
        raise ValueError("Input JSON must be an ordinary file")
    if st.st_size > limit:
        raise ValueError("Input JSON exceeds size bound")
    raw = path.read_bytes()
    if len(raw) > limit:
        raise ValueError("Input JSON exceeds size bound")
    value = json.loads(raw.decode("utf-8"), object_pairs_hook=_strict_object)
    if not isinstance(value, dict):
        raise ValueError("Expected a JSON object")
    return value


def _strict_object(pairs):
    value = {}
    for key, item in pairs:
        if key in value:
            raise ValueError("Duplicate JSON field")
        value[key] = item
    return value


def _powershell_env(base=None):
    # A pwsh 7 caller exports module paths incompatible with Windows PowerShell.
    # These probes use only the built-in Windows modules.
    env = dict(os.environ if base is None else base)
    env["PSModulePath"] = str(Path(env.get("SystemRoot", r"C:\Windows")) /
                              "System32/WindowsPowerShell/v1.0/Modules")
    return env


def _failure_frames(exc):
    frames = []
    current = exc.__traceback__
    while current is not None:
        code = current.tb_frame.f_code
        filename = Path(code.co_filename).name
        if filename in ("windows_sandboxie_control.py", "windows_proxybridge_control.py",
                        "windows_free_backend_fixture.py", "windows_native_dns_probe.py"):
            frames.append({"file": filename, "function": code.co_name[:80], "line": current.tb_lineno})
        current = current.tb_next
    return frames[-8:]


def _sha256(path: Path) -> str:
    h = hashlib.sha256()
    with path.open("rb") as stream:
        while chunk := stream.read(1024 * 1024):
            h.update(chunk)
    return h.hexdigest()


def verify_installer(path: Path) -> dict:
    """Check fixed upstream bytes; caller separately collects Authenticode."""
    st = path.lstat()
    if not path.is_file() or path.is_symlink() or getattr(st, "st_file_attributes", 0) & 0x400:
        raise ValueError("Pinned installer must be an ordinary file")
    size = path.stat().st_size
    digest = _sha256(path)
    if size != INSTALLER_SIZE or digest != INSTALLER_SHA256:
        raise ValueError("ProxyBridge installer does not match the fixed upstream release")
    return {"tag": TAG, "commit": COMMIT, "asset_size": size, "asset_sha256": digest,
            "authenticode_valid": None, "runtime_product_version": None}


def manifest_pins_installer(manifest: dict) -> bool:
    if manifest.get("schema_version") != 1 or manifest.get("backend") != BACKEND:
        return False
    entries = manifest.get("files")
    if not isinstance(entries, list):
        return False
    matches = [item for item in entries if isinstance(item, dict)
               and item.get("path") == f"installers/{INSTALLER_NAME}"]
    return (len(matches) == 1 and matches[0].get("sha256") == INSTALLER_SHA256
            and matches[0].get("size") == INSTALLER_SIZE)


def installer_path(bundle: Path) -> Path:
    return bundle / "installers" / INSTALLER_NAME


def fetch_fixed_bundle(bundle_dir: Path) -> dict:
    """Fetch only the fixed signed upstream installer and verify its immutable digest."""
    bundle_dir.mkdir(parents=True, exist_ok=True)
    target = bundle_dir / INSTALLER_NAME
    request = urllib.request.Request(INSTALLER_URL, headers={"User-Agent": "RuleProxy-diagnostic"})
    with urllib.request.urlopen(request, timeout=60) as response:
        final_host = response.geturl().split("/", 3)[2].lower()
        if final_host not in {"github.com", "release-assets.githubusercontent.com",
                              "objects.githubusercontent.com"}:
            raise ValueError("Installer download left the fixed GitHub release hosts")
        data = response.read(INSTALLER_SIZE + 1)
    if len(data) != INSTALLER_SIZE or hashlib.sha256(data).hexdigest() != INSTALLER_SHA256:
        raise ValueError("Downloaded installer failed the fixed size/SHA-256 pin")
    temp = target.with_name(target.name + ".tmp")
    temp.write_bytes(data)
    os.replace(temp, target)
    return verify_installer(target)


def validate_probe_sid(value: str) -> str:
    if not isinstance(value, str) or not re.fullmatch(r"S-1-(?:[0-9]+-){1,14}[0-9]+", value):
        raise ValueError("A target ordinary-user SID is required for service authorization")
    return value


def validate_fixture_spec(spec: dict) -> dict:
    """Validate the fixture's fixed local and documentation-marker endpoint shape."""
    allowed = {"schema_version", "nonce", "proxy_host", "proxy_port", "origin_host",
               "origin_port", "origin_url", "http_origin_host", "http_origin_port",
               "blocked_tcp_host", "blocked_tcp_port", "udp4_host", "udp4_port",
               "udp6_host", "udp6_port", "public_udp4_host", "public_udp6_host",
               "public_udp_port"}
    if set(spec) - allowed:
        raise ValueError("Unexpected fixture field")
    required = allowed
    if required - set(spec):
        raise ValueError("Fixture is missing required proxy/origin endpoints")
    if (spec["schema_version"] != 1 or not isinstance(spec["nonce"], str)
            or not re.fullmatch(r"[0-9a-f]{32}", spec["nonce"])):
        raise ValueError("Fixture schema or nonce is invalid")
    for key in ("proxy_host", "origin_host", "origin_url", "http_origin_host",
                "blocked_tcp_host", "udp4_host", "udp6_host", "public_udp4_host", "public_udp6_host"):
        if key in spec and (not isinstance(spec[key], str) or not spec[key] or len(spec[key]) > 253
                            or any(ord(ch) < 33 or ord(ch) > 126 for ch in spec[key])):
            raise ValueError("Fixture endpoint host/name is invalid")
    for key in ("proxy_port", "origin_port", "http_origin_port", "blocked_tcp_port", "udp4_port",
                "public_udp_port"):
        if type(spec[key]) is not int or not 1 <= spec[key] <= 65535:
            raise ValueError("Fixture endpoint port is invalid")
    if spec["udp6_port"] is not None and (type(spec["udp6_port"]) is not int
                                             or not 1 <= spec["udp6_port"] <= 65535):
        raise ValueError("Fixture IPv6 UDP port is invalid")
    if (spec["proxy_host"] != "127.0.0.1" or spec["origin_host"] != "ruleproxy-fixture.invalid"
            or spec["http_origin_host"] != "127.0.0.1" or spec["blocked_tcp_host"] != "127.0.0.1"
            or spec["udp4_host"] != "127.0.0.1" or spec["udp6_host"] != "::1"
            or spec["public_udp4_host"] != "198.51.100.17"
            or spec["public_udp6_host"] != "2001:db8::17" or spec["public_udp_port"] != 39017
            or spec["origin_port"] != spec["http_origin_port"]
            or spec["origin_url"] != f"http://ruleproxy-fixture.invalid:{spec['origin_port']}/{spec['nonce']}"):
        raise ValueError("Fixture endpoint is outside the fixed test scope")
    return spec


def encode_u32(value: int) -> bytes:
    if type(value) is not int or not 0 <= value <= 0xFFFFFFFF:
        raise ValueError("Protocol integer is outside uint32")
    return value.to_bytes(4, "little")


def encode_str(value: str | None) -> bytes:
    if value is None:
        return encode_u32(0xFFFFFFFF)
    if not isinstance(value, str):
        raise ValueError("Protocol string must be text or null")
    data = value.encode("utf-8")
    if len(data) > 32768:
        raise ValueError("Protocol string exceeds upstream bound")
    return encode_u32(len(data)) + data


def add_proxy_request(host: str, port: int) -> bytes:
    # pb_proto.h: ADD_PROXY(type=SOCKS5, host, port, username, password, sendDomain)
    return (encode_u32(PBOP_ADD_PROXY) + encode_u32(1) + encode_str(host) + encode_u32(port)
            + encode_str("") + encode_str("") + encode_u32(0))


def add_rule_request(process_name: str, proxy_id: int, *, hosts="*", ports="*", action=0) -> bytes:
    # pb_proto.h: protocol TCP+UDP (2), action PROXY (0), selected endpoint config.
    if not re.fullmatch(r"[A-Za-z0-9_.-]{1,128}", process_name):
        raise ValueError("Process image name is invalid")
    if action not in (0, 1, 2):
        raise ValueError("Rule action is invalid")
    return (encode_u32(PBOP_ADD_RULE) + encode_str(process_name) + encode_str(hosts)
            + encode_str(ports) + encode_str(None) + encode_u32(2) + encode_u32(action)
            + encode_u32(proxy_id))


def _windows_only() -> None:
    if sys.platform != "win32":
        raise RuntimeError("ProxyBridge installation and native probe run only on Windows VMs")


def _is_elevated() -> bool:
    if sys.platform != "win32":
        return False
    return bool(ctypes.windll.shell32.IsUserAnAdmin())


def _add_local_group_sid(group_name: str, user_sid: str) -> bool:
    """Add the future interactive user's SID to the product-created local group."""
    if sys.platform != "win32":
        raise RuntimeError("Local group configuration is Windows-only")
    advapi = ctypes.WinDLL("advapi32", use_last_error=True)
    netapi = ctypes.WinDLL("netapi32", use_last_error=True)
    advapi.ConvertStringSidToSidW.argtypes = [ctypes.c_wchar_p, ctypes.POINTER(ctypes.c_void_p)]
    advapi.ConvertStringSidToSidW.restype = ctypes.c_int
    netapi.NetLocalGroupAddMembers.argtypes = [ctypes.c_wchar_p, ctypes.c_wchar_p,
                                               ctypes.c_ulong, ctypes.c_void_p, ctypes.c_ulong]
    netapi.NetLocalGroupAddMembers.restype = ctypes.c_ulong
    ctypes.windll.kernel32.LocalFree.argtypes = [ctypes.c_void_p]
    ctypes.windll.kernel32.LocalFree.restype = ctypes.c_void_p
    sid_ptr = ctypes.c_void_p()
    if not advapi.ConvertStringSidToSidW(user_sid, ctypes.byref(sid_ptr)):
        raise OSError(ctypes.get_last_error(), "Invalid user SID")
    try:
        class LOCALGROUP_MEMBERS_INFO_0(ctypes.Structure):
            _fields_ = [("lgrmi0_sid", ctypes.c_void_p)]
        member = LOCALGROUP_MEMBERS_INFO_0(sid_ptr)
        status = netapi.NetLocalGroupAddMembers(None, group_name, 0,
                                               ctypes.byref(member), 1)
        # NERR_Success or ERROR_MEMBER_IN_ALIAS means effective membership exists.
        if status not in (0, 1378):
            raise OSError(int(status), "Could not grant the target user service access")
        return status == 0
    finally:
        ctypes.windll.kernel32.LocalFree(sid_ptr)


def _authenticode(installer: Path) -> dict:
    ps = shutil_which("powershell.exe")
    if not ps:
        raise RuntimeError("PowerShell is required to inspect the installer signature")
    script = "$p='" + str(installer).replace("'", "''") + "'; $s=Get-AuthenticodeSignature -LiteralPath $p; [ordered]@{status=[string]$s.Status; subject=[string]$s.SignerCertificate.Subject; thumbprint=[string]$s.SignerCertificate.Thumbprint}|ConvertTo-Json -Compress"
    result = subprocess.run([ps, "-NoProfile", "-NonInteractive", "-Command", script],
                            capture_output=True, text=True, timeout=20, check=False, env=_powershell_env())
    if result.returncode != 0:
        raise RuntimeError("Authenticode signature inspection failed")
    try:
        value = json.loads(result.stdout.strip())
    except (ValueError, json.JSONDecodeError) as exc:
        raise RuntimeError("Authenticode result was malformed") from exc
    subject = value.get("subject", "")
    return {"authenticode_valid": value.get("status") == "Valid",
            "signer_interceptsuite": "interceptsuite" in str(subject).lower(),
            "signer_thumbprint_present": bool(value.get("thumbprint"))}


def _driver_signature_facts() -> dict:
    """Inspect installed WinDivert driver signatures without exporting file paths."""
    ps = shutil.which("powershell.exe")
    if not ps:
        raise RuntimeError("PowerShell is required to inspect installed driver signatures")
    script = ("$svc=Get-CimInstance -ClassName Win32_Service -Filter \"Name='ProxyBridgeSvc'\"; "
              "$status='UnknownError'; "
              "if($null -ne $svc){$m=[regex]::Match([string]$svc.PathName,'^\\s*\"(?<path>[^\"]+)\"'); "
              "if(!$m.Success){$m=[regex]::Match([string]$svc.PathName,"
              "'^\\s*(?<path>.+?\\.exe)(?:\\s|$)',[System.Text.RegularExpressions.RegexOptions]::IgnoreCase)}; "
              "if($m.Success){$p=Join-Path (Split-Path -Parent $m.Groups['path'].Value) 'WinDivert64.sys'; "
              "if(Test-Path -LiteralPath $p -PathType Leaf){$status=[string](Get-AuthenticodeSignature -LiteralPath $p).Status}}}; "
              "ConvertTo-Json -InputObject ([ordered]@{name='WinDivert64';status=$status}) -Compress")
    result = subprocess.run([ps, "-NoProfile", "-NonInteractive", "-Command", script],
                            capture_output=True, text=True, timeout=30, check=False, env=_powershell_env())
    if result.returncode != 0:
        raise RuntimeError("Installed driver signature inspection failed")
    try:
        values = json.loads(result.stdout.strip())
    except (ValueError, json.JSONDecodeError) as exc:
        raise RuntimeError("Driver signature result was malformed") from exc
    return normalize_driver_signature_values(values)


def normalize_driver_signature_values(values) -> dict:
    if isinstance(values, dict):
        values = [values]
    if not isinstance(values, list) or not values:
        raise RuntimeError("Installed WinDivert driver was not found")
    drivers = []
    for value in values:
        name = value.get("name") if isinstance(value, dict) else None
        status = value.get("status") if isinstance(value, dict) else None
        if not isinstance(name, str) or not re.fullmatch(r"[A-Za-z0-9_.-]{1,64}", name):
            raise RuntimeError("Installed driver identity was malformed")
        if status not in ("Valid", "NotSigned", "HashMismatch", "NotTrusted", "UnknownError"):
            status = "UnknownError"
        row = {"name": name, "signature_status": status}
        if value.get("status") != status:
            row["raw_status"] = str(value.get("status"))[:64]
        drivers.append(row)
    return {"status": "Valid" if all(d["signature_status"] == "Valid" for d in drivers)
            else "Invalid", "count": len(drivers), "drivers": drivers}


def _service_install_facts() -> dict:
    """Report bounded SCM facts; ordinary-user probe still verifies live protocol."""
    ps = shutil.which("powershell.exe")
    if not ps:
        raise RuntimeError("PowerShell is required to inspect the installed service")
    script = ("$s=Get-CimInstance -ClassName Win32_Service -Filter \"Name='ProxyBridgeSvc'\"; "
              "$v=if($null -eq $s){[ordered]@{exists=$false;state='unknown';start_type='unknown'}} "
              "else{[ordered]@{exists=$true;state=[string]$s.State;start_type=[string]$s.StartMode}}; "
              "ConvertTo-Json -InputObject $v -Compress")
    result = subprocess.run([ps, "-NoProfile", "-NonInteractive", "-Command", script],
                            capture_output=True, text=True, timeout=20, check=False, env=_powershell_env())
    if result.returncode != 0:
        raise RuntimeError("Service installation inspection failed")
    try:
        value = json.loads(result.stdout.strip())
    except (ValueError, json.JSONDecodeError) as exc:
        raise RuntimeError("Service inspection result was malformed") from exc
    return normalize_service_install(value)


def normalize_service_install(value) -> dict:
    if not isinstance(value, dict) or type(value.get("exists")) is not bool:
        raise RuntimeError("Service inspection result was invalid")
    state = value.get("state", "unknown").lower()
    start = value.get("start_type", "unknown").lower()
    return {"exists": value["exists"],
            "state": state if state in ("running", "stopped", "unknown") else "unknown",
            "start_type": start if start in ("auto", "manual", "disabled", "unknown") else "unknown"}


def shutil_which(command: str) -> str | None:
    return shutil.which(command)


def _write_unavailable(report: Path, phase: str, reason: str) -> int:
    _write_report(report, {"schema_version": 1, "backend": BACKEND, "phase": phase,
                           "status": "unsupported", "source_diagnostic_only": True,
                           "release_eligible": False, "reason": reason})
    return 2


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--phase", choices=("prepare-bundle", "install", "probe"), required=True)
    parser.add_argument("--bundle", type=Path, required=True)
    parser.add_argument("--report", type=Path, required=True)
    parser.add_argument("--manifest", type=Path)
    parser.add_argument("--install-report", type=Path)
    parser.add_argument("--artifacts", type=Path)
    parser.add_argument("--probe-user")
    parser.add_argument("--probe-user-sid")
    parser.add_argument("--fixture-spec", type=Path,
                        help="Reserved for runner compatibility; the probe owns its fixture lifecycle")
    args = parser.parse_args(argv)
    try:
        if args.phase == "prepare-bundle":
            facts = fetch_fixed_bundle(args.bundle)
            _write_report(args.report, {"schema_version": 1, "backend": BACKEND,
                                        "phase": args.phase, "status": "prepared",
                                        "source_diagnostic_only": True, "release_eligible": False,
                                        "installer": facts})
            return 0
        _windows_only()
        if args.phase == "install":
            return install_phase(args)
        return probe_phase(args)
    except Exception as exc:
        # Do not serialize exception text, paths, accounts, or native command output.
        _write_report(args.report, {"schema_version": 1, "backend": BACKEND,
                                    "phase": args.phase, "status": "error",
                                    "source_diagnostic_only": True, "release_eligible": False,
                                    "error_type": type(exc).__name__, "failure_frames": _failure_frames(exc),
                                    "driver_signature": getattr(exc, "driver_signature", None)})
        return 1


def install_phase(args: argparse.Namespace) -> int:
    if not _is_elevated():
        return _write_unavailable(args.report, "install", "administrator_required")
    if (args.manifest is None or args.probe_user_sid is None
            or args.probe_user != "RuleProxyCI"):
        raise ValueError("Install requires the pinned manifest and ordinary-user SID")
    target_sid = validate_probe_sid(args.probe_user_sid)
    installer = installer_path(args.bundle)
    facts = verify_installer(installer)
    signature = _authenticode(installer)
    manifest = _read_json(args.manifest, MAX_REPORT_BYTES)
    if not manifest_pins_installer(manifest):
        raise ValueError("Installer manifest does not match the pinned source and binary")
    run = subprocess.run([str(installer), "/S"], timeout=240, check=False,
                         creationflags=getattr(subprocess, "CREATE_NO_WINDOW", 0))
    if run.returncode != 0:
        raise RuntimeError("Silent installer failed")
    driver_signature = _driver_signature_facts()
    if driver_signature["status"] != "Valid":
        exc = ValueError("Installed WinDivert driver signature is not valid")
        exc.driver_signature = driver_signature
        raise exc
    member = _add_local_group_sid("ProxyBridge Users", target_sid)
    installed_version = _installed_display_version()
    service_install = _service_install_facts()
    if not service_install["exists"] or service_install["state"] not in ("running", "stopped"):
        raise RuntimeError("ProxyBridge service installation state is invalid")
    report = {"schema_version": 1, "backend": BACKEND, "phase": "install", "status": "passed",
              "source_diagnostic_only": True, "diagnostic_only": True,
              "release_eligible": False, "product_acceptance_passed": False,
              "ordinary_user": False, "is_elevated": True,
              "installer_sha256": facts["asset_sha256"], "installer_tag_version": TAG,
              "installer_product_version": installed_version,
              "installer_authenticode_valid": signature["authenticode_valid"],
              "installer_signer_interceptsuite": signature["signer_interceptsuite"],
              "driver_signature": driver_signature,
              "service_install": service_install,
              "installer_exit_code": run.returncode, "target_user_authorized": True,
              "reboot_required": bool(member)}
    _write_report(args.report, report)
    return 0


def probe_phase(args: argparse.Namespace) -> int:
    if args.install_report is None or args.artifacts is None:
        raise ValueError("Probe requires install report and private artifact directory")
    install = _read_json(args.install_report, MAX_REPORT_BYTES)
    if (install.get("status") != "passed" or install.get("backend") != BACKEND
            or install.get("source_diagnostic_only") is not True
            or install.get("release_eligible") is not False
            or install.get("target_user_authorized") is not True
            or install.get("installer_sha256") != INSTALLER_SHA256
            or not isinstance(install.get("driver_signature"), dict)
            or install["driver_signature"].get("status") != "Valid"
            or not isinstance(install.get("service_install"), dict)
            or install["service_install"].get("exists") is not True
            or install["service_install"].get("state") not in ("running", "stopped")):
        raise ValueError("Install evidence does not authorize the ordinary-user probe")
    ordinary_user = _ordinary_user_facts()
    if (not ordinary_user["non_admin"] or not ordinary_user["not_system"]
            or ordinary_user["is_administrator"] or not ordinary_user["proxybridge_group_member"]):
        return _write_unavailable(args.report, "probe", "probe_must_run_as_non_admin_user")
    args.artifacts.mkdir(parents=True, exist_ok=True)
    # The real probe uses the v4.1.1 named-pipe API, not the elevated CLI.  It will
    # only emit bounded aggregate facts; raw fixture endpoints remain private.
    observations = _run_service_probe(args.artifacts, args.bundle)
    build = _windows_build()
    if build["build"] != 26200 or build["ubr"] < 9711:
        raise RuntimeError("Probe OS does not match the fixed Windows 25H2 target")
    cleanup = observations.pop("cleanup", False)
    report = {"schema_version": 1, "backend": BACKEND, "phase": "probe",
              "status": "passed" if cleanup is True else "failed",
              "source_diagnostic_only": True,
              "diagnostic_only": True, "release_eligible": False,
              "product_acceptance_passed": False, "ordinary_user": True,
              "is_elevated": False, "is_administrator": False,
              "windows_build": build["build"], "windows_ubr": build["ubr"],
              "service_protocol_version": PROTOCOL_VERSION, "proxybridge_group_member": True,
              "initial_install_reboot_required": install.get("reboot_required") is True,
              "cleanup": cleanup, "cleanup_proven": cleanup is True,
              "observations": observations}
    _write_report(args.report, report)
    return 0 if cleanup is True else 1


def _ordinary_user_facts() -> dict:
    if sys.platform != "win32":
        raise RuntimeError("Ordinary-user token check is Windows-only")
    class TOKEN_ELEVATION(ctypes.Structure):
        _fields_ = [("TokenIsElevated", ctypes.c_ulong)]
    advapi = ctypes.WinDLL("advapi32", use_last_error=True)
    kernel = ctypes.WinDLL("kernel32", use_last_error=True)
    kernel.GetCurrentProcess.restype = ctypes.c_void_p
    kernel.CloseHandle.argtypes = [ctypes.c_void_p]
    kernel.CloseHandle.restype = ctypes.c_int
    kernel.LocalFree.argtypes = [ctypes.c_void_p]
    kernel.LocalFree.restype = ctypes.c_void_p
    advapi.OpenProcessToken.argtypes = [ctypes.c_void_p, ctypes.c_ulong,
                                        ctypes.POINTER(ctypes.c_void_p)]
    advapi.OpenProcessToken.restype = ctypes.c_int
    advapi.GetTokenInformation.argtypes = [ctypes.c_void_p, ctypes.c_int, ctypes.c_void_p,
                                           ctypes.c_ulong, ctypes.POINTER(ctypes.c_ulong)]
    advapi.GetTokenInformation.restype = ctypes.c_int
    advapi.ConvertStringSidToSidW.argtypes = [ctypes.c_wchar_p, ctypes.POINTER(ctypes.c_void_p)]
    advapi.ConvertStringSidToSidW.restype = ctypes.c_int
    advapi.EqualSid.argtypes = [ctypes.c_void_p, ctypes.c_void_p]
    advapi.EqualSid.restype = ctypes.c_int
    token = ctypes.c_void_p()
    if not advapi.OpenProcessToken(kernel.GetCurrentProcess(), 0x0008,
                                                   ctypes.byref(token)):
        raise ctypes.WinError(ctypes.get_last_error())
    try:
        info = TOKEN_ELEVATION()
        size = ctypes.c_ulong()
        if not advapi.GetTokenInformation(token, 20, ctypes.byref(info),
                                                          ctypes.sizeof(info), ctypes.byref(size)):
            raise ctypes.WinError(ctypes.get_last_error())
        user = ctypes.create_string_buffer(4096)
        if not advapi.GetTokenInformation(token, 1, user, len(user), ctypes.byref(size)):
            raise ctypes.WinError(ctypes.get_last_error())
        sid_ptr = ctypes.cast(user, ctypes.POINTER(ctypes.c_void_p))[0]
        system_sid = ctypes.c_void_p()
        if not advapi.ConvertStringSidToSidW("S-1-5-18", ctypes.byref(system_sid)):
            raise ctypes.WinError(ctypes.get_last_error())
        try:
            is_system = bool(advapi.EqualSid(sid_ptr, system_sid))
        finally:
            ctypes.windll.kernel32.LocalFree(system_sid)
        admins = _lookup_account_sid("BUILTIN\\Administrators")
        group = _lookup_account_sid("ProxyBridge Users")
        return {"non_admin": not bool(info.TokenIsElevated), "not_system": not is_system,
                "is_administrator": _token_has_sid(token, admins),
                "proxybridge_group_member": _token_has_sid(token, group)}
    finally:
        ctypes.windll.kernel32.CloseHandle(token)


def _run_service_probe(artifacts: Path, bundle: Path) -> dict:
    """Perform authenticated service-protocol and bounded socket checks."""
    client = _ServiceClient()
    fixture_obj = None
    engine_started = False
    engine_stopped = False
    fixture_closed = False
    facts = None
    try:
        client.connect()
        module = _fixture_module(bundle)
        fixture_obj = module.Fixture(mihomo_path=bundle / "mihomo" / "mihomo.exe",
                                     directory=artifacts / "fixture")
        fixture_obj.__enter__()
        fixture = validate_fixture_spec(fixture_obj.spec)
        spec_path = fixture_obj.write_spec()
        proxy_id = client.add_proxy(fixture["proxy_host"], fixture["proxy_port"])
        if not proxy_id:
            raise RuntimeError("Service rejected the local SOCKS proxy configuration")
        # Preserve an explicit local SOCKS endpoint bypass to avoid recursive routing.
        bypass = client.add_rule("free-probe.exe", proxy_id, hosts="127.0.0.1",
                                 ports=str(fixture["proxy_port"]), action=1)
        if not bypass:
            raise RuntimeError("Service rejected the local-proxy loop-prevention rule")
        rule_id = client.add_rule("free-probe.exe", proxy_id)
        if not rule_id:
            raise RuntimeError("Service rejected the diagnostic application rule")
        if not client.set_localhost_via_proxy(True):
            raise RuntimeError("Service rejected local-origin routing")
        dns_before = _run_native_dns_control(bundle, artifacts, fixture["nonce"], "outside_before")
        started = client.start()
        if not started:
            raise RuntimeError("Service did not start the packet engine")
        engine_started = True
        # Network requests are executed by isolated child interpreters so their process
        # image matches the selected rule. Results contain only booleans and counts.
        selected = _run_fixture_worker(bundle, spec_path, artifacts, role="parent", selected=True,
                                       nonce=fixture["nonce"])
        unselected = _run_fixture_worker(bundle, spec_path, artifacts, role="child", selected=False,
                                         nonce=fixture["nonce"])
        counts = _safe_snapshot(fixture_obj.snapshot())
        proxy_stop = fixture_obj.stop_proxy()
        after_proxy_stop = _run_fixture_worker(bundle, spec_path, artifacts,
                                               role="child", selected=True, nonce=fixture["nonce"])
        dns_after = _run_native_dns_control(bundle, artifacts, fixture["nonce"], "outside_after")
        engine_stopped = client.stop()
        service_stop_denied = _ordinary_user_stop_service_denied()
        facts = {"service_pipe_authenticated": True, "engine_started": True,
                 "ordinary_user_started_engine": True,
                 "engine_stop_acknowledged": bool(engine_stopped),
                 "per_launch_elevation_requested": False,
                 "ordinary_user_could_not_stop_service": bool(service_stop_denied),
                 "selected_parent_and_child": selected, "unselected_network": unselected,
                 "native_dns_outside_before": dns_before,
                 "native_dns_outside_after": dns_after,
                 "fixture_nonce": fixture["nonce"],
                 "browser_gui": {"status": "not_tested"},
                 "fixture_counts_before_stop": counts,
                 "proxy_stop": {"owned_process_started": proxy_stop.get("owned_process_started") is True,
                                "exited": proxy_stop.get("exited") is True},
                 "after_proxy_stop": after_proxy_stop}
    finally:
        if engine_started and not engine_stopped:
            try:
                engine_stopped = client.stop()
            except Exception:
                engine_stopped = False
        if fixture_obj is not None:
            try:
                fixture_obj.close()
                fixture_closed = True
            except Exception:
                fixture_closed = False
        client.close()
    if facts is None:
        raise RuntimeError("Probe did not produce observations")
    facts["cleanup"] = bool(engine_stopped and fixture_closed)
    facts["host_proxy_dns_route_settings_modified"] = False
    return facts


class _ServiceClient:
    """Minimal bounded client for the upstream PB_PROTO_VERSION=1 GUI pipe API."""
    def __init__(self):
        self._kernel = ctypes.WinDLL("kernel32", use_last_error=True)
        self._kernel.CreateFileW.restype = ctypes.c_void_p
        self._kernel.CreateFileW.argtypes = [ctypes.c_wchar_p, ctypes.c_ulong, ctypes.c_ulong,
                                             ctypes.c_void_p, ctypes.c_ulong, ctypes.c_ulong,
                                             ctypes.c_void_p]
        self._kernel.SetNamedPipeHandleState.argtypes = [ctypes.c_void_p,
                                                         ctypes.POINTER(ctypes.c_ulong),
                                                         ctypes.c_void_p, ctypes.c_void_p]
        self._kernel.SetNamedPipeHandleState.restype = ctypes.c_int
        self._kernel.WriteFile.argtypes = [ctypes.c_void_p, ctypes.c_void_p, ctypes.c_ulong,
                                           ctypes.POINTER(ctypes.c_ulong), ctypes.c_void_p]
        self._kernel.WriteFile.restype = ctypes.c_int
        self._kernel.ReadFile.argtypes = [ctypes.c_void_p, ctypes.c_void_p, ctypes.c_ulong,
                                          ctypes.POINTER(ctypes.c_ulong), ctypes.c_void_p]
        self._kernel.ReadFile.restype = ctypes.c_int
        self._kernel.CloseHandle.argtypes = [ctypes.c_void_p]
        self._kernel.CloseHandle.restype = ctypes.c_int
        self._ctl = ctypes.c_void_p(-1)
        self._evt = ctypes.c_void_p(-1)
        self._event_stop = threading.Event()
        self._event_thread = None

    def _open(self, name: str, access: int):
        handle = self._kernel.CreateFileW(name, access, 0, None, 3, 0, None)
        if handle == ctypes.c_void_p(-1).value:
            raise ctypes.WinError(ctypes.get_last_error())
        return ctypes.c_void_p(handle)

    def connect(self):
        self._ctl = self._open(PIPE_CTL, 0xC0000000)
        self._evt = self._open(r"\\.\pipe\ProxyBridgeEvt", 0x80000000)
        mode = ctypes.c_ulong(2)
        if not self._kernel.SetNamedPipeHandleState(self._evt, ctypes.byref(mode), None, None):
            raise ctypes.WinError(ctypes.get_last_error())
        self._event_thread = threading.Thread(target=self._drain_events, daemon=True)
        self._event_thread.start()
        response = self.call(encode_u32(PBOP_HELLO))
        if response != PROTOCOL_VERSION:
            raise RuntimeError("ProxyBridge service protocol version mismatch")

    def call(self, request: bytes) -> int:
        written = ctypes.c_ulong()
        read = ctypes.c_ulong()
        response = ctypes.create_string_buffer(64)
        if not self._kernel.WriteFile(self._ctl, request, len(request), ctypes.byref(written), None):
            raise ctypes.WinError(ctypes.get_last_error())
        if written.value != len(request) or not self._kernel.ReadFile(self._ctl, response,
                                                                      len(response), ctypes.byref(read), None):
            raise ctypes.WinError(ctypes.get_last_error())
        if read.value < 4:
            raise RuntimeError("ProxyBridge service returned a truncated response")
        return int.from_bytes(response.raw[:4], "little")

    def add_proxy(self, host: str, port: int) -> int:
        return self.call(add_proxy_request(host, port))

    def add_rule(self, image: str, proxy_id: int, *, hosts="*", ports="*", action=0) -> int:
        return self.call(add_rule_request(image, proxy_id, hosts=hosts, ports=ports, action=action))

    def set_localhost_via_proxy(self, value: bool) -> bool:
        self.call(encode_u32(PBOP_SET_LOCALHOST) + encode_u32(int(value)))
        return True

    def start(self) -> bool:
        return bool(self.call(encode_u32(PBOP_START)))

    def stop(self) -> bool:
        return bool(self.call(encode_u32(PBOP_STOP)))

    def close(self):
        self._event_stop.set()
        for handle in (self._evt, self._ctl):
            if handle and handle.value not in (None, ctypes.c_void_p(-1).value):
                self._kernel.CloseHandle(handle)
        if self._event_thread is not None:
            self._event_thread.join(timeout=2)

    def _drain_events(self):
        while not self._event_stop.is_set():
            data = ctypes.create_string_buffer(64 * 1024)
            read = ctypes.c_ulong()
            if not self._kernel.ReadFile(self._evt, data, len(data), ctypes.byref(read), None):
                break


def _fixture_module(bundle: Path):
    candidates = (bundle / "scripts" / "windows_free_backend_fixture.py",
                  bundle / ".github" / "windows_free_backend_fixture.py")
    path = next((candidate for candidate in candidates if candidate.is_file()), None)
    if path is None:
        raise RuntimeError("Pinned synthetic fixture worker is missing")
    spec = importlib.util.spec_from_file_location("windows_free_backend_fixture", path)
    if spec is None or spec.loader is None:
        raise RuntimeError("Could not load the pinned fixture helper")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def _run_fixture_worker(bundle: Path, spec_path: Path, artifacts: Path,
                        *, role: str, selected: bool, nonce: str) -> dict:
    py_dir = bundle / "python"
    python = py_dir / "python.exe"
    worker = next((candidate for candidate in (bundle / "scripts" / "windows_free_backend_fixture.py",
                                                bundle / ".github" / "windows_free_backend_fixture.py")
                   if candidate.is_file()), None)
    if not python.is_file() or worker is None:
        raise RuntimeError("Pinned Python or fixture worker is missing")
    executable = python
    if selected:
        private_python = artifacts / "selected-python-runtime"
        if not private_python.exists():
            shutil.copytree(py_dir, private_python)
        elif not private_python.is_dir() or private_python.is_symlink():
            raise RuntimeError("Private selected-runtime directory is unsafe")
        executable = private_python / "free-probe.exe"
        shutil.copyfile(python, executable)
    report = artifacts / (("selected-" if selected else "unselected-") + role + ".json")
    command = [str(executable), "-I", "-S", str(worker), "--worker", "--spec",
               str(spec_path), "--report", str(report), "--role", role]
    if not selected:
        command.append("--skip-native-dns")
    result = subprocess.run(command, timeout=120, capture_output=True, check=False,
                            creationflags=getattr(subprocess, "CREATE_NO_WINDOW", 0))
    if result.returncode != 0 or not report.is_file():
        return {"status": "failed", "exit_code": result.returncode}
    raw = _read_json(report, MAX_REPORT_BYTES)
    if raw.get("schema_version") != 1 or raw.get("role") != role:
        raise RuntimeError("Fixture worker report schema mismatch")
    return _safe_worker_report(raw, nonce=nonce)


def _run_native_dns_control(bundle: Path, artifacts: Path, nonce: str, role: str) -> dict:
    """Run the pinned system-resolver controls from the unmatched ordinary Python image."""
    if role not in ("outside_before", "outside_after"):
        raise ValueError("Native DNS control role is outside the fixed control scope")
    script = bundle / "scripts" / "windows_native_dns_probe.py"
    python = bundle / "python" / "python.exe"
    if not script.is_file() or not python.is_file():
        raise RuntimeError("Pinned native DNS control helper is missing")
    report = artifacts / ("native-dns-" + role + ".json")
    result = subprocess.run([str(python), "-I", "-S", str(script), "--nonce", nonce,
                             "--role", role, "--report", str(report)],
                            timeout=90, capture_output=True, check=False,
                            creationflags=getattr(subprocess, "CREATE_NO_WINDOW", 0))
    if not report.is_file():
        return {"status": "unavailable", "calls_count": 0,
                "exit_code": result.returncode if -255 <= result.returncode <= 255 else None}
    raw = _read_json(report, MAX_REPORT_BYTES)
    return _safe_native_dns_control(raw, result.returncode, nonce=nonce, role=role)


def _safe_worker_report(report: dict, *, nonce: str | None = None) -> dict:
    allowed = {
        "proxy_http": {"ok", "error_type", "winerror"},
        "proxy_socks": {"ok", "error_type", "winerror"},
        "direct_tcp": {"connected", "error_type", "winerror"},
        "udp4": {"attempted", "send_ok", "error_type", "winerror"},
        "udp6": {"attempted", "send_ok", "error_type", "winerror"},
        "public_udp4": {"attempted", "send_ok", "error_type", "winerror"},
        "public_udp6": {"attempted", "send_ok", "error_type", "winerror"},
    }
    result = {"role": report.get("role") if report.get("role") in ("parent", "child") else "unknown"}
    for name, keys in allowed.items():
        item = report.get(name)
        if not isinstance(item, dict):
            continue
        clean = {}
        for key in keys:
            value = item.get(key)
            if key == "error_type" and isinstance(value, str):
                clean[key] = value if value in ("TimeoutError", "ConnectionError", "OSError",
                                                 "socket.timeout", "gaierror") else "other"
            elif key == "winerror" and type(value) is int and -2147483648 <= value <= 2147483647:
                clean[key] = value
            elif key != "error_type" and type(value) is bool:
                clean[key] = value
        result[name] = clean
    dns = report.get("native_dns")
    if isinstance(dns, dict):
        calls = dns.get("calls")
        role = report.get("role")
        safe_calls = _safe_dns_calls(calls, nonce=nonce, role=role) if isinstance(calls, list) else []
        result["native_dns"] = {"status": dns.get("status") if dns.get("status") in
                                 ("observed", "unavailable") else "unknown",
                                 "calls_count": len(safe_calls), "calls": safe_calls,
                                 "wire_privacy_proven": dns.get("wire_privacy_proven") is True}
    child = report.get("child")
    if isinstance(child, dict):
        result["child"] = _safe_worker_report(child, nonce=nonce)
    return result


def _safe_snapshot(snapshot: dict) -> dict:
    keys = ("proxy_requests", "origin_requests", "direct_connections", "udp4_received", "udp6_received")
    result = {key: snapshot[key] for key in keys
              if type(snapshot.get(key)) is int and 0 <= snapshot[key] <= 1_000_000}
    result["error_count"] = len(snapshot.get("errors", [])) if isinstance(snapshot.get("errors"), list) else 0
    for key in ("udp4_by_role", "udp6_by_role"):
        value = snapshot.get(key)
        if isinstance(value, dict):
            result[key] = {role: n for role, n in value.items()
                           if role in ("parent", "child") and type(n) is int and 0 <= n <= 1_000_000}
    return result


def _safe_dns_calls(calls, *, nonce: str, role: str) -> list[dict]:
    if (not isinstance(nonce, str) or not re.fullmatch(r"[0-9a-f]{32}", nonce)
            or role not in ("parent", "child", "outside_before", "outside_after")):
        return []
    safe_calls = []
    for call in calls[:3]:
        if not isinstance(call, dict):
            continue
        api = call.get("api")
        if api not in ("getaddrinfo", "dns_a", "dns_aaaa"):
            continue
        role_text = role.replace("_", "-")
        expected_qname = f"{nonce}.{api.replace('_', '-')}.{role_text}.ruleproxy-ci.example.com."
        if call.get("qname") != expected_qname:
            continue
        item = {"api": api, "qname": expected_qname, "requested_role": role}
        outcome = call.get("outcome")
        if outcome in ("returned", "deadline", "tool_error"):
            item["outcome"] = outcome
        error = call.get("error")
        if error in ("OSError", "TimeoutError", "ConnectionError", "PermissionError", "ValueError"):
            item["error"] = error
        for key in ("error_stage",):
            value = call.get(key)
            if isinstance(value, str) and re.fullmatch(r"[a-z_]{1,64}", value):
                item[key] = value
        for key in ("setup_error", "cleanup_error"):
            value = call.get(key)
            if value in ("WSAStartup", "WSACleanup", "NativeWorkerCleanupUnproven"):
                item[key] = value
        for key in ("native_completion_proven", "api_returned", "records_present", "records_released",
                    "worker_cleanup_proven", "operation_pending", "default_system_server_list",
                    "server_list_override", "dns_blocked_proven", "acceptance_passed"):
            if type(call.get(key)) is bool:
                item[key] = call[key]
        for key in ("return_code", "query_status", "winerror", "errno", "error_winerror", "error_errno"):
            value = call.get(key)
            if type(value) is int and -(1 << 31) <= value < (1 << 32):
                item[key] = value
        safe_calls.append(item)
    return safe_calls


def _safe_native_dns_control(report: dict, exit_code: int | None, *, nonce: str, role: str) -> dict:
    calls = report.get("calls")
    safe_calls = _safe_dns_calls(calls, nonce=nonce, role=role) if isinstance(calls, list) else []
    status = report.get("status")
    return {"status": status if status in ("native_dns_probe_only", "unsupported", "failed") else "unknown",
            "nonce": nonce, "requested_role": role,
            "calls_count": len(safe_calls), "calls": safe_calls,
            "cleanup_proven": report.get("cleanup_proven") is True,
            "default_system_server_list": (report.get("default_system_server_list")
                                           if type(report.get("default_system_server_list")) is bool else None),
            "server_list_override": (report.get("server_list_override")
                                     if type(report.get("server_list_override")) is bool else None),
            "acceptance_passed": report.get("acceptance_passed") is True,
            "exit_code": exit_code if type(exit_code) is int and -255 <= exit_code <= 255 else None}


def _safe_boolean_result(value) -> dict:
    return {"ok": value is True, "result_type": type(value).__name__}


def _ordinary_user_stop_service_denied() -> bool:
    advapi = ctypes.WinDLL("advapi32", use_last_error=True)
    advapi.OpenSCManagerW.argtypes = [ctypes.c_wchar_p, ctypes.c_wchar_p, ctypes.c_ulong]
    advapi.OpenSCManagerW.restype = ctypes.c_void_p
    advapi.OpenServiceW.argtypes = [ctypes.c_void_p, ctypes.c_wchar_p, ctypes.c_ulong]
    advapi.OpenServiceW.restype = ctypes.c_void_p
    advapi.ControlService.argtypes = [ctypes.c_void_p, ctypes.c_ulong, ctypes.c_void_p]
    advapi.ControlService.restype = ctypes.c_int
    advapi.CloseServiceHandle.argtypes = [ctypes.c_void_p]
    advapi.CloseServiceHandle.restype = ctypes.c_int
    scm = advapi.OpenSCManagerW(None, None, 0x0001)
    if not scm:
        return False
    try:
        service = advapi.OpenServiceW(scm, "ProxyBridgeSvc", 0x0020 | 0x0004)
        if not service:
            return ctypes.get_last_error() == 5
        try:
            class ServiceStatus(ctypes.Structure):
                _fields_ = [("service_type", ctypes.c_ulong), ("current_state", ctypes.c_ulong),
                            ("controls_accepted", ctypes.c_ulong), ("win32_exit", ctypes.c_ulong),
                            ("service_exit", ctypes.c_ulong), ("check_point", ctypes.c_ulong),
                            ("wait_hint", ctypes.c_ulong)]
            status = ServiceStatus()
            if advapi.ControlService(service, 1, ctypes.byref(status)):
                return False
            return ctypes.get_last_error() == 5
        finally:
            advapi.CloseServiceHandle(service)
    finally:
        advapi.CloseServiceHandle(scm)


def _lookup_account_sid(name: str) -> bytes:
    advapi = ctypes.WinDLL("advapi32", use_last_error=True)
    advapi.LookupAccountNameW.argtypes = [ctypes.c_wchar_p, ctypes.c_wchar_p, ctypes.c_void_p,
                                          ctypes.POINTER(ctypes.c_ulong), ctypes.c_wchar_p,
                                          ctypes.POINTER(ctypes.c_ulong), ctypes.POINTER(ctypes.c_ulong)]
    advapi.LookupAccountNameW.restype = ctypes.c_int
    sid_len, domain_len, use = ctypes.c_ulong(), ctypes.c_ulong(), ctypes.c_ulong()
    advapi.LookupAccountNameW(None, name, None, ctypes.byref(sid_len), None,
                              ctypes.byref(domain_len), ctypes.byref(use))
    if ctypes.get_last_error() != 122:
        raise ctypes.WinError(ctypes.get_last_error())
    sid, domain = ctypes.create_string_buffer(sid_len.value), ctypes.create_unicode_buffer(domain_len.value)
    if not advapi.LookupAccountNameW(None, name, sid, ctypes.byref(sid_len), domain,
                                     ctypes.byref(domain_len), ctypes.byref(use)):
        raise ctypes.WinError(ctypes.get_last_error())
    return sid.raw[:sid_len.value]


def _token_has_sid(token, sid_bytes: bytes) -> bool:
    advapi = ctypes.WinDLL("advapi32", use_last_error=True)
    advapi.CheckTokenMembership.argtypes = [ctypes.c_void_p, ctypes.c_void_p,
                                             ctypes.POINTER(ctypes.c_int)]
    advapi.CheckTokenMembership.restype = ctypes.c_int
    sid = ctypes.create_string_buffer(sid_bytes)
    member = ctypes.c_int()
    if not advapi.CheckTokenMembership(token, sid, ctypes.byref(member)):
        raise ctypes.WinError(ctypes.get_last_error())
    return bool(member.value)


def _windows_build() -> dict:
    import winreg
    with winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE,
                        r"SOFTWARE\Microsoft\Windows NT\CurrentVersion") as key:
        build = int(winreg.QueryValueEx(key, "CurrentBuildNumber")[0])
        ubr = int(winreg.QueryValueEx(key, "UBR")[0])
    return {"build": build, "ubr": ubr}


def _installed_display_version() -> str:
    import winreg
    key_name = r"SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\ProxyBridge"
    with winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, key_name) as key:
        value = winreg.QueryValueEx(key, "DisplayVersion")[0]
    if not isinstance(value, str) or not re.fullmatch(r"[0-9]+\.[0-9]+\.[0-9]+", value):
        raise RuntimeError("Installed product version metadata is malformed")
    return value


if __name__ == "__main__":
    raise SystemExit(main())
