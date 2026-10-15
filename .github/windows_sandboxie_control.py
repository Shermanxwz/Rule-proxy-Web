"""Source-only diagnostic for the free Sandboxie Plus/WFP path.

This is not product acceptance.  The install phase is intended for a disposable
Windows VM running as SYSTEM/elevated; the probe phase must run as the ordinary
interactive user after any requested reboot.  It uses only the free WFP and
NetworkAccess features and never configures paid Proxy Injection/DNS Filter.
"""
from __future__ import annotations

import argparse
import ctypes
import hashlib
import importlib.util
import json
import os
from pathlib import Path
from pathlib import PurePosixPath
import re
import shutil
import subprocess
import sys
import tempfile
import time

BACKEND = "sandboxie"
RELEASE = "v1.18.5"
INSTALLER_REL = "installers/Sandboxie-Plus-x64-v1.18.5.exe"
INSTALLER_URL = "https://github.com/sandboxie-plus/Sandboxie/releases/download/v1.18.5/Sandboxie-Plus-x64-v1.18.5.exe"
INSTALLER_SIZE = 24_856_520
INSTALLER_SHA256 = "bd984db71900ecb9fc22e4bbffda4363a92cd755840a8792c2422d6d42fd6fa3"
CHROME_CONTROL_SHA256 = {
    "chromium/chrome-win64/chrome.exe": "f0b204ce7239e221f84c4030cd38e4b688ad05320acc8373da166f548bf57eb5",
    "chromium/chrome-win64/chrome.dll": "76249ef0bfc397679308ccca2e8e663b00dd4698353c0930d38d7fbeb840d6ef",
    "chromium/chrome-win64/chrome_elf.dll": "a2fffdae42224ffd308963c4071a8f6854ad27d2314f88491a7e9aaa38ef6366",
}
INSTALL_TIMEOUT = 600
COMMAND_TIMEOUT = 120
MAX_REPORT_BYTES = 32 * 1024
MAX_INPUT_BYTES = 8 * 1024 * 1024
MAX_BUNDLE_FILE_BYTES = 512 * 1024 * 1024
BOX_BASE = "RuleProxyNet"
BOX_DNS = "RuleProxyDnsIpc"
_SAFE_INSTALL_EXIT = {0, 3010, 1641}
GUEST_ROOT = Path(r"C:\RuleProxyCI")
PINNED_BUNDLE = GUEST_ROOT / "bundle"
PINNED_ARTIFACTS = GUEST_ROOT / "artifacts"


class ProbeError(RuntimeError):
    pass


def _json_read(path: Path, limit=MAX_INPUT_BYTES):
    with path.open("rb") as stream:
        raw = stream.read(limit + 1)
    if not raw or len(raw) > limit:
        raise ValueError("bounded JSON input is missing or oversized")
    result = json.loads(raw)
    if type(result) is not dict:
        raise ValueError("JSON input must be an object")
    return result


def _json_write(path: Path, value):
    raw = json.dumps(value, ensure_ascii=True, separators=(",", ":")).encode("ascii")
    if len(raw) > MAX_REPORT_BYTES:
        raise ValueError("report exceeds bounded size")
    path.parent.mkdir(parents=True, exist_ok=True)
    temp = path.with_name(path.name + ".tmp")
    try:
        with temp.open("xb") as stream:
            stream.write(raw)
            stream.flush()
            os.fsync(stream.fileno())
        os.replace(temp, path)
    finally:
        temp.unlink(missing_ok=True)


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


def _sha256(path: Path):
    digest = hashlib.sha256()
    size = 0
    with path.open("rb") as stream:
        while True:
            block = stream.read(1024 * 1024)
            if not block:
                break
            size += len(block)
            if size > MAX_BUNDLE_FILE_BYTES:
                raise ValueError("bundle file exceeded its fixed size bound")
            digest.update(block)
    return size, digest.hexdigest()


def _manifest_installer(bundle: Path, manifest: Path):
    if not bundle.is_absolute() or not manifest.is_absolute():
        raise ValueError("bundle and manifest paths must be absolute")
    if bundle.is_symlink() or manifest.is_symlink() or not bundle.is_dir():
        raise ValueError("bundle paths must be ordinary directories and files")
    data = _json_read(manifest)
    base_keys = {"schema_version", "backend", "release", "files",
                 "source_diagnostic_only", "release_eligible", "downloaded_archives"}
    if (set(data) != base_keys or data.get("schema_version") != 1 or data.get("backend") != BACKEND
            or data.get("release") != RELEASE or data.get("source_diagnostic_only") is not True
            or data.get("release_eligible") is not False or type(data.get("files")) is not list):
        raise ValueError("bundle manifest identity mismatch")
    archives = data.get("downloaded_archives")
    expected_archives = {
        "python": ("3.14.8", "https://www.python.org/ftp/python/3.14.8/python-3.14.8-embed-amd64.zip",
                   "a93abe456ab01bd96d7a085b3cdb6566b3063f4241360d114142fbdb07f0a310"),
        "mihomo": ("v1.19.32", "https://github.com/MetaCubeX/mihomo/releases/download/v1.19.32/mihomo-windows-amd64-compatible-v1.19.32.zip",
                   "974a4d7ad69aed27aa2e8f91d61113573c14dadb14562c63e58effabf59816f0"),
        "chromium": ("154.0.8037.92", "https://storage.googleapis.com/chrome-for-testing-public/154.0.8037.92/win64/chrome-win64.zip",
                     "b897ef3601c947ac0620c784556dec719ac602b0159ce105927acf645ee0f598"),
        "sandboxie": (RELEASE, INSTALLER_URL, INSTALLER_SHA256),
    }
    if type(archives) is not list or len(archives) != len(expected_archives):
        raise ValueError("bundle archive provenance is incomplete")
    seen_archives = set()
    for item in archives:
        if type(item) is not dict or item.get("component") not in expected_archives:
            raise ValueError("bundle archive provenance contains an unknown component")
        component = item["component"]
        if component in seen_archives:
            raise ValueError("bundle archive provenance contains duplicates")
        seen_archives.add(component)
        version, url, digest = expected_archives[component]
        if (item.get("release"), item.get("url"), item.get("sha256")) != (version, url, digest):
            raise ValueError("bundle archive provenance pins mismatch")
    if seen_archives != set(expected_archives):
        raise ValueError("bundle archive provenance is incomplete")
    matches = []
    by_path = {}
    for record in data["files"]:
        if (type(record) is not dict or set(record) - {"path", "size", "sha256", "source_url"}
                or not isinstance(record.get("path"), str)):
            raise ValueError("bundle manifest file record is malformed")
        rel = record["path"]
        pure = PurePosixPath(rel)
        if (pure.is_absolute() or "\\" in rel or ":" in rel or not pure.parts
                or any(part in ("", ".", "..") for part in pure.parts)
                or type(record.get("size")) is not int or record["size"] <= 0
                or type(record.get("sha256")) is not str
                or not re.fullmatch(r"[0-9a-f]{64}", record["sha256"])):
            raise ValueError("bundle manifest contains an unsafe or invalid file record")
        folded = rel.casefold()
        if folded in by_path:
            raise ValueError("bundle manifest contains a duplicate path")
        by_path[folded] = record
        if rel == INSTALLER_REL:
            matches.append(record)
    if len(matches) != 1:
        raise ValueError("bundle manifest must contain exactly one pinned installer")
    record = matches[0]
    if set(record) not in ({"path", "size", "sha256", "source_url"},
                           {"path", "size", "sha256", "source_url", "authenticode_subject", "authenticode_thumbprint"}):
        raise ValueError("installer manifest record fields mismatch")
    if (record.get("size") != INSTALLER_SIZE or record.get("sha256") != INSTALLER_SHA256
            or record.get("source_url") != INSTALLER_URL
            or record.get("authenticode_subject") not in (None, "")
            or record.get("authenticode_thumbprint") not in (None, "")):
        raise ValueError("installer manifest pins mismatch")
    required_files = {
        INSTALLER_REL, "python/python.exe", "mihomo/mihomo.exe",
        "chromium/chrome-win64/chrome.exe",
        "scripts/windows_free_backend_fixture.py", "scripts/windows_native_dns_probe.py",
        "scripts/windows_sandboxie_control.py",
    }
    required_files.update(CHROME_CONTROL_SHA256)
    if any(path.casefold() not in by_path for path in required_files):
        raise ValueError("bundle manifest omitted a required pinned control file")
    # Verify every listed payload file, not only the executables used below.
    # This keeps the bundled interpreter and its libraries tied to the fixed
    # source archives and rejects unmanifested or modified files.
    if len(by_path) != len(data["files"]):
        raise ValueError("bundle manifest contains duplicate paths")
    for _, expected in sorted(by_path.items()):
        rel = expected["path"]
        if expected["size"] > MAX_BUNDLE_FILE_BYTES:
            raise ValueError("bundle manifest file exceeds fixed size bound")
        target = bundle.joinpath(*PurePosixPath(rel).parts)
        for parent in (target, *target.parents):
            try:
                info = parent.lstat()
            except OSError as exc:
                raise ValueError("required bundle file is unavailable") from exc
            if parent.is_symlink() or getattr(info, "st_file_attributes", 0) & 0x400:
                raise ValueError("bundle file path contains a link or reparse point")
        if not target.is_file():
            raise ValueError("required bundle file is unavailable")
        size, digest = _sha256(target)
        if size != expected["size"] or digest != expected["sha256"]:
            raise ValueError("bundle file bytes do not match the manifest")
        chrome_pin = CHROME_CONTROL_SHA256.get(rel)
        if chrome_pin is not None and digest != chrome_pin:
            raise ValueError("Chrome control executable bytes do not match the fixed pin")
    return bundle / INSTALLER_REL


def _win_identity():
    if os.name != "nt":
        raise OSError("Windows token inspection is required")
    advapi = ctypes.WinDLL("advapi32", use_last_error=True)
    kernel = ctypes.WinDLL("kernel32", use_last_error=True)
    token = ctypes.c_void_p()
    TOKEN_QUERY = 0x0008
    TokenElevation = 20
    elevation = ctypes.c_uint32()
    returned = ctypes.c_uint32()
    advapi.OpenProcessToken.argtypes = [ctypes.c_void_p, ctypes.c_uint32, ctypes.POINTER(ctypes.c_void_p)]
    advapi.OpenProcessToken.restype = ctypes.c_int32
    advapi.GetTokenInformation.argtypes = [ctypes.c_void_p, ctypes.c_int, ctypes.c_void_p,
                                           ctypes.c_uint32, ctypes.POINTER(ctypes.c_uint32)]
    advapi.GetTokenInformation.restype = ctypes.c_int32
    kernel.GetCurrentProcess.restype = ctypes.c_void_p
    kernel.CloseHandle.argtypes = [ctypes.c_void_p]
    kernel.CloseHandle.restype = ctypes.c_int32
    if not advapi.OpenProcessToken(kernel.GetCurrentProcess(), TOKEN_QUERY, ctypes.byref(token)):
        raise ctypes.WinError(ctypes.get_last_error())
    try:
        if not advapi.GetTokenInformation(token, TokenElevation, ctypes.byref(elevation),
                                          ctypes.sizeof(elevation), ctypes.byref(returned)):
            raise ctypes.WinError(ctypes.get_last_error())
    finally:
        if not kernel.CloseHandle(token):
            raise ctypes.WinError(ctypes.get_last_error())
    elevated = bool(elevation.value)
    # Check Administrators membership independently from the elevated token bit.
    try:
        shell32 = ctypes.WinDLL("shell32", use_last_error=True)
        shell32.IsUserAnAdmin.argtypes, shell32.IsUserAnAdmin.restype = [], ctypes.c_int32
        administrator = bool(shell32.IsUserAnAdmin())
    except Exception as exc:
        raise OSError("administrator membership query failed") from exc
    return {"is_elevated": elevated, "is_administrator": administrator,
            "ordinary_user": not elevated and not administrator}


def _os_facts():
    import platform
    version = sys.getwindowsversion()
    build = int(version.build)
    ubr = _registry_ubr()
    return {"os_version": platform.version(), "os_build": build, "os_ubr": ubr,
            "windows_build": build, "windows_ubr": ubr}


def _registry_ubr():
    try:
        import winreg
        with winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE,
                            r"SOFTWARE\Microsoft\Windows NT\CurrentVersion") as key:
            return int(winreg.QueryValueEx(key, "UBR")[0])
    except Exception:
        return None


def _install_root():
    candidates = (Path(os.environ.get("ProgramFiles", r"C:\Program Files")) / "Sandboxie-Plus",
                  Path(os.environ.get("ProgramFiles", r"C:\Program Files")) / "Sandboxie")
    for path in candidates:
        if (path / "Start.exe").is_file() and (path / "SbieSvc.exe").is_file():
            return path
    raise FileNotFoundError("installed Sandboxie Plus files were not found")


def _service_facts():
    query = _run(["sc.exe", "query", "SbieSvc"], 15)
    if query.returncode != 0:
        return {"exists": False, "state": "missing", "start_type": "unknown"}
    text = query.stdout.decode("ascii", "replace")
    match = re.search(r"STATE\s*:\s*\d+\s+([A-Z_]+)", text, re.IGNORECASE)
    state = match.group(1).lower() if match else "unknown"
    qc = _run(["sc.exe", "qc", "SbieSvc"], 15)
    qc_text = qc.stdout.decode("ascii", "replace")
    start = re.search(r"START_TYPE\s*:\s*\d+\s+([A-Z_]+)", qc_text, re.IGNORECASE)
    start_type = start.group(1).lower() if start else "unknown"
    if state not in {"running", "stopped", "start_pending", "stop_pending", "paused", "unknown"}:
        state = "unknown"
    if start_type not in {"boot_start", "system_start", "auto_start", "demand_start", "disabled", "unknown"}:
        start_type = "unknown"
    return {"exists": True, "state": state, "start_type": start_type}


def _authenticode(path: Path):
    # Return only finite signature facts; no command output or path is persisted.
    script = ("$p='" + str(path).replace("'", "''") + "';"
              "$s=Get-AuthenticodeSignature -LiteralPath $p;"
              "$v=(Get-Item -LiteralPath $p).VersionInfo;")
    script += (
              "[pscustomobject]@{status=[string]$s.Status;subject=[string]$s.SignerCertificate.Subject;"
              "thumbprint=[string]$s.SignerCertificate.Thumbprint;version=[string]$v.FileVersion}|"
              "ConvertTo-Json -Compress")
    completed = subprocess.run(["powershell.exe", "-NoProfile", "-NonInteractive", "-Command", script], stdin=subprocess.DEVNULL, stdout=subprocess.PIPE,
                               stderr=subprocess.DEVNULL, timeout=30, check=False, shell=False,
                               creationflags=getattr(subprocess, "CREATE_NO_WINDOW", 0))
    if completed.returncode != 0 or len(completed.stdout) > 8192:
        raise RuntimeError("installed file signature query failed")
    value = json.loads(completed.stdout.decode("utf-8-sig"))
    if type(value) is not dict:
        raise RuntimeError("installed file signature query returned invalid data")
    status = value.get("status")
    subject = value.get("subject")
    thumbprint = value.get("thumbprint")
    version = value.get("version")
    if any(type(x) is not str for x in (status, subject, thumbprint, version)):
        raise RuntimeError("installed file signature facts were incomplete")
    return {"status": status if status in {"Valid", "NotSigned", "HashMismatch", "NotTrusted", "UnknownError"} else "UnknownError",
            "subject_present": bool(subject),
            "thumbprint_valid": bool(re.fullmatch(r"[0-9A-Fa-f]{40,64}", thumbprint)),
            "version": version[:64], "raw_status": str(status)[:64]}


def _config_text(proxy_port: int):
    if proxy_port is not None and (type(proxy_port) is not int or not 1 <= proxy_port <= 65535):
        raise ValueError("invalid private proxy endpoint")
    bundle = r"C:\RuleProxyCI\bundle"
    artifacts = r"C:\RuleProxyCI\artifacts"
    common = ["Enabled=y", "AllowNetworkAccess=y", "NetworkAccess=*,Block",
              f"OpenFilePath={artifacts}",
              f"ReadFilePath={bundle}\\python", f"ReadFilePath={bundle}\\scripts",
              f"ReadFilePath={bundle}\\chromium\\chrome-win64"]
    lines = ["[GlobalSettings]", "NetworkEnableWFP=y", "", f"[{BOX_BASE}]", *common]
    if proxy_port is not None:
        lines.append(f"NetworkAccess=*,Allow;Address=127.0.0.1;Port={proxy_port};Protocol=TCP")
    lines += ["", f"[{BOX_DNS}]", *common, r"ClosedIpcPath=\RPC Control\DNSResolver"]
    if proxy_port is not None:
        lines.append(f"NetworkAccess=*,Allow;Address=127.0.0.1;Port={proxy_port};Protocol=TCP")
    lines.append("")
    return "\r\n".join(lines)


def _run(argv, timeout=COMMAND_TIMEOUT, *, capture=True, env=None):
    return subprocess.run(argv, stdin=subprocess.DEVNULL,
                          stdout=subprocess.PIPE if capture else subprocess.DEVNULL,
                          stderr=subprocess.DEVNULL, timeout=timeout, check=False, shell=False,
                          env=env,
                          creationflags=getattr(subprocess, "CREATE_NO_WINDOW", 0))


def _ini_path(root: Path):
    system = Path(os.environ.get("SystemRoot", r"C:\Windows")) / "Sandboxie.ini"
    return system if system.exists() else root / "Sandboxie.ini"


def _append_test_config(path: Path):
    path.parent.mkdir(parents=True, exist_ok=True)
    original = path.read_bytes() if path.exists() else b""
    if len(original) > 4 * 1024 * 1024 or b"[RuleProxyNet]" in original or b"[RuleProxyDnsIpc]" in original:
        raise ValueError("Sandboxie configuration is not a clean disposable baseline")
    backup = Path(os.environ.get("ProgramData", r"C:\ProgramData")) / "RuleProxyCI" / "sandboxie.ini.original"
    backup.parent.mkdir(parents=True, exist_ok=True)
    if backup.exists():
        raise ValueError("Sandboxie configuration backup already exists")
    backup.write_bytes(original)
    additions = _config_text(None).encode("ascii")
    with path.open("ab") as stream:
        if original and not original.endswith((b"\n", b"\r")):
            stream.write(b"\r\n")
        stream.write(additions)
        stream.flush()
        os.fsync(stream.fileno())
    return backup


def _add_proxy_allow(install_root: Path, box: str, port: int):
    """Append one runtime-selected exact endpoint through the service API."""
    if type(port) is not int or not 1 <= port <= 65535:
        raise ValueError("invalid exact proxy port")
    sbie_ini = install_root / "SbieIni.exe"
    if not sbie_ini.is_file():
        raise FileNotFoundError("Sandboxie configuration utility is unavailable")
    rule = f"*,Allow;Address=127.0.0.1;Port={port};Protocol=TCP"
    completed = _run([str(sbie_ini), "append", "/drv", box, "NetworkAccess", rule], 30)
    if completed.returncode != 0:
        raise RuntimeError("Sandboxie service rejected the exact proxy endpoint rule")
    reloaded = _run([str(install_root / "Start.exe"), "/reload"], 30)
    if reloaded.returncode != 0:
        raise RuntimeError("Sandboxie failed to reload the exact endpoint rule")


def install(bundle: Path, manifest: Path, report: Path, user: str, sid: str):
    result = {"schema_version": 1, "backend": BACKEND, "phase": "install", "status": "failed",
              "ordinary_user": False, "is_elevated": None, "is_administrator": None,
              "reboot_required": False, "acceptance_passed": False,
              "source_diagnostic_only": True, "diagnostic_only": True,
              "product_acceptance": False, "product_acceptance_passed": False,
              "release_eligible": False, "host_configuration_restored": False}
    result.update(_os_facts())
    identity = _win_identity()
    result.update(identity)
    if not identity["is_elevated"] or not identity["is_administrator"]:
        raise PermissionError("install phase requires an elevated administrator")
    if not isinstance(user, str) or not re.fullmatch(r"[A-Za-z0-9_.-]{1,64}", user):
        raise ValueError("invalid probe account name")
    if not isinstance(sid, str) or not re.fullmatch(r"S-1-(?:[0-9]+-){1,14}[0-9]+", sid):
        raise ValueError("invalid probe account SID")
    if bundle.resolve(strict=True) != PINNED_BUNDLE:
        raise ValueError("install bundle must use the runner's fixed private directory")
    installer = _manifest_installer(bundle, manifest)
    result["installer_sha256"] = INSTALLER_SHA256
    result["installer_size"] = INSTALLER_SIZE
    result["installer_version"] = RELEASE
    installer_signature = _authenticode(installer)
    result["installer_authenticode_status"] = installer_signature["status"]
    result["installer_authenticode_valid"] = installer_signature["status"] == "Valid"
    # Validate the signed target account exists and exactly matches the requested SID.
    completed = _run(["powershell.exe", "-NoProfile", "-NonInteractive", "-Command",
        "$u=Get-LocalUser -Name '" + user + "' -ErrorAction Stop; $u.SID.Value"], 30)
    if completed.returncode != 0 or completed.stdout.decode("utf-8", "replace").strip() != sid:
        raise RuntimeError("probe account identity did not match the runner's fixed SID")
    code = _run([str(installer), "/VERYSILENT", "/SUPPRESSMSGBOXES", "/NORESTART", "/SP-"],
                INSTALL_TIMEOUT, capture=False).returncode
    if code not in _SAFE_INSTALL_EXIT:
        result["installer_exit_code"] = int(code)
        raise RuntimeError("pinned Sandboxie installer returned an unsuccessful status")
    result["installer_exit_code"] = int(code)
    result["reboot_required"] = code in {3010, 1641}
    root = _install_root()
    driver = root / "SbieDrv.sys"
    signature = _authenticode(driver)
    if signature["status"] != "Valid":
        exc = RuntimeError("installed Sandboxie driver signature is not valid")
        exc.driver_signature = signature
        raise exc
    service = _service_facts()
    if not service["exists"]:
        raise RuntimeError("Sandboxie service is missing after installation")
    ini_path = _ini_path(root)
    backup = _append_test_config(ini_path)
    reloaded = _run([str(root / "Start.exe"), "/reload"], 30)
    if reloaded.returncode != 0:
        raise RuntimeError("Sandboxie failed to load the WFP diagnostic configuration")
    # The probe account is retained for the following ordinary-user scheduled task.
    result.update(status="passed", install_files_present=True, driver_signature=signature,
                  installed_product_version=RELEASE, install_root_present=True,
                  probe_account_present=True, configuration_written=True,
                  service_install=service, service_installed=True,
                  target_user_authorized=True,
                  configuration_backup_created=backup.is_file(), vm_disposal_required=True,
                  acceptance_passed=False)
    _json_write(report, result)
    return result


def _validate_fixture(value):
    required = {"schema_version", "nonce", "proxy_host", "proxy_port", "origin_host", "origin_port",
                "origin_url", "http_origin_host", "http_origin_port", "blocked_tcp_host", "blocked_tcp_port",
                "udp4_host", "udp4_port", "udp6_host", "udp6_port", "public_udp4_host", "public_udp6_host",
                "public_udp_port"}
    if type(value) is not dict or set(value) != required or value.get("schema_version") != 1:
        raise ValueError("fixture spec schema mismatch")
    if type(value["nonce"]) is not str or not re.fullmatch(r"[0-9a-f]{32}", value["nonce"]):
        raise ValueError("fixture nonce is invalid")
    if value["proxy_host"] != "127.0.0.1" or value["http_origin_host"] != "127.0.0.1":
        raise ValueError("fixture endpoints must use the fixed local IPv4 listener")
    for key in ("proxy_port", "origin_port", "http_origin_port", "blocked_tcp_port", "udp4_port", "public_udp_port"):
        if type(value[key]) is not int or not 1 <= value[key] <= 65535:
            raise ValueError("fixture port is outside its valid range")
    if value["udp6_port"] is not None and (type(value["udp6_port"]) is not int or not 1 <= value["udp6_port"] <= 65535):
        raise ValueError("fixture IPv6 port is invalid")
    for key in ("origin_host", "blocked_tcp_host", "udp4_host", "udp6_host", "public_udp4_host", "public_udp6_host"):
        if type(value[key]) is not str or not value[key] or len(value[key]) > 128:
            raise ValueError("fixture host field is invalid")
    expected_url = f"http://{value['origin_host']}:{value['origin_port']}/{value['nonce']}"
    if value["origin_url"] != expected_url:
        raise ValueError("fixture origin URL is not bound to the nonce")
    return value


def _start_exe(root: Path):
    path = root / "Start.exe"
    if not path.is_file():
        raise FileNotFoundError("Sandboxie Start.exe is unavailable")
    return path


def _run_box(start: Path, box: str, argv: list[str], timeout=120, *, env=None):
    return _run([str(start), f"/box:{box}", "/wait", *argv], timeout, env=env)


def _import_from(path: Path, module_name: str):
    spec = importlib.util.spec_from_file_location(module_name, path)
    if spec is None or spec.loader is None:
        raise ImportError("fixed bundled helper could not be loaded")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def _bounded_worker_summary(path: Path):
    value = _json_read(path)
    if value.get("schema_version") != 1 or value.get("role") != "parent":
        raise ValueError("fixed worker report schema mismatch")
    child = value.get("child")
    if type(child) is not dict or child.get("role") != "child":
        raise ValueError("fixed worker child report missing")
    parent_dns = value.get("native_dns", {}).get("calls", [])
    child_dns = child.get("native_dns", {}).get("calls", [])
    if type(parent_dns) is not list or type(child_dns) is not list:
        raise ValueError("fixed worker DNS summary malformed")
    return {"worker_report_observed": True,
            "proxy_http_ok": value.get("proxy_http", {}).get("ok") is True,
            "proxy_socks_ok": value.get("proxy_socks", {}).get("ok") is True,
            "direct_tcp_connected": value.get("direct_tcp", {}).get("connected") is True,
            "parent_native_dns_calls": len(parent_dns), "child_native_dns_calls": len(child_dns),
            "udp_send_observations": {key: value.get(key, {}).get("send_ok")
                                      for key in ("udp4", "udp6", "public_udp4", "public_udp6")},
            "child": {"proxy_http_ok": child.get("proxy_http", {}).get("ok") is True,
                      "proxy_socks_ok": child.get("proxy_socks", {}).get("ok") is True,
                      "direct_tcp_connected": child.get("direct_tcp", {}).get("connected") is True,
                      "udp_send_observations": {key: child.get(key, {}).get("send_ok")
                                                for key in ("udp4", "udp6", "public_udp4", "public_udp6")}}}


def _run_worker(start: Path, python: Path, worker: Path, spec_path: Path,
                artifacts: Path, box: str, label: str, *, timeout=120, env=None):
    report_path = artifacts / f"{label}.json"
    argv = [str(python), "-I", "-S", "-X", "utf8", str(worker), "--worker", "--spec",
            str(spec_path), "--report", str(report_path), "--role", "parent"]
    completed = _run_box(start, box, argv, timeout, env=env)
    if completed.returncode != 0:
        raise RuntimeError(f"boxed fixed worker failed for {label}")
    summary = _bounded_worker_summary(report_path)
    summary["worker_exit_code"] = int(completed.returncode)
    return summary


def _run_outside_worker(python: Path, worker: Path, spec_path: Path,
                        artifacts: Path, label: str, *, env=None):
    report_path = artifacts / f"{label}.json"
    completed = _run([str(python), "-I", "-S", "-X", "utf8", str(worker), "--worker", "--spec",
                      str(spec_path), "--report", str(report_path), "--role", "parent"], 120, env=env)
    if completed.returncode != 0:
        raise RuntimeError(f"outside fixed worker failed for {label}")
    summary = _bounded_worker_summary(report_path)
    summary["worker_exit_code"] = int(completed.returncode)
    return summary


def _run_dns_box(start: Path, python: Path, dns_probe: Path, nonce: str,
                 artifacts: Path, box: str, *, env=None):
    records = {}
    for role in ("parent", "child"):
        report_path = artifacts / f"dns-{box}-{role}.json"
        argv = [str(python), "-I", "-S", "-X", "utf8", str(dns_probe),
                "--nonce", nonce, "--role", role, "--report", str(report_path)]
        completed = _run_box(start, box, argv, 90, env=env)
        if completed.returncode not in (0, 3):
            raise RuntimeError("boxed native DNS probe exited unsuccessfully")
        value = _json_read(report_path)
        calls = value.get("calls")
        if type(calls) is not list:
            raise ValueError("boxed native DNS probe report malformed")
        records[role] = {"report_observed": True, "probe_status": value.get("status"),
                         "call_count": len(calls), "worker_cleanup_proven": value.get("cleanup_proven") is True,
                         "dns_blocked_proven": value.get("dns_blocked_proven") is True,
                         "wire_observed": value.get("wire_observed")}
    return records


def _run_dns_outside(python: Path, dns_probe: Path, nonce: str,
                     artifacts: Path, role: str):
    report_path = artifacts / f"dns-{role}.json"
    completed = _run([str(python), "-I", "-S", "-X", "utf8", str(dns_probe),
                      "--nonce", nonce, "--role", role, "--report", str(report_path)], 90)
    if completed.returncode not in (0, 3):
        raise RuntimeError("outside native DNS probe exited unsuccessfully")
    value = _json_read(report_path)
    calls = value.get("calls")
    if type(calls) is not list:
        raise ValueError("outside native DNS probe report malformed")
    return {"report_observed": True, "probe_status": value.get("status"),
            "call_count": len(calls), "worker_cleanup_proven": value.get("cleanup_proven") is True,
            "dns_blocked_proven": value.get("dns_blocked_proven") is True,
            "wire_observed": value.get("wire_observed")}


def _window_facts(image_name: str):
    if os.name != "nt":
        raise OSError("visible window inspection requires Windows")
    from ctypes import wintypes
    user32 = ctypes.WinDLL("user32", use_last_error=True)
    enum = user32.EnumWindows
    enum.argtypes = [ctypes.c_void_p, ctypes.c_void_p]
    enum.restype = ctypes.c_int32
    get_pid = user32.GetWindowThreadProcessId
    get_pid.argtypes = [wintypes.HWND, ctypes.POINTER(wintypes.DWORD)]
    get_pid.restype = wintypes.DWORD
    visible = user32.IsWindowVisible
    visible.argtypes, visible.restype = [wintypes.HWND], wintypes.BOOL
    found = []
    CALLBACK = ctypes.WINFUNCTYPE(wintypes.BOOL, wintypes.HWND, wintypes.LPARAM)
    @CALLBACK
    def visit(hwnd, _):
        if visible(hwnd):
            pid = wintypes.DWORD()
            get_pid(hwnd, ctypes.byref(pid))
            if pid.value:
                found.append(int(pid.value))
        return True
    if not enum(visit, 0):
        raise ctypes.WinError(ctypes.get_last_error())
    # Image-name matching is intentionally done against held process handles elsewhere;
    # this function only establishes that the interactive desktop has visible windows.
    return {"visible_top_level_window_count": min(len(found), 4096), "visible_window_observed": bool(found)}


def _chrome_windows(path: Path):
    from ctypes import wintypes
    user32 = ctypes.WinDLL("user32", use_last_error=True)
    user32.EnumWindows.argtypes = [ctypes.c_void_p, ctypes.c_void_p]
    user32.EnumWindows.restype = ctypes.c_int32
    user32.IsWindowVisible.argtypes = [wintypes.HWND]
    user32.IsWindowVisible.restype = wintypes.BOOL
    user32.GetWindowThreadProcessId.argtypes = [wintypes.HWND, ctypes.POINTER(wintypes.DWORD)]
    user32.GetWindowThreadProcessId.restype = wintypes.DWORD
    found = []
    callback_type = ctypes.WINFUNCTYPE(wintypes.BOOL, wintypes.HWND, wintypes.LPARAM)
    @callback_type
    def visit(hwnd, _):
        if user32.IsWindowVisible(hwnd):
            pid = wintypes.DWORD()
            user32.GetWindowThreadProcessId(hwnd, ctypes.byref(pid))
            if pid.value:
                image = _process_image(int(pid.value))
                if image and os.path.normcase(os.path.abspath(image)) == os.path.normcase(os.path.abspath(path)):
                    found.append((int(hwnd), int(pid.value)))
        return True
    if not user32.EnumWindows(visit, 0):
        raise ctypes.WinError(ctypes.get_last_error())
    return found


def _process_image(pid):
    kernel = ctypes.WinDLL("kernel32", use_last_error=True)
    kernel.OpenProcess.argtypes = [ctypes.c_uint32, ctypes.c_int32, ctypes.c_uint32]
    kernel.OpenProcess.restype = ctypes.c_void_p
    kernel.CloseHandle.argtypes = [ctypes.c_void_p]
    kernel.CloseHandle.restype = ctypes.c_int32
    handle = kernel.OpenProcess(0x1000, 0, pid)
    if not handle:
        return None
    try:
        length = ctypes.c_uint32(32768)
        buffer = ctypes.create_unicode_buffer(length.value)
        query = kernel.QueryFullProcessImageNameW
        query.argtypes = [ctypes.c_void_p, ctypes.c_uint32, ctypes.c_wchar_p, ctypes.POINTER(ctypes.c_uint32)]
        query.restype = ctypes.c_int32
        if not query(handle, 0, buffer, ctypes.byref(length)):
            return None
        return buffer.value
    finally:
        kernel.CloseHandle(handle)


def _close_chrome_windows(windows):
    from ctypes import wintypes
    user32 = ctypes.WinDLL("user32", use_last_error=True)
    user32.SendMessageTimeoutW.argtypes = [wintypes.HWND, wintypes.UINT, wintypes.WPARAM,
                                          wintypes.LPARAM, wintypes.UINT, wintypes.UINT,
                                          ctypes.POINTER(ctypes.c_size_t)]
    user32.SendMessageTimeoutW.restype = ctypes.c_void_p
    closed = 0
    for hwnd, _pid in windows:
        response = ctypes.c_size_t()
        if user32.SendMessageTimeoutW(hwnd, 0x0010, 0, 0, 0x0002, 2000, ctypes.byref(response)):
            closed += 1
    return closed


def _run_gui(start: Path, chrome: Path, box: str, origin_url: str,
             proxy_host: str, proxy_port: int, fixture):
    before = fixture.snapshot().get("origin_requests", 0)
    profile = os.environ.get("LOCALAPPDATA")
    if not profile:
        raise RuntimeError("interactive user profile path is unavailable")
    profile_dir = Path(profile) / "RuleProxyFreeBackend" / box
    argv = [str(start), f"/box:{box}", "/wait", str(chrome), "--new-window", "--no-first-run",
            "--no-default-browser-check", "--disable-background-networking",
            f"--user-data-dir={profile_dir}", f"--proxy-server=http://{proxy_host}:{proxy_port}",
            "--proxy-bypass-list=<-loopback>", origin_url]
    wrapper = subprocess.Popen(argv, stdin=subprocess.DEVNULL, stdout=subprocess.DEVNULL,
                               stderr=subprocess.DEVNULL, shell=False,
                               creationflags=getattr(subprocess, "CREATE_NO_WINDOW", 0))
    try:
        windows = []
        deadline = time.monotonic() + 45
        while time.monotonic() < deadline:
            windows = _chrome_windows(chrome)
            if windows and fixture.snapshot().get("origin_requests", 0) > before:
                break
            if wrapper.poll() is not None:
                raise RuntimeError("boxed Chromium exited before visible fixture load")
            time.sleep(.2)
        if not windows or fixture.snapshot().get("origin_requests", 0) <= before:
            raise TimeoutError("visible Chromium did not load the fixed proxy fixture")
        closed = _close_chrome_windows(windows)
        if not closed:
            raise RuntimeError("visible Chromium window could not be closed")
        code = wrapper.wait(timeout=20)
        if code != 0:
            raise RuntimeError("boxed Chromium did not exit successfully")
        return {"visible_window_observed": True, "fixture_request_observed": True,
                "dom_content_verified": False, "closed_verified_chrome_window_count": closed,
                "natural_wrapper_exit": True, "wrapper_exit_code": int(code)}
    finally:
        if wrapper.poll() is None:
            _close_chrome_windows(_chrome_windows(chrome))
            try:
                wrapper.wait(timeout=5)
            except subprocess.TimeoutExpired:
                _run([str(start), f"/box:{box}", "/terminate"], 30)
                try:
                    wrapper.wait(timeout=5)
                except subprocess.TimeoutExpired:
                    wrapper.kill()
                    wrapper.wait(timeout=5)


def _box_cleanup(start: Path, box: str):
    terminated = _run([str(start), f"/box:{box}", "/terminate"], 30)
    deleted = _run([str(start), f"/box:{box}", "delete_sandbox_silent"], 30)
    listed = _run([str(start), f"/box:{box}", "/listpids"], 15)
    try:
        lines = [int(line.strip()) for line in listed.stdout.decode("ascii", "strict").splitlines()
                 if line.strip()]
        empty = bool(lines) and lines[0] == 0 and len(lines) == 1
    except Exception:
        empty = False
    return {"terminate_exit_code": int(terminated.returncode), "delete_exit_code": int(deleted.returncode),
            "pid_list_exit_code": int(listed.returncode), "empty_box_proven": empty,
            "cleanup_proven": terminated.returncode == 0 and deleted.returncode == 0 and empty}


def _report_base(phase):
    return {"schema_version": 1, "backend": BACKEND, "phase": phase, "status": "failed",
            "acceptance_passed": False, "product_acceptance": False,
            "source_diagnostic_only": True, "diagnostic_only": True,
            "product_acceptance_passed": False, "release_eligible": False,
            "host_configuration_restored": False, "cleanup_proven": False}


def probe(bundle: Path, manifest: Path, report: Path, install_report: Path,
          artifacts: Path):
    result = _report_base("probe")
    identity = _win_identity()
    result.update(identity, **_os_facts())
    if not identity["ordinary_user"]:
        raise PermissionError("probe phase must run as a non-elevated ordinary user")
    previous = _json_read(install_report)
    if (previous.get("schema_version") != 1 or previous.get("backend") != BACKEND
            or previous.get("phase") != "install" or previous.get("status") != "passed"
            or previous.get("ordinary_user") is not False or previous.get("reboot_required") not in (True, False)
            or previous.get("installer_sha256") != INSTALLER_SHA256
            or previous.get("diagnostic_only") is not True
            or previous.get("product_acceptance_passed") is not False
            or previous.get("release_eligible") is not False
            or previous.get("target_user_authorized") is not True
            or type(previous.get("driver_signature")) is not dict
            or previous["driver_signature"].get("status") != "Valid"):
        raise ValueError("verified install report is missing or mismatched")
    if bundle.resolve(strict=True) != PINNED_BUNDLE or artifacts.resolve() != PINNED_ARTIFACTS:
        raise ValueError("probe bundle/artifacts do not use the runner's fixed paths")
    _manifest_installer(bundle, manifest)
    if artifacts.is_symlink() or not artifacts.is_absolute():
        raise ValueError("artifact directory must be absolute and not a symlink")
    artifacts.mkdir(parents=True, exist_ok=True)
    if os.name != "nt":
        raise OSError("Sandboxie probe requires Windows")
    install_root = _install_root()
    start = _start_exe(install_root)
    driver = install_root / "SbieDrv.sys"
    driver_signature = _authenticode(driver)
    if driver_signature["status"] != "Valid":
        raise RuntimeError("installed Sandboxie driver signature is no longer valid")
    service = _service_facts()
    if not service["exists"] or service["state"] != "running":
        raise RuntimeError("Sandboxie service is not running for the ordinary-user probe")
    result["driver_signature"] = driver_signature
    result["service_install"] = service
    result["service_running"] = True
    python = bundle / "python" / "python.exe"
    chrome = bundle / "chromium" / "chrome-win64" / "chrome.exe"
    worker = bundle / "scripts" / "windows_free_backend_fixture.py"
    dns_probe = bundle / "scripts" / "windows_native_dns_probe.py"
    mihomo = bundle / "mihomo" / "mihomo.exe"
    if not all(path.is_file() for path in (python, chrome, worker, dns_probe, mihomo)):
        raise FileNotFoundError("fixed Python, Chromium, Mihomo, fixture, or DNS helper is missing")
    result.update(status="running", sandboxie_version=RELEASE,
                  policy_variant="free_wfp_exact_loopback_proxy_tcp_allow_default_deny",
                  dns_ipc_policy_variant="same_network_policy_plus_closed_dnsresolver_ipc_candidate",
                  paid_features_used=False, product_runtime_replaced=False,
                  privacy_claimed=False, network_policy_controlled=False,
                  vm_disposal_required=True, simple_deployment_observed=False)
    fixture_module = _import_from(bundle / "scripts" / "windows_free_backend_fixture.py",
                                  "sandboxie_free_backend_fixture")
    fixture_obj = None
    host_fixture_closed = False
    cleanup = {BOX_BASE: None, BOX_DNS: None}
    summaries = {}
    phase_complete = False
    try:
        fixture_obj = fixture_module.Fixture(mihomo_path=mihomo, directory=artifacts / "fixture")
        fixture_obj.__enter__()
        spec_path = fixture_obj.write_spec()
        spec = _validate_fixture(_json_read(spec_path))
        # Install the same dynamic, single-host/single-TCP-port exception in
        # both boxes. This ordinary-user /drv update is itself a simplicity gate.
        _add_proxy_allow(install_root, BOX_BASE, spec["proxy_port"])
        _add_proxy_allow(install_root, BOX_DNS, spec["proxy_port"])
        result["runtime_policy_update"] = {
            "method": "SbieIni append /drv exact endpoint",
            "ordinary_user_update_succeeded": True,
            "exact_proxy_host": spec["proxy_host"],
            "exact_proxy_port": spec["proxy_port"],
            "other_ports_permitted": False,
        }
        env = os.environ.copy()
        env["TEMP"] = str(artifacts)
        env["TMP"] = str(artifacts)
        result["outside_before"] = _run_outside_worker(python, worker, spec_path, artifacts,
                                                        "outside-before", env=env)
        result["outside_native_dns_before"] = _run_dns_outside(
            python, dns_probe, spec["nonce"], artifacts, "outside_before")
        summaries[BOX_BASE] = _run_worker(start, python, worker, spec_path, artifacts, BOX_BASE,
                                          "boxed-network", timeout=150, env=env)
        summaries[BOX_DNS] = _run_worker(start, python, worker, spec_path, artifacts, BOX_DNS,
                                         "boxed-dns-ipc", timeout=150, env=env)
        result["native_dns"] = {
            BOX_BASE: _run_dns_box(start, python, dns_probe, spec["nonce"], artifacts, BOX_BASE, env=env),
            BOX_DNS: _run_dns_box(start, python, dns_probe, spec["nonce"], artifacts, BOX_DNS, env=env),
        }
        result["gui"] = _run_gui(start, chrome, BOX_BASE, spec["origin_url"],
                                 spec["proxy_host"], spec["proxy_port"], fixture_obj)
        stop = fixture_obj.stop_proxy()
        if stop.get("exited") is not True:
            raise RuntimeError("owned Mihomo proxy did not stop for fail-closed control")
        # Reuse the exact configured endpoint after stopping its owned proxy.
        # This tests a genuinely unavailable configured proxy, with no policy
        # change and no alternate listener that could create a false pass.
        failed_spec = dict(spec)
        failure_spec_path = artifacts / "proxy-failure-spec.json"
        fixture_module.write_json(failure_spec_path, failed_spec)
        failure_report = artifacts / "proxy-failure.json"
        failed = _run_box(start, BOX_BASE,
            [str(python), "-I", "-S", "-X", "utf8", str(worker), "--worker", "--spec",
             str(failure_spec_path), "--report", str(failure_report), "--role", "parent"], 150, env=env)
        if failed.returncode != 0:
            raise RuntimeError("proxy-down fail-closed worker failed before observations")
        failed_value = _bounded_worker_summary(failure_report)
        result["proxy_failure_closed"] = {
            "proxy_http_failed": failed_value["proxy_http_ok"] is False,
            "proxy_socks_failed": failed_value["proxy_socks_ok"] is False,
            "direct_tcp_connected": failed_value["direct_tcp_connected"],
            "child_proxy_http_failed": failed_value["child"]["proxy_http_ok"] is False,
            "child_proxy_socks_failed": failed_value["child"]["proxy_socks_ok"] is False,
            "child_direct_tcp_connected": failed_value["child"]["direct_tcp_connected"],
            "expected_fail_closed": (failed_value["proxy_http_ok"] is False
                                     and failed_value["proxy_socks_ok"] is False
                                     and failed_value["direct_tcp_connected"] is False
                                     and failed_value["child"]["proxy_http_ok"] is False
                                     and failed_value["child"]["proxy_socks_ok"] is False
                                     and failed_value["child"]["direct_tcp_connected"] is False),
        }
        result["outside_after"] = _run_outside_worker(python, worker, spec_path, artifacts,
                                                       "outside-after", env=env)
        result["outside_native_dns_after"] = _run_dns_outside(
            python, dns_probe, spec["nonce"], artifacts, "outside_after")
        snapshot = fixture_obj.snapshot()
        result["fixture_observations"] = {
            key: int(snapshot.get(key, 0)) for key in
            ("proxy_requests", "origin_requests", "direct_connections", "udp4_received", "udp6_received")}
        result["fixture_errors_count"] = len(snapshot.get("errors", []))
        result["network_policy_controlled"] = bool(
            summaries[BOX_BASE]["proxy_http_ok"] and summaries[BOX_BASE]["proxy_socks_ok"]
            and summaries[BOX_BASE]["direct_tcp_connected"] is False
            and summaries[BOX_DNS]["proxy_http_ok"] and summaries[BOX_DNS]["proxy_socks_ok"]
            and summaries[BOX_DNS]["direct_tcp_connected"] is False
            and result["proxy_failure_closed"]["expected_fail_closed"])
        result["boxes"] = summaries
        result["outside_app_unaffected"] = bool(
            result["outside_before"]["direct_tcp_connected"]
            and result["outside_after"]["direct_tcp_connected"])
        result["dns_network_denial_proven"] = False
        result["diagnostic_observed"] = True
        phase_complete = True
    except BaseException as exc:
        result["status"] = "failed"
        result["failure_type"] = type(exc).__name__[:64]
        result["failure_frames"] = _failure_frames(exc)
    finally:
        if fixture_obj is not None:
            try:
                fixture_obj.close()
                host_fixture_closed = (fixture_obj.process is not None
                                       and fixture_obj.process.poll() is not None
                                       and all(not thread.is_alive() for thread in fixture_obj.threads))
            except Exception:
                host_fixture_closed = False
        for box in (BOX_BASE, BOX_DNS):
            try:
                cleanup[box] = _box_cleanup(start, box)
            except Exception as exc:
                cleanup[box] = {"cleanup_proven": False, "failure_type": type(exc).__name__[:64]}
    result["sandbox_cleanup"] = cleanup
    result["fixture_cleanup_proven"] = host_fixture_closed
    result["cleanup_proven"] = bool(host_fixture_closed and all(
        type(value) is dict and value.get("cleanup_proven") is True for value in cleanup.values()))
    if not result["cleanup_proven"]:
        result["status"] = "failed"
    elif phase_complete:
        # This status means the diagnostic ran and cleaned up. It never means
        # product acceptance or successful network containment.
        result["status"] = "passed"
    result["acceptance_passed"] = False
    result["product_acceptance"] = False
    result["product_acceptance_passed"] = False
    result["source_diagnostic_only"] = True
    result["diagnostic_only"] = True
    result["release_eligible"] = False
    result["product_acceptance_passed"] = False
    result["host_configuration_restored"] = False
    result["deployment_steps"] = ["administrator installs a signed kernel driver",
                                  "one reboot may be required",
                                  "ordinary user runs source diagnostic",
                                  "disposable VM is discarded"]
    _json_write(report, result)
    return result


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--phase", choices=("install", "probe"), required=True)
    parser.add_argument("--bundle", type=Path, required=True)
    parser.add_argument("--manifest", type=Path, required=True)
    parser.add_argument("--report", type=Path, required=True)
    parser.add_argument("--probe-user")
    parser.add_argument("--probe-user-sid")
    parser.add_argument("--install-report", type=Path)
    parser.add_argument("--artifacts", type=Path)
    args = parser.parse_args(argv)
    try:
        if args.phase == "install":
            if args.install_report or args.artifacts:
                raise ValueError("probe-only arguments are invalid during install")
            value = install(args.bundle, args.manifest, args.report, args.probe_user, args.probe_user_sid)
        else:
            if args.probe_user or args.probe_user_sid or not args.install_report or not args.artifacts:
                raise ValueError("probe arguments are incomplete or invalid")
            value = probe(args.bundle, args.manifest, args.report, args.install_report,
                          args.artifacts)
        return 0 if value.get("status") == "passed" else 1
    except BaseException as exc:
        # Error types are bounded diagnostics; never serialize arbitrary exception text.
        failure = {"schema_version": 1, "backend": BACKEND, "phase": args.phase,
                   "status": "failed", "failure_type": type(exc).__name__[:64],
                   "failure_frames": _failure_frames(exc),
                   "driver_signature": getattr(exc, "driver_signature", None),
                   "acceptance_passed": False, "product_acceptance": False,
                   "source_diagnostic_only": True, "diagnostic_only": True,
                   "product_acceptance_passed": False, "release_eligible": False,
                   "host_configuration_restored": False, "cleanup_proven": False}
        try:
            if os.name == "nt":
                failure.update(_win_identity(), **_os_facts())
        except Exception:
            failure.update(ordinary_user=None, is_elevated=None, is_administrator=None)
        try:
            _json_write(args.report, failure)
        except Exception:
            pass
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
