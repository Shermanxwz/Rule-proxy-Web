"""Pinned ProxiFyre console adapter for a disposable Windows comparison.

The administrator coordinator owns this adapter; network actors run separately
as ordinary users. Mihomo is only a loopback SOCKS5 outlet: this module never
enables TUN or changes system proxy, DNS, or routes. Upstream's installer adds
its own NDIS filter, manual service registration and program firewall rules.
The comparison runs the console engine, not that service.
"""
from __future__ import annotations

import argparse
import ctypes
import hashlib
import json
import os
from pathlib import Path, PureWindowsPath
import shutil
import signal
import subprocess
import sys
import time
import urllib.request
import zipfile


BACKEND = "proxifyre"
VERSION = "2.6.4"
TAG = "v" + VERSION
SOURCE_URL = "https://github.com/wiresock/proxifyre/releases/tag/" + TAG
ASSETS = {
    "setup": {
        "name": "ProxiFyre-2.6.4-win-x64-setup.exe",
        "url": "https://github.com/wiresock/proxifyre/releases/download/v2.6.4/ProxiFyre-2.6.4-win-x64-setup.exe",
        "size": 2889730,
        "sha256": "afaf3ac8a2069f9653adb1b4a63b31d1edd8aa109ccdc367cf0d4462e78f5027",
    },
    "payload": {
        "name": "ProxiFyre-v2.6.4-x64.zip",
        "url": "https://github.com/wiresock/proxifyre/releases/download/v2.6.4/ProxiFyre-v2.6.4-x64.zip",
        "size": 1868618,
        "sha256": "c7da1dc5fdf9aaa7828fbf5c2076c4f612cba7889dcac2e3d06dc2e1dee4c3df",
    },
}
# Published in the fixed release's docs/installer.md and embedded in Burn.
# Setup verifies these external prerequisite payloads before executing them.
INSTALLER_PREREQUISITES = {
    "windows_packet_filter": {
        "version": "3.6.2.1", "size": 819200,
        "url": "https://github.com/wiresock/ndisapi/releases/download/v3.6.2/Windows.Packet.Filter.3.6.2.1.x64.msi",
        "sha256": "9c388c0b7f189f7fa98720bae2caecf7d64f30910838b80b438ecf8956b8502c",
    },
    "visual_cpp_runtime": {
        "version": "14.44.35211.0", "size": 25635768,
        "url": "https://download.visualstudio.microsoft.com/download/pr/0b44c2d1-8944-4834-a01a-c9a225f8088a/CC0FF0EB1DC3F5188AE6300FAEF32BF5BEEBA4BDD6E8E445A9184072096B713B/VC_redist.x64.exe",
        "sha256": "cc0ff0eb1dc3f5188ae6300faef32bf5beeba4bdd6e8e445a9184072096b713b",
    },
}
PE_FILES = ("ProxiFyre.exe", "ProxiFyreUI.exe", "ProxiFyreUI.Managed.dll",
            "ProxiFyre.Configuration.dll", "socksify.dll", "Newtonsoft.Json.dll",
            "NLog.dll", "Topshelf.dll")
READY_TEXT = "ProxiFyre Service is running..."
MAX_OUTPUT = 128 * 1024


def sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        for block in iter(lambda: stream.read(1024 * 1024), b""):
            digest.update(block)
    return digest.hexdigest()


def _write_json(path: Path, value: dict) -> None:
    body = (json.dumps(value, sort_keys=True, indent=2) + "\n").encode("utf-8")
    if len(body) > MAX_OUTPUT:
        raise ValueError("comparison JSON exceeds fixed bound")
    temporary = path.with_name(path.name + ".tmp")
    temporary.write_bytes(body)
    temporary.replace(path)


def verify_asset(path: Path, asset: dict) -> None:
    st = path.lstat()
    if (not path.is_file() or path.is_symlink()
            or getattr(st, "st_file_attributes", 0) & 0x400
            or st.st_size != asset["size"] or sha256(path) != asset["sha256"]):
        raise ValueError("fixed upstream asset size or SHA-256 mismatch")


def fetch_asset(directory: Path, asset: dict) -> Path:
    path = directory / asset["name"]
    if path.exists():
        verify_asset(path, asset)
        return path
    temporary = path.with_name(path.name + ".partial")
    request = urllib.request.Request(asset["url"], headers={"User-Agent": "RuleProxy-proxy-compare/1"})
    try:
        with urllib.request.urlopen(request, timeout=45) as source, temporary.open("xb") as target:
            received = 0
            deadline = time.monotonic() + 90
            while block := source.read(1024 * 1024):
                received += len(block)
                if received > asset["size"] or time.monotonic() > deadline:
                    raise ValueError("upstream asset exceeded download bounds")
                target.write(block)
        verify_asset(temporary, asset)
        temporary.replace(path)
        return path
    finally:
        temporary.unlink(missing_ok=True)


def configuration(proxy_ports: dict[str, int], app_paths: list[str], group: str) -> dict:
    """Build path rules only; child executables must be explicitly supplied."""
    if (not isinstance(proxy_ports, dict) or not proxy_ports
            or group not in proxy_ports
            or any(not isinstance(key, str) or not key or len(key) > 32
                   or type(port) is not int or not 1 <= port <= 65535
                   for key, port in proxy_ports.items())):
        raise ValueError("invalid loopback proxy groups")
    if not isinstance(app_paths, list) or not 1 <= len(app_paths) <= 32:
        raise ValueError("one to 32 explicit executable paths are required")
    normalized = []
    for value in app_paths:
        if (not isinstance(value, str) or len(value) > 1024 or "\x00" in value
                or any(char in value for char in "*?")):
            raise ValueError("invalid selected executable path")
        path = PureWindowsPath(value)
        if (not path.is_absolute() or path.drive.startswith("\\")
                or path.suffix.lower() != ".exe" or ".." in path.parts):
            raise ValueError("selected application must be a local absolute exe path")
        canonical = str(path)
        if canonical.casefold() not in {item.casefold() for item in normalized}:
            normalized.append(canonical)
    return {"logLevel": "Info", "bypassLan": False, "excludes": [], "proxies": [{
        "appNames": normalized,
        "socks5ProxyEndpoint": "127.0.0.1:" + str(proxy_ports[group]),
        "socks5Transport": "TCP", "supportedProtocols": ["TCP", "UDP"],
        "supportedAddressFamilies": ["IPv4", "IPv6"],
    }]}


def _ps_quote(value: object) -> str:
    return "'" + str(value).replace("'", "''") + "'"


class Adapter:
    def __init__(self, work_dir: Path, artifacts: Path):
        self.work_dir = Path(work_dir)
        self.artifacts = Path(artifacts)
        self.install_root = Path(os.environ.get("ProgramFiles", r"C:\Program Files")) / "ProxiFyre"
        self.engine = self.install_root / "ProxiFyre.exe"
        self.process = None
        self._output = None
        self._ports: dict[str, int] = {}
        self._apps: list[str] = []
        self._group = None
        self._prepared = False
        self._generation = 0
        self._prepare_facts: dict = {}
        self._stop_facts: dict = {}
        self._config = None
        self._engine_log_offset = 0

    def _require_windows_admin(self) -> None:
        if sys.platform != "win32" or not ctypes.windll.shell32.IsUserAnAdmin():
            raise RuntimeError("disposable Windows administrator coordinator required")
        expected = os.path.normcase(os.path.abspath(r"C:\RuleProxyCompare\backend"))
        if os.path.normcase(os.path.abspath(self.work_dir)) != expected:
            raise ValueError("adapter accepts only the fixed disposable comparison directory")

    def _powershell(self, body: str, timeout: int = 20) -> dict:
        executable = shutil.which("powershell.exe")
        if not executable:
            raise RuntimeError("Windows PowerShell is required")
        env = dict(os.environ)
        env["PSModulePath"] = str(Path(env.get("SystemRoot", r"C:\Windows")) /
                                  "System32/WindowsPowerShell/v1.0/Modules")
        result = subprocess.run([executable, "-NoProfile", "-NonInteractive", "-Command",
                                 "$ErrorActionPreference='Stop'; " + body],
                                capture_output=True, timeout=timeout, env=env, check=False)
        if result.returncode or len(result.stdout) > MAX_OUTPUT:
            raise RuntimeError("bounded Windows inspection failed")
        value = json.loads(result.stdout.decode("utf-8-sig"))
        if not isinstance(value, dict):
            raise RuntimeError("Windows inspection returned a non-object")
        return value

    def _deployment_facts(self) -> dict:
        return self._powershell(
            "$s=Get-CimInstance Win32_Service -Filter \"Name='ProxiFyreService'\"; "
            "$d=Get-CimInstance Win32_SystemDriver -Filter \"Name='NDISRD'\"; "
            "$p=Join-Path $env:SystemRoot 'System32\\drivers\\ndisrd.sys'; "
            "$signature=if(Test-Path -LiteralPath $p){"
            "[string](Get-AuthenticodeSignature -LiteralPath $p).Status}else{'Missing'}; "
            "[ordered]@{service_exists=($null -ne $s); service_state=[string]$s.State; "
            "driver_exists=($null -ne $d); driver_state=[string]$d.State; "
            "driver_signature=$signature}|ConvertTo-Json -Compress")

    def _verify_installed_payload(self, archive_path: Path) -> dict:
        with zipfile.ZipFile(archive_path) as archive:
            rows = []
            for name in PE_FILES:
                members = [item for item in archive.infolist()
                           if item.filename.replace("\\", "/").split("/")[-1] == name]
                if len(members) != 1 or members[0].file_size > 32 * 1024**2:
                    raise ValueError("fixed release payload layout changed")
                expected = hashlib.sha256(archive.read(members[0])).hexdigest()
                installed = self.install_root / name
                if (not installed.is_file() or installed.is_symlink()
                        or sha256(installed) != expected):
                    raise ValueError("installed module differs from fixed upstream ZIP")
                rows.append({"file": name, "sha256": expected})
        return {"matches_fixed_release_zip": True, "modules": rows}

    def prepare(self) -> dict:
        self._require_windows_admin()
        if self._prepared:
            return dict(self._prepare_facts)
        self.work_dir.mkdir(parents=True, exist_ok=True)
        self.artifacts.mkdir(parents=True, exist_ok=True)
        # This comparison owns a fresh installation; it never upgrades or changes
        # a pre-existing user's ProxiFyre deployment.
        before = self._deployment_facts()
        if before["service_exists"] or self.install_root.exists():
            raise RuntimeError("comparison refuses an existing ProxiFyre installation")
        setup = fetch_asset(self.work_dir, ASSETS["setup"])
        payload = fetch_asset(self.work_dir, ASSETS["payload"])
        setup_log = self.artifacts / "proxifyre-setup.log"
        installer = subprocess.Popen([str(setup), "/quiet", "/norestart", "/log", str(setup_log)],
                                     cwd=self.work_dir, stdout=subprocess.DEVNULL,
                                     stderr=subprocess.DEVNULL)
        try:
            installer_exit = installer.wait(timeout=240)
        except subprocess.TimeoutExpired:
            # Burn can own a prerequisite installer child. Kill only the
            # comparison-owned process tree instead of leaving it behind.
            taskkill = Path(os.environ.get("SystemRoot", r"C:\Windows")) / "System32/taskkill.exe"
            subprocess.run([str(taskkill), "/PID", str(installer.pid), "/T", "/F"],
                           timeout=15, check=False, stdout=subprocess.DEVNULL,
                           stderr=subprocess.DEVNULL)
            if installer.poll() is None:
                installer.kill()
            installer.wait(timeout=5)
            raise RuntimeError("official setup exceeded 240-second bound") from None
        self._prepare_facts = {"backend": BACKEND, "version": VERSION,
            "source_url": SOURCE_URL, "assets": ASSETS,
            "prerequisites_verified_by_upstream_installer": INSTALLER_PREREQUISITES,
            "installer_exit_code": installer_exit, "tun_enabled": False,
            "engine_mode": "owned_administrator_console", "service_used_for_test": False,
            "installer_registers_manual_service": True,
            "installer_adds_program_scoped_inbound_firewall_rules": True,
            "first_party_authenticode": "unsigned_by_upstream_design_sha256_pinned",
            "child_process_inheritance": "not_implemented_explicit_exe_paths_only",
            "product_acceptance_passed": False, "diagnostic_only": True}
        _write_json(self.artifacts / "proxifyre-prepare.json", self._prepare_facts)
        if installer_exit in (1641, 3010):
            raise RuntimeError("official setup requires reboot; bounded comparison stops")
        if installer_exit:
            raise RuntimeError("fixed upstream setup failed")
        self._prepare_facts["payload"] = self._verify_installed_payload(payload)
        deployment = self._deployment_facts()
        self._prepare_facts["deployment"] = deployment
        if (not deployment["driver_exists"] or deployment["driver_signature"] != "Valid"
                or deployment["service_state"].lower() == "running"):
            raise RuntimeError("signed driver or unused manual-service state is not verified")
        # The official MSI leaves NDISRD demand-started. Console mode needs it
        # running too; starting this existing driver is not starting ProxiFyreService.
        self._powershell("Start-Service -Name NDISRD; "
                         "[ordered]@{started=$true}|ConvertTo-Json -Compress")
        self._prepared = True
        self._prepare_facts["status"] = "prepared"
        _write_json(self.artifacts / "proxifyre-prepare.json", self._prepare_facts)
        return dict(self._prepare_facts)

    def start(self, proxy_ports: dict[str, int], app_paths: list[str], group: str = "A") -> dict:
        self._require_windows_admin()
        config = configuration(proxy_ports, app_paths, group)
        if not self._prepared:
            raise RuntimeError("prepare must complete before starting the engine")
        if self.process is not None:
            self.stop()
        _write_json(self.install_root / "app-config.json", config)
        self._ports, self._apps, self._group = dict(proxy_ports), list(app_paths), group
        self._config = config
        self._generation += 1
        output_path = self.artifacts / f"proxifyre-console-{self._generation}.log"
        engine_log = self.install_root / "logs/logfile.txt"
        self._engine_log_offset = engine_log.stat().st_size if engine_log.is_file() else 0
        self._output = output_path.open("wb")
        try:
            self.process = subprocess.Popen([str(self.engine), "run"], cwd=self.install_root,
                stdin=subprocess.DEVNULL, stdout=self._output, stderr=subprocess.STDOUT,
                creationflags=subprocess.CREATE_NEW_PROCESS_GROUP)
            deadline = time.monotonic() + 20
            while time.monotonic() < deadline:
                if self.process.poll() is not None:
                    raise RuntimeError("console engine exited before readiness")
                # Only a current-launch console marker counts as readiness. The
                # actual datapath must still pass the coordinator's transparent probes.
                with output_path.open("rb") as stream:
                    stream.seek(max(0, output_path.stat().st_size - MAX_OUTPUT))
                    output = stream.read(MAX_OUTPUT).decode("utf-8", "replace")
                # Upstream NLog writes only to logs/logfile.txt. Read bytes
                # appended by this launch so an old generation cannot pass.
                if engine_log.is_file():
                    with engine_log.open("rb") as stream:
                        stream.seek(self._engine_log_offset)
                        output += stream.read(MAX_OUTPUT).decode("utf-8", "replace")
                if READY_TEXT in output or "The ProxiFyre service is now running" in output:
                    return {"started": True, "pid": self.process.pid, "group": group,
                            "console_ready_observed": True, "datapath_verified": False,
                            "tun_enabled": False}
                time.sleep(.2)
            raise RuntimeError("console engine readiness exceeded 20-second bound")
        except BaseException:
            self.stop()
            raise

    def set_group(self, group: str) -> dict:
        if not self._ports or not self._apps:
            raise RuntimeError("engine has no selected application configuration")
        result = self.start(self._ports, self._apps, group)
        return {**result, "rule_update_requires_engine_restart": True}

    def stop(self) -> dict:
        process = self.process
        graceful = False
        if process is not None:
            if process.poll() is None:
                try:
                    process.send_signal(signal.CTRL_BREAK_EVENT)
                    process.wait(timeout=5)
                    graceful = True
                except (OSError, subprocess.TimeoutExpired):
                    if process.poll() is None:
                        process.terminate()
                        try:
                            process.wait(timeout=5)
                        except subprocess.TimeoutExpired:
                            process.kill()
                            process.wait(timeout=5)
            self._stop_facts = {"stopped": process.poll() is not None,
                "owned_pid": process.pid, "exit_code": process.returncode,
                "graceful_console_stop": graceful,
                "driver_left_installed_in_disposable_runner": True}
            self.process = None
            engine_log = self.install_root / "logs/logfile.txt"
            if engine_log.is_file():
                with engine_log.open("rb") as stream:
                    stream.seek(self._engine_log_offset)
                    data = stream.read(MAX_OUTPUT)
                (self.artifacts / f"proxifyre-engine-{self._generation}.log").write_bytes(data)
        if self._output is not None:
            self._output.close()
            self._output = None
        return dict(self._stop_facts or {"stopped": True, "owned_pid": None})

    def facts(self) -> dict:
        running = self.process is not None and self.process.poll() is None
        value = {"backend": BACKEND, "version": VERSION, "prepared": self._prepared,
            "running": running, "pid": self.process.pid if running else None,
            "engine_exit_code": self.process.poll() if self.process is not None else None,
            "group": self._group, "engine_mode": "owned_administrator_console",
            "service_used_for_test": False, "tun_enabled": False,
            "system_dns_modified_by_adapter": False, "system_proxy_modified_by_adapter": False,
            "system_routes_modified_by_adapter": False,
            "supports": {"path_rules": True, "pid_rules": False,
                "automatic_child_inheritance": False, "tcp": True, "udp": True,
                "ipv4": True, "ipv6": True},
            "upstream_known_boundary": "IPv6 fragments may pass direct; engine exit can restore direct networking",
            "stop": dict(self._stop_facts), "prepare": dict(self._prepare_facts)}
        if self._config is not None:
            value["active_configuration"] = self._config
        if sys.platform == "win32":
            value["deployment"] = self._deployment_facts()
        return value


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--describe", action="store_true",
                        help="Print fixed sources without downloading or executing anything")
    args = parser.parse_args(argv)
    if not args.describe:
        parser.error("use Adapter from the administrator comparison coordinator")
    print(json.dumps({"backend": BACKEND, "version": VERSION, "assets": ASSETS,
                      "prerequisites": INSTALLER_PREREQUISITES, "tun_enabled": False}, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
