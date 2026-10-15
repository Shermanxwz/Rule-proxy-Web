"""Pinned Clew controller for a disposable Windows comparison VM.

This adapter supplies no traffic verdict. Actors must open ordinary destination
sockets; Clew excludes loopback traffic in its signed-release implementation.
It keeps DNS proxying disabled and never configures autostart or Mihomo TUN.
"""
from __future__ import annotations

import ctypes
import hashlib
import json
import ntpath
import os
from pathlib import Path, PurePosixPath
import re
import shutil
import socket
import stat
import subprocess
import time
import urllib.request
import zipfile


RELEASE = "v0.10.0"
ASSET_NAME = "clew-v0.10.0-windows-x64.zip"
ASSET_URL = ("https://github.com/ymonster/clew-proxy/releases/download/"
             + RELEASE + "/" + ASSET_NAME)
ASSET_SHA256 = "f1691d410269b432a03b4cbc5a251be161d0864f1420fe2722269e13b9c5e35d"
ASSET_SIZE = 2937630
API_PORT = 18080
API_ROOT = f"http://127.0.0.1:{API_PORT}"
MAX_JSON_BYTES = 2 * 1024 * 1024


def _sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as source:
        for block in iter(lambda: source.read(1024 * 1024), b""):
            digest.update(block)
    return digest.hexdigest()


def _write_json(path: Path, value) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    temporary = path.with_suffix(path.suffix + ".tmp")
    temporary.write_text(json.dumps(value, indent=2, ensure_ascii=True) + "\n", encoding="ascii")
    os.replace(temporary, path)


def _port_open() -> bool:
    try:
        with socket.create_connection(("127.0.0.1", API_PORT), timeout=.3):
            return True
    except OSError:
        return False


def _signature(path: Path, diagnostics: Path | None = None) -> dict:
    # Use an environment value, never interpolate an executable path as code.
    env = dict(os.environ, RULEPROXY_CLEW_DRIVER=str(path))
    # A pwsh 7 coordinator can export its own module path. Windows PowerShell
    # must load the inbox Security module used by Get-AuthenticodeSignature.
    env["PSModulePath"] = str(Path(env.get("SystemRoot", r"C:\Windows")) /
                              "System32/WindowsPowerShell/v1.0/Modules")
    command = ("$ErrorActionPreference='Stop'; "
               "$s=Get-AuthenticodeSignature -LiteralPath $env:RULEPROXY_CLEW_DRIVER; "
               "[ordered]@{status=[string]$s.Status; "
               "subject=[string]$s.SignerCertificate.Subject} | ConvertTo-Json -Compress")
    result = subprocess.run(["powershell.exe", "-NoLogo", "-NoProfile", "-NonInteractive",
                             "-Command", command], env=env, capture_output=True, timeout=20)
    observed = {"returncode": result.returncode,
                "stdout": result.stdout[:16384].decode("utf-8-sig", errors="replace"),
                "stderr": result.stderr[:16384].decode("utf-8-sig", errors="replace")}
    if diagnostics is not None:
        _write_json(diagnostics, observed)
    if result.returncode:
        raise RuntimeError("Clew bundled driver signature inspection failed: "
                           + json.dumps(observed, ensure_ascii=True))
    value = json.loads(result.stdout.decode("utf-8-sig"))
    if value.get("status") != "Valid":
        raise RuntimeError("Clew bundled WinDivert driver signature is not valid")
    return value


class Adapter:
    def __init__(self, work_dir: Path, artifacts: Path):
        self.work_dir = Path(work_dir).resolve()
        self.artifacts = Path(artifacts).resolve()
        self.root = self.work_dir / "clew-v0.10.0-windows-x64"
        self.exe = self.root / "clew.exe"
        self.config = self.root / "ruleproxy-compare.json"
        self.process = None
        self.group_ids = {}
        self.rule_ids = []
        self._firewall_names = []
        self._facts = {"backend": "clew", "release": RELEASE, "asset_url": ASSET_URL,
                       "asset_sha256": ASSET_SHA256, "dns_proxy_enabled": False,
                       "mihomo_tun_enabled": False, "api_host": "127.0.0.1",
                       "api_port": API_PORT, "transparent_traffic_proven": False,
                       "source_limits": ["loopback excluded by backend",
                                         "SYN watchdog may release undecided flow direct",
                                         "backend exit does not retain isolation"]}

    def _save(self) -> None:
        _write_json(self.artifacts / "clew-adapter.json", self._facts)

    def prepare(self) -> dict:
        self.work_dir.mkdir(parents=True, exist_ok=True)
        self.artifacts.mkdir(parents=True, exist_ok=True)
        archive = self.work_dir / ASSET_NAME
        valid = (archive.is_file() and not archive.is_symlink()
                 and archive.stat().st_size == ASSET_SIZE and _sha256(archive) == ASSET_SHA256)
        if not valid:
            partial = archive.with_suffix(".partial")
            try:
                request = urllib.request.Request(ASSET_URL, headers={"User-Agent": "RuleProxy-compare/1"})
                with urllib.request.urlopen(request, timeout=45) as source, partial.open("wb") as target:
                    total = 0
                    while block := source.read(128 * 1024):
                        total += len(block)
                        if total > ASSET_SIZE:
                            raise ValueError("Clew official archive exceeds pinned size")
                        target.write(block)
                if partial.stat().st_size != ASSET_SIZE or _sha256(partial) != ASSET_SHA256:
                    raise ValueError("Clew official archive SHA-256 or size mismatch")
                os.replace(partial, archive)
            finally:
                partial.unlink(missing_ok=True)
        expanded = 0
        seen = set()
        with zipfile.ZipFile(archive) as zipped:
            for member in zipped.infolist():
                name = member.filename
                path = PurePosixPath(name)
                mode = member.external_attr >> 16
                if (path.is_absolute() or ".." in path.parts or ":" in name or "\\" in name
                        or member.orig_filename != name or name.casefold() in seen
                        or stat.S_ISLNK(mode) or path.parts[0] != self.root.name):
                    raise ValueError("Unsafe Clew archive member")
                seen.add(name.casefold())
                expanded += member.file_size
                if member.file_size > 16 * 1024**2 or expanded > 64 * 1024**2:
                    raise ValueError("Clew expanded archive exceeds bounds")
                destination = self.work_dir.joinpath(*path.parts)
                if any(parent.is_symlink() for parent in (destination, *destination.parents)):
                    raise ValueError("Clew extraction path contains a symlink")
            zipped.extractall(self.work_dir)
        for name in ("clew.exe", "WinDivert.dll", "WinDivert64.sys"):
            if not (self.root / name).is_file():
                raise ValueError("Clew official archive layout changed")
        if (self.root / "dns_state.json").exists():
            raise RuntimeError("Refuse pre-existing Clew DNS recovery state")
        self._facts.update(prepared=True, archive_size=archive.stat().st_size,
                           executable_sha256=_sha256(self.exe),
                           driver_sha256=_sha256(self.root / "WinDivert64.sys"))
        self._save()
        return self.facts()

    def _api(self, method: str, path: str, body=None):
        data = None if body is None and method == "GET" else json.dumps(body or {}).encode("ascii")
        request = urllib.request.Request(API_ROOT + path, data=data, method=method,
                                         headers={"Content-Type": "application/json"})
        # Local control must not be sent through an inherited environment proxy.
        opener = urllib.request.build_opener(urllib.request.ProxyHandler({}))
        with opener.open(request, timeout=4) as response:
            raw = response.read(MAX_JSON_BYTES + 1)
            if len(raw) > MAX_JSON_BYTES:
                raise ValueError("Clew API response exceeds bounds")
            return json.loads(raw) if raw else {}

    def _log_ready(self) -> bool:
        path = self.root / "clew.log"
        if not path.is_file():
            return False
        with path.open("rb") as source:
            source.seek(max(0, path.stat().st_size - 256 * 1024))
            log = source.read().decode("utf-8", errors="replace")
        return all(marker in log for marker in ("Clew is ready.",
                   "WinDivert SOCKET layer started", "WinDivert NETWORK layer started",
                   "WinDivert UDP SOCKET layer started", "WinDivert UDP NETWORK layer started",
                   "UDP Relay started"))

    def _firewall_command(self, body: str, values: dict, artifact_name: str) -> dict:
        env = dict(os.environ, **values)
        env["PSModulePath"] = str(Path(env.get("SystemRoot", r"C:\Windows")) /
                                  "System32/WindowsPowerShell/v1.0/Modules")
        result = subprocess.run(["powershell.exe", "-NoLogo", "-NoProfile", "-NonInteractive",
                                 "-Command", "$ErrorActionPreference='Stop'; " + body],
                                env=env, capture_output=True, timeout=25)
        diagnostic = {"returncode": result.returncode,
                      "stdout": result.stdout[:32768].decode("utf-8-sig", errors="replace"),
                      "stderr": result.stderr[:16384].decode("utf-8-sig", errors="replace")}
        _write_json(self.artifacts / artifact_name, diagnostic)
        if result.returncode:
            raise RuntimeError("Clew program-scoped firewall operation failed: "
                               + json.dumps(diagnostic, ensure_ascii=True))
        return json.loads(result.stdout.decode("utf-8-sig"))

    def _allow_reflected_inbound(self) -> None:
        # Reflection enters the local relay as inbound traffic from the
        # original remote IP. Authorize only this executable and its observed
        # relay ports, matching the prerequisite an interactive firewall prompt
        # otherwise asks for. No profile, policy, or default action is changed.
        log = (self.root / "clew.log").read_text(encoding="utf-8", errors="replace")
        self._facts["configuration_durability_warning"] = (
            "Failed to rename" in log and "Access is denied" in log)
        tcp = sorted(set(re.findall(r"(?:Acceptor listening|\[ACCEPTOR\] Listening) on port (\d+)", log)))
        udp = sorted(set(re.findall(r"(?:UDP Relay started|\[UDP-RELAY\] Listening) on port (\d+)", log)))
        if len(tcp) != 1 or len(udp) != 1 or any(not 1 <= int(port) <= 65535 for port in (*tcp, *udp)):
            raise RuntimeError("Cannot identify exact Clew relay ports for inbound authorization")
        unique = str(os.getpid()) + "-" + str(time.time_ns())
        names = ["RuleProxyCompare-Clew-" + unique + "-" + protocol for protocol in ("TCP", "UDP")]
        values = {"RULEPROXY_CLEW_FW_TCP_NAME": names[0], "RULEPROXY_CLEW_FW_UDP_NAME": names[1],
                  "RULEPROXY_CLEW_FW_EXE": str(self.exe),
                  "RULEPROXY_CLEW_FW_TCP": tcp[0], "RULEPROXY_CLEW_FW_UDP": udp[0]}
        before = self._firewall_command(
            "$names=@($env:RULEPROXY_CLEW_FW_TCP_NAME,$env:RULEPROXY_CLEW_FW_UDP_NAME); "
            "$r=@(Get-NetFirewallRule -Name $names -ErrorAction SilentlyContinue); "
            "[ordered]@{existing_count=$r.Count}|ConvertTo-Json -Compress", values,
            "clew-firewall-before.json")
        if before.get("existing_count") != 0:
            raise RuntimeError("Refuse existing diagnostic firewall rule names")
        self._firewall_names = names  # Include partial install in exception cleanup.
        created = self._firewall_command(
            "$names=@($env:RULEPROXY_CLEW_FW_TCP_NAME,$env:RULEPROXY_CLEW_FW_UDP_NAME); "
            "New-NetFirewallRule -Name ([string]$names[0]) -DisplayName ([string]$names[0]) -Direction Inbound "
            "-Action Allow -Enabled True -Profile Any -Program $env:RULEPROXY_CLEW_FW_EXE "
            "-Protocol TCP -LocalPort ([int]$env:RULEPROXY_CLEW_FW_TCP) -EdgeTraversalPolicy Block|Out-Null; "
            "New-NetFirewallRule -Name ([string]$names[1]) -DisplayName ([string]$names[1]) -Direction Inbound "
            "-Action Allow -Enabled True -Profile Any -Program $env:RULEPROXY_CLEW_FW_EXE "
            "-Protocol UDP -LocalPort ([int]$env:RULEPROXY_CLEW_FW_UDP) -EdgeTraversalPolicy Block|Out-Null; "
            "$r=@(Get-NetFirewallRule -Name $names); "
            "[ordered]@{rules=@($r|Select-Object Name,Enabled,Direction,Action,Profile); "
            "application_filters=@($r|Get-NetFirewallApplicationFilter|Select-Object Program); "
            "port_filters=@($r|Get-NetFirewallPortFilter|Select-Object Protocol,LocalPort)} "
            "|ConvertTo-Json -Depth 5 -Compress", values, "clew-firewall-installed.json")
        if len(created.get("rules", [])) != 2:
            raise RuntimeError("Clew inbound authorization read-back incomplete")
        self._facts["program_scoped_firewall"] = {"before": before, "installed": created,
            "program": str(self.exe), "relay_tcp_port": int(tcp[0]), "relay_udp_port": int(udp[0]),
            "reason": "bounded inbound reflection compatibility control", "root_cause_proven": False,
            "global_policy_changed": False}
        self._save()

    def _remove_reflected_inbound(self) -> dict:
        if not self._firewall_names:
            return {"owned_rule_count": 0, "remaining_count": 0, "cleanup_proven": True}
        values = {"RULEPROXY_CLEW_FW_TCP_NAME": self._firewall_names[0],
                  "RULEPROXY_CLEW_FW_UDP_NAME": self._firewall_names[1]}
        after = self._firewall_command(
            "$names=@($env:RULEPROXY_CLEW_FW_TCP_NAME,$env:RULEPROXY_CLEW_FW_UDP_NAME); "
            "Get-NetFirewallRule -Name $names -ErrorAction SilentlyContinue "
            "|Remove-NetFirewallRule; "
            "$r=@(Get-NetFirewallRule -Name $names -ErrorAction SilentlyContinue); "
            "[ordered]@{remaining_count=$r.Count}|ConvertTo-Json -Compress", values,
            "clew-firewall-after.json")
        after.update(owned_rule_count=len(self._firewall_names),
                     cleanup_proven=after.get("remaining_count") == 0)
        if after["cleanup_proven"]:
            self._firewall_names = []
        return after

    def start(self, proxy_ports: dict[str, int], app_paths: list[str], group: str = "A") -> dict:
        if os.name != "nt" or not ctypes.windll.shell32.IsUserAnAdmin():
            raise RuntimeError("Clew diagnostic start requires an elevated Windows VM controller")
        if self.process is not None:
            raise RuntimeError("Clew adapter already started")
        if group not in proxy_ports or not app_paths or any(
                type(port) is not int or not 1 <= port <= 65535 for port in proxy_ports.values()):
            raise ValueError("Invalid fixed proxy ports or empty selected applications")
        if _port_open():
            raise RuntimeError("Refuse to attach to a pre-existing Clew API on port 18080")
        self._facts["driver_signature"] = _signature(
            self.root / "WinDivert64.sys", self.artifacts / "clew-driver-signature.json")
        if (self.root / "clew.log").exists():
            raise RuntimeError("Refuse stale Clew runtime directory")
        initial = {"version": 2, "default_proxy": {"type": "socks5", "host": "127.0.0.1",
                    "port": proxy_ports[group]}, "proxy_groups": [], "next_group_id": 1,
                   "default_exclude_cidrs": [], "auto_rules": [], "dns": {"enabled": False},
                   "log_level": "info", "io_threads": 2,
                   "tcp_syn_parking": {"enabled": True, "watchdog_ms": 20, "pool_size": 256}}
        _write_json(self.config, initial)
        self.process = subprocess.Popen([str(self.exe), "--minimized", "--config", str(self.config)],
                                        cwd=self.root, stdin=subprocess.DEVNULL,
                                        stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
                                        creationflags=subprocess.CREATE_NEW_PROCESS_GROUP)
        self._facts.update(started=True, owned_pid=self.process.pid, running=True)
        self._save()
        try:
            deadline = time.monotonic() + 40
            while time.monotonic() < deadline:
                if self.process.poll() is not None:
                    raise RuntimeError("Clew exited before interception readiness")
                try:
                    self._api("GET", "/api/stats")
                    if self._log_ready():
                        break
                except (OSError, ValueError):
                    pass
                time.sleep(.2)
            else:
                raise TimeoutError("Clew API/interception readiness timeout")
            loaded = self._api("GET", "/api/config")
            if loaded.get("dns", {}).get("enabled") is not False:
                raise RuntimeError("Clew unexpectedly enabled global DNS proxy")
            self._allow_reflected_inbound()
            for label, port in proxy_ports.items():
                created = self._api("POST", "/api/proxy-groups", {"name": "RuleProxyCompare-" + label,
                                    "host": "127.0.0.1", "port": port, "type": "socks5"})
                self.group_ids[label] = created["id"]
            for index, app_path in enumerate(app_paths):
                normalized = ntpath.normpath(app_path)
                if not ntpath.isabs(normalized) or "*" in normalized or "?" in normalized:
                    raise ValueError("Selected application must be an absolute exact Windows path")
                rule_id = "ruleproxy_compare_" + str(index)
                rule = {"id": rule_id, "name": rule_id, "enabled": True,
                        "process_name": ntpath.basename(normalized), "cmdline_pattern": "",
                        "image_path_pattern": normalized, "hack_tree": True, "protocol": "both",
                        "proxy_group_id": self.group_ids[group], "dst_filter": {}}
                self._api("POST", "/api/auto-rules", rule)
                self.rule_ids.append(rule_id)
            self._verify_rules(group)
            self._facts.update(api_ready=True, interception_layers_started=True,
                               proxy_groups=dict(self.group_ids), selected_group=group,
                               selected_application_count=len(app_paths), rule_count=len(self.rule_ids))
            self._save()
            return self.facts()
        except BaseException:
            self.stop()
            raise

    def _verify_rules(self, group: str) -> None:
        rules = self._api("GET", "/api/auto-rules")
        by_id = {row["id"]: row for row in rules}
        for rule_id in self.rule_ids:
            row = by_id.get(rule_id, {})
            if (row.get("proxy_group_id") != self.group_ids[group] or row.get("enabled") is not True
                    or row.get("hack_tree") is not True or row.get("protocol") != "both"):
                raise RuntimeError("Clew rule read-back mismatch")

    def set_group(self, group: str) -> dict:
        if group not in self.group_ids or self.process is None or self.process.poll() is not None:
            raise ValueError("Clew group unavailable or owned backend stopped")
        for rule_id in self.rule_ids:
            self._api("PUT", "/api/auto-rules/" + rule_id,
                      {"proxy_group_id": self.group_ids[group]})
        self._verify_rules(group)
        self._facts["selected_group"] = group
        self._save()
        return {"updated": True, "group": group, "rule_count": len(self.rule_ids),
                "existing_connections_rebound": False}

    def _request_exit(self) -> int:
        """Send the official tray Exit command only to windows of our own PID."""
        from ctypes import wintypes
        user32 = ctypes.WinDLL("user32", use_last_error=True)
        callback_type = ctypes.WINFUNCTYPE(wintypes.BOOL, wintypes.HWND, wintypes.LPARAM)
        user32.EnumWindows.argtypes = (callback_type, wintypes.LPARAM)
        user32.GetWindowThreadProcessId.argtypes = (wintypes.HWND, ctypes.POINTER(wintypes.DWORD))
        user32.PostMessageW.argtypes = (wintypes.HWND, wintypes.UINT, wintypes.WPARAM, wintypes.LPARAM)
        count = 0
        @callback_type
        def visit(hwnd, _):
            nonlocal count
            owner = wintypes.DWORD()
            user32.GetWindowThreadProcessId(hwnd, ctypes.byref(owner))
            if owner.value == self.process.pid:
                if user32.PostMessageW(hwnd, 0x0111, 40002, 0):  # WM_COMMAND / IDM_TRAY_EXIT
                    count += 1
            return True
        user32.EnumWindows(visit, 0)
        return count

    def stop(self) -> dict:
        forced = False
        requested = 0
        errors = []
        if self.process is not None and self.process.poll() is None:
            try:
                requested = self._request_exit()
                self.process.wait(timeout=10)
            except (OSError, subprocess.TimeoutExpired) as exc:
                errors.append(type(exc).__name__)
                forced = True
                self.process.terminate()
                self.process.wait(timeout=5)
        exited = self.process is None or self.process.poll() is not None
        deadline = time.monotonic() + 3
        while exited and _port_open() and time.monotonic() < deadline:
            time.sleep(.1)
        api_closed = not _port_open()
        try:
            firewall_cleanup = self._remove_reflected_inbound()
        except Exception as exc:
            firewall_cleanup = {"cleanup_proven": False, "error_type": type(exc).__name__}
            errors.append("program_scoped_firewall_cleanup_failed")
        log = self.root / "clew.log"
        if log.is_file():
            shutil.copyfile(log, self.artifacts / "clew.log")
        result = {"exited": exited, "api_closed": api_closed, "forced": forced,
                  "graceful_exit_command_windows": requested, "errors": errors,
                  "cleanup_proven": exited and api_closed and firewall_cleanup["cleanup_proven"],
                  "program_scoped_firewall_cleanup": firewall_cleanup,
                  "global_dns_change_requested": False, "driver_uninstalled": False}
        self._facts.update(running=False, stop=result)
        self._save()
        return result

    def facts(self) -> dict:
        value = json.loads(json.dumps(self._facts))
        if self.process is not None and self.process.poll() is None:
            try:
                value["stats"] = self._api("GET", "/api/stats")
            except (OSError, ValueError) as exc:
                value["stats_error"] = type(exc).__name__
        return value
