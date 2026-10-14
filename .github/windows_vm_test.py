"""Run the release's real Windows x64 tests in an ephemeral KVM guest.

Requires Ubuntu packages: qemu-system-x86 qemu-utils ovmf swtpm xorriso curl
and 7zip (7zz) or p7zip-full (7z), for Microsoft's UDF installation media.
Run with access to /dev/kvm (sudo on GitHub's Ubuntu runner). No TCG fallback,
host network changes, prebuilt third-party Windows image or product key.
Only logs/reports/screenshots enter --artifacts; the answer file, passwords,
test capability, OS ISO and guest disk remain in a private temporary directory.
"""

from __future__ import annotations

import argparse
import hashlib
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
import json
import os
from pathlib import Path
import platform
import secrets
import shutil
import socket
import struct
import subprocess
import sys
import tempfile
import threading
import time
import xml.etree.ElementTree as ET
import zipfile
import zlib


ROOT = Path(__file__).resolve().parent.parent
ISO_URL = ("https://software-static.download.prss.microsoft.com/dbazure/"
           "26300.9457.260913-1737.26h2_ge_release_svc_refresh_"
           "CLIENTENTERPRISEEVAL_OEMRET_x64FRE_en-us.iso")
ISO_SHA256 = "bc3f24086ebadc94489066b5ad78089e2cf5c3491e90e790bb81a2b199c10e38"
ISO_BYTES = 8_225_329_152
ISO_SOURCE = "https://www.microsoft.com/en-us/evalcenter/download-windows-11-enterprise"
ISO_HASH_SOURCE = ("https://support.microsoft.com/en-us/servicing/os/windows/docs/2026/09/"
                   "verify-the-authenticity-of-a-windows-11-enterprise-evaluation-iso-file")
UPDATE_BUILD = 26300
UPDATE_UBR = 9711
UPDATE_SOURCE = ("https://support.microsoft.com/en-us/servicing/os/windows-11/2026/10/"
                 "kb5127648-windows-11-24h2-25h2-26h2-security-update")
UPDATE_CATALOG_ID = "3aa52c0d-45db-47a4-be28-4b0042c5ac78"
# SHA-256 values come from Microsoft's Catalog DownloadDialog metadata, not
# from a locally downloaded package. Checkpoint and target share one MSU-only
# directory so Windows servicing can discover the required dependency.
UPDATE_PACKAGES = (
    {"filename": "windows11.0-kb5043080-x64_953449672073f8fb99badb4cc6d5d7849b9c83e8.msu",
     "seed_filename": "windows11.0-kb5043080-x64.msu",
     "url": "https://catalog.sf.dl.delivery.mp.microsoft.com/filestreamingservice/files/"
            "d8b7f92b-bd35-4b4c-96e5-46ce984b31e0/public/"
            "windows11.0-kb5043080-x64_953449672073f8fb99badb4cc6d5d7849b9c83e8.msu",
     "sha256": "819632610a101af11c72907fb13ff05b5fb4222c0e263ee9a03bcc1d1d5f26a4",
     "bytes": 533_761_740},
    {"filename": "windows11.0-kb5127648-x64_2b88d2d308adc938fcd4d2876a68ee0b2a3c4c09.msu",
     "seed_filename": "windows11.0-kb5127648-x64.msu",
     "url": "https://catalog.sf.dl.delivery.mp.microsoft.com/filestreamingservice/files/"
            "4225b261-8248-43e5-a808-34f3faafe3f6/public/"
            "windows11.0-kb5127648-x64_2b88d2d308adc938fcd4d2876a68ee0b2a3c4c09.msu",
     "sha256": "8a1067c763121953876e2e0dcbf5e2c5832545a44ef6baba362938287e05fcfb",
     "bytes": 4_775_050_195},
)
MIN_FREE_BYTES = 55 * 1024**3
MAX_RESULT_BYTES = 8 * 1024**2
MAX_PHASE_RECORD_BYTES = 256 * 1024
PHASE_NAMES = ("probe", "transport", "manager", "browser", "package_tests")
MIN_BOOT_IMAGE_BYTES = 64 * 1024**2
MIN_INSTALL_IMAGE_BYTES = 1024**3


def digest(path: Path) -> str:
    checksum = hashlib.sha256()
    with path.open("rb") as stream:
        for block in iter(lambda: stream.read(1024 * 1024), b""):
            checksum.update(block)
    return checksum.hexdigest()


def write_json(path: Path, value: dict) -> None:
    path.write_text(json.dumps(value, ensure_ascii=True, indent=2) + "\n", encoding="ascii")


def require_kvm() -> int:
    """Verify the real KVM_CREATE_VM ioctl before downloading an 8 GB ISO."""
    if sys.platform != "linux" or platform.machine().lower() not in ("x86_64", "amd64"):
        raise RuntimeError("The guest requires an x64 Linux KVM host")
    import fcntl

    with open("/dev/kvm", "r+b", buffering=0) as device:
        version = fcntl.ioctl(device.fileno(), 0xAE00, 0)
        if version != 12:
            raise RuntimeError("Unexpected KVM API version")
        guest = fcntl.ioctl(device.fileno(), 0xAE01, 0)
        os.close(guest)
    return version


def verify_package(path: Path, expected: str) -> None:
    if len(expected) != 64 or any(char not in "0123456789abcdef" for char in expected):
        raise ValueError("--package-sha256 must contain the expected SHA-256 from the package build")
    if digest(path) != expected:
        raise ValueError("Release ZIP does not match its external SHA-256")
    with zipfile.ZipFile(path) as archive:
        names = set(archive.namelist())
        needed = {"RuleProxy-Web/python/python.exe", "RuleProxy-Web/ruleproxy/windows_runtime.py",
                  "RuleProxy-Web/bin/windows-amd64/wxc-exec.exe", "RuleProxy-Web/bin/windows-amd64/runtime.json"}
        if not needed <= names:
            raise ValueError("Release ZIP is missing the embedded Python or fixed runtime")
        for name in names:
            parts = Path(name).parts
            if name.startswith("/") or ".." in parts or "\\" in name or ":" in name:
                raise ValueError("Release ZIP contains an unsafe member")


def make_payload(package: Path, destination: Path) -> str:
    """Ship source tests separately, preserving the release's code origin."""
    with zipfile.ZipFile(destination, "w", compression=zipfile.ZIP_DEFLATED) as archive:
        archive.write(package, "package.zip")
        for folder in ("tests", "scripts", ".github"):
            for path in sorted((ROOT / folder).rglob("*")):
                if path.is_file() and path.suffix in (".py", ".xml", ".ps1") and "__pycache__" not in path.parts:
                    archive.write(path, path.relative_to(ROOT).as_posix())
        # Manager/server tests import this public example as source data.
        # Include the exact fixture instead of adding arbitrary YAML files or
        # checkout product code alongside the separately verified release.
        relative = "examples/ruleproxy.example.yaml"
        archive.write(ROOT / relative, relative)
    return digest(destination)


def prepare_seed(tree: Path, password: str, configuration: dict, *, updates: Path | None = None) -> None:
    template = (ROOT / ".github/windows-vm-unattend.xml").read_text(encoding="utf-8")
    # The generated password is alphanumeric plus a fixed complexity suffix,
    # so it has no XML markup, quotes, newlines or shell interpolation.
    rendered = template.replace("@PASSWORD@", password)
    ET.fromstring(rendered)
    (tree / "autounattend.xml").write_text(rendered, encoding="utf-8")
    for source, target in (("windows-vm-setup.ps1", "ruleproxy-vm-setup.ps1"),
                           ("windows-vm-run.ps1", "ruleproxy-vm-run.ps1")):
        # Windows PowerShell 5 needs a UTF-8 BOM to parse the Chinese path.
        data = (ROOT / ".github" / source).read_text(encoding="utf-8")
        (tree / target).write_text(data, encoding="utf-8-sig")
    write_json(tree / "ruleproxy-vm-config.json", configuration)
    if updates is not None:
        directory = tree / "ruleproxy-updates"
        directory.mkdir()
        packages = directory / "packages"
        packages.mkdir()
        for item in UPDATE_PACKAGES:
            source = updates / item["filename"]
            if source.stat().st_size != item["bytes"] or digest(source) != item["sha256"]:
                raise RuntimeError("Official Windows update changed before seed creation")
            # Keep names within Windows' ordinary Joliet limit on the seed
            # DVD. MSU content, signature and externally verified hash persist.
            shutil.copyfile(source, packages / item.get("seed_filename", item["filename"]))
        write_json(directory / "update-manifest.json", {
            "target_build": UPDATE_BUILD, "target_ubr": UPDATE_UBR,
            "target_package": UPDATE_PACKAGES[-1].get("seed_filename", UPDATE_PACKAGES[-1]["filename"]),
            "packages": [{"filename": item.get("seed_filename", item["filename"]), "sha256": item["sha256"]} for item in UPDATE_PACKAGES],
        })
        source = (ROOT / ".github/windows-vm-update.ps1").read_text(encoding="utf-8")
        (directory / "windows-vm-update.ps1").write_text(source, encoding="utf-8-sig")


def download_updates(directory: Path) -> list[dict]:
    directory.mkdir()
    verified = []
    for item in UPDATE_PACKAGES:
        path = directory / item["filename"]
        print(f"Downloading Microsoft Catalog update: {item['filename']}", flush=True)
        subprocess.run(["curl", "--fail", "--location", "--silent", "--show-error", "--retry", "5",
                        "--retry-all-errors", "--connect-timeout", "30", "--max-time", "1800", "--proto", "=https",
                        "--proto-redir", "=https", "--output", str(path), item["url"]], check=True, timeout=1800)
        if path.stat().st_size != item["bytes"] or digest(path) != item["sha256"]:
            raise RuntimeError("Microsoft Catalog update size/SHA-256 mismatch; servicing was refused")
        verified.append(dict(item, verified=True))
    return verified


def validate_install_tree(tree: Path) -> str:
    """Reject the tiny ISO9660 compatibility tree present on Microsoft UDF media."""
    for relative, minimum in (("boot/etfsboot.com", 512),
                              ("sources/boot.wim", MIN_BOOT_IMAGE_BYTES)):
        path = tree / relative
        if not path.is_file() or path.stat().st_size < minimum:
            raise RuntimeError(f"UDF extraction did not produce the complete Windows boot file: {relative}")
    images = [tree / "sources" / name for name in ("install.wim", "install.esd")]
    if not any(path.is_file() and path.stat().st_size >= MIN_INSTALL_IMAGE_BYTES for path in images):
        raise RuntimeError("UDF extraction did not produce a complete Windows install.wim/install.esd")
    for name in ("efisys_noprompt.bin", "efisys.bin"):
        relative = f"efi/microsoft/boot/{name}"
        path = tree / relative
        if path.is_file() and path.stat().st_size >= 512:
            return relative
    raise RuntimeError("UDF extraction did not produce an official Windows UEFI boot image")


class GuestServer(ThreadingHTTPServer):
    daemon_threads = True

    def __init__(self, payload: Path, artifacts: Path):
        self.payload = payload
        self.artifacts = artifacts
        self.capability = secrets.token_hex(32)
        self.received = threading.Event()
        self.result = None
        super().__init__(("127.0.0.1", 0), GuestHandler)


class GuestHandler(BaseHTTPRequestHandler):
    def log_message(self, *_):
        pass  # Never put the private capability URL into a CI log.

    def do_GET(self):
        if self.path != f"/{self.server.capability}/payload.zip":
            self.send_error(404)
            return
        self.send_response(200)
        self.send_header("Content-Type", "application/zip")
        self.send_header("Content-Length", str(self.server.payload.stat().st_size))
        self.end_headers()
        with self.server.payload.open("rb") as source:
            shutil.copyfileobj(source, self.wfile)

    def do_POST(self):
        if self.path != f"/{self.server.capability}/result":
            self.send_error(404)
            return
        try:
            size = int(self.headers.get("Content-Length", "0"))
            if not 0 < size <= MAX_RESULT_BYTES:
                raise ValueError("Guest result is outside its size bound")
            self.connection.settimeout(30)
            raw = self.rfile.read(size)
            if len(raw) != size:
                raise ValueError("Incomplete guest result")
            result = json.loads(raw.decode("utf-8"))
            if not isinstance(result, dict) or result.get("status") not in ("passed", "failed"):
                raise ValueError("Invalid guest result")
            write_json(self.server.artifacts / "guest-result.json", result)
            reports = result.get("reports", {})
            logs = result.get("logs", {})
            if not isinstance(reports, dict) or not isinstance(logs, dict):
                raise ValueError("Invalid guest report or logs")
            for name in ("probe", "transport", "manager", "browser", "experiments"):
                if name in reports:
                    write_json(self.server.artifacts / f"windows-{name}.json", reports[name])
            for name in ("probe", "transport", "manager", "browser", "experiments", "tests", "supervisor", "windows_update"):
                if name in logs:
                    if not isinstance(logs[name], str):
                        raise ValueError("Invalid guest log")
                    (self.server.artifacts / f"guest-{name}.log").write_text(logs[name], encoding="utf-8")
            self.server.result = result
            self.server.received.set()
        except (ValueError, UnicodeError, OSError):
            self.send_error(400)
            return
        self.send_response(200)
        self.send_header("Content-Length", "0")
        self.end_headers()


class Qmp:
    def __init__(self, path: Path):
        self.socket = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        self.socket.settimeout(10)
        try:
            self.socket.connect(str(path))
            self.file = self.socket.makefile("rwb")
            if "QMP" not in json.loads(self.file.readline()):
                raise RuntimeError("QEMU did not send its QMP greeting")
            self.execute("qmp_capabilities")
        except BaseException:
            self.close()
            raise

    def execute(self, command: str, arguments: dict | None = None):
        request = {"execute": command}
        if arguments:
            request["arguments"] = arguments
        self.file.write(json.dumps(request).encode("ascii") + b"\n")
        self.file.flush()
        while True:
            raw = self.file.readline()
            if not raw:
                raise RuntimeError("QEMU closed its QMP connection")
            response = json.loads(raw)
            if "error" in response:
                raise RuntimeError(f"QEMU {command} failed: {response['error']}")
            if "return" in response:
                return response["return"]

    def close(self):
        if getattr(self, "file", None) is not None:
            self.file.close()
        self.socket.close()


def screenshot(qmp: Qmp, temporary: Path, output: Path) -> None:
    """Convert QEMU's P6 screenshot to a small standalone PNG using stdlib."""
    import re

    qmp.execute("screendump", {"filename": str(temporary)})
    raw = temporary.read_bytes()
    match = re.match(rb"P6\s+(\d+)\s+(\d+)\s+255\n", raw)
    if not match:
        raise ValueError("Unexpected QEMU screenshot format")
    width, height = map(int, match.groups())
    pixels = raw[match.end():]
    if not 0 < width <= 4096 or not 0 < height <= 4096 or len(pixels) != width * height * 3:
        raise ValueError("Unexpected QEMU screenshot size")

    def chunk(kind, data):
        return struct.pack("!I", len(data)) + kind + data + struct.pack("!I", zlib.crc32(kind + data))

    lines = b"".join(b"\0" + pixels[row * width * 3:(row + 1) * width * 3] for row in range(height))
    png = (b"\x89PNG\r\n\x1a\n" + chunk(b"IHDR", struct.pack("!IIBBBBB", width, height, 8, 2, 0, 0, 0))
           + chunk(b"IDAT", zlib.compress(lines)) + chunk(b"IEND", b""))
    output.write_bytes(png)


def verify_phase_report(name: str, report: dict) -> None:
    if not isinstance(report, dict):
        raise RuntimeError(f"{name} returned an invalid report")
    if any(report.get(key) is not False for key in ("acceptance_passed", "real_node_passed")):
        raise RuntimeError("Credential-free fixtures cannot claim real-node/full acceptance")
    if "cleanup_error" in report or "recovery_directory" in report:
        raise RuntimeError(f"{name} left pending cleanup or recovery state")
    host = report.get("host", {})
    if not isinstance(host, dict) or host.get("acceptance_scope") != "native_x64" or any(
        type(host.get(key)) is not int or host[key] != 0x8664 for key in ("native_machine", "python_pe_machine")
    ):
        raise RuntimeError(f"{name} fixture did not prove native x64 execution")
    if name == "probe":
        if report.get("status") != "supported_only" or report.get("probe", {}).get("supported") is not True:
            raise RuntimeError("Guest probe report did not prove strict policy support")
        if report.get("transport_passed") is not False:
            raise RuntimeError("Probe report claimed a transport test it did not run")
        return
    entries = report.get("checks", [])
    if not isinstance(entries, list) or not all(isinstance(check, dict) for check in entries):
        raise RuntimeError(f"{name} returned invalid check evidence")
    checks = {check.get("check"): check for check in entries}
    if checks.get("host_proxy_dns_default_routes_unchanged", {}).get("status") != "passed":
        raise RuntimeError(f"{name} fixture did not preserve host network settings")
    if name == "experiments":
        if report.get("status") != "experiment_only" or report.get("full_acceptance_passed") is not False:
            raise RuntimeError("Network experiments cannot claim product acceptance")
        variants = report.get("variants")
        if not isinstance(variants, list) or not 1 <= len(variants) <= 16 or not all(isinstance(item, dict) for item in variants):
            raise RuntimeError("Network experiment report omitted its independent variant results")
        if report.get("cleanup_proven") is not True or experiment_has_recovery(variants):
            raise RuntimeError("Network experiment cleanup was not proven")
        for variant in variants:
            if variant.get("process_started") is True:
                if any(variant.get(key) is not True for key in ("descendant_cleanup_proven", "resources_closed")):
                    raise RuntimeError("Started network variant omitted descendant/resource cleanup proof")
            elif variant.get("process_started") is not False or variant.get("no_process_started") is not True:
                raise RuntimeError("Network variant did not establish whether a workload was started")
    elif name == "transport":
        if report.get("status") != "transport_only" or report.get("transport_passed") is not True:
            raise RuntimeError("Guest report did not pass the real PSEC transport fixture")
        if report.get("manager_core_loss_passed") is not False:
            raise RuntimeError("Transport report claimed a Manager test it did not run")
        if not all(checks.get(key, {}).get("status") == "passed" for key in (
            "transport_parent_child", "fixture_loss", "safe_psec_stop")):
            raise RuntimeError("Transport report omitted a required isolation/lifecycle check")
    elif name == "manager":
        if report.get("status") != "manager_fixture_only" or any(report.get(key) is not True for key in (
            "manager_fixture_passed", "manager_normal_stop_passed", "manager_core_loss_passed", "test_only_endpoint_override")):
            raise RuntimeError("Manager report did not pass both owned-core fixture lifecycle cases")
        for key in ("manager_normal_stop", "manager_core_loss"):
            check = checks.get(key, {})
            if check.get("status") != "passed" or any(check.get(field) is not True for field in (
                "parent_and_child_exited", "held_handles_verified", "manager_active_removed", "runtime_resources_closed",
                "manager_owned_core_stopped")):
                raise RuntimeError("Manager fixture omitted held-handle or resource teardown proof")
        if checks["manager_core_loss"].get("manager_watcher_exercised") is not True:
            raise RuntimeError("Manager core-loss fixture did not exercise the production watcher")
    elif name == "browser":
        if report.get("status") != "browser_fixture_only" or report.get("browser_fixture_passed") is not True:
            raise RuntimeError("Native Windows Edge fixture did not pass")
        for key in ("real_edge_launch_1", "real_edge_launch_2"):
            check = checks.get(key, {})
            if check.get("status") != "passed" or any(check.get(field) is not True for field in (
                "dom_nonce_via_page_ack", "cookie_request_verified", "natural_headless_exit")):
                raise RuntimeError("Edge fixture omitted live browser/DOM/cookie/exit proof")
        if checks["real_edge_launch_2"].get("private_profile_reused") is not True:
            raise RuntimeError("Edge fixture did not retain the private browser profile")
    else:
        raise RuntimeError("Unknown fixture phase")


def experiment_has_recovery(value) -> bool:
    """Recovery nested in one variant cannot be hidden by an aggregate success."""
    if isinstance(value, dict):
        return (any(key in value for key in ("cleanup_error", "recovery_directory"))
                or value.get("cleanup_proven") is False or bool(value.get("cleanup_errors"))) or any(
            experiment_has_recovery(item) for item in value.values())
    if isinstance(value, list):
        return any(experiment_has_recovery(item) for item in value)
    return False


def verify_result(result: dict, *, require_official_update: bool = False) -> None:
    if result.get("status") != "passed" or result.get("ordinary_user") is not True:
        raise RuntimeError(f"Guest tests failed: {result.get('error', 'missing ordinary-user proof')}")
    if require_official_update:
        update = result.get("official_update", {})
        if (update.get("status") != "completed" or update.get("completed") is not True
                or update.get("packages_verified") is not True or update.get("task_unregistered") is not True
                or type(update.get("actual_build")) is not int
                or update["actual_build"] != UPDATE_BUILD or type(update.get("actual_ubr")) is not int
                or update["actual_ubr"] < UPDATE_UBR):
            raise RuntimeError("Guest did not prove the pinned official cumulative update was installed")
    if result.get("recovery_records", []) != []:
        raise RuntimeError("Guest retained unproven cleanup or recovery records")
    if "experiments_phase" in result or "experiments" in result.get("reports", {}):
        experiment = result.get("experiments_phase", {})
        if experiment.get("status") != "passed" or type(experiment.get("exit_code")) is not int or experiment["exit_code"] != 0:
            raise RuntimeError("Guest network experiment collection/cleanup failed")
        verify_phase_report("experiments", result.get("reports", {}).get("experiments"))
    phases = result.get("phases")
    if not isinstance(phases, list) or not all(isinstance(phase, dict) for phase in phases) or [
        phase.get("name") for phase in phases
    ] != list(PHASE_NAMES):
        raise RuntimeError("Guest did not complete each required test phase")
    if any(phase.get("status") != "passed" or type(phase.get("exit_code")) is not int
           or phase["exit_code"] != 0 for phase in phases):
        raise RuntimeError("A guest test phase failed or was blocked")
    for name in PHASE_NAMES[:-1]:
        verify_phase_report(name, result.get("reports", {}).get(name))


def read_bounded_log(path: Path) -> str:
    with path.open("rb") as stream:
        raw = stream.read(MAX_PHASE_RECORD_BYTES + 1)
    clipped = len(raw) > MAX_PHASE_RECORD_BYTES
    text = raw[:MAX_PHASE_RECORD_BYTES].decode("utf-8", "replace")
    return text + ("\n[phase log truncated at its size limit]\n" if clipped else "")


def run_guest_phase(name: str, command: list[str], directory: Path, *, timeout: float) -> tuple[dict, dict | None, str]:
    record = {"name": name, "status": "failed", "exit_code": None}
    report, process = None, None
    log = directory / f"{name}.log"
    report_path = directory / f"{name}.json"
    started = time.monotonic()
    try:
        # A fresh interpreter must produce its own report; a previous run's
        # zero-exit JSON can never prove the current invocation succeeded.
        report_path.unlink(missing_ok=True)
        with log.open("wb") as output:
            process = subprocess.Popen(command, stdin=subprocess.DEVNULL, stdout=output,
                                       stderr=subprocess.STDOUT, shell=False)
            record["interpreter_started"] = True
            try:
                record["exit_code"] = process.wait(timeout=timeout)
            except subprocess.TimeoutExpired:
                # Only this held test-interpreter process is terminated.
                # Descendant cleanup is unproven on timeout; keep that explicit
                # and further PSEC fixtures must wait for cleanup.
                record.update(timed_out=True, descendant_cleanup_proven=False)
                process.kill()
                record["exit_code"] = process.wait(timeout=10)
                raise RuntimeError(f"{name} exceeded its {timeout:g}s budget; test interpreter stopped")
    except Exception as exc:
        record["error"] = f"{type(exc).__name__}: {exc}"[:700]
    try:
        if name != "package_tests" and record.get("interpreter_started"):
            with report_path.open("rb") as source:
                raw = source.read(MAX_PHASE_RECORD_BYTES + 1)
            if len(raw) > MAX_PHASE_RECORD_BYTES:
                raise RuntimeError(f"{name} report exceeded its size limit")
            value = json.loads(raw.decode("utf-8-sig"))
            if not isinstance(value, dict):
                raise RuntimeError(f"{name} returned an invalid report")
            report = value
        if "error" in record:
            raise RuntimeError(record["error"])
        if record["exit_code"] != 0:
            raise RuntimeError(f"{name} exited with status {record['exit_code']}")
        if report is not None:
            verify_phase_report(name, report)
        record["status"] = "passed"
    except Exception as exc:
        record.setdefault("error", f"{type(exc).__name__}: {exc}"[:700])
    finally:
        record["elapsed_seconds"] = round(time.monotonic() - started, 1)
    try:
        text = read_bounded_log(log)
    except OSError as exc:
        text = f"Could not read {name} log ({type(exc).__name__})."
        record.update(status="failed")
        record.setdefault("error", text)
    return record, report, text


def run_guest_phases(root: Path, workspace: Path, directory: Path, *, python: str | None = None,
                     phase_timeout: float = 900) -> dict:
    """Collect independent real-test failures without promoting partial success."""
    directory.mkdir(parents=True, exist_ok=True)
    executable = python or sys.executable
    acceptance = workspace / "scripts/windows-acceptance.py"
    result = {"status": "failed", "phases": [], "reports": {}, "logs": {}, "recovery_records": []}
    probe_passed = False
    cleanup_pending = False
    # This optional source-only experiment precedes the product fixtures. Its
    # policy variants never replace a required phase or grant release status.
    # Incomplete experiment teardown prevents every later contained launch.
    experiment = workspace / ".github/windows_network_experiment.py"
    if experiment.is_file():
        record, report, log = run_guest_phase(
            "experiments", [executable, "-X", "utf8", "-B", str(experiment),
                            "--root", str(root), "--report", str(directory / "experiments.json")],
            directory, timeout=min(600, phase_timeout))
        result["experiments_phase"] = record
        result["logs"]["experiments"] = log
        if report is not None:
            result["reports"]["experiments"] = report
        if record["status"] != "passed":
            cleanup_pending = True
            recovery = {"phase": "experiments", "reason": record.get("error", "Experiment cleanup was not proven"),
                        "descendant_cleanup_proven": False}
            if report is not None:
                for key in ("cleanup_error", "recovery_directory"):
                    if key in report:
                        recovery[key] = str(report[key])[:1024]
            result["recovery_records"].append(recovery)
    for name in PHASE_NAMES:
        if name in ("transport", "manager", "browser") and (not probe_passed or cleanup_pending):
            result["phases"].append({"name": name, "status": "blocked", "exit_code": None,
                                     "error": ("A previous fixture left pending cleanup; recovery state was retained"
                                               if cleanup_pending else
                                               "Strict policy probe did not pass; dependent fixture was not run")})
            continue
        command = [executable, "-X", "utf8", "-B"]
        if name == "package_tests":
            command.extend([str(workspace / ".github/run_tests.py"), "--code", str(root)])
        elif name == "browser":
            command.extend([str(workspace / ".github/windows_browser_check.py"), "--root", str(root),
                            "--report", str(directory / "browser.json")])
        else:
            option = {"probe": "--probe-only", "transport": "--transport-fixture", "manager": "--manager-fixture"}[name]
            command.extend([str(acceptance), "--root", str(root), option, "--report", str(directory / f"{name}.json")])
        record, report, log = run_guest_phase(name, command, directory,
                                             timeout=min(90, phase_timeout) if name == "probe" else phase_timeout)
        result["phases"].append(record)
        result["logs"]["tests" if name == "package_tests" else name] = log
        if report is not None:
            result["reports"][name] = report
        # The fixture writes its report after its finally/cleanup path. A
        # missing report or forced termination cannot prove that path ran.
        # Never bypass an earlier recovery directory by using a new fixture.
        if name in ("transport", "manager", "browser") and record.get("interpreter_started"):
            pending = record.get("timed_out") or report is None or any(
                key in report for key in ("cleanup_error", "recovery_directory"))
            if pending:
                cleanup_pending = True
                recovery = {"phase": name, "reason": record.get("error", "Fixture cleanup remained pending"),
                            "descendant_cleanup_proven": False}
                if report is not None:
                    for key in ("cleanup_error", "recovery_directory"):
                        if key in report:
                            recovery[key] = str(report[key])[:1024]
                            record[key] = recovery[key]
                result["recovery_records"].append(recovery)
        if name == "probe":
            probe_passed = record["status"] == "passed"
    if all(phase["status"] == "passed" for phase in result["phases"]):
        result["status"] = "passed"
    else:
        result["error"] = "Guest phases failed or were blocked: " + ", ".join(
            phase["name"] for phase in result["phases"] if phase["status"] != "passed")
    return result


def stop_owned(process: subprocess.Popen | None) -> None:
    if process is None or process.poll() is not None:
        return
    process.terminate()
    try:
        process.wait(timeout=15)
    except subprocess.TimeoutExpired:
        process.kill()
        process.wait(timeout=15)


def run(args) -> dict:
    artifacts = args.artifacts.resolve()
    artifacts.mkdir(parents=True, exist_ok=True)
    summary = {"status": "failed", "full_acceptance_passed": False, "real_node_passed": False,
               "transport_passed": False, "manager_fixture_passed": False, "browser_fixture_passed": False,
               "iso": {"url": ISO_URL, "sha256": ISO_SHA256,
               "download_page": ISO_SOURCE, "hash_source": ISO_HASH_SOURCE, "evaluation_days": 90},
               "official_update": {"kb": "KB5127648", "target_build": UPDATE_BUILD, "target_ubr": UPDATE_UBR,
                                   "source": UPDATE_SOURCE, "catalog_update_id": UPDATE_CATALOG_ID}}
    try:
        summary["kvm_api_version"] = require_kvm()
        package = args.package.resolve(strict=True)
        verify_package(package, args.package_sha256.lower())
        summary["package_sha256"] = args.package_sha256.lower()
        for name in ("qemu-system-x86_64", "qemu-img", "swtpm", "xorriso", "curl"):
            if not shutil.which(name):
                raise RuntimeError(f"Missing Ubuntu test dependency: {name}")
        extractor = shutil.which("7zz") or shutil.which("7z")
        if extractor is None:
            raise RuntimeError("Missing UDF extractor: install Ubuntu 7zip or p7zip-full")
        firmware = Path("/usr/share/OVMF")
        code = firmware / "OVMF_CODE_4M.ms.fd"
        variables = firmware / "OVMF_VARS_4M.ms.fd"
        if not code.is_file() or not variables.is_file():
            raise RuntimeError("OVMF 4 MB Microsoft Secure Boot firmware/variables are missing")
        # All potentially sensitive state is outside the repository/artifacts.
        with tempfile.TemporaryDirectory(prefix="ruleproxy-win11-vm-") as name:
            work = Path(name)
            os.chmod(work, 0o700)
            free = shutil.disk_usage(work).free
            summary["free_disk_bytes_before"] = free
            if free < MIN_FREE_BYTES:
                raise RuntimeError("Windows ISO/install needs at least 55 GiB free; no host files were removed")
            iso = work / "official.iso"
            print("Downloading the fixed Microsoft Enterprise Evaluation ISO", flush=True)
            subprocess.run(["curl", "--fail", "--location", "--retry", "5", "--retry-all-errors",
                            "--connect-timeout", "30", "--max-time", "1800", "--proto", "=https",
                            "--proto-redir", "=https", "--continue-at", "-",
                            "--output", str(iso), ISO_URL], check=True, timeout=1800)
            if iso.stat().st_size != ISO_BYTES or digest(iso) != ISO_SHA256:
                raise RuntimeError("Microsoft ISO size/SHA-256 mismatch; guest installation was refused")
            summary["iso"]["verified"] = True
            updates = work / "official-updates"
            summary["official_update"]["packages"] = download_updates(updates)
            payload = work / "payload.zip"
            payload_hash = make_payload(package, payload)
            server = GuestServer(payload, artifacts)
            http_thread = threading.Thread(target=server.serve_forever, daemon=True)
            http_thread.start()
            qemu, tpm, qmp = None, None, None
            try:
                tree = work / "iso-tree"
                tree.mkdir()
                print("Preparing the unattended ISO; the source ISO hash remains recorded", flush=True)
                # Microsoft's ISO exposes only a README through ISO9660.
                # Explicit UDF extraction obtains the real boot/install tree;
                # xorriso is used solely to rebuild the unattended media.
                subprocess.run([extractor, "x", "-tudf", "-y", f"-o{tree}", str(iso)],
                               check=True, timeout=900)
                efi_boot = validate_install_tree(tree)
                needs_boot_key = efi_boot.endswith("/efisys.bin")
                summary["installer_boot_image"] = efi_boot
                prepare_seed(tree, secrets.token_hex(16) + "Ci!9", {
                    "host_url": f"http://10.0.2.2:{server.server_address[1]}/{server.capability}",
                    "payload_sha256": payload_hash, "package_sha256": args.package_sha256.lower(),
                    "require_official_update": True, "update_build": UPDATE_BUILD, "update_ubr": UPDATE_UBR,
                }, updates=updates)
                unattended = work / "unattended.iso"
                subprocess.run(["xorriso", "-as", "mkisofs", "-iso-level", "3", "-J", "-joliet-long", "-R",
                                "-V", "RULEPROXY_CI", "-b", "boot/etfsboot.com", "-no-emul-boot",
                                "-boot-load-size", "8", "-boot-info-table", "-eltorito-alt-boot",
                                "-e", efi_boot, "-no-emul-boot",
                                "-o", str(unattended), str(tree)], check=True)
                shutil.rmtree(tree)
                shutil.rmtree(updates)
                iso.unlink()
                disk = work / "windows.qcow2"
                subprocess.run(["qemu-img", "create", "-f", "qcow2", str(disk), "80G"], check=True)
                nvram = work / "OVMF_VARS.fd"
                shutil.copyfile(variables, nvram)
                state = work / "tpm-state"
                state.mkdir()
                tpm_socket, qmp_socket = work / "tpm.sock", work / "qmp.sock"
                with (artifacts / "swtpm.log").open("wb") as tpm_log, (artifacts / "qemu.log").open("wb") as qemu_log:
                    tpm = subprocess.Popen(["swtpm", "socket", "--tpm2", "--tpmstate", f"dir={state}",
                                            "--ctrl", f"type=unixio,path={tpm_socket}"], stdout=tpm_log, stderr=subprocess.STDOUT)
                    deadline = time.monotonic() + 20
                    while not tpm_socket.exists():
                        if tpm.poll() is not None or time.monotonic() >= deadline:
                            raise RuntimeError("Software TPM did not initialize")
                        time.sleep(0.1)
                    command = ["qemu-system-x86_64", "-machine", "q35,accel=kvm,smm=on", "-cpu",
                               "host,hv-relaxed=on,hv-vapic=on,hv-spinlocks=0x1fff,hv-time=on", "-m", "6144", "-smp", "4",
                               "-global", "driver=cfi.pflash01,property=secure,value=on",
                               "-drive", f"if=pflash,format=raw,readonly=on,file={code}",
                               "-drive", f"if=pflash,format=raw,file={nvram}",
                               "-drive", f"if=none,id=system,file={disk},format=qcow2,discard=unmap",
                               "-device", "ide-hd,drive=system,bus=ide.0,bootindex=1",
                               "-drive", f"if=none,id=install,file={unattended},media=cdrom,readonly=on",
                               "-device", "ide-cd,drive=install,bus=ide.1,bootindex=2",
                               "-netdev", "user,id=vmnet", "-device", "e1000,netdev=vmnet",
                               "-chardev", f"socket,id=tpm,path={tpm_socket}", "-tpmdev", "emulator,id=tpmdev,chardev=tpm",
                               "-device", "tpm-tis,tpmdev=tpmdev", "-device", "qemu-xhci", "-device", "usb-tablet",
                               "-vga", "std", "-display", "none", "-serial", f"file:{artifacts / 'serial.log'}",
                               "-monitor", "none", "-qmp", f"unix:{qmp_socket},server=on,wait=off"]
                    qemu = subprocess.Popen(command, stdin=subprocess.DEVNULL, stdout=qemu_log, stderr=subprocess.STDOUT)
                    deadline = time.monotonic() + 20
                    while qmp is None:
                        if qemu.poll() is not None or time.monotonic() >= deadline:
                            raise RuntimeError("KVM QEMU startup failed; inspect qemu.log")
                        try:
                            qmp = Qmp(qmp_socket)
                        except OSError:
                            time.sleep(0.1)
                    kvm = qmp.execute("query-kvm")
                    if kvm.get("enabled") is not True:
                        raise RuntimeError("QEMU did not enable KVM; software emulation is forbidden")
                    summary["qemu_kvm_enabled"] = True
                    if needs_boot_key:
                        # Some official media include only the loader that asks
                        # for a key. Use that signed image unchanged; press Enter
                        # only in the initial boot window. Disk bootindex=1 then
                        # takes precedence on every installation reboot.
                        for _ in range(8):
                            qmp.execute("send-key", {"keys": [{"type": "qcode", "data": "ret"}], "hold-time": 100})
                            time.sleep(2)
                        summary["initial_boot_key_window_seconds"] = 16
                    started = time.monotonic()
                    deadline = started + args.timeout_seconds
                    while not server.received.wait(30):
                        if qemu.poll() is not None:
                            raise RuntimeError("Windows VM exited before returning its test report")
                        if time.monotonic() >= deadline:
                            raise TimeoutError("Windows unattended install/test timed out")
                        if shutil.disk_usage(work).free < 5 * 1024**3:
                            raise RuntimeError("Runner has under 5 GiB free; VM stopped before disk exhaustion")
                        print(f"Windows VM running for {int(time.monotonic() - started)} s", flush=True)
                        try:
                            screenshot(qmp, work / "screen.ppm", artifacts / "last-screen.png")
                        except (OSError, ValueError, RuntimeError):
                            pass  # A screenshot never substitutes for the guest report.
                    summary["phase_results"] = server.result.get("phases", [])
                    summary["recovery_records"] = server.result.get("recovery_records", [])
                    summary["official_update"]["guest"] = server.result.get("official_update")
                    verify_result(server.result, require_official_update=True)
                    summary.update(status="transport_and_package_tests_passed", transport_passed=True,
                                   manager_fixture_passed=True, browser_fixture_passed=True,
                                   ordinary_user=True, native_x64=True, elapsed_seconds=int(time.monotonic() - started))
                    print("Native x64 PSEC transport, Manager lifecycle, Edge fixture and release package tests passed; real-node acceptance remains separate", flush=True)
            finally:
                # Dispose only this ephemeral test VM and TPM, never a named
                # host process or a user-owned Windows application.
                if qmp is not None:
                    if qemu is not None and qemu.poll() is None:
                        try:
                            qmp.execute("system_powerdown")
                            qemu.wait(timeout=30)
                        except (OSError, RuntimeError, subprocess.TimeoutExpired):
                            pass
                    qmp.close()
                stop_owned(qemu)
                stop_owned(tpm)
                server.shutdown()
                server.server_close()
                http_thread.join(timeout=5)
    except Exception as exc:
        summary.update(status="failed", transport_passed=False, manager_fixture_passed=False,
                       browser_fixture_passed=False, error=f"{type(exc).__name__}: {exc}")
        print(f"::error title=Windows KVM guest::{type(exc).__name__}: {exc}", flush=True)
    finally:
        write_json(artifacts / "windows-vm-summary.json", summary)
    return summary


def main(argv: list[str]) -> int:
    if argv[:1] == ["--guest-phases"]:
        parser = argparse.ArgumentParser(description="Collect independent tests inside the ordinary-user Windows VM")
        parser.add_argument("--root", required=True, type=Path)
        parser.add_argument("--workspace", required=True, type=Path)
        parser.add_argument("--report", required=True, type=Path)
        args = parser.parse_args(argv[1:])
        result = run_guest_phases(args.root.resolve(), args.workspace.resolve(), args.report.resolve().parent)
        write_json(args.report, result)
        print(json.dumps({"status": result["status"], "phases": result["phases"]}, ensure_ascii=True), flush=True)
        return 0 if result["status"] == "passed" else 1
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--package", required=True, type=Path)
    parser.add_argument("--package-sha256", required=True)
    parser.add_argument("--artifacts", required=True, type=Path)
    parser.add_argument("--timeout-seconds", type=int, default=5400)
    args = parser.parse_args(argv)
    if not 300 <= args.timeout_seconds <= 14400:
        parser.error("--timeout-seconds must be between 300 and 14400")
    result = run(args)
    return 0 if result["status"] == "transport_and_package_tests_passed" else 1


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))
