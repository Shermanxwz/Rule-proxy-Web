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
import importlib.util
import json
import os
from pathlib import Path
import platform
import re
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
MAX_CAPTURE_REQUEST_BYTES = 128 * 1024
VM_NIC_MAC = "52:54:00:12:34:56"
WIRE_VARIANTS = ("model3", "model1_internal_ingress_deny", "model1_internal", "model2_host")
PHASE_NAMES = ("probe", "transport", "manager", "browser", "gui", "package_tests")
MIN_BOOT_IMAGE_BYTES = 64 * 1024**2
MIN_INSTALL_IMAGE_BYTES = 1024**3
TEST_EXECUTOR_DIRECTORY = "test-psec-executor"
TEST_EXECUTOR_FILES = ("wxc-exec.exe", "build-manifest.json", "MXC-LICENSE.md")
TEST_EXECUTOR_LICENSE_SHA256 = "d9a1b1e30d633d5732ea18e3cba9538d293ebc53e1a9e4e96ab739e0c5c4f1cb"
CHROMIUM_CONTROL_ARCHIVE_MEMBER = "chromium-control.zip"
OUTSIDE_EDGE_SCOPE = "ordinary_windows_stock_edge_fixed_http_health"
OUTSIDE_EDGE_FALSE_FLAGS = ("acceptance_passed", "full_acceptance_passed", "real_node_passed",
                           "browser_fixture_passed", "browser_sandbox_weakened", "public_udp_proven", "system_dns_proven")


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


def network_executor_verifier(workspace: Path):
    """Use the same source-only verifier on the host and in the guest."""
    path = workspace / ".github/windows_network_experiment.py"
    spec = importlib.util.spec_from_file_location("ruleproxy_vm_test_executor_verifier", path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def package_executor_sha256(package: Path) -> str:
    """Bind the diagnostic to the original executor in the verified release ZIP."""
    prefix = "RuleProxy-Web/bin/windows-amd64/"
    with zipfile.ZipFile(package) as archive:
        for name in ("runtime.json", "wxc-exec.exe"):
            if archive.namelist().count(prefix + name) != 1:
                raise ValueError("Release ZIP must contain one original executor and manifest")
        with archive.open(prefix + "runtime.json") as stream:
            raw = stream.read(64 * 1024 + 1)
        if not raw or len(raw) > 64 * 1024:
            raise ValueError("Original runtime manifest exceeded its size limit")
        module = network_executor_verifier(ROOT)
        value = json.loads(raw, object_pairs_hook=module.strict_json_object)
        hashes = value.get("sha256") if isinstance(value, dict) else None
        expected = hashes.get("wxc-exec.exe") if isinstance(hashes, dict) else None
        if not isinstance(expected, str) or not re.fullmatch(r"[0-9a-f]{64}", expected):
            raise ValueError("Original executor digest is missing from the release manifest")
        checksum = hashlib.sha256()
        with archive.open(prefix + "wxc-exec.exe") as stream:
            for block in iter(lambda: stream.read(1024 * 1024), b""):
                checksum.update(block)
        if checksum.hexdigest() != expected:
            raise ValueError("Original release executor did not match its runtime manifest")
    return expected


def verify_executor_bundle(root: Path, workspace: Path, executor: Path, manifest: Path,
                           original_sha256: str):
    module = network_executor_verifier(workspace)
    executor, metadata = module.verify_test_executor(root, executor, manifest, original_sha256)
    license_path = module.test_executor_file(manifest.parent / "MXC-LICENSE.md")
    if digest(license_path) != TEST_EXECUTOR_LICENSE_SHA256:
        raise ValueError("Diagnostic executor license did not match the fixed upstream release")
    return executor, metadata


def stage_test_executor(directory: Path, executor: Path, manifest: Path, original_sha256: str):
    executor, metadata = verify_executor_bundle(ROOT, ROOT, executor, manifest, original_sha256)
    directory.mkdir()  # Never reuse a prior bundle or put it in the product ZIP.
    for source, name in ((executor, "wxc-exec.exe"), (manifest, "build-manifest.json"),
                         (manifest.parent / "MXC-LICENSE.md", "MXC-LICENSE.md")):
        shutil.copyfile(source, directory / name)
    _, staged = verify_executor_bundle(ROOT, ROOT, directory / "wxc-exec.exe",
                                      directory / "build-manifest.json", original_sha256)
    if staged != metadata:
        raise ValueError("Diagnostic executor provenance changed during staging")
    return metadata


def guest_test_executor(root: Path, workspace: Path, vm_config: Path | None):
    """A fixed payload location and protected VM config select diagnostic mode."""
    if vm_config is None:
        return None
    def unique_fields(pairs):
        value = {}
        for key, item in pairs:
            if key in value:
                raise ValueError("Duplicate VM configuration field")
            value[key] = item
        return value
    try:
        with vm_config.open("rb") as stream:
            raw = stream.read(128 * 1024 + 1)
        if not raw or len(raw) > 128 * 1024:
            raise ValueError
        # Configuration may also contain the private HTTP capability. Never
        # echo its contents in validation errors or the public report.
        config = json.loads(raw, object_pairs_hook=unique_fields)
        enabled = config.get("test_psec_executor_diagnostic", False) if isinstance(config, dict) else None
        if type(enabled) is not bool:
            raise ValueError
    except (OSError, ValueError, TypeError) as exc:
        raise ValueError("Private VM diagnostic executor configuration is invalid") from exc
    if not enabled:
        return None
    expected = config.get("test_psec_executor_sha256")
    if not isinstance(expected, str) or not re.fullmatch(r"[0-9a-f]{64}", expected):
        raise ValueError("Private VM diagnostic executor digest is invalid")
    module = network_executor_verifier(workspace)
    original = module.load_helpers().verify_runtime_manifest(root).get("wxc-exec.exe")
    if original != config.get("test_psec_original_runtime_sha256"):
        raise ValueError("Guest product executor differs from the host-verified release")
    directory = workspace / TEST_EXECUTOR_DIRECTORY
    executor, metadata = verify_executor_bundle(root, workspace, directory / "wxc-exec.exe",
                                                directory / "build-manifest.json", original)
    if metadata["executor_sha256"] != expected:
        raise ValueError("Guest diagnostic executor differs from the host-verified artifact")
    return executor, directory / "build-manifest.json", metadata


def load_chromium_control_helper(root: Path = ROOT):
    path = root / ".github/windows_chromium_control.py"
    spec = importlib.util.spec_from_file_location("ruleproxy_windows_chromium_control", path)
    if spec is None or spec.loader is None:
        raise RuntimeError("Pinned Chromium control helper is unavailable")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def guest_diagnostic_options(vm_config: Path | None) -> tuple[bool, bool, bool, bool, str | None]:
    """Read mutually exclusive source diagnostic phase selections safely."""
    if vm_config is None:
        return False, False, False, False, None
    def unique_fields(pairs):
        value = {}
        for key, item in pairs:
            if key in value:
                raise ValueError("Duplicate VM configuration field")
            value[key] = item
        return value
    try:
        with vm_config.open("rb") as stream:
            raw = stream.read(128 * 1024 + 1)
        if not raw or len(raw) > 128 * 1024:
            raise ValueError
        config = json.loads(raw, object_pairs_hook=unique_fields)
        enabled = config.get("gui_diagnostic_only", False) if isinstance(config, dict) else None
        network = config.get("network_diagnostic_only", False) if isinstance(config, dict) else None
        singleton = config.get("singleton_port_range_diagnostic", False) if isinstance(config, dict) else None
        chromium_control = config.get("chromium_gui_control_diagnostic", False) if isinstance(config, dict) else None
        executor_enabled = config.get("test_psec_executor_diagnostic", False) if isinstance(config, dict) else None
        chromium_sha256 = config.get("chromium_gui_control_archive_sha256") if isinstance(config, dict) else None
        if any(type(flag) is not bool for flag in (enabled, network, singleton, chromium_control, executor_enabled)):
            raise ValueError
        if (enabled and (executor_enabled or network)) or (singleton and (not network or executor_enabled)):
            raise ValueError
        if chromium_control:
            if (not enabled or network or executor_enabled or not isinstance(chromium_sha256, str)
                    or not re.fullmatch(r"[0-9a-f]{64}", chromium_sha256)):
                raise ValueError
        elif chromium_sha256 is not None:
            raise ValueError
        return enabled, network, singleton, chromium_control, chromium_sha256
    except (OSError, ValueError, TypeError) as exc:
        raise ValueError("Private VM diagnostic configuration is invalid") from exc


def guest_diagnostic_modes(vm_config: Path | None) -> tuple[bool, bool]:
    return guest_diagnostic_options(vm_config)[:2]


def guest_gui_diagnostic_only(vm_config: Path | None) -> bool:
    return guest_diagnostic_modes(vm_config)[0]


def guest_network_diagnostic_only(vm_config: Path | None) -> bool:
    return guest_diagnostic_modes(vm_config)[1]


def make_payload(package: Path, destination: Path, *, test_executor_bundle: Path | None = None,
                 chromium_control_archive: Path | None = None) -> str:
    """Ship source tests separately, preserving the release's code origin."""
    if chromium_control_archive is not None:
        helper = load_chromium_control_helper(ROOT)
        if helper._check_archive(chromium_control_archive) != helper.ARCHIVE_SHA256:
            raise RuntimeError("Pinned Chromium control archive changed before payload creation")
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
        # The packaged source tests inspect the manual CI workflow contract.
        # Ship only that public workflow input, never runner secrets/state.
        relative = ".github/workflows/check.yml"
        archive.write(ROOT / relative, relative)
        if test_executor_bundle is not None:
            for name in TEST_EXECUTOR_FILES:
                archive.write(test_executor_bundle / name, f"{TEST_EXECUTOR_DIRECTORY}/{name}")
        if chromium_control_archive is not None:
            archive.write(chromium_control_archive, CHROMIUM_CONTROL_ARCHIVE_MEMBER,
                          compress_type=zipfile.ZIP_STORED)
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
        (directory / "packages").mkdir()
        verified = verified_update_files(updates)
        # Keep the large MSUs off the boot DVD. Windows downloads them through
        # the same private capability route as the separately verified payload.
        base = configuration["host_url"]
        write_json(directory / "update-manifest.json", {
            "target_build": UPDATE_BUILD, "target_ubr": UPDATE_UBR,
            "target_package": UPDATE_PACKAGES[-1].get("seed_filename", UPDATE_PACKAGES[-1]["filename"]),
            "packages": [{"filename": filename, "sha256": item["sha256"], "bytes": item["bytes"],
                          "url": f"{base}/updates/{filename}"} for filename, (_, item) in verified.items()],
        })
        source = (ROOT / ".github/windows-vm-update.ps1").read_text(encoding="utf-8")
        (directory / "windows-vm-update.ps1").write_text(source, encoding="utf-8-sig")


def verified_update_files(directory: Path) -> dict[str, tuple[Path, dict]]:
    """Map only the fixed, externally verified packages to their short names."""
    files = {}
    for item in UPDATE_PACKAGES:
        filename = item.get("seed_filename", item["filename"])
        if (Path(item["filename"]).name != item["filename"] or Path(filename).name != filename
                or "/" in filename or "\\" in filename or ".." in filename
                or not filename.endswith(".msu") or filename in files):
            raise RuntimeError("Invalid fixed Windows update filename")
        source = directory / item["filename"]
        if not source.is_file() or source.stat().st_size != item["bytes"] or digest(source) != item["sha256"]:
            raise RuntimeError("Official Windows update changed before seed creation or private serving")
        files[filename] = (source, item)
    return files


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


def installer_layout(iso: Path) -> dict:
    """Record actual remastered media size/extents; never alter its ordering."""
    result = {"bytes": iso.stat().st_size, "filesystem_options": "iso9660_level3_joliet_rockridge",
              "boot_wim_layout_status": "unavailable", "boot_wim_extents": []}
    try:
        command = ["xorriso", "-indev", str(iso), "-find", "/sources/boot.wim", "-exec", "report_lba", "--"]
        probe = subprocess.run(command, stdout=subprocess.PIPE, stderr=subprocess.DEVNULL,
                               check=False, timeout=30)
        if probe.returncode != 0 or len(probe.stdout) > 16384:
            return result
        for line in probe.stdout.decode("ascii", "strict").splitlines():
            match = re.fullmatch(r"File data lba:\s*(\d+)\s*,\s*(\d+)\s*,\s*(\d+)\s*,\s*(\d+)\s*,\s*'/sources/boot\.wim'", line)
            if match:
                extent, lba, blocks, size = map(int, match.groups())
                result["boot_wim_extents"].append({"extent_index": extent, "lba": lba,
                    "blocks": blocks, "file_bytes": size, "byte_offset": lba * 2048})
        if result["boot_wim_extents"]:
            result["boot_wim_layout_status"] = "reported"
    except (OSError, UnicodeError, subprocess.TimeoutExpired):
        pass  # Optional layout facts never substitute for a real boot report.
    return result


class GuestServer(ThreadingHTTPServer):
    daemon_threads = True

    def __init__(self, payload: Path, artifacts: Path, *, updates: Path | None = None, capture=None):
        self.payload = payload
        self.artifacts = artifacts
        self.capability = secrets.token_hex(32)
        self.updates = verified_update_files(updates) if updates is not None else {}
        self.capture = capture
        self.received = threading.Event()
        self.result = None
        super().__init__(("127.0.0.1", 0), GuestHandler)


class GuestHandler(BaseHTTPRequestHandler):
    def log_message(self, *_):
        pass  # Never put the private capability URL into a CI log.

    def do_GET(self):
        if self.path == f"/{self.server.capability}/payload.zip":
            path, size, content_type = self.server.payload, self.server.payload.stat().st_size, "application/zip"
        else:
            update = next((value for name, value in self.server.updates.items()
                           if self.path == f"/{self.server.capability}/updates/{name}"), None)
            if update is None:
                self.send_error(404)
                return
            path, item = update
            size, content_type = item["bytes"], "application/octet-stream"
        # Reject a removed or truncated host file before announcing its size.
        # The SYSTEM downloader separately verifies the entire MSU's SHA-256.
        if not path.is_file() or path.stat().st_size != size:
            self.send_error(503)
            return
        self.send_response(200)
        self.send_header("Content-Type", content_type)
        self.send_header("Content-Length", str(size))
        self.end_headers()
        with path.open("rb") as source:
            shutil.copyfileobj(source, self.wfile)

    def do_POST(self):
        if self.path in (f"/{self.server.capability}/capture/start", f"/{self.server.capability}/capture/finish"):
            self.capture_post()
            return
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
            for name in ("probe", "transport", "manager", "browser", "gui", "outside_edge", "experiments", "edge_ui"):
                if name in reports:
                    write_json(self.server.artifacts / f"windows-{name}.json", reports[name])
            for name in ("probe", "transport", "manager", "browser", "gui", "outside_edge", "experiments", "edge_ui", "tests", "supervisor", "windows_update"):
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


    def capture_post(self):
        controller = self.server.capture
        if controller is None:
            self.send_error(409, "capture_not_ready")
            return
        finishing = self.path.endswith("/finish")
        try:
            size = int(self.headers.get("Content-Length", "0"))
            if not 0 < size <= MAX_CAPTURE_REQUEST_BYTES:
                raise ValueError("capture_request_size")
            self.connection.settimeout(10)
            raw = self.rfile.read(size)
            if len(raw) != size:
                raise ValueError("capture_request_incomplete")
            value = json.loads(raw.decode("utf-8"))
        except (ValueError, UnicodeError, OSError):
            if finishing:
                controller.abort("capture_request_invalid")
            self.send_error(400, "capture_request_invalid")
            return
        try:
            result = controller.finish(value) if finishing else controller.start(value)
        except RuntimeError:
            self.send_error(409, "capture_state_or_control_failed")
            return
        body = json.dumps(result, ensure_ascii=True, separators=(",", ":")).encode("ascii")
        if len(body) > MAX_CAPTURE_REQUEST_BYTES:
            self.send_error(500, "capture_summary_size")
            return
        self.send_response(200)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)


class WireCaptureController:
    """Own one fixed QMP filter; raw packets and manifests stay in private work."""
    def __init__(self, qmp, work: Path, artifacts: Path, qemu_log: Path):
        self.qmp, self.artifacts, self.qemu_log = qmp, artifacts, qemu_log
        self.pcap, self.manifest = work / "wire-private.pcap", work / "wire-private-manifest.json"
        self.lock = threading.RLock()
        self.state, self.active, self.result = "idle", False, None
        self.collection_error = False
        spec = importlib.util.spec_from_file_location("ruleproxy_vm_packet_evidence", ROOT / ".github/windows_packet_evidence.py")
        self.packet = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(self.packet)
        spec = importlib.util.spec_from_file_location("ruleproxy_vm_dns_evidence", ROOT / ".github/windows_dns_packet_evidence.py")
        self.dns_packet = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(self.dns_packet)

    def incomplete(self, reason):
        return {"schema_version": 1, "status": "incomplete", "acceptance_passed": False,
                "kernel_denial_proven": False, "execution_proven": False, "absence_observed": False,
                "contained_markers_absent": None, "capture_flushed": not self.active, "error": reason}

    def record(self, value):
        if len(json.dumps(value, ensure_ascii=True).encode("ascii")) > MAX_CAPTURE_REQUEST_BYTES:
            value = self.incomplete("capture_summary_size")
        self.result = value
        write_json(self.artifacts / "windows-wire-evidence.json", value)
        return value

    def start(self, value):
        with self.lock:
            if self.state != "idle" or not isinstance(value, dict) or value:
                raise RuntimeError("capture_start_state")
            self.state = "starting"
            try:
                fd = os.open(self.pcap, os.O_CREAT | os.O_EXCL | os.O_WRONLY, 0o600)
                os.close(fd)
                self.active = True
                self.qmp.execute("object-add", {"qom-type": "filter-dump", "id": "ruleproxy_wire",
                                              "netdev": "vmnet", "file": str(self.pcap)})
            except Exception:
                self.collection_error = True
                self.record(self.incomplete("capture_filter_start_failed"))
                raise RuntimeError("capture_filter_start_failed") from None
            self.state = "active"
            return {"schema_version": 1, "source_mac": VM_NIC_MAC}

    def flush(self):
        if self.active:
            try:
                self.qmp.execute("object-del", {"id": "ruleproxy_wire"})
            except Exception:
                self.collection_error = True
                raise RuntimeError("capture_filter_flush_failed") from None
            self.active = False

    def log_clean(self):
        try:
            with self.qemu_log.open("rb") as source:
                raw = source.read(1024 * 1024 + 1)
            if len(raw) > 1024 * 1024:
                return False
            text = raw.decode("utf-8", "replace")
            failure = r"(?:error|fail(?:ed|ure)?|cannot|unable|could not)"
            dump = r"(?:filter[- ]?dump|ruleproxy_wire|dump|writ(?:e|ing))"
            return not re.search(r"(?im)^.*(?:" + dump + r".*?" + failure + "|" + failure + r".*?" + dump + r").*$", text)
        except OSError:
            return False

    def execution_groups(self, value):
        probes = value["manifest"]["probes"]
        groups = {p["group"]: False for p in probes}
        base_keys = {"manifest", "execution", "actor_execution_attested"}
        version = value.get("execution_schema_version", 1)
        if (type(version) is not int or version not in (1, 2)
                or set(value) - {"dns"} != (base_keys if version == 1 else base_keys | {"execution_schema_version"})
                or value["actor_execution_attested"] is not True
                or len(probes) != (32 if version == 1 else 64)):
            return groups
        execution = value["execution"]
        if not isinstance(execution, list) or len(execution) > len(probes):
            return groups
        expected = {p["id"]: p["role"] for p in probes}
        seen = {}
        fields = {"id", "role", "attempted", "bind_succeeded", "api_accepted", "errno"}
        booleans = {"attempted", "bind_succeeded", "api_accepted"}
        if version == 2:
            fields |= {"bind_attempted", "send_attempted"}
            booleans |= {"bind_attempted", "send_attempted"}
        for item in execution:
            if (not isinstance(item, dict) or set(item) != fields
                    or not isinstance(item["id"], str) or item["id"] in seen
                    or item["id"] not in expected or expected[item["id"]] != item["role"]
                    or any(type(item[key]) is not bool for key in booleans)
                    or (item["errno"] is not None and type(item["errno"]) is not int)):
                return groups
            if version == 2:
                unbound = item["id"].split(".")[1].endswith("_unbound")
                if ((unbound and (item["bind_attempted"] or item["bind_succeeded"]))
                        or (not unbound and item["bind_succeeded"] and not item["bind_attempted"])
                        or (not unbound and item["send_attempted"] and not item["bind_succeeded"])
                        or (item["api_accepted"] and (not item["send_attempted"] or item["errno"] is not None))
                        or (not item["attempted"] and any(item[key] for key in booleans - {"attempted"}))):
                    return groups
            seen[item["id"]] = item
        for group in groups:
            rows = [seen.get(p["id"]) for p in probes if p["group"] == group]
            if version == 1:
                # The old sender recorded success after bind and then either
                # the full send return or its OSError. Invalid marker/setup
                # (-1) and a missing result cannot imply a send was reached.
                groups[group] = len(rows) == 4 and all(row is not None and row["attempted"]
                    and row["bind_succeeded"] and ((row["api_accepted"] and row["errno"] is None)
                    or (not row["api_accepted"] and type(row["errno"]) is int and row["errno"] != -1)) for row in rows)
            else:
                groups[group] = len(rows) == 4 and all(row is not None and row["attempted"] and row["send_attempted"]
                    and (not row["bind_attempted"] if group.endswith("_unbound") else row["bind_succeeded"])
                    and row["errno"] != -1 for row in rows)
        return groups

    def fixed_manifest(self, manifest):
        if not isinstance(manifest, dict) or set(manifest) != {"schema_version", "probes"}:
            raise ValueError("capture_manifest_schema")
        self.packet.prepare_manifest(manifest)
        probes = manifest["probes"]
        suffixes = ("",) if len(probes) == 32 else ("", "_unbound")
        fixed_groups = {variant + "." + family + suffix for variant in WIRE_VARIANTS
                        for family in ("ipv4", "ipv6") for suffix in suffixes}
        expected = {group + "." + role for group in fixed_groups for role in self.packet.ROLES}
        if len(probes) not in (32, 64) or {p["id"] for p in probes} != expected:
            raise ValueError("capture_manifest_fixed_probes")
        if any(len({p["source_ip"] for p in probes if p["family"] == family}) != 1
               for family in ("ipv4", "ipv6")):
            raise ValueError("capture_manifest_fixed_route_source")
        for probe in probes:
            if (probe["id"] != probe["group"] + "." + probe["role"]
                    or probe["group"] not in {variant + "." + probe["family"] + suffix
                                              for variant in WIRE_VARIANTS for suffix in suffixes}
                    or probe["source_mac"].lower() != VM_NIC_MAC or probe["port"] != 53
                    or probe["destination"] != {"ipv4": "1.1.1.1", "ipv6": "2606:4700:4700::1111"}[probe["family"]]):
                raise ValueError("capture_manifest_fixed_tuple")

    def fixed_dns_manifest(self, manifest):
        self.dns_packet.prepare_manifest(manifest)
        preferred = "model1_internal_ingress_deny"
        expected = {f"{preferred}.{api}.{role}" for api in self.dns_packet.APIS for role in self.dns_packet.ROLES}
        probes = manifest["probes"]
        if len(probes) != 12 or {p["id"] for p in probes} != expected:
            raise ValueError("capture_dns_fixed_probes")
        nonces = set()
        for probe in probes:
            group = preferred + "." + probe["api"]
            if (probe["group"] != group or probe["id"] != group + "." + probe["role"]
                    or (probe["api"] == "getaddrinfo" and "query_type" in probe)
                    or (probe["api"] != "getaddrinfo" and probe.get("query_type") != (1 if probe["api"] == "dns_a" else 28))):
                raise ValueError("capture_dns_fixed_api_scope")
            nonces.add(probe["qname"].lower().split(".")[0])
        if len(nonces) != 1:
            raise ValueError("capture_dns_fixed_nonce")

    def dns_execution_groups(self, value):
        probes = value["manifest"]["probes"]
        groups = {p["group"]: False for p in probes}
        if (set(value) != {"manifest", "execution", "actor_execution_attested"}
                or value["actor_execution_attested"] is not True
                or not isinstance(value["execution"], list) or len(value["execution"]) > 12):
            return groups
        expected = {p["id"]: p for p in probes}
        seen = {}
        for row in value["execution"]:
            if (not isinstance(row, dict) or not isinstance(row.get("id"), str)
                    or row["id"] not in expected or row["id"] in seen
                    or row.get("role") != expected[row["id"]]["role"]):
                return groups
            probe = expected[row["id"]]
            valid = (row.get("api") == probe["api"] and row.get("requested_role") == probe["role"]
                and isinstance(row.get("qname"), str)
                and row["qname"].lower().removesuffix(".") == probe["qname"].lower().removesuffix(".")
                and row.get("outcome") == "returned"
                and all(row.get(key) is True for key in ("attempted", "entry_lease_published", "api_returned",
                    "native_completion_proven", "worker_cleanup_proven", "worker_exit_verified", "worker_handle_closed",
                    "records_released", "default_system_server_list"))
                and all(row.get(key) is False for key in ("server_list_override", "dns_blocked_proven", "acceptance_passed"))
                and all(type(row.get(key)) is int and 0 < row[key] <= limit
                    for key, limit in (("pid", 0xFFFFFFFF), ("ppid", 0xFFFFFFFF), ("process_created", 0xFFFFFFFFFFFFFFFF)))
                and type(row.get("worker_exit_code")) is int
                and type(row.get("return_code")) is int and row["return_code"] not in (87, 123, 998, 10022, 9506)
                and type(row.get("query_options")) is int
                and row["query_options"] == (0 if probe["api"] == "getaddrinfo" else 0x108)
                and not any(key in row for key in ("error", "setup_error", "cleanup_error", "cleanup_errors",
                    "recovery_directory", "operation_pending", "no_process_started")))
            if probe["api"] != "getaddrinfo":
                valid &= (type(row.get("query_status")) is int
                          and row["query_status"] not in (87, 123, 998, 10022, 9506))
            seen[row["id"]] = valid
        for group in groups:
            groups[group] = all(seen.get(p["id"]) is True for p in probes if p["group"] == group)
        return groups

    def native_dns(self, value):
        incomplete = {"schema_version": 1, "status": "incomplete", "scope": self.dns_packet.SCOPE,
            "acceptance_passed": False, "kernel_denial_proven": False, "execution_proven": False,
            "absence_observed": False, "contained_questions_absent": None, "capture_flushed": not self.active,
            "error": "capture_native_dns_invalid_or_incomplete"}
        try:
            if not isinstance(value, dict) or "manifest" not in value:
                return incomplete
            self.fixed_dns_manifest(value["manifest"])
            # No QNAME, PID, route address, private path or raw API record
            # enters the artifact. Fixed group IDs and counts are sanitized.
            result = self.dns_packet.analyze_capture(self.pcap, value["manifest"])
            proof = self.dns_execution_groups(value)
            for group in result["groups"]:
                group["execution_proven"] = proof[group["id"]]
                group["absence_observed"] = group["execution_proven"] and group["contained_questions_absent"] is True
                if not group["execution_proven"]:
                    group["contained_questions_absent"] = None
            proven = all(proof.values())
            result.update(execution_proven=proven, actor_execution_attested=value.get("actor_execution_attested") is True,
                          packet_analysis_complete=result["status"] == "complete", capture_flushed=not self.active)
            if not proven:
                result.update(status="incomplete", absence_observed=False, contained_questions_absent=None,
                              error="capture_native_dns_execution_incomplete")
            return result
        except Exception:
            return incomplete

    def finish(self, value):
        with self.lock:
            if self.state != "active":
                raise RuntimeError("capture_finish_state")
            self.state = "finished"
            try:
                self.flush()
                if not isinstance(value, dict) or "manifest" not in value:
                    raise ValueError("capture_finish_schema")
                # Parser validates bounded markers/groups. Only its sanitized
                # counters leave this private directory.
                self.fixed_manifest(value["manifest"])
                write_json(self.manifest, value["manifest"])
                result = self.packet.analyze_capture(self.pcap, value["manifest"])
                group_proof = self.execution_groups(value)
                proven = all(group_proof.values())
                for group in result.get("groups", []):
                    group["execution_proven"] = group_proof[group["id"]]
                    group["absence_observed"] = group["execution_proven"] and group["contained_markers_absent"] is True
                    if not group["execution_proven"]:
                        group["contained_markers_absent"] = None
                result.update(execution_proven=proven, actor_execution_attested=value.get("actor_execution_attested") is True,
                              packet_analysis_complete=result["status"] == "complete", capture_flushed=True)
                if not proven:
                    result.update(status="incomplete", absence_observed=False, contained_markers_absent=None,
                                  error="capture_sender_execution_incomplete")
                if "dns" in value:
                    result["native_dns"] = self.native_dns(value["dns"])
                if not self.log_clean():
                    self.collection_error = True
                    result = self.incomplete("capture_qemu_log_error")
                return self.record(result)
            except Exception:
                return self.record(self.incomplete("capture_analysis_or_flush_failed"))

    def abort(self, reason="capture_not_finished"):
        with self.lock:
            if self.state in ("idle", "finished") and not self.active:
                return
            self.state = "finished"
            try:
                self.flush()
            except RuntimeError:
                reason = "capture_filter_flush_failed"
            self.record(self.incomplete(reason))

    def close(self):
        with self.lock:
            self.abort()
            if not self.log_clean():
                self.collection_error = True
                self.record(self.incomplete("capture_qemu_log_error"))


class Qmp:
    def __init__(self, path: Path):
        self.lock = threading.RLock()
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
        with self.lock:
            return self._execute(command, arguments)

    def _execute(self, command: str, arguments: dict | None = None):
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
        with self.lock:
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
    if name == "outside_edge":
        if (not outside_edge_teardown_proven(report) or report.get("status") != "outside_control_only"
                or report.get("outside_headless_control_passed") is not True
                or report.get("ordinary_user") is not True or report.get("host_network_unchanged") is not True):
            raise RuntimeError("Outside Edge health control did not pass its separate scope")
        checks = report.get("checks")
        if not isinstance(checks, list) or len(checks) != 2:
            raise RuntimeError("Outside Edge control omitted its two independent launches")
        for phase, check in enumerate(checks, 1):
            if (not isinstance(check, dict) or type(check.get("phase")) is not int or check["phase"] != phase
                    or type(check.get("edge_exit_code")) is not int or check["edge_exit_code"] != 0
                    or check.get("edge_exit_hex") != "0x00000000"
                    or not isinstance(check.get("command_template_sha256"), str)
                    or not re.fullmatch(r"[0-9a-f]{64}", check["command_template_sha256"])
                    or check.get("private_profile_reused") is not (phase == 2)
                    or any(check.get(key) is not True for key in (
                        "assigned_before_resume", "natural_root_and_job_exit", "dom_nonce_via_page_ack",
                        "cookie_request_verified", "owned_job_cleanup_proven"))):
                raise RuntimeError("Outside Edge control omitted nonce, cookie, natural exit or owned-job cleanup proof")
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
    elif name == "edge_ui":
        if (report.get("status") != "experiment_only" or report.get("collection_completed") is not True
                or report.get("cleanup_proven") is not True
                or report.get("test_only_ui_override") is not True
                or any(report.get(key) is not False for key in (
                    "production_policy_changed", "browser_sandbox_weakened", "browser_fixture_passed",
                    "gui_fixture_passed", "full_acceptance_passed", "public_udp_proven", "system_dns_proven"))
                or experiment_has_recovery(report)):
            raise RuntimeError("UI diagnostics cannot claim product acceptance or hide pending cleanup")
        variants = report.get("variants")
        expected = ("container_ime", "handles_ime", "desktop_ime", "container_no_ime", "handles_no_ime", "ui_no_job_limits")
        if (not isinstance(variants, list) or [v.get("id") for v in variants if isinstance(v, dict)] != list(expected)
                or any(v.get("cleanup_proven") is not True
                       or v.get("status") not in ("observed", "budget_not_started") for v in variants)):
            raise RuntimeError("UI diagnostics omitted bounded independent variant records")
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
    elif name == "gui":
        browser = report.get("browser", {})
        chrome_control = (report.get("chromium_gui_control_diagnostic") is True
                          and report.get("source_diagnostic_only") is True
                          and isinstance(browser, dict)
                          and browser.get("application") == "chrome_for_testing_control"
                          and report.get("product_browser_replaced") is False)
        check_prefix = "real_chromium_control_gui" if chrome_control else "real_edge_gui"
        if (report.get("status") != "gui_fixture_only" or report.get("gui_fixture_passed") is not True
                or report.get("cleanup_proven") is not True
                or report.get("interactive", {}).get("ordinary_interactive") is not True
                or not isinstance(browser, dict)
                or browser.get("headless") is not False
                or browser.get("sandbox_weakened") is not False
                or any(report.get(key) is not False for key in (
                    "full_acceptance_passed", "public_udp_proven", "system_dns_proven"))):
            raise RuntimeError("Native ordinary-user Edge GUI fixture did not pass")
        for key in (f"{check_prefix}_1", f"{check_prefix}_2"):
            check = checks.get(key, {})
            if check.get("status") != "passed" or any(check.get(field) is not True for field in (
                "visible_window_verified", "dom_nonce_via_page_ack", "cookie_request_verified",
                "wm_close_requested", "natural_helper_wrapper_exit", "held_handles_verified",
                "descendant_cleanup_proven", "resources_closed")):
                raise RuntimeError("GUI omitted owned visible-window, page or natural teardown evidence")
            rects = check.get("visible_window_rects")
            if (not isinstance(rects, list) or not 1 <= len(rects) <= 16 or any(
                not isinstance(rect, list) or len(rect) != 4 or any(type(x) is not int for x in rect)
                or rect[2] <= rect[0] or rect[3] <= rect[1] for rect in rects)):
                raise RuntimeError("GUI omitted nonempty visible rectangles")
        if checks[f"{check_prefix}_2"].get("private_profile_reused") is not True:
            raise RuntimeError("GUI did not retain its own browser profile")
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


def outside_edge_teardown_proven(report: dict | None) -> bool:
    """A failed health check may be closed safely; its failure remains recorded."""
    return (isinstance(report, dict) and type(report.get("schema_version")) is int
            and report["schema_version"] == 1 and report.get("scope") == OUTSIDE_EDGE_SCOPE
            and report.get("outside_psec") is True and report.get("cleanup_proven") is True
            and report.get("status") in ("outside_control_only", "failed", "unsupported")
            and type(report.get("outside_headless_control_passed")) is bool
            and report["outside_headless_control_passed"] is (report["status"] == "outside_control_only")
            and all(report.get(key) is False for key in OUTSIDE_EDGE_FALSE_FLAGS)
            and not any(key in report for key in ("recovery_retained", "cleanup_failure", "fixture_cleanup_failure"))
            and not experiment_has_recovery(report))


def experiment_teardown_proven(name: str, report: dict | None) -> bool:
    """Permit independent diagnostics after a failed, fully closed collection.

    This only establishes whether starting a new container is safe. The real
    failed phase and report remain unchanged and still fail verify_result.
    """
    if (not isinstance(report, dict) or report.get("cleanup_proven") is not True
            or experiment_has_recovery(report)):
        return False
    checks = report.get("checks")
    if not isinstance(checks, list) or not any(isinstance(check, dict)
            and check.get("check") == "host_proxy_dns_default_routes_unchanged"
            and check.get("status") == "passed" for check in checks):
        return False
    variants = report.get("variants")
    if not isinstance(variants, list) or not 1 <= len(variants) <= 16:
        return False
    for variant in variants:
        if not isinstance(variant, dict):
            return False
        if name == "experiments":
            if variant.get("process_started") is True:
                if any(variant.get(key) is not True for key in ("descendant_cleanup_proven", "resources_closed")):
                    return False
            elif variant.get("process_started") is not False or variant.get("no_process_started") is not True:
                return False
        elif name == "edge_ui":
            if variant.get("cleanup_proven") is not True:
                return False
        else:
            return False
    return True


def verify_result(result: dict, *, require_official_update: bool = False,
                  gui_diagnostic_only: bool = False, network_diagnostic_only: bool = False) -> None:
    if gui_diagnostic_only or result.get("gui_diagnostic_only") is True:
        raise RuntimeError("GUI diagnostic-only report cannot qualify product acceptance")
    if network_diagnostic_only or result.get("network_diagnostic_only") is True:
        raise RuntimeError("Network diagnostic-only report cannot qualify product acceptance")
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
    if "outside_edge_phase" in result or "outside_edge" in result.get("reports", {}):
        phase = result.get("outside_edge_phase", {})
        if phase.get("status") != "passed" or type(phase.get("exit_code")) is not int or phase["exit_code"] != 0:
            raise RuntimeError("Guest outside Edge health control failed")
        verify_phase_report("outside_edge", result.get("reports", {}).get("outside_edge"))
    if "experiments_phase" in result or "experiments" in result.get("reports", {}):
        experiment = result.get("experiments_phase", {})
        if experiment.get("status") != "passed" or type(experiment.get("exit_code")) is not int or experiment["exit_code"] != 0:
            raise RuntimeError("Guest network experiment collection/cleanup failed")
        verify_phase_report("experiments", result.get("reports", {}).get("experiments"))
    if "edge_ui_phase" in result or "edge_ui" in result.get("reports", {}):
        phase = result.get("edge_ui_phase", {})
        if phase.get("status") != "passed" or type(phase.get("exit_code")) is not int or phase["exit_code"] != 0:
            raise RuntimeError("Guest UI diagnostic collection/cleanup failed")
        verify_phase_report("edge_ui", result.get("reports", {}).get("edge_ui"))
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


def _boundary_records(value, field, scope):
    entries = value.get(field)
    if (not isinstance(entries, list) or not 1 <= len(entries) <= 128
            or not all(isinstance(entry, dict) and isinstance(entry.get("id"), str) for entry in entries)):
        raise RuntimeError(f"{scope} omitted bounded {field} evidence")
    indexed = {entry["id"]: entry for entry in entries}
    if len(indexed) != len(entries):
        raise RuntimeError(f"{scope} repeated an evidence identifier")
    return indexed


def _verify_boundary_scope(value, scope, groups, *, dns=False):
    if (not isinstance(value, dict) or type(value.get("schema_version")) is not int
            or value["schema_version"] != 1 or value.get("scope") != scope
            or value.get("status") not in ("complete", "incomplete")
            or any(value.get(key) is not True for key in (
                "capture_format_complete", "capture_flushed", "actor_execution_attested"))
            or any(value.get(key) is not False for key in ("acceptance_passed", "kernel_denial_proven"))
            or not isinstance(value.get("capture_sha256"), str)
            or not re.fullmatch(r"[0-9a-f]{64}", value["capture_sha256"])
            or type(value.get("capture_bytes")) is not int or value["capture_bytes"] < 24
            or type(value.get("packet_records")) is not int or value["packet_records"] < 1):
        raise RuntimeError(f"{scope} did not establish a flushed, attested packet capture")
    observed = _boundary_records(value, "groups", scope)
    counts = _boundary_records(value, "counts", scope)
    hash_field = "qname_sha256" if dns else "payload_sha256"
    hashes = set()
    for group, api in groups.items():
        record = observed.get(group)
        if not isinstance(record, dict):
            raise RuntimeError(f"{scope} omitted a preferred policy group")
        query_type = {"getaddrinfo": None, "dns_a": 1, "dns_aaaa": 28}.get(api)
        for role in ("outside_before", "parent", "child", "outside_after"):
            row = counts.get(group + "." + role)
            if (not isinstance(row, dict) or row.get("group") != group or row.get("role") != role
                    or type(row.get("count")) is not int or row["count"] < 0
                    or not isinstance(row.get(hash_field), str)
                    or not re.fullmatch(r"[0-9a-f]{64}", row[hash_field])
                    or row[hash_field] in hashes
                    or (dns and (row.get("api") != api or "query_type" not in row
                        or type(row["query_type"]) is not type(query_type) or row["query_type"] != query_type))):
                raise RuntimeError(f"{scope} omitted distinct, typed preferred probe counters")
            hashes.add(row[hash_field])
            if role in ("parent", "child") and row["count"]:
                raise RuntimeError(f"{scope} observed contained traffic on the VM NIC")
            if role in ("outside_before", "outside_after") and row["count"] < 1:
                raise RuntimeError(f"{scope} lacked an outside positive control")
        absence_field = "contained_questions_absent" if dns else "contained_markers_absent"
        if (any(record.get(key) is not True for key in (
                "execution_proven", "positive_controls_complete", "control_window_ordered", "absence_observed", absence_field))
                or (dns and (record.get("api") != api or "query_type" not in record
                    or type(record["query_type"]) is not type(query_type) or record["query_type"] != query_type))):
            raise RuntimeError(f"{scope} did not prove executed preferred probes inside healthy control windows")
    if (type(value.get("unknown_records")) is not int or value["unknown_records"] != 0
            or value.get("unknown_reasons") != {}):
        raise RuntimeError(f"{scope} contained unknown or opaque packet evidence")
    permitted_error = "capture_native_dns_execution_incomplete" if dns else "capture_sender_execution_incomplete"
    if value.get("error") not in (None, permitted_error):
        raise RuntimeError(f"{scope} had an unresolved collection failure")


def verify_network_boundary(value):
    """Require the preferred policy's fixed UDP/default-DNS wire observations.

    Other diagnostic policies need not execute. Their aggregate incomplete
    label cannot erase independently complete preferred group evidence.
    These observations never establish blanket kernel or real-node acceptance.
    """
    preferred = "model1_internal_ingress_deny"
    udp_groups = {preferred + "." + family + suffix: None
        for family in ("ipv4", "ipv6") for suffix in ("", "_unbound")}
    _verify_boundary_scope(value, "captured_qemu_vm_nic_egress", udp_groups)
    dns = value.get("native_dns")
    dns_groups = {preferred + "." + api: api for api in ("getaddrinfo", "dns_a", "dns_aaaa")}
    _verify_boundary_scope(dns, "default_test_vm_resolver_configuration_observed", dns_groups, dns=True)
    if any(dns.get(key) != value.get(key) for key in ("capture_sha256", "capture_bytes", "packet_records")):
        raise RuntimeError("UDP and native DNS evidence did not use the same capture")
    return {"status": "passed", "scope": "preferred_policy_fixed_udp_and_default_dns_on_test_vm_nic",
            "preferred_policy": preferred, "udp_groups_verified": list(udp_groups),
            "native_dns_groups_verified": list(dns_groups), "contained_udp_markers_received": 0,
            "contained_native_dns_questions_received": 0, "capture_sha256": value["capture_sha256"],
            "kernel_denial_proven": False, "full_acceptance_passed": False, "real_node_passed": False}


def diagnostic_network_boundary(value, *, executor_attested: bool, collection_failed: bool = False):
    """Keep custom-executor wire results separate even when product UI fails."""
    try:
        if executor_attested is not True:
            raise RuntimeError("Source experiment did not report the host-verified diagnostic executor")
        if collection_failed:
            raise RuntimeError("VM packet capture control or dump/write failed")
        result = verify_network_boundary(value)
    except (RuntimeError, ValueError, TypeError) as exc:
        result = {"status": "failed", "error": str(exc)[:700],
                  "kernel_denial_proven": False, "full_acceptance_passed": False, "real_node_passed": False}
    return {**result, "executor_scope": "source_only_test_executor", "product_acceptance_passed": False}


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
                     phase_timeout: float = 900, vm_config: Path | None = None) -> dict:
    """Collect independent real-test failures without promoting partial success."""
    directory.mkdir(parents=True, exist_ok=True)
    executable = python or sys.executable
    acceptance = workspace / "scripts/windows-acceptance.py"
    result = {"status": "failed", "phases": [], "reports": {}, "logs": {}, "recovery_records": []}
    probe_passed = False
    cleanup_pending = False
    try:
        gui_only, network_only, singleton, chromium_control, chromium_sha256 = guest_diagnostic_options(vm_config)
    except ValueError:
        result["diagnostic_configuration_error"] = "invalid_private_configuration"
        result["error"] = "Private diagnostic configuration could not be verified"
        result["phases"] = [{"name": name, "status": "blocked", "exit_code": None,
                             "reason": "invalid_private_configuration"} for name in PHASE_NAMES]
        return result
    if gui_only:
        result.update(gui_diagnostic_only=True, source_diagnostic_only=True,
                      full_acceptance_passed=False, product_acceptance_passed=False,
                      execution_mode="original_sdk", product_runtime_replaced=False)
        if chromium_control:
            result["chromium_gui_control_diagnostic"] = True
        probe_command = [executable, "-X", "utf8", "-B", str(acceptance), "--root", str(root),
                         "--probe-only", "--report", str(directory / "probe.json")]
        probe, report, log = run_guest_phase("probe", probe_command, directory,
                                             timeout=min(90, phase_timeout))
        result["phases"].append(probe)
        result["logs"]["probe"] = log
        if report is not None:
            result["reports"]["probe"] = report
        probe_passed = probe.get("status") == "passed" and probe.get("exit_code") == 0
        for name in ("transport", "manager", "browser"):
            result["phases"].append({"name": name, "status": "skipped", "exit_code": None,
                                     "reason": "gui_diagnostic_only"})
        chromium_control_root = None
        chromium_control_ready = not chromium_control
        if probe_passed and chromium_control:
            try:
                helper = load_chromium_control_helper(workspace)
                if chromium_sha256 != helper.ARCHIVE_SHA256:
                    raise ValueError("Pinned Chromium archive digest did not match the private seed")
                chromium_control_root = directory / "chromium-control"
                chrome_exe = helper.extract_archive(workspace / CHROMIUM_CONTROL_ARCHIVE_MEMBER,
                                                    chromium_control_root)
                result["chromium_gui_control"] = {
                    "status": "ready", "version": helper.VERSION, "platform": helper.PLATFORM,
                    "archive_sha256": helper.ARCHIVE_SHA256, "chrome_exe_sha256": digest(chrome_exe),
                }
                chromium_control_ready = True
            except Exception as exc:
                result["chromium_gui_control"] = {
                    "status": "failed", "error_type": type(exc).__name__, "archive_sha256": chromium_sha256,
                }
                result["error"] = "Pinned Chromium control was unavailable; GUI process was not launched"
        if probe_passed and chromium_control_ready:
            gui_command = [executable, "-X", "utf8", "-B", str(workspace / ".github/windows_gui_check.py"),
                           "--root", str(root), "--report", str(directory / "gui.json")]
            if chromium_control_root is not None:
                gui_command.extend(["--chromium-control-root", str(chromium_control_root)])
            gui, report, log = run_guest_phase("gui", gui_command, directory, timeout=phase_timeout)
            result["phases"].append(gui)
            result["logs"]["gui"] = log
            if report is not None:
                result["reports"]["gui"] = report
            if gui.get("interpreter_started") and (
                    gui.get("timed_out") or report is None
                    or any(key in report for key in ("cleanup_error", "recovery_directory"))):
                recovery = {"phase": "gui", "reason": gui.get("error", "GUI diagnostic cleanup remained pending"),
                            "descendant_cleanup_proven": False}
                if report is not None:
                    for key in ("cleanup_error", "recovery_directory"):
                        if key in report:
                            recovery[key] = str(report[key])[:1024]
                            gui[key] = recovery[key]
                result["recovery_records"].append(recovery)
        elif not probe_passed:
            result["phases"].append({"name": "gui", "status": "blocked", "exit_code": None,
                                     "reason": "strict_policy_probe_failed"})
        else:
            result["phases"].append({"name": "gui", "status": "blocked", "exit_code": None,
                                     "reason": "pinned_chromium_control_unavailable"})
        result["phases"].append({"name": "package_tests", "status": "skipped", "exit_code": None,
                                 "reason": "gui_diagnostic_only"})
        result["status"] = "failed"
        result["error"] = "GUI diagnostic-only does not complete product acceptance"
        return result
    if network_only:
        result.update(network_diagnostic_only=True, source_diagnostic_only=True,
                      singleton_port_range_diagnostic=singleton,
                      full_acceptance_passed=False, product_acceptance_passed=False,
                      acceptance_passed=False, real_node_passed=False,
                      execution_mode="original_sdk", product_runtime_replaced=False)
        probe_command = [executable, "-X", "utf8", "-B", str(acceptance), "--root", str(root),
                         "--probe-only", "--report", str(directory / "probe.json")]
        probe, report, log = run_guest_phase("probe", probe_command, directory,
                                             timeout=min(90, phase_timeout))
        result["phases"].append(probe)
        result["logs"]["probe"] = log
        if report is not None:
            result["reports"]["probe"] = report
        probe_passed = probe.get("status") == "passed" and probe.get("exit_code") == 0
        for name in ("outside_edge", "edge_ui"):
            result[f"{name}_phase"] = {"name": name, "status": "skipped", "exit_code": None,
                                       "reason": "network_diagnostic_only"}
        for name in ("transport", "manager", "browser", "gui", "package_tests"):
            result["phases"].append({"name": name,
                "status": "blocked" if name in ("transport", "manager") and not probe_passed else "skipped",
                "exit_code": None, "reason": "network_diagnostic_only" if probe_passed
                    else "strict_policy_probe_failed"})
        if not probe_passed:
            result["experiments_phase"] = {"name": "experiments", "status": "blocked", "exit_code": None,
                                            "reason": "strict_policy_probe_failed"}
            result["error"] = "Strict policy probe failed; network experiment was not run"
            return result
        diagnostic_arguments = []
        try:
            diagnostic = guest_test_executor(root, workspace, vm_config)
            if diagnostic is not None:
                executor, manifest, metadata = diagnostic
                diagnostic_arguments = ["--test-psec-executor", str(executor), "--test-psec-manifest", str(manifest)]
                result.update(execution_mode="source_executor_diagnostic", test_psec_executor=metadata,
                              product_runtime_replaced=False)
        except Exception as exc:
            result["executor_validation_error"] = type(exc).__name__
            result["experiments_phase"] = {"name": "experiments", "status": "blocked", "exit_code": None,
                                            "reason": "executor_validation_failed"}
            result["error"] = "Source executor validation failed; network experiment was not run"
            return result
        experiment = workspace / ".github/windows_network_experiment.py"
        if not experiment.is_file():
            result["experiments_phase"] = {"name": "experiments", "status": "blocked", "exit_code": None,
                                            "reason": "network_experiment_missing"}
            result["error"] = "Network experiment source was unavailable"
            return result
        command = [executable, "-X", "utf8", "-B", str(experiment), "--root", str(root),
                   "--report", str(directory / "experiments.json"), "--preferred-policy-only",
                   "--vm-config", str(vm_config)]
        command.extend(diagnostic_arguments)
        if singleton:
            command.append("--singleton-port-range")
        record, report, log = run_guest_phase("experiments", command, directory,
                                              timeout=min(600, phase_timeout))
        result["experiments_phase"] = record
        result["logs"]["experiments"] = log
        if report is not None:
            result["reports"]["experiments"] = report
        if record.get("timed_out") or not experiment_teardown_proven("experiments", report):
            recovery = {"phase": "experiments", "reason": record.get("error", "Experiment cleanup was not proven"),
                        "descendant_cleanup_proven": False}
            if report is not None:
                for key in ("cleanup_error", "recovery_directory"):
                    if key in report:
                        recovery[key] = str(report[key])[:1024]
            result["recovery_records"].append(recovery)
        result["error"] = "Network diagnostic-only does not complete product acceptance"
        return result
    outside = workspace / ".github/windows_edge_outside_control.py"
    if outside.is_file():
        # Finish the ordinary-browser positive control before the network
        # experiment opens its private NIC capture window.
        command = [executable, "-X", "utf8", "-B", str(outside), "--root", str(root),
                   "--report", str(directory / "outside_edge.json"), "--timeout", "45"]
        record, report, log = run_guest_phase("outside_edge", command, directory, timeout=min(420, phase_timeout))
        result["outside_edge_phase"], result["logs"]["outside_edge"] = record, log
        if report is not None:
            result["reports"]["outside_edge"] = report
        if record.get("timed_out") or not outside_edge_teardown_proven(report):
            cleanup_pending = True
            recovery = {"phase": "outside_edge", "reason": record.get("error", "Outside Edge cleanup was not proven"),
                        "descendant_cleanup_proven": False}
            if report is not None and "recovery_directory" in report:
                recovery["recovery_directory"] = str(report["recovery_directory"])[:1024]
            result["recovery_records"].append(recovery)
    diagnostic_arguments = []
    result["execution_mode"] = "original_sdk"
    try:
        diagnostic = guest_test_executor(root, workspace, vm_config)
        if diagnostic is not None:
            executor, manifest, metadata = diagnostic
            diagnostic_arguments = ["--test-psec-executor", str(executor), "--test-psec-manifest", str(manifest)]
            result.update(execution_mode="source_executor_diagnostic", test_psec_executor=metadata,
                          product_runtime_replaced=False, product_network_boundary_passed=False)
    except Exception as exc:
        # A bad custom bundle cannot fall back to the product executor and
        # masquerade as a completed custom comparison. Unit tests still run.
        cleanup_pending = True
        result["executor_validation_error"] = type(exc).__name__
    # This optional source-only experiment precedes the product fixtures. Its
    # policy variants never replace a required phase or grant release status.
    # Incomplete experiment teardown prevents every later contained launch.
    experiment = workspace / ".github/windows_network_experiment.py"
    if experiment.is_file() and not cleanup_pending:
        command = [executable, "-X", "utf8", "-B", str(experiment),
                   "--root", str(root), "--report", str(directory / "experiments.json"), "--preferred-policy-only"]
        if vm_config is not None:
            command.extend(["--vm-config", str(vm_config)])
        command.extend(diagnostic_arguments)
        record, report, log = run_guest_phase(
            "experiments", command,
            directory, timeout=min(600, phase_timeout))
        result["experiments_phase"] = record
        result["logs"]["experiments"] = log
        if report is not None:
            result["reports"]["experiments"] = report
        if record.get("timed_out") or not experiment_teardown_proven("experiments", report):
            cleanup_pending = True
            recovery = {"phase": "experiments", "reason": record.get("error", "Experiment cleanup was not proven"),
                        "descendant_cleanup_proven": False}
            if report is not None:
                for key in ("cleanup_error", "recovery_directory"):
                    if key in report:
                        recovery[key] = str(report[key])[:1024]
            result["recovery_records"].append(recovery)
    ui_experiment = workspace / ".github/windows_edge_policy_experiment.py"
    if ui_experiment.is_file() and not cleanup_pending:
        command = [executable, "-X", "utf8", "-B", str(ui_experiment), "--root", str(root),
                   "--report", str(directory / "edge_ui.json")]
        command.extend(diagnostic_arguments)
        record, report, log = run_guest_phase("edge_ui", command, directory, timeout=min(900, phase_timeout))
        result["edge_ui_phase"], result["logs"]["edge_ui"] = record, log
        if report is not None:
            result["reports"]["edge_ui"] = report
        if record.get("timed_out") or not experiment_teardown_proven("edge_ui", report):
            cleanup_pending = True
            recovery = {"phase": "edge_ui", "reason": record.get("error", "UI diagnostic cleanup was not proven"),
                        "descendant_cleanup_proven": False}
            if report is not None:
                for key in ("cleanup_error", "recovery_directory"):
                    if key in report:
                        recovery[key] = str(report[key])[:1024]
            result["recovery_records"].append(recovery)
    for name in PHASE_NAMES:
        if ((cleanup_pending and name != "package_tests")
                or (name in ("transport", "manager", "browser", "gui") and not probe_passed)):
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
        elif name == "gui":
            command.extend([str(workspace / ".github/windows_gui_check.py"), "--root", str(root),
                            "--report", str(directory / "gui.json")])
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
        if name in ("transport", "manager", "browser", "gui") and record.get("interpreter_started"):
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
    collected = result["phases"] + [result[key] for key in ("outside_edge_phase", "experiments_phase", "edge_ui_phase") if key in result]
    if all(phase["status"] == "passed" for phase in collected):
        result["status"] = "passed"
    else:
        result["error"] = "Guest phases failed or were blocked: " + ", ".join(
            phase["name"] for phase in collected if phase["status"] != "passed")
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
    baseline = getattr(args, "baseline_diagnostic", False) is True
    custom_executor = getattr(args, "test_psec_executor", None)
    custom_manifest = getattr(args, "test_psec_manifest", None)
    diagnostic_mode = custom_executor is not None or custom_manifest is not None
    gui_diagnostic_only = getattr(args, "gui_diagnostic_only", False) is True
    chromium_gui_control_diagnostic = getattr(args, "chromium_gui_control", False) is True
    network_diagnostic_only = getattr(args, "network_diagnostic_only", False) is True
    singleton_port_range_diagnostic = getattr(args, "singleton_port_range_diagnostic", False) is True
    require_update = not baseline
    summary = {"status": "failed", "baseline_diagnostic": baseline,
               "execution_mode": "source_executor_diagnostic" if diagnostic_mode else "original_sdk",
               "product_runtime_replaced": False,
               "gui_diagnostic_only": gui_diagnostic_only,
               "chromium_gui_control_diagnostic": chromium_gui_control_diagnostic,
               "network_diagnostic_only": network_diagnostic_only,
               "singleton_port_range_diagnostic": singleton_port_range_diagnostic,
               "source_diagnostic_only": gui_diagnostic_only or chromium_gui_control_diagnostic or network_diagnostic_only or singleton_port_range_diagnostic or diagnostic_mode,
               "product_acceptance_passed": False,
               "full_acceptance_passed": False, "real_node_passed": False,
               "transport_passed": False, "manager_fixture_passed": False, "browser_fixture_passed": False,
               "gui_fixture_passed": False, "network_boundary_passed": False,
               "iso": {"url": ISO_URL, "sha256": ISO_SHA256,
               "download_page": ISO_SOURCE, "hash_source": ISO_HASH_SOURCE, "evaluation_days": 90},
               "official_update": {"required": require_update, "kb": "KB5127648", "target_build": UPDATE_BUILD, "target_ubr": UPDATE_UBR,
                                   "source": UPDATE_SOURCE, "catalog_update_id": UPDATE_CATALOG_ID}}
    try:
        if chromium_gui_control_diagnostic and (not gui_diagnostic_only or network_diagnostic_only or diagnostic_mode):
            raise ValueError("Chromium GUI control requires GUI-only diagnostic mode with the original SDK")
        summary["kvm_api_version"] = require_kvm()
        package = args.package.resolve(strict=True)
        verify_package(package, args.package_sha256.lower())
        summary["package_sha256"] = args.package_sha256.lower()
        original_sha256 = None
        if diagnostic_mode:
            if custom_executor is None or custom_manifest is None:
                raise ValueError("Test PSEC executor and manifest must be provided together")
            original_sha256 = package_executor_sha256(package)
            _, summary["test_psec_executor"] = verify_executor_bundle(
                ROOT, ROOT, custom_executor, custom_manifest, original_sha256)
            summary["diagnostic_network_boundary"] = {"status": "not_collected", "product_acceptance_passed": False}
            summary["diagnostic_executor_attested"] = False
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
            executor_bundle = None
            if diagnostic_mode:
                executor_bundle = work / TEST_EXECUTOR_DIRECTORY
                staged = stage_test_executor(executor_bundle, custom_executor, custom_manifest, original_sha256)
                if staged != summary["test_psec_executor"]:
                    raise ValueError("Diagnostic executor changed after host validation")
            iso = work / "official.iso"
            print("Downloading the fixed Microsoft Enterprise Evaluation ISO", flush=True)
            subprocess.run(["curl", "--fail", "--location", "--retry", "5", "--retry-all-errors",
                            "--connect-timeout", "30", "--max-time", "1800", "--proto", "=https",
                            "--proto-redir", "=https", "--continue-at", "-",
                            "--output", str(iso), ISO_URL], check=True, timeout=1800)
            if iso.stat().st_size != ISO_BYTES or digest(iso) != ISO_SHA256:
                raise RuntimeError("Microsoft ISO size/SHA-256 mismatch; guest installation was refused")
            summary["iso"]["verified"] = True
            updates = None
            if require_update:
                updates = work / "official-updates"
                summary["official_update"]["packages"] = download_updates(updates)
            chromium_control_archive = None
            chromium_control_sha256 = None
            if chromium_gui_control_diagnostic:
                control_helper = load_chromium_control_helper(ROOT)
                chromium_control_archive = work / CHROMIUM_CONTROL_ARCHIVE_MEMBER
                chromium_control_sha256 = control_helper.fetch_archive(chromium_control_archive)
                if chromium_control_sha256 != control_helper.ARCHIVE_SHA256:
                    raise RuntimeError("Pinned Chromium control archive digest mismatch")
                summary["chromium_gui_control"] = {
                    "status": "downloaded", "version": control_helper.VERSION,
                    "platform": control_helper.PLATFORM, "archive_sha256": chromium_control_sha256,
                }
            payload = work / "payload.zip"
            payload_options = {"test_executor_bundle": executor_bundle}
            if chromium_control_archive is not None:
                payload_options["chromium_control_archive"] = chromium_control_archive
            payload_hash = make_payload(package, payload, **payload_options)
            server = GuestServer(payload, artifacts, updates=updates)
            http_thread = threading.Thread(target=server.serve_forever, daemon=True)
            http_thread.start()
            qemu, tpm, qmp, capture = None, None, None, None
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
                    "require_official_update": require_update, "update_build": UPDATE_BUILD, "update_ubr": UPDATE_UBR,
                    "test_psec_executor_diagnostic": diagnostic_mode,
                    "gui_diagnostic_only": gui_diagnostic_only,
                    "chromium_gui_control_diagnostic": chromium_gui_control_diagnostic,
                    "network_diagnostic_only": network_diagnostic_only,
                    "singleton_port_range_diagnostic": singleton_port_range_diagnostic,
                    **({"chromium_gui_control_archive_sha256": chromium_control_sha256}
                       if chromium_control_sha256 is not None else {}),
                    **({"test_psec_executor_sha256": summary["test_psec_executor"]["executor_sha256"],
                        "test_psec_original_runtime_sha256": original_sha256}
                       if diagnostic_mode else {}),
                }, updates=updates)
                unattended = work / "unattended.iso"
                subprocess.run(["xorriso", "-as", "mkisofs", "-iso-level", "3", "-J", "-joliet-long", "-R",
                                "-V", "RULEPROXY_CI", "-b", "boot/etfsboot.com", "-no-emul-boot",
                                "-boot-load-size", "8", "-boot-info-table", "-eltorito-alt-boot",
                                "-e", efi_boot, "-no-emul-boot",
                                "-o", str(unattended), str(tree)], check=True)
                summary["remastered_iso"] = installer_layout(unattended)
                print("Remastered ISO facts: " + json.dumps(summary["remastered_iso"], separators=(",", ":")), flush=True)
                shutil.rmtree(tree)
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
                               "-netdev", "user,id=vmnet", "-device", f"e1000,netdev=vmnet,mac={VM_NIC_MAC}",
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
                    capture = WireCaptureController(qmp, work, artifacts, artifacts / "qemu.log")
                    server.capture = capture
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
                    if "chromium_gui_control" in server.result:
                        summary["chromium_gui_control_guest"] = server.result["chromium_gui_control"]
                    summary["official_update"]["guest"] = server.result.get("official_update")
                    if diagnostic_mode:
                        report = server.result.get("reports", {}).get("experiments", {})
                        summary["diagnostic_executor_attested"] = (
                            report.get("test_psec_executor") == summary["test_psec_executor"])
                    if not capture.log_clean() or capture.collection_error:
                        raise RuntimeError("VM packet capture control or dump/write failed")
                    verify_result(server.result, require_official_update=require_update,
                                  gui_diagnostic_only=gui_diagnostic_only,
                                  network_diagnostic_only=network_diagnostic_only or singleton_port_range_diagnostic)
                    if diagnostic_mode:
                        raise RuntimeError("Source executor diagnostics cannot qualify the original product network boundary")
                    summary["network_boundary"] = verify_network_boundary(capture.result)
                    summary.update(status="baseline_transport_and_package_tests_passed" if baseline else "transport_and_package_tests_passed", transport_passed=True,
                                   manager_fixture_passed=True, browser_fixture_passed=True, gui_fixture_passed=True, network_boundary_passed=True,
                                   ordinary_user=True, native_x64=True, elapsed_seconds=int(time.monotonic() - started))
                    scope = "Baseline diagnostic" if baseline else "Officially updated native x64"
                    print(scope + " PSEC fixtures, scoped UDP/default DNS boundary and package tests passed; full/real-node acceptance remains separate", flush=True)
            finally:
                # Dispose only this ephemeral test VM and TPM, never a named
                # host process or a user-owned Windows application.
                if capture is not None:
                    capture.close()
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
                if capture is not None:
                    # A delayed QEMU dump/write error invalidates an earlier
                    # packet summary and cannot leave a successful VM result.
                    capture.close()
                    summary["wire_evidence"] = capture.result
                    summary["wire_evidence_executor"] = (
                        "source_only_test_executor" if summary.get("diagnostic_executor_attested") is True
                        else "unverified_diagnostic_execution") if diagnostic_mode else "original_sdk"
                    if diagnostic_mode:
                        summary["diagnostic_network_boundary"] = diagnostic_network_boundary(
                            capture.result, executor_attested=summary.get("diagnostic_executor_attested") is True,
                            collection_failed=bool(capture.collection_error))
                    if capture.collection_error:
                        summary.pop("network_boundary", None)
                        summary.update(status="failed", transport_passed=False, manager_fixture_passed=False,
                                       browser_fixture_passed=False, gui_fixture_passed=False, network_boundary_passed=False,
                                       error="VM packet capture control or dump/write failed")
                server.shutdown()
                server.server_close()
                http_thread.join(timeout=5)
    except Exception as exc:
        summary.update(status="failed", transport_passed=False, manager_fixture_passed=False,
                       browser_fixture_passed=False, gui_fixture_passed=False, network_boundary_passed=False,
                       error=f"{type(exc).__name__}: {exc}")
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
        parser.add_argument("--vm-config", type=Path)
        args = parser.parse_args(argv[1:])
        result = run_guest_phases(args.root.resolve(), args.workspace.resolve(), args.report.resolve().parent,
                                  vm_config=args.vm_config)
        write_json(args.report, result)
        print(json.dumps({"status": result["status"], "phases": result["phases"]}, ensure_ascii=True), flush=True)
        return 0 if result["status"] == "passed" else 1
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--package", required=True, type=Path)
    parser.add_argument("--package-sha256", required=True)
    parser.add_argument("--artifacts", required=True, type=Path)
    parser.add_argument("--timeout-seconds", type=int, default=5400)
    parser.add_argument("--baseline-diagnostic", action="store_true",
                        help="Diagnose the fixed official ISO baseline; skips only CU staging/requirement, never full acceptance")
    parser.add_argument("--gui-diagnostic-only", action="store_true",
                        help="Run only the strict probe and packaged product GUI diagnostic; never qualifies acceptance")
    parser.add_argument("--chromium-gui-control", action="store_true",
                        help="Use the pinned Chrome for Testing control only in original-SDK GUI diagnostic mode")
    parser.add_argument("--network-diagnostic-only", action="store_true",
                        help="Run only the strict probe and preferred-policy network experiment; never qualifies acceptance")
    parser.add_argument("--singleton-port-range-diagnostic", action="store_true",
                        help="Encode the same single TCP port as an inclusive singleton range in network diagnostics")
    parser.add_argument("--test-psec-executor", type=Path,
                        help="Source-only diagnostic executor; never replaces product bin or grants release success")
    parser.add_argument("--test-psec-manifest", type=Path)
    args = parser.parse_args(argv)
    if (args.test_psec_executor is None) != (args.test_psec_manifest is None):
        parser.error("--test-psec-executor and --test-psec-manifest must be provided together")
    if args.gui_diagnostic_only and args.test_psec_executor is not None:
        parser.error("--gui-diagnostic-only uses the packaged product SDK and cannot be combined with a source executor")
    if args.gui_diagnostic_only and args.network_diagnostic_only:
        parser.error("GUI and network diagnostic-only modes are mutually exclusive")
    if args.chromium_gui_control and (not args.gui_diagnostic_only or args.network_diagnostic_only
                                      or args.test_psec_executor is not None):
        parser.error("Chromium GUI control requires GUI-only diagnostic mode with the original SDK")
    if args.singleton_port_range_diagnostic and (not args.network_diagnostic_only or args.test_psec_executor is not None):
        parser.error("Singleton port encoding requires network diagnostic-only with the original SDK")
    if not 300 <= args.timeout_seconds <= 14400:
        parser.error("--timeout-seconds must be between 300 and 14400")
    result = run(args)
    if (args.test_psec_executor is not None or args.gui_diagnostic_only or args.chromium_gui_control
            or args.network_diagnostic_only):
        return 1  # Partial diagnostics never qualify product acceptance.
    expected = "baseline_transport_and_package_tests_passed" if args.baseline_diagnostic else "transport_and_package_tests_passed"
    return 0 if (result["status"] == expected and result.get("baseline_diagnostic") is args.baseline_diagnostic
                 and result.get("network_boundary_passed") is True
                 and result.get("official_update", {}).get("required") is (not args.baseline_diagnostic)) else 1


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))
