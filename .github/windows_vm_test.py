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
MIN_FREE_BYTES = 55 * 1024**3
MAX_RESULT_BYTES = 8 * 1024**2
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
    return digest(destination)


def prepare_seed(tree: Path, password: str, configuration: dict) -> None:
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
            for name in ("probe", "transport", "browser"):
                if name in reports:
                    write_json(self.server.artifacts / f"windows-{name}.json", reports[name])
            for name in ("probe", "transport", "browser", "tests"):
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


def verify_result(result: dict) -> None:
    if result.get("status") != "passed" or result.get("ordinary_user") is not True:
        raise RuntimeError(f"Guest tests failed: {result.get('error', 'missing ordinary-user proof')}")
    phases = result.get("phases")
    if not isinstance(phases, list) or [phase.get("name") for phase in phases] != ["probe", "transport", "browser", "package_tests"]:
        raise RuntimeError("Guest did not complete each required test phase")
    if any(phase.get("exit_code") != 0 for phase in phases):
        raise RuntimeError("A guest test phase returned a failure exit code")
    reports = result.get("reports", {})
    probe, transport, browser = reports.get("probe", {}), reports.get("transport", {}), reports.get("browser", {})
    if probe.get("status") != "supported_only" or probe.get("probe", {}).get("supported") is not True:
        raise RuntimeError("Guest probe report did not prove strict policy support")
    if transport.get("status") != "transport_only" or transport.get("transport_passed") is not True:
        raise RuntimeError("Guest report did not pass the real PSEC transport fixture")
    if transport.get("host", {}).get("acceptance_scope") != "native_x64":
        raise RuntimeError("Transport did not prove native x64 execution")
    if any(report.get(key) is not False for report in (probe, transport, browser)
           for key in ("acceptance_passed", "real_node_passed")):
        raise RuntimeError("Credential-free fixtures cannot claim real-node/full acceptance")
    if probe.get("transport_passed") is not False or transport.get("manager_core_loss_passed") is not False:
        raise RuntimeError("Reports claimed an acceptance phase this VM run did not exercise")
    checks = {check.get("check"): check.get("status") for check in transport.get("checks", [])}
    required = {"transport_parent_child", "fixture_loss", "safe_psec_stop", "host_proxy_dns_default_routes_unchanged"}
    if not all(checks.get(name) == "passed" for name in required):
        raise RuntimeError("Transport report omitted a required isolation/lifecycle/network check")
    if browser.get("status") != "browser_fixture_only" or browser.get("browser_fixture_passed") is not True:
        raise RuntimeError("Native Windows Edge fixture did not pass")
    if browser.get("host", {}).get("acceptance_scope") != "native_x64":
        raise RuntimeError("Edge fixture did not prove native x64 execution")
    browser_checks = {check.get("check"): check for check in browser.get("checks", [])}
    for name in ("real_edge_launch_1", "real_edge_launch_2"):
        check = browser_checks.get(name, {})
        if check.get("status") != "passed" or any(check.get(key) is not True for key in (
            "dom_nonce_via_page_ack", "cookie_request_verified", "natural_headless_exit")):
            raise RuntimeError("Edge fixture omitted live browser/DOM/cookie/exit proof")
    if browser_checks["real_edge_launch_2"].get("private_profile_reused") is not True:
        raise RuntimeError("Edge fixture did not retain the private browser profile")
    if browser_checks.get("host_proxy_dns_default_routes_unchanged", {}).get("status") != "passed":
        raise RuntimeError("Edge fixture did not preserve host network settings")


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
               "transport_passed": False, "browser_fixture_passed": False,
               "iso": {"url": ISO_URL, "sha256": ISO_SHA256,
               "download_page": ISO_SOURCE, "hash_source": ISO_HASH_SOURCE, "evaluation_days": 90}}
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
                })
                unattended = work / "unattended.iso"
                subprocess.run(["xorriso", "-as", "mkisofs", "-iso-level", "3", "-J", "-joliet-long", "-R",
                                "-V", "RULEPROXY_CI", "-b", "boot/etfsboot.com", "-no-emul-boot",
                                "-boot-load-size", "8", "-boot-info-table", "-eltorito-alt-boot",
                                "-e", efi_boot, "-no-emul-boot",
                                "-o", str(unattended), str(tree)], check=True)
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
                    verify_result(server.result)
                    summary.update(status="transport_and_package_tests_passed", transport_passed=True, browser_fixture_passed=True,
                                   ordinary_user=True, native_x64=True, elapsed_seconds=int(time.monotonic() - started))
                    print("Native x64 PSEC transport, Edge fixture and release package tests passed; real-node acceptance remains separate", flush=True)
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
        summary.update(status="failed", transport_passed=False, browser_fixture_passed=False, error=f"{type(exc).__name__}: {exc}")
        print(f"::error title=Windows KVM guest::{type(exc).__name__}: {exc}", flush=True)
    finally:
        write_json(artifacts / "windows-vm-summary.json", summary)
    return summary


def main(argv: list[str]) -> int:
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
