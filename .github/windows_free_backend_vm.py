"""Run one fixed alternative backend in a disposable updated Windows 11 x64 VM.

This harness deliberately does not install the RuleProxy package or MXC/PSEC.
It reuses only the repository's pinned Windows ISO, CU, UEFI/TPM and KVM
helpers. Backend installation is a SYSTEM-only setup stage; the actual probe
starts after the CU and runs from the ordinary RuleProxyCI desktop session.
"""
from __future__ import annotations

import argparse
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import re
import shutil
import subprocess
import sys
import tempfile
import threading
import time
import zipfile

ROOT = Path(__file__).resolve().parents[1]
MAX_BUNDLE_BYTES = 512 * 1024 * 1024
MAX_MANIFEST_BYTES = 128 * 1024
MAX_RESULT_BYTES = 2 * 1024 * 1024
BACKENDS = {"sandboxie", "proxybridge"}
BACKEND_RELEASE = {"sandboxie": "v1.18.5", "proxybridge": "v4.1.1"}
INSTALLER_MEMBER = {
    "sandboxie": "installers/Sandboxie-Plus-x64-v1.18.5.exe",
    "proxybridge": "installers/ProxyBridge-Setup-4.1.1.exe",
}
INSTALLER_PIN = {
    "sandboxie": (24_856_520, "bd984db71900ecb9fc22e4bbffda4363a92cd755840a8792c2422d6d42fd6fa3"),
    "proxybridge": (799_792, "754f45fb31f3953b9b81005090f9a479f89827adb628cf2c76bc4139f673a152"),
}


def _load_vm_helpers():
    path = ROOT / ".github/windows_vm_test.py"
    spec = importlib.util.spec_from_file_location("ruleproxy_free_backend_vm_helpers", path)
    if spec is None or spec.loader is None:
        raise RuntimeError("Pinned disposable Windows VM helpers are unavailable")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def _strict_object(pairs):
    value = {}
    for key, item in pairs:
        if key in value:
            raise ValueError("Duplicate JSON object key")
        value[key] = item
    return value


def sha256_file(path: Path) -> str:
    checksum = hashlib.sha256()
    with path.open("rb") as stream:
        for block in iter(lambda: stream.read(1024 * 1024), b""):
            checksum.update(block)
    return checksum.hexdigest()


def read_manifest(path: Path, backend: str) -> dict:
    raw = path.read_bytes()
    if not raw or len(raw) > MAX_MANIFEST_BYTES:
        raise ValueError("Backend bundle manifest is empty or oversized")
    value = json.loads(raw.decode("utf-8"), object_pairs_hook=_strict_object)
    if (not isinstance(value, dict) or type(value.get("schema_version")) is not int
            or value.get("schema_version") != 1
            or value.get("backend") != backend or value.get("release") != BACKEND_RELEASE[backend]
            or value.get("source_diagnostic_only") is not True
            or value.get("release_eligible") is not False
            or not isinstance(value.get("files"), list) or not value["files"]):
        raise ValueError("Backend bundle manifest has the wrong schema or backend")
    return value


def validate_bundle(bundle: Path, manifest_path: Path, backend: str) -> dict:
    """Validate the builder-produced ZIP against its embedded fixed manifest."""
    if backend not in BACKENDS:
        raise ValueError("Unknown fixed backend")
    bundle = bundle.resolve(strict=True)
    manifest = read_manifest(manifest_path, backend)
    if bundle.stat().st_size <= 0 or bundle.stat().st_size > MAX_BUNDLE_BYTES:
        raise ValueError("Backend bundle size is outside its bound")
    expected = {}
    for row in manifest["files"]:
        if (not isinstance(row, dict) or set(row) - {"path", "size", "sha256", "source_url"}
                or not isinstance(row.get("path"), str) or not isinstance(row.get("size"), int)
                or type(row.get("size")) is not int or row["size"] <= 0
                or not re.fullmatch(r"[0-9a-f]{64}", str(row.get("sha256", "")))):
            raise ValueError("Invalid bundle file record")
        if "source_url" in row and (not isinstance(row["source_url"], str)
                or not row["source_url"].startswith("https://")):
            raise ValueError("Bundle source URL must be HTTPS")
        name = row["path"]
        parts = Path(name).parts
        if (name.startswith("/") or "\\" in name or ":" in name or ".." in parts
                or name in expected or name == "manifest.json"):
            raise ValueError("Unsafe or duplicate bundle member")
        allowed = (name.startswith("python/") or name.startswith("mihomo/")
                   or name.startswith("chromium/chrome-win64/")
                   or name.startswith("installers/") or name.startswith("scripts/"))
        if not allowed:
            raise ValueError("Bundle member is outside the fixed backend payload areas")
        if name.startswith("installers/") and name != INSTALLER_MEMBER[backend]:
            raise ValueError("Bundle contains an installer for a different backend")
        if name == INSTALLER_MEMBER[backend]:
            expected_size, expected_sha256 = INSTALLER_PIN[backend]
            if row["size"] != expected_size or row["sha256"] != expected_sha256:
                raise ValueError("Installer member does not match the independently pinned official bytes")
        expected[name] = row
    with zipfile.ZipFile(bundle) as archive:
        records = archive.infolist()
        names = [record.filename for record in records]
        if len(names) != len(set(names)) or set(names) != set(expected) | {"manifest.json"}:
            raise ValueError("Bundle ZIP members do not exactly match the manifest")
        embedded = archive.read("manifest.json")
        if len(embedded) > MAX_MANIFEST_BYTES or json.loads(
                embedded.decode("utf-8"), object_pairs_hook=_strict_object) != manifest:
            raise ValueError("Embedded bundle manifest differs from the supplied manifest")
        for record in records:
            name = record.filename
            if (record.is_dir() or record.flag_bits & 1 or record.file_size > MAX_BUNDLE_BYTES
                    or record.external_attr >> 16 & 0o170000 == 0o120000):
                raise ValueError("Bundle contains a directory, encrypted, oversized or linked member")
            if name == "manifest.json":
                continue
            row = expected[name]
            if record.file_size != row["size"]:
                raise ValueError("Bundle file size differs from its fixed manifest")
            checksum = hashlib.sha256()
            with archive.open(record) as source:
                for block in iter(lambda: source.read(1024 * 1024), b""):
                    checksum.update(block)
            if checksum.hexdigest() != row["sha256"]:
                raise ValueError("Bundle file digest differs from its fixed manifest")
    required = {"python/python.exe", "mihomo/mihomo.exe", "chromium/chrome-win64/chrome.exe",
                "scripts/windows_native_dns_probe.py",
                "scripts/windows_free_backend_fixture.py", f"scripts/windows_{backend}_control.py"}
    if not required.issubset(expected):
        raise ValueError("Backend bundle is missing required pinned helpers")
    if INSTALLER_MEMBER[backend] not in expected:
        raise ValueError("Backend bundle is missing its fixed installer")
    return {"backend": backend, "release": manifest["release"], "file_count": len(expected),
            "bundle_sha256": sha256_file(bundle), "manifest_sha256": hashlib.sha256(
                json.dumps(manifest, sort_keys=True, separators=(",", ":")).encode("utf-8")).hexdigest()}


class ProbeCapture:
    """QMP NIC capture started/stopped only around the ordinary-user probe."""
    def __init__(self, qmp, work: Path, artifacts: Path, qemu_log: Path):
        self.qmp, self.work, self.artifacts, self.qemu_log = qmp, work, artifacts, qemu_log
        self.path = work / "free-backend-probe.pcap"
        self.active = False
        self.started = False
        self.error = None
        self.result = None
        self._lock = threading.RLock()

    def start(self, _value=None):
        with self._lock:
            if self.started or self.path.exists():
                raise RuntimeError("Probe capture may start only once")
            self.started = True
            try:
                fd = os.open(self.path, os.O_CREAT | os.O_EXCL | os.O_WRONLY, 0o600)
                os.close(fd)
                self.qmp.execute("object-add", {"qom-type": "filter-dump", "id": "free_backend_wire",
                                                  "netdev": "vmnet", "file": str(self.path)})
                self.active = True
                self.result = {"status": "active", "scope": "qemu_vm_nic_probe_window_only"}
                return self.result
            except Exception:
                self.error = "capture_start_failed"
                raise RuntimeError(self.error) from None

    def stop(self):
        with self._lock:
            if not self.active:
                raise RuntimeError("Probe capture was not active")
            try:
                self.qmp.execute("object-del", {"id": "free_backend_wire"})
                self.active = False
                if not self.path.is_file() or self.path.stat().st_size < 24:
                    raise RuntimeError("capture_file_missing_or_empty")
                target = self.artifacts / "free-backend-probe.pcap"
                shutil.copyfile(self.path, target)
                with self.qemu_log.open("rb") as source:
                    log = source.read(1024 * 1024 + 1)
                text = log.decode("utf-8", "replace")
                failure = r"(?:error|fail(?:ed|ure)?|cannot|unable|could not)"
                dump = r"(?:filter[- ]?dump|free_backend_wire|dump|writ(?:e|ing))"
                if len(log) > 1024 * 1024 or re.search(
                        r"(?im)^.*(?:" + dump + r".*?" + failure + r"|" + failure + r".*?" + dump + r").*$", text):
                    raise RuntimeError("qemu_capture_log_error")
                self.result = {"status": "stopped", "bytes": target.stat().st_size,
                               "scope": "qemu_vm_nic_probe_window_only", "raw_pcap_retained": True}
                return self.result
            except Exception:
                self.error = "capture_stop_or_copy_failed"
                raise RuntimeError(self.error) from None

    def finish(self, _value):
        return self.stop()

    def close(self):
        if self.active:
            try:
                self.qmp.execute("object-del", {"id": "free_backend_wire"})
                self.active = False
            except Exception:
                self.error = "capture_cleanup_failed"


def make_payload(bundle: Path, output: Path, backend: str) -> str:
    with zipfile.ZipFile(output, "w", compression=zipfile.ZIP_DEFLATED) as archive:
        archive.write(bundle, "backend-bundle.zip")
        archive.writestr("backend.json", json.dumps({"schema_version": 1, "backend": backend},
                                                       sort_keys=True, separators=(",", ":")))
    return sha256_file(output)


def _safe_result(value: object) -> dict:
    if not isinstance(value, dict) or len(json.dumps(value, ensure_ascii=True).encode("ascii")) > MAX_RESULT_BYTES:
        raise ValueError("Guest backend result is invalid or oversized")
    if value.get("schema_version") != 1 or value.get("status") not in ("passed", "failed"):
        raise ValueError("Guest backend result schema/status is invalid")
    if value.get("diagnostic_only") is not True or value.get("product_acceptance_passed") is not False:
        raise ValueError("Alternative backend result cannot claim product acceptance")
    return value


def verify_guest_result(value: dict, backend: str, build: int, ubr: int) -> None:
    if value.get("backend") != backend or value.get("ordinary_user") is not True:
        raise ValueError("Guest result did not prove the requested backend and ordinary user")
    if value.get("is_elevated") is not False or value.get("is_administrator") is not False:
        raise ValueError("Guest probe was not an ordinary non-administrator user")
    if (type(value.get("windows_build")) is not int or value["windows_build"] != build
            or type(value.get("windows_ubr")) is not int or value["windows_ubr"] < ubr):
        raise ValueError("Guest result did not prove the pinned target Windows build")
    reports = value.get("reports")
    if not isinstance(reports, dict):
        raise ValueError("Guest result omitted phase reports")
    install, probe = reports.get("install"), reports.get("probe")
    driver_signature = install.get("driver_signature") if isinstance(install, dict) else None
    service_install = install.get("service_install") if isinstance(install, dict) else None
    if (not isinstance(install, dict) or install.get("status") != "passed"
            or install.get("schema_version") != 1
            or install.get("phase") != "install" or install.get("backend") != backend
            or install.get("ordinary_user") is not False or install.get("is_elevated") is not True
            or type(install.get("reboot_required")) is not bool
            or install.get("target_user_authorized") is not True
            or install.get("installer_sha256") != INSTALLER_PIN[backend][1]
            or not isinstance(driver_signature, dict) or driver_signature.get("status") != "Valid"
            or not isinstance(service_install, dict) or service_install.get("exists") is not True
            or str(service_install.get("state", "")).lower() not in ("running", "stopped")
            or str(service_install.get("start_type", "")).lower() not in (
                "auto", "manual", "auto_start", "demand_start", "boot_start",
                "system_start", "disabled", "unknown")):
        raise ValueError("SYSTEM install report is incomplete or inconsistent")
    if (not isinstance(probe, dict) or probe.get("status") != "passed"
            or probe.get("schema_version") != 1
            or probe.get("phase") != "probe" or probe.get("backend") != backend
            or probe.get("ordinary_user") is not True or probe.get("is_elevated") is not False
            or probe.get("is_administrator") is not False
            or probe.get("windows_build") != build or probe.get("windows_ubr", 0) < ubr
            or probe.get("cleanup_proven") is not True
            or probe.get("diagnostic_only") is not True
            or probe.get("product_acceptance_passed") is not False):
        raise ValueError("Ordinary-user probe report did not satisfy required identity/cleanup gates")
    capture = value.get("capture")
    if not isinstance(capture, dict) or capture.get("status") != "stopped":
        raise ValueError("Probe-window packet capture was not completed")


def run(args) -> dict:
    vm = _load_vm_helpers()
    artifacts = args.artifacts.resolve()
    artifacts.mkdir(parents=True, exist_ok=True)
    summary = {"schema_version": 1, "backend": args.backend, "status": "failed",
               "diagnostic_only": True, "product_acceptance_passed": False,
               "bundle": validate_bundle(args.bundle, args.manifest, args.backend),
               "target_windows": {"build": vm.UPDATE_BUILD, "minimum_ubr": vm.UPDATE_UBR,
                                  "verified": False},
               "native_x64": True, "install_identity": "disposable_vm_system_only",
               "probe_identity": "ordinary_ruleproxyci_desktop_user",
               "capture_scope": "probe_window_only", "iso": {"url": vm.ISO_URL,
                   "sha256": vm.ISO_SHA256, "verified": False}, "elapsed_seconds": 0}
    start_time = time.monotonic()
    qemu = tpm = qmp = server = http_thread = capture = None
    try:
        summary["kvm_api_version"] = vm.require_kvm()
        for name in ("qemu-system-x86_64", "qemu-img", "swtpm", "xorriso", "curl"):
            if not shutil.which(name):
                raise RuntimeError(f"Missing Ubuntu test dependency: {name}")
        extractor = shutil.which("7zz") or shutil.which("7z")
        if extractor is None:
            raise RuntimeError("Missing UDF extractor: install Ubuntu 7zip or p7zip-full")
        firmware = Path("/usr/share/OVMF")
        code, variables = firmware / "OVMF_CODE_4M.ms.fd", firmware / "OVMF_VARS_4M.ms.fd"
        if not code.is_file() or not variables.is_file():
            raise RuntimeError("OVMF 4 MB Secure Boot firmware is unavailable")
        with tempfile.TemporaryDirectory(prefix="ruleproxy-free-backend-") as temp_name:
            work = Path(temp_name)
            os.chmod(work, 0o700)
            if shutil.disk_usage(work).free < vm.MIN_FREE_BYTES:
                raise RuntimeError("Windows installation requires at least 55 GiB free")
            iso = work / "official.iso"
            subprocess.run(["curl", "--fail", "--location", "--retry", "5", "--retry-all-errors",
                            "--connect-timeout", "30", "--max-time", "1800", "--proto", "=https",
                            "--proto-redir", "=https", "--continue-at", "-", "--output", str(iso), vm.ISO_URL],
                           check=True, timeout=1800)
            if iso.stat().st_size != vm.ISO_BYTES or sha256_file(iso) != vm.ISO_SHA256:
                raise RuntimeError("Pinned Microsoft Windows ISO failed size/SHA-256 verification")
            summary["iso"]["verified"] = True
            updates = work / "official-updates"
            vm.download_updates(updates)
            payload = work / "payload.zip"
            payload_sha = make_payload(args.bundle, payload, args.backend)
            server = vm.GuestServer(payload, artifacts, updates=updates)
            http_thread = threading.Thread(target=server.serve_forever, daemon=True)
            http_thread.start()
            tree = work / "iso-tree"
            tree.mkdir()
            subprocess.run([extractor, "x", "-tudf", "-y", f"-o{tree}", str(iso)],
                           check=True, timeout=900)
            boot = vm.validate_install_tree(tree)
            summary["installer_boot_image"] = boot
            vm.prepare_seed(tree, os.urandom(12).hex() + "Ci!9", {
                "host_url": f"http://10.0.2.2:{server.server_address[1]}/{server.capability}",
                "payload_sha256": payload_sha, "package_sha256": "0" * 64,
                "require_official_update": True, "update_build": vm.UPDATE_BUILD,
                "update_ubr": vm.UPDATE_UBR, "free_backend": args.backend,
                "free_backend_bundle_sha256": summary["bundle"]["bundle_sha256"],
            }, updates=updates)
            # The UDF seed helper writes the same stable script names expected by
            # the unattend file. Replace only those two guest entrypoints.
            setup_path = tree / "ruleproxy-vm-setup.ps1"
            setup_path.rename(tree / "ruleproxy-base-setup.ps1")
            (tree / "ruleproxy-vm-setup.ps1").write_text(
                (ROOT / ".github/windows-free-backend-setup.ps1").read_text(encoding="utf-8"),
                encoding="utf-8-sig")
            (tree / "ruleproxy-vm-run.ps1").write_text(
                (ROOT / ".github/windows-free-backend-run.ps1").read_text(encoding="utf-8"),
                encoding="utf-8-sig")
            # These are guest-only scripts; no update package or backend binary
            # is added to the repository artifact tree.
            (tree / "windows-free-backend-install.ps1").write_text(
                (ROOT / ".github/windows-free-backend-install.ps1").read_text(encoding="utf-8"),
                encoding="utf-8-sig")
            (tree / "windows-free-backend-acl.ps1").write_text(
                (ROOT / ".github/windows-free-backend-acl.ps1").read_text(encoding="utf-8"),
                encoding="utf-8-sig")
            unattended = work / "unattended.iso"
            subprocess.run(["xorriso", "-as", "mkisofs", "-iso-level", "3", "-J", "-joliet-long", "-R",
                            "-V", "RULEPROXY_FREE", "-b", "boot/etfsboot.com", "-no-emul-boot",
                            "-boot-load-size", "8", "-boot-info-table", "-eltorito-alt-boot", "-e", boot,
                            "-no-emul-boot", "-o", str(unattended), str(tree)], check=True)
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
                try:
                    tpm = subprocess.Popen(["swtpm", "socket", "--tpm2", "--tpmstate", f"dir={state}",
                                        "--ctrl", f"type=unixio,path={tpm_socket}"], stdout=tpm_log,
                                       stderr=subprocess.STDOUT)
                    deadline = time.monotonic() + 20
                    while not tpm_socket.exists():
                        if tpm.poll() is not None or time.monotonic() >= deadline:
                            raise RuntimeError("Software TPM failed to initialize")
                        time.sleep(.1)
                    command = ["qemu-system-x86_64", "-machine", "q35,accel=kvm,smm=on", "-cpu",
                           "host,hv-relaxed=on,hv-vapic=on,hv-spinlocks=0x1fff,hv-time=on", "-m", "6144", "-smp", "4",
                           "-global", "driver=cfi.pflash01,property=secure,value=on",
                           "-drive", f"if=pflash,format=raw,readonly=on,file={code}",
                           "-drive", f"if=pflash,format=raw,file={nvram}",
                           "-drive", f"if=none,id=system,file={disk},format=qcow2,discard=unmap",
                           "-device", "ide-hd,drive=system,bus=ide.0,bootindex=1",
                           "-drive", f"if=none,id=install,file={unattended},media=cdrom,readonly=on",
                           "-device", "ide-cd,drive=install,bus=ide.1,bootindex=2",
                           "-netdev", "user,id=vmnet", "-device", f"e1000,netdev=vmnet,mac={vm.VM_NIC_MAC}",
                           "-chardev", f"socket,id=tpm,path={tpm_socket}", "-tpmdev", "emulator,id=tpmdev,chardev=tpm",
                           "-device", "tpm-tis,tpmdev=tpmdev", "-device", "qemu-xhci", "-device", "usb-tablet",
                           "-vga", "std", "-display", "none", "-serial", f"file:{artifacts / 'serial.log'}",
                           "-monitor", "none", "-qmp", f"unix:{qmp_socket},server=on,wait=off"]
                    qemu = subprocess.Popen(command, stdin=subprocess.DEVNULL, stdout=qemu_log, stderr=subprocess.STDOUT)
                    deadline = time.monotonic() + 20
                    while qmp is None:
                        if qemu.poll() is not None or time.monotonic() >= deadline:
                            raise RuntimeError("QEMU KVM guest failed to start")
                        try:
                            qmp = vm.Qmp(qmp_socket)
                        except OSError:
                            time.sleep(.1)
                    if qmp.execute("query-kvm").get("enabled") is not True:
                        raise RuntimeError("QEMU did not enable KVM; TCG is forbidden")
                    summary["qemu_kvm_enabled"] = True
                    capture = ProbeCapture(qmp, work, artifacts, artifacts / "qemu.log")
                    server.capture = capture
                    started = time.monotonic()
                    deadline = started + args.timeout_seconds
                    while not server.received.wait(30):
                        if qemu.poll() is not None:
                            raise RuntimeError("Windows guest exited before returning its report")
                        if time.monotonic() >= deadline:
                            raise TimeoutError("Disposable Windows backend VM exceeded its time budget")
                        print(f"Windows backend VM running for {int(time.monotonic()-started)} seconds", flush=True)
                        try:
                            vm.screenshot(qmp, work / "screen.ppm", artifacts / "last-screen.png")
                        except (OSError, ValueError, RuntimeError):
                            pass
                    result = _safe_result(server.result)
                    # Retain the guest's bounded partial result even if a
                    # host-side gate rejects it; failure artifacts must show
                    # what the guest actually observed.
                    summary["guest_result"] = result
                    verify_guest_result(result, args.backend, vm.UPDATE_BUILD, vm.UPDATE_UBR)
                    summary["target_windows"]["verified"] = (result.get("windows_build") == vm.UPDATE_BUILD
                        and result.get("windows_ubr", 0) >= vm.UPDATE_UBR)
                    summary["capture"] = capture.result
                    summary["elapsed_seconds"] = int(time.monotonic() - started)
                    if (result.get("status") == "passed" and summary["target_windows"]["verified"] is True
                            and capture.result is not None and capture.result.get("status") == "stopped"):
                        summary["status"] = "diagnostic_probe_passed"
                    else:
                        summary["status"] = "failed"
                finally:
                    if capture is not None:
                        capture.close()
                        if capture.error:
                            summary["capture_error"] = capture.error
                            summary["status"] = "failed"
                    if qmp is not None:
                        if qemu is not None and qemu.poll() is None:
                            try:
                                qmp.execute("system_powerdown")
                                qemu.wait(timeout=30)
                            except (OSError, RuntimeError, subprocess.TimeoutExpired):
                                pass
                        qmp.close()
                    vm.stop_owned(qemu)
                    vm.stop_owned(tpm)
                    if server is not None:
                        server.shutdown()
                        server.server_close()
                    if http_thread is not None:
                        http_thread.join(timeout=5)
    except Exception as exc:
        # Exception text can contain a private temporary path, capability URL,
        # or command argument. Keep only a bounded type label in public logs.
        summary.update(status="failed", error_type=type(exc).__name__[:64])
        print(f"::error title=Windows free backend VM::{type(exc).__name__}", flush=True)
    finally:
        summary["elapsed_seconds"] = int(time.monotonic() - start_time)
        vm.write_json(artifacts / "windows-free-backend-summary.json", summary)
    return summary


def main(argv=None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--backend", choices=sorted(BACKENDS), required=True)
    parser.add_argument("--bundle", type=Path, required=True)
    parser.add_argument("--manifest", type=Path, required=True)
    parser.add_argument("--artifacts", type=Path, required=True)
    parser.add_argument("--timeout-seconds", type=int, default=10800)
    args = parser.parse_args(argv)
    if not 600 <= args.timeout_seconds <= 14400:
        parser.error("--timeout-seconds must be between 600 and 14400")
    result = run(args)
    return 0 if result.get("status") == "diagnostic_probe_passed" else 1


if __name__ == "__main__":
    raise SystemExit(main())
