"""Qualify the installed product in a fixed official Windows 11 x64 KVM VM.

Only media/VM primitives are reused from the historical harness. No MXC policy,
capability gate or PSEC acceptance result participates in this qualification.
"""
from __future__ import annotations

import argparse
import base64
import binascii
from contextlib import contextmanager
import hashlib
import importlib.util
import json
import os
import platform
from pathlib import Path, PurePosixPath
import secrets
import shutil
import signal
import stat
import struct
import subprocess
import sys
import tempfile
import threading
import time
import xml.etree.ElementTree as ET
import zipfile

ROOT = Path(__file__).resolve().parent.parent
_spec = importlib.util.spec_from_file_location("ruleproxy_vm_media", ROOT / ".github/windows_vm_test.py")
media = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(media)

SOURCE_IDENTITIES = frozenset({"manager.py", "server.py", "launcher.py", "windows_proxy_service.py",
    "windows_proxy_policy.py", "windows_proxy_client.py", "windows_proxy_runtime.py",
    "windows_proxy_pins.py", "windows_app_process.py", "windows_core_process.py"})
MAX_GUEST_RESULT_BYTES = 8 * 1024**2
VISIBLE_GUI_CHECKS = frozenset({"suite_interactive_session", "visible_browser_window", "visible_browser_ordinary",
                              "visible_browser_png_created", "visible_browser_job_stop"})


def visible_screenshot_bytes(report):
    """Validate the transported screenshot before it becomes a local artifact."""
    user = report.get("ordinary_suite", {})
    browser = user.get("browser_visible", {}) if isinstance(user, dict) else None
    if not isinstance(browser, dict):
        raise RuntimeError("Native visible browser screenshot evidence is missing")
    encoded, expected = browser.get("screenshot_png_base64"), browser.get("screenshot_sha256")
    if (not isinstance(encoded, str) or not encoded or len(encoded) > MAX_GUEST_RESULT_BYTES
            or not isinstance(expected, str) or len(expected) != 64
            or any(char not in "0123456789abcdef" for char in expected)):
        raise RuntimeError("Native visible browser screenshot metadata is invalid")
    try:
        raw = base64.b64decode(encoded, validate=True)
    except (ValueError, binascii.Error) as exc:
        raise RuntimeError("Native visible browser screenshot is not strict base64") from exc
    if (not raw or len(raw) > 6 * 1024**2 or hashlib.sha256(raw).hexdigest() != expected
            or not raw.startswith(b"\x89PNG\r\n\x1a\n")):
        raise RuntimeError("Native visible browser screenshot digest or PNG signature failed")
    offset, seen_header, seen_data, seen_end = 8, False, False, False
    while offset < len(raw):
        if offset + 12 > len(raw):
            raise RuntimeError("Native visible browser PNG is truncated")
        size = struct.unpack_from(">I", raw, offset)[0]
        kind = raw[offset + 4:offset + 8]
        end = offset + 12 + size
        if end > len(raw):
            raise RuntimeError("Native visible browser PNG chunk exceeds its size")
        payload = raw[offset + 8:end - 4]
        crc = struct.unpack_from(">I", raw, end - 4)[0]
        if binascii.crc32(kind + payload) & 0xFFFFFFFF != crc:
            raise RuntimeError("Native visible browser PNG chunk checksum failed")
        if not seen_header:
            if kind != b"IHDR" or size != 13:
                raise RuntimeError("Native visible browser PNG has no initial IHDR")
            width, height, depth, color, compression, filtering, interlace = struct.unpack(">IIBBBBB", payload)
            depths = {0: (1, 2, 4, 8, 16), 2: (8, 16), 3: (1, 2, 4, 8), 4: (8, 16), 6: (8, 16)}
            if (not 0 < width <= 8192 or not 0 < height <= 8192 or depth not in depths.get(color, ())
                    or compression != 0 or filtering != 0 or interlace not in (0, 1)):
                raise RuntimeError("Native visible browser PNG header is invalid")
            seen_header = True
        elif kind == b"IHDR":
            raise RuntimeError("Native visible browser PNG repeats IHDR")
        if kind == b"IDAT" and size:
            seen_data = True
        if kind == b"IEND":
            if size or end != len(raw) or not seen_data:
                raise RuntimeError("Native visible browser PNG ending is invalid")
            seen_end = True
        offset = end
    if not seen_header or not seen_data or not seen_end:
        raise RuntimeError("Native visible browser PNG is incomplete")
    return raw


class QualificationInterrupted(Exception):
    def __init__(self, signum):
        self.signum = signum
        super().__init__("Native qualification interrupted by " + signal.Signals(signum).name)


@contextmanager
def cancellation_signals():
    """Turn runner cancellation into a normal, evidence-preserving cleanup path."""
    previous = {}
    def interrupt(signum, _frame):
        for number in previous:
            signal.signal(number, signal.SIG_IGN)
        raise QualificationInterrupted(signum)
    try:
        for number in (signal.SIGINT, signal.SIGTERM):
            previous[number] = signal.signal(number, interrupt)
        yield
    finally:
        for number, handler in previous.items():
            signal.signal(number, handler)


def persist_summary(artifacts, summary, phase=None):
    """A complete summary must exist before expensive or interruptible work."""
    if phase is not None:
        summary["phase"] = phase
        summary.setdefault("phases", []).append({"phase": phase, "unix_time": time.time()})
    temporary = artifacts / "native-product-summary.tmp"
    temporary.write_text(json.dumps(summary, ensure_ascii=True, indent=2) + "\n", encoding="ascii")
    os.replace(temporary, artifacts / "native-product-summary.json")


def host_resources(work):
    result = {"architecture": platform.machine(), "kernel": platform.release(),
              "cpu_count": os.cpu_count(), "disk_free_bytes": shutil.disk_usage(work).free}
    cgroup = Path("/sys/fs/cgroup")
    try:
        membership = Path("/proc/self/cgroup").read_text().strip()
        result["cgroup_membership"] = membership
        relative = next(line.split(":", 2)[2] for line in membership.splitlines() if line.startswith("0::"))
        parts = PurePosixPath(relative).parts
        candidate = cgroup.joinpath(*(parts[1:] if relative.startswith("/") else parts))
        if ".." not in parts and candidate.is_dir():
            cgroup = candidate
    except (OSError, StopIteration):
        pass
    try:
        result["cpu_affinity_count"] = len(os.sched_getaffinity(0))
    except AttributeError:
        result["cpu_affinity_count"] = os.cpu_count()
    for key, path in {"cpu_max": cgroup / "cpu.max", "cpu_stat": cgroup / "cpu.stat",
                      "memory_max": cgroup / "memory.max", "memory_current": cgroup / "memory.current",
                      "cpu_pressure": "/proc/pressure/cpu", "io_pressure": "/proc/pressure/io",
                      "memory_pressure": "/proc/pressure/memory", "cpu_times": "/proc/stat"}.items():
        try:
            text = Path(path).read_text()
            result[key] = text.splitlines()[0] if key == "cpu_times" else text.strip()
        except OSError:
            pass
    try:
        memory = {line.split(":", 1)[0]: int(line.split()[1]) * 1024
                  for line in Path("/proc/meminfo").read_text().splitlines()
                  if line.startswith(("MemTotal:", "MemAvailable:", "SwapTotal:", "SwapFree:"))}
        result.update(memory)
    except (OSError, ValueError, IndexError):
        pass
    effective = result["cpu_affinity_count"] or 0
    try:
        quota, period = result.get("cpu_max", "max 100000").split()
        if quota != "max":
            effective = min(effective, int(quota) / int(period))
        if result.get("memory_max", "max") != "max":
            result["cgroup_memory_available"] = int(result["memory_max"]) - int(result["memory_current"])
    except (ValueError, KeyError, ZeroDivisionError):
        pass
    result["effective_cpu_count"] = effective
    return result


def check_host_resources(facts):
    available = min(facts.get("MemAvailable", 0), facts.get("cgroup_memory_available", 2**63))
    if facts.get("effective_cpu_count", 0) < 4 or available < 8 * 1024**3:
        raise RuntimeError("Native VM requires at least 4 effective host CPUs and 8 GiB available memory for its fixed 4-vCPU/6-GiB guest")


def vm_sample(work, process, qmp):
    """Only numeric counters and QMP device state; never export private config."""
    result = {"unix_time": time.time(), "host": host_resources(work)}
    if process is not None:
        result["qemu_exit_code"] = process.poll()
        try:
            fields = Path(f"/proc/{process.pid}/stat").read_text().rsplit(")", 1)[1].split()
            result["qemu_cpu_seconds"] = (int(fields[11]) + int(fields[12])) / os.sysconf("SC_CLK_TCK")
            result["qemu_threads"] = int(fields[17])
            result["qemu_rss_bytes"] = int(fields[21]) * os.sysconf("SC_PAGE_SIZE")
            result["qemu_io"] = {key: int(value) for key, value in
                (line.split(":", 1) for line in Path(f"/proc/{process.pid}/io").read_text().splitlines())}
        except (OSError, ValueError, IndexError):
            pass
    disk = work / "windows.qcow2"
    if disk.exists():
        info = disk.stat()
        result["disk_allocated_bytes"] = info.st_blocks * 512
        result["disk_file_bytes"] = info.st_size
    if qmp is not None:
        for command in ("query-status", "query-blockstats"):
            try:
                raw = qmp.execute(command)
                if command == "query-status":
                    result["qmp_status"] = {name: raw[name] for name in ("running", "status", "singlestep") if name in raw}
                else:
                    result["blockstats"] = [{"device": row.get("device"), "stats": {
                        key: value for key, value in row.get("stats", {}).items()
                        if type(value) in (int, float, bool)}} for row in raw]
            except (OSError, ValueError, RuntimeError) as exc:
                result[command + "_error_type"] = type(exc).__name__
    return result


def verify_package(package: Path, expected: str):
    if len(expected) != 64 or any(c not in "0123456789abcdef" for c in expected) or media.digest(package) != expected:
        raise ValueError("Native product package SHA-256 mismatch")
    required = {"RuleProxy-Web/python/python.exe", "RuleProxy-Web/package-manifest.json",
                "RuleProxy-Web/ruleproxy/windows_proxy_service.py", "RuleProxy-Web/scripts/windows-setup.ps1"}
    with zipfile.ZipFile(package) as archive:
        names = archive.namelist()
        if not required.issubset(names) or len({name.casefold() for name in names}) != len(names):
            raise ValueError("Invalid native product package layout")
        total = 0
        for item in archive.infolist():
            name = item.filename
            path = PurePosixPath(name)
            total += item.file_size
            if (path.is_absolute() or ".." in path.parts or "\\" in name or ":" in name
                    or not path.parts or path.parts[0] != "RuleProxy-Web"
                    or item.orig_filename != name or stat.S_ISLNK(item.external_attr >> 16)
                    or total > 512 * 1024**2):
                raise ValueError("Unsafe native product package path")


def make_payload(package: Path, destination: Path):
    with zipfile.ZipFile(destination, "w", compression=zipfile.ZIP_DEFLATED) as archive:
        archive.write(package, "package/" + package.name)
        archive.writestr("package/SHA256SUMS.txt", media.digest(package) + "  " + package.name + "\n")
        for folder in (".github", "ruleproxy"):
            for path in sorted((ROOT / folder).rglob("*.py")):
                if "__pycache__" not in path.parts and path.is_file() and not path.is_symlink():
                    archive.write(path, path.relative_to(ROOT).as_posix())
    return media.digest(destination)


def verify_result(result, *, package_sha256=None):
    if not isinstance(result, dict):
        raise RuntimeError("Native Windows product result must be an object")
    try:
        if len(json.dumps(result, ensure_ascii=True).encode("ascii")) > MAX_GUEST_RESULT_BYTES:
            raise RuntimeError("Native Windows product result exceeds its 8 MiB limit")
    except (TypeError, ValueError) as exc:
        raise RuntimeError("Native Windows product result is not JSON data") from exc
    reports = result.get("reports", {})
    if not isinstance(reports, dict) or not isinstance(reports.get("product"), dict):
        raise RuntimeError("Native Windows product report must be an object")
    report = reports["product"]
    os_info = result.get("os", {})
    actual = report.get("actual_os", {})
    if (not isinstance(os_info, dict) or not isinstance(actual, dict)
            or result.get("status") != "passed" or type(result.get("exit_code")) is not int or result["exit_code"] != 0
            or os_info.get("product_type") != "WinNT" or os_info.get("native_architecture") != "AMD64"
            or type(os_info.get("build")) is not int or os_info["build"] < 22000
            or actual.get("product_type") != 1 or type(actual.get("product_type")) is not int
            or actual.get("architecture") != "AMD64" or actual.get("major") != 10
            or type(actual.get("build")) is not int or actual["build"] != os_info["build"]
            or report.get("status") not in {"passed_server_product_qualification", "passed_windows_11_product_qualification"}
            or report.get("hosts_restored") is not True or result.get("user_cleanup_confirmed") is not True):
        raise RuntimeError("Native Windows 11 installed product evidence is incomplete")
    checks = report.get("checks", {})
    user = report.get("ordinary_suite", {})
    identities = report.get("source_matches_bundle", {})
    package = report.get("package", {})
    receiver = report.get("receiver_phase_evidence", [])
    user_checks = user.get("checks", {}) if isinstance(user, dict) else None
    if (not all(isinstance(value, dict) for value in (checks, user, identities, package, user_checks))
            or not isinstance(receiver, list) or any(not isinstance(row, dict) for row in receiver)
            or checks.get("install_and_reinstall") is not True
            or checks.get("uninstall_preserves_user_state_and_shared_driver") is not True
            or user.get("status") != "passed" or user.get("is_elevated") is not False
            or user.get("panel_is_elevated") is not False
            or not isinstance(identities, dict) or set(identities) != SOURCE_IDENTITIES
            or not all(value is True for value in identities.values())
            or package.get("manifest_verified") is not True
            or (package_sha256 is not None and package.get("sha256") != package_sha256)
            or not receiver or not all(row.get("passed") is True for row in receiver)
            or not {"suite_ordinary", "panel_ordinary", "installed_package_loaded", "holder_ordinary"}.issubset(user_checks)
            or not all(value is True for value in user_checks.values())):
        raise RuntimeError("Native Windows product lifecycle checks are missing")
    launcher = report.get("ordinary_launcher", {})
    session = result.get("actor_session_id")
    if (not isinstance(launcher, dict)
            or launcher.get("method") != "WTSQueryUserToken+CreateProcessAsUserW"
            or type(session) is not int or session <= 0
            or type(launcher.get("session_id")) is not int or launcher["session_id"] != session
            or type(user.get("interactive_session_id")) is not int or user["interactive_session_id"] != session
            or not VISIBLE_GUI_CHECKS.issubset(user_checks)
            or not all(user_checks[name] is True for name in VISIBLE_GUI_CHECKS)
            or report.get("gui_verified") is not True
            or user.get("visible_gui_local_checks_passed") is not True
            or not any(row.get("label") == "real_edge_visible" and row.get("passed") is True for row in receiver)):
        raise RuntimeError("Native Windows interactive session and visible browser evidence is incomplete")
    visible_screenshot_bytes(report)
    return report


def cleanup_owned(qmp, qemu, tpm, server, thread, private_directory):
    """Stop VM users of the private disk/ISO/password before deleting them."""
    errors = []
    actions = [("qmp", lambda: qmp.close())] if qmp is not None else []
    actions += [("qemu", lambda: media.stop_owned(qemu)), ("tpm", lambda: media.stop_owned(tpm))]
    if server is not None:
        actions += [("server_shutdown", server.shutdown), ("server_close", server.server_close)]
    if thread is not None:
        actions.append(("server_thread", lambda: thread.join(timeout=5)))
    for name, action in actions:
        try:
            action()
        except Exception as exc:
            errors.append({"stage": name, "error_type": type(exc).__name__})
    # A live VM may still hold secrets or mutate its disk. Keep the private work
    # tree available for termination rather than unlinking it underneath QEMU.
    live = any(process is not None and process.poll() is None for process in (qemu, tpm))
    if private_directory is not None and not live:
        try:
            shutil.rmtree(private_directory)
        except OSError as exc:
            errors.append({"stage": "private_directory", "error_type": type(exc).__name__})
    elif live:
        errors.append({"stage": "private_directory", "error_type": "OwnedProcessStillRunning"})
    return errors


def run(args):
    artifacts = args.artifacts.resolve()
    artifacts.mkdir(parents=True, exist_ok=True)
    summary = {"schema_version": 2, "status": "running", "scope": "native Windows 11 x64 final offline product",
               "native_windows_11_product_passed": False, "real_exit_ip_verified": False,
               "gui_verified": False, "linux_equivalent_isolation": False,
               "iso": {"url": media.ISO_URL, "sha256": media.ISO_SHA256, "bytes": media.ISO_BYTES},
               "cumulative_update_required": False,
               "update_scope": "The selected proxy backend does not require the former MXC build contract."}
    summary["vm_configuration"] = {"machine": "q35,accel=kvm,smm=on", "vcpu": 4, "ram_mib": 6144,
        "disk_controller": "q35 built-in AHCI/SATA (ide-hd on ide.0)", "disk_virtual_gib": 80,
        "installer_dynamic_update": False, "secure_boot": True, "tpm": "2.0"}
    server = thread = qemu = tpm = qmp = private_directory = work = None
    overall_started = time.monotonic()
    def stage(name):
        summary["elapsed_total_seconds"] = round(time.monotonic() - overall_started, 2)
        persist_summary(artifacts, summary, name)
    stage("host_preflight")
    try:
        summary["kvm_api_version"] = media.require_kvm()
        summary["host_preflight"] = host_resources(Path(tempfile.gettempdir()))
        stage("host_resources_recorded")
        check_host_resources(summary["host_preflight"])
        package = args.package.resolve(strict=True)
        verify_package(package, args.package_sha256)
        summary["package_sha256"] = args.package_sha256
        extractor = shutil.which("7zz") or shutil.which("7z")
        for binary in ("qemu-system-x86_64", "qemu-img", "swtpm", "xorriso", "curl"):
            if not shutil.which(binary):
                raise RuntimeError("Missing native VM dependency: " + binary)
        if not extractor:
            raise RuntimeError("Missing UDF extractor")
        summary["qemu_version"] = subprocess.run(["qemu-system-x86_64", "--version"],
            capture_output=True, text=True, check=True, timeout=5).stdout.splitlines()[0]
        firmware = Path("/usr/share/OVMF")
        code, variables = firmware / "OVMF_CODE_4M.ms.fd", firmware / "OVMF_VARS_4M.ms.fd"
        if not code.is_file() or not variables.is_file():
            raise RuntimeError("Microsoft Secure Boot firmware is missing")
        private_directory = Path(tempfile.mkdtemp(prefix="ruleproxy-proxifyre-win11-"))
        directory = str(private_directory)
        work = Path(directory)
        work.chmod(0o700)
        if shutil.disk_usage(work).free < media.MIN_FREE_BYTES:
            raise RuntimeError("At least 55 GiB free is required for official Windows media")
        iso = work / "official.iso"
        stage("official_iso_download")
        subprocess.run(["curl", "--fail", "--location", "--retry", "3", "--retry-all-errors",
            "--connect-timeout", "30", "--max-time", "1200", "--proto", "=https", "--proto-redir", "=https",
            "--output", str(iso), media.ISO_URL], check=True, timeout=1220)
        if iso.stat().st_size != media.ISO_BYTES or media.digest(iso) != media.ISO_SHA256:
            raise RuntimeError("Official Windows media size or hash mismatch")
        summary["iso"]["verified"] = True
        stage("official_iso_verified")
        payload = work / "payload.zip"
        payload_hash = make_payload(package, payload)
        server = media.GuestServer(payload, artifacts)
        thread = threading.Thread(target=server.serve_forever, daemon=True)
        thread.start()
        tree = work / "iso-tree"
        tree.mkdir()
        stage("official_iso_extract")
        subprocess.run([extractor, "x", "-tudf", "-y", f"-o{tree}", str(iso)], check=True, timeout=900)
        efi_boot = media.validate_install_tree(tree)
        password = secrets.token_hex(16) + "Ci!9"
        xml = (ROOT / ".github/windows-vm-unattend.xml").read_text().replace("@PASSWORD@", password)
        ET.fromstring(xml)
        (tree / "autounattend.xml").write_text(xml, encoding="utf-8")
        for name, destination in (("windows-proxifyre-vm-setup.ps1", "ruleproxy-vm-setup.ps1"),
                                  ("windows-proxifyre-vm-run.ps1", "ruleproxy-vm-run.ps1")):
            (tree / destination).write_text((ROOT / ".github" / name).read_text(), encoding="utf-8-sig")
        media.write_json(tree / "ruleproxy-vm-config.json", {
            "host_url": f"http://10.0.2.2:{server.server_address[1]}/{server.capability}",
            "payload_sha256": payload_hash, "package_sha256": args.package_sha256})
        unattended = work / "unattended.iso"
        stage("unattended_iso_build")
        subprocess.run(["xorriso", "-as", "mkisofs", "-iso-level", "3", "-J", "-joliet-long", "-R", "-V", "RULEPROXY_CI",
            "-b", "boot/etfsboot.com", "-no-emul-boot", "-boot-load-size", "8", "-boot-info-table",
            "-eltorito-alt-boot", "-e", efi_boot, "-no-emul-boot", "-o", str(unattended), str(tree)], check=True)
        summary["remastered_iso"] = media.installer_layout(unattended)
        stage("unattended_iso_verified")
        shutil.rmtree(tree)
        iso.unlink()
        disk, nvram = work / "windows.qcow2", work / "OVMF_VARS.fd"
        subprocess.run(["qemu-img", "create", "-f", "qcow2", str(disk), "80G"], check=True)
        shutil.copyfile(variables, nvram)
        state = work / "tpm-state"
        state.mkdir()
        tpm_socket, qmp_socket = work / "tpm.sock", work / "qmp.sock"
        stage("vm_start")
        with (artifacts / "swtpm.log").open("wb") as tpm_log, (artifacts / "qemu.log").open("wb") as qemu_log:
            tpm = subprocess.Popen(["swtpm", "socket", "--tpm2", "--tpmstate", f"dir={state}",
                "--ctrl", f"type=unixio,path={tpm_socket}"], stdout=tpm_log, stderr=subprocess.STDOUT)
            deadline = time.monotonic() + 20
            while not tpm_socket.exists():
                if tpm.poll() is not None or time.monotonic() > deadline:
                    raise RuntimeError("Software TPM failed")
                time.sleep(.1)
            command = ["qemu-system-x86_64", "-machine", "q35,accel=kvm,smm=on", "-cpu",
                "host,hv-relaxed=on,hv-vapic=on,hv-spinlocks=0x1fff,hv-time=on", "-m", "6144", "-smp", "4",
                "-global", "driver=cfi.pflash01,property=secure,value=on",
                "-drive", f"if=pflash,format=raw,readonly=on,file={code}", "-drive", f"if=pflash,format=raw,file={nvram}",
                "-drive", f"if=none,id=system,file={disk},format=qcow2,discard=unmap", "-device", "ide-hd,drive=system,bus=ide.0,bootindex=1",
                "-drive", f"if=none,id=install,file={unattended},media=cdrom,readonly=on", "-device", "ide-cd,drive=install,bus=ide.1,bootindex=2",
                "-netdev", "user,id=vmnet", "-device", f"e1000,netdev=vmnet,mac={media.VM_NIC_MAC}",
                "-chardev", f"socket,id=tpm,path={tpm_socket}", "-tpmdev", "emulator,id=tpmdev,chardev=tpm", "-device", "tpm-tis,tpmdev=tpmdev",
                "-device", "qemu-xhci", "-device", "usb-tablet", "-vga", "std", "-display", "none", "-monitor", "none",
                "-serial", f"file:{artifacts / 'serial.log'}", "-qmp", f"unix:{qmp_socket},server=on,wait=off"]
            qemu = subprocess.Popen(command, stdin=subprocess.DEVNULL, stdout=qemu_log, stderr=subprocess.STDOUT)
            deadline = time.monotonic() + 20
            while qmp is None:
                if qemu.poll() is not None or time.monotonic() > deadline:
                    raise RuntimeError("KVM VM failed to start")
                try:
                    qmp = media.Qmp(qmp_socket)
                except OSError:
                    time.sleep(.1)
            if qmp.execute("query-kvm").get("enabled") is not True:
                raise RuntimeError("KVM required; software CPU emulation refused")
            summary["qemu_kvm_enabled"] = True
            try:
                cpus = qmp.execute("query-cpus-fast")
                summary["actual_guest_vcpus"] = [{"index": cpu.get("cpu-index"), "host_thread_id": cpu.get("thread-id")}
                                                  for cpu in cpus]
            except (OSError, ValueError, RuntimeError) as exc:
                summary["guest_vcpu_query_error_type"] = type(exc).__name__
            stage("vm_kvm_confirmed")
            if efi_boot.endswith("/efisys.bin"):
                for _ in range(8):
                    qmp.execute("send-key", {"keys": [{"type": "qcode", "data": "ret"}], "hold-time": 100})
                    time.sleep(2)
            started = time.monotonic()
            (artifacts / "screenshots").mkdir(exist_ok=True)
            stage("guest_installation_or_qualification_wait")
            while not server.received.is_set():
                sample = vm_sample(work, qemu, qmp)
                sample["vm_elapsed_seconds"] = int(time.monotonic() - started)
                try:
                    media.screenshot(qmp, work / "screen.ppm", artifacts / "last-screen.png")
                    sample["screen_sha256"] = hashlib.sha256((artifacts / "last-screen.png").read_bytes()).hexdigest()
                    # Retain a bounded timeline rather than only the last overwritten frame.
                    bucket = int(sample["vm_elapsed_seconds"] // 300)
                    timeline = artifacts / "screenshots" / f"vm-{bucket * 300:05d}s.png"
                    if not timeline.exists():
                        shutil.copyfile(artifacts / "last-screen.png", timeline)
                except (OSError, ValueError, RuntimeError) as exc:
                    sample["screenshot_error_type"] = type(exc).__name__
                with (artifacts / "vm-samples.jsonl").open("a", encoding="ascii") as stream:
                    stream.write(json.dumps(sample, ensure_ascii=True) + "\n")
                summary["latest_vm_sample"] = sample
                stage("guest_installation_or_qualification_wait")
                if qemu.poll() is not None or time.monotonic() - overall_started > args.timeout_seconds:
                    raise RuntimeError("Native Windows installation/product qualification did not finish within its budget")
                if shutil.disk_usage(work).free < 5 * 1024**3:
                    raise RuntimeError("VM disk safety reserve reached")
                print(f"Native Windows product VM: {int(time.monotonic() - started)} s", flush=True)
                server.received.wait(30)
            stage("guest_result_received")
            report = verify_result(server.result, package_sha256=args.package_sha256)
            screenshot = visible_screenshot_bytes(report)
            (artifacts / "visible-edge.png").write_bytes(screenshot)
            media.write_json(artifacts / "native-product-report.json", report)
            summary.update(status="passed", native_windows_11_product_passed=True,
                           gui_verified=True, interactive_session_id=server.result["actor_session_id"],
                           visible_edge_screenshot={"file": "visible-edge.png", "bytes": len(screenshot),
                                                    "sha256": hashlib.sha256(screenshot).hexdigest()},
                           os=server.result["os"], elapsed_seconds=int(time.monotonic() - started))
    except QualificationInterrupted as exc:
        summary.update(status="cancelled", native_windows_11_product_passed=False,
                       cancellation_signal=signal.Signals(exc.signum).name,
                       stop_reason="Controller/runner cancellation; no product failure is inferred.")
        stage("cancelled")
        # Ask owned children to exit immediately; do not spend cancellation grace
        # waiting on additional QMP commands or screenshots.
        for process in (qemu, tpm):
            if process is not None and process.poll() is None:
                try:
                    process.terminate()
                except OSError:
                    pass
    except Exception as exc:
        summary["status"] = "failed"
        summary["failure_phase"] = summary["phase"]
        summary["error"] = type(exc).__name__ + ": " + str(exc)
        print("::error title=Native Windows product::" + summary["error"], flush=True)
    finally:
        summary["product_execution_confirmed"] = bool(server is not None and isinstance(server.result, dict)
            and isinstance(server.result.get("reports", {}).get("product"), dict))
        summary["phase_before_cleanup"] = summary["phase"]
        stage("cleanup")
        cleanup_errors = cleanup_owned(qmp, qemu, tpm, server, thread, private_directory)
        if cleanup_errors:
            summary.update(status="failed", native_windows_11_product_passed=False, cleanup_errors=cleanup_errors)
        stage("finished")
    return summary


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--package", type=Path, required=True)
    parser.add_argument("--package-sha256", required=True)
    parser.add_argument("--artifacts", type=Path, required=True)
    parser.add_argument("--timeout-seconds", type=int, default=2700)
    args = parser.parse_args()
    if not 300 <= args.timeout_seconds <= 3600:
        parser.error("VM execution budget must be 300–3600 seconds")
    with cancellation_signals():
        return 0 if run(args)["status"] == "passed" else 1


if __name__ == "__main__":
    raise SystemExit(main())
