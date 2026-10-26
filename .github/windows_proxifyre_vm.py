"""Qualify the installed product in a fixed official Windows 11 x64 KVM VM.

The product, compartment, global-capture and PSEC smoke suites are separate.
The PSEC smoke establishes functionality only, never product/privacy acceptance.
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
import re
import shutil
import signal
import stat
import struct
import subprocess
import sys
import tempfile
import threading
import time
import uuid
import xml.etree.ElementTree as ET
import zipfile

ROOT = Path(__file__).resolve().parent.parent
_spec = importlib.util.spec_from_file_location("ruleproxy_vm_media", ROOT / ".github/windows_vm_test.py")
media = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(media)

# A separate, fixed baseline for the PSEC experiment. Never silently change
# the media used by product, compartment or existing serviced-25H2 tests.
PSEC_26H2_MEDIA = {
    "url": "https://software-static.download.prss.microsoft.com/dbazure/"
           "26300.9457.260913-1737.26h2_ge_release_svc_refresh_CLIENTENTERPRISEEVAL_OEMRET_x64FRE_en-us.iso",
    "sha256": "bc3f24086ebadc94489066b5ad78089e2cf5c3491e90e790bb81a2b199c10e38",
    "bytes": 8_225_329_152,
    "download_page": "https://www.microsoft.com/en-us/evalcenter/download-windows-11-enterprise",
    "hash_source": "https://support.microsoft.com/en-us/servicing/os/windows/docs/2026/09/"
                   "verify-the-authenticity-of-a-windows-11-enterprise-evaluation-iso-file",
    "build": 26300,
    "ubr": 9457,
}


def selected_install_media(suite, psec_media):
    if psec_media not in {"serviced-25h2", "26h2"}:
        raise ValueError("Unknown fixed PSEC media profile")
    if psec_media == "26h2":
        if suite != "psec-compartment-smoke":
            raise ValueError("The 26H2 baseline is limited to the PSEC experiment")
        return dict(PSEC_26H2_MEDIA)
    return {"url": media.ISO_URL, "sha256": media.ISO_SHA256, "bytes": media.ISO_BYTES}


# Must equal the product acceptance controller's compared source list.
SOURCE_IDENTITIES = frozenset({"manager.py", "server.py", "launcher.py", "windows_proxy_service.py",
    "windows_proxy_policy.py", "windows_proxy_client.py", "windows_proxy_runtime.py",
    "windows_proxy_pins.py", "windows_app_process.py", "windows_core_process.py",
    "windows_appcontainer.py"})
GLOBAL_SOURCE_IDENTITIES = frozenset({"ruleproxy/windows_proxy_service.py", "ruleproxy/windows_global_guard.py",
    "ruleproxy/windows_global_dns.py", "ruleproxy/windows_global_runtime.py", "ruleproxy/global_runtime.py",
    "ruleproxy/windows_global_qualification.py", "ruleproxy/windows_app_process.py",
    "ruleproxy/config.py", "ruleproxy/manager.py", "web/app.js"})
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


def make_payload(package: Path, destination: Path, *, include_global_sources=False, psec_bundle=None):
    if psec_bundle is not None:
        # Explicit file input only; no ambient cache or mutable download pin.
        sys.path.insert(0, str(ROOT))
        import install_runtime
        data = install_runtime._g_bundle_bytes(Path(psec_bundle), allow_env_cache=False)
        with tempfile.TemporaryDirectory() as temporary:
            install_runtime._extract_g_bundle(data, Path(temporary))
    with zipfile.ZipFile(destination, "w", compression=zipfile.ZIP_DEFLATED) as archive:
        archive.write(package, "package/" + package.name)
        archive.writestr("package/SHA256SUMS.txt", media.digest(package) + "  " + package.name + "\n")
        if psec_bundle is not None:
            archive.writestr("psec/mxc-g-runtime-bundle.zip", data)
        for folder in (".github", "ruleproxy"):
            for path in sorted((ROOT / folder).rglob("*.py")):
                if "__pycache__" not in path.parts and path.is_file() and not path.is_symlink():
                    archive.write(path, path.relative_to(ROOT).as_posix())
        # The installed ordinary-user controller verifies and imports this
        # exact shared probe. Keep it out of the product ZIP, but include it in
        # the disposable guest workspace without copying the whole test suite.
        probe = ROOT / "tests/test_windows_native_proxy.py"
        if not probe.is_file() or probe.is_symlink():
            raise ValueError("Native proxy probe source is missing or unsafe")
        archive.write(probe, "tests/test_windows_native_proxy.py")
        if include_global_sources:
            present = set(archive.namelist())
            for name in sorted(GLOBAL_SOURCE_IDENTITIES - present):
                archive.write(ROOT / name, name)
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


def verify_compartment_lab_result(result, *, package_sha256):
    """Attest completion of an experiment, never promote it to isolation qualification."""
    if not isinstance(result, dict):
        raise RuntimeError("Compartment guest result must be an object")
    if len(json.dumps(result, ensure_ascii=True).encode("ascii")) > MAX_GUEST_RESULT_BYTES:
        raise RuntimeError("Compartment guest result exceeds its bound")
    facts, report = result.get("os", {}), result.get("reports", {}).get("compartment")
    if (not isinstance(facts, dict) or not isinstance(report, dict)
            or result.get("status") != "passed" or result.get("suite") != "compartment-lab"
            or result.get("exit_code") != 0
            or type(result.get("exit_code")) is not int
            or facts.get("product_type") != "WinNT" or facts.get("native_architecture") != "AMD64"
            or type(facts.get("build")) is not int or facts["build"] < 22000
            or result.get("package_sha256") != package_sha256
            or report.get("product_qualified") is not False or report.get("error") is not None
            or not isinstance(report.get("source_commit"), str)
            or not re.fullmatch(r"[a-f0-9]{40}", report["source_commit"])
            or not isinstance(report.get("assessment"), dict)):
        raise RuntimeError("Native Windows 11 compartment experiment evidence is incomplete")
    return report


def verify_psec_smoke_result(result, *, package_sha256, source_commit, psec_media="serviced-25h2"):
    """Verify this functional experiment without promoting privacy/GUI claims."""
    if (not isinstance(result, dict)
            or len(json.dumps(result, ensure_ascii=True).encode("ascii")) > MAX_GUEST_RESULT_BYTES):
        raise RuntimeError("Invalid PSEC smoke result")
    facts = result.get("os", {})
    reports = result.get("reports", {})
    report = reports.get("psec_smoke") if isinstance(reports, dict) else None
    if (not isinstance(facts, dict) or not isinstance(report, dict)
            or result.get("suite") != "psec-compartment-smoke" or result.get("status") != "passed"
            or type(result.get("exit_code")) is not int or result["exit_code"] != 0
            or result.get("package_sha256") != package_sha256
            or facts.get("product_type") != "WinNT" or facts.get("native_architecture") != "AMD64"
            or type(facts.get("build")) is not int or facts["build"] < 26100
            or report.get("source_commit") != source_commit
            or report.get("privacy_qualified") is not False or report.get("product_acceptance") is not False
            or report.get("functionality_passed") is not True or report.get("browser_requested") is not True
            or report.get("error") is not None
            or type(report.get("launcher_exit_code")) is not int or report["launcher_exit_code"] != 0
            or report.get("launcher_timed_out") is not False):
        raise RuntimeError("PSEC/compartment functional evidence is incomplete")
    spec = importlib.util.spec_from_file_location("psec_smoke_validation", ROOT / ".github/windows_psec_compartment_smoke.py")
    smoke = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(smoke)
    checks = smoke.checks(report)
    if not checks or report.get("checks") != checks or any(value is not True for value in checks.values()):
        raise RuntimeError("PSEC/compartment observations do not establish functionality")
    sys.path.insert(0, str(ROOT))
    from ruleproxy import windows_runtime_pins as pins
    provenance = report.get("provenance", {})
    actual_os = report.get("os", {})
    if (not isinstance(provenance, dict)
            or provenance.get("executor_sha256") != pins.MXC_G_EXECUTOR_SHA256
            or provenance.get("upstream_commit") != pins.MXC_G_BUILD_MANIFEST["upstream_commit"]
            or provenance.get("g_patch_applies_to_model2") is not False):
        raise RuntimeError("PSEC executor provenance differs from the fixed experiment")
    if (not isinstance(actual_os, dict) or actual_os.get("architecture") != "AMD64"
            or actual_os.get("python_pointer_bits") != 64 or actual_os.get("build") != facts["build"]
            or type(actual_os.get("ubr")) is not int or actual_os["ubr"] != facts.get("ubr")):
        raise RuntimeError("PSEC process OS facts differ from the Windows guest")
    if psec_media == "26h2":
        baseline = result.get("install_media", {})
        expected = {"profile": "26h2", "iso_sha256": PSEC_26H2_MEDIA["sha256"],
                    "actual_build": PSEC_26H2_MEDIA["build"], "actual_ubr": PSEC_26H2_MEDIA["ubr"]}
        if (baseline != expected or result.get("official_update") is not None
                or facts["build"] != expected["actual_build"] or facts["ubr"] != expected["actual_ubr"]):
            raise RuntimeError("PSEC smoke did not run the fixed 26H2 installation baseline")
        return report
    if psec_media != "serviced-25h2":
        raise RuntimeError("Unknown PSEC result media profile")
    update = result.get("official_update", {})
    if (not isinstance(update, dict) or update.get("status") != "completed"
            or any(update.get(key) is not True for key in ("completed", "packages_verified", "task_unregistered"))
            or update.get("reboot_required") is not False
            or facts["build"] != media.UPDATE_BUILD or facts.get("ubr", -1) < media.UPDATE_UBR
            or update.get("actual_build") != facts["build"] or update.get("actual_ubr") != facts["ubr"]):
        raise RuntimeError("PSEC smoke did not prove the required official servicing")
    return report


def global_source_identity():
    commit = subprocess.run(["git", "rev-parse", "HEAD"], cwd=ROOT, check=True,
                            capture_output=True, text=True, timeout=5).stdout.strip()
    if len(commit) != 40 or any(char not in "0123456789abcdef" for char in commit):
        raise RuntimeError("Missing global capture checkout identity")
    return {"tested_source_commit": commit,
            "source_sha256": {name: media.digest(ROOT / name) for name in sorted(GLOBAL_SOURCE_IDENTITIES)},
            "harness_sha256": media.digest(ROOT / ".github/check_windows_global_capture.py")}


def verify_global_result(result, *, package_sha256, source_identity):
    """Accept only the bounded capture experiment, never product qualification."""
    if not isinstance(result, dict) or len(json.dumps(result).encode("utf-8")) > MAX_GUEST_RESULT_BYTES:
        raise RuntimeError("Invalid or oversized Windows global result")
    if not isinstance(result.get("reports"), dict):
        raise RuntimeError("Native Windows global reports are missing")
    report = result["reports"].get("global_capture", {})
    os_info, owner, package = result.get("os", {}), result.get("owner", {}), result.get("package", {})
    if (not all(isinstance(value, dict) for value in (report, os_info, owner, package))
            or result.get("suite") != "global-capture" or result.get("status") != "passed"
            or type(result.get("exit_code")) is not int or result["exit_code"] != 0
            or any(result.get(name) is not True for name in ("user_cleanup_confirmed", "task_cleanup_confirmed",
                                                           "installation_cleanup_confirmed"))
            or os_info.get("product_type") != "WinNT" or os_info.get("native_architecture") != "AMD64"
            or type(os_info.get("build")) is not int or os_info["build"] < 22000
            or owner.get("elevated") is not True or owner.get("sid_matches_installation") is not True
            or not isinstance(owner.get("sid"), str) or not re.fullmatch(r"S-1-5-21-(?:\d+-){3}\d+", owner["sid"])
            or package.get("manifest_verified") is not True or package.get("sha256") != package_sha256
            or result.get("source_identity") != source_identity):
        raise RuntimeError("Native Windows 11 global identity or cleanup evidence is incomplete")
    if not all(isinstance(report.get(name), dict) for name in
               ("recovery", "ipv6_scoped_action", "tun_identity", "guard_after_service_death")):
        raise RuntimeError("Native Windows global stage evidence is missing")
    if (report.get("mode") != "disposable_windows_native_capture" or report.get("passed") is not True
            or report.get("strict_qualified") is not False or report.get("raw_capture_exported") is not False
            or any(report.get(name) is not False for name in
                   ("ipv6_public_egress_qualified", "dns_qualified", "rdp_qualified"))
            or any(report.get(name) is not True for name in ("ipv4_physical_scope_passed",
                "tun_tcp_udp_v4_v6_passed", "explicit_global_stop", "system_core_carrier_http"))
            or report.get("recovery", {}).get("recovered") is not True
            or report.get("ipv6_scoped_action", {}).get("passed") is not True
            or report.get("tun_identity", {}).get("identity_matches") is not True
            or report.get("tun_identity", {}).get("start_guard_tun_ready") is not True
            or report.get("guard_after_service_death", {}).get("active") is not True
            or report.get("guard_after_service_death", {}).get("persistent") is not True
            or report.get("windows_build") != [10, 0, os_info["build"]]
            or report.get("fixed_core_sha256") != package.get("fixed_core_sha256")
            or report.get("guard_source_sha256") != source_identity["source_sha256"]["ruleproxy/windows_global_guard.py"]
            or report.get("task_cleanup_errors")):
        raise RuntimeError("Native Windows global capture or precise recovery evidence is incomplete")
    phases = report.get("phases")
    if not isinstance(phases, dict):
        raise RuntimeError("Native Windows global physical phases are missing")
    declared = report.get("components", {}).get("capture_components") if isinstance(report.get("components"), dict) else None
    if (not isinstance(declared, list) or not 1 <= len(declared) <= 4
            or any(type(item) is not int or not 0 < item <= 0xffffffff for item in declared)
            or declared != sorted(set(declared))):
        raise RuntimeError("Native Windows global capture component identities are missing")
    allowed_errors = {13, 110, 111, 10013, 10060, 10061}
    for name in ("outside_before", "running_guard", "core_dead", "service_stopped", "outside_after"):
        phase = phases.get(name)
        if not isinstance(phase, dict):
            raise RuntimeError("Native Windows global physical phase is missing: " + name)
        positive = name in {"outside_before", "outside_after"}
        if any(type(phase.get(key)) is not int or phase[key] < 0
               or (phase[key] == 0 if positive else phase[key] != 0) for key in ("tcp_syn", "udp_marker")):
            raise RuntimeError("Native Windows global physical controls or denials disagree: " + name)
        etl_count, components = phase.get("etl_count"), phase.get("components")
        if (phase.get("declared_components") != declared or type(etl_count) is not int or not 1 <= etl_count <= 4
                or not isinstance(components, dict) or set(components) != {str(item) for item in declared}):
            raise RuntimeError("Native Windows global component conversions are incomplete: " + name)
        totals, captures = dict.fromkeys(("tcp_syn", "udp_marker", "packets_parsed"), 0), []
        for component in declared:
            value = components[str(component)]
            if (not isinstance(value, dict) or any(type(value.get(key)) is not int or value[key] < 0 for key in totals)
                    or value["packets_parsed"] < value["tcp_syn"] + value["udp_marker"]
                    or (not positive and (value["tcp_syn"] != 0 or value["udp_marker"] != 0))
                    or not isinstance(value.get("captures"), list) or len(value["captures"]) != etl_count
                    or any(not isinstance(row, dict) or set(row) != {"sha256", "bytes"}
                           or type(row.get("bytes")) is not int or row["bytes"] <= 0
                           or not isinstance(row.get("sha256"), str) or not re.fullmatch("[0-9a-f]{64}", row["sha256"])
                           for row in value["captures"])
                    or sum(row["bytes"] for row in value["captures"]) > 64 * 1024**2):
                raise RuntimeError("Native Windows global component evidence is incomplete: " + name)
            for key in totals:
                totals[key] += value[key]
            captures.extend({"component": component, **row} for row in value["captures"])
        if (any(type(phase.get(key)) is not int or phase[key] != total for key, total in totals.items())
                or phase.get("captures") != captures):
            raise RuntimeError("Native Windows global capture receipts are incomplete: " + name)
        diagnostics = phase.get("capture_diagnostics")
        if (not isinstance(diagnostics, dict) or diagnostics.get("declared_components") != declared
                or diagnostics.get("component_results") != components or phase.get("capture_loss_verified") is not True):
            raise RuntimeError("Native Windows global capture diagnostics are incomplete: " + name)
        buffer_info, restore = diagnostics.get("buffer_info"), diagnostics.get("restore")
        metadata = restore.get("cli_metadata") if isinstance(restore, dict) else None
        stopped = metadata.get("stop") if isinstance(metadata, dict) else None
        if (not isinstance(buffer_info, dict) or any(type(buffer_info.get(key)) is not int or buffer_info[key] != 0
                for key in ("events_lost", "buffers_lost")) or not isinstance(restore, dict)
                or restore.get("stopped") is not True or not isinstance(stopped, dict)
                or type(stopped.get("final_events_lost")) is not int or stopped["final_events_lost"] != 0
                or stopped.get("log_parent_is_private_run_directory") is not True
                or stopped.get("log_matches_owned_prefix") is not True):
            raise RuntimeError("Native Windows global capture loss or stop ownership is unconfirmed: " + name)
        actors = phase.get("actor")
        if not isinstance(actors, dict):
            raise RuntimeError("Native Windows global actors are missing: " + name)
        for protocol in ("tcp", "udp"):
            actor = actors.get(protocol)
            if (not isinstance(actor, dict) or actor.get("executed") is not True
                    or actor.get("stage") not in {"connect", "send"}
                    or not (actor.get("socket_ok") is True or
                            (type(actor.get("error")) is int and actor["error"] in allowed_errors))):
                raise RuntimeError("Native Windows global probe execution is unconfirmed: " + name)
    echoes, counts = report.get("tun_echo"), report.get("synthetic_node_counts")
    if not isinstance(echoes, dict) or not isinstance(counts, dict):
        raise RuntimeError("Native Windows global synthetic receivers are missing")
    for family in ("4", "6"):
        if not isinstance(echoes.get(family), dict):
            raise RuntimeError("Native Windows global TUN family is missing")
        for protocol in ("tcp", "udp"):
            row, count = echoes[family].get(protocol), counts.get(protocol + family)
            if (not isinstance(row, dict) or any(row.get(key) is not True
                    for key in ("executed", "received_echo", "socket_ok")) or row.get("stage") != "send"
                    or type(count) is not int or count <= 0):
                raise RuntimeError("Native Windows global TUN receiver evidence is incomplete")
    identity = report["tun_identity"]
    expected_guid = str(uuid.UUID(bytes_le=hashlib.md5(b"wintunRuleProxyTun").digest()))
    if (identity.get("alias") != "RuleProxyTun" or identity.get("expected_guid") != expected_guid
            or identity.get("interface_guid") != expected_guid
            or type(identity.get("interface_index")) is not int or not 0 < identity["interface_index"] <= 0xffffffff
            or type(identity.get("luid")) is not int or not 0 < identity["luid"] <= 0xffffffffffffffff
            or identity.get("native_qualified") is not False):
        raise RuntimeError("Native Windows global TUN identity is invalid")
    return report


_DIGEST_REDACTIONS = (
    (re.compile(r"(?i)\b[a-z][a-z0-9+.-]*://[^\s\"'<>\\]+"), "[URL REDACTED]"),
    (re.compile(r"(?<![A-Za-z0-9])(?:[A-Za-z]:[\\/]|\\\\)[^\s\"'<>|]*"), "[PATH REDACTED]"),
    (re.compile(r"\bS-1-\d+(?:-\d+)+"), "[SID REDACTED]"),
)


def _digest_text(value, limit=200):
    """Redacted and truncated text for a public annotation; non-strings are dropped."""
    if not isinstance(value, str):
        return None
    for pattern, replacement in _DIGEST_REDACTIONS:
        value = pattern.sub(replacement, value)
    return value[:limit]


def _digest_scalar(value, limit=200):
    if value is None or isinstance(value, (bool, int, float)):
        return value
    return _digest_text(value, limit)


def _digest_strings(values, limit, count):
    if not isinstance(values, list):
        return []
    return [_digest_text(value, limit) for value in values if isinstance(value, str)][:count]


def _digest_column(rows, key, limit, count):
    if not isinstance(rows, list):
        return []
    return _digest_strings([row.get(key) for row in rows if isinstance(row, dict)], limit, count)


def _digest_recovery(value):
    if not isinstance(value, dict):
        return None
    return {"recovered": _digest_scalar(value.get("recovered")),
            "errors": _digest_strings(value.get("errors"), 200, 2)}


def global_guest_digest(result):
    """Bounded, secret-free view of a guest global-capture result for a public annotation."""
    if not isinstance(result, dict):
        return {"result_type": type(result).__name__}
    errors = result.get("errors")
    last = errors[-1] if isinstance(errors, list) and errors else None
    guest = {name: _digest_scalar(result.get(name)) for name in (
        "status", "phase", "error_type", "error_code", "exit_code",
        "user_cleanup_confirmed", "task_cleanup_confirmed", "installation_cleanup_confirmed")}
    guest["step_phases"] = _digest_column(result.get("steps"), "phase", 200, 30)
    guest["last_error"] = None
    if isinstance(last, dict):
        guest["last_error"] = {"phase": _digest_scalar(last.get("phase")),
                               "type": _digest_scalar(last.get("type")),
                               "message": _digest_text(last.get("message"), 300)}
    trust = result.get("fixture_trust")
    if isinstance(trust, dict):
        guest["fixture_trust"] = {key: value for key, value in trust.items()
                                  if isinstance(key, str) and isinstance(value, bool)}
    settle = result.get("settle")
    if isinstance(settle, dict):
        guest["settle"] = {key: _digest_scalar(settle.get(key)) for key in (
            "settled", "probes", "first_seconds", "last_seconds", "waited_seconds")}
        guest["settle"]["busy_processes"] = _digest_strings(settle.get("busy_processes"), 60, 6)
    digest = {"guest": guest}
    reports = result.get("reports")
    report = reports.get("global_capture") if isinstance(reports, dict) else None
    if isinstance(report, dict):
        budget = report.get("time_budget")
        stages = budget.get("stages") if isinstance(budget, dict) else None
        harness = {"passed": _digest_scalar(report.get("passed")),
                   "failed_stage": _digest_scalar(report.get("failed_stage")),
                   "error": _digest_text(report.get("error"), 300),
                   "stages": _digest_column(stages, "stage", 200, 40),
                   "recovery": _digest_recovery(report.get("recovery"))}
        if isinstance(report.get("ci_network_reclaim"), dict):
            harness["ci_network_reclaim"] = _digest_recovery(report["ci_network_reclaim"])
        digest["harness"] = harness
    return digest


def print_ci_annotation(level, title, payload):
    text = json.dumps(payload, separators=(",", ":"), sort_keys=True)[:1800]
    text = text.replace("%", "%25").replace("\r", "%0D").replace("\n", "%0A")
    print("::" + level + " title=" + title + "::" + text, flush=True)


def print_global_guest_digest(level, server):
    """Diagnostics only: printing must never change the qualification outcome."""
    try:
        if server is not None and server.result is not None:
            print_ci_annotation(level, "Win11 global guest digest", global_guest_digest(server.result))
    except Exception:
        pass


# The workflows wrap this process in `timeout` with the same --timeout-seconds.
# Stop waiting early enough that failure diagnostics and owned cleanup finish
# before that outer TERM.
CLEANUP_RESERVE_SECONDS = 120
_SERIAL_BEACON = re.compile(r"RPBEACON ([\x20-\x7e]{1,2000})")
_GUEST_HARNESS_TITLES = ("Global capture hard deadline", "Global capture watchdog", "Global capture summary")


def serial_beacons(path, limit=262144):
    """Guest progress lines relayed over the VM serial console; independent of guest networking."""
    try:
        with Path(path).open("rb") as stream:
            stream.seek(0, os.SEEK_END)
            stream.seek(max(0, stream.tell() - limit))
            data = stream.read(limit)
    except OSError:
        return []
    return _SERIAL_BEACON.findall(data.decode("ascii", "replace"))


def plug_network_after_beacon(qmp, path):
    """Plug the NIC in once the claimed guest script has beaconed; OOBE never beacons."""
    if not serial_beacons(path):
        return False
    qmp.execute("set_link", {"name": "vmnet", "up": True})
    return True


def print_serial_beacons(level, path):
    """Diagnostics only: last guest phases, then the last harness digest of each kind."""
    try:
        beacons = serial_beacons(path)
        print_ci_annotation(level, "Win11 guest serial progress",
                            {"count": len(beacons), "last": [_digest_text(line, 110) for line in beacons[-12:]]})
        for title in _GUEST_HARNESS_TITLES:
            marker = " title=" + title + "::"
            found = [line for line in beacons if marker in line]
            if found:
                payload = found[-1].split(marker, 1)[1]
                payload = payload.replace("%0D", "\r").replace("%0A", "\n").replace("%25", "%")
                print_ci_annotation(level, "Win11 guest " + title[len("Global "):], {"payload": _digest_text(payload, 1700)})
    except Exception:
        pass


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
    suite = getattr(args, "suite", "product")
    if suite not in {"product", "global-capture", "compartment-lab", "psec-compartment-smoke"}:
        raise ValueError("Unknown native Windows suite")
    psec_media = getattr(args, "psec_media", "serviced-25h2")
    install_media = selected_install_media(suite, psec_media)
    artifacts = args.artifacts.resolve()
    artifacts.mkdir(parents=True, exist_ok=True)
    summary = {"schema_version": 2, "status": "running", "scope": "native Windows 11 x64 final offline product",
               "native_windows_11_product_passed": False, "real_exit_ip_verified": False,
               "gui_verified": False, "linux_equivalent_isolation": False,
               "iso": install_media,
               "cumulative_update_required": False,
               "update_scope": "The selected proxy backend does not require the former MXC build contract."}
    summary["suite"] = suite
    if suite == "global-capture":
        summary.update(scope="native Windows 11 x64 bounded global capture experiment",
                       native_windows_11_global_capture_passed=False, strict_qualified=False)
    elif suite == "compartment-lab":
        summary.update(scope="native Windows 11 x64 compartment experiment",
                       native_windows_11_compartment_lab_completed=False, strict_qualified=False)
    elif suite == "psec-compartment-smoke":
        summary.update(scope="native Windows 11 x64 PSEC/compartment functional smoke",
                       native_windows_11_psec_functionality_passed=False, strict_qualified=False,
                       psec_media_profile=psec_media,
                       cumulative_update_required=psec_media == "serviced-25h2",
                       update_scope=("Pinned official KB5127648 and checkpoint; executor probe still gates PSEC support."
                                     if psec_media == "serviced-25h2" else
                                     "Fixed official 26H2 media and exact installed build; the executor probe still gates PSEC support."))
    summary["vm_configuration"] = {"machine": "q35,accel=kvm,smm=on", "vcpu": 4, "ram_mib": 6144,
        "disk_controller": "q35 built-in AHCI/SATA (ide-hd on ide.0)", "disk_virtual_gib": 80,
        "installer_dynamic_update": False, "secure_boot": True, "tpm": "2.0"}
    server = thread = qemu = tpm = qmp = private_directory = work = compartment_capture = None
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
        source_identity = global_source_identity() if suite == "global-capture" else None
        if source_identity is not None:
            summary["source_identity"] = source_identity
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
        updates = None
        if suite == "psec-compartment-smoke" and psec_media == "serviced-25h2":
            stage("official_cumulative_update_download")
            updates = work / "official-updates"
            summary["official_update_packages"] = media.download_updates(updates)
        stage("official_iso_download")
        subprocess.run(["curl", "--fail", "--location", "--retry", "3", "--retry-all-errors",
            "--connect-timeout", "30", "--max-time", "1200", "--proto", "=https", "--proto-redir", "=https",
            "--output", str(iso), install_media["url"]], check=True, timeout=1220)
        if iso.stat().st_size != install_media["bytes"] or media.digest(iso) != install_media["sha256"]:
            raise RuntimeError("Official Windows media size or hash mismatch")
        summary["iso"]["verified"] = True
        stage("official_iso_verified")
        payload = work / "payload.zip"
        payload_hash = make_payload(package, payload, include_global_sources=suite == "global-capture",
                                    psec_bundle=getattr(args, "psec_bundle", None) if suite == "psec-compartment-smoke" else None)
        server = media.GuestServer(payload, artifacts, updates=updates)
        thread = threading.Thread(target=server.serve_forever, daemon=True)
        thread.start()
        tree = work / "iso-tree"
        tree.mkdir()
        stage("official_iso_extract")
        subprocess.run([extractor, "x", "-tudf", "-y", f"-o{tree}", str(iso)], check=True, timeout=900)
        efi_boot = media.validate_install_tree(tree)
        password = secrets.token_hex(16) + "Ci!9"
        source_commit = subprocess.run(["git", "rev-parse", "HEAD"], cwd=ROOT, check=True,
                                       capture_output=True, text=True, timeout=5).stdout.strip()
        seed_configuration = {"host_url": f"http://10.0.2.2:{server.server_address[1]}/{server.capability}",
            "payload_sha256": payload_hash, "package_sha256": args.package_sha256,
            "source_commit": source_commit, "suite": suite,
            **({"source_identity": source_identity} if source_identity is not None else {})}
        if suite == "psec-compartment-smoke":
            seed_configuration["psec_media_profile"] = psec_media
            if psec_media == "26h2":
                seed_configuration.update(media_build=install_media["build"], media_ubr=install_media["ubr"],
                                          media_iso_sha256=install_media["sha256"], require_official_update=False)
        if updates is not None:
            seed_configuration.update(require_official_update=True,
                                      update_build=media.UPDATE_BUILD, update_ubr=media.UPDATE_UBR)
            # Reuse the verified update seed, then replace only its legacy
            # ordinary-user setup/runner with this suite's SYSTEM controller.
            media.prepare_seed(tree, password, seed_configuration, updates=updates)
        xml = (ROOT / ".github/windows-vm-unattend.xml").read_text().replace("@PASSWORD@", password)
        ET.fromstring(xml)
        (tree / "autounattend.xml").write_text(xml, encoding="utf-8")
        runner = {"global-capture": "windows-global-vm-run.ps1",
                  "compartment-lab": "windows-compartment-vm-run.ps1",
                  "psec-compartment-smoke": "windows-compartment-vm-run.ps1"}.get(suite, "windows-proxifyre-vm-run.ps1")
        for name, destination in (("windows-proxifyre-vm-setup.ps1", "ruleproxy-vm-setup.ps1"),
                                  (runner, "ruleproxy-vm-run.ps1")):
            (tree / destination).write_text((ROOT / ".github" / name).read_text(), encoding="utf-8-sig")
        media.write_json(tree / "ruleproxy-vm-config.json", seed_configuration)
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
            if suite == "compartment-lab":
                spec = importlib.util.spec_from_file_location("compartment_private_capture",
                    ROOT / ".github/windows_compartment_wire.py")
                module = importlib.util.module_from_spec(spec)
                spec.loader.exec_module(module)
                compartment_capture = module.Capture(qmp, work, artifacts)
                server.capture = compartment_capture
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
            # Online Windows 11 OOBE fetches a zero-day patch, and an update-service failure
            # parks setup on "Something went wrong (OOBEZDP)" with no unattended skip (run
            # 39030476856). Every suite keeps the NIC unplugged until its claimed guest
            # script beacons over COM1; that script waits, bounded, for the host endpoint.
            network_pending = suite in {"product", "global-capture", "compartment-lab", "psec-compartment-smoke"}
            if network_pending:
                qmp.execute("set_link", {"name": "vmnet", "up": False})
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
                if (qemu.poll() is not None
                        or time.monotonic() - overall_started > args.timeout_seconds - CLEANUP_RESERVE_SECONDS):
                    raise RuntimeError("Native Windows installation/product qualification did not finish within its budget")
                if shutil.disk_usage(work).free < 5 * 1024**3:
                    raise RuntimeError("VM disk safety reserve reached")
                print(f"Native Windows product VM: {int(time.monotonic() - started)} s", flush=True)
                for _ in range(6):
                    if server.received.wait(5):
                        break
                    if network_pending and plug_network_after_beacon(qmp, artifacts / "serial.log"):
                        network_pending = False
                        summary["guest_network_plugged_seconds"] = int(time.monotonic() - started)
                        print_ci_annotation("notice", "Win11 guest network",
                                            {"plugged_after_seconds": summary["guest_network_plugged_seconds"]})
            stage("guest_result_received")
            if suite == "global-capture":
                report = verify_global_result(server.result, package_sha256=args.package_sha256,
                                              source_identity=source_identity)
                media.write_json(artifacts / "native-global-capture-report.json", report)
                summary.update(status="passed", native_windows_11_global_capture_passed=True,
                               os=server.result["os"], elapsed_seconds=int(time.monotonic() - started))
                print_global_guest_digest("notice", server)
            elif suite == "psec-compartment-smoke":
                report = verify_psec_smoke_result(server.result, package_sha256=args.package_sha256,
                                                 source_commit=source_commit, psec_media=psec_media)
                media.write_json(artifacts / "native-psec-smoke-report.json", report)
                summary.update(status="passed", native_windows_11_psec_functionality_passed=True,
                               os=server.result["os"], elapsed_seconds=int(time.monotonic() - started))
            elif suite == "compartment-lab":
                report = verify_compartment_lab_result(server.result, package_sha256=args.package_sha256)
                media.write_json(artifacts / "native-compartment-report.json", report)
                summary.update(status="passed", native_windows_11_compartment_lab_completed=True,
                               os=server.result["os"], elapsed_seconds=int(time.monotonic() - started))
            else:
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
        if suite == "global-capture":
            print_serial_beacons("error", artifacts / "serial.log")
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
        if suite == "global-capture":
            print_global_guest_digest("error", server)
            print_serial_beacons("error", artifacts / "serial.log")
    finally:
        summary["product_execution_confirmed"] = bool(server is not None and isinstance(server.result, dict)
            and isinstance(server.result.get("reports", {}).get("product"), dict))
        if suite == "global-capture":
            summary["global_capture_execution_confirmed"] = bool(server is not None and isinstance(server.result, dict)
                and isinstance(server.result.get("reports", {}).get("global_capture"), dict))
        summary["phase_before_cleanup"] = summary["phase"]
        stage("cleanup")
        if compartment_capture is not None:
            try:
                compartment_capture.close()
            except Exception as exc:
                summary["capture_cleanup_error"] = type(exc).__name__
                summary["status"] = "failed"
        cleanup_errors = cleanup_owned(qmp, qemu, tpm, server, thread, private_directory)
        if cleanup_errors:
            summary.update(status="failed", native_windows_11_product_passed=False, cleanup_errors=cleanup_errors)
            if suite == "global-capture":
                summary["native_windows_11_global_capture_passed"] = False
        stage("finished")
    return summary


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--package", type=Path, required=True)
    parser.add_argument("--package-sha256", required=True)
    parser.add_argument("--artifacts", type=Path, required=True)
    parser.add_argument("--timeout-seconds", type=int, default=2700)
    parser.add_argument("--suite", choices=("product", "global-capture", "compartment-lab", "psec-compartment-smoke"), default="product")
    parser.add_argument("--psec-bundle", type=Path)
    parser.add_argument("--psec-media", choices=("serviced-25h2", "26h2"), default="serviced-25h2")
    args = parser.parse_args()
    maximum = 7200 if args.suite == "psec-compartment-smoke" else 3600
    if not 300 <= args.timeout_seconds <= maximum:
        parser.error(f"VM execution budget must be 300–{maximum} seconds")
    if (args.suite == "psec-compartment-smoke") != (args.psec_bundle is not None):
        parser.error("Only the PSEC functional suite requires --psec-bundle")
    if args.psec_media != "serviced-25h2" and args.suite != "psec-compartment-smoke":
        parser.error("--psec-media is limited to the PSEC functional experiment")
    with cancellation_signals():
        return 0 if run(args)["status"] == "passed" else 1


if __name__ == "__main__":
    raise SystemExit(main())
