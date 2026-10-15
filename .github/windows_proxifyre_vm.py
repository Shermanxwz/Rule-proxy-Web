"""Qualify the installed product in a fixed official Windows 11 x64 KVM VM.

Only media/VM primitives are reused from the historical harness. No MXC policy,
capability gate or PSEC acceptance result participates in this qualification.
"""
from __future__ import annotations

import argparse
import importlib.util
import json
import os
from pathlib import Path, PurePosixPath
import secrets
import shutil
import stat
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
    summary = {"schema_version": 1, "status": "failed", "scope": "native Windows 11 x64 final offline product",
               "native_windows_11_product_passed": False, "real_exit_ip_verified": False,
               "gui_verified": False, "linux_equivalent_isolation": False,
               "iso": {"url": media.ISO_URL, "sha256": media.ISO_SHA256, "bytes": media.ISO_BYTES},
               "cumulative_update_required": False,
               "update_scope": "The selected proxy backend does not require the former MXC build contract."}
    server = thread = qemu = tpm = qmp = private_directory = None
    try:
        summary["kvm_api_version"] = media.require_kvm()
        package = args.package.resolve(strict=True)
        verify_package(package, args.package_sha256)
        summary["package_sha256"] = args.package_sha256
        extractor = shutil.which("7zz") or shutil.which("7z")
        for binary in ("qemu-system-x86_64", "qemu-img", "swtpm", "xorriso", "curl"):
            if not shutil.which(binary):
                raise RuntimeError("Missing native VM dependency: " + binary)
        if not extractor:
            raise RuntimeError("Missing UDF extractor")
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
        subprocess.run(["curl", "--fail", "--location", "--retry", "3", "--retry-all-errors",
            "--connect-timeout", "30", "--max-time", "1200", "--proto", "=https", "--proto-redir", "=https",
            "--output", str(iso), media.ISO_URL], check=True, timeout=1220)
        if iso.stat().st_size != media.ISO_BYTES or media.digest(iso) != media.ISO_SHA256:
            raise RuntimeError("Official Windows media size or hash mismatch")
        summary["iso"]["verified"] = True
        payload = work / "payload.zip"
        payload_hash = make_payload(package, payload)
        server = media.GuestServer(payload, artifacts)
        thread = threading.Thread(target=server.serve_forever, daemon=True)
        thread.start()
        tree = work / "iso-tree"
        tree.mkdir()
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
        subprocess.run(["xorriso", "-as", "mkisofs", "-iso-level", "3", "-J", "-joliet-long", "-R", "-V", "RULEPROXY_CI",
            "-b", "boot/etfsboot.com", "-no-emul-boot", "-boot-load-size", "8", "-boot-info-table",
            "-eltorito-alt-boot", "-e", efi_boot, "-no-emul-boot", "-o", str(unattended), str(tree)], check=True)
        summary["remastered_iso"] = media.installer_layout(unattended)
        shutil.rmtree(tree)
        iso.unlink()
        disk, nvram = work / "windows.qcow2", work / "OVMF_VARS.fd"
        subprocess.run(["qemu-img", "create", "-f", "qcow2", str(disk), "80G"], check=True)
        shutil.copyfile(variables, nvram)
        state = work / "tpm-state"
        state.mkdir()
        tpm_socket, qmp_socket = work / "tpm.sock", work / "qmp.sock"
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
            if efi_boot.endswith("/efisys.bin"):
                for _ in range(8):
                    qmp.execute("send-key", {"keys": [{"type": "qcode", "data": "ret"}], "hold-time": 100})
                    time.sleep(2)
            started = time.monotonic()
            while not server.received.wait(30):
                if qemu.poll() is not None or time.monotonic() - started > args.timeout_seconds:
                    raise RuntimeError("Native Windows installation/product qualification did not finish within its budget")
                if shutil.disk_usage(work).free < 5 * 1024**3:
                    raise RuntimeError("VM disk safety reserve reached")
                print(f"Native Windows product VM: {int(time.monotonic() - started)} s", flush=True)
                try:
                    media.screenshot(qmp, work / "screen.ppm", artifacts / "last-screen.png")
                except (OSError, ValueError, RuntimeError):
                    pass
            report = verify_result(server.result, package_sha256=args.package_sha256)
            media.write_json(artifacts / "native-product-report.json", report)
            summary.update(status="passed", native_windows_11_product_passed=True,
                           os=server.result["os"], elapsed_seconds=int(time.monotonic() - started))
    except Exception as exc:
        summary["error"] = type(exc).__name__ + ": " + str(exc)
        print("::error title=Native Windows product::" + summary["error"], flush=True)
    finally:
        cleanup_errors = cleanup_owned(qmp, qemu, tpm, server, thread, private_directory)
        if cleanup_errors:
            summary.update(status="failed", native_windows_11_product_passed=False, cleanup_errors=cleanup_errors)
        media.write_json(artifacts / "native-product-summary.json", summary)
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
    return 0 if run(args)["status"] == "passed" else 1


if __name__ == "__main__":
    raise SystemExit(main())
