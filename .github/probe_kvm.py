"""Record whether this ephemeral runner can actually create a KVM guest.

This is a host capability diagnostic, never a Windows/PSEC acceptance result.
No VM, listener, driver or host network configuration is created.
"""
import argparse
import json
import os
from pathlib import Path
import shutil
import sys


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--report", type=Path, required=True)
    args = parser.parse_args()
    report = {"kvm_available": False, "windows_acceptance_passed": False,
              "free_disk_bytes": shutil.disk_usage(Path.cwd()).free}
    descriptor = None
    guest = None
    try:
        import fcntl
        descriptor = os.open("/dev/kvm", os.O_RDWR | os.O_CLOEXEC)
        version = fcntl.ioctl(descriptor, 0xAE00, 0)  # KVM_GET_API_VERSION
        if version != 12:
            raise RuntimeError("unexpected KVM API version")
        guest = fcntl.ioctl(descriptor, 0xAE01, 0)  # KVM_CREATE_VM
        report.update(kvm_available=True, kvm_api_version=version)
    except (OSError, RuntimeError, ImportError) as exc:
        report["detail"] = f"{type(exc).__name__}: {exc}"
    finally:
        if guest is not None:
            os.close(guest)
        if descriptor is not None:
            os.close(descriptor)
    args.report.write_text(json.dumps(report, indent=2) + "\n", encoding="utf-8")
    print(json.dumps(report, indent=2))
    return 0  # Diagnostic job success records evidence, not guest acceptance.


if __name__ == "__main__":
    sys.exit(main())
