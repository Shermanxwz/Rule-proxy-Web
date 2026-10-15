"""Run a diagnostic-only free-backend network probe on an installed Server VM.

This is a short troubleshooting entry point, not the Windows 11 acceptance
runner. It uses only the fixed disposable-lab paths under C:\\RuleProxyCI.
"""
from __future__ import annotations

import argparse
import importlib.util
import json
import os
from pathlib import Path
import sys

ROOT = Path(r"C:\RuleProxyCI")
BUNDLE = ROOT / "bundle"
ARTIFACTS = ROOT / "artifacts"
RESULTS = ROOT / "results"
MANIFEST = BUNDLE / "manifest.json"
INSTALL_REPORT = ROOT / "install-report.json"
REPORT = RESULTS / "probe-report.json"
MAX_REPORT_BYTES = 128 * 1024


def _write_json(path: Path, value: dict) -> None:
    encoded = (json.dumps(value, sort_keys=True, separators=(",", ":")) + "\n").encode("utf-8")
    if len(encoded) > MAX_REPORT_BYTES:
        raise ValueError("server probe report exceeds size limit")
    path.parent.mkdir(parents=True, exist_ok=True)
    temporary = path.with_name(path.name + ".tmp")
    temporary.write_bytes(encoded)
    os.replace(temporary, path)


def _load_control(bundle: Path, backend: str):
    name = "windows_proxybridge_control.py" if backend == "proxybridge" else "windows_sandboxie_control.py"
    path = bundle / "scripts" / name
    if not path.is_file() or path.is_symlink():
        raise FileNotFoundError("fixed backend control helper is missing")
    spec = importlib.util.spec_from_file_location("server_probe_" + backend, path)
    if spec is None or spec.loader is None:
        raise ImportError("backend control helper cannot be loaded")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def _require_lab_paths(bundle: Path, artifacts: Path, manifest: Path,
                       install_report: Path, report: Path) -> None:
    expected = ((bundle, BUNDLE), (artifacts, ARTIFACTS), (manifest, MANIFEST),
                (install_report, INSTALL_REPORT), (report, REPORT))
    for actual, fixed in expected:
        if os.path.normcase(os.path.abspath(actual)) != os.path.normcase(os.path.abspath(fixed)):
            raise ValueError("server probe accepts only the fixed RuleProxyCI lab paths")


def _base(backend: str, status: str) -> dict:
    return {"schema_version": 1, "backend": backend, "phase": "server_network_probe",
            "status": status, "diagnostic_only": True, "source_diagnostic_only": True,
            "product_acceptance_passed": False, "release_eligible": False,
            "windows_server_network_diagnostic": True, "windows_11_verified": False,
            "gui_status": "not_tested_noninteractive"}


def run(backend: str, *, bundle: Path = BUNDLE, artifacts: Path = ARTIFACTS,
        manifest: Path = MANIFEST, install_report: Path = INSTALL_REPORT,
        report: Path = REPORT, control_module=None) -> dict:
    """Perform a real ordinary-user probe and persist a non-acceptance report."""
    if backend not in ("proxybridge", "sandboxie"):
        raise ValueError("unsupported backend")
    value = _base(backend, "failed")
    _require_lab_paths(bundle, artifacts, manifest, install_report, report)
    if sys.platform != "win32":
        raise OSError("server probe is Windows-only")
    if not bundle.is_dir() or bundle.is_symlink():
        raise FileNotFoundError("fixed backend bundle is unavailable")
    artifacts.mkdir(parents=True, exist_ok=True)
    module = control_module or _load_control(bundle, backend)
    if backend == "proxybridge":
        identity = module._ordinary_user_facts()
        if (identity.get("non_admin") is not True or identity.get("not_system") is not True
                or identity.get("is_administrator") is not False):
            raise PermissionError("network probe requires a non-admin, non-SYSTEM user")
        if not module.manifest_pins_installer(module._read_json(manifest, module.MAX_REPORT_BYTES)):
            raise ValueError("ProxyBridge manifest does not match the pinned installer")
        os_facts = module._windows_build()
        observations = module._run_service_probe(artifacts, bundle)
        cleanup = observations.pop("cleanup", False) is True
        value.update(status="diagnostic_completed" if cleanup else "diagnostic_incomplete",
                     ordinary_user=True, is_elevated=False, is_administrator=False,
                     windows_build=os_facts["build"], windows_ubr=os_facts["ubr"],
                     observations=observations, cleanup_proven=cleanup)
    else:
        # The existing Sandboxie probe owns its GUI/network/cleanup measurements.
        # It performs its own ordinary-token, manifest, bundle and install checks.
        returned = module.probe(bundle, manifest, report, install_report, artifacts,
                                include_gui=False)
        if not isinstance(returned, dict):
            raise TypeError("Sandboxie probe returned no structured report")
        value.update(status="diagnostic_completed" if returned.get("status") == "passed"
                     else "diagnostic_incomplete",
                     ordinary_user=returned.get("ordinary_user"),
                     is_elevated=returned.get("is_elevated"),
                     is_administrator=returned.get("is_administrator"),
                     windows_build=returned.get("windows_build"),
                     windows_ubr=returned.get("windows_ubr"),
                     gui_status=(returned.get("gui", {}).get("status")
                                 if type(returned.get("gui")) is dict
                                 else "not_tested_noninteractive"),
                     cleanup_proven=returned.get("cleanup_proven") is True,
                     backend_report=returned)
    _write_json(report, value)
    return value


def main(argv=None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--backend", choices=("proxybridge", "sandboxie"), required=True)
    args = parser.parse_args(argv)
    try:
        value = run(args.backend)
    except Exception as exc:
        value = _base(args.backend, "failed")
        value["failure_type"] = type(exc).__name__[:64]
        errno = getattr(exc, "errno", None)
        winerror = getattr(exc, "winerror", None)
        value["error_errno"] = errno if type(errno) is int and -2147483648 <= errno <= 2147483647 else None
        value["error_winerror"] = (winerror if type(winerror) is int
                                   and -2147483648 <= winerror <= 2147483647 else None)
        frames = []
        current = exc.__traceback__
        while current is not None:
            name = Path(current.tb_frame.f_code.co_filename).name
            if name in ("windows_free_backend_server_probe.py", "windows_proxybridge_control.py",
                        "windows_sandboxie_control.py", "windows_free_backend_fixture.py"):
                frames.append({"file": name, "function": current.tb_frame.f_code.co_name[:80],
                               "line": current.tb_lineno})
            current = current.tb_next
        value["failure_frames"] = frames[-8:]
        try:
            _write_json(REPORT, value)
        except Exception:
            pass
    return 0 if value["status"] == "diagnostic_completed" else 1


if __name__ == "__main__":
    raise SystemExit(main())
