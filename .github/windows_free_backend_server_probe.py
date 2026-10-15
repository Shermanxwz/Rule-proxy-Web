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
import re
import select
import secrets
import socket
import sys

ROOT = Path(r"C:\RuleProxyCI")
BUNDLE = ROOT / "bundle"
ARTIFACTS = ROOT / "artifacts"
RESULTS = ROOT / "results"
MANIFEST = BUNDLE / "manifest.json"
INSTALL_REPORT = ROOT / "install-report.json"
REPORT = RESULTS / "probe-report.json"
MAX_REPORT_BYTES = 128 * 1024
UDP_WORKER_SOURCE = r'''import json, os, re, socket, sys
from pathlib import Path
args = sys.argv
if len(args) != 5 or args[1] != "--spec" or args[3] != "--report": raise SystemExit(2)
spec = json.loads(Path(args[2]).read_text(encoding="ascii"))
if (spec.get("schema_version") != 1 or spec.get("stage") != "contained"
        or spec.get("box") not in ("RuleProxyNet", "RuleProxyDnsIpc")
        or not re.fullmatch(r"[0-9a-f]{32}", spec.get("nonce", ""))): raise SystemExit(3)
rows = {}
for family, af in (("ipv4", socket.AF_INET), ("ipv6", socket.AF_INET6)):
    row = {"attempted": True, "sent_bytes": None, "error_errno": None, "error_winerror": None}
    try:
        host, port = spec["endpoints"][family]
        if host != ("127.0.0.1" if family == "ipv4" else "::1") or type(port) is not int or not 1 <= port <= 65535:
            raise ValueError("invalid fixed loopback endpoint")
        payload = ("RPWFREE:" + spec["nonce"] + ":" + family + ":contained:" + spec["box"]).encode("ascii")
        with socket.socket(af, socket.SOCK_DGRAM) as sock:
            address = (host, port) if af == socket.AF_INET else (host, port, 0, 0)
            row["sent_bytes"] = sock.sendto(payload, address)
    except OSError as exc:
        row["error_errno"] = exc.errno if type(exc.errno) is int else None
        winerror = getattr(exc, "winerror", None)
        row["error_winerror"] = winerror if type(winerror) is int else None
    except (KeyError, TypeError, ValueError):
        row["error_errno"] = -1
    rows[family] = row
out = {"schema_version": 1, "box": spec["box"], "families": rows}
target = Path(args[4]); temporary = target.with_name(target.name + ".tmp")
temporary.write_text(json.dumps(out, sort_keys=True, separators=(",", ":")), encoding="ascii")
os.replace(temporary, target)
'''


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


def _bounded_int(value):
    return value if type(value) is int and -2147483648 <= value <= 2147483647 else None


def _send_marker(family: str, endpoint: tuple[str, int], marker: bytes) -> dict:
    af = socket.AF_INET if family == "ipv4" else socket.AF_INET6
    try:
        # Deliberately unconnected and unbound: this is sendto-only behavior.
        with socket.socket(af, socket.SOCK_DGRAM) as sender:
            address = endpoint if af == socket.AF_INET else (endpoint[0], endpoint[1], 0, 0)
            sent = sender.sendto(marker, address)
        return {"attempted": True, "sent_bytes": sent, "error_errno": None,
                "error_winerror": None}
    except OSError as exc:
        return {"attempted": True, "sent_bytes": None,
                "error_errno": _bounded_int(getattr(exc, "errno", None)),
                "error_winerror": _bounded_int(getattr(exc, "winerror", None))}


def _udp_listener(family: str):
    af = socket.AF_INET if family == "ipv4" else socket.AF_INET6
    sock = socket.socket(af, socket.SOCK_DGRAM)
    try:
        if af == socket.AF_INET6:
            sock.setsockopt(socket.IPPROTO_IPV6, socket.IPV6_V6ONLY, 1)
            sock.bind(("::1", 0))
        else:
            sock.bind(("127.0.0.1", 0))
        sock.setblocking(False)
        address = sock.getsockname()
        return sock, (address[0], address[1])
    except OSError:
        sock.close()
        raise


def _drain_udp(listeners: dict, marker_labels: dict, counts: dict, timeout=0.25):
    """Drain exact fixed markers for a short bounded interval; retain no payloads."""
    sockets = list(listeners.values())
    unknown = 0
    deadline = __import__("time").monotonic() + timeout
    total = 0
    while sockets and total < 128:
        wait = max(0.0, deadline - __import__("time").monotonic())
        ready, _, _ = select.select(sockets, [], [], wait)
        if not ready:
            break
        for sock in ready:
            while total < 128:
                try:
                    data, _peer = sock.recvfrom(512)
                except BlockingIOError:
                    break
                total += 1
                label = marker_labels.get(data)
                if label is None:
                    unknown += 1
                else:
                    counts[label] = min(1000, counts.get(label, 0) + 1)
    return unknown


def _raw_unconnected_udp(module, bundle: Path, artifacts: Path) -> dict:
    """Compare unconnected sendto against outside controls on owned loopback sockets."""
    boxes = (module.BOX_BASE, module.BOX_DNS)
    nonce = secrets.token_hex(16)
    listeners, endpoints, family_errors = {}, {}, {}
    for family in ("ipv4", "ipv6"):
        try:
            listeners[family], endpoints[family] = _udp_listener(family)
        except OSError as exc:
            family_errors[family] = {"listener_ready": False,
                                     "error_errno": _bounded_int(getattr(exc, "errno", None)),
                                     "error_winerror": _bounded_int(getattr(exc, "winerror", None))}
    if not listeners:
        cleanup = {}
        try:
            start = module._start_exe(module._install_root())
            for box in boxes:
                try:
                    cleanup[box] = module._box_cleanup(start, box)
                except Exception as exc:
                    cleanup[box] = {"cleanup_proven": False, "empty_box_proven": False,
                                    "error_type": type(exc).__name__[:64]}
        except Exception:
            pass
        proven = (len(cleanup) == len(boxes) and all(
            type(row) is dict and row.get("cleanup_proven") is True
            and row.get("empty_box_proven") is True for row in cleanup.values()))
        return {"status": "incomplete", "cleanup_proven": proven,
                "sandbox_cleanup": cleanup, "families": {},
                "reason": "no_loopback_udp_listener_available"}

    labels = {}
    result = {"status": "incomplete", "cleanup_proven": False,
              "worker_cleanup_proven": {}, "families": {}}
    counts = {}
    for family in listeners:
        for box in boxes:
            for stage in ("outside_before", "contained", "outside_after"):
                label = f"{family}:{box}:{stage}"
                labels[(f"RPWFREE:{nonce}:{family}:{stage}:{box}").encode("ascii")] = label
                counts[label] = 0

    token = secrets.token_hex(8)
    worker_path = artifacts / (".raw-udp-worker-" + token + ".py")
    spec_paths, report_paths = {}, {}
    started = {}
    unknown_packets = 0
    start = None
    try:
        worker_path.write_text(UDP_WORKER_SOURCE, encoding="ascii")
        for box in boxes:
            spec_path = artifacts / (".raw-udp-spec-" + token + "-" + box + ".json")
            report_path = artifacts / (".raw-udp-report-" + token + "-" + box + ".json")
            spec = {"schema_version": 1, "nonce": nonce, "stage": "contained", "box": box,
                    "endpoints": {family: list(address) for family, address in endpoints.items()}}
            spec_path.write_text(json.dumps(spec, sort_keys=True, separators=(",", ":")), encoding="ascii")
            spec_paths[box], report_paths[box] = spec_path, report_path

        for family, endpoint in endpoints.items():
            for box in boxes:
                marker = f"RPWFREE:{nonce}:{family}:outside_before:{box}".encode("ascii")
                started[f"{family}:{box}:outside_before"] = _send_marker(family, endpoint, marker)
        unknown_packets += _drain_udp(listeners, labels, counts)

        python = bundle / "python" / "python.exe"
        start = module._start_exe(module._install_root())
        worker_exit_ok = {}
        for box in boxes:
            try:
                completed = module._run_box(start, box,
                    [str(python), "-I", "-S", "-X", "utf8", str(worker_path),
                     "--spec", str(spec_paths[box]), "--report", str(report_paths[box])],
                    timeout=30)
                report = module._json_read(report_paths[box], 16 * 1024)
                valid = (completed.returncode == 0 and report.get("schema_version") == 1
                         and report.get("box") == box and type(report.get("families")) is dict)
                rows = report.get("families") if type(report.get("families")) is dict else {}
                for family in endpoints:
                    row = rows.get(family)
                    valid = valid and type(row) is dict and row.get("attempted") is True
                    if type(row) is dict:
                        started[f"{family}:{box}:contained"] = {
                            "attempted": row.get("attempted") is True,
                            "sent_bytes": row.get("sent_bytes") if type(row.get("sent_bytes")) is int else None,
                            "error_errno": _bounded_int(row.get("error_errno")),
                            "error_winerror": _bounded_int(row.get("error_winerror"))}
                worker_exit_ok[box] = bool(valid)
            except Exception as exc:
                worker_exit_ok[box] = False
                started["worker_failure_" + box] = {
                    "error_type": type(exc).__name__[:64],
                    "error_errno": _bounded_int(getattr(exc, "errno", None)),
                    "error_winerror": _bounded_int(getattr(exc, "winerror", None))}
            unknown_packets += _drain_udp(listeners, labels, counts)

        for family, endpoint in endpoints.items():
            for box in boxes:
                marker = f"RPWFREE:{nonce}:{family}:outside_after:{box}".encode("ascii")
                started[f"{family}:{box}:outside_after"] = _send_marker(family, endpoint, marker)
        unknown_packets += _drain_udp(listeners, labels, counts)
        outside_positive = all(
            started.get(f"{family}:{box}:{stage}", {}).get("sent_bytes") ==
            len(f"RPWFREE:{nonce}:{family}:{stage}:{box}".encode("ascii"))
            and counts.get(f"{family}:{box}:{stage}", 0) > 0
            for family in endpoints for box in boxes for stage in ("outside_before", "outside_after"))
        worker_facts = {}
        for box in boxes:
            worker_facts[box] = bool(worker_exit_ok.get(box))
        result["worker_exit_verified"] = worker_facts
        result["outside_controls_positive"] = outside_positive
        result["unknown_datagram_count"] = min(1000, unknown_packets)
        result["families"] = {
            family: {"listener_ready": True,
                     "outside_before": {box: {
                         "send": started.get(f"{family}:{box}:outside_before"),
                         "received_count": counts.get(f"{family}:{box}:outside_before", 0)}
                                         for box in boxes},
                     "contained": {box: {**started.get(f"{family}:{box}:contained", {
                                            "attempted": False, "sent_bytes": None,
                                            "error_errno": None, "error_winerror": None}),
                                          "received_count": counts.get(f"{family}:{box}:contained", 0)}
                                   for box in boxes},
                     "outside_after": {box: {
                         "send": started.get(f"{family}:{box}:outside_after"),
                         "received_count": counts.get(f"{family}:{box}:outside_after", 0)}
                                        for box in boxes}}
            for family in ("ipv4", "ipv6")}
        for family, facts in family_errors.items():
            result["families"][family] = facts
        result["status"] = ("complete" if outside_positive and unknown_packets == 0
                             and len(listeners) == 2
                             and all(worker_facts.values())
                             and all(started.get(f"{family}:{box}:contained", {}).get("attempted") is True
                                     for family in endpoints for box in boxes)
                             else "incomplete")
        result["reason"] = None if result["status"] == "complete" else "control_or_worker_evidence_incomplete"
    finally:
        sandbox_cleanup = {}
        if start is not None:
            for box in boxes:
                try:
                    facts = module._box_cleanup(start, box)
                    sandbox_cleanup[box] = facts if type(facts) is dict else {
                        "cleanup_proven": False, "empty_box_proven": False}
                except Exception as exc:
                    sandbox_cleanup[box] = {"cleanup_proven": False,
                                            "empty_box_proven": False,
                                            "error_type": type(exc).__name__[:64],
                                            "error_errno": _bounded_int(getattr(exc, "errno", None)),
                                            "error_winerror": _bounded_int(getattr(exc, "winerror", None))}
        result["sandbox_cleanup"] = sandbox_cleanup
        close_ok = True
        for sock in listeners.values():
            try:
                sock.close()
            except OSError:
                close_ok = False
        result["sockets_closed"] = close_ok
        boxes_empty = (len(sandbox_cleanup) == len(boxes) and all(
            facts.get("cleanup_proven") is True and facts.get("empty_box_proven") is True
            for facts in sandbox_cleanup.values()))
        result["cleanup_proven"] = boxes_empty and close_ok
        if not result["cleanup_proven"]:
            result["status"] = "incomplete"
            result["reason"] = "cleanup_not_proven"
        # Retain nonce-bearing worker inputs until both fixed boxes are proven empty.
        if result.get("cleanup_proven"):
            for path in [worker_path, *spec_paths.values(), *report_paths.values()]:
                try:
                    path.unlink(missing_ok=True)
                except OSError:
                    result["cleanup_proven"] = False
                    result["status"] = "incomplete"
                    result["reason"] = "temporary_file_cleanup_not_proven"
    return result


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
        raw_udp = None
        if returned.get("status") == "passed":
            try:
                raw_udp = _raw_unconnected_udp(module, bundle, artifacts)
            except Exception as exc:
                raw_udp = {"status": "incomplete", "cleanup_proven": False,
                           "reason": "unconnected_udp_probe_error",
                           "error_type": type(exc).__name__[:64],
                           "error_errno": _bounded_int(getattr(exc, "errno", None)),
                           "error_winerror": _bounded_int(getattr(exc, "winerror", None))}
        probe_ok = returned.get("status") == "passed"
        raw_udp_ok = (raw_udp is None or (raw_udp.get("status") == "complete"
                                          and raw_udp.get("cleanup_proven") is True))
        aggregate_cleanup = (returned.get("cleanup_proven") is True
                             and (raw_udp is None or raw_udp.get("cleanup_proven") is True))
        value.update(status="diagnostic_completed" if probe_ok and raw_udp_ok
                     else "diagnostic_incomplete",
                     ordinary_user=returned.get("ordinary_user"),
                     is_elevated=returned.get("is_elevated"),
                     is_administrator=returned.get("is_administrator"),
                     windows_build=returned.get("windows_build"),
                     windows_ubr=returned.get("windows_ubr"),
                     gui_status=(returned.get("gui", {}).get("status")
                                 if type(returned.get("gui")) is dict
                                 else "not_tested_noninteractive"),
                     cleanup_proven=aggregate_cleanup,
                     backend_report=returned)
        if raw_udp is not None:
            value["raw_unconnected_udp"] = raw_udp
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
