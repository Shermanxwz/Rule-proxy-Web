"""Bounded disposable Windows comparison; never product installation or acceptance.

Actors use ordinary sockets, with no proxy handshake or native proxy settings.
The independently owned SOCKS receivers return unique route markers through
Mihomo. These prove the selected controlled route, not a geographic exit IP.
"""
from __future__ import annotations

import argparse
import ctypes
from ctypes import wintypes
from contextlib import nullcontext
import hashlib
import importlib.util
import ipaddress
import json
import os
from pathlib import Path
import secrets
import shutil
import socket
import statistics
import struct
import subprocess
import sys
import time
import traceback
import urllib.request
import zipfile


ROOT = Path(r"C:\RuleProxyCompare")


def write_json(path, value):
    path = Path(path)
    path.parent.mkdir(parents=True, exist_ok=True)
    temp = path.with_suffix(path.suffix + ".tmp")
    temp.write_text(json.dumps(value, indent=2, ensure_ascii=True) + "\n", encoding="ascii")
    os.replace(temp, path)


def load_module(name):
    spec = importlib.util.spec_from_file_location(name, Path(__file__).with_name(name + ".py"))
    module = importlib.util.module_from_spec(spec)
    sys.modules[name] = module
    spec.loader.exec_module(module)
    return module


def error_facts(exc):
    return {"type": type(exc).__name__, "errno": getattr(exc, "errno", None),
            "winerror": getattr(exc, "winerror", None), "message": str(exc)[:350]}


def http_attempt(spec, token):
    family = socket.AF_INET6 if spec.get("family") == "ipv6" else socket.AF_INET
    started = time.perf_counter()
    row = {"token": token, "protocol": "tcp", "family": spec.get("family", "ipv4")}
    try:
        with socket.socket(family, socket.SOCK_STREAM) as connection:
            connection.settimeout(6)
            connection.connect((spec["target"], 80))
            path = "/ruleproxy-compare/" + spec["nonce"] + "/" + token
            request = ("GET " + path + " HTTP/1.1\r\nHost: example.com\r\n"
                       "Connection: close\r\nCache-Control: no-cache\r\n\r\n").encode("ascii")
            connection.sendall(request)
            result = b""
            while len(result) < 65536:
                block = connection.recv(8192)
                if not block:
                    break
                result += block
            head, _, body = result.partition(b"\r\n\r\n")
            headers = {}
            for line in head.split(b"\r\n")[1:]:
                key, separator, value = line.partition(b":")
                if separator:
                    headers[key.decode("ascii", "replace").lower()] = value.decode("ascii", "replace").strip()
            row.update(connected=True, response_bytes=len(result),
                       http_status=head.split(b"\r\n", 1)[0].decode("ascii", "replace")[:100],
                       node=headers.get("x-ruleproxy-node"),
                       marker_nonce_valid=headers.get("x-ruleproxy-nonce") == spec["nonce"],
                       marker_token_valid=token.encode("ascii") in body)
            row["controlled_proxy_response"] = bool(row["node"] in ("A", "B") and
                row["marker_nonce_valid"] and row["marker_token_valid"])
    except Exception as exc:
        row.update(connected=False, controlled_proxy_response=False, error=error_facts(exc))
    row["elapsed_ms"] = round((time.perf_counter() - started) * 1000, 3)
    return row


def dns_attempt(spec, token, existing_socket=None):
    name = token + "." + spec["nonce"] + ".ruleproxy-ci.example.com"
    transaction = secrets.randbelow(65536)
    query = struct.pack("!HHHHHH", transaction, 0x0100, 1, 0, 0, 0)
    query += b"".join(bytes([len(label)]) + label.encode("ascii") for label in name.split("."))
    query += b"\x00\x00\x01\x00\x01"
    family = socket.AF_INET6 if spec.get("family") == "ipv6" else socket.AF_INET
    row = {"token": token, "protocol": "udp", "family": spec.get("family", "ipv4"),
           "connected_udp": bool(spec.get("connected_udp")),
           "destination_port": spec.get("destination_port", 53),
           "same_bound_socket_reused": existing_socket is not None}
    started = time.perf_counter()
    try:
        with (nullcontext(existing_socket) if existing_socket is not None else
              socket.socket(family, socket.SOCK_DGRAM)) as sender:
            sender.settimeout(5)
            endpoint = (spec["target"], spec.get("destination_port", 53))
            if spec.get("connected_udp"):
                sender.connect(endpoint)
                sender.send(query)
                data = sender.recv(8192)
            else:
                sender.sendto(query, endpoint)
                data, _ = sender.recvfrom(8192)
            valid = len(data) >= 12 and struct.unpack("!H", data[:2])[0] == transaction
            # Synthetic A records are deliberately reserved documentation IPs.
            node = next((node for node, address in (("A", "198.51.100.101"), ("B", "198.51.100.102"))
                         if socket.inet_aton(address) in data), None)
            row.update(response_received=valid, response_bytes=len(data), node=node,
                       controlled_proxy_response=bool(valid and node))
    except Exception as exc:
        row.update(response_received=False, controlled_proxy_response=False, error=error_facts(exc))
    row["elapsed_ms"] = round((time.perf_counter() - started) * 1000, 3)
    return row


def native_curl_attempt(spec, token):
    started = time.perf_counter()
    path = "/ruleproxy-compare/" + spec["nonce"] + "/" + token
    row = {"token": token, "protocol": "tcp", "family": "ipv4", "application": "Windows inbox curl"}
    try:
        result = subprocess.run([spec["native_curl"], "--noproxy", "*", "--max-time", "6",
            "--silent", "--show-error", "--include", "--http1.1", "--header", "Host: example.com",
            "http://" + spec["target"] + path], capture_output=True, timeout=10)
        head, _, body = result.stdout.partition(b"\r\n\r\n")
        headers = {}
        for line in head.split(b"\r\n")[1:]:
            key, separator, value = line.partition(b":")
            if separator:
                headers[key.decode("ascii", "replace").lower()] = value.decode("ascii", "replace").strip()
        row.update(exit_code=result.returncode, connected=bool(result.stdout),
                   response_bytes=len(result.stdout), node=headers.get("x-ruleproxy-node"),
                   marker_nonce_valid=headers.get("x-ruleproxy-nonce") == spec["nonce"],
                   marker_token_valid=token.encode("ascii") in body)
        row["controlled_proxy_response"] = bool(row["node"] in ("A", "B") and
            row["marker_nonce_valid"] and row["marker_token_valid"] and result.returncode == 0)
    except Exception as exc:
        row.update(connected=False, controlled_proxy_response=False, error=error_facts(exc))
    row["elapsed_ms"] = round((time.perf_counter() - started) * 1000, 3)
    return row


def actor(spec_path, result_path):
    spec = json.loads(Path(spec_path).read_text(encoding="ascii"))
    result = {"pid": os.getpid(), "exe": str(Path(sys.executable).resolve()), "rows": [],
              "explicit_proxy_used": False, "role": spec["role"], "children": []}
    if os.name == "nt":
        result["is_elevated"] = bool(ctypes.windll.shell32.IsUserAnAdmin())
    if spec.get("udp_ports"):
        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as sender:
            sender.bind(("0.0.0.0", 0))
            for index in range(spec.get("count", 1)):
                for port in spec["udp_ports"]:
                    token = spec["token"] + "-p" + str(port) + "-" + str(index)
                    result["rows"].append(dns_attempt(dict(spec, destination_port=port), token, sender))
    else:
        for index in range(spec.get("count", 1)):
            token = spec["token"] + "-" + str(index)
            result["rows"].append(native_curl_attempt(spec, token) if spec.get("native_curl") else
                dns_attempt(spec, token) if spec.get("protocol") == "udp" else http_attempt(spec, token))
    for child in spec.get("children", []):
        child_spec = dict(spec, role=child["role"], token=spec["token"] + "-" + child["role"],
                          count=1, children=[])
        child_path = Path(result_path).with_name(Path(result_path).stem + "-" + child["role"] + ".spec.json")
        child_result = child_path.with_suffix(".result.json")
        write_json(child_path, child_spec)
        try:
            child_run = subprocess.run([child["exe"], "-I", "-S", str(Path(__file__).resolve()),
                                        "--actor", str(child_path), "--actor-result", str(child_result)],
                                       timeout=20, capture_output=True)
            value = json.loads(child_result.read_text(encoding="ascii"))
            result["children"].append({"role": child["role"], "exit_code": child_run.returncode, **value})
        except Exception as exc:
            result["children"].append({"role": child["role"], "error": error_facts(exc)})
    write_json(result_path, result)
    return 0


def launch_ordinary(executable, spec_path, result_path, username, password):
    """New ordinary logon, never pass the password in a command line or report."""
    class STARTUPINFO(ctypes.Structure):
        _fields_ = [("cb", wintypes.DWORD), ("lpReserved", wintypes.LPWSTR),
                    ("lpDesktop", wintypes.LPWSTR), ("lpTitle", wintypes.LPWSTR),
                    ("dwX", wintypes.DWORD), ("dwY", wintypes.DWORD),
                    ("dwXSize", wintypes.DWORD), ("dwYSize", wintypes.DWORD),
                    ("dwXCountChars", wintypes.DWORD), ("dwYCountChars", wintypes.DWORD),
                    ("dwFillAttribute", wintypes.DWORD), ("dwFlags", wintypes.DWORD),
                    ("wShowWindow", wintypes.WORD), ("cbReserved2", wintypes.WORD),
                    ("lpReserved2", ctypes.POINTER(ctypes.c_byte)),
                    ("hStdInput", wintypes.HANDLE), ("hStdOutput", wintypes.HANDLE),
                    ("hStdError", wintypes.HANDLE)]

    class PROCESS_INFORMATION(ctypes.Structure):
        _fields_ = [("hProcess", wintypes.HANDLE), ("hThread", wintypes.HANDLE),
                    ("dwProcessId", wintypes.DWORD), ("dwThreadId", wintypes.DWORD)]

    advapi = ctypes.WinDLL("advapi32", use_last_error=True)
    kernel = ctypes.WinDLL("kernel32", use_last_error=True)
    create = advapi.CreateProcessWithLogonW
    create.argtypes = [wintypes.LPCWSTR, wintypes.LPCWSTR, wintypes.LPCWSTR, wintypes.DWORD,
                       wintypes.LPCWSTR, wintypes.LPWSTR, wintypes.DWORD, wintypes.LPVOID,
                       wintypes.LPCWSTR, ctypes.POINTER(STARTUPINFO), ctypes.POINTER(PROCESS_INFORMATION)]
    create.restype = wintypes.BOOL
    kernel.WaitForSingleObject.argtypes = [wintypes.HANDLE, wintypes.DWORD]
    kernel.GetExitCodeProcess.argtypes = [wintypes.HANDLE, ctypes.POINTER(wintypes.DWORD)]
    kernel.TerminateProcess.argtypes = [wintypes.HANDLE, wintypes.UINT]
    kernel.CloseHandle.argtypes = [wintypes.HANDLE]
    command = subprocess.list2cmdline([str(executable), "-I", "-S", str(ROOT / "actor.py"),
                                       "--actor", str(spec_path), "--actor-result", str(result_path)])
    info, process = STARTUPINFO(), PROCESS_INFORMATION()
    info.cb = ctypes.sizeof(info)
    started = time.monotonic()
    if not create(username, ".", password, 1, str(executable), ctypes.create_unicode_buffer(command),
                  0x08000000, None, str(ROOT), ctypes.byref(info), ctypes.byref(process)):
        raise ctypes.WinError(ctypes.get_last_error())
    try:
        wait = kernel.WaitForSingleObject(process.hProcess, 45000)
        if wait != 0:
            kernel.TerminateProcess(process.hProcess, 124)
            raise TimeoutError("ordinary actor exceeded 45 seconds")
        code = wintypes.DWORD()
        kernel.GetExitCodeProcess(process.hProcess, ctypes.byref(code))
        result = json.loads(Path(result_path).read_text(encoding="ascii"))
        result.update(exit_code=code.value, launcher_pid=process.dwProcessId,
                      process_elapsed_ms=round((time.monotonic() - started) * 1000, 3))
        if result.get("is_elevated") is not False:
            raise RuntimeError("actor ordinary-user check failed")
        return result
    finally:
        kernel.CloseHandle(process.hThread)
        kernel.CloseHandle(process.hProcess)


def fetch_pinned(url, digest, target, max_bytes=180 * 1024**2):
    request = urllib.request.Request(url, headers={"User-Agent": "RuleProxy-bounded-comparison/1"})
    h, size = hashlib.sha256(), 0
    with urllib.request.urlopen(request, timeout=90) as response, target.open("wb") as output:
        while block := response.read(1024 * 1024):
            size += len(block)
            if size > max_bytes:
                raise ValueError("pinned asset exceeds limit")
            h.update(block)
            output.write(block)
    if h.hexdigest() != digest:
        raise ValueError("pinned asset SHA256 mismatch")
    return {"url": url, "sha256": digest, "bytes": size}


def settings():
    command = ("$v=[ordered]@{dns=@(Get-DnsClientServerAddress|Select-Object InterfaceIndex,AddressFamily,ServerAddresses);"
               "default_routes=@(Get-NetRoute|Where-Object {$_.DestinationPrefix -in @('0.0.0.0/0','::/0')}|"
               "Select-Object DestinationPrefix,InterfaceIndex,NextHop,RouteMetric);"
               "winhttp=@(netsh winhttp show proxy)};$v|ConvertTo-Json -Depth 6 -Compress")
    result = subprocess.run(["powershell.exe", "-NoProfile", "-NonInteractive", "-Command", command],
                            capture_output=True, text=True, timeout=30)
    return json.loads(result.stdout.strip()) if result.returncode == 0 else {"read_error": result.returncode}


def process_resources(pid):
    if not pid:
        return {"measured": False}
    command = ("$rows=@(Get-CimInstance Win32_Process);$ids=@(" + str(int(pid)) + ");"
               "do{$new=@($rows|Where-Object {$_.ParentProcessId -in $ids -and $_.ProcessId -notin $ids}|"
               "ForEach-Object {[int]$_.ProcessId});$ids+=@($new)}while($new.Count -gt 0);"
               "$p=@(Get-Process -Id $ids -ErrorAction SilentlyContinue);"
               "[ordered]@{process_count=$p.Count;working_set_bytes=($p|Measure-Object WorkingSet64 -Sum).Sum;"
               "private_bytes=($p|Measure-Object PrivateMemorySize64 -Sum).Sum;"
               "cpu_seconds=($p|Measure-Object CPU -Sum).Sum;includes_driver_memory=$false;"
               "includes_mihomo=$false}|ConvertTo-Json -Compress")
    result = subprocess.run(["powershell.exe", "-NoProfile", "-NonInteractive", "-Command", command],
                            capture_output=True, text=True, timeout=30)
    return json.loads(result.stdout.strip()) if result.returncode == 0 else {"read_error": result.returncode}


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--backend", choices=("clew", "proxifyre"))
    parser.add_argument("--output", type=Path)
    parser.add_argument("--actor", type=Path)
    parser.add_argument("--actor-result", type=Path)
    args = parser.parse_args(argv)
    if args.actor:
        return actor(args.actor, args.actor_result)
    if os.name != "nt" or not args.backend or args.output is None:
        parser.error("controller requires disposable Windows, backend and output")
    if not ctypes.windll.shell32.IsUserAnAdmin():
        raise RuntimeError("controller must run elevated")
    username = os.environ.pop("RULEPROXY_TEST_USER")
    password = os.environ.pop("RULEPROXY_TEST_PASSWORD")
    args.output.mkdir(parents=True, exist_ok=True)
    report = {"schema_version": 1, "backend": args.backend, "status": "running", "phases": [],
              "environment": {"platform": sys.platform, "windows_version": sys.getwindowsversion().build,
                              "windows_11_verified": False, "gui_verified": False},
              "diagnostic_only": True, "product_acceptance_passed": False, "tun_enabled": False,
              "system_dns_leak_prevention_tested": False,
              "node_evidence": "controlled independent SOCKS route markers, not geographic exit IP",
              "target_app_native_proxy_configured": False}
    adapter = fixture = None
    report_path = args.output / "comparison-report.json"
    try:
        before = settings()
        report["settings_before"] = before
        assets = load_module("windows_free_backend_assets")
        downloads, runtime = ROOT / "downloads", ROOT / "runtime"
        downloads.mkdir(exist_ok=True)
        runtime.mkdir(exist_ok=True)
        shutil.copyfile(Path(__file__).resolve(), ROOT / "actor.py")
        report["assets"] = []
        for name in ("python", "mihomo"):
            value = assets.ASSETS[name]
            archive = downloads / value["name"]
            report["assets"].append(fetch_pinned(value["url"], value["sha256"], archive))
            assets.extract(archive, runtime if name == "python" else ROOT / "mihomo")
        executables = {}
        for role in ("app_a", "app_b", "child_other", "unselected"):
            exe = runtime / ("ruleproxy_" + role + ".exe")
            shutil.copyfile(runtime / "python.exe", exe)
            executables[role] = exe
        report["actor_paths"] = {key: str(value) for key, value in executables.items()}
        adapter = load_module("windows_proxy_compare_" + args.backend).Adapter(ROOT / "backend", args.output)
        report["prepare"] = adapter.prepare()
        write_json(report_path, report)
        mihomo = next((ROOT / "mihomo").glob("*.exe"))
        fixture_module = load_module("windows_proxy_compare_fixture")
        fixture = fixture_module.Fixture(mihomo, args.output / "fixture")
        fixture.__enter__()
        report["fixture"] = fixture.facts()
        native_curl = Path(os.environ["SystemRoot"]) / "System32/curl.exe"
        if not native_curl.is_file():
            raise RuntimeError("Windows inbox curl is unavailable")
        report["backend_start"] = adapter.start(fixture.ports,
            [str(executables["app_a"]), str(executables["app_b"]), str(native_curl)], "A")
        actor_directory = ROOT / "actors"
        actor_directory.mkdir(exist_ok=True)

        def phase(label, role="app_a", count=1, protocol="tcp", family="ipv4", children=False,
                  expected_node="A", connected_udp=False, use_native_curl=False, udp_ports=None):
            token = secrets.token_hex(8)
            spec = {"nonce": fixture.nonce, "token": token, "role": role, "count": count,
                    "target": fixture.target_ipv6 if family == "ipv6" else fixture.target_ipv4,
                    "protocol": protocol, "family": family, "connected_udp": connected_udp}
            if use_native_curl:
                spec["native_curl"] = str(native_curl)
            if udp_ports:
                spec["udp_ports"] = list(udp_ports)
            if children:
                spec["children"] = [{"role": "same_image", "exe": str(executables[role])},
                                    {"role": "different_image", "exe": str(executables["child_other"])}]
            spec_path, result_path = actor_directory / (token + ".spec.json"), actor_directory / (token + ".json")
            write_json(spec_path, spec)
            snapshot_before = fixture.snapshot()
            try:
                result = launch_ordinary(executables[role], spec_path, result_path, username, password)
            except Exception as exc:
                result = {"launcher_error": error_facts(exc), "rows": [], "children": []}
            snapshot_after = fixture.snapshot()
            rows = result.get("rows", [])
            transactions = [entry for entry in snapshot_after["transactions"]
                if entry["sequence"] > snapshot_before["transaction_count"]
                and entry.get("evidence_role") == "actor"
                and token in (entry.get("request_target", "") + entry.get("qname", ""))]
            receiver_counts = {node: sum(entry.get("node") == node and entry["protocol"] in
                ("tcp_http_response", "udp_dns") for entry in transactions) for node in ("A", "B")}
            value = {"label": label, "token": token, "expected_node": expected_node,
                     "result": result, "receiver_before": snapshot_before, "receiver_after": snapshot_after,
                     "matching_receiver_transactions": transactions, "receiver_node_counts": receiver_counts}
            value["marker_responses"] = sum(row.get("controlled_proxy_response") is True and
                                            row.get("node") == expected_node for row in rows)
            value["attempts"] = count * len(udp_ports) if udp_ports else count
            value["direct_response_count"] = sum(bool(not row.get("controlled_proxy_response") and
                (row.get("connected") or row.get("response_received"))) for row in rows)
            report["phases"].append(value)
            write_json(report_path, report)
            print(json.dumps({"phase": label, "marker_responses": value["marker_responses"],
                              "attempts": value["attempts"],
                              "direct_responses": value["direct_response_count"]}), flush=True)
            return value

        phase("unselected_before", "unselected", count=2, expected_node=None)
        phase("selected_app_a_tcp", count=10)
        phase("selected_app_b_tcp", "app_b", count=5)
        phase("selected_native_curl", "unselected", count=3, use_native_curl=True)
        for index in range(5):
            phase("fresh_process_" + str(index), count=1)
        phase("selected_children", children=True)
        phase("selected_udp_sendto", count=3, protocol="udp")
        phase("selected_udp_connected", count=3, protocol="udp", connected_udp=True)
        phase("selected_udp_port_pair", count=3, protocol="udp", udp_ports=(53, 39017))
        phase("selected_udp_port_pair_connected", count=3, protocol="udp", connected_udp=True,
              udp_ports=(53, 39017))
        baseline6 = phase("unselected_ipv6", "unselected", family="ipv6", expected_node=None)
        if baseline6["direct_response_count"]:
            phase("selected_ipv6_tcp", family="ipv6", count=3)
            phase("selected_ipv6_udp", family="ipv6", protocol="udp")
        else:
            report["ipv6_runtime_verdict"] = "unverified: ordinary outside positive control unavailable"
        report["switch_to_b"] = adapter.set_group("B")
        phase("selected_node_b", count=5, expected_node="B")
        phase("unselected_with_rules", "unselected", count=2, expected_node=None)
        fixture.stop_proxy()
        phase("mihomo_down_selected", count=1, expected_node=None)
        phase("mihomo_down_unselected", "unselected", count=1, expected_node=None)
        report["backend_facts"] = adapter.facts()
        report["backend_resources"] = process_resources(report["backend_facts"].get("pid") or
                                                         report["backend_facts"].get("owned_pid"))
        report["backend_stop"] = adapter.stop()
        adapter = None
        phase("backend_stopped_selected", count=1, expected_node=None)
        report["receiver_final"] = fixture.snapshot()
        report["status"] = "diagnostic_completed"
        required = ("selected_app_a_tcp", "selected_app_b_tcp", "selected_native_curl", "selected_node_b", *(
            "fresh_process_" + str(index) for index in range(5)))
        report["core_tcp_routing_observed"] = all(
            row["marker_responses"] == row["attempts"] and
            row["receiver_node_counts"].get(row["expected_node"], 0) >= row["attempts"]
            for row in report["phases"] if row["label"] in required)
        report["ordinary_actor_elevation_verified"] = all(
            phase_row["result"].get("is_elevated") is False for phase_row in report["phases"])
        report["unselected_direct_positive_controls"] = all(
            phase_row["direct_response_count"] == phase_row["attempts"] and
            sum(phase_row["receiver_node_counts"].values()) == 0
            for phase_row in report["phases"] if phase_row["label"] in (
                "unselected_before", "unselected_with_rules", "mihomo_down_unselected"))
        child_phase = next(row for row in report["phases"] if row["label"] == "selected_children")
        report["child_routing"] = {child["role"]: {
            "attempts": len(child.get("rows", [])),
            "proxy_marker_responses": sum(attempt.get("controlled_proxy_response") is True
                and attempt.get("node") == "A" for attempt in child.get("rows", [])),
            "is_elevated": child.get("is_elevated"), "error": child.get("error")}
            for child in child_phase["result"].get("children", [])}
        report["controlled_tcp_median_ms"] = statistics.median(
            attempt["elapsed_ms"] for phase_row in report["phases"]
            if phase_row["label"] in required for attempt in phase_row["result"].get("rows", []))
    except Exception as exc:
        report.update(status="failed_or_incomplete", error=error_facts(exc), traceback=traceback.format_exc()[-6000:])
    finally:
        if adapter is not None:
            try:
                report["backend_cleanup"] = adapter.stop()
            except Exception as exc:
                report["backend_cleanup_error"] = error_facts(exc)
        if fixture is not None:
            try:
                fixture.close()
                report["fixture_cleanup_completed"] = True
            except Exception as exc:
                report["fixture_cleanup_error"] = error_facts(exc)
        try:
            report["settings_after"] = settings()
            report["settings_verified"] = all(isinstance(report.get(stage), dict) and
                all(key in report[stage] for key in ("dns", "default_routes", "winhttp"))
                for stage in ("settings_before", "settings_after"))
            report["settings_unchanged"] = (report["settings_before"] == report["settings_after"]
                if report["settings_verified"] else None)
        except Exception as exc:
            report["settings_read_error"] = error_facts(exc)
        write_json(report_path, report)
    print(json.dumps({key: report.get(key) for key in (
        "backend", "status", "core_tcp_routing_observed", "ordinary_actor_elevation_verified",
        "unselected_direct_positive_controls", "child_routing", "ipv6_runtime_verdict",
        "settings_unchanged")}), flush=True)
    return 0 if (report["status"] == "diagnostic_completed" and
                 report.get("core_tcp_routing_observed") is True and
                 report.get("ordinary_actor_elevation_verified") is True and
                 report.get("unselected_direct_positive_controls") is True) else 1


if __name__ == "__main__":
    raise SystemExit(main())
