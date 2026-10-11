"""Exercise real MXC processes and the shipped Windows launch path.

No mocks, real node credentials, system proxy, firewall edits, or release writes.
Run after install_runtime.py --platform windows-amd64. A supported host where
the current application cannot start is a failure, even if MXC --probe passes.
"""
from __future__ import annotations

import argparse
import json
import os
from pathlib import Path
import platform
import socket
import struct
import subprocess
import sys
import sysconfig
import tempfile
import threading
import time
import traceback


ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))
from ruleproxy import __version__, windows_runtime as runtime


PAYLOAD = r'''
import json, os, socket, subprocess, sys, threading
from pathlib import Path
output, proxy, fixture, target = sys.argv[1], *map(int, sys.argv[2:5])
result = {"python_bits": 64 if sys.maxsize > 2**32 else 32}
def check(name, action):
    try:
        result[name] = {"ok": True, "value": action()}
    except Exception as exc:
        result[name] = {"ok": False, "error": str(exc), "winerror": getattr(exc, "winerror", None), "errno": getattr(exc, "errno", None)}
def self_roundtrip(family, address):
    with socket.socket(family, socket.SOCK_STREAM) as listener:
        listener.bind((address, 0)); listener.listen(1); listener.settimeout(3)
        with socket.create_connection((address, listener.getsockname()[1]), timeout=3) as client:
            with listener.accept()[0] as accepted:
                accepted.sendall(b"self-ok"); client.settimeout(3)
                if client.recv(7) != b"self-ok": raise RuntimeError("bad local roundtrip")
    return "self-ok"
def child_roundtrip():
    with socket.socket() as listener:
        listener.bind(("127.0.0.1", 0)); listener.listen(1); listener.settimeout(5)
        def respond():
            try:
                with listener.accept()[0] as accepted: accepted.sendall(b"child-ok")
            except OSError: pass
        worker = threading.Thread(target=respond, daemon=True); worker.start()
        script = "import socket,sys; s=socket.create_connection(('127.0.0.1',int(sys.argv[1])),timeout=3); print(s.recv(8).decode()); s.close()"
        child = subprocess.run([sys.executable, "-I", "-S", "-X", "utf8", "-c", script, str(listener.getsockname()[1])], capture_output=True, encoding="utf-8", errors="replace", timeout=8)
        if child.returncode: raise RuntimeError(child.stderr[-600:])
        if child.stdout.strip() != "child-ok": raise RuntimeError("bad child roundtrip")
    return "child-ok"
def greeting():
    with socket.create_connection(("127.0.0.1", proxy), timeout=3) as client:
        client.settimeout(4); client.sendall(b"\x05\x01\x00")
        data = b""
        while len(data) < 2:
            part = client.recv(2-len(data))
            if not part: break
            data += part
        if data != b"\x05\x00": raise RuntimeError("bad SOCKS5 response " + repr(data))
    return "0500"
def tunnel():
    with socket.create_connection(("127.0.0.1", proxy), timeout=3) as client:
        client.settimeout(4)
        request = "CONNECT 127.0.0.1:%d HTTP/1.1\r\nHost: 127.0.0.1:%d\r\n\r\n" % (target, target)
        client.sendall(request.encode("ascii")); data = b""
        while b"\r\n\r\n" not in data and len(data) < 8192:
            part = client.recv(1024)
            if not part: break
            data += part
        header, sep, body = data.partition(b"\r\n\r\n")
        if not sep or b" 200 " not in header.split(b"\r\n", 1)[0]: raise RuntimeError("bad proxy HTTP response " + repr(header[:200]))
        while len(body) < 9:
            part = client.recv(9-len(body))
            if not part: break
            body += part
        if body != b"target-ok": raise RuntimeError("bad proxy data roundtrip " + repr(body))
    return "target-ok"
def connect(address, port):
    with socket.create_connection((address, port), timeout=2): pass
    return "connected"
def udp():
    with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as client:
        client.settimeout(2); client.sendto(b"", ("1.1.1.1", 53))
    return "sent"
check("self_ipv4", lambda: self_roundtrip(socket.AF_INET, "127.0.0.1"))
check("self_ipv6", lambda: self_roundtrip(socket.AF_INET6, "::1"))
check("child_to_parent", child_roundtrip)
check("proxy_greeting", greeting)
check("proxy_data_roundtrip", tunnel)
check("other_host_loopback", lambda: connect("127.0.0.1", fixture))
check("direct_ipv4", lambda: connect("1.1.1.1", 443))
check("direct_ipv6", lambda: connect("2606:4700:4700::1111", 443))
# A successful zero-length send is not evidence of packet delivery. This matches
# the current launch self-check's operation without claiming to prove UDP leakage.
check("empty_udp_send", udp)
Path(output).write_text(json.dumps(result), encoding="ascii")
'''


class Listener:
    def __init__(self, message: bytes):
        self.sock = socket.socket()
        self.sock.bind(("127.0.0.1", 0))
        self.port = self.sock.getsockname()[1]
        self.sock.listen(8)
        self.sock.settimeout(0.2)
        self.message = message
        self.accepted = 0
        self.stopped = threading.Event()
        self.worker = threading.Thread(target=self.run, daemon=True)
        self.worker.start()

    def run(self):
        while not self.stopped.is_set():
            try:
                connection, _ = self.sock.accept()
                self.accepted += 1
                with connection:
                    connection.settimeout(1)
                    connection.sendall(self.message)
            except socket.timeout:
                pass
            except OSError:
                if self.stopped.is_set(): return

    def close(self):
        self.stopped.set()
        self.sock.close()
        self.worker.join(2)


def free_port():
    with socket.socket() as sock:
        sock.bind(("127.0.0.1", 0))
        return sock.getsockname()[1]


def host_info():
    import ctypes
    import winreg
    values = {}
    with winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, r"SOFTWARE\Microsoft\Windows NT\CurrentVersion") as key:
        for name in ("DisplayVersion", "CurrentBuild", "UBR", "InstallationType"):
            try: values[name] = winreg.QueryValueEx(key, name)[0]
            except OSError: values[name] = None
    values.update(python=sys.version.split()[0], python_bits=struct.calcsize("P")*8,
                  python_platform=sysconfig.get_platform(), native_architecture=platform.machine(),
                  runner_architecture=os.environ.get("RUNNER_ARCH"), ruleproxy=__version__, elevated=bool(ctypes.windll.shell32.IsUserAnAdmin()))
    return values


def start_core(folder: Path, proxy: int):
    config = folder / "mihomo.yaml"
    config.write_text(f"mixed-port: {proxy}\nallow-lan: false\nbind-address: 127.0.0.1\nmode: rule\nlog-level: warning\nproxies: []\nrules:\n  - IP-CIDR,127.0.0.1/32,DIRECT,no-resolve\n  - MATCH,REJECT\n", encoding="ascii")
    log = (folder / "mihomo.log").open("wb")
    process = subprocess.Popen([str(ROOT / "bin/windows-amd64/mihomo.exe"), "-d", str(folder), "-f", str(config)], stdout=log, stderr=subprocess.STDOUT)
    deadline = time.monotonic()+20
    while time.monotonic() < deadline:
        if process.poll() is not None:
            log.close()
            raise RuntimeError("Mihomo exited: " + (folder / "mihomo.log").read_text(encoding="utf-8", errors="replace"))
        try:
            with socket.create_connection(("127.0.0.1", proxy), timeout=0.5): return process, log
        except OSError: time.sleep(0.1)
    process.terminate(); process.wait(10); log.close()
    raise RuntimeError("Mihomo did not become ready")


def raw_case(name: str, folder: Path, executable: Path, proxy: int, fixture: int, target: int):
    profile = folder / name
    profile.mkdir()
    script = profile / "payload.py"
    script.write_text(PAYLOAD, encoding="ascii")
    output = profile / "result.json"
    command = [sys.executable, "-I", "-S", "-X", "utf8", str(script), str(output), str(proxy), str(fixture), str(target)]
    policy = runtime.build_policy(command, {}, profile, proxy)
    policy["process"]["commandLine"] = subprocess.list2cmdline(command)
    if name == "model3":
        policy["network"]["ingress"] = {"default": "deny", "hostLoopback": "deny"}
        policy.pop("runtimeConfig", None)
    path = profile / "policy.json"
    path.write_text(json.dumps(policy), encoding="ascii")
    result = {"policy": policy["network"], "executed": False}
    probe = subprocess.run([str(executable), "--probe", "--config", str(path)], capture_output=True, encoding="utf-8", errors="replace", timeout=25)
    result["probe_exit"] = probe.returncode
    try: result["probe"] = json.loads(probe.stdout)
    except ValueError: result["probe_output"] = (probe.stdout+probe.stderr)[-2000:]
    try:
        runtime._probe_request(executable, policy)
    except runtime.UnsupportedRuntimeError as exc:
        result["refusal"] = str(exc)
        return result
    log = (profile / "mxc.log").open("wb")
    process = subprocess.Popen([str(executable), "--config", str(path)], stdout=log, stderr=subprocess.STDOUT)
    result["executed"] = True
    try:
        result["exit"] = process.wait(45)
    except subprocess.TimeoutExpired:
        result["timeout"] = True
        runtime.stop(process, timeout=15)
    finally:
        log.close()
    result["mxc_log_tail"] = (profile / "mxc.log").read_text(encoding="utf-8", errors="replace")[-6000:]
    if output.is_file(): result["inside"] = json.loads(output.read_text(encoding="ascii"))
    return result


def host_control(folder: Path, proxy: int, fixture: int, target: int):
    script, output = folder / "host-payload.py", folder / "host-control.json"
    script.write_text(PAYLOAD, encoding="ascii")
    run = subprocess.run([sys.executable, "-I", "-S", "-X", "utf8", str(script), str(output), str(proxy), str(fixture), str(target)], capture_output=True, encoding="utf-8", errors="replace", timeout=35)
    if run.returncode or not output.is_file():
        raise RuntimeError("host positive control failed: " + run.stderr[-1000:])
    result = json.loads(output.read_text(encoding="ascii"))
    if not result["proxy_greeting"]["ok"] or not result["proxy_data_roundtrip"]["ok"]:
        raise RuntimeError("Mihomo's real proxy did not work on the host: " + json.dumps(result))
    return result


def current_launch(folder: Path, executable: Path, proxy: int, fixture: int, target: int):
    profile = folder / "current-launch"
    profile.mkdir()
    marker = profile / "application-started.txt"
    script = profile / "application.py"
    output = profile / "application-result.json"
    script.write_text(PAYLOAD + "\nimport time\nPath(sys.argv[5]).write_text('started',encoding='ascii')\ntime.sleep(60)\n", encoding="ascii")
    command = [sys.executable, "-I", "-S", str(script), str(output), str(proxy), str(fixture), str(target), str(marker)]
    result = {"started": False, "guest_status": None}
    observed = threading.Event()
    def record_status():
        while not observed.is_set():
            for path in profile.glob(".ruleproxy-runtime/*/guest-status.json"):
                try:
                    value = json.loads(path.read_text(encoding="ascii"))
                    result["guest_status"] = {key:value[key] for key in ("state", "detail") if key in value}
                except (OSError, ValueError): pass
            observed.wait(0.02)
    watcher = threading.Thread(target=record_status, daemon=True)
    watcher.start()
    process = resource = None
    try:
        process, resource = runtime.launch(command, {"HTTP_PROXY": f"http://127.0.0.1:{proxy}"}, profile, proxy, str(executable))
        deadline = time.monotonic()+25
        while not marker.is_file() and time.monotonic() < deadline and process.poll() is None:
            time.sleep(0.05)
        result["started"] = marker.is_file()
        result["detail"] = resource.detail
        if output.is_file(): result["inside"] = json.loads(output.read_text(encoding="ascii"))
        result["guard_fixture_received"] = resource.fixture.accepted.is_set()
    except Exception as exc:
        result.update(error=str(exc), error_type=type(exc).__name__)
        process = getattr(exc, "process", process)
        resource = getattr(exc, "resource", resource)
    finally:
        if process is not None: runtime.stop(process, timeout=15)
        if resource is not None: resource.close()
        observed.set(); watcher.join(2)
    result["application_marker"] = marker.is_file()
    return result


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    args.output.mkdir(parents=True, exist_ok=True)
    report = {"real_windows": os.name == "nt", "mocked": False}
    code = 1
    try:
        if os.name != "nt": raise RuntimeError("This test must run on real Windows")
        report["host"] = host_info()
        executable = ROOT / "bin/windows-amd64/wxc-exec.exe"
        report["public_probe"] = runtime.probe(str(executable))
        with tempfile.TemporaryDirectory(prefix="ruleproxy-native-", ignore_cleanup_errors=True) as temporary:
            folder = Path(temporary)
            proxy = free_port()
            core, log = start_core(folder, proxy)
            fixture, target = Listener(b"fixture-ok"), Listener(b"target-ok")
            try:
                report["host_control"] = host_control(folder, proxy, fixture.port, target.port)
                report["current_launch"] = current_launch(folder, executable, proxy, fixture.port, target.port)
                for name in ("model3", "model2"):
                    report[name] = raw_case(name, folder, executable, proxy, fixture.port, target.port)
                report["fixture_connections"] = fixture.accepted
                report["target_connections"] = target.accepted
            finally:
                fixture.close(); target.close()
                core.terminate(); core.wait(10); log.close()
            if report["public_probe"]["supported"]:
                report["verdict"] = "current-launch-working" if report["current_launch"]["started"] else "current-launch-failed-on-supported-host"
                inside = report["current_launch"].get("inside", {})
                works = all(inside.get(key, {}).get("ok") is True for key in ("proxy_greeting", "proxy_data_roundtrip"))
                denied = all(inside.get(key, {}).get("winerror") == 10013 for key in ("other_host_loopback", "direct_ipv4"))
                code = 0 if report["current_launch"]["started"] and works and denied else 1
            else:
                refused = not report["current_launch"]["application_marker"] and not report["model3"]["executed"]
                report["verdict"] = "unsupported-host-refused-safely" if refused else "unsafe-launch-on-unsupported-host"
                code = 0 if refused else 1
    except Exception:
        report["harness_error"] = traceback.format_exc()
    path = args.output / "report.json"
    path.write_text(json.dumps(report, indent=2, ensure_ascii=False), encoding="utf-8")
    print(json.dumps(report, indent=2, ensure_ascii=True), flush=True)
    summary = os.environ.get("GITHUB_STEP_SUMMARY")
    if summary:
        with open(summary, "a", encoding="utf-8") as stream:
            stream.write("## Real Windows validation\n\n```json\n" + json.dumps(report, indent=2, ensure_ascii=False) + "\n```\n")
    return code


if __name__ == "__main__":
    for stream in (sys.stdout, sys.stderr):
        if stream is not None and hasattr(stream, "reconfigure"): stream.reconfigure(encoding="utf-8", errors="replace")
    raise SystemExit(main())
