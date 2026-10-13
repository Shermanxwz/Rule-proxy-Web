"""Real Windows SDK/BFE denial experiment, restricted to disposable hosted CI.

All probes use real Winsock TCP/UDP and IPv4/IPv6 loopback peers. No result is
an external packet capture, browser test, redirect proof, or release acceptance.
The C++ controller reads installed filter properties back from BFE; a JSON
receipt is never accepted as proof of a live security boundary.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import os
from pathlib import Path
import platform
import shutil
import socket
import subprocess
import tempfile
import threading
import time
import uuid


def command(argv: list[str], timeout: float = 15) -> dict:
    completed = subprocess.run(argv, capture_output=True, text=True, encoding="utf-8", timeout=timeout)
    try:
        value = json.loads(completed.stdout.strip())
    except (ValueError, TypeError):
        value = {"stdout": completed.stdout, "stderr": completed.stderr}
    return {"exit": completed.returncode, **value}


def powershell_json(script: str) -> dict:
    result = subprocess.run(
        ["powershell.exe", "-NoProfile", "-NonInteractive", "-Command", script],
        capture_output=True, text=True, encoding="utf-8", timeout=55,
    )
    if result.returncode:
        raise RuntimeError(f"read-only Windows metadata query failed: {result.stderr}")
    return json.loads(result.stdout.lstrip("\ufeff"))


def os_identity() -> dict:
    return powershell_json(r"""
        $ErrorActionPreference = 'Stop'
        [Console]::OutputEncoding = [Text.UTF8Encoding]::new($false)
        $os = Get-CimInstance Win32_OperatingSystem
        $cpu = Get-CimInstance Win32_Processor | Select-Object -First 1
        [ordered]@{caption=$os.Caption; version=$os.Version; build=$os.BuildNumber;
            product_type=$os.ProductType; os_architecture=$os.OSArchitecture;
            cpu_architecture=$cpu.Architecture; runner_arch=$env:RUNNER_ARCH;
            image_os=$env:ImageOS; image_version=$env:ImageVersion} | ConvertTo-Json -Compress
    """)


def state_digest() -> str:
    # Compare exact configuration without publishing proxy strings, node data,
    # machine identifiers or unrelated filter contents in a public artifact.
    value = powershell_json(r"""
        $ErrorActionPreference = 'Stop'
        [Console]::OutputEncoding = [Text.UTF8Encoding]::new($false)
        $settings = Get-ItemProperty 'HKCU:\Software\Microsoft\Windows\CurrentVersion\Internet Settings'
        [ordered]@{
            winhttp=@(netsh winhttp show proxy)
            user_proxy=@($settings.ProxyEnable,$settings.ProxyServer,$settings.AutoConfigURL)
            dns=@(Get-DnsClientServerAddress | Sort-Object InterfaceIndex,AddressFamily |
                Select-Object InterfaceIndex,AddressFamily,ServerAddresses)
            routes=@(Get-NetRoute | Sort-Object InterfaceIndex,DestinationPrefix,NextHop |
                Select-Object InterfaceIndex,DestinationPrefix,NextHop,RouteMetric)
            firewall=@(Get-NetFirewallProfile | Sort-Object Name |
                Select-Object Name,Enabled,DefaultInboundAction,DefaultOutboundAction)
        } | ConvertTo-Json -Depth 8 -Compress
    """)
    return hashlib.sha256(json.dumps(value, sort_keys=True).encode()).hexdigest()


class EchoTargets:
    """Four real loopback listeners, with independently recorded deliveries."""

    def __init__(self):
        self.sockets: list[socket.socket] = []
        self.threads: list[threading.Thread] = []
        self.targets: list[dict] = []
        self.received: list[dict] = []
        self.lock = threading.Lock()
        self.stopped = threading.Event()

    def __enter__(self):
        try:
            for family, host in [(socket.AF_INET, "127.0.0.1"), (socket.AF_INET6, "::1")]:
                for kind, protocol in [(socket.SOCK_STREAM, "tcp"), (socket.SOCK_DGRAM, "udp")]:
                    server = socket.socket(family, kind)
                    self.sockets.append(server)
                    if family == socket.AF_INET6:
                        server.setsockopt(socket.IPPROTO_IPV6, socket.IPV6_V6ONLY, 1)
                    server.bind((host, 0))
                    server.settimeout(0.2)
                    if protocol == "tcp":
                        server.listen(8)
                    target = {"host": host, "port": server.getsockname()[1], "protocol": protocol}
                    self.targets.append(target)
                    worker = threading.Thread(target=self._serve, args=(server, target), daemon=True)
                    self.threads.append(worker)
                    worker.start()
        except BaseException:
            self.__exit__(None, None, None)
            raise
        return self

    def _serve(self, server: socket.socket, target: dict):
        while not self.stopped.is_set():
            try:
                if target["protocol"] == "tcp":
                    peer, _ = server.accept()
                    with peer:
                        peer.settimeout(2)
                        data = bytearray()
                        while len(data) < 7:
                            chunk = peer.recv(7 - len(data))
                            if not chunk:
                                break
                            data.extend(chunk)
                        peer.sendall(data)
                else:
                    data, address = server.recvfrom(128)
                    server.sendto(data, address)
                with self.lock:
                    self.received.append({**target, "bytes": len(data)})
            except (OSError, TimeoutError):
                continue

    def count(self) -> int:
        with self.lock:
            return len(self.received)

    def __exit__(self, *_):
        self.stopped.set()
        for server in self.sockets:
            server.close()
        for worker in self.threads:
            worker.join(3)


def wait_record(process: subprocess.Popen, output: Path, field: str) -> dict:
    deadline = time.monotonic() + 15
    while time.monotonic() < deadline:
        if output.is_file():
            try:
                result = json.loads(output.read_text(encoding="utf-8"))
                if result.get(field):
                    return result
                if "error_code" in result:
                    raise RuntimeError(f"native controller refused: {result}")
            except (OSError, ValueError):
                pass
        if process.poll() is not None:
            raise RuntimeError(f"native controller exited before {field}: {process.returncode}")
        time.sleep(0.05)
    raise TimeoutError(f"native controller did not publish {field}")


def run(executable: Path, evidence: Path) -> dict:
    report = {
        "environment": "GitHub-hosted Windows virtual machine; real kernel, not a physical device",
        "os": os_identity(), "binary_sha256": hashlib.sha256(executable.read_bytes()).hexdigest(),
        "accepted": False, "lab_passed": False, "scope": "executable-path-only",
        "security_findings": {},
        "checks": {}, "observations": {}, "error": None,
        "unproved": ["transparent redirect", "unique descendant identity", "external IPv6 route and packet capture",
                     "browser login and cookies", "reboot and boot-time enforcement", "signed production callout"],
    }
    try:
        before = state_digest()
    except Exception as exc:
        before = None
        report["system_state_before_error"] = f"{type(exc).__name__}: {exc}"
    report["system_state_before_sha256"] = before
    checks, observations = report["checks"], report["observations"]
    with tempfile.TemporaryDirectory(prefix="ruleproxy-wfp-", dir=os.environ["RUNNER_TEMP"]) as folder:
        root = Path(folder)
        programs = []
        for name in ("protected", "control", "owned-canary"):
            target = root / name / "RuleProxyNativeProbe.exe"
            target.parent.mkdir()
            shutil.copyfile(executable, target)
            programs.append(target)
        protected, control, canary = programs
        seed, canary_seed, pending_seed = [str(uuid.uuid4()) for _ in range(3)]
        report["policy_guids"] = {"primary": seed, "owned_canary": canary_seed, "aborted": pending_seed}
        policies = [(seed, protected), (canary_seed, canary), (pending_seed, protected)]
        held: list[subprocess.Popen] = []

        def native(operation: str, key: str, target: Path) -> dict:
            return command([str(executable), operation, key, str(target)])

        def need(condition: bool, name: str):
            checks[name] = bool(condition)
            if not condition:
                raise RuntimeError(f"real Windows lab check failed: {name}")

        def group(label: str, program: Path, targets: EchoTargets, blocked: bool, child: Path | None = None):
            results = []
            start = targets.count()
            observations[label] = {"probes": results, "peer_deliveries": None}
            for target in targets.targets:
                prefix = [str(program), "spawn", str(child)] if child else [str(program), "probe"]
                result = command([*prefix, target["host"], str(target["port"]), target["protocol"]])
                results.append({**target, **result})
            time.sleep(0.05)
            delivered = targets.count() - start
            observations[label] = {"probes": results, "peer_deliveries": delivered}
            if blocked:
                # UDP can be silently discarded at ALE despite a successful
                # send. Only a bounded receive timeout at a baseline-confirmed
                # loopback peer, zero deliveries and verified persistent filters
                # are recorded as a local UDP drop. No external-route claim.
                def denied(result):
                    explicit = result.get("wsa_error") == 10013
                    silent_udp = (result["protocol"] == "udp" and result.get("wsa_error") == 10060
                                  and result.get("stage") == "receive" and result.get("sent_bytes") == 7)
                    return result["exit"] == 2 and (explicit or silent_udp)
                need(all(denied(r) for r in results) and delivered == 0, label)
            else:
                need(all(r.get("connected") is True and r["exit"] == 0 for r in results) and delivered == 4, label)

        def hold(operation: str, key: str, output_name: str, field: str) -> subprocess.Popen:
            output = evidence / output_name
            with output.open("wb") as out:
                process = subprocess.Popen([str(executable), operation, key, str(protected)], stdout=out, stderr=subprocess.STDOUT)
            held.append(process)
            observations[operation] = wait_record(process, output, field)
            return process

        try:
            with EchoTargets() as targets:
                group("baseline_ipv4_ipv6_tcp_udp", protected, targets, False)
                pending = hold("abort-hold", pending_seed, "pending-controller.json", "transaction_pending")
                pending.kill()
                pending.wait(timeout=5)
                deadline = time.monotonic() + 5
                while time.monotonic() < deadline:
                    value = native("inspect", pending_seed, protected)
                    if value.get("absent") is True:
                        break
                    time.sleep(0.1)
                observations["aborted_transaction"] = value
                need(value.get("absent") is True and value["exit"] == 0, "uncommitted_transaction_rolls_back_on_kill")
                group("after_aborted_install_connectivity", protected, targets, False)
                controller = hold("hold", seed, "committed-controller.json", "verified")
                controller.kill()
                controller.wait(timeout=5)
                value = native("inspect", seed, protected)
                observations["after_controller_kill"] = value
                need(value.get("verified") is True and value.get("object_count") == 5 and value["exit"] == 0,
                     "persistent_objects_verified_after_controller_kill")
                group("blocked_after_controller_kill_ipv4_ipv6_tcp_udp", protected, targets, True)
                group("same_basename_other_path_unaffected", control, targets, False)

                # These are deliberately measured negative security findings.
                # A passing denial lab must never become process-tree admission.
                group("same_path_new_instances_also_blocked", protected, targets, True)
                report["security_findings"]["unrelated_instance_of_same_executable_unaffected"] = False
                group("different_path_child_can_connect", protected, targets, False, child=control)
                need(native("inspect", seed, protected).get("verified") is True,
                     "child_escape_measured_while_parent_policy_is_active")
                report["security_findings"]["full_process_tree_contained"] = False

                wrong = native("remove", seed, control)
                observations["wrong_app_cleanup_refusal"] = wrong
                need(wrong["exit"] != 0 and native("inspect", seed, protected).get("verified") is True,
                     "cleanup_rejects_wrong_application_receipt")
                observations["canary_install"] = native("install", canary_seed, canary)
                need(observations["canary_install"].get("verified") is True, "independent_owned_canary_installed")
                observations["primary_remove"] = native("remove", seed, protected)
                need(observations["primary_remove"].get("absent") is True, "primary_objects_removed")
                need(native("inspect", canary_seed, canary).get("verified") is True, "other_policy_preserved_by_cleanup")
                group("other_policy_still_blocks", canary, targets, True)
                group("after_cleanup_connectivity_restored", protected, targets, False)
                need(native("remove", seed, protected).get("absent") is True, "cleanup_is_idempotent")
                report["echo_deliveries"] = targets.received
        except Exception as exc:
            report["error"] = f"{type(exc).__name__}: {exc}"
        finally:
            for process in held:
                if process.poll() is None:
                    process.kill()
                    process.wait(timeout=5)
            cleanup = [native("remove", key, target) for key, target in policies]
            observations["final_cleanup"] = cleanup
            checks["all_owned_wfp_objects_absent"] = all(value["exit"] == 0 and value.get("absent") is True for value in cleanup)
            if not checks["all_owned_wfp_objects_absent"]:
                report["error"] = report["error"] or "owned native WFP lab objects remain installed"
    try:
        after = state_digest()
    except Exception as exc:
        after = None
        report["system_state_after_error"] = f"{type(exc).__name__}: {exc}"
    report["system_state_after_sha256"] = after
    checks["global_proxy_dns_routes_firewall_profiles_unchanged"] = before is not None and after is not None and before == after
    report["lab_passed"] = report["error"] is None and len(checks) >= 15 and all(checks.values())
    return report


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("executable", type=Path)
    parser.add_argument("--evidence", type=Path, default=Path("native-wfp-evidence"))
    args = parser.parse_args()
    if os.name != "nt" or os.environ.get("GITHUB_ACTIONS") != "true" or not os.environ.get("RUNNER_TEMP"):
        raise SystemExit("Native WFP lab requires a disposable GitHub-hosted Windows runner")
    args.evidence.mkdir(parents=True, exist_ok=True)
    try:
        report = run(args.executable.resolve(strict=True), args.evidence)
    except Exception as exc:
        report = {"accepted": False, "lab_passed": False, "platform": platform.platform(), "error": f"{type(exc).__name__}: {exc}"}
    (args.evidence / "native-wfp.json").write_text(json.dumps(report, indent=2) + "\n", encoding="utf-8")
    print(json.dumps(report, indent=2), flush=True)
    return 0 if report["lab_passed"] else 1


if __name__ == "__main__":
    raise SystemExit(main())
