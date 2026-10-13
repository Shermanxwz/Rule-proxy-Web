"""Real Windows SDK/BFE denial experiment, restricted to disposable hosted CI.

All probes use real Winsock TCP/UDP and IPv4/IPv6 loopback peers. No result is
an external packet capture, browser test, redirect proof, or release acceptance.
The C++ controller reads installed filter properties back from BFE; a JSON
receipt is never accepted as proof of a live security boundary.
"""

from __future__ import annotations

import argparse
import ctypes
from ctypes import wintypes
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


class SessionProbe:
    """Real suspended Win32 process with a newly created net-only logon SID.

    Deliberately fictitious credentials are not authenticated or used on the
    network. SID text stays in local memory, rather than public evidence.
    """

    def __init__(self, program: Path, argv: list[str], output: Path):
        class Startup(ctypes.Structure):
            _fields_ = [("cb", wintypes.DWORD), ("reserved", wintypes.LPWSTR),
                        ("desktop", wintypes.LPWSTR), ("title", wintypes.LPWSTR),
                        ("x", wintypes.DWORD), ("y", wintypes.DWORD),
                        ("xsize", wintypes.DWORD), ("ysize", wintypes.DWORD),
                        ("xchars", wintypes.DWORD), ("ychars", wintypes.DWORD),
                        ("fill", wintypes.DWORD), ("flags", wintypes.DWORD),
                        ("show", wintypes.WORD), ("reserved_size", wintypes.WORD),
                        ("reserved_data", ctypes.POINTER(ctypes.c_byte)),
                        ("stdin", wintypes.HANDLE), ("stdout", wintypes.HANDLE), ("stderr", wintypes.HANDLE)]

        class Process(ctypes.Structure):
            _fields_ = [("process", wintypes.HANDLE), ("thread", wintypes.HANDLE),
                        ("pid", wintypes.DWORD), ("tid", wintypes.DWORD)]

        class SidAndAttributes(ctypes.Structure):
            _fields_ = [("sid", wintypes.LPVOID), ("attributes", wintypes.DWORD)]

        class Groups(ctypes.Structure):
            _fields_ = [("count", wintypes.DWORD), ("group", SidAndAttributes * 1)]

        self.kernel = ctypes.WinDLL("kernel32", use_last_error=True)
        self.advapi = ctypes.WinDLL("advapi32", use_last_error=True)
        self.kernel.CloseHandle.argtypes = [wintypes.HANDLE]
        self.kernel.CloseHandle.restype = wintypes.BOOL
        self.kernel.ResumeThread.argtypes = [wintypes.HANDLE]
        self.kernel.ResumeThread.restype = wintypes.DWORD
        self.kernel.WaitForSingleObject.argtypes = [wintypes.HANDLE, wintypes.DWORD]
        self.kernel.WaitForSingleObject.restype = wintypes.DWORD
        self.kernel.GetExitCodeProcess.argtypes = [wintypes.HANDLE, ctypes.POINTER(wintypes.DWORD)]
        self.kernel.GetExitCodeProcess.restype = wintypes.BOOL
        self.kernel.TerminateProcess.argtypes = [wintypes.HANDLE, wintypes.UINT]
        self.kernel.TerminateProcess.restype = wintypes.BOOL
        self.kernel.LocalFree.argtypes = [wintypes.HLOCAL]
        self.kernel.LocalFree.restype = wintypes.HLOCAL
        self.advapi.OpenProcessToken.argtypes = [wintypes.HANDLE, wintypes.DWORD, ctypes.POINTER(wintypes.HANDLE)]
        self.advapi.OpenProcessToken.restype = wintypes.BOOL
        self.advapi.GetTokenInformation.argtypes = [wintypes.HANDLE, ctypes.c_int, wintypes.LPVOID,
                                                  wintypes.DWORD, ctypes.POINTER(wintypes.DWORD)]
        self.advapi.GetTokenInformation.restype = wintypes.BOOL
        self.advapi.ConvertSidToStringSidW.argtypes = [wintypes.LPVOID, ctypes.POINTER(wintypes.LPWSTR)]
        self.advapi.ConvertSidToStringSidW.restype = wintypes.BOOL
        self.advapi.CreateProcessWithLogonW.argtypes = [wintypes.LPCWSTR, wintypes.LPCWSTR, wintypes.LPCWSTR,
            wintypes.DWORD, wintypes.LPCWSTR, wintypes.LPWSTR, wintypes.DWORD, wintypes.LPVOID,
            wintypes.LPCWSTR, ctypes.POINTER(Startup), ctypes.POINTER(Process)]
        self.advapi.CreateProcessWithLogonW.restype = wintypes.BOOL
        startup, self.process = Startup(), Process()
        startup.cb = ctypes.sizeof(startup)
        line = subprocess.list2cmdline([str(program), *argv])
        if len(line) >= 1024:
            raise ValueError("net-only probe command exceeds the Win32 API limit")
        mutable_line = ctypes.create_unicode_buffer(line)
        if not self.advapi.CreateProcessWithLogonW(
            "RuleProxyLabSynthetic", ".", "RuleProxyLab-NotAnAccount-42!", 2,
            str(program), mutable_line, 0x08000004, None, str(program.parent),
            ctypes.byref(startup), ctypes.byref(self.process),
        ):
            raise ctypes.WinError(ctypes.get_last_error())
        self.output = output
        token = wintypes.HANDLE()
        try:
            if not self.advapi.OpenProcessToken(self.process.process, 8, ctypes.byref(token)):
                raise ctypes.WinError(ctypes.get_last_error())
            size = wintypes.DWORD()
            self.advapi.GetTokenInformation(token, 28, None, 0, ctypes.byref(size))  # TokenLogonSid
            if ctypes.get_last_error() != 122 or not size.value:
                raise RuntimeError("real child token did not expose a logon SID")
            buffer = ctypes.create_string_buffer(size.value)
            if not self.advapi.GetTokenInformation(token, 28, buffer, size, ctypes.byref(size)):
                raise ctypes.WinError(ctypes.get_last_error())
            groups = ctypes.cast(buffer, ctypes.POINTER(Groups)).contents
            if groups.count != 1:
                raise RuntimeError("real child token has an ambiguous logon SID")
            text_sid = wintypes.LPWSTR()
            if not self.advapi.ConvertSidToStringSidW(groups.group[0].sid, ctypes.byref(text_sid)):
                raise ctypes.WinError(ctypes.get_last_error())
            try:
                self.sid = text_sid.value
            finally:
                self.kernel.LocalFree(ctypes.cast(text_sid, wintypes.HLOCAL))
        except BaseException:
            self.close()
            raise
        finally:
            if token:
                self.kernel.CloseHandle(token)

    def finish(self) -> dict:
        if self.kernel.ResumeThread(self.process.thread) != 1:
            raise RuntimeError("suspended probe thread did not have exactly one suspend count")
        if self.kernel.WaitForSingleObject(self.process.process, 13000) != 0:
            raise TimeoutError("real net-only probe did not exit within its bounded socket deadline")
        code = wintypes.DWORD()
        if not self.kernel.GetExitCodeProcess(self.process.process, ctypes.byref(code)):
            raise ctypes.WinError(ctypes.get_last_error())
        data = json.loads(self.output.read_text(encoding="utf-8"))
        return {"exit": code.value, "root_process_id": self.process.pid,
                "logon_sid_sha256": hashlib.sha256(self.sid.encode()).hexdigest(), **data}

    def close(self):
        if self.process.process:
            if self.kernel.WaitForSingleObject(self.process.process, 0) == 258:
                if not self.kernel.TerminateProcess(self.process.process, 1):
                    raise ctypes.WinError(ctypes.get_last_error())
                if self.kernel.WaitForSingleObject(self.process.process, 5000) != 0:
                    raise RuntimeError("owned net-only probe did not terminate")
            self.kernel.CloseHandle(self.process.process)
            self.process.process = None
        if self.process.thread:
            self.kernel.CloseHandle(self.process.thread)
            self.process.thread = None


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
        session_policies = []
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

        def session_cases(targets: EchoTargets):
            """Measure logon-SID enforcement and an explicit new-token escape."""
            cases = [("baseline", "probe-file", False, False),
                     ("direct", "probe-file", True, True),
                     ("ordinary_child", "spawn-file", True, True),
                     ("new_logon_child", "netonly-spawn-file", True, False)]
            for label, operation, guarded, blocked in cases:
                samples = []
                observations["logon_sid_" + label] = samples
                for index, target in enumerate(targets.targets):
                    output = root / f"session-{label}-{index}.json"
                    arguments = [operation]
                    if operation != "probe-file":
                        arguments.append(str(control))
                    arguments.extend([target["host"], str(target["port"]), target["protocol"], str(output)])
                    session = SessionProbe(protected, arguments, output)
                    policy_key = str(uuid.uuid4())
                    sample = {**target, "filter_committed_before_resume": False}
                    samples.append(sample)
                    try:
                        if guarded:
                            session_policies.append((policy_key, session.sid))
                            record = evidence / f"session-controller-{label}-{index}.json"
                            with record.open("wb") as out:
                                owner = subprocess.Popen([str(executable), "user-hold", policy_key,
                                                          str(protected), session.sid], stdout=out, stderr=subprocess.STDOUT)
                            held.append(owner)
                            wait_record(owner, record, "verified")
                            sample["filter_committed_before_resume"] = True
                            owner.kill()
                            owner.wait(timeout=5)
                            live = command([str(executable), "user-inspect", policy_key, str(protected), session.sid])
                            sample["policy_after_controller_kill"] = live
                            need(live["exit"] == 0 and live.get("verified") is True and live.get("scope") == "logon-sid-only",
                                 "logon_sid_objects_read_back_after_controller_kill")
                        start = targets.count()
                        result = session.finish()
                        time.sleep(0.05)
                        delivered = targets.count() - start
                        sample.update({"probe": result, "peer_deliveries": delivered})
                        if blocked:
                            explicit = result.get("wsa_error") == 10013
                            silent_udp = (target["protocol"] == "udp" and result.get("wsa_error") == 10060
                                          and result.get("stage") == "receive" and result.get("sent_bytes") == 7)
                            need(result["exit"] == 2 and (explicit or silent_udp) and delivered == 0,
                                 "logon_sid_" + label + "_ipv4_ipv6_tcp_udp_blocked")
                        else:
                            need(result["exit"] == 0 and result.get("connected") is True and delivered == 1,
                                 "logon_sid_" + label + "_ipv4_ipv6_tcp_udp_connected")
                        if operation != "probe-file":
                            need(result.get("process_id") != result.get("root_process_id"), "logon_sid_child_is_a_real_separate_process")
                        if guarded:
                            # The same file under the ordinary runner token
                            # must retain its confirmed baseline connectivity.
                            before_control = targets.count()
                            ordinary = command([str(protected), "probe", target["host"], str(target["port"]), target["protocol"]])
                            time.sleep(0.05)
                            sample["same_path_normal_instance"] = ordinary
                            need(ordinary["exit"] == 0 and ordinary.get("connected") is True
                                 and targets.count() - before_control == 1,
                                 "logon_sid_scope_preserves_same_path_normal_instances")
                    finally:
                        # Held process handles establish exit before denial
                        # removal; a PID receipt alone is not sufficient.
                        session.close()
                        if guarded:
                            removed = command([str(executable), "user-remove", policy_key, str(protected), session.sid])
                            sample["cleanup"] = removed
                            need(removed["exit"] == 0 and removed.get("absent") is True, "logon_sid_owned_objects_removed_after_probe_exit")
            report["security_findings"]["logon_sid_scope_contains_ordinary_createprocess_children"] = True
            report["security_findings"]["logon_sid_scope_contains_token_changing_children"] = False
            report["security_findings"]["logon_sid_scope_preserves_same_path_normal_instances"] = True

        try:
            value = command([str(executable), "token-identity", str(protected)])
            observations["netonly_token_identity"] = value
            need(value["exit"] == 0 and value.get("identity_measured") is True
                 and value.get("child_never_resumed") is True and value.get("child_exited") is True
                 and value.get("network_credentials_used") is False,
                 "netonly_token_identity_measured_and_suspended_child_removed")
            # Record local SID identities separately from LSA authentication
            # sessions. Even distinct SIDs would still need live WFP matching
            # and browser/descendant inheritance tests before admission.
            report["security_findings"]["netonly_gives_distinct_logon_sid"] = value.get("logon_sid_distinct") is True
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
                session_cases(targets)
                report["echo_deliveries"] = targets.received
        except Exception as exc:
            report["error"] = f"{type(exc).__name__}: {exc}"
        finally:
            for process in held:
                if process.poll() is None:
                    process.kill()
                    process.wait(timeout=5)
            cleanup = [native("remove", key, target) for key, target in policies]
            cleanup.extend(command([str(executable), "user-remove", key, str(protected), sid])
                           for key, sid in session_policies)
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
