"""Acceptance tooling must identify emulation and verify portable runtimes."""
import hashlib
from contextlib import ExitStack
import importlib.util
import io
import json
import os
from pathlib import Path
import socket
import struct
import subprocess
import threading
import sys
import tempfile
import time
from types import SimpleNamespace
import unittest
from unittest import mock


SCRIPT = Path(__file__).resolve().parent.parent / "scripts" / "windows-acceptance.py"
acceptance = None
if SCRIPT.is_file():
    spec = importlib.util.spec_from_file_location("ruleproxy_acceptance_checks", SCRIPT)
    acceptance = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(acceptance)


@unittest.skipIf(acceptance is None, "standalone acceptance script is absent from this copy")
class WindowsAcceptanceTests(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        self.root = Path(self.temporary.name)

    def test_cli_runs_outside_project_root_without_importing_checkout(self):
        script = SCRIPT.resolve()
        with tempfile.TemporaryDirectory(prefix="acceptance-outside-cwd-") as temporary:
            help_result = subprocess.run(
                [sys.executable, str(script), "--help"], cwd=temporary,
                capture_output=True, text=True, timeout=10)
            self.assertEqual(help_result.returncode, 0, help_result.stderr)
            self.assertIn("--probe-only", help_result.stdout)

            probe_result = subprocess.run(
                [sys.executable, str(script), "--probe-only", "--report",
                 str(Path(temporary) / "probe-report.json")], cwd=temporary,
                capture_output=True, text=True, timeout=15)
            self.assertNotIn("ModuleNotFoundError", probe_result.stderr)
            self.assertEqual(probe_result.returncode, 3, probe_result.stderr)

    def executable(self, machine, path=None):
        header = bytearray(64)
        header[:2] = b"MZ"
        struct.pack_into("<I", header, 60, 64)
        path = path or self.root / "python.exe"
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_bytes(header + b"PE\0\0" + struct.pack("<H", machine))
        return path

    def test_arm_host_with_unknown_wow64_machine_uses_python_pe_machine(self):
        executable = self.executable(0x8664)
        kernel = mock.Mock()

        def machine_info(_handle, process, native):
            process._obj.value, native._obj.value = 0, 0xAA64
            return True

        kernel.IsWow64Process2.side_effect = machine_info
        with mock.patch.object(sys, "platform", "win32"), \
                mock.patch.object(sys, "getwindowsversion", create=True,
                                  return_value=SimpleNamespace(build=26200, product_type=1)), \
                mock.patch.object(sys, "executable", str(executable)), \
                mock.patch("ctypes.WinDLL", create=True, return_value=kernel):
            facts = acceptance.host_facts()
        self.assertEqual(facts["process_machine"], 0)
        self.assertEqual(facts["python_pe_machine"], 0x8664)
        self.assertEqual(facts["acceptance_scope"], "x64_on_arm_emulation")

    def test_native_architectures_and_invalid_executable_headers(self):
        self.assertEqual(acceptance.acceptance_scope(0x8664, 0x8664), "native_x64")
        self.assertEqual(acceptance.acceptance_scope(0xAA64, 0xAA64), "native_arm64_probe")
        self.assertEqual(acceptance.executable_machine(self.executable(0xAA64)), 0xAA64)
        path = self.root / "python.exe"
        for data in (b"not PE", b"MZ" + bytes(62), b"MZ" + bytes(58) + struct.pack("<I", 0xFFFFFFFF)):
            with self.subTest(data=data[:8]):
                path.write_bytes(data)
                with self.assertRaises(ValueError):
                    acceptance.executable_machine(path)

    def test_snapshot_prefers_native_system_powershell_on_arm(self):
        emulated = self.executable(0x8664, self.root / "Sysnative/WindowsPowerShell/v1.0/powershell.exe")
        native = self.executable(0xAA64, self.root / "System32/WindowsPowerShell/v1.0/powershell.exe")
        with mock.patch.dict(os.environ, {"SystemRoot": str(self.root)}):
            self.assertEqual(acceptance.select_powershell(0xAA64), (native, 0xAA64))
            native.unlink()
            self.assertEqual(acceptance.select_powershell(0xAA64), (emulated, 0x8664))
            emulated.unlink()
            with self.assertRaises(RuntimeError):
                acceptance.select_powershell(0xAA64)

    def test_snapshot_has_cold_cim_budget_and_never_logs_configuration(self):
        record = {"dns": [], "routes": [], "proxy": {"server": "private-proxy-password"}, "winhttp": "private-config"}
        powershell = self.root / "powershell.exe"
        with mock.patch.object(acceptance, "host_facts", return_value={"native_machine": 0xAA64}), \
                mock.patch.object(acceptance, "select_powershell", return_value=(powershell, 0xAA64)), \
                mock.patch.object(acceptance.subprocess, "run", return_value=SimpleNamespace(
                    stdout=json.dumps(record), stderr="RULEPROXY_SNAPSHOT_STAGE=serialize\n")) as run, \
                mock.patch.object(sys, "stderr", new_callable=io.StringIO) as logged:
            digest = acceptance.network_snapshot()
            self.assertEqual(len(digest), 64)
            self.assertEqual(run.call_args.kwargs["timeout"], 120)
            self.assertEqual(run.call_args.args[0][0], str(powershell))
            self.assertIn("snapshot completed", logged.getvalue())
            self.assertNotIn("private-proxy-password", logged.getvalue())
            self.assertNotIn("private-config", logged.getvalue())

    def test_snapshot_timeout_and_failure_keep_fixed_stage_without_raw_output(self):
        output = b"RULEPROXY_SNAPSHOT_STAGE=dns\nprivate password must not be echoed\n"
        errors = (
            subprocess.TimeoutExpired(["private command"], 120, stderr=output),
            subprocess.CalledProcessError(1, ["private command"], stderr=output),
        )
        for error in errors:
            with self.subTest(error=type(error).__name__), \
                    mock.patch.object(acceptance, "host_facts", return_value={"native_machine": 0xAA64}), \
                    mock.patch.object(acceptance, "select_powershell", return_value=(Path("powershell.exe"), 0xAA64)), \
                    mock.patch.object(acceptance.subprocess, "run", side_effect=error), \
                    mock.patch.object(sys, "stderr", new_callable=io.StringIO):
                with self.assertRaises(RuntimeError) as raised:
                    acceptance.network_snapshot()
                self.assertIn("during dns", str(raised.exception))
                self.assertNotIn("private", str(raised.exception))

    def test_snapshot_rejects_an_empty_json_value_instead_of_claiming_a_hash(self):
        with mock.patch.object(acceptance, "host_facts", return_value={"native_machine": 0x8664}), \
                mock.patch.object(acceptance, "select_powershell", return_value=(Path("powershell.exe"), 0x8664)), \
                mock.patch.object(acceptance.subprocess, "run", return_value=SimpleNamespace(stdout="null", stderr="")), \
                mock.patch.object(sys, "stderr", new_callable=io.StringIO):
            with self.assertRaises(RuntimeError):
                acceptance.network_snapshot()

    def manifest(self):
        directory = self.root / "bin" / "windows-amd64"
        directory.mkdir(parents=True)
        files = {name: ("fixture " + name).encode() for name in acceptance.RUNTIME_REQUIRED_FILES}
        files["additional.dll"] = b"additional runtime dependency"
        pins = (
            mock.patch.object(acceptance, "MXC_G_EXECUTOR_SHA256", hashlib.sha256(files["wxc-exec.exe"]).hexdigest()),
            mock.patch.object(acceptance, "MXC_G_LICENSE_SHA256", hashlib.sha256(files["MXC-LICENSE.md"]).hexdigest()),
        )
        for pin in pins:
            pin.start()
            self.addCleanup(pin.stop)
        for name, data in files.items():
            (directory / name).write_bytes(data)
        record = dict(acceptance.RUNTIME_VERSIONS)
        record["sha256"] = {name: hashlib.sha256(data).hexdigest() for name, data in files.items()}
        manifest = directory / "runtime.json"
        manifest.write_text(json.dumps(record), encoding="utf-8")
        return directory, manifest, record

    def test_portable_manifest_needs_no_builder_and_checks_additional_dll(self):
        directory, _manifest, record = self.manifest()
        self.assertFalse((self.root / "install_runtime.py").exists())
        self.assertEqual(acceptance.verify_runtime_manifest(self.root), record["sha256"])
        (directory / "additional.dll").write_bytes(b"tampered dependency")
        with self.assertRaises(ValueError):
            acceptance.verify_runtime_manifest(self.root)

    def test_portable_manifest_cannot_repin_a_replaced_g_executor(self):
        directory, manifest, record = self.manifest()
        replacement = b"replacement executor with a self-consistent local manifest"
        (directory / "wxc-exec.exe").write_bytes(replacement)
        record["sha256"]["wxc-exec.exe"] = hashlib.sha256(replacement).hexdigest()
        manifest.write_text(json.dumps(record), encoding="utf-8")
        with self.assertRaisesRegex(ValueError, "fixed G executor"):
            acceptance.verify_runtime_manifest(self.root)

    def test_missing_executable_unlisted_file_versions_and_path_traversal_fail(self):
        directory, manifest, original = self.manifest()
        (directory / "mihomo.exe").unlink()
        with self.assertRaises(ValueError):
            acceptance.verify_runtime_manifest(self.root)
        (directory / "mihomo.exe").write_bytes(b"fixture mihomo.exe")
        (directory / "unknown.exe").write_bytes(b"unknown")
        with self.assertRaises(ValueError):
            acceptance.verify_runtime_manifest(self.root)
        (directory / "unknown.exe").unlink()
        for mutate in (lambda value: value.update(mxc="old"),
                       lambda value: value["sha256"].update({"../outside.dll": "a" * 64}),
                       lambda value: value["sha256"].update({"C:\\outside.dll": "a" * 64})):
            value = json.loads(json.dumps(original))
            mutate(value)
            manifest.write_text(json.dumps(value), encoding="utf-8")
            with self.assertRaises(ValueError):
                acceptance.verify_runtime_manifest(self.root)

    def test_project_origin_accepts_loaded_product_and_rejects_other_root(self):
        import ruleproxy
        actual = Path(ruleproxy.__file__).resolve().parent.parent
        acceptance.verify_project_origin(actual)
        (self.root / "ruleproxy").mkdir()
        (self.root / "ruleproxy" / "__init__.py").write_text("", encoding="utf-8")
        with self.assertRaises(ValueError):
            acceptance.verify_project_origin(self.root)

    def test_fixture_negotiation_cross_frame_payload_and_both_fin_directions(self):
        fixture = acceptance.FixedTransportFixture()
        self.addCleanup(fixture.close)
        with socket.create_connection(("127.0.0.1", fixture.port), timeout=3) as connection:
            connection.sendall(b"\x05\x01\0")
            self.assertEqual(connection.recv(2), b"\x05\0")
        with mock.patch.dict(os.environ, {"HTTPS_PROXY": f"http://127.0.0.1:{fixture.port}"}):
            result = acceptance.fixture_roundtrip(fixture.token)
        self.assertGreater(result["payload_bytes_each_direction"], 4 * 16384)
        self.assertTrue(result["bidirectional_fin"])
        self.assertFalse(result["real_node_passed"])
        deadline = time.monotonic() + 2
        while time.monotonic() < deadline and fixture.roundtrips != 1:
            time.sleep(0.01)
        self.assertEqual(fixture.roundtrips, 1)
        self.assertEqual(fixture.errors, [])
        fixture.close()
        with mock.patch.dict(os.environ, {"HTTPS_PROXY": f"http://127.0.0.1:{fixture.port}"}):
            with self.assertRaises(OSError):
                acceptance.fixture_roundtrip(fixture.token)

    def test_connect_response_accepts_mihomo_reason_phrase_but_requires_bounded_200(self):
        for response in (b"HTTP/1.1 200 Connection Established\r\n\r\n",
                         b"HTTP/1.1 200 Connection established\r\n\r\n",
                         b"HTTP/1.0 200 OK\r\nContent-Length: 0\r\n\r\n"):
            acceptance.validate_connect_response(response)
        for response in (b"HTTP/1.1 502 Bad Gateway\r\n\r\n", b"HTTP/2 200 OK\r\n\r\n",
                         b"HTTP/1.1 200 OK\r\n", b"HTTP/1.1 200 OK\r\nX: " + b"x" * 4096 + b"\r\n\r\n"):
            with self.subTest(response=response[:32]):
                with self.assertRaises(RuntimeError):
                    acceptance.validate_connect_response(response)

    def test_public_udp_api_results_remain_diagnostic_without_short_circuiting_tcp(self):
        from ruleproxy import windows_guest
        self.assertEqual(acceptance._UDP_PROBE_DATAGRAM, windows_guest._UDP_PROBE_DATAGRAM)
        for outcome, expected in ((len(acceptance._UDP_PROBE_DATAGRAM), {"ok": False, "code": "allowed"}),
                                  (0, {"ok": False, "code": "short_send"}),
                                  (OSError(10013, "denied"), {"ok": True, "code": 10013}),
                                  (OSError(10051, "unavailable"), {"ok": False, "code": 10051}),
                                  (TimeoutError(), {"ok": False, "code": "timeout"})):
            with self.subTest(code=expected["code"]), mock.patch("socket.socket") as factory:
                sender = factory.return_value.__enter__.return_value
                if isinstance(outcome, Exception):
                    sender.sendto.side_effect = outcome
                else:
                    sender.sendto.return_value = outcome
                self.assertEqual(acceptance.public_udp_diagnostics(), dict(ipv4_udp=expected, ipv6_udp=expected))
                self.assertEqual(sender.sendto.call_args_list, [
                    mock.call(acceptance._UDP_PROBE_DATAGRAM, ("1.1.1.1", 53)),
                    mock.call(acceptance._UDP_PROBE_DATAGRAM, ("2606:4700:4700::1111", 53, 0, 0))])
                sender.connect.assert_not_called()
        with mock.patch.object(acceptance, "denied", side_effect=lambda family, kind, addr, name:
                               {"check": name, "status": "passed", "socket_error": 10013}) as denied:
            checks = acceptance.network_checks(19001, 19002)
        self.assertEqual(len(checks), 4)
        self.assertTrue(all(call.args[1] == socket.SOCK_STREAM for call in denied.call_args_list))

    def test_manager_socks_fixture_accepts_only_fixed_destination_and_fin_payload(self):
        fixture = acceptance.FixedSocksFixture()
        self.addCleanup(fixture.close)
        payload = acceptance.fixture_payload(fixture.token)
        with socket.create_connection(("127.0.0.1", fixture.port), timeout=3) as connection:
            connection.settimeout(3)
            connection.sendall(b"\x05\x01\0")
            self.assertEqual(fixture._read_exact(connection, 2), b"\x05\0")
            host = fixture.host.encode("ascii")
            connection.sendall(b"\x05\x01\0\x03" + bytes([len(host)]) + host + struct.pack("!H", 443))
            self.assertEqual(fixture._read_exact(connection, 10), b"\x05\0\0\x01\x7f\0\0\x01\0\0")
            connection.sendall(payload)
            connection.shutdown(socket.SHUT_WR)
            echoed = bytearray()
            while True:
                part = connection.recv(16384)
                if not part:
                    break
                echoed.extend(part)
            self.assertEqual(bytes(echoed), payload[::-1])
        deadline = time.monotonic() + 2
        while time.monotonic() < deadline and fixture.roundtrips != 1:
            time.sleep(0.01)
        self.assertEqual(fixture.roundtrips, 1)
        self.assertEqual(fixture.errors, [])
        with socket.create_connection(("127.0.0.1", fixture.port), timeout=3) as connection:
            connection.settimeout(3)
            connection.sendall(b"\x05\x01\0")
            self.assertEqual(fixture._read_exact(connection, 2), b"\x05\0")
            wrong = b"unrelated.example"
            connection.sendall(b"\x05\x01\0\x03" + bytes([len(wrong)]) + wrong + struct.pack("!H", 443))
            self.assertEqual(connection.recv(1), b"")
        self.assertEqual(fixture.roundtrips, 1)

    def test_manager_override_changes_only_owned_core_endpoint_and_preserves_import_guard(self):
        import yaml
        from ruleproxy.config import compile_config
        fixture = acceptance.FixedSocksFixture()
        self.addCleanup(fixture.close)
        source = acceptance.manager_fixture_source(fixture)
        compiled = compile_config(source, secret="test-controller-token")
        original = json.loads(json.dumps(compiled.config))
        manager = SimpleNamespace(core=mock.Mock(), compiled=compiled, _controller=mock.Mock())
        manager.core.poll.return_value = None
        metadata = acceptance.reload_manager_fixture(manager, fixture)
        self.assertTrue(metadata["test_only_endpoint_override"])
        self.assertEqual(manager.compiled.config, original)
        call = manager._controller.call_args
        self.assertEqual(call.args[:2], ("PUT", "/configs?force=true"))
        actual = yaml.safe_load(call.args[2]["payload"])
        self.assertEqual(actual["proxies"][0]["server"], "127.0.0.1")
        actual["proxies"][0]["server"] = "upstream.ruleproxy.invalid"
        self.assertEqual(actual, original)
        with self.assertRaises(ValueError):
            compile_config(source.replace("upstream.ruleproxy.invalid", "127.0.0.1"), secret="test-token")
        manager.core.poll.return_value = 1
        with self.assertRaises(RuntimeError):
            acceptance.reload_manager_fixture(manager, fixture)

    @staticmethod
    def startup_resources():
        from ruleproxy import windows_guest
        nonce = "a" * 64
        reports = {}
        for role, pid, ppid in (("parent", 123, 100), ("child", 456, 123)):
            proxy = "proxy_self" if role == "parent" else "proxy_parent"
            reports[role] = {"scope": role, "pid": pid, "parent_pid": ppid, "process_created": pid * 100,
                             "checks": {proxy: {"ok": True, "code": "ok"},
                                        **{name: {"ok": True, "code": 10013} for name in windows_guest._MANDATORY_DENY_PROBES}},
                             "public_udp": {"ipv4_udp": {"ok": False, "code": "allowed"},
                                            "ipv6_udp": {"ok": False, "code": 10051}},
                             "local_udp": {family: {"state": "access_denied", "stage": "send", "code": 10013,
                                                     "sent_bytes": None} for family in ("ipv4", "ipv6")}}
        return SimpleNamespace(startup_diagnostics={"schema_version": 1, "nonce": nonce, **reports,
                               "config_readonly": {"ok": True, "code": 5},
                               "aux": {"parent_ipv6_loopback": {"ok": False, "code": 10013}}},
                               host_ipv6_observation={"scope": "fixed_ipv6_tcp_route_probe", "host_ipv6_route_unavailable": False,
                                                      "code": "connected", "kernel_denial_proven": False},
                               udp_observation={"scope": "fixed_host_loopback_endpoints", "non_delivery_observed": True,
                               "kernel_denial_proven": False, "public_udp_proven": False, "dns_proven": False,
                               "observations": {family: {"before_received": 1, "after_received": 1,
                                                         "parent_received": 0, "child_received": 0}
                                                for family in ("ipv4", "ipv6")}}, close=mock.Mock())

    def test_startup_evidence_copies_actual_scoped_records_and_refuses_missing_controls(self):
        resources = self.startup_resources()
        result = acceptance.startup_evidence(resources)
        self.assertEqual(result["startup_diagnostics"]["config_readonly"], {"ok": True, "code": 5})
        self.assertFalse(result["public_udp_proven"])
        self.assertFalse(result["system_dns_proven"])
        self.assertNotIn("nonce", result["startup_diagnostics"])
        self.assertIn("nonce", resources.startup_diagnostics, "copying evidence must not mutate runtime ownership")
        resources.udp_observation["observations"]["ipv6"]["after_received"] = 0
        with self.assertRaisesRegex(RuntimeError, "controls"):
            acceptance.startup_evidence(resources)

    def test_guest_continues_proxy_after_public_udp_accepted_and_route_error(self):
        proxy = {"check": "fixed_loopback_transport_cross_frame_fin", "status": "passed"}
        def tcp_checks(_v4, _v6, **kwargs):
            return [{"check": name, "status": "passed", "socket_error": 10013} for name in
                    ("direct_ipv4_tcp", "direct_ipv6_tcp", "guest_to_host_ipv4", "guest_to_host_ipv6")]
        with mock.patch.object(acceptance, "network_checks", side_effect=tcp_checks), \
                mock.patch.object(acceptance, "guest_host_ipv6_unavailable", return_value=False), \
                mock.patch.object(acceptance, "fixture_roundtrip", return_value=proxy) as roundtrip, \
                mock.patch.object(acceptance, "public_udp_diagnostics", return_value={
                    "ipv4_udp": {"ok": False, "code": "allowed"}, "ipv6_udp": {"ok": False, "code": 10051}}), \
                mock.patch.object(acceptance, "write_json") as write, \
                mock.patch.object(acceptance.time, "sleep", side_effect=KeyboardInterrupt):
            with self.assertRaises(KeyboardInterrupt):
                acceptance.guest_main(["--role", "child", "--fixture-token", "a" * 64,
                                      "--host-v4-port", "19001", "--host-v6-port", "19002", "--run-token", "b" * 64])
        roundtrip.assert_called_once()
        report = write.call_args.args[1]
        self.assertEqual(report["status"], "passed")
        self.assertFalse(report["public_udp"]["ipv4_udp"]["ok"])
        self.assertFalse(report["public_udp"]["ipv6_udp"]["ok"])

    def test_empty_listener_or_stale_report_cannot_claim_both_families_denied(self):
        wrapper = mock.Mock()
        wrapper.poll.return_value = None
        report = {"role": "parent", "pid": 123, "parent_pid": 100, "status": "passed", "run_token": "a" * 64,
                  "checks": [{"check": name, "status": "passed", "socket_error": 10013} for name in
                             ("direct_ipv4_tcp", "direct_ipv6_tcp", "guest_to_host_ipv4", "guest_to_host_ipv6")]
                             + [{"check": "real_proxy_https", "status": "passed"}],
                  "public_udp": {"ipv4_udp": {"ok": False, "code": "allowed"}, "ipv6_udp": {"ok": False, "code": 10051}},
                  "listeners": []}
        acceptance.write_json(self.root / "acceptance-parent.json", report)
        with self.assertRaisesRegex(RuntimeError, "listeners"):
            acceptance.read_guest_reports(self.root, wrapper, timeout=0.1, run_token="a" * 64)
        report["listeners"] = [19001, 19002]
        acceptance.write_json(self.root / "acceptance-parent.json", report)
        with self.assertRaisesRegex(RuntimeError, "identity"):
            acceptance.read_guest_reports(self.root, wrapper, timeout=0.1, run_token="b" * 64)

    def test_mock_https_lifecycle_success_never_promotes_full_security_acceptance(self):
        from ruleproxy import windows_runtime
        yaml = self.root / "private.yaml"
        yaml.write_text("private fixture bytes")
        report = self.root / "full.json"
        manager = mock.Mock()
        with ExitStack() as stack:
            stack.enter_context(mock.patch.object(sys, "platform", "win32"))
            stack.enter_context(mock.patch.object(acceptance, "host_facts", return_value={
                "windows_product_type": 1, "windows_build": 26300, "pointer_bits": 64,
                "python_pe_machine": 0x8664, "native_machine": 0x8664}))
            stack.enter_context(mock.patch.object(acceptance, "verify_runtime_manifest", return_value={
                "wxc-exec.exe": "a" * 64, "mihomo.exe": "b" * 64}))
            stack.enter_context(mock.patch.object(windows_runtime, "probe", return_value={"supported": True}))
            stack.enter_context(mock.patch.object(acceptance, "network_snapshot", return_value="c" * 64))
            stack.enter_context(mock.patch.object(acceptance, "HostFixtures"))
            stack.enter_context(mock.patch("ruleproxy.manager.Manager", return_value=manager))
            stack.enter_context(mock.patch.object(acceptance, "lifecycle_case", side_effect=lambda _manager, _fixtures, _url, case, **kwargs:
                                                  {"check": case, "status": "passed"}))
            stack.enter_context(mock.patch.object(sys, "stdout", new_callable=io.StringIO))
            loaded_root = Path(windows_runtime.__file__).resolve().parent.parent
            self.assertEqual(acceptance.main(["--root", str(loaded_root), "--yaml", str(yaml), "--report", str(report)]), 0)
        result = json.loads(report.read_text())
        self.assertTrue(result["real_node_passed"])
        self.assertFalse(result["acceptance_passed"])
        self.assertFalse(result["full_acceptance_passed"])
        self.assertFalse(result["public_udp_proven"])
        self.assertFalse(result["system_dns_proven"])

    def browser_module(self):
        path = SCRIPT.parent.parent / ".github/windows_browser_check.py"
        spec = importlib.util.spec_from_file_location("ruleproxy_browser_checks_test", path)
        module = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(module)
        return module

    def test_real_browser_fixture_second_page_cannot_reissue_cookie_and_cleanup_closes_handlers(self):
        browser = self.browser_module()
        fixture = browser.BrowserFixture()
        self.addCleanup(fixture.close)
        fixture.begin(1)
        url = f"http://{browser.HOST}/phase/1"
        status, body, extra = fixture.response("GET", url, "HTTP/1.1", {})
        self.assertEqual(status, "200 OK")
        self.assertIn(fixture.nonce.encode(), body)
        self.assertIn("Set-Cookie:", extra)
        self.assertIn("Max-Age=3600", extra)
        fixture.begin(2)
        _, _, extra = fixture.response("GET", f"http://{browser.HOST}/phase/2", "HTTP/1.1", {})
        self.assertNotIn("Set-Cookie:", extra)
        fixture.response("GET", f"http://{browser.HOST}/ack/2?nonce={fixture.nonce}", "HTTP/1.1",
                         {"cookie": f"{browser.COOKIE}={fixture.nonce}"})
        with self.assertRaisesRegex(RuntimeError, "persistent cookie"):
            fixture.check(2)
        connection = socket.create_connection(("127.0.0.1", fixture.port), timeout=1)
        self.addCleanup(connection.close)
        connection.sendall(b"GET ")
        deadline = time.monotonic() + 1
        while not fixture.handlers and time.monotonic() < deadline:
            threading.Event().wait(0.005)
        handlers = list(fixture.handlers)
        self.assertTrue(handlers)
        fixture.close()
        self.assertTrue(all(not worker.is_alive() for worker in handlers))

    def test_mock_browser_run_preserves_actual_runtime_startup_record_without_public_claims(self):
        from ruleproxy import launcher, windows_runtime
        browser = self.browser_module()
        resources = self.startup_resources()
        wrapper = mock.Mock()
        wrapper.wait.return_value = 0
        fixture = mock.Mock(port=19002)
        owner = browser.BrowserRun(Path("runtime"), Path("msedge.exe"), self.root, fixture)
        prepared = ["msedge.exe", "--headless=new", "--dump-dom", "--restore-last-session",
                    "http://ruleproxy-browser-fixture.invalid/phase/1?literal=--restore-last-session"]
        original = prepared.copy()
        environment = {"PUBLIC_FIXTURE_ENV": "unchanged"}
        with mock.patch.object(launcher, "prepare_app", return_value=(prepared, environment, "")), \
                mock.patch.object(windows_runtime, "choose_guest_port", return_value=19001), \
                mock.patch.object(windows_runtime, "launch", return_value=(wrapper, resources)) as launch, \
                mock.patch.object(windows_runtime, "stop"):
            result = owner.run(1, 90)
        self.assertEqual(launch.call_args.args[0], [original[0], original[1], original[2], original[4]])
        self.assertIs(launch.call_args.args[1], environment)
        self.assertEqual(prepared, original, "Source fixture filtering must not mutate prepared product commands")
        self.assertEqual(result["startup_diagnostics"]["config_readonly"], {"ok": True, "code": 5})
        self.assertFalse(result["public_udp_proven"])
        self.assertFalse(result["system_dns_proven"])
        self.assertTrue(result["host_udp_observation"]["non_delivery_observed"])
        self.assertTrue(result["wrapper_exit_observed"])
        self.assertEqual(result["wrapper_exit_code"], 0)
        self.assertTrue(result["natural_headless_exit"])
        self.assertTrue(result["owned_workload_cleanup_proven"])
        self.assertTrue(result["resources_closed"])
        resources.close.assert_called_once()

    def test_public_ipv6_no_route_requires_actual_host_fact_and_local_ipv6_access_denial(self):
        with mock.patch("socket.socket") as factory:
            sender = factory.return_value.__enter__.return_value
            sender.connect.side_effect = [OSError(10013, "denied"), OSError(10013, "denied"),
                                          OSError(10013, "denied"), OSError(10051, "no route")]
            checks = acceptance.network_checks(19001, 19002, host_ipv6_route_unavailable=True)
        self.assertEqual(checks[1], {"check": "direct_ipv6_tcp", "status": "unavailable", "socket_error": 10051, "ok": False})
        self.assertTrue(all(check["socket_error"] == 10013 for check in (checks[0], *checks[2:])))
        for host_fact, local_code, public_code in ((False, 10013, 10051), (True, 10051, 10051),
                                                   (True, 10013, 10060), (True, 10013, 10065)):
            with self.subTest(host_fact=host_fact, local_code=local_code, public_code=public_code), \
                    mock.patch("socket.socket") as factory:
                factory.return_value.__enter__.return_value.connect.side_effect = [
                    OSError(10013, "denied"), OSError(10013, "denied"), OSError(local_code, "local result"),
                    OSError(public_code, "public result")]
                with self.assertRaises(RuntimeError):
                    acceptance.network_checks(19001, 19002, host_ipv6_route_unavailable=host_fact)

    def test_startup_ipv6_unavailable_preserves_raw_false_and_actual_host_observation(self):
        resources = self.startup_resources()
        for role in ("parent", "child"):
            resources.startup_diagnostics[role]["checks"]["ipv6_tcp"] = {"ok": False, "code": 10051}
        with self.assertRaisesRegex(RuntimeError, "mandatory startup"):
            acceptance.startup_evidence(resources)
        resources.host_ipv6_observation.update(host_ipv6_route_unavailable=True, code=10051)
        result = acceptance.startup_evidence(resources)
        self.assertEqual(result["startup_diagnostics"]["child"]["checks"]["ipv6_tcp"], {"ok": False, "code": 10051})
        self.assertTrue(result["host_ipv6_observation"]["host_ipv6_route_unavailable"])
        self.assertFalse(result["public_udp_proven"])
        resources.startup_diagnostics["aux"]["parent_ipv6_loopback"] = {"ok": False, "code": 10051}
        with self.assertRaisesRegex(RuntimeError, "mandatory startup"):
            acceptance.startup_evidence(resources)

    def test_guest_availability_reads_forced_config_outside_profile_not_writable_claim(self):
        profile = self.root / "profile"
        profile.mkdir()
        directory = self.root / "config"
        directory.mkdir()
        config = directory / "guest-config.json"
        value = {"schema_version": 1, "command": ["fixture"], "env": {}, "profile": str(profile),
                 "listener_port": 19001, "bridge_directory": str(profile), "bridge_nonce": "a" * 64,
                 "host_fixture_port": 19002, "host_udp_ports": [19003, 19004], "host_ipv6_route_unavailable": True}
        config.write_text(json.dumps(value))
        with mock.patch.object(Path, "cwd", return_value=profile), \
                mock.patch.dict(os.environ, {"RULEPROXY_RUNTIME_CONFIG": str(config)}):
            self.assertTrue(acceptance.guest_host_ipv6_unavailable())
            value["host_ipv6_route_unavailable"] = "true"
            config.write_text(json.dumps(value))
            with self.assertRaises(RuntimeError):
                acceptance.guest_host_ipv6_unavailable()
        value["host_ipv6_route_unavailable"] = True
        mutable = profile / "forged.json"
        mutable.write_text(json.dumps(value))
        with mock.patch.object(Path, "cwd", return_value=profile), \
                mock.patch.dict(os.environ, {"RULEPROXY_RUNTIME_CONFIG": str(mutable)}):
            with self.assertRaisesRegex(RuntimeError, "writable profile"):
                acceptance.guest_host_ipv6_unavailable()


if __name__ == "__main__":
    unittest.main()
