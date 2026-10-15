import importlib.util
import ctypes
import json
from pathlib import Path
import sys
import tempfile
import unittest
from unittest import mock

SCRIPT = Path(__file__).resolve().parents[1] / ".github" / "windows_proxybridge_control.py"
SPEC = importlib.util.spec_from_file_location("windows_proxybridge_control", SCRIPT)
control = importlib.util.module_from_spec(SPEC)
sys.modules[SPEC.name] = control
SPEC.loader.exec_module(control)


class FixedReleaseTests(unittest.TestCase):
    def test_official_asset_constants_are_fully_pinned(self):
        self.assertEqual(control.BUNDLE_FILES, ({
            "name": "ProxyBridge-Setup-4.1.1.exe",
            "url": "https://github.com/InterceptSuite/ProxyBridge/releases/download/v4.1.1/ProxyBridge-Setup-4.1.1.exe",
            "size": 799792,
            "sha256": "754f45fb31f3953b9b81005090f9a479f89827adb628cf2c76bc4139f673a152",
        },))

    def test_installer_verification_rejects_wrong_size_or_digest(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / control.INSTALLER_NAME
            path.write_bytes(b"wrong")
            with self.assertRaisesRegex(ValueError, "fixed upstream"):
                control.verify_installer(path)

    def test_probe_sid_requires_windows_sid_syntax(self):
        self.assertEqual(control.validate_probe_sid("S-1-5-21-42-43-44-1001"),
                         "S-1-5-21-42-43-44-1001")
        for invalid in ("", "S-1-5-18\n", "administrator", "S-1--5"):
            with self.subTest(invalid=invalid), self.assertRaises(ValueError):
                control.validate_probe_sid(invalid)

    def test_installer_is_read_from_builder_manifest_member_path(self):
        self.assertEqual(control.installer_path(Path("C:/bundle")),
                         Path("C:/bundle/installers/ProxyBridge-Setup-4.1.1.exe"))

    def test_bundle_manifest_must_pin_the_exact_installer_once(self):
        entry = {"path": "installers/ProxyBridge-Setup-4.1.1.exe",
                 "size": 799792,
                 "sha256": "754f45fb31f3953b9b81005090f9a479f89827adb628cf2c76bc4139f673a152"}
        manifest = {"schema_version": 1, "backend": control.BACKEND,
                    "release": "v4.1.1", "files": [entry]}
        self.assertTrue(control.manifest_pins_installer(manifest))
        self.assertFalse(control.manifest_pins_installer(dict(manifest, files=[entry, entry])))
        self.assertFalse(control.manifest_pins_installer(dict(manifest, files=[dict(entry, size=1)])))
        self.assertFalse(control.manifest_pins_installer(dict(manifest, backend="other")))

    def test_installed_driver_signature_is_required_and_paths_are_not_reported(self):
        good = control.normalize_driver_signature_values(
            [{"name": "WinDivert", "status": "Valid", "path": "C:\\private\\driver.sys"}])
        self.assertEqual(good, {"status": "Valid", "count": 1,
                                "drivers": [{"name": "WinDivert", "signature_status": "Valid"}]})
        bad = control.normalize_driver_signature_values(
            [{"name": "WinDivert64", "status": "NotSigned"}])
        self.assertEqual(bad["status"], "Invalid")
        self.assertNotIn("path", bad["drivers"][0])
        with self.assertRaises(RuntimeError):
            control.normalize_driver_signature_values([])
        with self.assertRaises(RuntimeError):
            control.normalize_driver_signature_values([{"name": "../secret", "status": "Valid"}])

    def test_service_install_report_is_bounded_and_normalized(self):
        self.assertEqual(control.normalize_service_install(
            {"exists": True, "state": "Running", "start_type": "Auto", "path": "private"}),
            {"exists": True, "state": "running", "start_type": "auto"})
        self.assertEqual(control.normalize_service_install(
            {"exists": False, "state": "odd", "start_type": "odd"}),
            {"exists": False, "state": "unknown", "start_type": "unknown"})
        with self.assertRaises(RuntimeError):
            control.normalize_service_install({"exists": "true"})


class ServiceProtocolTests(unittest.TestCase):
    def test_socks_endpoint_and_process_rule_match_upstream_wire_format(self):
        request = control.add_proxy_request("127.0.0.1", 10808)
        self.assertEqual(request, b"\x02\x00\x00\x00" + b"\x01\x00\x00\x00"
                         + b"\x09\x00\x00\x00" + b"127.0.0.1"
                         + b"\x38\x2a\x00\x00" + b"\x00\x00\x00\x00"
                         + b"\x00\x00\x00\x00" + b"\x00\x00\x00\x00")
        rule = control.add_rule_request("python.exe", 7)
        self.assertTrue(rule.startswith(b"\x06\x00\x00\x00"))
        self.assertIn(b"python.exe", rule)
        self.assertTrue(rule.endswith(b"\x02\x00\x00\x00\x00\x00\x00\x00\x07\x00\x00\x00"))

    def test_rejects_invalid_wire_values_and_unexpected_fixture_controls(self):
        with self.assertRaises(ValueError):
            control.encode_u32(True)
        with self.assertRaises(ValueError):
            control.add_rule_request("python.exe\n", 1)
        with self.assertRaises(ValueError):
            control.validate_fixture_spec({"proxy_host": "127.0.0.1", "proxy_port": 1,
                                           "http_origin_host": "127.0.0.1", "http_origin_port": 2,
                                           "arbitrary_command": "whoami"})

    def test_fixture_requires_fixed_local_bounded_endpoints(self):
        nonce = "a" * 32
        good = {"schema_version": 1, "nonce": nonce, "proxy_host": "127.0.0.1", "proxy_port": 10808,
                "origin_host": "ruleproxy-fixture.invalid", "origin_port": 18080,
                "origin_url": f"http://ruleproxy-fixture.invalid:18080/{nonce}",
                "http_origin_host": "127.0.0.1", "http_origin_port": 18080,
                "blocked_tcp_host": "127.0.0.1", "blocked_tcp_port": 18081,
                "udp4_host": "127.0.0.1", "udp4_port": 18082,
                "udp6_host": "::1", "udp6_port": 18083,
                "public_udp4_host": "198.51.100.17", "public_udp6_host": "2001:db8::17",
                "public_udp_port": 39017}
        self.assertEqual(control.validate_fixture_spec(good), good)
        for bad in (dict(good, proxy_port=True), dict(good, proxy_port=65536),
                    dict(good, proxy_host="192.0.2.10"), dict(good, nonce="private"),
                    dict(good, origin_url="https://unexpected.invalid/" + nonce)):
            with self.subTest(bad=bad), self.assertRaises(ValueError):
                control.validate_fixture_spec(bad)

    def test_safe_projection_discards_pid_nonce_paths_and_raw_errors(self):
        raw = {"role": "parent", "parent_pid": 473, "nonce": "x" * 32,
               "proxy_http": {"ok": True, "path": "C:\\private", "error_type": "RuntimeError",
                              "exception": "contains private response"},
               "native_dns": {"status": "observed", "calls": [{"qname": "nonce.invalid"}]},
               "child": {"role": "child", "parent_pid": 474,
                         "proxy_socks": {"ok": False, "winerror": 10013}}}
        safe = control._safe_worker_report(raw)
        self.assertNotIn("parent_pid", safe)
        self.assertNotIn("nonce", safe)
        self.assertNotIn("path", safe["proxy_http"])
        self.assertNotIn("exception", safe["proxy_http"])
        self.assertEqual(safe["proxy_http"], {"ok": True, "error_type": "other"})
        self.assertEqual(safe["native_dns"], {"status": "observed", "calls_count": 0,
                                                "calls": [], "wire_privacy_proven": False,
                                                "helper_status": "unknown", "exit_code": None,
                                                "cleanup_proven": False})
        self.assertEqual(safe["child"]["proxy_socks"], {"ok": False, "winerror": 10013})

    def test_safe_fixture_snapshot_keeps_counts_but_not_raw_errors(self):
        safe = control._safe_snapshot({"proxy_requests": 2, "direct_connections": 1,
                                       "udp4_by_role": {"parent": 4, "outside_before": 3,
                                                         "outside_after": 2, "secret": 99},
                                       "errors": ["private endpoint path", "nonce"]})
        self.assertEqual(safe["proxy_requests"], 2)
        self.assertEqual(safe["error_count"], 2)
        self.assertEqual(safe["udp4_by_role"], {"parent": 4, "outside_before": 3,
                                                  "outside_after": 2})
        self.assertNotIn("errors", safe)

    def test_worker_projection_keeps_exact_nonce_bound_outside_udp_tuple(self):
        nonce = "a" * 32
        spec = {"udp4_host": "127.0.0.1", "udp4_port": 18082}
        payload = ("RPWFREE:" + nonce + ":outside_before").encode("ascii").hex()
        raw = {"role": "parent", "parent_pid": 17, "udp4": {
            "attempted": True, "send_ok": True, "denial_proven": False,
            "family": "ipv4", "dest_ip": "127.0.0.1", "dest_port": 18082,
            "source_ip": "127.0.0.1", "source_ip_observed": True,
            "payload_hex": payload, "timeout_ms": 2000, "metadata_complete": True,
            "path": "C:\\private"}}
        safe = control._safe_worker_report(raw, nonce=nonce, wire_role="outside_before", fixture=spec)
        self.assertEqual(safe["udp4"], {
            "attempted": True, "send_ok": True, "denial_proven": False,
            "family": "ipv4", "dest_ip": "127.0.0.1", "dest_port": 18082,
            "source_ip": "127.0.0.1", "source_ip_observed": True,
            "payload_hex": payload, "timeout_ms": 2000, "metadata_complete": True})
        self.assertNotIn("parent_pid", safe)
        self.assertNotIn("path", str(safe))
        bad = control._safe_worker_report(raw, nonce=nonce, wire_role="outside_after", fixture=spec)
        self.assertNotIn("payload_hex", bad["udp4"])
        self.assertFalse(bad["udp4"]["metadata_complete"])

    def test_outside_worker_receives_wire_role_and_keeps_controller_exit(self):
        nonce = "b" * 32
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            bundle, artifacts = root / "bundle", root / "artifacts"
            (bundle / "python").mkdir(parents=True)
            (bundle / "scripts").mkdir()
            (bundle / "python" / "python.exe").write_bytes(b"runtime")
            (bundle / "scripts" / "windows_free_backend_fixture.py").write_bytes(b"fixture")
            report = artifacts / "unselected-parent.json"
            worker_data = {"schema_version": 1, "role": "parent", "udp4": {
                "attempted": True, "send_ok": False, "family": "ipv4",
                "dest_ip": "127.0.0.1", "dest_port": 18082,
                "source_ip": None, "source_ip_observed": False,
                "payload_hex": ("RPWFREE:" + nonce + ":outside_before").encode().hex(),
                "timeout_ms": 2000, "metadata_complete": False}}

            def run(command, **_kwargs):
                self.assertIn("--wire-role", command)
                self.assertEqual(command[command.index("--wire-role") + 1], "outside_before")
                report.parent.mkdir(parents=True, exist_ok=True)
                report.write_text(json.dumps(worker_data), encoding="utf-8")
                return type("Completed", (), {"returncode": 0})()

            fixture = {"udp4_host": "127.0.0.1", "udp4_port": 18082}
            with mock.patch.object(control.subprocess, "run", side_effect=run):
                safe = control._run_fixture_worker(bundle, root / "spec.json", artifacts,
                    role="parent", selected=False, nonce=nonce,
                    wire_role="outside_before", fixture=fixture)
            self.assertEqual(safe["controller_exit_code"], 0)
            self.assertEqual(safe["udp4"]["timeout_ms"], 2000)
            self.assertFalse(safe["udp4"]["metadata_complete"])

    def test_selected_dns_preserves_helper_facts_separate_from_controller(self):
        nonce = "c" * 32
        qname = f"{nonce}.dns-a.parent.ruleproxy-ci.example.com."
        safe = control._safe_worker_report({"role": "parent", "native_dns": {
            "status": "observed", "helper_status": "failed", "exit_code": 4,
            "cleanup_proven": False, "wire_privacy_proven": False,
            "calls": [{"api": "dns_a", "qname": qname, "outcome": "returned",
                       "return_code": 9501, "worker_cleanup_proven": False}]}}, nonce=nonce)
        self.assertEqual(safe["native_dns"]["helper_status"], "failed")
        self.assertEqual(safe["native_dns"]["exit_code"], 4)
        self.assertFalse(safe["native_dns"]["cleanup_proven"])
        self.assertEqual(safe["native_dns"]["calls_count"], 1)
        self.assertNotIn("controller_cleanup_proven", safe["native_dns"])

    def test_check_token_membership_uses_current_effective_token(self):
        class FakeAdvapi:
            def __init__(self):
                self.args = None
                self.CheckTokenMembership = FakeFunction(self)

            class _Unused:
                pass

        class FakeFunction:
            def __init__(self, owner):
                self.owner = owner

            def __call__(self, token, sid, member_ptr):
                self.owner.args = (token, sid)
                ctypes.cast(member_ptr, ctypes.POINTER(ctypes.c_int))[0] = 1
                return 1

        fake = FakeAdvapi()
        with mock.patch.object(control.ctypes, "WinDLL", return_value=fake, create=True):
            self.assertTrue(control._current_token_has_sid(b"sid"))
        self.assertIsNone(fake.args[0])

    def test_event_pipe_requests_state_change_access_and_closes_handles_on_setup_failure(self):
        class FakeKernel:
            def __init__(self):
                self.opened = []
                self.closed = []

            def CreateFileW(self, path, access, *_args):
                self.opened.append((path, access))
                return 100 + len(self.opened)

            def SetNamedPipeHandleState(self, *_args):
                return 0

            def CloseHandle(self, handle):
                self.closed.append(handle.value)
                return 1

        client = object.__new__(control._ServiceClient)
        kernel = FakeKernel()
        client._kernel = kernel
        client._ctl = ctypes.c_void_p(-1)
        client._evt = ctypes.c_void_p(-1)
        client._event_stop = __import__("threading").Event()
        client._event_thread = None
        with mock.patch.object(control.ctypes, "WinError", side_effect=lambda code: OSError(code), create=True), \
             mock.patch.object(control.ctypes, "get_last_error", return_value=5, create=True):
            with self.assertRaises(OSError):
                client.connect()
        self.assertEqual(kernel.opened[1][1], 0x80000000 | control.FILE_WRITE_ATTRIBUTES)
        self.assertEqual(kernel.closed, [102, 101])
        self.assertTrue(client._event_stop.is_set())
        self.assertEqual(client._evt.value, ctypes.c_void_p(-1).value)
        self.assertEqual(client._ctl.value, ctypes.c_void_p(-1).value)

    def test_native_dns_control_projection_keeps_scope_and_controls_private(self):
        nonce = "a" * 32
        qname = f"{nonce}.dns-a.outside-before.ruleproxy-ci.example.com."
        safe = control._safe_native_dns_control({
            "status": "native_dns_probe_only", "cleanup_proven": True,
            "default_system_server_list": True, "server_list_override": False,
            "acceptance_passed": False, "recovery_directory": "C:\\private",
            "calls": [{"api": "dns_a", "qname": qname, "pid": 42,
                       "outcome": "returned", "return_code": 9501,
                       "worker_cleanup_proven": True, "path": "C:\\private"}],
        }, 0, nonce=nonce, role="outside_before")
        self.assertEqual(safe["calls_count"], 1)
        self.assertEqual(safe["calls"][0], {"api": "dns_a", "qname": qname,
                                             "requested_role": "outside_before", "outcome": "returned",
                                             "worker_cleanup_proven": True, "return_code": 9501})
        self.assertTrue(safe["default_system_server_list"])
        self.assertFalse(safe["server_list_override"])
        self.assertFalse(safe["acceptance_passed"])
        self.assertEqual(safe["helper_status"], "native_dns_probe_only")
        self.assertEqual(safe["exit_code"], 0)
        self.assertNotIn("recovery_directory", safe)
        self.assertNotIn("path", str(safe))


if __name__ == "__main__":
    unittest.main()
