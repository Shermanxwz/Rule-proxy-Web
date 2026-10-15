import importlib.util
from pathlib import Path
import sys
import tempfile
import unittest

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
                                                "calls": [], "wire_privacy_proven": False})
        self.assertEqual(safe["child"]["proxy_socks"], {"ok": False, "winerror": 10013})

    def test_safe_fixture_snapshot_keeps_counts_but_not_raw_errors(self):
        safe = control._safe_snapshot({"proxy_requests": 2, "direct_connections": 1,
                                       "udp4_by_role": {"parent": 4},
                                       "errors": ["private endpoint path", "nonce"]})
        self.assertEqual(safe["proxy_requests"], 2)
        self.assertEqual(safe["error_count"], 2)
        self.assertEqual(safe["udp4_by_role"], {"parent": 4})
        self.assertNotIn("errors", safe)

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
        self.assertNotIn("recovery_directory", safe)
        self.assertNotIn("path", str(safe))


if __name__ == "__main__":
    unittest.main()
