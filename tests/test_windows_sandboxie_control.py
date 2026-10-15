from __future__ import annotations

import hashlib
import importlib.util
import json
from pathlib import Path
import tempfile
import unittest
from unittest import mock


ROOT = Path(__file__).resolve().parents[1]
SCRIPT = ROOT / ".github" / "windows_sandboxie_control.py"
SPEC = importlib.util.spec_from_file_location("windows_sandboxie_control_tested", SCRIPT)
control = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(control)


def fixture_spec():
    nonce = "a" * 32
    return {
        "schema_version": 1, "nonce": nonce, "proxy_host": "127.0.0.1", "proxy_port": 18080,
        "origin_host": "ruleproxy-fixture.invalid", "origin_port": 18081,
        "origin_url": f"http://ruleproxy-fixture.invalid:18081/{nonce}",
        "http_origin_host": "127.0.0.1", "http_origin_port": 18081,
        "blocked_tcp_host": "127.0.0.1", "blocked_tcp_port": 18082,
        "udp4_host": "127.0.0.1", "udp4_port": 18083, "udp6_host": "::1", "udp6_port": 18084,
        "public_udp4_host": "198.51.100.17", "public_udp6_host": "2001:db8::17",
        "public_udp_port": 39017,
    }


class WindowsSandboxieControlTests(unittest.TestCase):
    def test_installer_pin_is_fixed_and_no_authenticode_signer_is_assumed(self):
        self.assertEqual(control.RELEASE, "v1.18.5")
        self.assertEqual(control.INSTALLER_SIZE, 24_856_520)
        self.assertEqual(control.INSTALLER_SHA256,
                         "bd984db71900ecb9fc22e4bbffda4363a92cd755840a8792c2422d6d42fd6fa3")
        self.assertTrue(control.INSTALLER_URL.startswith("https://github.com/sandboxie-plus/Sandboxie/releases/"))

    def test_bundle_manifest_verifies_actual_builder_schema_and_returns_installer_path(self):
        required = {
            "installers/Sandboxie-Plus-x64-v1.18.5.exe", "python/python.exe", "mihomo/mihomo.exe",
            "chromium/chrome-win64/chrome.exe", "chromium/chrome-win64/chrome.dll",
            "chromium/chrome-win64/chrome_elf.dll", "scripts/windows_free_backend_fixture.py",
            "scripts/windows_native_dns_probe.py", "scripts/windows_sandboxie_control.py",
        }
        contents = {path: ("fixture-file-" + path).encode("ascii") for path in required}
        fake_sha = {path: hashlib.sha256(data).hexdigest() for path, data in contents.items()}
        archive_pins = [
            {"component": "python", "release": "3.14.8",
             "url": "https://www.python.org/ftp/python/3.14.8/python-3.14.8-embed-amd64.zip",
             "sha256": "a93abe456ab01bd96d7a085b3cdb6566b3063f4241360d114142fbdb07f0a310"},
            {"component": "mihomo", "release": "v1.19.32",
             "url": "https://github.com/MetaCubeX/mihomo/releases/download/v1.19.32/mihomo-windows-amd64-compatible-v1.19.32.zip",
             "sha256": "974a4d7ad69aed27aa2e8f91d61113573c14dadb14562c63e58effabf59816f0"},
            {"component": "chromium", "release": "154.0.8037.92",
             "url": "https://storage.googleapis.com/chrome-for-testing-public/154.0.8037.92/win64/chrome-win64.zip",
             "sha256": "b897ef3601c947ac0620c784556dec719ac602b0159ce105927acf645ee0f598"},
            {"component": "sandboxie", "release": control.RELEASE,
             "url": control.INSTALLER_URL, "sha256": control.INSTALLER_SHA256},
        ]
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            bundle = root / "bundle"
            records = []
            for rel, payload in contents.items():
                target = bundle / Path(*rel.split("/"))
                target.parent.mkdir(parents=True, exist_ok=True)
                target.write_bytes(payload)
                record = {"path": rel, "size": len(payload), "sha256": fake_sha[rel]}
                if rel.startswith(("installers/", "python/", "mihomo/", "chromium/")):
                    record["source_url"] = "https://example.invalid/fixed-source.zip"
                records.append(record)
            manifest = root / "manifest.json"
            manifest.write_text(json.dumps({
                "schema_version": 1, "backend": "sandboxie", "release": control.RELEASE,
                "source_diagnostic_only": True, "release_eligible": False,
                "files": records, "downloaded_archives": archive_pins,
            }), encoding="ascii")
            with (mock.patch.object(control, "INSTALLER_SIZE", len(contents[control.INSTALLER_REL])),
                  mock.patch.object(control, "INSTALLER_SHA256", fake_sha[control.INSTALLER_REL]),
                  mock.patch.object(control, "CHROME_CONTROL_SHA256", {
                      rel: fake_sha[rel] for rel in control.CHROME_CONTROL_SHA256}),
                  mock.patch.object(control, "INSTALLER_URL", "https://example.invalid/installer.exe")):
                # Keep the test's installer provenance paired with the overridden fixed pin.
                archive_pins[-1]["url"] = control.INSTALLER_URL
                archive_pins[-1]["sha256"] = control.INSTALLER_SHA256
                records = [dict(item) for item in records]
                installer_record = next(x for x in records if x["path"] == control.INSTALLER_REL)
                installer_record["source_url"] = control.INSTALLER_URL
                manifest.write_text(json.dumps({
                    "schema_version": 1, "backend": "sandboxie", "release": control.RELEASE,
                    "source_diagnostic_only": True, "release_eligible": False,
                    "files": records, "downloaded_archives": archive_pins,
                }), encoding="ascii")
                self.assertEqual(control._manifest_installer(bundle, manifest),
                                 bundle / control.INSTALLER_REL)
                (bundle / "python/python.exe").write_bytes(b"changed")
                with self.assertRaises(ValueError):
                    control._manifest_installer(bundle, manifest)

    def test_common_report_fields_never_claim_acceptance_or_release_eligibility(self):
        report = control._report_base("probe")
        self.assertTrue(report["diagnostic_only"])
        self.assertFalse(report["product_acceptance_passed"])
        self.assertFalse(report["release_eligible"])
        self.assertFalse(report["host_configuration_restored"])

    def test_config_has_default_deny_and_network_is_identical_across_dns_candidate(self):
        config = control._config_text(None)
        self.assertIn("[GlobalSettings]\r\nNetworkEnableWFP=y", config)
        base = config.split(f"[{control.BOX_BASE}]\r\n", 1)[1].split(f"\r\n[{control.BOX_DNS}]", 1)[0]
        dns = config.split(f"[{control.BOX_DNS}]\r\n", 1)[1]
        base_lines = [line for line in base.splitlines() if line.startswith(("Enabled=", "AllowNetworkAccess=",
                     "NetworkAccess=", "OpenFilePath=", "ReadFilePath="))]
        dns_lines = [line for line in dns.splitlines() if line.startswith(("Enabled=", "AllowNetworkAccess=",
                     "NetworkAccess=", "OpenFilePath=", "ReadFilePath="))]
        self.assertEqual(base_lines, dns_lines)
        self.assertIn("NetworkAccess=*,Block", base_lines)
        self.assertNotIn("NetworkAccess=*,Allow", base_lines)
        self.assertIn(r"ClosedIpcPath=\RPC Control\DNSResolver", config)
        self.assertNotIn("NetworkDnsFilter", config)
        self.assertNotIn("ProxyInjection", config)

    def test_dynamic_endpoint_rule_is_single_loopback_tcp_port(self):
        config = control._config_text(19452)
        allowed = [line for line in config.splitlines() if "Allow;Address=" in line]
        self.assertEqual(len(allowed), 2)
        self.assertEqual(allowed[0], "NetworkAccess=*,Allow;Address=127.0.0.1;Port=19452;Protocol=TCP")
        self.assertEqual(allowed[1], allowed[0])
        for bad in (0, 65536, True, "19452"):
            with self.subTest(bad=bad), self.assertRaises(ValueError):
                control._config_text(bad)

    def test_config_backup_preserves_existing_bytes_and_fails_on_test_section_conflict(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            config = root / "Sandboxie.ini"
            original = b"[GlobalSettings]\r\nSomeExistingSetting=y\r\n"
            config.write_bytes(original)
            with mock.patch.dict(control.os.environ, {"ProgramData": str(root / "ProgramData")}):
                backup = control._append_test_config(config)
            self.assertEqual(backup.read_bytes(), original)
            content = config.read_text("ascii")
            self.assertIn("SomeExistingSetting=y", content)
            self.assertIn("NetworkEnableWFP=y", content)
            with self.assertRaises(ValueError):
                control._append_test_config(config)

    def test_fixed_fixture_schema_rejects_widened_or_malformed_values(self):
        value = fixture_spec()
        self.assertIs(control._validate_fixture(value), value)
        for update in ({"proxy_host": "0.0.0.0"}, {"proxy_port": True},
                       {"nonce": "../" + "a" * 29}, {"origin_url": "http://elsewhere/" + "a" * 32}):
            bad = dict(value)
            bad.update(update)
            with self.subTest(update=update), self.assertRaises(ValueError):
                control._validate_fixture(bad)

    def test_worker_summary_is_scalar_and_drops_nonce_pid_and_error_text(self):
        record = {
            "schema_version": 1, "role": "parent", "pid": 900, "parent_pid": 800,
            "proxy_http": {"ok": True, "error_type": "OSError"},
            "proxy_socks": {"ok": True}, "direct_tcp": {"connected": False},
            "udp4": {"send_ok": False, "winerror": 10013},
            "udp6": {"send_ok": True}, "public_udp4": {"send_ok": False},
            "public_udp6": {"send_ok": False},
            "native_dns": {"calls": [{"qname": "secret nonce", "outcome": "returned"}]},
            "child": {"role": "child", "pid": 901,
                      "proxy_http": {"ok": True}, "proxy_socks": {"ok": True},
                      "direct_tcp": {"connected": False},
                      "native_dns": {"calls": [{"qname": "secret"}]}},
        }
        with tempfile.TemporaryDirectory() as temp:
            path = Path(temp) / "report.json"
            path.write_text(json.dumps(record), encoding="ascii")
            summary = control._bounded_worker_summary(path)
        serialized = json.dumps(summary)
        self.assertNotIn("secret", serialized)
        self.assertNotIn("pid", serialized)
        self.assertEqual(summary["parent_native_dns_calls"], 1)
        self.assertEqual(summary["child_native_dns_calls"], 1)
        self.assertFalse(summary["direct_tcp_connected"])
        self.assertIs(summary["udp_send_observations"]["udp4"], False)

    def test_proxy_allow_updates_only_exact_endpoint_and_refreshes_configuration(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            (root / "SbieIni.exe").write_bytes(b"not executed")
            (root / "Start.exe").write_bytes(b"not executed")
            outputs = [mock.Mock(returncode=0), mock.Mock(returncode=0)]
            with mock.patch.object(control, "_run", side_effect=outputs) as run:
                control._add_proxy_allow(root, control.BOX_BASE, 18080)
            first = run.call_args_list[0].args[0]
            self.assertEqual(first[-2:], ["NetworkAccess",
                "*,Allow;Address=127.0.0.1;Port=18080;Protocol=TCP"])
            self.assertIn("/drv", first)
            self.assertEqual(run.call_args_list[1].args[0][-1], "/reload")
            with self.assertRaises(ValueError):
                control._add_proxy_allow(root, control.BOX_BASE, 0)

    def test_failure_report_never_contains_exception_message_or_acceptance(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            report = root / "report.json"
            args = ["--phase", "install", "--bundle", str(root / "bundle"),
                    "--manifest", str(root / "manifest"), "--report", str(report)]
            code = control.main(args)
            self.assertNotEqual(code, 0)
            value = json.loads(report.read_text("ascii"))
            self.assertFalse(value["acceptance_passed"])
            self.assertFalse(value["product_acceptance"])
            self.assertTrue(value["source_diagnostic_only"])
            self.assertNotIn("detail", value)
            self.assertNotIn("message", value)


if __name__ == "__main__":
    unittest.main()
