import importlib.util
import json
from pathlib import Path
import socket
import subprocess
import sys
import tempfile
import unittest
from unittest import mock


SCRIPT = Path(__file__).resolve().parents[1] / ".github" / "windows_free_backend_server_probe.py"
SPEC = importlib.util.spec_from_file_location("windows_free_backend_server_probe", SCRIPT)
probe = importlib.util.module_from_spec(SPEC)
sys.modules[SPEC.name] = probe
SPEC.loader.exec_module(probe)


class ServerProbeTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        root = Path(self.temp.name)
        self.bundle = root / "bundle"
        self.bundle.mkdir()
        self.artifacts = root / "artifacts"
        self.results = root / "results"
        self.results.mkdir()
        self.manifest = self.bundle / "manifest.json"
        self.install = self.results / "install-report.json"
        self.report = self.results / "server-network-probe.json"
        self.manifest.write_text("{}", encoding="utf-8")
        self.install.write_text("{}", encoding="utf-8")
        self.paths = (self.bundle, self.artifacts, self.manifest, self.install, self.report)

    def tearDown(self):
        self.temp.cleanup()

    def run_with_paths(self, backend, module):
        with mock.patch.object(probe, "BUNDLE", self.bundle), \
             mock.patch.object(probe, "ARTIFACTS", self.artifacts), \
             mock.patch.object(probe, "MANIFEST", self.manifest), \
             mock.patch.object(probe, "INSTALL_REPORT", self.install), \
             mock.patch.object(probe, "REPORT", self.report), \
             mock.patch.object(probe.sys, "platform", "win32"):
            return probe.run(backend, bundle=self.bundle, artifacts=self.artifacts,
                             manifest=self.manifest, install_report=self.install,
                             report=self.report, control_module=module)

    def test_rejects_nonfixed_output_or_bundle_path(self):
        with mock.patch.object(probe, "BUNDLE", self.bundle):
            with self.assertRaisesRegex(ValueError, "fixed RuleProxyCI"):
                probe._require_lab_paths(self.bundle / "elsewhere", self.artifacts,
                                         self.manifest, self.install, self.report)

    def test_proxybridge_requires_real_ordinary_nonadmin_identity_before_network(self):
        class Control:
            MAX_REPORT_BYTES = 1000

            @staticmethod
            def _ordinary_user_facts():
                return {"non_admin": True, "not_system": True, "is_administrator": False}

            @staticmethod
            def manifest_pins_installer(_):
                return True

            @staticmethod
            def _read_json(*_):
                return {}

            @staticmethod
            def _windows_build():
                return {"build": 26100, "ubr": 1000}

            @staticmethod
            def _run_service_probe(*_):
                return {"cleanup": True, "selected_parent_and_child": {"ok": True},
                        "browser_gui": {"status": "not_tested"}}

        result = self.run_with_paths("proxybridge", Control)
        self.assertEqual(result["status"], "diagnostic_completed")
        self.assertEqual((result["windows_build"], result["windows_ubr"]), (26100, 1000))
        self.assertTrue(result["diagnostic_only"])
        self.assertFalse(result["product_acceptance_passed"])
        self.assertFalse(result["windows_11_verified"])
        self.assertEqual(result["gui_status"], "not_tested_noninteractive")
        self.assertEqual(json.loads(self.report.read_text()), result)

    def test_proxybridge_rejects_admin_before_manifest_or_probe(self):
        class Control:
            @staticmethod
            def _ordinary_user_facts():
                return {"non_admin": False, "not_system": True, "is_administrator": True}

            @staticmethod
            def _run_service_probe(*_):
                raise AssertionError("network probe must not run elevated")

        with mock.patch.object(probe, "BUNDLE", self.bundle), \
             mock.patch.object(probe, "ARTIFACTS", self.artifacts), \
             mock.patch.object(probe, "MANIFEST", self.manifest), \
             mock.patch.object(probe, "INSTALL_REPORT", self.install), \
             mock.patch.object(probe, "REPORT", self.report), \
             mock.patch.object(probe.sys, "platform", "win32"):
            with self.assertRaises(PermissionError):
                probe.run("proxybridge", bundle=self.bundle, artifacts=self.artifacts,
                          manifest=self.manifest, install_report=self.install,
                          report=self.report, control_module=Control)

    def test_sandboxie_delegates_to_native_control_and_preserves_server_identity(self):
        class Control:
            @staticmethod
            def probe(bundle, manifest, report, install_report, artifacts, *, include_gui=True):
                self.assertFalse(include_gui)
                self.assertEqual((bundle, manifest, report, install_report, artifacts), probe_paths)
                return {"status": "passed", "ordinary_user": True, "is_elevated": False,
                        "is_administrator": False, "windows_build": 26100, "windows_ubr": 1000,
                        "cleanup_proven": True, "gui": {"status": "not_tested_noninteractive"}}

        probe_paths = (self.bundle, self.manifest, self.report, self.install, self.artifacts)
        with mock.patch.object(probe, "_raw_unconnected_udp", return_value={
                "status": "complete", "cleanup_proven": True, "families": {}}) as adjunct:
            result = self.run_with_paths("sandboxie", Control)
        adjunct.assert_called_once()
        self.assertEqual(result["status"], "diagnostic_completed")
        self.assertEqual(result["windows_build"], 26100)
        self.assertFalse(result["windows_11_verified"])
        self.assertEqual(result["gui_status"], "not_tested_noninteractive")
        self.assertFalse(result["product_acceptance_passed"])
        self.assertEqual(result["raw_unconnected_udp"]["status"], "complete")

    def test_unconnected_udp_adjunct_does_not_run_after_failed_sandboxie_probe(self):
        class Control:
            @staticmethod
            def probe(*_args, **_kwargs):
                return {"status": "failed", "ordinary_user": True,
                        "cleanup_proven": False, "gui": {"status": "not_started"}}

        with mock.patch.object(probe, "_raw_unconnected_udp",
                               side_effect=AssertionError("adjunct must wait for main success")):
            result = self.run_with_paths("sandboxie", Control)
        self.assertEqual(result["status"], "diagnostic_incomplete")
        self.assertFalse(result["cleanup_proven"])
        self.assertNotIn("raw_unconnected_udp", result)

    def test_unconnected_worker_script_uses_sendto_without_connect_or_bind(self):
        source = probe.UDP_WORKER_SOURCE
        self.assertNotIn(".connect(", source)
        self.assertNotIn(".bind(", source)
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            receiver = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            receiver.bind(("127.0.0.1", 0))
            receiver.settimeout(2)
            port = receiver.getsockname()[1]
            nonce = "a" * 32
            spec = {"schema_version": 1, "nonce": nonce, "stage": "contained",
                    "box": "RuleProxyNet", "endpoints": {
                        "ipv4": ["127.0.0.1", port], "ipv6": ["::1", 9]}}
            spec_path, script_path, report_path = root / "spec.json", root / "worker.py", root / "result.json"
            spec_path.write_text(json.dumps(spec), encoding="ascii")
            script_path.write_text(source, encoding="ascii")
            completed = subprocess.run([sys.executable, "-I", "-S", str(script_path),
                                         "--spec", str(spec_path), "--report", str(report_path)],
                                        timeout=5, check=False, capture_output=True)
            self.assertEqual(completed.returncode, 0, completed.stderr.decode("utf-8", "replace"))
            report = json.loads(report_path.read_text(encoding="ascii"))
            self.assertEqual(report["families"]["ipv4"]["sent_bytes"],
                             len(f"RPWFREE:{nonce}:ipv4:contained:RuleProxyNet".encode()))
            self.assertEqual(receiver.recvfrom(256)[0],
                             f"RPWFREE:{nonce}:ipv4:contained:RuleProxyNet".encode())
            receiver.close()

    def test_outside_udp_controls_are_received_as_exact_nonce_stage_box_markers(self):
        listener = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        listener.bind(("127.0.0.1", 0))
        listener.setblocking(False)
        endpoint = ("127.0.0.1", listener.getsockname()[1])
        nonce = "b" * 32
        labels = {f"RPWFREE:{nonce}:ipv4:{stage}:RuleProxyNet".encode(): stage
                  for stage in ("outside_before", "outside_after")}
        counts = {}
        try:
            for stage in ("outside_before", "outside_after"):
                marker = f"RPWFREE:{nonce}:ipv4:{stage}:RuleProxyNet".encode()
                sent = probe._send_marker("ipv4", endpoint, marker)
                probe._drain_udp({"ipv4": listener}, labels, counts, timeout=0.1)
                self.assertEqual(sent["sent_bytes"], len(marker))
                self.assertEqual(counts.get(stage), 1)
        finally:
            listener.close()

    def test_full_optional_udp_adjunct_observes_both_families_and_all_stages(self):
        class FakeSandboxie:
            BOX_BASE = "RuleProxyNet"
            BOX_DNS = "RuleProxyDnsIpc"
            cleanup_calls = []
            inject_unknown = False

            @staticmethod
            def _install_root():
                return Path("fixed-install-root")

            @staticmethod
            def _start_exe(_root):
                return Path("fixed-Start.exe")

            @staticmethod
            def _json_read(path, _limit):
                return json.loads(Path(path).read_text(encoding="ascii"))

            @classmethod
            def _run_box(cls, _start, _box, argv, timeout):
                # This runs the exact generated stdlib worker on the test host.
                # It validates packet wiring, not Sandboxie containment.
                completed = subprocess.run([sys.executable, *argv[1:]], timeout=timeout,
                                            check=False, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
                if cls.inject_unknown:
                    spec = json.loads(Path(argv[7]).read_text(encoding="ascii"))
                    endpoint = spec["endpoints"]["ipv4"]
                    with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as sender:
                        sender.sendto(b"unmatched-diagnostic-datagram", tuple(endpoint))
                return completed

            @classmethod
            def _box_cleanup(cls, _start, box):
                cls.cleanup_calls.append(box)
                return {"cleanup_proven": True, "empty_box_proven": True}

        with tempfile.TemporaryDirectory() as directory:
            result = probe._raw_unconnected_udp(FakeSandboxie, Path(directory), Path(directory))
        self.assertEqual(result["status"], "complete")
        self.assertTrue(result["cleanup_proven"])
        self.assertCountEqual(FakeSandboxie.cleanup_calls, ["RuleProxyNet", "RuleProxyDnsIpc"])
        self.assertTrue(all(row["empty_box_proven"] for row in result["sandbox_cleanup"].values()))
        self.assertTrue(result["outside_controls_positive"])
        self.assertEqual(result["unknown_datagram_count"], 0)
        for family in ("ipv4", "ipv6"):
            self.assertTrue(result["families"][family]["listener_ready"])
            for box in ("RuleProxyNet", "RuleProxyDnsIpc"):
                self.assertEqual(result["families"][family]["outside_before"][box]["received_count"], 1)
                self.assertEqual(result["families"][family]["contained"][box]["received_count"], 1)
                self.assertEqual(result["families"][family]["outside_after"][box]["received_count"], 1)

        FakeSandboxie.inject_unknown = True
        with tempfile.TemporaryDirectory() as directory:
            noisy = probe._raw_unconnected_udp(FakeSandboxie, Path(directory), Path(directory))
        self.assertGreater(noisy["unknown_datagram_count"], 0)
        self.assertEqual(noisy["status"], "incomplete")
        self.assertTrue(noisy["cleanup_proven"])

    def test_rejects_unknown_backend(self):
        with self.assertRaisesRegex(ValueError, "unsupported backend"):
            probe.run("other")


if __name__ == "__main__":
    unittest.main()
