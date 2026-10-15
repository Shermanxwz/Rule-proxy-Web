import importlib.util
import json
from pathlib import Path
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
        self.assertEqual(result["gui_status"], "not_tested")
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
            def probe(bundle, manifest, report, install_report, artifacts):
                self.assertEqual((bundle, manifest, report, install_report, artifacts), probe_paths)
                return {"status": "passed", "ordinary_user": True, "is_elevated": False,
                        "is_administrator": False, "windows_build": 26100, "windows_ubr": 1000,
                        "cleanup_proven": True, "gui": {"visible": None}}

        probe_paths = (self.bundle, self.manifest, self.report, self.install, self.artifacts)
        result = self.run_with_paths("sandboxie", Control)
        self.assertEqual(result["status"], "diagnostic_completed")
        self.assertEqual(result["windows_build"], 26100)
        self.assertFalse(result["windows_11_verified"])
        self.assertEqual(result["gui_status"], "not_tested")
        self.assertFalse(result["product_acceptance_passed"])

    def test_rejects_unknown_backend(self):
        with self.assertRaisesRegex(ValueError, "unsupported backend"):
            probe.run("other")


if __name__ == "__main__":
    unittest.main()
