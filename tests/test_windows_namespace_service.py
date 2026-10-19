"""Namespace operation must not enable path routing or accept an unowned core."""
import importlib.util
import json
from pathlib import Path
import tempfile
import unittest
from unittest import mock

from ruleproxy import windows_proxy_policy as policy
from ruleproxy import windows_proxy_service as service
from ruleproxy.manager import Manager
from ruleproxy.windows_proxy_runtime import Runtime
from tests.test_windows_proxy_service import Control, Lease


class NamespaceServiceTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        self.engine = self.root / "engine"
        self.engine.mkdir()
        self.sid = "S-1-5-21-1-2-3-1000"
        self.control = Control()
        self.leases = []
        def lease(pid, sid):
            value = Lease(pid, sid, self.root)
            self.leases.append(value)
            return value
        self.gate = mock.Mock()
        self.gate.purge.return_value = {"active": False}
        self.broker = service.Broker({"owner_sid": self.sid, "root": str(self.root),
            "proxifyre_root": str(self.engine)}, self.control, lease,
            namespace_factory=lambda metadata: self.gate)

    def request(self, **changes):
        value = {"op": "namespace_prepare", "client_pid": 101, "mihomo_pid": 102,
                 "proxy_port": 7890, "generation": self.broker.generation + 1}
        value.update(changes)
        return value

    def handle(self, **changes):
        return self.broker.handle(self.request(**changes), 101, self.sid)

    def test_prepare_holds_core_without_starting_path_engine(self):
        result = self.handle()
        self.assertEqual(result["state"], "running")
        self.assertTrue(result["namespace_ready"])
        self.assertFalse(result["engine_running"])
        self.assertEqual(self.control.calls, [])
        self.assertFalse((self.engine / "app-config.json").exists())
        self.assertEqual(self.broker.core.pid, 102)

    def test_generation_and_caller_mismatch_do_not_mutate(self):
        for changes, caller, sid in (({"generation": 9}, 101, self.sid), ({}, 999, self.sid),
                                    ({}, 101, self.sid + "1")):
            with self.subTest(changes=changes, caller=caller), self.assertRaises(policy.ProxyError):
                self.broker.handle(self.request(**changes), caller, sid)
        self.assertEqual(self.leases, [])
        self.assertEqual(self.control.calls, [])

    def test_foreign_running_engine_is_not_stopped(self):
        self.control.state = 4
        with self.assertRaisesRegex(policy.ProxyError, "其他程序"):
            self.handle()
        self.assertEqual(self.control.calls, [])
        self.assertTrue(all(item.closed for item in self.leases))
        self.assertIsNone(self.broker.panel)

    def test_wrong_core_image_is_rejected_before_releasing_any_state(self):
        with mock.patch.object(Lease, "image_path", return_value=str(self.root / "different.exe")):
            with self.assertRaisesRegex(policy.ProxyError, "Mihomo"):
                self.handle()
        self.assertEqual(self.control.calls, [])
        self.assertTrue(all(item.closed for item in self.leases))

    def test_owned_path_engine_is_released_when_switching_to_namespaces(self):
        with mock.patch.object(service, "verify_selected_paths"):
            self.broker.handle(self.request(op="apply", paths=[r"C:\Apps\App.exe"]), 101, self.sid)
        self.assertEqual(self.control.state, 4)
        self.control.calls.clear()
        result = self.handle()
        self.assertEqual(self.control.calls, ["stop"])
        self.assertTrue(result["namespace_ready"])
        self.assertEqual(result["path_count"], 0)
        self.assertTrue(all(item.closed for item in self.leases[:2]))

    def test_core_death_seals_namespace_gate(self):
        self.handle()
        self.broker._namespaces()
        self.broker.namespaces.add("owned")
        self.broker.core.live = False
        self.broker.check_lease()
        self.gate.purge.assert_called_once_with()
        self.assertIsNone(self.broker.panel)
        self.assertEqual(self.broker.snapshot()["state"], "idle")

    def test_unchanged_prepare_preserves_jobs_and_advances_generation(self):
        self.handle()
        held = self.broker.core
        self.assertTrue(self.handle()["unchanged"])
        self.assertIs(self.broker.core, held)
        self.assertEqual(len(self.leases), 2)
        self.assertEqual(self.broker.generation, 2)

    def test_request_decoder_rejects_invalid_numeric_identity(self):
        base = {**self.request(), "schema_version": 1, "request_id": "a" * 32}
        self.assertEqual(policy.decode_request(json.dumps(base).encode())["op"], "namespace_prepare")
        for key, value in (("proxy_port", True), ("mihomo_pid", False), ("generation", 0),
                           ("mihomo_pid", 2**32), ("proxy_port", 65536)):
            with self.subTest(key=key, value=value), self.assertRaises(policy.ProxyError):
                policy.decode_request(json.dumps({**base, key: value}).encode())

    def test_runtime_reports_namespace_readiness_without_claiming_qualification(self):
        runtime = Runtime(self.root)
        client = mock.Mock()
        client.request.return_value = {"state": "running", "generation": 1, "namespace_ready": True}
        with mock.patch.object(runtime, "_connect", return_value=client):
            result = runtime.probe()
        self.assertTrue(result["supported"])
        self.assertFalse(result["strict_isolation"])
        self.assertEqual(result["mode"], "isolated_application")
        self.assertEqual(result["limitations"], policy.NAMESPACE_LIMITATIONS)


class NamespaceSelectionTests(unittest.TestCase):
    def test_isolated_image_is_excluded_from_path_policy(self):
        with tempfile.TemporaryDirectory() as directory:
            manager = Manager(Path(directory), 18879)
            try:
                manager.settings["apps"] = [
                    {"id": "isolated", "enabled": True, "windows_container": True,
                     "path": r"C:\Apps\browser.exe", "related_paths": [r"C:\Apps\helper.exe"]},
                    {"id": "compat", "enabled": True, "path": r"C:\Apps\compat.exe"}]
                self.assertEqual(manager._selected_windows_paths(), [r"C:\Apps\compat.exe"])
                manager.settings["apps"].pop()
                manager.core = mock.Mock(pid=102, poll=mock.Mock(return_value=None))
                manager._windows_backend = mock.Mock()
                with mock.patch("ruleproxy.manager.sys.platform", "win32"):
                    manager._sync_windows_policy()
                manager._windows_backend.namespace_prepare.assert_called_once_with(manager.mixed_port, 102)
                manager._windows_backend.apply.assert_not_called()
                # Another path policy must not mark an unlaunched namespace
                # instance as routed. Its own running Job is the prerequisite.
                manager._windows_paths = [r"C:\Apps\compat.exe"]
                with mock.patch.object(manager, "available_apps", return_value=([], False)), \
                        mock.patch.object(manager, "files_dir", return_value=None), \
                        mock.patch.object(manager, "protection", return_value={"supported": True}), \
                        mock.patch.object(manager, "autostart_status", return_value="off"), \
                        mock.patch("ruleproxy.manager.sys.platform", "win32"):
                    self.assertFalse(manager.state()["apps"][0]["routed"])
                    manager.active["isolated"] = (mock.Mock(pid=200, poll=mock.Mock(return_value=None)), None)
                    self.assertTrue(manager.state()["apps"][0]["routed"])
            finally:
                manager.active.clear()
                manager.core = None
                manager.close()


class NativeCompartmentEvidenceTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        path = Path(__file__).resolve().parent.parent / ".github/windows_proxifyre_vm.py"
        spec = importlib.util.spec_from_file_location("namespace_vm_review", path)
        cls.vm = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(cls.vm)

    def result(self):
        return {"status": "passed", "suite": "compartment-lab", "exit_code": 0, "package_sha256": "a" * 64,
                "os": {"build": 26100, "product_type": "WinNT", "native_architecture": "AMD64"},
                "reports": {"compartment": {"product_qualified": False, "source_commit": "b" * 40,
                                             "assessment": {}}}}

    def test_lab_completion_never_qualifies_the_product(self):
        report = self.vm.verify_compartment_lab_result(self.result(), package_sha256="a" * 64)
        self.assertFalse(report["product_qualified"])
        for scope in ("product_qualified", "source_commit", "assessment"):
            bad = self.result()
            del bad["reports"]["compartment"][scope]
            with self.subTest(scope=scope), self.assertRaises(RuntimeError):
                self.vm.verify_compartment_lab_result(bad, package_sha256="a" * 64)

    def test_server_failure_wrong_package_and_false_exit_are_rejected(self):
        variants = [self.result() for _ in range(4)]
        variants[0]["os"]["product_type"] = "ServerNT"
        variants[1]["package_sha256"] = "c" * 64
        variants[2]["exit_code"] = False
        variants[3]["reports"]["compartment"]["error"] = "failed"
        for value in variants:
            with self.assertRaises(RuntimeError):
                self.vm.verify_compartment_lab_result(value, package_sha256="a" * 64)


if __name__ == "__main__":
    unittest.main()
