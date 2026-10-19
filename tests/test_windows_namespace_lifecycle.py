"""Failure paths must seal every gate without taking an unrelated engine."""
import copy
from pathlib import Path
import tempfile
import unittest
from unittest import mock

from ruleproxy.manager import Manager
from ruleproxy import windows_proxy_policy as policy
from ruleproxy import windows_proxy_service as service
from tests.test_windows_proxy_service import Control, Lease


class NamespaceLifecycleTests(unittest.TestCase):
    def setUp(self):
        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        self.root = Path(temporary.name)
        (self.root / "engine").mkdir()
        self.sid = "S-1-5-21-1-2-3-1001"
        self.control = Control()
        self.leases = []

        def lease(pid, sid):
            result = Lease(pid, sid, self.root)
            self.leases.append(result)
            return result

        self.broker = service.Broker({"owner_sid": self.sid, "root": str(self.root),
            "proxifyre_root": str(self.root / "engine")}, self.control, lease)
        patch = mock.patch.object(service, "verify_selected_paths")
        patch.start()
        self.addCleanup(patch.stop)

    def request(self, operation="namespace_prepare", **fields):
        result = {"op": operation, "client_pid": 101, "mihomo_pid": 102,
                  "proxy_port": 7890, "generation": self.broker.generation + 1}
        if operation == "apply":
            result["paths"] = [r"C:\Apps\App.exe"]
        result.update(fields)
        return self.broker.handle(result, 101, self.sid)

    def gates(self):
        container, namespace = mock.Mock(), mock.Mock()
        for gate in (container, namespace):
            gate.purge.return_value = {"active": False}
            gate.allow.return_value = {"active": True}
        self.broker.container_gate = container
        self.broker.namespace_gate = namespace
        self.broker.containers.add("old-container")
        self.broker.namespaces.add("old-namespace")
        return container, namespace

    def test_namespace_stop_never_controls_an_engine_started_after_prepare(self):
        self.request()
        _, namespace = self.gates()
        self.control.state = 4
        self.assertTrue(self.request("stop")["stopped"])
        self.assertEqual(self.control.calls, [])
        self.assertEqual(self.control.state, 4)
        namespace.purge.assert_called_once_with()
        self.assertTrue(all(lease.closed for lease in self.leases))
        self.assertEqual(self.broker.snapshot()["state"], "external_conflict")

    def test_dead_namespace_owner_seals_gate_without_stopping_external_engine(self):
        self.request()
        _, namespace = self.gates()
        self.control.state = 4
        self.broker.panel.live = False
        self.broker.check_lease()
        namespace.purge.assert_called_once_with()
        self.assertEqual(self.control.calls, [])
        self.assertEqual(self.control.state, 4)
        self.assertIsNone(self.broker.panel)

    def test_external_engine_blocks_reprepare_and_apply_even_with_a_namespace_lease(self):
        self.request()
        self.control.state = 4
        for operation in ("namespace_prepare", "apply"):
            with self.subTest(operation=operation), self.assertRaises(policy.ProxyError) as caught:
                self.request(operation)
            self.assertEqual(caught.exception.code, "external_instance_conflict")
        self.assertNotIn("stop", self.control.calls)
        self.assertEqual(self.broker.generation, 1)
        result = self.broker.snapshot()
        self.assertEqual(result["state"], "external_conflict")
        self.assertFalse(result["namespace_ready"])
        self.assertFalse(result["running"])

    def test_same_core_transition_keeps_namespace_jobs_while_releasing_own_engine(self):
        self.request("apply")
        _, namespace = self.gates()
        self.control.calls.clear()
        result = self.request()
        namespace.purge.assert_not_called()
        self.assertEqual(self.broker.namespaces, {"old-namespace"})
        self.assertEqual(self.control.calls, ["stop"])
        self.assertTrue(result["namespace_ready"])
        self.assertFalse(self.broker.engine_owned)

    def test_relay_core_check_survives_same_pid_lease_replacement_and_rejects_death(self):
        self.request()
        _, namespace = self.gates()
        self.request("namespace_allow", container="new-namespace", job_handle=42)
        arguments = namespace.allow.call_args.kwargs
        self.assertEqual(arguments["core_pid"], 102)
        alive = arguments["core_alive"]
        original_lease = self.broker.core
        self.assertTrue(alive())
        self.request("apply")
        self.request()
        self.assertTrue(original_lease.closed)
        self.assertTrue(alive())
        self.broker.core.live = False
        self.assertFalse(alive())
        self.broker.stop()
        self.assertFalse(alive())

    def test_failed_gate_cleanup_still_seals_other_gate_and_stops_owned_engine(self):
        self.request("apply")
        container, namespace = self.gates()
        container.purge.side_effect = OSError("container failure")
        panel = self.broker.panel
        with self.assertRaisesRegex(policy.ProxyError, "container failure"):
            self.broker.stop()
        namespace.purge.assert_called_once_with()
        self.assertEqual(self.control.state, 1)
        self.assertFalse(self.broker.engine_owned)
        self.assertIs(self.broker.panel, panel)
        self.assertFalse(panel.closed)
        self.assertEqual(self.broker.namespaces, set())
        self.assertEqual(self.broker.containers, {"old-container"})
        self.assertTrue(self.broker.snapshot()["cleanup_pending"])
        container.purge.side_effect = None
        self.broker.check_lease()
        self.assertIsNone(self.broker.panel)
        self.assertTrue(panel.closed)
        self.assertEqual(self.broker.snapshot()["state"], "idle")

    def test_all_cleanup_failures_are_reported_and_override_running_status(self):
        self.request("apply")
        container, namespace = self.gates()
        container.purge.side_effect = OSError("container failure")
        namespace.purge.side_effect = OSError("namespace failure")
        with mock.patch.object(self.control, "set_running", side_effect=OSError("engine failure")):
            with self.assertRaises(policy.ProxyError) as caught:
                self.broker.stop()
        for message in ("container failure", "namespace failure", "engine failure"):
            self.assertIn(message, str(caught.exception))
        result = self.broker.snapshot()
        self.assertTrue(result["engine_running"])
        self.assertTrue(result["engine_owned"])
        self.assertTrue(result["cleanup_pending"])
        self.assertEqual(result["state"], "failed")
        self.assertFalse(result["running"])

    def test_ownerless_stop_attempts_both_gates_on_first_failure(self):
        container, namespace = self.gates()
        container.purge.side_effect = OSError("orphan container")
        with self.assertRaises(policy.ProxyError):
            self.request("stop")
        namespace.purge.assert_called_once_with()
        self.assertEqual(self.control.calls, [])
        self.assertTrue(self.broker.snapshot()["cleanup_pending"])

    def test_changed_core_cleanup_failure_does_not_skip_namespace_or_replace_lease(self):
        self.request()
        held = self.broker.core
        container, namespace = self.gates()
        container.purge.side_effect = OSError("container failure")
        with self.assertRaises(policy.ProxyError):
            self.request(mihomo_pid=103)
        namespace.purge.assert_called_once_with()
        self.assertIs(self.broker.core, held)
        self.assertFalse(held.closed)
        self.assertTrue(all(lease.closed for lease in self.leases[2:]))
        self.assertEqual(self.broker.generation, 1)
        self.assertFalse(self.broker.snapshot()["namespace_ready"])

    def test_pending_cleanup_blocks_new_namespace_authorization(self):
        self.request()
        container, namespace = self.gates()
        container.purge.side_effect = OSError("cleanup still failing")
        with self.assertRaises(policy.ProxyError):
            self.broker.stop()
        with self.assertRaises(policy.ProxyError) as caught:
            self.request("namespace_allow", container="new", job_handle=42)
        self.assertEqual(caught.exception.code, "cleanup_incomplete")
        namespace.allow.assert_not_called()

    def test_dead_lease_cannot_report_running_before_watchdog_cleanup(self):
        for operation in ("namespace_prepare", "apply"):
            with self.subTest(operation=operation):
                self.request(operation)
                self.broker.core.live = False
                result = self.broker.snapshot()
                self.assertEqual(result["state"], "failed")
                self.assertEqual(result["error"]["code"], "lease_expired")
                self.assertFalse(result["running"])
                self.assertFalse(result["namespace_ready"])
                self.broker.stop()

    def test_unconfirmed_engine_stop_retains_ownership_for_retry(self):
        self.request("apply")
        with mock.patch.object(self.control, "set_running", return_value={"state": 4}):
            with self.assertRaises(policy.ProxyError):
                self.broker.stop()
        self.assertTrue(self.broker.engine_owned)
        self.assertIsNotNone(self.broker.panel)
        self.broker.stop()
        self.assertFalse(self.broker.engine_owned)
        self.assertIsNone(self.broker.panel)

    def test_uncertain_start_retains_cleanup_authority_without_a_published_lease(self):
        def fail_transition(running):
            if running:
                self.control.state = 4
                raise OSError("start timed out after process creation")
            raise OSError("stop timed out")

        with mock.patch.object(self.control, "set_running", side_effect=fail_transition):
            with self.assertRaises(policy.ProxyError):
                self.request("apply")
        self.assertTrue(self.broker.engine_owned)
        self.assertIsNone(self.broker.panel)
        self.assertTrue(all(lease.closed for lease in self.leases))
        self.assertEqual(self.broker.snapshot()["state"], "failed")
        self.broker.check_lease()
        self.assertFalse(self.broker.engine_owned)
        self.assertEqual(self.control.state, 1)
        self.assertEqual(self.broker.snapshot()["state"], "idle")

    def test_shutdown_attempts_global_cleanup_after_each_application_failure(self):
        self.request()
        container, namespace = self.gates()
        container.purge.side_effect = OSError("container failure")
        namespace.purge.side_effect = OSError("namespace failure")
        self.broker.global_core = mock.Mock()
        self.broker.global_core.stop.side_effect = OSError("global failure")
        global_panel = self.broker.global_panel = mock.Mock()
        with self.assertRaises(policy.ProxyError) as caught:
            self.broker.shutdown()
        namespace.purge.assert_called_once_with()
        self.broker.global_core.stop.assert_called_once_with(normal=False)
        global_panel.close.assert_not_called()
        for message in ("container failure", "namespace failure", "global failure"):
            self.assertIn(message, str(caught.exception))


class IsolationToggleRollbackTests(unittest.TestCase):
    def setUp(self):
        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        self.manager = Manager(Path(temporary.name), 18879)
        self.addCleanup(self.manager.close)
        self.manager.settings["apps"] = [{"id": "app", "label": "App", "path": str(Path(temporary.name) / "app.exe"),
            "adapter": "environment", "args": [], "enabled": True, "windows_container": False}]
        self.original = copy.deepcopy(self.manager.settings["apps"])

    def test_failed_isolation_change_restores_settings_and_old_policy(self):
        with mock.patch("ruleproxy.manager.sys.platform", "win32"), \
                mock.patch.object(self.manager, "_sync_windows_policy", side_effect=[OSError("new policy failed"), None]) as sync, \
                mock.patch.object(self.manager, "_save") as save, \
                mock.patch.object(self.manager, "stop") as stop:
            with self.assertRaisesRegex(OSError, "new policy failed"):
                self.manager.set_app_isolation("app", True)
        self.assertEqual(self.manager.settings["apps"], self.original)
        self.assertEqual(sync.call_count, 2)
        save.assert_not_called()
        stop.assert_not_called()

    def test_failed_policy_restoration_stops_core_and_preserves_original_failure(self):
        with mock.patch("ruleproxy.manager.sys.platform", "win32"), \
                mock.patch.object(self.manager, "_sync_windows_policy", side_effect=[OSError("new policy failed"), OSError("old policy failed")]), \
                mock.patch.object(self.manager, "stop") as stop:
            with self.assertRaisesRegex(OSError, "new policy failed"):
                self.manager.set_app_isolation("app", True)
        self.assertEqual(self.manager.settings["apps"], self.original)
        self.assertIn("旧规则也未能恢复", self.manager.error)
        stop.assert_called_once_with()

    def test_settings_write_failure_restores_old_network_policy(self):
        with mock.patch("ruleproxy.manager.sys.platform", "win32"), \
                mock.patch.object(self.manager, "_sync_windows_policy") as sync, \
                mock.patch.object(self.manager, "_save", side_effect=OSError("disk full")), \
                mock.patch.object(self.manager, "stop") as stop:
            with self.assertRaisesRegex(OSError, "disk full"):
                self.manager.set_app_isolation("app", True)
        self.assertEqual(self.manager.settings["apps"], self.original)
        self.assertEqual(sync.call_count, 2)
        stop.assert_not_called()


if __name__ == "__main__":
    unittest.main()
