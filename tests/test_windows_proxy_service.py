import ctypes
import json
from pathlib import Path
import tempfile
import unittest
from unittest import mock

from ruleproxy import windows_proxy_service as service
from ruleproxy import windows_proxy_policy as policy
from ruleproxy.windows_proxy_runtime import Runtime


class Control:
    def __init__(self):
        self.state, self.calls, self.fail_start = 1, [], False

    def status(self):
        return {"state": self.state, "pid": 77 if self.state == 4 else 0}

    def verify(self, _metadata):
        self.calls.append("verify")

    def set_running(self, running):
        self.calls.append("start" if running else "stop")
        if running and self.fail_start:
            self.fail_start = False
            raise policy.ProxyError("backend_start_failed", "injected start failure")
        self.state = 4 if running else 1
        return self.status()


class Lease:
    def __init__(self, pid, _sid, root):
        self.pid, self.root, self.live, self.closed = pid, root, True, False

    def alive(self):
        return self.live

    def close(self):
        self.closed = True

    def image_path(self):
        return str(self.root / "bin/windows-amd64/mihomo.exe")


class BrokerTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        self.engine = self.root / "engine"
        self.engine.mkdir()
        self.sid = "S-1-5-21-1-2-3-1000"
        self.control = Control()
        self.created = []
        def factory(pid, sid):
            item = Lease(pid, sid, self.root)
            self.created.append(item)
            return item
        self.broker = service.Broker({"owner_sid": self.sid, "root": str(self.root),
            "proxifyre_root": str(self.engine)}, self.control, factory)
        self.patch = mock.patch.object(service, "verify_selected_paths")
        self.patch.start()
        self.addCleanup(self.patch.stop)

    def request(self, operation="apply", **fields):
        value = {"op": operation, "client_pid": 101}
        if operation == "apply":
            value.update(paths=[r"C:\Apps\App.exe"], proxy_port=10809, mihomo_pid=102,
                         generation=self.broker.generation + 1)
        value.update(fields)
        return value

    def handle(self, operation="apply", **fields):
        return self.broker.handle(self.request(operation, **fields), 101, self.sid)

    def test_apply_writes_fixed_config_and_tracks_generation(self):
        result = self.handle()
        self.assertEqual(result["state"], "running")
        self.assertEqual(result["generation"], 1)
        config = json.loads((self.engine / "app-config.json").read_text())
        self.assertEqual(config["proxies"][0]["socks5ProxyEndpoint"], "127.0.0.1:10809")

    def test_same_policy_is_idempotent(self):
        self.handle()
        before = list(self.control.calls)
        self.assertTrue(self.handle()["unchanged"])
        self.assertEqual(self.control.calls, before)
        self.assertEqual(self.broker.generation, 1)

    def test_identity_and_generation_rejected_before_mutation(self):
        for pid, sid, fields in ((999, self.sid, {}), (101, "S-1-5-21-1-2-3-1001", {}),
                                 (101, self.sid, {"generation": 9})):
            with self.assertRaises(policy.ProxyError):
                self.broker.handle(self.request(**fields), pid, sid)
        self.assertEqual(self.control.calls, [])

    def test_start_failure_restores_previous_file(self):
        config = self.engine / "app-config.json"
        config.write_bytes(b"old safe config")
        self.control.fail_start = True
        with self.assertRaises(policy.ProxyError):
            self.handle()
        self.assertEqual(config.read_bytes(), b"old safe config")
        self.assertEqual(self.control.state, 1)
        self.assertTrue(all(item.closed for item in self.created))
        self.assertEqual(self.broker.generation, 0)

    def test_panel_or_core_death_stops_owned_engine(self):
        self.handle()
        self.broker.core.live = False
        self.broker.check_lease()
        self.assertEqual(self.control.state, 1)
        self.assertEqual(self.broker.snapshot()["state"], "idle")
        self.assertTrue(all(item.closed for item in self.created))

    def test_external_service_not_stopped_or_adopted(self):
        self.control.state = 4
        self.assertEqual(self.broker.snapshot()["state"], "external_conflict")
        self.assertTrue(self.handle("stop")["not_owned"])
        self.assertEqual(self.control.state, 4)
        with self.assertRaises(policy.ProxyError):
            self.handle()
        self.assertNotIn("stop", self.control.calls)

    def test_second_panel_cannot_replace_lease(self):
        self.handle()
        request = self.request(client_pid=222)
        with self.assertRaises(policy.ProxyError):
            self.broker.handle(request, 222, self.sid)

    def test_source_runtime_reports_setup_without_fallback(self):
        runtime = Runtime(self.root)
        with mock.patch("ruleproxy.windows_proxy_runtime.os.name", "posix"):
            result = runtime.probe()
        self.assertFalse(result["supported"])
        self.assertEqual(result["state"], "setup_required")
        self.assertFalse(result["strict_isolation"])

    def container_gate(self):
        gate = mock.Mock()
        gate.allow.return_value = {'active': True}
        gate.revoke.return_value = {'active': False}
        gate.purge.return_value = {'active': False, 'purged_sids': []}
        self.broker.container_factory = mock.Mock(return_value=gate)
        return gate

    def allow_container(self, **fields):
        return self.handle('container_allow', container='RuleProxy.' + 'a' * 20,
                           proxy_port=fields.pop('proxy_port', 10809), **fields)

    def test_container_allow_requires_the_held_panel_and_core_port(self):
        gate = self.container_gate()
        with self.assertRaises(policy.ProxyError):
            self.allow_container()
        gate.allow.assert_not_called()
        self.handle()
        with self.assertRaises(policy.ProxyError):
            self.allow_container(proxy_port=10810)
        request = self.request('container_allow', client_pid=222,
                               container='RuleProxy.' + 'a' * 20, proxy_port=10809)
        with self.assertRaises(policy.ProxyError):
            self.broker.handle(request, 222, self.sid)
        gate.allow.assert_not_called()
        self.allow_container()
        self.assertEqual(self.broker.snapshot()['container_count'], 1)

    def test_dead_owner_purges_containers_before_releasing_held_processes(self):
        gate = self.container_gate()
        self.handle()
        self.allow_container()
        gate.purge.side_effect = lambda: (self.assertFalse(self.broker.panel.closed)
                                          or {'active': False, 'purged_sids': []})
        self.broker.panel.live = False
        self.broker.check_lease()
        gate.purge.assert_called_once()
        self.assertEqual(self.control.state, 1)
        self.assertEqual(self.broker.snapshot()['container_count'], 0)

    def test_failed_allow_retains_cleanup_intent_until_confirmed_purge(self):
        gate = self.container_gate()
        self.handle()
        gate.allow.side_effect = OSError('readback failed after commit')
        with self.assertRaises(OSError):
            self.allow_container()
        self.assertEqual(len(self.broker.containers), 1)
        self.handle('stop')
        gate.purge.assert_called_once()
        self.assertFalse(self.broker.containers)

    def test_failed_purge_preserves_owner_and_retries_on_next_watch(self):
        gate = self.container_gate()
        self.handle()
        self.allow_container()
        self.broker.panel.live = False
        gate.purge.side_effect = [OSError('temporary WFP failure'), {'active': False}]
        with mock.patch.object(service, '_log_service_error'):
            self.broker.check_lease()
        self.assertIsNotNone(self.broker.panel)
        self.assertEqual(len(self.broker.containers), 1)
        self.assertTrue(self.broker.snapshot()['cleanup_pending'])
        self.broker.check_lease()
        self.assertIsNone(self.broker.panel)
        self.assertFalse(self.broker.containers)
        self.assertEqual(gate.purge.call_count, 2)

    def test_failed_revoke_keeps_broker_intent_and_can_be_retried(self):
        gate = self.container_gate()
        self.handle()
        self.allow_container()
        gate.revoke.side_effect = [OSError('temporary IPC failure'), {'active': False}]
        fields = {'container': 'RuleProxy.' + 'a' * 20}
        with self.assertRaises(OSError):
            self.handle('container_revoke', **fields)
        self.assertEqual(len(self.broker.containers), 1)
        self.handle('container_revoke', **fields)
        self.assertFalse(self.broker.containers)

    def test_restart_recovery_and_ownerless_shutdown_require_confirmed_purge(self):
        gate = self.container_gate()
        self.broker.recover_containers()
        self.broker.containers.add('RuleProxy.' + 'a' * 20)
        self.broker.shutdown()
        self.assertEqual(gate.purge.call_count, 2)
        self.assertFalse(self.broker.containers)
        gate.purge.return_value = {'active': True}
        with self.assertRaises(policy.ProxyError):
            self.broker.recover_containers()

    def test_replacing_proxy_port_revokes_old_container_permissions(self):
        gate = self.container_gate()
        self.handle()
        self.allow_container()
        self.handle(proxy_port=10810)
        gate.purge.assert_called_once()
        self.assertFalse(self.broker.containers)


class ServiceConfigurationTests(unittest.TestCase):
    def test_scm_configuration_query_never_exceeds_native_eight_kib_limit(self):
        class QueryObserved(Exception):
            pass
        control = object.__new__(service.ServiceControl)
        control.api = mock.Mock()
        control._open = mock.Mock(return_value=19)
        def query(_handle, buffer, length, _needed):
            self.assertLessEqual(length, 8192)
            self.assertEqual(length, len(buffer))
            self.assertGreater(length, 0)
            raise QueryObserved()
        control.api.QueryServiceConfigW.side_effect = query
        with mock.patch.object(service, "_dll", return_value=mock.Mock()), self.assertRaises(QueryObserved):
            control.verify({"root": str(Path.cwd()), "proxifyre_root": str(Path.cwd() / "engine")})
        control.api.QueryServiceConfigW.assert_called_once()
        control.api.CloseServiceHandle.assert_called_once_with(19)


class ServiceDiagnosticTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name) / "RuleProxy-Web"
        self.root.mkdir()
        self.environment = mock.patch.dict(service.os.environ, {"ProgramData": self.temp.name})
        self.environment.start()
        self.addCleanup(self.environment.stop)

    def test_protected_fixed_log_keeps_time_frames_and_error_codes_without_secrets(self):
        try:
            try:
                raise ValueError("request body and node credential must never be logged")
            except ValueError as cause:
                raise OSError(5, "private configuration contents") from cause
        except OSError as error:
            with mock.patch.object(service, "protected_path") as protect:
                self.assertTrue(service._log_service_error("service_main", error))
        raw = (self.root / "service.log").read_text()
        record = json.loads(raw)
        self.assertEqual(protect.call_args_list, [mock.call(self.root)])
        self.assertEqual(record["context"], "service_main")
        self.assertTrue(record["time_utc"].endswith("+00:00"))
        self.assertEqual(record["exceptions"][0]["errno"], 5)
        self.assertEqual([item["type"] for item in record["exceptions"]], ["OSError", "ValueError"])
        self.assertTrue(record["exceptions"][0]["traceback"])
        self.assertNotIn("credential", raw)
        self.assertNotIn("private configuration", raw)
        self.assertNotIn("raise OSError", raw)

    def test_untrusted_log_directory_does_not_receive_privileged_fallback(self):
        with mock.patch.object(service, "protected_path", side_effect=policy.ProxyError("unsafe_installation", "unsafe")):
            self.assertFalse(service._log_service_error("service_main", RuntimeError("private")))
        self.assertFalse((self.root / "service.log").exists())

    def test_diagnostic_file_is_bounded_and_existing_file_is_revalidated(self):
        path = self.root / "service.log"
        path.write_bytes(b"x" * service._LOG_LIMIT)
        with mock.patch.object(service, "protected_path") as protect:
            self.assertTrue(service._log_service_error("watchdog", policy.ProxyError("backend_timeout", "private")))
        self.assertEqual(protect.call_args_list, [mock.call(self.root), mock.call(path)])
        self.assertLess(path.stat().st_size, service._LOG_LIMIT)
        self.assertEqual(json.loads(path.read_text())["exceptions"][0]["code"], "backend_timeout")

    def test_lease_cleanup_failure_is_logged_once_and_remains_visible(self):
        broker = service.Broker({"owner_sid": "owner"}, control=mock.Mock())
        broker.panel = mock.Mock()
        broker.panel.alive.return_value = False
        broker.core = mock.Mock()
        broker.engine_owned = True
        broker.control.set_running.side_effect = OSError(5, "private")
        with mock.patch.object(service, "_log_service_error") as log:
            broker.check_lease()
            broker.check_lease()
        log.assert_called_once()
        self.assertEqual(log.call_args.args[0], "lease_cleanup")
        self.assertEqual(broker.error["code"], "cleanup_incomplete")


if __name__ == "__main__":
    unittest.main()
