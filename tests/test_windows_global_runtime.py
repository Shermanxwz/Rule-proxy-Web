"""Global broker trust/lifecycle checks; these never create a TUN or WFP rule."""
import json
from pathlib import Path
import socket
import sys
import tempfile
from types import SimpleNamespace
import unittest
from unittest import mock

import yaml

from ruleproxy import windows_proxy_policy as policy
from ruleproxy import windows_proxy_service as service
from ruleproxy.windows_global_runtime import Runtime


SOURCE = "proxies:\n  - {name: node-a, type: socks5, server: 1.1.1.1, port: 29001}\n"
SID = "S-1-5-21-1-2-3-1000"


def fields(**overrides):
    return {"source": SOURCE, "secret": "local-test-secret", "mixed_port": 28009,
            "controller_port": 29097, "selected_node": "node-a", "require_strict": False, **overrides}


class Guard:
    def __init__(self, events):
        self.events, self.active, self.applies = events, False, 0
        self.strict = False

    def status(self):
        return {"supported": True, "active": self.active, "persistent": self.active,
                "strict_isolation": self.active and self.strict and self.applies > 1, "native_qualified": True,
                "tun_ready": self.active and self.applies > 1,
                "detail": "Unit fixture only: no native protection claim"}

    def apply(self, core, tun):
        self.events.append(("guard_apply", Path(core), dict(tun)))
        self.applies += 1
        self.active = True
        return self.status()

    def normal_stop(self):
        self.events.append(("normal_stop",))
        self.active = False
        return self.status()

    def crash_keep(self):
        self.events.append(("crash_keep",))
        return self.status()


class LateTunGuard(Guard):
    """The TUN adapter appears one poll after the controller already answers."""

    def status(self):
        value = super().status()
        ready = self.active and self.applies > 2
        value["tun_ready"] = ready
        value["strict_isolation"] = self.active and self.strict and ready
        return value


class Process:
    def __init__(self, events, live=True):
        self.events, self.live, self.pid = events, live, 12345

    def poll(self):
        return None if self.live else 1

    def terminate(self):
        self.events.append(("terminate",))
        self.live = False

    def wait(self, timeout):
        self.events.append(("wait", timeout))
        return 1


class DNS:
    def __init__(self, events):
        self.events, self.active = events, False

    def status(self, *, refresh=False):
        return {"supported": True, "active": self.active, "effective": self.active,
                "persistent": self.active, "fresh": True, "native_qualified": True,
                "state": "candidate_active" if self.active else "idle"}

    def apply(self):
        self.events.append(("dns_apply",))
        self.active = True
        return self.status()

    def normal_stop(self):
        self.events.append(("dns_stop",))
        self.active = False
        return self.status()

    def crash_keep(self):
        self.events.append(("dns_keep",))
        return self.status()


class GlobalCoreTests(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        self.root = Path(self.temporary.name)
        self.state = self.root / "state/global"
        self.state.mkdir(parents=True)
        self.executable = self.root / "bin/windows-amd64/mihomo.exe"
        self.executable.parent.mkdir(parents=True)
        self.executable.write_bytes(b"fixed installed core fixture")
        required = {"ruleproxy/config.py", "ruleproxy/windows_global_runtime.py", "ruleproxy/windows_app_process.py",
                    "ruleproxy/windows_global_dns.py", "ruleproxy/windows_global_qualification.py"}
        self.metadata = {"root": str(self.root), "owner_sid": SID, "global_backend_version": 1,
                         "files": {name: "a" * 64 for name in required}}
        self.metadata["files"]["bin/windows-amd64/mihomo.exe"] = service._file_hash(self.executable)
        self.events = []
        self.guard = Guard(self.events)
        self.dns = DNS(self.events)
        self.process = Process(self.events)
        def launch(command, env, cwd):
            self.events.append(("launch", command, env, cwd))
            return self.process
        def validate(command, **kwargs):
            self.events.append(("validate", command, kwargs))
            return SimpleNamespace(returncode=0)
        self.launch = mock.Mock(side_effect=launch)
        self.validator = mock.Mock(side_effect=validate)
        self.core = service.GlobalCore(self.metadata, guard=self.guard, dns=self.dns, launcher=self.launch,
                    validator=self.validator, health=lambda *_: True, management=lambda: [],
                    state_directory=self.state)
        self.protection = mock.patch.object(service, "protected_path")
        self.protection.start()
        self.addCleanup(self.protection.stop)

    def test_config_validation_failure_has_no_launch_or_guard_effect(self):
        self.validator.side_effect = None
        self.validator.return_value = SimpleNamespace(returncode=1)
        with self.assertRaises(policy.ProxyError):
            self.core.start(fields())
        self.launch.assert_not_called()
        self.assertFalse(self.guard.active)
        self.assertEqual(self.guard.applies, 0)

    def test_dns_readonly_preflight_failure_does_not_install_a_guard(self):
        self.dns.status = mock.Mock(return_value={"supported": False, "state": "unavailable"})
        with self.assertRaises(policy.ProxyError) as caught:
            self.core.start(fields())
        self.assertEqual(caught.exception.code, "global_dns_conflict")
        self.assertEqual(self.events, [])
        self.assertFalse((self.state / "config.yaml").exists())

    def test_changed_core_is_rejected_before_any_guard_effect(self):
        self.executable.write_bytes(b"changed")
        with self.assertRaises(policy.ProxyError) as caught:
            self.core.start(fields())
        self.assertEqual(caught.exception.code, "installation_changed")
        self.assertEqual(self.events, [])

    def test_strict_request_is_rejected_if_native_guard_unavailable(self):
        self.core.guard = service.UnavailableGlobalGuard()
        with self.assertRaises(policy.ProxyError) as caught:
            self.core.start(fields(require_strict=True))
        self.assertEqual(caught.exception.code, "strict_guard_unavailable")
        self.assertFalse((self.state / "config.yaml").exists())
        self.assertEqual(self.events, [])

    def test_supported_but_unqualified_guard_is_rejected_without_installing_filters(self):
        candidate = self.guard.status()
        candidate["native_qualified"] = False
        self.guard.status = mock.Mock(return_value=candidate)
        with self.assertRaises(policy.ProxyError) as caught:
            self.core.start(fields(require_strict=True))
        self.assertEqual(caught.exception.code, "strict_guard_unavailable")
        self.assertFalse((self.state / "config.yaml").exists())
        self.assertEqual(self.events, [])

    def test_strict_dns_preflight_requires_fresh_supported_qualified_idle_state(self):
        original = self.dns.status()
        for field in ("supported", "native_qualified", "fresh", "state"):
            for bad in (None, 1):
                with self.subTest(field=field, bad=bad):
                    value = {**original, field: bad}
                    with mock.patch.object(self.dns, "status", return_value=value), \
                            self.assertRaises(policy.ProxyError):
                        self.core.start(fields(require_strict=True))
                    self.assertEqual(self.events, [])
                    self.assertFalse((self.state / "config.yaml").exists())

    def test_private_controller_never_discloses_token_to_a_replaced_listener(self):
        connection = mock.Mock()
        connection.sock.getsockname.return_value = ("127.0.0.1", 48291)
        row = {"state": 5, "pid": 98765, "local_port": 29097, "remote_port": 48291,
               "local": "127.0.0.1", "remote": "127.0.0.1"}
        with mock.patch.object(service.http.client, "HTTPConnection", return_value=connection), \
                mock.patch.object(service, "_tcp_connections", return_value=[row]), \
                self.assertRaises(policy.ProxyError) as caught:
            self.core._controller_ready(29097, self.core._controller_secret, self.process)
        self.assertEqual(caught.exception.code, "invalid_controller_owner")
        connection.request.assert_not_called()
        connection.close.assert_called_once()

    def test_old_installation_is_setup_required_even_while_idle(self):
        self.metadata.pop("global_backend_version")
        result = self.core.status()
        self.assertFalse(result["supported"])
        self.assertTrue(result["setup_required"])
        self.assertFalse(result["running"])
        self.assertIn("修复", result["detail"])

    def test_dns_checking_keeps_installed_capability_separate_from_policy_confirmation(self):
        self.dns.status = mock.Mock(return_value={"supported": True, "component_available": True,
            "state": "checking", "active": None, "effective": False, "fresh": False,
            "verification_pending": True, "native_qualified": False})
        result = self.core.status()
        self.assertTrue(result["supported"])
        self.assertTrue(result["component_supported"])
        self.assertFalse(result["policy_ready"])
        self.assertFalse(result["strict_isolation"])


class GlobalProtocolTests(unittest.TestCase):
    def request(self, **overrides):
        return {"schema_version": 1, "request_id": "c" * 32, "op": "global_start", "client_pid": 101,
                **fields(), **overrides}

    def test_closed_protocol_rejects_command_paths_ports_and_boolean_confusion(self):
        request = self.request()
        self.assertEqual(policy.decode_request(json.dumps(request).encode()), request)
        for change in ({"command": "whoami"}, {"executable": r"C:\Users\x\evil.exe"},
                       {"directory": r"C:\Users\x"}, {"mixed_port": True},
                       {"env": {"SKIP_SYSTEM_IPV6_CHECK": "false"}},
                       {"controller_port": 80}, {"controller_port": 28009},
                       {"require_strict": 1}, {"source": "x\0"}, {"op": []}):
            with self.subTest(change=change), self.assertRaises(policy.ProxyError):
                policy.decode_request(json.dumps({**request, **change}).encode())

    def test_node_switch_does_not_offer_an_arbitrary_controller_proxy(self):
        request = {"schema_version": 1, "request_id": "e" * 32, "op": "global_select_node",
                   "client_pid": 101, "selected_node": "node-a"}
        self.assertEqual(policy.decode_request(json.dumps(request).encode()), request)
        for extra in ({"path": "/configs"}, {"method": "PUT"}, {"data": {"path": "evil.yaml"}},
                      {"selected_node": None}):
            with self.subTest(extra=extra), self.assertRaises(policy.ProxyError):
                policy.decode_request(json.dumps({**request, **extra}).encode())

    def test_source_and_wire_have_independent_hard_bounds(self):
        with self.assertRaises(policy.ProxyError):
            policy.validate_global_request(fields(source="x" * (policy.MAX_GLOBAL_SOURCE + 1)))
        with self.assertRaises(policy.ProxyError):
            policy.decode_request(b"x" * (policy.MAX_MESSAGE + 1))
        with self.assertRaises(policy.ProxyError):
            policy.validate_global_request(fields(source="\ud800"))
        request = self.request(source="#" + "中文" * 45000 + "\n" + SOURCE)
        raw = json.dumps(request, ensure_ascii=False).encode("utf-8")
        self.assertGreater(len(raw), 256 * 1024)
        self.assertEqual(policy.decode_request(raw), request)

    def test_old_or_missing_service_does_not_masquerade_as_idle_capability(self):
        runtime = Runtime(Path.cwd())
        connection = mock.Mock()
        connection.request.side_effect = policy.ProxyError("invalid_request", "old service")
        with mock.patch.object(runtime, "_connect", return_value=connection):
            result = runtime.status()
        self.assertFalse(result["supported"])
        self.assertTrue(result["setup_required"])
        self.assertIn("Setup-Windows.cmd", result["detail"])
        self.assertFalse(result["guard"]["active"])

    def test_stop_reconnects_to_restore_guard_after_a_previous_panel_crash(self):
        runtime = Runtime(Path.cwd())
        connection = mock.Mock()
        connection.request.return_value = {"stopped": True}
        with mock.patch.object(runtime, "_connect", return_value=connection) as connect:
            self.assertEqual(runtime.stop(), {"stopped": True})
        connect.assert_called_once()
        connection.request.assert_called_once_with("global_stop")

class ManagementExceptionsTests(unittest.TestCase):
    def test_only_real_established_rdp_service_or_system_owned_peers_are_exempt(self):
        registry = SimpleNamespace(HKEY_LOCAL_MACHINE=1, OpenKey=mock.MagicMock(),
                                   QueryValueEx=mock.Mock(return_value=(3391, 4)))
        def rows(family):
            if family == socket.AF_INET6:
                return [{"pid": 4, "state": 5, "local_port": 3391, "remote": "2001:db8::2"}]
            return [{"pid": 77, "state": 5, "local_port": 3391, "remote": "192.0.2.1"},
                    {"pid": 77, "state": 5, "local_port": 3391, "remote": "192.0.2.1"},
                    {"pid": 1337, "state": 5, "local_port": 3391, "remote": "192.0.2.3"},
                    {"pid": 77, "state": 2, "local_port": 3391, "remote": "192.0.2.4"},
                    {"pid": 77, "state": 5, "local_port": 22, "remote": "192.0.2.5"}]
        with mock.patch.dict(sys.modules, {"winreg": registry}), \
                mock.patch.object(service, "ServiceControl") as control, \
                mock.patch.object(service, "_tcp_connections", side_effect=rows):
            control.return_value.status.return_value = {"state": 4, "pid": 77}
            result = service._management_exceptions()
        self.assertEqual([item["route"] for item in result], ["192.0.2.1/32", "2001:db8::2/128"])
        self.assertTrue(all(item["local_port"] == 3391 for item in result))
        control.return_value.status.assert_called_once_with("TermService")


class GlobalBrokerTests(unittest.TestCase):
    def setUp(self):
        self.control = mock.Mock()
        self.control.status.return_value = {"state": 1}
        self.control.set_running.return_value = {"state": 1}
        self.core = mock.Mock()
        self.core.status.return_value = {"running": False, "guard": {"active": False}}
        self.core.is_running.return_value = False
        self.core.start.return_value = {"running": True, "pid": 12345}
        self.core.stop.return_value = {"running": False, "stopped": True}
        self.factory = mock.Mock(return_value=self.core)
        self.leases = []
        def lease(pid, sid):
            item = mock.Mock(spec=["pid", "alive", "close"], pid=pid)
            item.alive.return_value = True
            self.leases.append(item)
            return item
        self.broker = service.Broker({"root": "/fixed/installation", "owner_sid": SID},
            self.control, lease, self.factory)

    def request(self, op="global_start", **extra):
        return {"op": op, "client_pid": 101,
                **(fields(require_strict=True) if op == "global_start" else {}), **extra}

    def test_tun_start_is_removed_and_touches_nothing(self):
        with self.assertRaises(policy.ProxyError) as caught:
            self.broker.handle(self.request(require_strict=False), 101, SID)
        self.assertEqual(caught.exception.code, "global_tun_removed")
        self.factory.assert_not_called()
        self.control.verify.assert_not_called()
        self.control.set_running.assert_not_called()
        self.assertEqual(self.leases, [])

    def test_legacy_stop_still_releases_an_old_guard(self):
        self.core.stop.return_value = {"running": False, "stopped": True, "guard": {"active": False}}
        result = self.broker.handle(self.request("global_stop"), 101, SID)
        self.core.stop.assert_called_once_with(normal=True)
        self.assertTrue(result["stopped"])

    def test_wrong_caller_has_no_global_side_effects(self):
        for pid, sid in ((102, SID), (101, SID + "1")):
            with self.assertRaises(policy.ProxyError):
                self.broker.handle(self.request(), pid, sid)
        self.factory.assert_not_called()
        self.control.verify.assert_not_called()

    def test_external_proxifyre_is_never_stopped_to_start_global(self):
        self.control.status.return_value = {"state": 4}
        with self.assertRaises(policy.ProxyError):
            self.broker.handle(self.request(), 101, SID)
        self.factory.assert_not_called()
        self.control.set_running.assert_not_called()

    def test_uncertified_start_still_rejects_another_users_request(self):
        with self.assertRaises(policy.ProxyError) as caught:
            self.broker.handle(self.request(require_strict=False), 101, "S-1-5-21-9-9-9-1001")
        self.assertEqual(caught.exception.code, "access_denied")
        self.core.start.assert_not_called()
        self.control.verify.assert_not_called()

    def test_guard_still_active_blocks_application_mode(self):
        self.broker.global_core = self.core
        self.core.status.return_value = {"running": False, "guard": {"active": True}}
        with self.assertRaises(policy.ProxyError) as caught:
            self.broker.handle(self.request("apply"), 101, SID)
        self.assertEqual(caught.exception.code, "mode_conflict")
        self.control.set_running.assert_not_called()

    def test_service_shutdown_is_not_an_explicit_guard_restore(self):
        self.broker.global_core = self.core
        self.broker.shutdown()
        self.core.stop.assert_called_once_with(normal=False)

    def test_watchdog_only_checks_process_and_never_queries_full_dns_status(self):
        self.broker.global_core = self.core
        self.broker.global_panel = mock.Mock(pid=101)
        self.broker.global_panel.alive.return_value = True
        self.core.is_running.return_value = True
        self.core.status.side_effect = AssertionError("watchdog must not enter DNS status")
        self.broker.check_lease()
        self.core.status.assert_not_called()
        self.core.stop.assert_not_called()


if __name__ == "__main__":
    unittest.main()
