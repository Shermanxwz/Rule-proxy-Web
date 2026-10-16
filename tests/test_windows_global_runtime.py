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

    def test_only_fixed_executable_config_and_compiled_tun_cross_privilege_boundary(self):
        imported = SOURCE + "tun: {enable: false, device: UntrustedAdapter, auto-route: false}\n"
        result = self.core.start(fields(source=imported))
        self.assertTrue(result["running"])
        self.assertEqual(result["pid"], self.process.pid)
        self.assertFalse(result["strict_isolation"])
        self.assertEqual(result["protection"], "persistent_guard_unqualified")
        self.assertNotIn("local-test-secret", json.dumps(result))
        config = yaml.safe_load((self.state / "config.yaml").read_text())
        self.assertNotEqual(config["secret"], "local-test-secret")
        self.assertEqual(config["secret"], self.core._controller_secret)
        self.assertNotIn(self.core._controller_secret, json.dumps(result))
        self.assertEqual(config["tun"]["device"], "RuleProxyTun")
        self.assertTrue(config["tun"]["enable"])
        self.assertTrue(config["tun"]["auto-route"])
        command, env, cwd = self.launch.call_args.args
        self.assertEqual(command, [str(self.executable), "-d", str(self.state), "-f", str(self.state / "config.yaml")])
        self.assertEqual(cwd, str(self.root))
        self.assertIsInstance(env, dict)
        validation = self.validator.call_args
        self.assertEqual(validation.args[0], [command[0], "-t", *command[1:]])
        self.assertLessEqual(validation.kwargs["timeout"], 15)
        names = [event[0] for event in self.events]
        self.assertEqual(names, ["validate", "guard_apply", "dns_apply", "launch", "guard_apply"])
        self.assertEqual(self.guard.applies, 2)

    def test_global_validation_and_core_use_fixed_ipv6_override_without_mutating_service_env(self):
        with mock.patch.dict(service.os.environ, {"SKIP_SYSTEM_IPV6_CHECK": "false", "RULEPROXY_ENV_FIXTURE": "kept"}):
            before = dict(service.os.environ)
            self.core.start(fields())
            validation_env = self.validator.call_args.kwargs["env"]
            launched_env = self.launch.call_args.args[1]
            self.assertTrue(validation_env == {**before, "SKIP_SYSTEM_IPV6_CHECK": "true"}, "unexpected global environment")
            self.assertTrue(launched_env == validation_env, "validation and runtime environments differ")
            self.assertTrue(dict(service.os.environ) == before, "service environment changed")
            self.assertIsNot(launched_env, service.os.environ)

    def test_global_ipv6_override_stays_out_of_environment_inherited_by_other_children(self):
        with mock.patch.dict(service.os.environ):
            service.os.environ.pop("SKIP_SYSTEM_IPV6_CHECK", None)
            self.core.start(fields())
            self.assertEqual(self.launch.call_args.args[1]["SKIP_SYSTEM_IPV6_CHECK"], "true")
            self.assertNotIn("SKIP_SYSTEM_IPV6_CHECK", service.os.environ)

    def test_explicit_stop_removes_guard_after_confirmed_core_exit(self):
        self.core.start(fields())
        result = self.core.stop()
        self.assertTrue(result["stopped"])
        self.assertFalse(result["running"])
        self.assertFalse(self.guard.active)
        self.assertEqual([event[0] for event in self.events][-4:], ["terminate", "wait", "dns_stop", "normal_stop"])

    def test_crash_cleanup_keeps_guard_and_does_not_report_strict_test_evidence(self):
        self.core.start(fields())
        result = self.core.stop(normal=False)
        self.assertTrue(self.guard.active)
        self.assertFalse(result["running"])
        self.assertFalse(result["strict_isolation"])
        self.assertEqual(self.events[-1][0], "crash_keep")
        self.assertNotIn("normal_stop", [event[0] for event in self.events])

    def test_shutdown_result_does_not_start_a_new_dns_status_query(self):
        self.core.start(fields())
        last = self.dns.status()
        self.dns.crash_keep = mock.Mock(return_value=last)
        self.dns.status = mock.Mock(side_effect=AssertionError("no DNS query during shutdown"))
        result = self.core.stop(normal=False)
        self.assertFalse(result["running"])
        self.dns.status.assert_not_called()

    def test_early_exit_keeps_guard_and_never_returns_success(self):
        self.process.live = False
        with self.assertRaisesRegex(policy.ProxyError, "全局核心未能"):
            self.core.start(fields())
        self.assertTrue(self.guard.active)
        self.assertEqual(self.events[-1][0], "crash_keep")
        self.assertIsNone(self.core.process)
        self.assertEqual(self.core.status()["state"], "failed")

    def test_launch_failure_keeps_pre_guard(self):
        self.launch.side_effect = OSError("injected launch failure")
        with self.assertRaises(OSError):
            self.core.start(fields())
        self.assertTrue(self.guard.active)
        self.assertEqual(self.events[-1][0], "crash_keep")
        self.assertNotIn("normal_stop", [event[0] for event in self.events])

    def test_failed_cleanup_cannot_withdraw_guard(self):
        self.core.start(fields())
        self.process.wait = mock.Mock(side_effect=TimeoutError("cleanup unconfirmed"))
        with self.assertRaises(TimeoutError):
            self.core.stop()
        self.assertTrue(self.guard.active)
        self.assertNotIn("normal_stop", [event[0] for event in self.events])

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

    def test_dns_apply_failure_keeps_pre_guard_and_never_launches_core(self):
        self.dns.apply = mock.Mock(side_effect=policy.ProxyError("global_dns_conflict", "conflict"))
        with self.assertRaises(policy.ProxyError):
            self.core.start(fields())
        self.launch.assert_not_called()
        self.assertTrue(self.guard.active)
        self.assertEqual([event[0] for event in self.events][-2:], ["dns_keep", "crash_keep"])
        self.assertNotIn("normal_stop", [event[0] for event in self.events])

    def test_unconfirmed_dns_restore_cannot_withdraw_guard(self):
        self.core.start(fields())
        self.dns.normal_stop = mock.Mock(return_value={"supported": False, "active": None})
        with self.assertRaises(policy.ProxyError):
            self.core.stop()
        self.assertTrue(self.guard.active)
        self.assertNotIn("normal_stop", [event[0] for event in self.events])

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

    def test_guard_without_final_strict_evidence_stops_core_and_keeps_protection(self):
        with self.assertRaises(policy.ProxyError) as caught:
            self.core.start(fields(require_strict=True))
        self.assertEqual(caught.exception.code, "strict_guard_unavailable")
        self.launch.assert_called_once()
        self.assertIsNone(self.core.process)
        self.assertTrue(self.guard.active)
        self.assertEqual(self.events[-1][0], "crash_keep")

    def test_qualified_idle_components_can_start_without_active_strict_preflight(self):
        self.guard.strict = True
        self.assertFalse(self.guard.status()["strict_isolation"])
        self.assertFalse(self.dns.status()["active"])
        result = self.core.start(fields(require_strict=True))
        self.assertTrue(result["running"])
        self.assertTrue(result["strict_isolation"])
        self.assertTrue(result["guard"]["tun_ready"])
        self.assertEqual(result["protection"], "persistent_guard")

    def test_each_strict_start_rechecks_qualification_before_mutating_or_unchanged_return(self):
        self.guard.strict = True
        self.core.start(fields(require_strict=True))
        self.events.clear()
        revoked = {**self.guard.status(), "native_qualified": False}
        def refresh():
            self.guard.status = mock.Mock(return_value=revoked)
        self.guard.refresh_qualification = mock.Mock(side_effect=refresh)
        self.dns.refresh_qualification = mock.Mock()
        with self.assertRaises(policy.ProxyError) as caught:
            self.core.start(fields(require_strict=True))
        self.assertEqual(caught.exception.code, "strict_guard_unavailable")
        self.guard.refresh_qualification.assert_called_once()
        self.dns.refresh_qualification.assert_called_once()
        self.assertEqual(self.events, [])
        self.assertTrue(self.core.is_running())

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

    def test_preguard_requires_complete_boolean_protection_before_dns_or_core(self):
        self.guard.strict = True
        original = self.guard.apply
        for field in ("supported", "active", "persistent", "native_qualified"):
            for bad in (None, 1):
                with self.subTest(field=field, bad=bad):
                    self.events.clear()
                    def apply(core, tun):
                        return {**original(core, tun), field: bad}
                    with mock.patch.object(self.guard, "apply", side_effect=apply), \
                            self.assertRaises(policy.ProxyError) as caught:
                        self.core.start(fields(require_strict=True))
                    self.assertEqual(caught.exception.code, "strict_guard_unavailable")
                    self.launch.assert_not_called()
                    self.assertNotIn("dns_apply", [event[0] for event in self.events])
                    self.assertTrue(self.guard.active)
                    self.assertEqual(self.events[-1][0], "crash_keep")

    def test_dns_losing_qualification_during_apply_keeps_preguard_without_launch(self):
        self.guard.strict = True
        original = self.dns.apply
        def apply():
            return {**original(), "native_qualified": False}
        with mock.patch.object(self.dns, "apply", side_effect=apply), \
                self.assertRaises(policy.ProxyError) as caught:
            self.core.start(fields(require_strict=True))
        self.assertEqual(caught.exception.code, "strict_dns_unavailable")
        self.launch.assert_not_called()
        self.assertTrue(self.guard.active)
        self.assertTrue(self.dns.active)
        self.assertEqual([event[0] for event in self.events][-2:], ["dns_keep", "crash_keep"])

    def test_second_guard_apply_requires_explicit_true_tun_readiness(self):
        original = self.guard.apply
        def apply(core, tun):
            value = original(core, tun)
            if self.guard.applies > 1:
                value.pop("tun_ready")
            return value
        with mock.patch.object(self.guard, "apply", side_effect=apply), \
                mock.patch.object(service.time, "monotonic", side_effect=[0, 0, 9]), \
                mock.patch.object(service.time, "sleep"), \
                self.assertRaises(policy.ProxyError) as caught:
            self.core.start(fields())
        self.assertEqual(caught.exception.code, "global_start_failed")
        self.assertIsNone(self.core.process)
        self.assertTrue(self.guard.active)
        self.assertTrue(self.dns.active)
        self.assertNotIn("normal_stop", [event[0] for event in self.events])

    def test_guard_losing_qualification_during_second_apply_stops_core_and_keeps_protection(self):
        self.guard.strict = True
        original = self.guard.apply
        def apply(core, tun):
            value = original(core, tun)
            if self.guard.applies > 1:
                value["native_qualified"] = False
            return value
        with mock.patch.object(self.guard, "apply", side_effect=apply), \
                self.assertRaises(policy.ProxyError) as caught:
            self.core.start(fields(require_strict=True))
        self.assertEqual(caught.exception.code, "strict_guard_unavailable")
        self.assertIsNone(self.core.process)
        self.assertTrue(self.guard.active)
        self.assertTrue(self.dns.active)
        self.assertEqual([event[0] for event in self.events][-4:], ["terminate", "wait", "dns_keep", "crash_keep"])

    def test_final_guard_readback_cannot_reuse_successful_apply_after_state_loss(self):
        self.guard.strict = True
        original = self.guard.status
        def status():
            value = original()
            if self.guard.applies > 1:
                value["persistent"] = False
            return value
        original_apply = self.guard.apply
        def apply(core, tun):
            # The apply response can be healthy while the independent final
            # readback detects a change made immediately afterwards.
            original_apply(core, tun)
            return original()
        with mock.patch.object(self.guard, "status", side_effect=status), \
                mock.patch.object(self.guard, "apply", side_effect=apply), \
                self.assertRaises(policy.ProxyError) as caught:
            self.core.start(fields(require_strict=True))
        self.assertEqual(caught.exception.code, "strict_guard_unavailable")
        self.assertIsNone(self.core.process)
        self.assertTrue(self.guard.active)
        self.assertNotIn("normal_stop", [event[0] for event in self.events])

    def test_final_dns_readback_requires_qualification_after_effective_apply(self):
        self.guard.strict = True
        original = self.dns.status
        def status(*, refresh=False):
            value = original(refresh=refresh)
            if refresh and self.guard.applies > 1:
                value["native_qualified"] = False
            return value
        with mock.patch.object(self.dns, "status", side_effect=status), \
                self.assertRaises(policy.ProxyError) as caught:
            self.core.start(fields(require_strict=True))
        self.assertEqual(caught.exception.code, "strict_dns_unavailable")
        self.assertIsNone(self.core.process)
        self.assertTrue(self.guard.active)
        self.assertTrue(self.dns.active)

    def test_identical_request_rechecks_current_tun_before_unchanged_success(self):
        self.core.start(fields())
        self.assertTrue(self.core.start(fields())["unchanged"])
        original = self.guard.status()
        with mock.patch.object(self.guard, "status", return_value={**original, "tun_ready": False}), \
                self.assertRaises(policy.ProxyError) as caught:
            self.core.start(fields())
        self.assertEqual(caught.exception.code, "global_guard_not_effective")
        self.assertIsNone(self.core.process)
        self.assertTrue(self.guard.active)
        self.assertEqual([event[0] for event in self.events][-2:], ["dns_keep", "crash_keep"])

    def test_failed_start_cleanup_keeps_both_leases_even_if_core_exit_is_unconfirmed(self):
        self.guard.strict = True
        original = self.dns.status
        def status(*, refresh=False):
            value = original(refresh=refresh)
            if refresh and self.guard.applies > 1:
                value["effective"] = False
            return value
        self.process.wait = mock.Mock(side_effect=TimeoutError("cleanup unconfirmed"))
        with mock.patch.object(self.dns, "status", side_effect=status), self.assertRaises(TimeoutError):
            self.core.start(fields(require_strict=True))
        self.assertIs(self.core.process, self.process)
        self.assertTrue(self.guard.active)
        self.assertTrue(self.dns.active)
        self.assertEqual([event[0] for event in self.events][-2:], ["dns_keep", "crash_keep"])
        self.assertNotIn("normal_stop", [event[0] for event in self.events])

    def test_status_never_reports_strict_for_incomplete_runtime_component_state(self):
        self.guard.strict = True
        self.core.start(fields(require_strict=True))
        guard, dns = self.guard.status(), self.dns.status()
        for component, field in (("guard", "supported"), ("guard", "tun_ready"),
                                 ("guard", "persistent"), ("guard", "native_qualified"),
                                 ("dns", "supported"), ("dns", "active"), ("dns", "persistent"),
                                 ("dns", "effective"), ("dns", "fresh"), ("dns", "native_qualified")):
            for bad in (None, 1):
                with self.subTest(component=component, field=field, bad=bad):
                    changed_guard, changed_dns = dict(guard), dict(dns)
                    (changed_guard if component == "guard" else changed_dns)[field] = bad
                    result = self.core.status(guard_state=changed_guard, dns_state=changed_dns)
                    self.assertFalse(result["strict_isolation"])
        self.assertFalse(self.core.status(guard_state=guard,
            dns_state={**dns, "state": "conflict"})["strict_isolation"])
        self.process.live = False
        self.assertFalse(self.core.status(guard_state=guard, dns_state=dns)["strict_isolation"])

    def test_existing_rdp_exceptions_are_explicit_and_limited_to_current_peers(self):
        exceptions = [{"remote": "192.0.2.11", "route": "192.0.2.11/32", "local_port": 3389,
                       "protocol": "TCP", "reason": "existing management fixture"},
                      {"remote": "2001:db8::11", "route": "2001:db8::11/128", "local_port": 3389,
                       "protocol": "TCP", "reason": "existing management fixture"}]
        self.core._management = lambda: exceptions
        result = self.core.start(fields())
        config = yaml.safe_load((self.state / "config.yaml").read_text())
        self.assertEqual(config["tun"]["route-exclude-address"], [item["route"] for item in exceptions])
        self.assertEqual(result["management_exceptions"], exceptions)

    def test_node_switch_uses_private_controller_and_only_compiled_node_allowlist(self):
        self.core.start(fields())
        connection = mock.Mock()
        connection.sock.getsockname.return_value = ("127.0.0.1", 48291)
        connection.getresponse.return_value.status = 204
        connection.getresponse.return_value.read.return_value = b""
        row = {"state": 5, "pid": self.process.pid, "local_port": 29097, "remote_port": 48291,
               "local": "127.0.0.1", "remote": "127.0.0.1"}
        with mock.patch.object(service.http.client, "HTTPConnection", return_value=connection), \
                mock.patch.object(service, "_tcp_connections", return_value=[row]):
            with self.assertRaises(policy.ProxyError):
                self.core.select_node("DIRECT")
            connection.request.assert_not_called()
            result = self.core.select_node("node-a")
        request = connection.request.call_args
        self.assertEqual(request.args, ("PUT", "/proxies/RuleProxySelected"))
        self.assertEqual(json.loads(request.kwargs["body"]), {"name": "node-a"})
        self.assertEqual(request.kwargs["headers"]["Authorization"], "Bearer " + self.core._controller_secret)
        self.assertNotIn("local-test-secret", request.kwargs["headers"]["Authorization"])
        self.assertEqual(result["selected_node"], "node-a")
        connection.close.assert_called_once()

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

    def test_product_facade_defaults_to_strict_and_experimental_opt_out_is_explicit(self):
        runtime = Runtime(Path.cwd())
        connection = mock.Mock()
        connection.request.return_value = {"global_schema_version": 1, "mode": "global",
            "running": True, "supported": True, "pid": 12345}
        with mock.patch.object(runtime, "_connect", return_value=connection):
            runtime.start(SOURCE, "desktop-secret", 28009, 29097, "node-a")
            self.assertIs(connection.request.call_args.kwargs["require_strict"], True)
            runtime.start(SOURCE, "desktop-secret", 28009, 29097, "node-a", require_strict=False)
            self.assertIs(connection.request.call_args.kwargs["require_strict"], False)


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

    def test_owned_proxifyre_is_stopped_before_global_core(self):
        panel, app_core = mock.Mock(pid=101), mock.Mock(pid=102)
        panel.alive.return_value = app_core.alive.return_value = True
        self.broker.panel, self.broker.core = panel, app_core
        self.broker.handle(self.request(), 101, SID)
        self.control.set_running.assert_called_once_with(False)
        panel.close.assert_called_once()
        app_core.close.assert_called_once()
        self.core.start.assert_called_once()
        self.assertEqual(self.broker.global_panel.pid, 101)

    def test_ordinary_strict_client_needs_no_elevation_query(self):
        self.broker.handle(self.request(), 101, SID)
        self.assertFalse(hasattr(self.leases[0], "is_elevated"))
        self.core.start.assert_called_once()
        self.assertIs(self.core.start.call_args.args[0]["require_strict"], True)

    def test_ordinary_owner_cannot_opt_out_of_strict_or_stop_existing_proxy(self):
        panel, app_core = mock.Mock(pid=101), mock.Mock(pid=102)
        panel.alive.return_value = app_core.alive.return_value = True
        self.broker.panel, self.broker.core = panel, app_core
        with self.assertRaises(policy.ProxyError) as caught:
            self.broker.handle(self.request(require_strict=False), 101, SID)
        self.assertEqual(caught.exception.code, "experimental_global_requires_admin")
        self.leases[0].close.assert_called_once()
        self.assertIsNone(self.broker.global_panel)
        self.control.verify.assert_not_called()
        self.control.set_running.assert_not_called()
        self.factory.assert_not_called()
        panel.close.assert_not_called()
        app_core.close.assert_not_called()

    def test_experimental_request_requires_explicit_native_boolean_elevation(self):
        for elevation in (False, None, 1, "true", mock.Mock()):
            with self.subTest(elevation=elevation):
                owner = mock.Mock(spec=["pid", "alive", "close", "is_elevated"], pid=101)
                owner.is_elevated.return_value = elevation
                self.broker.lease_factory = mock.Mock(return_value=owner)
                with self.assertRaises(policy.ProxyError) as caught:
                    self.broker.handle(self.request(require_strict=False), 101, SID)
                self.assertEqual(caught.exception.code, "experimental_global_requires_admin")
                owner.is_elevated.assert_called_once_with()
                owner.close.assert_called_once()
                self.control.verify.assert_not_called()
                self.control.set_running.assert_not_called()
                self.factory.assert_not_called()

    def test_failed_elevation_query_closes_owner_and_leaves_network_untouched(self):
        owner = mock.Mock(spec=["pid", "alive", "close", "is_elevated"], pid=101)
        owner.is_elevated.side_effect = OSError("access denied")
        self.broker.lease_factory = mock.Mock(return_value=owner)
        with self.assertRaises(policy.ProxyError) as caught:
            self.broker.handle(self.request(require_strict=False), 101, SID)
        self.assertEqual(caught.exception.code, "experimental_global_requires_admin")
        owner.close.assert_called_once()
        self.control.verify.assert_not_called()
        self.control.set_running.assert_not_called()
        self.factory.assert_not_called()

    def test_explicit_elevated_experiment_can_start_and_retains_held_owner(self):
        owner = mock.Mock(spec=["pid", "alive", "close", "is_elevated"], pid=101)
        owner.is_elevated.return_value = True
        self.broker.lease_factory = mock.Mock(return_value=owner)
        result = self.broker.handle(self.request(require_strict=False), 101, SID)
        self.assertTrue(result["running"])
        self.assertIs(self.broker.global_panel, owner)
        owner.is_elevated.assert_called_once_with()
        owner.close.assert_not_called()
        self.control.verify.assert_called_once()
        self.core.start.assert_called_once()
        self.assertIs(self.core.start.call_args.args[0]["require_strict"], False)

    def test_global_core_death_keeps_guard_and_closes_owner_lease(self):
        self.broker.handle(self.request(), 101, SID)
        self.broker.check_lease()
        self.core.stop.assert_called_once_with(normal=False)
        self.leases[0].close.assert_called_once()
        self.assertIsNone(self.broker.global_panel)

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
