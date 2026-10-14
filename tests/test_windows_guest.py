import json
import socket
import struct
import subprocess
import sys
import tempfile
import threading
import unittest
from contextlib import ExitStack
from pathlib import Path
from types import SimpleNamespace
from unittest import mock

from ruleproxy import file_bridge, windows_guest


class WindowsGuestTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        root = Path(self.temp.name)
        self.config = {
            "command": [r"C:\Apps\browser.exe"],
            "env": {}, "profile": str(root), "listener_port": 19001,
            "bridge_directory": str(root), "bridge_nonce": "a" * 64,
            "host_fixture_port": 19002,
        }

    def helper_setup(self, bridge_worker, decision="approved"):
        stack = ExitStack()
        self.addCleanup(stack.close)
        stack.enter_context(mock.patch.dict(sys.modules, {"file_bridge": file_bridge}))
        stack.enter_context(mock.patch.object(sys, "path", sys.path.copy()))
        stack.enter_context(mock.patch.object(windows_guest, "_read_config", return_value=self.config))
        status = stack.enter_context(mock.patch.object(windows_guest, "_atomic_status"))
        check = stack.enter_context(mock.patch.object(windows_guest, "_child_self_check"))
        stack.enter_context(mock.patch.object(file_bridge, "run_guest_bridge", side_effect=bridge_worker))
        stack.enter_context(mock.patch.object(file_bridge, "wait_for_bridge_ready", return_value=True))
        ready = stack.enter_context(mock.patch.object(file_bridge, "signal_guest_ready"))
        host_decision = stack.enter_context(mock.patch.object(file_bridge, "wait_for_decision", return_value=decision))
        application = mock.Mock()
        application.poll.return_value = 0
        application.wait.return_value = 0
        popen = stack.enter_context(mock.patch.object(windows_guest.subprocess, "Popen", return_value=application))
        return status, check, ready, host_decision, popen

    @staticmethod
    def running_bridge(_port, _directory, _nonce, stop):
        stop.wait(4)

    def test_application_starts_only_after_live_bridge_self_check_and_approval(self):
        status, check, ready, decision, popen = self.helper_setup(self.running_bridge)
        events = []
        check.side_effect = lambda *args: events.append("network check")
        ready.side_effect = lambda *args: events.append("guest ready")
        decision.side_effect = lambda *args: events.append("host approval") or "approved"
        app = popen.return_value
        popen.side_effect = lambda *args, **kwargs: events.append("application") or app
        self.assertEqual(windows_guest.run(Path("config")), 0)
        self.assertEqual(events, ["network check", "guest ready", "host approval", "application"])
        self.assertFalse(popen.call_args.kwargs["shell"])
        self.assertTrue(popen.call_args.kwargs["close_fds"])
        self.assertEqual(status.call_args_list[-1].args[2], "APP_EXITED")

    def test_self_check_failure_never_publishes_ready_or_starts_application(self):
        status, check, ready, decision, popen = self.helper_setup(self.running_bridge)
        check.side_effect = RuntimeError("direct UDP was not denied")
        self.assertEqual(windows_guest.run(Path("config")), 70)
        ready.assert_not_called()
        decision.assert_not_called()
        popen.assert_not_called()
        self.assertEqual(status.call_args.args[2], "FAILED")

    def test_host_rejection_never_starts_application(self):
        _, _, _, _, popen = self.helper_setup(self.running_bridge, "rejected")
        self.assertEqual(windows_guest.run(Path("config")), 70)
        popen.assert_not_called()

    def test_bridge_normal_exit_before_approval_never_starts_application(self):
        stopped = threading.Event()
        bridge_threads = []

        def exited_bridge(*args):
            bridge_threads.append(threading.current_thread())
            stopped.set()

        _, check, ready, decision, popen = self.helper_setup(exited_bridge)

        def finish_check(*args):
            self.assertTrue(stopped.wait(2))
            bridge_threads[0].join(2)

        check.side_effect = finish_check
        self.assertEqual(windows_guest.run(Path("config")), 70)
        ready.assert_not_called()
        decision.assert_not_called()
        popen.assert_not_called()

    def test_bridge_normal_exit_during_host_decision_never_starts_application(self):
        leave_bridge = threading.Event()
        bridge_left = threading.Event()
        bridge_threads = []

        def bridge(*args):
            bridge_threads.append(threading.current_thread())
            leave_bridge.wait(4)
            bridge_left.set()

        _, _, _, decision, popen = self.helper_setup(bridge)

        def approve(*args):
            leave_bridge.set()
            self.assertTrue(bridge_left.wait(2))
            bridge_threads[0].join(2)
            return "approved"

        decision.side_effect = approve
        self.assertEqual(windows_guest.run(Path("config")), 70)
        popen.assert_not_called()

    @staticmethod
    def probe_report(scope, *, proxy_ok=True):
        proxy = "proxy_self" if scope == "parent" else "proxy_parent"
        return {"scope": scope, "pid": 123 if scope == "parent" else 456,
                "checks": {proxy: {"ok": proxy_ok, "code": "ok" if proxy_ok else 10013},
                           **{name: {"ok": True, "code": 10013} for name in windows_guest._DENY_PROBES}}}

    def test_failed_proxy_does_not_suppress_same_pid_or_six_denial_probes(self):
        for scope in ("parent", "child"):
            with self.subTest(scope=scope), \
                    mock.patch.object(windows_guest, "_proxy_roundtrip", side_effect=OSError(10013, "localized text")), \
                    mock.patch.object(windows_guest, "_same_process_loopback", side_effect=OSError(10013, "denied")) as own, \
                    mock.patch.object(windows_guest, "_socket_attempt", side_effect=OSError(10013, "localized text")) as direct:
                report = windows_guest._run_network_probes(scope, 19001, 19002)
            proxy = "proxy_self" if scope == "parent" else "proxy_parent"
            self.assertEqual(report["checks"][proxy], {"ok": False, "code": 10013})
            self.assertTrue(report["checks"]["own_loopback"]["ok"])
            own.assert_called_once()
            self.assertEqual(direct.call_count, 5)
            self.assertTrue(all(report["checks"][name]["ok"] for name in windows_guest._DENY_PROBES))

    def test_parent_and_child_results_are_persisted_before_any_failure_rejects(self):
        parent, child = self.probe_report("parent", proxy_ok=False), self.probe_report("child", proxy_ok=False)
        directory = Path(self.temp.name)
        with mock.patch.object(windows_guest, "_run_network_probes", return_value=parent), \
                mock.patch.object(windows_guest, "_nested_network_report", return_value=child):
            with self.assertRaises(RuntimeError) as raised:
                windows_guest._child_self_check(19001, 19002, directory, "a" * 64)
        detail = str(raised.exception)
        self.assertLessEqual(len(detail), 600)
        self.assertIn("parent(self-proxy=fail:10013)", detail)
        self.assertIn("child(parent-proxy=fail:10013)", detail)
        self.assertIn("deny 12/12", detail)
        raw = (directory / "network-probe.json").read_bytes()
        self.assertLessEqual(len(raw), windows_guest._MAX_PROBE_OUTPUT_BYTES)
        report = json.loads(raw)
        self.assertEqual(set(report), {"nonce", "parent", "child", "aux"})
        self.assertEqual(report["parent"], parent)
        self.assertEqual(report["child"], child)

    def test_aggregated_loopback_failure_never_signals_ready_or_starts_application(self):
        actual_check = windows_guest._child_self_check
        parent, child = self.probe_report("parent"), self.probe_report("child", proxy_ok=False)
        status, check, ready, decision, popen = self.helper_setup(self.running_bridge)
        check.side_effect = actual_check
        with mock.patch.object(windows_guest, "_run_network_probes", return_value=parent), \
                mock.patch.object(windows_guest, "_nested_network_report", return_value=child):
            self.assertEqual(windows_guest.run(Path("config")), 70)
        ready.assert_not_called()
        decision.assert_not_called()
        popen.assert_not_called()
        self.assertEqual(status.call_args.args[2], "FAILED")
        self.assertIn("child(parent-proxy=fail:10013)", status.call_args.args[3])
        self.assertIn("deny 12/12", status.call_args.args[3])

    def test_auxiliary_ipv6_success_never_overrides_a_required_proxy_failure(self):
        parent, child = self.probe_report("parent", proxy_ok=False), self.probe_report("child")
        directory = Path(self.temp.name)
        with mock.patch.object(windows_guest, "_run_network_probes", return_value=parent), \
                mock.patch.object(windows_guest, "_nested_network_report", return_value=child), \
                mock.patch.object(windows_guest, "_same_process_loopback") as own:
            with self.assertRaisesRegex(RuntimeError, "self-proxy=fail:10013.*parent-ipv6-loop=ok"):
                windows_guest._child_self_check(19001, 19002, directory, "a" * 64)
        own.assert_called_once_with(socket.AF_INET6)
        report = json.loads((directory / "network-probe.json").read_bytes())
        self.assertEqual(report["aux"], {"parent_ipv6_loopback": {"ok": True, "code": "ok"}})
        self.assertFalse(report["parent"]["checks"]["proxy_self"]["ok"])
        self.assertEqual(len(report["parent"]["checks"]) + len(report["child"]["checks"]), 14)

    def test_all_fourteen_checks_must_pass_before_gate_returns(self):
        parent, child = self.probe_report("parent"), self.probe_report("child")
        child["checks"]["ipv6_udp"] = {"ok": False, "code": 10047}
        with mock.patch.object(windows_guest, "_run_network_probes", return_value=parent), \
                mock.patch.object(windows_guest, "_nested_network_report", return_value=child):
            with self.assertRaisesRegex(RuntimeError, "deny 11/12.*c.6udp=10047"):
                windows_guest._child_self_check(19001, 19002)
            child["checks"]["ipv6_udp"] = {"ok": True, "code": 10013}
            result = windows_guest._child_self_check(19001, 19002)
        self.assertEqual(len(result["parent"]["checks"]) + len(result["child"]["checks"]), 14)

    def test_allowed_direct_and_route_errors_are_never_policy_denial_evidence(self):
        self.assertEqual(windows_guest._probe(lambda: None, deny=True), {"ok": False, "code": "allowed"})
        for code in (10047, 10051, 10060):
            with self.subTest(code=code):
                def route_error():
                    raise OSError(code, "must not appear in diagnostics")
                self.assertEqual(windows_guest._probe(route_error, deny=True), {"ok": False, "code": code})

    def test_udp_probe_reaches_a_real_listener_as_one_fixed_dns_query(self):
        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as listener:
            listener.bind(("127.0.0.1", 0))
            listener.settimeout(2)
            result = windows_guest._probe(
                lambda: windows_guest._socket_attempt(socket.AF_INET, socket.SOCK_DGRAM,
                                                      listener.getsockname()), deny=True)
            packet, _peer = listener.recvfrom(512)
        self.assertEqual(result, {"ok": False, "code": "allowed"})
        self.assertEqual(len(packet), 35)
        self.assertEqual(struct.unpack("!6H", packet[:12]), (0x5250, 0, 1, 0, 0, 0))
        labels, offset = [], 12
        while packet[offset]:
            length = packet[offset]
            labels.append(packet[offset + 1:offset + 1 + length])
            offset += length + 1
        self.assertEqual(labels, [b"ruleproxy", b"invalid"])
        self.assertEqual(struct.unpack("!HH", packet[offset + 1:]), (1, 1))

    def test_udp_probe_requires_full_datagram_and_only_access_denial_passes(self):
        cases = (
            (len(windows_guest._UDP_PROBE_DATAGRAM), {"ok": False, "code": "allowed"}),
            (0, {"ok": False, "code": "short_send"}),
            (len(windows_guest._UDP_PROBE_DATAGRAM) - 1, {"ok": False, "code": "short_send"}),
            (OSError(10013, "denied"), {"ok": True, "code": 10013}),
            (OSError(10051, "unreachable"), {"ok": False, "code": 10051}),
            (TimeoutError(), {"ok": False, "code": "timeout"}),
        )
        for family, address in ((socket.AF_INET, ("1.1.1.1", 53)),
                                (socket.AF_INET6, ("2606:4700:4700::1111", 53, 0, 0))):
            for outcome, expected in cases:
                with self.subTest(family=family, expected=expected), mock.patch("socket.socket") as factory:
                    connection = factory.return_value.__enter__.return_value
                    if isinstance(outcome, Exception):
                        connection.sendto.side_effect = outcome
                    else:
                        connection.sendto.return_value = outcome
                    result = windows_guest._probe(
                        lambda: windows_guest._socket_attempt(family, socket.SOCK_DGRAM, address), deny=True)
                self.assertEqual(result, expected)
                connection.sendto.assert_called_once_with(windows_guest._UDP_PROBE_DATAGRAM, address)
                connection.connect.assert_not_called()
                factory.assert_called_once_with(family, socket.SOCK_DGRAM)
        child = self.probe_report("child")
        child["checks"]["ipv4_udp"] = {"ok": False, "code": "short_send"}
        self.assertEqual(windows_guest._validated_child_report(json.dumps(child)), child)

    def test_own_process_listener_roundtrip_closes_its_probe_thread(self):
        windows_guest._same_process_loopback()
        self.assertFalse(any(thread.name == "ruleproxy-own-loopback-probe" and thread.is_alive()
                             for thread in threading.enumerate()))

    def test_real_unrelated_internal_listener_is_a_failure_and_access_denial_is_required(self):
        self.assertEqual(len(windows_guest._DENY_PROBES), 6)
        self.assertEqual(len(set(windows_guest._DENY_PROBES)), 6)
        with mock.patch.object(windows_guest, "_proxy_roundtrip"), \
                mock.patch.object(windows_guest, "_socket_attempt", side_effect=OSError(10013, "denied")):
            # The real echo listener and matching reply prove this port is open.
            # A refused or known-closed port is never used as denial evidence.
            record = windows_guest._run_network_probes("parent", 19001, 19002)
            self.assertEqual(record["checks"]["own_loopback"], {"ok": False, "code": "allowed"})
            with mock.patch.object(windows_guest, "_same_process_loopback", side_effect=OSError(10013, "denied")):
                denied = windows_guest._run_network_probes("parent", 19001, 19002)
            self.assertEqual(denied["checks"]["own_loopback"], {"ok": True, "code": 10013})
        child = self.probe_report("child")
        child["checks"]["own_loopback"] = {"ok": True, "code": "ok"}
        with self.assertRaisesRegex(ValueError, "required evidence"):
            windows_guest._validated_child_report(json.dumps(child))

    def test_unrelated_internal_port_success_rejects_the_startup_gate(self):
        parent, child = self.probe_report("parent"), self.probe_report("child")
        child["checks"]["own_loopback"] = {"ok": False, "code": "allowed"}
        with mock.patch.object(windows_guest, "_run_network_probes", return_value=parent), \
                mock.patch.object(windows_guest, "_nested_network_report", return_value=child):
            with self.assertRaisesRegex(RuntimeError, "deny 11/12.*c.own=allowed"):
                windows_guest._child_self_check(19001, 19002)

    def test_nested_output_is_bounded_and_rejects_false_positive_denials(self):
        valid = self.probe_report("child")
        self.assertEqual(windows_guest._validated_child_report(json.dumps(valid)), valid)
        valid["checks"]["ipv4_tcp"] = {"ok": True, "code": "allowed"}
        with self.assertRaises(ValueError):
            windows_guest._validated_child_report(json.dumps(valid))
        for output in ("localized traceback with private path", "x" * (windows_guest._MAX_PROBE_OUTPUT_BYTES + 1)):
            with self.subTest(output_length=len(output)), \
                    mock.patch.object(windows_guest.subprocess, "run", return_value=SimpleNamespace(returncode=0, stdout=output)):
                child = windows_guest._nested_network_report(19001, 19002)
                self.assertTrue(all(item == {"ok": False, "code": "invalid_report"}
                                    for item in child["checks"].values()))

    def test_child_timeout_is_short_structured_failure_without_locale_traceback(self):
        with mock.patch.object(windows_guest.subprocess, "run", side_effect=subprocess.TimeoutExpired(
                ["command with private path"], 20, stderr="localized traceback")):
            child = windows_guest._nested_network_report(19001, 19002)
        summary = windows_guest._probe_summary(self.probe_report("parent"), child)
        self.assertIn("child_timeout", summary)
        self.assertNotIn("private", summary)
        self.assertNotIn("localized", summary)
        self.assertLessEqual(len(summary), 600)


if __name__ == "__main__":
    unittest.main()
