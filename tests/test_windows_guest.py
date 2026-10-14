import json
import socket
import struct
import subprocess
import sys
import tempfile
import threading
import time
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
            "host_fixture_port": 19002, "schema_version": 1, "host_udp_ports": [19003, 19004],
        }

    def helper_setup(self, bridge_worker, decision="approved"):
        stack = ExitStack()
        self.addCleanup(stack.close)
        stack.enter_context(mock.patch.dict(sys.modules, {"file_bridge": file_bridge}))
        stack.enter_context(mock.patch.object(sys, "path", sys.path.copy()))
        stack.enter_context(mock.patch.object(windows_guest, "_read_config", return_value=self.config))
        status = stack.enter_context(mock.patch.object(windows_guest, "_atomic_status"))
        check = stack.enter_context(mock.patch.object(windows_guest, "_child_self_check"))
        stack.enter_context(mock.patch.object(windows_guest, "_readonly_config_probe", return_value={"ok": True, "code": 5}))
        stack.enter_context(mock.patch.object(file_bridge, "run_guest_bridge", side_effect=bridge_worker))
        stack.enter_context(mock.patch.object(file_bridge, "wait_for_bridge_ready", return_value=True))
        ready = stack.enter_context(mock.patch.object(file_bridge, "signal_guest_ready"))
        host_decision = stack.enter_context(mock.patch.object(file_bridge, "wait_for_decision", return_value=decision))
        stack.enter_context(mock.patch.object(windows_guest, "_host_approved", return_value=True))
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
        check.side_effect = lambda *args, **kwargs: events.append("network check")
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

    def test_writable_bridge_approval_without_readonly_host_record_never_starts_application(self):
        _, _, _, decision, popen = self.helper_setup(self.running_bridge)
        with mock.patch.object(windows_guest, "_host_approved", return_value=False):
            self.assertEqual(windows_guest.run(Path("config")), 70)
        decision.assert_called_once()
        popen.assert_not_called()

    def test_host_confirmation_rejects_stale_nonce_and_is_read_from_fixed_config_directory(self):
        config = Path(self.temp.name) / "guest-config.json"
        record = config.parent / "host-approval.json"
        self.assertFalse(windows_guest._host_approved(config, "a" * 64))
        record.write_text(json.dumps({"schema_version": 1, "nonce": "b" * 64, "state": "APPROVED"}))
        self.assertFalse(windows_guest._host_approved(config, "a" * 64))
        record.write_text(json.dumps({"schema_version": 1, "nonce": "a" * 64, "state": "APPROVED"}))
        self.assertTrue(windows_guest._host_approved(config, "a" * 64))

    def test_bridge_normal_exit_before_approval_never_starts_application(self):
        stopped = threading.Event()
        bridge_threads = []

        def exited_bridge(*args):
            bridge_threads.append(threading.current_thread())
            stopped.set()

        _, check, ready, decision, popen = self.helper_setup(exited_bridge)

        def finish_check(*args, **kwargs):
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

    @classmethod
    def startup_report(cls, scope, *, proxy_ok=True):
        raw = cls.probe_report(scope, proxy_ok=proxy_ok)
        public = {name: raw["checks"].pop(name) for name in ("ipv4_udp", "ipv6_udp")}
        public["ipv4_udp"] = {"ok": False, "code": "allowed"}
        public["ipv6_udp"] = {"ok": False, "code": 10051}
        return {**raw, "parent_pid": 101 if scope == "parent" else 123,
                "process_created": 1000 if scope == "parent" else 2000,
                "public_udp": public,
                "local_udp": {family: {"state": "accepted_full", "stage": "complete", "code": None,
                                       "sent_bytes": len(windows_guest._local_udp_marker("a" * 64, scope, family))}
                              for family in ("ipv4", "ipv6")}}

    def self_check(self):
        with mock.patch.object(windows_guest, "_readonly_config_probe", return_value={"ok": True, "code": 5}):
            return windows_guest._child_self_check(19001, 19002, Path(self.temp.name), "a" * 64, [19003, 19004],
                                                   config_path=Path(self.temp.name) / "guest-config.json")

    def test_parent_and_child_results_are_persisted_before_any_failure_rejects(self):
        parent, child = self.startup_report("parent", proxy_ok=False), self.startup_report("child", proxy_ok=False)
        with mock.patch.object(windows_guest, "_run_startup_probes", return_value=parent), \
                mock.patch.object(windows_guest, "_nested_startup_report", return_value=child):
            with self.assertRaises(RuntimeError) as raised:
                self.self_check()
        detail = str(raised.exception)
        self.assertLessEqual(len(detail), 600)
        self.assertIn("parent(self-proxy=fail:10013)", detail)
        self.assertIn("child(parent-proxy=fail:10013)", detail)
        self.assertIn("deny 8/8", detail)
        raw = (Path(self.temp.name) / "network-probe.json").read_bytes()
        self.assertLessEqual(len(raw), windows_guest._MAX_PROBE_OUTPUT_BYTES)
        report = json.loads(raw)
        self.assertEqual(set(report), {"schema_version", "nonce", "parent", "child", "aux", "config_readonly"})
        self.assertEqual(report["parent"], parent)
        self.assertEqual(report["child"], child)

    def test_aggregated_loopback_failure_never_signals_ready_or_starts_application(self):
        actual_check = windows_guest._child_self_check
        parent, child = self.startup_report("parent"), self.startup_report("child", proxy_ok=False)
        status, check, ready, decision, popen = self.helper_setup(self.running_bridge)
        check.side_effect = actual_check
        with mock.patch.object(windows_guest, "_run_startup_probes", return_value=parent), \
                mock.patch.object(windows_guest, "_nested_startup_report", return_value=child):
            self.assertEqual(windows_guest.run(Path("config")), 70)
        ready.assert_not_called()
        decision.assert_not_called()
        popen.assert_not_called()
        self.assertIn("child(parent-proxy=fail:10013)", status.call_args.args[3])

    def test_auxiliary_ipv6_success_never_overrides_required_failure(self):
        parent, child = self.startup_report("parent", proxy_ok=False), self.startup_report("child")
        with mock.patch.object(windows_guest, "_run_startup_probes", return_value=parent), \
                mock.patch.object(windows_guest, "_nested_startup_report", return_value=child), \
                mock.patch.object(windows_guest, "_same_process_loopback"):
            with self.assertRaisesRegex(RuntimeError, "self-proxy=fail:10013.*parent-ipv6-loop=ok"):
                self.self_check()

    def test_public_udp_accepted_or_no_route_diagnostics_do_not_become_denial(self):
        parent, child = self.startup_report("parent"), self.startup_report("child")
        with mock.patch.object(windows_guest, "_run_startup_probes", return_value=parent), \
                mock.patch.object(windows_guest, "_nested_startup_report", return_value=child):
            result = self.self_check()
        for scope in (result["parent"], result["child"]):
            self.assertEqual(scope["public_udp"], {"ipv4_udp": {"ok": False, "code": "allowed"},
                                                  "ipv6_udp": {"ok": False, "code": 10051}})
        self.assertEqual(len(result["parent"]["checks"]) + len(result["child"]["checks"]), 10)

    def test_incomplete_local_udp_attempt_cannot_publish_ready(self):
        actual_check = windows_guest._child_self_check
        parent, child = self.startup_report("parent"), self.startup_report("child")
        child["local_udp"]["ipv6"] = {"state": "invalid", "stage": "send", "code": 10051, "sent_bytes": None}
        _, check, ready, decision, popen = self.helper_setup(self.running_bridge)
        check.side_effect = actual_check
        with mock.patch.object(windows_guest, "_run_startup_probes", return_value=parent), \
                mock.patch.object(windows_guest, "_nested_startup_report", return_value=child):
            self.assertEqual(windows_guest.run(Path("config")), 70)
        ready.assert_not_called()
        decision.assert_not_called()
        popen.assert_not_called()

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

    def test_loopback_access_denial_survives_real_accept_thread_cleanup(self):
        started = time.monotonic()
        with mock.patch("socket.create_connection", side_effect=OSError(10013, "denied")):
            result = windows_guest._probe(lambda: windows_guest._same_process_loopback(
                deadline=time.monotonic() + 1), deny=True)
        self.assertEqual(result, {"ok": True, "code": 10013})
        self.assertLess(time.monotonic() - started, 0.5)
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
        parent, child = self.startup_report("parent"), self.startup_report("child")
        child["checks"]["own_loopback"] = {"ok": False, "code": "allowed"}
        with mock.patch.object(windows_guest, "_run_startup_probes", return_value=parent), \
                mock.patch.object(windows_guest, "_nested_startup_report", return_value=child):
            with self.assertRaisesRegex(RuntimeError, "deny 7/8.*c.own=allowed"):
                self.self_check()

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

    def test_local_udp_attempt_sends_only_role_bound_marker_to_fixed_loopback(self):
        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as observer:
            observer.bind(("127.0.0.1", 0))
            observer.settimeout(1)
            results = []
            for role in ("parent", "child"):
                result = windows_guest._local_udp_attempt(role, "ipv4", observer.getsockname()[1],
                                                         "a" * 64, deadline=time.monotonic() + 1)
                packet, peer = observer.recvfrom(512)
                self.assertEqual(packet, windows_guest._local_udp_marker("a" * 64, role, "ipv4"))
                self.assertEqual(peer[0], "127.0.0.1")
                self.assertEqual(result["state"], "accepted_full")
                self.assertEqual(result["sent_bytes"], len(packet))
                self.assertNotIn("ok", result)
                results.append(packet)
        self.assertNotEqual(*results)

    def test_local_udp_short_send_route_and_deadline_are_incomplete(self):
        for outcome in (0, OSError(10051, "private text"), TimeoutError()):
            with self.subTest(outcome=type(outcome).__name__), mock.patch("socket.socket") as factory:
                sender = factory.return_value.__enter__.return_value
                if isinstance(outcome, Exception):
                    sender.sendto.side_effect = outcome
                else:
                    sender.sendto.return_value = outcome
                result = windows_guest._local_udp_attempt("child", "ipv4", 19003, "a" * 64,
                                                         deadline=time.monotonic() + 1)
                self.assertEqual(result["state"], "invalid")
                sender.bind.assert_called_once_with(("127.0.0.1", 0))
                sender.sendto.assert_called_once_with(windows_guest._local_udp_marker("a" * 64, "child", "ipv4"),
                                                     ("127.0.0.1", 19003))
                sender.connect.assert_not_called()
        with mock.patch("socket.socket") as factory:
            result = windows_guest._local_udp_attempt("parent", "ipv6", 19004, "a" * 64,
                                                     deadline=time.monotonic() - 1)
        factory.assert_not_called()
        self.assertEqual(result["code"], "deadline")

    def test_config_rejects_udp_destinations_extra_fields_duplicate_keys_and_bool_ports(self):
        path = Path(self.temp.name) / "config.json"
        path.write_text(json.dumps(self.config))
        self.assertEqual(windows_guest._read_config(path), self.config)
        for change in ({"host_udp_ports": [True, 19004]}, {"host_udp_ports": [19003]},
                       {"udp_destination": "1.1.1.1"}, {"schema_version": True}):
            path.write_text(json.dumps({**self.config, **change}))
            with self.assertRaises(ValueError):
                windows_guest._read_config(path)
        path.write_text(json.dumps(self.config)[:-1] + ',"host_udp_ports":[19003,19004]}')
        with self.assertRaisesRegex(ValueError, "duplicate"):
            windows_guest._read_config(path)

    def test_startup_report_rejects_forged_udp_pass_and_process_identity(self):
        report = {"schema_version": 1, "nonce": "a" * 64, "config_readonly": {"ok": True, "code": 5},
                  "parent": self.startup_report("parent"), "child": self.startup_report("child"),
                  "aux": {"parent_ipv6_loopback": {"ok": False, "code": 10013}}}
        windows_guest._validate_startup_report(report, "a" * 64)
        for change in ({"ok": True}, {"sent_bytes": True}, {"code": 10013}, {"sent_bytes": 0}):
            altered = json.loads(json.dumps(report))
            altered["child"]["local_udp"]["ipv4"].update(change)
            with self.assertRaises(ValueError):
                windows_guest._validate_startup_report(altered, "a" * 64)
        report["child"]["parent_pid"] = 999
        with self.assertRaisesRegex(ValueError, "child parent"):
            windows_guest._validate_startup_report(report, "a" * 64)

    def test_child_popen_handle_identity_is_checked_before_handle_release(self):
        report = self.startup_report("child")
        report.update(pid=456, parent_pid=123, process_created=2000)
        process = mock.Mock(pid=456, _handle=mock.Mock(), returncode=0)
        process.poll.return_value = 0
        process.communicate.return_value = (json.dumps({"nonce": "a" * 64, "report": report}).encode("ascii"), None)
        with mock.patch.object(windows_guest.subprocess, "Popen", return_value=process), \
                mock.patch.object(windows_guest, "_process_creation_time", return_value=2000) as created, \
                mock.patch.object(windows_guest.os, "getpid", return_value=123):
            self.assertEqual(windows_guest._nested_startup_report(19001, 19002, [19003, 19004], "a" * 64,
                                                                deadline=time.monotonic() + 1), report)
            created.assert_called_once_with(process._handle)
            process._handle.Close.assert_called_once()
        report["process_created"] = 2001
        process.communicate.return_value = (json.dumps({"nonce": "a" * 64, "report": report}).encode("ascii"), None)
        with mock.patch.object(windows_guest.subprocess, "Popen", return_value=process), \
                mock.patch.object(windows_guest, "_process_creation_time", return_value=2000), \
                mock.patch.object(windows_guest.os, "getpid", return_value=123):
            with self.assertRaisesRegex(windows_guest._ProbeFailure, "invalid_report"):
                windows_guest._nested_startup_report(19001, 19002, [19003, 19004], "a" * 64,
                                                    deadline=time.monotonic() + 1)

    def test_shared_deadline_stall_cannot_publish_ready_or_start_application(self):
        actual_check = windows_guest._child_self_check
        parent, child = self.startup_report("parent"), self.startup_report("child")
        _, check, ready, decision, popen = self.helper_setup(self.running_bridge)
        check.side_effect = actual_check
        seen = []
        def stalled_child(*args, deadline):
            seen.append(deadline)
            while time.monotonic() < deadline:
                threading.Event().wait(0.005)
            raise windows_guest._ProbeFailure("child_timeout")
        def parent_checks(*args, deadline):
            seen.append(deadline)
            return parent
        started = time.monotonic()
        with mock.patch.object(windows_guest, "_SELF_CHECK_BUDGET", 0.65), \
                mock.patch.object(windows_guest, "_run_startup_probes", side_effect=parent_checks), \
                mock.patch.object(windows_guest, "_nested_startup_report", side_effect=stalled_child), \
                mock.patch.object(windows_guest, "_same_process_loopback"):
            self.assertEqual(windows_guest.run(Path("config")), 70)
        self.assertLess(time.monotonic() - started, 1)
        self.assertEqual(seen[0], seen[1])
        ready.assert_not_called()
        decision.assert_not_called()
        popen.assert_not_called()

    @unittest.skipUnless(sys.platform == "win32", "real CreateFileW ABI requires Windows")
    def test_real_win32_writable_config_probe_closes_deletes_own_file_and_refuses(self):
        directory = Path(self.temp.name) / "配置 目录"
        directory.mkdir()
        config = directory / "guest-config.json"
        unrelated = config.parent / "unrelated.txt"
        unrelated.write_text("keep")
        result = windows_guest._readonly_config_probe(config, "a" * 64)
        self.assertEqual(result, {"ok": False, "code": "writable"})
        self.assertEqual(unrelated.read_text(), "keep")
        self.assertEqual(list(config.parent.glob(".ruleproxy-readonly-*")), [])

    def test_readonly_config_proof_requires_exact_windows_access_denied(self):
        for winerror in (5, 3, 13, 32, None):
            api = mock.Mock()
            api.create_new.return_value = (None, winerror)
            with self.subTest(winerror=winerror), mock.patch.object(windows_guest, "_ReadOnlyProbeApi", return_value=api), \
                    mock.patch.object(Path, "open", side_effect=AssertionError("CRT must not implement this probe")):
                result = windows_guest._readonly_config_probe(Path(self.temp.name) / "guest-config.json", "a" * 64)
            self.assertEqual(result["ok"], winerror == 5)
            self.assertEqual(result["code"], winerror if winerror is not None else "error")
            api.close.assert_not_called()
            api.delete.assert_not_called()

    def test_win32_success_ignores_stale_access_error_and_closes_before_delete(self):
        api = mock.Mock()
        api.create_new.return_value = (77, 5)
        api.close.return_value = True
        api.delete.return_value = True
        config = Path(self.temp.name) / "guest-config.json"
        with mock.patch.object(windows_guest, "_ReadOnlyProbeApi", return_value=api):
            self.assertEqual(windows_guest._readonly_config_probe(config, "a" * 64),
                             {"ok": False, "code": "writable"})
        expected = config.parent / (".ruleproxy-readonly-" + "a" * 64)
        self.assertEqual(api.mock_calls, [mock.call.create_new(expected), mock.call.close(77), mock.call.delete(expected)])

    def test_win32_close_or_delete_failure_is_cleanup_failure_and_cannot_pass(self):
        for close_ok, delete_ok in ((False, True), (True, False)):
            api = mock.Mock()
            api.create_new.return_value = (77, 0)
            api.close.return_value = close_ok
            api.delete.return_value = delete_ok
            with self.subTest(close_ok=close_ok, delete_ok=delete_ok), \
                    mock.patch.object(windows_guest, "_ReadOnlyProbeApi", return_value=api):
                self.assertEqual(windows_guest._readonly_config_probe(Path(self.temp.name) / "guest.json", "a" * 64),
                                 {"ok": False, "code": "cleanup"})
            api.close.assert_called_once_with(77)
            if not close_ok:
                api.delete.assert_not_called()

    def test_readonly_probe_never_overwrites_or_deletes_existing_nonce_name(self):
        config = Path(self.temp.name) / "guest-config.json"
        existing = config.parent / (".ruleproxy-readonly-" + "a" * 64)
        existing.write_bytes(b"keep existing")
        with mock.patch.object(windows_guest, "_ReadOnlyProbeApi") as factory:
            result = windows_guest._readonly_config_probe(config, "a" * 64)
        self.assertEqual(result, {"ok": False, "code": "existing"})
        factory.assert_not_called()
        self.assertEqual(existing.read_bytes(), b"keep existing")

    def test_win32_create_requests_write_create_new_without_delete_access_or_delete_on_close(self):
        api = object.__new__(windows_guest._ReadOnlyProbeApi)
        api.kernel32 = mock.Mock()
        api.kernel32.CreateFileW.return_value = 77
        with mock.patch.object(windows_guest.ctypes, "set_last_error", create=True) as clear, \
                mock.patch.object(windows_guest.ctypes, "get_last_error", return_value=5, create=True):
            self.assertEqual(api.create_new(Path("owned")), (77, 5))
        clear.assert_called_once_with(0)
        args = api.kernel32.CreateFileW.call_args.args
        self.assertEqual(args[1:5], (0x40000000, 7, None, 1))
        self.assertFalse(args[1] & 0x00010000, "DELETE access must not distort readonly checks")
        self.assertFalse(args[5] & 0x04000000, "DELETE_ON_CLOSE must not distort readonly checks")
        self.assertTrue(args[5] & 0x00200000, "reparse points must not be followed")

    def test_writable_config_mount_never_publishes_ready_or_starts_application(self):
        actual_check = windows_guest._child_self_check
        parent, child = self.startup_report("parent"), self.startup_report("child")
        _, check, ready, decision, popen = self.helper_setup(self.running_bridge)
        check.side_effect = actual_check
        with mock.patch.object(windows_guest, "_run_startup_probes", return_value=parent), \
                mock.patch.object(windows_guest, "_nested_startup_report", return_value=child), \
                mock.patch.object(windows_guest, "_readonly_config_probe", return_value={"ok": False, "code": "writable"}):
            self.assertEqual(windows_guest.run(Path("config")), 70)
        ready.assert_not_called()
        decision.assert_not_called()
        popen.assert_not_called()
        self.assertEqual(json.loads((Path(self.temp.name) / "network-probe.json").read_text())["config_readonly"],
                         {"ok": False, "code": "writable"})


if __name__ == "__main__":
    unittest.main()
