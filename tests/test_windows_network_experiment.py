"""Verify the experimental harness without claiming Windows containment."""
import importlib.util
import json
from pathlib import Path
import socket
import shutil
import tempfile
import threading
import time
from types import SimpleNamespace
import unittest
from unittest import mock

from ruleproxy.file_bridge import FileProxyBridge, run_guest_bridge


ROOT = Path(__file__).resolve().parent.parent
spec = importlib.util.spec_from_file_location("ruleproxy_network_experiment", ROOT / ".github/windows_network_experiment.py")
experiment = importlib.util.module_from_spec(spec)
spec.loader.exec_module(experiment)


class WindowsNetworkExperimentTests(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        self.directory = Path(self.temporary.name)

    def test_fixed_model1_rule_cannot_open_other_addresses_ports_or_protocols(self):
        policy = experiment.network_policy("model1_internal", 49123, 10809)
        self.assertEqual(policy, {"network": {
            "egress": {"default": "deny", "allow": [{"to": [{"cidr": "127.0.0.1/32"}],
                       "ports": [{"protocol": "tcp", "port": 49123}]}]},
            "ingress": {"default": "allow", "hostLoopback": "deny"}}})
        self.assertNotIn("runtimeConfig", policy)
        self.assertNotIn("processContainer", policy)
        for name, first, second in (("invalid", 49123, 10809), ("model1_internal", True, 10809),
                                    ("model1_internal", 49123, 0)):
            with self.assertRaises(ValueError):
                experiment.network_policy(name, first, second)

    def test_baseline_and_host_proxy_have_explicit_distinct_contracts(self):
        baseline = experiment.network_policy("model3", 49123, 10809)
        self.assertEqual(baseline["network"]["ingress"], {"default": "deny", "hostLoopback": "deny"})
        self.assertNotIn("runtimeConfig", baseline)
        proxy = experiment.network_policy("model2_host", 49123, 10809)
        self.assertEqual(proxy["runtimeConfig"], {"networkProxy": "http://127.0.0.1:10809"})
        self.assertEqual(proxy["network"]["ingress"], {"default": "allow", "hostLoopback": "allow"})
        self.assertNotIn("allow", proxy["network"]["egress"])

    def test_fixed_http_and_socks_fixture_cross_frames_and_keep_both_fin_directions(self):
        fixture = experiment.FixedProxy()
        self.addCleanup(fixture.close)
        for protocol in ("http", "socks"):
            experiment.proxy_roundtrip(fixture.port, fixture.token, protocol)
        deadline = time.monotonic() + 1
        while fixture.roundtrips != 2 and time.monotonic() < deadline:
            time.sleep(0.01)
        self.assertEqual(fixture.roundtrips, 2)
        self.assertEqual(fixture.errors, [])
        self.assertGreater(len(experiment.payload(fixture.token)), 65536)

    def test_fixture_rejects_any_unrelated_socks_destination(self):
        fixture = experiment.FixedProxy()
        self.addCleanup(fixture.close)
        with socket.create_connection(("127.0.0.1", fixture.port), timeout=2) as connection:
            connection.sendall(b"\x05\x01\x00")
            self.assertEqual(experiment.exact(connection, 2), b"\x05\x00")
            connection.sendall(b"\x05\x01\x00\x03\x04evil\x01\xbb")
            try:
                self.assertEqual(connection.recv(1), b"")
            except ConnectionResetError:
                pass  # Rejection closes only this local fixture connection.
        self.assertEqual(fixture.roundtrips, 0)

    def test_real_file_relay_passes_the_new_fixture_protocols(self):
        fixture = experiment.FixedProxy()
        bridge = FileProxyBridge(fixture.port, self.directory / "bridge")
        listener = socket.socket()
        listener.bind(("127.0.0.1", 0))
        port = listener.getsockname()[1]
        listener.close()
        stop = threading.Event()
        errors = []

        def run():
            try:
                run_guest_bridge(port, bridge.directory, bridge.nonce, stop)
            except Exception as exc:
                errors.append(exc)

        worker = threading.Thread(target=run, daemon=True)
        worker.start()
        try:
            deadline = time.monotonic() + 3
            while not (bridge.directory / "bridge-ready.json").exists() and time.monotonic() < deadline:
                time.sleep(0.01)
            for protocol in ("http", "socks"):
                experiment.proxy_roundtrip(port, fixture.token, protocol)
        finally:
            stop.set()
            worker.join(5)
            bridge.close()
            fixture.close()
        self.assertFalse(worker.is_alive())
        self.assertEqual(errors, [])
        self.assertEqual(fixture.roundtrips, 2)

    def test_udp_observers_have_real_positive_controls_and_bounded_teardown(self):
        observer = experiment.DatagramObservers()
        try:
            self.assertEqual(observer.received, [1, 1])
            self.assertEqual(observer.positive_controls,
                             [{"family": "ipv4", "received": True}, {"family": "ipv6", "received": True}])
        finally:
            observer.close()
        self.assertFalse(any(thread.is_alive() for thread in observer.threads))

    def test_pending_recovery_is_not_hidden_in_nested_actor_or_ipc_reports(self):
        self.assertFalse(experiment.pending_recovery({"status": "unsupported", "checks": []}))
        self.assertFalse(experiment.pending_recovery({"actors": [{"ipc": {
            "cleanup_proven": True, "cleanup_errors": []}}]}))
        self.assertTrue(experiment.pending_recovery({"actors": [{"ipc": {"cleanup_error": "HANDLE"}}]}))
        self.assertTrue(experiment.pending_recovery({"probe": {"recovery_directory": "retained"}}))
        for ipc in ({"cleanup_proven": False, "cleanup_errors": []},
                    {"cleanup_proven": True, "cleanup_errors": ["CancelIoEx failed"]},
                    {"checks": [{"client": {"cleanup_proven": False}}]}):
            with self.subTest(ipc=ipc):
                self.assertTrue(experiment.pending_recovery({"actors": [{"ipc": ipc}]}))

    def test_actor_report_requires_live_parent_child_relationship(self):
        for role, pid, parent in (("parent", 42, 30), ("child", 43, 41)):
            experiment.write_json(self.directory / f"actor-{role}-initial.json",
                                  {"scope": role, "phase": "initial", "pid": pid, "parent_pid": parent})
        with self.assertRaisesRegex(RuntimeError, "parent/child"):
            experiment.wait_actor_reports(self.directory, SimpleNamespace(poll=lambda: None), "initial", timeout=1)

    def test_report_pids_must_match_both_retained_kernel_handle_generations(self):
        api = mock.Mock()
        api.process_creation_time.return_value = 100
        api.direct_children.side_effect = [[(42, 201)], [(999, 202)]]
        api.process_alive.return_value = True
        runtime = SimpleNamespace(_WinProcessApi=lambda: api, _raw_handle=lambda value: value)
        wrapper = SimpleNamespace(pid=40, _handle=101)
        with self.assertRaisesRegex(RuntimeError, "verified workload descendant"):
            experiment.retain_actor_handles(runtime, wrapper,
                                            [{"pid": 42, "process_created": 100},
                                             {"pid": 43, "process_created": 100}])
        self.assertEqual({call.args[0] for call in api.close.call_args_list}, {201, 202})

    def attestation_fixture(self, children, *, living=None, created=None):
        api = mock.Mock()
        times = {101: 90, 201: 100, 202: 110, 203: 120}
        times.update(created or {})
        api.process_creation_time.side_effect = times.__getitem__
        api.direct_children.side_effect = [[(42, 201)], children]
        api.process_alive.side_effect = lambda handle: (living or {}).get(handle, True)
        runtime = SimpleNamespace(_WinProcessApi=lambda: api, _raw_handle=lambda value: value)
        wrapper = SimpleNamespace(pid=40, _handle=101)
        reports = [{"pid": 42, "process_created": 100}, {"pid": 43, "process_created": 110}]
        return api, runtime, wrapper, reports

    def test_completed_pipe_helper_is_excluded_only_by_its_signaled_held_handle(self):
        api, runtime, wrapper, reports = self.attestation_fixture(
            [(43, 202), (10368, 203)], living={203: False})
        diagnostic = {}
        held_api, handles = experiment.retain_actor_handles(runtime, wrapper, reports, diagnostic)
        self.assertIs(held_api, api)
        self.assertEqual(handles, [(42, 201), (43, 202)])
        api.close.assert_called_once_with(203)
        self.assertTrue(diagnostic["attestation_passed"])
        child = diagnostic["snapshots"][1]
        self.assertEqual(child["returned_pids"], [43, 10368])
        self.assertEqual(child["live_pids"], [43])
        self.assertTrue(child["held_handle_generation_verified"])
        self.assertEqual(child["children"][1], {"pid": 10368, "process_created": 120, "alive": False})

    def test_extra_living_child_is_rejected_and_all_owned_handles_are_closed(self):
        api, runtime, wrapper, reports = self.attestation_fixture([(43, 202), (44, 203)])
        diagnostic = {}
        with self.assertRaisesRegex(RuntimeError, "verified workload descendant"):
            experiment.retain_actor_handles(runtime, wrapper, reports, diagnostic)
        self.assertFalse(diagnostic["attestation_passed"])
        self.assertEqual(diagnostic["snapshots"][1]["failure"], "unexpected_live_children")
        self.assertEqual(diagnostic["snapshots"][1]["live_pids"], [43, 44])
        self.assertEqual({call.args[0] for call in api.close.call_args_list}, {201, 202, 203})

    def test_reported_child_that_exited_is_distinguished_from_an_extra_process(self):
        api, runtime, wrapper, reports = self.attestation_fixture([(43, 202)], living={202: False})
        diagnostic = {}
        with self.assertRaisesRegex(RuntimeError, "verified workload descendant"):
            experiment.retain_actor_handles(runtime, wrapper, reports, diagnostic)
        self.assertEqual(diagnostic["snapshots"][1]["failure"], "reported_process_exited")
        self.assertFalse(diagnostic["attestation_passed"])
        self.assertEqual({call.args[0] for call in api.close.call_args_list}, {201, 202})
        self.assertEqual(api.close.call_count, 2)

    def test_reused_report_pid_with_a_new_process_generation_is_rejected(self):
        api, runtime, wrapper, reports = self.attestation_fixture([(43, 202)], created={202: 111})
        diagnostic = {}
        with self.assertRaisesRegex(RuntimeError, "generation did not match"):
            experiment.retain_actor_handles(runtime, wrapper, reports, diagnostic)
        self.assertEqual(diagnostic["snapshots"][1]["failure"], "reported_process_generation_mismatch")
        self.assertEqual(diagnostic["snapshots"][1]["children"][0]["process_created"], 111)
        self.assertEqual(diagnostic["reported_child_created"], 110)
        self.assertEqual({call.args[0] for call in api.close.call_args_list}, {201, 202})

    def test_nested_recovery_stops_the_matrix_and_keeps_its_directory(self):
        helpers = mock.Mock()
        helpers.verify_runtime_manifest.return_value = {"fixed-runtime": "verified"}
        helpers.host_facts.return_value = {"native_machine": 0x8664, "python_pe_machine": 0x8664,
                                          "acceptance_scope": "native_x64"}
        helpers.network_snapshot.return_value = "unchanged"
        fixtures = mock.Mock(threads=[])
        helpers.HostFixtures.return_value = fixtures
        retained = self.directory / "retained"
        retained.mkdir()
        self.addCleanup(shutil.rmtree, retained, True)
        report = self.directory / "result.json"
        value = {"name": "model3", "status": "failed", "process_started": True,
                 "actors": [{"ipc": {"cleanup_proven": False,
                                      "cleanup_errors": ["handle remained live"]}}]}
        with mock.patch.object(experiment, "load_helpers", return_value=helpers), \
                mock.patch.object(experiment, "import_project", return_value=(mock.Mock(), None, None)), \
                mock.patch.object(experiment, "DatagramObservers"), \
                mock.patch.object(experiment.tempfile, "mkdtemp", return_value=str(retained)), \
                mock.patch.object(experiment, "run_variant", return_value=value) as variant, \
                mock.patch("builtins.print"):
            code = experiment.main(["--root", str(self.directory), "--report", str(report)])
        result = json.loads(report.read_text())
        self.assertEqual(code, 1)
        self.assertEqual(variant.call_count, 1)
        self.assertFalse(result["cleanup_proven"])
        self.assertEqual(result["recovery_directory"], str(retained))
        self.assertTrue(retained.exists())
        self.assertEqual(result["variants"][0]["actors"][0]["ipc"]["cleanup_errors"],
                         ["handle remained live"])

    def test_read_and_write_reports_are_bounded(self):
        report = self.directory / "report.json"
        report.write_bytes(b"x" * (experiment.MAX_REPORT_BYTES + 1))
        with self.assertRaises(RuntimeError):
            experiment.read_json(report)
        with self.assertRaises(RuntimeError):
            experiment.write_json(report, {"log": "x" * experiment.MAX_REPORT_BYTES})

    def test_failed_setup_still_writes_false_acceptance_and_no_collection_success(self):
        report = self.directory / "result.json"
        with mock.patch.object(experiment, "load_helpers", side_effect=RuntimeError("fixture setup failed")), \
                mock.patch("builtins.print"):
            code = experiment.main(["--root", str(self.directory), "--report", str(report)])
        value = json.loads(report.read_text())
        self.assertEqual(code, 1)
        self.assertEqual(value["status"], "failed")
        self.assertEqual(value["variants"], [])
        self.assertFalse(value["full_acceptance_passed"])
        self.assertFalse(value["acceptance_passed"])
        self.assertFalse(value["real_node_passed"])


if __name__ == "__main__":
    unittest.main()
