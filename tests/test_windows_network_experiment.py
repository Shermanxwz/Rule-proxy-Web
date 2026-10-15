"""Verify the experimental harness without claiming Windows containment."""
import importlib.util
import copy
import hashlib
import json
from pathlib import Path
import socket
import shutil
import sys
import tempfile
import threading
import time
from types import SimpleNamespace
import unittest
from unittest import mock

from ruleproxy.file_bridge import FileProxyBridge, run_guest_bridge
from ruleproxy import windows_runtime


ROOT = Path(__file__).resolve().parent.parent
spec = importlib.util.spec_from_file_location("ruleproxy_network_experiment", ROOT / ".github/windows_network_experiment.py")
experiment = importlib.util.module_from_spec(spec)
spec.loader.exec_module(experiment)


class WindowsNetworkExperimentTests(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        self.directory = Path(self.temporary.name).resolve(strict=True)

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

    def test_internal_port_candidate_keeps_external_ingress_and_host_loopback_denied(self):
        policy = experiment.network_policy("model1_internal_ingress_deny", 49123, 10809)
        self.assertEqual(policy, {"network": {
            "egress": {"default": "deny", "allow": [{"to": [{"cidr": "127.0.0.1/32"}],
                       "ports": [{"protocol": "tcp", "port": 49123}]}]},
            "ingress": {"default": "deny", "hostLoopback": "deny"}}})
        self.assertLess(experiment.VARIANTS.index("model1_internal_ingress_deny"),
                        experiment.VARIANTS.index("model1_internal"))

    def test_ingress_control_changes_only_default_ingress_and_keeps_host_loopback_denied(self):
        baseline = experiment.network_policy(experiment.PREFERRED_VARIANT, 49123, 10809)
        control = experiment.network_policy(experiment.PREFERRED_VARIANT, 49123, 10809,
                                            ingress_default_allow_control=True)
        self.assertEqual(control["network"]["ingress"], {"default": "allow", "hostLoopback": "deny"})
        self.assertEqual(control["network"]["egress"], baseline["network"]["egress"])
        self.assertNotIn("runtimeConfig", control)
        self.assertEqual(baseline["network"]["ingress"], {"default": "deny", "hostLoopback": "deny"})
        with self.assertRaises(ValueError):
            experiment.network_policy("model1_internal", 49123, 10809,
                                       ingress_default_allow_control=True)
        with self.assertRaises(ValueError):
            experiment.network_policy(experiment.PREFERRED_VARIANT, 49123, 10809,
                                      singleton_port_range=True, ingress_default_allow_control=True)

    def test_singleton_range_option_changes_only_port_encoding_for_model1(self):
        for name in experiment.MODEL1_VARIANTS:
            with self.subTest(name=name):
                single = experiment.network_policy(name, 49123, 10809)
                ranged = experiment.network_policy(name, 49123, 10809, singleton_port_range=True)
                rule = ranged["network"]["egress"]["allow"][0]
                self.assertEqual(rule["to"], [{"cidr": "127.0.0.1/32"}])
                self.assertEqual(rule["ports"], [{"protocol": "tcp", "port": 49123, "endPort": 49123}])
                rule["ports"][0].pop("endPort")
                self.assertEqual(ranged, single)
        for name in ("model3", "model2_host"):
            self.assertEqual(experiment.network_policy(name, 49123, 10809, singleton_port_range=True),
                             experiment.network_policy(name, 49123, 10809))

    def test_psec_1_1_diagnostic_adds_only_owned_nested_enumeration_path(self):
        profile = self.directory / "profile"
        profile.mkdir()
        policy = {"filesystem": {"readwritePaths": [str(profile)], "readonlyPaths": [str(self.directory)]},
                  **experiment.network_policy("model3", 49123, 10809)}
        original_network = copy.deepcopy(policy["network"])
        experiment.add_psec_1_1_diagnostic_path(policy, profile)
        paths = policy["processContainer"]["filesystem"]["enumeratePaths"]
        self.assertEqual(len(paths), 1)
        child = Path(paths[0])
        self.assertEqual(child.parent, profile)
        self.assertEqual(list(child.iterdir()), [])
        self.assertEqual(policy["network"], original_network)
        self.assertEqual(policy["filesystem"]["readwritePaths"], [str(profile)])
        self.assertEqual(policy["filesystem"]["readonlyPaths"], [str(self.directory)])

    def test_psec_1_1_diagnostic_requires_exact_existing_rw_profile(self):
        profile = self.directory / "profile"
        profile.mkdir()
        with self.assertRaisesRegex(RuntimeError, "exact read-write"):
            experiment.add_psec_1_1_diagnostic_path({"filesystem": {"readwritePaths": []}}, profile)
        self.assertFalse((profile / ".psec-enumerate-path-diagnostic").exists())

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

    def complete_actor_reports(self, phase="initial"):
        for role, pid, parent in (("parent", 42, 30), ("child", 43, 42)):
            experiment.write_json(self.directory / f"actor-{role}-{phase}.json",
                                  {"scope": role, "phase": phase, "pid": pid, "parent_pid": parent})

    def test_final_report_published_between_read_and_clean_exit_is_collected(self):
        def poll():
            self.complete_actor_reports()
            return 0
        records = experiment.wait_actor_reports(self.directory, SimpleNamespace(poll=poll), "initial", timeout=1)
        self.assertEqual([record["pid"] for record in records], [42, 43])

    def test_complete_reports_never_hide_a_failed_wrapper_exit(self):
        self.complete_actor_reports()
        with self.assertRaisesRegex(RuntimeError, "exited with status 1"):
            experiment.wait_actor_reports(self.directory, SimpleNamespace(poll=lambda: 1), "initial", timeout=1)

    def test_clean_exit_without_both_reports_remains_incomplete(self):
        with self.assertRaisesRegex(RuntimeError, "reports completed"):
            experiment.wait_actor_reports(self.directory, SimpleNamespace(poll=lambda: 0), "initial", timeout=1)

    def test_persistent_stop_bridge_control_publishes_exactly_once(self):
        relay = self.directory / "relay"
        relay.mkdir()
        config = {"root": str(ROOT), "variant": "model1_internal_ingress_deny", "endpoint_port": 49123,
                  "bridge_directory": str(relay), "bridge_nonce": "a" * 64}
        config_file = self.directory / "actor-config.json"
        experiment.write_json(config_file, config)
        experiment.write_json(relay / "bridge-ready.json", {"ready": True, "nonce": config["bridge_nonce"]})
        experiment.write_json(self.directory / "actor-control.json", {"state": "stop_bridge"})
        original_write = experiment.write_json
        publications = []
        def write(path, value, **kwargs):
            if path.name == "bridge-stopped.json":
                if path.exists():
                    # The Windows regression was a second os.replace while the
                    # host read this persistent notification. No retry hides it.
                    raise PermissionError("destination is held by the reader")
                publications.append(value)
            return original_write(path, value, **kwargs)
        thread = mock.Mock()
        thread.is_alive.return_value = False
        bridge = SimpleNamespace(run_guest_bridge=mock.Mock())
        with mock.patch.object(experiment, "import_project", return_value=(None, None, bridge)), \
                mock.patch.object(experiment.threading, "Thread", return_value=thread), \
                mock.patch.object(experiment.subprocess, "Popen"), \
                mock.patch.object(experiment, "collect_actor_checks", return_value={"scope": "parent"}), \
                mock.patch.object(experiment, "write_json", side_effect=write), \
                mock.patch.object(experiment.time, "monotonic", side_effect=[0, 0, 0, 0.1, 0.2, 86]), \
                mock.patch.object(experiment.time, "sleep"):
            self.assertEqual(experiment.actor(config_file, "parent"), 0)
        self.assertEqual(publications, [{"stopped": True}])
        self.assertEqual(thread.join.call_count, 2)  # First stop, then final safe closure.

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

    def test_native_open_failure_identifies_first_open_or_reopen_without_changing_access(self):
        for reopen in (False, True):
            with self.subTest(reopen=reopen):
                api = object.__new__(windows_runtime._WinProcessApi)
                kernel = mock.Mock()
                kernel.OpenProcess.side_effect = [201, 0] if reopen else [0]
                kernel.CloseHandle.return_value = 1
                api.kernel32 = kernel
                api._snapshot_parent_ids = mock.Mock(side_effect=[{42: 40}, {42: 40}])
                api._creation_time = mock.Mock(return_value=100)
                api.process_creation_time = mock.Mock(return_value=90)
                runtime = SimpleNamespace(_WinProcessApi=lambda: api, _raw_handle=lambda value: value)
                error = PermissionError(13, "fixed test denial")
                error.winerror = 5
                diagnostic = {}
                with mock.patch.object(experiment.ctypes, "get_last_error", return_value=5, create=True), \
                        mock.patch.object(experiment.ctypes, "set_last_error", create=True) as restore, \
                        mock.patch.object(experiment.ctypes, "WinError", return_value=error, create=True), \
                        self.assertRaises(PermissionError) as raised:
                    experiment.retain_actor_handles(runtime, SimpleNamespace(pid=40, _handle=101),
                        [{"pid": 42, "process_created": 100}, {"pid": 43, "process_created": 110}], diagnostic)
                self.assertIs(raised.exception, error)
                failure = diagnostic["native_api_failure"]
                self.assertEqual(failure, {"operation": "OpenProcess", "scope": "parent", "parent_pid": 40,
                    "target_pid": 42, "desired_access": 0x101001 if reopen else 0x1000,
                    "open_phase": "reopen" if reopen else "first_open", "succeeded": False,
                    "errno": None, "winerror": 5})
                self.assertEqual(diagnostic["snapshots"][0]["status"], "failed")
                self.assertEqual(diagnostic["snapshots"][0]["winerror"], 5)
                self.assertFalse(diagnostic["attestation_passed"])
                expected_calls = [mock.call(0x1000, False, 42)]
                if reopen:
                    expected_calls.append(mock.call(0x101001, False, 42))
                self.assertEqual(kernel.OpenProcess.call_args_list, expected_calls)
                self.assertEqual(kernel.CloseHandle.call_args_list, [mock.call(201)] if reopen else [])
                kernel.TerminateProcess.assert_not_called()
                restore.assert_called_with(5)

    def test_observer_preserves_function_signatures_results_and_bounded_failure_facts(self):
        kernel, diagnostic = mock.Mock(), {}
        kernel.WaitForSingleObject.return_value = 258
        error_state = [0]
        observer = experiment._ProcessApiObservation(kernel, diagnostic,
            get_error=lambda: error_state[0], set_error=lambda value: error_state.__setitem__(0, value))
        observer.handles[101] = (40, 0x101001)
        observer.context("child", 42)
        observer.WaitForSingleObject.argtypes = [int, int]
        self.assertEqual(kernel.WaitForSingleObject.argtypes, [int, int])
        for _ in range(80):
            self.assertEqual(observer.WaitForSingleObject(101, 0), 258)
        kernel.OpenProcess.return_value = 0
        error_state[0] = 5
        self.assertEqual(observer.OpenProcess(0x101001, False, 43), 0)
        self.assertEqual(error_state[0], 5)
        self.assertEqual(len(diagnostic["native_api_calls"]), 64)
        self.assertTrue(diagnostic["native_api_calls_truncated"])
        self.assertEqual(diagnostic["native_api_failure"]["target_pid"], 43)
        self.assertNotIn("handle", json.dumps(diagnostic))
        self.assertNotIn("image", json.dumps(diagnostic))

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
        self.assertEqual({key: child["children"][1][key] for key in ("pid", "process_created", "alive")},
                         {"pid": 10368, "process_created": 120, "alive": False})

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

    def test_verified_system_console_is_accounted_and_its_handle_remains_owned(self):
        api, runtime, wrapper, reports = self.attestation_fixture([(43, 202), (44, 203)])
        diagnostic = {}
        image = {"image_path": r"C:\Windows\System32\conhost.exe", "image_path_truncated": False}
        signature = {"signature_status": "Valid", "signature_type": "Catalog", "is_os_binary": True,
                     "publisher": "Microsoft Windows", "signer_thumbprint": "A" * 40, "file_sha256": "b" * 64}
        with mock.patch.object(experiment, "held_image_diagnostic", return_value=image), \
                mock.patch.object(experiment, "system_directory", return_value=r"C:\Windows\System32"), \
                mock.patch.object(experiment, "system_console_signature", return_value=signature) as trust:
            _, handles = experiment.retain_actor_handles(runtime, wrapper, reports, diagnostic)
        self.assertEqual(handles, [(42, 201), (43, 202), (44, 203)])
        api.close.assert_not_called()
        trust.assert_called_once_with(r"C:\Windows\System32", image)
        self.assertTrue(diagnostic["attestation_passed"])
        self.assertEqual(diagnostic["snapshots"][1]["live_count"], 2)
        helper = diagnostic["snapshots"][1]["accounted_system_helpers"][0]
        self.assertEqual(helper["pid"], 44)
        self.assertEqual(helper["signature"], signature)

    def test_multiple_live_helpers_fail_before_any_signature_can_allow_them(self):
        api, runtime, wrapper, reports = self.attestation_fixture([(43, 202), (44, 203), (45, 204)], created={204: 130})
        with mock.patch.object(experiment, "system_console_signature") as trust, \
                self.assertRaisesRegex(RuntimeError, "verified workload descendant"):
            experiment.retain_actor_handles(runtime, wrapper, reports)
        trust.assert_not_called()
        self.assertEqual({call.args[0] for call in api.close.call_args_list}, {201, 202, 203, 204})

    def test_signature_query_uses_system_powershell_modules_and_real_catalog_result(self):
        image = {"image_path": r"C:\Windows\System32\conhost.exe", "image_path_truncated": False}
        good = {"signature_status": "Valid", "signature_type": "Catalog", "is_os_binary": True,
                "publisher": "Microsoft Windows", "signer_thumbprint": "A" * 40, "file_sha256": "b" * 64}
        completed = SimpleNamespace(returncode=0, stdout=json.dumps(good))
        with mock.patch.object(experiment.subprocess, "run", return_value=completed) as run:
            self.assertEqual(experiment.system_console_signature(r"C:\Windows\System32", image), good)
        command = run.call_args.args[0]
        self.assertEqual(command[0], r"C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe")
        script = experiment.base64.b64decode(command[-1]).decode("utf-16-le")
        self.assertIn("$PSHOME, 'Modules'", script)
        self.assertIn("Microsoft.PowerShell.Security\\Get-AuthenticodeSignature -LiteralPath", script)
        self.assertNotIn("Get-FileHash", script)
        for key, bad in (("signature_status", "NotTrusted"), ("signature_type", "None"),
                         ("is_os_binary", False), ("publisher", "Other vendor"), ("signer_thumbprint", "")):
            with self.subTest(key=key), \
                    mock.patch.object(experiment.subprocess, "run", return_value=SimpleNamespace(
                        returncode=0, stdout=json.dumps(dict(good, **{key: bad})))):
                with self.assertRaisesRegex(RuntimeError, "valid Microsoft OS signature"):
                    experiment.system_console_signature(r"C:\Windows\System32", image)

    def test_console_basename_outside_system_directory_does_not_run_signature_query(self):
        for path in (r"C:\untrusted\conhost.exe", r"C:\Windows\System32\conhost.exe:other"):
            with self.subTest(path=path), mock.patch.object(experiment.subprocess, "run") as run:
                with self.assertRaisesRegex(RuntimeError, "canonical system console"):
                    experiment.system_console_signature(r"C:\Windows\System32",
                        {"image_path": path, "image_path_truncated": False})
                run.assert_not_called()

    def console_cache_fixture(self):
        class FileApi:
            def __init__(self):
                self.next_handle, self.opened, self.closed = 100, [], []
                self.identity = {'volume': 7, 'file_id': 11, 'size': 1024,
                    'creation_filetime': 1000, 'write_filetime': 2000, 'attributes': 32, 'sha256': 'b' * 64}
                self.close_error = False
            def open(self, path):
                self.next_handle += 1
                self.opened.append((self.next_handle, path))
                return self.next_handle
            def fingerprint(self, handle):
                if handle in self.closed:
                    raise RuntimeError('used closed file handle')
                return dict(self.identity)
            def close(self, handle):
                if self.close_error:
                    raise OSError('public fixture close error')
                self.closed.append(handle)
        api = FileApi()
        with mock.patch.object(experiment, 'system_directory', return_value=r'C:\Windows\System32'):
            cache = experiment.SystemConsoleTrustCache(api)
        self.addCleanup(lambda: (setattr(api, 'close_error', False), cache.close()))
        signature = {'signature_status': 'Valid', 'signature_type': 'Catalog', 'is_os_binary': True,
            'publisher': 'Microsoft Windows', 'signer_thumbprint': 'A' * 40, 'file_sha256': 'b' * 64}
        return cache, api, signature

    def test_preflight_cache_keeps_held_file_and_avoids_online_trust_inside_capture(self):
        cache, api, signature = self.console_cache_fixture()
        with mock.patch.object(experiment, 'system_console_signature', return_value=signature) as trust:
            cache.prepare()
            self.assertEqual(len(cache.handles), 1)
            held = cache.handles[0]
            self.assertNotIn(held, api.closed)
            cache.before_capture()
            for _ in range(3):
                self.assertEqual(cache.verify(cache.directory, cache.image), signature)
            trust.assert_called_once_with(cache.directory, cache.image)
            self.assertEqual(cache.handles, [held])
            self.assertEqual(len(api.closed), 3)
            cache.close()
        report = cache.summary()
        self.assertTrue(report['signature_prevalidated'])
        self.assertTrue(report['warmup_completed_before_capture_request'])
        self.assertEqual(report['cache_hits'], 3)
        self.assertEqual(report['inside_capture_revalidations'], 0)
        self.assertFalse(report['capture_contaminated'])
        self.assertTrue(report['cleanup_proven'])
        serialized = json.dumps(report)
        self.assertNotIn('Windows', serialized)
        self.assertNotIn('signer_thumbprint', serialized)
        with self.assertRaises(RuntimeError):
            cache.verify(cache.directory, cache.image)
        with self.assertRaises(RuntimeError):
            cache.prepare()

    def test_same_path_and_sha_are_insufficient_when_file_id_size_or_times_change(self):
        for field, value in (('file_id', 12), ('volume', 8), ('size', 2048),
                             ('creation_filetime', 1001), ('write_filetime', 2001), ('sha256', 'c' * 64)):
            with self.subTest(field=field):
                cache, api, signature = self.console_cache_fixture()
                with mock.patch.object(experiment, 'system_console_signature', return_value=signature) as trust:
                    cache.prepare(); cache.before_capture()
                    api.identity[field] = value
                    with self.assertRaisesRegex(RuntimeError, 'binding changed'):
                        cache.verify(cache.directory, cache.image)
                    self.assertEqual(trust.call_count, 2)  # The original trust check is retained on a mismatch.
                    self.assertTrue(cache.contaminated)
                    self.assertEqual(cache.summary()['cache_hits'], 0)
                    with self.assertRaises(RuntimeError):
                        cache.verify(cache.directory, cache.image)
                    self.assertEqual(trust.call_count, 2)  # An invalidated cache is never silently refreshed.

    def test_preflight_hash_and_metadata_must_remain_bound_across_signature_query(self):
        cache, api, signature = self.console_cache_fixture()
        def change_during_signature(*_):
            api.identity['file_id'] = 999
            return signature
        with mock.patch.object(experiment, 'system_console_signature', side_effect=change_during_signature):
            with self.assertRaisesRegex(RuntimeError, 'held file bytes'):
                cache.prepare()
        self.assertFalse(cache.summary()['signature_prevalidated'])
        with self.assertRaises(RuntimeError):
            cache.before_capture()
        cache.close()
        self.assertTrue(cache.summary()['cleanup_proven'])

    def test_cache_identity_read_error_is_contaminated_and_cannot_bypass_revalidation(self):
        cache, api, signature = self.console_cache_fixture()
        with mock.patch.object(experiment, 'system_console_signature', return_value=signature) as trust:
            cache.prepare(); cache.before_capture()
            with mock.patch.object(api, 'fingerprint', side_effect=OSError('public fixture read error')):
                with self.assertRaisesRegex(RuntimeError, 'could not be verified'):
                    cache.verify(cache.directory, cache.image)
            self.assertEqual(trust.call_count, 2)
        self.assertTrue(cache.summary()['capture_contaminated'])
        cache.close()

    def test_console_file_close_failure_is_retained_and_retriable_without_claiming_cleanup(self):
        cache, api, signature = self.console_cache_fixture()
        with mock.patch.object(experiment, 'system_console_signature', return_value=signature):
            cache.prepare()
        api.close_error = True
        with self.assertRaisesRegex(RuntimeError, 'cleanup was not proven'):
            cache.close()
        self.assertFalse(cache.summary()['cleanup_proven'])
        self.assertIn(cache, experiment._CONSOLE_RECOVERY_OWNERS)
        api.close_error = False
        cache.close()
        self.assertTrue(cache.summary()['cleanup_proven'])
        experiment._CONSOLE_RECOVERY_OWNERS.remove(cache)

    @unittest.skipUnless(sys.platform == 'win32', 'real Windows file handle ABI required')
    def test_real_windows_console_file_api_reads_owned_file_and_denies_concurrent_write(self):
        api = experiment._ConsoleFileApi()
        target = self.directory / '私有 file.bin'
        target.write_bytes(b'public owned file bytes' * 10000)
        handle = api.open(str(target))
        try:
            identity = api.fingerprint(handle)
            self.assertEqual(identity['sha256'], hashlib.sha256(target.read_bytes()).hexdigest())
            self.assertEqual(identity['size'], target.stat().st_size)
            attempted = api.kernel32.CreateFileW(str(target), 0x40000000, 7, None, 3, 0x80, None)
            if attempted != experiment.ctypes.c_void_p(-1).value:
                api.close(attempted)
                self.fail('held read-only image handle allowed a concurrent writer')
            self.assertEqual(experiment.ctypes.get_last_error(), 32)
        finally:
            api.close(handle)
        target.write_bytes(b'write succeeds after releasing the owned handle')

    def test_cached_console_identity_still_requires_canonical_held_process_image(self):
        api, runtime, wrapper, reports = self.attestation_fixture([(43, 202), (44, 203)])
        image = {'image_path': r'C:\Windows\System32\conhost.exe', 'image_path_truncated': False}
        cache, _, signature = self.console_cache_fixture()
        with mock.patch.object(experiment, 'system_console_signature', return_value=signature) as trust, \
                mock.patch.object(experiment, 'held_image_diagnostic', return_value=image), \
                mock.patch.object(experiment, 'system_directory', return_value=cache.directory):
            cache.prepare(); cache.before_capture()
            _, handles = experiment.retain_actor_handles(runtime, wrapper, reports, console_trust=cache)
            self.assertEqual(handles, [(42, 201), (43, 202), (44, 203)])
            self.assertEqual(cache.summary()['cache_hits'], 1)
            trust.assert_called_once()
            with self.assertRaisesRegex(RuntimeError, 'canonical system console'):
                cache.verify(cache.directory, {**image, 'image_path': r'C:\untrusted\conhost.exe'})

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

    def executor_build_fixture(self, *, ingress_control=False):
        directory = self.directory / "source-build"
        directory.mkdir()
        executor = directory / "wxc-exec.exe"
        executor.write_bytes(b"fixed source-only executor artifact")
        manifest = directory / "build-manifest.json"
        value = {"schema_version": 1, "status": "built", "upstream_commit": experiment.PSEC_UPSTREAM_COMMIT,
                 "executor_sha256": hashlib.sha256(executor.read_bytes()).hexdigest(),
                 "patch": copy.deepcopy(experiment.PSEC_TEST_INGRESS_PATCH if ingress_control
                                         else experiment.PSEC_TEST_PATCH),
                 "original_file_sha256": experiment.PSEC_ORIGINAL_SOURCE_SHA256,
                 "patch_sha256": (experiment.PSEC_INGRESS_PATCH_SHA256 if ingress_control
                                  else experiment.PSEC_PATCH_SHA256),
                 "patched_file_sha256": (experiment.PSEC_INGRESS_PATCHED_SOURCE_SHA256 if ingress_control
                                         else experiment.PSEC_PATCHED_SOURCE_SHA256),
                 "toolchain": "1.93", "target": "x86_64-pc-windows-msvc"}
        manifest.write_text(json.dumps(value))
        return executor, manifest, value

    def test_g2_executor_manifest_is_selected_only_for_explicit_ingress_diagnostic(self):
        executor, manifest, _ = self.executor_build_fixture(ingress_control=True)
        original_sha = "b" * 64
        selected, facts = experiment.verify_test_executor(self.directory, executor, manifest, original_sha,
                                                           ingress_controls_diagnostic=True)
        self.assertEqual(selected, executor.resolve())
        self.assertEqual(facts["patch"], experiment.PSEC_TEST_INGRESS_PATCH)
        self.assertFalse(facts["patch"]["capabilities_null"])
        self.assertFalse(facts["default_product_runtime_replaced"])
        self.assertFalse(facts["acceptance_passed"])
        with self.assertRaisesRegex(ValueError, "fixed source-only capability experiment"):
            experiment.verify_test_executor(self.directory, executor, manifest, original_sha)

    def test_ingress_diagnostic_rejects_missing_or_conflicting_selectors_before_setup(self):
        invalid_args = (
            ["--ingress-controls-diagnostic"],
            ["--ingress-controls-diagnostic", "--preferred-policy-only", "--psec-1-1-diagnostic",
             "--collect-native-dns"],
        )
        for index, extra in enumerate(invalid_args):
            report = self.directory / f"invalid-ingress-{index}.json"
            with mock.patch.object(experiment, "load_helpers") as setup, \
                    mock.patch.object(experiment, "run_variant") as launch, mock.patch("builtins.print"):
                code = experiment.main(["--root", str(self.directory), "--report", str(report), *extra])
            result = json.loads(report.read_text())
            self.assertEqual(code, 1)
            self.assertIn("ingress-controls-diagnostic requires", result["detail"])
            self.assertFalse(result["acceptance_passed"])
            setup.assert_not_called()
            launch.assert_not_called()

    def test_valid_ingress_diagnostic_runs_only_named_control_with_dns_and_false_acceptance(self):
        code, result, wire, dns, launch, _ = self.native_dns_main_fixture(
            explicit_dns=True, test_executor=True, preferred_only=True, psec_1_1_diagnostic=True,
            ingress_controls_diagnostic=True)
        self.assertEqual(code, 0)
        self.assertEqual(result["selected_variants"], [experiment.PREFERRED_VARIANT])
        self.assertEqual([call.args[0] for call in launch.call_args_list], [experiment.PREFERRED_VARIANT])
        self.assertTrue(launch.call_args.kwargs["ingress_default_allow_control"])
        self.assertEqual([call.args[0] for call in dns.control.call_args_list], ["outside_before", "outside_after"])
        dns.actors.assert_called_once()
        self.assertEqual(result["source_policy_variant"], "private_network_capability_control")
        self.assertEqual(result["ingress_control"], {"default": "allow", "hostLoopback": "deny"})
        self.assertTrue(result["production_policy_unchanged"])
        self.assertTrue(result["variants"][0]["production_policy_unchanged"])
        self.assertEqual(result["variants"][0]["source_policy_variant"], "private_network_capability_control")
        self.assertFalse(result["full_acceptance_passed"])
        self.assertFalse(result["acceptance_passed"])
        self.assertFalse(result["real_node_passed"])
        self.assertEqual(result["test_psec_executor"]["patch"], experiment.PSEC_TEST_INGRESS_PATCH)
        _, probe_policy = wire.runtime._probe_request.call_args.args
        self.assertEqual(probe_policy["network"]["ingress"], {"default": "allow", "hostLoopback": "deny"})
        self.assertEqual(probe_policy["network"]["egress"], experiment.network_policy(
            experiment.PREFERRED_VARIANT, 23456, 23456)["network"]["egress"])

    def test_old_g_manifest_cannot_be_selected_as_ingress_diagnostic(self):
        executor, manifest, _ = self.executor_build_fixture()
        with self.assertRaisesRegex(ValueError, "fixed source-only capability experiment"):
            experiment.verify_test_executor(self.directory, executor, manifest, "b" * 64,
                                            ingress_controls_diagnostic=True)

    def test_source_executor_hash_and_fixed_patch_are_verified_without_replacing_runtime(self):
        executor, manifest, value = self.executor_build_fixture()
        product = self.directory / "bin/windows-amd64/wxc-exec.exe"
        product.parent.mkdir(parents=True)
        product.write_bytes(b"unchanged original product executor")
        original_sha = hashlib.sha256(product.read_bytes()).hexdigest()
        selected, report = experiment.verify_test_executor(self.directory, executor, manifest, original_sha)
        self.assertEqual(selected, executor.resolve())
        self.assertEqual(report["executor_sha256"], value["executor_sha256"])
        self.assertEqual(report["original_runtime_sha256"], original_sha)
        self.assertTrue(report["source_only_executor_changed"])
        self.assertFalse(report["default_product_runtime_replaced"])
        self.assertFalse(report["acceptance_passed"])
        self.assertNotIn(str(executor), json.dumps(report))
        self.assertEqual(hashlib.sha256(product.read_bytes()).hexdigest(), original_sha)
        executor.write_bytes(b"different artifact")
        with self.assertRaisesRegex(ValueError, "SHA-256"):
            experiment.verify_test_executor(self.directory, executor, manifest, original_sha)
        with self.assertRaisesRegex(ValueError, "product runtime directory"):
            experiment.verify_test_executor(self.directory, product, manifest, original_sha)

    def test_test_executor_manifest_rejects_wrong_source_preparation_and_unknown_semantics(self):
        executor, manifest, value = self.executor_build_fixture()
        bad = []
        for key, item in (("schema_version", True), ("status", "prepared_only"),
                          ("upstream_commit", "e" * 40), ("executor_sha256", None),
                          ("target", "aarch64-pc-windows-msvc"), ("toolchain", "stable"),
                          ("toolchain", "1.93.0"), ("original_file_sha256", "a" * 64),
                          ("patch_sha256", "c" * 64), ("patched_file_sha256", "d" * 64),
                          ("untrusted_extra", "ignored")):
            bad.append(dict(value, **{key: item}))
        for key in ("original_file_sha256", "patch_sha256", "patched_file_sha256", "toolchain", "target"):
            bad.append({name: item for name, item in value.items() if name != key})
        bad.append(dict(value, patch=dict(value["patch"], capabilities_null=1)))
        bad.append(dict(value, patch=dict(value["patch"], network_table_unchanged=False)))
        for index, record in enumerate(bad):
            manifest.write_text(json.dumps(record))
            with self.subTest(index=index), self.assertRaises(ValueError):
                experiment.verify_test_executor(self.directory, executor, manifest, "b" * 64)
        manifest.write_text(json.dumps(value)[:-1] + ',"status":"built"}')
        with self.assertRaisesRegex(ValueError, "Duplicate"):
            experiment.verify_test_executor(self.directory, executor, manifest, "b" * 64)
        manifest.write_bytes(b"x" * (experiment.MAX_REPORT_BYTES + 1))
        with self.assertRaisesRegex(ValueError, "size limit"):
            experiment.verify_test_executor(self.directory, executor, manifest, "b" * 64)

    def test_test_executor_requires_absolute_files_and_rejects_file_or_parent_aliases(self):
        executor, manifest, value = self.executor_build_fixture()
        with self.assertRaisesRegex(ValueError, "absolute"):
            experiment.verify_test_executor(self.directory, Path("wxc-exec.exe"), manifest, "b" * 64)
        if experiment.os.name == "posix":
            alias = self.directory / "executor-alias.exe"
            alias.symlink_to(executor)
            with self.assertRaisesRegex(ValueError, "reparse"):
                experiment.verify_test_executor(self.directory, alias, manifest, "b" * 64)
            folder_alias = self.directory / "source-alias"
            folder_alias.symlink_to(executor.parent, target_is_directory=True)
            with self.assertRaisesRegex(ValueError, "reparse"):
                experiment.verify_test_executor(self.directory, folder_alias / executor.name, manifest, "b" * 64)

    def test_unpaired_test_executor_flags_cannot_start_any_variant(self):
        report = self.directory / "unpaired.json"
        for flag in ("--test-psec-executor", "--test-psec-manifest"):
            with mock.patch.object(experiment, "load_helpers"), \
                    mock.patch.object(experiment, "run_variant") as launch, mock.patch("builtins.print"):
                code = experiment.main(["--root", str(self.directory), "--report", str(report),
                                        flag, str(self.directory / "input")])
            result = json.loads(report.read_text())
            self.assertEqual(code, 1)
            launch.assert_not_called()
            self.assertEqual(result["status"], "failed")
            self.assertFalse(result["acceptance_passed"])

    def test_singleton_range_rejects_custom_executor_before_setup_or_launch(self):
        executor, manifest, _ = self.executor_build_fixture()
        report = self.directory / "singleton-custom-executor.json"
        with mock.patch.object(experiment, "load_helpers") as setup, \
                mock.patch.object(experiment, "run_variant") as launch, mock.patch("builtins.print"):
            code = experiment.main(["--root", str(self.directory), "--report", str(report),
                                    "--singleton-port-range", "--test-psec-executor", str(executor),
                                    "--test-psec-manifest", str(manifest)])
        result = json.loads(report.read_text())
        self.assertEqual(code, 1)
        self.assertEqual(result["diagnostic_port_encoding"], "singleton_range")
        self.assertFalse(result["acceptance_passed"])
        self.assertIn("custom test executor", result["detail"])
        setup.assert_not_called()
        launch.assert_not_called()

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

    def native_dns_main_fixture(self, *, fail_control=False, fail_actor=False, arm=False,
                                explicit_dns=False, wire_enabled=True, test_executor=False, preferred_only=False,
                                singleton_port_range=False, trust_contaminated=False, warmup_failure=False, trust_close_failure=False,
                                dns_payload=None, candidate_probe_failure=False, psec_1_1_diagnostic=False,
                                enumerate_paths_supported=True, ingress_controls_diagnostic=False):
        helpers = mock.Mock()
        helpers.verify_runtime_manifest.return_value = {"fixed-runtime": "verified"}
        helpers.host_facts.return_value = {"native_machine": 0x8664, "python_pe_machine": 0x8664,
                                          "acceptance_scope": "native_x64", "platform": "win32",
                                          "windows_build": 26200, "windows_product_type": 1}
        if arm:
            helpers.host_facts.return_value.update(native_machine=0xAA64, acceptance_scope="x64_on_arm_emulation")
        helpers.network_snapshot.return_value = "unchanged"
        helpers.HostFixtures.return_value = mock.Mock(threads=[])
        wire = mock.Mock()
        wire.execution = []
        wire.for_variant.side_effect = lambda name: [
            {"id": f"{name}.{family}.{role}", "role": role}
            for family in ("ipv4", "ipv4_unbound", "ipv6", "ipv6_unbound")
            for role in ("outside_before", "parent", "child", "outside_after")]
        def wire_session(_configuration, variants):
            wire.requested_variants = tuple(variants)
            return wire
        wire.finish.return_value = {"acceptance_passed": False, "kernel_denial_proven": False}
        trust = mock.Mock(contaminated=trust_contaminated)
        trust.summary.return_value = {"scope": "system_console_signature_pre_capture", "signature_prevalidated": True,
            "warmup_completed_before_capture_request": True, "cache_hits": 0, "inside_capture_revalidations": 0,
            "capture_contaminated": trust_contaminated, "cleanup_proven": not trust_close_failure, "acceptance_passed": False}
        wire.console_trust = trust
        wire.sequence = []
        trust.prepare.side_effect = lambda: wire.sequence.append('signature_prepare')
        if warmup_failure:
            trust.prepare.side_effect = RuntimeError('public fixture warmup failed')
        trust.before_capture.side_effect = lambda: wire.sequence.append('before_capture')
        wire.start.side_effect = lambda: wire.sequence.append('capture_start')
        wire.finish.side_effect = lambda: (wire.sequence.append('capture_finish') or
            {"acceptance_passed": False, "kernel_denial_proven": False})
        trust.close.side_effect = lambda: wire.sequence.append('signature_file_close')
        if trust_close_failure:
            trust.close.side_effect = RuntimeError('public fixture handle close failed')
        dns = mock.Mock(safe=True, controls=[])
        dns.control.return_value = {"calls": [], "cleanup_proven": True}
        dns.finish_payload.return_value = (dns_payload if dns_payload is not None else
            {"manifest": "private-fixed-manifest", "execution": [], "actor_execution_attested": False})
        dns.close.return_value = None
        runtime = mock.Mock()
        runtime.choose_guest_port.return_value = 23456
        runtime.build_policy.side_effect = lambda _command, _capabilities, profile, _port: {
            "filesystem": {"readwritePaths": [str(profile)], "readonlyPaths": []},
            "network": {"egress": {"default": "deny"},
                        "ingress": {"default": "deny", "hostLoopback": "deny"}}}
        runtime._probe_request.side_effect = (RuntimeError("private candidate path") if candidate_probe_failure else
            lambda executor, policy: (wire.sequence.append("candidate_probe") or {
                "tier": "base-container", "probes": {"baseContainerApiPresent": True,
                    "baseContainerSupportsEnumeratePaths": enumerate_paths_supported},
                "needsDaclAugmentation": False}))
        wire.runtime = runtime
        retained = self.directory / "private-work"
        retained.mkdir()
        self.addCleanup(shutil.rmtree, retained, True)
        if fail_control:
            dns.control.return_value = {"cleanup_proven": False, "cleanup_error": "NativeWorkerAlive",
                                       "recovery_directory": str(retained)}

        def variant(name, *_args, **kwargs):
            wire.sequence.append("actor_start")
            result = {"name": name, "status": "observed", "process_started": True,
                      "descendant_cleanup_proven": True, "resources_closed": True}
            if name == "model1_internal_ingress_deny" and fail_actor:
                result["actors"] = [{"scope": "parent", "native_dns": {"cleanup_proven": False,
                    "cleanup_error": "NativeWorkerAlive", "recovery_directory": str(retained)}}]
            return result

        original_executor_verifier = experiment.verify_test_executor
        def verify_executor(*args, **kwargs):
            value = original_executor_verifier(*args, **kwargs)
            wire.sequence.append("candidate_verified")
            return value

        report = self.directory / "native-report.json"
        with mock.patch.object(experiment, "load_helpers", return_value=helpers), \
                mock.patch.object(experiment, "verify_test_executor", side_effect=verify_executor), \
                mock.patch.object(experiment, "import_project", return_value=(runtime, None, None)), \
                mock.patch.object(experiment, "DatagramObservers"), \
                mock.patch.object(experiment.tempfile, "mkdtemp", return_value=str(retained)), \
                mock.patch.object(experiment, "load_wire_helpers", return_value=SimpleNamespace(WireSession=wire_session)), \
                mock.patch.object(experiment, "load_dns_session", return_value=SimpleNamespace(DnsSession=lambda *args: dns)), \
                mock.patch.object(experiment, "SystemConsoleTrustCache", return_value=trust), \
                mock.patch.object(experiment, "run_variant", side_effect=variant) as launch, \
                mock.patch("builtins.print"):
            arguments = ["--root", str(self.directory), "--report", str(report),
                         *(["--vm-config", str(self.directory / "private-config.json")] if wire_enabled else [])]
            if arm:
                arguments.append("--allow-emulated-x64")
            if explicit_dns:
                arguments.append("--collect-native-dns")
            if preferred_only:
                arguments.append("--preferred-policy-only")
            if singleton_port_range:
                arguments.append("--singleton-port-range")
            if psec_1_1_diagnostic:
                arguments.append("--psec-1-1-diagnostic")
            if ingress_controls_diagnostic:
                arguments.append("--ingress-controls-diagnostic")
            if test_executor:
                executor, manifest, _ = self.executor_build_fixture(ingress_control=ingress_controls_diagnostic)
                helpers.verify_runtime_manifest.return_value = {"wxc-exec.exe": "b" * 64}
                arguments.extend(["--test-psec-executor", str(executor), "--test-psec-manifest", str(manifest)])
            code = experiment.main(arguments)
        return code, json.loads(report.read_text()), wire, dns, launch, retained

    def test_main_prevalidates_signature_before_capture_and_closes_binding_after_finish(self):
        code, result, wire, _, launch, _ = self.native_dns_main_fixture(preferred_only=True)
        self.assertEqual(code, 0)
        self.assertEqual(wire.sequence, ['signature_prepare', 'before_capture', 'capture_start',
                                         'actor_start', 'capture_finish', 'signature_file_close'])
        self.assertTrue(result['system_console_signature_preflight']['warmup_completed_before_capture_request'])
        self.assertTrue(result['system_console_signature_preflight']['cleanup_proven'])
        self.assertIs(launch.call_args.kwargs['console_trust'], wire.console_trust)

    def test_main_passes_singleton_range_only_as_diagnostic_encoding(self):
        code, result, _, _, launch, _ = self.native_dns_main_fixture(preferred_only=True,
                                                                      singleton_port_range=True)
        self.assertEqual(code, 0)
        self.assertEqual(result["diagnostic_port_encoding"], "singleton_range")
        self.assertFalse(result["acceptance_passed"])
        self.assertTrue(launch.call_args.kwargs["singleton_port_range"])

    def test_psec_1_1_preferred_only_selects_model3_and_preferred_with_no_acceptance_claim(self):
        code, result, wire, dns, launch, _ = self.native_dns_main_fixture(
            preferred_only=True, psec_1_1_diagnostic=True)
        self.assertEqual(code, 0)
        self.assertEqual(result["selected_variants"], ["model3", experiment.PREFERRED_VARIANT])
        self.assertEqual([call.args[0] for call in launch.call_args_list], result["selected_variants"])
        self.assertTrue(all(call.kwargs["psec_1_1_diagnostic"] for call in launch.call_args_list))
        self.assertEqual(["dns" in call.kwargs for call in launch.call_args_list], [False, True])
        self.assertEqual(wire.requested_variants, experiment.VARIANTS)
        self.assertTrue(result["psec_1_1_diagnostic_requested"])
        self.assertFalse(result["psec_1_1_kernel_contract_confirmed"])
        self.assertFalse(result["acceptance_passed"])
        self.assertFalse(result["full_acceptance_passed"])

    def test_psec_1_1_candidate_prewarm_requests_feature_before_capture(self):
        code, result, wire, _, launch, _ = self.native_dns_main_fixture(
            preferred_only=True, test_executor=True, psec_1_1_diagnostic=True)
        self.assertEqual(code, 0)
        warmup = result["candidate_precapture_probe"]
        self.assertTrue(warmup["psec_1_1_diagnostic_requested"])
        self.assertTrue(warmup["feature_supported"])
        self.assertFalse(warmup["kernel_contract_version_confirmed"])
        self.assertLess(wire.sequence.index("candidate_probe"), wire.sequence.index("capture_start"))
        _, policy = wire.runtime._probe_request.call_args.args
        path = Path(policy["processContainer"]["filesystem"]["enumeratePaths"][0])
        self.assertEqual(path.parent.name, "candidate-prewarm")
        self.assertFalse(path.exists())  # The private prewarm tree was cleaned after capture teardown.
        self.assertEqual(policy["network"], experiment.network_policy(
            experiment.PREFERRED_VARIANT, 23456, 23456)["network"])
        self.assertEqual(launch.call_count, 2)

    def test_psec_1_1_candidate_feature_false_blocks_capture_and_actors(self):
        code, result, wire, _, launch, _ = self.native_dns_main_fixture(
            preferred_only=True, test_executor=True, psec_1_1_diagnostic=True,
            enumerate_paths_supported=False)
        self.assertEqual(code, 1)
        self.assertEqual(result["candidate_precapture_probe"]["status"], "failed")
        self.assertFalse(result["candidate_precapture_probe"]["acceptance_passed"])
        self.assertFalse(result["candidate_precapture_probe"].get("feature_supported", False))
        wire.start.assert_not_called()
        launch.assert_not_called()

    def test_failed_trust_preparation_starts_neither_capture_nor_actor_and_closes_owned_cache(self):
        code, result, wire, _, launch, _ = self.native_dns_main_fixture(warmup_failure=True)
        self.assertEqual(code, 1)
        self.assertEqual(result['status'], 'failed')
        wire.start.assert_not_called()
        wire.finish.assert_not_called()
        launch.assert_not_called()
        wire.console_trust.close.assert_called_once()

    def test_changed_console_binding_revokes_wire_attestation_and_fails_collection(self):
        code, result, wire, _, _, _ = self.native_dns_main_fixture(trust_contaminated=True)
        self.assertEqual(code, 1)
        self.assertEqual(result['status'], 'failed')
        self.assertIs(wire.attested, False)
        self.assertTrue(result['system_console_signature_preflight']['capture_contaminated'])

    def test_contaminated_console_binding_revokes_already_attested_dns_but_preserves_observation_rows(self):
        # Use the real session/finish contract, without invoking any OS resolver.
        session = experiment.load_dns_session().DnsSession(self.directory / "dns-contract", time.monotonic() + 100)
        session.attested = True
        session.execution = [{"id": probe["id"], "role": probe["role"], "api": probe["api"],
                              "api_returned": True, "observed_call_count": 1}
                             for probe in session.manifest["probes"]]
        original = session.finish_payload()
        self.assertTrue(original["actor_execution_attested"])
        self.assertEqual(len(original["execution"]), 12)
        code, result, wire, _, _, _ = self.native_dns_main_fixture(trust_contaminated=True, dns_payload=original)
        self.assertEqual(code, 1)
        self.assertEqual(result["status"], "failed")
        self.assertIs(wire.attested, False)
        self.assertIs(wire.dns_observation["actor_execution_attested"], False)
        self.assertIs(wire.dns_observation["manifest"], original["manifest"])
        self.assertIs(wire.dns_observation["execution"], original["execution"])
        self.assertEqual(sum(row["observed_call_count"] for row in wire.dns_observation["execution"]), 12)
        self.assertTrue(original["actor_execution_attested"])  # Historical session data was not rewritten.

    def test_console_trust_handle_close_error_retains_recovery_and_cannot_report_success(self):
        code, result, wire, _, _, retained = self.native_dns_main_fixture(trust_close_failure=True)
        self.assertEqual(code, 1)
        self.assertEqual(result['status'], 'failed')
        self.assertFalse(result['cleanup_proven'])
        self.assertFalse(result['system_console_signature_preflight']['cleanup_proven'])
        self.assertEqual(result['cleanup_error'], 'SystemConsoleTrustHandleCloseFailed')
        self.assertTrue(retained.exists())
        wire.finish.assert_called_once()

    def test_native_dns_only_couples_to_preferred_variant_and_finish_payload_stays_separate(self):
        code, result, wire, dns, launch, _ = self.native_dns_main_fixture()
        self.assertEqual(code, 0)
        self.assertEqual(launch.call_count, 4)
        self.assertEqual([call.args[0] for call in dns.control.call_args_list], ["outside_before", "outside_after"])
        for call in launch.call_args_list:
            self.assertEqual("dns" in call.kwargs, call.args[0] == "model1_internal_ingress_deny")
        wire.start.assert_called_once()
        wire.finish.assert_called_once()
        self.assertEqual(wire.dns_observation, dns.finish_payload.return_value)
        self.assertTrue(result["cleanup_proven"])
        self.assertFalse(result["acceptance_passed"])
        self.assertEqual(result["policy_selection"], "all_fixed")
        self.assertEqual(result["selected_variants"], list(experiment.VARIANTS))
        self.assertEqual(result["unselected_variants"], [])
        self.assertEqual(wire.execution, [])

    def test_preferred_only_never_launches_unselected_policies_and_preserves_full_wire_manifest(self):
        code, result, wire, dns, launch, _ = self.native_dns_main_fixture(preferred_only=True)
        preferred = experiment.PREFERRED_VARIANT
        self.assertEqual(code, 0)
        self.assertEqual(result["status"], "experiment_only")
        self.assertEqual([call.args[0] for call in launch.call_args_list], [preferred])
        self.assertEqual(wire.requested_variants, experiment.VARIANTS)
        self.assertEqual(result["policy_selection"], "preferred_only")
        self.assertEqual(result["selected_variants"], [preferred])
        self.assertEqual(result["unselected_variants"], [{"name": name, "status": "unselected",
            "process_started": False, "no_process_started": True}
            for name in experiment.VARIANTS if name != preferred])
        self.assertEqual(wire.control.call_args_list,
                         [mock.call(preferred, "outside_before"), mock.call(preferred, "outside_after")])
        self.assertEqual(dns.control.call_args_list,
                         [mock.call("outside_before", mock.ANY), mock.call("outside_after", mock.ANY)])
        self.assertEqual(len(wire.execution), 48)
        self.assertEqual(len({row["id"] for row in wire.execution}), 48)
        self.assertTrue(all(not row[key] for row in wire.execution for key in
            ("attempted", "bind_attempted", "bind_succeeded", "send_attempted", "api_accepted")))
        self.assertTrue(all(not row["id"].startswith(preferred + ".") for row in wire.execution))
        self.assertTrue(result["cleanup_proven"])
        self.assertFalse(result["acceptance_passed"])

    def test_preferred_only_cleanup_failure_still_prevents_launch_or_after_controls(self):
        for fail_control in (True, False):
            with self.subTest(fail_control=fail_control):
                code, result, wire, dns, launch, retained = self.native_dns_main_fixture(
                    preferred_only=True, fail_control=fail_control, fail_actor=not fail_control)
                self.assertEqual(code, 1)
                self.assertEqual(launch.call_count, 0 if fail_control else 1)
                self.assertEqual(dns.control.call_count, 1)
                self.assertEqual(wire.control.call_args_list,
                                 [mock.call(experiment.PREFERRED_VARIANT, "outside_before")])
                wire.finish.assert_called_once()
                self.assertFalse(result["cleanup_proven"])
                self.assertTrue(retained.exists())
                # The next subcase uses a new owned private work directory.
                shutil.rmtree(retained)

    def test_dns_control_cleanup_failure_blocks_preferred_and_all_next_contained_launches(self):
        code, result, wire, dns, launch, retained = self.native_dns_main_fixture(fail_control=True)
        self.assertEqual(code, 1)
        self.assertEqual([call.args[0] for call in launch.call_args_list], ["model3"])
        self.assertEqual(dns.control.call_count, 1)
        wire.finish.assert_called_once()
        self.assertFalse(result["cleanup_proven"])
        self.assertTrue(retained.exists())

    def test_actor_dns_recovery_prevents_after_query_and_new_policy_but_capture_finishes(self):
        code, result, wire, dns, launch, retained = self.native_dns_main_fixture(fail_actor=True)
        self.assertEqual(code, 1)
        self.assertEqual([call.args[0] for call in launch.call_args_list], ["model3", "model1_internal_ingress_deny"])
        self.assertEqual(dns.control.call_count, 1)
        self.assertNotIn(mock.call("model1_internal_ingress_deny", "outside_after"), wire.control.call_args_list)
        wire.finish.assert_called_once()
        self.assertFalse(result["cleanup_proven"])
        self.assertTrue(retained.exists())

    def test_arm_experiments_keep_their_existing_scope_without_native_dns_queries(self):
        code, result, wire, dns, launch, _ = self.native_dns_main_fixture(arm=True)
        self.assertEqual(code, 0)
        self.assertEqual(launch.call_count, 4)
        dns.control.assert_not_called()
        dns.close.assert_not_called()
        self.assertTrue(all("dns" not in call.kwargs for call in launch.call_args_list))
        self.assertNotIn("native_dns_controls", result)
        self.assertNotIn("dns_observation", wire.__dict__)

    def test_explicit_arm_native_dns_collects_controls_and_contained_calls_without_wire_claims(self):
        code, result, wire, dns, launch, _ = self.native_dns_main_fixture(arm=True, explicit_dns=True, wire_enabled=False)
        self.assertEqual(code, 0)
        self.assertEqual(launch.call_count, 4)
        self.assertEqual([call.args[0] for call in dns.control.call_args_list], ["outside_before", "outside_after"])
        dns.actors.assert_called_once()
        dns.close.assert_called_once()
        wire.start.assert_not_called()
        wire.finish.assert_not_called()
        self.assertEqual(result["host"]["acceptance_scope"], "x64_on_arm_emulation")
        self.assertFalse(result["native_dns_scope"]["wire_observed"])
        self.assertFalse(result["native_dns_scope"]["wire_capture_available"])
        self.assertFalse(result["acceptance_passed"])
        self.assertFalse(result["real_node_passed"])
        self.assertTrue(all(("dns" in call.kwargs) == (call.args[0] == "model1_internal_ingress_deny")
                            for call in launch.call_args_list))

    def test_test_executor_is_only_an_explicit_source_choice_after_original_integrity_check(self):
        code, result, wire, dns, launch, _ = self.native_dns_main_fixture(test_executor=True)
        self.assertEqual(code, 0)
        for call in launch.call_args_list:
            self.assertEqual(call.kwargs["executor"], (self.directory / "source-build/wxc-exec.exe").resolve(strict=True))
        self.assertEqual(result["runtime_integrity"]["verified_file_count"], 1)
        self.assertEqual(result["test_psec_executor"]["original_runtime_sha256"], "b" * 64)
        self.assertEqual(result["test_psec_executor"]["patch"], experiment.PSEC_TEST_PATCH)
        warmup = result["candidate_precapture_probe"]
        self.assertEqual(warmup["status"], "probe_passed")
        self.assertEqual(warmup["scope"], "source_only_strict_policy_probe")
        self.assertTrue(warmup["warmup_before_capture"])
        self.assertEqual(warmup["executor_sha256"], result["test_psec_executor"]["executor_sha256"])
        self.assertEqual(warmup["backend_confirmation"], {"tier": "base-container",
            "base_container_api_present": True, "needs_dacl_augmentation": False})
        self.assertFalse(warmup["acceptance_passed"])
        self.assertLess(wire.sequence.index("candidate_verified"), wire.sequence.index("candidate_probe"))
        self.assertLess(wire.sequence.index("candidate_probe"), wire.sequence.index("capture_start"))
        self.assertLess(wire.sequence.index("capture_start"), wire.sequence.index("actor_start"))
        wire.runtime._probe_request.assert_called_once()
        called_executor, called_policy = wire.runtime._probe_request.call_args.args
        self.assertEqual(called_executor, str((self.directory / "source-build/wxc-exec.exe").resolve()))
        self.assertEqual(called_policy["network"], {"egress": {"default": "deny", "allow": [
            {"to": [{"cidr": "127.0.0.1/32"}], "ports": [{"protocol": "tcp", "port": 23456}]}]},
            "ingress": {"default": "deny", "hostLoopback": "deny"}})
        self.assertFalse(result["product_provider_changed"])
        self.assertFalse(result["full_acceptance_passed"])

    def test_candidate_precapture_probe_failure_blocks_capture_and_all_variants(self):
        code, result, wire, dns, launch, _ = self.native_dns_main_fixture(
            test_executor=True, candidate_probe_failure=True)
        self.assertEqual(code, 1)
        self.assertEqual(result["status"], "failed")
        self.assertEqual(result["candidate_precapture_probe"]["status"], "failed")
        self.assertTrue(result["candidate_precapture_probe"]["warmup_before_capture"])
        self.assertFalse(result["candidate_precapture_probe"]["acceptance_passed"])
        self.assertNotIn("private candidate path", json.dumps(result))
        self.assertNotIn("candidate_probe", wire.sequence)
        wire.start.assert_not_called()
        wire.finish.assert_not_called()
        dns.control.assert_not_called()
        launch.assert_not_called()

    def test_stock_executor_path_does_not_add_candidate_prewarm(self):
        code, result, wire, _, _, _ = self.native_dns_main_fixture(preferred_only=True)
        self.assertEqual(code, 0)
        self.assertNotIn("candidate_precapture_probe", result)
        self.assertNotIn("candidate_probe", wire.sequence)
        wire.runtime._probe_request.assert_not_called()

    def test_actor_native_dns_collects_directly_in_its_owned_role_directory(self):
        guest = mock.Mock()
        guest._run_network_probes.return_value = {"scope": "parent", "pid": 1234, "checks": {}}
        guest._probe.return_value = {"ok": True, "code": None}
        runtime = mock.Mock(wintypes=SimpleNamespace(HANDLE=int))
        runtime._raw_handle.return_value = 101
        runtime._WinProcessApi.return_value.process_creation_time.return_value = 123456
        native = mock.Mock()
        observation = {"status": "incomplete", "calls": [], "cleanup_proven": True,
                       "acceptance_passed": False, "dns_blocked_proven": False}
        native.collect_calls.return_value = observation
        config = {"root": str(self.directory), "endpoint_port": 12345,
                  "host_tcp_ports": [23456, 34567], "host_udp_ports": [45678, 56789], "token": "fixed",
                  "native_dns": {"session_script": str(self.directory / "session.py"),
                                 "directory": str(self.directory / "role-workers"), "deadline": 1000,
                                 "nonce": "a" * 32, "script": "fixed-native.py"}}
        with mock.patch.object(experiment, "import_project", return_value=(runtime, guest, None)), \
                mock.patch.object(experiment, "load_wire_helpers", return_value=native), \
                mock.patch.object(experiment.subprocess, "run") as outer_timeout:
            result = experiment.collect_actor_checks(config, "parent")
        native.collect_calls.assert_called_once_with(config["native_dns"], "parent",
            self.directory / "role-workers/parent", 1000)
        outer_timeout.assert_not_called()
        self.assertEqual(result["native_dns"], observation)
        self.assertEqual(experiment.ACTOR_WAIT_SECONDS, 45)
        self.assertEqual(experiment.MATRIX_PHASE_SECONDS, 440)


if __name__ == "__main__":
    unittest.main()
