"""Exercise budgeting/record ownership without claiming native DNS behavior."""
import importlib.util
from pathlib import Path
import tempfile
import time
from types import SimpleNamespace
import unittest
from unittest import mock

ROOT = Path(__file__).resolve().parent.parent
spec = importlib.util.spec_from_file_location("ruleproxy_dns_session_tests", ROOT / ".github/windows_dns_session.py")
session = importlib.util.module_from_spec(spec)
spec.loader.exec_module(session)
native_spec = importlib.util.spec_from_file_location("ruleproxy_session_native_fixture", ROOT / ".github/windows_native_dns_probe.py")
native = importlib.util.module_from_spec(native_spec)
native_spec.loader.exec_module(native)


class WindowsDnsSessionTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.directory = Path(self.temp.name)
        self.calls = []

        def collect(nonce, role, api, directory, identity):
            self.calls.append((role, api, directory))
            directory.mkdir()
            return {"api": api, "qname": native.qname(nonce, role, api), "requested_role": role,
                "outcome": "returned", "api_returned": True, "native_completion_proven": True,
                "entry_lease_published": True, "worker_cleanup_proven": True,
                "pid": 100, "ppid": 90, "process_created": 123456,
                "worker_exit_verified": True, "worker_handle_closed": True,
                "default_system_server_list": True, "server_list_override": False,
                "acceptance_passed": False, "dns_blocked_proven": False}

        self.native = SimpleNamespace(STARTUP_SECONDS=5, CALL_SECONDS=4, qname=native.qname,
                                      ProcessIdentity=mock.Mock(), collect_call=mock.Mock(side_effect=collect),
                                      error_facts=native.error_facts)
        patch = mock.patch.object(session, "load_native", return_value=self.native)
        patch.start(); self.addCleanup(patch.stop)
        self.value = session.DnsSession(self.directory / "ordinary", time.monotonic() + 200)

    def test_manifest_and_original_records_use_one_nonce_and_exact_preferred_api_roles(self):
        self.value.control("outside_before")
        config = self.value.actor_config(self.directory / "actor")
        actors = []
        for role in ("parent", "child"):
            observed = session.collect_calls(config, role, Path(config["directory"]) / role, time.monotonic() + 40)
            actors.append({"scope": role, "native_dns": observed})
        self.value.actors({"name": session.PREFERRED, "process_started": True,
            "actor_attestation": {"attestation_passed": True}, "actors": actors})
        self.value.control("outside_after")
        value = self.value.finish_payload()
        self.assertEqual(len(value["manifest"]["probes"]), 12)
        self.assertEqual(len(value["execution"]), 12)
        self.assertTrue(value["actor_execution_attested"])
        self.assertEqual({row["id"] for row in value["execution"]}, {p["id"] for p in value["manifest"]["probes"]})
        self.assertTrue(all(row["attempted"] and row["worker_cleanup_proven"] for row in value["execution"]))
        self.assertTrue(all(not row["acceptance_passed"] and not row["dns_blocked_proven"] for row in value["execution"]))
        self.assertEqual({p["qname"].split(".")[0] for p in value["manifest"]["probes"]}, {self.value.config["nonce"]})
        self.assertTrue(all("query_type" not in p for p in value["manifest"]["probes"] if p["api"] == "getaddrinfo"))
        self.value.close()
        self.assertFalse(self.value.directory.exists())

    def test_less_than_full_worker_bound_starts_no_native_controller_or_worker(self):
        result = session.collect_calls(self.value.config, "parent", self.directory / "unused", time.monotonic() + 11)
        self.native.ProcessIdentity.assert_not_called()
        self.native.collect_call.assert_not_called()
        self.assertEqual(len(result["calls"]), 3)
        self.assertTrue(result["cleanup_proven"])
        self.assertTrue(all(row["outcome"] == "budget_incomplete" and not row["entry_lease_published"] for row in result["calls"]))
        self.assertFalse((self.directory / "unused").exists())

    def test_remaining_budget_is_checked_between_each_call(self):
        ticks = iter((100, 110, 120))
        with mock.patch.object(session.time, "monotonic", side_effect=lambda: next(ticks)):
            result = session.collect_calls(self.value.config, "parent", self.directory / "actor", 125)
        self.assertEqual(self.native.collect_call.call_count, 2)
        self.assertEqual(result["calls"][-1]["outcome"], "budget_incomplete")
        self.assertEqual(result["status"], "incomplete")

    def test_native_worker_cleanup_failure_stops_queries_and_preserves_recovery(self):
        self.native.collect_call.side_effect = lambda nonce, role, api, directory, identity: {
            "api": api, "qname": native.qname(nonce, role, api), "requested_role": role,
            "worker_cleanup_proven": False, "cleanup_error": "HeldWorkerAlive", "recovery_directory": str(directory),
            "cleanup_error_stage": "verify_worker_exit", "cleanup_errno": None, "cleanup_winerror": 5}
        observation = self.value.control("outside_before")
        self.assertFalse(observation["cleanup_proven"])
        self.assertEqual(self.native.collect_call.call_count, 1)
        self.value.control("outside_after")
        self.assertEqual(self.native.collect_call.call_count, 1)
        self.assertFalse(self.value.safe)
        self.assertEqual(self.value.recovery["cleanup_error_stage"], "verify_worker_exit")
        self.assertEqual(self.value.recovery["cleanup_winerror"], 5)
        self.value.directory.mkdir(exist_ok=True)
        self.assertIsNotNone(self.value.close())
        self.assertTrue(self.value.directory.exists())

    def test_controller_exception_cannot_be_misreported_as_safe_worker_exit(self):
        self.native.collect_call.side_effect = RuntimeError("do not serialize private paths")
        result = session.collect_calls(self.value.config, "parent", self.directory / "actor", time.monotonic() + 40)
        self.assertFalse(result["cleanup_proven"])
        self.assertEqual(result["cleanup_error"], "RuntimeError")
        self.assertEqual(result["cleanup_error_stage"], "collect_native_call")
        self.assertIsNone(result["cleanup_errno"])
        self.assertIsNone(result["cleanup_winerror"])
        self.assertNotIn("do not serialize", str(result))
        self.assertEqual(self.native.collect_call.call_count, 1)

    def test_prepare_directory_error_stage_survives_session_boundary_and_stops_queries(self):
        error = PermissionError(13, "private command credential", "private-path")
        error.winerror = 5
        native.annotate_stage(error, "prepare_worker_directory")
        self.native.collect_call.side_effect = error
        observation = self.value.control("outside_before")
        self.assertFalse(observation["cleanup_proven"])
        self.assertEqual(observation["cleanup_error_stage"], "prepare_worker_directory")
        self.assertEqual((observation["cleanup_errno"], observation["cleanup_winerror"]), (13, 5))
        self.value.control("outside_after")
        self.assertEqual(self.native.collect_call.call_count, 1)
        self.assertFalse(self.value.safe)
        for private in ("private command", "credential", "private-path"):
            self.assertNotIn(private, str(observation))

    def test_session_directory_cleanup_failure_records_only_stage_and_error_codes(self):
        self.value.directory.mkdir()
        error = PermissionError(13, "private command credential", "private-path")
        error.winerror = 5
        with mock.patch.object(session.shutil, "rmtree", side_effect=error):
            recovery = self.value.close()
        self.assertFalse(recovery["cleanup_proven"])
        self.assertEqual(recovery["cleanup_error_stage"], "cleanup_session_directory")
        self.assertEqual((recovery["cleanup_errno"], recovery["cleanup_winerror"]), (13, 5))
        self.assertTrue(self.value.directory.exists())
        self.assertFalse(self.value.safe)
        self.assertNotIn("private-path", str(recovery))

    def test_deadline_is_an_incomplete_observation_not_kernel_denial(self):
        self.native.collect_call.side_effect = lambda nonce, role, api, directory, identity: {
            "api": api, "qname": native.qname(nonce, role, api), "requested_role": role,
            "outcome": "deadline", "api_returned": False, "native_completion_proven": False,
            "worker_cleanup_proven": True, "entry_lease_published": True}
        result = session.collect_calls(self.value.config, "child", self.directory / "actor", time.monotonic() + 40)
        self.assertEqual(result["status"], "incomplete")
        self.assertTrue(result["cleanup_proven"])
        self.assertFalse(result["dns_blocked_proven"])
        self.assertFalse(result["acceptance_passed"])

    def test_unsupported_or_unattested_preferred_policy_cannot_invent_actor_execution(self):
        self.value.actors({"name": session.PREFERRED, "process_started": False, "status": "unsupported"})
        self.assertFalse(self.value.attested)
        self.assertEqual(self.value.execution, [])
        self.value.actors({"name": session.PREFERRED, "process_started": True, "actor_attestation": {"attestation_passed": False}})
        self.assertFalse(self.value.finish_payload()["actor_execution_attested"])


if __name__ == "__main__":
    unittest.main()
