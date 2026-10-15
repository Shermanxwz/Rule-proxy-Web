"""Exercise native resolver contracts and worker ownership; no Windows claim."""
import ctypes
import importlib.util
import json
import os
from pathlib import Path
import subprocess
import secrets
import tempfile
import time
from types import SimpleNamespace
import unittest
from unittest import mock

ROOT = Path(__file__).resolve().parent.parent
spec = importlib.util.spec_from_file_location("native_dns_probe", ROOT / ".github/windows_native_dns_probe.py")
probe = importlib.util.module_from_spec(spec)
spec.loader.exec_module(probe)


class NativeDnsProbeTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        self.nonce = "a" * 32

    def test_qnames_are_unique_fixed_fully_qualified_non_invalid_test_names(self):
        names = {probe.qname(self.nonce, role, api) for role in probe.ROLES for api in probe.APIS}
        self.assertEqual(len(names), 12)
        for value in names:
            self.assertTrue(value.endswith(".ruleproxy-ci.example.com."))
            self.assertNotIn("invalid", value)
        for bad in ("user credential", "b" * 31, "C" * 32, "b" * 33, None):
            with self.assertRaises(ValueError):
                probe.qname(bad, "parent", "getaddrinfo")

    def test_dns_request_layout_matches_x64_windows_header_and_uses_default_server(self):
        if ctypes.sizeof(ctypes.c_void_p) == 8:
            self.assertEqual(ctypes.sizeof(probe.DnsQueryRequest), 64)
            self.assertEqual(ctypes.sizeof(probe.DnsQueryResult), 32)
            self.assertEqual(probe.DnsQueryRequest.QueryOptions.offset, 24)
            self.assertEqual(probe.DnsQueryRequest.pDnsServerList.offset, 32)
        resolver = object.__new__(probe.NativeResolver)
        resolver.dns = mock.Mock()

        def query(request, result, cancel):
            self.assertIsNone(request._obj.pDnsServerList)
            self.assertEqual(request._obj.InterfaceIndex, 0)
            self.assertEqual(request._obj.QueryOptions, 0x108)
            self.assertIsNone(request._obj.pQueryCompletionCallback)
            self.assertIsNone(cancel)
            result._obj.QueryStatus = 9003  # NXDOMAIN is an API result, not denial.
            result._obj.pQueryRecords = 1234
            return 9003

        resolver.dns.DnsQueryEx.side_effect = query
        result = resolver.invoke("dns_aaaa", probe.qname(self.nonce, "parent", "dns_aaaa"))
        self.assertEqual(result["return_code"], 9003)
        self.assertEqual(result["query_status"], 9003)
        self.assertTrue(result["records_released"])
        self.assertNotIn("blocked", result)
        resolver.dns.DnsFree.assert_called_once_with(1234, 1)

    def test_getaddrinfo_uses_no_server_hints_and_frees_native_result_and_winsock(self):
        resolver = object.__new__(probe.NativeResolver)
        resolver.wsa = mock.Mock()
        resolver.wsa.WSAStartup.return_value = resolver.wsa.WSACleanup.return_value = 0

        def query(name, service, hints, result):
            self.assertIsNone(service)
            self.assertIsNone(hints)
            result._obj.value = 5678
            return 0

        resolver.wsa.GetAddrInfoW.side_effect = query
        result = resolver.invoke("getaddrinfo", probe.qname(self.nonce, "child", "getaddrinfo"))
        self.assertTrue(result["records_present"])
        self.assertTrue(result["records_released"])
        resolver.wsa.FreeAddrInfoW.assert_called_once()
        self.assertEqual(resolver.wsa.FreeAddrInfoW.call_args.args[0].value, 5678)
        resolver.wsa.WSACleanup.assert_called_once()

    def test_unexpected_pending_native_dns_buffers_are_not_freed(self):
        resolver = object.__new__(probe.NativeResolver)
        resolver.dns = mock.Mock()
        resolver.dns.DnsQueryEx.return_value = probe.DNS_REQUEST_PENDING
        result = resolver.invoke("dns_a", probe.qname(self.nonce, "parent", "dns_a"))
        self.assertTrue(result["operation_pending"])
        self.assertFalse(result["native_completion_proven"])
        self.assertEqual(len(resolver.pending_buffers), 3)
        resolver.dns.DnsFree.assert_not_called()

    def worker_records(self, api="getaddrinfo"):
        process = mock.Mock(pid=4321, _handle=mock.Mock(), returncode=0)
        process.poll.return_value = None
        process.wait.return_value = 0
        identity = mock.Mock()
        identity.created.return_value = 120
        identity.exited.return_value = True
        value = {"api": api, "qname": probe.qname(self.nonce, "parent", api), "requested_role": "parent",
                 "pid": 4321, "ppid": os.getpid(), "process_created": 120,
                 "default_system_server_list": True, "server_list_override": False,
                 "dns_blocked_proven": False, "acceptance_passed": False}
        lease = dict(value, monotonic=time.monotonic(), state="native_call_prepared")
        result = dict(value, api_returned=True, return_code=11001, records_released=True)
        return process, identity, lease, result

    def test_nxdomain_only_collects_api_return_and_releases_held_worker_handle(self):
        process, identity, lease, result = self.worker_records()
        with mock.patch.object(probe.subprocess, "Popen", return_value=process), \
                mock.patch.object(probe, "read_json", side_effect=[lease, result]):
            report = probe.collect_call(self.nonce, "parent", "getaddrinfo", self.root / "call", identity)
        self.assertEqual(report["outcome"], "returned")
        self.assertEqual(report["return_code"], 11001)
        self.assertFalse(report["dns_blocked_proven"])
        self.assertTrue(report["worker_cleanup_proven"])
        process.kill.assert_not_called()
        process._handle.Close.assert_called_once()

    def test_four_second_deadline_kills_only_owned_handle_and_never_claims_denial(self):
        process, identity, lease, result = self.worker_records()
        process.wait.side_effect = [subprocess.TimeoutExpired(["owned"], 4), 0]
        identity.exited.side_effect = [False, True]
        with mock.patch.object(probe.subprocess, "Popen", return_value=process), \
                mock.patch.object(probe, "read_json", side_effect=[lease, FileNotFoundError()]):
            report = probe.collect_call(self.nonce, "parent", "getaddrinfo", self.root / "call", identity)
        self.assertEqual(report["outcome"], "deadline")
        self.assertFalse(report["api_returned"])
        self.assertFalse(report["dns_blocked_proven"])
        self.assertTrue(report["worker_cleanup_proven"])
        process.kill.assert_called_once()
        self.assertLessEqual(process.wait.call_args_list[0].kwargs["timeout"], 4)
        process._handle.Close.assert_called_once()

    def test_wrong_worker_generation_is_rejected_and_live_cleanup_failure_is_retained(self):
        process, identity, lease, result = self.worker_records()
        lease["process_created"] = 121
        identity.exited.side_effect = [False, False]
        with mock.patch.object(probe.subprocess, "Popen", return_value=process), \
                mock.patch.object(probe, "read_json", return_value=lease):
            report = probe.collect_call(self.nonce, "parent", "getaddrinfo", self.root / "call", identity)
        self.assertEqual(report["outcome"], "tool_error")
        self.assertFalse(report["worker_cleanup_proven"])
        self.assertIn("recovery_directory", report)
        process._handle.Close.assert_not_called()

    def permission_error(self):
        error = PermissionError(13, "private command and credential", "private-path")
        error.winerror = 5
        return error

    def test_entry_lease_open_failure_records_exact_stage_and_numeric_error_only(self):
        process, identity, lease, result = self.worker_records()
        with mock.patch.object(probe.subprocess, "Popen", return_value=process), \
                mock.patch.object(Path, "open", side_effect=self.permission_error()):
            report = probe.collect_call(self.nonce, "parent", "getaddrinfo", self.root / "lease-failure", identity)
        self.assertEqual(report["outcome"], "tool_error")
        self.assertEqual(report["error_stage"], "entry_lease_open")
        self.assertEqual((report["error"], report["errno"], report["winerror"]), ("PermissionError", 13, 5))
        self.assertTrue(report["worker_cleanup_proven"])
        self.assertNotIn("entry_lease_published", report)
        for private in ("private command", "credential", "private-path"):
            self.assertNotIn(private, json.dumps(report))

    def test_record_replace_failure_retains_specific_operation_without_serializing_path(self):
        with mock.patch.object(probe.os, "replace", side_effect=self.permission_error()):
            with self.assertRaises(PermissionError) as observed:
                probe.write_json(self.root / "lease.json", {"state": "prepared"}, stage="lease")
        facts = probe.error_facts(observed.exception, "worker_prepare_lease")
        self.assertEqual(facts, {"error": "PermissionError", "error_stage": "lease_replace", "errno": 13, "winerror": 5})
        self.assertNotIn("private-path", json.dumps(facts))
        self.assertNotIn(str(self.root), json.dumps(facts))

    def test_controller_rejection_preserves_native_worker_error_origin(self):
        process, identity, lease, result = self.worker_records()
        result.update(api_returned=False, **probe.error_facts(self.permission_error(), "worker_invoke_api"))
        process.returncode = 1
        with mock.patch.object(probe.subprocess, "Popen", return_value=process), \
                mock.patch.object(probe, "read_json", side_effect=[lease, result]):
            report = probe.collect_call(self.nonce, "parent", "getaddrinfo", self.root / "native-failure", identity)
        self.assertEqual(report["error"], "PermissionError")
        self.assertEqual(report["error_stage"], "worker_invoke_api")
        self.assertEqual(report["winerror"], 5)
        self.assertEqual(report["controller_error"], "RuntimeError")
        self.assertEqual(report["controller_error_stage"], "check_native_completion")
        self.assertIsNone(report["controller_winerror"])
        self.assertFalse(report["api_returned"])
        self.assertTrue(report["worker_cleanup_proven"])
        self.assertFalse(report["acceptance_passed"])

    def test_handle_close_failure_is_separate_from_returned_api_and_preserves_recovery(self):
        process, identity, lease, result = self.worker_records()
        process._handle.Close.side_effect = self.permission_error()
        with mock.patch.object(probe.subprocess, "Popen", return_value=process), \
                mock.patch.object(probe, "read_json", side_effect=[lease, result]):
            report = probe.collect_call(self.nonce, "parent", "getaddrinfo", self.root / "close-failure", identity)
        self.assertEqual(report["outcome"], "returned")
        self.assertNotIn("error", report)
        self.assertEqual(report["cleanup_error_stage"], "close_worker_handle")
        self.assertEqual((report["cleanup_errno"], report["cleanup_winerror"]), (13, 5))
        self.assertFalse(report["worker_cleanup_proven"])
        self.assertNotIn("worker_handle_closed", report)
        self.assertIn("recovery_directory", report)
        self.assertNotIn("private-path", json.dumps(report))

    def test_cleanup_failure_stops_new_native_queries_and_preserves_directory(self):
        report_path = self.root / "report.json"
        retained = self.root / "retained"
        retained.mkdir()
        value = {"outcome": "returned", "worker_cleanup_proven": False, "cleanup_error": "live"}
        with mock.patch.object(probe, "os", SimpleNamespace(name="nt", replace=os.replace)), mock.patch.object(probe, "ProcessIdentity"), \
                mock.patch.object(probe.tempfile, "mkdtemp", return_value=str(retained)), \
                mock.patch.object(probe, "collect_call", return_value=value) as call:
            code = probe.main(["--nonce", self.nonce, "--role", "parent", "--report", str(report_path)])
        self.assertEqual(code, 1)
        self.assertEqual(call.call_count, 1)
        self.assertTrue(retained.exists())
        self.assertFalse(json.loads(report_path.read_text())["cleanup_proven"])

    def test_non_windows_is_an_explicit_unsupported_result(self):
        report = self.root / "report.json"
        with mock.patch.object(probe, "os", SimpleNamespace(name="posix", replace=os.replace)):
            code = probe.main(["--nonce", self.nonce, "--role", "outside_before", "--report", str(report)])
        self.assertEqual(code, 3)
        result = json.loads(report.read_text())
        self.assertEqual(result["status"], "unsupported")
        self.assertFalse(result["dns_blocked_proven"])
        self.assertFalse(result["acceptance_passed"])

    @unittest.skipUnless(os.name == "nt", "Real Windows resolver API ABI smoke only")
    def test_real_windows_cli_observes_native_api_abi_and_owned_worker_cleanup(self):
        # Run the complete CLI entry without mocks. Invoking main in this test
        # process keeps every worker under its existing held-HANDLE controller;
        # an additional timeout wrapper must not orphan a blocked DNS worker.
        # This is an outside API control, never an assertion about PSEC policy.
        nonce = secrets.token_hex(16)
        controller_created = probe.ProcessIdentity().current_created()
        report_path = self.root / "native-abi.json"
        started = time.monotonic()
        code = probe.main(["--nonce", nonce, "--role", "outside_before", "--report", str(report_path)])
        elapsed = time.monotonic() - started
        result = probe.read_json(report_path)
        self.assertEqual(code, 0, result)
        self.assertEqual(result["status"], "native_dns_probe_only", result)
        self.assertTrue(result["cleanup_proven"], result)
        self.assertFalse(result["acceptance_passed"])
        self.assertFalse(result["real_node_passed"])
        self.assertFalse(result["dns_blocked_proven"])
        self.assertIsNone(result["wire_observed"])
        self.assertTrue(result["default_system_server_list"])
        self.assertFalse(result["server_list_override"])
        self.assertEqual(result["requested_role"], "outside_before")
        self.assertNotIn("cleanup_error", result)
        self.assertNotIn("recovery_directory", result)
        self.assertEqual([x["api"] for x in result["calls"]], list(probe.APIS))
        self.assertLess(elapsed, len(probe.APIS) * (probe.STARTUP_SECONDS + probe.CALL_SECONDS + 2) + 10)
        generations = set()
        incomplete = []
        for item in result["calls"]:
            with self.subTest(api=item["api"]):
                self.assertEqual(item["qname"], probe.qname(nonce, "outside_before", item["api"]))
                self.assertEqual(item["requested_role"], "outside_before")
                self.assertIs(type(item["pid"]), int)
                self.assertGreater(item["pid"], 0)
                self.assertNotEqual(item["pid"], os.getpid())
                self.assertEqual(item["ppid"], os.getpid())
                self.assertIs(type(item["process_created"]), int)
                self.assertGreaterEqual(item["process_created"], controller_created)
                generation = (item["pid"], item["process_created"])
                self.assertNotIn(generation, generations)
                generations.add(generation)
                self.assertTrue(item["entry_lease_published"])
                self.assertTrue(item["worker_exit_verified"])
                self.assertTrue(item["worker_handle_closed"])
                self.assertTrue(item["worker_cleanup_proven"])
                self.assertIs(type(item["worker_exit_code"]), int)
                self.assertTrue(item["default_system_server_list"])
                self.assertFalse(item["server_list_override"])
                self.assertFalse(item["dns_blocked_proven"])
                self.assertFalse(item["acceptance_passed"])
                for unexpected in ("error", "cleanup_error", "recovery_directory", "operation_pending", "setup_error"):
                    self.assertNotIn(unexpected, item)
                self.assertIn(item["outcome"], ("returned", "deadline"), item)
                if item["outcome"] == "returned":
                    self.assertTrue(item["api_returned"])
                    self.assertTrue(item["native_completion_proven"])
                    self.assertTrue(item["records_released"])
                    self.assertIs(type(item["return_code"]), int)
                    # These are malformed input/memory failures, not resolver
                    # observations for our fixed, valid requests. NXDOMAIN and
                    # other resolution errors are not policy success or failure.
                    self.assertNotIn(item["return_code"], (87, 123, 998, 10022), item)
                    self.assertEqual(item["query_options"], 0 if item["api"] == "getaddrinfo" else probe.DNS_OPTIONS)
                    if item["api"] != "getaddrinfo":
                        self.assertIs(type(item["query_status"]), int)
                        self.assertNotIn(item["query_status"], (87, 123, 998, 10022), item)
                else:
                    self.assertFalse(item["api_returned"])
                    self.assertFalse(item["native_completion_proven"])
                    self.assertTrue(item["owned_worker_terminated"])
                    self.assertNotIn("return_code", item)
                    incomplete.append(item["api"])
        print("Windows native DNS ABI smoke observations: " + json.dumps({
            "scope": "outside_api_control_only", "abi_completion_observed": not incomplete,
            "inconclusive_apis": incomplete, "worker_cleanup_proven": True,
            "acceptance_passed": False, "dns_blocked_proven": False,
            "calls": [{key: item.get(key) for key in ("api", "pid", "ppid", "process_created", "outcome",
                "return_code", "query_status", "worker_exit_verified", "worker_handle_closed")}
                for item in result["calls"]]}, separators=(",", ":")))
        if incomplete:
            self.skipTest("Native resolver deadline: API ABI completion inconclusive; owned cleanup verified")


if __name__ == "__main__":
    unittest.main()
