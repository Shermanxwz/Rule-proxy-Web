"""Exact-generation event correlation; fixtures are not real crash evidence."""
import copy
import datetime as dt
import hashlib
import importlib.util
import json
import ntpath
import os
from pathlib import Path
import subprocess
import sys
import unittest
from unittest import mock
import xml.etree.ElementTree as ET

ROOT = Path(__file__).resolve().parent.parent
spec = importlib.util.spec_from_file_location("ruleproxy_edge_crash_test", ROOT / ".github/windows_edge_crash_evidence.py")
crash = importlib.util.module_from_spec(spec)
spec.loader.exec_module(crash)


class EdgeCrashEvidenceTests(unittest.TestCase):
    def setUp(self):
        self.start = dt.datetime(2026, 10, 15, 12, tzinfo=dt.timezone.utc)
        self.end = self.start + dt.timedelta(seconds=60)
        created = int((self.start - dt.datetime(1601, 1, 1, tzinfo=dt.timezone.utc)).total_seconds()) * 10000000
        self.edge = r"C:\Program Files\Microsoft\Edge\Application\msedge.exe"
        self.identity = {"status": "observed", "scope": crash.IDENTITY_SCOPE, "pid": 1234,
                         "process_created": created, "image_sha256": hashlib.sha256(crash.image_key(self.edge).encode()).hexdigest(),
                         "held_handle_verified": True, "error": None}
        self.report_id = "01234567-89ab-cdef-0123-456789abcdef"

    def event(self, *, provider="Application Error", event_id=1000, fields=None, execution_pid=9999, timestamp=None):
        root = ET.Element(crash._NS + "Event")
        system = ET.SubElement(root, crash._NS + "System")
        ET.SubElement(system, crash._NS + "Provider", Name=provider)
        ET.SubElement(system, crash._NS + "EventID").text = str(event_id)
        ET.SubElement(system, crash._NS + "Channel").text = "Application"
        ET.SubElement(system, crash._NS + "TimeCreated", SystemTime=(timestamp or self.start).isoformat().replace("+00:00", "Z"))
        ET.SubElement(system, crash._NS + "Execution", ProcessID=str(execution_pid))
        data = ET.SubElement(root, crash._NS + "EventData")
        entries = {"ProcessId": hex(self.identity["pid"]), "ProcessCreationTime": hex(self.identity["process_created"]),
                   "AppName": "msedge.exe", "AppPath": self.edge, "ModuleName": "msedge.dll", "ModuleVersion": "150.0.1.2",
                   "ExceptionCode": "c0000005", "FaultingOffset": "0000000000001234", "IntegratorReportId": self.report_id,
                   "ModulePath": r"C:\PRIVATE_USER\module.dll", "PrivateMessage": "PRIVATE_OTHER_EVENT_MESSAGE"}
        entries.update(fields or {})
        for key, value in entries.items():
            ET.SubElement(data, crash._NS + "Data", Name=key).text = value
        return ET.tostring(root, encoding="unicode")

    def correlate(self, *records):
        return crash.correlate_events(self.identity, list(records), self.start, self.end)

    def test_only_exact_pid_creation_and_full_image_match_can_produce_crash_facts(self):
        result = self.correlate(self.event())
        self.assertEqual(result["status"], "crash_evidence_observed")
        self.assertEqual(result["events"], [{"event_id": 1000, "pid": 1234,
            "process_created": self.identity["process_created"], "module": "msedge.dll", "module_version": "150.0.1.2",
            "exception_code": "0xC0000005", "fault_offset": "0x0000000000001234", "report_id": self.report_id}])
        for private in (self.edge, "PRIVATE_USER", "PRIVATE_OTHER_EVENT_MESSAGE", "ModulePath", "Execution"):
            self.assertNotIn(private, json.dumps(result))
        for field in ("acceptance_passed", "full_acceptance_passed", "real_node_passed", "collector_re_attested_identity",
                      "browser_sandbox_weakened", "host_configuration_changed"):
            self.assertIs(result[field], False)

    def test_foreign_event_system_pid_and_recycled_generation_cannot_correlate(self):
        for fields in ({"ProcessId": "0x999"}, {"ProcessCreationTime": hex(self.identity["process_created"] + 1)}):
            with self.subTest(fields=fields):
                result = self.correlate(self.event(fields=fields, execution_pid=1234))
                self.assertEqual(result["status"], "not_observed")
                self.assertEqual(result["events"], [])
        result = self.correlate(self.event(fields={"AppPath": r"C:\Other\msedge.exe"}))
        self.assertEqual(result["status"], "incomplete")
        self.assertEqual(result["events"], [])

    def test_wer_requires_matching_application_error_report_id_not_its_execution_pid(self):
        wer = self.event(provider="Windows Error Reporting", event_id=1001,
                         fields={"ReportId": self.report_id, "EventName": "APPCRASH", "AttachedFiles": "PRIVATE_DUMP_PATH"})
        unlinked = self.event(provider="Windows Error Reporting", event_id=1001,
                             fields={"ReportId": "11111111-2222-3333-4444-555555555555", "EventName": "APPCRASH"}, execution_pid=1234)
        self.assertEqual(self.correlate(wer)["wer_reports"], [])
        result = self.correlate(self.event(), wer, unlinked)
        self.assertEqual(result["wer_reports"], [{"event_id": 1001, "report_id": self.report_id, "event_name": "APPCRASH",
                                                "association": "matched_application_error_integrator_report_id"}])
        self.assertNotIn("PRIVATE_DUMP_PATH", json.dumps(result))

    def test_wrong_provider_time_or_id_is_not_reclassified_as_an_edge_event(self):
        for event in (self.event(provider="Other Provider"), self.event(event_id=1001),
                      self.event(timestamp=self.start - dt.timedelta(seconds=1))):
            self.assertEqual(self.correlate(event)["status"], "not_observed")

    def test_ambiguous_oversized_or_missing_crash_fields_remain_incomplete(self):
        root = ET.fromstring(self.event())
        ET.SubElement(root.find(crash._NS + "EventData"), crash._NS + "Data", Name="ProcessId").text = "1234"
        for xml in (ET.tostring(root, encoding="unicode"), "x" * (crash.MAX_XML_BYTES + 1),
                    self.event(fields={"ProcessCreationTime": ""}), self.event(fields={"ExceptionCode": "private"}),
                    "<!DOCTYPE Event>" + self.event()):
            with self.subTest(prefix=xml[:10]):
                result = self.correlate(xml)
                self.assertEqual(result["status"], "incomplete")
                self.assertNotIn("PRIVATE", json.dumps(result))
        self.assertEqual(crash.correlate_events(self.identity, [self.event()] * 33, self.start, self.end)["status"], "incomplete")

    def test_query_contains_exact_generation_and_only_already_linked_wer_report_ids(self):
        query = crash.event_query(self.identity, self.start, self.end)
        self.assertIn("Application Error", query)
        self.assertIn("EventID=1000", query)
        self.assertIn("ProcessCreationTime", query)
        self.assertIn(hex(self.identity["process_created"]), query)
        self.assertNotIn("Execution", query)
        self.assertNotIn("Windows Error Reporting", query)
        query = crash.event_query(self.identity, self.start, self.end, {self.report_id})
        self.assertIn("EventID=1001", query)
        self.assertIn(self.report_id, query)
        with self.assertRaises(ValueError):
            crash.event_query(self.identity, self.start, self.end, {"unrelated or *"})
        for end in (self.start, self.start + dt.timedelta(seconds=181)):
            with self.assertRaises(ValueError):
                crash.event_window(self.identity, self.start, end)

    def fake_process_api(self):
        api = mock.Mock()
        api.pid.return_value = self.identity["pid"]
        api.created.return_value = self.identity["process_created"]
        api.image.return_value = self.edge
        return api

    def test_capture_borrows_actual_handle_and_rechecks_generation_without_wait_kill_or_close(self):
        process = mock.Mock(pid=1234, _handle=5678)
        api = self.fake_process_api()
        result = crash.capture_held_edge_identity(process, self.edge, api)
        self.assertEqual(result, self.identity)
        self.assertIs(crash.validate_identity(result), result)
        self.assertEqual(api.pid.call_args_list, [mock.call(5678), mock.call(5678)])
        self.assertEqual(api.created.call_args_list, [mock.call(5678), mock.call(5678)])
        process.wait.assert_not_called()
        process.kill.assert_not_called()
        api.close.assert_not_called()
        api.open.assert_not_called()

    def test_identity_query_failure_wrong_image_or_generation_never_publishes_partial_identity(self):
        for mode in ("image", "pid", "created", "permission"):
            api = self.fake_process_api()
            if mode == "image": api.image.return_value = r"C:\Other\msedge.exe"
            if mode == "pid": api.pid.return_value = 99
            if mode == "created": api.created.side_effect = [self.identity["process_created"], self.identity["process_created"] + 1]
            if mode == "permission":
                error = PermissionError(13, "PRIVATE_MESSAGE", "PRIVATE_PATH"); error.winerror = 5
                api.image.side_effect = error
            with self.subTest(mode=mode):
                result = crash.capture_held_edge_identity(mock.Mock(pid=1234, _handle=5678), self.edge, api)
                self.assertEqual(result["status"], "incomplete")
                self.assertIsNone(result["pid"])
                self.assertIsNone(result["process_created"])
                self.assertFalse(result["held_handle_verified"])
                self.assertNotIn("PRIVATE", json.dumps(result))
                self.assertIs(crash.validate_identity(result), result)

    def test_invalid_or_incomplete_identity_never_queries_eventlog(self):
        with mock.patch.object(crash.subprocess, "Popen") as launch:
            incomplete = crash.incomplete_identity(error_type="SourceUnavailable")
            self.assertEqual(crash.collect_crash_events(incomplete)["status"], "incomplete")
            for field, value in (("pid", True), ("held_handle_verified", False), ("image_sha256", "bad")):
                identity = dict(self.identity, **{field: value})
                self.assertEqual(crash.collect_crash_events(identity, self.start, self.end)["status"], "incomplete")
                with self.assertRaises(ValueError): crash.validate_identity(identity)
            launch.assert_not_called()

    def test_event_reader_timeout_only_stops_its_owned_popen_and_proves_cleanup(self):
        process = mock.Mock()
        process.communicate.side_effect = subprocess.TimeoutExpired("private command", 12)
        process.poll.return_value = None
        process.wait.return_value = -1
        with mock.patch.object(crash.subprocess, "Popen", return_value=process):
            result = crash.collect_crash_events(self.identity, self.start, self.end)
        self.assertEqual(result["status"], "incomplete")
        self.assertEqual(result["failure"]["stage"], "reader_wait")
        self.assertTrue(result["reader_cleanup_proven"])
        process.kill.assert_called_once_with()
        process.wait.assert_called_once_with(timeout=2)
        process._handle.Close.assert_called_once_with()
        self.assertNotIn("private", json.dumps(result))

    def test_event_reader_cleanup_failure_keeps_actual_owner_and_cannot_claim_complete(self):
        process = mock.Mock()
        process.communicate.side_effect = subprocess.TimeoutExpired("reader", 12)
        process.poll.return_value = None
        process.kill.side_effect = PermissionError(13, "PRIVATE_PATH")
        count = len(crash._RECOVERY_READERS)
        try:
            with mock.patch.object(crash.subprocess, "Popen", return_value=process):
                result = crash.collect_crash_events(self.identity, self.start, self.end)
            self.assertFalse(result["reader_cleanup_proven"])
            self.assertEqual(result["status"], "incomplete")
            self.assertIs(crash._RECOVERY_READERS[-1], process)
            process._handle.Close.assert_not_called()
        finally:
            del crash._RECOVERY_READERS[count:]

    @unittest.skipUnless(os.name == "nt", "Real outside Windows ABI only; no Edge/PSEC result")
    def test_windows_borrowed_process_and_narrow_event_reader_abi_outside_only(self):
        process = subprocess.Popen([sys.executable, "-I", "-S", "-c", "import time;time.sleep(2)"])
        try:
            api = crash.ProcessIdentityApi()
            self.assertEqual(api.pid(int(process._handle)), process.pid)
            created = api.created(int(process._handle))
            self.assertGreater(created, 0)
            self.assertEqual(ntpath.basename(api.image(int(process._handle))).casefold(), ntpath.basename(sys.executable).casefold())
            identity = dict(self.identity, pid=process.pid, process_created=created)
            # This is an exact query for a Python generation, not a claim that
            # it is Edge. There must be no matched Edge event for that image.
            start = dt.datetime.now(dt.timezone.utc) - dt.timedelta(seconds=2)
            end = dt.datetime.now(dt.timezone.utc) + dt.timedelta(seconds=1)
            result = crash.collect_crash_events(identity, start, end)
            self.assertTrue(result["reader_cleanup_proven"])
            self.assertEqual(result["status"], "not_observed", result.get("failure"))
            self.assertEqual(result["events"], [])
        finally:
            if process.poll() is None:
                process.wait(timeout=5)
            process._handle.Close()


if __name__ == "__main__":
    unittest.main()
