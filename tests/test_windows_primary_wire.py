"""Private capture format/lifecycle checks, not Windows DNS enforcement tests."""
import hashlib
import importlib.util
import io
import json
from pathlib import Path
import struct
import sys
import tempfile
import unittest
from unittest import mock

sys.path.insert(0, str(Path(__file__).parent))
import test_windows_dns_packet_evidence as fixture

spec = importlib.util.spec_from_file_location("primary_wire_test",
    Path(__file__).resolve().parents[1] / ".github/windows_primary_wire.py")
wire = importlib.util.module_from_spec(spec)
spec.loader.exec_module(wire)
NAME = "a" * 32 + ".1.2.3.4.sslip.io"
OTHER = "b" * 32 + ".1.2.3.4.sslip.io"
MAC = fixture.dns.SOURCE_MAC
REPORT = {"started": 1000.0, "finished": 1002.0, "variants": {"plain": {"dns": [{"name": NAME}]}}}


def block(kind, body, endian="<"):
    size = len(body) + 12
    assert size % 4 == 0
    return struct.pack(endian + "II", kind, size) + body + struct.pack(endian + "I", size)


def option(code, raw, endian="<"):
    return struct.pack(endian + "HH", code, len(raw)) + raw + b"\0" * (-len(raw) % 4)


def capture(frames, endian="<", *, direction=2, interface=0, resolution=6, offset=0):
    result = block(0x0A0D0D0A, struct.pack(endian + "IHHq", 0x1A2B3C4D, 1, 0, -1), endian)
    opts = option(9, bytes([resolution]), endian) + option(14, struct.pack(endian + "q", offset), endian) + b"\0" * 4
    result += block(1, struct.pack(endian + "HHI", 1, 0, 65535) + opts, endian)
    for index, frame in enumerate(frames):
        stamp = 1_000_000_000 + index * 1_000_000
        body = struct.pack(endian + "IIIII", interface, stamp >> 32, stamp & 0xFFFFFFFF, len(frame), len(frame))
        body += frame + b"\0" * (-len(frame) % 4)
        body += option(2, struct.pack(endian + "I", direction), endian) + b"\0" * 4
        result += block(6, body, endian)
    return result


class PcapngEvidenceTests(unittest.TestCase):
    def observe(self, raw, report=REPORT):
        return wire.observe([io.BytesIO(raw)], report, [MAC])

    def test_only_report_matched_hashes_leave_the_private_decoder(self):
        frames = [fixture.frame({"qname": name}) for name in (NAME, NAME, OTHER, "private-user.example")]
        result = self.observe(capture(frames))
        self.assertEqual(result["queries"][0]["qname_sha256"], hashlib.sha256(NAME.encode()).hexdigest())
        self.assertEqual(result["queries"][0]["outbound_question_records"], 2)
        self.assertEqual(result["queries"][0]["by_query_type"], {"1": 2})
        raw = json.dumps(result)
        for secret in (NAME, OTHER, "private-user", MAC, "192.0.2"):
            self.assertNotIn(secret, raw)

    def test_inbound_wrong_source_mac_responses_and_non53_are_not_outbound_queries(self):
        frame = fixture.frame({"qname": NAME})
        self.assertEqual(self.observe(capture([frame], direction=1))["queries"][0]["outbound_question_records"], 0)
        wrong_source = frame[:6] + b"\x02\x22\x33\x44\x55\x66" + frame[12:]
        response = fixture.frame({"qname": NAME}, payload=fixture.question(NAME, flags=0x8100))
        mdns = fixture.frame({"qname": NAME}, port=5353)
        result = self.observe(capture([wrong_source, response, mdns]))
        self.assertEqual(result["queries"][0]["outbound_question_records"], 0)

    def test_ipv6_and_unknown_direction_use_host_source_mac(self):
        result = self.observe(capture([fixture.frame({"qname": NAME}, family="ipv6", query_type=28)], direction=0))
        self.assertEqual(result["queries"][0]["by_query_type"], {"28": 1})

    def test_sections_can_switch_byte_order_and_timestamp_units(self):
        frame = fixture.frame({"qname": NAME})
        raw = capture([frame], "<") + capture([frame], ">", resolution=0x8A, offset=2)
        result = self.observe(raw)
        self.assertEqual(result["queries"][0]["outbound_question_records"], 2)
        self.assertEqual(result["captures"][0]["sections"], 2)
        self.assertEqual(result["queries"][0]["last_observed_unix_ns"], 1_000_000_000 * 1_000_000_000 // 1024 + 2_000_000_000)

    def test_empty_and_tcp_only_capture_cannot_be_mistaken_for_complete_dns_visibility(self):
        empty = self.observe(capture([]))
        self.assertEqual(empty["queries"][0]["outbound_question_records"], 0)
        tcp = struct.pack("!HHIIHHHH", 45123, 53, 1, 0, 5 << 12, 65535, 0, 0) + fixture.question(NAME)
        result = self.observe(capture([fixture.frame({"qname": NAME}, protocol=6, payload=tcp)]))
        self.assertEqual(result["opaque_packets"], {"tcp_dns_not_reassembled": 1})

    def test_truncation_bad_trailers_missing_interfaces_and_unsupported_packets_fail_closed(self):
        frame = fixture.frame({"qname": NAME})
        valid = capture([frame])
        cases = [valid[:-1], valid[:-4] + b"\0" * 4, capture([frame], interface=1),
                 capture([frame], direction=3), capture([]) + block(3, struct.pack("<I", 42)), b"not pcapng"]
        for raw in cases:
            with self.subTest(digest=hashlib.sha256(raw).hexdigest()), self.assertRaises(wire.CaptureError):
                self.observe(raw)

    def test_capture_truncation_and_duplicate_direction_options_are_rejected(self):
        frame = fixture.frame({"qname": NAME})
        for original, flags in ((len(frame) + 1, b""), (len(frame), option(2, b"\0" * 4) * 2)):
            packet = struct.pack("<IIIII", 0, 0, 1, len(frame), original)
            packet += frame + b"\0" * (-len(frame) % 4) + flags + b"\0" * 4
            with self.assertRaises(wire.CaptureError):
                self.observe(capture([]) + block(6, packet))

    def test_unknown_blocks_are_counted_and_never_expose_strings(self):
        result = self.observe(capture([]) + block(0xBAD, b"secret!!") + block(0xBAE, b""))
        self.assertEqual(result["captures"][0]["unknown_blocks"], 2)
        self.assertNotIn("secret", json.dumps(result))

    def test_report_without_a_valid_nonce_is_rejected(self):
        for report in ({}, {"name": "private-user.example"}, {"name": "a" * 31 + ".1.2.3.4.sslip.io"}):
            with self.assertRaises(wire.CaptureError):
                self.observe(capture([]), report)

    def test_rotations_require_every_number(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            for number in (1, 3):
                (root / f"capture{number}.etl").write_bytes(b"etl")
            with self.assertRaisesRegex(wire.CaptureError, "rotation_gap"):
                wire.capture_files(root)
            (root / "capture2.etl").write_bytes(b"etl")
            self.assertEqual([p.name for p in wire.capture_files(root)], ["capture1.etl", "capture2.etl", "capture3.etl"])


class FakeNative:
    def __init__(self):
        self.calls, self.private, self.active, self.fail_convert, self.fail_start = [], None, False, False, False

    def protect(self, path):
        self.calls.append(("protect",))

    def macs(self):
        return [MAC]

    def trace(self, flush=False):
        if not self.active:
            return None
        return {"logfile": str(self.private / "capture%d.etl"), "context": 42, "log_mode": 8,
                "events_lost": 0, "log_buffers_lost": 0, "realtime_buffers_lost": 0, "buffers_written": 4}

    def pktmon(self, *args):
        self.calls.append(args)
        if args[0] == "start":
            self.private = Path(args[args.index("--file-name") + 1]).parent
            (self.private / "capture1.etl").write_bytes(b"private raw ETL")
            self.active = True
            if self.fail_start:
                raise wire.CaptureError("pktmon_start_failed")
        elif args[0] == "stop":
            self.active = False
        elif args[0] == "etl2pcap":
            if self.fail_convert:
                raise wire.CaptureError("pktmon_etl2pcap_failed")
            Path(args[-1]).write_bytes(capture([fixture.frame({"qname": NAME})]))


class CaptureLifecycleTests(unittest.TestCase):
    def setUp(self):
        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        self.root = Path(temporary.name)
        self.state, self.report, self.output = (self.root / name for name in ("state.json", "report.json", "summary.json"))
        self.report.write_text(json.dumps(REPORT))
        self.native = FakeNative()

    def test_finish_stops_converts_and_erases_raw_files_before_exposing_hash_summary(self):
        self.assertTrue(wire.start(self.state, self.native)["started"])
        result = wire.finish(self.state, self.report, self.output, native=self.native)
        self.assertEqual(result["status"], "observed")
        self.assertEqual(result["queries"][0]["outbound_question_records"], 1)
        self.assertFalse(result["privacy_qualified"])
        self.assertFalse(result["absence_proven"])
        self.assertFalse(result["coverage"]["no_capture_loss_proven"])
        self.assertEqual(result["coverage"]["loss_after_last_query"], "unknown")
        self.assertFalse(self.native.private.exists())
        self.assertFalse(self.state.exists())
        self.assertTrue(result["raw_capture_removed"])
        self.assertLess(self.native.calls.index(("stop",)), next(i for i, call in enumerate(self.native.calls) if call[0] == "etl2pcap"))
        self.assertNotIn(NAME, self.output.read_text())
        self.assertNotIn(str(self.root), self.output.read_text())

    def test_failed_conversion_still_removes_private_capture_and_does_not_report_zero_success(self):
        wire.start(self.state, self.native)
        self.native.fail_convert = True
        result = wire.finish(self.state, self.report, self.output, native=self.native)
        self.assertEqual(result["status"], "incomplete")
        self.assertEqual(result["errors"], ["pktmon_etl2pcap_failed"])
        self.assertEqual(result["queries"], [])
        self.assertFalse(result["coverage"]["all_rotations_converted_and_parsed"])
        self.assertFalse(self.native.private.exists())

    def test_timed_out_start_that_committed_session_is_stopped(self):
        self.native.fail_start = True
        with self.assertRaisesRegex(wire.CaptureError, "start_failed"):
            wire.start(self.state, self.native)
        self.assertIn(("stop",), self.native.calls)
        self.assertFalse(self.native.active)
        self.assertFalse(self.native.private.exists())

    def test_existing_capture_is_not_stopped_or_reconfigured(self):
        self.native.private, self.native.active = self.root, True
        with self.assertRaisesRegex(wire.CaptureError, "existing_pktmon"):
            wire.start(self.state, self.native)
        self.assertEqual(self.native.calls, [])

    def test_abort_works_without_a_report_and_erases_raw_files(self):
        wire.start(self.state, self.native)
        result = wire.finish(self.state, native=self.native, abort=True)
        self.assertTrue(result["raw_capture_removed"])
        self.assertFalse(self.native.active)
        self.assertFalse(self.state.exists())
        self.assertEqual(result["queries"], [])

    def test_loss_and_window_facts_cannot_grant_absence(self):
        state = {"start_confirmed_unix_ns": 999_000_000_000}
        trace = {"events_lost": 0, "log_buffers_lost": 0, "realtime_buffers_lost": 0, "log_mode": 8}
        result = wire.coverage(state, trace, 1003_000_000_000, REPORT, True, True)
        self.assertTrue(result["report_window_bracketed"])
        self.assertTrue(result["etl_loss_counters_zero_through_flush"])
        self.assertFalse(result["no_capture_loss_proven"])
        self.assertFalse(wire.coverage(state, {**trace, "events_lost": 1}, 1003_000_000_000, REPORT, True, True)["etl_loss_counters_zero_through_flush"])
        self.assertFalse(wire.coverage(state, trace, 1001_000_000_000, REPORT, True, True)["report_window_bracketed"])
        self.assertFalse(wire.coverage(state, {**trace, "log_mode": 2}, 1003_000_000_000, REPORT, True, True)["multi_file_non_circular_confirmed"])

    def test_native_entry_is_unavailable_outside_explicit_disposable_windows_ci(self):
        with mock.patch.dict(wire.os.environ, {"GITHUB_ACTIONS": "false", "RULEPROXY_DISPOSABLE_CI": "1"}):
            with self.assertRaisesRegex(wire.CaptureError, "disposable_windows_ci_required"):
                wire.Native()

    def test_native_etw_query_and_flush_preserve_loss_counters_without_text_parsing(self):
        native = object.__new__(wire.Native)
        queried = []
        def control(handle, name, buffer, operation):
            self.assertEqual(handle, 0)
            self.assertEqual(name, "PktMon")
            props = wire.TraceProperties.from_buffer(buffer)
            self.assertEqual(props.wnode.size, len(buffer))
            self.assertEqual(props.wnode.flags, 0x20000)
            props.events_lost, props.log_buffers_lost, props.realtime_buffers_lost = 3, 4, 5
            props.log_mode = 8
            filename = "C:\\private\\capture%d.etl".encode("utf-16-le") + b"\0\0"
            wire.C.memmove(wire.C.addressof(buffer) + props.file_offset, filename, len(filename))
            queried.append(operation)
            return 0
        dll = mock.Mock()
        dll.ControlTraceW = mock.Mock(side_effect=control)
        with mock.patch.object(wire.C, "WinDLL", return_value=dll, create=True):
            result = native.trace()
            native.trace(flush=True)
        self.assertEqual(queried, [0, 3])
        self.assertEqual([result[name] for name in wire.LOSS_FIELDS], [3, 4, 5])
        self.assertEqual(result["logfile"], "C:\\private\\capture%d.etl")


if __name__ == "__main__":
    unittest.main()
