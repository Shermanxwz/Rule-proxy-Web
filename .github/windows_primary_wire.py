"""Independent, private DNS observer for a disposable Windows CI host only.

start --state <private-launch-directory/wire-state.json>
finish --state ... --report <primary-report.json> --output <public-summary.json>
abort --state ...

Requires GITHUB_ACTIONS=true and RULEPROXY_DISPOSABLE_CI=1. Start before the
experiment; finish in the parent's finally block after its bounded settling
period. Never upload the state, ETL, pcapng, or native command output. The helper
deletes raw captures even when conversion/parsing fails. No production import.

References:
https://learn.microsoft.com/windows-server/administration/windows-commands/pktmon-start
https://learn.microsoft.com/windows-server/administration/windows-commands/pktmon-etl2pcap
https://learn.microsoft.com/windows-server/administration/windows-commands/pktmon-filter-add
https://learn.microsoft.com/windows/win32/api/evntrace/ns-evntrace-event_trace_properties
https://learn.microsoft.com/windows/win32/api/evntrace/nf-evntrace-controltracew

NIC capture is a host observation, not delivery or process attribution. Counts
are packet observations (retransmits/multiple NIC appearances are not deduped).
Only complete UDP DNS questions are decoded. No absence/privacy qualification
is possible, including when all reported ETW loss counters are zero.
"""
from __future__ import annotations

import argparse
from collections import Counter
import ctypes as C
import hashlib
import importlib.util
import json
import math
import os
from pathlib import Path
import re
import shutil
import struct
import subprocess
import sys
import time
import uuid


def sibling(name):
    spec = importlib.util.spec_from_file_location("primary_" + name, Path(__file__).with_name(name + ".py"))
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


pcapng = sibling("windows_pcapng")
dns = sibling("windows_dns_packet_evidence")
CaptureError = pcapng.CaptureError
NAME = re.compile(r"[0-9a-f]{32}\.1\.2\.3\.4\.sslip\.io\Z")
PRIVATE_PREFIX = ".RuleProxyWirePrivate-"
MAX_REPORT = 4 * 1024 * 1024
LOSS_FIELDS = ("events_lost", "log_buffers_lost", "realtime_buffers_lost")


def report_names(value):
    found, visited = set(), 0
    def visit(item, depth=0):
        nonlocal visited
        visited += 1
        if visited > 50_000 or depth > 32:
            raise CaptureError("report_structure_limit")
        if isinstance(item, dict):
            name = item.get("name")
            if isinstance(name, str) and NAME.fullmatch(name.lower().removesuffix(".")):
                found.add(name.lower().removesuffix(".").encode("ascii"))
            for child in item.values():
                visit(child, depth + 1)
        elif isinstance(item, list):
            for child in item:
                visit(child, depth + 1)
    visit(value)
    if not 1 <= len(found) <= 512:
        raise CaptureError("report_nonce_names_missing_or_excessive")
    return found


def outgoing_questions(frame, macs):
    """Only host-source Ethernet UDP/53 queries; retain opaque DNS as unknown."""
    if len(frame) < 14:
        raise CaptureError("ethernet_header_truncated")
    mac = frame[6:12]
    if mac not in macs:
        return [], None
    offset, kind = 14, struct.unpack_from("!H", frame, 12)[0]
    for _ in range(4):
        if kind not in (0x8100, 0x88A8, 0x9100):
            break
        if offset + 4 > len(frame):
            raise CaptureError("vlan_header_truncated")
        kind = struct.unpack_from("!H", frame, offset + 2)[0]
        offset += 4
    else:
        return [], "unsupported_vlan_stack"
    if kind == 0x0800:
        if offset + 20 > len(frame):
            raise CaptureError("ipv4_header_truncated")
        family, protocol = 4, frame[offset + 9]
        source, target = frame[offset + 12:offset + 16], frame[offset + 16:offset + 20]
        start = offset + (frame[offset] & 15) * 4
    elif kind == 0x86DD:
        if offset + 40 > len(frame):
            raise CaptureError("ipv6_header_truncated")
        family, protocol = 6, frame[offset + 6]
        source, target = frame[offset + 8:offset + 24], frame[offset + 24:offset + 40]
        start = offset + 40
    else:
        return [], None
    port = struct.unpack_from("!H", frame, start + 2)[0] if len(frame) >= start + 4 else 0
    candidate = {"base": (mac, family, source, target, port), "payload": b""}
    try:
        packet, unknown = dns._packet.udp_frame(frame, [candidate])
    except dns.EvidenceError:
        return [], "unparsed_network_frame"
    if unknown:
        return [], "opaque_network_frame"
    if protocol == 6:
        return [], "tcp_dns_not_reassembled" if port == 53 else None
    if packet is None or port != 53:
        return [], None
    try:
        return dns.dns_questions(packet[1], 53), None
    except dns.EvidenceError:
        return [], "unparsed_dns_datagram"


def observe(streams, report, macs):
    names = report_names(report)
    macs = {bytes.fromhex(value.replace("-", "").replace(":", "")) for value in macs}
    if not macs or any(len(value) != 6 or not any(value) or value[0] & 1 for value in macs):
        raise CaptureError("host_nic_identity_invalid")
    counts, times, unknown, captures = Counter(), {}, Counter(), []
    total_bytes = 0
    for stream in streams:
        reader = pcapng.Reader(stream)
        for timestamp, direction, frame in reader.frames():
            if direction == 1:  # Explicit inbound metadata overrides source MAC.
                continue
            questions, opaque = outgoing_questions(frame, macs)
            if opaque:
                unknown[opaque] += 1
            for labels, kind, query_class in questions:
                name = b".".join(labels)
                if query_class != 1 or name not in names:
                    continue
                hashed = hashlib.sha256(name).hexdigest()
                counts[hashed, kind] += 1
                first, last = times.get(hashed, (timestamp, timestamp))
                times[hashed] = (min(first, timestamp), max(last, timestamp))
        facts = reader.facts()
        total_bytes += facts["bytes"]
        if total_bytes > pcapng.MAX_BYTES:
            raise CaptureError("capture_size_limit")
        captures.append(facts)
    queries = []
    for name in sorted(names):
        hashed = hashlib.sha256(name).hexdigest()
        by_type = {str(kind): count for (item, kind), count in sorted(counts.items()) if item == hashed}
        first, last = times.get(hashed, (None, None))
        queries.append({"qname_sha256": hashed, "outbound_question_records": sum(by_type.values()),
                        "by_query_type": by_type, "first_observed_unix_ns": first, "last_observed_unix_ns": last})
    return {"queries": queries, "captures": captures, "opaque_packets": dict(unknown),
            "host_nic_identity_count": len(macs), "parsed_all_capture_files": bool(captures)}


class WNode(C.Structure):
    _fields_ = [("size", C.c_uint32), ("provider", C.c_uint32), ("context", C.c_uint64),
                ("timestamp", C.c_int64), ("guid", C.c_ubyte * 16),
                ("clock", C.c_uint32), ("flags", C.c_uint32)]


class TraceProperties(C.Structure):
    _fields_ = [("wnode", WNode)] + [(name, C.c_uint32) for name in (
        "buffer_kb", "minimum_buffers", "maximum_buffers", "maximum_file_mb", "log_mode", "flush_timer",
        "enable_flags", "age", "buffer_count", "free_buffers", "events_lost", "buffers_written",
        "log_buffers_lost", "realtime_buffers_lost")] + [("logger_thread", C.c_void_p),
        ("file_offset", C.c_uint32), ("logger_offset", C.c_uint32)]


class Native:
    def __init__(self):
        if sys.platform != "win32" or os.environ.get("GITHUB_ACTIONS") != "true" or os.environ.get("RULEPROXY_DISPOSABLE_CI") != "1":
            raise CaptureError("disposable_windows_ci_required")
        self.system = Path(os.environ["SystemRoot"]) / "System32"

    def command(self, program, args, code, timeout=60):
        try:
            result = subprocess.run([str(program), *map(str, args)], capture_output=True, timeout=timeout)
            if result.returncode:
                raise CaptureError(code)
            return result.stdout
        except (OSError, subprocess.TimeoutExpired):
            raise CaptureError(code) from None

    def pktmon(self, *args):
        return self.command(self.system / "pktmon.exe", args, "pktmon_" + str(args[0]) + "_failed", timeout=120)

    def protect(self, directory):
        self.command(self.system / "icacls.exe", [directory, "/inheritance:r", "/grant:r",
            "*S-1-5-18:(OI)(CI)F", "*S-1-5-32-544:(OI)(CI)F"], "private_capture_acl_failed")

    def macs(self):
        command = ("$ErrorActionPreference='Stop';[Console]::OutputEncoding=[Text.UTF8Encoding]::new();"
                   "ConvertTo-Json -Compress -InputObject @(Get-NetAdapter -IncludeHidden | "
                   "Where-Object Status -eq Up | Select-Object -ExpandProperty MacAddress)")
        raw = self.command(self.system / "WindowsPowerShell/v1.0/powershell.exe",
            ["-NoProfile", "-NonInteractive", "-Command", command], "nic_inventory_failed")
        try:
            values = json.loads(raw.decode("utf-8-sig"))
            return sorted({value.lower() for value in values if isinstance(value, str)
                           and re.fullmatch(r"(?:[0-9a-fA-F]{2}-){5}[0-9a-fA-F]{2}", value)
                           and value != "00-00-00-00-00-00"})
        except (ValueError, TypeError):
            raise CaptureError("nic_inventory_failed") from None

    def trace(self, flush=False):
        buffer = C.create_string_buffer(C.sizeof(TraceProperties) + 4096 * 2)
        props = TraceProperties.from_buffer(buffer)
        props.wnode.size = len(buffer)
        props.wnode.flags = 0x00020000  # WNODE_FLAG_TRACED_GUID
        props.logger_offset = C.sizeof(TraceProperties)
        props.file_offset = props.logger_offset + 2048
        api = C.WinDLL("advapi32", use_last_error=True).ControlTraceW
        api.argtypes = [C.c_uint64, C.c_wchar_p, C.c_void_p, C.c_uint32]
        api.restype = C.c_uint32
        code = api(0, "PktMon", buffer, 3 if flush else 0)  # FLUSH / QUERY
        if code == 4201:  # ERROR_WMI_INSTANCE_NOT_FOUND
            return None
        if code:
            raise CaptureError("etw_flush_failed" if flush else "etw_query_failed")
        if not C.sizeof(TraceProperties) <= props.file_offset <= len(buffer) - 2 or props.file_offset % 2:
            raise CaptureError("etw_filename_invalid")
        raw = bytes(buffer)[props.file_offset:]
        end = next((index for index in range(0, len(raw) - 1, 2) if raw[index:index + 2] == b"\0\0"), None)
        if end is None:
            raise CaptureError("etw_filename_invalid")
        return {"logfile": raw[:end].decode("utf-16-le"), "context": props.wnode.context,
                "log_mode": props.log_mode, "buffers_written": props.buffers_written,
                **{name: getattr(props, name) for name in LOSS_FIELDS}}


def write_json(path, value):
    path = Path(path)
    raw = (json.dumps(value, sort_keys=True, indent=2, ensure_ascii=True) + "\n").encode("ascii")
    with path.open("wb") as output:
        output.write(raw)
        output.flush()
        os.fsync(output.fileno())


def read_json(path, maximum=MAX_REPORT):
    path = Path(path)
    if not path.is_file() or path.is_symlink() or path.stat().st_size > maximum:
        raise CaptureError("input_file_invalid")
    try:
        return json.loads(path.read_text(encoding="utf-8-sig"))
    except (OSError, ValueError):
        raise CaptureError("input_json_invalid") from None


def owned_trace(trace, private):
    if not isinstance(trace, dict):
        return False
    path = Path(trace["logfile"])
    return path.parent.resolve() == private.resolve() and path.name.startswith("capture") and path.suffix.lower() == ".etl"


def start(state_path, native=None):
    native = native or Native()
    state_path = Path(state_path).absolute()
    if state_path.exists() or state_path.is_symlink() or not state_path.parent.is_dir():
        raise CaptureError("state_path_not_new")
    if native.trace() is not None:
        raise CaptureError("existing_pktmon_session")
    private = state_path.parent / (PRIVATE_PREFIX + uuid.uuid4().hex)
    private.mkdir()
    try:
        native.protect(private)
        macs = native.macs()
        if not macs:
            raise CaptureError("host_nic_identity_missing")
        # Publish private cleanup intent before pktmon can create a session.
        state = {"version": 1, "private": str(private), "macs": macs,
                 "start_confirmed_unix_ns": 0, "start_trace": None}
        write_json(state_path, state)
        # The dedicated-host gate is explicit because pktmon filters are global.
        native.pktmon("filter", "remove")
        native.pktmon("filter", "add", "RuleProxyPrimaryDNS", "-p", "53")
        native.pktmon("start", "--capture", "--comp", "nics", "--type", "flow", "--pkt-size", "0",
                      "--flags", "0x013", "--file-name", private / "capture.etl", "--file-size", "64",
                      "--log-mode", "multi-file")
        trace = native.trace()
        if not owned_trace(trace, private):
            raise CaptureError("capture_session_identity_unconfirmed")
        state.update(start_confirmed_unix_ns=time.time_ns(), start_trace=trace)
        write_json(state_path, state)
        return {"started": True, "scope": "positive_outbound_udp_dns_observations_only"}
    except Exception:
        try:
            # A timeout can occur after StartService/ETW already committed.
            # Conversely, never stop a different session after an identity race.
            if owned_trace(native.trace(), private):
                native.pktmon("stop")
        except Exception:
            pass
        try:
            shutil.rmtree(private)
        except OSError:
            raise CaptureError("capture_start_cleanup_incomplete") from None
        state_path.unlink(missing_ok=True)
        raise


def load_state(state_path):
    state_path = Path(state_path).absolute()
    state = read_json(state_path, 65536)
    private = Path(state["private"])
    if (state.get("version") != 1 or private.parent.resolve() != state_path.parent.resolve()
            or not re.fullmatch(re.escape(PRIVATE_PREFIX) + r"[0-9a-f]{32}", private.name)
            or private.is_symlink() or getattr(private.lstat(), "st_file_attributes", 0) & 0x400):
        raise CaptureError("private_capture_path_invalid")
    return state, private


def capture_files(private):
    files = sorted(private.glob("capture*.etl"))
    if not 1 <= len(files) <= 16 or any(path.is_symlink() or not path.is_file() for path in files):
        raise CaptureError("capture_files_invalid")
    if len(files) == 1 and files[0].name == "capture.etl":
        return files
    numbers = []
    for path in files:
        match = re.fullmatch(r"capture(\d+)\.etl", path.name)
        if not match:
            raise CaptureError("capture_rotation_name_unknown")
        numbers.append(int(match[1]))
    if sorted(numbers) != list(range(1, len(files) + 1)):
        raise CaptureError("capture_rotation_gap")
    return [path for _, path in sorted(zip(numbers, files))]


def coverage(state, end_trace, flushed_ns, report, parsed, stopped):
    def ns(value):
        return int(value * 1e9) if type(value) in (int, float) and math.isfinite(value) and value >= 0 else None
    report_start, report_end = ns(report.get("started")), ns(report.get("finished"))
    loss = {name: end_trace.get(name) for name in LOSS_FIELDS} if end_trace else None
    mode = end_trace.get("log_mode") if end_trace else None
    no_loss = bool(loss and all(type(value) is int and value == 0 for value in loss.values()))
    multi = type(mode) is int and bool(mode & 8) and not mode & 2
    bracketed = (state["start_confirmed_unix_ns"] > 0 and report_start is not None and report_end is not None and flushed_ns is not None
                 and state["start_confirmed_unix_ns"] <= report_start <= report_end <= flushed_ns)
    return {"capture_start_confirmed_unix_ns": state["start_confirmed_unix_ns"],
            "prestop_flush_started_unix_ns": flushed_ns, "report_started_unix_ns": report_start,
            "report_finished_unix_ns": report_end, "report_window_bracketed": bool(bracketed),
            "etl_loss_counters_after_flush": loss, "etl_loss_counters_zero_through_flush": no_loss,
            "loss_after_last_query": "unknown", "multi_file_non_circular_confirmed": bool(multi),
            "all_rotations_converted_and_parsed": bool(parsed), "pktmon_stop_confirmed": bool(stopped),
            "no_capture_loss_proven": False}


def finish(state_path, report_path=None, output_path=None, *, native=None, abort=False):
    native = native or Native()
    state, private = load_state(state_path)
    result = {"schema_version": 1, "scope": "positive_outbound_udp_dns_observations_only",
              "privacy_qualified": False, "absence_proven": False, "process_attribution_proven": False,
              "network_delivery_proven": False, "queries": [], "errors": [], "status": "incomplete"}
    stopped, parsed, end_trace, flushed_ns, report = False, False, None, None, {}
    try:
        trace = native.trace()
        if not owned_trace(trace, private):
            raise CaptureError("capture_session_identity_lost")
        try:
            flushed_ns = time.time_ns()
            if not owned_trace(native.trace(flush=True), private):
                raise CaptureError("capture_flush_identity_lost")
            end_trace = native.trace()
            if not owned_trace(end_trace, private):
                raise CaptureError("capture_query_identity_lost")
        except CaptureError as exc:
            result["errors"].append(str(exc))
            flushed_ns, end_trace = None, None
        native.pktmon("stop")
        stopped = True
        try:
            native.pktmon("filter", "remove")
        except CaptureError as exc:
            result["errors"].append(str(exc))
        if not abort:
            report = read_json(report_path)
            if not isinstance(report, dict):
                raise CaptureError("report_object_required")
            result["report_sha256"] = hashlib.sha256(Path(report_path).read_bytes()).hexdigest()
            files = capture_files(private)
            pcaps = []
            for number, path in enumerate(files):
                converted = private / f"converted{number}.pcapng"
                native.pktmon("etl2pcap", path, "--out", converted)
                pcaps.append(converted)
            streams = []
            try:
                for path in pcaps:
                    streams.append(path.open("rb"))
                result.update(observe(streams, report, state["macs"]))
                parsed = True
            finally:
                for stream in streams:
                    stream.close()
            result["status"] = "observed" if any(row["outbound_question_records"] for row in result["queries"]) else "no_matching_queries_observed"
    except Exception as exc:
        result["errors"].append(str(exc) if isinstance(exc, CaptureError) else "capture_processing_failed")
    finally:
        if not stopped:
            try:
                if owned_trace(native.trace(), private):
                    native.pktmon("stop")
                    stopped = True
            except Exception:
                result["errors"].append("capture_cleanup_stop_failed")
        try:
            shutil.rmtree(private)
            result["raw_capture_removed"] = not private.exists()
        except OSError:
            result["raw_capture_removed"] = False
            result["errors"].append("raw_capture_cleanup_failed")
        # Retain recoverable private state when raw cleanup could not complete.
        if result["raw_capture_removed"]:
            Path(state_path).unlink(missing_ok=True)
        result["coverage"] = coverage(state, end_trace, flushed_ns, report, parsed, stopped)
        if output_path is not None:
            write_json(output_path, result)
    return result


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("action", choices=("start", "finish", "abort"))
    parser.add_argument("--state", required=True)
    parser.add_argument("--report")
    parser.add_argument("--output")
    args = parser.parse_args()
    try:
        if args.action == "start":
            result = start(args.state)
        else:
            if args.action == "finish" and (not args.report or not args.output):
                raise CaptureError("finish_report_and_output_required")
            result = finish(args.state, args.report, args.output, abort=args.action == "abort")
        # Never print paths, native tool output, exception text, names, or frames.
        print(json.dumps({"action": args.action, "started": result.get("started"),
                          "status": result.get("status"), "errors": result.get("errors", [])}))
        return int(bool(result.get("errors")))
    except Exception as exc:
        code = str(exc) if isinstance(exc, CaptureError) else "capture_operation_failed"
        print(json.dumps({"action": args.action, "error": code}))
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
