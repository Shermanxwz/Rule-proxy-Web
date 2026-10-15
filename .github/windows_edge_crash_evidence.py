"""Read only crash facts for an exact, previously captured stock Edge generation.

The contained job wrapper uses capture_held_edge_identity and never reads logs.
The outside controller calls collect_crash_events only with its nonce-bound
wrapper report. JSON identity input is correlation input, not new attestation.
No WER settings, dump configuration, ACLs or browser sandbox flags are changed.
"""
from __future__ import annotations

import argparse
import ctypes
import datetime as dt
import hashlib
import json
import ntpath
import os
from pathlib import Path
import re
import subprocess
import sys
import uuid
import xml.etree.ElementTree as ET
from xml.sax.saxutils import escape


IDENTITY_SCOPE = "borrowed_popen_edge_process_handle"
EVENT_SCOPE = "provided_exact_edge_generation_application_events"
MAX_XML_BYTES = 65536
MAX_EVENTS = 32
MAX_WINDOW_SECONDS = 180
READER_TIMEOUT_SECONDS = 12
_RECOVERY_READERS = []
_STAGES = frozenset({"identity_source", "identity_handle", "identity_pid", "identity_creation",
    "identity_image", "identity_recheck", "identity_validate", "window_validate", "event_api_bind",
    "event_query", "event_next", "event_render", "event_render_size", "event_render_result",
    "event_render_xml", "event_close", "event_xml", "reader_start",
    "reader_wait", "reader_stop", "reader_handle_close", "reader_report"})
_NS = "{http://schemas.microsoft.com/win/2004/08/events/event}"


def failure_facts(error, stage):
    if stage not in _STAGES:
        stage = "identity_validate"
    name = type(error).__name__
    if name not in {"PermissionError", "FileNotFoundError", "OSError", "RuntimeError",
                    "TimeoutError", "ValueError", "TypeError", "AttributeError", "SourceUnavailable"}:
        name = "Exception"
    facts = {"stage": stage, "error_type": name}
    for key in ("errno", "winerror"):
        value = getattr(error, key, None)
        facts[key] = value if type(value) is int and 0 <= value <= 0xffffffff else None
    return facts


def incomplete_identity(error=None, stage="identity_source", *, error_type=None):
    facts = failure_facts(error or RuntimeError(), stage)
    if error_type == "SourceUnavailable":
        facts["error_type"] = error_type
    return {"status": "incomplete", "scope": IDENTITY_SCOPE, "pid": None, "process_created": None,
            "image_sha256": None, "held_handle_verified": False, "error": facts}


def image_key(value):
    # The original prepared Edge path is canonicalized outside PSEC already.
    # Do not introduce a normalized Mount Manager query inside the container.
    value = os.fspath(value)
    if value.startswith("\\\\?\\"):
        value = value[4:]
    drive, tail = ntpath.splitdrive(value)
    if not re.fullmatch(r"[a-zA-Z]:", drive) or not tail.startswith("\\") or "\0" in value:
        raise ValueError("a full local Windows process image is required")
    return ntpath.normcase(ntpath.normpath(value))


class ProcessIdentityApi:
    class FileTime(ctypes.Structure):
        _fields_ = [("low", ctypes.c_uint32), ("high", ctypes.c_uint32)]

    def __init__(self):
        if os.name != "nt":
            raise OSError("Windows process APIs are required")
        self.kernel = ctypes.WinDLL("kernel32", use_last_error=True)
        self.kernel.GetProcessId.argtypes, self.kernel.GetProcessId.restype = [ctypes.c_void_p], ctypes.c_uint32
        self.kernel.GetProcessTimes.argtypes = [ctypes.c_void_p] + [ctypes.POINTER(self.FileTime)] * 4
        self.kernel.GetProcessTimes.restype = ctypes.c_int32
        self.kernel.QueryFullProcessImageNameW.argtypes = [ctypes.c_void_p, ctypes.c_uint32,
                                                         ctypes.c_wchar_p, ctypes.POINTER(ctypes.c_uint32)]
        self.kernel.QueryFullProcessImageNameW.restype = ctypes.c_int32

    def pid(self, handle):
        value = self.kernel.GetProcessId(handle)
        if not value:
            raise ctypes.WinError(ctypes.get_last_error())
        return int(value)

    def created(self, handle):
        values = [self.FileTime() for _ in range(4)]
        if not self.kernel.GetProcessTimes(handle, *(ctypes.byref(value) for value in values)):
            raise ctypes.WinError(ctypes.get_last_error())
        return int(values[0].low) | (int(values[0].high) << 32)

    def image(self, handle):
        value, size = ctypes.create_unicode_buffer(32768), ctypes.c_uint32(32768)
        if not self.kernel.QueryFullProcessImageNameW(handle, 0, value, ctypes.byref(size)):
            raise ctypes.WinError(ctypes.get_last_error())
        if not 0 < size.value < len(value):
            raise ValueError("process image exceeded its bound")
        return value.value


def capture_held_edge_identity(process, expected_edge, api=None):
    """Borrow Popen's handle; never reopen a PID, terminate, wait or close it."""
    stage = "identity_handle"
    try:
        api = ProcessIdentityApi() if api is None else api
        handle, pid = int(process._handle), process.pid
        if type(pid) is not int or not 0 < pid <= 0xffffffff or not handle:
            raise ValueError("a borrowed Popen process generation is required")
        stage = "identity_pid"
        if api.pid(handle) != pid:
            raise ValueError("borrowed process PID mismatch")
        stage = "identity_creation"
        created = api.created(handle)
        if type(created) is not int or not 0 < created < 2**64:
            raise ValueError("borrowed process creation time was unavailable")
        stage = "identity_image"
        expected, actual = image_key(expected_edge), image_key(api.image(handle))
        if ntpath.basename(expected) != "msedge.exe" or actual != expected:
            raise ValueError("borrowed process image did not match the prepared stock Edge image")
        stage = "identity_recheck"
        if api.pid(handle) != pid or api.created(handle) != created:
            raise ValueError("borrowed process generation changed")
        return {"status": "observed", "scope": IDENTITY_SCOPE, "pid": pid, "process_created": created,
                "image_sha256": hashlib.sha256(actual.encode("utf-8")).hexdigest(),
                "held_handle_verified": True, "error": None}
    except Exception as error:
        return incomplete_identity(error, stage)


def validate_identity(value):
    fields = {"status", "scope", "pid", "process_created", "image_sha256", "held_handle_verified", "error"}
    if not isinstance(value, dict) or set(value) != fields or value["scope"] != IDENTITY_SCOPE:
        raise ValueError("invalid fixed Edge identity structure")
    if value["status"] == "incomplete":
        error = value["error"]
        if (any(value[key] is not None for key in ("pid", "process_created", "image_sha256"))
                or value["held_handle_verified"] is not False or not isinstance(error, dict)
                or set(error) != {"stage", "error_type", "errno", "winerror"}
                or type(error.get("stage")) is not str or error["stage"] not in _STAGES
                or type(error.get("error_type")) is not str or error["error_type"] not in {"PermissionError", "FileNotFoundError", "OSError", "RuntimeError",
                    "TimeoutError", "ValueError", "TypeError", "AttributeError", "SourceUnavailable", "Exception"}
                or any(error[key] is not None and (type(error[key]) is not int or not 0 <= error[key] <= 0xffffffff)
                       for key in ("errno", "winerror"))):
            raise ValueError("invalid incomplete Edge identity")
        return value
    if (value["status"] != "observed" or type(value["pid"]) is not int or not 0 < value["pid"] <= 0xffffffff
            or type(value["process_created"]) is not int or not 0 < value["process_created"] < 2**64
            or not isinstance(value["image_sha256"], str) or not re.fullmatch(r"[0-9a-f]{64}", value["image_sha256"])
            or value["held_handle_verified"] is not True or value["error"] is not None):
        raise ValueError("invalid observed Edge identity")
    return value


def _utc(value):
    if isinstance(value, str) and re.fullmatch(r"\d{4}-\d\d-\d\dT\d\d:\d\d:\d\d(?:\.\d{1,7})?Z", value):
        return dt.datetime.fromisoformat(value[:-1] + "+00:00")
    if isinstance(value, dt.datetime) and value.tzinfo is not None and value.utcoffset() == dt.timedelta():
        return value
    raise ValueError("a bounded UTC timestamp is required")


def event_window(identity, started_utc=None, ended_utc=None):
    validate_identity(identity)
    if identity["status"] != "observed":
        raise ValueError("no captured Edge generation is available")
    born = dt.datetime(1601, 1, 1, tzinfo=dt.timezone.utc) + dt.timedelta(microseconds=identity["process_created"] // 10)
    start = born - dt.timedelta(seconds=2) if started_utc is None else _utc(started_utc)
    end = dt.datetime.now(dt.timezone.utc) if ended_utc is None else _utc(ended_utc)
    if not start <= born <= end or not 0 < (end - start).total_seconds() <= MAX_WINDOW_SECONDS:
        raise ValueError("Edge event query must use only the current launch's narrow time window")
    return start, end


def initial_result():
    return {"schema_version": 1, "status": "incomplete", "scope": EVENT_SCOPE,
            "collector_re_attested_identity": False, "events": [], "wer_reports": [],
            "render_observations": [],
            "reader_cleanup_proven": True, "acceptance_passed": False, "full_acceptance_passed": False,
            "real_node_passed": False, "browser_sandbox_weakened": False, "host_configuration_changed": False,
            "limitations": ["Only matching Application Error 1000 and its ReportId-linked WER 1001 are read.",
                            "No event is not crash absence; application crash reporting can be disabled or delayed.",
                            "Faulting module and exception do not establish the crash root cause."]}


def _number(text, bits):
    if not isinstance(text, str) or not re.fullmatch(r"(?:0[xX][0-9a-fA-F]+|[0-9]+)", text):
        raise ValueError("invalid event process generation field")
    value = int(text, 16 if text.lower().startswith("0x") else 10)
    if not 0 < value < 2**bits:
        raise ValueError("invalid event process generation field")
    return value


def _guid(text):
    return str(uuid.UUID(text)) if isinstance(text, str) and re.fullmatch(r"\{?[0-9A-Fa-f-]{36}\}?", text) else None


def _event(xml):
    if not isinstance(xml, str) or len(xml.encode("utf-8")) > MAX_XML_BYTES or "<!" in xml:
        raise ValueError("event XML exceeded its fixed format or byte limit")
    root = ET.fromstring(xml)
    if root.tag != _NS + "Event":
        raise ValueError("invalid Windows event namespace")
    system, data = root.find(_NS + "System"), root.find(_NS + "EventData")
    if system is None or data is None or system.findtext(_NS + "Channel") != "Application":
        raise ValueError("invalid Application event structure")
    provider = system.find(_NS + "Provider")
    timestamp = system.find(_NS + "TimeCreated")
    if provider is None or timestamp is None:
        raise ValueError("event provider/time was omitted")
    fields = {}
    for row in data:
        name = row.get("Name")
        if row.tag != _NS + "Data" or not name or name in fields or len(row):
            raise ValueError("event data is ambiguous")
        fields[name] = row.text or ""
    return provider.get("Name"), system.findtext(_NS + "EventID"), _utc(timestamp.get("SystemTime")), fields


def correlate_events(identity, xml_records, started_utc=None, ended_utc=None):
    """Sanitize only exact PID + FILETIME + image matches; never use System PID."""
    result = initial_result()
    try:
        validate_identity(identity)
        if identity["status"] != "observed":
            result["reason"] = "edge_identity_incomplete"
            return result
        start, end = event_window(identity, started_utc, ended_utc)
        if not isinstance(xml_records, list) or len(xml_records) > MAX_EVENTS:
            raise ValueError("event record limit exceeded")
        parsed = [_event(xml) for xml in xml_records]
        reports = set()
        for provider, event_id, timestamp, fields in parsed:
            if provider != "Application Error" or event_id != "1000" or not start <= timestamp <= end:
                continue
            if (_number(fields.get("ProcessId"), 32) != identity["pid"]
                    or _number(fields.get("ProcessCreationTime"), 64) != identity["process_created"]):
                continue
            if (fields.get("AppName", "").casefold() != "msedge.exe"
                    or hashlib.sha256(image_key(fields.get("AppPath", "")).encode("utf-8")).hexdigest() != identity["image_sha256"]):
                raise ValueError("event image conflicts with the captured process generation")
            module, version = fields.get("ModuleName", ""), fields.get("ModuleVersion", "")
            exception, offset = fields.get("ExceptionCode", ""), fields.get("FaultingOffset", "")
            if not re.fullmatch(r"(?:0x)?[0-9a-fA-F]{8}", exception) or not re.fullmatch(r"(?:0x)?[0-9a-fA-F]{1,16}", offset):
                raise ValueError("crash exception or offset was not present")
            report_id = _guid(fields.get("IntegratorReportId"))
            if report_id:
                reports.add(report_id)
            result["events"].append({"event_id": 1000, "pid": identity["pid"], "process_created": identity["process_created"],
                "module": module if re.fullmatch(r"[a-zA-Z0-9_.-]{1,128}", module) else None,
                "module_version": version if re.fullmatch(r"[0-9.]{1,64}", version) else None,
                "exception_code": f"0x{int(exception, 16):08X}", "fault_offset": f"0x{int(offset, 16):016X}",
                "report_id": report_id})
        for provider, event_id, timestamp, fields in parsed:
            report_id = _guid(fields.get("ReportId"))
            if provider == "Windows Error Reporting" and event_id == "1001" and start <= timestamp <= end and report_id in reports:
                name = fields.get("EventName")
                result["wer_reports"].append({"event_id": 1001, "report_id": report_id,
                    "event_name": name if name in {"APPCRASH", "BEX", "BEX64", "MoAppCrash"} else "other",
                    "association": "matched_application_error_integrator_report_id"})
        result["status"] = "crash_evidence_observed" if result["events"] else "not_observed"
    except Exception as error:
        result["failure"] = failure_facts(error, "event_xml")
    return result


def _formats(value, bits):
    return sorted({str(value), f"0x{value:x}", f"0x{value:X}", f"0x{value:0{bits // 4}x}", f"0x{value:0{bits // 4}X}"})


def event_query(identity, start, end, report_ids=()):
    """OS-side exact-generation filtering; never a provider-wide log dump."""
    start, end = _utc(start), _utc(end)
    validate_identity(identity)
    if identity["status"] != "observed" or not 0 < (end - start).total_seconds() <= MAX_WINDOW_SECONDS:
        raise ValueError("invalid narrow event query")
    when = f"TimeCreated[@SystemTime >= '{start.isoformat().replace('+00:00', 'Z')}' and @SystemTime <= '{end.isoformat().replace('+00:00', 'Z')}']"
    if report_ids:
        if len(report_ids) > 8 or any(_guid(value) != value for value in report_ids):
            raise ValueError("invalid bounded matched report identifiers")
        selectors = []
        for report in sorted(set(report_ids)):
            matches = " or ".join(f"Data[@Name='ReportId']='{value}'" for value in (report, report.upper(), "{" + report + "}", "{" + report.upper() + "}"))
            selectors.append(f"*[System[Provider[@Name='Windows Error Reporting'] and EventID=1001 and {when}] and EventData[{matches}]]")
    else:
        created = " or ".join(f"Data[@Name='ProcessCreationTime']='{value}'" for value in _formats(identity["process_created"], 64))
        # Separate selectors keep each XPath below the documented 20-expression
        # threshold, while every selector still requires the full generation.
        selectors = [f"*[System[Provider[@Name='Application Error'] and EventID=1000 and {when}] and EventData[Data[@Name='ProcessId']='{pid}' and ({created})]]"
                     for pid in _formats(identity["pid"], 32)]
    return '<QueryList><Query Id="0" Path="Application">' + "".join('<Select Path="Application">' + escape(value) + '</Select>' for value in selectors) + '</Query></QueryList>'


class EventLogApi:
    def __init__(self, api=None, last_error=None, error_factory=None):
        if api is None and os.name != "nt":
            raise OSError("Windows event APIs are required")
        self.api = ctypes.WinDLL("wevtapi", use_last_error=True) if api is None else api
        self.last_error = ctypes.get_last_error if last_error is None else last_error
        self.error_factory = ctypes.WinError if error_factory is None else error_factory
        handle, dword = ctypes.c_void_p, ctypes.c_uint32
        self.api.EvtQuery.argtypes, self.api.EvtQuery.restype = [handle, ctypes.c_wchar_p, ctypes.c_wchar_p, dword], handle
        self.api.EvtNext.argtypes = [handle, dword, ctypes.POINTER(handle), dword, dword, ctypes.POINTER(dword)]
        self.api.EvtNext.restype = ctypes.c_int32
        self.api.EvtRender.argtypes = [handle, handle, dword, dword, handle, ctypes.POINTER(dword), ctypes.POINTER(dword)]
        self.api.EvtRender.restype = ctypes.c_int32
        self.api.EvtClose.argtypes, self.api.EvtClose.restype = [handle], ctypes.c_int32
        self.handles = []
        self.render_observations = []
        self.stage = "event_api_bind"

    def _close(self, handle):
        self.stage = "event_close"
        if not self.api.EvtClose(handle):
            raise self.error_factory(self.last_error())
        self.handles.remove(handle)

    def close(self):
        failure = None
        for handle in list(self.handles):
            try:
                self._close(handle)
            except Exception as error:
                failure = failure or error
        if failure is not None:
            raise failure

    def query(self, expression):
        self.stage = "event_query"
        query = self.api.EvtQuery(None, "Application", expression, 1 | 0x200)
        if not query:
            raise self.error_factory(self.last_error())
        self.handles.append(query)
        records = []
        while True:
            self.stage = "event_next"
            events, returned = (ctypes.c_void_p * 1)(), ctypes.c_uint32()
            if not self.api.EvtNext(query, 1, events, 1000, 0, ctypes.byref(returned)):
                error = self.last_error()
                if error == 259:  # ERROR_NO_MORE_ITEMS, never a timeout success.
                    break
                raise self.error_factory(error)
            event = events[0]
            if event:
                self.handles.append(event)
            if returned.value != 1 or not event:
                raise ValueError("event API returned an invalid handle count")
            if len(records) >= MAX_EVENTS:
                raise ValueError("event record limit exceeded")
            records.append(self.render_event_xml(event))
            self._close(event)
        self._close(query)
        return records

    def render_event_xml(self, event):
        """Follow EvtRender's byte-count probe/allocation flow, without raw output."""
        self.stage = "event_render_size"
        used, count = ctypes.c_uint32(), ctypes.c_uint32()
        facts = {"render_flags": 1, "probe_okay": None, "probe_last_error": None,
                 "required_bytes": None, "probe_property_count": None, "render_okay": None,
                 "render_last_error": None, "used_bytes": None, "capacity_bytes": None,
                 "property_count": None, "utf16_complete": False, "xml_complete": False}
        self.render_observations.append(facts)
        okay = bool(self.api.EvtRender(None, event, 1, 0, None, ctypes.byref(used), ctypes.byref(count)))
        error = None if okay else int(self.last_error())
        facts.update(probe_okay=okay, probe_last_error=error,
                     required_bytes=int(used.value), probe_property_count=int(count.value))
        if okay or error != 122 or not 0 < used.value <= MAX_XML_BYTES or used.value % 2:
            raise ValueError("event render size could not be bounded")
        # EvtRender BufferSize/BufferUsed are bytes, including the UTF-16 NUL.
        # This equals the official malloc(requiredBytes) example and does not
        # depend on Python's host wchar element size.
        value = ctypes.create_string_buffer(used.value)
        capacity = ctypes.sizeof(value)
        facts["capacity_bytes"] = capacity
        self.stage = "event_render_result"
        okay = bool(self.api.EvtRender(None, event, 1, capacity, value, ctypes.byref(used), ctypes.byref(count)))
        error = None if okay else int(self.last_error())
        facts.update(render_okay=okay, render_last_error=error,
                     used_bytes=int(used.value), property_count=int(count.value))
        if not okay:
            raise self.error_factory(error)
        # The documented PropertyCount is zero outside EventValues. Preserve
        # that contract; telemetry distinguishes it from any size failure.
        if not 0 < used.value <= capacity or used.value % 2 or count.value != 0:
            raise ValueError("event renderer returned an invalid XML size or property count")
        self.stage = "event_render_xml"
        raw = value.raw[:used.value]
        if not raw.endswith(b"\0\0"):
            raise ValueError("rendered event XML was not terminated")
        xml = raw[:-2].decode("utf-16-le", errors="strict")
        if "\0" in xml:
            raise ValueError("rendered event XML contained an embedded terminator")
        facts["utf16_complete"] = True
        _event(xml)  # Complete XML + namespace/shape before retaining a record.
        facts["xml_complete"] = True
        return xml


def _read_events(identity, start, end):
    result, reader = initial_result(), None
    try:
        reader = EventLogApi()
        records = reader.query(event_query(identity, start, end))
        first = correlate_events(identity, records, start, end)
        if first["status"] == "incomplete":
            result = first
            return result
        report_ids = {event["report_id"] for event in first["events"] if event["report_id"]}
        if report_ids:
            records += reader.query(event_query(identity, start, end, report_ids))
        result = correlate_events(identity, records, start, end)
    except Exception as error:
        result["failure"] = failure_facts(error, reader.stage if reader is not None else "event_api_bind")
    finally:
        if reader is not None:
            # Numeric/boolean API facts only. XML stays private to this worker.
            result["render_observations"] = reader.render_observations[:MAX_EVENTS]
            try:
                reader.close()
            except Exception as error:
                result.update(status="incomplete", reader_cleanup_proven=False,
                              cleanup_error="EventHandlesCleanupUnproven", cleanup_failure=failure_facts(error, "event_close"))
    return result


def collect_crash_events(identity, started_utc=None, ended_utc=None, *, timeout=READER_TIMEOUT_SECONDS):
    """Bound even a stalled event service in this owned, disposable reader only."""
    result, process, cleanup = initial_result(), None, True
    try:
        validate_identity(identity)
        if identity["status"] != "observed":
            result["reason"] = "edge_identity_incomplete"
            return result
        start, end = event_window(identity, started_utc, ended_utc)
        if not 0 < timeout <= READER_TIMEOUT_SECONDS:
            raise ValueError("reader timeout exceeded its fixed bound")
        payload = json.dumps({"identity": identity, "start": start.isoformat().replace("+00:00", "Z"),
                              "end": end.isoformat().replace("+00:00", "Z")}).encode("ascii")
        process = subprocess.Popen([sys.executable, "-I", "-S", "-X", "utf8", __file__, "--event-worker"],
            stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.DEVNULL, close_fds=True)
        try:
            stdout, _ = process.communicate(payload, timeout=timeout)
        except subprocess.TimeoutExpired:
            result["failure"] = failure_facts(TimeoutError(), "reader_wait")
            return result
        if process.returncode != 0 or len(stdout) > 32768:
            raise ValueError("reader did not return a bounded diagnostic record")
        value = json.loads(stdout)
        if (not isinstance(value, dict) or value.get("schema_version") != 1 or value.get("scope") != EVENT_SCOPE
                or value.get("status") not in {"incomplete", "not_observed", "crash_evidence_observed"}
                or any(value.get(key) is not False for key in ("acceptance_passed", "full_acceptance_passed",
                    "real_node_passed", "browser_sandbox_weakened", "host_configuration_changed", "collector_re_attested_identity"))):
            raise ValueError("reader returned an invalid diagnostic record")
        result = value
    except Exception as error:
        result["failure"] = failure_facts(error, "reader_report")
    finally:
        if process is not None:
            try:
                if process.poll() is None:
                    process.kill()  # Only our event-reader Popen HANDLE; never MXC or Edge.
                    process.wait(timeout=2)
                for stream in (process.stdin, process.stdout, process.stderr):
                    if stream is not None:
                        stream.close()
                if hasattr(getattr(process, "_handle", None), "Close"):
                    process._handle.Close()
            except Exception as error:
                cleanup = False
                _RECOVERY_READERS.append(process)
                result.update(status="incomplete", cleanup_error="OwnedEventReaderCleanupUnproven",
                              cleanup_failure=failure_facts(error, "reader_stop"))
        result["reader_cleanup_proven"] = cleanup and result.get("reader_cleanup_proven") is True
    return result


def main(arguments=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--identity", type=Path)
    parser.add_argument("--report", type=Path)
    parser.add_argument("--event-worker", action="store_true", help=argparse.SUPPRESS)
    args = parser.parse_args(arguments)
    if args.event_worker:
        value = json.loads(sys.stdin.buffer.read(4097))
        if set(value) != {"identity", "start", "end"}:
            return 1
        result = _read_events(value["identity"], value["start"], value["end"])
        print(json.dumps(result, ensure_ascii=True), flush=True)
        return 0
    if args.identity is None or args.report is None:
        parser.error("--identity and --report are required")
    try:
        with args.identity.open("rb") as source:
            raw = source.read(4097)
        if len(raw) > 4096:
            raise ValueError("identity input limit")
        result = collect_crash_events(json.loads(raw))
    except Exception as error:
        result = initial_result()
        result["failure"] = failure_facts(error, "identity_validate")
    args.report.parent.mkdir(parents=True, exist_ok=True)
    args.report.write_text(json.dumps(result, ensure_ascii=True, indent=2) + "\n", encoding="utf-8")
    return 1 if result["status"] == "incomplete" else 0


if __name__ == "__main__":
    raise SystemExit(main())
