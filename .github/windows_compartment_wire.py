"""Positive DNS observations from a disposable VM; raw capture stays private.

Only hashes of random lab names are retained. This does not establish absence,
process attribution, or coverage of encrypted or TCP DNS.
"""
from collections import Counter
import hashlib
import importlib.util
import json
from pathlib import Path
import re
import struct
import threading

_spec = importlib.util.spec_from_file_location("compartment_dns_decoder",
    Path(__file__).with_name("windows_dns_packet_evidence.py"))
_dns = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(_dns)
_packet = _dns._packet
LAB_NAME = re.compile(rb"[0-9a-f]{32}\.1\.2\.3\.4\.sslip\.io\Z")


def observe(stream):
    reader = _packet.Reader(stream)
    header = reader.read(24)
    if header[:4] not in _packet.MAGICS:
        raise _packet.EvidenceError("unsupported_capture_format")
    endian, fractions = _packet.MAGICS[header[:4]]
    major, minor, _zone, _accuracy, snaplen, linktype = struct.unpack(endian + "HHiiII", header[4:])
    if (major, minor) != (2, 4) or linktype != 1 or not 14 <= snaplen <= _packet.MAX_FRAME_BYTES:
        raise _packet.EvidenceError("unsupported_capture_header")
    counts, opaque, records = Counter(), Counter(), 0
    while True:
        row = reader.read(16, allow_eof=True)
        if row is None:
            break
        records += 1
        if records > _packet.MAX_RECORDS:
            raise _packet.EvidenceError("capture_record_limit")
        _seconds, fraction, captured, original = struct.unpack(endian + "IIII", row)
        if fraction >= fractions or captured != original or not 14 <= captured <= snaplen:
            raise _packet.EvidenceError("truncated_or_invalid_capture_packet")
        questions, unknown = _dns.frame_questions(reader.read(captured))
        if unknown:
            opaque[unknown] += 1
        for labels, kind, query_class in questions:
            name = b".".join(labels)
            if query_class == 1 and LAB_NAME.fullmatch(name):
                counts[(hashlib.sha256(name).hexdigest(), kind)] += 1
        if len(counts) > 512:
            raise _packet.EvidenceError("lab_query_limit")
    return {"schema_version": 1, "scope": "positive_plaintext_dns_observations_only",
            "absence_proven": False, "process_attribution_proven": False,
            "capture_sha256": reader.digest.hexdigest(), "capture_bytes": reader.total,
            "records": records, "opaque_packets": dict(opaque),
            "queries": [{"qname_sha256": name, "query_type": kind, "count": count}
                        for (name, kind), count in sorted(counts.items())]}


class Capture:
    def __init__(self, qmp, work, artifacts):
        self.qmp, self.private, self.artifacts = qmp, Path(work) / "compartment-wire-private.pcap", Path(artifacts)
        self.lock = threading.RLock()
        self.state = "idle"

    def start(self, value):
        with self.lock:
            if self.state != "idle" or value != {}:
                raise RuntimeError("capture_start_state")
            self.state = "starting"
            try:
                with self.private.open("xb"):
                    pass
                self.private.chmod(0o600)
                self.qmp.execute("object-add", {"qom-type": "filter-dump", "id": "compartment_wire",
                    "netdev": "vmnet", "file": str(self.private)})
            except Exception:
                self.state = "failed"
                raise RuntimeError("capture_start_failed") from None
            self.state = "active"
            return {"started": True, "scope": "positive_observations_only"}

    def finish(self, value):
        with self.lock:
            if self.state != "active" or value != {}:
                raise RuntimeError("capture_finish_state")
            try:
                self.qmp.execute("object-del", {"id": "compartment_wire"})
                with self.private.open("rb") as stream:
                    result = observe(stream)
                self.state = "finished"
                (self.artifacts / "compartment-dns-wire-observations.json").write_text(
                    json.dumps(result, indent=2) + "\n", encoding="ascii")
                return result
            except Exception:
                self.state = "failed"
                raise RuntimeError("capture_finish_failed") from None
            finally:
                self.private.unlink(missing_ok=True)

    def abort(self, _reason=None):
        with self.lock:
            if self.state == "active":
                try:
                    self.qmp.execute("object-del", {"id": "compartment_wire"})
                finally:
                    self.state = "aborted"
            self.private.unlink(missing_ok=True)

    close = abort
