"""Observe nonce DNS questions in a private test-VM PCAP; never prove denial.

Scope: default test VM resolver configuration observed during the capture.
The caller must prove same-API actors executed, complete their operations,
cover any broker delay, stop/flush QEMU and reject its dump/write errors.
Worker exit alone does not prove broker completion. Raw captures/manifests
remain private. No DNS server, IP route, proxy or Windows setting is changed.

Manifest: schema_version=1, source_mac='52:54:00:12:34:56', probes=[{id,
group, role, api, qname, query_type?}]. Each group has four roles. A missing
query_type accepts IN A or AAAA, including getaddrinfo's default AF_UNSPEC.
"""
from __future__ import annotations

import argparse
import hashlib
import importlib.util
import io
import json
import os
from pathlib import Path
import re
import struct
import tempfile

_spec = importlib.util.spec_from_file_location("ruleproxy_dns_private_capture_format",
    Path(__file__).with_name("windows_packet_evidence.py"))
_packet = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(_packet)
EvidenceError = _packet.EvidenceError
SOURCE_MAC = "52:54:00:12:34:56"
APIS = ("getaddrinfo", "dns_a", "dns_aaaa")
ROLES = _packet.ROLES
DNS_PORTS = (53, 5353, 5355)
ENCRYPTED_PORTS = (443, 853)
SCOPE = "default_test_vm_resolver_configuration_observed"


def prepare_manifest(value):
    if (not isinstance(value, dict) or set(value) != {"schema_version", "source_mac", "probes"}
            or type(value["schema_version"]) is not int or value["schema_version"] != 1
            or not isinstance(value["source_mac"], str) or value["source_mac"].lower() != SOURCE_MAC
            or not isinstance(value["probes"], list) or not 4 <= len(value["probes"]) <= 48):
        raise EvidenceError("invalid_dns_manifest")
    probes, groups, ids, names = [], {}, set(), set()
    required = {"id", "group", "role", "api", "qname"}
    for item in value["probes"]:
        if (not isinstance(item, dict) or not required <= item.keys() or item.keys() - required - {"query_type"}
                or any(not isinstance(item[key], str) or not _packet.IDENTIFIER.fullmatch(item[key]) for key in ("id", "group"))
                or item["id"] in ids or item["api"] not in APIS or item["role"] not in ROLES
                or not isinstance(item["qname"], str)):
            raise EvidenceError("invalid_dns_probe")
        name = item["qname"].lower().removesuffix(".")
        expected = r"[0-9a-f]{32}\." + re.escape(item["api"].replace("_", "-")) + r"\." + re.escape(item["role"].replace("_", "-")) + r"\.ruleproxy-ci\.example\.com"
        if not re.fullmatch(expected, name) or name in names:
            raise EvidenceError("invalid_or_duplicate_dns_nonce_name")
        query_type = item.get("query_type")
        if query_type is not None and (type(query_type) is not int or query_type not in (1, 28)):
            raise EvidenceError("invalid_dns_query_type")
        if ((item["api"] == "dns_a" and query_type not in (None, 1))
                or (item["api"] == "dns_aaaa" and query_type not in (None, 28))):
            raise EvidenceError("dns_api_query_type_mismatch")
        if query_type is None and item["api"] != "getaddrinfo":
            query_type = 1 if item["api"] == "dns_a" else 28
        ids.add(item["id"]); names.add(name)
        probe = {"id": item["id"], "group": item["group"], "role": item["role"], "api": item["api"],
                 "name": tuple(label.encode("ascii") for label in name.split(".")), "query_type": query_type,
                 "count": 0, "first": None, "last": None}
        probes.append(probe)
        groups.setdefault(item["group"], []).append(probe)
    if len(groups) > 12:
        raise EvidenceError("dns_group_limit")
    for group in groups.values():
        if (len(group) != 4 or {p["role"] for p in group} != set(ROLES)
                or len({(p["api"], p["query_type"]) for p in group}) != 1):
            raise EvidenceError("dns_group_missing_roles_or_api_mismatch")
    canonical = json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=True).encode("ascii")
    return probes, groups, hashlib.sha256(canonical).hexdigest()


def read_name(message, start, boundaries=None):
    """Parse a complete bounded DNS name, including backward compression."""
    boundaries = set() if boundaries is None else boundaries
    position, end, labels, visited, length = start, None, [], set(), 1
    for _ in range(128):
        if position >= len(message) or position in visited:
            raise EvidenceError("malformed_dns_name")
        visited.add(position)
        size = message[position]
        if size & 0xC0 == 0xC0:
            if position + 1 >= len(message):
                raise EvidenceError("malformed_dns_pointer")
            target = ((size & 63) << 8) | message[position + 1]
            if not 12 <= target < position or target not in boundaries:
                raise EvidenceError("malformed_dns_pointer")
            end = position + 2 if end is None else end
            position = target
            continue
        if size & 0xC0 or size > 63 or position + 1 + size > len(message):
            raise EvidenceError("malformed_dns_label")
        boundaries.add(position)
        position += 1
        if not size:
            return tuple(labels), position if end is None else end
        length += size + 1
        if length > 255:
            raise EvidenceError("dns_name_length")
        labels.append(message[position:position + size].lower())
        position += size
    raise EvidenceError("dns_name_pointer_limit")


def dns_questions(message, destination_port):
    if len(message) < 12:
        raise EvidenceError("incomplete_dns_header")
    _, flags, questions, answers, authorities, additionals = struct.unpack_from("!6H", message)
    if flags & 0x8000:  # Responses are not outgoing resolver questions.
        return []
    if flags & 0x7800 or flags & 0x0200 or questions > 64 or answers + authorities + additionals > 512:
        raise EvidenceError("unsupported_dns_message")
    offset, result, boundaries = 12, [], set()
    for _ in range(questions):
        name, offset = read_name(message, offset, boundaries)
        if offset + 4 > len(message):
            raise EvidenceError("incomplete_dns_question")
        query_type, query_class = struct.unpack_from("!HH", message, offset)
        offset += 4
        # mDNS's question high bit requests a unicast response; class is IN.
        if destination_port == 5353:
            query_class &= 0x7FFF
        result.append((name, query_type, query_class))
    for _ in range(answers + authorities + additionals):
        _, offset = read_name(message, offset, boundaries)
        if offset + 10 > len(message):
            raise EvidenceError("incomplete_dns_resource_header")
        data_length = struct.unpack_from("!H", message, offset + 8)[0]
        offset += 10 + data_length
        if offset > len(message):
            raise EvidenceError("incomplete_dns_resource_data")
    if offset != len(message):
        raise EvidenceError("unparsed_dns_trailing_data")
    return result


def frame_questions(frame):
    """Peek transport identity; delegate complete Ethernet/IP/UDP validation."""
    if len(frame) < 14:
        raise EvidenceError("malformed_ethernet_header")
    mac = frame[6:12]
    if mac != bytes.fromhex(SOURCE_MAC.replace(":", "")):
        return [], None
    offset, ethertype, tags = 14, struct.unpack_from("!H", frame, 12)[0], 0
    while ethertype in (0x8100, 0x88A8, 0x9100):
        if len(frame) < offset + 4:
            raise EvidenceError("malformed_vlan_header")
        tags += 1
        if tags > 4:
            return [], "opaque_vm_vlan"
        ethertype = struct.unpack_from("!H", frame, offset + 2)[0]
        offset += 4
    fragmented = False
    if ethertype == 0x0800:
        if len(frame) < offset + 20:
            raise EvidenceError("malformed_ipv4_header")
        family, protocol, start = 4, frame[offset + 9], offset + (frame[offset] & 15) * 4
        source, destination = frame[offset + 12:offset + 16], frame[offset + 16:offset + 20]
        end = offset + struct.unpack_from("!H", frame, offset + 2)[0]
        fragmented = bool(struct.unpack_from("!H", frame, offset + 6)[0] & 0x3FFF)
    elif ethertype == 0x86DD:
        if len(frame) < offset + 40:
            raise EvidenceError("malformed_ipv6_header")
        family, protocol, start = 6, frame[offset + 6], offset + 40
        source, destination = frame[offset + 8:offset + 24], frame[offset + 24:offset + 40]
        end = start + struct.unpack_from("!H", frame, offset + 4)[0]
    else:
        return [], None
    port = struct.unpack_from("!H", frame, start + 2)[0] if len(frame) >= start + 4 else 0
    # Use the packet's own tuple only inside this decoder. Broker addresses
    # never constrain nonce matching or enter the summary.
    candidate = {"base": (mac, family, source, destination, port), "payload": b""}
    match, unknown = _packet.udp_frame(frame, [candidate])
    if unknown:
        return [], "opaque_vm_network_packet"
    if fragmented:
        return [], "opaque_vm_network_packet"
    if protocol == 6:
        if end - start < 20:
            return [], "opaque_dns_tcp_or_https"
        tcp_header = (frame[start + 12] >> 4) * 4
        if tcp_header < 20 or start + tcp_header > end:
            return [], "opaque_dns_tcp_or_https"
        if port in (53, 853, 443) and start + tcp_header == end:
            # A complete IP/TCP frame with no application bytes cannot carry a
            # DNS question. Count it separately; this is not process attribution.
            return [], "empty_tcp_payload"
        return [], "opaque_dns_tcp_or_https" if port in (53, 853, 443) or not port else None
    if match is None:
        return [], None
    if port in ENCRYPTED_PORTS:
        return [], "opaque_dns_encrypted_udp"
    if port not in DNS_PORTS:
        return [], None
    try:
        return dns_questions(match[1], port), None
    except EvidenceError:
        return [], "unparsed_dns_datagram"


def analyze_stream(stream, manifest):
    probes, groups, manifest_hash = prepare_manifest(manifest)
    reader = _packet.Reader(stream)
    header = reader.read(24)
    if header[:4] not in _packet.MAGICS:
        raise EvidenceError("unsupported_capture_format")
    endian, fraction_limit = _packet.MAGICS[header[:4]]
    major, minor, _zone, _accuracy, snaplen, linktype = struct.unpack(endian + "HHiiII", header[4:])
    if (major, minor) != (2, 4) or linktype != 1 or not 14 <= snaplen <= _packet.MAX_FRAME_BYTES:
        raise EvidenceError("unsupported_capture_header")
    records, unknown, empty_tcp_payload_frames = 0, {}, 0
    while True:
        record = reader.read(16, allow_eof=True)
        if record is None:
            break
        records += 1
        if records > _packet.MAX_RECORDS:
            raise EvidenceError("capture_record_limit")
        _seconds, fraction, captured, original = struct.unpack(endian + "IIII", record)
        if fraction >= fraction_limit or captured != original or not 14 <= captured <= snaplen:
            raise EvidenceError("truncated_or_invalid_capture_packet")
        questions, reason = frame_questions(reader.read(captured))
        if reason == "empty_tcp_payload":
            empty_tcp_payload_frames += 1
        elif reason:
            unknown[reason] = unknown.get(reason, 0) + 1
        for name, query_type, query_class in questions:
            for probe in probes:
                if name != probe["name"]:
                    continue
                matches = query_class == 1 and (query_type == probe["query_type"] or probe["query_type"] is None and query_type in (1, 28))
                if matches:
                    probe["count"] += 1
                    probe["first"] = records if probe["first"] is None else probe["first"]
                    probe["last"] = records
                else:
                    key = "nonce_question_unexpected_type_or_class"
                    unknown[key] = unknown.get(key, 0) + 1
    results, complete, absent = [], not unknown, True
    for name, group in groups.items():
        roles = {p["role"]: p for p in group}
        before, after = roles["outside_before"], roles["outside_after"]
        controls = before["count"] > 0 and after["count"] > 0
        ordered = controls and before["last"] < after["first"]
        if ordered:
            ordered = all(p["count"] == 0 or before["last"] < p["first"] <= p["last"] < after["first"]
                          for p in (roles["parent"], roles["child"]))
        group_complete = not unknown and controls and bool(ordered)
        zero = roles["parent"]["count"] == roles["child"]["count"] == 0
        complete &= group_complete; absent &= zero
        results.append({"id": name, "api": before["api"], "query_type": before["query_type"],
            "positive_controls_complete": controls, "control_window_ordered": bool(ordered),
            "contained_questions_absent": zero if group_complete else None,
            "absence_observed": group_complete and zero})
    return {"schema_version": 1, "status": "complete" if complete else "incomplete", "scope": SCOPE,
        "acceptance_passed": False, "kernel_denial_proven": False, "capture_format_complete": True,
        "capture_sha256": reader.digest.hexdigest(), "capture_bytes": reader.total,
        "manifest_sha256": manifest_hash, "packet_records": records,
        "empty_tcp_payload_frames": empty_tcp_payload_frames,
        "unknown_records": sum(unknown.values()), "unknown_reasons": unknown,
        "contained_questions_absent": absent if complete else None, "absence_observed": complete and absent,
        "groups": results, "counts": [{"id": p["id"], "group": p["group"], "role": p["role"],
            "api": p["api"], "query_type": p["query_type"], "count": p["count"],
            "qname_sha256": hashlib.sha256(b".".join(p["name"])).hexdigest()} for p in probes]}


def analyze_bytes(data, manifest):
    return analyze_stream(io.BytesIO(data), manifest)


# This loader created a private format-module instance, not the UDP parser's
# shared module. Bind its existing safe file API to the DNS-specific decoder,
# retaining O_NOFOLLOW, ownership/mode/link checks and unchanged-file checks.
_packet.analyze_stream = analyze_stream
analyze_capture = _packet.analyze_capture


def main(arguments=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--pcap", required=True, type=Path)
    parser.add_argument("--manifest", required=True, type=Path)
    parser.add_argument("--report", required=True, type=Path)
    args = parser.parse_args(arguments)
    if args.report.resolve() in {args.pcap.resolve(), args.manifest.resolve()}:
        parser.error("report must differ from capture and manifest")
    try:
        with args.manifest.open("rb") as stream:
            raw = stream.read(_packet.MAX_MANIFEST_BYTES + 1)
        if len(raw) > _packet.MAX_MANIFEST_BYTES:
            raise EvidenceError("manifest_size_limit")
        result = analyze_capture(args.pcap, json.loads(raw))
        code = 0 if result["status"] == "complete" else 1
    except (EvidenceError, ValueError, OSError):
        result = {"schema_version": 1, "status": "incomplete", "scope": SCOPE,
            "acceptance_passed": False, "kernel_denial_proven": False, "absence_observed": False,
            "contained_questions_absent": None, "empty_tcp_payload_frames": 0,
            "error": "dns_capture_or_manifest_invalid"}
        code = 1
    pending = None
    try:
        with tempfile.NamedTemporaryFile(mode="w", encoding="ascii", dir=args.report.parent,
                                         prefix=".dns-summary-", delete=False) as output:
            pending = Path(output.name)
            output.write(json.dumps(result, ensure_ascii=True, indent=2) + "\n")
        os.replace(pending, args.report)
    finally:
        if pending is not None:
            pending.unlink(missing_ok=True)
    print(json.dumps({"status": result["status"], "absence_observed": result["absence_observed"]}))
    return code


if __name__ == "__main__":
    raise SystemExit(main())
