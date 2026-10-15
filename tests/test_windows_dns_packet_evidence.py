"""Construct DNS wire questions; never simulate Windows resolver enforcement."""
import copy
import importlib.util
import json
import os
from pathlib import Path
import struct
import tempfile
import unittest
from unittest import mock

import test_windows_packet_evidence as wire

ROOT = Path(__file__).resolve().parent.parent
spec = importlib.util.spec_from_file_location("ruleproxy_dns_packet_test", ROOT / ".github/windows_dns_packet_evidence.py")
dns = importlib.util.module_from_spec(spec)
spec.loader.exec_module(dns)


def manifest(api="getaddrinfo", group=None, nonce_base=1):
    probes = []
    for index, role in enumerate(dns.ROLES):
        probes.append({"id": (group or api) + "." + role, "group": group or api, "role": role, "api": api,
            "qname": f"{nonce_base + index:032x}.{api.replace('_', '-')}.{role.replace('_', '-')}.ruleproxy-ci.example.com."})
    return {"schema_version": 1, "source_mac": dns.SOURCE_MAC, "probes": probes}


def question(name, query_type=1, query_class=1, flags=0x0100):
    labels = name.removesuffix(".").encode("ascii").split(b".")
    return struct.pack("!6H", 1234, flags, 1, 0, 0, 0) + b"".join(bytes([len(label)]) + label for label in labels) + b"\0" + struct.pack("!HH", query_type, query_class)


def frame(probe, family="ipv4", port=53, query_type=1, query_class=1, **kwargs):
    payload = kwargs.pop("payload", question(probe["qname"], query_type, query_class))
    configuration = {"family": family, "source_ip": "192.0.2.33" if family == "ipv4" else "fd00::33",
                     "destination": "192.0.2.99" if family == "ipv4" else "fd00::99", "port": port,
                     "payload_hex": payload.hex()}
    return wire.frame(configuration, **kwargs)


def controls(value, **kwargs):
    return [frame(value["probes"][index], **kwargs) for index in (0, 3)]


class WindowsDnsPacketEvidenceTests(unittest.TestCase):
    def test_unknown_broker_addresses_and_case_normalized_names_match_all_dns_udp_ports(self):
        for port in dns.DNS_PORTS:
            for family in ("ipv4", "ipv6"):
                value = manifest()
                value["probes"][0]["qname"] = value["probes"][0]["qname"].upper()
                before, after = controls(value, family=family, port=port)
                parent = frame(value["probes"][1], family=family, port=port, query_class=0x8001 if port == 5353 else 1)
                with self.subTest(port=port, family=family):
                    result = dns.analyze_bytes(wire.pcap([before, parent, after]), value)
                    self.assertEqual(result["status"], "complete")
                    self.assertEqual([p["count"] for p in result["counts"]], [1, 1, 0, 1])
                    self.assertFalse(result["absence_observed"])
                    self.assertFalse(result["kernel_denial_proven"])
                    self.assertFalse(result["acceptance_passed"])

    def test_getaddrinfo_default_accepts_aaaa_and_explicit_dns_types_remain_scoped(self):
        for api, query_type in (("getaddrinfo", 28), ("dns_a", 1), ("dns_aaaa", 28)):
            value = manifest(api)
            result = dns.analyze_bytes(wire.pcap(controls(value, query_type=query_type)), value)
            self.assertTrue(result["absence_observed"])
            self.assertEqual(result["scope"], "default_test_vm_resolver_configuration_observed")
        value = manifest("dns_a")
        before, after = controls(value)
        result = dns.analyze_bytes(wire.pcap([before, frame(value["probes"][1], query_type=28), after]), value)
        self.assertFalse(result["absence_observed"])
        self.assertEqual(result["unknown_reasons"], {"nonce_question_unexpected_type_or_class": 1})

    def test_backward_compressed_questions_and_complete_edns_record_are_parsed(self):
        value = manifest()
        parent = value["probes"][1]
        first = question(parent["qname"])
        compressed = struct.pack("!6H", 1, 0x0100, 2, 0, 0, 1) + first[12:] + b"\xc0\x0c\0\x1c\0\1"
        compressed += b"\0" + struct.pack("!HHIH", 41, 1232, 0, 0)
        before, after = controls(value)
        result = dns.analyze_bytes(wire.pcap([before, frame(parent, payload=compressed), after]), value)
        self.assertEqual([p["count"] for p in result["counts"]], [1, 2, 0, 1])
        self.assertEqual(result["unknown_records"], 0)

    def test_invalid_compression_or_incomplete_question_is_unknown_never_zero_proof(self):
        value = manifest()
        before, after = controls(value)
        name = value["probes"][1]["qname"]
        cases = [question(name)[:-1], struct.pack("!6H", 1, 0x0100, 1, 0, 0, 0) + b"\xc0\x0c\0\1\0\1",
                 question(name) + b"unparsed", question(name, flags=0x0300)]
        for message in cases:
            with self.subTest(message_sha=__import__("hashlib").sha256(message).hexdigest()):
                result = dns.analyze_bytes(wire.pcap([before, frame(value["probes"][1], payload=message), after]), value)
                self.assertEqual(result["unknown_reasons"], {"unparsed_dns_datagram": 1})
                self.assertFalse(result["absence_observed"])
                self.assertIsNone(result["contained_questions_absent"])

    def test_tcp_fallback_tls_quic_fragments_extensions_and_tunnels_cannot_prove_absence(self):
        value = manifest()
        before, after = controls(value)
        parent = value["probes"][1]
        opaque = [frame(parent, protocol=6, payload=struct.pack("!HH", 45123, port) + b"\0" * 8 + b"\x50\0" + b"\0" * 6) for port in (53, 853, 443)]
        opaque += [frame(parent, port=port) for port in (443, 853)]
        opaque += [frame(parent, fragment=0x2000), frame(parent, fragment=1, protocol=6, payload=b"\0" * 20),
                   frame(parent, family="ipv6", extension=0), frame(parent, protocol=41)]
        for packet in opaque:
            result = dns.analyze_bytes(wire.pcap([before, packet, after]), value)
            self.assertEqual(result["status"], "incomplete")
            self.assertEqual(result["unknown_records"], 1)
            self.assertFalse(result["absence_observed"])

    def test_missing_same_api_controls_bad_window_or_late_broker_question_is_incomplete(self):
        value = manifest()
        before, after = controls(value)
        for packets in ([], [before], [after], [after, before], [before, after, frame(value["probes"][1])]):
            result = dns.analyze_bytes(wire.pcap(packets), value)
            self.assertEqual(result["status"], "incomplete")
            self.assertFalse(result["absence_observed"])

    def test_empty_tcp_controls_remain_unknown_and_payload_is_separately_reported(self):
        value = manifest()
        before, after = controls(value)
        for family in ("ipv4", "ipv6"):
            for port in (53, 853, 443):
                header = struct.pack("!HH", 45123, port) + b"\0" * 8 + b"\x50\x02" + b"\0" * 6
                for payload, reason in ((header, "opaque_dns_tcp_control_only"),
                        (header + b"encrypted data", "opaque_dns_tcp_or_https")):
                    with self.subTest(family=family, port=port, reason=reason):
                        packet = frame(value["probes"][1], family=family, protocol=6, payload=payload)
                        result = dns.analyze_bytes(wire.pcap([before, packet, after]), value)
                        self.assertEqual(result["unknown_reasons"], {reason: 1})
                        self.assertEqual(result["status"], "incomplete")
                        self.assertFalse(result["absence_observed"])
                        self.assertFalse(result["kernel_denial_proven"])

    def test_unrelated_payload_response_and_other_source_mac_do_not_match_questions(self):
        value = manifest()
        before, after = controls(value)
        private = b"GET /PRIVATE_CAPABILITY HTTP/1.1\r\nCookie: PRIVATE_BYTES\r\n\r\n"
        unrelated = frame(value["probes"][1], protocol=6, payload=struct.pack("!HH", 45123, 12345) + b"\0" * 8 + b"\x50\0" + b"\0" * 6 + private)
        response = frame(value["probes"][1], payload=question(value["probes"][1]["qname"], flags=0x8100))
        other = frame(value["probes"][1], mac=wire.OTHER_MAC)
        result = dns.analyze_bytes(wire.pcap([before, unrelated, response, other, after]), value)
        self.assertTrue(result["absence_observed"])
        encoded = json.dumps(result)
        for secret in ("PRIVATE_CAPABILITY", "PRIVATE_BYTES", "192.0.2.33", "192.0.2.99", value["probes"][0]["qname"].removesuffix(".")):
            self.assertNotIn(secret, encoded)

    def test_manifest_rejects_api_name_role_type_duplicates_and_incomplete_groups(self):
        good = manifest()
        cases = []
        for key, bad in (("api", "unknown"), ("qname", "arbitrary.example.com"), ("role", "unknown"), ("query_type", 255)):
            value = copy.deepcopy(good); value["probes"][0][key] = bad; cases.append(value)
        value = copy.deepcopy(good); value["probes"].pop(); cases.append(value)
        value = copy.deepcopy(good); value["probes"][1]["id"] = value["probes"][0]["id"]; cases.append(value)
        value = copy.deepcopy(good); value["source_mac"] = "52:54:00:12:34:57"; cases.append(value)
        for value in cases:
            with self.assertRaises(dns.EvidenceError):
                dns.analyze_bytes(wire.pcap([]), value)

    def test_twelve_api_variant_groups_are_independent_and_thirteenth_is_rejected(self):
        all_probes, packets = [], []
        for variant in range(4):
            for api in dns.APIS:
                value = manifest(api, group=f"v{variant}.{api}", nonce_base=100 * len(all_probes) + 1)
                all_probes.extend(value["probes"])
                packets.extend(controls(value, query_type=28 if api == "dns_aaaa" else 1))
        value = {"schema_version": 1, "source_mac": dns.SOURCE_MAC, "probes": all_probes}
        result = dns.analyze_bytes(wire.pcap(packets), value)
        self.assertEqual(len(result["groups"]), 12)
        self.assertTrue(result["absence_observed"])
        value["probes"] += manifest(group="extra", nonce_base=99999)["probes"]
        with self.assertRaises(dns.EvidenceError):
            dns.analyze_bytes(wire.pcap([]), value)

    def test_existing_udp_parser_private_globals_are_not_modified(self):
        value = wire.manifest()
        before, after = wire.controls(value)
        self.assertTrue(wire.evidence.analyze_bytes(wire.pcap(before + after), value)["absence_observed"])
        self.assertIsNot(wire.evidence.analyze_stream, dns._packet.analyze_stream)

    @unittest.skipUnless(os.name == "posix" and hasattr(os, "O_NOFOLLOW"), "Private Linux QEMU capture ownership")
    def test_existing_private_file_api_rejects_aliases_and_cli_never_serializes_raw_evidence(self):
        value = manifest()
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            capture = root / "private.pcap"; capture.write_bytes(wire.pcap(controls(value))); capture.chmod(0o600)
            self.assertTrue(dns.analyze_capture(capture, value)["absence_observed"])
            alias = root / "alias.pcap"; alias.symlink_to(capture)
            with self.assertRaises(dns.EvidenceError): dns.analyze_capture(alias, value)
            capture.write_bytes(b"PRIVATE_PACKET_AND_PATH")
            source = root / "manifest.json"; source.write_text(json.dumps(value))
            report = root / "summary.json"
            with mock.patch("builtins.print"):
                self.assertEqual(dns.main(["--pcap", str(capture), "--manifest", str(source), "--report", str(report)]), 1)
            text = report.read_text()
            self.assertNotIn("PRIVATE_PACKET_AND_PATH", text)
            self.assertNotIn(str(root), text)


if __name__ == "__main__":
    unittest.main()
