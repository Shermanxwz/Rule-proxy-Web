"""Offline correlation tests; absence remains diagnostic evidence only."""
import importlib.util
import json
import os
from pathlib import Path
import tempfile
import unittest
from unittest import mock

import test_windows_dns_packet_evidence as dns_test
import test_windows_packet_evidence as wire

ROOT = Path(__file__).resolve().parent.parent
spec = importlib.util.spec_from_file_location(
    "ruleproxy_free_backend_evidence_test", ROOT / ".github/windows_free_backend_evidence.py")
evidence = importlib.util.module_from_spec(spec)
spec.loader.exec_module(evidence)

PRIVATE_CAPTURE_SUPPORTED = os.name == "posix" and hasattr(os, "O_NOFOLLOW")


def call_rows(nonce, role, backend="sandboxie"):
    rows = []
    for api in evidence.DNS_APIS:
        row = {"api": api, "requested_role": role,
               "qname": evidence._qname(nonce, api, role), "api_returned": True,
               "worker_cleanup_proven": True, "native_completion_proven": True,
               "outcome": "returned"}
        if backend == "sandboxie":
            row.update(entry_lease_published=True, worker_exit_verified=True)
        rows.append(row)
    return rows


def outside(nonce, role, proxybridge=False):
    if proxybridge:
        return {"status": "native_dns_probe_only", "cleanup_proven": True,
                "calls": call_rows(nonce, role, "proxybridge")}
    return {"report_observed": True, "probe_status": "native_dns_probe_only",
            "worker_cleanup_proven": True, "calls": call_rows(nonce, role)}


def udp_tuple(nonce, role, family):
    ipv4 = family == "ipv4"
    return {"attempted": True, "send_ok": True, "family": family,
            "dest_ip": "198.51.100.17" if ipv4 else "2001:db8::17",
            "dest_port": 39017, "source_ip": "10.0.2.15" if ipv4 else "fec0::15",
            "source_ip_observed": True,
            "payload_hex": ("RPWFREE:" + nonce + ":" + role).encode().hex(),
            "timeout_ms": 2500, "metadata_complete": True}


def udp_tuple_sets(nonce, role):
    return {"public_udp4": udp_tuple(nonce, role, "ipv4"),
            "public_udp6": udp_tuple(nonce, role, "ipv6")}


def make_guest(backend, contained=False):
    if backend == "sandboxie":
        nonces = {"RuleProxyNet": "1" * 32, "RuleProxyDnsIpc": "2" * 32}
        dns_boxes = {}
        for box, nonce in nonces.items():
            dns_boxes[box] = {role: {"report_observed": True, "probe_status": "native_dns_probe_only",
                                  "worker_cleanup_proven": True,
                                  "calls": call_rows(nonce, role), "call_count": 3,
                                  "dns_blocked_proven": False, "wire_observed": None}
                          for role in ("parent", "child")}
        fixture_nonce = "4" * 32
        boxes = {}
        for box in nonces:
            boxes[box] = {
                "udp_tuple_observations": udp_tuple_sets(fixture_nonce, "parent"),
                "child": {"udp_tuple_observations": udp_tuple_sets(fixture_nonce, "child")}}
        probe = {"backend": backend, "phase": "probe", "status": "passed",
                 "dns_nonces": nonces, "native_dns": dns_boxes, "fixture_nonce": fixture_nonce,
                 "outside_base_dns_before": outside(nonces["RuleProxyNet"], "outside_before"),
                 "outside_base_dns_after": outside(nonces["RuleProxyNet"], "outside_after"),
                 "outside_native_dns_before": outside(nonces["RuleProxyDnsIpc"], "outside_before"),
                 "outside_native_dns_after": outside(nonces["RuleProxyDnsIpc"], "outside_after"),
                 "outside_before": {"udp_tuple_observations": udp_tuple_sets(fixture_nonce, "outside_before")},
                 "outside_after": {"udp_tuple_observations": udp_tuple_sets(fixture_nonce, "outside_after")},
                 "boxes": boxes}
        guest = {"schema_version": 1, "backend": backend, "status": "passed", "reports": {"probe": probe}}
        return guest, nonces
    nonce = "5" * 32
    selected = {"native_dns": {"status": "observed", "calls_count": 3,
                                "calls": call_rows(nonce, "parent", "proxybridge")},
                "child": {"native_dns": {"status": "observed", "calls_count": 3,
                         "calls": call_rows(nonce, "child", "proxybridge")}}}
    fixture_nonce = nonce
    selected = {"native_dns": selected["native_dns"], "child": selected["child"]}
    selected.update(udp_tuple_sets(fixture_nonce, "parent"))
    selected["child"].update(udp_tuple_sets(fixture_nonce, "child"))
    observations = {"fixture_nonce": fixture_nonce,
                    "selected_parent_and_child": selected,
                    "native_dns_outside_before": outside(nonce, "outside_before", True),
                    "native_dns_outside_after": outside(nonce, "outside_after", True),
                    "outside_wire_before": {**udp_tuple_sets(fixture_nonce, "outside_before"),
                                            "child": udp_tuple_sets(fixture_nonce, "outside_before")},
                    "outside_wire_after": {**udp_tuple_sets(fixture_nonce, "outside_after"),
                                           "child": udp_tuple_sets(fixture_nonce, "outside_after")},
                    "unselected_network": {}, "after_proxy_stop": {}}
    probe = {"backend": backend, "phase": "probe", "status": "passed", "fixture_nonce": nonce,
             "observations": observations}
    guest = {"schema_version": 1, "backend": backend, "status": "passed", "reports": {"probe": probe}}
    return guest, {"proxybridge_selected": nonce}


def capture_for(manifest, include_contained=False):
    packets = []
    probes = manifest["probes"]
    for item in probes:
        if item["role"] in ("outside_before", "outside_after") or (
                include_contained and item["role"] == "parent"):
            query_type = 28 if item["api"] == "dns_aaaa" else 1
            packets.append(dns_test.frame(item, query_type=query_type))
    return wire.pcap(packets)


class WindowsFreeBackendEvidenceTests(unittest.TestCase):
    def test_exact_groups_are_generated_without_exposing_nonce_or_qname(self):
        for backend, count in (("sandboxie", 24), ("proxybridge", 12)):
            guest, _ = make_guest(backend)
            probe, _ = evidence._probe_report(guest, backend)
            manifest, execution = evidence.prepare_dns_evidence(backend, probe)
            self.assertEqual(len(manifest["probes"]), count)
            self.assertEqual(execution["status"], "complete")
            encoded = json.dumps(execution)
            for item in manifest["probes"]:
                self.assertNotIn(item["qname"], encoded)
                self.assertNotIn(item["qname"].split(".")[0], encoded)

    @unittest.skipUnless(PRIVATE_CAPTURE_SUPPORTED, "Private PCAP copies require POSIX O_NOFOLLOW")
    def test_parser_integration_reports_complete_wire_scope_without_product_claims(self):
        for backend in ("sandboxie", "proxybridge"):
            guest, _ = make_guest(backend)
            probe, _ = evidence._probe_report(guest, backend)
            result = evidence.analyze(backend, guest, self._pcap_for(backend, probe))
            manifest, _ = evidence.prepare_dns_evidence(backend, probe)
            encoded = json.dumps(result)
            for item in manifest["probes"]:
                self.assertNotIn(item["qname"], encoded)
                self.assertNotIn(item["qname"].split(".")[0], encoded)
            self.assertFalse(result["product_acceptance_passed"])
            self.assertFalse(result["dns"]["kernel_denial_proven"])

    def _pcap_for(self, backend, probe, include_contained=False):
        manifest, _ = evidence.prepare_dns_evidence(backend, probe)
        # Keep one classic-PCAP envelope and include each IP family once. The
        # parser independently replays this same private copy for each cohort.
        dns_rows = []
        for item in manifest["probes"]:
            if item["role"] in ("outside_before", "outside_after") or (
                    include_contained and item["role"] == "parent"):
                dns_rows.append(dns_test.frame(item, query_type=28 if item["api"] == "dns_aaaa" else 1))
        udp_plans, _ = evidence.prepare_udp_evidence(backend, probe)
        udp_rows = []
        for family in ("ipv4", "ipv6"):
            plan = next((candidate for candidate in udp_plans if candidate["family"] == family), None)
            if plan is None:
                continue
            for role in ("outside_before", "parent", "child", "outside_after"):
                if role in ("outside_before", "outside_after") or include_contained:
                    item = next(row for row in plan["manifest"]["probes"] if row["role"] == role)
                    udp_rows.append(wire.frame(item))
        return self._private_capture(wire.pcap(dns_rows + udp_rows))

    def _private_capture(self, data):
        temporary = tempfile.NamedTemporaryFile(delete=False)
        temporary.write(data)
        temporary.close()
        self.addCleanup(lambda: Path(temporary.name).unlink(missing_ok=True))
        os.chmod(temporary.name, 0o644)  # analyzer must safely copy CI artifacts
        return Path(temporary.name)

    @unittest.skipUnless(PRIVATE_CAPTURE_SUPPORTED, "Private PCAP copies require POSIX O_NOFOLLOW")
    def test_wire_zero_plus_completed_exact_api_records_is_not_kernel_or_product_proof(self):
        for backend in ("sandboxie", "proxybridge"):
            guest, _ = make_guest(backend)
            probe, _ = evidence._probe_report(guest, backend)
            result = evidence.analyze(backend, guest, self._pcap_for(backend, probe))
            self.assertEqual(result["dns"]["status"], "complete")
            self.assertTrue(result["dns"]["wire_absence_observed"])
            self.assertTrue(result["dns"]["positive_controls_complete"])
            self.assertEqual(result["dns"]["classification"],
                "no_contained_nonce_dns_questions_observed_with_completed_api_records")
            self.assertFalse(result["dns"]["kernel_denial_proven"])
            self.assertFalse(result["product_acceptance_passed"])

    @unittest.skipUnless(PRIVATE_CAPTURE_SUPPORTED, "Private PCAP copies require POSIX O_NOFOLLOW")
    def test_contained_exact_nonce_query_is_reported_positive(self):
        guest, _ = make_guest("proxybridge")
        probe, _ = evidence._probe_report(guest, "proxybridge")
        result = evidence.analyze("proxybridge", guest,
                                  self._pcap_for("proxybridge", probe, include_contained=True))
        self.assertTrue(result["dns"]["contained_questions_observed"])
        self.assertEqual(result["dns"]["classification"], "contained_nonce_dns_questions_observed")
        self.assertFalse(result["dns"]["acceptance_passed"])

    @unittest.skipUnless(PRIVATE_CAPTURE_SUPPORTED, "Private PCAP copies require POSIX O_NOFOLLOW")
    def test_missing_exact_call_or_failed_guest_keeps_wire_observation_incomplete(self):
        guest, _ = make_guest("proxybridge")
        probe = guest["reports"]["probe"]
        probe["observations"]["selected_parent_and_child"]["child"]["native_dns"]["calls"] = []
        result = evidence.analyze("proxybridge", guest,
                                  self._pcap_for("proxybridge", probe))
        self.assertEqual(result["api_execution"]["status"], "incomplete")
        self.assertEqual(result["dns"]["classification"], "wire_scope_zero_observed_but_api_execution_incomplete")
        guest["status"] = "failed"
        result = evidence.analyze("proxybridge", guest, self._pcap_for("proxybridge", probe))
        self.assertEqual(result["api_execution"]["status"], "incomplete")
        self.assertEqual(result["dns"]["classification"], "wire_scope_zero_observed_but_api_execution_incomplete")
        self.assertEqual(result["status"], "incomplete")

    def test_absent_nonce_and_unknown_report_status_fail_closed(self):
        guest, _ = make_guest("sandboxie")
        probe = guest["reports"]["probe"]
        del probe["dns_nonces"]["RuleProxyNet"]
        manifest, execution = evidence.prepare_dns_evidence("sandboxie", probe)
        self.assertEqual(execution["status"], "incomplete")
        self.assertEqual(len(manifest["probes"]), 12)
        guest, _ = make_guest("proxybridge")
        probe, _ = evidence._probe_report(guest, "proxybridge")
        probe["observations"]["native_dns_outside_before"]["status"] = "unknown"
        _, execution = evidence.prepare_dns_evidence("proxybridge", probe)
        self.assertEqual(execution["status"], "incomplete")

    def test_completed_resolver_denial_is_execution_not_success_and_timeout_is_incomplete(self):
        call = {"api_returned": False, "native_completion_proven": True,
                "worker_cleanup_proven": True, "requested_role": "child",
                "qname": "a" * 32, "outcome": "returned"}
        denied = evidence._call_execution(call, {}, False, "child", "observed")
        self.assertTrue(denied["execution_proven"])
        self.assertFalse(denied["api_returned"])
        call["native_completion_proven"] = False
        call["outcome"] = "deadline"
        timeout = evidence._call_execution(call, {}, False, "child", "observed")
        self.assertFalse(timeout["execution_proven"])

    @unittest.skipUnless(PRIVATE_CAPTURE_SUPPORTED, "Private PCAP copies require POSIX O_NOFOLLOW")
    def test_udp_socket_send_success_never_becomes_wire_evidence(self):
        guest, _ = make_guest("sandboxie")
        probe = guest["reports"]["probe"]
        probe["boxes"] = {"RuleProxyNet": {"udp_send_observations": {"udp4": True}}}
        result = evidence.analyze("sandboxie", guest, self._pcap_for("sandboxie", probe))
        self.assertEqual(result["udp_wire"]["status"], "incomplete")
        self.assertFalse(result["udp_wire"]["wire_absence_observed"])
        self.assertTrue(result["udp_wire"]["socket_send_observations"][0]["send_ok"])
        self.assertFalse(result["udp_wire"]["socket_send_observations"][0]["wire_proven"])

    @unittest.skipUnless(PRIVATE_CAPTURE_SUPPORTED, "Private PCAP copies require POSIX O_NOFOLLOW")
    def test_exact_udp_wire_controls_and_api_attempts_are_required_for_scoped_absence(self):
        for backend in ("sandboxie", "proxybridge"):
            guest, _ = make_guest(backend)
            probe, _ = evidence._probe_report(guest, backend)
            result = evidence.analyze(backend, guest, self._pcap_for(backend, probe))
            udp = result["udp_wire"]
            self.assertEqual(udp["status"], "complete")
            self.assertTrue(udp["wire_absence_observed"])
            self.assertFalse(udp["selected_udp_marker_observed"])
            self.assertFalse(udp["acceptance_passed"])
            self.assertFalse(udp["kernel_denial_proven"])
            for family in udp["families"]:
                self.assertGreater(family["outside_before_packet_count"], 0)
                self.assertGreater(family["outside_after_packet_count"], 0)
                self.assertTrue(family["api_roles"]["parent"]["attempted"])
                self.assertTrue(family["api_roles"]["child"]["metadata_complete"])

    @unittest.skipUnless(PRIVATE_CAPTURE_SUPPORTED, "Private PCAP copies require POSIX O_NOFOLLOW")
    def test_selected_packet_is_positive_even_when_api_send_metadata_is_incomplete(self):
        guest, _ = make_guest("proxybridge")
        probe, _ = evidence._probe_report(guest, "proxybridge")
        selected = probe["observations"]["selected_parent_and_child"]
        selected["public_udp4"]["send_ok"] = False
        selected["public_udp4"]["attempted"] = False
        selected["public_udp4"]["metadata_complete"] = False
        result = evidence.analyze("proxybridge", guest,
                                  self._pcap_for("proxybridge", probe, include_contained=True))
        udp = result["udp_wire"]
        self.assertTrue(udp["selected_udp_marker_observed"])
        self.assertFalse(udp["wire_absence_observed"])
        parent4 = next(row for row in udp["families"]
                       if row["family"] == "ipv4")
        self.assertTrue(parent4["selected_marker_observed"])
        self.assertFalse(parent4["api_attempts_and_metadata_complete"])

    @unittest.skipUnless(PRIVATE_CAPTURE_SUPPORTED, "Private PCAP copies require POSIX O_NOFOLLOW")
    def test_proxybridge_child_marker_is_not_attributed_across_unselected_phase(self):
        guest, _ = make_guest("proxybridge")
        probe, _ = evidence._probe_report(guest, "proxybridge")
        nonce = probe["observations"]["fixture_nonce"]
        probe["observations"]["unselected_network"] = {
            "public_udp4": udp_tuple(nonce, "child", "ipv4")}
        plans, _ = evidence.prepare_udp_evidence("proxybridge", probe)
        plan = next(row for row in plans if row["family"] == "ipv4")
        probes = plan["manifest"]["probes"]
        packets = [wire.frame(next(row for row in probes if row["role"] == role))
                   for role in ("outside_before", "child", "outside_after")]
        result = evidence.analyze("proxybridge", guest, self._private_capture(wire.pcap(packets)))
        udp4 = next(row for row in result["udp_wire"]["families"]
                    if row["family"] == "ipv4")
        self.assertFalse(udp4["selected_marker_observed"])
        self.assertTrue(udp4["child_marker_phase_ambiguous"])
        self.assertFalse(udp4["child_marker_attributable_to_selected"])
        self.assertEqual(udp4["classification"], "child_marker_observed_but_phase_ambiguous")
        self.assertFalse(udp4["wire_absence_observed"])

    @unittest.skipUnless(PRIVATE_CAPTURE_SUPPORTED, "Private PCAP copies require POSIX O_NOFOLLOW")
    def test_missing_ipv6_control_and_unknown_exact_tuple_packets_keep_scope_incomplete(self):
        guest, _ = make_guest("sandboxie")
        probe, _ = evidence._probe_report(guest, "sandboxie")
        del probe["outside_after"]["udp_tuple_observations"]["public_udp6"]
        result = evidence.analyze("sandboxie", guest, self._pcap_for("sandboxie", probe))
        self.assertEqual(result["udp_wire"]["status"], "incomplete")
        self.assertFalse(result["udp_wire"]["wire_absence_observed"])
        ipv6 = [row for row in result["udp_wire"]["families"] if row["family"] == "ipv6"]
        self.assertTrue(ipv6)
        self.assertTrue(all(not row["api_attempts_and_metadata_complete"] for row in ipv6))

        guest, _ = make_guest("proxybridge")
        probe, _ = evidence._probe_report(guest, "proxybridge")
        plans, _ = evidence.prepare_udp_evidence("proxybridge", probe)
        ipv4 = next(plan for plan in plans if plan["family"] == "ipv4")
        altered = dict(ipv4["manifest"]["probes"][1], source_ip="10.0.2.99")
        packets = [wire.frame(row) for row in ipv4["manifest"]["probes"]
                   if row["role"] in ("outside_before", "outside_after")]
        packets.insert(1, wire.frame(altered))
        path = self._private_capture(wire.pcap(packets))
        result = evidence.analyze("proxybridge", guest, path)
        self.assertFalse(result["udp_wire"]["wire_absence_observed"])
        ipv4_result = next(row for row in result["udp_wire"]["families"]
                           if row["family"] == "ipv4")
        self.assertEqual(ipv4_result["parser_status"], "incomplete")
        self.assertGreater(ipv4_result["unknown_records"], 0)

    @unittest.skipUnless(PRIVATE_CAPTURE_SUPPORTED, "Private PCAP copies require POSIX O_NOFOLLOW")
    def test_capture_symlink_rejected_before_private_copy(self):
        with tempfile.TemporaryDirectory() as directory:
            target = Path(directory) / "target.pcap"
            target.write_bytes(b"x")
            link = Path(directory) / "link.pcap"
            link.symlink_to(target)
            with self.assertRaisesRegex(ValueError, "capture_symlink_rejected"):
                evidence._secure_private_copy(link)

    def test_unsupported_platform_rejects_capture_copy_before_opening_input(self):
        source = Path("does-not-need-to-exist.pcap")
        with mock.patch.object(evidence.os, "name", "nt"):
            with self.assertRaisesRegex(ValueError, "private_capture_copy_unavailable"):
                evidence._secure_private_copy(source)


if __name__ == "__main__":
    unittest.main()
