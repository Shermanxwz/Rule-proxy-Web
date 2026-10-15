"""Correlate private free-backend PCAPs with bounded backend reports.

This is an offline observation tool. It reports nonce DNS questions on the
captured VM NIC and API/worker metadata; it does not prove kernel enforcement
or product acceptance.
"""
from __future__ import annotations

import argparse
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import stat
import tempfile

ROOT = Path(__file__).resolve().parents[1]
MAX_REPORT_BYTES = 2 * 1024 * 1024
MAX_PCAP_BYTES = 512 * 1024 * 1024
DNS_APIS = ("getaddrinfo", "dns_a", "dns_aaaa")
ROLES = ("outside_before", "parent", "child", "outside_after")
SANDBOXIE_BASE = "RuleProxyNet"
SANDBOXIE_DNS = "RuleProxyDnsIpc"
UDP_DESTINATIONS = {"ipv4": "198.51.100.17", "ipv6": "2001:db8::17"}
UDP_SOURCE_MAC = "52:54:00:12:34:56"
UDP_PORT = 39017


def _load_module(name: str, path: Path):
    spec = importlib.util.spec_from_file_location(name, path)
    if spec is None or spec.loader is None:
        raise RuntimeError("fixed_packet_parser_unavailable")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def _strict_object(pairs):
    result = {}
    for key, value in pairs:
        if key in result:
            raise ValueError("duplicate_json_key")
        result[key] = value
    return result


def read_json(path: Path, max_bytes: int = MAX_REPORT_BYTES) -> dict:
    with path.open("rb") as source:
        raw = source.read(max_bytes + 1)
    if not raw or len(raw) > max_bytes:
        raise ValueError("json_size_invalid")
    value = json.loads(raw.decode("utf-8"), object_pairs_hook=_strict_object)
    if not isinstance(value, dict):
        raise ValueError("json_object_required")
    return value


def _probe_report(guest: dict, expected_backend: str) -> tuple[dict, str | None]:
    if guest.get("schema_version") != 1 or guest.get("backend") != expected_backend:
        raise ValueError("guest_result_identity_invalid")
    reports = guest.get("reports")
    if not isinstance(reports, dict) or not isinstance(reports.get("probe"), dict):
        raise ValueError("guest_probe_report_missing")
    probe = reports["probe"]
    if probe.get("backend") != expected_backend or probe.get("phase") != "probe":
        raise ValueError("probe_report_identity_invalid")
    return probe, guest.get("status") if guest.get("status") in ("passed", "failed") else None


def _nonce(value) -> str | None:
    if isinstance(value, str) and len(value) == 32 and all(c in "0123456789abcdef" for c in value):
        return value
    return None


def _qname(nonce: str, api: str, role: str) -> str:
    return f"{nonce}.{api.replace('_', '-')}.{role.replace('_', '-')}.ruleproxy-ci.example.com."


def _call_container(probe: dict, backend: str, cohort: str, role: str):
    """Return (container, envelope-cleanup) without guessing missing calls."""
    if backend == "sandboxie":
        if role in ("outside_before", "outside_after"):
            field = ("outside_base_dns_" if cohort == "sandboxie_base" else "outside_native_dns_") + role.removeprefix("outside_")
            value = probe.get(field)
            return value if isinstance(value, dict) else None, (value.get("worker_cleanup_proven") is True
                if isinstance(value, dict) else False)
        boxes = probe.get("native_dns")
        box = SANDBOXIE_BASE if cohort == "sandboxie_base" else SANDBOXIE_DNS
        row = boxes.get(box) if isinstance(boxes, dict) else None
        value = row.get(role) if isinstance(row, dict) else None
        return value if isinstance(value, dict) else None, (value.get("worker_cleanup_proven") is True
            if isinstance(value, dict) else False)

    observations = probe.get("observations")
    if not isinstance(observations, dict):
        return None, False
    if role in ("outside_before", "outside_after"):
        value = observations.get("native_dns_" + role)
        return value if isinstance(value, dict) else None, (value.get("cleanup_proven") is True
            if isinstance(value, dict) else False)
    selected = observations.get("selected_parent_and_child")
    if not isinstance(selected, dict):
        return None, False
    actor = selected if role == "parent" else selected.get("child")
    value = actor.get("native_dns") if isinstance(actor, dict) else None
    return value if isinstance(value, dict) else None, False


def _matching_call(container: dict | None, api: str, role: str, nonce: str):
    if not isinstance(container, dict) or not isinstance(container.get("calls"), list):
        return None, "missing_call_list"
    expected = _qname(nonce, api, role)
    found = [item for item in container["calls"] if isinstance(item, dict)
             and item.get("api") == api and item.get("requested_role") == role
             and item.get("qname") == expected]
    if len(found) != 1:
        return None, "missing_or_duplicate_exact_call"
    return found[0], None


def _call_execution(call: dict | None, container: dict | None, envelope_cleanup: bool,
                    role: str, report_status: str | None) -> dict:
    if call is None:
        return {"reported": False, "api_returned": None, "cleanup_proven": False,
                "execution_proven": False, "reason": "exact_api_call_not_recorded"}
    api_returned = call.get("api_returned") if type(call.get("api_returned")) is bool else None
    native_completion = (call.get("native_completion_proven")
                         if type(call.get("native_completion_proven")) is bool else None)
    # Both wrappers preserve native completion and a returned outcome. An
    # API call can complete with a denial/error, so API success is not required.
    completed = (native_completion is True and call.get("outcome") == "returned"
                 and call.get("operation_pending") is not True)
    # Sandboxie's projection is explicit about its shared worker envelope;
    # ProxyBridge reports cleanup on each safe call row.
    cleanup = call.get("worker_cleanup_proven") is True or call.get("cleanup_proven") is True or envelope_cleanup
    identity_fields = call.get("requested_role") == role and isinstance(call.get("qname"), str)
    # These are the affirmative statuses emitted by the two fixed wrappers.
    # Missing or unfamiliar status is not evidence that the operation ran.
    successful_report = report_status in (
        "native_dns_probe_only", "observed", "passed")
    proof = bool(identity_fields and completed and cleanup and successful_report
                 and native_completion is not False and call.get("timed_out") is not True)
    return {"reported": True, "api_returned": api_returned,
            "native_completion_proven": native_completion, "cleanup_proven": cleanup,
            "completion_proven": completed, "execution_proven": proof,
            "reason": None if proof else "api_completion_or_cleanup_not_proven"}


def prepare_dns_evidence(backend: str, probe: dict) -> tuple[dict, dict]:
    """Create exact API/role nonce groups; return manifest and execution facts."""
    cohorts = []
    if backend == "sandboxie":
        nonces = probe.get("dns_nonces")
        if not isinstance(nonces, dict):
            return {"schema_version": 1, "source_mac": "52:54:00:12:34:56", "probes": []}, {
                "status": "incomplete", "reason": "dns_nonces_missing", "groups": []}
        cohort_specs = (("sandboxie_base", nonces.get(SANDBOXIE_BASE)),
                        ("sandboxie_dns_ipc", nonces.get(SANDBOXIE_DNS)))
    elif backend == "proxybridge":
        observations = probe.get("observations")
        observations = observations if isinstance(observations, dict) else {}
        cohort_specs = (("proxybridge_selected", observations.get("fixture_nonce")),)
    else:
        raise ValueError("unknown_backend")

    probes, execution_groups = [], []
    missing_nonce_cohorts = []
    for cohort, raw_nonce in cohort_specs:
        nonce = _nonce(raw_nonce)
        if nonce is None:
            missing_nonce_cohorts.append(cohort)
            continue
        for api in DNS_APIS:
            group_id = cohort + "_" + api
            group_execution = {"id": group_id, "api": api, "roles": []}
            for role in ROLES:
                probes.append({"id": group_id + "_" + role, "group": group_id,
                               "role": role, "api": api, "qname": _qname(nonce, api, role)})
                container, envelope_cleanup = _call_container(probe, backend, cohort, role)
                call, lookup_error = _matching_call(container, api, role, nonce)
                report_status = None
                if isinstance(container, dict):
                    report_status = container.get("status", container.get("probe_status"))
                facts = _call_execution(call, container, envelope_cleanup, role, report_status)
                facts["role"] = role
                facts["lookup_complete"] = lookup_error is None
                group_execution["roles"].append(facts)
            group_execution["all_api_calls_proven"] = all(row["execution_proven"]
                                                            for row in group_execution["roles"])
            execution_groups.append(group_execution)
    manifest = {"schema_version": 1, "source_mac": "52:54:00:12:34:56", "probes": probes}
    status = "complete" if execution_groups and not missing_nonce_cohorts else "incomplete"
    if not all(group["all_api_calls_proven"] for group in execution_groups):
        status = "incomplete"
    execution = {"status": status, "reason": None if status == "complete" else "api_execution_or_nonce_metadata_incomplete",
                 "missing_nonce_cohorts": missing_nonce_cohorts, "groups": execution_groups}
    return manifest, execution


def _socket_observations(backend: str, probe: dict) -> list[dict]:
    """Retain user-mode socket send observations without treating them as wire proof."""
    rows = []
    def add(scope: str, value):
        if not isinstance(value, dict):
            return
        for name in ("udp4", "udp6", "public_udp4", "public_udp6"):
            item = value.get(name)
            if type(item) is bool:
                rows.append({"scope": scope, "family": name, "attempted": None,
                             "send_ok": item, "wire_proven": False})
                continue
            if not isinstance(item, dict):
                continue
            rows.append({"scope": scope, "family": name,
                         "attempted": item.get("attempted") if type(item.get("attempted")) is bool else None,
                         "send_ok": item.get("send_ok") if type(item.get("send_ok")) is bool else None,
                         "wire_proven": False})

    if backend == "sandboxie":
        boxes = probe.get("boxes")
        if isinstance(boxes, dict):
            for box, report in boxes.items():
                if isinstance(report, dict):
                    add("sandboxie_" + box + "_parent", report.get("udp_send_observations"))
                    child = report.get("child")
                    if isinstance(child, dict):
                        add("sandboxie_" + box + "_child", child.get("udp_send_observations"))
    else:
        observations = probe.get("observations")
        if not isinstance(observations, dict):
            observations = {}
        selected = observations.get("selected_parent_and_child")
        add("proxybridge_selected_parent", selected)
        if isinstance(selected, dict):
            add("proxybridge_selected_child", selected.get("child"))
        add("proxybridge_unselected", observations.get("unselected_network"))
        add("proxybridge_after_proxy_stop", observations.get("after_proxy_stop"))
    return rows


def _udp_row(probe: dict, backend: str, cohort: str, role: str, family: str):
    """Fetch the fixed public-UDP tuple from the backend's bounded schema."""
    key = "public_udp4" if family == "ipv4" else "public_udp6"
    if backend == "sandboxie":
        if role.startswith("outside_"):
            envelope = probe.get(role)
            tuples = envelope.get("udp_tuple_observations") if isinstance(envelope, dict) else None
            return tuples.get(key) if isinstance(tuples, dict) else None
        boxes = probe.get("boxes")
        box = boxes.get(cohort) if isinstance(boxes, dict) else None
        actor = box if role == "parent" else box.get("child") if isinstance(box, dict) else None
        tuples = actor.get("udp_tuple_observations") if isinstance(actor, dict) else None
        return tuples.get(key) if isinstance(tuples, dict) else None

    observations = probe.get("observations")
    if not isinstance(observations, dict):
        return None
    if role.startswith("outside_"):
        envelope = observations.get("outside_wire_" + role.removeprefix("outside_"))
        actor = envelope
    else:
        selected = observations.get("selected_parent_and_child")
        actor = selected if role == "parent" else selected.get("child") if isinstance(selected, dict) else None
    return actor.get(key) if isinstance(actor, dict) else None


def _udp_metadata(row, family: str, role: str, nonce: str):
    """Validate a tuple row; never infer wire delivery from send_ok."""
    import ipaddress
    expected_payload = ("RPWFREE:" + nonce + ":" + role).encode("ascii").hex()
    if not isinstance(row, dict):
        return {"present": False, "tuple_valid": False, "attempted": False,
                "metadata_complete": False, "send_ok": None, "source_ip": None,
                "payload_valid": False}
    try:
        source = ipaddress.ip_address(row.get("source_ip"))
        destination = ipaddress.ip_address(row.get("dest_ip"))
        source_ok = source.version == (4 if family == "ipv4" else 6) and not source.is_unspecified
        dest_ok = str(destination) == UDP_DESTINATIONS[family]
    except (TypeError, ValueError):
        source_ok = dest_ok = False
        source = None
    family_ok = row.get("family") == family
    payload_valid = row.get("payload_hex") == expected_payload
    tuple_valid = bool(source_ok and dest_ok and row.get("dest_port") == UDP_PORT and family_ok)
    return {"present": True, "tuple_valid": tuple_valid, "attempted": row.get("attempted") is True,
            "metadata_complete": row.get("metadata_complete") is True,
            "send_ok": row.get("send_ok") if type(row.get("send_ok")) is bool else None,
            "source_ip": str(source) if source_ok else None, "payload_valid": payload_valid}


def cohorts_for(backend):
    return (SANDBOXIE_BASE, SANDBOXIE_DNS) if backend == "sandboxie" else ("proxybridge_selected",)


def prepare_udp_evidence(backend: str, probe: dict):
    """Return one parser manifest per cohort/family plus strict API facts."""
    if backend == "sandboxie":
        nonce = _nonce(probe.get("fixture_nonce"))
    elif backend == "proxybridge":
        observations = probe.get("observations")
        nonce = _nonce(observations.get("fixture_nonce") if isinstance(observations, dict) else None)
    else:
        raise ValueError("unknown_backend")
    plans, missing = [], []
    if nonce is None:
        return [], {"status": "incomplete", "reason": "udp_fixture_nonce_missing", "missing_groups": []}
    for cohort in cohorts_for(backend):
        for family in ("ipv4", "ipv6"):
            roles = {role: _udp_metadata(_udp_row(probe, backend, cohort, role, family),
                                         family, role, nonce) for role in ROLES}
            sources = {facts["source_ip"] for facts in roles.values()
                       if facts["tuple_valid"] and facts["source_ip"] is not None}
            # If one role row is absent, other validated rows can still permit
            # a positive marker observation. Absence separately requires every
            # role's actual API attempt and full metadata.
            tuple_ready = len(sources) == 1 and all(
                facts["tuple_valid"] for facts in roles.values() if facts["present"])
            metadata_complete = tuple_ready and all(
                facts["present"] and facts["attempted"] and facts["metadata_complete"]
                and facts["payload_valid"] for facts in roles.values())
            group = cohort + "_" + family
            if not tuple_ready:
                missing.append(group)
                continue
            source_ip = next(iter(sources))
            probes = [{"id": group + "_" + role, "group": group, "role": role,
                       "family": family, "protocol": "udp", "source_mac": UDP_SOURCE_MAC,
                       "source_ip": source_ip, "destination": UDP_DESTINATIONS[family],
                       "port": UDP_PORT,
                       "payload_hex": ("RPWFREE:" + nonce + ":" + role).encode("ascii").hex()}
                      for role in ROLES]
            plans.append({"id": group, "cohort": cohort, "family": family,
                          "manifest": {"schema_version": 1, "source_mac": UDP_SOURCE_MAC,
                                       "probes": probes},
                          "metadata_complete": metadata_complete, "roles": roles})
    status = ("complete" if len(plans) == len(cohorts_for(backend)) * 2 and not missing
              and all(plan["metadata_complete"] for plan in plans) else "incomplete")
    return plans, {"status": status,
                   "reason": None if status == "complete" else "udp_tuple_metadata_incomplete",
                   "missing_groups": missing}


def _pb_child_marker_ambiguous(probe: dict, family: str, nonce: str) -> bool:
    observations = probe.get("observations")
    if not isinstance(observations, dict):
        return False
    key = "public_udp4" if family == "ipv4" else "public_udp6"
    expected = ("RPWFREE:" + nonce + ":child").encode("ascii").hex()
    # These stages share the selected child's marker and source tuple; a NIC
    # capture has no stage timestamps to distinguish their packets.
    for scope in ("unselected_network", "after_proxy_stop"):
        actor = observations.get(scope)
        row = actor.get(key) if isinstance(actor, dict) else None
        facts = _udp_metadata(row, family, "child", nonce)
        if (facts["tuple_valid"] and facts["attempted"] and facts["payload_valid"]
                and isinstance(row, dict) and row.get("payload_hex") == expected):
            return True
    return False


def _analyze_udp(parser, private_pcap: Path, backend: str, probe: dict):
    plans, metadata = prepare_udp_evidence(backend, probe)
    nonce = (_nonce(probe.get("fixture_nonce")) if backend == "sandboxie" else
             _nonce(probe.get("observations", {}).get("fixture_nonce")
                    if isinstance(probe.get("observations"), dict) else None))
    family_reports = []
    for plan in plans:
        try:
            with private_pcap.open("rb") as stream:
                wire = parser.analyze_stream(stream, plan["manifest"])
        except (ValueError, OSError):
            wire = {"status": "incomplete", "unknown_records": None,
                    "positive_controls_complete": False, "control_windows_ordered": False,
                    "absence_observed": False, "counts": [], "unknown_reasons": {}}
        counts = {row.get("role"): row.get("count", 0) for row in wire.get("counts", [])
                  if isinstance(row, dict)}
        ambiguous = (backend == "proxybridge" and nonce is not None
                     and _pb_child_marker_ambiguous(probe, plan["family"], nonce))
        selected_roles = ("parent",) if backend == "proxybridge" else ("parent", "child")
        child_count = counts.get("child", 0)
        selected_observed = (any(counts.get(role, 0) > 0 for role in selected_roles)
                             or (backend == "proxybridge" and child_count > 0 and not ambiguous))
        controls = (wire.get("positive_controls_complete") is True
                    and wire.get("control_windows_ordered") is True)
        group_absent = (wire.get("absence_observed") is True and controls
                        and plan["metadata_complete"])
        if selected_observed:
            classification = "exact_selected_udp_marker_observed"
        elif child_count > 0 and ambiguous:
            classification = "child_marker_observed_but_phase_ambiguous"
        elif group_absent:
            classification = "no_selected_udp_marker_observed_with_complete_controls_and_api_metadata"
        else:
            classification = "capture_controls_or_api_metadata_incomplete"
        family_reports.append({"cohort": plan["cohort"], "family": plan["family"],
                               "cohort_identity_from_wire_proven": backend == "proxybridge",
                               "marker_scope": ("selected_backend_workload_shared_fixture_nonce"
                                                if backend == "sandboxie" else "proxybridge_selected_workload"),
                               "parser_status": wire.get("status"),
                               "unknown_records": wire.get("unknown_records"),
                               "unknown_reasons": wire.get("unknown_reasons"),
                               "positive_controls_complete": controls,
                               "api_attempts_and_metadata_complete": plan["metadata_complete"],
                               "selected_marker_observed": selected_observed,
                               "child_marker_count": child_count,
                               "child_marker_phase_ambiguous": ambiguous,
                               "child_marker_attributable_to_selected": child_count > 0 and not ambiguous,
                               "outside_before_packet_count": counts.get("outside_before", 0),
                               "outside_after_packet_count": counts.get("outside_after", 0),
                               "api_roles": {role: {key: facts[key] for key in
                                                   ("tuple_valid", "attempted", "metadata_complete",
                                                    "send_ok", "payload_valid")}
                                             for role, facts in plan["roles"].items()},
                               "wire_absence_observed": group_absent,
                               "classification": classification, "counts": wire.get("counts")})
    complete = (metadata["status"] == "complete"
                and len(family_reports) == len(cohorts_for(backend)) * 2
                and all(row["parser_status"] == "complete"
                        and row["api_attempts_and_metadata_complete"]
                        and row["positive_controls_complete"] for row in family_reports))
    return {"status": "complete" if complete else "incomplete",
            "reason": None if complete else metadata.get("reason", "udp_wire_scope_incomplete"),
            "families": family_reports,
            "selected_udp_marker_observed": any(row["selected_marker_observed"]
                                                  for row in family_reports),
            "wire_absence_observed": complete and all(row["wire_absence_observed"]
                                                       for row in family_reports),
            "acceptance_passed": False, "kernel_denial_proven": False}


def _secure_private_copy(path: Path):
    """Copy an artifact PCAP into a private, bounded file for the existing parser API."""
    if os.name != "posix" or not hasattr(os, "O_NOFOLLOW"):
        raise ValueError("private_capture_copy_unavailable")
    # Do not resolve before O_NOFOLLOW: resolving first would silently turn a
    # symlink input into its target and defeat the no-follow check.
    source_path = Path(os.path.abspath(os.fspath(path)))
    before_path = os.lstat(source_path)
    if stat.S_ISLNK(before_path.st_mode):
        raise ValueError("capture_symlink_rejected")
    fd = os.open(source_path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
    temporary_dir = tempfile.TemporaryDirectory(prefix="ruleproxy-free-evidence-")
    target = Path(temporary_dir.name) / "capture.pcap"
    try:
        before = os.fstat(fd)
        if (not stat.S_ISREG(before.st_mode) or before.st_nlink != 1
                or before.st_size > MAX_PCAP_BYTES
                or (before.st_dev, before.st_ino) != (before_path.st_dev, before_path.st_ino)):
            raise ValueError("capture_not_bounded_regular_file")
        with os.fdopen(fd, "rb") as source, target.open("xb") as dest:
            fd = -1
            os.chmod(target, 0o600)
            digest = hashlib.sha256()
            copied = 0
            while True:
                block = source.read(1024 * 1024)
                if not block:
                    break
                copied += len(block)
                if copied > MAX_PCAP_BYTES:
                    raise ValueError("capture_size_limit")
                dest.write(block)
                digest.update(block)
            after = os.fstat(source.fileno())
        if (copied != before.st_size or
                (before.st_dev, before.st_ino, before.st_size, before.st_mtime_ns, before.st_ctime_ns) !=
                (after.st_dev, after.st_ino, after.st_size, after.st_mtime_ns, after.st_ctime_ns)):
            raise ValueError("capture_changed_during_copy")
        return temporary_dir, target, digest.hexdigest()
    except Exception:
        if fd >= 0:
            os.close(fd)
        temporary_dir.cleanup()
        raise


def analyze(backend: str, guest: dict, pcap_path: Path) -> dict:
    probe, guest_status = _probe_report(guest, backend)
    manifest, api_execution = prepare_dns_evidence(backend, probe)
    probe_status = probe.get("status") if probe.get("status") in ("passed", "failed", "running") else None
    if guest_status != "passed" or probe_status != "passed":
        api_execution["status"] = "incomplete"
        api_execution["reason"] = "guest_or_probe_run_not_passed"
    result = {"schema_version": 1, "backend": backend, "status": "incomplete",
              "diagnostic_only": True, "product_acceptance_passed": False,
              "guest_run_status": guest_status, "probe_run_status": probe_status, "dns": None,
              "api_execution": api_execution,
              "udp_wire": {"status": "incomplete", "wire_absence_observed": False,
                           "reason": "udp_tuple_metadata_incomplete",
                           "socket_send_observations": _socket_observations(backend, probe),
                           "acceptance_passed": False, "kernel_denial_proven": False}}
    udp_plans, udp_metadata = prepare_udp_evidence(backend, probe)
    result["udp_wire"]["metadata_status"] = udp_metadata["status"]
    if len(manifest["probes"]) < 4 and not udp_plans:
        result["dns"] = {"status": "incomplete", "reason": "no_complete_nonce_group_available",
                         "acceptance_passed": False, "kernel_denial_proven": False}
        return result
    parser = _load_module("ruleproxy_free_backend_dns_parser", ROOT / ".github/windows_dns_packet_evidence.py")
    private_dir, private_pcap, copy_hash = _secure_private_copy(pcap_path)
    try:
        if len(manifest["probes"]) >= 4:
            wire = parser.analyze_capture(private_pcap, manifest)
        else:
            wire = None
        udp_parser = _load_module("ruleproxy_free_backend_udp_parser", ROOT / ".github/windows_packet_evidence.py")
        udp_wire = _analyze_udp(udp_parser, private_pcap, backend, probe)
    finally:
        private_dir.cleanup()
    result["udp_wire"].update(udp_wire)
    result["udp_wire"]["socket_send_observations"] = _socket_observations(backend, probe)
    result["udp_wire"]["capture_copy_sha256"] = copy_hash
    if wire is None:
        result["dns"] = {"status": "incomplete", "reason": "no_complete_nonce_group_available",
                         "acceptance_passed": False, "kernel_denial_proven": False}
        return result
    contained_observed = any(row["role"] in ("parent", "child") and row["count"] > 0
                             for row in wire.get("counts", []) if isinstance(row, dict))
    wire_zero = wire.get("absence_observed") is True
    api_complete = api_execution["status"] == "complete" and guest_status == "passed"
    if contained_observed:
        classification = "contained_nonce_dns_questions_observed"
    elif wire_zero and api_complete:
        classification = "no_contained_nonce_dns_questions_observed_with_completed_api_records"
    elif wire_zero:
        classification = "wire_scope_zero_observed_but_api_execution_incomplete"
    else:
        classification = "capture_or_controls_incomplete_or_unknown"
    result["dns"] = {"status": wire.get("status"), "classification": classification,
                      "scope": wire.get("scope"), "capture_sha256": wire.get("capture_sha256"),
                      "capture_copy_sha256": copy_hash,
                      "packet_records": wire.get("packet_records"),
                      "unknown_records": wire.get("unknown_records"),
                      "unknown_reasons": wire.get("unknown_reasons"),
                      "empty_tcp_payload_frames": wire.get("empty_tcp_payload_frames"),
                      "positive_controls_complete": all(g.get("positive_controls_complete") is True
                                                         for g in wire.get("groups", [])),
                      "contained_questions_observed": contained_observed,
                      "wire_absence_observed": wire_zero,
                      "kernel_denial_proven": False, "acceptance_passed": False,
                      "groups": wire.get("groups"), "counts": wire.get("counts")}
    result["status"] = ("observations_available" if wire.get("status") == "complete"
                        and (contained_observed or api_complete) else "incomplete")
    return result


def main(argv=None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--backend", choices=("sandboxie", "proxybridge"), required=True)
    parser.add_argument("--guest-result", type=Path, required=True)
    parser.add_argument("--pcap", type=Path, required=True)
    parser.add_argument("--report", type=Path, required=True)
    args = parser.parse_args(argv)
    if args.report.resolve() in (args.guest_result.resolve(), args.pcap.resolve()):
        parser.error("report must differ from its evidence inputs")
    try:
        guest = read_json(args.guest_result)
        result = analyze(args.backend, guest, args.pcap)
        exit_code = 0 if result["status"] == "observations_available" else 1
    except (ValueError, OSError, json.JSONDecodeError):
        result = {"schema_version": 1, "backend": args.backend, "status": "incomplete",
                  "diagnostic_only": True, "product_acceptance_passed": False,
                  "error": "guest_report_or_capture_invalid", "dns": None,
                  "udp_wire": {"status": "incomplete", "wire_absence_observed": False,
                               "reason": "analysis_input_invalid", "acceptance_passed": False,
                               "kernel_denial_proven": False}}
        exit_code = 1
    args.report.parent.mkdir(parents=True, exist_ok=True)
    pending = None
    try:
        with tempfile.NamedTemporaryFile(mode="w", encoding="ascii", dir=args.report.parent,
                                         prefix=".free-backend-evidence-", delete=False) as stream:
            pending = Path(stream.name)
            stream.write(json.dumps(result, ensure_ascii=True, indent=2) + "\n")
        os.replace(pending, args.report)
    finally:
        if pending is not None:
            pending.unlink(missing_ok=True)
    print(json.dumps({"status": result["status"], "backend": args.backend,
                      "product_acceptance_passed": False}, ensure_ascii=True))
    return exit_code


if __name__ == "__main__":
    raise SystemExit(main())
