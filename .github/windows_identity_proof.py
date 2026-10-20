"""Disabled-by-default native PSEC identity proof, not product qualification.

Stage 0 only executes a native token reporter. No socket, firewall, proxy,
credential, account, or desktop changes. Windows PSEC creates temporary
security state, so execution requires an explicitly approved disposable host.
Stage 1 policy construction is offline only until the real proxy is implemented.
"""
from __future__ import annotations
import argparse
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import re
import secrets
import shutil
import subprocess

ROOT = Path(__file__).resolve().parent.parent
SPEC = importlib.util.spec_from_file_location("identity_smoke_helpers", ROOT / ".github/windows_psec_compartment_smoke.py")
smoke = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(smoke)
NONCE = re.compile(r"[0-9a-f]{32}\Z")
PROFILE = re.compile(r"RuleProxy\.IdentityProof\.[0-9a-f]{32}\Z")
SID = re.compile(r"S-1-15-2(?:-[0-9]{1,10}){7}\Z")
MAX_OUTPUT = 128 * 1024


def policy(inputs, profile, actor, nonce, *, proxy=None):
    if not isinstance(nonce, str) or not NONCE.fullmatch(nonce):
        raise ValueError("invalid case nonce")
    command = [str(actor), "actor", nonce, str(Path(profile) / "actor.json")]
    value = {
        "$schema": "https://github.com/microsoft/mxc/schemas/stable/mxc-config.schema.1.0.0.json",
        "version": "1.0.0", "containment": "processcontainer",
        "containerId": "ruleproxy-identity-proof-" + nonce,
        "fallback": {"allowDaclMutation": False},
        "process": {"commandLine": subprocess.list2cmdline(command), "cwd": str(profile),
                    "inheritDefaultEnv": False, "env": [], "timeout": 15000},
        "filesystem": {"readonlyPaths": [str(inputs)], "readwritePaths": [str(profile)]},
        "ui": {"disable": True, "clipboard": "none"},
        "network": {"egress": {"default": "deny"},
                    "ingress": {"default": "deny", "hostLoopback": "deny"}},
    }
    if proxy is not None:
        # Input is an observed identity record, not an arbitrary profile string.
        # This validation is NOT evidence: the Windows controller must obtain it
        # from the owned process handle and OS-derived profile SID at runtime.
        if (not isinstance(proxy, dict) or set(proxy) != {"profile", "derived_sid", "token_sid", "appcontainer", "port"}
                or not isinstance(proxy["profile"], str) or not PROFILE.fullmatch(proxy["profile"])
                or not isinstance(proxy["derived_sid"], str) or not SID.fullmatch(proxy["derived_sid"])
                or proxy["token_sid"] != proxy["derived_sid"] or proxy["appcontainer"] is not True
                or type(proxy["port"]) is not int or not 1025 <= proxy["port"] <= 65535):
            raise ValueError("a live verified proxy identity and bounded port are required")
        value["network"]["ingress"]["default"] = "allow"
        value["processContainer"] = {"network": {"allowedProxyPeer": proxy["profile"]}}
        value["runtimeConfig"] = {"networkProxy": f"http://127.0.0.1:{proxy['port']}"}
        command[1] = "actor-http"
        command.append(str(proxy["port"]))
        value["process"]["commandLine"] = subprocess.list2cmdline(command)
    return value


def actual_tiers(data):
    # Closed-value extraction from the pinned executor's diagnostics. An
    # absent, duplicate, ambiguous or contradictory tier never counts as proof.
    if not isinstance(data, bytes) or len(data) > MAX_OUTPUT:
        return []
    return re.findall(r"(?m)^selected isolation tier: ([a-z-]+)\s*$", data.decode("utf-8", "replace"))


def stage0_checks(report):
    actor = report.get("actor", {})
    return {
        "request_aware_base_container": smoke.base_container_selected(report.get("probe"), report.get("probe_exit_code")),
        "actual_base_container": report.get("actual_tiers") == ["base-container"],
        "fresh_actor": actor.get("nonce") == report.get("nonce") and isinstance(report.get("nonce"), str)
                       and NONCE.fullmatch(report["nonce"]) is not None,
        "native_identity": actor.get("schemaVersion") == 1 and actor.get("mode") == "actor"
                           and actor.get("queriesSucceeded") is True and actor.get("errors") == []
                           and actor.get("tokenIsAppContainer") is True
                           and isinstance(actor.get("tokenAppContainerSid"), str)
                           and SID.fullmatch(actor["tokenAppContainerSid"]) is not None
                           and actor.get("tokenElevated") is False and actor.get("isProcessInJob") is True
                           and actor.get("tokenCapabilities") == []
                           and type(actor.get("pid")) is int and actor["pid"] > 0,
        "normal_exit": report.get("executor_exit_code") == 0 and report.get("timed_out") is False,
        "no_harness_error": "error" not in report,
    }


# Probe wire contract at pinned microsoft/mxc 7bf2102 probe.rs:20-113.
# These projections are evidence labels, never replacement acceptance rules.
TIERS = ("base-container", "appcontainer-bfs", "appcontainer-dacl")
PROBE_FACTS = ("baseContainerApiPresent", "nativeCaptureAvailable", "guardedCaptureAvailable",
    "bfscfgPresent", "bfsCompiledIn", "baseContainerSupportsDenyPaths", "baseContainerSupportsEnumeratePaths",
    "baseContainerSupportsIngressHostLoopbackAllow", "isolationSessionAvailable", "hyperlightAvailable")
UI_FACTS = ("canBlockClipboardRead", "canBlockClipboardWrite", "canBlockInputInjection",
    "canBlockInputMethodChanges", "canBlockExternalUiObjects", "canBlockGlobalUiNamespace",
    "canBlockDesktopSwitching", "canBlockLogoffOrShutdown", "canBlockSystemParameterChanges", "canBlockDisplaySettingsChanges")
DIAGNOSTIC_CATEGORIES = ("configuration", "permission", "unsupported", "job", "process_creation", "psec", "proxy")
DIAGNOSTIC_OPERATIONS = ("CreateProcessW", "CreateProcessAsUserW", "CreateProcessWithTokenW", "AssignProcessToJobObject",
    "CreateJobObjectW", "SetInformationJobObject", "CreateProcessSecurityEnvironment", "DeriveAppContainerSidFromAppContainerName",
    "CreateAppContainerProfile", "UpdateProcThreadAttribute", "GetLastError", "GetStdHandle", "SetHandleInformation", "ResumeThread")
ENVELOPE_CLASSES = ("psec_environment_create", "psec_environment_attach", "child_environment", "job_setup",
    "child_resume", "host_loopback_contract", "proxy_identity_conflict", "unclassified")
DETECTOR_ERRORS = {
    "DACL fallback required but fallback.allowDaclMutation is false": "reported_dacl_fallback_forbidden",
    "guarded WPR captureDenials fallback is unavailable": "reported_guarded_capture_unavailable",
    "processContainer.filesystem.enumeratePaths is not supported by this version of Windows; enumeration-only access requires native ProcessContainer support": "reported_enumerate_contract_unavailable",
    "network.ingress.hostLoopback='allow' is not supported by this version of Windows; host-loopback ingress requires native ProcessContainer support": "reported_host_loopback_contract_unavailable",
}
DETECTOR_CLASSES = tuple(DETECTOR_ERRORS.values()) + ("reported_write_dac_unavailable", "reported_system_directory_failure", "unclassified", "absent", "wrong_type")
POLICY_FIELDS = ("version", "containment", "containerId", "fallback.allowDaclMutation", "process.commandLine", "process.cwd",
    "process.env", "process.env[]", "process.inheritDefaultEnv", "process.timeout", "filesystem.readonlyPaths",
    "filesystem.readonlyPaths[]", "filesystem.readwritePaths", "filesystem.readwritePaths[]", "ui.disable", "ui.clipboard",
    "network.egress.default", "network.ingress.default", "network.ingress.hostLoopback")
CLI_CLASSES = ("reported_config_load_failure", "reported_json_syntax", "reported_typed_configuration",
    "reported_configuration", "reported_config_read_failure", "reported_containment_rejected", "reported_serialization_failure")
PROBE_OUTCOMES = ("not_attempted", "timed_out", "spawn_failed", "invocation_failed", "nonzero_exit", "output_over_bound",
    "invalid_json", "non_object", "reported_detector_error", "invalid_required_fact", "alternate_tier", "unknown_tier",
    "dacl_required", "api_not_observed", "selected", "unclassified")
CONTROLLER_PHASES = ("not_started", "identity_observation", "executor_verification", "actor_verification", "work_validation",
    "staging", "case", "report_write", "completed", "unclassified")
FAILURE_PHASES = ("policy_write", "probe_invocation", "executor_output_open", "executor_invocation", "executor_diagnostic_read", "actor_read", "unclassified", "absent")
FAILURE_TYPES = ("PermissionError", "ValueError", "TypeError", "FileNotFoundError", "FileExistsError", "OSError",
    "RuntimeError", "TimeoutError", "TimeoutExpired", "JSONDecodeError", "UnicodeDecodeError", "AttributeError", "unclassified", "absent")
ACTOR_STATES = ("not_reached", "absent", "link_rejected", "over_bound", "malformed_json", "non_object", "read_failed", "parsed", "unclassified")


def detector_error_class(value):
    if value is None: return "absent"
    if not isinstance(value, str): return "wrong_type"
    if value in DETECTOR_ERRORS: return DETECTOR_ERRORS[value]
    if value.startswith("WRITE_DAC unavailable on path "): return "reported_write_dac_unavailable"
    if value.startswith("Could not resolve Windows system directory: "): return "reported_system_directory_failure"
    return "unclassified"


def cli_diagnostic(data):
    message = data[:65536].decode("utf-8", "replace")
    markers = {"reported_config_load_failure": "Error: failed to load probe config",
        "reported_json_syntax": "Invalid JSON syntax:", "reported_typed_configuration": "Invalid configuration at `",
        "reported_configuration": "Invalid configuration:", "reported_config_read_failure": "Unable to read JSON configuration:",
        "reported_containment_rejected": "Error: request-aware probe supports only ProcessContainer containment; got ",
        "reported_serialization_failure": "Error: probe serialization failed:"}
    paths = []
    for path in re.findall(r"Invalid configuration at `([^`\r\n]{1,256})`", message):
        path = re.sub(r"\[[0-9]{1,5}\]", "[]", path)
        if path in POLICY_FIELDS and path not in paths: paths.append(path)
    return {"classes": [key for key, marker in markers.items() if marker in message], "policy_fields": paths}


def _dict(value): return value if isinstance(value, dict) else {}
def _enum(value, allowed, default="unclassified"): return value if isinstance(value, str) and value in allowed else default
def _integer(value, low=0, high=0xffffffff): return value if type(value) is int and low <= value <= high else None
def _boolean(value): return value if type(value) is bool else None
def _digest(value): return value if isinstance(value, str) and re.fullmatch(r"[0-9a-f]{64}", value) else None

def _known_list(value, allowed):
    return [key for key in allowed if isinstance(value, list) and key in value]


def _codes(value):
    result = set()
    for item in value[:8] if isinstance(value, list) else []:
        if type(item) is int:
            number = item
        elif isinstance(item, str) and re.fullmatch(r"(?:0x[0-9a-fA-F]{1,8}|-?[0-9]{1,10})", item):
            number = int(item, 16 if item.startswith("0x") else 10)
        else: continue
        if -0x80000000 <= number <= 0xffffffff: result.add(number)
    return sorted(result)


def diagnostic_summary(value):
    """Rebuild closed helper output; never trust a nested dictionary as safe."""
    value = _dict(value)
    result = {"bytes_observed": _integer(value.get("bytes_observed"), high=2**31-1),
        "inspection_truncated": value.get("inspection_truncated") is True,
        "categories": _known_list(value.get("categories"), DIAGNOSTIC_CATEGORIES),
        "operations": _known_list(value.get("operations"), DIAGNOSTIC_OPERATIONS),
        "native_codes": _codes(value.get("native_codes")), "inspected_sha256": _digest(value.get("inspected_sha256")),
        "error_envelope_count": max(_integer(value.get("error_envelope_count"), high=4) or 0, min(4, len(value.get("error_envelopes", []))) if isinstance(value.get("error_envelopes"), list) else 0),
        "error_envelopes": []}
    for entry in value.get("error_envelopes", [])[:1] if isinstance(value.get("error_envelopes"), list) else []:
        entry = _dict(entry)
        result["error_envelopes"].append({"code": _enum(entry.get("code"), ("backend_error", "policy_validation")),
            "message_class": _enum(entry.get("message_class"), ENVELOPE_CLASSES),
            "message_sha256": _digest(entry.get("message_sha256")), "has_extended_error": entry.get("has_extended_error") is True,
            "extended_error_sha256": _digest(entry.get("extended_error_sha256")),
            "categories": _known_list(entry.get("categories"), DIAGNOSTIC_CATEGORIES),
            "operations": _known_list(entry.get("operations"), DIAGNOSTIC_OPERATIONS), "native_codes": _codes(entry.get("native_codes"))})
    return result


def _fact(container, key):
    if not isinstance(container, dict) or key not in container: return {"state": "missing", "value": None}
    value = container[key]
    return {"state": "value" if type(value) is bool else "wrong_type", "value": _boolean(value)}


def _closed_fact(value):
    value = _dict(value)
    state = _enum(value.get("state"), ("missing", "wrong_type", "value"), "missing")
    boolean = _boolean(value.get("value"))
    if state == "value" and boolean is None: state = "wrong_type"
    return {"state": state, "value": boolean if state == "value" else None}


def closed_diagnostics(raw):
    """Idempotent public projection; no paths, IDs, warning/error text or SID."""
    raw = _dict(raw)
    candidate = raw.get("diagnostics")
    if not isinstance(candidate, dict):
        probe = _dict(raw.get("probe")); facts = probe.get("probes"); ui = _dict(facts).get("uiCapabilities")
        tier = probe.get("tier")
        warnings = probe.get("warnings")
        actual = raw.get("actual_tiers")
        candidate = {"controller_phase": raw.get("controller_phase"), "failure_phase": raw.get("failure_phase"),
            "failure": raw.get("error"), "probe": {
                "attempted": raw.get("probe_attempted"), "completed": raw.get("probe_completed"),
                "outcome": raw.get("probe_outcome"), "exit_code": raw.get("probe_exit_code"),
                "stdout_state": raw.get("probe_stdout_state"), "tier": tier,
                "tier_state": "missing" if "tier" not in probe else "known" if tier in TIERS else "unknown" if isinstance(tier, str) else "wrong_type",
                "needs_dacl_augmentation": _fact(probe, "needsDaclAugmentation"),
                "probes_state": "missing" if "probes" not in probe else "object" if isinstance(facts, dict) else "wrong_type",
                "facts": {key: _fact(facts, key) for key in PROBE_FACTS},
                "ui_state": "missing" if "uiCapabilities" not in _dict(facts) else "object" if isinstance(ui, dict) else "wrong_type",
                "ui_facts": {key: _fact(ui, key) for key in UI_FACTS},
                "error_present": probe.get("error") is not None, "error_class": raw.get("probe_error_class"),
                "error_summary": raw.get("probe_error_diagnostic"),
                "warnings_state": "missing" if "warnings" not in probe else "array" if isinstance(warnings, list) else "wrong_type",
                "warning_count": len(warnings) if isinstance(warnings, list) else None,
                "warning_nonstring_count": sum(not isinstance(item, str) for item in warnings) if isinstance(warnings, list) else None,
                "warning_summaries": raw.get("probe_warning_diagnostics"),
                "stdout": raw.get("probe_stdout_diagnostic"), "stderr": raw.get("probe_diagnostic"), "cli": raw.get("probe_cli_diagnostic")},
            "execution": {"launch_attempted": raw.get("started"), "outcome": raw.get("executor_outcome"),
                "exit_code": raw.get("executor_exit_code"), "timed_out": raw.get("timed_out"),
                "actual_tier_count": len(actual) if isinstance(actual, list) else None,
                "actual_tiers": [tier for tier in actual if tier in TIERS] if isinstance(actual, list) else [],
                "unknown_tier_count": sum(tier not in TIERS for tier in actual) if isinstance(actual, list) else None,
                "actor_report_state": raw.get("actor_report_state"),
                "actor_reparse_point_observed": raw.get("actor_reparse_point_observed"),
                "actor_checks_passed": _dict(raw.get("checks")).get("fresh_actor") is True and _dict(raw.get("checks")).get("native_identity") is True,
                "stdout": raw.get("stdout_diagnostic"), "stderr": raw.get("stderr_diagnostic")}}
    probe = _dict(candidate.get("probe")); execution = _dict(candidate.get("execution")); failure = _dict(candidate.get("failure"))
    cli = _dict(probe.get("cli"))
    return {"policy_schema_version": "1.0.0", "required_tier": "base-container",
        "probe_schema_version_available": False, "numeric_psec_contract_version_available": False,
        "controller_phase": _enum(candidate.get("controller_phase"), CONTROLLER_PHASES),
        "failure_phase": _enum(candidate.get("failure_phase"), FAILURE_PHASES, "absent"),
        "failure": {"type": _enum(failure.get("type"), FAILURE_TYPES, "absent" if not failure else "unclassified"),
                    "winerror": _integer(failure.get("winerror"), -0x80000000), "errno": _integer(failure.get("errno"), -0x80000000)},
        "probe": {"attempted": probe.get("attempted") is True, "completed": probe.get("completed") is True,
            "outcome": _enum(probe.get("outcome"), PROBE_OUTCOMES, "not_attempted"),
            "exit_code": _integer(probe.get("exit_code"), -0x80000000),
            "stdout_state": _enum(probe.get("stdout_state"), ("object", "invalid_json", "non_object", "output_over_bound"), "not_observed"),
            "tier": _enum(probe.get("tier"), TIERS, "not_observed"),
            "tier_state": _enum(probe.get("tier_state"), ("known", "unknown", "missing", "wrong_type"), "missing"),
            "needs_dacl_augmentation": _closed_fact(probe.get("needs_dacl_augmentation")),
            "probes_state": _enum(probe.get("probes_state"), ("object", "missing", "wrong_type"), "missing"),
            "facts": {key: _closed_fact(_dict(probe.get("facts")).get(key)) for key in PROBE_FACTS},
            "ui_state": _enum(probe.get("ui_state"), ("object", "missing", "wrong_type"), "missing"),
            "ui_facts": {key: _closed_fact(_dict(probe.get("ui_facts")).get(key)) for key in UI_FACTS},
            "error_present": probe.get("error_present") is True, "error_class": _enum(probe.get("error_class"), DETECTOR_CLASSES, "absent"),
            "error_summary": diagnostic_summary(probe.get("error_summary")),
            "warnings_state": _enum(probe.get("warnings_state"), ("array", "missing", "wrong_type"), "missing"),
            "warning_count": _integer(probe.get("warning_count"), high=MAX_OUTPUT),
            "warning_nonstring_count": _integer(probe.get("warning_nonstring_count"), high=MAX_OUTPUT),
            "warning_summaries": [diagnostic_summary(item) for item in probe.get("warning_summaries", [])[:2]] if isinstance(probe.get("warning_summaries"), list) else [],
            "stdout": diagnostic_summary(probe.get("stdout")), "stderr": diagnostic_summary(probe.get("stderr")),
            "cli": {"classes": _known_list(cli.get("classes"), CLI_CLASSES), "policy_fields": _known_list(cli.get("policy_fields"), POLICY_FIELDS)}},
        "execution": {"launch_attempted": execution.get("launch_attempted") is True,
            "outcome": _enum(execution.get("outcome"), ("not_attempted", "launch_attempted", "completed", "timed_out", "launch_failed"), "not_attempted"),
            "exit_code": _integer(execution.get("exit_code"), -0x80000000), "timed_out": _boolean(execution.get("timed_out")),
            "actual_tier_count": _integer(execution.get("actual_tier_count"), high=8192),
            "actual_tiers": _known_list(execution.get("actual_tiers"), TIERS),
            "unknown_tier_count": _integer(execution.get("unknown_tier_count"), high=8192),
            "actor_report_state": _enum(execution.get("actor_report_state"), ACTOR_STATES, "not_reached"),
            "actor_reparse_point_observed": _boolean(execution.get("actor_reparse_point_observed")),
            "actor_checks_passed": execution.get("actor_checks_passed") is True,
            "stdout": diagnostic_summary(execution.get("stdout")), "stderr": diagnostic_summary(execution.get("stderr"))}}


def probe_outcome(result):
    """Describe observations, not OS support. Never replace the acceptance gate."""
    if result.get("probe_completed") is not True:
        return result.get("probe_failure_kind", "not_attempted")
    if result.get("probe_exit_code") != 0:
        return "nonzero_exit"
    state = result.get("probe_stdout_state")
    if state != "object":
        return state
    value = result["probe"]
    if value.get("error") is not None:
        return "reported_detector_error" if isinstance(value["error"], str) else "invalid_required_fact"
    if (not isinstance(value.get("tier"), str) or type(value.get("needsDaclAugmentation")) is not bool
            or not isinstance(value.get("probes"), dict)
            or type(value["probes"].get("baseContainerApiPresent")) is not bool):
        return "invalid_required_fact"
    if value["tier"] != "base-container":
        return "alternate_tier" if value["tier"] in TIERS else "unknown_tier"
    if value["needsDaclAugmentation"]:
        return "dacl_required"
    if not value["probes"]["baseContainerApiPresent"]:
        return "api_not_observed"
    return "selected" if smoke.base_container_selected(value, result["probe_exit_code"]) else "unclassified"


def run_case(executor, value, profile, *, runner=subprocess.run):
    """Retain bounded causal evidence; policy, order and acceptance are unchanged."""
    target = Path(profile) / "policy.json"
    result = {"started": False, "probe_attempted": False, "probe_completed": False,
              "actor_report_state": "not_reached", "executor_outcome": "not_attempted"}
    try:
        smoke.save(target, value)
    except Exception as exc:
        result.update(error=smoke.failure(exc), failure_phase="policy_write", probe_outcome="not_attempted", status="probe_failed")
        return result
    result["probe_attempted"] = True
    try:
        probe = runner([str(executor), "--probe", "--config", str(target)],
                       stdin=subprocess.DEVNULL, capture_output=True, timeout=30)
    except Exception as exc:
        result.update(error=smoke.failure(exc), failure_phase="probe_invocation", status="probe_failed",
                      probe_failure_kind="timed_out" if isinstance(exc, subprocess.TimeoutExpired) else
                      "spawn_failed" if isinstance(exc, OSError) else "invocation_failed")
        if isinstance(exc, subprocess.TimeoutExpired):
            for source, target_name in ((exc.stdout, "probe_stdout_diagnostic"), (exc.stderr, "probe_diagnostic")):
                if isinstance(source, bytes): result[target_name] = smoke.executor_diagnostic(source)
            if isinstance(exc.stderr, bytes): result["probe_cli_diagnostic"] = cli_diagnostic(exc.stderr)
        result["probe_outcome"] = probe_outcome(result)
        return result
    result.update(probe_completed=True, probe_exit_code=probe.returncode)
    result["probe_diagnostic"] = smoke.executor_diagnostic(probe.stderr)
    result["probe_stdout_diagnostic"] = smoke.executor_diagnostic(probe.stdout)
    result["probe_cli_diagnostic"] = cli_diagnostic(probe.stderr)
    parsed = None
    if len(probe.stdout) > MAX_OUTPUT:
        result["probe_stdout_state"] = "output_over_bound"
    else:
        try:
            parsed = json.loads(probe.stdout)
            result["probe_stdout_state"] = "object" if isinstance(parsed, dict) else "non_object"
        except (ValueError, TypeError):
            result["probe_stdout_state"] = "invalid_json"
    result["probe"] = ({key: parsed[key] for key in ("tier", "needsDaclAugmentation", "warnings", "probes", "error")
                        if key in parsed} if isinstance(parsed, dict) else None)
    if isinstance(parsed, dict):
        error = parsed.get("error")
        result["probe_error_diagnostic"] = smoke.executor_diagnostic(error.encode("utf-8", "replace")) if isinstance(error, str) else None
        result["probe_error_class"] = detector_error_class(error)
        warnings = parsed.get("warnings")
        result["probe_warning_diagnostics"] = [smoke.executor_diagnostic(item.encode("utf-8", "replace"))
            for item in warnings[:8] if isinstance(item, str)] if isinstance(warnings, list) else []
    result["probe_outcome"] = probe_outcome(result)
    if not smoke.base_container_selected(result["probe"], probe.returncode):
        result["status"] = "unsupported"  # Historical private status, not an OS inference.
        return result
    # These are launch attempts, not independently observed actor startup.
    try:
        with (Path(profile) / "executor.stdout").open("xb") as out, (Path(profile) / "executor.stderr").open("xb") as err:
            result["started"] = True
            result["executor_outcome"] = "launch_attempted"
            try:
                completed = runner([str(executor), "--config", str(target), "--debug"],
                                   stdin=subprocess.DEVNULL, stdout=out, stderr=err, timeout=35)
                result.update(executor_exit_code=completed.returncode, timed_out=False, executor_outcome="completed")
            except subprocess.TimeoutExpired:
                result.update(executor_exit_code=None, timed_out=True, executor_outcome="timed_out")
            except Exception as exc:
                result.update(error=smoke.failure(exc), failure_phase="executor_invocation", executor_outcome="launch_failed")
    except Exception as exc:
        result.update(error=smoke.failure(exc), failure_phase="executor_output_open", status="observed")
        return result
    tiers = []
    try:
        for name in ("stdout", "stderr"):
            with (Path(profile) / ("executor." + name)).open("rb") as stream:
                data = stream.read(MAX_OUTPUT + 1)
            tiers.extend(actual_tiers(data))
            result[name + "_diagnostic"] = smoke.executor_diagnostic(data)
    except Exception as exc:
        result.update(error=smoke.failure(exc), failure_phase="executor_diagnostic_read")
    result["actual_tiers"] = tiers
    actor = Path(profile) / "actor.json"
    result["actor_report_state"] = "absent"
    try:
        attributes = getattr(actor.lstat(), "st_file_attributes", None)
        result["actor_reparse_point_observed"] = bool(attributes & 0x400) if type(attributes) is int else None
    except OSError:
        result["actor_reparse_point_observed"] = None
    try:
        if actor.is_symlink():
            result["actor_report_state"] = "link_rejected"
        elif actor.is_file():
            result["actor_report_state"] = "read_attempted"
            with actor.open("rb") as stream:
                data = stream.read(smoke.MAX_JSON + 1)
            if len(data) > smoke.MAX_JSON:
                result["actor_report_state"] = "over_bound"
                raise ValueError("bounded actor report required")
            try:
                actor_value = json.loads(data)
            except (ValueError, TypeError):
                result["actor_report_state"] = "malformed_json"
                raise
            if not isinstance(actor_value, dict):
                result["actor_report_state"] = "non_object"
                raise ValueError("actor report must be an object")
            result["actor"] = actor_value
            result["actor_report_state"] = "parsed"
    except Exception as exc:
        if result["actor_report_state"] == "read_attempted": result["actor_report_state"] = "read_failed"
        result.update(error=smoke.failure(exc), failure_phase="actor_read")
    result["status"] = "observed"
    return result


def controller(args):
    if os.name != "nt" or not args.disposable_ci or not args.approved_security_test:
        raise PermissionError("requires an approved disposable Windows security test")
    args.diagnostic_phase = "identity_observation"
    identity = smoke.identity_snapshot()
    if identity["elevated"] or identity["appcontainer"] or identity["cid"] != 1:
        raise PermissionError("run from an ordinary non-AppContainer user in the default compartment")
    args.diagnostic_phase = "executor_verification"
    provenance = smoke.verify_executor(args.executor, args.manifest)
    args.diagnostic_phase = "actor_verification"
    actor = args.actor.resolve(strict=True)
    if actor.suffix.lower() != ".exe" or not 512 <= actor.stat().st_size <= 8 * 1024 * 1024:
        raise ValueError("expected bounded native actor executable")
    digest = hashlib.sha256(actor.read_bytes()).hexdigest()
    if digest != args.actor_sha256:
        raise ValueError("actor differs from explicitly supplied build digest")
    args.diagnostic_phase = "work_validation"
    work = args.work.resolve()
    if args.report.resolve() != work / "report.json":
        raise ValueError("report must be new WORK/report.json")
    if work.exists():
        raise ValueError("a fresh disposable work directory is required")
    for name in ("SystemRoot", "ProgramFiles", "ProgramFiles(x86)"):
        if os.environ.get(name):
            protected = Path(os.environ[name]).resolve()
            if work == protected or protected in work.parents:
                raise ValueError("protected work directory")
    args.diagnostic_phase = "staging"
    work.mkdir(parents=True)
    inputs, profile = work / "inputs", work / "profile"
    inputs.mkdir(); profile.mkdir()
    staged_actor, staged_executor = inputs / "actor.exe", inputs / "wxc-exec.exe"
    shutil.copyfile(actor, staged_actor)
    shutil.copyfile(args.executor, staged_executor)
    nonce = secrets.token_hex(16)
    report = {"schema_version": 1, "stage": 0, "nonce": nonce, "provenance": provenance,
              "actor_sha256": digest, "privacy_qualified": False, "product_acceptance": False,
              "network_tested": False, "controller_identity": identity}
    args.diagnostic_phase = "case"
    try:
        report.update(run_case(staged_executor, policy(inputs, profile, staged_actor, nonce), profile))
    except Exception as exc:
        report["error"] = smoke.failure(exc)
    report["checks"] = stage0_checks(report)
    report["stage0_passed"] = all(report["checks"].values())
    # Retain owned directory as diagnostic evidence; no blanket recursive delete.
    report["cleanup"] = {"work_directory_retained": True, "psec_cleanup_independently_verified": False}
    # Keep a private in-memory snapshot so a failed final write/read cannot
    # erase already observed probe/executor evidence from the closed wrapper.
    args.diagnostic_report = report
    args.diagnostic_phase = "report_write"
    smoke.save(args.report, report)
    args.diagnostic_phase = "completed"
    return 0 if report["stage0_passed"] else 1


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--disposable-ci", action="store_true")
    parser.add_argument("--approved-security-test", action="store_true")
    for name in ("executor", "manifest", "actor", "work", "report"):
        parser.add_argument("--" + name, type=Path, required=True)
    parser.add_argument("--actor-sha256", required=True)
    args = parser.parse_args(argv)
    return controller(args)


if __name__ == "__main__":
    raise SystemExit(main())
