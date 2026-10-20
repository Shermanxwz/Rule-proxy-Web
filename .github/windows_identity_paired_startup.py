"""Four fixed native-startup diagnostic cells, not an isolation acceptance test.

The same full/IdentityOnly actor builds each run under the unchanged current
source token and an independently derived restricted token. No accounts, new
credentials, privilege grants/adjustments, profiles, ACLs, or network tests.
The source control is never a fallback or a restricted/ordinary-user success.
"""
from __future__ import annotations

import argparse
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import secrets
from types import SimpleNamespace

ROOT = Path(__file__).resolve().parents[1]
SPEC = importlib.util.spec_from_file_location(
    "paired_startup_restricted", Path(__file__).with_name("windows_identity_restricted_launcher.py"))
lab = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(lab)
ordinary = lab.ordinary
GateFailure = lab.GateFailure
CELLS = (("full-source", "full", False), ("full-restricted", "full", True),
         ("identity-source", "identity", False), ("identity-restricted", "identity", True))
PUBLIC_OPERATIONS = {
    "invariant": "invariant",
    "launcher": "launcher",
    "OpenProcessToken": "open_process_token",
    "OpenProcessToken(restricted_source)": "open_source_token",
    "CreateRestrictedToken": "create_restricted_token",
    "SetTokenInformation(new_token_medium_integrity)": "set_derived_medium_integrity",
    "CreateProcessAsUserW": "create_process_as_user",
    "CreateFileW(owned_stdio)": "create_owned_stdio",
    "CreateJobObjectW": "create_owned_job",
    "SetInformationJobObject": "configure_owned_job",
    "QueryInformationJobObject": "verify_owned_job",
    "QueryInformationJobObject(basic_accounting)": "query_owned_job_accounting",
    "AssignProcessToJobObject": "assign_owned_job",
    "IsProcessInJob": "verify_job_membership",
    "QueryFullProcessImageNameW": "verify_process_image",
    "InitializeProcThreadAttributeList": "initialize_process_attributes",
    "UpdateProcThreadAttribute(handle_list)": "set_owned_handle_list",
    "ResumeThread": "resume_owned_child",
    "WaitForSingleObject": "wait_owned_process",
    "GetExitCodeProcess": "query_owned_exit_code",
    "TerminateJobObject": "terminate_owned_job",
    "TerminateProcess": "terminate_owned_process",
    "CloseHandle": "close_owned_handle",
    "LookupPrivilegeNameW": "query_privilege_name",
    "ConvertSidToStringSidW": "convert_token_sid",
    "LocalFree(SID_string)": "free_token_sid_string",
}
for _name in ("TokenUser", "TokenGroups", "TokenPrivileges", "TokenType", "TokenStatistics",
              "TokenRestrictedSids", "TokenSessionId", "TokenSandBoxInert", "TokenElevationType",
              "TokenElevation", "TokenHasRestrictions", "TokenIntegrityLevel", "TokenUIAccess",
              "TokenLogonSid", "TokenIsAppContainer", "TokenCapabilities", "TokenAppContainerSid"):
    PUBLIC_OPERATIONS["GetTokenInformation(" + _name + ")"] = "query_" + _name


def public_boolean(value):
    return value if type(value) is bool else None


def public_digest(value):
    return value if isinstance(value, str) and ordinary.DIGEST_PATTERN.fullmatch(value) else None


def public_error(value):
    if not isinstance(value, dict):
        return None
    operation = value.get("operation")
    result = {"operation_id": PUBLIC_OPERATIONS.get(operation, "unclassified_operation")
              if isinstance(operation, str) else "unclassified_operation"}
    code = value.get("winerror")
    if type(code) is int and 0 <= code <= 0xFFFFFFFF:
        result["native_error_code"] = code
    # Never copy reason/type/message: even an ostensibly invariant error can
    # acquire arbitrary exception text. Native operation IDs are closed above.
    return result


def public_errors(values):
    if not isinstance(values, list):
        return []
    return [public_error(value) for value in values[:32] if isinstance(value, dict)]


def publication_projection(report):
    """Pure closed output boundary; full native evidence remains local only."""
    if not isinstance(report, dict):
        raise GateFailure("publication_source_must_be_report_object")
    source_bytes = (json.dumps(report, ensure_ascii=True, indent=2) + "\n").encode("ascii")
    if len(source_bytes) > ordinary.MAX_REPORT:
        raise GateFailure("publication_source_report_too_large")
    result = {
        "schema_version": 1, "stage": "paired-native-startup-diagnostic-public",
        "sanitized": True, "byte_exact": False,
        "source_report_sha256": hashlib.sha256(source_bytes).hexdigest(),
        "dependency_audit_sha256": public_digest(report.get("dependency_audit_sha256")),
        "ordinary_user_acceptance": False, "restricted_caller_r0_passed": False,
        "stage0b_passed": False, "psec_acceptance": False,
        "product_acceptance": False, "privacy_qualified": False,
        "diagnostic_completed": public_boolean(report.get("diagnostic_completed")),
        "all_actor_startups_succeeded": public_boolean(report.get("all_actor_startups_succeeded")),
        "source_identity_verified": public_boolean(report.get("source_identity_verified")),
        "parent_token_unchanged": public_boolean(report.get("parent_token_unchanged")),
        "builds": {}, "cells": [],
    }
    builds = report.get("builds")
    builds = builds if isinstance(builds, dict) else {}
    for variant in ("full", "identity"):
        build = builds.get(variant)
        build = build if isinstance(build, dict) else {}
        result["builds"][variant] = {
            key: public_digest(build.get(key))
            for key in ("actor_sha256", "source_sha256", "build_manifest_sha256")}
        result["builds"][variant]["http_compiled"] = public_boolean(build.get("http_compiled"))
        result["builds"][variant]["static_crt"] = public_boolean(build.get("static_crt"))
    cells = report.get("cells")
    if not isinstance(cells, list) or len(cells) > len(CELLS):
        raise GateFailure("publication_expected_bounded_cell_list")
    indexed, labels = {}, {item[0] for item in CELLS}
    for cell in cells:
        if (not isinstance(cell, dict) or not isinstance(cell.get("label"), str)
                or cell["label"] not in labels or cell["label"] in indexed):
            raise GateFailure("publication_expected_unique_fixed_cell_labels")
        indexed[cell["label"]] = cell
    for label, _, _ in CELLS:
        cell = indexed.get(label)
        item = {"label": label, "attempted": cell is not None}
        result["cells"].append(item)
        if cell is None:
            continue
        for key in ("derived_token_created", "derived_identity_verified", "process_created",
                    "parent_token_unchanged", "actor_report_present", "actor_matches_native_observation",
                    "actor_started_and_reported", "safe_to_continue"):
            item[key] = public_boolean(cell.get(key))
        item["actor_sha256"] = public_digest(cell.get("actor_sha256"))
        item["error"] = public_error(cell.get("error"))
        launch = cell.get("launch")
        launch = launch if isinstance(launch, dict) else {}
        for key in ("started", "resumed", "timed_out", "source_control", "job_created",
                    "assigned_to_owned_job", "native_verified_before_resume"):
            item[key] = public_boolean(launch.get(key))
        exit_code = launch.get("exit_code")
        item["native_exit_code"] = exit_code if type(exit_code) is int and 0 <= exit_code <= 0xFFFFFFFF else None
        item["launch_error"] = public_error(launch.get("error"))
        cleanup = cell.get("cleanup")
        cleanup = cleanup if isinstance(cleanup, dict) else {}
        launch_cleanup = launch.get("cleanup")
        launch_cleanup = launch_cleanup if isinstance(launch_cleanup, dict) else {}
        item["cleanup"] = {key: public_boolean(cleanup.get(key))
                           for key in ("derived_token_closed", "process_cleanup_confirmed")}
        item["cleanup"].update({key: public_boolean(launch_cleanup.get(key))
                                for key in ("job_closed", "job_empty", "process_exit_confirmed", "handles_closed")})
        item["cleanup"]["errors"] = public_errors(cleanup.get("errors")) + public_errors(launch_cleanup.get("errors"))
        checks = cell.get("parent_token_checks")
        checks = checks if isinstance(checks, list) else []
        item["parent_token_checks"] = [
            {"phase": check["phase"], "unchanged": public_boolean(check.get("unchanged")),
             "error": public_error(check.get("error"))}
            for check in checks[:3] if isinstance(check, dict)
            and check.get("phase") in ("before_cell", "after_derivation", "after_cleanup")]
    cleanup = report.get("cleanup")
    cleanup = cleanup if isinstance(cleanup, dict) else {}
    result["cleanup"] = {"source_token_closed": public_boolean(cleanup.get("source_token_closed")),
                         "errors": public_errors(cleanup.get("errors"))}
    result["error"] = public_error(report.get("error"))
    return result


def bounded_json(path, root):
    path = ordinary.checked_path(path, inside=root)
    with path.open("rb") as stream:
        content = stream.read(ordinary.MAX_REPORT + 1)
    if len(content) > ordinary.MAX_REPORT:
        raise GateFailure("paired_metadata_too_large")
    value = json.loads(content)
    if not isinstance(value, dict):
        raise GateFailure("paired_metadata_must_be_object")
    return value, hashlib.sha256(content).hexdigest()


def validate_inputs(args):
    root = ordinary.checked_path(ROOT, is_file=False)
    ordinary.checked_path(root / ".github/windows_identity_restricted_launcher.py", inside=root)
    builds, work = {}, None
    for variant, http in (("full", True), ("identity", False)):
        actor, cell_work = lab.validate_inputs(SimpleNamespace(
            actor=getattr(args, "actor_" + variant),
            actor_sha256=getattr(args, "actor_" + variant + "_sha256"),
            work=args.work, report=args.report))
        if work is not None and cell_work != work:
            raise GateFailure("paired_work_mismatch")
        work = cell_work
        digest = getattr(args, "actor_" + variant + "_sha256")
        manifest, manifest_digest = bounded_json(actor.parent / "build-manifest.json", root)
        source_digest = manifest.get("sourceSha256")
        if not (
            manifest.get("schemaVersion") == 1 and manifest.get("httpCompiled") is http
            and manifest.get("executableSha256") == digest
            and isinstance(source_digest, str) and ordinary.DIGEST_PATTERN.fullmatch(source_digest)
            and manifest.get("staticCrt") is True and manifest.get("compileOnly") is True
        ):
            raise GateFailure("paired_build_manifest_mismatch")
        builds[variant] = {
            "actor": actor, "actor_sha256": digest, "source_sha256": source_digest,
            "build_manifest_sha256": manifest_digest, "http_compiled": http, "static_crt": True,
        }
    if (builds["full"]["actor"] == builds["identity"]["actor"]
            or builds["full"]["actor_sha256"] == builds["identity"]["actor_sha256"]
            or builds["full"]["source_sha256"] != builds["identity"]["source_sha256"]):
        raise GateFailure("paired_distinct_builds_same_source_required")
    _, audit_digest = bounded_json(args.dependency_audit, root)
    return builds, work, audit_digest


def cleanup_confirmed(launch):
    if launch is None:
        return True  # No launch attempt was made.
    cleanup = launch.get("cleanup", {})
    return (
        not cleanup.get("errors") and cleanup.get("handles_closed") is True
        and (launch.get("job_created") is False or cleanup.get("job_closed") is True)
        and (launch.get("started") is False or
             cleanup.get("process_exit_confirmed") is True
             and (launch.get("assigned_to_owned_job") is False or cleanup.get("job_empty") is True)))


def run_cell(api, label, build, restricted, work, source_token, source):
    cell = {
        "label": label, "token_context": "synthetic_restricted" if restricted else "unchanged_source_control",
        "actor_sha256": build["actor_sha256"], "actor_report": label + "/actor.json",
        "ordinary_user_acceptance": False, "restricted_caller_r0_passed": False,
        "stage0b_passed": False, "psec_acceptance": False, "product_acceptance": False,
        "derived_token_created": False, "process_created": False,
        "parent_token_unchanged": None, "actor_report_present": False,
        "parent_token_checks": [],
        "actor_started_and_reported": False,
        "cleanup": {"derived_token_closed": True, "errors": []},
    }
    derived_token, launch = None, None

    def check_parent(phase):
        record = {"phase": phase, "unchanged": None}
        cell["parent_token_checks"].append(record)
        try:
            record["unchanged"] = lab.restricted_identity(api, source_token) == source
        except Exception as exc:
            record["error"] = lab.failure(exc)
            raise
        if record["unchanged"] is not True:
            raise GateFailure("paired_parent_security_facts_changed")

    try:
        work.mkdir()
        (work / "temp").mkdir()
        check_parent("before_cell")
        token, expected = source_token, source
        if restricted:
            derived_token = api.create_restricted(source_token, source)
            cell["derived_token_created"] = True
            cell["cleanup"]["derived_token_closed"] = False
            api.set_medium_integrity(derived_token, source_token)
            expected = lab.restricted_identity(api, derived_token)
            lab.verify_derivation(expected, source)
            cell["derived_identity_verified"] = True
            check_parent("after_derivation")
            token = derived_token
            cell["derived_identity"] = lab.safe_identity(expected, source)
        nonce = secrets.token_hex(16)
        cell["nonce"] = nonce
        if restricted:
            launch = lab.launch_actor(api, build["actor"], nonce, work, token, expected, source)
        else:
            launch = lab.launch_source_control(api, build["actor"], nonce, work, token, source)
        cell["launch"] = launch
        cell["process_created"] = launch["started"]
        if "exit_code" in launch:
            cell["native_exit_code_hex"] = "0x%08X" % launch["exit_code"]
        report_path = work / "actor.json"
        cell["actor_report_present"] = report_path.exists()
        if cell["actor_report_present"]:
            cell["actor_matches_native_observation"] = lab.actor_matches(
                ordinary.read_probe(report_path), launch, expected, nonce)
        cell["actor_started_and_reported"] = (
            "error" not in launch and launch.get("native_verified_before_resume") is True
            and launch.get("exit_code") == 0 and cell.get("actor_matches_native_observation") is True)
    except Exception as exc:
        cell["error"] = lab.failure(exc)
    finally:
        if derived_token:
            try:
                api.close(derived_token)
                cell["cleanup"]["derived_token_closed"] = True
            except Exception as exc:
                cell["cleanup"]["errors"].append(lab.failure(exc))
        try:
            check_parent("after_cleanup")
            cell["parent_token_unchanged"] = True
        except Exception as exc:
            cell["parent_token_unchanged"] = cell["parent_token_checks"][-1]["unchanged"]
            cell["cleanup"]["errors"].append(lab.failure(exc))
        cell["cleanup"]["process_cleanup_confirmed"] = cleanup_confirmed(launch)
    cell["safe_to_continue"] = (
        cell["parent_token_unchanged"] is True and cell["cleanup"]["derived_token_closed"] is True
        and all(check["unchanged"] is True for check in cell["parent_token_checks"])
        and cell["cleanup"]["process_cleanup_confirmed"] is True and not cell["cleanup"]["errors"])
    cell["status"] = ("startup_observed" if cell["actor_started_and_reported"]
                      else "startup_not_established")
    return cell


def paired_startup(api, builds, work, audit_digest):
    report = {
        "schema_version": 1, "stage": "paired-native-startup-diagnostic",
        "controller_context": "four_cell_source_and_restricted_lab",
        "ordinary_user_acceptance": False, "restricted_caller_r0_passed": False,
        "stage0b_passed": False, "psec_acceptance": False,
        "product_acceptance": False, "privacy_qualified": False,
        "profile_created": False, "appcontainer_created": False, "acl_changed": False,
        "network_tested": False, "dependency_audit_sha256": audit_digest,
        "launch_policy": "fixed_actor_explicit_minimal_environment_stdio_suspended_owned_job",
        "run_deadline_per_cell_ms": lab.RUN_MILLISECONDS,
        "builds": {name: {key: value for key, value in build.items() if key != "actor"}
                   for name, build in builds.items()},
        "cells": [], "parent_token_unchanged": None,
        "cleanup": {"source_token_closed": False, "errors": []},
    }
    source_token, source = None, None
    try:
        source_token = api.source_token()
        source = lab.restricted_identity(api, source_token)
        if api.compartment() != 1 or not lab.source_identity_valid(source):
            raise GateFailure("paired_expected_current_elevated_unrestricted_source")
        report["source_identity"] = lab.safe_identity(source)
        report["source_identity_verified"] = True
        for label, variant, restricted in CELLS:
            cell = run_cell(api, label, builds[variant], restricted, work / label, source_token, source)
            report["cells"].append(cell)
            if not cell["safe_to_continue"]:
                report["stopped_reason"] = "cell_cleanup_or_parent_identity_not_confirmed"
                break
    except Exception as exc:
        report["error"] = lab.failure(exc)
    finally:
        if source_token and source is not None:
            try:
                report["parent_token_unchanged"] = lab.restricted_identity(api, source_token) == source
            except Exception as exc:
                report["cleanup"]["errors"].append(lab.failure(exc))
        if source_token:
            try:
                api.close(source_token)
                report["cleanup"]["source_token_closed"] = True
            except Exception as exc:
                report["cleanup"]["errors"].append(lab.failure(exc))
    report["diagnostic_completed"] = (
        "error" not in report and len(report["cells"]) == len(CELLS)
        and all(cell["safe_to_continue"] for cell in report["cells"])
        and report["parent_token_unchanged"] is True
        and report["cleanup"]["source_token_closed"] is True and not report["cleanup"]["errors"])
    report["all_actor_startups_succeeded"] = (
        report["diagnostic_completed"] and all(cell["actor_started_and_reported"] for cell in report["cells"]))
    report["status"] = "diagnostic_collected" if report["diagnostic_completed"] else "diagnostic_incomplete"
    return report


def run(args):
    if (os.name != "nt" or not args.paired_startup
            or not args.disposable_ci or not args.approved_security_test):
        raise PermissionError("requires an explicitly approved disposable Windows paired startup diagnostic")
    builds, work, audit_digest = validate_inputs(args)
    work.mkdir()
    report = paired_startup(lab.RestrictedAPI(), builds, work, audit_digest)
    ordinary.save_report(work / "report.json", report)
    public = publication_projection(report)
    if hashlib.sha256((work / "report.json").read_bytes()).hexdigest() != public["source_report_sha256"]:
        raise GateFailure("publication_source_hash_mismatch")
    ordinary.save_report(work / "public-report.json", public)
    # Diagnostic completion is not actor startup success or security acceptance.
    return 0 if report["diagnostic_completed"] else 1


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--paired-startup", action="store_true", required=True)
    parser.add_argument("--disposable-ci", action="store_true")
    parser.add_argument("--approved-security-test", action="store_true")
    for name in ("actor-full", "actor-identity", "dependency-audit", "work", "report"):
        parser.add_argument("--" + name, type=Path, required=True)
    for name in ("actor-full-sha256", "actor-identity-sha256"):
        parser.add_argument("--" + name, required=True)
    return run(parser.parse_args(argv))


if __name__ == "__main__":
    raise SystemExit(main())
