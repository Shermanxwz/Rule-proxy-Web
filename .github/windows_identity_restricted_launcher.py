"""R0: explicitly synthetic, transient restricted-caller native identity lab.

This is NOT a genuine ordinary-user token, ordinary Stage 0b, PSEC acceptance,
AppContainer isolation, or product qualification. No account, credentials,
service, UAC/policy change, privilege grant, desktop/ACL change, or network.
Only the caller's own token is copied and restricted; the original is checked
unchanged. Only the existing hashed native identity actor can be executed.
"""
from __future__ import annotations

import argparse
import ctypes as C
import hashlib
import importlib.util
import os
from pathlib import Path
import re
import secrets
import time

ROOT = Path(__file__).resolve().parents[1]
SPEC = importlib.util.spec_from_file_location(
    "restricted_lab_ordinary_primitives", Path(__file__).with_name("windows_identity_ordinary_launcher.py"))
ordinary = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(ordinary)
H, D, P = ordinary.H, ordinary.D, ordinary.P
GateFailure, NativeFailure = ordinary.GateFailure, ordinary.NativeFailure
BASELINE_GROUPS = frozenset({
    "S-1-1-0",       # Everyone
    "S-1-2-0",       # LOCAL
    "S-1-2-1",       # CONSOLE LOGON
    "S-1-5-4",       # INTERACTIVE
    "S-1-5-11",      # Authenticated Users
    "S-1-5-32-545",  # BUILTIN Users
})
CHANGE_NOTIFY = "SeChangeNotifyPrivilege"
ENABLED = 4
ENABLED_BY_DEFAULT = 2
DENY_ONLY = 16
INTEGRITY = 32
INTEGRITY_ENABLED = 64
LOGON_ID = 0xC0000000
TOKEN_SOURCE_ACCESS = 0x008B  # QUERY|DUPLICATE|ASSIGN_PRIMARY|ADJUST_DEFAULT
RUN_MILLISECONDS = 15_000


class LUID(C.Structure):
    _fields_ = [("LowPart", D), ("HighPart", C.c_int32)]


class LUIDAndAttributes(C.Structure):
    _fields_ = [("Luid", LUID), ("Attributes", D)]


class TokenPrivileges(C.Structure):
    _fields_ = [("PrivilegeCount", D), ("Privileges", LUIDAndAttributes * 1)]


class TokenStatistics(C.Structure):
    _fields_ = [
        ("TokenId", LUID), ("AuthenticationId", LUID), ("ExpirationTime", C.c_int64),
        ("TokenType", D), ("ImpersonationLevel", D), ("DynamicCharged", D),
        ("DynamicAvailable", D), ("GroupCount", D), ("PrivilegeCount", D), ("ModifiedId", LUID),
    ]


class JobAccounting(C.Structure):
    _fields_ = [(name, C.c_int64) for name in (
        "TotalUserTime", "TotalKernelTime", "ThisPeriodTotalUserTime", "ThisPeriodTotalKernelTime"
    )] + [(name, D) for name in (
        "TotalPageFaultCount", "TotalProcesses", "ActiveProcesses", "TotalTerminatedProcesses"
    )]


def luid_pair(value):
    return (int(value.LowPart), int(value.HighPart))


def group_map(groups):
    if not isinstance(groups, list) or len(groups) > 1024:
        raise GateFailure("invalid_full_group_list")
    result = {}
    for sid, attributes in groups:
        if (not isinstance(sid, str) or not ordinary.SID_PATTERN.fullmatch(sid)
                or type(attributes) is not int or not 0 <= attributes <= 0xFFFFFFFF or sid in result):
            raise GateFailure("invalid_or_duplicate_group")
        result[sid] = attributes
    return result


def logon_sid(identity):
    entries = identity["logon_sids"]
    if (not isinstance(entries, list) or len(entries) != 1
            or not re.fullmatch(r"S-1-5-5-[0-9]+-[0-9]+", entries[0][0])
            or entries[0][1] & LOGON_ID != LOGON_ID
            or not entries[0][1] & ENABLED or entries[0][1] & DENY_ONLY):
        raise GateFailure("one_enabled_native_logon_sid_required")
    groups = group_map(identity["groups"])
    if groups.get(entries[0][0]) != entries[0][1]:
        raise GateFailure("logon_sid_group_mismatch")
    return entries[0][0]


def preserved_groups(identity):
    return BASELINE_GROUPS | {identity["sid"], logon_sid(identity),
                              "S-1-16-" + str(identity["integrity_rid"])}


def disable_sids(identity):
    keep = preserved_groups(identity)
    return sorted(sid for sid in group_map(identity["groups"]) if sid not in keep)


def privilege_map(privileges):
    if not isinstance(privileges, list) or len(privileges) > 256:
        raise GateFailure("invalid_full_privilege_list")
    names, luids = {}, set()
    for entry in privileges:
        if not isinstance(entry, dict) or set(entry) != {"name", "luid", "attributes"}:
            raise GateFailure("invalid_privilege_entry")
        name, luid, attributes = entry["name"], entry["luid"], entry["attributes"]
        if (not isinstance(name, str) or not re.fullmatch(r"Se[A-Za-z]+Privilege", name)
                or not isinstance(luid, tuple) or len(luid) != 2
                or any(type(item) is not int for item in luid)
                or not 0 <= luid[0] <= 0xFFFFFFFF or not -(2**31) <= luid[1] < 2**31
                or type(attributes) is not int or not 0 <= attributes <= 0xFFFFFFFF
                or name in names or luid in luids):
            raise GateFailure("invalid_or_duplicate_privilege")
        names[name] = entry
        luids.add(luid)
    return names


def source_identity_valid(identity):
    try:
        groups = group_map(identity["groups"])
        privilege_map(identity["privileges"])
        logon_sid(identity)
        return (
            ordinary.SID_PATTERN.fullmatch(identity["sid"]) is not None
            and identity["sid"] not in ("S-1-5-18", "S-1-5-19", "S-1-5-20")
            and identity["token_type"] == 1 and identity["elevated"] is True
            and identity["elevation_type"] in (1, 2) and identity["integrity_rid"] == 12288
            and identity["appcontainer"] is False and identity["appcontainer_sid"] is None
            and identity["capability_count"] == 0 and identity["ui_access"] is False
            and identity["has_restrictions"] is False and identity["restricted_sids"] == []
            and identity["sandbox_inert"] is False
            and not identity["user_attributes"] & DENY_ONLY
            and bool(groups.get(ordinary.ADMIN_SID, 0) & ENABLED)
            and not bool(groups.get(ordinary.ADMIN_SID, 0) & DENY_ONLY)
            and type(identity["session_id"]) is int and identity["session_id"] >= 0
            and len(identity["authentication_luid"]) == 2)
    except (KeyError, TypeError, ValueError, GateFailure):
        return False


def restricted_identity_valid(identity):
    """Synthetic-lab gate only. Elevation is recorded, not called ordinary."""
    try:
        groups = group_map(identity["groups"])
        privileges = privilege_map(identity["privileges"])
        keep = preserved_groups(identity)
        if not (
            ordinary.SID_PATTERN.fullmatch(identity["sid"]) is not None
            and type(identity["session_id"]) is int and identity["session_id"] >= 0
            and type(identity["token_type"]) is int and identity["token_type"] == 1
            and type(identity["elevated"]) is bool
            and type(identity["elevation_type"]) is int and identity["elevation_type"] in (1, 2, 3)
            and type(identity["integrity_rid"]) is int and identity["integrity_rid"] == 8192
            and identity["appcontainer"] is False and identity["appcontainer_sid"] is None
            and type(identity["capability_count"]) is int and identity["capability_count"] == 0
            and identity["ui_access"] is False and identity["has_restrictions"] is True
            and identity["sandbox_inert"] is False and identity["restricted_sids"] == []
            and type(identity["user_attributes"]) is int and not identity["user_attributes"] & DENY_ONLY
            and set(privileges).issubset({CHANGE_NOTIFY})
            and groups.get(ordinary.ADMIN_SID, 0) & DENY_ONLY
            and not groups.get(ordinary.ADMIN_SID, 0) & (ENABLED | ENABLED_BY_DEFAULT)
            and identity["admin_attributes"] == groups.get(ordinary.ADMIN_SID)
        ):
            return False
        for entry in privileges.values():
            if entry["attributes"] & ~(1 | 2 | 0x80000000):
                return False
        for sid, attributes in groups.items():
            if sid not in keep:
                if not attributes & DENY_ONLY or attributes & (ENABLED | ENABLED_BY_DEFAULT):
                    return False
            elif sid == "S-1-16-8192":
                if attributes & (INTEGRITY | INTEGRITY_ENABLED) != INTEGRITY | INTEGRITY_ENABLED:
                    return False
                if attributes & DENY_ONLY:
                    return False
        auth = identity["authentication_luid"]
        return (isinstance(auth, tuple) and len(auth) == 2
                and all(type(item) is int for item in auth))
    except (KeyError, TypeError, ValueError, GateFailure):
        return False


def verify_derivation(derived, source):
    if not restricted_identity_valid(derived):
        raise GateFailure("synthetic_restricted_token_gate_failed")
    for name in ("sid", "user_attributes", "session_id", "authentication_luid", "logon_sids"):
        if derived[name] != source[name]:
            raise GateFailure("restricted_token_provenance_mismatch")
    before, after = group_map(source["groups"]), group_map(derived["groups"])
    old_integrity, new_integrity = "S-1-16-" + str(source["integrity_rid"]), "S-1-16-8192"
    expected_sids = {(new_integrity if sid == old_integrity else sid) for sid in before}
    if set(after) != expected_sids:
        raise GateFailure("restricted_group_membership_changed")
    keep = preserved_groups(source)
    for sid, attributes in before.items():
        actual = after[new_integrity if sid == old_integrity else sid]
        if sid in keep:
            if actual != attributes:
                raise GateFailure("preserved_group_attributes_changed")
        elif (not actual & DENY_ONLY or actual & (ENABLED | ENABLED_BY_DEFAULT)
              or actual & ~(attributes | DENY_ONLY)):
            raise GateFailure("disabled_group_attributes_not_reduced")
    source_privileges, derived_privileges = privilege_map(source["privileges"]), privilege_map(derived["privileges"])
    for name, entry in derived_privileges.items():
        if name not in source_privileges or entry != source_privileges[name]:
            raise GateFailure("retained_privilege_changed")


def safe_identity(identity, source=None):
    result = ordinary.safe_identity(identity, source)
    groups = group_map(identity["groups"])
    result.update(
        synthetic_restricted_caller=restricted_identity_valid(identity),
        has_restrictions=identity["has_restrictions"],
        sandbox_inert=identity["sandbox_inert"],
        restricting_sid_count=len(identity["restricted_sids"]),
        group_count=len(groups),
        deny_only_group_count=sum(bool(attributes & DENY_ONLY) for attributes in groups.values()),
        enabled_baseline_groups=sorted(sid for sid, attributes in groups.items()
                                       if sid in BASELINE_GROUPS and attributes & ENABLED),
        privileges=[{"name": entry["name"], "attributes": entry["attributes"]}
                    for entry in identity["privileges"]],
        logon_sid_present=True)
    if source is not None:
        result["same_authentication_luid"] = identity["authentication_luid"] == source["authentication_luid"]
    return result


class RestrictedAPI(ordinary.NativeAPI):
    def __init__(self):
        super().__init__()
        for name, args, result in (
            ("LookupPrivilegeNameW", [P, C.POINTER(LUID), P, C.POINTER(D)], C.c_int),
            ("CreateRestrictedToken", [H, D, D, H, D, H, D, H, C.POINTER(H)], C.c_int),
            ("SetTokenInformation", [H, C.c_int, H, D], C.c_int),
        ):
            fn = getattr(self.a, name)
            fn.argtypes, fn.restype = args, result

    def source_token(self):
        token = H()
        self.check(self.a.OpenProcessToken(self.k.GetCurrentProcess(), TOKEN_SOURCE_ACCESS, C.byref(token)),
                   "OpenProcessToken(restricted_source)")
        return token.value

    def authentication_luid(self, token):
        value, size = TokenStatistics(), D()
        self.check(self.a.GetTokenInformation(token, 10, C.byref(value), C.sizeof(value), C.byref(size)),
                   "GetTokenInformation(TokenStatistics)")
        if size.value != C.sizeof(value) or value.TokenType != 1:
            raise GateFailure("invalid_primary_token_statistics")
        return luid_pair(value.AuthenticationId)

    def user_attributes(self, token):
        buffer, size = self.query(token, 1, "TokenUser")
        if size < C.sizeof(ordinary.SIDAndAttributes):
            raise GateFailure("invalid_token_user_header")
        return ordinary.SIDAndAttributes.from_buffer(buffer).Attributes

    def privileges(self, token):
        buffer, size = self.query(token, 3, "TokenPrivileges")
        if size < C.sizeof(D):
            raise GateFailure("invalid_privilege_buffer")
        count = D.from_buffer(buffer).value
        start = TokenPrivileges.Privileges.offset
        if count > 256 or start + count * C.sizeof(LUIDAndAttributes) > size:
            raise GateFailure("invalid_privilege_array_length")
        result = []
        for index in range(count):
            entry = LUIDAndAttributes.from_buffer(buffer, start + index * C.sizeof(LUIDAndAttributes))
            text, length = C.create_unicode_buffer(256), D(256)
            self.check(self.a.LookupPrivilegeNameW(None, C.byref(entry.Luid), text, C.byref(length)),
                       "LookupPrivilegeNameW")
            if not 1 <= length.value < len(text) or len(text.value) != length.value:
                raise GateFailure("invalid_privilege_name_length")
            result.append({"name": text.value, "luid": luid_pair(entry.Luid), "attributes": entry.Attributes})
        privilege_map(result)
        return sorted(result, key=lambda item: item["name"])

    def create_restricted(self, source_token, source):
        # Explicit deletion, not DISABLE_MAX_PRIVILEGE: its deletion list would
        # be ignored. No LUA_TOKEN/SANDBOX_INERT/WRITE_RESTRICTED flags are used.
        wanted = set(disable_sids(source))
        buffer, size = self.query(source_token, 2, "TokenGroups")
        count, offset = D.from_buffer(buffer).value, ordinary.TokenGroups.Groups.offset
        if count > 1024 or offset + count * C.sizeof(ordinary.SIDAndAttributes) > size:
            raise GateFailure("invalid_source_group_array")
        disabled, seen = [], set()
        for index in range(count):
            entry = ordinary.SIDAndAttributes.from_buffer(buffer, offset + index * C.sizeof(ordinary.SIDAndAttributes))
            sid = self.sid_text(entry.Sid, buffer, size)
            if sid in wanted:
                disabled.append(ordinary.SIDAndAttributes(entry.Sid, 0))
                seen.add(sid)
        if seen != wanted or len(disabled) != len(wanted):
            raise GateFailure("source_groups_changed_before_restriction")
        sids = (ordinary.SIDAndAttributes * len(disabled))(*disabled)
        deletes = [entry for entry in source["privileges"] if entry["name"] != CHANGE_NOTIFY]
        privileges = (LUIDAndAttributes * len(deletes))(
            *(LUIDAndAttributes(LUID(*entry["luid"]), 0) for entry in deletes))
        new = H()
        self.check(self.a.CreateRestrictedToken(source_token, 0, len(sids), sids if len(sids) else None,
                                                len(privileges), privileges if len(privileges) else None,
                                                0, None, C.byref(new)), "CreateRestrictedToken")
        if not new.value or new.value == source_token:
            raise GateFailure("new_distinct_restricted_token_required")
        return new.value

    def set_medium_integrity(self, token, source_token):
        if token == source_token:
            raise GateFailure("must_not_mutate_source_token")
        header_size = C.sizeof(ordinary.SIDAndAttributes)
        # Self-contained TOKEN_MANDATORY_LABEL plus fixed S-1-16-8192 SID.
        sid_bytes = b"\x01\x01\x00\x00\x00\x00\x00\x10" + (8192).to_bytes(4, "little")
        buffer = C.create_string_buffer(header_size + len(sid_bytes))
        label = ordinary.SIDAndAttributes.from_buffer(buffer)
        label.Sid, label.Attributes = C.addressof(buffer) + header_size, INTEGRITY
        C.memmove(label.Sid, sid_bytes, len(sid_bytes))
        self.check(self.a.SetTokenInformation(token, 25, buffer, len(buffer)),
                   "SetTokenInformation(new_token_medium_integrity)")

    def verify_image(self, process, expected):
        buffer, size = C.create_unicode_buffer(32768), D(32768)
        self.check(self.k.QueryFullProcessImageNameW(process, 0, buffer, C.byref(size)),
                   "QueryFullProcessImageNameW")
        if os.path.normcase(buffer.value) != os.path.normcase(str(expected)):
            raise GateFailure("child_image_not_fixed_native_actor")

    def child_restricted_identity(self, process):
        token = self.token_for_process(process)
        try:
            return restricted_identity(self, token)
        finally:
            self.close(token)

    def wait_job_empty(self, job, milliseconds):
        deadline = time.monotonic() + milliseconds / 1000
        while True:
            value, size = JobAccounting(), D()
            self.check(self.k.QueryInformationJobObject(job, 1, C.byref(value), C.sizeof(value), C.byref(size)),
                       "QueryInformationJobObject(basic_accounting)")
            if size.value != C.sizeof(value):
                raise GateFailure("invalid_job_accounting_size")
            if value.ActiveProcesses == 0:
                return True
            if time.monotonic() >= deadline:
                return False
            time.sleep(.02)


def restricted_identity(api, token):
    values = {name: reader() for name, reader in api.observation_readers(token).items()}
    result = ordinary.identity_from_observations(values)
    result.update(
        groups=sorted(values["groups"]),
        user_attributes=api.user_attributes(token),
        privileges=api.privileges(token),
        authentication_luid=api.authentication_luid(token),
        has_restrictions=api.boolean(token, 21, "TokenHasRestrictions"),
        sandbox_inert=api.boolean(token, 15, "TokenSandBoxInert"),
        restricted_sids=sorted(api.groups(token, 11, "TokenRestrictedSids")),
        logon_sids=sorted(api.groups(token, 28, "TokenLogonSid")))
    group_map(result["groups"])
    return result


def launch_actor(api, actor, nonce, work, token, derived, source):
    info, job, handles, assigned = api.process_info(), None, [], False
    result = {"started": False, "resumed": False, "timed_out": False,
              "cleanup": {"errors": [], "job_closed": False, "job_empty": False, "handles_closed": False}}
    try:
        job = api.create_job()
        for name in ("controller.stdin", "controller.stdout", "controller.stderr"):
            handles.append(api.open_stdio_file(work / name, read=name.endswith("stdin")))
        command = [str(actor), "actor", nonce, str(work / "actor.json")]
        api.create_suspended(info, command, work, handles, token)
        result.update(started=True, child_pid=int(info.dwProcessId))
        api.assign_job(job, info.hProcess)
        assigned = True
        api.verify_job(job, info.hProcess)
        api.verify_image(info.hProcess, actor)
        child = api.child_restricted_identity(info.hProcess)
        verify_derivation(child, source)
        if child != derived:
            raise GateFailure("suspended_child_differs_from_verified_restricted_token")
        result["child_identity"] = safe_identity(child, source)
        result["native_verified_before_resume"] = True
        api.resume(info.hThread)
        result["resumed"] = True
        if not api.wait(info.hProcess, RUN_MILLISECONDS):
            result["timed_out"] = True
            raise GateFailure("restricted_actor_deadline")
        result["exit_code"] = api.exit_code(info.hProcess)
    except Exception as exc:
        result["error"] = ordinary.failure(exc)
    finally:
        cleanup = result["cleanup"]

        def attempt(call):
            try:
                call()
                return True
            except Exception as exc:
                cleanup["errors"].append(ordinary.failure(exc))
                return False

        if info.hProcess:
            if assigned:
                attempt(lambda: api.terminate_job(job))

                def drain_job():
                    if not api.wait_job_empty(job, 5000):
                        raise GateFailure("restricted_actor_job_drain_deadline")
                    cleanup["job_empty"] = True
                attempt(drain_job)
                if attempt(lambda: api.close(job)):
                    cleanup["job_closed"], job = True, None
            else:
                attempt(lambda: api.terminate_process(info.hProcess))

            def wait_exit():
                if not api.wait(info.hProcess, 5000):
                    raise GateFailure("restricted_actor_cleanup_deadline")
            attempt(wait_exit)
        if job and attempt(lambda: api.close(job)):
            cleanup["job_closed"] = True
        closed = True
        for handle in (info.hThread, info.hProcess, *reversed(handles)):
            if handle:
                closed = attempt(lambda handle=handle: api.close(handle)) and closed
        cleanup["handles_closed"] = closed
    return result


def actor_matches(value, launch, derived, nonce):
    return (isinstance(value, dict) and value.get("schemaVersion") == 1
            and value.get("mode") == "actor" and value.get("nonce") == nonce
            and type(value.get("pid")) is int and value["pid"] == launch.get("child_pid")
            and value.get("tokenUserSid") == derived["sid"]
            and value.get("tokenElevated") is derived["elevated"]
            and value.get("tokenIsAppContainer") is False and value.get("tokenAppContainerSid") is None
            and value.get("tokenCapabilities") == [] and value.get("isProcessInJob") is True
            and value.get("queriesSucceeded") is True and value.get("errors") == [])


def validate_inputs(args):
    root = ordinary.checked_path(ROOT, is_file=False)
    ordinary.checked_path(root / "ruleproxy/windows_app_process.py", inside=root)
    actor = ordinary.checked_path(args.actor, inside=root)
    if actor.name != "windows_identity_actor.exe" or not 512 <= actor.stat().st_size <= 8 * 1024 * 1024:
        raise GateFailure("expected_bounded_native_actor")
    if not isinstance(args.actor_sha256, str) or not ordinary.DIGEST_PATTERN.fullmatch(args.actor_sha256):
        raise GateFailure("invalid_actor_sha256")
    with actor.open("rb") as stream:
        content = stream.read(8 * 1024 * 1024 + 1)
    if (not 512 <= len(content) <= 8 * 1024 * 1024 or content[:2] != b"MZ"
            or hashlib.sha256(content).hexdigest() != args.actor_sha256):
        raise GateFailure("native_actor_digest_mismatch")
    raw = Path(os.path.abspath(args.work))
    if Path(os.path.abspath(args.report)) != raw / "report.json":
        raise GateFailure("report_must_be_work_report_json")
    parent = ordinary.checked_path(raw.parent, inside=root, is_file=False)
    work = parent / raw.name
    if root not in work.parents or work.exists() or work.is_symlink():
        raise GateFailure("fresh_owned_work_required")
    return actor, work


def run(args):
    if os.name != "nt" or not args.disposable_ci or not args.approved_security_test:
        raise PermissionError("requires an explicitly approved disposable Windows security test")
    actor, work = validate_inputs(args)
    work.mkdir()
    (work / "temp").mkdir()
    report = {
        "schema_version": 1, "stage": "R0-restricted-caller-native-identity",
        "controller_context": "synthetic_restricted_caller_lab",
        "ordinary_user_acceptance": False, "stage0b_passed": False,
        "product_acceptance": False, "psec_acceptance": False, "privacy_qualified": False,
        "appcontainer_created": False, "acl_changed": False, "network_tested": False,
        "actor_sha256": args.actor_sha256, "actor_report": "actor.json",
        "restriction_strategy": "explicit_privilege_deletion_and_deny_only_nonbaseline_groups",
        "parent_token_unchanged": False, "restricted_caller_r0_passed": False,
        "cleanup": {"token_handles_closed": False, "errors": []},
    }
    api, source_token, new_token, source = None, None, None, None
    try:
        api = RestrictedAPI()
        source_token = api.source_token()
        source = restricted_identity(api, source_token)
        if api.compartment() != 1 or not source_identity_valid(source):
            raise GateFailure("expected_current_elevated_unrestricted_default_compartment_source")
        report["parent_identity"] = safe_identity(source)
        new_token = api.create_restricted(source_token, source)
        api.set_medium_integrity(new_token, source_token)
        derived = restricted_identity(api, new_token)
        verify_derivation(derived, source)
        if restricted_identity(api, source_token) != source:
            raise GateFailure("parent_token_changed_during_restriction")
        report["derived_identity"] = safe_identity(derived, source)
        nonce = secrets.token_hex(16)
        report["nonce"] = nonce
        report["launch"] = launch_actor(api, actor, nonce, work, new_token, derived, source)
        launch = report["launch"]
        if "error" not in launch and launch.get("exit_code") == 0:
            report["actor_matches_native_parent_observation"] = actor_matches(
                ordinary.read_probe(work / "actor.json"), launch, derived, nonce)
    except Exception as exc:
        report["error"] = ordinary.failure(exc)
    finally:
        if api is not None and source_token and source is not None:
            try:
                report["parent_token_unchanged"] = restricted_identity(api, source_token) == source
                if not report["parent_token_unchanged"]:
                    report["cleanup"]["errors"].append({"operation": "invariant", "reason": "parent_token_changed"})
            except Exception as exc:
                report["cleanup"]["errors"].append(ordinary.failure(exc))
        for token in (new_token, source_token):
            if token:
                try:
                    api.close(token)
                except Exception as exc:
                    report["cleanup"]["errors"].append(ordinary.failure(exc))
        report["cleanup"]["token_handles_closed"] = not report["cleanup"]["errors"]
    launch = report.get("launch", {})
    cleanup = launch.get("cleanup", {})
    report["restricted_caller_r0_passed"] = (
        "error" not in report and "error" not in launch
        and launch.get("native_verified_before_resume") is True and launch.get("exit_code") == 0
        and report.get("actor_matches_native_parent_observation") is True
        and report["parent_token_unchanged"] is True
        and cleanup.get("job_closed") is True and cleanup.get("job_empty") is True
        and cleanup.get("handles_closed") is True
        and not cleanup.get("errors") and report["cleanup"]["token_handles_closed"])
    report["status"] = "restricted_lab_observed" if report["restricted_caller_r0_passed"] else "blocked_or_failed"
    ordinary.save_report(work / "report.json", report)
    return 0 if report["restricted_caller_r0_passed"] else 1


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--disposable-ci", action="store_true")
    parser.add_argument("--approved-security-test", action="store_true")
    for name in ("actor", "work", "report"):
        parser.add_argument("--" + name, type=Path, required=True)
    parser.add_argument("--actor-sha256", required=True)
    return run(parser.parse_args(argv))


if __name__ == "__main__":
    raise SystemExit(main())
