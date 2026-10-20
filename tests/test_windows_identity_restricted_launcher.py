"""Pure R0 tests; never call a Windows API or create a real token/process."""
import copy
import importlib.util
import json
import io
from pathlib import Path
import tempfile
from types import SimpleNamespace
import unittest
from unittest import mock

from test_windows_identity_ordinary_launcher import FakeAPI

ROOT = Path(__file__).resolve().parents[1]
SPEC = importlib.util.spec_from_file_location(
    "restricted_identity_lab", ROOT / ".github/windows_identity_restricted_launcher.py")
lab = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(lab)
USER = "S-1-5-21-1-2-3-1001"
LOGON = "S-1-5-5-1-2"
UNKNOWN = "S-1-5-21-1-2-3-512"


def source():
    return {
        "sid": USER, "user_attributes": 0, "session_id": 1, "token_type": 1,
        "elevation_type": 1, "elevated": True, "integrity_rid": 12288,
        "admin_attributes": 15, "appcontainer": False, "appcontainer_sid": None,
        "capability_count": 0, "ui_access": False, "has_restrictions": False,
        "sandbox_inert": False, "authentication_luid": (123, 0),
        "restricted_sids": [], "logon_sids": [(LOGON, 0xC0000007)],
        "groups": sorted([
            (lab.ordinary.ADMIN_SID, 15), ("S-1-5-32-545", 7), ("S-1-1-0", 7),
            (LOGON, 0xC0000007), ("S-1-16-12288", 96), (UNKNOWN, 7)]),
        "privileges": [
            {"name": "SeChangeNotifyPrivilege", "luid": (23, 0), "attributes": 3},
            {"name": "SeDebugPrivilege", "luid": (20, 0), "attributes": 0},
        ],
    }


def restricted():
    value = source()
    value.update(integrity_rid=8192, has_restrictions=True, admin_attributes=25)
    value["groups"] = sorted([
        (lab.ordinary.ADMIN_SID, 25), ("S-1-5-32-545", 7), ("S-1-1-0", 7),
        (LOGON, 0xC0000007), ("S-1-16-8192", 96), (UNKNOWN, 17)])
    value["privileges"] = value["privileges"][:1]
    return value


class RestrictedGateTests(unittest.TestCase):
    def test_elevated_fact_is_preserved_without_ordinary_claim(self):
        self.assertTrue(lab.source_identity_valid(source()))
        self.assertTrue(lab.restricted_identity_valid(restricted()))
        lab.verify_derivation(restricted(), source())
        self.assertFalse(lab.ordinary.token_is_ordinary(restricted()))
        self.assertFalse(lab.safe_identity(source())["synthetic_restricted_caller"])
        self.assertTrue(lab.safe_identity(restricted(), source())["synthetic_restricted_caller"])

    def test_unknown_and_administrator_groups_are_disabled_not_classified(self):
        self.assertEqual(lab.disable_sids(source()), sorted([lab.ordinary.ADMIN_SID, UNKNOWN]))
        self.assertNotIn(USER, lab.disable_sids(source()))
        self.assertNotIn(LOGON, lab.disable_sids(source()))
        self.assertNotIn("S-1-16-12288", lab.disable_sids(source()))

    def test_missing_observations_never_pass(self):
        for key in restricted():
            value = restricted()
            del value[key]
            with self.subTest(key=key):
                self.assertFalse(lab.restricted_identity_valid(value))

    def test_wrong_token_security_facts_fail(self):
        for key, value in (
            ("user_attributes", 16), ("token_type", 2), ("integrity_rid", 12288),
            ("has_restrictions", False), ("sandbox_inert", True),
            ("appcontainer", True), ("appcontainer_sid", "S-1-15-2-1"),
            ("capability_count", 1), ("ui_access", True),
            ("restricted_sids", [("S-1-1-0", 7)]), ("logon_sids", []),
        ):
            identity = restricted()
            identity[key] = value
            with self.subTest(key=key):
                self.assertFalse(lab.restricted_identity_valid(identity))

    def test_other_retained_privileges_fail_even_if_disabled(self):
        value = restricted()
        value["privileges"].append({"name": "SeDebugPrivilege", "luid": (20, 0), "attributes": 0})
        self.assertFalse(lab.restricted_identity_valid(value))
        value["privileges"] = []
        self.assertTrue(lab.restricted_identity_valid(value))

    def test_unknown_enabled_group_and_duplicate_groups_fail(self):
        value = restricted()
        value["groups"].append(("S-1-5-21-9-9-9-519", 7))
        self.assertFalse(lab.restricted_identity_valid(value))
        value = restricted()
        value["groups"].append(value["groups"][0])
        self.assertFalse(lab.restricted_identity_valid(value))

    def test_provenance_authentication_user_session_and_group_delta_are_exact(self):
        for key, change in (
            ("sid", "S-1-5-21-9-9-9-1001"), ("session_id", 2),
            ("authentication_luid", (999, 0)), ("user_attributes", 1),
        ):
            identity = restricted()
            identity[key] = change
            with self.subTest(key=key), self.assertRaises(lab.GateFailure):
                lab.verify_derivation(identity, source())
        identity = restricted()
        identity["groups"].append(("S-1-5-21-9-9-9-519", 17))
        self.assertTrue(lab.restricted_identity_valid(identity))
        with self.assertRaisesRegex(lab.GateFailure, "membership_changed"):
            lab.verify_derivation(identity, source())

    def test_duplicate_privilege_names_or_luids_fail(self):
        for entry in (
            {"name": "SeChangeNotifyPrivilege", "luid": (99, 0), "attributes": 0},
            {"name": "SeDebugPrivilege", "luid": (23, 0), "attributes": 0},
        ):
            value = restricted()
            value["privileges"].append(entry)
            self.assertFalse(lab.restricted_identity_valid(value))

    def test_safe_projection_redacts_user_logon_and_authentication_ids(self):
        encoded = json.dumps(lab.safe_identity(restricted(), source()))
        self.assertNotIn(USER, encoded)
        self.assertNotIn(LOGON, encoded)
        self.assertNotIn("authentication_luid\": [", encoded)
        self.assertIn('"same_authentication_luid": true', encoded)


class NativeABITests(unittest.TestCase):
    def query_api(self, returned, payload=0, success=True):
        def query(token, kind, buffer, length, output_size):
            self.assertEqual(length, 4)
            self.assertEqual(lab.C.cast(buffer, lab.H).value % lab.C.alignment(lab.D), 0)
            # Poison the unreturned high bytes. Class 21 must consume byte 0,
            # not interpret all four allocated bytes as initialized output.
            lab.C.memmove(buffer, bytes([payload, 0xA5, 0x5A, 0xFF]), 4)
            lab.C.cast(output_size, lab.C.POINTER(lab.D))[0] = returned
            return int(success)
        api = lab.RestrictedAPI.__new__(lab.RestrictedAPI)
        api.a = SimpleNamespace(GetTokenInformation=query)
        return api

    def test_class21_reads_only_boolean_byte_at_dword_aligned_address(self):
        for payload in (0, 1):
            api = self.query_api(1, payload)
            with mock.patch.object(lab.C, "get_last_error", create=True,
                                   side_effect=AssertionError("success must ignore LastError")):
                self.assertIs(api.has_restrictions(100), bool(payload))
            self.assertEqual(api.fixed_query_diagnostics[21], {
                "operation": "GetTokenInformation(TokenHasRestrictions)",
                "token_information_class": 21, "abi_type": "BOOLEAN_DWORD_ALIGNED",
                "capacity": 4, "expected_size": 1, "returned_size": 1, "native_success": True})

    def test_class21_rejects_wrong_extent_and_invalid_boolean(self):
        for returned, payload in ((0, 0), (2, 0), (3, 0), (4, 0), (5, 0), (1, 2)):
            with self.subTest(returned=returned, payload=payload):
                api = self.query_api(returned, payload)
                with self.assertRaises(lab.FixedQueryFailure) as raised:
                    api.has_restrictions(100)
                record = lab.failure(raised.exception)
                self.assertEqual(record["token_information_class"], 21)
                self.assertEqual(record["capacity"], 4)
                self.assertEqual(record["expected_size"], 1)
                self.assertEqual(record["returned_size"], returned)
                self.assertIn("reason", record)
                self.assertNotIn("winerror", record)

    def test_other_dword_classes_never_accept_one_byte_extent(self):
        for kind, (name, _, _, expected) in lab.FIXED_QUERY_TYPES.items():
            if kind in (10, 21):
                continue
            self.assertEqual(expected, 4)
            with self.subTest(kind=kind), self.assertRaises(lab.FixedQueryFailure) as raised:
                self.query_api(1).scalar(100, kind, name)
            self.assertEqual(lab.failure(raised.exception)["expected_size"], 4)
        with self.assertRaisesRegex(lab.GateFailure, "unsupported_restricted_dword_scalar"):
            self.query_api(1).scalar(100, 21, "TokenHasRestrictions")

    def test_native_failure_retains_exact_closed_query_metadata_and_winerror(self):
        api = self.query_api(1, success=False)
        with mock.patch.object(lab.C, "get_last_error", create=True, return_value=24) as last_error:
            with self.assertRaises(lab.FixedQueryFailure) as raised:
                api.has_restrictions(100)
        last_error.assert_called_once_with()
        record = lab.failure(raised.exception)
        self.assertEqual(record["winerror"], 24)
        self.assertFalse(record["native_success"])
        self.assertEqual(record["returned_size"], 1)
        self.assertEqual(record["expected_size"], 1)

    def test_luid_privilege_and_statistics_layouts(self):
        self.assertEqual(lab.C.sizeof(lab.LUID), 8)
        self.assertEqual(lab.C.sizeof(lab.LUIDAndAttributes), 12)
        self.assertEqual(lab.TokenPrivileges.Privileges.offset, 4)
        self.assertEqual(lab.C.sizeof(lab.TokenStatistics), 56)
        self.assertEqual(lab.TokenStatistics.AuthenticationId.offset, 8)
        self.assertEqual(lab.C.sizeof(lab.JobAccounting), 48)

    def test_fixed_token_statistics_reads_authentication_not_token_id(self):
        def query(token, kind, buffer, length, returned):
            self.assertEqual((kind, length), (10, 56))
            value = lab.C.cast(buffer, lab.C.POINTER(lab.TokenStatistics))[0]
            value.TokenId = lab.LUID(999, 0)
            value.AuthenticationId = lab.LUID(123, -1)
            value.TokenType = 1
            lab.C.cast(returned, lab.C.POINTER(lab.D))[0] = length
            return 1
        api = lab.RestrictedAPI.__new__(lab.RestrictedAPI)
        api.a = SimpleNamespace(GetTokenInformation=query)
        self.assertEqual(api.authentication_luid(100), (123, -1))
        self.assertEqual(api.fixed_query_diagnostics[10]["abi_type"], "TOKEN_STATISTICS")
        self.assertEqual(api.fixed_query_diagnostics[10]["expected_size"], 56)

    def test_statistics_size_failure_has_named_diagnostics(self):
        def query(token, kind, buffer, length, returned):
            self.assertEqual((kind, length), (10, 56))
            lab.C.cast(returned, lab.C.POINTER(lab.D))[0] = 48
            return 1
        api = lab.RestrictedAPI.__new__(lab.RestrictedAPI)
        api.a = SimpleNamespace(GetTokenInformation=query)
        with self.assertRaises(lab.FixedQueryFailure) as raised:
            api.authentication_luid(100)
        self.assertEqual(lab.failure(raised.exception), {
            "operation": "GetTokenInformation(TokenStatistics)", "token_information_class": 10,
            "abi_type": "TOKEN_STATISTICS", "capacity": 56, "expected_size": 56,
            "returned_size": 48, "native_success": True, "reason": "invalid_token_fixed_size"})

    def test_medium_integrity_is_self_contained_and_only_new_token(self):
        calls = []

        def set_information(token, kind, buffer, length):
            self.assertEqual((token, kind), (200, 25))
            header = lab.ordinary.SIDAndAttributes.from_buffer(buffer)
            self.assertEqual(header.Attributes, lab.INTEGRITY)
            self.assertEqual(header.Sid, lab.C.addressof(buffer) + lab.C.sizeof(header))
            self.assertEqual(length, lab.C.sizeof(header) + 12)
            self.assertEqual(lab.C.string_at(header.Sid, 12),
                             b"\x01\x01\x00\x00\x00\x00\x00\x10\x00\x20\x00\x00")
            calls.append(token)
            return 1
        api = lab.RestrictedAPI.__new__(lab.RestrictedAPI)
        api.a = SimpleNamespace(SetTokenInformation=set_information)
        api.set_medium_integrity(200, 100)
        with self.assertRaisesRegex(lab.GateFailure, "must_not_mutate_source"):
            api.set_medium_integrity(100, 100)
        self.assertEqual(calls, [200])

    def test_privilege_array_count_must_fit_native_buffer(self):
        api = lab.RestrictedAPI.__new__(lab.RestrictedAPI)
        buffer = lab.C.create_string_buffer(4)
        lab.D.from_buffer(buffer).value = 1
        api.query = lambda *args: (buffer, len(buffer))
        with self.assertRaisesRegex(lab.GateFailure, "privilege_array_length"):
            api.privileges(100)

    def test_explicit_deletion_uses_flags_zero_and_no_restricting_sids(self):
        snapshot = source()
        groups = snapshot["groups"]
        offset = lab.ordinary.TokenGroups.Groups.offset
        buffer = lab.C.create_string_buffer(offset + len(groups) * lab.C.sizeof(lab.ordinary.SIDAndAttributes))
        lab.D.from_buffer(buffer).value = len(groups)
        sid_by_pointer = {}
        for index, (sid, attrs) in enumerate(groups):
            entry = lab.ordinary.SIDAndAttributes.from_buffer(
                buffer, offset + index * lab.C.sizeof(lab.ordinary.SIDAndAttributes))
            entry.Sid, entry.Attributes = 1000 + index, attrs
            sid_by_pointer[1000 + index] = sid
        api = lab.RestrictedAPI.__new__(lab.RestrictedAPI)
        api.query = lambda *args: (buffer, len(buffer))
        api.sid_text = lambda pointer, *args: sid_by_pointer[pointer]

        def create(token, flags, sid_count, sids, delete_count, deletes, restrict_count, restrict_sids, output):
            self.assertEqual((token, flags, restrict_count, restrict_sids), (100, 0, 0, None))
            self.assertEqual({sid_by_pointer[sids[i].Sid] for i in range(sid_count)},
                             {lab.ordinary.ADMIN_SID, UNKNOWN})
            self.assertEqual(delete_count, 1)
            self.assertEqual(lab.luid_pair(deletes[0].Luid), (20, 0))
            lab.C.cast(output, lab.C.POINTER(lab.H))[0] = 200
            return 1
        api.a = SimpleNamespace(CreateRestrictedToken=create)
        self.assertEqual(api.create_restricted(100, snapshot), 200)


class RestrictedFakeAPI(FakeAPI):
    def __init__(self, fail=None, child=None, timeout=False):
        super().__init__(fail=fail, child=child or restricted(), timeout=timeout)

    def event(self, name, *args):
        self.events.append((name, *args))
        if self.fail == name:
            raise lab.NativeFailure(name, 1314)

    def child_restricted_identity(self, process):
        self.event("child_restricted_identity", process)
        return copy.deepcopy(self.child)

    def wait(self, process, milliseconds):
        self.event("wait", process, milliseconds)
        return not self.timeout or milliseconds != lab.RUN_MILLISECONDS

    def wait_job_empty(self, job, milliseconds):
        self.event("wait_job_empty", job, milliseconds)
        return True

    def create_suspended(self, info, command, work, stdio, token):
        if command != ["windows_identity_actor.exe", "actor", "a" * 32, str(Path("owned/actor.json"))]:
            raise AssertionError("Not the fixed native actor command")
        super().create_suspended(info, command, work, stdio, token)


class PreflightFakeAPI(lab.RestrictedAPI):
    """Only in-memory observations. No Windows API binding or mutation methods."""

    def __init__(self, fail=None):
        self.events, self.fail = [], fail
        self.a = SimpleNamespace(GetTokenInformation=self.get_token_information)

    def get_token_information(self, token, kind, buffer, length, returned):
        self.events.append(("query", kind))
        self.assert_token(token)
        if kind == 10:
            value = lab.C.cast(buffer, lab.C.POINTER(lab.TokenStatistics))[0]
            value.TokenType = 1
            value.AuthenticationId = lab.LUID(123, 0)
            size = 56
        else:
            value = {8: 1, 12: 1, 15: 0, 18: 1, 20: 1, 21: 0, 26: 0, 29: 0}[kind]
            lab.C.cast(buffer, lab.C.POINTER(lab.D))[0] = value
            size = 1 if kind == 21 else 4
        lab.C.cast(returned, lab.C.POINTER(lab.D))[0] = 0 if self.fail == kind else size
        return 1

    def assert_token(self, token):
        if token != 100:
            raise AssertionError("not the one current token")

    def compartment(self):
        self.events.append(("compartment",))
        return 1

    def current_token(self):
        self.events.append(("current_token_query_only",))
        return 100

    def close(self, token):
        self.assert_token(token)
        self.events.append(("close", token))

    def sid_field(self, token, kind, name, *, nullable=False):
        self.assert_token(token)
        self.events.append(("sid", kind))
        return {1: USER, 25: "S-1-16-12288", 31: None}[kind]

    def groups(self, token, kind, name):
        self.assert_token(token)
        self.events.append(("groups", kind))
        return {2: source()["groups"], 30: [], 11: [], 28: source()["logon_sids"]}[kind]

    def user_attributes(self, token):
        self.assert_token(token)
        self.events.append(("user_attributes",))
        return source()["user_attributes"]

    def privileges(self, token):
        self.assert_token(token)
        self.events.append(("privileges",))
        return source()["privileges"]

    def forbidden(self, *args, **kwargs):
        raise AssertionError("preflight attempted a mutation or runtime token operation")

    source_token = create_restricted = set_medium_integrity = create_job = forbidden
    create_suspended = open_stdio_file = linked_token = forbidden


class PreflightTests(unittest.TestCase):
    def test_independent_preflight_covers_all_original_and_new_fields_without_mutation(self):
        api = PreflightFakeAPI()
        report = lab.token_preflight(api)
        self.assertTrue(report["observations_complete"])
        self.assertEqual(set(report["current"]), set(lab.OBSERVATION_NAMES))
        self.assertEqual(len(report["current"]), 18)
        self.assertTrue(report["source_identity_gate"]["value"])
        self.assertEqual(report["token_access"], 8)
        self.assertTrue(report["cleanup"]["token_handles_closed"])
        self.assertEqual(api.events[-1], ("close", 100))
        self.assertIn(("current_token_query_only",), api.events)
        for name in lab.FIXED_OBSERVATIONS:
            self.assertTrue(report["current"][name]["native_query"]["native_success"])
        for key in ("ordinary_user_acceptance", "stage0b_passed", "product_acceptance",
                    "psec_acceptance", "restricted_caller_r0_passed", "derived_token_created",
                    "process_created", "profile_created", "appcontainer_created", "acl_changed",
                    "network_tested"):
            self.assertIs(report[key], False)

    def test_one_query_failure_does_not_hide_other_fields_and_retains_sizes(self):
        api = PreflightFakeAPI(fail=21)
        report = lab.token_preflight(api)
        self.assertFalse(report["observations_complete"])
        self.assertEqual(sum(record["ok"] for record in report["current"].values()), 17)
        self.assertTrue(report["current"]["sandbox_inert"]["ok"])
        self.assertTrue(report["current"]["restricted_sids"]["ok"])
        self.assertTrue(report["current"]["logon_sids"]["ok"])
        error = report["current"]["has_restrictions"]["error"]
        self.assertEqual(error["operation"], "GetTokenInformation(TokenHasRestrictions)")
        self.assertEqual((error["capacity"], error["expected_size"], error["returned_size"]), (4, 1, 0))
        self.assertFalse(report["source_identity_gate"]["ok"])
        self.assertTrue(report["cleanup"]["token_handles_closed"])

    def test_runtime_and_preflight_use_same_strict_native_readers(self):
        api = PreflightFakeAPI(fail=21)
        with self.assertRaises(lab.FixedQueryFailure):
            lab.restricted_identity(api, 100)
        self.assertNotIn(("query", 15), api.events)
        clean = PreflightFakeAPI()
        self.assertEqual(lab.restricted_identity(clean, 100), source())

    def test_preflight_redacts_raw_user_logon_and_authentication_identifiers(self):
        report = lab.token_preflight(PreflightFakeAPI())
        encoded = json.dumps(report)
        self.assertNotIn(USER, encoded)
        self.assertNotIn(LOGON, encoded)
        self.assertNotIn(UNKNOWN, encoded)
        self.assertNotIn("[123, 0]", encoded)
        self.assertNotIn('"luid":', encoded)

    def test_preflight_permission_gate_prevents_api_construction(self):
        with mock.patch.object(lab, "RestrictedAPI", side_effect=AssertionError("native construction")):
            with self.assertRaises(PermissionError):
                lab.run_preflight(SimpleNamespace(disposable_ci=False, approved_security_test=False))

    def test_preflight_cli_needs_no_actor_and_rejects_runtime_arguments(self):
        arguments = ["--token-preflight", "--disposable-ci", "--approved-security-test",
                     "--report", "fresh.json"]
        with mock.patch.object(lab, "run_preflight", return_value=0) as preflight:
            with mock.patch.object(lab, "run", side_effect=AssertionError("runtime")):
                self.assertEqual(lab.main(arguments), 0)
        self.assertIsNone(preflight.call_args.args[0].actor)
        for extra in (["--actor", "actor.exe"], ["--work", "work"], ["--actor-sha256", "a" * 64]):
            with mock.patch("sys.stderr", new_callable=io.StringIO), self.assertRaises(SystemExit):
                lab.main(arguments + extra)

    def test_preflight_report_must_be_fresh_inside_checkout(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            (root / "ruleproxy").mkdir()
            (root / "ruleproxy/windows_app_process.py").write_text("# fixture")
            with mock.patch.object(lab, "ROOT", root):
                path = root / "fresh.json"
                self.assertEqual(lab.validate_preflight_report(path), path.resolve())
                path.write_text("preserved")
                with self.assertRaisesRegex(lab.GateFailure, "fresh_preflight_report_required"):
                    lab.validate_preflight_report(path)
                self.assertEqual(path.read_text(), "preserved")
                with self.assertRaises(lab.GateFailure):
                    lab.validate_preflight_report(root.parent / "outside.json")


class LifecycleTests(unittest.TestCase):
    def launch(self, api):
        return lab.launch_actor(api, Path("windows_identity_actor.exe"), "a" * 32, Path("owned"),
                                200, restricted(), source())

    def test_fixed_actor_is_verified_before_resume_and_job_drained_before_close(self):
        api = RestrictedFakeAPI()
        result = self.launch(api)
        self.assertNotIn("error", result)
        self.assertTrue(result["cleanup"]["job_empty"])
        events = [e[0] for e in api.events]
        self.assertLess(events.index("child_restricted_identity"), events.index("resume"))
        self.assertLess(events.index("assign_job"), events.index("resume"))
        self.assertLess(events.index("terminate_job"), events.index("wait_job_empty"))
        self.assertLess(events.index("wait_job_empty"), events.index("close"))
        self.assertIn(("wait", 30, 15000), api.events)

    def test_privilege_or_authentication_mismatch_never_resumes(self):
        for field, value in (("privileges", source()["privileges"]), ("authentication_luid", (555, 0))):
            child = restricted()
            child[field] = value
            api = RestrictedFakeAPI(child=child)
            result = self.launch(api)
            self.assertFalse(result["resumed"])
            self.assertIn("error", result)
            self.assertIn(("terminate_job", 10), api.events)

    def test_creation_1314_stops_without_fallback(self):
        api = RestrictedFakeAPI(fail="create_suspended")
        result = self.launch(api)
        self.assertFalse(result["started"])
        self.assertEqual(result["error"]["winerror"], 1314)
        self.assertEqual(sum(e[0] == "create_suspended" for e in api.events), 1)

    def test_assignment_failure_terminates_owned_suspended_process(self):
        api = RestrictedFakeAPI(fail="assign_job")
        result = self.launch(api)
        self.assertFalse(result["resumed"])
        self.assertIn(("terminate_process", 30), api.events)
        self.assertNotIn(("terminate_job", 10), api.events)

    def test_timeout_kills_then_drains_job(self):
        api = RestrictedFakeAPI(timeout=True)
        result = self.launch(api)
        self.assertTrue(result["timed_out"])
        self.assertIn(("terminate_job", 10), api.events)
        self.assertIn(("wait_job_empty", 10, 5000), api.events)

    def test_failed_job_drain_still_closes_job_but_never_claims_empty(self):
        api = RestrictedFakeAPI(fail="wait_job_empty")
        result = self.launch(api)
        self.assertFalse(result["cleanup"]["job_empty"])
        self.assertTrue(result["cleanup"]["errors"])
        self.assertIn(("close", 10), api.events)

    def test_runtime_requires_explicit_windows_approval(self):
        with self.assertRaises(PermissionError):
            lab.run(SimpleNamespace(disposable_ci=False, approved_security_test=False))


if __name__ == "__main__":
    unittest.main()
