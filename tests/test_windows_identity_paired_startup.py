"""Pure paired startup tests; all native calls and process work are fakes."""
import copy
import hashlib
import importlib.util
import json
from pathlib import Path
from types import SimpleNamespace
import unittest
from unittest import mock
import windows_identity_test_support as test_support
from windows_identity_test_support import owned_temp_directory

from test_windows_identity_ordinary_launcher import FakeAPI
from test_windows_identity_restricted_launcher import source, restricted

ROOT = Path(__file__).resolve().parents[1]
SPEC = importlib.util.spec_from_file_location("paired_startup_test", ROOT / ".github/windows_identity_paired_startup.py")
paired = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(paired)


class MatrixAPI(FakeAPI):
    def __init__(self, fail=None, exit_codes=None, parent_changes=None):
        super().__init__(fail=fail)
        self.exit_codes = exit_codes or {}
        self.parent_changes = parent_changes or set()
        self.parent_reads = 0
        self.cell = None
        self.next_token = 200

    def event(self, name, *args):
        self.events.append((name, *args))
        if self.fail == name:
            raise paired.lab.NativeFailure(name, 1314)

    def source_token(self):
        self.event("source_token")
        return 100

    def compartment(self):
        return 1

    def identity(self, token):
        self.event("identity", token)
        if token != 100:
            return restricted()
        self.parent_reads += 1
        value = source()
        if self.parent_reads in self.parent_changes:
            value["session_id"] = 999
        return value

    def create_restricted(self, token, snapshot):
        self.event("create_restricted", token)
        value = self.next_token
        self.next_token += 1
        return value

    def set_medium_integrity(self, token, source_token):
        self.event("set_medium_integrity", token, source_token)

    def create_suspended(self, info, command, work, handles, token):
        self.cell = work.name
        self.command, self.work, self.token = command, work, token
        if (len(command) != 4 or command[1] != "actor"
                or command[3] != str(work / "actor.json")):
            raise AssertionError("unexpected actor command")
        super().create_suspended(info, command, work, handles, token)

    def child_restricted_identity(self, process):
        self.event("child_restricted_identity", process)
        return source() if self.token == 100 else restricted()

    def resume(self, thread):
        self.event("resume", thread)
        if self.exit_codes.get(self.cell, 0) == 0:
            value = source() if self.token == 100 else restricted()
            report = {"schemaVersion": 1, "mode": "actor", "nonce": self.command[2], "pid": 32,
                      "tokenUserSid": value["sid"], "tokenElevated": value["elevated"],
                      "tokenIsAppContainer": False, "tokenAppContainerSid": None,
                      "tokenCapabilities": [], "isProcessInJob": True,
                      "queriesSucceeded": True, "errors": []}
            (self.work / "actor.json").write_text(json.dumps(report))

    def exit_code(self, process):
        self.event("exit_code", process)
        return self.exit_codes.get(self.cell, 0)

    def wait_job_empty(self, job, milliseconds):
        self.event("wait_job_empty", job, milliseconds)
        return True


def builds():
    return {
        "full": {"actor": Path("full/windows_identity_actor.exe"), "actor_sha256": "a" * 64,
                 "source_sha256": "c" * 64, "http_compiled": True},
        "identity": {"actor": Path("minimal/windows_identity_actor.exe"), "actor_sha256": "b" * 64,
                     "source_sha256": "c" * 64, "http_compiled": False},
    }


class MatrixTests(unittest.TestCase):
    def matrix(self, api):
        with owned_temp_directory() as root:
            with mock.patch.object(paired.lab, "restricted_identity",
                                   side_effect=lambda target, token: target.identity(token)):
                return paired.paired_startup(api, builds(), root, "d" * 64)

    def closed_cell_errors(self, report):
        # Future CI assertion failures expose only the publication projection's
        # closed operation IDs/codes, never full identity, nonce, or path data.
        public = paired.publication_projection(report)
        diagnostics = []
        raw_cells = {cell["label"]: cell for cell in report["cells"]}
        for cell in public["cells"]:
            error = raw_cells.get(cell["label"], {}).get("error", {})
            reason = error.get("reason")
            diagnostics.append({
                "label": cell["label"], "error": cell.get("error"),
                "launch_error": cell.get("launch_error"),
                "native_exit_code": cell.get("native_exit_code"),
                "actor_report_present": cell.get("actor_report_present"),
                "actor_matches_native_observation": cell.get("actor_matches_native_observation"),
                "closed_reason": reason if reason in (
                    "path_outside_owned_root", "reparse_or_symlink_path",
                    "probe_report_too_large", "probe_report_not_object") else None,
            })
        return diagnostics

    def test_short_parent_fixture_is_canonical_before_mock_process_and_report_paths(self):
        with owned_temp_directory() as canonical:
            short = canonical.parent / (canonical.name + "~1")
            context = mock.MagicMock()
            context.__enter__.return_value = str(short)
            original_resolve = Path.resolve
            expansions = []

            def resolve(path, *args, **kwargs):
                if path == short:
                    expansions.append(kwargs)
                    return canonical
                return original_resolve(path, *args, **kwargs)

            with mock.patch.object(test_support.tempfile, "TemporaryDirectory", return_value=context), \
                    mock.patch.object(Path, "resolve", autospec=True, side_effect=resolve):
                api = MatrixAPI()
                report = self.matrix(api)
            self.assertEqual(expansions, [{"strict": True}])
            self.assertTrue(report["all_actor_startups_succeeded"], self.closed_cell_errors(report))
            self.assertEqual(api.work.parent, canonical)
            self.assertEqual(Path(api.command[3]).parent.parent, canonical)

    def test_simulated_uncanonical_fixture_reproduces_closed_report_containment_failure(self):
        # Reproduce the old fixture's possible Windows behavior, without a real
        # alias or relaxing production checks: the file resolves to a long
        # spelling while read_probe's supplied inside parent stays short.
        with owned_temp_directory() as raw:
            canonical = raw.parent / ("long-spelling-" + raw.name)
            original_resolve = Path.resolve

            def resolve(path, *args, **kwargs):
                result = original_resolve(path, *args, **kwargs)
                if path.name == "actor.json" and raw in result.parents:
                    return canonical / result.relative_to(raw)
                return result

            with mock.patch.object(Path, "resolve", autospec=True, side_effect=resolve), \
                    mock.patch.object(paired.lab, "restricted_identity",
                                      side_effect=lambda target, token: target.identity(token)):
                report = paired.paired_startup(MatrixAPI(), builds(), raw, "d" * 64)
            self.assertTrue(report["diagnostic_completed"])
            self.assertFalse(report["all_actor_startups_succeeded"])
            for cell in report["cells"]:
                self.assertEqual(cell["error"],
                                 {"operation": "invariant", "reason": "path_outside_owned_root"})
            self.assertEqual([item["closed_reason"] for item in self.closed_cell_errors(report)],
                             ["path_outside_owned_root"] * 4)

    def test_fixture_assertion_diagnostics_never_echo_unclassified_error_text(self):
        report = self.matrix(MatrixAPI())
        report["cells"][0]["error"] = {
            "operation": "SECRET_PATH", "reason": "SECRET_PATH", "message": "SECRET_PATH"}
        self.assertNotIn("SECRET_PATH", json.dumps(self.closed_cell_errors(report)))

    def test_all_four_cells_keep_source_control_distinct_and_clean_each_before_next(self):
        api = MatrixAPI()
        report = self.matrix(api)
        self.assertTrue(report["diagnostic_completed"])
        self.assertTrue(report["all_actor_startups_succeeded"], self.closed_cell_errors(report))
        self.assertEqual([c["label"] for c in report["cells"]], [c[0] for c in paired.CELLS])
        for index, cell in enumerate(report["cells"]):
            restricted_cell = index in (1, 3)
            self.assertEqual(cell["derived_token_created"], restricted_cell)
            self.assertEqual(cell["launch"]["source_control"], not restricted_cell)
            self.assertTrue(cell["parent_token_unchanged"])
            self.assertTrue(cell["cleanup"]["process_cleanup_confirmed"])
            self.assertEqual(cell["launch"]["child_identity"]["synthetic_restricted_caller"], restricted_cell)
            for field in ("ordinary_user_acceptance", "restricted_caller_r0_passed",
                          "stage0b_passed", "psec_acceptance", "product_acceptance"):
                self.assertFalse(cell[field])
                self.assertFalse(report[field])
        self.assertEqual(sum(e[0] == "create_restricted" for e in api.events), 2)
        self.assertEqual(sum(e[0] == "set_medium_integrity" for e in api.events), 2)
        self.assertEqual(sum(e[0] == "wait_job_empty" for e in api.events), 4)
        self.assertEqual(api.events[-1], ("close", 100))
        creation_indices = [i for i, e in enumerate(api.events) if e[0] == "create_suspended"]
        for before, after in zip(creation_indices, creation_indices[1:]):
            between = api.events[before + 1:after]
            self.assertIn(("wait_job_empty", 10, 5000), between)
            self.assertIn(("close", 30), between)

    def test_startup_loader_failure_collects_all_cells_but_not_startup_success(self):
        api = MatrixAPI(exit_codes={"full-restricted": 0xC0000142, "identity-restricted": 0xC0000142})
        report = self.matrix(api)
        self.assertTrue(report["diagnostic_completed"])
        self.assertFalse(report["all_actor_startups_succeeded"])
        for index in (1, 3):
            self.assertEqual(report["cells"][index]["native_exit_code_hex"], "0xC0000142")
            self.assertFalse(report["cells"][index]["actor_report_present"])
            self.assertTrue(report["cells"][index]["safe_to_continue"])

    def test_creation_1314_is_recorded_with_no_fallback_and_clean_cells_continue(self):
        api = MatrixAPI(fail="create_suspended")
        report = self.matrix(api)
        self.assertTrue(report["diagnostic_completed"])
        self.assertFalse(report["all_actor_startups_succeeded"])
        self.assertEqual(sum(e[0] == "create_suspended" for e in api.events), 4)
        self.assertEqual(sum(e[0] == "resume" for e in api.events), 0)
        for cell in report["cells"]:
            self.assertEqual(cell["launch"]["error"]["winerror"], 1314)
            self.assertFalse(cell["process_created"])
            self.assertTrue(cell["safe_to_continue"])

    def test_uncertain_job_cleanup_stops_remaining_cells(self):
        api = MatrixAPI(fail="wait_job_empty")
        report = self.matrix(api)
        self.assertFalse(report["diagnostic_completed"])
        self.assertEqual(len(report["cells"]), 1)
        self.assertFalse(report["cells"][0]["safe_to_continue"])
        self.assertEqual(sum(e[0] == "create_suspended" for e in api.events), 1)
        self.assertIn(("close", 100), api.events)

    def test_derived_token_close_failure_stops_before_third_cell(self):
        api = MatrixAPI()
        original_close = api.close

        def close(handle):
            if handle == 200:
                raise paired.lab.NativeFailure("CloseHandle", 6)
            original_close(handle)
        api.close = close
        report = self.matrix(api)
        self.assertFalse(report["diagnostic_completed"])
        self.assertEqual(len(report["cells"]), 2)
        self.assertFalse(report["cells"][1]["cleanup"]["derived_token_closed"])
        self.assertFalse(report["cells"][1]["safe_to_continue"])
        self.assertTrue(report["cleanup"]["source_token_closed"])

    def test_parent_read_failure_stops_despite_later_matching_observation(self):
        api = MatrixAPI()
        original_identity = api.identity

        def identity(token):
            value = original_identity(token)
            if token == 100 and api.parent_reads == 2:
                raise paired.lab.NativeFailure("GetTokenInformation(TokenUser)", 5)
            return value
        api.identity = identity
        report = self.matrix(api)
        self.assertFalse(report["diagnostic_completed"])
        self.assertEqual(len(report["cells"]), 1)
        self.assertIsNone(report["cells"][0]["parent_token_checks"][0]["unchanged"])
        self.assertFalse(report["cells"][0]["safe_to_continue"])
        self.assertTrue(report["parent_token_unchanged"])

    def test_changed_parent_stops_even_if_later_readback_matches(self):
        # Initial snapshot is read 1; before first cell is read 2. A later
        # restored observation must not erase the earlier change evidence.
        api = MatrixAPI(parent_changes={2})
        report = self.matrix(api)
        self.assertFalse(report["diagnostic_completed"])
        self.assertEqual(len(report["cells"]), 1)
        self.assertFalse(report["cells"][0]["parent_token_checks"][0]["unchanged"])
        self.assertFalse(report["cells"][0]["safe_to_continue"])
        self.assertTrue(report["parent_token_unchanged"])
        self.assertFalse(any(e[0] == "create_suspended" for e in api.events))

    def test_source_control_rejects_restricted_child_without_resume(self):
        api = MatrixAPI()
        api.child_restricted_identity = lambda process: restricted()
        report = self.matrix(api)
        self.assertTrue(report["diagnostic_completed"])
        for index in (0, 2):
            cell = report["cells"][index]
            self.assertFalse(cell["launch"]["resumed"])
            self.assertEqual(cell["launch"]["error"]["reason"],
                             "suspended_child_differs_from_verified_source_token")

    def test_restricted_cells_reject_source_child_without_relaxing_existing_gate(self):
        api = MatrixAPI()
        api.child_restricted_identity = lambda process: source()
        report = self.matrix(api)
        self.assertTrue(report["diagnostic_completed"])
        for index in (1, 3):
            cell = report["cells"][index]
            self.assertFalse(cell["launch"]["resumed"])
            self.assertEqual(cell["launch"]["error"]["reason"], "synthetic_restricted_token_gate_failed")

    def test_safe_report_has_no_source_paths_or_raw_account_identifiers(self):
        report = self.matrix(MatrixAPI())
        encoded = json.dumps(report)
        self.assertNotIn("full/windows_identity_actor.exe", encoded)
        self.assertNotIn(source()["sid"], encoded)
        self.assertNotIn(source()["logon_sids"][0][0], encoded)
        self.assertNotIn('"luid":', encoded)
        self.assertEqual(report["dependency_audit_sha256"], "d" * 64)

    def test_cleanup_missing_evidence_is_not_confirmation(self):
        self.assertTrue(paired.cleanup_confirmed(None))
        self.assertFalse(paired.cleanup_confirmed({}))
        self.assertFalse(paired.cleanup_confirmed({
            "started": True, "job_created": True, "assigned_to_owned_job": True,
            "cleanup": {"handles_closed": True, "job_closed": True, "process_exit_confirmed": True,
                        "job_empty": False, "errors": []}}))

    def test_cli_permission_gate_prevents_native_execution(self):
        with self.assertRaises(PermissionError):
            paired.run(SimpleNamespace(paired_startup=True, disposable_ci=False, approved_security_test=False))


class InputTests(unittest.TestCase):
    def setup_inputs(self, root):
        (root / "ruleproxy").mkdir()
        (root / "ruleproxy/windows_app_process.py").write_text("# fixture")
        (root / ".github").mkdir()
        (root / ".github/windows_identity_restricted_launcher.py").write_text("# fixture")
        kwargs = {"work": root / "work", "report": root / "work/report.json",
                  "dependency_audit": root / "dependency-audit.json"}
        kwargs["dependency_audit"].write_text('{"checked": true}')
        for variant, http, fill in (("full", True, b"f"), ("identity", False, b"i")):
            directory = root / variant
            directory.mkdir()
            actor = directory / "windows_identity_actor.exe"
            content = b"MZ" + fill * 1022
            actor.write_bytes(content)
            digest = hashlib.sha256(content).hexdigest()
            kwargs["actor_" + variant], kwargs["actor_" + variant + "_sha256"] = actor, digest
            manifest = {"schemaVersion": 1, "sourceSha256": "c" * 64, "executableSha256": digest,
                        "httpCompiled": http, "staticCrt": True, "compileOnly": True}
            (directory / "build-manifest.json").write_text(json.dumps(manifest))
        return SimpleNamespace(**kwargs)

    def test_distinct_hashed_variants_same_source_and_audit_are_bound(self):
        with owned_temp_directory() as root:
            args = self.setup_inputs(root)
            with mock.patch.object(paired, "ROOT", root), mock.patch.object(paired.lab, "ROOT", root):
                result, work, audit_hash = paired.validate_inputs(args)
            self.assertEqual(work, (root / "work").resolve())
            self.assertFalse(work.exists())
            self.assertTrue(result["full"]["http_compiled"])
            self.assertFalse(result["identity"]["http_compiled"])
            self.assertEqual(audit_hash, hashlib.sha256(args.dependency_audit.read_bytes()).hexdigest())

    def test_manifest_wrong_variant_hash_or_source_fails_closed(self):
        for key, value in (("httpCompiled", True), ("executableSha256", "0" * 64),
                           ("sourceSha256", "b" * 64), ("staticCrt", False)):
            with self.subTest(key=key), owned_temp_directory() as root:
                args = self.setup_inputs(root)
                path = root / "identity/build-manifest.json"
                manifest = json.loads(path.read_text())
                manifest[key] = value
                path.write_text(json.dumps(manifest))
                with mock.patch.object(paired, "ROOT", root), mock.patch.object(paired.lab, "ROOT", root):
                    with self.assertRaises(paired.GateFailure):
                        paired.validate_inputs(args)

    def test_existing_work_and_oversized_audit_are_rejected(self):
        with owned_temp_directory() as root:
            args = self.setup_inputs(root)
            with mock.patch.object(paired, "ROOT", root), mock.patch.object(paired.lab, "ROOT", root):
                args.dependency_audit.write_bytes(b" " * (paired.ordinary.MAX_REPORT + 1))
                with self.assertRaisesRegex(paired.GateFailure, "metadata_too_large"):
                    paired.validate_inputs(args)
                args.dependency_audit.write_text("{}")
                args.work.mkdir()
                with self.assertRaisesRegex(paired.GateFailure, "fresh_owned_work_required"):
                    paired.validate_inputs(args)


class PublicationTests(unittest.TestCase):
    def report(self):
        return MatrixTests().matrix(MatrixAPI(exit_codes={"full-restricted": 0xC0000142}))

    def test_public_copy_is_labeled_sanitized_and_bound_to_exact_local_source_bytes(self):
        report = self.report()
        public = paired.publication_projection(report)
        with owned_temp_directory() as root:
            path = root / "report.json"
            paired.ordinary.save_report(path, report)
            self.assertEqual(public["source_report_sha256"], hashlib.sha256(path.read_bytes()).hexdigest())
        self.assertTrue(public["sanitized"])
        self.assertFalse(public["byte_exact"])
        self.assertTrue(public["diagnostic_completed"])
        self.assertFalse(public["all_actor_startups_succeeded"])
        self.assertEqual(public["cells"][1]["native_exit_code"], 0xC0000142)
        self.assertTrue(public["cells"][1]["native_verified_before_resume"])
        self.assertTrue(public["cells"][1]["cleanup"]["job_empty"])

    def test_secret_identifiers_and_inventory_at_any_depth_cannot_leak(self):
        report = self.report()
        before = paired.publication_projection(report)
        secret = "NEVER_PUBLISH_PRIVATE_SENTINEL"
        payload = {
            "sid": "S-1-5-21-891-892-893-999", "privileges": [{"name": secret}],
            "group_count": 919191, "groups": [secret], "pid": 828282, "session_id": 737373,
            "nonce": secret, "authentication_luid": [646464, 0], "username": secret,
            "hostname": secret, "path": "C:\\private\\" + secret, "unknown": secret,
        }
        report.update(payload)
        report["source_identity"] = payload
        report["builds"]["full"].update(payload)
        for cell in report["cells"]:
            cell.update(payload)
            cell["derived_identity"] = payload
            cell["actor_report"] = "C:\\private\\" + secret
            cell["launch"].update(payload)
            cell["launch"]["child_identity"] = payload
            cell["cleanup"].update(payload)
            cell["launch"]["cleanup"].update(payload)
        public = paired.publication_projection(report)
        encoded = json.dumps(public)
        for value in (secret, "S-1-5-21-891-892-893-999", "919191", "828282", "737373", "646464",
                      "privileges", "group_count", "session_id", "authentication_luid",
                      "username", "hostname", '"pid"', '"nonce"', '"path"'):
            self.assertNotIn(value, encoded)
        before.pop("source_report_sha256")
        public.pop("source_report_sha256")
        self.assertEqual(before, public)

    def test_error_projection_preserves_only_closed_operation_and_native_code(self):
        report = self.report()
        secret = "secret_native_message_or_operation"
        report["error"] = {"operation": secret, "winerror": 1314, "reason": secret, "type": secret}
        report["cells"][0]["launch"]["error"] = {
            "operation": "CreateProcessAsUserW", "winerror": 5, "message": secret}
        report["cleanup"]["errors"] = [{"operation": "CloseHandle", "winerror": 6, "path": secret}]
        public = paired.publication_projection(report)
        self.assertEqual(public["error"], {"operation_id": "unclassified_operation", "native_error_code": 1314})
        self.assertEqual(public["cells"][0]["launch_error"],
                         {"operation_id": "create_process_as_user", "native_error_code": 5})
        self.assertEqual(public["cleanup"]["errors"],
                         [{"operation_id": "close_owned_handle", "native_error_code": 6}])
        self.assertNotIn(secret, json.dumps(public))

    def test_missing_cells_have_fixed_not_attempted_labels_and_no_false_pass(self):
        report = self.report()
        report["cells"] = report["cells"][:1]
        report["diagnostic_completed"] = False
        report["all_actor_startups_succeeded"] = False
        public = paired.publication_projection(report)
        self.assertEqual([cell["label"] for cell in public["cells"]], [cell[0] for cell in paired.CELLS])
        self.assertTrue(public["cells"][0]["attempted"])
        self.assertEqual([cell["attempted"] for cell in public["cells"][1:]], [False, False, False])
        self.assertFalse(public["diagnostic_completed"])

    def test_unknown_or_duplicate_cell_labels_are_rejected_without_echo(self):
        for duplicate in (False, True):
            report = self.report()
            report["cells"][1]["label"] = "full-source" if duplicate else "SECRET_LABEL"
            with self.assertRaisesRegex(paired.GateFailure, "^publication_expected_unique_fixed_cell_labels$"):
                paired.publication_projection(report)

    def test_typed_scalars_and_digests_cannot_carry_identifiers(self):
        report = self.report()
        secret = "SECRET_IDENTIFIER"
        report["parent_token_unchanged"] = secret
        report["source_identity_verified"] = {"private": secret}
        report["dependency_audit_sha256"] = secret
        report["cells"][0]["launch"]["exit_code"] = secret
        report["cells"][0]["safe_to_continue"] = secret
        report["builds"]["full"]["actor_sha256"] = secret
        report["error"] = {"operation": {"private": secret}, "winerror": secret}
        public = paired.publication_projection(report)
        self.assertNotIn(secret, json.dumps(public))
        self.assertIsNone(public["parent_token_unchanged"])
        self.assertIsNone(public["cells"][0]["native_exit_code"])
        self.assertIsNone(public["builds"]["full"]["actor_sha256"])

    def test_acceptance_flags_remain_false_even_if_input_has_unsupported_claims(self):
        report = self.report()
        flags = ("ordinary_user_acceptance", "restricted_caller_r0_passed", "stage0b_passed",
                 "psec_acceptance", "product_acceptance", "privacy_qualified")
        report.update({key: True for key in flags})
        public = paired.publication_projection(report)
        for flag in flags:
            self.assertIs(public[flag], False)


if __name__ == "__main__":
    unittest.main()
