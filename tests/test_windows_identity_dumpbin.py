"""Pure parser tests. Fixtures are synthetic; no Windows programs are run."""
import copy
import importlib.util
import io
import json
from pathlib import Path
import tempfile
import unittest
from unittest import mock

ROOT = Path(__file__).resolve().parents[1]
SPEC = importlib.util.spec_from_file_location(
    "identity_dumpbin_test", ROOT / ".github/windows_identity_dumpbin.py")
dumpbin = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(dumpbin)

FULL = ["ADVAPI32.dll", "WINHTTP.dll", "KERNEL32.dll"]
MINIMAL = ["ADVAPI32.dll", "KERNEL32.dll"]
PRIVATE_PATH = r"C:\Users\private-person\work\private-file.exe"


def dependents(names, indent="    "):
    return (
        "Dump of file " + PRIVATE_PATH + "\r\n\r\nFile Type: EXECUTABLE IMAGE\r\n"
        "  Image has the following dependencies:\r\n\r\n" +
        "".join(indent + name + "\r\n" for name in names) +
        "\r\n  Summary\r\n\r\n        1000 .text\r\n"
    ).encode("utf-8")


def imports(names):
    return (
        "Dump of file " + PRIVATE_PATH + "\r\n\r\nFile Type: EXECUTABLE IMAGE\r\n"
        "  Section contains the following imports:\r\n\r\n" +
        "".join("    " + name + "\r\n"
                "             180030000 Import Address Table\r\n"
                "                          130 PrivateSymbolNotForPublication\r\n"
                for name in names) +
        "\r\n  Summary\r\n        1000 .text\r\n"
    ).encode("utf-8")


class Runner:
    def __init__(self, overrides=None):
        self.overrides = overrides or {}
        self.calls = []

    def __call__(self, command):
        mode, label = command[2][1:], command[3]
        self.calls.append((label, mode))
        names = FULL if label == "full" else MINIMAL
        result = {"status": "completed", "exit_code": 0,
                  "data": dependents(names) if mode == "dependents" else imports(names)}
        result.update(self.overrides.get((label, mode), {}))
        return result


def collect(runner=None):
    return dumpbin.collect(
        {label: label for label in dumpbin.LABELS}, "installed-dumpbin",
        runner=runner or Runner(), system_version="10.0.26100.1")


class ParserTests(unittest.TestCase):
    def test_preserves_audit_schema_and_actual_local_import_text(self):
        fixture, audit = collect()
        self.assertTrue(fixture["metadata_gate_passed"])
        self.assertEqual(set(audit), {
            "schema_version", "full", "identity_only", "system_winhttp",
            "full_import_table", "identity_only_import_table", "system_winhttp_file_version"})
        self.assertEqual(audit["full"], sorted(name.upper() for name in FULL))
        self.assertEqual(audit["identity_only"], sorted(name.upper() for name in MINIMAL))
        self.assertIn("130 PrivateSymbolNotForPublication", audit["full_import_table"])
        self.assertNotIn(PRIVATE_PATH, json.dumps(audit))

    def test_public_fixture_contains_no_paths_symbols_or_arbitrary_text(self):
        malicious = imports(FULL) + (
            "S-1-5-21-111-222-333-1001\r\n"
            "secret private-user@example.invalid\r\n"
            "C:\\private\\sensitive.dll\r\n"
        ).encode()
        fixture, _ = collect(Runner({("full", "imports"): {"data": malicious}}))
        text = json.dumps(fixture)
        for forbidden in (PRIVATE_PATH, "PrivateSymbolNotForPublication",
                          "S-1-5-21", "private-user", "sensitive.dll", "C:\\"):
            self.assertNotIn(forbidden, text)
        self.assertIn("WINHTTP.DLL", text)
        self.assertIn("import_header", text)
        dumpbin.validate_fixture(fixture)

    def test_zero_matches_collects_all_five_observations_before_failing(self):
        runner = Runner({("full", "dependents"): {"data": b"unknown private output\n"}})
        fixture, audit = collect(runner)
        self.assertEqual(len(runner.calls), 5)
        self.assertEqual(len(fixture["observations"]), 5)
        self.assertFalse(fixture["metadata_gate_passed"])
        self.assertIsNone(audit)
        self.assertIn("dependency_count", fixture["failures"])
        self.assertEqual(fixture["observations"][0]["legacy_names"], [])

    def test_65_system_dlls_are_diagnosed_without_raising_acceptance_limit(self):
        names = [f"API-MS-WIN-SYNTHETIC-{index}.dll" for index in range(65)]
        runner = Runner({("system_winhttp", "dependents"): {"data": dependents(names)}})
        fixture, audit = collect(runner)
        self.assertEqual(len(runner.calls), 5)
        self.assertEqual(fixture["accepted_dll_limit"], 64)
        self.assertEqual(len(fixture["observations"][2]["legacy_names"]), 65)
        self.assertIsNone(audit)
        self.assertIn("dependency_count", fixture["failures"])

    def test_missing_indentation_is_visible_but_does_not_broaden_legacy_gate(self):
        fixture, audit = collect(Runner({
            ("full", "dependents"): {"data": dependents(FULL, indent="")}}))
        record = fixture["observations"][0]
        self.assertEqual(record["legacy_match_count"], 0)
        self.assertEqual(record["trimmed_match_count"], 3)
        self.assertEqual(record["legacy_names"], [])
        self.assertEqual(len(record["trimmed_names"]), 3)
        self.assertIsNone(audit)

    def test_names_case_fold_and_deduplicate_with_counts_retained(self):
        fixture, audit = collect(Runner({
            ("full", "dependents"): {"data": dependents(FULL + ["kernel32.DLL"])}}))
        self.assertIsNotNone(audit)
        record = fixture["observations"][0]
        self.assertEqual(record["legacy_match_count"], 4)
        self.assertEqual(len(record["legacy_names"]), 3)

    def test_oversize_dll_like_name_is_counted_but_never_published(self):
        too_long = "PRIVATE_" + "x" * 130 + ".dll"
        fixture, audit = collect(Runner({
            ("system_winhttp", "dependents"): {"data": dependents([too_long])}}))
        self.assertIsNone(audit)
        self.assertIn("invalid_dependency_name", fixture["failures"])
        self.assertEqual(fixture["observations"][2]["invalid_legacy_name_count"], 1)
        self.assertNotIn(too_long, json.dumps(fixture))

    def test_tool_failure_does_not_drop_later_targets(self):
        runner = Runner({
            ("identity_only", "dependents"): {
                "status": "start_failed", "exit_code": None,
                "data": b"private machine path that must not be shared"},
            ("full", "imports"): {"exit_code": 2},
        })
        fixture, audit = collect(runner)
        self.assertEqual(len(runner.calls), 5)
        self.assertIsNone(audit)
        self.assertIn("capture_failed", fixture["failures"])
        self.assertNotIn("private machine", json.dumps(fixture))

    def test_truncated_structure_fails_closed(self):
        with mock.patch.object(dumpbin, "MAX_STRUCTURE", 1):
            fixture, audit = collect()
        self.assertIsNone(audit)
        self.assertIn("fixture_incomplete", fixture["failures"])

    def test_utf16_bom_decode_is_explicit_in_diagnostic(self):
        data = dependents(FULL).decode().encode("utf-16")
        fixture, audit = collect(Runner({("full", "dependents"): {"data": data}}))
        self.assertIsNotNone(audit)
        self.assertEqual(fixture["observations"][0]["encoding"], "utf16_bom")
        self.assertGreater(fixture["observations"][0]["nul_bytes"], 0)

    def test_closed_schema_rejects_unknown_fields_at_every_level(self):
        fixture, _ = collect()
        for target in ("top", "observation", "row"):
            changed = copy.deepcopy(fixture)
            value = (changed if target == "top" else changed["observations"][0]
                     if target == "observation" else changed["observations"][0]["structure"][0])
            value["raw_text"] = PRIVATE_PATH
            with self.subTest(target=target), self.assertRaises(ValueError):
                dumpbin.validate_fixture(changed)

    def test_closed_schema_rejects_paths_and_unknown_category_strings(self):
        fixture, _ = collect()
        bad_names = copy.deepcopy(fixture)
        bad_names["observations"][0]["legacy_names"] = [PRIVATE_PATH]
        bad_kind = copy.deepcopy(fixture)
        bad_kind["observations"][0]["structure"][0]["kind"] = PRIVATE_PATH
        for changed in (bad_names, bad_kind):
            with self.assertRaises(ValueError):
                dumpbin.validate_fixture(changed)

    def test_fresh_bounded_writes_do_not_overwrite(self):
        fixture, _ = collect()
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "fixture.json"
            dumpbin.write_new(path, fixture, dumpbin.MAX_FIXTURE_BYTES)
            self.assertEqual(json.loads(path.read_text()), fixture)
            with self.assertRaises(FileExistsError):
                dumpbin.write_new(path, fixture, dumpbin.MAX_FIXTURE_BYTES)
            with self.assertRaises(ValueError):
                dumpbin.write_new(Path(directory) / "too-small.json", fixture, 1)


class CaptureTests(unittest.TestCase):
    def test_capture_byte_bound_is_not_an_acceptance_expansion(self):
        process = mock.Mock()
        process.stdout = io.BytesIO(b"x" * 80)
        process.poll.return_value = 0
        with mock.patch.object(dumpbin, "MAX_CAPTURE_BYTES", 64), \
                mock.patch.object(dumpbin.subprocess, "Popen", return_value=process):
            result = dumpbin.capture(["installed-dumpbin", "/dependents", "fixed-target"])
        self.assertEqual(result["status"], "output_limit")
        self.assertEqual(len(result["data"]), 64)

    def test_capture_timeout_kills_only_owned_reader_process(self):
        process = mock.Mock()
        process.stdout = io.BytesIO(b"")
        process.poll.side_effect = [None, -9]
        with mock.patch.object(dumpbin, "MAX_CAPTURE_SECONDS", 0), \
                mock.patch.object(dumpbin.subprocess, "Popen", return_value=process):
            result = dumpbin.capture(["installed-dumpbin", "/dependents", "fixed-target"])
        self.assertEqual(result["status"], "timeout")
        process.kill.assert_called_once()
        process.wait.assert_called_once_with(timeout=5)


if __name__ == "__main__":
    unittest.main()
