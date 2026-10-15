"""ABI fakes and report-safety tests for the read-only Windows GUI context probe."""
from __future__ import annotations

import ctypes
import importlib.util
import json
import os
from pathlib import Path
import tempfile
import unittest
from unittest import mock


ROOT = Path(__file__).resolve().parent.parent
SPEC = importlib.util.spec_from_file_location(
    "ruleproxy_windows_gui_context", ROOT / ".github/windows_gui_context.py"
)
context = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(context)


class FakeFunction:
    def __init__(self, function):
        self.function = function
        self.argtypes = None
        self.restype = None

    def __call__(self, *args):
        return self.function(*args)


class FakeLibrary:
    def __init__(self, **functions):
        for name, function in functions.items():
            setattr(self, name, function if isinstance(function, FakeFunction) else FakeFunction(function))


class AbiFixture:
    def __init__(self, *, folder_hr=0, known_hr=0, open_thread=True,
                 close_success=True, app_container=1):
        self.calls = []
        self.folder_hr = folder_hr
        self.known_hr = known_hr
        self.open_thread = open_thread
        self.close_success = close_success
        self.app_container = app_container
        self.current_error = 0
        self.known_buffer = None

        def write_handle(output, value):
            ctypes.cast(output, ctypes.POINTER(ctypes.c_void_p))[0] = ctypes.c_void_p(value)

        def write_dword(output, value):
            ctypes.cast(output, ctypes.POINTER(ctypes.c_uint32))[0] = value

        def open_process(_process, access, output):
            self.calls.append(("open_process", access))
            write_handle(output, 0x333)
            return 1

        def open_thread(_thread, access, as_self, output):
            self.calls.append(("open_thread", access, as_self))
            if self.open_thread:
                write_handle(output, 0x444)
                return 1
            self.current_error = 1008
            return 0

        def information(token, info_class, output, size, returned):
            self.calls.append(("token_info", token, info_class, size))
            value = 1 if info_class == context.TOKEN_TYPE_CLASS else self.app_container
            write_dword(output, value)
            write_dword(returned, ctypes.sizeof(ctypes.c_uint32))
            return 1

        def close(handle):
            self.calls.append(("close", handle))
            if not self.close_success:
                self.current_error = 6
                return 0
            return 1

        def folder_path(_hwnd, csidl, token, flags, output):
            self.calls.append(("folder_path", csidl, token, flags))
            buffer = ctypes.cast(output, ctypes.POINTER(ctypes.c_wchar))
            for index, char in enumerate("C:\\private\\localappdata"):
                buffer[index] = char
            buffer[len("C:\\private\\localappdata")] = "\0"
            return self.folder_hr

        def known_folder(guid_ptr, flags, token, output):
            guid = ctypes.cast(guid_ptr, ctypes.POINTER(context.GUID)).contents
            self.calls.append(("known_folder", guid.Data1, flags, token))
            self.known_buffer = ctypes.create_unicode_buffer("C:\\private\\localappdata")
            ctypes.cast(output, ctypes.POINTER(ctypes.c_wchar_p))[0] = ctypes.cast(
                self.known_buffer, ctypes.c_wchar_p
            )
            return self.known_hr

        def free(pointer):
            self.calls.append(("free", pointer.value))

        kernel = FakeLibrary(GetCurrentProcess=lambda: 0x111,
                             GetCurrentThread=lambda: 0x222, CloseHandle=close)
        advapi = FakeLibrary(OpenProcessToken=open_process, OpenThreadToken=open_thread,
                             GetTokenInformation=information)
        shell = FakeLibrary(SHGetFolderPathW=folder_path, SHGetKnownFolderPath=known_folder)
        ole = FakeLibrary(CoTaskMemFree=free)
        self.api = context.WindowsApi((kernel, advapi, shell, ole), last_error=lambda: self.current_error)
        self.kernel, self.advapi, self.shell, self.ole = kernel, advapi, shell, ole


class WindowsGuiContextTests(unittest.TestCase):
    def test_internal_known_folder_resolver_requires_real_directory_without_reporting_path(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary) / "private-local-appdata"
            root.mkdir()
            class FakeLocation:
                def known_folder_location(self):
                    return root
            resolved = context.resolve_local_appdata_path(FakeLocation())
            self.assertEqual(resolved, root.resolve())
            facts = context.query_context(api=FakeLocation(), environ={})
            self.assertNotIn(str(root), json.dumps(facts))
            class InvalidLocation:
                def known_folder_location(self):
                    return root / "missing"
            with self.assertRaises(OSError):
                context.resolve_local_appdata_path(InvalidLocation())

    def test_abi_bindings_use_fixed_width_types_and_writable_output_pointers(self):
        fixture = AbiFixture()
        self.assertEqual(fixture.shell.SHGetFolderPathW.restype, ctypes.c_int32)
        self.assertEqual(fixture.shell.SHGetKnownFolderPath.restype, ctypes.c_int32)
        self.assertEqual(fixture.advapi.OpenThreadToken.argtypes[1], ctypes.c_uint32)
        self.assertEqual(fixture.advapi.OpenThreadToken.argtypes[2], ctypes.c_int32)
        self.assertEqual(fixture.ole.CoTaskMemFree.argtypes, [ctypes.c_void_p])

        folder = fixture.api.get_folder_path()
        known = fixture.api.get_known_folder_path()
        self.assertEqual(folder, {"hresult_u32": 0, "success": True, "path_present": True})
        self.assertTrue(known["success"] and known["path_present"])
        self.assertTrue(known["free_attempted"] and known["free_success"])
        self.assertEqual(known["free_error"], 0)
        self.assertTrue(any(call[0] == "free" for call in fixture.calls))
        self.assertEqual(fixture.api.process_token()["token_type"], 1)

    def test_hresult_keeps_unsigned_code_and_success_uses_signed_hresult_semantics(self):
        fixture = AbiFixture(folder_hr=-2147467259, known_hr=-2147467259)
        folder = fixture.api.get_folder_path()
        known = fixture.api.get_known_folder_path()
        self.assertEqual(folder["hresult_u32"], 0x80004005)
        self.assertFalse(folder["success"])
        self.assertFalse(folder["path_present"])
        self.assertEqual(known["hresult_u32"], 0x80004005)
        self.assertFalse(known["success"])
        self.assertTrue(known["free_attempted"])
        self.assertTrue(known["free_success"])

    def test_thread_token_no_token_is_reported_as_1008_without_a_handle_close(self):
        fixture = AbiFixture(open_thread=False)
        result = fixture.api.thread_token()
        self.assertFalse(result["open_success"])
        self.assertEqual(result["open_error"], 1008)
        self.assertFalse(result["close_attempted"])
        self.assertFalse(any(call[0] == "close" for call in fixture.calls))
        call = next(call for call in fixture.calls if call[0] == "open_thread")
        self.assertEqual(call[1:], (context.TOKEN_QUERY, True))

    def test_token_close_failure_is_explicit_and_app_container_value_is_bounded(self):
        fixture = AbiFixture(close_success=False, app_container=3)
        result = fixture.api.process_token()
        self.assertTrue(result["open_success"])
        self.assertTrue(result["app_container_query_success"])
        self.assertTrue(result["app_container"])
        self.assertFalse(result["close_success"])
        self.assertEqual(result["close_error"], 6)

    def test_query_report_contains_only_presence_booleans_and_integer_codes(self):
        fixture = AbiFixture(open_thread=False)
        report = context.query_context(fixture.api, {
            "LOCALAPPDATA": "C:\\private\\profile", "APPDATA": "C:\\private\\roaming",
        })
        encoded = json.dumps(report, sort_keys=True)
        self.assertNotIn("private", encoded)
        self.assertNotIn("USERPROFILE", report["environment"])
        self.assertEqual(report["environment"], {
            "localappdata_present": True, "appdata_present": True, "userprofile_present": False,
        })

        def check(value):
            if isinstance(value, dict):
                for nested in value.values():
                    check(nested)
            else:
                self.assertIn(type(value), (bool, int))
        check(report)
        self.assertEqual(report["thread_token"]["open_error"], 1008)

    def test_environment_presence_does_not_depend_on_nonempty_value(self):
        report = context.query_context(AbiFixture().api, {"LOCALAPPDATA": ""})
        self.assertTrue(report["environment"]["localappdata_present"])
        self.assertFalse(report["environment"]["appdata_present"])

    def test_optional_api_result_is_reduced_to_expected_scalar_facts(self):
        class UnexpectedApi:
            def get_folder_path(self):
                return {"hresult_u32": 0, "success": True, "path_present": True,
                        "path": "C:\\private"}

            def get_known_folder_path(self):
                return {"hresult_u32": 0, "success": True, "path_present": True,
                        "free_attempted": True, "free_success": True, "free_error": 0,
                        "extra": {"token": "private"}}

            def process_token(self):
                return {"open_success": True, "open_error": 0, "token_type_success": True,
                        "token_type": 1, "token_type_error": 0,
                        "app_container_query_success": True, "app_container": False,
                        "app_container_error": 0, "close_attempted": True,
                        "close_success": True, "close_error": 0, "sid": "S-1-private"}

            def thread_token(self):
                return {"open_success": False, "open_error": 1008}

        report = context.query_context(UnexpectedApi(), {})
        serialized = json.dumps(report, sort_keys=True)
        self.assertNotIn("private", serialized)
        self.assertNotIn('"path":', serialized)
        self.assertNotIn("sid", serialized)
        self.assertEqual(report["thread_token"]["open_error"], 1008)

    def test_write_report_is_atomic_bounded_and_cli_probe_contract(self):
        report = context.query_context(AbiFixture().api, {})
        with tempfile.TemporaryDirectory() as directory:
            output = Path(directory) / "subdir" / "context.json"
            self.assertEqual(context.main(["--probe", "--report", str(output)]), 0)
            saved = json.loads(output.read_text(encoding="utf-8"))
            self.assertEqual(saved["schema"], context.REPORT_SCHEMA)
            context.write_report(output, report)
            self.assertLessEqual(output.stat().st_size, context.MAX_REPORT_BYTES)
            self.assertEqual(list(output.parent.glob("*.partial")), [])

    def test_release_wait_accepts_exact_file_with_fake_clock(self):
        with tempfile.TemporaryDirectory() as directory:
            release = Path(directory) / "release.signal"
            now, waits = [0.0], []

            def sleep(duration):
                waits.append(duration)
                now[0] += duration
                if len(waits) == 3:
                    release.write_bytes(context.RELEASE_CONTENT)

            context.wait_for_release(release, timeout=0.2, interval=0.02,
                                     clock=lambda: now[0], sleep=sleep)
            self.assertEqual(len(waits), 3)
            self.assertTrue(all(0 < duration <= 0.02 for duration in waits))

    def test_release_wait_times_out_deterministically(self):
        with tempfile.TemporaryDirectory() as directory:
            release = Path(directory) / "release.signal"
            now = [0.0]

            def sleep(duration):
                now[0] += duration

            with self.assertRaisesRegex(context.ReleaseHandshakeError, "timed out"):
                context.wait_for_release(release, timeout=0.04, interval=0.02,
                                         clock=lambda: now[0], sleep=sleep)
            self.assertEqual(now[0], 0.04)

    def test_release_wait_rejects_invalid_content_and_symlink(self):
        with tempfile.TemporaryDirectory() as directory:
            release = Path(directory) / "release.signal"
            release.write_bytes(b"not release\n")
            with self.assertRaisesRegex(context.ReleaseHandshakeError, "content is invalid"):
                context.wait_for_release(release, clock=lambda: 0.0, sleep=lambda _delay: None)
            release.unlink()
            target = Path(directory) / "target"
            target.write_bytes(context.RELEASE_CONTENT)
            try:
                release.symlink_to(target)
            except (OSError, NotImplementedError):
                self.skipTest("symlink creation is unavailable")
            with self.assertRaisesRegex(context.ReleaseHandshakeError, "symlink"):
                context.wait_for_release(release, clock=lambda: 0.0, sleep=lambda _delay: None)

    def test_release_path_must_be_absolute_same_directory_and_absent(self):
        with tempfile.TemporaryDirectory() as directory, tempfile.TemporaryDirectory() as other:
            report = Path(directory) / "context.json"
            release = Path(directory) / "release.signal"
            context._validate_release_destination(report, release)
            with self.assertRaisesRegex(context.ReleaseHandshakeError, "absolute"):
                context._validate_release_destination(report, Path("relative.signal"))
            with self.assertRaisesRegex(context.ReleaseHandshakeError, "share the report"):
                context._validate_release_destination(report, Path(other) / "release.signal")
            release.write_bytes(context.RELEASE_CONTENT)
            with self.assertRaisesRegex(context.ReleaseHandshakeError, "already exists"):
                context._validate_release_destination(report, release)

    def test_cli_timeout_returns_two_after_report_is_written(self):
        with tempfile.TemporaryDirectory() as directory:
            report = Path(directory) / "context.json"
            release = Path(directory) / "release.signal"
            with mock.patch.object(context, "query_context", return_value={"schema": 1}), \
                    mock.patch.object(context, "wait_for_release",
                                      side_effect=context.ReleaseHandshakeError("release wait timed out")):
                result = context.main(["--probe", "--report", str(report),
                                       "--release-file", str(release)])
            self.assertEqual(result, 2)
            self.assertTrue(report.exists())
            self.assertFalse(release.exists())

    @unittest.skipUnless(os.name == "nt", "native Windows ABI smoke test")
    def test_real_windows_known_folder_and_current_process_token_abi(self):
        api = context.WindowsApi()
        folder = api.get_folder_path()
        known = api.get_known_folder_path()
        process = api.process_token()
        for result in (folder, known):
            self.assertIs(type(result["hresult_u32"]), int)
            self.assertGreaterEqual(result["hresult_u32"], 0)
            self.assertLessEqual(result["hresult_u32"], 0xFFFFFFFF)
            self.assertEqual(result["success"], result["hresult_u32"] < 0x80000000)
        if known["free_attempted"]:
            self.assertTrue(known["free_success"])
        self.assertTrue(process["open_success"])
        self.assertTrue(process["token_type_success"])
        self.assertEqual(process["token_type"], 1)  # TokenPrimary
        self.assertTrue(process["close_attempted"])
        self.assertTrue(process["close_success"])
        location = context.resolve_local_appdata_path(api)
        self.assertTrue(location.is_absolute() and location.is_dir())


if __name__ == "__main__":
    unittest.main()
