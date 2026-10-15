"""Verify owned GUI identity and cleanup contracts without claiming PSEC success."""
import ctypes
import importlib.machinery
import importlib.util
import json
import ntpath
import os
from pathlib import Path, PureWindowsPath
import subprocess
import sys
import tempfile
import threading
import traceback
import unittest
from unittest import mock
from types import SimpleNamespace


ROOT = Path(__file__).resolve().parent.parent
spec = importlib.util.spec_from_file_location("windows_gui_check", ROOT / ".github/windows_gui_check.py")
gui = importlib.util.module_from_spec(spec)
spec.loader.exec_module(gui)
class FakeProcessApi:
    def __init__(self, *, edge, helper, wrapper):
        self.info = {100: {"pid": 10, "created": 100, "alive": True, "image": wrapper},
                     200: {"pid": 20, "created": 110, "alive": True, "image": helper},
                     300: {"pid": 30, "created": 120, "alive": True, "image": edge}}
        self.parent_map = {10: 1, 20: 10, 30: 20, 99: 1}
        self.snapshots = []
        self.opened, self.closed, self.waited = [], [], []
        self.query_opened = []

    def pid(self, handle):
        return self.info[handle]["pid"]

    def created(self, handle):
        return self.info[handle]["created"]

    def exited_at(self, handle):
        return self.info[handle].get("exited_at", 150)

    def alive(self, handle):
        return self.info[handle]["alive"]

    def wait(self, handle, milliseconds):
        self.waited.append((handle, milliseconds))
        return not self.alive(handle)

    def exit_code(self, handle):
        return self.info[handle].get("exit_code", 0)

    def image(self, handle):
        return self.info[handle]["image"]

    def snapshot(self):
        return self.snapshots.pop(0) if self.snapshots else dict(self.parent_map)

    def open(self, pid):
        self.opened.append(pid)
        return next(handle for handle, value in self.info.items() if value["pid"] == pid)

    def open_query(self, pid):
        self.query_opened.append(pid)
        source = next(value for value in self.info.values() if value["pid"] == pid)
        handle = 10000 + len(self.query_opened)
        self.info[handle] = source
        return handle

    def close(self, handle):
        self.closed.append(handle)


class FakeWindows:
    def __init__(self):
        self.values = [(700, 99), (800, 30)]
        self.pids = {700: 99, 800: 30}
        self.rects = {700: [0, 0, 500, 400], 800: [10, 20, 650, 500]}
        self.posted = []

    def windows(self, allowed_pids=None):
        return [value for value in self.values if allowed_pids is None or value[1] in allowed_pids]

    def pid(self, hwnd):
        return self.pids.get(hwnd)

    def visible_rect(self, hwnd):
        return self.rects.get(hwnd)

    def post_close(self, hwnd):
        self.posted.append(hwnd)


class FakeJobApi:
    def __init__(self):
        self.count = 1
        self.live = True
        self.member_value = True
        self.fail_active = False
        self.fail_close = False
        self.closed = []
        self.active_values = []

    def create(self): return 900
    def configure(self, handle): return 0
    def assign_current(self, handle): pass
    def controller(self): return (77, self.live)
    def member(self, handle): return self.member_value
    def active(self, handle):
        if self.fail_active: raise OSError("accounting unavailable")
        if self.active_values: return self.active_values.pop(0)
        return self.count
    def close(self, handle):
        if self.fail_close: raise OSError("close unavailable")
        self.closed.append(handle)


class GuiCheckTests(unittest.TestCase):
    def setUp(self):
        temporary = tempfile.TemporaryDirectory(prefix="ruleproxy-gui-unit-")
        self.addCleanup(temporary.cleanup)
        self.directory = Path(temporary.name).resolve()
        self.edge = self.directory / "Edge 测试" / "Application" / "msedge.exe"
        self.foreign_edge = self.directory / "Foreign Edge" / "msedge.exe"
        self.helper = self.directory / "Package" / "python.exe"
        self.wrapper = self.directory / "Runtime" / "wxc-exec.exe"
        for image in (self.edge, self.foreign_edge, self.helper, self.wrapper):
            image.parent.mkdir(parents=True, exist_ok=True)
            image.write_bytes(b"public fake image path fixture; never executed")
        self.local_images = {}
        if os.name != "nt":
            # Fake Win32 image queries must return Windows-absolute names.
            # ntpath.isabs('/tmp/...') correctly became False in Python 3.13.
            # Keep real local files for the separate strict-resolve adapter.
            for name in ("edge", "foreign_edge", "helper", "wrapper"):
                local = getattr(self, name)
                windows = PureWindowsPath(r"C:\RuleProxyFixture", *local.relative_to(self.directory).parts)
                self.local_images[ntpath.normcase(str(windows))] = local
                setattr(self, name, windows)

    def test_ingress_control_selector_is_strict_and_confined_to_chromium_control(self):
        with self.assertRaisesRegex(ValueError, "strict boolean"):
            gui.GuiRun(None, None, None, None, None, None,
                       application_kind="chrome_for_testing_control", ingress_default_allow_control=1)
        with self.assertRaisesRegex(ValueError, "limited to the pinned Chromium"):
            gui.GuiRun(None, None, None, None, None, None, ingress_default_allow_control=True)

    def test_standard_profile_layout_selector_is_strict_and_excludes_g2(self):
        with self.assertRaisesRegex(ValueError, "strict boolean"):
            gui.GuiRun(None, None, None, None, None, None,
                       application_kind="chrome_for_testing_control", standard_profile_layout_control=1)
        with self.assertRaisesRegex(ValueError, "limited to the pinned Chromium"):
            gui.GuiRun(None, None, None, None, None, None, standard_profile_layout_control=True)
        with self.assertRaisesRegex(ValueError, "cannot combine with G2"):
            gui.GuiRun(None, None, None, None, None, None,
                       application_kind="chrome_for_testing_control", ingress_default_allow_control=True,
                       standard_profile_layout_control=True)

    def test_standard_profile_cli_skips_localappdata_resolution_and_never_claims_acceptance(self):
        from ruleproxy import windows_runtime
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            report = root / "reports" / "gui.json"
            profile = root / "profile"
            profile.mkdir()
            helpers = mock.Mock()
            helpers.host_facts.return_value = {"windows_product_type": 1, "native_machine": 0x8664,
                                               "python_pe_machine": 0x8664}
            helpers.executable_machine.return_value = 0x8664
            helpers.verify_runtime_manifest.return_value = {"wxc-exec.exe": "a" * 64}
            helpers.network_snapshot.return_value = {"proxy": "unchanged"}
            helpers.write_json.side_effect = lambda path, value: Path(path).write_text(json.dumps(value))
            browser = mock.Mock()
            browser.acceptance_helpers.return_value = helpers
            owner = mock.Mock()
            owner.collect_context.return_value = {"acceptance_passed": False}
            owner.run.side_effect = [{"check": "real_chromium_control_gui_1", "status": "passed"},
                                     {"check": "real_chromium_control_gui_2", "status": "passed"}]

            class Context:
                query_context = staticmethod(mock.Mock(return_value={"outside": True}))
                resolve_local_appdata_path = staticmethod(mock.Mock(side_effect=AssertionError(
                    "standard profile mode must not resolve LocalAppData for a grant")))

            args = ["--root", str(root), "--report", str(report), "--chromium-control-root", str(root / "cft"),
                    "--standard-profile-layout-control"]
            with mock.patch.object(gui, "browser_helpers", return_value=browser), \
                    mock.patch.object(gui.sys, "platform", "win32"), \
                    mock.patch.object(gui, "interactive_facts", return_value={"ordinary_interactive": True}), \
                    mock.patch.object(gui, "chromium_control_browser", return_value=(self.edge, {"verified": True})), \
                    mock.patch.object(gui, "context_helpers", return_value=Context), \
                    mock.patch.object(windows_runtime, "probe", return_value={"supported": True}), \
                    mock.patch.object(gui, "GuiRun", return_value=owner) as run_factory, \
                    mock.patch.object(gui, "GuiJob", return_value=mock.Mock(close=mock.Mock())), \
                    mock.patch.object(gui.tempfile, "mkdtemp", return_value=str(profile)), \
                    mock.patch("builtins.print"):
                code = gui.main(args)
            value = json.loads(report.read_text())
            self.assertEqual(code, 0, value)
            Context.query_context.assert_called_once()
            Context.resolve_local_appdata_path.assert_not_called()
            self.assertTrue(value["standard_profile_layout_control"])
            self.assertEqual(value["source_policy_variant"],
                             "standard_profile_layout_without_extra_directory_grants")
            self.assertFalse(value["additional_directory_grants"])
            self.assertFalse(value["directory_query_list_permission_changed"])
            self.assertFalse(value["acceptance_passed"])
            self.assertFalse(value["full_acceptance_passed"])
            self.assertFalse(value["all_acceptance_passed"])
            self.assertEqual(run_factory.call_args.kwargs["standard_profile_layout_control"], True)
            self.assertNotIn("enumerate_path", run_factory.call_args.kwargs)
            self.assertEqual(owner.run.call_count, 2)

    def test_standard_profile_cli_rejects_missing_cft_and_g2_combination(self):
        for extra in ([], ["--ingress-controls-diagnostic", "--test-psec-executor", "G2.exe",
                           "--test-psec-manifest", "manifest.json"]):
            with self.subTest(extra=extra), mock.patch("builtins.print"):
                with self.assertRaises(SystemExit) as failure:
                    gui.main(["--standard-profile-layout-control", *extra])
                self.assertEqual(failure.exception.code, 2)

    def test_ingress_cli_requires_chromium_control_and_paired_g2_bundle(self):
        base = ["--ingress-controls-diagnostic"]
        for extra in ([], ["--chromium-control-root", str(self.directory)],
                      ["--test-psec-executor", str(self.directory / "wxc-exec.exe"),
                       "--test-psec-manifest", str(self.directory / "manifest.json")]):
            with self.subTest(extra=extra), mock.patch("builtins.print"):
                with self.assertRaises(SystemExit) as raised:
                    gui.main([*base, *extra])
                self.assertEqual(raised.exception.code, 2)

    def test_g2_gui_mode_verifies_g2_bundle_and_never_claims_product_acceptance(self):
        from ruleproxy import windows_runtime
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            report = root / "reports" / "gui.json"
            local_appdata = root / "LocalAppData"
            local_appdata.mkdir()
            private_profile = root / "private-profile"
            private_profile.mkdir()
            helpers = mock.Mock()
            helpers.host_facts.return_value = {"windows_product_type": 1, "native_machine": 0x8664,
                                               "python_pe_machine": 0x8664}
            helpers.executable_machine.return_value = 0x8664
            helpers.verify_runtime_manifest.return_value = {"wxc-exec.exe": "a" * 64}
            helpers.network_snapshot.return_value = {"proxy": "unchanged"}
            helpers.write_json.side_effect = lambda path, value: Path(path).write_text(json.dumps(value))
            browser = mock.Mock()
            browser.acceptance_helpers.return_value = helpers
            owner = mock.Mock()
            owner.collect_context.return_value = {"acceptance_passed": False}
            owner.run.side_effect = [{"check": "real_chromium_control_gui_1", "status": "passed"},
                                     {"check": "real_chromium_control_gui_2", "status": "passed"}]
            control_metadata = {"executor_sha256": "b" * 64, "upstream_commit": "fixed", "patch_sha256": "c" * 64,
                                "patch": {"capabilities_null": False,
                                          "private_network_capability_preserved": True}}
            verify_executor = mock.Mock(return_value=(root / "G2.exe", control_metadata))

            original_spec = importlib.util.spec_from_file_location

            def load_spec(name, location, *args, **kwargs):
                if Path(location).name == "windows_vm_test.py":
                    source_spec = original_spec(name, str(location), *args, **kwargs)

                    class Loader:
                        def create_module(self, spec):
                            return None

                        def exec_module(self, module):
                            source_spec.loader.exec_module(module)
                            module.verify_executor_bundle = verify_executor

                    spec = importlib.machinery.ModuleSpec(name, Loader(), origin=str(location))
                    spec.has_location = True
                    return spec
                return original_spec(name, str(location), *args, **kwargs)

            class Context:
                @staticmethod
                def query_context():
                    return {"outside": True}

                @staticmethod
                def resolve_local_appdata_path():
                    return local_appdata

            args = ["--root", str(root), "--report", str(report), "--chromium-control-root", str(root / "cft"),
                    "--test-psec-executor", str(root / "G2.exe"), "--test-psec-manifest", str(root / "G2.json"),
                    "--ingress-controls-diagnostic"]
            with mock.patch.object(gui, "browser_helpers", return_value=browser), \
                    mock.patch.object(gui.sys, "platform", "win32"), \
                    mock.patch.object(gui, "interactive_facts", return_value={"ordinary_interactive": True}), \
                    mock.patch.object(gui, "chromium_control_browser", return_value=(self.edge, {"verified": True})), \
                    mock.patch.object(gui, "context_helpers", return_value=Context), \
                    mock.patch.object(gui.importlib.util, "spec_from_file_location", side_effect=load_spec), \
                    mock.patch.object(windows_runtime, "probe", return_value={"supported": True}), \
                    mock.patch.object(gui, "GuiRun", return_value=owner) as run_factory, \
                    mock.patch.object(gui, "GuiJob", return_value=mock.Mock(close=mock.Mock())), \
                    mock.patch.object(gui.tempfile, "mkdtemp", return_value=str(private_profile)), \
                    mock.patch.object(gui, "error_facts", side_effect=lambda exc, stage: {"stage": stage,
                        "error_type": type(exc).__name__, "message": str(exc),
                        "trace": "".join(traceback.format_exception(exc))}), \
                    mock.patch("builtins.print"):
                code = gui.main(args)
            value = json.loads(report.read_text())
            self.assertEqual(code, 0, value)
            verify_executor.assert_called_once()
            self.assertTrue(verify_executor.call_args.kwargs["ingress_controls_diagnostic"])
            self.assertEqual(value["source_policy_variant"], "private_network_and_localappdata_control")
            self.assertTrue(value["product_runtime_unchanged"])
            self.assertFalse(value["acceptance_passed"])
            self.assertFalse(value["full_acceptance_passed"])
            self.assertFalse(value["all_acceptance_passed"])
            self.assertFalse(value["capabilities_null"])
            self.assertTrue(value["private_network_capability_preserved"])
            self.assertFalse(value["test_psec_executor"]["patch"]["capabilities_null"])
            self.assertFalse(value["browser"]["sandbox_weakened"])
            self.assertEqual(run_factory.call_args.kwargs["ingress_default_allow_control"], True)
            self.assertEqual(owner.run.call_count, 2)

    def local_fixture_path(self, value):
        key = ntpath.normcase(ntpath.normpath(os.fspath(value)))
        local = self.local_images.get(key, self.directory / "missing.exe")
        def resolve(*, strict):
            # Use real filesystem existence/strict resolution, then represent
            # its canonical result in the simulated Win32 image namespace.
            relative = local.resolve(strict=strict).relative_to(self.directory)
            return PureWindowsPath(r"C:\RuleProxyFixture", *relative.parts)
        return SimpleNamespace(resolve=resolve)

    def tree(self):
        api = FakeProcessApi(edge=str(self.edge), helper=str(self.helper), wrapper=str(self.wrapper))
        wrapper = mock.Mock(pid=10, _handle=100)
        return gui.OwnedTree(api, wrapper, self.edge), api

    def test_process_api_binds_exit_code_with_pointer_safe_win32_prototype(self):
        from ruleproxy import windows_runtime
        api = mock.Mock()
        with mock.patch.object(windows_runtime, "_WinProcessApi", return_value=api):
            gui.ProcessApi()
        self.assertEqual(api.kernel32.GetExitCodeProcess.argtypes,
                         [gui.wintypes.HANDLE, ctypes.POINTER(gui.wintypes.DWORD)])
        self.assertIs(api.kernel32.GetExitCodeProcess.restype, gui.wintypes.BOOL)

    def test_outer_job_fails_closed_on_membership_liveness_accounting_and_close(self):
        api = FakeJobApi()
        job = gui.GuiJob(api)
        api.member_value = False
        with self.assertRaisesRegex(RuntimeError, "not live"):
            job.active_processes()
        api.member_value, api.live = True, False
        with self.assertRaisesRegex(RuntimeError, "not live"):
            job.active_processes()
        api.live = True
        api.fail_active = True
        with self.assertRaises(OSError):
            job.active_processes()
        api.fail_active = False
        api.count = 2
        with self.assertRaisesRegex(RuntimeError, "descendant processes"):
            job.close()
        api.count = 1
        api.fail_close = True
        with self.assertRaises(OSError):
            job.close()
        self.assertFalse(job.closed)
        self.assertEqual(api.closed, [])
        self.assertFalse(hasattr(gui.WinJobApi, "terminate"))

    def test_assigned_job_setup_failure_remains_available_for_cleanup(self):
        api = FakeJobApi()
        api.member_value = False
        before = len(gui._RECOVERY_OWNERS)
        with self.assertRaisesRegex(RuntimeError, "not live") as raised:
            gui.GuiJob(api)
        owner = raised.exception._gui_job_owner
        self.assertIs(gui._RECOVERY_OWNERS[-1], owner)
        self.assertTrue(owner.assigned)
        self.assertEqual(owner.handle, 900)
        self.assertEqual(len(gui._RECOVERY_OWNERS), before + 1)
        del gui._RECOVERY_OWNERS[before:]

    def test_unqueryable_access_denied_candidate_uses_only_outer_job_count(self):
        tree, api = self.tree()
        job_api = FakeJobApi()
        job_api.count = 2
        tree.job = gui.GuiJob(job_api)
        with mock.patch.object(api, "open", side_effect=self.access_denied()), \
                mock.patch.object(api, "open_query", side_effect=self.access_denied()):
            tree.refresh()
        self.assertEqual(len(tree.unqueryable_candidates), 1)
        self.assertEqual(tree.entries, {})
        self.assertEqual(tree.pending, [])
        self.assertEqual(job_api.count, 2)
        windows = FakeWindows()
        windows.values, windows.pids = [(801, 20)], {801: 20}
        windows.rects = {801: [0, 0, 500, 400]}
        self.assertEqual(gui.owned_windows(tree, windows), [])
        api.info[100]["alive"] = False
        api.info[200]["alive"] = False
        api.info[300]["alive"] = False
        job_api.count = 1
        self.assertTrue(tree.all_exited())
        self.assertEqual(len(tree.unqueryable_candidates), 1)

    def test_unqueryable_access_denied_candidate_rejected_without_outer_job_proof(self):
        tree, api = self.tree()
        with mock.patch.object(api, "open", side_effect=self.access_denied()), \
                mock.patch.object(api, "open_query", side_effect=self.access_denied()), self.assertRaises(PermissionError):
            tree.refresh()

    def test_incomplete_query_only_diagnostic_other_than_win5_fails_closed(self):
        tree, api = self.tree()
        tree.job = gui.GuiJob(FakeJobApi())
        with mock.patch.object(api, "open", side_effect=self.access_denied()), \
                mock.patch.object(api, "open_query", side_effect=OSError("non-access failure")), \
                self.assertRaises(PermissionError):
            tree.refresh()
        self.assertEqual(tree.unqueryable_candidates, set())

    def test_outer_job_proof_precedes_any_owned_handle_or_resource_release(self):
        from ruleproxy import windows_runtime
        tree, api = self.tree()
        job_api = FakeJobApi()
        job_api.count = 2
        tree.job = gui.GuiJob(job_api)
        for value in api.info.values():
            value["alive"] = False
        api.parent_map = {10: 1}
        owner = gui.GuiRun(None, None, None, None, None, None, tree.job)
        owner.tree, owner.wrapper, owner.resources = tree, tree.wrapper, mock.Mock()
        job_api.fail_active = True
        with mock.patch.object(windows_runtime, "stop"), self.assertRaises(OSError):
            owner.close()
        self.assertFalse(tree.closed)
        self.assertEqual(api.closed, [])
        owner.resources.close.assert_not_called()
        job_api.fail_active = False
        with mock.patch.object(windows_runtime, "stop"), self.assertRaisesRegex(RuntimeError, "outer Job accounting"):
            owner.close()
        self.assertFalse(tree.closed)
        self.assertEqual(api.closed, [])
        owner.resources.close.assert_not_called()
        self.assertTrue(owner.wrapper is tree.wrapper)
        job_api.count = 1
        with mock.patch.object(windows_runtime, "stop"):
            owner.close()
        self.assertTrue(owner.cleanup_proven)

    def test_windows_nested_job_aggregate_accounting_abi(self):
        module_path = str(ROOT / ".github/windows_gui_check.py")
        child_code = "import sys;print('ready', flush=True);sys.stdin.read(1)"
        compile(child_code, "<windows-job-abi-grandchild>", "exec")
        code = f'''import importlib.util, json, subprocess, sys, time
s = importlib.util.spec_from_file_location("gui", {module_path!r})
m = importlib.util.module_from_spec(s)
s.loader.exec_module(m)
outer = m.GuiJob()
inner = m.GuiJob()
child = {child_code!r}
p = subprocess.Popen([sys.executable, "-c", child], stdin=subprocess.PIPE, stdout=subprocess.PIPE, text=True)
assert p.stdout.readline().strip() == "ready"
outer_count = outer.active_processes()
inner_count = inner.active_processes()
assert outer_count >= 2 and inner_count >= 2
p.stdin.write("x")
p.stdin.flush()
p.wait(timeout=10)
deadline = time.monotonic() + 5
while time.monotonic() < deadline and (outer.active_processes() != 1 or inner.active_processes() != 1):
    time.sleep(0.05)
controller_only = outer.active_processes() == 1 and inner.active_processes() == 1
inner.close()
outer.close()
print(json.dumps({{"nested_accounting": True, "controller_only": controller_only}}))
'''
        compile(code, "<windows-job-abi-child>", "exec")
        if os.name != "nt":
            self.skipTest("Windows Job Object ABI")
        completed = subprocess.run([sys.executable, "-c", code], capture_output=True, text=True, timeout=30)
        self.assertEqual(completed.returncode, 0, completed.stderr[-1000:])
        facts = json.loads(completed.stdout.strip().splitlines()[-1])
        self.assertTrue(facts["nested_accounting"])
        self.assertTrue(facts["controller_only"])

    def access_denied(self):
        error = PermissionError(13, "private error text", "C:\\User Secret\\private.exe")
        error.winerror = 5
        return error

    def test_failed_child_open_records_exact_stage_without_granting_ownership(self):
        tree, api = self.tree()
        error = self.access_denied()
        with mock.patch.object(api, "open", side_effect=error), self.assertRaises(PermissionError) as raised:
            tree.refresh()
        self.assertIs(raised.exception, error)
        facts = gui.error_facts(error)
        diagnostic = facts.pop("query_only_diagnostic")
        self.assertEqual(facts, {"stage": "tree_child_open", "error_type": "PermissionError",
                                "errno": 13, "winerror": 5, "operation": "OpenProcess",
                                "candidate_pid": 20, "parent_pid": 10,
                                "parent_creation_filetime": 100, "requested_access": 0x101000})
        self.assertEqual(diagnostic["status"], "observed")
        self.assertEqual(diagnostic["requested_access"], 0x1000)
        self.assertTrue(diagnostic["handle_closed"])
        self.assertFalse(diagnostic["older_than_parent"])
        self.assertEqual(len(diagnostic["image_key_sha256"]), 64)
        self.assertNotIn("private", json.dumps(gui.error_facts(error)))
        self.assertEqual(tree.entries, {})
        self.assertEqual(tree.pending, [])
        self.assertEqual(api.closed, [10001])
        self.assertEqual(api.query_opened, [20])
        self.assertEqual(tree.diagnostic_query_owners, [])
        with self.assertRaisesRegex(RuntimeError, "live process"):
            tree.close_exited()

    def test_query_only_diagnostic_identifies_older_candidate_without_granting_ownership_or_waiting_it(self):
        tree, api = self.tree()
        api.info[200]["created"] = 90
        error = self.access_denied()
        with mock.patch.object(api, "open", side_effect=error), self.assertRaises(PermissionError) as raised:
            tree.refresh()
        self.assertIs(raised.exception, error)
        diagnostic = gui.error_facts(error)["query_only_diagnostic"]
        self.assertTrue(diagnostic["older_than_parent"])
        self.assertTrue(diagnostic["parent_identity_verified"])
        self.assertTrue(diagnostic["second_parent_matches"])
        self.assertTrue(diagnostic["handle_closed"])
        self.assertEqual(tree.entries, {})
        self.assertEqual(tree.pending, [])
        self.assertEqual(api.waited, [])
        self.assertEqual(gui.owned_windows(tree, FakeWindows()), [])
        with mock.patch.object(api, "open", side_effect=self.access_denied()), self.assertRaises(PermissionError) as second:
            tree.refresh()
        self.assertEqual(api.query_opened, [20])
        self.assertEqual(gui.error_facts(second.exception)["query_only_diagnostic"]["status"], "not_repeated")

    def test_query_only_close_failure_retains_separate_owner_and_safe_stop_still_runs_before_retry(self):
        from ruleproxy import windows_runtime
        tree, api = self.tree()
        error = self.access_denied()
        with mock.patch.object(api, "open", side_effect=error), \
                mock.patch.object(api, "close", side_effect=self.access_denied()), self.assertRaises(PermissionError) as raised:
            tree.refresh()
        self.assertIs(raised.exception, error)
        self.assertEqual(tree.entries, {})
        self.assertEqual(tree.pending, [])
        self.assertEqual(len(tree.diagnostic_query_owners), 1)
        self.assertEqual(tree.diagnostic_query_owners[0].handle, 10001)
        self.assertFalse(gui.error_facts(error)["query_only_diagnostic"]["handle_closed"])
        owner = gui.GuiRun(None, None, None, None, None, None)
        owner.wrapper, owner.tree, owner.resources = tree.wrapper, tree, mock.Mock()
        resources = owner.resources
        with mock.patch.object(api, "close", side_effect=self.access_denied()), \
                mock.patch.object(windows_runtime, "stop") as stop, self.assertRaises(PermissionError):
            owner.close()
        stop.assert_called_once_with(tree.wrapper)
        self.assertFalse(owner.cleanup_proven)
        resources.close.assert_not_called()
        self.assertEqual(len(tree.diagnostic_query_owners), 1)
        self.assertEqual(api.waited, [])
        for value in api.info.values():
            value["alive"] = False
        api.parent_map = {10: 1}
        with mock.patch.object(windows_runtime, "stop"):
            owner.close()
        self.assertTrue(owner.cleanup_proven)
        self.assertEqual(tree.diagnostic_query_owners, [])
        self.assertEqual(api.closed, [10001])
        self.assertFalse(any(handle == 10001 for handle, _ in api.waited))

    def test_query_only_failure_preserves_original_win5_and_cannot_disclose_private_details(self):
        tree, api = self.tree()
        original = self.access_denied()
        with mock.patch.object(api, "open", side_effect=original), \
                mock.patch.object(api, "open_query", side_effect=self.access_denied()), self.assertRaises(PermissionError) as raised:
            tree.refresh()
        self.assertIs(raised.exception, original)
        facts = gui.error_facts(original)
        self.assertEqual(facts["stage"], "tree_child_open")
        self.assertEqual(facts["query_only_diagnostic"]["status"], "incomplete")
        self.assertEqual(facts["query_only_diagnostic"]["failure"]["stage"], "tree_diagnostic_query_open")
        self.assertNotIn("private", json.dumps(facts))
        self.assertEqual(tree.diagnostic_query_owners, [])

    def test_query_only_open_requests_neither_synchronize_nor_termination_rights(self):
        api = object.__new__(gui.ProcessApi)
        api.kernel = mock.Mock()
        api.kernel.OpenProcess.return_value = 1234
        self.assertEqual(api.open_query(20), 1234)
        api.kernel.OpenProcess.assert_called_once_with(0x1000, False, 20)

    def test_nested_query_diagnostic_errors_filter_private_text_and_invalid_numeric_properties(self):
        error = self.access_denied()
        error._gui_query_only_diagnostic = {"status": "incomplete", "opened": False,
            "failure": {"stage": "tree_diagnostic_query_open", "error_type": "C:\\Private\\secret.exe",
                        "errno": "private text", "winerror": True},
            "close_failure": {"stage": "tree_diagnostic_handle_close", "error_type": "PermissionError",
                              "errno": -1, "winerror": 2**32, "message": "private command"}}
        facts = gui.error_facts(error)["query_only_diagnostic"]
        self.assertEqual(facts["failure"], {"stage": "tree_diagnostic_query_open", "error_type": "Exception",
                                            "errno": None, "winerror": None})
        self.assertEqual(facts["close_failure"], {"stage": "tree_diagnostic_handle_close", "error_type": "PermissionError",
                                                  "errno": None, "winerror": None})
        self.assertNotIn("private", json.dumps(facts).lower())

    def test_failed_child_image_query_retains_pending_handle_and_separates_cleanup_failure(self):
        tree, api = self.tree()
        error = self.access_denied()
        with mock.patch.object(api, "image", side_effect=error), self.assertRaises(PermissionError) as raised:
            gui._diagnostic_call("tree_refresh", tree.refresh)
        self.assertIs(raised.exception, error)
        self.assertEqual(gui.error_facts(error)["stage"], "tree_child_image_query")
        self.assertEqual(tree.pending, [200])
        self.assertEqual(tree.entries, {})
        self.assertEqual(api.closed, [])
        owner = gui.GuiRun(None, None, None, None, None, None)
        owner.tree, owner.wrapper, owner.resources = tree, tree.wrapper, object()
        state = gui.owner_facts(owner)
        self.assertEqual(state["wrapper_creation_filetime"], 100)
        self.assertEqual(state["pending_query_handles"], 1)
        self.assertTrue(state["runtime_resources_retained"])
        with self.assertRaisesRegex(RuntimeError, "live process"):
            gui._diagnostic_call("tree_close_exited", tree.close_exited)
        self.assertEqual(tree.pending, [200])
        self.assertEqual(api.closed, [])

    def test_canonical_path_error_has_its_own_stage_and_does_not_publish_filename(self):
        error = self.access_denied()
        path = mock.Mock()
        path.resolve.side_effect = error
        with mock.patch.object(gui.os, "name", "nt"), mock.patch.object(gui, "Path", return_value=path), \
                self.assertRaises(PermissionError) as raised:
            gui.image_key("C:\\User Secret\\private.exe")
        path.resolve.assert_called_once_with(strict=True)
        self.assertIs(raised.exception, error)
        facts = gui.error_facts(error)
        self.assertEqual(facts["stage"], "image_path_canonicalize")
        self.assertNotIn("private", json.dumps(facts))
        self.assertNotIn("filename", facts)

    def test_window_visibility_and_close_errors_are_distinct_and_do_not_touch_foreign_window(self):
        for method, stage in (("visible_rect", "window_visibility_query"), ("post_close", "window_close_post")):
            with self.subTest(method=method):
                tree, api = self.tree()
                tree.refresh()
                windows = FakeWindows()
                selected = gui.owned_windows(tree, windows)[0]
                error = self.access_denied()
                with mock.patch.object(windows, method, side_effect=error), self.assertRaises(PermissionError):
                    gui.close_owned_window(tree, windows, selected)
                self.assertEqual(gui.error_facts(error)["stage"], stage)
                self.assertEqual(windows.posted, [])
                self.assertNotIn(99, api.opened)
                self.assertEqual(api.closed, [])

    def test_error_facts_reject_unregistered_stage_and_non_integer_codes(self):
        error = self.access_denied()
        error._gui_diagnostic_stage = ["private path"]
        error.errno, error.winerror = True, "5"
        self.assertEqual(gui.error_facts(error), {"stage": "unknown", "error_type": "PermissionError",
                                                 "errno": None, "winerror": None})
        with self.assertRaisesRegex(ValueError, "unregistered"):
            gui._diagnostic_call("private path", lambda: None)

    @unittest.skipIf(os.name == "nt", "Windows already exercises its real strict Path.resolve in every fake-lineage test")
    def test_windows_canonicalization_branch_requires_real_files_and_keeps_foreign_images_distinct(self):
        # Translate simulated absolute Win32 names to the real POSIX fixture
        # files. Keep the actual image_key guard and strict existence checks.
        with mock.patch.object(gui.os, "name", "nt"), \
                mock.patch.object(gui, "Path", side_effect=self.local_fixture_path):
            alias = self.edge.parent / ".." / "Application" / self.edge.name
            self.assertEqual(gui.image_key(self.edge), gui.image_key(alias))
            with self.assertRaises(FileNotFoundError):
                gui.image_key(self.edge.parent / "missing.exe")
            tree, api = self.tree()
            tree.refresh()
            self.assertIsNotNone(tree.edge_owner(30))
            api.info[300]["image"] = str(self.foreign_edge)
            self.assertIsNone(tree.edge_owner(30))

    def test_complete_lineage_holds_every_layer_and_excludes_foreign_windows(self):
        tree, api = self.tree()
        tree.refresh()
        self.assertEqual(set(tree.entries), {20, 30})
        self.assertEqual(tree.entries[30]["depth"], 2)
        self.assertEqual(api.opened, [20, 30])
        windows = FakeWindows()
        selected = gui.owned_windows(tree, windows)
        self.assertEqual([value["hwnd"] for value in selected], [800])
        self.assertNotIn(99, api.opened)
        gui.close_owned_window(tree, windows, selected[0])
        self.assertEqual(windows.posted, [800])

    def test_same_basename_at_another_path_cannot_authorize_a_window(self):
        tree, api = self.tree()
        api.info[300]["image"] = str(self.foreign_edge)
        tree.refresh()
        self.assertEqual(gui.owned_windows(tree, FakeWindows()), [])

    def test_startup_helper_must_match_the_held_direct_child_generation(self):
        tree, api = self.tree()
        tree.refresh()
        parent = {"pid": 20, "parent_pid": 10, "process_created": 110}
        tree.verify_startup_helper(parent)
        for value in (dict(parent, process_created=111), dict(parent, parent_pid=99),
                      dict(parent, pid=30), None):
            with self.assertRaisesRegex(RuntimeError, "held wrapper generation"):
                tree.verify_startup_helper(value)
        api.info[200]["alive"] = False
        with self.assertRaisesRegex(RuntimeError, "helper exited"):
            tree.verify_startup_helper(parent)

    def test_changed_child_parent_between_snapshots_fails_and_retains_query_handle(self):
        tree, api = self.tree()
        api.snapshots = [dict(api.parent_map), dict(api.parent_map)]
        api.snapshots[1][20] = 99
        with self.assertRaisesRegex(RuntimeError, "lineage changed"):
            tree.refresh()
        self.assertEqual(tree.pending, [200])
        with self.assertRaisesRegex(RuntimeError, "live process"):
            tree.close_exited()
        self.assertEqual(api.closed, [])

    def test_recycled_parent_pid_is_not_an_owned_generation(self):
        tree, api = self.tree()
        api.info[200]["created"] = 90
        tree.refresh()
        self.assertEqual(tree.entries, {})
        self.assertEqual(api.closed, [200])
        self.assertEqual(gui.owned_windows(tree, FakeWindows()), [])

    def test_child_created_after_held_parent_exit_fails_closed(self):
        tree, api = self.tree()
        api.info[100].update(alive=False, exited_at=105)
        with self.assertRaisesRegex(RuntimeError, "parent generation"):
            tree.refresh()
        self.assertEqual(tree.pending, [200])

    def test_wrapper_generation_or_opened_pid_mismatch_cannot_grant_window_ownership(self):
        tree, api = self.tree()
        api.info[100]["created"] = 101
        with self.assertRaisesRegex(RuntimeError, "generation changed"):
            tree.refresh()
        tree, api = self.tree()
        with mock.patch.object(api, "pid", side_effect=lambda handle: 21 if handle == 200 else 10):
            with self.assertRaisesRegex(RuntimeError, "PID did not match"):
                tree.refresh()
        self.assertEqual(tree.pending, [200])

    def test_handle_limit_is_checked_before_open_and_never_closes_a_live_owned_process(self):
        tree, api = self.tree()
        with mock.patch.object(gui, "MAX_HANDLES", 2):
            with self.assertRaisesRegex(RuntimeError, "handle limit"):
                tree.refresh()
        self.assertEqual(api.opened, [20])
        self.assertLessEqual(tree.peak_handles, 2)
        with self.assertRaises(RuntimeError):
            tree.close_exited()
        self.assertEqual(api.closed, [])

    def test_window_reuse_or_changed_generation_is_rejected_before_post(self):
        tree, api = self.tree()
        tree.refresh()
        windows = FakeWindows()
        selected = gui.owned_windows(tree, windows)[0]
        windows.pids[800] = 99
        with self.assertRaisesRegex(RuntimeError, "identity changed"):
            gui.close_owned_window(tree, windows, selected)
        self.assertEqual(windows.posted, [])
        windows.pids[800] = 30
        api.info[300]["created"] = 121
        with self.assertRaisesRegex(RuntimeError, "generation changed"):
            gui.close_owned_window(tree, windows, selected)
        self.assertEqual(windows.posted, [])

    def test_invisible_window_is_not_a_visible_gui_pass(self):
        tree, api = self.tree()
        tree.refresh()
        windows = FakeWindows()
        windows.rects[800] = None
        self.assertEqual(gui.owned_windows(tree, windows), [])

    def test_all_held_descendants_must_be_kernel_exited_before_handles_close(self):
        tree, api = self.tree()
        tree.refresh()
        api.info[100]["alive"] = api.info[200]["alive"] = False
        self.assertFalse(tree.all_exited())
        with self.assertRaises(RuntimeError):
            tree.close_exited()
        self.assertEqual(api.closed, [])
        api.info[300]["alive"] = False
        tree.close_exited()
        self.assertEqual(set(api.closed), {200, 300})
        self.assertNotIn(100, api.closed)  # The borrowed Popen HANDLE belongs to GuiRun.
        tree.close_exited()
        self.assertEqual(len(api.closed), 2)

    def test_delayed_kernel_signals_are_waited_with_one_shared_budget_before_close(self):
        tree, api = self.tree()
        tree.refresh()
        self.assertFalse(tree.all_exited())

        def delayed_signal(handle, milliseconds):
            api.waited.append((handle, milliseconds))
            self.assertEqual(api.closed, [])
            api.info[handle]["alive"] = False
            return True

        with mock.patch.object(api, "wait", side_effect=delayed_signal), \
                mock.patch.object(gui.time, "monotonic", side_effect=[0, 1, 2, 4]):
            tree.close_exited()
        self.assertEqual(api.waited, [(100, 4000), (200, 3000), (300, 1000)])
        self.assertTrue(tree.closed)
        self.assertEqual(api.closed, [200, 300])

    def test_tree_kernel_wait_timeout_preserves_all_handles_and_can_retry(self):
        tree, api = self.tree()
        tree.refresh()
        api.info[100]["alive"] = api.info[200]["alive"] = False
        with mock.patch.object(gui.time, "monotonic", side_effect=[0, 1, 2, 5]):
            with self.assertRaisesRegex(RuntimeError, "live process"):
                tree.close_exited()
        self.assertEqual(api.waited, [(100, 4000), (200, 3000), (300, 0)])
        self.assertFalse(tree.closed)
        self.assertEqual(set(tree.entries), {20, 30})
        self.assertEqual(api.closed, [])
        api.info[300]["alive"] = False
        tree.close_exited()
        self.assertTrue(tree.closed)
        self.assertEqual(api.closed, [200, 300])

    def test_child_open_context_only_exports_fixed_operation_and_bounded_numeric_facts(self):
        error = self.access_denied()
        error._gui_process_open_context = {"operation": "OpenProcess", "candidate_pid": "private",
            "parent_pid": True, "parent_creation_filetime": -1, "requested_access": 2**32,
            "image": "C:\\Private\\msedge.exe"}
        facts = gui.error_facts(error)
        self.assertEqual(facts, {"stage": "unknown", "error_type": "PermissionError", "errno": 13,
                                 "winerror": 5, "operation": "OpenProcess"})
        self.assertNotIn("private", json.dumps(facts).lower())

    def test_failed_tracking_can_report_held_visible_window_and_fixture_counts_without_opening_processes(self):
        tree, api = self.tree()
        tree.refresh()
        fixture = SimpleNamespace(lock=threading.Lock(), phase=1,
            pages={1: [False, True], 2: []}, acks={1: [True], 2: []})
        owner = SimpleNamespace(tree=tree, fixture=fixture)
        windows = FakeWindows()
        with mock.patch.object(api, "open", side_effect=AssertionError("no new process may be opened")), \
                mock.patch.object(windows, "visible_rect", wraps=windows.visible_rect) as geometry:
            facts = gui.failure_auxiliary(owner, windows=windows)
        self.assertEqual(facts["fixture"], {"status": "observed", "phase": 1,
            "page_request_count": 2, "dom_ack_count": 1, "counts_capped": False})
        self.assertEqual(facts["visible_owned_windows"], {"status": "observed",
            "held_browser_generation_count": 1, "visible_window_count": 1, "visible_window_observed": True})
        geometry.assert_called_once_with(800)
        self.assertEqual(windows.posted, [])
        self.assertNotIn("nonce", json.dumps(facts))
        self.assertNotIn("cookie", json.dumps(facts))
        self.assertNotIn("hwnd", json.dumps(facts))
        self.assertTrue(facts["diagnostic_only"])

    def test_failure_auxiliary_does_not_attribute_a_changed_held_generation_to_visible_edge(self):
        tree, api = self.tree()
        tree.refresh()
        api.info[300]["created"] = 121
        owner = SimpleNamespace(tree=tree, fixture=SimpleNamespace(lock=threading.Lock(), phase=2,
            pages={1: [], 2: [True]}, acks={1: [], 2: []}))
        windows = FakeWindows()
        with mock.patch.object(windows, "windows", wraps=windows.windows) as enumerate_windows:
            facts = gui.failure_auxiliary(owner, windows=windows)
        self.assertEqual(facts["visible_owned_windows"]["status"], "incomplete")
        self.assertEqual(facts["fixture"]["dom_ack_count"], 0)
        enumerate_windows.assert_not_called()
        self.assertEqual(windows.posted, [])

    def test_failure_auxiliary_reports_wrapper_and_only_signaled_held_browser_exit_codes(self):
        tree, api = self.tree()
        tree.refresh()
        api.info[300].update(alive=False, exit_code=0x101000)
        wrapper = mock.Mock()
        wrapper.poll.return_value = 0x101000
        fixture = SimpleNamespace(lock=threading.Lock(), phase=1,
            pages={1: [], 2: []}, acks={1: [], 2: []})
        owner = SimpleNamespace(tree=tree, wrapper=wrapper, fixture=fixture)
        with mock.patch.object(api, "open", side_effect=AssertionError("must not reopen PIDs")):
            facts = gui.failure_auxiliary(owner, windows=FakeWindows())
        self.assertEqual(facts["wrapper_exit"], {"status": "observed", "exit_code": 0x101000,
                                                  "exit_code_hex": "0x00101000"})
        self.assertEqual(facts["held_browser_exit_codes"], {"status": "observed", "count": 1,
                                                        "codes": ["0x00101000"]})
        self.assertEqual(api.closed, [])

    def test_failure_auxiliary_exit_query_errors_are_bounded_and_do_not_replace_failure(self):
        tree, api = self.tree()
        tree.refresh()
        api.info[300]["alive"] = False
        api.exit_code = mock.Mock(side_effect=OSError("private diagnostic detail"))
        wrapper = mock.Mock()
        wrapper.poll.side_effect = OSError("private poll detail")
        owner = SimpleNamespace(tree=tree, wrapper=wrapper, fixture=SimpleNamespace(
            lock=threading.Lock(), phase=1, pages={1: [], 2: []}, acks={1: [], 2: []}))
        facts = gui.failure_auxiliary(owner)
        self.assertEqual(facts["wrapper_exit"]["status"], "unknown")
        self.assertEqual(facts["held_browser_exit_codes"]["status"], "incomplete")
        rendered = json.dumps(facts)
        self.assertNotIn("private diagnostic detail", rendered)
        self.assertNotIn("private poll detail", rendered)

    def test_partial_handle_close_failure_preserves_remaining_handles(self):
        tree, api = self.tree()
        tree.refresh()
        for value in api.info.values():
            value["alive"] = False
        with mock.patch.object(api, "close", side_effect=[None, OSError("close failed")]):
            with self.assertRaises(OSError):
                tree.close_exited()
        self.assertFalse(tree.closed)
        self.assertEqual(set(tree.entries), {30})

    def test_safe_stop_failure_preserves_owner_and_resources(self):
        from ruleproxy import windows_runtime
        owner = gui.GuiRun(None, None, None, mock.Mock(), mock.Mock(), mock.Mock())
        owner.wrapper, owner.resources, owner.tree = mock.Mock(), mock.Mock(), mock.Mock()
        owner.tree.closed = False
        wrapper, resources, tree = owner.wrapper, owner.resources, owner.tree
        owner.cleanup_proven = False
        with mock.patch.object(windows_runtime, "stop", side_effect=RuntimeError("retain")):
            with self.assertRaises(RuntimeError) as raised:
                owner.close()
        self.assertEqual(gui.error_facts(raised.exception)["stage"], "runtime_safe_stop")
        self.assertIs(owner.wrapper, wrapper)
        self.assertIs(owner.resources, resources)
        tree.close_exited.assert_not_called()
        resources.close.assert_not_called()
        wrapper.kill.assert_not_called()
        wrapper.terminate.assert_not_called()

    def test_resource_close_retry_preserves_the_completed_tree_release(self):
        from ruleproxy import windows_runtime
        owner = gui.GuiRun(None, None, None, mock.Mock(), mock.Mock(), mock.Mock())
        owner.wrapper, owner.resources, owner.tree = mock.Mock(), mock.Mock(), mock.Mock()
        owner.tree.closed = False
        tree, resources = owner.tree, owner.resources
        tree.close_exited.side_effect = lambda: setattr(tree, "closed", True)
        resources.close.side_effect = [OSError("fixture still closing"), None]
        with mock.patch.object(windows_runtime, "stop"):
            with self.assertRaises(OSError):
                owner.close()
            owner.close()
        self.assertEqual(tree.refresh.call_count, 1)
        self.assertEqual(tree.close_exited.call_count, 1)
        self.assertEqual(resources.close.call_count, 2)
        self.assertIsNone(owner.wrapper)
        self.assertTrue(owner.cleanup_proven)

    def test_real_gui_run_uses_new_window_and_acks_before_owned_close(self):
        from ruleproxy import launcher, windows_runtime
        fixture, helpers = mock.Mock(), mock.Mock()
        helpers.startup_evidence.return_value = {"startup_checks_verified": True}
        browser = mock.Mock(HOST="ruleproxy-browser-fixture.invalid")
        wrapper, resources, tree, windows = mock.Mock(), mock.Mock(), mock.Mock(), mock.Mock()
        resources.bounded_guest_status.return_value = {"status": "observed", "state": "APP_EXITED", "app_exit": 0}
        wrapper.poll.side_effect = [None, 0]
        tree.entries, tree.peak_handles = {30: {}}, 4
        tree.unqueryable_candidates = set()
        tree.closed = False
        tree.all_exited.return_value = True
        value = {"hwnd": 800, "pid": 30, "created": 120, "rect": [0, 0, 600, 500]}
        with tempfile.TemporaryDirectory() as temporary, \
                mock.patch.object(launcher, "prepare_app", return_value=([str(self.edge)], {}, {})) as prepare, \
                mock.patch.object(windows_runtime, "choose_guest_port", return_value=34567), \
                mock.patch.object(windows_runtime, "launch", return_value=(wrapper, resources)) as runtime_launch, \
                mock.patch.object(windows_runtime, "stop") as stop, \
                mock.patch.object(gui, "ProcessApi"), mock.patch.object(gui, "OwnedTree", return_value=tree), \
                mock.patch.object(gui, "WindowApi", return_value=windows), \
                mock.patch.object(gui, "owned_windows", return_value=[value]), \
                mock.patch.object(gui, "close_owned_window") as close:
            run_job_api = FakeJobApi()
            run_job_api.active_values = [1, 2, 1]
            local_appdata = Path(temporary) / "local-appdata"
            local_appdata.mkdir()
            owner = gui.GuiRun("runtime", self.edge, Path(temporary), fixture, helpers, browser, gui.GuiJob(run_job_api),
                               application_kind="chrome_for_testing_control", enumerate_path=local_appdata,
                               ingress_default_allow_control=True)
            check = owner.run(2)
        args = prepare.call_args.args[0]["args"]
        self.assertIn("--new-window", args)
        self.assertFalse(any("headless" in arg or "sandbox" in arg for arg in args))
        self.assertEqual(close.call_count, 1)
        self.assertEqual(stop.call_count, 1)
        self.assertTrue(check["natural_helper_wrapper_exit"])
        self.assertTrue(check["private_profile_reused"])
        self.assertEqual(check["gui_budget_seconds"], 90)
        self.assertTrue(check["resources_closed"])
        self.assertEqual(check["source_policy_variant"], "private_network_and_localappdata_control")
        self.assertTrue(check["product_runtime_unchanged"])
        self.assertFalse(check["all_acceptance_passed"])
        self.assertFalse(check["capabilities_null"])
        self.assertTrue(check["private_network_capability_preserved"])
        self.assertTrue(runtime_launch.call_args.kwargs["ingress_default_allow_control"])
        self.assertEqual(runtime_launch.call_args.kwargs["enumerate_path"], local_appdata)
        fixture.check.assert_any_call(2)
        wrapper.kill.assert_not_called()

    def test_context_probe_attests_held_helper_before_release_and_cleanup(self):
        from ruleproxy import windows_runtime
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            fixture, helpers, browser, job = mock.Mock(), mock.Mock(), mock.Mock(), mock.Mock()
            job.active_processes.side_effect = [1, 2]
            fixture.port = 10809
            local_appdata = root / "local-appdata"
            local_appdata.mkdir()
            helpers.startup_evidence.return_value = {"startup_diagnostics": {"parent": {"pid": 20}}}
            wrapper, resources, tree = mock.Mock(), mock.Mock(), mock.Mock()
            resources.bounded_guest_status.return_value = {"status": "observed", "state": "APP_EXITED", "app_exit": 0}
            wrapper.wait.return_value = 0
            events = []
            launch_arguments = {}
            def launch(command, *_args, **_kwargs):
                launch_arguments.update(_kwargs)
                report = Path(command[command.index("--report") + 1])
                report.write_text(json.dumps({"schema": 1, "windows": True, "environment": {"localappdata_present": True}}))
                events.append("launch")
                return wrapper, resources
            def verify(_facts):
                self.assertFalse((root / "context/release").exists())
                events.append("attest")
            tree.verify_startup_helper.side_effect = verify
            def wait(*_args, **_kwargs):
                self.assertEqual((root / "context/release").read_bytes(), b"release\n")
                events.append("natural_exit")
                return 0
            wrapper.wait.side_effect = wait
            owner = gui.GuiRun("runtime", self.edge, root, fixture, helpers, browser, job,
                               application_kind="chrome_for_testing_control", enumerate_path=local_appdata,
                               ingress_default_allow_control=True)
            with mock.patch.object(windows_runtime, "launch", side_effect=launch), \
                    mock.patch.object(windows_runtime, "choose_guest_port", return_value=34567), \
                    mock.patch.object(gui, "ProcessApi"), mock.patch.object(gui, "OwnedTree", return_value=tree), \
                    mock.patch.object(owner, "close", side_effect=lambda: events.append("cleanup")):
                facts = owner.collect_context()
            self.assertEqual(events, ["launch", "attest", "natural_exit", "cleanup"])
            self.assertTrue(facts["descendant_cleanup_proven"])
            self.assertFalse(facts["acceptance_passed"])
            self.assertEqual(facts["guest_status"]["app_exit"], 0)
            self.assertEqual(launch_arguments["enumerate_path"], local_appdata)
            self.assertTrue(launch_arguments["ingress_default_allow_control"])
            self.assertEqual(facts["source_policy_variant"], "private_network_and_localappdata_control")
            self.assertTrue(facts["product_runtime_unchanged"])
            self.assertFalse(facts["all_acceptance_passed"])
            self.assertFalse(facts["capabilities_null"])
            self.assertTrue(facts["private_network_capability_preserved"])

    def test_context_report_rejects_strings_duplicates_and_oversize(self):
        with tempfile.TemporaryDirectory() as temporary:
            path = Path(temporary) / "context.json"
            for raw in ('{"schema":1,"windows":true,"path":"private"}',
                        '{"schema":1,"schema":1,"windows":true}',
                        '{"schema":true,"windows":true}', 'x' * 8193):
                path.write_text(raw)
                with self.subTest(raw=raw[:32]), self.assertRaises((ValueError, RuntimeError)):
                    gui.read_context_report(path)

    def test_summary_never_promotes_http_gui_to_full_public_network_or_real_node(self):
        result = gui.initial_result()
        for key in ("gui_fixture_passed", "acceptance_passed", "full_acceptance_passed", "real_node_passed",
                    "public_udp_proven", "system_dns_proven"):
            self.assertIs(result[key], False)

    def test_main_cleanup_failure_retains_actual_owner_and_does_not_delete_profile(self):
        from ruleproxy import windows_runtime
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            profile = root / "retained"
            profile.mkdir()
            report = root / "reports/gui.json"
            helpers = mock.Mock()
            helpers.host_facts.return_value = {"windows_product_type": 1, "native_machine": 0x8664,
                                               "python_pe_machine": 0x8664}
            helpers.executable_machine.return_value = 0x8664
            helpers.network_snapshot.return_value = {"fixed": True}
            helpers.verify_runtime_manifest.return_value = {}
            helpers.write_json.side_effect = lambda path, value: path.write_text(json.dumps(value))
            browser = mock.Mock()
            browser.acceptance_helpers.return_value = helpers
            browser.find_edge.return_value = self.edge
            owner = mock.Mock()
            error = TimeoutError("GUI budget expired")
            error._gui_diagnostic_stage = "wrapper_poll"
            owner.run.side_effect = error
            owner.close.side_effect = RuntimeError("owned process remains alive")
            owner.wrapper = mock.Mock(pid=10)
            owner.resources = mock.Mock()
            owner.tree = mock.Mock(entries={}, pending=[200], root_created=100)
            retained_count = len(gui._RECOVERY_OWNERS)
            try:
                with mock.patch.object(gui.sys, "platform", "win32"), \
                        mock.patch.object(gui, "browser_helpers", return_value=browser), \
                        mock.patch.object(gui, "interactive_facts", return_value={"ordinary_interactive": True}), \
                        mock.patch.object(windows_runtime, "probe", return_value={"supported": True}), \
                        mock.patch.object(gui.tempfile, "mkdtemp", return_value=str(profile)), \
                        mock.patch.object(gui, "GuiRun", return_value=owner), \
                        mock.patch.object(gui, "GuiJob", return_value=gui.GuiJob(FakeJobApi())), \
                        mock.patch.object(gui.shutil, "rmtree") as remove, mock.patch("builtins.print"):
                    self.assertEqual(gui.main(["--root", str(root), "--report", str(report)]), 1)
                value = json.loads(report.read_text())
                self.assertEqual(value["status"], "failed")
                self.assertIs(value["cleanup_proven"], False)
                self.assertEqual(value["recovery_directory"], str(profile))
                self.assertFalse(value["gui_fixture_passed"])
                self.assertEqual(value["failure"], {"stage": "wrapper_poll", "error_type": "TimeoutError",
                                                    "errno": None, "winerror": None})
                self.assertEqual(value["failure_auxiliary"]["wrapper_exit"]["status"], "unknown")
                self.assertEqual(value["failure_auxiliary"]["held_browser_exit_codes"]["status"], "incomplete")
                self.assertEqual(value["cleanup_failure"]["stage"], "owner_cleanup")
                self.assertEqual(value["cleanup_failure"]["error_type"], "RuntimeError")
                self.assertEqual(value["failure_owner_state"]["pending_query_handles"], 1)
                self.assertTrue(value["cleanup_owner_state"]["wrapper_handle_retained"])
                self.assertTrue(value["cleanup_owner_state"]["runtime_resources_retained"])
                self.assertIs(gui._RECOVERY_OWNERS[-1], owner)
                owner.run.assert_called_once_with(1)
                remove.assert_not_called()
            finally:
                del gui._RECOVERY_OWNERS[retained_count:]

    @unittest.skipUnless(os.name == "nt", "actual Windows ABI only; outside ordinary PSEC evidence")
    def test_windows_read_only_window_and_held_process_api_smoke(self):
        # This checks real exports/ctypes and owned generations on any Windows
        # runner. It never posts WM_CLOSE or claims an interactive PSEC result.
        from ruleproxy import windows_runtime
        process = subprocess.Popen([sys.executable, "-I", "-S", "-c", "import time; time.sleep(2)"])
        api, tree = gui.ProcessApi(), None
        try:
            query = api.open_query(process.pid)
            try:
                self.assertEqual(api.pid(query), process.pid)
                self.assertGreater(api.created(query), 0)
                self.assertTrue(api.image(query))
            finally:
                api.close(query)  # QUERY-only is never passed to a wait API.
            tree = gui.OwnedTree(api, process, Path(sys.executable).resolve())
            self.assertEqual(api.pid(tree.root_handle), process.pid)
            self.assertGreater(tree.root_created, 0)
            tree.refresh()
            windows = gui.WindowApi()
            values = windows.windows()
            self.assertLessEqual(len(values), 1024)
            self.assertTrue(all(type(hwnd) is int and hwnd > 0 and type(pid) is int and pid > 0
                                for hwnd, pid in values))
            # Query geometry only for our own test process's windows, if any.
            for hwnd, pid in values:
                if pid == process.pid:
                    rect = windows.visible_rect(hwnd)
                    if rect is not None:
                        self.assertGreater(rect[2] - rect[0], 0)
            self.assertEqual(process.wait(timeout=5), 0)
            self.assertEqual(api.exit_code(process._handle), 0)
            tree.refresh()
            self.assertTrue(tree.all_exited())
            tree.close_exited()
        finally:
            if process.poll() is None:
                process.kill()  # Only this ABI test's owned Popen HANDLE, never an MXC wrapper.
                process.wait(timeout=5)
            if tree is not None and not tree.closed:
                tree.close_exited()
            process._handle.Close()


if __name__ == "__main__":
    unittest.main()
