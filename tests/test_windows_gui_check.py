"""Verify owned GUI identity and cleanup contracts without claiming PSEC success."""
import importlib.util
import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest
from unittest import mock


ROOT = Path(__file__).resolve().parent.parent
spec = importlib.util.spec_from_file_location("windows_gui_check", ROOT / ".github/windows_gui_check.py")
gui = importlib.util.module_from_spec(spec)
spec.loader.exec_module(gui)
EDGE = r"C:\Program Files\Microsoft\Edge\Application\msedge.exe"


class FakeProcessApi:
    def __init__(self):
        self.info = {100: {"pid": 10, "created": 100, "alive": True, "image": r"C:\bin\wxc-exec.exe"},
                     200: {"pid": 20, "created": 110, "alive": True, "image": r"C:\pkg\python.exe"},
                     300: {"pid": 30, "created": 120, "alive": True, "image": EDGE}}
        self.parent_map = {10: 1, 20: 10, 30: 20, 99: 1}
        self.snapshots = []
        self.opened, self.closed = [], []

    def pid(self, handle):
        return self.info[handle]["pid"]

    def created(self, handle):
        return self.info[handle]["created"]

    def exited_at(self, handle):
        return self.info[handle].get("exited_at", 150)

    def alive(self, handle):
        return self.info[handle]["alive"]

    def image(self, handle):
        return self.info[handle]["image"]

    def snapshot(self):
        return self.snapshots.pop(0) if self.snapshots else dict(self.parent_map)

    def open(self, pid):
        self.opened.append(pid)
        return next(handle for handle, value in self.info.items() if value["pid"] == pid)

    def close(self, handle):
        self.closed.append(handle)


class FakeWindows:
    def __init__(self):
        self.values = [(700, 99), (800, 30)]
        self.pids = {700: 99, 800: 30}
        self.rects = {700: [0, 0, 500, 400], 800: [10, 20, 650, 500]}
        self.posted = []

    def windows(self):
        return self.values

    def pid(self, hwnd):
        return self.pids.get(hwnd)

    def visible_rect(self, hwnd):
        return self.rects.get(hwnd)

    def post_close(self, hwnd):
        self.posted.append(hwnd)


class GuiCheckTests(unittest.TestCase):
    def tree(self):
        api = FakeProcessApi()
        wrapper = mock.Mock(pid=10, _handle=100)
        return gui.OwnedTree(api, wrapper, EDGE), api

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
        api.info[300]["image"] = r"C:\foreign\msedge.exe"
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
            with self.assertRaises(RuntimeError):
                owner.close()
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
        wrapper.poll.side_effect = [None, 0]
        tree.entries, tree.peak_handles = {30: {}}, 4
        tree.closed = False
        tree.all_exited.return_value = True
        value = {"hwnd": 800, "pid": 30, "created": 120, "rect": [0, 0, 600, 500]}
        with tempfile.TemporaryDirectory() as temporary, \
                mock.patch.object(launcher, "prepare_app", return_value=([EDGE], {}, {})) as prepare, \
                mock.patch.object(windows_runtime, "choose_guest_port", return_value=34567), \
                mock.patch.object(windows_runtime, "launch", return_value=(wrapper, resources)), \
                mock.patch.object(windows_runtime, "stop") as stop, \
                mock.patch.object(gui, "ProcessApi"), mock.patch.object(gui, "OwnedTree", return_value=tree), \
                mock.patch.object(gui, "WindowApi", return_value=windows), \
                mock.patch.object(gui, "owned_windows", return_value=[value]), \
                mock.patch.object(gui, "close_owned_window") as close:
            owner = gui.GuiRun("runtime", EDGE, Path(temporary), fixture, helpers, browser)
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
        fixture.check.assert_any_call(2)
        wrapper.kill.assert_not_called()

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
            browser.find_edge.return_value = Path(EDGE)
            owner = mock.Mock()
            owner.run.side_effect = RuntimeError("GUI unavailable")
            owner.close.side_effect = RuntimeError("owned process remains alive")
            retained_count = len(gui._RECOVERY_OWNERS)
            try:
                with mock.patch.object(gui.sys, "platform", "win32"), \
                        mock.patch.object(gui, "browser_helpers", return_value=browser), \
                        mock.patch.object(gui, "interactive_facts", return_value={"ordinary_interactive": True}), \
                        mock.patch.object(windows_runtime, "probe", return_value={"supported": True}), \
                        mock.patch.object(gui.tempfile, "mkdtemp", return_value=str(profile)), \
                        mock.patch.object(gui, "GuiRun", return_value=owner), \
                        mock.patch.object(gui.shutil, "rmtree") as remove, mock.patch("builtins.print"):
                    self.assertEqual(gui.main(["--root", str(root), "--report", str(report)]), 1)
                value = json.loads(report.read_text())
                self.assertEqual(value["status"], "failed")
                self.assertIs(value["cleanup_proven"], False)
                self.assertEqual(value["recovery_directory"], str(profile))
                self.assertFalse(value["gui_fixture_passed"])
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
