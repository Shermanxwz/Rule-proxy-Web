"""Shared browser profile: validation, live-browser and stored-secret guards, and sandbox binds."""
import json
import os
from pathlib import Path
import socket
import sqlite3
import subprocess
import sys
import tempfile
import time
import unittest
from unittest.mock import Mock, patch

from ruleproxy.launcher import check_shared_profile, prepare_app, shared_data_dir, validate_shared_data_dir
from ruleproxy.manager import Manager


LINUX = sys.platform.startswith("linux")


def write_cookie_db(path: Path, blobs, *, table="cookies", column="encrypted_value"):
    path.parent.mkdir(parents=True, exist_ok=True)
    path.unlink(missing_ok=True)
    connection = sqlite3.connect(path)
    connection.execute(f"CREATE TABLE {table} (name TEXT, {column} BLOB)")
    for index, blob in enumerate(blobs):
        connection.execute(f"INSERT INTO {table} VALUES (?, ?)", (f"c{index}", blob))
    connection.commit()
    connection.close()


class Sandbox(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.root = Path(self.temp.name).resolve()
        self.home = self.root / "home"
        self.home.mkdir()
        self.state = self.root / "state"
        self.state.mkdir()
        self.env = patch.dict(os.environ, {"HOME": str(self.home)})
        self.env.start()

    def tearDown(self):
        self.env.stop()
        self.temp.cleanup()

    def executable(self, name="chrome"):
        path = self.root / "bin" / name
        path.parent.mkdir(exist_ok=True)
        path.write_text("#!/bin/sh\nexit 0\n")
        path.chmod(0o755)
        return str(path)


@unittest.skipUnless(LINUX, "shared profiles are Linux-only")
class SharedDirectoryValidationTests(Sandbox):
    def test_accepts_a_browser_profile_inside_home(self):
        chrome = self.home / ".config" / "google-chrome"
        chrome.mkdir(parents=True)
        self.assertEqual(validate_shared_data_dir(str(chrome), self.state, "chromium"), chrome.resolve())

    def test_accepts_a_user_owned_directory_outside_home(self):
        elsewhere = self.root / "elsewhere"
        elsewhere.mkdir()
        self.assertEqual(validate_shared_data_dir(str(elsewhere), self.state, "chromium"), elsewhere.resolve())

    def test_refuses_home_its_parents_and_the_panel_state(self):
        refused = [self.home, self.root, self.state, self.state / "profiles" / "app-1"]
        for path in refused:
            with self.subTest(path=str(path)), self.assertRaises(ValueError):
                validate_shared_data_dir(str(path), self.state, "chromium")

    def test_refuses_missing_files_relative_paths_and_other_adapters(self):
        file_path = self.root / "file.txt"
        file_path.write_text("x")
        cases = [
            (str(self.root / "missing"), "chromium"),
            (str(file_path), "chromium"),
            ("relative/profile", "chromium"),
            ("", "chromium"),
            (str(self.home / "profile"), "firefox"),
            (str(self.home / "profile"), "environment"),
        ]
        (self.home / "profile").mkdir()
        for value, adapter in cases:
            with self.subTest(value=value, adapter=adapter), self.assertRaises(ValueError):
                validate_shared_data_dir(value, self.state, adapter)

    def test_refuses_on_non_linux_platforms(self):
        with patch("ruleproxy.launcher.sys.platform", "win32"), self.assertRaises(ValueError):
            validate_shared_data_dir(str(self.home), self.state, "chromium")

    def test_apps_without_a_shared_directory_use_their_own_profile(self):
        self.assertIsNone(shared_data_dir({"id": "a", "adapter": "chromium"}, self.state / "profiles"))


@unittest.skipUnless(LINUX, "Chromium profile locks are Linux-only here")
class SharedProfileGuardTests(Sandbox):
    def make_lock(self, profile: Path, owner: str, socket_target: str | None):
        profile.mkdir(parents=True, exist_ok=True)
        (profile / "SingletonLock").symlink_to(owner)
        if socket_target is not None:
            (profile / "SingletonSocket").symlink_to(socket_target)

    def test_a_profile_without_lock_is_free(self):
        profile = self.home / "free"
        profile.mkdir()
        check_shared_profile(profile)

    def test_a_live_browser_answering_on_its_socket_blocks_sharing(self):
        profile = self.home / "live"
        socket_path = self.root / "live-singleton"
        listener = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        self.addCleanup(listener.close)
        listener.bind(str(socket_path))
        listener.listen(1)
        self.make_lock(profile, f"{socket.gethostname()}-4321", str(socket_path))
        with self.assertRaisesRegex(ValueError, "正被普通浏览器使用"):
            check_shared_profile(profile)

    def test_a_stale_lock_from_a_stopped_browser_is_allowed(self):
        profile = self.home / "stale"
        exited = subprocess.Popen([sys.executable, "-c", "pass"])
        exited.wait()  # this pid no longer belongs to any process
        self.make_lock(profile, f"{socket.gethostname()}-{exited.pid}", str(self.root / "gone" / "SingletonSocket"))
        check_shared_profile(profile)

    def test_a_lock_held_by_another_machine_blocks_sharing(self):
        profile = self.home / "remote"
        self.make_lock(profile, "otherhost-77", str(self.root / "gone" / "SingletonSocket"))
        with self.assertRaises(ValueError):
            check_shared_profile(profile)

    def test_a_lock_without_a_socket_fails_closed(self):
        profile = self.home / "unclear"
        self.make_lock(profile, f"{socket.gethostname()}-5", None)
        with self.assertRaises(ValueError):
            check_shared_profile(profile)

    def test_a_hidden_socket_of_a_live_browser_fails_closed(self):
        profile = self.home / "hidden"
        self.make_lock(profile, f"{socket.gethostname()}-{os.getpid()}", str(self.root / "gone" / "SingletonSocket"))
        with self.assertRaisesRegex(ValueError, "正被普通浏览器使用"):
            check_shared_profile(profile)

    def test_a_refused_socket_of_a_live_browser_fails_closed(self):
        profile = self.home / "refused"
        socket_path = self.root / "refused-singleton"
        bound = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        self.addCleanup(bound.close)
        bound.bind(str(socket_path))  # bound but never listening: connections are refused
        self.make_lock(profile, f"{socket.gethostname()}-{os.getpid()}", str(socket_path))
        with self.assertRaisesRegex(ValueError, "正被普通浏览器使用"):
            check_shared_profile(profile)

    def test_only_v10_cookies_are_allowed(self):
        profile = self.home / "v10"
        write_cookie_db(profile / "Default" / "Cookies", [b"v10abc", b""])
        check_shared_profile(profile)
        write_cookie_db(profile / "Default" / "Cookies", [b"v10abc", b"v11keyring"])
        with self.assertRaisesRegex(ValueError, "v11"):
            check_shared_profile(profile)

    def test_nested_network_and_electron_partition_cookies_are_checked(self):
        profile = self.home / "nested"
        write_cookie_db(profile / "Partitions" / "app" / "Network" / "Cookies", [b"v11keyring"])
        with self.assertRaisesRegex(ValueError, "v11"):
            check_shared_profile(profile)

    def test_v11_passwords_refuse_sharing(self):
        profile = self.home / "logins"
        write_cookie_db(profile / "Default" / "Login Data", [b"v11secret"], table="logins", column="password_value")
        with self.assertRaisesRegex(ValueError, "v11"):
            check_shared_profile(profile)

    def test_an_unreadable_database_fails_closed(self):
        profile = self.home / "corrupt"
        (profile / "Default").mkdir(parents=True)
        (profile / "Default" / "Cookies").write_bytes(b"not a sqlite database at all" * 40)
        with self.assertRaises(ValueError):
            check_shared_profile(profile)

    def test_prepare_app_shares_the_profile_without_restoring_the_session(self):
        chrome = self.home / ".config" / "google-chrome"
        chrome.mkdir(parents=True)
        app = {"id": "shared-1", "label": "Chrome", "path": self.executable(), "adapter": "chromium", "args": [], "data_dir": str(chrome.resolve())}
        command, _env, detail = prepare_app(app, 10809, self.state / "profiles")
        self.assertIn(f"--user-data-dir={chrome.resolve()}", command)
        self.assertNotIn("--restore-last-session", command)
        self.assertIn("共用配置目录", detail)
        self.assertTrue((self.state / "profiles" / "shared-1").is_dir())
        self.assertFalse((chrome / "SingletonLock").exists())

    def test_prepare_app_keeps_the_private_profile_and_restore_flag_by_default(self):
        app = {"id": "private-1", "label": "Chrome", "path": self.executable(), "adapter": "chromium", "args": []}
        command, _env, _detail = prepare_app(app, 10809, self.state / "profiles")
        self.assertIn(f"--user-data-dir={self.state / 'profiles' / 'private-1'}", command)
        self.assertIn("--restore-last-session", command)

    def test_prepare_app_refuses_a_profile_the_sandbox_would_damage(self):
        chrome = self.home / "keyring-profile"
        write_cookie_db(chrome / "Default" / "Cookies", [b"v11keyring"])
        app = {"id": "keyring-1", "label": "Chrome", "path": self.executable(), "adapter": "chromium", "args": [], "data_dir": str(chrome.resolve())}
        with self.assertRaisesRegex(ValueError, "v11"):
            prepare_app(app, 10809, self.state / "profiles")


@unittest.skipUnless(LINUX, "Linux sandbox")
class ManagerSharedProfileTests(Sandbox):
    def setUp(self):
        super().setUp()
        self.manager = Manager(self.state, 18879)
        self.manager._probe_cache = {"supported": True, "backend": "test", "detail": "ok", "limitations": []}

    def tearDown(self):
        # Mocked core and app handles are not OS processes; drop them before closing.
        self.manager.core = None
        self.manager.active.clear()
        self.manager.close()
        super().tearDown()

    def add(self, label="Chrome"):
        self.manager.add_app({"label": label, "path": self.executable(f"{label}-{len(self.manager.settings['apps'])}"), "adapter": "chromium"})
        return self.manager.settings["apps"][-1]["id"]

    def test_sharing_needs_explicit_acknowledgement(self):
        ident = self.add()
        profile = self.home / "chrome"
        profile.mkdir()
        with self.assertRaisesRegex(ValueError, "确认风险"):
            self.manager.set_app_data_dir(ident, str(profile))
        self.assertNotIn("data_dir", self.manager.app(ident))
        self.manager.set_app_data_dir(ident, str(profile), acknowledged=True)
        self.assertEqual(self.manager.app(ident)["data_dir"], str(profile.resolve()))

    def test_restoring_the_private_profile_removes_the_shared_directory(self):
        ident = self.add()
        profile = self.home / "chrome"
        profile.mkdir()
        self.manager.set_app_data_dir(ident, str(profile), acknowledged=True)
        self.manager.set_app_data_dir(ident, "")
        self.assertNotIn("data_dir", self.manager.app(ident))

    def test_two_apps_cannot_share_one_directory(self):
        first, second = self.add("Chrome"), self.add("Brave")
        profile = self.home / "chrome"
        profile.mkdir()
        self.manager.set_app_data_dir(first, str(profile), acknowledged=True)
        with self.assertRaisesRegex(ValueError, "已经使用"):
            self.manager.set_app_data_dir(second, str(profile), acknowledged=True)

    def test_launch_refuses_while_another_instance_holds_the_directory(self):
        first, second = self.add("Chrome"), self.add("Brave")
        profile = self.home / "chrome"
        profile.mkdir()
        self.manager.set_app_data_dir(first, str(profile), acknowledged=True)
        self.manager.app(second)["data_dir"] = str(profile.resolve())  # bypass the save-time check
        self.manager.core = Mock()
        self.manager.core.poll.return_value = None
        self.manager.active[first] = (Mock(poll=Mock(return_value=None)), Mock())
        with self.assertRaisesRegex(ValueError, "已被另一个隔离实例使用"):
            self.manager.launch(second)

    def test_cannot_change_the_directory_while_the_app_runs(self):
        ident = self.add()
        profile = self.home / "chrome"
        profile.mkdir()
        self.manager.active[ident] = (Mock(poll=Mock(return_value=None)), Mock())
        with self.assertRaisesRegex(ValueError, "请先关闭"):
            self.manager.set_app_data_dir(ident, str(profile), acknowledged=True)

    def test_refused_directory_is_not_saved(self):
        ident = self.add()
        profile = self.home / "chrome"
        write_cookie_db(profile / "Default" / "Cookies", [b"v11keyring"])
        with self.assertRaisesRegex(ValueError, "v11"):
            self.manager.set_app_data_dir(ident, str(profile), acknowledged=True)
        self.assertNotIn("data_dir", self.manager.app(ident))


@unittest.skipUnless(LINUX, "Linux sandbox")
class LiveSharedProfileTests(Sandbox):
    def test_shared_directory_is_the_only_user_data_the_sandbox_gets(self):
        from ruleproxy.linux_runtime import launch, probe, stop

        if not probe()["supported"]:
            self.skipTest("user/network namespaces unavailable")
        shared = self.home / "shared-profile"
        shared.mkdir()
        profile = self.state / "profiles" / "live-1"
        profile.mkdir(parents=True)
        code = (
            "from pathlib import Path\n"
            "import time\n"
            f"Path({str(shared / 'marker.txt')!r}).write_text('shared')\n"
            f"Path({str(shared / 'settings-visible.txt')!r}).write_text(str(Path({str(self.state / 'settings.json')!r}).exists()))\n"
            "print('ready', flush=True)\n"
            "time.sleep(30)\n"
        )
        (self.state / "settings.json").write_text("{}")
        command = [sys.executable, "-c", code]
        env = {k: v for k, v in os.environ.items() if k not in {"DISPLAY", "WAYLAND_DISPLAY"}}
        process, resource = launch(command, env, profile, 10809, shared)
        try:
            deadline = time.monotonic() + 10
            while time.monotonic() < deadline and "ready" not in ((profile / "runtime.log").read_text() if (profile / "runtime.log").exists() else ""):
                time.sleep(0.05)
            self.assertEqual((shared / "marker.txt").read_text(), "shared")
            self.assertEqual((shared / "settings-visible.txt").read_text(), "False")
            self.assertTrue((profile / "runtime.log").exists())
            self.assertFalse((shared / "runtime.log").exists())
        finally:
            stop(process)
            resource.close()


if __name__ == "__main__":
    unittest.main()
