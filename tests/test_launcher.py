import os
import stat
import sys
import tempfile
import unittest
from pathlib import Path
from unittest import mock

from ruleproxy import launcher


class LauncherTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        self.executable = self.root / "browser"
        self.executable.write_text("", encoding="utf-8")
        self.executable.chmod(self.executable.stat().st_mode | stat.S_IXUSR)

    def app_for(self, adapter="chromium", **extra):
        return {
            "id": "saved-app-1",
            "label": "Browser",
            "path": str(self.executable),
            "adapter": adapter,
            **extra,
        }

    def test_validate_normalizes_and_preserves_argument_list(self):
        result = launcher.validate_app(
            self.app_for(args=["--new-window", "https://example.test"])
        )
        self.assertEqual(
            result,
            {
                "label": "Browser",
                "path": str(self.executable.resolve()),
                "adapter": "chromium",
                "args": ["--new-window", "https://example.test"],
            },
        )

    def test_validate_rejects_invalid_selection(self):
        invalid_selections = [
            self.app_for(path="/definitely/missing/executable"),
            self.app_for(adapter="unknown"),
            self.app_for(args="--flag"),
            self.app_for(args=["bad\0arg"]),
            self.app_for(args=["x" * 4097]),
            self.app_for(args=["x"] * 65),
        ]
        for selection in invalid_selections:
            with self.subTest(selection=selection):
                with self.assertRaises(ValueError):
                    launcher.validate_app(selection)

    def test_original_data_mode_requires_a_boolean_and_preserves_explicit_choice(self):
        for value in (None, 0, 1, 'true', '', [], {}):
            with self.subTest(value=value), self.assertRaisesRegex(ValueError, '布尔值'):
                launcher.validate_app(self.app_for(use_original_data=value))
        for value in (True, False):
            with self.subTest(value=value):
                normalized = launcher.validate_app(self.app_for(use_original_data=value))
                self.assertIs(normalized['use_original_data'], value)
        self.assertNotIn('use_original_data', launcher.validate_app(self.app_for()))
        with self.assertRaisesRegex(ValueError, '不支持切换'):
            launcher.validate_app(self.app_for('environment', use_original_data=True))
        self.assertIs(launcher.validate_app(self.app_for('environment', use_original_data=False))['use_original_data'], False)

    def test_original_data_directory_selects_real_linux_profile_and_keeps_private_mode(self):
        base = self.root / 'profiles'
        source = self.root / 'actual-original-data'
        with mock.patch('ruleproxy.app_profile_data.original_profile_source', return_value=source) as resolve:
            for platform in ('linux', 'win32'):
                with mock.patch.object(launcher.sys, 'platform', platform):
                    for mode in (False, True):
                        with self.subTest(platform=platform, mode=mode):
                            app = self.app_for(use_original_data=mode)
                            expected = source if mode and platform == 'linux' else base / app['id']
                            self.assertEqual(launcher.app_profile_directory(base, app), expected)
            resolve.assert_called_once()
        self.assertFalse(base.exists(), 'selecting a directory must not create it')
        with self.assertRaisesRegex(ValueError, '应用 ID 无效'):
            launcher.app_profile_directory(base, self.app_for(id='../outside', use_original_data=True))

    def test_windows_original_data_uses_native_browser_selection_without_writes(self):
        proxy_vars = {name: 'http://unrelated:1' for name in (
            'HTTP_PROXY', 'HTTPS_PROXY', 'ALL_PROXY', 'NO_PROXY', 'FTP_PROXY',
            'http_proxy', 'https_proxy', 'all_proxy', 'no_proxy', 'ftp_proxy')}
        source = self.root / 'original-app-data'
        source.mkdir()
        original = source / 'user.js'
        original.write_text('keep original preferences', encoding='utf-8')
        for adapter in ('chromium', 'firefox'):
            base = self.root / ('not-created-' + adapter)
            with self.subTest(adapter=adapter), mock.patch.object(launcher.sys, 'platform', 'win32'), \
                    mock.patch.dict(os.environ, {**proxy_vars, 'APPDATA': str(source), 'LOCALAPPDATA': str(source)}):
                command, environment, detail = launcher.prepare_app(
                    self.app_for(adapter, args=['https://example.test'], use_original_data=True),
                    8899, base, transparent=True)
                self.assertEqual(command, [str(self.executable.resolve()), 'https://example.test'])
                self.assertEqual(environment['APPDATA'], str(source))
                self.assertEqual(environment['LOCALAPPDATA'], str(source))
                for name in proxy_vars:
                    self.assertNotIn(name, environment)
                self.assertIn('原有数据', detail)
                self.assertFalse(base.exists(), 'native mode must not create a private profile')
        self.assertEqual(original.read_text(encoding='utf-8'), 'keep original preferences')
        self.assertEqual(list(source.iterdir()), [original])

    def test_windows_original_data_leaves_existing_private_firefox_preferences_intact(self):
        base = self.root / 'profiles'
        private = base / 'saved-app-1'
        private.mkdir(parents=True)
        user_js = private / 'user.js'
        user_js.write_text('private preferences must survive mode switching', encoding='utf-8')
        with mock.patch.object(launcher.sys, 'platform', 'win32'):
            launcher.prepare_app(self.app_for('firefox', use_original_data=True), 8899, base, transparent=True)
        self.assertEqual(user_js.read_text(encoding='utf-8'), 'private preferences must survive mode switching')

    def test_windows_explicit_private_mode_preserves_browser_profile_flags(self):
        for adapter in ('chromium', 'firefox'):
            with self.subTest(adapter=adapter), mock.patch.object(launcher.sys, 'platform', 'win32'):
                command, _env, _detail = launcher.prepare_app(
                    self.app_for(adapter, use_original_data=False), 8899, self.root / 'profiles', transparent=True)
            profile = self.root / 'profiles' / 'saved-app-1'
            if adapter == 'chromium':
                self.assertIn(f'--user-data-dir={profile}', command)
            else:
                self.assertEqual(command[-3:], ['-no-remote', '-profile', str(profile)])
                self.assertEqual((profile / 'user.js').read_text(), 'user_pref("network.proxy.type", 0);\n')

    def test_linux_original_mode_rejects_unresolved_profile_without_creating_new_data(self):
        base = self.root / 'profiles'
        app = self.app_for(use_original_data=True)
        with mock.patch.object(launcher.sys, 'platform', 'linux'), \
                mock.patch('ruleproxy.app_profile_data.original_profile_source',
                           side_effect=ValueError('无法确定原应用数据目录')) as resolve:
            with self.assertRaisesRegex(ValueError, '无法确定'):
                launcher.prepare_app(app, 8899, base)
        resolve.assert_called_once_with(app)
        self.assertFalse(base.exists())

    def test_linux_original_mode_uses_real_profile_without_writing_source_preferences(self):
        normal = self.root / 'profiles/saved-app-1'
        normal.mkdir(parents=True)
        private_prefs = normal / 'user.js'
        private_prefs.write_text('private mode stays intact', encoding='utf-8')
        source = self.root / 'original-profile'
        source.mkdir()
        source_prefs = source / 'user.js'
        source_prefs.write_text('original proxy and browser settings', encoding='utf-8')
        (source / 'prefs.js').write_text('original saved preferences', encoding='utf-8')
        before = {path.name: path.read_bytes() for path in source.iterdir()}
        for adapter in ('chromium', 'firefox'):
            app = self.app_for(adapter, use_original_data=True)
            with self.subTest(adapter=adapter), mock.patch.object(launcher.sys, 'platform', 'linux'), \
                    mock.patch('ruleproxy.app_profile_data.original_profile_source', return_value=source) as resolve:
                command, environment, _detail = launcher.prepare_app(app, 8899, self.root / 'profiles')
                resolve.assert_called_once_with(app)
                self.assertEqual(environment['HTTP_PROXY'], 'http://127.0.0.1:8899')
                if adapter == 'chromium':
                    self.assertIn(f'--user-data-dir={source}', command)
                    self.assertIn('--proxy-server=http://127.0.0.1:8899', command)
                    self.assertIn('--force-webrtc-ip-handling-policy=disable_non_proxied_udp', command)
                else:
                    self.assertEqual(command[-3:], ['-no-remote', '-profile', str(source)])
        self.assertEqual({path.name: path.read_bytes() for path in source.iterdir()}, before)
        self.assertEqual(private_prefs.read_text(encoding='utf-8'), 'private mode stays intact')
        self.assertFalse((self.root / 'profiles-inherited').exists())

    @unittest.skipUnless(sys.platform.startswith('linux'), 'native Linux profile discovery')
    def test_linux_chromium_original_profile_discovery_and_command_use_same_real_directory(self):
        browser = self.root / 'google-chrome'
        browser.write_bytes(b'')
        browser.chmod(0o755)
        home = self.root / 'desktop-home'
        source = home / '.config/google-chrome'
        (source / 'Default').mkdir(parents=True)
        (source / 'Local State').write_text('{}')
        (source / 'Default/Preferences').write_text('{}')
        (source / 'Default/Bookmarks').write_bytes(b'original bookmarks')
        before = {path.relative_to(source): path.read_bytes() for path in source.rglob('*') if path.is_file()}
        app = self.app_for(path=str(browser), use_original_data=True)
        with mock.patch.object(Path, 'home', return_value=home), mock.patch.dict(os.environ, {
                'CHROME_USER_DATA_DIR': '', 'CHROME_CONFIG_HOME': '', 'XDG_CONFIG_HOME': str(home / '.config')}):
            selected = launcher.app_profile_directory(self.root / 'profiles', app)
            command, _environment, _detail = launcher.prepare_app(app, 8899, self.root / 'profiles')
        self.assertEqual(selected, source)
        self.assertIn(f'--user-data-dir={source}', command)
        self.assertEqual({path.relative_to(source): path.read_bytes() for path in source.rglob('*') if path.is_file()}, before)
        self.assertFalse((self.root / 'profiles').exists())

    @unittest.skipUnless(sys.platform.startswith('linux'), 'native Linux profile discovery')
    def test_linux_firefox_original_profile_is_selected_without_changing_its_proxy_preferences(self):
        browser = self.root / 'firefox'
        browser.write_bytes(b'')
        browser.chmod(0o755)
        home = self.root / 'desktop-home'
        firefox = home / '.mozilla/firefox'
        source = firefox / 'original.default'
        source.mkdir(parents=True)
        (firefox / 'profiles.ini').write_text('[Profile0]\nPath=original.default\nIsRelative=1\nDefault=1\n')
        (source / 'prefs.js').write_text('user_pref("network.proxy.type", 0);\n')
        (source / 'user.js').write_text('user_pref("browser.startup.page", 1);\n')
        before = {path.name: path.read_bytes() for path in source.iterdir()}
        app = self.app_for('firefox', path=str(browser), use_original_data=True)
        with mock.patch.object(Path, 'home', return_value=home):
            command, _environment, _detail = launcher.prepare_app(app, 8899, self.root / 'profiles')
        self.assertEqual(command[-3:], ['-no-remote', '-profile', str(source)])
        self.assertEqual({path.name: path.read_bytes() for path in source.iterdir()}, before)
        self.assertFalse((self.root / 'profiles').exists())

    def test_original_data_does_not_allow_profile_or_proxy_override_arguments(self):
        for adapter, args in (('chromium', ['--user-data-dir=somewhere']),
                              ('chromium', ['--proxy-server=direct://']),
                              ('firefox', ['-profile', 'somewhere']),
                              ('firefox', ['-no-remote'])):
            with self.subTest(adapter=adapter, args=args), mock.patch.object(launcher.sys, 'platform', 'win32'), \
                    self.assertRaises(ValueError):
                launcher.prepare_app(self.app_for(adapter, args=args, use_original_data=True),
                                     8899, self.root / 'profiles', transparent=True)

    def test_transparent_launch_has_no_native_proxy_configuration(self):
        with mock.patch.dict(os.environ, {"HTTP_PROXY": "http://unrelated:1", "all_proxy": "socks5://unrelated:2"}):
            command, env, _ = launcher.prepare_app(self.app_for(), 8899, self.root / "profiles", transparent=True)
        self.assertFalse(any(arg.startswith("--proxy") for arg in command))
        self.assertNotIn("--disable-quic", command)
        self.assertNotIn("HTTP_PROXY", env)
        self.assertNotIn("all_proxy", env)
        self.assertTrue(any(arg.startswith("--user-data-dir=") for arg in command))

    def test_transparent_firefox_clears_legacy_profile_proxy_mode(self):
        app = self.app_for("firefox")
        launcher.prepare_app(app, 8899, self.root / "profiles")
        profile = self.root / "profiles" / app["id"]
        self.assertIn('network.proxy.type", 1', (profile / "user.js").read_text())
        command, env, _ = launcher.prepare_app(app, 8899, self.root / "profiles", transparent=True)
        self.assertEqual((profile / "user.js").read_text(), 'user_pref("network.proxy.type", 0);\n')
        self.assertIn("-no-remote", command)

    def test_related_paths_are_validated_deduplicated_and_not_launched(self):
        helper = self.root / "helper"
        helper.write_text("")
        normalized = launcher.validate_app(self.app_for(related_paths=[str(helper), str(helper)]))
        self.assertEqual(normalized["related_paths"], [str(helper.resolve())])
        with self.assertRaises(ValueError):
            launcher.validate_app(self.app_for(related_paths=["relative-helper"]))

    def test_prepare_chromium_uses_profile_proxy_and_webrtc_restrictions(self):
        command, env, detail = launcher.prepare_app(
            self.app_for(args=["https://example.test"]), 8899, self.root / "profiles"
        )
        self.assertEqual(command[0], str(self.executable.resolve()))
        self.assertEqual(command[1], "https://example.test")
        self.assertIn(f"--user-data-dir={self.root / 'profiles' / 'saved-app-1'}", command)
        self.assertIn("--proxy-server=http://127.0.0.1:8899", command)
        self.assertIn("--proxy-bypass-list=<-loopback>", command)
        self.assertIn("--disable-quic", command)
        self.assertIn("--disable-background-networking", command)
        self.assertIn("--restore-last-session", command)
        # Chromium warns about --host-resolver-rules as an unsupported switch.
        # Name resolution is enforced by the isolation boundary instead.
        self.assertFalse(
            any(arg.startswith("--host-resolver-rules") for arg in command), command
        )
        self.assertIn(
            "--force-webrtc-ip-handling-policy=disable_non_proxied_udp", command
        )
        self.assertEqual(env["HTTP_PROXY"], "http://127.0.0.1:8899")
        self.assertEqual(env.get("DISPLAY"), os.environ.get("DISPLAY"))
        self.assertIn("blocks direct egress", detail)
        self.assertFalse(hasattr(launcher, "launch_app"))

    def test_prepare_rejects_user_proxy_profile_or_subprocess_switches(self):
        for args in (
            ["--proxy-server=direct://"],
            ["--user-data-dir=C:\\other"],
            ["--renderer-cmd-prefix=cmd.exe"],
            ["--"],
        ):
            with self.subTest(args=args), self.assertRaises(ValueError):
                launcher.prepare_app(self.app_for(args=args), 8899, self.root / "profiles")
        with self.assertRaises(ValueError):
            launcher.prepare_app(
                self.app_for("firefox", args=["-profile", "C:\\other"]),
                8899,
                self.root / "profiles",
            )

    def test_prepare_firefox_uses_socks_remote_dns_and_disables_prefetch(self):
        command, env, _ = launcher.prepare_app(
            self.app_for("firefox"), 7777, self.root / "profiles"
        )
        profile = self.root / "profiles" / "saved-app-1"
        prefs = (profile / "user.js").read_text(encoding="utf-8")
        self.assertIn('user_pref("network.proxy.socks_version", 5);', prefs)
        self.assertIn('user_pref("network.proxy.socks_remote_dns", true);', prefs)
        self.assertIn('user_pref("network.proxy.socks5_remote_dns", true);', prefs)
        self.assertIn('user_pref("network.proxy.allow_hijacking_localhost", true);', prefs)
        self.assertIn('user_pref("network.dns.disablePrefetch", true);', prefs)
        self.assertIn('user_pref("network.prefetch-next", false);', prefs)
        self.assertIn("-no-remote", command)
        self.assertEqual(command[-2:], ["-profile", str(profile)])
        self.assertEqual(env["HTTP_PROXY"], "http://127.0.0.1:7777")

    def test_prepare_environment_adapter_sets_child_only_proxy_variables(self):
        before = os.environ.get("HTTP_PROXY")
        command, env, detail = launcher.prepare_app(
            self.app_for("environment"), 8888, self.root / "profiles"
        )
        self.assertEqual(command, [str(self.executable.resolve())])
        self.assertEqual(env["HTTP_PROXY"], "http://127.0.0.1:8888")
        self.assertEqual(env["HTTPS_PROXY"], env["HTTP_PROXY"])
        self.assertEqual(env["ALL_PROXY"], env["HTTP_PROXY"])
        self.assertEqual(env["http_proxy"], env["HTTP_PROXY"])
        self.assertEqual(env["NO_PROXY"], "")
        self.assertEqual(os.environ.get("HTTP_PROXY"), before)
        self.assertIn("fail to connect", detail)

    def test_environment_adapter_rejects_shell_executables(self):
        shell = self.root / "powershell.exe"
        shell.write_text("", encoding="utf-8")
        shell.chmod(shell.stat().st_mode | stat.S_IXUSR)
        selection = self.app_for("environment", path=str(shell))
        with self.assertRaisesRegex(ValueError, "命令行解释器"):
            launcher.prepare_app(selection, 8888, self.root / "profiles")

    def test_prepare_rejects_unsafe_profile_identifier_and_port(self):
        with self.assertRaisesRegex(ValueError, "应用 ID 无效"):
            launcher.prepare_app(self.app_for(id="../other"), 8000, self.root)
        with self.assertRaisesRegex(ValueError, "proxy_port"):
            launcher.prepare_app(self.app_for(), 0, self.root)

    def test_discover_apps_uses_path_lookup_without_executing(self):
        firefox = self.root / "firefox"
        firefox.write_text("", encoding="utf-8")
        firefox.chmod(firefox.stat().st_mode | stat.S_IXUSR)
        with mock.patch.object(launcher.sys, "platform", "linux"), mock.patch.object(
            launcher.shutil, "which", side_effect=lambda name: str(firefox) if name == "firefox" else None
        ):
            found = launcher.discover_apps()
        entry = next(app for app in found if app["path"] == str(firefox.resolve()))
        self.assertEqual(entry["label"], "Mozilla Firefox")
        self.assertEqual(entry["adapter"], "firefox")
        self.assertEqual(entry["args"], [])
        self.assertEqual(entry["category"], "browser")
        self.assertIn("fails closed", entry["compatibility"])

    @unittest.skipUnless(sys.platform.startswith("linux"), "desktop entries are Linux-only")
    def test_discovery_skips_locations_it_cannot_read(self):
        share = self.root / "share" / "applications"
        share.mkdir(parents=True)
        tool = self.root / "tool"
        tool.write_bytes(b"\x7fELF")
        tool.chmod(0o755)
        locked = self.root / "unreadable" / "locked"
        locked.parent.mkdir()
        locked.write_bytes(b"\x7fELF")
        locked.chmod(0o755)
        (share / "tool.desktop").write_text(f"[Desktop Entry]\nType=Application\nName=Readable Tool\nExec={tool}\n", encoding="utf-8")
        (share / "locked.desktop").write_text(f"[Desktop Entry]\nType=Application\nName=Locked Tool\nExec={locked}\n", encoding="utf-8")

        def denied(real):
            # Root ignores file modes, so simulate the PermissionError a normal user gets.
            def check(path, *args, **kwargs):
                if "unreadable" in str(path):
                    raise PermissionError(13, "Permission denied", str(path))
                return real(path, *args, **kwargs)
            return check

        environment = {"XDG_DATA_HOME": str(self.root / "share"), "XDG_DATA_DIRS": f"{self.root / 'unreadable' / 'share'}:/nonexistent"}
        with mock.patch.dict(os.environ, environment), mock.patch.object(Path, "is_dir", denied(Path.is_dir)), mock.patch.object(Path, "is_file", denied(Path.is_file)):
            found = launcher.discover_apps(refresh=True)
        labels = [app["label"] for app in found]
        self.assertIn("Readable Tool", labels)
        self.assertNotIn("Locked Tool", labels)


if __name__ == "__main__":
    unittest.main()
