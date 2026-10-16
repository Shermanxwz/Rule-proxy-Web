"""Original-profile selection must be explicit, bounded and non-mutating."""
import os
from pathlib import Path
import socket
import subprocess
import sys
import tempfile
import unittest
from unittest.mock import patch

from ruleproxy import app_profile_data as profiles


@unittest.skipUnless(sys.platform.startswith('linux'), 'Linux original profile discovery')
class OriginalProfileTests(unittest.TestCase):
    def setUp(self):
        temporary = tempfile.TemporaryDirectory(prefix='ruleproxy-original-profile-')
        self.addCleanup(temporary.cleanup)
        self.home = Path(temporary.name) / 'home'
        self.home.mkdir()
        home = patch.object(profiles.Path, 'home', return_value=self.home)
        home.start()
        self.addCleanup(home.stop)
        variables = {key: value for key, value in os.environ.items()
                     if key not in ('XDG_CONFIG_HOME', 'CHROME_CONFIG_HOME', 'CHROME_USER_DATA_DIR')}
        environment = patch.dict(os.environ, variables, clear=True)
        environment.start()
        self.addCleanup(environment.stop)

    def app(self, name='chrome', adapter='chromium'):
        return {'path': '/opt/browser/' + name, 'adapter': adapter}

    def chromium(self, relative='google-chrome', *, base=None, electron=False):
        root = (base if base is not None else self.home / '.config') / relative
        root.mkdir(parents=True)
        (root / 'Local State').write_text('{}', encoding='utf-8')
        preferences = root / 'Preferences' if electron else root / 'Default/Preferences'
        preferences.parent.mkdir(parents=True, exist_ok=True)
        preferences.write_text('{}', encoding='utf-8')
        (preferences.parent / 'Cookies').write_bytes(b'synthetic cookies; never real user data')
        return root

    def firefox(self, name='one.default', *, default=True):
        base = self.home / '.mozilla/firefox'
        root = base / name
        root.mkdir(parents=True)
        (root / 'prefs.js').write_text('user_pref("example.synthetic", true);\n', encoding='utf-8')
        (base / 'profiles.ini').write_text(
            '[Profile0]\nName=Test\nIsRelative=1\nPath=' + name + '\nDefault=' + str(int(default)) + '\n',
            encoding='utf-8')
        return root

    def test_common_browser_channels_choose_the_existing_native_root(self):
        cases = [('chrome', 'google-chrome'), ('google-chrome-beta', 'google-chrome-beta'),
                 ('google-chrome-unstable', 'google-chrome-unstable'), ('chromium', 'chromium'),
                 ('msedge', 'microsoft-edge'), ('microsoft-edge-dev', 'microsoft-edge-dev'),
                 ('brave', 'BraveSoftware/Brave-Browser'),
                 ('brave-browser-nightly', 'BraveSoftware/Brave-Browser-Nightly')]
        for name, folder in cases:
            with self.subTest(name=name):
                source = self.chromium(folder)
                self.assertEqual(profiles.original_profile_source(self.app(name)), source)

    def test_xdg_chrome_config_and_user_data_overrides_have_the_documented_precedence(self):
        xdg, chrome = self.home / 'xdg', self.home / 'chrome-config'
        first = self.chromium(base=xdg)
        second = self.chromium(base=chrome)
        third = self.chromium('custom-root', base=self.home)
        with patch.dict(os.environ, {'XDG_CONFIG_HOME': str(xdg)}):
            self.assertEqual(profiles.original_profile_source(self.app()), first)
            with patch.dict(os.environ, {'CHROME_CONFIG_HOME': str(chrome)}):
                self.assertEqual(profiles.original_profile_source(self.app()), second)
                with patch.dict(os.environ, {'CHROME_USER_DATA_DIR': str(third)}):
                    self.assertEqual(profiles.original_profile_source(self.app()), third)

    def test_relative_override_symlink_root_and_home_root_are_refused(self):
        source = self.chromium()
        link = self.home / 'linked-profile'
        link.symlink_to(source, target_is_directory=True)
        for value in ('relative-profile', str(link), str(self.home)):
            with self.subTest(value=value), patch.dict(os.environ, {'CHROME_USER_DATA_DIR': value}), self.assertRaises(ValueError):
                profiles.original_profile_source(self.app())

    def test_symlink_metadata_or_profile_parent_is_not_read(self):
        source = self.chromium()
        original = source / 'Default/Preferences'
        original.unlink()
        original.symlink_to(source / 'Local State')
        with self.assertRaisesRegex(ValueError, '符号链接|索引损坏'):
            profiles.original_profile_source(self.app())

    def test_missing_unknown_empty_or_corrupt_original_data_never_creates_a_profile(self):
        with self.assertRaises(ValueError):
            profiles.original_profile_source(self.app())
        self.assertFalse((self.home / '.config').exists())
        source = self.chromium()
        for content in ('not json', '[]', ' ' * (profiles.MAX_METADATA_BYTES + 1)):
            with self.subTest(content=content[:10]):
                (source / 'Local State').write_text(content, encoding='utf-8')
                with self.assertRaises(ValueError):
                    profiles.original_profile_source(self.app())
        with self.assertRaisesRegex(ValueError, '尚不能可靠识别'):
            profiles.original_profile_source(self.app('unknown-electron'))
        with self.assertRaisesRegex(ValueError, '不支持'):
            profiles.original_profile_source(self.app('editor', 'environment'))

    def test_wrong_profile_owner_is_refused(self):
        self.chromium()
        with patch.object(profiles.os, 'getuid', return_value=os.getuid() + 1), self.assertRaisesRegex(ValueError, '属于当前'):
            profiles.original_profile_source(self.app())

    def test_chromium_active_foreign_and_unknown_locks_are_refused_without_removal(self):
        source = self.chromium()
        lock = source / 'SingletonLock'
        for target in (socket.gethostname() + '-' + str(os.getpid()), 'foreign-host-123', 'not-a-pid'):
            with self.subTest(target=target):
                lock.symlink_to(target)
                with self.assertRaisesRegex(ValueError, '关闭原应用'):
                    profiles.original_profile_source(self.app())
                self.assertEqual(os.readlink(lock), target)
                lock.unlink()
        lock.write_text('unknown lock', encoding='ascii')
        with self.assertRaises(ValueError):
            profiles.original_profile_source(self.app())
        self.assertEqual(lock.read_text(), 'unknown lock')

    def test_a_proven_stale_chromium_lock_is_refused_without_deleting_or_changing_it(self):
        source = self.chromium()
        lock = source / 'SingletonLock'
        target = socket.gethostname() + '-12345'
        lock.symlink_to(target)
        with patch.object(profiles.os, 'kill', side_effect=ProcessLookupError):
            with self.assertRaisesRegex(ValueError, '正常退出原应用以释放旧锁'):
                profiles.original_profile_source(self.app())
        self.assertEqual(os.readlink(lock), target)

    def test_known_electron_roots_need_persistent_markers_and_never_use_chrome_overrides(self):
        source = self.chromium('discord', electron=True)
        with patch.dict(os.environ, {'CHROME_USER_DATA_DIR': str(self.home / 'wrong')}):
            self.assertEqual(profiles.original_profile_source(self.app('Discord')), source)
        self.chromium('ChatGPT', electron=True)
        self.chromium('chatgpt', electron=True)
        with self.assertRaisesRegex(ValueError, '唯一'):
            profiles.original_profile_source(self.app('chatgpt'))

    def test_firefox_install_default_takes_precedence_over_legacy_profile_default(self):
        old = self.firefox()
        selected = old.parent / 'actual.default-release'
        selected.mkdir()
        (selected / 'prefs.js').write_text('user_pref("example.other", true);\n', encoding='utf-8')
        (old.parent / 'installs.ini').write_text('[InstallHash]\nDefault=actual.default-release\nLocked=1\n', encoding='utf-8')
        self.assertEqual(profiles.original_profile_source(self.app('firefox', 'firefox')), selected)

    def test_firefox_conflicting_install_defaults_and_escaped_paths_are_refused(self):
        source = self.firefox()
        (source.parent / 'installs.ini').write_text('[First]\nDefault=one.default\n[Second]\nDefault=two.default\n', encoding='utf-8')
        with self.assertRaisesRegex(ValueError, '多个'):
            profiles.original_profile_source(self.app('firefox', 'firefox'))
        (source.parent / 'installs.ini').unlink()
        (source.parent / 'profiles.ini').write_text('[Profile0]\nPath=../other\nIsRelative=1\nDefault=1\n', encoding='utf-8')
        with self.assertRaisesRegex(ValueError, '上级目录'):
            profiles.original_profile_source(self.app('firefox', 'firefox'))

    def test_firefox_xdg_profile_root_is_supported_without_guessing_between_two_roots(self):
        configured = self.home / 'xdg-config'
        base = configured / 'mozilla/firefox'
        source = base / 'new.default-release'
        source.mkdir(parents=True)
        (source / 'prefs.js').write_text('user_pref("synthetic.xdg", true);\n', encoding='utf-8')
        (base / 'profiles.ini').write_text('[Profile0]\nIsRelative=1\nPath=new.default-release\nDefault=1\n', encoding='utf-8')
        with patch.dict(os.environ, {'XDG_CONFIG_HOME': str(configured)}):
            self.assertEqual(profiles.original_profile_source(self.app('firefox', 'firefox')), source)
            self.firefox()
            with self.assertRaisesRegex(ValueError, '多个可能的资料根目录'):
                profiles.original_profile_source(self.app('firefox', 'firefox'))

    def test_firefox_stale_regular_parent_locks_are_accepted_without_modification(self):
        source = self.firefox()
        for name in ('.parentlock', 'parent.lock'):
            (source / name).write_bytes(b'synthetic stale metadata')
        before = {path.name: path.read_bytes() for path in source.iterdir()}
        self.assertEqual(profiles.original_profile_source(self.app('firefox', 'firefox')), source)
        self.assertEqual({path.name: path.read_bytes() for path in source.iterdir()}, before)

    def test_firefox_actual_os_lock_from_another_process_is_refused(self):
        source = self.firefox()
        lock = source / '.parentlock'
        lock.write_bytes(b'')
        code = 'import fcntl,sys,time; f=open(sys.argv[1],"r+"); fcntl.lockf(f,fcntl.LOCK_EX); print("ready",flush=True); time.sleep(15)'
        child = subprocess.Popen([sys.executable, '-I', '-S', '-c', code, str(lock)], stdout=subprocess.PIPE, text=True)
        try:
            self.assertEqual(child.stdout.readline().strip(), 'ready')
            with self.assertRaisesRegex(ValueError, '仍在使用'):
                profiles.original_profile_source(self.app('firefox', 'firefox'))
        finally:
            child.terminate()
            child.wait(timeout=5)
            child.stdout.close()


if __name__ == '__main__':
    unittest.main()
