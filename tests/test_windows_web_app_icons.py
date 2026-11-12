"""Selected-profile PWA icon copies; no browser, device, network or shell runs."""
import base64
from copy import deepcopy
import hashlib
import os
from pathlib import Path
import struct
import tempfile
import unittest
from unittest.mock import Mock, patch
import zlib

from ruleproxy import shortcuts, windows_web_app_icons as icons


APP_ID = 'gdfaincndogidkdcdkhapmbffkckdkhn'


def png_ico():
    def chunk(kind, data):
        return struct.pack('>I', len(data)) + kind + data + struct.pack('>I', zlib.crc32(kind + data) & 0xffffffff)
    image = b'\x89PNG\r\n\x1a\n'
    image += chunk(b'IHDR', struct.pack('>IIBBBBB', 1, 1, 8, 6, 0, 0, 0))
    image += chunk(b'IDAT', zlib.compress(b'\0\x20\x40\x80\xff')) + chunk(b'IEND', b'')
    return struct.pack('<HHHBBBBHHII', 0, 1, 1, 1, 1, 0, 0, 1, 32, len(image), 22) + image


def dib_ico():
    image = struct.pack('<IiiHHIIiiII', 40, 1, 2, 1, 32, 0, 4, 0, 0, 0, 0)
    image += b'\x20\x40\x80\xff' + b'\0' * 4
    return struct.pack('<HHHBBBBHHII', 0, 1, 1, 1, 1, 0, 0, 1, 32, len(image), 22) + image


class IconTests(unittest.TestCase):
    def setUp(self):
        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        self.root = Path(temporary.name)
        self.local = self.root / 'Local'
        self.executable = self.root / 'Program Files/Google/Chrome/Application/chrome.exe'
        self.executable.parent.mkdir(parents=True)
        self.executable.write_bytes(b'MZ fixture, never executed')
        self.profile = self.local / 'Google/Chrome/User Data/Profile 1'
        self.directory = self.profile / 'Web Applications' / ('_crx_' + APP_ID)
        self.directory.mkdir(parents=True)
        self.source = self.directory / 'Gemini.ico'
        self.data = png_ico()
        self.source.write_bytes(self.data)
        (self.directory / 'Gemini.ico.md5').write_bytes(b'x' * 16)
        self.state = self.root / 'state'
        self.state.mkdir()
        self.app = {'id': 'saved-123', 'label': 'Gemini', 'path': str(self.executable), 'args': [],
                    'web_app': {'browser': 'chrome', 'profile_directory': 'Profile 1', 'app_id': APP_ID,
                                'start_url': 'https://gemini.google.com/app', 'launch_mode': 'isolated_url'}}
        environment = patch.dict(os.environ, {'LOCALAPPDATA': str(self.local)})
        environment.start()
        self.addCleanup(environment.stop)

    def resolve(self, app=None):
        return icons.shortcut_icon(self.app if app is None else app, self.state)

    def link(self, target, path, *, directory=False):
        try:
            path.symlink_to(target, target_is_directory=directory)
        except OSError as error:
            self.skipTest('Symlink fixture unavailable: ' + str(error))

    def test_unique_installed_icon_is_copied_without_changing_source_or_settings(self):
        original, modified = deepcopy(self.app), self.source.stat().st_mtime_ns
        cached = self.resolve()
        expected = self.state / 'shortcut-icons/saved-123' / (hashlib.sha256(self.data).hexdigest() + '.ico')
        self.assertEqual(cached, expected)
        self.assertEqual(cached.read_bytes(), self.data)
        self.assertEqual(self.source.read_bytes(), self.data)
        self.assertEqual(self.source.stat().st_mtime_ns, modified)
        self.assertEqual(self.app, original)

    def test_same_content_reuses_cache_without_overwriting(self):
        first = self.resolve()
        before = first.stat()
        self.assertEqual(self.resolve(), first)
        after = first.stat()
        self.assertEqual((before.st_ino, before.st_mtime_ns), (after.st_ino, after.st_mtime_ns))
        self.assertEqual(list(first.parent.iterdir()), [first])

    def test_changed_source_uses_another_content_hash_and_keeps_old_cache(self):
        first = self.resolve()
        self.source.write_bytes(dib_ico())
        second = self.resolve()
        self.assertNotEqual(first, second)
        self.assertEqual(first.read_bytes(), self.data)
        self.assertEqual(second.read_bytes(), dib_ico())

    def test_missing_and_ambiguous_icons_use_no_cache(self):
        self.source.unlink()
        self.assertIsNone(self.resolve())
        self.source.write_bytes(self.data)
        (self.directory / 'other.ico').write_bytes(self.data)
        self.assertIsNone(self.resolve())
        self.assertFalse((self.state / 'shortcut-icons').exists())

    def test_only_selected_profile_browser_and_app_id_are_consulted(self):
        for change in ({'profile_directory': 'Default'}, {'app_id': 'a' * 32}, {'browser': 'edge'}):
            app = deepcopy(self.app)
            app['web_app'].update(change)
            with self.subTest(change=change):
                self.assertIsNone(self.resolve(app))
        self.assertFalse((self.state / 'shortcut-icons').exists())

    def test_matching_browser_channels_use_their_own_current_owner_profile(self):
        for browser, product, executable in (('edge', 'Microsoft/Edge Beta', 'msedge.exe'),
                                              ('brave', 'BraveSoftware/Brave-Browser', 'brave.exe')):
            with self.subTest(browser=browser):
                path = self.root / 'Program Files' / product / 'Application' / executable
                path.parent.mkdir(parents=True)
                path.write_bytes(b'MZ fixture')
                folder = self.local / product / 'User Data/Profile 1/Web Applications' / ('_crx_' + APP_ID)
                folder.mkdir(parents=True)
                (folder / 'App.ico').write_bytes(self.data)
                app = deepcopy(self.app)
                app['path'], app['web_app']['browser'] = str(path), browser
                self.assertEqual(self.resolve(app).read_bytes(), self.data)

    def test_paths_schema_and_url_only_apps_fall_back_without_writing(self):
        for field, value in (('profile_directory', '../Default'), ('app_id', '../escape'),
                             ('app_id', ''), ('browser', 'unknown'), ('icon_path', '/outside.ico')):
            app = deepcopy(self.app)
            app['web_app'][field] = value
            with self.subTest(field=field, value=value):
                self.assertIsNone(self.resolve(app))
        for value in ('../chrome.exe', '//server/Google/Chrome/chrome.exe', '\\\\server\\chrome.exe', None, {}):
            app = deepcopy(self.app)
            app['path'] = value
            with self.subTest(path=value):
                self.assertIsNone(self.resolve(app))
        for value in ('../escape', 'CON', 'NUL.txt', 'saved.', 'x/y', ''):
            app = {**self.app, 'id': value}
            with self.subTest(saved_id=value):
                self.assertIsNone(self.resolve(app))
        self.assertFalse((self.state / 'shortcut-icons').exists())

    def test_no_browser_database_network_or_shortcut_execution_is_used(self):
        for name in ('Cookies', 'History', 'Login Data', 'Preferences', 'Secure Preferences'):
            (self.profile / name).write_bytes(b'not read')
        original = icons._MetadataDirectory.file
        opened = []
        def observe(directory, name, maximum):
            opened.append((directory.path, name))
            return original(directory, name, maximum)
        with patch.object(icons._MetadataDirectory, 'file', observe), \
                patch('subprocess.Popen', side_effect=AssertionError('No execution')), \
                patch('http.client.HTTPConnection', side_effect=AssertionError('No network')):
            cached = self.resolve()
        self.assertEqual(opened, [(self.directory, 'Gemini.ico'), (cached.parent, cached.name)])

    def test_ico_bounds_crc_and_frame_corruption_fall_back(self):
        bad = [b'not ico', self.data[:-1]]
        for offset, value in ((2, 2), (4, 0), (4, 65), (9, 1), (18, 0xff)):
            value_bytes = bytearray(self.data)
            value_bytes[offset] = value
            bad.append(bytes(value_bytes))
        corrupt_crc = bytearray(self.data)
        corrupt_crc[-1] ^= 1
        bad.append(bytes(corrupt_crc))
        bad.append(self.data[:6] + struct.pack('<BBBBHHII', 1, 1, 0, 0, 1, 32, 0xffffffff, 22) + self.data[22:])
        dib = bytearray(dib_ico())
        struct.pack_into('<i', dib, 22 + 8, 3)
        bad.append(bytes(dib))
        for data in bad:
            with self.subTest(digest=hashlib.sha256(data).hexdigest()):
                self.source.write_bytes(data)
                self.assertIsNone(self.resolve())
        self.assertFalse((self.state / 'shortcut-icons').exists())

    def test_overlapping_ico_images_are_not_accepted(self):
        frame = self.data[22:]
        entry = struct.pack('<BBBBHHII', 1, 1, 0, 0, 1, 32, len(frame), 38)
        self.assertFalse(icons._valid_ico(struct.pack('<HHH', 0, 1, 2) + entry * 2 + frame))
        self.assertTrue(icons._valid_ico(self.data))
        self.assertTrue(icons._valid_ico(dib_ico()))

    def test_icon_size_and_directory_inventory_are_bounded(self):
        with patch.object(icons, '_MAX_ICON_BYTES', len(self.data) - 1):
            self.assertIsNone(self.resolve())
        for number in range(icons._MAX_ENTRIES):
            (self.directory / str(number)).write_bytes(b'')
        self.assertIsNone(self.resolve())

    def test_source_link_or_reparse_is_not_followed(self):
        outside = self.root / 'outside.ico'
        outside.write_bytes(self.data)
        self.source.unlink()
        self.link(outside, self.source)
        self.assertIsNone(self.resolve())
        self.assertEqual(outside.read_bytes(), self.data)

    def test_source_directory_link_is_not_followed(self):
        original = self.directory.with_name('original')
        self.directory.rename(original)
        self.link(original, self.directory, directory=True)
        self.assertIsNone(self.resolve())

    def test_executable_link_is_not_used_for_profile_selection(self):
        real = self.executable.with_name('real.exe')
        self.executable.rename(real)
        self.link(real, self.executable)
        self.assertIsNone(self.resolve())

    def test_cache_parent_link_never_creates_files_outside_state(self):
        outside = self.root / 'outside'
        outside.mkdir()
        self.link(outside, self.state / 'shortcut-icons', directory=True)
        self.assertIsNone(self.resolve())
        self.assertEqual(list(outside.iterdir()), [])

    def test_saved_app_cache_directory_link_is_not_followed(self):
        cache = self.state / 'shortcut-icons'
        cache.mkdir()
        outside = self.root / 'outside'
        outside.mkdir()
        self.link(outside, cache / self.app['id'], directory=True)
        self.assertIsNone(self.resolve())
        self.assertEqual(list(outside.iterdir()), [])

    def test_state_directory_link_is_not_followed(self):
        actual = self.root / 'actual-state'
        self.state.rename(actual)
        self.link(actual, self.state, directory=True)
        self.assertIsNone(self.resolve())
        self.assertEqual(list(actual.iterdir()), [])

    def test_cache_file_link_and_corrupt_content_are_never_overwritten(self):
        cached = self.resolve()
        cached.write_bytes(b'corrupt existing cache')
        self.assertIsNone(self.resolve())
        self.assertEqual(cached.read_bytes(), b'corrupt existing cache')
        cached.unlink()
        outside = self.root / 'other.ico'
        outside.write_bytes(self.data)
        self.link(outside, cached)
        self.assertIsNone(self.resolve())
        self.assertEqual(outside.read_bytes(), self.data)

    def test_hardlinked_icon_is_not_copied_or_reused(self):
        outside = self.root / 'other.ico'
        try:
            os.link(self.source, outside)
        except OSError as error:
            self.skipTest('Hard link fixture unavailable: ' + str(error))
        self.assertIsNone(self.resolve())
        outside.unlink()
        cached = self.resolve()
        os.link(cached, outside)
        self.assertIsNone(self.resolve())
        self.assertEqual(outside.read_bytes(), self.data)

    def test_shortcut_only_changes_internal_icon_not_name_argv_or_app_schema(self):
        original = deepcopy(self.app)
        path = str(self.root / 'Gemini (RuleProxy).lnk')
        output = base64.b64encode(path.encode()).decode() + '\n'
        argv = ['pythonw.exe', 'Run-RuleProxy.py', '--launch-app', self.app['id'], '--state-dir', str(self.state)]
        with patch.object(shortcuts.sys, 'platform', 'win32'), \
                patch.object(shortcuts, 'runner_argv', return_value=argv), \
                patch.object(shortcuts.subprocess, 'run', return_value=Mock(returncode=0, stdout=output, stderr='')) as run:
            shortcuts.create_shortcut_files(self.app, state_dir=self.state, ports=(8879, 10809, 19097))
        env = run.call_args.kwargs['env']
        self.assertEqual(Path(env['RULEPROXY_SHORTCUT_ICON']).read_bytes(), self.data)
        self.assertEqual(env['RULEPROXY_SHORTCUT_NAME'], 'Gemini (RuleProxy)')
        self.assertEqual(env['RULEPROXY_SHORTCUT_TARGET'], argv[0])
        self.assertEqual(env['RULEPROXY_SHORTCUT_ARGUMENTS'], shortcuts.subprocess.list2cmdline(argv[1:]))
        self.assertEqual(self.app, original)
        self.assertIn('SHChangeNotify(0x00002000, 0x0005, path', shortcuts._SHELL_LINK_TYPES)

    def test_missing_pwa_icon_and_plain_exe_preserve_browser_exe_fallback(self):
        self.source.unlink()
        output = base64.b64encode(str(self.root / 'App.lnk').encode()).decode() + '\n'
        plain = {key: value for key, value in self.app.items() if key != 'web_app'}
        for app in (self.app, plain, {**plain, 'icon_path': '/untrusted.ico'}):
            with self.subTest(app=app), patch.object(shortcuts.sys, 'platform', 'win32'), \
                    patch.object(shortcuts.subprocess, 'run', return_value=Mock(returncode=0, stdout=output, stderr='')) as run:
                shortcuts.create_shortcut_files(app, state_dir=self.state, ports=(8879, 10809, 19097))
                self.assertEqual(run.call_args.kwargs['env']['RULEPROXY_SHORTCUT_ICON'], str(self.executable))


if __name__ == '__main__':
    unittest.main()
