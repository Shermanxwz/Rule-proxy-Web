"""Linux original-PWA contract using only temporary browser/profile fixtures."""
from contextlib import contextmanager
from copy import deepcopy
import io
import json
import os
from pathlib import Path
import shlex
import socket
import subprocess
import sys
import tempfile
import threading
from types import SimpleNamespace
import unittest
from unittest.mock import Mock, patch

from ruleproxy import app_profile_data as profiles
from ruleproxy import launcher, linux_profile_access as access, linux_runtime as runtime
from ruleproxy import linux_web_apps as web, shortcut_launcher, shortcuts
from ruleproxy.manager import Manager


APP_ID = 'a' * 32
START_URL = 'https://example.test/pwa'


@unittest.skipUnless(sys.platform.startswith('linux'), 'Linux original-PWA fixtures')
class OriginalPwaFixture(unittest.TestCase):
    def setUp(self):
        temporary = tempfile.TemporaryDirectory(prefix='rp-original-pwa-')
        self.addCleanup(temporary.cleanup)
        self.root = Path(temporary.name)
        self.home = self.root / 'home'
        self.config = self.home / '.config'
        self.chrome = self.elf('/opt/google/chrome/chrome')
        self.source = self.initialized('google-chrome')
        self.selected = self.source / 'Profile 1'
        self.private = self.root / 'profiles'
        self.patch(patch.dict(web._BROWSER_LOCATIONS, {
            self.relocate(path): value for path, value in web._BROWSER_LOCATIONS.items()
        }, clear=True))
        self.patch(patch.dict(os.environ, {'HOME': str(self.home), 'XDG_CONFIG_HOME': str(self.config),
            'XDG_DATA_HOME': str(self.home / '.local/share'), 'PATH': '/usr/bin:/bin'}, clear=True))
        self.spawn = self.patch(patch.object(subprocess, 'Popen', side_effect=AssertionError('No real process')))
        self.patch(patch.object(subprocess, 'run', side_effect=AssertionError('No process queries')))

    def patch(self, context):
        result = context.start()
        self.addCleanup(context.stop)
        return result

    def relocate(self, path):
        return self.root / 'system' / Path(path).relative_to('/')

    def elf(self, path):
        executable = self.relocate(path)
        executable.parent.mkdir(parents=True, exist_ok=True)
        executable.write_bytes(b'\x7fELF fixture; never executed')
        executable.chmod(0o700)
        return executable

    def initialized(self, folder, *, config=None):
        source = (config or self.config) / folder
        source.mkdir(parents=True, exist_ok=True)
        (source / 'Local State').write_text('{}', encoding='utf-8')
        for name in ('Default', 'Profile 1'):
            selected = source / name
            selected.mkdir(exist_ok=True)
            (selected / 'Preferences').write_text('{}', encoding='utf-8')
        return source

    def metadata(self, **changes):
        return {'browser': 'chrome', 'profile_directory': 'Profile 1', 'app_id': APP_ID,
                'start_url': START_URL, 'launch_mode': 'isolated_url', **changes}

    def app(self, **changes):
        return {'id': 'original-pwa', 'label': 'Fixture PWA', 'path': str(self.chrome),
                'adapter': 'chromium', 'args': [], 'web_app': self.metadata(),
                'use_original_data': True, **changes}

    def snapshot(self):
        return {str(path.relative_to(self.source)): path.read_bytes()
                for path in self.source.rglob('*') if path.is_file()}

    @contextmanager
    def installation_alias(self, *, known_channel, level):
        target = self.elf('/opt/google/chrome-beta/chrome' if known_channel else '/unrecognized-install/chrome')
        if known_channel:
            self.initialized('google-chrome-beta')
        alias = self.chrome.parent if level == 'parent' else self.chrome
        destination = target.parent if level == 'parent' else target
        original = alias.with_name(alias.name + '-original-fixture')
        alias.rename(original)
        alias.symlink_to(destination, target_is_directory=level == 'parent')
        try:
            yield target
        finally:
            alias.unlink()
            original.rename(alias)


class OriginalPwaResolutionTests(OriginalPwaFixture):
    def test_exact_known_browser_channels_and_default_or_profile_one(self):
        with patch.object(profiles, '_chromium_location', side_effect=AssertionError('No basename guesses')):
            for browser, folder, binaries, _ in web._INSTALLS:
                source = self.initialized(folder)
                for binary in binaries:
                    executable = self.elf(binary)
                    for name in ('Default', 'Profile 1'):
                        with self.subTest(binary=binary, profile=name):
                            app = self.app(path=str(executable), web_app=self.metadata(
                                browser=browser, profile_directory=name))
                            self.assertEqual(web.original_profile_directory(app['web_app'], executable), source / name)
                            self.assertEqual(profiles.original_profile_source(app), source)

    def test_pwa_reads_only_root_index_and_exact_preferences_without_profile_inventory(self):
        for name in ('Cookies', 'Login Data', 'History'):
            (self.selected / name).write_bytes(b'synthetic private database; never opened')
        (self.source / 'Default/Preferences').write_text('corrupt unrelated profile; do not inspect')
        before = self.snapshot()
        opened = []
        real_open = os.open

        def bounded_open(path, flags, *args, **kwargs):
            self.assertIn(Path(path), (self.chrome, self.source / 'Local State', self.selected / 'Preferences'))
            self.assertFalse(flags & (os.O_WRONLY | os.O_RDWR | os.O_CREAT))
            opened.append(Path(path))
            return real_open(path, flags, *args, **kwargs)

        with patch.object(Path, 'iterdir', side_effect=AssertionError('No profile inventory')), \
                patch.object(os, 'scandir', side_effect=AssertionError('No profile traversal')), \
                patch.object(os, 'open', side_effect=bounded_open), \
                patch.object(web, 'resolve_start_url', side_effect=AssertionError('No app registry rescan')):
            self.assertEqual(profiles.original_profile_source(self.app()), self.source)
        self.assertEqual(opened, [self.chrome, self.source / 'Local State', self.selected / 'Preferences'])
        self.assertEqual(self.snapshot(), before)

    def test_other_initialized_profile_does_not_satisfy_missing_selected_directory(self):
        (self.selected / 'Preferences').unlink()
        self.selected.rmdir()
        with self.assertRaises(ValueError):
            profiles.original_profile_source(self.app())
        self.assertFalse(self.selected.exists())
        self.assertTrue((self.source / 'Default/Preferences').is_file())

    def test_missing_or_corrupt_exact_indexes_are_rejected_without_changes(self):
        for path in (self.source / 'Local State', self.selected / 'Preferences'):
            for content in (None, b'broken', b'[]', b'null', b'\xff', b' ' * (profiles.MAX_METADATA_BYTES + 1)):
                with self.subTest(index=path.name, content=content[:10] if content else None):
                    if content is None:
                        path.unlink()
                    else:
                        path.write_bytes(content)
                    with self.assertRaises(ValueError):
                        profiles.original_profile_source(self.app())
                    self.assertEqual(path.read_bytes() if path.exists() else None, content)
                    path.write_text('{}')

    def test_unknown_install_channel_custom_root_and_mismatched_browser_do_not_guess(self):
        unknown = self.elf('/portable/chrome')
        beta = self.elf('/opt/google/chrome-beta/chrome')
        for executable in (unknown, beta):
            with self.subTest(path=executable), self.assertRaises(ValueError):
                profiles.original_profile_source(self.app(path=str(executable)))
        with patch.dict(web._BROWSER_LOCATIONS, {self.chrome: ('edge', 'microsoft-edge')}), self.assertRaises(ValueError):
            profiles.original_profile_source(self.app())
        for root in (str(self.source), str(self.home / 'custom-root'), 'relative'):
            with patch.dict(os.environ, {'CHROME_USER_DATA_DIR': root}), self.assertRaises(ValueError):
                profiles.original_profile_source(self.app())

    def test_config_precedence_and_ambiguous_roots_are_not_normalized_into_valid_roots(self):
        chrome_config = self.home / 'chrome-config'
        other = self.initialized('google-chrome', config=chrome_config)
        with patch.dict(os.environ, {'CHROME_CONFIG_HOME': str(chrome_config)}):
            self.assertEqual(profiles.original_profile_source(self.app()), other)
        for root in ('relative', str(self.config / '../.config'), '//' + str(self.config).lstrip('/'),
                     str(self.config) + ':other', str(self.config) + '\\other'):
            with self.subTest(root=root), patch.dict(os.environ, {'CHROME_CONFIG_HOME': root}), self.assertRaises(ValueError):
                profiles.original_profile_source(self.app())

    def test_enable_resolver_checks_existing_executable_elf_and_execution_permission(self):
        for content, mode in ((b'#!/bin/sh\n', 0o700), (b'MZ fixture', 0o700), (b'\x7fELF fixture', 0o600)):
            with self.subTest(content=content, mode=mode):
                self.chrome.write_bytes(content)
                self.chrome.chmod(mode)
                with self.assertRaises(ValueError):
                    profiles.original_profile_source(self.app())
        self.chrome.unlink()
        with self.assertRaises(ValueError):
            profiles.original_profile_source(self.app())
        other = self.elf('/other/chrome')
        self.chrome.symlink_to(other)
        with self.assertRaises(ValueError):
            profiles.original_profile_source(self.app())

    def test_original_resolver_rejects_installation_parent_and_file_aliases_to_unknown_or_known_channel(self):
        before = self.snapshot()
        for known_channel in (False, True):
            for level in ('parent', 'file'):
                with self.subTest(known_channel=known_channel, level=level), \
                        self.installation_alias(known_channel=known_channel, level=level), \
                        self.assertRaises(ValueError):
                    profiles.original_profile_source(self.app())
        self.assertEqual(self.snapshot(), before)

    def test_root_selected_directory_indexes_and_config_ancestors_reject_symlinks(self):
        for path in (self.source, self.selected, self.source / 'Local State',
                     self.selected / 'Preferences', self.config):
            with self.subTest(path=path):
                moved = path.with_name(path.name + '-fixture-original')
                path.rename(moved)
                path.symlink_to(moved, target_is_directory=moved.is_dir())
                try:
                    with self.assertRaises(ValueError):
                        profiles.original_profile_source(self.app())
                    self.assertTrue(path.is_symlink())
                finally:
                    path.unlink()
                    moved.rename(path)

    def test_owned_root_selected_directory_and_both_indexes_are_required(self):
        real_lstat = Path.lstat
        for foreign in (self.source, self.selected, self.source / 'Local State', self.selected / 'Preferences'):
            def lstat(path, *args, **kwargs):
                info = real_lstat(path, *args, **kwargs)
                return SimpleNamespace(st_mode=info.st_mode, st_uid=os.getuid() + 1) if path == foreign else info

            with self.subTest(path=foreign), patch.object(Path, 'lstat', lstat), self.assertRaises(ValueError):
                profiles.original_profile_source(self.app())

    def test_original_root_never_shares_home_or_home_ancestor(self):
        for home in (self.source, self.source / 'nested-home'):
            with patch.dict(os.environ, {'HOME': str(home)}), self.assertRaisesRegex(ValueError, '整个家目录'):
                profiles.original_profile_source(self.app())

    def test_live_foreign_malformed_regular_and_stale_locks_remain_rejected_and_untouched(self):
        lock = self.source / 'SingletonLock'
        targets = (socket.gethostname() + '-' + str(os.getpid()), 'foreign-host-123', 'bad-lock',
                   socket.gethostname() + '-0')
        for target in targets:
            with self.subTest(target=target):
                lock.symlink_to(target)
                with self.assertRaises(ValueError):
                    profiles.original_profile_source(self.app())
                self.assertEqual(os.readlink(lock), target)
                lock.unlink()
        lock.write_bytes(b'unrecognized lock')
        with self.assertRaises(ValueError):
            profiles.original_profile_source(self.app())
        self.assertEqual(lock.read_bytes(), b'unrecognized lock')
        lock.unlink()
        target = socket.gethostname() + '-12345'
        lock.symlink_to(target)
        with patch.object(os, 'kill', side_effect=ProcessLookupError), self.assertRaisesRegex(ValueError, '旧资料锁'):
            profiles.original_profile_source(self.app())
        self.assertEqual(os.readlink(lock), target)


class OriginalPwaSchemaLaunchTests(OriginalPwaFixture):
    def test_strict_boolean_default_and_unchanged_metadata_fields(self):
        app = self.app()
        app.pop('use_original_data')
        self.assertFalse(launcher.validate_app(app)['use_original_data'])
        for value in (False, True):
            normalized = launcher.validate_app(self.app(use_original_data=value))
            self.assertIs(normalized['use_original_data'], value)
            self.assertEqual(normalized['web_app'], self.metadata())
            self.assertEqual(normalized['compatibility'], web.web_app_detail(value))
        for value in (None, 0, 1, 'false', 'true', [], {}):
            with self.subTest(value=value), self.assertRaisesRegex(ValueError, '布尔值'):
                launcher.validate_app(self.app(use_original_data=value), check_exists=False)
        for value in (None, {}, self.metadata(profile_directory='../Default'), self.metadata(browser='edge'),
                      self.metadata(app_id='z' * 32), self.metadata(start_url='file:///private'),
                      self.metadata(launch_mode='original_profile'), self.metadata(user_data_dir=str(self.source))):
            with self.subTest(metadata=value), self.assertRaises(ValueError):
                launcher.validate_app(self.app(web_app=value), check_exists=False)

    def test_restore_is_schema_only_without_binary_profile_or_filesystem_reads(self):
        self.chrome.unlink()
        with patch.object(Path, 'open', side_effect=AssertionError('No opens')), \
                patch.object(Path, 'stat', side_effect=AssertionError('No stat')), \
                patch.object(Path, 'lstat', side_effect=AssertionError('No lstat')), \
                patch.object(Path, 'resolve', side_effect=AssertionError('No resolve')), \
                patch.object(os, 'open', side_effect=AssertionError('No os.open')), \
                patch.object(web, 'original_profile_directory', side_effect=AssertionError('No source lookup')):
            for value in (False, True):
                normalized = launcher.validate_app(self.app(use_original_data=value), check_exists=False)
                self.assertIs(normalized['use_original_data'], value)
                self.assertEqual(normalized['web_app'], self.metadata())
            # Windows records remain restorable in cross-platform tooling too.
            for platform in ('linux', 'win32', 'darwin'):
                with patch.object(sys, 'platform', platform):
                    restored = launcher.validate_app(self.app(path=str(self.chrome.with_suffix('.exe'))), check_exists=False)
                    self.assertTrue(restored['use_original_data'])
                    self.assertEqual(restored['source'], 'windows-web-app')

    def test_unknown_platform_and_foreign_executable_still_fail_actual_launch(self):
        with patch.object(sys, 'platform', 'darwin'), self.assertRaises(ValueError):
            launcher.prepare_app(self.app(), 8899, self.private)
        foreign = self.elf('/foreign/chrome.exe')
        foreign.write_bytes(b'MZ fixture')
        with self.assertRaisesRegex(ValueError, 'ELF'):
            launcher.prepare_app(self.app(path=str(foreign)), 8899, self.private)
        self.assertFalse(self.private.exists())

    def test_exact_profile_id_or_url_root_flags_and_no_restore_unrelated_tabs_in_both_modes(self):
        before = self.snapshot()
        for profile in ('Default', 'Profile 1'):
            for app_id in (APP_ID, ''):
                for global_mode in (False, True):
                    with self.subTest(profile=profile, app_id=app_id, global_mode=global_mode), \
                            patch('ruleproxy.windows_web_apps.original_profile_directory',
                                  side_effect=AssertionError('Windows helper is Windows-only')):
                        command, env, detail = launcher.prepare_app(self.app(web_app=self.metadata(
                            profile_directory=profile, app_id=app_id)), 8899, self.private,
                            transparent=global_mode, native_proxy=global_mode, system_proxy=global_mode)
                    self.assertEqual(command[:3], [str(self.chrome), '--profile-directory=' + profile,
                        '--app-id=' + app_id if app_id else '--app=' + START_URL])
                    self.assertEqual([arg for arg in command if arg.startswith('--user-data-dir=')],
                                     ['--user-data-dir=' + str(self.source)])
                    self.assertNotIn('--restore-last-session', command)
                    self.assertNotIn('--no-sandbox', command)
                    self.assertNotIn('--password-store=basic', command)
                    self.assertIn('--proxy-server=http://127.0.0.1:8899', command)
                    self.assertIn('--disable-quic', command)
                    self.assertIn('--force-webrtc-ip-handling-policy=disable_non_proxied_udp', command)
                    self.assertNotIn('首次需重新登录', detail)
                    self.assertNotIn('Windows', detail)
                    self.assertNotIn('按程序路径', detail)
                    if global_mode:
                        self.assertIn('全局模式使用系统代理', detail)
                        self.assertIn('不适用于此启动', detail)
                        self.assertNotIn('保留网络、进程和家目录隔离', detail)
                    else:
                        self.assertEqual(env['NO_PROXY'], '')
                        self.assertEqual(env['no_proxy'], '')
                        self.assertIn('--proxy-bypass-list=<-loopback>', command)
                        self.assertIn('--disable-setuid-sandbox', command)
                        self.assertIn(web.WEB_APP_ORIGINAL_DETAIL, detail)
        self.assertFalse(self.private.exists())
        self.assertEqual(self.snapshot(), before)

    def test_failed_launch_checks_do_not_create_independent_profile_or_switch_mode(self):
        app = self.app()
        before = deepcopy(app)
        (self.selected / 'Preferences').unlink()
        for global_mode in (False, True):
            with self.subTest(global_mode=global_mode), self.assertRaises(ValueError):
                launcher.prepare_app(app, 8899, self.private, transparent=global_mode)
        self.assertEqual(app, before)
        self.assertFalse(self.private.exists())
        self.spawn.assert_not_called()

    def test_both_original_launch_modes_reject_aliases_before_profile_lookup(self):
        before = self.snapshot()
        app = self.app()
        saved = deepcopy(app)
        for known_channel in (False, True):
            for level in ('parent', 'file'):
                with self.installation_alias(known_channel=known_channel, level=level), \
                        patch.object(profiles, 'original_profile_source', wraps=profiles.original_profile_source) as resolve:
                    for global_mode in (False, True):
                        with self.subTest(known_channel=known_channel, level=level, global_mode=global_mode), \
                                self.assertRaisesRegex(ValueError, '身份不明确'):
                            launcher.prepare_app(app, 8899, self.private, transparent=global_mode,
                                                 native_proxy=global_mode, system_proxy=global_mode)
                    resolve.assert_not_called()
        self.assertEqual(app, saved)
        self.assertEqual(self.snapshot(), before)
        self.assertFalse(self.private.exists())
        self.spawn.assert_not_called()

    def test_original_profile_and_command_use_the_same_normalized_executable_identity(self):
        for global_mode in (False, True):
            with self.subTest(global_mode=global_mode), \
                    patch.object(profiles, 'original_profile_source', wraps=profiles.original_profile_source) as resolve:
                command, _, _ = launcher.prepare_app(self.app(label='  Fixture PWA  '), 8899, self.private,
                                                      transparent=global_mode)
            resolve.assert_called_once()
            selected = resolve.call_args.args[0]
            self.assertEqual(selected['path'], command[0])
            self.assertEqual(selected['label'], 'Fixture PWA')
            self.assertEqual(selected['web_app'], self.metadata())
            self.assertEqual(selected['id'], 'original-pwa')

    def test_independent_alias_launch_and_schema_only_restore_keep_existing_behavior(self):
        for known_channel in (False, True):
            with self.installation_alias(known_channel=known_channel, level='parent') as target:
                with patch.object(profiles, 'original_profile_source', side_effect=AssertionError('No original source')):
                    for global_mode in (False, True):
                        command, _, _ = launcher.prepare_app(self.app(use_original_data=False), 8899, self.private,
                                                             transparent=global_mode)
                        self.assertEqual(command[0], str(target))
                        self.assertIn('--app=' + START_URL, command)
                with patch.object(Path, 'stat', side_effect=AssertionError('No stat on restore')), \
                        patch.object(Path, 'lstat', side_effect=AssertionError('No lstat on restore')), \
                        patch.object(Path, 'resolve', side_effect=AssertionError('No resolve on restore')), \
                        patch.object(os, 'open', side_effect=AssertionError('No source open on restore')):
                    for value in (False, True):
                        restored = launcher.validate_app(self.app(use_original_data=value), check_exists=False)
                        self.assertEqual(restored['path'], str(self.chrome))
                        self.assertIs(restored['use_original_data'], value)

    def test_switch_false_uses_existing_private_data_without_source_or_migration(self):
        app = self.app(use_original_data=False)
        private = self.private / app['id']
        private.mkdir(parents=True)
        marker = private / 'private-session-fixture'
        marker.write_bytes(b'keep existing independent data')
        launcher.prepare_app(self.app(), 8899, self.private)
        self.source.rename(self.source.with_name('missing-original-fixture'))
        with patch.object(profiles, 'original_profile_source', side_effect=AssertionError('Independent mode ignores source')):
            for global_mode in (False, True):
                command, _, detail = launcher.prepare_app(app, 8899, self.private, transparent=global_mode,
                                                         native_proxy=global_mode, system_proxy=global_mode)
                self.assertIn('--user-data-dir=' + str(private), command)
                self.assertIn('--app=' + START_URL, command)
                self.assertIn('--restore-last-session', command)
                self.assertFalse(any(arg.startswith(('--app-id=', '--profile-directory=')) for arg in command))
                self.assertIn('首次需重新登录', detail)
        self.assertEqual(marker.read_bytes(), b'keep existing independent data')
        self.assertFalse(self.source.exists())


class OriginalPwaManagerTests(OriginalPwaFixture):
    def setUp(self):
        super().setUp()
        self.patch(patch.object(Manager, '_watch'))
        self.patch(patch.object(Manager, '_legacy_artifacts_present', return_value=False))
        self.manager = Manager(self.root / 'state', 18879)
        self.addCleanup(self.close_manager)
        self.patch(patch.object(self.manager, 'windows_backend', side_effect=AssertionError('No Windows backend')))
        self.manager.add_app(self.app(use_original_data=False))
        self.saved = self.manager.settings['apps'][0]
        self.ident = self.saved['id']
        self.settings_path = self.manager.directory / 'settings.json'

    def close_manager(self):
        self.manager.active.clear()
        self.manager.core = None
        self.manager.closed.set()
        self.manager.launch_owner.shutdown(wait=True)

    def request(self, path, payload):
        from ruleproxy.server import Handler
        handler = Handler.__new__(Handler)
        handler.path, handler.command = path, 'POST'
        body = json.dumps(payload).encode()
        handler.headers = {'Host': '127.0.0.1:18879', 'Content-Type': 'application/json',
                           'Content-Length': str(len(body)), 'X-RuleProxy-Token': self.manager.token}
        handler.rfile = io.BytesIO(body)
        handler.server = SimpleNamespace(manager=self.manager, client_identity=None,
                                         server_address=('127.0.0.1', 18879))
        handler.reply = Mock()
        handler.state_payload = lambda: {'apps': deepcopy(self.manager.settings['apps'])}
        handler.do_POST()
        handler.reply.assert_called_once()
        return handler.reply.call_args.args

    def set_mode(self, value):
        return self.request('/api/apps/' + self.ident + '/profile', {'use_original_data': value})

    def launch_ready(self):
        self.manager.core = Mock(poll=Mock(return_value=None))
        self.patch(patch.object(self.manager, 'protection', return_value={'supported': True}))
        self.patch(patch.object(runtime, 'downloads_folder', return_value=None))

    def test_api_true_false_save_restore_and_false_with_missing_original(self):
        metadata = deepcopy(self.saved['web_app'])
        status, response = self.set_mode(True)
        self.assertEqual(status, 200, response)
        self.assertTrue(response['apps'][0]['use_original_data'])
        self.assertEqual(self.saved['compatibility'], web.WEB_APP_ORIGINAL_DETAIL)
        persisted = json.loads(self.settings_path.read_text())['apps'][0]
        self.assertEqual(persisted, self.saved)
        self.chrome.unlink()
        self.source.rename(self.source.with_name('missing-original-fixture'))
        self.manager.settings['apps'] = []
        with patch.object(web, 'original_profile_directory', side_effect=AssertionError('Restore does no source I/O')), \
                patch.object(profiles, 'original_profile_source', side_effect=AssertionError('No profile lookup')):
            self.manager._restore_settings()
            self.assertEqual(self.manager.app(self.ident), persisted)
            status, response = self.set_mode(False)
        self.assertEqual(status, 200, response)
        restored = self.manager.app(self.ident)
        self.assertFalse(restored['use_original_data'])
        self.assertEqual(restored['compatibility'], web.WEB_APP_DETAIL)
        self.assertEqual(restored['web_app'], metadata)
        self.assertFalse((self.manager.directory / 'profiles').exists())
        self.assertFalse(self.source.exists())

    def test_add_original_selection_validates_source_before_persisting(self):
        other = self.app(web_app=self.metadata(app_id='b' * 32))
        before = self.settings_path.read_bytes()
        (self.selected / 'Preferences').unlink()
        status, _ = self.request('/api/apps', other)
        self.assertEqual(status, 400)
        self.assertEqual(self.settings_path.read_bytes(), before)
        (self.selected / 'Preferences').write_text('{}')
        status, response = self.request('/api/apps', other)
        self.assertEqual(status, 200, response)
        self.assertTrue(response['apps'][1]['use_original_data'])
        self.assertEqual(response['apps'][1]['compatibility'], web.WEB_APP_ORIGINAL_DETAIL)

    def test_enable_original_rejects_aliases_without_rebinding_or_saving(self):
        saved, persisted = deepcopy(self.saved), self.settings_path.read_bytes()
        before = self.snapshot()
        for known_channel in (False, True):
            for level in ('parent', 'file'):
                with self.subTest(known_channel=known_channel, level=level), \
                        self.installation_alias(known_channel=known_channel, level=level):
                    status, response = self.set_mode(True)
                    self.assertEqual(status, 400, response)
                    self.assertEqual(self.saved, saved)
                    self.assertEqual(self.settings_path.read_bytes(), persisted)
                    self.assertEqual(self.manager._profile_preparing, set())
                    with patch.object(profiles, 'original_profile_source', side_effect=AssertionError('False ignores source')):
                        self.assertEqual(self.set_mode(False)[0], 200)
        self.assertEqual(self.snapshot(), before)
        self.assertFalse((self.manager.directory / 'profiles').exists())

    def test_add_original_rejects_aliases_to_unknown_or_another_known_channel_before_save(self):
        saved, persisted = deepcopy(self.saved), self.settings_path.read_bytes()
        other = self.app(web_app=self.metadata(app_id='b' * 32))
        before = deepcopy(other)
        for known_channel in (False, True):
            for level in ('parent', 'file'):
                with self.subTest(known_channel=known_channel, level=level), \
                        self.installation_alias(known_channel=known_channel, level=level):
                    status, response = self.request('/api/apps', other)
                    self.assertEqual(status, 400, response)
                    self.assertEqual(self.manager.settings['apps'], [saved])
                    self.assertEqual(self.settings_path.read_bytes(), persisted)
        self.assertEqual(other, before)
        self.assertFalse((self.manager.directory / 'profiles').exists())

    def test_original_manager_launch_rejects_aliases_before_namespace_or_global_spawn(self):
        self.assertEqual(self.set_mode(True)[0], 200)
        self.launch_ready()
        saved, persisted = deepcopy(self.saved), self.settings_path.read_bytes()
        for known_channel in (False, True):
            for level in ('parent', 'file'):
                with self.installation_alias(known_channel=known_channel, level=level), \
                        patch.object(self.manager, '_proxy_watchdog_healthy', return_value=True), \
                        patch.object(self.manager.launch_owner, 'submit', side_effect=AssertionError('No namespace launch')) as submit:
                    for mode in ('applications', 'global'):
                        self.manager.settings['capture_mode'] = mode
                        with self.subTest(known_channel=known_channel, level=level, mode=mode), \
                                self.assertRaisesRegex(ValueError, '身份不明确'):
                            self.manager.launch(self.ident)
                    submit.assert_not_called()
        self.assertEqual(self.manager.active, {})
        self.assertEqual(self.saved, saved)
        self.assertEqual(self.settings_path.read_bytes(), persisted)
        self.assertFalse((self.manager.directory / 'profiles').exists())
        self.spawn.assert_not_called()

    def test_add_normalization_and_original_checks_allow_other_thread_to_acquire_manager_lock(self):
        checked = []
        resolve = profiles.original_profile_source

        def unlocked(stage, function, app):
            acquired = threading.Event()

            def acquire():
                with self.manager.lock:
                    acquired.set()

            worker = threading.Thread(target=acquire)
            worker.start()
            try:
                self.assertTrue(acquired.wait(2), stage + ' must not block core cleanup')
            finally:
                worker.join(2)
            checked.append(stage)
            self.assertEqual(len(self.manager.settings['apps']), 1)
            return function(app)

        with patch('ruleproxy.manager.validate_app', side_effect=lambda app: unlocked('normalize', launcher.validate_app, app)), \
                patch.object(profiles, 'original_profile_source', side_effect=lambda app: unlocked('profile', resolve, app)):
            self.manager.add_app(self.app(web_app=self.metadata(app_id='b' * 32)))
        self.assertEqual(checked, ['normalize', 'profile'])
        self.assertEqual(len(self.manager.settings['apps']), 2)
        self.assertTrue(self.manager.settings['apps'][1]['use_original_data'])

    def test_nonboolean_failed_checks_and_failed_save_preserve_choice_compatibility_and_settings(self):
        before, persisted = deepcopy(self.saved), self.settings_path.read_bytes()
        for value in (None, 'true', 0, 1, [], {}):
            self.assertEqual(self.set_mode(value)[0], 400)
        with patch.object(profiles, 'original_profile_source', side_effect=ValueError('profile busy')):
            self.assertEqual(self.set_mode(True)[0], 400)
        with patch.object(self.manager, '_save', side_effect=OSError('disk full')):
            status, response = self.set_mode(True)
        self.assertEqual(status, 400)
        self.assertIn('disk full', response['error'])
        self.assertEqual(self.saved, before)
        self.assertEqual(self.settings_path.read_bytes(), persisted)
        self.assertEqual(self.manager._profile_preparing, set())

    def test_active_cleanup_and_preparing_guards_do_not_stop_or_modify_app(self):
        before = deepcopy(self.saved)
        process = Mock(poll=Mock(return_value=None))
        for resource in (None, SimpleNamespace(failed_process=Mock())):
            self.manager.active[self.ident] = (process, resource)
            self.assertEqual(self.set_mode(True)[0], 400)
        process.terminate.assert_not_called()
        self.manager.active.clear()
        self.manager._profile_preparing.add(self.ident)
        try:
            self.assertEqual(self.set_mode(True)[0], 400)
        finally:
            self.manager._profile_preparing.clear()
        self.assertEqual(self.saved, before)

    def test_checks_release_lock_and_preparing_blocks_launch_delete_and_parallel_switch(self):
        acquired = threading.Event()
        resolve = profiles.original_profile_source

        def check(app):
            def acquire():
                with self.manager.lock:
                    acquired.set()
            worker = threading.Thread(target=acquire)
            worker.start()
            try:
                self.assertTrue(acquired.wait(2))
            finally:
                worker.join(2)
            self.assertIn(self.ident, self.manager._profile_preparing)
            with self.assertRaisesRegex(ValueError, '正在检查'):
                self.manager.launch(self.ident)
            with self.assertRaisesRegex(ValueError, '正在准备'):
                self.manager.change_app(self.ident, delete=True)
            self.assertEqual(self.set_mode(False)[0], 400)
            return resolve(app)

        with patch.object(profiles, 'original_profile_source', side_effect=check):
            self.assertEqual(self.set_mode(True)[0], 200)
        self.assertEqual(self.manager._profile_preparing, set())

    def test_shutdown_during_check_preserves_saved_choice(self):
        before = self.settings_path.read_bytes()

        def check(_app):
            self.manager.quitting = True
            return self.source

        with patch.object(profiles, 'original_profile_source', side_effect=check):
            self.assertEqual(self.set_mode(True)[0], 400)
        self.assertEqual(self.settings_path.read_bytes(), before)
        self.assertFalse(self.saved['use_original_data'])
        self.assertEqual(self.manager._profile_preparing, set())

    def test_original_manager_uses_existing_runtime_narrow_bind_and_filtered_keyring(self):
        self.assertEqual(self.set_mode(True)[0], 200)
        self.launch_ready()
        for name in ('Cookies', 'Login Data', 'History'):
            (self.selected / name).write_bytes(b'synthetic database; contents stay untouched')
        before = self.snapshot()
        endpoint = socket.socket(socket.AF_UNIX)
        self.addCleanup(endpoint.close)
        keyring_path = self.root / 'filtered-keyring.sock'
        endpoint.bind(str(keyring_path))
        keyring, bridge = Mock(path=keyring_path), Mock(path='/tmp/fixture-bridge.sock')
        process = Mock(pid=12345, poll=Mock(return_value=None), stdin=Mock(),
                       stdout=io.StringIO('RULEPROXY_NAMESPACE_READY\n'), stderr=io.StringIO(''))
        command_input = process.stdin
        original_open = Path.open

        def no_secrets(path, *args, **kwargs):
            self.assertNotIn(path.name, ('Cookies', 'Login Data', 'History'))
            return original_open(path, *args, **kwargs)

        with patch.dict(os.environ, {'DBUS_SESSION_BUS_ADDRESS': 'unix:path=/host-desktop-bus',
                                    'NO_PROXY': '*', 'no_proxy': 'localhost'}), \
                patch.object(runtime, 'ProxyBridge', return_value=bridge), \
                patch.object(access, 'FilteredKeyringProxy', return_value=keyring) as filtered, \
                patch.object(access, 'require_wallet_provider') as provider, \
                patch.object(access, 'shared_profile', wraps=access.shared_profile) as shared, \
                patch.object(runtime, 'bwrap_executable', return_value='/usr/bin/bwrap'), \
                patch.object(runtime.select, 'select', return_value=([process.stdout], [], [])), \
                patch.object(subprocess, 'Popen', return_value=process) as spawn, \
                patch.object(self.manager.launch_owner, 'submit', wraps=self.manager.launch_owner.submit) as submit, \
                patch.object(Path, 'open', no_secrets):
            result = self.manager.launch(self.ident)
        self.addCleanup(self.manager.active[self.ident][1].close)
        submit.assert_called_once()
        self.assertIs(submit.call_args.args[0], runtime.launch)
        self.assertEqual(submit.call_args.kwargs, {'original_profile': self.source, 'profile_adapter': 'chromium'})
        workspace = self.manager.directory / 'profiles' / self.ident
        for call in shared.call_args_list:
            self.assertEqual(call.args, (self.source, workspace))
        self.assertEqual(shared.call_count, 2)
        filtered.assert_called_once_with('unix:path=/host-desktop-bus')
        self.assertEqual(provider.call_args.args[1], 'unix:path=' + str(keyring_path))
        args = spawn.call_args.args[0]
        policy = json.loads(command_input.write.call_args.args[0])
        self.assertEqual(args[0], '/usr/bin/bwrap')
        for flag in ('--unshare-net', '--unshare-user', '--unshare-pid', '--unshare-ipc',
                     '--unshare-uts', '--die-with-parent', '--new-session', '--cap-drop'):
            self.assertIn(flag, args)
        binds = [tuple(args[index + 1:index + 3]) for index, arg in enumerate(args) if arg in ('--bind', '--ro-bind')]
        self.assertEqual(binds.count((str(self.source), str(self.source))), 1)
        self.assertIn((str(workspace), str(workspace)), binds)
        destination = f'/run/user/{os.getuid()}/bus'
        self.assertIn((str(keyring_path), destination), binds)
        for forbidden in (str(self.home), str(self.config), str(self.selected), '/host-desktop-bus'):
            self.assertNotIn(forbidden, [source for source, _ in binds])
        self.assertIn('--app-id=' + APP_ID, policy['command'])
        self.assertIn('--user-data-dir=' + str(self.source), policy['command'])
        self.assertIn('--proxy-bypass-list=<-loopback>', policy['command'])
        self.assertEqual(policy['env']['NO_PROXY'], '')
        self.assertEqual(policy['env']['no_proxy'], '')
        self.assertEqual(policy['env']['DBUS_SESSION_BUS_ADDRESS'], 'unix:path=' + destination)
        self.assertNotIn('DBUS_SYSTEM_BUS_ADDRESS', policy['env'])
        self.assertIn(web.WEB_APP_ORIGINAL_DETAIL, result['detail'])
        self.assertEqual(self.snapshot(), before)
        self.assertFalse(any(path.name in ('Cookies', 'Login Data', 'History') for path in workspace.rglob('*')))

    def test_missing_keyring_and_runtime_ipc_failure_never_fall_back_to_host_launch(self):
        self.assertEqual(self.set_mode(True)[0], 200)
        self.launch_ready()
        marker = self.selected / 'Cookies'
        marker.write_bytes(b'untouched synthetic cookie database')
        bridge = Mock(path='/tmp/fixture-bridge.sock')
        with patch.object(runtime, 'ProxyBridge', return_value=bridge), self.assertRaisesRegex(ValueError, '桌面密钥服务'):
            self.manager.launch(self.ident)
        bridge.close.assert_called_once()
        self.assertEqual(self.manager.active, {})
        self.assertEqual(marker.read_bytes(), b'untouched synthetic cookie database')
        os.mkfifo(self.selected / 'host-control.pipe')
        bridge.reset_mock()
        with patch.object(runtime, 'ProxyBridge', return_value=bridge), self.assertRaisesRegex(ValueError, '套接字、管道或设备'):
            self.manager.launch(self.ident)
        bridge.close.assert_called_once()
        self.spawn.assert_not_called()
        self.assertEqual(self.manager.active, {})

    def test_global_manager_uses_explicit_root_and_system_proxy_not_namespace_or_path_routing(self):
        self.assertEqual(self.set_mode(True)[0], 200)
        self.launch_ready()
        self.manager.settings['capture_mode'] = 'global'
        process = Mock(pid=12345, poll=Mock(return_value=None))
        with patch.object(self.manager, '_proxy_watchdog_healthy', return_value=True), \
                patch.object(subprocess, 'Popen', return_value=process) as spawn, \
                patch.object(self.manager.launch_owner, 'submit') as submit:
            result = self.manager.launch(self.ident)
            repeated = self.manager.launch(self.ident)
        submit.assert_not_called()
        spawn.assert_called_once()
        self.assertNotIn('隔离', repeated['detail'])
        self.assertIn('--user-data-dir=' + str(self.source), spawn.call_args.args[0])
        self.assertIn('--profile-directory=Profile 1', spawn.call_args.args[0])
        self.assertIn('--app-id=' + APP_ID, spawn.call_args.args[0])
        self.assertNotIn('--restore-last-session', spawn.call_args.args[0])
        self.assertTrue(spawn.call_args.kwargs['start_new_session'])
        self.assertIn('全局系统代理', result['detail'])
        self.assertIn('不适用于此启动', result['detail'])
        self.assertIn('检测到资料占用时停止启动，不接管或关闭外部已有窗口', result['detail'])
        self.assertNotIn('不接力', result['detail'])
        self.assertNotIn('保留网络、进程和家目录隔离', result['detail'])
        self.assertNotIn('按程序路径', result['detail'])
        self.assertNotIn('首次需重新登录', result['detail'])
        self.assertFalse((self.manager.directory / 'profiles').exists())

    def test_saved_id_shortcuts_follow_mode_without_recreation_or_argument_changes(self):
        (self.home / 'Desktop').mkdir()
        with patch.object(shortcuts, 'linux_desktop_icon', return_value='fixture-browser-icon'), \
                patch.object(shortcuts, '_best_effort'):
            created = [Path(path) for path in self.manager.create_shortcuts(self.ident)]
        snapshots = {path: path.read_bytes() for path in created}
        fields = launcher._desktop_fields(created[0])
        argv = shlex.split(fields['Exec'])
        saved_id = argv[argv.index('--launch-app') + 1]
        self.assertEqual(saved_id, self.ident)
        self.assertNotIn('--use-original-data', argv)
        self.launch_ready()
        process = Mock(pid=12345, poll=Mock(return_value=None))
        results = []

        def post(_port, _token, path):
            status, response = self.request(path, {})
            self.assertEqual(status, 200, response)
            results.append(response)
            return response

        with patch.object(shortcut_launcher, 'panel_state', return_value={'token': self.manager.token, 'running': True}), \
                patch.object(shortcut_launcher, 'post', side_effect=post), \
                patch.object(runtime, 'launch', return_value=(process, None)) as launch, \
                patch('ruleproxy.manager.create_shortcut_files', side_effect=AssertionError('Keep existing shortcut files')):
            for mode in (False, True, False):
                if not mode and len(results) == 2:
                    self.source.rename(self.source.with_name('missing-original-fixture'))
                self.assertEqual(self.set_mode(mode)[0], 200)
                self.assertEqual(shortcut_launcher.run(saved_id, state_dir=self.manager.directory,
                    panel_port=18879, mixed_port=10809, controller_port=19097), 0)
                command = launch.call_args.args[0]
                expected = self.source if mode else self.manager.directory / 'profiles' / saved_id
                self.assertIn('--user-data-dir=' + str(expected), command)
                self.assertEqual('--app-id=' + APP_ID in command, mode)
                self.assertEqual(launch.call_args.kwargs,
                    {'original_profile': self.source, 'profile_adapter': 'chromium'} if mode else {})
                self.manager.active.clear()
        self.assertEqual(len(results), 3)
        self.assertEqual({path: path.read_bytes() for path in created}, snapshots)
        self.assertEqual(self.saved['shortcuts'], [str(path) for path in created])


if __name__ == '__main__':
    unittest.main()
