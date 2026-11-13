"""Linux PWA integration fixtures; never run a browser, process, or network call."""
from copy import deepcopy
import io
import json
import os
from pathlib import Path
import socket
import subprocess
import sys
import tempfile
import threading
from types import SimpleNamespace
import unittest
from unittest.mock import Mock, patch

from ruleproxy import launcher, linux_runtime, linux_web_apps as web
from ruleproxy.manager import Manager


APP_ID = 'a' * 32
OTHER_ID = 'b' * 32
START_URL = 'https://example.test/app'


@unittest.skipUnless(sys.platform.startswith('linux'), 'Linux PWA integration')
class LinuxWebAppFixture(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        self.root = Path(self.temporary.name)
        self.home = self.root / 'home'
        self.desktop = self.home / '.local/share/applications'
        self.desktop.mkdir(parents=True)
        self.profile = self.home / '.config/google-chrome/Profile 1'
        self.profile.mkdir(parents=True)
        self.chrome = self.root / 'browser-install/chrome'
        self.chrome.parent.mkdir()
        self.chrome.write_bytes(b'\x7fELF fixture, never executed')
        self.chrome.chmod(0o755)
        self.patch(patch.dict(os.environ, {'HOME': str(self.home),
            'XDG_DATA_HOME': str(self.home / '.local/share'), 'XDG_DATA_DIRS': '',
            'XDG_CONFIG_HOME': str(self.home / '.config'), 'CHROME_CONFIG_HOME': '',
            'CHROME_USER_DATA_DIR': '', 'PATH': ''}))
        self.patch(patch.object(launcher, '_DISCOVERY_CACHE', None))
        self.popen = self.patch(patch.object(subprocess, 'Popen', side_effect=AssertionError('No real process')))
        self.patch(patch.object(subprocess, 'run', side_effect=AssertionError('No process query')))
        self.patch(patch.object(socket, 'socket', side_effect=AssertionError('No network socket')))
        self.patch(patch.object(socket, 'create_connection', side_effect=AssertionError('No network connection')))

    def patch(self, patcher):
        value = patcher.start()
        self.addCleanup(patcher.stop)
        return value

    def metadata(self, **changes):
        return {'browser': 'chrome', 'profile_directory': 'Profile 1', 'app_id': APP_ID,
                'start_url': START_URL, 'launch_mode': 'isolated_url', **changes}

    def app(self, **changes):
        return {'label': 'Example PWA', 'path': str(self.chrome), 'adapter': 'chromium',
                'args': [], 'web_app': self.metadata(), **changes}

    def entry(self, name, arguments='', *, text=None):
        path = self.desktop / (name + '.desktop')
        path.write_text(text if text is not None else (
            f'[Desktop Entry]\nType=Application\nName={name}\nExec={self.chrome} {arguments}\n'),
            encoding='utf-8')
        return path

    def discover(self, directories=None):
        resolve = launcher._resolve_program

        def local_program(program):
            return resolve(program) if Path(program).is_relative_to(self.root) else None

        with patch.object(launcher, '_linux_applications_dirs', return_value=directories or [self.desktop]), \
                patch.object(launcher, '_resolve_program', side_effect=local_program):
            return launcher._linux_discover()


class LinuxWebAppDiscoveryTests(LinuxWebAppFixture):
    def test_browser_two_apps_and_two_profiles_coexist_and_duplicates_merge(self):
        self.entry('ordinary', '--new-window %U')
        for name, app_id, profile in (('pwa', APP_ID, 'Profile 1'), ('duplicate', APP_ID, 'Profile 1'),
                                      ('other-app', OTHER_ID, 'Profile 1'), ('other-profile', APP_ID, 'Default')):
            self.entry(name, f'--profile-directory="{profile}" --app-id={app_id} %U')
        with patch.object(web, 'resolve_start_url', return_value=START_URL):
            found = self.discover()
        self.assertEqual(len(found), 4)
        self.assertEqual(len({launcher.app_identity(app) for app in found}), 4)
        self.assertEqual({app['path'] for app in found}, {str(self.chrome)})
        pwas = [app for app in found if 'web_app' in app]
        self.assertEqual(len(pwas), 3)
        self.assertTrue(all(app['args'] == [] and app['launchable'] for app in pwas))
        ordinary = next(app for app in found if 'web_app' not in app)
        self.assertEqual(ordinary['args'], ['--new-window'])

    def test_conflicting_urls_are_sticky_not_first_or_last_wins(self):
        for number in range(4):
            self.entry(str(number), f'--profile-directory="Profile 1" --app-id={APP_ID}')
        with patch.object(web, 'resolve_start_url', side_effect=[START_URL, 'https://other.test/', None, START_URL]):
            found = self.discover()
        self.assertEqual(len(found), 1)
        self.assertFalse(found[0]['launchable'])
        self.assertEqual(found[0]['web_app']['start_url'], '')
        self.assertIn('多个启动网址', found[0]['unavailable_reason'])
        with self.assertRaises(ValueError):
            launcher.validate_app(found[0])

    def test_resolved_duplicate_wins_over_unresolved_in_either_order(self):
        self.entry('a', f'--profile-directory="Profile 1" --app-id={APP_ID}')
        self.entry('b', f'--profile-directory="Profile 1" --app-id={APP_ID}')
        for urls in ([None, START_URL], [START_URL, None]):
            with self.subTest(urls=urls), patch.object(web, 'resolve_start_url', side_effect=urls):
                found = self.discover()
            self.assertEqual(len(found), 1)
            self.assertEqual(found[0]['web_app']['start_url'], START_URL)
            self.assertTrue(found[0]['launchable'])
            self.assertNotIn('unavailable_reason', found[0])

    def test_raw_invalid_web_intent_never_falls_back_to_plain_browser(self):
        for number, arguments in enumerate((
            '--app=javascript:alert(1)', '--app=file:///tmp/private',
            '--app=https://example.test/ --proxy-server=direct://',
            '--app=https://example.test/ --user-data-dir=/source',
            '--app=https://example.test/ --renderer-cmd-prefix=sh',
            '--app=https://example.test/ -- --no-sandbox',
            '--app="unterminated', '--app=https://example.test/%U',
            f'--profile-directory="Profile 1" --app-id={APP_ID} --app-id={OTHER_ID}',
            '--a"pp"=https://example.test/%U',
        )):
            self.entry(str(number), arguments)
        with patch.object(launcher, '_desktop_entry', side_effect=AssertionError('No ordinary fallback')):
            self.assertEqual(self.discover(), [])

    def test_plain_browser_reserved_profile_args_still_do_not_launch(self):
        self.entry('plain-profile-override', '--profile-directory="Profile 1"')
        self.assertEqual(self.discover(), [])

    def test_user_hidden_or_invalid_entry_masks_system_desktop_identity(self):
        system = self.root / 'system-applications'
        system.mkdir()
        text = f'[Desktop Entry]\nType=Application\nName=Example\nExec={self.chrome} --app={START_URL}\n'
        (system / 'pwa.desktop').write_text(text)
        for extra in ('Hidden=true\n', 'NoDisplay=true\n', '[Desktop Entry]\n', 'Exec=bad\n'):
            with self.subTest(extra=extra):
                self.entry('pwa', text=text + extra)
                self.assertEqual(self.discover([self.desktop, system]), [])
        (self.desktop / 'pwa.desktop').write_bytes(b'\xff')
        self.assertEqual(self.discover([self.desktop, system]), [])
        (self.desktop / 'pwa.desktop').unlink()
        self.assertEqual(len(self.discover([self.desktop, system])), 1)

    def test_strict_desktop_reader_rejects_duplicate_fields_groups_and_bad_utf8(self):
        valid = f'[Desktop Entry]\nType=Application\nName=Example\nExec={self.chrome}\n'
        for content in (valid + f'Exec={self.chrome} --app={START_URL}\n',
                        valid + 'Name=Second\n', valid + '[Desktop Entry]\nName=Second\n',
                        valid + 'Exec =other\n', valid + '\0', valid + '#' * (1024 * 1024)):
            with self.subTest(content=content[:80]):
                entry = self.entry('invalid', text=content)
                self.assertIsNone(launcher._desktop_fields(entry))
                self.assertEqual(self.discover(), [])
        entry.write_bytes(valid.encode() + b'\xff')
        self.assertIsNone(launcher._desktop_fields(entry))
        self.assertEqual(self.discover(), [])

    def test_reader_uses_only_selected_desktop_and_preserves_ordinary_fields(self):
        entry = self.entry('ordinary', '--new-window %U', text=(
            f'[Desktop Entry]\nType=Application\nName=Ordinary\nName[zh_CN]=普通\n'
            f'Exec={self.chrome} --new-window %U\nIcon=chromium\n'
            '[Desktop Action NewWindow]\nName=New\nExec=ignored\n'))
        with patch.object(Path, 'read_text', side_effect=AssertionError('No unbounded text read')), \
                patch.object(Path, 'iterdir', side_effect=AssertionError('No directory inventory')):
            fields = launcher._desktop_fields(entry)
        self.assertEqual(fields['Name'], 'Ordinary')
        self.assertEqual(fields['Name[zh_CN]'], '普通')
        self.assertEqual(fields['Icon'], 'chromium')
        self.assertEqual(launcher._desktop_entry(entry)[3], ['--new-window'])
        with patch('ruleproxy.web_app_leveldb.os.open', side_effect=AssertionError('Only .desktop names')):
            self.assertIsNone(launcher._desktop_fields(self.profile / 'Cookies'))

    def test_reader_rejects_file_parent_symlinks_and_file_swap_before_open(self):
        entry = self.entry('entry', '--app=' + START_URL)
        other = self.root / 'unrelated.desktop'
        other.write_text('[Desktop Entry]\nName=Unrelated\n')
        link = self.desktop / 'link.desktop'
        link.symlink_to(other)
        self.assertIsNone(launcher._desktop_fields(link))
        parent_link = self.root / 'linked-applications'
        parent_link.symlink_to(self.desktop, target_is_directory=True)
        self.assertIsNone(launcher._desktop_fields(parent_link / entry.name))
        real_open = os.open
        swapped = False

        def swap(name, flags, *args, **kwargs):
            nonlocal swapped
            if name == entry.name:
                self.assertTrue(flags & os.O_NOFOLLOW)
                self.assertIsNotNone(kwargs.get('dir_fd'))
                entry.unlink()
                entry.symlink_to(other)
                swapped = True
            return real_open(name, flags, *args, **kwargs)

        with patch('ruleproxy.web_app_leveldb.os.open', side_effect=swap), \
                patch('ruleproxy.web_app_leveldb.os.read', side_effect=AssertionError('No symlink content read')):
            self.assertIsNone(launcher._desktop_fields(entry))
        self.assertTrue(swapped)

    def test_reader_detects_parent_swap_and_never_opens_replacement_file(self):
        entry = self.entry('entry', '--app=' + START_URL)
        retired = self.root / 'retired-applications'
        outside = self.root / 'outside'
        outside.mkdir()
        (outside / entry.name).write_bytes(b'SECRET replacement must not be read')
        real_open, real_read = os.open, os.read
        payloads = []

        def swap(name, flags, *args, **kwargs):
            if name == entry.name:
                self.desktop.rename(retired)
                self.desktop.symlink_to(outside, target_is_directory=True)
            return real_open(name, flags, *args, **kwargs)

        def read(*args):
            payload = real_read(*args)
            payloads.append(payload)
            return payload

        with patch('ruleproxy.web_app_leveldb.os.open', side_effect=swap), \
                patch('ruleproxy.web_app_leveldb.os.read', side_effect=read):
            self.assertIsNone(launcher._desktop_fields(entry))
        self.assertTrue(payloads)
        self.assertFalse(any(b'SECRET' in value for value in payloads))

    def test_desktop_scan_has_file_directory_entry_and_between_record_time_limits(self):
        for number in range(4):
            self.entry(str(number))
        with patch.object(launcher, '_linux_applications_dirs', return_value=[self.desktop]), \
                patch.object(launcher, '_LINUX_MAX_DESKTOP_FILES', 2):
            self.assertEqual(len(list(launcher._linux_desktop_files())), 2)
        inspected = []

        def entries(_path):
            for number in range(20):
                inspected.append(number)
                yield self.desktop / f'{number}.txt'

        with patch.object(launcher, '_linux_applications_dirs', return_value=[self.desktop]), \
                patch.object(launcher, '_LINUX_MAX_DIRECTORY_ENTRIES', 3), patch.object(Path, 'iterdir', entries):
            self.assertEqual(list(launcher._linux_desktop_files()), [])
        self.assertEqual(inspected, [0, 1, 2])
        with patch.object(launcher, '_linux_applications_dirs', return_value=[self.desktop]), \
                patch.object(launcher.time, 'monotonic', side_effect=[0, 0, 0, 13]):
            self.assertEqual(len(list(launcher._linux_desktop_files())), 1)

    def test_pwa_source_environment_invalidates_only_linux_discovery_cache(self):
        for name in ('HOME', 'XDG_CONFIG_HOME', 'CHROME_CONFIG_HOME', 'CHROME_USER_DATA_DIR'):
            with self.subTest(name=name), patch.object(launcher, '_DISCOVERY_CACHE', None), \
                    patch.object(launcher, '_linux_discover', return_value=[]) as scan:
                launcher.discover_apps()
                launcher.discover_apps()
                with patch.dict(os.environ, {name: str(self.root / 'changed')}):
                    launcher.discover_apps()
                self.assertEqual(scan.call_count, 2)
            with patch.object(sys, 'platform', 'win32'):
                key = launcher._discovery_key()
                with patch.dict(os.environ, {name: str(self.root / 'changed')}):
                    self.assertEqual(launcher._discovery_key(), key)


class LinuxWebAppValidationTests(LinuxWebAppFixture):
    def test_linux_schema_source_and_managed_args_or_auxiliary_paths(self):
        normalized = launcher.validate_app(self.app())
        self.assertEqual(normalized['web_app'], self.metadata())
        self.assertEqual(normalized['source'], 'linux-web-app')
        self.assertEqual(normalized['compatibility'], web.WEB_APP_DETAIL)
        self.assertFalse(normalized['use_original_data'])
        original = launcher.validate_app(self.app(use_original_data=True), check_exists=False)
        self.assertTrue(original['use_original_data'])
        self.assertEqual(original['compatibility'], web.WEB_APP_ORIGINAL_DETAIL)
        self.assertEqual(original['web_app'], normalized['web_app'])
        for change in ({'use_original_data': 1},
                       {'args': ['--app-id=' + APP_ID]}, {'args': ['--new-window']},
                       {'related_paths': [str(self.chrome)]}, {'adapter': 'environment'},
                       {'enabled': 'true'}, {'store_binding': {'package_family_name': 'Vendor.App_pub',
                        'application_id': 'App', 'scope': 'package'}}):
            with self.subTest(change=change), self.assertRaises(ValueError):
                launcher.validate_app(self.app(**change))
        for metadata in (None, {}, {**self.metadata(), 'user_data_dir': str(self.profile)},
                         self.metadata(start_url=''), self.metadata(start_url='file:///tmp/private'),
                         self.metadata(start_url='javascript:alert(1)'), self.metadata(profile_directory='../Default'),
                         self.metadata(app_id='z' * 32), self.metadata(launch_mode='original_profile')):
            with self.subTest(metadata=metadata), self.assertRaises(ValueError):
                launcher.validate_app(self.app(web_app=metadata))

    def test_launch_validation_requires_real_elf_not_script_with_browser_name(self):
        for contents in (b'#!/bin/sh\n', b'MZ Windows fixture', b'', b'not an ELF'):
            with self.subTest(contents=contents):
                self.chrome.write_bytes(contents)
                with self.assertRaisesRegex(ValueError, 'ELF'):
                    launcher.validate_app(self.app())

    def test_restore_is_schema_only_keeps_missing_linux_and_windows_executables(self):
        self.chrome.unlink()
        with patch.object(Path, 'open', side_effect=AssertionError('No file opens during validation')), \
                patch.object(Path, 'stat', side_effect=AssertionError('No executable stat')), \
                patch.object(Path, 'resolve', side_effect=AssertionError('No executable resolve')), \
                patch.object(web, 'resolve_start_url', side_effect=AssertionError('No original profile lookup')):
            linux = launcher.validate_app(self.app(), check_exists=False)
            windows = launcher.validate_app(self.app(path=str(self.chrome.with_suffix('.exe'))), check_exists=False)
        self.assertEqual(linux['source'], 'linux-web-app')
        self.assertEqual(windows['source'], 'windows-web-app')
        self.assertEqual(linux['web_app'], windows['web_app'])

    def test_prepare_uses_url_private_persistent_data_and_original_linux_proxy_flags(self):
        for name in ('Cookies', 'Login Data', 'Preferences'):
            (self.profile / name).write_bytes(b'original data untouched')
        before = {path.name: path.read_bytes() for path in self.profile.iterdir()}
        profiles = self.root / 'private-profiles'
        with patch.object(web, 'resolve_start_url', side_effect=AssertionError('No profile discovery at launch')):
            command, env, detail = launcher.prepare_app(self.app(id='pwa'), 8899, profiles)
        self.assertEqual(command[0], str(self.chrome))
        for argument in ('--app=' + START_URL, '--user-data-dir=' + str(profiles / 'pwa'),
                         '--proxy-server=http://127.0.0.1:8899', '--proxy-bypass-list=<-loopback>',
                         '--disable-quic', '--disable-setuid-sandbox',
                         '--force-webrtc-ip-handling-policy=disable_non_proxied_udp', '--restore-last-session'):
            self.assertIn(argument, command)
        self.assertFalse(any(argument.startswith(('--app-id', '--profile-directory', '--no-sandbox')) for argument in command))
        self.assertNotIn(str(self.profile), command)
        self.assertEqual(env['HTTP_PROXY'], 'http://127.0.0.1:8899')
        self.assertEqual(env['NO_PROXY'], '')
        self.assertEqual(env['no_proxy'], '')
        self.assertIn('Linux 应用模式', detail)
        self.assertNotIn('Windows', detail)
        self.assertNotIn('按浏览器程序路径', detail)
        self.assertEqual({path.name: path.read_bytes() for path in self.profile.iterdir()}, before)
        saved = profiles / 'pwa' / 'private-login-fixture'
        saved.write_bytes(b'private persistent data')
        launcher.prepare_app(self.app(id='pwa'), 8899, profiles)
        self.assertEqual(saved.read_bytes(), b'private persistent data')

    def test_linux_global_pwa_retains_existing_command_mode_without_exe_routing_claim(self):
        command, env, detail = launcher.prepare_app(self.app(id='pwa'), 8899, self.root / 'profiles',
            transparent=True, native_proxy=True, system_proxy=True)
        self.assertIn('--app=' + START_URL, command)
        self.assertIn('--user-data-dir=' + str(self.root / 'profiles/pwa'), command)
        self.assertEqual(env['NO_PROXY'], 'localhost,127.0.0.1,::1')
        self.assertNotIn('--disable-setuid-sandbox', command)
        self.assertIn('全局模式', detail)
        self.assertIn('不适用于此启动', detail)
        self.assertNotIn('按程序路径', detail)
        self.assertNotIn('Windows', detail)


class LinuxWebAppManagerTests(LinuxWebAppFixture):
    def setUp(self):
        super().setUp()
        self.patch(patch.object(Manager, '_watch'))
        self.patch(patch.object(Manager, '_legacy_artifacts_present', return_value=False))
        self.manager = Manager(self.root / 'state', 18879)
        self.addCleanup(self.cleanup_manager)
        self.windows_backend = self.patch(patch.object(self.manager, 'windows_backend',
            side_effect=AssertionError('Linux must not access Windows backend')))

    def cleanup_manager(self):
        self.manager.active.clear()
        self.manager.core = None
        self.manager.closed.set()
        self.manager.launch_owner.shutdown(wait=True)

    def add(self, app):
        self.manager.add_app(app)
        return self.manager.settings['apps'][-1]

    def request(self, path, payload):
        # Exercise the real API JSON/origin/dispatch code with in-memory I/O.
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

    def test_api_add_save_restore_keeps_all_identities_and_blocks_bad_updates(self):
        browser = {'label': 'Chrome', 'path': str(self.chrome), 'adapter': 'chromium'}
        for candidate in (browser, self.app(), self.app(web_app=self.metadata(app_id=OTHER_ID)),
                          self.app(web_app=self.metadata(profile_directory='Default'))):
            status, _ = self.request('/api/apps', candidate)
            self.assertEqual(status, 200)
        self.assertEqual(len(self.manager.settings['apps']), 4)
        saved = deepcopy(self.manager.settings['apps'])
        settings_path = self.manager.directory / 'settings.json'
        before = settings_path.read_bytes()
        for candidate in (self.app(), self.app(web_app=None), self.app(web_app=self.metadata(start_url='')),
                          self.app(web_app=self.metadata(start_url='file:///tmp/private')),
                          self.app(web_app={**self.metadata(), 'profile_path': str(self.profile)}),
                          self.app(args=['--app-id=' + APP_ID]), self.app(use_original_data=True)):
            with self.subTest(candidate=candidate):
                status, response = self.request('/api/apps', candidate)
                self.assertEqual(status, 400)
                self.assertIn('error', response)
                self.assertEqual(settings_path.read_bytes(), before)
                self.assertEqual(self.manager.settings['apps'], saved)
        status, _ = self.request('/api/apps/' + saved[1]['id'] + '/profile', {'use_original_data': True})
        self.assertEqual(status, 400)
        self.assertEqual(settings_path.read_bytes(), before)
        self.chrome.unlink()
        self.manager.settings['apps'] = []
        with patch.object(web, 'resolve_start_url', side_effect=AssertionError('No metadata restore')):
            self.manager._restore_settings()
        self.assertEqual(self.manager.settings['apps'], saved)

    def test_restore_skips_unknown_urls_extra_fields_and_duplicate_identities(self):
        first = deepcopy(self.add(self.app()))
        second = deepcopy(self.add(self.app(web_app=self.metadata(profile_directory='Default'))))
        records = [first, second, {**first, 'id': 'duplicate'},
                   {**first, 'id': 'unresolved', 'web_app': self.metadata(start_url='')},
                   {**first, 'id': 'extra', 'web_app': {**self.metadata(), 'credentials': 'ignored'}},
                    # Original mode is valid, but cannot duplicate the first
                    # record's browser/profile/app identity under another ID.
                    {**first, 'id': 'duplicate-original', 'use_original_data': True}]
        path = self.manager.directory / 'settings.json'
        path.write_text(json.dumps({**self.manager.settings, 'apps': records}))
        before = path.read_bytes()
        self.manager.settings['apps'] = []
        self.manager._restore_settings()
        self.assertEqual(self.manager.settings['apps'], [first, second])
        self.assertTrue(self.manager._settings_need_backup)
        self.assertEqual(path.read_bytes(), before)

    def test_linux_shortcuts_keep_original_label_and_distinct_profile_ids(self):
        first = self.add(self.app())
        second = self.add(self.app(web_app=self.metadata(profile_directory='Default')))
        recorded = []

        def create(app, **kwargs):
            recorded.append(deepcopy(app))
            return [self.desktop / ('ruleproxy-' + app['id'] + '.desktop')]

        with patch('ruleproxy.manager.create_shortcut_files', side_effect=create):
            one = self.manager.create_shortcuts(first['id'])
            two = self.manager.create_shortcuts(second['id'])
        self.assertNotEqual(one, two)
        self.assertEqual([app['label'] for app in recorded], ['Example PWA', 'Example PWA'])
        self.assertEqual([app['id'] for app in recorded], [first['id'], second['id']])
        self.assertEqual(first['shortcuts'], one)
        self.assertEqual(second['shortcuts'], two)

    def test_manager_real_prepare_runs_on_launch_owner_and_builds_unchanged_namespace(self):
        app = self.add(self.app())
        self.manager.core = Mock(poll=Mock(return_value=None))
        process, resource = Mock(pid=12345, poll=Mock(return_value=None)), Mock()
        private = self.manager.directory / 'profiles' / app['id']
        downloads = (self.home / 'Downloads', self.home / 'Downloads')
        downloads[0].mkdir()
        captured = {}

        def launch(command, env, profile, port, folder, **kwargs):
            self.assertTrue(threading.current_thread().name.startswith('RuleProxyLaunchOwner'))
            self.assertEqual(profile, private)
            self.assertEqual(port, self.manager.mixed_port)
            self.assertEqual(folder, downloads)
            self.assertEqual(kwargs, {}, 'Independent PWA must not pass original_profile or keyring options')
            # The real builder is still responsible for the isolation boundary.
            args, isolated = linux_runtime.build_command(command, env, profile, '/tmp/fixture-bridge.sock', folder)
            captured.update(command=command, args=args, env=isolated)
            return process, resource

        with patch.object(self.manager, 'protection', return_value={'supported': True}), \
                patch.object(linux_runtime, 'downloads_folder', return_value=downloads), \
                patch.object(linux_runtime, 'bwrap_executable', return_value='/usr/bin/bwrap'), \
                patch.object(linux_runtime, 'launch', side_effect=launch) as launch_mock, \
                patch.object(self.manager.launch_owner, 'submit', wraps=self.manager.launch_owner.submit) as submit, \
                patch('ruleproxy.app_profile_data.original_profile_source', side_effect=AssertionError('No original data')):
            result = self.manager.launch(app['id'])
        submit.assert_called_once()
        self.assertIs(submit.call_args.args[0], launch_mock)
        self.assertEqual(submit.call_args.kwargs, {})
        launch_mock.assert_called_once()
        args, env = captured['args'], captured['env']
        self.assertEqual(args[0], '/usr/bin/bwrap')
        for flag in ('--unshare-net', '--unshare-user', '--unshare-pid', '--unshare-ipc', '--unshare-uts',
                     '--die-with-parent', '--new-session', '--cap-drop'):
            self.assertIn(flag, args)
        self.assertIn('--app=' + START_URL, captured['command'])
        self.assertIn('--user-data-dir=' + str(private), captured['command'])
        binds = [tuple(args[index + 1:index + 3]) for index, arg in enumerate(args) if arg in ('--bind', '--ro-bind')]
        self.assertIn((str(private), str(private)), binds)
        self.assertIn(('/tmp/fixture-bridge.sock', '/run/ruleproxy.sock'), binds)
        self.assertIn((str(downloads[0]), str(downloads[1])), binds)
        for forbidden in (self.home, self.home / '.config', self.profile, self.profile.parent):
            self.assertNotIn(str(forbidden), [source for source, _ in binds])
        self.assertEqual(env['HOME'], str(private))
        self.assertEqual(env['XDG_CONFIG_HOME'], str(private / '.config'))
        self.assertEqual(env['NO_PROXY'], '')
        self.assertNotIn('DBUS_SESSION_BUS_ADDRESS', env)
        self.assertEqual(self.manager.active[app['id']], (process, resource))
        self.assertIn('Linux 应用模式', result['detail'])
        self.assertNotIn('Windows', result['detail'])
        self.assertFalse(self.manager.uses_system_proxy)
        self.windows_backend.assert_not_called()
        self.popen.assert_not_called()

    def test_global_manager_launch_keeps_native_spawn_and_system_proxy_mode(self):
        app = self.add(self.app())
        self.manager.settings['capture_mode'] = 'global'
        self.manager.core = Mock(poll=Mock(return_value=None))
        process = Mock(pid=12345, poll=Mock(return_value=None))
        with patch.object(self.manager, '_proxy_watchdog_healthy', return_value=True), \
                patch.object(self.manager, 'protection', return_value={'supported': True}), \
                patch.object(subprocess, 'Popen', return_value=process) as spawn, \
                patch.object(self.manager.launch_owner, 'submit') as submit:
            result = self.manager.launch(app['id'])
        submit.assert_not_called()
        spawn.assert_called_once()
        self.assertIn('--app=' + START_URL, spawn.call_args.args[0])
        self.assertTrue(spawn.call_args.kwargs['start_new_session'])
        self.assertEqual(spawn.call_args.kwargs['env']['NO_PROXY'], 'localhost,127.0.0.1,::1')
        self.assertEqual(self.manager.active[app['id']], (process, None))
        self.assertIn('全局系统代理', result['detail'])
        self.assertNotIn('Windows', result['detail'])
        self.windows_backend.assert_not_called()

    def test_failed_preflight_never_submits_or_spawns_and_runtime_failure_never_falls_back(self):
        app = self.add(self.app())
        self.manager.core = Mock(poll=Mock(return_value=None))
        with patch.object(self.manager, 'protection', return_value={'supported': False, 'detail': 'isolation absent'}), \
                patch.object(self.manager.launch_owner, 'submit') as submit, self.assertRaisesRegex(ValueError, 'isolation absent'):
            self.manager.launch(app['id'])
        submit.assert_not_called()
        self.chrome.write_bytes(b'#!/bin/sh\n')
        with patch.object(self.manager, 'protection', return_value={'supported': True}), \
                patch.object(self.manager.launch_owner, 'submit') as submit, self.assertRaisesRegex(ValueError, 'ELF'):
            self.manager.launch(app['id'])
        submit.assert_not_called()
        self.chrome.write_bytes(b'\x7fELF fixture')
        bridge = Mock(path='/tmp/fixture-bridge.sock')
        with patch.object(self.manager, 'protection', return_value={'supported': True}), \
                patch.object(linux_runtime, 'downloads_folder', return_value=None), \
                patch.object(linux_runtime, 'ProxyBridge', return_value=bridge), \
                patch.object(linux_runtime, 'bwrap_executable', return_value=None), \
                self.assertRaisesRegex(ValueError, 'bubblewrap'):
            self.manager.launch(app['id'])
        bridge.close.assert_called_once_with()
        self.assertEqual(self.manager.active, {})
        self.popen.assert_not_called()

    def test_namespace_helper_uses_only_namespace_loopback_and_unix_proxy_bridge(self):
        from ruleproxy import namespace_helper as helper
        policy = {'command': [str(self.chrome), '--app=' + START_URL], 'env': {'NO_PROXY': ''}, 'port': 10809}
        listener = Mock()
        child = Mock(wait=Mock(return_value=0))
        with patch.object(helper.sys, 'stdin', SimpleNamespace(buffer=io.BytesIO(json.dumps(policy).encode()))), \
                patch.object(helper.socket, 'if_nameindex', return_value=[(1, 'lo')]), \
                patch.object(helper.socket, 'socket', return_value=listener) as create_socket, \
                patch.object(helper.subprocess, 'Popen', return_value=child) as spawn, \
                patch.object(helper.threading, 'Thread') as thread, patch.object(helper.signal, 'signal'), \
                patch('builtins.print'):
            self.assertEqual(helper.main(), 0)
        create_socket.assert_called_once_with(socket.AF_INET, socket.SOCK_STREAM)
        listener.bind.assert_called_once_with(('127.0.0.1', 10809))
        spawn.assert_called_once_with(policy['command'], env=policy['env'], stdin=subprocess.DEVNULL)
        self.assertEqual(thread.call_count, 1)
        client, peer = Mock(), Mock()
        client.recv.return_value = b''
        with patch.object(helper.socket, 'socket', return_value=peer) as create_socket, \
                patch.object(helper.select, 'select', return_value=([client], [], [])):
            helper.bridge(client, '/run/ruleproxy.sock')
        create_socket.assert_called_once_with(socket.AF_UNIX, socket.SOCK_STREAM)
        peer.connect.assert_called_once_with('/run/ruleproxy.sock')
        client.close.assert_called_once()
        peer.close.assert_called_once()
        with patch.object(helper.sys, 'stdin', SimpleNamespace(buffer=io.BytesIO(json.dumps(policy).encode()))), \
                patch.object(helper.socket, 'if_nameindex', return_value=[(1, 'lo'), (2, 'eth0')]), \
                patch.object(helper.subprocess, 'Popen') as spawn, self.assertRaisesRegex(RuntimeError, 'uplink'):
            helper.main()
        spawn.assert_not_called()


if __name__ == '__main__':
    unittest.main()
