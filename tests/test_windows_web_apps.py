"""Installed PWA discovery/launch contracts; no browser or Windows device runs."""
from copy import deepcopy
import http.client
import json
import os
from pathlib import Path
import subprocess
import tempfile
import threading
import unittest
from unittest.mock import Mock, patch

from ruleproxy import launcher, windows_web_apps as web


APP_ID = 'gdfaincndogidkdcdkhapmbffkckdkhn'
OTHER_ID = 'a' * 32
START_URL = 'https://gemini.google.com/app'


def varint(number):
    data = bytearray()
    while number >= 128:
        data.append((number & 127) | 128); number >>= 7
    data.append(number)
    return bytes(data)


def field(number, value):
    if isinstance(value, int):
        return varint(number << 3) + varint(value)
    if isinstance(value, str):
        value = value.encode('utf-8')
    return varint((number << 3) | 2) + varint(len(value)) + value


class WebAppFixture(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        self.root = Path(self.temporary.name)
        self.programs = self.root / 'Program Files'
        self.local = self.root / 'Local'
        self.chrome = self.programs / 'Google/Chrome/Application/chrome.exe'
        self.trampoline = self.chrome.with_name('chrome_proxy.exe')
        for path in (self.chrome, self.trampoline):
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_bytes(b'MZ fixture, never executed')
            path.chmod(0o755)
        self.profile = self.local / 'Google/Chrome/User Data/Profile 1'
        self.profile.mkdir(parents=True)
        self.environment = patch.dict(os.environ, {
            'PROGRAMFILES': str(self.programs), 'PROGRAMFILES(X86)': str(self.root / 'x86'),
            'LOCALAPPDATA': str(self.local)})
        self.environment.start(); self.addCleanup(self.environment.stop)

    def metadata(self, **kwargs):
        return {'browser': 'chrome', 'profile_directory': 'Profile 1', 'app_id': APP_ID,
                'start_url': START_URL, 'launch_mode': 'isolated_url', **kwargs}

    def app(self, **kwargs):
        return {'label': 'Gemini', 'path': str(self.chrome), 'adapter': 'chromium',
                'args': [], 'web_app': self.metadata(), **kwargs}

    def shortcut(self, **kwargs):
        return {'label': 'Gemini', 'target': str(self.trampoline),
                'arguments': f' --profile-directory="Profile 1" --app-id={APP_ID}', **kwargs}

    def parse(self, rows):
        return web.parse_shortcuts(json.dumps({'schema_version': 1, 'shortcuts': rows}).encode())

    def legacy_metadata(self, url=START_URL):
        document = {'extensions': {'settings': {APP_ID: {'state': 1, 'manifest': {
            'name': 'Gemini', 'app': {'launch': {'web_url': url}}}}}}}
        (self.profile / 'Preferences').write_text(json.dumps(document))


class WebAppDiscoveryTests(WebAppFixture):
    def test_windows_arguments_keep_profile_and_reject_malformed_quoting(self):
        self.assertEqual(web.split_windows_arguments(' --profile-directory="Profile 1"\t--app-id=' + APP_ID),
                         ['--profile-directory=Profile 1', '--app-id=' + APP_ID])
        for value in ('"unterminated', 'bad\0argument', 'bad\nargument'):
            with self.subTest(value=value), self.assertRaises(ValueError):
                web.split_windows_arguments(value)
        args = ['--profile-directory=Profile 1', '--app=https://example.test/a?name=two%20words', r'back\slash', 'a"b']
        self.assertEqual(web.split_windows_arguments(subprocess.list2cmdline(args)), args)

    def test_real_chrome_shortcut_uses_exact_profile_and_installed_app_metadata(self):
        self.legacy_metadata()
        before = (self.profile / 'Preferences').read_bytes()
        with patch('subprocess.Popen', side_effect=AssertionError('No candidate may start')):
            result = self.parse([self.shortcut()])
        self.assertEqual(len(result), 1)
        app = result[0]
        self.assertEqual(app['path'], str(self.chrome.resolve()))
        self.assertEqual(app['web_app'], self.metadata())
        self.assertEqual(app['args'], [])
        self.assertTrue(app['launchable'])
        self.assertFalse(app['use_original_data'])
        self.assertEqual(app['source'], 'windows-web-app')
        self.assertEqual((self.profile / 'Preferences').read_bytes(), before)

    def test_shared_datastore_only_requests_selected_web_app_key(self):
        database = self.profile / 'Sync Data/LevelDB'
        database.mkdir(parents=True)
        record = field(1, field(1, START_URL)) + field(8, 1)
        key = b'web_apps-dt-' + APP_ID.encode()
        with patch('ruleproxy.web_app_leveldb.read_values', return_value={key: record}) as read:
            result = self.parse([self.shortcut()])
        read.assert_called_once_with(database, {key})
        self.assertEqual(result[0]['web_app']['start_url'], START_URL)

    def test_deleted_modern_record_does_not_resurrect_legacy_manifest(self):
        self.legacy_metadata()
        (self.profile / 'Sync Data/LevelDB').mkdir(parents=True)
        with patch('ruleproxy.web_app_leveldb.read_values', return_value={}):
            result = self.parse([self.shortcut()])
        self.assertFalse(result[0]['launchable'])
        self.assertEqual(result[0]['web_app']['start_url'], '')

    def test_only_necessary_metadata_files_are_opened(self):
        from ruleproxy.web_app_leveldb import read_metadata_file
        self.legacy_metadata()
        for name in ('Cookies', 'Login Data', 'History'):
            (self.profile / name).write_bytes(b'not read')
        original_open = Path.open
        opened = []

        def tracked(path, *args, **kwargs):
            self.assertNotIn(path.name, ('Cookies', 'Login Data', 'History'))
            opened.append(path)
            return original_open(path, *args, **kwargs)

        with patch.object(Path, 'open', tracked), \
                patch('ruleproxy.web_app_leveldb.read_metadata_file', wraps=read_metadata_file) as metadata:
            self.assertTrue(self.parse([self.shortcut()])[0]['launchable'])
        self.assertCountEqual(opened, [self.chrome])
        metadata.assert_called_once_with(self.profile, 'Preferences')

    def test_unknown_or_unreadable_metadata_remains_an_unlaunchable_discovery(self):
        for error in (None, ValueError('Unknown database format'), PermissionError('Locked metadata')):
            with self.subTest(error=error), patch.object(web, 'resolve_start_url', return_value=None, side_effect=error):
                result = self.parse([self.shortcut()])
            self.assertEqual(len(result), 1)
            self.assertEqual(result[0]['web_app']['app_id'], APP_ID)
            self.assertFalse(result[0]['launchable'])
            self.assertIn('unavailable_reason', result[0])
            with patch.object(launcher.sys, 'platform', 'win32'), self.assertRaises(ValueError):
                launcher.validate_app(result[0])

    def test_multiple_apps_profiles_and_browser_stay_distinct_but_duplicate_links_merge(self):
        rows = [self.shortcut(), self.shortcut(label='Gemini desktop'),
                self.shortcut(label='Another PWA', arguments=f'--profile-directory="Profile 1" --app-id={OTHER_ID}'),
                self.shortcut(label='Gemini other profile', arguments=f'--profile-directory=Default --app-id={APP_ID}')]
        with patch.object(web, 'resolve_start_url', return_value=START_URL):
            installed = self.parse(rows)
        self.assertEqual(len(installed), 3)
        with patch.object(launcher, '_win_registry_apps', return_value=[]), \
                patch.object(launcher, '_win_store_apps', return_value=[]), \
                patch.object(launcher, '_win_web_apps', return_value=installed), \
                patch('subprocess.Popen', side_effect=AssertionError('No executable launch')):
            apps = launcher._windows_discover()
        self.assertEqual(len(apps), 4)
        self.assertEqual(len({launcher.app_identity(app) for app in apps}), 4)
        self.assertEqual({app['path'] for app in apps}, {str(self.chrome.resolve())})

    def test_explicit_url_shortcut_and_edge_trampoline_are_supported(self):
        edge = self.programs / 'Microsoft/Edge/Application/msedge.exe'
        edge.parent.mkdir(parents=True)
        proxy = edge.with_name('msedge_proxy.exe')
        for path in (edge, proxy):
            path.write_bytes(b'MZ fixture'); path.chmod(0o755)
        rows = [self.shortcut(arguments='--profile-directory=Default --app=https://example.test/app'),
                self.shortcut(target=str(proxy), arguments=f'--profile-directory=Default --app-id={APP_ID} --app-url=https://example.test/app')]
        with patch.object(web, 'resolve_start_url', side_effect=AssertionError('Shortcut contains URL')):
            apps = self.parse(rows)
        self.assertEqual(len(apps), 2)
        self.assertEqual(apps[0]['web_app']['app_id'], '')
        self.assertEqual(apps[1]['web_app']['browser'], 'edge')
        self.assertEqual(apps[1]['path'], str(edge.resolve()))

    def test_brave_chromium_vivaldi_and_channels_use_their_own_profile_roots(self):
        for browser, product, executable in (
                ('chrome', 'Google/Chrome Beta', 'chrome.exe'),
                ('edge', 'Microsoft/Edge Dev', 'msedge.exe'),
                ('brave', 'BraveSoftware/Brave-Browser', 'brave.exe'),
                ('brave', 'BraveSoftware/Brave-Browser-Nightly', 'brave.exe'),
                ('chromium', 'Chromium', 'chrome.exe'), ('vivaldi', 'Vivaldi', 'vivaldi.exe')):
            with self.subTest(product=product):
                path = self.programs / product / 'Application' / executable
                path.parent.mkdir(parents=True); path.write_bytes(b'MZ fixture')
                profile = self.local / product / 'User Data/Default'
                profile.mkdir(parents=True)
                self.assertEqual(web._browser_target(str(path)), (browser, path))
                self.assertEqual(web._profile_path(path, browser, 'Default'), profile)

    def test_missing_profile_is_not_guessed_from_last_used_browser_profile(self):
        with patch.object(web, 'resolve_start_url', side_effect=AssertionError('Unknown source profile')):
            self.assertEqual(self.parse([self.shortcut(arguments='--app-id=' + APP_ID)]), [])

    def test_conflicting_duplicate_urls_are_reported_instead_of_first_wins(self):
        base = f'--profile-directory="Profile 1" --app-id={APP_ID} --app-url='
        apps = self.parse([self.shortcut(arguments=base + START_URL),
                           self.shortcut(arguments=base + 'https://other.test/app'),
                           self.shortcut(arguments=base + START_URL)])
        self.assertEqual(len(apps), 1)
        self.assertFalse(apps[0]['launchable'])
        self.assertEqual(apps[0]['web_app']['start_url'], '')
        self.assertIn('多个启动网址', apps[0]['unavailable_reason'])

    def test_shortcut_document_shape_and_size_are_bounded(self):
        for document in ({'schema_version': True, 'shortcuts': []},
                         {'schema_version': 1, 'shortcuts': {}},
                         {'schema_version': 1, 'shortcuts': [{}] * 2049}, []):
            with self.subTest(document_type=type(document).__name__), self.assertRaises(ValueError):
                web.parse_shortcuts(json.dumps(document).encode())
        with self.assertRaises(ValueError):
            web.parse_shortcuts(b' ' * (web._MAX_OUTPUT + 1))

    def test_shortcut_query_reads_metadata_through_system_powershell_only(self):
        output = b'{"schema_version":1,"shortcuts":[]}'
        system = self.root / 'Windows/System32/WindowsPowerShell/v1.0/powershell.exe'
        def run(command, **kwargs):
            self.assertEqual(command[0], str(system))
            self.assertIn('-NoProfile', command)
            self.assertIn('-NonInteractive', command)
            self.assertEqual(kwargs['stdin'], subprocess.DEVNULL)
            self.assertEqual(kwargs['timeout'], web._DISCOVERY_SECONDS)
            kwargs['stdout'].write(output)
            return Mock(returncode=0)
        with patch('ruleproxy.windows_store_apps._system_powershell', return_value=system), \
                patch.object(web.subprocess, 'run', side_effect=run):
            self.assertEqual(web._query(), output)
        self.assertNotIn('.Save(', web._QUERY_SCRIPT)
        self.assertNotIn('.Run(', web._QUERY_SCRIPT)

    def test_discovery_never_strips_dangerous_or_ambiguous_shortcut_args(self):
        for args in (f'--app-id={APP_ID} --user-data-dir=C:\\Elsewhere',
                     f'--app-id={APP_ID} --proxy-server=direct://',
                     f'--app-id={APP_ID} --renderer-cmd-prefix=cmd.exe',
                     f'--app-id={APP_ID} --profile-directory=../Other',
                     f'--app-id={APP_ID} --app-id={OTHER_ID}',
                     '--app=javascript:alert(1)', '--app=file:///C:/secret',
                     f'--app-id={APP_ID} --app=https://example.test/',
                     '--app=https://example.test -- --proxy-server=direct://'):
            with self.subTest(args=args):
                self.assertEqual(self.parse([self.shortcut(arguments=args)]), [])

    def test_missing_actual_browser_is_omitted_not_routed_via_proxy_trampoline(self):
        self.chrome.unlink()
        self.assertEqual(self.parse([self.shortcut()]), [])

    def test_new_browser_discovery_failure_does_not_hide_desktop_apps(self):
        with patch.object(web.sys, 'platform', 'win32'), patch.object(web, '_query', side_effect=OSError('COM unavailable')):
            self.assertEqual(web.discover_web_apps(), [])

    def test_profile_symlink_is_not_followed(self):
        if not hasattr(os, 'symlink'):
            self.skipTest('Symlinks unavailable')
        redirected = self.root / 'unrelated-profile'
        redirected.mkdir()
        self.profile.rmdir()
        try:
            self.profile.symlink_to(redirected, target_is_directory=True)
        except OSError:
            self.skipTest('Symlinks require local permission')
        with self.assertRaises(ValueError):
            web._profile_path(self.chrome, 'chrome', 'Profile 1')

    def test_proto_matches_exact_fields_and_rejects_uninstalled_pending_or_non_web_apps(self):
        valid = field(1, field(1, START_URL)) + field(8, 1)
        self.assertEqual(web._start_url_from_proto(valid), START_URL)
        invalid = [field(1, field(1, START_URL)), valid + field(45, 1), valid + field(9, 1),
                   valid + field(60, b''), field(1, field(2, START_URL)) + field(8, 1),
                   field(1, field(1, 'chrome://settings')) + field(8, 1),
                   field(1, field(1, START_URL)) + field(8, 0),
                   field(1, field(1, START_URL)) + field(8, 3), valid + b'\x80',
                   field(1, field(1, START_URL) + field(1, 'https://other.test')) + field(8, 1)]
        for data in invalid:
            with self.subTest(data=data), self.assertRaises(ValueError):
                web._start_url_from_proto(data)
        with self.assertRaises(ValueError):
            web._protobuf_fields(field(2, b'') * 4097)


class WebAppValidationTests(WebAppFixture):
    def test_strict_metadata_schema_and_http_urls(self):
        self.assertEqual(web.validate_web_app(self.metadata(), self.chrome), self.metadata())
        for invalid in (None, [], {}, {**self.metadata(), 'extra': True},
                        self.metadata(browser='firefox'), self.metadata(profile_directory='../Profile 1'),
                        self.metadata(profile_directory='Default/Other'), self.metadata(app_id='z' * 32),
                        self.metadata(app_id=None), self.metadata(start_url=''),
                        self.metadata(launch_mode='original_profile')):
            with self.subTest(invalid=invalid), self.assertRaises((ValueError, UnicodeError)):
                web.validate_web_app(invalid, self.chrome)
        for url in ('javascript:alert(1)', 'file:///C:/Windows', '//example.test', 'chrome://settings',
                    'https://user:password@example.test', 'https://example.test\\evil',
                    'https://example.test/\n--proxy-server=direct://', 'https://exa mple.test',
                    'http://[::1', 'https://example.test:0', 'https://example.test:65536',
                    'https://example.test/%oops', 'https://%65xample.test', 'https://-bad.test',
                    'https://example.test/a"b', 'https://example.test/\ud800'):
            with self.subTest(url=url), self.assertRaises((ValueError, UnicodeError)):
                web.validate_start_url(url)
        for url in ('http://localhost:8888/app', 'https://example.test/a?b=c#d', 'http://[::1]:9000/',
                    'https://例子.测试/应用'):
            with self.subTest(url=url):
                self.assertEqual(web.validate_start_url(url), url)

    def test_validate_preserves_typed_metadata_and_locks_data_arguments_and_paths(self):
        with patch.object(launcher.sys, 'platform', 'win32'):
            normalized = launcher.validate_app(self.app())
            self.assertEqual(normalized['web_app'], self.metadata())
            self.assertIs(normalized['use_original_data'], False)
            self.assertEqual(normalized['source'], 'windows-web-app')
            for changes in ({'args': ['--profile-directory=Profile 1']},
                            {'args': ['--app-id=' + APP_ID]}, {'args': ['--proxy-server=direct://']},
                            {'adapter': 'environment'}, {'related_paths': [str(self.trampoline)]},
                            {'path': str(self.trampoline)}, {'enabled': 'true'},
                            {'store_binding': {'package_family_name': 'Vendor.App_pub', 'application_id': 'App', 'scope': 'package'}}):
                with self.subTest(changes=changes), self.assertRaises(ValueError):
                    launcher.validate_app(self.app(**changes))
        self.chrome.unlink()
        with patch.object(web, 'resolve_start_url', side_effect=AssertionError('No metadata read on restore')):
            normalized = launcher.validate_app(self.app(), check_exists=False)
        self.assertEqual(normalized['web_app'], self.metadata())

    def test_original_mode_preserves_identity_and_strict_schema_without_restore_reads(self):
        for platform in ('win32', 'linux', 'darwin'):
            with self.subTest(platform=platform), patch.object(launcher.sys, 'platform', platform), \
                    patch.object(web, '_profile_path', side_effect=AssertionError('Restore performs no profile checks')), \
                    patch.object(Path, 'open', side_effect=AssertionError('Restore opens no data')):
                private = launcher.validate_app(self.app(), check_exists=False)
                original = launcher.validate_app(self.app(use_original_data=True), check_exists=False)
                self.assertIs(original['use_original_data'], True)
                self.assertEqual(original['web_app'], private['web_app'])
                self.assertEqual(launcher.app_identity(original), launcher.app_identity(private))
                self.assertEqual(original['compatibility'], web.WEB_APP_ORIGINAL_DETAIL)
                self.assertNotIn('首次需重新登录', original['compatibility'])
        with patch.object(launcher.sys, 'platform', 'win32'):
            for value in (None, 0, 1, 'true', [], {}):
                with self.subTest(value=value), self.assertRaisesRegex(ValueError, '布尔值'):
                    launcher.validate_app(self.app(use_original_data=value))
            for invalid in (None, {}, {**self.metadata(), 'user_data_dir': str(self.profile)},
                            self.metadata(browser='edge'), self.metadata(profile_directory='../Default'),
                            self.metadata(profile_directory=''), self.metadata(app_id='z' * 32),
                            self.metadata(start_url='file:///secret'), self.metadata(launch_mode='original_profile')):
                with self.subTest(invalid=invalid), self.assertRaises(ValueError):
                    launcher.validate_app(self.app(use_original_data=True, web_app=invalid))
            for adapter in ('firefox', 'environment'):
                with self.subTest(adapter=adapter), self.assertRaises(ValueError):
                    launcher.validate_app(self.app(use_original_data=True, adapter=adapter))

    def test_original_launch_uses_exact_profile_id_or_url_without_browser_data_io(self):
        originals = {name: b'original secret fixture' for name in ('Cookies', 'Login Data', 'Preferences')}
        for name, contents in originals.items():
            (self.profile / name).write_bytes(contents)
        original_open = Path.open

        def executable_only(path, *args, **kwargs):
            self.assertEqual(path, self.chrome, 'Only the executable header may be read')
            return original_open(path, *args, **kwargs)

        profiles = self.root / 'profiles'
        for app_id in (APP_ID, ''):
            for native_proxy in (False, True):
                with self.subTest(app_id=app_id, native_proxy=native_proxy), \
                        patch.object(launcher.sys, 'platform', 'win32'), \
                        patch.object(Path, 'open', executable_only), \
                        patch.object(web, 'resolve_start_url', side_effect=AssertionError('No registry rescan')):
                    command, environment, detail = launcher.prepare_app(
                        self.app(id='pwa-original', use_original_data=True, web_app=self.metadata(app_id=app_id)),
                        8899, profiles, transparent=True, native_proxy=native_proxy)
                self.assertEqual(command[:3], [str(self.chrome), '--profile-directory=Profile 1',
                    '--app-id=' + APP_ID if app_id else '--app=' + START_URL])
                self.assertFalse(any(arg.startswith('--user-data-dir') for arg in command))
                self.assertNotIn('--restore-last-session', command)
                self.assertIn(web.WEB_APP_ORIGINAL_DETAIL, detail)
                self.assertNotIn('首次需重新登录', detail)
                if native_proxy:
                    self.assertIn('--proxy-server=http://127.0.0.1:8899', command)
                    self.assertIn('--proxy-bypass-list=<-loopback>;localhost;127.0.0.1;[::1]', command)
                    self.assertIn('--disable-quic', command)
                    self.assertIn('--force-webrtc-ip-handling-policy=disable_non_proxied_udp', command)
                    self.assertEqual(environment['NO_PROXY'], 'localhost,127.0.0.1,::1')
                    self.assertEqual(environment['HTTP_PROXY'], 'http://127.0.0.1:8899')
                else:
                    self.assertEqual(len(command), 3)
                    self.assertNotIn('HTTP_PROXY', environment)
        self.assertFalse(profiles.exists())
        self.assertEqual({path.name: path.read_bytes() for path in self.profile.iterdir()}, originals)

    def test_original_launch_matches_each_browser_channel_and_profile(self):
        for browser, product, executable in (('chrome', 'Google/Chrome Beta', 'chrome.exe'),
                ('edge', 'Microsoft/Edge Dev', 'msedge.exe'),
                ('brave', 'BraveSoftware/Brave-Browser-Nightly', 'brave.exe'),
                ('chromium', 'Chromium', 'chrome.exe'), ('vivaldi', 'Vivaldi', 'vivaldi.exe')):
            path = self.programs / product / 'Application' / executable
            path.parent.mkdir(parents=True); path.write_bytes(b'MZ fixture'); path.chmod(0o755)
            profile = self.local / product / 'User Data/Default'
            profile.mkdir(parents=True)
            metadata = self.metadata(browser=browser, profile_directory='Default')
            with self.subTest(browser=browser), patch.object(launcher.sys, 'platform', 'win32'):
                self.assertEqual(web.original_profile_directory(metadata, path), profile)
                command, _, _ = launcher.prepare_app(self.app(id='pwa-original', path=str(path),
                    web_app=metadata, use_original_data=True), 8899, self.root / 'profiles', transparent=True)
            self.assertEqual(command, [str(path), '--profile-directory=Default', '--app-id=' + APP_ID])

    def test_missing_or_ambiguous_original_profile_never_creates_or_guesses_one(self):
        app = self.app(id='pwa-original', use_original_data=True)
        profiles = self.root / 'profiles'
        self.profile.rmdir()
        with patch.object(launcher.sys, 'platform', 'win32'), self.assertRaisesRegex(ValueError, '资料目录缺失'):
            launcher.prepare_app(app, 8899, profiles, transparent=True)
        self.assertFalse(self.profile.exists())
        self.assertFalse(profiles.exists())
        self.profile.mkdir()
        for local in ('', 'relative/not-a-profile'):
            with self.subTest(local=local), patch.object(launcher.sys, 'platform', 'win32'), \
                    patch.dict(os.environ, {'LOCALAPPDATA': local}), self.assertRaises(ValueError):
                launcher.prepare_app(app, 8899, profiles, transparent=True)
        unknown = self.root / 'custom-browser/chrome.exe'
        unknown.parent.mkdir(); unknown.write_bytes(b'MZ fixture'); unknown.chmod(0o755)
        with patch.object(launcher.sys, 'platform', 'win32'), self.assertRaisesRegex(ValueError, '身份不明确'):
            launcher.prepare_app({**app, 'path': str(unknown)}, 8899, profiles, transparent=True)
        self.assertFalse(profiles.exists())

    def test_original_mode_has_no_nontransparent_or_linux_execution_fallback(self):
        profiles = self.root / 'profiles'
        app = self.app(id='pwa-original', use_original_data=True)
        for native_proxy in (False, True):
            with self.subTest(native_proxy=native_proxy), patch.object(launcher.sys, 'platform', 'win32'), \
                    self.assertRaisesRegex(ValueError, '透明代理'):
                launcher.prepare_app(app, 8899, profiles, native_proxy=native_proxy)
        for transparent in (False, True):
            with self.subTest(transparent=transparent), patch.object(launcher.sys, 'platform', 'linux'), \
                    self.assertRaisesRegex(ValueError, '独立资料'):
                launcher.prepare_app(app, 8899, profiles, transparent=transparent)
        self.assertFalse(profiles.exists())

    def test_launch_uses_real_browser_verified_url_private_profile_and_full_proxy_flags(self):
        app = self.app(id='pwa-1')
        profiles = self.root / 'profiles'
        for transparent, native_proxy in ((True, True), (False, False)):
            with self.subTest(transparent=transparent), patch.object(launcher.sys, 'platform', 'win32'):
                command, environment, detail = launcher.prepare_app(app, 8899, profiles,
                    transparent=transparent, native_proxy=native_proxy)
            self.assertEqual(command[0], str(self.chrome.resolve()))
            self.assertIn('--app=' + START_URL, command)
            self.assertIn('--user-data-dir=' + str(profiles / 'pwa-1'), command)
            self.assertIn('--proxy-server=http://127.0.0.1:8899', command)
            self.assertIn('--disable-quic', command)
            self.assertIn('--force-webrtc-ip-handling-policy=disable_non_proxied_udp', command)
            self.assertIn('--restore-last-session', command)
            self.assertFalse(any(arg.startswith(('--app-id', '--profile-directory')) for arg in command))
            self.assertNotIn('--no-sandbox', command)
            self.assertEqual(environment['HTTP_PROXY'], 'http://127.0.0.1:8899')
            self.assertIn('首次需重新登录', detail)
        self.assertEqual(list(self.profile.iterdir()), [], 'Original profile must stay untouched')
        (profiles / 'pwa-1' / 'private-login-fixture').write_text('persisted login')
        with patch.object(launcher.sys, 'platform', 'win32'):
            command, _, _ = launcher.prepare_app(app, 8899, profiles, transparent=True, native_proxy=True)
        self.assertEqual((profiles / 'pwa-1' / 'private-login-fixture').read_text(), 'persisted login')

    def test_switching_back_to_explicit_private_mode_reuses_private_data_without_source_profile(self):
        app = self.app(id='pwa-1', use_original_data=False)
        profiles = self.root / 'profiles'
        private = profiles / 'pwa-1'
        private.mkdir(parents=True)
        marker = private / 'private-login-fixture'
        marker.write_text('existing isolated session')
        with patch.object(launcher.sys, 'platform', 'win32'):
            command, _, _ = launcher.prepare_app({**app, 'use_original_data': True},
                8899, profiles, transparent=True, native_proxy=True)
            self.assertFalse(any(arg.startswith('--user-data-dir') for arg in command))
            self.profile.rmdir()
            with patch.object(web, 'original_profile_directory', side_effect=AssertionError('Private mode ignores source')):
                command, _, detail = launcher.prepare_app(app, 8899, profiles, transparent=True, native_proxy=True)
        self.assertIn('--user-data-dir=' + str(private), command)
        self.assertIn('--app=' + START_URL, command)
        self.assertFalse(any(arg.startswith(('--app-id', '--profile-directory')) for arg in command))
        self.assertIn(web.WEB_APP_DETAIL, detail)
        self.assertEqual(marker.read_text(), 'existing isolated session')
        self.assertFalse(self.profile.exists())

    def test_ordinary_chromium_reserved_profile_and_proxy_rules_remain(self):
        app = {'id': 'browser', 'label': 'Chrome', 'path': str(self.chrome), 'adapter': 'chromium'}
        for argument in ('--profile-directory=Profile 1', '--user-data-dir=somewhere',
                         '--proxy-server=direct://', '--no-sandbox', '--renderer-cmd-prefix=cmd.exe'):
            with self.subTest(argument=argument), patch.object(launcher.sys, 'platform', 'win32'), self.assertRaises(ValueError):
                launcher.prepare_app({**app, 'args': [argument]}, 8899, self.root / 'profiles', transparent=True, native_proxy=True)


class WebAppManagerTests(WebAppFixture):
    def setUp(self):
        super().setUp()
        from ruleproxy.manager import Manager
        with patch.object(Manager, 'available_apps', return_value=([], False)):
            self.manager = Manager(self.root / 'state', 18879)
        self.addCleanup(self.manager.close)
        self.backend = Mock()
        self.backend.probe.return_value = {'supported': True, 'backend': 'ProxiFyre'}
        self.backend.snapshot.return_value = {'state': 'running'}
        self.manager._windows_backend = self.backend

    def tearDown(self):
        self.manager.active.clear()
        self.manager.core = None
        self.backend.reset_mock(side_effect=True)

    def add(self, app):
        with patch.object(launcher.sys, 'platform', 'win32'), \
                patch('ruleproxy.windows_proxy_policy.normalize_paths'), \
                patch.object(self.manager, '_sync_windows_policy'):
            self.manager.add_app(app)
        return self.manager.settings['apps'][-1]

    def test_add_save_restore_and_state_keep_browser_apps_profiles_separate(self):
        browser = {'label': 'Chrome', 'path': str(self.chrome), 'adapter': 'chromium'}
        self.add(browser)
        self.add(self.app())
        self.add(self.app(web_app=self.metadata(app_id=OTHER_ID), label='Second app'))
        self.add(self.app(web_app=self.metadata(profile_directory='Default'), label='Other profile'))
        with self.assertRaisesRegex(ValueError, '已在列表'):
            self.add(self.app(label='Same application renamed'))
        self.assertEqual(len(self.manager.settings['apps']), 4)
        settings_path = self.root / 'state/settings.json'
        persisted = json.loads(settings_path.read_text())['apps']
        self.assertEqual([app.get('web_app') for app in persisted],
                         [app.get('web_app') for app in self.manager.settings['apps']])
        before = deepcopy(self.manager.settings['apps'])
        self.manager.settings['apps'] = []
        with patch.object(web, 'resolve_start_url', side_effect=AssertionError('Restore never queries original browser')):
            self.manager._restore_settings()
        self.assertEqual(self.manager.settings['apps'], before)
        with patch.object(self.manager, 'available_apps', return_value=([], False)), \
                patch.object(self.manager, 'protection', return_value={'supported': True}), \
                patch.object(self.manager, 'autostart_status', return_value=False):
            state = self.manager.state()
        self.assertEqual([app.get('web_app') for app in state['apps']], [app.get('web_app') for app in before])

    def test_original_pwa_choice_and_compatibility_survive_save_restore_without_migration(self):
        saved = self.add(self.app())
        before_metadata = deepcopy(saved['web_app'])
        with patch.object(launcher.sys, 'platform', 'win32'):
            self.manager.set_app_profile(saved['id'], True)
        self.assertIs(saved['use_original_data'], True)
        self.assertEqual(saved['compatibility'], web.WEB_APP_ORIGINAL_DETAIL)
        settings_path = self.root / 'state/settings.json'
        persisted = json.loads(settings_path.read_text())['apps'][0]
        self.assertEqual(persisted, saved)
        self.manager.settings['apps'] = []
        with patch.object(web, 'original_profile_directory', side_effect=AssertionError('No profile reads on restore')):
            self.manager._restore_settings()
        restored = self.manager.app(saved['id'])
        self.assertEqual(restored, persisted)
        self.profile.rmdir()
        with patch.object(launcher.sys, 'platform', 'win32'):
            self.manager.set_app_profile(saved['id'], False)
        self.assertIs(restored['use_original_data'], False)
        self.assertEqual(restored['web_app'], before_metadata)
        self.assertEqual(restored['compatibility'], web.WEB_APP_DETAIL)
        self.assertFalse((self.root / 'state/profiles').exists())
        self.assertFalse(self.profile.exists())

    def test_original_pwa_toggle_failures_roll_back_choice_and_compatibility(self):
        saved = self.add(self.app())
        before = deepcopy(saved)
        settings_path = self.root / 'state/settings.json'
        persisted = settings_path.read_bytes()
        for value in (None, 'true', 0, 1, [], {}):
            with self.subTest(value=value), patch.object(launcher.sys, 'platform', 'win32'), \
                    self.assertRaisesRegex(ValueError, '布尔值'):
                self.manager.set_app_profile(saved['id'], value)
        with patch.object(launcher.sys, 'platform', 'win32'), \
                patch.object(self.manager, '_save', side_effect=OSError('disk full')), \
                self.assertRaisesRegex(OSError, 'disk full'):
            self.manager.set_app_profile(saved['id'], True)
        self.assertEqual(saved, before)
        self.assertEqual(settings_path.read_bytes(), persisted)
        self.assertEqual(self.manager._profile_preparing, set())
        self.profile.rmdir()
        with patch.object(launcher.sys, 'platform', 'win32'), self.assertRaisesRegex(ValueError, '资料目录缺失'):
            self.manager.set_app_profile(saved['id'], True)
        self.assertEqual(saved, before)
        self.assertEqual(settings_path.read_bytes(), persisted)
        self.assertEqual(self.manager._profile_preparing, set())

    def test_original_pwa_toggle_keeps_running_instance_and_preparation_guards(self):
        saved = self.add(self.app())
        process = Mock(poll=Mock(return_value=None))
        self.manager.active[saved['id']] = (process, None)
        with patch.object(launcher.sys, 'platform', 'win32'), self.assertRaisesRegex(ValueError, '先关闭此工具启动'):
            self.manager.set_app_profile(saved['id'], True)
        process.terminate.assert_not_called()
        self.assertFalse(saved['use_original_data'])
        self.manager.active.clear()
        self.manager._profile_preparing.add(saved['id'])
        with patch.object(launcher.sys, 'platform', 'win32'), self.assertRaisesRegex(ValueError, '正在准备'):
            self.manager.set_app_profile(saved['id'], True)
        self.manager._profile_preparing.clear()

    def test_original_profile_stat_check_releases_manager_lock(self):
        saved = self.add(self.app())
        acquired = threading.Event()

        def worker():
            with self.manager.lock:
                acquired.set()

        def check(metadata, path):
            self.assertEqual(metadata, self.metadata())
            self.assertEqual(path, self.chrome)
            thread = threading.Thread(target=worker)
            thread.start()
            try:
                self.assertTrue(acquired.wait(2))
                self.assertIn(saved['id'], self.manager._profile_preparing)
                with self.assertRaisesRegex(ValueError, '正在检查'):
                    self.manager.launch(saved['id'])
            finally:
                thread.join(2)
            return self.profile

        with patch.object(launcher.sys, 'platform', 'win32'), \
                patch.object(web, 'original_profile_directory', side_effect=check):
            self.manager.set_app_profile(saved['id'], True)
        self.assertEqual(self.manager._profile_preparing, set())

    def test_restore_drops_bad_web_metadata_and_duplicate_identity_not_other_profiles(self):
        first = deepcopy(self.add(self.app()))
        other = deepcopy(self.add(self.app(web_app=self.metadata(profile_directory='Default'))))
        records = [first, other, {**first, 'id': 'duplicate-id'},
                   {**first, 'id': 'unsafe-url', 'web_app': self.metadata(start_url='file:///C:/secret')},
                   {**first, 'id': 'extra-field', 'web_app': {**self.metadata(), 'user_data_dir': str(self.profile)}}]
        path = self.root / 'state/settings.json'
        path.write_text(json.dumps({**self.manager.settings, 'apps': records}))
        before = path.read_bytes()
        self.manager.settings['apps'] = []
        self.manager._restore_settings()
        self.assertEqual(self.manager.settings['apps'], [first, other])
        self.assertTrue(self.manager._settings_need_backup)
        self.assertEqual(path.read_bytes(), before, 'Restore must not rewrite malformed originals')

    def test_same_named_pwa_profiles_get_distinct_shortcut_filenames(self):
        first = self.add(self.app())
        second = self.add(self.app(web_app=self.metadata(profile_directory='Default')))
        recorded = []
        def create(app, **kwargs):
            recorded.append(deepcopy(app))
            return [self.root / (app['label'] + ' (RuleProxy).lnk')]
        with patch('ruleproxy.manager.create_shortcut_files', side_effect=create):
            one = self.manager.create_shortcuts(first['id'])
            two = self.manager.create_shortcuts(second['id'])
        self.assertNotEqual(one, two)
        self.assertEqual([app['id'] for app in recorded], [first['id'], second['id']])
        self.assertIn('Profile 1', recorded[0]['label'])
        self.assertIn('Default', recorded[1]['label'])
        self.assertEqual(first['label'], 'Gemini')
        self.assertEqual(second['label'], 'Gemini')
        self.assertTrue(all(Path(path).stem.endswith(' (RuleProxy)') for path in one + two))

    def test_http_api_preserves_identity_and_rejects_forged_metadata_without_partial_save(self):
        from ruleproxy.server import PanelServer
        server = PanelServer(0, self.manager)
        thread = threading.Thread(target=server.serve_forever, daemon=True)
        thread.start()

        def request(path, payload):
            connection = http.client.HTTPConnection('127.0.0.1', server.server_port, timeout=5)
            try:
                connection.request('POST', path, json.dumps(payload).encode(), headers={
                    'Content-Type': 'application/json', 'X-RuleProxy-Token': self.manager.token})
                response = connection.getresponse()
                return response.status, json.loads(response.read())
            finally:
                connection.close()

        try:
            with patch.object(launcher.sys, 'platform', 'win32'), \
                    patch('ruleproxy.windows_proxy_policy.normalize_paths'), \
                    patch.object(self.manager, 'available_apps', return_value=([], False)), \
                    patch.object(self.manager, 'protection', return_value={'supported': True}), \
                    patch.object(self.manager, 'autostart_status', return_value=False):
                status, state = request('/api/apps', self.app())
                self.assertEqual(status, 200)
                self.assertEqual(state['apps'][0]['web_app'], self.metadata())
                saved = deepcopy(self.manager.settings['apps'])
                for invalid in (self.metadata(start_url='javascript:alert(1)'),
                                {**self.metadata(), 'user_data_dir': str(self.profile)}, None):
                    status, response = request('/api/apps', self.app(web_app=invalid))
                    self.assertEqual(status, 400)
                    self.assertIn('error', response)
                    self.assertEqual(self.manager.settings['apps'], saved)
                status, _ = request('/api/apps/' + saved[0]['id'] + '/profile', {'use_original_data': True})
                self.assertEqual(status, 200)
                self.assertTrue(self.manager.settings['apps'][0]['use_original_data'])
                self.assertEqual(self.manager.settings['apps'][0]['compatibility'], web.WEB_APP_ORIGINAL_DETAIL)
                for value in (None, 1, 'true'):
                    status, _ = request('/api/apps/' + saved[0]['id'] + '/profile', {'use_original_data': value})
                    self.assertEqual(status, 400)
                    self.assertTrue(self.manager.settings['apps'][0]['use_original_data'])
                status, state = request('/api/apps/' + saved[0]['id'] + '/profile', {'use_original_data': False})
                self.assertEqual(status, 200)
                self.assertEqual(state['apps'][0]['compatibility'], web.WEB_APP_DETAIL)
                self.assertEqual(self.manager.settings['apps'], saved)
        finally:
            server.shutdown(); server.server_close(); thread.join(5)

    def test_policy_uses_one_actual_browser_path_before_launch_and_keeps_shared_route(self):
        pwa = self.add(self.app())
        second = self.add(self.app(web_app=self.metadata(app_id=OTHER_ID), label='Another app'))
        self.manager.core = Mock(pid=1234, poll=Mock(return_value=None))
        process = Mock(pid=5678, poll=Mock(return_value=None))
        order = []
        self.backend.apply.side_effect = lambda *args: order.append(('policy', args[0]))

        def launch(command, env, **kwargs):
            order.append(('launch', command))
            self.assertEqual(kwargs, {'native_proxy_port': self.manager.mixed_port})
            self.assertEqual(env['HTTP_PROXY'], f'http://127.0.0.1:{self.manager.mixed_port}')
            return process

        with patch.object(launcher.sys, 'platform', 'win32'), \
                patch('ruleproxy.windows_app_process.launch', side_effect=launch), \
                patch.object(self.manager, 'protection', return_value={'supported': True}):
            result = self.manager.launch(pwa['id'])
            self.assertEqual(order[0], ('policy', [str(self.chrome)]))
            self.assertEqual(order[1][0], 'launch')
            self.assertEqual(order[1][1][0], str(self.chrome))
            self.assertIn('--app=' + START_URL, order[1][1])
            self.assertIn('--proxy-server=http://127.0.0.1:' + str(self.manager.mixed_port), order[1][1])
            self.assertIn('首次需重新登录', result['detail'])
            self.assertFalse(self.manager.uses_system_proxy, 'PWA must not expand system proxy scope')
            self.manager.settings['apps'][0]['enabled'] = False
            self.assertEqual(self.manager._selected_windows_paths(), [str(self.chrome)])
            self.manager._windows_paths = [str(self.chrome)]
            with patch.object(self.manager, 'available_apps', return_value=([], False)), \
                    patch.object(self.manager, 'autostart_status', return_value=False):
                state = self.manager.state()
            self.assertTrue(state['apps'][0]['routed'], 'Shared exe stays routed via the other enabled app')
            self.assertFalse(state['apps'][0]['enabled'])
            second['enabled'] = False
            self.assertEqual(self.manager._selected_windows_paths(), [])

    def test_policy_failure_blocks_web_app_process(self):
        saved = self.add(self.app())
        self.manager.core = Mock(pid=1234, poll=Mock(return_value=None))
        self.backend.apply.side_effect = OSError('Proxy path policy failed')
        with patch.object(launcher.sys, 'platform', 'win32'), \
                patch('ruleproxy.windows_app_process.launch') as launch, \
                patch.object(self.manager, 'protection', return_value={'supported': True}), \
                self.assertRaises(OSError):
            self.manager.launch(saved['id'])
        launch.assert_not_called()

    def test_original_launch_keeps_policy_and_owned_bootstrap_state_honest_after_handoff(self):
        pwa = self.add(self.app(use_original_data=True))
        self.manager.core = Mock(pid=1234, poll=Mock(return_value=None))
        bootstrap = Mock(pid=5678, poll=Mock(return_value=None))
        with patch.object(launcher.sys, 'platform', 'win32'), \
                patch('ruleproxy.windows_app_process.launch', return_value=bootstrap) as launch, \
                patch.object(self.manager, 'protection', return_value={'supported': True}), \
                patch.object(self.manager, 'available_apps', return_value=([], False)), \
                patch.object(self.manager, 'autostart_status', return_value=False):
            result = self.manager.launch(pwa['id'])
            self.assertEqual(launch.call_args.args[0][:3],
                [str(self.chrome), '--profile-directory=Profile 1', '--app-id=' + APP_ID])
            self.assertEqual(launch.call_args.kwargs, {'native_proxy_port': self.manager.mixed_port})
            self.assertEqual(self.manager._windows_paths, [str(self.chrome)])
            self.assertIn(web.WEB_APP_ORIGINAL_DETAIL, result['detail'])
            self.assertNotIn('首次需重新登录', result['detail'])
            self.assertIn('沿用其启动和代理设置', result['detail'])
            self.assertIn('已有进程不会由面板接管或关闭', result['detail'])
            self.assertIn('本工具新建的浏览器实例，其共用窗口会随实例一同关闭。', result['detail'])
            self.assertIn('Windows 应用模式按浏览器程序路径代理', result['detail'])
            self.assertEqual(result['pid'], bootstrap.pid)
            self.assertTrue(self.manager.state()['apps'][0]['active'])
            # A same-profile browser can accept the request while our new
            # bootstrap exits. An exit is not evidence that its window closed.
            bootstrap.poll.return_value = 0
            state = self.manager.state()['apps'][0]
            self.assertFalse(state['active'])
            self.assertFalse(state['cleanup_pending'])
            self.assertTrue(state['routed'])
            self.assertFalse(self.manager.has_active_apps())
            self.assertEqual(self.manager.active, {pwa['id']: (bootstrap, None)})
            self.manager.stop_app(pwa['id'])
            bootstrap.terminate.assert_called_once_with()
            bootstrap.wait.assert_called_once_with(timeout=10)
            self.assertEqual(self.manager.active, {})
            self.assertFalse(self.manager.uses_system_proxy)
        self.assertFalse((self.root / 'state/profiles').exists())


if __name__ == '__main__':
    unittest.main()
