"""Linux desktop PWA discovery with temporary ELF/metadata fixtures only."""
from copy import deepcopy
import json
import os
from pathlib import Path
import shlex
import sys
import tempfile
import unittest
from unittest.mock import patch

from ruleproxy import linux_web_apps as web


APP_ID = 'gdfaincndogidkdcdkhapmbffkckdkhn'
OTHER_ID = 'a' * 32
START_URL = 'https://gemini.google.com/app'


def varint(value):
    result = bytearray()
    while value >= 128:
        result.append((value & 127) | 128)
        value >>= 7
    result.append(value)
    return bytes(result)


def field(number, value):
    if isinstance(value, int):
        return varint(number << 3) + varint(value)
    if isinstance(value, str):
        value = value.encode('utf-8')
    return varint((number << 3) | 2) + varint(len(value)) + value


@unittest.skipUnless(sys.platform.startswith('linux'), 'Linux executable fixtures')
class LinuxWebAppFixture(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        self.root = Path(self.temporary.name) / '用户 空间'
        self.system = self.root / 'system'
        self.home = self.root / 'home'
        self.config = self.home / '配置'
        self.profile = self.config / 'google-chrome/Profile 1'
        self.profile.mkdir(parents=True)
        self.chrome = self.relocate('/opt/google/chrome/chrome')
        self.make_elf(self.chrome)
        locations = {self.relocate(path): value for path, value in web._BROWSER_LOCATIONS.items()}
        wrappers = {self.relocate(path): tuple(self.relocate(target) for target in targets)
                    for path, targets in web._WRAPPER_TARGETS.items()}
        for context in (
            patch.dict(web._BROWSER_LOCATIONS, locations, clear=True),
            patch.dict(web._WRAPPER_TARGETS, wrappers, clear=True),
            patch.dict(os.environ, {'HOME': str(self.home), 'XDG_CONFIG_HOME': str(self.config),
                                    'PATH': str(self.root / 'path')}, clear=True),
            patch('subprocess.Popen', side_effect=AssertionError('Discovery must not execute programs')),
            patch('subprocess.run', side_effect=AssertionError('Discovery must not execute programs')),
            patch('os.system', side_effect=AssertionError('Discovery must not execute a shell')),
        ):
            context.start()
            self.addCleanup(context.stop)

    def relocate(self, path):
        return self.system / Path(path).relative_to('/')

    def make_elf(self, path, content=b'\x7fELF fixture: never executed', mode=0o755):
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_bytes(content)
        path.chmod(mode)
        return path

    def command(self, *args, program=None):
        # Percent is escaped at the Desktop Entry layer, before shlex quoting.
        return ' '.join(shlex.quote(str(value).replace('%', '%%'))
                        for value in (program or self.chrome, *args))

    def desktop(self, **changes):
        return {'Type': 'Application', 'Name': 'Gemini 网页应用',
                'Exec': self.command('--profile-directory=Profile 1', '--app-id=' + APP_ID), **changes}

    def metadata(self, **changes):
        return {'browser': 'chrome', 'profile_directory': 'Profile 1', 'app_id': APP_ID,
                'start_url': START_URL, 'launch_mode': 'isolated_url', **changes}

    def parse(self, **changes):
        intent, candidate = web.from_desktop_entry(self.desktop(**changes))
        self.assertIs(intent, True)
        return candidate

    def legacy_metadata(self, profile=None, url=START_URL):
        profile = profile or self.profile
        profile.mkdir(parents=True, exist_ok=True)
        document = {'extensions': {'settings': {APP_ID: {'state': 1, 'manifest': {
            'app': {'launch': {'web_url': url}}}}}}}
        (profile / 'Preferences').write_text(json.dumps(document), encoding='utf-8')

    def proto(self, url=START_URL):
        return field(1, field(1, url)) + field(8, 1)


class LinuxDesktopDiscoveryTests(LinuxWebAppFixture):
    def test_app_id_and_explicit_profile_produce_exact_candidate_schema(self):
        self.legacy_metadata()
        before = (self.profile / 'Preferences').read_bytes()
        candidate = self.parse()
        self.assertEqual(candidate, {
            'label': 'Gemini 网页应用', 'path': str(self.chrome), 'adapter': 'chromium',
            'args': [], 'web_app': self.metadata(), 'use_original_data': False,
            'category': 'web-app', 'source': 'linux-web-app', 'launchable': True,
            'compatibility': web.WEB_APP_DETAIL,
        })
        self.assertEqual((self.profile / 'Preferences').read_bytes(), before)
        self.assertEqual(set(candidate['web_app']),
                         {'browser', 'profile_directory', 'app_id', 'start_url', 'launch_mode'})
        self.assertIn('Linux 应用模式下', candidate['compatibility'])
        self.assertIn('网络命名空间实例', candidate['compatibility'])
        self.assertNotIn('Windows', candidate['compatibility'])

    def test_non_web_entries_remain_eligible_for_ordinary_discovery(self):
        for value in (self.command('%U'), self.command('--new-window', 'https://example.test'),
                      self.command('--profile-directory=Default'),
                      self.command('https://example.test/?arg=--app=value'), ''):
            with self.subTest(value=value):
                self.assertEqual(web.from_desktop_entry(self.desktop(Exec=value)), (False, None))
        self.assertEqual(web.from_desktop_entry({}), (False, None))
        self.assertEqual(web.from_desktop_entry(None), (False, None))

    def test_type_name_exec_and_visibility_fields_are_strict(self):
        changes = ({'Type': ''}, {'Type': 'Link'}, {'Type': 'Directory'}, {'Type': 'application'},
                   {'Name': ''}, {'Name': '  '}, {'Name': 'x' * 201}, {'Name': 'bad\nname'},
                   {'Hidden': 'true'}, {'Hidden': 'TRUE'}, {'Hidden': '1'}, {'Hidden': None},
                   {'NoDisplay': 'true'}, {'NoDisplay': 'yes'}, {'NoDisplay': False})
        with patch.object(web, '_browser_target', side_effect=AssertionError('Suppressed entry')):
            for change in changes:
                with self.subTest(change=change):
                    self.assertIsNone(self.parse(**change))
            missing_type = self.desktop()
            del missing_type['Type']
            self.assertEqual(web.from_desktop_entry(missing_type), (True, None))
        self.legacy_metadata()
        self.assertIsNotNone(self.parse(Hidden='false', NoDisplay='false',
                                       Categories='WebBrowser;Network;', Icon='ignored'))

    def test_linux_shlex_quoting_separate_values_and_tabs(self):
        self.legacy_metadata()
        raw = f'{shlex.quote(str(self.chrome))}\t--profile-directory "Profile 1" --app-id {APP_ID} %U'
        self.assertEqual(self.parse(Exec=raw)['web_app'], self.metadata())
        joined = self.command('--app=' + START_URL).replace('--app=', '--a"pp"=')
        self.assertEqual(self.parse(Exec=joined)['web_app']['start_url'], START_URL)

    def test_independent_standard_field_codes_are_removed(self):
        for code in ('%f', '%F', '%u', '%U', '%i', '%c', '%k', '%d', '%D', '%n', '%N', '%v', '%m'):
            with self.subTest(code=code):
                raw = self.command('--app=' + START_URL) + ' ' + code
                candidate = self.parse(Exec=raw)
                self.assertEqual(candidate['args'], [])
                self.assertEqual(candidate['web_app']['start_url'], START_URL)

    def test_percent_literal_escaping_preserves_url_and_unicode_program_path(self):
        binary = self.make_elf(self.root / '百分比 % 目录/chrome')
        url = 'https://例子.测试/应用%25?value=two%20words&encoded=%25'
        candidate = self.parse(Exec=self.command('--app=' + url, program=binary))
        self.assertEqual(candidate['path'], str(binary))
        self.assertEqual(candidate['web_app']['start_url'], url)

    def test_embedded_unknown_or_incomplete_field_codes_reject_entire_entry(self):
        for suffix in ('/%u', '/%U', '/%c', '/%k', '/%i', '/%z', '/%', '/%20', '/%%%u'):
            with self.subTest(suffix=suffix):
                raw = self.command() + ' --app=https://example.test' + suffix
                self.assertIsNone(self.parse(Exec=raw))
        raw = self.command() + ' --a"pp"=https://example.test/%u'
        self.assertIsNone(self.parse(Exec=raw))
        self.assertIsNone(self.parse(Exec=self.command('--app=' + START_URL) + ' %%'))
        self.assertIsNone(self.parse(Exec='%u --app=' + START_URL))

    def test_url_entries_default_identity_and_never_read_source_profiles(self):
        with patch.object(web, 'resolve_start_url', side_effect=AssertionError('Explicit URL')), \
                patch.object(web, '_profile_path', side_effect=AssertionError('Explicit URL')):
            default = self.parse(Exec=self.command('--app=' + START_URL))
            specified = self.parse(Exec=self.command('--app=' + START_URL, '--profile-directory=Profile 2'))
        self.assertEqual(default['web_app'], self.metadata(profile_directory='Default', app_id=''))
        self.assertEqual(specified['web_app'], self.metadata(profile_directory='Profile 2', app_id=''))

    def test_http_https_local_ipv6_and_unicode_start_urls(self):
        for url in ('http://localhost:8888/app', 'https://example.test', 'http://[::1]:9000/',
                    'https://example.test/a?b=c#d', 'https://例子.测试/应用',
                    'https://example.test/a%20b?value=%25'):
            with self.subTest(url=url):
                self.assertEqual(self.parse(Exec=self.command('--app=' + url))['web_app']['start_url'], url)

    def test_bad_urls_and_non_http_schemes_remain_web_intent(self):
        for url in ('javascript:alert(1)', 'file:///etc/passwd', '//example.test', 'chrome://settings',
                    'https://user:password@example.test', 'https://example.test\\evil',
                    'https://example.test/\n--proxy-server=direct://', 'https://exa mple.test',
                    'http://[::1', 'https://example.test:0', 'https://example.test:65536',
                    'https://example.test/%oops', 'https://%65xample.test', 'https://-bad.test',
                    'https://example.test/a"b', 'https://example.test/\ud800'):
            with self.subTest(url=url):
                self.assertIsNone(self.parse(Exec=self.command('--app=' + url)))

    def test_bad_or_unsupported_arguments_never_downgrade_to_ordinary_browser(self):
        base = ['--profile-directory=Profile 1', '--app-id=' + APP_ID]
        for extra in ('--user-data-dir=/elsewhere', '--proxy-server=direct://', '--proxy-pac-url=x',
                      '--no-proxy-server', '--no-sandbox', '--disable-setuid-sandbox',
                      '--disable-namespace-sandbox', '--disable-seccomp-filter-sandbox',
                      '--host-resolver-rules=MAP * 127.0.0.1', '--force-webrtc-ip-handling-policy=default',
                      '--remote-debugging-port=9222', '--renderer-cmd-prefix=sh', '--utility-cmd-prefix=sh',
                      '--browser-subprocess-path=/bin/sh', '--gpu-launcher=sh', '--plugin-launcher=sh',
                      '--zygote-cmd-prefix=sh', '--load-extension=/elsewhere', '--disable-extensions-except=x',
                      '--app-launch-source=4', '--app-url=' + START_URL, '--new-window',
                      'https://another.test', '--', ';', '|', '$(id)', '`id`', '#ignored'):
            with self.subTest(extra=extra):
                self.assertIsNone(self.parse(Exec=self.command(*base, extra)))

    def test_duplicate_missing_invalid_or_conflicting_switches_are_rejected(self):
        for args in (
            ['--app-id=' + APP_ID], ['--app-id=', '--profile-directory=Default'],
            ['--app-id=' + APP_ID, '--profile-directory'],
            ['--app-id=' + APP_ID, '--profile-directory=../Other'],
            ['--app-id=' + APP_ID, '--profile-directory=Profile 1000000'],
            ['--app-id=' + APP_ID, '--profile-directory=Default/Other'],
            ['--app-id=' + 'z' * 32, '--profile-directory=Default'],
            ['--app-id=' + 'a' * 31, '--profile-directory=Default'],
            ['--app-id=' + APP_ID, '--profile-directory=Default', '--app-id=' + OTHER_ID],
            ['--app-id=' + APP_ID, '--profile-directory=Default', '--profile-directory=Default'],
            ['--app=' + START_URL, '--app=' + START_URL],
            ['--app=' + START_URL, '--app-id=' + APP_ID, '--profile-directory=Default'],
            ['--app='], ['--app'], ['--app-url=' + START_URL], ['--app-launch-source=4'],
        ):
            with self.subTest(args=args):
                self.assertIsNone(self.parse(Exec=self.command(*args)))

    def test_malformed_quoting_control_characters_and_size_limits_keep_intent(self):
        base = self.command()
        for suffix in (' --app="unterminated', ' --app=https://example.test\0bad',
                       ' --app=https://example.test\n--new-window',
                       ' --app=https://example.test/' + 'x' * 4096,
                       ' --app=' + START_URL + ' %U' * 64,
                       ' --app=' + START_URL + ' ' * 16384):
            with self.subTest(suffix=suffix[:80]):
                self.assertIsNone(self.parse(Exec=base + suffix))
        for raw in (base + ' --a"pp"=' + START_URL + ' "unterminated',
                    base + ' --a\\pp=' + START_URL + '\n',
                    base + ' --a"pp"=' + START_URL + ' %U' * 64):
            with self.subTest(raw=raw[:100]):
                self.assertIsNone(self.parse(Exec=raw))

    def test_profiles_app_ids_and_browser_category_have_separate_identity(self):
        with patch.object(web, 'resolve_start_url', return_value=START_URL):
            one = self.parse()
            other_profile = self.parse(Exec=self.command('--profile-directory=Default', '--app-id=' + APP_ID))
            other_app = self.parse(Exec=self.command('--profile-directory=Profile 1', '--app-id=' + OTHER_ID))
        identities = {(row['path'], row['category'], row['web_app']['profile_directory'],
                       row['web_app']['app_id'] or row['web_app']['start_url'])
                      for row in (one, other_profile, other_app)}
        self.assertEqual(len(identities), 3)
        self.assertEqual({row['path'] for row in (one, other_profile, other_app)}, {str(self.chrome)})
        self.assertEqual({row['category'] for row in (one, other_profile, other_app)}, {'web-app'})
        self.assertNotEqual(one['category'], 'browser')
        self.assertEqual(web.from_desktop_entry(self.desktop(Exec=self.command())), (False, None))


class LinuxBrowserResolutionTests(LinuxWebAppFixture):
    def test_try_exec_must_resolve_to_same_browser_and_actual_binary(self):
        exec_value = self.command('--app=' + START_URL)
        wrapper = self.make_elf(self.relocate('/usr/bin/google-chrome'), b'#!/bin/sh\nexit 99\n')
        for try_exec in ('', '  ', str(self.chrome), str(wrapper)):
            with self.subTest(try_exec=try_exec):
                self.assertTrue(self.parse(Exec=exec_value, TryExec=try_exec)['launchable'])
        with patch.dict(os.environ, {'PATH': str(wrapper.parent)}):
            self.assertTrue(self.parse(Exec=exec_value, TryExec='google-chrome')['launchable'])
        other = self.make_elf(self.root / 'other/chrome')
        edge = self.make_elf(self.root / 'other/msedge')
        for try_exec in (str(self.root / 'missing/chrome'), str(other), str(edge),
                         str(self.chrome) + ' --app=' + START_URL, 'env google-chrome', None):
            with self.subTest(try_exec=try_exec):
                self.assertIsNone(self.parse(Exec=exec_value, TryExec=try_exec))

    def test_home_ancestor_and_config_tree_binaries_are_not_discovered(self):
        for path in (self.home / 'chrome', self.home.parent / 'chrome',
                     self.home / '.config/google-chrome/chrome', self.config / 'bin/chrome'):
            with self.subTest(path=path):
                binary = self.make_elf(path)
                self.assertIsNone(self.parse(Exec=self.command('--app=' + START_URL, program=binary)))
        alternate = self.root / 'chrome-config'
        binary = self.make_elf(alternate / 'google-chrome/chrome')
        with patch.dict(os.environ, {'CHROME_CONFIG_HOME': str(alternate)}):
            self.assertIsNone(self.parse(Exec=self.command('--app=' + START_URL, program=binary)))
        mount = self.root / 'independent-mount'
        sibling = self.make_elf(mount / 'chrome')
        with patch.dict(os.environ, {'XDG_CONFIG_HOME': str(mount / 'config')}):
            self.assertIsNone(self.parse(Exec=self.command('--app=' + START_URL, program=sibling)))

    def test_known_install_wrapper_maps_to_real_elf_without_opening_script(self):
        for browser, _, binaries, wrappers in web._INSTALLS:
            actual = self.make_elf(self.relocate(binaries[0]))
            for name in wrappers:
                wrapper = self.make_elf(self.relocate(name), b'#!/bin/sh\nexit 99\n')
                real_open = os.open

                def checked_open(path, *args, **kwargs):
                    self.assertNotEqual(Path(path), wrapper, 'Wrapper content must not be read')
                    return real_open(path, *args, **kwargs)

                with self.subTest(wrapper=name), patch.object(web.os, 'open', side_effect=checked_open):
                    candidate = self.parse(Exec=self.command('--app=' + START_URL, program=wrapper))
                self.assertEqual(candidate['path'], str(actual))
                self.assertEqual(candidate['web_app']['browser'], browser)

    def test_path_lookup_and_system_wrapper_symlink_are_resolved_without_execution(self):
        wrapper = self.make_elf(self.relocate('/opt/google/chrome/google-chrome'), b'#!/bin/sh\nexit 99\n')
        entry = self.relocate('/usr/bin/google-chrome')
        entry.parent.mkdir(parents=True, exist_ok=True)
        entry.symlink_to(wrapper)
        with patch.dict(os.environ, {'PATH': str(entry.parent)}):
            candidate = self.parse(Exec='google-chrome --app=' + START_URL)
        self.assertEqual(candidate['path'], str(self.chrome))

    def test_missing_actual_wrapper_binary_does_not_fall_back_to_script(self):
        wrapper = self.make_elf(self.relocate('/usr/bin/google-chrome'), b'#!/bin/sh\nexit 99\n')
        self.chrome.unlink()
        with patch.object(web.os, 'open', side_effect=AssertionError('No script reads')):
            self.assertIsNone(self.parse(Exec=self.command('--app=' + START_URL, program=wrapper)))

    def test_ambiguous_wrapper_installations_are_not_chosen_arbitrarily(self):
        wrapper = self.make_elf(self.relocate('/usr/bin/chromium'), b'#!/bin/sh\nexit 99\n')
        for actual in web._WRAPPER_TARGETS[wrapper]:
            self.make_elf(actual)
        self.assertIsNone(self.parse(Exec=self.command('--app=' + START_URL, program=wrapper)))

    def test_all_known_linux_names_accept_actual_elf_and_reject_windows_names(self):
        for browser, names in web._EXECUTABLES.items():
            for name in names:
                with self.subTest(browser=browser, name=name):
                    binary = self.make_elf(self.root / 'portable' / name)
                    candidate = self.parse(Exec=self.command('--app=' + START_URL, program=binary))
                    self.assertEqual(candidate['web_app']['browser'], browser)
                    self.assertEqual(web.validate_web_app(candidate['web_app'], binary), candidate['web_app'])
        for name in ('chrome.exe', 'msedge.exe', 'brave.exe', 'vivaldi.exe', 'not-a-browser'):
            binary = self.make_elf(self.root / 'portable' / name)
            self.assertIsNone(self.parse(Exec=self.command('--app=' + START_URL, program=binary)))

    def test_scripts_shell_env_flatpak_snap_and_interpreters_are_not_run(self):
        for name in ('google-chrome', 'sh', 'bash', 'env', 'flatpak', 'snap', 'python3', 'xdg-open'):
            with self.subTest(name=name):
                program = self.make_elf(self.root / 'custom' / name, b'#!/bin/sh\nexit 99\n')
                self.assertIsNone(self.parse(Exec=self.command('--app=' + START_URL, program=program)))
        for raw in ('env FOO=1 google-chrome --app=' + START_URL,
                    'flatpak run org.chromium.Chromium --app=' + START_URL,
                    "sh -c 'google-chrome --app=" + START_URL + "'",
                    'snap run chromium --app=' + START_URL):
            self.assertIsNone(self.parse(Exec=raw))

    def test_elf_signature_executable_permission_and_regular_file_are_required(self):
        for content, mode in ((b'MZ other platform', 0o755), (b'#!/bin/sh', 0o755),
                              (b'\x7fELF fixture', 0o644), (b'', 0o755)):
            with self.subTest(content=content, mode=mode):
                self.make_elf(self.chrome, content, mode)
                self.assertIsNone(self.parse(Exec=self.command('--app=' + START_URL)))
        self.chrome.unlink()
        self.chrome.mkdir()
        self.assertIsNone(self.parse(Exec=self.command('--app=' + START_URL)))
        self.chrome.rmdir()
        os.mkfifo(self.chrome)
        self.assertIsNone(self.parse(Exec=self.command('--app=' + START_URL)))

    def test_relative_paths_missing_path_programs_and_mismatched_symlinks_are_rejected(self):
        for program in ('./chrome', '../chrome', '~/chrome', 'chrome'):
            with self.subTest(program=program):
                self.assertIsNone(self.parse(Exec=self.command('--app=' + START_URL, program=program)))
        other = self.make_elf(self.root / 'other/msedge')
        self.chrome.unlink()
        self.chrome.symlink_to(other)
        self.assertIsNone(self.parse(Exec=self.command('--app=' + START_URL)))


class LinuxMetadataResolutionTests(LinuxWebAppFixture):
    def test_modern_reader_requests_exact_selected_key_and_preserves_profile(self):
        database = self.profile / 'Sync Data/LevelDB'
        database.mkdir(parents=True)
        key = b'web_apps-dt-' + APP_ID.encode('ascii')
        with patch('ruleproxy.web_app_leveldb.read_values', return_value={key: self.proto()}) as reader:
            candidate = self.parse()
        reader.assert_called_once_with(database, {key})
        self.assertEqual(candidate['web_app'], self.metadata())

    def test_secondary_supported_registry_uses_same_selected_key(self):
        database = self.profile / 'Web Applications/WebApp Database'
        database.mkdir(parents=True)
        key = b'web_apps-dt-' + APP_ID.encode('ascii')
        with patch('ruleproxy.web_app_leveldb.read_values', return_value={key: self.proto()}) as reader:
            self.assertTrue(self.parse()['launchable'])
        reader.assert_called_once_with(database, {key})

    def test_modern_deletion_or_failure_never_resurrects_legacy_metadata(self):
        self.legacy_metadata()
        (self.profile / 'Sync Data/LevelDB').mkdir(parents=True)
        for result, error in (({}, None), (None, ValueError('Unknown format')),
                              (None, PermissionError('Snapshot locked'))):
            with self.subTest(error=error), \
                    patch('ruleproxy.web_app_leveldb.read_values', return_value=result, side_effect=error), \
                    patch.object(web, '_legacy_start_url', side_effect=AssertionError('No legacy fallback')):
                candidate = self.parse()
            self.assertEqual(candidate['web_app']['start_url'], '')
            self.assertFalse(candidate['launchable'])
            self.assertTrue(candidate['unavailable_reason'])

    def test_missing_unreadable_or_invalid_metadata_preserves_disabled_identity(self):
        for result, error in ((None, None), (None, ValueError('Unknown format')),
                              (None, PermissionError('Locked')), (None, RuntimeError('Symlink loop')),
                              ('javascript:alert(1)', None), ('https://bad host', None)):
            with self.subTest(result=result, error=error), \
                    patch.object(web, 'resolve_start_url', return_value=result, side_effect=error):
                candidate = self.parse()
            self.assertEqual(candidate['web_app'], self.metadata(start_url=''))
            self.assertFalse(candidate['launchable'])
            self.assertTrue(candidate['unavailable_reason'])

    def test_known_products_and_channels_only_use_their_corresponding_config_root(self):
        for browser, config_dir, binaries, _ in web._INSTALLS:
            for name in binaries:
                with self.subTest(binary=name):
                    binary = self.make_elf(self.relocate(name))
                    profile = self.config / config_dir / 'Default'
                    self.legacy_metadata(profile)
                    candidate = self.parse(Exec=self.command('--app-id=' + APP_ID,
                                                            '--profile-directory=Default', program=binary))
                    self.assertTrue(candidate['launchable'])
                    self.assertEqual(candidate['web_app']['browser'], browser)
                    self.assertEqual(web._profile_path(binary, browser, 'Default'), profile)

    def test_chrome_config_home_precedes_xdg_config_home_and_default_is_current_home(self):
        for env, config in (({'CHROME_CONFIG_HOME': str(self.root / 'chrome 配置')}, self.root / 'chrome 配置'),
                            ({'CHROME_CONFIG_HOME': '', 'XDG_CONFIG_HOME': ''}, self.home / '.config')):
            profile = config / 'google-chrome/Profile 1'
            self.legacy_metadata(profile)
            with self.subTest(config=config), patch.dict(os.environ, env):
                self.assertEqual(web._profile_path(self.chrome, 'chrome', 'Profile 1'), profile)
                self.assertTrue(self.parse()['launchable'])

    def test_unknown_installation_channel_or_config_root_does_not_guess_profiles(self):
        portable = self.make_elf(self.root / 'unknown-channel/google/chrome/chrome')
        self.legacy_metadata()
        with patch('ruleproxy.web_app_leveldb.read_values', side_effect=AssertionError('Unknown source')), \
                patch.object(web, '_legacy_start_url', side_effect=AssertionError('Unknown source')):
            candidate = self.parse(Exec=self.command('--app-id=' + APP_ID,
                                                    '--profile-directory=Profile 1', program=portable))
            self.assertFalse(candidate['launchable'])
            self.assertEqual(candidate['path'], str(portable))
            for change in ({'XDG_CONFIG_HOME': 'relative'}, {'CHROME_CONFIG_HOME': '~/config'},
                           {'CHROME_CONFIG_HOME': str(self.root / '..' / 'elsewhere')},
                           {'CHROME_USER_DATA_DIR': str(self.root / 'custom-data')}):
                with self.subTest(change=change), patch.dict(os.environ, change):
                    self.assertFalse(self.parse()['launchable'])

    def test_missing_profile_is_not_replaced_with_another_profile(self):
        self.legacy_metadata(self.config / 'google-chrome/Default')
        self.assertFalse(self.parse()['launchable'])
        with patch.object(web, 'resolve_start_url', side_effect=AssertionError('Explicit profile required')):
            self.assertIsNone(self.parse(Exec=self.command('--app-id=' + APP_ID)))

    def test_profile_config_and_database_symlinks_never_reach_metadata_reader(self):
        outside = self.root / 'unrelated'
        self.legacy_metadata(outside)
        self.profile.rmdir()
        self.profile.symlink_to(outside, target_is_directory=True)
        with patch('ruleproxy.web_app_leveldb.read_values', side_effect=AssertionError('No redirected reads')), \
                patch.object(web, '_legacy_start_url', side_effect=AssertionError('No redirected reads')):
            self.assertFalse(self.parse()['launchable'])
        self.profile.unlink()
        self.profile.mkdir()
        (self.profile / 'Sync Data').symlink_to(outside, target_is_directory=True)
        with patch.object(web, '_legacy_start_url', side_effect=AssertionError('No legacy fallback')):
            self.assertFalse(self.parse()['launchable'])
        redirected_config = self.root / 'config-link'
        redirected_config.symlink_to(self.config, target_is_directory=True)
        with patch.dict(os.environ, {'CHROME_CONFIG_HOME': str(redirected_config)}), \
                patch.object(web, '_legacy_start_url', side_effect=AssertionError('No redirected reads')):
            self.assertFalse(self.parse()['launchable'])

    def test_legacy_reads_only_allowlisted_metadata_and_never_enumerates_profile(self):
        self.legacy_metadata()
        for name in ('Cookies', 'Login Data', 'History'):
            (self.profile / name).write_bytes(b'private fixture: never read')
        from ruleproxy.web_app_leveldb import read_metadata_file
        original_open = os.open

        def checked_open(path, *args, **kwargs):
            self.assertNotIn(Path(path).name, ('Cookies', 'Login Data', 'History'))
            return original_open(path, *args, **kwargs)

        with patch('os.scandir', side_effect=AssertionError('No profile enumeration')), \
                patch('os.open', side_effect=checked_open), \
                patch('ruleproxy.web_app_leveldb.read_metadata_file', wraps=read_metadata_file) as reader:
            self.assertTrue(self.parse()['launchable'])
        reader.assert_called_once_with(self.profile, 'Preferences')

    def test_legacy_metadata_symlink_is_disabled_via_held_handle_reader(self):
        outside = self.root / 'elsewhere'
        self.legacy_metadata(outside)
        (self.profile / 'Preferences').symlink_to(outside / 'Preferences')
        self.assertFalse(self.parse()['launchable'])


class LinuxWebAppValidationTests(LinuxWebAppFixture):
    def test_restored_paths_cannot_expand_runtime_mount_to_home_or_config_tree(self):
        with patch.object(Path, 'stat', side_effect=AssertionError('No filesystem reads')), \
                patch.object(Path, 'lstat', side_effect=AssertionError('No filesystem reads')):
            for path in (self.home / 'chrome', self.home.parent / 'chrome', Path('/home/chrome'),
                         Path('/chrome'), self.home / '.config/google-chrome/chrome',
                         self.config / 'google-chrome/chrome'):
                with self.subTest(path=path), self.assertRaises(ValueError):
                    web.validate_web_app(self.metadata(), path)
            self.assertEqual(web.validate_web_app(self.metadata(), self.root / 'bin/chrome'), self.metadata())
        with patch.dict(os.environ, {'CHROME_CONFIG_HOME': str(self.root / 'chrome-config')}), \
                self.assertRaises(ValueError):
            web.validate_web_app(self.metadata(), self.root / 'chrome-config/bin/chrome')
        mount = self.root / 'independent-mount'
        with patch.dict(os.environ, {'XDG_CONFIG_HOME': str(mount / 'config')}), \
                patch.object(Path, 'stat', side_effect=AssertionError('No filesystem reads')), \
                patch.object(Path, 'lstat', side_effect=AssertionError('No filesystem reads')), \
                self.assertRaises(ValueError):
            web.validate_web_app(self.metadata(), mount / 'chrome')

    def test_saved_schema_validation_is_pure_and_allows_temporarily_missing_binary(self):
        removed = self.root / 'uninstalled/chrome'
        with patch.object(Path, 'stat', side_effect=AssertionError('No saved-state filesystem reads')), \
                patch.object(Path, 'lstat', side_effect=AssertionError('No saved-state filesystem reads')), \
                patch('os.open', side_effect=AssertionError('No saved-state filesystem reads')), \
                patch.object(web, 'resolve_start_url', side_effect=AssertionError('No source metadata reads')):
            self.assertEqual(web.validate_web_app(self.metadata(), removed), self.metadata())

    def test_exact_five_field_schema_and_linux_browser_identity_are_required(self):
        invalid = [None, [], {}, {**self.metadata(), 'extra': True},
                   self.metadata(browser='firefox'), self.metadata(browser='edge'),
                   self.metadata(profile_directory='../Profile 1'),
                   self.metadata(profile_directory='Default/Other'), self.metadata(app_id='z' * 32),
                   self.metadata(app_id=None), self.metadata(start_url=''),
                   self.metadata(start_url='file:///etc/passwd'), self.metadata(launch_mode='original_profile')]
        for key in self.metadata():
            missing = deepcopy(self.metadata())
            del missing[key]
            invalid.append(missing)
        for value in invalid:
            with self.subTest(value=value), self.assertRaises(ValueError):
                web.validate_web_app(value, self.chrome)
        for path in (Path('/removed/chrome.exe'), Path('/removed/sh'), Path('chrome'),
                     Path('/removed/../chrome'), Path('/removed/Chrome')):
            with self.subTest(path=path), self.assertRaises(ValueError):
                web.validate_web_app(self.metadata(), path)


if __name__ == '__main__':
    unittest.main()
