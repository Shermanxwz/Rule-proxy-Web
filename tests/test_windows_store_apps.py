"""Synthetic package eligibility and bounded, read-only Windows enumeration."""
import base64
import json
import os
from pathlib import Path
import stat
import subprocess
import sys
import tempfile
import time
from types import SimpleNamespace
import unittest
from unittest.mock import Mock, patch

from ruleproxy import windows_store_apps as store


def document(*rows):
    return json.dumps({'schema_version': 1, 'applications': list(rows)}, ensure_ascii=False).encode('utf-8')


class StoreMetadataTests(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory(prefix='ruleproxy-store-metadata-')
        self.addCleanup(self.temporary.cleanup)
        self.root = Path(self.temporary.name).resolve()
        self.package = self.root / 'WindowsApps' / 'Example.Package_1.0.0.0_x64_publisher'
        self.package.mkdir(parents=True)
        self.make_exe('app.exe')

    def make_exe(self, relative):
        target = self.package.joinpath(*relative.replace('\\', '/').split('/'))
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_bytes(b'MZ synthetic fixture; never executed')
        return target

    def row(self, **overrides):
        return {'label': '示例应用', 'package_name': 'Example.Package',
                'package_family_name': 'Example.Package_publisher', 'application_id': 'DesktopApp',
                'install_location': str(self.package), 'executable': 'app.exe',
                'entry_point': 'Windows.FullTrustApplication', 'runtime_behavior': '',
                'trust_level': '', **overrides}

    def test_legacy_and_both_explicit_desktop_runtimes_keep_real_unicode_paths(self):
        self.make_exe('目录 space/classic.exe')
        self.make_exe('win32.exe')
        rows = [self.row(), self.row(executable=r'目录 space\classic.exe', entry_point='',
                    runtime_behavior='packagedClassicApp', trust_level='mediumIL'),
                self.row(executable='win32.exe', entry_point='', runtime_behavior='win32App', trust_level='mediumIL')]
        before = {p: p.read_bytes() for p in self.package.rglob('*.exe')}
        result = store._parse(document(*rows))
        self.assertEqual(len(result), 3)
        self.assertEqual(result[0], {'label': '示例应用', 'path': str(self.package / 'app.exe'),
            'package_family_name': 'Example.Package_publisher', 'application_id': 'DesktopApp'})
        self.assertEqual(result[1]['path'], str(self.package / '目录 space/classic.exe'))
        self.assertEqual({p: p.read_bytes() for p in before}, before)

    def test_uwp_hosted_container_resources_and_startup_metadata_are_not_direct_exes(self):
        cases = [dict(entry_point='Example.ManagedApp'), dict(runtime_behavior='windowsApp'),
                 dict(trust_level='appContainer'), dict(entry_point='', runtime_behavior='packagedClassicApp'),
                 dict(entry_point='', runtime_behavior='win32App', trust_level=''),
                 dict(entry_point='Windows.PartialTrustApplication'), dict(host_id='Host'),
                 dict(start_page='index.html'), dict(parameters='--needed'), dict(current_directory='app'),
                 dict(is_framework=True), dict(is_resource=True), dict(is_framework='false')]
        for fields in cases:
            with self.subTest(fields=fields):
                self.assertEqual(store._parse(document(self.row(**fields))), [])

    def test_relative_package_path_cannot_escape_or_use_aliases_macros_or_arguments(self):
        for executable in ('../outside.exe', r'app\..\outside.exe', r'C:\outside.exe', r'C:app.exe',
                r'\app.exe', r'\\host\share\app.exe', 'app.exe:stream', '%PATH%/app.exe',
                '$(exec)/app.exe', 'app.exe --argument', 'app.dll', './app.exe', 'trailing. /app.exe',
                'app.exe\x00', 'missing.exe'):
            with self.subTest(executable=executable):
                self.assertEqual(store._parse(document(self.row(executable=executable))), [])
        self.assertEqual(store._parse(document(self.row(install_location=r'\\server\share'))), [])
        self.assertEqual(store._parse(document(self.row(install_location='relative'))), [])

    def test_missing_unreadable_and_non_executable_files_skip_only_the_bad_record(self):
        (self.package / 'fake.exe').write_text('not a PE executable')
        self.assertEqual(len(store._parse(document(self.row(executable='fake.exe'), self.row()))), 1)
        original = Path.open
        def access(path, *args, **kwargs):
            if path.name == 'app.exe':
                raise PermissionError('synthetic unreadable package')
            return original(path, *args, **kwargs)
        self.make_exe('readable.exe')
        with patch.object(Path, 'open', access):
            result = store._parse(document(self.row(), self.row(executable='readable.exe')))
        self.assertEqual([Path(row['path']).name for row in result], ['readable.exe'])

    def test_symbolic_links_and_windows_reparse_points_are_not_candidates(self):
        outside = self.root / 'outside.exe'
        outside.write_bytes(b'MZ outside fixture')
        try:
            (self.package / 'alias.exe').symlink_to(outside)
        except OSError:
            pass
        else:
            self.assertEqual(store._parse(document(self.row(executable='alias.exe'))), [])
        with patch.object(Path, 'lstat', return_value=SimpleNamespace(st_mode=stat.S_IFREG, st_file_attributes=0x400)):
            with self.assertRaises(ValueError):
                store._plain(outside, directory=False, deadline=time.monotonic() + 1)

    def test_labels_fall_back_without_exposing_ms_resource_tokens_and_duplicates_collapse(self):
        result = store._parse(document(self.row(label='ms-resource:Name'), self.row(label='duplicate')))
        self.assertEqual(len(result), 1)
        self.assertEqual(result[0]['label'], 'Example.Package')
        result = store._parse(document(self.row(label='', package_name='ms-resource:PackageName')))
        self.assertEqual(result[0]['label'], 'app')

    def test_payload_schema_output_count_and_inspection_deadline_are_bounded(self):
        for invalid in (b'not json', b'\xff', b'[]', b'{"schema_version":true,"applications":[]}',
                        b'{"schema_version":1,"applications":{}}'):
            with self.subTest(invalid=invalid), self.assertRaises((ValueError, UnicodeError)):
                store._parse(invalid)
        with patch.object(store, '_MAX_OUTPUT', 4), self.assertRaises(ValueError):
            store._parse(document(self.row()))
        with patch.object(store, '_MAX_APPLICATIONS', 1), self.assertRaises(ValueError):
            store._parse(document(self.row(), self.row()))
        with patch.object(store, '_PARSE_SECONDS', 0):
            self.assertEqual(store._parse(document(self.row())), [])

    def test_one_malformed_record_does_not_hide_a_valid_application(self):
        result = store._parse(document(None, self.row(label=3), self.row(application_id='bad!id'), self.row()))
        self.assertEqual(len(result), 1)


class StoreQueryTests(unittest.TestCase):
    def test_fixed_system_powershell_query_is_hidden_read_only_utf8_and_bounded(self):
        powershell = Path('/fixed-system/WindowsPowerShell/v1.0/powershell.exe')
        payload = document()
        def run(command, **options):
            options['stdout'].write(payload)
            self.assertEqual(command[0], str(powershell))
            for flag in ('-NoProfile', '-NonInteractive', '-EncodedCommand'):
                self.assertIn(flag, command)
            script = base64.b64decode(command[-1]).decode('utf-16-le')
            self.assertEqual(script, store._QUERY_SCRIPT)
            self.assertIn('Get-AppxPackage -PackageTypeFilter Main', script)
            self.assertNotIn('-AllUsers', script)
            self.assertNotIn('Start-Process', script)
            self.assertIn('OpenStandardOutput', script)
            self.assertEqual(options['env']['PSModulePath'], str(powershell.parent / 'Modules'))
            self.assertEqual(options['cwd'], powershell.parent)
            self.assertEqual(options['stdin'], subprocess.DEVNULL)
            self.assertEqual(options['stderr'], subprocess.DEVNULL)
            self.assertEqual(options['creationflags'], getattr(subprocess, 'CREATE_NO_WINDOW', 0))
            self.assertLessEqual(options['timeout'] + store._PARSE_SECONDS, 20)
            return SimpleNamespace(returncode=0)
        with patch.object(store.subprocess, 'run', side_effect=run) as execute:
            self.assertEqual(store._query(powershell), payload)
        execute.assert_called_once()

    def test_nonzero_missing_exit_oversize_and_timeout_do_not_become_success(self):
        powershell = Path('/fixed-system/powershell.exe')
        for code in (1, None, False):
            with self.subTest(code=code), patch.object(store.subprocess, 'run', return_value=SimpleNamespace(returncode=code)):
                with self.assertRaises(OSError):
                    store._query(powershell)
        def overflow(_command, **options):
            options['stdout'].write(b'x' * (store._MAX_OUTPUT + 1))
            return SimpleNamespace(returncode=0)
        with patch.object(store.subprocess, 'run', side_effect=overflow), self.assertRaises(ValueError):
            store._query(powershell)
        with patch.object(store.subprocess, 'run', side_effect=subprocess.TimeoutExpired('fixed query', 16)):
            with self.assertRaises(subprocess.TimeoutExpired):
                store._query(powershell)

    def test_complete_query_failure_and_non_windows_leave_ordinary_discovery_available(self):
        with patch.object(store.sys, 'platform', 'linux'), patch.object(store, '_system_powershell') as locate:
            self.assertEqual(store.discover_store_apps(), [])
        locate.assert_not_called()
        for failure in (OSError('missing API'), subprocess.TimeoutExpired('query', 16), ValueError('bad document')):
            with self.subTest(failure=type(failure).__name__), patch.object(store.sys, 'platform', 'win32'), \
                    patch.object(store, '_system_powershell', return_value=Path('/fixed/powershell.exe')), \
                    patch.object(store, '_query', side_effect=failure):
                self.assertEqual(store.discover_store_apps(), [])


@unittest.skipUnless(sys.platform == 'win32', 'Windows system PowerShell and current-user package APIs')
class NativeStoreQueryTests(unittest.TestCase):
    def test_actual_current_user_main_package_query_is_read_only_and_can_be_empty(self):
        # This is discovery only. An empty result is supported and does not
        # qualify ChatGPT, a specific Store package, or direct packaged startup.
        start = time.monotonic()
        raw = store._query(store._system_powershell())
        application_count = len(json.loads(raw.decode('utf-8'))['applications'])
        applications = store._parse(raw)
        print(f'::notice::Current-user Main package query: {application_count} manifest applications, '
              f'{len(applications)} eligible executables. Discovery only; no application was activated.')
        self.assertIsInstance(applications, list)
        self.assertLess(time.monotonic() - start, 25)
        for app in applications:
            self.assertEqual(set(app), {'label', 'path', 'package_family_name', 'application_id'})
            self.assertTrue(Path(app['path']).is_file())

    def test_production_script_extracts_namespaced_xml_and_writes_utf8_without_activation(self):
        fixtures = r'''
function Get-AppxPackage {
    param($PackageTypeFilter, $ErrorAction)
    if ($PackageTypeFilter -ne 'Main') { throw 'Only current-user Main packages are allowed' }
    foreach ($name in @('broken','legacy','classic','win32','uwp','hosted','resource','parameters11','directory11','previewruntime','previewtrust','duplicate')) {
        [pscustomobject]@{Name=('Example.'+$name);PackageFullName=$name;
            PackageFamilyName=('Example.'+$name+'_publisher');
            InstallLocation=$env:RULEPROXY_STORE_TEST_ROOT;IsFramework=$false;IsResourcePackage=($name -eq 'resource');IsBundle=$false}
    }
}
function Get-AppxPackageManifest {
    param($Package, $ErrorAction)
    if ($Package -eq 'broken') { throw 'Synthetic missing manifest' }
    $attributes = switch ($Package) {
        'legacy' { 'EntryPoint="Windows.FullTrustApplication"' }
        'classic' { 'uap10:RuntimeBehavior="packagedClassicApp" uap10:TrustLevel="mediumIL"' }
        'win32' { 'uap10:RuntimeBehavior="win32App" uap10:TrustLevel="mediumIL"' }
        'uwp' { 'EntryPoint="Example.App" uap10:RuntimeBehavior="windowsApp" uap10:TrustLevel="appContainer"' }
        'hosted' { 'EntryPoint="Windows.FullTrustApplication" uap10:HostId="ExternalHost"' }
        'parameters11' { 'EntryPoint="Windows.FullTrustApplication" uap11:Parameters="--required"' }
        'directory11' { 'EntryPoint="Windows.FullTrustApplication" uap11:CurrentDirectoryPath="app"' }
        'previewruntime' { 'EntryPoint="Windows.FullTrustApplication" previewsecurity2:RuntimeBehavior="windowsApp"' }
        'previewtrust' { 'EntryPoint="Windows.FullTrustApplication" previewsecurity:TrustLevel="appContainer"' }
        'duplicate' { 'EntryPoint="Windows.FullTrustApplication" uap10:RuntimeBehavior="packagedClassicApp" previewsecurity2:RuntimeBehavior="windowsApp"' }
    }
    [xml]('<Package xmlns="http://schemas.microsoft.com/appx/manifest/foundation/windows10" xmlns:uap10="http://schemas.microsoft.com/appx/manifest/uap/windows10/10" '+
        'xmlns:uap11="http://schemas.microsoft.com/appx/manifest/uap/windows10/11" xmlns:previewsecurity="urn:unsupported-preview-security" xmlns:previewsecurity2="urn:unsupported-preview-security-2">'+
        '<Applications><Application Id="App" Executable="'+$Package+'.exe" '+$attributes+' /></Applications></Package>')
}
function Get-StartApps {
    param($ErrorAction)
    [pscustomobject]@{AppID='Example.legacy_publisher!App';Name=$env:RULEPROXY_STORE_TEST_LABEL}
}
'''
        # Replace only the two system provider imports. All production XML
        # extraction, caps, JSON emission, command flags and file checks run.
        script = store._QUERY_SCRIPT.replace('Import-Module Appx -ErrorAction Stop | Out-Null', fixtures)
        script = script.replace('Import-Module StartLayout -ErrorAction Stop | Out-Null', '$null = 0')
        with tempfile.TemporaryDirectory(prefix='ruleproxy-store-native-') as temporary:
            root = Path(temporary).resolve() / '商店 fixture'
            root.mkdir()
            for name in ('legacy', 'classic', 'win32', 'uwp', 'hosted', 'parameters11', 'directory11',
                         'previewruntime', 'previewtrust', 'duplicate'):
                (root / (name + '.exe')).write_bytes(b'MZ synthetic fixture, never execute')
            with patch.dict(os.environ, {'RULEPROXY_STORE_TEST_ROOT': str(root), 'RULEPROXY_STORE_TEST_LABEL': '示例桌面应用'}), \
                    patch.object(store, '_QUERY_SCRIPT', script):
                result = store._parse(store._query(store._system_powershell()))
            self.assertEqual([row['package_family_name'] for row in result],
                             ['Example.legacy_publisher', 'Example.classic_publisher', 'Example.win32_publisher'])
            self.assertEqual(result[0]['label'], '示例桌面应用')


if __name__ == '__main__':
    unittest.main()
