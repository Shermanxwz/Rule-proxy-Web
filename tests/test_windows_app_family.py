"""Stable Store identity and complete, fail-closed package path enumeration."""
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
from unittest.mock import patch

from ruleproxy import windows_app_family as family


def binding(**overrides):
    return {'package_family_name': 'Example.Package_publisher',
            'application_id': 'DesktopApp', 'scope': 'package', **overrides}


class StoreFamilyResolutionTests(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory(prefix='ruleproxy-store-family-')
        self.addCleanup(self.temporary.cleanup)
        self.base = Path(self.temporary.name).resolve()
        self.root = self.base / 'WindowsApps' / 'Example.Package_1.0.0.0_x64__publisher'
        self.root.mkdir(parents=True)
        self.entry = self.make_exe('app/Example.exe')

    def make_exe(self, relative, *, root=None):
        target = (root or self.root).joinpath(*relative.replace('\\', '/').split('/'))
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_bytes(b'MZ fixture, never execute')
        return target

    def metadata(self, *, root=None, applications=None, **overrides):
        row = {'package_family_name': 'Example.Package_publisher',
               'package_full_name': 'Example.Package_1.0.0.0_x64__publisher',
               'install_location': str(root or self.root),
               'is_framework': False, 'is_resource': False, 'is_bundle': False,
               'applications': applications if applications is not None else [self.application()],
               **overrides}
        return json.dumps({'schema_version': 1, 'packages': [row]}, ensure_ascii=False).encode('utf-8')

    def application(self, **overrides):
        return {'application_id': 'DesktopApp', 'executable': r'app\Example.exe',
                'entry_point': 'Windows.FullTrustApplication', **overrides}

    def test_binding_contains_only_portable_identity_and_explicit_package_scope(self):
        self.assertEqual(family.validate_binding(binding()), binding())
        invalid = [None, [], {}, binding(scope='application'), binding(scope=True),
                   binding(path=str(self.entry)), binding(package_family_name='Example.Package'),
                   binding(package_family_name='Example.Package_'),
                   binding(package_family_name='Example.*_publisher'), binding(application_id='a!b'),
                   binding(application_id='a' * 129), binding(package_family_name='../Example_publisher')]
        for value in invalid:
            with self.subTest(value=value), self.assertRaises(family.FamilyResolutionError):
                family.validate_binding(value)

    def test_resolves_nested_helpers_read_only_without_walking_other_packages(self):
        helper = self.make_exe('app/resources/runner.exe')
        second = self.make_exe('runtime/工具 helper.EXE')
        other_root = self.root.parent / 'Unrelated.Package'
        self.make_exe('secret.exe', root=other_root)
        (self.root / 'resources.txt').write_text('unchanged')
        before = {path: path.read_bytes() for path in (self.entry, helper, second)}
        original = os.scandir
        def guarded(path):
            if Path(path) in (self.root.parent, other_root):
                raise AssertionError('Must inspect only the registered package')
            return original(path)
        with patch.object(family.os, 'scandir', side_effect=guarded), \
                patch('subprocess.Popen', side_effect=AssertionError('No candidate may be activated')):
            resolved = family.resolve_metadata(binding(), self.metadata())
        self.assertEqual(resolved.entry_path, str(self.entry))
        self.assertEqual(set(resolved.paths), {str(self.entry), str(helper), str(second)})
        self.assertEqual(resolved.other_application_ids, ())
        self.assertEqual({path: path.read_bytes() for path in before}, before)

    def test_same_binding_tracks_registration_version_and_renamed_entry(self):
        new_root = self.root.parent / 'Example.Package_2.0.0.0_x64__publisher'
        new_entry = self.make_exe('desktop/NewName.exe', root=new_root)
        helper = self.make_exe('lib/new-helper.exe', root=new_root)
        first = family.resolve_metadata(binding(), self.metadata())
        second = family.resolve_metadata(binding(), self.metadata(root=new_root,
            package_full_name='Example.Package_2.0.0.0_x64__publisher',
            applications=[self.application(executable=r'desktop\NewName.exe')]))
        self.assertEqual(first.entry_path, str(self.entry))
        self.assertEqual(second.entry_path, str(new_entry))
        self.assertEqual(set(second.paths), {str(new_entry), str(helper)})
        self.assertNotIn(str(self.entry), second.paths)
        self.assertEqual(second.package_family_name, first.package_family_name)
        self.assertEqual(second.application_id, first.application_id)

    def test_multi_entry_package_explicitly_returns_sibling_identity_and_scope(self):
        sibling = self.make_exe('sibling/Other.exe')
        result = family.resolve_metadata(binding(), self.metadata(applications=[self.application(),
            self.application(application_id='OtherApp', executable=r'sibling\Other.exe')]))
        self.assertEqual(result.other_application_ids, ('OtherApp',))
        self.assertEqual(set(result.paths), {str(self.entry), str(sibling)})

    def test_missing_ambiguous_or_changed_identity_does_not_fall_back_to_old_path(self):
        package = json.loads(self.metadata())['packages'][0]
        documents = [dict(schema_version=1, packages=[]),
                     dict(schema_version=1, packages=[package, package]),
                     dict(schema_version=True, packages=[package])]
        for document in documents:
            with self.subTest(document=document), self.assertRaises(family.FamilyResolutionError):
                family.resolve_metadata(binding(), json.dumps(document).encode())
        cases = [dict(package_family_name='Other.Package_publisher'),
                 dict(package_full_name='Other.Package_1.0.0.0_x64__publisher'),
                 dict(package_full_name='Example.Package_1.0.0.0_x64__otherpublisher'),
                 dict(package_full_name='Example.Package_publisher'),
                 dict(applications=[]), dict(is_framework=True), dict(is_resource=True),
                 dict(is_bundle=True), dict(is_bundle=None),
                 dict(applications=[self.application(application_id='Changed')]),
                 dict(applications=[self.application(), self.application()])]
        for override in cases:
            with self.subTest(override=override), self.assertRaises(family.FamilyResolutionError):
                family.resolve_metadata(binding(), self.metadata(**override))

    def test_unsupported_entry_attributes_do_not_activate_or_guess_a_replacement(self):
        for override in (dict(entry_point='Example.ManagedApp'), dict(runtime_behavior='windowsApp'),
                         dict(trust_level='appContainer'), dict(host_id='host'), dict(start_page='index.html'),
                         dict(parameters='--required'), dict(current_directory='app')):
            with self.subTest(override=override), self.assertRaises(family.FamilyResolutionError):
                family.resolve_metadata(binding(), self.metadata(applications=[self.application(**override)]))

    def test_manifest_executable_escape_macro_unc_and_ads_are_rejected(self):
        for target in ('../outside.exe', r'app\..\outside.exe', r'C:\outside.exe',
                       r'\\server\share\app.exe', r'app\Example.exe:stream',
                       '%ROOT%/app.exe', 'app.exe --argument', r'app\.\Example.exe'):
            with self.subTest(target=target), self.assertRaises(family.FamilyResolutionError):
                family.resolve_metadata(binding(), self.metadata(applications=[self.application(executable=target)]))
        with self.assertRaises(family.FamilyResolutionError):
            family.resolve_metadata(binding(), self.metadata(install_location=r'\\server\share'))

    def test_bad_helper_mz_unreadability_and_vanishing_file_reject_complete_family(self):
        helper = self.make_exe('resources/runner.exe')
        helper.write_bytes(b'not a PE executable')
        with self.assertRaises(family.FamilyResolutionError):
            family.resolve_metadata(binding(), self.metadata())
        helper.write_bytes(b'MZ fixture')
        original = Path.open
        for failure in (PermissionError('not readable'), FileNotFoundError('updated')):
            def access(path, *args, **kwargs):
                if path == helper:
                    raise failure
                return original(path, *args, **kwargs)
            with self.subTest(failure=type(failure).__name__), patch.object(Path, 'open', access), \
                    self.assertRaises(family.FamilyResolutionError):
                family.resolve_metadata(binding(), self.metadata())

    def test_symlinked_helper_and_linked_ancestor_are_not_scanned(self):
        outside = self.make_exe('outside.exe', root=self.base)
        try:
            (self.root / 'alias.exe').symlink_to(outside)
        except OSError as error:
            self.skipTest('Cannot create test symlink: ' + str(error))
        with self.assertRaises(family.FamilyResolutionError):
            family.resolve_metadata(binding(), self.metadata())
        (self.root / 'alias.exe').unlink()
        linked_root = self.base / 'linked'
        linked_root.symlink_to(self.root, target_is_directory=True)
        with self.assertRaises(family.FamilyResolutionError):
            family.resolve_metadata(binding(), self.metadata(install_location=str(linked_root)))

    def test_directory_reparse_point_aborts_before_traversal(self):
        linked = self.root / 'linked-directory'
        original = os.scandir
        def scan(path):
            if Path(path) == self.root:
                class Listing:
                    def __enter__(self):
                        return iter([SimpleNamespace(name=linked.name, path=str(linked), stat=lambda **_: \
                            SimpleNamespace(st_mode=stat.S_IFDIR, st_file_attributes=0x400))])
                    def __exit__(self, *_args):
                        pass
                return Listing()
            return original(path)
        with patch.object(family.os, 'scandir', side_effect=scan), self.assertRaisesRegex(family.FamilyResolutionError, '重解析点'):
            family.resolve_metadata(binding(), self.metadata())

    def test_limits_abort_instead_of_returning_a_partial_policy(self):
        self.make_exe('helpers/runner.exe')
        cases = [('_MAX_PATHS', 1), ('_MAX_ENTRIES', 1), ('_MAX_DIRECTORIES', 1),
                 ('_MAX_DEPTH', 0), ('_INSPECTION_SECONDS', 0), ('_MAX_OUTPUT', 2),
                 ('_MAX_APPLICATIONS', 0)]
        for constant, value in cases:
            with self.subTest(constant=constant), patch.object(family, constant, value), \
                    self.assertRaises(family.FamilyResolutionError):
                family.resolve_metadata(binding(), self.metadata())

    def test_129_executables_are_rejected_with_an_actionable_path_limit(self):
        for number in range(128):
            self.make_exe(f'helpers/runner-{number:03}.exe')
        with self.assertRaisesRegex(family.FamilyResolutionError, '128'):
            family.resolve_metadata(binding(), self.metadata())

    def test_directory_access_failure_and_duplicate_json_keys_are_fatal(self):
        with patch.object(family.os, 'scandir', side_effect=PermissionError('cannot enumerate')), \
                self.assertRaises(family.FamilyResolutionError):
            family.resolve_metadata(binding(), self.metadata())
        with self.assertRaisesRegex(family.FamilyResolutionError, '重复字段'):
            family.resolve_metadata(binding(), b'{"schema_version":1,"schema_version":1,"packages":[]}')

    def test_existing_record_binds_only_to_exact_current_manifest_entry(self):
        with patch.object(family.sys, 'platform', 'win32'), \
                patch.object(family, '_query_binding', return_value=self.metadata()) as query:
            actual = family.binding_for_path(str(self.entry))
        self.assertEqual(actual, binding())
        query.assert_called_once_with(self.entry)
        # Directory names and familiar executable names do not establish an
        # application identity: the target must itself be a manifest entry.
        helper = self.make_exe('resources/runner.exe')
        with patch.object(family.sys, 'platform', 'win32'), \
                patch.object(family, '_query_binding', return_value=self.metadata()):
            self.assertIsNone(family.binding_for_path(helper))

    def test_independently_declared_helper_can_bind_but_shared_entry_is_ambiguous(self):
        helper = self.make_exe('resources/runner.exe')
        rows = [self.application(), self.application(application_id='Runner', executable=r'resources\runner.exe')]
        with patch.object(family.sys, 'platform', 'win32'), \
                patch.object(family, '_query_binding', return_value=self.metadata(applications=rows)):
            self.assertEqual(family.binding_for_path(helper), binding(application_id='Runner'))
        ambiguous = [self.application(), self.application(application_id='SecondEntry')]
        with patch.object(family.sys, 'platform', 'win32'), \
                patch.object(family, '_query_binding', return_value=self.metadata(applications=ambiguous)):
            self.assertIsNone(family.binding_for_path(self.entry))

    def test_binding_never_guesses_from_old_version_path_missing_registration_or_query_failure(self):
        missing = self.entry.parent / 'Missing.exe'
        with patch.object(family.sys, 'platform', 'win32'), patch.object(family, '_query_binding') as query:
            self.assertIsNone(family.binding_for_path(missing))
        query.assert_not_called()
        invalid_documents = [b'{"schema_version":1,"packages":[]}', b'not JSON',
            json.dumps({'schema_version': 1, 'packages': json.loads(self.metadata())['packages'] * 3}).encode()]
        with patch.object(family.sys, 'platform', 'win32'):
            for document in invalid_documents:
                with self.subTest(document=document[:60]), patch.object(family, '_query_binding', return_value=document):
                    self.assertIsNone(family.binding_for_path(self.entry))
            for error in (OSError('API unavailable'), subprocess.TimeoutExpired('query', 16)):
                with self.subTest(error=type(error).__name__), patch.object(family, '_query_binding', side_effect=error):
                    self.assertIsNone(family.binding_for_path(self.entry))
        with patch.object(family.sys, 'platform', 'linux'), patch.object(family, '_query_binding') as query:
            self.assertIsNone(family.binding_for_path(self.entry))
        query.assert_not_called()

    def test_binding_rejects_duplicate_registrations_instead_of_deduplicating_identity(self):
        package = json.loads(self.metadata())['packages'][0]
        metadata = json.dumps({'schema_version': 1, 'packages': [package, package]}).encode()
        with patch.object(family.sys, 'platform', 'win32'), patch.object(family, '_query_binding', return_value=metadata):
            self.assertIsNone(family.binding_for_path(self.entry))


class StoreFamilyQueryTests(unittest.TestCase):
    def test_query_is_fixed_hidden_current_user_specific_and_bounded(self):
        powershell = Path('/fixed-system/WindowsPowerShell/v1.0/powershell.exe')
        data = b'{"schema_version":1,"packages":[]}'
        def run(command, **options):
            options['stdout'].write(data)
            self.assertEqual(command[0], str(powershell))
            for flag in ('-NoProfile', '-NonInteractive', '-EncodedCommand'):
                self.assertIn(flag, command)
            script = base64.b64decode(command[-1]).decode('utf-16-le')
            self.assertEqual(script, family._QUERY_SCRIPT)
            self.assertIn('Get-AppxPackage -Name $name -PackageTypeFilter Main', script)
            self.assertNotIn('-AllUsers', script)
            self.assertNotIn('Start-Process', script)
            self.assertNotIn('Get-ChildItem', script)
            self.assertEqual(options['env']['PSModulePath'], str(powershell.parent / 'Modules'))
            self.assertEqual(options['env'][family._QUERY_FAMILY_ENV], binding()['package_family_name'])
            self.assertEqual(options['cwd'], powershell.parent)
            self.assertEqual(options['stdin'], subprocess.DEVNULL)
            self.assertEqual(options['stderr'], subprocess.DEVNULL)
            self.assertEqual(options['creationflags'], getattr(subprocess, 'CREATE_NO_WINDOW', 0))
            self.assertEqual(options['timeout'], 16)
            return SimpleNamespace(returncode=0)
        with patch.object(family.store, '_system_powershell', return_value=powershell), \
                patch.object(family.subprocess, 'run', side_effect=run) as execute:
            self.assertEqual(family._query(binding()), data)
        execute.assert_called_once()

    def test_binding_query_uses_registration_location_not_windowsapps_name_inference(self):
        powershell = Path('/fixed-system/WindowsPowerShell/v1.0/powershell.exe')
        path = Path('/custom registered location/app.exe')
        def run(command, **options):
            options['stdout'].write(b'{"schema_version":1,"packages":[]}')
            script = base64.b64decode(command[-1]).decode('utf-16-le')
            self.assertEqual(script, family._BINDING_QUERY_SCRIPT)
            self.assertIn('Get-AppxPackage -PackageTypeFilter Main', script)
            self.assertIn('Select-Object -First 513', script)
            self.assertIn('$registered.Count -gt 512', script)
            self.assertNotIn('Get-ChildItem', script)
            self.assertNotIn('WindowsApps', script)
            self.assertNotIn('-AllUsers', script)
            self.assertEqual(options['env'][family._QUERY_TARGET_ENV], str(path))
            return SimpleNamespace(returncode=0)
        with patch.object(family.store, '_system_powershell', return_value=powershell), \
                patch.object(family.subprocess, 'run', side_effect=run):
            self.assertEqual(family._query_binding(path), b'{"schema_version":1,"packages":[]}')

    def test_query_failure_is_not_best_effort_empty_success(self):
        with patch.object(family.sys, 'platform', 'win32'), \
                patch.object(family, '_query', side_effect=OSError('missing API')), \
                self.assertRaisesRegex(family.FamilyResolutionError, '停止受保护启动'):
            family.resolve_store_family(binding())
        with patch.object(family.sys, 'platform', 'win32'), \
                patch.object(family, '_query', side_effect=subprocess.TimeoutExpired('query', 16)), \
                self.assertRaises(family.FamilyResolutionError):
            family.resolve_store_family(binding())
        with patch.object(family.sys, 'platform', 'linux'), patch.object(family, '_query') as query, \
                self.assertRaisesRegex(family.FamilyResolutionError, 'Windows'):
            family.resolve_store_family(binding())
        query.assert_not_called()

    def test_query_rejects_nonzero_missing_exit_and_oversized_output(self):
        with patch.object(family.store, '_system_powershell', return_value=Path('/fixed/powershell.exe')):
            for code in (1, None, False):
                with self.subTest(code=code), patch.object(family.subprocess, 'run', return_value=SimpleNamespace(returncode=code)), \
                        self.assertRaises(family.FamilyResolutionError):
                    family._query(binding())
            def overflow(_command, **options):
                options['stdout'].write(b'x' * (family._MAX_OUTPUT + 1))
                return SimpleNamespace(returncode=0)
            with patch.object(family.subprocess, 'run', side_effect=overflow), self.assertRaises(family.FamilyResolutionError):
                family._query(binding())


@unittest.skipUnless(sys.platform == 'win32', 'Windows system PowerShell and current-user package APIs')
class NativeStoreFamilyQueryTests(unittest.TestCase):
    def test_production_query_and_utf8_paths_resolve_a_complete_synthetic_package(self):
        fixture = r'''
function Get-AppxPackage {
    param($Name, $PackageTypeFilter, $ErrorAction)
    if ($Name -cne 'Example.Package' -or $PackageTypeFilter -cne 'Main') { throw 'Incorrect package query' }
    [pscustomobject]@{PackageFamilyName='Example.Package_publisher';PackageFullName='Example.Package_2.0.0.0_x64__publisher';
        InstallLocation=$env:RULEPROXY_FAMILY_TEST_ROOT;IsFramework=$false;IsResourcePackage=$false;IsBundle=$false}
}
function Get-AppxPackageManifest {
    param($Package, $ErrorAction)
    if ($Package -cne 'Example.Package_2.0.0.0_x64__publisher') { throw 'Wrong current package' }
    [xml]'<Package xmlns="http://schemas.microsoft.com/appx/manifest/foundation/windows10"><Applications><Application Id="DesktopApp" Executable="应用\Example.exe" EntryPoint="Windows.FullTrustApplication" /></Applications></Package>'
}
'''
        script = family._QUERY_SCRIPT.replace('Import-Module Appx -ErrorAction Stop | Out-Null', fixture)
        with tempfile.TemporaryDirectory(prefix='ruleproxy-family-native-') as temporary:
            root = Path(temporary).resolve() / '商店 fixture'
            entry = root / '应用' / 'Example.exe'
            helper = root / 'resources' / 'runner.exe'
            for path in (entry, helper):
                path.parent.mkdir(parents=True, exist_ok=True)
                path.write_bytes(b'MZ synthetic fixture, never execute')
            with patch.dict(os.environ, {'RULEPROXY_FAMILY_TEST_ROOT': str(root)}), \
                    patch.object(family, '_QUERY_SCRIPT', script):
                result = family.resolve_store_family(binding())
            self.assertEqual(result.entry_path, str(entry))
            self.assertEqual(set(result.paths), {str(entry), str(helper)})
            self.assertEqual(result.package_full_name, 'Example.Package_2.0.0.0_x64__publisher')

    def test_production_binding_query_distinguishes_manifest_helper_from_unlisted_executable(self):
        fixture = r'''
function Get-AppxPackage {
    param($PackageTypeFilter, $ErrorAction)
    if ($PackageTypeFilter -cne 'Main') { throw 'Incorrect package query' }
    [pscustomobject]@{PackageFamilyName='Example.Package_publisher';PackageFullName='Example.Package_2.0.0.0_x64__publisher';
        InstallLocation=$env:RULEPROXY_FAMILY_TEST_ROOT;IsFramework=$false;IsResourcePackage=$false;IsBundle=$false}
}
function Get-AppxPackageManifest {
    param($Package, $ErrorAction)
    if ($Package -cne 'Example.Package_2.0.0.0_x64__publisher') { throw 'Wrong current package' }
    [xml]'<Package xmlns="http://schemas.microsoft.com/appx/manifest/foundation/windows10"><Applications><Application Id="DesktopApp" Executable="应用\Example.exe" EntryPoint="Windows.FullTrustApplication" /><Application Id="Runner" Executable="resources\runner.exe" EntryPoint="Windows.FullTrustApplication" /></Applications></Package>'
}
'''
        script = family._BINDING_QUERY_SCRIPT.replace('Import-Module Appx -ErrorAction Stop | Out-Null', fixture)
        with tempfile.TemporaryDirectory(prefix='ruleproxy-family-bind-native-') as temporary:
            root = Path(temporary).resolve() / '自选安装目录'
            entry, helper, unlisted = root / '应用/Example.exe', root / 'resources/runner.exe', root / 'unlisted.exe'
            for path in (entry, helper, unlisted):
                path.parent.mkdir(parents=True, exist_ok=True)
                path.write_bytes(b'MZ synthetic fixture, never execute')
            with patch.dict(os.environ, {'RULEPROXY_FAMILY_TEST_ROOT': str(root)}), \
                    patch.object(family, '_BINDING_QUERY_SCRIPT', script):
                self.assertEqual(family.binding_for_path(entry), binding())
                self.assertEqual(family.binding_for_path(helper), binding(application_id='Runner'))
                self.assertIsNone(family.binding_for_path(unlisted))


if __name__ == '__main__':
    unittest.main()
