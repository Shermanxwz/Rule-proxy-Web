"""Execute the uninstaller's fixed Python recovery snippets with network-free fakes."""
from contextlib import redirect_stdout
import io
import json
from pathlib import Path
import re
from types import SimpleNamespace
import unittest
from unittest.mock import Mock, patch


SCRIPT = Path(__file__).resolve().parent.parent / 'scripts/windows-uninstall.ps1'
SID = 'S-1-5-21-11-22-33-1001'


def snippet(function):
    source = SCRIPT.read_text(encoding='utf-8')
    section = source[source.index('function ' + function + ' {'):]
    match = re.search(r"\$code = @'\n(.*?)\n'@", section, re.S)
    if not match:
        raise AssertionError('Fixed uninstaller recovery code is missing')
    return match.group(1)


class UninstallRecoveryTests(unittest.TestCase):
    def run_code(self, function, modules, owner=SID):
        output = io.StringIO()
        with patch.dict('sys.modules', modules), patch('sys.argv', ['-c', r'C:\Program Files\RuleProxy-Web', owner]), \
                redirect_stdout(output):
            exec(compile(snippet(function), str(SCRIPT), 'exec'), {})
        return json.loads(output.getvalue())

    def test_proxy_recovery_binds_the_protected_owner_before_calling_hku_restoration(self):
        restore = Mock(return_value=True)
        modules = {'ruleproxy.windows_proxy_service': SimpleNamespace(load_deployment=lambda root: {'owner_sid': SID}),
                   'ruleproxy.system_proxy': SimpleNamespace(restore_windows_owner=restore)}
        receipt = self.run_code('Restore-OwnerSystemProxy', modules)
        restore.assert_called_once_with(SID)
        self.assertEqual(receipt, {'checked': True, 'owner_sid': SID, 'restored': True})
        restore.reset_mock()
        with self.assertRaisesRegex(RuntimeError, 'does not match'):
            self.run_code('Restore-OwnerSystemProxy', modules, SID + '9')
        restore.assert_not_called()

    def test_failed_proxy_restore_never_produces_a_success_receipt(self):
        modules = {'ruleproxy.windows_proxy_service': SimpleNamespace(load_deployment=lambda root: {'owner_sid': SID}),
                   'ruleproxy.system_proxy': SimpleNamespace(restore_windows_owner=Mock(side_effect=OSError('retry required')))}
        with self.assertRaisesRegex(OSError, 'retry required'):
            self.run_code('Restore-OwnerSystemProxy', modules)

    def network_modules(self, events, *, dns_active=False, container_active=False, guard_error=None,
                        app_guard=False, app_guard_active=False):
        def remove_guard():
            events.append('guard')
            if guard_error:
                raise guard_error
            return {'supported': True, 'active': False}
        deployment = {'owner_sid': SID, 'global_backend_version': 1}
        modules = {
            'ruleproxy.windows_proxy_service': SimpleNamespace(
                load_deployment=lambda root: deployment,
                ServiceControl=lambda: SimpleNamespace(status=lambda name: {'state': 1})),
            'ruleproxy.windows_global_dns': SimpleNamespace(DnsLease=lambda metadata: SimpleNamespace(
                normal_stop=lambda: events.append('dns') or {'supported': True, 'active': dns_active})),
            'ruleproxy.windows_global_guard': SimpleNamespace(Guard=lambda metadata: SimpleNamespace(
                normal_stop=remove_guard)),
            'ruleproxy.windows_appcontainer': SimpleNamespace(ContainerGate=lambda metadata: SimpleNamespace(
                purge=lambda: events.append('containers') or {'active': container_active, 'purged_sids': []})),
        }
        if app_guard:
            deployment['files'] = {'ruleproxy/windows_app_guard.py': 'a' * 64}
            modules['ruleproxy.windows_app_guard'] = SimpleNamespace(AppGuard=lambda metadata: SimpleNamespace(
                normal_stop=lambda: events.append('app_guard') or
                    {'supported': True, 'active': app_guard_active}))
        return modules

    def test_owned_dns_guard_and_container_purge_must_all_confirm_cleanup(self):
        events = []
        receipt = self.run_code('Restore-OwnedGlobalNetwork', self.network_modules(events))
        self.assertEqual(events, ['guard', 'dns', 'containers'])
        self.assertEqual(receipt, {'restored': True})
        events.clear()
        with self.assertRaisesRegex(RuntimeError, 'DNS restoration'):
            self.run_code('Restore-OwnedGlobalNetwork', self.network_modules(events, dns_active=True))
        self.assertEqual(events, ['guard', 'dns', 'containers'])
        events.clear()
        with self.assertRaisesRegex(RuntimeError, 'container protection cleanup'):
            self.run_code('Restore-OwnedGlobalNetwork', self.network_modules(events, container_active=True))

    def test_app_guard_cleanup_runs_only_when_the_component_is_installed(self):
        events = []
        receipt = self.run_code('Restore-OwnedGlobalNetwork', self.network_modules(events, app_guard=True))
        self.assertEqual(events, ['guard', 'dns', 'containers', 'app_guard'])
        self.assertEqual(receipt, {'restored': True})
        events.clear()
        with self.assertRaisesRegex(RuntimeError, 'egress guard cleanup'):
            self.run_code('Restore-OwnedGlobalNetwork',
                          self.network_modules(events, app_guard=True, app_guard_active=True))
        self.assertEqual(events, ['guard', 'dns', 'containers', 'app_guard'])

    def test_guard_failure_does_not_skip_dns_or_containers_and_aggregates_errors(self):
        events = []
        with self.assertRaises(RuntimeError) as caught:
            self.run_code('Restore-OwnedGlobalNetwork', self.network_modules(
                events, guard_error=OSError('owned WFP unavailable'), container_active=True))
        self.assertEqual(events, ['guard', 'dns', 'containers'])
        self.assertIn('owned WFP unavailable', str(caught.exception))
        self.assertIn('container protection cleanup', str(caught.exception))

    def test_owner_proxy_recovery_precedes_service_stop_and_forced_panel_termination(self):
        source = SCRIPT.read_text(encoding='utf-8')
        owner_restore = source.index('\nRestore-OwnerSystemProxy\n')
        self.assertLess(owner_restore, source.index('Stop-Service RuleProxyControl -ErrorAction Stop'))
        self.assertLess(owner_restore, source.index('Stop-Process -Id $ownedProcess.ProcessId'))
        self.assertLess(source.index('\nRestore-OwnedGlobalNetwork\n'),
                        source.index('& sc.exe delete RuleProxyControl'))
        self.assertIn('$root $OwnerSid', source)
        self.assertIn('$confirmation.owner_sid -ne $OwnerSid', source)

    def test_second_owner_restore_keeps_validated_roots_until_after_panel_stop(self):
        source = SCRIPT.read_text(encoding='utf-8')
        restores = [match.start() for match in re.finditer(r'^Restore-OwnerSystemProxy$', source, re.M)]
        self.assertEqual(len(restores), 2)
        owner_stop = source.index('Stop-Process -Id $ownedProcess.ProcessId -Force -ErrorAction Stop')
        self.assertLess(restores[0], owner_stop)
        self.assertLess(owner_stop, restores[1])
        self.assertLess(source.index("if ($owner.Sid -eq $OwnerSid)"), owner_stop)
        self.assertLess(source.index('Stop-Service ProxiFyreService -ErrorAction Stop'), restores[1])
        # Native C4 proved load_deployment requires pfRoot even when the
        # owner journal is already restored. Neither Burn nor residual/root
        # deletion may run before the post-panel recovery has succeeded.
        for destructive in ('Start-Process -FilePath $bundle',
                            'foreach ($name in $remaining) { Remove-Item',
                            'Remove-Item -LiteralPath $root -Recurse -Force'):
            self.assertLess(restores[1], source.index(destructive))


if __name__ == '__main__':
    unittest.main()
