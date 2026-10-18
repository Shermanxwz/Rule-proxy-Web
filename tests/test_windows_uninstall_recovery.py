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

    def network_modules(self, events, *, dns_active=False, container_active=False, guard_error=None):
        def remove_guard():
            events.append('guard')
            if guard_error:
                raise guard_error
            return {'supported': True, 'active': False}
        return {
            'ruleproxy.windows_proxy_service': SimpleNamespace(
                load_deployment=lambda root: {'owner_sid': SID, 'global_backend_version': 1},
                ServiceControl=lambda: SimpleNamespace(status=lambda name: {'state': 1})),
            'ruleproxy.windows_global_dns': SimpleNamespace(DnsLease=lambda metadata: SimpleNamespace(
                normal_stop=lambda: events.append('dns') or {'supported': True, 'active': dns_active})),
            'ruleproxy.windows_global_guard': SimpleNamespace(Guard=lambda metadata: SimpleNamespace(
                normal_stop=remove_guard)),
            'ruleproxy.windows_appcontainer': SimpleNamespace(ContainerGate=lambda metadata: SimpleNamespace(
                purge=lambda: events.append('containers') or {'active': container_active, 'purged_sids': []})),
        }

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


if __name__ == '__main__':
    unittest.main()
