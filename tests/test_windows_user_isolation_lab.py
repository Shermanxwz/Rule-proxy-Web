"""Evidence must distinguish DNS brokerage from missing positive controls."""
import copy
import importlib.util
import os
from pathlib import Path
import unittest
from unittest import mock

SOURCE = Path(__file__).resolve().parents[1] / '.github/windows_user_isolation_lab.py'
SPEC = importlib.util.spec_from_file_location('windows_user_isolation_lab', SOURCE)
lab = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(lab)


class ReceiptTests(unittest.TestCase):
    sid = 'S-1-5-21-1-2-3-1001'

    def receipt(self):
        return {'sid': self.sid, 'elevated': False, 'pid': 203, 'phase': 'before',
                'rows': {key: {'ok': True} for key in ('tcp4', 'tcp6', 'udp4', 'udp6')},
                'dns': {'ok': True, 'name': 'a' * 32 + '.1.2.3.4.sslip.io'}, 'proxy': {'ok': True}}

    def valid(self, value):
        return lab.valid_receipt(value, self.sid, 'before', 203, 'a' * 32 + '.1.2.3.4.sslip.io')

    def test_actual_ordinary_identity_and_phase_binding_are_required(self):
        value = self.receipt()
        self.assertTrue(self.valid(value))
        for key, replacement in (('sid', 'S-1-5-18'), ('elevated', True), ('elevated', 0),
                                  ('pid', True), ('pid', 204), ('phase', 'filtered')):
            changed = copy.deepcopy(value); changed[key] = replacement
            self.assertFalse(self.valid(changed))
        for key in ('tcp4', 'tcp6', 'udp4', 'udp6'):
            changed = copy.deepcopy(value); changed['rows'][key]['ok'] = 1
            self.assertFalse(self.valid(changed))

    def test_clean_environment_removes_all_credentials_and_restores_controller_on_failure(self):
        original = {'SystemRoot': r'C:\Windows', 'TEMP': r'C:\Temp', 'PATH': 'trusted',
                    'GITHUB_TOKEN': 'must-not-inherit', 'ACTIONS_RUNTIME_TOKEN': 'must-not-inherit',
                    'RULEPROXY_TEST_PASSWORD': 'must-not-inherit', 'HTTP_PROXY': 'must-not-inherit'}
        with mock.patch.dict(os.environ, original, clear=True):
            with self.assertRaises(RuntimeError):
                with lab.clean_actor_environment():
                    self.assertEqual({key.upper(): value for key, value in os.environ.items()},
                                     {key.upper(): original[key] for key in ('SystemRoot', 'TEMP', 'PATH')})
                    raise RuntimeError('injected process creation failure')
            self.assertEqual({key.upper(): value for key, value in os.environ.items()},
                             {key.upper(): value for key, value in original.items()})

    def test_system_account_or_unbounded_filter_identity_is_rejected_before_native_access(self):
        for sid, port, marker in (('S-1-5-18', 20809, 'RuleProxyUserLab:' + 'a' * 32),
                                  (self.sid, True, 'RuleProxyUserLab:' + 'a' * 32),
                                  (self.sid, 80, 'RuleProxyUserLab:' + 'a' * 32),
                                  (self.sid, 20809, 'any-marker')):
            with self.subTest(sid=sid, port=port), self.assertRaises(ValueError):
                lab.UserRules(sid, port, marker)


class AssessmentTests(unittest.TestCase):
    nonce = 'd' * 32

    def evidence(self, dns_bypass=True):
        phases, received = {}, []
        for index, label in enumerate(('before', 'filtered', 'after')):
            rows = {key: {'ok': label != 'filtered'} for key in ('tcp4', 'tcp6', 'udp4', 'udp6')}
            target = f'http://{label}.invalid/{self.nonce}/{label}'
            phases[label] = {'rows': rows, 'dns': {'ok': label != 'filtered' or dns_bypass,
                'addresses': ['1.2.3.4'] if label != 'filtered' or dns_bypass else [],
                'name': str(index) * 32 + '.1.2.3.4.sslip.io'},
                'proxy': {'ok': True, 'target': target}}
            received.append(target)
            if label != 'filtered':
                received += [f'{self.nonce}:{label}:{key}' for key in rows]
        return phases, received

    def assess(self, phases, received):
        return lab.assess(phases, received, self.nonce)

    def test_fresh_system_dns_success_is_explicit_no_go_even_when_all_sockets_block(self):
        value = self.assess(*self.evidence())
        self.assertTrue(value['valid_experiment'])
        self.assertTrue(value['filtered_sockets_blocked'])
        self.assertTrue(value['dns_broker_bypass'])
        self.assertEqual(value['decision'], 'no_go_dns_broker_bypass')
        self.assertIs(value['linux_equivalent'], False)
        self.assertIs(value['product_qualified'], False)
        self.assertIs(value['browser_tested'], False)

    def test_ipv6_missing_positive_or_receiver_cannot_be_called_blocking_success(self):
        phases, received = self.evidence()
        phases['before']['rows']['tcp6']['ok'] = False
        self.assertFalse(self.assess(phases, received)['valid_experiment'])
        phases, received = self.evidence()
        received.remove(f'{self.nonce}:after:udp6')
        self.assertFalse(self.assess(phases, received)['valid_experiment'])

    def test_filtered_socket_leak_is_not_labelled_dns_broker_bypass(self):
        phases, received = self.evidence()
        received.append(f'{self.nonce}:filtered:udp4')
        value = self.assess(phases, received)
        self.assertFalse(value['filtered_sockets_blocked'])
        self.assertFalse(value['dns_broker_bypass'])
        self.assertEqual(value['decision'], 'no_go_socket_filter_failed')

    def test_reused_dns_name_or_unreceived_proxy_response_is_inconclusive(self):
        phases, received = self.evidence()
        phases['filtered']['dns']['name'] = phases['before']['dns']['name']
        self.assertFalse(self.assess(phases, received)['valid_experiment'])
        phases, received = self.evidence(); received.remove(phases['filtered']['proxy']['target'])
        self.assertFalse(self.assess(phases, received)['valid_experiment'])

    def test_socket_and_dns_denial_still_does_not_qualify_product_or_browser(self):
        value = self.assess(*self.evidence(dns_bypass=False))
        self.assertTrue(value['valid_experiment'])
        self.assertEqual(value['decision'], 'socket_scope_only_requires_dns_broker_work')
        self.assertFalse(value['linux_equivalent'])

    def test_successful_dns_with_unexpected_address_also_refutes_no_dns_egress(self):
        phases, received = self.evidence(dns_bypass=False)
        phases['filtered']['dns'].update(ok=False, addresses=['1.2.3.5'])
        value = self.assess(phases, received)
        self.assertTrue(value['dns_broker_bypass'])
        self.assertEqual(value['decision'], 'no_go_dns_broker_bypass')

    def test_standalone_actor_compiles(self):
        compile(lab.ACTOR, 'user-isolation-actor.py', 'exec')


if __name__ == '__main__':
    unittest.main()
