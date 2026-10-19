"""Compartment evidence must not promote incomplete probes into qualification."""
import copy
import importlib.util
from pathlib import Path
import unittest
import urllib.request


SOURCE = Path(__file__).resolve().parents[1] / '.github' / 'windows_compartment_lab.py'
SPEC = importlib.util.spec_from_file_location('windows_compartment_lab', SOURCE)
lab = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(lab)


class AssessmentTests(unittest.TestCase):
    sid = 'S-1-5-21-1-2-3-1001'

    def actor(self, allowed, compartment, *, proxy=True):
        def member():
            return {'exit_code': 0, 'compartment': compartment,
                    'identity': {'sid': self.sid, 'elevated': False},
                    'rows': {key: {'ok': allowed} for key in lab.ROW_KEYS}, 'proxy': {'ok': proxy}}
        return dict(member(), child=member(), nested=member())

    def report(self):
        outside, inside = self.actor(True, 1), self.actor(False, 2)
        launcher = {'identity': {'sid': self.sid, 'elevated': False},
                    'user-outside': outside, 'user-inside': inside}
        live = {'exit_code': 0, 'compartment': 2, 'pid': 44, 'released': True,
                'before': {'proxy': {'ok': True}},
                'after': {'proxy': {'ok': False}, 'rows': {key: {'ok': False} for key in lab.ROW_KEYS}}}
        report = {'nonce': 'n', 'binds': {'A': {'compartment_id': 2}},
                  'phases': {'outside': outside, 'inside': inside, 'relay-live-inside': live,
                             'relay-stopped-inside': self.actor(False, 2, proxy=False)},
                  'relay_failure_ready': {'pid': 44, 'before': {'proxy': {'ok': True}}},
                  'user_flow': {'exit_code': 0, 'timed_out': False,
                                'identity': {'sid': self.sid, 'elevated': False}, 'launcher': launcher},
                  'user_launcher': launcher, 'dns_matrix': {}, 'broker_matrix': {},
                  'cleanup_result': {'deletes': {'2': 1359}}}
        keys = ('getaddrinfo:0', 'DnsQuery_W:0', 'DnsQuery_W:264', 'DnsQueryEx:0', 'DnsQueryEx:264',
                'DnsQuery_W:0:restricted', 'DnsQueryEx:0:restricted', 'Resolve-DnsName:0')
        index = 0
        for scope in ('outside_before', 'inside', 'outside_after'):
            entries = report['dns_matrix'][scope] = {}
            for key in keys:
                index += 1
                entries[key] = {'name': f'{index:032x}.1.2.3.4.sslip.io', 'execution': {'timed_out': False},
                                'result': {'completed': True, 'addresses': [] if scope == 'inside' else ['1.2.3.4']}}
        for scope in ('outside', 'inside'):
            report['broker_matrix'][scope] = {
                'wmi': {'execution': {'timed_out': False}, 'invocation': {'return_value': 5},
                        'child': None, 'fixture_hits': 0},
                'bits': {'execution': {'timed_out': False}, 'result': {'supported': False}, 'fixture_hits': 0}}
        return report

    def test_successful_socket_and_api_denials_never_qualify_product_or_wire_denial(self):
        checks = lab.qualification_checks(self.report())
        self.assertTrue(checks['required_observations_complete'])
        self.assertTrue(checks['ordinary_user_flow'])
        self.assertTrue(checks['relay_stop_live_and_new_processes'])
        for key in ('dns_no_egress_proven', 'real_mihomo_https_tested', 'browser_sandbox_state_verified',
                    'primary_restricted_token_tested', 'hcn_dns_remediation_tested', 'compartment_cleanup_complete'):
            self.assertIs(checks[key], False, key)
        self.assertEqual(lab.experiment_decision(checks), 'poc_only_requires_wire_evidence_and_product_acceptance')

    def test_missing_positive_control_and_elevated_descendant_are_not_ordinary_success(self):
        report = self.report()
        report['user_launcher']['user-outside']['rows']['tcp6_loopback']['ok'] = False
        self.assertFalse(lab.qualification_checks(report)['ordinary_user_flow'])
        report = self.report()
        report['user_launcher']['user-inside']['nested']['identity']['elevated'] = True
        self.assertFalse(lab.qualification_checks(report)['ordinary_user_flow'])

    def test_relay_probe_requires_same_process_before_and_after_and_new_denial(self):
        report = self.report()
        report['relay_failure_ready']['pid'] = 45
        self.assertFalse(lab.qualification_checks(report)['relay_stop_live_and_new_processes'])
        report = self.report()
        report['phases']['relay-stopped-inside']['child']['proxy']['ok'] = True
        self.assertFalse(lab.qualification_checks(report)['relay_stop_live_and_new_processes'])

    def test_dns_timeout_missing_result_or_reused_name_remains_incomplete(self):
        report = self.report()
        report['dns_matrix']['inside']['DnsQueryEx:0']['execution']['timed_out'] = True
        self.assertFalse(lab.qualification_checks(report)['required_observations_complete'])
        report = self.report()
        report['dns_matrix']['inside']['DnsQuery_W:0']['result'] = None
        self.assertFalse(lab.qualification_checks(report)['dns_matrix_complete_and_names_unique'])
        report = self.report()
        report['dns_matrix']['inside']['DnsQuery_W:0']['name'] = report['dns_matrix']['inside']['getaddrinfo:0']['name']
        self.assertFalse(lab.qualification_checks(report)['dns_matrix_complete_and_names_unique'])

    def test_inside_dns_answer_is_no_go_even_if_other_probe_missing(self):
        report = self.report()
        report['dns_matrix']['inside']['Resolve-DnsName:0']['result']['addresses'] = ['1.2.3.5']
        report['user_flow']['exit_code'] = 1
        checks = lab.qualification_checks(report)
        self.assertTrue(checks['dns_answer_inside_observed'])
        self.assertEqual(lab.experiment_decision(checks), 'no_go_dns_broker_bypass')

    def test_wmi_bypass_requires_receipt_receiver_and_pid_binding(self):
        report = self.report()
        row = report['broker_matrix']['inside']['wmi']
        row.update(fixture_hits=1, invocation={'return_value': 0, 'child_pid': 101},
                   child={'direct_http': True, 'compartment': 1, 'identity': {'pid': 101},
                          'marker': 'RuleProxyFixture:n:wmi_inside'})
        checks = lab.qualification_checks(report)
        self.assertTrue(checks['wmi_broker_bypass_observed'])
        self.assertEqual(lab.experiment_decision(checks), 'no_go_local_broker_bypass')
        for key, replacement in (('fixture_hits', 0), ('invocation', {'child_pid': 102})):
            changed = copy.deepcopy(report)
            changed['broker_matrix']['inside']['wmi'][key] = replacement
            self.assertFalse(lab.qualification_checks(changed)['wmi_broker_bypass_observed'])

    def test_bits_unavailable_is_not_a_positive_control_or_bypass(self):
        checks = lab.qualification_checks(self.report())
        self.assertFalse(checks['broker_positive_controls'])
        self.assertFalse(checks['bits_broker_bypass_observed'])
        report = self.report()
        report['broker_matrix']['inside']['bits'].update(fixture_hits=1, result={'marker_matches': True})
        self.assertTrue(lab.qualification_checks(report)['bits_broker_bypass_observed'])

    def test_empty_report_is_incomplete_and_never_passes_a_probe(self):
        checks = lab.qualification_checks({})
        self.assertFalse(any(checks.values()))
        self.assertEqual(lab.experiment_decision(checks), 'incomplete_experiment')


class FixtureTests(unittest.TestCase):
    def test_bits_head_range_and_get_are_real_receiver_controls(self):
        fixture = lab.Fixture('nonce', direct=True)
        opener = urllib.request.build_opener(urllib.request.ProxyHandler({}))
        url = f'http://127.0.0.1:{fixture.port}/nonce/bits_inside'
        try:
            with opener.open(urllib.request.Request(url, method='HEAD'), timeout=3) as response:
                length = int(response.headers['Content-Length'])
                self.assertEqual(response.headers['Accept-Ranges'], 'bytes')
                self.assertEqual(response.read(), b'')
            self.assertEqual(fixture.count('bits_inside'), 0)
            with opener.open(urllib.request.Request(url, headers={'Range': 'bytes=0-'}), timeout=3) as response:
                self.assertEqual(response.status, 206)
                body = response.read()
                self.assertEqual(len(body), length)
                self.assertIn(fixture.marker('bits_inside').encode(), body)
            self.assertEqual(fixture.count('bits_inside'), 1)
        finally:
            fixture.close()

    def test_standalone_workers_compile(self):
        for name in ('ACTOR', 'LAUNCHER', 'DNS_PROBE', 'BROKER_CHILD'):
            with self.subTest(name=name):
                compile(getattr(lab, name), name + '.py', 'exec')


if __name__ == '__main__':
    unittest.main()
