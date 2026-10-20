import copy
import hashlib
import importlib.util
import json
from pathlib import Path
import subprocess
import tempfile
import unittest
from unittest.mock import Mock, patch

ROOT = Path(__file__).resolve().parents[1]
SPEC = importlib.util.spec_from_file_location('windows_identity_proof', ROOT / '.github/windows_identity_proof.py')
proof = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(proof)
N = 'a' * 32
SID = 'S-1-15-2-1-2-3-4-5-6-7'
ENV = [r'SYSTEMROOT=C:\Windows', r'LOCALAPPDATA=C:\Users\Fixture\AppData\Local']

def proxy():
    return dict(profile='RuleProxy.IdentityProof.' + N, derived_sid=SID, token_sid=SID, appcontainer=True, port=31001)

def probe():
    return dict(tier='base-container', needsDaclAugmentation=False, probes={'baseContainerApiPresent': True}, error=None)

def evidence():
    return dict(nonce=N, probe=probe(), probe_exit_code=0, actual_tiers=['base-container'], executor_exit_code=0,
                timed_out=False, actor=dict(schemaVersion=1, mode='actor', nonce=N, queriesSucceeded=True, errors=[],
                tokenIsAppContainer=True, tokenAppContainerSid=SID, tokenElevated=False, isProcessInJob=True, tokenCapabilities=[], pid=123))

def full_probe():
    value = probe()
    value['probes'].update({key: True for key in proof.PROBE_FACTS})
    value['probes']['uiCapabilities'] = {key: True for key in proof.UI_FACTS}
    value['warnings'] = []
    return value


def probe_process(value=None, *, stdout=None, stderr=b'', returncode=0):
    if stdout is None:
        stdout = json.dumps(full_probe() if value is None else value).encode()
    return subprocess.CompletedProcess([], returncode, stdout, stderr)


def checked_result(result):
    """Supply only the controller's nonce and checks, never repair observations."""
    result = dict(result, nonce=N)
    result['checks'] = proof.stage0_checks(result)
    return result


class PolicyTests(unittest.TestCase):
    def test_stage_zero_has_no_proxy_or_network_grants(self):
        p = proof.policy('inputs', 'profile', 'actor.exe', N, required_environment=ENV)
        self.assertEqual(p['network'], {'egress': {'default': 'deny'}, 'ingress': {'default': 'deny', 'hostLoopback': 'deny'}})
        self.assertNotIn('runtimeConfig', p)
        self.assertNotIn('processContainer', p)
        self.assertEqual(p['fallback'], {'allowDaclMutation': False})
        self.assertIs(p['process']['inheritDefaultEnv'], False)
    def test_identity_policy_never_opens_general_host_loopback(self):
        p = proof.policy('inputs', 'profile', 'actor.exe', N, proxy=proxy(), required_environment=ENV)
        self.assertEqual(p['network'], {'egress': {'default': 'deny'}, 'ingress': {'default': 'allow', 'hostLoopback': 'deny'}})
        self.assertEqual(p['processContainer']['network']['allowedProxyPeer'], proxy()['profile'])
        self.assertEqual(p['runtimeConfig']['networkProxy'], 'http://127.0.0.1:31001')
        self.assertIn('actor-http', p['process']['commandLine'])
    def test_bad_nonce_rejected(self):
        for n in ('', 'A'*32, 'a'*31, N+'\n', None):
            with self.subTest(n=n), self.assertRaises(ValueError): proof.policy('i','p','a',n)
    def test_identity_mismatch_rejected(self):
        for key, val in [('token_sid', 'S-1-15-2-9-2-3-4-5-6-7'), ('appcontainer', False), ('profile', 'MXC-Loopback'),
                         ('derived_sid', ''), ('port', 80), ('port', 65536), ('port', True), ('port', '31001')]:
            p=proxy(); p[key]=val
            with self.subTest(key=key,val=val), self.assertRaises(ValueError): proof.policy('i','p','a',N,proxy=p,required_environment=ENV)
    def test_missing_or_extra_identity_field_rejected(self):
        for p in ({}, {'profile':'foo'}, dict(proxy(), invented=True)):
            with self.assertRaises(ValueError): proof.policy('i','p','a',N,proxy=p,required_environment=ENV)

class EvidenceTests(unittest.TestCase):
    def test_complete_evidence_passes(self): self.assertTrue(all(proof.stage0_checks(evidence()).values()))
    def test_tier_extraction_is_exact(self):
        self.assertEqual(proof.actual_tiers(b'selected isolation tier: base-container\r\n'), ['base-container'])
        self.assertEqual(proof.actual_tiers(b'fake selected isolation tier: base-container\n'), [])
        self.assertEqual(proof.actual_tiers(b'x'*(proof.MAX_OUTPUT+1)), [])
    def test_duplicate_tier_is_not_success(self):
        r=evidence(); r['actual_tiers']*=2
        self.assertFalse(proof.stage0_checks(r)['actual_base_container'])
    def test_fallback_and_missing_evidence_fail(self):
        for key,val in [('actual_tiers', []), ('actual_tiers',['appcontainer-bfs']), ('probe_exit_code',1),
                        ('executor_exit_code',1), ('timed_out',True), ('nonce','b'*32)]:
            r=evidence(); r[key]=val
            with self.subTest(key=key): self.assertFalse(all(proof.stage0_checks(r).values()))
    def test_actor_identity_failures(self):
        for key,val in [('tokenIsAppContainer',False), ('tokenAppContainerSid',None), ('tokenElevated',True),
                        ('isProcessInJob',False), ('queriesSucceeded',False), ('errors',['failed']), ('pid',True),
                        ('mode','actor-http'), ('nonce','b'*32)]:
            r=evidence(); r['actor'][key]=val
            with self.subTest(key=key): self.assertFalse(all(proof.stage0_checks(r).values()))
    def test_empty_report_never_passes(self): self.assertFalse(all(proof.stage0_checks({}).values()))


class ClosedDiagnosticTests(unittest.TestCase):
    SECRET = 'PRIVATE_SENTINEL_do_not_publish'

    def project(self, value):
        return proof.closed_diagnostics(value)

    def test_projection_roundtrip_is_idempotent_and_does_not_mutate_input(self):
        raw = dict(evidence(), probe=full_probe(), probe_attempted=True, probe_completed=True,
                   probe_outcome='selected', probe_stdout_state='object', started=True,
                   executor_outcome='completed', actor_report_state='parsed', controller_phase='completed')
        raw['checks'] = proof.stage0_checks(raw)
        original = copy.deepcopy(raw)
        first = self.project(raw)
        self.assertEqual(self.project({'diagnostics': first}), first)
        self.assertEqual(raw, original)
        self.assertTrue(first['execution']['actor_checks_passed'])
        self.assertEqual(first['probe']['outcome'], 'selected')
        self.assertIs(first['numeric_psec_contract_version_available'], False)
        self.assertIs(first['probe_schema_version_available'], False)
        self.assertEqual(first['policy_schema_version'], '1.0.0')
        self.assertEqual(first['required_tier'], 'base-container')

    def test_all_fact_fields_distinguish_missing_false_and_wrong_type(self):
        for field in proof.PROBE_FACTS:
            for state, value in (('missing', None), ('wrong_type', 0), ('wrong_type', 1),
                                 ('wrong_type', 'false'), ('wrong_type', {}), ('wrong_type', None),
                                 ('value', False), ('value', True)):
                wire = full_probe()
                if state == 'missing':
                    del wire['probes'][field]
                else:
                    wire['probes'][field] = value
                with self.subTest(field=field, state=state, value=value):
                    fact = self.project({'probe': wire})['probe']['facts'][field]
                    self.assertEqual(fact, {'state': state, 'value': value if state == 'value' else None})

    def test_all_ui_fact_fields_distinguish_missing_false_and_wrong_type(self):
        for field in proof.UI_FACTS:
            for state, value in (('missing', None), ('wrong_type', 0), ('wrong_type', 1),
                                 ('wrong_type', 'true'), ('wrong_type', []), ('wrong_type', None),
                                 ('value', False), ('value', True)):
                wire = full_probe()
                if state == 'missing':
                    del wire['probes']['uiCapabilities'][field]
                else:
                    wire['probes']['uiCapabilities'][field] = value
                with self.subTest(field=field, state=state, value=value):
                    fact = self.project({'probe': wire})['probe']['ui_facts'][field]
                    self.assertEqual(fact, {'state': state, 'value': value if state == 'value' else None})

    def test_missing_or_wrong_type_containers_do_not_invent_false_facts(self):
        for present, value, state in ((False, None, 'missing'), (True, None, 'wrong_type'),
                                      (True, [], 'wrong_type'), (True, False, 'wrong_type'),
                                      (True, {}, 'object')):
            wire = full_probe()
            if present:
                wire['probes'] = value
            else:
                del wire['probes']
            with self.subTest(container='probes', value=value, present=present):
                actual = self.project({'probe': wire})['probe']
                self.assertEqual(actual['probes_state'], state)
                self.assertEqual(actual['ui_state'], 'missing')
                self.assertTrue(all(fact == {'state': 'missing', 'value': None}
                                    for fact in actual['facts'].values()))
            wire = full_probe()
            if present:
                wire['probes']['uiCapabilities'] = value
            else:
                del wire['probes']['uiCapabilities']
            with self.subTest(container='uiCapabilities', value=value, present=present):
                actual = self.project({'probe': wire})['probe']
                self.assertEqual(actual['ui_state'], state)
                self.assertTrue(all(fact == {'state': 'missing', 'value': None}
                                    for fact in actual['ui_facts'].values()))

    def test_dacl_fact_and_tier_are_closed_observations(self):
        for present, value, state in ((False, None, 'missing'), (True, None, 'wrong_type'),
                                      (True, 0, 'wrong_type'), (True, False, 'value'),
                                      (True, True, 'value')):
            wire = full_probe()
            if present:
                wire['needsDaclAugmentation'] = value
            else:
                del wire['needsDaclAugmentation']
            with self.subTest(value=value, present=present):
                self.assertEqual(self.project({'probe': wire})['probe']['needs_dacl_augmentation'],
                                 {'state': state, 'value': value if state == 'value' else None})
        for present, value, state, tier in ((False, None, 'missing', 'not_observed'),
                (True, None, 'wrong_type', 'not_observed'),
                (True, [], 'wrong_type', 'not_observed'),
                (True, self.SECRET, 'unknown', 'not_observed'),
                (True, 'appcontainer-bfs', 'known', 'appcontainer-bfs')):
            wire = full_probe()
            if present:
                wire['tier'] = value
            else:
                del wire['tier']
            with self.subTest(tier=value, present=present):
                actual = self.project({'probe': wire})['probe']
                self.assertEqual((actual['tier_state'], actual['tier']), (state, tier))

    def test_warning_shapes_counts_and_summaries_are_bounded(self):
        for present, value, state, count, nonstrings in (
                (False, None, 'missing', None, None), (True, None, 'wrong_type', None, None),
                (True, self.SECRET, 'wrong_type', None, None), (True, [], 'array', 0, 0),
                (True, [self.SECRET, None, False, 0, {}], 'array', 5, 4)):
            wire = full_probe()
            if present:
                wire['warnings'] = value
            else:
                del wire['warnings']
            summaries = [proof.smoke.executor_diagnostic(self.SECRET.encode())] * 12
            with self.subTest(value=value, present=present):
                actual = self.project({'probe': wire, 'probe_warning_diagnostics': summaries})['probe']
                self.assertEqual((actual['warnings_state'], actual['warning_count'],
                                  actual['warning_nonstring_count']), (state, count, nonstrings))
                self.assertEqual(len(actual['warning_summaries']), 2)
                self.assertNotIn(self.SECRET, json.dumps(actual))

    def test_detector_errors_have_only_safe_classes(self):
        cases = [(value, expected) for value, expected in proof.DETECTOR_ERRORS.items()]
        cases += [('WRITE_DAC unavailable on path C:\\' + self.SECRET, 'reported_write_dac_unavailable'),
                  ('Could not resolve Windows system directory: ' + self.SECRET, 'reported_system_directory_failure'),
                  (self.SECRET, 'unclassified'), ('', 'unclassified'), (None, 'absent'),
                  (False, 'wrong_type'), ({'message': self.SECRET}, 'wrong_type')]
        for value, expected in cases:
            with self.subTest(expected=expected, value=value):
                self.assertEqual(proof.detector_error_class(value), expected)

    def test_cli_keeps_static_fieldpaths_and_categories_not_user_values(self):
        raw = ('Error: failed to load probe config ' + self.SECRET + '\n'
               'Invalid JSON syntax: ' + self.SECRET + '\n'
               'Invalid configuration at `filesystem.readonlyPaths[12]`: ' + self.SECRET + '\n'
               'Invalid configuration at `process.env[3]`: ' + self.SECRET + '\n'
               'Invalid configuration at `process.env[17]`: duplicate\n'
               'Invalid configuration at `process.env[' + self.SECRET + ']`: not static\n'
               'Invalid configuration at `' + self.SECRET + '`: private\n'
               'Invalid configuration: ' + self.SECRET + '\n'
               'Unable to read JSON configuration: ' + self.SECRET + '\n'
               'Error: request-aware probe supports only ProcessContainer containment; got ' + self.SECRET + '\n'
               'Error: probe serialization failed: ' + self.SECRET).encode()
        actual = proof.cli_diagnostic(raw)
        self.assertEqual(actual['classes'], list(proof.CLI_CLASSES))
        self.assertEqual(actual['policy_fields'], ['filesystem.readonlyPaths[]', 'process.env[]'])
        self.assertNotIn(self.SECRET, json.dumps(actual))
        self.assertEqual(proof.cli_diagnostic(b'x' * 65536 + raw), {'classes': [], 'policy_fields': []})

    def test_untrusted_nested_projection_cannot_export_raw_values_or_extra_fields(self):
        bad_summary = {
            'bytes_observed': self.SECRET, 'inspection_truncated': self.SECRET,
            'categories': [self.SECRET, 'permission', 'permission'],
            'operations': ['CreateProcessW', self.SECRET], 'native_codes': [True, '5', '0x80070005', self.SECRET],
            'inspected_sha256': self.SECRET, 'error_envelope_count': 900,
            'error_envelopes': [{'code': self.SECRET, 'message_class': self.SECRET,
                'message_sha256': self.SECRET, 'message': self.SECRET, 'extended_error': self.SECRET,
                'has_extended_error': self.SECRET, 'extended_error_sha256': self.SECRET,
                'categories': [self.SECRET, 'psec'], 'operations': [self.SECRET, 'ResumeThread'],
                'native_codes': [False, '-1', self.SECRET], 'path': self.SECRET}] * 10,
            'raw': self.SECRET}
        candidate = {'controller_phase': self.SECRET, 'failure_phase': self.SECRET,
            'failure': {'type': self.SECRET, 'winerror': self.SECRET, 'errno': True, 'detail': self.SECRET},
            'probe': {'attempted': self.SECRET, 'completed': 1, 'outcome': self.SECRET,
                'exit_code': True, 'tier': self.SECRET, 'tier_state': self.SECRET,
                'stdout_state': self.SECRET, 'probes_state': self.SECRET, 'ui_state': self.SECRET,
                'needs_dacl_augmentation': {'state': 'value', 'value': self.SECRET},
                'facts': {key: {'state': 'value', 'value': self.SECRET} for key in proof.PROBE_FACTS},
                'ui_facts': {key: {'state': self.SECRET, 'value': self.SECRET} for key in proof.UI_FACTS},
                'error_present': self.SECRET, 'error_class': self.SECRET, 'error_summary': bad_summary,
                'warnings_state': self.SECRET, 'warning_count': True, 'warning_nonstring_count': -1,
                'warning_summaries': [bad_summary] * 20, 'stdout': bad_summary, 'stderr': bad_summary,
                'cli': {'classes': [self.SECRET, 'reported_configuration'],
                        'policy_fields': [self.SECRET, 'process.commandLine']}, 'raw': self.SECRET},
            'execution': {'launch_attempted': self.SECRET, 'outcome': self.SECRET, 'exit_code': False,
                'timed_out': self.SECRET, 'actual_tier_count': True, 'actual_tiers': [self.SECRET, 'base-container'],
                'unknown_tier_count': -1, 'actor_report_state': self.SECRET, 'actor_checks_passed': self.SECRET,
                'stdout': bad_summary, 'stderr': bad_summary, 'actor': self.SECRET}, 'raw': self.SECRET}
        raw = {'diagnostics': candidate, 'hostname': self.SECRET, 'sid': self.SECRET,
               'nonce': self.SECRET, 'path': self.SECRET, 'actor': self.SECRET}
        before = copy.deepcopy(raw)
        actual = self.project(raw)
        self.assertNotIn(self.SECRET, json.dumps(actual))
        self.assertEqual(raw, before)
        self.assertEqual(self.project({'diagnostics': actual}), actual)
        summary = actual['probe']['error_summary']
        self.assertEqual(summary['categories'], ['permission'])
        self.assertEqual(summary['operations'], ['CreateProcessW'])
        self.assertEqual(summary['native_codes'], [5, 0x80070005])
        self.assertEqual(summary['error_envelope_count'], 4)
        self.assertEqual(len(summary['error_envelopes']), 1)
        self.assertEqual(len(actual['probe']['warning_summaries']), 2)
        self.assertFalse(actual['probe']['attempted'])
        self.assertFalse(actual['probe']['completed'])
        self.assertIsNone(actual['probe']['exit_code'])
        self.assertIsNone(actual['execution']['exit_code'])
        self.assertIsNone(actual['execution']['timed_out'])

    def test_diagnostic_summary_bounds_numeric_codes_and_digests(self):
        actual = proof.diagnostic_summary({'bytes_observed': 0, 'inspected_sha256': 'a' * 64,
            'native_codes': [-0x80000000, 0xffffffff, -0x80000001, 0x100000000, True, '0x80070005', '5', '-1', '6'],
            'error_envelopes': []})
        self.assertEqual(actual['native_codes'], [-0x80000000, -1, 5, 0x80070005, 0xffffffff])
        self.assertEqual(actual['inspected_sha256'], 'a' * 64)
        self.assertEqual(actual['bytes_observed'], 0)
        for value in (True, -1, 2**31, '123', None):
            with self.subTest(value=value):
                self.assertIsNone(proof.diagnostic_summary({'bytes_observed': value})['bytes_observed'])
        for value in ('A' * 64, 'a' * 63, 'a' * 65, 'a' * 64 + '\n', self.SECRET):
            with self.subTest(digest=value):
                self.assertIsNone(proof.diagnostic_summary({'inspected_sha256': value})['inspected_sha256'])

    def test_duplicate_and_unknown_tiers_keep_counts_not_private_names(self):
        actual = self.project({'actual_tiers': ['base-container', 'base-container', self.SECRET,
                                               None, 'appcontainer-dacl']})['execution']
        self.assertEqual(actual['actual_tier_count'], 5)
        self.assertEqual(actual['unknown_tier_count'], 2)
        self.assertEqual(actual['actual_tiers'], ['base-container', 'appcontainer-dacl'])
        self.assertNotIn(self.SECRET, json.dumps(actual))

    def test_diagnostic_fields_cannot_change_existing_acceptance_or_policy(self):
        original = evidence()
        baseline_checks = proof.stage0_checks(original)
        baseline_policy = proof.policy('inputs', 'profile', 'actor.exe', N, required_environment=ENV)
        for diagnostics in ({}, {'execution': {'actor_checks_passed': True}},
                            {'probe': {'outcome': 'selected'}}, self.SECRET):
            report = dict(original, diagnostics=diagnostics)
            self.project(report)
            with self.subTest(diagnostics=diagnostics):
                self.assertEqual(proof.stage0_checks(report), baseline_checks)
                report['actual_tiers'] = ['appcontainer-bfs']
                self.assertFalse(proof.stage0_checks(report)['actual_base_container'])
        self.assertEqual(proof.policy('inputs', 'profile', 'actor.exe', N, required_environment=ENV), baseline_policy)

    def test_optional_diagnostic_facts_are_not_added_to_acceptance_gate(self):
        for value in (None, False, 0, self.SECRET):
            wire = full_probe()
            for field in proof.PROBE_FACTS:
                if field != 'baseContainerApiPresent':
                    wire['probes'][field] = value
            wire['probes']['uiCapabilities'] = {key: value for key in proof.UI_FACTS}
            with self.subTest(value=value):
                self.assertTrue(all(proof.stage0_checks(dict(evidence(), probe=wire)).values()))
        self.assertTrue(all(proof.stage0_checks(evidence()).values()))

    def test_reparse_observation_is_nullable_and_not_an_acceptance_claim(self):
        for value in (True, False, None, 0, 1, self.SECRET):
            with self.subTest(value=value):
                actual = self.project({'actor_reparse_point_observed': value})['execution']
                self.assertIs(actual['actor_reparse_point_observed'], value if type(value) is bool else None)
                self.assertFalse(actual['actor_checks_passed'])
                self.assertFalse(actual['launch_attempted'])
                self.assertNotIn(self.SECRET, json.dumps(actual))

    def test_wrong_type_nested_diagnostics_are_rebuilt_fail_closed(self):
        for value in (None, [], False, 1, self.SECRET):
            candidate = {'probe': value, 'execution': value, 'failure': value}
            with self.subTest(value=value):
                actual = self.project({'diagnostics': candidate})
                self.assertEqual(self.project({'diagnostics': actual}), actual)
                self.assertFalse(actual['probe']['attempted'])
                self.assertFalse(actual['execution']['actor_checks_passed'])
                self.assertNotIn(self.SECRET, json.dumps(actual))


class ProbeDiagnosticRunnerTests(unittest.TestCase):
    def run_probe(self, completed):
        runner = Mock(return_value=completed)
        with tempfile.TemporaryDirectory() as directory:
            result = proof.run_case('executor.exe', {}, directory, runner=runner)
        return result, runner

    def assert_closed_probe(self, result, expected):
        projected = proof.closed_diagnostics(result)['probe']
        self.assertEqual(result['probe_outcome'], expected)
        self.assertEqual(projected['outcome'], expected)
        return projected

    def test_probe_failure_outcomes_are_distinct_and_never_execute_actor(self):
        cases = [('nonzero_exit', probe_process(returncode=7)),
                 ('invalid_json', probe_process(stdout=b'not json')),
                 ('invalid_json', probe_process(stdout=b'\xff')),
                 ('non_object', probe_process(stdout=b'[]')),
                 ('non_object', probe_process(stdout=b'null')),
                 ('non_object', probe_process(stdout=b'false')),
                 ('output_over_bound', probe_process(stdout=b' ' * (proof.MAX_OUTPUT + 1))),
                 ('reported_detector_error', probe_process(dict(full_probe(), error='detector failed'))),
                 ('reported_detector_error', probe_process(dict(full_probe(), error=''))),
                 ('invalid_required_fact', probe_process(dict(full_probe(), error=0))),
                 ('invalid_required_fact', probe_process(dict(full_probe(), error=False))),
                 ('alternate_tier', probe_process(dict(full_probe(), tier='appcontainer-bfs'))),
                 ('alternate_tier', probe_process(dict(full_probe(), tier='appcontainer-dacl'))),
                 ('unknown_tier', probe_process(dict(full_probe(), tier='private-unrecognized-tier'))),
                 ('dacl_required', probe_process(dict(full_probe(), needsDaclAugmentation=True)))]
        api_false = full_probe()
        api_false['probes']['baseContainerApiPresent'] = False
        cases.append(('api_not_observed', probe_process(api_false)))
        for expected, completed in cases:
            with self.subTest(expected=expected, stdout=completed.stdout[:120]):
                result, runner = self.run_probe(completed)
                self.assert_closed_probe(result, expected)
                self.assertFalse(result['started'])
                self.assertEqual(runner.call_count, 1)
                self.assertTrue(result['probe_attempted'])
                self.assertTrue(result['probe_completed'])
                self.assertEqual(result['probe_exit_code'], completed.returncode)
                self.assertNotIn('executor_exit_code', result)
                self.assertEqual(result['actor_report_state'], 'not_reached')
                self.assertFalse(all(proof.stage0_checks(result).values()))

    def test_invalid_required_probe_fields_remain_fail_closed(self):
        cases = []
        for field in ('tier', 'needsDaclAugmentation', 'probes'):
            for value in (None, 0, [], 'wrong type'):
                wire = full_probe()
                wire[field] = value
                cases.append((field, value, wire))
            wire = full_probe()
            del wire[field]
            cases.append((field, 'missing', wire))
        for value in (None, 0, 1, 'true', []):
            wire = full_probe()
            wire['probes']['baseContainerApiPresent'] = value
            cases.append(('baseContainerApiPresent', value, wire))
        wire = full_probe()
        del wire['probes']['baseContainerApiPresent']
        cases.append(('baseContainerApiPresent', 'missing', wire))
        for field, value, wire in cases:
            with self.subTest(field=field, value=value):
                result, runner = self.run_probe(probe_process(wire))
                expected = 'unknown_tier' if field == 'tier' and value == 'wrong type' else 'invalid_required_fact'
                self.assert_closed_probe(result, expected)
                self.assertFalse(result['started'])
                self.assertEqual(runner.call_count, 1)

    def test_probe_nonzero_exit_has_priority_but_retains_parsed_detector_facts(self):
        wire = full_probe()
        wire.update(tier='appcontainer-dacl', error='WRITE_DAC unavailable on path PRIVATE_SENTINEL')
        result, runner = self.run_probe(probe_process(wire, returncode=9,
            stderr=b'Invalid configuration at `process.env[2]`: PRIVATE_SENTINEL'))
        projected = self.assert_closed_probe(result, 'nonzero_exit')
        self.assertEqual(projected['tier'], 'appcontainer-dacl')
        self.assertEqual(projected['error_class'], 'reported_write_dac_unavailable')
        self.assertTrue(projected['error_present'])
        self.assertEqual(projected['cli']['policy_fields'], ['process.env[]'])
        self.assertNotIn('PRIVATE_SENTINEL', json.dumps(proof.closed_diagnostics(result)))
        self.assertEqual(runner.call_count, 1)

    def test_probe_timeout_spawn_and_invocation_failure_are_distinct(self):
        for error, expected in ((subprocess.TimeoutExpired(['executor.exe'], 30), 'timed_out'),
                                (FileNotFoundError(2, 'PRIVATE_SENTINEL'), 'spawn_failed'),
                                (PermissionError(13, 'PRIVATE_SENTINEL'), 'spawn_failed'),
                                (RuntimeError('PRIVATE_SENTINEL'), 'invocation_failed')):
            runner = Mock(side_effect=error)
            with self.subTest(expected=expected, error=type(error).__name__), tempfile.TemporaryDirectory() as directory:
                result = proof.run_case('executor.exe', {}, directory, runner=runner)
                projected = self.assert_closed_probe(result, expected)
                self.assertTrue(projected['attempted'])
                self.assertFalse(projected['completed'])
                self.assertEqual(result['failure_phase'], 'probe_invocation')
                self.assertEqual(result['error']['type'], type(error).__name__)
                self.assertFalse(result['started'])
                self.assertEqual(runner.call_count, 1)
                self.assertNotIn('PRIVATE_SENTINEL', json.dumps(proof.closed_diagnostics(result)))

    def test_probe_timeout_preserves_bounded_partial_diagnostics_without_parsing_as_success(self):
        stdout = json.dumps(full_probe()).encode() + b' ' * proof.MAX_OUTPUT
        stderr = (b'Invalid configuration at `process.env[7]`: PRIVATE_SENTINEL '
                  b'CreateProcessW WINERROR 5\n' + b'x' * proof.MAX_OUTPUT)
        runner = Mock(side_effect=subprocess.TimeoutExpired(['executor.exe'], 30, output=stdout, stderr=stderr))
        with tempfile.TemporaryDirectory() as directory:
            result = proof.run_case('executor.exe', {}, directory, runner=runner)
        actual = self.assert_closed_probe(result, 'timed_out')
        self.assertTrue(actual['attempted'])
        self.assertFalse(actual['completed'])
        self.assertIsNone(actual['exit_code'])
        self.assertEqual(actual['stdout_state'], 'not_observed')
        self.assertEqual(actual['tier'], 'not_observed')
        self.assertEqual(actual['stdout']['bytes_observed'], len(stdout))
        self.assertEqual(actual['stderr']['bytes_observed'], len(stderr))
        self.assertTrue(actual['stdout']['inspection_truncated'])
        self.assertTrue(actual['stderr']['inspection_truncated'])
        self.assertEqual(actual['stdout']['inspected_sha256'], hashlib.sha256(stdout[:65536]).hexdigest())
        self.assertEqual(actual['stderr']['inspected_sha256'], hashlib.sha256(stderr[:65536]).hexdigest())
        self.assertEqual(actual['stderr']['operations'], ['CreateProcessW'])
        self.assertEqual(actual['stderr']['native_codes'], [5])
        self.assertEqual(actual['cli']['policy_fields'], ['process.env[]'])
        self.assertEqual(actual['cli']['classes'], ['reported_typed_configuration'])
        self.assertNotIn('PRIVATE_SENTINEL', json.dumps(proof.closed_diagnostics(result)))
        self.assertFalse(result['started'])
        self.assertNotIn('probe', result)
        self.assertEqual(runner.call_count, 1)
        self.assertFalse(all(proof.stage0_checks(result).values()))

    def test_probe_timeout_ignores_unexpected_partial_stream_types(self):
        for stdout, stderr in ((None, None), ('PRIVATE_SENTINEL', 'PRIVATE_SENTINEL'), ([], {})):
            runner = Mock(side_effect=subprocess.TimeoutExpired(['executor.exe'], 30, output=stdout, stderr=stderr))
            with self.subTest(stdout=stdout, stderr=stderr), tempfile.TemporaryDirectory() as directory:
                result = proof.run_case('executor.exe', {}, directory, runner=runner)
                actual = self.assert_closed_probe(result, 'timed_out')
                self.assertIsNone(actual['stdout']['bytes_observed'])
                self.assertIsNone(actual['stderr']['bytes_observed'])
                self.assertEqual(actual['cli'], {'classes': [], 'policy_fields': []})
                self.assertNotIn('PRIVATE_SENTINEL', json.dumps(proof.closed_diagnostics(result)))
                self.assertFalse(result['started'])
                self.assertEqual(runner.call_count, 1)

    def test_policy_write_failure_never_attempts_probe(self):
        runner = Mock()
        with tempfile.TemporaryDirectory() as directory, patch.object(proof.smoke, 'save',
                side_effect=PermissionError(13, 'PRIVATE_SENTINEL')):
            result = proof.run_case('executor.exe', {}, directory, runner=runner)
        self.assert_closed_probe(result, 'not_attempted')
        self.assertFalse(result['probe_attempted'])
        self.assertFalse(result['started'])
        self.assertEqual(result['failure_phase'], 'policy_write')
        self.assertEqual(proof.closed_diagnostics(result)['failure']['type'], 'PermissionError')
        runner.assert_not_called()

    def test_exact_probe_output_bound_is_parsed_but_overbound_is_not(self):
        base = json.dumps(dict(full_probe(), tier='appcontainer-bfs')).encode()
        for size in (proof.MAX_OUTPUT, proof.MAX_OUTPUT + 1):
            completed = probe_process(stdout=base + b' ' * (size - len(base)))
            with self.subTest(size=size):
                result, runner = self.run_probe(completed)
                projected = proof.closed_diagnostics(result)['probe']
                self.assertEqual(result['probe_stdout_state'], 'object' if size == proof.MAX_OUTPUT else 'output_over_bound')
                self.assertEqual(projected['stdout']['bytes_observed'], size)
                self.assertTrue(projected['stdout']['inspection_truncated'])
                self.assertEqual(projected['stdout']['inspected_sha256'],
                                 hashlib.sha256(completed.stdout[:65536]).hexdigest())
                self.assertEqual(runner.call_count, 1)


class ExecutorDiagnosticRunnerTests(unittest.TestCase):
    def run_execution(self, directory, *, actor=None, actor_bytes=None, error=None, exit_code=0,
                      stdout=b'', stderr=b'selected isolation tier: base-container\n'):
        def run(args, **kwargs):
            if '--probe' in args:
                return probe_process()
            kwargs['stdout'].write(stdout)
            kwargs['stderr'].write(stderr)
            if actor is not None:
                (Path(directory) / 'actor.json').write_text(json.dumps(actor))
            elif actor_bytes is not None:
                (Path(directory) / 'actor.json').write_bytes(actor_bytes)
            if error is not None:
                raise error
            return subprocess.CompletedProcess(args, exit_code)
        runner = Mock(side_effect=run)
        result = proof.run_case('executor.exe', {}, directory, runner=runner)
        self.assertEqual(runner.call_count, 2)
        return checked_result(result)

    def test_success_retains_complete_evidence_without_inventing_contract_version(self):
        with tempfile.TemporaryDirectory() as directory:
            result = self.run_execution(directory, actor=evidence()['actor'])
        actual = proof.closed_diagnostics(result)
        self.assertTrue(all(result['checks'].values()))
        self.assertEqual(actual['execution']['outcome'], 'completed')
        self.assertEqual(actual['execution']['actor_report_state'], 'parsed')
        self.assertTrue(actual['execution']['actor_checks_passed'])
        self.assertEqual(actual['execution']['actual_tiers'], ['base-container'])
        self.assertFalse(actual['numeric_psec_contract_version_available'])
        self.assertFalse(actual['probe_schema_version_available'])

    def test_output_open_failure_retains_probe_without_claiming_launch(self):
        for filename in ('executor.stdout', 'executor.stderr'):
            runner = Mock(return_value=probe_process())
            with self.subTest(filename=filename), tempfile.TemporaryDirectory() as directory:
                (Path(directory) / filename).write_bytes(b'already owned')
                result = proof.run_case('executor.exe', {}, directory, runner=runner)
                actual = proof.closed_diagnostics(result)
                self.assertEqual(result['failure_phase'], 'executor_output_open')
                self.assertEqual(actual['failure']['type'], 'FileExistsError')
                self.assertEqual(actual['probe']['outcome'], 'selected')
                self.assertTrue(actual['probe']['completed'])
                self.assertFalse(actual['execution']['launch_attempted'])
                self.assertEqual(actual['execution']['outcome'], 'not_attempted')
                self.assertEqual(actual['execution']['actor_report_state'], 'not_reached')
                self.assertEqual(runner.call_count, 1)
                self.assertEqual((Path(directory) / filename).read_bytes(), b'already owned')

    def test_executor_exception_retains_outputs_tier_and_actor_observations(self):
        payload = b'PRIVATE_SENTINEL CreateProcessW WINERROR 5\n'
        with tempfile.TemporaryDirectory() as directory:
            result = self.run_execution(directory, actor=evidence()['actor'], stdout=payload,
                                        error=PermissionError(13, 'PRIVATE_SENTINEL'))
        actual = proof.closed_diagnostics(result)
        self.assertEqual(result['failure_phase'], 'executor_invocation')
        self.assertEqual(actual['probe']['outcome'], 'selected')
        self.assertEqual(actual['execution']['outcome'], 'launch_failed')
        self.assertTrue(actual['execution']['launch_attempted'])
        self.assertEqual(actual['execution']['stdout']['bytes_observed'], len(payload))
        self.assertEqual(actual['execution']['stdout']['native_codes'], [5])
        self.assertEqual(actual['execution']['stdout']['operations'], ['CreateProcessW'])
        self.assertEqual(actual['execution']['actual_tiers'], ['base-container'])
        self.assertEqual(actual['execution']['actor_report_state'], 'parsed')
        self.assertTrue(actual['execution']['actor_checks_passed'])
        self.assertFalse(result['checks']['normal_exit'])
        self.assertFalse(result['checks']['no_harness_error'])
        self.assertNotIn('PRIVATE_SENTINEL', json.dumps(actual))

    def test_executor_timeout_retains_partial_outputs_and_actor_evidence(self):
        payload = b'PRIVATE_SENTINEL ResumeThread ERROR 5\n'
        with tempfile.TemporaryDirectory() as directory:
            result = self.run_execution(directory, actor=evidence()['actor'], stdout=payload,
                                        error=subprocess.TimeoutExpired(['executor.exe'], 35))
        actual = proof.closed_diagnostics(result)
        self.assertEqual(actual['probe']['outcome'], 'selected')
        self.assertEqual(actual['execution']['outcome'], 'timed_out')
        self.assertTrue(actual['execution']['launch_attempted'])
        self.assertTrue(actual['execution']['timed_out'])
        self.assertIsNone(actual['execution']['exit_code'])
        self.assertEqual(actual['execution']['stdout']['bytes_observed'], len(payload))
        self.assertEqual(actual['execution']['actual_tiers'], ['base-container'])
        self.assertEqual(actual['execution']['actor_report_state'], 'parsed')
        self.assertTrue(actual['execution']['actor_checks_passed'])
        self.assertFalse(result['checks']['normal_exit'])
        self.assertNotIn('PRIVATE_SENTINEL', json.dumps(actual))

    def test_nonzero_executor_exit_keeps_valid_actor_but_never_passes(self):
        with tempfile.TemporaryDirectory() as directory:
            result = self.run_execution(directory, actor=evidence()['actor'], exit_code=0xc0000005)
        actual = proof.closed_diagnostics(result)
        self.assertEqual(actual['execution']['exit_code'], 0xc0000005)
        self.assertEqual(actual['execution']['outcome'], 'completed')
        self.assertTrue(actual['execution']['actor_checks_passed'])
        self.assertFalse(all(result['checks'].values()))

    def test_actor_states_are_distinct_and_fail_closed(self):
        cases = [('absent', None), ('over_bound', b' ' * (proof.smoke.MAX_JSON + 1)),
                 ('malformed_json', b'{invalid'), ('malformed_json', b'\xff'),
                 ('non_object', b'[]'), ('non_object', b'null'), ('non_object', b'false')]
        for state, data in cases:
            with self.subTest(state=state, data=data[:20] if data else data), tempfile.TemporaryDirectory() as directory:
                result = self.run_execution(directory, actor_bytes=data)
                actual = proof.closed_diagnostics(result)
                self.assertEqual(result['actor_report_state'], state)
                self.assertEqual(actual['execution']['actor_report_state'], state)
                self.assertFalse(actual['execution']['actor_checks_passed'])
                self.assertEqual(actual['probe']['outcome'], 'selected')
                self.assertEqual(actual['execution']['actual_tiers'], ['base-container'])
                self.assertNotIn('actor', result)
                self.assertFalse(all(result['checks'].values()))
                if state != 'absent':
                    self.assertEqual(result['failure_phase'], 'actor_read')

    def test_actor_link_is_not_opened_or_accepted(self):
        original_open = Path.open
        def guarded_open(path, *args, **kwargs):
            if path.name == 'actor.json':
                self.fail('A rejected actor link must never be opened')
            return original_open(path, *args, **kwargs)
        with tempfile.TemporaryDirectory() as directory, patch.object(Path, 'is_symlink', autospec=True,
                side_effect=lambda path: path.name == 'actor.json'), patch.object(Path, 'open', guarded_open):
            result = self.run_execution(directory)
        actual = proof.closed_diagnostics(result)
        self.assertEqual(actual['execution']['actor_report_state'], 'link_rejected')
        self.assertFalse(actual['execution']['actor_checks_passed'])
        self.assertNotIn('actor', result)
        self.assertFalse(all(result['checks'].values()))

    def test_actor_reparse_bit_is_reported_without_changing_existing_acceptance(self):
        original_lstat = Path.lstat
        for attributes, expected in ((0, False), (0x400, True), (0x420, True)):
            def observed_lstat(path, *args, **kwargs):
                actual = original_lstat(path, *args, **kwargs)
                if path.name == 'actor.json':
                    return Mock(st_file_attributes=attributes, st_mode=actual.st_mode)
                return actual
            with self.subTest(attributes=attributes), tempfile.TemporaryDirectory() as directory, \
                    patch.object(Path, 'lstat', observed_lstat):
                result = self.run_execution(directory, actor=evidence()['actor'])
                actual = proof.closed_diagnostics(result)['execution']
                self.assertIs(actual['actor_reparse_point_observed'], expected)
                self.assertEqual(actual['actor_report_state'], 'parsed')
                self.assertTrue(all(result['checks'].values()))

    def test_unavailable_reparse_metadata_remains_unknown_not_false(self):
        original_lstat = Path.lstat
        calls = []
        def unavailable_lstat(path, *args, **kwargs):
            if path.name == 'actor.json' and not calls:
                calls.append(path)
                raise OSError('PRIVATE_SENTINEL')
            return original_lstat(path, *args, **kwargs)
        with tempfile.TemporaryDirectory() as directory, patch.object(Path, 'lstat', unavailable_lstat):
            result = self.run_execution(directory, actor=evidence()['actor'])
        actual = proof.closed_diagnostics(result)['execution']
        self.assertIsNone(actual['actor_reparse_point_observed'])
        self.assertEqual(actual['actor_report_state'], 'parsed')
        self.assertTrue(all(result['checks'].values()))

    def test_parsed_but_failed_actor_is_not_confused_with_parse_failure(self):
        for field, value in (('queriesSucceeded', False), ('nonce', 'b' * 32), ('tokenIsAppContainer', False),
                             ('tokenElevated', True), ('errors', ['PRIVATE_SENTINEL'])):
            actor = dict(evidence()['actor'])
            actor[field] = value
            with self.subTest(field=field), tempfile.TemporaryDirectory() as directory:
                result = self.run_execution(directory, actor=actor)
                actual = proof.closed_diagnostics(result)
                self.assertEqual(actual['execution']['actor_report_state'], 'parsed')
                self.assertFalse(actual['execution']['actor_checks_passed'])
                self.assertFalse(all(result['checks'].values()))
                self.assertNotIn('PRIVATE_SENTINEL', json.dumps(actual))

    def test_actor_read_failure_retains_probe_and_executor_evidence(self):
        original_open = Path.open
        def failing_open(path, mode='r', *args, **kwargs):
            if path.name == 'actor.json' and mode == 'rb':
                raise PermissionError(13, 'PRIVATE_SENTINEL')
            return original_open(path, mode, *args, **kwargs)
        with tempfile.TemporaryDirectory() as directory, patch.object(Path, 'open', failing_open):
            result = self.run_execution(directory, actor=evidence()['actor'])
        actual = proof.closed_diagnostics(result)
        self.assertEqual(result['failure_phase'], 'actor_read')
        self.assertEqual(actual['execution']['actor_report_state'], 'read_failed')
        self.assertEqual(actual['probe']['outcome'], 'selected')
        self.assertEqual(actual['execution']['actual_tiers'], ['base-container'])
        self.assertNotIn('PRIVATE_SENTINEL', json.dumps(actual))
        self.assertFalse(all(result['checks'].values()))

    def test_executor_diagnostic_read_failure_still_inspects_actor(self):
        original_open = Path.open
        def failing_open(path, mode='r', *args, **kwargs):
            if path.name == 'executor.stderr' and mode == 'rb':
                raise PermissionError(13, 'PRIVATE_SENTINEL')
            return original_open(path, mode, *args, **kwargs)
        payload = b'CreateProcessW WINERROR 5 PRIVATE_SENTINEL\n'
        with tempfile.TemporaryDirectory() as directory, patch.object(Path, 'open', failing_open):
            result = self.run_execution(directory, actor=evidence()['actor'], stdout=payload)
        actual = proof.closed_diagnostics(result)
        self.assertEqual(result['failure_phase'], 'executor_diagnostic_read')
        self.assertEqual(actual['execution']['stdout']['bytes_observed'], len(payload))
        self.assertEqual(actual['execution']['actor_report_state'], 'parsed')
        self.assertTrue(actual['execution']['actor_checks_passed'])
        self.assertEqual(actual['probe']['outcome'], 'selected')
        self.assertFalse(result['checks']['actual_base_container'])
        self.assertFalse(result['checks']['no_harness_error'])
        self.assertNotIn('PRIVATE_SENTINEL', json.dumps(actual))

    def test_executor_output_overbound_keeps_summary_without_accepting_tier(self):
        payload = b'selected isolation tier: base-container\n' + b'x' * proof.MAX_OUTPUT
        with tempfile.TemporaryDirectory() as directory:
            result = self.run_execution(directory, actor=evidence()['actor'], stdout=payload, stderr=b'')
        actual = proof.closed_diagnostics(result)
        self.assertEqual(actual['execution']['stdout']['bytes_observed'], proof.MAX_OUTPUT + 1)
        self.assertTrue(actual['execution']['stdout']['inspection_truncated'])
        self.assertEqual(actual['execution']['stdout']['inspected_sha256'],
                         hashlib.sha256(payload[:65536]).hexdigest())
        self.assertEqual(actual['execution']['actual_tiers'], [])
        self.assertFalse(result['checks']['actual_base_container'])


class RunnerTests(unittest.TestCase):
    def test_unsupported_never_executes_actor(self):
        runner=Mock(return_value=subprocess.CompletedProcess([], 0, json.dumps(dict(probe(), tier='appcontainer-bfs')).encode(), b''))
        with tempfile.TemporaryDirectory() as d:
            r=proof.run_case('executor.exe', {}, d, runner=runner)
        self.assertEqual(r['status'],'unsupported'); self.assertFalse(r['started']); self.assertEqual(runner.call_count,1)
    def test_malformed_probe_never_executes_actor(self):
        runner=Mock(return_value=subprocess.CompletedProcess([], 0, b'garbage', b''))
        with tempfile.TemporaryDirectory() as d: r=proof.run_case('executor.exe',{},d,runner=runner)
        self.assertFalse(r['started']); self.assertEqual(runner.call_count,1)
    def test_oversize_probe_fails_closed(self):
        runner=Mock(return_value=subprocess.CompletedProcess([], 0, b' '*(proof.MAX_OUTPUT+1), b''))
        with tempfile.TemporaryDirectory() as d: r=proof.run_case('executor.exe',{},d,runner=runner)
        self.assertFalse(r['started'])
    def test_runtime_tier_is_not_copied_from_probe(self):
        def run(args, **kw):
            if '--probe' in args: return subprocess.CompletedProcess(args,0,json.dumps(probe()).encode(),b'')
            kw['stderr'].write(b'selected isolation tier: appcontainer-bfs\n')
            return subprocess.CompletedProcess(args,0)
        with tempfile.TemporaryDirectory() as d: r=proof.run_case('executor.exe',{},d,runner=run)
        self.assertEqual(r['actual_tiers'], ['appcontainer-bfs'])
    def test_timeout_is_preserved(self):
        def run(args, **kw):
            if '--probe' in args: return subprocess.CompletedProcess(args,0,json.dumps(probe()).encode(),b'')
            raise subprocess.TimeoutExpired(args,35)
        with tempfile.TemporaryDirectory() as d: r=proof.run_case('executor.exe',{},d,runner=run)
        self.assertTrue(r['timed_out']); self.assertIsNone(r['executor_exit_code'])
    def test_runtime_requires_explicit_windows_approval(self):
        class Args: disposable_ci=False; approved_security_test=False
        with self.assertRaises(PermissionError): proof.controller(Args())



class RequiredEnvironmentTests(unittest.TestCase):
    def native(self):
        return {'SYSTEMROOT':r'C:\Windows','LOCALAPPDATA':r'C:\Users\Fixture\AppData\Local'}
    def test_exact_pair_and_case_insensitive_native_agreement(self):
        self.assertEqual(proof.validate_required_environment(self.native(),self.native()),ENV)
        observed={k:v.lower() for k,v in self.native().items()}
        self.assertEqual(proof.validate_required_environment(observed,self.native()),[k+'='+v for k,v in observed.items()])
    def test_missing_extra_casechanged_keys_fail_closed(self):
        for bad in ({}, {'SYSTEMROOT':r'C:\Windows'},dict(self.native(),PATH='SECRET'),
                    {'SystemRoot':r'C:\Windows','LOCALAPPDATA':self.native()['LOCALAPPDATA']},None,[]):
            with self.assertRaises(ValueError):proof.validate_required_environment(bad,self.native())
            with self.assertRaises(ValueError):proof.validate_required_environment(self.native(),bad)
    def test_path_alias_injection_or_unbounded_values_rejected(self):
        bad_values=(None,True,1,'',r'Windows',r'C:Windows',r'\Windows',r'\\server\share',r'\\?\C:\Windows',
            'C:/Windows',r'C:\Windows\..\Elsewhere',r'C:\Windows\.','C:\\Windows\\',r'C:\\Windows',
            'C:\\Windows ', 'C:\\Windows.', 'C:\\Windows\nSECRET', 'C:\\Windows\x00SECRET',
            r'C:\Windows:stream',r'C:\%SYSTEMROOT%',r'C:\PROGRA~1',r'C:\Windows=SECRET',
            r'C:\Windows?','C:\\'+'a'*260,'C:\\\ud800')
        for value in bad_values:
            native=self.native();observed=self.native();observed['SYSTEMROOT']=value
            with self.subTest(value=repr(value)),self.assertRaises(ValueError):proof.validate_required_environment(observed,native)
    def test_other_user_or_windows_directory_rejected(self):
        for key,value in (('SYSTEMROOT',r'D:\Windows'),('LOCALAPPDATA',r'C:\Users\Other\AppData\Local')):
            observed=self.native();observed[key]=value
            with self.assertRaises(ValueError):proof.validate_required_environment(observed,self.native())
    def test_policy_requires_exact_two_explicit_entries(self):
        for value in (None,[],ENV[:1],ENV+['PATH=SECRET'],list(reversed(ENV)),
                      ['SystemRoot=C:\\Windows',ENV[1]],['SYSTEMROOT=',ENV[1]],dict(self.native())):
            with self.subTest(value=value),self.assertRaises(ValueError):
                proof.policy('inputs','profile','actor.exe',N,required_environment=value)
    def test_policy_only_environment_changed(self):
        value=proof.policy('inputs','profile','actor.exe',N,required_environment=ENV)
        self.assertEqual(value['process']['env'],ENV);self.assertIsNot(value['process']['env'],ENV)
        self.assertIs(value['process']['inheritDefaultEnv'],False)
        self.assertEqual(value['filesystem'],{'readonlyPaths':['inputs'],'readwritePaths':['profile']})
        self.assertEqual(value['ui'],{'disable':True,'clipboard':'none'})
        self.assertEqual(value['network'],{'egress':{'default':'deny'},'ingress':{'default':'deny','hostLoopback':'deny'}})
        self.assertEqual(value['fallback'],{'allowDaclMutation':False})
    def test_observation_selects_only_two_native_agreed_existing_directories(self):
        native=self.native()
        def path(value):
            directory=Mock();directory.is_dir.return_value=True;directory.resolve.return_value=value;return directory
        with patch.object(proof,'native_required_environment_paths',return_value=native),patch.dict(proof.os.environ,dict(native,SECRET='never copied'),clear=True),patch.object(proof,'Path',side_effect=path):
            self.assertEqual(proof.observe_required_environment(),ENV)
    def test_missing_or_nonexistent_or_resolved_alias_fails_closed(self):
        native=self.native()
        for exists,resolved in ((False,native['SYSTEMROOT']),(True,r'C:\Other')):
            directory=Mock();directory.is_dir.return_value=exists;directory.resolve.return_value=resolved
            with patch.object(proof,'native_required_environment_paths',return_value=native),patch.dict(proof.os.environ,native,clear=True),patch.object(proof,'Path',return_value=directory):
                with self.assertRaises(ValueError):proof.observe_required_environment()
        with patch.object(proof,'native_required_environment_paths',return_value=native),patch.dict(proof.os.environ,{},clear=True):
            with self.assertRaises(ValueError):proof.observe_required_environment()
    def test_controller_observes_after_ordinary_gate_before_executor(self):
        args=Mock(disposable_ci=True,approved_security_test=True)
        for identity in ({'elevated':True,'appcontainer':False,'cid':1}, {'elevated':False,'appcontainer':True,'cid':1}, {'elevated':False,'appcontainer':False,'cid':2}):
            with patch.object(proof.os,'name','nt'),patch.object(proof.smoke,'identity_snapshot',return_value=identity),patch.object(proof,'observe_required_environment') as observe:
                with self.assertRaises(PermissionError):proof.controller(args)
                observe.assert_not_called()
        with patch.object(proof.os,'name','nt'),patch.object(proof.smoke,'identity_snapshot',return_value={'elevated':False,'appcontainer':False,'cid':1}),patch.object(proof,'observe_required_environment',side_effect=ValueError('closed')) as observe,patch.object(proof.smoke,'verify_executor') as executor:
            with self.assertRaises(ValueError):proof.controller(args)
            observe.assert_called_once_with();executor.assert_not_called()
            self.assertEqual(args.diagnostic_phase,'required_environment')
    def test_empty_environment_controller_boundary_never_reaches_executor_or_actor(self):
        args=Mock(disposable_ci=True,approved_security_test=True)
        with patch.object(proof.os,'name','nt'),patch.object(proof.smoke,'identity_snapshot',return_value={'elevated':False,'appcontainer':False,'cid':1}),patch.object(proof,'native_required_environment_paths',return_value=self.native()),patch.dict(proof.os.environ,{},clear=True),patch.object(proof.smoke,'verify_executor') as verify,patch.object(proof,'run_case') as run_case,patch.object(proof.subprocess,'run') as subprocess_run:
            with self.assertRaises(ValueError):proof.controller(args)
            verify.assert_not_called();run_case.assert_not_called();subprocess_run.assert_not_called()
            self.assertEqual(args.diagnostic_phase,'required_environment')
    def test_empty_policy_environment_never_enters_case_runner(self):
        with patch.object(proof,'run_case') as run_case,patch.object(proof.subprocess,'run') as subprocess_run:
            with self.assertRaises(ValueError):
                proof.run_case('executor',proof.policy('inputs','profile','actor.exe',N,required_environment=[]),'profile')
            run_case.assert_not_called();subprocess_run.assert_not_called()
    def test_environment_error_and_projection_never_publish_values(self):
        observed=self.native();observed['LOCALAPPDATA']=r'C:\Users\PRIVATE_SENTINEL\AppData\Local'
        with self.assertRaises(ValueError) as caught:proof.validate_required_environment(observed,self.native())
        self.assertNotIn('PRIVATE_SENTINEL',str(caught.exception))
        result=proof.closed_diagnostics({'required_environment':observed,'controller_phase':'required_environment'})
        self.assertNotIn('PRIVATE_SENTINEL',json.dumps(result));self.assertEqual(result['controller_phase'],'required_environment')


class NativeIdentityFactTests(unittest.TestCase):
    def facts(self, report):
        return proof.closed_diagnostics(report)['execution']['native_identity']
    def test_each_existing_clause_has_exact_false_diagnostic(self):
        mutations=(('schemaVersion',2,'schema_v1'),('mode','wrong','mode_actor'),
            ('queriesSucceeded',False,'queries_succeeded'),('errors',['hidden'],'errors_empty'),
            ('tokenIsAppContainer',False,'token_is_appcontainer'),('tokenAppContainerSid',None,'sid_string'),
            ('tokenAppContainerSid','S-1-0-0','sid_shape_valid'),('tokenElevated',True,'not_elevated'),
            ('isProcessInJob',False,'in_job'),('tokenCapabilities',['hidden'],'capabilities_empty'),
            ('pid',0,'pid_positive_integer'),('pid',True,'pid_positive_integer'))
        for field,value,key in mutations:
            report=evidence();report['actor'][field]=value;report['checks']=proof.stage0_checks(report)
            facts=self.facts(report)
            with self.subTest(field=field,value=value):
                self.assertFalse(facts[key]);self.assertTrue(facts['available'])
                self.assertFalse(facts['predicate_conjunction']);self.assertFalse(facts['recorded_check_passed'])
                self.assertTrue(facts['recorded_check_observed'])
                self.assertEqual(facts['predicate_conjunction'],report['checks']['native_identity'])
    def test_valid_facts_preserve_exact_conjunction(self):
        report=evidence();report['checks']=proof.stage0_checks(report)
        facts=self.facts(report)
        self.assertTrue(all(facts[k] for k in proof.NATIVE_IDENTITY_PREDICATES))
        self.assertTrue(facts['predicate_conjunction']);self.assertTrue(facts['recorded_check_passed'])
    def test_type_observations_do_not_change_original_equality_semantics(self):
        for schema in (True,1.0):
            report=evidence();report['actor']['schemaVersion']=schema
            facts=self.facts(report)
            self.assertTrue(facts['schema_v1']);self.assertFalse(facts['schema_typed'])
            self.assertEqual(facts['predicate_conjunction'],proof.stage0_checks(report)['native_identity'])
    def test_missing_null_and_wrong_types_have_presence_and_type_flags(self):
        for name,field,expected in proof.NATIVE_IDENTITY_FIELDS:
            for present,value in ((False,None),(True,None),(True,{})):
                report=evidence()
                if present:report['actor'][field]=value
                else:del report['actor'][field]
                facts=self.facts(report)
                self.assertIs(facts[name+'_present'],present)
                self.assertFalse(facts[name+'_typed'])
                self.assertEqual(facts['predicate_conjunction'],proof.stage0_checks(report)['native_identity'])
    def test_original_false_is_not_repaired_by_positive_predicates(self):
        report=evidence();report['checks']={'native_identity':False}
        facts=self.facts(report)
        self.assertFalse(facts['recorded_check_passed']);self.assertTrue(facts['recorded_check_observed'])
        self.assertTrue(facts['predicate_conjunction'])
        self.assertFalse(report['checks']['native_identity'])
    def test_old_or_unavailable_actor_not_invented_as_observed(self):
        for report in ({},{'actor':None},{'actor':[]},{'diagnostics':{'execution':{}}}):
            facts=self.facts(report)
            self.assertFalse(facts['available']);self.assertFalse(facts['recorded_check_observed'])
            self.assertFalse(facts['predicate_conjunction'])
    def test_repeated_projection_is_idempotent_and_bool_only(self):
        report=evidence();report['checks']=proof.stage0_checks(report)
        first=proof.closed_diagnostics(report)
        self.assertEqual(first,proof.closed_diagnostics({'diagnostics':first}))
        facts=first['execution']['native_identity']
        self.assertEqual(set(facts),set(proof.NATIVE_IDENTITY_FACT_KEYS)|{'predicate_conjunction'})
        self.assertTrue(all(type(v) is bool for v in facts.values()))
    def test_malicious_values_and_extras_are_not_exported(self):
        sentinel='PRIVATE_SENTINEL_PATH_SID_CAPABILITY_PID'
        report=evidence();report['actor'].update({key:sentinel*1000 for _,key,_ in proof.NATIVE_IDENTITY_FIELDS})
        report['actor'][sentinel]=sentinel
        facts=self.facts(report)
        self.assertNotIn(sentinel,json.dumps(facts));self.assertLess(len(json.dumps(facts)),2000)
        poisoned={key:sentinel for key in proof.NATIVE_IDENTITY_FACT_KEYS};poisoned[sentinel]=True
        poisoned['predicate_conjunction']=True
        projected=self.facts({'diagnostics':{'execution':{'native_identity':poisoned}}})
        self.assertNotIn(sentinel,json.dumps(projected));self.assertFalse(any(projected.values()))
    def test_diagnostics_never_mutate_acceptance(self):
        report=evidence();before=copy.deepcopy(report);checks=proof.stage0_checks(report)
        self.facts(report)
        self.assertEqual(report,before);self.assertEqual(proof.stage0_checks(report),checks)


class DiagnosticOperationBoundTests(unittest.TestCase):
    def test_all_recognized_labels_bounded_with_count_and_truncation(self):
        labels=list(proof.DIAGNOSTIC_OPERATIONS)
        self.assertEqual(len(labels),14)
        raw={'operations':labels,'inspected_sha256':'a'*64,'bytes_observed':123,
             'categories':['psec'],'native_codes':[5],
             'error_envelopes':[{'operations':labels,'message_sha256':'b'*64,'code':'backend_error','message_class':'psec_environment_create','native_codes':[5]}]}
        result=proof.diagnostic_summary(raw)
        for item in (result,result['error_envelopes'][0]):
            self.assertEqual(item['operations'],labels[:8]);self.assertEqual(item['operation_label_count'],len(labels))
            self.assertTrue(item['operations_truncated']);self.assertEqual(item['native_codes'],[5])
        self.assertEqual(result['inspected_sha256'],'a'*64);self.assertEqual(result['bytes_observed'],123)
        self.assertEqual(result['error_envelopes'][0]['message_sha256'],'b'*64)
        self.assertEqual(result,proof.diagnostic_summary(result))
    def test_sixteen_allowlisted_fixture_labels_truncate_to_eight(self):
        # Production currently has 14 allowlisted labels; exercise a 16-label
        # input without adding invented operations to the production allowlist.
        fixture=proof.DIAGNOSTIC_OPERATIONS+('FixtureOperationA','FixtureOperationB')
        with patch.object(proof,'DIAGNOSTIC_OPERATIONS',fixture):
            result=proof.diagnostic_summary({'operations':list(fixture)})
            self.assertEqual(len(result['operations']),8);self.assertEqual(result['operation_label_count'],16)
            self.assertTrue(result['operations_truncated']);self.assertEqual(result,proof.diagnostic_summary(result))
    def test_small_labels_not_reported_truncated_and_unknowns_not_counted(self):
        for count in (0,1,8):
            labels=list(proof.DIAGNOSTIC_OPERATIONS[:count])
            result=proof.diagnostic_summary({'operations':labels+['SECRET']*100})
            self.assertEqual(result['operations'],labels);self.assertEqual(result['operation_label_count'],count)
            self.assertFalse(result['operations_truncated']);self.assertNotIn('SECRET',json.dumps(result))
    def test_invalid_counts_never_escape_or_expand_bounds(self):
        for count in (True,-1,17,'SECRET',{},None):
            result=proof.diagnostic_summary({'operations':['CreateProcessW'],'operation_label_count':count,'operations_truncated':'true'})
            self.assertEqual(result['operation_label_count'],1);self.assertFalse(result['operations_truncated'])
    def test_operation_summaries_never_change_acceptance(self):
        report=evidence();expected=proof.stage0_checks(report)
        report['diagnostics']={'execution':{'stderr':{'operations':list(proof.DIAGNOSTIC_OPERATIONS)}}}
        proof.closed_diagnostics(report)
        self.assertEqual(proof.stage0_checks(report),expected)


if __name__ == "__main__":
    unittest.main()
