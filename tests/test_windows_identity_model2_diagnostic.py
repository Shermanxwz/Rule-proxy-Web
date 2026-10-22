"""Pure diagnostic gates. No profiles, policy, processes or sockets are created."""
import copy
import importlib.util
from pathlib import Path
from types import SimpleNamespace
import unittest

ROOT = Path(__file__).resolve().parents[1]
spec = importlib.util.spec_from_file_location('model2_diagnostic', ROOT / '.github/windows_identity_model2_controller.py')
m = importlib.util.module_from_spec(spec)
spec.loader.exec_module(m)
l = m.live


def observation(operation='profiles-status'):
    return dict(schema_version=1, stage='model2-firewall-operation', operation=operation, attempted=False,
        success=True, record=None, failure=None, execution_mode='profiles-off-diagnostic',
        profiles_off_verified=True, effective_full_verified=False, profiles_qpc=9000)


def completed(connected=False):
    v = l.blank('profiles-off-diagnostic')
    for key in ('sources','artifacts','ordinary','guard_held','live_probe','selected_held','declared_caps',
                'positive','origin_healthy','same_selected','cleanup'):
        v['checks'][key] = True
    v['observations'] = {key: True for key in v['observations']}
    v['diagnostic'].update(profiles_off_verified=True, exact_rule_scope_verified=True, positive_verified=True,
        direct_attempted=True, observation_complete=True, direct_connected=connected, forbidden_nonce_received=connected)
    v['violations'].update(direct_connected=connected, forbidden_receiver_accepted=connected)
    return v


class DiagnosticTests(unittest.TestCase):
    def test_leak_observation_can_complete_but_never_qualifies(self):
        for connected in (False, True):
            with self.subTest(connected=connected):
                v = l.finalize_public(completed(connected))
                self.assertEqual(v['status'], 'diagnostic-observed')
                self.assertTrue(v['diagnostic_completed'])
                self.assertFalse(l.first_ready(v, require_guard=False))
                for key in ('first_chain_verified','local_c_qualified','direct_deny_verified','product_acceptance'):
                    self.assertFalse(v[key])
                self.assertFalse(v['checks']['firewall_exact'])

    def test_inner_and_outer_guard_predicates_are_distinct(self):
        v = completed(True)
        v['checks']['guard_held'] = False
        self.assertTrue(l.diagnostic_ready(v, require_guard=False))
        self.assertFalse(l.diagnostic_ready(v))
        self.assertFalse(l.finalize_public(v)['diagnostic_completed'])
        for field in ('positive_verified','direct_attempted','observation_complete','profiles_off_verified'):
            bad = completed()
            bad['diagnostic'][field] = False
            self.assertFalse(l.diagnostic_ready(bad))
        bad = completed()
        bad['failure'] = 'deadline'
        self.assertFalse(l.diagnostic_ready(bad))

    def test_profiles_report_closed_explicit_fresh_and_original_deadline(self):
        good = observation()
        self.assertIs(m.maintenance.validate_profiles_observation(good,'profiles-status',
            'profiles-off-diagnostic',1000,1000,20000,10000),good)
        variants = [dict(good, profiles_off_verified=x) for x in (False, None, 'False', 'NotConfigured', 1)]
        variants += [dict(good, profiles_qpc=x) for x in (None,999,20000,10001,3999)]
        variants += [dict(good, extra=False), dict(good, execution_mode='strict'),dict(good, attempted=True)]
        for bad in variants:
            with self.subTest(bad=bad):
                with self.assertRaises(ValueError):
                    m.maintenance.validate_profiles_observation(bad,'profiles-status',
                        'profiles-off-diagnostic',1000,1000,20000,10000)

    def test_strict_full_requirement_unchanged(self):
        v = observation('create')
        v.update(execution_mode='strict', profiles_off_verified=False, profiles_qpc=None)
        with self.assertRaises(ValueError):
            m.maintenance.validate_profiles_observation(v,'create','strict',1000,1000,20000,10000)
        v['effective_full_verified'] = True
        m.maintenance.validate_profiles_observation(v,'create','strict',1000,1000,20000,10000)

    def test_go_refresh_propagates_failure_and_has_no_automatic_fallback(self):
        owner = object.__new__(m.FirstController)
        owner.mode = 'profiles-off-diagnostic'
        owner.config = dict(start_qpc=1000,frequency=1000,deadline_qpc=20000)
        owner.rule_owner = SimpleNamespace(rule={'name':'fixed'})
        owner.budget = SimpleNamespace(read=lambda:10000)
        calls = []
        owner.maintenance = SimpleNamespace(last_observation=observation(), operation=lambda *args:calls.append(args))
        owner.refresh_profiles()
        self.assertEqual(calls,[('profiles-status','fixed')])
        owner.maintenance.last_observation = dict(observation(), profiles_off_verified=False)
        with self.assertRaises(ValueError): owner.refresh_profiles()
        owner.mode = 'strict'
        owner.refresh_profiles()
        self.assertEqual(len(calls),2)


if __name__ == '__main__': unittest.main()
