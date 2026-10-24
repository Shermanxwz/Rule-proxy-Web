"""Pure C ownership/barrier counterexamples. No Windows actor or network runs."""
import copy
import importlib.util
from pathlib import Path
import struct
import tempfile
from types import SimpleNamespace
import unittest
from unittest import mock

ROOT = Path(__file__).resolve().parents[1]
spec = importlib.util.spec_from_file_location('c_owner_test', ROOT / '.github/windows_identity_model2_controller.py')
m = importlib.util.module_from_spec(spec)
spec.loader.exec_module(m)
l = m.live
AGENTIC = 'S-1-15-3-1024-1-2-3-4-5-6-7-8'
CATALOG = {'AgenticAppContainer': AGENTIC, 'privateNetworkClientServer': l.PNCS}
AC = 'S-1-15-2-1-2-3-4-5-6-7'


def ordinary():
    return dict(sid='S-1-5-21-1-2-3-1000', session_id=1, token_type=1, elevation_type=3, elevated=False,
        integrity_rid=8192, admin_attributes=16, appcontainer=False, appcontainer_sid=None, capability_count=0, ui_access=False)


def selected():
    return dict(ordinary(), appcontainer=True, appcontainer_sid=AC, capability_count=2, integrity_rid=4096)


def config():
    values = [('%032x' % i) for i in range(1, 10)]
    hashes = {name: 'a' * 64 for name in l.SOURCES}
    return dict(schema_version=1, stage='model2-first-owned-input', run=values[0], boot_case=values[1],
        positive_case=values[2], direct_case=values[3], admission_nonce=values[4], maintenance_nonce=values[5],
        health_cases=values[6:], capability_profile='agentic-pncs', start_qpc=1000, frequency=1000,
        deadline_qpc=116000, root_deadline_qpc=121000, source_hashes=hashes, source_sha256=l.sha(l.encode(hashes)),
        actor_sha256='b' * 64, manifest_sha256='c' * 64, guard_job_name='Local\\RuleProxy.LocalGuard.' + values[0],
        device_sha256='d' * 64, recovery_plan_sha256='e' * 64)


class Clock:
    def __init__(self, now=1000):
        self.now = now
        self.log = []
    def qpc(self):
        self.now += 1
        return self.now
    def qpc_frequency(self):
        return 1000
    def close(self, handle):
        self.log.append(('close', handle))


class GateAPI(Clock):
    def __init__(self, fault=None):
        super().__init__()
        self.fault = fault
        self.snapshots = 0
    def wait(self, handle, milliseconds):
        return self.fault == 'g_exited' and handle == 1
    def creation_time(self, handle):
        if handle == 1:
            return 100
        return 201 if self.fault == 'pid_reused' and handle == 2050 else 200
    def process_id(self, handle):
        return 40 if handle == 1 else 50
    def parent_snapshot(self):
        self.snapshots += 1
        result = {50: 40, 60: 90}
        if self.fault == 'new_child' and self.snapshots == 2:
            result[51] = 40
        if self.fault == 'two_children':
            result[51] = 40
        if self.fault == 'child_disappeared' and self.snapshots == 2:
            del result[50]
        return result
    def open_query_process(self, pid):
        if self.fault == 'query_denied':
            raise PermissionError('fake')
        return 1000 + pid
    def open_owned_process(self, pid):
        return 2000 + pid
    def verify_job(self, job, handle):
        self.log.append(('exact_job', job, handle))
        if self.fault == 'wrong_job':
            raise ValueError('fake')
    def verify_image(self, handle, image):
        self.log.append(('image', handle))
        if self.fault == 'wrong_image':
            raise ValueError('fake')
    def token_for_process(self, handle):
        return 3000 + handle
    def identity(self, token):
        result = selected()
        if self.fault == 'another_user':
            result['sid'] = 'S-1-5-21-9-9-9-1000'
        return result
    def groups(self, token, kind, name):
        values = [(AGENTIC, 4), (l.PNCS, 4)]
        if self.fault == 'unknown_cap':
            values[1] = ('S-1-15-3-999', 4)
        if self.fault == 'wrong_attributes':
            values[1] = (l.PNCS, 6)
        return values


class OwnershipTests(unittest.TestCase):
    def test_exact_native_operation_labels_and_payload_lengths(self):
        self.assertEqual(l.OPS, {1: 'proxy-get', 2: 'direct-tcp', 3: 'wrong-port', 4: 'wrong-peer', 5: 'proxy-after-death', 6: 'dns-query', 7: 'dns-raw-udp', 255: 'finish'})
        cpp = (ROOT / '.github/native/windows_identity_proxy_c_contract.hpp').read_text()
        for label in l.OPS.values():
            self.assertIn('return "' + label + '"', cpp)
        proxy, _ = m.transport_payload('1' * 32, 55000, 'proxy-get')
        direct, _ = m.transport_payload('1' * 32, 55000, 'direct-tcp')
        self.assertNotEqual(len(proxy), len(direct))
        self.assertTrue(proxy.startswith(b'GET http://'))
        self.assertTrue(direct.startswith(b'GET /p1/'))

    def test_go_exact_bytes_reserved_clock_nonce_and_no_overwrite(self):
        values = dict(run='1' * 32, case='2' * 32, sequence=1, opcode=2, frequency=1000, deadline=121000,
            fixed_ports=dict(proxy=55000, wrong_port=55001, origin=55002), admission='3' * 32, phase_deadline=20000)
        raw = l.go_record(**values)
        self.assertEqual(len(raw), 128)
        self.assertEqual(raw[:6], b'RPC1\x01\x02')
        self.assertEqual(struct.unpack_from('<QQHHH', raw, 48), (1000, 121000, 55000, 55001, 55002))
        for index in range(128):
            changed = bytearray(raw)
            changed[index] ^= 1
            with self.subTest(index=index), self.assertRaises(ValueError):
                l.validate_go(bytes(changed), **values)
        clock = Clock()
        budget = l.launcher.QpcBudget(clock, 121000, 1000)
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory)
            l.publish_go(path, budget=budget, **values)
            self.assertEqual((path / 'phase-0001.bin').read_bytes(), raw)
            self.assertFalse((path / '.phase-0001.tmp').exists())
            with self.assertRaises(ValueError):
                l.publish_go(path, budget=budget, **values)

    def test_fixture_finish_is_atomic_distinct_zero_port_contract(self):
        clock = Clock()
        budget = l.launcher.QpcBudget(clock, 121000, 1000)
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory)
            digest = l.publish_fixture_finish(path, budget=budget, run='1' * 32, boot_case='2' * 32)
            raw = (path / 'finish.bin').read_bytes()
            self.assertEqual(l.sha(raw), digest)
            self.assertEqual(raw[64:72], b'\0' * 8)
            self.assertEqual(raw[32:48], raw[72:88])
            self.assertFalse((path / '.finish.tmp').exists())
            with self.assertRaises(ValueError):
                l.publish_fixture_finish(path, budget=budget, run='1' * 32, boot_case='2' * 32)

    def test_held_kernel_child_admission_has_no_claim_before_first_resume(self):
        api = GateAPI()
        owners = l.helpers.OneShotHandles(api.close)
        budget = l.launcher.QpcBudget(api, 121000, 1000)
        with mock.patch.object(l.helpers, 'verify_copied_actor'):
            result = l.admit_selected(api, owners, budget, g_process=1, g_created=100, job=7,
                image=Path('unused.exe'), image_hash='a' * 64, parent=ordinary(), capability_profile='agentic-pncs', catalog=CATALOG)
        self.assertEqual(result['pid'], 50)
        self.assertEqual(result['discovery']['first_children'], result['discovery']['second_children'])
        self.assertFalse(result['externally_held_before_first_resume'])
        self.assertTrue(result['externally_held_before_network_go'])
        self.assertIn(('exact_job', 7, 2050), api.log)
        self.assertEqual(owners.pending, {1050, 2050, 5050})

    def test_pid_reuse_child_set_change_unknown_cap_and_inaccessible_ownership_never_admit(self):
        for fault in ('pid_reused', 'new_child', 'two_children', 'child_disappeared', 'query_denied',
                      'wrong_job', 'wrong_image', 'another_user', 'unknown_cap', 'wrong_attributes', 'g_exited'):
            with self.subTest(fault=fault):
                api = GateAPI(fault)
                owners = l.helpers.OneShotHandles(api.close)
                budget = l.launcher.QpcBudget(api, 121000, 1000)
                with mock.patch.object(l.helpers, 'verify_copied_actor'), self.assertRaises((ValueError, PermissionError)):
                    l.admit_selected(api, owners, budget, g_process=1, g_created=100, job=7, image=Path('unused.exe'),
                        image_hash='a' * 64, parent=ordinary(), capability_profile='agentic-pncs', catalog=CATALOG)

    def test_failed_child_set_keeps_bounded_private_discovery_without_admission(self):
        for fault in ('new_child','two_children','child_disappeared'):
            api=GateAPI(fault);owners=l.helpers.OneShotHandles(api.close)
            budget=l.launcher.QpcBudget(api,121000,1000)
            with mock.patch.object(l.helpers,'verify_copied_actor'),self.assertRaises(ValueError) as caught:
                l.admit_selected(api,owners,budget,g_process=1,g_created=100,job=7,image=Path('unused.exe'),
                    image_hash='a'*64,parent=ordinary(),capability_profile='agentic-pncs',catalog=CATALOG)
            self.assertEqual(str(caught.exception),'selected_child_set_changed')
            evidence=caught.exception.discovery
            self.assertLessEqual(len(evidence['first_children']),16)
            self.assertLessEqual(len(evidence['second_children']),16)
            self.assertLessEqual(len(evidence['candidates']),16)
            self.assertFalse(any(row[0]=='exact_job' for row in api.log))

    def test_selected_caps_profile_is_not_accept_observed_and_config_disallows_identity_profile(self):
        entries = [{'sid': AGENTIC, 'attributes': 4}, {'sid': l.PNCS, 'attributes': 4}]
        self.assertTrue(l.capability_set(entries, 'agentic-pncs', CATALOG))
        for altered in (entries[:1], entries + [{'sid': 'S-1-15-3-999', 'attributes': 4}],
                        entries + entries[:1], [dict(entries[0], attributes=6), entries[1]]):
            with self.assertRaises(ValueError):
                l.capability_set(altered, 'agentic-pncs', CATALOG)
        value = config()
        m.validate_config(value)
        value['capability_profile'] = 'agentic-only'
        with self.assertRaises(ValueError):
            m.validate_config(value)

    def test_health_ordinary_is_explicitly_separate_from_g_selected_command(self):
        values = config()
        fixed = dict(proxy=55000, wrong_port=55001, origin=55002)
        command = l.selected_command('actor.exe', 'health-client', values['run'], values['boot_case'], 'ready',
            'reports', 'control', 1000, 1000, 121000, fixed, ordinary()['sid'], 'ordinary', values['admission_nonce'])
        self.assertEqual(command[14], 'ordinary')
        with self.assertRaises(ValueError):
            l.selected_command('actor.exe', 'selected-client', values['run'], values['boot_case'], 'ready',
                'reports', 'control', 1000, 1000, 121000, fixed, ordinary()['sid'], 'ordinary', values['admission_nonce'])

    def test_public_never_qualifies_all_c_from_first_chain_or_preflight(self):
        value = l.blank()
        for name in value['checks']:
            value['checks'][name] = name not in ('wrong_port', 'wrong_peer', 'proxy_death')
        value['observations'] = {k: True for k in value['observations']}
        l.finalize_public(value)
        self.assertEqual(value['status'], 'observed')
        self.assertTrue(value['first_chain_verified'])
        self.assertFalse(value['local_c_qualified'])
        self.assertFalse(value['product_acceptance'])
        bad = copy.deepcopy(value)
        bad['violations']['direct_connected'] = True
        with self.assertRaises(ValueError):
            l.validate_public(bad)
        l.finalize_public(bad)
        self.assertFalse(bad['direct_deny_verified'])
        value = l.blank()
        value['status'] = 'ready'
        value['checks'].update(sources=True, artifacts=True, selected_held=True)
        with self.assertRaises(ValueError):
            l.validate_public(value)

    def test_maintenance_token_cannot_be_other_account_or_uia_or_system_il(self):
        held = dict(ordinary(), elevated=True, integrity_rid=12288, elevation_type=2, admin_attributes=4)
        self.assertTrue(m.maintenance.maintenance_identity(held, ordinary()))
        for patch in ({'sid': 'S-1-5-21-9-9-9-1000'}, {'session_id': 2}, {'ui_access': True},
                      {'integrity_rid': 16384}, {'capability_count': 1}, {'appcontainer': True}):
            with self.subTest(patch=patch), self.assertRaises(ValueError):
                m.maintenance.maintenance_identity(dict(held, **patch), ordinary())

    def test_maintenance_cannot_mutate_before_admit_or_change_frozen_rule(self):
        for op in ('create', 'remove', 'read-active', 'finish'):
            with self.assertRaises(ValueError):
                m.maintenance.command('1' * 32, 'a' * 64, 1, op, None if op == 'finish' else 'RuleProxy.Model2.' + '1' * 32 + '.A-P')
        first = m.maintenance.command('1' * 32, 'a' * 64, 1, 'admit')
        m.maintenance.validate_command(first, run='1' * 32, plan_hash='a' * 64, sequence=1)
        for key, changed in (('run', '2' * 32), ('sequence', True), ('operation', 'create'), ('extra', True)):
            bad = dict(first, **{key: changed})
            with self.assertRaises(ValueError):
                m.maintenance.validate_command(bad, run='1' * 32, plan_hash='a' * 64, sequence=1)

    def test_rule_mutation_is_exact_journaled_and_cannot_remove_live_or_changed_scope(self):
        class Rules:
            row = None
            def rule_read(self, name, store): return copy.deepcopy(self.row)
            def rule_create(self, row):
                self.row = dict(row)
            def rule_remove(self, row):
                self.row = None
        api = Rules()
        clock = Clock()
        budget = l.launcher.QpcBudget(clock, 121000, 1000)
        rule = l.firewall_rule('1' * 32, 'A-P', AC, Path('actor.exe'), 55000)
        owner = l.RuleOwnership(rule)
        journal = []
        owner.create(api, budget, journal.append)
        self.assertEqual([x['state'] for x in journal], ['intent', 'present-verified'])
        with self.assertRaises(ValueError):
            owner.remove(api, budget, journal.append, all_held_exited=False, job_empty=True)
        api.row['local_port'] += 1
        with self.assertRaises(ValueError):
            owner.remove(api, budget, journal.append, all_held_exited=True, job_empty=True)
        self.assertIsNotNone(api.row)
        api.row = dict(rule)
        self.assertTrue(owner.remove(api, budget, journal.append, all_held_exited=True, job_empty=True))
        self.assertIsNone(api.row)

    def test_partial_rule_create_keeps_historical_uncertainty_after_absence(self):
        class Rules:
            row = None
            def rule_read(self, name, store): return copy.deepcopy(self.row)
            def rule_create(self, row):
                self.row = dict(row)
                raise TimeoutError('fake RPC may still commit')
            def rule_remove(self, row): self.row = None
        api = Rules()
        budget = l.launcher.QpcBudget(Clock(), 121000, 1000)
        owner = l.RuleOwnership(l.firewall_rule('1' * 32, 'A-P', AC, Path('actor.exe'), 55000))
        with self.assertRaises(TimeoutError):
            owner.create(api, budget, lambda row: None)
        self.assertTrue(owner.uncertain)
        self.assertTrue(owner.remove(api, budget, lambda row: None, all_held_exited=True, job_empty=True))
        self.assertTrue(owner.uncertain)

    def test_handle_number_reuse_is_separated_by_scope(self):
        api = Clock()
        stdio = l.helpers.OneShotHandles(api.close)
        parent_pipe = l.helpers.OneShotHandles(api.close)
        lifetime = l.helpers.OneShotHandles(api.close)
        stdio.add(7)
        stdio.close(7)
        parent_pipe.add(8)
        parent_pipe.close(8)
        lifetime.add(7)  # A different kernel object now reused this number.
        lifetime.add(8)
        combined = l.origin.CombinedLedgers(lifetime, stdio, parent_pipe)
        self.assertEqual(combined.pending, {7, 8})
        for handle in tuple(combined.pending):
            combined.close(handle)
        self.assertTrue(combined.confirmed_closed)
        self.assertEqual(api.log.count(('close', 7)), 2)
        self.assertEqual(api.log.count(('close', 8)), 2)

    def test_system_firewall_module_and_boolean_are_pinned_not_ambient(self):
        script = (ROOT / '.github/windows_identity_model2_firewall.ps1').read_text()
        self.assertIn("[Environment]::SystemDirectory", script)
        self.assertIn('WindowsPowerShell\\v1.0\\Modules\\NetSecurity\\NetSecurity.psd1', script)
        self.assertIn('NetSecurity\\New-NetFirewallRule', script)
        self.assertIn('-OverrideBlockRules $false', script)
        self.assertNotIn('Import-Module NetSecurity', script)
        self.assertIn("$RequireEffective -and $Store -ceq 'ActiveStore'", script)

    def test_execution_policy_is_only_the_bound_operation_child_argv(self):
        image, script, input_file, output_file = map(Path, ('system-powershell.exe', 'bound-script.ps1', 'plan.json', 'report.json'))
        argv = m.maintenance.operation_command(image, script, input_file, output_file)
        self.assertEqual(argv, [str(image), '-NoLogo', '-NoProfile', '-NonInteractive', '-ExecutionPolicy', 'Bypass',
            '-File', str(script), '-InputPlan', str(input_file), '-OutputReport', str(output_file)])
        self.assertNotIn('Set-ExecutionPolicy', argv)
        self.assertNotIn('-Scope', argv)

    def test_original_budget_cannot_be_renewed_by_barrier(self):
        api = Clock(119000)
        budget = l.launcher.QpcBudget(api, 121000, 1000)
        with tempfile.TemporaryDirectory() as directory, self.assertRaises(l.launcher.GateFailure):
            l.publish_go(Path(directory), budget=budget, run='1' * 32, case='2' * 32, sequence=1, opcode=2,
                frequency=1000, deadline=121000, fixed_ports=dict(proxy=55000, wrong_port=55001, origin=55002),
                admission='3' * 32, phase_deadline=120500)


if __name__ == '__main__':
    unittest.main()
