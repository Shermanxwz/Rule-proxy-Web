"""Pure fake clock/API/file fixtures only: no process, socket, DNS or inventory."""
import copy
import importlib.util
from pathlib import Path
import tempfile
import unittest
from unittest.mock import Mock, patch

ROOT = Path(__file__).resolve().parents[1]
spec = importlib.util.spec_from_file_location('dns_standard_owner_test', ROOT/'.github/windows_identity_dns_standard_local.py')
m = importlib.util.module_from_spec(spec); spec.loader.exec_module(m)
RUN, ACTOR_RUN, INVENTORY_RUN = '1'*32, '2'*32, '3'*32
SID, H = 'S-1-5-21-1', 'a'*64
HASHES = dict.fromkeys(m.SOURCES, m.sha(b'source'))
CLOSURE = m.sha(m.encode(HASHES))

def config():
    return dict(schema_version=1, run=RUN, actor_run=ACTOR_RUN, inventory_run=INVENTORY_RUN, frequency=10, start=100,
        root_deadline=1300, deadline=1250, source_sha256=CLOSURE, source_hashes=HASHES,
        actor_sha256=H, manifest_sha256=H, device_sha256=H, guard_job_name='Local\\RuleProxy.LocalGuard.'+RUN,
        recovery_plan_sha256=m.sha(b'plan'))

def launch(pid):
    return dict(started=True, resumed=True, timed_out=False, exit_code=0, child_pid=pid,
        native_identity_verified_before_resume=True,
        cleanup=dict(job_closed=True, job_empty=True, handles_closed=True, process_exit_confirmed=True, close_uncertain=False, errors=[]))

def raw_inventory():
    return dict(schema_version=1, stage='dns-standard-readonly-inventory', run=INVENTORY_RUN, pid=502,
        qpc_frequency=10, start_qpc=100, deadline_qpc=1250, begin_qpc=101, end_qpc=105, read_only=True,
        dns_servers=['192.0.2.53', '2001:db8::53'], effective_nrpt_count=0, udp53_count=0, tcp53_count=0)

def inventory(raw=None, now=110):
    value = raw_inventory() if raw is None else raw
    text = m.encode(value).decode('ascii'); digest = m.sha(text.encode('ascii'))
    projection = m.inventory_projection(value, run=INVENTORY_RUN, pid=502, frequency=10, start=100, deadline=1250, now=now, raw_sha256=digest)
    return dict(launch=launch(502), attempted=True, atomic=True, raw=value, raw_text=text,
        raw_sha256=digest, observed_qpc=now, projection=projection)

def native():
    return dict(schema_version=1, stage='dns-standard-native', server_constructor=m.CONSTRUCTOR, qpc_frequency=10, deadline_qpc=1100,
        identity=dict(schemaVersion=1, mode='actor', nonce=ACTOR_RUN, pid=501, tokenUserSid=SID,
            tokenIsAppContainer=False, tokenAppContainerSid=None, tokenElevated=False, isProcessInJob=True,
            tokenCapabilities=[], queriesSucceeded=True, errors=[]),
        result=dict(configured=True, called=True, completed=True, pending=False, answer_match=True, records_released=True,
            context_retained=False, within_deadline=True, api_status=0, query_status=0, record_count=1, start_qpc=115, end_qpc=120))

def fixture_result():
    return dict(ready=True, socket_closed=True, thread_stopped=True, cleanup_confirmed=True, error='none',
        counts=dict(datagrams=1, bytes=60, matched_queries=1, answers_sent=1, rejected=0, oversized=0, send_failed=0),
        query_observed=True, byte_count_is_observed_lower_bound=True, broker_cancellation_proven=False)

def report():
    c = config(); raw = m.encode(native()); text, status, digest = m.v1.native_text(raw)
    return dict(schema_version=1, stage='dns-standard-owned-worker', run=RUN, worker_pid=500, worker_sid=SID,
        **{key:c[key] for key in ('source_sha256', 'actor_sha256', 'manifest_sha256', 'frequency', 'start', 'deadline', 'root_deadline')},
        inventory=inventory(), inventory_before_bind=True, inventory_before_bind_qpc=111,
        inventory_before_query=True, inventory_before_query_qpc=112, launch=launch(501), actor_attempted=True, actor_atomic=True,
        fixture=fixture_result(), fixture_attempted=True, native=text, native_status=status, native_sha256=digest, failure=None)

class Clock:
    def __init__(self, now=111): self.now = now
    def qpc(self): return self.now
    def qpc_frequency(self): return 10

class OwnerAPI:
    atomic_job_requested = True
    def __init__(self): self.reads = 0
    def qpc_frequency(self): return 10
    def qpc(self):
        self.reads += 1
        return 100 if self.reads == 1 else 200
    def device_sha256(self): return H
    def windows_x64(self): return True
    def private_directory(self, path, sid): path.mkdir()

class Fixture:
    bind_port = 53; bind_address = '127.0.0.1'; allowed_peers = ('127.0.0.1',)
    def __init__(self, nonce, *, deadline):
        self.nonce = nonce; self.deadline = deadline; self.started = False; self.finished = False
    def start(self): self.started = True; return 53
    def finish(self, *, deadline): self.finished = True; return fixture_result()

class ActorAPI:
    atomic_job_requested = True
    def __init__(self, gate):
        self.gate = gate; self.inventory_gate_checked = False; self.inventory_gate_qpc = None
    def qpc_frequency(self): return 10

class StandardDnsTests(unittest.TestCase):
    def test_qpc_uses_signed_64_bit_ticks_after_long_host_uptime(self):
        offset = 419398842782
        c = config()
        for key in ('start', 'deadline', 'root_deadline'): c[key] += offset
        self.assertIs(m.config_valid(c), c)
        raw = raw_inventory()
        for key in ('start_qpc', 'deadline_qpc', 'begin_qpc', 'end_qpc'): raw[key] += offset
        projection = m.inventory_projection(raw, run=INVENTORY_RUN, pid=502, frequency=10,
            start=c['start'], deadline=c['deadline'], now=110+offset, raw_sha256=H)
        self.assertTrue(m.inventory_safe(projection))
        c['root_deadline'] = 0x8000000000000000
        with self.assertRaises(ValueError): m.config_valid(c)

    def owner(self, mutated=None, outer=None, api=OwnerAPI):
        rep = report() if mutated is None else mutated
        pre = m.blank('preflight'); pre.update(status='ready', source_sha256=CLOSURE, actor_sha256=H,
            manifest_sha256=H, recovery_plan_sha256=m.sha(b'plan'))
        for key in m.PRECHECKS: pre['checks'][key] = True
        files = dict.fromkeys(m.SOURCES, b'source')
        def bounded(path, limit):
            name = Path(path).name
            return m.encode(rep) if name == 'dns-standard-worker-report.json' else b'plan' if name == 'plan.json' else b'native'
        with tempfile.TemporaryDirectory() as temp:
            parent = Path(temp)
            with patch.object(m.local, 'LocalNativeAPI', api), patch.object(m.local, 'ordinary', return_value={'sid':SID}), \
                 patch.object(m, 'preflight', return_value=pre), patch.object(m, 'snapshot', return_value=(files, HASHES, CLOSURE)), \
                 patch.object(m, 'artifact'), patch.object(m.local, 'bounded', side_effect=bounded), \
                 patch.object(m.launcher, 'write_private_bytes', side_effect=lambda path, raw:path.write_bytes(raw)), \
                 patch.object(m.launcher, 'launch_owned', return_value=launch(500) if outer is None else outer), \
                 patch.object(m.secrets, 'token_hex', side_effect=[RUN, ACTOR_RUN, INVENTORY_RUN]):
                return m.run_local(parent/'actor', parent/'manifest', H, H, parent, parent/'plan.json', approved=True)

    def perform(self, inv, *, clock=None, factory=None, launcher=None):
        clock = Clock() if clock is None else clock
        with tempfile.TemporaryDirectory() as temp, patch.object(m.local, 'ordinary', return_value={'sid':SID}):
            stage = Path(temp)
            def native_launch(api, command, work, *args, **kwargs):
                self.assertEqual(len(command), 4)  # no CLI port or fallback
                api.inventory_gate_qpc = api.gate(); api.inventory_gate_checked = True
                (work/'controller.stdout').write_bytes(m.encode(native())); (work/'controller.stderr').write_bytes(b'')
                return launch(501)
            with patch.object(m.launcher, 'launch_owned', side_effect=native_launch if launcher is None else launcher):
                return m.perform_mechanism(stage, config(), {'sid':SID}, m.launcher.QpcBudget(clock, 1250, 10),
                    inventory_fn=lambda *args:inv, fixture_factory=Fixture if factory is None else factory, actor_api_factory=ActorAPI)

    def test_complete_ordinary_standard_mechanism_only(self):
        v = self.owner(); self.assertEqual(v['status'], 'passed'); self.assertTrue(v['api']['query_status_valid'])
        self.assertEqual(v['server_constructor'], 'official-v1-zero-port')
        for key in ('default_resolver_tested', 'selected_application_tested', 'dns_isolation_qualified', 'product_acceptance'):
            self.assertFalse(v[key])

    def test_inventory_blockers_never_construct_fixture_or_launch_actor(self):
        cases = [dict(dns_servers=[address]) for address in ('127.0.0.1', '127.99.1.2', '::1', '::ffff:127.0.0.1')]
        cases += [dict(effective_nrpt_count=1), dict(udp53_count=1), dict(tcp53_count=1)]
        for change in cases:
            with self.subTest(change=change):
                raw = raw_inventory(); raw.update(change); inv = inventory(raw)
                constructor = Mock(side_effect=AssertionError('no bind')); launcher = Mock(side_effect=AssertionError('no query'))
                result = self.perform(inv, factory=constructor, launcher=launcher)
                constructor.assert_not_called(); launcher.assert_not_called()
                self.assertEqual(result['failure'], 'inventory'); self.assertFalse(result['fixture_attempted'])

    def test_unknown_nonzero_timeout_inventory_never_binds(self):
        variants = []
        unknown = inventory(); unknown.update(raw=None, raw_text=None, raw_sha256=None, observed_qpc=None, projection=m.unknown_inventory())
        variants.append(unknown)
        for key, value in (('exit_code', 1), ('timed_out', True), ('native_identity_verified_before_resume', False)):
            bad = inventory(); bad['launch'][key] = value; variants.append(bad)
        bad = inventory(); bad['atomic'] = False; variants.append(bad)
        for inv in variants:
            fixture = Mock(side_effect=AssertionError('no bind')); result = self.perform(inv, factory=fixture)
            fixture.assert_not_called(); self.assertEqual(result['failure'], 'inventory')

    def test_stale_inventory_never_binds(self):
        fixture = Mock(); result = self.perform(inventory(), clock=Clock(156), factory=fixture)
        fixture.assert_not_called(); self.assertFalse(result['inventory_before_bind'])

    def test_inventory_becomes_stale_after_bind_no_query_and_fixture_closed(self):
        clock = Clock(111); made = []
        class SlowFixture(Fixture):
            def start(self):
                made.append(self); clock.now = 156; return super().start()
        launcher = Mock(side_effect=AssertionError('no query'))
        result = self.perform(inventory(), clock=clock, factory=SlowFixture, launcher=launcher)
        launcher.assert_not_called(); self.assertTrue(made[0].finished); self.assertFalse(result['actor_attempted'])

    def test_safe_inventory_fixed53_and_resume_gate(self):
        result = self.perform(inventory())
        self.assertIsNone(result['failure']); self.assertTrue(result['inventory_before_bind']); self.assertTrue(result['inventory_before_query'])
        self.assertTrue(result['actor_atomic']); self.assertTrue(result['fixture']['cleanup_confirmed'])

    def test_hostile_inventory_schema_clock_pid_and_addresses_rejected(self):
        changes = [dict(pid=999), dict(run='4'*32), dict(qpc_frequency=True), dict(deadline_qpc=1300),
            dict(begin_qpc=99), dict(end_qpc=1300), dict(dns_servers=['hostname.invalid']),
            dict(dns_servers=['0.0.0.0']), dict(dns_servers=['ff02::1']), dict(dns_servers=[' 192.0.2.1']),
            dict(effective_nrpt_count=True), dict(udp53_count=-1), dict(extra=True)]
        for change in changes:
            raw = raw_inventory(); raw.update(change)
            with self.subTest(change=change), self.assertRaises(ValueError): inventory(raw)

    def test_inventory_digest_or_projection_forgery_rejected(self):
        for key, value in (('raw_sha256', 'b'*64), ('raw_text', '{}')):
            rep = report(); rep['inventory'][key] = value
            self.assertFalse(self.owner(rep)['mechanism_passed'])
        rep = report(); rep['inventory']['projection']['udp53_count'] = 1
        self.assertFalse(self.owner(rep)['checks']['inventory_before_bind'])

    def test_no_resumed_actor_without_fresh_gate(self):
        rep = report(); rep['inventory_before_query_qpc'] = 156
        self.assertFalse(self.owner(rep)['checks']['inventory_before_query'])
        rep = report(); rep['inventory']['observed_qpc'] = 201
        self.assertFalse(self.owner(rep)['checks']['inventory_report_bound'])

    def test_sticky_wire_survives_malformed_native_and_outer_timeout(self):
        rep = report(); rep.update(native='{', native_sha256=m.sha(b'{'))
        v = self.owner(rep); self.assertTrue(v['owned_query_observed']); self.assertIsNone(v['api']); self.assertFalse(v['mechanism_passed'])
        outer = launch(500); outer['timed_out'] = True
        v = self.owner(outer=outer); self.assertTrue(v['owned_query_observed']); self.assertTrue(v['api']['answer_match']); self.assertFalse(v['mechanism_passed'])

    def test_standard_native_only_and_ordinary_capability_zero(self):
        for target, key, value in ((None, 'stage', 'dns-v1-native'), (None, 'server_constructor', 'high-port'),
                ('identity', 'pid', 999), ('identity', 'tokenCapabilities', [dict(sid='S-1-15-3-3', attributes=4)]),
                ('identity', 'tokenIsAppContainer', True)):
            n = native(); (n if target is None else n[target])[key] = value
            with self.subTest(key=key), self.assertRaises(ValueError): m.native_projection(n, ACTOR_RUN, 10, 1100, 501, SID, 112)

    def test_pending_retains_context_and_query_status_is_not_valid(self):
        n = native(); n['result'].update(completed=False, pending=True, answer_match=False, records_released=False, context_retained=True, record_count=0)
        rep = report(); rep['native'] = m.encode(n).decode('ascii'); rep['native_sha256'] = m.sha(rep['native'].encode('ascii'))
        v = self.owner(rep); self.assertFalse(v['mechanism_passed']); self.assertFalse(v['api']['query_status_valid']); self.assertTrue(v['owned_query_observed'])
        n['result']['context_retained'] = False
        with self.assertRaises(ValueError): m.native_projection(n, ACTOR_RUN, 10, 1100, 501, SID, 112)

    def test_actor_timeout_and_unknown_cleanup_cannot_pass(self):
        rep = report(); rep['launch']['timed_out'] = True; self.assertFalse(self.owner(rep)['mechanism_passed'])
        rep = report(); rep['launch'] = None
        v = self.owner(rep); self.assertTrue(v['recovery_required']); self.assertFalse(v['mechanism_passed'])

    def test_blocked_inventory_clean_exit_needs_no_recovery(self):
        rep = report(); raw = raw_inventory(); raw['udp53_count'] = 1; rep['inventory'] = inventory(raw)
        rep.update(inventory_before_bind=False, inventory_before_bind_qpc=None, inventory_before_query=False, inventory_before_query_qpc=None,
            launch=None, actor_attempted=False, actor_atomic=False, fixture=None, fixture_attempted=False,
            native=None, native_status='missing', native_sha256=None, failure='inventory')
        v = self.owner(rep); self.assertEqual(v['failure'], 'inventory'); self.assertFalse(v['recovery_required']); self.assertFalse(v['network_tested'])

    def test_original_qpc_configuration_and_unique_nonces_closed(self):
        self.assertEqual(m.config_valid(config())['deadline'], 1250)
        for change in (dict(deadline=1300), dict(root_deadline=1400), dict(actor_run=RUN), dict(extra=True)):
            c = config(); c.update(change)
            with self.subTest(change=change), self.assertRaises(ValueError): m.config_valid(c)

    def test_default_preflight_no_inventory_process_socket_or_query(self):
        plan = dict(schema_version=1, scope=m.SCOPE, device_sha256=H, actor_sha256=H, manifest_sha256=H,
            source_sha256=CLOSURE, residue_review_acknowledged=True, recovery_reference='owner review', standard53_impact_acknowledged=True)
        with tempfile.TemporaryDirectory() as temp, patch.object(m.local, 'LocalNativeAPI', OwnerAPI), \
                patch.object(m.local, 'ordinary', return_value={'sid':SID}), patch.object(m, 'snapshot', return_value=({}, HASHES, CLOSURE)), \
                patch.object(m, 'artifact'), patch.object(m.launcher, 'checked_path', side_effect=lambda path, **kwargs:Path(path)), \
                patch.object(m.local, 'bounded', return_value=m.encode(plan)), patch.object(m, 'collect_inventory') as collect, \
                patch.object(m.launcher, 'launch_owned') as launched:
            value = m.preflight(Path(temp)/'actor', Path(temp)/'manifest', H, H, temp, Path(temp)/'plan')
        self.assertEqual(value['status'], 'ready'); self.assertIsNone(value['inventory']); collect.assert_not_called(); launched.assert_not_called()

    def test_inventory_parse_failure_keeps_held_cleanup_without_binding(self):
        c = config(); helper = b'fixed readonly helper'; c['source_hashes'] = dict(HASHES); c['source_hashes'][m.INVENTORY] = m.sha(helper)
        def ps_launch(api, command, work, *args, **kwargs):
            (work/'controller.stdout').write_bytes(b'not-json'); (work/'controller.stderr').write_bytes(b'')
            return launch(502)
        with tempfile.TemporaryDirectory() as temp:
            stage = Path(temp); (stage/m.INVENTORY).parent.mkdir(); (stage/m.INVENTORY).write_bytes(helper)
            with patch.object(m.local, 'ordinary', return_value={'sid':SID}), patch.object(m, 'system_powershell', return_value=stage/'fixed-powershell.exe'), \
                    patch.object(m.launcher, 'launch_owned', side_effect=ps_launch):
                inv = m.collect_inventory(stage, c, {'sid':SID}, m.launcher.QpcBudget(Clock(), 1250, 10), api_factory=OwnerAPI)
            self.assertTrue(inv['attempted']); self.assertTrue(m.local.guest.cleanup_verified(inv['launch']))
            self.assertEqual(inv['projection'], m.unknown_inventory())
            forbidden_fixture = Mock(); self.perform(inv, factory=forbidden_fixture); forbidden_fixture.assert_not_called()

    def test_actual_resume_method_checks_inventory_before_resume(self):
        api = object.__new__(m.GatedActorAPI)
        api.inventory_gate = Mock(side_effect=ValueError('stale')); api.inventory_gate_checked = False; api.inventory_gate_qpc = None
        with patch.object(m.local.LocalNativeAPI, 'resume') as resume:
            with self.assertRaises(ValueError): api.resume(1)
            resume.assert_not_called(); self.assertFalse(api.inventory_gate_checked)
            api.inventory_gate = lambda:112
            api.resume(1); resume.assert_called_once_with(1)
            self.assertEqual(api.inventory_gate_qpc, 112)

    def test_unknown_inventory_spawn_is_recovery_required(self):
        rep = report(); rep['inventory'].update(launch=None, raw=None, raw_text=None, raw_sha256=None, observed_qpc=None, projection=m.unknown_inventory())
        rep.update(inventory_before_bind=False, inventory_before_bind_qpc=None, inventory_before_query=False, inventory_before_query_qpc=None,
            launch=None, actor_attempted=False, actor_atomic=False, fixture=None, fixture_attempted=False,
            native=None, native_status='missing', native_sha256=None, failure='inventory')
        v = self.owner(rep); self.assertTrue(v['recovery_required']); self.assertFalse(v['network_tested'])

    def test_setup_elapsed_time_does_not_renew_original_deadline(self):
        class SlowAPI(OwnerAPI):
            def qpc(self):
                self.reads += 1
                return 100 if self.reads == 1 else 600
        value = self.owner(api=SlowAPI)
        self.assertEqual(value['failure'], 'deadline'); self.assertFalse(value['tree_retained']); self.assertFalse(value['checks']['worker_held'])

    def test_preflight_cannot_claim_runtime_or_selected_scope(self):
        v = m.blank('preflight'); v['inventory'] = inventory()['projection']
        with self.assertRaises(ValueError): m.validate(v)
        v = self.owner(); v['selected_application_tested'] = True
        with self.assertRaises(ValueError): m.validate(v)

    def test_inventory_helper_is_fixed_readonly_and_no_dns_query(self):
        text = (ROOT/m.INVENTORY).read_text(encoding='utf-8')
        for command in ('Get-DnsClientServerAddress', 'Get-DnsClientNrptPolicy -Effective', 'Get-NetUDPEndpoint', 'Get-NetTCPConnection'):
            self.assertIn(command, text)
        for command in ('Set-Dns', 'Set-Net', 'New-Net', 'Resolve-DnsName', 'nslookup', 'netsh', 'Start-Process'):
            self.assertNotIn(command, text)

if __name__ == '__main__': unittest.main()
