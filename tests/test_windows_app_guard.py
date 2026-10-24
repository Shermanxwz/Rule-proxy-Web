"""App egress guard policy/ownership safety and broker binding checks.

These unit checks do not establish packet non-delivery on a real Windows
host. The guard deliberately remains natively unqualified.
"""
import json
from pathlib import Path
import tempfile
import unittest
from unittest import mock

from ruleproxy import windows_app_guard as app_guard
from ruleproxy import windows_global_guard as shared
from ruleproxy import windows_proxy_policy as policy
from ruleproxy import windows_proxy_service as service
from ruleproxy.windows_proxy_policy import ProxyError


def metadata(root='/protected/RuleProxy-Web'):
    return {'root': root, 'owner_sid': 'S-1-5-21-1-2-3-1001', 'files': {}}


APP_A, APP_B = b'app-id-alpha', b'app-id-beta'
PORT = 10809


def decision(rules, *, family=4, app=APP_A, flags=0, remote_port=443, remote='203.0.113.77'):
    # A policy-spec oracle for the fields in our own sublayer only. It does
    # not model Windows packet routing or arbitration with other providers.
    fields = {'app': app, 'flags': flags, 'remote_port': remote_port, 'remote': remote}
    for rule in sorted((r for r in rules if r.family == family), key=lambda r: -r.weight):
        matched = True
        for field, match, _kind, expected in rule.conditions:
            value = fields[field]
            if match == 6:
                same = value is not None and value & expected == expected
            else:
                same = value == expected
            matched = matched and same
        if matched:
            return rule.action
    return None


class AppGuardPlanTests(unittest.TestCase):
    def setUp(self):
        self.rules = app_guard._plan([APP_A, APP_B], PORT)

    def test_selected_app_may_only_reach_the_loopback_proxy_endpoint(self):
        for family in (4, 6):
            self.assertEqual(decision(self.rules, family=family, flags=1, remote_port=PORT,
                                      remote='127.0.0.1' if family == 4 else '::1'), shared._PERMIT)
            self.assertEqual(decision(self.rules, family=family, app=APP_B, flags=1,
                                      remote_port=PORT), shared._PERMIT)

    def test_everything_else_from_a_selected_app_is_blocked(self):
        cases = [
            dict(flags=0, remote_port=443, remote='203.0.113.77'),   # direct Internet
            dict(flags=0, remote_port=443, remote='192.168.1.1'),    # LAN
            dict(flags=0, remote_port=53, remote='223.5.5.5'),      # direct DNS
            dict(flags=1, remote_port=8080, remote='127.0.0.1'),    # other loopback port
            dict(flags=1, remote_port=PORT + 1, remote='127.0.0.1'), # near-miss port
            dict(flags=0, remote_port=443, remote='2001:db8::77'),  # IPv6 direct
        ]
        for family in (4, 6):
            for case in cases:
                with self.subTest(family=family, case=case):
                    self.assertEqual(decision(self.rules, family=family, **case), shared._BLOCK)

    def test_unselected_programs_match_nothing_and_keep_normal_treatment(self):
        for family in (4, 6):
            self.assertIsNone(decision(self.rules, family=family, app=b'someone-else',
                                       flags=1, remote_port=PORT))
            self.assertIsNone(decision(self.rules, family=family, app=b'someone-else',
                                       flags=0, remote_port=443))

    def test_plan_shape_and_validation(self):
        self.assertEqual(len(self.rules), 2 * 2 * 2)
        self.assertEqual(len({(rule.family, rule.name) for rule in self.rules}), len(self.rules))
        for bad in ([], [APP_A, APP_A], [b''], ['not-bytes']):
            with self.subTest(bad=bad), self.assertRaises(ValueError):
                app_guard._plan(bad, PORT)
        for bad_port in (0, 1024, 65536, '10809'):
            with self.subTest(bad_port=bad_port), self.assertRaises(ValueError):
                app_guard._plan([APP_A], bad_port)


class AppGuardOwnershipTests(unittest.TestCase):
    def test_keys_are_stable_scoped_and_distinct_from_the_global_guard(self):
        first, same = app_guard.AppGuard(metadata()), app_guard.AppGuard(metadata())
        other = app_guard.AppGuard({**metadata(), 'owner_sid': 'S-1-5-21-1-2-3-1002'})
        global_guard = shared.Guard(metadata())
        self.assertEqual(first.provider, same.provider)
        self.assertNotEqual(first.provider, other.provider)
        self.assertNotEqual(first.provider, global_guard.provider)
        self.assertNotEqual(first.sublayer, global_guard.sublayer)
        keys = {first._rule_key(family, kind + '-' + str(index))
                for family in (4, 6) for kind in ('permit', 'block') for index in range(3)}
        self.assertEqual(len(keys), 12)

    def test_invalid_metadata_is_rejected(self):
        for value in ({}, None, metadata(root=''), metadata(root='bad\0root'),
                      {**metadata(), 'owner_sid': 'bad'}):
            with self.subTest(value=value), self.assertRaises(ProxyError):
                app_guard.AppGuard(value)

    def test_consistent_readback_and_tamper_detection(self):
        guard = app_guard.AppGuard(metadata())
        rules = app_guard._plan([APP_A, APP_B], PORT)
        filters = guard._expected(rules)
        self.assertEqual(app_guard.AppGuard._consistent(filters), (2, PORT))
        for family, name in ((4, 'block-1'), (6, 'permit-0')):
            broken = dict(filters)
            del broken[(family, name)]
            with self.subTest(missing=(family, name)), self.assertRaises(ProxyError):
                app_guard.AppGuard._consistent(broken)
        tampered = dict(filters)
        action, weight_type, weight, conditions = tampered[(4, 'permit-0')]
        conditions = tuple((field, match, kind, PORT + 1 if field == shared._FIELDS['remote_port'] else data)
                           for field, match, kind, data in conditions)
        tampered[(4, 'permit-0')] = (action, weight_type, weight, conditions)
        with self.assertRaises(ProxyError):
            app_guard.AppGuard._consistent(tampered)
        self.assertEqual(app_guard.AppGuard._consistent({}), (0, None))

    def test_apply_is_system_only(self):
        guard = app_guard.AppGuard(metadata())
        with mock.patch.object(shared.os, 'name', 'nt'), \
                mock.patch('ruleproxy.windows_proxy_client.current_user_sid',
                           return_value='S-1-5-21-1-2-3-1001'):
            with self.assertRaises(ProxyError):
                guard.apply([r'C:\Apps\App.exe'], PORT)

    def test_non_windows_status_is_unavailable_and_never_qualified(self):
        guard = app_guard.AppGuard(metadata())
        with mock.patch.object(shared.os, 'name', 'posix'):
            result = guard.status()
        self.assertFalse(result['supported'])
        self.assertFalse(result['active'])
        self.assertFalse(result['strict_isolation'])
        self.assertFalse(result['native_qualified'])


class AppGuardPolicyTests(unittest.TestCase):
    def request(self, operation, **fields):
        value = {'schema_version': 1, 'request_id': 'a' * 32, 'op': operation, 'client_pid': 7}
        value.update(fields)
        return policy.decode_request(json.dumps(value).encode())

    def test_new_operations_decode_with_exact_fields(self):
        self.assertEqual(self.request('app_guard_apply', proxy_port=PORT)['op'], 'app_guard_apply')
        self.assertEqual(self.request('app_guard_revoke')['op'], 'app_guard_revoke')
        with self.assertRaises(ProxyError):
            self.request('app_guard_apply', proxy_port=80)
        with self.assertRaises(ProxyError):
            self.request('app_guard_apply', proxy_port=PORT, paths=[])
        with self.assertRaises(ProxyError):
            self.request('app_guard_revoke', proxy_port=PORT)


class FakeAppGuard:
    def __init__(self):
        self.active, self.applied, self.purges = False, [], 0

    def apply(self, paths, proxy_port):
        self.applied.append((list(paths), proxy_port))
        self.active = True
        return {'supported': True, 'active': True, 'app_count': len(paths), 'proxy_port': proxy_port}

    def purge(self):
        self.purges += 1
        self.active = False
        return {'supported': True, 'active': False, 'stopped': True}

    def status(self):
        return {'supported': True, 'active': self.active, 'state': 'active' if self.active else 'idle'}


class Control:
    def __init__(self):
        self.state = 1

    def status(self):
        return {'state': self.state, 'pid': 77 if self.state == 4 else 0}

    def verify(self, _metadata):
        pass

    def set_running(self, running):
        self.state = 4 if running else 1
        return self.status()


class Lease:
    def __init__(self, pid, _sid, root):
        self.pid, self.root, self.live = pid, root, True

    def alive(self):
        return self.live

    def close(self):
        pass

    def image_path(self):
        return str(self.root / 'bin/windows-amd64/mihomo.exe')


class AppGuardBrokerTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        (self.root / 'engine').mkdir()
        self.sid = 'S-1-5-21-1-2-3-1000'
        self.fake = FakeAppGuard()
        self.broker = service.Broker(
            {'owner_sid': self.sid, 'root': str(self.root), 'proxifyre_root': str(self.root / 'engine')},
            Control(), lambda pid, sid: Lease(pid, sid, self.root),
            app_guard_factory=lambda _metadata: self.fake)
        self.patch = mock.patch.object(service, 'verify_selected_paths')
        self.patch.start()
        self.addCleanup(self.patch.stop)

    def handle(self, operation, **fields):
        value = {'op': operation, 'client_pid': 101}
        value.update(fields)
        return self.broker.handle(value, 101, self.sid)

    def apply_paths(self):
        return self.handle('apply', paths=[r'C:\Apps\App.exe'], proxy_port=PORT,
                           mihomo_pid=102, generation=self.broker.generation + 1)

    def test_guard_binds_to_the_held_paths_and_port(self):
        with self.assertRaises(ProxyError):
            self.handle('app_guard_apply', proxy_port=PORT)
        self.apply_paths()
        with self.assertRaises(ProxyError):
            self.handle('app_guard_apply', proxy_port=PORT + 1)
        result = self.handle('app_guard_apply', proxy_port=PORT)
        self.assertTrue(result['active'])
        self.assertEqual(self.fake.applied, [([r'C:\Apps\App.exe'], PORT)])
        self.assertTrue(self.broker.app_guard_intent)
        self.assertTrue(self.broker.snapshot()['app_guard']['active'])

    def test_revoke_and_explicit_stop_remove_the_guard(self):
        self.apply_paths()
        baseline = self.fake.purges  # the apply transition already purged once
        self.handle('app_guard_apply', proxy_port=PORT)
        result = self.handle('app_guard_revoke')
        self.assertFalse(result['active'])
        self.assertFalse(self.broker.app_guard_intent)
        self.handle('app_guard_apply', proxy_port=PORT)
        self.handle('stop')
        self.assertEqual(self.fake.purges, baseline + 2)
        self.assertFalse(self.fake.active)

    def test_lease_cleanup_retains_the_guard(self):
        self.apply_paths()
        baseline = self.fake.purges
        self.handle('app_guard_apply', proxy_port=PORT)
        self.broker.stop(retain_app_guard=True)
        self.assertEqual(self.fake.purges, baseline)
        self.assertTrue(self.fake.active)
        self.assertTrue(self.broker.app_guard_intent)


if __name__ == '__main__':
    unittest.main()
