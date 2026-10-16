"""Guard policy/ownership safety; read-only native API capability verification.

These unit checks do not establish packet non-delivery, crash isolation, RDP
continuity or reboot protection. The candidate deliberately remains unqualified.
"""
from contextlib import contextmanager
import ctypes
import ipaddress
import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
from types import SimpleNamespace
import unittest
from unittest.mock import Mock, patch

from ruleproxy import windows_global_guard as guard
from ruleproxy.windows_proxy_policy import ProxyError


def metadata(root='/protected/RuleProxy-Web'):
    return {'root': root, 'owner_sid': 'S-1-5-21-1-2-3-1001', 'files': {}}


APP, SYSTEM, MAINTENANCE = b'fixed-core-app-id', b'system-descriptor', b'os-service-descriptor'


def decision(rules, *, family=4, app=b'other', user=b'user', next_interface=44,
             arrival=None, flags=0, protocol=6, local_port=50000, remote_port=443,
             remote='203.0.113.77'):
    # A policy-spec oracle for the fields in our own sublayer only. It does not
    # model Windows packet routing or arbitration with other WFP providers.
    fields = {'app': app, 'user': user, 'next': next_interface, 'arrival': arrival,
              'flags': flags, 'protocol': protocol, 'local_port': local_port,
              'remote_port': remote_port, 'remote': remote}
    for rule in sorted((r for r in rules if r.family == family), key=lambda r: -r.weight):
        matched = True
        for field, match, kind, expected in rule.conditions:
            value = fields[field]
            if field == 'user':
                same = ((expected == SYSTEM and value == SYSTEM)
                        or (expected == MAINTENANCE and value in (SYSTEM, MAINTENANCE)))
            elif field == 'remote':
                address = ipaddress.ip_address(value)
                if kind == 257:
                    raw, prefix = expected
                    same = address in ipaddress.ip_network((ipaddress.IPv6Address(raw), prefix))
                elif kind == 11:
                    same = address.packed == expected
                else:
                    same = int(address) == expected
            elif match == 6:
                same = value is not None and value & expected == expected
            else:
                same = value == expected
            matched = matched and same
        if matched:
            return rule.action
    raise AssertionError('No catch-all policy decision')


class GuardPolicyTests(unittest.TestCase):
    def setUp(self):
        self.rules = guard._plan(APP, SYSTEM, 9001, MAINTENANCE)

    def test_unknown_direct_tcp_udp_ipv4_ipv6_and_physical_dns_are_blocked_by_policy(self):
        for family, remote in ((4, '203.0.113.77'), (6, '2001:db8::77')):
            for app in (b'other', None):
                for protocol, remote_port in ((6, 443), (17, 443), (17, 53), (6, 53)):
                    with self.subTest(family=family, app=app, protocol=protocol, remote_port=remote_port):
                        self.assertEqual(decision(self.rules, family=family, remote=remote,
                            app=app, protocol=protocol, remote_port=remote_port), guard._BLOCK)

    def test_fixed_executable_requires_system_token_and_loopback_is_preserved(self):
        self.assertEqual(decision(self.rules, app=APP, user=SYSTEM), guard._PERMIT)
        self.assertEqual(decision(self.rules, app=APP, user=b'ordinary-user'), guard._BLOCK)
        self.assertEqual(decision(self.rules, flags=1), guard._PERMIT)

    def test_verified_tun_direction_and_empty_next_hop_reauthorization_are_explicit(self):
        self.assertEqual(decision(self.rules, next_interface=9001), guard._PERMIT)
        self.assertEqual(decision(self.rules, next_interface=9002), guard._BLOCK)
        self.assertEqual(decision(self.rules, next_interface=None, arrival=9001), guard._PERMIT)
        self.assertEqual(decision(self.rules, next_interface=None, arrival=44), guard._BLOCK)
        self.assertEqual(decision(self.rules, next_interface=None, arrival=None), guard._BLOCK)
        self.assertEqual(decision(self.rules, next_interface=44, arrival=9001), guard._BLOCK)

    def test_first_start_has_no_tun_exemption_and_no_inbound_filter_layer(self):
        before_tun = guard._plan(APP, SYSTEM, None, MAINTENANCE)
        self.assertFalse(any(rule.name.startswith('tun-') for rule in before_tun))
        self.assertEqual(decision(before_tun, next_interface=9001), guard._BLOCK)
        self.assertEqual(decision(before_tun, app=APP, user=SYSTEM), guard._PERMIT)
        self.assertEqual(set(guard._LAYERS), {4, 6})
        self.assertEqual(guard._LAYERS[4], 'c38d57d1-05a7-4c33-904f-7fbceee60e82')
        self.assertEqual(guard._LAYERS[6], '4a72393b-319f-44bc-84c3-ba54dcb3b6b4')

    def test_link_maintenance_does_not_allow_unprivileged_dhcp_or_global_ndp_payloads(self):
        self.assertEqual(decision(self.rules, user=MAINTENANCE, protocol=17,
            local_port=68, remote_port=67), guard._PERMIT)
        self.assertEqual(decision(self.rules, protocol=17, local_port=68, remote_port=67), guard._BLOCK)
        for remote in ('ff02::1:ff00:12', 'fe80::1'):
            self.assertEqual(decision(self.rules, family=6, protocol=58, local_port=135,
                remote_port=0, remote=remote), guard._PERMIT)
        self.assertEqual(decision(self.rules, family=6, protocol=58, local_port=135,
            remote_port=0, remote='2001:db8::77'), guard._BLOCK)
        self.assertEqual(decision(self.rules, family=6, protocol=58, local_port=128,
            remote_port=0, remote='fe80::1'), guard._BLOCK)

    def test_no_management_address_lan_folder_or_process_name_exemption(self):
        for remote in ('192.168.1.1', '10.0.0.1', '169.254.1.2'):
            self.assertEqual(decision(self.rules, remote=remote), guard._BLOCK)
        self.assertFalse(any(rule.name.startswith('management') for rule in self.rules))
        self.assertEqual(len({(rule.family, rule.name) for rule in self.rules}), len(self.rules))
        self.assertEqual(set(guard._ALL_RULES), {(rule.family, rule.name) for rule in self.rules})

    def test_real_value_layouts_roundtrip_and_malformed_pointer_values_are_rejected(self):
        self.assertEqual(ctypes.sizeof(guard._GUID), 16)
        if ctypes.sizeof(ctypes.c_void_p) == 8:
            expected = [(guard._Value, 16), (guard._Session, 72), (guard._Provider, 64),
                        (guard._Sublayer, 72), (guard._Condition, 40), (guard._Filter, 200), (guard._Layer, 72)]
            for structure, size in expected:
                self.assertEqual(ctypes.sizeof(structure), size)
        for rule in self.rules:
            for _field, _match, kind, data in rule.conditions:
                retained = []
                value = guard._value(kind, data, retained)
                self.assertEqual(guard._data(value), data)
        for kind in (4, 11, 12, 14, 257):
            with self.subTest(kind=kind), self.assertRaises(ProxyError):
                guard._data(guard._Value(kind))


class GuardOwnershipAndLifecycleTests(unittest.TestCase):
    def test_apply_is_system_only_but_restore_checks_real_administrator_authority(self):
        with patch.object(guard.os, 'name', 'nt'), \
                patch('ruleproxy.windows_proxy_client.current_user_sid', return_value='S-1-5-21-1-2-3-1001'):
            with self.assertRaises(ProxyError):
                guard.Guard._system_only()
            with patch('ruleproxy.windows_app_process._KernelAPI') as api:
                api.return_value.is_elevated.return_value = False
                with self.assertRaisesRegex(ProxyError, '已提升权限'):
                    guard.Guard._restore_authority()
                api.return_value.is_elevated.assert_called_once()
        with patch.object(guard.os, 'name', 'nt'), \
                patch('ruleproxy.windows_proxy_client.current_user_sid', return_value='S-1-5-18'), \
                patch('ruleproxy.windows_app_process._KernelAPI') as api:
            guard.Guard._system_only()
            guard.Guard._restore_authority()
        api.assert_not_called()

    def test_elevated_restore_requires_enabled_admin_membership_and_frees_sid(self):
        for member in (False, True):
            def convert(text, output):
                self.assertEqual(text, 'S-1-5-32-544')
                ctypes.cast(output, ctypes.POINTER(ctypes.c_void_p)).contents.value = 1234
                return 1
            def membership(token, sid, output):
                self.assertIsNone(token)
                ctypes.cast(output, ctypes.POINTER(ctypes.c_int)).contents.value = int(member)
                return 1
            advapi = SimpleNamespace(ConvertStringSidToSidW=Mock(side_effect=convert),
                                    CheckTokenMembership=Mock(side_effect=membership))
            kernel = SimpleNamespace(LocalFree=Mock())
            def load(name, **_options):
                return advapi if name == 'advapi32.dll' else kernel
            with self.subTest(member=member), patch.object(guard.os, 'name', 'nt'), \
                    patch('ruleproxy.windows_proxy_client.current_user_sid', return_value='S-1-5-21-1-2-3-1002'), \
                    patch('ruleproxy.windows_app_process._KernelAPI') as api, \
                    patch.object(guard.C, 'WinDLL', side_effect=load, create=True):
                api.return_value.is_elevated.return_value = True
                if member:
                    guard.Guard._restore_authority()
                else:
                    with self.assertRaisesRegex(ProxyError, '有效的管理员组权限'):
                        guard.Guard._restore_authority()
            kernel.LocalFree.assert_called_once()
            advapi.CheckTokenMembership.assert_called_once()

    def test_invalid_metadata_and_arbitrary_core_path_are_rejected_before_network_api(self):
        for value in ({}, None, metadata(root=''), metadata(root='bad\0root'), {**metadata(), 'owner_sid': 'bad'}):
            with self.subTest(value=value), self.assertRaises(ProxyError):
                guard.Guard(value)
        value = guard.Guard(metadata())
        with patch.object(guard, '_Engine') as engine, self.assertRaises(ProxyError):
            value._fixed_core(Path('/arbitrary/mihomo.exe'))
        engine.assert_not_called()

    def test_persistent_object_keys_are_stable_and_scoped_to_installation(self):
        first, same = guard.Guard(metadata()), guard.Guard(metadata())
        other = guard.Guard({**metadata(), 'owner_sid': 'S-1-5-21-1-2-3-1002'})
        self.assertEqual(first.provider, same.provider)
        self.assertNotEqual(first.provider, other.provider)
        self.assertNotEqual(first.provider, first.sublayer)
        self.assertEqual(len({first._rule_key(family, name) for family, name in guard._ALL_RULES}), 20)

    def test_invalid_tun_rejects_before_fixed_core_or_native_mutation(self):
        value = guard.Guard(metadata())
        for tun in ({}, {'enable': True, 'device': 'someone-else', 'auto-route': True},
                    {'enable': True, 'device': 'RuleProxyTun', 'auto-route': False}):
            with self.subTest(tun=tun), patch.object(value, '_system_only'), \
                    patch.object(value, '_fixed_core') as core, patch.object(guard, '_Engine') as engine, \
                    self.assertRaises(ProxyError):
                value.apply(Path('/protected/RuleProxy-Web/bin/windows-amd64/mihomo.exe'), tun)
            core.assert_not_called()
            engine.assert_not_called()

    def test_crash_retains_guard_and_never_calls_delete_or_normal_stop(self):
        value = guard.Guard(metadata())
        with patch.object(value, 'status', return_value={'active': True, 'strict_isolation': False}), \
                patch.object(value, 'normal_stop') as stop, patch.object(guard, '_Engine') as engine:
            self.assertEqual(value.crash_keep(), {'active': True, 'strict_isolation': False,
                                                  'retained_after_failure': True})
        stop.assert_not_called()
        engine.assert_not_called()

    def test_failed_transaction_aborts_before_exception_escapes(self):
        engine = object.__new__(guard._Engine)
        engine.handle = ctypes.c_void_p(42)
        engine.api = SimpleNamespace(FwpmTransactionBegin0=Mock(return_value=0),
            FwpmTransactionCommit0=Mock(return_value=0), FwpmTransactionAbort0=Mock(return_value=0))
        with self.assertRaisesRegex(RuntimeError, 'incomplete policy'):
            with engine.transaction():
                raise RuntimeError('incomplete policy')
        engine.api.FwpmTransactionCommit0.assert_not_called()
        engine.api.FwpmTransactionAbort0.assert_called_once()
        engine.api.FwpmTransactionAbort0.reset_mock()
        engine.api.FwpmTransactionCommit0.return_value = 5
        with self.assertRaises(ProxyError):
            with engine.transaction():
                pass
        engine.api.FwpmTransactionAbort0.assert_called_once()

    def test_conflicting_owned_object_is_never_deleted(self):
        value = guard.Guard(metadata())
        @contextmanager
        def get(_kind, _key, _structure):
            wrong = guard._Provider()
            wrong.flags, wrong.service = 1, guard.SERVICE_NAME
            wrong.display = guard._Display('foreign', 'not our marker')
            yield wrong
        engine = SimpleNamespace(get=get)
        with self.assertRaisesRegex(ProxyError, '身份冲突'):
            value._owned_provider(engine)

    def test_non_windows_reports_unavailable_and_never_claims_native_qualification(self):
        value = guard.Guard(metadata())
        with patch.object(guard.os, 'name', 'posix'):
            result = value.status()
        self.assertFalse(result['supported'])
        self.assertFalse(result['strict_isolation'])
        self.assertFalse(result['native_qualified'])


@unittest.skipUnless(os.name == 'nt' and ctypes.sizeof(ctypes.c_void_p) == 8,
                     'Read-only Windows WFP capability and AppId API checks')
class NativeGuardReadOnlyTests(unittest.TestCase):
    def test_actual_layer_schema_and_owned_executable_app_id_without_changing_network(self):
        import sys
        with guard._Engine() as engine:
            engine.capability()
            application = engine.app_id(Path(sys.executable))
        self.assertGreater(len(application), 2)
        descriptor = guard._system_descriptor()
        self.assertTrue(descriptor)
        self.assertTrue(guard._maintenance_descriptor())
        from ruleproxy.windows_app_process import _KernelAPI
        if _KernelAPI().is_elevated():
            guard.Guard._restore_authority()
        print('::notice::Global guard native read-only API capability passed; '
              'no filter installed; packet non-delivery and crash isolation remain unqualified.')


@unittest.skipUnless(os.name == 'nt'
    and os.environ.get('RULEPROXY_GLOBAL_GUARD_NATIVE_ACK') == 'isolated-windows-guest'
    and os.environ.get('RULEPROXY_GLOBAL_GUARD_NATIVE_ROOT'),
    'Opt-in isolated Windows guest only; never run on a user desktop or ordinary CI worker')
class NativeGuardPersistentObjectExperiment(unittest.TestCase):
    def test_real_persistent_filters_survive_installer_process_exit_and_restore_owned_state(self):
        # This experiment briefly installs an outbound default block. It is
        # intentionally excluded from normal CI and requires an already installed
        # candidate package and LocalSystem execution inside an expendable guest.
        # It checks actual BFE object lifetime/readback, not packet non-delivery.
        from ruleproxy.windows_proxy_client import current_user_sid
        from ruleproxy.windows_proxy_service import load_deployment
        if current_user_sid() != 'S-1-5-18':
            self.fail('The isolated native experiment must run as LocalSystem')
        root = Path(os.environ['RULEPROXY_GLOBAL_GUARD_NATIVE_ROOT'])
        installed = load_deployment(root)
        candidate = guard.Guard(installed)
        initial = candidate.status()
        self.assertTrue(initial['supported'])
        self.assertFalse(initial['active'], 'Do not disturb an already active guard')
        self.assertIsNone(guard._tun_luid(), 'Start with no existing TUN adapter')
        code = (
            'import json,sys;from pathlib import Path;'
            'root=Path(sys.argv[1]);sys.path.insert(0,str(root));'
            'from ruleproxy.windows_proxy_service import load_deployment;'
            'from ruleproxy.windows_global_guard import Guard;'
            'g=Guard(load_deployment(root));'
            'r=g.apply(root/"bin/windows-amd64/mihomo.exe",'
            '{"enable":True,"device":"RuleProxyTun","auto-route":True});'
            'print(json.dumps({k:r[k] for k in ("active","persistent","tun_ready","native_qualified")}))'
        )
        try:
            child = subprocess.run([str(root / 'python/python.exe'), '-I', '-S', '-c', code, str(root)],
                stdin=subprocess.DEVNULL, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                timeout=30, creationflags=getattr(subprocess, 'CREATE_NO_WINDOW', 0), check=False)
            self.assertEqual(child.returncode, 0, child.stderr.decode('utf-8', errors='replace')[-1000:])
            created = json.loads(child.stdout.decode('utf-8'))
            self.assertTrue(created['active'])
            self.assertTrue(created['persistent'])
            self.assertFalse(created['tun_ready'])
            self.assertFalse(created['native_qualified'])
            # The installing process has terminated and its WFP engine session
            # has closed. Only genuinely persistent BFE objects can remain.
            after_exit = candidate.crash_keep()
            self.assertTrue(after_exit['active'])
            self.assertTrue(after_exit['persistent'])
            self.assertTrue(after_exit['retained_after_failure'])
            self.assertFalse(after_exit['strict_isolation'])
            self.assertFalse(after_exit['native_qualified'])
        finally:
            restored = candidate.normal_stop()
            self.assertTrue(restored['stopped'])
            self.assertFalse(restored['active'])
        print('::notice::Opt-in candidate persistent WFP object lifetime passed; '
              'packet, RDP, TUN, competing-provider and reboot qualification remains incomplete.')


class ReadbackFlagCompatibilityTests(unittest.TestCase):
    def readback(self, flags, *, marker_matches=True):
        owned = guard.Guard(metadata())
        value = guard._Filter()
        provider = guard._GUID.of(owned.provider)
        value.key = guard._GUID.of(owned._rule_key(6, 'block'))
        value.display = guard._Display('guard', owned.marker if marker_matches else 'foreign')
        value.provider = ctypes.pointer(provider)
        value.layer = guard._GUID.of(guard._LAYERS[6])
        value.sublayer = guard._GUID.of(owned.sublayer)
        value.flags, value.count, value.action.type = flags, 0, guard._BLOCK
        value.weight.type, value.weight.value.u8 = 1, 0
        @contextmanager
        def get(kind, identity, structure):
            yield value if str(identity) == value.key.text() else None
        return owned._filters(SimpleNamespace(get=get))

    def test_bfe_indexed_annotation_preserves_exact_persistent_policy(self):
        expected = {(6, 'block'): (guard._BLOCK, 1, 0, ())}
        for flags in (guard._PERSISTENT, guard._PERSISTENT | guard._INDEXED):
            with self.subTest(flags=flags):
                self.assertEqual(self.readback(flags), expected)

    def test_disabled_clear_action_right_missing_persistence_and_unknown_bits_rejected(self):
        for flags in (0, 0x40, 0x21, 0x61, 0x09, 0x49, 0x81, 0x101, 0x80000001):
            with self.subTest(flags=flags), self.assertRaises(ProxyError) as caught:
                self.readback(flags)
            self.assertEqual(caught.exception.code, 'global_guard_conflict')

    def test_indexed_never_excuses_marker_identity_mismatch(self):
        with self.assertRaises(ProxyError) as caught:
            self.readback(0x41, marker_matches=False)
        self.assertEqual(caught.exception.code, 'global_guard_conflict')


if __name__ == '__main__':
    unittest.main()
