"""Pure only: injected API, memory buffers, and clocks; no native DLL load."""
import copy
import ctypes as C
import importlib.util
from pathlib import Path
import unittest
from types import SimpleNamespace as NS
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[1]
spec = importlib.util.spec_from_file_location('lpac_accesscheck_candidate', ROOT / '.github/windows_identity_lpac_accesscheck.py')
m = importlib.util.module_from_spec(spec); spec.loader.exec_module(m)


def primary():
    return dict(sid='S-1-5-21-1-2-3-1001', session_id=1, token_type=1, impersonation_level=None,
        appcontainer=True, appcontainer_sid='S-1-15-2-11-12-13-14-15-16-17', integrity_rid=4096,
        elevated=False, ui_access=False,
        capabilities=[dict(sid='S-1-15-3-1024-1-2-3-4-5-6-7-8', attributes=4), dict(sid='S-1-15-3-3', attributes=4)],
        token_id=10, authentication_id=20)


class FakeAPI:
    def __init__(self, role='lpac', fault=None):
        self.role, self.fault, self.now = role, fault, 100
        self.closed, self.freed, self.opened, self.dups, self.checks, self.created = [], [], [], [], [], []
        self.descriptors = {}; self.identities = 0; self.generation_checks = 0

    def qpc(self):
        self.now += 1
        return self.now

    def frequency(self): return 10

    def verify_process(self, process, pid, creation):
        assert (process, pid, creation) == (55, 66, 77)
        self.generation_checks += 1
        return not (self.fault == 'generation-after' and self.generation_checks == 2)

    def open_token(self, process, rights):
        self.opened.append((process, rights))
        if self.fault == 'open-unknown': raise OSError('unknown return')
        if self.fault == 'open-error': return False, None, 5
        return True, 11, None

    def duplicate_token(self, token, rights, level, kind):
        self.dups.append((token, rights, level, kind))
        if self.fault == 'duplicate-error-returned': return False, 12, 5
        return True, 11 if self.fault == 'duplicate-alias' else 12, None

    def identity(self, token):
        self.identities += 1
        result = primary()
        if token == 12:
            result.update(token_type=2, impersonation_level=1, token_id=11)
            if self.fault == 'duplicate-privilege': result['elevated'] = True
            if self.fault == 'duplicate-level': result['impersonation_level'] = 2
            if self.fault == 'duplicate-auth': result['authentication_id'] += 1
            if self.fault == 'duplicate-cap': result['capabilities'][1]['attributes'] = 0
        elif self.fault == 'primary-mismatch': result['integrity_rid'] = 8192
        elif self.fault == 'primary-changed-after' and self.identities >= 3: result['token_id'] += 1
        return result

    def create_descriptor(self, text):
        label = next(k for k, v in m.SDDLS.items() if v == text)
        self.created.append(label)
        # Legal numeric address reuse after prior LocalFree; each allocation has its own once ledger.
        self.descriptors[30] = label
        return True, 30, None

    def describe_descriptor(self, pointer):
        label = self.descriptors[pointer]
        d = m.descriptor_expected(label) | dict(bytes=96, sha256='a' * 64)
        if self.fault == 'descriptor-owner': d['owner'] = m.WORLD
        if self.fault == 'descriptor-extra-ace': d['aces'].append(dict(type=0, flags=0, mask=0xffffffff, sid=m.WORLD))
        return d

    def access_check(self, descriptor, token, desired, mapping):
        label = self.descriptors[descriptor]
        assert token == 12 and desired == m.MAXIMUM_ALLOWED and mapping == (0, 0, 0, 0)
        self.checks.append(label)
        value = m.EXPECTED[self.role][m.LABELS.index(label)]
        if self.fault in ('api-5', 'api-87'): return False, True, 2, 0, int(self.fault[4:])
        if self.fault == 'wrong-mask': value ^= 1
        if self.fault == 'late': self.now = 1001
        return True, bool(value), value, int(self.fault == 'privilege-used'), None

    def close_token(self, value):
        self.closed.append(value)
        if self.fault == 'close-raise' and value == 12: raise OSError('unknown close')
        return not (self.fault == 'close-false' and value == 12)

    def free_descriptor(self, value):
        self.freed.append(value)
        return self.fault != 'free-false'


def observe(api):
    return m.observe_held(api, 55, primary(), expected_pid=66, expected_creation=77,
        expected_role=api.role, frequency=10, deadline=1000)


def validate(proof, role='lpac'):
    return m.validate_proof(proof, expected_primary_identity=primary(), expected_role=role,
        expected_pid=66, expected_creation=77, frequency=10, deadline=1000)


class AccessCheckCoreTests(unittest.TestCase):
    def test_exact_matched_matrix_both_roles_and_no_api_error_for_denied_controls(self):
        for role in ('ac', 'lpac'):
            with self.subTest(role=role):
                api = FakeAPI(role); p = observe(api); validate(p, role)
                self.assertTrue(p['qualified']); self.assertTrue(p['observation_complete'])
                self.assertEqual([c['granted_access'] for c in p['calls']], list(m.EXPECTED[role]))
                self.assertTrue(all(c['api_success'] for c in p['calls']))
                self.assertFalse(p['calls'][1]['access_status']); self.assertEqual(p['calls'][1]['granted_access'], 0)
                self.assertEqual(api.opened, [(55, 10)]); self.assertEqual(api.dups, [(11, 8, 1, 2)])
                self.assertEqual(api.closed, [12, 11]); self.assertEqual(api.freed, [30] * 4)
                self.assertFalse(p['network_tested']); self.assertFalse(p['token_class46_queried'])

    def test_api_failure_drops_stale_output_bytes_and_cannot_be_lpac(self):
        for error in (5, 87):
            p = observe(FakeAPI(fault='api-' + str(error))); validate(p)
            c = p['calls'][0]
            self.assertFalse(c['api_success']); self.assertEqual(c['win32_error'], error)
            self.assertIsNone(c['granted_access']); self.assertIsNone(c['access_status']); self.assertIsNone(c['privilege_count'])
            self.assertFalse(p['qualified']); self.assertEqual(p['classification'], 'unknown')
            self.assertTrue(p['resource_cleanup_verified'])
            bad = copy.deepcopy(p); bad['calls'][0]['granted_access'] = 2
            with self.assertRaises(ValueError): validate(bad)

    def test_exact_identity_level_auth_caps_and_privileges_no_observed_adaptation(self):
        for fault in ('primary-mismatch', 'duplicate-privilege', 'duplicate-level', 'duplicate-auth', 'duplicate-cap', 'primary-changed-after'):
            with self.subTest(fault=fault):
                api = FakeAPI(fault=fault); p = observe(api); validate(p)
                self.assertFalse(p['qualified']); self.assertTrue(p['resource_cleanup_verified'])
                self.assertEqual(api.closed.count(11), 1)

    def test_descriptor_readback_owner_and_extra_ace_refused_before_access(self):
        for fault in ('descriptor-owner', 'descriptor-extra-ace'):
            api = FakeAPI(fault=fault); p = observe(api); validate(p)
            self.assertFalse(p['qualified']); self.assertEqual(api.checks, []); self.assertEqual(api.freed, [30])

    def test_unknown_create_alias_and_uncertain_close_do_not_wash_clean(self):
        for fault in ('open-unknown', 'duplicate-alias', 'close-raise', 'close-false', 'free-false'):
            with self.subTest(fault=fault):
                api = FakeAPI(fault=fault); p = observe(api); validate(p)
                self.assertFalse(p['qualified']); self.assertFalse(p['resource_cleanup_verified'])
                self.assertLessEqual(api.closed.count(11), 1); self.assertLessEqual(api.closed.count(12), 1)
                if fault.startswith('close-'): self.assertEqual(api.closed, [12, 11])

    def test_partial_failed_api_returned_token_is_still_consumed_once(self):
        api = FakeAPI(fault='duplicate-error-returned'); p = observe(api); validate(p)
        self.assertFalse(p['qualified']); self.assertEqual(api.closed, [12, 11]); self.assertTrue(p['resource_cleanup_verified'])

    def test_wrong_masks_privilege_use_deadline_and_held_generation_never_qualify(self):
        for fault in ('wrong-mask', 'privilege-used', 'late', 'generation-after'):
            with self.subTest(fault=fault):
                api = FakeAPI(fault=fault); p = observe(api); validate(p)
                self.assertFalse(p['qualified']); self.assertEqual(p['classification'], 'unknown')
                self.assertTrue(p['resource_cleanup_verified'])

    def test_validator_recomputes_masks_scope_source_binding_and_cleanup(self):
        p = observe(FakeAPI())
        for change in ({'classification':'ac-semantic-match'}, {'profile':'fallback'}, {'network_tested':True},
                       {'source_identity_bound':False}, {'resource_cleanup_verified':False}, {'extra':True}):
            with self.subTest(change=change), self.assertRaises(ValueError): validate(copy.deepcopy(p) | change)
        bad = copy.deepcopy(p); bad['calls'][0].update(granted_access=3, access_status=True)
        with self.assertRaises(ValueError): validate(bad)
        bad = copy.deepcopy(p); bad['calls'][1].update(granted_access=2, access_status=False)
        with self.assertRaises(ValueError): validate(bad)
        bad = copy.deepcopy(p); bad['resources'] = bad['resources'][:2]
        with self.assertRaises(ValueError): validate(bad)
        bad = copy.deepcopy(p)
        for key in m.RESOURCE_KEYS - {'name', 'kind'}: bad['resources'][2][key] = False
        with self.assertRaises(ValueError): validate(bad)
        with self.assertRaises(ValueError): m.validate_proof(p, expected_primary_identity=primary(), expected_role='lpac',
            expected_pid=67, expected_creation=77, frequency=10, deadline=1000)

    def test_descriptor_contract_exact_builtin_only_no_object_acl_edit(self):
        self.assertEqual([len(m.descriptor_expected(k)['aces']) for k in m.LABELS], [3, 1, 2, 2])
        for k in m.LABELS:
            d = m.descriptor_expected(k)
            self.assertEqual((d['owner'], d['group'], d['control']), (m.SYSTEM, m.SYSTEM, 0x8004))
            self.assertTrue(m.SDDLS[k].startswith('O:SYG:SYD:'))


class AdapterPureTests(unittest.TestCase):
    def test_scalar_uses_one_direct_dword_call_without_a_size_probe(self):
        api = m.NativeAPI.__new__(m.NativeAPI); calls = []
        def information(token, kind, value, size, returned):
            calls.append((token, kind, value is not None, size))
            if value is None or size == 0:
                raise AssertionError('zero-length scalar probe is forbidden')
            C.cast(value, C.POINTER(C.c_uint32))[0] = 2
            C.cast(returned, C.POINTER(C.c_uint32))[0] = 4
            return 1
        api.a = NS(GetTokenInformation=information)
        self.assertEqual(api._scalar(11, 8), 2)
        self.assertEqual(calls, [(11, 8, True, 4)])

    def test_scalar_failure_never_reads_stale_output_or_retries(self):
        api = m.NativeAPI.__new__(m.NativeAPI); calls = []
        def failed(token, kind, value, size, returned):
            calls.append((token, kind, size))
            C.cast(value, C.POINTER(C.c_uint32))[0] = 1
            C.cast(returned, C.POINTER(C.c_uint32))[0] = 4
            C.set_last_error(87)
            return 0
        api.a = NS(GetTokenInformation=failed)
        with self.assertRaises(m.ApiError) as error:
            api._scalar(11, 29)
        self.assertEqual((error.exception.operation, error.exception.code), ('GetTokenInformation', 87))
        self.assertEqual(calls, [(11, 29, 4)])

    def test_scalar_requires_exact_returned_dword_width(self):
        for reported in (0, 1, 3, 5, 8):
            api = m.NativeAPI.__new__(m.NativeAPI); calls = []
            def information(token, kind, value, size, returned):
                calls.append(size)
                C.cast(value, C.POINTER(C.c_uint32))[0] = 1
                C.cast(returned, C.POINTER(C.c_uint32))[0] = reported
                return 1
            api.a = NS(GetTokenInformation=information)
            with self.subTest(reported=reported), self.assertRaisesRegex(ValueError, 'token_scalar_length'):
                api._scalar(11, 29)
            self.assertEqual(calls, [4])

    def test_capability_header_is_bounded_before_first_dereference(self):
        for reported in range(4):
            api = m.NativeAPI.__new__(m.NativeAPI)
            buf = C.create_string_buffer(max(1, reported))
            api._information = lambda token, kind: (buf, reported)
            with self.subTest(reported=reported), patch.object(m.C, 'cast', side_effect=AssertionError('unbounded first read')):
                with self.assertRaisesRegex(ValueError, 'capability_header_length'):
                    api.identity(11)

    def test_capability_count_and_full_entry_bounds_still_precede_sid_reads(self):
        for count, size in ((65, 8), (2, 8), (2, 24)):
            api = m.NativeAPI.__new__(m.NativeAPI); buf = C.create_string_buffer(size)
            C.cast(buf, C.POINTER(C.c_uint32))[0] = count
            api._information = lambda token, kind: (buf, size)
            api._sid = lambda *args: (_ for _ in ()).throw(AssertionError('SID read before entry bounds'))
            with self.subTest(count=count, size=size), self.assertRaisesRegex(ValueError, 'capability_buffer'):
                api.identity(11)

    def descriptor_api(self, label, bad_pointer=False):
        def sid(text):
            parts = [int(x) for x in text.split('-')[1:]]
            return bytes((parts[0], len(parts) - 2)) + parts[1].to_bytes(6, 'big') + b''.join(x.to_bytes(4, 'little') for x in parts[2:])
        owner = sid(m.SYSTEM); aces = []; offsets = []
        for principal, mask in m.ACES[label]:
            value = sid(principal); n = 8 + len(value)
            offsets.append(sum(map(len, aces))); aces.append(bytes((0, 0)) + n.to_bytes(2, 'little') + mask.to_bytes(4, 'little') + value)
        acl = bytes((2, 0)) + (8 + sum(map(len, aces))).to_bytes(2, 'little') + len(aces).to_bytes(2, 'little') + b'\0\0' + b''.join(aces)
        owner_at, group_at = 20, 20 + len(owner); acl_at = group_at + len(owner)
        raw = b'\1\0\4\x80' + b''.join(x.to_bytes(4, 'little') for x in (owner_at, group_at, 0, acl_at)) + owner + owner + acl
        buf = C.create_string_buffer(raw, len(raw)); base = C.addressof(buf)
        def output(pointer, kind, value): C.cast(pointer, C.POINTER(kind))[0] = value
        def control(p, c, rev): output(c, C.c_uint16, 0x8004); output(rev, C.c_uint32, 1); return 1
        def principal(offset):
            def get(p, out, default): output(out, C.c_void_p, base + offset); output(default, C.c_int, 0); return 1
            return get
        def dacl(p, present, out, default):
            output(present, C.c_int, 1); output(out, C.c_void_p, base + acl_at); output(default, C.c_int, 0); return 1
        def ace(p, index, out): output(out, C.c_void_p, base if bad_pointer else base + acl_at + 8 + offsets[index]); return 1
        api = m.NativeAPI.__new__(m.NativeAPI)
        api.a = NS(IsValidSecurityDescriptor=lambda p:1, GetSecurityDescriptorLength=lambda p:len(raw),
            GetSecurityDescriptorControl=control, GetSecurityDescriptorOwner=principal(owner_at), GetSecurityDescriptorGroup=principal(group_at),
            GetSecurityDescriptorDacl=dacl, GetAce=ace, IsValidSid=lambda p:1,
            GetLengthSid=lambda p:8 + C.string_at(p, 2)[1] * 4)
        return api, buf

    def test_native_descriptor_reader_four_fixed_byte_layouts_with_fake_sdk(self):
        for label in m.LABELS:
            with self.subTest(label=label):
                api, buf = self.descriptor_api(label)
                observed = api.describe_descriptor(C.addressof(buf))
                self.assertEqual({k:v for k,v in observed.items() if k not in ('bytes','sha256')}, m.descriptor_expected(label))
                self.assertEqual(observed['bytes'], len(buf)); self.assertEqual(observed['sha256'], m.sha(buf.raw))

    def test_native_descriptor_reader_rejects_out_of_acl_ace_before_dereference(self):
        api, buf = self.descriptor_api('combined', bad_pointer=True)
        with self.assertRaisesRegex(ValueError, 'ace_bounds'): api.describe_descriptor(C.addressof(buf))

    def test_native_access_failure_outputs_are_null_even_if_api_wrote_stale_success(self):
        api = m.NativeAPI.__new__(m.NativeAPI)
        def failed(sd, token, desired, generic, privileges, n, granted, status):
            C.cast(granted, C.POINTER(C.c_uint32))[0] = 2
            C.cast(status, C.POINTER(C.c_int))[0] = 1
            C.set_last_error(87); return 0
        api.a = NS(AccessCheck=failed)
        self.assertEqual(api.access_check(10, 20, m.MAXIMUM_ALLOWED, (0, 0, 0, 0)), (False, None, None, None, 87))

    def test_native_negative_is_api_success_not_win32_failure(self):
        api = m.NativeAPI.__new__(m.NativeAPI)
        def denied(sd, token, desired, generic, privileges, n, granted, status):
            C.cast(granted, C.POINTER(C.c_uint32))[0] = 0
            C.cast(status, C.POINTER(C.c_int))[0] = 0
            C.cast(n, C.POINTER(C.c_uint32))[0] = 8
            C.cast(privileges, C.POINTER(C.c_uint32))[0] = 0
            C.set_last_error(5); return 1
        api.a = NS(AccessCheck=denied)
        self.assertEqual(api.access_check(10, 20, m.MAXIMUM_ALLOWED, (0, 0, 0, 0)), (True, False, 0, 0, None))

    def test_native_api_has_no_launch_impersonate_class46_or_network_entry(self):
        self.assertFalse(hasattr(m.NativeAPI, 'spawn')); self.assertFalse(hasattr(m.NativeAPI, 'impersonate'))
        self.assertFalse(hasattr(m.NativeAPI, 'lpac_flag')); self.assertFalse(hasattr(m, 'main'))


if __name__ == '__main__': unittest.main()
