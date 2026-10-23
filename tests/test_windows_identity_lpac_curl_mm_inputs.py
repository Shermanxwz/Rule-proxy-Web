"""Portable packet tests; never instantiate a native backend."""
from pathlib import Path
import copy
import importlib.util
import struct
import unittest

SPEC = importlib.util.spec_from_file_location('cmm_inputs_tested', Path(__file__).resolve().parents[1] / '.github/windows_identity_lpac_curl_mm_inputs.py')
M = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(M)


def fixture():
    config = dict(run='01' * 16, config_sha256='02' * 32, source_sha256='03' * 32,
                  target_sha256='04' * 32, marker_sha256='05' * 32,
                  frequency=10, start_qpc=1000, root_deadline_qpc=2200)
    window = dict(start=1100, end=1180)
    generation = dict(pid=42, created=133000000000000000)
    handles = dict(zip(('process', 'thread', 'primary_token', 'inner_job', 'outer_job',
                        'entered_event', 'body_event', 'target_lease', 'marker_lease'), range(11, 20)))
    pointers = dict(zip(('target_path', 'marker_nt_path', 'marker_ascii_path', 'expected_identity', 'expected_security'),
                        (0x100000, 0x110000, 0x120000, 0x130000, 0x140000)))
    paths = dict(target='C:\\Windows\\System32\\curl.exe',
                 marker_nt='\\Device\\HarddiskVolume1\\private\\marker.dll',
                 marker_ascii='C:\\private\\marker.dll')
    target = dict(fact=dict(nt_path='\\Device\\HarddiskVolume1\\Windows\\System32\\curl.exe',
                            volume_serial=0x123456789abcdef0, file_id='06' * 16), bytes=818512,
                  pe=dict(machine=0x8664, timestamp=123, entry_rva=4096, image_bytes=827392,
                          header_bytes=1024, subsystem=3, is_dll=False))
    marker = copy.deepcopy(target)
    marker['fact'].update(nt_path=paths['marker_nt'], file_id='07' * 16)
    marker['bytes'] = 200000
    marker['pe']['is_dll'] = True
    return config, window, generation, handles, pointers, paths, target, marker, M.CMM_GUID


def primary():
    return dict(sid='S-1-5-21-1-2-3-1001', session_id=0, token_type=1,
                impersonation_level=None, appcontainer=True,
                appcontainer_sid='S-1-15-2-1-2-3-4-5-6-7', integrity_rid=4096,
                elevated=False, ui_access=False, capabilities=[],
                token_id=0xfedcba9876543210, authentication_id=0x123456789abcdef0)


class InputPackingTests(unittest.TestCase):
    def test_primary_preserves_full_ids_and_exact_sid_ranges(self):
        raw = M.identity_bytes(primary())
        self.assertEqual(len(raw), 256)
        self.assertEqual(raw[:16], struct.pack('<IIII', 256, 2, 28, 40))
        self.assertEqual(raw[16:28], bytes.fromhex('010500000000000515000000'))
        self.assertEqual(struct.unpack_from('<IIIIIIIIQQ', raw, 152),
                         (0, 1, 0xffffffff, 4096, 1, 0, 0, 0, 0xfedcba9876543210, 0x123456789abcdef0))
        self.assertEqual(raw[200:], bytes(56))

    def test_identity_and_sid_invalid_inputs_refused(self):
        for sid in ('S-1-281474976710656-1', 'S-1-5-4294967296', 'S-1-05-1', 'S-1-5-01', 'S-1-5' + '-1' * 16):
            with self.subTest(sid=sid), self.assertRaises(ValueError):
                M.sid_bytes(sid)
        for key, value in (('capabilities', ['S-1-15-3-1']), ('token_type', True),
                           ('appcontainer', 1), ('integrity_rid', 8192), ('token_id', 0)):
            value_primary = primary()
            value_primary[key] = value
            with self.subTest(key=key), self.assertRaises(ValueError):
                M.identity_bytes(value_primary)

    def test_plan_marker_cross_commitments_and_abi_offsets(self):
        args = fixture()
        plan = M.plan_bytes(*args)
        marker = M.marker_bytes(*args[:3], [101, 102])
        self.assertEqual(len(plan), 512)
        self.assertEqual(struct.unpack_from('<II5QIIQ9Q', plan),
                         (512, 2, 10, 1000, 2200, 1100, 1180, 42, 0, 133000000000000000, *range(11, 20)))
        self.assertEqual(plan[136:152], marker[8:24])
        self.assertEqual(plan[152:216], marker[24:88])
        self.assertEqual(plan[248:280], marker[88:120])
        self.assertEqual(plan[472:488].hex(), '526462b45933344b9a97dd85e4b79f2c')
        self.assertEqual(struct.unpack_from('<QQ', plan, 488), (818512, 200000))
        self.assertEqual(plan[504:], bytes(8))
        self.assertEqual(marker[:8], b'CMM2\x02\0\x40\x01')
        self.assertEqual(struct.unpack_from('<QQQII', marker, 168), (133000000000000000, 101, 102, 128, 2))
        self.assertEqual(marker[200:], bytes(120))

    def test_root_work_cutoff_wins_without_new_epoch(self):
        args = list(fixture())
        args[1] = dict(start=1800, end=1850)
        plan = M.plan_bytes(*args)
        self.assertEqual(struct.unpack_from('<5Q', plan, 8), (10, 1000, 2200, 1800, 1850))
        for window in (dict(start=1800, end=1880), dict(start=1850, end=1851), dict(start=999, end=1079)):
            with self.subTest(window=window), self.assertRaises(ValueError):
                M.marker_bytes(args[0], window, args[2], [101, 102])

    def test_sd_and_path_policy_refuses_added_access_or_aliases(self):
        sid = primary()['sid']
        sddl = 'D:P(A;;GA;;;SY)(A;;0x1fffff;;;' + sid + ')'
        raw = M.security_bytes(dict(process=sddl, thread=sddl), sid)
        self.assertEqual(len(raw), 1024)
        self.assertEqual(struct.unpack_from('<IIII', raw), (1024, 2, len(sddl), len(sddl)))
        with self.assertRaises(ValueError):
            M.security_bytes(dict(process=sddl + '(A;;GA;;;WD)', thread=sddl), sid)
        for path in ('curl.exe', '\\\\server\\curl.exe', 'C:\\..\\curl.exe', 'C:\\Windows\0\\curl.exe'):
            with self.subTest(path=path), self.assertRaises(ValueError):
                M.utf16(path, 260, dos=True)

    def test_handle_pointer_file_and_guid_binding_refused(self):
        for index, key, value in ((3, 'thread', 11), (4, 'expected_security', 0x130000),
                                  (5, 'marker_nt', '\\Device\\HarddiskVolume1\\wrong.dll')):
            args = list(fixture())
            args[index][key] = value
            with self.subTest(key=key), self.assertRaises(ValueError):
                M.plan_bytes(*args)
        args = list(fixture())
        args[8] = '00000000-0000-0000-0000-000000000001'
        with self.assertRaises(ValueError):
            M.plan_bytes(*args)
        with self.assertRaises(ValueError):
            M.file_id_bytes(dict(nt_path='\\Device\\HarddiskVolume1\\file', volume_serial=0, file_id='0' * 32))


if __name__ == '__main__':
    unittest.main()
