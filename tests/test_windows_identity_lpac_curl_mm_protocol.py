"""Inert ctypes-buffer/export fakes; no DLL or Windows API is loaded."""
from pathlib import Path
import ctypes as C
import importlib.util
import struct
import unittest


def load(name, path):
    spec = importlib.util.spec_from_file_location(name, path)
    value = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(value)
    return value


ROOT = Path(__file__).resolve().parents[1]
P = load('cmm_protocol_under_test', ROOT / '.github/windows_identity_lpac_curl_mm_protocol.py')
F = load('cmm_protocol_fixture', ROOT / 'tests/test_windows_identity_lpac_curl_mm_inputs.py')


def buffers():
    config, window, generation, handles, pointers, paths, target, marker_file, guid = F.fixture()
    del pointers, guid
    sid = F.primary()['sid']
    sd = 'D:P(A;;GA;;;SY)(A;;0x1fffff;;;' + sid + ')'
    value = P.NativeBuffers(config=config, window=window, generation=generation,
                            handles=handles, paths=paths, target=target, marker_file=marker_file,
                            primary=F.primary(), security=dict(process=sd, thread=sd), signals=[101, 102])
    return value, config


class Function:
    def __init__(self, name, calls):
        self.name, self.calls = name, calls
        self.raise_after = False

    def __call__(self, *args):
        self.calls.append((self.name, tuple(C.cast(arg, C.c_void_p).value for arg in args)))
        if self.name == 'cmm_abi_version':
            return 2
        op, code = {'cmm_begin_v2': (1, 9), 'cmm_update_v2': (2, 11),
                    'cmm_install_marker_v2': (3, 5), 'cmm_observe_v2': (4, 7),
                    'cmm_forget_exited_v2': (5, 10)}[self.name]
        address = C.cast(args[-1], C.c_void_p).value
        C.memmove(address, struct.pack('<IIII', 256, 2, op, code), 16)
        if self.name == 'cmm_observe_v2':
            C.memmove(address + 12416, b'PHYSICAL', 8)
        if self.raise_after:
            raise RuntimeError('fake returned-output then exception')
        return code


class Library:
    def __init__(self):
        self.calls = []
        for name in ('cmm_abi_version', *(value[0] for value in P.EXPORTS.values())):
            setattr(self, name, Function(name, self.calls))


class ProtocolBufferTests(unittest.TestCase):
    def test_preallocation_alignment_exact_pointers_and_binding(self):
        value, _ = buffers()
        self.assertEqual((C.sizeof(value.ctx), C.sizeof(value.plan), C.sizeof(value.marker), C.sizeof(value.output)),
                         (8192, 512, 320, 24576))
        self.assertTrue(all(C.addressof(item) % 8 == 0 for item in
                            (value.ctx, value.plan, value.marker, value.output, *value._buffers.values())))
        raw = value.expectation()['plan512']
        for offset, name in ((280, 'target_path'), (296, 'marker_nt_path'), (312, 'marker_ascii_path'),
                             (328, 'expected_identity'), (344, 'expected_security')):
            self.assertEqual(struct.unpack_from('<Q', raw, offset)[0], C.addressof(value._buffers[name]))
        library = Library()
        P.bind_library(library)
        self.assertEqual([name for name, _ in library.calls], ['cmm_abi_version'])
        self.assertEqual(len(library.cmm_begin_v2.argtypes), 3)

    def test_all_five_calls_use_preallocated_storage_and_return_physical_bytes(self):
        value, _ = buffers()
        library = Library()
        pointers = C.addressof(value.ctx), C.addressof(value.output)
        for operation, expected_code in (('begin', 9), ('update', 11), ('install', 5), ('observe', 7), ('forget', 10)):
            code, raw, output = value.call(library, operation)
            self.assertEqual((code, len(raw), struct.unpack_from('<I', raw, 12)[0]), (expected_code, 256, expected_code))
            if operation == 'observe':
                self.assertEqual(library.calls[-1][1], pointers)
                self.assertEqual(len(output), 24576)
                self.assertEqual(output[12416:12424], b'PHYSICAL')
                self.assertEqual(raw, output[:256])
            else:
                self.assertIsNone(output)
        self.assertTrue(value.inputs_unchanged())
        with self.assertRaises(ValueError):
            value.call(library, 'observe')
        self.assertEqual(len(library.calls), 5)

    def test_expectations_do_not_refresh_from_mutated_inputs(self):
        value, config = buffers()
        original = value.expectation()
        original['commitments']['run'] = b'x' * 16
        config['run'] = 'ff' * 16
        self.assertEqual(value.expectation()['commitments']['run'], bytes.fromhex('01' * 16))
        initial = value.input_files()
        value.plan.storage[136] ^= 1
        self.assertFalse(value.inputs_unchanged())
        self.assertEqual(value.expectation()['plan512'], initial['native-plan.bin'])
        self.assertEqual(value.input_files()['native-marker.bin'][8:24], bytes.fromhex('01' * 16))

    def test_entered_export_cannot_retry_after_unknown_return(self):
        value, _ = buffers()
        library = Library()
        library.cmm_update_v2.raise_after = True
        with self.assertRaises(RuntimeError):
            value.call(library, 'update')
        with self.assertRaises(ValueError):
            value.call(library, 'update')
        self.assertEqual(len(library.calls), 1)
        self.assertEqual(struct.unpack_from('<I', P.logical_bytes(value._results['update']), 12)[0], 11)


if __name__ == '__main__':
    unittest.main()
