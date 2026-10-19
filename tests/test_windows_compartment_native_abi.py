"""Real Windows compartment ABI checks without creating any compartments.

Every native call runs in an isolated child so an incompatible DLL or a broken
guard cannot corrupt the unittest runner. No administrator privileges required.
"""
import ctypes
import json
import os
from pathlib import Path
import subprocess
import sys
import textwrap
import unittest


ROOT = Path(__file__).resolve().parent.parent

NATIVE_SETUP = r'''
import ctypes as C
from ctypes import wintypes as W
import importlib.util
import json
from pathlib import Path
import sys
from types import SimpleNamespace
import uuid

root = Path(sys.argv[1])
sys.path.insert(0, str(root))
from ruleproxy import windows_compartment as ns

class MemoryInformation(C.Structure):
    _fields_ = [('BaseAddress', C.c_void_p), ('AllocationBase', C.c_void_p),
                ('AllocationProtect', W.DWORD), ('PartitionId', W.WORD),
                ('RegionSize', C.c_size_t), ('State', W.DWORD),
                ('Protect', W.DWORD), ('Type', W.DWORD)]

kernel = C.WinDLL('kernel32', use_last_error=True)
kernel.VirtualQuery.argtypes = [C.c_void_p, C.POINTER(MemoryInformation), C.c_size_t]
kernel.VirtualQuery.restype = C.c_size_t
kernel.SetErrorMode.argtypes = [W.UINT]
kernel.SetErrorMode.restype = W.UINT
kernel.SetErrorMode(0x0001 | 0x0002)  # No modal system-error/crash dialogs.

def memory(address):
    info = MemoryInformation()
    size = kernel.VirtualQuery(address, C.byref(info), C.sizeof(info))
    if size != C.sizeof(info):
        raise C.WinError(C.get_last_error())
    return {'state': int(info.State), 'protect': int(info.Protect),
            'allocation_base': info.AllocationBase}
'''


@unittest.skipUnless(os.name == 'nt' and ctypes.sizeof(ctypes.c_void_p) == 8,
                     'requires real 64-bit Windows DLLs and virtual-memory protection')
class NativeCompartmentAbiTests(unittest.TestCase):
    def run_native(self, body):
        completed = subprocess.run(
            [sys.executable, '-I', '-B', '-c', NATIVE_SETUP + '\n' + textwrap.dedent(body), str(ROOT)],
            cwd=ROOT, capture_output=True, text=True, timeout=30,
        )
        self.assertEqual(completed.returncode, 0,
                         f'Native worker exit {completed.returncode}:\n{completed.stdout}\n{completed.stderr}')
        return json.loads(completed.stdout)

    def test_actual_initializer_fits_production_and_lab_guarded_rows(self):
        rows = self.run_native(r'''
            spec = importlib.util.spec_from_file_location(
                'compartment_abi_test_lab', root / '.github' / 'windows_compartment_lab.py')
            lab = importlib.util.module_from_spec(spec)
            sys.modules[spec.name] = lab
            spec.loader.exec_module(lab)
            ip = C.WinDLL('iphlpapi', use_last_error=True)
            ip.InitializeCompartmentEntry.argtypes = [C.c_void_p]
            ip.InitializeCompartmentEntry.restype = None
            results = []
            for name, row_type, allocator in (
                ('production', ns._Row, ns._guarded_row),
                ('lab', lab.MIB_COMPARTMENT_ROW, lab._guarded_compartment_row),
            ):
                with allocator() as row:
                    address = C.addressof(row)
                    size = C.sizeof(row_type)
                    observation = {'name': name, 'size': size,
                        'flags_offset': row_type.OpaqueFlags.offset,
                        'description_offset': row_type.Description.offset,
                        'row_memory': memory(address), 'after_row_memory': memory(address + size)}
                    ip.InitializeCompartmentEntry(C.byref(row))
                    observation.update(compartment_id=int(row.CompartmentId),
                        description=row.Description, opaque_flags=int(row.OpaqueFlags))
                    row.CompartmentGuid = type(row.CompartmentGuid).of(
                        uuid.UUID('67d80dbd-a93d-4f8f-8662-1cfa5cb50346'))
                    row.Description = 'ABI initialization check'
                    observation['flags_after_fields_written'] = int(row.OpaqueFlags)
                observation['released_memory'] = memory(address)
                results.append(observation)
            print(json.dumps(results))
        ''')
        self.assertEqual([row['name'] for row in rows], ['production', 'lab'])
        for row in rows:
            with self.subTest(implementation=row['name']):
                self.assertEqual((row['size'], row['flags_offset'], row['description_offset']),
                                 (540, 536, 20))
                self.assertEqual((row['compartment_id'], row['description'], row['opaque_flags']),
                                 (0, '', 0xFFFFFFFF))
                self.assertEqual(row['flags_after_fields_written'], 0xFFFFFFFF)
                self.assertEqual(row['row_memory']['state'], 0x1000)  # MEM_COMMIT
                self.assertEqual(row['row_memory']['protect'], 0x04)  # PAGE_READWRITE
                self.assertEqual(row['after_row_memory']['protect'], 0x01)  # PAGE_NOACCESS
                self.assertEqual(row['released_memory']['state'], 0x10000)  # MEM_FREE

    def test_create_error_releases_the_actual_initialized_native_allocation(self):
        result = self.run_native(r'''
            ip = C.WinDLL('iphlpapi', use_last_error=True)
            ip.InitializeCompartmentEntry.argtypes = [C.POINTER(ns._Row)]
            ip.InitializeCompartmentEntry.restype = None
            observation = {'create_called': False}
            def fail_create(pointer):
                observation['create_called'] = True
                observation['address'] = C.cast(pointer, C.c_void_p).value
                row = C.cast(pointer, C.POINTER(ns._Row)).contents
                observation['opaque_flags'] = int(row.OpaqueFlags)
                observation['description'] = row.Description
                return 5  # ERROR_ACCESS_DENIED, without making an OS compartment.
            api = ns._CompartmentAPI.__new__(ns._CompartmentAPI)
            api.i = SimpleNamespace(InitializeCompartmentEntry=ip.InitializeCompartmentEntry,
                                    CreateCompartment=fail_create)
            try:
                api.create('67d80dbd-a93d-4f8f-8662-1cfa5cb50346', 'ABI create failure test')
            except ns.ProxyError as error:
                observation['error_code'] = error.code
            observation['released_memory'] = memory(observation['address'])
            print(json.dumps(observation))
        ''')
        self.assertTrue(result['create_called'])
        self.assertEqual(result['opaque_flags'], 0xFFFFFFFF)
        self.assertEqual(result['description'], 'ABI create failure test')
        self.assertEqual(result.get('error_code'), 'namespace_failed')
        self.assertEqual(result['released_memory']['state'], 0x10000)  # MEM_FREE

    def test_initializer_overrun_is_contained_and_releases_native_allocation(self):
        result = self.run_native(r'''
            runtime = C.WinDLL('ucrtbase', use_last_error=True)
            runtime.memset.argtypes = [C.c_void_p, C.c_int, C.c_size_t]
            runtime.memset.restype = C.c_void_p
            observation = {'initializer_called': False, 'create_called': False}
            def oversized_initializer(pointer):
                observation['initializer_called'] = True
                observation['address'] = C.cast(pointer, C.c_void_p).value
                # The extra byte crosses the actual guard page. ctypes must
                # translate the native access violation into an OSError.
                runtime.memset(pointer, 0xFF, C.sizeof(ns._Row) + 1)
                observation['overflow_returned'] = True
            def must_not_create(pointer):
                observation['create_called'] = True
                raise AssertionError('Compartment creation followed an ABI overrun')
            api = ns._CompartmentAPI.__new__(ns._CompartmentAPI)
            api.i = SimpleNamespace(InitializeCompartmentEntry=oversized_initializer,
                                    CreateCompartment=must_not_create)
            try:
                api.create('67d80dbd-a93d-4f8f-8662-1cfa5cb50346', 'ABI guard test')
            except ns.ProxyError as error:
                observation['error_code'] = error.code
            observation['released_memory'] = memory(observation['address'])
            print(json.dumps(observation))
        ''')
        self.assertTrue(result['initializer_called'])
        self.assertFalse(result['create_called'])
        self.assertFalse(result.get('overflow_returned', False))
        self.assertEqual(result.get('error_code'), 'namespace_unsupported')
        self.assertEqual(result['released_memory']['state'], 0x10000)  # MEM_FREE


if __name__ == '__main__':
    unittest.main()
