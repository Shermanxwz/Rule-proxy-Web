"""Child capture gate regression tests; mocked QEMU is not native evidence."""
import hashlib
import importlib.util
import os
from pathlib import Path
import struct
import tempfile
from types import SimpleNamespace
import unittest
from unittest import mock

ROOT = Path(__file__).resolve().parents[1]
SPEC = importlib.util.spec_from_file_location('child_capture_gate', ROOT / '.github/test_windows_n0a_capture_child_qemu.py')
gate = importlib.util.module_from_spec(SPEC); SPEC.loader.exec_module(gate)
original = gate.private_gate()
HEADER = struct.pack('<IHHIIII', 0xa1b2c3d4, 2, 4, 0, 0, 262144, 1)
RECORD = struct.pack('<IIII', 1, 0, len(original.FRAME), len(original.FRAME)) + original.FRAME


class FakeControl:
    def connect(self, *args): pass
    def execute(self, name):
        if name == 'query-version': return {'qemu': {'major': 8, 'minor': 2, 'micro': 2}}
        return {'running': False, 'status': 'prelaunch'}
    def close(self): pass


class ChildGateTests(unittest.TestCase):
    def simulate(self, kind, *, missing_error=False, cleanup=True, forced_complete=False):
        class Owner:
            def __init__(self, root, **kwargs):
                self.fifo_path = root / 'capture.fifo'; self.output_path = root / 'capture.pcap'
                self.process = SimpleNamespace(pid=123, poll=lambda: None)
                self.fixture = False; self.closed_reader = False; self.network_fd = None
            @classmethod
            def for_test(cls, root, **kwargs):
                value = cls(root); value.fixture = True; return value
            def start(self): pass
            def spawn(self, *args, **kwargs):
                self.network_fd = os.dup(kwargs['pass_fds'][0])
                self.output_path.write_bytes(HEADER if kind == 'dump_error' else (HEADER + RECORD)[:64] if kind == 'overflow' else HEADER + RECORD)
            def wait_header(self, *args): return True
            def fixture_close_reader(self, *args): self.closed_reader = True; return True
            def wait(self, predicate, deadline):
                status = {'qemu_dump_write_error': self.closed_reader and not missing_error,
                          'drained': len(HEADER + RECORD), 'overflow': kind == 'overflow'}
                return predicate(status)
            def finish(self, **kwargs):
                if self.network_fd is not None:
                    os.close(self.network_fd); self.network_fd = None
                return {'cleanup_confirmed': cleanup, 'drain_complete': kind == 'normal' or forced_complete,
                        'qemu_forced': kind == 'forced', 'child_forced': False,
                        'capture': {'header': True, 'qemu_dump_write_error': self.closed_reader and not missing_error,
                                    'overflow': kind == 'overflow', 'retained': 64 if kind == 'overflow' else len(HEADER + RECORD),
                                    'drained': len(HEADER + RECORD)}}
        helper = SimpleNamespace(FRAME=original.FRAME, command=original.command,
                                 GateQmp=FakeControl, injected_frame_seen=original.injected_frame_seen)
        with tempfile.TemporaryDirectory() as root, mock.patch.object(gate.os, 'kill') as kill:
            result = gate.run_case(SimpleNamespace(CaptureOwner=Owner), helper, '/unused', Path(root),
                                   kind=kind, deadline=gate.time.monotonic() + 30)
            if kind == 'forced': kill.assert_called_once_with(123, gate.signal.SIGSTOP)
            else: kill.assert_not_called()
            return result

    def test_all_four_closed_case_outcomes(self):
        for kind in gate.KINDS:
            with self.subTest(kind=kind):
                result = self.simulate(kind)
                self.assertTrue(result['passed'])
                self.assertTrue(result['work_removed'])
                self.assertFalse(result['packet_egress_tested'])

    def test_error_must_be_actual_fixed_witness_not_just_reader_closed(self):
        result = self.simulate('dump_error', missing_error=True)
        self.assertFalse(result['passed'])
        self.assertTrue(result['reader_close_ack'])
        self.assertFalse(result['actual_dump_write_error'])

    def test_fault_cannot_be_promoted_to_complete(self):
        for kind in ('forced', 'dump_error', 'overflow'):
            self.assertFalse(self.simulate(kind, forced_complete=True)['passed'])

    def test_uncertain_owned_cleanup_retains_work(self):
        result = self.simulate('normal', cleanup=False)
        self.assertFalse(result['passed'])
        self.assertFalse(result['work_removed'])

    def test_unchanged_original_gate_pin(self):
        source = (ROOT / '.github/test_windows_n0a_capture_qemu.py').read_bytes()
        self.assertEqual(hashlib.sha256(source).hexdigest(), 'cf3cbf003d5b2089e4e5a1ee3465ed79defbb28e329df04ffe6c1685d9721dcd')

    def test_fixed_scope_and_first_packet_fault_order(self):
        source = (ROOT / '.github/test_windows_n0a_capture_child_qemu.py').read_text()
        self.assertEqual(gate.MAX_SECONDS, 75)
        self.assertEqual(gate.KINDS, ('normal', 'forced', 'dump_error', 'overflow'))
        self.assertLess(source.index('owner.fixture_close_reader('), source.index('network[0].sendall('))
        self.assertIn("byte_limit=64", source)
        self.assertIn("owner.output_path.stat().st_size != 64", source)
        self.assertNotIn("execute('cont')", source)
        self.assertNotIn('capture.pcap\"', source)

    def test_qmp_running_or_missing_state_rejected(self):
        for value in ({'running': True, 'status': 'running'}, {}, [], {'running': False, 'status': 'shutdown'}):
            with self.assertRaises(ValueError): gate.require_paused(SimpleNamespace(execute=lambda _: value))

    def test_no_exception_text_leaks(self):
        self.assertEqual(gate.closed_failure(OSError('raw private file and identity')), 'os_error')
        self.assertEqual(gate.closed_failure(TimeoutError('raw timeout')), 'timeout')

if __name__ == '__main__': unittest.main()
