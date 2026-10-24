"""Source/fixture tests do not substitute for the opt-in actual QEMU gate."""
import importlib.util
from pathlib import Path
import struct
import tempfile
from types import SimpleNamespace
import unittest
from unittest import mock

ROOT = Path(__file__).resolve().parents[1]
SPEC = importlib.util.spec_from_file_location('capture_qemu_gate', ROOT / '.github/test_windows_n0a_capture_qemu.py')
gate = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(gate)


class CaptureGateTests(unittest.TestCase):
    def test_paused_local_only_exact_filter(self):
        argv = gate.command('/usr/bin/qemu-system-x86_64', Path('/owned'), Path('/owned/capture.fifo'), 17)
        self.assertIn('-S', argv)
        self.assertEqual(argv[argv.index('-accel') + 1], 'tcg')
        self.assertEqual(argv[argv.index('-netdev') + 1], 'socket,id=vmnet,fd=17')
        self.assertEqual(argv[argv.index('-object') + 1], 'filter-dump,id=n0acap,netdev=vmnet,queue=all,status=on,maxlen=262144,file=/owned/capture.fifo')
        for forbidden in ('-enable-kvm', '-drive', '-cdrom', '-kernel', '-bios', 'user,', 'hostfwd'):
            self.assertFalse(any(forbidden in part for part in argv))

    def check_capture(self, data):
        with tempfile.TemporaryDirectory() as root:
            path = Path(root) / 'synthetic.pcap'
            path.write_bytes(data)
            return gate.injected_frame_seen(path)

    def test_private_header_both_endian_and_ingress_frame(self):
        for endian in ('<', '>'):
            header = struct.pack(endian + 'IHHIIII', 0xa1b2c3d4, 2, 4, 0, 0, 262144, 1)
            self.assertFalse(self.check_capture(header))
            record = struct.pack(endian + 'IIII', 1, 0, len(gate.FRAME), len(gate.FRAME)) + gate.FRAME
            self.assertTrue(self.check_capture(header + record))

    def test_invalid_or_partial_capture_rejected(self):
        header = struct.pack('<IHHIIII', 0xa1b2c3d4, 2, 4, 0, 0, 262144, 1)
        for value in (b'', header[:-1], header + b'x', header + bytes(4097),
                      struct.pack('<IHHIIII', 0xa1b2c3d4, 2, 4, 0, 0, 65536, 1),
                      header + struct.pack('<IIII', 1, 1000000, 0, 0),
                      header + struct.pack('<IIII', 1, 0, 1, 2) + b'x'):
            with self.assertRaises(ValueError): self.check_capture(value)

    def test_qmp_close_owns_partial_connection(self):
        control = gate.GateQmp()
        control.sock = mock.Mock()
        sock = control.sock
        control.close()
        sock.close.assert_called_once()
        self.assertIsNone(control.sock)

    def test_qmp_read_rejects_overbound_frame(self):
        control = gate.GateQmp()
        control.deadline = gate.time.monotonic() + 5
        control.sock = mock.Mock()
        control.sock.recv.return_value = b'x' * 4096
        with self.assertRaises(ValueError): control.read()

    def test_partial_start_failure_still_finishes_and_removes_owned_root(self):
        owners = []
        class Sink:
            def __init__(self, root, **kwargs): self.root = root; owners.append(self)
            def start(self): raise OSError('private path must never escape')
            def finish(self, **kwargs): self.finished = True; return {'cleanup_confirmed': True}
        with tempfile.TemporaryDirectory() as root:
            result = gate.run_case(SimpleNamespace(CaptureSink=Sink), '/unused', Path(root), force=False,
                                   deadline=gate.time.monotonic() + 30)
            self.assertTrue(owners[0].finished)
            self.assertTrue(result['work_removed'])
            self.assertFalse(result['passed'])
            self.assertNotIn('private path', str(result))

    def test_uncertain_sink_cleanup_retains_owned_root(self):
        class Sink:
            def __init__(self, root, **kwargs): pass
            def start(self): raise OSError('fixture')
            def finish(self, **kwargs): return {'cleanup_confirmed': False}
        with tempfile.TemporaryDirectory() as root:
            result = gate.run_case(SimpleNamespace(CaptureSink=Sink), '/unused', Path(root), force=True,
                                   deadline=gate.time.monotonic() + 30)
            self.assertFalse(result['work_removed'])
            self.assertFalse(result['passed'])
            self.assertEqual(len(list(Path(root).iterdir())), 1)

    def test_owned_socket_cleanup_runs_after_spawn_failure(self):
        class Sink:
            def __init__(self, root, **kwargs): self.fifo_path = root / 'capture.fifo'
            def start(self): pass
            def spawn(self, *args, **kwargs): raise OSError('private command')
            def finish(self, **kwargs): return {'cleanup_confirmed': True}
        with tempfile.TemporaryDirectory() as root:
            result = gate.run_case(SimpleNamespace(CaptureSink=Sink), '/unused', Path(root), force=False,
                                   deadline=gate.time.monotonic() + 30)
            self.assertTrue(result['network_sockets_closed'])
            self.assertTrue(result['qmp_closed'])
            self.assertTrue(result['work_removed'])
            self.assertFalse(result['passed'])

    def test_no_runtime_or_direction_claim(self):
        source = (ROOT / '.github/test_windows_n0a_capture_qemu.py').read_text()
        self.assertIn('host-side\nnetdev ingress only', source)
        self.assertNotIn("execute('cont')", source)
        self.assertIn("if not force and result['injected_ingress_frame_observed'] is not True:", source)

if __name__ == '__main__': unittest.main()
