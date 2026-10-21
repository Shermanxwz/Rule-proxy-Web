"""Opt-in paused QEMU FIFO transport gate. No Windows, KVM or guest execution.

Captured bytes and socket tuples remain private. An injected packet is host-side
netdev ingress only; this test is never Windows egress or isolation evidence.
"""
from __future__ import annotations
import argparse
import importlib.util
import json
import os
from pathlib import Path
import shutil
import signal
import socket
import struct
import sys
import tempfile
import time

ROOT = Path(__file__).resolve().parents[1]
MAX_SECONDS = 65
FRAME = bytes.fromhex('ffffffffffff02000000000188b5') + b'N0A-CAPTURE-TRANSPORT' + bytes(27)


def load_sink():
    spec = importlib.util.spec_from_file_location('n0a_capture_gate_sink', ROOT / '.github/windows_n0a_capture.py')
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    return module


def command(binary, work, fifo, network_fd):
    return [binary, '-S', '-machine', 'q35', '-accel', 'tcg', '-m', '64',
            '-nodefaults', '-display', 'none', '-monitor', 'none', '-serial', 'none',
            '-no-reboot', '-qmp', f'unix:{work / "qmp.sock"},server=on,wait=off',
            '-netdev', f'socket,id=vmnet,fd={network_fd}',
            '-device', 'e1000,netdev=vmnet',
            '-object', f'filter-dump,id=n0acap,netdev=vmnet,queue=all,status=on,maxlen=262144,file={fifo}']


class GateQmp:
    """Bounded private control; allocate owner before connect/handshake."""
    def __init__(self):
        self.sock = None
        self.buffer = bytearray()
        self.counter = 0
        self.deadline = None

    def connect(self, path, deadline):
        self.deadline = deadline
        self.sock = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        self.sock.settimeout(1)
        while True:
            try:
                self.sock.connect(str(path))
                break
            except (FileNotFoundError, ConnectionRefusedError):
                if time.monotonic() >= deadline:
                    raise TimeoutError('qmp_start') from None
                time.sleep(.02)
        greeting = self.read()
        if not isinstance(greeting, dict) or not isinstance(greeting.get('QMP'), dict):
            raise ValueError('qmp_greeting')
        self.execute('qmp_capabilities')

    def read(self):
        while b'\n' not in self.buffer:
            remaining = self.deadline - time.monotonic()
            if remaining <= 0:
                raise TimeoutError('qmp_deadline')
            self.sock.settimeout(min(1, remaining))
            block = self.sock.recv(4096)
            if not block:
                raise EOFError('qmp_eof')
            self.buffer.extend(block)
            if len(self.buffer) > 65536:
                raise ValueError('qmp_bound')
        line, _, rest = self.buffer.partition(b'\n')
        self.buffer = bytearray(rest)
        return json.loads(line)

    def execute(self, name):
        self.counter += 1
        self.sock.sendall(json.dumps({'execute': name, 'id': self.counter}).encode('ascii') + b'\n')
        for _ in range(16):
            value = self.read()
            if value.get('id') == self.counter:
                if 'error' in value or 'return' not in value:
                    raise ValueError('qmp_result')
                return value['return']
        raise ValueError('qmp_events')

    def close(self):
        if self.sock is not None:
            self.sock.close()
            self.sock = None


def injected_frame_seen(path):
    """Read only a small private synthetic capture; no packet contents escape."""
    with path.open('rb') as stream:
        data = stream.read(4097)
    if len(data) > 4096 or len(data) < 24:
        raise ValueError('capture_bound')
    endian = '<' if data[:4] == bytes.fromhex('d4c3b2a1') else '>' if data[:4] == bytes.fromhex('a1b2c3d4') else None
    if endian is None or struct.unpack(endian + 'IHHIIII', data[:24]) != (0xa1b2c3d4, 2, 4, 0, 0, 262144, 1):
        raise ValueError('capture_header')
    position = 24
    found = False
    while position < len(data):
        if position + 16 > len(data):
            raise ValueError('capture_record')
        _, micros, length, original = struct.unpack(endian + 'IIII', data[position:position + 16])
        position += 16
        if micros >= 1000000 or length != original or length > 262144 or position + length > len(data):
            raise ValueError('capture_record')
        found |= data[position:position + length] == FRAME
        position += length
    return found


def run_case(module, binary, root, *, force, deadline):
    result = {'passed': False, 'forced_case': force, 'header_observed': False,
              'qemu_8_2_2': False, 'never_running': False,
              'injected_ingress_frame_observed': False,
              'packet_egress_tested': False, 'qmp_closed': False,
              'network_sockets_closed': False, 'work_removed': False,
              'phase': 'create', 'failure_kind': 'none'}
    sink = control = None
    network = []
    finish = None
    work = None
    try:
        work = Path(tempfile.mkdtemp(prefix='case-', dir=root)); work.chmod(0o700)
        sink = module.CaptureSink(work, deadline=deadline - 20)
        result['phase'] = 'reader'
        sink.start()
        network = list(socket.socketpair(socket.AF_UNIX, socket.SOCK_STREAM))
        for sock in network: sock.settimeout(1)
        result['phase'] = 'spawn'
        sink.spawn(command(binary, work, sink.fifo_path, network[1].fileno()), pass_fds=(network[1].fileno(),))
        # Parent's duplicate is no longer needed, and must not mask backend EOF.
        network[1].close()
        result['phase'] = 'header'
        if sink.wait_header(min(time.monotonic() + 5, deadline - 20)) is not True:
            raise ValueError('header_missing')
        result['header_observed'] = True
        control = GateQmp()
        control.connect(work / 'qmp.sock', min(time.monotonic() + 5, deadline - 20))
        result['phase'] = 'version'
        version = control.execute('query-version')
        if version.get('qemu') != {'major': 8, 'minor': 2, 'micro': 2}:
            raise ValueError('version')
        result['qemu_8_2_2'] = True
        state = control.execute('query-status')
        if state.get('running') is not False or state.get('status') not in ('paused', 'prelaunch'):
            raise ValueError('not_paused')
        result['never_running'] = True
        result['phase'] = 'inject'
        network[0].sendall(struct.pack('!I', len(FRAME)) + FRAME)
        time.sleep(.1)
        control.close(); result['qmp_closed'] = True
        if force:
            # A stopped, still-owned QEMU cannot service SIGTERM. Only this PID
            # is stopped; finish must kill it and mark capture incomplete.
            result['phase'] = 'force_stop'
            if sink.process.poll() is not None:
                raise ValueError('early_exit')
            os.kill(sink.process.pid, signal.SIGSTOP)
        result['phase'] = 'finish'
        finish = sink.finish(cleanup_deadline=deadline)
        result['sink'] = finish
        if (finish.get('cleanup_confirmed') is not True or finish.get('output_flushed') is not True
                or finish.get('fifo_eof') is not True or finish.get('header_verified') is not True):
            raise ValueError('cleanup_or_capture')
        if force:
            if finish.get('forced_kill') is not True or finish.get('drain_complete') is not False:
                raise ValueError('forced_not_incomplete')
        elif finish.get('forced_kill') is not False or finish.get('drain_complete') is not True:
            raise ValueError('normal_not_complete')
        result['injected_ingress_frame_observed'] = injected_frame_seen(sink.output_path)
        if not force and result['injected_ingress_frame_observed'] is not True:
            raise ValueError('ingress_not_observed')
        result['phase'] = 'completed'
        result['passed'] = True
    except BaseException as exc:
        result['failure_kind'] = ('timeout' if isinstance(exc, TimeoutError) else
                                  'os_error' if isinstance(exc, OSError) else
                                  'validation' if isinstance(exc, (ValueError, AssertionError)) else 'other')
    finally:
        if control is None:
            result['qmp_closed'] = True
        elif not result['qmp_closed']:
            try: control.close(); result['qmp_closed'] = True
            except BaseException: pass
        if sink is not None and finish is None:
            try: finish = sink.finish(cleanup_deadline=deadline); result['sink'] = finish
            except BaseException: pass
        network_ok = True
        for sock in network:
            try: sock.close()
            except BaseException: network_ok = False
        result['network_sockets_closed'] = network_ok
        # Never delete beneath an unconfirmed producer/reader.
        if work is None:
            result['work_removed'] = True
        elif (sink is None or isinstance(finish, dict) and finish.get('cleanup_confirmed') is True) and result['qmp_closed'] and network_ok:
            try: shutil.rmtree(work); result['work_removed'] = not work.exists()
            except BaseException: pass
        result['passed'] = result['passed'] and all(result[key] for key in ('qmp_closed', 'network_sockets_closed', 'work_removed'))
    return result


def run_actual():
    result = {'schema': 1, 'test_kind': 'paused_qemu_fifo_capture', 'passed': False,
              'runtime_acceptance': False, 'packet_egress_tested': False,
              'guest_execution': False, 'root_removed': False, 'failure_kind': 'none'}
    root = None
    try:
        binary = shutil.which('qemu-system-x86_64')
        if sys.platform != 'linux' or binary is None:
            raise ValueError('linux_qemu_required')
        module = load_sink()
        deadline = time.monotonic() + MAX_SECONDS
        root = Path(tempfile.mkdtemp(prefix='n0a-capture-qemu-')); root.chmod(0o700)
        result['normal'] = run_case(module, binary, root, force=False, deadline=deadline)
        # Also collect forced lifecycle evidence if normal capture validation
        # failed but ownership was positively resolved; never overlap producers.
        if result['normal']['work_removed']:
            result['forced'] = run_case(module, binary, root, force=True, deadline=deadline)
        result['passed'] = result['normal']['passed'] and result.get('forced', {}).get('passed') is True
    except BaseException as exc:
        result['failure_kind'] = 'os_error' if isinstance(exc, OSError) else 'validation' if isinstance(exc, ValueError) else 'other'
    finally:
        if root is None:
            result['root_removed'] = True
        else:
            try: root.rmdir(); result['root_removed'] = True
            except OSError: pass
        result['passed'] = result['passed'] and result['root_removed']
    return result


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--run-actual-qemu', action='store_true')
    args = parser.parse_args(argv)
    if not args.run_actual_qemu:
        parser.error('explicit actual QEMU opt-in required')
    result = run_actual()
    print(json.dumps(result, sort_keys=True, separators=(',', ':')))
    return 0 if result['passed'] else 1

if __name__ == '__main__':
    raise SystemExit(main())
