"""Opt-in actual paused-QEMU gate for the separate owned capture child.

Only local synthetic netdev ingress is injected. No Windows, firmware execution,
KVM, external networking, packet-absence verdict or public capture bytes.
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
MAX_SECONDS = 75
KINDS = ('normal', 'forced', 'dump_error', 'overflow')


def load_module(name, path):
    spec = importlib.util.spec_from_file_location(name, path)
    value = importlib.util.module_from_spec(spec)
    sys.modules[name] = value
    spec.loader.exec_module(value)
    return value


def private_gate():
    return load_module('n0a_original_capture_gate', ROOT / '.github/test_windows_n0a_capture_qemu.py')


def require_paused(control):
    state = control.execute('query-status')
    if not isinstance(state, dict) or state.get('running') is not False or state.get('status') not in ('paused', 'prelaunch'):
        raise ValueError('not_paused')


def closed_failure(exc):
    return ('timeout' if isinstance(exc, TimeoutError) else
            'os_error' if isinstance(exc, OSError) else
            'validation' if isinstance(exc, (ValueError, AssertionError)) else 'other')


def require_cleanup(facts):
    if not isinstance(facts, dict) or facts.get('cleanup_confirmed') is not True:
        raise ValueError('cleanup_not_confirmed')


def run_case(module, original, binary, root, *, kind, deadline):
    if kind not in KINDS:
        raise ValueError('case_kind')
    result = {'passed': False, 'kind': kind, 'phase': 'create', 'failure_kind': 'none',
              'qemu_8_2_2': False, 'never_running': False, 'header_observed': False,
              'reader_close_ack': False, 'actual_dump_write_error': False,
              'producer_live_after_fault': False, 'qmp_paused_after_fault': False,
              'injected_ingress_frame_observed': False, 'overflow_bound_verified': False,
              'qmp_closed': False, 'network_sockets_closed': False, 'work_removed': False,
              'packet_egress_tested': False}
    owner = control = None
    network = []
    work = final = None
    active_deadline = deadline - 20
    try:
        if time.monotonic() >= active_deadline:
            raise TimeoutError('admission')
        work = Path(tempfile.mkdtemp(prefix='case-', dir=root)); work.chmod(0o700)
        if kind == 'dump_error':
            owner = module.CaptureOwner.for_test(work, deadline=deadline, mode='close_reader')
        elif kind == 'overflow':
            owner = module.CaptureOwner.for_test(work, deadline=deadline, byte_limit=64)
        else:
            owner = module.CaptureOwner(work, deadline=deadline)
        result['phase'] = 'reader'
        owner.start()
        network = list(socket.socketpair(socket.AF_UNIX, socket.SOCK_STREAM))
        for sock in network: sock.settimeout(1)
        result['phase'] = 'spawn'
        owner.spawn(original.command(binary, work, owner.fifo_path, network[1].fileno()),
                    pass_fds=(network[1].fileno(),))
        network[1].close()
        result['phase'] = 'header'
        if owner.wait_header(min(time.monotonic() + 5, active_deadline)) is not True:
            raise ValueError('header_missing')
        result['header_observed'] = True
        control = original.GateQmp()
        control.connect(work / 'qmp.sock', min(time.monotonic() + 10, active_deadline))
        result['phase'] = 'version'
        if control.execute('query-version').get('qemu') != {'major': 8, 'minor': 2, 'micro': 2}:
            raise ValueError('version')
        result['qemu_8_2_2'] = True
        require_paused(control); result['never_running'] = True
        if kind == 'dump_error':
            result['phase'] = 'close_reader'
            if owner.fixture_close_reader(min(time.monotonic() + 2, active_deadline)) is not True:
                raise ValueError('reader_not_closed')
            result['reader_close_ack'] = True
        # The first packet reaches filter-dump before the paused NIC queue.
        # A second packet could remain queued at the socket backend, so the
        # EPIPE case deliberately closes the reader before its FIRST packet.
        result['phase'] = 'inject'
        network[0].sendall(struct.pack('!I', len(original.FRAME)) + original.FRAME)
        total = 24 + 16 + len(original.FRAME)
        wait_deadline = min(time.monotonic() + 5, active_deadline)
        if kind == 'dump_error':
            if owner.wait(lambda value: isinstance(value, dict) and value.get('qemu_dump_write_error') is True,
                          wait_deadline) is not True:
                raise ValueError('actual_dump_error_missing')
            result['actual_dump_write_error'] = True
        elif kind == 'overflow':
            if owner.wait(lambda value: isinstance(value, dict) and value.get('drained') == total and value.get('overflow') is True,
                          wait_deadline) is not True:
                raise ValueError('frame_not_drained')
        else:
            # No per-packet status traffic is required from the production child.
            # This fixture owns the private output, so observe only its byte size.
            while owner.output_path.stat().st_size < total:
                if time.monotonic() >= wait_deadline or owner.process.poll() is not None:
                    raise ValueError('frame_not_retained')
                time.sleep(.02)
        if kind in ('dump_error', 'overflow'):
            result['phase'] = 'fault_control'
            if owner.process.poll() is not None:
                raise ValueError('producer_died')
            result['producer_live_after_fault'] = True
            require_paused(control); result['qmp_paused_after_fault'] = True
        control.close(); result['qmp_closed'] = True
        if kind == 'forced':
            result['phase'] = 'force_stop'
            if owner.process.poll() is not None:
                raise ValueError('producer_died')
            os.kill(owner.process.pid, signal.SIGSTOP)
        result['phase'] = 'finish'
        final = owner.finish(cleanup_deadline=deadline)
        result['sink'] = final
        require_cleanup(final)
        status = final.get('capture')
        if not isinstance(status, dict) or status.get('header') is not True:
            raise ValueError('final_header')
        if kind == 'normal':
            if final.get('drain_complete') is not True or final.get('qemu_forced') is not False or final.get('child_forced') is not False:
                raise ValueError('normal_not_complete')
            result['injected_ingress_frame_observed'] = original.injected_frame_seen(owner.output_path)
            if result['injected_ingress_frame_observed'] is not True:
                raise ValueError('ingress_not_observed')
        else:
            if final.get('drain_complete') is not False:
                raise ValueError('fault_marked_complete')
            if kind == 'forced' and final.get('qemu_forced') is not True:
                raise ValueError('forced_not_observed')
            if kind == 'dump_error' and status.get('qemu_dump_write_error') is not True:
                raise ValueError('dump_error_not_sticky')
            if kind == 'overflow':
                if (status.get('overflow') is not True or status.get('retained') != 64
                        or status.get('drained') != total or owner.output_path.stat().st_size != 64):
                    raise ValueError('overflow_bound')
                result['overflow_bound_verified'] = True
        result['phase'] = 'completed'; result['passed'] = True
    except BaseException as exc:
        result['failure_kind'] = closed_failure(exc)
    finally:
        if control is None:
            result['qmp_closed'] = True
        elif not result['qmp_closed']:
            try: control.close(); result['qmp_closed'] = True
            except BaseException: pass
        if owner is not None and final is None:
            try: final = owner.finish(cleanup_deadline=deadline); result['sink'] = final
            except BaseException: pass
        sockets_closed = True
        for sock in network:
            try: sock.close()
            except BaseException: sockets_closed = False
        result['network_sockets_closed'] = sockets_closed
        if work is None:
            result['work_removed'] = True
        elif (owner is None or isinstance(final, dict) and final.get('cleanup_confirmed') is True) and result['qmp_closed'] and sockets_closed:
            try: shutil.rmtree(work); result['work_removed'] = not work.exists()
            except BaseException: pass
        result['passed'] = result['passed'] and all(result[key] for key in ('qmp_closed', 'network_sockets_closed', 'work_removed'))
    return result


def run_actual():
    result = {'schema': 1, 'test_kind': 'paused_qemu_capture_child', 'passed': False,
              'runtime_acceptance': False, 'packet_egress_tested': False,
              'guest_execution': False, 'root_removed': False, 'failure_kind': 'none', 'cases': []}
    root = None
    try:
        binary = shutil.which('qemu-system-x86_64')
        if sys.platform != 'linux' or binary is None:
            raise ValueError('linux_qemu_required')
        module = load_module('n0a_child_gate_owner', ROOT / '.github/windows_n0a_capture_child.py')
        original = private_gate()
        deadline = time.monotonic() + MAX_SECONDS
        root = Path(tempfile.mkdtemp(prefix='n0a-capture-child-qemu-')); root.chmod(0o700)
        for kind in KINDS:
            value = run_case(module, original, binary, root, kind=kind, deadline=deadline)
            result['cases'].append(value)
            if not value['work_removed']:
                break  # Never overlap an uncertain owned process with another case.
        result['passed'] = len(result['cases']) == len(KINDS) and all(case['passed'] for case in result['cases'])
    except BaseException as exc:
        result['failure_kind'] = closed_failure(exc)
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
