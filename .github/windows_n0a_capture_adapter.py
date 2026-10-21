"""Inactive runner-only capture composition; private bytes never become output.

Source-report digests are ordinary-controller attestations, not independent
native-report authentication. Tuple observations are not full egress, delivery,
or isolation acceptance. Linux lifecycle imports are lazy for pure Windows gates.
"""
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import re
import secrets
import stat
import sys

CAPTURE_EXECUTION_ENABLED = False
MAX_FLOW = 65536
MAX_CAPTURE = 64 * 1024 * 1024
EXTRA_RESERVE = 65 * 1024 * 1024
MAX_RESULT = 4096


class CaptureReadCloseError(OSError):
    """Owned read descriptor closure unknown; never retry its numeric FD."""



def helper(name):
    path = Path(__file__).with_name('windows_n0a_' + name + '.py')
    spec = importlib.util.spec_from_file_location('n0a_capture_' + name, path)
    module = importlib.util.module_from_spec(spec)
    previous = sys.modules.get(spec.name)
    sys.modules[spec.name] = module
    try:
        spec.loader.exec_module(module)
    except BaseException:
        if previous is None: sys.modules.pop(spec.name, None)
        else: sys.modules[spec.name] = previous
        raise
    return module


def hex_value(value, length):
    return type(value) is str and re.fullmatch('[0-9a-f]{%d}' % length, value) is not None


def make_configuration(n0a_config, source_commit, mac):
    if n0a_config.get('enabled') is not True or not hex_value(source_commit, 40):
        raise ValueError('capture configuration')
    mac = mac.replace(':', '') if type(mac) is str else None
    if not hex_value(mac, 12) or int(mac[:2], 16) & 1 or int(mac, 16) == 0:
        raise ValueError('capture configuration')
    return dict(enabled=True, run_nonce=secrets.token_hex(16), source_commit=source_commit, vm_mac=mac)


def admit(payload_bytes, free_bytes, baseline_launch_free):
    if any(type(v) is not int or v < 0 for v in (payload_bytes, free_bytes, baseline_launch_free)):
        raise ValueError('capture capacity')
    if not 0 < payload_bytes or 2 * payload_bytes + 16 * 1024 * 1024 > MAX_CAPTURE:
        raise ValueError('capture payload bound')
    if free_bytes < baseline_launch_free + EXTRA_RESERVE:
        raise ValueError('capture capacity')
    return dict(payload_admitted=True, capacity_admitted=True, planning_only=True)


def new_owner(root, outer_deadline):
    return helper('capture_child').CaptureOwner(root, deadline=outer_deadline)


def valid_commitment(value):
    return (type(value) is dict and set(value) == {'sha256', 'bytes', 'contained_report_sha256', 'ordinary_report_sha256'}
            and type(value['bytes']) is int and 0 < value['bytes'] <= MAX_FLOW
            and all(hex_value(value[k], 64) for k in ('sha256', 'contained_report_sha256', 'ordinary_report_sha256')))


def validate_capture_envelope(value, expected_n0a):
    if (type(value) is not dict or set(value) != {'schema_version', 'legacy', 'flow_commitment'}
            or type(value['schema_version']) is not int or value['schema_version'] != 2):
        raise ValueError('capture envelope')
    try:
        if len(json.dumps(value, ensure_ascii=True).encode('ascii')) > MAX_RESULT:
            raise ValueError('capture bound')
    except (TypeError, RecursionError):
        raise ValueError('capture envelope') from None
    legacy = helper('control').validate_host_n0a_envelope(value['legacy'], expected_n0a)
    commitment = value['flow_commitment']
    valid = valid_commitment(commitment)
    return dict(legacy=legacy, commitment=dict(commitment) if valid else None,
                commitment_error=commitment is not None and not valid)


def accept_private_body(raw, commitment):
    return (type(raw) is bytes and valid_commitment(commitment)
            and len(raw) == commitment['bytes']
            and hashlib.sha256(raw).hexdigest() == commitment['sha256'])


def unavailable(reason='unavailable'):
    if reason not in {'unavailable', 'flow', 'capture_file', 'normalization', 'parse'}:
        reason = 'unavailable'
    return dict(schema_version=1, status='inconclusive', packet_egress_tested=False,
                scope='runner_ipv4_tcp_tuple', source_report_binding='ordinary_controller_attested',
                actor_attribution_established=False,
                tuple_packet_observed=None, packet=None, reason=reason,
                host_prerequisites_verified=False, capture_read_cleanup_confirmed=None, isolation_acceptance=False)


def read_capture(path):
    path = Path(path)
    before = path.lstat()
    if not stat.S_ISREG(before.st_mode) or before.st_nlink != 1 or not 24 <= before.st_size <= MAX_CAPTURE:
        raise ValueError('capture file')
    fd = os.open(path, os.O_RDONLY | getattr(os, 'O_NOFOLLOW', 0) | getattr(os, 'O_BINARY', 0))
    try:
        current = os.fstat(fd)
        if (current.st_dev, current.st_ino, current.st_size) != (before.st_dev, before.st_ino, before.st_size):
            raise ValueError('capture file')
        chunks = []; remaining = current.st_size
        while remaining:
            chunk = os.read(fd, min(1048576, remaining))
            if not chunk: raise ValueError('capture file')
            chunks.append(chunk); remaining -= len(chunk)
        if os.read(fd, 1): raise ValueError('capture file')
        after = os.fstat(fd)
        if (after.st_size, after.st_mtime_ns, after.st_ctime_ns) != (current.st_size, current.st_mtime_ns, current.st_ctime_ns):
            raise ValueError('capture file')
        return b''.join(chunks)
    finally:
        # Detach ownership before the sole close attempt: Linux may release the
        # descriptor even when close reports an error. Never retry its number.
        closing, fd = fd, None
        try: os.close(closing)
        except OSError: raise CaptureReadCloseError("capture read close uncertain") from None


def capture_contract(data, facts, *, header_before_link, terminal_before_shutdown, capacity_abort):
    facts = facts if type(facts) is dict else {}
    child = facts.get('capture')
    child = child if type(child) is dict else {}
    complete = (all(facts.get(k) is True for k in ('drain_complete', 'cleanup_confirmed', 'final_status_observed',
                'status_eof', 'child_exit_observed', 'descriptors_closed'))
                and type(facts.get('child_exit_code')) is int and facts['child_exit_code'] == 0
                and facts.get('child_forced') is False and facts.get('errors') == [] and child.get('errors') == [])
    orderly = (facts.get('shutdown_authorized') is True and facts.get('producer_live_at_shutdown') is True
               and facts.get('qemu_exit_observed') is True and type(facts.get('qemu_exit_code')) is int
               and facts['qemu_exit_code'] == 0 and facts.get('qemu_forced') is False)
    return dict(sha256=hashlib.sha256(data).hexdigest(), bytes=len(data),
                header_before_cases=header_before_link is True and facts.get('header_verified') is True,
                shutdown_after_terminal=terminal_before_shutdown is True,
                fifo_eof=child.get('fifo_eof') is True, stderr_eof=child.get('stderr_eof') is True,
                dump_error=not complete or child.get('qemu_dump_write_error') is not False or capacity_abort is not False,
                overflow=child.get('overflow') is not False, truncated=child.get('structure') is not True,
                fsynced=child.get('flushed') is True, fd_closed=facts.get('descriptors_closed') is True and child.get('closed') is True,
                qemu_exited_orderly=orderly, qemu_killed=facts.get('qemu_forced') is not False,
                sink_status='complete' if complete else 'incomplete',
                sink_exit_code=facts.get('child_exit_code') if facts.get('child_exit_observed') is True else None)


def parse_before_cleanup(path, capture_facts, raw_flow, flow_expected, *, header_before_link,
                         terminal_before_shutdown, capacity_abort=False):
    if type(flow_expected) is not dict or not accept_private_body(raw_flow, flow_expected.get('flow_commitment')):
        return unavailable('flow')
    try:
        normalized = helper('flow').normalize(raw_flow, flow_expected)
    except Exception:
        return unavailable('normalization')
    # Do not read a still-owned writer's mutable file. Forced but observed exits
    # permit positive-byte diagnostics, never a completeness inference.
    if (type(capture_facts) is not dict or capture_facts.get('qemu_exit_observed') is not True
            or capture_facts.get('child_exit_observed') is not True):
        return unavailable('capture_file')
    try:
        data = read_capture(path)
    except CaptureReadCloseError:
        result = unavailable('capture_file')
        result['capture_read_cleanup_confirmed'] = False
        return result
    except Exception:
        return unavailable('capture_file')
    try:
        contract = capture_contract(data, capture_facts, header_before_link=header_before_link,
                                    terminal_before_shutdown=terminal_before_shutdown, capacity_abort=capacity_abort)
        packet = helper('packet').evaluate(data, normalized['manifest_bytes'], normalized['expected'], contract)
    except Exception:
        result = unavailable('parse')
        result['capture_read_cleanup_confirmed'] = True
        return result
    result = unavailable()
    result.update(capture_read_cleanup_confirmed=True, packet_egress_tested=True, tuple_packet_observed=packet['tuple_packet_observed'],
                  packet=packet, reason='none', status=packet['status'])
    return result


def qualify(tentative, original_public, n0a_public):
    result = json.loads(json.dumps(tentative))
    receiver = n0a_public.get('host_receiver')
    receiver = receiver if type(receiver) is dict else {}
    counts = receiver.get('receiver_counts')
    counts = counts if type(counts) is dict else {}
    ready = (original_public.get('guest_result_provenance_verified') is True
             and original_public.get('vm_destroyed') is True
             and n0a_public.get('receipt_verified') is True
             and n0a_public.get('vm_destroyed') is True
             and n0a_public.get('original_stage0_receipt_verified') is True
             and receiver.get('socket_cleanup_confirmed') is True and receiver.get('endpoint_error') is False
             and set(counts) == {'accepted', 'ordinary_verified_frames', 'contained_verified_frames', 'rejected', 'timed_out'}
             and all(type(v) is int and 0 <= v <= 128 for v in counts.values())
             and counts.get('ordinary_verified_frames', 0) >= 5 and counts.get('contained_verified_frames') == 0
             and n0a_public.get('result', {}).get('status') == 'observed_connect_denial')
    result['host_prerequisites_verified'] = ready
    if result['status'] == 'no_selected_tuple_observed' and not ready:
        result['status'] = 'inconclusive'
        if type(result.get('packet')) is dict:
            result['packet']['status'] = 'inconclusive'
            result['packet']['reasons'] = sorted(set(result['packet']['reasons']) | {'host_prerequisites'})
    result['isolation_acceptance'] = False
    return result
