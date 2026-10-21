"""Explicit Windows test-only socket fixture; never container/network acceptance.

Own loopback listeners only. Child raw output stays private; stdout is fixed booleans.
The fixture binary directly invokes the production socket helper, deliberately not
its token guard. Production actor invocation separately tests fail-closed arguments.
"""
from __future__ import annotations
import argparse
import hashlib
import json
import os
from pathlib import Path
import socket
import subprocess
import threading
import time
import tempfile
import secrets
import shutil
import importlib.util
import sys

GATE_STAGE = 'initialization'
FRAME = b'N0A1 0123456789abcdef0123456789abcdef guest ordinary\n'


def finish_child(child):
    """Attempt every exact-owned cleanup even if kill/wait/close fails."""
    if child is None:
        return True, True
    clean = True
    exited = False
    try:
        exited = child.poll() is not None
    except BaseException:
        clean = False
    if not exited:
        try: child.kill()
        except BaseException: clean = False
    try:
        child.wait(timeout=2)
        exited = child.poll() is not None
    except BaseException:
        clean = False
        try: exited = child.poll() is not None
        except BaseException: exited = False
    for name in ('stdout', 'stderr'):
        try:
            stream = getattr(child, name)
            if stream is not None:
                stream.close()
                clean = clean and stream.closed
        except BaseException:
            clean = False
    return exited, clean


def fixture_case(executable, mode):
    listener = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    listener.bind(('127.0.0.1', 0))
    port = listener.getsockname()[1]
    listener.listen(1)
    listener.settimeout(3)
    facts = {'accepted': False, 'frame': False, 'closed': False}
    failure = []

    def serve():
        try:
            with listener.accept()[0] as peer:
                facts['accepted'] = True
                peer.settimeout(2)
                data = b''
                while len(data) < len(FRAME):
                    chunk = peer.recv(len(FRAME)-len(data))
                    if not chunk:
                        break
                    data += chunk
                facts['frame'] = data == FRAME
                if mode == 'good':
                    # Fragmented actual receive path, same fixed payload only.
                    peer.sendall(FRAME[:7]); peer.sendall(FRAME[7:])
                elif mode == 'wrong':
                    peer.sendall(b'X' * len(FRAME))
                elif mode == 'timeout':
                    time.sleep(1.2)
                else:
                    raise AssertionError('fixed fixture mode')
        except BaseException:
            failure.append('fixture_failure')
        finally:
            try:
                listener.close()
                facts['closed'] = listener.fileno() == -1
            except BaseException:
                failure.append('listener_cleanup')

    thread = threading.Thread(target=serve, daemon=True)
    thread.start()
    started = time.monotonic()
    child = None
    exited = False
    try:
        child = subprocess.Popen([str(executable), '--owned-loopback-fixture', str(port)],
                                 stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        output, error = child.communicate(timeout=5)
        exited = child.poll() is not None
        assert exited and child.returncode == 0 and not error and len(output) <= 32768
        wire = json.loads(output)
        # Schema/timing parity only. Binding is explicitly SYNTHETIC and is not
        # passed to runtime evaluation or claimed as current OS/G provenance.
        spec = importlib.util.spec_from_file_location('n0a_fixture_control', Path(__file__).with_name('windows_n0a_control.py'))
        engine = importlib.util.module_from_spec(spec)
        sys.modules[spec.name] = engine
        spec.loader.exec_module(engine)
        binding = engine.Binding('0123456789abcdef0123456789abcdef', 'a'*64, 'b'*64,
                                 'S-1-15-3-1024-1', (port, port), 1, False, False)
        envelope = {'nonce': binding.nonce, 'actor_sha256': binding.actor_sha256,
                    'executor_sha256': binding.executor_sha256, 'build': binding.build,
                    'ubr': binding.ubr, 'actor': wire}
        parsed = engine.observation(envelope, binding, 'guest', 'ordinary', 'single')
        assert parsed is not None and parsed['profileMatched'] is False
        record = wire['n0a']['attempts'][0]
        assert type(record) is dict and record['attempted'] is True
        assert record['bindSucceeded'] is True and record['connectSucceeded'] is True
        assert record['closed'] is True and 1024 < record['localPort'] <= 65535
        assert 0 < record['connectStartQpc'] <= record['connectEndQpc'] <= record['exchangeEndQpc']
        if mode == 'good':
            assert record['nonceMatched'] is True and record['win32Error'] == 0 and record['failure'] == 'none'
        else:
            assert record['nonceMatched'] is False
            assert record['failure'] == ('echo' if mode == 'wrong' else 'recv')
            assert record['win32Error'] == (10022 if mode == 'wrong' else 10060)
        assert time.monotonic()-started < 5
    finally:
        exited, child_clean = finish_child(child)
        if not child_clean: failure.append('child_cleanup')
        try: listener.close()
        except BaseException: failure.append('listener_cleanup')
        try: thread.join(timeout=3)
        except BaseException: failure.append('thread_cleanup')
    assert exited and not thread.is_alive() and facts == {'accepted': True, 'frame': True, 'closed': True} and not failure
    return True


def production_guard(executable, role):
    # Actual production entry; the host's observed non-AppContainer token must
    # fail the contained profile before any socket. No temporary account/token.
    directory = Path(tempfile.mkdtemp(prefix='n0a-production-guard-'))
    child = None
    confirmed = True
    listener = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    listener.bind(('127.0.0.1', 0))
    port = listener.getsockname()[1]
    listener.listen(1)
    listener.settimeout(0.1)
    try:
        report = directory / 'private.json'
        nonce = secrets.token_hex(16)
        child = subprocess.Popen([str(executable), 'n0a-tcp', nonce, str(report),
                                  'guest', str(port), role, 'single'],
                                 stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        confirmed = False
        output, error = child.communicate(timeout=5)
        confirmed = child.poll() is not None
        assert child.returncode == 0 and not output and not error
        assert not report.is_symlink() and report.stat().st_size <= 32768
        raw_report = report.read_bytes()
        value = json.loads(raw_report)
        flow_spec = importlib.util.spec_from_file_location('native_snapshot_flow', Path(__file__).with_name('windows_n0a_flow.py'))
        flow = importlib.util.module_from_spec(flow_spec); flow_spec.loader.exec_module(flow)
        snapshot_value, snapshot = flow.read_snapshot(report)
        assert snapshot_value == value and snapshot == {'sha256': hashlib.sha256(raw_report).hexdigest(), 'bytes': len(raw_report)}
        assert value['nonce'] == nonce and value['pid'] == child.pid
        assert value['mode'] == 'actor-n0a' and value['queriesSucceeded'] is True
        assert value['tokenIsAppContainer'] is False and value['errors'] == []
        assert value['n0a']['profileMatched'] is False and value['n0a']['attempts'] == []
        assert value['n0a']['startupError'] == 0
        if role == 'ordinary':
            assert value['tokenElevated'] is True  # actual hosted-admin negative, not a bypass
        try:
            peer, _ = listener.accept()
        except socket.timeout:
            pass
        else:
            peer.close()
            raise AssertionError('profile guard unexpectedly opened a connection')
    finally:
        confirmed, child_clean = finish_child(child)
        listener_clean = True
        try: listener.close()
        except BaseException: listener_clean = False
        # If owned process exit is uncertain, keep its exact root; no false cleanup.
        if confirmed:
            assert not directory.is_symlink()
            shutil.rmtree(directory)
    assert confirmed and child_clean and listener_clean and not directory.exists()
    return True


def main():
    global GATE_STAGE
    parser = argparse.ArgumentParser()
    parser.add_argument('--run-owned-loopback-fixtures', action='store_true', required=True)
    parser.add_argument('--fixture-exe', type=Path, required=True)
    parser.add_argument('--actor-exe', type=Path, required=True)
    args = parser.parse_args()
    if os.name != 'nt':
        raise RuntimeError('Windows native fixture required')
    facts = {}
    for mode in ('good', 'wrong', 'timeout'):
        GATE_STAGE = 'socket_' + mode
        facts[mode] = fixture_case(args.fixture_exe, mode)
    GATE_STAGE = 'contained_guard'
    facts['production_contained_guard_rejects_source_token'] = production_guard(args.actor_exe, 'contained')
    GATE_STAGE = 'ordinary_admin_guard'
    facts['production_ordinary_guard_rejects_observed_admin'] = production_guard(args.actor_exe, 'ordinary')
    facts['actual_native_snapshot_parse_hash_parity'] = True
    GATE_STAGE = 'profile_contract'
    profile = subprocess.run([str(args.fixture_exe), '--profile-contract'], capture_output=True, timeout=5)
    assert profile.returncode == 0 and not profile.stderr and len(profile.stdout) <= 256
    profile_record = json.loads(profile.stdout)
    facts['native_profile_contract_12_synthetic_cases'] = profile_record == {'profile_checks': 12, 'synthetic_identity': True}
    GATE_STAGE = 'report_composition'
    shaped = subprocess.run([str(args.fixture_exe), '--report-shape'], capture_output=True, timeout=5)
    assert shaped.returncode == 0 and not shaped.stderr and len(shaped.stdout) <= 32768
    shape = json.loads(shaped.stdout)
    facts['actual_report_composition_max40'] = (shape['mode'] == 'actor-n0a' and len(shape['n0a']['attempts']) == 40
                                               and shape['n0a']['windowEndQpc'] == 9223372036854775807)

    GATE_STAGE = 'invalid_role'
    child = subprocess.run([str(args.actor_exe), 'not-authorized-role'], capture_output=True, timeout=5)
    facts['invalid_role_rejected_without_output'] = child.returncode == 2 and child.stdout == b'' and child.stderr == b''
    assert all(facts.values())
    print(json.dumps({'schema_version': 1, 'checks': facts, 'runtime_acceptance': False,
                      'token_guard_exercised_by_socket_fixture': False, 'wire_binding_synthetic': True,
                      'owned_cleanup_confirmed': True}, sort_keys=True))


if __name__ == '__main__':
    try:
        main()
    except BaseException as failure:
        # Never print traceback, argv, raw report, nonce, path, or exception text.
        allowed = {'initialization', 'socket_good', 'socket_wrong', 'socket_timeout',
                   'contained_guard', 'ordinary_admin_guard', 'profile_contract',
                   'report_composition', 'invalid_role'}
        kind = ('timeout' if isinstance(failure, subprocess.TimeoutExpired) else
                'assertion' if isinstance(failure, AssertionError) else
                'os_error' if isinstance(failure, OSError) else 'other')
        print(json.dumps({'schema_version': 1, 'runtime_acceptance': False, 'passed': False,
                          'failure_stage': GATE_STAGE if GATE_STAGE in allowed else 'initialization',
                          'failure_kind': kind, 'owned_cleanup_confirmed': False}, sort_keys=True))
        raise SystemExit(1)

