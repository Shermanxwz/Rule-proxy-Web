"""Explicit Windows compile-gate source-token control, not isolation acceptance.

Runs only the hash-pinned IdentityOnly actor's 'actor' role. No token creation,
network, pipes, account changes, ACL changes or sandbox executor are involved.
Raw native identity stays in one owned temporary report and is always removed.
"""
from __future__ import annotations
import argparse
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import re
import secrets
import stat
import subprocess
import tempfile

ROOT = Path(__file__).resolve().parents[1]
MAX_REPORT = 128 * 1024


def load_proof():
    spec = importlib.util.spec_from_file_location('actor_projection_control_proof', ROOT / '.github/windows_identity_proof.py')
    proof = importlib.util.module_from_spec(spec); spec.loader.exec_module(proof)
    return proof


def windows_available():
    return os.name == 'nt'


def regular_bounded(path, minimum, maximum):
    value = path.lstat()
    if (not stat.S_ISREG(value.st_mode) or value.st_nlink != 1 or
            getattr(value, 'st_file_attributes', 0) & 0x400 or
            not minimum <= value.st_size <= maximum):
        raise ValueError('bounded non-reparse regular file required')


def evaluate(proof, actor, nonce, pid, exit_code):
    if not isinstance(actor, dict):
        raise ValueError('actor object required')
    report = {'actor': actor, 'nonce': nonce, 'executor_exit_code': exit_code, 'timed_out': False}
    checks = proof.stage0_checks(report)
    facts = proof.native_identity_facts(actor, checks['native_identity'])
    # Native values are consumed only here, never returned or logged.
    fresh = checks['fresh_actor'] is True and type(actor.get('pid')) is int and actor['pid'] > 0 and actor['pid'] == pid
    normal = checks['normal_exit'] is True
    queries = actor.get('queriesSucceeded') is True and actor.get('errors') == []
    source = (actor.get('tokenIsAppContainer') is False and 'tokenAppContainerSid' in actor
              and actor['tokenAppContainerSid'] is None)
    schema = type(actor.get('schemaVersion')) is int and actor['schemaVersion'] == 1 and actor.get('mode') == 'actor'
    complete = all(facts[name + '_present'] and (name == 'sid' or facts[name + '_typed'])
                   for name, _, _ in proof.NATIVE_IDENTITY_FIELDS)
    rejected = checks['native_identity'] is False and facts['predicate_conjunction'] is False
    if set(facts) != set(proof.NATIVE_IDENTITY_FACT_KEYS) | {'predicate_conjunction'} or any(type(v) is not bool for v in facts.values()):
        raise ValueError('closed boolean projection required')
    return {'control_passed': all((fresh, normal, queries, source, schema, rejected, complete)),
            'fresh_report': fresh, 'normal_exit': normal, 'queries_succeeded': queries,
            'schema_and_mode_valid': schema, 'complete_typed_report': complete,
            'source_token_observed': source, 'native_identity_rejected': rejected,
            'native_identity': facts}


def run_control(actor_path, expected_sha256):
    result = {'control_passed': False, 'runtime_acceptance': False,
              'actor_hash_verified': False, 'actor_started': False,
              'process_exited': False, 'raw_report_removed': False, 'work_removed': False}
    process = None; work = None; report_path = None
    try:
        if not windows_available() or not re.fullmatch(r'[0-9a-f]{64}', expected_sha256):
            raise ValueError('explicit Windows hash-pinned control required')
        actor_path = Path(actor_path).absolute()
        regular_bounded(actor_path, 512, 8 * 1024 * 1024)
        if actor_path.suffix.lower() != '.exe' or hashlib.sha256(actor_path.read_bytes()).hexdigest() != expected_sha256:
            raise ValueError('actor hash mismatch')
        result['actor_hash_verified'] = True
        proof = load_proof()
        work = Path(tempfile.mkdtemp(prefix='ruleproxy-actor-control-'))
        report_path = work / 'actor.json'
        if report_path.exists(): raise ValueError('fresh report required')
        nonce = secrets.token_hex(16)
        process = subprocess.Popen([str(actor_path), 'actor', nonce, str(report_path)],
            cwd=str(work), stdin=subprocess.DEVNULL, stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL, close_fds=True)
        result['actor_started'] = True
        exit_code = process.wait(timeout=10)
        regular_bounded(report_path, 2, MAX_REPORT)
        with report_path.open('rb') as handle:
            raw = handle.read(MAX_REPORT + 1)
        if len(raw) > MAX_REPORT: raise ValueError('report bound')
        actor = json.loads(raw)
        result.update(evaluate(proof, actor, nonce, process.pid, exit_code))
    except Exception:
        # Never print raw exceptions, actor identity, nonce, PID, SID or paths.
        pass
    finally:
        if process is not None:
            try:
                if process.poll() is None: process.kill()
                process.wait(timeout=5)
                result['process_exited'] = process.poll() is not None
            except Exception:
                pass
        else:
            result['process_exited'] = True
        if report_path is not None and result['process_exited']:
            try:
                report_path.unlink(missing_ok=True)
                result['raw_report_removed'] = not report_path.exists()
            except Exception:
                pass
        elif report_path is None:
            result['raw_report_removed'] = True
        if work is not None and result['process_exited']:
            try:
                work.rmdir()
                result['work_removed'] = not work.exists()
            except Exception:
                pass
        elif work is None:
            result['work_removed'] = True
        result['control_passed'] = (result['control_passed'] and all(result[k] for k in
            ('process_exited', 'raw_report_removed', 'work_removed')))
    return result


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--run-source-token-control', action='store_true', required=True)
    parser.add_argument('--actor', type=Path, required=True)
    parser.add_argument('--actor-sha256', required=True)
    args = parser.parse_args()
    result = run_control(args.actor, args.actor_sha256)
    print(json.dumps(result, sort_keys=True, separators=(',', ':')))
    return 0 if result['control_passed'] else 1


if __name__ == '__main__':
    raise SystemExit(main())
