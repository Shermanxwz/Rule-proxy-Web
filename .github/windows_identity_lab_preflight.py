"""Read-only, closed storage/KVM evidence for the disposable client lab.

Inspect four fixed existing locations only. Never enumerate directories,
create a VM, change permissions/mounts, or remove anything. Output contains
labels rather than host paths, device identifiers, usernames or environment.
"""
from __future__ import annotations
import argparse
import json
from itertools import combinations
import os
from pathlib import Path
import stat
import sys

MIN_FREE_BYTES = 55 * 1024**3
LABELS = ('workspace', 'tmp', 'runner_temp', 'mnt')


def error_code(exc):
    value = getattr(exc, 'errno', None)
    return value if type(value) is int and 0 <= value <= 65535 else None


def inspect_storage(path):
    result = {'exists': False, 'directory': False, 'writable': False,
              'total_bytes': None, 'free_bytes': None, 'minimum_met': False, 'error_errno': None}
    device = None
    if path is None:
        return result, device
    try:
        info = os.stat(path)
        result['exists'] = True
        result['directory'] = stat.S_ISDIR(info.st_mode)
        if not result['directory']: return result, device
        device = info.st_dev
        facts = os.statvfs(path)
        result['total_bytes'] = int(facts.f_blocks) * int(facts.f_frsize)
        result['free_bytes'] = int(facts.f_bavail) * int(facts.f_frsize)
        result['writable'] = os.access(path, os.W_OK | os.X_OK)
        result['minimum_met'] = result['free_bytes'] >= MIN_FREE_BYTES
    except OSError as exc:
        result['error_errno'] = error_code(exc)
    return result, device


def inspect_kvm():
    result = {'exists': False, 'opened_read_write': False,
              'api_version': None, 'api_supported': False, 'error_errno': None,
              'handle_closed': False}
    descriptor = None
    try:
        result['exists'] = os.path.exists('/dev/kvm')
        descriptor = os.open('/dev/kvm', os.O_RDWR | os.O_CLOEXEC)
        result['opened_read_write'] = True
        import fcntl
        # KVM_GET_API_VERSION is a read-only query, not KVM_CREATE_VM.
        version = fcntl.ioctl(descriptor, 0xAE00, 0)
        if type(version) is int and 0 <= version <= 65535:
            result['api_version'] = version
            result['api_supported'] = version == 12
    except OSError as exc:
        result['error_errno'] = error_code(exc)
    finally:
        if descriptor is not None:
            try: os.close(descriptor); result['handle_closed'] = True
            except OSError as exc: result['error_errno'] = error_code(exc)
    return result


def collect(*, storage_reader=inspect_storage, kvm_reader=inspect_kvm, runner_temp=None, workspace=None):
    candidates = {'workspace': workspace, 'tmp': '/tmp', 'runner_temp': runner_temp, 'mnt': '/mnt'}
    result = {'schema_version': 1, 'stage': 'windows-client-lab-read-only-preflight',
              'minimum_free_bytes': MIN_FREE_BYTES, 'storage': {}, 'same_filesystem': {},
              'read_only': True, 'vm_created': False, 'host_changes': False,
              'account_created': False, 'media_downloaded': False}
    devices = {}
    for label in LABELS:
        result['storage'][label], devices[label] = storage_reader(candidates[label])
    groups = {}
    for label in LABELS:
        device = devices[label]
        if device is not None and device not in groups: groups[device] = 'filesystem_' + str(len(groups) + 1)
        result['storage'][label]['filesystem_group'] = groups.get(device)
    for a, b in combinations(LABELS, 2):
        result['same_filesystem'][a + '__' + b] = (devices[a] == devices[b]
            if devices[a] is not None and devices[b] is not None else None)
    # Always observe KVM, even when every storage candidate is insufficient.
    result['kvm'] = kvm_reader()
    result['eligible_storage_labels'] = [label for label in LABELS
        if all(result['storage'][label][key] is True for key in ('directory','writable','minimum_met'))]
    result['existing_tmp_ready'] = ('tmp' in result['eligible_storage_labels'] and
        all(result['kvm'].get(key) is True for key in ('opened_read_write','api_supported','handle_closed')))
    result['alternate_storage_available'] = any(label != 'tmp' for label in result['eligible_storage_labels'])
    # This is a proposal, not a selection, mkdir, mount or VM authorization.
    result['proposed_storage_label'] = next((label for label in ('tmp', 'runner_temp', 'mnt', 'workspace') if label in result['eligible_storage_labels']), None)
    return result


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--output', type=Path, required=True)
    parser.add_argument('--require-existing-tmp', action='store_true')
    args = parser.parse_args(argv)
    if sys.platform != 'linux': parser.error('Linux hosted runner required')
    value = collect(runner_temp=os.environ.get('RUNNER_TEMP') or None, workspace=os.environ.get('GITHUB_WORKSPACE') or None)
    # Only the closed report is written. No candidate filesystem is modified.
    args.output.parent.mkdir(parents=True, exist_ok=True)
    with args.output.open('x', encoding='ascii') as stream:
        json.dump(value, stream, indent=2, sort_keys=True); stream.write('\n')
    return 0 if not args.require_existing_tmp or value['existing_tmp_ready'] else 1

if __name__ == '__main__': raise SystemExit(main())
