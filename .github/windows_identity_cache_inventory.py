"""READ-ONLY inventory of three source-proven hosted-image tool directories.

No file contents, symlink targets, user directories or arbitrary paths are read.
This is evidence for review, never permission to delete or proof of recovery.
"""
import argparse
import json
import os
from pathlib import Path
import re
import stat
import time

IMAGE_SOURCE = '7e7dc1bcc0ef464e5e315a2b4c33609590c6cffe'
SOURCE_BASE = 'https://github.com/actions/runner-images/blob/' + IMAGE_SOURCE + '/images/ubuntu/'
TARGETS = {
    'android_sdk': ('/usr/local/lib/android/sdk', 'scripts/build/install-android-sdk.sh'),
    'dotnet_sdk': ('/usr/share/dotnet', 'scripts/build/install-dotnetcore-sdk.sh'),
    'swift_toolchain': ('/usr/share/swift', 'scripts/build/install-swift.sh'),
}
MAX_ENTRIES = 500000


class InventoryStopped(Exception):
    pass


def mount_points():
    # Kernel metadata only. Never publish mount source, names or raw paths.
    with open('/proc/self/mountinfo', encoding='ascii') as stream:
        data = stream.read(1024 * 1024 + 1)
    if len(data) > 1024 * 1024: raise InventoryStopped('mount_metadata_bound')
    result = set()
    for line in data.splitlines():
        fields = line.split()
        if len(fields) < 6: raise InventoryStopped('mount_metadata_invalid')
        result.add(re.sub(r'\\([0-7]{3})', lambda m: chr(int(m[1], 8)), fields[4]))
    return result


def mount_id(descriptor):
    # Inspect only this owned descriptor's kernel mount identity; no names or
    # identifiers leave the process. This also rejects same-device bind mounts.
    with open('/proc/self/fdinfo/' + str(descriptor), encoding='ascii') as stream:
        data = stream.read(4097)
    values = re.findall(r'^mnt_id:\s*([0-9]+)$', data, flags=re.MULTILINE)
    if len(data) > 4096 or len(values) != 1: raise InventoryStopped('mount_identity_unavailable')
    return int(values[0])


def open_root(path):
    descriptor = os.open('/', os.O_RDONLY | os.O_DIRECTORY | os.O_CLOEXEC)
    try:
        root_mount = mount_id(descriptor)
        for part in Path(path).parts[1:]:
            info = os.stat(part, dir_fd=descriptor, follow_symlinks=False)
            if stat.S_ISLNK(info.st_mode): raise InventoryStopped('root_or_ancestor_symlink')
            if info.st_uid != 0 or info.st_gid != 0: raise InventoryStopped('unknown_ownership')
            child = os.open(part, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC, dir_fd=descriptor)
            try:
                current = os.fstat(child)
                if mount_id(child) != root_mount: raise InventoryStopped('mount_boundary')
                if (current.st_dev, current.st_ino) != (info.st_dev, info.st_ino): raise InventoryStopped('entry_changed')
            except BaseException:
                os.close(child); raise
            os.close(descriptor); descriptor = child
        return descriptor
    except BaseException:
        os.close(descriptor); raise


def inspect_target(path, mounts, deadline):
    result = {'status': 'blocked', 'complete': False, 'allocated_bytes': None,
              'logical_bytes': None, 'entries': 0, 'symlink_count': 0,
              'multiply_linked_file_count': 0, 'world_writable_entry_count': 0, 'ownership': 'unverified',
              'root_or_ancestor_symlink': False, 'nested_mount': False,
              'special_entries': False, 'linux_reparse_points': 'not_applicable',
              'stage0_dependency': False, 'removal_authorized': False,
              'recoverability_verified': False, 'atomic_snapshot': False}
    root = None
    seen = set()
    allocated = logical = 0
    try:
        if any(p == path or p.startswith(path + '/') for p in mounts):
            result['nested_mount'] = True; raise InventoryStopped('mount_boundary')
        root = open_root(path)
        base = os.fstat(root)
        root_mount = mount_id(root)
        result['ownership'] = 'root_uid0_gid0_only'

        def add(info):
            nonlocal allocated, logical
            if time.monotonic() >= deadline: raise InventoryStopped('time_bound')
            result['entries'] += 1
            if info.st_mode & stat.S_IWOTH: result['world_writable_entry_count'] += 1
            if result['entries'] > MAX_ENTRIES: raise InventoryStopped('entry_bound')
            if info.st_uid != 0 or info.st_gid != 0:
                result['ownership'] = 'unknown_nonroot_encountered'; raise InventoryStopped('unknown_ownership')
            if info.st_dev != base.st_dev:
                result['nested_mount'] = True; raise InventoryStopped('mount_boundary')
            if not (stat.S_ISREG(info.st_mode) or stat.S_ISDIR(info.st_mode) or stat.S_ISLNK(info.st_mode)):
                result['special_entries'] = True; raise InventoryStopped('special_entry')
            key = (info.st_dev, info.st_ino)
            if key in seen: return
            seen.add(key)
            allocated += info.st_blocks * 512; logical += info.st_size
            if stat.S_ISLNK(info.st_mode): result['symlink_count'] += 1
            if stat.S_ISREG(info.st_mode) and info.st_nlink > 1: result['multiply_linked_file_count'] += 1

        def walk(descriptor):
            before = os.fstat(descriptor)
            with os.scandir(descriptor) as entries:
                for entry in entries:
                    info = os.stat(entry.name, dir_fd=descriptor, follow_symlinks=False)
                    add(info)
                    if stat.S_ISDIR(info.st_mode):
                        child = os.open(entry.name, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC, dir_fd=descriptor)
                        try:
                            current = os.fstat(child)
                            if mount_id(child) != root_mount:
                                result['nested_mount'] = True; raise InventoryStopped('mount_boundary')
                            if (current.st_dev,current.st_ino) != (info.st_dev,info.st_ino): raise InventoryStopped('entry_changed')
                            walk(child)
                        finally: os.close(child)
            after = os.fstat(descriptor)
            if (before.st_mtime_ns,before.st_ctime_ns) != (after.st_mtime_ns,after.st_ctime_ns): raise InventoryStopped('directory_changed')

        add(base); walk(root)
        result.update(status='measured', complete=True, allocated_bytes=allocated, logical_bytes=logical)
    except InventoryStopped as exc:
        result['stop_reason'] = str(exc)
        if str(exc) == 'root_or_ancestor_symlink': result['root_or_ancestor_symlink'] = True
        if str(exc) == 'mount_boundary': result['nested_mount'] = True
        if str(exc) == 'unknown_ownership': result['ownership'] = 'unknown_nonroot_encountered'
    except RecursionError:
        result['stop_reason'] = 'depth_bound'
    except OSError as exc:
        result['stop_reason'] = 'filesystem_error'
        result['error_errno'] = exc.errno if type(exc.errno) is int and 0 <= exc.errno <= 65535 else None
    finally:
        if root is not None: os.close(root)
    return result


def collect():
    result = {'schema_version': 1, 'stage': 'hosted-runner-known-cache-read-only-inventory',
              'read_only': True, 'vm_created': False, 'removed_bytes': 0,
              'removal_authorized': False, 'image_definition_commit': IMAGE_SOURCE,
              'reviewed_image_release_tag': 'ubuntu24/20261012.334',
              'image_environment_provenance': {}, 'targets': {}}
    for key, pattern in (('ImageOS', r'ubuntu24'), ('ImageVersion', r'[0-9]{8}\.[0-9]+\.[0-9]+')):
        value = os.environ.get(key, '')
        result['image_environment_provenance'][key] = value if re.fullmatch(pattern, value) else 'unverified'
    result['reviewed_image_version_matches'] = (result['image_environment_provenance'] == {'ImageOS':'ubuntu24', 'ImageVersion':'20261012.334.1'})
    try: mounts = mount_points()
    except (OSError, InventoryStopped):
        result['status'] = 'mount_metadata_unavailable'; return result
    deadline = time.monotonic() + 180
    for label, (path, source) in TARGETS.items():
        item = inspect_target(path, mounts, deadline)
        item['source_definition'] = SOURCE_BASE + source
        item['source_defined_install_location'] = True
        # Definition establishes installation location, not this instance's
        # exact versions/bytes or its reconstructibility after hypothetical removal.
        result['targets'][label] = item
    result['status'] = 'observed'
    return result


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--output', type=Path, required=True)
    args = parser.parse_args()
    result = collect()
    args.output.parent.mkdir(parents=True, exist_ok=True)
    with args.output.open('x', encoding='ascii') as stream:
        json.dump(result, stream, sort_keys=True, indent=2); stream.write('\n')

if __name__ == '__main__': main()
