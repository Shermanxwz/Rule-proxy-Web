"""Narrow, fail-closed provider-cache recovery candidate (DISABLED FOR REVIEW).

Only the three fixed provider trees below are eligible. The default is read-only.
Execution must be enabled in the reviewed source, with a reviewed fixed free-space
goal, and explicitly requested in a fresh standard GitHub job before checkout or
any untrusted step. Image provenance and workflow assertions are not a proof that
the current files are provider content.

This is not an adversarial-concurrency sandbox: Linux unlinkat/rmdir have no
compare-and-delete-by-inode operation. Descriptors, no-follow opens, full snapshots,
and immediate binding/mount revalidation reject observed replacements, but cannot
eliminate the final syscall race with a concurrent privileged writer. Therefore
execution is forbidden in a reused job or alongside untrusted/privileged writers.
No chmod, mounts, broad cleanup, content reads, or symlink-target reads are used.
"""
from __future__ import annotations

import argparse
import json
import os
from pathlib import Path
import re
import stat
import sys
import time

IMAGE_SOURCE = 'b4067e48bd9bd803e958bfe1503ea0a06a3a127f'
PRIOR_IDENTICAL_INSTALL_SCRIPTS_SOURCE = '7e7dc1bcc0ef464e5e315a2b4c33609590c6cffe'
IMAGE_TAG = 'ubuntu24/20261018.339'
IMAGE_VERSION = '20261018.339.1'
TARGETS = {
    'android_sdk': '/usr/local/lib/android/sdk',
    'dotnet_sdk': '/usr/share/dotnet',
    'swift_toolchain': '/usr/share/swift',
}
# These are intentionally not command-line/environment overrides. The 32 GiB
# proposal still requires final resource review; enabling this source is a
# separately approved frozen action, never a self-granted permission.
EXECUTION_ENABLED = True
REVIEWED_FREE_TARGET_BYTES = 32 * 1024**3
MAX_ENTRIES = 500000
MAX_DEPTH = 128
MAX_SECONDS = 240
GIB = 1024**3
STOP_REASONS = frozenset({
    'execution_not_reviewed', 'free_target_not_reviewed', 'not_fresh_hosted_job',
    'workspace_not_empty', 'workspace_unavailable', 'image_not_reviewed',
    'root_privilege_required', 'linux_required', 'unknown_ownership',
    'writable_entry', 'root_or_ancestor_symlink', 'mount_boundary',
    'mount_metadata_invalid', 'mount_metadata_bound', 'mount_identity_unavailable',
    'entry_changed', 'ancestor_changed', 'directory_changed', 'special_entry',
    'multiply_linked_file', 'entry_bound', 'depth_bound', 'time_bound',
    'filesystem_error', 'cleanup_failed', 'goal_not_reached', 'invalid_target',
    'insufficient_capacity_upper_bound',
})


class RecoveryStopped(Exception):
    def __init__(self, reason):
        if reason not in STOP_REASONS:
            raise ValueError('unknown closed stop reason')
        self.reason = reason
        super().__init__(reason)


def _errno(exc):
    number = getattr(exc, 'errno', None)
    return number if type(number) is int and 0 <= number <= 65535 else None


def _budget(deadline):
    if time.monotonic() >= deadline:
        raise RecoveryStopped('time_bound')


def mount_points():
    """Kernel metadata only; names and sources never enter public results."""
    with open('/proc/self/mountinfo', encoding='ascii') as stream:
        data = stream.read(1024 * 1024 + 1)
    if len(data) > 1024 * 1024:
        raise RecoveryStopped('mount_metadata_bound')
    points = set()
    for line in data.splitlines():
        fields = line.split()
        if len(fields) < 10 or '-' not in fields[6:]:
            raise RecoveryStopped('mount_metadata_invalid')
        points.add(re.sub(r'\\([0-7]{3})', lambda m: chr(int(m[1], 8)), fields[4]))
    if not points:
        raise RecoveryStopped('mount_metadata_invalid')
    return points


def mount_id(descriptor):
    with open('/proc/self/fdinfo/' + str(descriptor), encoding='ascii') as stream:
        data = stream.read(4097)
    values = re.findall(r'^mnt_id:\s*([0-9]+)$', data, flags=re.MULTILINE)
    if len(data) > 4096 or len(values) != 1:
        raise RecoveryStopped('mount_identity_unavailable')
    return int(values[0])


def _identity(info):
    return (info.st_dev, info.st_ino, info.st_mode, info.st_uid, info.st_gid)


def _fingerprint(info):
    return _identity(info) + (
        info.st_nlink, info.st_size, info.st_blocks, info.st_mtime_ns, info.st_ctime_ns)


def _metadata(info):
    if info.st_uid != 0 or info.st_gid != 0:
        raise RecoveryStopped('unknown_ownership')
    if not (stat.S_ISREG(info.st_mode) or stat.S_ISDIR(info.st_mode)
            or stat.S_ISLNK(info.st_mode)):
        raise RecoveryStopped('special_entry')
    if stat.S_ISREG(info.st_mode) and info.st_nlink != 1:
        raise RecoveryStopped('multiply_linked_file')
    # Symlink modes conventionally contain all write bits, but are never followed.
    if not stat.S_ISLNK(info.st_mode) and info.st_mode & 0o022:
        raise RecoveryStopped('writable_entry')


def _directory_open(name, parent=None):
    return os.open(name, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC,
                   dir_fd=parent)


def _entry_open(name, parent):
    # O_PATH opens the link itself with O_NOFOLLOW, never its content or target.
    return os.open(name, os.O_PATH | os.O_NOFOLLOW | os.O_CLOEXEC, dir_fd=parent)


def _bound_entry(parent, name, expected, root_mount, root_device):
    """Return an owned O_PATH fd after checking a single no-follow binding."""
    before = os.stat(name, dir_fd=parent, follow_symlinks=False)
    _metadata(before)
    if _fingerprint(before) != expected:
        raise RecoveryStopped('entry_changed')
    descriptor = _entry_open(name, parent)
    try:
        current = os.fstat(descriptor)
        _metadata(current)
        if mount_id(descriptor) != root_mount or current.st_dev != root_device:
            raise RecoveryStopped('mount_boundary')
        if _fingerprint(current) != expected:
            raise RecoveryStopped('entry_changed')
        after = os.stat(name, dir_fd=parent, follow_symlinks=False)
        if _fingerprint(after) != expected:
            raise RecoveryStopped('entry_changed')
        return descriptor
    except BaseException:
        os.close(descriptor)
        raise


def _open_anchors(path, expected=None):
    """Open from / component-by-component, checking every ancestor binding."""
    if not path.startswith('/') or str(Path(path)) != path:
        raise RecoveryStopped('invalid_target')
    descriptor = _directory_open('/')
    observations = []
    try:
        root = os.fstat(descriptor)
        _metadata(root)
        root_mount = mount_id(descriptor)
        observations.append((_identity(root), root_mount))
        for part in Path(path).parts[1:]:
            before = os.stat(part, dir_fd=descriptor, follow_symlinks=False)
            if stat.S_ISLNK(before.st_mode):
                raise RecoveryStopped('root_or_ancestor_symlink')
            _metadata(before)
            child = _directory_open(part, descriptor)
            try:
                current = os.fstat(child)
                _metadata(current)
                current_mount = mount_id(child)
                if current_mount != root_mount or current.st_dev != root.st_dev:
                    raise RecoveryStopped('mount_boundary')
                if _identity(current) != _identity(before):
                    raise RecoveryStopped('ancestor_changed')
                after = os.stat(part, dir_fd=descriptor, follow_symlinks=False)
                if _identity(after) != _identity(current):
                    raise RecoveryStopped('ancestor_changed')
                observations.append((_identity(current), current_mount))
            except BaseException:
                os.close(child)
                raise
            os.close(descriptor)
            descriptor = child
        if expected is not None and observations != expected:
            raise RecoveryStopped('ancestor_changed')
        return descriptor, observations
    except BaseException:
        os.close(descriptor)
        raise


class TreeSnapshot:
    """Internal snapshot. Its path/name/device/inode data must not be published."""
    def __init__(self, label, deadline):
        if label not in TARGETS:
            raise RecoveryStopped('invalid_target')
        self.label = label
        self.path = TARGETS[label]
        self.deadline = deadline
        self.root = None
        self.anchors = None
        self.records = {}
        self.children = {}
        self.allocated = 0
        self.symlinks = 0
        self.removed = 0
        self.attempted_removals = 0
        self.cleanup_outcome_uncertain = False
        self.root_removed = False

    def close(self):
        if self.root is not None:
            os.close(self.root)
            self.root = None

    def _mount_list_check(self):
        if any(p == self.path or p.startswith(self.path + '/') for p in mount_points()):
            raise RecoveryStopped('mount_boundary')

    def _add(self, relative, info):
        _budget(self.deadline)
        _metadata(info)
        if info.st_dev != self.device:
            raise RecoveryStopped('mount_boundary')
        if len(relative) > MAX_DEPTH:
            raise RecoveryStopped('depth_bound')
        if len(self.records) >= MAX_ENTRIES:
            raise RecoveryStopped('entry_bound')
        self.records[relative] = _fingerprint(info)
        self.allocated += info.st_blocks * 512
        if stat.S_ISLNK(info.st_mode):
            self.symlinks += 1

    def _scan(self, descriptor, relative):
        before = os.fstat(descriptor)
        names = []
        with os.scandir(descriptor) as entries:
            for entry in entries:
                _budget(self.deadline)
                name = entry.name
                # scandir excludes these; explicitly preserve the dir_fd contract.
                if name in ('', '.', '..') or '/' in name or '\0' in name:
                    raise RecoveryStopped('invalid_target')
                child_relative = relative + (name,)
                info = os.stat(name, dir_fd=descriptor, follow_symlinks=False)
                self._add(child_relative, info)
                pinned = _bound_entry(descriptor, name, self.records[child_relative],
                                      self.mount, self.device)
                try:
                    if stat.S_ISDIR(info.st_mode):
                        child = _directory_open(name, descriptor)
                        try:
                            if (_fingerprint(os.fstat(child)) != self.records[child_relative]
                                    or mount_id(child) != self.mount):
                                raise RecoveryStopped('entry_changed')
                            self._scan(child, child_relative)
                        finally:
                            os.close(child)
                finally:
                    os.close(pinned)
                names.append(name)
        if _fingerprint(os.fstat(descriptor)) != _fingerprint(before):
            raise RecoveryStopped('directory_changed')
        self.children[relative] = tuple(sorted(names))

    def capture(self):
        self._mount_list_check()
        self.root, self.anchors = _open_anchors(self.path)
        info = os.fstat(self.root)
        self.device = info.st_dev
        self.mount = mount_id(self.root)
        self._add((), info)
        self._scan(self.root, ())
        self.verify()
        return self

    def _verify_root(self):
        _budget(self.deadline)
        current, _ = _open_anchors(self.path, self.anchors)
        try:
            if _fingerprint(os.fstat(current)) != self.records[()]:
                raise RecoveryStopped('entry_changed')
            if _fingerprint(os.fstat(self.root)) != self.records[()]:
                raise RecoveryStopped('entry_changed')
        finally:
            os.close(current)

    def _verify_directory(self, descriptor, relative):
        _budget(self.deadline)
        current = os.fstat(descriptor)
        _metadata(current)
        if mount_id(descriptor) != self.mount or current.st_dev != self.device:
            raise RecoveryStopped('mount_boundary')
        if _fingerprint(current) != self.records[relative]:
            raise RecoveryStopped('directory_changed')

    def _verify_walk(self, descriptor, relative):
        self._verify_directory(descriptor, relative)
        names = []
        with os.scandir(descriptor) as entries:
            for entry in entries:
                _budget(self.deadline)
                names.append(entry.name)
                if len(names) > len(self.children[relative]):
                    raise RecoveryStopped('directory_changed')
        names = tuple(sorted(names))
        if names != self.children[relative]:
            raise RecoveryStopped('directory_changed')
        for name in names:
            child_relative = relative + (name,)
            pinned = _bound_entry(descriptor, name, self.records[child_relative],
                                  self.mount, self.device)
            try:
                if stat.S_ISDIR(self.records[child_relative][2]):
                    child = _directory_open(name, descriptor)
                    try:
                        self._verify_walk(child, child_relative)
                    finally:
                        os.close(child)
            finally:
                os.close(pinned)
        self._verify_directory(descriptor, relative)

    def verify(self):
        self._mount_list_check()
        self._verify_root()
        self._verify_walk(self.root, ())
        self._verify_root()

    def _verify_chain(self, chain):
        """Reopen and compare every current binding, including same-device mounts."""
        self._verify_root()
        for parent, relative, child in chain:
            self._verify_directory(parent, relative[:-1])
            pinned = _bound_entry(parent, relative[-1], self.records[relative],
                                  self.mount, self.device)
            try:
                if _fingerprint(os.fstat(child)) != self.records[relative]:
                    raise RecoveryStopped('entry_changed')
                if mount_id(child) != self.mount:
                    raise RecoveryStopped('mount_boundary')
            finally:
                os.close(pinned)

    def _remove_entry(self, parent, relative, chain, directory=False):
        self._verify_chain(chain)
        self._verify_directory(parent, relative[:-1])
        pinned = _bound_entry(parent, relative[-1], self.records[relative],
                              self.mount, self.device)
        try:
            # Last checks immediately precede unlinkat/rmdir. See module-level
            # limitation: these syscalls cannot atomically compare the inode.
            self._verify_chain(chain)
            if _fingerprint(os.stat(relative[-1], dir_fd=parent, follow_symlinks=False)) != self.records[relative]:
                raise RecoveryStopped('entry_changed')
            self.attempted_removals += 1
            try:
                if directory:
                    os.rmdir(relative[-1], dir_fd=parent)
                else:
                    os.unlink(relative[-1], dir_fd=parent)
            except OSError as exc:
                self.cleanup_outcome_uncertain = True
                raise CleanupFailed(exc) from None
            self.removed += 1
            self.records[relative[:-1]] = _fingerprint(os.fstat(parent))
            self.children[relative[:-1]] = tuple(
                name for name in self.children[relative[:-1]] if name != relative[-1])
        finally:
            os.close(pinned)

    def _remove_walk(self, descriptor, relative, chain, goal_reached):
        for name in tuple(self.children[relative]):
            if goal_reached():
                return True
            child_relative = relative + (name,)
            self._verify_chain(chain)
            self._verify_directory(descriptor, relative)
            pinned = _bound_entry(descriptor, name, self.records[child_relative],
                                  self.mount, self.device)
            is_directory = stat.S_ISDIR(self.records[child_relative][2])
            try:
                if is_directory:
                    child = _directory_open(name, descriptor)
                    try:
                        if self._remove_walk(child, child_relative,
                                             chain + [(descriptor, child_relative, child)],
                                             goal_reached):
                            return True
                    finally:
                        os.close(child)
            finally:
                os.close(pinned)
            if goal_reached():
                return True
            self._remove_entry(descriptor, child_relative, chain, is_directory)
        return goal_reached()

    def remove_until(self, goal_reached):
        """Private deletion primitive; caller must pass all execution gates first."""
        self.verify()
        if self._remove_walk(self.root, (), [], goal_reached):
            return True
        if goal_reached():
            return True
        self._verify_root()
        # Remove only the now-empty exact allowlisted root, relative to its
        # separately revalidated parent. Never resolve a symlink path.
        parent_path = str(Path(self.path).parent)
        parent, _ = _open_anchors(parent_path, self.anchors[:-1])
        try:
            self._verify_root()
            pinned = _bound_entry(parent, Path(self.path).name, self.records[()],
                                  self.mount, self.device)
            try:
                self.attempted_removals += 1
                try:
                    os.rmdir(Path(self.path).name, dir_fd=parent)
                except OSError as exc:
                    self.cleanup_outcome_uncertain = True
                    raise CleanupFailed(exc) from None
                self.removed += 1
                self.root_removed = True
            finally:
                os.close(pinned)
        finally:
            os.close(parent)
        return goal_reached()


class CleanupFailed(RecoveryStopped):
    def __init__(self, cause):
        super().__init__('cleanup_failed')
        self.errno = _errno(cause)


def _free_bytes(descriptor):
    value = os.fstatvfs(descriptor)
    return int(value.f_bavail) * int(value.f_frsize)


def _execution_gate(fresh_job_before_checkout):
    if not EXECUTION_ENABLED:
        raise RecoveryStopped('execution_not_reviewed')
    # No user-controlled broad target. A separately reviewed frozen source
    # selects one exact threshold; bounds protect an accidental source edit.
    if (type(REVIEWED_FREE_TARGET_BYTES) is not int
            or not 24 * GIB <= REVIEWED_FREE_TARGET_BYTES <= 40 * GIB):
        raise RecoveryStopped('free_target_not_reviewed')
    if sys.platform != 'linux' or not hasattr(os, 'O_PATH'):
        raise RecoveryStopped('linux_required')
    if os.geteuid() != 0:
        raise RecoveryStopped('root_privilege_required')
    expected = {'GITHUB_ACTIONS': 'true', 'RUNNER_ENVIRONMENT': 'github-hosted',
                'RUNNER_OS': 'Linux', 'RUNNER_ARCH': 'X64'}
    if not fresh_job_before_checkout or any(os.environ.get(k) != v for k, v in expected.items()):
        raise RecoveryStopped('not_fresh_hosted_job')
    if os.environ.get('ImageOS') != 'ubuntu24' or os.environ.get('ImageVersion') != IMAGE_VERSION:
        raise RecoveryStopped('image_not_reviewed')
    workspace = os.environ.get('GITHUB_WORKSPACE')
    if not workspace or not os.path.isabs(workspace):
        raise RecoveryStopped('workspace_unavailable')
    descriptor = None
    try:
        # This examines directory-entry presence only, not contents or names.
        # The workflow must additionally prove this is its first run step.
        descriptor = _directory_open(workspace)
        with os.scandir(descriptor) as entries:
            if next(entries, None) is not None:
                raise RecoveryStopped('workspace_not_empty')
    except OSError:
        raise RecoveryStopped('workspace_unavailable') from None
    finally:
        if descriptor is not None:
            os.close(descriptor)


def collect(*, execute=False, fresh_job_before_checkout=False):
    """Closed public projection. Never return paths, entry names, or exceptions."""
    report = {
        'schema_version': 1, 'stage': 'reviewed-provider-cache-recovery',
        'status': 'blocked', 'read_only': not execute, 'execution_requested': bool(execute),
        'execution_enabled_in_source': EXECUTION_ENABLED,
        'image_definition_commit': IMAGE_SOURCE, 'reviewed_image_release_tag': IMAGE_TAG,
        'prior_identical_install_scripts_commit': PRIOR_IDENTICAL_INSTALL_SCRIPTS_SOURCE,
        'reviewed_image_version_matches': (
            os.environ.get('ImageOS') == 'ubuntu24' and os.environ.get('ImageVersion') == IMAGE_VERSION),
        'source_provenance_is_content_proof': False,
        'atomic_snapshot': False, 'concurrent_privileged_mutation_safe': False,
        'minimum_free_bytes': REVIEWED_FREE_TARGET_BYTES,
        'free_bytes_before': None, 'free_bytes_after': None,
        'free_bytes_after_snapshot': None, 'capacity_upper_bound_sufficient': None,
        'goal_reached': False, 'removed_entries': 0, 'host_changes': False,
        'attempted_removals': 0, 'cleanup_outcome_uncertain': False,
        'vm_created': False, 'targets': {},
    }
    trees = []
    filesystem = None
    try:
        if execute:
            _execution_gate(fresh_job_before_checkout)
        if sys.platform != 'linux' or not hasattr(os, 'O_PATH'):
            raise RecoveryStopped('linux_required')
        deadline = time.monotonic() + MAX_SECONDS
        # Measure the root filesystem, and require every eligible target and all
        # ancestors to share its dev AND kernel mount ID.
        filesystem = _directory_open('/')
        report['free_bytes_before'] = _free_bytes(filesystem)
        if (execute and report['free_bytes_before'] >= REVIEWED_FREE_TARGET_BYTES):
            report.update(status='goal_already_met', goal_reached=True)
        else:
            # Complete ALL selected snapshots before the first possible deletion.
            for label in TARGETS:
                tree = TreeSnapshot(label, deadline)
                trees.append(tree)
                tree.capture()
                report['targets'][label] = {
                    'snapshot_complete': True, 'entries': len(tree.records),
                    'allocated_bytes_upper_bound': tree.allocated,
                    'symlink_count': tree.symlinks, 'removed_entries': 0,
                    'root_removed': False,
                }
            # A second whole-set check catches changes while later trees scanned.
            for tree in trees:
                tree.verify()
            report['free_bytes_after_snapshot'] = _free_bytes(filesystem)
            report['capacity_upper_bound_sufficient'] = (
                report['free_bytes_after_snapshot'] + sum(tree.allocated for tree in trees)
                >= REVIEWED_FREE_TARGET_BYTES)
            if execute:
                # This is a necessary upper-bound test, not a guarantee of
                # reclaim: open handles, allocation changes, and other consumers
                # can reduce actual recovery. Do not delete if even this fails.
                if not report['capacity_upper_bound_sufficient']:
                    raise RecoveryStopped('insufficient_capacity_upper_bound')
                def goal_reached():
                    _budget(deadline)
                    return _free_bytes(filesystem) >= REVIEWED_FREE_TARGET_BYTES
                for tree in trees:
                    if goal_reached():
                        break
                    tree.remove_until(goal_reached)
                report['goal_reached'] = goal_reached()
                if not report['goal_reached']:
                    raise RecoveryStopped('goal_not_reached')
                report['status'] = 'goal_met'
            else:
                report['status'] = 'snapshots_validated_read_only'
    except RecoveryStopped as exc:
        report['stop_reason'] = exc.reason
        if isinstance(exc, CleanupFailed):
            report['error_errno'] = exc.errno
    except OSError as exc:
        report['stop_reason'] = 'filesystem_error'
        report['error_errno'] = _errno(exc)
    except RecursionError:
        report['stop_reason'] = 'depth_bound'
    finally:
        for tree in trees:
            report['removed_entries'] += tree.removed
            report['attempted_removals'] += tree.attempted_removals
            report['cleanup_outcome_uncertain'] |= tree.cleanup_outcome_uncertain
            if tree.label in report['targets']:
                report['targets'][tree.label].update(
                    removed_entries=tree.removed, root_removed=tree.root_removed)
            tree.close()
        report['host_changes'] = (True if report['removed_entries'] > 0 else
                                  None if report['cleanup_outcome_uncertain'] else False)
        if filesystem is not None:
            try:
                report['free_bytes_after'] = _free_bytes(filesystem)
                if (report['status'] in ('goal_met', 'goal_already_met')
                        and report['free_bytes_after'] < REVIEWED_FREE_TARGET_BYTES):
                    report['status'] = 'blocked'
                    report['stop_reason'] = 'goal_not_reached'
                    report['goal_reached'] = False
            except OSError as exc:
                report['status'] = 'blocked'
                report['goal_reached'] = False
                report['stop_reason'] = 'filesystem_error'
                report['error_errno'] = _errno(exc)
            finally:
                os.close(filesystem)
    return report


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--execute-reviewed-recovery', action='store_true')
    parser.add_argument('--fresh-job-before-checkout', action='store_true')
    args = parser.parse_args(argv)
    # Stdout is the only output destination. The reviewed workflow captures it;
    # the helper never creates report directories or follows output symlinks.
    result = collect(execute=args.execute_reviewed_recovery,
                     fresh_job_before_checkout=args.fresh_job_before_checkout)
    print(json.dumps(result, sort_keys=True, separators=(',', ':')))
    return 0 if result['status'] != 'blocked' else 1


if __name__ == '__main__':
    raise SystemExit(main())
