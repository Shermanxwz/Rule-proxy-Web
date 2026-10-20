"""Synthetic fixtures only. Never invoke recovery against any provider path."""
import contextlib
import importlib.util
import io
import json
import os
from pathlib import Path
import stat
import tempfile
import time
from types import SimpleNamespace
import unittest
from unittest.mock import Mock, mock_open, patch

ROOT = Path(__file__).resolve().parents[1]
SOURCE = ROOT / '.github/windows_identity_provider_cache_recovery.py'
SPEC = importlib.util.spec_from_file_location('provider_cache_candidate', SOURCE)
m = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(m)  # Definitions only, never main or any native helper.
RAW_STAT, RAW_FSTAT = os.stat, os.fstat


class SyntheticTreeTests(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory(prefix='provider-cache-test-')
        self.parent = Path(self.temporary.name)
        self.root = self.parent / 'provider'
        self.root.mkdir()
        self.outside = self.parent / 'outside-sensitive-file'
        self.outside.write_bytes(b'external target must survive unchanged')
        # Root ownership is a production requirement. Fixtures remain owned by
        # the current test user; normalize only observations, never chown/chmod.
        self.ancestor_keys = {
            (RAW_STAT(p).st_dev, RAW_STAT(p).st_ino)
            for p in (self.root.parent, *self.root.parent.parents)
        }
        self.transform = None
        self.context = contextlib.ExitStack()
        self.context.enter_context(patch.object(m, 'TARGETS', {'android_sdk': str(self.root)}))
        self.context.enter_context(patch.object(m.os, 'stat', side_effect=self.normal_stat))
        self.context.enter_context(patch.object(m.os, 'fstat', side_effect=self.normal_fstat))
        self.context.enter_context(patch.object(m, 'mount_points', return_value={'/'}))
        # /tmp may itself be a separate mount in the test container. Simulate
        # the reviewed single-filesystem layout; dedicated tests change mount
        # IDs to exercise same-device bind and file-mount rejection.
        self.context.enter_context(patch.object(m, 'mount_id', return_value=700))
        self.snapshots = []

    def tearDown(self):
        for tree in self.snapshots:
            tree.close()
        self.context.close()
        self.temporary.cleanup()

    def normalized(self, info):
        values = {key: getattr(info, key) for key in dir(info) if key.startswith('st_')}
        values.update(st_uid=0, st_gid=0, st_dev=123)
        if (info.st_dev, info.st_ino) in self.ancestor_keys:
            values['st_mode'] &= ~0o022  # Synthetic /tmp ancestor is not production.
        if self.transform is not None:
            values.update(self.transform(info) or {})
        return SimpleNamespace(**values)

    def normal_stat(self, *args, **kwargs):
        return self.normalized(RAW_STAT(*args, **kwargs))

    def normal_fstat(self, descriptor):
        return self.normalized(RAW_FSTAT(descriptor))

    def snapshot(self):
        tree = m.TreeSnapshot('android_sdk', time.monotonic() + 60)
        self.snapshots.append(tree)
        return tree.capture()

    def populate(self):
        (self.root / 'a').write_bytes(b'a' * 8192)
        (self.root / 'dir').mkdir()
        (self.root / 'dir' / 'b').write_bytes(b'b' * 4096)
        (self.root / 'external-link').symlink_to(self.outside)

    def assert_reason(self, reason, operation):
        with self.assertRaises(m.RecoveryStopped) as raised:
            operation()
        self.assertEqual(raised.exception.reason, reason)

    def test_snapshot_is_read_only_and_never_reads_symlink_target(self):
        self.populate()
        with patch.object(m.os, 'unlink') as unlink, patch.object(m.os, 'rmdir') as rmdir, \
                patch.object(m.os, 'readlink', side_effect=AssertionError('never read a link target')):
            tree = self.snapshot()
        self.assertEqual(len(tree.records), 5)
        self.assertEqual(tree.symlinks, 1)
        self.assertEqual(tree.removed, 0)
        unlink.assert_not_called()
        rmdir.assert_not_called()
        self.assertTrue(self.outside.exists())

    def test_private_remover_unlinks_internal_link_not_external_target(self):
        self.populate()
        tree = self.snapshot()
        with patch.object(m.os, 'readlink', side_effect=AssertionError('never follow a link')):
            self.assertFalse(tree.remove_until(lambda: False))
        self.assertFalse(self.root.exists())
        self.assertEqual(self.outside.read_bytes(), b'external target must survive unchanged')
        self.assertEqual(tree.removed, 5)
        self.assertTrue(tree.root_removed)

    def test_goal_met_before_removal_leaves_every_entry(self):
        self.populate()
        tree = self.snapshot()
        with patch.object(m.os, 'unlink') as unlink, patch.object(m.os, 'rmdir') as rmdir:
            self.assertTrue(tree.remove_until(lambda: True))
        unlink.assert_not_called()
        rmdir.assert_not_called()
        self.assertEqual(tree.removed, 0)

    def test_measured_goal_stops_mid_tree_without_claiming_full_recovery(self):
        (self.root / 'a').write_bytes(b'a')
        (self.root / 'b').write_bytes(b'b')
        tree = self.snapshot()
        self.assertTrue(tree.remove_until(lambda: not (self.root / 'a').exists()))
        self.assertEqual(tree.removed, 1)
        self.assertFalse(tree.root_removed)
        self.assertTrue((self.root / 'b').exists())

    def test_root_symlink_is_rejected_without_following(self):
        self.root.rmdir()
        self.root.symlink_to(self.parent, target_is_directory=True)
        self.assert_reason('root_or_ancestor_symlink', self.snapshot)
        self.assertTrue(self.outside.exists())

    def test_ancestor_symlink_is_rejected_without_following(self):
        alias = self.parent / 'alias'
        alias.symlink_to(self.root, target_is_directory=True)
        (self.root / 'nested').mkdir()
        with patch.object(m, 'TARGETS', {'android_sdk': str(alias / 'nested')}):
            self.assert_reason('root_or_ancestor_symlink', self.snapshot)

    def test_swapped_root_aborts_and_keeps_both_trees(self):
        self.populate()
        tree = self.snapshot()
        moved = self.parent / 'original-provider'
        self.root.rename(moved)
        self.root.mkdir()
        (self.root / 'replacement').write_bytes(b'keep')
        self.assert_reason('ancestor_changed', lambda: tree.remove_until(lambda: False))
        self.assertTrue((moved / 'a').exists())
        self.assertTrue((self.root / 'replacement').exists())
        self.assertEqual(tree.removed, 0)

    def test_swapped_ancestor_aborts(self):
        container = self.root / 'container'
        container.mkdir()
        target = container / 'provider'
        target.mkdir()
        (target / 'a').write_bytes(b'keep')
        with patch.object(m, 'TARGETS', {'android_sdk': str(target)}):
            tree = self.snapshot()
            moved = self.root / 'moved-container'
            container.rename(moved)
            container.mkdir()
            (container / 'provider').mkdir()
            self.assert_reason('ancestor_changed', lambda: tree.remove_until(lambda: False))
            self.assertTrue((moved / 'provider' / 'a').exists())
            self.assertEqual(tree.removed, 0)

    def test_entry_swap_immediately_before_last_check_is_rejected(self):
        victim = self.root / 'a'
        victim.write_bytes(b'original')
        tree = self.snapshot()
        saved = self.parent / 'saved-original'
        original_verify = tree._verify_chain
        count = 0
        def swap_after_check(chain):
            nonlocal count
            original_verify(chain)
            count += 1
            if count == 2:
                victim.rename(saved)
                victim.symlink_to(self.outside)
        with patch.object(tree, '_verify_chain', side_effect=swap_after_check):
            self.assert_reason('entry_changed',
                               lambda: tree._remove_entry(tree.root, ('a',), []))
        self.assertEqual(saved.read_bytes(), b'original')
        self.assertTrue(victim.is_symlink())
        self.assertEqual(self.outside.read_bytes(), b'external target must survive unchanged')
        self.assertEqual(tree.removed, 0)

    def test_entry_replaced_between_lstat_and_opath_open_is_rejected(self):
        victim = self.root / 'a'
        victim.write_bytes(b'original')
        tree = self.snapshot()
        saved = self.parent / 'saved-before-open'
        original_open = m._entry_open
        def replace_before_open(name, parent):
            victim.rename(saved)
            victim.symlink_to(self.outside)
            return original_open(name, parent)
        with patch.object(m, '_entry_open', side_effect=replace_before_open):
            self.assert_reason('entry_changed',
                               lambda: tree._remove_entry(tree.root, ('a',), []))
        self.assertEqual(saved.read_bytes(), b'original')
        self.assertTrue(victim.is_symlink())
        self.assertEqual(self.outside.read_bytes(), b'external target must survive unchanged')
        self.assertEqual(tree.removed, 0)

    def test_directory_contents_changed_since_snapshot_is_rejected(self):
        (self.root / 'a').write_bytes(b'original')
        tree = self.snapshot()
        (self.root / 'new-entry').write_bytes(b'never delete')
        self.assert_reason('entry_changed', lambda: tree.remove_until(lambda: False))
        self.assertEqual(tree.removed, 0)
        self.assertTrue((self.root / 'new-entry').exists())

    def test_mount_metadata_rejects_nested_mount_before_open(self):
        with patch.object(m, 'mount_points', return_value={str(self.root / 'nested')}), \
                patch.object(m, '_open_anchors') as opened:
            self.assert_reason('mount_boundary', self.snapshot)
            opened.assert_not_called()

    def test_same_device_bind_mount_detected_by_descriptor_mount_id(self):
        subdir = self.root / 'nested'
        subdir.mkdir()
        inode = RAW_STAT(subdir).st_ino
        original = m.mount_id
        def mount(descriptor):
            value = original(descriptor)
            return value + 999 if RAW_FSTAT(descriptor).st_ino == inode else value
        with patch.object(m, 'mount_id', side_effect=mount):
            self.assert_reason('mount_boundary', self.snapshot)
        self.assertTrue(subdir.exists())

    def test_same_device_file_mount_detected_without_reading_file(self):
        entry = self.root / 'a'
        entry.write_bytes(b'keep')
        inode = RAW_STAT(entry).st_ino
        original = m.mount_id
        with patch.object(m, 'mount_id', side_effect=lambda fd: (
                original(fd) + 999 if RAW_FSTAT(fd).st_ino == inode else original(fd))):
            self.assert_reason('mount_boundary', self.snapshot)

    def test_new_mount_on_entry_after_snapshot_is_rejected_before_unlink(self):
        entry = self.root / 'a'
        entry.write_bytes(b'keep')
        tree = self.snapshot()
        inode = RAW_STAT(entry).st_ino
        original = m.mount_id
        with patch.object(m, 'mount_id', side_effect=lambda fd: (
                original(fd) + 999 if RAW_FSTAT(fd).st_ino == inode else original(fd))):
            self.assert_reason('mount_boundary',
                               lambda: tree._remove_entry(tree.root, ('a',), []))
        self.assertTrue(entry.exists())
        self.assertEqual(tree.removed, 0)

    def test_regular_file_hardlink_to_outside_is_rejected(self):
        os.link(self.outside, self.root / 'hardlink')
        self.assert_reason('multiply_linked_file', self.snapshot)
        self.assertEqual(self.outside.read_bytes(), b'external target must survive unchanged')

    def test_unknown_ownership_is_rejected(self):
        entry = self.root / 'a'
        entry.write_bytes(b'keep')
        inode = RAW_STAT(entry).st_ino
        self.transform = lambda info: {'st_uid': 12345} if info.st_ino == inode else {}
        self.assert_reason('unknown_ownership', self.snapshot)
        self.assertTrue(entry.exists())

    def test_writable_file_is_rejected_without_changing_permissions(self):
        entry = self.root / 'a'
        entry.write_bytes(b'keep')
        inode = RAW_STAT(entry).st_ino
        self.transform = lambda info: {'st_mode': info.st_mode | stat.S_IWOTH} if info.st_ino == inode else {}
        self.assert_reason('writable_entry', self.snapshot)

    def test_fifo_is_rejected_without_opening_or_reading(self):
        os.mkfifo(self.root / 'fifo')
        self.assert_reason('special_entry', self.snapshot)

    def test_cleanup_failure_stops_without_retry_or_false_success(self):
        entry = self.root / 'a'
        entry.write_bytes(b'keep')
        tree = self.snapshot()
        with patch.object(m.os, 'unlink', side_effect=PermissionError(13, 'private-sensitive-path')) as unlink:
            with self.assertRaises(m.CleanupFailed) as raised:
                tree.remove_until(lambda: False)
        self.assertEqual(raised.exception.errno, 13)
        self.assertEqual(str(raised.exception), 'cleanup_failed')
        self.assertEqual(unlink.call_count, 1)
        self.assertEqual(tree.removed, 0)
        self.assertEqual(tree.attempted_removals, 1)
        self.assertTrue(tree.cleanup_outcome_uncertain)
        self.assertTrue(entry.exists())

    def test_bounds_stop_before_mutation(self):
        (self.root / 'a').write_bytes(b'keep')
        with patch.object(m, 'MAX_ENTRIES', 1):
            self.assert_reason('entry_bound', self.snapshot)
        with patch.object(m, 'MAX_DEPTH', 0):
            self.assert_reason('depth_bound', self.snapshot)
        tree = self.snapshot()
        tree.deadline = time.monotonic() - 1
        self.assert_reason('time_bound', lambda: tree.remove_until(lambda: False))
        self.assertEqual(tree.removed, 0)

    def test_collect_read_only_closed_projection_omits_names_paths_and_contents(self):
        self.populate()
        with patch.object(m.os, 'unlink') as unlink, patch.object(m.os, 'rmdir') as rmdir:
            report = m.collect()
        self.assertEqual(report['status'], 'snapshots_validated_read_only')
        self.assertTrue(report['read_only'])
        self.assertFalse(report['host_changes'])
        self.assertFalse(report['concurrent_privileged_mutation_safe'])
        self.assertEqual(report['removed_entries'], 0)
        text = json.dumps(report)
        for private in (str(self.parent), 'outside-sensitive-file', 'external-link', 'must survive unchanged'):
            self.assertNotIn(private, text)
        unlink.assert_not_called()
        rmdir.assert_not_called()

    def test_main_defaults_to_read_only_stdout_report_without_output_path(self):
        (self.root / 'a').write_bytes(b'keep')
        output = io.StringIO()
        with contextlib.redirect_stdout(output):
            self.assertEqual(m.main([]), 0)
        self.assertTrue(json.loads(output.getvalue())['read_only'])
        self.assertTrue((self.root / 'a').exists())


class ClosedGateTests(unittest.TestCase):
    def test_exact_fixed_allowlist_source_and_fixed_proposed_goal(self):
        self.assertEqual(m.TARGETS, {
            'android_sdk': '/usr/local/lib/android/sdk',
            'dotnet_sdk': '/usr/share/dotnet',
            'swift_toolchain': '/usr/share/swift',
        })
        self.assertEqual(m.REVIEWED_IMAGES, {
            '20261012.334.1': (
                'ubuntu24/20261012.334', '7e7dc1bcc0ef464e5e315a2b4c33609590c6cffe'),
            '20261018.339.1': (
                'ubuntu24/20261018.339', 'b4067e48bd9bd803e958bfe1503ea0a06a3a127f'),
        })
        self.assertIs(type(m.EXECUTION_ENABLED), bool)
        self.assertEqual(m.REVIEWED_FREE_TARGET_BYTES, 32 * 1024**3)

    def test_execution_request_is_blocked_before_any_filesystem_access(self):
        with patch.object(m, 'EXECUTION_ENABLED', False), \
                patch.object(m, '_directory_open') as opened, patch.object(m, 'TreeSnapshot') as snapshot:
            report = m.collect(execute=True, fresh_job_before_checkout=True)
        self.assertEqual(report['stop_reason'], 'execution_not_reviewed')
        self.assertEqual(report['removed_entries'], 0)
        opened.assert_not_called()
        snapshot.assert_not_called()

    def test_no_cli_arbitrary_root_or_threshold_escape_hatch(self):
        for args in (['--root', '/tmp/arbitrary'], ['--desired-free-gib', '1'], ['--output', '/tmp/x']):
            with contextlib.redirect_stderr(io.StringIO()), self.assertRaises(SystemExit):
                m.main(args)

    def test_closed_error_never_serializes_os_exception_path(self):
        with patch.object(m, '_directory_open', side_effect=OSError(5, 'secret path and filename')):
            report = m.collect()
        self.assertEqual(report['stop_reason'], 'filesystem_error')
        self.assertEqual(report['error_errno'], 5)
        self.assertNotIn('secret', json.dumps(report))

    def test_public_provenance_matches_each_exact_observed_reviewed_image(self):
        for version, (tag, commit) in m.REVIEWED_IMAGES.items():
            with self.subTest(version=version), \
                    patch.dict(m.os.environ, {'ImageOS': 'ubuntu24', 'ImageVersion': version}), \
                    patch.object(m, '_directory_open', side_effect=OSError(5, 'synthetic stop')):
                report = m.collect()
            self.assertTrue(report['reviewed_image_version_matches'])
            self.assertEqual(report['reviewed_image_version'], version)
            self.assertEqual(report['reviewed_image_release_tag'], tag)
            self.assertEqual(report['image_definition_commit'], commit)
            self.assertFalse(report['source_provenance_is_content_proof'])
            self.assertEqual(report['attempted_removals'], 0)

    def test_collect_validates_whole_set_before_any_private_remove_call(self):
        calls = []
        class FakeTree:
            def __init__(self, label, deadline):
                self.label = label
                self.records = {(): None}
                self.allocated = 999999999999
                self.symlinks = self.removed = 0
                self.attempted_removals = 0
                self.cleanup_outcome_uncertain = False
                self.root_removed = False
            def capture(self):
                calls.append('capture:' + self.label)
            def verify(self):
                calls.append('verify:' + self.label)
            def remove_until(self, goal):
                calls.append('remove:' + self.label)
            def close(self):
                calls.append('close:' + self.label)
        # This exercises orchestration with pure stubs, not a real deletion path.
        with patch.object(m, 'TreeSnapshot', FakeTree), patch.object(m, '_execution_gate'), \
                patch.object(m, '_free_bytes', return_value=1):
            report = m.collect(execute=True, fresh_job_before_checkout=True)
        last_verify = max(i for i, value in enumerate(calls) if value.startswith('verify:'))
        first_remove = min(i for i, value in enumerate(calls) if value.startswith('remove:'))
        self.assertLess(last_verify, first_remove)
        self.assertEqual(report['stop_reason'], 'goal_not_reached')
        self.assertFalse(report['goal_reached'])  # Allocated size is not recovery.

    def test_failed_later_snapshot_prevents_all_private_remove_calls(self):
        fake = Mock()
        fake.label = 'android_sdk'
        fake.records = {(): None}
        fake.allocated = 1
        fake.symlinks = fake.removed = 0
        fake.attempted_removals = 0
        fake.cleanup_outcome_uncertain = False
        fake.root_removed = False
        with patch.object(m, 'TreeSnapshot', side_effect=[fake, m.RecoveryStopped('unknown_ownership')]), \
                patch.object(m, '_execution_gate'), patch.object(m, '_free_bytes', return_value=1):
            report = m.collect(execute=True, fresh_job_before_checkout=True)
        fake.remove_until.assert_not_called()
        self.assertEqual(report['stop_reason'], 'unknown_ownership')
        self.assertFalse(report['host_changes'])

    def test_failed_cleanup_projection_explicitly_preserves_uncertain_outcome(self):
        fake = Mock()
        fake.label = 'android_sdk'
        fake.records = {(): None}
        fake.allocated = m.REVIEWED_FREE_TARGET_BYTES
        fake.symlinks = fake.removed = 0
        fake.attempted_removals = 1
        fake.cleanup_outcome_uncertain = True
        fake.root_removed = False
        fake.remove_until.side_effect = m.CleanupFailed(OSError(5, 'private path'))
        with patch.object(m, 'TARGETS', {'android_sdk': '/never-opened'}), \
                patch.object(m, 'TreeSnapshot', return_value=fake), \
                patch.object(m, '_execution_gate'), patch.object(m, '_free_bytes', return_value=1):
            report = m.collect(execute=True, fresh_job_before_checkout=True)
        self.assertEqual(report['stop_reason'], 'cleanup_failed')
        self.assertIsNone(report['host_changes'])
        self.assertTrue(report['cleanup_outcome_uncertain'])
        self.assertEqual(report['attempted_removals'], 1)
        self.assertEqual(report['removed_entries'], 0)
        self.assertNotIn('private path', json.dumps(report))

    def test_insufficient_capacity_upper_bound_blocks_before_any_removal(self):
        fake = Mock()
        fake.label = 'android_sdk'
        fake.records = {(): None}
        fake.allocated = m.GIB
        fake.symlinks = fake.removed = fake.attempted_removals = 0
        fake.cleanup_outcome_uncertain = fake.root_removed = False
        with patch.object(m, 'TARGETS', {'android_sdk': '/never-opened'}), \
                patch.object(m, 'TreeSnapshot', return_value=fake), \
                patch.object(m, '_execution_gate'), patch.object(m, '_free_bytes', return_value=13 * m.GIB):
            report = m.collect(execute=True, fresh_job_before_checkout=True)
        fake.remove_until.assert_not_called()
        self.assertEqual(report['stop_reason'], 'insufficient_capacity_upper_bound')
        self.assertFalse(report['capacity_upper_bound_sufficient'])
        self.assertFalse(report['host_changes'])
        self.assertEqual(report['removed_entries'], 0)

    def test_goal_already_met_is_revoked_when_final_measured_free_falls(self):
        goal = m.REVIEWED_FREE_TARGET_BYTES
        with patch.object(m, '_execution_gate'), patch.object(m, 'TreeSnapshot') as trees, \
                patch.object(m, '_free_bytes', side_effect=[goal, goal - 1]):
            report = m.collect(execute=True, fresh_job_before_checkout=True)
        trees.assert_not_called()
        self.assertEqual(report['status'], 'blocked')
        self.assertEqual(report['stop_reason'], 'goal_not_reached')
        self.assertFalse(report['goal_reached'])
        self.assertEqual(report['free_bytes_after'], goal - 1)

    def test_post_removal_goal_is_revoked_when_final_measured_free_falls(self):
        goal = m.REVIEWED_FREE_TARGET_BYTES
        fake = Mock()
        fake.label = 'android_sdk'
        fake.records = {(): None}
        fake.allocated = goal
        fake.symlinks = fake.removed = fake.attempted_removals = 0
        fake.cleanup_outcome_uncertain = fake.root_removed = False
        with patch.object(m, 'TARGETS', {'android_sdk': '/never-opened'}), \
                patch.object(m, 'TreeSnapshot', return_value=fake), \
                patch.object(m, '_execution_gate'), \
                patch.object(m, '_free_bytes', side_effect=[1, 1, 1, goal, goal - 1]):
            report = m.collect(execute=True, fresh_job_before_checkout=True)
        fake.remove_until.assert_called_once()
        self.assertTrue(report['capacity_upper_bound_sufficient'])
        self.assertEqual(report['status'], 'blocked')
        self.assertEqual(report['stop_reason'], 'goal_not_reached')
        self.assertFalse(report['goal_reached'])
        self.assertEqual(report['free_bytes_after'], goal - 1)

    def test_final_measurement_failure_cannot_report_success(self):
        goal = m.REVIEWED_FREE_TARGET_BYTES
        with patch.object(m, '_execution_gate'), \
                patch.object(m, '_free_bytes', side_effect=[goal, OSError(5, 'private detail')]):
            report = m.collect(execute=True, fresh_job_before_checkout=True)
        self.assertEqual(report['status'], 'blocked')
        self.assertEqual(report['stop_reason'], 'filesystem_error')
        self.assertFalse(report['goal_reached'])
        self.assertIsNone(report['free_bytes_after'])

    def test_repeated_import_has_no_filesystem_actions(self):
        spec = importlib.util.spec_from_file_location('reimport_recovery_candidate', SOURCE)
        module = importlib.util.module_from_spec(spec)
        with patch.object(os, 'unlink') as unlink, patch.object(os, 'rmdir') as rmdir, \
                patch.object(os, 'scandir') as scandir:
            spec.loader.exec_module(module)
        unlink.assert_not_called()
        rmdir.assert_not_called()
        scandir.assert_not_called()

    def test_mountinfo_parser_rejects_missing_or_malformed_kernel_metadata(self):
        for value in ('', 'bad\n', 'a b c d e f g h i j\n'):
            with patch('builtins.open', mock_open(read_data=value)), \
                    self.assertRaises(m.RecoveryStopped) as raised:
                m.mount_points()
            self.assertEqual(raised.exception.reason, 'mount_metadata_invalid')

    def test_mountinfo_parser_decodes_escapes_without_exposing_sources(self):
        value = '77 1 8:1 / /private\\040mount rw - ext4 private-source rw\n'
        with patch('builtins.open', mock_open(read_data=value)):
            self.assertEqual(m.mount_points(), {'/private mount'})

    def test_mountinfo_size_is_bounded(self):
        with patch('builtins.open', mock_open(read_data='x' * (1024 * 1024 + 1))), \
                self.assertRaises(m.RecoveryStopped) as raised:
            m.mount_points()
        self.assertEqual(raised.exception.reason, 'mount_metadata_bound')

    def test_descriptor_mount_id_is_required_unique_and_bounded(self):
        for value in ('', 'mnt_id: 3\nmnt_id: 4\n', 'mnt_id: private\n', 'x' * 4097):
            with patch('builtins.open', mock_open(read_data=value)), \
                    self.assertRaises(m.RecoveryStopped) as raised:
                m.mount_id(7)
            self.assertEqual(raised.exception.reason, 'mount_identity_unavailable')
        with patch('builtins.open', mock_open(read_data='pos:\t0\nmnt_id:\t123\n')):
            self.assertEqual(m.mount_id(7), 123)


class ContextGateTests(unittest.TestCase):
    """Read-only context checks only; never call collect with an enabled source."""
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory(prefix='provider-context-test-')
        self.environment = {
            'GITHUB_ACTIONS': 'true', 'RUNNER_ENVIRONMENT': 'github-hosted',
            'RUNNER_OS': 'Linux', 'RUNNER_ARCH': 'X64',
            'ImageOS': 'ubuntu24', 'ImageVersion': '20261018.339.1',
            'GITHUB_WORKSPACE': self.temporary.name,
        }
        self.context = contextlib.ExitStack()
        self.context.enter_context(patch.object(m, 'EXECUTION_ENABLED', True))
        self.context.enter_context(patch.object(m.os, 'geteuid', return_value=0))
        self.context.enter_context(patch.dict(m.os.environ, self.environment, clear=True))

    def tearDown(self):
        self.context.close()
        self.temporary.cleanup()

    def assert_reason(self, reason, fresh=True):
        with self.assertRaises(m.RecoveryStopped) as raised:
            m._execution_gate(fresh)
        self.assertEqual(raised.exception.reason, reason)

    def test_both_exact_empty_fresh_job_contexts_pass_read_only_gate(self):
        for version in m.REVIEWED_IMAGES:
            with self.subTest(version=version), patch.dict(m.os.environ, {'ImageVersion': version}):
                m._execution_gate(True)

    def test_missing_explicit_fresh_assertion_blocks(self):
        self.assert_reason('not_fresh_hosted_job', fresh=False)

    def test_hosted_job_requires_every_fixed_context_value(self):
        for key in ('GITHUB_ACTIONS', 'RUNNER_ENVIRONMENT', 'RUNNER_OS', 'RUNNER_ARCH'):
            with patch.dict(m.os.environ, {key: 'different'}):
                self.assert_reason('not_fresh_hosted_job')

    def test_image_provenance_requires_exact_os_and_version(self):
        for key in ('ImageOS', 'ImageVersion'):
            with patch.dict(m.os.environ, {key: 'different'}):
                self.assert_reason('image_not_reviewed')

    def test_unknown_image_blocks_execution_before_stat_open_or_deletion(self):
        candidates = (
            {'ImageVersion': '20261019.999.1'},
            {'ImageVersion': '20261012.334.2'},
            {'ImageVersion': '20261018.339.1 '},
            {'ImageVersion': '20261018.339'},
            {'ImageVersion': 'latest'},
            {'ImageVersion': ''},
            {'ImageOS': 'ubuntu22', 'ImageVersion': '20261012.334.1'},
        )
        for candidate in candidates:
            with self.subTest(candidate=candidate), patch.dict(m.os.environ, candidate), \
                    patch.object(m.os, 'stat') as inspected, \
                    patch.object(m, '_directory_open') as opened, \
                    patch.object(m, 'TreeSnapshot') as tree, \
                    patch.object(m.os, 'unlink') as unlink, patch.object(m.os, 'rmdir') as rmdir:
                report = m.collect(execute=True, fresh_job_before_checkout=True)
            self.assertEqual(report['stop_reason'], 'image_not_reviewed')
            self.assertFalse(report['reviewed_image_version_matches'])
            self.assertIsNone(report['reviewed_image_version'])
            self.assertIsNone(report['reviewed_image_release_tag'])
            self.assertIsNone(report['image_definition_commit'])
            self.assertEqual(report['attempted_removals'], 0)
            self.assertFalse(report['host_changes'])
            self.assertFalse(report['vm_created'])
            inspected.assert_not_called()
            opened.assert_not_called()
            tree.assert_not_called()
            unlink.assert_not_called()
            rmdir.assert_not_called()

    def test_populated_workspace_blocks_before_any_cleanup(self):
        (Path(self.temporary.name) / 'checkout-or-other-step').write_bytes(b'keep')
        self.assert_reason('workspace_not_empty')

    def test_missing_or_symlink_workspace_is_rejected(self):
        with patch.dict(m.os.environ, {'GITHUB_WORKSPACE': ''}):
            self.assert_reason('workspace_unavailable')
        with tempfile.TemporaryDirectory(prefix='provider-workspace-link-test-') as parent:
            link = Path(parent) / 'workspace'
            link.symlink_to(self.temporary.name, target_is_directory=True)
            with patch.dict(m.os.environ, {'GITHUB_WORKSPACE': str(link)}):
                self.assert_reason('workspace_unavailable')

    def test_privilege_required_without_requesting_escalation(self):
        with patch.object(m.os, 'geteuid', return_value=1000):
            self.assert_reason('root_privilege_required')

    def test_invalid_source_free_goal_is_rejected(self):
        for goal in (None, True, 1, 41 * m.GIB):
            with patch.object(m, 'REVIEWED_FREE_TARGET_BYTES', goal):
                self.assert_reason('free_target_not_reviewed')


if __name__ == '__main__':
    unittest.main()
