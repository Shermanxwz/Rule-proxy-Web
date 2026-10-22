"""Pure C tree capacity/alias checks; no ACL/profile/process/network mutation."""
import importlib.util
from pathlib import Path
from types import SimpleNamespace
import tempfile
import unittest
from unittest import mock

ROOT = Path(__file__).resolve().parents[1]
spec = importlib.util.spec_from_file_location('c_tree_test', ROOT / '.github/windows_identity_model2_controller.py')
m = importlib.util.module_from_spec(spec)
spec.loader.exec_module(m)


class TreeTests(unittest.TestCase):
    def test_realistic_95_node_closure_exceeds_legacy_but_is_admitted_by_c(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            for index in range(94):
                (root / ('source-%03d' % index)).write_bytes(b'fixed source')
            with self.assertRaises(RuntimeError):
                m.helpers.owned_paths(root)
            self.assertEqual(set(m.owned_tree(root)), {root, *root.iterdir()})

    def test_capacity_counts_pending_nodes_and_accepts_exactly_512(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            for index in range(511):
                (root / ('item-%03d' % index)).touch()
            self.assertEqual(len(m.owned_tree(root)), 512)
            (root / 'one-too-many').touch()
            with self.assertRaisesRegex(ValueError, 'owned_tree_nodes'):
                m.owned_tree(root)

    def test_depth_and_total_file_bytes_are_independent_closed_bounds(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            leaf = root
            for _ in range(16):
                leaf = leaf / 'level'
                leaf.mkdir()
            self.assertEqual(len(m.owned_tree(root)), 17)
            (leaf / 'too-deep').touch()
            with self.assertRaisesRegex(ValueError, 'owned_tree_depth'):
                m.owned_tree(root)
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            (root / 'a').write_bytes(b'1234567')
            (root / 'b').write_bytes(b'12345')
            self.assertEqual(len(m.owned_tree(root, max_bytes=12)), 3)
            with self.assertRaisesRegex(ValueError, 'owned_tree_bytes'):
                m.owned_tree(root, max_bytes=11)

    def test_reparse_and_symlink_are_rejected_before_any_acl_intent_or_tool(self):
        for mode in ('reparse', 'symlink'):
            with self.subTest(mode=mode), tempfile.TemporaryDirectory() as directory:
                root = Path(directory)
                child = root / 'alias'
                child.touch()
                original = Path.lstat
                def lstat(path, *args, **kwargs):
                    actual = original(path, *args, **kwargs)
                    if path == child:
                        return SimpleNamespace(st_mode=0o120777 if mode == 'symlink' else actual.st_mode,
                            st_size=actual.st_size, st_file_attributes=0x400 if mode == 'reparse' else 0)
                    return actual
                controller = m.FirstController.__new__(m.FirstController)
                controller.root = root
                controller.acl_attempted = False
                calls = []
                controller.tool = lambda *args, **kwargs: calls.append(args)
                with mock.patch.object(Path, 'lstat', lstat), self.assertRaises(ValueError):
                    controller.grant('unused')
                self.assertFalse(controller.acl_attempted)
                self.assertEqual(calls, [])

    def test_grant_readback_uses_c_boundary_and_never_legacy_helper(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            inputs, front = root / 'inputs', root / 'front'
            inputs.mkdir()
            front.mkdir()
            for index in range(92):
                (inputs / ('source-%03d' % index)).touch()
            calls = []
            def read_acl(path, sid):
                return ([(0, 0x1200a9)] if path == root else [(3, 0x1200a9)] if path == inputs
                    else [(3, 0x1301bf)] if path == front else [(16, 0x1200a9)])
            controller = m.FirstController.__new__(m.FirstController)
            controller.root = root
            controller.acl_attempted = False
            controller.fixed_icacls = lambda: root / 'icacls-placeholder'
            controller.tool = lambda argv, name: calls.append((argv, name))
            controller.api = SimpleNamespace(acl_read=read_acl)
            controller.budget = SimpleNamespace(require_ms=lambda cutoff: 1, cutoff=lambda seconds: 1)
            with mock.patch.object(m.helpers, 'owned_paths', side_effect=AssertionError('legacy helper used')):
                controller.grant('fixed-private-test-sid')
            self.assertTrue(controller.acl_attempted)
            self.assertEqual([name for _, name in calls], ['acl-root', 'acl-inputs', 'acl-front'])

    def test_invalid_bounds_cannot_turn_check_into_unbounded_walk(self):
        with tempfile.TemporaryDirectory() as directory:
            for patch in ({'max_nodes': 513}, {'max_nodes': True}, {'max_depth': 17},
                          {'max_bytes': m.live.local.MAX_STAGE + 1}):
                with self.subTest(patch=patch), self.assertRaises(ValueError):
                    m.owned_tree(Path(directory), **patch)


if __name__ == '__main__':
    unittest.main()
