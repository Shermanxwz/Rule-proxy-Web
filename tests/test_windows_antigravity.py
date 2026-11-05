"""Pure fixture tests: never launch the installed app or call Windows filters."""
import ast
import copy
import os
from pathlib import Path
import stat
import sys
import tempfile
from types import SimpleNamespace
import unittest
from unittest.mock import Mock, patch

from ruleproxy import windows_antigravity as adapter


class AntigravityTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.local = Path(self.temp.name)
        self.root = self.local / 'Programs' / 'antigravity'
        self.main = self.root / 'Antigravity.exe'
        self.helper = self.root / 'resources' / 'bin' / 'language_server.exe'
        self.helper.parent.mkdir(parents=True)
        self.main.write_bytes(b'fixture only')
        self.helper.write_bytes(b'fixture only')
        self.env = patch.dict(os.environ, LOCALAPPDATA=str(self.local))
        self.env.start()
        self.addCleanup(self.env.stop)

    def test_exact_pair_only(self):
        (self.root / 'unrelated.exe').write_bytes(b'fixture')
        self.assertTrue(adapter.is_antigravity(self.main))
        self.assertEqual(adapter.routing_paths(self.main), [str(self.main), str(self.helper)])

    def test_non_target(self):
        for value in (self.local / 'Antigravity.exe', self.helper, 'Antigravity.exe',
                      self.root / 'other.exe'):
            self.assertFalse(adapter.is_antigravity(value))
            self.assertEqual(adapter.routing_paths(value), [])

    def test_missing_helper_fails_closed(self):
        self.helper.unlink()
        with self.assertRaises(ValueError):
            adapter.routing_paths(self.main)

    def test_missing_main_fails_closed(self):
        self.main.unlink()
        self.assertTrue(adapter.is_antigravity(self.main))
        with self.assertRaises(ValueError):
            adapter.routing_paths(self.main)

    def test_case_insensitive_entry(self):
        upper = str(self.main).upper()
        self.assertTrue(adapter.is_antigravity(upper))
        self.assertEqual(adapter.routing_paths(upper), [str(self.main), str(self.helper)])

    def test_reparse_entry_still_recognized_then_rejected(self):
        original = Path.lstat
        def fake(path, *args, **kwargs):
            if path == self.main:
                return SimpleNamespace(st_mode=stat.S_IFREG, st_file_attributes=0x400)
            return original(path, *args, **kwargs)
        with patch.object(Path, 'lstat', fake):
            self.assertTrue(adapter.is_antigravity(self.main))
            with self.assertRaises(ValueError):
                adapter.routing_paths(self.main)

    def test_reparse_directory_rejected(self):
        original = Path.lstat
        def fake(path, *args, **kwargs):
            if path == self.helper.parent:
                return SimpleNamespace(st_mode=stat.S_IFDIR, st_file_attributes=0x400)
            return original(path, *args, **kwargs)
        with patch.object(Path, 'lstat', fake):
            with self.assertRaises(ValueError):
                adapter.routing_paths(self.main)

    def test_resolution_escape_rejected(self):
        original = Path.resolve
        def fake(path, *args, **kwargs):
            if path == self.helper:
                return self.local / 'outside.exe'
            return original(path, *args, **kwargs)
        with patch.object(Path, 'resolve', fake):
            with self.assertRaises(ValueError):
                adapter.routing_paths(self.main)

    def manager_fixture(self, related=()):
        # Compile the actual selected methods, avoiding application initialization,
        # credentials/config loading, optional dependencies and native side effects.
        source = Path(__file__).resolve().parents[1] / 'ruleproxy' / 'manager.py'
        tree = ast.parse(source.read_text(encoding='utf-8'))
        wanted = {'_selected_windows_paths', '_sync_windows_policy'}
        methods = [item for node in tree.body if isinstance(node, ast.ClassDef)
                   for item in node.body if isinstance(item, ast.FunctionDef) and item.name in wanted]
        self.assertEqual({item.name for item in methods}, wanted)
        namespace = {'__package__': 'ruleproxy', 'copy': copy, 'Path': Path,
                     'sys': SimpleNamespace(platform='win32')}
        exec(compile(ast.Module(body=methods, type_ignores=[]), str(source), 'exec'), namespace)
        cls = type('FixtureManager', (), {name: namespace[name] for name in wanted})
        manager = cls()
        manager.settings = {'apps': [{'id': 'fixture', 'enabled': True,
                            'path': str(self.main), 'related_paths': list(related)}],
                            'windows_app_guard': True}
        manager._bind_store_app = lambda app: None
        manager._windows_family_paths = {}
        manager.capture_mode = 'applications'
        manager.core = SimpleNamespace(pid=123, poll=lambda: None)
        manager.mixed_port = 12345
        manager.backend = Mock()
        manager.windows_backend = lambda: manager.backend
        return manager

    def test_manager_paths_related_and_guard_share_policy(self):
        related = str(self.root / 'explicit.exe')
        manager = self.manager_fixture([related, str(self.helper)])
        expected = [str(self.main), str(self.helper), related]
        self.assertEqual(manager._selected_windows_paths(), expected)
        manager._sync_windows_policy()
        manager.backend.apply.assert_called_once_with(expected, 12345, 123)
        manager.backend.app_guard_apply.assert_called_once_with(12345)
        self.assertEqual(manager._windows_paths, expected)

    def test_manager_missing_helper_no_apply(self):
        manager = self.manager_fixture()
        self.helper.unlink()
        with self.assertRaises(ValueError):
            manager._sync_windows_policy()
        manager.backend.apply.assert_not_called()
        manager.backend.app_guard_apply.assert_not_called()

    def test_manager_total_limit_retained(self):
        manager = self.manager_fixture(str(self.root / f'extra{i}.exe') for i in range(127))
        with self.assertRaises(ValueError):
            manager._selected_windows_paths()


if __name__ == '__main__':
    unittest.main()
