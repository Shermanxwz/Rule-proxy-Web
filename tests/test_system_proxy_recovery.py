"""Interrupted desktop writes and cross-account uninstall recovery; no real proxy changes."""
import json
import os
from pathlib import Path
import tempfile
from types import SimpleNamespace
import unittest
from unittest.mock import Mock, patch

from ruleproxy import system_proxy as proxy
from ruleproxy import windows_proxy_client, system_proxy_watchdog


SID = 'S-1-5-21-11-22-33-1001'


class Registry:
    HKEY_CURRENT_USER, HKEY_USERS, HKEY_LOCAL_MACHINE = 'admin-hkcu', 'hku', 'hklm'
    REG_SZ, REG_EXPAND_SZ, REG_DWORD, KEY_SET_VALUE = 1, 2, 4, 2

    def __init__(self):
        self.values = {}
        self.calls = []
        self.fail = lambda root, name, value: None

    def OpenKey(self, root, path, *args):
        self.calls.append(('open', root, path))
        return Key(self, root, path)

    def QueryValueEx(self, key, name):
        if key.root == self.HKEY_LOCAL_MACHINE and name == 'ProfileImagePath':
            return r'C:\Users\Owner', self.REG_SZ
        try:
            value, kind = self.values[(key.root, key.path)][name]
            return value, kind
        except KeyError:
            raise FileNotFoundError(name)

    def SetValueEx(self, key, name, reserved, kind, value):
        self.fail(key.root, name, value)
        self.calls.append(('set', key.root, key.path, name))
        self.values.setdefault((key.root, key.path), {})[name] = [value, kind]

    def DeleteValue(self, key, name):
        self.calls.append(('delete', key.root, key.path, name))
        try:
            del self.values[(key.root, key.path)][name]
        except KeyError:
            raise FileNotFoundError(name)

    def ExpandEnvironmentStrings(self, value):
        return value


class Key:
    def __init__(self, registry, root, path):
        self.registry, self.root, self.path = registry, root, path

    def __enter__(self):
        return self

    def __exit__(self, *args):
        pass


class SystemProxyRecoveryTests(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        self.directory = Path(self.temporary.name)
        self.registry = Registry()
        self.addCleanup(patch.stopall)
        patch.dict('sys.modules', {'winreg': self.registry}).start()
        patch.object(proxy.sys, 'platform', 'win32').start()
        patch.object(windows_proxy_client, 'current_user_sid', return_value='S-1-5-21-11-22-33-500').start()
        self.notify = Mock()
        self.notify.InternetSetOptionW.return_value = 1
        patch('ctypes.WinDLL', return_value=self.notify, create=True).start()
        self.previous = {'ProxyEnable': [0, 4], 'ProxyServer': ['old.example:8080', 1],
                         'ProxyOverride': None, 'AutoConfigURL': ['https://pac.invalid/settings', 1],
                         'AutoDetect': [1, 4]}
        self.registry.values[(Registry.HKEY_CURRENT_USER, proxy._WIN_KEY)] = {
            key: list(value) for key, value in self.previous.items() if value is not None}

    def test_failure_after_only_proxy_enable_rolls_back_before_losing_the_journal(self):
        failed = []
        def fail(root, name, value):
            if name == 'ProxyServer' and not failed:
                failed.append(name)
                raise OSError('simulated second registry write failure')
        self.registry.fail = fail
        with self.assertRaises(OSError):
            proxy.enable(self.directory, 18809)
        self.assertEqual(proxy._win_read(), self.previous)
        self.assertFalse((self.directory / proxy.BACKUP).exists())

    def test_failed_readback_reports_only_fixed_field_presence_and_kinds_then_restores(self):
        actual_read = proxy._win_read
        reads = []
        def read(*args):
            observed = actual_read(*args)
            reads.append(True)
            if len(reads) == 2:
                observed.update(ProxyServer=['credential-user:private-password@remote.invalid', 1],
                                AutoConfigURL=['https://private-pac.invalid/private-token', 1],
                                AutoDetect=['private-string', 1])
            return observed
        with patch.object(proxy, '_win_read', side_effect=read), self.assertRaises(proxy.SystemProxyError) as raised:
            proxy.enable(self.directory, 18809)
        message = str(raised.exception)
        for detail in ('ProxyServer(present:1->present:1)', 'AutoConfigURL(absent->present:1)',
                       'AutoDetect(present:4->present:1)'):
            self.assertIn(detail, message)
        for secret in ('credential-user', 'private-password', 'remote.invalid', 'private-pac', 'private-token',
                       'private-string', '127.0.0.1', '18809', 'old.example'):
            self.assertNotIn(secret, message)
        self.assertLess(len(message), 300)
        self.assertEqual(actual_read(), self.previous)
        self.assertFalse((self.directory / proxy.BACKUP).exists())

    def test_failed_partial_rollback_keeps_original_settings_for_a_later_retry(self):
        failures = []
        def fail(root, name, value):
            if not failures and name == 'ProxyServer':
                failures.append('apply')
                raise OSError('apply interrupted')
            if failures == ['apply'] and name == 'ProxyEnable' and value == 0:
                failures.append('restore')
                raise OSError('rollback temporarily denied')
        self.registry.fail = fail
        with self.assertRaises(proxy.SystemProxyError):
            proxy.enable(self.directory, 18809)
        path = self.directory / proxy.BACKUP
        self.assertEqual(json.loads(path.read_text())['previous'], self.previous)
        self.assertEqual(proxy._win_read()['ProxyEnable'], [1, 4])
        self.registry.fail = lambda *args: None
        self.assertTrue(proxy.restore(self.directory))
        self.assertEqual(proxy._win_read(), self.previous)
        self.assertFalse(path.exists())

    def test_partial_restore_can_resume_even_after_endpoint_has_already_changed_back(self):
        proxy.enable(self.directory, 18809)
        failed = []
        def fail(root, name, value):
            if name == 'AutoDetect' and not failed:
                failed.append(name)
                raise OSError('interrupted after restoring endpoint')
        self.registry.fail = fail
        with self.assertRaises(OSError):
            proxy.restore(self.directory)
        self.assertEqual(proxy._win_read()['ProxyServer'], self.previous['ProxyServer'])
        self.assertTrue((self.directory / proxy.BACKUP).exists())
        proxy.restore(self.directory)
        self.assertEqual(proxy._win_read(), self.previous)

    def test_wrong_kind_duplicate_and_oversized_journals_are_retained(self):
        valid = {'kind': 'wininet', 'port': 18809, 'previous': self.previous}
        for raw in ('{', json.dumps({**valid, 'kind': 'gnome'}),
                    json.dumps(valid)[:-1] + ',"port":18810}', ' ' * (proxy.MAX_JOURNAL + 1)):
            with self.subTest(raw=raw[:60]):
                path = self.directory / proxy.BACKUP
                path.write_text(raw)
                before = dict(self.registry.values[(Registry.HKEY_CURRENT_USER, proxy._WIN_KEY)])
                with self.assertRaises(proxy.SystemProxyError):
                    proxy.restore(self.directory)
                self.assertEqual(path.read_text(), raw)
                self.assertEqual(self.registry.values[(Registry.HKEY_CURRENT_USER, proxy._WIN_KEY)], before)

    def test_an_old_watchdog_cannot_restore_or_delete_a_new_session_on_the_same_port(self):
        proxy.enable(self.directory, 18809, watchdog_session='a' * 32)
        proxy.enable(self.directory, 18809, watchdog_session='b' * 32)
        path = self.directory / proxy.BACKUP
        journal = path.read_bytes()
        active = proxy._win_read()
        self.registry.calls.clear()
        self.assertFalse(proxy.restore(self.directory, expected_session='a' * 32))
        self.assertEqual(path.read_bytes(), journal)
        self.assertEqual(proxy._win_read(), active)
        self.assertFalse(any(item[0] in {'set', 'delete'} for item in self.registry.calls))
        self.assertTrue(proxy.restore(self.directory, expected_session='b' * 32))
        self.assertEqual(proxy._win_read(), self.previous)

    def test_cross_account_uninstaller_uses_only_real_owner_hku_and_fixed_values(self):
        owner_key = (Registry.HKEY_USERS, SID + '\\' + proxy._WIN_KEY)
        self.registry.values[owner_key] = {key: list(value) for key, value in proxy._win_ours(18809).items()
                                           if value is not None}
        admin_before = proxy._win_read()
        raw = json.dumps({'kind': 'wininet', 'port': 18809, 'previous': self.previous}).encode()
        self.registry.calls.clear()
        with patch.object(proxy, '_read_owner_journal', return_value=raw) as read:
            self.assertTrue(proxy.restore_windows_owner(SID))
        self.assertEqual(str(read.call_args.args[0]),
                         'C:\\Users\\Owner\\AppData\\Local\\RuleProxyWebSafe\\system-proxy.json')
        self.assertEqual(proxy._win_read(SID), self.previous)
        self.assertEqual(proxy._win_read(), admin_before)
        writes = [item for item in self.registry.calls if item[0] in {'set', 'delete'}]
        self.assertTrue(writes)
        self.assertTrue(all(item[1:3] == (Registry.HKEY_USERS, SID + '\\' + proxy._WIN_KEY)
                            and item[3] in proxy._WIN_VALUES for item in writes))
        self.notify.InternetSetOptionW.assert_not_called()

    def test_owner_recovery_rejects_sid_or_journal_chosen_registry_paths(self):
        with self.assertRaises(proxy.SystemProxyError):
            proxy.restore_windows_owner(SID + '\\OtherUser')
        malformed = {**self.previous, r'Software\OtherApplication': ['injected', 1]}
        raw = json.dumps({'kind': 'wininet', 'port': 18809, 'previous': malformed}).encode()
        with patch.object(proxy, '_read_owner_journal', return_value=raw), self.assertRaises(proxy.SystemProxyError):
            proxy.restore_windows_owner(SID)
        self.assertFalse(any(item[0] in {'set', 'delete'} for item in self.registry.calls))


@unittest.skipUnless(os.name == 'nt', 'Real Windows held-file identity API, no registry changes')
class NativeJournalReadTests(unittest.TestCase):
    def test_real_regular_journal_is_read_and_reparse_target_is_refused(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory).resolve()
            target = root / 'system-proxy.json'
            target.write_bytes(b'{"fixture":true}')
            self.assertEqual(proxy._read_owner_journal(target), b'{"fixture":true}')
            linked = root / 'linked.json'
            try:
                linked.symlink_to(target)
            except OSError as error:
                self.skipTest('This Windows token cannot create the reparse fixture: ' + str(error))
            with self.assertRaises(proxy.SystemProxyError):
                proxy._read_owner_journal(linked)


if __name__ == '__main__':
    unittest.main()
