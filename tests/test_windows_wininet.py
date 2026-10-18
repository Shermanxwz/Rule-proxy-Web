"""Documented LAN flags ABI; fake writes never change desktop settings."""
import ctypes
import os
from pathlib import Path
import unittest
from unittest.mock import Mock, patch

from ruleproxy import windows_wininet as wininet


class FlagsTests(unittest.TestCase):
    def test_query_uses_ui_and_falls_back_only_when_the_call_fails(self):
        for ui_ok in (True, False):
            calls = []
            def query(handle, identifier, pointer, length):
                options = ctypes.cast(pointer, ctypes.POINTER(wininet.Options)).contents
                self.assertIsNone(handle)
                self.assertEqual(identifier, 75)
                self.assertIsNone(options.pszConnection)
                self.assertEqual(options.dwOptionCount, 1)
                option = options.pOptions.contents
                calls.append(option.dwOption)
                option.Value.dwValue = 9 if option.dwOption == 10 else 3
                return ui_ok or option.dwOption == 1
            with patch.object(wininet, '_api', return_value=Mock(InternetQueryOptionW=query)):
                self.assertEqual(wininet.query_flags(), 9 if ui_ok else 3)
            self.assertEqual(calls, [10] if ui_ok else [10, 1])

    def test_query_failure_is_not_a_direct_connection_default(self):
        with patch.object(wininet, '_api', return_value=Mock(InternetQueryOptionW=Mock(return_value=0))), \
                self.assertRaises(OSError):
            wininet.query_flags()

    def test_set_uses_flags_and_refreshes_only_after_success(self):
        calls = []
        def setter(handle, identifier, pointer, length):
            if identifier == 75:
                options = ctypes.cast(pointer, ctypes.POINTER(wininet.Options)).contents
                self.assertIsNone(options.pszConnection)
                self.assertEqual(options.pOptions.contents.dwOption, 1)
                self.assertEqual(options.pOptions.contents.Value.dwValue, 3)
            calls.append(identifier)
            return 1
        with patch.object(wininet, '_api', return_value=Mock(InternetSetOptionW=setter)):
            wininet.set_flags(3)
        self.assertEqual(calls, [75, 39, 37])
        for value in (True, -1, 2 ** 32, '3'):
            with self.subTest(value=value), self.assertRaises(ValueError):
                wininet.set_flags(value)

    def test_failed_setting_never_continues_as_success(self):
        api = Mock(InternetSetOptionW=Mock(return_value=0))
        with patch.object(wininet, '_api', return_value=api), self.assertRaises(OSError):
            wininet.set_flags(3)
        self.assertEqual(api.InternetSetOptionW.call_count, 1)

    def test_either_notification_failure_is_reported_after_the_owned_api_write(self):
        for failed in (39, 37):
            calls = []
            def setter(handle, identifier, pointer, length):
                calls.append(identifier)
                return identifier != failed
            with self.subTest(failed=failed), patch.object(wininet, '_api', return_value=Mock(InternetSetOptionW=setter)), \
                    self.assertRaises(OSError):
                wininet.set_flags(3)
            self.assertEqual(calls, [75, 39] if failed == 39 else [75, 39, 37])

    def test_disposable_native_check_compares_flags_before_enable_normal_stop_and_parent_kill(self):
        source = (Path(__file__).resolve().parents[1] / '.github/check_system_proxy_native.py').read_text()
        self.assertIn('before_flags = query_flags()', source)
        self.assertIn("report['manual_connection_flags_verified'] = query_flags() == MANUAL_FLAGS", source)
        self.assertIn("report['normal_connection_flags_restored'] = query_flags() == before_flags", source)
        self.assertIn('and query_flags() == before_flags', source)
        self.assertIn("report['connection_flags_restored'] = query_flags() == before_flags", source)

    @unittest.skipUnless(os.name == 'nt', 'native read-only WinINet query')
    def test_native_query_abi_returns_a_dword_without_modifying_the_desktop(self):
        flags = wininet.query_flags()
        self.assertIs(type(flags), int)
        self.assertTrue(0 <= flags <= 0xffffffff)


if __name__ == '__main__':
    unittest.main()
