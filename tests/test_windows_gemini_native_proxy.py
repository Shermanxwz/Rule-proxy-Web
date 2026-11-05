import hashlib
import json
import os
from pathlib import Path
import tempfile
from types import SimpleNamespace
import unittest
from unittest.mock import patch
from ruleproxy import windows_gemini_native_proxy as n


class NativeBindingTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory(); self.addCleanup(self.tmp.cleanup)
        self.root = Path(self.tmp.name)
        resources = self.root / 'install/resources'; resources.mkdir(parents=True)
        (resources / 'app.asar').write_bytes(b'tested-fixture')
        self.command = [str(self.root / 'install/Gemini.exe')]
        self.profile = self.root / 'roaming/Gemini'
        self.addCleanup(patch.stopall)
        patch.object(n, 'is_gemini', return_value=True).start()
        patch.object(n, 'VERIFIED_ASAR', hashlib.sha256(b'tested-fixture').hexdigest()).start()
        self.idle = patch.object(n, 'require_idle').start()
        patch.dict(os.environ, {'APPDATA': str(self.root / 'roaming')}).start()

    def test_native_profile_preserved(self):
        self.profile.mkdir(parents=True)
        (self.profile / 'Preferences').write_text('{"keep":123}')
        lease = n.prepare(self.command, 10809)
        self.addCleanup(lease.lock.close)
        self.assertEqual(self.command[-1], '--user-data-dir='+str(self.profile))
        lease.close()
        self.assertEqual(json.loads((self.profile/'Preferences').read_text()), {'keep':123})
        self.assertEqual(self.idle.call_count, 3)

    def test_non_gemini_untouched(self):
        with patch.object(n, 'is_gemini', return_value=False):
            self.assertIsNone(n.prepare(self.command,10809))
        self.assertFalse(self.profile.exists())

    def test_changed_build_no_profile_write(self):
        with patch.object(n,'VERIFIED_ASAR','changed'), self.assertRaises(ValueError):
            n.prepare(self.command,10809)
        self.assertFalse(self.profile.exists())

    def test_python310_hashes_empty_exact_and_multiple_blocks(self):
        # Deliberately expose no file_digest, as on Python 3.10. Real fixture
        # files exercise EOF, a full block and a multi-block trailing fragment.
        legacy_hashlib = SimpleNamespace(sha256=hashlib.sha256)
        for size in (0, 1, 256 * 1024, 2 * 256 * 1024 + 17):
            with self.subTest(size=size):
                body = (bytes(range(256)) * (size // 256 + 1))[:size]
                (self.root / 'install/resources/app.asar').write_bytes(body)
                command = self.command.copy()
                with patch.object(n, 'hashlib', legacy_hashlib), \
                        patch.object(n, 'VERIFIED_ASAR', hashlib.sha256(body).hexdigest()):
                    lease = n.prepare(command, 10809)
                    try:
                        self.assertEqual(command[-1], '--user-data-dir=' + str(self.profile))
                        self.assertIsNotNone(n.pending_receipt())
                        lease.close()
                        self.assertIsNone(n.pending_receipt())
                    finally:
                        lease.lock.close()

    def test_python310_changed_multiblock_build_before_profile_write(self):
        body = b'x' * (2 * 256 * 1024 + 17)
        (self.root / 'install/resources/app.asar').write_bytes(body)
        self.profile.mkdir(parents=True)
        preferences = self.profile / 'Preferences'
        original = b'{"keep":"existing-profile"}'
        preferences.write_bytes(original)
        command = self.command.copy()
        with patch.object(n, 'hashlib', SimpleNamespace(sha256=hashlib.sha256)), \
                patch.object(n, 'acquire') as acquire, self.assertRaisesRegex(ValueError, '版本已变化'):
            n.prepare(command, 10809)
        acquire.assert_not_called()
        self.idle.assert_not_called()
        self.assertEqual(command, self.command)
        self.assertEqual(preferences.read_bytes(), original)
        self.assertEqual(list(self.profile.iterdir()), [preferences])

    def test_custom_profile_rejected(self):
        for flag in ('--user-data-dir=other','--profile-directory=other','/USER-DATA-DIR=other'):
            with self.subTest(flag=flag), self.assertRaises(ValueError):
                n.prepare(self.command+[flag],10809)
        self.assertFalse(self.profile.exists())

    def test_relative_appdata_rejected(self):
        with patch.dict(os.environ,{'APPDATA':'relative'}), self.assertRaises(ValueError):
            n.prepare(self.command,10809)

    def test_no_pending_is_noop(self):
        n.recover_pending();self.idle.assert_not_called()
        self.assertFalse(self.profile.exists())

    def test_crash_recovery_independent_of_build(self):
        lease=n.prepare(self.command,10809);lease.lock.close()
        with patch.object(n,'VERIFIED_ASAR','changed'):
            n.recover_pending()
        self.assertIsNone(n.pending_receipt())
        self.assertNotIn('proxy',json.loads((self.profile/'Preferences').read_text()))

    def test_running_process_stops_mutation(self):
        self.idle.side_effect=ValueError('running')
        with self.assertRaises(ValueError): n.prepare(self.command,10809)
        self.assertFalse((self.profile/'Preferences').exists())

if __name__=='__main__': unittest.main()
