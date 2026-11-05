import hashlib
import json
import os
from pathlib import Path
import tempfile
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
