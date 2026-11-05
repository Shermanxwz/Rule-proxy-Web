import hashlib
import json
import os
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch
from ruleproxy import windows_gemini_native_proxy as n
from ruleproxy.windows_gemini_preferences import acquire


class IdleWaitTests(unittest.TestCase):
    def test_already_idle_does_not_sleep(self):
        with patch.object(n,'require_idle') as idle,patch.object(n.time,'sleep') as sleep:
            n.wait_for_idle()
        idle.assert_called_once();sleep.assert_not_called()

    def test_exiting_descendants_are_retried(self):
        with patch.object(n,'require_idle',side_effect=[ValueError('active'),None]) as idle,patch.object(n.time,'sleep') as sleep:
            n.wait_for_idle()
        self.assertEqual(idle.call_count,2);sleep.assert_called_once_with(.1)

    def test_timeout_remains_failure(self):
        with patch.object(n,'require_idle',side_effect=ValueError('active')),patch.object(n.time,'monotonic',side_effect=[0,5]),patch.object(n.time,'sleep') as sleep:
            with self.assertRaises(ValueError):n.wait_for_idle()
        sleep.assert_not_called()

    def test_inventory_error_is_not_retried(self):
        with patch.object(n,'require_idle',side_effect=OSError('inventory')),patch.object(n.time,'sleep') as sleep:
            with self.assertRaises(OSError):n.wait_for_idle()
        sleep.assert_not_called()

    def lease(self,root):
        profile=Path(root);receipt=profile/'receipt.json'
        (profile/'Preferences').write_text('{"keep":123}')
        lease=acquire(profile,receipt,10809,lambda:None)
        self.addCleanup(lease.lock.close);lease.check_idle=n.wait_for_idle
        return lease,receipt

    def test_close_restores_after_descendants_exit(self):
        with tempfile.TemporaryDirectory() as root:
            lease,receipt=self.lease(root)
            try:
                with patch.object(n,'require_idle',side_effect=[ValueError('active'),None]),patch.object(n.time,'sleep'):
                    lease.close()
                self.assertTrue(lease.closed);self.assertFalse(receipt.exists())
                self.assertEqual(json.loads((Path(root)/'Preferences').read_text()),{'keep':123})
            finally:lease.lock.close()

    def test_timeout_retains_lease_receipt_and_proxy(self):
        with tempfile.TemporaryDirectory() as root:
            lease,receipt=self.lease(root)
            try:
                with patch.object(n,'require_idle',side_effect=ValueError('active')),patch.object(n.time,'monotonic',side_effect=[0,5]):
                    with self.assertRaises(ValueError):lease.close()
                self.assertFalse(lease.closed);self.assertTrue(receipt.exists());self.assertFalse(lease.lock.file.closed)
                self.assertIn('proxy',json.loads((Path(root)/'Preferences').read_text()))
            finally:lease.lock.close()

    def test_startup_still_fails_immediately(self):
        with tempfile.TemporaryDirectory() as root:
            root=Path(root);resources=root/'install/resources';resources.mkdir(parents=True)
            (resources/'app.asar').write_bytes(b'fixture')
            with patch.object(n,'is_gemini',return_value=True),patch.object(n,'VERIFIED_ASAR',hashlib.sha256(b'fixture').hexdigest()),patch.dict(os.environ,{'APPDATA':str(root/'roaming')}),patch.object(n,'require_idle',side_effect=ValueError('running')),patch.object(n.time,'sleep') as sleep:
                with self.assertRaises(ValueError):n.prepare([str(root/'install/Gemini.exe')],10809)
                sleep.assert_not_called()
            self.assertFalse((root/'roaming/Gemini/Preferences').exists())

if __name__=='__main__':unittest.main()
