import json
import os
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

from ruleproxy import windows_gemini_preferences as p


class PreferenceLeaseTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.profile = Path(self.tmp.name) / 'Gemini'
        self.profile.mkdir()
        self.target = self.profile / 'Preferences'
        self.receipt = self.profile / '.ruleproxy-proxy-recovery.json'
        self.leases = []
        self.addCleanup(self.release_locks)

    def release_locks(self):
        for lease in self.leases:
            lease.lock.close()

    def acquire(self):
        lease = p.acquire(self.profile, self.receipt, 10809, lambda: None)
        self.leases.append(lease)
        return lease

    def save(self, value):
        self.target.write_text(json.dumps(value), encoding='utf8')

    def load(self):
        return json.loads(self.target.read_text())

    def test_missing(self):
        lease = self.acquire()
        self.assertEqual(self.load()['proxy'], p._proxy(10809))
        lease.close(); lease.close()
        self.assertEqual(self.load(), {})
        self.assertFalse(self.receipt.exists())

    def test_preserve_existing_and_new_keys(self):
        old = {'mode': 'system'}
        self.save({'proxy': old, 'original': 123})
        lease = self.acquire()
        value = self.load(); value['new'] = 'app-change'; self.save(value)
        lease.close()
        self.assertEqual(self.load(), {'proxy': old, 'original': 123, 'new': 'app-change'})

    def test_null_original(self):
        self.save({'proxy': None}); lease = self.acquire(); lease.close()
        self.assertEqual(self.load(), {'proxy': None})

    def test_conflict_retains_receipt(self):
        lease = self.acquire(); self.save({'proxy': {'mode': 'direct'}})
        with self.assertRaises(ValueError): lease.close()
        self.assertTrue(self.receipt.exists())
        self.assertEqual(self.load()['proxy']['mode'], 'direct')

    def test_idle_failure_no_mutation(self):
        with self.assertRaises(RuntimeError):
            p.acquire(self.profile, self.receipt, 10809, lambda: (_ for _ in ()).throw(RuntimeError()))
        self.assertFalse(self.receipt.exists()); self.assertFalse(self.target.exists())

    def test_close_idle_failure_preserves(self):
        lease = self.acquire()
        lease.check_idle = lambda: (_ for _ in ()).throw(RuntimeError())
        with self.assertRaises(RuntimeError): lease.close()
        self.assertTrue(self.receipt.exists())

    def test_duplicate(self):
        self.target.write_text('{"a":1,"a":2}')
        with self.assertRaises(ValueError): self.acquire()
        self.assertFalse(self.receipt.exists())

    def test_nonobject(self):
        self.target.write_text('[]')
        with self.assertRaises(ValueError): self.acquire()

    def test_invalid_json(self):
        self.target.write_text('{')
        with self.assertRaises(ValueError): self.acquire()

    def test_size_limit(self):
        self.target.write_bytes(b' ' * (p.LIMIT + 1))
        with self.assertRaises(ValueError): self.acquire()

    def test_ports(self):
        for value in (True, 0, 1024, 65536, '10809'):
            with self.subTest(value=value), self.assertRaises(ValueError):
                p.acquire(self.profile, self.receipt, value, lambda: None)

    def test_hardlink(self):
        source = Path(self.tmp.name) / 'other'; source.write_text('{}')
        os.link(source, self.target)
        with self.assertRaises(ValueError): self.acquire()
        self.assertEqual(source.read_text(), '{}')

    def test_directory_target(self):
        self.target.mkdir()
        with self.assertRaises(OSError): self.acquire()

    def test_lock_prevents_second_lease(self):
        lease = self.acquire()
        with self.assertRaises(OSError): self.acquire()
        lease.close()
        self.acquire().close()

    def test_failed_preference_write_recover(self):
        self.save({'keep': 1})
        real = p._atomic
        def fail(target, value, expected):
            if target == self.target: raise OSError('injected')
            return real(target, value, expected)
        with patch.object(p, '_atomic', side_effect=fail), self.assertRaises(OSError): self.acquire()
        self.assertTrue(self.receipt.exists())
        p.recover(self.profile, self.receipt)
        self.assertEqual(self.load(), {'keep': 1})
        self.assertFalse(self.receipt.exists())

    def test_failed_receipt_no_profile_change(self):
        self.save({'keep': 1})
        with patch.object(p, '_atomic', side_effect=OSError('injected')), self.assertRaises(OSError): self.acquire()
        self.assertEqual(self.load(), {'keep': 1})

    def test_crash_receipt_recovered_on_next_acquire(self):
        self.save({'keep': 2, 'proxy': {'mode': 'system'}})
        lease = self.acquire(); lease.lock.close()  # simulate kernel releasing lock on exit
        new = self.acquire(); new.close()
        self.assertEqual(self.load(), {'keep': 2, 'proxy': {'mode': 'system'}})

    def test_wrong_receipt_path(self):
        lease = self.acquire()
        saved = json.loads(self.receipt.read_text()); saved['path'] = 'elsewhere'
        self.receipt.write_text(json.dumps(saved))
        with self.assertRaises(ValueError): lease.close()
        self.assertTrue(self.receipt.exists())

    def test_same_original_proxy(self):
        self.save({'proxy': p._proxy(10809), 'keep': 1})
        lease = self.acquire(); lease.close()
        self.assertEqual(self.load(), {'proxy': p._proxy(10809), 'keep': 1})

    def test_compare_before_replace(self):
        self.save({'keep': 3})
        with self.assertRaises(ValueError): p._atomic(self.target, {}, b'wrong')
        self.assertEqual(self.load(), {'keep': 3})
        self.assertEqual(list(self.profile.glob('.ruleproxy-*')), [])

    def test_symlink(self):
        source = Path(self.tmp.name) / 'other'; source.write_text('{}')
        try: self.target.symlink_to(source)
        except OSError: self.skipTest('symlink privilege unavailable')
        with self.assertRaises(ValueError): self.acquire()


if __name__ == '__main__': unittest.main()
