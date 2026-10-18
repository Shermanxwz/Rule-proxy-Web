"""Held identities and real independent helpers; no desktop settings changed."""
import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import time
import unittest
from unittest import mock

from ruleproxy import system_proxy_watchdog as watchdog

ROOT = Path(__file__).resolve().parents[1]
FAKE_MONITOR = '''import sys,json
from pathlib import Path
sys.path.insert(0,sys.argv[1])
from ruleproxy import system_proxy_watchdog as w
directory=Path(sys.argv[2])
def restore(path,session):
 with w.transaction_lock(path):
  f=path/'fake.json';data=json.loads(f.read_text())
  if data['session']==session:
   data['value']='original';f.write_text(json.dumps(data));(path/'recovered').write_text(session)
 return True
raise SystemExit(w._watch(directory,int(sys.argv[3]),int(sys.argv[4]),sys.argv[5],sys.argv[6],sys.argv[7],restore=restore))
'''


def child():
    return subprocess.Popen([sys.executable, '-I', '-S', '-c', 'import time;time.sleep(30)'],
                            stdin=subprocess.DEVNULL, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
                            **watchdog._options())


class WatchdogTests(unittest.TestCase):
    def test_binary_protocol_accepts_only_exact_lf_or_windows_crlf_with_matching_nonce(self):
        for prefix in (b'READY ', b'ARMED '):
            expected = prefix + b'a' * 32 + b'\n'
            for ending in (b'\n', b'\r\n'):
                with self.subTest(prefix=prefix, ending=ending):
                    process = mock.Mock()
                    process.stdout.readline.return_value = prefix + b'a' * 32 + ending
                    watchdog._line(process, expected)
            for invalid in (prefix + b'b' * 32 + b'\r\n', prefix + b'a' * 32 + b' \r\n',
                            prefix + b'a' * 32 + b'\r\r\n', b' ' + expected, expected + b'extra', b''):
                with self.subTest(prefix=prefix, invalid=invalid), self.assertRaises(OSError):
                    process = mock.Mock()
                    process.stdout.readline.return_value = invalid
                    watchdog._line(process, expected)

    def core(self):
        process = child()
        def cleanup():
            if process.poll() is None:
                process.kill()
            process.wait(timeout=3)
        self.addCleanup(cleanup)
        return process

    def test_identity_is_held_and_a_wrong_creation_stamp_is_refused(self):
        core = self.core()
        identity = watchdog.Identity(core.pid)
        self.addCleanup(identity.close)
        with self.assertRaises(OSError):
            watchdog.Identity(core.pid, identity.stamp + '9')
        self.assertFalse(identity.dead())
        core.kill()
        core.wait(timeout=3)
        self.assertTrue(identity.dead())

    def test_environment_keeps_desktop_context_but_drops_all_proxy_and_ci_credentials(self):
        with mock.patch.dict(os.environ, {'DBUS_SESSION_BUS_ADDRESS': 'desktop-address',
                'XDG_RUNTIME_DIR': '/run/user/fixture', 'HTTP_PROXY': 'secret', 'https_proxy': 'secret',
                'ACTIONS_ID_TOKEN_REQUEST_TOKEN': 'secret', 'GITHUB_TOKEN': 'secret', 'PYTHONPATH': 'secret'}, clear=True):
            env = watchdog._environment()
        self.assertEqual(env, {'DBUS_SESSION_BUS_ADDRESS': 'desktop-address', 'XDG_RUNTIME_DIR': '/run/user/fixture'})

    def test_cross_process_transaction_lock_has_a_bounded_timeout(self):
        with tempfile.TemporaryDirectory() as directory:
            code = ('import sys;sys.path.insert(0,sys.argv[1]);'
                    'from ruleproxy.system_proxy_watchdog import transaction_lock;'
                    'from pathlib import Path;'
                    'with_lock=transaction_lock(Path(sys.argv[2]),timeout=.15);'
                    'with_lock.__enter__();print("locked");with_lock.__exit__(None,None,None)')
            with watchdog.transaction_lock(directory):
                blocked = subprocess.run([sys.executable, '-I', '-S', '-c', code, str(ROOT), directory],
                                         capture_output=True, timeout=3)
                self.assertNotEqual(blocked.returncode, 0)
            free = subprocess.run([sys.executable, '-I', '-S', '-c', code, str(ROOT), directory],
                                  capture_output=True, timeout=3)
            self.assertEqual(free.returncode, 0, free.stderr.decode())
            self.assertEqual(free.stdout.strip(), b'locked')

    def spawn_fake_monitor(self, directory, core, nonce):
        parent, identity = watchdog.Identity(os.getpid()), watchdog.Identity(core.pid)
        try:
            process = subprocess.Popen([sys.executable, '-I', '-S', '-c', FAKE_MONITOR, str(ROOT), str(directory),
                                        str(os.getpid()), str(core.pid), parent.stamp, identity.stamp, nonce],
                                       stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.DEVNULL,
                                       env=watchdog._environment(), **watchdog._options())
            watchdog._line(process, ('READY ' + nonce + '\n').encode())
            monitor = watchdog.Watchdog(process, nonce)
            self.addCleanup(monitor.close)
            return monitor
        finally:
            parent.close()
            identity.close()

    def test_core_death_before_arm_waits_for_transaction_then_restores(self):
        core = self.core()
        nonce = 'a' * 32
        with tempfile.TemporaryDirectory() as d:
            directory = Path(d)
            monitor = self.spawn_fake_monitor(directory, core, nonce)
            core.kill();core.wait(timeout=3)
            time.sleep(.2)
            self.assertIsNone(monitor.process.poll())
            self.assertFalse((directory / 'recovered').exists())
            (directory / 'fake.json').write_text(json.dumps({'session': nonce, 'value': 'proxy'}))
            with self.assertRaises(OSError):
                monitor.arm()
            monitor.process.wait(timeout=3)
            self.assertEqual(json.loads((directory / 'fake.json').read_text())['value'], 'original')

    def test_late_old_monitor_does_not_restore_a_new_session_even_on_same_endpoint(self):
        core = self.core()
        nonce = 'a' * 32
        with tempfile.TemporaryDirectory() as d:
            directory = Path(d)
            (directory / 'fake.json').write_text(json.dumps({'session': nonce, 'value': 'proxy'}))
            monitor = self.spawn_fake_monitor(directory, core, nonce)
            monitor.arm()
            with watchdog.transaction_lock(directory):
                (directory / 'fake.json').write_text(json.dumps({'session': 'b' * 32, 'value': 'proxy'}))
            core.kill();core.wait(timeout=3)
            monitor.process.wait(timeout=3)
            self.assertEqual(json.loads((directory / 'fake.json').read_text())['session'], 'b' * 32)
            self.assertEqual(json.loads((directory / 'fake.json').read_text())['value'], 'proxy')
            self.assertFalse((directory / 'recovered').exists())

    def test_helper_survives_real_parent_kill_and_restores_fake_backend(self):
        core = self.core()
        with tempfile.TemporaryDirectory() as d:
            directory = Path(d)
            (directory / 'fake.json').write_text(json.dumps({'session': 'a' * 32, 'value': 'proxy'}))
            parent_code = '''import sys,os,subprocess,time
sys.path.insert(0,sys.argv[1])
from ruleproxy import system_proxy_watchdog as w
p,c=w.Identity(os.getpid()),w.Identity(int(sys.argv[3]))
m=subprocess.Popen([sys.executable,'-I','-S','-c',sys.argv[4],sys.argv[1],sys.argv[2],str(os.getpid()),
 sys.argv[3],p.stamp,c.stamp,'a'*32],stdin=subprocess.PIPE,stdout=subprocess.PIPE,stderr=subprocess.DEVNULL,
 env=w._environment(),**w._options())
w._line(m,('READY '+'a'*32+'\\n').encode());m.stdin.write(b'ARM\\n');m.stdin.flush()
w._line(m,('ARMED '+'a'*32+'\\n').encode());print('PARENT_READY',flush=True);print(m.pid,flush=True)
time.sleep(30)
'''
            parent = subprocess.Popen([sys.executable, '-I', '-S', '-c', parent_code, str(ROOT), d,
                                       str(core.pid), FAKE_MONITOR], stdout=subprocess.PIPE,
                                      stderr=subprocess.DEVNULL, **watchdog._options())
            identity = None
            try:
                watchdog._line(parent, b'PARENT_READY\n')
                monitor_pid = int(parent.stdout.readline(32))
                identity = watchdog.Identity(monitor_pid)
                parent.kill();parent.wait(timeout=3)
                deadline = time.monotonic() + 4
                while not identity.dead() and time.monotonic() < deadline:
                    time.sleep(.05)
                self.assertTrue(identity.dead())
                self.assertEqual(json.loads((directory / 'fake.json').read_text())['value'], 'original')
                self.assertEqual((directory / 'recovered').read_text(), 'a' * 32)
                self.assertIsNone(core.poll(), 'Restoration never kills an unrelated/live owned core')
            finally:
                if parent.poll() is None:
                    parent.kill()
                parent.wait(timeout=3)
                parent.stdout.close()
                if identity is not None:
                    identity.close()

    def test_restore_failure_retries_are_finite_and_keep_the_original_journal(self):
        with tempfile.TemporaryDirectory() as d:
            path = Path(d) / 'system-proxy.json'
            path.write_text('original journal')
            worker = mock.Mock()
            worker.wait.return_value = 1
            with mock.patch.object(watchdog.subprocess, 'Popen', return_value=worker) as spawn, \
                    mock.patch.object(watchdog.time, 'sleep'):
                self.assertFalse(watchdog._restore_bounded(Path(d), 'a' * 32))
            self.assertEqual(spawn.call_count, 3)
            self.assertEqual(path.read_text(), 'original journal')
            status = json.loads((Path(d) / watchdog.STATUS).read_text())
            self.assertEqual((status['attempts'], status['restored']), (3, False))
            self.assertEqual(status['session'], 'a' * 32)

    def test_restore_worker_spawn_failure_is_bounded_and_recorded(self):
        with tempfile.TemporaryDirectory() as d, \
                mock.patch.object(watchdog.subprocess, 'Popen', side_effect=OSError('synthetic')) as spawn, \
                mock.patch.object(watchdog.time, 'sleep'):
            self.assertFalse(watchdog._restore_bounded(Path(d), 'a' * 32))
            self.assertEqual(spawn.call_count, 3)
            status = json.loads((Path(d) / watchdog.STATUS).read_text())
            self.assertEqual(status['error'], 'restore_failed_journal_retained')
            self.assertNotIn('synthetic', json.dumps(status))

    def test_real_start_arm_close_with_no_journal_leaves_desktop_untouched(self):
        core = self.core()
        with tempfile.TemporaryDirectory() as d:
            monitor = watchdog.start(Path(d), core.pid)
            try:
                self.assertEqual(len(monitor.nonce), 32)
                monitor.arm()
                monitor.close()
                self.assertEqual(monitor.process.wait(timeout=8), 0)
                status = json.loads((Path(d) / watchdog.STATUS).read_text())
                self.assertIs(status['restored'], True)
                self.assertEqual(status['session'], monitor.nonce)
                self.assertFalse((Path(d) / 'system-proxy.json').exists())
            finally:
                monitor.close()


if __name__ == '__main__':
    unittest.main()
