"""Mocks only; these tests never invoke system QEMU or prove real compatibility."""
import importlib.util
import json
import os
from pathlib import Path
import tempfile
import unittest
from unittest.mock import Mock, patch
from types import SimpleNamespace

ROOT = Path(__file__).resolve().parents[1]
spec = importlib.util.spec_from_file_location('serviced_qmp_test', ROOT / '.github/test_windows_serviced_qmp.py')
smoke = importlib.util.module_from_spec(spec); spec.loader.exec_module(smoke)
host = smoke.load_host()


class FakeQmp:
    def __init__(self, work, public, *, wrong_accept=False, bad_qdev=False, bad_ro=False, major=8, bad_tray=False):
        self.work, self.public = work, public
        self.wrong_accept, self.bad_qdev, self.bad_ro, self.major = wrong_accept, bad_qdev, bad_ro, major
        self.bad_tray = bad_tray
        self.installed = True; self.updated = False; self.calls = []
    def execute(self, command, arguments=None):
        self.calls.append((command, arguments))
        if command == 'query-status': return {'running': False, 'status': 'prelaunch'}
        if command == 'query-version': return {'qemu': {'major': self.major, 'minor': 2, 'micro': 2}}
        if command == 'query-block':
            rows = [{'device': 'install', 'qdev': 'bad' if self.bad_qdev else 'install-cd', 'tray_open': not self.installed},
                    {'device': 'updates', 'qdev': 'update-cd', 'tray_open': self.bad_tray or not self.updated}]
            if self.installed: rows[0]['inserted'] = {'file': str(self.work / 'official.iso'), 'ro': True}
            if self.updated: rows[1]['inserted'] = {'file': str(self.work / 'updates.iso'), 'ro': not self.bad_ro}
            return rows
        if command == 'query-named-block-nodes':
            return [{'file': str(self.work / name)} for name, active in [('official.iso', self.installed), ('updates.iso', self.updated)] if active]
        if command == 'blockdev-remove-medium':
            if arguments == {'device': 'install'}:
                if self.wrong_accept: return {}
                self.public['qmp_diagnostic'] = {'command': command, 'completed': False, 'error_class': 'GenericError'}
                raise RuntimeError('PRIVATE_QMP_DESCRIPTION')
            if arguments != {'id': 'install-cd'}: raise AssertionError('incorrect frontend remove')
            self.installed = False; return {}
        if command == 'blockdev-open-tray':
            if arguments != {'id': 'install-cd', 'force': True}: raise AssertionError('incorrect frontend tray')
            return {}
        if command == 'blockdev-change-medium':
            if arguments != {'id': 'update-cd', 'filename': str(self.work / 'updates.iso'), 'format': 'raw', 'read-only-mode': 'read-only'}:
                raise AssertionError('incorrect update frontend')
            self.updated = True; return {}
        raise AssertionError('unexpected command')


class SyntheticQmpTests(unittest.TestCase):
    def run_mock(self, **kwargs):
        with tempfile.TemporaryDirectory() as directory:
            work = Path(directory)
            for name in ('official.iso', 'updates.iso'): (work / name).write_bytes(bytes(smoke.MEDIA_BYTES))
            public = {}; result = {}; qmp = FakeQmp(work, public, **kwargs)
            smoke.exercise(host, qmp, work, public, result)
            return result, qmp.calls

    @unittest.skipUnless(os.name == 'posix', 'POSIX ownership and permission semantics required')
    def test_production_helpers_complete_mock_contract(self):
        result, calls = self.run_mock()
        self.assertEqual(result['phase'], 'completed')
        self.assertTrue(result['installer_reclaimed'])
        self.assertEqual(result['readback_failure'], 'none')
        self.assertTrue(result['never_running_verified'])
        self.assertTrue(result['installer_tray_open_verified'])
        self.assertTrue(result['update_tray_closed_verified'])
        self.assertEqual(result['qemu_version'], {'major':8, 'minor':2, 'micro':2})
        self.assertEqual(result['wrong_backend_error_class'], 'GenericError')
        self.assertFalse(any(command in ('cont', 'set_link') for command, _ in calls))
        self.assertNotIn('PRIVATE', json.dumps(result))

    def test_wrong_command_acceptance_fails(self):
        with self.assertRaises(ValueError): self.run_mock(wrong_accept=True)

    @unittest.skipUnless(os.name == 'posix', 'POSIX ownership and permission semantics required')
    def test_wrong_frontend_fails(self):
        with self.assertRaises(ValueError): self.run_mock(bad_qdev=True)

    @unittest.skipUnless(os.name == 'posix', 'POSIX ownership and permission semantics required')
    def test_writable_update_fails(self):
        with self.assertRaises(ValueError): self.run_mock(bad_ro=True)

    @unittest.skipUnless(os.name == 'posix', 'POSIX ownership and permission semantics required')
    def test_update_tray_not_closed_fails(self):
        with self.assertRaises(ValueError): self.run_mock(bad_tray=True)

    @unittest.skipUnless(os.name == 'posix', 'POSIX process harness required')
    def test_actual_harness_failure_keeps_closed_qmp_and_closes_socket(self):
        process = Mock(); process.poll.return_value = None
        process.kill.side_effect = lambda: setattr(process.poll, 'return_value', -9)
        sock = Mock(); sock.fileno.return_value = -1
        class Transport:
            def __init__(self, path):
                self.socket = sock; self.file = SimpleNamespace(closed=True)
            def close(self): raise BrokenPipeError('PRIVATE_CLOSE_DETAIL')
        def scoped(base, public):
            public['qmp_diagnostic'] = {'command': 'blockdev-change-medium',
                'error_class': 'GenericError', 'completed': False, 'desc': 'PRIVATE_QMP_DETAIL'}
            return Transport
        def spawn(args, **kwargs):
            path = args[args.index('-qmp')+1].split(',', 1)[0][5:]
            Path(path).touch()
            return process
        with patch.object(smoke.shutil, 'which', return_value='/system/qemu'), \
             patch.object(smoke, 'load_host', return_value=host), \
             patch.object(host, 'load', return_value=SimpleNamespace(Qmp=object)), \
             patch.object(host, 'scoped_qmp_class', side_effect=scoped), \
             patch.object(smoke.subprocess, 'Popen', side_effect=spawn), \
             patch.object(smoke, 'exercise', side_effect=RuntimeError('PRIVATE_FAILURE')), \
             patch.object(smoke.threading, 'Timer'):
            result = smoke.run_actual()
        self.assertEqual(result['qmp_diagnostic'], {'command':'blockdev-change-medium', 'error_class':'GenericError', 'completed':False})
        sock.close.assert_called_once()
        self.assertTrue(result['qmp_closed'])
        self.assertTrue(result['cleanup_error'])
        self.assertTrue(result['process_exited'])
        self.assertTrue(result['work_removed'])
        self.assertFalse(result['passed'])
        self.assertNotIn('PRIVATE', json.dumps(result))

    @unittest.skipUnless(os.name == 'posix', 'POSIX ownership and permission semantics required')
    def test_missing_underscore_tray_field_fails_closed(self):
        with tempfile.TemporaryDirectory() as directory:
            work = Path(directory)
            for name in ('official.iso', 'updates.iso'): (work / name).write_bytes(bytes(smoke.MEDIA_BYTES))
            public = {}; result = {}; qmp = FakeQmp(work, public)
            original = qmp.execute
            def wrong_event_schema(command, arguments=None):
                value = original(command, arguments)
                if command == 'query-block':
                    for row in value: row['tray-open'] = row.pop('tray_open')
                return value
            qmp.execute = wrong_event_schema
            with self.assertRaises(ValueError): smoke.exercise(host, qmp, work, public, result)
            self.assertEqual(result['readback_failure'], 'installer_tray_not_open')

    def test_wrong_version_fails(self):
        with self.assertRaises(ValueError): self.run_mock(major=9)

    def test_paused_launch_no_network_or_kvm(self):
        args = smoke.command('/system/qemu', Path('/owned'))
        for key, value in (('-accel', 'tcg'), ('-nic', 'none'), ('-m', '64'), ('-machine', 'q35')):
            self.assertEqual(args[args.index(key) + 1], value)
        self.assertIn('-S', args); self.assertIn('-nodefaults', args)
        self.assertNotIn('kvm', ' '.join(args))
        self.assertEqual(sum('id=install-cd,' in x for x in args), 1)
        self.assertEqual(sum('id=update-cd,' in x for x in args), 1)

    def test_preflight_failure_closed_no_real_process(self):
        with patch.object(smoke.shutil, 'which', return_value=None), patch.object(smoke.subprocess, 'Popen') as spawn:
            result = smoke.run_actual()
        spawn.assert_not_called()
        self.assertFalse(result['passed'])
        self.assertFalse(result['runtime_acceptance'])
        self.assertEqual(result['failure_class'], 'RuntimeError')
        self.assertTrue(all(result[x] for x in ('process_exited', 'qmp_closed', 'work_removed')))

    def test_source_bounds_cleanup_and_actual_optin(self):
        source = (ROOT / '.github/test_windows_serviced_qmp.py').read_text()
        for marker in ('MAX_SECONDS = 45', 'process.wait(timeout=5)', 'watchdog.cancel()',
                       'qmp.socket.fileno() == -1', 'shutil.rmtree(work)',
                       "'--run-actual-qemu'", 'qmp_type.__new__(qmp_type)'):
            self.assertIn(marker, source)
        self.assertNotIn('str(exc)', source)
        self.assertNotIn("qmp.execute('cont'", source)


if __name__ == '__main__': unittest.main()
