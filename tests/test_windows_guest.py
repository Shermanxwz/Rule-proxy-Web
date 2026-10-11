"""Regression checks for the contained startup gate and its untrusted state files."""
import json
import os
from pathlib import Path
import tempfile
import unittest
from unittest import mock
from ruleproxy import windows_guest as guest

class WindowsGuestTests(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        self.profile = Path(self.temporary.name)
        self.directory = self.profile / 'runtime'
        self.directory.mkdir()
        self.config = {
            'command':['browser.exe'], 'env':{'CUSTOM':'configured'},
            'profile':str(self.profile), 'proxy_port':10809,
            'status_directory':str(self.directory), 'nonce':'a'*64,
            'fixtures':[{'address':'127.0.0.1','port':19001,'protocol':'tcp'},
                        {'address':'127.0.0.1','port':19002,'protocol':'udp'}],
        }
        self.path = self.profile / 'config.json'
    def save(self):
        self.path.write_text(json.dumps(self.config), encoding='utf-8')
    def test_application_inherits_windows_defaults_and_only_overrides_requested_values(self):
        self.save()
        application = mock.Mock(); application.wait.return_value = 0
        with mock.patch.object(guest, '_child_self_check'), mock.patch.object(guest, '_wait_for_decision', return_value=True), mock.patch.object(
            guest.subprocess, 'Popen', return_value=application
        ) as popen, mock.patch.dict(os.environ, {'SYSTEMROOT':r'C:\Windows'}):
            self.assertEqual(guest.run(self.path), 0)
            self.assertEqual(popen.call_args.kwargs['env']['SYSTEMROOT'], r'C:\Windows')
            self.assertEqual(popen.call_args.kwargs['env']['CUSTOM'], 'configured')
        self.assertEqual(json.loads((self.directory/'guest-status.json').read_text())['state'], 'APP_EXITED')
    def test_rejected_network_check_never_starts_the_application(self):
        self.save()
        with mock.patch.object(guest, '_child_self_check', side_effect=RuntimeError('direct connection allowed')), mock.patch.object(guest.subprocess,'Popen') as popen:
            self.assertEqual(guest.run(self.path), 70)
        popen.assert_not_called()
        self.assertEqual(json.loads((self.directory/'guest-status.json').read_text())['state'], 'FAILED')
    def test_host_rejection_never_starts_the_application(self):
        self.save()
        with mock.patch.object(guest, '_child_self_check'), mock.patch.object(guest, '_wait_for_decision', return_value=False), mock.patch.object(guest.subprocess,'Popen') as popen:
            self.assertEqual(guest.run(self.path), 70)
        popen.assert_not_called()
    def test_invalid_config_cannot_redirect_the_gate_outside_the_profile(self):
        self.config['status_directory'] = str(self.profile.parent)
        self.save()
        with self.assertRaises(ValueError): guest._read_config(self.path)
    def test_fixtures_cannot_target_a_remote_machine_or_the_allowed_proxy(self):
        for changes in ({'address':'1.1.1.1'}, {'port':10809}):
            with self.subTest(changes=changes):
                self.config['fixtures'][0] = {'address':'127.0.0.1','port':19001,'protocol':'tcp',**changes}
                self.save()
                with self.assertRaises(ValueError): guest._read_config(self.path)

    def test_status_publication_survives_a_transient_windows_reader(self):
        guest._atomic_status(self.directory, 'a'*64, 'READY')
        real_replace = os.replace
        denied = PermissionError(13, 'a reader holds the old status file')
        denied.winerror = 5
        calls = []
        def replace(source, destination):
            calls.append((source, destination))
            if len(calls) < 3:
                old = json.loads(destination.read_text())
                self.assertEqual(old['state'], 'READY')
                raise denied
            real_replace(source, destination)
        with mock.patch.object(guest.os, 'replace', side_effect=replace), mock.patch.object(guest.time, 'sleep'):
            guest._atomic_status(self.directory, 'a'*64, 'APP_STARTED', started=True)
        self.assertEqual(len(calls), 3)
        status = json.loads((self.directory/'guest-status.json').read_text())
        self.assertEqual(status['state'], 'APP_STARTED')
        self.assertTrue(status['started'])
        self.assertFalse((self.directory/'guest-status.tmp').exists())

    def test_persistent_denial_is_bounded_and_does_not_destroy_previous_status(self):
        guest._atomic_status(self.directory, 'a'*64, 'READY')
        denied = PermissionError(13, 'persistent denial')
        denied.winerror = 5
        with mock.patch.object(guest.os, 'replace', side_effect=denied), mock.patch.object(
            guest.time, 'monotonic', side_effect=[0, 0, 2]
        ), mock.patch.object(guest.time, 'sleep'):
            with self.assertRaises(PermissionError):
                guest._atomic_status(self.directory, 'a'*64, 'APP_STARTED', started=True)
        self.assertEqual(json.loads((self.directory/'guest-status.json').read_text())['state'], 'READY')

    def test_unrelated_status_write_error_is_not_retried(self):
        error = OSError(28, 'disk full')
        with mock.patch.object(guest.os, 'replace', side_effect=error) as replace, mock.patch.object(guest.time, 'sleep') as sleep:
            with self.assertRaises(OSError):
                guest._atomic_status(self.directory, 'a'*64, 'READY')
        replace.assert_called_once()
        sleep.assert_not_called()

if __name__=='__main__': unittest.main()
