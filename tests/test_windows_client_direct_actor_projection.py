"""Mock-only source-token control tests; never executes a native actor locally."""
import hashlib
import importlib.util
import json
from pathlib import Path
import subprocess
import tempfile
import unittest
from unittest.mock import Mock, patch

ROOT = Path(__file__).resolve().parents[1]
spec = importlib.util.spec_from_file_location('direct_actor_projection_test', ROOT / '.github/test_windows_identity_actor_projection.py')
control = importlib.util.module_from_spec(spec); spec.loader.exec_module(control)
proof = control.load_proof()
NONCE = 'a' * 32


def fixture():
    return {'schemaVersion':1, 'mode':'actor', 'nonce':NONCE, 'pid':123,
            'queriesSucceeded':True, 'errors':[], 'tokenIsAppContainer':False,
            'tokenAppContainerSid':None, 'tokenElevated':True, 'isProcessInJob':True,
            'tokenCapabilities':[], 'private':'PRIVATE_SENTINEL'}


class ActorProjectionTests(unittest.TestCase):
    def test_nonvacuous_source_token_projection_redacts(self):
        result = control.evaluate(proof, fixture(), NONCE, 123, 0)
        self.assertTrue(result['native_identity_rejected'])
        self.assertFalse(result['native_identity']['token_is_appcontainer'])
        self.assertTrue(result['native_identity']['sid_present'])
        self.assertFalse(result['native_identity']['sid_string'])
        self.assertNotIn('PRIVATE_SENTINEL', json.dumps(result))
        self.assertNotIn(NONCE, json.dumps(result))
        self.assertTrue(all(type(v) is bool for v in result['native_identity'].values()))

    def test_each_required_observation_fails_closed(self):
        changes = [('schemaVersion',True), ('schemaVersion',2), ('mode','actor-http'),
                   ('nonce','b'*32), ('pid',0), ('pid',124), ('pid',True),
                   ('queriesSucceeded',False), ('errors',['PRIVATE']),
                   ('tokenIsAppContainer',True), ('tokenAppContainerSid','PRIVATE_SID'),
                   ('tokenElevated',1), ('isProcessInJob',1), ('tokenCapabilities','PRIVATE')]
        for name, value in changes:
            with self.subTest(field=name):
                actor = fixture(); actor[name] = value
                result = control.evaluate(proof, actor, NONCE, 123, 0)
                self.assertFalse(result['control_passed'])
                self.assertIn('native_identity', result)
        for name in ('tokenAppContainerSid', 'tokenIsAppContainer', 'queriesSucceeded', 'errors', 'pid', 'schemaVersion', 'mode', 'nonce', 'tokenElevated', 'isProcessInJob', 'tokenCapabilities'):
            actor=fixture(); actor.pop(name)
            with self.subTest(missing=name):
                self.assertFalse(control.evaluate(proof, actor, NONCE, 123, 0)['control_passed'])
        self.assertFalse(control.evaluate(proof, fixture(), NONCE, 123, 1)['control_passed'])
        with self.assertRaises(ValueError): control.evaluate(proof, None, NONCE, 123, 0)

    def test_unexpected_token_retains_closed_failure_facts(self):
        actor = fixture(); actor['tokenIsAppContainer'] = True
        result = control.evaluate(proof, actor, NONCE, 123, 0)
        self.assertFalse(result['control_passed'])
        self.assertFalse(result['source_token_observed'])
        self.assertTrue(result['native_identity']['token_is_appcontainer'])
        self.assertTrue(result['fresh_report'])
        self.assertTrue(result['normal_exit'])
        self.assertNotIn('PRIVATE', json.dumps(result))

    def run_mock(self, *, timeout=False, malformed=False, hash_bad=False):
        with tempfile.TemporaryDirectory() as directory:
            actor = Path(directory)/'actor.exe'; actor.write_bytes(b'x'*512)
            digest=hashlib.sha256(actor.read_bytes()).hexdigest()
            process=Mock(); process.pid=123; process.poll.return_value=0
            process.wait.side_effect=[subprocess.TimeoutExpired('owned',10),0] if timeout else [0,0]
            if timeout:
                process.poll.return_value=None
                process.kill.side_effect=lambda: setattr(process.poll, 'return_value', -9)
            captured={}
            def spawn(args, **kwargs):
                self.assertEqual(args[1], 'actor')
                self.assertEqual(len(args), 4)
                self.assertTrue(kwargs['close_fds'])
                captured['path']=Path(args[3]); captured['work']=Path(kwargs['cwd'])
                payload=fixture(); payload['nonce']=args[2]
                captured['path'].write_text('invalid PRIVATE' if malformed else json.dumps(payload))
                return process
            with patch.object(control, 'windows_available', return_value=True), patch.object(control.subprocess, 'Popen', side_effect=spawn) as popen:
                result=control.run_control(actor, '0'*64 if hash_bad else digest)
            if hash_bad: popen.assert_not_called()
            if captured:
                self.assertFalse(captured['path'].exists()); self.assertFalse(captured['work'].exists())
            return result, process

    def test_mock_success_removes_all_raw_files(self):
        result, process=self.run_mock()
        self.assertTrue(result['control_passed'])
        self.assertFalse(result['runtime_acceptance'])
        self.assertTrue(all(result[k] for k in ('process_exited','raw_report_removed','work_removed')))
        self.assertNotIn('PRIVATE', json.dumps(result))

    def test_timeout_kills_waits_and_cleans(self):
        result, process=self.run_mock(timeout=True)
        self.assertFalse(result['control_passed'])
        process.kill.assert_called_once()
        self.assertTrue(result['process_exited'] and result['raw_report_removed'] and result['work_removed'])

    def test_malformed_report_fails_and_cleans(self):
        result, _=self.run_mock(malformed=True)
        self.assertFalse(result['control_passed'])
        self.assertTrue(result['raw_report_removed'] and result['work_removed'])
        self.assertNotIn('PRIVATE', json.dumps(result))

    def test_hash_mismatch_never_executes(self):
        result, _=self.run_mock(hash_bad=True)
        self.assertFalse(result['actor_started'])
        self.assertFalse(result['actor_hash_verified'])

    def test_report_bound_and_symlink_are_rejected(self):
        with tempfile.TemporaryDirectory() as directory:
            target=Path(directory)/'file'; target.write_bytes(b'x'*10)
            with self.assertRaises(ValueError): control.regular_bounded(target,2,9)
            fake=Mock(); fake.lstat.return_value=Mock(st_mode=0o120777,st_nlink=1,st_file_attributes=0,st_size=10)
            with self.assertRaises(ValueError): control.regular_bounded(fake,2,20)


if __name__ == '__main__': unittest.main()
