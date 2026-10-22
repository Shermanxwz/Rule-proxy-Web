"""Pure request/ownership/reaper-isolation tests; no native or network calls."""
import copy
import importlib.util
import io
import json
from pathlib import Path
import tempfile
import types
import unittest
from unittest import mock
import zipfile

ROOT = Path(__file__).resolve().parents[1]
spec = importlib.util.spec_from_file_location('local_model2_test', ROOT / '.github/windows_identity_model2_local_probe.py')
m = importlib.util.module_from_spec(spec); spec.loader.exec_module(m)


def ordinary():
    return dict(sid='S-1-5-21-1-2-3-1001', session_id=1, token_type=1, elevation_type=1,
        elevated=False, integrity_rid=8192, admin_attributes=None, appcontainer=False,
        appcontainer_sid=None, capability_count=0, ui_access=False)


def output(*, tier='base-container', error=None):
    proof = m.local.controller.pipe_helpers.proof
    facts = {key: False for key in proof.PROBE_FACTS}
    facts['baseContainerApiPresent'] = True
    facts['uiCapabilities'] = {key: True for key in proof.UI_FACTS}
    value = dict(warnings=[], probes=facts)
    if error is None:
        value.update(tier=tier, needsDaclAugmentation=False)
    else:
        value['error'] = error
    return value


class ClockAPI:
    def __init__(self):
        self.now = 1000; self.created = []; self.closed = []
        self.atomic_job_requested = False
    def qpc_frequency(self): return 1000
    def qpc(self): return self.now
    def current_token(self): return 51
    def identity(self, token): return ordinary()
    def compartment(self): return 1
    def close(self, handle): self.closed.append(handle)
    def windows_x64(self): return True
    def private_directory(self, path, sid): self.created.append(path); path.mkdir()


class ProbeTests(unittest.TestCase):
    def test_bundle_and_extracted_closure_fail_closed_before_execution(self):
        image=bytearray(512);image[:2]=b'MZ';image[0x3c:0x40]=(64).to_bytes(4,'little')
        image[64:70]=b'PE\0\0\x64\x86';image=bytes(image);license_bytes=b'fixed MIT fixture\n'
        manifest={'schema_version':1,'executor_sha256':m.sha(image)}
        for variant in ('valid','outer_digest','extracted_member','extra_member','inner_digest','symlink'):
            with self.subTest(variant=variant),tempfile.TemporaryDirectory() as temp:
                root=Path(temp);runtime=root/'runtime';runtime.mkdir();bundle=root/'bundle.zip'
                files={'build-manifest.json':m.encode(manifest),'wxc-exec.exe':image,'MXC-LICENSE.md':license_bytes}
                if variant=='inner_digest':files['wxc-exec.exe']=image+b'changed'
                memory=io.BytesIO()
                with zipfile.ZipFile(memory,'w',compression=zipfile.ZIP_STORED) as archive:
                    for name in m.MEMBERS:
                        info=zipfile.ZipInfo(name,(1980,1,1,0,0,0));info.create_system=3
                        info.external_attr=(0o120777 if variant=='symlink' and name=='wxc-exec.exe' else 0o100644)<<16
                        archive.writestr(info,files[name]);(runtime/name).write_bytes(files[name])
                bundle.write_bytes(memory.getvalue())
                if variant=='extracted_member':(runtime/'wxc-exec.exe').write_bytes(b'wrong')
                if variant=='extra_member':(runtime/'unreviewed.dll').write_bytes(b'wrong')
                with mock.patch.object(m.pins,'MXC_G_BUNDLE_SHA256','0'*64 if variant=='outer_digest' else m.sha(bundle.read_bytes())), \
                     mock.patch.object(m.pins,'MXC_G_EXECUTOR_SHA256',m.sha(image)), \
                     mock.patch.object(m.pins,'MXC_G_LICENSE_SHA256',m.sha(license_bytes)), \
                     mock.patch.object(m.pins,'MXC_G_BUILD_MANIFEST',manifest):
                    if variant=='valid':self.assertEqual(m.verify_artifacts(bundle,runtime),runtime/'wxc-exec.exe')
                    else:
                        with self.assertRaises(ValueError):m.verify_artifacts(bundle,runtime)

    def test_default_cli_never_constructs_api_or_runs_probe(self):
        stream=types.SimpleNamespace(buffer=io.BytesIO())
        with mock.patch.object(m,'ProbeAPI') as api,mock.patch.object(m,'run_probe') as run, \
             mock.patch.object(m.sys,'stdout',stream):
            self.assertEqual(m.main([]),1)
        api.assert_not_called();run.assert_not_called()
        self.assertEqual(json.loads(stream.buffer.getvalue())['status'],'failed')

    def test_closed_model2_shape_is_identity_scoped_without_direct_rules(self):
        value = m.validate_request(m.request_document('a'*32))
        self.assertEqual(value['version'], '1.0.0')
        self.assertEqual(value['fallback'], {'allowDaclMutation': False})
        self.assertEqual(value['network'], {'egress': {'default': 'deny'},
            'ingress': {'default': 'allow', 'hostLoopback': 'deny'}})
        self.assertEqual(value['process']['env'], [])
        self.assertIs(value['process']['inheritDefaultEnv'], False)
        for value in ('0'*31, 'A'*32, '../wrong', 1):
            with self.subTest(value=value), self.assertRaises(ValueError):
                m.request_document(value)
        for port in (True, 1024, 49151, 65536):
            with self.subTest(port=port), self.assertRaises(ValueError):
                m.request_document('a'*32, port)

    def test_request_rejects_weakening_extra_fields_and_crossed_peer(self):
        original = m.request_document('a'*32)
        cases = []
        value = copy.deepcopy(original); value['network']['ingress']['hostLoopback'] = 'allow'; cases.append(value)
        value = copy.deepcopy(original); value['network']['egress']['allow'] = []; cases.append(value)
        value = copy.deepcopy(original); value['fallback']['allowDaclMutation'] = 0; cases.append(value)
        value = copy.deepcopy(original); value['processContainer']['network']['allowedProxyPeer'] += 'b'; cases.append(value)
        value = copy.deepcopy(original); value['runtimeConfig']['networkProxy'] = 'http://localhost:49183'; cases.append(value)
        value = copy.deepcopy(original); value['process']['commandLine'] = 'unexpected.exe'; cases.append(value)
        value = copy.deepcopy(original); value['phase'] = 'start'; cases.append(value)
        for value in cases:
            with self.subTest(value=value), self.assertRaises(ValueError):
                m.validate_request(value)

    def test_fixed_cli_cannot_become_actual_launch(self):
        command = m.fixed_command(Path('fixed/wxc-exec.exe'), Path('private/request.json'))
        self.assertEqual(command[1:3], ['--probe', '--config'])
        self.assertEqual(len(command), 4)
        self.assertNotIn('--debug', command)

    def test_child_environment_is_exact_five_and_reaper_override_is_child_only(self):
        work = Path('private')
        base = dict(SystemRoot='native-windows', WINDIR='native-windows', TEMP=str(work/'temp'), TMP=str(work/'temp'))
        result = m.child_environment(base, work, work/'dacl-state')
        self.assertEqual(set(result), {'SystemRoot', 'WINDIR', 'TEMP', 'TMP', 'MXC_DACL_STATE_DIR'})
        self.assertEqual(base.keys(), {'SystemRoot', 'WINDIR', 'TEMP', 'TMP'})
        for changed in (dict(base, SECRET='bad'), dict(base, TEMP='foreign'), dict(base, WINDIR='foreign')):
            with self.subTest(changed=changed), self.assertRaises(ValueError):
                m.child_environment(changed, work, work/'dacl-state')
        with self.assertRaises(ValueError):m.child_environment(base, work, work/'other-state')

    def test_native_environment_override_reuses_only_native_four_key_block(self):
        api = m.ProbeAPI.__new__(m.ProbeAPI); api.reaper_state = Path('private/dacl-state')
        api.proc = types.SimpleNamespace(_environment_block=lambda env:env)
        original = 'SystemRoot=native\0WINDIR=native\0TEMP=private\\temp\0TMP=private\\temp\0\0'
        with mock.patch.object(m.local.LocalNativeAPI, 'environment', return_value=original):
            result = api.environment(Path('private'))
        self.assertTrue(api.five_key_environment)
        self.assertEqual(result['MXC_DACL_STATE_DIR'], str(api.reaper_state))

    def test_stale_reaper_state_blocks_create_before_native_api(self):
        api = m.ProbeAPI.__new__(m.ProbeAPI); api.worker_sid = ordinary()['sid']
        with tempfile.TemporaryDirectory() as temp:
            work = Path(temp); state=work/'dacl-state';state.mkdir(); (state/'foreign.json').write_text('{}')
            api.reaper_state = state; api.verify_private_directory = mock.Mock()
            with mock.patch.object(m.local.LocalNativeAPI, 'create_suspended') as create:
                with self.assertRaises(ValueError):api.create_suspended(None, None, work, None, None)
            create.assert_not_called()

    def test_work_parent_restricted_to_existing_repo_private_or_descendant(self):
        with tempfile.TemporaryDirectory() as temp:
            root=Path(temp); base=root/'private';base.mkdir();child=base/'child';child.mkdir()
            self.assertEqual(m.admit_work_parent(None,root=root),base)
            self.assertEqual(m.admit_work_parent(child,root=root),child)
            with self.assertRaises(m.launcher.GateFailure):m.admit_work_parent(root,root=root)

    def test_projection_strict_types_and_no_raw_error_warning_export(self):
        value = output(error='private machine path and SID must not leave')
        value['warnings'] = ['secret-argument']
        result = m.projection(m.encode(value))
        self.assertTrue(result['detector_error_present'])
        self.assertEqual(result['warning_count'], 1)
        self.assertNotIn('private', json.dumps(result))
        self.assertNotIn('secret', json.dumps(result))
        for changed in (dict(output(), extra=True), dict(output(), warnings=[1]),
                        dict(output(), error='contradictory')):
            with self.subTest(changed=changed), self.assertRaises(ValueError):m.projection(m.encode(changed))
        changed=output(); changed['probes']['baseContainerApiPresent']=1
        with self.assertRaises(ValueError):m.projection(m.encode(changed))
        with self.assertRaises(ValueError):m.projection(b'{"warnings":[],"warnings":[],"probes":{}}')
        with self.assertRaises(ValueError):m.projection(b'x'*(m.MAX_OUTPUT+1))

    def test_run_requires_explicit_flag_before_constructing_native_api(self):
        with mock.patch.object(m, 'ProbeAPI') as api:
            result = m.run_probe(None,None,None,None,None)
        api.assert_not_called()
        self.assertEqual(result['failure'], 'platform')

    def exercise(self, *, setup_ms=0, source_changed=False, stale_state=False, late=False,
                 unknown_exit=False, exit_code=0, stderr=b'', candidate_error=None):
        api=ClockAPI(); calls={}; image=b'statically admitted fixture'
        with tempfile.TemporaryDirectory() as temp:
            root=Path(temp);work_parent=root/'private';work_parent.mkdir();runtime=root/'runtime';runtime.mkdir()
            executable=runtime/'wxc-exec.exe';executable.write_bytes(image)
            request=work_parent/'request.json';request.write_bytes(m.encode(m.request_document('a'*32)))
            def verify(*args):api.now+=setup_ms;return executable
            def launch(unused_api,command,work,parent,expected,**kwargs):
                calls.update(command=command,kwargs=kwargs,work=work)
                self.assertEqual(command[1:3], ['--probe','--config'])
                self.assertEqual((work/'model2-request.json').read_bytes(), request.read_bytes())
                self.assertEqual(list((work/'dacl-state').iterdir()), [])
                api.atomic_job_requested=True;api.five_key_environment=True
                (work/'controller.stdout').write_bytes(m.encode(output(error=candidate_error)))
                (work/'controller.stderr').write_bytes(stderr)
                if stale_state:(work/'dacl-state'/'unexpected.json').write_text('{}')
                if late:api.now=121001
                return dict(started=True,resumed=True,timed_out=False,exit_code=exit_code,
                    native_identity_verified_before_resume=True,
                    cleanup=dict(job_closed=True,job_empty=True,handles_closed=True,
                        process_exit_confirmed=not unknown_exit,close_uncertain=False,errors=[]))
            snapshots=['5'*64,'6'*64 if source_changed else '5'*64]
            with mock.patch.object(m,'os',types.SimpleNamespace(name='nt')), \
                 mock.patch.object(m,'verify_artifacts',side_effect=verify), \
                 mock.patch.object(m,'source_snapshot',side_effect=snapshots), \
                 mock.patch.object(m.pins,'MXC_G_EXECUTOR_SHA256',m.sha(image)), \
                 mock.patch.object(m.launcher,'launch_owned',side_effect=launch):
                result=m.run_probe('bundle',runtime,request,work_parent,'5'*64,run=True,api=api,root=root,ids=lambda n:'b'*32)
            calls['directories_created']=len(api.created)
        return result,api,calls

    def test_single_epoch_atomic_ownership_and_empty_reaper_directory(self):
        value,api,calls=self.exercise(setup_ms=7000)
        self.assertEqual(value['status'],'supported_candidate')
        self.assertTrue(all(value['checks'].values()))
        self.assertEqual(calls['kwargs']['qpc_budget'].deadline,121000)
        self.assertEqual(calls['kwargs']['work_cutoff'],106000)
        self.assertEqual(calls['kwargs']['cleanup_cutoff'],121000)
        self.assertEqual(calls['directories_created'],3)
        for key in ('peer_observed','listener_observed','network_tested','proxy_tested',
                    'model2_runtime_qualified','strict_stage0_passed','product_acceptance'):
            self.assertIs(value[key],False)
        encoded=m.encode(value)
        for private in (ordinary()['sid'].encode(),b'local-model2-probe-',b'RuleProxy.IdentityProof',b'127.0.0.1',b'MXC_DACL_STATE_DIR'):
            self.assertNotIn(private,encoded)

    def test_spent_setup_budget_does_not_renew_deadline_or_create_directories(self):
        value,api,calls=self.exercise(setup_ms=76000)
        self.assertEqual(value['status'],'failed');self.assertEqual(value['failure'],'deadline')
        self.assertEqual(api.created,[]);self.assertNotIn('command',calls)

    def test_changed_sources_block_launch_after_setup(self):
        value,api,calls=self.exercise(source_changed=True)
        self.assertEqual(value['status'],'failed');self.assertNotIn('command',calls)

    def test_unknown_exit_stderr_reaper_residue_nonzero_and_late_results_fail(self):
        for options in (dict(unknown_exit=True),dict(stderr=b'DACL recovery: private'),dict(stale_state=True),
                        dict(exit_code=1),dict(late=True)):
            with self.subTest(options=options):
                value,_,_=self.exercise(**options)
                self.assertEqual(value['status'],'failed')
                self.assertFalse(value['model2_runtime_qualified'])

    def test_nonzero_exit_preserves_verified_detector_projection(self):
        value,_,_=self.exercise(exit_code=1,candidate_error='reported detector error')
        self.assertEqual(value['status'],'failed')
        self.assertEqual(value['probe_exit_code'],1)
        self.assertTrue(value['checks']['parsed_output'])
        self.assertTrue(value['probe']['detector_error_present'])

    def test_directory_readback_failure_keeps_conservative_residue_flag(self):
        api=ClockAPI()
        def failed_create(path,sid):
            path.mkdir();raise ValueError('readback_failed')
        api.private_directory=failed_create
        with tempfile.TemporaryDirectory() as temp:
            root=Path(temp);private=root/'private';private.mkdir();request=root/'request.json'
            request.write_bytes(m.encode(m.request_document('a'*32)))
            with mock.patch.object(m,'os',types.SimpleNamespace(name='nt')), \
                 mock.patch.object(m,'verify_artifacts',return_value=root/'executor'), \
                 mock.patch.object(m,'source_snapshot',return_value='5'*64):
                result=m.run_probe(None,None,request,private,'5'*64,run=True,api=api,root=root,ids=lambda n:'b'*32)
            self.assertTrue(result['private_tree_retained'])
            self.assertEqual(result['failure'],'staging')
            self.assertEqual(len(list(private.iterdir())),1)

    def test_detector_error_is_unsupported_candidate_without_runtime_claim(self):
        value,_,_=self.exercise(candidate_error='DACL fallback required but fallback.allowDaclMutation is false')
        self.assertEqual(value['status'],'unsupported_candidate')
        self.assertIsNone(value['failure'])
        self.assertTrue(value['probe']['detector_error_present'])
        self.assertFalse(value['model2_runtime_qualified'])

    def test_public_validator_rejects_false_runtime_claim_and_missing_bindings(self):
        value,_,_=self.exercise()
        for key in ('peer_observed','model2_runtime_qualified','product_acceptance'):
            changed=copy.deepcopy(value);changed[key]=True
            with self.subTest(key=key),self.assertRaises(ValueError):m.validate_public(changed)
        changed=copy.deepcopy(value);changed['source_sha256']=None
        with self.assertRaises(ValueError):m.validate_public(changed)
        changed=copy.deepcopy(value);changed['checks']['held_exit']=False
        with self.assertRaises(ValueError):m.validate_public(changed)


if __name__ == '__main__':
    unittest.main()
