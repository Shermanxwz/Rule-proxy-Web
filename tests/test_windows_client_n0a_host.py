"""Pure tests of opt-in host integration; no VM, listeners, or native actor."""
import ast
import hashlib
import importlib.util
import io
import json
from pathlib import Path
from types import SimpleNamespace
import tempfile
import threading
import unittest
from unittest.mock import Mock,patch
ROOT=Path(__file__).resolve().parents[1]
spec=importlib.util.spec_from_file_location('n0a_direct_host_test',ROOT/'.github/windows_identity_direct_stage0.py')
host=importlib.util.module_from_spec(spec);spec.loader.exec_module(host)

class PinTests(unittest.TestCase):
    def manifest(self,data):
        return dict(schemaVersion=1,sourceSha256=hashlib.sha256((ROOT/'.github/native/windows_n0a_actor.cpp').read_bytes()).hexdigest(),
            identitySourceSha256=hashlib.sha256((ROOT/'.github/native/windows_identity_actor.cpp').read_bytes()).hexdigest(),
            executableSha256=hashlib.sha256(data).hexdigest(),targetArchitecture='x64',staticCrt=True,
            httpCompiled=False,rawTcpCompiled=True,compileOnly=True,testOnly=False,actorRole='n0a-tcp',builtAtUtc='2026-10-21T00:00:00Z')
    def test_production_two_source_pin_and_exact_optin_seed_contract(self):
        with tempfile.TemporaryDirectory() as temporary:
            actor=Path(temporary)/'actor.exe';manifest=Path(temporary)/'manifest.json';data=b'x'*512
            actor.write_bytes(data);manifest.write_text(json.dumps(self.manifest(data)))
            result=host.verify_n0a_inputs(actor,manifest)
            self.assertEqual(set(result['config']),{'enabled','case_nonce','runner_port','actor_sha256',
                'manifest_sha256','actor_source_sha256','identity_source_sha256'})
            self.assertEqual(len(result['config']['case_nonce']),32)
            self.assertEqual(result['config']['actor_sha256'],hashlib.sha256(data).hexdigest())
            self.assertEqual(result['config']['manifest_sha256'],hashlib.sha256(manifest.read_bytes()).hexdigest())
    def test_test_only_wrong_sources_and_shapes_rejected(self):
        changes=[('testOnly',True),('staticCrt',False),('rawTcpCompiled',False),('httpCompiled',True),
                 ('sourceSha256','a'*64),('identitySourceSha256','a'*64),('executableSha256','a'*64),
                 ('targetArchitecture','ARM64'),('actorRole','fixture'),('schemaVersion',True)]
        with tempfile.TemporaryDirectory() as temporary:
            actor=Path(temporary)/'actor.exe';manifest=Path(temporary)/'manifest.json';data=b'x'*512;actor.write_bytes(data)
            for key,value in changes:
                with self.subTest(key=key):
                    row=self.manifest(data);row[key]=value;manifest.write_text(json.dumps(row))
                    with self.assertRaises(ValueError):host.verify_n0a_inputs(actor,manifest)
            manifest.write_text('{"schemaVersion":1,"schemaVersion":1}')
            with self.assertRaises(ValueError):host.verify_n0a_inputs(actor,manifest)
    def test_execution_gate_fails_before_any_media_or_filesystem_work(self):
        args=SimpleNamespace(n0a=True)
        with patch.object(host,'n0a_helpers',return_value=SimpleNamespace(EXECUTION_ENABLED=False)),patch.object(host,'load') as load:
            with self.assertRaises(PermissionError):host.host(args)
            load.assert_not_called()

class HandlerTests(unittest.TestCase):
    def handler(self,value,path='/cap/n0a-result',expected=True):
        item=host.ClosedHandler.__new__(host.ClosedHandler)
        data=json.dumps(value).encode();item.rfile=io.BytesIO(data);item.headers={'Content-Length':str(len(data))}
        item.path=path;item.send_error=Mock();item.send_response=Mock();item.end_headers=Mock()
        item.server=SimpleNamespace(capability='cap',n0a_expected={} if expected else None,
            received=threading.Event(),n0a_received=threading.Event(),result=None,n0a_result=None,original_received_at=None)
        return item
    def test_n0a_requires_original_and_validates_with_expected_pins(self):
        handler=self.handler({'private':'not_exported'})
        helper=SimpleNamespace(unique_object=lambda pairs:dict(pairs),validate_host_n0a_envelope=Mock(return_value={'status':'inconclusive'}))
        with patch.object(host,'n0a_helpers',return_value=helper):
            handler.do_POST();handler.send_error.assert_called_with(409);helper.validate_host_n0a_envelope.assert_not_called()
            handler.server.received.set();handler.do_POST()
        self.assertTrue(handler.server.n0a_received.is_set());self.assertEqual(handler.server.n0a_result,{'status':'inconclusive'})
        helper.validate_host_n0a_envelope.assert_called_once_with({'private':'not_exported'},handler.server.n0a_expected)
    def test_actual_closed_projection_receives_private_binding_without_export(self):
        engine=host.n0a_helpers();expected={'case_nonce':'a'*32,'actor_sha256':'b'*64}
        value={'schema_version':1,**expected,'report':None,'launcher':engine.default_host_n0a()['launcher']}
        handler=self.handler(value);handler.server.n0a_expected=expected;handler.server.received.set()
        handler.do_POST()
        self.assertTrue(handler.server.n0a_received.is_set())
        self.assertEqual(handler.server.n0a_result['result']['status'],'inconclusive')
        self.assertNotIn('case_nonce',json.dumps(handler.server.n0a_result))
        wrong=self.handler({**value,'case_nonce':'c'*32});wrong.server.n0a_expected=expected;wrong.server.received.set()
        wrong.do_POST();self.assertFalse(wrong.server.n0a_received.is_set());wrong.send_error.assert_called_with(400)

    def test_original_optin_receipt_immutable_and_monotonic_stamp(self):
        handler=self.handler({'stage0_passed':False},'/cap/result')
        with patch.object(host.time,'monotonic',return_value=42):handler.do_POST()
        self.assertEqual(handler.server.original_received_at,42);self.assertFalse(handler.server.result['stage0_passed'])
        handler.rfile=io.BytesIO(b'{"stage0_passed": true}');handler.headers={'Content-Length':'23'}
        handler.do_POST();handler.send_error.assert_called_with(409)
        self.assertFalse(handler.server.result['stage0_passed'])
    def test_off_mode_n0a_route_rejected_and_original_unchanged(self):
        handler=self.handler({},expected=False);handler.do_POST();handler.send_error.assert_called_with(400)
        handler=self.handler({'stage0_passed':False},'/cap/result',expected=False)
        with patch.object(host.time,'monotonic',side_effect=AssertionError('off mode does not stamp')):handler.do_POST()
        self.assertTrue(handler.server.received.is_set());self.assertIsNone(handler.server.original_received_at)
    def test_bounded_and_failed_n0a_never_overwrites_original(self):
        handler=self.handler({});handler.server.received.set();handler.server.result={'stage0_passed':False}
        handler.headers={'Content-Length':str(host.MAX_N0A_REPORT+1)};handler.do_POST()
        self.assertFalse(handler.server.n0a_received.is_set());self.assertEqual(handler.server.result,{'stage0_passed':False})

class LifecycleTests(unittest.TestCase):
    def test_optional_deadline_only_shortens_existing_outer(self):
        server=SimpleNamespace(original_received_at=100)
        self.assertEqual(host.n0a_wait_deadline(server,500),220)
        self.assertEqual(host.n0a_wait_deadline(server,150),150)
        self.assertEqual(host.n0a_wait_deadline(SimpleNamespace(original_received_at=None),150),150)
    def test_optional_timeout_and_qemu_exit_preserve_original(self):
        server=SimpleNamespace(original_received_at=100,n0a_received=Mock(),result={'stage0_passed':False})
        server.n0a_received.wait.return_value=False;disk=Mock();disk.stat.return_value.st_size=1
        qemu=Mock();qemu.poll.return_value=None;public={'stage0_passed':False,'guest_result_provenance_verified':True}
        with patch.object(host.time,'monotonic',return_value=220):
            self.assertEqual(host.wait_for_n0a(server,500,SimpleNamespace(reason=None),disk,qemu,public),'deadline')
        self.assertTrue(public['guest_result_provenance_verified'])
        qemu.poll.return_value=0
        self.assertEqual(host.wait_for_n0a(server,500,SimpleNamespace(reason=None),disk,qemu,public),'qemu_exited')
    def test_endpoint_cleanup_uncertainty_retains_work_and_revokes_cleanup(self):
        endpoint=Mock();endpoint.finish.return_value={'socket_cleanup_confirmed':False,'endpoint_error':True,'receiver_counts':None}
        public={'stage0_passed':True}
        with patch.object(host,'cleanup_owned',return_value=False) as cleanup:
            host.finalize_owned(public,Mock(),Path('owned'),n0a_endpoint=endpoint)
        self.assertTrue(cleanup.call_args.kwargs['retain_work']);self.assertFalse(public['vm_destroyed']);self.assertFalse(public['stage0_passed'])
    def test_endpoint_cleanup_throw_is_closed_and_retains_work(self):
        endpoint=Mock();endpoint.finish.side_effect=RuntimeError('PRIVATE')
        public={}
        with patch.object(host,'cleanup_owned',return_value=False) as cleanup:
            host.finalize_owned(public,Mock(),Path('owned'),n0a_endpoint=endpoint)
        self.assertTrue(cleanup.call_args.kwargs['retain_work']);self.assertNotIn('PRIVATE',json.dumps(public))
    def test_denial_requires_original_provenance_and_owned_cleanup(self):
        receipt={'result':{'status':'observed_connect_denial','endpoints':{
            name:{'status':'observed_connect_denial'} for name in ('guest','runner')}}}
        complete={'guest_result_provenance_verified':True,'vm_destroyed':True,
                  'n0a_receiver_cleanup':{'socket_cleanup_confirmed':True,'endpoint_error':False,
                   'receiver_counts':dict.fromkeys(('accepted','ordinary_verified_frames','contained_verified_frames','rejected','timed_out'),0)}}
        complete['n0a_receiver_cleanup']['receiver_counts'].update(accepted=5,ordinary_verified_frames=5)
        server=SimpleNamespace(n0a_result=receipt)
        self.assertEqual(host.compose_n0a_public(server,complete,'received')['result']['status'],'observed_connect_denial')
        for field,value in [('guest_result_provenance_verified',False),('guest_result_provenance_verified',None),
                            ('vm_destroyed',False),('n0a_receiver_cleanup',None),
                            ('n0a_receiver_cleanup',{'socket_cleanup_confirmed':True,'endpoint_error':False,'receiver_counts':None}),
                            ('n0a_receiver_cleanup',{'socket_cleanup_confirmed':False,'endpoint_error':False}),
                            ('n0a_receiver_cleanup',{'socket_cleanup_confirmed':True,'endpoint_error':True})]:
            public=dict(complete);public[field]=value
            projected=host.compose_n0a_public(server,public,'deadline')
            self.assertEqual(projected['result']['status'],'inconclusive')
            self.assertTrue(all(v['status']=='inconclusive' for v in projected['result']['endpoints'].values()))
        for key,value in [('ordinary_verified_frames',4),('contained_verified_frames',1),('accepted',True),('timed_out',129)]:
            public=json.loads(json.dumps(complete));public['n0a_receiver_cleanup']['receiver_counts'][key]=value
            self.assertEqual(host.compose_n0a_public(server,public,'received')['result']['status'],'inconclusive')
        self.assertEqual(receipt['result']['status'],'observed_connect_denial')
    def test_attributed_connect_success_survives_missing_original_and_cleanup(self):
        receipt={'result':{'status':'connect_succeeded','endpoints':{'guest':{'status':'connect_succeeded'}}}}
        projected=host.compose_n0a_public(SimpleNamespace(n0a_result=receipt),{},'deadline')
        self.assertEqual(projected['result']['status'],'connect_succeeded')
        self.assertFalse(projected['original_stage0_receipt_verified'])
        self.assertFalse(projected['vm_destroyed'])
    def test_off_teardown_and_stage0_before_optional_wait_source_contract(self):
        source=(ROOT/'.github/windows_identity_direct_stage0.py').read_text()
        tree=ast.parse(source);functions={x.name:ast.get_source_segment(source,x) for x in tree.body if isinstance(x,ast.FunctionDef)}
        body=functions['host']
        self.assertLess(body.index('merge_direct_result(public, server.result'),body.index('wait_for_n0a(server'))
        self.assertIn("if n0a is not None and not original_merged",body)
        self.assertIn("'n0a-connect-public.json'",body)
        self.assertIn('n0a=n0a',body)
        self.assertEqual(host.MAX_REPORT,16384);self.assertEqual(host.MAX_N0A_REPORT,4096)
        self.assertEqual((host.DISK_FILE_CAP,host.LAUNCH_FREE,host.STOP_FREE),(22*2**30,24*2**30,4*2**30))
        payload=functions['payload']
        for name in ('n0a/actor.exe','n0a/build-manifest.json','.github/windows_n0a_control.py','.github/windows_n0a_guest.py'):
            self.assertIn(name,payload)

if __name__=='__main__':unittest.main()
