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

class CaptureHostTests(unittest.TestCase):
    def handler(self,value,body=False):
        item=HandlerTests.handler(self,value,'/cap/n0a-runner-flow' if body else '/cap/n0a-capture-result')
        item.connection=Mock();item.server.capture_enabled=True
        item.server.capture_work_deadline=500;item.server.capture_accepting=True
        item.server.capture_lock=threading.Lock();item.server.capture_received_at=None
        item.server.capture_commitment=None;item.server.capture_commitment_error=False
        item.server.capture_private_body=None;item.server.capture_body_attempted=False
        item.server.capture_body_received=threading.Event();item.server.received.set()
        item.server.original_received_at=40
        return item
    def test_disabled_before_media(self):
        with patch.object(host,'n0a_helpers',return_value=SimpleNamespace(EXECUTION_ENABLED=True)),patch.object(host,'capture_helpers',return_value=SimpleNamespace(CAPTURE_EXECUTION_ENABLED=False)),patch.object(host,'load') as load:
            with self.assertRaises(PermissionError):host.host(SimpleNamespace(n0a=True,n0a_capture_runner=True))
            load.assert_not_called()
    def test_actual_wrapper_then_private_body(self):
        engine=host.n0a_helpers();expected={'case_nonce':'a'*32,'actor_sha256':'b'*64}
        legacy={'schema_version':1,**expected,'report':None,'launcher':engine.default_host_n0a()['launcher']}
        raw=b'private-flow-fixture';commit={'sha256':hashlib.sha256(raw).hexdigest(),'bytes':len(raw),
            'contained_report_sha256':'c'*64,'ordinary_report_sha256':'d'*64}
        item=self.handler({'schema_version':2,'legacy':legacy,'flow_commitment':commit});item.server.n0a_expected=expected
        with patch.object(host.time,'monotonic',return_value=42):item.do_POST()
        self.assertTrue(item.server.n0a_received.is_set());self.assertEqual(item.server.capture_commitment,commit)
        item.path='/cap/n0a-runner-flow';item.rfile=io.BytesIO(raw);item.headers={'Content-Length':str(len(raw))}
        with patch.object(host.time,'monotonic',return_value=43):item.do_POST()
        self.assertTrue(item.server.capture_body_received.is_set());self.assertEqual(item.server.capture_private_body,raw)
        self.assertNotIn('case_nonce',json.dumps(item.server.n0a_result))
    def test_bad_commit_cannot_erase_valid_legacy(self):
        item=self.handler({});legacy={'result':{'status':'connect_succeeded'}}
        adapter=SimpleNamespace(validate_capture_envelope=Mock(return_value={'legacy':legacy,'commitment':None,'commitment_error':True}))
        with patch.object(host,'capture_helpers',return_value=adapter),patch.object(host.time,'monotonic',return_value=42):item.do_POST()
        self.assertIs(item.server.n0a_result,legacy);self.assertTrue(item.server.capture_commitment_error)
        item.rfile=io.BytesIO(b'{}');item.headers={'Content-Length':'2'}
        item.do_POST();item.send_error.assert_called_with(409);self.assertIs(item.server.n0a_result,legacy)
    def test_exact_private_body_once_and_late_rejection(self):
        for accepted,now in ((True,45),(False,45),(True,52)):
            item=self.handler({},True);item.server.n0a_received.set();item.server.capture_received_at=42;item.server.capture_commitment={}
            adapter=SimpleNamespace(MAX_FLOW=65536,accept_private_body=Mock(return_value=accepted))
            with patch.object(host,'capture_helpers',return_value=adapter),patch.object(host.time,'monotonic',return_value=now):item.do_POST()
            self.assertEqual(item.server.capture_body_received.is_set(),accepted and now<52)
            self.assertTrue(item.server.capture_body_attempted)
            item.do_POST();item.send_error.assert_called_with(409)
    def test_route_bounds_duplicate_constants_and_recursion_closed(self):
        for raw in (b'{"x":1,"x":2}',b'{"x":NaN}',b'{"x":Infinity}',b'['*2000+b']'*2000):
            item=self.handler({});item.rfile=io.BytesIO(raw);item.headers={'Content-Length':str(len(raw))}
            with patch.object(host.time,'monotonic',return_value=42):item.do_POST()
            item.send_error.assert_called_with(400);self.assertFalse(item.server.n0a_received.is_set())
        item=self.handler({});item.headers={'Content-Length':'4097'}
        with patch.object(host.time,'monotonic',return_value=42):item.do_POST()
        item.send_error.assert_called_with(400)
    def test_read_drip_clips_absolute_deadline(self):
        item=SimpleNamespace(connection=Mock(),rfile=Mock());item.rfile.read1.return_value=b'x'
        with patch.object(host.time,'monotonic',side_effect=[8,9,10]):
            with self.assertRaises(ValueError):host.read_capture_request(item,3,10)
        self.assertEqual(item.rfile.read1.call_count,2)
        self.assertEqual([c.args[0] for c in item.connection.settimeout.call_args_list],[2,1])
    def test_final_read_at_boundary_rejected(self):
        item=SimpleNamespace(connection=Mock(),rfile=io.BytesIO(b'x'))
        with patch.object(host.time,'monotonic',side_effect=[9,10]):
            with self.assertRaises(ValueError):host.read_capture_request(item,1,10)
    def test_request_bound_minimum(self):
        server=SimpleNamespace(capture_work_deadline=500,original_received_at=40,capture_received_at=155)
        self.assertEqual(host.capture_request_deadline(server,True),160)
        server.capture_work_deadline=158;self.assertEqual(host.capture_request_deadline(server,True),158)
        server.capture_received_at=100;self.assertEqual(host.capture_request_deadline(server,True),110)
    def test_freeze_during_read_rejects_commit_and_no_lock_held(self):
        item=self.handler({});adapter=SimpleNamespace(validate_capture_envelope=Mock(return_value={'legacy':{},'commitment':None,'commitment_error':False}))
        def read(_):
            self.assertTrue(item.server.capture_lock.acquire(False));item.server.capture_lock.release()
            item.server.capture_accepting=False;return b'{}'
        item.rfile=SimpleNamespace(read1=read)
        with patch.object(host,'capture_helpers',return_value=adapter),patch.object(host.time,'monotonic',return_value=42):item.do_POST()
        self.assertFalse(item.server.n0a_received.is_set());item.send_error.assert_called_with(400)
    def test_legacy_route_rejected_capture_on(self):
        item=self.handler({});item.path='/cap/n0a-result';item.do_POST()
        item.send_error.assert_called_with(400)
    def test_body_wait_deadline_not_renewed(self):
        item=self.handler({});server=item.server;server.n0a_received.set();server.capture_received_at=100;server.capture_commitment={}
        server.capture_body_received=Mock();server.capture_body_received.wait.return_value=False
        qemu=Mock();qemu.poll.return_value=None;disk=Mock();disk.stat.return_value.st_size=1
        with patch.object(host.time,'monotonic',return_value=110):
            self.assertEqual(host.wait_for_n0a(server,500,SimpleNamespace(reason=None),disk,qemu,{}),'capture_body_deadline')
    def test_finish_snapshot_original_deadline_and_private_parse(self):
        item=self.handler({});server=item.server;server.n0a_received.set();server.capture_body_received.set()
        server.capture_private_body=b'private';server.capture_commitment={};server.n0a_result={}
        owner=Mock();owner.output_path=Path('owned/capture.pcap')
        def finish(**kwargs):
            self.assertFalse(server.capture_accepting);self.assertEqual(kwargs,{'cleanup_deadline':970});return {'cleanup_confirmed':True}
        owner.finish.side_effect=finish
        adapter=SimpleNamespace(unavailable=Mock(return_value={'status':'inconclusive'}),parse_before_cleanup=Mock(return_value={'tentative':True}))
        config={'run_nonce':'a'*32,'source_commit':'b'*40,'vm_mac':'525400123456'}
        n0a={'case_nonce':'c'*32,'actor_sha256':'d'*64,'actor_source_sha256':'e'*64,'identity_source_sha256':'f'*64,'runner_port':12345}
        with patch.object(host,'capture_helpers',return_value=adapter),patch.object(host.time,'monotonic',return_value=900):
            facts,result=host.finish_capture_before_cleanup(owner,server,config,n0a,{},1000,True)
        self.assertEqual(result,{'tentative':True});self.assertTrue(facts['cleanup_confirmed'])
        call=adapter.parse_before_cleanup.call_args;self.assertEqual(call.args[2],b'private')
        self.assertEqual(call.args[3]['endpoint']['destination_port'],12345)
        self.assertTrue(call.kwargs['terminal_before_shutdown']);self.assertTrue(call.kwargs['header_before_link'])
        adapter.parse_before_cleanup.return_value={'capture_read_cleanup_confirmed':False}
        with patch.object(host,'capture_helpers',return_value=adapter),patch.object(host.time,'monotonic',return_value=900):
            facts,_=host.finish_capture_before_cleanup(owner,server,config,n0a,{},1000,True)
        self.assertFalse(facts['cleanup_confirmed'])

    def test_owner_failure_no_parse_and_lock_failure_still_finishes(self):
        for throws in (True,False):
            item=self.handler({});item.server.capture_lock=Mock();item.server.capture_lock.acquire.return_value=False
            owner=Mock();owner.finish.side_effect=RuntimeError('PRIVATE') if throws else None
            owner.finish.return_value={'cleanup_confirmed':True}
            adapter=SimpleNamespace(unavailable=Mock(return_value={'status':'inconclusive'}),parse_before_cleanup=Mock())
            with patch.object(host,'capture_helpers',return_value=adapter),patch.object(host.time,'monotonic',return_value=900):
                facts,result=host.finish_capture_before_cleanup(owner,item.server,None,None,{},1000,False)
            owner.finish.assert_called_once();adapter.parse_before_cleanup.assert_not_called()
            self.assertNotIn('PRIVATE',json.dumps((facts,result)))
    def test_capture_cleanup_never_resignals_qemu_retains_unknown(self):
        qemu=Mock();qemu.poll.return_value=None;public={};work=Mock()
        # This fixture models the Linux-only host signal contract, even on Windows CI.
        with patch.object(host.signal,'SIGXFSZ',25,create=True), patch.object(host,'finish_capture_server',return_value=True):
            host.finalize_owned(public,Mock(),work,qemu=qemu,capture_facts={},cleanup_deadline=100)
        qemu.kill.assert_not_called();qemu.wait.assert_not_called();self.assertFalse(public['vm_destroyed'])
        self.assertTrue(public['teardown_diagnostic']['work_retained'])
    def test_capture_tpm_poll_and_kill_errors_do_not_skip_owned_wait(self):
        for error in ('poll','kill'):
            tpm=Mock();tpm.poll.return_value=None;getattr(tpm,error).side_effect=OSError('PRIVATE')
            public={}
            with patch.object(host,'finish_capture_server',return_value=True),patch.object(host.time,'monotonic',return_value=99):
                host.finalize_owned(public,Mock(),Mock(),tpm=tpm,capture_facts={'cleanup_confirmed':True},cleanup_deadline=100)
            tpm.kill.assert_called_once();tpm.wait.assert_called_once_with(timeout=1)
            self.assertFalse(public['vm_destroyed']);self.assertTrue(public['teardown_diagnostic']['work_retained'])
            self.assertNotIn('PRIVATE',json.dumps(public))
    def test_shutdown_registered_before_start_and_clipped(self):
        server=Mock();server.capture_shutdown_thread=None;server.socket.fileno.return_value=-1
        serve=Mock();serve.ident=1;serve.is_alive.return_value=False;shutdown=Mock();shutdown.is_alive.return_value=False
        def start():
            self.assertIs(server.capture_shutdown_thread,shutdown);server.capture_shutdown_ok=True
        shutdown.start.side_effect=start
        with patch.object(host.threading,'Thread',return_value=shutdown),patch.object(host.time,'monotonic',return_value=99):
            self.assertTrue(host.finish_capture_server(server,serve,100,{}))
        shutdown.join.assert_called_once_with(timeout=1);serve.join.assert_called_once_with(timeout=1)
    def test_shutdown_uncertain_or_budget_exhausted_not_restarted(self):
        for alive in (True,False):
            server=Mock();server.capture_shutdown_thread=None;server.socket.fileno.return_value=-1
            serve=Mock();serve.ident=1;serve.is_alive.return_value=alive
            with patch.object(host.threading,'Thread') as constructor,patch.object(host.time,'monotonic',return_value=100):
                self.assertFalse(host.finish_capture_server(server,serve,100,{}));constructor.assert_not_called()
        server.capture_shutdown_thread=Mock();server.capture_shutdown_thread.is_alive.return_value=True
        with patch.object(host.threading,'Thread') as constructor,patch.object(host.time,'monotonic',return_value=99):
            self.assertFalse(host.finish_capture_server(server,serve,100,{}));constructor.assert_not_called()
    def test_exceptional_owner_finish_exact_fallback_never_qualifies(self):
        server=self.handler({}).server;owner=Mock();owner.finish.side_effect=RuntimeError('PRIVATE')
        owner.process.poll.return_value=0;owner.child.poll.side_effect=[None,0]
        owner.close_ledger=SimpleNamespace(uncertain=False)
        names=('root_fd','stderr_read','stderr_write','dummy_fd','child_channel','channel')
        for name in names:setattr(owner,name,None)
        owner._close.side_effect=lambda name:setattr(owner,name,None)
        adapter=SimpleNamespace(unavailable=Mock(return_value={'status':'inconclusive'}),parse_before_cleanup=Mock())
        public={}
        with patch.object(host,'capture_helpers',return_value=adapter),patch.object(host.time,'monotonic',return_value=969):
            facts,result=host.finish_capture_before_cleanup(owner,server,None,None,public,1000,False)
        owner.process.kill.assert_not_called();owner.child.kill.assert_called_once();owner.child.wait.assert_called_once_with(timeout=1)
        self.assertFalse(facts['cleanup_confirmed']);self.assertTrue(public['capture_owner_fallback']['process_exit_confirmed'])
        self.assertTrue(public['capture_owner_fallback']['descriptors_closed']);adapter.parse_before_cleanup.assert_not_called()
    def test_exceptional_fallback_poll_kill_wait_close_failures_closed(self):
        for failure in ('poll','kill','wait','close'):
            owner=Mock();owner.process=None;owner.child.poll.return_value=None;owner.close_ledger=SimpleNamespace(uncertain=False)
            names=('root_fd','stderr_read','stderr_write','dummy_fd','child_channel','channel')
            for name in names:setattr(owner,name,None)
            owner._close.side_effect=lambda name:setattr(owner,name,None)
            if failure=='close':owner._close.side_effect=OSError('PRIVATE')
            else:getattr(owner.child,failure).side_effect=OSError('PRIVATE')
            with patch.object(host.time,'monotonic',return_value=100):result=host.fallback_capture_owner(owner,100)
            self.assertTrue(result['attempted']);self.assertFalse(result['process_exit_confirmed'])
            if failure=='poll':
                owner.child.kill.assert_called_once();owner.child.wait.assert_called_once_with(timeout=0)
            if failure=='kill':owner.child.wait.assert_called_once_with(timeout=0)
            if failure=='wait':owner.child.wait.assert_called_once_with(timeout=0)
            if failure=='close':self.assertFalse(result['descriptors_closed'])
            self.assertEqual(owner._close.call_count,6);self.assertNotIn('PRIVATE',json.dumps(result))
    def test_capture_live_failures_abort_wait_and_reach_owned_finish(self):
        for change in ('overflow','qemu_dump_write_error','ipc','child_exit','capture_error','premature_final'):
            owner=Mock();owner.errors=set();owner.ipc_eof=False
            owner.child.poll.return_value=None
            status={'phase':'active','overflow':False,'qemu_dump_write_error':False,'errors':[]}
            if change in ('overflow','qemu_dump_write_error'):status[change]=True
            elif change=='ipc':owner.errors={'ipc'}
            elif change=='child_exit':owner.child.poll.return_value=3
            elif change=='capture_error':status['errors']=['write']
            else:status['phase']='final'
            owner.poll_status.return_value=status
            server=self.handler({}).server;server.n0a_received=Mock();server.n0a_received.wait.return_value=False
            adapter=SimpleNamespace(unavailable=Mock(return_value={'status':'inconclusive'}),parse_before_cleanup=Mock())
            public={}
            with patch.object(host,'capture_helpers',return_value=adapter):
                with self.assertRaises(host.CaptureTransportFailure):
                    try:host.wait_for_n0a(server,500,SimpleNamespace(reason=None),Mock(),Mock(),public,owner)
                    finally:host.finish_capture_before_cleanup(owner,server,None,None,public,1000,True)
            self.assertIn('capture_abort',public);owner.fail.assert_called_once();owner.finish.assert_called_once()
    def test_capture_body_wait_polls_even_after_receipt(self):
        owner=Mock();owner.errors=set();owner.ipc_eof=False;owner.child.poll.return_value=None
        healthy={'phase':'active','overflow':False,'qemu_dump_write_error':False,'errors':[]}
        owner.poll_status.side_effect=[healthy,{**healthy,'overflow':True}]
        server=self.handler({}).server;server.n0a_received.set();server.capture_commitment={};server.capture_received_at=100
        server.capture_body_received=Mock();server.capture_body_received.wait.return_value=False
        with self.assertRaises(host.CaptureTransportFailure):
            host.wait_for_n0a(server,500,SimpleNamespace(reason=None),Mock(),Mock(),{},owner)
        self.assertEqual(owner.poll_status.call_count,2)
    def test_startup_and_two_phase_finalization_source(self):
        source=(ROOT/'.github/windows_identity_direct_stage0.py').read_text()
        functions={n.name:ast.get_source_segment(source,n) for n in ast.parse(source).body if isinstance(n,ast.FunctionDef)}
        body=functions['host'];self.assertIn('outer_deadline = deadline + 120',body)
        self.assertIn('new_owner(capture_root, outer_deadline)',body)
        self.assertLess(body.index('capture_owner = capture_helpers().new_owner'),body.index('capture_owner.start()'))
        self.assertIn('admit(package.stat().st_size,',body)
        self.assertIn('filter-dump,id=n0a-capture,netdev=vmnet,file={capture_owner.fifo_path},queue=all,status=on,maxlen=262144',body)
        self.assertIn('capture_owner.spawn(limited_command(qemu_command, DISK_FILE_CAP))',body)
        self.assertLess(body.index("qmp.execute('set_link', {'name': 'vmnet', 'up': False})"),body.index('capture_owner.wait_header'))
        self.assertLess(body.index('capture_owner.wait_header'),body.index("qmp.execute('set_link', {'name': 'vmnet', 'up': True})"))
        self.assertNotIn('watch.register(capture_owner',body)
        self.assertLess(body.index('finish_capture_before_cleanup(capture_owner'),body.index('finalize_owned(public'))
        self.assertLess(body.index('finalize_owned(public'),body.index('capture_helpers().qualify('))
        self.assertIn("'n0a-capture-public.json'",body)
        self.assertIn("if capture: archive.write(ROOT / '.github/windows_n0a_flow.py'",functions['payload'])

def write_payload_fixtures(root):
    """Actual ZIP writer; synthetic authenticated inputs, never runnable binaries."""
    import io
    import zipfile
    import sys
    root=Path(root)
    root.mkdir(parents=True,exist_ok=False)
    sys.path.insert(0,str(ROOT))
    import install_runtime
    actor=root/'identity-fixture.exe';actor.write_bytes(b'nonexecuted-identity-fixture')
    native=root/'n0a-fixture.exe';native.write_bytes(b'nonexecuted-production-shaped-fixture'*16)
    manifest=root/'manifest.json';manifest.write_text('{"testOnly":false}',encoding='ascii')
    bundle=root/'bundle.zip'
    with zipfile.ZipFile(bundle,'w') as archive:
        archive.writestr('build-manifest.json','{"fixture":true}')
        archive.writestr('wxc-exec.exe',b'nonexecuted-G-fixture')
        archive.writestr('MXC-LICENSE.md',b'fixture')
    bundle_data=bundle.read_bytes()
    n0a={'actor':native,'manifest':manifest,'config':{
        'actor_sha256':hashlib.sha256(native.read_bytes()).hexdigest(),
        'manifest_sha256':hashlib.sha256(manifest.read_bytes()).hexdigest()}}
    def extract(data,destination):
        with zipfile.ZipFile(io.BytesIO(data)) as archive:
            for name in ('wxc-exec.exe','MXC-LICENSE.md'):
                (destination/name).write_bytes(archive.read(name))
    base={'python-embed.zip','actor.exe','stage0-input.json','g/build-manifest.json',
          'g/wxc-exec.exe','g/MXC-LICENSE.md',*host.GUEST_SOURCES}
    extra={'n0a/actor.exe','n0a/build-manifest.json','.github/windows_n0a_control.py','.github/windows_n0a_guest.py'}
    for mode,optional,capture,expected in [('baseline',None,False,base),('n0a',n0a,False,base|extra),
            ('capture',n0a,True,base|extra|{'.github/windows_n0a_flow.py'})]:
        target=root/(mode+'.zip')
        with patch.object(host,'verify_python',return_value=b'nonexecuted-python-fixture'),\
             patch.object(install_runtime,'_g_bundle_bytes',return_value=bundle_data),\
             patch.object(install_runtime,'_extract_g_bundle',side_effect=extract):
            digest=host.payload(root/'unused-python.zip',actor,hashlib.sha256(actor.read_bytes()).hexdigest(),
                                bundle,target,n0a=optional,capture=capture)
        assert digest==hashlib.sha256(target.read_bytes()).hexdigest()
        with zipfile.ZipFile(target) as archive:
            names=archive.namelist()
            assert len(names)==len(expected) and set(names)==expected
            if capture:assert archive.read('.github/windows_n0a_flow.py')==(ROOT/'.github/windows_n0a_flow.py').read_bytes()
    forbidden=['.github/windows_n0a_capture_adapter.py','capture.pcap','private-n0a/runner-flow.json','n0a/TEST_ONLY.exe']
    with zipfile.ZipFile(root/'capture.zip') as archive:
        entries={name:archive.read(name) for name in archive.namelist()}
    for index,name in enumerate(forbidden):
        with zipfile.ZipFile(root/('bad-%d.zip'%index),'w') as archive:
            for member,data in entries.items():
                archive.writestr(name if member=='.github/windows_n0a_flow.py' else member,data)
    return {'baseline':10,'n0a':14,'capture':15,'negative_cases':len(forbidden)}

class GeneratedPayloadTests(unittest.TestCase):
    def test_actual_zip_writer_exact_three_modes_and_forbidden_replacements(self):
        with tempfile.TemporaryDirectory() as root:
            result=write_payload_fixtures(Path(root)/'owned')
            self.assertEqual(result,{'baseline':10,'n0a':14,'capture':15,'negative_cases':4})

if __name__=='__main__':unittest.main()
