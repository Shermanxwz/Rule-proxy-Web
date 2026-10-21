"""UDP6 host dispatch/lifecycle contracts; no VM or network execution."""
import ast
import hashlib
import importlib.util
from pathlib import Path
from types import SimpleNamespace
import unittest
from unittest.mock import Mock,patch
ROOT=Path(__file__).resolve().parents[1]
spec=importlib.util.spec_from_file_location('udp6_direct_host_test',ROOT/'.github/windows_identity_direct_stage0.py');h=importlib.util.module_from_spec(spec);spec.loader.exec_module(h)

class HostTests(unittest.TestCase):
    def test_disabled_before_media_even_base_enabled(self):
        with patch.object(h.udp6_capture_helpers().helper('control'),'EXECUTION_ENABLED',False),patch.object(h,'EXECUTION_ENABLED',True),patch.object(h,'load') as load:
            with self.assertRaises(PermissionError):h.host(SimpleNamespace(n0a_udp6_runner=True))
            load.assert_not_called()
    def test_mutually_exclusive_intents_before_any_load(self):
        for key in ('n0a','n0a_capture_runner','n0a_udp_runner','n0a_udp_parent_runner'):
            with patch.object(h,'EXECUTION_ENABLED',True),patch.object(h,'load') as load:
                with self.assertRaises(ValueError):h.host(SimpleNamespace(n0a_udp6_runner=True,**{key:True}))
                load.assert_not_called()
    def test_routes_only_new_protocol(self):
        handler=object.__new__(h.UDP6ClosedHandler);handler.server=SimpleNamespace(capability='c')
        with patch.object(handler,'send_error') as error,patch.object(handler,'do_udp_POST') as post:
            for name in ('n0a-result','udp-capture-result','udp-parent-capture-result','udp-runner-flow','n0a-runner-flow'):
                handler.path='/c/'+name;handler.do_POST();error.assert_called_with(404)
            post.assert_not_called()
            handler.path='/c/udp6-capture-result';handler.do_POST();post.assert_called_with(False)
            handler.path='/c/udp6-runner-flow';handler.do_POST();post.assert_called_with(True)
    def test_payload_rejects_mixed_mode_before_work(self):
        for key in ('n0a','udp','parent_udp','capture'):
            with self.assertRaises(ValueError):h.payload(None,None,None,None,None,udp6={},**{key:True if key=='capture' else {}})
    def test_same_bounded_handler_no_ipv4_schema_alias(self):
        tree=ast.parse(Path(h.__file__).read_text());classes={n.name:n for n in tree.body if isinstance(n,ast.ClassDef)}
        old=next(n for n in classes['ParentUDPClosedHandler'].body if isinstance(n,ast.FunctionDef) and n.name=='do_udp_POST')
        new=next(n for n in classes['UDP6ClosedHandler'].body if isinstance(n,ast.FunctionDef) and n.name=='do_udp_POST')
        class Normalize(ast.NodeTransformer):
            def visit_Name(self,n):
                if n.id=='udp6_capture_helpers':n.id='parent_udp_capture_helpers'
                return n
        self.assertEqual(ast.dump(old,include_attributes=False),ast.dump(Normalize().visit(new),include_attributes=False))
    def test_finalizer_single_stop_and_parse_before_legacy_cleanup(self):
        adapter=Mock();adapter.unavailable.return_value={'status':'inconclusive'};adapter.flow_context.return_value={};adapter.parse_before_cleanup.return_value={}
        owner=Mock();owner.finish.return_value={'cleanup_confirmed':True};owner.output_path=Path('owned')
        server=SimpleNamespace(capture_accepting=True,capture_lock=Mock(),capture_private_body=b'x',n0a_received=Mock(),capture_body_received=Mock())
        server.capture_lock.acquire.return_value=True;server.n0a_received.is_set.return_value=True;server.capture_body_received.is_set.return_value=True
        with patch.object(h,'udp6_capture_helpers',return_value=adapter),patch.object(h.time,'monotonic',return_value=100):
            facts,result=h.finish_udp6_capture_before_cleanup(owner,server,{}, {},{},200,True)
        owner.finish.assert_called_once_with(cleanup_deadline=170);adapter.parse_before_cleanup.assert_called_once();self.assertFalse(server.capture_accepting)
    def test_finalizer_exception_attempts_exact_owner_fallback(self):
        owner=Mock();owner.finish.side_effect=OSError('private');public={}
        with patch.object(h,'fallback_capture_owner',return_value={'attempted':True}) as fallback:
            facts,_=h.finish_udp6_capture_before_cleanup(owner,None,None,None,public,200,False)
        fallback.assert_called_once_with(owner,170);self.assertFalse(facts['cleanup_confirmed'])
    def test_provenance_registered_before_admit_recheck_before_stop_close_before_delete(self):
        source=Path(h.__file__).read_text();body=source[source.index('def host(args):'):source.index('\ndef main(')]
        self.assertLess(body.index('mapped_observer = optional_udp.new_provenance'),body.index('mapped_observer.admit()'))
        self.assertLess(body.index('mapped_observer.admit()'),body.index("'up': True"))
        self.assertLess(body.index('mapped_observer.recheck_before_stop()'),body.index('finish_udp6_capture_before_cleanup('))
        self.assertLess(body.index('mapped_observer.close(cleanup_deadline=outer_deadline-25)'),body.index('finalize_owned('))
        self.assertIn("deadline = time.monotonic() + available - 120",body);self.assertIn('outer_deadline = deadline + 120',body)
        self.assertIn("new_provenance(qemu, Path(shutil.which('qemu-system-x86_64')).resolve(), deadline)",body)
        self.assertNotIn("ipv6=",body);self.assertIn("'-netdev', 'user,id=vmnet'",body)

# Exact baseline AST pins from reviewed archive 0b08ffaf; dispatch functions are
# separately tested above. Every existing helper/class remains byte-AST equal.
LEGACY_AST_PINS={'load': '51461bc5593165cae9d8bfca0db3e2602a37d250cd61eb350131e4c4ed77bec9', 'preparation_record': 'a3ab6934a4049da3ae6cdeff34fbf84a74359b0faf3d0953343e7719f5d6861e', 'preparation_checkpoint': '0e87fb19af8cd01d4d1c91be441614f1a7fae1f8ff8cd41d2e455b60a40e529b', 'apt_simulated_packages': '07e892b893f14bd99a9a75fdea8978a6291a7b06ad9230456b83a80cffab9e64', 'reviewed_apt_plan': '8a365a71c85a7afd54777af5e4e8b91471371e521a17724d3b25a71f250b07d9', 'check_apt_plan': 'f1b70e7d357c9ec7521e94d5bb02efd12602f4b37ae12c8958de8efffaf660a1', 'checked_members': '8b1bd257f048eafa4e5294b955120a4085286598131231ba3f1ab1c0ac46ff6b', 'verify_python': '85bd1ebbbbe543e64b612ee1bee194a3dc9e82cf8f1b32893f9e5af4d28a58cb', 'download_python': '33095c7e36c23e0a3e6f0b7244f75a8dc4d6bd9c525259d5398e3b58ce7539e1', 'verify_guest_import_path': 'dc55afe1c862ffc2231512aa5fd4f4d585478bb0470f31a00774812616670e87', 'proof_helpers': 'b472ec1b729da1b81e87f1bb8d3d6a56737a82829bb877f026d7d5ad0aa848b5', 'closed_failure': '54e2e6822dfd89fbfb58a0bd3d5394fca6227e0c1821aca607a114d69ac2d5ca', 'project_stage0': 'b3e0e6ee940ecefd92e06a1f0a22498b3f4347c09a2df9abc3c8277968af68c7', 'validate_guest': 'e3fd2a08b82ad042f0a5386379d78f78416a482f3ac81b8a3f1bc0401845a91a', 'guest': '233d82c2b783fbf65f8566c3a452700258345a879206143baa9bbb445783b797', 'record_breadcrumb': 'db41352f60bb8ae582c014a502fa11abe45c88c80814980c53b73cf3210db0d4', 'n0a_helpers': 'cd5c4e28c0e1f77080c1e51bf37f347f8e7a86290404fb1dd0e5df62300905a8', 'capture_helpers': '8b3538d480c5a3b728a7667705dac8ea4b31a7a1f1df7d03542497cb03663aad', 'udp_helpers': 'f0b7466b08dc7bac573d1aed8bdde63af08029ce025541c2375275c7ca89af06', 'udp_capture_helpers': '14d581b3cf55400ae30c69833e26d9f03bf895fcc8c6966f59c87d8564d0bde8', 'parent_udp_capture_helpers': '49800063ef2b8a3f68b209c7e2a0792cc699f55f1bf547993ebfe4398aceb639', 'CaptureTransportFailure': '6cee041904471292e23bd78edab6e1b9e1e5634e42ff8e9d6a834161c3babb28', 'observe_capture': '0808377caf2ce94c6bf41bcff38ea2972524e7ad0071c0a52e91e249a91c27fe', 'capture_request_deadline': '584405519a65a564756991fe682f271caa035efaa8ab7e9deb28e70c687eaa76', 'read_capture_request': 'bc66b3b51b5c6d69e8cbc2dde2b25a62eedcd00d301c20d4756088f0c40001b8', 'reject_capture_constant': '7a056db612a4582b52b1192e1e1be32c7e0835a762e9dd09896b488813813b4c', 'fallback_capture_owner': 'b92a81f2a986acf0b938e86831e0e7336ec345b54880c074b1aa77e586c728ad', 'finish_capture_before_cleanup': 'a85761e170f9cc0ff887b2e8d8b2a60baee091a89a9ce84a917f11ab19117ce5', 'finish_parent_capture_before_cleanup': '82a05e8edb15a97eef314411752e84b0a46f6322f5ea3ca910b713d007282270', 'cleanup_remaining': '13db0f0ae1879fb841beb64a88da707cca19a4e3cdd35d7277660c643f0349ba', 'finish_capture_server': '40a7941dc5966f88a6abfcf5c2fbcfefff4e92c3fa5e0f8a038ff4a6c29d3048', 'finalize_capture_owned': 'a32b41e20d573f40c63bd58bb985de41cb837af85432bc32d2bffd70ab868be4', 'verify_n0a_inputs': '3de02b197492b794dc805fb7e60bfda7e532da6825d420e65f4c977b799ebf82', 'n0a_wait_deadline': 'ff5653b84cf0abe5d86f113d02091e7bae68deba57baf4d651cb1ee2b7717dc7', 'wait_for_n0a': 'c5912750b833d258f3fee6fb3215054654eeb0d3846033be6b7f3fbbf5281244', 'collect_n0a_result': '72c29be026a89dd829f11c3edb99414ad909152837eb6bc948c9270fa6650ebf', 'compose_n0a_public': 'ee6f328027be4f9111b902f862354b372caa65babf3c70c81e7ed198f10f4954', 'ClosedServer': '0e147ef18528ed1dcd5a922fb84eaf06ff283239d79d4e13a9a0dc2c1e97234d', 'ClosedHandler': '69c60168b164cddcfbe50803760bfa22292f2a509e914add0815a5d508be362e', 'UDPClosedServer': '3d12b67f7d26474c39c4f8fd4876815cee211aa37a3bf2026c02a0c7b5d7be66', 'UDPClosedHandler': 'b0e23d845f203b34272e7943493ab58e1d10e971b28b427046dd8445e3169e63', 'ParentUDPClosedServer': '0723dec5e431a88feffeeab24c97606742dc9271e37d9a4a0754366e6e1fdfcd', 'ParentUDPClosedHandler': '205d93c3e07aac26a5c3713c219a5223734ca0e1d3f41189154365590a6decaa', 'limited_command': '5afc7a5e39aa609cd378552117897e5bc2cadd331b72b219c551560c77df9620', 'CapacityWatch': '5a58f2ce87d0e46eef2f48ba0de0a7ff6e9a7864909172e33aab23cb7ecf3a54', 'reconcile_capacity': '05810f9eebdc1cc956048cc68d2ba6db361a2e1f62a1de5eeb1c0227fde99fb4', 'interrupted': '9f69ffabd622a00eef01c7fe2fa48e0e8b9966720dfa43a8f8ff1c3333b41fd5', 'remaining_budget': '026597d0372a939bd51f492b471a07ec666709c5b54a8bf25ea2e90bcd7fa512', 'VMWorkBudgetInsufficient': '26faa260d4409da902d7007088495ef51a1f451934e750cc9cfa648492e7ef37', 'require_vm_work_budget': '697675b147b20075a05365f7acdbe6842a017a77acc4d523b28b1df5aff8afcc', 'run_bounded': '2efcfd9643ddb7519882f7242ffd815fdb9961b655b531cc559361afa2da0062', 'teardown_error': '37e8c7fd08ed7165b4a026775945da801a536b3fbcaed741a7e95ae72614884c', 'new_teardown_facts': 'd52f10ea0a782fd67f398ce3cd7c9f9fc15ba3f2cfe277f9f6668716e1c5c4a2', 'exit_observation': '93fb868a61b1af94eeb24e4286987018d1619502797a8142b1cc87ac47a3b125', 'observe_qmp_closed': '5e2c3a56b182a93e1a9fd5be5078f6b590920b4afdd880a22682b2f34143c3da', 'cleanup_owned': '88c22b93aee31f15c8bb888b86862278e8961969e2441d250ceaedac3127e3cb', 'finalize_owned': '77d23e539773d82cbe13043ff61fa412064928da2bc1298142dfbf1eece382e1', 'scoped_qmp_class': '4cf5f409117dc50025fe137fe94e28864e3e3a0f55db068276b1878b9aba8509', 'merge_direct_result': '4ef32f05747942b23398a471b6a8a26b9a2db5502d4ac5abc7d57dea1fd9cf62', 'EarlyGuestFailure': '43acb26eba408a7f70e9fa01ffe0d32433f22402865be1d1ea122d5a365ccbf4', 'parse_early_guest': 'f6cdba938469801c8f452c1144a61e6fd10bb05b29c1de078d077de3ca9ba2c3', 'EarlyGuestSerial': 'd60c5a4c45e766eba2437eab357f637d5d7cf17694320d356998a56aa330b0c4', 'observe_guest_serial': 'c450bd63ab207e20b5f4e90e27fb0797efad2f4513ee1c12fcae40ccc5b5d5e7', 'BootstrapTimeout': '638a9d2c0c69b2faa2e342c4c6c68ad8ce307762a017827e99eb5cdeb493ac2b', 'observe_bootstrap': '723b87a91dceafb373c6db43b502883ee3884b821d14ba1bd0ecd948e7279ad6', 'download_direct_iso': 'c5ff001f6a416c1be00a868c47d25f769520e81e50f98ce7eab048f6ad1659c4'}

class LegacyParityTests(unittest.TestCase):
    def test_all_existing_non_dispatch_ast_unchanged(self):
        nodes={n.name:n for n in ast.parse(Path(h.__file__).read_text()).body if isinstance(n,(ast.FunctionDef,ast.ClassDef))}
        for name,pin in LEGACY_AST_PINS.items():
            self.assertEqual(hashlib.sha256(ast.dump(nodes[name],include_attributes=False).encode()).hexdigest(),pin,name)
