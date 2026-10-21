import ast
import importlib.util
import json
from pathlib import Path
from types import SimpleNamespace
import unittest
from unittest.mock import patch
ROOT=Path(__file__).resolve().parents[1]
spec=importlib.util.spec_from_file_location('parent_udp_host_test',ROOT/'.github/windows_identity_direct_stage0.py');h=importlib.util.module_from_spec(spec);spec.loader.exec_module(h)
class HostTests(unittest.TestCase):
    def test_disabled_before_media(self):
        adapter=SimpleNamespace(helper=lambda _:SimpleNamespace(EXECUTION_ENABLED=False))
        with patch.object(h,'EXECUTION_ENABLED',True),patch.object(h,'parent_udp_capture_helpers',return_value=adapter),patch.object(h,'load') as load:
            with self.assertRaises(PermissionError):h.host(SimpleNamespace(n0a_udp_parent_runner=True))
            load.assert_not_called()
    def test_mutually_exclusive_before_media(self):
        with patch.object(h,'EXECUTION_ENABLED',True),patch.object(h,'load') as load:
            with self.assertRaises(ValueError):h.host(SimpleNamespace(n0a_udp_parent_runner=True,n0a_udp_runner=True))
            load.assert_not_called()
    def test_new_routes_no_old_schema_fallback(self):
        handler=object.__new__(h.ParentUDPClosedHandler);handler.server=SimpleNamespace(capability='c')
        with patch.object(handler,'send_error') as error,patch.object(handler,'do_udp_POST') as post:
            for path in ('udp-capture-result','udp-runner-flow','n0a-result'):
                handler.path='/c/'+path;handler.do_POST();error.assert_called_with(404)
            handler.path='/c/udp-parent-capture-result';handler.do_POST();post.assert_called_with(False)
            handler.path='/c/udp-parent-runner-flow';handler.do_POST();post.assert_called_with(True)
    def test_handler_exact_existing_bounded_transport_with_only_helper_substitution(self):
        tree=ast.parse(Path(h.__file__).read_text());classes={n.name:n for n in tree.body if isinstance(n,ast.ClassDef)}
        def method(name):return next(n for n in classes[name].body if isinstance(n,ast.FunctionDef) and n.name=='do_udp_POST')
        class Normalize(ast.NodeTransformer):
            def visit_Name(self,n):
                if n.id=='parent_udp_capture_helpers':n.id='udp_capture_helpers'
                return n
        self.assertEqual(ast.dump(method('UDPClosedHandler')),ast.dump(Normalize().visit(method('ParentUDPClosedHandler'))))
    def test_payload_mixed_mode_refused(self):
        for extra in ({'udp':{}},{'n0a':{}},{'capture':True}):
            with self.assertRaises(ValueError):h.payload(None,None,None,None,None,parent_udp={},**extra)
    def test_original_capture_finalizer_and_stop_ownership_unchanged(self):
        tree=ast.parse(Path(h.__file__).read_text());nodes={n.name:n for n in tree.body if isinstance(n,ast.FunctionDef)}
        parent=ast.unparse(nodes['finish_parent_capture_before_cleanup'])
        self.assertIn('adapter.flow_context',parent);self.assertIn('owner.finish(cleanup_deadline=outer_deadline - 30)',parent)
        self.assertNotIn('process.kill',parent);self.assertNotIn('actor_sha256',parent)
        host=ast.unparse(nodes['host']);self.assertIn('outer_deadline = deadline + 120',host)
        self.assertIn('parent_udp_mode',host);self.assertIn("'n0a_udp_parent'",host)
    def test_old_functions_ast_match_published_baseline(self):
        # Exact baseline files are optional external evidence; assertions below
        # pin known old helper ASTs by snapshots captured during this change.
        tree=ast.parse(Path(h.__file__).read_text());nodes={n.name:n for n in tree.body if isinstance(n,(ast.FunctionDef,ast.ClassDef))}
        import hashlib
        pins={'ClosedHandler': '69c60168b164cddcfbe50803760bfa22292f2a509e914add0815a5d508be362e', 'ClosedServer': '0e147ef18528ed1dcd5a922fb84eaf06ff283239d79d4e13a9a0dc2c1e97234d', 'UDPClosedHandler': 'b0e23d845f203b34272e7943493ab58e1d10e971b28b427046dd8445e3169e63', 'UDPClosedServer': '3d12b67f7d26474c39c4f8fd4876815cee211aa37a3bf2026c02a0c7b5d7be66', 'finalize_owned': '77d23e539773d82cbe13043ff61fa412064928da2bc1298142dfbf1eece382e1', 'finish_capture_before_cleanup': 'a85761e170f9cc0ff887b2e8d8b2a60baee091a89a9ce84a917f11ab19117ce5', 'n0a_wait_deadline': 'ff5653b84cf0abe5d86f113d02091e7bae68deba57baf4d651cb1ee2b7717dc7', 'wait_for_n0a': 'c5912750b833d258f3fee6fb3215054654eeb0d3846033be6b7f3fbbf5281244'}
        for name,digest in pins.items():self.assertEqual(hashlib.sha256(ast.dump(nodes[name],include_attributes=False).encode()).hexdigest(),digest,name)
