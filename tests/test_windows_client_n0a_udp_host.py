import ast
import importlib.util
from pathlib import Path
from types import SimpleNamespace
import unittest
from unittest.mock import patch
ROOT=Path(__file__).resolve().parents[1]
spec=importlib.util.spec_from_file_location('udp_direct_host_test',ROOT/'.github/windows_identity_direct_stage0.py');h=importlib.util.module_from_spec(spec);spec.loader.exec_module(h)
class HostTests(unittest.TestCase):
    def test_disabled_before_media_even_with_base_enabled(self):
        with patch.object(h,'EXECUTION_ENABLED',True),patch.object(h,'udp_helpers',return_value=SimpleNamespace(EXECUTION_ENABLED=False)),patch.object(h,'load') as load:
            with self.assertRaises(PermissionError):h.host(SimpleNamespace(n0a_udp_runner=True,n0a=False,n0a_capture_runner=False))
            load.assert_not_called()
    def test_mutually_exclusive_intents(self):
        with patch.object(h,'EXECUTION_ENABLED',True),patch.object(h,'load') as load:
            with self.assertRaises(ValueError):h.host(SimpleNamespace(n0a_udp_runner=True,n0a=True,n0a_capture_runner=False))
            load.assert_not_called()
    def test_udp_routes_reject_tcp_before_bodyread(self):
        handler=object.__new__(h.UDPClosedHandler);handler.server=SimpleNamespace(capability='c')
        with patch.object(handler,'send_error') as error,patch.object(handler,'do_udp_POST') as post:
            for path in ('n0a-result','n0a-capture-result','n0a-runner-flow'):
                handler.path='/c/'+path;handler.do_POST();error.assert_called_with(404)
            handler.path='/c/udp-capture-result';handler.do_POST();post.assert_called_with(False)
            handler.path='/c/udp-runner-flow';handler.do_POST();post.assert_called_with(True)
    def test_receiver_and_capture_share_original_outer_deadline(self):
        tree=ast.parse(Path(h.__file__).read_text());host=next(n for n in tree.body if isinstance(n,ast.FunctionDef) and n.name=='host')
        calls=[n for n in ast.walk(host) if isinstance(n,ast.Call)]
        receiver=next(n for n in calls if isinstance(n.func,ast.Attribute) and n.func.attr=='receiver')
        self.assertEqual(ast.unparse(receiver.args[-1]),'outer_deadline')
        owner=next(n for n in calls if isinstance(n.func,ast.Attribute) and n.func.attr=='new_owner')
        self.assertEqual(ast.unparse(owner.args[-1]),'outer_deadline')
    def test_payload_replacement_refuses_mixed_mode_before_work(self):
        with self.assertRaises(ValueError):h.payload(None,None,None,None,None,n0a={},udp={})
        with self.assertRaises(ValueError):h.payload(None,None,None,None,None,capture=True,udp={})
    def test_udp_handler_uses_same_bounded_body_and_lock_contract(self):
        tree=ast.parse(Path(h.__file__).read_text())
        classes={n.name:n for n in tree.body if isinstance(n,ast.ClassDef)}
        old=next(n for n in classes['ClosedHandler'].body if isinstance(n,ast.FunctionDef) and n.name=='do_capture_POST')
        new=next(n for n in classes['UDPClosedHandler'].body if isinstance(n,ast.FunctionDef) and n.name=='do_udp_POST')
        old.name=new.name
        class Normalize(ast.NodeTransformer):
            def visit_Name(self,n):
                if n.id=='udp_capture_helpers':n.id='capture_helpers'
                return n
        self.assertEqual(ast.dump(old,include_attributes=False),ast.dump(Normalize().visit(new),include_attributes=False))
