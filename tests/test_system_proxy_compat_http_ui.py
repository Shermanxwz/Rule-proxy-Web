"""Socket-free HTTP handler tests; never import Manager or Windows backends."""
import ast
import io
import json
from pathlib import Path
import secrets
from types import SimpleNamespace
import unittest
from unittest.mock import Mock
import urllib.parse
from http.server import BaseHTTPRequestHandler

ROOT = Path(__file__).resolve().parents[1]
source = ast.parse((ROOT / 'ruleproxy/server.py').read_text(encoding='utf-8'))
handler_node = next(n for n in source.body if isinstance(n, ast.ClassDef) and n.name == 'Handler')
namespace = dict(BaseHTTPRequestHandler=BaseHTTPRequestHandler, json=json,
                 secrets=secrets, urllib=urllib, MAX_REQUEST=2 * 1024 * 1024 + 65536)
exec(compile(ast.Module(body=[handler_node], type_ignores=[]), 'server.py', 'exec'), namespace)
Handler = namespace['Handler']


class CompatHTTPTests(unittest.TestCase):
    def request(self, payload, *, headers=None, method='POST', rejected=False, raw=False):
        # Bypass BaseHTTPRequestHandler.__init__: no sockets, threads or service.
        handler = object.__new__(Handler)
        body = payload if raw else json.dumps(payload).encode()
        manager = SimpleNamespace(token='test-session', enabled=False)
        def setter(enabled):
            if rejected:
                raise ValueError('核心运行中或平台/模式不支持')
            manager.enabled = enabled
        manager.set_system_proxy_compat = Mock(side_effect=setter)
        handler.server = SimpleNamespace(manager=manager, client_identity=None,
                                         server_address=('127.0.0.1', 12345))
        handler.headers = {'Host': '127.0.0.1:12345', 'Origin': 'http://127.0.0.1:12345',
                           'X-RuleProxy-Token': 'test-session', 'Content-Type': 'application/json',
                           'Content-Length': str(len(body))}
        handler.headers.update(headers or {})
        handler.path = '/api/system-proxy-compat'
        handler.command = method
        handler.rfile = io.BytesIO(body)
        handler.reply = Mock()
        handler.state_payload = lambda: {'system_proxy_compat': manager.enabled}
        handler.mutate()
        return handler, manager

    def test_boolean_values_are_forwarded_and_state_returned(self):
        for enabled in (True, False):
            with self.subTest(enabled=enabled):
                handler, manager = self.request({'enabled': enabled})
                manager.set_system_proxy_compat.assert_called_once_with(enabled)
                handler.reply.assert_called_once_with(200, {'system_proxy_compat': enabled})

    def test_invalid_payload_never_calls_setter(self):
        values = [{}, {'extra': True}, {'enabled': True, 'extra': False},
                  [], None, True, 'enabled', 1]
        values += [{'enabled': v} for v in (None, 0, 1, 'true', 'false', [], {})]
        for value in values:
            with self.subTest(value=value):
                handler, manager = self.request(value)
                self.assertEqual(handler.reply.call_args.args[0], 400)
                manager.set_system_proxy_compat.assert_not_called()
                self.assertFalse(manager.enabled)

    def test_malformed_json_never_calls_setter(self):
        handler, manager = self.request(b'{broken', raw=True)
        self.assertEqual(handler.reply.call_args.args[0], 400)
        manager.set_system_proxy_compat.assert_not_called()
        self.assertFalse(manager.enabled)

    def test_existing_origin_and_session_checks_apply(self):
        for headers in ({'Host': 'other:12345'}, {'Origin': 'http://other'},
                        {'X-RuleProxy-Token': ''}, {'X-RuleProxy-Token': 'wrong'},
                        {'Sec-Fetch-Site': 'cross-site'}):
            with self.subTest(headers=headers):
                handler, manager = self.request({'enabled': True}, headers=headers)
                self.assertEqual(handler.reply.call_args.args[0], 403)
                manager.set_system_proxy_compat.assert_not_called()
                self.assertFalse(manager.enabled)

    def test_wrong_content_type_and_delete_do_not_mutate(self):
        for options, status in (({'headers': {'Content-Type': 'text/plain'}}, 415),
                                ({'method': 'DELETE'}, 404)):
            handler, manager = self.request({'enabled': True}, **options)
            self.assertEqual(handler.reply.call_args.args[0], status)
            manager.set_system_proxy_compat.assert_not_called()
            self.assertFalse(manager.enabled)

    def test_manager_rejection_preserves_state(self):
        handler, manager = self.request({'enabled': True}, rejected=True)
        self.assertEqual(handler.reply.call_args.args[0], 400)
        self.assertFalse(manager.enabled)


class CompatStaticUITests(unittest.TestCase):
    def test_html_default_off_hidden_and_scope_explained(self):
        from html.parser import HTMLParser
        class Tags(HTMLParser):
            def __init__(self):
                super().__init__()
                self.ids = {}
            def handle_starttag(self, tag, attrs):
                attrs = dict(attrs)
                if 'id' in attrs:
                    self.ids[attrs['id']] = attrs
        html = (ROOT / 'web/index.html').read_text(encoding='utf-8')
        parser = Tags()
        parser.feed(html)
        self.assertIn('hidden', parser.ids['system-proxy-compat-row'])
        control = parser.ids['system-proxy-compat-toggle']
        self.assertNotIn('checked', control)
        self.assertIn('disabled', control)
        self.assertEqual(control['aria-describedby'], 'system-proxy-compat-detail')
        self.assertIn('系统代理兼容：影响当前Windows用户其他遵循系统代理的应用，保留应用出站守卫；核心停止时可修改', html)
        self.assertIn('开启后不是仅按应用隔离', html)

    def test_js_scope_runtime_disable_state_and_mutation_contract(self):
        js = (ROOT / 'web/app.js').read_text(encoding='utf-8')
        self.assertIn("ui.systemProxyCompatRow.hidden = !isWindows() || state.capture_mode !== 'applications';", js)
        self.assertIn('ui.systemProxyCompat.checked = state.system_proxy_compat === true;', js)
        self.assertIn('ui.systemProxyCompat.disabled = busy || !ready || running || recoveryPending', js)
        self.assertIn("mutate('/api/system-proxy-compat', { body: { enabled } }", js)
        start = js.index("ui.systemProxyCompat.addEventListener('change'")
        end = js.index("ui.appGuard.addEventListener('change'", start)
        listener = js[start:end]
        self.assertIn("!isWindows() || state.capture_mode !== 'applications'", listener)
        self.assertIn('busy || !state || state.running', listener)
        self.assertIn('if (!result && state) render(state);', listener)
        self.assertNotIn('/api/app-guard', listener)


if __name__ == '__main__':
    unittest.main()
