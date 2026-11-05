"""Socket-free HTTP and static UI contracts; no Manager/native imports or service."""
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
from html.parser import HTMLParser

ROOT = Path(__file__).resolve().parents[1]
source = ast.parse((ROOT / 'ruleproxy/server.py').read_text(encoding='utf-8'))
handler_node = next(n for n in source.body if isinstance(n, ast.ClassDef) and n.name == 'Handler')
namespace = dict(BaseHTTPRequestHandler=BaseHTTPRequestHandler, json=json,
                 secrets=secrets, urllib=urllib, MAX_REQUEST=2 * 1024 * 1024 + 65536)
exec(compile(ast.Module(body=[handler_node], type_ignores=[]), 'server.py', 'exec'), namespace)
Handler = namespace['Handler']


class AntigravityIpcHTTPTests(unittest.TestCase):
    def request(self, payload, *, headers=None, method='POST', rejected=False, raw=False):
        handler = object.__new__(Handler)  # no sockets or BaseHTTPRequestHandler init
        body = payload if raw else json.dumps(payload).encode()
        manager = SimpleNamespace(token='test-session', enabled=False)
        def setter(enabled):
            if rejected:
                raise ValueError('核心、应用或恢复状态尚未完全停止')
            manager.enabled = enabled
        manager.set_antigravity_ipc_compat = Mock(side_effect=setter)
        manager.set_system_proxy_compat = Mock()
        handler.server = SimpleNamespace(manager=manager, client_identity=None,
                                         server_address=('127.0.0.1', 12345))
        handler.headers = {'Host': '127.0.0.1:12345', 'Origin': 'http://127.0.0.1:12345',
                           'X-RuleProxy-Token': 'test-session', 'Content-Type': 'application/json',
                           'Content-Length': str(len(body))}
        handler.headers.update(headers or {})
        handler.path = '/api/antigravity-ipc-compat'
        handler.command = method
        handler.rfile = io.BytesIO(body)
        handler.reply = Mock()
        handler.state_payload = lambda: {'antigravity_ipc_compat': manager.enabled}
        handler.mutate()
        manager.set_system_proxy_compat.assert_not_called()
        return handler, manager

    def test_exact_booleans_forwarded_and_state_returned(self):
        for enabled in (True, False):
            with self.subTest(enabled=enabled):
                handler, manager = self.request({'enabled': enabled})
                manager.set_antigravity_ipc_compat.assert_called_once_with(enabled)
                handler.reply.assert_called_once_with(200, {'antigravity_ipc_compat': enabled})

    def test_invalid_shape_or_type_never_calls_setter(self):
        values = [{}, {'extra': True}, {'enabled': True, 'extra': False},
                  [], None, True, 'enabled', 1]
        values += [{'enabled': v} for v in (None, 0, 1, 'true', 'false', [], {})]
        for value in values:
            with self.subTest(value=value):
                handler, manager = self.request(value)
                self.assertEqual(handler.reply.call_args.args[0], 400)
                manager.set_antigravity_ipc_compat.assert_not_called()
                self.assertFalse(manager.enabled)

    def test_malformed_json_never_calls_setter(self):
        handler, manager = self.request(b'{broken', raw=True)
        self.assertEqual(handler.reply.call_args.args[0], 400)
        manager.set_antigravity_ipc_compat.assert_not_called()

    def test_existing_origin_host_and_token_checks_apply(self):
        for headers in ({'Host': 'other:12345'}, {'Origin': 'http://other'},
                        {'X-RuleProxy-Token': ''}, {'X-RuleProxy-Token': 'wrong'},
                        {'Sec-Fetch-Site': 'cross-site'}):
            with self.subTest(headers=headers):
                handler, manager = self.request({'enabled': True}, headers=headers)
                self.assertEqual(handler.reply.call_args.args[0], 403)
                manager.set_antigravity_ipc_compat.assert_not_called()
                self.assertFalse(manager.enabled)

    def test_content_type_and_delete_rejected_without_mutation(self):
        for options, status in (({'headers': {'Content-Type': 'text/plain'}}, 415),
                                ({'method': 'DELETE'}, 404)):
            handler, manager = self.request({'enabled': True}, **options)
            self.assertEqual(handler.reply.call_args.args[0], status)
            manager.set_antigravity_ipc_compat.assert_not_called()

    def test_manager_lifecycle_rejection_preserves_state(self):
        handler, manager = self.request({'enabled': True}, rejected=True)
        self.assertEqual(handler.reply.call_args.args[0], 400)
        manager.set_antigravity_ipc_compat.assert_called_once_with(True)
        self.assertFalse(manager.enabled)


class AntigravityIpcStaticUITests(unittest.TestCase):
    def test_html_default_hidden_unchecked_disabled_and_scope(self):
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
        self.assertIn('hidden', parser.ids['antigravity-ipc-compat-row'])
        control = parser.ids['antigravity-ipc-compat-toggle']
        self.assertNotIn('checked', control)
        self.assertIn('disabled', control)
        self.assertEqual(control['aria-describedby'], 'antigravity-ipc-compat-detail')
        self.assertIn('Antigravity 本机通信兼容', html)
        self.assertIn('仅所选Antigravity及语言服务的经验证127.0.0.1 TCP端口，不开放任意本地服务', html)
        self.assertIn('按路径与用户身份匹配', html)
        self.assertIn('退出已有 Antigravity → 完全停止核心 → 关闭本机通信兼容以清错 → 再启用 → 重新启动核心和应用', html)
        self.assertIn('仅重启应用不会清除故障', html)
        self.assertNotIn('已有实例需重启', html)
        self.assertIn('系统代理兼容：影响当前Windows用户其他遵循系统代理的应用，保留应用出站守卫；核心停止时可修改', html)

    def test_js_default_state_scope_and_lock_contract(self):
        js = (ROOT / 'web/app.js').read_text(encoding='utf-8')
        self.assertIn("ui.antigravityIpcCompatRow.hidden = !isWindows() || state.capture_mode !== 'applications';", js)
        self.assertIn('ui.antigravityIpcCompat.checked = state.antigravity_ipc_compat === true;', js)
        self.assertIn('ui.antigravityIpcCompat.disabled = antigravityIpcCompatLocked();', js)
        lock = js.split('function antigravityIpcCompatLocked() {', 1)[1].split('\n  }', 1)[0]
        for check in ('stopped || busy || !state', '!isWindows()', "state.capture_mode !== 'applications'",
                      '!!state.running', 'state.global_fault === true',
                      'state.antigravity_ipc_compat_locked === true',
                      'app.active || app.cleanup_pending || app.profile_preparing'):
            self.assertIn(check, lock)

    def test_ipc_detail_textcontent_and_guard_notice_contract(self):
        js = (ROOT / 'web/app.js').read_text(encoding='utf-8')
        self.assertIn("$('antigravity-ipc-compat-detail').textContent = antigravityIpcCompatDetail(state);", js)
        self.assertNotIn("$('antigravity-ipc-compat-detail').innerHTML", js)
        self.assertNotIn('已有实例需重启', js)
        self.assertNotIn('所选程序只能连接本机代理端口', js)
        self.assertIn('基础出站守卫已开启', js)
        self.assertIn('以组件实际状态为准', js)

    def test_ipc_detail_runtime_states_and_untrusted_errors(self):
        import shutil
        import subprocess
        node = shutil.which('node')
        if not node:
            self.skipTest('Node.js required for pure status formatter fixture')
        js = (ROOT / 'web/app.js').read_text(encoding='utf-8')
        function = 'function antigravityIpcCompatDetail(value) {' + js.split(
            'function antigravityIpcCompatDetail(value) {', 1)[1].split('\n  }', 1)[0] + '\n}'
        def state(**ipc):
            return {'antigravity_ipc_compat': True, 'protection': {'status': {'antigravity_ipc': ipc}}}
        cases = [
            ({}, '未启用；组件尚无状态'),
            ({'antigravity_ipc_compat': True}, '已配置开启，组件尚无状态'),
            (state(supported=False, enabled=False, state='inactive'), '当前组件不支持'),
            (state(supported=True, enabled=False, state='inactive'), '当前未启用'),
            (state(supported=True, enabled=True, active=False, state='inactive'), '当前未活动'),
            (state(supported=True, enabled=True, active=False, state='watching', endpoint_count=0), '等待新实例监听端口'),
            (state(supported=True, enabled=True, active=True, state='active', endpoint_count=2), '已验证 2 个端口'),
            (state(supported=True, enabled=True, active=False, state='active', endpoint_count=2), '状态待确认'),
            (state(supported=True, enabled=True, active=True, state='active', endpoint_count='<img>'), '状态待确认'),
            (state(supported=True, enabled=True, active=False, state='failed', error='<img onerror=secret-token>'), '兼容故障'),
            (state(supported=True, enabled=True, active=True, state='active', endpoint_count=2, error='secret-token'), '兼容故障'),
        ]
        disabled = state(supported=True, enabled=True, active=True, state='active', endpoint_count=2)
        disabled['antigravity_ipc_compat'] = False
        cases.append((disabled, '当前未启用'))
        program = function + '\nconst inputs = ' + json.dumps([value for value, _ in cases]) + ';\n'
        program += 'console.log(JSON.stringify(inputs.map(antigravityIpcCompatDetail)));'
        result = subprocess.run([node, '-e', program], capture_output=True, text=True, encoding='utf-8', timeout=15)
        self.assertEqual(result.returncode, 0, result.stderr)
        outputs = json.loads(result.stdout)
        self.assertEqual(len(outputs), len(cases))
        for (value, expected), output in zip(cases, outputs):
            with self.subTest(value=value):
                self.assertIn(expected, output)
                self.assertIn('退出已有 Antigravity → 完全停止核心 → 关闭本机通信兼容以清错 → 再启用 → 重新启动核心和应用', output)
                self.assertIn('仅重启应用不会清除故障', output)
                self.assertNotIn('secret-token', output)
                self.assertNotIn('<img', output)
                if expected != '已验证 2 个端口':
                    self.assertNotIn('已验证 2 个端口', output)
        self.assertIn('这不代表应用联网成功', outputs[6])

    def test_js_mutation_and_failure_restore_only_this_option(self):
        js = (ROOT / 'web/app.js').read_text(encoding='utf-8')
        start = js.index("ui.antigravityIpcCompat.addEventListener('change'")
        end = js.index("ui.appGuard.addEventListener('change'", start)
        listener = js[start:end]
        self.assertIn('if (antigravityIpcCompatLocked())', listener)
        self.assertIn('ui.antigravityIpcCompat.checked = state?.antigravity_ipc_compat === true;', listener)
        self.assertIn("mutate('/api/antigravity-ipc-compat', { body: { enabled } }", listener)
        self.assertIn('if (!result && state) render(state);', listener)
        self.assertNotIn('/api/system-proxy-compat', listener)
        self.assertNotIn('/api/app-guard', listener)
        # The existing mutation helper owns success render and failure handling.
        mutation = js.split('async function mutate(', 1)[1].split('\n  async function ', 1)[0]
        self.assertIn('render(', mutation)
        self.assertIn('catch', mutation)


if __name__ == '__main__':
    unittest.main()
