"""Removed compatibility routes and explicit scope controls, without sockets or a browser."""
import ast
import io
import json
from pathlib import Path
import secrets
import shutil
import subprocess
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


def http_request(payload, *, path, headers=None, method='POST', raw=False):
    """Run the production handler against only the currently supported Manager API."""
    handler = object.__new__(Handler)
    body = payload if raw else json.dumps(payload).encode()
    manager = Mock(spec=['token', 'settings', 'set_capture_mode', 'set_app_guard', 'save_settings'])
    manager.token = 'test-session'
    manager.settings = {'capture_mode': 'applications', 'windows_app_guard': False}
    manager.set_capture_mode.side_effect = lambda mode: manager.settings.update(capture_mode=mode)
    manager.set_app_guard.side_effect = lambda enabled: manager.settings.update(windows_app_guard=enabled)
    handler.server = SimpleNamespace(manager=manager, client_identity=None,
                                     server_address=('127.0.0.1', 12345))
    handler.headers = {'Host': '127.0.0.1:12345', 'Origin': 'http://127.0.0.1:12345',
                       'X-RuleProxy-Token': 'test-session', 'Content-Type': 'application/json',
                       'Content-Length': str(len(body))}
    handler.headers.update(headers or {})
    handler.path = path
    handler.command = method
    handler.rfile = io.BytesIO(body)
    handler.reply = Mock()
    handler.state_payload = Mock(side_effect=lambda: dict(manager.settings))
    if method == 'GET':
        handler.do_GET()
    else:
        handler.mutate()
    return handler, manager


def run_javascript(program):
    node = shutil.which('node')
    if not node:
        raise unittest.SkipTest('Node.js required for offline UI function contracts')
    result = subprocess.run([node, '-e', program], capture_output=True, text=True,
                            encoding='utf-8', timeout=15)
    if result.returncode:
        raise AssertionError(result.stderr)
    return json.loads(result.stdout)


def js_function(name):
    """Extract an unchanged top-level formatter/render function, not a reimplementation."""
    js = (ROOT / 'web/app.js').read_text(encoding='utf-8')
    start = js.index('  function ' + name + '(')
    end = js.index('\n  }', start) + len('\n  }')
    return js[start:end]


def run_listener(control, following, cases):
    js = (ROOT / 'web/app.js').read_text(encoding='utf-8')
    start = js.index('  ui.' + control + '.addEventListener(')
    end = js.index('  ui.' + following, start)
    listener = js[start:end]
    return run_javascript('const cases = ' + json.dumps(cases) + ';\n' + r'''
      async function execute(input) {
        let state = structuredClone(input.state);
        const mutations = [], renders = [], handlers = {};
        const element = { value: input.value, checked: input.checked,
          addEventListener: (event, callback) => { handlers[event] = callback; } };
        const ui = { CONTROL: element };
        const mutate = async (...args) => { mutations.push(args); return input.result; };
        const render = (value) => { renders.push(structuredClone(value)); };
        LISTENER
        await handlers.change();
        return { mutations, renders, state };
      }
      (async () => console.log(JSON.stringify(await Promise.all(cases.map(execute)))))();
    '''.replace('CONTROL', control.rstrip('?')).replace('LISTENER', listener))


class HTMLIndex(HTMLParser):
    def __init__(self):
        super().__init__()
        self.ids, self.records, self.stack = {}, [], []
        self.feed((ROOT / 'web/index.html').read_text(encoding='utf-8'))

    def handle_starttag(self, tag, attrs):
        attrs = dict(attrs)
        record = {'tag': tag, 'attrs': attrs,
                  'ancestors': tuple(ident for _, ident in self.stack if ident)}
        self.records.append(record)
        if 'id' in attrs:
            self.ids[attrs['id']] = record
        if tag not in {'input', 'meta', 'link', 'br', 'hr', 'img'}:
            self.stack.append((tag, attrs.get('id')))

    def handle_endtag(self, tag):
        for position in range(len(self.stack) - 1, -1, -1):
            if self.stack[position][0] == tag:
                del self.stack[position:]
                break


class CompatHTTPTests(unittest.TestCase):
    def request(self, payload, **options):
        return http_request(payload, path='/api/system-proxy-compat', **options)

    def assert_no_mutation(self, handler, manager, status):
        self.assertEqual(handler.reply.call_args.args[0], status)
        self.assertEqual(manager.mock_calls, [])
        self.assertEqual(manager.settings, {'capture_mode': 'applications', 'windows_app_guard': False})
        handler.state_payload.assert_not_called()

    def test_removed_route_returns_404_even_with_valid_session_and_boolean(self):
        for enabled in (True, False):
            for method in ('POST', 'DELETE', 'GET'):
                with self.subTest(enabled=enabled, method=method):
                    handler, manager = self.request({'enabled': enabled}, method=method)
                    self.assert_no_mutation(handler, manager, 404)

    def test_removed_route_never_translates_old_payload_to_global_mode(self):
        for payload in ({}, {'enabled': 'true'}, {'capture_mode': 'global'},
                        {'enabled': True, 'windows_app_guard': True},
                        {'system_proxy_compat': True, 'antigravity_ipc_compat': True}):
            with self.subTest(payload=payload):
                self.assert_no_mutation(*self.request(payload), 404)

    def test_existing_json_validation_precedes_unknown_route(self):
        for payload in ([], None, True, 'enabled', 1):
            with self.subTest(payload=payload):
                self.assert_no_mutation(*self.request(payload), 400)
        self.assert_no_mutation(*self.request(b'{broken', raw=True), 400)

    def test_existing_origin_and_session_checks_apply(self):
        for headers in ({'Host': 'other:12345'}, {'Origin': 'http://other'},
                        {'X-RuleProxy-Token': ''}, {'X-RuleProxy-Token': 'wrong'},
                        {'Sec-Fetch-Site': 'cross-site'}):
            with self.subTest(headers=headers):
                handler, manager = self.request({'enabled': True}, headers=headers)
                self.assert_no_mutation(handler, manager, 403)

    def test_wrong_content_type_and_delete_do_not_mutate(self):
        for options, status in (({'headers': {'Content-Type': 'text/plain'}}, 415),
                                ({'method': 'DELETE'}, 404)):
            handler, manager = self.request({'enabled': True}, **options)
            self.assert_no_mutation(handler, manager, status)

    def test_global_mode_is_an_explicit_scope_change_only(self):
        for mode in ('applications', 'global'):
            with self.subTest(mode=mode):
                handler, manager = http_request({'capture_mode': mode}, path='/api/mode')
                manager.set_capture_mode.assert_called_once_with(mode)
                manager.set_app_guard.assert_not_called()
                manager.save_settings.assert_not_called()
                handler.reply.assert_called_once_with(200, {'capture_mode': mode, 'windows_app_guard': False})

    def test_scope_request_rejects_mixed_guard_and_deprecated_preferences(self):
        for extra in ({'windows_app_guard': True}, {'system_proxy_compat': True},
                      {'antigravity_ipc_compat': True}, {'enabled': True}):
            with self.subTest(extra=extra):
                self.assert_no_mutation(*http_request({'capture_mode': 'global', **extra}, path='/api/mode'), 400)


class CaptureScopeUITests(unittest.TestCase):
    def test_system_proxy_has_one_explicit_mode_control_and_no_compat_checkbox(self):
        html = HTMLIndex()
        self.assertEqual(html.ids['capture-mode']['tag'], 'select')
        options = [item['attrs']['value'] for item in html.records
                   if item['tag'] == 'option' and 'capture-mode' in item['ancestors']]
        self.assertEqual(options, ['applications', 'global'])
        for ident in ('system-proxy-compat-row', 'system-proxy-compat-toggle', 'system-proxy-compat-detail'):
            self.assertNotIn(ident, html.ids)

    def test_removed_controls_and_endpoints_have_no_script_bindings(self):
        js = (ROOT / 'web/app.js').read_text(encoding='utf-8')
        for removed in ('systemProxyCompat', '/api/system-proxy-compat', 'system_proxy_compat'):
            self.assertNotIn(removed, js)
        self.assertNotRegex(js, r'\.\s*innerHTML\b')

    def test_mode_change_mutates_only_mode_and_rolls_back_failed_selection(self):
        cases = [{'state': {'capture_mode': old, 'windows_app_guard': guard},
                  'value': new, 'result': result}
                 for old, new in (('applications', 'global'), ('global', 'applications'))
                 for guard in (True, False) for result in (None, {'token': 'session'})]
        outputs = run_listener('captureMode?', 'stop.addEventListener', cases)
        for case, output in zip(cases, outputs):
            with self.subTest(case=case):
                self.assertEqual(output['mutations'], [['/api/mode', {'body': {'capture_mode': case['value']}}]])
                self.assertEqual(output['state'], case['state'])
                self.assertEqual(output['renders'], [case['state']] if case['result'] is None else [])

    def test_render_changes_visibility_without_changing_scope_or_guard(self):
        cases = [{'platform': platform, 'capture_mode': mode, 'windows_app_guard': guard,
                  'system_proxy_compat': True, 'antigravity_ipc_compat': True,
                  'apps': [], 'available_apps': [], 'protection': {}}
                 for platform in ('Windows', 'Linux') for mode in ('applications', 'global')
                 for guard in (True, False)]
        program = 'const inputs = ' + json.dumps(cases) + ';\n' + r'''
          let state = null;
          const elements = new Map();
          const element = () => ({ textContent: '', hidden: false, checked: false,
            classList: { toggle() {} }, replaceChildren() {}, append() {}, querySelector() { return null; } });
          const $ = (id) => { if (!elements.has(id)) elements.set(id, element()); return elements.get(id); };
          const ui = new Proxy({}, { get: (_, key) => $(key) });
          const document = { activeElement: null, createElement: element };
          const isWindows = () => state?.platform === 'Windows';
          const isGlobal = () => state?.capture_mode === 'global';
          const AUTOSTART_TEXT = '', AUTOSTART_STALE_TEXT = '';
          const renderNodes = () => {}, renderApps = () => {}, renderAvailableApps = () => {}, renderControls = () => {};
          const textElement = () => element();
          const mutate = () => { throw Error('render performed a mutation'); };
          const fetch = () => { throw Error('render performed a request'); };
        ''' + '\n'.join(js_function(name) for name in ('localIpcSummary', 'guardSummary', 'needsRecovery', 'render')) + r'''
          console.log(JSON.stringify(inputs.map((input) => {
            render(input);
            return { state, mode: ui.captureMode.value, guard: ui.appGuard.checked,
              guardHidden: ui.appGuardRow.hidden, ipcHidden: ui.localIpcRow.hidden,
              advancedHidden: ui.advancedNetwork.hidden, summary: ui.localIpcSummary.textContent };
          })));
        '''
        outputs = run_javascript(program)
        for case, output in zip(cases, outputs):
            with self.subTest(case=case):
                self.assertEqual(output['state'], case)
                self.assertEqual(output['mode'], case['capture_mode'])
                self.assertIs(output['guard'], case['windows_app_guard'])
                hidden = case['platform'] != 'Windows' or case['capture_mode'] == 'global'
                for key in ('guardHidden', 'ipcHidden', 'advancedHidden'):
                    self.assertIs(output[key], hidden)
                self.assertNotIn('已自动核验', output['summary'])


if __name__ == '__main__':
    unittest.main()
