"""Removed IPC switch, automatic status, and recovery controls with offline JS fixtures."""
import json
import unittest

from test_system_proxy_compat_http_ui import (
    HTMLIndex, ROOT, http_request, js_function, run_javascript, run_listener,
)


class AntigravityIpcHTTPTests(unittest.TestCase):
    def request(self, payload, **options):
        return http_request(payload, path='/api/antigravity-ipc-compat', **options)

    def assert_no_mutation(self, handler, manager, status):
        self.assertEqual(handler.reply.call_args.args[0], status)
        self.assertEqual(manager.mock_calls, [])
        self.assertEqual(manager.settings, {'capture_mode': 'applications', 'windows_app_guard': False})
        handler.state_payload.assert_not_called()

    def test_removed_endpoint_is_404_even_with_valid_token(self):
        for enabled in (True, False):
            for method in ('POST', 'DELETE', 'GET'):
                with self.subTest(enabled=enabled, method=method):
                    self.assert_no_mutation(*self.request({'enabled': enabled}, method=method), 404)

    def test_removed_endpoint_never_enables_guard_or_changes_capture_scope(self):
        for payload in ({}, {'enabled': 'true'}, {'enabled': True, 'extra': False},
                        {'enabled': True, 'windows_app_guard': True}, {'capture_mode': 'global'},
                        {'antigravity_ipc_compat': True, 'system_proxy_compat': True}):
            with self.subTest(payload=payload):
                self.assert_no_mutation(*self.request(payload), 404)

    def test_existing_json_validation_remains_without_mutation(self):
        for payload in ([], None, True, 'enabled', 1):
            with self.subTest(payload=payload):
                self.assert_no_mutation(*self.request(payload), 400)
        self.assert_no_mutation(*self.request(b'{broken', raw=True), 400)

    def test_existing_origin_host_and_token_checks_apply(self):
        for headers in ({'Host': 'other:12345'}, {'Origin': 'http://other'},
                        {'X-RuleProxy-Token': ''}, {'X-RuleProxy-Token': 'wrong'},
                        {'Sec-Fetch-Site': 'cross-site'}):
            with self.subTest(headers=headers):
                self.assert_no_mutation(*self.request({'enabled': True}, headers=headers), 403)

    def test_wrong_content_type_does_not_mutate(self):
        self.assert_no_mutation(*self.request({'enabled': True}, headers={'Content-Type': 'text/plain'}), 415)

    def test_guard_endpoint_changes_only_guard_preference(self):
        for enabled in (True, False):
            with self.subTest(enabled=enabled):
                handler, manager = http_request({'enabled': enabled}, path='/api/app-guard')
                manager.set_app_guard.assert_called_once_with(enabled)
                manager.set_capture_mode.assert_not_called()
                manager.save_settings.assert_not_called()
                handler.reply.assert_called_once_with(200, {'capture_mode': 'applications',
                                                           'windows_app_guard': enabled})

    def test_guard_endpoint_does_not_accept_scope_or_legacy_options(self):
        for extra in ({'capture_mode': 'global'}, {'system_proxy_compat': True},
                      {'antigravity_ipc_compat': True}, {'local_ipc_automatic': False}):
            with self.subTest(extra=extra):
                self.assert_no_mutation(*http_request({'enabled': True, **extra}, path='/api/app-guard'), 400)


def local_state(ipc=None, *, guard=None, **settings):
    status = {'app_guard': {'active': True} if guard is None else guard}
    if ipc is not None:
        status['local_ipc'] = ipc
    return {'running': True, 'windows_app_guard': True, 'protection': {'status': status}, **settings}


def format_states(name, states):
    return run_javascript(js_function(name) + '\nconst inputs = ' + json.dumps(states) + ';\n'
                          + 'console.log(JSON.stringify(inputs.map(' + name + ')));')


class AutomaticLocalIpcUITests(unittest.TestCase):
    def test_automatic_row_is_status_not_a_checkbox_and_guard_stays_advanced(self):
        html = HTMLIndex()
        for ident in ('antigravity-ipc-compat-row', 'antigravity-ipc-compat-toggle',
                      'antigravity-ipc-compat-detail', 'system-proxy-compat-toggle'):
            self.assertNotIn(ident, html.ids)
        self.assertIn('hidden', html.ids['local-ipc-row']['attrs'])
        self.assertEqual(html.ids['local-ipc-summary']['attrs']['role'], 'status')
        self.assertNotIn(html.ids['local-ipc-summary']['tag'], ('input', 'button', 'select'))
        for record in html.records:
            if 'local-ipc-row' in record['ancestors']:
                self.assertNotEqual(record['tag'], 'input')
                self.assertNotEqual(record['attrs'].get('role'), 'switch')
        advanced = html.ids['advanced-network-settings']
        self.assertEqual(advanced['tag'], 'details')
        self.assertNotIn('open', advanced['attrs'])
        self.assertIn('advanced-network-settings', html.ids['app-guard-toggle']['ancestors'])
        self.assertEqual(html.ids['app-guard-toggle']['attrs']['type'], 'checkbox')

    def test_script_has_no_deprecated_preferences_endpoints_or_html_sinks(self):
        js = (ROOT / 'web/app.js').read_text(encoding='utf-8')
        for removed in ('antigravityIpcCompat', 'antigravity_ipc_compat', '/api/antigravity-ipc-compat',
                        'systemProxyCompat', 'system_proxy_compat', '/api/system-proxy-compat'):
            self.assertNotIn(removed, js)
        self.assertNotRegex(js, r'\.\s*innerHTML\b')
        self.assertNotIn('insertAdjacentHTML', js)

    def test_local_ipc_runtime_states_are_not_connectivity_claims(self):
        active = {'supported': True, 'enabled': True, 'active': True, 'state': 'active', 'endpoint_count': 2}
        cases = [
            (None, '未启用出站守卫'),
            ({}, '未启用出站守卫'),
            ({'windows_app_guard': True}, '已配置自动处理'),
            ({'windows_app_guard': True, 'running': True}, '尚未确认生效'),
            (local_state(), '尚不支持自动本机通信'),
            (local_state({'supported': False}), '尚不支持自动本机通信'),
            (local_state({'supported': 'true'}), '尚不支持自动本机通信'),
            (local_state({**active, 'state': 'unsupported'}), '尚不支持自动本机通信'),
            (local_state({'supported': True, 'enabled': False, 'active': False, 'state': 'inactive'}), '状态待确认'),
            (local_state({'supported': True, 'enabled': True, 'active': False, 'state': 'watching'}), '等待所选应用监听'),
            (local_state(active), '已自动核验 2 个同应用本机端口'),
            (local_state({**active, 'state': 'unknown'}), '状态待确认'),
            (local_state({**active, 'enabled': False}), '状态待确认'),
            (local_state({**active, 'active': False}), '状态待确认'),
            (local_state(active, guard={'active': False}), '尚未确认生效'),
            (local_state(active, guard={'active': 'true'}), '尚未确认生效'),
        ]
        for value in (True, False, 0, -1, 1.5, '2', '<img onerror=secret-token>', None, 2 ** 53):
            cases.append((local_state({**active, 'endpoint_count': value}), '状态待确认'))
        for key in ('enabled', 'active'):
            for value in ('true', 1, None):
                cases.append((local_state({**active, key: value}), '状态待确认'))
        outputs = format_states('localIpcSummary', [value for value, _ in cases])
        self.assertEqual(len(outputs), len(cases))
        for (value, expected), output in zip(cases, outputs):
            with self.subTest(value=value):
                self.assertIn(expected, output)
                self.assertNotIn('<img', output)
                self.assertNotIn('secret-token', output)
                if expected.startswith('已自动核验'):
                    self.assertIn('这不代表应用联网成功', output)
                else:
                    self.assertNotIn('已自动核验', output)

    def test_fault_and_unknown_guard_override_stale_active_ipc(self):
        active = {'supported': True, 'enabled': True, 'active': True, 'state': 'active', 'endpoint_count': 2}
        cases = [
            (local_state({**active, 'state': 'failed'}), '故障'),
            (local_state({**active, 'error': '<img onerror=secret-token>'}), '故障'),
            (local_state({**active, 'error': {'code': 'secret-token'}}), '故障'),
            (local_state(active, guard={'active': True, 'state': 'failed'}), '状态异常'),
            (local_state(active, guard={'active': True, 'state': 'unavailable'}), '状态异常'),
            (local_state(active, guard={'active': True, 'error': '<img onerror=secret-token>'}), '状态异常'),
            (local_state(active, guard={'active': True, 'state': 'unknown'}), '尚未确认'),
        ]
        outputs = format_states('localIpcSummary', [value for value, _ in cases])
        for (value, expected), output in zip(cases, outputs):
            with self.subTest(value=value):
                self.assertIn(expected, output)
                self.assertNotIn('已自动核验', output)
                self.assertNotIn('secret-token', output)
                self.assertNotIn('<img', output)

    def test_waiting_restart_is_precise_and_does_not_claim_a_live_exception(self):
        watching = {'supported': True, 'enabled': True, 'active': False, 'state': 'watching'}
        values = [local_state({**watching, 'waiting_restart_count': count})
                  for count in (1, 2, 0, -1, True, '1', '<img>', 1.5, 2 ** 53)]
        outputs = format_states('localIpcSummary', values)
        for index, output in enumerate(outputs):
            with self.subTest(value=values[index]):
                if index < 2:
                    self.assertIn('退出原应用后从这里重新启动', output)
                    self.assertIn('尚未确认本机通信例外生效', output)
                else:
                    self.assertIn('等待所选应用监听', output)
                    self.assertNotIn('检测到启动前已有', output)
                self.assertNotIn('已自动核验', output)
                self.assertNotIn('<img', output)
        active = local_state({**watching, 'state': 'active', 'active': True,
                              'endpoint_count': 2, 'waiting_restart_count': 1})
        output = format_states('localIpcSummary', [active])[0]
        self.assertIn('已自动核验 2 个', output)
        self.assertIn('退出原应用后从这里重新启动', output)
        self.assertIn('这不代表应用联网成功', output)

    def test_legacy_preference_or_broker_status_does_not_invent_automatic_success(self):
        old = {'supported': True, 'enabled': True, 'active': True, 'state': 'active', 'endpoint_count': 2}
        value = local_state()
        value['antigravity_ipc_compat'] = True
        value['protection']['status']['antigravity_ipc'] = old
        output = format_states('localIpcSummary', [value])[0]
        self.assertIn('尚不支持自动本机通信', output)
        self.assertNotIn('已自动核验', output)

    def test_guard_summary_uses_runtime_faults_and_retention_not_only_preference(self):
        cases = [
            (None, '出站守卫未开启'),
            ({'windows_app_guard': True}, '尚未确认生效'),
            (local_state(guard={'active': False}), '尚未确认生效'),
            (local_state(guard={'active': 'true'}), '尚未确认生效'),
            (local_state(guard={'active': None, 'state': 'unknown'}), '状态待确认'),
            (local_state(guard={'active': True, 'state': 'unknown'}), '状态待确认'),
            (local_state(guard={'active': True}, windows_app_guard=False), '实际生效中'),
            (local_state(guard={'active': True}, running=False), '核心已停，出站守卫仍保留'),
        ]
        for active in (True, False):
            for fault in ({'state': 'failed'}, {'state': 'unavailable'}, {'error': '<img onerror=secret-token>'}):
                cases.append((local_state(guard={'active': active, **fault}), '状态异常'))
        outputs = format_states('guardSummary', [value for value, _ in cases])
        for (value, expected), output in zip(cases, outputs):
            with self.subTest(value=value):
                self.assertIn(expected, output)
                if expected != '实际生效中':
                    self.assertNotIn('实际生效中', output)
                self.assertNotIn('secret-token', output)
                self.assertNotIn('<img', output)

    def test_guard_listener_changes_only_guard_and_failure_restores_display(self):
        cases = [{'state': {'capture_mode': mode, 'windows_app_guard': not enabled},
                  'checked': enabled, 'result': result}
                 for mode in ('applications', 'global') for enabled in (True, False)
                 for result in (None, {'token': 'session'})]
        outputs = run_listener('appGuard', 'quit.addEventListener', cases)
        for case, output in zip(cases, outputs):
            with self.subTest(case=case):
                self.assertEqual(len(output['mutations']), 1)
                path, request, options = output['mutations'][0]
                self.assertEqual(path, '/api/app-guard')
                self.assertEqual(request, {'body': {'enabled': case['checked']}})
                if case['checked']:
                    self.assertIn('已配置', options['notice'])
                    self.assertIn('以组件实际状态为准', options['notice'])
                    self.assertNotIn('实际生效', options['notice'])
                self.assertEqual(output['state'], case['state'])
                self.assertEqual(output['renders'], [case['state']] if case['result'] is None else [])

    def test_fault_retention_keeps_stop_available_and_blocks_new_work(self):
        faults = [
            {'global_fault': True},
            {'apps': [{'id': 'a', 'enabled': True, 'cleanup_pending': True}]},
            {'status': {'cleanup_pending': True}},
            {'status': {'error': {'code': 'cleanup_incomplete'}}},
            {'status': {'local_ipc': {'state': 'failed'}}},
            {'status': {'local_ipc': {'error': '<img onerror=secret-token>'}}},
            {'status': {'app_guard': {'state': 'failed'}}},
            {'status': {'app_guard': {'state': 'unavailable'}}},
            {'status': {'app_guard': {'active': True, 'state': 'unknown'}}},
            {'status': {'app_guard': {'error': '<img onerror=secret-token>'}}},
        ]
        cases = []
        for running in (False, True):
            for fault in faults:
                status = fault.get('status', {})
                value = {'platform': 'Windows', 'capture_mode': 'applications', 'running': running,
                         'imported': True, 'apps': [{'id': 'a', 'enabled': True}],
                         'protection': {'supported': True, 'status': status},
                         **{key: val for key, val in fault.items() if key != 'status'}}
                cases.append({'state': value, 'fault': True})
        retained = {'platform': 'Windows', 'capture_mode': 'applications', 'running': False,
                    'imported': True, 'apps': [{'id': 'a', 'enabled': True}],
                    'protection': {'supported': True, 'status': {'app_guard': {'active': True}}}}
        cases.append({'state': retained, 'fault': True})
        for running in (False, True):
            cases.append({'state': {**retained, 'running': running, 'protection': {'supported': True}}, 'fault': False})
        cases.append({'state': retained, 'fault': True, 'busy': True})
        for case in cases:
            case['state'] = {**case['state'], 'apps': [*case['state']['apps'], {'id': 'fresh', 'enabled': True}]}
        program = 'const cases = ' + json.dumps(cases) + ';\n' + r'''
          let state, busy = false, stopped = false, testingAllNodes = false, refreshingApps = false;
          const testingNodes = new Set();
          const controls = new Map();
          const action = { dataset: { appId: 'a' } };
          const freshAction = { dataset: { appId: 'fresh' } };
          const ui = new Proxy({}, { get: (_, name) => {
            if (!controls.has(name)) controls.set(name, { querySelectorAll: (selector) =>
              selector === '.app-action' ? [action, freshAction] : [] });
            return controls.get(name);
          }});
          const document = { querySelectorAll: () => [...controls.values(), action] };
          const isGlobal = () => state?.capture_mode === 'global';
          const isWindows = () => state?.platform === 'Windows';
        ''' + js_function('needsRecovery') + '\n' + js_function('renderControls') + r'''
          console.log(JSON.stringify(cases.map((input) => {
            state = input.state; busy = input.busy === true;
            renderControls();
            return { recovery: needsRecovery(state), stop: ui.stop.disabled, start: ui.start.disabled,
              mode: ui.captureMode.disabled, launch: ui.launchAll.disabled,
              action: action.disabled, freshAction: freshAction.disabled };
          })));
        '''
        outputs = run_javascript(program)
        for case, output in zip(cases, outputs):
            with self.subTest(case=case):
                self.assertIs(output['recovery'], case['fault'])
                if case['fault']:
                    self.assertIs(output['stop'], case.get('busy', False))
                    for control in ('start', 'mode', 'launch', 'freshAction'):
                        self.assertTrue(output[control], control)
                    # An existing cleanup action must remain usable, unlike a new launch.
                    app_cleanup = case['state']['apps'][0].get('cleanup_pending', False)
                    self.assertIs(output['action'], case.get('busy', False) or not app_cleanup)
                elif case['state']['running']:
                    self.assertFalse(output['stop'])
                    self.assertFalse(output['launch'])
                    self.assertFalse(output['action'])
                    self.assertFalse(output['freshAction'])
                else:
                    self.assertTrue(output['stop'])
                    self.assertFalse(output['start'])
                    self.assertFalse(output['mode'])


if __name__ == '__main__':
    unittest.main()
