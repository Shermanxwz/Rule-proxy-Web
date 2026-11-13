"""Execute the shipped UI and its DOM events in Node with an offline HTTP fixture."""
import json
from pathlib import Path
import shutil
import subprocess
import unittest


ROOT = Path(__file__).resolve().parents[1]
NODE = shutil.which('node')

# Small DOM surface used by app.js, including focus loss on detached elements
# and disabled-input focus behavior. No browser packages or network are used.
HARNESS = r'''
const assert = require('node:assert/strict');
const vm = require('node:vm');
const flush = () => new Promise(resolve => setImmediate(resolve));
class Element {
  constructor(tag, document) {
    this.tagName = tag; this.document = document; this.children = [];
    this.parentElement = null; this.dataset = {}; this.attributes = {};
    this.className = ''; this.value = ''; this.checked = false;
    this.disabled = false; this.hidden = false; this.title = ''; this.events = {};
    this.classList = {
      contains: name => this.className.split(/\s+/).includes(name),
      toggle: (name, enabled) => {
        const names = new Set(this.className.split(/\s+/).filter(Boolean));
        enabled ? names.add(name) : names.delete(name);
        this.className = [...names].join(' ');
      },
    };
  }
  get textContent() { return (this.text || '') + this.children.map(c => c.textContent).join(''); }
  set textContent(value) { this.replaceChildren(); this.text = String(value); }
  append(...children) {
    for (const child of children) { child.parentElement = this; this.children.push(child); }
  }
  contains(element) { return this === element || this.children.some(c => c.contains(element)); }
  replaceChildren(...children) {
    if (this.children.some(c => c.contains(this.document.activeElement))) {
      this.document.activeElement = this.document.body;
    }
    this.children.forEach(c => { c.parentElement = null; });
    this.children = []; this.text = ''; this.append(...children);
  }
  setAttribute(name, value) { this.attributes[name] = String(value); }
  getAttribute(name) {
    return name.startsWith('data-')
      ? this.dataset[name.slice(5).replace(/-([a-z])/g, (_, c) => c.toUpperCase())]
      : this.attributes[name];
  }
  matches(selector) {
    if (selector.startsWith('.')) return this.classList.contains(selector.slice(1));
    const attr = selector.match(/^(?:([\w-]+))?\[([^=]+)="(.*)"\]$/);
    if (attr) return (!attr[1] || attr[1] === this.tagName)
      && this.getAttribute(attr[2]) === attr[3].replace(/\\(.)/g, '$1');
    return selector === this.tagName;
  }
  querySelectorAll(selector) {
    const descendants = [];
    const visit = parent => parent.children.forEach(child => { descendants.push(child); visit(child); });
    visit(this);
    return descendants.filter(node => selector.split(',').some(part => {
      const tokens = part.trim().split(/\s+/);
      if (!node.matches(tokens.pop())) return false;
      let parent = node.parentElement;
      while (tokens.length) {
        const token = tokens.pop();
        while (parent && !parent.matches(token)) parent = parent.parentElement;
        if (!parent) return false;
        parent = parent.parentElement;
      }
      return true;
    }));
  }
  querySelector(selector) { return this.querySelectorAll(selector)[0] || null; }
  addEventListener(type, callback) { (this.events[type] ||= []).push(callback); }
  dispatch(type) { for (const callback of this.events[type] || []) callback({type, target: this}); }
  focus() { if (!this.disabled) this.document.activeElement = this; }
}
const pwa = (fields = {}) => ({id: 'pwa/one', label: 'Fixture PWA', path: 'C:\\Browser\\browser.exe',
  adapter: 'chrome', enabled: true, active: false, cleanup_pending: false, profile_preparing: false,
  use_original_data: false, web_app: {browser: 'chrome', profile_directory: 'Profile 1',
    app_id: 'a'.repeat(32), start_url: 'https://fixture.invalid/app'}, ...fields});
const makeState = (platform, apps, fields = {}) => ({platform, apps, token: 'offline-fixture',
  running: true, imported: true, capture_mode: 'applications', protection: {supported: true},
  nodes: [], available_apps: [], ...fields});
async function mount(initial) {
  const document = {hidden: false, ids: new Map()};
  document.body = new Element('body', document); document.activeElement = document.body;
  document.createElement = tag => new Element(tag, document);
  document.getElementById = id => {
    if (!document.ids.has(id)) {
      const element = document.createElement('div');
      document.ids.set(id, element); document.body.append(element);
    }
    return document.ids.get(id);
  };
  document.querySelectorAll = selector => document.body.querySelectorAll(selector);
  const session = {document, server: structuredClone(initial), requests: [], failNext: null, pausePost: null};
  const context = {document, CSS: {escape: value => String(value).replace(/[^\w-]/g, '\\$&')},
    window: {setInterval: () => 1, setTimeout: () => 1},
    fetch: async (url, options = {}) => {
      const request = {url, method: options.method || 'GET', headers: options.headers,
        body: options.body ? JSON.parse(options.body) : undefined};
      session.requests.push(request);
      if (request.method === 'POST') {
        if (session.pausePost) await session.pausePost;
        if (session.failNext) {
          const error = session.failNext; session.failNext = null;
          if (error instanceof Error) throw error;
          return {ok: false, status: 409, json: async () => ({error})};
        }
        if (url === '/api/apps') session.server.apps.push({id: 'added', ...request.body});
        else if (url.endsWith('/shortcut')) {
          assert.ok(session.server.apps.some(app => url === `/api/apps/${encodeURIComponent(app.id)}/shortcut`));
          assert.deepEqual(request.body, {});
          return {ok: true, status: 200, json: async () => ({created: ['fixture.desktop']})};
        }
        else if (url.endsWith('/stop')) {
          const app = session.server.apps.find(app => url === `/api/apps/${encodeURIComponent(app.id)}/stop`);
          assert.ok(app); assert.deepEqual(request.body, {});
          app.active = false;
        }
        else {
          const app = session.server.apps.find(app => url === `/api/apps/${encodeURIComponent(app.id)}/profile`);
          assert.ok(app, `unexpected mutation: ${url}`);
          assert.deepEqual(Object.keys(request.body), ['use_original_data']);
          assert.equal(typeof request.body.use_original_data, 'boolean');
          app.use_original_data = request.body.use_original_data;
        }
      } else assert.equal(url, '/api/state');
      return {ok: true, status: 200, json: async () => structuredClone(session.server)};
    },
  };
  const end = SOURCE.lastIndexOf('\n})();');
  assert.ok(end > 0);
  vm.runInNewContext(SOURCE.slice(0, end)
    + '\n  globalThis.uiTestHooks = {render, readState};' + SOURCE.slice(end), context);
  await flush();
  session.element = id => document.getElementById(id);
  session.rows = () => session.element('apps-list').querySelectorAll('.app-row');
  session.profile = (index = 0) => session.rows()[index].querySelector('.app-profile-option input');
  session.posts = () => session.requests.filter(request => request.method === 'POST');
  session.poll = async () => { await context.uiTestHooks.readState({quiet: true}); await flush(); };
  session.change = async (value, index = 0) => {
    const control = session.profile(index); control.focus(); control.checked = value;
    control.dispatch('change'); await flush();
  };
  return session;
}
function assertMode(session, original, index = 0) {
  const row = session.rows()[index];
  assert.equal(session.profile(index).checked, original);
  const note = row.querySelector('.app-web-note').textContent;
  const badge = row.querySelector('.app-adapter').textContent;
  assert.match(note, original ? /原所属 Profile.*登录资料/ : /独立资料.*首次需重新登录/);
  assert.match(badge, original ? /原所属 Profile/ : /独立资料/);
  if (original) { assert.doesNotMatch(note, /独立资料|首次需重新登录/); assert.doesNotMatch(badge, /独立/); }
}
'''


@unittest.skipUnless(NODE, 'Node.js is required for actual UI event execution')
class WindowsPWAProfileUITests(unittest.TestCase):
    def run_case(self, code):
        source = (ROOT / 'web/app.js').read_text(encoding='utf-8')
        script = 'const SOURCE = ' + json.dumps(source) + ';\n' + HARNESS
        script += '\n(async () => {\n' + code + '\n})().catch(error => { console.error(error); process.exitCode = 1; });'
        result = subprocess.run([NODE, '-e', script], capture_output=True, text=True, timeout=20)
        self.assertEqual(result.returncode, 0, result.stderr)

    def test_all_windows_pwa_browsers_preserve_saved_choice_and_describe_precise_profile(self):
        self.run_case(r'''
for (const [browser, adapter] of [['chrome', 'chrome'], ['edge', 'edge'], ['brave', 'brave'],
                                 ['chromium', 'chromium'], ['vivaldi', 'chromium']]) {
  for (const original of [false, true, undefined, 'true', 1]) {
    const app = pwa({adapter, use_original_data: original}); app.web_app.browser = browser;
    const before = JSON.stringify(app);
    const session = await mount(makeState('Windows', [app]));
    assertMode(session, original === true);
    assert.equal(JSON.stringify(app), before);
    assert.equal(session.posts().length, 0);
    assert.equal(session.profile().disabled, false);
    assert.match(session.profile().title, /原所属 Profile.*共享|共享.*原所属 Profile/);
    assert.match(session.profile().title, /修改互通.*已有浏览器进程.*不纳入本工具关闭范围/);
    assert.match(session.profile().title, /下次启动生效/);
    if (original === true) assert.match(session.rows()[0].textContent, /Profile 1/);
  }
}
''')

    def test_toggle_uses_existing_boolean_post_and_updates_note_badge_and_focus(self):
        self.run_case(r'''
for (const platform of ['Windows', 'Linux']) {
for (const appId of ['a'.repeat(32), '']) {
  const app = pwa(); app.web_app.app_id = appId;
  const session = await mount(makeState(platform, [app]));
  for (const choice of [true, false]) {
    await session.change(choice);
    assertMode(session, choice);
    const request = session.posts().at(-1);
    assert.equal(request.url, '/api/apps/pwa%2Fone/profile');
    assert.deepEqual(request.body, {use_original_data: choice});
    assert.equal(request.headers['X-RuleProxy-Token'], 'offline-fixture');
    assert.equal(session.document.activeElement, session.profile());
    assert.equal(session.profile().disabled, false);
    assert.deepEqual(session.server.apps[0].web_app, app.web_app);
  }
}
}
''')

    def test_http_and_network_errors_rollback_both_directions_and_keep_error_focus(self):
        self.run_case(r'''
for (const platform of ['Windows', 'Linux']) {
for (const initial of [false, true]) {
  for (const failure of ['fixture profile conflict', 'fixture occupied original root',
                         'fixture keyring unavailable', new Error('fixture network failure')]) {
    const session = await mount(makeState(platform, [pwa({use_original_data: initial})]));
    session.failNext = failure;
    await session.change(!initial);
    assertMode(session, initial);
    assert.equal(session.document.activeElement, session.profile());
    assert.equal(session.profile().disabled, false);
    assert.equal(session.element('global-error').textContent, failure.message || failure);
    assert.equal(session.element('global-error').hidden, false);
    assert.equal(session.requests.filter(r => r.method === 'GET').length, 2);
  }
}
}
''')

    def test_pending_request_keeps_confirmed_mode_and_does_not_steal_moved_focus(self):
        self.run_case(r'''
for (const platform of ['Windows', 'Linux']) {
const session = await mount(makeState(platform, [pwa()]));
let release;
session.pausePost = new Promise(resolve => { release = resolve; });
const control = session.profile(); control.focus(); control.checked = true; control.dispatch('change');
assert.equal(control.disabled, true);
assertMode(session, false);
control.checked = true; control.dispatch('change');
assertMode(session, false);
assert.equal(session.posts().length, 1);
session.element('app-search').focus();
release(); await flush();
assertMode(session, true);
assert.equal(session.document.activeElement, session.element('app-search'));
}
''')

    def test_recovery_poll_uses_authoritative_saved_state_after_lost_response(self):
        self.run_case(r'''
for (const platform of ['Windows', 'Linux']) {
const session = await mount(makeState(platform, [pwa()]));
session.server.apps[0].use_original_data = true;
session.failNext = new Error('fixture lost response');
await session.change(true);
assertMode(session, true);
assert.equal(session.element('global-error').textContent, 'fixture lost response');
assert.equal(session.document.activeElement, session.profile());
}
''')

    def test_active_cleanup_and_preparation_disable_changes_and_show_close_instruction(self):
        self.run_case(r'''
for (const platform of ['Windows', 'Linux']) {
for (const [field, status] of [['active', platform === 'Windows' ? '代理中运行' : '隔离中运行'], ['cleanup_pending', '清理待完成'],
                              ['profile_preparing', '检查应用资料…']]) {
  for (const original of [false, true]) {
    const session = await mount(makeState(platform, [pwa({[field]: true, use_original_data: original})]));
    assertMode(session, original);
    assert.equal(session.profile().disabled, true);
    assert.match(session.profile().title, /请先关闭本工具启动的实例/);
    assert.match(session.rows()[0].querySelector('.app-profile-hint').textContent, /请先关闭本工具启动的实例/);
    assert.equal(session.rows()[0].querySelector('.app-inline-status').textContent, status);
    await session.change(!original);
    assertMode(session, original);
    assert.equal(session.posts().length, 0);
    session.server.apps[0][field] = false;
    await session.poll();
    assert.equal(session.profile().disabled, false);
    assert.equal(session.rows()[0].querySelector('.app-profile-hint'), null);
  }
}
}
''')

    def test_shared_close_scope_is_explicit_and_isolated_and_ordinary_labels_stay_unchanged(self):
        self.run_case(r'''
for (const original of [false, true]) {
  const session = await mount(makeState('Windows', [pwa({active: true, use_original_data: original})]));
  const action = session.rows()[0].querySelector('.app-action');
  assert.equal(action.textContent, original ? '关闭共享实例' : '关闭实例');
  assert.equal(action.title, original
    ? '关闭本工具启动的浏览器实例，共用该实例的窗口会一起关闭' : '关闭此工具启动的实例');
  if (original) {
    const note = session.rows()[0].querySelector('.app-web-note').textContent;
    assert.match(note, /同实例的窗口会一起关闭/);
    assert.match(note, /已有浏览器接力实例不纳入关闭范围/);
  }
}
const browser = pwa({active: true, use_original_data: true}); delete browser.web_app;
const ordinary = await mount(makeState('Windows', [browser]));
assert.equal(ordinary.rows()[0].querySelector('.app-action').textContent, '关闭实例');
assert.equal(ordinary.rows()[0].querySelector('.app-action').title, '关闭此工具启动的实例');
''')

    def test_linux_pwa_defaults_to_independent_with_explicit_original_profile_option(self):
        self.run_case(r'''
for (const [browser, adapter] of [['chrome', 'chrome'], ['edge', 'edge'], ['brave', 'brave'],
                                 ['chromium', 'chromium'], ['vivaldi', 'chromium']]) {
  for (const profile of ['Default', 'Profile 1']) {
    for (const original of [false, true, undefined, 'true', 1]) {
      const app = pwa({adapter, path: '/opt/browser/browser', use_original_data: original});
      app.web_app.browser = browser; app.web_app.profile_directory = profile;
      const before = JSON.stringify(app);
      const session = await mount(makeState('Linux', [app]));
      assertMode(session, original === true);
      assert.equal(session.profile().disabled, false);
      assert.equal(JSON.stringify(app), before);
      assert.equal(session.posts().length, 0);
      assert.equal(session.element('web-apps-note').hidden, false);
      assert.match(session.profile().title, /原所属 Profile.*原浏览器资料根.*修改互通.*完全退出/);
      const note = session.rows()[0].querySelector('.app-web-note').textContent;
      assert.match(note, /开启或启动原资料模式前.*完全退出占用原资料根.*后台进程/);
      assert.match(note, /下次启动生效.*命名空间隔离/);
      assert.doesNotMatch(note + session.profile().title, /接力|路径代理|关闭共享实例|Windows/);
      if (original === true) {
        assert.ok(note.includes(profile));
        assert.match(note, /原资料根通过受限绑定开放.*密钥服务使用受限通道/);
      }
    }
  }
}
''')

    def test_linux_mode_and_platform_poll_refresh_without_app_record_changes(self):
        self.run_case(r'''
for (const original of [false, true]) {
  const session = await mount(makeState('Linux', [pwa({use_original_data: original})], {running: false}));
  const appRecord = JSON.stringify(session.server.apps);
  session.profile().focus();
  for (const mode of ['global', 'applications', 'global']) {
    const before = session.rows()[0];
    session.server.capture_mode = mode; await session.poll();
    assert.equal(JSON.stringify(session.server.apps), appRecord);
    assert.notEqual(session.rows()[0], before);
    assertMode(session, original);
    assert.equal(session.rows()[0].querySelector('.app-action').textContent,
      mode === 'global' ? '启动应用 ↗' : '启动隔离实例 ↗');
    const note = session.rows()[0].querySelector('.app-web-note').textContent;
    if (mode === 'global') {
      assert.match(note, /全局模式使用系统代理，不附带按应用命名空间隔离/);
      assert.doesNotMatch(note, /保留网络与进程|受限绑定|密钥服务使用受限通道/);
    } else assert.match(note, /按应用模式.*网络与进程命名空间隔离/);
    assert.equal(session.document.activeElement, session.profile());
    const unchanged = session.rows()[0]; await session.poll();
    assert.equal(session.rows()[0], unchanged);
  }
  assert.equal(session.posts().length, 0);
}
const session = await mount(makeState('Windows', [pwa({active: true, use_original_data: true})]));
const appRecord = JSON.stringify(session.server.apps);
for (const platform of ['Linux', 'Windows', 'Darwin']) {
  session.server.platform = platform; await session.poll();
  assert.equal(JSON.stringify(session.server.apps), appRecord);
  const action = session.rows()[0].querySelector('.app-action');
  assert.equal(action.textContent, platform === 'Windows' ? '关闭共享实例' : '关闭实例');
  if (platform === 'Linux') {
    assertMode(session, true);
    assert.equal(action.title, '关闭此工具启动的实例');
    assert.doesNotMatch(session.rows()[0].textContent, /接力|路径代理|关闭共享实例/);
  }
  if (platform === 'Darwin') {
    assert.equal(session.profile(), null);
    assert.equal(session.element('web-apps-note').hidden, true);
  }
}
''')

    def test_linux_shortcut_keeps_saved_app_id_and_current_profile_choice(self):
        self.run_case(r'''
const session = await mount(makeState('Linux', [pwa({path: '/opt/browser/browser'})]));
for (const original of [true, false]) {
  await session.change(original); assertMode(session, original);
  const saved = structuredClone(session.server.apps[0]);
  session.rows()[0].querySelector('.app-shortcut').dispatch('click'); await flush();
  assert.deepEqual(structuredClone(session.posts().at(-1)), {url: '/api/apps/pwa%2Fone/shortcut', method: 'POST',
    headers: {'Content-Type': 'application/json', 'X-RuleProxy-Token': 'offline-fixture'}, body: {}});
  assert.deepEqual(session.server.apps[0], saved);
  assertMode(session, original);
}
''')

    def test_linux_close_notice_matches_mode_without_windows_shared_scope(self):
        self.run_case(r'''
for (const mode of ['applications', 'global']) {
  const session = await mount(makeState('Linux', [pwa({active: true, use_original_data: true})], {capture_mode: mode}));
  const action = session.rows()[0].querySelector('.app-action');
  assert.equal(action.textContent, '关闭实例');
  assert.equal(action.title, '关闭此工具启动的实例');
  action.dispatch('click'); await flush();
  assert.equal(session.posts().at(-1).url, '/api/apps/pwa%2Fone/stop');
  assert.equal(session.element('global-error').textContent,
    mode === 'global' ? 'Fixture PWA的实例已关闭。' : 'Fixture PWA的隔离实例已关闭。');
  assertMode(session, true);
  assert.equal(session.profile().disabled, false);
}
''')

    def test_ordinary_browser_controls_still_work_on_both_platforms(self):
        self.run_case(r'''
for (const platform of ['Windows', 'Linux']) {
  for (const adapter of ['chrome', 'chromium', 'edge', 'brave', 'firefox']) {
    const app = pwa({adapter}); delete app.web_app;
    const session = await mount(makeState(platform, [app]));
    assert.equal(session.profile().checked, false);
    assert.equal(session.rows()[0].querySelector('.app-web-note'), null);
    await session.change(true);
    assert.equal(session.profile().checked, true);
    assert.match(session.rows()[0].querySelector('.app-adapter').textContent, /原应用数据/);
    await session.change(false);
    assert.equal(session.profile().checked, false);
    assert.match(session.rows()[0].querySelector('.app-adapter').textContent, /独立配置/);
    assert.equal(session.posts().length, 2);
  }
}
''')

    def test_discovery_defaults_to_false_and_identity_ignores_profile_mode(self):
        self.run_case(r'''
for (const platform of ['Windows', 'Linux']) {
  const discovered = pwa({use_original_data: true});
  const session = await mount(makeState(platform, [], {available_apps: [discovered]}));
  const available = session.element('available-apps-list');
  const hint = available.querySelector('.available-app-hint').textContent;
  assert.match(hint, /独立.*首次需重新登录/);
  if (platform === 'Windows') {
    assert.match(hint, /添加后可开启/);
    assert.match(session.element('web-apps-note').textContent, /默认使用独立资料.*添加后可选择/);
  } else {
    assert.match(hint, /添加后可开启.*使用原应用数据.*完全退出占用原资料根/);
    assert.match(session.element('web-apps-note').textContent, /默认使用独立资料.*添加后可选择.*已有快捷方式跟随保存/);
    assert.doesNotMatch(hint, /路径代理|接力/);
  }
  available.querySelector('.discovery-add').dispatch('click'); await flush();
  assert.equal(session.posts()[0].url, '/api/apps');
  assert.equal(session.posts()[0].body.use_original_data, false);
}
const saved = pwa({use_original_data: true});
const original = pwa();
const otherProfile = pwa({web_app: {...original.web_app, profile_directory: 'Profile 2'}});
const otherPwa = pwa({web_app: {...original.web_app, app_id: 'b'.repeat(32)}});
const browser = pwa(); delete browser.web_app;
const session = await mount(makeState('Windows', [saved], {available_apps: [original, otherProfile, otherPwa, browser]}));
const added = () => session.element('available-apps-list').querySelectorAll('.discovery-add').map(x => x.dataset.added);
assert.deepEqual(added(), ['true', 'false', 'false', 'false']);
await session.change(false);
assert.deepEqual(added(), ['true', 'false', 'false', 'false']);
''')

    def test_discovery_platform_poll_refreshes_hint_without_record_changes(self):
        self.run_case(r'''
const session = await mount(makeState('Windows', [pwa({use_original_data: true})], {available_apps: [pwa()]}));
const records = JSON.stringify([session.server.apps, session.server.available_apps]);
const hint = () => session.element('available-apps-list').querySelector('.available-app-hint');
assert.match(hint().textContent, /同浏览器其他窗口也可能走代理/);
for (const platform of ['Linux', 'Windows']) {
  session.server.platform = platform; await session.poll();
  assert.equal(JSON.stringify([session.server.apps, session.server.available_apps]), records);
  if (platform === 'Linux') {
    assert.match(hint().textContent, /使用原应用数据.*完全退出占用原资料根/);
    assert.doesNotMatch(hint().textContent, /同浏览器其他窗口也可能走代理/);
  } else assert.match(hint().textContent, /同浏览器其他窗口也可能走代理/);
}
const beforeMode = hint(); session.server.capture_mode = 'global'; await session.poll();
assert.equal(hint(), beforeMode);
assert.equal(session.posts().length, 0);
''')


if __name__ == '__main__':
    unittest.main()
