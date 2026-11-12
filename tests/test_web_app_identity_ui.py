"""Exercise the actual UI identity helpers without a browser or private data."""
import json
from pathlib import Path
import shutil
import subprocess
import unittest


ROOT = Path(__file__).resolve().parents[1]


@unittest.skipUnless(shutil.which('node'), 'Node.js is required for UI helper execution')
class WebAppIdentityUITests(unittest.TestCase):
    def check_platform(self, platform):
        source = (ROOT / 'web/app.js').read_text(encoding='utf-8')
        functions = source[source.index('  function sameAppPath('):source.index('  function renderAvailableApps(')]
        script = r'''
const assert = require('node:assert/strict');
const vm = require('node:vm');
const platform = PLATFORM;
const functions = FUNCTIONS;
const windows = platform === 'Windows';
const api = vm.runInNewContext(`(() => {
  const isWindows = () => /windows|win32|win64/i.test(state.platform);
  ${functions}
  return {sameAppPath, sameApp};
})()`, {state: {platform}});
assert.equal(api.sameAppPath('/opt/Chrome/chrome', '/opt/chrome/chrome'), windows);
assert.equal(api.sameAppPath('/opt/a\\b/chrome', '/opt/a/b/chrome'), windows);
assert.equal(api.sameAppPath('/opt/chrome/', '/opt/chrome'), windows);
assert.equal(api.sameAppPath('/opt/chrome/chrome', '/opt/chrome/chrome'), true);
const app = {path: '/opt/chrome/chrome', web_app: {profile_directory: 'Default', app_id: 'a'.repeat(32)}};
const change = fields => ({...app, web_app: {...app.web_app, ...fields}});
assert.equal(api.sameApp(app, change({profile_directory: 'default'})), windows);
assert.equal(api.sameApp(app, change({profile_directory: 'Profile 1'})), false);
assert.equal(api.sameApp(app, change({app_id: 'b'.repeat(32)})), false);
assert.equal(api.sameApp(app, {path: app.path}), false);
assert.equal(api.sameApp(app, change({})), true);
assert.equal(api.sameApp({path: app.path}, {path: app.path}), true);
'''.replace('PLATFORM', json.dumps(platform)).replace('FUNCTIONS', json.dumps(functions))
        result = subprocess.run([shutil.which('node'), '-e', script], capture_output=True, text=True, timeout=15)
        self.assertEqual(result.returncode, 0, result.stderr)

    def test_linux_identity_preserves_case_and_backslashes(self):
        self.check_platform('Linux')

    def test_windows_identity_keeps_existing_normalization(self):
        self.check_platform('Windows')


if __name__ == '__main__':
    unittest.main()
