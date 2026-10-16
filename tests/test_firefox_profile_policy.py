"""A namespace-only locked policy must leave original profile/settings intact."""
import json
import os
from pathlib import Path
import sys
import tempfile
import unittest
from unittest.mock import patch

from ruleproxy import firefox_profile_policy as policy


@unittest.skipUnless(sys.platform.startswith('linux'), 'Linux Firefox namespace policy')
class FirefoxProfilePolicyTests(unittest.TestCase):
    def setUp(self):
        temporary = tempfile.TemporaryDirectory(prefix='ruleproxy-firefox-policy-test-')
        self.addCleanup(temporary.cleanup)
        self.root = Path(temporary.name)
        self.executable = self.root / 'browser/firefox'
        self.executable.parent.mkdir()
        self.executable.write_bytes(b'\x7fELF synthetic browser; never executed')
        self.workspace = self.root / 'private-workspace'
        self.targets = (self.root / 'etc/firefox/policies', self.root / 'etc/firefox-esr/policies')
        system = patch.object(policy, 'SYSTEM_POLICY_DIRS', self.targets)
        system.start()
        self.addCleanup(system.stop)

    def write_policy(self, folder, data):
        folder.mkdir(parents=True, exist_ok=True)
        path = folder / 'policies.json'
        path.write_text(json.dumps(data), encoding='utf-8')
        return path

    def test_locked_proxy_is_mounted_without_creating_missing_system_paths(self):
        mounts = policy.prepare_policy_mounts(self.executable, self.workspace, 39017)
        self.assertEqual([target for _source, target in mounts], [*self.targets, self.executable.parent / 'distribution'])
        for source, target in mounts:
            value = json.loads((source / 'policies.json').read_text())['policies']['Proxy']
            self.assertEqual(value, {'Mode': 'manual', 'Locked': True, 'SOCKSProxy': '127.0.0.1:39017',
                                     'SOCKSVersion': 5, 'UseProxyForDNS': True, 'Passthrough': '',
                                     'UseHTTPProxyForAllProtocols': False})
            self.assertFalse(target.exists())
            self.assertTrue(source.is_relative_to(self.workspace))
            self.assertNotEqual(target, self.executable.parent)
            self.assertEqual(source.stat().st_mode & 0o777, 0o700)
            self.assertEqual((source / 'policies.json').stat().st_mode & 0o777, 0o600)

    def test_existing_policies_distribution_files_and_original_user_prefs_are_preserved(self):
        original = self.write_policy(self.targets[0], {'policies': {'Homepage': {'URL': 'https://example.test/'},
                                                                   'Proxy': {'Mode': 'none'}}, 'metadata': 'keep'})
        distribution = self.executable.parent / 'distribution'
        second = self.write_policy(distribution, {'policies': {'DisableTelemetry': True}})
        addon = distribution / 'extensions/example.test/addon.xpi'
        addon.parent.mkdir(parents=True)
        addon.write_bytes(b'synthetic packaged distribution addon')
        profile = self.root / 'original-profile'
        profile.mkdir()
        for name in ('user.js', 'prefs.js', 'cookies.sqlite', 'places.sqlite'):
            (profile / name).write_bytes(('original synthetic ' + name).encode('ascii'))
        before = {path: (path.read_bytes(), path.stat().st_mtime_ns)
                  for path in (original, second, addon, *profile.iterdir())}
        mounts = dict((target, source) for source, target in policy.prepare_policy_mounts(self.executable, self.workspace, 10809))
        first_copy = json.loads((mounts[self.targets[0]] / 'policies.json').read_text())
        self.assertEqual(first_copy['policies']['Homepage'], {'URL': 'https://example.test/'})
        self.assertEqual(first_copy['metadata'], 'keep')
        self.assertTrue(json.loads((mounts[distribution] / 'policies.json').read_text())['policies']['DisableTelemetry'])
        self.assertEqual((mounts[distribution] / 'extensions/example.test/addon.xpi').read_bytes(), addon.read_bytes())
        self.assertEqual({path: (path.read_bytes(), path.stat().st_mtime_ns) for path in before}, before)
        self.assertEqual({path.name for path in profile.iterdir()}, {'user.js', 'prefs.js', 'cookies.sqlite', 'places.sqlite'})

    def test_bad_port_malformed_or_disabled_policy_fails_without_partial_mount_trees(self):
        for port in (True, 0, 65536, '10809'):
            with self.subTest(port=port), self.assertRaises(ValueError):
                policy.prepare_policy_mounts(self.executable, self.workspace, port)
        original = self.write_policy(self.targets[0], {})
        for value in ('not json', '[]', '{"policies": []}', '{"policies":{"DisableEnterprisePolicies":true}}',
                      '{"policies":{"DisableLocalPolicies":true}}', '{"policies":{"Preferences":[]}}'):
            original.write_text(value, encoding='utf-8')
            with self.subTest(value=value), self.assertRaises(ValueError):
                policy.prepare_policy_mounts(self.executable, self.workspace, 10809)
            self.assertEqual(list(self.workspace.iterdir()), [])
            self.assertEqual(original.read_text(), value)

    def test_original_http_and_pac_defaults_are_cleared_only_in_private_locked_preferences(self):
        previous = {'policies': {'Proxy': {'Mode': 'autoConfig', 'AutoConfigURL': 'https://pac.example.test/'},
                                  'Preferences': {'network.proxy.http': {'Value': 'old.example.test', 'Status': 'locked'},
                                                  'network.proxy.ssl_port': 8443,
                                                  'browser.startup.homepage': 'https://home.example.test/'}}}
        original = self.write_policy(self.targets[0], previous)
        before = original.read_bytes()
        mounts = dict((target, source) for source, target in policy.prepare_policy_mounts(self.executable, self.workspace, 39017))
        value = json.loads((mounts[self.targets[0]] / 'policies.json').read_text())['policies']
        self.assertEqual(value['Proxy']['SOCKSProxy'], '127.0.0.1:39017')
        self.assertEqual(value['Preferences']['browser.startup.homepage'], 'https://home.example.test/')
        for name, expected in {'network.proxy.http': '', 'network.proxy.http_port': 0,
                               'network.proxy.ssl': '', 'network.proxy.ssl_port': 0,
                               'network.proxy.ftp': '', 'network.proxy.ftp_port': 0,
                               'network.proxy.autoconfig_url': ''}.items():
            setting = value['Preferences'][name]
            self.assertEqual(setting, {'Value': expected, 'Status': 'locked',
                                       'Type': 'number' if isinstance(expected, int) else 'string'})
        self.assertEqual(original.read_bytes(), before)

    def test_symlink_and_special_file_inputs_are_rejected(self):
        distribution = self.executable.parent / 'distribution'
        distribution.mkdir()
        secret = self.root / 'not-a-distribution-file'
        secret.write_bytes(b'synthetic unrelated data')
        linked = distribution / 'policies.json'
        linked.symlink_to(secret)
        with self.assertRaisesRegex(ValueError, '链接'):
            policy.prepare_policy_mounts(self.executable, self.workspace, 10809)
        linked.unlink()
        os.mkfifo(distribution / 'broker.pipe')
        with self.assertRaisesRegex(ValueError, '不支持'):
            policy.prepare_policy_mounts(self.executable, self.workspace, 10809)
        self.assertEqual(secret.read_bytes(), b'synthetic unrelated data')
        self.assertEqual(list(self.workspace.iterdir()), [])

    def test_existing_source_and_workspace_cannot_overlap(self):
        distribution = self.executable.parent / 'distribution'
        distribution.mkdir()
        destination = distribution / 'must-not-create'
        with self.assertRaisesRegex(ValueError, '原策略目录内'):
            policy.prepare_policy_mounts(self.executable, destination, 10809)
        self.assertFalse(destination.exists())

    def test_distribution_copy_has_file_size_and_time_bounds_and_cleans_up(self):
        original = self.write_policy(self.targets[0], {'policies': {'DisableTelemetry': True}})
        for name, value in (('MAX_POLICY_FILES', 0), ('MAX_POLICY_BYTES', 1)):
            with self.subTest(bound=name), patch.object(policy, name, value), self.assertRaises(ValueError):
                policy.prepare_policy_mounts(self.executable, self.workspace, 10809)
            self.assertEqual(list(self.workspace.iterdir()), [])
        with patch.object(policy.time, 'monotonic', side_effect=[0, 6]), self.assertRaisesRegex(ValueError, '时间限制'):
            policy.prepare_policy_mounts(self.executable, self.workspace, 10809)
        self.assertEqual(list(self.workspace.iterdir()), [])
        self.assertTrue(original.exists())


if __name__ == '__main__':
    unittest.main()
