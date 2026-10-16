"""Protected installer tests use only temporary paths and a mocked import check."""
import importlib.util
import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest
from unittest.mock import patch
import hashlib
from contextlib import nullcontext

ROOT=Path(__file__).resolve().parent.parent
SPEC=importlib.util.spec_from_file_location('ruleproxy_global_installer',ROOT/'scripts/install-linux-global.py')
installer=importlib.util.module_from_spec(SPEC);SPEC.loader.exec_module(installer)


@unittest.skipUnless(sys.platform=='linux','Linux protected installer permissions')
class GlobalInstallTests(unittest.TestCase):
    def setUp(self):
        self.temporary=tempfile.TemporaryDirectory();self.addCleanup(self.temporary.cleanup)
        self.root=Path(self.temporary.name);self.source=self.root/'source'
        (self.source/'ruleproxy').mkdir(parents=True);(self.source/'vendor/yaml').mkdir(parents=True)
        (self.source/'bin/linux-amd64').mkdir(parents=True)
        for name in installer.MODULES:(self.source/'ruleproxy'/name).write_text('# fixture\n')
        (self.source/'vendor/yaml/__init__.py').write_text('# pure yaml fixture\n')
        (self.source/'bin/linux-amd64/mihomo').write_bytes(b'fixed fixture core')
        self.destination=self.root/'libexec/ruleproxy-web-global';self.destination.parent.mkdir()
        self.policy=self.root/'polkit/io.ruleproxy.global.policy';self.policy.parent.mkdir()
        self.run=self.root/'run';self.run.mkdir()
        for item in (patch.object(installer,'DESTINATION',self.destination),patch.object(installer,'POLICY',self.policy),
                     patch.object(installer,'RUN',self.run),patch.object(installer,'trusted_directory'),
                     patch.object(installer,'installation_lock',side_effect=lambda:nullcontext()),
                     patch.object(installer,'CORE_SIZE',len(b'fixed fixture core')),
                     patch.object(installer,'CORE_SHA256',hashlib.sha256(b'fixed fixture core').hexdigest()),
                     patch.object(installer.subprocess,'run',return_value=subprocess.CompletedProcess([],0,b'',b''))):
            item.start();self.addCleanup(item.stop)

    def test_install_copies_fixed_components_without_starting_capture(self):
        installer.install(self.source,1000)
        self.assertEqual(json.loads((self.destination/'owner.json').read_text()),{'owner_uid':1000})
        self.assertEqual((self.destination/'mihomo').read_bytes(),b'fixed fixture core')
        self.assertIn('-I -S',(self.destination/'launch').read_text())
        self.assertNotIn('allow_active>yes',self.policy.read_text())
        calls=installer.subprocess.run.call_args_list
        self.assertEqual(len(calls),1);self.assertIn('import ruleproxy.config',calls[0].args[0][4])
        self.assertFalse(any(self.run.iterdir()))
        for path in self.destination.rglob('*'):
            self.assertEqual(path.stat().st_mode & 0o022,0)

    def test_active_or_crashed_lease_blocks_upgrade_and_removal(self):
        (self.run/'lease-1000.json').write_text('{}')
        with self.assertRaises(ValueError):installer.install(self.source,1000)
        with self.assertRaises(ValueError):installer.remove()
        self.assertFalse(self.destination.exists())

    def test_wrong_core_rejected_before_installation(self):
        (self.source/'bin/linux-amd64/mihomo').write_bytes(b'tampered')
        with self.assertRaises(ValueError):installer.install(self.source,1000)
        self.assertFalse(self.destination.exists());self.assertFalse(self.policy.exists())

    def test_symlink_component_cannot_enter_protected_copy(self):
        source=self.source/'ruleproxy/config.py';source.unlink();source.symlink_to(self.source/'ruleproxy/__init__.py')
        with self.assertRaises(ValueError):installer.install(self.source,1000)
        self.assertFalse(self.destination.exists())

    def test_remove_has_no_network_commands(self):
        installer.install(self.source,1000);installer.subprocess.run.reset_mock()
        installer.remove()
        self.assertFalse(self.destination.exists());self.assertFalse(self.policy.exists())
        installer.subprocess.run.assert_not_called()


if __name__=='__main__':unittest.main()
