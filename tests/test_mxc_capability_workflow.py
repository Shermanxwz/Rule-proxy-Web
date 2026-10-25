"""Exercise the actual workflow's installer call against its path contract."""
import os
from pathlib import Path
import re
import sys
import tempfile
from types import SimpleNamespace
import unittest
from unittest import mock

import yaml


ROOT = Path(__file__).resolve().parents[1]


class CapabilityRuntimePreparationTests(unittest.TestCase):
    def command(self):
        workflow = yaml.safe_load((ROOT / '.github/workflows/mxc-capability.yml').read_text())
        step = next(item for item in workflow['jobs']['arm-observation']['steps']
                    if item.get('name') == 'Prepare an independent package with its original verified runtimes')
        return re.search(r'python -X utf8 -B -c "([^"]+)"', step['run']).group(1)

    def test_installer_receives_absolute_existing_bundle_in_disposable_root(self):
        previous = Path.cwd()
        with tempfile.TemporaryDirectory() as temporary:
            work = Path(temporary).resolve()
            bundle = work / 'fixed-mxc-g-bundle/mxc-g-bundle.zip'
            bundle.parent.mkdir()
            bundle.write_bytes(b'fixture only; the production installer checks the pinned digest')
            target = work / 'extracted/RuleProxy-Web'
            target.mkdir(parents=True)
            def install(platform, **options):
                self.assertEqual(platform, 'windows-amd64')
                self.assertEqual(options['root'], target)
                path = options['g_bundle_path']
                self.assertTrue(path.is_absolute() and path.is_file() and not path.is_symlink())
                self.assertEqual(path, bundle)
                self.assertEqual(options['mxc_variant'], 'g-patched')
                self.assertTrue(options['variant_explicit'])
                self.assertFalse(options['allow_env_bundle_cache'])
            try:
                os.chdir(work)
                with mock.patch.dict(os.environ, RULEPROXY_DIAGNOSTIC_ROOT=str(target)), \
                        mock.patch.dict(sys.modules, install_runtime=SimpleNamespace(install=mock.Mock(side_effect=install))):
                    exec(compile(self.command(), 'workflow-runtime-preparation', 'exec'), {})
                    sys.modules['install_runtime'].install.assert_called_once()
            finally:
                os.chdir(previous)
