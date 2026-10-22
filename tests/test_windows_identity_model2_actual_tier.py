"""Pinned actual-run diagnostics: absent/ambiguous evidence never proves tier."""
import importlib.util
from pathlib import Path
import unittest

ROOT=Path(__file__).resolve().parents[1]
spec=importlib.util.spec_from_file_location('actual_tier_test',ROOT/'.github/windows_identity_model2_live.py')
l=importlib.util.module_from_spec(spec);spec.loader.exec_module(l)


class ActualTierTests(unittest.TestCase):
    def test_only_actual_cli_enables_pinned_tier_console_diagnostics(self):
        self.assertEqual(l.g_command('wxc-exec.exe','request.json',actual=True),
            ['wxc-exec.exe','--debug','--config','request.json'])
        self.assertEqual(l.g_command('wxc-exec.exe','request.json'),
            ['wxc-exec.exe','--probe','--config','request.json'])

    def test_exact_actual_line_still_required_and_not_replaced_by_probe_json(self):
        line=b'selected isolation tier: base-container\r\n'
        self.assertEqual(l.proof.actual_tiers(b'launching bounded actor\r\n'+line+b'Runner completed\r\n'),['base-container'])
        for raw in (b'',b'{"tier":"base-container"}',b'{"backendTier":"base-container"}',
                    b'selected isolation tier: appcontainer-dacl\n',line+line,
                    line+b'selected isolation tier: appcontainer-bfs\n'):
            with self.subTest(raw=raw): self.assertNotEqual(l.proof.actual_tiers(raw),['base-container'])


if __name__=='__main__': unittest.main()
