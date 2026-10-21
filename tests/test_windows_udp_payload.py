"""Actual four-mode payload writer and production-AST gate source contracts."""
import importlib.util
from pathlib import Path
import tempfile
import unittest
import zipfile
ROOT=Path(__file__).resolve().parents[1]
spec=importlib.util.spec_from_file_location('udp_payload_fixture',ROOT/'.github/test_windows_udp_payload.py')
gate=importlib.util.module_from_spec(spec);spec.loader.exec_module(gate)
class PayloadTests(unittest.TestCase):
    def test_actual_all_four_writers_and_equal_count_negatives(self):
        with tempfile.TemporaryDirectory() as directory:
            root=Path(directory)/'owned';result=gate.generate(root)
            self.assertEqual(result['members'],[10,14,15,17,22]);self.assertFalse(result['runtime_artifact'])
            for name,count in zip(('baseline','n0a','capture','udp','parent_udp'),(10,14,15,17,22)):
                with zipfile.ZipFile(root/(name+'.zip')) as archive:self.assertEqual(len(archive.namelist()),count)
            with zipfile.ZipFile(root/'udp.zip') as archive:
                names=set(archive.namelist())
                for member in names:
                    if member.startswith('.github/') or member.startswith('ruleproxy/'):
                        self.assertEqual(archive.read(member),(ROOT/member).read_bytes())
            for index,forbidden in enumerate(gate.FORBIDDEN):
                with zipfile.ZipFile(root/f'udp-bad-{index}.zip') as archive:
                    self.assertEqual(len(archive.namelist()),17);self.assertIn(forbidden,archive.namelist())
                    self.assertNotEqual(set(archive.namelist()),names)
    def test_parent_actual22_source_bytes_and_equal_count_negatives(self):
        with tempfile.TemporaryDirectory() as directory:
            root=Path(directory)/'owned';gate.generate(root)
            with zipfile.ZipFile(root/'udp.zip') as archive:old=set(archive.namelist())
            with zipfile.ZipFile(root/'parent_udp.zip') as archive:
                names=set(archive.namelist())
                expected={'parent/actor.exe','parent/build-manifest.json',*('.github/windows_n0a_udp_parent_'+suffix+'.py' for suffix in ('control','guest','flow'))}
                self.assertEqual(names,old|expected);self.assertEqual(len(names),22)
                self.assertFalse(any('TEST_ONLY' in name for name in names))
                for member in names:
                    if member.startswith(('.github/','ruleproxy/')):self.assertEqual(archive.read(member),(ROOT/member).read_bytes())
            for index,forbidden in enumerate(gate.PARENT_FORBIDDEN):
                with zipfile.ZipFile(root/f'parent_udp-bad-{index}.zip') as archive:
                    self.assertEqual(len(archive.namelist()),22);self.assertIn(forbidden,archive.namelist());self.assertNotEqual(set(archive.namelist()),names)
    def test_existing_destination_refused(self):
        with tempfile.TemporaryDirectory() as directory:
            with self.assertRaises(FileExistsError):gate.generate(Path(directory))
    def test_ast_gate_uses_exact_producer_selector_and_extractor(self):
        source=(ROOT/'.github/test-windows-udp-payload-gates.ps1').read_text()
        for fragment in ('FunctionDefinitionAst','AssignmentStatementAst','IfStatementAst',
                         'Get-N0aUdpPayloadNames','Expand-CheckedStage0Zip',"$branches[0].Extent.Text",
                         "@('baseline','n0a','capture','udp','parent_udp')",'test_windows_udp_payload.py',
                         'Check (-not (Test-Path -LiteralPath $workspace))','ReparsePoint'):
            self.assertIn(fragment,source)
        for count in (10,14,15,17,22):self.assertIn('-MemberCount '+str(count),source)
        self.assertNotIn('& $source',source);self.assertNotIn('Start-Process',source)
        self.assertIn('runtime_artifact=$false',source)
    def test_cleanup_requires_successful_exclusive_generation(self):
        source=(ROOT/'.github/test-windows-udp-payload-gates.ps1').read_text()
        self.assertIn('$cleanupAuthorized=$false',source)
        self.assertEqual(source.count('$cleanupAuthorized=$true'),1)
        self.assertLess(source.index('Check ($LASTEXITCODE -eq 0)'),source.index('$cleanupAuthorized=$true'))
        self.assertLess(source.index("if(-not $cleanupAuthorized) { throw 'ownership_unconfirmed' }"),source.index('Remove-Item -LiteralPath $owned'))
        # Existing-root rejection also executes the real generator above; the PS
        # authorization remains false on any thrown Check before successful exit.
    def test_actual_udp_selector_names_match_production_payload(self):
        ps=(ROOT/'.github/windows-identity-direct-stage0-run.ps1').read_text()
        body=ps.split('function Get-N0aUdpPayloadNames {',1)[1].split('\n}',1)[0]
        import re
        extras=set(re.findall("'([^']+)'",body))
        self.assertEqual(len(extras),7)
        with tempfile.TemporaryDirectory() as directory:
            root=Path(directory)/'owned';gate.generate(root)
            with zipfile.ZipFile(root/'baseline.zip') as archive:base=set(archive.namelist())
            with zipfile.ZipFile(root/'udp.zip') as archive:self.assertEqual(set(archive.namelist()),base|extras)
if __name__=='__main__':unittest.main()
