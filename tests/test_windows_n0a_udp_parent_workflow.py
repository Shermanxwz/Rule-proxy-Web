"""Standalone descendant mechanics publication boundary, not a guest run."""
import ast
import hashlib
from pathlib import Path
import re
import runpy
import unittest

ROOT=Path(__file__).resolve().parents[1]
PATH=ROOT/'.github/workflows/windows-n0a-udp-parent-gates.yml'
OLD=runpy.run_path(str(ROOT/'tests/test_windows_n0a_udp_workflow.py'))
NAMES=OLD['NAMES']+('test_windows_n0a_udp_parent_actor.py','test_windows_n0a_udp_parent_gate.py','test_windows_n0a_udp_parent_workflow.py')+('test_windows_client_n0a_udp_parent_host.py','test_windows_client_n0a_udp_parent_capture_adapter.py','test_windows_udp_parent_guest_transport.py','test_windows_udp_parent_composed.py','test_windows_udp_parent_guest.py')

class ParentWorkflowTests(unittest.TestCase):
    def test_real_yaml_structure_and_exact_required_suites(self):
        import yaml
        text=PATH.read_text(encoding='utf-8');doc=yaml.load(text,Loader=yaml.BaseLoader)
        self.assertEqual(set(doc['on']),{'push'})
        self.assertEqual(doc['on']['push']['branches'],['dot/windows-isolation-proof'])
        for dependency in ('.github/test-windows-n0a-guest-gates.ps1','tests/test_windows_n0a_guest.py'):
            self.assertIn(dependency,doc['on']['push']['paths'])
        self.assertEqual(doc['permissions'],{'contents':'read'})
        self.assertEqual(set(doc['jobs']),{'pure','native-mechanism'})
        self.assertEqual(doc['jobs']['pure']['timeout-minutes'],'5')
        self.assertEqual(doc['jobs']['native-mechanism']['timeout-minutes'],'8')
        self.assertEqual(doc['jobs']['pure']['runs-on'],'ubuntu-24.04')
        self.assertEqual(doc['jobs']['native-mechanism']['runs-on'],'windows-2025')
        self.assertEqual(doc['concurrency']['cancel-in-progress'],'false')
        matches=re.findall(r'names=(\([^\n]+?\)); assert all',text)
        self.assertEqual(len(matches),2)
        for match in matches:self.assertEqual(ast.literal_eval(match),NAMES)
        self.assertEqual(text.count('pip install --disable-pip-version-check "PyYAML==6.0.3"'),2)
        self.assertIn('python -m pip install --disable-pip-version-check "PyYAML==6.0.3"\n          if ($LASTEXITCODE -ne 0)',text)
        for forbidden in ('actions/upload-artifact','workflow_dispatch:','pull_request:','sudo ','continue-on-error','--n0a-udp','qemu-system'):
            self.assertNotIn(forbidden,text)

    def test_exact_marker_branch_event_and_existing_runtime_negatives(self):
        import yaml
        doc=yaml.load(PATH.read_text(),Loader=yaml.BaseLoader)
        marker='[n0a-udp-parent-gates]'
        for job in doc['jobs'].values():
            expr=job['if'][3:-2]
            self.assertTrue(OLD['condition'](expr,marker))
            self.assertFalse(OLD['condition'](expr,marker,branch='refs/heads/main'))
            self.assertFalse(OLD['condition'](expr,marker,event='workflow_dispatch'))
            for message in ('unrelated','[n0a-udp-gates]','[n0a-udp-runtime]','[n0a-capture-runtime]','[identity-direct-stage0-runtime]'):
                self.assertFalse(OLD['condition'](expr,message))
        for file in ('windows-identity-direct-stage0.yml','windows-n0a-udp-gates.yml','windows-n0a-connect-gates.yml'):
            legacy=yaml.load((PATH.parent/file).read_text(),Loader=yaml.BaseLoader)
            for job in legacy['jobs'].values():
                self.assertFalse(OLD['condition'](job['if'][3:-2],marker))

    def test_pinned_separate_builds_and_fixed_harness(self):
        text=PATH.read_text()
        for name in ('windows_n0a_udp_parent.cpp','windows_n0a_udp_parent_fixture.cpp','windows_n0a_udp_actor.cpp','windows_n0a_udp_fixture.cpp','windows_identity_actor.cpp'):
            self.assertIn(hashlib.sha256((ROOT/'.github/native'/name).read_bytes()).hexdigest(),text)
        for value in ('udp-parent-production-build/windows_n0a_udp_parent.exe','udp-parent-TEST-ONLY-build/windows_n0a_UDP_PARENT_TEST_ONLY_fixture.exe','udp-child-TEST-ONLY-build/windows_n0a_UDP_TEST_ONLY_fixture.exe','--run-actual-windows','--output udp-parent-mechanism-public.json'):
            self.assertIn(value,text)
        self.assertNotIn('build_windows_n0a_udp_actor.ps1',text)
        self.assertNotIn('GITHUB_OUTPUT',text)

if __name__=='__main__':unittest.main()
