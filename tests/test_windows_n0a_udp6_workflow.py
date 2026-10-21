"""Separate UDP6 hosted-only workflow; no guest admission or runtime trigger."""
import ast
import hashlib
from pathlib import Path
import re
import runpy
import unittest

ROOT=Path(__file__).resolve().parents[1]
PATH=ROOT/'.github/workflows/windows-n0a-udp6-gates.yml'
OLD=runpy.run_path(str(ROOT/'tests/test_windows_n0a_udp_parent_workflow.py'))
NAMES=OLD['NAMES']+('test_windows_n0a_udp6_actor.py','test_windows_client_n0a_udp6.py','test_windows_n0a_udp6_gate.py','test_windows_client_n0a_udp6_packet.py','test_windows_n0a_udp6_workflow.py','test_windows_client_n0a_udp6_flow.py','test_windows_client_n0a_udp6_guest.py','test_windows_udp6_flow_composed.py','test_windows_n0a_udp6_integration_control.py','test_windows_client_n0a_udp6_capture_adapter.py','test_windows_client_n0a_udp6_host.py','test_windows_udp6_guest_transport.py','test_windows_n0a_qemu_slirp.py')
MARKER='[n0a-udp6-gates]'

class UDP6WorkflowTests(unittest.TestCase):
    def document(self):
        import yaml
        return yaml.load(PATH.read_text(encoding='utf-8'),Loader=yaml.BaseLoader)

    def test_actual_yaml_bounds_and_required_suites(self):
        doc=self.document();text=PATH.read_text()
        self.assertEqual(set(doc['on']),{'push'})
        self.assertEqual(doc['on']['push']['branches'],['dot/windows-isolation-proof'])
        self.assertEqual(doc['permissions'],{'contents':'read'})
        self.assertEqual(doc['concurrency']['cancel-in-progress'],'false')
        self.assertEqual(set(doc['jobs']),{'pure','native-mechanism'})
        for name,runner,minutes in (('pure','ubuntu-24.04','5'),('native-mechanism','windows-2025','8')):
            self.assertEqual(doc['jobs'][name]['runs-on'],runner)
            self.assertEqual(doc['jobs'][name]['timeout-minutes'],minutes)
        matches=re.findall(r'names=(\([^\n]+?\)); assert all',text)
        self.assertEqual(len(matches),2)
        for match in matches:self.assertEqual(ast.literal_eval(match),NAMES)
        self.assertIn('python -m pip install --disable-pip-version-check "PyYAML==6.0.3"\n          if ($LASTEXITCODE -ne 0)',text)
        for forbidden in ('actions/upload-artifact','workflow_dispatch:','pull_request:','continue-on-error','--n0a-udp-parent-runner'):
            self.assertNotIn(forbidden,text)

    def test_marker_event_branch_and_existing_workflow_negatives(self):
        condition=OLD['OLD']['condition']
        for job in self.document()['jobs'].values():
            expr=job['if'][3:-2]
            self.assertTrue(condition(expr,MARKER))
            self.assertFalse(condition(expr,MARKER,branch='refs/heads/main'))
            self.assertFalse(condition(expr,MARKER,event='workflow_dispatch'))
            for runtime in ('[identity-direct-stage0-runtime]','[n0a-connect-runtime]','[n0a-capture-runtime]','[n0a-udp-runtime]','[n0a-udp-parent-runtime]'):
                self.assertFalse(condition(expr,runtime))
                self.assertFalse(condition(expr,MARKER+' '+runtime))
        import yaml
        for name in ('windows-identity-direct-stage0.yml','windows-n0a-udp-gates.yml','windows-n0a-udp-parent-gates.yml','windows-n0a-connect-gates.yml'):
            doc=yaml.load((PATH.parent/name).read_text(),Loader=yaml.BaseLoader)
            for job in doc['jobs'].values():self.assertFalse(condition(job['if'][3:-2],MARKER))

    def test_distinct_pinned_artifacts_and_harness(self):
        text=PATH.read_text()
        for name in ('windows_n0a_udp6_actor.cpp','windows_n0a_udp6_fixture.cpp','windows_identity_actor.cpp'):
            self.assertIn(hashlib.sha256((ROOT/'.github/native'/name).read_bytes()).hexdigest(),text)
        for value in ('udp6-production-build/windows_n0a_udp6_actor.exe','udp6-TEST-ONLY-build/windows_n0a_UDP6_TEST_ONLY_fixture.exe','N0A-UDP6-manifest.json','UDP6-TEST-ONLY-manifest.json','--run-actual-windows'):
            self.assertIn(value,text)
        self.assertNotIn('GITHUB_OUTPUT',text)
        for path in ('.github/windows_n0a_udp6.py','.github/windows_n0a_udp6_packet.py','.github/test_windows_n0a_udp6.py','tests/test_windows_n0a_udp6_workflow.py'):
            self.assertIn(path,self.document()['on']['push']['paths'])

    def test_paused_provenance_and_integration_prerequisites_only(self):
        doc=self.document();jobs=doc['jobs'];text=PATH.read_text()
        linux={s.get('name'):s for s in jobs['pure']['steps']}
        install=linux['Install existing official Ubuntu QEMU for paused provenance only']['run']
        self.assertEqual(install,'sudo apt-get update\nsudo apt-get install -y --no-install-recommends qemu-system-x86\n')
        self.assertEqual(text.count('sudo '),2)
        self.assertEqual(linux['Tiny paused owned QEMU mapped-file provenance and cleanup']['run'],
                         'python3 -B .github/test_windows_n0a_qemu_slirp.py --run-actual-qemu')
        windows={s.get('name'):s for s in jobs['native-mechanism']['steps']}
        verify=windows['Isolated production inputs verification without PE execution']['run']
        self.assertIn('--verify-production-inputs --actor udp6-production-build/windows_n0a_udp6_actor.exe --manifest udp6-production-build/N0A-UDP6-manifest.json',verify)
        self.assertIn("if ($LASTEXITCODE -ne 0)",verify)
        ps=windows['Actual UDP6 and legacy PowerShell transport semantics']['run']
        for name in ('n0a','udp','udp-parent','udp6'):
            self.assertIn(f'& ./.github/test-windows-{name}-guest-gates.ps1',ps)
        self.assertEqual(ps.count('if ($LASTEXITCODE -ne 0)'),4)
        self.assertIn('test-windows-udp-payload-gates.ps1',windows['Actual six-mode payload ZIP and PowerShell extraction parity']['run'])
        for path in ('.github/windows_n0a_udp6_guest.py','.github/windows_n0a_udp6_flow.py','.github/windows_n0a_udp6_capture_adapter.py','.github/windows_n0a_qemu_slirp.py','.github/test_windows_n0a_qemu_slirp.py','.github/windows-identity-direct-stage0-run.ps1','.github/test-windows-udp6-guest-gates.ps1','.github/test-windows-n0a-guest-gates.ps1','.github/test_windows_udp_payload.py'):
            self.assertIn(path,doc['on']['push']['paths'])
        self.assertNotIn('--n0a-udp6-runner',text)

if __name__=='__main__':unittest.main()
