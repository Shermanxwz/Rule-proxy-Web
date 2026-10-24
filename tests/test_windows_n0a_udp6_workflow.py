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
STAGE0B_NAMES=('test_windows_identity_pipe_probe.py', 'test_windows_identity_ordinary_launcher.py', 'test_windows_identity_stage0b_guest.py', 'test_windows_stage0b_host.py', 'test_windows_stage0b_guest_transport.py')
STAGE0B_PATHS=('.github/windows_identity_pipe_probe.py', '.github/windows_identity_ordinary_launcher.py', 'ruleproxy/windows_app_process.py', '.github/windows_identity_stage0b_guest.py', '.github/test-windows-stage0b-guest-gates.ps1', 'tests/test_windows_identity_pipe_probe.py', 'tests/test_windows_identity_ordinary_launcher.py', 'tests/test_windows_identity_stage0b_guest.py', 'tests/test_windows_stage0b_host.py', 'tests/test_windows_stage0b_guest_transport.py')
AC_NAMES=('test_windows_identity_proxy_pipe_probe.py','test_windows_identity_proxy_pipe_ac_guest.py','test_windows_proxy_pipe_ac_transport.py')
AC_PATHS=('.github/windows_identity_proxy_pipe_probe.py','.github/windows_identity_proxy_pipe_ac_guest.py','.github/native/windows_identity_proxy_pipe_actor.cpp','.github/native/windows_identity_proxy_bridge_core.hpp','.github/native/windows_identity_actor.cpp','.github/test-windows-proxy-pipe-ac-guest-gates.ps1','docs/validation/2026-10-22-proxy-pipe-ac-prerequisite.md')+tuple('tests/'+n for n in AC_NAMES)+('.github/windows_identity_proof.py','.github/windows_psec_compartment_smoke.py','ruleproxy/windows_runtime_pins.py')
AC_PIN_PATHS=('.github/windows_identity_proxy_pipe_probe.py','.github/windows_identity_proxy_pipe_ac_guest.py','.github/windows_identity_direct_stage0.py','.github/windows-identity-direct-stage0-run.ps1','.github/windows_identity_ordinary_launcher.py','.github/windows_identity_pipe_probe.py','ruleproxy/windows_app_process.py','.github/windows_identity_proof.py','.github/windows_psec_compartment_smoke.py','ruleproxy/windows_runtime_pins.py','.github/native/windows_identity_proxy_pipe_actor.cpp','.github/native/windows_identity_proxy_bridge_core.hpp','.github/native/windows_identity_actor.cpp')

def without_ac(text):
    text=text.replace(" && !contains(github.event.head_commit.message, '[identity-proxy-pipe-ac-runtime]')",'')
    block=''.join("      - '"+n+"'\n" for n in AC_PATHS)
    assert text.count(block)==1
    text=text.replace(block,'',1)
    suffix="'test_windows_stage0b_guest_transport.py', "+', '.join(repr(n) for n in AC_NAMES)+'); assert all'
    assert text.count(suffix)==2
    text=text.replace(suffix,"'test_windows_stage0b_guest_transport.py'); assert all")
    step='          powershell -NoProfile -File ./.github/test-windows-proxy-pipe-ac-guest-gates.ps1\n          if ($LASTEXITCODE -ne 0) { exit $LASTEXITCODE }\n'
    assert text.count(step)==1
    text=text.replace(step,'',1)
    text,count=re.subn(r'      - name: Verify activated AC prerequisite sources without execution\n(?:(?!      - name:).*(?:\n|$))*','',text)
    assert count==2
    return text.replace('Actual eight-mode payload ZIP','Actual seven-mode payload ZIP')

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
        for match in matches:self.assertEqual(ast.literal_eval(match),NAMES+STAGE0B_NAMES+AC_NAMES)
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
            for runtime in ('[identity-direct-stage0-runtime]','[n0a-connect-runtime]','[n0a-capture-runtime]','[n0a-udp-runtime]','[n0a-udp-parent-runtime]','[n0a-udp6-runtime]','[identity-stage0b-runtime]','[identity-proxy-pipe-ac-runtime]'):
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
        for name in ('n0a','udp','udp-parent','udp6','stage0b'):
            self.assertIn(f'& ./.github/test-windows-{name}-guest-gates.ps1',ps)
        self.assertEqual(ps.count('if ($LASTEXITCODE -ne 0)'),6)
        self.assertIn('test-windows-udp-payload-gates.ps1',windows['Actual eight-mode payload ZIP and PowerShell extraction parity']['run'])
        for path in ('.github/windows_n0a_udp6_guest.py','.github/windows_n0a_udp6_flow.py','.github/windows_n0a_udp6_capture_adapter.py','.github/windows_n0a_qemu_slirp.py','.github/test_windows_n0a_qemu_slirp.py','.github/windows-identity-direct-stage0-run.ps1','.github/test-windows-udp6-guest-gates.ps1','.github/test-windows-n0a-guest-gates.ps1','.github/test_windows_udp_payload.py'):
            self.assertIn(path,doc['on']['push']['paths'])
        self.assertNotIn('--n0a-udp6-runner',text)

    def test_stage0b_additions_invert_to_exact_prior_short_workflow(self):
        text=without_ac(PATH.read_text())
        for path in STAGE0B_PATHS:self.assertIn(path,self.document()['on']['push']['paths'])
        suffix=" && !contains(github.event.head_commit.message, '[identity-stage0b-runtime]')"
        self.assertEqual(text.count(suffix),2);text=text.replace(suffix,'')
        block=''.join("      - '"+n+"'\n" for n in STAGE0B_PATHS)
        self.assertEqual(text.count(block),1);text=text.replace(block,'',1)
        suffix="'test_windows_n0a_qemu_slirp.py', "+', '.join(repr(n) for n in STAGE0B_NAMES)+'); assert all'
        self.assertEqual(text.count(suffix),2)
        text=text.replace(suffix,"'test_windows_n0a_qemu_slirp.py'); assert all")
        step="          & ./.github/test-windows-stage0b-guest-gates.ps1\n          if ($LASTEXITCODE -ne 0) { exit $LASTEXITCODE }\n"
        self.assertEqual(text.count(step),1);text=text.replace(step,'',1)
        text=text.replace('Actual seven-mode payload ZIP','Actual six-mode payload ZIP')
        self.assertEqual(hashlib.sha256(text.encode()).hexdigest(),'7878d096dca036028ff82003fd43caeb5a41d13cd78c7da2120be56d7c4c6f7d')
        # Required modules are explicit and remain fail-closed for missing/empty/skipped suites.
        self.assertEqual(len(set(NAMES+STAGE0B_NAMES)),51)
        self.assertEqual(PATH.read_text().count('not result.wasSuccessful() or bool(result.skipped)'),2)

    def test_ac_additions_invert_to_exact_51_suite_baseline(self):
        text=PATH.read_text()
        self.assertEqual(hashlib.sha256(without_ac(text).encode()).hexdigest(),'a3b9c5cad9c67361050b208f9ccbf071e8bb1ad8f17399bf7c2b617472e39be7')
        self.assertEqual(len(set(NAMES+STAGE0B_NAMES+AC_NAMES)),54)
        for path in AC_PATHS:self.assertIn(path,self.document()['on']['push']['paths'])
        steps=self.document()['jobs']['native-mechanism']['steps']
        ps=next(s['run'] for s in steps if s.get('name')=='Actual UDP6 and legacy PowerShell transport semantics')
        self.assertLess(ps.index('test-windows-stage0b-guest-gates.ps1'),ps.index('test-windows-proxy-pipe-ac-guest-gates.ps1'))
        self.assertIn('powershell -NoProfile -File ./.github/test-windows-proxy-pipe-ac-guest-gates.ps1',ps)
        for forbidden in ('--run-ac-pair','--run-native-pipe','--proxy-pipe-ac-runner','build_windows_identity_proxy_pipe_actor.ps1','windows_identity_proxy_pipe_actor.exe'):
            self.assertNotIn(forbidden,text)

    def test_ac_readonly_pins_and_authoritative_true_before_required_tests(self):
        doc=self.document()
        for job in doc['jobs'].values():
            steps=job['steps']; index=next(i for i,s in enumerate(steps) if s.get('name')=='Verify activated AC prerequisite sources without execution')
            required=next(i for i,s in enumerate(steps) if s.get('name')=='Required UDP6 and unchanged regression contracts')
            self.assertLess(index,required)
            code=steps[index]['run'];match=re.search(r'pins=(\{[^\n]+?\}); assert all',code)
            self.assertIsNotNone(match);pins=ast.literal_eval(match.group(1))
            self.assertEqual(tuple(pins),AC_PIN_PATHS)
            self.assertEqual(len(pins),13)
            for path,digest in pins.items():self.assertEqual(digest,hashlib.sha256((ROOT/path).read_bytes()).hexdigest())
            self.assertIn("t.id=='AC_EXECUTION_ENABLED'",code)
            self.assertIn('assert len(flags)==1 and flags[0] is True',code)
            # Execute only the literal hash/flag verification, never import a controller.
            command=next(line for line in code.splitlines() if ' -B -c ' in line)
            literal=command.split(' -B -c ',1)[1]
            program=ast.literal_eval(literal)
            import subprocess,sys
            result=subprocess.run([sys.executable,'-B','-c',program],cwd=ROOT,capture_output=True,timeout=10)
            self.assertEqual(result.returncode,0)

    def test_activation_delta_inverts_to_exact_prior_short_gate(self):
        text=PATH.read_text()
        marker=" && !contains(github.event.head_commit.message, '[identity-proxy-pipe-ac-runtime]')"
        self.assertEqual(text.count(marker),2)
        text=text.replace(marker,'')
        text=text.replace('Verify activated AC prerequisite sources without execution','Verify default-OFF AC prerequisite sources without execution')
        text=text.replace('assert len(flags)==1 and flags[0] is True','assert len(flags)==1 and flags[0] is False')
        self.assertEqual(text.count('7412d86d31f0d152e600aa423910cbd632bb88ded413ace284d5255447c0fe9d'),2)
        text=text.replace('7412d86d31f0d152e600aa423910cbd632bb88ded413ace284d5255447c0fe9d','4af0bceac888fd0a38d2ecc43f2455d72eb0a6fe11de70214b81132e0119be34')
        self.assertEqual(hashlib.sha256(text.encode()).hexdigest(),'8ea317f3ddafbf0278139e82380fb30ee3ac9ebce0fd07244538e878ee38a565')

if __name__=='__main__':unittest.main()
