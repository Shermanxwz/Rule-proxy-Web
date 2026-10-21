"""Short direct UDP adapter gates; no guest runtime or artifact publication."""
import ast
import hashlib
from pathlib import Path
import re
import unittest

ROOT=Path(__file__).resolve().parents[1]
PATH=ROOT/'.github/workflows/windows-n0a-udp-gates.yml'
BRANCH='refs/heads/dot/windows-isolation-proof'
MARKER='[n0a-udp-gates]'
NAMES=('test_windows_n0a_udp_actor.py', 'test_windows_client_n0a_udp.py', 'test_windows_n0a_udp_gate.py', 'test_windows_client_n0a_udp_packet.py', 'test_windows_n0a_udp_workflow.py', 'test_windows_client_n0a_udp_guest.py', 'test_windows_client_n0a_udp_flow.py', 'test_windows_client_n0a_udp_host.py', 'test_windows_client_n0a_udp_capture_adapter.py', 'test_windows_udp_guest_transport.py', 'test_windows_udp_payload.py', 'test_windows_n0a_actor.py', 'test_windows_client_n0a_control.py', 'test_windows_n0a_workflow.py', 'test_windows_client_n0a_adapter.py', 'test_windows_client_n0a_host.py', 'test_windows_client_n0a_flow.py', 'test_windows_client_n0a_capture_adapter.py', 'test_windows_client_n0a_packet.py', 'test_windows_n0a_guest.py', 'test_windows_client_direct_stage0.py', 'test_windows_client_direct_guest.py', 'test_windows_client_direct_actor_projection.py', 'test_windows_client_direct_workflow.py')


def condition(expression,message,branch=BRANCH,event='push'):
    value=re.sub(r"contains\(github.event.head_commit.message, '([^']+)'\)",lambda m:str(m.group(1) in message),expression)
    value=value.replace('github.ref',repr(branch)).replace('github.event_name',repr(event))
    value=re.sub(r'\btrue\b','True',value);value=re.sub(r'\bfalse\b','False',value)
    value=value.replace('&&',' and ').replace('||',' or ').replace('!',' not ')
    tree=ast.parse(value.strip(),mode='eval')
    allowed=(ast.Expression,ast.BoolOp,ast.UnaryOp,ast.Compare,ast.Constant,ast.And,ast.Or,ast.Not,ast.Eq,ast.Load)
    if any(not isinstance(node,allowed) for node in ast.walk(tree)):raise ValueError('condition')
    return eval(compile(tree,'<actual-job-condition>','eval'),{'__builtins__':{}},{})


class UdpWorkflowTests(unittest.TestCase):
    def setUp(self):self.text=PATH.read_text()

    def test_exact_marker_branch_event(self):
        self.assertEqual(re.findall(r'^  ([a-z][a-z-]+):$',self.text.split('jobs:',1)[1],re.M),['pure','native-mechanism'])
        expressions=re.findall(r'^    if: \$\{\{ (.+) \}\}$',self.text,re.M)
        self.assertEqual(len(expressions),2)
        for expression in expressions:
            self.assertTrue(condition(expression,MARKER))
            for msg in ('unrelated','[dns-request3-gates]','[n0a-connect-gates]','[n0a-capture-gates]','[n0a-connect-runtime]','[n0a-capture-runtime]','[identity-direct-stage0-runtime]','[identity-serviced-stage0-runtime]'):
                self.assertFalse(condition(expression,msg))
            for branch in ('refs/heads/main',BRANCH+'-other'):
                self.assertFalse(condition(expression,MARKER,branch=branch))
            for event in ('workflow_dispatch','pull_request','schedule'):
                self.assertFalse(condition(expression,MARKER,event=event))

    def test_udp_marker_cannot_start_existing_work(self):
        for name in ('windows-identity-direct-stage0.yml','windows-identity-serviced-stage0.yml','windows-n0a-connect-gates.yml','windows-n0a-capture-gates.yml','windows-dns-request3-gates.yml'):
            expressions=re.findall(r'^    if: \$\{\{ (.+) \}\}$',(ROOT/'.github/workflows'/name).read_text(),re.M)
            self.assertTrue(expressions)
            for expression in expressions:self.assertFalse(condition(expression,MARKER),name)

    def test_fixed_resources_and_no_upload_or_runtime(self):
        self.assertIn('runs-on: ubuntu-24.04',self.text);self.assertIn('runs-on: windows-2025',self.text)
        self.assertEqual(re.findall(r'^    timeout-minutes: (\d+)$',self.text,re.M),['5','8'])
        self.assertEqual(self.text.count('persist-credentials: false'),2)
        for x in ('contents: read','cancel-in-progress: false','timeout-minutes: 2'):self.assertIn(x,self.text)
        for x in ('workflow_dispatch:','schedule:','pull_request:','upload-artifact','download-artifact','continue-on-error','qemu-system','sudo ','--approved-disposable-vm','--n0a-capture-runner'):
            self.assertNotIn(x,self.text)

    def test_required_tests_before_actual_mechanics(self):
        for name in NAMES:self.assertEqual(self.text.count("'"+name+"'"),2)
        self.assertEqual(self.text.count('p.countTestCases()>0'),2)
        self.assertEqual(self.text.count('bool(result.skipped)'),2)
        self.assertLess(self.text.index('Required UDP contracts before actual mechanics'),self.text.index('Owned loopback mechanics'))
        self.assertNotIn('test_windows_dns_request3.py',self.text)

    def test_adapter_gates_and_separate_runtime_entrypoint(self):
        for name in ('test-windows-n0a-guest-gates.ps1','test-windows-udp-guest-gates.ps1','test-windows-udp-payload-gates.ps1'):
            self.assertIn('& ./.github/'+name,self.text)
        module=ast.parse((ROOT/'.github/windows_n0a_udp.py').read_text())
        flags=[n.value.value for n in module.body if isinstance(n,ast.Assign) and any(isinstance(t,ast.Name) and t.id=='EXECUTION_ENABLED' for t in n.targets) and isinstance(n.value,ast.Constant)]
        self.assertEqual(flags,[True])
        self.assertNotIn('--n0a-udp-runner',self.text)

    def test_exact_separate_build_pins(self):
        actor=hashlib.sha256((ROOT/'.github/native/windows_n0a_udp_actor.cpp').read_bytes()).hexdigest()
        fixture=hashlib.sha256((ROOT/'.github/native/windows_n0a_udp_fixture.cpp').read_bytes()).hexdigest()
        identity=hashlib.sha256((ROOT/'.github/native/windows_identity_actor.cpp').read_bytes()).hexdigest()
        self.assertEqual(self.text.count('-ExpectedActorSha256 '+actor),2)
        self.assertEqual(self.text.count('-ExpectedIdentitySha256 '+identity),2)
        self.assertEqual(self.text.count('-ExpectedFixtureSha256 '+fixture),1)
        for x in ('UDP_ACTOR_PIN','UDP_FIXTURE_PIN','IDENTITY_PIN'):self.assertNotIn(x,self.text)
        for x in ('udp-production-build/windows_n0a_udp_actor.exe','udp-production-build/N0A-UDP-manifest.json','udp-TEST-ONLY-build/windows_n0a_UDP_TEST_ONLY_fixture.exe','udp-TEST-ONLY-build/UDP-TEST-ONLY-manifest.json'):
            self.assertIn(x,self.text)
        line=next(x for x in self.text.splitlines() if 'python -B .github/test_windows_n0a_udp.py' in x)
        for x in ('--run-actual-windows','--production-actor','--production-manifest','--fixture-actor','--fixture-manifest','--output'):self.assertIn(x,line)
        self.assertIn('ParseFile',self.text)

    def test_document_keeps_independent_claims(self):
        text=(ROOT/'docs/validation/2026-10-21-direct-udp-mechanism.md').read_text()
        for x in ('explicit_send_denial','bounded_no_selected_udp_datagram','not delivery','not actor attribution','cannot authenticate','REQUEST3','TEST_ONLY','No artifacts'):
            self.assertIn(x,text)
        self.assertIn('precede all socket operations',text)


if __name__=='__main__':unittest.main()
