"""Exact opt-in publication boundary for TEST_ONLY DNS REQUEST3 mechanism gates."""
import ast
import hashlib
from pathlib import Path
import re
import unittest

ROOT=Path(__file__).resolve().parents[1]
PATH=ROOT/'.github/workflows/windows-dns-request3-gates.yml'
BRANCH='refs/heads/dot/windows-isolation-proof'
MARKER='[dns-request3-gates]'


def condition(expression,message,branch=BRANCH,event='push'):
    value=re.sub(r"contains\(github.event.head_commit.message, '([^']+)'\)",lambda m:str(m.group(1) in message),expression)
    value=value.replace('github.ref',repr(branch)).replace('github.event_name',repr(event))
    value=re.sub(r'\btrue\b','True',value);value=re.sub(r'\bfalse\b','False',value)
    value=value.replace('&&',' and ').replace('||',' or ').replace('!',' not ')
    tree=ast.parse(value.strip(),mode='eval')
    allowed=(ast.Expression,ast.BoolOp,ast.UnaryOp,ast.Compare,ast.Constant,ast.And,ast.Or,ast.Not,ast.Eq,ast.Load)
    if any(not isinstance(node,allowed) for node in ast.walk(tree)):raise ValueError('Unsupported job condition')
    return eval(compile(tree,'<actual-job-condition>','eval'),{'__builtins__':{}},{})


class DnsWorkflowTests(unittest.TestCase):
    def setUp(self):self.text=PATH.read_text()

    def test_exact_two_jobs_and_marker_truth_table(self):
        self.assertEqual(re.findall(r'^  ([a-z][a-z-]+):$',self.text.split('jobs:',1)[1],re.M),['pure','native-mechanism'])
        expressions=re.findall(r'^    if: \$\{\{ (.+) \}\}$',self.text,re.M)
        self.assertEqual(len(expressions),2)
        other=('unrelated','[n0a-connect-gates]','[n0a-connect-runtime]','[n0a-capture-runtime]',
               '[identity-direct-stage0-gates]','[identity-direct-stage0-runtime]',
               '[identity-serviced-stage0-gates]','[identity-serviced-stage0-runtime]')
        for expression in expressions:
            self.assertTrue(condition(expression,MARKER))
            for message in other:self.assertFalse(condition(expression,message),message)
            for branch in ('refs/heads/main','refs/heads/other',BRANCH+'-other'):
                self.assertFalse(condition(expression,MARKER,branch=branch))
            for event in ('workflow_dispatch','pull_request','schedule'):
                self.assertFalse(condition(expression,MARKER,event=event))

    def test_dns_only_never_admits_existing_runtime_jobs(self):
        # Evaluate actual job-level predicates, not a recreated marker list.
        for name in ('windows-identity-direct-stage0.yml','windows-identity-serviced-stage0.yml','windows-n0a-connect-gates.yml','windows-n0a-capture-gates.yml'):
            text=(ROOT/'.github/workflows'/name).read_text()
            expressions=re.findall(r'^    if: \$\{\{ (.+) \}\}$',text,re.M)
            self.assertGreater(len(expressions),0)
            for expression in expressions:self.assertFalse(condition(expression,MARKER),name)

    def test_standard_bounded_no_vm_artifacts_or_external_trigger(self):
        pure,native=self.text.split('  native-mechanism:',1)
        self.assertIn('runs-on: ubuntu-24.04',pure);self.assertIn('timeout-minutes: 5',pure)
        self.assertIn('runs-on: windows-2025',native);self.assertIn('timeout-minutes: 8',native)
        self.assertEqual(self.text.count('persist-credentials: false'),2)
        self.assertIn('contents: read',self.text);self.assertIn('cancel-in-progress: false',self.text)
        for forbidden in ('workflow_dispatch:','pull_request:','schedule:', 'actions/upload-artifact',
                          'actions/download-artifact','continue-on-error','sudo ', 'qemu-system',
                          '--approved-disposable-vm','--n0a-capture-runner','--n0a-actor'):
            self.assertNotIn(forbidden,self.text)

    def test_fixed_non_deployable_build_and_explicit_mechanism(self):
        self.assertIn('build_windows_n0a_dns_fixture.ps1',self.text)
        self.assertIn('dns-TEST-ONLY-build/windows_n0a_DNS_TEST_ONLY_fixture.exe',self.text)
        self.assertIn('dns-TEST-ONLY-build/DNS-TEST-ONLY-manifest.json',self.text)
        self.assertIn('--run-actual-windows',self.text)
        self.assertIn('--actor',self.text)
        self.assertIn('--output',self.text)
        self.assertIn('ParseFile',self.text)
        self.assertIn('if ($LASTEXITCODE -ne 0) { exit $LASTEXITCODE }',self.text)
        self.assertNotIn('build_windows_identity_actor.ps1',self.text)
        self.assertNotIn('build_windows_n0a_actor.ps1',self.text)

    def test_test_only_compile_guard_and_official_sdk_resolution(self):
        native=(ROOT/'.github/native/windows_n0a_dns_fixture.cpp').read_text()
        build=(ROOT/'.github/build_windows_n0a_dns_fixture.ps1').read_text()
        self.assertIn('#if !defined(N0A_DNS_TEST_ONLY) || N0A_DNS_TEST_ONLY != 1',native)
        self.assertIn('#error This source is only a non-deployable DNS mechanism fixture.',native)
        self.assertIn('/DN0A_DNS_TEST_ONLY=1',build)
        self.assertIn('testOnly=$true; deployable=$false; compileOnly=$true',build)
        self.assertLess(native.index('#include <ws2ipdef.h>'),native.index('#include <windns.h>'))
        for value in ('WindowsSdkDir','WindowsSDKVersion','SDK include shadow rejected.',
                      "@('windns.h','windnsdef.h','ws2ipdef.h')",'OrdinalIgnoreCase',
                      'SDK header changed during compilation.'):
            self.assertIn(value,build)
        self.assertNotIn('typedef struct _DNS_QUERY_REQUEST3',native)
        self.assertNotIn('GITHUB_OUTPUT',build)

    def test_exact_native_source_pin_not_placeholder(self):
        source=ROOT/'.github/native/windows_n0a_dns_fixture.cpp'
        self.assertTrue(source.is_file(),'Reviewed DNS fixture source required')
        digest=hashlib.sha256(source.read_bytes()).hexdigest()
        self.assertIn('-ExpectedSourceSha256 '+digest,self.text)
        self.assertNotIn('SOURCE_HASH_PENDING',self.text)

    def test_explicit_suite_zero_and_skip_refusal(self):
        expected=('test_windows_client_dns_fixture.py','test_windows_dns_request3.py','test_windows_dns_workflow.py')
        tuples=re.findall(r'names=(\([^;]+\));',self.text)
        self.assertEqual(len(tuples),2)
        for names in tuples:self.assertEqual(ast.literal_eval(names),expected)
        for filename in expected:self.assertTrue((ROOT/'tests'/filename).is_file(),filename)
        self.assertEqual(self.text.count('all(p.countTestCases()>0 for p in parts)'),2)
        self.assertEqual(self.text.count('bool(result.skipped)'),2)
        self.assertNotIn("pattern='*",self.text)

    def test_test_only_excluded_from_existing_production_paths(self):
        for filename in ('.github/windows_identity_direct_stage0.py','.github/windows_identity_serviced_stage0.py',
                         '.github/windows-identity-direct-stage0-run.ps1','.github/windows-identity-serviced-stage0-run.ps1',
                         '.github/workflows/windows-identity-direct-stage0.yml',
                         '.github/workflows/windows-identity-serviced-stage0.yml'):
            text=(ROOT/filename).read_text()
            for forbidden in ('windows_n0a_DNS_TEST_ONLY_fixture.exe','DNS-TEST-ONLY-manifest.json',
                              'dns-TEST-ONLY-build','windows_n0a_dns_fixture.cpp'):
                self.assertNotIn(forbidden,text,filename)

    def test_scope_document_preserves_claim_limits(self):
        text=(ROOT/'docs/validation/2026-10-21-dns-request3-mechanism.md').read_text()
        for required in ('TEST_ONLY','NRPT','127.0.0.1','10.0.2.2','not isolation','DnsCancelQuery',
                         'No VM','forwarding','ordinary non-administrator'):
            self.assertIn(required,text)


if __name__=='__main__':unittest.main()
