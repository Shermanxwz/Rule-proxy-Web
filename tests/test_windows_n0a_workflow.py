"""Publication boundaries for standalone N0a-connect gates, never a VM."""
import ast
import itertools
import json
import time
from unittest.mock import Mock, patch
import hashlib
from pathlib import Path
import re
import runpy
import os
import shutil
import subprocess
import tempfile
import textwrap
import unittest

ROOT = Path(__file__).resolve().parents[1]
WORKFLOW = ROOT / '.github/workflows/windows-n0a-connect-gates.yml'
SHELL_OBSERVATIONS=0


# Fixed fixture diagnostics only. No command, exception message, or raw output is
# returned. The held process is the only cleanup target; its exit is not proof
# that Git Bash descendants exited. A failed wait therefore preserves the root.
def observe_fixture_shell(command, root, env, *, factory=None, clock=None):
    factory = subprocess.Popen if factory is None else factory
    clock = time.monotonic if clock is None else clock
    facts = dict(outcome='spawn_failed', elapsed='unobserved', exit_confirmed=False,
                 kill_attempted=False, kill_failed=False, descendants_observed=False, exit_zero=None)
    process=None; code=None; start=clock()
    try:
        process=factory(command,cwd=root,env=env,stdout=subprocess.DEVNULL,stderr=subprocess.DEVNULL)
        try:
            code=process.wait(timeout=5)
            facts.update(outcome='exited' if code in (0,1) else 'unexpected_exit',exit_confirmed=True,exit_zero=(code==0))
        except subprocess.TimeoutExpired:
            facts['outcome']='work_timeout'
        except Exception:
            facts['outcome']='wait_failed'
    except Exception:
        facts['outcome']='spawn_failed'
    elapsed=max(0,clock()-start)
    facts['elapsed']='under_1s' if elapsed<1 else 'under_5s' if elapsed<5 else 'at_least_5s'
    if process is not None and not facts['exit_confirmed']:
        cleanup_end=clock()+1
        try:facts['exit_confirmed']=process.poll() is not None
        except Exception:pass
        if not facts['exit_confirmed']:
            facts['kill_attempted']=True
            try:process.kill()
            except Exception:facts['kill_failed']=True
        remaining=max(0,cleanup_end-clock())
        if not facts['exit_confirmed'] and remaining>0:
            try:
                process.wait(timeout=remaining)
                facts['exit_confirmed']=True
            except Exception:pass
        # Independent final observation even if kill or wait raised. Native OS
        # creation/kill calls have no claimed hard bound; wait budgets are5+1s.
        try:facts['exit_confirmed']=process.poll() is not None or facts['exit_confirmed']
        except Exception:pass
    return code,facts


def fixture_shell_stage(path):
    try:
        with path.open('rb') as stream:value=stream.read(33)
        return value.decode('ascii') if value in (b'startup_unobserved',b'startup',b'guards',b'body',b'stub') else 'unobserved'
    except Exception:return 'unobserved'


class N0aWorkflowTests(unittest.TestCase):
    def setUp(self):
        self.text = WORKFLOW.read_text(encoding='utf-8')

    def test_only_two_explicit_branch_marker_jobs(self):
        self.assertEqual(re.findall(r'^  ([a-z][a-z-]+):$', self.text.split('jobs:', 1)[1], re.M), ['host-unit', 'native-fixture'])
        self.assertEqual(self.text.count("contains(github.event.head_commit.message, '[n0a-connect-gates]')"), 2)
        self.assertEqual(self.text.count("github.ref == 'refs/heads/dot/windows-isolation-proof'"), 2)
        self.assertNotIn('workflow_dispatch:', self.text)
        self.assertNotIn('pull_request', self.text)
        self.assertNotIn('schedule:', self.text)

    def test_standard_small_jobs_and_no_upload_or_runtime(self):
        self.assertIn('runs-on: windows-2025', self.text)
        self.assertIn('runs-on: ubuntu-24.04', self.text)
        self.assertIn('timeout-minutes: 8', self.text)
        self.assertIn('timeout-minutes: 5', self.text)
        self.assertNotIn('actions/upload-artifact', self.text)
        self.assertNotIn('python3 -B .github/windows_identity_direct_stage0.py', self.text)
        self.assertNotIn('windows_identity_serviced_stage0.py', self.text)
        self.assertNotIn('continue-on-error', self.text)
        self.assertNotIn('sudo ', self.text)
        self.assertIn('cancel-in-progress: false', self.text)

    def test_fixture_is_distinct_and_explicitly_opted_in(self):
        self.assertIn('n0a-production-build/windows_n0a_actor.exe', self.text)
        self.assertIn('n0a-TEST-ONLY-build/windows_n0a_TEST_ONLY_fixture.exe', self.text)
        self.assertIn('TEST-ONLY-manifest.json', self.text)
        self.assertIn('--run-owned-loopback-fixtures', self.text)
        self.assertIn('$fixture.deployable', self.text)
        self.assertIn('$production.testOnly', self.text)

    def test_source_hash_pins_match_exact_files(self):
        for filename in ('windows_n0a_actor.cpp', 'windows_identity_actor.cpp', 'windows_n0a_fixture.cpp'):
            digest = hashlib.sha256((ROOT / '.github/native' / filename).read_bytes()).hexdigest()
            self.assertIn(digest, self.text)

    def test_required_tests_cannot_pass_zero_or_skips(self):
        for name in ('test_windows_n0a_actor.py', 'test_windows_client_n0a_control.py', 'test_windows_n0a_workflow.py', 'test_windows_client_n0a_adapter.py', 'test_windows_client_n0a_host.py', 'test_windows_client_n0a_flow.py', 'test_windows_client_n0a_capture_adapter.py', 'test_windows_client_n0a_packet.py', 'test_windows_n0a_guest.py', 'test_windows_client_direct_stage0.py', 'test_windows_client_direct_guest.py', 'test_windows_client_direct_actor_projection.py', 'test_windows_client_direct_workflow.py'):
            self.assertEqual(self.text.count("'" + name + "'"), 2)
            self.assertTrue((ROOT / 'tests' / name).is_file())
        self.assertEqual(self.text.count('suite.countTestCases()>=43'), 2)
        self.assertEqual(self.text.count('bool(result.skipped)'), 2)
        self.assertEqual(self.text.count('all(p.countTestCases()>0 for p in parts)'), 2)
        self.assertEqual(self.text.count('persist-credentials: false'), 2)
        self.assertIn('if ($LASTEXITCODE -ne 0) { exit $LASTEXITCODE }', self.text)


class N0aDirectWorkflowTests(unittest.TestCase):
    def setUp(self):
        self.text = (ROOT / '.github/workflows/windows-identity-direct-stage0.yml').read_text()

    def native_allowed(self, message, branch='refs/heads/dot/windows-isolation-proof', event='push'):
        expression = self.text.split('  native:',1)[1].split('if: ${{',1)[1].split('}}',1)[0].strip()
        expression = re.sub(r"contains\(github.event.head_commit.message, '([^']+)'\)",
                            lambda m: str(m.group(1) in message), expression)
        expression = expression.replace('github.ref', repr(branch)).replace('github.event_name', repr(event))
        expression = re.sub(r'\btrue\b','True',expression)
        expression = re.sub(r'\bfalse\b','False',expression)
        expression = expression.replace('&&',' and ').replace('||',' or ').replace('!',' not ')
        tree=ast.parse(expression.strip(), mode='eval')
        self.assertTrue(all(isinstance(node,(ast.Expression,ast.BoolOp,ast.UnaryOp,ast.Compare,ast.Constant,
            ast.And,ast.Or,ast.Not,ast.Eq,ast.Load)) for node in ast.walk(tree)))
        return eval(compile(tree,'<actual-workflow-if>','eval'), {'__builtins__':{}}, {})

    def test_actual_native_condition_truth_table(self):
        self.assertTrue(self.native_allowed('[identity-direct-stage0-runtime]'))
        self.assertTrue(self.native_allowed('[n0a-connect-runtime]'))
        self.assertTrue(self.native_allowed('[n0a-capture-runtime]'))
        for message in ('unrelated','[identity-direct-stage0-gates]','[n0a-connect-gates]',
                        '[identity-direct-stage0-runtime] [n0a-connect-runtime]'):
            self.assertFalse(self.native_allowed(message),message)
        self.assertFalse(self.native_allowed('[identity-direct-stage0-runtime]', branch='refs/heads/main'))
        self.assertFalse(self.native_allowed('[identity-direct-stage0-runtime]', event='workflow_dispatch'))
        self.assertFalse(self.native_allowed('[n0a-connect-runtime]', branch='refs/heads/main'))
        self.assertFalse(self.native_allowed('[n0a-connect-runtime]', event='workflow_dispatch'))
        markers=('[identity-direct-stage0-runtime]','[n0a-connect-runtime]','[n0a-capture-runtime]','[n0a-udp-runtime]','[n0a-udp-parent-runtime]','[n0a-udp6-runtime]')
        for first in markers:
            self.assertFalse(self.native_allowed(first,branch='refs/heads/main'))
            self.assertFalse(self.native_allowed(first,event='workflow_dispatch'))
            for second in markers:
                if first!=second:self.assertFalse(self.native_allowed(first+' '+second))
        self.assertFalse(self.native_allowed(' '.join(markers)))
        for present in itertools.product((False,True),repeat=6):
            message=' '.join(m for m,selected in zip(markers,present) if selected)
            self.assertEqual(self.native_allowed(message),sum(present)==1,message)
        for message in ('[n0a-udp-gates]','[dns-request3-gates]','[n0a-capture-gates]'):
            self.assertFalse(self.native_allowed(message))

    def test_optional_artifact_matches_actual_host_output(self):
        source = (ROOT / '.github/windows_identity_direct_stage0.py').read_text()
        names = {node.value for node in ast.walk(ast.parse(source))
                 if isinstance(node, ast.Constant) and isinstance(node.value, str)
                 and node.value.startswith('n0a-') and node.value.endswith('.json')}
        self.assertEqual(names, {'n0a-connect-public.json', 'n0a-capture-public.json', 'n0a-udp-public.json', 'n0a-udp-parent-public.json', 'n0a-udp6-public.json'})
        self.assertEqual(self.text.count('path: client-stage0-public/n0a-udp6-public.json'),1)
        self.assertEqual(self.text.count('path: client-stage0-public/n0a-udp-parent-public.json'),1)
        self.assertIn('--n0a-udp-parent-runner',self.text)
        self.assertEqual(self.text.count('path: client-stage0-public/n0a-udp-public.json'),1)
        self.assertIn('--n0a-udp-runner',self.text)
        self.assertIn('path: client-stage0-public/public-report.json',self.text)
        self.assertIn('path: client-stage0-public/n0a-connect-public.json', self.text)
        capture=self.text.split('name: n0a-capture-exploratory-public',1)[0].rsplit('- uses: actions/upload-artifact@v7',1)[1]
        self.assertIn("always() && contains(github.event.head_commit.message, '[n0a-capture-runtime]')",capture)
        self.assertNotIn('[n0a-connect-runtime]',capture)
        self.assertEqual(self.text.count('path: client-stage0-public/n0a-capture-public.json'),1)
        self.assertNotIn('path: client-stage0-public/*',self.text)
        self.assertIn('--n0a-capture-runner',self.text)

    def test_production_upload_explicit_marker_and_fixture_excluded(self):
        step=self.text.split('name: n0a-connect-production-actor',1)[0].rsplit('- uses: actions/upload-artifact@v7',1)[1]
        self.assertIn("contains(github.event.head_commit.message, '[n0a-connect-runtime]') || contains(github.event.head_commit.message, '[n0a-capture-runtime]')",step)
        download=next(block.split('      - ',1)[0] for block in self.text.split('- uses: actions/download-artifact@v8')[1:] if 'name: n0a-connect-production-actor' in block.split('      - ',1)[0])
        self.assertIn("contains(github.event.head_commit.message, '[n0a-connect-runtime]') || contains(github.event.head_commit.message, '[n0a-capture-runtime]')",download)
        self.assertIn('name: n0a-connect-production-actor',download)
        self.assertIn('n0a-production-build/windows_n0a_actor.exe',self.text)
        self.assertIn('n0a-production-build/build-manifest.json',self.text)
        self.assertNotIn('TEST_ONLY',self.text)
        self.assertNotIn('TEST-ONLY',self.text)
        self.assertNotIn('build_windows_n0a_fixture',self.text)
        self.assertIn('timeout-minutes: 120',self.text)
        self.assertIn('--timeout-seconds 6600',self.text)
        self.assertIn('Read-only provider capacity admission, never cache deletion',self.text)


    def test_windows_suite_is_exact_short_gate_list(self):
        short=WORKFLOW.read_text()
        names=ast.literal_eval(re.search(r"names=(\([^;]+\));",short).group(1))
        compiled=self.text.split('  compile:',1)[1].split('  host-unit:',1)[0]
        actual=ast.literal_eval(re.search(r"names=(\([^;]+\));",compiled).group(1))
        self.assertEqual(actual,names)
        self.assertNotIn('test_windows_client_n0a*.py',compiled)
        self.assertNotIn('test_windows_client_n0a_capture.py',actual)
        self.assertIn('bool(result.skipped)',compiled)

    def capture_shell(self,capture,n0a,commit,github_sha,udp='false',parent='false',udp6='false',stage0b='false',actor_size=512):
        # Execute the exact production argument block/command with inert timeout.
        # No sudo, Python harness, VM, or endpoint ever executes in this fixture.
        script=self.text.split('          n0a_args=()',1)[1].split('      - uses: actions/upload-artifact@v7',1)[0]
        script='n0a_args=()'+textwrap.dedent(script)
        script=re.sub(r'\$\{\{ steps\.stock_budget_8\.outputs\.deadline \}\}', '2000',script)
        self.assertNotIn('${{',script)
        bash=shutil.which('bash')
        if os.name=='nt':
            candidate=Path(os.environ.get('ProgramFiles','C:/Program Files'))/'Git/bin/bash.exe'
            if candidate.is_file():bash=str(candidate)
        self.assertIsNotNone(bash,'Actual Bash fixture required; no skipped coverage')
        try:root=Path(tempfile.mkdtemp(prefix='n0a-shell-fixture-'))
        except Exception:raise AssertionError('Closed shell fixture root_create_failed') from None
        output=root/'argv.bin';cwd_output=root/'cwd.bin';stage=root/'stage.txt'
        facts=None;cleanup=False;read_failed=False
        try:
            stage.write_bytes(b'startup_unobserved')
            if stage0b=='true':
                actor_root=root/'client-stage0-actor';actor_root.mkdir()
                with (actor_root/'windows_identity_actor.exe').open('xb') as actor_file:actor_file.truncate(actor_size)
            for name,body in [('date', '#!/bin/sh\nprintf 1000\n'), ('timeout', '#!/bin/sh\nprintf stub > "$CAPTURE_STAGE"\nprintf \'%s\\0\' "$@" > "$CAPTURE_ARGV"\n')]:
                path=root/name;path.write_bytes(body.encode('ascii'));path.chmod(0o700)
            logical_root=('/'+root.drive[0].lower()+root.as_posix()[2:]) if os.name=='nt' else root.as_posix()
            env=dict(os.environ,CAPTURE_REQUESTED=capture,N0A_REQUESTED=n0a,UDP_REQUESTED=udp,PARENT_UDP_REQUESTED=parent,UDP6_REQUESTED=udp6,STAGE0B_REQUESTED=stage0b,
                     CAPTURE_SOURCE_COMMIT=commit,GITHUB_SHA=github_sha,
                     CAPTURE_ARGV=output.as_posix(),CAPTURE_CWD=cwd_output.as_posix(),CAPTURE_STAGE=stage.as_posix(),FIXTURE_BIN=logical_root)
            source='printf startup > "$CAPTURE_STAGE"\nexport PATH="$FIXTURE_BIN:$PATH"\ntest "$(command -v timeout)" = "$FIXTURE_BIN/timeout"\ntest "$(command -v date)" = "$FIXTURE_BIN/date"\ntest "$PWD" -ef "$FIXTURE_BIN"\nprintf guards > "$CAPTURE_STAGE"\nprintf \'%s\' "$PWD" > "$CAPTURE_CWD"\nactor='+('b'*64)+'\nprintf body > "$CAPTURE_STAGE"\n'+script
            code,facts=observe_fixture_shell([bash,'-euo','pipefail','-c',source],root,env)
            if facts['outcome']!='exited':
                facts.update(stage=fixture_shell_stage(stage),root_removal_skipped=True)
                raise AssertionError('Closed shell fixture '+json.dumps(facts,sort_keys=True)) from None
            # Do not expose actual private argv/paths on fixture failure.
            args=output.read_bytes().split(b'\0')[:-1] if output.exists() else None
            with cwd_output.open('rb') as stream:canonical=stream.read(4097)
            self.assertTrue(0<len(canonical)<=4096,'Owned shell cwd bound')
            canonical=canonical.decode('utf-8','strict')
            self.assertTrue(canonical.startswith('/') and '\x00' not in canonical,'Owned shell cwd shape')
            return code,[a.decode() for a in args] if args is not None else None,canonical
        except Exception:
            if facts is None:facts=dict(outcome='fixture_prepare_failed',elapsed='unobserved',exit_confirmed=False,kill_attempted=False,kill_failed=False,descendants_observed=False)
            read_failed=facts['outcome']=='exited'
            raise AssertionError('Closed shell fixture '+json.dumps(dict(facts,stage=fixture_shell_stage(stage),read_failed=read_failed),sort_keys=True)) from None
        finally:
            # Timeout/creation/cleanup uncertainty retains the owned root; no
            # descendant-tree or stub-exit claim follows from parent exit.
            last_stage=fixture_shell_stage(stage)
            if facts is not None and facts['outcome']=='exited' and facts['exit_confirmed']:
                try:shutil.rmtree(root);cleanup=True
                except Exception:pass
            global SHELL_OBSERVATIONS
            if SHELL_OBSERVATIONS<64:
                SHELL_OBSERVATIONS+=1
                print(json.dumps(dict(facts or {},fixture='owned_bash',stage=fixture_shell_stage(stage) if not cleanup else last_stage,root_removal_skipped=not(facts is not None and facts['outcome']=='exited' and facts['exit_confirmed']),root_cleanup_confirmed=cleanup,read_failed=read_failed),sort_keys=True))
            if facts is not None and facts['outcome']=='exited' and not cleanup:
                raise AssertionError('Closed shell fixture cleanup_failed') from None

    def test_actual_capture_shell_source_binding_and_old_argv(self):
        sha='a'*40
        for capture,n0a in [('false','false'),('false','true'),('true','true')]:
            code,args,root=self.capture_shell(capture,n0a,sha,sha)
            self.assertEqual(code,0);self.assertIsNotNone(args)
            self.assertTrue(args[:4]==['--signal=TERM','--kill-after=30s','1000s','sudo'],'Closed timeout/sudo prefix mismatch')
            expected=['/usr/bin/python3','-B','.github/windows_identity_direct_stage0.py',
                      '--approved-disposable-vm','--python-archive',root+'/client-stage0-python/python-3.14.8-embed-amd64.zip',
                      '--actor',root+'/client-stage0-actor/windows_identity_actor.exe','--actor-sha256','b'*64,
                      '--bundle',root+'/g-bundle.zip','--output','client-stage0-public','--timeout-seconds','6600',
                      '--job-deadline-epoch','2000']
            if n0a=='true':expected+=['--n0a','--n0a-actor',root+'/n0a-production-build/windows_n0a_actor.exe','--n0a-manifest',root+'/n0a-production-build/build-manifest.json']
            if capture=='true':expected=['/usr/bin/env','GITHUB_SHA='+sha]+expected+['--n0a-capture-runner']
            self.assertTrue(args[4:]==expected,'Closed production argv mismatch')
        for commit,observed,n0a in [('',sha,'true'),('A'*40,'A'*40,'true'),('a'*39,'a'*39,'true'),('a'*41,'a'*41,'true'),(sha,'c'*40,'true'),(sha,'','true'),(sha,sha,'false')]:
            code,args,_=self.capture_shell('true',n0a,commit,observed)
            self.assertNotEqual(code,0);self.assertIsNone(args)

    def test_udp_production_artifact_and_exact_required_suites(self):
        short=(ROOT/'.github/workflows/windows-n0a-udp-gates.yml').read_text()
        names=ast.literal_eval(re.search(r"names=(\([^;]+\));",short).group(1))
        self.assertEqual(len(names),25)
        block=self.text.split('name: Build pinned production-only UDP actor',1)[1].split('      - uses: actions/upload-artifact@v7',1)[0]
        actual=ast.literal_eval(re.search(r"names=(\([^;]+\));",block).group(1))
        self.assertEqual(actual,names)
        for gate in ('test-windows-n0a-guest-gates.ps1','test-windows-udp-guest-gates.ps1','test-windows-udp-payload-gates.ps1'):
            self.assertIn(gate,block)
        for name,arg in (('windows_n0a_udp_actor.cpp','-ExpectedActorSha256 '),('windows_identity_actor.cpp','-ExpectedIdentitySha256 ')):
            self.assertIn(arg+hashlib.sha256((ROOT/'.github/native'/name).read_bytes()).hexdigest(),block)
        upload=next(b.split('      - ',1)[0] for b in self.text.split('- uses: actions/upload-artifact@v7')[1:] if 'name: n0a-udp-production-actor' in b.split('      - ',1)[0])
        paths=upload.split('path: |',1)[1].split('retention-days:',1)[0].split()
        self.assertEqual(paths,['n0a-udp-production-build/windows_n0a_udp_actor.exe','n0a-udp-production-build/N0A-UDP-manifest.json'])
        self.assertIn("'[n0a-udp-runtime]'",upload)
        self.assertIn('name: n0a-udp-production-actor',self.text.split('actions/download-artifact@v8',1)[1])
        self.assertNotIn('build_windows_n0a_udp_fixture',self.text)
        self.assertNotIn('sudo -E',self.text)

    def test_udp_actual_shell_exact_exclusive_argv_and_sha(self):
        sha='a'*40
        code,args,root=self.capture_shell('false','false',sha,sha,udp='true')
        self.assertEqual(code,0);self.assertIsNotNone(args)
        expected=['--signal=TERM','--kill-after=30s','1000s','sudo','/usr/bin/env','GITHUB_SHA='+sha,
                  '/usr/bin/python3','-B','.github/windows_identity_direct_stage0.py','--approved-disposable-vm',
                  '--python-archive',root+'/client-stage0-python/python-3.14.8-embed-amd64.zip',
                  '--actor',root+'/client-stage0-actor/windows_identity_actor.exe','--actor-sha256','b'*64,
                  '--bundle',root+'/g-bundle.zip','--output','client-stage0-public','--timeout-seconds','6600',
                  '--job-deadline-epoch','2000','--n0a-udp-runner','--udp-actor',
                  root+'/n0a-udp-production-build/windows_n0a_udp_actor.exe','--udp-manifest',
                  root+'/n0a-udp-production-build/N0A-UDP-manifest.json']
        self.assertTrue(args==expected,'Closed UDP argv mismatch')
        for capture,n0a in (('false','true'),('true','true'),('true','false')):
            code,args,_=self.capture_shell(capture,n0a,sha,sha,udp='true')
            self.assertNotEqual(code,0);self.assertIsNone(args)
        for commit,observed in (('',sha),('A'*40,'A'*40),('a'*39,'a'*39),('a'*41,'a'*41),(sha,'c'*40),(sha,'')):
            code,args,_=self.capture_shell('false','false',commit,observed,udp='true')
            self.assertNotEqual(code,0);self.assertIsNone(args)


    def test_parent_production_build_artifacts_and_required_gates(self):
        import yaml
        doc=yaml.load(self.text,Loader=yaml.BaseLoader)
        condition=runpy.run_path(str(ROOT/'tests/test_windows_n0a_udp_workflow.py'))['condition']
        compile_steps=doc['jobs']['compile']['steps'];native_steps=doc['jobs']['native']['steps']
        build=next(step for step in compile_steps if step.get('name')=='Build pinned production descendant parent and child')
        helpers=next(step for step in compile_steps if step.get('name')=='Actual descendant parent and legacy payload helper gates')
        host=next(step for step in doc['jobs']['host-unit']['steps'] if 'test_windows_udp_parent_composed.py' in step.get('run',''))
        for filename in ('windows_n0a_udp_parent.cpp','windows_n0a_udp_actor.cpp','windows_identity_actor.cpp'):
            self.assertIn(hashlib.sha256((ROOT/'.github/native'/filename).read_bytes()).hexdigest(),build['run'])
        self.assertIn('build_windows_n0a_udp_parent.ps1',build['run'])
        self.assertIn('build_windows_n0a_udp_actor.ps1',build['run'])
        binary_loop=re.search(r'foreach \(\$binary in @\(([^\n]+)\)\)',build['run']).group(1)
        self.assertEqual(re.findall(r"'([^']+)'",binary_loop),[
            'udp-parent-production-build/windows_n0a_udp_parent.exe',
            'n0a-udp-production-build/windows_n0a_udp_actor.exe'])
        self.assertIn('$size=(Get-Item -LiteralPath $binary).Length',build['run'])
        self.assertIn('$size -lt 512 -or $size -gt 8388608',build['run'])
        short=(ROOT/'.github/workflows/windows-n0a-udp-parent-gates.yml').read_text()
        expected=ast.literal_eval(re.search(r'names=(\([^;]+\));',short).group(1))
        self.assertEqual(len(expected),33)
        for step in (build,host):
            actual=ast.literal_eval(re.search(r'names=(\([^;]+\));',step['run']).group(1))
            self.assertEqual(actual,expected)
            self.assertIn('bool(result.skipped)',step['run'])
            self.assertIn('all(p.countTestCases()>0 for p in parts)',step['run'])
        self.assertEqual(helpers['shell'],'powershell')
        self.assertEqual(helpers['timeout-minutes'],'2')
        for gate in ('test-windows-n0a-guest-gates.ps1','test-windows-udp-guest-gates.ps1','test-windows-udp-parent-guest-gates.ps1','test-windows-udp-payload-gates.ps1'):
            self.assertIn(gate,helpers['run'])
        def artifact(steps,action,name):
            return next(step for step in steps if step.get('uses','').startswith(action) and step.get('with',{}).get('name')==name)
        parent_upload=artifact(compile_steps,'actions/upload-artifact','n0a-udp-parent-production-actor')
        child_upload=artifact(compile_steps,'actions/upload-artifact','n0a-udp-production-actor')
        parent_download=artifact(native_steps,'actions/download-artifact','n0a-udp-parent-production-actor')
        child_download=artifact(native_steps,'actions/download-artifact','n0a-udp-production-actor')
        public=artifact(native_steps,'actions/upload-artifact','n0a-udp-parent-exploratory-public')
        self.assertEqual(parent_upload['with']['path'].split(),[
            'udp-parent-production-build/windows_n0a_udp_parent.exe',
            'udp-parent-production-build/N0A-UDP-PARENT-manifest.json'])
        self.assertEqual(child_upload['with']['path'].split(),[
            'n0a-udp-production-build/windows_n0a_udp_actor.exe',
            'n0a-udp-production-build/N0A-UDP-manifest.json'])
        self.assertEqual(parent_download['with']['path'],'udp-parent-production-build')
        self.assertEqual(child_download['with']['path'],'n0a-udp-production-build')
        self.assertEqual(public['with']['path'],'client-stage0-public/n0a-udp-parent-public.json')
        self.assertLess(compile_steps.index(build),compile_steps.index(parent_upload))
        self.assertLess(compile_steps.index(build),compile_steps.index(child_upload))
        markers=('[identity-direct-stage0-runtime]','[n0a-connect-runtime]','[n0a-capture-runtime]','[n0a-udp-runtime]','[n0a-udp-parent-runtime]','[n0a-udp6-runtime]')
        for present in itertools.product((False,True),repeat=6):
            message=' '.join(m for m,on in zip(markers,present) if on)
            for step in (build,helpers,host,parent_upload,parent_download,public):
                expression=step['if'][3:-2].replace('always()','true')
                self.assertEqual(condition(expression,message),sum(present)==1 and present[4])
            for step in (child_upload,child_download):
                self.assertEqual(condition(step['if'][3:-2],message),sum(present)==1 and (present[3] or present[4]))
        run=next(step for step in native_steps if 'PARENT_UDP_REQUESTED' in step.get('env',{}))
        self.assertEqual(run['env']['CAPTURE_SOURCE_COMMIT'],'${{ github.sha }}')
        self.assertEqual(run['env']['PARENT_UDP_REQUESTED'],"${{ contains(github.event.head_commit.message, '[n0a-udp-parent-runtime]') }}")

    def test_parent_actual_shell_exact_exclusive_argv_and_sha(self):
        sha='a'*40
        code,args,root=self.capture_shell('false','false',sha,sha,parent='true')
        self.assertEqual(code,0);self.assertIsNotNone(args)
        expected=['--signal=TERM','--kill-after=30s','1000s','sudo','/usr/bin/env','GITHUB_SHA='+sha,
                  '/usr/bin/python3','-B','.github/windows_identity_direct_stage0.py','--approved-disposable-vm',
                  '--python-archive',root+'/client-stage0-python/python-3.14.8-embed-amd64.zip',
                  '--actor',root+'/client-stage0-actor/windows_identity_actor.exe','--actor-sha256','b'*64,
                  '--bundle',root+'/g-bundle.zip','--output','client-stage0-public','--timeout-seconds','6600',
                  '--job-deadline-epoch','2000','--n0a-udp-parent-runner','--udp-parent-actor',
                  root+'/udp-parent-production-build/windows_n0a_udp_parent.exe','--udp-parent-manifest',
                  root+'/udp-parent-production-build/N0A-UDP-PARENT-manifest.json','--udp-actor',
                  root+'/n0a-udp-production-build/windows_n0a_udp_actor.exe','--udp-manifest',
                  root+'/n0a-udp-production-build/N0A-UDP-manifest.json']
        self.assertTrue(args==expected,'Closed parent UDP argv mismatch')
        # Every mixed environment is rejected before the inert timeout is called.
        for capture,n0a,udp in itertools.product(('false','true'),repeat=3):
            if (capture,n0a,udp)==('false','false','false'):continue
            code,args,_=self.capture_shell(capture,n0a,sha,sha,udp=udp,parent='true')
            self.assertNotEqual(code,0);self.assertIsNone(args)
        for commit,observed in (('',sha),('A'*40,'A'*40),('a'*39,'a'*39),('a'*41,'a'*41),(sha,'c'*40),(sha,'')):
            code,args,_=self.capture_shell('false','false',commit,observed,parent='true')
            self.assertNotEqual(code,0);self.assertIsNone(args)
    def test_udp6_exact_production_artifacts_suites_and_exclusive_steps(self):
        import yaml
        doc=yaml.load(self.text,Loader=yaml.BaseLoader)
        condition=runpy.run_path(str(ROOT/'tests/test_windows_n0a_udp_workflow.py'))['condition']
        steps=doc['jobs']['compile']['steps']+doc['jobs']['host-unit']['steps']+doc['jobs']['native']['steps']
        selected=[v for v in steps if v.get('name') in ('Build pinned production-only UDP6 actor and require adapter gates','Actual UDP6 and legacy payload helper gates','Required UDP6 Linux contracts') or v.get('with',{}).get('name') in ('n0a-udp6-production-actor','n0a-udp6-exploratory-public')]
        self.assertEqual(len(selected),6)
        markers=('[identity-direct-stage0-runtime]','[n0a-connect-runtime]','[n0a-capture-runtime]','[n0a-udp-runtime]','[n0a-udp-parent-runtime]','[n0a-udp6-runtime]')
        for present in itertools.product((False,True),repeat=6):
            msg=' '.join(m for m,on in zip(markers,present) if on)
            for step in selected:self.assertEqual(condition(step['if'][3:-2].replace('always()','true'),msg),sum(present)==1 and present[5])
        for jobname in ('compile','host-unit'):
            expr=doc['jobs'][jobname]['if'][3:-2]
            for present in itertools.product((False,True),repeat=6):
                message=' '.join(m for m,on in zip(markers,present) if on)
                self.assertEqual(condition(expr,message),any(present))
            self.assertFalse(condition(expr,markers[5],branch='refs/heads/main'))
            self.assertFalse(condition(expr,markers[5],event='workflow_dispatch'))
        self.assertFalse(self.native_allowed('[n0a-udp6-gates]'))
        run=next(x for x in steps if 'UDP6_REQUESTED' in x.get('env',{}))
        self.assertEqual(run['env']['UDP6_REQUESTED'],"${{ contains(github.event.head_commit.message, '[n0a-udp6-runtime]') }}")
        self.assertEqual(run['env']['CAPTURE_SOURCE_COMMIT'],'${{ github.sha }}')
        build=selected[0];self.assertIn('build_windows_n0a_udp6_actor.ps1',build['run'])
        for filename in ('windows_n0a_udp6_actor.cpp','windows_identity_actor.cpp'):
            self.assertIn(hashlib.sha256((ROOT/'.github/native'/filename).read_bytes()).hexdigest(),build['run'])
        self.assertIn("foreach ($binary in @('udp6-production-build/windows_n0a_udp6_actor.exe'))",build['run'])
        self.assertIn('$size -lt 512 -or $size -gt 8388608',build['run'])
        short=(ROOT/'.github/workflows/windows-n0a-udp6-gates.yml').read_text()
        names=ast.literal_eval(re.search(r'names=(\([^;]+\));',short).group(1));self.assertEqual(len(names),51)
        self.assertEqual(names[46:],('test_windows_identity_pipe_probe.py','test_windows_identity_ordinary_launcher.py','test_windows_identity_stage0b_guest.py','test_windows_stage0b_host.py','test_windows_stage0b_guest_transport.py'))
        names=names[:46]  # Runtime prerequisite list is unchanged; Stage0b remains short-gate-only.
        for step in selected:
            if 'names=' in step.get('run',''):
                self.assertEqual(ast.literal_eval(re.search(r'names=(\([^;]+\));',step['run']).group(1)),names)
                self.assertIn('bool(result.skipped)',step['run']);self.assertIn('all(p.countTestCases()>0 for p in parts)',step['run'])
        helper=selected[1]
        for name in ('n0a','udp','udp-parent','udp6'):
            self.assertIn('test-windows-'+name+'-guest-gates.ps1',helper['run'])
        self.assertIn('test-windows-udp-payload-gates.ps1',helper['run'])
        self.assertEqual(helper['shell'],'powershell')
        upload=next(x for x in selected if x.get('uses')=='actions/upload-artifact@v7' and x['with']['name']=='n0a-udp6-production-actor')
        download=next(x for x in selected if x.get('uses')=='actions/download-artifact@v8')
        self.assertEqual(upload['with']['path'].split(),['udp6-production-build/windows_n0a_udp6_actor.exe','udp6-production-build/N0A-UDP6-manifest.json'])
        self.assertEqual(download['with']['path'],'udp6-production-build')
        public=next(x for x in selected if x.get('with',{}).get('name')=='n0a-udp6-exploratory-public')
        self.assertEqual(public['with']['path'],'client-stage0-public/n0a-udp6-public.json')
        self.assertLess(steps.index(build),steps.index(upload))
        self.assertNotIn('build_windows_n0a_udp6_fixture',self.text)

    def test_stage0b_actual_all_128_conditions_and_existing_artifact_reuse(self):
        import yaml
        doc=yaml.load(self.text,Loader=yaml.BaseLoader)
        condition=runpy.run_path(str(ROOT/'tests/test_windows_n0a_udp_workflow.py'))['condition']
        markers=('[identity-direct-stage0-runtime]','[n0a-connect-runtime]','[n0a-capture-runtime]','[n0a-udp-runtime]','[n0a-udp-parent-runtime]','[n0a-udp6-runtime]','[identity-stage0b-runtime]')
        steps=doc['jobs']['compile']['steps']+doc['jobs']['host-unit']['steps']+doc['jobs']['native']['steps']
        newsteps=[x for x in steps if x.get('name','').startswith(('Stage0b ','Required Stage0b ')) or x.get('with',{}).get('name')=='stage0b-ipc-public']
        self.assertEqual(len(newsteps),4)
        oldsteps=[x for x in steps if 'if' in x and any(m in x['if'] for m in markers[:6]) and x not in newsteps]
        self.assertTrue(oldsteps)
        for present in itertools.product((False,True),repeat=7):
            message=' '.join(m for m,on in zip(markers,present) if on)
            self.assertEqual(self.native_allowed(message),sum(present)==1)
            for step in newsteps:self.assertEqual(condition(step['if'][3:-2].replace('always()','true'),message),sum(present)==1 and present[6])
            if present[6]:
                for step in oldsteps:self.assertFalse(condition(step['if'][3:-2].replace('always()','true'),message))
            for job in ('compile','host-unit'):self.assertEqual(condition(doc['jobs'][job]['if'][3:-2],message),any(present))
        for job in doc['jobs'].values():
            expr=job['if'][3:-2]
            self.assertFalse(condition(expr,markers[6],branch='refs/heads/main'))
            self.assertFalse(condition(expr,markers[6],event='workflow_dispatch'))
        self.assertFalse(self.native_allowed('[n0a-udp6-gates]'))
        self.assertEqual(self.text.count('build_windows_identity_actor.ps1 -IdentityOnly'),1)
        artifacts=[x for x in doc['jobs']['compile']['steps'] if x.get('uses')=='actions/upload-artifact@v7' and x['with']['name']=='client-stage0-actor']
        self.assertEqual(len(artifacts),1)
        self.assertEqual(artifacts[0]['with']['path'].splitlines(),['client-stage0-actor/windows_identity_actor.exe','client-stage0-actor/actor-sha256.txt'])
        self.assertIn('$manifest.httpCompiled -or -not $manifest.staticCrt',self.text)
        admission=newsteps[0];self.assertIn('$binary.Length -lt 512 -or $binary.Length -gt 8388608',admission['run'])
        self.assertLess(doc['jobs']['compile']['steps'].index(admission),doc['jobs']['compile']['steps'].index(artifacts[0]))
        short=(ROOT/'.github/workflows/windows-n0a-udp6-gates.yml').read_text()
        expected=ast.literal_eval(re.search(r'names=(\([^;]+\));',short).group(1));self.assertEqual(len(expected),51)
        for step in newsteps:
            if 'names=' in step.get('run',''):
                self.assertEqual(ast.literal_eval(re.search(r'names=(\([^;]+\));',step['run']).group(1)),expected)
                self.assertIn('pip install --disable-pip-version-check "PyYAML==6.0.3"',step['run'])
                if step.get('shell')=='powershell':self.assertIn('PyYAML==6.0.3"\nif ($LASTEXITCODE -ne 0)',step['run'])
                self.assertIn('bool(result.skipped)',step['run']);self.assertIn('all(p.countTestCases()>0 for p in parts)',step['run'])
        helpers=newsteps[1]['run']
        for mode in ('n0a','udp','udp-parent','udp6','stage0b'):self.assertIn('test-windows-'+mode+'-guest-gates.ps1',helpers)
        self.assertIn('test-windows-udp-payload-gates.ps1',helpers);self.assertEqual(helpers.count('if ($LASTEXITCODE -ne 0)'),6)
        self.assertEqual(newsteps[-1]['with']['path'],'client-stage0-public/stage0b-public.json')
        self.assertNotIn('path: client-stage0-public/*',self.text)
        self.assertIn('path: client-stage0-public/public-report.json',self.text)

    def test_stage0b_actual_shell_exact_sha_size_and_legacy_paths(self):
        sha='a'*40
        code,args,root=self.capture_shell('false','false',sha,sha,stage0b='true')
        expected=['--signal=TERM','--kill-after=30s','1000s','sudo','/usr/bin/env','GITHUB_SHA='+sha,
                  '/usr/bin/python3','-B','.github/windows_identity_direct_stage0.py','--approved-disposable-vm',
                  '--python-archive',root+'/client-stage0-python/python-3.14.8-embed-amd64.zip',
                  '--actor',root+'/client-stage0-actor/windows_identity_actor.exe','--actor-sha256','b'*64,
                  '--bundle',root+'/g-bundle.zip','--output','client-stage0-public','--timeout-seconds','6600',
                  '--job-deadline-epoch','2000','--stage0b']
        self.assertEqual(code,0);self.assertTrue(args==expected,'Closed Stage0b argv mismatch')
        for size in (511,8388609):
            code,args,_=self.capture_shell('false','false',sha,sha,stage0b='true',actor_size=size)
            self.assertNotEqual(code,0);self.assertIsNone(args)
        code,args,_=self.capture_shell('false','false',sha,sha,stage0b='true',actor_size=8388608)
        self.assertEqual(code,0);self.assertIsNotNone(args)
        for flags in itertools.product(('false','true'),repeat=5):
            if flags==('false',)*5:continue
            capture,n0a,udp,parent,udp6=flags
            code,args,_=self.capture_shell(capture,n0a,sha,sha,udp=udp,parent=parent,udp6=udp6,stage0b='true')
            self.assertNotEqual(code,0);self.assertIsNone(args)
        for commit,observed in (('',sha),('A'*40,'A'*40),('a'*39,'a'*39),('a'*41,'a'*41),(sha,'c'*40),(sha,'')):
            code,args,_=self.capture_shell('false','false',commit,observed,stage0b='true')
            self.assertNotEqual(code,0);self.assertIsNone(args)

    def test_udp6_actual_shell_exact_exclusive_argv_and_sha(self):
        sha='a'*40
        code,args,root=self.capture_shell('false','false',sha,sha,udp6='true')
        self.assertEqual(code,0);self.assertIsNotNone(args)
        expected=['--signal=TERM','--kill-after=30s','1000s','sudo','/usr/bin/env','GITHUB_SHA='+sha,
                  '/usr/bin/python3','-B','.github/windows_identity_direct_stage0.py','--approved-disposable-vm',
                  '--python-archive',root+'/client-stage0-python/python-3.14.8-embed-amd64.zip',
                  '--actor',root+'/client-stage0-actor/windows_identity_actor.exe','--actor-sha256','b'*64,
                  '--bundle',root+'/g-bundle.zip','--output','client-stage0-public','--timeout-seconds','6600',
                  '--job-deadline-epoch','2000','--n0a-udp6-runner','--udp6-actor',
                  root+'/udp6-production-build/windows_n0a_udp6_actor.exe','--udp6-manifest',
                  root+'/udp6-production-build/N0A-UDP6-manifest.json']
        self.assertTrue(args==expected,'Closed UDP6 argv mismatch')
        # Every mixed environment is rejected before the inert timeout is called.
        for capture,n0a,udp,parent in itertools.product(('false','true'),repeat=4):
            if (capture,n0a,udp,parent)==('false','false','false','false'):continue
            code,args,_=self.capture_shell(capture,n0a,sha,sha,udp=udp,parent=parent,udp6='true')
            self.assertNotEqual(code,0);self.assertIsNone(args)
        for commit,observed in (('',sha),('A'*40,'A'*40),('a'*39,'a'*39),('a'*41,'a'*41),(sha,'c'*40),(sha,'')):
            code,args,_=self.capture_shell('false','false',commit,observed,udp6='true')
            self.assertNotEqual(code,0);self.assertIsNone(args)

class ShellDiagnosticTests(unittest.TestCase):
    def test_success_and_no_raw_streams(self):
        child=Mock();child.wait.return_value=0;factory=Mock(return_value=child)
        code,facts=observe_fixture_shell(['private-command'],'private-root',{},factory=factory,clock=lambda:0)
        self.assertEqual(code,0);self.assertEqual(facts['outcome'],'exited')
        self.assertTrue(facts['exit_confirmed']);self.assertFalse(facts['descendants_observed'])
        child.wait.assert_called_once_with(timeout=5);child.kill.assert_not_called()
        self.assertEqual(factory.call_args.kwargs['stdout'],subprocess.DEVNULL)
        self.assertEqual(factory.call_args.kwargs['stderr'],subprocess.DEVNULL)
        self.assertNotIn('private',json.dumps(facts))

    def test_timeout_same_wait_and_one_cleanup_budget(self):
        child=Mock();child.wait.side_effect=[subprocess.TimeoutExpired('private-command',5),0]
        child.poll.side_effect=[None,0];ticks=iter((0,5,5,5.25))
        code,facts=observe_fixture_shell(['private-command'],'private-root',{},factory=lambda *a,**k:child,clock=lambda:next(ticks))
        self.assertIsNone(code);self.assertEqual(facts['outcome'],'work_timeout')
        self.assertEqual(facts['elapsed'],'at_least_5s');self.assertTrue(facts['exit_confirmed'])
        self.assertEqual([call.kwargs['timeout'] for call in child.wait.call_args_list],[5,.75])
        child.kill.assert_called_once();self.assertEqual(child.poll.call_count,2)
        self.assertNotIn('private',json.dumps(facts))

    def test_cleanup_failures_do_not_skip_final_poll_or_retry(self):
        child=Mock();child.wait.side_effect=[subprocess.TimeoutExpired('private',5),OSError('private')]
        child.kill.side_effect=OSError('private');child.poll.side_effect=[OSError('private'),None]
        code,facts=observe_fixture_shell(['private'],'private',{},factory=lambda *a,**k:child,clock=lambda:0)
        self.assertIsNone(code);self.assertFalse(facts['exit_confirmed']);self.assertTrue(facts['kill_failed'])
        self.assertEqual(child.wait.call_count,2);self.assertEqual(child.poll.call_count,2)
        child.kill.assert_called_once();self.assertNotIn('private',json.dumps(facts))
        child.reset_mock();child.wait.side_effect=[subprocess.TimeoutExpired('private',5)];child.poll.side_effect=[None,None]
        ticks=iter((0,5,5,6.1))
        observe_fixture_shell([],'.',{},factory=lambda *a,**k:child,clock=lambda:next(ticks))
        self.assertEqual(child.wait.call_count,1);self.assertEqual(child.poll.call_count,2)

    def test_spawn_and_unexpected_exit_closed(self):
        factory=Mock(side_effect=OSError('private-command'))
        code,facts=observe_fixture_shell([],'.',{},factory=factory,clock=lambda:0)
        self.assertIsNone(code);self.assertEqual(facts['outcome'],'spawn_failed');factory.assert_called_once()
        self.assertNotIn('private',json.dumps(facts))
        # Windows termination is a positive DWORD, not necessarily a POSIX signal.
        for exit_code in (-9,2,0xC000013A):
            child=Mock();child.wait.return_value=exit_code
            _,facts=observe_fixture_shell([],'.',{},factory=lambda *a,**k:child,clock=lambda:0)
            self.assertEqual(facts['outcome'],'unexpected_exit');self.assertTrue(facts['exit_confirmed'])
        child.wait.return_value=1
        _,facts=observe_fixture_shell([],'.',{},factory=lambda *a,**k:child,clock=lambda:0)
        self.assertEqual(facts['outcome'],'exited');self.assertFalse(facts['exit_zero'])

    def test_stage_allowlist_and_failed_wait_retains_root(self):
        with tempfile.TemporaryDirectory(prefix='n0a-diagnostic-test-') as directory:
            parent=Path(directory);stage=parent/'stage'
            for value in (b'startup_unobserved',b'startup',b'guards',b'body',b'stub'):
                stage.write_bytes(value);self.assertEqual(fixture_shell_stage(stage),value.decode())
            for value in (b'',b'bo',b'private-path',b'body\n',b'x'*33):
                stage.write_bytes(value);self.assertEqual(fixture_shell_stage(stage),'unobserved')
            self.assertEqual(fixture_shell_stage(parent/'missing'),'unobserved')
            root=parent/'owned';root.mkdir()
            instance=N0aDirectWorkflowTests();instance.setUp()
            facts=dict(outcome='work_timeout',elapsed='at_least_5s',exit_confirmed=True,kill_attempted=True,kill_failed=False,descendants_observed=False)
            with patch(__name__+'.SHELL_OBSERVATIONS',0),patch.object(tempfile,'mkdtemp',return_value=str(root)),patch(__name__+'.observe_fixture_shell',return_value=(None,facts)),patch('builtins.print') as output:
                with self.assertRaises(AssertionError) as caught:instance.capture_shell('false','false','a'*40,'a'*40)
            self.assertNotIn(str(root),str(caught.exception));self.assertTrue(root.exists())
            closed=json.loads(output.call_args.args[0]);self.assertTrue(closed['root_removal_skipped'])
            self.assertFalse(closed['root_cleanup_confirmed']);self.assertFalse(closed['descendants_observed'])


if __name__ == '__main__':
    unittest.main()
