"""Closed Stage0b dispatch and source invariants; actual PS gate is Windows-only."""
import ast
import hashlib
import importlib.util
from pathlib import Path
import re
import unittest
ROOT=Path(__file__).resolve().parents[1]
S=(ROOT/'.github/windows-identity-direct-stage0-run.ps1').read_text()
def part(name):return re.search(r'^function '+re.escape(name)+r'(?:\(|\s).*?^}',S,re.M|re.S).group()
def diagnostic_fixture_cases():
    import copy
    spec=importlib.util.spec_from_file_location('stage0b_diagnostic_fixture',ROOT/'.github/windows_identity_stage0b_guest.py')
    g=importlib.util.module_from_spec(spec);spec.loader.exec_module(g)
    base=g.default_public('a'*32,'b'*64)
    cases=[dict(name='default',valid=True,value=base)]
    def add(name,path,value,valid=False,template=None):
        row=copy.deepcopy(base if template is None else template);target=row
        for key in path[:-1]:target=target[key]
        target[path[-1]]=value;cases.append(dict(name=name,valid=valid,value=row));return row
    full=copy.deepcopy(base)
    full['diagnostic'].update(held=dict(created=True,resumed=True,exit_observed=True,exit_code=4294967295,cleanup_confirmed=True),reads=['parsed']*3,bindings=['verified']*3,stdout_reads=['parsed']*2,execution_sources=['owner','report','owned_stdout'],execution=[['input_validation','initial_token','native','process_terminate',4294967295]]*3)
    cases.append(dict(name='full_uint32',valid=True,value=full))
    add('old_schema',('schema_version',),1)
    old=copy.deepcopy(base);old['schema_version']=1;del old['diagnostic'];cases.append(dict(name='old_history',valid=False,value=old))
    add('diagnostic_version_bool',('diagnostic','v'),True)
    add('unknown_diagnostic_key',('diagnostic','private_path'),'private-fixture')
    add('held_bool',('diagnostic','held','created'),1)
    add('exit_without_creation',('diagnostic','held','exit_observed'),True)
    add('resumed_without_creation',('diagnostic','held','resumed'),True)
    add('code_without_creation',('diagnostic','held','exit_code'),0)
    for label,code in [('negative',-1),('overflow',4294967296),('boolean',True),('float',1.0)]:
        add('held_'+label,('diagnostic','held','exit_code'),code,template=full)
    add('cleanup_without_exit',('diagnostic','held','exit_observed'),False,template=full)
    add('uncreated_empty_cleanup',('diagnostic','held','cleanup_confirmed'),True,valid=True)
    for key,count in [('reads',3),('bindings',3),('stdout_reads',2),('execution_sources',3)]:
        add(key+'_short',('diagnostic',key),base['diagnostic'][key][:-1])
        add(key+'_scalar',('diagnostic',key),'not_attempted')
        add(key+'_unknown',('diagnostic',key),['private-fixture']*count)
    add('execution_short',('diagnostic','execution'),[None,None])
    add('source_without_record',('diagnostic','execution_sources'),['owner','none','none'])
    add('record_without_source',('diagnostic','execution',0),['complete',None,'none','none',None])
    add('slot0_stdout',('diagnostic','execution_sources',0),'owned_stdout',template=full)
    add('slot1_owner',('diagnostic','execution_sources',1),'owner',template=full)
    for label,record in [('short',['wait','wait','native','process_wait']),('stage',['raw-path','wait','native','process_wait',5]),('first',['wait','raw-path','native','process_wait',5]),('category',['wait','wait','raw-path','process_wait',5]),('operation',['wait','wait','native','raw-path',5]),('native_bool',['wait','wait','native','process_wait',True]),('native_negative',['wait','wait','native','process_wait',-1]),('native_overflow',['wait','wait','native','process_wait',4294967296]),('native_float',['wait','wait','native','process_wait',5.0]),('none_failure',['wait','wait','none','none',None]),('failure_no_stage',['wait',None,'native','process_wait',5]),('none_operation',['wait',None,'none','process_wait',None]),('io_win32',['wait','wait','io','process_wait',5]),('profile_not_win32',['profile','profile','native','profile',5])]:
        add('execution_'+label,('diagnostic','execution',0),record,template=full)
    for index,labels in [('reads',g.READ_STATES),('bindings',g.BINDING_STATES),('stdout_reads',g.READ_STATES)]:
        for label in labels:add(index+'_'+label,('diagnostic',index,0),label,valid=True)
    add('report_unparsed',('diagnostic','reads',0),'missing',template=full)
    add('report_unbound',('diagnostic','bindings',0),'identity',template=full)
    add('stdout_unparsed',('diagnostic','stdout_reads',1),'missing',template=full)
    add('stdout_parent_unbound',('diagnostic','bindings',0),'identity',template=full)
    stdout=add('launcher_stdout',('diagnostic','execution_sources',1),'owned_stdout',valid=True,template=full)
    add('launcher_stdout_unparsed',('diagnostic','stdout_reads',0),'missing',template=stdout)
    add('launcher_stdout_not_owned',('diagnostic','held'),dict(created=False,resumed=False,exit_observed=False,exit_code=None,cleanup_confirmed=False),template=stdout)
    add('probe_report',('diagnostic','execution_sources',2),'report',valid=True,template=full)
    # Parsed/verified observations alone never promote original acceptance fields.
    add('observations_not_identity',('diagnostic','reads'),['parsed']*3,valid=True)
    return g,cases

class TransportTests(unittest.TestCase):
    def test_python_diagnostic_cases_and_exact_ps_enums(self):
        g,cases=diagnostic_fixture_cases()
        for case in cases:
            with self.subTest(case=case['name']):
                try:g.validate_public(case['value'],'a'*32,'b'*64);accepted=True
                except Exception:accepted=False
                self.assertEqual(accepted,case['valid'])
        launcher=g.launcher_module();p=part('Test-Stage0bDiagnostic')
        for variable,expected in (('readStates',g.READ_STATES),('bindingStates',g.BINDING_STATES),('sources',g.EXECUTION_SOURCES),('stages',launcher.DIAGNOSTIC_STAGES),('categories',launcher.DIAGNOSTIC_CATEGORIES),('operations',launcher.DIAGNOSTIC_OPERATIONS)):
            actual=tuple(re.findall("'([^']+)'",p.split('$'+variable+'=@(',1)[1].split(')',1)[0]))
            self.assertEqual(actual,expected)
        keys=list(g.PUBLIC_KEYS)+list(g.default_diagnostic())+list(g.default_diagnostic()['held'])
        self.assertEqual(len(keys),len(set(keys)))  # Global duplicate-key rejection is valid only for this closed object layout.
        self.assertIn('$Value.schema_version -ne 2',part('Test-Stage0bPublic'))
        self.assertNotIn('diagnostic',part('Wait-Stage0bOwnedChild'))
    def test_exact_fourteen_additions_and_exclusion(self):
        names=set(re.findall("'([^']+)'",part('Get-Stage0bPayloadNames')))
        self.assertEqual(names,{'.github/windows_identity_pipe_probe.py','.github/windows_identity_ordinary_launcher.py','ruleproxy/windows_app_process.py','.github/windows_identity_stage0b_guest.py'})
        selector=S[S.index('    $stage0bPresent='):S.index('    $udp6Present=')]
        for name in ('n0a','capture','n0a_udp','n0a_udp_parent','n0a_udp6'):self.assertIn("'"+name+"'",selector)
        self.assertIn('Assert-Stage0bStagingBound $payload',S)
        self.assertIn('-MemberCount 14 -ExactBytes 0 -MaximumBytes 134217728',S)
    def test_same_original_deadline_and_clipped_cleanup(self):
        p=part('Invoke-Stage0bGuestDiagnostic');w=part('Wait-Stage0bOwnedChild')
        self.assertIn('$workEnd=$Deadline',p);self.assertNotIn('$Deadline-',p);self.assertNotIn('120*',p)
        self.assertIn('Wait-Stage0bOwnedChild $process $workEnd $Frequency',p)
        self.assertEqual(S.count('$n0aDeadline=$now+120*$n0aFrequency'),1)
        self.assertIn('Get-N0aRemainingMilliseconds $Deadline $Frequency',w)
        self.assertNotIn('WaitForExit(5000)',w)
        self.assertIn('--deadline-qpc',p);self.assertIn('--qpc-frequency',p)
        self.assertIn('Invoke-Stage0bGuestDiagnostic $configuration $workspace $python $n0aDeadline $n0aFrequency $n0aOriginalReady $delivered',S)
    def test_original_result_finalizer_and_extractor(self):
        final=S[S.index('} finally {\n    if ($failed'):S.index('\n# Original Stage0 delivery above')]
        self.assertEqual(hashlib.sha256(final.encode()).hexdigest(),'7e10be5db5c65d9c7b18cd10004d15f1be9339bdd4a3c10ceb5a2abd721cdb2b')
        extraction=S[S.index('function Expand-CheckedStage0Zip {'):S.index('\ntry {\n    $configuration')]
        self.assertEqual(hashlib.sha256(extraction.encode()).hexdigest(),'6e754133def219c06d5a6f3d96b5a5d88640383f9da6c62e889313df7c519140')
    def test_actual_schema_parity_and_no_observation_erasure(self):
        spec=importlib.util.spec_from_file_location('stage0b_ps_schema',ROOT/'.github/windows_identity_stage0b_guest.py');m=importlib.util.module_from_spec(spec);spec.loader.exec_module(m)
        p=part('Test-Stage0bPublic')
        booleans=set(re.findall("'([^']+)'",p.split('$booleans=@(',1)[1].split(')',1)[0]))
        self.assertEqual(booleans,set(m.BOOL_FIELDS))
        self.assertTrue(all("'"+x+"'" in p for x in m.FAILURES))
        inv=part('Invoke-Stage0bGuestDiagnostic')
        self.assertEqual(inv.count('$envelope.stage0b=$value'),1)
        self.assertNotIn('$envelope.stage0b=$null',inv)
        self.assertIn("'/stage0b-result'",inv);self.assertIn('Send-N0aClosedReport',inv)
        self.assertIn('4097',inv);self.assertIn('$body.Length -gt 4096',inv)
    def test_actual_windows_gate_uses_production_ast_and_mocks(self):
        gate=(ROOT/'.github/test-windows-stage0b-guest-gates.ps1').read_text()
        for text in ('FunctionDefinitionAst','g.default_public','g.validate_public','Test-Stage0bPublic','Invoke-Stage0bGuestDiagnostic','Wait-Stage0bOwnedChild','process_and_transport_mocked=$true','original_transport','work_budget_exhausted','case_nonce_sha256','--deadline-qpc '):self.assertIn(text,gate)
        self.assertNotIn('& $source',gate)
        self.assertIn('[IO.Directory]::Delete($root,$false)',gate)
if __name__=='__main__':unittest.main()
