import ast
import importlib.util
import json
import re
from pathlib import Path
import unittest
from unittest.mock import patch

ROOT=Path(__file__).resolve().parents[1]
def load(name):
    spec=importlib.util.spec_from_file_location(name,ROOT/'.github'/f'{name}.py')
    module=importlib.util.module_from_spec(spec);spec.loader.exec_module(module);return module
host=load('windows_identity_direct_stage0')
serviced=load('windows_identity_serviced_stage0')

class DirectStage0Tests(unittest.TestCase):
    def receipt(self):
        return dict(stage0_passed=True,checks={k:True for k in host.CHECKS},ordinary_account=True,
            direct_build_verified=True,harness_completed=True,actor_sha256='a'*64,
            os=dict(build=26300,ubr=9457,product_type='WinNT',architecture='AMD64'))
    def test_exact_minimal_result_is_exploratory_only(self):
        value=host.validate_guest(self.receipt(),'a'*64)
        self.assertTrue(value['stage0_passed']);self.assertTrue(value['exploratory_stage0'])
        self.assertFalse(value['product_acceptance']);self.assertFalse(value['privacy_qualified'])
        self.assertEqual(value['documented_support_floor'],'26300.9550')
    def test_all_checks_and_ordinary_build_harness_required(self):
        for key in host.CHECKS:
            raw=self.receipt();raw['checks'][key]=False
            self.assertFalse(host.validate_guest(raw,'a'*64)['stage0_passed'])
        for key in ('ordinary_account','direct_build_verified','harness_completed'):
            for wrong in (False,None,1,'true'):
                raw=self.receipt();raw[key]=wrong
                self.assertFalse(host.validate_guest(raw,'a'*64)['stage0_passed'])
    def test_exact_build_arch_product_and_actor(self):
        for key,wrong in (('build',26200),('ubr',9550),('ubr',9458),('architecture','ARM64'),('product_type','ServerNT')):
            raw=self.receipt();raw['os'][key]=wrong
            with self.assertRaises(ValueError):host.validate_guest(raw,'a'*64)
        with self.assertRaises(ValueError):host.validate_guest(self.receipt(),'b'*64)
    def test_no_handoff_never_accepts(self):
        public={'stage0_passed':True}
        with self.assertRaises(ValueError):host.merge_direct_result(public,self.receipt(),'a'*64,False)
        self.assertFalse(public['stage0_passed'])
    def test_handoff_and_exact_result_accepts(self):
        public={};host.merge_direct_result(public,self.receipt(),'a'*64,True)
        self.assertTrue(public['stage0_passed']);self.assertTrue(public['guest_result_provenance_verified'])
    def test_early_failure_cannot_be_overwritten(self):
        public={'early_guest_diagnostic':{},'stage0_passed':True}
        with self.assertRaises(host.EarlyGuestFailure):host.merge_direct_result(public,self.receipt(),'a'*64,True)
        self.assertFalse(public['stage0_passed'])
    def test_provenance_failure_preserves_closed_diagnostics(self):
        raw=self.receipt();raw['os']['ubr']=9550;raw['launcher_diagnostic']={'phase':'direct_build','failed':True,'raw':'SECRET'}
        public={}
        with self.assertRaises(ValueError):host.merge_direct_result(public,raw,'a'*64,True)
        self.assertTrue(public['launcher_diagnostic']['failed']);self.assertNotIn('SECRET',json.dumps(public))
    def test_no_update_logic_or_media_switch_in_source(self):
        source=(ROOT/'.github/windows_identity_direct_stage0.py').read_text()
        for forbidden in ('prepare_servicing','UPDATE_PACKAGES','blockdev-change-medium','blockdev-remove-medium','windows-identity-serviced-update','media.ISO_URL ='):
            self.assertNotIn(forbidden,source)
        self.assertIn('windows-identity-direct-stage0-{role}.ps1',source)
    def test_local_pins_guards_and_execution_disabled(self):
        self.assertIs(type(host.EXECUTION_ENABLED),bool)
        with patch.object(host,'EXECUTION_ENABLED',False):
            with self.assertRaises(PermissionError):host.host(None)
        self.assertEqual(host.ISO_BYTES,8225329152)
        self.assertEqual(host.ISO_SHA256,'bc3f24086ebadc94489066b5ad78089e2cf5c3491e90e790bb81a2b199c10e38')
        self.assertTrue(host.ISO_URL.startswith('https://software-static.download.prss.microsoft.com/dbazure/26300.9457.'))
        self.assertEqual((host.DISK_FILE_CAP,host.LAUNCH_FREE,host.STOP_FREE),(22*2**30,24*2**30,4*2**30))
        self.assertEqual(host.CHECKS,serviced.CHECKS)
    def test_payload_controller_only_changes_host_member(self):
        self.assertEqual(host.GUEST_SOURCES[0],'.github/windows_identity_direct_stage0.py')
        self.assertEqual(host.GUEST_SOURCES[1:],serviced.GUEST_SOURCES[1:])
    def test_reviewed_teardown_and_projection_infrastructure_unchanged(self):
        def functions(path):
            return {n.name:ast.dump(n,include_attributes=False) for n in ast.parse(path.read_text()).body if isinstance(n,(ast.FunctionDef,ast.ClassDef))}
        direct=functions(ROOT/'.github/windows_identity_direct_stage0.py');original=functions(ROOT/'.github/windows_identity_serviced_stage0.py')
        for name in ('cleanup_owned','finalize_owned','new_teardown_facts','teardown_error','exit_observation','observe_qmp_closed','EarlyGuestSerial','parse_early_guest','observe_guest_serial','VMWatchdog'):
            if name in original:self.assertEqual(direct[name],original[name],name)
    def diagnostic(self):
        return dict(schema=1,phase='installed_boot_gate',operation='gate',failure_category='installed_boot_gate',hresult=None,gates={k:None for k in host.EARLY_GATES})
    def test_exact_guest_enum_parity(self):
        source=(ROOT/'.github/windows-identity-direct-stage0-run.ps1').read_text()
        block=source.split('function Get-ClosedEarlyDiagnostic {',1)[1].split('function ',1)[0]
        def values(name):
            match=re.search(r'\$'+name+r'=\s*@\((.*?)\)',block,re.S)
            self.assertIsNotNone(match,name)
            return set(re.findall(r"'([^']*)'",match.group(1)))
        self.assertEqual(values('phases'),set(host.LAUNCHER_PHASES)-{'not_observed','direct_build'})
        self.assertEqual(values('operations'),set(host.EARLY_OPERATIONS))
        self.assertEqual(values('categories'),set(host.LAUNCHER_FAILURES))
    def test_direct_early_wire_and_fragmented_failure(self):
        observer=host.EarlyGuestSerial();line='RPDIAG1 '+json.dumps(self.diagnostic())+'\r\n'
        self.assertIn('build_26300',host.EARLY_GATES);self.assertIn('ubr_direct',host.EARLY_GATES)
        self.assertIsNone(observer.feed(line[:200]));self.assertEqual(observer.feed(line[200:]),self.diagnostic())
    def test_bootstrap_boundary_and_handoff(self):
        beacon='RPBEACON identity-ordinary-ready\r\n'
        args=dict(started=100,handed_off=False,plugged=False)
        self.assertTrue(host.observe_bootstrap({},host.EarlyGuestSerial(),beacon,'',now=2199.999,**args)[1])
        for now in (2200,2201):
            with self.assertRaises(host.BootstrapTimeout):host.observe_bootstrap({},host.EarlyGuestSerial(),beacon,'',now=now,**args)
        args.update(handed_off=True,plugged=True)
        self.assertFalse(host.observe_bootstrap({},host.EarlyGuestSerial(),beacon,'',now=9999,**args)[1])
    def test_early_failure_precedes_bootstrap_timeout(self):
        line='RPDIAG1 '+json.dumps(self.diagnostic())+'\r\n';public={}
        with self.assertRaises(host.EarlyGuestFailure):host.observe_bootstrap(public,host.EarlyGuestSerial(),line,'',started=0,now=2101,handed_off=False,plugged=False)
        self.assertEqual(public['host_wait_failure'],'guest_launcher_failure')

class DirectDownloadBudgetTests(unittest.TestCase):
    def test_download_extended_but_capped_by_remaining_work(self):
        for remaining,expected in ((4000,1800),(1800,1800),(250,250)):
            with patch.object(host.time,'monotonic',return_value=100), patch.object(host,'limited_command',side_effect=lambda command,ceiling:command), patch.object(host.subprocess,'run') as run:
                host.download_direct_iso(Path('official.iso'),100+remaining)
                self.assertEqual(run.call_args.kwargs['timeout'],expected)
                argv=run.call_args.args[0]
                self.assertEqual(argv[argv.index('--max-time')+1],'1780')
    def test_cleanup_reserve_never_available_to_download(self):
        # Production computes work_deadline=start+available-120.
        start=100;available=1000;work_deadline=start+available-120
        with patch.object(host.time,'monotonic',return_value=start), patch.object(host,'limited_command',side_effect=lambda command,ceiling:command), patch.object(host.subprocess,'run') as run:
            host.download_direct_iso(Path('official.iso'),work_deadline)
            self.assertEqual(run.call_args.kwargs['timeout'],880)
        with patch.object(host.time,'monotonic',return_value=work_deadline), patch.object(host,'limited_command',side_effect=lambda command,ceiling:command), patch.object(host.subprocess,'run') as run:
            with self.assertRaises(TimeoutError):host.download_direct_iso(Path('official.iso'),work_deadline)
            run.assert_not_called()
    def test_long_download_cannot_bypass_guest_work_admission(self):
        clock=[0]
        def download(*args,**kwargs):clock[0]+=kwargs['timeout']
        with patch.object(host.time,'monotonic',side_effect=lambda:clock[0]), patch.object(host,'limited_command',side_effect=lambda command,ceiling:command), patch.object(host.subprocess,'run',side_effect=download):
            deadline=3500
            host.download_direct_iso(Path('official.iso'),deadline)
            self.assertEqual(clock[0],1800)
            with self.assertRaises(host.VMWorkBudgetInsufficient):host.require_vm_work_budget(deadline)
        self.assertEqual(host.require_vm_work_budget(3600,now=1800),1800)

if __name__=='__main__':unittest.main()
