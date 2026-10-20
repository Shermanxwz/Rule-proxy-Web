import importlib.util
from pathlib import Path
import unittest
from unittest.mock import patch
from types import SimpleNamespace
ROOT = Path(__file__).resolve().parents[1]
SPEC = importlib.util.spec_from_file_location('stock', ROOT / '.github/windows_identity_stock_stage0.py')
stock = importlib.util.module_from_spec(SPEC); SPEC.loader.exec_module(stock)
class StockTests(unittest.TestCase):
    def test_execution_disabled(self):
        with patch.object(stock, 'EXECUTION_ENABLED', False):
            with self.assertRaises(PermissionError): stock.host(SimpleNamespace())
    def test_budget_is_not_fit_claim(self):
        self.assertGreaterEqual(stock.LAUNCH_FREE - stock.DISK_FILE_CAP, 6 * stock.GIB)
        self.assertGreater(stock.LAUNCH_FREE - stock.DISK_FILE_CAP, stock.STOP_FREE)
    def test_limit_primitive_in_owned_temp(self):
        import shutil, subprocess, sys, tempfile
        if sys.platform != 'linux' or not shutil.which('prlimit'): self.skipTest('Linux prlimit required')
        with tempfile.TemporaryDirectory() as directory:
            target = Path(directory) / 'bounded.bin'
            code = "import resource,sys; assert resource.getrlimit(resource.RLIMIT_FSIZE)==(4096,4096); f=open(sys.argv[1],'wb',buffering=0); f.write(b'x'*8192); f.write(b'x')"
            run = subprocess.run(stock.limited_command([sys.executable,'-c',code,str(target)],4096),
                                 stdout=subprocess.DEVNULL,stderr=subprocess.DEVNULL,timeout=5)
            self.assertNotEqual(run.returncode,0)
            self.assertLessEqual(target.stat().st_size,4096)
    def test_limit_applied_before_exec(self):
        c = stock.limited_command(['owned-binary'], 17)
        self.assertEqual(c, ['prlimit', '--fsize=17:17', '--core=0:0', '--', 'owned-binary'])
    def test_closed_projection(self):
        r = stock.project_stage0({'secret': '/private/identity', 'stage0_passed': True})
        self.assertNotIn('secret', r); self.assertFalse(r['stage0_passed'])
        self.assertIn('stock26200.6584', r['stage'])
    def test_exact_stock_gate(self):
        v = {'checks': {k: True for k in stock.CHECKS}, 'stage0_passed': True,
             'ordinary_account': True, 'stock_build_verified': True, 'harness_completed': True,
             'actor_sha256': 'a'*64, 'os': {'build':26200,'ubr':6584,'product_type':'WinNT','architecture':'AMD64'}}
        self.assertTrue(stock.validate_guest(v, 'a'*64)['stage0_passed'])
        v['os']['ubr'] = 9711
        with self.assertRaises(ValueError): stock.validate_guest(v, 'a'*64)
    def test_capacity_trip_overrides_simultaneous_result(self):
        result = stock.reconcile_capacity({'status':'passed','stage0_passed':True}, 'free_reserve_reached')
        self.assertFalse(result['stage0_passed']); self.assertEqual(result['status'], 'resource_abort')
    def test_register_after_trip_kills_process(self):
        import tempfile
        with tempfile.TemporaryDirectory() as path:
            watch = stock.CapacityWatch(Path(path)); watch.reason='free_reserve_reached'
            proc = SimpleNamespace(poll=lambda: None, kill=lambda: setattr(watch,'killed',True))
            with self.assertRaises(RuntimeError): watch.register(proc)
            self.assertTrue(watch.killed)
    def test_finalize_late_trip_and_cleanup_failure(self):
        watch = SimpleNamespace(reason=None, minimum_free=1, thread=SimpleNamespace(is_alive=lambda:False))
        watch.close=lambda: setattr(watch,'reason','free_reserve_reached')
        with patch.object(stock,'cleanup_owned',return_value=True):
            result=stock.finalize_owned({'stage0_passed':True,'status':'passed'},None,Path('/unused'),watch=watch)
        self.assertFalse(result['stage0_passed']); self.assertEqual(result['status'],'resource_abort')
        with patch.object(stock,'cleanup_owned',return_value=False):
            result=stock.finalize_owned({'stage0_passed':True,'status':'passed'},None,Path('/unused'))
        self.assertFalse(result['stage0_passed']); self.assertEqual(result['status'],'cleanup_unconfirmed')
    def test_finalize_kill_race_and_live_watcher_retains_work(self):
        import tempfile
        with tempfile.TemporaryDirectory() as directory:
            work=Path(directory)/'owned'; work.mkdir()
            process=SimpleNamespace(poll=lambda:None,kill=lambda:(_ for _ in ()).throw(ProcessLookupError()),wait=lambda timeout:0)
            watch=SimpleNamespace(reason=None,minimum_free=100,thread=SimpleNamespace(is_alive=lambda:True),close=lambda:None)
            media=SimpleNamespace(stop_owned=lambda p:None)
            result=stock.finalize_owned({'stage0_passed':True},media,work,qemu=process,watch=watch)
            self.assertTrue(work.exists()); self.assertFalse(result['vm_destroyed']); self.assertFalse(result['stage0_passed'])
    def test_absolute_workflow_budget(self):
        text=(ROOT / '.github/workflows/windows-identity-stock-stage0.yml').read_text()
        self.assertIn('STOCK_JOB_DEADLINE=',text)
        self.assertIn('--job-deadline-epoch "$STOCK_HOST_DEADLINE"',text)
        self.assertNotIn('112m sudo',text)
    def test_recovery_embedding_matches_source(self):
        text=(ROOT / '.github/workflows/windows-identity-stock-stage0.yml').read_text()
        body=text.split("<<'REVIEWED_RECOVERY'\n",1)[1].split('          REVIEWED_RECOVERY',1)[0]
        decoded='\n'.join(line[10:] for line in body.splitlines())+'\n'
        self.assertEqual(decoded,(ROOT / '.github/windows_identity_provider_cache_recovery.py').read_text())
        self.assertIn("github.ref == 'refs/heads/dot/windows-isolation-proof'",text)
        self.assertIn('[identity-stock-stage0-runtime]',text)
    def test_no_servicing_or_full_media_copy(self):
        source = (ROOT / '.github/windows_identity_stock_stage0.py').read_text()
        self.assertNotIn('download_updates', source)
        self.assertNotIn('iso-tree', source)
        self.assertIn('preallocation=off', source)
        self.assertIn('ringbuf,id=serialbuf,size=65536', source)
        setup = (ROOT / '.github/windows-identity-stock-stage0-setup.ps1').read_text()
        self.assertNotIn('ScheduledTask', setup)
if __name__ == '__main__': unittest.main()
