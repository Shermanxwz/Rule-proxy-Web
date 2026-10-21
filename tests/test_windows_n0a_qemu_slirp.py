import importlib.util
from contextlib import contextmanager
import json
import stat
import os
from pathlib import Path
import tempfile
import time
import unittest
from unittest import mock
ROOT=Path(__file__).resolve().parents[1]
def load(name,file):
    spec=importlib.util.spec_from_file_location(name,ROOT/'.github'/file)
    value=importlib.util.module_from_spec(spec); spec.loader.exec_module(value); return value
m=load('slirp_unit','windows_n0a_qemu_slirp.py')
g=load('slirp_gate_unit','test_windows_n0a_qemu_slirp.py')

def fixture_nofollow_open(real_open, real_lstat):
    # Capture the low-level primitive before os.stat is modeled. Path.is_symlink
    # calls path stat and would recurse through the modeled open operation.
    def nofollow(path,flags,*args,**kwargs):
        if stat.S_ISLNK(real_lstat(path).st_mode):raise OSError('fixture_nofollow')
        return real_open(path,flags,*args,**kwargs)
    return nofollow

@contextmanager
def linux_fixture_stats(paths, *, enabled=None):
    """Model Linux path/FD metadata only for these owned test files on Windows.

    Windows CPython path stat may expose birthtime as ctime while fstat exposes
    ChangeTime (upstream CPython #157671). Do not drop any production field.
    Actual Linux tests and the separate Linux QEMU gate remain unmodified.
    """
    allowed={name for path in paths for name in (str(Path(path)),str(Path(path).resolve(strict=True)))}
    real_stat=os.stat
    def same_api_stat(path,*args,**kwargs):
        info=real_stat(path,*args,**kwargs)
        if str(path) not in allowed or not stat.S_ISREG(info.st_mode):return info
        fd=os.open(path,os.O_RDONLY|getattr(os,'O_BINARY',0))
        try:return os.fstat(fd)
        finally:os.close(fd)
    if enabled is True or (enabled is None and os.name=='nt'):
        with mock.patch.object(m.os,'stat',side_effect=same_api_stat):yield
    else:yield

@contextmanager
def owned_observer(*args,**kwargs):
    observer=m.MappedQemu(*args,**kwargs)
    try:yield observer
    finally:observer.close()

class Tests(unittest.TestCase):
    def setUp(self):
        # Emulate only unavailable Linux file primitives in the cross-platform
        # source/unit suite. Actual O_NOFOLLOW/proc/package behavior is Linux-gated.
        if not hasattr(os,'O_NOFOLLOW'):
            nofollow=fixture_nofollow_open(os.open,os.lstat)
            for name,value in (('O_NOFOLLOW',0),('O_CLOEXEC',0),('open',nofollow)):
                patch=mock.patch.object(m.os,name,value,create=True);patch.start();self.addCleanup(patch.stop)
        if not hasattr(os,'pread'):
            def pread(fd,count,offset):
                prior=os.lseek(fd,0,os.SEEK_CUR)
                try: os.lseek(fd,offset,os.SEEK_SET);return os.read(fd,count)
                finally:os.lseek(fd,prior,os.SEEK_SET)
            patch=mock.patch.object(m.os,'pread',pread,create=True);patch.start();self.addCleanup(patch.stop)
        for name,value in (('major',lambda dev:0),('minor',lambda dev:dev)):
            if not hasattr(os,name):
                patch=mock.patch.object(m.os,name,value,create=True);patch.start();self.addCleanup(patch.stop)

    def test_closed_native_stat_discriminator_and_scoped_model(self):
        with tempfile.TemporaryDirectory() as d:
            path=Path(d)/'owned';path.write_bytes(b'before');path.write_bytes(b'after')
            fd=os.open(path,os.O_RDONLY|getattr(os,'O_BINARY',0))
            try:
                by_path=os.stat(path);by_fd=os.fstat(fd)
                names=('device','inode','size','mtime','ctime','mode')
                comparison=dict(zip(names,(a==b for a,b in zip(m.signature(by_path),m.signature(by_fd)))))
                print(json.dumps({'fixture_only':True,'path_fd_fields_equal':comparison},sort_keys=True))
                self.assertTrue(os.path.samestat(by_path,by_fd))
                with linux_fixture_stats((path,)):
                    self.assertEqual(m.signature(os.stat(path)),m.signature(os.fstat(fd)))
            finally:os.close(fd)
    def test_admission_mismatch_still_rejects_and_finally_closes(self):
        with tempfile.TemporaryDirectory() as d:
            exe=Path(d)/'qemu';lib=Path(d)/'libslirp.so.0';exe.write_bytes(b'QEMU');lib.write_bytes(b'SLIRP')
            ei,li=exe.stat(),lib.stat();identity=(17,ei.st_dev,ei.st_ino,(str(lib),os.major(li.st_dev),os.minor(li.st_dev),li.st_ino))
            held=[]
            with self.assertRaisesRegex(AssertionError,'forced_fixture_assertion'):
                with owned_observer(process=mock.Mock(pid=123),expected_executable=exe,deadline=time.monotonic()+2) as ob,linux_fixture_stats((exe,lib)):
                    with mock.patch.object(ob,'_identity',return_value=identity),mock.patch.object(m,'package',return_value={}),mock.patch.object(ob,'_backing_bracket',side_effect=ValueError('fixture_signature_mismatch')):
                        self.assertFalse(ob.admit());held=list(ob.fds.values())
                        raise AssertionError('forced_fixture_assertion')
            self.assertEqual(len(held),2)
            self.assertTrue(ob.snapshot()['close_confirmed']);self.assertEqual(ob.fds,{})
            for fd in held:
                with self.assertRaises(OSError):os.fstat(fd)
    def test_linux_model_exact_raw_and_resolved_alias_only(self):
        with tempfile.TemporaryDirectory() as d:
            root=Path(d);sub=root/'sub';sub.mkdir();path=root/'owned';path.write_bytes(b'owned')
            outside=root/'outside';outside.write_bytes(b'outside');alias=sub/'..'/'owned';canonical=path.resolve()
            real_open=os.open
            with mock.patch.object(m.os,'open',wraps=real_open) as opened:
                with linux_fixture_stats((alias,),enabled=True):
                    self.assertEqual(os.stat(canonical).st_size,5)
                    self.assertEqual(os.stat(outside).st_size,7)
                self.assertEqual(opened.call_count,1)
                self.assertEqual(Path(opened.call_args.args[0]),canonical)
    def test_combined_nofollow_and_stat_emulation_does_not_recurse(self):
        from types import SimpleNamespace
        with tempfile.TemporaryDirectory() as d:
            path=Path(d)/'owned';path.write_bytes(b'owned')
            lib=Path(d)/'libslirp.so.0';lib.write_bytes(b'library')
            ei,li=path.stat(),lib.stat()
            identity=(17,ei.st_dev,ei.st_ino,(str(lib),os.major(li.st_dev),os.minor(li.st_dev),li.st_ino))
            real_open,real_lstat=os.open,os.lstat;opened=[]
            def recorded_open(*args,**kwargs):
                fd=real_open(*args,**kwargs);opened.append(fd);return fd
            emulated=fixture_nofollow_open(recorded_open,real_lstat)
            with mock.patch.object(m.os,'open',side_effect=emulated),linux_fixture_stats((path,lib),enabled=True):
                self.assertEqual(os.stat(path).st_size,5)
                fd=os.open(path,os.O_RDONLY|getattr(os,'O_BINARY',0))
                try:self.assertEqual(os.fstat(fd).st_size,5)
                finally:os.close(fd)
                forbidden_open=mock.Mock()
                reject=fixture_nofollow_open(forbidden_open,lambda unused:SimpleNamespace(st_mode=stat.S_IFLNK))
                with self.assertRaisesRegex(OSError,'fixture_nofollow'):reject(path,os.O_RDONLY)
                forbidden_open.assert_not_called()
                for drift in (False,True):
                    with owned_observer(process=mock.Mock(pid=123),expected_executable=path,deadline=time.monotonic()+2) as ob:
                        with mock.patch.object(ob,'_identity',return_value=identity),mock.patch.object(m,'package',return_value={}):
                            self.assertTrue(ob.admit())
                            if drift:
                                old_signature=m.signature
                                with mock.patch.object(m,'signature',side_effect=lambda info:(0,)*6 if info.st_ino==li.st_ino else old_signature(info)):
                                    self.assertFalse(ob.recheck_before_stop())
                            else:self.assertTrue(ob.recheck_before_stop())
                    self.assertTrue(ob.snapshot()['close_confirmed']);self.assertEqual(ob.fds,{})
            self.assertGreaterEqual(len(opened),2)
            for fd in opened:
                with self.assertRaises(OSError):os.fstat(fd)
    def test_maps_unique_inode_multiple_segments(self):
        row=b'1000-2000 r-xp 0000 08:02 42 /usr/lib/x86_64-linux-gnu/libslirp.so.0.4.0\n'
        self.assertEqual(m.mapped_slirp(row+row),('/usr/lib/x86_64-linux-gnu/libslirp.so.0.4.0',8,2,42))
        for bad in (b'',row+row.replace(b' 42 ',b' 43 '),row.replace(b'.0.4.0',b'.0.4.0 (deleted)'),row.replace(b' 42 ',b' 0 ')):
            with self.assertRaises(ValueError):m.mapped_slirp(bad)
    def test_proc_stat_comm_parentheses(self):
        self.assertEqual(m.start_time(b'123 (name ) spaces) '+b'S '+b'0 '*18+b'42 '+b'0 '*3),42)
        with self.assertRaises(ValueError):m.start_time(b'bad')
    def test_hash_and_nofollow_bound(self):
        with tempfile.TemporaryDirectory() as d:
            p=Path(d)/'file';p.write_bytes(b'abc');link=Path(d)/'link'
            if os.name!='nt':link.symlink_to(p)
            self.assertEqual(m.bounded_read(p,3,time.monotonic()+1,[]),b'abc')
            with self.assertRaises(ValueError):m.bounded_read(p,2,time.monotonic()+1,[])
            if os.name=='nt':
                with mock.patch.object(m.os,'open',side_effect=OSError):
                    with self.assertRaises(OSError):m.bounded_read(link,3,time.monotonic()+1,[])
            else:
                with self.assertRaises(OSError):m.bounded_read(link,3,time.monotonic()+1,[])
            fd=os.open(p,os.O_RDONLY)
            try:
                sha,md5,sig=m.hash_fd(fd,time.monotonic()+1)
                self.assertEqual(sha,m.hashlib.sha256(b'abc').hexdigest());self.assertEqual(md5,m.hashlib.md5(b'abc').hexdigest())
                with self.assertRaises(TimeoutError):m.hash_fd(fd,time.monotonic()-1)
            finally:os.close(fd)
    def observer(self):
        return m.MappedQemu(process=mock.Mock(pid=10),expected_executable=__file__,deadline=time.monotonic()+10)
    def test_failed_admission_and_no_retry(self):
        ob=self.observer()
        with mock.patch.object(ob,'_identity',side_effect=ValueError):self.assertFalse(ob.admit())
        self.assertFalse(ob.recheck_before_stop());self.assertTrue(ob.close());self.assertTrue(ob.snapshot()['failure'])
    def test_close_uncertainty_one_shot(self):
        ob=self.observer();ob.fds={'qemu':123}
        with mock.patch.object(m.os,'close',side_effect=OSError) as close:
            self.assertFalse(ob.close());self.assertFalse(ob.close());self.assertEqual(close.call_count,1)
        self.assertTrue(ob.snapshot()['failure']);self.assertIn(ob,m.RETAINED_OWNERS)
    def test_pre_stop_change_refuses(self):
        ob=self.observer();ob.facts['admitted']=True;ob.original=(1,2)
        with mock.patch.object(ob,'_identity',return_value=(2,3)):self.assertFalse(ob.recheck_before_stop())
        self.assertFalse(ob.snapshot()['pre_stop_verified'])
    def test_no_raw_path_or_pid_snapshot(self):
        self.assertEqual(set(self.observer().snapshot()),{'schema_version','admitted','pre_stop_verified','close_confirmed','qemu','libslirp','failure','resident_bytes_verified','source_equivalence_verified'})
    def test_package_exact_metadata_and_integrity(self):
        path='/usr/lib/libslirp.so.0';digest='a'*32
        with mock.patch.object(m,'command',side_effect=['libslirp0:amd64: '+path,'libslirp0:amd64\tamd64\t4.7.0-1ubuntu3\tinstalled']),mock.patch.object(Path,'exists',side_effect=[True,False]),mock.patch.object(m,'bounded_read',return_value=(digest+'  '+path[:] .lstrip('/')+'\n').encode()):
            self.assertTrue(m.package(path,'libslirp0',digest,time.monotonic()+1,[],[])['local_integrity_verified'])
        with mock.patch.object(m,'command',return_value='other: '+path):
            with self.assertRaises(ValueError):m.package(path,'libslirp0',digest,time.monotonic()+1,[],[])
    def test_actual_backing_fds_admission_recheck_and_close(self):
        with tempfile.TemporaryDirectory() as d:
            exe=Path(d)/'qemu';lib=Path(d)/'libslirp.so.0';exe.write_bytes(b'QEMU');lib.write_bytes(b'SLIRP')
            ei,li=exe.stat(),lib.stat()
            identity=(17,ei.st_dev,ei.st_ino,(str(lib),os.major(li.st_dev),os.minor(li.st_dev),li.st_ino))
            with owned_observer(process=mock.Mock(pid=123),expected_executable=exe,deadline=time.monotonic()+2) as ob, linux_fixture_stats((exe,lib)):
                def package(path,name,md5,deadline,children,ledger):
                    return {'name':name,'architecture':'amd64','version':'1.0','local_integrity_verified':True}
                with mock.patch.object(ob,'_identity',return_value=identity),mock.patch.object(m,'package',side_effect=package):
                    self.assertTrue(ob.admit());self.assertEqual(len(ob.fds),2)
                    self.assertTrue(ob.recheck_before_stop());self.assertTrue(ob.snapshot()['pre_stop_verified'])
                    self.assertTrue(ob.close());self.assertTrue(ob.close());self.assertEqual(ob.fds,{})
    def test_changed_library_path_blocks_recheck(self):
        with tempfile.TemporaryDirectory() as d:
            exe=Path(d)/'qemu';lib=Path(d)/'libslirp.so.0';exe.write_bytes(b'QEMU');lib.write_bytes(b'SLIRP')
            ei,li=exe.stat(),lib.stat();identity=(17,ei.st_dev,ei.st_ino,(str(lib),os.major(li.st_dev),os.minor(li.st_dev),li.st_ino))
            with owned_observer(process=mock.Mock(pid=123),expected_executable=exe,deadline=time.monotonic()+2) as ob, linux_fixture_stats((exe,lib)):
                with mock.patch.object(ob,'_identity',return_value=identity),mock.patch.object(m,'package',return_value={}):
                    self.assertTrue(ob.admit())
                    # Windows CRT descriptors may deny rename while open; simulate the
                    # changed pathname signature there rather than assuming Linux sharing.
                    if os.name=='nt':
                        old_signature=m.signature
                        with mock.patch.object(m,'signature',side_effect=lambda info: (0,)*6 if info.st_ino==li.st_ino else old_signature(info)):
                            self.assertFalse(ob.recheck_before_stop())
                    else:
                        replacement=Path(d)/'new';replacement.write_bytes(b'EVIL');replacement.replace(lib)
                        self.assertFalse(ob.recheck_before_stop())
                    self.assertTrue(ob.close())
    def test_package_command_bounded_output_and_owned_reap(self):
        for data,valid in ((b'ok\n',True),(b'x'*5000,False)):
            with tempfile.TemporaryFile() as stream:
                stream.write(data);stream.seek(0)
                process=mock.Mock(stdout=stream);process.poll.return_value=0;process.wait.return_value=0
                children=[]
                with mock.patch.object(m.subprocess,'Popen',return_value=process),mock.patch.object(m.select,'select',return_value=([stream],[],[])):
                    if valid:self.assertEqual(m.command(['fixed'],time.monotonic()+2,children),'ok\n')
                    else:
                        with self.assertRaises(ValueError):m.command(['fixed'],time.monotonic()+2,children)
                self.assertTrue(children[0]['stream_closed']);self.assertTrue(stream.closed)
    def test_package_command_timeout_is_reaped(self):
        with tempfile.TemporaryFile() as stream:
            process=mock.Mock(stdout=stream);process.poll.return_value=None;process.wait.return_value=0
            children=[]
            with mock.patch.object(m.subprocess,'Popen',return_value=process),mock.patch.object(m.select,'select',return_value=([],[],[])):
                with self.assertRaises(TimeoutError):m.command(['fixed'],time.monotonic()+2,children)
            process.kill.assert_called_once();process.wait.assert_called_once();self.assertTrue(children[0]['stream_closed'])
    def test_prior_helper_cleanup_uncertainty_sticky(self):
        ob=self.observer();child=mock.Mock();child.poll.return_value=0
        record=m.new_process_record();record.update(process=child,stream_closed=True,uncertain=True);ob.children=[record]
        self.assertFalse(ob.close());self.assertTrue(ob.snapshot()['failure'])
    def test_transient_close_error_after_fd_reuse_never_retries(self):
        with tempfile.TemporaryDirectory() as d:
            path=Path(d)/'input';path.write_bytes(b'data')
            ledger=[];reused=[];real_close=os.close;real_open=os.open
            def close_then_error(fd):
                real_close(fd);reused.append(real_open(path,os.O_RDONLY));raise OSError('after_close')
            with mock.patch.object(m.os,'close',side_effect=close_then_error) as close:
                with self.assertRaises(OSError):m.bounded_read(path,10,time.monotonic()+1,ledger)
                ob=self.observer();ob.transient=ledger
                self.assertFalse(ob.close());self.assertFalse(ob.close());self.assertEqual(close.call_count,1)
            try:self.assertEqual(os.fstat(reused[0]).st_size,4)
            finally:real_close(reused[0])
    def test_spawn_failure_registered_and_cleanup_uncertain(self):
        children=[]
        with mock.patch.object(m.subprocess,'Popen',side_effect=OSError):
            with self.assertRaises(OSError):m.command(['fixed'],time.monotonic()+1,children)
        self.assertEqual(len(children),1);self.assertTrue(children[0]['spawn_attempted'])
        ob=self.observer();ob.children=children;self.assertFalse(ob.close())
    def test_expired_command_never_spawns(self):
        with mock.patch.object(m.subprocess,'Popen') as spawn:
            with self.assertRaises(TimeoutError):m.command(['fixed'],time.monotonic()-1,[])
            spawn.assert_not_called()
    def test_independent_cleanup_after_poll_and_signal_errors(self):
        child=mock.Mock();child.poll.side_effect=[OSError(),0];child.kill.side_effect=OSError();child.wait.return_value=0
        record=m.new_process_record();record.update(process=child,spawn_attempted=True)
        self.assertFalse(m.stop_process(record,time.monotonic()+1));self.assertTrue(record['exit_observed'])
        child.kill.assert_called_once();child.wait.assert_called_once()
        self.assertFalse(m.stop_process(record,time.monotonic()+1));child.kill.assert_called_once()
    def test_wait_error_not_hidden_by_final_exit(self):
        child=mock.Mock();child.poll.side_effect=[None,0];child.wait.side_effect=OSError()
        record=m.new_process_record();record.update(process=child,spawn_attempted=True)
        self.assertFalse(m.stop_process(record,time.monotonic()+1));self.assertTrue(record['exit_observed'])
    def test_mutation_during_package_blocks_admission(self):
        with tempfile.TemporaryDirectory() as d:
            exe=Path(d)/'qemu';lib=Path(d)/'libslirp.so.0';exe.write_bytes(b'QEMU');lib.write_bytes(b'SLIRP')
            ei,li=exe.stat(),lib.stat();identity=(17,ei.st_dev,ei.st_ino,(str(lib),os.major(li.st_dev),os.minor(li.st_dev),li.st_ino))
            with owned_observer(process=mock.Mock(pid=123),expected_executable=exe,deadline=time.monotonic()+2) as ob, linux_fixture_stats((exe,lib)):
                def package(path,*args):
                    if path==str(lib):lib.write_bytes(b'CHANGED')
                    return {}
                with mock.patch.object(ob,'_identity',return_value=identity),mock.patch.object(m,'package',side_effect=package):
                    self.assertFalse(ob.admit());self.assertFalse(ob.snapshot()['admitted']);self.assertTrue(ob.close())
    def test_executable_inode_mismatch_blocks_before_package(self):
        with tempfile.TemporaryDirectory() as d:
            exe=Path(d)/'qemu';exe.write_bytes(b'QEMU');ei=exe.stat()
            with owned_observer(process=mock.Mock(pid=123),expected_executable=exe,deadline=time.monotonic()+2) as ob:
                with mock.patch.object(ob,'_identity',return_value=(17,ei.st_dev,ei.st_ino+1,('/no/library',0,0,1))),mock.patch.object(m,'package') as package:
                    self.assertFalse(ob.admit());package.assert_not_called();self.assertTrue(ob.close())
    def test_identity_live_owned_process_required(self):
        ob=self.observer();ob.process.poll.return_value=0
        self.assertFalse(ob.admit());self.assertFalse(ob.admit());self.assertFalse(ob.snapshot()['admitted'])
    def test_gate_spawn_failure_retains_fresh_work(self):
        with tempfile.TemporaryDirectory() as d:
            owned=Path(d)/'owned';owned.mkdir()
            with mock.patch.object(g.shutil,'which',return_value='/usr/bin/qemu-system-x86_64'),mock.patch.object(g.tempfile,'mkdtemp',return_value=str(owned)),mock.patch.object(g,'load',side_effect=[mock.Mock(),m]),mock.patch.object(g.subprocess,'Popen',side_effect=OSError):
                facts=g.run()
            self.assertFalse(facts['passed']);self.assertFalse(facts['process_exit_observed']);self.assertFalse(facts['cleanup_confirmed']);self.assertTrue(owned.exists());self.assertEqual(g.RETAINED_OWNERS[-1]['root'],owned)
    def test_gate_observer_close_uncertainty_retains_work(self):
        with tempfile.TemporaryDirectory() as d:
            owned=Path(d)/'owned';owned.mkdir()
            process=mock.Mock();process.poll.return_value=0
            control=mock.Mock();control.execute.side_effect=[{'qemu':{'major':8,'minor':2,'micro':2}},{'running':False,'status':'prelaunch'}]
            old=mock.Mock();old.GateQmp.return_value=control
            observer=mock.Mock();observer.admit.return_value=True;observer.recheck_before_stop.return_value=True;observer.close.side_effect=OSError();observer.snapshot.side_effect=OSError()
            with mock.patch.object(g.shutil,'which',return_value='/usr/bin/qemu-system-x86_64'),mock.patch.object(g.tempfile,'mkdtemp',return_value=str(owned)),mock.patch.object(g,'load',side_effect=[old,m]),mock.patch.object(g.subprocess,'Popen',return_value=process),mock.patch.object(m,'MappedQemu',return_value=observer):
                facts=g.run()
            self.assertTrue(facts['process_exit_observed']);self.assertFalse(facts['cleanup_confirmed']);self.assertTrue(owned.exists())
    def test_gate_paused_restricted_no_guest(self):
        args=g.command('/usr/bin/qemu-system-x86_64',Path('/owned'))
        self.assertIn('-S',args);self.assertIn('user,id=vmnet,restrict=on,ipv6=on',args)
        for bad in ('-drive','-kernel','-cdrom','-enable-kvm','hostfwd'):self.assertNotIn(bad,' '.join(args))
        source=(ROOT/'.github/test_windows_n0a_qemu_slirp.py').read_text()
        self.assertNotIn("execute('cont')",source)
        self.assertIn("control.execute('query-status')",source)
        self.assertIn('observer.recheck_before_stop()',source)
    def test_forbidden_mechanisms_absent(self):
        source=(ROOT/'.github/windows_n0a_qemu_slirp.py').read_text()
        for bad in ('ctypes','map_files/','/proc/self/mem','CDLL(','ldd ',"'-V'","'sudo'"):
            self.assertNotIn(bad,source)
if __name__=='__main__':unittest.main()
