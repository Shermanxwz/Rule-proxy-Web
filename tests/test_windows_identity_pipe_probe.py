import copy
import importlib.util
from pathlib import Path
import unittest
import tempfile

PATH=Path(__file__).resolve().parents[1]/'.github/windows_identity_pipe_probe.py'
SPEC=importlib.util.spec_from_file_location('identity_pipe_probe',PATH)
pipe=importlib.util.module_from_spec(SPEC); SPEC.loader.exec_module(pipe)
N='a'*32; SID='S-1-15-2-1-2-3-4-5-6-7'

def good():
    return {'actor_sha256':'a'*64,'copied_actor_sha256':'a'*64,'image_verified_before_resume':True,'child_pid':42,'controller_identity':{'sid':'S-1-5-21-1-2-3-1001'},'nonce':N,'derived_sid':SID,'observed_child_sid':SID,'echo_matched':True,'exit_code':0,
            'pipe_eof_observed':True,'actor':{'schemaVersion':1,'pid':42,'tokenUserSid':'S-1-5-21-1-2-3-1001','mode':'actor-pipe','nonce':N,'tokenAppContainerSid':SID,
            'tokenIsAppContainer':True,'tokenElevated':False,'isProcessInJob':True,'queriesSucceeded':True,
            'errors':[],'pipeSucceeded':True,'pipe':{'attempted':True,'inheritanceCleared':True,'nonceMatched':True,'requiresControllerTimeout':True,'bytesRead':32,'bytesWritten':32,'win32Error':0,'failure':None},'tokenCapabilities':[]},
            'cleanup':{'close_uncertain':False,'process_exit_confirmed':True,'job_closed':True,'profile_deleted':True,'handles_closed':True,'owned_aces_removed':True,'job_empty':True,'errors':[]}}

class PipeEvidenceTests(unittest.TestCase):
    def test_complete_passes(self): self.assertTrue(all(pipe.checks(good()).values()))
    def test_empty_fails(self): self.assertFalse(all(pipe.checks({}).values()))
    def test_wrong_sid_fails(self):
        r=good();r['observed_child_sid']=SID+'-8';self.assertFalse(all(pipe.checks(r).values()))
    def test_nonce_replay_fails(self):
        r=good();r['actor']['nonce']='b'*32;self.assertFalse(all(pipe.checks(r).values()))
    def test_transport_missing_or_error_fails(self):
        for key,val in [('echo_matched',False),('exit_code',1),('pipe_eof_observed',False)]:
            r=good();r[key]=val
            with self.subTest(key=key):self.assertFalse(all(pipe.checks(r).values()))
    def test_capability_grant_fails_zero_capability_stage(self):
        r=good();r['actor']['tokenCapabilities']=['S-1-15-3-3'];self.assertFalse(all(pipe.checks(r).values()))
    def test_cleanup_failure_fails(self):
        for key in ('job_closed','profile_deleted','handles_closed','owned_aces_removed','job_empty'):
            r=good();r['cleanup'][key]=False
            with self.subTest(key=key):self.assertFalse(all(pipe.checks(r).values()))
    def test_owned_tree_is_bounded(self):
        with tempfile.TemporaryDirectory() as d:
            root=Path(d)
            for i in range(33): (root/str(i)).write_text('fixture')
            with self.assertRaises(RuntimeError):pipe.owned_paths(root)
    def test_owned_tree_rejects_symlink_before_recursing(self):
        with tempfile.TemporaryDirectory() as d:
            root=Path(d); target=root/'target';target.mkdir()
            try:(root/'alias').symlink_to(target,target_is_directory=True)
            except OSError:self.skipTest('symlink creation unavailable')
            with self.assertRaises(RuntimeError):pipe.owned_paths(root)
    def test_owned_tree_lists_fresh_fixture(self):
        with tempfile.TemporaryDirectory() as d:
            root=Path(d);(root/'inputs').mkdir();(root/'inputs'/'actor').write_text('fixture')
            self.assertEqual(len(pipe.owned_paths(root)),3)
    def test_sid_pointer_accepts_only_bounded_valid_sid(self):
        C=pipe.C; header=C.sizeof(C.c_void_p)
        buf=C.create_string_buffer(header+12)
        C.c_void_p.from_buffer(buf).value=C.addressof(buf)+header
        C.c_ubyte.from_buffer(buf,header).value=1
        C.c_ubyte.from_buffer(buf,header+1).value=1
        self.assertEqual(pipe.checked_sid_pointer(buf,len(buf)),C.addressof(buf)+header)
        for returned in (0,header,len(buf)-1,len(buf)+1):
            with self.subTest(returned=returned),self.assertRaises(RuntimeError):
                pipe.checked_sid_pointer(buf,returned)
        C.c_ubyte.from_buffer(buf,header+1).value=16
        with self.assertRaises(RuntimeError):pipe.checked_sid_pointer(buf,len(buf))
    def test_sid_pointer_rejects_null_or_external_pointer(self):
        C=pipe.C;buf=C.create_string_buffer(32)
        for pointer in (None,C.addressof(buf)-1,C.addressof(buf)+28):
            C.c_void_p.from_buffer(buf).value=pointer
            with self.subTest(pointer=pointer),self.assertRaises(RuntimeError):
                pipe.checked_sid_pointer(buf,len(buf))
    def test_runtime_requires_permission(self):
        class Args: disposable_ci=False;approved_security_test=False
        with self.assertRaises(PermissionError):pipe.run(Args())


class OneShotOwnershipTests(unittest.TestCase):
    def test_close_failure_consumed_before_api_no_retry(self):
        calls=[]
        owner=None
        def fail(handle):
            calls.append(handle)
            self.assertNotIn(handle,owner.pending)
            self.assertIn(handle,owner.attempted)
            raise OSError('fixture')
        owner=pipe.OneShotHandles(fail);owner.add(7)
        with self.assertRaises(OSError):owner.close(7)
        owner.close(7)
        self.assertEqual(calls,[7]);self.assertFalse(owner.confirmed_closed)
        with self.assertRaises(RuntimeError):owner.add(7)
        self.assertTrue(owner.uncertain)

    def test_each_owned_handle_closed_once(self):
        calls=[];owner=pipe.OneShotHandles(calls.append)
        for h in (1,2,3):owner.add(h)
        for h in tuple(owner.pending):owner.close(h);owner.close(h)
        self.assertEqual(sorted(calls),[1,2,3]);self.assertTrue(owner.confirmed_closed)

class SuspendedAdmissionTests(unittest.TestCase):
    def fixture(self, failure=None):
        from types import SimpleNamespace
        events=[];state={'assigned_to_job':False};report={}
        def step(name):
            events.append(name)
            if failure==name:raise RuntimeError('fixture_'+name)
        class API:
            def assign_job(self,job,process):step('assign')
            def verify_image(self,process,path):step('image')
            def verify_job(self,job,process):step('job')
            def resume_thread(self,thread):step('resume')
        owner=pipe.OneShotHandles(lambda handle:step('close'+str(handle)))
        for handle in (101,102,103,104):owner.add(handle)
        def read_sid(process):step('sid');return SID if failure!='sid_mismatch' else SID+'-1'
        def require(seconds,cleanup=False):step('time')
        return API(),SimpleNamespace(hProcess=103,hThread=104),owner,state,report,events,read_sid,require

    def test_actual_helper_single_resume_after_all_checks(self):
        import hashlib
        with tempfile.TemporaryDirectory() as d:
            exe=Path(d)/'actor.exe';exe.write_bytes(b'x'*512)
            digest=hashlib.sha256(exe.read_bytes()).hexdigest()
            api,info,owner,state,report,events,sid,clock=self.fixture()
            pipe.admit_suspended(api,api,info,77,exe,digest,SID,sid,owner,(101,102),clock,state,report)
            self.assertEqual(events,['time','assign','image','job','sid','close101','close102','time','resume','close104'])
            self.assertTrue(state['assigned_to_job']);self.assertTrue(report['image_verified_before_resume'])
            self.assertEqual(report['copied_actor_sha256'],digest)

    def test_assignment_image_job_sid_hash_clock_close_failure_never_resume(self):
        import hashlib
        with tempfile.TemporaryDirectory() as d:
            exe=Path(d)/'actor.exe';exe.write_bytes(b'x'*512)
            digest=hashlib.sha256(exe.read_bytes()).hexdigest()
            for failure in ('time','assign','image','job','sid','sid_mismatch','hash','close101','close102'):
                with self.subTest(failure=failure):
                    api,info,owner,state,report,events,sid,clock=self.fixture(failure)
                    with self.assertRaises((RuntimeError,OSError)):
                        pipe.admit_suspended(api,api,info,77,exe,'0'*64 if failure=='hash' else digest,
                                             SID,sid,owner,(101,102),clock,state,report)
                    self.assertNotIn('resume',events)
                    self.assertEqual(state['assigned_to_job'],failure not in ('time','assign'))
                    if failure.startswith('close'):self.assertTrue(owner.uncertain)

    def test_resume_failure_is_single_attempt_and_cleanup_owns_process(self):
        import hashlib
        with tempfile.TemporaryDirectory() as d:
            exe=Path(d)/'actor.exe';exe.write_bytes(b'x'*512)
            api,info,owner,state,report,events,sid,clock=self.fixture('resume')
            with self.assertRaises(RuntimeError):
                pipe.admit_suspended(api,api,info,77,exe,hashlib.sha256(exe.read_bytes()).hexdigest(),
                                     SID,sid,owner,(101,102),clock,state,report)
            self.assertEqual(events.count('resume'),1)
            self.assertIn(103,owner.pending);self.assertIn(104,owner.pending)
            self.assertTrue(state['assigned_to_job'])

    def test_copied_file_bound_and_hash(self):
        import hashlib
        with tempfile.TemporaryDirectory() as d:
            exe=Path(d)/'actor.exe';exe.write_bytes(b'x'*512)
            digest=hashlib.sha256(exe.read_bytes()).hexdigest()
            self.assertEqual(pipe.verify_copied_actor(exe,digest),digest)
            exe.write_bytes(b'y'*512)
            with self.assertRaises(RuntimeError):pipe.verify_copied_actor(exe,digest)
            exe.write_bytes(b'x'*511)
            with self.assertRaises(RuntimeError):pipe.verify_copied_actor(exe,digest)

class StrictNestedPipeTests(unittest.TestCase):
    def test_every_required_nested_fact_missing_wrong_or_bool_integer_rejected(self):
        value=good()['actor']['pipe']
        for key in value:
            bad=dict(value);bad.pop(key)
            self.assertFalse(pipe.pipe_result_valid(bad),key)
        for key,values in {'attempted':[False,1], 'inheritanceCleared':[False,1],
                           'nonceMatched':[False,1],'requiresControllerTimeout':[False,1],'bytesRead':[31,33,True],
                           'bytesWritten':[31,33,True],'win32Error':[1,False],
                           'failure':['',0,False]}.items():
            for v in values:
                bad=dict(value);bad[key]=v;self.assertFalse(pipe.pipe_result_valid(bad))

    def test_parent_echo_eof_and_image_cleanup_still_required(self):
        for key,val in (('echo_matched',False),('pipe_eof_observed',False),('exit_code',False),
                        ('copied_actor_sha256','b'*64),('image_verified_before_resume',False)):
            report=good();report[key]=val;self.assertFalse(all(pipe.checks(report).values()))
        for key,val in (('close_uncertain',True),('process_exit_confirmed',False)):
            report=good();report['cleanup'][key]=val;self.assertFalse(all(pipe.checks(report).values()))

class OriginalQpcDeadlineTests(unittest.TestCase):
    def fixture(self,now=100000,deadline=220000,frequency=1000):
        spec=importlib.util.spec_from_file_location('pipe_budget_test',PATH.with_name('windows_identity_ordinary_launcher.py'))
        launcher=importlib.util.module_from_spec(spec);spec.loader.exec_module(launcher)
        class API:
            tick=now
            def qpc(self):return self.tick
            def qpc_frequency(self):return 1000
        api=API();budget=launcher.QpcBudget(api,deadline,frequency)
        return api,budget,pipe.ProbePhases(budget,api,frequency)

    def test_original_active_and_cleanup_cutoffs_caps_only_shrink(self):
        api,budget,phase=self.fixture()
        self.assertEqual((phase.active,phase.cleanup),(190000,210000))
        self.assertEqual(phase.require(15),15)
        api.tick=188501
        self.assertEqual(phase.require(15),1.499)
        self.assertEqual(phase.limit(5),190000)
        api.tick=190000
        with self.assertRaises(RuntimeError):phase.require(5)
        self.assertEqual(phase.require(15,True),15)
        api.tick=209999;self.assertEqual(phase.require(5,True),.001)
        api.tick=210000
        with self.assertRaises(RuntimeError):phase.require(5,True)

    def test_phase_captured_once_consumed_time_no_renewal(self):
        api,budget,phase=self.fixture()
        limit=phase.limit(5);self.assertEqual(limit,105000)
        api.tick=104999;self.assertEqual(phase.remaining(limit),1)
        api.tick=105000;self.assertEqual(phase.remaining(limit),0)
        # A late probe may start with no active budget though original D is future.
        api,budget,phase=self.fixture(now=195000)
        with self.assertRaises(RuntimeError):phase.require(15)
        self.assertEqual(phase.require(15,True),15)

    def test_wrong_frequency_expiry_backwards_rejected(self):
        for now,deadline,frequency in ((100000,100000,1000),(100000,220001,1000),(100000,220000,999)):
            with self.assertRaises(RuntimeError):self.fixture(now,deadline,frequency)
        api,budget,phase=self.fixture();api.tick=99999
        with self.assertRaises(RuntimeError):phase.require(5)

    def test_legacy_caps_remain_local_without_original_contract(self):
        ticks=[7.0];phase=pipe.ProbePhases(None,None,None,lambda:ticks[0])
        self.assertEqual(phase.require(15),15)
        limit=phase.limit(5);self.assertEqual(limit,12)
        ticks[0]=11.5;self.assertEqual(phase.remaining(limit),500)
        ticks[0]=12;self.assertEqual(phase.remaining(limit),0)

class SetupAndStopTests(unittest.TestCase):
    def test_owned_setup_failures_remain_journalable_without_spawn(self):
        import hashlib
        import shutil
        for stage in ('save','copy','hash','time_after_copy'):
            with self.subTest(stage=stage),tempfile.TemporaryDirectory() as d:
                parent=Path(d);actor=parent/'source.exe';actor.write_bytes(b'x'*512)
                digest=hashlib.sha256(actor.read_bytes()).hexdigest()
                work=parent/'owned';state={'created':False};calls=[]
                def save(path,value):
                    calls.append('save')
                    if stage=='save':raise OSError('fixture')
                    path.write_bytes(b'{}')
                def copy(src,dst):
                    calls.append('copy')
                    if stage=='copy':raise OSError('fixture')
                    shutil.copyfile(src,dst)
                    if stage=='hash':dst.write_bytes(b'y'*512)
                def require(seconds):
                    calls.append('time')
                    if stage=='time_after_copy' and calls.count('time')==3:raise TimeoutError('fixture')
                with self.assertRaises((OSError,RuntimeError)):
                    pipe.prepare_owned_files(work,work/'inputs',work/'output',actor,work/'inputs/actor.exe',
                                             digest,{},state,save,copy,require)
                self.assertTrue(state['created']);self.assertTrue(work.is_dir())
                self.assertNotIn('spawn',calls)

    def test_pre_setup_expiry_creates_nothing(self):
        with tempfile.TemporaryDirectory() as d:
            work=Path(d)/'owned';state={'created':False}
            def expired(seconds):raise TimeoutError('fixture')
            with self.assertRaises(TimeoutError):
                pipe.prepare_owned_files(work,work/'inputs',work/'output',None,None,None,{},state,None,None,expired)
            self.assertFalse(state['created']);self.assertFalse(work.exists())

    def test_exact_owned_stop_assignment_and_uncertainty(self):
        for assigned in (False,True):
            for problem in (None,'terminate','wait','expired','job'):
                events=[];errors=[]
                class API:
                    def terminate_job(self,job):
                        events.append(('job',job))
                        if problem=='terminate':raise OSError('fixture')
                    def terminate_process(self,process):
                        events.append(('process',process))
                        if problem=='terminate':raise OSError('fixture')
                    def wait_process(self,process,millis):
                        events.append(('wait',process,millis));return 258 if problem=='wait' else 0
                def remaining():
                    if problem=='expired':raise TimeoutError('fixture')
                    return 7
                stopped,empty=pipe.stop_owned_child(API(),12,34,assigned,remaining,
                                                   lambda job:problem!='job',errors)
                self.assertEqual(events[0],('job',34) if assigned else ('process',12))
                self.assertEqual(stopped,problem not in ('wait','expired'))
                self.assertEqual(empty,problem!='job')
                if problem:self.assertTrue(errors)
                # Either uncertainty prevents the run's profile/ACL deletion condition.
                if problem in ('wait','expired','job'):self.assertFalse(stopped and empty)



class BoundedSnapshotTests(unittest.TestCase):
    def test_native_duplicate_constants_invalid_encoding_and_bounds(self):
        import json
        with tempfile.TemporaryDirectory() as d:
            path=Path(d)/'actor.json'
            path.write_bytes(json.dumps(good()['actor']).encode('utf-8'))
            self.assertEqual(pipe.read_actor_report(path),good()['actor'])
            for data in (b'{"pipe":{"nonceMatched":true,"nonceMatched":false}}',
                         b'{"x":NaN}', b'[]',b'\xff',b'{}'+b' '*8191):
                path.write_bytes(data)
                with self.assertRaises((RuntimeError,ValueError)):
                    pipe.read_actor_report(path)

    def test_read_bound_and_size_race_and_close_error_propagate(self):
        class Stream:
            def __init__(self,data,close_error=False):self.data=data;self.close_error=close_error;self.reads=[];self.closes=0
            def read(self,count):self.reads.append(count);return self.data[:count]
            def close(self):
                self.closes+=1
                if self.close_error:raise OSError('fixture_close')
        class PathLike:
            def __init__(self,stream):self.stream=stream
            def open(self,mode):return self.stream
        for data,expected,close_error in ((b'x'*10,None,False),(b'x',2,False),(b'x',1,True)):
            stream=Stream(data,close_error)
            with self.assertRaises((OSError,RuntimeError)):
                pipe.read_bounded_file(PathLike(stream),8,expected)
            self.assertEqual(stream.reads,[9]);self.assertEqual(stream.closes,1)



class CreateBoundaryTests(unittest.TestCase):
    def test_attempted_empty_or_partial_create_preserves_uncertainty_and_ownership(self):
        from types import SimpleNamespace
        for failure in ('return_empty','raise_empty','raise_partial'):
            state={'creation_attempted':False};info=SimpleNamespace(hProcess=None,hThread=None)
            owner=pipe.OneShotHandles(lambda h:None)
            def create():
                if failure=='raise_partial':info.hProcess=15;info.hThread=16
                if failure!='return_empty':raise OSError('fixture')
                return 0
            def check(ok):
                if not ok:raise OSError('fixture')
            with self.assertRaises(OSError):pipe.create_suspended_owned(create,check,info,owner,state)
            self.assertTrue(state['creation_attempted'])
            if failure=='raise_partial':self.assertEqual(owner.pending,{15,16})
            else:
                stopped,empty=pipe.stop_owned_child(None,None,None,False,None,None,[],attempted=True)
                self.assertFalse(stopped);self.assertTrue(empty)
        stopped,empty=pipe.stop_owned_child(None,None,None,False,None,None,[],attempted=False)
        self.assertTrue(stopped and empty)



class ComposedRunTests(unittest.TestCase):
    """Actual run orchestration with fake Win32 APIs; NOT a Windows execution."""
    def exercise(self, fault=None):
        import ctypes as C
        import hashlib
        import json
        import os
        import sys
        from types import SimpleNamespace
        from unittest import mock
        from ruleproxy import windows_app_process as proc
        spec=importlib.util.spec_from_file_location('composed_pipe_launcher',PATH.with_name('windows_identity_ordinary_launcher.py'))
        launcher=importlib.util.module_from_spec(spec);spec.loader.exec_module(launcher)
        events=[];last_error=[0];pipe_counter=[100];read_count=[0];tick=[100000]
        class Fn:
            def __init__(self,call=lambda *args:1):self.call=call
            def __call__(self,*args):return self.call(*args)
        class DLL:
            def __init__(self):self.functions={}
            def __getattr__(self,name):
                return self.functions.setdefault(name,Fn())
            def put(self,name,call):self.functions[name]=Fn(call)
        k,a,ue=DLL(),DLL(),DLL()
        def profile(name,title,description,caps,count,out):
            events.append('profile_create');out._obj.value=777;return 0
        ue.put('CreateAppContainerProfile',profile)
        ue.put('DeleteAppContainerProfile',lambda name:events.append('profile_delete') or 0)
        a.put('FreeSid',lambda sid:0)
        def sid_text(sid,out):out._obj.value=SID;return 1
        a.put('ConvertSidToStringSidW',sid_text)
        def token(process,access,out):out._obj.value=501;return 1
        a.put('OpenProcessToken',token)
        def token_info(token,kind,buf,size,out):
            out._obj.value=32
            if buf is None:last_error[0]=122;return 0
            pointer=C.addressof(buf)+C.sizeof(C.c_void_p)
            C.c_void_p.from_buffer(buf).value=pointer
            C.c_ubyte.from_address(pointer).value=1;C.c_ubyte.from_address(pointer+1).value=1
            events.append('sid_read');return 1
        a.put('GetTokenInformation',token_info)
        def create_pipe(reader,writer,sa,size):
            pipe_counter[0]+=1;reader._obj.value=pipe_counter[0]
            pipe_counter[0]+=1;writer._obj.value=pipe_counter[0];return 1
        k.put('CreatePipe',create_pipe)
        k.put('SetHandleInformation',lambda handle,mask,flags:events.append(('inherit_clear',handle.value,mask,flags)) or 1)
        def attrs(buf,count,flags,size):size._obj.value=64;return 1
        k.put('InitializeProcThreadAttributeList',attrs)
        def update(attrs,flags,kind,value,size,old,returned):
            if kind==0x20002:events.append(('handle_list',tuple(value._obj)))
            else:events.append(('capabilities',value._obj.CapabilityCount))
            return 1
        k.put('UpdateProcThreadAttribute',update)
        def create_process(exe,cmd,ps,ts,inherit,flags,env,cwd,startup,info):
            events.append(('create',bool(flags & proc._CREATE_SUSPENDED),inherit))
            if fault=='create_empty':return 0
            info._obj.hProcess=301;info._obj.hThread=302;info._obj.dwProcessId=42;return 1
        k.put('CreateProcessW',create_process)
        def job_info(job,kind,info,size,returned):
            info._obj.active=0;returned._obj.value=size;return 1
        k.put('QueryInformationJobObject',job_info)
        def write(handle,payload,length,out,overlapped):
            events.append(('write',length));out._obj.value=length;return 1
        k.put('WriteFile',write)
        def peek(handle,buf,length,read,available,left):available._obj.value=32;return 1
        k.put('PeekNamedPipe',peek)
        def read(handle,buf,length,out,overlapped):
            read_count[0]+=1
            if read_count[0]==1:
                C.memmove(buf,N.encode(),32);out._obj.value=32;events.append('echo');return 1
            out._obj.value=0;last_error[0]=109;events.append('eof');return 0
        k.put('ReadFile',read)
        class API:
            kernel=k;advapi=a
            def _check(self,ok):
                if not ok:raise OSError('fake_native_failure')
            def close_handle(self,handle):
                events.append(('close',handle))
                if fault=='late_close' and handle==201:tick[0]=210000
            def create_job(self):events.append('job_create');return 201
            def configure_job(self,job,flags):events.append('job_configure')
            def assign_job(self,job,process):events.append('job_assign')
            def resume_thread(self,thread):
                events.append('resume')
                report=good()['actor']
                (work/'output/actor.json').write_bytes(json.dumps(report).encode('utf-8'))
            def terminate_job(self,job):events.append('terminate_job')
            def terminate_process(self,process):events.append('terminate_process')
            def wait_process(self,process,millis):
                events.append(('wait',process,millis))
                if fault=='late_wait':tick[0]+=5001
                return 0
            def exit_code(self,process):return 0
        class TokenAPI:
            def qpc_frequency(self):return 1000
            def qpc(self):return tick[0]
            def current_token(self):return 601
            def close(self,handle):events.append(('close',handle))
            def compartment(self):return 1
            def identity(self,handle):
                return dict(sid=good()['controller_identity']['sid'],session_id=1,token_type=1,
                            elevation_type=1,elevated=False,integrity_rid=8192,admin_attributes=None,
                            appcontainer=False,appcontainer_sid=None,capability_count=0,ui_access=False)
            def verify_image(self,process,expected):
                events.append('image')
                if fault=='image':raise RuntimeError('fake_image')
            def verify_job(self,job,process):events.append('job_verify')
        class Loader:
            def create_module(self,spec):return None
            def exec_module(self,module):
                module.NativeAPI=TokenAPI;module.QpcBudget=launcher.QpcBudget
                module.token_is_ordinary=launcher.token_is_ordinary
        original_spec=importlib.util.spec_from_file_location
        def token_spec(name,path):
            if name=='identity_pipe_token_reader':return importlib.util.spec_from_loader(name,Loader())
            return original_spec(name,path)
        def acl_readback(*args):
            if fault=='acl_readback_raise':raise OSError('fake_acl_readback')
            return fault!='acl_readback_false'
        with tempfile.TemporaryDirectory() as directory:
            root=Path(directory);actor=root/'source.exe';actor.write_bytes(b'x'*512);work=root/'owned'
            digest=hashlib.sha256(actor.read_bytes()).hexdigest()
            args=SimpleNamespace(disposable_ci=True,approved_security_test=True,actor=actor,
                                 work=work,report=work/'report.json',actor_sha256=digest,
                                 deadline_qpc=220000,qpc_frequency=1000,case_nonce=N)
            fake_os=SimpleNamespace(**os.__dict__);fake_os.name='nt'
            fake_os.environ={'SystemRoot':str(root/'Windows')}
            before_path=list(sys.path)
            with mock.patch.object(pipe,'os',fake_os),mock.patch.object(proc,'_KernelAPI',API), \
                 mock.patch.object(C,'WinDLL',lambda name,**kw:ue if name=='userenv' else a if name=='advapi32' else k,create=True), \
                 mock.patch.object(C,'get_last_error',lambda:last_error[0],create=True), \
                 mock.patch.object(C,'set_last_error',lambda value:last_error.__setitem__(0,value),create=True), \
                 mock.patch.object(pipe.importlib.util,'spec_from_file_location',token_spec), \
                 mock.patch.object(pipe.subprocess,'run',lambda *args,**kwargs:events.append('icacls')), \
                 mock.patch.object(pipe,'verify_no_owned_ace',acl_readback):
                try:code=pipe.run(args)
                finally:sys.path[:]=before_path
            result=json.loads((work/'report.json').read_bytes())
        return code,result,events

    def test_actual_run_success_and_exact_pipe_ownership_order(self):
        code,result,events=self.exercise()
        self.assertEqual(code,0);self.assertTrue(result['stage0b_passed'])
        self.assertEqual(result['deadline_qpc'],220000);self.assertEqual(result['qpc_frequency'],1000)
        self.assertIn(('handle_list',(101,104)),events)
        self.assertIn(('inherit_clear',102,1,0),events);self.assertIn(('inherit_clear',103,1,0),events)
        self.assertIn(('capabilities',0),events)
        self.assertIn(('create',True,True),events)
        self.assertLess(events.index('image'),events.index('sid_read'))
        self.assertLess(events.index('sid_read'),events.index('resume'))
        self.assertLess(events.index('resume'),events.index(('write',32)))
        self.assertLess(events.index('echo'),events.index('eof'))
        closed=[x[1] for x in events if isinstance(x,tuple) and x[0]=='close']
        self.assertEqual(len(closed),len(set(closed)))

    def test_actual_run_acl_readback_uncertain_retains_profile(self):
        for fault in ('acl_readback_false','acl_readback_raise'):
            code,result,events=self.exercise(fault)
            self.assertEqual(code,1)
            self.assertNotIn('profile_delete',events)
            self.assertTrue(result['cleanup']['profile_retained_due_to_uncertain_acl_cleanup'])
            self.assertTrue(result['cleanup']['process_exit_confirmed'])
            self.assertFalse(result['stage0b_passed'])

    def test_actual_run_pre_resume_image_failure(self):
        code,result,events=self.exercise('image')
        self.assertEqual(code,1);self.assertNotIn('resume',events)
        self.assertIn('terminate_job',events);self.assertFalse(result['stage0b_passed'])

    def test_actual_run_late_successful_operations_cannot_pass(self):
        for fault in ('late_wait','late_close'):
            code,result,events=self.exercise(fault)
            self.assertEqual(code,1)
            self.assertFalse(result['stage0b_passed'])
            self.assertTrue(result['cleanup']['process_exit_confirmed'])
            self.assertTrue(result['cleanup']['errors'] or 'error' in result)

    def test_actual_run_empty_create_retains_profile_and_uncertainty(self):
        code,result,events=self.exercise('create_empty')
        self.assertEqual(code,1);self.assertNotIn('resume',events)
        self.assertNotIn('profile_delete',events)
        self.assertFalse(result['cleanup']['process_exit_confirmed'])
        self.assertTrue(result['cleanup']['profile_retained_due_to_uncertain_process_exit'])

if __name__=='__main__':unittest.main()
