"""Pure mocked two-process ownership; never creates a native process or pipe."""
import copy
import hashlib
import importlib.util
import json
from pathlib import Path
from types import SimpleNamespace
import tempfile
import unittest
from unittest import mock

ROOT=Path(__file__).resolve().parents[1]
spec=importlib.util.spec_from_file_location('proxy_pipe_probe_test',ROOT/'.github/windows_identity_proxy_pipe_probe.py')
p=importlib.util.module_from_spec(spec);spec.loader.exec_module(p)


def identity():
    return {'sid':'S-1-5-21-1-2-3-1001','session_id':1,'token_type':1,'elevated':True,
            'appcontainer':False,'appcontainer_sid':None,'capability_count':0}


def native_report(command,pid,kind='success'):
    _,role,run,case,report,read,write,start,freq,end,sid,ac,elevated=command
    front=role=='pipe-front';success=kind=='success'
    own=7 if front else 56
    return {'schema_version':1,'stage':'bridge-pipe-test','role':role,'run_id':run,'case_id':case,'pid':pid,
      'identity':{'schemaVersion':1,'mode':'actor','nonce':run,'pid':pid,'tokenUserSid':sid,
        'tokenIsAppContainer':False,'tokenAppContainerSid':None,'tokenElevated':elevated=='1','isProcessInJob':True,
        'tokenCapabilities':[],'queriesSucceeded':True,'errors':[]},
      'qpc':[int(freq),int(start),int(end),int(start)+1],
      'pipe':{'read_bytes':(96 if front else 144) if success else (48 if front else 0),
        'write_bytes':(144 if front else 96) if success else (0 if front else 48),
        'read_frames':(2 if front else 3) if success else 0,
        'write_frames':(3 if front else 2) if success else (0 if front else 1),
        'inheritance_cleared':True,'eof_observed':success,'reader_close':'confirmed','writer_close':'confirmed',
        'requires_controller_timeout':True},
      'core':{'failure':0 if success or not front else 2,'observations':(177 if front else 78) if success else 0,
              'requested':own if success or front else 0,'confirmed':own if success else (3 if front else 0),'uncertain':0},
      'synthetic_http':{'request_checked':success,'response_checked':success,'client_sink_checked':front and success},
      'failure':None if success else ('core' if front else 'pipe_read'),'win32_error':109 if not success and not front else None,
      'network_tested':False,'proxy_tested':False,'product_acceptance':False}


class FakeAPI:
    def __init__(self,fault=None):
        self.now=1000;self.number=100;self.fault=fault;self.log=[];self.processes={};self.jobs={};self.closes={};self.created=0
    def handle(self):self.number+=1;return self.number
    def qpc_frequency(self):return 1000
    def qpc(self):return self.now
    def close(self,h):
        self.log.append(('close',h));self.closes[h]=self.closes.get(h,0)+1
        if self.fault=='parent_close' and h in getattr(self,'data',[]):raise OSError('PRIVATE path')
        if self.fault=='process_close' and h in self.processes:raise OSError('PRIVATE')
    def identity_owned(self,owners,process=None):
        token=self.handle();owners.add(token)
        out=identity()
        if self.fault=='identity' and process is not None:out['sid']='S-1-5-21-99'
        return out
    def owned_job(self,owners):
        job=self.handle();owners.add(job);self.jobs[job]=[];self.log.append(('job',job))
        if self.fault=='job_setup':raise OSError('PRIVATE')
        return job
    def owned_pipe(self,owners):
        a,b=self.handle(),self.handle();owners.add(a);owners.add(b)
        self.data=getattr(self,'data',[])+[a,b];self.log.append(('pipe',a,b))
        if self.fault=='pipe_setup':raise OSError('PRIVATE')
        return a,b
    def process_info(self):return SimpleNamespace(hProcess=None,hThread=None,dwProcessId=0)
    def owned_create(self,info,command,work,handles,owners,state):
        self.created+=1;self.log.append(('create',tuple(handles),tuple(command)))
        def create():
            if self.fault=='create_no_handle' and self.created==2:raise OSError('PRIVATE')
            info.hProcess=self.handle();info.hThread=self.handle();info.dwProcessId=info.hProcess+1000
            self.processes[info.hProcess]={'info':info,'command':command,'exited':False,'code':None,'resumed':False,'job':None}
            if self.fault=='create_partial' and self.created==2:raise OSError('PRIVATE')
            return True
        p.pipe_helpers.create_suspended_owned(create,lambda value:None,info,owners,state)
    def assign_job(self,job,process):
        self.log.append(('assign',job,process))
        if self.fault=='assign' and self.created==2:raise OSError('PRIVATE')
        self.jobs[job].append(process);self.processes[process]['job']=job
    def verify_job(self,job,process):
        if self.fault=='job_verify':raise OSError('PRIVATE')
        assert process in self.jobs[job]
    def verify_image(self,process,path):
        if self.fault=='image':raise OSError('PRIVATE')
    def resume(self,thread):
        self.log.append(('resume',thread))
        if self.fault=='resume':raise OSError('PRIVATE')
        row=next(x for x in self.processes.values() if x['info'].hThread==thread);row['resumed']=True
        peers=[self.processes[x] for x in self.jobs[row['job']]]
        if len(peers)==2 and all(x['resumed'] for x in peers):
            mismatch=peers[0]['command'][3]!=peers[1]['command'][3]
            for item in peers:
                item['exited']=True;item['code']=5 if mismatch else 0
                value=native_report(item['command'],item['info'].dwProcessId,'mismatch' if mismatch else 'success')
                if self.fault=='report_pid':value['pid']+=1
                if self.fault=='report_identity':value['identity']['tokenElevated']=False
                if self.fault!='report_missing':Path(item['command'][4]).write_text(json.dumps(value),encoding='utf-8')
    def wait(self,process,ms):
        self.log.append(('wait',process,ms))
        if self.fault=='wait':raise OSError('PRIVATE')
        row=self.processes[process]
        if not row['exited']:self.now+=ms
        if self.fault=='late_wait':self.now+=10000
        return row['exited']
    def exit_code(self,process):return self.processes[process]['code']
    def terminate_job(self,job):
        self.log.append(('stop_job',job))
        if self.fault=='terminate':raise OSError('PRIVATE')
        for process in self.jobs[job]:self.processes[process].update(exited=True,code=1)
    def terminate_process(self,process):self.log.append(('stop_process',process));self.processes[process].update(exited=True,code=1)
    def job_empty(self,job):
        if self.fault=='job_nonempty':return False
        return all(self.processes[x]['exited'] for x in self.jobs[job])
    def sleep_ms(self,ms):self.now+=ms


class ControllerTests(unittest.TestCase):
    def exercise(self,fault=None):
        with tempfile.TemporaryDirectory() as tmp:
            root=Path(tmp).resolve();actor=root/'actor.exe';actor.write_bytes(b'MZ'+b'x'*510)
            digest=hashlib.sha256(actor.read_bytes()).hexdigest();api=FakeAPI(fault)
            identifiers=iter(format(i,'032x') for i in range(1,5))
            result=p.run_suite(api,actor,None,None,root/'suite',ids=lambda n:next(identifiers),
                               artifact_verifier=lambda *a:(actor,digest))
            private=(root/'suite/private.json').read_bytes() if (root/'suite/private.json').exists() else b''
            self.assertLessEqual(len(private),p.MAX_PRIVATE)
            self.assertNotIn(identity()['sid'],json.dumps(result));self.assertNotIn('a'*32,json.dumps(result))
            self.assertNotIn(str(root),json.dumps(result));self.assertNotIn('PRIVATE',json.dumps(result))
            return result,api
    def test_actual_controller_composition_all_three_fake_cases(self):
        result,api=self.exercise()
        self.assertTrue(result['suite_complete']);self.assertTrue(result['cleanup_confirmed'])
        self.assertEqual([x['reports_bound'] for x in result['cases']],[3,3,0])
        self.assertTrue(result['cases'][2]['watchdog_stop'])
        self.assertEqual(api.created,6);self.assertLess(api.now,61000)
        self.assertTrue(all(n==1 for n in api.closes.values()))
        # Both create/assign/identity complete and all four parent ends closed before resume.
        for index,row in enumerate(api.log):
            if row[0]=='resume':
                prior=api.log[:index];self.assertGreaterEqual(sum(x[0]=='create' for x in prior),2)
                self.assertGreaterEqual(sum(x[0]=='close' and x[1] in api.data for x in prior),4)
    def test_partial_setup_and_no_handle_uncertainty(self):
        for fault in ('job_setup','pipe_setup','create_partial','create_no_handle','assign','job_verify','image','identity','resume','parent_close'):
            with self.subTest(fault=fault):
                result,api=self.exercise(fault)
                self.assertFalse(result['suite_complete']);self.assertTrue(all(n==1 for n in api.closes.values()))
                if fault in ('create_no_handle','parent_close'):
                    self.assertFalse(result['cases'][0]['cleanup_confirmed']);self.assertFalse(result['cases'][1]['admitted'])
                if fault!='resume':self.assertEqual(result['cases'][0]['resumed'],0)
                if fault=='create_partial':self.assertTrue(any(x[0]=='stop_process' for x in api.log))
    def test_cleanup_exit_and_job_empty_are_independent(self):
        for fault in ('wait','job_nonempty','process_close','terminate','late_wait'):
            with self.subTest(fault=fault):
                result,api=self.exercise(fault)
                self.assertFalse(result['suite_complete'])
                self.assertTrue(all(n==1 for n in api.closes.values()))
                self.assertLessEqual(api.now,81000) # fake synchronous late call is observed, never a hard interrupt claim
    def test_report_failure_cannot_erase_earlier_pipe_observation(self):
        for fault in ('report_pid','report_identity','report_missing'):
            result,api=self.exercise(fault);self.assertFalse(result['suite_complete'])
            self.assertEqual(result['cases'][0]['reports_bound'],0)
        result,api=self.exercise('process_close')
        self.assertFalse(result['suite_complete']);self.assertEqual(result['cases'][0]['observations'],[177,78])
        self.assertEqual(result['cases'][0]['reports_bound'],3)
    def test_hosted_elevation_not_ordinary_and_no_network(self):
        result,_=self.exercise();self.assertTrue(result['controller_elevated'])
        for name in ('network_tested','proxy_tested','product_acceptance'):self.assertFalse(result[name])
        self.assertTrue(result['synthetic_http_only'])


class ReportTests(unittest.TestCase):
    def candidate(self):
        command=['actor','pipe-front','a'*32,'b'*32,'private','1','2','1000','1000','11000',identity()['sid'],'none','1']
        return native_report(command,42)
    def validate(self,value):
        return p.validate_native(value,role='pipe-front',run_id='a'*32,case_id='b'*32,pid=42,
            identity=identity(),frequency=1000,start=1000,end=11000)
    def test_strict_native_report_shape_binding_and_bounds(self):
        value=self.candidate();self.assertTrue(p.successful_native(self.validate(value)))
        for key,bad in [('schema_version',True),('pid',True),('run_id','c'*32),('case_id','a'*32),('role','pipe-relay'),('extra',0)]:
            changed=copy.deepcopy(value);changed[key]=bad
            with self.assertRaises(ValueError):self.validate(changed)
        for key,bad in [('read_bytes',98),('write_frames',True),('reader_close','raw'),('requires_controller_timeout',False)]:
            changed=copy.deepcopy(value);changed['pipe'][key]=bad
            with self.assertRaises(ValueError):self.validate(changed)
        for key,bad in [('observations',255),('failure',True),('confirmed',56),('uncertain',1)]:
            changed=copy.deepcopy(value);changed['core'][key]=bad
            with self.assertRaises(ValueError):self.validate(changed)
        changed=copy.deepcopy(value);changed['qpc'][3]=0;changed['failure']='qpc'
        self.assertEqual(self.validate(changed)['qpc'][3],0);self.assertFalse(p.successful_native(changed))
    def test_bounded_duplicate_free_utf8_report_reader(self):
        with tempfile.TemporaryDirectory() as tmp:
            root=Path(tmp).resolve();path=root/'report.json'
            for raw in (b'{"x":1,"x":2}',b'{"x":NaN}',b'{} trailing','{}'.encode('utf-16'),b'x'*8193):
                path.write_bytes(raw)
                with self.assertRaises((ValueError,RuntimeError,UnicodeError)):p.bounded_json(path,8192,inside=root)
            path.write_bytes(b'{}');self.assertEqual(p.bounded_json(path,8192,inside=root)[0],{})
    def test_public_full_pretty_ceiling(self):
        value={'schema_version':1,'stage':'native-proxy-pipe-mechanics','network_tested':False,'proxy_tested':False,
            'product_acceptance':False,'synthetic_http_only':True,'controller_elevated':False,'actor_sha256':'f'*64,
            'cases':[p._case_public(i) for i in range(3)],'suite_complete':False,'cleanup_confirmed':False,'failure':'configuration'}
        for case in value['cases']:
            case.update(created=3,resumed=3,exit_observed=3,identity_verified=3,reports_bound=3,
                observations=[177,78],core_failure=[11,11],failure='configuration')
        self.assertLessEqual(len((json.dumps(value,indent=2)+'\n').encode()),4096)
        self.assertLessEqual(len((json.dumps(self.candidate(),indent=2)+'\n').encode()),8192)


class OwnershipBoundaryTests(unittest.TestCase):
    def test_real_identity_wrapper_keeps_handle_generations_owned(self):
        class Tokens:
            def __init__(self):self.active=set();self.closed=[];self.fail=False
            def token_for_process(self,process):
                token=next(x for x in range(100,200) if x not in self.active)
                self.active.add(token);return token
            def identity(self,token):
                if self.fail:raise OSError('PRIVATE')
                return identity()
            def close(self,token):self.active.remove(token);self.closed.append(token)
        native=Tokens();api=p.WindowsAPI.__new__(p.WindowsAPI);api.native=native
        owners=p.pipe_helpers.OneShotHandles(native.close)
        api.identity_owned(owners,1);api.identity_owned(owners,2)
        self.assertEqual(owners.pending,{100,101});self.assertEqual(native.closed,[])
        native.fail=True
        with self.assertRaises(OSError):api.identity_owned(owners,3)
        self.assertEqual(owners.pending,{100,101,102})
        for token in tuple(owners.pending):owners.close(token)
        self.assertTrue(owners.confirmed_closed);self.assertEqual(len(native.closed),3)

    def test_qpc_invalid_frequency_overflow_and_consumed_setup(self):
        for value in (True,0,1000000001):
            api=FakeAPI();api.qpc_frequency=lambda:value
            with self.assertRaises(ValueError):p.run_suite(api,None,None,None,Path('/unused'))
        api=FakeAPI();api.now=0x7fffffffffffffff
        with self.assertRaises(ValueError):p.run_suite(api,None,None,None,Path('/unused'))
        with tempfile.TemporaryDirectory() as tmp:
            root=Path(tmp).resolve();actor=root/'actor.exe';actor.write_bytes(b'MZ'+b'x'*510)
            h=hashlib.sha256(actor.read_bytes()).hexdigest();api=FakeAPI()
            def delayed(*args):api.now+=31000;return actor,h
            result=p.run_suite(api,actor,None,None,root/'suite',artifact_verifier=delayed)
            self.assertFalse(result['suite_complete']);self.assertEqual(api.created,0)

    def test_capacity_copy_and_identity_before_any_resume(self):
        with mock.patch.object(p.shutil,'disk_usage',return_value=SimpleNamespace(free=1)):
            result,api=ControllerTests().exercise()
        self.assertFalse(result['suite_complete']);self.assertEqual(api.created,0)
        original=p.pipe_helpers.verify_copied_actor;calls=[]
        def changed(*args):
            calls.append(1)
            if len(calls)==3:raise RuntimeError('PRIVATE')
            return original(*args)
        with mock.patch.object(p.pipe_helpers,'verify_copied_actor',side_effect=changed):
            result,api=ControllerTests().exercise()
        self.assertFalse(result['suite_complete']);self.assertEqual(result['cases'][0]['resumed'],0)

    def test_close_reader_uncertainty_sticky_and_no_report_retries(self):
        original=p.bounded_json;calls=[]
        def uncertain(path,*args,**kwargs):
            calls.append(path.name)
            if path.name=='front.json':
                marker=object();p.pipe_helpers._RETAINED_FILES.append(marker)
                raise p.pipe_helpers.FileCloseUncertain('PRIVATE')
            return original(path,*args,**kwargs)
        with mock.patch.object(p,'bounded_json',side_effect=uncertain):result,api=ControllerTests().exercise()
        self.assertFalse(result['cleanup_confirmed']);self.assertFalse(result['cases'][1]['admitted'])
        self.assertEqual(calls.count('front.json'),1)
        self.assertEqual(result['cases'][0]['reports_bound'],2)

    def test_native_reports_both_exit_codes_are_required(self):
        original=FakeAPI.exit_code
        with mock.patch.object(FakeAPI,'exit_code',lambda self,process:3 if self.processes[process]['code']==0 else original(self,process)):
            result,api=ControllerTests().exercise()
        self.assertFalse(result['suite_complete']);self.assertEqual(result['cases'][0]['reports_bound'],3)
        self.assertEqual(result['cases'][0]['observations'],[177,78])

    def test_private_write_late_or_close_failure_downgrades_final_receipt(self):
        original=p.launcher.write_private_bytes
        def late(path,data):
            original(path,data)
            if path.name=='private.json':raise p.launcher.GateFailure('private_report_close_uncertain')
        with mock.patch.object(p.launcher,'write_private_bytes',side_effect=late):result,api=ControllerTests().exercise()
        self.assertFalse(result['suite_complete'])
        self.assertEqual(result['cases'][0]['observations'],[177,78])

    def test_manifest_sources_image_and_digest_all_bound(self):
        with tempfile.TemporaryDirectory() as tmp:
            root=Path(tmp).resolve();actor=root/'windows_identity_proxy_pipe_actor.exe';actor.write_bytes(b'MZ'+b'x'*510)
            manifest=root/'identity-proxy-pipe-manifest.json'
            value={'schemaVersion':1,'compileOnly':True,'runtimeAcceptance':False,'executableSha256':hashlib.sha256(actor.read_bytes()).hexdigest()}
            for key,name in (('actorSourceSha256','.github/native/windows_identity_proxy_pipe_actor.cpp'),
                             ('identitySourceSha256','.github/native/windows_identity_actor.cpp'),
                             ('coreSha256','.github/native/windows_identity_proxy_bridge_core.hpp')):
                value[key]=hashlib.sha256((ROOT/name).read_bytes()).hexdigest()
            raw=json.dumps(value).encode();manifest.write_bytes(raw);h=hashlib.sha256(raw).hexdigest()
            self.assertEqual(p.verify_artifact(actor,manifest,h),(actor,value['executableSha256']))
            actor.write_bytes(b'MZ'+b'y'*510)
            with self.assertRaises(RuntimeError):p.verify_artifact(actor,manifest,h)
            with self.assertRaises(ValueError):p.verify_artifact(actor,manifest,'0'*64)


class FinalReceiptTests(unittest.TestCase):
    def test_stdout_only_emit_and_future_owner_boundary(self):
        import io
        result,api=ControllerTests().exercise()
        raw=p.public_bytes(result)
        self.assertTrue(p.accept_public(raw,0,True))
        self.assertTrue(p.accept_public(raw[:-1]+b'\r\n',0,True))
        for body,code,eof in ((raw,1,True),(raw,0,False),(raw[:-1],0,True),
                              (raw+raw,0,True),(raw+b'\n',0,True),(b'{}\n',0,True),
                              (raw.replace(b'"schema_version":1',b'"schema_version":1,"schema_version":1'),0,True)):
            self.assertFalse(p.accept_public(body,code,eof))
        for key,bad in (('created',0),('resumed',0),('reports_bound',0),('observations',[0,0])):
            altered=copy.deepcopy(result);altered['cases'][0][key]=bad
            self.assertFalse(p.accept_public(p.public_bytes(altered),0,True))
        for key,bad in (('observations',[1,0]),('core_failure',[9,None]),('pipe_eof',[True,False]),('native_close',[True,False])):
            altered=copy.deepcopy(result);altered['cases'][2][key]=bad
            self.assertFalse(p.accept_public(p.public_bytes(altered),0,True))
        for failure,observed in ((0,0),(9,2)):
            altered=copy.deepcopy(result);altered['cases'][2].update(reports_bound=1,core_failure=[failure,None],observations=[observed,0])
            self.assertFalse(p.accept_public(p.public_bytes(altered),0,True))
        stream=io.BytesIO();self.assertTrue(p.emit_public(result,stream));self.assertEqual(stream.getvalue(),raw)
        for mode in ('write','partial','flush'):
            class Broken:
                def write(self,data):
                    if mode=='write':raise OSError('PRIVATE')
                    return len(data)-1 if mode=='partial' else len(data)
                def flush(self):raise OSError('PRIVATE')
            self.assertFalse(p.emit_public(result,Broken()))

    def test_final_private_write_late_and_uncertain_close(self):
        original=p.launcher.write_private_bytes
        api_holder=[];original_init=FakeAPI.__init__
        def init(api,*args,**kwargs):original_init(api,*args,**kwargs);api_holder.append(api)
        for mode in ('late','close'):
            def write(path,data):
                original(path,data)
                if path.name=='private.json':
                    if mode=='late':api_holder[-1].now=61000
                    else:
                        p.launcher._RETAINED_PRIVATE_STREAMS.append(object())
                        raise p.launcher.GateFailure('private_report_close_uncertain')
            with mock.patch.object(FakeAPI,'__init__',init),mock.patch.object(p.launcher,'write_private_bytes',side_effect=write):
                result,api=ControllerTests().exercise()
            self.assertFalse(result['suite_complete']);self.assertFalse(p.accept_public(p.public_bytes(result),0,True))
            self.assertEqual(result['cases'][0]['observations'],[177,78])
            if mode=='close':self.assertFalse(result['cleanup_confirmed'])

    def test_conservative_complete_schema_size_witnesses(self):
        # Independent field maxima, not a simultaneously successful native report.
        native=ReportTests().candidate()
        native['pid']=4294967295;native['identity']['pid']=4294967295
        native['identity']['tokenUserSid']='S-1-281474976710655'+('-4294967295'*15)
        native['identity']['tokenElevated']=False
        native['qpc']=[1000000000,9223372036854775807,9223372036854775807,9223372036854775807]
        native['pipe'].update(read_bytes=145,write_bytes=144,read_frames=3,write_frames=3,
            inheritance_cleared=False,eof_observed=False,reader_close='not_attempted',writer_close='not_attempted')
        native['core'].update(failure=11,observations=255,requested=63,confirmed=63,uncertain=63)
        native['synthetic_http']={k:False for k in native['synthetic_http']}
        native.update(failure='configuration',win32_error=4294967295)
        native_size=len((json.dumps(native,indent=2)+'\n').encode())
        aggregate=[{'case':i,'run_id':'f'*32,'case_id':'f'*32,'reports':[
            {'role':role,'sha256':'f'*64,'bytes':8192,'report':copy.deepcopy(native)}
            for role in ('pipe-front','pipe-relay')]} for i in range(3)]
        aggregate_size=len((json.dumps(aggregate,indent=2)+'\n').encode())
        public={'schema_version':1,'stage':'native-proxy-pipe-mechanics','network_tested':False,
            'proxy_tested':False,'product_acceptance':False,'synthetic_http_only':True,
            'controller_elevated':False,'actor_sha256':'f'*64,'cases':[p._case_public(i) for i in range(3)],
            'suite_complete':False,'cleanup_confirmed':False,'failure':'configuration'}
        for case in public['cases']:
            case.update(created=3,resumed=3,exit_observed=3,identity_verified=3,reports_bound=3,
                observations=[255,255],core_failure=[None,None],failure='configuration')
        public_size=len((json.dumps(public,indent=2)+'\n').encode())
        self.assertLessEqual(native_size,8192);self.assertLessEqual(aggregate_size,128*1024)
        self.assertLessEqual(public_size,4096)
        self.assertEqual((native_size,aggregate_size,public_size),(1521,13254,2222))

    def test_no_redundant_public_file(self):
        source=(ROOT/'.github/windows_identity_proxy_pipe_probe.py').read_text()
        self.assertNotIn("root/'public.json'",source)

# Explicit hosted runner only; unittest discovery never launches the controller.
import os
import subprocess
import sys
import threading
import time

OUTER_RETAINED=[]


def drain_controller(pipe,state):
    try:
        while len(state['data'])<4097:
            part=os.read(pipe.fileno(),min(4096,4097-len(state['data'])))
            if not part:state['eof']=True;return
            state['data'].extend(part)
        state['overflow']=True
    except BaseException:state['error']=True
    finally:state['stopped']=True


def cleanup_controller(process,thread,state,cutoff,clock):
    exited=False;code=None;uncertain=False;closed=True;forced=False
    try:
        code=process.poll();exited=type(code) is int
    except BaseException:uncertain=True
    if not exited:
        forced=True
        try:process.kill()
        except BaseException:uncertain=True
    try:
        code2=process.wait(timeout=max(0,cutoff-clock()))
        if type(code2) is int:code=code2;exited=True
    except BaseException:uncertain=True
    try:
        code2=process.poll()
        if type(code2) is int:code=code2;exited=True
    except BaseException:uncertain=True
    stopped=thread is None
    if thread is not None:
        try:thread.join(timeout=max(0,cutoff-clock()))
        except BaseException:uncertain=True
        try:stopped=not thread.is_alive() and state['stopped']
        except BaseException:uncertain=True;stopped=False
    if stopped:
        try:
            if process.stdout is not None:process.stdout.close()
        except BaseException:closed=False;uncertain=True
    else:closed=False
    handle=getattr(process,'_handle',None)
    if handle is not None:
        if exited:
            try:handle.Close()
            except BaseException:closed=False;uncertain=True
        else:closed=False
    if clock()>cutoff:uncertain=True
    cleanup=exited and stopped and closed and not uncertain
    if not cleanup:OUTER_RETAINED.append((process,thread,state))
    return exited,code,stopped,closed,cleanup,forced


def run_hosted(actor,manifest,expected_digest,work,*,clock=time.monotonic,
               process_factory=subprocess.Popen,thread_factory=threading.Thread,
               drainer=drain_controller,sleeper=time.sleep):
    deadline=clock()+65.0
    result={'schema_version':1,'stage':'native-proxy-pipe-owner','mechanics_verified':False,
            'controller_exit_observed':False,'reader_stopped':False,'handles_closed':False,
            'cleanup_confirmed':False,'descendant_cleanup_confirmed':None,'forced_stop':False,
            'controller_receipt':None,'failure':None,'network_tested':False,'proxy_tested':False,
            'product_acceptance':False}
    state={'data':bytearray(),'eof':False,'stopped':False,'error':False,'overflow':False}
    process=None;thread=None;attempted=False;code=None;qualified=False
    def fail(label):
        if result['failure'] is None:result['failure']=label
    try:
        if (any(not Path(x).is_absolute() for x in (actor,manifest,work)) or
                Path(work).exists() or not p.digest(expected_digest)):raise ValueError('configuration')
        if clock()>=deadline:raise ValueError('deadline')
        command=[sys.executable,'-I','-S','-B',str(ROOT/'.github/windows_identity_proxy_pipe_probe.py'),
                 '--run-native-pipe','--actor',str(actor),'--manifest',str(manifest),
                 '--expected-manifest-sha256',expected_digest,'--work',str(work)]
        attempted=True
        process=process_factory(command,stdin=subprocess.DEVNULL,stdout=subprocess.PIPE,
                                stderr=subprocess.DEVNULL,close_fds=True)
        if clock()>=deadline:raise ValueError('deadline')
        thread=thread_factory(target=drainer,args=(process.stdout,state),daemon=True)
        thread.start()
        while True:
            if clock()>=deadline:fail('deadline');break
            code=process.poll()
            if clock()>=deadline:fail('deadline');break
            if state['overflow']:fail('overflow');break
            if state['error']:fail('reader');break
            if type(code) is int and state['stopped']:break
            sleeper(min(.005,max(0,deadline-clock())))
        if result['failure'] is None:
            if p.accept_public(bytes(state['data']),code,state['eof']):
                result['controller_receipt']=json.loads(bytes(state['data']).decode('ascii'))
                qualified=True
            else:fail('receipt')
            if clock()>=deadline:qualified=False;fail('deadline')
    except BaseException as exc:
        label=str(exc) if type(exc) is ValueError and str(exc) in ('configuration','deadline') else (
            'spawn' if attempted and process is None else 'internal')
        fail(label)
    finally:
        cutoff=clock()+5.0
        if process is not None:
            try:
                exited,code,stopped,closed,cleanup,forced=cleanup_controller(process,thread,state,cutoff,clock)
                result.update(controller_exit_observed=exited,reader_stopped=stopped,
                    handles_closed=closed,cleanup_confirmed=cleanup,forced_stop=forced)
            except BaseException:
                OUTER_RETAINED.append((process,thread,state));fail('cleanup')
        elif attempted:OUTER_RETAINED.append(('spawn_uncertain',))
        else:result.update(reader_stopped=True,handles_closed=True,cleanup_confirmed=True)
        if not result['cleanup_confirmed']:fail('cleanup')
    if qualified and not result['forced_stop'] and code==0 and result['cleanup_confirmed'] and result['failure'] is None:
        result['descendant_cleanup_confirmed']=True;result['mechanics_verified']=True
    return result


def hosted_cli(argv):
    import argparse
    parser=argparse.ArgumentParser()
    parser.add_argument('--run-hosted',action='store_true');parser.add_argument('--actor',type=Path,required=True)
    parser.add_argument('--manifest',type=Path,required=True);parser.add_argument('--expected-manifest-sha256',required=True)
    parser.add_argument('--work',type=Path,required=True)
    args=parser.parse_args(argv)
    if not args.run_hosted or os.name!='nt':return 2
    result=run_hosted(args.actor,args.manifest,args.expected_manifest_sha256,args.work)
    try:
        raw=(json.dumps(result,separators=(',',':'))+'\n').encode('ascii')
        if len(raw)>4096:return 1
        if sys.stdout.buffer.write(raw)!=len(raw):return 1
        sys.stdout.buffer.flush()
    except BaseException:return 1
    return 0 if result['mechanics_verified'] else 1

class OuterOwnerTests(unittest.TestCase):
    class Clock:
        def __init__(self):self.now=0.0
        def __call__(self):return self.now
        def sleep(self,x):self.now+=x
    class Pipe:
        def __init__(self,mode):self.mode=mode;self.closes=0
        def close(self):
            self.closes+=1
            if self.mode=='close':raise OSError('PRIVATE')
    class Process:
        def __init__(self,mode,clock):
            self.mode=mode;self.clock=clock;self.stdout=OuterOwnerTests.Pipe(mode);self.calls=[];self.killed=False
            if mode=='handle':self._handle=SimpleNamespace(Close=lambda:(_ for _ in ()).throw(OSError('PRIVATE')))
        def poll(self):
            self.calls.append('poll')
            if self.mode=='poll':raise OSError('PRIVATE')
            if self.mode=='late':self.clock.now=66
            if self.mode in ('timeout','kill','wait','unknown') and not self.killed:return None
            return 1 if self.mode=='badexit' else 0
        def kill(self):
            self.calls.append('kill')
            if self.mode=='kill':raise OSError('PRIVATE')
            if self.mode!='unknown':self.killed=True
        def wait(self,timeout):
            self.calls.append('wait')
            if self.mode in ('wait','unknown'):raise subprocess.TimeoutExpired('PRIVATE',timeout)
            if self.mode=='late_wait':self.clock.now+=6
            return 1 if self.mode=='badexit' else 0
    class Thread:
        def __init__(self,*,target,args,daemon):self.target=target;self.args=args;self.alive=False
        def start(self):self.target(*self.args)
        def join(self,timeout):pass
        def is_alive(self):return self.alive
    def exercise(self,mode='ok',*,eof=True,overflow=False,error=False,data=None,thread_factory=None):
        result,_=ControllerTests().exercise();raw=p.public_bytes(result) if data is None else data
        clock=self.Clock();process=self.Process(mode,clock);commands=[]
        def spawn(command,**kwargs):
            commands.append((command,kwargs))
            if mode=='spawn':raise OSError('PRIVATE')
            if mode=='late_spawn':clock.now=66
            return process
        def drain(pipe,state):state.update(data=bytearray(raw),eof=eof,overflow=overflow,error=error,stopped=True)
        with tempfile.TemporaryDirectory() as tmp:
            root=Path(tmp).resolve()
            result=run_hosted(root/'actor.exe',root/'manifest.json','a'*64,root/'fresh',
                clock=clock,process_factory=spawn,thread_factory=thread_factory or self.Thread,drainer=drain,sleeper=clock.sleep)
        self.assertNotIn('PRIVATE',json.dumps(result));self.assertLessEqual(len(p.public_bytes(result)),4096)
        self.assertEqual(commands[0][0][1:4],['-I','-S','-B'])
        self.assertEqual(commands[0][1]['stderr'],subprocess.DEVNULL)
        return result,process,clock
    def test_closed_success_no_actual_native_execution(self):
        result,process,clock=self.exercise()
        self.assertTrue(result['mechanics_verified']);self.assertTrue(result['descendant_cleanup_confirmed'])
        self.assertEqual(process.stdout.closes,1);self.assertNotIn('kill',process.calls)
    def test_all_faults_withhold_descendant_cleanup(self):
        for mode,kw in [('spawn',{}),('timeout',{}),('kill',{}),('wait',{}),('unknown',{}),
                        ('poll',{}),('close',{}),('handle',{}),('late',{}),('late_spawn',{}),('late_wait',{}),
                        ('badexit',{}),('ok',{'eof':False}),('ok',{'overflow':True}),
                        ('ok',{'error':True}),('ok',{'data':b'{'}),('ok',{'data':b'x'*4097})]:
            with self.subTest(mode=mode,kw=kw):
                result,process,clock=self.exercise(mode,**kw)
                self.assertFalse(result['mechanics_verified']);self.assertIsNone(result['descendant_cleanup_confirmed'])
                self.assertLessEqual(process.stdout.closes,1)
                if mode in ('timeout','kill','wait','unknown'):self.assertTrue(result['forced_stop'])
    def test_reader_start_failure_and_blocked_reader_retained(self):
        for mode in ('start','blocked'):
            class Reader(self.Thread):
                def start(self):
                    if mode=='start':raise RuntimeError('PRIVATE')
                    self.alive=True
            before=len(OUTER_RETAINED)
            result,process,clock=self.exercise(thread_factory=Reader)
            self.assertFalse(result['cleanup_confirmed']);self.assertFalse(result['mechanics_verified'])
            self.assertEqual(process.stdout.closes,0);self.assertGreater(len(OUTER_RETAINED),before)
    def test_complete_outer_serialization_ceiling(self):
        result,_,_=self.exercise()
        result.update(mechanics_verified=False,controller_exit_observed=False,reader_stopped=False,
            handles_closed=False,cleanup_confirmed=False,descendant_cleanup_confirmed=None,
            forced_stop=False,failure='configuration')
        child=result['controller_receipt'];child.update(controller_elevated=False,suite_complete=False,
            cleanup_confirmed=False,failure='configuration')
        for case in child['cases']:
            for key,value in list(case.items()):
                if type(value) is bool:case[key]=False
            case.update(observations=[255,255],core_failure=[None,None],pipe_eof=[False,False],
                        native_close=[False,False],failure='configuration')
        pretty=len((json.dumps(result,indent=2)+'\n').encode('ascii'))
        compact=len((json.dumps(result,separators=(',',':'))+'\n').encode('ascii'))
        self.assertLessEqual(pretty,4096);self.assertLessEqual(compact,4096)
        self.assertEqual((compact,pretty),(1793,2854))

    def test_isolated_import_only_and_bounded_stdout_composition(self):
        # Root-approved Python-only loader check: never controller.main/NativeAPI.
        receipt,_=ControllerTests().exercise();raw=p.public_bytes(receipt)
        script=("import importlib.util,sys; p=sys.argv[1]; "
                "s=importlib.util.spec_from_file_location('isolated_pipe_controller',p); "
                "m=importlib.util.module_from_spec(s); s.loader.exec_module(m); "
                "assert m.MAX_PUBLIC==4096; sys.stdout.buffer.write(bytes.fromhex(sys.argv[2])); sys.stdout.buffer.flush()")
        commands=[]
        def import_only(command,**kwargs):
            actual=[sys.executable,'-I','-S','-B','-c',script,
                    str(ROOT/'.github/windows_identity_proxy_pipe_probe.py'),raw.hex()]
            commands.append(actual)
            return subprocess.Popen(actual,**kwargs)
        with tempfile.TemporaryDirectory() as tmp:
            result=run_hosted(Path(tmp)/'actor.exe',Path(tmp)/'manifest.json','a'*64,Path(tmp)/'fresh',
                              process_factory=import_only)
        self.assertTrue(result['mechanics_verified']) # Synthetic receipt plumbing only.
        self.assertEqual(commands[0][1:4],['-I','-S','-B'])
        self.assertNotIn('--run-native-pipe',commands[0]);self.assertNotIn('NativeAPI(',script)

    def test_actual_bounded_drainer_overflow_eof_and_error(self):
        for chunks,expected in (([b'x'*4096,b'y'],'overflow'),([b'abc',b''],'eof'),([OSError('PRIVATE')],'error')):
            state={'data':bytearray(),'eof':False,'stopped':False,'error':False,'overflow':False}
            def read(fd,limit):
                item=chunks.pop(0)
                if isinstance(item,Exception):raise item
                self.assertLessEqual(len(item),limit);return item
            with mock.patch.object(os,'read',side_effect=read):drain_controller(SimpleNamespace(fileno=lambda:7),state)
            self.assertTrue(state[expected]);self.assertTrue(state['stopped']);self.assertLessEqual(len(state['data']),4097)


class PipeWorkflowTests(unittest.TestCase):
    def test_exclusive_dedicated_gate_and_bounded_owner_only(self):
        text=(ROOT/'.github/workflows/windows-identity-proxy-pipe-gates.yml').read_text()
        self.assertEqual(text.count('    if: ${{'),2)
        self.assertIn('timeout-minutes: 5',text);self.assertIn('timeout-minutes: 8',text)
        self.assertEqual(text.count("github.event_name == 'push'"),2)
        self.assertEqual(text.count("github.ref == 'refs/heads/dot/windows-isolation-proof'"),2)
        excluded=json.loads(text.split('  EXCLUDED_MARKERS: >-\n    ',1)[1].split('\n',1)[0])
        self.assertEqual(len(excluded),26);self.assertEqual(len(set(excluded)),26)
        for marker in excluded:
            self.assertEqual(text.count("!contains(github.event.head_commit.message, '"+marker+"')"),2)
        self.assertEqual(text.count("m.count('[identity-proxy-pipe-gates]')==1"),2)
        self.assertEqual(text.count('--run-hosted --actor'),1);self.assertNotIn('--run-native-pipe',text)
        self.assertIn("pathlib.Path(os.environ['RUNNER_TEMP']).resolve(strict=True)",text)
        self.assertNotIn('Join-Path $env:RUNNER_TEMP',text)
        self.assertEqual(text.count('sum(counts[:3])==63'),2)
        self.assertEqual(text.count('result.wasSuccessful() and not result.skipped'),2)
        self.assertEqual(text.count('persist-credentials: false'),2)
        self.assertEqual(text.count('ref: ${{ github.sha }}'),2)
        for name in ('test_windows_identity_proxy_bridge_codec.py','test_windows_identity_proxy_bridge_model.py',
                     'test_windows_identity_proxy_bridge_native.py','test_windows_identity_proxy_pipe_probe.py'):
            self.assertGreaterEqual(text.count(name),3)
        for forbidden in ('upload-artifact','download-artifact','workflow_dispatch:','schedule:',
                          'continue-on-error','qemu-system','pip install'):
            self.assertNotIn(forbidden,text)
        self.assertLess(text.index('Verify pins and required pure bridge and pipe suites'),text.index('Explicit bounded hosted pipe suite once'))

def ordinary_identity():
    return dict(identity(),elevated=False,elevation_type=1,integrity_rid=8192,admin_attributes=None,ui_access=False)


class FakeACAPI(FakeAPI):
    SID='S-1-15-2-1-2-3-4-5-6-7'
    def __init__(self,fault=None):super().__init__(fault);self.controls_uncertain=False
    def identity_owned(self,owners,process=None):
        token=self.handle();owners.add(token);value=ordinary_identity()
        if process is not None and self.processes[process]['command'][1]=='pipe-front':
            value.update(appcontainer=True,appcontainer_sid=self.SID)
            if self.fault=='frontend_sid':value['appcontainer_sid']='S-1-15-2-9'
            if self.fault=='frontend_caps':value['capability_count']=1
        if self.fault=='ordinary':value['elevated']=True
        self.log.append(('identity',process))
        return value
    def local_appdata(self,budget,metadata):
        self.log.append(('known_folder',))
        metadata.update(lookup_state='ready',hresult=0,release_attempted=True,release_returned=True,
            com=[True,0,True,True],deadline_verified=True)
        if self.fault=='environment':raise ValueError('environment')
        return 'C:\\Users\\ordinary\\AppData\\Local'
    def front_environment(self,path,metadata):metadata['exact_child_keyset']=True;return 'SystemRoot=C:\\Windows\0LOCALAPPDATA='+path+'\0\0'
    def create_profile(self,name,state):
        self.log.append(('profile_create',name));state.update(attempted=True,returned=True)
        if self.fault=='profile_exists':raise p.ACNativeFailure('hresult',0x800700b7)
        state.update(created=True,pointer=777,sid=self.SID);return self.SID
    def release_profile_sid(self,state):
        self.log.append(('sid_release',state['pointer']));state['pointer']=None
        if self.fault=='sid_release':raise ValueError('close')
    def grant_acl(self,work,inputs,output,sid,budget):
        self.log.append(('grant',work,inputs,output))
        if self.fault=='grant_readback':raise ValueError('acl')
    def remove_acl(self,work,sid,budget):
        self.log.append(('remove_acl',))
        if self.fault=='remove_acl':return False
        if self.fault=='late_cleanup':self.now=51000
        return True
    def delete_profile(self,name):
        self.log.append(('profile_delete',))
        if self.fault=='profile_delete':raise p.ACNativeFailure('hresult',0x80004005)
    def owned_create_front(self,info,command,work,handles,owners,state,sid_pointer,environment):
        self.log.append(('front_security',sid_pointer,environment))
        return super().owned_create(info,command,work,handles,owners,state)
    def resume(self,thread):
        super().resume(thread)
        for row in self.processes.values():
            path=Path(row['command'][4])
            if path.exists():
                value=json.loads(path.read_text())
                if row['command'][1]=='pipe-front':value['identity'].update(tokenIsAppContainer=True,tokenAppContainerSid=self.SID)
                path.write_text(json.dumps(value),encoding='utf-8')


def ac_fixture(fault=None):
    with tempfile.TemporaryDirectory() as tmp:
        root=Path(tmp).resolve();actor=root/'windows_identity_proxy_pipe_actor.exe';actor.write_bytes(b'MZ'+b'x'*510)
        digest=hashlib.sha256(actor.read_bytes()).hexdigest();api=FakeACAPI(fault)
        value=p.run_ac_pair(api,actor,root/'identity-proxy-pipe-manifest.json',digest,'b'*64,root/'case','a'*32,'c'*32,61000,1000,
            artifact_verifier=lambda *args:(actor,digest))
        expected={'run_nonce':'a'*32,'case_nonce':'c'*32,'actor_sha256':digest,'manifest_sha256':'b'*64,
            'deadline_qpc':61000,'qpc_frequency':1000,'controller_pid':os.getpid(),'controller_sid':ordinary_identity()['sid'],'controller_session':1}
        return value,expected,api


class ACPairTests(unittest.TestCase):
    def test_actual_orchestration_and_private_validator_composed(self):
        value,expected,api=ac_fixture();result=p.validate_private_report(value,expected)
        self.assertTrue(value['pair']['expected_outcome']);self.assertIsNone(result['ac_failure'])
        self.assertTrue(all(v for k,v in result['facts'].items() if k not in ('controller_exit_verified','outer_cleanup_verified')))
        self.assertFalse(result['facts']['controller_exit_verified']);self.assertFalse(result['facts']['outer_cleanup_verified'])
        first=next(i for i,x in enumerate(api.log) if x[0]=='resume')
        self.assertEqual(sum(x[0]=='create' for x in api.log[:first]),2)
        self.assertEqual(sum(x[0]=='identity' and x[1] is not None for x in api.log[:first]),2)
        self.assertEqual(sum(x[0]=='close' and x[1] in api.data for x in api.log[:first]),4)
        self.assertTrue(all(n==1 for n in api.closes.values()))
        self.assertEqual(value['pair_qpc'],[1000,11000]);self.assertEqual(value['deadline_qpc'],61000)
    def test_all_partial_failure_and_cleanup_paths(self):
        for fault in ('ordinary','environment','profile_exists','grant_readback','create_partial','create_no_handle',
                      'assign','image','frontend_sid','frontend_caps','parent_close','resume','process_close',
                      'remove_acl','profile_delete','sid_release','late_cleanup','report_missing'):
            with self.subTest(fault=fault):
                value,expected,api=ac_fixture(fault)
                self.assertFalse(value['pair']['expected_outcome'] and all(value['cleanup'].values()))
                self.assertTrue(all(n==1 for n in api.closes.values()))
                if fault in ('ordinary','environment','profile_exists','grant_readback','frontend_sid','frontend_caps','parent_close'):
                    self.assertFalse(any(x[0]=='resume' for x in api.log))
                if fault in ('create_no_handle','remove_acl','late_cleanup','parent_close','process_close'):
                    self.assertFalse(any(x[0]=='profile_delete' for x in api.log))
                if fault in ('parent_close','process_close'):
                    self.assertFalse(any(x[0]=='remove_acl' for x in api.log));self.assertFalse(value['pair']['cleanup_confirmed'])
                if fault=='ordinary':self.assertFalse(any(x[0]=='profile_create' for x in api.log))
    def test_bound_observations_survive_profile_or_close_failure(self):
        for fault in ('profile_delete','sid_release','remove_acl','process_close'):
            value,expected,api=ac_fixture(fault);result=p.validate_private_report(value,expected)
            self.assertEqual(result['pair']['observations'],[177,78])
            self.assertFalse(result['pair']['expected_outcome'] and result['ac_failure'] is None)
    def test_role_and_held_private_binding_refusals(self):
        value,expected,_=ac_fixture()
        for key,bad in (('controller_pid',999),('case_nonce','d'*32),('qpc_frequency',1001),('actor_sha256','0'*64)):
            changed=copy.deepcopy(value);changed[key]=bad
            with self.assertRaises(ValueError):p.validate_private_report(changed,expected)
        for role in (0,1):
            changed=copy.deepcopy(value);changed['children'][role]['identity']['session_id']=2
            with self.assertRaises(ValueError):p.validate_private_report(changed,expected)
        forged=copy.deepcopy(value);forged['derived_sid']=expected['controller_sid']
        forged['children'][0]['identity']['appcontainer_sid']=expected['controller_sid']
        forged['children'][0]['native']['identity']['tokenAppContainerSid']=expected['controller_sid']
        with self.assertRaises(ValueError):p.validate_private_report(forged,expected)
        self.assertFalse(p.ac_profile_sid('S-1-15-2-4294967296-2-3-4-5-6-7'))
        self.assertTrue(p.ac_profile_sid('S-1-15-2-4294967295-2-3-4-5-6-7'))
        row=value['children'][0]
        with self.assertRaises(ValueError):p.validate_ac_native(row['native'],role='pipe-front',run_id=value['run_nonce'],case_id=value['case_nonce'],pid=row['pid'],identity=row['identity'],frequency=1000,start=1000,end=11000,expected_ac_sid=None)
    def test_off_entry_before_native_and_hosted_inverse(self):
        with mock.patch.object(p,'AC_EXECUTION_ENABLED',False),mock.patch.object(p,'ACWindowsAPI',side_effect=AssertionError('native')):
            self.assertEqual(p.main(['--run-ac-pair']),2)
        import ast
        current=ast.parse((ROOT/'.github/windows_identity_proxy_pipe_probe.py').read_text())
        pins={'validate_native': 'a3881d6a387c55ffd58e8e0e34d1321e9958ff0c811d5ef7d2297ec0d451053c', 'successful_native': 'fc09bbc876b97811af0f49bd6e85574cc640916b3c7ec8b1faf019fb00a81069', 'WindowsAPI': '5228391fb00010d54e54666ccf294d789ea0abf329d73ebb0bd9c723734161f5', '_cleanup': '1d9b57ed78d81bd924982f90f1f1d5de88cf7f9a385130c7eff6da1c50e8b84a', 'run_case': 'fc6b6c6faa302f944515c2a80b52bc2fc931ade190664a5cd8733eb2424f6af3', 'verify_artifact': '937c379298c052f5bcee3b751d263725511332952dd0150a12f11e5b058088e7', 'run_suite': '542324050b8c8fbbbdc14f4e4b6f840c0cdf1d4478011cbd71f350d68108ae7d'}
        actual={n.name:hashlib.sha256(ast.dump(n,include_attributes=False).encode()).hexdigest() for n in current.body if isinstance(n,(ast.FunctionDef,ast.ClassDef))}
        for name,digest in pins.items():self.assertEqual(actual[name],digest)
        self.assertIs(p.AC_EXECUTION_ENABLED,True)
    def test_packaged_artifact_binding_does_not_claim_source_files(self):
        with tempfile.TemporaryDirectory() as tmp:
            root=Path(tmp).resolve();actor=root/'windows_identity_proxy_pipe_actor.exe';actor.write_bytes(b'MZ'+b'x'*510)
            actor_hash=hashlib.sha256(actor.read_bytes()).hexdigest();manifest=root/'identity-proxy-pipe-manifest.json'
            value={'schemaVersion':1,'compileOnly':True,'runtimeAcceptance':False,'actorSourceSha256':'a'*64,
                'identitySourceSha256':'b'*64,'coreSha256':'c'*64,'executableSha256':actor_hash}
            raw=json.dumps(value).encode();manifest.write_bytes(raw);manifest_hash=hashlib.sha256(raw).hexdigest()
            with mock.patch.object(p,'ROOT',root/'absent-repository'):
                self.assertEqual(p.verify_ac_artifact(actor,manifest,manifest_hash,actor_hash),(actor,actor_hash))
            for mh,ah in (('0'*64,actor_hash),(manifest_hash,'0'*64)):
                with self.assertRaises(ValueError):p.verify_ac_artifact(actor,manifest,mh,ah)
            actor.write_bytes(b'MZ'+b'y'*510)
            with self.assertRaises(RuntimeError):p.verify_ac_artifact(actor,manifest,manifest_hash,actor_hash)

    def test_actual_front_attribute_construction_and_partial_handle_registration(self):
        import ctypes as C
        spec=importlib.util.spec_from_file_location('ac_fixed_proc',ROOT/'ruleproxy/windows_app_process.py')
        proc=importlib.util.module_from_spec(spec);spec.loader.exec_module(proc)
        calls=[]
        class Kernel:
            def InitializeProcThreadAttributeList(self,attrs,count,flags,size):
                calls.append(('attrs',count))
                if attrs is None:C.cast(size,C.POINTER(C.c_size_t))[0]=128;return 0
                return 1
            def UpdateProcThreadAttribute(self,attrs,flags,kind,value,size,previous,returned):
                if kind==0x20002:
                    handles=C.cast(value,C.POINTER(C.c_void_p*2)).contents
                    calls.append(('handles',list(handles)))
                else:
                    cap=C.cast(value,C.POINTER(proc._SecurityCapabilities)).contents
                    calls.append(('caps',cap.AppContainerSid,cap.CapabilityCount,cap.Capabilities))
                return 1
            def CreateProcessW(self,exe,command,pa,ta,inherit,flags,environment,cwd,startup,info):
                st=C.cast(startup,C.POINTER(proc._StartupInfoEx)).contents
                calls.append(('create',inherit,flags,st.StartupInfo.dwFlags,environment.value))
                out=C.cast(info,C.POINTER(proc._ProcessInfo)).contents
                out.hProcess=101;out.hThread=102;out.dwProcessId=103
                return 0
            def DeleteProcThreadAttributeList(self,attrs):calls.append(('delete_attrs',))
        api=p.ACWindowsAPI.__new__(p.ACWindowsAPI);api.k=Kernel();api.proc=proc
        api.native=SimpleNamespace(check=lambda ok,op:None if ok else (_ for _ in ()).throw(ValueError(op)))
        owners=p.pipe_helpers.OneShotHandles(lambda h:None);state={'creation_attempted':False};info=proc._ProcessInfo()
        with mock.patch.object(C,'get_last_error',return_value=5,create=True):
            with self.assertRaises(p.launcher.NativeFailure):
                api.owned_create_front(info,['fixed.exe','pipe-front'],Path('.'),(11,12),owners,state,777,'SystemRoot=X\0LOCALAPPDATA=Y\0\0')
        self.assertTrue(state['creation_attempted']);self.assertEqual(owners.pending,{101,102})
        self.assertIn(('handles',[11,12]),calls);self.assertIn(('caps',777,0,None),calls)
        row=next(x for x in calls if x[0]=='create')
        self.assertTrue(row[1]);self.assertEqual(row[3],0)
        self.assertEqual(row[2],proc._CREATE_SUSPENDED|proc._CREATE_UNICODE_ENVIRONMENT|proc._EXTENDED_STARTUPINFO_PRESENT)
        self.assertEqual(calls[-1],('delete_attrs',))

    def test_actual_acl_scope_and_removal_readback_cutoffs(self):
        api=p.ACWindowsAPI.__new__(p.ACWindowsAPI);api.controls_uncertain=False;calls=[]
        api.acl_command=lambda args,budget,cleanup=False:calls.append((args,cleanup))
        clock=FakeACAPI();budget=p.launcher.QpcBudget(clock,61000,1000)
        root=Path('/owned');inputs=root/'inputs';output=root/'frontend-output'
        paths=[root,inputs,inputs/'windows_identity_proxy_pipe_actor.exe',output,root/'relay-output',root/'ownership.json']
        api.acl_read=lambda path,sid:p.ac_scope_expected(root,inputs,output,path)
        with mock.patch.object(p.pipe_helpers,'owned_paths',return_value=paths),mock.patch.dict(os.environ,{'SystemRoot':r'C:\Windows'}):
            api.grant_acl(root,inputs,output,FakeACAPI.SID,budget)
            self.assertEqual([x[0][1] for x in calls],[str(root),str(inputs),str(output)])
            api.acl_read=lambda path,sid:[(0,1)] if path.name=='relay-output' else p.ac_scope_expected(root,inputs,output,path)
            self.assertFalse(api.verify_acl_scope(root,inputs,output,FakeACAPI.SID,budget))
            api.acl_read=lambda path,sid:[]
            self.assertTrue(api.remove_acl(root,FakeACAPI.SID,budget))
            api.acl_read=lambda path,sid:[(0,0x1200a9)]
            self.assertFalse(api.remove_acl(root,FakeACAPI.SID,budget))
            def late(path,sid):clock.now=51000;return []
            api.acl_read=late
            with self.assertRaises(p.launcher.GateFailure):api.remove_acl(root,FakeACAPI.SID,budget)

    def test_acl_binary_projection_and_scope_are_exact(self):
        import struct
        sid=p.ac_sid_bytes(FakeACAPI.SID);ace=struct.pack('<BBHI',0,3,8+len(sid),0x1200a9)+sid
        acl=struct.pack('<BBHHH',2,0,8+len(ace),1,0)+ace
        descriptor=struct.pack('<BBHIIII',1,0,0x8004,0,0,0,20)+acl
        self.assertEqual(p.ac_sid_aces(descriptor,FakeACAPI.SID),[(3,0x1200a9)])
        for position,value in ((20,3),(21,1),(26,1),(27,1)):
            altered=bytearray(descriptor);altered[position]=value
            with self.assertRaises(ValueError):p.ac_sid_aces(bytes(altered),FakeACAPI.SID)
        revision4=bytearray(descriptor);revision4[20]=4
        self.assertEqual(p.ac_sid_aces(bytes(revision4),FakeACAPI.SID),[(3,0x1200a9)])
        spare=bytearray(descriptor+b'\0'*4);struct.pack_into('<H',spare,22,len(acl)+4)
        self.assertEqual(p.ac_sid_aces(bytes(spare),FakeACAPI.SID),[(3,0x1200a9)])
        for damaged in (descriptor[:19],descriptor[:25],descriptor[:20]+b'\0'*8,descriptor[:28]+bytes([1])+descriptor[29:]):
            with self.assertRaises(ValueError):p.ac_sid_aces(damaged,FakeACAPI.SID)
        root=Path('/owned');self.assertEqual(p.ac_scope_expected(root,root/'inputs',root/'frontend-output',root/'relay-output'),[])
        self.assertEqual(p.ac_scope_expected(root,root/'inputs',root/'frontend-output',root/'ownership.json'),[])


class SourceTests(unittest.TestCase):
    def test_exact_two_handle_path_and_frozen_ordinary_gate(self):
        source=(ROOT/'.github/windows_identity_proxy_pipe_probe.py').read_text()
        self.assertIn('(H*2)(*data_handles)',source)
        self.assertIn('pipe_helpers.create_suspended_owned',source)
        self.assertNotIn('launch_owned(',source);self.assertNotIn('CreateProcessAsUser',source)
        hosted=source.split('# Separate, inactive AC integration.',1)[0]
        self.assertNotIn('CreateAppContainerProfile',hosted);self.assertNotIn('icacls',hosted)
        self.assertIn('owners.add(job)',source);self.assertIn('owners.close(handle)',source)
        self.assertIn('initial+60*frequency',source);self.assertIn('end>budget.cutoff(30)',source)
    def test_native_source_guard_and_fixed_role_wire(self):
        source=(ROOT/'.github/native/windows_identity_proxy_pipe_actor.cpp').read_text()
        for token in ('argc!=13','pipe-front','pipe-relay','CREATE_NEW','WriteReport','requires_controller_timeout'):
            self.assertIn(token,source)
        self.assertNotIn('FlushFileBuffers',source)
        self.assertNotIn('WinHttpOpen',source)


if __name__=='__main__':
    if '--run-hosted' in sys.argv:raise SystemExit(hosted_cli(sys.argv[1:]))
    unittest.main()
