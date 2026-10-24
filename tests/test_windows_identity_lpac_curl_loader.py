"""Fake-only coordinator and physical ledger regressions; no native backend.

Synthetic PE bytes/constant substitution identify this as an inert fixture,
not curl compatibility or a Windows loader result. Production NativeAPI and
WinDLL constructors are forbidden for the entire test invocation.
"""
import copy
import ctypes as C
import importlib.util
from pathlib import Path
import shutil
import struct
import tempfile
from types import SimpleNamespace as NS
import unittest
from unittest.mock import patch

ROOT=Path(__file__).resolve().parents[1]
def load(name,path):
    s=importlib.util.spec_from_file_location(name,path);m=importlib.util.module_from_spec(s);s.loader.exec_module(m);return m
m=load('curl_loader_coordinator_test',ROOT/'.github/windows_identity_lpac_curl_loader.py')
b=load('curl_loader_ordinary_fake',ROOT/'tests/test_windows_identity_lpac_dns_local.py')
af=load('curl_loader_access_fake',ROOT/'tests/test_windows_identity_lpac_accesscheck.py')
F,T,D=b.F,b.T,b.D
VERSION=b'curl 8.21.0 (Windows) libcurl/8.21.0 Schannel\nRelease-Date: 2026-04-01\nProtocols: http https\nFeatures: SSL threadsafe\n'

def pe(dll,size=8192):
    raw=bytearray(size);raw[:2]=b'MZ';struct.pack_into('<I',raw,60,128);raw[128:132]=b'PE\0\0'
    struct.pack_into('<HHIIIHH',raw,132,0x8664,1,123,0,0,240,0x2022 if dll else 0x22)
    struct.pack_into('<H',raw,152,0x20b);struct.pack_into('<I',raw,168,4096);struct.pack_into('<I',raw,208,8192);return bytes(raw)

class Probe(af.FakeAPI):
    def __init__(self,parent):super().__init__('lpac',parent.probe_fault);self.parent=parent
    def qpc(self):return self.parent.qpc()
    def frequency(self):return F
    def verify_process(self,process,pid,creation):return process==pid and not self.parent.wait(process,0) and creation==self.parent.creation_time(process)
    def identity(self,token):
        r=copy.deepcopy(self.parent.owner.tasks['selected']['expected_primary'])
        if token==12:r.update(token_type=2,impersonation_level=1,token_id=r['token_id']+1)
        return r

class API(b.API):
    def __init__(self,root,fault=None,probe_fault=None):
        super().__init__(root,fault);self.probe_fault=probe_fault;self.labels={};self.calls=[];self.libraries=[];self.now=T+100
        self.native.query=self.statistics;self.updated=False;self.copied=False;self.file_paths={};self.reads=0
    def qpc(self):self.now+=1;return self.now
    def system_curl(self):return self.root/'win/System32/curl.exe'
    def statistics(self,token,kind,label):
        assert kind==10;s=m.access.TOKEN_STATISTICS();s.TokenType=1;s.TokenId.LowPart=10000+token;s.AuthenticationId.LowPart=20
        return C.create_string_buffer(bytes(s)),C.sizeof(s)
    def groups(self,token,*args):return []
    def identity(self,token):
        r=super().identity(token)
        if self.rows[token-2]['lpac']:r['capability_count']=0
        return r
    def process_id(self,h):return h
    def kernel_sddl(self,h):return 'D:P(A;;GA;;;SY)(A;;GA;;;'+b.SID+')'
    def acl_read(self,path,sid):return m.expected_acl(self.root,path) if self.granted and not self.removed else []
    def label_read(self,path):return self.labels.get(path)
    def label_set(self,path,value):
        if self.fault=='label-restore' and value is None:raise OSError('unknown label restore')
        self.labels[path]=value
    def access_api(self):return Probe(self)
    def lpac_flag(self,token):raise AssertionError('class46 forbidden')
    def open_marker(self,path,owners,other,budget,end):
        self.next+=10;owners.add(self.next);self.file_paths[self.next]=Path(path)
        return self.next,dict(nt_path='\\Device\\HarddiskVolume4\\fixture\\marker.dll',volume_serial=1,file_id='12'*16)
    def held_file_hash(self,h,expected_bytes,budget,end):
        raw=self.file_paths[h].read_bytes();assert len(raw)==expected_bytes;return m.sha(raw)
    def event(self,ledger,other,sid):self.next+=10;ledger.add(self.next);return self.next
    def signal_duplicate(self,h,ledger,other):self.next+=10;ledger.add(self.next);return self.next
    def create_curl(self,info,command,cwd,environment,job,owners,state,*,handles,stdio,profile_pointer,parent_sid,budget,end,on_return,other_owned):
        selected=profile_pointer is not None;assert len(handles)==(5 if selected else 3) and list(handles[-3:])==list(stdio)
        assert command==[str(self.system_curl()),'--disable','--version'];self.calls.append(('create',selected))
        state.update(creation_attempted=True,creation_unknown=True,create_status='returned_true',raw_return=1,raw_error=None,raw_pi=[0,0,0,0],returned_qpc=self.qpc())
        if selected and self.fault=='unknowncreate':state['create_status']='exception';on_return(state.copy());raise OSError('unknown create')
        if selected and self.fault=='known-false':
            state.update(creation_unknown=False,create_status='returned_false',raw_return=0,raw_error=5);on_return(state.copy());raise OSError('known false')
        self.next+=10;h=self.next;v=[h,h+1,h,h+3];info.hProcess,info.hThread,info.dwProcessId,info.dwThreadId=v
        owners.add(h);owners.add(h+1);state.update(creation_unknown=False,raw_pi=v);on_return(state.copy())
        self.rows[h]=dict(argv=command,job=job,lpac=selected,exited=False,kwargs=dict(directory=Path(cwd)))
    def resume(self,thread):
        h=thread-1;r=self.rows[h]
        if r['argv'][0]!=str(self.system_curl()):return super().resume(thread)
        if r['lpac']:
            assert len(self.owner.j['proofs'])==2 and all(x['value']['qualified'] for x in self.owner.j['proofs'])
            assert self.owner.signal_owners.confirmed_closed and all(x.confirmed_closed for x in self.owner.stdio_ledgers)
        self.calls.append(('resume',r['lpac']));directory=self.root/'selected-output' if r['lpac'] else r['kwargs']['directory']
        out=VERSION
        if self.fault=='before-output' and directory.name=='ordinary-before':out=b'bad version\n'
        (directory/'stdout').write_bytes(out);(directory/'stderr').write_bytes(b'')
    def wait(self,h,ms):
        r=self.rows[h]
        if ms and r['argv'][0]==str(self.system_curl()):r['exited']=True
        return r['exited']
    def exit_code(self,h):return 5 if self.fault=='selected-nonzero' and self.rows[h]['lpac'] else 0
    def load_wrapper(self,path):
        self.calls.append(('load-wrapper',str(path)))
        if self.fault=='wrapper-load':raise OSError('known wrapper load failure')
        self.libraries.append(path)
    def wrapper_call(self,op,ctx,plan,marker):
        self.calls.append(('wrapper',op));r=m.Result128();r.size=128;r.version=1;r.operation=m.OPERATIONS[op]
        r.entered_qpc=self.qpc();r.returned_qpc=self.qpc();r.validation_passed=1;r.return_clock_known=1;r.within_original_window=1;r.exact_target_still_alive=1;r.local_context_generation=1
        if op=='update':self.updated=True
        if self.updated:r.update_entered=r.update_returned=1;r.raw_update_BOOL=1;r.remote_mutation_possible=1
        if op=='install':self.copied=True
        if self.copied:r.copy_entered=r.copy_returned=r.copy_nonnull=1
        code=dict(begin=9,update=11,install=5,read=7,forget=10)[op]
        if op=='update' and self.fault=='update-false':
            code=2;r.raw_update_BOOL=0;r.update_error_valid=1;r.update_GetLastError=5;r.remote_outcome_unknown=1
        if op=='install' and self.fault=='copy-null-error0':code=3;r.copy_nonnull=0;r.copy_error_valid=1;r.copy_GetLastError=0;r.remote_outcome_unknown=1
        output=None
        if op=='read':
            self.reads+=1;r.marker_read_entered=r.marker_read_returned=r.marker_read_exact256=r.coherent_snapshot=1
            marker.progress_flags=6143;marker.failure_stage=0;marker.raw_restore_BOOL=marker.raw_SetEvent_entered_BOOL=marker.raw_SetEvent_body_BOOL=1
            marker.last_original_domain_qpc=self.qpc();marker.writer_target_pid=plan.target_pid;marker.even_stable_status_sequence=self.reads*2
            if self.fault=='status-race' and self.reads==1:marker.progress_flags=1
            if self.fault=='rpm-false0':code=12;r.marker_read_exact256=r.coherent_snapshot=0;r.read_GetLastError=0
            output=bytes(marker)
        if op=='forget':r.exact_target_still_alive=0
        r.returned_qpc=self.qpc();r.result_class=code;return code,bytes(r),output
    def event_states(self,events,process,budget,end):return dict(wait=0,entered=True,body=True,process_exited=self.wait(process,0),qpc=self.qpc())
    def mapped_marker(self,row,retained,path,digest,budget,end,other):
        return dict(verified=True,query_closed=True,file_closed=True,error=None,file_identity=retained.copy(),modules=3,base=0x100000,qpc=self.qpc())

class LoaderTests(unittest.TestCase):
    def setUp(self):
        self.stack=[]
        for target,name in ((m,'NativeAPI'),(C,'WinDLL')):
            p=patch.object(target,name,side_effect=AssertionError('production backend/library forbidden'),create=True);p.start();self.addCleanup(p.stop)
    def fixture(self,fault=None,probe_fault=None):
        td=tempfile.TemporaryDirectory();self.addCleanup(td.cleanup);root=Path(td.name).resolve()
        for name in ('owner-inputs','package','selected-output','ordinary-before','ordinary-after','tools','guard','returns','journal'):(root/name).mkdir()
        for name in m.SOURCES:
            p=root/name;p.parent.mkdir(parents=True,exist_ok=True);p.write_bytes((ROOT/name).read_bytes())
        app=pe(False,m.CURL_BYTES);path=root/'win/System32/curl.exe';path.parent.mkdir(parents=True);path.write_bytes(app)
        (path.parent/'icacls.exe').write_bytes(b'fixed-inert-tool')
        files=dict(curl=path,wrapper=root/'owner-inputs'/m.WRAPPER,marker=root/'package'/m.MARKER,manifest=root/'owner-inputs'/m.MANIFEST)
        files['wrapper'].write_bytes(pe(True));files['marker'].write_bytes(pe(True))
        pins={k:dict(bytes=p.stat().st_size,sha256=m.sha(p.read_bytes())) for k,p in files.items() if k!='manifest'}
        manifest=dict(schemaVersion=1,compileOnly=True,runtimeAcceptance=False,interfaceVersion=1,wrapperSha256=pins['wrapper']['sha256'],markerSha256=pins['marker']['sha256'],
            nativeSourceHashes={n:m.sha((root/n).read_bytes()) for n in m.NATIVE_SOURCES},detoursCommit='1dbd4ea281d73d478aa8d09a8b83fbd265f715f7',
            detoursSourceHashes={'.github/vendor/detours/'+n:m.sha((root/'.github/vendor/detours'/n).read_bytes()) for n in m.VENDOR_FILES})
        files['manifest'].write_bytes(m.encode(manifest));pins['manifest']=dict(bytes=files['manifest'].stat().st_size,sha256=m.sha(files['manifest'].read_bytes()))
        p=patch.object(m,'CURL_SHA256',pins['curl']['sha256']);p.start();self.addCleanup(p.stop)
        hashes={n:m.sha((root/n).read_bytes()) for n in m.SOURCES}
        c=dict(schema_version=1,scope=m.SCOPE,profile=m.PROFILE,**{n:'%032x'%(i+1) for i,n in enumerate(m.NONCES)},start_qpc=T,frequency=F,
            root_deadline_qpc=T+120*F,deadline_qpc=D,guard_job_name='Local\\RuleProxy.LocalGuard.'+'%032x'%1,source_hashes=hashes,source_sha256=m.sha(m.encode(hashes)),
            device_sha256='1'*64,recovery_plan_sha256='2'*64,artifacts=pins,curl_path=str(path))
        api=API(root,fault,probe_fault);o=m.Owner(root,c,copy.deepcopy(b.PARENT),api,m.launcher.QpcBudget(api,D,F));api.owner=o
        return root,c,api,o
    def run_case(self,*a,**kw):
        root,c,api,o=self.fixture(*a,**kw);j=o.run();m.validate_result(j,c,parent=b.PARENT,root=root)
        return root,c,api,o,j,m.project(j,c,parent=b.PARENT,root=root)
    def test_real_owner_fake_backend_complete_and_control_artifact_gates(self):
        root,c,api,o,j,v=self.run_case();self.assertTrue(v['observation_complete']);self.assertTrue(all(v[k] for k in m.CLEAN_KEYS))
        self.assertEqual([x for x in api.calls if x[0]=='wrapper'],[('wrapper',k) for k in ('begin','update','install','read','forget')])
        self.assertEqual([x[1] for x in api.calls if x[0]=='resume'],[False,True,False]);self.assertFalse(any(v[k] for k in m.FALSE_CLAIMS))
    def test_before_control_negative_never_constructs_or_updates_selected(self):
        root,c,api,o,j,v=self.run_case('before-output');self.assertFalse(v['ordinary_before_positive']);self.assertFalse(v['observation_complete'])
        self.assertFalse(any(x==('create',True) or x[0]=='wrapper' for x in api.calls));self.assertEqual(j['proofs'],[])
    def test_returned_update_false_and_copy_null0_never_resume_selected(self):
        for fault in ('update-false','copy-null-error0'):
            with self.subTest(fault=fault):
                root,c,api,o,j,v=self.run_case(fault);self.assertNotIn(('resume',True),api.calls);self.assertTrue(v['ordinary_after_positive'])
                self.assertTrue(j['context_forgotten']);self.assertFalse(v['observation_complete'])
    def test_unknown_constructor_and_observer_cleanup_cannot_delete_profile(self):
        root,c,api,o,j,v=self.run_case('unknowncreate');self.assertTrue(j['creation_unknown']);self.assertFalse(j['profile_deleted'])
        self.assertNotIn(('resume',True),api.calls);self.assertFalse(v['observation_complete'])
    def test_status_commit_race_uses_second_read_without_new_window(self):
        root,c,api,o,j,v=self.run_case('status-race');self.assertEqual(api.reads,2);self.assertTrue(v['observation_complete'])
        self.assertEqual(j['window']['end']-j['window']['start'],8*F)
    def test_rpm_false_error0_is_partial_not_coherent_success(self):
        root,c,api,o,j,v=self.run_case('rpm-false0');self.assertEqual(api.reads,4);self.assertFalse(v['coherent_marker_observed']);self.assertFalse(v['observation_complete'])
        reads=[r for r in j['operations'] if r['operation']=='read'];self.assertTrue(all(m.result_record(bytes.fromhex(x['raw']),'read',(j['window']['start'],j['window']['end']))['read_GetLastError']==0 for x in reads))
    def test_selected_nonzero_retains_loader_facts_and_separate_controls(self):
        root,c,api,o,j,v=self.run_case('selected-nonzero');self.assertTrue(v['loader_mechanism_observed']);self.assertFalse(v['selected_version_positive'])
        self.assertTrue(v['ordinary_before_positive'] and v['ordinary_after_positive']);self.assertFalse(v['observation_complete'])
    def test_physical_PI_or_stdout_tamper_rejects_and_control_reader_independent(self):
        root,c,api,o,j,v=self.run_case();r=j['tasks'][0]['receipt'];path=root/'returns'/r['name'];raw=path.read_bytes();path.write_bytes(raw+b' ')
        with self.assertRaises(ValueError):m.validate_result(j,c,parent=b.PARENT,root=root)
        controls=m.ordinary_controls(root,c,b.PARENT);self.assertFalse(controls['before']);self.assertTrue(controls['after'])
    def test_success_tuple_and_physical_native_clock_mutations_reject(self):
        root,c,api,o,j,v=self.run_case()
        for field in ('validation_passed','exact_target_still_alive','within_original_window'):
            row=next(x for x in j['operations'] if x['operation']=='update');r=m.Result128.from_buffer_copy(bytes.fromhex(row['raw']));setattr(r,field,0)
            with self.subTest(field=field),self.assertRaises(ValueError):m.result_record(bytes(r),'update',(j['window']['start'],j['window']['end']))
        changed=copy.deepcopy(j);row=next(x for x in changed['operations'] if x['operation']=='update');receipt=row['receipt']
        value=m.decode(receipt['text'].encode('ascii'));r=m.Result128.from_buffer_copy(bytes.fromhex(row['raw']));r.returned_qpc=value['qpc']+1
        row['raw']=bytes(r).hex();value['data']['raw']=row['raw'];raw=m.encode(value)
        replacement=dict(name=receipt['name'],text=raw.decode('ascii'),sha256=m.sha(raw));(root/'returns'/receipt['name']).write_bytes(raw)
        changed['returns'][changed['returns'].index(receipt)]=replacement;row['receipt']=replacement
        with self.assertRaisesRegex(ValueError,'loader_native_return_causal'):m.validate_result(changed,c,parent=b.PARENT,root=root)
    def test_window_without_inputs_is_typed_clean_partial_not_loader_success(self):
        root,c,api,o,j,v=self.run_case('wrapper-load');self.assertIsNotNone(j['window']);self.assertIsNone(j['native_inputs'])
        self.assertEqual(j['operations'],[]);self.assertFalse(j['context_bound']);self.assertTrue(all(j[k] for k in m.CLEAN_KEYS))
        self.assertTrue(v['ordinary_before_positive'] and v['ordinary_after_positive']);self.assertFalse(v['observation_complete'])
        changed=copy.deepcopy(j);changed['failure']=None;changed['failure_detail']=None
        with self.assertRaisesRegex(ValueError,'loader_partial_native_preparation'):m.validate_result(changed,c,parent=b.PARENT,root=root)
        root,c,api,o=self.fixture();real=m.base.durable_private
        def fail_marker(path,raw):
            if Path(path).name=='native-marker.bin':raise OSError('known native input write failure')
            return real(path,raw)
        with patch.object(m.base,'durable_private',side_effect=fail_marker):j=o.run()
        m.validate_result(j,c,parent=b.PARENT,root=root);self.assertTrue((root/'native-plan.bin').exists());self.assertIsNone(j['native_inputs'])
        self.assertFalse(m.project(j,c,parent=b.PARENT,root=root)['observation_complete'])
    def test_nested_schema_booleans_are_not_integer_versions(self):
        root,c,api,o,j,v=self.run_case();changed=copy.deepcopy(j);changed['schema_version']=True
        with self.assertRaises(ValueError):m.validate_result(changed,c,parent=b.PARENT,root=root)
        control=m.decode((root/'control-before.json').read_bytes());control['schema_version']=True
        with self.assertRaises(ValueError):m.validate_ordinary_control(control,c,role='before',parent=b.PARENT,root=root)
        manifest=m.decode((root/'owner-inputs'/m.MANIFEST).read_bytes());manifest['interfaceVersion']=True
        with self.assertRaises(ValueError):m.verify_manifest(m.encode(manifest),c['artifacts'],source_root=root)
    def test_physical_return_causality_and_invalid_pi_cannot_be_rebound(self):
        def rebind(root,j,old,value):
            raw=m.encode(value);replacement=dict(name=old['name'],text=raw.decode('ascii'),sha256=m.sha(raw))
            (root/'returns'/old['name']).write_bytes(raw);j['returns'][j['returns'].index(old)]=replacement
            return replacement
        root,c,api,o,j,v=self.run_case();task=j['tasks'][0];old=task['receipt'];value=m.decode(old['text'].encode('ascii'))
        value['data']['raw_pi'][0]=0xffffffffffffffff;task['receipt']=rebind(root,j,old,value)
        with self.assertRaisesRegex(ValueError,'loader_PI_owned'):m.validate_result(j,c,parent=b.PARENT,root=root)
        root,c,api,o,j,v=self.run_case('status-race');reads=[x for x in j['operations'] if x['operation']=='read']
        reads[1]['intent_sha256']=reads[0]['intent_sha256']
        with self.assertRaisesRegex(ValueError,'loader_native_return_physical'):m.validate_result(j,c,parent=b.PARENT,root=root)
        root,c,api,o,j,v=self.run_case();row=next(x for x in j['operations'] if x['operation']=='read');old=row['receipt']
        value=m.decode(old['text'].encode('ascii'));marker=m.Marker256.from_buffer_copy(bytes.fromhex(row['marker']))
        native=m.Result128.from_buffer_copy(bytes.fromhex(row['raw']));marker.last_original_domain_qpc=native.returned_qpc+1
        row['marker']=bytes(marker).hex();value['data']['marker']=row['marker'];row['receipt']=rebind(root,j,old,value)
        with self.assertRaisesRegex(ValueError,'loader_marker_status'):m.validate_result(j,c,parent=b.PARENT,root=root)
        root,c,api,o,j,v=self.run_case();mapping=j['mapping'][0];old=mapping['receipt'];value=m.decode(old['text'].encode('ascii'))
        mapping['qpc']=value['qpc']+1;value['data']['qpc']=mapping['qpc'];mapping['receipt']=rebind(root,j,old,value)
        with self.assertRaisesRegex(ValueError,'loader_mapping_gate'):m.validate_result(j,c,parent=b.PARENT,root=root)
    def test_semantic_proof_or_label_and_grant_projection_mutations_reject(self):
        root,c,api,o,j,v=self.run_case()
        mutations=[lambda x:x['proofs'].pop(),lambda x:x['labels'].clear(),lambda x:x['tasks'].remove(next(t for t in x['tasks'] if t['name']=='grant-output')),
            lambda x:x['tasks'][4]['expected_primary'].update(capabilities=[dict(sid='S-1-15-3-1',attributes=4)]),lambda x:x.update(product_acceptance=True)]
        for mutate in mutations:
            changed=copy.deepcopy(j);mutate(changed)
            with self.assertRaises((ValueError,KeyError)):m.validate_result(changed,c,parent=b.PARENT,root=root)
    def test_output_calendar_and_conditional_lines_without_golden_runtime(self):
        self.assertTrue(m.version_output(VERSION,b'')['recognized']);self.assertTrue(m.version_output(b'\n'.join(VERSION.splitlines()[:2])+b'\n',b'')['recognized'])
        for date in (b'2025-02-29',b'2026-13-01',b'2026-04-31'):
            self.assertFalse(m.version_output(VERSION.replace(b'2026-04-01',date),b'')['recognized'])
        self.assertFalse(m.version_output(VERSION,b'warning')['recognized']);self.assertFalse(m.version_output(VERSION+b'extra\n',b'')['recognized'])
    def test_context_alignment_and_read12_error0_late_class_preserved(self):
        self.assertEqual((C.sizeof(m.Context2048),C.alignment(m.Context2048)),(2048,8));self.assertEqual(m.Marker256.even_stable_status_sequence.offset,248)
        r=m.Result128();r.size=128;r.version=1;r.operation=4;r.result_class=12;r.marker_read_entered=r.marker_read_returned=1
        self.assertEqual(m.result_record(bytes(r),'read',(100,200))['result_class'],12)
        r.result_class=6;r.read_GetLastError=5
        with self.assertRaises(ValueError):m.result_record(bytes(r),'read',(100,200))

if __name__=='__main__':unittest.main()
