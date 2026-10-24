"""Pure injected owner/physical-record tests; no DLL, backend or target.

The synthetic PE/native trace is not an actual curl observation. The complete
case runs the real new owner and independent byte reader against injected API
returns, retaining the reviewed ordinary and AccessCheck fixture adapters.
"""
import copy
import ctypes as C
import importlib.util
from pathlib import Path
import struct
import tempfile
import unittest
from unittest.mock import patch

ROOT=Path(__file__).resolve().parents[1]
def load(name,path):
    s=importlib.util.spec_from_file_location(name,path);m=importlib.util.module_from_spec(s);s.loader.exec_module(m);return m
m=load('cmm_owner_test',ROOT/'.github/windows_identity_lpac_curl_mm_loader.py')
old=load('cmm_constructor_fixture',ROOT/'tests/test_windows_identity_lpac_curl_loader.py')
b=old.b
def put(raw,off,val,kind='I'):struct.pack_into('<'+kind,raw,off,val)

def complete_output(api,buffers):
    e=m.reader.validate_inputs(buffers.expectation());p=e['plan'];out=bytearray(24576);rows=[]
    pid,created=e['pid'],e['creation'];hs=e['borrowed'];base=0x180000000
    for o,v in ((0,256),(4,2),(8,4),(12,7),(92,2),(116,2),(120,2)):put(out,o,v)
    for o in (*range(32,92,4),96,100,104):put(out,o,1)
    put(out,52,0)
    for i in range(2):
        out[4352+i*256:4608+i*256]=buffers.expectation()['identity256']
        out[4864+i*1024:5888+i*1024]=buffers.expectation()['security1024']
        h=bytearray(192);struct.pack_into('<4IQ2I',h,0,192,2,pid,pid,created,1,0)
        for o in (32,40,48,56,72,80,96,168):put(h,o,1)
        put(h,60,0x2000);put(h,84,0x2000)
        h[104:128],h[128:152],h[152:168]=p[360:384],p[384:408],p[488:504]
        out[16512+i*192:16704+i*192]=h
        image=bytearray(608);v=e['raw']['target_path'].encode('utf-16-le');image[64:64+len(v)]=v;put(image,584,len(e['raw']['target_path']))
        out[21056+i*608:21664+i*608]=image
    g=bytearray(64);struct.pack_into('<4IQ2I',g,0,64,2,pid,pid,created,1,0)
    for o in (32,40,44,52,56):put(g,o,1)
    out[16896:16960]=g
    marker=bytearray(buffers.expectation()['initial_marker320'])
    for o,v in ((200,6143),(208,1),(216,1),(224,1),(240,pid),(264,1)):put(marker,o,v)
    put(marker,248,2,'Q');put(marker,256,base,'Q')
    region=bytearray(64);struct.pack_into('<IIQQQIIIIQI',region,0,64,2,base,base,8192,0x20,0x1000,0x20,0x1000000,48,0)
    out[8192:8256]=region;out[8256:8320]=region
    for off in (8320,10368):
        raw=e['raw']['marker_nt_path'].encode('utf-16-le');out[off:off+len(raw)]=raw
    out[12416:16512]=m.local.bounded(m.artifact_paths(api.root)['marker'],8*1024*1024)[:4096]
    def emit(op,req,obs=0,kind=1,success=True,error=0):
        entered=api.qpc();returned=api.qpc();boolean=int(success) if kind==1 else error if kind==7 else 0
        valid=int((kind==1 and not success) or (kind in (2,7,8) and error!=0))
        raw=struct.pack('<IIIiIIIIQQQQ',op,1,1,boolean,error,valid,kind,0,entered,returned,req,obs);rows.append(raw);return raw
    def full(index):
        alloc=[90000+index*100+n for n in range(5)];token,sd,text,tsd,ttext=alloc
        probes={116:64,118:64,120:4,122:64,124:56}
        for op in (*range(100,105),*range(110,127),*range(130,138),*range(140,148),*range(150,158)):
            if op in (100,103):emit(op,hs[0 if op==100 else 1],pid,2)
            elif op==101:emit(op,hs[0],created)
            elif op==102:emit(op,0,258,3)
            elif op==104:
                q=emit(op,260,len(e['raw']['target_path']));out[21056+index*608:21120+index*608]=q
            elif op==110:emit(op,hs[0],token)
            elif op in range(111,116):emit(op,4,4|({111:1,112:e['identity']['session_id'],113:1,114:0,115:0}[op]<<32))
            elif op in probes:emit(op,0,probes[op],success=False,error=122)
            elif op in (117,119,121,123,125):emit(op,probes[op-1],probes[op-1]|((1 if op==125 else 0)<<32))
            elif op==126:emit(op,token)
            elif op in (130,134):emit(op,hs[0 if op==130 else 1],sd if op==130 else tsd,7)
            elif op in (131,135):emit(op,sd if op==131 else tsd,text if op==131 else ttext)
            elif op in (132,133,136,137):emit(op,{132:text,133:sd,136:ttext,137:tsd}[op],0,8)
            elif op in (140,144):emit(op,hs[3 if op==140 else 4],1)
            elif op in (141,145,150,154):emit(op,hs[{141:3,145:4,150:7,154:8}[op]])
            elif op in (142,146):emit(op,9|(144<<32),144|(0x2000<<32))
            elif op in (143,147):emit(op,4|(4<<32),4)
            elif op in (151,155):emit(op,8,0x80)
            elif op in (152,156):emit(op,24)
            elif op in (153,157):emit(op,24,struct.unpack_from('<Q',p,488 if op==153 else 496)[0])
    full(0);emit(160,1,1,3)
    for op in (162,163,164):emit(op,0,258 if op==162 else 0,3)
    for op in range(170,176):
        if op in (170,173):emit(op,hs[0 if op==170 else 1],pid,2)
        elif op==171:emit(op,hs[0],created)
        elif op==172:emit(op,0,258,3)
        else:emit(op,hs[3 if op==174 else 4],1)
    emit(182,320,320);emit(183,320,320)
    marker_tick=struct.unpack_from('<Q',rows[-2],40)[0];put(marker,232,marker_tick,'Q')
    for off in (7552,7872):out[off:off+320]=marker
    emit(190,48,48,2);emit(191,1024,len(e['raw']['marker_nt_path']),2);emit(192,4096,4096)
    emit(193,48,48,2);emit(194,1024,len(e['raw']['marker_nt_path']),2);full(1)
    for index,row in enumerate(rows):off=256+64*index if index<64 else 16960+64*(index-64);out[off:off+64]=row
    put(out,112,len(rows));put(out,16,struct.unpack_from('<Q',rows[45],32)[0],'Q');put(out,24,struct.unpack_from('<Q',rows[-1],40)[0],'Q')
    return bytes(out)

class API(old.API):
    def handle_flags(self,h):return 0
    def open_marker(self,path,owners,other,budget,end):
        self.next+=10;h=self.next;owners.add(h);self.file_paths[h]=Path(path)
        return h,self.file_fact(h,budget,end)
    def file_fact(self,h,budget,end):
        target=self.file_paths[h].name.casefold()=='curl.exe'
        return dict(nt_path='\\Device\\HarddiskVolume4\\fixture\\'+('curl.exe' if target else 'marker.dll'),volume_serial=1,file_id=('11' if target else '12')*16)
    def open_outer_query(self,name,process,ledger,other):self.next+=10;ledger.add(self.next);return self.next
    def resume_raw(self,thread):
        self.calls.append(('resume-raw',thread))
        if self.fault=='resume-minus1':return 0xffffffff,0
        if self.fault=='resume-zero':return 0,None
        self.resume(thread);return 1,None
    def wrapper_call(self,op,buffers):
        self.calls.append(('wrapper',op))
        if op=='observe':
            if self.fault=='native-throw':raise OSError('injected unknown observe')
            raw=complete_output(self,buffers)
            if self.fault=='native-resource':
                raw=bytearray(raw);put(raw,104,0);raw=bytes(raw)
            return 7,raw[:256],raw
        code={'begin':9,'update':11,'install':5,'forget':10}[op];r=bytearray(256)
        for off,val in ((0,256),(4,2),(8,m.OPERATIONS[op]),(12,code)):put(r,off,val)
        entered=self.qpc()
        for off in (32,36,40,44,64,104):put(r,off,1)
        if op in ('update','install'):
            value=1 if op=='update' else 0
            kind=1 if op=='update' else 8;observed=0 if op=='update' else 0x200000
            r[136:200]=struct.pack('<IIIiIIIIQQQQ',220 if op=='update' else 221,1,1,value,0,0,kind,0,self.qpc(),self.qpc(),struct.unpack_from('<Q',buffers.expectation()['plan512'],64)[0] if op=='update' else 320,observed)
        returned=self.qpc();put(r,16,entered,'Q');put(r,24,returned,'Q')
        if op=='forget':buffers.ctx.storage[:]=bytes(8192);put(r,64,0)
        return code,bytes(r),None

class MMTests(unittest.TestCase):
    def setUp(self):
        for obj,name in ((m,'NativeAPI'),(C,'WinDLL')):
            p=patch.object(obj,name,side_effect=AssertionError('production backend forbidden'),create=True);p.start();self.addCleanup(p.stop)
    def fixture(self,fault=None):
        td=tempfile.TemporaryDirectory();self.addCleanup(td.cleanup);root=Path(td.name).resolve()
        for name in ('owner-inputs','package','selected-output','ordinary-before','ordinary-after','tools','guard','returns','journal'):(root/name).mkdir()
        for name in m.SOURCES:
            p=root/name;p.parent.mkdir(parents=True,exist_ok=True);source=ROOT/name
            p.write_bytes(source.read_bytes() if source.exists() else b'// synthetic pending native input\n')
        files=dict(curl=root/'win/System32/curl.exe',wrapper=root/'owner-inputs'/m.WRAPPER,marker=root/'package'/m.MARKER,manifest=root/'owner-inputs'/m.MANIFEST)
        files['curl'].parent.mkdir(parents=True);(files['curl'].parent/'icacls.exe').write_bytes(b'fixed inert tool')
        for name in ('curl','wrapper','marker'):
            raw=bytearray(old.pe(name!='curl',m.CURL_BYTES if name=='curl' else 8192));put(raw,212,512);struct.pack_into('<H',raw,220,3 if name=='curl' else 2);files[name].write_bytes(raw)
        pins={name:dict(bytes=p.stat().st_size,sha256=m.sha(p.read_bytes())) for name,p in files.items() if name!='manifest'}
        v=dict(schemaVersion=1,compileOnly=True,runtimeAcceptance=False,interfaceVersion=2,wrapperSha256=pins['wrapper']['sha256'],markerSha256=pins['marker']['sha256'],
            nativeSourceHashes={n:m.sha((root/n).read_bytes()) for n in m.NATIVE_SOURCES},detoursCommit='1dbd4ea281d73d478aa8d09a8b83fbd265f715f7',detoursSourceHashes={'.github/vendor/detours/'+n:m.sha((root/'.github/vendor/detours'/n).read_bytes()) for n in m.VENDOR_FILES})
        files['manifest'].write_bytes(m.encode(v));pins['manifest']=dict(bytes=files['manifest'].stat().st_size,sha256=m.sha(files['manifest'].read_bytes()))
        for name,value in (('CURL_SHA256',pins['curl']['sha256']),('NATIVE_SOURCE_CLOSURE_FINAL',True)):
            p=patch.object(m,name,value);p.start();self.addCleanup(p.stop)
        hashes={n:m.sha((root/n).read_bytes()) for n in m.SOURCES}
        c=dict(schema_version=1,scope=m.SCOPE,profile=m.PROFILE,**{n:'%032x'%(i+1) for i,n in enumerate(m.NONCES)},start_qpc=b.T,frequency=b.F,
            root_deadline_qpc=b.T+120*b.F,deadline_qpc=b.D,guard_job_name='Local\\RuleProxy.LocalGuard.'+'%032x'%1,source_hashes=hashes,source_sha256=m.sha(m.encode(hashes)),
            device_sha256='1'*64,recovery_plan_sha256='2'*64,artifacts=pins,curl_path=str(files['curl']))
        api=API(root,fault);owner=m.Owner(root,c,copy.deepcopy(b.PARENT),api,m.launcher.QpcBudget(api,b.D,b.F));api.owner=owner
        return root,c,api,owner
    def run_case(self,fault=None):
        root,c,api,o=self.fixture(fault);j=o.run();m.validate_result(j,c,parent=b.PARENT,root=root);return root,c,api,o,j,m.project(j,c,parent=b.PARENT,root=root)
    def test_complete_real_owner_independent_reader_and_context_bytes(self):
        root,c,api,o,j,v=self.run_case();self.assertTrue(v['observation_complete']);self.assertTrue(all(v[k] for k in m.CLEAN_KEYS))
        self.assertEqual([x for x in api.calls if x[0]=='wrapper'],[('wrapper',k) for k in ('begin','update','install','observe','forget')])
        self.assertEqual((root/'native-forget-context.bin').read_bytes(),bytes(8192));self.assertEqual(len(j['lease_checks']),2)
    def test_resume_minus1_error0_and_zero_never_observe_or_retry(self):
        for fault in ('resume-minus1','resume-zero'):
            root,c,api,o,j,v=self.run_case(fault);self.assertNotIn(('wrapper','observe'),api.calls)
            r=m.decode(j['resume_observation']['text'].encode('ascii'))['data'];self.assertTrue(r['returned']);self.assertFalse(v['observation_complete'])
            self.assertEqual(sum(x[0]=='resume-raw' for x in api.calls),1)
    def test_resume_observe_hot_path_has_no_disk_or_held_calls_between(self):
        root,c,api,o=self.fixture();events=[];durable=m.base.durable_private;held=o.held;raw=api.resume_raw;native=api.wrapper_call
        def write(path,data):events.append('disk');return durable(path,data)
        def hold(*a):events.append('held');return held(*a)
        def resume(*a):events.append('resume');return raw(*a)
        def call(op,*a):events.append(op);return native(op,*a)
        with patch.object(m.base,'durable_private',side_effect=write),patch.object(o,'held',side_effect=hold),patch.object(api,'resume_raw',side_effect=resume),patch.object(api,'wrapper_call',side_effect=call):j=o.run()
        self.assertEqual(events[events.index('resume')+1],'observe');self.assertIsNotNone(j['resume_observation'])
    def test_native_exception_preserves_resume_and_blocks_profile_delete(self):
        root,c,api,o,j,v=self.run_case('native-throw');self.assertTrue(m.decode(j['resume_observation']['text'].encode('ascii'))['data']['returned'])
        self.assertFalse(j['profile_deleted']);self.assertFalse(j['native_resources_closed']);self.assertFalse(v['observation_complete'])
    def test_natural_nonzero_preserves_finite_mechanism_not_version(self):
        root,c,api,o,j,v=self.run_case('selected-nonzero');self.assertTrue(v['loader_mechanism_observed']);self.assertTrue(v['observation_complete'])
        self.assertFalse(v['selected_version_positive']);self.assertFalse(v['version_behavior_observed']);self.assertEqual(v['selected_exit_code'],5)
    def test_physical_output_or_context_tamper_rejected(self):
        for name in ('native-observe-output.bin','native-update-context.bin'):
            root,c,api,o,j,v=self.run_case();path=root/name;raw=path.read_bytes();path.write_bytes(raw[:-1]+bytes([raw[-1]^1]))
            with self.assertRaises(ValueError):m.validate_result(j,c,parent=b.PARENT,root=root)
    def test_bad_before_no_profile_no_selected(self):
        root,c,api,o,j,v=self.run_case('before-output');self.assertFalse(v['ordinary_before_positive']);self.assertFalse(j['profile_created'])
        self.assertFalse(any(x==('create',True) for x in api.calls));self.assertEqual(j['operations'],[])
    def test_no_native_fallback_and_false_claims(self):
        self.assertIs(type(m.ACTUAL_READY),bool);self.assertNotIn('mapped_marker',m.API.__dict__);self.assertNotIn('read',m.OPERATIONS)
        root,c,api,o,j,v=self.run_case();self.assertFalse(any(v[k] for k in m.FALSE_CLAIMS))
    def test_resume_clock_failure_retains_raw_one_but_never_observes(self):
        root,c,api,o=self.fixture();raw=api.resume_raw;qpc=api.qpc;fail=[False]
        def resume(h):
            result=raw(h);fail[0]=True;return result
        def clock():
            if fail[0]:fail[0]=False;raise OSError('post Resume clock unknown')
            return qpc()
        with patch.object(api,'resume_raw',side_effect=resume),patch.object(api,'qpc',side_effect=clock):j=o.run()
        r=m.decode(j['resume_observation']['text'].encode('ascii'))['data']
        self.assertEqual(r['count'],1);self.assertTrue(r['returned'] and r['clock_error']);self.assertIsNone(r['returned_qpc'])
        self.assertNotIn(('wrapper','observe'),api.calls);self.assertFalse(j['profile_deleted'])
        m.validate_result(j,c,parent=b.PARENT,root=root)
    def test_resume_receipt_write_failure_does_not_discard_native_binaries(self):
        root,c,api,o=self.fixture();write=m.base.durable_private
        def durable(path,data):
            if Path(path).parent.name=='returns' and Path(path).name.endswith('-resume-selected.json'):raise OSError('receipt write unavailable')
            return write(path,data)
        with patch.object(m.base,'durable_private',side_effect=durable):j=o.run()
        self.assertTrue((root/'native-observe-result.bin').is_file());self.assertTrue((root/'native-observe-output.bin').is_file())
        self.assertTrue((root/'native-observe-context.bin').is_file());self.assertFalse(j['profile_deleted'])
        self.assertTrue(next(r for r in j['operations'] if r['operation']=='observe')['returned'])
    def test_native_context_copy_failure_still_preserves_raw_result_output_and_resume(self):
        root,c,api,o=self.fixture();logical=m.protocol.logical_bytes
        def snapshot(buffer):
            if api.calls[-1]==('wrapper','observe') and buffer is o.buffers.ctx:raise OSError('context copy unavailable')
            return logical(buffer)
        with patch.object(m.protocol,'logical_bytes',side_effect=snapshot):j=o.run()
        self.assertTrue((root/'native-observe-result.bin').is_file());self.assertTrue((root/'native-observe-output.bin').is_file())
        self.assertIsNotNone(j['resume_observation']);self.assertFalse(j['profile_deleted'])
    def test_unknown_target_or_outer_close_blocks_profile_deletion(self):
        for attribute in ('target_handle','outer_query'):
            root,c,api,o=self.fixture();close=api.close
            def shutdown(h):
                if h==getattr(o,attribute):raise OSError('known handle close uncertain')
                return close(h)
            with patch.object(api,'close',side_effect=shutdown):
                # Ledgers bind the callable at construction; replace only the
                # injected owner's new resource ledger, not imported globals.
                o.resources=m.helpers.OneShotHandles(api.close);j=o.run()
            self.assertFalse(j['profile_deleted']);self.assertFalse(j['target_file_closed']);self.assertFalse(j['outer_query_closed'])
            m.validate_result(j,c,parent=b.PARENT,root=root)
    def test_natural_exit_earlier_than_native_alive_observation_rejected(self):
        root,c,api,o,j,v=self.run_case();changed=copy.deepcopy(j);selected=next(t for t in changed['tasks'] if t['name']=='selected')
        selected['exit_observed_qpc']=selected['resume_qpc']
        with self.assertRaisesRegex(ValueError,'mm_natural_exit_alive_causal'):m.validate_result(changed,c,parent=b.PARENT,root=root)
        changed=copy.deepcopy(j);changed['selected_stop_attempted']=True
        with self.assertRaisesRegex(ValueError,'mm_natural_exit_not_controlled_stop'):m.validate_result(changed,c,parent=b.PARENT,root=root)
    def test_physical_marker_before_resume_intent_rejected_after_rehash(self):
        root,c,api,o,j,v=self.run_case();changed=copy.deepcopy(j)
        selected=next(t for t in changed['tasks'] if t['name']=='selected');row=next(r for r in changed['operations'] if r['operation']=='observe')
        d=row['output'];path=root/d['name'];raw=bytearray(path.read_bytes())
        for offset in (7552+232,7872+232):put(raw,offset,selected['resume_intent_qpc']-1,'Q')
        path.write_bytes(raw);row['output']=dict(d,sha256=m.sha(raw))
        old_receipt=row['receipt'];value=m.decode(old_receipt['text'].encode('ascii'));value['data']['output']=row['output'];receipt=m.encode(value)
        replacement=dict(name=old_receipt['name'],text=receipt.decode('ascii'),sha256=m.sha(receipt))
        (root/'returns'/replacement['name']).write_bytes(receipt);row['receipt']=replacement
        changed['returns'][changed['returns'].index(old_receipt)]=replacement
        with self.assertRaisesRegex(ValueError,'mm_marker_resume_causal'):m.validate_result(changed,c,parent=b.PARENT,root=root)
    def test_resume_return_at_original_end_never_enters_observe(self):
        root,c,api,o=self.fixture();resume=api.resume_raw
        def late(h):
            value=resume(h);api.now=o.j['window']['end']-1;return value
        with patch.object(api,'resume_raw',side_effect=late):j=o.run()
        self.assertTrue(o.tasks['selected']['resumed']);self.assertEqual(o.tasks['selected']['resume_qpc'],j['window']['end'])
        self.assertNotIn(('wrapper','observe'),api.calls);self.assertEqual(j['failure'],'resume')
        self.assertEqual(m.decode(j['resume_observation']['text'].encode('ascii'))['data']['count'],1)
        m.validate_result(j,c,parent=b.PARENT,root=root)

if __name__=='__main__':unittest.main()
