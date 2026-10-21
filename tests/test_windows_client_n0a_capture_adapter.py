"""Pure capture composition: no QEMU, sockets, actor or Linux child required."""
import hashlib
import importlib.util
import json
from pathlib import Path
import tempfile
from types import SimpleNamespace
import unittest
from unittest.mock import patch
ROOT=Path(__file__).resolve().parents[1]
def load(name,path):
    spec=importlib.util.spec_from_file_location(name,path);m=importlib.util.module_from_spec(spec);spec.loader.exec_module(m);return m
m=load('capture_adapter_test',ROOT/'.github/windows_n0a_capture_adapter.py')
p=load('packet_fixture',ROOT/'tests/test_windows_client_n0a_packet.py')
def commitment(raw=b'{}'):
    return dict(sha256=hashlib.sha256(raw).hexdigest(),bytes=len(raw),contained_report_sha256='a'*64,ordinary_report_sha256='b'*64)
def facts():
    return dict(drain_complete=True,cleanup_confirmed=True,shutdown_authorized=True,producer_live_at_shutdown=True,
        qemu_exit_observed=True,qemu_exit_code=0,qemu_forced=False,header_verified=True,descriptors_closed=True,
        child_exit_observed=True,child_exit_code=0,child_forced=False,final_status_observed=True,status_eof=True,
        errors=[],capture=dict(fifo_eof=True,stderr_eof=True,overflow=False,structure=True,flushed=True,closed=True,qemu_dump_write_error=False,errors=[]))
def final_inputs():
    original=dict(guest_result_provenance_verified=True,vm_destroyed=True)
    n0a=dict(receipt_verified=True,vm_destroyed=True,original_stage0_receipt_verified=True,
        result=dict(status='observed_connect_denial'),host_receiver=dict(socket_cleanup_confirmed=True,endpoint_error=False,
        receiver_counts=dict(accepted=5,ordinary_verified_frames=5,contained_verified_frames=0,rejected=0,timed_out=0)))
    return original,n0a
class AdmissionTests(unittest.TestCase):
    def test_default_disabled_and_lazy_child(self):
        self.assertIs(m.CAPTURE_EXECUTION_ENABLED,False)
        self.assertNotIn('import windows_n0a_capture_child',Path(m.__file__).read_text())
    def test_actual_payload_boundary_extra_reserve(self):
        baseline=24*1024**3;free=baseline+m.EXTRA_RESERVE
        self.assertTrue(m.admit(24*1024**2,free,baseline)['planning_only'])
        for payload,space in [(24*1024**2+1,free),(24*1024**2,free-1),(True,free),(0,free)]:
            with self.assertRaises(ValueError):m.admit(payload,space,baseline)
    def test_fixed_seed_pins(self):
        c=m.make_configuration({'enabled':True},'a'*40,'52:54:00:12:34:56')
        self.assertEqual(set(c),{'enabled','run_nonce','source_commit','vm_mac'});self.assertEqual(c['vm_mac'],'525400123456')
        for mac in ['ffffffffffff','000000000000','secret']:
            with self.assertRaises(ValueError):m.make_configuration({'enabled':True},'a'*40,mac)
class PairingTests(unittest.TestCase):
    def test_commitment_strict_and_body_exact(self):
        c=commitment();self.assertTrue(m.accept_private_body(b'{}',c))
        for key,value in [('bytes',True),('bytes',65537),('sha256','private'),('contained_report_sha256','x'*64)]:
            bad=dict(c);bad[key]=value;self.assertFalse(m.valid_commitment(bad))
        self.assertFalse(m.accept_private_body(b'[]',c));self.assertFalse(m.accept_private_body('{}',c))
    def test_bad_commitment_preserves_legacy(self):
        legacy={'result':{'status':'connect_succeeded'}}
        envelope=dict(schema_version=2,legacy={},flow_commitment={'secret':'PRIVATE_SENTINEL'})
        with patch.object(m,'helper',return_value=SimpleNamespace(validate_host_n0a_envelope=lambda a,b:legacy)):
            result=m.validate_capture_envelope(envelope,{})
        self.assertEqual(result['legacy'],legacy);self.assertTrue(result['commitment_error'])
        self.assertNotIn('PRIVATE_SENTINEL',json.dumps(result))
    def test_wrapper_strict_bound(self):
        for value in [dict(schema_version=True,legacy={},flow_commitment=None),dict(schema_version=2,legacy={},flow_commitment=None,extra=1),
                      dict(schema_version=2,legacy={'secret':'x'*4096},flow_commitment=None)]:
            with self.assertRaises(ValueError):m.validate_capture_envelope(value,{})
    def test_actual_control_loader_and_empty_report(self):
        control=m.helper('control');default=control.default_host_n0a()
        legacy=dict(schema_version=1,case_nonce='a'*32,actor_sha256='b'*64,report=None,launcher=default['launcher'])
        result=m.validate_capture_envelope(dict(schema_version=2,legacy=legacy,flow_commitment=None),legacy)
        self.assertFalse(result['legacy']['receipt_verified'])
class WireTests(unittest.TestCase):
    def test_full_capture_wrapper_worst_valid_legacy_composition(self):
        import copy,itertools
        fixtures=load('capture_wire_fixture',ROOT/'tests/test_windows_client_n0a_adapter.py')
        engine=fixtures.engine;value=fixtures.envelope();longest={}
        flags=('profile_verified','controls_verified','window_overlap_verified','connect_success_observed')
        for status,bits,count in itertools.product(('inconclusive','connect_succeeded','observed_connect_denial'),itertools.product((False,True),repeat=4),range(4)):
            row=dict(zip(flags,bits),status=status,explicit_denials=count)
            result=copy.deepcopy(value['report']['result']);result.update(status=status,endpoints={name:dict(row) for name in engine.ENDPOINTS})
            try:engine.closed_result(result)
            except ValueError:continue
            if status not in longest or len(json.dumps(row))>len(json.dumps(longest[status])):longest[status]=row
        value['launcher'].update(phase=max(engine.LAUNCHER_PHASES,key=len),failure=max(engine.LAUNCHER_FAILURES,key=len),python_exit_code=-2147483648,process_exit_confirmed=False,timed_out=False,budget_exhausted=False)
        value['report']['execution'].update(phase=max(engine.EXECUTION_PHASES,key=len),failed=False,cleanup_confirmed=False)
        value['report']['receiver'].update(socket_cleanup_confirmed=False,endpoint_error=False)
        value['report']['receiver']['receiver_counts'].update(ordinary_verified_frames=100,contained_verified_frames=28)
        maximum=0
        for left,right in itertools.product(longest,longest):
            result=value['report']['result'];result['endpoints']={'guest':longest[left],'runner':longest[right]}
            result['status']='connect_succeeded' if 'connect_succeeded' in (left,right) else ('observed_connect_denial' if left==right=='observed_connect_denial' else 'inconclusive')
            for present,exitcode,seen in itertools.product((False,True),(None,-2147483648,2147483647),(None,False,True)):
                legacy=copy.deepcopy(value)
                if not present:legacy['report']=None
                legacy['launcher'].update(python_exit_code=exitcode,process_exit_confirmed=seen)
                c=commitment();c['bytes']=65536
                wire=dict(schema_version=2,legacy=legacy,flow_commitment=c)
                maximum=max(maximum,len(json.dumps(wire).encode()))
                m.validate_capture_envelope(wire,legacy)
        self.assertEqual(maximum,2017)
        self.assertLessEqual(maximum,4096)

class CompositionTests(unittest.TestCase):
    def parse(self,*,selected=False,changes=None,capacity=False):
        manifest,expected=p.bound(p.manifest());raw=b'{}'
        data=p.pcap(([p.frame(50000)] if selected else [])+[p.frame(51000+i) for i in range(4)])
        f=facts();f.update(changes or {})
        flow=SimpleNamespace(normalize=lambda raw,e:dict(manifest_bytes=manifest,expected=expected,controls_verified=True))
        original_helper=m.helper
        with tempfile.TemporaryDirectory() as root:
            path=Path(root)/'capture.pcap';path.write_bytes(data)
            with patch.object(m,'helper',side_effect=lambda name:flow if name=='flow' else original_helper(name)):
                return m.parse_before_cleanup(path,f,raw,{'flow_commitment':commitment(raw)},
                    header_before_link=True,terminal_before_shutdown=True,capacity_abort=capacity)
    def test_actual_packet_absence_then_cleanup_qualification(self):
        result=self.parse();self.assertEqual(result['status'],'no_selected_tuple_observed')
        original,n0a=final_inputs();self.assertEqual(m.qualify(result,original,n0a)['status'],'no_selected_tuple_observed')
        for target,key,value in [('original','vm_destroyed',False),('original','guest_result_provenance_verified',False),('n0a','receipt_verified',False),('n0a','host_receiver',None)]:
            a,b=final_inputs();(a if target=='original' else b)[key]=value
            qualified=m.qualify(result,a,b)
            self.assertEqual(qualified['status'],'inconclusive')
            self.assertEqual(qualified['packet']['status'],'inconclusive')
            self.assertIn('host_prerequisites',qualified['packet']['reasons'])
        self.assertEqual(result['status'],'no_selected_tuple_observed')
    def test_positive_tuple_retained_under_uncertainty(self):
        for change in [{},{'drain_complete':False},{'qemu_forced':True}]:
            result=self.parse(selected=True,changes=change)
            self.assertTrue(result['tuple_packet_observed']);self.assertTrue(m.qualify(result,{},{} )['tuple_packet_observed'])
        self.assertEqual(m.qualify(self.parse(selected=True),{},{} )['status'],'tuple_packet_observed')
    def test_inconsistent_complete_unknown_exit_fd_ipc_and_natural_exit(self):
        for key,value in [('drain_complete',False),('cleanup_confirmed',False),('producer_live_at_shutdown',False),
                          ('qemu_exit_code',True),('qemu_forced',True),('child_exit_observed',False),('header_verified',False),
                          ('final_status_observed',False),('status_eof',False),('child_exit_code',1),('child_forced',True),
                          ('descriptors_closed',False),('errors',['ipc'])]:
            with self.subTest(key=key):self.assertEqual(self.parse(changes={key:value})['status'],'inconclusive')
        self.assertEqual(self.parse(capacity=True)['status'],'inconclusive')
    def test_missing_header_or_terminal_not_invented_from_final(self):
        for key in ['header_before_link','terminal_before_shutdown']:
            args=dict(header_before_link=True,terminal_before_shutdown=True,capacity_abort=False);args[key]=False
            result=m.capture_contract(p.pcap([]),facts(),**args)
            self.assertFalse(result['header_before_cases' if key=='header_before_link' else 'shutdown_after_terminal'])
    def test_missing_flow_no_raw_error(self):
        result=m.parse_before_cleanup(Path('PRIVATE_SENTINEL'),{},None,{},header_before_link=False,terminal_before_shutdown=False)
        self.assertEqual(result['reason'],'flow');self.assertNotIn('PRIVATE_SENTINEL',json.dumps(result))
    def test_file_bounds_regular_and_growing_same_inode(self):
        with tempfile.TemporaryDirectory() as root:
            path=Path(root)/'capture';path.write_bytes(b'x'*23)
            with self.assertRaises(ValueError):m.read_capture(path)
            with self.assertRaises(ValueError):m.read_capture(Path(root))
            path.write_bytes(b'x'*24);self.assertEqual(m.read_capture(path),b'x'*24)
            original=m.os.read;calls=[]
            def grow(fd,n):
                if not calls:
                    calls.append(True)
                    with path.open('ab') as handle:handle.write(b'!')
                return original(fd,n)
            with patch.object(m.os,'read',side_effect=grow),self.assertRaises(ValueError):m.read_capture(path)
            with patch.object(m,'MAX_CAPTURE',24),self.assertRaises(ValueError):m.read_capture(path)
    def test_binary_capture_all_octets_and_platform_flag(self):
        data=b'A\r\n'+bytes(range(256))*2
        with tempfile.TemporaryDirectory() as root:
            path=Path(root)/'capture';path.write_bytes(data)
            old_fd=m.os.open(path,m.os.O_RDONLY | getattr(m.os,'O_NOFOLLOW',0))
            try:old_data=m.os.read(old_fd,len(data))
            finally:m.os.close(old_fd)
            if m.os.name == 'nt':
                self.assertNotEqual(old_data,data,'legacy CRT flags unexpectedly preserved all octets')
                self.assertEqual(old_data,b'A\n'+bytes(range(26)),'legacy text EOF/CRLF discriminator changed')
            self.assertEqual(m.read_capture(path),data)
            actual_open=m.os.open;binary=getattr(m.os,'O_BINARY',0x80000000);seen=[]
            def check_open(path,flags):
                seen.append(flags)
                self.assertEqual(flags & binary,binary)
                # Linux fixture exercises flagselection without passing a foreign
                # CRT flag to Linux; Windows retains its actual binary flag.
                native_flags=flags if hasattr_original else flags & ~binary
                return actual_open(path,native_flags)
            hasattr_original=hasattr(m.os,'O_BINARY')
            with patch.object(m.os,'O_BINARY',binary,create=True),patch.object(m.os,'open',side_effect=check_open):
                self.assertEqual(m.read_capture(path),data)
            self.assertEqual(len(seen),1)

    def test_read_close_error_detaches_number_no_retry_and_blocks_cleanup(self):
        original=m.os.close;replacement=[];closed_numbers=[]
        with tempfile.TemporaryDirectory() as root:
            path=Path(root)/'capture';path.write_bytes(b'x'*24)
            def close_error(fd):
                closed_numbers.append(fd)
                original(fd)
                replacement.append(m.os.open(path,m.os.O_RDONLY))
                raise OSError('PRIVATE_SENTINEL')
            with patch.object(m.os,'close',side_effect=close_error) as close:
                with self.assertRaises(m.CaptureReadCloseError):m.read_capture(path)
                self.assertEqual(close.call_count,1)
            self.assertEqual(replacement[0],closed_numbers[0])
            self.assertEqual(m.os.read(replacement[0],1),b'x')
            original(replacement[0])
        manifest,expected=p.bound(p.manifest())
        fake=SimpleNamespace(normalize=lambda a,b:dict(manifest_bytes=manifest,expected=expected))
        with patch.object(m,'helper',return_value=fake),patch.object(m,'read_capture',side_effect=m.CaptureReadCloseError('PRIVATE_SENTINEL')):
            result=m.parse_before_cleanup(Path('unused'),facts(),b'{}',{'flow_commitment':commitment()},header_before_link=True,terminal_before_shutdown=True)
        self.assertIs(result['capture_read_cleanup_confirmed'],False)
        self.assertNotIn('PRIVATE_SENTINEL',json.dumps(result))

    def test_actual_flow_commitment_network_controls_and_packet_pipeline(self):
        fixture=load('capture_full_flow_fixture',ROOT/'tests/test_windows_client_n0a_flow.py')
        for count in (3,40):
            _,_,raw,expected=fixture.make(count)
            normalized=m.helper('flow').normalize(raw,expected)
            manifest=json.loads(normalized['manifest_bytes'])
            frames=[p.frame(row['source_port'],dport=expected['endpoint']['destination_port']) for row in manifest['ordinary']]
            with tempfile.TemporaryDirectory() as root:
                path=Path(root)/'capture.pcap';path.write_bytes(p.pcap(frames))
                result=m.parse_before_cleanup(path,facts(),raw,expected,header_before_link=True,terminal_before_shutdown=True)
                self.assertEqual(result['status'],'no_selected_tuple_observed',json.dumps(result,sort_keys=True))
                self.assertTrue(result['packet']['ordinary_syn_controls'])
                bad=dict(expected);bad['controller_result']={'receipt_verified':False}
                result=m.parse_before_cleanup(path,facts(),raw,bad,header_before_link=True,terminal_before_shutdown=True)
                self.assertEqual(result['status'],'inconclusive')
                self.assertFalse(result['packet']['connect_controls_contract'])
                frames.insert(0,p.frame(manifest['selected'][0]['source_port'],dport=expected['endpoint']['destination_port']))
                path.write_bytes(p.pcap(frames))
                f=facts();f['qemu_forced']=True;f['drain_complete']=False
                result=m.parse_before_cleanup(path,f,raw,expected,header_before_link=True,terminal_before_shutdown=True)
                self.assertTrue(result['tuple_packet_observed']);self.assertEqual(result['status'],'inconclusive')

    def test_closed_output_contains_no_private_bindings(self):
        output=json.dumps(self.parse(selected=True))
        for raw in ['source_port','manifest_sha256','actor_sha256','capture.pcap','525400123456']:self.assertNotIn(raw,output)
        self.assertLess(len(output.encode()),4096)
class EndpointDeadlineTests(unittest.TestCase):
    def test_default_join_unchanged_and_optional_absolute_clipped(self):
        from unittest.mock import Mock
        import threading
        control=m.helper('control')
        for deadline,expected in [(None,1),(10.25,.25),(9,0)]:
            endpoint=control.NonceEndpoint.__new__(control.NonceEndpoint)
            endpoint.stop=threading.Event();endpoint.connection=None;endpoint.listener=None
            endpoint.thread=Mock();endpoint.thread.is_alive.return_value=False
            endpoint.error=False;endpoint.counts={}
            with patch.object(control.time,'monotonic',return_value=10):
                result=endpoint.finish(deadline=deadline)
            endpoint.thread.join.assert_called_once_with(expected)
            self.assertTrue(result['socket_cleanup_confirmed'])
    def test_exhausted_live_thread_never_cleanup_or_counts(self):
        from unittest.mock import Mock
        import threading
        control=m.helper('control');endpoint=control.NonceEndpoint.__new__(control.NonceEndpoint)
        endpoint.stop=threading.Event();endpoint.connection=None;endpoint.listener=None
        endpoint.thread=Mock();endpoint.thread.is_alive.return_value=True
        endpoint.error=False;endpoint.counts={'accepted':2}
        with patch.object(control.time,'monotonic',return_value=10):result=endpoint.finish(deadline=9)
        self.assertFalse(result['socket_cleanup_confirmed']);self.assertIsNone(result['receiver_counts'])

if __name__=='__main__':unittest.main()
