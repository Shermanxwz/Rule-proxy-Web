"""Synthetic UDP bytes and caller contracts only; no socket/capture/guest execution."""
import copy
import hashlib
import importlib.util
import json
from pathlib import Path
import struct
import unittest
from unittest.mock import patch

PATH=Path(__file__).resolve().parents[1]/'.github/windows_n0a_udp6_packet.py'
spec=importlib.util.spec_from_file_location('udp6_packet',PATH)
p=importlib.util.module_from_spec(spec);spec.loader.exec_module(p)
MAC=bytes.fromhex('525400123456')

def manifest(samples=2):
    binding={k:'a'*(32 if k.endswith('nonce') else 40 if k=='source_commit' else 64)
             for k in p.BINDING_KEYS-{'build','ubr'}}
    binding.update(build=26300,ubr=9457)
    rows=[('before',0)]+[('sample',i) for i in range(samples)]+[('after',0)]
    return dict(schema_version=1,protocol='udp6',binding=binding,
                endpoint=dict(vm_mac=MAC.hex(),destination_ipv6='fec0::2',scope_id=0,destination_port=4444),
                selected=[dict(index=i,source_port=50000+i,send_invoked=True) for i in range(3)],
                ordinary=[dict(phase=phase,index=index,source_port=51000+n,send_invoked=True,nonce_verified=True)
                          for n,(phase,index) in enumerate(rows)])

def bound(m):
    raw=json.dumps(m,separators=(',',':')).encode()
    return raw,dict(binding=copy.deepcopy(m['binding']),endpoint=copy.deepcopy(m['endpoint']),
                    manifest_sha256=hashlib.sha256(raw).hexdigest(),controls_verified=True,cleanup_verified=True)

DST=bytes.fromhex('fec00000000000000000000000000002')
SRC=bytes.fromhex('fec0000000000000000000000000000f')
def frame(port,body,mac=MAC,dst=DST,dport=4444,src=SRC,extensions=()):
    tail=struct.pack('!HHHH',port,dport,8+len(body),0)+body;next_header=17
    for kind,size in reversed(extensions):
        header=bytes([next_header,size//4-2 if kind==51 else size//8-1])+b'\0'*(size-2)
        tail=header+tail;next_header=kind
    ip=struct.pack('!IHBB16s16s',6<<28,len(tail),next_header,64,src,dst)
    return b'\x52\x54\0\xaa\xbb\xcc'+mac+b'\x86\xdd'+ip+tail

def frames(m):
    return [frame(r['source_port'],p.payload(m['binding']['case_nonce'],r['phase'],r['index'])) for r in m['ordinary']]

def selected(m,index=0,port=None):
    row=m['selected'][index]
    return frame(row['source_port'] if port is None else port,p.payload(m['binding']['case_nonce'],'contained',index))

def pcap(fs,endian='<',nano=False,snaplen=262144,link=1):
    header=struct.pack(endian+'IHHIIII',0xa1b23c4d if nano else 0xa1b2c3d4,2,4,0,0,snaplen,link)
    return header+b''.join(struct.pack(endian+'IIII',1,i,len(f),len(f))+f for i,f in enumerate(fs))

def capture(data):
    return dict(sha256=hashlib.sha256(data).hexdigest(),bytes=len(data),
                **{k:True for k in p.POSITIVE_CAPTURE},**{k:False for k in p.NEGATIVE_CAPTURE},
                sink_status='complete',sink_exit_code=0)

def run(m=None,data=None,fs=None,change=None):
    m=manifest() if m is None else m;raw,expected=bound(m)
    data=pcap(frames(m) if fs is None else fs) if data is None else data
    c=capture(data)
    if change:change(expected,c)
    return p.evaluate(data,raw,expected,c)

class Udp6PacketTests(unittest.TestCase):
    def test_absence_contract_not_api_denial(self):
        r=run();self.assertTrue(r['bounded_no_selected_udp_datagram'])
        self.assertFalse(r['actor_attribution_established']);self.assertFalse(r['isolation_acceptance'])
        self.assertNotIn('send_accepted',json.dumps(r));self.assertNotIn('10013',json.dumps(r))
    def test_selected_payload_positive(self):
        m=manifest();r=run(m,fs=frames(m)+[selected(m)])
        self.assertTrue(r['selected_payload_observed']);self.assertTrue(r['selected_bound_payload_observed'])
        self.assertFalse(r['bounded_no_selected_udp_datagram'])
    def test_typed_negative_control_preserves_positive(self):
        m=manifest();m['ordinary'][1]['nonce_verified']=False
        r=run(m,fs=frames(m)+[selected(m)])
        self.assertTrue(r['selected_payload_observed']);self.assertIn('ordinary_payload',r['reasons'])
    def test_uninvoked_unavailable_ports_preserve_other_positive(self):
        for group in ('selected','ordinary'):
            m=manifest();m[group][1].update(source_port=None,send_invoked=False)
            fs=[f for i,f in enumerate(frames(manifest())) if group!='ordinary' or i!=1]
            r=run(m,fs=fs+[selected(m)])
            self.assertTrue(r['selected_bound_payload_observed'])
            self.assertFalse(r['ports_complete']);self.assertTrue(r['ports_unique'])
            self.assertIn('port_unavailable',r['reasons'])
            self.assertFalse(r['bounded_no_selected_udp_datagram'])
        for value in (None,0):
            m=manifest();m['selected'][1]['source_port']=value;raw,e=bound(m)
            with self.assertRaises(ValueError):p.validate_manifest(raw,e)
        m=manifest();m['ordinary'][0].update(source_port=0,send_invoked=False);raw,e=bound(m)
        with self.assertRaises(ValueError):p.validate_manifest(raw,e)

    def test_all_selected_invocations_required(self):
        for i in range(3):
            m=manifest();m['selected'][i]['send_invoked']=False
            r=run(m);self.assertFalse(r['bounded_no_selected_udp_datagram']);self.assertIn('send_unattempted',r['reasons'])
    def test_all_ordinary_rows_retained(self):
        m=manifest(40);r=run(m);self.assertTrue(r['bounded_no_selected_udp_datagram'])
        self.assertEqual(r['records'],42)
        m['ordinary'][20]['send_invoked']=False
        self.assertFalse(run(m)['bounded_no_selected_udp_datagram'])
    def test_schema_bounds_and_types(self):
        for mutate in (lambda m:m.update(extra=True),lambda m:m['binding'].update(build=True),
                       lambda m:m['selected'][0].update(send_invoked=1),lambda m:m['ordinary'][0].update(nonce_verified=1),
                       lambda m:m['ordinary'][-1].update(index=41),lambda m:m['endpoint'].update(destination_ipv6='::ffff:10.0.2.2'),
                       lambda m:m['endpoint'].update(vm_mac='ffffffffffff'),lambda m:m['selected'].pop()):
            m=manifest();mutate(m);raw,e=bound(m)
            with self.assertRaises(ValueError):p.validate_manifest(raw,e)
        with self.assertRaises(ValueError):p.validate_manifest(b' '*(p.MAX_MANIFEST+1),{})
        m=manifest(41);raw,e=bound(m)
        with self.assertRaises(ValueError):p.validate_manifest(raw,e)
    def test_duplicate_json_keys(self):
        raw,e=bound(manifest());raw=raw.replace(b'"schema_version":1',b'"schema_version":1,"schema_version":1')
        e['manifest_sha256']=hashlib.sha256(raw).hexdigest()
        with self.assertRaises(ValueError):p.validate_manifest(raw,e)
    def test_binding_failure_no_scoped_observation(self):
        m=manifest();raw,e=bound(m);data=pcap([selected(m)])
        for key,value in [('manifest_sha256','0'*64),('controls_verified',1),('cleanup_verified',None)]:
            changed=copy.deepcopy(e);changed[key]=value
            r=p.evaluate(data,raw,changed,capture(data));self.assertIsNone(r['selected_payload_observed'])
        e['binding']['actor_sha256']='b'*64
        self.assertIsNone(p.evaluate(data,raw,e,capture(data))['selected_payload_observed'])
    def test_expected_controls_cleanup_false_preserve_bytes(self):
        m=manifest()
        for key in ('controls_verified','cleanup_verified'):
            r=run(m,fs=frames(m)+[selected(m)],change=lambda e,c:e.update({key:False}))
            self.assertTrue(r['selected_payload_observed']);self.assertEqual(r['status'],'inconclusive')
    def test_capture_hash_mismatch_retains_only_bytes(self):
        m=manifest();r=run(m,fs=frames(m)+[selected(m)],change=lambda e,c:c.update(sha256='0'*64))
        self.assertTrue(r['selected_payload_observed']);self.assertFalse(r['capture_complete_contract'])
        self.assertFalse(r['actor_attribution_established'])
    def test_all_capture_lifecycle_fields(self):
        for key in p.POSITIVE_CAPTURE|p.NEGATIVE_CAPTURE:
            r=run(change=lambda e,c:c.update({key:not c[key]}));self.assertFalse(r['bounded_no_selected_udp_datagram'])
        for key,val in [('sink_exit_code',False),('sink_status','partial'),('bytes',24),('overflow',0)]:
            self.assertFalse(run(change=lambda e,c:c.update({key:val}))['bounded_no_selected_udp_datagram'])
    def test_port_reuse_all_roles(self):
        for mutate in (lambda m:m['selected'][1].update(source_port=50000),
                       lambda m:m['ordinary'][1].update(source_port=51000),
                       lambda m:m['ordinary'][1].update(source_port=50000)):
            m=manifest();mutate(m);r=run(m,fs=frames(m)+[selected(m)])
            self.assertTrue(r['selected_payload_observed']);self.assertIn('port_collision',r['reasons'])
    def test_wrong_port_selected_payload_is_unbound_observation(self):
        m=manifest();r=run(m,fs=frames(m)+[selected(m,port=59999)])
        self.assertTrue(r['selected_payload_observed']);self.assertFalse(r['selected_bound_payload_observed'])
        self.assertIn('unknown_flow',r['reasons']);self.assertIn('payload_port_mismatch',r['reasons'])
    def test_wrong_payload_and_unknown_flow(self):
        m=manifest()
        for port,body in [(50000,b'wrong'),(59999,b'wrong'),(51000,b'wrong')]:
            r=run(m,fs=frames(m)+[frame(port,body)]);self.assertIn('payload_mismatch',r['reasons'])
            self.assertFalse(r['bounded_no_selected_udp_datagram'])
    def test_nonce_phase_index_exact(self):
        m=manifest()
        for body in (p.payload('b'*32,'contained',0),p.payload('a'*32,'sample',0),
                     b'N0AU6 '+b'a'*32+b' contained 00\n',p.payload('a'*32,'contained',0)+b'x'):
            r=run(m,fs=frames(m)+[frame(50000,body)]);self.assertFalse(r['selected_payload_observed'])
            self.assertFalse(r['bounded_no_selected_udp_datagram'])
    def test_terminal_control_required_and_last(self):
        m=manifest();fs=frames(m)
        for sequence in (fs[:-1],fs[-1:]+fs[:-1]):
            self.assertIn('ordinary_payload',run(m,fs=sequence)['reasons'])
    def test_positive_then_truncated(self):
        m=manifest();data=pcap(frames(m)+[selected(m)])+b'\0'
        r=run(m,data=data);self.assertTrue(r['selected_payload_observed']);self.assertIn('truncated',r['reasons'])
    def test_empty_not_absence(self):
        self.assertFalse(run(data=pcap([]))['bounded_no_selected_udp_datagram'])
    def test_endian_and_timestamp_forms(self):
        for endian in ('<','>'):
            for nano in (True,False):self.assertTrue(run(data=pcap(frames(manifest()),endian,nano))['bounded_no_selected_udp_datagram'])
    def test_header_and_record_bounds(self):
        for data in (b'',b'x'*24,pcap([],link=101),pcap([],snaplen=262145),pcap(frames(manifest()))[:-1]):
            self.assertFalse(run(data=data)['bounded_no_selected_udp_datagram'])
        with patch.object(p,'MAX_PCAP',25):self.assertIn('capture_bound',run()['reasons'])
        with patch.object(p,'MAX_RECORDS',1):self.assertIn('record_bound',run()['reasons'])
        with patch.object(p,'MAX_FRAME',14):self.assertIn('frame_bound',run()['reasons'])
    def test_capture_truncated_record(self):
        data=bytearray(pcap(frames(manifest())));struct.pack_into('<I',data,36,999)
        self.assertIn('truncated',run(data=bytes(data))['reasons'])
    def test_fragments_atomic_noninitial_and_vlan(self):
        m=manifest();body=p.payload('a'*32,'contained',0)
        for bits in (0,1,8):
            raw=bytearray(frame(50000,body,extensions=((44,8),)));struct.pack_into('!H',raw,56,bits)
            self.assertIn('fragment',run(m,fs=frames(m)+[bytes(raw)])['reasons'])
        raw=bytearray(frame(50000,body));raw[12:14]=b'\x81\0'
        self.assertIn('encapsulation',run(m,fs=frames(m)+[bytes(raw)])['reasons'])
    def test_udp_ipv6_lengths_and_no_jumbo(self):
        m=manifest();raw=frame(50000,p.payload('a'*32,'contained',0))
        for offset,value in [(58,7),(58,9),(18,0),(18,65535),(18,1)]:
            broken=bytearray(raw);struct.pack_into('!H',broken,offset,value)
            self.assertFalse(run(m,fs=frames(m)+[bytes(broken)])['bounded_no_selected_udp_datagram'])
        self.assertFalse(run(m,fs=frames(m)+[raw+b'\0'])['bounded_no_selected_udp_datagram'])
    def test_supported_extensions_and_no_source_address_constraint(self):
        m=manifest()
        for chain in (((0,8),),((60,8),),((43,8),),((51,16),),((0,8),(43,8),(60,8),(51,16))):
            fs=[frame(r['source_port'],p.payload('a'*32,r['phase'],r['index']),src=b'\x20\x01'+b'\0'*14,extensions=chain) for r in m['ordinary']]
            self.assertTrue(run(m,fs=fs)['bounded_no_selected_udp_datagram'],chain)
        self.assertTrue(run(m,fs=[frame(r['source_port'],p.payload('a'*32,r['phase'],r['index']),src=b'\0'*16) for r in m['ordinary']])['bounded_no_selected_udp_datagram'])
    def test_extension_count_and_byte_bounds(self):
        m=manifest();body=p.payload('a'*32,'contained',0)
        for chain in (((60,8),)*9,((60,264),)):
            self.assertIn('extension_bound',run(m,fs=frames(m)+[frame(50000,body,extensions=chain)])['reasons'])
        for chain in (((60,8),)*8,((60,256),)):
            self.assertTrue(run(m,fs=frames(m)+[frame(50000,body,extensions=chain)])['selected_bound_payload_observed'])
    def test_extension_malformed_hop_order_routing_opaque(self):
        m=manifest();body=p.payload('a'*32,'contained',0)
        self.assertIn('hop_order',run(m,fs=frames(m)+[frame(50000,body,extensions=((60,8),(0,8)))])['reasons'])
        raw=bytearray(frame(50000,body,extensions=((43,8),)));raw[57]=1
        self.assertIn('routing_unsupported',run(m,fs=frames(m)+[bytes(raw)])['reasons'])
        for kind in (50,6,58,59,253):
            raw=bytearray(frame(50000,body));raw[20]=kind
            self.assertIn('opaque_protocol',run(m,fs=frames(m)+[bytes(raw)])['reasons'])
        for kind in (0,60,43,51):
            raw=bytearray(frame(50000,body,extensions=((kind,16),)));raw[55]=255
            self.assertIn('extension',run(m,fs=frames(m)+[bytes(raw)])['reasons'])
        raw=bytearray(frame(50000,body,extensions=((51,16),)));raw[55]=0
        self.assertIn('extension',run(m,fs=frames(m)+[bytes(raw)])['reasons'])
    def test_prior_selected_survives_later_opaque_fragment_and_cleanup_failure(self):
        m=manifest();opaque=bytearray(frame(59999,b'x'));opaque[20]=50
        data=pcap(frames(m)+[selected(m),bytes(opaque),frame(59999,b'x',extensions=((44,8),))])
        r=run(m,data=data,change=lambda e,c:e.update(cleanup_verified=False))
        self.assertTrue(r['selected_bound_payload_observed']);self.assertEqual(r['status'],'inconclusive')
        self.assertIn('fragment',r['reasons']);self.assertIn('opaque_protocol',r['reasons'])
    def test_unrelated_arp_ipv4_ndp_other_mac_ignored(self):
        m=manifest();arp=bytearray(frame(59999,b'x'));arp[12:14]=b'\x08\x06'
        v4=bytearray(arp);v4[12:14]=b'\x08\0'
        ndp=bytearray(frame(59999,b'x',dst=bytes.fromhex('ff020000000000000000000000000001')));ndp[20]=58
        self.assertTrue(run(m,fs=frames(m)+[bytes(arp),bytes(v4),bytes(ndp),frame(59999,b'x',mac=b'\x02'*6)])['bounded_no_selected_udp_datagram'])
    def test_scope_protocol_mapped_ipv4_and_types(self):
        for mutate in (lambda m:m.update(protocol='udp'),lambda m:m['endpoint'].update(scope_id=True),lambda m:m['endpoint'].update(scope_id=1),lambda m:m['endpoint'].update(destination_ipv6='FEC0::2')):
            m=manifest();mutate(m);raw,e=bound(m)
            with self.assertRaises(ValueError):p.validate_manifest(raw,e)
        m=manifest();r=run(m,fs=frames(m)+[frame(50000,b'N0AU1 '+b'a'*32+b' contained 0\n')]);self.assertFalse(r['selected_payload_observed'])
    def test_closed_public_output(self):
        r=run();text=json.dumps(r)
        for forbidden in ('a'*32,MAC.hex(),'fec0::2','51000','source_port','N0AU6'):self.assertNotIn(forbidden,text)
        self.assertFalse(r['checksums_validated']);self.assertFalse(r['qpc_timestamp_mapping_used'])

    def diagnostic(self,result):
        diagnostic=result['decoder_diagnostic']
        self.assertEqual(set(diagnostic),{'v','opaque_next_header_counts','truncated_counts',
                                         'omitted_category_count','omitted_event_count','detail_complete'})
        self.assertIs(type(diagnostic['v']),int);self.assertEqual(diagnostic['v'],1)
        opaque=diagnostic['opaque_next_header_counts'];truncated=diagnostic['truncated_counts']
        self.assertIs(type(opaque),list);self.assertLessEqual(len(opaque),16)
        self.assertTrue(all(type(row)is list and len(row)==2 and type(row[0])is int
                            and 0<=row[0]<=255 and type(row[1])is int and 1<=row[1]<=p.MAX_RECORDS for row in opaque))
        self.assertEqual([row[0] for row in opaque],sorted({row[0] for row in opaque}))
        self.assertLessEqual(sum(row[1] for row in opaque)+diagnostic['omitted_event_count'],result['records'])
        self.assertIs(type(diagnostic['detail_complete']),bool)
        self.assertEqual(diagnostic['detail_complete'],diagnostic['omitted_category_count']==0)
        self.assertIs(type(truncated),list);self.assertEqual(len(truncated),3)
        self.assertTrue(all(type(n)is int for n in truncated))
        self.assertIn(truncated[0],(0,1));self.assertIn(truncated[2],(0,1))
        self.assertTrue(0<=truncated[1]<=p.MAX_RECORDS)
        self.assertLessEqual(truncated[1],result['records']+1)
        return diagnostic

    def test_diagnostic_null_only_before_decode_attempt(self):
        m=manifest();raw,expected=bound(m);data=pcap(frames(m));c=capture(data)
        for bad in (b'bad',raw+b' '):
            result=p.evaluate(data,bad,expected,c)
            self.assertIsNone(result['decoder_diagnostic'])
        for data in (b'',b'invalid header',pcap([])):
            result=run(data=data);d=self.diagnostic(result)
            self.assertEqual(d['opaque_next_header_counts'],[])
            self.assertEqual(d['truncated_counts'],[0,0,0])

    def test_exact_all_opaque_header_enums_and_only_targeted_branch(self):
        m=manifest();fs=frames(m)+[selected(m)]
        unsupported=set(range(256))-{0,43,60,51,44,17}
        for value in sorted(unsupported):
            raw=bytearray(frame(59999,b'unrelated'));raw[20]=value;fs.append(bytes(raw))
        for value in (6,50,58,59,253):
            raw=bytearray(frame(59999,b'unrelated'));raw[20]=value;fs.append(bytes(raw))
        result=run(m,fs=fs);d=self.diagnostic(result)
        expected=[[value,1+int(value in (6,50,58,59,253))] for value in sorted(unsupported)]
        self.assertEqual(d['opaque_next_header_counts'],expected[:16])
        self.assertEqual(d['omitted_category_count'],len(expected)-16)
        self.assertEqual(d['omitted_event_count'],sum(row[1] for row in expected[16:]))
        self.assertFalse(d['detail_complete'])
        self.assertTrue(result['selected_bound_payload_observed'])
        self.assertEqual(result['unknown_flow_packets'],0)
        self.assertFalse(result['bounded_no_selected_udp_datagram'])
        # Other source MAC/destination never reaches the opaque branch.
        ignored=[]
        for raw in (bytearray(frame(59999,b'x',mac=b'\x02'*6)),
                    bytearray(frame(59999,b'x',dst=b'\xff\x02'+b'\0'*14))):
            raw[20]=58;ignored.append(bytes(raw))
        clean=run(m,fs=frames(m)+ignored)
        self.assertEqual(self.diagnostic(clean)['opaque_next_header_counts'],[])

    def test_common_opaque_categories_are_individually_exact(self):
        m=manifest();fs=frames(m)+[selected(m)]
        for value in (6,50,58,59,253,253):
            raw=bytearray(frame(59999,b'unrelated'));raw[20]=value;fs.append(bytes(raw))
        result=run(m,fs=fs);d=self.diagnostic(result)
        self.assertEqual(d['opaque_next_header_counts'],[[6,1],[50,1],[58,1],[59,1],[253,2]])
        self.assertTrue(d['detail_complete']);self.assertEqual(d['omitted_event_count'],0)
        self.assertTrue(result['selected_bound_payload_observed'])
        self.assertIn('opaque_protocol',result['reasons'])
        self.assertFalse(result['bounded_no_selected_udp_datagram'])

    def test_opaque_after_supported_extension_counts_final_enum(self):
        m=manifest();raw=bytearray(frame(59999,b'x',extensions=((60,8),)))
        raw[54]=58
        result=run(m,fs=frames(m)+[bytes(raw)])
        d=self.diagnostic(result)
        self.assertEqual(d['opaque_next_header_counts'],[[58,1]])

    def test_three_truncation_branches_and_unconsumed_record(self):
        m=manifest();base=pcap(frames(m)+[selected(m)])
        header=run(m,data=base+b'\0')
        self.assertEqual(self.diagnostic(header)['truncated_counts'],[1,0,0])
        body=run(m,data=pcap(frames(m)+[selected(m),frame(59999,b'x'*100)])[:-1])
        self.assertEqual(self.diagnostic(body)['truncated_counts'],[0,0,1])
        raw=bytearray(pcap([selected(m)]));captured=struct.unpack_from('<I',raw,32)[0]
        struct.pack_into('<I',raw,36,captured+1)
        mismatch=run(m,data=bytes(raw))
        self.assertEqual(self.diagnostic(mismatch)['truncated_counts'],[0,1,0])
        self.assertTrue(mismatch['selected_bound_payload_observed'])
        both=run(m,data=bytes(raw[:-1]))
        self.assertEqual(both['records'],0)
        self.assertEqual(self.diagnostic(both)['truncated_counts'],[0,1,1])
        for result in (header,body,mismatch,both):
            self.assertIn('truncated',result['reasons'])
            self.assertFalse(result['bounded_no_selected_udp_datagram'])
        self.assertTrue(header['selected_bound_payload_observed'])
        self.assertTrue(body['selected_bound_payload_observed'])

    def test_capped_prefix_is_not_record_aligned_and_counters_are_bounded(self):
        m=manifest();full=pcap([frame(59999,b'x'*1000)])
        result=run(m,data=full[:64])
        self.assertEqual(self.diagnostic(result)['truncated_counts'],[0,0,1])
        self.assertFalse(result['bounded_no_selected_udp_datagram'])
        raw=bytearray(frame(59999,b'x'));raw[20]=6
        with patch.object(p,'MAX_RECORDS',2):
            result=run(m,fs=[bytes(raw)]*3)
            self.assertEqual(self.diagnostic(result)['opaque_next_header_counts'],[[6,2]])
            self.assertIn('record_bound',result['reasons'])
        with patch.object(p,'MAX_RECORDS',1):
            raw=bytearray(pcap([frame(59999,b'x')]))
            struct.pack_into('<I',raw,36,struct.unpack_from('<I',raw,32)[0]+1)
            result=run(m,data=bytes(raw)+bytes(raw[24:]))
            self.assertEqual(self.diagnostic(result)['truncated_counts'][1],1)
            self.assertIn('record_bound',result['reasons'])

    def test_sparse_projection_zero_one_sixteen_seventeen_all_categories(self):
        for size in (0,1,16,17,256):
            counts=[1 if i<size else 0 for i in range(256)]
            value={'v':1,'opaque_next_header_counts':counts,'truncated_counts':[0,0,0]}
            projected=p.project_decoder_diagnostic(value,size)
            self.assertEqual(projected['opaque_next_header_counts'],[[i,1] for i in range(min(size,16))])
            self.assertEqual(projected['omitted_category_count'],max(0,size-16))
            self.assertEqual(projected['omitted_event_count'],max(0,size-16))
            self.assertEqual(projected['detail_complete'],size<=16)
            self.assertEqual(sum(row[1] for row in projected['opaque_next_header_counts'])+projected['omitted_event_count'],size)
        counts=[0]*256;counts[253]=p.MAX_RECORDS
        value={'v':1,'opaque_next_header_counts':counts,'truncated_counts':[1,p.MAX_RECORDS,1]}
        projected=p.project_decoder_diagnostic(value,p.MAX_RECORDS)
        self.assertEqual(projected['opaque_next_header_counts'],[[253,p.MAX_RECORDS]])
        self.assertEqual(projected['omitted_event_count'],0)

    def test_malformed_diagnostic_projection_cannot_affect_original_verdict(self):
        good={'v':1,'opaque_next_header_counts':[0]*256,'truncated_counts':[0,0,0]}
        cases=[None,{},dict(good,extra=0),dict(good,v=True),dict(good,v=2),dict(good,opaque_next_header_counts=[])]
        for count in (-1,True,p.MAX_RECORDS+1):
            bad=copy.deepcopy(good);bad['opaque_next_header_counts'][6]=count;cases.append(bad)
        for trunc in ([2,0,0],[0,0,2],[0,-1,0],[0,False,0],[0,2,0],[0,0],(0,0,0)):
            cases.append(dict(good,truncated_counts=trunc))
        for value in cases:self.assertIsNone(p.project_decoder_diagnostic(value,0))
        count=copy.deepcopy(good);count['opaque_next_header_counts'][6]=1
        self.assertIsNone(p.project_decoder_diagnostic(count,0))
        for records in (-1,True,p.MAX_RECORDS+1):self.assertIsNone(p.project_decoder_diagnostic(good,records))
        m=manifest();data=pcap(frames(m)+[selected(m)])
        original=run(m,data=data)
        with patch.object(p,'project_decoder_diagnostic',return_value=None):missing=run(m,data=data)
        self.assertIsNone(missing.pop('decoder_diagnostic'))
        original.pop('decoder_diagnostic');self.assertEqual(missing,original)

    def test_diagnostic_does_not_change_original_program_semantics(self):
        # Exact old module AST after removing ONLY the additive diagnostic nodes.
        import ast
        class WithoutDiagnostic(ast.NodeTransformer):
            def visit_FunctionDef(self,node):
                if node.name=='project_decoder_diagnostic':return None
                return self.generic_visit(node)
            def visit_Call(self,node):
                node=self.generic_visit(node)
                if isinstance(node.func,ast.Name) and node.func.id=='dict':
                    node.keywords=[k for k in node.keywords if k.arg!='decoder_diagnostic']
                return node
            def visit_Assign(self,node):
                if len(node.targets)==1:
                    target=node.targets[0]
                    if isinstance(target,ast.Name) and target.id=='diagnostic':return None
                    if (isinstance(target,ast.Subscript) and isinstance(target.value,ast.Name)
                        and target.value.id=='public' and isinstance(target.slice,ast.Constant)
                        and target.slice.value=='decoder_diagnostic'):return None
                return self.generic_visit(node)
            def visit_AugAssign(self,node):
                target=node.target
                while isinstance(target,ast.Subscript):target=target.value
                if isinstance(target,ast.Name) and target.id=='diagnostic':return None
                return self.generic_visit(node)
        cleaned=WithoutDiagnostic().visit(ast.parse(PATH.read_text()))
        self.assertEqual(hashlib.sha256(ast.dump(cleaned,include_attributes=False).encode()).hexdigest(),
                         'a17e6995ba430230b1d2f6f9cd4545c896f671b8d09c66ab941dfb9042117198')

    def test_full_public_packet_conservative_maximum_under_4096(self):
        import ast
        result=run();tree=ast.parse(PATH.read_text())
        reasons={'binding','manifest'}
        for node in ast.walk(tree):
            if (isinstance(node,ast.Call) and node.args and isinstance(node.args[0],ast.Constant)
                and isinstance(node.args[0].value,str)
                and ((isinstance(node.func,ast.Name) and node.func.id=='bad')
                     or (isinstance(node.func,ast.Attribute) and node.func.attr=='add'))):
                reasons.add(node.args[0].value)
        for key,value in list(result.items()):
            if type(value)is bool or value is None:result[key]=False # Longest bool/null spelling.
        result.update(status='bounded_no_selected_udp_datagram',selected_payload_count=3,
                      unknown_flow_packets=p.MAX_RECORDS,records=p.MAX_RECORDS,reasons=sorted(reasons))
        # Deliberately stronger than the possible sum<=records bound: every slot max.
        result['decoder_diagnostic']={'v':1,'opaque_next_header_counts':[[n,p.MAX_RECORDS] for n in range(240,256)],
                                      'omitted_category_count':240,'omitted_event_count':p.MAX_RECORDS,
                                      'detail_complete':False,'truncated_counts':[1,p.MAX_RECORDS,1]}
        for options in ({'separators':(',',':')},{},{'indent':2}):
            self.assertLessEqual(len((json.dumps(result,ensure_ascii=True,**options)+'\n').encode('ascii')),4096)
        text=json.dumps(result)
        for private in ('a'*32,MAC.hex(),'fec0::2','source_port','N0AU6'):
            self.assertNotIn(private,text)

if __name__=='__main__':unittest.main()
