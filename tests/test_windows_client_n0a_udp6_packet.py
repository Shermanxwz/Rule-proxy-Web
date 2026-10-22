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
                                         'omitted_category_count','omitted_event_count','detail_complete','icmp_type_code_counts',
                                         'icmp_omitted_event_count','icmp_detail_complete','checksum_counts','quote_counts',
                                         'quote_detail_counts','raw_selected_nonce_match','ndp'})
        self.assertIs(type(diagnostic['v']),int);self.assertEqual(diagnostic['v'],4)
        opaque=diagnostic['opaque_next_header_counts'];truncated=diagnostic['truncated_counts']
        self.assertIs(type(opaque),list);self.assertLessEqual(len(opaque),2)
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
        self.assertEqual(d['opaque_next_header_counts'],expected[:2])
        self.assertEqual(d['omitted_category_count'],len(expected)-2)
        self.assertEqual(d['omitted_event_count'],sum(row[1] for row in expected[2:]))
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
        self.assertEqual(d['opaque_next_header_counts'],[[6,1],[50,1]])
        self.assertFalse(d['detail_complete']);self.assertEqual(d['omitted_event_count'],4)
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
            value=p._diagnostic_new();value.update(opaque_next_header_counts=counts)
            value['checksum_counts'][2]=counts[58];value['quote_counts'][3]=counts[58]
            projected=p.project_decoder_diagnostic(value,size)
            self.assertEqual(projected['opaque_next_header_counts'],[[i,1] for i in range(min(size,2))])
            self.assertEqual(projected['omitted_category_count'],max(0,size-2))
            self.assertEqual(projected['omitted_event_count'],max(0,size-2))
            self.assertEqual(projected['detail_complete'],size<=2)
            self.assertEqual(sum(row[1] for row in projected['opaque_next_header_counts'])+projected['omitted_event_count'],size)
        counts=[0]*256;counts[253]=p.MAX_RECORDS
        value=p._diagnostic_new();value.update(opaque_next_header_counts=counts,truncated_counts=[1,p.MAX_RECORDS,1])
        projected=p.project_decoder_diagnostic(value,p.MAX_RECORDS)
        self.assertEqual(projected['opaque_next_header_counts'],[[253,p.MAX_RECORDS]])
        self.assertEqual(projected['omitted_event_count'],0)

    def test_malformed_diagnostic_projection_cannot_affect_original_verdict(self):
        good=p._diagnostic_new()
        cases=[None,{},dict(good,extra=0),dict(good,v=True),dict(good,v=3),dict(good,opaque_next_header_counts=[])]
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
            def visit_Module(self,node):
                node.body[0].value.value=node.body[0].value.value.replace("Direct-UDP checksums", "Checksums").replace("absence unless the strict trace-calibrated ND profile applies.\nIPv4", "absence. IPv4")
                return self.generic_visit(node)
            def visit_FunctionDef(self,node):
                if node.name=='project_decoder_diagnostic' or node.name.startswith(('_diagnostic_','_nd_')):return None
                return self.generic_visit(node)
            def visit_Call(self,node):
                node=self.generic_visit(node)
                if isinstance(node.func,ast.Name) and node.func.id=='dict':
                    node.keywords=[k for k in node.keywords if k.arg!='decoder_diagnostic']
                    for k in node.keywords:
                        if k.arg=='schema_version' and isinstance(k.value,ast.Constant) and k.value.value==2:k.value.value=1
                return node
            def visit_Assign(self,node):
                if len(node.targets)==1:
                    target=node.targets[0]
                    if isinstance(target,ast.Name) and target.id in ('diagnostic','witness'):return None
                    base=target
                    while isinstance(base,ast.Subscript):base=base.value
                    if isinstance(base,ast.Name) and base.id=='diagnostic':return None
                    if (isinstance(target,ast.Subscript) and isinstance(target.value,ast.Name)
                        and target.value.id=='public' and isinstance(target.slice,ast.Constant)
                        and target.slice.value=='decoder_diagnostic'):return None
                return self.generic_visit(node)
            def visit_If(self,node):
                if isinstance(node.test,ast.Compare) and ast.unparse(node.test)=='next_header == 58':return None
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
        result['decoder_diagnostic']=dict(v=4,opaque_next_header_counts=[[254,p.MAX_RECORDS],[255,p.MAX_RECORDS]],
            omitted_category_count=254,omitted_event_count=p.MAX_RECORDS,detail_complete=False,truncated_counts=[1,p.MAX_RECORDS,1],
            icmp_type_code_counts=[[255,n,p.MAX_RECORDS] for n in range(254,256)],icmp_omitted_event_count=p.MAX_RECORDS,
            icmp_detail_complete=False,checksum_counts=[p.MAX_RECORDS]*3,quote_counts=[p.MAX_RECORDS]*4,
            quote_detail_counts=[p.MAX_RECORDS]*14,raw_selected_nonce_match=[False,3],ndp=[p.MAX_RECORDS]*4+[0x7ffff]+[p.MAX_RECORDS]*3+[2,False,31,p.MAX_RECORDS])
        for options in ({'separators':(',',':')},{},{'indent':2}):
            self.assertLessEqual(len((json.dumps(result,ensure_ascii=True,**options)+'\n').encode('ascii')),4096)
        text=json.dumps(result)
        for private in ('a'*32,MAC.hex(),'fec0::2','source_port','N0AU6'):
            self.assertNotIn(private,text)

def checksum_bytes(source,destination,body,protocol):
    data=source+destination+struct.pack('!I3xB',len(body),protocol)+body
    if len(data)%2:data+=b'\0'
    total=sum(struct.unpack('!%dH'%(len(data)//2),data))
    while total>>16:total=(total&65535)+(total>>16)
    return (~total)&65535


def quote_packet(m,selected=True,reverse=True,body=None,port=None):
    row=m['selected'][0] if selected else m['ordinary'][0]
    phase='contained' if selected else row['phase']
    body=p.payload(m['binding']['case_nonce'],phase,row['index']) if body is None else body
    local=row['source_port'] if port is None else port
    src,dst=(DST,SRC) if reverse else (SRC,DST)
    sport,dport=(4444,local) if reverse else (local,4444)
    udp=struct.pack('!HHHH',sport,dport,8+len(body),0)+body
    check=checksum_bytes(src,dst,udp,17) or 65535
    udp=udp[:6]+struct.pack('!H',check)+udp[8:]
    return struct.pack('!IHBB16s16s',6<<28,len(udp),17,64,src,dst)+udp


def icmp_frame(quote=b'',kind=1,code=0,word=b'\0'*4,extension=False):
    body=bytes([kind,code,0,0])+word+quote
    check=checksum_bytes(SRC,DST,body,58)
    body=body[:2]+struct.pack('!H',check)+body[4:]
    tail=(bytes([58,0])+b'\0'*6 if extension else b'')+body
    return b'\x52\x54\0\xaa\xbb\xcc'+MAC+b'\x86\xdd'+struct.pack('!IHBB16s16s',6<<28,len(tail),60 if extension else 58,64,SRC,DST)+tail


class IcmpDiagnosticV2Tests(unittest.TestCase):
    def diagnostic(self,fs,m=None):
        m=manifest() if m is None else m
        result=run(m,fs=frames(m)+fs)
        self.assertIn('opaque_protocol',result['reasons'])
        self.assertFalse(result['bounded_no_selected_udp_datagram'])
        self.assertFalse(result['selected_payload_observed'])
        self.assertFalse(result['selected_bound_payload_observed'])
        self.assertFalse(result['actor_attribution_established'])
        d=result['decoder_diagnostic'];self.assertIsNotNone(d)
        return d

    def test_forged_checksum_consistent_selected_and_ordinary_not_authenticity(self):
        m=manifest()
        d=self.diagnostic([icmp_frame(quote_packet(m)),icmp_frame(quote_packet(m,selected=False))])
        self.assertEqual(d['checksum_counts'],[2,0,0]);self.assertEqual(d['quote_counts'],[2,0,0,0])
        self.assertEqual(d['quote_detail_counts'],[2,0,0,1,1,0,0,2,0,0,2,0,1,1])
        self.assertEqual(d['raw_selected_nonce_match'],[True,1])

    def test_forward_quote_bound_but_address_relation_mismatch(self):
        d=self.diagnostic([icmp_frame(quote_packet(manifest(),reverse=False))])
        self.assertEqual(d['quote_detail_counts'][6],1)
        self.assertEqual(d['quote_detail_counts'][11],1)
        self.assertEqual(d['quote_detail_counts'][12:], [0,0])

    def test_outer_inner_checksums_independent_zero_inner_invalid(self):
        m=manifest();q=bytearray(quote_packet(m));q[46:48]=b'\0\0'
        f=bytearray(icmp_frame(quote_packet(m)));f[56]^=1
        d=self.diagnostic([bytes(f),icmp_frame(bytes(q))])
        self.assertEqual(d['checksum_counts'],[1,1,0]);self.assertEqual(d['quote_detail_counts'][:3],[1,1,0])
        self.assertEqual(d['quote_detail_counts'][12:],[0,0]);self.assertEqual(d['raw_selected_nonce_match'],[True,1])

    def test_partial_malformed_unsupported_precedence(self):
        q=quote_packet(manifest())
        partial=[b'',q[:1],q[:39],q[:40],q[:47],q[:-1]]
        malformed=[b'\x40',q[:4]+b'\0\x07'+q[6:40],q[:44]+b'\0\x07'+q[46:]]
        unsupported=[q+b'\0',q[:4]+b'\0\0'+q[6:],q[:6]+b'\x2c'+q[7:],q[:6]+b'\x32'+q[7:]]
        for quotes,index in ((partial,1),(malformed,2),(unsupported,3)):
            for value in quotes:
                with self.subTest(category=index,length=len(value)):
                    d=self.diagnostic([icmp_frame(value)])
                    self.assertEqual(d['quote_counts'][index],1)
                    self.assertEqual(sum(d['quote_detail_counts']),0)

    def test_rfc4884_only_types_one_three_and_unknown_codes_framing_only(self):
        q=quote_packet(manifest())
        for kind in (1,3):
            d=self.diagnostic([icmp_frame(q,kind,255,b'\1\0\0\0')]);self.assertEqual(d['quote_counts'][3],1)
        for kind in (2,4):
            d=self.diagnostic([icmp_frame(q,kind,255,b'\1\0\0\0')]);self.assertEqual(d['quote_counts'][0],1)
        d=self.diagnostic([icmp_frame(q,128)]);self.assertEqual(d['quote_counts'][3],1)

    def test_extensions_raw_before_unknown_and_no_partial_record_expansion(self):
        q=quote_packet(manifest());d=self.diagnostic([icmp_frame(q,extension=True)])
        self.assertEqual(d['checksum_counts'],[0,0,1]);self.assertEqual(d['quote_counts'],[0,0,0,1])
        self.assertEqual(d['raw_selected_nonce_match'],[True,1])
        data=pcap([icmp_frame(q)])+b'\0'
        r=run(data=data);self.assertEqual(r['decoder_diagnostic']['raw_selected_nonce_match'],[True,1])
        self.assertIn('truncated',r['reasons'])
        r=run(data=pcap([icmp_frame(q)])[:-1]);self.assertEqual(r['decoder_diagnostic']['raw_selected_nonce_match'],[False,0])

    def test_raw_scan_not_exact_payload_tuple_or_checksum_claim(self):
        m=manifest();body=b'prefix'+p.payload(m['binding']['case_nonce'],'contained',2)+b'suffix'
        d=self.diagnostic([icmp_frame(quote_packet(m,body=body))])
        self.assertEqual(d['raw_selected_nonce_match'],[True,1]);self.assertEqual(d['quote_detail_counts'][5],1)
        self.assertEqual(d['quote_detail_counts'][12:],[0,0])
        bad=bytearray(icmp_frame(quote_packet(m)));bad[6:12]=b'\x02'*6
        r=run(m,fs=[bytes(bad)]);self.assertEqual(r['decoder_diagnostic']['raw_selected_nonce_match'],[False,0])

    def test_wrong_missing_collision_ports_never_joint(self):
        m=manifest();d=self.diagnostic([icmp_frame(quote_packet(m,port=60000))]);self.assertEqual(d['quote_detail_counts'][8],1)
        for missing in (True,False):
            m=manifest();q=quote_packet(m)
            if missing:m['selected'][0].update(source_port=None,send_invoked=False)
            else:m['ordinary'][0]['source_port']=m['selected'][0]['source_port']
            d=self.diagnostic([icmp_frame(q)],m);self.assertEqual(d['quote_detail_counts'][9],1)
            self.assertEqual(d['quote_detail_counts'][12:],[0,0]);self.assertEqual(d['raw_selected_nonce_match'],[True,1])

    def test_first_four_pairs_track_retained_after_omission_sorted_only_output(self):
        pairs=[(4,9),(3,8),(2,7),(1,6),(5,5),(4,9),(5,5),(6,4)]
        d=self.diagnostic([icmp_frame(kind=a,code=b) for a,b in pairs])
        self.assertEqual(d['icmp_type_code_counts'],[[3,8,1],[4,9,2]])
        self.assertEqual(d['icmp_omitted_event_count'],5);self.assertFalse(d['icmp_detail_complete'])
        self.assertNotIn('icmp_omitted_category_count',d)

    def test_short_icmp_no_invented_pair_checksum_or_quote(self):
        for n in range(8):
            raw=bytearray(frame(1,b''));body=b'\1'*n
            raw=bytes(raw[:14])+struct.pack('!IHBB16s16s',6<<28,len(body),58,64,SRC,DST)+body
            if n==0:continue # Existing zero IPv6 payload refuses before observer.
            d=self.diagnostic([raw]);self.assertEqual(d['quote_counts'][3],1)
            self.assertEqual(len(d['icmp_type_code_counts']),int(n>=2))
            self.assertEqual(d['checksum_counts'][2],int(n<4))

    def test_unusable_or_degenerate_outer_source_is_diagnostic_ambiguous(self):
        m=manifest()
        for guest in (b'\0'*16,b'\0'*15+b'\1',b'\xff'+b'\0'*15,b'\0'*10+b'\xff\xff'+b'\x7f\0\0\1',DST):
            q=bytearray(quote_packet(m));q[24:40]=guest
            udp=bytearray(q[40:]);udp[6:8]=b'\0\0'
            udp[6:8]=struct.pack('!H',checksum_bytes(DST,guest,bytes(udp),17) or 65535);q[40:]=udp
            f=bytearray(icmp_frame(bytes(q)));f[22:38]=guest
            body=bytearray(f[54:]);body[2:4]=b'\0\0'
            body[2:4]=struct.pack('!H',checksum_bytes(guest,DST,bytes(body),58));f[54:]=body
            d=self.diagnostic([bytes(f)])
            self.assertEqual(d['quote_detail_counts'][9],1)
            self.assertEqual(d['quote_detail_counts'][12:],[0,0])
            self.assertEqual(d['raw_selected_nonce_match'],[True,1])
        m['selected'][0]['source_port']=4444
        d=self.diagnostic([icmp_frame(quote_packet(m))],m)
        self.assertEqual(d['quote_detail_counts'][9],1)
        self.assertEqual(d['quote_detail_counts'][12:],[0,0])

    def test_joint_invariants_reject_marginal_inference_and_type_forgery(self):
        d=p.decode_pcap(pcap([icmp_frame(quote_packet(manifest()))]),manifest())['decoder_diagnostic']
        self.assertIsNotNone(p.project_decoder_diagnostic(d,1))
        for key,index in (('checksum_counts',0),('quote_detail_counts',0),('quote_detail_counts',3),('quote_detail_counts',7),('quote_detail_counts',10)):
            bad=copy.deepcopy(d);bad[key][index]=0
            self.assertIsNone(p.project_decoder_diagnostic(bad,1))
        for key in ('checksum_counts','quote_counts','quote_detail_counts'):
            bad=copy.deepcopy(d);bad[key][0]=True;self.assertIsNone(p.project_decoder_diagnostic(bad,1))
        bad=copy.deepcopy(d);bad['raw_selected_nonce_match']={True};self.assertIsNone(p.project_decoder_diagnostic(bad,1))
        bad=copy.deepcopy(d);bad['icmp_omitted_event_count']=1;self.assertIsNone(p.project_decoder_diagnostic(bad,1))


def calibration_frames(m,src=SRC):
    fs=[]
    for r in m['ordinary']:
        f=bytearray(frame(r['source_port'],p.payload(m['binding']['case_nonce'],r['phase'],r['index']),src=src))
        udp=bytearray(f[54:]);udp[6:8]=struct.pack('!H',checksum_bytes(src,DST,bytes(udp),17) or 65535)
        f[54:]=udp;fs.append(bytes(f))
    return fs


def nd_frame(kind=135,option=True,override=False,source=SRC,target=None,hop=255,code=0,
             flags=None,options=None,extension=False):
    target=(DST if kind==135 else source) if target is None else target
    flags=(0 if kind==135 else 0x40000000|(0x20000000 if override else 0)) if flags is None else flags
    body=bytes([kind,code,0,0])+struct.pack('!I',flags)+target
    if options is None:options=bytes([1 if kind==135 else 2,1])+MAC if option else b''
    body+=options
    body=body[:2]+struct.pack('!H',checksum_bytes(source,DST,body,58))+body[4:]
    tail=(bytes([58,0])+b'\0'*6 if extension else b'')+body
    return b'\x52\x54\0\xaa\xbb\xcc'+MAC+b'\x86\xdd'+struct.pack('!IHBB16s16s',6<<28,len(tail),60 if extension else 58,hop,source,DST)+tail


class StrictNdProfileTests(unittest.TestCase):
    def result(self,nd,fs=None,m=None):
        m=manifest() if m is None else m
        return run(m,fs=list(nd)+(calibration_frames(m) if fs is None else fs))

    def denied(self,r,bit=None):
        self.assertFalse(r['bounded_no_selected_udp_datagram']);self.assertIn('opaque_protocol',r['reasons'])
        self.assertEqual(r['schema_version'],2)
        d=r['decoder_diagnostic'];self.assertEqual(d['v'],4)
        if bit is not None:self.assertTrue(d['ndp'][4]&(1<<bit))
        return d['ndp']

    def test_all_strict_shapes_and_two_pass_before_controls(self):
        for kind in (135,136):
            for option in (False,True):
                for override in (False,True):
                    r=self.result([nd_frame(kind,option,override)])
                    self.assertTrue(r['bounded_no_selected_udp_datagram'])
                    self.assertEqual(r['schema_version'],2);self.assertFalse(r['checksums_validated'])
                    self.assertEqual(r['records'],5)
                    nd=r['decoder_diagnostic']['ndp'];self.assertEqual(nd[:4],[int(kind==135),int(kind==136),0,0])
                    self.assertEqual(nd[4:],[0,4,4,0,1,False,16 if kind==136 else 0,0])
                    self.assertEqual(r['decoder_diagnostic']['opaque_next_header_counts'],[[58,1]])

    def test_duplicate_good_source_allowed_not_counted_twice_by_passes(self):
        m=manifest();fs=calibration_frames(m);fs.insert(1,fs[0])
        r=self.result([nd_frame()],fs,m);self.assertTrue(r['bounded_no_selected_udp_datagram'])
        self.assertEqual(r['records'],6);self.assertEqual(r['decoder_diagnostic']['ndp'][5:8],[5,5,0])

    def test_bad_checksum_duplicate_permanently_taints_both_orders(self):
        m=manifest();good=calibration_frames(m)
        for zero in (False,True):
            bad=bytearray(good[0]);bad[60:62]=b'\0\0' if zero else bytes([bad[60]^1,bad[61]])
            for reverse in (False,True):
                fs=[bytes(bad)]+good if not reverse else good+[bytes(bad)]
                nd=self.denied(self.result([nd_frame()],fs,m),14)
                self.assertEqual(nd[5:8],[5,4,1])
                self.assertEqual(nd[:4],[0,0,0,1])

    def test_extension_duplicate_cannot_hide_checksum_or_source_taint(self):
        m=manifest();row=m['ordinary'][0]
        for kind in (0,43,60,51,44,50):
            for conflict in (False,True):
                source=SRC[:-1]+b'\x10' if conflict else SRC
                bad=frame(row['source_port'],p.payload(m['binding']['case_nonce'],row['phase'],row['index']),
                          src=source,extensions=((60,8),)) # zero UDP checksum
                bad=bytearray(bad);bad[20]=kind
                nd=self.denied(self.result([nd_frame()],calibration_frames(m)+[bytes(bad)],m),0)
                self.assertEqual(nd[0:2],[0,0])
        # Conservatively reject even a checksum-correct extended duplicate.
        f=calibration_frames(m)[0];extended=f[:18]+struct.pack('!H',len(f)-54+8)+bytes([60])+f[21:54]+bytes([17,0])+b'\0'*6+f[54:]
        self.denied(self.result([nd_frame()],calibration_frames(m)+[extended],m),0)

    def test_source_conflict_sticky_and_unusable_source(self):
        m=manifest();fs=calibration_frames(m)
        conflict=calibration_frames(m,src=SRC[:-1]+b'\x10')[0]
        nd=self.denied(self.result([nd_frame()],fs+[conflict],m),15);self.assertEqual(nd[8],2)
        for source in (b'\0'*16,b'\0'*15+b'\1',b'\xff'+b'\0'*15,b'\0'*10+b'\xff\xff'+b'\1'*4,DST):
            nd=self.denied(self.result([nd_frame()],calibration_frames(m,source),m),16)
            self.assertEqual(nd[8],0)

    def test_missing_failed_flags_order_and_port_collisions(self):
        m=manifest();fs=calibration_frames(m)
        for changed in (fs[:-1],fs[1:],fs[-1:]+fs[:-1]):self.denied(self.result([nd_frame()],changed,m),13)
        for field in ('send_invoked','nonce_verified'):
            mm=copy.deepcopy(m);mm['ordinary'][1][field]=False
            self.denied(self.result([nd_frame()],fs,mm),13)
        mm=copy.deepcopy(m);mm['selected'][0]['source_port']=mm['ordinary'][0]['source_port']
        self.denied(self.result([nd_frame()],fs,mm),17)
        mm=copy.deepcopy(m);mm['ordinary'][0].update(source_port=None,send_invoked=False)
        self.denied(self.result([nd_frame()],fs,mm),17)

    def test_checksums_do_not_redefine_direct_udp_adjudication(self):
        m=manifest();r=run(m,fs=frames(m));self.assertTrue(r['bounded_no_selected_udp_datagram'])
        self.assertFalse(r['checksums_validated'])
        self.denied(self.result([nd_frame()],frames(m),m),14)

    def test_wire_rejections(self):
        for f,bit in ((nd_frame(hop=64),2),(nd_frame(code=1),3),
                      (nd_frame(target=b'\xff'+b'\0'*15),5),(nd_frame(source=b'\0'*16),5),
                      (nd_frame(options=b'\1\0'+b'\0'*6),8),
                      (nd_frame(options=b'\1\2'+b'\0'*6),8)):
            nd=self.denied(self.result([f]),bit);self.assertEqual(nd[2],1)
        bad=bytearray(nd_frame());bad[56]^=1
        self.assertEqual(self.denied(self.result([bytes(bad)]),4)[2],1)
        for n in (1,2,4,23):
            f=nd_frame(option=False);body=f[54:54+n]
            f=f[:18]+struct.pack('!H',n)+f[20:54]+body
            nd=self.denied(self.result([f]),1);self.assertEqual(nd[2],1)

    def test_legal_but_unsupported_fixture_shapes(self):
        cases=[(nd_frame(source=SRC[:-1]+b'\x10'),6),
               (nd_frame(target=SRC),6),
               (nd_frame(kind=136,target=DST),6),
               (nd_frame(flags=1),7),(nd_frame(kind=136,flags=0xc0000000),7),
               (nd_frame(kind=136,flags=0),7),(nd_frame(kind=136,flags=0x40000001),7),
               (nd_frame(options=b'\2\1'+MAC),9),(nd_frame(options=b'\7\1'+MAC),9),
               (nd_frame(options=(b'\1\1'+MAC)*2),9),
               (nd_frame(options=b'\1\1'+b'\x02'*6),10)]
        for f,bit in cases:
            nd=self.denied(self.result([f]),bit);self.assertEqual(nd[3],1)

    def test_extension_fragment_jumbo_unchanged_refusal(self):
        nd=self.denied(self.result([nd_frame(extension=True)]),0);self.assertEqual(nd[3],1)
        f=bytearray(nd_frame());f[20]=44
        r=self.result([bytes(f)]);self.assertIn('fragment',r['reasons']);self.assertFalse(r['bounded_no_selected_udp_datagram'])
        f=bytearray(nd_frame());f[18:20]=b'\0\0'
        r=self.result([bytes(f)]);self.assertIn('jumbo_unsupported',r['reasons']);self.assertFalse(r['bounded_no_selected_udp_datagram'])

    def test_raw_case_and_selected_bytes_prevent_exception_even_bad_checksum(self):
        m=manifest();nonce=m['binding']['case_nonce'].encode()
        for body in (nonce,p.payload(m['binding']['case_nonce'],'contained',0)):
            for corrupt in (False,True):
                f=bytearray(nd_frame(options=body))
                if corrupt:f[56]^=1
                r=self.result([bytes(f)],m=m);nd=self.denied(r,12)
                self.assertTrue(nd[9]);self.assertFalse(r['selected_payload_observed'])
                self.assertEqual(r['decoder_diagnostic']['raw_selected_nonce_match'],[body!=nonce,int(body!=nonce)])
        # A candidate's fixed header/address bytes count too, not only its options.
        # ASCII nonce cannot fit a single address; the whole-frame scan has no payload-only assumption.
        r=run(m,fs=calibration_frames(m));self.assertFalse(r['decoder_diagnostic']['ndp'][9])

    def test_mixed_profile_nd_and_opaque_never_global_reason_deletion(self):
        m=manifest();other=bytearray(frame(59999,b'x'));other[20]=6
        r=self.result([nd_frame(),bytes(other)],m=m)
        self.assertIn('opaque_protocol',r['reasons']);self.assertEqual(r['decoder_diagnostic']['ndp'][0],1)
        self.assertFalse(r['bounded_no_selected_udp_datagram'])
        r=self.result([nd_frame(),selected(m)],m=m)
        self.assertTrue(r['selected_bound_payload_observed']);self.assertEqual(r['status'],'selected_payload_observed')

    def test_capture_structural_failure_taints_nd_even_after_valid_controls(self):
        m=manifest();base=pcap([nd_frame()]+calibration_frames(m))
        for data in (base+b'\0',base+struct.pack('<IIII',1,0,100,100)+b'\0',base+struct.pack('<IIII',1,0,2,2)+b'\0\0'):
            r=run(m,data=data);self.denied(r,18)
        bad=bytearray(base);struct.pack_into('<I',bad,36,struct.unpack_from('<I',bad,32)[0]+1)
        self.denied(run(m,data=bytes(bad)),18)
        with patch.object(p,'MAX_RECORDS',4):self.denied(run(m,data=base),18)
        r=run(m,data=pcap([selected(m),nd_frame()]+calibration_frames(m))+b'\0')
        self.assertTrue(r['selected_bound_payload_observed']);self.denied(r,18)

    def test_diagnostic_strict_types_and_projection_loss_cannot_hide_schema(self):
        m=manifest();d=p.decode_pcap(pcap([nd_frame()]+calibration_frames(m)),m)['decoder_diagnostic']
        for i,value in ((0,True),(4,0x80000),(5,-1),(8,3),(9,1)):
            bad=copy.deepcopy(d);bad['ndp'][i]=value;self.assertIsNone(p.project_decoder_diagnostic(bad,5))
        bad=copy.deepcopy(d);bad['ndp'][6]+=1;self.assertIsNone(p.project_decoder_diagnostic(bad,5))
        for index,value in ((4,1<<0),(4,1<<13),(4,1<<15),(6,0),(7,1),(8,2)):
            bad=copy.deepcopy(d);bad['ndp'][index]=value
            if index in (6,7):bad['ndp'][5]=bad['ndp'][6]+bad['ndp'][7]
            self.assertIsNone(p.project_decoder_diagnostic(bad,5))
        with patch.object(p,'project_decoder_diagnostic',return_value=None):r=self.result([nd_frame()])
        self.assertEqual(r['schema_version'],2);self.assertTrue(r['bounded_no_selected_udp_datagram'])
        self.assertIsNone(r['decoder_diagnostic'])

    def test_exact_v2_decoder_and_evaluator_reverse_only_authorized_nd_delta(self):
        import ast
        class ReverseNd(ast.NodeTransformer):
            def visit_Assign(self,node):
                target=node.targets[0] if len(node.targets)==1 else None
                if isinstance(target,ast.Name) and target.id=='witness':return None
                if isinstance(target,ast.Subscript) and ast.unparse(target)=="diagnostic['ndp'][4:9]":return None
                return self.generic_visit(node)
            def visit_If(self,node):
                if isinstance(node.test,ast.Call) and isinstance(node.test.func,ast.Name) and node.test.func.id=='_nd_profile':return None
                return self.generic_visit(node)
            def visit_Call(self,node):
                node=self.generic_visit(node)
                if isinstance(node.func,ast.Name) and node.func.id=='dict':
                    for key in node.keywords:
                        if key.arg=='schema_version' and isinstance(key.value,ast.Constant) and key.value.value==2:key.value.value=1
                return node
        expected={'decode_pcap':'663641e611a2667f260107d752f6412441b2315dc3eab37661ad3235d0a96905',
                  'evaluate':'af133a625d589e514a789ebd57f923c41639135d12435afe997921d1ecfc3a7c'}
        for node in ast.parse(PATH.read_text()).body:
            if isinstance(node,ast.FunctionDef) and node.name in expected:
                restored=ReverseNd().visit(node)
                self.assertEqual(hashlib.sha256(ast.dump(restored,include_attributes=False).encode()).hexdigest(),expected[node.name])

    def test_two_pass_memory_and_fixed_state_source_contract(self):
        import inspect
        source=inspect.getsource(p._nd_witness)
        self.assertIn('view=memoryview(data)',source)
        for forbidden in ('bytes(data)','list(view)','list(data)','read_bytes','open(','append(frame','list(frame'):
            self.assertNotIn(forbidden,source)
        m=manifest(40);state=p._nd_witness(pcap(calibration_frames(m)),m)
        self.assertTrue(state['ready']);self.assertEqual(state['exact'],42)
        self.assertEqual(set(state),{'bits','exact','valid','invalid','source','source_state','ready'})


class NaRelationV4Tests(unittest.TestCase):
    def result(self,fs,m=None,controls=None):
        m=manifest() if m is None else m
        return run(m,fs=fs+(calibration_frames(m) if controls is None else controls))

    def test_zero_events_and_ns_do_not_invent_na_relations(self):
        for fs in ([],[nd_frame(kind=135)]):
            r=self.result(fs);d=r['decoder_diagnostic']
            self.assertEqual(d['v'],4);self.assertEqual(d['ndp'][10:],[0,0])
            self.assertNotIn('na_events',d);self.assertEqual(r['schema_version'],2)

    def test_all_five_joint_patterns_presence_not_marginal_or_frequency(self):
        a=SRC[:-1]+b'\x10';b=SRC[:-1]+b'\x11'
        pairs=[(a,b),(SRC,a),(a,SRC),(a,a),(SRC,SRC)]
        frames_by_pattern=[nd_frame(kind=136,source=s,target=t) for s,t in pairs]
        for index,frame_bytes in enumerate(frames_by_pattern):
            r=self.result([frame_bytes]);self.assertEqual(r['decoder_diagnostic']['ndp'][10:],[1<<index,0])
        r=self.result(frames_by_pattern+frames_by_pattern)
        self.assertEqual(r['decoder_diagnostic']['ndp'][10:],[31,0])
        self.assertEqual(r['decoder_diagnostic']['ndp'][1],2)
        self.assertEqual(r['decoder_diagnostic']['ndp'][3],8)
        # source==G on one event plus target==G on another never manufactures all-equal.
        r=self.result(frames_by_pattern[1:3]);self.assertEqual(r['decoder_diagnostic']['ndp'][10],6)
        self.assertFalse(r['bounded_no_selected_udp_datagram'])
        self.assertIn('opaque_protocol',r['reasons']);self.assertTrue(r['decoder_diagnostic']['ndp'][4]&(1<<6))

    def test_relation_survives_checksum_code_and_flag_rejection(self):
        fs=[]
        f=bytearray(nd_frame(kind=136));f[56]^=1;fs.append(bytes(f))
        fs += [nd_frame(kind=136,code=1),nd_frame(kind=136,flags=0),nd_frame(kind=136,hop=1)]
        for f in fs:
            r=self.result([f]);self.assertEqual(r['decoder_diagnostic']['ndp'][10:],[16,0])
            self.assertFalse(r['bounded_no_selected_udp_datagram'])

    def test_all_witness_taints_mean_unknown_not_false_comparisons(self):
        m=manifest();good=calibration_frames(m)
        bad=bytearray(good[0]);bad[60:62]=b'\0\0'
        cases=[good[:-1],good+[bytes(bad)],good+[calibration_frames(m,SRC[:-1]+b'\x10')[0]]]
        for controls in cases:
            r=self.result([nd_frame(kind=136)],m,controls)
            self.assertEqual(r['decoder_diagnostic']['ndp'][10:],[0,1])
        for field in ('send_invoked','nonce_verified'):
            mm=copy.deepcopy(m);mm['ordinary'][0][field]=False
            r=self.result([nd_frame(kind=136)],mm,good);self.assertEqual(r['decoder_diagnostic']['ndp'][10:],[0,1])
        data=pcap([nd_frame(kind=136)]+good)+b'\0'
        r=run(m,data=data);self.assertEqual(r['decoder_diagnostic']['ndp'][10:],[0,1])

    def test_short_target_and_mixed_known_unknown_na(self):
        for length in (1,2,8,23):
            full=nd_frame(kind=136);f=full[:18]+struct.pack('!H',length)+full[20:54]+full[54:54+length]
            r=self.result([f]);self.assertEqual(r['decoder_diagnostic']['ndp'][10:],[0,1])
        full=nd_frame(kind=136);short=full[:18]+struct.pack('!H',1)+full[20:55]
        r=self.result([full,short,nd_frame(kind=135)])
        self.assertEqual(r['decoder_diagnostic']['ndp'][10:],[16,1])
        self.assertFalse(r['bounded_no_selected_udp_datagram'])

    def test_unknown_maximum_and_fixed_internal_counter(self):
        d=p._diagnostic_new();d['opaque_next_header_counts'][58]=p.MAX_RECORDS
        d['checksum_counts'][2]=p.MAX_RECORDS;d['quote_counts'][3]=p.MAX_RECORDS
        d['ndp'][2]=p.MAX_RECORDS;d['ndp'][11]=p.MAX_RECORDS;d['na_events']=p.MAX_RECORDS
        out=p.project_decoder_diagnostic(d,p.MAX_RECORDS)
        self.assertIsNotNone(out);self.assertEqual(out['ndp'][10:],[0,p.MAX_RECORDS])
        self.assertNotIn('na_events',out)

    def test_invalid_masks_counts_and_joint_invariants_fail_closed(self):
        m=manifest();data=pcap([nd_frame(kind=136)]+calibration_frames(m))
        d=p.decode_pcap(data,m)['decoder_diagnostic'];self.assertIsNotNone(p.project_decoder_diagnostic(d,5))
        for field,value in ((10,True),(10,-1),(10,32),(11,True),(11,-1),(11,2),(10,3),(10,0),(11,1)):
            bad=copy.deepcopy(d);bad['ndp'][field]=value
            self.assertIsNone(p.project_decoder_diagnostic(bad,5))
        for value in (True,-1,0,2,p.MAX_RECORDS+1):
            bad=copy.deepcopy(d);bad['na_events']=value;self.assertIsNone(p.project_decoder_diagnostic(bad,5))
        # Admitted NA must itself contribute a known all-equality pattern.
        bad=copy.deepcopy(d);bad['ndp'][10]=1;self.assertIsNone(p.project_decoder_diagnostic(bad,5))
        bad=copy.deepcopy(d);bad['ndp'][10]=0;bad['ndp'][11]=1
        self.assertIsNone(p.project_decoder_diagnostic(bad,5))
        bad=copy.deepcopy(d);bad['na_events']=0;bad['ndp'][10]=0
        self.assertIsNone(p.project_decoder_diagnostic(bad,5))

    def test_projection_unavailable_does_not_change_strict_verdict(self):
        m=manifest();data=pcap([nd_frame(kind=136),selected(m)]+calibration_frames(m))
        normal=run(m,data=data)
        with patch.object(p,'project_decoder_diagnostic',return_value=None):missing=run(m,data=data)
        normal.pop('decoder_diagnostic');self.assertIsNone(missing.pop('decoder_diagnostic'))
        self.assertEqual(normal,missing);self.assertTrue(missing['selected_bound_payload_observed'])
        self.assertEqual(missing['schema_version'],2)

    def test_core_v3_exact_ast_reverse_only_added_diagnostic_call(self):
        import ast
        class ReverseRelation(ast.NodeTransformer):
            def visit_Expr(self,node):
                if isinstance(node.value,ast.Call) and isinstance(node.value.func,ast.Name) and node.value.func.id=='_nd_relation':return None
                return self.generic_visit(node)
        expected={'_nd_witness':'8d0a9a13aadbe94db96d9824a517d879a231526f34338d3eec8c50b83959fb59',
                  '_nd_profile':'4b5bc83eba57419fbed8153707637500e7079f103af946a0ddddd0426cb30685',
                  'decode_pcap':'f35054c1031eec0d74a3748e33cd394193883ee078bb8d4b3404054df2da52e0',
                  'evaluate':'e6cc1f18f08764d80d81840624e8f5cacb8e35bc40805efb4e55b89c91aca19b'}
        for node in ast.parse(PATH.read_text()).body:
            if isinstance(node,ast.FunctionDef) and node.name in expected:
                restored=ReverseRelation().visit(node)
                self.assertEqual(hashlib.sha256(ast.dump(restored,include_attributes=False).encode()).hexdigest(),expected[node.name])


if __name__=='__main__':unittest.main()
