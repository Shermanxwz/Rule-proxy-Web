"""Synthetic UDP bytes and caller contracts only; no socket/capture/guest execution."""
import copy
import hashlib
import importlib.util
import json
from pathlib import Path
import struct
import unittest
from unittest.mock import patch

PATH=Path(__file__).resolve().parents[1]/'.github/windows_n0a_udp_packet.py'
spec=importlib.util.spec_from_file_location('udp_packet',PATH)
p=importlib.util.module_from_spec(spec);spec.loader.exec_module(p)
MAC=bytes.fromhex('525400123456')

def manifest(samples=2):
    binding={k:'a'*(32 if k.endswith('nonce') else 40 if k=='source_commit' else 64)
             for k in p.BINDING_KEYS-{'build','ubr'}}
    binding.update(build=26300,ubr=9457)
    rows=[('before',0)]+[('sample',i) for i in range(samples)]+[('after',0)]
    return dict(schema_version=1,binding=binding,
                endpoint=dict(vm_mac=MAC.hex(),destination_ipv4='10.0.2.2',destination_port=4444),
                selected=[dict(index=i,source_port=50000+i,send_invoked=True) for i in range(3)],
                ordinary=[dict(phase=phase,index=index,source_port=51000+n,send_invoked=True,nonce_verified=True)
                          for n,(phase,index) in enumerate(rows)])

def bound(m):
    raw=json.dumps(m,separators=(',',':')).encode()
    return raw,dict(binding=copy.deepcopy(m['binding']),endpoint=copy.deepcopy(m['endpoint']),
                    manifest_sha256=hashlib.sha256(raw).hexdigest(),controls_verified=True,cleanup_verified=True)

def frame(port,body,mac=MAC,dst=b'\x0a\0\x02\x02',dport=4444,fragment=0,options=0,src=b'\x0a\0\x02\x0f'):
    udp=struct.pack('!HHHH',port,dport,8+len(body),0)+body
    ip=struct.pack('!BBHHHBBH4s4s',0x40+(20+options)//4,0,20+options+len(udp),0,fragment,64,17,0,src,dst)+b'\0'*options
    return b'\x52\x54\0\xaa\xbb\xcc'+mac+b'\x08\0'+ip+udp

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

class UdpPacketTests(unittest.TestCase):
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
                       lambda m:m['ordinary'][-1].update(index=41),lambda m:m['endpoint'].update(destination_ipv4='0.0.0.0'),
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
                     b'N0AU1 '+b'a'*32+b' contained 00\n',p.payload('a'*32,'contained',0)+b'x'):
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
    def test_fragments_and_vlan(self):
        m=manifest();body=p.payload('a'*32,'contained',0)
        for frag in (1,0x2000):self.assertIn('fragment',run(m,fs=frames(m)+[frame(50000,body,fragment=frag)])['reasons'])
        f=bytearray(frame(50000,body));f[12:14]=b'\x81\0'
        self.assertIn('encapsulation',run(m,fs=frames(m)+[bytes(f)])['reasons'])
    def test_udp_ip_lengths(self):
        m=manifest();f=frame(50000,p.payload('a'*32,'contained',0))
        for offset,value in [(38,7),(38,9),(16,19),(16,65535)]:
            broken=bytearray(f);struct.pack_into('!H',broken,offset,value)
            self.assertFalse(run(m,fs=frames(m)+[bytes(broken)])['bounded_no_selected_udp_datagram'])
    def test_options_and_no_source_ip_constraint(self):
        m=manifest();fs=[frame(r['source_port'],p.payload('a'*32,r['phase'],r['index']),options=4,src=b'\xc0\x00\x02\x01') for r in m['ordinary']]
        self.assertTrue(run(m,fs=fs)['bounded_no_selected_udp_datagram'])
    def test_unrelated_protocols_and_other_mac(self):
        m=manifest();f=bytearray(frame(59999,b'x'));f[12:14]=b'\x08\x06'
        g=bytearray(f);g[12:14]=b'\x86\xdd'
        self.assertTrue(run(m,fs=frames(m)+[bytes(f),bytes(g),frame(59999,b'x',mac=b'\x02'*6)])['bounded_no_selected_udp_datagram'])
    def test_closed_public_output(self):
        r=run();text=json.dumps(r)
        for forbidden in ('a'*32,MAC.hex(),'10.0.2.2','51000','source_port','N0AU1'):self.assertNotIn(forbidden,text)
        self.assertFalse(r['checksums_validated']);self.assertFalse(r['qpc_timestamp_mapping_used'])

if __name__=='__main__':unittest.main()
