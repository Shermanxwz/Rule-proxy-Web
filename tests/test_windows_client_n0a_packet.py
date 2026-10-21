"""Synthetic byte fixtures only: no capture, guest, actor or network execution."""
import copy
import hashlib
import importlib.util
import json
from pathlib import Path
import struct
import unittest
from unittest.mock import patch

PATH = Path(__file__).resolve().parents[1]/'.github/windows_n0a_packet.py'
SPEC = importlib.util.spec_from_file_location('n0a_packet', PATH)
p = importlib.util.module_from_spec(SPEC); SPEC.loader.exec_module(p)
MAC = bytes.fromhex('525400123456')

def manifest():
    binding = {k: 'a'*(32 if k.endswith('nonce') else 40 if k=='source_commit' else 64)
               for k in p.BINDING_KEYS-{'build','ubr'}}
    binding.update(build=26300,ubr=9457)
    return {'schema_version':1,'binding':binding,
            'endpoint':{'vm_mac':MAC.hex(),'destination_ipv4':'10.0.2.2','destination_port':4444},
            'selected':[{'index':i,'source_port':50000+i} for i in range(3)],
            'ordinary':[{'index':i,'source_port':51000+i,'phase':phase,'connect_succeeded':True,'nonce_verified':True}
                        for i,phase in enumerate(('before','sample','sample','after'))]}

def bound(value):
    raw=json.dumps(value,separators=(',',':')).encode()
    return raw, {'binding':copy.deepcopy(value['binding']),'endpoint':copy.deepcopy(value['endpoint']),
                 'manifest_sha256':hashlib.sha256(raw).hexdigest(),'connect_controls_verified':True}

def frame(port, flags=2, mac=MAC, dst=b'\x0a\0\x02\x02', dport=4444, ip_options=0, tcp_options=0, fragment=0):
    tcp=struct.pack('!HHIIBBHHH',port,dport,0,0,((20+tcp_options)//4)<<4,flags,0,0,0)+b'\0'*tcp_options
    ip=struct.pack('!BBHHHBBH4s4s',0x40+(20+ip_options)//4,0,20+ip_options+len(tcp),0,fragment,64,6,0,b'\x0a\0\x02\x0f',dst)+b'\0'*ip_options
    return b'\x52\x54\0\xaa\xbb\xcc'+mac+b'\x08\0'+ip+tcp

def pcap(frames, endian='<',nano=False,snaplen=262144,link=1):
    magic=0xa1b23c4d if nano else 0xa1b2c3d4
    data=struct.pack(endian+'IHHIIII',magic,2,4,0,0,snaplen,link)
    return data+b''.join(struct.pack(endian+'IIII',1,i,len(f),len(f))+f for i,f in enumerate(frames))

def evidence(data):
    return dict(sha256=hashlib.sha256(data).hexdigest(),bytes=len(data),
                **{k:True for k in p.POSITIVE_CAPTURE},**{k:False for k in p.NEGATIVE_CAPTURE},
                sink_status='complete',sink_exit_code=0)

def run(frames=None, value=None, data=None):
    value=manifest() if value is None else value
    raw,expected=bound(value)
    if data is None: data=pcap([frame(51000+i) for i in range(4)] if frames is None else frames)
    return p.evaluate(data,raw,expected,evidence(data))

class ManifestTests(unittest.TestCase):
    def test_valid(self):
        raw,expected=bound(manifest()); value,collision=p.validate_manifest(raw,expected)
        self.assertFalse(collision); self.assertEqual(len(value['selected']),3)
    def test_duplicate_json_key(self):
        raw,expected=bound(manifest()); raw=raw.replace(b'"schema_version":1',b'"schema_version":1,"schema_version":1')
        expected['manifest_sha256']=hashlib.sha256(raw).hexdigest()
        with self.assertRaises(ValueError): p.validate_manifest(raw,expected)
    def test_manifest_bound(self):
        with self.assertRaises(ValueError): p.validate_manifest(b' '*(p.MAX_MANIFEST+1),{})
    def test_binding_mismatch_has_no_positive_claim(self):
        raw,expected=bound(manifest()); expected['binding']['actor_sha256']='b'*64
        data=pcap([frame(50000)])
        result=p.evaluate(data,raw,expected,evidence(data))
        self.assertEqual(result['reasons'],['binding']); self.assertIsNone(result['tuple_packet_observed'])
    def test_expected_binding_exact_types(self):
        raw,expected=bound(manifest());expected['binding']['build']=26300.0
        with self.assertRaises(ValueError):p.validate_manifest(raw,expected)
    def test_digest_mismatch(self):
        raw,expected=bound(manifest()); expected['manifest_sha256']='0'*64
        with self.assertRaises(ValueError): p.validate_manifest(raw,expected)
    def test_strict_types_extra_missing_nonce(self):
        for field,value in [('build',True),('ubr',9457.0),('case_nonce','wrong')]:
            m=manifest();m['binding'][field]=value
            raw,expected=bound(m)
            with self.subTest(field=field),self.assertRaises(ValueError):p.validate_manifest(raw,expected)
        for change in ('extra','missing','bool_port','bad_phase','bad_index','not_success','bad_mac'):
            m=manifest()
            if change=='extra':m['ordinary'][0]['raw']='secret'
            if change=='missing':m.pop('selected')
            if change=='bool_port':m['selected'][0]['source_port']=True
            if change=='bad_phase':m['ordinary'][-1]['phase']='sample'
            if change=='bad_index':m['selected'][0]['index']=True
            if change=='not_success':m['ordinary'][0]['connect_succeeded']=1
            if change=='bad_mac':m['endpoint']['vm_mac']='ffffffffffff'
            raw,expected=bound(m)
            with self.subTest(change=change),self.assertRaises(ValueError):p.validate_manifest(raw,expected)
    def test_all_collision_classes(self):
        for group,source in [('selected',50000),('ordinary',51000),('ordinary',50000)]:
            m=manifest();m[group][-1]['source_port']=source
            result=run(value=m,frames=[frame(50000)]+[frame(51000+i) for i in range(4)])
            self.assertFalse(result['ports_unique']);self.assertTrue(result['tuple_packet_observed'])
            self.assertEqual(result['status'],'inconclusive');self.assertIn('port_collision',result['reasons'])
    def test_max_ordinary_rows(self):
        m=manifest();m['ordinary']=[dict(index=i,phase=('before' if i==0 else 'after' if i==41 else 'sample'),source_port=51000+i,connect_succeeded=True,nonce_verified=True) for i in range(42)]
        raw,expected=bound(m);self.assertLess(len(raw),65536);p.validate_manifest(raw,expected)
        m['ordinary'].append(m['ordinary'][-1]);raw,expected=bound(m)
        with self.assertRaises(ValueError):p.validate_manifest(raw,expected)

class DecoderTests(unittest.TestCase):
    def test_complete_controls_absence(self):
        result=run();self.assertEqual(result['status'],'no_selected_tuple_observed')
        self.assertFalse(result['actor_attribution_established']);self.assertFalse(result['isolation_acceptance'])
    def test_all_magic_variants_options(self):
        for endian in '<>':
            for nano in (False,True):
                result=run(data=pcap([frame(51000+i,ip_options=40,tcp_options=40) for i in range(4)],endian,nano))
                self.assertEqual(result['status'],'no_selected_tuple_observed')
    def test_any_selected_packet_flags(self):
        for flags in (2,16,4,0,0xff):
            result=run([frame(50000,flags)]+[frame(51000+i) for i in range(4)])
            self.assertTrue(result['tuple_packet_observed']);self.assertEqual(result['status'],'tuple_packet_observed')
    def test_positive_then_truncated_sticky(self):
        data=pcap([frame(50000)])+b'\0'*7
        result=run(data=data)
        self.assertTrue(result['tuple_packet_observed']);self.assertEqual(result['status'],'inconclusive')
        self.assertFalse(result['actor_attribution_established'])
    def test_terminal_required_and_ordered(self):
        for ports in ([51000,51001,51002],[51003,51000,51001,51002]):
            result=run([frame(port) for port in ports]);self.assertIn('ordinary_syn',result['reasons'])
    def test_invalid_syn_flags(self):
        for flags in (0,16,18,3,6,0xff):
            result=run([frame(51000+i,flags) for i in range(4)])
            self.assertFalse(result['ordinary_syn_controls'])
        self.assertTrue(run([frame(51000+i,0xc2) for i in range(4)])['ordinary_syn_controls'])
    def test_unknown_flow(self):
        result=run([frame(52000)]+[frame(51000+i) for i in range(4)])
        self.assertEqual(result['unknown_flow_packets'],1);self.assertEqual(result['status'],'inconclusive')
    def test_foreign_and_other_destinations_ignored(self):
        extras=[frame(50000,mac=b'\x52\x54\0\0\0\1'),frame(50000,dport=4445),frame(50000,dst=b'\x08\x08\x08\x08')]
        self.assertEqual(run(extras+[frame(51000+i) for i in range(4)])['status'],'no_selected_tuple_observed')
    def test_arp_ipv6_ignored_vlan_unknown_refused(self):
        for ether in (0x0806,0x86dd,0x8100,0x88a8,0x1234):
            extra=b'\0'*6+MAC+struct.pack('!H',ether)+b'\0'*40
            result=run([extra]+[frame(51000+i) for i in range(4)])
            self.assertEqual(result['status'],'no_selected_tuple_observed' if ether in (0x0806,0x86dd) else 'inconclusive')
    def test_fragments(self):
        for fragment in (0x2000,1,0x2001):
            result=run([frame(50000,fragment=fragment)]+[frame(51000+i) for i in range(4)])
            self.assertIn('fragment',result['reasons']);self.assertEqual(result['status'],'inconclusive')
    def test_header_and_record_bounds(self):
        for data in (b'',pcap([]),pcap([],link=101),pcap([],snaplen=262145),b'\x0a\x0d\x0d\x0a'+b'\0'*20):
            self.assertEqual(run(data=data)['status'],'inconclusive')
        with patch.object(p,'MAX_PCAP',24):self.assertEqual(run()['status'],'inconclusive')
        with patch.object(p,'MAX_RECORDS',1):self.assertIn('record_bound',run()['reasons'])
        self.assertIn('frame_bound',run(data=pcap([b'\0'*65537]))['reasons'])
    def test_truncated_packet_and_bad_lengths(self):
        base=pcap([frame(50000)])
        result=run(data=base[:-1]);self.assertIn('truncated',result['reasons'])
        data=bytearray(base);struct.pack_into('<I',data,36,len(frame(50000))+1)
        self.assertIn('truncated',run(data=bytes(data))['reasons'])
        for offset,value in ((14,0x44),(16,0xff),(46,0x40)):
            bad=bytearray(frame(50000));bad[offset]=value
            self.assertEqual(run([bytes(bad)]+[frame(51000+i) for i in range(4)])['status'],'inconclusive')
    def test_retransmissions_do_not_invent_collision(self):
        result=run([frame(51000),frame(51000)]+[frame(51000+i) for i in range(1,4)])
        self.assertTrue(result['ports_unique']);self.assertEqual(result['status'],'no_selected_tuple_observed')
    def test_lifecycle_facts_all_required(self):
        m=manifest();raw,expected=bound(m);data=pcap([frame(51000+i) for i in range(4)])
        good=evidence(data)
        for key in p.POSITIVE_CAPTURE|p.NEGATIVE_CAPTURE:
            bad=dict(good);bad[key]=not good[key]
            self.assertEqual(p.evaluate(data,raw,expected,bad)['status'],'inconclusive')
            bad[key]=1 if good[key] else 0
            self.assertEqual(p.evaluate(data,raw,expected,bad)['status'],'inconclusive')
        for key,value in [('sha256','0'*64),('bytes',True),('sink_status','running'),('sink_exit_code',True)]:
            bad=dict(good);bad[key]=value
            self.assertEqual(p.evaluate(data,raw,expected,bad)['status'],'inconclusive')
    def test_connect_controls_contract_strict_and_separate(self):
        raw,expected=bound(manifest());data=pcap([frame(50000)]+[frame(51000+i) for i in range(4)])
        expected['connect_controls_verified']=False
        result=p.evaluate(data,raw,expected,evidence(data))
        self.assertTrue(result['tuple_packet_observed']);self.assertEqual(result['status'],'inconclusive')
        self.assertIn('connect_controls',result['reasons'])
        expected['connect_controls_verified']=1
        self.assertIsNone(p.evaluate(data,raw,expected,evidence(data))['tuple_packet_observed'])
        expected.pop('connect_controls_verified')
        self.assertEqual(p.evaluate(data,raw,expected,evidence(data))['status'],'inconclusive')
    def test_capture_digest_mismatch_retains_only_byte_observation(self):
        raw,expected=bound(manifest());data=pcap([frame(50000)]+[frame(51000+i) for i in range(4)])
        bad=evidence(data);bad['sha256']='0'*64
        result=p.evaluate(data,raw,expected,bad)
        self.assertTrue(result['tuple_packet_observed']);self.assertEqual(result['status'],'inconclusive')
        self.assertFalse(result['capture_complete_contract']);self.assertFalse(result['actor_attribution_established'])
    def test_closed_output_no_private_identifiers(self):
        result=run();encoded=json.dumps(result)
        for private in (MAC.hex(),'10.0.2.2','50000','51000','a'*32):self.assertNotIn(private,encoded)
        self.assertLess(len(encoded),4096)
        self.assertFalse(result['checksums_validated']);self.assertFalse(result['qpc_timestamp_mapping_used'])

if __name__=='__main__':unittest.main()
