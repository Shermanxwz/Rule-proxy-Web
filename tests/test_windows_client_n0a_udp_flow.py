"""Private UDP bundle/normalizer contract, no actor/transport execution."""
import copy
import hashlib
import importlib.util
import json
from pathlib import Path
import struct
import tempfile
import unittest
ROOT=Path(__file__).resolve().parents[1]
def load(name,path):
    spec=importlib.util.spec_from_file_location(name,path);value=importlib.util.module_from_spec(spec);spec.loader.exec_module(value);return value
f=load('udp_flow_test',ROOT/'.github/windows_n0a_udp_flow.py')
p=load('udp_packet_test',ROOT/'.github/windows_n0a_udp_packet.py')
u=f.engine()

def network(phase,starts):
    rows=[]
    for i,start in enumerate(starts):
        rows.append(dict(index=i,attempted=True,socketCreated=True,bindSucceeded=True,localPort={'before':40000,'sample':41000,'contained':42000,'after':43000}[phase]+i,localIpv4=0,
          sendStartQpc=start,sendEndQpc=start+1,sendAccepted=True,sendBytes=len(u.frame('a'*32,phase,i)),nonceMatched=True,exchangeEndQpc=start+2,win32Error=0,failure='none',closed=True,closeError=0,closeQpc=20000))
    return dict(version=1,endpoint='runner',phase=phase,port=44000,profileMatched=True,startupError=0,qpcFrequency=1000,windowStartQpc=starts[0],windowEndQpc=starts[-1]+2,attempts=rows,testOnly=False,socketsCleanupConfirmed=True)

def value(samples=None):
    binding={k:'a'*(32 if k.endswith('nonce') else 40 if k=='source_commit' else 64) for k in f.BINDING_KEYS-{'build','ubr'}};binding.update(build=26300,ubr=9457)
    ns={k:network(k,s) for k,s in {'before':[10],'sample':samples or [100,700,1800],'contained':[500,1000,1500],'after':[1900]}.items()}
    return dict(schema_version=1,protocol='udp',binding=binding,endpoint=dict(vm_mac='525400123456',destination_ipv4='10.0.2.2',destination_port=44000),reports={k:dict(sha256=hex(i+1)[2:]*64,bytes=100+i,udp=ns[k]) for i,k in enumerate(f.ROLES)})

def expected(v,raw):
    facts=u.controls({k:r['udp'] for k,r in v['reports'].items()},'a'*32,44000)
    result=u.evaluate({},None);result.update(facts)
    result['profile_verified']={k:True for k in f.ROLES};result['provenance_verified']={k:True for k in f.ROLES}
    return dict(binding=copy.deepcopy(v['binding']),endpoint=copy.deepcopy(v['endpoint']),flow_commitment=f.commitment(raw),controller_result=dict(receipt_verified=True,result=result),cleanup_verified=True)

class FlowTests(unittest.TestCase):
    def test_same_buffer_hash_not_reserialized(self):
        raw=b'{ "mode" : "actor-n0a-udp", "udp" : {} }\n'
        with tempfile.TemporaryDirectory() as root:
            path=Path(root)/'report';path.write_bytes(raw)
            parsed,snapshot=f.read_snapshot(path)
        self.assertEqual(snapshot,dict(sha256=hashlib.sha256(raw).hexdigest(),bytes=len(raw)))
        self.assertNotEqual(snapshot['sha256'],hashlib.sha256(f.encode(parsed)).hexdigest())
    def test_read_bounds_duplicate_and_symlink(self):
        with tempfile.TemporaryDirectory() as root:
            path=Path(root)/'report'
            for raw in (b'',b'x'*32769,b'{"a":1,"a":2}'):
                path.write_bytes(raw)
                with self.assertRaises(ValueError):f.read_snapshot(path)
            path.write_bytes(b'{}');link=Path(root)/'link'
            try:link.symlink_to(path)
            except OSError:return
            with self.assertRaises(ValueError):f.read_snapshot(link)
    def test_aggregate_domain_roles_lengths(self):
        v=value();data=b'N0AU-ordinary-reports-v1\0'
        for role in ('before','sample','after'):
            r=v['reports'][role];data+=role.encode()+b'\0'+struct.pack('>Q',r['bytes'])+bytes.fromhex(r['sha256'])
        self.assertEqual(f.ordinary_digest(v['reports']),hashlib.sha256(data).hexdigest())
        original=f.ordinary_digest(v['reports']);v['reports']['before']['bytes']+=1
        self.assertNotEqual(original,f.ordinary_digest(v['reports']))
    def test_normalize_accepted_send_not_denial_requirement(self):
        v=value();raw=f.encode(v);result=f.normalize(raw,expected(v,raw))
        self.assertTrue(result['controls_verified']);m,collision=p.validate_manifest(result['manifest_bytes'],result['expected'])
        self.assertFalse(collision);self.assertEqual(len(m['selected']),3)
        self.assertEqual([r['index'] for r in m['ordinary']],[0,0,1,2,0])
    def test_all_40_samples_including_failed_preserved(self):
        v=value([100+i*250 for i in range(40)]);v['reports']['after']['udp']=network('after',[11000])
        row=v['reports']['sample']['udp']['attempts'][8];row.update(attempted=False,socketCreated=False,bindSucceeded=False,localPort=0,sendAccepted=False,sendBytes=-1,nonceMatched=False,closed=False,closeQpc=0)
        raw=f.encode(v);e=expected(v,raw);result=f.normalize(raw,e);m=json.loads(result['manifest_bytes'])
        self.assertEqual(len(m['ordinary']),42);self.assertIsNone(m['ordinary'][9]['source_port'])
        self.assertFalse(result['controls_verified']);self.assertLess(len(raw),65536)
    def test_bad_controls_cleanup_do_not_discard_selected_rows(self):
        v=value();raw=f.encode(v);e=expected(v,raw);e['cleanup_verified']=False;e['controller_result']['receipt_verified']=False
        result=f.normalize(raw,e);m=json.loads(result['manifest_bytes'])
        self.assertEqual(len(m['selected']),3);self.assertFalse(result['expected']['cleanup_verified']);self.assertFalse(result['controls_verified'])
    def test_no_guest_boolean_authority(self):
        v=value();v['reports']['sample']['udp']['attempts'][1]['nonceMatched']=False
        raw=f.encode(v);e=expected(v,raw);e['controller_result']['result']['ordinary_controls_verified']=True
        self.assertFalse(f.normalize(raw,e)['controls_verified'])
    def test_binding_protocol_commitment_and_types(self):
        v=value();raw=f.encode(v)
        for change in ('hash','nonce','port','cleanup'):
            e=expected(v,raw)
            if change=='hash':e['flow_commitment']['sha256']='0'*64
            if change=='nonce':e['binding']['case_nonce']='b'*32
            if change=='port':e['endpoint']['destination_port']=True
            if change=='cleanup':e['cleanup_verified']=1
            with self.assertRaises(ValueError):f.normalize(raw,e)
        v['protocol']='tcp'
        with self.assertRaises(ValueError):f.bundle(f.encode(v))
    def test_unknown_identity_fields_and_bounds_rejected(self):
        v=value();v['reports']['contained']['sid']='PRIVATE'
        with self.assertRaises(ValueError):f.bundle(f.encode(v))
        with self.assertRaises(ValueError):f.bundle(b' '*65537)
    def test_missing_rows_never_synthesized(self):
        v=value();v['reports']['contained']['udp']['attempts']=v['reports']['contained']['udp']['attempts'][:2]
        raw=f.encode(v);r=f.normalize(raw,expected(v,raw));self.assertEqual(len(json.loads(r['manifest_bytes'])['selected']),2)
        with self.assertRaises(ValueError):p.validate_manifest(r['manifest_bytes'],r['expected'])

if __name__=='__main__':unittest.main()
