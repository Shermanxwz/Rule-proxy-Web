import copy
import hashlib
import importlib.util
import json
from pathlib import Path
import struct
import sys
import tempfile
import unittest
from unittest.mock import patch
import test_windows_client_n0a_control as fixture
ROOT=Path(__file__).resolve().parents[1]
def load(name,path):
    spec=importlib.util.spec_from_file_location(name,ROOT/path);m=importlib.util.module_from_spec(spec);sys.modules[name]=m;spec.loader.exec_module(m);return m
f=load('flow_test','.github/windows_n0a_flow.py')
g=load('flow_guest_test','.github/windows_n0a_guest.py')
p=load('flow_packet_test','.github/windows_n0a_packet.py')
CONFIG={'capture':{'enabled':True,'run_nonce':'1'*32,'source_commit':'2'*40,'vm_mac':'525400123456'},'n0a':{'actor_source_sha256':'3'*64,'identity_source_sha256':'4'*64}}
def make(sample_count=3):
    case=fixture.case('runner')
    if sample_count==40:case['during']=fixture.report('runner','ordinary','sample',[1500]+list(range(2000,2114,3))+[3300])
    snapshots={};port=31000
    for role in ('before','during','contained','after'):
        actor=case[role]['actor']
        for row in actor['n0a']['attempts']:row['localPort']=port;port+=1
        raw=json.dumps(actor,indent=2).encode('ascii');snapshots[id(actor)]={'sha256':hashlib.sha256(raw).hexdigest(),'bytes':len(raw)}
    raw=f.build_bundle(CONFIG,fixture.B,case,snapshots)
    value=f.bundle(raw)
    observed={'receipt_verified':True,'result':fixture.n.evaluate({'runner':case,'guest':fixture.case('guest')},fixture.B)}
    expected={'binding':value['binding'],'endpoint':value['endpoint'],'flow_commitment':f.commitment(raw),'controller_result':observed}
    return case,snapshots,raw,expected
class FlowTests(unittest.TestCase):
    def test_snapshot_exact_original_bytes(self):
        with tempfile.TemporaryDirectory() as d:
            path=Path(d)/'a';raw=b'{ "native" : true }\n';path.write_bytes(raw)
            value,digest=f.read_snapshot(path)
            self.assertEqual(value,{'native':True});self.assertEqual(digest,{'sha256':hashlib.sha256(raw).hexdigest(),'bytes':len(raw)})
            self.assertNotEqual(digest['sha256'],hashlib.sha256(f.encode(value)).hexdigest())
    def test_snapshot_hash_and_parse_use_one_read(self):
        from unittest.mock import mock_open
        raw=b'{ "native": 1 }\n';opener=mock_open(read_data=raw)
        with tempfile.TemporaryDirectory() as d:
            path=Path(d)/'a';path.write_bytes(raw)
            with patch.object(Path,'open',opener):
                value,snapshot=f.read_snapshot(path)
            opener.assert_called_once_with('rb')
            opener().read.assert_called_once_with(32769)
            self.assertEqual(value,{'native':1})
            self.assertEqual(snapshot['sha256'],hashlib.sha256(raw).hexdigest())
    def test_snapshot_bounds_duplicates_and_link(self):
        with tempfile.TemporaryDirectory() as d:
            path=Path(d)/'a'
            for raw in (b'',b' '*32769,b'{"x":1,"x":2}',b'[]',b'{"x":NaN}'):
                path.write_bytes(raw)
                with self.assertRaises(ValueError):f.read_snapshot(path)
            path.write_bytes(b'{}');link=Path(d)/'link'
            try:link.symlink_to(path)
            except OSError:return
            with self.assertRaises(ValueError):f.read_snapshot(link)
    def test_complete_and_private_projection(self):
        _,_,raw,expected=make();value=f.normalize(raw,expected)
        self.assertTrue(value['controls_verified']);p.validate_manifest(value['manifest_bytes'],value['expected'])
        for token in (b'PRIVATE',b'token',b'pid',b'S-1-'):
            self.assertNotIn(token,raw)
    def test_all_forty_samples_retained(self):
        _,_,raw,e=make(40);value=f.normalize(raw,e);manifest=json.loads(value['manifest_bytes'])
        self.assertEqual(len(manifest['ordinary']),42);self.assertEqual(manifest['ordinary'][-1]['phase'],'after')
        self.assertEqual([r['phase'] for r in manifest['ordinary'][1:-1]],['sample']*40)
    def test_aggregate_exact_domain_length_role(self):
        _,_,raw,_=make();reports=f.bundle(raw)['reports'];data=b'N0A-ordinary-reports-v1\0'
        for role in ('before','sample','after'):data+=role.encode()+b'\0'+struct.pack('>Q',reports[role]['bytes'])+bytes.fromhex(reports[role]['sha256'])
        self.assertEqual(f.ordinary_digest(reports),hashlib.sha256(data).hexdigest())
        reports['sample']['bytes']+=1;self.assertNotEqual(f.ordinary_digest(reports),hashlib.sha256(data).hexdigest())
    def test_invalid_context_commitment(self):
        _,_,raw,e=make()
        for key in ('sha256','bytes','contained_report_sha256','ordinary_report_sha256'):
            bad=copy.deepcopy(e);bad['flow_commitment'][key]=0
            with self.assertRaises(ValueError):f.normalize(raw,bad)
        bad=copy.deepcopy(e);bad['binding']['case_nonce']='e'*32
        with self.assertRaises(ValueError):f.normalize(raw,bad)
    def test_no_controller_boolean_shortcut(self):
        _,_,raw,e=make();e['controller_result']={'receipt_verified':False}
        self.assertFalse(f.normalize(raw,e)['controls_verified'])
        _,_,raw,e=make();value=f.bundle(raw);value['reports']['sample']['n0a']['attempts'][1]['nonceMatched']=False;raw=f.encode(value);e['flow_commitment']=f.commitment(raw)
        self.assertFalse(f.normalize(raw,e)['controls_verified'])
    def test_network_observation_parity(self):
        case,_,_,_=make()
        for key,value in [('win32Error',10061),('closed',False),('connectStartQpc',True),('failure','private')]:
            c=copy.deepcopy(case);c['contained']['actor']['n0a']['attempts'][0][key]=value
            observed=fixture.n.observation(c['contained'],fixture.B,'runner','contained','single')
            self.assertEqual(f.validate_network(c['contained']['actor']['n0a'],19002,'contained','single'),observed)
    def test_missing_snapshot_or_invalid_source(self):
        case,snapshots,_,_=make();snapshots.clear()
        with self.assertRaises(KeyError):f.build_bundle(CONFIG,fixture.B,case,snapshots)
        case,snapshots,_,_=make();case['contained']['pid_verified']=False
        with self.assertRaises(ValueError):f.build_bundle(CONFIG,fixture.B,case,snapshots)
    def test_success_not_fabricated_denial(self):
        case,snapshots,_,_=make();case['contained']['actor']['n0a']['attempts'][0]['connectSucceeded']=True
        raw=f.build_bundle(CONFIG,fixture.B,case,snapshots)
        self.assertFalse(f.network_controls(f.bundle(raw)['reports']))
        self.assertTrue(f.bundle(raw)['reports']['contained']['n0a']['attempts'][0]['connectSucceeded'])
    def test_bundle_bounds_strict_types(self):
        _,_,raw,e=make()
        for value in (None,b'',b' '*65537,b'{"x":1,"x":2}'):
            with self.assertRaises((ValueError,TypeError)):f.bundle(value)
        v=f.bundle(raw);v['binding']['build']=True
        with self.assertRaises(ValueError):f.bundle(f.encode(v))
    def test_capture_prepare_failure_does_not_change_result(self):
        case,snapshots,_,_=make();result=fixture.n.evaluate({'runner':case},fixture.B);before=copy.deepcopy(result)
        execution=type('E',(),{'snapshots':snapshots})()
        with patch.object(g,'flow_helpers',side_effect=ValueError('fixture')):
            self.assertFalse(g.prepare_flow(CONFIG['n0a'],CONFIG['capture'],fixture.B,{'runner':case},execution,10**20))
        self.assertEqual(result,before)
    def test_off_mode_never_loads_flow(self):
        with patch.object(g,'flow_helpers',side_effect=AssertionError('off')):
            self.assertFalse(g.prepare_flow({},None,None,None,None,0))
    def test_expired_preparation_does_not_write(self):
        with patch.object(g,'flow_helpers',side_effect=AssertionError('expired')):
            self.assertFalse(g.prepare_flow({},CONFIG['capture'],None,None,object(),0))
if __name__=='__main__':unittest.main()
