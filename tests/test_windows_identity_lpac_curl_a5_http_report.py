"""Pure fake-input tests. No project owner import, process, socket or Windows API."""
import copy
import hashlib
import importlib.util
import json
from pathlib import Path
from types import SimpleNamespace
import unittest

DIRECTORY=Path(__file__).resolve().parents[1]/'.github'
def load(name):
    spec=importlib.util.spec_from_file_location(name,DIRECTORY/(name+'.py'))
    module=importlib.util.module_from_spec(spec);spec.loader.exec_module(module);return module
physical=load('windows_identity_lpac_curl_a5_physical')
report=load('windows_identity_lpac_curl_a5_http_report')

def need(value,label):
    if not value:raise ValueError(label)
def digest(raw):return hashlib.sha256(raw).hexdigest()


class ConstructorBinding(unittest.TestCase):
    def setUp(self):
        self.m=SimpleNamespace(require=need)
        self.handles=[11,12,13,14,15,16]
        self.task={'inherited_handles':list(self.handles)}
        self.data=dict(handle_list=list(self.handles),stdio=[14,15,16],handle_flags=[1]*6,inherit_handles=True)
    def test_six_actual_constructor_inputs(self):
        observed=physical.constructor_handles(self.m,self.data,self.task,selected=True)
        self.assertEqual(observed,self.handles);self.assertIsNot(observed,self.task['inherited_handles'])
    def test_ordinary_exact_three(self):
        data=dict(handle_list=[14,15,16],stdio=[14,15,16],handle_flags=[1]*3,inherit_handles=True)
        self.assertEqual(physical.constructor_handles(self.m,data,{'inherited_handles':[14,15,16]},selected=False),[14,15,16])
    def test_missing_observed_fields_never_uses_expected(self):
        for key in self.data:
            with self.subTest(key=key):
                data=copy.deepcopy(self.data);del data[key]
                with self.assertRaises(ValueError):physical.constructor_handles(self.m,data,self.task,selected=True)
    def test_wrong_swapped_duplicate_or_bool_handles(self):
        for handles in ([11,13,12,14,15,16],[11,12,13,14,15,15],[True,12,13,14,15,16],[11,12,13,14,15]):
            with self.subTest(handles=handles):
                data=copy.deepcopy(self.data);data['handle_list']=handles
                with self.assertRaises(ValueError):physical.constructor_handles(self.m,data,self.task,selected=True)
    def test_stdio_flags_and_actual_inherit_bool(self):
        for key,value in [('stdio',[14,16,15]),('handle_flags',[1,1,1,1,1,0]),('handle_flags',[True]*6),('inherit_handles',1),('inherit_handles',False)]:
            with self.subTest(key=key,value=value):
                data=copy.deepcopy(self.data);data[key]=value
                with self.assertRaises(ValueError):physical.constructor_handles(self.m,data,self.task,selected=True)


class HTTPBytes(unittest.TestCase):
    def setUp(self):
        self.root=Path('fake-owned-root');self.case='12'*16;self.port=51001
        self.req_header=(f'POST /ruleproxy-a2/{self.case} HTTP/1.1\r\nHost: 127.0.0.1:{self.port}\r\n'
            'Content-Length: 8065\r\nConnection: close\r\n\r\n').encode('ascii')
        self.res_header=('HTTP/1.1 200 OK\r\nContent-Length: 12176\r\nConnection: close\r\n'
            f'X-RuleProxy-Case: {self.case}\r\n\r\n').encode('ascii')
        # Different from the historical calibration formulas, and independent
        # of the nonce; each body includes every byte value and literal RPS1.
        self.req_body=b'RPS1'+(bytes(range(256))*32)[:8061]
        self.res_body=b'RPS1'+(bytes(reversed(range(256)))*48)[:12172]
        self.request=self.req_header+self.req_body;self.response=self.res_header+self.res_body
        self.paths=(self.root/'inputs/request.bin',self.root/'inputs/response.bin')
        self.files={self.paths[0]:self.request,self.paths[1]:self.response,
            self.root/'package/request-body.bin':self.req_body,
            self.root/'selected-output/stdout':self.res_body,self.root/'selected-output/stderr':b''}
        self.c={'case':self.case,'proxy':{'ports':{'origin_port':self.port},'challenges':{
            'request':{'bytes':8193,'sha256':digest(self.request)},'response':{'bytes':12289,'sha256':digest(self.response)}}}}
        def bounded(path,limit):
            raw=self.files[Path(path)];need(len(raw)<=limit,'bounded');return raw
        def challenge(raw,*,response,case,origin_port):
            need(case==self.case and origin_port==self.port,'case_port')
            header=self.res_header if response else self.req_header
            need(raw.startswith(header) and set(raw[len(header):])==set(range(256)) and b'RPS1' in raw[len(header):],'challenge')
            return dict(bytes=len(raw),sha256=digest(raw))
        self.m=SimpleNamespace(require=need,sha=digest,http_challenge_paths=lambda root:self.paths,
            launcher=SimpleNamespace(checked_path=lambda path,**kw:Path(path)),local=SimpleNamespace(bounded=bounded),
            config_codec=SimpleNamespace(fixed_headers=lambda case,port:(self.req_header,self.res_header)),
            proxy_protocol=SimpleNamespace(http_challenge=challenge))
    def test_this_run_full_HTTP_and_selected_body(self):
        self.assertEqual(report.HTTP_inputs(self.m,self.c,self.root),(self.request,self.response))
        out=report.selected_output(self.m,self.c,self.root)
        self.assertTrue(out['exact_HTTP_body']);self.assertEqual(out['stdout_bytes'],12176)
        self.assertEqual(out['stdout_sha256'],digest(self.res_body))
    def test_changed_full_challenge_rejected_by_pin(self):
        self.files[self.paths[1]]=self.response[:-1]+bytes([self.response[-1]^1])
        with self.assertRaisesRegex(ValueError,'pins'):report.HTTP_inputs(self.m,self.c,self.root)
    def test_wrong_request_body_file_rejected(self):
        self.files[self.root/'package/request-body.bin']=bytes(8065)
        with self.assertRaisesRegex(ValueError,'request_body'):report.HTTP_inputs(self.m,self.c,self.root)
    def test_historical_calibration_body_is_not_this_run_positive(self):
        self.files[self.root/'selected-output/stdout']=bytes((i*29+211)%256 for i in range(12176))
        self.assertFalse(report.selected_output(self.m,self.c,self.root)['exact_HTTP_body'])
    def test_changed_selected_byte_and_stderr_are_negative(self):
        self.files[self.root/'selected-output/stdout']=self.res_body[:-1]+bytes([self.res_body[-1]^1])
        self.assertFalse(report.selected_output(self.m,self.c,self.root)['exact_HTTP_body'])
        self.files[self.root/'selected-output/stdout']=self.res_body
        self.files[self.root/'selected-output/stderr']=b'error'
        self.assertFalse(report.selected_output(self.m,self.c,self.root)['exact_HTTP_body'])
    def test_forged_selected_summary_rejected(self):
        out=report.selected_output(self.m,self.c,self.root);out['stdout_sha256']='a'*64
        with self.assertRaises(ValueError):report.validate_selected_output(self.m,{'selected_output':out},self.c,self.root,{'exited':True})


class NarrowPredicate(unittest.TestCase):
    def test_pipe_wire_bytes_crossbind_physical_and_mutation(self):
        raw=json.dumps({'pipe':{'read_bytes':9001,'write_bytes':13249}}).encode('ascii')
        proxy={'reports':{'relay':{'text':raw.decode('ascii'),'sha256':digest(raw)}}}
        facts={'complete':True,'read_bytes':13249,'write_bytes':9001};trace={'transport':{'pipe_facts':facts}}
        m=SimpleNamespace(require=need,sha=digest,decode=lambda data:json.loads(data),
            launcher=SimpleNamespace(checked_path=lambda path,**kw:path),
            local=SimpleNamespace(bounded=lambda path,limit:raw))
        self.assertTrue(report.pipe_bytes_crossbind(m,trace,proxy,Path('fake')))
        for key in ('read_bytes','write_bytes'):
            facts[key]+=1
            self.assertFalse(report.pipe_bytes_crossbind(m,trace,proxy,Path('fake')))
            facts[key]-=1
        self.assertFalse(report.pipe_bytes_crossbind(m,None,proxy,Path('fake')))
        facts['complete']=False;self.assertFalse(report.pipe_bytes_crossbind(m,trace,proxy,Path('fake')))
        facts['complete']=True;m.local.bounded=lambda path,limit:b'changed'
        with self.assertRaises(ValueError):report.pipe_bytes_crossbind(m,trace,proxy,Path('fake'))
        all_facts=dict.fromkeys(report.FINITE_REQUIRED,True)
        self.assertFalse(report.finite_HTTP(all_facts,leases_complete=True))
        self.assertFalse(report.finite_HTTP(all_facts,leases_complete=True,pipe_bytes_bound=False))

    def test_reader_binding_uses_physical_observed_handles(self):
        expected=[11,12,13,14,15,16];observed=[21,22,23,24,25,26];captured={}
        def review(raw,**kwargs):captured.update(kwargs);return {'result':'fake-reader'}
        m=SimpleNamespace(SCOPE='local-lpac-curl-a5-http',sha=digest,
            trace_reader=SimpleNamespace(SCHEMA_METADATA={},validate_config=lambda *a,**k:{'window_start':100,'window_end':108},review=review),
            physical=SimpleNamespace(observed_handles=lambda *a:observed))
        c={'run':'12'*16,'case':'34'*16,'source_sha256':'56'*32,'proxy':{'ports':{'origin_port':51001}}}
        selected={'pid':123,'created':456,'inherited_handles':expected}
        result=report.reader_review(m,b'trace',b'config',c,selected,parent={},root=None)
        self.assertEqual(result,{'result':'fake-reader'})
        binding=captured['transport_binding']
        self.assertEqual(binding['inherited_handles'],expected)
        self.assertEqual(binding['observed_inherited_handles'],observed)
        self.assertNotEqual(binding['inherited_handles'],binding['observed_inherited_handles'])
        self.assertEqual(binding['config_bytes_sha256'],digest(b'config'))
        self.assertEqual(binding['endpoint'],{'family':'IPv4','address':'127.0.0.1','port':51001,'protocol':'TCP'})

    def test_calibration_is_optional_and_never_supplies_finite_gate(self):
        value=dict.fromkeys(report.FINITE_REQUIRED,True)
        value['ordinary_HTTP_calibration_positive']=False
        self.assertTrue(report.finite_HTTP(value,leases_complete=True,pipe_bytes_bound=True))
        for key in report.FINITE_REQUIRED:
            changed=dict(value);changed[key]=False;changed['ordinary_HTTP_calibration_positive']=True
            with self.subTest(key=key):self.assertFalse(report.finite_HTTP(changed,leases_complete=True,pipe_bytes_bound=True))
        self.assertFalse(report.finite_HTTP(value,leases_complete=False,pipe_bytes_bound=True))
    def test_missing_calibration_root_false(self):
        m=SimpleNamespace(trace_reader=SimpleNamespace(review_HTTP_byte_controls=lambda records:{'byte_controls_candidate':False}))
        self.assertFalse(report.validate_HTTP_calibration(m,{})['byte_controls_candidate'])
        m.http_calibration_root=lambda c:None
        self.assertFalse(report.validate_HTTP_calibration(m,{})['byte_controls_candidate'])
    def test_missing_proxy_stays_absent(self):
        self.assertIsNone(report.proxy_review(SimpleNamespace(),{'proxy':None},{},None,None,parent=None))
    def test_proxy_same_pid_generation_and_totals_required(self):
        selected={'pid':123,'created':456};c={'run':'12'*16,'case':'34'*16}
        value=dict(scope='local-lpac-curl-a5-http',run=c['run'],case=c['case'],selected_pid=123,
            selected_creation=456,request_bytes=8193,response_bytes=12289,
            transport_positive=True,byte_sinks_verified=True,cleanup_verified=True)
        m=SimpleNamespace(SCOPE=value['scope'],require=need,validate_proxy_result=lambda *args,**kw:value)
        self.assertEqual(report.proxy_review(m,{'proxy':{}},c,None,selected,parent={}),value)
        for key,bad in [('selected_pid',124),('selected_creation',457),('request_bytes',8192),('response_bytes',12288),('request_bytes',True)]:
            original=value[key];value[key]=bad
            with self.subTest(key=key):
                with self.assertRaises(ValueError):report.proxy_review(m,{'proxy':{}},c,None,selected,parent={})
            value[key]=original


if __name__=='__main__':unittest.main()
