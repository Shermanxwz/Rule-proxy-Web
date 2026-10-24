import copy,hashlib,importlib.util,json
from pathlib import Path
from types import SimpleNamespace as NS
import unittest
source=Path(__file__).resolve().parents[1]/'.github/windows_identity_lpac_curl_a5_staging_inputs.py'
spec=importlib.util.spec_from_file_location('a5_staging_under_test',source);module=importlib.util.module_from_spec(spec);spec.loader.exec_module(module)
def require(value,label):
    if not value:raise ValueError(label)
def encode(value):return json.dumps(value,sort_keys=True).encode()
def sha(value):return hashlib.sha256(value).hexdigest()
def ports(value):
    require(type(value) is dict and set(value)=={'origin_port','proxy_port'},'ports')
    require(all(type(x) is int and 49153<=x<=65535 for x in value.values()) and len(set(value.values()))==2,'ports')
    return value
core=NS(require=require,encode=encode,sha=sha,base=NS(ac=NS(digest=lambda v:type(v) is str and len(v)==64 and all(c in '0123456789abcdef' for c in v))),
        proxy_protocol=NS(ports=ports,mihomo_configuration=lambda p:dict(fixed_ports=p)))
def fixture():
    p=dict(ports=dict(origin_port=51001,proxy_port=51002),virtual_local_port=51003,artifacts=copy.deepcopy(module.FIXED),
           challenges={k:dict(bytes=n,sha256='11'*32) for k,n in [('request',8193),('response',12289)]},request_body=dict(bytes=8065,sha256='22'*32))
    p['mihomo_config_sha256']=sha(encode(core.proxy_protocol.mihomo_configuration(p['ports'])));return p
class InputsTests(unittest.TestCase):
    def test_configuration_and_exact_fixed_roles(self):
        p=fixture();self.assertEqual(module.metadata(core,p),encode(core.proxy_protocol.mihomo_configuration(p['ports'])))
        for field,value in [('virtual_local_port',True),('virtual_local_port',51001),('virtual_local_port',51002),
                            ('mihomo_config_sha256','00'*32),('challenges',{'request':dict(bytes=8193,sha256='11'*32)})]:
            q=fixture();q[field]=value
            with self.subTest(field=field),self.assertRaises(ValueError):module.metadata(core,q)
        for role in module.FIXED:
            q=fixture();q['artifacts'][role]['bytes']+=1
            with self.subTest(role=role),self.assertRaises(ValueError):module.metadata(core,q)
    def test_no_new_artifact_role_or_length_or_unknown_key(self):
        for mutator in (lambda p:p.update(extra=True),lambda p:p['request_body'].update(bytes=8193),
                        lambda p:p['challenges']['response'].update(bytes=12176),lambda p:p['artifacts'].update(other=dict(bytes=1,sha256='22'*32))):
            q=fixture();mutator(q)
            with self.assertRaises(ValueError):module.metadata(core,q)
    def test_bundle_is_sibling_exact_nonce_never_parent_traversal(self):
        parent=Path('C:/owned/private');stage=parent/'local-lpac-curl-a5-http-test'
        self.assertEqual(module.bundle(stage,'12'*16),parent/('mihomo-a5-private-bundle-'+'12'*16))
        for bad in ('../outside','12'*15,True,'G'*32):
            with self.subTest(bad=bad),self.assertRaises(ValueError):module.bundle(stage,bad)
if __name__=='__main__':unittest.main()
