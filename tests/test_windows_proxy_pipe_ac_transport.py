"""Inert default-off AC-pair host/PS transport, no native process or VM execution."""
import ast,copy,hashlib,importlib.util,io,json,re,sys,tempfile,threading,unittest,zipfile
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import Mock,patch
ROOT=Path(__file__).resolve().parents[1]
def load(name,path):
    spec=importlib.util.spec_from_file_location(name,ROOT/path);m=importlib.util.module_from_spec(spec);spec.loader.exec_module(m);return m
h=load('ac_transport_host','.github/windows_identity_direct_stage0.py')
S=(ROOT/'.github/windows-identity-direct-stage0-run.ps1').read_text()
CONFIG=dict(enabled=True,run_nonce='a'*32,case_nonce='b'*32,actor_sha256='c'*64,manifest_sha256='d'*64)
def part(name):return re.search(r'^function '+re.escape(name)+r'(?:\(|\s).*?^}',S,re.M|re.S).group()
def envelope():
    return dict(schema_version=1,proxy_pipe_ac=h.proxy_pipe_ac_helpers().default_public(CONFIG),launcher=dict(phase='completed',failure='none',python_exit_code=0,process_exit_confirmed=True,timed_out=False,budget_exhausted=False))
def passed():
    value=envelope();g=h.proxy_pipe_ac_helpers();c=g.controller_module();r=value['proxy_pipe_ac'];r['facts']={k:True for k in g.FACTS};pair=c._case_public(0)
    pair.update(admitted=True,created=3,resumed=3,exit_observed=3,identity_verified=3,parent_data_closed=True,reports_bound=3,observations=[177,78],core_failure=[0,0],pipe_eof=[True,True],native_close=[True,True],cleanup_confirmed=True,job_empty=True,expected_outcome=True,failure=None)
    r.update(pair=pair,status='passed',ac_pipe_passed=True);r['diagnostic'].update(controller_report='bound');return value
def parity_cases():
    rows=[]
    def add(name,value):
        try:h.proxy_pipe_ac_helpers().validate_public(value,CONFIG);valid=True
        except (ValueError,TypeError,KeyError):valid=False
        rows.append(dict(name=name,value=value,valid=valid))
    add('default',envelope()['proxy_pipe_ac']);add('passed',passed()['proxy_pipe_ac'])
    for key in h.proxy_pipe_ac_helpers().FACTS:
        row=passed()['proxy_pipe_ac'];row['facts'][key]=False;add('fact_'+key,row)
    mutations=[('schema',lambda r:r.update(schema_version=True)),('raw',lambda r:r.update(raw='private')),
      ('nonce',lambda r:r.update(run_nonce_sha256='0'*64)),('product',lambda r:r.update(product_acceptance=True)),
      ('failure',lambda r:r.update(ac_failure='unknown')),('phase',lambda r:r['diagnostic'].update(phase='unknown')),
      ('error',lambda r:r['diagnostic'].update(error_domain='none',error_code=1)),('binding',lambda r:r['diagnostic'].update(controller_report='parsed')),
      ('created_bool',lambda r:r['pair'].update(created=True)),('mask',lambda r:r['pair'].update(created=4)),
      ('observation',lambda r:r['pair'].update(observations=[255,78])),('eof',lambda r:r['pair'].update(pipe_eof=[True])),
      ('watchdog',lambda r:r['pair'].update(watchdog_stop=True)),('nested_extra',lambda r:r['pair'].update(raw='private'))]
    for name,mutate in mutations:
        row=passed()['proxy_pipe_ac'];mutate(row);add(name,row)
    return rows

def export_fixture(root):
    root=Path(root)
    if root.exists():raise ValueError('fixture ownership')
    root.mkdir()
    for name,value in [('cases.json',parity_cases()),('passed.json',passed()['proxy_pipe_ac'])]:
        raw=json.dumps(value,separators=(',',':')).encode('ascii')
        if len(raw)>131072:raise ValueError('fixture bound')
        with (root/name).open('xb') as stream:stream.write(raw)

class TransportTests(unittest.TestCase):
    def test_actual_ps_case_export_and_closed_dispatch_fixture(self):
        cases=parity_cases();self.assertEqual(len(cases),28);self.assertEqual(sum(r['valid'] for r in cases),2)
        self.assertEqual(len({r['name'] for r in cases}),28)
        with tempfile.TemporaryDirectory() as d:
            root=Path(d)/'owned';export_fixture(root)
            self.assertEqual(json.loads((root/'cases.json').read_text()),cases)
            self.assertLessEqual((root/'cases.json').stat().st_size,131072)
            with self.assertRaises(ValueError):export_fixture(root)
        source=(ROOT/'.github/test-windows-proxy-pipe-ac-guest-gates.ps1').read_text()
        for text in ('FunctionDefinitionAst','Test-ProxyPipeACPublic','ConvertFrom-ProxyPipeACPublic','Invoke-ProxyPipeACGuestDiagnostic','--export-ac-fixture','cases.Count -eq 28','handle_dispose','work_budget_exhausted','proxy-pipe-ac-result','process_and_http_mocked=$true'):
            self.assertIn(text,source)
        self.assertNotIn('Start-Process',source);self.assertNotIn('& $source',source)
        self.assertLess(source.index('Check ($LASTEXITCODE -eq 0)'),source.index('$owned=$true'))
        self.assertIn("$item.Name -cnotin @('cases.json','passed.json','public-proxy-pipe-ac.json')",source)
    def test_old_selector_fixture_exact_additive_inverse(self):
        source=(ROOT/'.github/test-windows-n0a-guest-gates.ps1').read_text()
        before=source.replace("'Test-ProxyPipeACConfiguration','Get-ProxyPipeACPayloadNames',",'').replace('$proxyPipeAcEnabled=$false;','')
        self.assertEqual(hashlib.sha256(before.encode()).hexdigest(),'7477b5da4992b3acd15a481c92089bc8452241b5779f5dafa65b5e32989fd00e')
    def test_all_original_helpers_byte_identical(self):
        source=(ROOT/'.github/windows_identity_direct_stage0.py').read_text();tree=ast.parse(source)
        excluded={'payload','host','main',*['proxy_pipe_ac_controller', 'proxy_pipe_ac_helpers', 'verify_proxy_pipe_ac_inputs', 'proxy_pipe_ac_staging_capacity', 'validate_proxy_pipe_ac_envelope', 'proxy_pipe_ac_ipc_qualified', 'ProxyPipeACClosedServer', 'ProxyPipeACClosedHandler']}
        originals=[(n.name,ast.get_source_segment(source,n)) for n in tree.body if isinstance(n,(ast.FunctionDef,ast.ClassDef)) and n.name not in excluded]
        self.assertEqual(len(originals),77)
        self.assertEqual(hashlib.sha256(repr(originals).encode()).hexdigest(),'c1fb49087dc1acb519da875c4f4e2a31ffbdc111df71db4bb32827d32bd38543')
        new_helpers=['Test-ProxyPipeACConfiguration', 'Get-ProxyPipeACPayloadNames', 'Test-ProxyPipeACStagingBound', 'Assert-ProxyPipeACStagingBound', 'Test-ProxyPipeACKeys', 'Test-ProxyPipeACPair', 'Test-ProxyPipeACPairPassed', 'Test-ProxyPipeACPublic', 'ConvertFrom-ProxyPipeACPublic', 'Invoke-ProxyPipeACGuestDiagnostic']
        originals=[(m[1],m[0]) for m in re.finditer('^function ([A-Za-z0-9-]+)(?:\\(|\\s).*?^}',S,re.M|re.S) if m[1] not in new_helpers]
        self.assertEqual(len(originals),45)
        self.assertEqual(hashlib.sha256(repr(originals).encode()).hexdigest(),'581877aacff8a67c1412acc1d1eda43267190d70bf1bb2cee5a8bb36574d36ea')
    def test_enabled_intent_and_forced_off_before_media_or_owned_resources(self):
        c=h.proxy_pipe_ac_controller();self.assertIs(c,h.proxy_pipe_ac_helpers().controller_module());self.assertIs(c.AC_EXECUTION_ENABLED,True)
        with patch.object(c,'AC_EXECUTION_ENABLED',False),patch.object(h,'load') as loader,patch.object(h.tempfile,'mkdtemp') as create,patch.object(h,'verify_python') as verify:
            with self.assertRaises(PermissionError):h.host(SimpleNamespace(proxy_pipe_ac=True))
            loader.assert_not_called();create.assert_not_called();verify.assert_not_called()
    def test_cached_wrong_module_rejected(self):
        key='identity_proxy_pipe_controller'
        with patch.dict(sys.modules,{key:SimpleNamespace(__file__='not-the-fixed-source')}):
            with self.assertRaises(ValueError):h.proxy_pipe_ac_controller()
    def test_cli_new_intent_exclusive_and_old_defaults_unchanged(self):
        common=['--output','inert-out','--python-archive','inert-python','--actor','inert-actor','--bundle','inert-bundle','--actor-sha256','a'*64,'--job-deadline-epoch','2000000000']
        for optional in ([],['--stage0b'],['--n0a','--n0a-actor','a','--n0a-manifest','m'],['--n0a','--n0a-capture-runner','--n0a-actor','a','--n0a-manifest','m'],['--n0a-udp-runner','--udp-actor','a','--udp-manifest','m'],['--n0a-udp6-runner','--udp6-actor','a','--udp6-manifest','m'],['--n0a-udp-parent-runner','--udp-actor','a','--udp-manifest','m','--udp-parent-actor','p','--udp-parent-manifest','pm']):
            with patch.object(h,'host',return_value=0) as host:
                self.assertEqual(h.main(common+optional),0);args=host.call_args.args[0]
                self.assertIs(args.proxy_pipe_ac,False);self.assertIsNone(args.proxy_pipe_ac_actor);self.assertEqual(args.timeout_seconds,6600)
        opt=['--proxy-pipe-ac','--proxy-pipe-ac-actor','bridge','--proxy-pipe-ac-manifest','manifest']
        with patch.object(h,'host',return_value=0) as host:
            self.assertEqual(h.main(common+opt),0);self.assertIs(host.call_args.args[0].proxy_pipe_ac,True)
        for conflict in ('--stage0b','--n0a','--n0a-capture-runner','--n0a-udp-runner','--n0a-udp6-runner','--n0a-udp-parent-runner','--guest','--download-python','--check-preparation','--check-apt-plan'):
            with patch.object(h,'host') as host,patch('sys.stderr',new=io.StringIO()):
                with self.assertRaises(SystemExit):h.main(common+opt+[conflict])
                host.assert_not_called()
    def test_optional_conflicts_before_import(self):
        for key in ('stage0b','n0a','n0a_capture_runner','n0a_udp_runner','n0a_udp_parent_runner','n0a_udp6_runner'):
            with patch.object(h,'proxy_pipe_ac_controller') as c:
                with self.assertRaises(ValueError):h.host(SimpleNamespace(proxy_pipe_ac=True,**{key:True}))
                c.assert_not_called()
        for key,value in [('stage0b',{}),('n0a',{}),('capture',True),('udp',{}),('parent_udp',{}),('udp6',{})]:
            with self.assertRaises(ValueError):h.payload(None,None,None,None,None,proxy_pipe_ac={},**{key:value})
    def test_actual_seventeen_zip_exact_closure_and_equal_count_forbidden(self):
        f=load('ac_payload_old','.github/test_windows_udp_payload.py')
        with tempfile.TemporaryDirectory() as d:
            root=Path(d)/'owned';f.generate(root)
            actor=root/'bridge.exe';actor.write_bytes(b'inert-bridge-fixture'*64);manifest=root/'bridge.json';manifest.write_bytes(b'{"fixture":true}')
            item=dict(actor=actor,manifest=manifest,config=dict(actor_sha256=hashlib.sha256(actor.read_bytes()).hexdigest(),manifest_sha256=hashlib.sha256(manifest.read_bytes()).hexdigest()))
            sys.path.insert(0,str(ROOT));import install_runtime
            bundle=root/'bundle.zip';data=bundle.read_bytes()
            def extract(raw,destination):
                with zipfile.ZipFile(io.BytesIO(raw)) as z:
                    for n in ('wxc-exec.exe','MXC-LICENSE.md'):(destination/n).write_bytes(z.read(n))
            a=root/'identity-fixture.exe';a.write_bytes(b'inert-baseline'*64);target=root/'ac.zip'
            with patch.object(h,'verify_python',return_value=b'inert-python'),patch.object(install_runtime,'_g_bundle_bytes',return_value=data),patch.object(install_runtime,'_extract_g_bundle',side_effect=extract):
                h.payload(root/'unused',a,hashlib.sha256(a.read_bytes()).hexdigest(),bundle,target,proxy_pipe_ac=item)
            with zipfile.ZipFile(root/'baseline.zip') as z:base=set(z.namelist())
            with zipfile.ZipFile(target) as z:entries={n:z.read(n) for n in z.namelist()};self.assertEqual(len(z.namelist()),17)
            self.assertEqual(set(entries),base|set(h.PROXY_PIPE_AC_FILES)|{h.PROXY_PIPE_AC_BRIDGE,h.PROXY_PIPE_AC_MANIFEST})
            for n in h.PROXY_PIPE_AC_FILES:self.assertEqual(entries[n],(ROOT/n).read_bytes())
            # All dynamically imported guest Python dependencies are present; native source is host-only.
            self.assertTrue({'.github/windows_identity_proof.py','.github/windows_psec_compartment_smoke.py','ruleproxy/windows_runtime_pins.py'}.issubset(entries))
            self.assertFalse(any(n.endswith(('.cpp','.hpp')) for n in entries))
            capacity=h.proxy_pipe_ac_staging_capacity(target)
            self.assertEqual(capacity['total'],capacity['compressed']+capacity['expanded']+24405990+capacity['baseline_actor_bytes']+capacity['executor_bytes']+capacity['bridge_bytes']+1048576)
            for i,bad in enumerate(('bridge/TEST_ONLY.exe','private-proxy-pipe-ac/private-ac.json','.github/windows_identity_stage0b_guest.py','capture.pcap')):
                path=root/f'bad-{i}.zip'
                with zipfile.ZipFile(path,'w') as z:
                    for n,raw in entries.items():z.writestr(bad if n==h.PROXY_PIPE_AC_BRIDGE else n,raw)
                with self.assertRaises(ValueError):h.proxy_pipe_ac_staging_capacity(path)
    def test_actual_manifest_three_source_hashes(self):
        c=h.proxy_pipe_ac_controller()
        with tempfile.TemporaryDirectory() as d:
            root=Path(d).resolve();actor=root/'windows_identity_proxy_pipe_actor.exe';actor.write_bytes(b'inert'*128)
            manifest=root/'identity-proxy-pipe-manifest.json'
            value=dict(schemaVersion=1,compileOnly=True,runtimeAcceptance=False,executableSha256=hashlib.sha256(actor.read_bytes()).hexdigest())
            for k,p in [('actorSourceSha256','.github/native/windows_identity_proxy_pipe_actor.cpp'),('identitySourceSha256','.github/native/windows_identity_actor.cpp'),('coreSha256','.github/native/windows_identity_proxy_bridge_core.hpp')]:value[k]=hashlib.sha256((ROOT/p).read_bytes()).hexdigest()
            manifest.write_text(json.dumps(value));result=h.verify_proxy_pipe_ac_inputs(actor,manifest)
            self.assertEqual(result['config']['actor_sha256'],value['executableSha256'])
            for key in ('actorSourceSha256','identitySourceSha256','coreSha256'):
                bad=dict(value);bad[key]='0'*64;manifest.write_text(json.dumps(bad))
                with self.assertRaises(ValueError):h.verify_proxy_pipe_ac_inputs(actor,manifest)
    def test_capacity_exact_limit_and_no_actor_doublecount(self):
        base={'python-embed.zip','actor.exe','stage0-input.json','g/wxc-exec.exe','g/build-manifest.json','g/MXC-LICENSE.md',*h.GUEST_SOURCES}|set(h.PROXY_PIPE_AC_FILES)|{h.PROXY_PIPE_AC_BRIDGE,h.PROXY_PIPE_AC_MANIFEST}
        sizes={n:1 for n in base};sizes.update({'actor.exe':512,'g/wxc-exec.exe':2048,h.PROXY_PIPE_AC_BRIDGE:1024})
        expanded=sum(sizes.values());compressed=134217728-expanded-24405990-512-2048-1024-1048576
        z=Mock();z.__enter__=Mock(return_value=z);z.__exit__=Mock(return_value=False);z.infolist.return_value=[SimpleNamespace(filename=n,file_size=v) for n,v in sizes.items()]
        with patch.object(h.zipfile,'ZipFile',return_value=z),patch.object(h.Path,'stat',return_value=SimpleNamespace(st_size=compressed)):
            self.assertEqual(h.proxy_pipe_ac_staging_capacity('inert')['total'],134217728)
        with patch.object(h.zipfile,'ZipFile',return_value=z),patch.object(h.Path,'stat',return_value=SimpleNamespace(st_size=compressed+1)):
            with self.assertRaises(ValueError):h.proxy_pipe_ac_staging_capacity('inert')
    def test_closed_schema_independent_ipc_and_sticky_positive(self):
        value=passed();self.assertEqual(h.validate_proxy_pipe_ac_envelope(value,CONFIG),value)
        self.assertTrue(h.proxy_pipe_ac_ipc_qualified(value,True));self.assertFalse(h.proxy_pipe_ac_ipc_qualified(value,False))
        baseline={'stage0_passed':False};combined=dict(proxy_pipe_ac_ipc_qualified=h.proxy_pipe_ac_ipc_qualified(value,True),product_acceptance=False)
        self.assertFalse(baseline['stage0_passed']);self.assertTrue(combined['proxy_pipe_ac_ipc_qualified']);self.assertFalse(combined['product_acceptance'])
        for key,item in [('timed_out',True),('budget_exhausted',True),('failure','handle_dispose'),('process_exit_confirmed',None),('python_exit_code',None),('python_exit_code',True)]:
            row=copy.deepcopy(value);row['launcher'][key]=item;self.assertFalse(h.proxy_pipe_ac_ipc_qualified(row,True));self.assertTrue(row['proxy_pipe_ac']['ac_pipe_passed'])
        for change in (lambda v:v.update(raw='private'),lambda v:v['proxy_pipe_ac'].update(run_nonce_sha256='0'*64),lambda v:v['proxy_pipe_ac']['pair'].update(created=True)):
            row=copy.deepcopy(value);change(row)
            with self.assertRaises(ValueError):h.validate_proxy_pipe_ac_envelope(row,CONFIG)
        self.assertLessEqual(len(json.dumps(dict(schema_version=1,stage='proxy-pipe-ac-host',report=value,report_validation='unavailable',proxy_pipe_ac_ipc_qualified=False,vm_destroyed=False,product_acceptance=False),indent=2).encode())+1,4096)
    def test_result_first_http_size_duplicate_and_exclusive_route(self):
        def post(raw,path='proxy-pipe-ac-result',ready=True):
            server=SimpleNamespace(capability='fixed',received=threading.Event(),n0a_received=threading.Event(),n0a_expected=CONFIG,proxy_pipe_ac_validation='unavailable')
            if ready:server.received.set()
            x=object.__new__(h.ProxyPipeACClosedHandler);x.server=server;x.path='/fixed/'+path;x.headers={'Content-Length':str(len(raw))};x.rfile=io.BytesIO(raw);x.send_error=Mock();x.send_response=Mock();x.end_headers=Mock();x.do_POST();return x,server
        raw=json.dumps(envelope()).encode();x,server=post(raw);self.assertTrue(server.n0a_received.is_set());x.send_response.assert_called_once_with(200)
        for data,path,ready,code in [(raw,'proxy-pipe-ac-result',False,409),(b'x'*4097,'proxy-pipe-ac-result',True,400),(b'{"schema_version":1,"schema_version":1}','proxy-pipe-ac-result',True,400),(raw,'stage0b-result',True,404)]:
            x,server=post(data,path,ready);x.send_error.assert_called_once_with(code);self.assertFalse(server.n0a_received.is_set())
    def test_ps_exact_members_enum_parity_same_deadline(self):
        names=set(re.findall("'([^']+)'",part('Get-ProxyPipeACPayloadNames')));self.assertEqual(names,set(h.PROXY_PIPE_AC_FILES)|{h.PROXY_PIPE_AC_BRIDGE,h.PROXY_PIPE_AC_MANIFEST})
        c=h.proxy_pipe_ac_controller();public=part('Test-ProxyPipeACPublic')
        for variable,expected in [('failures',c.AC_FAILURES),('phases',c.AC_PHASES),('domains',c.AC_ERROR_DOMAINS),('reports',c.AC_REPORT_STATES),('factKeys',c.AC_FACTS)]:
            self.assertEqual(tuple(re.findall("'([^']+)'",public.split('$'+variable+'=@(',1)[1].split(')',1)[0])),expected)
        inv=part('Invoke-ProxyPipeACGuestDiagnostic');self.assertIn('$workEnd=$Deadline',inv);self.assertNotIn('120*',inv);self.assertIn('Wait-Stage0bOwnedChild $process $workEnd $Frequency',inv);self.assertIn('/proxy-pipe-ac-result',inv)
        self.assertEqual(S.count('$n0aDeadline=$now+120*$n0aFrequency'),1)
        self.assertIn('AvailableFreeSpace -lt $remaining',part('Assert-ProxyPipeACStagingBound'))
        final=S[S.index('} finally {\n    if ($failed'):S.index('\n# Original Stage0 delivery above')]
        self.assertEqual(hashlib.sha256(final.encode()).hexdigest(),'7e10be5db5c65d9c7b18cd10004d15f1be9339bdd4a3c10ceb5a2abd721cdb2b')
        extractor=S[S.index('function Expand-CheckedStage0Zip {'):S.index('\ntry {\n    $configuration')]
        self.assertEqual(hashlib.sha256(extractor.encode()).hexdigest(),'6e754133def219c06d5a6f3d96b5a5d88640383f9da6c62e889313df7c519140')
if __name__=='__main__':
    if len(sys.argv)==3 and sys.argv[1]=='--export-ac-fixture':
        try:export_fixture(sys.argv[2])
        except Exception:print('{"passed":false,"failure":"fixture_export"}');raise SystemExit(1)
    else:unittest.main()
