import importlib.util
import ast
from contextlib import ExitStack
import hashlib
import io
import json
from pathlib import Path
import stat
import struct
import sys
import tempfile
import unittest
from unittest.mock import Mock, patch
from types import SimpleNamespace
import zipfile
ROOT = Path(__file__).resolve().parents[1]
SPEC = importlib.util.spec_from_file_location('stock', ROOT / '.github/windows_identity_stock_stage0.py')
stock = importlib.util.module_from_spec(SPEC); SPEC.loader.exec_module(stock)
class StockTests(unittest.TestCase):
    @staticmethod
    def raw_zip_info(name):
        # ZipInfo(name), including writestr's string-name convenience path,
        # normalizes backslashes to slashes on Windows and truncates NULs.
        # Malformed-input fixtures must serialize the intended raw name.
        item=zipfile.ZipInfo('fixture')
        item.filename=item.orig_filename=name
        return item
    def test_minimum_vm_work_budget_boundary_excludes_existing_cleanup_reserve(self):
        self.assertEqual(stock.MIN_VM_WORK_SECONDS,1800)
        with self.assertRaises(stock.VMWorkBudgetInsufficient):
            stock.require_vm_work_budget(5000,now=3201)
        self.assertEqual(stock.require_vm_work_budget(5000,now=3200),1800)
        source=(ROOT/'.github/windows_identity_stock_stage0.py').read_text()
        self.assertIn('deadline = time.monotonic() + available - 120',source)
        position=source.index("public['vm_work_seconds_available'] = int(require_vm_work_budget(deadline))")
        self.assertGreater(position,source.index('package_digest = payload('))
        self.assertLess(position,source.index("qemu = subprocess.Popen(limited_command(['qemu-system-x86_64'"))
        self.assertIn("except VMWorkBudgetInsufficient as exc:", source)
        self.assertIn("public['status'] = 'time_budget_insufficient'", source)
    def prep_fixture(self, path, *, baseline=None, phases=1, apt=False):
        baseline=stock.PREMEDIA_FREE+stock.PREP_ALLOWANCE if baseline is None else baseline
        value={'schema_version':1,'allowance_bytes':stock.PREP_ALLOWANCE,
               'minimum_free_bytes':stock.PREMEDIA_FREE,'baseline_free_bytes':baseline,
               'status':'observed_within_allowance','peak_measured':False,
               'provider_background_writes_excluded':False,
               'samples':[{'phase':phase,'free_bytes':baseline,'net_decline_bytes':0}
                          for phase in stock.PREP_PHASES[:phases]]}
        if apt:
            value['apt_plan']={'verified':True,'package_count':0,'download_bytes':0,
                'positive_installed_growth_bytes':0,'plan_sha256':'a'*64}
        path.write_text(json.dumps(value))
        return value
    def test_preparation_gate_measures_same_filesystem_and_closed_ordered_samples(self):
        import os
        with tempfile.TemporaryDirectory() as directory:
            path=Path(directory)/'public.json'; self.prep_fixture(path)
            with patch.object(stock,'ROOT',Path(directory)),patch.dict(os.environ,STOCK_PREP_DEVICE_ID=str(path.stat().st_dev)),\
                 patch.object(stock.sys,'version_info',(3,12,0)),\
                 patch.object(stock.shutil,'disk_usage',return_value=SimpleNamespace(free=stock.PREMEDIA_FREE)):
                self.assertEqual(stock.preparation_checkpoint(path,'post_checkout'),0)
            result=json.loads(path.read_text())
            self.assertEqual(result['samples'][-1]['net_decline_bytes'],stock.PREP_ALLOWANCE)
            self.assertEqual(result['minimum_free_bytes'],32*stock.GIB)
            self.assertFalse(result['peak_measured'])
            self.assertFalse(result['provider_background_writes_excluded'])
            self.assertFalse(result['installed_plan_verified'])
            self.assertFalse(result['planning_ledger_is_hard_quota'])
            self.assertEqual(sum(result['planning_ledger_bytes'].values()),523416078)
            self.assertLess(sum(result['planning_ledger_bytes'].values()),stock.PREP_ALLOWANCE)
            self.assertTrue(result['same_filesystem'])
            with self.assertRaises(ValueError): stock.preparation_checkpoint(path,'pre_vm')
    def test_preparation_rejects_unexpected_overhead_wrong_filesystem_and_python(self):
        import os
        for variant in ('floor','allowance','filesystem','python','apt_plan'):
            with self.subTest(variant=variant),tempfile.TemporaryDirectory() as directory:
                path=Path(directory)/'public.json'
                baseline=stock.PREMEDIA_FREE+2*stock.PREP_ALLOWANCE
                self.prep_fixture(path,baseline=baseline,phases=3 if variant=='apt_plan' else 1)
                free=(stock.PREMEDIA_FREE-1 if variant=='floor' else
                      baseline-stock.PREP_ALLOWANCE-1 if variant=='allowance' else baseline)
                device=path.stat().st_dev+(1 if variant=='filesystem' else 0)
                with patch.object(stock,'ROOT',Path(directory)),patch.dict(os.environ,STOCK_PREP_DEVICE_ID=str(device)),\
                     patch.object(stock.sys,'version_info',(3,14,0) if variant=='python' else (3,12,0)),\
                     patch.object(stock.shutil,'disk_usage',return_value=SimpleNamespace(free=free)):
                    self.assertEqual(stock.preparation_checkpoint(path,'post_apt' if variant=='apt_plan' else 'post_checkout'),1)
                self.assertEqual(json.loads(path.read_text())['status'],'blocked')
    def test_preparation_requires_full_initial_allowance_and_strips_unknown_fields(self):
        with tempfile.TemporaryDirectory() as directory:
            path=Path(directory)/'public.json'
            self.prep_fixture(path,baseline=stock.PREMEDIA_FREE)
            with self.assertRaises(ValueError): stock.preparation_record(path)
            value=self.prep_fixture(path); value['raw_path']='/private/never/export'
            path.write_text(json.dumps(value))
            self.assertNotIn('raw_path',stock.preparation_record(path))
            value['samples'][0]['raw_path']='/private/never/export'
            path.write_text(json.dumps(value))
            with self.assertRaises(ValueError): stock.preparation_record(path)
    def apt_runner(self, *, install_size=10, archive_size=100, old=None, installed_version=None,
                   simulation=None, metadata_suffix=''):
        calls=[]
        def runner(command,**kwargs):
            calls.append(command)
            if command[0]=='apt-get':
                text=simulation or (('1 upgraded, 0 newly installed' if old else '0 upgraded, 1 newly installed')+
                    ', 0 to remove and 0 not upgraded.\nInst fixture'+(' ['+old+']' if old else '')+
                    ' (2.0 Ubuntu:stable [amd64])\nConf fixture (2.0 Ubuntu:stable [amd64])\n')
                return SimpleNamespace(returncode=0,stdout=text,stderr='')
            if command[0]=='apt-cache':
                text=f'Package: fixture\nVersion: 2.0\nArchitecture: amd64\nSize: {archive_size}\nInstalled-Size: {install_size}\n'
                return SimpleNamespace(returncode=0,stdout=text+metadata_suffix,stderr='')
            if command[0]=='dpkg-query':
                return SimpleNamespace(returncode=0 if old else 1,
                    stdout='installed\n5\n'+(installed_version or old)+'\n' if old else '',stderr='')
            raise AssertionError('No install/update command may run in plan inspection')
        return runner,calls
    def test_current_apt_plan_counts_new_and_positive_upgrade_growth(self):
        for old,expected in ((None,10*1024),('1.0',5*1024)):
            runner,calls=self.apt_runner(old=old)
            result=stock.reviewed_apt_plan(runner=runner)
            self.assertEqual(result['package_count'],1)
            self.assertEqual(result['download_bytes'],100)
            self.assertEqual(result['positive_installed_growth_bytes'],expected)
            self.assertRegex(result['plan_sha256'],r'^[0-9a-f]{64}$')
            self.assertEqual(calls[0],['apt-get','-s','--no-install-recommends','--no-remove','install',*stock.VM_PACKAGES])
            self.assertEqual({command[0] for command in calls},{'apt-get','apt-cache','dpkg-query'})
    def test_current_apt_plan_rejects_unreviewed_size_metadata_or_removals(self):
        bad=[
            {'archive_size':stock.APT_DOWNLOAD_CEILING+1},
            {'install_size':stock.APT_INSTALLED_GROWTH_CEILING//1024+1},
            {'old':'1.0','installed_version':'unexpected'},
            {'metadata_suffix':'Size: 100\n'},
            {'metadata_suffix':'\nPackage: fixture\nVersion: 9.0\nArchitecture: amd64\nSize: 1\nInstalled-Size: 1\n'},
            {'simulation':'0 upgraded, 0 newly installed, 1 to remove and 0 not upgraded.\nRemv fixture\n'},
            {'simulation':'0 upgraded, 0 newly installed, 0 to remove and 0 not upgraded.\nInst fixture (2.0 Ubuntu [amd64])\n'},
            {'simulation':'metadata unavailable'},
        ]
        for options in bad:
            runner,_=self.apt_runner(**options)
            with self.subTest(options=options),self.assertRaises(ValueError):
                stock.reviewed_apt_plan(runner=runner)
    def measured_apt_fixture(self):
        fixture=json.loads((ROOT/'tests/fixtures/windows_stock_apt_after_refresh.json').read_text(encoding='ascii'))
        records=[dict(zip(fixture['record_fields'],row)) for row in fixture['records']]
        return fixture,records
    def measured_apt_runner(self,records):
        calls=[]
        by_name={row['name']:row for row in records}
        def runner(command,**kwargs):
            calls.append(command)
            if command[0]=='apt-get':
                self.assertEqual(command,['apt-get','-s','--no-install-recommends','--no-remove','install',*stock.VM_PACKAGES])
                upgraded=sum(row['old_version'] is not None for row in records)
                text=f'{upgraded} upgraded, {len(records)-upgraded} newly installed, 0 to remove and 78 not upgraded.\n'
                for row in records:
                    text+='Inst '+row['name']+(' ['+row['old_version']+']' if row['old_version'] else '')
                    text+=' ('+row['version']+' Ubuntu [amd64])\n'
                return SimpleNamespace(returncode=0,stdout=text,stderr='')
            if command[0]=='apt-cache':
                name,version=command[2].split('='); row=by_name[name]
                self.assertEqual(version,row['version'])
                text='\n'.join(key+': '+str(value) for key,value in (
                    ('Package',name),('Version',version),('Architecture',row['architecture']),
                    ('Size',row['download_bytes']),('Installed-Size',row['installed_kib'])))+'\n'
                return SimpleNamespace(returncode=0,stdout=text,stderr='')
            if command[0]=='dpkg-query':
                row=by_name[command[-1]]
                text=('installed\n'+str(row['previous_kib'])+'\n'+row['old_version']+'\n') if row['old_version'] else ''
                return SimpleNamespace(returncode=0 if row['old_version'] else 1,stdout=text,stderr='')
            self.fail('Only fake read-only APT plan commands are permitted')
        return runner,calls
    def test_exact_measured_refreshed_plan_is_accepted_without_other_scope_changes(self):
        fixture,records=self.measured_apt_fixture()
        self.assertEqual(fixture['source_run_id'],39389193171)
        self.assertEqual(fixture['source_commit'],'342c8cd336af4811366d1e3af6b1f89834975930')
        self.assertEqual(fixture['source_artifact_id'],12248706851)
        self.assertEqual(fixture['source_artifact_sha256'],'fe8c5dacc7adda9e90faa93dff04f9b47d1b17cedd8fc32a46e624bd6be1febf')
        self.assertRegex(fixture['source_report_sha256'],r'^[0-9a-f]{64}$')
        upgraded=[row for row in records if row['old_version'] is not None]
        self.assertEqual({row['name'] for row in upgraded},{'curl','libcurl4t64','libcurl3t64-gnutls'})
        self.assertTrue(all(row['old_version']=='8.5.0-2ubuntu10.15' and row['version']=='8.5.0-2ubuntu10.16' for row in upgraded))
        self.assertFalse(fixture['third_upgrade_solver_causality_proven'])
        runner,calls=self.measured_apt_runner(records)
        result=stock.reviewed_apt_plan(runner=runner)
        self.assertEqual((result['package_count'],result['download_bytes'],result['positive_installed_growth_bytes']),
                         (26,26223118,115951616))
        self.assertEqual(len(calls),53)
        self.assertEqual((stock.PREP_ALLOWANCE,stock.PREMEDIA_FREE,stock.LAUNCH_FREE,stock.DISK_FILE_CAP,stock.STOP_FREE),
                         (512*1024**2,32*stock.GIB,24*stock.GIB,18*stock.GIB,4*stock.GIB))
        self.assertEqual(stock.MIN_VM_WORK_SECONDS,1800)
        self.assertEqual(stock.PREP_PLANNING_BYTES['apt_positive_growth_plan_ceiling'],115951616)
        self.assertEqual(stock.PREP_PLANNING_BYTES['dpkg_transient_assumption'],115951616)
        self.assertEqual(sum(stock.PREP_PLANNING_BYTES.values()),523416078)
        self.assertEqual(stock.PREP_ALLOWANCE-sum(stock.PREP_PLANNING_BYTES.values()),13454834)
        with patch.object(stock,'APT_PACKAGE_CEILING',23),self.assertRaisesRegex(ValueError,'APT package count differs'):
            stock.reviewed_apt_plan(runner=runner)
    def test_measured_plan_rejects_first_representable_increase_and_one_byte_lower_ceiling(self):
        _,original=self.measured_apt_fixture()
        for variant in ('count','download','growth'):
            records=[dict(row) for row in original]
            if variant=='count':
                records.append(dict(name='extra-fixture',version='1.0',old_version=None,architecture='all',
                                    download_bytes=0,installed_kib=0,previous_kib=0))
            elif variant=='download': records[0]['download_bytes']+=1
            else: records[0]['installed_kib']+=1
            runner,_=self.measured_apt_runner(records)
            with self.subTest(variant=variant),self.assertRaises(ValueError): stock.reviewed_apt_plan(runner=runner)
        for field,bound in (('APT_DOWNLOAD_CEILING',26223117),('APT_INSTALLED_GROWTH_CEILING',115951615)):
            runner,_=self.measured_apt_runner(original)
            with patch.object(stock,field,bound),self.assertRaisesRegex(ValueError,'APT plan exceeds'):
                stock.reviewed_apt_plan(runner=runner)
    def test_record_accepts_each_exact_ceiling_and_rejects_each_plus_one(self):
        with tempfile.TemporaryDirectory() as directory:
            path=Path(directory)/'public.json'
            for changed in (None,'package_count','download_bytes','positive_installed_growth_bytes'):
                value=self.prep_fixture(path,phases=3,apt=True)
                value['apt_plan'].update(package_count=26,download_bytes=26223118,positive_installed_growth_bytes=115951616)
                if changed is not None: value['apt_plan'][changed]+=1
                path.write_text(json.dumps(value))
                if changed is None: self.assertTrue(stock.preparation_record(path)['apt_plan']['verified'])
                else:
                    with self.subTest(field=changed),self.assertRaises(ValueError): stock.preparation_record(path)
    def test_apt_plan_failure_report_contains_only_closed_failure(self):
        with tempfile.TemporaryDirectory() as directory:
            path=Path(directory)/'public.json'; self.prep_fixture(path,phases=3)
            with patch.object(stock,'reviewed_apt_plan',side_effect=ValueError('/private/package/path')):
                self.assertEqual(stock.check_apt_plan(path),1)
            result=json.loads(path.read_text())
            self.assertFalse(result['apt_plan_verified'])
            self.assertEqual(result['status'],'blocked')
            self.assertNotIn('/private',path.read_text())
    def test_all_preparation_gates_precede_native_execution_and_use_system_python(self):
        text=(ROOT/'.github/workflows/windows-identity-stock-stage0.yml').read_text()
        self.assertNotIn('actions/setup-python',text)
        self.assertEqual(text.count('fetch-depth: 1'),2)
        self.assertIn('sudo apt-get install -y --no-install-recommends --no-remove ',text)
        positions=[text.index("'phase':'before_checkout'")]
        positions.extend(text.index('--preparation-phase '+phase) for phase in stock.PREP_PHASES[1:])
        self.assertEqual(positions,sorted(positions))
        self.assertLess(text.index('--check-apt-plan'),text.index('sudo apt-get install -y'))
        self.assertLess(positions[-1],text.index('--approved-disposable-vm --python-archive'))
        native=text.split('  native:\n',1)[1]
        self.assertNotIn('          python ',native)
        self.assertNotIn('command -v python',native)
        self.assertIn('sudo /usr/bin/python3 -B .github/windows_identity_stock_stage0.py',native)
        self.assertIn('floor=32*1024**3',text)
        self.assertIn('free>=floor+allowance',text)
        for number in ('2059230','5682058','5682398'):
            self.assertIn(number,text)
    def python_fixture(self, *, runtime_changes=None, stdlib_changes=None):
        library = {name: b'fixture-only-not-executable' for name in stock.STDLIB_REQUIRED}
        library.update(stdlib_changes or {})
        inner = io.BytesIO()
        with zipfile.ZipFile(inner, 'w') as archive:
            for name, data in library.items():
                if data is not None: archive.writestr(self.raw_zip_info(name), data)
        binary = b'MZ' + b'\0' * 58 + (64).to_bytes(4, 'little') + b'PE\0\0\x64\x86\0'
        members = {name: b'fixture-only-not-executable' for name in stock.PYTHON_REQUIRED}
        members.update({'python.exe': binary, 'python314.dll': binary,
                        'python314.zip': inner.getvalue(), 'python314._pth': stock.PYTHON_PTH})
        members.update(runtime_changes or {})
        outer = io.BytesIO()
        with zipfile.ZipFile(outer, 'w') as archive:
            for name, data in members.items():
                if data is not None: archive.writestr(self.raw_zip_info(name), data)
        data = outer.getvalue()
        values = {'PYTHON_ASSET': dict(stock.PYTHON_ASSET, size=len(data), sha256=hashlib.sha256(data).hexdigest()),
                  'PYTHON_MEMBERS': sum(value is not None for value in members.values()),
                  'PYTHON_EXPANDED': sum(len(value) for value in members.values() if value is not None),
                  'STDLIB_MEMBERS': sum(value is not None for value in library.values()),
                  'STDLIB_EXPANDED': sum(len(value) for value in library.values() if value is not None)}
        return data, values
    def check_python_fixture(self, data, values):
        with tempfile.TemporaryDirectory() as directory, ExitStack() as patches:
            target=Path(directory)/'fixture.zip'; target.write_bytes(data)
            for name,value in values.items(): patches.enter_context(patch.object(stock,name,value))
            return stock.verify_python(target)
    def test_existing_official_python_pin_and_archive_bounds(self):
        self.assertEqual(stock.PYTHON_ASSET, {
            'name':'python-3.14.8-embed-amd64.zip','size':12601679,
            'url':'https://www.python.org/ftp/python/3.14.8/python-3.14.8-embed-amd64.zip',
            'sha256':'a93abe456ab01bd96d7a085b3cdb6566b3063f4241360d114142fbdb07f0a310'})
        self.assertEqual((stock.PYTHON_MEMBERS,stock.PYTHON_EXPANDED),(37,24405990))
        self.assertEqual((stock.STDLIB_MEMBERS,stock.STDLIB_EXPANDED),(563,9772779))
        path=ROOT/'ruleproxy/windows_proxy_pins.py'
        # Sparse read-only audit workspaces may omit unrelated product sources.
        # The real checkout always exercises this parity assertion.
        if path.exists():
            pins=stock.load('stock_test_existing_pin',path)
            self.assertEqual(pins.ASSETS['python'],stock.PYTHON_ASSET)
    def test_python_fixture_validates_without_running_binary(self):
        data,values=self.python_fixture()
        self.assertEqual(self.check_python_fixture(data,values),data)
    def test_python_requires_size_hash_and_expansion_pins(self):
        data,values=self.python_fixture()
        for name,bad in (
            ('PYTHON_ASSET',dict(values['PYTHON_ASSET'],size=len(data)+1)),
            ('PYTHON_ASSET',dict(values['PYTHON_ASSET'],sha256='0'*64)),
            ('PYTHON_MEMBERS',values['PYTHON_MEMBERS']+1),
            ('PYTHON_EXPANDED',values['PYTHON_EXPANDED']+1),
            ('STDLIB_MEMBERS',values['STDLIB_MEMBERS']+1),
            ('STDLIB_EXPANDED',values['STDLIB_EXPANDED']+1)):
            with self.subTest(pin=name,bad=bad),self.assertRaises(ValueError):
                self.check_python_fixture(data,dict(values,**{name:bad}))
    def test_python_rejects_missing_runtime_or_stdlib_and_nonisolated_pth(self):
        for changes in ({'python.exe':None},{'python314.zip':None},{'python314._pth':b'python314.zip\n.\n..\nimport site\n'},
                        {'python.exe':b'not a PE file'},{'python314.dll':b'MZ'+b'\0'*100}):
            with self.subTest(changes=changes),self.assertRaises(ValueError):
                self.check_python_fixture(*self.python_fixture(runtime_changes=changes))
        with self.assertRaises(ValueError):
            self.check_python_fixture(*self.python_fixture(stdlib_changes={'ctypes/__init__.pyc':None}))
    def test_python_rejects_unsafe_runtime_and_nested_stdlib_paths(self):
        for name in ('../escape','/absolute','C:drive','dir\\member','double//name',
                     './relative','space /member','trailing.','NUL','COM1.txt','_CTYPES.pyd','null\0member'):
            for key in ('runtime_changes','stdlib_changes'):
                # The case-insensitive duplicate belongs to the runtime archive.
                if name=='_CTYPES.pyd' and key=='stdlib_changes': continue
                with self.subTest(name=name,layer=key),self.assertRaises(ValueError):
                    self.check_python_fixture(*self.python_fixture(**{key:{name:b'bad'}}))
    def test_raw_zip_names_are_preserved_and_rejected_under_both_separator_models(self):
        for separator,alternate in (('/',None),('\\','/')):
            # Replace only zipfile's OS reference, not the shared os module:
            # pathlib/tempfile and real filesystem behavior remain untouched.
            modeled_os=SimpleNamespace(**(vars(zipfile.os)|{'sep':separator,'altsep':alternate}))
            with self.subTest(separator=separator),patch.object(zipfile,'os',modeled_os):
                for name in ('dir\\member','null\0member'):
                    with self.subTest(name=name):
                        stream=io.BytesIO()
                        with zipfile.ZipFile(stream,'w') as archive:
                            archive.writestr(self.raw_zip_info(name),b'x')
                        data=stream.getvalue()
                        self.assertEqual(data[:4],b'PK\x03\x04')
                        local_length=struct.unpack_from('<H',data,26)[0]
                        self.assertEqual(data[30:30+local_length],name.encode('ascii'))
                        central=data.index(b'PK\x01\x02')
                        central_length=struct.unpack_from('<H',data,central+28)[0]
                        self.assertEqual(data[central+46:central+46+central_length],name.encode('ascii'))
                        with zipfile.ZipFile(io.BytesIO(data)) as archive:
                            self.assertEqual(archive.infolist()[0].orig_filename,name)
                            with self.assertRaises(ValueError):
                                stock.checked_members(archive,count=1,expanded=1)
                # Forward-slash stdlib directories are valid on either host.
                data,values=self.python_fixture(stdlib_changes={'valid/nested.pyc':b'fixture'})
                self.assertEqual(self.check_python_fixture(data,values),data)
    def test_zip_rejects_links_duplicates_encryption_and_directory_aliases(self):
        def item(name):
            result=zipfile.ZipInfo(name); result.file_size=1
            return result
        for change in ('symlink','directory','duplicate','encrypted','nul','special','compression'):
            entry=item('safe')
            members=[entry]
            if change=='symlink': entry.external_attr=(stat.S_IFLNK|0o777)<<16
            if change=='special': entry.external_attr=(stat.S_IFIFO|0o600)<<16
            if change=='directory': entry.external_attr=0x10
            if change=='duplicate': members.append(item('SAFE'))
            if change=='encrypted': entry.flag_bits=1
            if change=='nul': entry.orig_filename='safe\0hidden'
            if change=='compression': entry.compress_type=zipfile.ZIP_BZIP2
            with self.subTest(change=change),self.assertRaises(ValueError):
                stock.checked_members(SimpleNamespace(infolist=lambda:members),count=len(members),expanded=len(members))
    def test_download_uses_only_existing_official_pin_without_running_it(self):
        import urllib.request
        data,values=self.python_fixture()
        pins=SimpleNamespace(ASSETS={'python':values['PYTHON_ASSET']},PYTHON_VERSION='3.14.8',
                             PYTHON_PTH='python314._pth',PYTHON_STDLIB='python314.zip')
        class Response(io.BytesIO):
            headers={'Content-Length':str(len(data))}
            def geturl(self): return values['PYTHON_ASSET']['url']
        with tempfile.TemporaryDirectory() as directory,ExitStack() as patches:
            for name,value in values.items(): patches.enter_context(patch.object(stock,name,value))
            patches.enter_context(patch.object(stock,'load',return_value=pins))
            opener=Mock(); opener.open.return_value=Response(data)
            builder=patches.enter_context(patch.object(urllib.request,'build_opener',return_value=opener))
            path=Path(directory)/'official.zip'
            stock.download_python(path)
            self.assertEqual(path.read_bytes(),data)
            request=opener.open.call_args.args[0]
            self.assertEqual(request.full_url,values['PYTHON_ASSET']['url'])
            self.assertEqual(opener.open.call_args.kwargs,{'timeout':90})
            redirect=builder.call_args.args[0]()
            with self.assertRaises(ValueError): redirect.redirect_request(None,None,None,None,None,None)
    def test_download_blocks_changed_product_pin_and_response_identity(self):
        import urllib.request
        pins=SimpleNamespace(ASSETS={'python':dict(stock.PYTHON_ASSET)},PYTHON_VERSION='3.14.8',
                             PYTHON_PTH='python314._pth',PYTHON_STDLIB='python314.zip')
        with tempfile.TemporaryDirectory() as directory,patch.object(stock,'load',return_value=pins),\
             patch.object(urllib.request,'build_opener') as builder:
            target=Path(directory)/'rejected.zip'
            pins.ASSETS['python']['sha256']='0'*64
            with self.assertRaises(ValueError): stock.download_python(target)
            builder.assert_not_called(); self.assertFalse(target.exists())
            pins.ASSETS['python']=dict(stock.PYTHON_ASSET)
            for url,length in (('https://example.invalid/different',str(stock.PYTHON_ASSET['size'])),
                               (stock.PYTHON_ASSET['url'],'-1')):
                response=Mock(); response.geturl.return_value=url
                response.headers={'Content-Length':length}
                response.__enter__=Mock(return_value=response); response.__exit__=Mock(return_value=False)
                builder.return_value.open.return_value=response
                with self.subTest(url=url,length=length),self.assertRaises(ValueError):
                    stock.download_python(target)
                response.read.assert_not_called(); self.assertFalse(target.exists())
    def test_payload_contains_only_python_fixed_g_actor_and_guest_sources(self):
        from unittest.mock import patch as patcher
        with tempfile.TemporaryDirectory() as directory:
            root=Path(directory)
            actor=root/'actor'; actor.write_bytes(b'fixture actor')
            bundle=root/'g.zip'
            with zipfile.ZipFile(bundle,'w') as archive:
                archive.writestr('build-manifest.json',b'fixture validated manifest')
            def extract(data,target):
                # Match the real helper: it validates but does not write manifest.
                for name in ('wxc-exec.exe','MXC-LICENSE.md'):
                    (target/name).write_bytes(b'fixture-only-not-executable')
            runtime=SimpleNamespace(_g_bundle_bytes=lambda *a,**k:bundle.read_bytes(),_extract_g_bundle=extract)
            output=root/'payload.zip'
            with patcher.dict(sys.modules,{'install_runtime':runtime}),\
                 patch.object(stock,'verify_python',return_value=b'fixture pinned Python'),\
                 patch.object(stock.sys,'path',list(sys.path)):
                digest=stock.payload(root/'python.zip',actor,hashlib.sha256(actor.read_bytes()).hexdigest(),bundle,output)
            self.assertEqual(digest,hashlib.sha256(output.read_bytes()).hexdigest())
            with zipfile.ZipFile(output) as archive:
                self.assertEqual(set(archive.namelist()),set(stock.GUEST_SOURCES)|{
                    'python-embed.zip','actor.exe','stage0-input.json','g/wxc-exec.exe','g/build-manifest.json','g/MXC-LICENSE.md'})
                self.assertEqual(len(archive.namelist()),10)
                self.assertEqual(archive.read('python-embed.zip'),b'fixture pinned Python')
                self.assertEqual(archive.read('g/build-manifest.json'),b'fixture validated manifest')
    def test_transitive_guest_dependencies_are_stdlib_and_fixed_runtime_pins(self):
        modules={'.github/windows_identity_proof.py','.github/windows_psec_compartment_smoke.py',
                 'ruleproxy/windows_runtime_pins.py'}
        trees={filename:ast.parse((ROOT/filename).read_text()) for filename in modules}
        def reachable(tree, seeds):
            functions={node.name:node for node in tree.body if isinstance(node,(ast.FunctionDef,ast.ClassDef))}
            names=set(seeds)
            pending=list(seeds)
            while pending:
                for node in ast.walk(functions[pending.pop()]):
                    if isinstance(node,ast.Call) and isinstance(node.func,ast.Name):
                        name=node.func.id
                        if name in functions and name not in names:
                            names.add(name); pending.append(name)
            return names,[functions[name] for name in names]
        proof_names,proof_nodes=reachable(trees['.github/windows_identity_proof.py'],{'controller', 'closed_diagnostics'})
        self.assertEqual(proof_names,{'controller','policy','run_case','stage0_checks','actual_tiers','probe_outcome','detector_error_class','cli_diagnostic','closed_diagnostics','diagnostic_summary',
            '_dict','_enum','_integer','_boolean','_digest','_known_list','_codes','_fact','_closed_fact',
            'canonical_environment_directory','validate_required_environment','native_required_environment_paths',
            'observe_required_environment','required_environment_entries',
            'native_identity_facts','closed_native_identity_facts','capability_entries','closed_capability_diagnostic','observe_capability_context','capability_diagnostic','canonical_capability_sid','WindowsCapabilityObserver','_operation_labels'})
        smoke_seeds={'read'}  # Also called directly by the stock guest wrapper.
        for root in proof_nodes:
            for node in ast.walk(root):
                if (isinstance(node,ast.Attribute) and isinstance(node.value,ast.Name)
                        and node.value.id=='smoke'):
                    if node.attr != 'MAX_JSON': smoke_seeds.add(node.attr)
        smoke_names,smoke_nodes=reachable(trees['.github/windows_psec_compartment_smoke.py'],smoke_seeds)
        self.assertEqual(smoke_names,{'read','save','failure','verify_executor','identity_snapshot',
            'base_container_selected','executor_diagnostic','executor_message_summary','executor_error_envelopes'})
        self.assertNotIn('controller',smoke_names)
        # Its unrelated controller/run_case have lazy product/network imports.
        # They are absent from this audited Stage0 call closure, not dependencies.
        active=[*proof_nodes,*smoke_nodes,trees['ruleproxy/windows_runtime_pins.py']]
        for tree in trees.values():
            active.extend(node for node in tree.body if isinstance(node,(ast.Import,ast.ImportFrom)))
        nonstdlib=[]
        for root in active:
            for node in ast.walk(root):
                if isinstance(node,ast.Import):
                    nonstdlib.extend(name.name for name in node.names if name.name.split('.')[0] not in sys.stdlib_module_names)
                elif isinstance(node,ast.ImportFrom):
                    self.assertEqual(node.level,0)
                    if node.module.split('.')[0] not in sys.stdlib_module_names:
                        nonstdlib.append(node.module+'.'+','.join(name.name for name in node.names))
        self.assertEqual(nonstdlib,['ruleproxy.windows_runtime_pins'])
        self.assertEqual(set(stock.GUEST_SOURCES),modules|{'.github/windows_identity_stock_stage0.py'})
        proof=(ROOT/'.github/windows_identity_proof.py').read_text()
        self.assertIn('ROOT / ".github/windows_psec_compartment_smoke.py"',proof)
        for filename in modules:
            text=(ROOT/filename).read_text()
            self.assertNotIn('__import__(',text); self.assertNotIn('import_module(',text)
    def test_guest_source_tree_imports_in_isolated_no_site_no_bytecode_mode(self):
        import shutil,subprocess
        with tempfile.TemporaryDirectory() as directory:
            root=Path(directory)
            for filename in stock.GUEST_SOURCES:
                target=root/filename; target.parent.mkdir(parents=True,exist_ok=True)
                shutil.copyfile(ROOT/filename,target)
            code="""import importlib.util,pathlib,sys
root=pathlib.Path(sys.argv[1])
assert sys.flags.isolated and sys.flags.no_site and sys.dont_write_bytecode and 'site' not in sys.modules
spec=importlib.util.spec_from_file_location('isolated_stage0',root/'.github/windows_identity_stock_stage0.py')
stock=importlib.util.module_from_spec(spec); spec.loader.exec_module(stock)
proof=stock.load('isolated_proof',root/'.github/windows_identity_proof.py')
assert callable(proof.controller) and callable(proof.smoke.identity_snapshot)
sys.path.insert(0,str(root))
from ruleproxy import windows_runtime_pins
assert windows_runtime_pins.MXC_G_EXECUTOR_SHA256 == 'cd32e225fb858161b66bc23e9d2415843de348edf2cfdfb05cee0e7535dca1a7'
assert 'install_runtime' not in sys.modules and 'ruleproxy.windows_proxy_pins' not in sys.modules
assert not any(root.rglob('__pycache__'))
"""
            subprocess.run([sys.executable,'-I','-S','-B','-c',code,str(root)],check=True,timeout=10,
                           stdout=subprocess.PIPE,stderr=subprocess.PIPE)
    def test_guest_import_path_rejects_nonisolated_or_product_layout(self):
        runtime=stock.ROOT/'python'
        flags=SimpleNamespace(isolated=1,no_site=1)
        # Pure property check: no Windows API or security operation is called.
        with patch.object(stock.os,'name','nt'),patch.object(stock.sys,'flags',flags),\
             patch.object(stock.sys,'dont_write_bytecode',True),patch.object(stock.sys,'modules',{}),\
             patch.object(stock.sys,'executable',str(runtime/'python.exe')),\
             patch.object(stock.sys,'path',[str(runtime/'python314.zip'),str(runtime)]),\
             patch.object(stock,'Path',type(runtime)):
            stock.verify_guest_import_path()
            with patch.object(stock.sys,'path',[str(runtime/'python314.zip'),str(runtime),str(stock.ROOT)]):
                with self.assertRaises(ValueError): stock.verify_guest_import_path()
            flags.no_site=0
            with self.assertRaises(ValueError): stock.verify_guest_import_path()
    def test_dedicated_workflow_does_not_build_full_product_or_install_pip(self):
        text=(ROOT/'.github/workflows/windows-identity-stock-stage0.yml').read_text()
        for forbidden in ('build_windows_package.py','pip install','requirements.txt','client-stage0-package','--package '):
            self.assertNotIn(forbidden,text)
        self.assertIn('--download-python',text); self.assertIn('--python-archive',text)
        self.assertNotIn('windows_proxifyre_vm.py',(ROOT/'.github/windows_identity_stock_stage0.py').read_text())
    def test_guest_checks_archive_before_extracting_or_executing(self):
        text=(ROOT/'.github/windows-identity-stock-stage0-run.ps1').read_text()
        self.assertNotIn('Expand-Archive',text); self.assertNotIn('runtime\\RuleProxy-Web',text)
        self.assertIn(stock.PYTHON_ASSET['sha256'],text)
        self.assertIn('-MemberCount 37 -ExactBytes 24405990 -MaximumBytes 24405990',text)
        self.assertIn('-MemberCount 10 -ExactBytes 0 -MaximumBytes 134217728',text)
        self.assertIn("Join-Path $workspace 'python\\python.exe'",text)
        self.assertIn("$info.Arguments='-I -S -B ",text)
        self.assertLess(text.index("throw 'Payload digest mismatch'"),text.index('Expand-CheckedStage0Zip -ArchivePath $payload'))
        self.assertLess(text.index("throw 'Pinned Python mismatch'"),text.index('Expand-CheckedStage0Zip -ArchivePath $runtime'))
        self.assertLess(text.index('Expand-CheckedStage0Zip -ArchivePath $runtime'),text.index('$child.Start()'))
    def test_execution_disabled(self):
        with patch.object(stock, 'EXECUTION_ENABLED', False):
            with self.assertRaises(PermissionError): stock.host(SimpleNamespace())
    def test_budget_is_not_fit_claim(self):
        self.assertGreaterEqual(stock.LAUNCH_FREE - stock.DISK_FILE_CAP, 6 * stock.GIB)
        self.assertGreater(stock.LAUNCH_FREE - stock.DISK_FILE_CAP, stock.STOP_FREE)
    def test_limit_primitive_in_owned_temp(self):
        import shutil, subprocess, sys, tempfile
        if sys.platform != 'linux' or not shutil.which('prlimit'): self.skipTest('Linux prlimit required')
        with tempfile.TemporaryDirectory() as directory:
            target = Path(directory) / 'bounded.bin'
            code = "import resource,sys; assert resource.getrlimit(resource.RLIMIT_FSIZE)==(4096,4096); f=open(sys.argv[1],'wb',buffering=0); f.write(b'x'*8192); f.write(b'x')"
            run = subprocess.run(stock.limited_command([sys.executable,'-c',code,str(target)],4096),
                                 stdout=subprocess.DEVNULL,stderr=subprocess.DEVNULL,timeout=5)
            self.assertNotEqual(run.returncode,0)
            self.assertLessEqual(target.stat().st_size,4096)
    def test_limit_applied_before_exec(self):
        c = stock.limited_command(['owned-binary'], 17)
        self.assertEqual(c, ['prlimit', '--fsize=17:17', '--core=0:0', '--', 'owned-binary'])
    def test_diagnostic_projection_survives_guest_launcher_host_layers_under_cap(self):
        proof = stock.proof_helpers()
        summary = {'bytes_observed': 2**31-1, 'inspection_truncated': True,
            'categories': list(proof.DIAGNOSTIC_CATEGORIES), 'operations': list(proof.DIAGNOSTIC_OPERATIONS),
            'native_codes': list(range(4294967287, 4294967295)), 'inspected_sha256': 'a'*64,
            'error_envelope_count': 4, 'error_envelopes': [{'code': 'policy_validation',
                'message_class': 'psec_environment_attach', 'message_sha256': 'a'*64,
                'has_extended_error': True, 'extended_error_sha256': 'b'*64,
                'categories': list(proof.DIAGNOSTIC_CATEGORIES), 'operations': list(proof.DIAGNOSTIC_OPERATIONS),
                'native_codes': list(range(4294967287, 4294967295))}]}
        diag = proof.closed_diagnostics({})
        diag['probe'].update(stdout=summary, stderr=summary, error_summary=summary, warning_summaries=[summary]*2,
            cli={'classes': list(proof.CLI_CLASSES), 'policy_fields': list(proof.POLICY_FIELDS)},
            warning_count=131072, warning_nonstring_count=131072, attempted=True, completed=True,
            outcome='reported_detector_error', error_class='reported_host_loopback_contract_unavailable')
        cap_catalog={name:'S-1-15-3-'+str(index+1) for index,name in enumerate(proof.CAPABILITY_LABELS)}
        cap_entries=[{'sid':cap_catalog[proof.CAPABILITY_LABELS[0]],'attributes':0x17}]*16
        diag['execution']['capabilities']=proof.capability_diagnostic(
            {'queriesSucceeded':True,'errors':[],'tokenCapabilities':cap_entries},cap_entries,cap_catalog)
        self.assertEqual(diag['execution']['capabilities']['known'][0],[16]*10)
        diag['execution'].update(stdout=summary, stderr=summary, actual_tiers=list(proof.TIERS),
            actual_tier_count=8192, unknown_tier_count=8192, actor_reparse_point_observed=True)
        diag['probe']['facts']={key: {'state':'value','value':False} for key in proof.PROBE_FACTS}
        diag['probe']['ui_facts']={key: {'state':'value','value':True} for key in proof.UI_FACTS}
        raw = {'diagnostics': diag, 'checks': {key: True for key in stock.CHECKS}, 'stage0_passed': True,
               'actor_sha256': 'a'*64, 'executor_exit_code': 4294967295,
               'launcher_diagnostic': {'phase': 'payload_download', 'failed': True, 'hresult': -2147483648,
                                       'python_exit_code': 4294967295, 'transport_attempt': 3}}
        guest = stock.project_stage0(raw)
        guest.update(status='passed', ordinary_account=True, stock_build_verified=True, harness_completed=True,
                     os={'build':26200,'ubr':6584,'product_type':'WinNT','architecture':'AMD64'})
        # PowerShell's JSON object/array nesting must remain within Depth 10.
        def nesting(value):
            if isinstance(value,dict): return 1+max((nesting(v) for v in value.values()),default=0)
            if isinstance(value,list): return 1+max((nesting(v) for v in value),default=0)
            return 0
        self.assertLessEqual(nesting(guest),10)
        wire = json.dumps(guest)
        self.assertLessEqual(len(wire), stock.MAX_REPORT)
        self.assertTrue(guest['diagnostics']['probe']['stdout']['operations_truncated'])
        self.assertEqual(guest['diagnostics']['probe']['stdout']['operation_label_count'], len(proof.DIAGNOSTIC_OPERATIONS))
        self.assertEqual(len(guest['diagnostics']['probe']['stdout']['operations']), 6)
        restored=stock.validate_guest(json.loads(wire),'a'*64)
        self.assertEqual(restored['diagnostics'],guest['diagnostics'])
        self.assertEqual(stock.project_stage0(restored)['diagnostics'],guest['diagnostics'])
        self.assertEqual(restored['diagnostics']['probe']['ui_facts'][proof.UI_FACTS[0]], {'state':'value','value':True})
        direct_spec = importlib.util.spec_from_file_location('direct_wire_bound', ROOT / '.github/windows_identity_direct_stage0.py')
        direct = importlib.util.module_from_spec(direct_spec); direct_spec.loader.exec_module(direct)
        direct_guest = direct.project_stage0(raw)
        direct_guest.update(status='passed', ordinary_account=True, direct_build_verified=True, harness_completed=True,
                            os={'build':26300,'ubr':9457,'product_type':'WinNT','architecture':'AMD64'})
        direct_wire = json.dumps(direct_guest)
        self.assertLessEqual(len(direct_wire), direct.MAX_REPORT)
        self.assertLessEqual(nesting(direct_guest), 10)
        self.assertEqual(direct.validate_guest(json.loads(direct_wire),'a'*64)['diagnostics'], direct_guest['diagnostics'])
        serviced_spec = importlib.util.spec_from_file_location('serviced_wire_bound', ROOT / '.github/windows_identity_serviced_stage0.py')
        serviced = importlib.util.module_from_spec(serviced_spec); serviced_spec.loader.exec_module(serviced)
        serviced_guest = serviced.project_stage0(raw)
        serviced_guest.update(ordinary_account=False, servicing_verified=False, harness_completed=False,
            status='failed', os={'build':26200,'ubr':9711,'product_type':'WinNT','architecture':'AMD64'})
        # Match every field added by the actual PS finally wrapper, using the
        # longest closed receipt values (failure report, not a passing receipt).
        serviced_guest['servicing_diagnostic'] = serviced.closed_servicing({
            'phase': max(serviced.SERVICE_PHASES, key=len),
            'failure': max(serviced.SERVICE_FAILURES, key=len),
            'dism_exit_code': -2147483648, 'packages_verified': False,
            'reboot_observed': False, 'task_unregistered': False, 'completed': False})
        serviced_guest['launcher_diagnostic'].update(
            phase=max(serviced.LAUNCHER_PHASES,key=len),
            failure_category=max(serviced.LAUNCHER_FAILURES,key=len))
        serviced_guest['servicing_read_diagnostic']={
            'step':max(serviced.SERVICE_READ_STEPS,key=len),
            'reason':max(serviced.SERVICE_READ_REASONS,key=len),'remaining_seconds':-172800,
            'zone_pacific':False,'utc_offset_minutes':-480}
        serviced_guest['setup_read_diagnostic']=dict(serviced_guest['servicing_read_diagnostic'])
        serviced_guest['prior_service']={'s':max(serviced.PRIOR_SERVICE_STATUSES,key=len),
            'p':max(serviced.SERVICE_PHASES,key=len),'f':max(serviced.SERVICE_FAILURES,key=len),
            'e':-2147483648,'b':127}
        # JSON null is longer than every valid mask (including 127). Exercise
        # both observed/unavailable shapes, and null versus widest exit values.
        serviced_guest['pending_reboot']={'c':False,'w':False,'r':False}
        serviced_guest['extra_reboot']={'n':None,'b':False}
        prior_wire_sizes={}
        for mask in (None,127):
            for code in (None,-2147483648,4294967295):
                candidate=json.loads(json.dumps(serviced_guest))
                candidate['prior_service'].update(b=mask,e=code)
                candidate_wire=json.dumps(candidate)
                prior_wire_sizes[(mask,code)]=len(candidate_wire)
                self.assertLessEqual(len(candidate_wire),serviced.MAX_REPORT)
                restored_prior=serviced.validate_guest(json.loads(candidate_wire),'a'*64)['prior_service']
                self.assertEqual(restored_prior,candidate['prior_service'])
        self.assertEqual(max(prior_wire_sizes,key=prior_wire_sizes.get),(None,-2147483648))
        serviced_guest['prior_service']['b']=None
        serviced_wire = json.dumps(serviced_guest)
        self.assertEqual(len(serviced_wire),max(prior_wire_sizes.values()))
        for count in (None,0,1):
            for changed in (None,True,False):
                candidate=json.loads(serviced_wire)
                candidate['extra_reboot']={'n':count,'b':changed}
                optional_wire=json.dumps(candidate)
                self.assertLessEqual(len(optional_wire),len(serviced_wire))
                self.assertEqual(serviced.validate_guest(json.loads(optional_wire),'a'*64)['extra_reboot'],candidate['extra_reboot'])
        self.assertLessEqual(len(serviced_wire), serviced.MAX_REPORT)
        self.assertLessEqual(nesting(serviced_guest),10)
        serviced_restored=serviced.validate_guest(json.loads(serviced_wire),'a'*64)
        self.assertFalse(serviced_restored['stage0_passed'])
        self.assertEqual(serviced_restored['diagnostics'],serviced_guest['diagnostics'])
        self.assertEqual(serviced_restored['servicing_diagnostic'],serviced_guest['servicing_diagnostic'])
        serviced_ps=(ROOT/'.github/windows-identity-serviced-stage0-run.ps1').read_text()
        import re
        receipt_source=re.search(r'\$serviceFacts=@\{([^}]+)\}',serviced_ps).group(1)
        receipt_keys=set(re.findall(r'(\w+)\s*=',receipt_source))
        self.assertEqual(receipt_keys,set(serviced_guest['servicing_diagnostic']))
        self.assertIn("Set-ClosedResultField 'servicing_diagnostic' $serviceFacts",serviced_ps)
        self.assertIn('$body.Length -gt 16384',serviced_ps)
        ps=(ROOT/'.github/windows-identity-stock-stage0-run.ps1').read_text()
        self.assertIn('ConvertTo-Json -Depth 10 -Compress',ps)
        self.assertIn('$body.Length -gt 16384',ps)

    def test_projection_never_exports_malicious_nested_fields(self):
        secret='SECRET_PATH_SID_PASSWORD'
        report=stock.project_stage0({'checks':[secret], 'diagnostics': {'probe': {'tier':secret,
            'cli': {'classes':[secret], 'policy_fields':[secret]}, 'stdout': {'native_codes':[secret],
            'error_envelopes':[{'code':secret,'message_class':secret,'message_sha256':secret}]}},
            'execution': {'actual_tiers':[secret]}, 'failure': {'type':secret,'errno':True}},
            'guest_diagnostic': {'phase':secret,'failure':{'type':secret,'errno':secret}},
            'launcher_diagnostic': {'phase':secret,'hresult':secret,'python_exit_code':True}})
        self.assertNotIn(secret,json.dumps(report))
        self.assertIsNone(report['launcher_diagnostic']['python_exit_code'])
        self.assertFalse(report['stage0_passed'])

    def test_guest_preserves_probe_facts_after_private_report_read_failure(self):
        proof=stock.proof_helpers()
        prior={'probe': {'error':'DACL fallback required but fallback.allowDaclMutation is false'},
               'probe_attempted':True,'probe_completed':True,'probe_exit_code':0,
               'probe_outcome':'reported_detector_error','probe_error_class':'reported_dacl_fallback_forbidden'}
        def controller(options):
            options.diagnostic_phase='completed'; options.diagnostic_report=prior
            return 1
        fake=SimpleNamespace(controller=controller,smoke=SimpleNamespace(read=Mock(side_effect=ValueError('SECRET'))))
        real_load=stock.load
        def load(name,path): return fake if name=='identity_stage0_guest' else real_load(name,path)
        with tempfile.TemporaryDirectory() as directory:
            root=Path(directory); (root/'stage0-input.json').write_text(json.dumps({'actor_sha256':'a'*64}))
            # Only patch the configured input root during read. Pure helper imports
            # still load from the real fixed source tree.
            with patch.object(stock,'verify_guest_import_path'),patch.object(stock,'load',side_effect=load), \
                    patch.object(stock,'proof_helpers',return_value=proof),patch.object(stock,'ROOT',root):
                self.assertEqual(stock.guest(SimpleNamespace(output=root/'public.json')),1)
            result=json.loads((root/'public.json').read_text())
        self.assertEqual(result['guest_diagnostic']['phase'],'report_read')
        self.assertEqual(result['guest_diagnostic']['failure']['type'],'ValueError')
        self.assertEqual(result['diagnostics']['probe']['outcome'],'reported_detector_error')
        self.assertFalse(result['harness_completed']); self.assertFalse(result['stage0_passed'])
        self.assertNotIn('SECRET',json.dumps(result))

    def test_breadcrumbs_are_fixed_bounded_storage_time_observations(self):
        with tempfile.TemporaryDirectory() as directory:
            work=Path(directory); disk=work/'private-name.qcow2'; disk.write_bytes(b'x'*1024)
            public={}
            observed=SimpleNamespace(st_mode=stat.S_IFREG|0o600,st_size=1024,st_blocks=8)
            with patch.object(stock.time,'monotonic',return_value=100),patch('builtins.print') as output, \
                    patch.object(Path,'lstat',return_value=observed):
                for name in stock.BREADCRUMBS: stock.record_breadcrumb(public,name,work,disk,1900)
                stock.record_breadcrumb(public,'qemu_started',work,disk,1900)
                with self.assertRaises(ValueError): stock.record_breadcrumb(public,'SECRET',work,disk,1900)
            self.assertEqual(len(public['phase_samples']),6); self.assertEqual(output.call_count,6)
            for row in public['phase_samples']:
                self.assertEqual(row['qcow_size_bytes'],1024)
                self.assertEqual(row['qcow_allocated_bytes'],4096)
                self.assertEqual(row['remaining_work_seconds'],1800)
            self.assertNotIn(directory,json.dumps(public)); self.assertNotIn('private-name',json.dumps(public))

    def test_breadcrumb_unavailable_measurements_do_not_fabricate_zero(self):
        with tempfile.TemporaryDirectory() as directory:
            work=Path(directory)
            with patch.object(stock.shutil,'disk_usage',side_effect=OSError('SECRET')),patch('builtins.print'):
                result={}; stock.record_breadcrumb(result,'cleanup_done',work,work/'missing',0)
            row=result['phase_samples'][0]
            self.assertIsNone(row['filesystem_free_bytes']); self.assertIsNone(row['qcow_size_bytes'])
            self.assertEqual(row['filesystem_sample'],'unavailable'); self.assertEqual(row['qcow_sample'],'absent')
            self.assertEqual(row['remaining_work_seconds'],0)

    def test_host_failure_operations_and_launcher_phases_are_closed_and_covered(self):
        source=(ROOT/'.github/windows_identity_stock_stage0.py').read_text()
        tree=ast.parse(source)
        host=next(node for node in tree.body if isinstance(node,ast.FunctionDef) and node.name=='host')
        values={node.value.value for node in ast.walk(host) if isinstance(node,ast.Assign)
                and any(isinstance(target,ast.Name) and target.id=='operation' for target in node.targets)
                and isinstance(node.value,ast.Constant)}
        self.assertEqual(values,set(stock.HOST_OPERATIONS)-{'cleanup'})
        self.assertIn("for key in ('diagnostics', 'guest_diagnostic', 'launcher_diagnostic'):",source)
        self.assertLess(source.index("public[key] = observed[key]"),source.index('public.update(validate_guest'))
        ps=(ROOT/'.github/windows-identity-stock-stage0-run.ps1').read_text()
        for phase in set(stock.LAUNCHER_PHASES)-{'not_observed','transport'}:
            self.assertIn("$phase='"+phase+"'",ps)
        self.assertIn('$hresult=[int]$_.Exception.HResult',ps)
        for category in stock.LAUNCHER_FAILURES:
            self.assertIn("$failureCategory='"+category+"'",ps)
        self.assertIn('RPBEACON identity-result-transport-failed',ps)
        self.assertIn('RPBEACON identity-result-transport-failed',source)

    def test_result_receiver_retains_closed_failure_stage(self):
        for body,expected in [(b'{','json_parse'),(b'[]','object_check'),(b'{}','object_received')]:
            handler=object.__new__(stock.ClosedHandler)
            handler.server=SimpleNamespace(capability='fixed',received=Mock(),result=None)
            handler.path='/fixed/result'; handler.headers={'Content-Length':str(len(body))}
            handler.rfile=io.BytesIO(body); handler.send_error=Mock();handler.send_response=Mock();handler.end_headers=Mock()
            handler.do_POST()
            self.assertEqual(handler.server.result_transport_state,expected)
            if expected=='object_received': handler.server.received.set.assert_called_once()
            else: handler.server.received.set.assert_not_called()

    def test_closed_projection(self):
        r = stock.project_stage0({'secret': '/private/identity', 'stage0_passed': True})
        self.assertNotIn('secret', r); self.assertFalse(r['stage0_passed'])
        self.assertIn('stock26200.6584', r['stage'])
    def test_exact_stock_gate(self):
        v = {'checks': {k: True for k in stock.CHECKS}, 'stage0_passed': True,
             'ordinary_account': True, 'stock_build_verified': True, 'harness_completed': True,
             'actor_sha256': 'a'*64, 'os': {'build':26200,'ubr':6584,'product_type':'WinNT','architecture':'AMD64'}}
        self.assertTrue(stock.validate_guest(v, 'a'*64)['stage0_passed'])
        v['os']['ubr'] = 9711
        with self.assertRaises(ValueError): stock.validate_guest(v, 'a'*64)
    def test_capacity_trip_overrides_simultaneous_result(self):
        result = stock.reconcile_capacity({'status':'passed','stage0_passed':True}, 'free_reserve_reached')
        self.assertFalse(result['stage0_passed']); self.assertEqual(result['status'], 'resource_abort')
    def test_register_after_trip_kills_process(self):
        import tempfile
        with tempfile.TemporaryDirectory() as path:
            watch = stock.CapacityWatch(Path(path)); watch.reason='free_reserve_reached'
            proc = SimpleNamespace(poll=lambda: None, kill=lambda: setattr(watch,'killed',True))
            with self.assertRaises(RuntimeError): watch.register(proc)
            self.assertTrue(watch.killed)
    def test_finalize_late_trip_and_cleanup_failure(self):
        watch = SimpleNamespace(reason=None, minimum_free=1, thread=SimpleNamespace(is_alive=lambda:False))
        watch.close=lambda: setattr(watch,'reason','free_reserve_reached')
        with patch.object(stock,'cleanup_owned',return_value=True):
            result=stock.finalize_owned({'stage0_passed':True,'status':'passed'},None,Path('/unused'),watch=watch)
        self.assertFalse(result['stage0_passed']); self.assertEqual(result['status'],'resource_abort')
        with patch.object(stock,'cleanup_owned',return_value=False):
            result=stock.finalize_owned({'stage0_passed':True,'status':'passed'},None,Path('/unused'))
        self.assertFalse(result['stage0_passed']); self.assertEqual(result['status'],'cleanup_unconfirmed')
    def test_finalize_kill_race_and_live_watcher_retains_work(self):
        import tempfile
        # Model both Windows (attribute absent) and an existing Linux value.
        # Only the mocked Linux finalizer receives this scoped fixture; no
        # production signal fallback or operating-system guard is changed.
        for signals in (SimpleNamespace(), SimpleNamespace(SIGXFSZ=31)):
            original = dict(vars(signals))
            with self.subTest(signals=original), tempfile.TemporaryDirectory() as directory:
                work=Path(directory)/'owned'; work.mkdir()
                process=SimpleNamespace(poll=lambda:None,kill=lambda:(_ for _ in ()).throw(ProcessLookupError()),wait=lambda timeout:0)
                watch=SimpleNamespace(reason=None,minimum_free=100,thread=SimpleNamespace(is_alive=lambda:True),close=lambda:None)
                media=SimpleNamespace(stop_owned=lambda p:None)
                with patch.object(stock,'signal',signals):
                    with patch.object(stock.signal,'SIGXFSZ',getattr(signals,'SIGXFSZ',25),create=True):
                        result=stock.finalize_owned({'stage0_passed':True},media,work,qemu=process,watch=watch)
                self.assertEqual(vars(signals),original)
                self.assertTrue(work.exists()); self.assertFalse(result['vm_destroyed']); self.assertFalse(result['stage0_passed'])
    def test_mocked_file_limit_signal_uses_scoped_existing_value(self):
        for signals in (SimpleNamespace(), SimpleNamespace(SIGXFSZ=31)):
            original = dict(vars(signals))
            expected = getattr(signals,'SIGXFSZ',25)
            process = SimpleNamespace(poll=lambda: -expected)
            with self.subTest(signals=original), patch.object(stock,'signal',signals):
                with patch.object(stock.signal,'SIGXFSZ',expected,create=True), patch.object(stock,'cleanup_owned',return_value=True):
                    result=stock.finalize_owned({'stage0_passed':True},None,Path('/unused'),qemu=process)
            self.assertEqual(vars(signals),original)
            self.assertFalse(result['stage0_passed'])
            self.assertEqual(result['capacity_abort'],'file_size_limit_signal')
            self.assertEqual(result['status'],'resource_abort')
    def test_absolute_workflow_budget(self):
        text=(ROOT / '.github/workflows/windows-identity-stock-stage0.yml').read_text()
        self.assertIn('STOCK_JOB_DEADLINE=',text)
        self.assertIn('--job-deadline-epoch "$STOCK_HOST_DEADLINE"',text)
        self.assertNotIn('112m sudo',text)
    def test_workflow_numeric_fields_convert_step_output_strings(self):
        import re
        text=(ROOT / '.github/workflows/windows-identity-stock-stage0.yml').read_text()
        dynamic=[]
        for field,value in re.findall(r'^\s+(timeout-minutes|max-parallel):\s*(.*?)\s*$',text,re.MULTILINE):
            if value.isdecimal():
                self.assertGreater(int(value),0)
            else:
                self.assertRegex(value,r'^\$\{\{ fromJSON\(steps\.stock_budget_[0-8]\.outputs\.minutes\) \}\}$')
                dynamic.append(value)
        self.assertEqual(len(dynamic),9)
        self.assertEqual(len(set(dynamic)),9)
    def test_recovery_embedding_matches_source(self):
        text=(ROOT / '.github/workflows/windows-identity-stock-stage0.yml').read_text()
        body=text.split("<<'REVIEWED_RECOVERY'\n",1)[1].split('          REVIEWED_RECOVERY',1)[0]
        decoded='\n'.join(line[10:] for line in body.splitlines())+'\n'
        self.assertEqual(decoded,(ROOT / '.github/windows_identity_provider_cache_recovery.py').read_text())
        self.assertIn("github.ref == 'refs/heads/dot/windows-isolation-proof'",text)
        self.assertIn('[identity-stock-stage0-runtime]',text)
    def test_no_servicing_or_full_media_copy(self):
        source = (ROOT / '.github/windows_identity_stock_stage0.py').read_text()
        self.assertNotIn('download_updates', source)
        self.assertNotIn('iso-tree', source)
        self.assertIn('preallocation=off', source)
        self.assertIn('ringbuf,id=serialbuf,size=65536', source)
        setup = (ROOT / '.github/windows-identity-stock-stage0-setup.ps1').read_text()
        self.assertNotIn('ScheduledTask', setup)
if __name__ == '__main__': unittest.main()
