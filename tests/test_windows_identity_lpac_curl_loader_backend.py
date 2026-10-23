"""API-shaped pure fakes for the NEW loader adapter only.

No NativeAPI initializer, WinDLL, OS API, compiler, target, or network call.
Actual production methods run against caller-owned ctypes buffers and Python
functions. These tests do not establish compiled ABI or runtime acceptance.
"""
import copy
import ctypes as C
import importlib.util
from pathlib import Path
import types
import unittest
from unittest import mock

ROOT=Path(__file__).resolve().parents[1]


def source_module(name,path):
    spec=importlib.util.spec_from_file_location(name,path)
    module=importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


m=source_module('loader_backend_under_test',ROOT/'.github/windows_identity_lpac_curl_loader.py')
proc=source_module('loader_backend_ctypes_only',ROOT/'ruleproxy/windows_app_process.py')


class Fn:
    """Assigning argtypes/restype is supported; calling remains pure Python."""
    def __init__(self,call):self.call=call
    def __call__(self,*args):return self.call(*args)


class Budget:
    def __init__(self):self.tick=1200;self.calls=[]
    def read(self):self.calls.append(('read',self.tick));return self.tick
    def require_ms(self,end):
        self.calls.append(('require',end,self.tick))
        if self.tick>=end:raise ValueError('fake_original_deadline')
        return end-self.tick


class Fixture:
    def __init__(self):
        # Explicitly bypass the initializer that loads real Windows libraries.
        self.api=m.NativeAPI.__new__(m.NativeAPI)
        self.api.controls_uncertain=False;self.api.proc=proc
        self.error=0;self.trace=[];self.free_calls=[];self.close_calls=[];self.attrs=[];self.init_counts=[]
        self.closed=set();self.flags={};self.created=[];self.receipts=[]
        self.raw_pi=[0x100000110,0x100000114,70000,70004]
        self.create_bool=1;self.create_exception=None;self.after_create_tick=None;self.receipt_exception=None
        self.delete_exception=False;self.free_failure=set();self.free_exception=set()
        self.event_handle=0x210;self.event_exception=None;self.duplicate_handle=0x214;self.duplicate_bool=1;self.duplicate_exception=None
        self.duplicate_calls=[];self.event_calls=[];self.module_calls=0
        self.budget=Budget();self.info=proc._ProcessInfo();self.state={}
        self.api.k=types.SimpleNamespace(
            InitializeProcThreadAttributeList=Fn(self.initialize),
            UpdateProcThreadAttribute=Fn(self.update_attribute),
            DeleteProcThreadAttributeList=Fn(self.delete_attributes),
            CreateProcessW=Fn(self.create),LocalFree=Fn(self.free),
            GetCurrentProcess=Fn(lambda:-1),GetHandleInformation=Fn(self.handle_flags),
            CreateEventExW=Fn(self.event),DuplicateHandle=Fn(self.duplicate),
            K32EnumProcessModulesEx=Fn(self.modules),K32GetMappedFileNameW=Fn(self.unexpected_mapping_path))
        self.api.a=types.SimpleNamespace()
        self.api.native=types.SimpleNamespace(check=self.check)
        self.api.process_info=lambda:proc._ProcessInfo()
        self.api.system_curl=lambda:Path('C:/Windows/System32/curl.exe')
        self.api.close=self.close
        self.owners=m.helpers.OneShotHandles(self.close)
        self.job=0x7000;self.sid=0x6000;self.sd=0x8000
        self.selected_handles=[0x50,0x54,0x60,0x64,0x68]
        self.environment='SystemRoot=C:\\Windows\0LOCALAPPDATA=C:\\Owned\\AppData\0\0'
        self.expected_env=self.environment

    def check(self,ok,operation):
        if not ok:raise m.launcher.NativeFailure(operation,self.error)

    def initialize(self,attrs,count,flags,size):
        self.init_counts.append((bool(attrs),int(count),int(flags)))
        C.cast(size,C.POINTER(C.c_size_t))[0]=256
        return int(bool(attrs))

    def update_attribute(self,attrs,flags,kind,value,size,previous,returned):
        self.trace.append(('attribute',kind))
        if kind==m.base.JOB_LIST:
            observed=list(C.cast(value,C.POINTER(C.c_void_p*(size//8)))[0])
        elif kind==0x20002:
            observed=list(C.cast(value,C.POINTER(C.c_void_p*(size//8)))[0])
        elif kind==m.base.SECURITY_CAPABILITIES:
            v=C.cast(value,C.POINTER(proc._SecurityCapabilities))[0]
            observed=[v.AppContainerSid,v.Capabilities,v.CapabilityCount,v.Reserved]
        elif kind==m.base.ALL_APPLICATION_PACKAGES_POLICY:
            observed=C.cast(value,C.POINTER(C.c_uint32))[0]
        else:raise AssertionError('unexpected attribute')
        self.attrs.append((kind,size,observed));return 1

    def delete_attributes(self,attrs):
        self.trace.append(('delete_attributes',))
        if self.delete_exception:raise RuntimeError('fake_delete_attributes')

    def create(self,application,command,process_sa,thread_sa,inherit,flags,environment,cwd,startup,output):
        self.trace.append(('CreateProcessW',))
        p=C.cast(process_sa,C.POINTER(m.launcher.SecurityAttributes))[0]
        t=C.cast(thread_sa,C.POINTER(m.launcher.SecurityAttributes))[0]
        si=C.cast(startup,C.POINTER(proc._StartupInfoEx))[0]
        self.created.append(dict(application=application,command=command.value,inherit=bool(inherit),flags=flags,cwd=cwd,
            process_sa=[p.length,p.security,bool(p.inherit)],thread_sa=[t.length,t.security,bool(t.inherit)],
            same_sa=C.cast(process_sa,C.c_void_p).value==C.cast(thread_sa,C.c_void_p).value,
            startup_cb=si.StartupInfo.cb,startup_flags=si.StartupInfo.dwFlags,
            stdio=[si.StartupInfo.hStdInput,si.StartupInfo.hStdOutput,si.StartupInfo.hStdError],
            attr_pointer=si.lpAttributeList,environment=C.wstring_at(environment,len(self.expected_env))))
        result=C.cast(output,C.POINTER(proc._ProcessInfo))[0]
        result.hProcess,result.hThread,result.dwProcessId,result.dwThreadId=self.raw_pi
        if self.after_create_tick is not None:self.budget.tick=self.after_create_tick
        if self.create_exception:raise self.create_exception
        return self.create_bool

    def free(self,pointer):
        value=pointer.value if isinstance(pointer,C.c_void_p) else int(pointer)
        self.trace.append(('LocalFree',value));self.free_calls.append(value)
        if value in self.free_exception:raise RuntimeError('fake_LocalFree')
        return value if value in self.free_failure else 0

    def close(self,handle):
        self.close_calls.append(handle)
        if handle in self.closed:raise AssertionError('double close')
        self.closed.add(handle)

    def handle_flags(self,handle,out):
        C.cast(out,C.POINTER(C.c_uint32))[0]=self.flags.get(int(handle),1)
        return 1

    def event(self,sa,name,flags,access):
        v=C.cast(sa,C.POINTER(m.launcher.SecurityAttributes))[0]
        self.event_calls.append(dict(name=name,flags=flags,access=access,security=v.security,inherit=bool(v.inherit)))
        if self.event_exception:raise self.event_exception
        self.flags[self.event_handle]=0
        return self.event_handle

    def duplicate(self,source_process,source,target_process,output,access,inherit,options):
        self.duplicate_calls.append((source_process,source,target_process,access,bool(inherit),options))
        C.cast(output,C.POINTER(C.c_void_p))[0]=self.duplicate_handle
        if self.duplicate_exception:raise self.duplicate_exception
        self.flags[self.duplicate_handle]=int(bool(inherit))
        return self.duplicate_bool

    def modules(self,*args):
        self.module_calls+=1;return 0

    def unexpected_mapping_path(self,*args):
        raise AssertionError('mapping path must not be queried after failed module enumeration')

    def returned(self,value):
        self.trace.append(('receipt',))
        self.receipts.append(copy.deepcopy(value))
        if self.receipt_exception:raise self.receipt_exception

    def invoke(self,*,selected=True,other_owned=()):
        handles=self.selected_handles if selected else self.selected_handles[-3:]
        for h in handles:self.flags.setdefault(h,1)
        return self.api.create_curl(self.info,[str(self.api.system_curl()),'--disable','--version'],
            Path('C:/Owned/package'),self.environment,self.job,self.owners,self.state,
            handles=handles,stdio=handles[-3:],profile_pointer=self.sid if selected else None,
            parent_sid='S-1-5-21-1',budget=self.budget,end=1900,on_return=self.returned,other_owned=other_owned)


class BackendTests(unittest.TestCase):
    def setUp(self):
        self.no_init=mock.patch.object(m.NativeAPI,'__init__',side_effect=AssertionError('real backend forbidden')).start()
        self.no_dll=mock.patch.object(C,'WinDLL',side_effect=AssertionError('DLL loading forbidden'),create=True).start()
        self.addCleanup(mock.patch.stopall)

    def patches(self,fixture):
        stack=types.SimpleNamespace()
        stack.error=mock.patch.object(C,'get_last_error',lambda:fixture.error,create=True)
        stack.descriptor=mock.patch.object(m.local.LocalNativeAPI,'private_descriptor',return_value=fixture.sd)
        return stack

    def run_constructor(self,f,**kwargs):
        p=self.patches(f)
        with p.error,p.descriptor:return f.invoke(**kwargs)

    def test_selected_constructor_exact_five_handles_zero_caps_and_atomic_job(self):
        f=Fixture();self.run_constructor(f)
        self.assertEqual(f.init_counts,[(False,4,0),(True,4,0)])
        rows={kind:(size,value) for kind,size,value in f.attrs}
        self.assertEqual(set(rows),{m.base.JOB_LIST,0x20002,m.base.SECURITY_CAPABILITIES,m.base.ALL_APPLICATION_PACKAGES_POLICY})
        self.assertEqual(rows[m.base.JOB_LIST],(8,[f.job]))
        self.assertEqual(rows[0x20002],(40,f.selected_handles))
        self.assertEqual(rows[m.base.SECURITY_CAPABILITIES],(C.sizeof(proc._SecurityCapabilities),[f.sid,None,0,0]))
        self.assertEqual(rows[m.base.ALL_APPLICATION_PACKAGES_POLICY],(4,1))
        created=f.created[0]
        self.assertEqual(created['application'],str(f.api.system_curl()))
        self.assertTrue(created['command'].endswith(' --disable --version'))
        self.assertEqual(created['environment'],f.environment)
        self.assertEqual(created['stdio'],f.selected_handles[-3:])
        self.assertTrue(created['same_sa']);self.assertTrue(created['inherit'])
        self.assertEqual(created['process_sa'],[C.sizeof(m.launcher.SecurityAttributes),f.sd,False])
        self.assertEqual(created['thread_sa'],created['process_sa'])
        self.assertEqual(created['flags'],0x08000000|proc._CREATE_SUSPENDED|proc._CREATE_UNICODE_ENVIRONMENT|proc._EXTENDED_STARTUPINFO_PRESENT)
        self.assertEqual(created['startup_flags'],0x100);self.assertEqual(created['startup_cb'],C.sizeof(proc._StartupInfoEx))
        self.assertTrue(created['attr_pointer'])
        self.assertEqual(f.owners.pending,set(f.raw_pi[:2]));self.assertFalse(f.state['creation_unknown'])
        self.assertEqual(f.receipts[0]['raw_pi'],f.raw_pi);self.assertEqual(f.receipts[0]['create_status'],'returned_true')
        self.assertEqual(f.free_calls,[f.sd]);self.assertLess(f.trace.index(('receipt',)),f.trace.index(('delete_attributes',)))
        self.no_init.assert_not_called();self.no_dll.assert_not_called()

    def test_ordinary_constructor_has_only_job_and_three_stdio_handles(self):
        f=Fixture();f.environment='SystemRoot=C:\\Windows\0WINDIR=C:\\Windows\0TEMP=C:\\Owned\\temp\0TMP=C:\\Owned\\temp\0\0';f.expected_env=f.environment
        self.run_constructor(f,selected=False)
        self.assertEqual(f.init_counts,[(False,2,0),(True,2,0)])
        self.assertEqual([(k,v) for k,n,v in f.attrs],[(m.base.JOB_LIST,[f.job]),(0x20002,f.selected_handles[-3:])])
        self.assertEqual(f.created[0]['environment'],f.environment)

    def test_constructor_rejects_bad_handle_list_or_inheritance_before_allocation(self):
        for kind in ('count','alias','inheritance','environment'):
            with self.subTest(kind=kind):
                f=Fixture()
                if kind=='count':f.selected_handles.pop()
                if kind=='alias':f.selected_handles[1]=f.selected_handles[0]
                if kind=='inheritance':f.flags[f.selected_handles[0]]=0
                if kind=='environment':f.environment='SystemRoot=C:\\Windows\0LOCALAPPDATA=C:\\Owned\0WINDIR=C:\\Windows\0\0'
                with self.assertRaises(ValueError):self.run_constructor(f)
                self.assertEqual(f.created,[]);self.assertEqual(f.init_counts,[]);self.assertEqual(f.free_calls,[])

    def test_true_pi_alias_or_partial_never_enters_trusted_owners(self):
        cases=[('same',0x910,0x910),('ledger',0x900,0x914),('inherited',0x50,0x914),
               ('other-resource',0x920,0x914),('partial',0x910,0),('invalid',0xffffffffffffffff,0x914)]
        for name,hp,ht in cases:
            with self.subTest(name=name):
                f=Fixture();f.raw_pi=[hp,ht,70000,70004];f.owners.add(0x900)
                with self.assertRaises(ValueError):self.run_constructor(f,other_owned={0x920})
                self.assertTrue(f.state['creation_unknown']);self.assertEqual(f.owners.pending,{0x900})
                self.assertEqual([f.info.hProcess,f.info.hThread,f.info.dwProcessId,f.info.dwThreadId],[None,None,0,0])
                self.assertEqual(f.receipts[0]['raw_pi'],f.raw_pi);self.assertEqual(f.close_calls,[])

    def test_false_zero_error_partial_and_known_no_child_remain_distinct(self):
        for error,pi,unknown in [(0,[0,0,0,0],True),(5,[0,0,0,0],False),
                                 (5,[0x910,0,0,0],True),(5,[0x910,0x914,70000,70004],True)]:
            with self.subTest(error=error,pi=pi):
                f=Fixture();f.create_bool=0;f.error=error;f.raw_pi=pi
                with self.assertRaises(ValueError):self.run_constructor(f)
                self.assertEqual(f.state['creation_unknown'],unknown)
                self.assertEqual(f.receipts[0]['raw_return'],0);self.assertEqual(f.receipts[0]['raw_error'],error)
                self.assertEqual(f.receipts[0]['raw_pi'],pi)
                self.assertFalse(f.owners.pending);self.assertEqual(f.close_calls,[])

    def test_create_exception_preserves_partial_raw_pi_without_adoption(self):
        f=Fixture();f.raw_pi=[0x910,0,70000,0];f.create_exception=RuntimeError('physical_create_exception')
        with self.assertRaisesRegex(RuntimeError,'physical_create_exception'):self.run_constructor(f)
        self.assertEqual(f.state['create_status'],'exception');self.assertIsNone(f.state['raw_return'])
        self.assertTrue(f.state['creation_unknown']);self.assertEqual(f.receipts[0]['raw_pi'],f.raw_pi)
        self.assertFalse(f.owners.pending);self.assertEqual(f.close_calls,[]);self.assertEqual(f.free_calls,[f.sd])

    def test_late_true_owns_exact_pi_but_cannot_admit(self):
        f=Fixture();f.after_create_tick=1900
        with self.assertRaisesRegex(ValueError,'fake_original_deadline'):self.run_constructor(f)
        self.assertFalse(f.state['creation_unknown']);self.assertEqual(f.owners.pending,set(f.raw_pi[:2]))
        self.assertEqual(f.receipts[0]['create_status'],'returned_true');self.assertEqual(f.receipts[0]['returned_qpc'],1900)
        for h in tuple(f.owners.pending):f.owners.close(h)
        self.assertCountEqual(f.close_calls,f.raw_pi[:2]);self.assertTrue(f.owners.confirmed_closed)

    def test_return_receipt_failure_keeps_known_true_cleanup_authority(self):
        f=Fixture();f.receipt_exception=OSError('durable_return_failure')
        with self.assertRaisesRegex(OSError,'durable_return_failure'):self.run_constructor(f)
        self.assertEqual(f.owners.pending,set(f.raw_pi[:2]));self.assertFalse(f.state['creation_unknown'])
        self.assertEqual(f.receipts[0]['raw_pi'],f.raw_pi);self.assertEqual(f.free_calls,[f.sd])

    def test_attribute_cleanup_exception_still_attempts_known_sd_once(self):
        f=Fixture();f.delete_exception=True
        with self.assertRaisesRegex(ValueError,'loader_constructor_resource_close'):self.run_constructor(f)
        self.assertEqual(f.free_calls,[f.sd]);self.assertTrue(f.api.controls_uncertain)
        self.assertEqual(f.owners.pending,set(f.raw_pi[:2]));self.assertEqual(f.receipts[0]['raw_pi'],f.raw_pi)

    def sddl_fixture(self):
        f=Fixture();sd=C.create_string_buffer(64);text=C.create_unicode_buffer('D:P(A;;GA;;;SY)')
        f.sd_buffers=(sd,text);sdptr=C.addressof(sd);textptr=C.addressof(text)
        def get_security(handle,kind,information,owner,group,dacl,sacl,out):
            self.assertEqual((kind,information),(6,4));C.cast(out,C.POINTER(C.c_void_p))[0]=sdptr;return 0
        def convert(descriptor,revision,information,out,length):
            self.assertEqual((descriptor.value,revision,information),(sdptr,1,4))
            C.cast(out,C.POINTER(C.c_void_p))[0]=textptr;return 1
        f.api.a.GetSecurityInfo=Fn(get_security);f.api.a.ConvertSecurityDescriptorToStringSecurityDescriptorW=Fn(convert)
        return f,sdptr,textptr

    def test_sddl_all_known_allocations_consumed_even_if_first_free_fails(self):
        for throw in (False,True):
            with self.subTest(throw=throw):
                f,sd,text=self.sddl_fixture()
                (f.free_exception if throw else f.free_failure).add(text)
                with self.assertRaisesRegex(ValueError,'loader_kernel_SD_close'):f.api.kernel_sddl(0x42)
                self.assertEqual(f.free_calls,[text,sd]);self.assertTrue(f.api.controls_uncertain)

    def test_failed_sd_apis_do_not_free_unowned_nonzero_outputs(self):
        f,sd,text=self.sddl_fixture()
        def failed_get(*args):C.cast(args[-1],C.POINTER(C.c_void_p))[0]=sd;return 5
        f.api.a.GetSecurityInfo=Fn(failed_get)
        with self.assertRaises(ValueError):f.api.kernel_sddl(0x42)
        self.assertEqual(f.free_calls,[]);self.assertTrue(f.api.controls_uncertain)
        f,sd,text=self.sddl_fixture()
        def failed_convert(*args):C.cast(args[3],C.POINTER(C.c_void_p))[0]=text;return 0
        f.api.a.ConvertSecurityDescriptorToStringSecurityDescriptorW=Fn(failed_convert)
        with self.assertRaises(ValueError):f.api.kernel_sddl(0x42)
        self.assertEqual(f.free_calls,[sd]);self.assertTrue(f.api.controls_uncertain)

    def test_event_and_signal_duplicate_use_exact_rights_and_inheritance(self):
        f=Fixture();original=m.helpers.OneShotHandles(f.close);signal=m.helpers.OneShotHandles(f.close);p=self.patches(f)
        with p.error,p.descriptor:
            h=f.api.event(original,set(),'S-1-5-21-1')
            d=f.api.signal_duplicate(h,signal,original.pending)
        self.assertEqual(f.event_calls,[dict(name=None,flags=1,access=0x100002,security=f.sd,inherit=False)])
        self.assertEqual(f.duplicate_calls,[(-1,h,-1,2,True,0)])
        self.assertEqual(original.pending,{h});self.assertEqual(signal.pending,{d});self.assertNotEqual(h,d)
        self.assertEqual(f.flags[h],0);self.assertEqual(f.flags[d],1)
        self.assertEqual(f.free_calls,[f.sd])

    def test_event_and_duplicate_alias_or_flag_mismatch_fail_closed(self):
        f=Fixture();ledger=m.helpers.OneShotHandles(f.close);p=self.patches(f)
        with p.error,p.descriptor,self.assertRaisesRegex(ValueError,'loader_resource_alias'):
            f.api.event(ledger,{f.event_handle},'S-1-5-21-1')
        self.assertFalse(ledger.pending);self.assertTrue(f.api.controls_uncertain);self.assertEqual(f.close_calls,[])
        f=Fixture();ledger=m.helpers.OneShotHandles(f.close);f.duplicate_handle=0x50;p=self.patches(f)
        with p.error,self.assertRaisesRegex(ValueError,'loader_resource_alias'):f.api.signal_duplicate(0x50,ledger,{0x50})
        self.assertFalse(ledger.pending);self.assertTrue(f.api.controls_uncertain)
        f=Fixture();ledger=m.helpers.OneShotHandles(f.close);f.api.handle_flags=lambda h:0;p=self.patches(f)
        with p.error,self.assertRaisesRegex(ValueError,'loader_signal_inherit'):f.api.signal_duplicate(0x50,ledger,set())
        self.assertEqual(ledger.pending,{f.duplicate_handle});self.assertEqual(f.close_calls,[])

    def test_event_descriptor_free_exception_is_uncertain_but_event_stays_known(self):
        for throw in (False,True):
            with self.subTest(throw=throw):
                f=Fixture();ledger=m.helpers.OneShotHandles(f.close);p=self.patches(f)
                (f.free_exception if throw else f.free_failure).add(f.sd)
                with p.error,p.descriptor,self.assertRaises((ValueError,RuntimeError)):
                    f.api.event(ledger,set(),'S-1-5-21-1')
                self.assertTrue(f.api.controls_uncertain);self.assertEqual(ledger.pending,{f.event_handle})
                self.assertEqual(f.free_calls,[f.sd]);self.assertEqual(f.close_calls,[])

    def test_event_or_signal_allocation_exception_remains_unknown_without_adoption(self):
        for name in ('event','duplicate'):
            with self.subTest(name=name):
                f=Fixture();ledger=m.helpers.OneShotHandles(f.close);p=self.patches(f)
                if name=='event':f.event_exception=RuntimeError('event_call_exception')
                else:f.duplicate_exception=RuntimeError('duplicate_call_exception')
                with p.error,p.descriptor,self.assertRaises(RuntimeError):
                    if name=='event':f.api.event(ledger,set(),'S-1-5-21-1')
                    else:f.api.signal_duplicate(0x50,ledger,set())
                self.assertTrue(f.api.controls_uncertain);self.assertFalse(ledger.pending);self.assertEqual(f.close_calls,[])

    def test_mapping_duplicate_failure_or_exception_is_sticky_without_blind_close(self):
        for exception,output in [(False,0),(False,0x999),(True,0x999)]:
            with self.subTest(exception=exception,output=output):
                f=Fixture();f.duplicate_bool=0;f.duplicate_handle=output;f.error=0
                if exception:f.duplicate_exception=RuntimeError('query_duplicate_exception')
                p=self.patches(f)
                with p.error:
                    result=f.api.mapped_marker({'info':types.SimpleNamespace(hProcess=0x42)}, {},Path('unused-marker'), '0'*64,f.budget,1900,set())
                self.assertFalse(result['verified']);self.assertIsNotNone(result['error']);self.assertTrue(f.api.controls_uncertain)
                self.assertEqual(f.module_calls,0);self.assertEqual(f.close_calls,[])
                self.assertEqual(f.duplicate_calls,[(-1,0x42,-1,0x410,False,0)])

    def test_mapping_known_query_handle_is_closed_once_on_later_failure(self):
        f=Fixture();f.error=5;p=self.patches(f)
        with p.error:
            result=f.api.mapped_marker({'info':types.SimpleNamespace(hProcess=0x42)}, {},Path('unused-marker'),'0'*64,f.budget,1900,set())
        self.assertFalse(result['verified']);self.assertTrue(result['query_closed']);self.assertTrue(result['file_closed'])
        self.assertFalse(f.api.controls_uncertain);self.assertEqual(f.module_calls,1);self.assertEqual(f.close_calls,[f.duplicate_handle])


if __name__=='__main__':unittest.main()
