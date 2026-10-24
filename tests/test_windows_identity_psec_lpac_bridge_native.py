"""Portable production-core/spec tests. Never load the DLL or processmodel."""
from pathlib import Path
import hashlib
import importlib.util
import os
import shutil
import subprocess
import tempfile
import unittest

ROOT=Path(__file__).resolve().parents[1]
NATIVE=ROOT/'.github/native'

HARNESS=r'''
#include "windows_psec_lpac_bridge_core.hpp"
#include "windows_psec_lpac_bridge_spec.hpp"
#include <cstdio>
#include <cstdlib>
unsigned checks=0;
void checked(bool value,unsigned line){++checks;if(!value){std::fprintf(stderr,"check %u line %u failed\n",checks,line);std::exit(1);}}
#define check(value) checked((value),__LINE__)
PB_PLAN_V1 plan(std::uint64_t f=1000){return {sizeof(PB_PLAN_V1),1,f,10*f,130*f,125*f,95*f};}
pb::Machine machine(){pb::Machine s;check(s.initialize(plan())==pb::ok);s.bound=true;s.bind_verified=true;return s;}
PB_PI_V1 full_pi(){return {17,18,19,20};}
void normal(){
    auto s=machine();check(s.begin_environment()==pb::ok);check(s.begin_environment()==pb::bad_state);
    check(s.environment_result(0,true)==pb::ok);check(!s.opaque_unknown);check(!s.can_unbind());
    check(s.begin_arm(0,true)==pb::ok);check(s.begin_arm(1,true)==pb::bad_state);
    check(s.arm_result(true,full_pi())==pb::ok);check(s.begin_arm(1,true)==pb::ok);
    check(s.arm_result(true,full_pi())==pb::ok);check(s.begin_arm(1,true)==pb::bad_state);
    check(s.begin_close(false)==pb::bad_state);check(s.begin_close(true)==pb::ok);
    check(s.environment==pb::close_consumed && s.close_invoked && !s.close_returned);
    check(!s.can_unbind());check(s.begin_close(true)==pb::bad_state);s.end_close();
    check(s.can_unbind());s.module_close_attempted=true;check(!s.can_unbind());
}
void failures(){
    for(int hr:{-1,0,1})for(bool pointer:{false,true}){
        auto s=machine();check(s.begin_environment()==pb::ok);
        const auto result=s.environment_result(hr,pointer);
        if(hr==0&&pointer){check(result==pb::ok);check(s.begin_close(true)==pb::ok);}
        else if(hr<0&&!pointer){check(result==pb::api_failed);check(!s.opaque_unknown);check(s.can_unbind());}
        else{check(result!=pb::ok);check(s.opaque_unknown);check(s.begin_arm(0,true)==pb::bad_state);
            check(s.begin_close(true)==pb::bad_state);check(!s.can_unbind());}
        check(s.environment_result(0,true)==pb::bad_state);
    }
    {auto s=machine();s.bind_verified=false;check(s.begin_environment()==pb::bad_state);check(s.can_unbind());}
    {auto s=machine();s.begin_environment();check(!s.can_unbind());check(s.begin_close(true)==pb::bad_state);}
    for(unsigned index=0;index<5;++index){
        auto s=machine();s.begin_environment();s.environment_result(0,true);
        check(s.begin_arm(1,true)==pb::bad_state);check(s.begin_arm(0,false)==pb::bad_state);
        check(s.begin_arm(0,true)==pb::ok);auto pi=full_pi();
        if(index==0)pi.process=0;if(index==1)pi.thread=0;if(index==2)pi.process_id=0;
        if(index==3)pi.thread_id=0;if(index==4)pi.thread=pi.process;
        check(s.arm_result(true,pi)==pb::readback_failed);check(s.arm_failure);
        check(s.begin_arm(1,true)==pb::bad_state);check(s.begin_close(true)==pb::ok);
    }
    {auto s=machine();s.begin_environment();s.environment_result(0,true);s.begin_arm(0,true);
        check(s.arm_result(false,{})==pb::api_failed);check(!s.opaque_unknown);
        check(s.begin_arm(1,true)==pb::bad_state);check(s.begin_close(true)==pb::ok);}
    {auto s=machine();s.begin_environment();s.environment_result(0,true);s.begin_arm(0,true);
        check(s.begin_close(true)==pb::bad_state);check(!s.can_unbind());}
}
void clocks(){
    for(std::uint64_t f:{1ULL,1000ULL,10000000ULL}){
        auto p=plan(f);check(pb::valid_plan(p));
        check(pb::timely(p,f,p.start_qpc)==pb::ok);
        check(pb::timely(p,f,p.work_cutoff_qpc-1)==pb::ok);
        check(pb::timely(p,f,p.work_cutoff_qpc)==pb::deadline);
        check(pb::timely(p,f,p.worker_deadline_qpc-1,true)==pb::ok);
        check(pb::timely(p,f,p.worker_deadline_qpc,true)==pb::deadline);
        check(pb::timely(p,f,p.start_qpc-1)==pb::clock);check(pb::timely(p,f+1,p.start_qpc)==pb::clock);
        auto q=p;++q.worker_deadline_qpc;check(!pb::valid_plan(q));
        q=p;++q.work_cutoff_qpc;check(!pb::valid_plan(q));q=p;++q.root_deadline_qpc;check(!pb::valid_plan(q));
        q=p;q.start_qpc=q.root_deadline_qpc;check(!pb::valid_plan(q));
    }
    auto p=plan();p.frequency=0;check(!pb::valid_plan(p));p=plan();p.version=2;check(!pb::valid_plan(p));
    p=plan();p.frequency=~std::uint64_t(0);check(!pb::valid_plan(p));
}
std::vector<std::uint8_t> other_spec(unsigned kind){
    namespace L=ProcessSecurityEnvironmentLayout;flatbuffers::FlatBufferBuilder b;
    auto cap=b.CreateString(kind==0?"internetClient":"privateNetworkClientServer");
    std::vector<flatbuffers::Offset<flatbuffers::String>> p{b.CreateString("C:\\fixed\\inputs")};auto ro=b.CreateVector(p);
    auto proxy=kind==1?L::CreateProxyInfo(b,b.CreateString("http://127.0.0.1:1")):flatbuffers::Offset<L::ProxyInfo>{};
    auto e=L::CreateEndpointPolicy(b,kind==2?L::FilterAction_allow:L::FilterAction_deny);
    auto i=L::CreateIngressPolicy(b,L::FilterAction_deny,kind==3?L::FilterAction_allow:L::FilterAction_deny);
    auto net=L::CreateNetworkPolicy(b,proxy,e,0,i);L::SchemaVersion version(1,kind==4?0:1);
    auto root=L::CreateProcessSecurityEnvironment(b,&version,cap,kind!=5,kind==6?0:0x3ff,0,ro,0,net,0);
    L::FinishProcessSecurityEnvironmentBuffer(b,root);return {b.GetBufferPointer(),b.GetBufferPointer()+b.GetSize()};
}
void spec(){
    const std::string path="C:\\fixed\\inputs";const auto b=pb::build_spec(path);
    check(pb::verify_spec(b.data(),static_cast<unsigned>(b.size()),path));
    check(!pb::verify_spec(b.data(),static_cast<unsigned>(b.size()),path+"-other"));
    // FlatBuffers may end in unused alignment padding; every truncation into
    // the actual referenced payload must fail. Exact bytes are owner-SHA-bound.
    for(unsigned n=0;n+8<b.size();++n)check(!pb::verify_spec(b.data(),n,path));
    for(unsigned k=0;k<7;++k){const auto x=other_spec(k);check(!pb::verify_spec(x.data(),static_cast<unsigned>(x.size()),path));}
    auto x=b;x[4]='X';check(!pb::verify_spec(x.data(),static_cast<unsigned>(x.size()),path));
    std::string out;const std::u16string good=u"C:\\fixed\\inputs";
    check(pb::path_utf8(reinterpret_cast<const std::uint16_t*>(good.data()),static_cast<unsigned>(good.size()),out)&&out==path);
    for(const auto bad:{u"relative",u"C:/x",u"C:\\x\\..\\y",u"C:\\x\\.",u"C:\\x\\",u"C:\\x\""}){
        std::u16string s=bad;check(!pb::path_utf8(reinterpret_cast<const std::uint16_t*>(s.data()),static_cast<unsigned>(s.size()),out));}
    std::u16string unicode=u"C:\\path\\\u4e2d\U0001f600";
    check(pb::path_utf8(reinterpret_cast<const std::uint16_t*>(unicode.data()),static_cast<unsigned>(unicode.size()),out));
    check(out=="C:\\path\\\xe4\xb8\xad\xf0\x9f\x98\x80");
    unicode.push_back(0);check(!pb::path_utf8(reinterpret_cast<const std::uint16_t*>(unicode.data()),static_cast<unsigned>(unicode.size()),out));
}
int main(){normal();failures();clocks();spec();std::printf("PSEC_BRIDGE_FAKE_CHECKS %u\n",checks);}
'''

class BridgeNativeTests(unittest.TestCase):
    def compile_fake(self,code):
        compiler=shutil.which('cl.exe' if os.name=='nt' else 'c++')
        self.assertIsNotNone(compiler,'run in the installed compiler developer shell')
        with tempfile.TemporaryDirectory() as temp:
            p=Path(temp);source=p/'fake.cpp';source.write_bytes(code.encode())
            exe=p/('fake.exe' if os.name=='nt' else 'fake')
            includes=[NATIVE,ROOT/'generated',ROOT/'vendor/flatbuffers/include']
            if os.name=='nt':
                command=[compiler,'/nologo','/std:c++17','/EHsc','/W4','/WX','/MT','/O2',
                         *('/I'+str(x) for x in includes),'/Fo'+str(p/'fake.obj'),'/Fe'+str(exe),str(source)]
            else:
                command=[compiler,'-std=c++17','-Wall','-Wextra','-Werror','-O2',
                         *('-I'+str(x) for x in includes),str(source),'-o',str(exe)]
            result=subprocess.run(command,cwd=p,capture_output=True,text=True,errors='replace',timeout=60)
            self.assertEqual(result.returncode,0,result.stdout+result.stderr)
            result=subprocess.run([str(exe)],cwd=p,capture_output=True,text=True,errors='replace',timeout=10)
            self.assertEqual(result.returncode,0,result.stdout+result.stderr)
            return result.stdout

    def test_compiled_production_core_and_spec_without_windows_or_processmodel(self):
        result=self.compile_fake(HARNESS)
        self.assertGreater(int(result.split()[-1]),250)
        print(result.strip())

    def test_python_original_spec_bytes_pass_generated_cpp_verifier_and_exact_policy(self):
        loader=importlib.util.spec_from_file_location('psec_cross_language_spec',ROOT/'.github/windows_identity_psec_spec.py')
        codec=importlib.util.module_from_spec(loader);loader.loader.exec_module(codec)
        path=r'C:\fixed\inputs'
        raw=codec.build(path)
        self.assertEqual(codec.verify(raw,path)['read_only_count'],1)
        print('PYTHON_SPEC_ORIGINAL_BYTES',len(raw),hashlib.sha256(raw).hexdigest())
        # The same original Python bytes reach the official generated verifier;
        # the C++ builder never rebuilds or replaces this fixture.
        source='#include "windows_psec_lpac_bridge_spec.hpp"\n#include <cstdio>\n'
        source+='unsigned char raw[]={'+','.join(str(x) for x in raw)+'};\n'
        source+=r'''int main(){const auto n=static_cast<unsigned>(sizeof raw);
            if(!pb::verify_spec(raw,n,"C:\\fixed\\inputs"))return 1;
            if(pb::verify_spec(raw,n,"C:\\other\\inputs"))return 2;
            raw[4]='X';if(pb::verify_spec(raw,n,"C:\\fixed\\inputs"))return 3;
            raw[4]='P';raw[0]=255;if(pb::verify_spec(raw,n,"C:\\fixed\\inputs"))return 4;
            std::puts("PYTHON_SPEC_CPP_VERIFIED 4");return 0;}'''
        self.assertEqual(self.compile_fake(source).strip(),'PYTHON_SPEC_CPP_VERIFIED 4')

    def test_pinned_schema_and_no_active_execution_network_or_second_identity_source(self):
        schema=ROOT/'vendor/windows-sdk/ProcessSecurityEnvironment.fbs'
        self.assertEqual(hashlib.sha256(schema.read_bytes()).hexdigest(),
                         '736cacef37a6c97a0cb97c7132da462a3b51811fca8f1e4076cac51085dfa516')
        adapter=(NATIVE/'windows_psec_lpac_bridge.cpp').read_text()
        for forbidden in ('ResumeThread(', 'SECURITY_CAPABILITIES', 'CreateProcessAsUser', 'HANDLE_LIST',
                          'CreateAppContainerProfile(', 'socket(', 'WSAStartup(', 'DnsQuery', 'WinHttp',
                          'TerminateProcess(', 'TerminateJobObject(', 'CloseHandle('):
            self.assertNotIn(forbidden,adapter)
        self.assertIn('LoadLibraryExW(L"processmodel.dll",nullptr,LOAD_LIBRARY_SEARCH_SYSTEM32)',adapter)
        self.assertIn('InitializeProcThreadAttributeList(nullptr,3,0,&size)',adapter)
        self.assertIn('const DWORD error=GetLastError(); // Immediate',adapter)
        self.assertIn('c->environment=nullptr; // Consume before the VOID call',adapter)
        self.assertEqual(adapter.count('c->close(value);'),1)
        self.assertIn('CREATE_SUSPENDED|EXTENDED_STARTUPINFO_PRESENT',adapter)

if __name__=='__main__':unittest.main()
