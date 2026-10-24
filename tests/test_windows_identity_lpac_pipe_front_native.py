"""Portable production-branch fakes only. Never compile/run the Win32 actor."""
import hashlib
import json
import os
from pathlib import Path
import re
import shutil
import subprocess
import tempfile
import unittest

ROOT=Path(__file__).resolve().parents[1]
NATIVE=ROOT/'.github/native'
CPP='windows_identity_lpac_pipe_front_actor.cpp'

CONTRACT_HARNESS=r'''
#define RULEPROXY_LPAC_PIPE_FRONT_PORTABLE 1
#include "windows_identity_lpac_pipe_front_actor.cpp"
#include <algorithm>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <stdexcept>
unsigned checks=0;void checked(bool value,unsigned line){++checks;if(!value){std::fprintf(stderr,"line%u\n",line);std::exit(1);}}
#define check(v) checked((v),__LINE__)
std::vector<std::wstring> argv(){return {L"C:\\Owned\\front.exe",L"pipe-front",std::wstring(32,L'1'),std::wstring(32,L'2'),
 L"C:\\Owned\\selected-report\\final.json",L"40",L"44",L"10000",L"1000",L"20000",L"S-1-5-21-1",L"S-1-15-2-1-2-3-4-5-6-7",L"0",L"54321"};}
struct FakeProbe {struct {std::uint64_t last=10000;}facts;const char* failure=nullptr;std::uint32_t error=0;
 std::uint64_t deadline=20000;unsigned samples=0;
 bool sample(){++samples;++facts.last;if(facts.last>=deadline){fail("qpc");return false;}return true;}
 void fail(const char* name,std::uint32_t value=0){if(!failure){failure=name;error=value;}}
};
struct Flags {unsigned calls=0;bool read_set=false,write_set=false,read_error=false,write_error=false,throw_error=false;
 bool flags(std::uintptr_t handle,std::uint32_t& out,std::uint32_t& error){++calls;if(throw_error)throw std::runtime_error("fake");
  check(handle==40||handle==44);const bool read=handle==40;out=(read?read_set:write_set)?1u:0u;
  const bool ok=!(read?read_error:write_error);error=ok?0u:5u;return ok;}
};
rpb::Config config(){rpb::Config c{{},{},49152,54321,0,10000,rpb::OriginAuthority::LocalLoopback};c.run_id.fill(0x11);c.case_id.fill(0x22);return c;}
void frontend(unsigned split,bool error_frame=false){auto c=config();rpb::Frontend f(c);std::uint64_t tick=1;
 auto event=[&](std::uint8_t kind,std::uint8_t selector=0,rpb::ByteView bytes={nullptr,0},std::uint32_t count=0){f.apply({0,kind,selector,tick++,bytes,count});};
 auto feed=[&](const rpb::Buffer<48>& frame){for(std::size_t at=0;at<48;){const auto n=(std::min)(std::size_t(split),48-at);event(1,0,{frame.data.data()+at,n});at+=n;}};
 const auto hello=rpb::encode_frame(c,1);feed(hello);check(f.pending_output(0).size==48);event(4,0,{nullptr,0},48);
 rpb::Buffer<256> request;rpb::append_literal(request,"GET http://ruleproxy-identity-proof.invalid/");rpb::append_hex(request,c.case_id);
 rpb::append_literal(request," HTTP/1.1\r\nHost: ruleproxy-identity-proof.invalid\r\n\r\n");event(2,0,request.view());event(3);
 check(f.pending_output(0).size==48);event(4,0,{nullptr,0},48);const auto response=rpb::encode_frame(c,4,error_frame?1u:0u);feed(response);
 if(error_frame){check(f.snapshot().failure!=rpb::Failure::None);return;}
 event(5);event(6,0,{nullptr,0},1);const auto sink=rpb::expected_response(c);check(rpb::equal(f.pending_output(1),sink.view()));
 event(4,1,{nullptr,0},static_cast<std::uint32_t>(sink.size));event(6,2,{nullptr,0},1);
 check(f.pending_output(0).size==48);event(4,0,{nullptr,0},48);event(6,1,{nullptr,0},1);
 const auto s=f.snapshot();check(s.failure==rpb::Failure::None&&s.requested==7&&s.confirmed==7&&s.uncertain==0);
 check(f.pending_output(0).size==0&&f.pending_output(1).size==0);
}
int main(){
 lpac_pipe::Plan p;auto a=argv();check(lpac_pipe::plan(a,p)&&p.port==54321&&p.reader==40&&p.writer==44&&p.end==20000);
 for(unsigned index:{1u,12u}){auto b=a;b[index]=index==1?L"pipe-relay":L"1";check(!lpac_pipe::plan(b,p));}
 for(auto pair:std::vector<std::pair<unsigned,std::wstring>>{{5,L"0"},{5,L"-1"},{5,L"9223372036854775808"},{6,L"40"},{7,L"0"},{8,L"0"},{8,L"1000000001"},{9,L"20001"},{13,L"49152"},{13,L"65536"},{11,L"none"},{2,L"ABC"}}){auto b=a;b[pair.first]=pair.second;check(!lpac_pipe::plan(b,p));}
 {auto b=a;b[7]=L"9223372036854775800";check(!lpac_pipe::plan(b,p));}
 {auto b=a;b.pop_back();check(!lpac_pipe::plan(b,p));b=a;b.push_back(L"extra");check(!lpac_pipe::plan(b,p));}
 std::wstring command;for(const auto& value:a){if(!command.empty()){command+=L' ';}command+=L'"'+value+L'"';}
 std::vector<std::wstring> parsed;check(lpac_pipe::arguments(command.c_str(),parsed)&&parsed==a);
 for(auto suffix:{L" extra",L"\"",L" x\"bad"}){parsed.clear();check(!lpac_pipe::arguments((command+suffix).c_str(),parsed));}
 parsed.clear();check(!lpac_pipe::arguments((L"\""+std::wstring(4097,L'x')+L"\"").c_str(),parsed));
 for(unsigned kind=0;kind<7;++kind){Flags flags;FakeProbe probe;lpac_pipe::Readback r;
  if(kind==1){flags.read_set=true;}if(kind==2){flags.write_set=true;}if(kind==3){flags.read_error=true;}if(kind==4){flags.write_error=true;}
  if(kind==5){probe.deadline=10002;}if(kind==6){probe.deadline=10003;}
  const bool ok=lpac_pipe::inheritance_readback(flags,probe,40,44,r);
  if(kind==0)check(ok&&r.reader&&r.writer&&r.admitted&&r.admitted_qpc==10003&&flags.calls==2);
  else{check(!ok&&!r.admitted);if(kind==3||kind==4)check(probe.error==5);if(kind==6)check(r.reader&&r.writer);}
 }
 {Flags f;f.throw_error=true;FakeProbe p2;lpac_pipe::Readback r;bool threw=false;try{lpac_pipe::inheritance_readback(f,p2,40,44,r);}catch(...){threw=true;}check(threw&&!r.admitted&&f.calls==1);}
 auto c=config();for(std::uint8_t kind=1;kind<=5;++kind){auto frame=rpb::encode_frame(c,kind);std::uint8_t out=0;std::uint32_t status=0;
  check(frame.size==48&&rpb::decode_frame(c,frame.view(),out,status)&&out==kind&&status==0);
  for(std::size_t at=0;at<48;++at)for(unsigned bit=0;bit<8;++bit){auto mutated=frame;mutated.data[at]^=static_cast<std::uint8_t>(1u<<bit);
   const bool valid=rpb::decode_frame(c,mutated.view(),out,status);const bool allowed_error=kind==4&&at==44&&bit<3;
   check(valid==allowed_error);if(valid)check(status==1||status==2||status==4);}
  for(std::size_t n=0;n<48;++n)check(!rpb::decode_frame(c,{frame.data.data(),n},out,status));
  std::uint8_t long_frame[49]{};std::memcpy(long_frame,frame.data.data(),48);check(!rpb::decode_frame(c,{long_frame,49},out,status));
  auto wrong=c;wrong.case_id[0]^=1;check(!rpb::decode_frame(wrong,frame.view(),out,status));
 }
 for(unsigned split=1;split<=48;++split){frontend(split);frontend(split,true);}
 {rpb::Frontend f(c);const auto bad=rpb::encode_frame(c,2);f.apply({0,1,0,1,bad.view(),0});check(f.snapshot().failure==rpb::Failure::Order);}
 std::printf("LPAC_PIPE_PORTABLE_ASSERTIONS %u\n",checks);return 0;
}
'''

CAPS_PREFIX=r'''
#include <cstddef>
#include <cstdint>
#include <cstdio>
#include <cstring>
#include <cstdlib>
#include <optional>
#include <string>
#include <vector>
using DWORD=std::uint32_t;using BYTE=std::uint8_t;using HANDLE=std::uintptr_t;
constexpr int TokenCapabilities=30,ERROR_BUFFER_OVERFLOW=111,ERROR_INVALID_DATA=13;
constexpr DWORD kMaxCapabilities=16;
struct SID_AND_ATTRIBUTES {void* Sid;DWORD Attributes;};struct TOKEN_GROUPS {DWORD GroupCount;SID_AND_ATTRIBUTES Groups[1];};
struct Capability {std::string sid;DWORD attributes;};struct Observations {std::vector<int> errors;std::vector<Capability> tokenCapabilities;};
std::vector<BYTE> supplied;unsigned sid_reads=0;
void AddError(Observations& o,const char*,int e){o.errors.push_back(e);}
bool QueryVariable(HANDLE,int,std::size_t minimum,const char*,std::vector<BYTE>& out,Observations& o){if(supplied.size()<minimum){o.errors.push_back(13);return false;}out=supplied;return true;}
bool SidToString(void*,const std::vector<BYTE>&,const char*,std::optional<std::string>& out,Observations&){++sid_reads;out="fake-capability";return true;}
'''
CAPS_SUFFIX=r'''
int main(){unsigned count=0;auto check=[&](bool value){++count;if(!value)std::exit(1);};
 supplied.assign(4,0);Observations empty;ObserveCapabilities(1,empty);check(empty.errors.empty()&&empty.tokenCapabilities.empty()&&sid_reads==0);
 for(std::size_t n=0;n<4;++n){supplied.assign(n,0);Observations o;ObserveCapabilities(1,o);check(!o.errors.empty()&&sid_reads==0);}
 for(std::size_t n=4;n<offsetof(TOKEN_GROUPS,Groups)+sizeof(SID_AND_ATTRIBUTES);++n){supplied.assign(n,0);supplied[0]=1;Observations o;ObserveCapabilities(1,o);check(!o.errors.empty()&&sid_reads==0);}
 supplied.assign(4,0);supplied[0]=17;Observations many;ObserveCapabilities(1,many);check(!many.errors.empty()&&sid_reads==0);
 supplied.assign(offsetof(TOKEN_GROUPS,Groups)+sizeof(SID_AND_ATTRIBUTES),0);supplied[0]=1;Observations one;ObserveCapabilities(1,one);
 check(one.errors.empty()&&one.tokenCapabilities.size()==1&&sid_reads==1);
 std::printf("IMMUTABLE_CAPS_PRODUCTION_ASSERTIONS %u\n",count);return 0;}
'''

class NativeLPACPipeTests(unittest.TestCase):
    def compiled(self,text,marker):
        compiler=shutil.which('cl.exe') if os.name=='nt' else shutil.which('c++')
        self.assertIsNotNone(compiler,'use the installed x64 compiler developer shell')
        with tempfile.TemporaryDirectory() as folder:
            root=Path(folder);source=root/'fake.cpp';source.write_bytes(text.encode('utf-8'))
            exe=root/('fake.exe' if os.name=='nt' else 'fake')
            args=([compiler,'/nologo','/std:c++17','/W4','/WX','/EHsc','/MT','/O2','/I'+str(NATIVE),
                '/Fo'+str(root/'fake.obj'),'/Fe'+str(exe),str(source)] if os.name=='nt' else
                [compiler,'-std=c++17','-Wall','-Wextra','-Werror','-O2','-I',str(NATIVE),str(source),'-o',str(exe)])
            built=subprocess.run(args,cwd=root,capture_output=True,text=True,timeout=60)
            self.assertEqual(built.returncode,0,built.stdout+built.stderr)
            ran=subprocess.run([str(exe)],cwd=root,capture_output=True,text=True,timeout=15)
            self.assertEqual(ran.returncode,0,ran.stdout+ran.stderr)
            self.assertRegex(ran.stdout,marker)
            print(ran.stdout.strip())

    def test_compiled_production_frontend_plan_readback_qpc_and_rpb1_split_mutations(self):
        self.compiled(CONTRACT_HARNESS,r'LPAC_PIPE_PORTABLE_ASSERTIONS [2-9][0-9]{3}')

    def test_immutable_observe_capabilities_exact_production_body_handles_four_byte_zero(self):
        source=(NATIVE/'windows_identity_actor.cpp').read_text(encoding='utf-8')
        begin=source.index('void ObserveCapabilities(');end=source.index('\nObservations ObserveNativeIdentity()',begin)
        body=source[begin:end]
        self.assertIn('constexpr DWORD kMaxCapabilities = 16;',source)
        self.compiled(CAPS_PREFIX+body+CAPS_SUFFIX,r'IMMUTABLE_CAPS_PRODUCTION_ASSERTIONS [2-9][0-9]')

    def test_selected_only_four_source_composition_closed_report_and_no_network_entry(self):
        source=(NATIVE/CPP).read_text(encoding='utf-8')
        self.assertIn('#define RULEPROXY_PROXY_PIPE_LIBRARY 1',source)
        self.assertIn('#include "windows_identity_proxy_pipe_actor.cpp"',source)
        self.assertIn('rpb::OriginAuthority::LocalLoopback',source)
        self.assertIn('args.size()!=14||args[1]!=L"pipe-front"||args[12]!=L"0"',source)
        self.assertIn('out.end!=out.start+10*out.frequency',source)
        self.assertIn('GetHandleInformation',source)
        self.assertIn('result.admitted_qpc=probe.facts.last',source)
        self.assertLess(source.index('identity=ObserveNativeIdentity()'),source.index('if(probe.admitted(identity'))
        self.assertLess(source.index('if(probe.admitted(identity'),source.index('if(inheritance_readback(api'))
        for forbidden in ('winsock2.h','ws2tcpip.h','WSAStartup','WSASocket','WinHttp','DnsQuery','getaddrinfo','CreateProcessW(',
                'CreateAppContainerProfile(', 'CommandLineToArgvW', 'ShellExecute', 'CreateWindow', 'windows_identity_proxy_origin_actor.cpp'):
            self.assertNotIn(forbidden,source)
        keys=('schema_version','stage','role','run_id','case_id','pid','ipc_mechanics','admitted_qpc',
            'read_handle_inherit_cleared','write_handle_inherit_cleared','identity_basis','network_tested','proxy_tested','product_acceptance')
        for key in keys:self.assertIn('\\"'+key+'\\"',source)
        self.assertIn('external-held-four-descriptor-required',source)
        self.assertIn('lpac-ipc-origin-selected',source)
        self.assertIn('"network_tested\\":false',source)
        self.assertIn('!identity.tokenCapabilities.empty()', (NATIVE/'windows_identity_proxy_pipe_actor.cpp').read_text(encoding='utf-8'))
        for name in ('windows_identity_proxy_pipe_actor.cpp','windows_identity_actor.cpp','windows_identity_proxy_bridge_core.hpp'):
            self.assertEqual(len(hashlib.sha256((NATIVE/name).read_bytes()).hexdigest()),64)

if __name__=='__main__':unittest.main()
