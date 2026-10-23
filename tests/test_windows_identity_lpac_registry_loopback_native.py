"""Portable production-contract fakes. Never execute the network actor."""
from pathlib import Path
import os
import shutil
import struct
import subprocess
import tempfile
import unittest

ROOT=Path(__file__).resolve().parents[1]
NATIVE=ROOT/'.github/native'
HEADER=r'''
#include "windows_identity_lpac_registry_loopback_contract.hpp"
#include <cstdio>
#include <cstdlib>
unsigned checks=0;void checked(bool x,unsigned line){++checks;if(!x){std::fprintf(stderr,"line %u\n",line);std::exit(1);}}
#define check(x) checked((x),__LINE__)
rlp::Plan plan(rlp::Role role=rlp::Role::Front){rlp::Plan p;p.role=role;
 check(rlp::id("11111111111111111111111111111111",p.run));
 check(rlp::id("22222222222222222222222222222222",p.boot));
 check(rlp::id("33333333333333333333333333333333",p.before));
 check(rlp::id("44444444444444444444444444444444",p.selected));
 check(rlp::id("55555555555555555555555555555555",p.after));
 p.frequency=1000;p.start=10000;p.deadline=130000;p.frontend=50001;p.origin=50002;return p;}
'''


def command(role=1,sequence=1,case=bytes.fromhex('44'*16),issued=20000,deadline=28000,op=1):
    return (b'RCL1'+struct.pack('<HHII',1,op,sequence,role)+bytes.fromhex('11'*16)
            +bytes.fromhex('22'*16)+case+struct.pack('<QQQHHIQ',1000,130000,deadline,50001,50002,0,issued)+bytes(24))


def array(name,value):
    return 'std::array<std::uint8_t,%d> %s{%s};\n'%(len(value),name,','.join(map(str,value)))


class RegistryReadLoopbackNativeTests(unittest.TestCase):
    def compile_fake(self,source):
        compiler=shutil.which('cl.exe' if os.name=='nt' else 'c++')
        self.assertIsNotNone(compiler,'installed compiler developer shell is required; no skip/fallback')
        with tempfile.TemporaryDirectory() as temp:
            directory=Path(temp);cpp=directory/'fake.cpp';cpp.write_bytes(source.encode('ascii'))
            exe=directory/('fake.exe' if os.name=='nt' else 'fake')
            if os.name=='nt':
                command=[compiler,'/nologo','/std:c++17','/EHsc','/W4','/WX','/MT','/O2','/I'+str(NATIVE),
                         '/Fo'+str(directory/'fake.obj'),'/Fe'+str(exe),str(cpp)]
            else:
                command=[compiler,'-std=c++17','-Wall','-Wextra','-Werror','-O2','-I'+str(NATIVE),str(cpp),'-o',str(exe)]
            result=subprocess.run(command,cwd=directory,capture_output=True,text=True,errors='replace',timeout=60)
            self.assertEqual(result.returncode,0,result.stdout+result.stderr)
            result=subprocess.run([str(exe)],cwd=directory,capture_output=True,text=True,errors='replace',timeout=10)
            self.assertEqual(result.returncode,0,result.stdout+result.stderr)
            return int(result.stdout.split()[-1])

    def test_compiled_python_packets_commands_mutation_roles_and_original_deadline(self):
        request=b'RLP1'+struct.pack('<HH',1,1)+bytes.fromhex('44'*16)+bytes.fromhex('11'*16)+bytes(24)
        source=HEADER+array('go',command())+array('python_request',request)+r'''
int main(){auto p=plan();check(rlp::valid(p));rlp::Ticket ticket{};
 check(rlp::command(go,p,1,20000,ticket));check(ticket.issued==20000&&ticket.deadline==28000);
 check(rlp::packet(p,p.selected,false)==python_request);
 check(rlp::matches(python_request.data(),64,p,p.selected,false));
 check(!rlp::matches(python_request.data(),63,p,p.selected,false));
 check(!rlp::matches(python_request.data(),65,p,p.selected,false));
 check(!rlp::matches(nullptr,64,p,p.selected,false));
 for(unsigned i=0;i<64;++i){auto b=python_request;b[i]^=1;check(!rlp::matches(b.data(),64,p,p.selected,false));}
 for(unsigned i=0;i<128;++i){auto b=go;b[i]^=1;rlp::Ticket ignored{};
  // issued/deadline changes can remain legal; all binding/reserved bytes cannot.
  if((i>=80&&i<88)||(i>=96&&i<104))continue;
  check(!rlp::command(b,p,1,20000,ignored));}
 check(!rlp::command(go,p,1,19999,ticket));check(!rlp::command(go,p,1,28000,ticket));
 check(!rlp::command(go,p,2,20000,ticket));
 auto late=go;rlp::put(late.data()+80,28001,8);check(!rlp::command(late,p,1,20000,ticket));
 auto future=go;rlp::put(future.data()+96,20001,8);check(!rlp::command(future,p,1,20000,ticket));
 auto reserve=go;rlp::put(reserve.data()+96,92000,8);rlp::put(reserve.data()+80,96000,8);
 check(!rlp::command(reserve,p,1,92000,ticket)); // D-35F=95000, never now+8F renewed.
 check(rlp::command(go,p,1,20000,ticket));auto release=go;rlp::put(release.data()+6,2,2);
 rlp::put(release.data()+96,22000,8);rlp::Ticket released{};
 check(rlp::command(release,p,1,23000,released,&ticket));
 auto renewed=release;rlp::put(renewed.data()+80,29000,8);
 check(!rlp::command(renewed,p,1,23000,released,&ticket));
 check(!rlp::command(release,p,1,28000,released,&ticket));
 auto bad=p;bad.frequency=UINT64_MAX;check(!rlp::valid(bad));
 bad=p;bad.frontend=bad.origin;check(!rlp::valid(bad));bad=p;bad.after=bad.selected;check(!rlp::valid(bad));
 bad=p;bad.deadline=p.start+120*p.frequency+1;check(!rlp::valid(bad));
 auto ordinary=plan(rlp::Role::OrdinaryClient);auto ordinary_go=go;
 rlp::put(ordinary_go.data()+12,4,4);rlp::put(ordinary_go.data()+8,2,4);
 for(unsigned i=0;i<16;++i)ordinary_go[48+i]=ordinary.after[i];
 check(rlp::command(ordinary_go,ordinary,2,20000,released));
 check(!rlp::command(ordinary_go,ordinary,1,20000,released));
 check(!rlp::command(release,ordinary,1,23000,released,&ticket));
 std::printf("ZERO_CAP_CONTRACT_CHECKS %u\n",checks);}
'''
        self.assertGreater(self.compile_fake(source),200)

    def test_compiled_exact_registry_read_capability_and_zero_header_boundaries(self):
        source=HEADER+r'''
int main(){
 for(std::size_t bytes=0;bytes<4;++bytes)check(!rlp::capabilities_extent(bytes,0,8,16));
 check(rlp::capabilities_extent(4,0,8,16));check(rlp::capabilities_extent(8,0,8,16));
 check(!rlp::capabilities_extent(4,1,8,16));check(!rlp::capabilities_extent(8,1,8,16));
 check(!rlp::capabilities_extent(23,1,8,16));check(rlp::capabilities_extent(24,1,8,16));
 check(!rlp::capabilities_extent(24,2,8,16));check(rlp::capabilities_extent(40,2,8,16));
 check(!rlp::capabilities_extent(4096,65,8,16));check(!rlp::capabilities_extent(4096,1,8,0));
 check(!rlp::capabilities_extent(4096,1,3,16));check(!rlp::capabilities_extent(8,1,4096,16));
 check(rlp::registry_sid_extent(1000,72,1024));check(!rlp::registry_sid_extent(1000,71,1024));
 check(!rlp::registry_sid_extent(1000,72,999));check(!rlp::registry_sid_extent(1000,72,1073));
 check(!rlp::registry_sid_extent(1000,72,0));check(!rlp::registry_sid_extent(0,72,24));
 check(rlp::registry_sid_extent(1000,48,1000));check(!rlp::registry_sid_extent(1000,47,1000));
 check(rlp::registry_sid_extent(UINTPTR_MAX-64,64,UINTPTR_MAX-48));
 check(!rlp::registry_sid_extent(UINTPTR_MAX-64,63,UINTPTR_MAX-48));
 auto sid=rlp::RegistryReadSid;
 check(rlp::admitted_capabilities(rlp::Role::Selected,1,sid.data(),sid.size(),4));
 for(unsigned i=0;i<sid.size();++i)for(unsigned bit=0;bit<8;++bit){sid[i]^=static_cast<std::uint8_t>(1u<<bit);
  check(!rlp::admitted_capabilities(rlp::Role::Selected,1,sid.data(),sid.size(),4));sid[i]^=static_cast<std::uint8_t>(1u<<bit);}
 for(unsigned count:{0u,2u,64u,65u})check(!rlp::admitted_capabilities(rlp::Role::Selected,count,sid.data(),48,4));
 for(unsigned attributes:{0u,1u,2u,5u,8u,~0u})check(!rlp::admitted_capabilities(rlp::Role::Selected,1,sid.data(),48,attributes));
 for(std::size_t bytes:{0u,4u,8u,16u,47u,49u,68u})check(!rlp::admitted_capabilities(rlp::Role::Selected,1,sid.data(),bytes,4));
 check(!rlp::admitted_capabilities(rlp::Role::Selected,1,nullptr,48,4));
 check(!rlp::admitted_capabilities(static_cast<rlp::Role>(5),0,nullptr,0,0));
 for(auto role:{rlp::Role::Front,rlp::Role::OrdinaryClient,rlp::Role::OrdinaryListener}){
  check(rlp::admitted_capabilities(role,0,nullptr,0,0));
  check(!rlp::admitted_capabilities(role,1,sid.data(),48,4));}
 std::printf("REGISTRY_READ_HEADER_CHECKS %u\n",checks);}
'''
        self.assertEqual(self.compile_fake(source),436)

    def test_native_fixed_one_cap_selected_no_fallback_or_ui_and_bounded_sid_before_sdk(self):
        actor=(NATIVE/'windows_identity_lpac_registry_loopback_actor.cpp').read_text(encoding='utf-8')
        for forbidden in ('TokenIsLessPrivilegedAppContainer','DeriveCapability','CheckNetIsolation','WinHttp',
                          'ShellExecute','CommandLineToArgv','CreateWindow','AssignProcessToJobObject','ResumeThread'):
            self.assertNotIn(forbidden,actor)
        self.assertIn('SO_EXCLUSIVEADDRUSE',actor);self.assertNotIn('SO_REUSEADDR',actor)
        self.assertIn('WSA_FLAG_NO_HANDLE_INHERIT',actor)
        self.assertIn('rlp::capabilities_extent(n,caps,offsetof(TOKEN_GROUPS,Groups)',actor)
        self.assertIn('rlp::admitted_capabilities(p.role,caps',actor);self.assertIn('if(count==0)return true;',
                         (NATIVE/'windows_identity_lpac_registry_loopback_contract.hpp').read_text())
        self.assertLess(actor.index('rlp::registry_sid_extent(begin,n,sid_address)'),actor.index('IsValidSid(entry.Sid)'))
        self.assertIn('if(!command(control+L"\\\\"+numbered(L"phase-",seq,L".bin"),seq,t))',actor)
        self.assertIn('if(ok)ok=clock.sample(work(),issue)&&ready_file();',actor)
        self.assertIn('const auto d=release?release->deadline:work();',actor)
        self.assertIn('Ticket released;if(!command(control+L"\\\\release.bin",seq,released,&t))',actor)


if __name__=='__main__':unittest.main()
