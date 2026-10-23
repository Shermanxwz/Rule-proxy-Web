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
#include "windows_identity_lpac_loopback_contract.hpp"
#include <cstdio>
#include <cstdlib>
unsigned checks=0;void checked(bool x,unsigned line){++checks;if(!x){std::fprintf(stderr,"line %u\n",line);std::exit(1);}}
#define check(x) checked((x),__LINE__)
zlp::Plan plan(zlp::Role role=zlp::Role::Front){zlp::Plan p;p.role=role;
 check(zlp::id("11111111111111111111111111111111",p.run));
 check(zlp::id("22222222222222222222222222222222",p.boot));
 check(zlp::id("33333333333333333333333333333333",p.before));
 check(zlp::id("44444444444444444444444444444444",p.selected));
 check(zlp::id("55555555555555555555555555555555",p.after));
 p.frequency=1000;p.start=10000;p.deadline=130000;p.frontend=50001;p.origin=50002;return p;}
'''


def command(role=1,sequence=1,case=bytes.fromhex('44'*16),issued=20000,deadline=28000,op=1):
    return (b'ZCL1'+struct.pack('<HHII',1,op,sequence,role)+bytes.fromhex('11'*16)
            +bytes.fromhex('22'*16)+case+struct.pack('<QQQHHIQ',1000,130000,deadline,50001,50002,0,issued)+bytes(24))


def array(name,value):
    return 'std::array<std::uint8_t,%d> %s{%s};\n'%(len(value),name,','.join(map(str,value)))


class ZeroCapabilityLoopbackNativeTests(unittest.TestCase):
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
        request=b'ZLP1'+struct.pack('<HH',1,1)+bytes.fromhex('44'*16)+bytes.fromhex('11'*16)+bytes(24)
        source=HEADER+array('go',command())+array('python_request',request)+r'''
int main(){auto p=plan();check(zlp::valid(p));zlp::Ticket ticket{};
 check(zlp::command(go,p,1,20000,ticket));check(ticket.issued==20000&&ticket.deadline==28000);
 check(zlp::packet(p,p.selected,false)==python_request);
 check(zlp::matches(python_request.data(),64,p,p.selected,false));
 check(!zlp::matches(python_request.data(),63,p,p.selected,false));
 check(!zlp::matches(python_request.data(),65,p,p.selected,false));
 check(!zlp::matches(nullptr,64,p,p.selected,false));
 for(unsigned i=0;i<64;++i){auto b=python_request;b[i]^=1;check(!zlp::matches(b.data(),64,p,p.selected,false));}
 for(unsigned i=0;i<128;++i){auto b=go;b[i]^=1;zlp::Ticket ignored{};
  // issued/deadline changes can remain legal; all binding/reserved bytes cannot.
  if((i>=80&&i<88)||(i>=96&&i<104))continue;
  check(!zlp::command(b,p,1,20000,ignored));}
 check(!zlp::command(go,p,1,19999,ticket));check(!zlp::command(go,p,1,28000,ticket));
 check(!zlp::command(go,p,2,20000,ticket));
 auto late=go;zlp::put(late.data()+80,28001,8);check(!zlp::command(late,p,1,20000,ticket));
 auto future=go;zlp::put(future.data()+96,20001,8);check(!zlp::command(future,p,1,20000,ticket));
 auto reserve=go;zlp::put(reserve.data()+96,92000,8);zlp::put(reserve.data()+80,96000,8);
 check(!zlp::command(reserve,p,1,92000,ticket)); // D-35F=95000, never now+8F renewed.
 check(zlp::command(go,p,1,20000,ticket));auto release=go;zlp::put(release.data()+6,2,2);
 zlp::put(release.data()+96,22000,8);zlp::Ticket released{};
 check(zlp::command(release,p,1,23000,released,&ticket));
 auto renewed=release;zlp::put(renewed.data()+80,29000,8);
 check(!zlp::command(renewed,p,1,23000,released,&ticket));
 check(!zlp::command(release,p,1,28000,released,&ticket));
 auto bad=p;bad.frequency=UINT64_MAX;check(!zlp::valid(bad));
 bad=p;bad.frontend=bad.origin;check(!zlp::valid(bad));bad=p;bad.after=bad.selected;check(!zlp::valid(bad));
 bad=p;bad.deadline=p.start+120*p.frequency+1;check(!zlp::valid(bad));
 auto ordinary=plan(zlp::Role::OrdinaryClient);auto ordinary_go=go;
 zlp::put(ordinary_go.data()+12,4,4);zlp::put(ordinary_go.data()+8,2,4);
 for(unsigned i=0;i<16;++i)ordinary_go[48+i]=ordinary.after[i];
 check(zlp::command(ordinary_go,ordinary,2,20000,released));
 check(!zlp::command(ordinary_go,ordinary,1,20000,released));
 check(!zlp::command(release,ordinary,1,23000,released,&ticket));
 std::printf("ZERO_CAP_CONTRACT_CHECKS %u\n",checks);}
'''
        self.assertGreater(self.compile_fake(source),200)

    def test_compiled_zero_capability_header_is_safe_before_x64_group_offset(self):
        source=HEADER+r'''
int main(){
 for(std::size_t bytes=0;bytes<4;++bytes)check(!zlp::capabilities_extent(bytes,0,8,16));
 check(zlp::capabilities_extent(4,0,8,16));check(zlp::capabilities_extent(8,0,8,16));
 check(!zlp::capabilities_extent(4,1,8,16));check(!zlp::capabilities_extent(8,1,8,16));
 check(!zlp::capabilities_extent(23,1,8,16));check(zlp::capabilities_extent(24,1,8,16));
 check(!zlp::capabilities_extent(24,2,8,16));check(zlp::capabilities_extent(40,2,8,16));
 check(!zlp::capabilities_extent(4096,65,8,16));check(!zlp::capabilities_extent(4096,1,8,0));
 check(!zlp::capabilities_extent(4096,1,3,16));check(!zlp::capabilities_extent(8,1,4096,16));
 std::printf("ZERO_CAP_HEADER_CHECKS %u\n",checks);}
'''
        self.assertEqual(self.compile_fake(source),16)

    def test_native_is_fixed_role_no_capability_or_loopback_fallback_and_no_ui_loader(self):
        actor=(NATIVE/'windows_identity_lpac_loopback_actor.cpp').read_text(encoding='utf-8')
        for forbidden in ('TokenIsLessPrivilegedAppContainer','DeriveCapability','CheckNetIsolation','WinHttp',
                          'ShellExecute','CommandLineToArgv','CreateWindow','AssignProcessToJobObject','ResumeThread'):
            self.assertNotIn(forbidden,actor)
        self.assertIn('SO_EXCLUSIVEADDRUSE',actor);self.assertNotIn('SO_REUSEADDR',actor)
        self.assertIn('WSA_FLAG_NO_HANDLE_INHERIT',actor)
        self.assertIn('zlp::capabilities_extent(n,caps,offsetof(TOKEN_GROUPS,Groups)',actor)
        self.assertIn('&&caps==0',actor);self.assertIn('if(count==0)return true;',
                         (NATIVE/'windows_identity_lpac_loopback_contract.hpp').read_text())
        self.assertIn('if(!command(control+L"\\\\"+numbered(L"phase-",seq,L".bin"),seq,t))',actor)
        self.assertIn('if(ok)ok=clock.sample(work(),issue)&&ready_file();',actor)
        self.assertIn('const auto d=release?release->deadline:work();',actor)
        self.assertIn('Ticket released;if(!command(control+L"\\\\release.bin",seq,released,&t))',actor)


if __name__=='__main__':unittest.main()
