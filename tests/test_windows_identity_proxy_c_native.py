"""Portable C admission/fake transport only. Never runs the Windows C actor."""
import hashlib
import os
from pathlib import Path
import shutil
import subprocess
import tempfile
import unittest

ROOT=Path(__file__).resolve().parents[1]
NATIVE=ROOT/'.github/native'
HARNESS=r'''
#include "windows_identity_proxy_c_contract.hpp"
#include "windows_identity_proxy_bridge_core.hpp"
#include <cstdio>
using Bytes=std::array<std::uint8_t,128>;
void put(Bytes& b,unsigned offset,std::uint64_t n,unsigned count){for(unsigned i=0;i<count;++i)b[offset+i]=static_cast<std::uint8_t>(n>>(8*i));}
rpc::Binding binding(){rpc::Binding b;b.run.fill(0x11);b.admission.fill(0x22);b.frequency=1000;b.deadline=121000;b.p=50101;b.q=50102;b.o=50103;return b;}
Bytes command(const rpc::Binding& b,unsigned sequence=1,unsigned operation=1){
    Bytes out{};out[0]='R';out[1]='P';out[2]='C';out[3]='1';out[4]=1;out[5]=static_cast<std::uint8_t>(operation);
    put(out,8,sequence,4);for(unsigned i=0;i<16;++i){out[16+i]=b.run[i];out[32+i]=0x33;out[72+i]=b.admission[i];}
    put(out,48,b.frequency,8);put(out,56,b.deadline,8);put(out,64,b.p,2);put(out,66,b.q,2);put(out,68,b.o,2);put(out,88,110000,8);return out;
}
unsigned scenarios=0;
bool require(bool good,const char* name){++scenarios;if(!good)std::printf("FAIL %s\n",name);return good;}
bool decoded(const Bytes& bytes,const rpc::Binding& b,std::uint32_t sequence=1,std::uint64_t now=1000,bool fixture=false){
    rpc::Command c;return rpc::decode(bytes.data(),bytes.size(),b,sequence,now,c,fixture);}
int main(){bool good=true;const auto b=binding();const auto valid=command(b);
    for(unsigned op=0;op<256;++op){auto bytes=command(b,1,op);good=require(decoded(bytes,b)==((op>=1&&op<=6)||op==255),"closed-opcodes")&&good;}
    for(unsigned sequence=0;sequence<=17;++sequence){auto bytes=command(b,sequence);good=require(decoded(bytes,b,sequence)==(sequence>=1&&sequence<=16),"closed-sequences")&&good;
        if(sequence>=1&&sequence<=16)good=require(!decoded(bytes,b,sequence==16?1:sequence+1),"monotonic-next")&&good;}
    // Every bit outside the fresh phase case and phase deadline must be bound.
    for(unsigned offset=0;offset<128;++offset){if(offset==5||(offset>=8&&offset<12)||(offset>=32&&offset<48)||(offset>=88&&offset<96))continue;
        for(unsigned bit=0;bit<8;++bit){auto bytes=valid;bytes[offset]^=static_cast<std::uint8_t>(1u<<bit);
            good=require(!decoded(bytes,b),"binding-and-reserved-bits")&&good;}}
    for(unsigned size=0;size<=129;++size){rpc::Command c;
        good=require(rpc::decode(valid.data(),size,b,1,1000,c)==(size==128),"exact-size")&&good;}
    for(std::uint64_t end:std::array<std::uint64_t,7>{0,999,1000,1001,121000,121001,0xffffffffffffffffULL}){
        auto bytes=valid;put(bytes,88,end,8);good=require(decoded(bytes,b)==(end>1000&&end<=b.deadline),"absolute-phase-budget")&&good;}
    good=require(!decoded(valid,b,1,110000)&&!decoded(valid,b,1,121000),"no-deadline-renewal")&&good;
    for(unsigned op=1;op<=6;++op){rpc::Command c;auto bytes=command(b,1,op);
        good=require(rpc::decode(bytes.data(),128,b,1,1000,c)&&rpc::target(b,c.operation)==(op==6?53:op==2?b.o:op==3?b.q:b.p),"fixed-target-routing")&&good;}
    for(unsigned which=0;which<3;++which){auto bad=b;if(which==0)bad.p=49152;if(which==1)bad.q=bad.p;if(which==2)bad.o=bad.q;
        good=require(!rpc::valid_binding(bad)&&!decoded(valid,bad),"high-distinct-fixed-ports")&&good;}
    auto fixture=b;fixture.p=fixture.q=fixture.o=0;auto finish=command(fixture,1,255);
    for(unsigned i=0;i<16;++i)finish[32+i]=fixture.admission[i];put(finish,88,fixture.deadline,8);
    good=require(decoded(finish,fixture,1,1000,true)&&!decoded(finish,fixture),"fixture-finish-separate-authority")&&good;
    for(unsigned i=0;i<128;++i){auto bad=finish;bad[i]^=1;good=require(!decoded(bad,fixture,1,1000,true),"fixture-finish-all-fields-fixed")&&good;}
    rpc::Command absent;good=require(!rpc::decode(nullptr,128,b,1,1000,absent),"null")&&good;
    auto release=finish;release[5]=254;
    rpc::Command released;
    good=require(rpc::decode_release(release.data(),128,fixture,1000,released)&&released.operation==254
        &&released.sequence==1&&released.item==fixture.admission&&released.phase_deadline==fixture.deadline,
        "release-exact-separate-authority")&&good;
    good=require(!decoded(release,fixture,1,1000,true)&&!decoded(release,fixture)&&!rpc::decode_release(finish.data(),128,fixture,1000,released),
        "release-never-finish-or-network-go")&&good;
    for(unsigned offset=0;offset<128;++offset)for(unsigned bit=0;bit<8;++bit){auto bad=release;bad[offset]^=static_cast<std::uint8_t>(1u<<bit);
        good=require(!rpc::decode_release(bad.data(),128,fixture,1000,released),"release-all-bits-bound")&&good;}
    for(unsigned size=0;size<=129;++size)good=require(rpc::decode_release(release.data(),size,fixture,1000,released)==(size==128),"release-exact-size")&&good;
    good=require(!rpc::decode_release(nullptr,128,fixture,1000,released)
        &&!rpc::decode_release(release.data(),128,fixture,fixture.deadline,released)
        &&!rpc::decode_release(release.data(),128,b,1000,released),"release-null-late-or-network-binding")&&good;
    for(unsigned invalid=0;invalid<5;++invalid){rpc::WithholdGate gate;auto item=fixture.admission;
        if(invalid==0)item[0]^=1;
        good=require(!gate.begin(fixture,item,invalid!=1,invalid!=2,invalid==3?1u:0u,invalid==4?fixture.deadline:1000)
            &&!gate.held&&!gate.released&&!gate.closed,"withhold-needs-exact-declared-eof-zero-response-in-time")&&good;}
    rpc::WithholdGate gate;
    good=require(!gate.release(fixture,released,1000)&&!gate.consume_close(true),"no-release-or-close-before-held")&&good;
    good=require(gate.begin(fixture,fixture.admission,true,true,0,1000)&&gate.held&&!gate.released&&!gate.closed
        &&!gate.begin(fixture,fixture.admission,true,true,0,1000),"withhold-once-before-ack")&&good;
    good=require(rpc::decode_release(release.data(),128,fixture,1001,released),"release-decode-before-transition")&&good;
    for(unsigned invalid=0;invalid<5;++invalid){auto bad=released;
        if(invalid==0)bad.operation=255;if(invalid==1)bad.sequence=2;if(invalid==2)bad.item[0]^=1;if(invalid==3)--bad.phase_deadline;
        good=require(!gate.release(fixture,bad,invalid==4?fixture.deadline:1001)&&gate.held&&!gate.released,
            "withhold-rejects-other-authority-and-expiry")&&good;}
    good=require(gate.release(fixture,released,1001)&&gate.held&&gate.released&&!gate.closed
        &&!gate.release(fixture,released,1002),"release-once-keeps-socket-held-until-close")&&good;
    good=require(gate.consume_close(true)&&!gate.held&&gate.released&&gate.closed&&!gate.consume_close(true),"close-consumed-once")&&good;
    rpc::WithholdGate uncertain;
    good=require(uncertain.begin(fixture,fixture.admission,true,true,0,1000)&&uncertain.release(fixture,released,1001)
        &&!uncertain.consume_close(false)&&uncertain.closed&&!uncertain.held&&!uncertain.consume_close(true),"uncertain-close-never-retried")&&good;
    // Exact reducer state at relay death after origin accepted canonical GET+EOF.
    // Native ReadFile error 109 does not inject a core EOF or success event.
    const rpb::Config c{b.run,fixture.admission,49152,50103,0,10000,rpb::OriginAuthority::LocalLoopback};
    rpb::Frontend front(c);rpb::Relay relay(c);const auto hello=relay.pending_output(0);
    good=require(hello.size==48,"death-relay-hello")&&good;
    front.apply({0,1,0,1,hello,0});relay.apply({0,4,0,1,{nullptr,0},48});
    const auto ready=front.pending_output(0);good=require(ready.size==48,"death-front-ready")&&good;
    relay.apply({0,1,0,2,ready,0});front.apply({0,4,0,2,{nullptr,0},48});
    rpb::Buffer<256> request;rpb::append_literal(request,"GET http://ruleproxy-identity-proof.invalid/");rpb::append_hex(request,c.case_id);
    rpb::append_literal(request," HTTP/1.1\r\nHost: ruleproxy-identity-proof.invalid\r\n\r\n");
    good=require(request.size==129&&rpb::parse_request(c,request.view())==rpb::Failure::None,"death-real-client-request-129")&&good;
    front.apply({0,2,0,3,request.view(),0});front.apply({0,3,0,3,{nullptr,0},0});
    const auto request_frame=front.pending_output(0);good=require(request_frame.size==48,"death-request-frame")&&good;
    relay.apply({0,1,0,4,request_frame,0});front.apply({0,4,0,4,{nullptr,0},48});
    const auto canonical=rpb::relay_request(c);const auto upstream=relay.pending_output(1);
    good=require(canonical.size==95&&rpb::equal(upstream,canonical.view()),"death-relay-canonical-request-95")&&good;
    relay.apply({0,4,1,5,{nullptr,0},static_cast<std::uint32_t>(upstream.size)});
    const auto fs=front.snapshot();const auto rs=relay.snapshot();
    good=require(fs.failure==rpb::Failure::None&&fs.observations==1&&!fs.requested&&!fs.confirmed&&!fs.uncertain
        &&!front.pending_output(0).size&&!front.pending_output(1).size,"death-front-core-golden-0-1-0-0-0")&&good;
    good=require(rs.failure==rpb::Failure::None&&rs.observations==6&&!rs.requested&&!rs.confirmed&&!rs.uncertain
        &&!relay.pending_output(0).size&&!relay.pending_output(1).size,"death-relay-no-response-or-done-before-owner-stop")&&good;
    std::printf("C_FAKE_SCENARIOS %u\n",scenarios);return good?0:1;
}
'''


class NativeCContractTests(unittest.TestCase):
    def test_compiled_closed_command_binding_sequence_deadline_and_no_ambient_targets(self):
        compiler=shutil.which('cl.exe') if os.name=='nt' else shutil.which('c++')
        self.assertIsNotNone(compiler,'use the installed x64 developer compiler shell')
        with tempfile.TemporaryDirectory() as directory:
            work=Path(directory);source=work/'c-contract-fake.cpp';source.write_text(HARNESS,encoding='utf-8')
            exe=work/('c-contract-fake.exe' if os.name=='nt' else 'c-contract-fake')
            if os.name=='nt':command=[compiler,'/nologo','/W4','/WX','/std:c++17','/EHsc','/MT','/O2',
                '/I'+str(NATIVE),'/Fo'+str(work/'c-contract-fake.obj'),'/Fe'+str(exe),str(source)]
            else:command=[compiler,'-std=c++17','-Wall','-Wextra','-Werror','-O2','-I',str(NATIVE),str(source),'-o',str(exe)]
            built=subprocess.run(command,cwd=work,capture_output=True,text=True,timeout=60)
            self.assertEqual(built.returncode,0,built.stdout+built.stderr)
            ran=subprocess.run([str(exe)],cwd=work,capture_output=True,text=True,timeout=15)
            self.assertEqual(ran.returncode,0,ran.stdout+ran.stderr)
            self.assertIn('C_FAKE_SCENARIOS 2539',ran.stdout)

    def test_frozen_b_sources_are_reused_without_behavior_or_hash_rewrite(self):
        expected={'windows_identity_proxy_origin_actor.cpp':'3d079e77e387ba77545c27f5b5c260f591657ef3a44384426cd2039fa8c04010',
                  'windows_identity_proxy_origin_transport.hpp':'bed113e5e20064722cbb2c6d3e71b4d3ca6c4769ebd694c86997abec0af661c4'}
        for name,digest in expected.items():self.assertEqual(hashlib.sha256((NATIVE/name).read_bytes()).hexdigest(),digest)
        source=(NATIVE/'windows_identity_proxy_c_actor.cpp').read_text(encoding='utf-8')
        self.assertIn('#include "windows_identity_proxy_origin_actor.cpp"',source)
        self.assertIn('int WINAPI wWinMain',source)
        self.assertIn('__wargv',source)
        self.assertNotIn('CommandLineToArgvW',source)
        self.assertNotIn('shell32.lib',source)
        self.assertNotIn('probe.admitted(',source)
        self.assertNotIn('probe.run()',source)
        self.assertNotIn('synthetic_request()',source)
        self.assertIn('real-client-request-and-response-socket',source)

    def test_identity_first_and_fixed_raw_transport_surface(self):
        source=(NATIVE/'windows_identity_proxy_c_actor.cpp').read_text(encoding='utf-8')
        client=source[source.index('int client('):source.index('struct ListenerFacts')]
        barrier=client.index('const auto state=command_file(')
        self.assertNotIn('session.start()',client[:barrier])
        self.assertNotIn('Session session',client[:barrier])
        self.assertLess(client.index('if(command.operation==255)'),client.index('session.start()'))
        for forbidden in ('getaddrinfo(', 'GetAddrInfo', 'WinHttpOpen(', 'SO_REUSEADDR', 'CheckNetIsolation',
                          'CreateWindow', 'SetSecurityInfo(', 'CreateAppContainerProfile('):
            self.assertNotIn(forbidden,source)
        self.assertIn('AgenticAppContainer',source)
        self.assertIn('capability.attributes==4',source)
        self.assertIn('root_qpc',source)
        self.assertIn('command_close_verified',source)

    def test_compile_helper_binds_complete_closure_and_does_not_execute(self):
        source=(ROOT/'.github/build_windows_identity_proxy_c_actor.ps1').read_text(encoding='utf-8')
        for name in ('windows_identity_proxy_c_actor.cpp','windows_identity_proxy_c_contract.hpp',
                     'windows_identity_proxy_origin_actor.cpp','windows_identity_proxy_origin_transport.hpp',
                     'windows_identity_proxy_pipe_actor.cpp','windows_identity_proxy_bridge_core.hpp','windows_identity_actor.cpp'):
            self.assertIn(name,source)
        for flag in ('/SUBSYSTEM:WINDOWS','/W4','/WX','/MT','/guard:cf'):
            self.assertIn(flag,source)
        self.assertIn('compileOnly=$true;runtimeAcceptance=$false',source)
        self.assertNotIn('& $exe',source)

    def test_declared_withhold_keeps_default_origin_schema_and_never_reads_finish_while_held(self):
        source=(NATIVE/'windows_identity_proxy_c_actor.cpp').read_text(encoding='utf-8')
        held=source[source.index('bool withhold_origin('):source.index('int health_listener(')]
        for expected in ('death-held.json','death-release.json','release.bin','gate.begin(', 'gate.release(', 'gate.consume_close('):
            self.assertIn(expected,held)
        for forbidden in ('finish.bin','send_response(', 'receive_request(', 'accept_one(', 'send_bytes(', 'receive_bytes('):
            self.assertNotIn(forbidden,held)
        listener=source[source.index('int health_listener('):source.index('int dispatch(')]
        self.assertIn('argc!=(withholding?15:14)',listener)
        self.assertIn('withholding&&item==death',listener)
        self.assertIn('death==run||death==boot',listener)
        self.assertIn('role=withholding||std::wstring(argv[1])==L"health-origin"?"health-origin":"health-listener"',listener)


if __name__=='__main__':unittest.main()
