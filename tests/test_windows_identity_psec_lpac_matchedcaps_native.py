"""ABI-3 pure production-core tests; never load the bridge/processmodel.

Compilation of the portable harness is for the root's later reviewed pure run.
Preparing this file does not compile or execute it.
"""
import ctypes as C
from pathlib import Path
import os
import shutil
import struct
import subprocess
import tempfile
import unittest

ROOT=Path(__file__).resolve().parents[1]
NATIVE=ROOT/'.github/native'
AGENTIC='S-1-15-3-1024-530591407-3118584226-222893001-1659895842-537460181-133087082-1363364250-4100990745'
PNCS='S-1-15-3-3'


def sid_bytes(text):
    fields=text.split('-');values=[int(x) for x in fields[3:]]
    return bytes((int(fields[1]),len(values)))+int(fields[2]).to_bytes(6,'big')+struct.pack('<'+'I'*len(values),*values)


def fixture_header():
    def array(name,text):
        value=sid_bytes(text)
        return 'std::array<std::uint8_t,%d> %s{{%s}};\n'%(len(value),name,','.join(str(x) for x in value))
    return ('#include "windows_psec_lpac_matchedcaps_bridge_core.hpp"\n#include <cstdio>\n#include <cstdlib>\n'
            'unsigned checks=0;void tested(bool x,unsigned n){++checks;if(!x){std::fprintf(stderr,"failed %u\\n",n);std::exit(1);}}\n'
            '#define check(x) tested((x),__LINE__)\n'+array('agentic',AGENTIC)+array('pncs',PNCS)
            +array('package','S-1-15-2-10-20-30-40-50-60-70')+
            'PB_SC_INPUT_V3 input(){return {64,3,2,0,package.data(),static_cast<unsigned>(package.size()),0,'
            'agentic.data(),static_cast<unsigned>(agentic.size()),4,pncs.data(),static_cast<unsigned>(pncs.size()),4};}\n')


SC_HARNESS=r'''
int main(){
    auto in=input();pb::SecuritySnapshot original{};
    check(pb::security_input(in,original));
    pb::SecuritySnapshot same{};check(pb::security_input(in,same));check(pb::same_security(original,same));
    // Caller storage changes after validation cannot change native-owned bytes.
    const auto saved=package[12];package[12]^=1;
    check(original.package[12]==saved);
    pb::SecuritySnapshot different{};check(pb::security_input(in,different));
    check(!pb::same_security(original,different));package[12]=saved;
    auto bad=in;
    for(unsigned field=0;field<8;++field){
        bad=in;
        if(field==0)++bad.size;
        if(field==1)--bad.version;
        if(field==2)--bad.capability_count;
        if(field==3)bad.reserved=1;
        if(field==4)bad.reserved2=1;
        if(field==5)bad.agentic_attributes=0;
        if(field==6)bad.pncs_attributes=8;
        if(field==7)bad.capability_count=3;
        pb::SecuritySnapshot out{};check(!pb::security_input(bad,out));
    }
    bad=in;bad.agentic_sid=pncs.data();bad.agentic_bytes=static_cast<unsigned>(pncs.size());
    bad.pncs_sid=agentic.data();bad.pncs_bytes=static_cast<unsigned>(agentic.size());
    check(!pb::security_input(bad,same)); // Named positions/order cannot swap.
    std::array<std::uint8_t,68> padded_package{};
    std::copy(package.begin(),package.end(),padded_package.begin());
    for(unsigned n:{0u,1u,8u,16u,19u,67u,68u,69u,~0u}){
        bad=in;bad.package_sid=padded_package.data();bad.package_bytes=n;
        check(!pb::security_input(bad,same));
    }
    for(unsigned which=0;which<3;++which){
        bad=in;
        if(which==0)bad.package_sid=nullptr;
        if(which==1)bad.agentic_sid=nullptr;
        if(which==2)bad.pncs_sid=nullptr;
        check(!pb::security_input(bad,same));
    }
    for(unsigned n=0;n<agentic.size();++n){
        agentic[n]^=1;check(!pb::security_input(in,same));agentic[n]^=1;
    }
    for(unsigned n=0;n<pncs.size();++n){
        pncs[n]^=1;check(!pb::security_input(in,same));pncs[n]^=1;
    }
    for(unsigned n:{0u,1u,2u,7u,8u}){
        package[n]^=1;check(!pb::security_input(in,same));package[n]^=1;
    }
    bad=in;bad.agentic_bytes--;check(!pb::security_input(bad,same));
    bad=in;bad.pncs_bytes++;check(!pb::security_input(bad,same));
    check(pb::security_input(in,same));check(pb::same_security(original,same));
    std::printf("MATCHEDCAPS_SC_FAKE_CHECKS %u\n",checks);
}
'''

ROLE_HARNESS=r'''
PB_PLAN_V1 plan(){return {48,1,1000,10000,130000,125000,95000};}
pb::Machine machine(){pb::Machine m;check(m.initialize(plan())==pb::ok);m.bound=true;m.bind_verified=true;
    check(m.begin_environment()==pb::ok);check(m.environment_result(0,true)==pb::ok);return m;}
PB_PI_V1 pi(){return {71,72,73,74};}
int main(){
    for(unsigned role=0;role<3;++role)for(unsigned policy=0;policy<3;++policy)for(bool security:{false,true}){
        auto m=machine();
        const bool valid=role==0 && policy==0 && !security;
        check((m.begin_arm(role,policy,true,security)==pb::ok)==valid);
    }
    auto m=machine();
    check(m.begin_arm(0,0,false,false)==pb::bad_state);
    check(m.begin_arm(0,0,true,false)==pb::ok);
    check(m.begin_arm(1,0,true,true)==pb::bad_state); // No unreturned prior call.
    check(m.arm_result(true,pi())==pb::ok);
    check(m.begin_arm(1,1,true,true)==pb::bad_state);
    check(m.begin_arm(1,0,true,false)==pb::bad_state);
    check(m.begin_arm(1,0,true,true)==pb::ok);check(m.arm_result(true,pi())==pb::ok);
    check(m.begin_arm(2,0,true,true)==pb::bad_state);
    check(m.begin_arm(2,1,true,false)==pb::bad_state);
    check(m.begin_arm(2,1,true,true)==pb::ok);check(m.arm_result(true,pi())==pb::ok);
    check(m.arm_attempts==3 && m.arm_returns==3);
    check(m.begin_arm(3,1,true,true)==pb::bad_state);
    check(m.begin_close(false)==pb::bad_state);check(m.begin_close(true)==pb::ok);
    check(!m.can_unbind());check(m.begin_close(true)==pb::bad_state);m.end_close();check(m.can_unbind());
    for(unsigned bad_pi=0;bad_pi<5;++bad_pi){
        auto f=machine();check(f.begin_arm(0,0,true,false)==pb::ok);auto value=pi();
        if(bad_pi==0)value.process=0;
        if(bad_pi==1)value.thread=0;
        if(bad_pi==2)value.process_id=0;
        if(bad_pi==3)value.thread_id=0;
        if(bad_pi==4)value.thread=value.process;
        check(f.arm_result(true,value)==pb::readback_failed);
        check(f.begin_arm(1,0,true,true)==pb::bad_state);check(f.begin_close(true)==pb::ok);
    }
    auto failed=machine();check(failed.begin_arm(0,0,true,false)==pb::ok);
    check(failed.arm_result(false,{})==pb::api_failed);check(!failed.opaque_unknown);
    check(failed.begin_arm(1,0,true,true)==pb::bad_state);
    auto precreate=machine();check(precreate.begin_arm(0,0,true,false)==pb::ok);
    check(precreate.precreate_result({})==pb::precreate_failed);
    check(precreate.arm_failure && precreate.arm_attempts==1 && precreate.arm_returns==1);
    check(precreate.begin_arm(1,0,true,true)==pb::bad_state);
    check(precreate.begin_close(true)==pb::ok);
    auto partial=machine();check(partial.begin_arm(0,0,true,false)==pb::ok);
    check(partial.precreate_result(pi())==pb::bad_state);
    check(partial.arm_returns==0);check(partial.begin_close(true)==pb::bad_state);
    check(pb::timely(plan(),1000,94999)==pb::ok);check(pb::timely(plan(),1000,95000)==pb::deadline);
    check(pb::timely(plan(),1001,94999)==pb::clock);
    std::printf("MATCHEDCAPS_ROLE_FAKE_CHECKS %u\n",checks);
}
'''


class MatchedCapabilitiesNativeTests(unittest.TestCase):
    def compile_fake(self,source):
        compiler=shutil.which('cl.exe' if os.name=='nt' else 'c++')
        self.assertIsNotNone(compiler,'run pure tests from an installed compiler developer shell')
        with tempfile.TemporaryDirectory() as temp:
            directory=Path(temp);cpp=directory/'fake.cpp';cpp.write_bytes(source.encode())
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
            return result.stdout

    def test_compiled_fixed_catalog_lengths_order_attributes_and_owned_copy(self):
        output=self.compile_fake(fixture_header()+SC_HARNESS)
        self.assertGreater(int(output.split()[-1]),90)
        print(output.strip())

    def test_compiled_three_roles_once_only_partial_failure_and_original_clock(self):
        output=self.compile_fake(fixture_header()+ROLE_HARNESS)
        self.assertGreater(int(output.split()[-1]),90)
        print(output.strip())

    def test_abi_layout_and_create_has_no_resume_assignment_or_joblist_fallback(self):
        class SC(C.Structure):
            _fields_=[(x,C.c_uint32) for x in ('size','version','capability_count','reserved')]+sum(
                ([(x,C.c_void_p),(x.removesuffix('_sid')+'_bytes',C.c_uint32),(suffix,C.c_uint32)]
                 for x,suffix in (('package_sid','reserved2'),('agentic_sid','agentic_attributes'),('pncs_sid','pncs_attributes'))),[])
        self.assertEqual(C.sizeof(SC),64);self.assertEqual(C.alignment(SC),8)
        self.assertEqual([getattr(SC,x).offset for x in ('package_sid','agentic_sid','pncs_sid')],[16,32,48])
        cpp=(NATIVE/'windows_psec_lpac_matchedcaps_bridge.cpp').read_text()
        self.assertIn('pb_abi_version() noexcept { return 3; }',cpp)
        self.assertNotIn('pb_create_arm(',cpp)
        self.assertIn('pb_create_matched_child(',cpp)
        self.assertNotIn('ResumeThread(',cpp);self.assertNotIn('AssignProcessToJobObject(',cpp)
        self.assertNotIn('PROC_THREAD_ATTRIBUTE_JOB_LIST',cpp)
        self.assertIn('attrs.init(role==pb::bootstrap?2u:3u,attribute_error)',cpp)
        self.assertEqual(cpp.count('return precreate_failure(*c,*output,r,'),2)
        self.assertIn('const auto sampled=tick(c,r->after_qpc)',cpp)
        self.assertIn('c->security=candidate_security',cpp)
        self.assertIn('pb::same_security(c->security,candidate_security)',cpp)
        self.assertLess(cpp.index('c->security=candidate_security'),cpp.index('SECURITY_CAPABILITIES security{}'))
        self.assertIn('static_assert(sizeof(Internal)<=sizeof(PB_CONTEXT_V1))',cpp)


if __name__=='__main__':unittest.main()
