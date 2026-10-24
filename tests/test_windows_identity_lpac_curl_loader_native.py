"""Portable production-core fakes. Never load a DLL or execute Win32 adapters.

This source is prepared for a separately authorized compiler run. Creating it
does not constitute running these tests, compiling Detours, or loader acceptance.
"""
from pathlib import Path
import shutil
import subprocess
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[1]
NATIVE = ROOT / '.github' / 'native'

COMMON = r'''
#include "windows_identity_lpac_curl_loader_marker_core.hpp"
#include <cstdio>
#include <cstdlib>
#include <stdexcept>
#include <vector>
unsigned checks=0;
void checked(bool value,unsigned line){++checks;if(!value){std::fprintf(stderr,"line%u\n",line);std::exit(1);}}
#define check(v) checked((v),__LINE__)
const char fixture_marker_path[]="C:\\Owned\\marker.dll";
CL_PLAN256 plan(){CL_PLAN256 p{};p.size=256;p.version=1;p.frequency=100;p.root_start_qpc=1000;p.root_deadline_qpc=13000;
 p.window_start_qpc=1100;p.window_end_qpc=1900;p.target_pid=42;p.target_creation_FILETIME=133000000000000000ull;
 p.borrowed_held_process_handle=0x48;p.caller_owned_ASCII_marker_path_pointer=reinterpret_cast<std::uintptr_t>(fixture_marker_path);
 p.marker_path_bytes_excluding_NUL=sizeof(fixture_marker_path)-1;std::memset(p.run,1,16);std::memset(p.config_sha256,2,32);
 std::memset(p.source_sha256,3,32);std::memset(p.target_image_sha256,4,32);std::memset(p.marker_image_sha256,5,32);
 std::memcpy(p.marker_payload_GUID_Windows_bytes,cl::payload_guid,16);return p;}
CL_MARKER256 marker(const CL_PLAN256& p){CL_MARKER256 m{};std::memcpy(m.magic,"CLM1",4);m.version=1;m.size=256;
 std::memcpy(m.run,p.run,16);std::memcpy(m.config_sha256,p.config_sha256,32);std::memcpy(m.source_sha256,p.source_sha256,32);
 std::memcpy(m.marker_image_sha256,p.marker_image_sha256,32);m.frequency=p.frequency;m.root_start_qpc=p.root_start_qpc;
 m.root_deadline_qpc=p.root_deadline_qpc;m.window_start_qpc=p.window_start_qpc;m.window_end_qpc=p.window_end_qpc;
 m.target_pid=p.target_pid;m.target_creation_FILETIME=p.target_creation_FILETIME;m.inherited_enter_event_signal_only=0x50;
 m.inherited_body_event_signal_only=0x54;m.status_size=64;m.status_version=1;return m;}
'''

WRAPPER = COMMON + r'''
struct Fake {
 cl::u64 tick=1200;unsigned clocks=0,helds=0,updates=0,copies=0,reads=0;
 unsigned clock_fail=0,held_throw=0,advance_held=0,read_throw=0;bool update_throw=false,copy_throw=false;
 bool alive=true,exited=false;cl::BoolReturn update_value{1,0};cl::CopyReturn copy_value{0x1000,0};
 std::vector<cl::ReadReturn> read_values;std::vector<CL_MARKER256> read_markers;
 cl::u64 generation(){return 1;}
 bool clock(cl::u64 f,cl::u64& out){check(f==100);++clocks;if(clocks==clock_fail)return false;out=tick++;return true;}
 cl::HeldReturn held(const CL_PLAN256& p){check(p.target_pid==42&&p.target_creation_FILETIME==133000000000000000ull);++helds;
  if(helds==held_throw)throw std::runtime_error("held");if(helds==advance_held)tick+=800;return {true,alive,exited};}
 cl::BoolReturn update(cl::u64 h,const char* text){check(h==0x48&&std::strcmp(text,fixture_marker_path)==0);++updates;
  if(update_throw)throw std::runtime_error("update");return update_value;}
 cl::CopyReturn copy(cl::u64 h,const CL_MARKER256& m){check(h==0x48&&m.target_pid==42);++copies;
  if(copy_throw)throw std::runtime_error("copy");return copy_value;}
 cl::ReadReturn read(cl::u64 h,cl::u64 remote,void* out,std::size_t n){check(h==0x48&&remote==0x1000&&n==256);++reads;
  if(reads==read_throw)throw std::runtime_error("read");const std::size_t i=reads-1;
  const auto value=i<read_values.size()?read_values[i]:cl::ReadReturn{1,0,256};
  if(value.value){const auto m=i<read_markers.size()?read_markers[i]:marker(plan());std::memcpy(out,&m,value.bytes<256?value.bytes:256);}
  return value;}
};
struct Rig {
 Fake api;CL_PLAN256 p=plan();CL_CONTEXT c{};CL_RESULT128 r{};CL_MARKER256 m=marker(p),out{};
 Rig(){check(cl::begin(api,&p,&c,&r)==cl::bound);check(r.operation==1&&r.local_context_generation==1&&r.validation_passed);}
 void updated(){check(cl::update(api,&c,&r)==cl::updated);check(r.result_class==11&&r.update_returned&&r.raw_update_BOOL==1&&!r.copy_entered);}
 void prepared(){updated();check(cl::install(api,&c,&m,&r)==cl::prepared);check(r.operation==3&&r.copy_returned&&r.copy_nonnull&&r.within_original_window);}
};
int main(){
 check(sizeof(CL_PLAN256)==256&&sizeof(CL_MARKER256)==256&&sizeof(CL_RESULT128)==128&&sizeof(CL_CONTEXT)==2048);
 check(offsetof(CL_MARKER256,even_stable_status_sequence)==248&&offsetof(CL_RESULT128,read_GetLastError)==108);
 {Fake a;auto p=plan();CL_CONTEXT c{};CL_RESULT128 r{};p.reserved0=1;check(cl::begin(a,&p,&c,&r)==1&&a.updates==0&&a.helds==0);}
 {Fake a;auto p=plan();CL_CONTEXT c{};CL_RESULT128 r{};p.window_end_qpc++;check(cl::begin(a,&p,&c,&r)==1&&!cl::nonzero(&c,sizeof(c)));}
 {Fake a;auto p=plan();CL_CONTEXT c{};check(cl::begin(a,&p,&c,reinterpret_cast<CL_RESULT128*>(&c))==1&&a.helds==0);}
 {Rig x;check(cl::begin(x.api,&x.p,&x.c,&x.r)==1&&x.api.updates==0);}
 {Rig x;x.api.update_value={0,0};check(cl::update(x.api,&x.c,&x.r)==2&&x.r.update_returned&&x.r.update_error_valid&&x.r.update_GetLastError==0);
  check(x.r.remote_mutation_possible&&x.r.remote_outcome_unknown&&cl::install(x.api,&x.c,&x.m,&x.r)==1&&x.api.copies==0);
  check(cl::update(x.api,&x.c,&x.r)==1&&x.api.updates==1);}
 {Rig x;x.updated();x.api.copy_value={0,0};check(cl::install(x.api,&x.c,&x.m,&x.r)==3&&x.r.copy_returned&&x.r.copy_error_valid&&x.r.copy_GetLastError==0);
  check(cl::install(x.api,&x.c,&x.m,&x.r)==1&&x.api.copies==1);}
 for(auto address:{cl::u64(0x1001),(std::numeric_limits<cl::u64>::max)()-7}){Rig x;x.updated();x.api.copy_value={address,55};
  check(cl::install(x.api,&x.c,&x.m,&x.r)==14&&x.r.copy_nonnull&&!x.r.copy_error_valid&&x.r.remote_outcome_unknown);}
 {Rig x;x.updated();x.m.inherited_enter_event_signal_only=x.p.borrowed_held_process_handle;check(cl::install(x.api,&x.c,&x.m,&x.r)==1&&x.api.copies==0);}
 {Rig x;x.updated();x.m.inherited_body_event_signal_only=(std::numeric_limits<cl::u64>::max)();check(cl::install(x.api,&x.c,&x.m,&x.r)==1&&x.api.copies==0);}
 {Rig x;x.api.advance_held=x.api.helds+1;check(cl::update(x.api,&x.c,&x.r)==4&&x.api.updates==0&&!x.r.update_entered);}
 {Rig x;x.api.advance_held=x.api.helds+2;check(cl::update(x.api,&x.c,&x.r)==4&&x.api.updates==1&&x.r.update_returned&&x.r.raw_update_BOOL==1&&!x.r.within_original_window);}
 {Rig x;x.api.update_throw=true;try{cl::update(x.api,&x.c,&x.r);check(false);}catch(...){check(cl::caught(&x.c,&x.r,2,99)==8);}
  check(x.r.update_entered&&!x.r.update_returned&&x.r.remote_mutation_possible&&x.r.remote_outcome_unknown);check(cl::update(x.api,&x.c,&x.r)==1&&x.api.updates==1);}
 {Rig x;x.prepared();x.api.read_values={{0,0,0}};check(cl::read(x.api,&x.c,&x.out,&x.r)==12&&x.api.reads==1&&x.r.marker_read_returned&&x.r.read_GetLastError==0&&!x.r.marker_read_exact256);}
 {Rig x;x.prepared();x.api.read_values={{1,0,256},{0,5,0}};check(cl::read(x.api,&x.c,&x.out,&x.r)==13&&x.api.reads==2&&x.r.read_GetLastError==5&&!x.r.coherent_snapshot);}
 {Rig x;x.prepared();x.api.read_values={{1,0,255}};check(cl::read(x.api,&x.c,&x.out,&x.r)==6&&x.api.reads==1&&x.r.marker_read_returned&&!x.r.marker_read_exact256);}
 {Rig x;x.prepared();x.api.read_values={{1,0,256},{1,0,255}};check(cl::read(x.api,&x.c,&x.out,&x.r)==6&&x.api.reads==2&&!x.r.marker_read_exact256);}
 {Rig x;x.prepared();auto wrong=x.m;wrong.run[0]^=1;x.api.read_markers={x.m,wrong};check(cl::read(x.api,&x.c,&x.out,&x.r)==6&&x.r.marker_read_exact256&&!x.r.coherent_snapshot);}
 {Rig x;x.prepared();auto odd=x.m;odd.even_stable_status_sequence=1;x.api.read_markers={odd,odd};check(cl::read(x.api,&x.c,&x.out,&x.r)==6);}
 {Rig x;x.prepared();auto bad=x.m;bad.progress_flags=0x4000;bad.writer_target_pid=42;x.api.read_markers={bad,bad};check(cl::read(x.api,&x.c,&x.out,&x.r)==6);}
 {Rig x;x.prepared();for(unsigned i=0;i<4;++i)check(cl::read(x.api,&x.c,&x.out,&x.r)==7&&x.r.coherent_snapshot&&x.r.marker_read_exact256);
  check(x.api.reads==8&&cl::read(x.api,&x.c,&x.out,&x.r)==1&&x.api.reads==8);}
 for(unsigned second=0;second<2;++second){Rig x;x.prepared();x.api.read_values=second?std::vector<cl::ReadReturn>{{1,0,256},{0,0,0}}:std::vector<cl::ReadReturn>{{0,0,0}};
  x.api.held_throw=x.api.helds+2;try{cl::read(x.api,&x.c,&x.out,&x.r);check(false);}catch(...){check(cl::caught(&x.c,&x.r,4,77)==(second?13u:12u));}
  check(x.r.marker_read_entered&&x.r.marker_read_returned&&x.r.read_GetLastError==0&&!x.r.within_original_window&&!x.r.return_clock_known&&x.r.caught_exception_code_or_zero==77);}
 {Rig x;x.prepared();x.api.read_values={{0,0,0}};x.api.advance_held=x.api.helds+2;check(cl::read(x.api,&x.c,&x.out,&x.r)==12&&x.r.marker_read_returned&&!x.r.within_original_window);}
 {Rig x;x.prepared();x.api.read_throw=2;try{cl::read(x.api,&x.c,&x.out,&x.r);check(false);}catch(...){check(cl::caught(&x.c,&x.r,4,88)==8);}
  check(x.api.reads==2&&x.r.marker_read_entered&&!x.r.marker_read_returned&&!x.r.coherent_snapshot);}
 {Rig x;x.prepared();x.api.alive=false;x.api.exited=true;x.api.tick=2000;check(cl::forget(x.api,&x.c,&x.r)==10&&!x.r.within_original_window&&!cl::nonzero(&x.c,sizeof(x.c)));
  check(x.r.remote_mutation_possible&&!x.r.remote_outcome_unknown);}
 {Rig x;check(cl::forget(x.api,&x.c,&x.r)==1&&cl::nonzero(&x.c,sizeof(x.c)));}
 std::printf("CL_WRAPPER_PORTABLE_ASSERTIONS %u\n",checks);return 0;
}
'''

MARKER = COMMON + r'''
struct Fake {
 CL_MARKER256 value=marker(plan());CL_MARKER256* address=&value;std::size_t extent=256;cl::u64 tick=1200;
 unsigned finds=0,identities=0,clocks=0,clears=0,events=0,restores=0,clock_fail=0,clear_fail=0,event_fail=0;
 bool wrong_identity=false,restore_false=false,restore_throw=false,body_signalled=false;
 void permitted(){check(!body_signalled);}
 cl::Payload find(){permitted();++finds;return {address,extent};}
 cl::Identity identity(){permitted();++identities;return {wrong_identity?43u:42u,133000000000000000ull,true};}
 bool clock(cl::u64 f,cl::u64& out){permitted();check(f==100);++clocks;if(clocks==clock_fail)return false;out=tick++;return true;}
 cl::BoolReturn clear_inherit(cl::u64 handle){permitted();check(handle==(clears?0x54u:0x50u));++clears;return {clears==clear_fail?0:1,0};}
 cl::BoolReturn set_event(cl::u64 handle){permitted();++events;check(handle==(events==1?0x50u:0x54u));const bool ok=events!=event_fail;
  if(events==2&&ok)body_signalled=true;return {ok?1:0,0};}
 cl::BoolReturn restore(){permitted();++restores;if(restore_throw)throw std::runtime_error("restore");return {restore_false?0:1,0};}
 void sequence_increment(cl::u64& n){check(&n==&value.even_stable_status_sequence);++n;}
};
int main(){
 {Fake x;CL_MARKER256* touched=nullptr;check(cl::marker_attach(x,&touched)&&touched==&x.value);
  check(x.finds==1&&x.identities==1&&x.clears==2&&x.events==2&&x.restores==1&&x.clocks==4&&x.body_signalled);
  check(x.value.failure_stage==0&&x.value.raw_restore_BOOL==1&&x.value.raw_SetEvent_entered_BOOL==1&&x.value.raw_SetEvent_body_BOOL==1);
  check((x.value.progress_flags&0x7ffu)==0x7ffu&&(x.value.progress_flags&cl::clock_known)&&!(x.value.even_stable_status_sequence&1u));}
 for(unsigned kind=0;kind<5;++kind){Fake x;CL_MARKER256* touched=nullptr;
  if(kind==0)x.extent=255;if(kind==1)x.address=reinterpret_cast<CL_MARKER256*>(reinterpret_cast<std::uintptr_t>(&x.value)+1);
  if(kind==2)x.value.reserved0=1;if(kind==3)x.value.inherited_body_event_signal_only=x.value.inherited_enter_event_signal_only;
  if(kind==4)x.value.progress_flags=1;check(!cl::marker_attach(x,&touched)&&touched==nullptr&&x.events==0&&x.restores==0);}
 {Fake x;x.wrong_identity=true;CL_MARKER256* t=nullptr;check(!cl::marker_attach(x,&t)&&t==&x.value&&x.value.failure_stage==3&&x.events==0&&x.clears==0);}
 {Fake x;x.clock_fail=1;CL_MARKER256* t=nullptr;check(!cl::marker_attach(x,&t)&&x.value.failure_stage==4&&x.events==0&&x.clears==0);}
 {Fake x;x.tick=1900;CL_MARKER256* t=nullptr;check(!cl::marker_attach(x,&t)&&x.value.failure_stage==4&&x.events==0);}
 for(unsigned n=1;n<=2;++n){Fake x;x.clear_fail=n;CL_MARKER256* t=nullptr;check(!cl::marker_attach(x,&t)&&x.value.failure_stage==n+4&&x.events==0&&x.restores==0);
  check((x.value.progress_flags&cl::aux_error_valid)&&x.value.auxiliary_GetLastError==0&&x.clears==n);}
 {Fake x;x.event_fail=1;CL_MARKER256* t=nullptr;check(!cl::marker_attach(x,&t)&&x.events==1&&x.restores==0&&x.value.failure_stage==7&&x.value.entered_GetLastError==0);
  check((x.value.progress_flags&cl::entered_attempt)&&!(x.value.progress_flags&cl::entered_success));}
 {Fake x;x.restore_false=true;CL_MARKER256* t=nullptr;check(!cl::marker_attach(x,&t)&&x.events==1&&x.restores==1&&x.value.failure_stage==8&&x.value.restore_GetLastError==0);
  check((x.value.progress_flags&cl::restore_returned)&&!(x.value.progress_flags&cl::restore_true)&&!(x.value.progress_flags&cl::body_attempt));}
 {Fake x;x.clock_fail=4;CL_MARKER256* t=nullptr;check(!cl::marker_attach(x,&t)&&x.events==1&&x.restores==1&&x.value.failure_stage==4&&!(x.value.progress_flags&cl::body_attempt));}
 {Fake x;x.event_fail=2;CL_MARKER256* t=nullptr;check(!cl::marker_attach(x,&t)&&x.events==2&&x.restores==1&&x.value.failure_stage==9&&x.value.body_GetLastError==0);
  check((x.value.progress_flags&cl::body_attempt)&&!(x.value.progress_flags&cl::body_success)&&!(x.value.progress_flags&cl::pre_return_true));}
 {Fake x;x.restore_throw=true;CL_MARKER256* t=nullptr;try{cl::marker_attach(x,&t);check(false);}catch(...){check(!cl::marker_caught(x,t));}
  check(x.events==1&&x.restores==1&&x.value.failure_stage==10&&(x.value.progress_flags&cl::exception_flag));
  check((x.value.progress_flags&cl::restore_attempt)&&!(x.value.progress_flags&cl::restore_returned)&&!(x.value.progress_flags&cl::body_success));}
 std::printf("CL_MARKER_PORTABLE_ASSERTIONS %u\n",checks);return 0;
}
'''


def compile_and_run(source):
    compiler = shutil.which('cl') or shutil.which('c++') or shutil.which('g++')
    if compiler is None:
        raise RuntimeError('portable C++ compiler required; no test skip')
    with tempfile.TemporaryDirectory(prefix='cl-loader-pure-') as directory:
        root = Path(directory).resolve()
        cpp = root / 'test.cpp'
        cpp.write_text(source, encoding='utf-8', newline='\n')
        exe = root / ('test.exe' if Path(compiler).name.lower() in {'cl', 'cl.exe'} else 'test')
        if Path(compiler).name.lower() in {'cl', 'cl.exe'}:
            command = [compiler, '/nologo', '/std:c++17', '/EHsc', '/W4', '/WX', '/I' + str(NATIVE), str(cpp), '/Fe:' + str(exe)]
        else:
            command = [compiler, '-std=c++17', '-Wall', '-Wextra', '-Werror', '-I', str(NATIVE), str(cpp), '-o', str(exe)]
        # Keep compiler diagnostics as raw bytes: Windows compiler output can
        # use a different code page from Python's default text decoder.
        result = subprocess.run(command, cwd=root, capture_output=True, timeout=60)
        if result.returncode:
            raise AssertionError(f'compiler returncode={result.returncode} stdout={result.stdout!r} stderr={result.stderr!r}')
        result = subprocess.run([str(exe)], cwd=root, capture_output=True, timeout=15)
        if result.returncode:
            raise AssertionError(f'harness returncode={result.returncode} stdout={result.stdout!r} stderr={result.stderr!r}')
        try:
            return result.stdout.decode('ascii', 'strict')
        except UnicodeDecodeError as error:
            raise AssertionError(f'harness non-ASCII stdout={result.stdout!r} stderr={result.stderr!r}') from error


class NativeCoreTests(unittest.TestCase):
    def test_wrapper_production_policy_fakes(self):
        self.assertRegex(compile_and_run(WRAPPER), r'CL_WRAPPER_PORTABLE_ASSERTIONS [1-9][0-9]*')

    def test_marker_production_path_fakes(self):
        self.assertRegex(compile_and_run(MARKER), r'CL_MARKER_PORTABLE_ASSERTIONS [1-9][0-9]*')


if __name__ == '__main__':
    unittest.main()
