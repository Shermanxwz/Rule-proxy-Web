// Compile/run only by a separately authorized caller. No Win32 header/API.
#include "../.github/native/windows_identity_lpac_curl_ws2_startup_core.hpp"
#include <cstdlib>
#include <iostream>
using namespace a4startup;
static u32 checks=0;static void check(bool x){++checks;if(!x)std::abort();}
struct Writer {bool ok=true;u32 calls=0;StartupData408 value{};bool operator()(const StartupData408& d){++calls;value=d;return ok;}};
static void startup_tests(){Startup state;ErrorSlot a,b;Startup::set_error(a,71);Startup::set_error(b,93);Writer out;
 check(state.startup(0x0202,a,out)==0&&state.references()==1&&out.calls==1);
 check(out.value.version==0x0202&&out.value.high_version==0x0202&&out.value.vendor_info==0&&out.value.max_sockets==0&&out.value.max_udp==0);
 check(Startup::get_error(a)==71&&Startup::get_error(b)==93);
 check(state.startup(0x0202,b,out)==0&&state.references()==2);
 check(state.cleanup(a)==0&&state.references()==1&&Startup::get_error(a)==71);
 check(state.cleanup(b)==0&&state.references()==0&&Startup::get_error(b)==93);
 check(state.cleanup(a)==socket_error&&Startup::get_error(a)==not_initialized&&state.references()==0);
 Startup::set_error(a,0);check(Startup::get_error(a)==0&&Startup::get_error(b)==93);
 Startup failed;Writer bad;bad.ok=false;check(failed.startup(0x0202,a,bad)==bad_pointer&&failed.references()==0&&(failed.sticky()&output_fault));
 Startup old;Writer unused;check(old.startup(0x0101,a,unused)==version_not_supported&&unused.calls==0&&old.references()==0);
 Startup future;Writer negotiated;check(future.startup(0x0003,a,negotiated)==0&&negotiated.value.version==0x0202&&(future.sticky()&unsupported));
 Startup bounded;Writer many;for(u32 i=0;i<64;++i)check(bounded.startup(0x0202,a,many)==0);
 const auto before=many.calls;check(bounded.startup(0x0202,a,many)==process_limit&&bounded.references()==64&&many.calls==before&&(bounded.sticky()&capacity_exceeded));
 for(u32 i=0;i<64;++i)check(bounded.cleanup(a)==0);check(bounded.references()==0);
 Startup stubs;check(stubs.unsupported_call(a)==socket_error&&a.value==not_initialized&&(stubs.sticky()&unsupported));
 Writer ready;check(stubs.startup(0x0202,a,ready)==0);check(stubs.unsupported_call(a)==socket_error&&a.value==operation_unsupported);}
static u32 text(u16* b,const char* s){u32 n=0;while(s[n]){b[n]=static_cast<unsigned char>(s[n]);++n;}b[n]=0;return n;}
static void module_tests(){Config2048 c{};const char path[]="C:\\owned\\windows_identity_lpac_curl_ws2_shim.dll";std::memcpy(c.private_path,path,sizeof(path));c.private_path_bytes=sizeof(path)-1;
 c.system_ws2_chars=text(c.system_ws2_path,"C:\\Windows\\System32\\WS2_32.dll");u16 name[1024]{};
 auto classify=[&](const char* s){const auto n=text(name,s);return classify_module(name,n,c);};
 check(classify_module(nullptr,0,c)==Module::main_image);check(classify("Ws2_32.DLL")==Module::private_shim);
 check(classify(path)==Module::private_shim&&classify("C:\\Windows\\System32\\ws2_32.dll")==Module::private_shim);
 check(classify("ntdll")==Module::ntdll&&classify("NTDLL.DLL")==Module::ntdll);
 check(classify("ws2_32.dll.evil")==Module::unknown&&classify("C:\\other\\ws2_32.dll")==Module::unknown);
 check(resolve(Module::ntdll,"RtlVerifyVersionInfo",20).kind==ResolutionKind::ntdll_version);
 check(resolve(Module::ntdll,"NtCreateFile",12).kind==ResolutionKind::unsupported);
 check(resolve(Module::private_shim,"WSAStartup",10).ordinal==115&&resolve(Module::private_shim,nullptr,0,115).ordinal==115);
 check(resolve(Module::private_shim,nullptr,0,11).kind==ResolutionKind::unsupported);
 check(resolve(Module::private_shim,nullptr,0,200).kind==ResolutionKind::unsupported);
 check(resolve(Module::kernel32,"GetProcAddress",14).ordinal==200);
 check(resolve(Module::kernel32,"socket",6).kind==ResolutionKind::unsupported);
 check(resolve(Module::private_shim,"WSAPoll",7).kind==ResolutionKind::unsupported);
 check(load_allowed(Module::private_shim,0,0)&&load_allowed(Module::private_shim,0,0x800));
 check(!load_allowed(Module::private_shim,0,2)&&!load_allowed(Module::ntdll,0,0)&&!load_allowed(Module::private_shim,1,0));}
struct Reader {const std::uint8_t* data;u32 bytes,calls=0,fail_at=0;u64 base=0x10000;
 bool operator()(u64 address,std::uint8_t* out,u32 count){++calls;if(fail_at&&calls==fail_at)return false;
  if(address<base||address-base>bytes||count>bytes-static_cast<u32>(address-base))return false;
  std::memcpy(out,data+static_cast<std::size_t>(address-base),count);return true;}};
static void capture_tests(){
 u16 module[]={u'n',u't',u'd',u'l',u'l',0};Reader wide{reinterpret_cast<const std::uint8_t*>(module),sizeof(module)};TraceCall2176 row{};
 check(capture_name(row,InputKind::module_utf16,wide.base,wide)&&row.captured_bytes==sizeof(module)&&(row.raw.flags&capture_complete_flag));
 module[0]='X';check(row.name_or_WSADATA[0]=='n');
 const char procedure[]="RtlVerifyVersionInfo";Reader ascii{reinterpret_cast<const std::uint8_t*>(procedure),sizeof(procedure)};TraceCall2176 proc{};
 check(capture_name(proc,InputKind::procedure_ascii,ascii.base,ascii)&&proc.captured_bytes==sizeof(procedure));
 TraceCall2176 ordinal{},null{};const auto calls=ascii.calls;
 check(capture_ordinal(ordinal,115)&&capture_null(null)&&ascii.calls==calls&&ordinal.captured_bytes==0&&null.captured_bytes==0);
 std::uint8_t long_name[2048];std::memset(long_name,'x',sizeof(long_name));Reader overflow{long_name,sizeof(long_name)};TraceCall2176 too_long{};
 check(!capture_name(too_long,InputKind::module_utf16,overflow.base,overflow)&&too_long.captured_bytes==2048&&(too_long.raw.flags&input_fault_flag)&&!(too_long.raw.flags&capture_complete_flag));
 Reader broken{reinterpret_cast<const std::uint8_t*>(procedure),sizeof(procedure),0,2};TraceCall2176 partial{};
 check(!capture_name(partial,InputKind::procedure_ascii,broken.base,broken)&&partial.captured_bytes==1&&partial.name_or_WSADATA[0]=='R'&&(partial.raw.flags&input_fault_flag));
 StartupData408 data{};data.version=data.high_version=0x0202;TraceCall2176 committed{},failed{};
 check(capture_wsadata(committed,data,true)&&committed.captured_bytes==408&&std::memcmp(committed.name_or_WSADATA,&data,408)==0);
 check(!capture_wsadata(failed,data,false)&&failed.captured_bytes==0&&(failed.raw.flags&input_fault_flag));
 check(!capture_null(proc)&&(proc.raw.flags&input_fault_flag)&&proc.captured_bytes==sizeof(procedure));
}
int main(){startup_tests();module_tests();capture_tests();std::cout<<"A4_STARTUP_PURE_ASSERTIONS "<<checks<<"\n";return 0;}
