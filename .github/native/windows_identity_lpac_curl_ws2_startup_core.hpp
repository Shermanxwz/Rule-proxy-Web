#pragma once
// Portable production semantics only. No Windows API/loader/provider calls.
// Windows bodies must obtain the calling thread's trivial TLS ErrorSlot and
// use an SEH-protected bounded output writer. This core does not prove that
// adapter, Config, shared trace, input pointer or actual module identity.
#include "windows_identity_lpac_curl_ws2_startup_abi.hpp"
#include <atomic>
#include <cstring>
namespace a4startup {
constexpr int socket_error=-1,not_initialized=10093,version_not_supported=10092;
constexpr int bad_pointer=10014,process_limit=10067,operation_unsupported=10045;
enum Sticky:u32 {unsupported=1,output_fault=2,reference_unknown=4,capacity_exceeded=8};
struct ErrorSlot {int value=0;};
struct StartupData408 {
 u16 version,high_version,max_sockets,max_udp;u64 vendor_info;
 char description[257],system_status[129];std::uint8_t padding[6];
};
static_assert(sizeof(StartupData408)==408&&offsetof(StartupData408,description)==16&&offsetof(StartupData408,system_status)==273,"AMD64 WSADATA");
class Startup {
 std::atomic<u32> references_{0},sticky_{0};
public:
 u32 references()const{return references_.load();}u32 sticky()const{return sticky_.load();}
 void reject(u32 reason=unsupported){sticky_.fetch_or(reason);}
 static int get_error(const ErrorSlot& t){return t.value;}
 static void set_error(ErrorSlot& t,int value){t.value=value;}
 template<class Writer>int startup(u16 requested,ErrorSlot&,Writer& writer){
  const u32 major=requested&255u,minor=requested>>8;
  // This private diagnostic supports the single range [2.2,2.2]. A caller
  // requesting a higher maximum can negotiate2.2, but is outside fixed curl's
  // observed2.2 acceptance profile and therefore still sticky unsupported.
  if(major<2||(major==2&&minor<2)){reject();return version_not_supported;}
  if(requested!=0x0202)reject();
  if(references_.load()>=64){reject(capacity_exceeded);return process_limit;}
  StartupData408 data{};data.version=data.high_version=0x0202;
  const char description[]="Private startup diagnostic; transport unsupported";
  const char status[]="Diagnostic only";
  std::memcpy(data.description,description,sizeof(description));std::memcpy(data.system_status,status,sizeof(status));
  if(!writer(data)){reject(output_fault);return bad_pointer;}
  // Linearization follows the complete output copy. No real resource exists
  // before it. Bounded contention fails instead of waiting or wrapping.
  u32 expected=references_.load();
  for(u32 tries=0;tries<64;++tries){if(expected>=64){reject(capacity_exceeded);return process_limit;}
   if(references_.compare_exchange_weak(expected,expected+1))return 0;}
  reject(capacity_exceeded);return process_limit;
 }
 int cleanup(ErrorSlot& t){u32 expected=references_.load();
  for(u32 tries=0;tries<64;++tries){if(!expected){t.value=not_initialized;return socket_error;}
   if(references_.compare_exchange_weak(expected,expected-1))return 0;}
  reject(reference_unknown);t.value=process_limit;return socket_error;
 }
 int unsupported_call(ErrorSlot& t){reject();t.value=references_.load()?operation_unsupported:not_initialized;return socket_error;}
};
enum class InputKind:u32 {none=0,module_utf16=1,procedure_ascii=2,ordinal=3,null_value=4,wsadata408=5,configuration2048=6,payload_framing456=7,scan_summary=8,sdk_output=9};
constexpr u32 input_fault_flag=16,ordinal_input_flag=64,null_input_flag=128,capture_complete_flag=256;
inline bool capture_start(TraceCall2176& row,InputKind kind){
 if(row.input_kind||row.captured_bytes){row.raw.flags|=input_fault_flag;return false;}
 row.input_kind=static_cast<u32>(kind);return true;
}
inline bool capture_fault(TraceCall2176& row){row.raw.flags|=input_fault_flag;row.raw.flags&=~capture_complete_flag;return false;}
// Reader(addr,dst,count) must perform SEH-protected copying in future glue.
// The core never dereferences an arbitrary caller pointer or retains it as
// the only evidence. Prefix bytes already copied survive fault/overflow.
template<class Reader>bool capture_name(TraceCall2176& row,InputKind kind,u64 address,Reader& reader){
 if(kind!=InputKind::module_utf16&&kind!=InputKind::procedure_ascii)return capture_fault(row);
 if(!capture_start(row,kind)||!address)return capture_fault(row);
 const u32 width=kind==InputKind::module_utf16?2u:1u,units=width==2?1024u:65u;
 for(u32 i=0;i<units;++i){const u64 offset=static_cast<u64>(i)*width;
  if(address>~u64{0}-offset)return capture_fault(row);
  auto* out=row.name_or_WSADATA+i*width;
  if(!reader(address+offset,out,width))return capture_fault(row);
  row.captured_bytes+=width;
  if(out[0]==0&&(width==1||out[1]==0)){row.raw.flags|=capture_complete_flag;return true;}
 }
 return capture_fault(row);
}
inline bool capture_null(TraceCall2176& row){if(!capture_start(row,InputKind::null_value))return false;row.raw.flags|=null_input_flag|capture_complete_flag;return true;}
inline bool capture_ordinal(TraceCall2176& row,u32 ordinal){
 if(!capture_start(row,InputKind::ordinal)||ordinal==0||ordinal>65535)return capture_fault(row);
 row.raw.flags|=ordinal_input_flag|capture_complete_flag;return true;
}
inline bool capture_wsadata(TraceCall2176& row,const StartupData408& data,bool output_committed){
 if(!capture_start(row,InputKind::wsadata408)||!output_committed)return capture_fault(row);
 std::memcpy(row.name_or_WSADATA,&data,408);row.captured_bytes=408;row.raw.flags|=capture_complete_flag;return true;
}
inline u16 fold(u16 c){return c>='A'&&c<='Z'?static_cast<u16>(c+32):c;}
inline bool ascii_equal(const u16* s,u32 n,const char* literal){
 if(!s||n>1023)return false;u32 i=0;for(;literal[i];++i)if(i>=n||s[i]>127||fold(s[i])!=fold(static_cast<u16>(literal[i])))return false;return i==n;
}
inline bool wide_equal(const u16* s,u32 n,const u16* p,u32 count){
 if(!s||n!=count||n>1023)return false;for(u32 i=0;i<n;++i)if(s[i]>127||p[i]>127||fold(s[i])!=fold(p[i]))return false;return true;
}
enum class Module:u32 {unknown=0,main_image=1,private_shim=2,kernel32=3,kernelbase=4,ntdll=5};
inline Module classify_module(const u16* s,u32 n,const Config2048& c){
 if(!s)return n==0?Module::main_image:Module::unknown;
 if(!n||n>1023)return Module::unknown;
 if(ascii_equal(s,n,"WS2_32.dll")||ascii_equal(s,n,"windows_identity_lpac_curl_ws2_shim.dll")
  ||ascii_equal(s,n,"api-ms-win-core-libraryloader-l1-2-0.dll")
  ||(c.system_ws2_chars<260&&wide_equal(s,n,c.system_ws2_path,c.system_ws2_chars)))return Module::private_shim;
 if(c.private_path_bytes&&c.private_path_bytes<1024){bool same=n==c.private_path_bytes;
  for(u32 i=0;same&&i<n;++i)if(s[i]>127||fold(s[i])!=fold(static_cast<unsigned char>(c.private_path[i])))same=false;
  if(same)return Module::private_shim;}
 if(ascii_equal(s,n,"kernel32")||ascii_equal(s,n,"kernel32.dll"))return Module::kernel32;
 if(ascii_equal(s,n,"kernelbase")||ascii_equal(s,n,"kernelbase.dll"))return Module::kernelbase;
 if(ascii_equal(s,n,"ntdll")||ascii_equal(s,n,"ntdll.dll"))return Module::ntdll;
 return Module::unknown;
}
struct Symbol {const char* name;u32 ordinal;};
constexpr Symbol ws2_symbols[]={
 {"accept",1},{"bind",2},{"closesocket",3},{"connect",4},{"getpeername",5},{"getsockname",6},{"getsockopt",7},
 {"htonl",8},{"htons",9},{"ioctlsocket",10},{"listen",13},{"ntohs",15},{"recv",16},{"recvfrom",17},{"select",18},
 {"send",19},{"sendto",20},{"setsockopt",21},{"shutdown",22},{"socket",23},{"WSACloseEvent",45},{"WSACreateEvent",50},
 {"gethostname",57},{"WSAEnumNetworkEvents",64},{"WSAEventSelect",67},{"WSAIoctl",78},{"WSAResetEvent",95},
 {"WSAGetLastError",111},{"WSASetLastError",112},{"WSAStartup",115},{"WSACleanup",116},{"WSAWaitForMultipleEvents",124},
 {"__WSAFDIsSet",151},{"freeaddrinfo",191},{"getaddrinfo",192}};
inline bool exact(const char* s,u32 n,const char* p){if(!s||n>64)return false;u32 i=0;for(;p[i];++i)if(i>=n||s[i]!=p[i])return false;return i==n;}
enum class ResolutionKind:u32 {unsupported=0,private_export=1,system_filename=2,ntdll_version=3};
struct Resolution {ResolutionKind kind;u32 ordinal;};
inline Resolution resolve(Module module,const char* symbol,u32 n,u32 ordinal=0){
 if(module==Module::private_shim){
  for(const auto& v:ws2_symbols)if((!symbol&&n==0&&ordinal==v.ordinal)||(symbol&&ordinal==0&&exact(symbol,n,v.name)))return {ResolutionKind::private_export,v.ordinal};
 }
 if(ordinal||!symbol)return {ResolutionKind::unsupported,0};
 if(module==Module::private_shim||module==Module::kernel32||module==Module::kernelbase){
  const char* names[]={"GetProcAddress","GetModuleHandleW","LoadLibraryExW","FreeLibrary"};
  for(u32 i=0;i<4;++i)if(exact(symbol,n,names[i]))return {ResolutionKind::private_export,200+i};
  if(exact(symbol,n,"GetModuleFileNameA"))return {ResolutionKind::system_filename,204};
 }
 if(module==Module::ntdll&&exact(symbol,n,"RtlVerifyVersionInfo"))return {ResolutionKind::ntdll_version,0};
 return {ResolutionKind::unsupported,0};
}
// Classification is not module ownership. Future glue must first bind the
// actual HMODULE to source-reviewed retained identity; no numeric self-report
// or arbitrary module value is authorized by the enum passed to resolve().
inline bool load_allowed(Module module,u64 file,u32 flags){return module==Module::private_shim&&file==0&&(flags==0||flags==0x800);}
}
