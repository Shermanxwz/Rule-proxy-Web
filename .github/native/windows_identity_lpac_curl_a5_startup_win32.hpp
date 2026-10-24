#pragma once
// SOURCE ONLY. No author compilation or API execution. All raw SDK returns are
// copied before post-QPC; only an unknown returned endpoint may then be filled.
// No real WS2/provider calls, vendor unbounded finder, network or retry path.
#include "windows_identity_lpac_curl_a5_startup_shim.hpp"
#include "windows_identity_lpac_curl_a5_startup_find.hpp"
#include "windows_identity_lpac_curl_a5_startup_refs.hpp"
#include <atomic>
#include <cstring>
namespace a5startup { namespace win {
inline u64 number(const void* p){return static_cast<u64>(reinterpret_cast<std::uintptr_t>(p));}
inline HANDLE handle(u64 p){return reinterpret_cast<HANDLE>(static_cast<std::uintptr_t>(p));}
inline HMODULE module(u64 p){return reinterpret_cast<HMODULE>(static_cast<std::uintptr_t>(p));}
// Kept outside C++ objects/destructors to avoid SEH/C++ unwind C2712.
__declspec(noinline) inline bool guarded_copy(void* dst,const void* src,std::size_t n){
 __try {std::memcpy(dst,src,n);return true;} __except(EXCEPTION_EXECUTE_HANDLER){return false;}
}
struct MemoryReader {bool operator()(u64 from,void* out,u32 n)const{return guarded_copy(out,reinterpret_cast<const void*>(static_cast<std::uintptr_t>(from)),n);}};
struct SdkCall {u32 op;u64 a,b,c;void* out;u32 bytes;};
// Only closed operations. caller strings never enter this switch: paths/names
// are immutable owned literals/config captures prepared by the caller.
__declspec(noinline) inline void invoke_sdk(const SdkCall& in,SdkReceipt32& raw){
 raw.flags|=sdk_entered;SetLastError(0);
 __try {
  switch(in.op){
  case 300:raw.raw_return=QueryPerformanceFrequency(static_cast<LARGE_INTEGER*>(in.out));break;
  case 304:raw.raw_return=GetCurrentProcessId();break;
  case 305:{auto* t=static_cast<FILETIME*>(in.out);raw.raw_return=GetProcessTimes(GetCurrentProcess(),t,t+1,t+2,t+3);break;}
  case 306:case 308:raw.raw_return=GetHandleInformation(handle(in.a),static_cast<DWORD*>(in.out));break;
  case 307:raw.raw_return=SetHandleInformation(handle(in.a),HANDLE_FLAG_INHERIT,0);break;
  case 309:raw.raw_return=static_cast<std::int64_t>(number(MapViewOfFile(handle(in.a),FILE_MAP_WRITE,0,0,trace_bytes)));break;
  case 310:raw.raw_return=CloseHandle(handle(in.a));break;
  case 311:case 313:case 315:case 317:case 320:raw.raw_return=GetModuleFileNameW(module(in.a),static_cast<LPWSTR>(in.out),in.bytes/2);break;
  case 312:case 314:case 316:case 321:raw.raw_return=static_cast<std::int64_t>(number(GetModuleHandleW(reinterpret_cast<LPCWSTR>(static_cast<std::uintptr_t>(in.a)))));break;
  case 318:case 319:raw.raw_return=static_cast<std::int64_t>(number(reinterpret_cast<const void*>(GetProcAddress(module(in.a),reinterpret_cast<LPCSTR>(static_cast<std::uintptr_t>(in.b))))));break;
  case 322:raw.raw_return=GetSystemDirectoryW(static_cast<LPWSTR>(in.out),in.bytes/2);break;
   case 330:raw.raw_return=static_cast<std::int64_t>(number(CreateEventExW(nullptr,nullptr,CREATE_EVENT_MANUAL_RESET,SYNCHRONIZE|EVENT_MODIFY_STATE)));break;
   case 331:raw.raw_return=SetEvent(handle(in.a));break;
   case 332:raw.raw_return=ResetEvent(handle(in.a));break;
   case 333:raw.raw_return=WaitForSingleObject(handle(in.a),0);break;
   case 334:raw.raw_return=CloseHandle(handle(in.a));break;
  // Primary acquisition/release lives only in its export row.sdk. No second
  // internal row repeats these invocations or invents another reference.
  case 202:raw.raw_return=static_cast<std::int64_t>(number(LoadLibraryExW(reinterpret_cast<LPCWSTR>(static_cast<std::uintptr_t>(in.a)),nullptr,static_cast<DWORD>(in.c))));break;
  case 203:raw.raw_return=FreeLibrary(module(in.a));break;
  default:raw.raw_return=0;raw.error=ERROR_INVALID_PARAMETER;raw.flags|=sdk_exception;return;
  }
  // Preserve even FALSE/error0 and nonnull success followed by a late clock.
  raw.error=static_cast<std::int32_t>(GetLastError());raw.flags|=sdk_returned|sdk_error_captured;
 } __except(EXCEPTION_EXECUTE_HANDLER){raw.flags|=sdk_exception;}
}
struct Call {TraceCall2176 row{};LONG slot=-1;bool allowed=false,committed=false,can_trace=false;};
struct ScanSummary {u64 first,last,allocation,payload,framing_bytes;u32 regions,candidates,records,found,region_cap,candidate_cap,record_cap,reserved;};
static_assert(sizeof(ScanSummary)==72,"bounded scanner summary");
class Runtime {
 std::atomic<int> state_{0};std::atomic<u32> sticky_{0},bootstrap_thread_{0};std::atomic<u64> last_{0};
 Trace557312* trace_=nullptr;std::atomic<Trace557312*> published_{nullptr};Config2048 config_{};u64 frequency_=0;bool configured_=false,trace_handle_consumed_=false;
 TraceCall2176 pending_[32]{};u32 pending_count_=0;
 HMODULE self_=nullptr,kernel32_=nullptr,kernelbase_=nullptr,ntdll_=nullptr,main_=nullptr;
 FARPROC filename_=nullptr,version_=nullptr;PrivateReferences references_;std::atomic_flag reference_lock_=ATOMIC_FLAG_INIT;
 Startup startup_;
 // Default sequentially-consistent atomics close both publication orders.
 // A competing initializer never reads the unpublished plain trace_ member.
 void sticky_header(u32 bits){sticky_.fetch_or(bits);auto* p=published_.load();
  if(p)InterlockedOr(reinterpret_cast<volatile LONG*>(&p->header.state_flags),static_cast<LONG>(bits));}
 bool endpoint(u64& out,bool authority=true){
  LARGE_INTEGER q{};if(!QueryPerformanceCounter(&q)||q.QuadPart<=0){sticky_header(clock_failure);return false;}
  const u64 tick=static_cast<u64>(q.QuadPart);u64 expected=last_.load();
  for(u32 tries=0;tries<64;++tries){if(tick<expected){sticky_header(clock_failure);return false;}
   if(last_.compare_exchange_weak(expected,tick)){out=tick;
    if(authority&&configured_&&(tick<config_.window_start||tick>=config_.window_end)){sticky_header(clock_failure);return false;}return true;}}
  sticky_header(clock_failure);return false;
 }
 LONG claim(){
  if(!trace_)return -1;
  volatile LONG* p=reinterpret_cast<volatile LONG*>(&trace_->header.claimed);LONG n=*p;
  for(u32 tries=0;tries<64;++tries){if(n<0||n>=static_cast<LONG>(trace_capacity)){InterlockedExchange(reinterpret_cast<volatile LONG*>(&trace_->header.overflow),1);sticky_header(trace_failure);return -1;}
   const LONG seen=InterlockedCompareExchange(p,n+1,n);if(seen==n)return n;n=seen;}
  sticky_header(trace_failure);return -1;
 }
 bool save(Call& call,bool complete){
  if(call.committed||!call.can_trace)return false;
  if(!trace_)return true; // before a view exists, caller retains its local POD
  if(call.slot<0)call.slot=claim();if(call.slot<0)return false;
  call.row.raw.sequence=static_cast<u64>(call.slot)*2+1;
  auto* dst=&trace_->calls[call.slot];
  if(!guarded_copy(dst,&call.row,sizeof(call.row))){sticky_header(trace_failure);return false;}
  MemoryBarrier();
  if(complete){InterlockedExchange64(reinterpret_cast<volatile LONG64*>(&dst->raw.sequence),static_cast<LONG64>(call.row.raw.sequence+1));
   InterlockedAdd64(reinterpret_cast<volatile LONG64*>(&trace_->header.sequence),2);call.committed=true;}
  return true;
 }
 bool queue(Call& c){if(trace_)return save(c,true);if(pending_count_>=32){sticky_header(trace_failure);return false;}pending_[pending_count_++]=c.row;return true;}
 bool sdk(Call& c,const SdkCall& request,bool authority=true){
  u64 before=0;const bool pre=endpoint(before,authority);
  if(!pre){c.row.raw.flags|=before?late:clock_unknown;
   // No SDK call means an entirely zero SdkReceipt32, including on admission
   // failure. Consumed known-close obligations may still enter once below.
   if(request.op!=310&&request.op!=203&&request.op!=334)return false;}
  const bool recorded=save(c,false);
  if(!recorded&&trace_&&request.op!=310&&request.op!=203&&request.op!=334){c.row.raw.flags|=diagnostic_failure;return false;}
  c.row.sdk.entered_qpc=before;
  if(!pre)c.row.sdk.flags|=before?sdk_late:sdk_clock_unknown;
  invoke_sdk(request,c.row.sdk);
  if(request.out&&request.bytes){const u32 count=request.bytes>2048?2048:request.bytes;c.row.input_kind=static_cast<u32>(InputKind::sdk_output);
   if(guarded_copy(c.row.name_or_WSADATA,request.out,count)){c.row.captured_bytes=count;c.row.raw.flags|=capture_complete;}
   else{c.row.raw.flags|=input_fault;sticky_header(capture_failure);}}
  save(c,false); // original raw return/error/output first; no post-QPC yet
  u64 after=0;const bool post=endpoint(after,authority);
  if(c.row.sdk.flags&sdk_returned)c.row.sdk.returned_qpc=after;
  if(!post){c.row.sdk.flags|=after?sdk_late:sdk_clock_unknown;c.row.raw.flags|=after?late:clock_unknown;}
  save(c,false);return post&&(c.row.sdk.flags&sdk_returned)!=0&&(c.row.sdk.flags&sdk_exception)==0;
 }
 bool internal_sdk(u32 op,u64 a,u64 b,u64 c,void* out,u32 bytes,Call& row,bool authority=true){
  row.can_trace=true;row.row.raw.size=2176;row.row.raw.export_ordinal=op;row.row.raw.flags=entered|internal;row.row.raw.arg0=a;row.row.raw.arg1=b;row.row.arg2=c;row.row.thread_id=GetCurrentThreadId();
  const bool okay=sdk(row,{op,a,b,c,out,bytes},authority);
  row.row.raw.raw_return=row.row.sdk.raw_return;row.row.raw.error=row.row.sdk.error;
  row.row.raw.entered_qpc=row.row.sdk.entered_qpc;row.row.raw.returned_qpc=row.row.sdk.returned_qpc;
  if(row.row.sdk.flags&sdk_returned)row.row.raw.flags|=returned|error_valid;
  const bool persisted=queue(row);return okay&&persisted;
 }
 void summary(u32 op,InputKind kind,const void* data,u32 bytes,u64 before,u64 after){
  Call c{};c.can_trace=true;c.row.raw.size=2176;c.row.raw.export_ordinal=op;c.row.raw.flags=entered|returned|internal|capture_complete;
  c.row.raw.entered_qpc=before;c.row.raw.returned_qpc=after;c.row.raw.raw_return=1;c.row.thread_id=GetCurrentThreadId();
  c.row.input_kind=static_cast<u32>(kind);c.row.captured_bytes=bytes;std::memcpy(c.row.name_or_WSADATA,data,bytes);queue(c);
 }
 bool view_zero(Trace557312* view){const auto* p=reinterpret_cast<const std::uint8_t*>(view);std::uint8_t block[256]{};
  for(u32 at=0;at<trace_bytes;at+=256){const u32 n=trace_bytes-at<256?trace_bytes-at:256;if(!guarded_copy(block,p+at,n)||any(block,n))return false;}return true;}
 bool publish_view(u64 pointer){
  if(!pointer||pointer==~u64{0}||(pointer&7))return false;auto* view=reinterpret_cast<Trace557312*>(static_cast<std::uintptr_t>(pointer));
  if(!view_zero(view))return false;
  TraceHeader256 h{};std::memcpy(h.magic,"A5T1",4);h.version=1;h.header_bytes=256;h.total_bytes=trace_bytes;h.capacity=256;h.row_bytes=2176;
  std::memcpy(h.run,config_.run,16);std::memcpy(h.config_sha256,config_.config_sha256,32);std::memcpy(h.source_sha256,config_.source_sha256,32);std::memcpy(h.shim_sha256,config_.shim_sha256,32);
  h.target_pid=config_.target_pid;h.target_creation=config_.target_creation;h.frequency=config_.frequency;h.root_start=config_.root_start;h.root_deadline=config_.root_deadline;
  h.work_deadline=config_.work_deadline;h.window_start=config_.window_start;h.window_end=config_.window_end;std::memcpy(h.trace_nonce,config_.trace_nonce,16);h.state_flags=sticky_.load();
  if(!guarded_copy(&view->header,&h,sizeof(h)))return false;trace_=view;
  // Publish only the completely initialized known mapping, before bootstrap
  // rows can become complete. Earlier sticky bits are merged after the store;
  // later writers acquire the pointer and OR their own bits before returning.
  published_.store(view);
  InterlockedOr(reinterpret_cast<volatile LONG*>(&view->header.state_flags),static_cast<LONG>(sticky_.load()));
  for(u32 i=0;i<pending_count_;++i){Call c{};c.can_trace=true;c.row=pending_[i];if(!save(c,true))return false;}pending_count_=0;return true;
 }
 bool module_name(u32 op,HMODULE h,const u16* expected,u32 expected_chars){
  wchar_t actual[1024]{};Call row{};const bool okay=internal_sdk(op,number(h),0,0,actual,sizeof(actual),row);
  const auto count=row.row.sdk.raw_return;return okay&&count>0&&count<1024&&actual[count]==0&&wide_equal(reinterpret_cast<const u16*>(actual),static_cast<u32>(count),expected,expected_chars);
 }
 bool system_name(const char* leaf,u16 (&out)[260],u32& count){
  u32 end=0;for(u32 i=0;i<config_.system_ws2_chars;++i)if(config_.system_ws2_path[i]=='\\')end=i+1;
  if(end<3||end>=260)return false;std::memcpy(out,config_.system_ws2_path,end*2);count=end;
  for(u32 i=0;leaf[i];++i){if(count>=259)return false;out[count++]=static_cast<u16>(leaf[i]);}out[count]=0;return true;
 }
 bool cache_module(u32 hop,u32 nop,const wchar_t* literal,const char* leaf,HMODULE& result){
  Call c{};if(!internal_sdk(hop,number(literal),0,0,nullptr,0,c)||!c.row.sdk.raw_return)return false;
  result=module(static_cast<u64>(c.row.sdk.raw_return));u16 expected[260]{};u32 count=0;return system_name(leaf,expected,count)&&module_name(nop,result,expected,count);
 }
 bool initialize(){
  Call frequency{};LARGE_INTEGER f{};if(!internal_sdk(300,0,0,0,&f,sizeof(f),frequency,false)||!frequency.row.sdk.raw_return||f.QuadPart<=0)return false;frequency_=static_cast<u64>(f.QuadPart);
  struct Scanner {Runtime& rt;bool clock(u64& q){return rt.endpoint(q,false);}bool read(u64 a,void* p,u32 n){return MemoryReader{}(a,p,n);}
   bool query(u64 a,ScanRegion& out){MEMORY_BASIC_INFORMATION m{};SIZE_T n=0;__try {n=VirtualQuery(reinterpret_cast<const void*>(static_cast<std::uintptr_t>(a)),&m,sizeof(m));}__except(EXCEPTION_EXECUTE_HANDLER){return false;}
    if(n!=sizeof(m))return false;out={number(m.BaseAddress),static_cast<u64>(m.RegionSize),number(m.AllocationBase),m.State,m.Protect};return true;}} scanner{*this};
  PayloadFinder<Scanner> finder(scanner,frequency_);FindResult found{};if(!finder.find(found))return false;
  config_=found.config;configured_=true;
  if(pending_count_!=1||pending_[0].raw.entered_qpc<config_.window_start||pending_[0].raw.returned_qpc<pending_[0].raw.entered_qpc||pending_[0].raw.returned_qpc>=config_.window_end)return false;
  ScanSummary scan{found.first_qpc,found.last_qpc,found.allocation,found.payload,found.framing_bytes,found.regions,found.candidates,found.records,1,4096,256,64,0};
  summary(301,InputKind::scan_summary,&scan,sizeof(scan),found.first_qpc,found.last_qpc);
  summary(302,InputKind::payload_framing456,found.framing,456,found.first_qpc,found.last_qpc);
  summary(303,InputKind::configuration2048,&config_,2048,found.first_qpc,found.last_qpc);
  Call pid{};if(!internal_sdk(304,0,0,0,nullptr,0,pid)||static_cast<u64>(pid.row.sdk.raw_return)!=config_.target_pid)return false;
  FILETIME times[4]{};Call creation{};if(!internal_sdk(305,0,0,0,times,sizeof(times),creation)||!creation.row.sdk.raw_return)return false;
  const u64 created=static_cast<u64>(times[0].dwLowDateTime)|(static_cast<u64>(times[0].dwHighDateTime)<<32);if(created!=config_.target_creation)return false;
  DWORD flags=0;Call before{};if(!internal_sdk(306,config_.trace_handle,0,0,&flags,sizeof(flags),before)||!before.row.sdk.raw_return||flags!=HANDLE_FLAG_INHERIT)return false;
  Call clear{};if(!internal_sdk(307,config_.trace_handle,0,0,nullptr,0,clear)||!clear.row.sdk.raw_return)return false;
  flags=0;Call after{};if(!internal_sdk(308,config_.trace_handle,0,0,&flags,sizeof(flags),after)||!after.row.sdk.raw_return||flags!=0)return false;
  Call map{};const bool mapped=internal_sdk(309,config_.trace_handle,0,0,nullptr,0,map);
  const u64 view=static_cast<u64>(map.row.sdk.raw_return);
  // Known view/handle ownership survives failed postclock. View is retained
  // until supervised process exit, never reported as explicitly unmapped.
  const bool published=(map.row.sdk.flags&sdk_returned)&&view&&publish_view(view);
  if(trace_handle_consumed_)return false;trace_handle_consumed_=true;Call close{};const bool closed=internal_sdk(310,config_.trace_handle,0,0,nullptr,0,close)&&close.row.sdk.raw_return!=0;
  if(!mapped||!published||!closed)return false;
  wchar_t system[260]{};Call sys{};if(!internal_sdk(322,0,0,0,system,sizeof(system),sys)||sys.row.sdk.raw_return<=0||sys.row.sdk.raw_return>=260)return false;
  u16 expected_ws2[260]{};const u32 chars=static_cast<u32>(sys.row.sdk.raw_return);const char ws2[]="\\WS2_32.dll";
  if(system[chars]!=0||chars+sizeof(ws2)>260)return false;std::memcpy(expected_ws2,system,chars*2);for(u32 i=0;i<sizeof(ws2);++i)expected_ws2[chars+i]=static_cast<u16>(ws2[i]);
  if(!wide_equal(expected_ws2,chars+static_cast<u32>(sizeof(ws2))-1,config_.system_ws2_path,config_.system_ws2_chars))return false;
  u16 private_path[1024]{};for(u32 i=0;i<config_.private_path_bytes;++i)private_path[i]=static_cast<unsigned char>(config_.private_path[i]);
  if(!self_||!module_name(311,self_,private_path,config_.private_path_bytes))return false;
  if(!cache_module(312,313,L"kernel32.dll","kernel32.dll",kernel32_)||!cache_module(314,315,L"kernelbase.dll","kernelbase.dll",kernelbase_)||!cache_module(316,317,L"ntdll.dll","ntdll.dll",ntdll_))return false;
  Call main{};if(!internal_sdk(321,0,0,0,nullptr,0,main)||!main.row.sdk.raw_return)return false;main_=module(static_cast<u64>(main.row.sdk.raw_return));
  static const char filename[]="GetModuleFileNameA",version[]="RtlVerifyVersionInfo";
  Call fn{},vn{};if(!internal_sdk(318,number(kernel32_),number(filename),0,nullptr,0,fn)||!fn.row.sdk.raw_return)return false;
  if(!internal_sdk(319,number(ntdll_),number(version),0,nullptr,0,vn)||!vn.row.sdk.raw_return)return false;
  filename_=reinterpret_cast<FARPROC>(static_cast<std::uintptr_t>(fn.row.sdk.raw_return));version_=reinterpret_cast<FARPROC>(static_cast<std::uintptr_t>(vn.row.sdk.raw_return));return true;
 }
public:
 void attached(HMODULE self){self_=self;} // DllMain scalar only
 bool ready(){int expected=0;if(state_.compare_exchange_strong(expected,1)){bootstrap_thread_.store(GetCurrentThreadId());const bool okay=initialize();if(!okay)sticky_header(bootstrap_failure);state_.store(okay?2:-1);return okay;}
  if(expected==1)sticky_header(concurrent_bootstrap);return expected==2;}
 Call open(u32 ordinal,u64 a=0,u64 b=0,u64 c=0){Call out{};out.row.raw.size=2176;out.row.raw.export_ordinal=ordinal;out.row.raw.arg0=a;out.row.raw.arg1=b;out.row.arg2=c;out.row.thread_id=GetCurrentThreadId();
  const bool initialized=ready();out.row.raw.flags=entered;out.can_trace=initialized||state_.load()==-1;
  if(!out.can_trace){out.row.raw.flags|=diagnostic_failure|clock_unknown;return out;}
  u64 tick=0;const bool timely=endpoint(tick);out.row.raw.entered_qpc=tick;out.allowed=initialized&&timely;
  if(!timely)out.row.raw.flags|=tick?late:clock_unknown;out.allowed=save(out,false)&&out.allowed;return out;}
 void sync(Call& c){save(c,false);}
 void fault(Call& c,u32 state=capture_failure){c.row.raw.flags|=diagnostic_failure;sticky_header(state);}
 void finish(Call& c,std::int64_t delivered,int error,bool valid){
  c.row.raw.raw_return=delivered;c.row.raw.error=error;c.row.raw.flags|=returned|(valid?error_valid:0);if(!c.can_trace)return;save(c,false);
  u64 tick=0;const bool timely=endpoint(tick);c.row.raw.returned_qpc=tick;if(!timely)c.row.raw.flags|=tick?late:clock_unknown;
  if(c.row.raw.flags&input_fault){sticky_header(capture_failure);if(trace_)InterlockedExchange(reinterpret_cast<volatile LONG*>(&trace_->header.input_fault),1);}
  const u32 state=startup_.sticky();if(state&unsupported)sticky_header(unsupported_seen);if(state&output_fault)sticky_header(capture_failure);
  if(state&reference_unknown)sticky_header(reference_uncertain);if(state&capacity_exceeded)sticky_header(trace_failure);
  if(trace_)InterlockedExchange(reinterpret_cast<volatile LONG*>(&trace_->header.startup_refs),static_cast<LONG>(startup_.references()));save(c,true);
 }
 void reject(Call& c,u32 state=unsupported_seen){c.row.raw.flags|=unsupported_delivery;startup_.reject();sticky_header(state);
  if(c.can_trace&&trace_){u32 index=0;bool found=false;for(u32 i=0;i<35;++i)if(ws2_symbols[i].ordinal==c.row.raw.export_ordinal){index=i;found=true;break;}
   if(c.row.raw.export_ordinal>=200&&c.row.raw.export_ordinal<=204){index=35+c.row.raw.export_ordinal-200;found=true;}
   if(found)InterlockedOr64(reinterpret_cast<volatile LONG64*>(&trace_->header.unsupported_mask),static_cast<LONG64>(1ull<<index));}}
 bool allowed(Call& c){u64 tick=0;const bool okay=c.allowed&&endpoint(tick);if(!okay){c.row.raw.flags|=diagnostic_failure;sticky_header(clock_failure);}return okay;}
 Startup& startup(){return startup_;}const Config2048& config()const{static const Config2048 empty{};return state_.load()==2?config_:empty;}
 Module bound_module(HMODULE value)const {if(state_.load()!=2||!value)return Module::unknown;if(value==self_)return Module::private_shim;if(value==kernel32_)return Module::kernel32;if(value==kernelbase_)return Module::kernelbase;if(value==ntdll_)return Module::ntdll;if(value==main_)return Module::main_image;return Module::unknown;}
 HMODULE borrowed(Module m)const {switch(m){case Module::private_shim:return self_;case Module::kernel32:return kernel32_;case Module::kernelbase:return kernelbase_;case Module::ntdll:return ntdll_;case Module::main_image:return main_;default:return nullptr;}}
 FARPROC filename()const{return filename_;}FARPROC version()const{return version_;}
 bool primary(Call& c,const SdkCall& request){return sdk(c,request);}
 // Primary event acquisitions/releases occur only in their export's SDK32.
 // Auxiliary rows are distinct actual calls, never a second acquisition view.
 bool event_auxiliary(u32 op,u64 value,Call& row){
  if(op!=331&&op!=332&&op!=334)return false;
  return internal_sdk(op,value,0,0,nullptr,0,row);
 }
 bool lock_references(){if(reference_lock_.test_and_set()){sticky_header(reference_uncertain);return false;}return true;}
 void unlock_references(){reference_lock_.clear();}
 bool can_load()const{return references_.can_load();}
 bool acquired(Call& c){const bool returned_sdk=(c.row.sdk.flags&sdk_returned)!=0;const u64 value=static_cast<u64>(c.row.sdk.raw_return);
  const bool known=references_.returned_load(value,returned_sdk,value==number(self_));if(!known)sticky_header(reference_uncertain);return known;}
 bool take_release(HMODULE value,u32& ticket){const bool okay=references_.take_release(number(value),ticket);if(!okay)sticky_header(reference_uncertain);return okay;}
 bool released(u32 ticket,Call& c){const bool okay=references_.returned_release(ticket,(c.row.sdk.flags&sdk_returned)!=0,c.row.sdk.raw_return!=0);if(!okay)sticky_header(reference_uncertain);return okay;}
 bool verify_acquired_name(HMODULE value){u16 expected[1024]{};for(u32 i=0;i<config_.private_path_bytes;++i)expected[i]=static_cast<unsigned char>(config_.private_path[i]);return module_name(320,value,expected,config_.private_path_bytes);}
};
} }
