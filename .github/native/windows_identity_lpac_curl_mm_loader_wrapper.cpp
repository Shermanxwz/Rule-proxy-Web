#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#ifndef NOMINMAX
#define NOMINMAX
#endif
#define CMM_WRAPPER_BUILD
#include <windows.h>
#include "../vendor/detours/src/detours.h"
#include "windows_identity_lpac_curl_mm_loader_context.hpp"
#if !defined(_WIN64) || !defined(DETOURS_X64) || DETOURS_64BIT != 1
#error AMD64 Detours branch required
#endif
#if defined(_DEBUG) || (defined(DETOUR_DEBUG) && DETOUR_DEBUG != 0)
#error No debug/assertion branch admitted
#endif
namespace cmm { namespace win32 {
const GUID kPayloadGuid={0xb4626452,0x3359,0x4b34,{0x9a,0x97,0xdd,0x85,0xe4,0xb7,0x9f,0x2c}};
alignas(8) volatile LONG64 next_generation=0;
// Non-OBSERVE helpers are privately retained in the caller-owned opaque
// Context's fixed16 rows for the CURRENT export. They are not Output trace
// rows; no independent Output decoder is claimed to have validated them.
// begin: QPF1 + generation3; update/install: generation3 before+after;
// forget: generation3. QPC/GetLastError are endpoint metadata, not API rows.
inline bool helper(Context& c,Args& a,bool permit_exited=false){
 if(c.helper_count>=16)return false;u64 q=0;if(!qpc(q))return false;
 a.raw.entered_qpc=q;if(q<c.last_qpc||(!permit_exited&&!tick(c.input.plan,q)))return false;c.last_qpc=q;
 primitive(&a);const u32 index=c.helper_count++;c.helpers[index]=a.raw; // raw first
 u64 end=0;const bool clock=qpc(end);if(clock&&a.raw.returned==1)c.helpers[index].returned_qpc=end;
 a.raw=c.helpers[index];const bool monotonic=clock&&end>=c.last_qpc;if(monotonic)c.last_qpc=end;return a.raw.returned==1&&monotonic&&(permit_exited||tick(c.input.plan,end));
}
inline Args helper_args(Primitive op,u32 kind,u64 requested,u64 object){Args a{};a.raw.operation=operation(op);a.raw.kind=kind;a.raw.requested=requested;a.object=object;return a;}
inline bool small_generation(Context& c,bool exited,bool begin_phase=false){
 auto a=helper_args(begin_phase?Primitive::begin_process_id:exited?Primitive::forget_process_id:Primitive::helper_process_id,count_kind,c.input.plan.process,c.input.plan.process);
 if(!helper(c,a,exited)||a.raw.observed!=c.input.plan.target_pid)return false;
 a=helper_args(begin_phase?Primitive::begin_process_times:exited?Primitive::forget_process_times:Primitive::helper_process_times,boolean_kind,c.input.plan.process,c.input.plan.process);
 if(!helper(c,a,exited)||a.raw.raw_bool==0||a.raw.observed!=c.input.plan.target_creation)return false;
 a=helper_args(begin_phase?Primitive::begin_process_wait:exited?Primitive::forget_process_wait:Primitive::helper_process_wait,wait_kind,0,c.input.plan.process);
 return helper(c,a,exited)&&a.raw.observed==(exited?WAIT_OBJECT_0:WAIT_TIMEOUT);
}
inline bool final_tick(Context& c,CMM_RESULT256& r){u64 q=0;const bool clock=qpc(q);r.return_clock_known=clock?1u:0u;if(clock)r.returned_qpc=q;
 r.within_window=clock&&q>=r.entered_qpc&&q>=c.last_qpc&&tick(c.input.plan,q);if(clock&&q>=c.last_qpc)c.last_qpc=q;return r.within_window!=0;}
inline void mutation(Context& c,CMM_RESULT256& r,bool install){
 auto& physical=install?c.install:c.update;physical={};physical.operation=operation(install?Primitive::detour_copy:Primitive::detour_update);physical.kind=install?pointer_kind:boolean_kind;
 physical.requested=install?320:c.input.plan.process;physical.entered_qpc=r.entered_qpc;physical.entered=1;c.mutation_possible=1;
 // SEH is in mutation_seh below. physical fields survive post-clock/held
 // failures and are copied into Result.primary_call before any qualification.
}
void mutation_body(Context* c,bool install) noexcept {
 auto& raw=install?c->install:c->update;
 if(install){PVOID value=DetourCopyPayloadToProcessEx(H(c->input.plan.process),kPayloadGuid,&c->input.initial,320);const DWORD error=value?0:GetLastError();
  raw.observed=U(value);raw.returned=1;raw.error_valid=value?0u:1u;raw.error=error;c->remote=raw.observed;}
 else{LPCSTR names[1]={c->marker_path};const BOOL value=DetourUpdateProcessWithDll(H(c->input.plan.process),names,1);const DWORD error=value?0:GetLastError();
  raw.raw_bool=value;raw.returned=1;raw.error_valid=value?0u:1u;raw.error=error;}
}
void mutation_seh(Context* c,bool install,u32* exception_out) noexcept {
 __try{mutation_body(c,install);}__except(EXCEPTION_EXECUTE_HANDLER){*exception_out=static_cast<u32>(GetExceptionCode());}
}
u32 begin(const CMM_PLAN512* source,CMM_CONTEXT8192* opaque,CMM_RESULT256* result){
 if(!clean_output(opaque,result,256)||!span(source,512)||!align8(source)||overlaps(source,512,opaque,8192)||overlaps(source,512,result,256))return rejected;
 init(*result,1);if(nonzero(opaque,8192))return rejected;CMM_PLAN512 plan{};if(!safe_copy(&plan,source,512)||!plan_shape(plan)||!equal(plan.payload_guid,payload_guid,16)||!input_ranges(plan,source,opaque,result))return rejected;
 auto* c=::new(static_cast<void*>(opaque->bytes)) Context{};c->magic=context_magic;const LONG64 generation=InterlockedIncrement64(&next_generation);if(generation<=0){std::memset(opaque,0,8192);return rejected;}c->generation=static_cast<u64>(generation);c->input.plan=plan;c->busy=1;
 if(!safe_copy(&c->input.identity,reinterpret_cast<const void*>(static_cast<std::uintptr_t>(plan.expected_identity)),256)
   ||!safe_copy(&c->input.security,reinterpret_cast<const void*>(static_cast<std::uintptr_t>(plan.expected_security)),1024)
   ||!safe_copy(c->input.target_path,reinterpret_cast<const void*>(static_cast<std::uintptr_t>(plan.target_path)),2ull*(plan.target_path_chars+1))
   ||!safe_copy(c->input.marker_nt,reinterpret_cast<const void*>(static_cast<std::uintptr_t>(plan.marker_nt_path)),2ull*(plan.marker_nt_path_chars+1))
   ||!safe_copy(c->marker_path,reinterpret_cast<const void*>(static_cast<std::uintptr_t>(plan.marker_ascii_path)),static_cast<std::size_t>(plan.marker_ascii_path_bytes)+1))return done(*c,*result,rejected);
 // No caller pointer survives as a later authorization source.
 c->input.plan.target_path=c->input.plan.marker_nt_path=c->input.plan.marker_ascii_path=c->input.plan.expected_identity=c->input.plan.expected_security=0;
 if(!identity_shape(c->input.identity)||!security_allowed(c->input.security,c->input.identity)||!DOS_path(c->input.target_path,plan.target_path_chars)
  ||!text(c->input.marker_nt,plan.marker_nt_path_chars,1024)||!ascii_path(c->marker_path,plan.marker_ascii_path_bytes))return done(*c,*result,rejected);
 u64 q=0;if(!qpc(q)||!tick(plan,q))return done(*c,*result,late_clock);result->entered_qpc=q;c->last_qpc=q;
 // QPF is called once in BEGIN, never hidden in the hot OBSERVE graph.
 CMM_CALL64 f{};f.operation=operation(Primitive::begin_frequency);f.kind=boolean_kind;f.entered=1;f.entered_qpc=q;
 if(c->helper_count>=16)return done(*c,*result,capacity);
 LARGE_INTEGER frequency{};const BOOL value=QueryPerformanceFrequency(&frequency);const DWORD error=value?0:GetLastError();f.raw_bool=value;f.error_valid=value?0u:1u;f.error=error;f.returned=1;f.observed=static_cast<u64>(frequency.QuadPart);c->helpers[c->helper_count++]=f;
 u64 after=0;const bool clock=qpc(after);if(clock)c->helpers[0].returned_qpc=after;
 if(clock&&after>=c->last_qpc)c->last_qpc=after;
 if(!value||frequency.QuadPart<=0||f.observed!=plan.frequency||!clock||after<q||!tick(plan,after)||!small_generation(*c,false,true)||!final_tick(*c,*result))return done(*c,*result,late_clock);
 c->bound_ready=1;result->target_alive=1;result->validation_passed=1;result->resources_clean=1;return done(*c,*result,bound);
}
u32 update(CMM_CONTEXT8192* opaque,CMM_RESULT256* result){
 if(!clean_output(opaque,result,256))return rejected;init(*result,2);auto& c=*state(opaque);if(!known(c))return rejected;
 c.helper_count=0;std::memset(c.helpers,0,sizeof(c.helpers));if(!c.bound_ready||c.update_once||c.mutation_unknown)return done(c,*result,rejected);c.busy=1;
 if(!small_generation(c,false))return done(c,*result,identity_changed);u64 q=0;if(!qpc(q)||q<c.last_qpc||!tick(c.input.plan,q))return done(c,*result,late_clock);result->entered_qpc=q;c.last_qpc=q;
 c.update_once=1;mutation(c,*result,false);u32 code=0;mutation_seh(&c,false,&code);result->primary_call=c.update;result->exception_code=code;
 u64 end=0;const bool clock=qpc(end);if(clock&&c.update.returned==1)c.update.returned_qpc=end;result->primary_call=c.update;if(clock&&end>=c.last_qpc)c.last_qpc=end;
 const bool valid=clock&&end>=q&&end>=c.last_qpc&&tick(c.input.plan,end)&&small_generation(c,false)&&final_tick(c,*result);
 if(c.update.returned!=1){c.mutation_unknown=1;return done(c,*result,exception);}if(c.update.raw_bool==0){c.mutation_unknown=1;return done(c,*result,update_false);}
 if(!valid){c.mutation_unknown=1;return done(c,*result,late_clock);}c.update_timely=1;result->target_alive=1;result->validation_passed=1;result->resources_clean=1;return done(c,*result,updated);
}
u32 install(CMM_CONTEXT8192* opaque,const CMM_MARKER320* marker,CMM_RESULT256* result){
 if(!clean_output(opaque,result,256)||!span(marker,320)||!align8(marker)||overlaps(marker,320,opaque,8192)||overlaps(marker,320,result,256))return rejected;
 init(*result,3);auto& c=*state(opaque);if(!known(c))return rejected;c.helper_count=0;std::memset(c.helpers,0,sizeof(c.helpers));
 if(!c.update_timely||c.install_once||c.mutation_unknown||!marker_initial(*marker,c.input.plan))return done(c,*result,rejected);
 const u64 borrowed[]={c.input.plan.process,c.input.plan.thread,c.input.plan.primary_token,c.input.plan.inner_job,c.input.plan.outer_job,c.input.plan.entered_event,c.input.plan.body_event,c.input.plan.target_lease,c.input.plan.marker_lease};
 for(u64 h:borrowed)if(marker->entered_signal==h||marker->body_signal==h)return done(c,*result,rejected);c.busy=1;
 if(!small_generation(c,false))return done(c,*result,identity_changed);u64 q=0;if(!qpc(q)||q<c.last_qpc||!tick(c.input.plan,q))return done(c,*result,late_clock);result->entered_qpc=q;c.last_qpc=q;
 if(!safe_copy(&c.input.initial,marker,320))return done(c,*result,rejected);c.install_once=1;mutation(c,*result,true);u32 code=0;mutation_seh(&c,true,&code);result->primary_call=c.install;result->exception_code=code;
 u64 end=0;const bool clock=qpc(end);if(clock&&c.install.returned==1)c.install.returned_qpc=end;result->primary_call=c.install;if(clock&&end>=c.last_qpc)c.last_qpc=end;
 const bool valid=clock&&end>=q&&end>=c.last_qpc&&tick(c.input.plan,end)&&small_generation(c,false)&&final_tick(c,*result);
 if(c.install.returned!=1){c.mutation_unknown=1;return done(c,*result,exception);}if(c.remote==0){c.mutation_unknown=1;return done(c,*result,copy_null);}
 if((c.remote&7u)||c.remote<0x10000||c.remote>(1ull<<47)-320){c.mutation_unknown=1;return done(c,*result,copy_unaligned);}
 if(!valid){c.mutation_unknown=1;return done(c,*result,late_clock);}c.install_timely=1;result->target_alive=1;result->validation_passed=1;result->resources_clean=1;return done(c,*result,installed);
}
u32 observe_native(CMM_CONTEXT8192* opaque,CMM_OUTPUT24576* output){
 if(!clean_output(opaque,output,24576))return rejected;auto& c=*state(opaque);
 if(!known(c)){init(output->result,4);return rejected;}if(!c.install_timely||c.observe_once||c.mutation_unknown){init(output->result,4);facts(c,output->result);return rejected;}
 c.busy=1;c.observe_once=1;Observer machine(c.input,*output);NativeBackend backend(c.input,*output,c.remote,c.last_qpc);
 while(!machine.stopped()){if(!machine.begin_action())break;auto returned=backend.invoke(machine.next(),machine);
  if(backend.no_call()){const u32 klass=backend.failure_class();if(!machine.reject_without_call(klass==late_clock||klass==capacity?klass:exception,backend.pending()))machine.caught(0xe0000001u);}
  else machine.accept(returned);
 }
 // Carry forward only a known nonbackward endpoint. No new epoch or window.
 if(output->result.return_clock_known&&output->result.returned_qpc>=c.last_qpc)c.last_qpc=output->result.returned_qpc;
 facts(c,output->result);c.busy=0;return output->result.result_class;
}
u32 forget(CMM_CONTEXT8192* opaque,CMM_RESULT256* result){
 if(!clean_output(opaque,result,256))return rejected;init(*result,5);auto& c=*state(opaque);if(!known(c))return rejected;c.busy=1;c.helper_count=0;std::memset(c.helpers,0,sizeof(c.helpers));
 u64 q=0;if(qpc(q))result->entered_qpc=q;if(!small_generation(c,true))return done(c,*result,rejected);final_tick(c,*result);
 facts(c,*result);result->validation_passed=1;result->resources_clean=1;result->result_class=forgotten;
 // Successful forget consumes only local borrowed context. This is no process,
 // broker, environment or external absence proof. Opaque helper rows disappear
 // with the consumed context; the owner must not reconstruct them afterward.
 std::memset(opaque,0,8192);return forgotten;
}
u32 fault(CMM_CONTEXT8192* opaque,CMM_RESULT256* result,u32 op,u32 code) noexcept {
 if(!clean_output(opaque,result,256))return exception;if(result->size!=256||result->version!=2||result->operation!=op)init(*result,op);
 result->exception_code=code;result->within_window=result->return_clock_known=0;
 // Exception downgrades qualification and resource certainty. Retain every
 // physical API/primary/raw row and already sampled identity/Job/lease fact.
 result->validation_passed=result->observation_complete=result->mapping_qualified=0;
 result->resources_clean=0;result->result_class=exception;
 auto& c=*state(opaque);if(c.magic==context_magic){c.mutation_unknown|=c.mutation_possible;facts(c,*result);c.busy=0;}
 return exception;
}
u32 cpp_dispatch(u32 op,const CMM_PLAN512* plan,CMM_CONTEXT8192* context,const CMM_MARKER320* marker,void* output) noexcept {
 try{switch(op){case 1:return begin(plan,context,static_cast<CMM_RESULT256*>(output));case 2:return update(context,static_cast<CMM_RESULT256*>(output));case 3:return install(context,marker,static_cast<CMM_RESULT256*>(output));case 4:return observe_native(context,static_cast<CMM_OUTPUT24576*>(output));case 5:return forget(context,static_cast<CMM_RESULT256*>(output));default:return rejected;}}
 catch(...){return fault(context,static_cast<CMM_RESULT256*>(output),op,0xe06d7363u);}
}
u32 safe_fault(CMM_CONTEXT8192* context,void* output,u32 op,u32 code) noexcept {__try{return fault(context,static_cast<CMM_RESULT256*>(output),op,code);}__except(EXCEPTION_EXECUTE_HANDLER){return exception;}}
u32 seh_dispatch(u32 op,const CMM_PLAN512* plan,CMM_CONTEXT8192* context,const CMM_MARKER320* marker,void* output) noexcept {
 __try{return cpp_dispatch(op,plan,context,marker,output);}__except(EXCEPTION_EXECUTE_HANDLER){return safe_fault(context,output,op,static_cast<u32>(GetExceptionCode()));}
}
}} // namespace cmm::win32
CMM_API std::uint32_t CMM_CALL cmm_abi_version(){return 2;}
CMM_API std::uint32_t CMM_CALL cmm_begin_v2(const CMM_PLAN512* p,CMM_CONTEXT8192* c,CMM_RESULT256* r){return cmm::win32::seh_dispatch(1,p,c,nullptr,r);}
CMM_API std::uint32_t CMM_CALL cmm_update_v2(CMM_CONTEXT8192* c,CMM_RESULT256* r){return cmm::win32::seh_dispatch(2,nullptr,c,nullptr,r);}
CMM_API std::uint32_t CMM_CALL cmm_install_marker_v2(CMM_CONTEXT8192* c,const CMM_MARKER320* m,CMM_RESULT256* r){return cmm::win32::seh_dispatch(3,nullptr,c,m,r);}
CMM_API std::uint32_t CMM_CALL cmm_observe_v2(CMM_CONTEXT8192* c,CMM_OUTPUT24576* out){return cmm::win32::seh_dispatch(4,nullptr,c,nullptr,out);}
CMM_API std::uint32_t CMM_CALL cmm_forget_exited_v2(CMM_CONTEXT8192* c,CMM_RESULT256* r){return cmm::win32::seh_dispatch(5,nullptr,c,nullptr,r);}
