#pragma once
// Production policy/state machine shared by Win32 adapters and future inert fakes.
// No Windows calls, heap, threads, waits, retry, Resume or network API here.
#include "windows_identity_lpac_curl_loader_wrapper.hpp"
#include <cstring>
#include <limits>
#include <new>

namespace cl {
using u32=std::uint32_t;using u64=std::uint64_t;
enum Operation:u32 {begin_operation=1,update_operation=2,install_operation=3,read_operation=4,forget_operation=5};
enum Class:u32 {unfinished=0,rejected=1,update_false=2,copy_null=3,late_clock=4,prepared=5,incoherent=6,snapshot=7,
 exception=8,bound=9,forgotten=10,updated=11,read_first_false=12,read_second_false=13,copy_unaligned=14};
inline constexpr std::uint8_t payload_guid[16]={0x6c,0xd9,0x58,0x2b,0xf4,0x8a,0x07,0x4c,0xae,0x18,0x68,0xc3,0x74,0xd0,0xf2,0x91};
struct BoolReturn {std::int32_t value;u32 error;};
struct CopyReturn {u64 address;u32 error;};
struct ReadReturn {std::int32_t value;u32 error;std::size_t bytes;};
struct HeldReturn {bool identity_known;bool alive;bool exited;};
struct Context {
 u64 magic,generation;CL_PLAN256 plan;char path[1024];CL_MARKER256 installed;u64 remote;
 u32 busy,bound_ready,pre_failure,update_once,copy_once,read_count,update_entered,update_returned,copy_entered,copy_returned;
 std::int32_t update_bool;u32 update_error,update_error_valid,copy_nonnull,copy_error,copy_error_valid,mutation_possible,mutation_unknown,update_timely,copy_timely;
};
static_assert(sizeof(Context)<=sizeof(CL_CONTEXT),"opaque context capacity");
static_assert(std::is_trivial<Context>::value,"no destructor across ABI");
inline constexpr u64 context_magic=0x315854434c55434full;
inline bool nonzero(const void* p,std::size_t n){const auto* b=static_cast<const std::uint8_t*>(p);for(std::size_t i=0;i<n;++i)if(b[i])return true;return false;}
inline bool equal(const void* a,const void* b,std::size_t n){return std::memcmp(a,b,n)==0;}
inline bool span(const void* p,std::size_t n){const auto x=reinterpret_cast<std::uintptr_t>(p);return p && n && x<=std::numeric_limits<std::uintptr_t>::max()-(n-1);}
inline bool aligned(const void* p){return (reinterpret_cast<std::uintptr_t>(p)&7u)==0;}
inline bool overlaps(const void* a,std::size_t an,const void* b,std::size_t bn){if(!span(a,an)||!span(b,bn))return true;const auto x=reinterpret_cast<std::uintptr_t>(a),y=reinterpret_cast<std::uintptr_t>(b);return x<=y+bn-1 && y<=x+an-1;}
inline bool clean_result(CL_CONTEXT* c,CL_RESULT128* r){return span(c,sizeof(*c))&&aligned(c)&&span(r,sizeof(*r))&&aligned(r)&&!overlaps(c,sizeof(*c),r,sizeof(*r));}
inline bool epoch(u64 f,u64 s,u64 d,u64 a,u64 e){const auto max=static_cast<u64>(std::numeric_limits<std::int64_t>::max());if(!f||f>max/120||s>max-120*f||d!=s+120*f||a<s||a>max-8*f)return false;const u64 cap=d-35*f,w=a+8*f;return a<e && e==(w<cap?w:cap);}
inline bool remote_aligned(u64 p){return p && !(p&7u) && p<=std::numeric_limits<u64>::max()-248 && !((p+248)&7u);}
inline Context* state(CL_CONTEXT* c){return reinterpret_cast<Context*>(c->bytes);}
inline bool known(const Context* c){return c->magic==context_magic && c->generation && c->busy==0;}
inline void init(CL_RESULT128& r,u32 op){std::memset(&r,0,sizeof(r));r.size=128;r.version=1;r.operation=op;r.result_class=rejected;}
inline void facts(const Context& c,CL_RESULT128& r){r.local_context_generation=c.generation;r.update_entered=c.update_entered;r.update_returned=c.update_returned;r.raw_update_BOOL=c.update_bool;r.update_GetLastError=c.update_error;r.update_error_valid=c.update_error_valid;r.copy_entered=c.copy_entered;r.copy_returned=c.copy_returned;r.copy_nonnull=c.copy_nonnull;r.copy_GetLastError=c.copy_error;r.copy_error_valid=c.copy_error_valid;r.remote_mutation_possible=c.mutation_possible;r.remote_outcome_unknown=c.mutation_unknown;}
inline u32 done(Context& c,CL_RESULT128& r,u32 code){facts(c,r);r.result_class=code;c.busy=0;return code;}
inline bool path_valid(const char* p,u32 n){if(n<4||n>1023||!span(p,static_cast<std::size_t>(n)+1)||p[n]!=0||!((p[0]>='A'&&p[0]<='Z')||(p[0]>='a'&&p[0]<='z'))||p[1]!=':'||p[2]!='\\')return false;for(u32 i=0;i<n;++i){const unsigned char v=static_cast<unsigned char>(p[i]);if(v<32||v>126||v=='?'||v=='*'||v=='"'||v=='<'||v=='>'||v=='|'||(v==':'&&i!=1))return false;}for(u32 i=2;i+2<n;++i)if(p[i]=='\\'&&p[i+1]=='.'&&p[i+2]=='.'&&(i+3==n||p[i+3]=='\\'))return false;return true;}
inline bool plan_valid(const CL_PLAN256& p){return p.size==256&&p.version==1&&p.reserved0==0&&p.reserved1==0&&!nonzero(p.reserved2,8)&&p.target_pid&&p.target_creation_FILETIME&&p.borrowed_held_process_handle&&p.borrowed_held_process_handle!=std::numeric_limits<u64>::max()&&epoch(p.frequency,p.root_start_qpc,p.root_deadline_qpc,p.window_start_qpc,p.window_end_qpc)&&nonzero(p.run,16)&&nonzero(p.config_sha256,32)&&nonzero(p.source_sha256,32)&&nonzero(p.target_image_sha256,32)&&nonzero(p.marker_image_sha256,32)&&equal(p.marker_payload_GUID_Windows_bytes,payload_guid,16);}
inline bool marker_initial(const CL_MARKER256& m,const CL_PLAN256& p){return equal(m.magic,"CLM1",4)&&m.version==1&&m.size==256&&equal(m.run,p.run,16)&&equal(m.config_sha256,p.config_sha256,32)&&equal(m.source_sha256,p.source_sha256,32)&&equal(m.marker_image_sha256,p.marker_image_sha256,32)&&m.frequency==p.frequency&&m.root_start_qpc==p.root_start_qpc&&m.root_deadline_qpc==p.root_deadline_qpc&&m.window_start_qpc==p.window_start_qpc&&m.window_end_qpc==p.window_end_qpc&&m.target_pid==p.target_pid&&m.reserved0==0&&m.target_creation_FILETIME==p.target_creation_FILETIME&&m.inherited_enter_event_signal_only&&m.inherited_body_event_signal_only&&m.inherited_enter_event_signal_only!=std::numeric_limits<u64>::max()&&m.inherited_body_event_signal_only!=std::numeric_limits<u64>::max()&&m.inherited_enter_event_signal_only!=m.inherited_body_event_signal_only&&m.inherited_enter_event_signal_only!=p.borrowed_held_process_handle&&m.inherited_body_event_signal_only!=p.borrowed_held_process_handle&&m.status_size==64&&m.status_version==1&&!nonzero(reinterpret_cast<const std::uint8_t*>(&m)+200,56);}
template<class API> bool clock(API& api,const CL_PLAN256& p,u64& tick){return api.clock(p.frequency,tick)&&tick>=p.window_start_qpc;}
template<class API> bool before(API& api,Context& c,CL_RESULT128& r){c.pre_failure=late_clock;u64 t=0;if(!clock(api,c.plan,t))return false;r.entered_qpc=t;if(t>=c.plan.window_end_qpc)return false;c.pre_failure=rejected;const HeldReturn h=api.held(c.plan);r.exact_target_still_alive=h.identity_known&&h.alive;if(!r.exact_target_still_alive)return false;c.pre_failure=late_clock;u64 final=0;if(!clock(api,c.plan,final))return false;r.entered_qpc=final;return final>=t&&final<c.plan.window_end_qpc;}
template<class API> bool after(API& api,Context& c,CL_RESULT128& r){const HeldReturn h=api.held(c.plan);r.exact_target_still_alive=h.identity_known&&h.alive;u64 t=0;r.return_clock_known=clock(api,c.plan,t);if(r.return_clock_known)r.returned_qpc=t;r.within_original_window=r.return_clock_known&&t>=r.entered_qpc&&t<c.plan.window_end_qpc;return r.within_original_window&&r.exact_target_still_alive;}

template<class API> u32 begin(API& api,const CL_PLAN256* p,CL_CONTEXT* raw,CL_RESULT128* out){
 if(!clean_result(raw,out)||!span(p,sizeof(*p))||!aligned(p)||overlaps(p,sizeof(*p),raw,sizeof(*raw))||overlaps(p,sizeof(*p),out,sizeof(*out)))return rejected;
 const CL_PLAN256 plan=*p;const auto* path=reinterpret_cast<const char*>(static_cast<std::uintptr_t>(plan.caller_owned_ASCII_marker_path_pointer));
 if(!span(path,static_cast<std::size_t>(plan.marker_path_bytes_excluding_NUL)+1)||overlaps(path,static_cast<std::size_t>(plan.marker_path_bytes_excluding_NUL)+1,raw,sizeof(*raw))||overlaps(path,static_cast<std::size_t>(plan.marker_path_bytes_excluding_NUL)+1,out,sizeof(*out)))return rejected;
 init(*out,begin_operation);if(nonzero(raw,sizeof(*raw))||!plan_valid(plan)||!path_valid(path,plan.marker_path_bytes_excluding_NUL))return rejected;
 Context* c=::new(static_cast<void*>(raw->bytes)) Context{};c->magic=context_magic;c->generation=api.generation();if(!c->generation){std::memset(raw,0,sizeof(*raw));return rejected;}c->plan=plan;std::memcpy(c->path,path,static_cast<std::size_t>(plan.marker_path_bytes_excluding_NUL)+1);c->plan.caller_owned_ASCII_marker_path_pointer=0;c->busy=1;
 if(!before(api,*c,*out))return done(*c,*out,c->pre_failure);out->validation_passed=1;c->bound_ready=after(api,*c,*out)?1u:0u;return done(*c,*out,c->bound_ready?bound:late_clock);
}
template<class API> u32 update(API& api,CL_CONTEXT* raw,CL_RESULT128* out){
 if(!clean_result(raw,out))return rejected;init(*out,update_operation);Context& c=*state(raw);if(!known(&c))return rejected;
 if(!c.bound_ready||c.update_once||c.mutation_unknown)return done(c,*out,rejected);c.busy=1;if(!before(api,c,*out))return done(c,*out,c.pre_failure);out->validation_passed=1;
 c.update_once=1;c.update_entered=1;c.mutation_possible=1;const BoolReturn v=api.update(c.plan.borrowed_held_process_handle,c.path);c.update_returned=1;c.update_bool=v.value;c.update_error_valid=v.value==0;c.update_error=v.value==0?v.error:0;
 const bool timely=after(api,c,*out);if(v.value==0){c.mutation_unknown=1;return done(c,*out,update_false);}if(!timely){c.mutation_unknown=1;return done(c,*out,late_clock);}c.update_timely=1;return done(c,*out,updated);
}
template<class API> u32 install(API& api,CL_CONTEXT* raw,const CL_MARKER256* marker,CL_RESULT128* out){
 if(!clean_result(raw,out)||!span(marker,sizeof(*marker))||!aligned(marker)||overlaps(marker,sizeof(*marker),raw,sizeof(*raw))||overlaps(marker,sizeof(*marker),out,sizeof(*out)))return rejected;
 init(*out,install_operation);Context& c=*state(raw);if(!known(&c))return rejected;
 if(!c.bound_ready||c.copy_once||!c.update_timely||c.mutation_unknown||!marker_initial(*marker,c.plan))return done(c,*out,rejected);c.busy=1;if(!before(api,c,*out))return done(c,*out,c.pre_failure);out->validation_passed=1;
 c.installed=*marker;c.copy_once=1;c.copy_entered=1;c.mutation_possible=1;const CopyReturn v=api.copy(c.plan.borrowed_held_process_handle,c.installed);c.copy_returned=1;c.copy_nonnull=v.address!=0;c.copy_error_valid=v.address==0;c.copy_error=v.address==0?v.error:0;c.remote=v.address;
 const bool timely=after(api,c,*out);if(!v.address){c.mutation_unknown=1;return done(c,*out,copy_null);}if(!remote_aligned(v.address)){c.mutation_unknown=1;return done(c,*out,copy_unaligned);}if(!timely){c.mutation_unknown=1;return done(c,*out,late_clock);}c.copy_timely=1;return done(c,*out,prepared);
}
inline bool status_valid(const CL_MARKER256& m){const bool initial=!nonzero(reinterpret_cast<const std::uint8_t*>(&m)+200,56);return m.status_size==64&&m.status_version==1&&!(m.progress_flags&~0x3fffu)&&m.failure_stage<=10&&!(m.even_stable_status_sequence&1u)&&(initial||m.writer_target_pid==m.target_pid)&&(!(m.progress_flags&2048u)||m.failure_stage==5||m.failure_stage==6)&&((m.progress_flags&2048u)||m.auxiliary_GetLastError==0);}
template<class API> u32 read(API& api,CL_CONTEXT* raw,CL_MARKER256* marker,CL_RESULT128* out){
 if(!clean_result(raw,out)||!span(marker,sizeof(*marker))||!aligned(marker)||overlaps(marker,sizeof(*marker),raw,sizeof(*raw))||overlaps(marker,sizeof(*marker),out,sizeof(*out)))return rejected;
 init(*out,read_operation);Context& c=*state(raw);if(!known(&c))return rejected;
 if(!c.copy_timely||c.mutation_unknown||c.read_count>=4||!remote_aligned(c.remote))return done(c,*out,rejected);c.busy=1;if(!before(api,c,*out))return done(c,*out,c.pre_failure);out->validation_passed=1;++c.read_count;out->marker_read_entered=1;
 CL_MARKER256 a{},b{};const ReadReturn first=api.read(c.plan.borrowed_held_process_handle,c.remote,&a,sizeof(a));out->marker_read_returned=1;
 if(!first.value){out->read_GetLastError=first.error;out->result_class=read_first_false;after(api,c,*out);return done(c,*out,read_first_false);}if(first.bytes!=sizeof(a)){after(api,c,*out);return done(c,*out,incoherent);}
 out->marker_read_returned=0;const ReadReturn second=api.read(c.plan.borrowed_held_process_handle,c.remote,&b,sizeof(b));out->marker_read_returned=1;
 if(!second.value){out->read_GetLastError=second.error;out->result_class=read_second_false;after(api,c,*out);return done(c,*out,read_second_false);}if(second.bytes!=sizeof(b)){after(api,c,*out);return done(c,*out,incoherent);}out->marker_read_exact256=1;
 const bool coherent=equal(&a,&c.installed,192)&&equal(&b,&c.installed,192)&&equal(reinterpret_cast<const std::uint8_t*>(&a)+192,reinterpret_cast<const std::uint8_t*>(&b)+192,64)&&status_valid(a)&&status_valid(b);
 const bool timely=after(api,c,*out);if(!coherent)return done(c,*out,incoherent);out->coherent_snapshot=1;*marker=b;return done(c,*out,timely?snapshot:late_clock);
}
template<class API> u32 forget(API& api,CL_CONTEXT* raw,CL_RESULT128* out){
 if(!clean_result(raw,out))return rejected;init(*out,forget_operation);Context& c=*state(raw);if(!known(&c))return rejected;c.busy=1;
 u64 t=0;if(clock(api,c.plan,t))out->entered_qpc=t;const HeldReturn h=api.held(c.plan);if(!h.identity_known||!h.exited)return done(c,*out,rejected);
 out->validation_passed=1;out->return_clock_known=clock(api,c.plan,t);if(out->return_clock_known)out->returned_qpc=t;out->within_original_window=out->return_clock_known&&t>=out->entered_qpc&&t<c.plan.window_end_qpc;
 facts(c,*out);out->remote_outcome_unknown=0;out->result_class=forgotten;std::memset(raw,0,sizeof(*raw));return forgotten;
}
inline u32 caught(CL_CONTEXT* raw,CL_RESULT128* out,u32 op,u32 code){if(!clean_result(raw,out))return exception;Context* c=state(raw);if(out->size!=128||out->version!=1||out->operation!=op)init(*out,op);out->caught_exception_code_or_zero=code;
 const u32 physical=(op==read_operation&&out->marker_read_entered&&out->marker_read_returned&&!out->marker_read_exact256&&!out->coherent_snapshot&&(out->result_class==read_first_false||out->result_class==read_second_false))?out->result_class:exception;
 if(c->magic==context_magic){c->mutation_unknown=1;facts(*c,*out);c->busy=0;}out->within_original_window=0;out->return_clock_known=0;out->result_class=physical;return physical;}
} // namespace cl
