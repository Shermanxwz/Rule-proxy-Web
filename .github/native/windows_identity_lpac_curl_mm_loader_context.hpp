#pragma once
#include "windows_identity_lpac_curl_mm_loader_backend.hpp"
#include <new>
namespace cmm { namespace win32 {
inline constexpr u64 context_magic=0x325854434d4d434full;
struct Context {
 u64 magic,generation,last_qpc;Inputs input;char marker_path[1024];u64 remote;
 u32 busy,bound_ready,update_once,install_once,observe_once,mutation_possible,mutation_unknown,update_timely,install_timely;
 CMM_CALL64 update,install,helpers[16];u32 helper_count,reserved;
};
static_assert(sizeof(Context)<=8192&&alignof(Context)==8&&std::is_trivial<Context>::value,"opaque borrowed context capacity");
inline bool span(const void* p,std::size_t n){const u64 a=U(p);return a>=0x10000&&n&&a<=(1ull<<47)-n;}
inline bool align8(const void* p){return !(U(p)&7u);}
inline bool overlaps(const void* a,std::size_t n,const void* b,std::size_t m){return !span(a,n)||!span(b,m)||(U(a)<U(b)+m&&U(b)<U(a)+n);}
inline bool clean_output(CMM_CONTEXT8192* c,void* out,std::size_t bytes){return span(c,8192)&&align8(c)&&span(out,bytes)&&align8(out)&&!overlaps(c,8192,out,bytes);}
inline Context* state(CMM_CONTEXT8192* c){return reinterpret_cast<Context*>(c->bytes);}
inline bool known(const Context& c){return c.magic==context_magic&&c.generation&&c.busy==0;}
inline void init(CMM_RESULT256& r,u32 op){std::memset(&r,0,sizeof(r));r.size=256;r.version=2;r.operation=op;r.result_class=rejected;}
inline void facts(const Context& c,CMM_RESULT256& r){r.context_known=c.magic==context_magic&&c.generation;r.context_generation=c.generation;r.remote_mutation_possible=c.mutation_possible;r.remote_outcome_unknown=c.mutation_unknown;}
inline u32 done(Context& c,CMM_RESULT256& r,u32 klass){facts(c,r);r.result_class=klass;c.busy=0;return klass;}
inline bool ascii_path(const char* p,u32 n){if(n<4||n>1023||p[n]||p[1]!=':'||p[2]!='\\'||!((p[0]>='A'&&p[0]<='Z')||(p[0]>='a'&&p[0]<='z')))return false;
 for(u32 i=0;i<n;++i){const auto v=static_cast<unsigned char>(p[i]);if(v<32||v>126||v=='/'||v=='?'||v=='*'||v=='"'||v=='<'||v=='>'||v=='|'||(v==':'&&i!=1))return false;}
 for(u32 i=2;i+2<n;++i)if(p[i]=='\\'&&p[i+1]=='.'&&p[i+2]=='.'&&(i+3==n||p[i+3]=='\\'))return false;return true;}
inline bool input_ranges(const CMM_PLAN512& p,const CMM_PLAN512* source,CMM_CONTEXT8192* context,CMM_RESULT256* result){
 const void* addresses[]={reinterpret_cast<const void*>(static_cast<std::uintptr_t>(p.target_path)),reinterpret_cast<const void*>(static_cast<std::uintptr_t>(p.marker_nt_path)),reinterpret_cast<const void*>(static_cast<std::uintptr_t>(p.marker_ascii_path)),reinterpret_cast<const void*>(static_cast<std::uintptr_t>(p.expected_identity)),reinterpret_cast<const void*>(static_cast<std::uintptr_t>(p.expected_security))};
 const std::size_t sizes[]={2ull*(p.target_path_chars+1),2ull*(p.marker_nt_path_chars+1),static_cast<std::size_t>(p.marker_ascii_path_bytes)+1,256,1024};
 if(p.target_path_chars>259||p.marker_nt_path_chars>1023||p.marker_ascii_path_bytes>1023)return false;
 if(!align8(addresses[3])||!align8(addresses[4])||(U(addresses[0])&1u)||(U(addresses[1])&1u))return false;
 for(unsigned i=0;i<5;++i){if(!span(addresses[i],sizes[i])||overlaps(addresses[i],sizes[i],source,512)||overlaps(addresses[i],sizes[i],context,8192)||overlaps(addresses[i],sizes[i],result,256))return false;
  for(unsigned j=0;j<i;++j)if(overlaps(addresses[i],sizes[i],addresses[j],sizes[j]))return false;}
 return true;
}
}} // namespace cmm::win32
