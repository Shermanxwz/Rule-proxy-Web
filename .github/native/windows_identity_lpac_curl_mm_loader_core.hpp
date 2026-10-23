#pragma once
// Production pure observer policy. No Win32 adapter, export implementation,
// Detours operation, wait, allocation, thread, Resume or network call here.
#include "windows_identity_lpac_curl_mm_loader_wrapper.hpp"
#include "windows_identity_lpac_curl_mm_loader_ownership.hpp"
#include "windows_identity_lpac_curl_mm_loader_operations.hpp"
#include <cstring>
#include <limits>

namespace cmm {
using u32=std::uint32_t;using u64=std::uint64_t;
enum Class:u32 {unfinished=0,rejected=1,update_false=2,copy_null=3,late_clock=4,installed=5,incoherent=6,
 observed=7,exception=8,bound=9,forgotten=10,updated=11,read_first_false=12,read_second_false=13,
 copy_unaligned=14,target_exited=15,wait_timeout=16,wait_failed=17,identity_changed=18,region_rejected=19,
 name_rejected=20,headers_rejected=21,mapping_changed=22,lease_changed=23,capacity=24,body_missing=25};
enum Action:u32 {none=0,full_before=1,wait_first=2,sample_process=3,sample_entered=4,sample_body=5,
 progress_read_first=6,progress_read_second=7,wait_body=8,middle_generation=9,
 body_read_first=10,body_read_second=11,region_before=12,name_before=13,read_headers=14,
 region_after=15,name_after=16,full_after=17,complete=18};
enum RawKind:u32 {boolean_kind=1,count_kind=2,wait_kind=3,query_kind=4,close_kind=5,clock_failure_kind=6,status_kind=7,pointer_kind=8};
inline bool equal(const void* a,const void* b,std::size_t n){return std::memcmp(a,b,n)==0;}
inline bool nonzero(const void* p,std::size_t n){const auto* b=static_cast<const std::uint8_t*>(p);for(std::size_t i=0;i<n;++i)if(b[i])return true;return false;}
inline bool boolean(u32 x){return x<=1;}
inline bool handle(u64 x){return x && x!=std::numeric_limits<u64>::max();}
inline bool user_image_base(u64 base){return base>=0x10000&&base<=(1ull<<47)-4096&&!(base&0xffffu);}
inline bool epoch(const CMM_PLAN512& p){const auto max=static_cast<u64>(std::numeric_limits<std::int64_t>::max());
 if(!p.frequency||p.frequency>max/120||p.root_start>max-120*p.frequency||p.root_deadline!=p.root_start+120*p.frequency||p.window_start<p.root_start||p.window_start>max-8*p.frequency)return false;
 const u64 cap=p.root_deadline-35*p.frequency,e=p.window_start+8*p.frequency;
 return p.window_start<p.window_end&&p.window_end==(e<cap?e:cap);}
inline bool tick(const CMM_PLAN512& p,u64 q){return q>=p.window_start&&q<p.window_end;}
inline bool sid(const std::uint8_t* p,u32 n){return n>=8&&n<=68&&p[0]==1&&p[1]<=15&&n==8u+4u*p[1];}
inline bool identity_shape(const CMM_IDENTITY256& x){return x.size==256&&x.version==2&&sid(x.user_sid,x.user_sid_bytes)&&sid(x.appcontainer_sid,x.appcontainer_sid_bytes)
 &&!nonzero(x.user_sid+x.user_sid_bytes,68-x.user_sid_bytes)&&!nonzero(x.appcontainer_sid+x.appcontainer_sid_bytes,68-x.appcontainer_sid_bytes)
 &&x.token_type==1&&x.impersonation_level==0xffffffffu&&x.integrity_rid==4096&&x.is_appcontainer==1&&x.elevated==0&&x.ui_access==0&&x.capability_count==0
 &&x.token_id&&x.authentication_id&&!nonzero(x.reserved,sizeof(x.reserved));}
inline bool text(const std::uint16_t* p,u32 n,u32 capacity_){if(!n||n>=capacity_||p[n])return false;for(u32 i=0;i<n;++i)if(!p[i])return false;return true;}
inline bool DOS_path(const std::uint16_t* p,u32 n){if(!text(p,n,260)||n<4||p[1]!=':'||p[2]!='\\'||!((p[0]>='A'&&p[0]<='Z')||(p[0]>='a'&&p[0]<='z')))return false;
 for(u32 i=0;i<n;++i)if(p[i]<32||p[i]>126||p[i]=='/'||p[i]=='?'||p[i]=='*'||p[i]=='"'||p[i]=='<'||p[i]=='>'||p[i]=='|'||(p[i]==':'&&i!=1))return false;
 for(u32 i=2;i+2<n;++i)if(p[i]=='\\'&&p[i+1]=='.'&&p[i+2]=='.'&&(i+3==n||p[i+3]=='\\'))return false;return true;}
inline std::uint16_t ascii_fold(std::uint16_t x){return x>='A'&&x<='Z'?static_cast<std::uint16_t>(x+32):x;}
inline bool same_path(const std::uint16_t* a,u32 an,const std::uint16_t* b,u32 bn){if(an!=bn||!DOS_path(a,an)||!DOS_path(b,bn))return false;for(u32 i=0;i<an;++i)if(ascii_fold(a[i])!=ascii_fold(b[i]))return false;return true;}
inline bool security_shape(const CMM_SECURITY1024& x){return x.size==1024&&x.version==2&&text(x.process,x.process_chars,248)&&text(x.thread,x.thread_chars,248)&&!nonzero(x.reserved,16);}
inline bool append_ascii(std::uint16_t* b,u32& used,const char* s){while(*s){if(used>=247)return false;b[used++]=static_cast<std::uint16_t>(*s++);}b[used]=0;return true;}
inline bool append_number(std::uint16_t* b,u32& used,u64 x){char reversed[21]{};u32 n=0;do{reversed[n++]=static_cast<char>('0'+x%10);x/=10;}while(x);
 while(n){if(used>=247)return false;b[used++]=static_cast<std::uint16_t>(reversed[--n]);}b[used]=0;return true;}
inline bool append_sid(std::uint16_t* b,u32& used,const CMM_IDENTITY256& id){const auto* s=id.user_sid;if(!sid(s,id.user_sid_bytes)||!append_ascii(b,used,"S-1-"))return false;
 u64 authority=0;for(unsigned i=2;i<8;++i)authority=(authority<<8)|s[i];if(!append_number(b,used,authority))return false;
 for(u32 i=0;i<s[1];++i){const auto* q=s+8+4*i;const u32 value=static_cast<u32>(q[0])|(static_cast<u32>(q[1])<<8)|(static_cast<u32>(q[2])<<16)|(static_cast<u32>(q[3])<<24);
  if(!append_ascii(b,used,"-")||!append_number(b,used,value))return false;}return true;}
inline bool exact_private_sd(const std::uint16_t* observed,u32 chars,const CMM_IDENTITY256& id){const char* masks[]={"GA","0x1fffff"};
 for(const char* system:masks)for(const char* parent:masks){std::uint16_t expected[248]{};u32 n=0;
  if(append_ascii(expected,n,"D:P(A;;")&&append_ascii(expected,n,system)&&append_ascii(expected,n,";;;SY)(A;;")&&append_ascii(expected,n,parent)
   &&append_ascii(expected,n,";;;")&&append_sid(expected,n,id)&&append_ascii(expected,n,")")&&n==chars&&equal(observed,expected,(n+1)*2))return true;}return false;}
inline bool security_allowed(const CMM_SECURITY1024& sd,const CMM_IDENTITY256& id){return security_shape(sd)&&exact_private_sd(sd.process,sd.process_chars,id)&&exact_private_sd(sd.thread,sd.thread_chars,id);}
inline bool pe_shape(const CMM_PE32& p,bool dll){return p.size==32&&p.machine==0x8664u&&p.is_dll==(dll?1u:0u)&&p.entry_rva&&p.entry_rva<p.image_bytes&&p.image_bytes<=64u*1024u*1024u&&p.header_bytes>=512&&p.header_bytes<=4096;}
inline bool plan_shape(const CMM_PLAN512& p){if(p.size!=512||p.version!=2||!epoch(p)||!p.target_pid||!p.target_creation||p.reserved0||p.reserved1||p.reserved2||p.reserved3||p.reserved4||p.reserved5||nonzero(p.reserved6,8))return false;
 const u64 handles[]={p.process,p.thread,p.primary_token,p.inner_job,p.outer_job,p.entered_event,p.body_event,p.target_lease,p.marker_lease};
 for(unsigned i=0;i<9;++i){if(!handle(handles[i]))return false;for(unsigned j=0;j<i;++j)if(handles[i]==handles[j])return false;}
 return nonzero(p.run,16)&&nonzero(p.config_sha256,32)&&nonzero(p.source_sha256,32)&&nonzero(p.target_sha256,32)&&nonzero(p.marker_sha256,32)
 &&p.identity_bytes==256&&p.security_bytes==1024&&p.target_file_bytes&&p.marker_file_bytes&&nonzero(p.target_file_id,24)&&nonzero(p.marker_file_id,24)
 &&p.target_path_chars>0&&p.target_path_chars<260&&pe_shape(p.target_pe,false)&&pe_shape(p.marker_pe,true);}
inline bool marker_initial(const CMM_MARKER320& m,const CMM_PLAN512& p){return equal(m.magic,"CMM2",4)&&m.version==2&&m.size==320&&equal(m.run,p.run,16)
 &&equal(m.config_sha256,p.config_sha256,32)&&equal(m.source_sha256,p.source_sha256,32)&&equal(m.marker_sha256,p.marker_sha256,32)
 &&m.frequency==p.frequency&&m.root_start==p.root_start&&m.root_deadline==p.root_deadline&&m.window_start==p.window_start&&m.window_end==p.window_end
 &&m.target_pid==p.target_pid&&!m.reserved0&&m.target_creation==p.target_creation&&handle(m.entered_signal)&&handle(m.body_signal)&&m.entered_signal!=m.body_signal
 &&m.status_size==128&&m.status_version==2&&!nonzero(reinterpret_cast<const std::uint8_t*>(&m)+200,120);}
inline bool coherent(const CMM_MARKER320& a,const CMM_MARKER320& b,const CMM_MARKER320& initial){return equal(&a,&initial,192)&&equal(&b,&initial,192)
 &&equal(reinterpret_cast<const std::uint8_t*>(&a)+192,reinterpret_cast<const std::uint8_t*>(&b)+192,128)
 &&a.status_size==128&&a.status_version==2&&a.sequence&&!(a.sequence&1u)&&a.module_base_known==1&&user_image_base(a.module_base)
 &&!a.reserved1&&!nonzero(a.reserved2,48)&&a.writer_pid==a.target_pid&&a.failure<=11&&!(a.flags&~0x3fffu);}
inline bool marker_complete(const CMM_MARKER320& m,const CMM_PLAN512& p,u64 returned){return m.flags==6143u&&m.failure==0&&m.restore_bool!=0&&m.entered_bool!=0&&m.body_bool!=0
 &&m.restore_error==0&&m.entered_error==0&&m.body_error==0&&m.aux_error==0&&tick(p,m.last_qpc)&&m.last_qpc<=returned;}
inline bool members(const CMM_GENERATION64& g,const CMM_PLAN512& p){return g.size==64&&g.version==2&&g.pid==p.target_pid&&g.thread_pid==p.target_pid&&g.creation==p.target_creation
 &&g.alive==1&&g.exited==0&&g.inner_api!=0&&g.outer_api!=0&&g.inner_member==1&&g.outer_member==1&&g.inner_error==0&&g.outer_error==0&&g.resources_clean==1&&g.uncertain==0;}
inline bool full(const CMM_HELD192& h,const CMM_IDENTITY256& actual,const CMM_SECURITY1024& sd,
 const CMM_PLAN512& p,const CMM_IDENTITY256& expected,const CMM_SECURITY1024& expected_sd){return h.size==192&&h.version==2&&h.pid==p.target_pid&&h.thread_pid==p.target_pid&&h.creation==p.target_creation
 &&h.alive==1&&h.exited==0&&h.identity_api!=0&&h.security_api!=0&&h.identity_error==0&&h.security_error==0&&h.inner_api!=0&&h.outer_api!=0&&h.inner_member==1&&h.outer_member==1
 &&h.inner_error==0&&h.outer_error==0&&h.inner_limit_flags==0x2000&&h.outer_limit_flags==0x2000&&h.inner_ui_limits==0&&h.outer_ui_limits==0&&h.inner_handle_flags==0&&h.outer_handle_flags==0
 &&h.lease_api!=0&&h.lease_error==0&&equal(h.target_file_id,p.target_file_id,24)&&equal(h.marker_file_id,p.marker_file_id,24)&&h.target_file_bytes==p.target_file_bytes&&h.marker_file_bytes==p.marker_file_bytes
 &&h.resources_clean==1&&h.uncertain==0&&!nonzero(h.reserved,16)&&identity_shape(actual)&&equal(&actual,&expected,256)&&security_shape(sd)&&equal(&sd,&expected_sd,1024);}
inline bool readable(u32 protect){const u32 base=protect&0xffu;if(protect&~0x6ffu)return false;
 // PAGE_GUARD/NOACCESS/EXECUTE are not admitted. Only NO_CACHE/WRITECOMBINE
 // modifiers may accompany one exact readable base protection.
 if(protect&0x100u)return false;return base==2||base==4||base==8||base==0x20||base==0x40||base==0x80;}
inline bool region(const CMM_MEMORY64& m,u64 base){return user_image_base(base)&&m.size==64&&m.version==2&&m.returned_bytes==48&&m.error==0&&m.base==base&&m.allocation_base==base&&m.region_bytes>=4096
 &&m.region_bytes<=(1ull<<47)-base&&m.state==0x1000&&m.type==0x1000000&&readable(m.protect)&&!m.reserved;}
inline std::uint16_t le16(const std::uint8_t* b){return static_cast<std::uint16_t>(b[0]|(static_cast<u32>(b[1])<<8));}
inline u32 le32(const std::uint8_t* b){return static_cast<u32>(b[0])|(static_cast<u32>(b[1])<<8)|(static_cast<u32>(b[2])<<16)|(static_cast<u32>(b[3])<<24);}
inline bool headers(const std::uint8_t* b,const CMM_PE32& p){if(b[0]!='M'||b[1]!='Z')return false;const u32 n=le32(b+60);if(n<64||n>4096-264||!equal(b+n,"PE\0\0",4))return false;
 const auto* f=b+n+4;const auto* o=f+20;return le16(f)==0x8664&&le16(f+16)==240&&(le16(f+18)&0x2000)!=0&&le32(f+4)==p.timestamp
 &&le16(o)==0x20b&&le32(o+16)==p.entry_rva&&le32(o+56)==p.image_bytes&&le32(o+60)==p.header_bytes&&le16(o+68)==p.subsystem;}

// Backend return payloads carry physical observations, not qualifications.
// A future backend uses record() for EVERY allocation/query/close/probe before
// interpreting it. No later validation may overwrite physical API fields.
// EndpointOnce alone may fill returned_qpc from unknown zero once after the raw
// commit; failed QPC leaves a sealed zero, with no retry or replacement row.
// Ticket/index/reason are INTERNAL handoff metadata, not ABI06 Output fields.
// OBSERVE primary_call stays zero. An independent reader must inspect the raw
// prefix/unwind and cannot claim these internal values were persisted.
enum class RecordMode:u32 {append_once=0,already_committed=1};
enum class GroupState:u32 {complete=0,partial=1};
enum class FailureReason:u32 {api_return=1,postclock=2,validation=3,exception=4};
struct Return {
 RecordMode record_mode=RecordMode::append_once;u32 terminal_index=0xffffffffu;u64 action_ticket=0;
 GroupState group_state=GroupState::complete;u32 primary_failure_index=0xffffffffu;
 FailureReason failure_reason=FailureReason::validation;u32 partial_class=rejected;
 Action action;CMM_CALL64 call;CMM_HELD192 held;CMM_GENERATION64 generation;
 CMM_IDENTITY256 identity;CMM_SECURITY1024 security;CMM_IMAGE608 image;CMM_MARKER320 marker;
 CMM_MEMORY64 memory;std::uint16_t name[1024];std::uint8_t pe[4096];
};
inline u32 operation(Primitive p){return static_cast<u32>(p);}
inline bool actual_failure(const CMM_CALL64& c){if(c.entered!=1||c.returned!=1)return true;
 if(c.kind==boolean_kind)return c.raw_bool==0;
 if(c.kind==status_kind)return static_cast<u32>(c.raw_bool)!=0;
 if(c.kind==count_kind)return c.observed==0;
 if(c.kind==wait_kind)return c.observed==258||c.observed==0xffffffffull;
 if(c.kind==pointer_kind)return c.operation==operation(Primitive::detour_copy)?c.observed==0:c.observed!=0;
 return false;}
inline bool BOOL_error(const CMM_CALL64& c){return c.kind==boolean_kind&&(c.raw_bool?(c.error_valid==0&&c.error==0):c.error_valid==1);}
inline bool wait_error(const CMM_CALL64& c){return c.kind==wait_kind&&(c.observed==0xffffffffull?c.error_valid==1:c.error_valid==0&&c.error==0);}
inline bool raw_primitive(Action a,const Return& x){const auto& c=x.call;
 switch(a){
  case progress_read_first:case progress_read_second:case body_read_first:case body_read_second:return BOOL_error(c)&&c.requested==320
   &&c.operation==operation(a==progress_read_first?Primitive::rpm_progress_first:a==progress_read_second?Primitive::rpm_progress_second:a==body_read_first?Primitive::rpm_body_first:Primitive::rpm_body_second);
  case read_headers:return BOOL_error(c)&&c.requested==4096&&c.operation==operation(Primitive::rpm_pe);
  case region_before:case region_after:return c.kind==count_kind&&c.operation==operation(a==region_before?Primitive::region_before:Primitive::region_after)&&c.raw_bool==0&&c.requested==48&&c.observed==x.memory.returned_bytes
   &&(c.observed?(c.error_valid==0&&c.error==0&&x.memory.error==0):(c.error_valid==1&&c.error==x.memory.error));
  case name_before:case name_after:return c.kind==count_kind&&c.operation==operation(a==name_before?Primitive::mapped_name_before:Primitive::mapped_name_after)&&c.raw_bool==0&&c.requested==1024
   &&(c.observed==0||c.observed>=1024?c.error_valid==1:c.error_valid==0&&c.error==0);
  case wait_first:case wait_body:case sample_process:case sample_entered:case sample_body:return wait_error(c)
   &&c.operation==operation(a==wait_first?Primitive::wait_first:a==wait_body?Primitive::wait_body:a==sample_process?Primitive::sample_process:a==sample_entered?Primitive::sample_entered:Primitive::sample_body);
  case middle_generation:return BOOL_error(c)&&c.operation==operation(Primitive::middle_outer_member)&&c.raw_bool==x.generation.outer_api&&c.error==x.generation.outer_error&&c.observed==x.generation.outer_member;
  case full_before:case full_after:return BOOL_error(c)&&c.operation==operation(Primitive::marker_lease_standard)&&c.raw_bool==x.held.lease_api&&c.error==x.held.lease_error&&c.requested==24&&c.observed==x.held.marker_file_bytes;
  default:return false;
 }
}
struct Inputs {CMM_PLAN512 plan;CMM_IDENTITY256 identity;CMM_SECURITY1024 security;CMM_MARKER320 initial;std::uint16_t marker_nt[1024];std::uint16_t target_path[260];};
class Observer {
 const Inputs& in_;CMM_OUTPUT24576& out_;Action action_=none;bool second_phase_=false;u32 process_=258,enter_=258,body_=258;
 bool stopped_=false,process_exit_seen_=false,active_=false,last_accepted_=false;u64 last_=0,ticket_=0;u32 trace_start_=0;
 CMM_RESULT256& r(){return out_.result;}
 void stop(u32 klass){r().result_class=klass;r().observation_complete=0;stopped_=true;action_=none;}
 void next_after_progress(){if(body_==0)action_=middle_generation;else{second_phase_=true;action_=wait_body;}}
 bool call_clock(const CMM_CALL64& c){if(!tick(in_.plan,c.entered_qpc)||!tick(in_.plan,c.returned_qpc)||c.returned_qpc<c.entered_qpc||c.entered_qpc<last_)return false;last_=c.returned_qpc;r().returned_qpc=last_;r().return_clock_known=1;r().within_window=1;return true;}
 void read_done(bool body_pair){const u32 index=body_pair?2u:0u;
  const bool same=coherent(out_.markers[index],out_.markers[index+1],in_.initial);
  if(body_pair){if(!same||!marker_complete(out_.markers[3],in_.plan,last_)){stop(incoherent);return;}action_=region_before;}
  else next_after_progress();}
public:
 Observer(const Inputs& input,CMM_OUTPUT24576& output):in_(input),out_(output){std::memset(&out_,0,sizeof(out_));r().size=256;r().version=2;r().operation=4;r().result_class=rejected;
  if(!plan_shape(in_.plan)||!identity_shape(in_.identity)||!security_allowed(in_.security,in_.identity)||!marker_initial(in_.initial,in_.plan)||!text(in_.marker_nt,in_.plan.marker_nt_path_chars,1024)||!DOS_path(in_.target_path,in_.plan.target_path_chars)){stopped_=true;return;}
  // This pure observer is entered only by a future context owner after bound9,
  // updated11 and installed5, all original-window qualified. It does not expose
  // a raw remote address or create/Resume/update/copy implementation.
  action_=full_before;r().context_known=1;r().remote_mutation_possible=1;r().resources_clean=1;}
 Action next()const{return action_;}bool stopped()const{return stopped_;}
 bool begin_action(){if(stopped_||active_||action_==none||action_==complete||ticket_==std::numeric_limits<u64>::max())return false;
  ++ticket_;trace_start_=r().call_count;active_=true;return true;}
 // Backend08-only zero-physical-row rejection. No fake primitive, no typed
 // adoption, no upgrade of sticky resource state and no ticket replay.
 bool reject_without_call(u32 klass,u32 known_pending){
  if(stopped_||!active_||r().call_count!=trace_start_||known_pending!=0
    ||(klass!=late_clock&&klass!=capacity&&klass!=exception))return false;
  active_=false;last_accepted_=false;r().return_clock_known=0;r().within_window=0;
  stop(klass);return true;
 }
 u64 ticket()const{return ticket_;}u32 trace_start()const{return trace_start_;}bool last_accepted()const{return last_accepted_;}
 bool room(u32 n=1)const{return out_.result.call_count<=128&&n<=128-out_.result.call_count;}
 bool record(const CMM_CALL64& call){if(!room()){stop(capacity);return false;}const u32 i=r().call_count++;
  *call_slot(out_,i)=call;return true;}
 // The future native loop must call room(required primitive calls) BEFORE an
 // API, and call record(raw returned facts) BEFORE postclock or interpretation.
 void accept(const Return& x){last_accepted_=false;if(stopped_||action_==none)return;const Action a=action_;const u64 prior_last=last_;
  if(!active_||x.action!=a||x.action_ticket!=ticket_){stop(rejected);return;}active_=false;
  // Every action ticket is consumed once. A precommitted tail is referenced,
  // never appended again, rolled back, replaced, or reconstructed as summary.
  u32 terminal=0xffffffffu;
  if(x.record_mode==RecordMode::already_committed){if(r().call_count==0||r().call_count>128||x.terminal_index!=r().call_count-1||x.terminal_index<trace_start_
    ||!equal(call_slot(out_,x.terminal_index),&x.call,64)){stop(rejected);return;}terminal=x.terminal_index;}
  else if(x.record_mode==RecordMode::append_once){if(x.terminal_index!=0xffffffffu){stop(rejected);return;}terminal=r().call_count;if(!record(x.call))return;}
  else{stop(rejected);return;}
  last_accepted_=true;if(x.call.entered!=1||x.call.returned>1||x.call.reserved){stop(rejected);return;}
  // Preserve raw data before even the post-clock gate; a returned failure is
  // still a returned failure when a subsequent clock/identity observer fails.
  if(a==full_before||a==full_after){const u32 slot=a==full_before?0u:1u;out_.held[slot]=x.held;out_.identities[slot]=x.identity;out_.security[slot]=x.security;out_.images[slot]=x.image;++r().held_count;}
  if(a==middle_generation)out_.generation=x.generation;
  const bool reading=a==progress_read_first||a==progress_read_second||a==body_read_first||a==body_read_second;
  if(reading){const u32 slot=a==progress_read_first?0u:a==progress_read_second?1u:a==body_read_first?2u:3u;out_.markers[slot]=x.marker;++r().snapshot_count;}
  if(a==region_before||a==region_after){out_.regions[a==region_before?0:1]=x.memory;++r().mapping_count;}
  if(a==name_before||a==name_after)std::memcpy(out_.mapped_names[a==name_before?0:1],x.name,sizeof(x.name));
  if(a==read_headers)std::memcpy(out_.pe_header,x.pe,sizeof(x.pe));
  // A typed partial callback has rejection power only. Keep every already
  // committed raw row and copied partial tuple. A successful last Close does
  // not erase a failed API, unknown resource or late/failed observer earlier.
  if(x.group_state==GroupState::partial){if(x.primary_failure_index<trace_start_||x.primary_failure_index>terminal
    ||x.partial_class==unfinished||x.partial_class==observed||x.partial_class==bound||x.partial_class==updated||x.partial_class==installed||x.partial_class==forgotten||x.partial_class>body_missing){stop(rejected);return;}
   const auto* primary=call_slot(out_,x.primary_failure_index);
   if((x.failure_reason==FailureReason::api_return&&!actual_failure(*primary))
      ||static_cast<u32>(x.failure_reason)<1||static_cast<u32>(x.failure_reason)>4){stop(rejected);return;}
   if((a==full_before||a==full_after)&&(x.held.resources_clean!=1||x.held.uncertain))r().resources_clean=0;
   if(!call_clock(x.call)||x.failure_reason==FailureReason::postclock){r().return_clock_known=0;r().within_window=0;}stop(x.partial_class);return;}
  if(x.group_state!=GroupState::complete||x.primary_failure_index!=0xffffffffu){stop(rejected);return;}
  if(x.call.returned==0){r().resources_clean=0;stop(exception);return;}
  if(!raw_primitive(a,x)){stop(a==region_before||a==region_after?region_rejected:rejected);return;}
  if(reading&&!x.call.raw_bool){r().return_clock_known=call_clock(x.call)?1u:0u;if(!r().return_clock_known)r().within_window=0;stop(a==progress_read_first||a==body_read_first?read_first_false:read_second_false);return;}
  if(!call_clock(x.call)){r().return_clock_known=0;r().within_window=0;stop(late_clock);return;}
  if(!r().entered_qpc)r().entered_qpc=x.call.entered_qpc;
  if(reading&&(x.call.requested!=320||x.call.observed!=320)){stop(incoherent);return;}
  switch(a){
   case full_before:case full_after:{const u32 slot=a==full_before?0u:1u;const auto& h=out_.held[slot];const auto& image=out_.images[slot];const auto& q=image.query;
    u32 matches=0;for(u32 index=0;index<r().call_count;++index)if(equal(call_slot(out_,index),&q,64))++matches;
    if(matches!=1||q.operation!=operation(Primitive::image_name)||!BOOL_error(q)||q.entered!=1||q.returned!=1||q.raw_bool==0||q.requested!=260||q.observed!=image.chars||!tick(in_.plan,q.entered_qpc)||q.entered_qpc<prior_last||q.returned_qpc<q.entered_qpc||q.returned_qpc>x.call.entered_qpc
      ||!same_path(image.path,image.chars,in_.target_path,in_.plan.target_path_chars)||nonzero(image.reserved,20)){stop(identity_changed);return;}
    if(!full(h,out_.identities[slot],out_.security[slot],in_.plan,in_.identity,in_.security)){if(h.resources_clean!=1||h.uncertain)r().resources_clean=0;stop(identity_changed);return;}
    if(slot==0){r().identity_before=r().jobs_before=r().leases_before=1;action_=wait_first;}
    else{r().identity_after=r().jobs_after=r().leases_after=r().target_alive=1;
     if(r().resources_clean!=1||r().remote_outcome_unknown){stop(exception);return;}
     r().mapping_qualified=r().observation_complete=1;r().validation_passed=1;r().result_class=observed;stopped_=true;action_=complete;}break;}
   case wait_first:case wait_body:if(x.call.kind!=wait_kind||!(x.call.observed<=(a==wait_first?2u:1u)||x.call.observed==258)){stop(wait_failed);return;}if(x.call.observed==258){stop(wait_timeout);return;}if(x.call.observed==0)process_exit_seen_=true;action_=sample_process;break;
   case sample_process:if(x.call.observed!=0&&x.call.observed!=258){stop(wait_failed);return;}process_=static_cast<u32>(x.call.observed);if(process_==0)process_exit_seen_=true;action_=sample_entered;break;
   case sample_entered:if(x.call.observed!=0&&x.call.observed!=258){stop(wait_failed);return;}enter_=static_cast<u32>(x.call.observed);r().entered_observed|=enter_==0;action_=sample_body;break;
   case sample_body:if(x.call.observed!=0&&x.call.observed!=258){stop(wait_failed);return;}body_=static_cast<u32>(x.call.observed);r().body_observed|=body_==0;
    if(process_exit_seen_){stop(target_exited);return;}if(second_phase_){if(body_!=0||enter_!=0){stop(body_missing);return;}action_=middle_generation;}
    else if(enter_==0)action_=body_==0?middle_generation:progress_read_first;else{stop(body_missing);return;}break;
   case progress_read_first:action_=progress_read_second;break;
   case progress_read_second:read_done(false);break;
   case middle_generation:if(!members(x.generation,in_.plan)){if(x.generation.resources_clean!=1||x.generation.uncertain)r().resources_clean=0;stop(identity_changed);return;}action_=body_read_first;break;
   case body_read_first:action_=body_read_second;break;
   case body_read_second:read_done(true);break;
   case region_before:if(!region(x.memory,out_.markers[3].module_base)){stop(region_rejected);return;}action_=name_before;break;
   case name_before:case name_after:if(x.call.observed==0||x.call.observed>=1024||x.call.observed!=in_.plan.marker_nt_path_chars
     ||!text(x.name,static_cast<u32>(x.call.observed),1024)||!equal(x.name,in_.marker_nt,(in_.plan.marker_nt_path_chars+1)*2)){stop(name_rejected);return;}
    action_=a==name_before?read_headers:full_after;break;
   case read_headers:if(x.call.raw_bool==0||x.call.requested!=4096||x.call.observed!=4096||!headers(out_.pe_header,in_.plan.marker_pe)){stop(headers_rejected);return;}action_=region_after;break;
   case region_after:if(!region(x.memory,out_.markers[3].module_base)||!equal(&out_.regions[0],&out_.regions[1],sizeof(CMM_MEMORY64))){stop(mapping_changed);return;}action_=name_after;break;
   default:stop(rejected);break;
  }
 }
 void caught(u32 code){r().exception_code=code;r().resources_clean=0;r().within_window=0;r().return_clock_known=0;stop(exception);}
};

// Injected execution seam: fake and future Win32 adapters share this driver.
// Backend.invoke appends every nonterminal primitive receipt with record(),
// then returns its LAST actual primitive call plus the typed data. accept()
// records that last call once OR references the exact committed tail once;
// action ticket/range is separate from the raw primitive operation. A partial
// group may reject, never manufacture success from its final cleanup return.
// It must never call a new API
// without reserving room, and cannot return a self-qualified identity bool.
template<class Backend> void observe(Backend& api,const Inputs& inputs,CMM_OUTPUT24576& out){Observer machine(inputs,out);
 try{while(!machine.stopped()){if(!machine.room()){CMM_CALL64 dummy{};machine.record(dummy);break;}const Action action=machine.next();if(!machine.begin_action())break;Return returned=api.invoke(action,machine);machine.accept(returned);}}
 catch(...){machine.caught(0xe06d7363u);}}
} // namespace cmm
