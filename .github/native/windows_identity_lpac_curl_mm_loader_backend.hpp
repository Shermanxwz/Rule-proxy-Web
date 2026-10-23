#pragma once
#include "windows_identity_lpac_curl_mm_loader_win32.hpp"
namespace cmm { namespace win32 {
inline bool safe_copy(void* to,const void* from,std::size_t n) noexcept {__try{std::memcpy(to,from,n);return true;}__except(EXCEPTION_EXECUTE_HANDLER){return false;}}
inline bool scan_text(std::uint16_t* to,u32* chars,const std::uint16_t* from,u32 cap) noexcept {
 __try{for(u32 i=0;i<cap;++i){to[i]=from[i];if(!to[i]){*chars=i;return i!=0;}}return false;}__except(EXCEPTION_EXECUTE_HANDLER){return false;}}
inline bool copy_sid_from(const std::uint8_t* buffer,u32 bytes,const void* pointer,std::uint8_t* out,u32& count){
 const auto base=U(buffer),p=U(pointer);if(p<base||p-base>bytes||bytes-(p-base)<8)return false;
 const auto* b=static_cast<const std::uint8_t*>(pointer);const u32 n=8u+4u*b[1];if(n>bytes-(p-base)||!sid(b,n))return false;
 std::memcpy(out,b,n);count=n;return true;
}
class NativeBackend {
 const Inputs& in_;CMM_OUTPUT24576& out_;u64 borrowed_[9];RawOwners owners_;EndpointOnce endpoints_;
 Observer* machine_=nullptr;Return result_{};u32 failure_=0,primary_=0xffffffffu;FailureReason reason_=FailureReason::validation;
 u32 last_index_=0xffffffffu;bool no_call_=false;u64 last_tick_=0;u64 marker_address_=0;
 void fail(u32 klass,u32 index,FailureReason why){if(!failure_){failure_=klass;primary_=index;reason_=why;}}
 bool pre(Args& a,bool closing=false){u64 q=0;const bool known=qpc(q);a.raw.entered_qpc=known?q:0;
  if(!closing&&(!known||!tick(in_.plan,q)||q<last_tick_)){fail(late_clock,last_index_,FailureReason::postclock);return false;}
  if(known)last_tick_=q;return true;}
 void post(Args& a,u32 index){u64 q=0;const bool known=qpc(q);
  if(a.raw.returned==1){if(!endpoints_.finish(index,known?q:0,known))fail(exception,index,FailureReason::validation);}
  a.raw=*call_slot(out_,index);last_index_=index;
  if(!known||q<last_tick_||!tick(in_.plan,q)){fail(late_clock,index,FailureReason::postclock);}
  else last_tick_=q;
 }
 bool run(Args& a,u32 allocation=0,AllocationSuccess success=AllocationSuccess::nonzero_BOOL){
  if(failure_)return false;if(!pre(a))return false;
  if(a.raw.operation==operation(Primitive::wait_first)||a.raw.operation==operation(Primitive::wait_body)){
   const u64 remaining=in_.plan.window_end-a.raw.entered_qpc;
   // Conservative integer milliseconds from this actual pre-QPC. Subtract1
   // after bounded floating conversion to avoid rounding upward at a boundary.
   u64 ms=static_cast<u64>((static_cast<long double>(remaining)*1000)/in_.plan.frequency);if(ms)--ms;a.raw.requested=ms;
  }
  if(!owners_.before_api(allocation)){fail(capacity,last_index_,FailureReason::validation);return false;}
  primitive(&a);if(a.exception_code&&!out_.result.exception_code)out_.result.exception_code=a.exception_code;bool resource=true;
  if(allocation)resource=owners_.returned_allocation(a.raw,a.raw.observed,success);
  else resource=owners_.returned_plain(a.raw);
  const u32 index=owners_.last_index();if(index==0xffffffffu){fail(capacity,last_index_,FailureReason::validation);return false;}post(a,index);
  if(a.raw.returned!=1){fail(exception,index,FailureReason::exception);return false;}
  if(!resource){fail(identity_changed,index,actual_failure(a.raw)?FailureReason::api_return:FailureReason::validation);return false;}
  return failure_==0;
 }
 Args args(Primitive op,u32 kind,u64 requested,u64 object=0){Args a{};a.raw.operation=operation(op);a.raw.kind=kind;a.raw.requested=requested;a.object=object;return a;}
 bool yes(const Args& a,u32 klass=identity_changed){if(a.raw.raw_bool==0){fail(klass,last_index_,FailureReason::api_return);return false;}return true;}
 bool condition(bool ok,u32 klass=identity_changed){if(!ok)fail(klass,last_index_,FailureReason::validation);return ok;}
 bool close_one(u64 value,Primitive op,bool local){
  if(owners_.take_close(value)!=value){fail(exception,last_index_,FailureReason::validation);return false;}
  auto a=args(op,local?pointer_kind:boolean_kind,value,value);pre(a,true);primitive(&a);if(a.exception_code&&!out_.result.exception_code)out_.result.exception_code=a.exception_code;
  const bool ok=owners_.returned_close(a.raw,local?CloseSuccess::null_pointer:CloseSuccess::nonzero_BOOL);
  const u32 index=owners_.last_index();if(index!=0xffffffffu)post(a,index);else fail(capacity,last_index_,FailureReason::validation);
  if(!ok)fail(exception,index,actual_failure(a.raw)?FailureReason::api_return:FailureReason::exception);return ok&&failure_==0;
 }
 // Known owners are at most token, SD, SDDL. They are closed in reverse order
 // even after an earlier close failed, clock is late, or normal room ran out.
 void unwind(){while(owners_.pending()){
   const u64 value=owners_.pending_at(owners_.pending()-1);Primitive close_op=Primitive::current_token_close;bool local=false;
   for(u32 i=out_.result.call_count;i>machine_->trace_start();--i){const auto* row=call_slot(out_,i-1);if(row->observed!=value)continue;
    const auto op=static_cast<Primitive>(row->operation);
    if(op==Primitive::current_token_open){close_op=Primitive::current_token_close;break;}
    if(op==Primitive::process_sd_get){close_op=Primitive::process_sd_free;local=true;break;}
    if(op==Primitive::process_sd_text){close_op=Primitive::process_sd_text_free;local=true;break;}
    if(op==Primitive::thread_sd_get){close_op=Primitive::thread_sd_free;local=true;break;}
    if(op==Primitive::thread_sd_text){close_op=Primitive::thread_sd_text_free;local=true;break;}
   }close_one(value,close_op,local);
  }}
 bool generation(CMM_GENERATION64& g,bool middle){g.size=64;g.version=2;
  auto a=args(middle?Primitive::middle_process_id:Primitive::process_id,count_kind,in_.plan.process,in_.plan.process);
  bool ok=run(a);g.pid=static_cast<u32>(a.raw.observed);if(!ok||!condition(g.pid==in_.plan.target_pid))return false;
  a=args(middle?Primitive::middle_process_times:Primitive::process_times,boolean_kind,in_.plan.process,in_.plan.process);
  ok=run(a);g.creation=a.raw.observed;if(!ok||!yes(a)||!condition(g.creation==in_.plan.target_creation))return false;
  a=args(middle?Primitive::middle_process_wait0:Primitive::process_wait0,wait_kind,0,in_.plan.process);
  ok=run(a);g.alive=a.raw.observed==WAIT_TIMEOUT;g.exited=a.raw.observed==WAIT_OBJECT_0;
  if(!ok||!condition(g.alive==1,target_exited))return false;
  a=args(middle?Primitive::middle_thread_process_id:Primitive::thread_process_id,count_kind,in_.plan.thread,in_.plan.thread);
  ok=run(a);g.thread_pid=static_cast<u32>(a.raw.observed);return ok&&condition(g.thread_pid==in_.plan.target_pid);
 }
 bool member(CMM_GENERATION64& g,bool outer,bool middle){const u64 job=outer?in_.plan.outer_job:in_.plan.inner_job;
  auto a=args(middle?(outer?Primitive::middle_outer_member:Primitive::middle_inner_member):(outer?Primitive::outer_member:Primitive::inner_member),boolean_kind,job,in_.plan.process);a.aux=job;
  const bool ok=run(a);if(outer){g.outer_api=a.raw.raw_bool;g.outer_error=a.raw.error;g.outer_member=static_cast<u32>(a.raw.observed);}
  else{g.inner_api=a.raw.raw_bool;g.inner_error=a.raw.error;g.inner_member=static_cast<u32>(a.raw.observed);}
  return ok&&yes(a)&&condition(a.raw.observed==1);
 }
 bool image(CMM_IMAGE608& image_sample){auto a=args(Primitive::image_name,boolean_kind,260,in_.plan.process);a.buffer=image_sample.path;a.capacity=260;
  const bool ok=run(a);image_sample.query=a.raw;image_sample.chars=static_cast<u32>(a.raw.observed);
  return ok&&yes(a)&&condition(same_path(image_sample.path,image_sample.chars,in_.target_path,in_.plan.target_path_chars));
 }
 bool token(CMM_IDENTITY256& id){id.size=256;id.version=2;auto a=args(Primitive::current_token_open,boolean_kind,in_.plan.process,in_.plan.process);
  if(!run(a,1))return false;const u64 token_handle=a.raw.observed;
  const Primitive scalar_ops[]={Primitive::token_type,Primitive::token_session,Primitive::token_is_ac,Primitive::token_elevation,Primitive::token_ui_access};
  const u32 scalar_classes[]={8,12,29,20,26};u32* fields[]={&id.token_type,&id.session_id,&id.is_appcontainer,&id.elevated,&id.ui_access};
  for(unsigned i=0;i<5;++i){u32 value=0;a=args(scalar_ops[i],boolean_kind,4,token_handle);a.buffer=&value;a.capacity=4;a.info_class=scalar_classes[i];a.token_encoding=1;
   const bool ok=run(a);*fields[i]=value;if(!ok||!yes(a)||!condition(a.returned_length==4))return false;
   const u32 expected[]={in_.identity.token_type,in_.identity.session_id,in_.identity.is_appcontainer,in_.identity.elevated,in_.identity.ui_access};if(!condition(value==expected[i]))return false;}
  const Primitive probes[]={Primitive::token_user_probe,Primitive::token_il_probe,Primitive::token_caps_probe,Primitive::token_acsid_probe,Primitive::token_stats_probe};
  const Primitive fills[]={Primitive::token_user_fill,Primitive::token_il_fill,Primitive::token_caps_fill,Primitive::token_acsid_fill,Primitive::token_stats_fill};
  const u32 classes[]={1,25,30,31,10};
  for(unsigned i=0;i<5;++i){a=args(probes[i],boolean_kind,0,token_handle);a.info_class=classes[i];if(!run(a))return false;
   if(!condition(a.raw.raw_bool==0&&a.raw.error_valid==1&&a.raw.error==ERROR_INSUFFICIENT_BUFFER&&a.returned_length>0&&a.returned_length<=4096))return false;
   const u32 need=a.returned_length;if(i==4&&!condition(need==56))return false;
   alignas(8) std::uint8_t scratch[4096]{};a=args(fills[i],boolean_kind,need,token_handle);a.info_class=classes[i];a.buffer=scratch;a.capacity=need;a.token_encoding=i==2?1u:i==4?2u:0u;
   const bool parsed_clock=run(a);if(a.raw.returned!=1||!yes(a)||!condition(a.returned_length==need))return false;
   if(i==0){if(!condition(need>=sizeof(TOKEN_USER)&&copy_sid_from(scratch,need,reinterpret_cast<TOKEN_USER*>(scratch)->User.Sid,id.user_sid,id.user_sid_bytes)))return false;
    if(!condition(id.user_sid_bytes==in_.identity.user_sid_bytes&&equal(id.user_sid,in_.identity.user_sid,id.user_sid_bytes)))return false;}
   if(i==1){std::uint8_t label[68]{};u32 length=0;
    if(!condition(need>=sizeof(TOKEN_MANDATORY_LABEL)&&copy_sid_from(scratch,need,reinterpret_cast<TOKEN_MANDATORY_LABEL*>(scratch)->Label.Sid,label,length)))return false;
    if(!condition(length>=12&&label[1]==1&&label[2]==0&&label[3]==0&&label[4]==0&&label[5]==0&&label[6]==0&&label[7]==16))return false;
    id.integrity_rid=le32(label+8);if(!condition(id.integrity_rid==4096))return false;}
   if(i==2){if(!condition(need>=4))return false;id.capability_count=le32(scratch);if(!condition(id.capability_count==0))return false;}
   if(i==3){if(!condition(need>=sizeof(TOKEN_APPCONTAINER_INFORMATION)&&copy_sid_from(scratch,need,reinterpret_cast<TOKEN_APPCONTAINER_INFORMATION*>(scratch)->TokenAppContainer,id.appcontainer_sid,id.appcontainer_sid_bytes)))return false;
    if(!condition(id.appcontainer_sid_bytes==in_.identity.appcontainer_sid_bytes&&equal(id.appcontainer_sid,in_.identity.appcontainer_sid,id.appcontainer_sid_bytes)))return false;}
   if(i==4){const auto* stats=reinterpret_cast<const TOKEN_STATISTICS*>(scratch);id.token_id=(static_cast<u64>(static_cast<u32>(stats->TokenId.HighPart))<<32)|stats->TokenId.LowPart;
    id.authentication_id=(static_cast<u64>(static_cast<u32>(stats->AuthenticationId.HighPart))<<32)|stats->AuthenticationId.LowPart;
    // TOKEN_PRIMARY has no applicable impersonation level; canonical NA marker.
    id.impersonation_level=0xffffffffu;if(!condition(stats->TokenType==TokenPrimary))return false;}
   if(!parsed_clock)return false;
  }
  if(!condition(identity_shape(id)&&equal(&id,&in_.identity,256)))return false;
  return close_one(token_handle,Primitive::current_token_close,false);
 }
 bool security(bool thread,CMM_SECURITY1024& sd){const u64 object=thread?in_.plan.thread:in_.plan.process;
  auto a=args(thread?Primitive::thread_sd_get:Primitive::process_sd_get,status_kind,object,object);
  if(!run(a,1,AllocationSuccess::zero_status))return false;const u64 descriptor=a.raw.observed;
  a=args(thread?Primitive::thread_sd_text:Primitive::process_sd_text,boolean_kind,descriptor,descriptor);
  const bool parsed_clock=run(a,1);if(a.raw.returned!=1||a.raw.raw_bool==0||owners_.uncertain())return false;const u64 string=a.raw.observed;u32 chars=0;auto* destination=thread?sd.thread:sd.process;
  if(!condition(scan_text(destination,&chars,reinterpret_cast<const std::uint16_t*>(static_cast<std::uintptr_t>(string)),248),exception))return false;
  if(thread)sd.thread_chars=chars;else sd.process_chars=chars;
  if(!parsed_clock)return false;
  if(!condition(exact_private_sd(destination,chars,in_.identity)))return false;
  if(!close_one(string,thread?Primitive::thread_sd_text_free:Primitive::process_sd_text_free,true))return false;
  return close_one(descriptor,thread?Primitive::thread_sd_free:Primitive::process_sd_free,true);
 }
 bool job(bool outer,CMM_HELD192& h){CMM_GENERATION64 g{};if(!member(g,outer,false)){if(outer){h.outer_api=g.outer_api;h.outer_error=g.outer_error;h.outer_member=g.outer_member;}else{h.inner_api=g.inner_api;h.inner_error=g.inner_error;h.inner_member=g.inner_member;}return false;}
  if(outer){h.outer_api=g.outer_api;h.outer_error=g.outer_error;h.outer_member=g.outer_member;}else{h.inner_api=g.inner_api;h.inner_error=g.inner_error;h.inner_member=g.inner_member;}
  const u64 object=outer?in_.plan.outer_job:in_.plan.inner_job;auto a=args(outer?Primitive::outer_flags:Primitive::inner_flags,boolean_kind,object,object);
  bool ok=run(a);if(outer)h.outer_handle_flags=a.scalar;else h.inner_handle_flags=a.scalar;if(!ok||!yes(a)||!condition(a.scalar==0))return false;
  a=args(outer?Primitive::outer_limits:Primitive::inner_limits,boolean_kind,pack(JobObjectExtendedLimitInformation,144),object);
  ok=run(a);if(outer)h.outer_limit_flags=a.limits.BasicLimitInformation.LimitFlags;else h.inner_limit_flags=a.limits.BasicLimitInformation.LimitFlags;
  if(!ok||!yes(a)||!condition(a.returned_length==144&&a.limits.BasicLimitInformation.LimitFlags==JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE))return false;
  a=args(outer?Primitive::outer_ui:Primitive::inner_ui,boolean_kind,pack(JobObjectBasicUIRestrictions,4),object);
  ok=run(a);if(outer)h.outer_ui_limits=a.ui.UIRestrictionsClass;else h.inner_ui_limits=a.ui.UIRestrictionsClass;
  return ok&&yes(a)&&condition(a.returned_length==4&&a.ui.UIRestrictionsClass==0);
 }
 bool lease(bool marker,CMM_HELD192& h){const u64 object=marker?in_.plan.marker_lease:in_.plan.target_lease;
  auto a=args(marker?Primitive::marker_lease_flags:Primitive::target_lease_flags,boolean_kind,object,object);if(!run(a)||!yes(a)||!condition(a.scalar==0,lease_changed))return false;
  a=args(marker?Primitive::marker_lease_tag:Primitive::target_lease_tag,boolean_kind,8,object);if(!run(a)||!yes(a)||!condition(!(a.tag.FileAttributes&(FILE_ATTRIBUTE_DIRECTORY|FILE_ATTRIBUTE_REPARSE_POINT))&&a.tag.ReparseTag==0,lease_changed))return false;
  a=args(marker?Primitive::marker_lease_id:Primitive::target_lease_id,boolean_kind,24,object);bool ok=run(a);
  auto* id=marker?h.marker_file_id:h.target_file_id;std::memcpy(id,&a.file_id,24);if(!ok||!yes(a)||!condition(equal(id,marker?in_.plan.marker_file_id:in_.plan.target_file_id,24),lease_changed))return false;
  a=args(marker?Primitive::marker_lease_standard:Primitive::target_lease_standard,boolean_kind,24,object);ok=run(a);
  if(marker)h.marker_file_bytes=a.raw.observed;else h.target_file_bytes=a.raw.observed;
  if(!ok||!yes(a)||!condition(a.standard.EndOfFile.QuadPart>=0&&a.standard.DeletePending==0&&a.standard.Directory==0&&a.raw.observed==(marker?in_.plan.marker_file_bytes:in_.plan.target_file_bytes),lease_changed))return false;
  if(marker){h.lease_api=a.raw.raw_bool;h.lease_error=a.raw.error;}return true;
 }
 void full_group(){auto& h=result_.held;h.size=192;h.version=2;CMM_GENERATION64 g{};
  const bool ok=generation(g,false);h.pid=g.pid;h.thread_pid=g.thread_pid;h.creation=g.creation;h.alive=g.alive;h.exited=g.exited;
  if(!ok||!image(result_.image)||!token(result_.identity))return;h.identity_api=1;
  result_.security.size=1024;result_.security.version=2;if(!security(false,result_.security)||!security(true,result_.security))return;h.security_api=1;
  if(!job(false,h)||!job(true,h)||!lease(false,h)||!lease(true,h))return;
 }
public:
 NativeBackend(const Inputs& in,CMM_OUTPUT24576& out,u64 address,u64 initial_tick):in_(in),out_(out),borrowed_{in.plan.process,in.plan.thread,in.plan.primary_token,in.plan.inner_job,in.plan.outer_job,in.plan.entered_event,in.plan.body_event,in.plan.target_lease,in.plan.marker_lease},owners_(out,borrowed_,9),endpoints_(out),last_tick_(initial_tick),marker_address_(address){}
 Return invoke(Action action,Observer& machine){machine_=&machine;result_=Return{};result_.action=action;result_.action_ticket=machine.ticket();failure_=0;primary_=0xffffffffu;last_index_=0xffffffffu;no_call_=false;
  if(action==full_before||action==full_after)full_group();
  else if(action==middle_generation){if(generation(result_.generation,true)&&member(result_.generation,false,true)&&member(result_.generation,true,true))result_.generation.resources_clean=1;}
  else {Args a{};
   if(action==wait_first||action==wait_body){a=args(action==wait_first?Primitive::wait_first:Primitive::wait_body,wait_kind,0);
    a.capacity=action==wait_first?3u:2u;a.waits[0]=H(in_.plan.process);a.waits[1]=H(action==wait_first?in_.plan.entered_event:in_.plan.body_event);a.waits[2]=H(in_.plan.body_event);run(a);}
   else if(action==sample_process||action==sample_entered||action==sample_body){const auto op=action==sample_process?Primitive::sample_process:action==sample_entered?Primitive::sample_entered:Primitive::sample_body;
    a=args(op,wait_kind,0,action==sample_process?in_.plan.process:action==sample_entered?in_.plan.entered_event:in_.plan.body_event);run(a);}
   else if(action==progress_read_first||action==progress_read_second||action==body_read_first||action==body_read_second){const auto op=action==progress_read_first?Primitive::rpm_progress_first:action==progress_read_second?Primitive::rpm_progress_second:action==body_read_first?Primitive::rpm_body_first:Primitive::rpm_body_second;
    a=args(op,boolean_kind,320,in_.plan.process);a.aux=marker_address_;a.buffer=&result_.marker;a.capacity=320;run(a);
    if(a.raw.returned==1&&a.raw.raw_bool==0){failure_=(action==progress_read_first||action==body_read_first)?read_first_false:read_second_false;primary_=last_index_;reason_=FailureReason::api_return;}}
   else if(action==region_before||action==region_after){a=args(action==region_before?Primitive::region_before:Primitive::region_after,count_kind,48,in_.plan.process);a.aux=out_.markers[3].module_base;run(a);
    auto& m=result_.memory;m.size=64;m.version=2;m.base=U(a.memory.BaseAddress);m.allocation_base=U(a.memory.AllocationBase);m.region_bytes=a.memory.RegionSize;m.allocation_protect=a.memory.AllocationProtect;m.state=a.memory.State;m.protect=a.memory.Protect;m.type=a.memory.Type;m.returned_bytes=static_cast<u32>(a.raw.observed);m.error=a.raw.error;}
   else if(action==name_before||action==name_after){a=args(action==name_before?Primitive::mapped_name_before:Primitive::mapped_name_after,count_kind,1024,in_.plan.process);a.aux=out_.markers[3].module_base;a.buffer=result_.name;a.capacity=1024;run(a);}
   else if(action==read_headers){a=args(Primitive::rpm_pe,boolean_kind,4096,in_.plan.process);a.aux=out_.markers[3].module_base;a.buffer=result_.pe;a.capacity=4096;run(a);}
   else fail(rejected,last_index_,FailureReason::validation);
  }
  if(failure_)unwind();
  if(action==full_before||action==full_after){result_.held.resources_clean=owners_.clean()?1u:0u;result_.held.uncertain=owners_.uncertain()?1u:0u;}
  if(action==middle_generation){result_.generation.resources_clean=owners_.clean()?1u:0u;result_.generation.uncertain=owners_.uncertain()?1u:0u;}
  if(out_.result.call_count==machine.trace_start()){no_call_=true;return result_;}
  result_.record_mode=RecordMode::already_committed;result_.terminal_index=out_.result.call_count-1;result_.call=*call_slot(out_,result_.terminal_index);
  if(failure_){result_.group_state=GroupState::partial;result_.primary_failure_index=primary_>=machine.trace_start()&&primary_<=result_.terminal_index?primary_:result_.terminal_index;
   result_.failure_reason=reason_;result_.partial_class=failure_;}
  return result_;
 }
 u32 pending()const{return owners_.pending();}
 bool no_call()const{return no_call_;}u32 failure_class()const{return failure_?failure_:exception;}
};
}} // namespace cmm::win32
