// Inert production-core harness. No Win32 header/API, DLL, target or network.
#include "../.github/native/windows_identity_lpac_curl_mm_loader_marker_core.hpp"
#include <cstdlib>
#include <iostream>
#include <vector>
using cmm::u32;using cmm::u64;
static unsigned checks=0;
static void check(bool value){++checks;if(!value)std::abort();}
static void text16(std::uint16_t* out,const char* source){while(*source)*out++=static_cast<std::uint16_t>(*source++);*out=0;}
static u32 length16(const std::uint16_t* p){u32 n=0;while(p[n])++n;return n;}
static void put16(std::uint8_t* p,u32 x){p[0]=static_cast<std::uint8_t>(x);p[1]=static_cast<std::uint8_t>(x>>8);}
static void put32(std::uint8_t* p,u32 x){for(unsigned i=0;i<4;++i)p[i]=static_cast<std::uint8_t>(x>>(8*i));}
static cmm::Inputs inputs(){cmm::Inputs i{};auto& p=i.plan;p.size=512;p.version=2;p.frequency=10;p.root_start=1000;p.root_deadline=2200;p.window_start=1100;p.window_end=1180;p.target_pid=42;p.target_creation=133000000000000000ull;
 p.process=11;p.thread=12;p.primary_token=13;p.inner_job=14;p.outer_job=15;p.entered_event=16;p.body_event=17;p.target_lease=18;p.marker_lease=19;
 p.identity_bytes=256;p.security_bytes=1024;p.target_file_bytes=100000;p.marker_file_bytes=200000;
 for(unsigned n=0;n<16;++n)p.run[n]=1;for(unsigned n=0;n<32;++n)p.config_sha256[n]=p.source_sha256[n]=p.target_sha256[n]=p.marker_sha256[n]=2;
 p.target_file_id[0]=3;p.marker_file_id[0]=4;
 p.target_pe={32,0x8664,123,0x1000,0x4000,512,2,0};p.marker_pe=p.target_pe;p.marker_pe.is_dll=1;
 text16(i.marker_nt,"\\Device\\HarddiskVolume1\\fixed\\marker.dll");p.marker_nt_path_chars=length16(i.marker_nt);
 text16(i.target_path,"C:\\Windows\\System32\\curl.exe");p.target_path_chars=length16(i.target_path);
 auto& id=i.identity;id.size=256;id.version=2;id.user_sid_bytes=12;id.user_sid[0]=1;id.user_sid[1]=1;id.user_sid[7]=5;id.user_sid[8]=21;
 id.appcontainer_sid_bytes=16;id.appcontainer_sid[0]=1;id.appcontainer_sid[1]=2;id.appcontainer_sid[7]=15;id.appcontainer_sid[8]=2;id.appcontainer_sid[12]=1;
 id.session_id=1;id.token_type=1;id.impersonation_level=0xffffffffu;id.integrity_rid=4096;id.is_appcontainer=1;id.token_id=12345;id.authentication_id=456;
 auto& sd=i.security;sd.size=1024;sd.version=2;text16(sd.process,"D:P(A;;GA;;;SY)(A;;0x1fffff;;;S-1-5-21)");text16(sd.thread,"D:P(A;;0x1fffff;;;SY)(A;;GA;;;S-1-5-21)");sd.process_chars=length16(sd.process);sd.thread_chars=length16(sd.thread);
 auto& m=i.initial;std::memcpy(m.magic,"CMM2",4);m.version=2;m.size=320;std::memcpy(m.run,p.run,16);std::memcpy(m.config_sha256,p.config_sha256,32);std::memcpy(m.source_sha256,p.source_sha256,32);std::memcpy(m.marker_sha256,p.marker_sha256,32);
 m.frequency=p.frequency;m.root_start=p.root_start;m.root_deadline=p.root_deadline;m.window_start=p.window_start;m.window_end=p.window_end;m.target_pid=p.target_pid;m.target_creation=p.target_creation;m.entered_signal=101;m.body_signal=102;m.status_size=128;m.status_version=2;
 return i;}
static CMM_MARKER320 complete_marker(const cmm::Inputs& i){auto m=i.initial;m.flags=6143;m.restore_bool=m.entered_bool=m.body_bool=1;m.last_qpc=1101;m.writer_pid=m.target_pid;m.sequence=20;m.module_base=0x180000000ull;m.module_base_known=1;return m;}
static CMM_HELD192 held(const cmm::Inputs& i){CMM_HELD192 h{};h.size=192;h.version=2;h.pid=h.thread_pid=i.plan.target_pid;h.creation=i.plan.target_creation;h.alive=1;h.identity_api=h.security_api=h.inner_api=h.outer_api=h.lease_api=1;h.inner_member=h.outer_member=1;h.inner_limit_flags=h.outer_limit_flags=0x2000;
 std::memcpy(h.target_file_id,i.plan.target_file_id,24);std::memcpy(h.marker_file_id,i.plan.marker_file_id,24);h.target_file_bytes=i.plan.target_file_bytes;h.marker_file_bytes=i.plan.marker_file_bytes;h.resources_clean=1;return h;}
static CMM_GENERATION64 generation(const cmm::Inputs& i){CMM_GENERATION64 g{};g.size=64;g.version=2;g.pid=g.thread_pid=i.plan.target_pid;g.creation=i.plan.target_creation;g.alive=1;g.inner_api=g.outer_api=1;g.inner_member=g.outer_member=1;g.resources_clean=1;return g;}
enum Fault {good=0,current_token_before,current_token_after,job_member_false,unknown_token_close,false_error0,short_read,base_changed,private_region,wrong_name,wrong_pe,changed_region,late_read,exited_with_events,body_delayed,thrown_after_return,execute_only,high_image_base,wait_exit_then_alive,pretty_memory_failed_primitive,bad_body_wait_index,sticky_resource_failure,wrong_current_image};
struct Backend {
 cmm::Inputs in;Fault fault;u64 now=1102;std::vector<cmm::Action> actions;unsigned round=0;CMM_OUTPUT24576* output=nullptr;
 explicit Backend(Fault f=good):in(inputs()),fault(f){}
 cmm::Return invoke(cmm::Action a,cmm::Observer& machine){actions.push_back(a);cmm::Return x{};x.action=a;x.action_ticket=machine.ticket();
  switch(a){
   case cmm::full_before:case cmm::full_after:x.call.operation=cmm::operation(cmm::Primitive::marker_lease_standard);break;
   case cmm::wait_first:x.call.operation=cmm::operation(cmm::Primitive::wait_first);break;
   case cmm::wait_body:x.call.operation=cmm::operation(cmm::Primitive::wait_body);break;
   case cmm::sample_process:x.call.operation=cmm::operation(cmm::Primitive::sample_process);break;
   case cmm::sample_entered:x.call.operation=cmm::operation(cmm::Primitive::sample_entered);break;
   case cmm::sample_body:x.call.operation=cmm::operation(cmm::Primitive::sample_body);break;
   case cmm::middle_generation:x.call.operation=cmm::operation(cmm::Primitive::middle_outer_member);break;
   case cmm::progress_read_first:x.call.operation=cmm::operation(cmm::Primitive::rpm_progress_first);break;
   case cmm::progress_read_second:x.call.operation=cmm::operation(cmm::Primitive::rpm_progress_second);break;
   case cmm::body_read_first:x.call.operation=cmm::operation(cmm::Primitive::rpm_body_first);break;
   case cmm::body_read_second:x.call.operation=cmm::operation(cmm::Primitive::rpm_body_second);break;
   case cmm::region_before:x.call.operation=cmm::operation(cmm::Primitive::region_before);break;
   case cmm::region_after:x.call.operation=cmm::operation(cmm::Primitive::region_after);break;
   case cmm::name_before:x.call.operation=cmm::operation(cmm::Primitive::mapped_name_before);break;
   case cmm::name_after:x.call.operation=cmm::operation(cmm::Primitive::mapped_name_after);break;
   case cmm::read_headers:x.call.operation=cmm::operation(cmm::Primitive::rpm_pe);break;
   default:break;
  }x.call.entered=x.call.returned=1;x.call.raw_bool=1;x.call.entered_qpc=now++;x.call.returned_qpc=now++;
  x.call.kind=cmm::boolean_kind;
  if(a==cmm::full_before||a==cmm::full_after){x.held=held(in);x.identity=in.identity;x.security=in.security;x.call.requested=24;x.call.observed=x.held.marker_file_bytes;
   x.image.query=x.call;x.image.query.operation=cmm::operation(cmm::Primitive::image_name);x.image.query.requested=260;x.image.query.observed=in.plan.target_path_chars;x.image.chars=in.plan.target_path_chars;std::memcpy(x.image.path,in.target_path,sizeof(x.image.path));if(fault==wrong_current_image)x.image.path[3]='X';
   check(machine.record(x.image.query));x.call.entered_qpc=now++;x.call.returned_qpc=now++;
   if((fault==current_token_before&&a==cmm::full_before)||(fault==current_token_after&&a==cmm::full_after))++x.identity.token_id;
   if(fault==job_member_false)x.held.inner_member=0;
   if(fault==unknown_token_close){x.held.resources_clean=0;x.held.uncertain=1;}}
  if(fault==sticky_resource_failure&&a==cmm::full_after){check(output!=nullptr);const u64 borrowed[]={11,12,13};cmm::RawOwners ledger(*output,borrowed,3);CMM_CALL64 opened{};opened.kind=cmm::boolean_kind;opened.entered=opened.returned=1;opened.raw_bool=1;opened.observed=700;
   check(ledger.before_api(1));check(ledger.returned_allocation(opened,700,cmm::AllocationSuccess::nonzero_BOOL));check(ledger.take_close(700)==700);CMM_CALL64 closed{};closed.kind=cmm::boolean_kind;closed.entered=closed.returned=1;closed.error_valid=1;closed.requested=700;check(!ledger.returned_close(closed,cmm::CloseSuccess::nonzero_BOOL));}
  else if(a==cmm::wait_first||a==cmm::wait_body){x.call.kind=cmm::wait_kind;x.call.raw_bool=0;x.call.observed=fault==wait_exit_then_alive?0:1;if(a==cmm::wait_body){++round;if(fault==bad_body_wait_index)x.call.observed=2;}}
  else if(a==cmm::sample_process){x.call.kind=cmm::wait_kind;x.call.raw_bool=0;x.call.observed=fault==exited_with_events?0:258;}
  else if(a==cmm::sample_entered){x.call.kind=cmm::wait_kind;x.call.raw_bool=0;x.call.observed=0;}
  else if(a==cmm::sample_body){x.call.kind=cmm::wait_kind;x.call.raw_bool=0;x.call.observed=(fault==body_delayed||fault==bad_body_wait_index)&&round==0?258:0;}
  else if(a==cmm::middle_generation){x.generation=generation(in);x.call.requested=4;x.call.observed=1;}
  else if(a==cmm::progress_read_first||a==cmm::progress_read_second||a==cmm::body_read_first||a==cmm::body_read_second){x.marker=complete_marker(in);x.call.requested=x.call.observed=320;
   if(a==cmm::body_read_first&&fault==false_error0){x.call.raw_bool=0;x.call.error=0;x.call.error_valid=1;x.call.observed=0;}
   if(a==cmm::body_read_first&&fault==short_read)x.call.observed=319;
   if(a==cmm::body_read_second&&fault==base_changed)x.marker.module_base+=0x10000;
   if(fault==high_image_base)x.marker.module_base=0xffff800000000000ull;
   if(a==cmm::body_read_second&&fault==late_read)x.call.returned_qpc=in.plan.window_end;
   if(a==cmm::body_read_first&&fault==thrown_after_return){x.call.returned=0;x.call.raw_bool=0;}}
  else if(a==cmm::region_before||a==cmm::region_after){x.call.kind=cmm::count_kind;x.call.raw_bool=0;x.call.requested=x.call.observed=48;x.memory.size=64;x.memory.version=2;x.memory.base=x.memory.allocation_base=0x180000000ull;x.memory.region_bytes=4096;x.memory.state=0x1000;x.memory.type=0x1000000;x.memory.protect=4;x.memory.returned_bytes=48;
   if(fault==pretty_memory_failed_primitive){x.call.observed=0;x.call.error_valid=1;x.call.error=0;}
   if(fault==private_region)x.memory.type=0x20000;if(fault==execute_only)x.memory.protect=0x10;if(fault==changed_region&&a==cmm::region_after)x.memory.region_bytes=8192;}
  else if(a==cmm::name_before||a==cmm::name_after){x.call.kind=cmm::count_kind;x.call.raw_bool=0;x.call.requested=1024;std::memcpy(x.name,in.marker_nt,sizeof(x.name));x.call.observed=in.plan.marker_nt_path_chars;if(fault==wrong_name)x.name[10]^=1;}
  else if(a==cmm::read_headers){x.call.requested=x.call.observed=4096;x.pe[0]='M';x.pe[1]='Z';put32(x.pe+60,128);std::memcpy(x.pe+128,"PE\0\0",4);auto* f=x.pe+132;put16(f,0x8664);put32(f+4,123);put16(f+16,240);put16(f+18,0x2000);auto* o=f+20;put16(o,0x20b);put32(o+16,0x1000);put32(o+56,0x4000);put32(o+60,512);put16(o+68,2);if(fault==wrong_pe)o[16]^=1;}
  return x;}
};
static CMM_OUTPUT24576 exercise(Fault f=good){Backend b(f);CMM_OUTPUT24576 out{};b.output=&out;cmm::observe(b,b.in,out);return out;}
static void observer_tests(){auto positive=exercise();check(positive.result.result_class==cmm::observed&&positive.result.observation_complete==1&&positive.result.mapping_qualified==1&&positive.result.held_count==2&&positive.result.snapshot_count==2);
 Backend ready;CMM_OUTPUT24576 direct{};cmm::observe(ready,ready.in,direct);for(auto a:ready.actions)check(a!=cmm::progress_read_first&&a!=cmm::progress_read_second&&a!=cmm::wait_body);check(direct.result.snapshot_count==2);
 check(exercise(current_token_before).result.result_class==cmm::identity_changed);auto changed=exercise(current_token_after);check(changed.result.observation_complete==0&&changed.markers[3].module_base!=0&&changed.held[0].identity_api!=0);
 check(exercise(job_member_false).result.result_class==cmm::identity_changed);auto closed=exercise(unknown_token_close);check(!closed.result.resources_clean&&!closed.result.observation_complete);
 check(exercise(wrong_current_image).result.result_class==cmm::identity_changed);
 auto sticky=exercise(sticky_resource_failure);check(sticky.held[1].resources_clean==1&&sticky.result.resources_clean==0&&sticky.result.observation_complete==0&&sticky.result.result_class==cmm::exception);
 auto failed=exercise(false_error0);check(failed.result.result_class==cmm::read_first_false);check(failed.calls[failed.result.call_count-1].raw_bool==0&&failed.calls[failed.result.call_count-1].error_valid==1&&failed.calls[failed.result.call_count-1].error==0);
 check(exercise(short_read).result.result_class==cmm::incoherent);check(exercise(base_changed).result.result_class==cmm::incoherent);check(exercise(private_region).result.result_class==cmm::region_rejected);check(exercise(wrong_name).result.result_class==cmm::name_rejected);check(exercise(wrong_pe).result.result_class==cmm::headers_rejected);check(exercise(changed_region).result.result_class==cmm::mapping_changed);
 auto late=exercise(late_read);check(late.result.result_class==cmm::late_clock&&!late.result.observation_complete&&late.result.snapshot_count==2&&late.markers[3].module_base!=0);
 auto dead=exercise(exited_with_events);check(dead.result.result_class==cmm::target_exited&&dead.result.entered_observed&&dead.result.body_observed&&!dead.result.observation_complete);
 auto contradiction=exercise(wait_exit_then_alive);check(contradiction.result.result_class==cmm::target_exited&&contradiction.result.entered_observed&&contradiction.result.body_observed&&!contradiction.result.observation_complete);
 check(exercise(execute_only).result.result_class==cmm::region_rejected);check(exercise(high_image_base).result.result_class==cmm::incoherent);
 auto pretty=exercise(pretty_memory_failed_primitive);check(pretty.result.result_class==cmm::region_rejected&&!pretty.result.observation_complete&&pretty.regions[0].returned_bytes==48);check(pretty.calls[pretty.result.call_count-1].observed==0);
 Backend delayed(body_delayed);CMM_OUTPUT24576 out{};cmm::observe(delayed,delayed.in,out);check(out.result.result_class==cmm::observed&&out.result.snapshot_count==4);unsigned first=0,second=0;for(auto a:delayed.actions){first+=a==cmm::wait_first;second+=a==cmm::wait_body;}check(first==1&&second==1);
 check(exercise(bad_body_wait_index).result.result_class==cmm::wait_failed);
 auto exception=exercise(thrown_after_return);check(exception.result.result_class==cmm::exception&&!exception.result.resources_clean&&!exception.result.observation_complete);
 auto in=inputs();auto a=complete_marker(in),b=a;b.module_base+=0x10000;check(!cmm::coherent(a,b,in.initial));b=a;b.module_base_known=0;check(!cmm::coherent(a,b,in.initial));b=a;b.sequence|=1;check(!cmm::coherent(a,b,in.initial));
 for(const auto* name:{"D:(A;;GA;;;SY)(A;;GA;;;S-1-5-21)","D:P(A;;GA;;;S-1-5-21)(A;;GA;;;SY)","D:P(A;;0x1ffffe;;;SY)(A;;GA;;;S-1-5-21)","D:P(A;;GA;;;SY)(A;;GA;;;S-1-5-22)","D:P(A;;GA;;;SY)(A;;GA;;;S-1-5-21)(A;;GA;;;WD)"}){auto sd=in.security;std::memset(sd.process,0,sizeof(sd.process));text16(sd.process,name);sd.process_chars=length16(sd.process);check(!cmm::security_allowed(sd,in.identity));}}
static CMM_CALL64 call(bool success=true){CMM_CALL64 r{};r.operation=900;r.entered=r.returned=1;r.raw_bool=success?1:0;r.error_valid=success?0u:1u;r.kind=cmm::boolean_kind;return r;}
static CMM_CALL64 allocation(u64 pointer,bool success=true){auto r=call(success);r.observed=pointer;return r;}
static CMM_CALL64 closing(u64 pointer,bool success=true){auto r=call(success);r.requested=pointer;return r;}
static void ownership_tests(){CMM_OUTPUT24576 out{};const u64 borrowed[]={11,12,13};cmm::RawOwners ledger(out,borrowed,3);
 out.result.call_count=127;check(!ledger.before_api(1));check(out.result.call_count==127&&ledger.pending()==0);
 out.result.call_count=126;check(ledger.before_api(1));check(ledger.returned_allocation(allocation(100),100,cmm::AllocationSuccess::nonzero_BOOL));check(out.result.call_count==127&&ledger.pending()==1);check(!ledger.before_api());
 check(ledger.take_close(100)==100);auto close=closing(100,false);close.error=0;check(!ledger.returned_close(close,cmm::CloseSuccess::nonzero_BOOL));check(out.result.call_count==128&&ledger.pending()==0&&ledger.uncertain());check(ledger.take_close(100)==0);check(out.calls_extra[63].raw_bool==0&&out.calls_extra[63].error_valid==1);
 CMM_OUTPUT24576 two{};cmm::RawOwners known(two,borrowed,3);for(u64 h:{100ull,101ull}){check(known.before_api(1));check(known.returned_allocation(allocation(h),h,cmm::AllocationSuccess::nonzero_BOOL));}
 check(known.take_close(100)==100);check(!known.returned_close(closing(100,false),cmm::CloseSuccess::nonzero_BOOL));check(known.take_close(101)==101);check(known.returned_close(closing(101),cmm::CloseSuccess::nonzero_BOOL));check(!known.clean()&&known.pending()==0);
 CMM_OUTPUT24576 wrong_close{};cmm::RawOwners wrong(wrong_close,borrowed,3);check(wrong.before_api(1));check(wrong.returned_allocation(allocation(600),600,cmm::AllocationSuccess::nonzero_BOOL));check(wrong.take_close(600)==600);check(!wrong.returned_close(closing(601),cmm::CloseSuccess::nonzero_BOOL));check(wrong.pending()==0&&wrong.uncertain()&&wrong_close.calls[1].requested==601);check(wrong.take_close(600)==0);
 for(u64 h:{0ull,11ull,0xffffffffffffffffull}){CMM_OUTPUT24576 bad{};cmm::RawOwners o(bad,borrowed,3);check(o.before_api(1));check(!o.returned_allocation(allocation(h),h,cmm::AllocationSuccess::nonzero_BOOL));check(o.uncertain()&&o.pending()==0&&o.take_close(h)==0);}
 CMM_OUTPUT24576 mismatch{};cmm::RawOwners unbound(mismatch,borrowed,3);check(unbound.before_api(1));check(!unbound.returned_allocation(allocation(100),101,cmm::AllocationSuccess::nonzero_BOOL));check(unbound.pending()==0&&unbound.uncertain()&&mismatch.calls[0].observed==100);
 CMM_OUTPUT24576 false_out{};cmm::RawOwners failed(false_out,borrowed,3);check(failed.before_api(1));check(!failed.returned_allocation(allocation(999,false),999,cmm::AllocationSuccess::nonzero_BOOL));check(failed.pending()==0&&failed.take_close(999)==0&&failed.uncertain());
 CMM_OUTPUT24576 null_unknown{};cmm::RawOwners no_contract(null_unknown,borrowed,3);check(no_contract.before_api(1));check(!no_contract.returned_allocation(call(false),0,cmm::AllocationSuccess::nonzero_BOOL));check(no_contract.uncertain());
 CMM_OUTPUT24576 null_known{};cmm::RawOwners reviewed(null_known,borrowed,3);check(reviewed.before_api(1));check(!reviewed.returned_allocation(call(false),0,cmm::AllocationSuccess::nonzero_BOOL,cmm::FailedOutputContract::known_no_owned_output));check(reviewed.clean()&&reviewed.pending()==0);check(null_known.result.call_count==1&&null_known.calls[0].raw_bool==0);
 CMM_OUTPUT24576 status{};cmm::RawOwners sd(status,borrowed,3);auto zero=call();zero.kind=cmm::status_kind;zero.raw_bool=0;zero.observed=700;check(sd.before_api(1));check(sd.returned_allocation(zero,700,cmm::AllocationSuccess::zero_status));check(status.calls[0].observed==700&&status.calls[0].raw_bool==0);check(sd.take_close(700)==700);auto freed=closing(700);freed.kind=cmm::pointer_kind;freed.observed=0;check(sd.returned_close(freed,cmm::CloseSuccess::null_pointer));check(sd.clean());
 CMM_OUTPUT24576 slots{};for(u32 i=0;i<128;++i){auto row=call();row.operation=i;check(cmm::append_raw(slots,row));}check(!cmm::append_raw(slots,call()));for(u32 i=0;i<128;++i)check(cmm::call_slot(slots,i)->operation==i);check(slots.calls[63].operation==63&&slots.calls_extra[0].operation==64);}

// Fresh07 handoff probes use the real Observer/RawOwners production seam.
// They are not a fake implementation of the future 46-API Win32 full group.
static CMM_CALL64 trace_call(cmm::Primitive primitive,u64 q=1102){auto r=call();r.operation=cmm::operation(primitive);r.entered_qpc=q;r.returned_qpc=q+1;return r;}
static cmm::Return partial(cmm::Observer& machine,const CMM_OUTPUT24576& out,u32 primary,cmm::FailureReason reason=cmm::FailureReason::api_return){
 cmm::Return r{};r.action=machine.next();r.action_ticket=machine.ticket();r.record_mode=cmm::RecordMode::already_committed;
 r.terminal_index=out.result.call_count-1;r.call=*cmm::call_slot(const_cast<CMM_OUTPUT24576&>(out),r.terminal_index);
 r.group_state=cmm::GroupState::partial;r.primary_failure_index=primary;r.failure_reason=reason;r.partial_class=cmm::identity_changed;
 r.held.size=192;r.held.version=2;r.held.resources_clean=1;r.identity=inputs().identity;return r;
}
static void terminal_tests(){
 // Complete group: last real FileStandardInfo row already committed, not twice.
 {Backend b;CMM_OUTPUT24576 out{};cmm::Observer m(b.in,out);check(m.begin_action());auto x=b.invoke(m.next(),m);check(m.record(x.call));
  x.record_mode=cmm::RecordMode::already_committed;x.terminal_index=out.result.call_count-1;const u32 n=out.result.call_count;m.accept(x);
  check(m.last_accepted()&&out.result.call_count==n&&out.result.held_count==1&&m.next()==cmm::wait_first);
  const auto saved=out.held[0];m.accept(x);check(!m.last_accepted()&&m.stopped()&&out.result.call_count==n&&cmm::equal(&saved,&out.held[0],192));}
 // Tail index, exact all-64-bytes, action and ticket cannot be borrowed/replayed.
 for(unsigned fault=0;fault<4;++fault){Backend b;CMM_OUTPUT24576 out{};cmm::Observer m(b.in,out);check(m.begin_action());auto x=b.invoke(m.next(),m);check(m.record(x.call));
  x.record_mode=cmm::RecordMode::already_committed;x.terminal_index=out.result.call_count-1;const u32 n=out.result.call_count;
  const auto first=*cmm::call_slot(out,0),tail=*cmm::call_slot(out,n-1);
  if(fault==0)x.terminal_index=0;if(fault==1)x.call.error=1;if(fault==2)++x.action_ticket;if(fault==3)x.action=cmm::full_after;
  m.accept(x);check(!m.last_accepted()&&m.stopped()&&out.result.call_count==n&&out.result.held_count==0);
  check(cmm::equal(&first,cmm::call_slot(out,0),64)&&cmm::equal(&tail,cmm::call_slot(out,n-1),64));}
 // Even the exact tail from the prior action is outside this action's range.
 {Backend b;CMM_OUTPUT24576 out{};cmm::Observer m(b.in,out);check(m.begin_action());auto first=b.invoke(m.next(),m);m.accept(first);check(m.next()==cmm::wait_first);
  const u32 prior=out.result.call_count-1;check(m.begin_action());cmm::Return x{};x.action=m.next();x.action_ticket=m.ticket();x.record_mode=cmm::RecordMode::already_committed;x.terminal_index=prior;x.call=*cmm::call_slot(out,prior);
  const u32 n=out.result.call_count;m.accept(x);check(!m.last_accepted()&&out.result.call_count==n&&m.stopped());}
 // A failed getter followed by successful known-token unwind stays partial.
 {auto in=inputs();CMM_OUTPUT24576 out{};cmm::Observer m(in,out);check(m.begin_action());const u64 borrowed[]={11,12,13};cmm::RawOwners owners(out,borrowed,3);
  auto opened=trace_call(cmm::Primitive::current_token_open);opened.observed=700;check(owners.before_api(1));check(owners.returned_allocation(opened,700,cmm::AllocationSuccess::nonzero_BOOL));
  auto failed=trace_call(cmm::Primitive::token_type,1104);failed.raw_bool=0;failed.error_valid=1;failed.error=0;check(owners.before_api());check(owners.returned_plain(failed));const u32 primary=owners.last_index();
  check(owners.take_close(700)==700);auto closed=trace_call(cmm::Primitive::current_token_close,1106);closed.requested=700;check(owners.returned_close(closed,cmm::CloseSuccess::nonzero_BOOL));check(owners.clean());
  auto x=partial(m,out,primary);const u32 n=out.result.call_count;m.accept(x);check(m.last_accepted()&&out.result.call_count==n&&n==3&&out.result.result_class==cmm::identity_changed&&!out.result.observation_complete);
  check(out.held[0].size==192&&out.identities[0].token_id==in.identity.token_id&&out.calls[1].error_valid==1&&out.calls[1].error==0&&out.calls[2].requested==700);}
 // One unknown LocalFree cannot skip the second once-close or become clean.
 {auto in=inputs();CMM_OUTPUT24576 out{};cmm::Observer m(in,out);check(m.begin_action());const u64 borrowed[]={11};cmm::RawOwners owners(out,borrowed,1);
  auto sd=trace_call(cmm::Primitive::process_sd_get);sd.kind=cmm::status_kind;sd.raw_bool=0;sd.observed=800;check(owners.before_api(1));check(owners.returned_allocation(sd,800,cmm::AllocationSuccess::zero_status));
  auto txt=trace_call(cmm::Primitive::process_sd_text,1104);txt.observed=801;check(owners.before_api(1));check(owners.returned_allocation(txt,801,cmm::AllocationSuccess::nonzero_BOOL));
  check(owners.take_close(801)==801);auto bad=trace_call(cmm::Primitive::process_sd_text_free,1106);bad.kind=cmm::pointer_kind;bad.raw_bool=0;bad.requested=801;bad.observed=801;bad.error_valid=1;check(!owners.returned_close(bad,cmm::CloseSuccess::null_pointer));const u32 primary=owners.last_index();
  check(owners.take_close(800)==800);auto freed_ok=trace_call(cmm::Primitive::process_sd_free,1108);freed_ok.kind=cmm::pointer_kind;freed_ok.raw_bool=0;freed_ok.requested=800;check(owners.returned_close(freed_ok,cmm::CloseSuccess::null_pointer));
  check(owners.pending()==0&&!owners.clean()&&owners.take_close(800)==0&&owners.take_close(801)==0);
  auto x=partial(m,out,primary);x.held.resources_clean=0;x.held.uncertain=1;const u32 n=out.result.call_count;m.accept(x);
  check(m.last_accepted()&&n==4&&out.result.call_count==4&&!out.result.resources_clean&&!out.result.observation_complete&&out.calls[2].observed==801&&out.calls[3].requested==800);}
 // Known allocation remains owned if its post-QPC is late/unknown; unwind once.
 for(bool known:{false,true}){auto in=inputs();CMM_OUTPUT24576 out{};cmm::Observer m(in,out);check(m.begin_action());const u64 borrowed[]={11};cmm::RawOwners owners(out,borrowed,1);cmm::EndpointOnce endpoints(out);
  auto opened=trace_call(cmm::Primitive::current_token_open);opened.observed=900;opened.returned_qpc=0;check(owners.before_api(1));check(owners.returned_allocation(opened,900,cmm::AllocationSuccess::nonzero_BOOL));const u32 primary=owners.last_index();
  const auto raw=*cmm::call_slot(out,primary);check(endpoints.finish(primary,known?in.plan.window_end:0,known));check(!endpoints.finish(primary,1103,true));
  auto expected=raw;expected.returned_qpc=known?in.plan.window_end:0;check(cmm::equal(&expected,cmm::call_slot(out,primary),64));
  check(owners.take_close(900)==900);auto closed=trace_call(cmm::Primitive::current_token_close,known?in.plan.window_end:1106);closed.requested=900;check(owners.returned_close(closed,cmm::CloseSuccess::nonzero_BOOL));check(owners.clean());
  auto x=partial(m,out,primary,cmm::FailureReason::postclock);x.partial_class=cmm::late_clock;const u32 n=out.result.call_count;m.accept(x);
  check(m.last_accepted()&&out.result.call_count==n&&!out.result.observation_complete&&out.result.result_class==cmm::late_clock&&out.result.within_window==0&&out.result.return_clock_known==0&&out.calls[0].raw_bool==1&&out.calls[0].observed==900&&out.calls[1].requested==900);}
 // Partial metadata has rejection power only, and cannot cite prior/outside rows.
 for(unsigned fault=0;fault<3;++fault){auto in=inputs();CMM_OUTPUT24576 out{};cmm::Observer m(in,out);check(m.begin_action());auto row=trace_call(cmm::Primitive::process_id);row.observed=42;check(m.record(row));auto x=partial(m,out,0,cmm::FailureReason::validation);
  if(fault==0)x.primary_failure_index=1;if(fault==1)x.partial_class=cmm::observed;if(fault==2)x.failure_reason=cmm::FailureReason::api_return;
  m.accept(x);check(!out.result.observation_complete&&out.result.result_class==cmm::rejected&&out.result.call_count==1);}
 // Once endpoint writer spans the noncontiguous row64 boundary and seals zero.
 {CMM_OUTPUT24576 out{};for(u32 i=0;i<65;++i){auto row=trace_call(cmm::Primitive::process_id);row.returned_qpc=0;check(cmm::append_raw(out,row));}
  cmm::EndpointOnce endpoints(out);const auto raw=*cmm::call_slot(out,64);check(endpoints.finish(64,1104,true));auto expected=raw;expected.returned_qpc=1104;
  check(cmm::equal(&expected,&out.calls_extra[0],64)&&!endpoints.finish(64,1105,true));check(endpoints.finish(63,0,false));check(!endpoints.finish(63,1105,true)&&out.calls[63].returned_qpc==0);
  check(!endpoints.finish(65,1105,true)&&out.result.call_count==65);}
}


static void zero_row_tests(){
 // Failed pre-QPC, already-expired original window, and no-row capacity stop.
 for(unsigned reason=0;reason<3;++reason){auto in=inputs();CMM_OUTPUT24576 out{};cmm::Observer m(in,out);
  if(reason==2){for(u32 i=0;i<128;++i){auto row=trace_call(cmm::Primitive::process_id);check(m.record(row));}}
  check(m.begin_action());const auto n=out.result.call_count;out.result.resources_clean=reason==1?0u:1u;
  const u32 klass=reason==2?cmm::capacity:cmm::late_clock;check(m.reject_without_call(klass,0));
  check(m.stopped()&&out.result.call_count==n&&out.result.held_count==0&&!out.result.observation_complete&&!out.result.within_window&&!out.result.return_clock_known);
  check(out.result.resources_clean==(reason==1?0u:1u));check(!m.reject_without_call(klass,0));}
 // Once this action has a real raw row, only the normal partial/tail seam works.
 {auto in=inputs();CMM_OUTPUT24576 out{};cmm::Observer m(in,out);check(m.begin_action());auto row=trace_call(cmm::Primitive::process_id);row.observed=42;check(m.record(row));
  check(!m.reject_without_call(cmm::late_clock,0)&&!m.stopped());auto x=partial(m,out,0,cmm::FailureReason::postclock);x.partial_class=cmm::late_clock;m.accept(x);
  check(m.last_accepted()&&m.stopped()&&out.result.call_count==1&&!out.result.observation_complete);}
 {auto in=inputs();CMM_OUTPUT24576 out{};cmm::Observer m(in,out);check(!m.reject_without_call(cmm::late_clock,0));check(m.begin_action());
  check(!m.reject_without_call(cmm::observed,0)&&!m.reject_without_call(cmm::exception,1));check(!m.stopped()&&out.result.call_count==0);check(m.reject_without_call(cmm::exception,0));}
}

struct MarkerAPI {CMM_MARKER320 value;unsigned events=0,restores=0,clocks=0;u64 now=1101;bool bad_restore=false,backward=false;
 cmm::Payload find(){return {&value,320};}cmm::MarkerIdentity identity(){return {42,133000000000000000ull,true};}
 bool clock(u64 frequency,u64& tick){++clocks;tick=now++;if(backward&&clocks==2)tick-=2;return frequency==10;}
 void sequence_increment(u64& x){++x;}cmm::BoolReturn clear_inherit(u64 h){return {h==101||h==102,0};}
 cmm::BoolReturn set_event(u64 h){check(value.module_base==0x180000000ull&&value.module_base_known==1);++events;return {h==101||h==102,0};}
 cmm::BoolReturn restore(){++restores;return {bad_restore?0:1,0};}};
static void marker_tests(){auto in=inputs();MarkerAPI api{};api.value=in.initial;CMM_MARKER320* touched=nullptr;check(cmm::marker_attach(api,0x180000000ull,&touched));check(touched==&api.value&&api.events==2&&api.restores==1&&api.clocks==4);check(api.value.flags==6143&&api.value.sequence%2==0&&api.value.module_base_known==1);
 MarkerAPI bad{};bad.value=in.initial;check(!cmm::marker_attach(bad,0x180000001ull,&touched));check(bad.events==0&&bad.restores==0&&bad.value.failure==11);
 for(u64 address:{0ull,0x1000ull,0xffff800000000000ull,0x7ffffffff000ull}){MarkerAPI outside{};outside.value=in.initial;check(!cmm::marker_attach(outside,address,&touched));check(outside.events==0&&outside.restores==0);}
 MarkerAPI restore{};restore.value=in.initial;restore.bad_restore=true;check(!cmm::marker_attach(restore,0x180000000ull,&touched));check(restore.events==1&&restore.restores==1&&restore.value.failure==8&&restore.value.restore_error==0);
 MarkerAPI backwards{};backwards.value=in.initial;backwards.backward=true;check(!cmm::marker_attach(backwards,0x180000000ull,&touched));check(backwards.value.failure==4&&backwards.value.last_qpc==1101&&backwards.events==0);}
static void install_handle_domains_test(){
 // This is the production install predicate, not a reimplementation. Both
 // target signal values may coincide numerically with distinct worker borrows.
 auto in=inputs();in.initial.entered_signal=in.plan.primary_token;in.initial.body_signal=in.plan.process;
 check(cmm::install_inputs(in.initial,in.plan));
 // Real aliases within either one HANDLE table remain fail-closed.
 auto worker_alias=in.plan;worker_alias.primary_token=worker_alias.process;
 check(!cmm::install_inputs(in.initial,worker_alias));
 auto target_alias=in.initial;target_alias.body_signal=target_alias.entered_signal;
 check(!cmm::install_inputs(target_alias,in.plan));
}
int main(){install_handle_domains_test();observer_tests();ownership_tests();terminal_tests();zero_row_tests();marker_tests();std::cout<<"CMM_PURE_ASSERTIONS "<<checks<<"\n";return 0;}
