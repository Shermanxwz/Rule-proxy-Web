#pragma once
// Pure ownership/reservation policy. Does NOT invoke/close/free any resource.
#include "windows_identity_lpac_curl_mm_loader_wrapper.hpp"
#include <cstring>
#include <limits>
namespace cmm {
inline CMM_CALL64* call_slot(CMM_OUTPUT24576& out,std::uint32_t index){return index<64?&out.calls[index]:index<128?&out.calls_extra[index-64]:nullptr;}
inline bool append_raw(CMM_OUTPUT24576& out,const CMM_CALL64& value){if(out.result.call_count>=128)return false;
 CMM_CALL64* row=call_slot(out,out.result.call_count);if(!row)return false;*row=value;++out.result.call_count;return true;}
// The only permitted amendment to a committed raw API row is its previously
// unknown post-QPC endpoint. The caller samples QPC ONCE after committing raw
// return/error/output. A failed QPC seals endpoint zero; neither a retry nor a
// rewrite of physical fields is permitted. This is metadata, not a new API row.
class EndpointOnce {
 CMM_OUTPUT24576& out_;bool sealed_[128]{};
public:
 explicit EndpointOnce(CMM_OUTPUT24576& out):out_(out){}
 bool finish(std::uint32_t index,std::uint64_t tick,bool known){
  if(index>=out_.result.call_count||index>=128||sealed_[index])return false;
  auto* row=call_slot(out_,index);if(!row||row->returned!=1||row->returned_qpc!=0)return false;
  if((known&&tick==0)||(!known&&tick!=0))return false;
  sealed_[index]=true;if(known)row->returned_qpc=tick;return true;
 }
};
enum class AllocationSuccess {nonzero_BOOL,zero_status};
enum class CloseSuccess {nonzero_BOOL,null_pointer};
enum class FailedOutputContract {unknown,known_no_owned_output};
class RawOwners {
 CMM_OUTPUT24576& out_;std::uint64_t known_[8]{};std::uint32_t pending_=0;
 std::uint32_t last_index_=0xffffffffu;
 bool uncertain_=false,inflight_=false,closing_=false;std::uint32_t allowed_new_=0;std::uint64_t close_value_=0;
 const std::uint64_t* borrowed_;std::size_t borrowed_count_;
 bool valid(std::uint64_t h)const{return h&&h!=std::numeric_limits<std::uint64_t>::max();}
 bool alias(std::uint64_t h)const{for(std::size_t i=0;i<borrowed_count_;++i)if(borrowed_[i]==h)return true;for(std::uint32_t i=0;i<pending_;++i)if(known_[i]==h)return true;return closing_&&close_value_==h;}
 bool save(const CMM_CALL64& raw){last_index_=0xffffffffu;const auto index=out_.result.call_count;
  if(!append_raw(out_,raw))return false;last_index_=index;return true;}
 void unknown(){uncertain_=true;out_.result.resources_clean=0;}
public:
 RawOwners(CMM_OUTPUT24576& out,const std::uint64_t* borrowed,std::size_t count):out_(out),borrowed_(borrowed),borrowed_count_(count){}
 // Every normal primitive MUST reserve its raw return row plus all already
 // known closes and every possible successful new allocation's close row.
 bool before_api(std::uint32_t possible_new=0){if(uncertain_||inflight_||closing_||possible_new>8-pending_||out_.result.call_count>128)return false;
  if(out_.result.call_count+pending_+1+possible_new>128)return false;
  last_index_=0xffffffffu;inflight_=true;allowed_new_=possible_new;return true;}
 bool returned_plain(const CMM_CALL64& raw){if(!inflight_)return false;inflight_=false;allowed_new_=0;
  if(!save(raw)){unknown();return false;}if(!raw.returned){unknown();return false;}return true;}
 bool returned_allocation(const CMM_CALL64& raw,std::uint64_t value,AllocationSuccess success,FailedOutputContract failure=FailedOutputContract::unknown){if(!inflight_||allowed_new_!=1)return false;
  // Raw return is stored BEFORE ownership interpretation and postclock.
  const bool saved=save(raw);inflight_=false;allowed_new_=0;if(!saved){unknown();return false;}
  // observed is ALWAYS the raw output pointer, not a separate caller's claim.
  // raw_bool contains BOOL or the exact DWORD-return bit pattern, by kind.
  const bool typed=success==AllocationSuccess::nonzero_BOOL?raw.kind==1:raw.kind==7;
  const bool ok=typed&&raw.entered==1&&raw.returned==1&&(success==AllocationSuccess::nonzero_BOOL?raw.raw_bool!=0:static_cast<std::uint32_t>(raw.raw_bool)==0);
  if(value!=raw.observed){unknown();return false;}
  // Opt-in only for a separately reviewed API contract: a complete returned
  // failure+NULL acquired no owned output. This is NOT external absence.
  // Default stays unknown; FALSE+nonnull, exception or TRUE+bad never use it.
  if(!ok&&typed&&raw.entered==1&&raw.returned==1&&value==0&&failure==FailedOutputContract::known_no_owned_output)return false;
  if(!ok||!valid(value)||alias(value)){unknown();return false;}known_[pending_++]=value;return true;}
 std::uint64_t take_close(std::uint64_t value){if(inflight_||closing_)return 0;std::uint32_t found=pending_;
  for(std::uint32_t i=0;i<pending_;++i)if(known_[i]==value){found=i;break;}if(found==pending_)return 0;
  // Consume BEFORE invoking Close/LocalFree. Its row was reserved when the
  // known allocation was admitted. Normal-capacity exhaustion cannot skip it.
  for(std::uint32_t i=found+1;i<pending_;++i)known_[i-1]=known_[i];--pending_;known_[pending_]=0;
  last_index_=0xffffffffu;closing_=true;close_value_=value;return value;}
 bool returned_close(const CMM_CALL64& raw,CloseSuccess success){if(!closing_)return false;const auto expected=close_value_;closing_=false;close_value_=0;
  const bool saved=save(raw);const bool typed=success==CloseSuccess::nonzero_BOOL?raw.kind==1:raw.kind==8;
  const bool ok=saved&&typed&&raw.requested==expected&&raw.entered==1&&raw.returned==1&&(success==CloseSuccess::nonzero_BOOL?raw.raw_bool!=0:raw.observed==0);
  if(!ok)unknown();return ok;}
 void caught(const CMM_CALL64& raw){if(closing_){returned_close(raw,CloseSuccess::nonzero_BOOL);}
  else{inflight_=false;allowed_new_=0;if(!save(raw))unknown();}unknown();}
 std::uint32_t last_index()const{return last_index_;}
 bool clean()const{return !uncertain_&&!inflight_&&!closing_&&pending_==0;}
 bool uncertain()const{return uncertain_;}std::uint32_t pending()const{return pending_;}
 std::uint64_t pending_at(std::uint32_t i)const{return i<pending_?known_[i]:0;}
};
} // namespace cmm
