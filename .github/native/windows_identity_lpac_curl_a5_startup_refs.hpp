#pragma once
// Bounded source-owned net acquired-reference accounting; not module identity
// proof and not a substitute for actual SDK receipts in the Windows adapter.
#include "windows_identity_lpac_curl_a5_startup_core.hpp"
namespace a5startup {
class PrivateReferences {
 struct Entry {u64 module=0;bool consumed=false,released=false,return_seen=false;};
 Entry entries_[64]{};u32 used_=0;bool uncertain_=false;
public:
 bool can_load()const{return used_<64&&!uncertain_;}
 bool uncertain()const{return uncertain_;}
 u32 outstanding()const{u32 n=0;for(u32 i=0;i<used_;++i)n+=entries_[i].module&&!entries_[i].released;return n;}
 // Known nonnull real loader success remains an acquisition even if the
 // caller's post-clock qualification fails. Identity-mismatch or unreturned
 // outputs are retained as unknown, never blindly freed or returned to curl.
 bool returned_load(u64 module,bool returned,bool actual_private_identity){
  if(!returned){uncertain_=true;return false;}
  if(!module)return true;
  if(module==~u64{0}||!actual_private_identity||used_>=64){uncertain_=true;return false;}
  entries_[used_++].module=module;return true;
 }
 // The same actual HMODULE may label many acquisitions and borrowed queries.
 // Consume one net owned acquisition before invoking the real release; do not
 // pretend to know which particular returned integer a caller kept.
 bool take_release(u64 module,u32& ticket){
  for(u32 i=0;i<used_;++i)if(entries_[i].module==module&&!entries_[i].consumed){entries_[i].consumed=true;ticket=i;return true;}
  return false;
 }
 bool returned_release(u32 ticket,bool returned,bool raw_true){
  if(ticket>=used_||!entries_[ticket].consumed||entries_[ticket].return_seen){uncertain_=true;return false;}
  entries_[ticket].return_seen=true;
  if(!returned||!raw_true){uncertain_=true;return false;}
  entries_[ticket].released=true;return true;
 }
};
}
