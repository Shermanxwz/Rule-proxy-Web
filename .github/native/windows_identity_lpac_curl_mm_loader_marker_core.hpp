#pragma once
// Target marker policy only; no OS adapter or DllMain implementation yet.
#include "windows_identity_lpac_curl_mm_loader_core.hpp"
namespace cmm {
struct BoolReturn {std::int32_t value;u32 error;};
struct MarkerIdentity {u32 pid;u64 creation;bool known;};
struct Payload {CMM_MARKER320* address;std::size_t bytes;};
enum Progress:u32 {validated=1,entered_attempt=2,entered_success=4,restore_attempt=8,restore_returned=16,
 restore_true=32,body_attempt=64,body_success=128,pre_return_true=256,entered_cleared=512,body_cleared=1024,
 auxiliary_error_valid=2048,clock_known=4096,exception_flag=8192};
template<class API,class Write> void status_write(API& api,CMM_MARKER320& m,Write write){api.sequence_increment(m.sequence);write();api.sequence_increment(m.sequence);}
template<class API> void marker_fail(API& api,CMM_MARKER320& m,u32 failure){status_write(api,m,[&](){if(!m.failure)m.failure=failure;});}
inline bool marker_shape(const CMM_MARKER320& m){CMM_PLAN512 p{};p.frequency=m.frequency;p.root_start=m.root_start;p.root_deadline=m.root_deadline;p.window_start=m.window_start;p.window_end=m.window_end;
 return equal(m.magic,"CMM2",4)&&m.version==2&&m.size==320&&epoch(p)&&m.target_pid&&m.target_creation&&!m.reserved0
 &&nonzero(m.run,16)&&nonzero(m.config_sha256,32)&&nonzero(m.source_sha256,32)&&nonzero(m.marker_sha256,32)
 &&handle(m.entered_signal)&&handle(m.body_signal)&&m.entered_signal!=m.body_signal&&m.status_size==128&&m.status_version==2
 &&!nonzero(reinterpret_cast<const std::uint8_t*>(&m)+200,120);}
template<class API> bool marker_tick(API& api,CMM_MARKER320& m){u64 q=0;if(!api.clock(m.frequency,q)||q<m.window_start||q<m.last_qpc||q>=m.window_end){marker_fail(api,m,4);return false;}
 status_write(api,m,[&](){m.flags|=clock_known;m.last_qpc=q;});return true;}
template<class API> bool marker_attach(API& api,u64 supplied_HINSTANCE,CMM_MARKER320** touched){*touched=nullptr;const Payload p=api.find();
 if(!p.address||p.bytes!=320||(reinterpret_cast<std::uintptr_t>(p.address)&7u))return false;
 CMM_MARKER320& m=*p.address;if(!marker_shape(m))return false;*touched=&m;
 if(!user_image_base(supplied_HINSTANCE)){marker_fail(api,m,11);return false;}
 const MarkerIdentity i=api.identity();if(!i.known||i.pid!=m.target_pid||i.creation!=m.target_creation){marker_fail(api,m,3);return false;}
 // Sole new target behavior: copy the DllMain argument scalar within the SAME
 // sequence protocol. No module lookup, wait, new API, delay or remote thread.
 status_write(api,m,[&](){m.writer_pid=i.pid;m.module_base=supplied_HINSTANCE;m.module_base_known=1;m.flags|=validated;});
 if(!marker_tick(api,m))return false;
 const BoolReturn ec=api.clear_inherit(m.entered_signal);if(!ec.value){status_write(api,m,[&](){m.flags|=auxiliary_error_valid;m.aux_error=ec.error;m.failure=5;});return false;}
 status_write(api,m,[&](){m.flags|=entered_cleared;});
 const BoolReturn bc=api.clear_inherit(m.body_signal);if(!bc.value){status_write(api,m,[&](){m.flags|=auxiliary_error_valid;m.aux_error=bc.error;m.failure=6;});return false;}
 status_write(api,m,[&](){m.flags|=body_cleared;});if(!marker_tick(api,m))return false;
 status_write(api,m,[&](){m.flags|=entered_attempt;});const BoolReturn e=api.set_event(m.entered_signal);
 status_write(api,m,[&](){m.entered_bool=e.value;m.entered_error=e.value?0:e.error;if(e.value)m.flags|=entered_success;else m.failure=7;});
 if(!e.value||!marker_tick(api,m))return false;
 status_write(api,m,[&](){m.flags|=restore_attempt;});const BoolReturn r=api.restore();
 status_write(api,m,[&](){m.flags|=restore_returned;m.restore_bool=r.value;m.restore_error=r.value?0:r.error;if(r.value)m.flags|=restore_true;else m.failure=8;});
 if(!r.value||!marker_tick(api,m))return false;
 status_write(api,m,[&](){m.flags|=body_attempt;});const BoolReturn b=api.set_event(m.body_signal);
 // No API/QPC after successful BODY. Only bounded scalar/interlocked commit
 // and return: BODY can precede this final status commit, never proves return.
 status_write(api,m,[&](){m.body_bool=b.value;m.body_error=b.value?0:b.error;if(b.value)m.flags|=body_success|pre_return_true;else m.failure=9;});
 return b.value!=0;}
template<class API> void marker_caught(API& api,CMM_MARKER320* m){if(m&&(reinterpret_cast<std::uintptr_t>(m)&7u)==0)status_write(api,*m,[&](){m->flags|=exception_flag;m->failure=10;});}
} // namespace cmm
