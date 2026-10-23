#pragma once
// Shared actual marker path / inert fake seam. No syscall implementation here.
#include "windows_identity_lpac_curl_loader_core.hpp"
namespace cl {
enum Progress:u32 {validated=1,entered_attempt=2,entered_success=4,restore_attempt=8,restore_returned=16,restore_true=32,
 body_attempt=64,body_success=128,pre_return_true=256,entered_cleared=512,body_cleared=1024,aux_error_valid=2048,clock_known=4096,exception_flag=8192};
enum Failure:u32 {no_failure=0,payload_missing=1,payload_shape=2,identity_failure=3,clock_failure=4,entered_clear_failure=5,
 body_clear_failure=6,entered_event_failure=7,restore_failure=8,body_event_failure=9,marker_exception=10};
struct Identity {u32 pid;u64 creation;bool known;};
struct Payload {CL_MARKER256* address;std::size_t bytes;};
template<class API,class Write> void status_write(API& api,CL_MARKER256& m,Write write){api.sequence_increment(m.even_stable_status_sequence);write();api.sequence_increment(m.even_stable_status_sequence);}
template<class API> void fail(API& api,CL_MARKER256& m,u32 stage){status_write(api,m,[&](){if(!m.failure_stage)m.failure_stage=stage;});}
inline bool marker_shape(const CL_MARKER256& m){return equal(m.magic,"CLM1",4)&&m.version==1&&m.size==256&&nonzero(m.run,16)&&nonzero(m.config_sha256,32)&&nonzero(m.source_sha256,32)&&nonzero(m.marker_image_sha256,32)&&epoch(m.frequency,m.root_start_qpc,m.root_deadline_qpc,m.window_start_qpc,m.window_end_qpc)&&m.target_pid&&m.reserved0==0&&m.target_creation_FILETIME&&m.inherited_enter_event_signal_only&&m.inherited_body_event_signal_only&&m.inherited_enter_event_signal_only!=m.inherited_body_event_signal_only&&m.inherited_enter_event_signal_only!=std::numeric_limits<u64>::max()&&m.inherited_body_event_signal_only!=std::numeric_limits<u64>::max()&&m.status_size==64&&m.status_version==1&&!nonzero(reinterpret_cast<const std::uint8_t*>(&m)+200,56);}
template<class API> bool marker_tick(API& api,CL_MARKER256& m){u64 tick=0;if(!api.clock(m.frequency,tick)||tick<m.window_start_qpc||tick>=m.window_end_qpc){fail(api,m,clock_failure);return false;}status_write(api,m,[&](){m.progress_flags|=clock_known;m.last_original_domain_qpc=tick;});return true;}
template<class API> bool marker_attach(API& api,CL_MARKER256** validated_address){
 *validated_address=nullptr;const Payload p=api.find();if(!p.address||p.bytes!=sizeof(CL_MARKER256)||!span(p.address,sizeof(CL_MARKER256))||!remote_aligned(static_cast<u64>(reinterpret_cast<std::uintptr_t>(p.address))))return false;
 CL_MARKER256& m=*p.address;if(!marker_shape(m))return false;*validated_address=&m;
 const Identity identity=api.identity();if(!identity.known||identity.pid!=m.target_pid||identity.creation!=m.target_creation_FILETIME){fail(api,m,identity_failure);return false;}
 status_write(api,m,[&](){m.writer_target_pid=identity.pid;m.progress_flags|=validated;});if(!marker_tick(api,m))return false;
 const BoolReturn ec=api.clear_inherit(m.inherited_enter_event_signal_only);
 if(!ec.value){status_write(api,m,[&](){m.progress_flags|=aux_error_valid;m.auxiliary_GetLastError=ec.error;m.failure_stage=entered_clear_failure;});return false;}
 status_write(api,m,[&](){m.progress_flags|=entered_cleared;});
 const BoolReturn bc=api.clear_inherit(m.inherited_body_event_signal_only);
 if(!bc.value){status_write(api,m,[&](){m.progress_flags|=aux_error_valid;m.auxiliary_GetLastError=bc.error;m.failure_stage=body_clear_failure;});return false;}
 status_write(api,m,[&](){m.progress_flags|=body_cleared;});if(!marker_tick(api,m))return false;
 status_write(api,m,[&](){m.progress_flags|=entered_attempt;});const BoolReturn entered=api.set_event(m.inherited_enter_event_signal_only);
 status_write(api,m,[&](){m.raw_SetEvent_entered_BOOL=entered.value;m.entered_GetLastError=entered.value?0:entered.error;if(entered.value)m.progress_flags|=entered_success;else m.failure_stage=entered_event_failure;});
 if(!entered.value||!marker_tick(api,m))return false;
 status_write(api,m,[&](){m.progress_flags|=restore_attempt;});const BoolReturn restored=api.restore();
 status_write(api,m,[&](){m.progress_flags|=restore_returned;m.raw_restore_BOOL=restored.value;m.restore_GetLastError=restored.value?0:restored.error;if(restored.value)m.progress_flags|=restore_true;else m.failure_stage=restore_failure;});
 if(!restored.value||!marker_tick(api,m))return false;
 status_write(api,m,[&](){m.progress_flags|=body_attempt;});const BoolReturn body=api.set_event(m.inherited_body_event_signal_only);
 // Successful body marker: no further API/QPC call. Only bounded scalar and
 // interlocked status commits precede the literal successful return.
 status_write(api,m,[&](){m.raw_SetEvent_body_BOOL=body.value;m.body_GetLastError=body.value?0:body.error;if(body.value)m.progress_flags|=body_success|pre_return_true;else m.failure_stage=body_event_failure;});
 return body.value!=0;
}
template<class API> bool marker_caught(API& api,CL_MARKER256* m){if(m && span(m,sizeof(*m)) && remote_aligned(static_cast<u64>(reinterpret_cast<std::uintptr_t>(m))))status_write(api,*m,[&](){m->progress_flags|=exception_flag;m->failure_stage=marker_exception;});return false;}
} // namespace cl
