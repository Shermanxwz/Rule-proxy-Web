#pragma once
// ABI05: fixed POD wire layouts. No Windows types, allocation or OS calls here.
#include <cstddef>
#include <cstdint>
#include <type_traits>
#if defined(_WIN32)
#define CL_CALL __stdcall
#if defined(CL_WRAPPER_BUILD)
#define CL_API extern "C" __declspec(dllexport)
#else
#define CL_API extern "C"
#endif
#else
#define CL_CALL
#define CL_API extern "C"
#endif

struct alignas(8) CL_PLAN256 {
 std::uint32_t size,version;
 std::uint64_t frequency,root_start_qpc,root_deadline_qpc,window_start_qpc,window_end_qpc;
 std::uint32_t target_pid,reserved0;
 std::uint64_t target_creation_FILETIME,borrowed_held_process_handle;
 std::uint8_t run[16],config_sha256[32],source_sha256[32],target_image_sha256[32],marker_image_sha256[32];
 std::uint64_t caller_owned_ASCII_marker_path_pointer;
 std::uint32_t marker_path_bytes_excluding_NUL,reserved1;
 std::uint8_t marker_payload_GUID_Windows_bytes[16],reserved2[8];
};
struct alignas(8) CL_MARKER256 {
 std::uint8_t magic[4];std::uint16_t version,size;
 std::uint8_t run[16],config_sha256[32],source_sha256[32],marker_image_sha256[32];
 std::uint64_t frequency,root_start_qpc,root_deadline_qpc,window_start_qpc,window_end_qpc;
 std::uint32_t target_pid,reserved0;
 std::uint64_t target_creation_FILETIME,inherited_enter_event_signal_only,inherited_body_event_signal_only;
 std::uint32_t status_size,status_version,progress_flags,failure_stage;
 std::int32_t raw_restore_BOOL;std::uint32_t restore_GetLastError;
 std::int32_t raw_SetEvent_entered_BOOL;std::uint32_t entered_GetLastError;
 std::int32_t raw_SetEvent_body_BOOL;std::uint32_t body_GetLastError;
 std::uint64_t last_original_domain_qpc;
 std::uint32_t writer_target_pid,auxiliary_GetLastError;
 std::uint64_t even_stable_status_sequence;
};
struct alignas(8) CL_RESULT128 {
 std::uint32_t size,version,operation,result_class;
 std::uint64_t entered_qpc,returned_qpc;
 std::uint32_t validation_passed,update_entered,update_returned;
 std::int32_t raw_update_BOOL;
 std::uint32_t update_GetLastError,update_error_valid,copy_entered,copy_returned,copy_nonnull,copy_GetLastError,copy_error_valid;
 std::uint32_t within_original_window,return_clock_known,remote_mutation_possible,remote_outcome_unknown,caught_exception_code_or_zero;
 std::uint32_t marker_read_entered,marker_read_returned,marker_read_exact256,read_GetLastError,coherent_snapshot,exact_target_still_alive;
 std::uint64_t local_context_generation;
};
struct alignas(8) CL_CONTEXT {std::uint8_t bytes[2048];};
static_assert(sizeof(void*)==8,"AMD64 caller required");
static_assert(sizeof(CL_PLAN256)==256 && alignof(CL_PLAN256)==8,"Plan256");
static_assert(sizeof(CL_MARKER256)==256 && alignof(CL_MARKER256)==8,"Marker256");
static_assert(sizeof(CL_RESULT128)==128 && alignof(CL_RESULT128)==8,"Result128");
static_assert(sizeof(CL_CONTEXT)==2048 && alignof(CL_CONTEXT)==8,"Context2048");
#define CL_OFFSET(T,F,N) static_assert(offsetof(T,F)==N,#T "." #F)
CL_OFFSET(CL_PLAN256,size,0);CL_OFFSET(CL_PLAN256,version,4);CL_OFFSET(CL_PLAN256,root_start_qpc,16);
CL_OFFSET(CL_PLAN256,root_deadline_qpc,24);CL_OFFSET(CL_PLAN256,window_start_qpc,32);CL_OFFSET(CL_PLAN256,window_end_qpc,40);
CL_OFFSET(CL_PLAN256,reserved0,52);CL_OFFSET(CL_PLAN256,reserved1,228);
CL_OFFSET(CL_PLAN256,frequency,8);CL_OFFSET(CL_PLAN256,target_pid,48);CL_OFFSET(CL_PLAN256,target_creation_FILETIME,56);
CL_OFFSET(CL_PLAN256,borrowed_held_process_handle,64);CL_OFFSET(CL_PLAN256,run,72);CL_OFFSET(CL_PLAN256,config_sha256,88);
CL_OFFSET(CL_PLAN256,source_sha256,120);CL_OFFSET(CL_PLAN256,target_image_sha256,152);CL_OFFSET(CL_PLAN256,marker_image_sha256,184);
CL_OFFSET(CL_PLAN256,caller_owned_ASCII_marker_path_pointer,216);CL_OFFSET(CL_PLAN256,marker_path_bytes_excluding_NUL,224);
CL_OFFSET(CL_PLAN256,marker_payload_GUID_Windows_bytes,232);CL_OFFSET(CL_PLAN256,reserved2,248);
CL_OFFSET(CL_MARKER256,magic,0);CL_OFFSET(CL_MARKER256,version,4);CL_OFFSET(CL_MARKER256,size,6);CL_OFFSET(CL_MARKER256,run,8);
CL_OFFSET(CL_MARKER256,config_sha256,24);CL_OFFSET(CL_MARKER256,source_sha256,56);CL_OFFSET(CL_MARKER256,marker_image_sha256,88);
CL_OFFSET(CL_MARKER256,frequency,120);CL_OFFSET(CL_MARKER256,root_start_qpc,128);CL_OFFSET(CL_MARKER256,root_deadline_qpc,136);
CL_OFFSET(CL_MARKER256,window_start_qpc,144);CL_OFFSET(CL_MARKER256,window_end_qpc,152);CL_OFFSET(CL_MARKER256,target_pid,160);
CL_OFFSET(CL_MARKER256,reserved0,164);CL_OFFSET(CL_MARKER256,target_creation_FILETIME,168);CL_OFFSET(CL_MARKER256,inherited_enter_event_signal_only,176);
CL_OFFSET(CL_MARKER256,inherited_body_event_signal_only,184);CL_OFFSET(CL_MARKER256,status_size,192);CL_OFFSET(CL_MARKER256,status_version,196);
CL_OFFSET(CL_MARKER256,progress_flags,200);CL_OFFSET(CL_MARKER256,failure_stage,204);CL_OFFSET(CL_MARKER256,raw_restore_BOOL,208);
CL_OFFSET(CL_MARKER256,restore_GetLastError,212);CL_OFFSET(CL_MARKER256,raw_SetEvent_entered_BOOL,216);CL_OFFSET(CL_MARKER256,entered_GetLastError,220);
CL_OFFSET(CL_MARKER256,raw_SetEvent_body_BOOL,224);CL_OFFSET(CL_MARKER256,body_GetLastError,228);CL_OFFSET(CL_MARKER256,last_original_domain_qpc,232);
CL_OFFSET(CL_MARKER256,writer_target_pid,240);CL_OFFSET(CL_MARKER256,auxiliary_GetLastError,244);CL_OFFSET(CL_MARKER256,even_stable_status_sequence,248);
CL_OFFSET(CL_RESULT128,entered_qpc,16);CL_OFFSET(CL_RESULT128,returned_qpc,24);CL_OFFSET(CL_RESULT128,validation_passed,32);
CL_OFFSET(CL_RESULT128,size,0);CL_OFFSET(CL_RESULT128,version,4);CL_OFFSET(CL_RESULT128,operation,8);CL_OFFSET(CL_RESULT128,result_class,12);
CL_OFFSET(CL_RESULT128,update_returned,40);CL_OFFSET(CL_RESULT128,update_GetLastError,48);CL_OFFSET(CL_RESULT128,update_error_valid,52);
CL_OFFSET(CL_RESULT128,copy_returned,60);CL_OFFSET(CL_RESULT128,copy_nonnull,64);CL_OFFSET(CL_RESULT128,copy_GetLastError,68);
CL_OFFSET(CL_RESULT128,copy_error_valid,72);CL_OFFSET(CL_RESULT128,return_clock_known,80);CL_OFFSET(CL_RESULT128,remote_mutation_possible,84);
CL_OFFSET(CL_RESULT128,remote_outcome_unknown,88);CL_OFFSET(CL_RESULT128,marker_read_returned,100);CL_OFFSET(CL_RESULT128,marker_read_exact256,104);
CL_OFFSET(CL_RESULT128,update_entered,36);CL_OFFSET(CL_RESULT128,raw_update_BOOL,44);CL_OFFSET(CL_RESULT128,copy_entered,56);
CL_OFFSET(CL_RESULT128,within_original_window,76);CL_OFFSET(CL_RESULT128,caught_exception_code_or_zero,92);
CL_OFFSET(CL_RESULT128,marker_read_entered,96);CL_OFFSET(CL_RESULT128,read_GetLastError,108);CL_OFFSET(CL_RESULT128,coherent_snapshot,112);
CL_OFFSET(CL_RESULT128,exact_target_still_alive,116);CL_OFFSET(CL_RESULT128,local_context_generation,120);
#undef CL_OFFSET
static_assert(std::is_trivial<CL_PLAN256>::value && std::is_trivial<CL_MARKER256>::value && std::is_trivial<CL_RESULT128>::value,"POD only");

CL_API std::uint32_t CL_CALL cl_abi_version();
CL_API std::uint32_t CL_CALL cl_begin_v1(const CL_PLAN256*,CL_CONTEXT*,CL_RESULT128*);
CL_API std::uint32_t CL_CALL cl_update_v1(CL_CONTEXT*,CL_RESULT128*);
CL_API std::uint32_t CL_CALL cl_install_marker_v1(CL_CONTEXT*,const CL_MARKER256*,CL_RESULT128*);
CL_API std::uint32_t CL_CALL cl_read_marker_v1(CL_CONTEXT*,CL_MARKER256*,CL_RESULT128*);
CL_API std::uint32_t CL_CALL cl_forget_exited_v1(CL_CONTEXT*,CL_RESULT128*);
