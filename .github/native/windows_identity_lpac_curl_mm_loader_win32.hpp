#pragma once
// SOURCE-ONLY Win32 primitive adapter. No code in this file has been executed
// by its author. Each SEH frame is POD-only (no C++ unwind objects / C2712).
#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#ifndef NOMINMAX
#define NOMINMAX
#endif
#include <windows.h>
#include <aclapi.h>
#include <sddl.h>
#include <psapi.h>
#include "windows_identity_lpac_curl_mm_loader_core.hpp"
namespace cmm { namespace win32 {
static_assert(sizeof(void*)==8&&sizeof(BOOL)==4&&sizeof(DWORD)==4,"AMD64 widths");
static_assert(sizeof(TOKEN_STATISTICS)==56&&sizeof(MEMORY_BASIC_INFORMATION)==48,"SDK query shapes");
static_assert(sizeof(FILE_ATTRIBUTE_TAG_INFO)==8&&sizeof(FILE_ID_INFO)==24&&sizeof(FILE_STANDARD_INFO)==24,"SDK lease shapes");
static_assert(sizeof(JOBOBJECT_EXTENDED_LIMIT_INFORMATION)==144&&sizeof(JOBOBJECT_BASIC_UI_RESTRICTIONS)==4,"SDK Job shapes");
inline HANDLE H(u64 h){return reinterpret_cast<HANDLE>(static_cast<std::uintptr_t>(h));}
inline u64 U(const void* p){return static_cast<u64>(reinterpret_cast<std::uintptr_t>(p));}
inline u64 ft(FILETIME v){return (static_cast<u64>(v.dwHighDateTime)<<32)|v.dwLowDateTime;}
inline u64 pack(u32 low,u32 high){return low|(static_cast<u64>(high)<<32);}
struct Args {
 CMM_CALL64 raw;u64 object,aux;void* buffer;u32 capacity,info_class,token_encoding;
 HANDLE returned_handle;PSECURITY_DESCRIPTOR returned_sd;LPWSTR returned_text;
 DWORD returned_length,scalar;FILETIME times[4];HANDLE waits[3];
 MEMORY_BASIC_INFORMATION memory;FILE_ATTRIBUTE_TAG_INFO tag;FILE_ID_INFO file_id;FILE_STANDARD_INFO standard;
 JOBOBJECT_EXTENDED_LIMIT_INFORMATION limits;JOBOBJECT_BASIC_UI_RESTRICTIONS ui;
 SIZE_T bytes;u32 exception_code;
};
inline void bool_return(Args& a,BOOL value){a.raw.raw_bool=value;a.raw.returned=1;a.raw.error_valid=value?0u:1u;a.raw.error=value?0:GetLastError();}
inline void count_return(Args& a,u64 value,bool failed){a.raw.raw_bool=0;a.raw.observed=value;a.raw.returned=1;a.raw.error_valid=failed?1u:0u;a.raw.error=failed?GetLastError():0;}
inline void primitive_body(Args* a) noexcept {
 const auto id=static_cast<Primitive>(a->raw.operation);
 switch(id){
  case Primitive::process_id:case Primitive::middle_process_id:case Primitive::begin_process_id:case Primitive::forget_process_id:case Primitive::helper_process_id:
   {const DWORD value=GetProcessId(H(a->object));count_return(*a,value,value==0);break;}
  case Primitive::thread_process_id:case Primitive::middle_thread_process_id:
   {const DWORD value=GetProcessIdOfThread(H(a->object));count_return(*a,value,value==0);break;}
  case Primitive::process_times:case Primitive::middle_process_times:case Primitive::begin_process_times:case Primitive::forget_process_times:case Primitive::helper_process_times:
   {const BOOL value=GetProcessTimes(H(a->object),&a->times[0],&a->times[1],&a->times[2],&a->times[3]);bool_return(*a,value);a->raw.observed=ft(a->times[0]);break;}
  case Primitive::process_wait0:case Primitive::middle_process_wait0:case Primitive::begin_process_wait:case Primitive::forget_process_wait:case Primitive::helper_process_wait:
  case Primitive::sample_process:case Primitive::sample_entered:case Primitive::sample_body:
   {const DWORD value=WaitForSingleObject(H(a->object),0);count_return(*a,value,value==WAIT_FAILED);break;}
  case Primitive::wait_first:case Primitive::wait_body:
   {const DWORD value=WaitForMultipleObjects(a->capacity,a->waits,FALSE,static_cast<DWORD>(a->raw.requested));count_return(*a,value,value==WAIT_FAILED);break;}
  case Primitive::image_name:
   {a->returned_length=a->capacity;const BOOL value=QueryFullProcessImageNameW(H(a->object),0,static_cast<LPWSTR>(a->buffer),&a->returned_length);bool_return(*a,value);a->raw.observed=a->returned_length;break;}
  case Primitive::current_token_open:
   {const BOOL value=OpenProcessToken(H(a->object),TOKEN_QUERY,&a->returned_handle);bool_return(*a,value);a->raw.observed=U(a->returned_handle);break;}
  case Primitive::current_token_close:
   {const BOOL value=CloseHandle(H(a->object));bool_return(*a,value);break;}
  case Primitive::token_type:case Primitive::token_session:case Primitive::token_is_ac:case Primitive::token_elevation:case Primitive::token_ui_access:
  case Primitive::token_user_probe:case Primitive::token_user_fill:case Primitive::token_il_probe:case Primitive::token_il_fill:
  case Primitive::token_caps_probe:case Primitive::token_caps_fill:case Primitive::token_acsid_probe:case Primitive::token_acsid_fill:
  case Primitive::token_stats_probe:case Primitive::token_stats_fill:
   {const BOOL value=GetTokenInformation(H(a->object),static_cast<TOKEN_INFORMATION_CLASS>(a->info_class),a->buffer,a->capacity,&a->returned_length);bool_return(*a,value);
    // Raw returned length is always retained. These exact DWORD-bearing fills
    // additionally preserve the returned DWORD, never its expected value.
    u32 high=0;if(a->buffer&&a->capacity>=4&&a->token_encoding==1)std::memcpy(&high,a->buffer,4);
    if(a->buffer&&a->capacity>=56&&a->token_encoding==2){const auto* stats=static_cast<const TOKEN_STATISTICS*>(a->buffer);high=static_cast<u32>(stats->TokenType);}
    a->raw.observed=pack(a->returned_length,high);break;}
  case Primitive::process_sd_get:case Primitive::thread_sd_get:
   {const DWORD status=GetSecurityInfo(H(a->object),SE_KERNEL_OBJECT,DACL_SECURITY_INFORMATION,nullptr,nullptr,nullptr,nullptr,&a->returned_sd);
    a->raw.raw_bool=static_cast<std::int32_t>(status);a->raw.returned=1;a->raw.error_valid=status?1u:0u;a->raw.error=status;a->raw.observed=U(a->returned_sd);break;}
  case Primitive::process_sd_text:case Primitive::thread_sd_text:
   {const BOOL value=ConvertSecurityDescriptorToStringSecurityDescriptorW(reinterpret_cast<PSECURITY_DESCRIPTOR>(static_cast<std::uintptr_t>(a->object)),SDDL_REVISION_1,DACL_SECURITY_INFORMATION,&a->returned_text,nullptr);
    bool_return(*a,value);a->raw.observed=U(a->returned_text);break;}
  case Primitive::process_sd_text_free:case Primitive::process_sd_free:case Primitive::thread_sd_text_free:case Primitive::thread_sd_free:
   {const HLOCAL value=LocalFree(reinterpret_cast<HLOCAL>(static_cast<std::uintptr_t>(a->object)));count_return(*a,U(value),value!=nullptr);break;}
  case Primitive::inner_member:case Primitive::outer_member:case Primitive::middle_inner_member:case Primitive::middle_outer_member:
   {BOOL member=FALSE;const BOOL value=IsProcessInJob(H(a->object),H(a->aux),&member);bool_return(*a,value);a->raw.observed=static_cast<u32>(member);break;}
  case Primitive::inner_flags:case Primitive::outer_flags:case Primitive::target_lease_flags:case Primitive::marker_lease_flags:
   {const BOOL value=GetHandleInformation(H(a->object),&a->scalar);bool_return(*a,value);a->raw.observed=a->scalar;break;}
  case Primitive::inner_limits:case Primitive::outer_limits:
   {const BOOL value=QueryInformationJobObject(H(a->object),JobObjectExtendedLimitInformation,&a->limits,sizeof(a->limits),&a->returned_length);bool_return(*a,value);a->raw.observed=pack(a->returned_length,a->limits.BasicLimitInformation.LimitFlags);break;}
  case Primitive::inner_ui:case Primitive::outer_ui:
   {const BOOL value=QueryInformationJobObject(H(a->object),JobObjectBasicUIRestrictions,&a->ui,sizeof(a->ui),&a->returned_length);bool_return(*a,value);a->raw.observed=pack(a->returned_length,a->ui.UIRestrictionsClass);break;}
  case Primitive::target_lease_tag:case Primitive::marker_lease_tag:
   {const BOOL value=GetFileInformationByHandleEx(H(a->object),FileAttributeTagInfo,&a->tag,sizeof(a->tag));bool_return(*a,value);a->raw.observed=pack(a->tag.FileAttributes,a->tag.ReparseTag);break;}
  case Primitive::target_lease_id:case Primitive::marker_lease_id:
   {const BOOL value=GetFileInformationByHandleEx(H(a->object),FileIdInfo,&a->file_id,sizeof(a->file_id));bool_return(*a,value);break;}
  case Primitive::target_lease_standard:case Primitive::marker_lease_standard:
   {const BOOL value=GetFileInformationByHandleEx(H(a->object),FileStandardInfo,&a->standard,sizeof(a->standard));bool_return(*a,value);
    // Preserve the two actual BOOLEAN bytes, without normalizing to bool.
    a->raw.requested=pack(24,static_cast<u32>(a->standard.DeletePending)|(static_cast<u32>(a->standard.Directory)<<8));a->raw.observed=static_cast<u64>(a->standard.EndOfFile.QuadPart);break;}
  case Primitive::region_before:case Primitive::region_after:
   {const SIZE_T value=VirtualQueryEx(H(a->object),reinterpret_cast<const void*>(static_cast<std::uintptr_t>(a->aux)),&a->memory,sizeof(a->memory));count_return(*a,value,value==0);break;}
  case Primitive::mapped_name_before:case Primitive::mapped_name_after:
   {const DWORD value=K32GetMappedFileNameW(H(a->object),reinterpret_cast<void*>(static_cast<std::uintptr_t>(a->aux)),static_cast<LPWSTR>(a->buffer),a->capacity);count_return(*a,value,value==0||value>=a->capacity);break;}
  case Primitive::rpm_progress_first:case Primitive::rpm_progress_second:case Primitive::rpm_body_first:case Primitive::rpm_body_second:case Primitive::rpm_pe:
   {const BOOL value=ReadProcessMemory(H(a->object),reinterpret_cast<const void*>(static_cast<std::uintptr_t>(a->aux)),a->buffer,a->capacity,&a->bytes);bool_return(*a,value);a->raw.observed=static_cast<u64>(a->bytes);break;}
  default:break;
 }
}
inline void primitive(Args* a) noexcept {
 // Only POD locals enter this SEH frame. No allocation cleanup is attempted
 // here: the caller commits this raw partial then unwinds prior known owners.
 __try {a->raw.entered=1;primitive_body(a);}
 __except(EXCEPTION_EXECUTE_HANDLER){a->exception_code=static_cast<u32>(GetExceptionCode());}
 // Even a throwing API may have changed its output slot. Preserve that raw
 // number without adopting or closing it; ownership remains unknown.
 if(a->raw.returned==0){const auto id=static_cast<Primitive>(a->raw.operation);
  if(id==Primitive::current_token_open)a->raw.observed=U(a->returned_handle);
  if(id==Primitive::process_sd_get||id==Primitive::thread_sd_get)a->raw.observed=U(a->returned_sd);
  if(id==Primitive::process_sd_text||id==Primitive::thread_sd_text)a->raw.observed=U(a->returned_text);
 }
}
inline bool qpc(u64& value){LARGE_INTEGER q{};if(!QueryPerformanceCounter(&q)||q.QuadPart<0)return false;value=static_cast<u64>(q.QuadPart);return true;}
}} // namespace cmm::win32
