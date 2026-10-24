#define WIN32_LEAN_AND_MEAN
#define NOMINMAX
#define CL_WRAPPER_BUILD
#include <windows.h>
#include "../vendor/detours/src/detours.h"
#include "windows_identity_lpac_curl_loader_core.hpp"
#if !defined(_WIN64) || !defined(DETOURS_X64) || DETOURS_64BIT != 1
#error AMD64 Detours branch required
#endif
#if defined(_DEBUG) || (defined(DETOUR_DEBUG) && DETOUR_DEBUG != 0)
#error No debug tracing/assertion branch admitted
#endif
static_assert(sizeof(BOOL)==4 && sizeof(DWORD)==4 && sizeof(void*)==8,"Win32 ABI widths");
static_assert(sizeof(IMAGE_DOS_HEADER)==64 && sizeof(IMAGE_NT_HEADERS64)==264 && sizeof(IMAGE_SECTION_HEADER)==40,"PE64 payload arithmetic");
static_assert(sizeof(DETOUR_SECTION_HEADER)==64 && sizeof(DETOUR_SECTION_RECORD)==24,"pinned Detours payload arithmetic");
static_assert((64+264+40+64+24)%8==0 && (64+264+40+64+24+248)%8==0,"payload and sequence alignment source assertion");
namespace {
const GUID kPayloadGuid={0x2b58d96c,0x8af4,0x4c07,{0xae,0x18,0x68,0xc3,0x74,0xd0,0xf2,0x91}};
alignas(8) volatile LONG64 next_generation=0;
HANDLE handle(cl::u64 v){return reinterpret_cast<HANDLE>(static_cast<std::uintptr_t>(v));}
cl::u64 filetime(FILETIME f){return (static_cast<cl::u64>(f.dwHighDateTime)<<32)|f.dwLowDateTime;}
struct NativeAPI {
 cl::u64 generation(){const LONG64 v=InterlockedIncrement64(&next_generation);return v>0?static_cast<cl::u64>(v):0;}
 bool clock(cl::u64 expected,cl::u64& tick){LARGE_INTEGER f{},q{};if(!QueryPerformanceFrequency(&f)||f.QuadPart<=0||static_cast<cl::u64>(f.QuadPart)!=expected||!QueryPerformanceCounter(&q)||q.QuadPart<0)return false;tick=static_cast<cl::u64>(q.QuadPart);return true;}
 cl::HeldReturn held(const CL_PLAN256& p){const HANDLE h=handle(p.borrowed_held_process_handle);const DWORD pid=GetProcessId(h);FILETIME a{},b{},c{},d{};
  if(!pid||pid!=p.target_pid||!GetProcessTimes(h,&a,&b,&c,&d)||filetime(a)!=p.target_creation_FILETIME)return {false,false,false};
  const DWORD w=WaitForSingleObject(h,0);return {w==WAIT_TIMEOUT||w==WAIT_OBJECT_0,w==WAIT_TIMEOUT,w==WAIT_OBJECT_0};}
 cl::BoolReturn update(cl::u64 h,const char* path){LPCSTR names[1]={path};const BOOL value=DetourUpdateProcessWithDll(handle(h),names,1);const DWORD error=value?0:GetLastError();return {value,error};}
 cl::CopyReturn copy(cl::u64 h,const CL_MARKER256& m){PVOID value=DetourCopyPayloadToProcessEx(handle(h),kPayloadGuid,&m,sizeof(m));const DWORD error=value?0:GetLastError();return {static_cast<cl::u64>(reinterpret_cast<std::uintptr_t>(value)),error};}
 cl::ReadReturn read(cl::u64 h,cl::u64 address,void* data,std::size_t size){SIZE_T count=0;const BOOL value=ReadProcessMemory(handle(h),reinterpret_cast<const void*>(static_cast<std::uintptr_t>(address)),data,size,&count);const DWORD error=value?0:GetLastError();return {value,error,count};}
};
cl::u32 cpp_dispatch(cl::u32 op,const CL_PLAN256* p,CL_CONTEXT* c,CL_MARKER256* marker,CL_RESULT128* r) noexcept {
 try {NativeAPI api;
  switch(op){case cl::begin_operation:return cl::begin(api,p,c,r);case cl::update_operation:return cl::update(api,c,r);
   case cl::install_operation:return cl::install(api,c,marker,r);case cl::read_operation:return cl::read(api,c,marker,r);case cl::forget_operation:return cl::forget(api,c,r);default:return cl::rejected;}
 } catch(...) {return cl::caught(c,r,op,0xe06d7363u);}
}
// POD-only SEH boundaries intentionally contain no C++ object with a destructor.
// C++ exception handling lives in cpp_dispatch; no __try function can hit C2712.
cl::u32 safe_fault(cl::u32 op,CL_CONTEXT* c,CL_RESULT128* r,cl::u32 code) noexcept {
 __try {return cl::caught(c,r,op,code);} __except(EXCEPTION_EXECUTE_HANDLER){return cl::exception;}
}
cl::u32 seh_dispatch(cl::u32 op,const CL_PLAN256* p,CL_CONTEXT* c,CL_MARKER256* marker,CL_RESULT128* r) noexcept {
 __try {return cpp_dispatch(op,p,c,marker,r);} __except(EXCEPTION_EXECUTE_HANDLER){return safe_fault(op,c,r,static_cast<cl::u32>(GetExceptionCode()));}
}
} // namespace
CL_API std::uint32_t CL_CALL cl_abi_version(){return 1;}
CL_API std::uint32_t CL_CALL cl_begin_v1(const CL_PLAN256* p,CL_CONTEXT* c,CL_RESULT128* r){return seh_dispatch(cl::begin_operation,p,c,nullptr,r);}
CL_API std::uint32_t CL_CALL cl_update_v1(CL_CONTEXT* c,CL_RESULT128* r){return seh_dispatch(cl::update_operation,nullptr,c,nullptr,r);}
CL_API std::uint32_t CL_CALL cl_install_marker_v1(CL_CONTEXT* c,const CL_MARKER256* m,CL_RESULT128* r){return seh_dispatch(cl::install_operation,nullptr,c,const_cast<CL_MARKER256*>(m),r);}
CL_API std::uint32_t CL_CALL cl_read_marker_v1(CL_CONTEXT* c,CL_MARKER256* m,CL_RESULT128* r){return seh_dispatch(cl::read_operation,nullptr,c,m,r);}
CL_API std::uint32_t CL_CALL cl_forget_exited_v1(CL_CONTEXT* c,CL_RESULT128* r){return seh_dispatch(cl::forget_operation,nullptr,c,nullptr,r);}
