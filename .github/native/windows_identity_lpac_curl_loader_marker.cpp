#define WIN32_LEAN_AND_MEAN
#define NOMINMAX
#include <windows.h>
#include "../vendor/detours/src/detours.h"
#include "windows_identity_lpac_curl_loader_marker_core.hpp"
#if !defined(_WIN64) || !defined(DETOURS_X64) || DETOURS_64BIT != 1
#error AMD64 Detours branch required
#endif
#if defined(_DEBUG) || (defined(DETOUR_DEBUG) && DETOUR_DEBUG != 0)
#error No debug tracing/assertion branch admitted
#endif
static_assert(sizeof(BOOL)==4 && sizeof(DWORD)==4 && sizeof(void*)==8,"Win32 ABI widths");
namespace {
const GUID kPayloadGuid={0x2b58d96c,0x8af4,0x4c07,{0xae,0x18,0x68,0xc3,0x74,0xd0,0xf2,0x91}};
struct MarkerAPI {
 cl::Payload find(){DWORD size=0;PVOID p=DetourFindPayloadEx(kPayloadGuid,&size);return {static_cast<CL_MARKER256*>(p),size};}
 cl::Identity identity(){FILETIME a{},b{},c{},d{};const DWORD pid=GetCurrentProcessId();const BOOL ok=GetProcessTimes(GetCurrentProcess(),&a,&b,&c,&d);return {pid,(static_cast<cl::u64>(a.dwHighDateTime)<<32)|a.dwLowDateTime,ok!=FALSE};}
 bool clock(cl::u64 expected,cl::u64& tick){LARGE_INTEGER f{},q{};if(!QueryPerformanceFrequency(&f)||f.QuadPart<=0||static_cast<cl::u64>(f.QuadPart)!=expected||!QueryPerformanceCounter(&q)||q.QuadPart<0)return false;tick=static_cast<cl::u64>(q.QuadPart);return true;}
 cl::BoolReturn clear_inherit(cl::u64 h){const BOOL value=SetHandleInformation(reinterpret_cast<HANDLE>(static_cast<std::uintptr_t>(h)),HANDLE_FLAG_INHERIT,0);const DWORD error=value?0:GetLastError();return {value,error};}
 cl::BoolReturn set_event(cl::u64 h){const BOOL value=SetEvent(reinterpret_cast<HANDLE>(static_cast<std::uintptr_t>(h)));const DWORD error=value?0:GetLastError();return {value,error};}
 cl::BoolReturn restore(){const BOOL value=DetourRestoreAfterWith();const DWORD error=value?0:GetLastError();return {value,error};}
 void sequence_increment(cl::u64& value){InterlockedIncrement64(reinterpret_cast<volatile LONG64*>(&value));}
};
BOOL cpp_attach(CL_MARKER256** touched) noexcept {try{MarkerAPI api;return cl::marker_attach(api,touched)?TRUE:FALSE;}catch(...){MarkerAPI api;return cl::marker_caught(api,*touched)?TRUE:FALSE;}}
BOOL cpp_marker_fault(CL_MARKER256* touched) noexcept {MarkerAPI api;cl::marker_caught(api,touched);return FALSE;}
// SEH frames contain only scalar/POD values; C++ objects stay in callees.
BOOL marker_fault(CL_MARKER256* touched) noexcept {__try{return cpp_marker_fault(touched);}__except(EXCEPTION_EXECUTE_HANDLER){return FALSE;}}
BOOL seh_attach() noexcept {CL_MARKER256* touched=nullptr;__try{return cpp_attach(&touched);}__except(EXCEPTION_EXECUTE_HANDLER){return marker_fault(touched);}}
}
extern "C" void WINAPI cl_marker_anchor(void) {}
extern "C" BOOL WINAPI DllMain(HINSTANCE instance,DWORD reason,LPVOID reserved){(void)instance;(void)reserved;if(reason==DLL_PROCESS_ATTACH)return seh_attach();return TRUE;}
