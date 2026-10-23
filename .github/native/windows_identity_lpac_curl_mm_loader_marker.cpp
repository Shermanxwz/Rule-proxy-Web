#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#ifndef NOMINMAX
#define NOMINMAX
#endif
#include <windows.h>
#include "../vendor/detours/src/detours.h"
#include "windows_identity_lpac_curl_mm_loader_marker_core.hpp"
#if !defined(_WIN64) || !defined(DETOURS_X64) || DETOURS_64BIT != 1
#error AMD64 Detours branch required
#endif
#if defined(_DEBUG) || (defined(DETOUR_DEBUG) && DETOUR_DEBUG != 0)
#error No debug/assertion branch admitted
#endif
static_assert(sizeof(BOOL)==4&&sizeof(DWORD)==4&&sizeof(void*)==8,"Win32 widths");
namespace {
const GUID kPayloadGuid={0xb4626452,0x3359,0x4b34,{0x9a,0x97,0xdd,0x85,0xe4,0xb7,0x9f,0x2c}};
struct MarkerAPI {
 cmm::Payload find(){DWORD size=0;PVOID p=DetourFindPayloadEx(kPayloadGuid,&size);return {static_cast<CMM_MARKER320*>(p),size};}
 cmm::MarkerIdentity identity(){FILETIME a{},b{},c{},d{};const DWORD pid=GetCurrentProcessId();const BOOL ok=GetProcessTimes(GetCurrentProcess(),&a,&b,&c,&d);return {pid,(static_cast<cmm::u64>(a.dwHighDateTime)<<32)|a.dwLowDateTime,ok!=FALSE};}
 bool clock(cmm::u64 expected,cmm::u64& tick){LARGE_INTEGER f{},q{};if(!QueryPerformanceFrequency(&f)||f.QuadPart<=0||static_cast<cmm::u64>(f.QuadPart)!=expected||!QueryPerformanceCounter(&q)||q.QuadPart<0)return false;tick=static_cast<cmm::u64>(q.QuadPart);return true;}
 cmm::BoolReturn clear_inherit(cmm::u64 h){const BOOL value=SetHandleInformation(reinterpret_cast<HANDLE>(static_cast<std::uintptr_t>(h)),HANDLE_FLAG_INHERIT,0);const DWORD error=value?0:GetLastError();return {value,error};}
 cmm::BoolReturn set_event(cmm::u64 h){const BOOL value=SetEvent(reinterpret_cast<HANDLE>(static_cast<std::uintptr_t>(h)));const DWORD error=value?0:GetLastError();return {value,error};}
 cmm::BoolReturn restore(){const BOOL value=DetourRestoreAfterWith();const DWORD error=value?0:GetLastError();return {value,error};}
 void sequence_increment(cmm::u64& x){InterlockedIncrement64(reinterpret_cast<volatile LONG64*>(&x));}
};
BOOL cpp_attach(cmm::u64 base,CMM_MARKER320** touched) noexcept {try{MarkerAPI api;return cmm::marker_attach(api,base,touched)?TRUE:FALSE;}catch(...){MarkerAPI api;cmm::marker_caught(api,*touched);return FALSE;}}
BOOL cpp_fault(CMM_MARKER320* touched) noexcept {MarkerAPI api;cmm::marker_caught(api,touched);return FALSE;}
BOOL safe_fault(CMM_MARKER320* touched) noexcept {__try{return cpp_fault(touched);}__except(EXCEPTION_EXECUTE_HANDLER){return FALSE;}}
BOOL seh_attach(cmm::u64 base) noexcept {CMM_MARKER320* touched=nullptr;__try{return cpp_attach(base,&touched);}__except(EXCEPTION_EXECUTE_HANDLER){return safe_fault(touched);}}
}
extern "C" void WINAPI cmm_marker_anchor(void) {}
extern "C" BOOL WINAPI DllMain(HINSTANCE instance,DWORD reason,LPVOID reserved){(void)reserved;
 // Exactly the original target API sequence. The new HINSTANCE is passed as a
 // scalar to the new sequence-protected layout; no lookup, wait or delay.
 if(reason==DLL_PROCESS_ATTACH)return seh_attach(static_cast<cmm::u64>(reinterpret_cast<std::uintptr_t>(instance)));return TRUE;}
