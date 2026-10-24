// Source-only A4 configuration carrier. No DLL load, process creation,
// thread, Resume, network, rollback, close, payload search or restoration.
#define WIN32_LEAN_AND_MEAN
#define NOMINMAX
#include <windows.h>
#include <cstring>
#include "windows_identity_lpac_curl_a4_payload_wrapper.hpp"
#include "../vendor/detours/src/detours.h"
namespace {
const GUID config_guid={0x8b743b1e,0x2850,0x4c82,{0xa3,0x50,0xfd,0xa8,0x43,0x9e,0x3a,0xb1}};
bool span(const void* p,std::size_t count){const auto n=reinterpret_cast<std::uintptr_t>(p);
 return n>=0x10000&&count&&n<0x800000000000ull&&count<=0x800000000000ull-n;}
bool copy(void* dst,const void* src,std::size_t count){
 __try{std::memcpy(dst,src,count);return true;}__except(EXCEPTION_EXECUTE_HANDLER){return false;}
}
bool zero(const a4payload::Result32& r){const std::uint8_t* b=reinterpret_cast<const std::uint8_t*>(&r);
 for(std::size_t i=0;i<sizeof(r);++i)if(b[i])return false;return true;}
bool overlap(const void* a,std::size_t an,const void* b,std::size_t bn){
 const auto x=reinterpret_cast<std::uintptr_t>(a),y=reinterpret_cast<std::uintptr_t>(b);return x<y+bn&&y<x+an;}
// Capture the primitive result before any clock, identity or readback call.
// NULL can follow a partial remote allocation/write. No zero-effect or retry
// claim follows from it; only the supervised exact target lifetime resolves
// its process-local allocation scope.
void invoke(HANDLE process,const std::uint8_t* config,a4payload::Result32* out){
 out->flags|=a4payload::entered;
 __try{
  void* value=DetourCopyPayloadToProcessEx(process,config_guid,const_cast<std::uint8_t*>(config),a4payload::config_bytes);
  const DWORD error=value?0:GetLastError();
  out->raw_pointer=reinterpret_cast<std::uintptr_t>(value);out->flags|=a4payload::returned;
  if(!value){out->error=error;out->flags|=a4payload::error_valid;}
 }__except(EXCEPTION_EXECUTE_HANDLER){out->seh_code=GetExceptionCode();out->flags|=a4payload::exception;}
}
}
extern "C" __declspec(dllexport) std::uint32_t WINAPI a4_payload_abi_v1(){return 1;}
extern "C" __declspec(dllexport) std::uint32_t WINAPI a4_copy_config_v1(
 HANDLE process,const std::uint8_t* input,std::uint32_t bytes,a4payload::Result32* output){
 const auto handle=reinterpret_cast<std::uintptr_t>(process);
 if(!handle||handle>=0x800000000000ull||bytes!=a4payload::config_bytes||!span(input,bytes)
  ||!span(output,sizeof(*output))||(reinterpret_cast<std::uintptr_t>(output)&7u)
  ||overlap(input,bytes,output,sizeof(*output)))return 1;
 a4payload::Result32 previous{},result{};std::uint8_t owned[a4payload::config_bytes]{};
 if(!copy(&previous,output,sizeof(previous))||!zero(previous))return 1;
 result.size=static_cast<std::uint32_t>(sizeof(result));result.version=1;
 const std::uint8_t prefix[8]={'A','4','P','1',1,0,0,8};
 if(!copy(owned,input,bytes)||std::memcmp(owned,prefix,sizeof(prefix))){
  result.flags=a4payload::input_fault;return copy(output,&result,sizeof(result))?1u:2u;
 }
 invoke(process,owned,&result);
 // A returned record is raw transport evidence only. Parent must still
 // obtain exact framing+Config2048 physical readback and known RO/query
 // before it can consider any later selected Resume.
 if(!copy(output,&result,sizeof(result)))return 2;
 return (result.flags&a4payload::exception)?2u:0u;
}
