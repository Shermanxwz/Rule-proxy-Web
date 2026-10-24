// A5 startup diagnostic ONLY. SOURCE ONLY, Ready false, no author execution.
#include "windows_identity_lpac_curl_a5_startup_win32.hpp"
#include "windows_identity_lpac_curl_http_surface.hpp"
namespace a5_http_glue {
inline bool configure(const lpac_curl_http::Config&,std::uint64_t,std::uint64_t,lpac_curl_http::Endpoint);
inline bool transport_cleanup();
}
namespace {
using namespace a5startup;using namespace a5startup::win;
Runtime runtime;
// Trivial compiler TLS; no TLS allocator, Winsock TLS, mutex wait or callback.
__declspec(thread) int thread_error=0;
lpac_curl_http::Config fixed_http(const a5startup::Config2048& raw){
 lpac_curl_http::Config c;c.stream.front=true;std::memcpy(c.stream.run.data(),raw.run,16);std::memcpy(c.stream.case_id.data(),raw.case_id,16);
 c.stream.send=raw.request_total;c.stream.receive=raw.response_total;c.target={{127,0,0,1},raw.origin_port};
 c.frequency=raw.frequency;c.start=raw.window_start;c.end=raw.window_end;c.target_path="/ruleproxy-a2/"+lpac_curl_http::id(c.stream.case_id);
 c.request_body=raw.request_body;c.response_body=raw.response_body;
 // Expected prefixes only. send() still copies curl's original bytes; this
 // does not generate or substitute an application HTTP request or response.
 c.request_header="POST "+c.target_path+" HTTP/1.1\r\nHost: 127.0.0.1:"+std::to_string(raw.origin_port)+"\r\nContent-Length: 8065\r\nConnection: close\r\n\r\n";
 c.response_header="HTTP/1.1 200 OK\r\nContent-Length: 12176\r\nConnection: close\r\nX-RuleProxy-Case: "+lpac_curl_http::id(c.stream.case_id)+"\r\n\r\n";
 return c;
}
template<class T>u64 arg(T value){return static_cast<u64>(value);}
template<class T>u64 arg(T* value){return number(value);}
int deliver_unsupported(u32 ordinal,u64 a,u64 b,u64 c,std::int64_t delivered){
 auto row=runtime.open(ordinal,a,b,c);runtime.reject(row);ErrorSlot slot{thread_error};
 runtime.startup().unsupported_call(slot);thread_error=slot.value;
 runtime.finish(row,delivered,thread_error,true);return thread_error;
}
bool name(Call& row,InputKind kind,const void* pointer){MemoryReader reader{};
 const bool okay=capture_name(row.row,kind,number(pointer),reader);runtime.sync(row);if(!okay)runtime.fault(row);return okay;}
u32 utf16_length(const Call& row){return row.row.captured_bytes>=2?row.row.captured_bytes/2-1:0;}
FARPROC address(u32 ordinal){switch(ordinal){
 case 1:return reinterpret_cast<FARPROC>(&a5_accept);case 2:return reinterpret_cast<FARPROC>(&a5_bind);
 case 3:return reinterpret_cast<FARPROC>(&a5_closesocket);case 4:return reinterpret_cast<FARPROC>(&a5_connect);
 case 5:return reinterpret_cast<FARPROC>(&a5_getpeername);case 6:return reinterpret_cast<FARPROC>(&a5_getsockname);
 case 7:return reinterpret_cast<FARPROC>(&a5_getsockopt);case 8:return reinterpret_cast<FARPROC>(&a5_htonl);
 case 9:return reinterpret_cast<FARPROC>(&a5_htons);case 10:return reinterpret_cast<FARPROC>(&a5_ioctlsocket);
 case 13:return reinterpret_cast<FARPROC>(&a5_listen);case 15:return reinterpret_cast<FARPROC>(&a5_ntohs);
 case 16:return reinterpret_cast<FARPROC>(&a5_recv);case 17:return reinterpret_cast<FARPROC>(&a5_recvfrom);
 case 18:return reinterpret_cast<FARPROC>(&a5_select);case 19:return reinterpret_cast<FARPROC>(&a5_send);
 case 20:return reinterpret_cast<FARPROC>(&a5_sendto);case 21:return reinterpret_cast<FARPROC>(&a5_setsockopt);
 case 22:return reinterpret_cast<FARPROC>(&a5_shutdown);case 23:return reinterpret_cast<FARPROC>(&a5_socket);
 case 45:return reinterpret_cast<FARPROC>(&a5_WSACloseEvent);case 50:return reinterpret_cast<FARPROC>(&a5_WSACreateEvent);
 case 57:return reinterpret_cast<FARPROC>(&a5_gethostname);case 64:return reinterpret_cast<FARPROC>(&a5_WSAEnumNetworkEvents);
 case 67:return reinterpret_cast<FARPROC>(&a5_WSAEventSelect);case 78:return reinterpret_cast<FARPROC>(&a5_WSAIoctl);
 case 95:return reinterpret_cast<FARPROC>(&a5_WSAResetEvent);case 111:return reinterpret_cast<FARPROC>(&a5_WSAGetLastError);
 case 112:return reinterpret_cast<FARPROC>(&a5_WSASetLastError);case 115:return reinterpret_cast<FARPROC>(&a5_WSAStartup);
 case 116:return reinterpret_cast<FARPROC>(&a5_WSACleanup);case 124:return reinterpret_cast<FARPROC>(&a5_WSAWaitForMultipleEvents);
 case 151:return reinterpret_cast<FARPROC>(&a5___WSAFDIsSet);case 191:return reinterpret_cast<FARPROC>(&a5_freeaddrinfo);
 case 192:return reinterpret_cast<FARPROC>(&a5_getaddrinfo);case 200:return reinterpret_cast<FARPROC>(&a5_GetProcAddress);
 case 201:return reinterpret_cast<FARPROC>(&a5_GetModuleHandleW);case 202:return reinterpret_cast<FARPROC>(&a5_LoadLibraryExW);
 case 203:return reinterpret_cast<FARPROC>(&a5_FreeLibrary);default:return nullptr;}}
}
extern "C" BOOL WINAPI DllMain(HINSTANCE self,DWORD why,LPVOID){
 // No payload lookup, I/O, loader call, RestoreAfterWithEx, wait, thread,
 // transaction, network, allocation or TLS work under loader lock.
 if(why==DLL_PROCESS_ATTACH)runtime.attached(self);return TRUE;
}
extern "C" int WSAAPI a5_WSAStartup(WORD requested,LPWSADATA output){
 auto row=runtime.open(115,requested,number(output));ErrorSlot slot{thread_error};int status=bad_pointer;
 struct Writer {LPWSADATA target;StartupData408 committed{};bool copied=false;
  bool operator()(const StartupData408& data){if(!target||!guarded_copy(target,&data,408))return false;committed=data;copied=true;return true;}} writer{output};
 if(runtime.allowed(row)){status=runtime.startup().startup(requested,slot,writer);if(requested!=0x0202)runtime.reject(row);
  if(writer.copied)capture_wsadata(row.row,writer.committed,true);
  else if(status==bad_pointer){row.row.raw.flags|=input_fault;runtime.fault(row);}}
 if(status==0){
  bool configured=false;
  try {const auto& raw=runtime.config();const auto expected=fixed_http(raw);
   configured=a5_http_glue::configure(expected,raw.pipe_read,raw.pipe_write,{{127,0,0,1},raw.virtual_local_port});}
  catch(...){runtime.fault(row);}
  if(!configured){runtime.fault(row,reference_uncertain);status=10055;a5_http_glue::transport_cleanup();}
 }
 thread_error=slot.value;runtime.finish(row,status,0,false);return status;
}
extern "C" int WSAAPI a5_WSACleanup(void){
 auto row=runtime.open(116);ErrorSlot slot{thread_error};int result=socket_error;
 const bool resources=a5_http_glue::transport_cleanup(); // known once-close even after work expiry
 if(runtime.allowed(row))result=runtime.startup().cleanup(slot);else slot.value=not_initialized;
 if(!resources){runtime.fault(row,reference_uncertain);result=socket_error;slot.value=10038;}
 thread_error=slot.value;runtime.finish(row,result,result==socket_error?thread_error:0,result==socket_error);return result;
}
extern "C" int WSAAPI a5_WSAGetLastError(void){const int result=thread_error;auto row=runtime.open(111);runtime.finish(row,result,0,false);return result;}
extern "C" void WSAAPI a5_WSASetLastError(int value){auto row=runtime.open(112,static_cast<u64>(static_cast<std::int64_t>(value)));thread_error=value;runtime.finish(row,0,0,false);}
extern "C" FARPROC WINAPI a5_GetProcAddress(HMODULE value,LPCSTR procedure){
 auto row=runtime.open(200,number(value),number(procedure));FARPROC result=nullptr;int error=ERROR_PROC_NOT_FOUND;
 const auto module_kind=runtime.bound_module(value);row.row.module_kind=static_cast<u32>(module_kind);
 const u64 pointer=number(procedure);Resolution resolution{ResolutionKind::unsupported,0};
 bool captured=false;
 if(pointer&&pointer<=65535){captured=capture_ordinal(row.row,static_cast<u32>(pointer));if(captured)resolution=resolve(module_kind,nullptr,0,static_cast<u32>(pointer));}
 else if(!pointer){captured=capture_null(row.row);}
 else if(name(row,InputKind::procedure_ascii,procedure)){captured=true;
  resolution=resolve(module_kind,reinterpret_cast<const char*>(row.row.name_or_WSADATA),row.row.captured_bytes-1);}
 row.row.resolution_kind=static_cast<u32>(resolution.kind);row.row.resolved_ordinal=resolution.ordinal;runtime.sync(row);
 if(captured&&runtime.allowed(row)){
  if(resolution.kind==ResolutionKind::private_export)result=address(resolution.ordinal);
  else if(resolution.kind==ResolutionKind::system_filename)result=runtime.filename();
  else if(resolution.kind==ResolutionKind::ntdll_version)result=runtime.version();
 }
 if(!result)runtime.reject(row);runtime.finish(row,static_cast<std::int64_t>(number(reinterpret_cast<const void*>(result))),result?0:error,!result);
 if(!result)SetLastError(error);return result;
}
extern "C" HMODULE WINAPI a5_GetModuleHandleW(LPCWSTR input){
 auto row=runtime.open(201,number(input));HMODULE result=nullptr;Module kind=Module::unknown;bool captured=false;
 if(!input){captured=capture_null(row.row);kind=Module::main_image;}
 else if(name(row,InputKind::module_utf16,input)){captured=true;kind=classify_module(reinterpret_cast<const u16*>(row.row.name_or_WSADATA),utf16_length(row),runtime.config());}
 row.row.module_kind=static_cast<u32>(kind);runtime.sync(row);
 if(captured&&runtime.allowed(row))result=runtime.borrowed(kind);
 if(!result)runtime.reject(row);runtime.finish(row,static_cast<std::int64_t>(number(result)),result?0:ERROR_MOD_NOT_FOUND,!result);
 if(!result)SetLastError(ERROR_MOD_NOT_FOUND);return result;
}
extern "C" HMODULE WINAPI a5_LoadLibraryExW(LPCWSTR input,HANDLE file,DWORD flags){
 auto row=runtime.open(202,number(input),number(file),flags);HMODULE delivered=nullptr;int error=ERROR_MOD_NOT_FOUND;
 const bool captured=input&&name(row,InputKind::module_utf16,input);
 Module kind=Module::unknown;if(captured)kind=classify_module(reinterpret_cast<const u16*>(row.row.name_or_WSADATA),utf16_length(row),runtime.config());
 else if(!input)capture_null(row.row);row.row.module_kind=static_cast<u32>(kind);runtime.sync(row);
 if(captured&&load_allowed(kind,number(file),flags)&&runtime.allowed(row)&&runtime.lock_references()){
  if(runtime.can_load()){
   wchar_t owned_path[1024]{};const auto& config=runtime.config();for(u32 i=0;i<config.private_path_bytes;++i)owned_path[i]=static_cast<unsigned char>(config.private_path[i]);
   const bool timely=runtime.primary(row,{202,number(owned_path),0,flags,nullptr,0});
   // Raw SDK acquisition first. A late/failed observation does not erase it.
   const bool known=runtime.acquired(row);const auto actual=module(static_cast<u64>(row.row.sdk.raw_return));
   bool bound=false;if((row.row.sdk.flags&sdk_returned)&&actual&&known)bound=runtime.verify_acquired_name(actual);
   if(timely&&known&&bound)delivered=actual;
   if(!delivered&&row.row.sdk.flags&sdk_returned)error=row.row.sdk.error;
  }else runtime.fault(row,reference_uncertain);
  runtime.unlock_references();
 }
 if(!delivered)runtime.reject(row);runtime.finish(row,static_cast<std::int64_t>(number(delivered)),delivered?0:error,!delivered);
 if(!delivered)SetLastError(error);return delivered;
}
extern "C" BOOL WINAPI a5_FreeLibrary(HMODULE value){
 auto row=runtime.open(203,number(value));BOOL delivered=FALSE;int error=ERROR_INVALID_HANDLE;
 if(runtime.bound_module(value)==Module::private_shim&&runtime.lock_references()){
  u32 ticket=0;if(runtime.take_release(value,ticket)){
   // consume-before-call. Known release remains attempted despite late clock.
   const bool timely=runtime.primary(row,{203,number(value),0,0,nullptr,0});const bool known=runtime.released(ticket,row);
   if(timely&&known)delivered=static_cast<BOOL>(row.row.sdk.raw_return);
   if(!delivered&&(row.row.sdk.flags&sdk_returned))error=row.row.sdk.error;
  }
  runtime.unlock_references();
 }
 if(!delivered)runtime.reject(row);runtime.finish(row,delivered,delivered?0:error,!delivered);if(!delivered)SetLastError(error);return delivered;
}
// Unsupported functions never dereference their argument buffers or call a
// provider/socket API. Only first three scalar arguments are retained; full
// arbitrary protocol/name payload capture is deliberately not claimed.
extern "C" SOCKET WSAAPI a5_accept(SOCKET s,sockaddr* a,int* n){deliver_unsupported(1,arg(s),arg(a),arg(n),-1);return INVALID_SOCKET;}
extern "C" int WSAAPI a5_bind(SOCKET s,const sockaddr* a,int n){deliver_unsupported(2,arg(s),arg(a),arg(n),-1);return SOCKET_ERROR;}
extern "C" int WSAAPI a5_listen(SOCKET s,int backlog){deliver_unsupported(13,arg(s),arg(backlog),0,-1);return SOCKET_ERROR;}
extern "C" int WSAAPI a5_recvfrom(SOCKET s,char* p,int n,int,sockaddr*,int*){deliver_unsupported(17,arg(s),arg(p),arg(n),-1);return SOCKET_ERROR;}
extern "C" int WSAAPI a5_sendto(SOCKET s,const char* p,int n,int,const sockaddr*,int){deliver_unsupported(20,arg(s),arg(p),arg(n),-1);return SOCKET_ERROR;}
extern "C" int WSAAPI a5_shutdown(SOCKET s,int how){deliver_unsupported(22,arg(s),arg(how),0,-1);return SOCKET_ERROR;}
extern "C" int WSAAPI a5_gethostname(char* p,int n){deliver_unsupported(57,arg(p),arg(n),0,-1);return SOCKET_ERROR;}
extern "C" void WSAAPI a5_freeaddrinfo(PADDRINFOA p){deliver_unsupported(191,arg(p),0,0,0);}
extern "C" INT WSAAPI a5_getaddrinfo(PCSTR node,PCSTR service,const ADDRINFOA* hints,PADDRINFOA*){auto row=runtime.open(192,arg(node),arg(service),arg(hints));runtime.reject(row);
 ErrorSlot slot{thread_error};runtime.startup().unsupported_call(slot);thread_error=slot.value;runtime.finish(row,EAI_FAIL,0,false);return EAI_FAIL;}

// Actual finite A5 transport definitions; no extra DllMain work.
#include "windows_identity_lpac_curl_http_glue_win32.hpp"
