#define WIN32_LEAN_AND_MEAN
#define NOMINMAX
#include <windows.h>
#include <algorithm>
#include <array>
#include <cstdint>
#include <cstring>
#include <iostream>
#include <stdexcept>
#include <vector>
#include "../.github/native/windows_identity_lpac_curl_http_adapter.hpp"
namespace fake {
std::uint64_t now=1001, frequency=1000000, jump_after_write=0;
DWORD error=0, flags[2]={1,1}; unsigned closes[2]={0,0};
bool fail_close=false, broken=false, count_bad=false;
std::vector<std::uint8_t> output;
int index(HANDLE h){return static_cast<int>(reinterpret_cast<std::uintptr_t>(h))-100;}
BOOL qpc(LARGE_INTEGER* p){p->QuadPart=static_cast<LONGLONG>(now++);return TRUE;}
BOOL qpf(LARGE_INTEGER* p){p->QuadPart=static_cast<LONGLONG>(frequency);return TRUE;}
DWORD last(){return error;}
DWORD type(HANDLE){return FILE_TYPE_PIPE;}
BOOL get(HANDLE h,DWORD* p){*p=flags[index(h)];return TRUE;}
BOOL set(HANDLE h,DWORD mask,DWORD f){flags[index(h)]=(flags[index(h)]&~mask)|(f&mask);return TRUE;}
BOOL close(HANDLE h){++closes[index(h)];if(fail_close){error=ERROR_INVALID_HANDLE;return FALSE;}return TRUE;}
BOOL write(HANDLE,const void* p,DWORD n,DWORD* count,OVERLAPPED*){
    const auto* bytes=static_cast<const std::uint8_t*>(p);output.insert(output.end(),bytes,bytes+n);
    *count=n+(count_bad?1u:0u);if(jump_after_write)now=jump_after_write;return TRUE;
}
BOOL peek(HANDLE,void*,DWORD,DWORD*,DWORD* available,DWORD*){
    *available=0;if(broken){error=ERROR_BROKEN_PIPE;return FALSE;}return TRUE;
}
BOOL read(HANDLE,void*,DWORD,DWORD* count,OVERLAPPED*){*count=0;error=ERROR_BROKEN_PIPE;return FALSE;}
void reset(){now=1001;frequency=1000000;jump_after_write=0;error=0;flags[0]=flags[1]=1;
    closes[0]=closes[1]=0;fail_close=broken=count_bad=false;output.clear();}
}
#define QueryPerformanceCounter fake::qpc
#define QueryPerformanceFrequency fake::qpf
#define GetLastError fake::last
#define GetFileType fake::type
#define GetHandleInformation fake::get
#define SetHandleInformation fake::set
#define CloseHandle fake::close
#define WriteFile fake::write
#define PeekNamedPipe fake::peek
#define ReadFile fake::read
#include "../.github/native/windows_identity_lpac_curl_http_pipe_win32.hpp"
#undef QueryPerformanceCounter
#undef QueryPerformanceFrequency
#undef GetLastError
#undef GetFileType
#undef GetHandleInformation
#undef SetHandleInformation
#undef CloseHandle
#undef WriteFile
#undef PeekNamedPipe
#undef ReadFile
using namespace lpac_curl_http;
unsigned assertions=0;
void need(bool b){++assertions;if(!b)throw std::runtime_error("pipe assertion");}
Config configuration(){
    Config c;c.stream.front=true;c.stream.run.fill(1);c.stream.case_id.fill(2);
    c.stream.send=8193;c.stream.receive=12289;c.target={{127,0,0,1},51001};
    c.frequency=1000000;c.start=1000;c.end=8001000;c.target_path="/ruleproxy-a2/"+id(c.stream.case_id);
    c.request_header="POST "+c.target_path+" HTTP/1.1\r\nHost: 127.0.0.1:51001\r\nContent-Length: 8065\r\nConnection: close\r\n\r\n";
    c.response_header="HTTP/1.1 200 OK\r\nContent-Length: 12176\r\nConnection: close\r\nX-RuleProxy-Case: "+id(c.stream.case_id)+"\r\n\r\n";
    c.request_body=8065;c.response_body=12176;return c;
}
void opened(SocketCore& core,const Config& c){
    need(core.create(2,1,6,fake::now++).state==State::okay);
    need(core.begin_connect(VirtualSocket,c.target,fake::now++).state==State::pending);
}
int main(){try{
    const auto c=configuration();
    {fake::reset();SocketCore core(c);PipeTransport pipe(core,100,100,c.frequency,c.start,c.end);
        need(!pipe.prepare());pipe.cleanup();need(fake::closes[0]==0&&fake::closes[1]==0);}
    {fake::reset();SocketCore core(c);PipeTransport pipe(core,100,101,c.frequency,c.start,c.end);
        need(pipe.prepare());need(fake::flags[0]==0&&fake::flags[1]==0);
        need(pipe.facts().reader_inherit_cleared&&pipe.facts().writer_inherit_cleared);
        pipe.cleanup();pipe.cleanup();need(fake::closes[0]==1&&fake::closes[1]==1);
        need(pipe.facts().reader_closed&&pipe.facts().writer_closed&&!pipe.facts().close_unknown);}
    {fake::reset();SocketCore core(c);PipeTransport pipe(core,100,101,c.frequency,c.start,c.end);
        need(pipe.prepare());fake::fail_close=true;pipe.cleanup();pipe.cleanup();
        need(fake::closes[0]==1&&fake::closes[1]==1);need(pipe.facts().close_unknown&&!pipe.okay());}
    {fake::reset();fake::flags[0]=0;SocketCore core(c);PipeTransport pipe(core,100,101,c.frequency,c.start,c.end);
        need(!pipe.prepare());need(!pipe.facts().prepared);pipe.cleanup();need(fake::closes[0]==1&&fake::closes[1]==1);}
    {fake::reset();SocketCore core(c);opened(core,c);PipeTransport pipe(core,100,101,c.frequency,c.start,c.end);
        need(pipe.prepare());need(pipe.pump());need(pipe.facts().write_calls==1);
        need(pipe.facts().write_bytes==fake::output.size()&&!fake::output.empty());
        need(pipe.facts().write_bytes<=1088);need(pipe.facts().peek_calls==1);pipe.cleanup();}
    {fake::reset();SocketCore core(c);opened(core,c);PipeTransport pipe(core,100,101,c.frequency,c.start,c.end);
        need(pipe.prepare());fake::jump_after_write=c.end;need(!pipe.pump());
        need(pipe.facts().failure==2&&pipe.facts().write_bytes==fake::output.size()&&!fake::output.empty());
        need(pipe.facts().peek_calls==0);pipe.cleanup();need(fake::closes[0]==1&&fake::closes[1]==1);}
    {fake::reset();SocketCore core(c);opened(core,c);PipeTransport pipe(core,100,101,c.frequency,c.start,c.end);
        need(pipe.prepare());fake::count_bad=true;need(!pipe.pump());need(pipe.facts().raw_count_invalid);
        need(pipe.facts().write_bytes==fake::output.size()+1);pipe.cleanup();}
    {fake::reset();SocketCore core(c);opened(core,c);PipeTransport pipe(core,100,101,c.frequency,c.start,c.end);
        need(pipe.prepare());fake::broken=true;need(!pipe.pump());need(pipe.facts().eof_observed);
        need(pipe.facts().read_calls==1&&pipe.facts().read_bytes==0);need(core.failure()!=nullptr);pipe.cleanup();}
    std::cout<<"pipe fake assertions: "<<assertions<<"\n";return 0;
}catch(const std::exception& e){std::cerr<<e.what()<<" at "<<assertions<<"\n";return 1;}}
