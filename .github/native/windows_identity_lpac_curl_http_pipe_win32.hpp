#pragma once
// A5 physical anonymous-pipe transport. Definitions only; no static I/O.
// This is not a socket provider and never calls Winsock or a resolver.
#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#ifndef NOMINMAX
#define NOMINMAX
#endif
#include <windows.h>
#include <array>
#include <cstdint>
#include <algorithm>
#include <limits>
#include "windows_identity_lpac_curl_http_adapter.hpp"

namespace lpac_curl_http {
struct PipeFacts {
    std::uint64_t read_bytes=0,write_bytes=0,read_calls=0,write_calls=0,peek_calls=0;
    std::uint64_t prepared_qpc=0,last_qpc=0;
    std::uint32_t failure=0,winerror=0;
    bool prepared=false,eof_observed=false,reader_inherit_cleared=false,writer_inherit_cleared=false;
    bool reader_close_attempted=false,reader_closed=false,writer_close_attempted=false,writer_closed=false;
    bool close_unknown=false,clock_unknown=false,raw_count_invalid=false;
};

class PipeTransport {
    SocketCore& core_;HANDLE read_=nullptr,write_=nullptr;
    std::uint64_t frequency_=0,start_=0,end_=0,last_=0;
    PipeFacts facts_{};
    void fail(std::uint32_t reason,DWORD error=0){
        if(!facts_.failure){facts_.failure=reason;facts_.winerror=error;}
    }
    bool sample(bool work=true){
        LARGE_INTEGER raw{};
        if(!QueryPerformanceCounter(&raw)||raw.QuadPart<=0){facts_.clock_unknown=true;fail(1);return false;}
        const auto now=static_cast<std::uint64_t>(raw.QuadPart);
        if(now<start_||now<last_){facts_.clock_unknown=true;fail(1);return false;}
        facts_.last_qpc=last_=now;
        if(work&&now>=end_){fail(2);return false;}
        return true;
    }
    bool close(HANDLE& slot,bool writer){
        auto& attempted=writer?facts_.writer_close_attempted:facts_.reader_close_attempted;
        auto& closed=writer?facts_.writer_closed:facts_.reader_closed;
        if(attempted)return closed;
        if(!slot){fail(3);return false;}
        // Ownership is consumed before the API; an uncertain close is not retried.
        const HANDLE owned=slot;slot=nullptr;attempted=true;
        const BOOL okay=CloseHandle(owned);const DWORD error=okay?0:GetLastError();
        closed=okay!=FALSE;if(!closed){facts_.close_unknown=true;fail(3,error);}
        sample(false);return closed;
    }
    bool admit(HANDLE value,bool writer){
        if(!sample())return false;
        const DWORD kind=GetFileType(value);const DWORD error=kind==FILE_TYPE_UNKNOWN?GetLastError():0;
        const bool timely=sample();if(kind!=FILE_TYPE_PIPE){fail(4,error);return false;}if(!timely)return false;
        DWORD before=0;const BOOL queried=GetHandleInformation(value,&before);const DWORD qe=queried?0:GetLastError();
        const bool qt=sample();if(!queried||before!=HANDLE_FLAG_INHERIT){fail(5,qe);return false;}if(!qt)return false;
        const BOOL changed=SetHandleInformation(value,HANDLE_FLAG_INHERIT,0);const DWORD ce=changed?0:GetLastError();
        const bool ct=sample();if(!changed){fail(5,ce);return false;}if(!ct)return false;
        DWORD after=0;const BOOL observed=GetHandleInformation(value,&after);const DWORD ae=observed?0:GetLastError();
        if(writer)facts_.writer_inherit_cleared=observed&&after==0;
        else facts_.reader_inherit_cleared=observed&&after==0;
        const bool at=sample();if(!observed||after!=0){fail(5,ae);return false;}return at;
    }
public:
    // Caller has already validated the new A5 Config, all six distinct HANDLE
    // numbers, owner-bound inherited rights and process/Job identity.
    PipeTransport(SocketCore& core,std::uint64_t reader,std::uint64_t writer,
        std::uint64_t frequency,std::uint64_t start,std::uint64_t end)
      :core_(core),frequency_(frequency),start_(start),end_(end),last_(start){
        constexpr auto maximum=static_cast<std::uint64_t>((std::numeric_limits<std::int64_t>::max)());
        // Reject an invalid ownership tuple before adopting either number.
        // In particular, cleanup must not close a duplicated/arbitrary value.
        if(!reader||!writer||reader==writer||reader>maximum||writer>maximum){fail(6);return;}
        read_=reinterpret_cast<HANDLE>(static_cast<std::uintptr_t>(reader));
        write_=reinterpret_cast<HANDLE>(static_cast<std::uintptr_t>(writer));
        if(!frequency||frequency>maximum/8||!start||end>maximum||end<=start
            ||end-start>8*frequency||end!=core.original_deadline())fail(6);
    }
    PipeTransport(const PipeTransport&)=delete;PipeTransport& operator=(const PipeTransport&)=delete;
    ~PipeTransport()=default; // Explicit lifecycle, never an implicit second close.
    const PipeFacts& facts()const{return facts_;}
    bool okay()const{return !facts_.failure&&!core_.failure();}
    bool prepare(){
        if(facts_.failure||facts_.prepared||facts_.reader_close_attempted||facts_.writer_close_attempted){fail(6);return false;}
        LARGE_INTEGER f{};const BOOL q=QueryPerformanceFrequency(&f);const DWORD e=q?0:GetLastError();
        if(!q||f.QuadPart<=0||static_cast<std::uint64_t>(f.QuadPart)!=frequency_){fail(1,e);return false;}
        if(!sample()||!admit(read_,false)||!admit(write_,true))return false;
        facts_.prepared=true;facts_.prepared_qpc=last_;return true;
    }
    // One bounded write and one bounded read per call. The ABI wait loop owns
    // its original deadline; idle never creates a new window or a new thread.
    bool pump(){
        if(!facts_.prepared||!okay()||!sample())return false;
        bool progress=false;
        const auto* output=core_.pipe_output(last_);
        if(output&&core_.pipe_output_size()){
            const auto wanted=static_cast<DWORD>((std::min)(core_.pipe_output_size(),std::size_t(1088)));
            DWORD count=0;++facts_.write_calls;
            const BOOL success=WriteFile(write_,output,wanted,&count,nullptr);const DWORD error=success?0:GetLastError();
            facts_.write_bytes+=count;const bool timely=sample();
            if(count>wanted){facts_.raw_count_invalid=true;fail(7);return false;}
            if(!success||!count){fail(7,error);return false;}if(!timely)return false;
            if(!core_.pipe_written(count,last_)){fail(8);return false;}progress=true;
        }
        if(!facts_.eof_observed&&sample()){
            DWORD available=0;++facts_.peek_calls;
            const BOOL peek=PeekNamedPipe(read_,nullptr,0,nullptr,&available,nullptr);const DWORD error=peek?0:GetLastError();
            const bool timely=sample();
            if(!peek&&error!=ERROR_BROKEN_PIPE){fail(9,error);return false;}if(!timely)return false;
            if(!peek||available){
                std::array<std::uint8_t,lpac_stream::Payload> bytes{};
                const DWORD wanted=peek?(std::min)(available,static_cast<DWORD>(bytes.size())):1;
                DWORD count=0;++facts_.read_calls;
                const BOOL success=ReadFile(read_,bytes.data(),wanted,&count,nullptr);const DWORD re=success?0:GetLastError();
                facts_.read_bytes+=count;const bool rt=sample();
                if(count>wanted){facts_.raw_count_invalid=true;fail(10);return false;}
                if((success&&!count)||(!success&&re==ERROR_BROKEN_PIPE&&!count)){
                    facts_.eof_observed=true;
                    if(!rt)return false;
                    if(!core_.pipe_peer_eof(last_)){fail(8);return false;}progress=true;
                }else{
                    if(!success||!count){fail(10,re);return false;}if(!rt)return false;
                    if(!core_.pipe_feed(bytes.data(),count,last_)){fail(8);return false;}progress=true;
                }
            }
        }
        if(!facts_.writer_close_attempted&&sample()&&core_.pipe_writer_can_close(last_)){
            if(!close(write_,true))return false;
            if(!sample()||!core_.pipe_writer_closed(last_)){fail(8);return false;}progress=true;
        }
        if(core_.failure())fail(8);
        return progress;
    }
    // Called once by explicit closesocket/WSACleanup/failure unwind outside
    // DllMain. Physical cleanup may run after work expiry; it grants no I/O.
    void cleanup(){
        if(!facts_.writer_close_attempted&&write_)close(write_,true);
        if(!facts_.reader_close_attempted&&read_)close(read_,false);
    }
};
} // namespace lpac_curl_http
