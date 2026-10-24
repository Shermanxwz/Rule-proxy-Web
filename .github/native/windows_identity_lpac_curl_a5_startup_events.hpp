#pragma once
// Pure one-live Kernel32 event ownership and finite RPS1 notifications.
// Handles below are actual SDK return values supplied by the Win32 wrapper;
// this model never invents a HANDLE, calls an API or signals a host socket.
#include <cstdint>

namespace a5startup { namespace events {
constexpr std::uint32_t Read=1,Write=2,Oob=4,Accept=8,Connect=16,Close=32;
constexpr std::uint32_t SupportedMask=Read|Write|Oob|Accept|Connect|Close;
inline bool ipv6_capability_probe(int family,int type,int protocol){return family==23&&type==2&&protocol==0;}
struct BacklogInput48 {
    std::uint64_t input=0;std::uint32_t input_bytes=0,output_bytes=0;
    std::uint64_t output=0,returned_bytes=0,overlapped=0,completion=0;
};
static_assert(sizeof(BacklogInput48)==48,"owned synchronous optimization query input");
inline bool backlog_probe(std::uint64_t socket,std::uint64_t expected,std::uint32_t code,const BacklogInput48& value){
    return socket==expected&&code==0x4004747bU&&!value.input&&!value.input_bytes
        &&value.output&&value.output_bytes==4&&value.returned_bytes&&!value.overlapped&&!value.completion;
}
struct NetworkEvents44 {std::int32_t bits=0;std::int32_t errors[10]{};};
static_assert(sizeof(NetworkEvents44)==44,"Windows WSANETWORKEVENTS LONG32/int32");
struct WaitInput24 {std::uint64_t event=0;std::uint32_t milliseconds=0,wait_all=0,alertable=0,reserved=0;};
static_assert(sizeof(WaitInput24)==24,"owned event wait input");

class OneLive {
    std::uint64_t handle_=0,consumed_=0;
    std::uint32_t generation_=0,created_=0,closed_=0,mask_=0,latched_=0;
    bool allocation_pending_=false,close_pending_=false,unknown_=false;
    bool signaled_=false,read_armed_=true,write_armed_=true,connect_armed_=true,close_armed_=true;
public:
    bool begin_create(){
        if(handle_||allocation_pending_||close_pending_||unknown_||generation_>=16)return false;
        allocation_pending_=true;++generation_;return true;
    }
    // A known nonnull SDK result is owned even when its postclock is late.
    bool created(bool returned,std::uint64_t raw){
        if(!allocation_pending_)return false;
        allocation_pending_=false;
        if(!returned){unknown_=true;return false;}
        if(!raw)return false; // known failed allocation, no handle to close
        if(raw>0x7fffffffffffffffULL){unknown_=true;return false;}
        handle_=raw;consumed_=0;++created_;mask_=latched_=0;signaled_=false;
        read_armed_=write_armed_=connect_armed_=close_armed_=true;return true;
    }
    bool owns(std::uint64_t value)const{return value&&value==handle_&&!close_pending_;}
    bool begin_close(std::uint64_t value){
        if(!owns(value))return false;
        consumed_=handle_;handle_=0;close_pending_=true;mask_=latched_=0;return true;
    }
    bool closed(bool returned,bool success){
        if(!close_pending_)return false;
        close_pending_=false;
        if(!returned||!success){unknown_=true;return false;}
        ++closed_;signaled_=false;return true;
    }
    bool select(std::uint64_t event,std::uint32_t mask){
        if(mask&~SupportedMask)return false;
        if(mask&&!owns(event))return false;
        mask_=mask;latched_=0;
        // The event argument is ignored when canceling. Re-subscribing must
        // not replay this stream's one connect/close transition.
        read_armed_=write_armed_=true;return true;
    }
    void observe(bool connected,bool readable,bool writable,bool eof){
        if(!handle_||!mask_)return;
        if(connected&&connect_armed_&&(mask_&Connect)){latched_|=Connect;connect_armed_=false;}
        if(writable&&write_armed_&&(mask_&Write)){latched_|=Write;write_armed_=false;}
        if(readable&&read_armed_&&(mask_&Read)){latched_|=Read;read_armed_=false;}
        if(eof&&close_armed_&&(mask_&Close)){latched_|=Close;close_armed_=false;}
        // Accept/OOB are valid subscriptions but cannot occur on this one
        // client-only ordinary-byte stream. They are never manufactured.
    }
    void after_send(){write_armed_=true;}
    void after_recv(){read_armed_=true;}
    NetworkEvents44 peek()const{NetworkEvents44 out;out.bits=static_cast<std::int32_t>(latched_);return out;}
    NetworkEvents44 enumerate(){const auto out=peek();latched_=0;return out;}
    bool needs_signal()const{return handle_&&latched_&&!signaled_;}
    void signal_result(bool returned,bool success){if(returned&&success)signaled_=true;else unknown_=true;}
    void reset_result(bool returned,bool success){if(returned&&success)signaled_=false;else unknown_=true;}
    bool signaled()const{return signaled_;}
    bool unknown()const{return unknown_;}
    bool live()const{return handle_!=0;}
    bool closed_all()const{return !handle_&&!allocation_pending_&&!close_pending_&&!unknown_&&created_==closed_;}
    std::uint64_t handle()const{return handle_;}
    std::uint64_t consumed()const{return consumed_;}
    std::uint32_t generation()const{return generation_;}
    std::uint32_t created_count()const{return created_;}
    std::uint32_t closed_count()const{return closed_;}
    std::uint32_t latched()const{return latched_;}
};
} }
