#pragma once
// SOURCE ONLY. Include at the end of the new A5 shim TU, after Runtime runtime
// and trivial thread_error TLS exist. Remove only the 15 replaced stub bodies.
// No DllMain work, real Winsock/provider/DNS call, worker/thread or fallback.
#include "windows_identity_lpac_curl_http_surface.hpp"
#include "windows_identity_lpac_curl_http_pipe_win32.hpp"
#include "windows_identity_lpac_curl_a5_startup_events.hpp"
#include <new>
#include <atomic>
#include <type_traits>

namespace a5_http_glue {
namespace sem=lpac_curl_http_surface;
using NativeCall=a5startup::win::Call;
constexpr bool ActualReady=false;
struct LifecycleFacts {
    bool configure_attempted=false,configured=false,pipe_constructed=false;
    bool cleanup_called=false,failed=false,concurrent=false,clock_unknown=false;
    bool fallback_read_attempted=false,fallback_read_closed=false;
    bool fallback_write_attempted=false,fallback_write_closed=false,close_unknown=false;
    std::uint64_t last_qpc=0;std::uint32_t failure=0,last_winerror=0;
    lpac_curl_http::PipeFacts pipe{};
};
// Private process-local storage deliberately pads its placement-new buffers.
// It is never serialized; the trace uses explicit 128-byte LE fields instead.
#pragma warning(push)
#pragma warning(disable:4324)
struct State {
    std::atomic_flag lock=ATOMIC_FLAG_INIT;
    std::atomic<bool> concurrent_seen{false};
    alignas(sem::Surface) unsigned char surface_storage[sizeof(sem::Surface)]{};
    alignas(lpac_curl_http::PipeTransport) unsigned char pipe_storage[sizeof(lpac_curl_http::PipeTransport)]{};
    sem::Surface* surface=nullptr;lpac_curl_http::PipeTransport* pipe=nullptr;
    std::uint64_t reader=0,writer=0,start=0,end=0,last=0;
    LifecycleFacts facts{};bool summary_attempted=false;
    a5startup::events::OneLive events;
    void fail(std::uint32_t reason,DWORD error=0){facts.failed=true;if(!facts.failure){facts.failure=reason;facts.last_winerror=error;}}
    bool sample(std::uint64_t& now){
        LARGE_INTEGER raw{};const BOOL returned=QueryPerformanceCounter(&raw);const DWORD error=returned?0:GetLastError();
        if(!returned||raw.QuadPart<=0){facts.clock_unknown=true;fail(1,error);return false;}
        now=static_cast<std::uint64_t>(raw.QuadPart);facts.last_qpc=now;
        if(now<start||now<last){facts.clock_unknown=true;fail(1);return false;}
        last=now;if(now>=end){fail(2);return false;}return true;
    }
    bool pump(NativeCall& row,bool sleep_if_idle=true){
        if(!pipe||!surface||facts.failed||!runtime.allowed(row)){fail(3);return false;}
        std::uint64_t now=0;if(!sample(now))return false;
        const bool progress=pipe->pump();facts.pipe=pipe->facts();
        if(!pipe->okay()){fail(4,facts.pipe.winerror);return false;}
        if(!progress&&sleep_if_idle){
            // This is bounded idle scheduling, not another deadline/window.
            if(!runtime.allowed(row)||!sample(now))return false;
            Sleep(1);
        }
        return sample(now);
    }
    template<class Continue>sem::Call await(sem::Call result,NativeCall& row,Continue continuation){
        while(result.completion==sem::Completion::pending){
            if(!pump(row))return error(sem::TimedOut);
            std::uint64_t now=0;if(!sample(now))return error(sem::TimedOut);
            result=continuation(now);
        }
        return result;
    }
    static sem::Call error(int e){sem::Call c;c.error=e;return c;}
    static sem::Call okay(std::int64_t v=0){sem::Call c;c.completion=sem::Completion::returned;c.value=v;c.error=0;c.error_valid=false;return c;}
    sem::Call pointer_fault(NativeCall& row){row.row.raw.flags|=a5startup::input_fault;runtime.fault(row);fail(5);return error(a5startup::bad_pointer);}
    bool now(NativeCall& row,std::uint64_t& tick){
        if(facts.failed||!runtime.allowed(row)||!sample(tick)){runtime.fault(row,a5startup::clock_failure);return false;}return true;
    }
    void fallback_close(std::uint64_t& slot,bool writer_side){
        auto& attempted=writer_side?facts.fallback_write_attempted:facts.fallback_read_attempted;
        auto& closed=writer_side?facts.fallback_write_closed:facts.fallback_read_closed;
        if(attempted||!slot)return;
        const auto value=slot;slot=0;attempted=true;
        const BOOL returned=CloseHandle(reinterpret_cast<HANDLE>(static_cast<std::uintptr_t>(value)));
        const DWORD error=returned?0:GetLastError();closed=returned!=FALSE;
        if(!closed){facts.close_unknown=true;fail(6,error);}
    }
    bool cleanup_pipes(){
        if(!facts.cleanup_called){
            facts.cleanup_called=true;
            if(pipe){pipe->cleanup();facts.pipe=pipe->facts();reader=writer=0;}
            else{fallback_close(writer,true);fallback_close(reader,false);}
        }
        if(!facts.configure_attempted)return true;
        if(pipe)return facts.pipe.reader_closed&&facts.pipe.writer_closed&&!facts.pipe.close_unknown;
        return facts.fallback_read_closed&&facts.fallback_write_closed&&!facts.close_unknown;
    }
    bool cleanup(){
        const bool pipes_closed=cleanup_pipes();
        if(events.live()){
            const auto h=events.handle();events.begin_close(h);
            NativeCall close{};const bool timely=runtime.event_auxiliary(334,h,close);
            const bool returned=(close.row.sdk.flags&a5startup::sdk_returned)!=0
                &&(close.row.sdk.flags&a5startup::sdk_exception)==0;
            const bool closed=events.closed(returned,close.row.sdk.raw_return!=0);
            if(!closed){facts.close_unknown=true;fail(20,static_cast<DWORD>(close.row.sdk.error));}
            if(!timely)fail(21);
        }
        return pipes_closed&&events.closed_all();
    }
};
#pragma warning(pop)
// Only byte storage and scalar/atomic initialization at module initialization.
// Surface/transport constructors and all IO happen in configure, never DllMain.
State state;
struct Lock {
    bool held=false;
    Lock(){held=!state.lock.test_and_set();if(!held)state.concurrent_seen.store(true);}
    ~Lock(){if(held)state.lock.clear();}
    Lock(const Lock&)=delete;Lock& operator=(const Lock&)=delete;
};

// Explicit external new-scope wiring. Call once after successful WSAStartup,
// outside DllMain, with owner-bound six distinct inherited handles already
// admitted. The raw A5 Config and independently frozen headers must be checked
// by that caller. This function cannot authorize identity, handles or Resume.
inline bool configure(const lpac_curl_http::Config& c,std::uint64_t read_handle,std::uint64_t write_handle,lpac_curl_http::Endpoint virtual_local){
    Lock lock;if(!lock.held)return false;
    if(state.facts.configure_attempted||state.facts.cleanup_called||state.summary_attempted)return false;
    state.facts.configure_attempted=true;
    const auto& native=runtime.config();
    const auto maximum=static_cast<std::uint64_t>((std::numeric_limits<std::int64_t>::max)());
    if(!runtime.startup().references()||!read_handle||!write_handle||read_handle==write_handle||read_handle>maximum||write_handle>maximum
        ||read_handle!=native.pipe_read||write_handle!=native.pipe_write||read_handle==native.trace_handle||write_handle==native.trace_handle
        ||c.frequency!=native.frequency||c.start!=native.window_start||c.end!=native.window_end
        ||c.stream.send!=native.request_total||c.stream.receive!=native.response_total
        ||c.target.port!=native.origin_port||virtual_local.port!=native.virtual_local_port
        ||c.request_header.size()!=native.request_header_bytes||c.response_header.size()!=native.response_header_bytes
        ||c.request_body!=native.request_body||c.response_body!=native.response_body
        ||std::memcmp(c.stream.run.data(),native.run,16)||std::memcmp(c.stream.case_id.data(),native.case_id,16)){
        state.fail(7);return false;
    }
    // Both known inherited resources are adopted before any allocation that
    // can throw. Failed construction leaves explicit once-close obligations.
    state.reader=read_handle;state.writer=write_handle;state.start=c.start;state.end=c.end;state.last=c.start;
    try{
        state.surface=new(state.surface_storage) sem::Surface(c,virtual_local);
        state.pipe=new(state.pipe_storage) lpac_curl_http::PipeTransport(state.surface->core(),read_handle,write_handle,c.frequency,c.start,c.end);
        state.facts.pipe_constructed=true;
        if(state.surface->qualification_failed()||!state.pipe->prepare()){state.facts.pipe=state.pipe->facts();state.fail(8);return false;}
        state.facts.pipe=state.pipe->facts();state.facts.configured=true;return true;
    }catch(...){state.fail(9);return false;}
}

// Root's A5 WSACleanup path must call this even after runtime.allowed is false
// (known cleanup is not renewed IO admission). No DllMain/destructor cleanup.
inline void store32(std::uint8_t* p,std::uint32_t v){for(unsigned i=0;i<4;++i)p[i]=static_cast<std::uint8_t>(v>>(8*i));}
inline void store64(std::uint8_t* p,std::uint64_t v){for(unsigned i=0;i<8;++i)p[i]=static_cast<std::uint8_t>(v>>(8*i));}
// Called while the serial lock is held, only after explicit cleanup. Exactly
// one owned snapshot, no invented primary SDK call or second network action.
inline void emit_summary(){
    if(state.summary_attempted||!state.facts.cleanup_called)return;
    state.summary_attempted=true;if(state.pipe)state.facts.pipe=state.pipe->facts();
    auto row=runtime.open(400);std::array<std::uint8_t,128> raw{};
    raw[0]='A';raw[1]='5';raw[2]='P';raw[3]='F';raw[4]=1;raw[6]=128;
    const auto& f=state.facts.pipe;
    const std::uint64_t counts[7]={f.read_bytes,f.write_bytes,f.read_calls,f.write_calls,f.peek_calls,f.prepared_qpc,f.last_qpc};
    for(unsigned i=0;i<7;++i)store64(raw.data()+8+8*i,counts[i]);
    store32(raw.data()+64,f.failure?f.failure:state.facts.failure);store32(raw.data()+68,f.failure?f.winerror:state.facts.last_winerror);
    const std::uint32_t flags=(f.prepared?1U:0U)|(f.eof_observed?2U:0U)|(f.reader_inherit_cleared?4U:0U)|(f.writer_inherit_cleared?8U:0U)
        |(f.reader_close_attempted?16U:0U)|(f.reader_closed?32U:0U)|(f.writer_close_attempted?64U:0U)|(f.writer_closed?128U:0U)
        |((f.close_unknown||state.facts.close_unknown)?256U:0U)|((f.clock_unknown||state.facts.clock_unknown)?512U:0U)|(f.raw_count_invalid?1024U:0U);
    store32(raw.data()+72,flags);
    const bool core_bad=!state.surface||state.surface->qualification_failed()||state.facts.failed||state.concurrent_seen.load()||!state.events.closed_all();
    store32(raw.data()+76,core_bad?1U:0U);
    if(state.surface){store32(raw.data()+80,state.surface->core().request_accepted());store32(raw.data()+84,state.surface->core().response_delivered());
        store32(raw.data()+88,state.surface->core().transport_complete()?1U:0U);store32(raw.data()+92,state.surface->core().close_ready()?1U:0U);}
    row.row.input_kind=10;row.row.captured_bytes=128;std::memcpy(row.row.name_or_WSADATA,raw.data(),raw.size());row.row.raw.flags|=a5startup::internal|a5startup::capture_complete;
    runtime.sync(row);
    const bool clean=state.facts.configured&&!core_bad&&f.reader_closed&&f.writer_closed&&!f.close_unknown;
    if(!clean)runtime.fault(row,a5startup::reference_uncertain);
    // Delivery1 means this owned snapshot was supplied to the trace, not that
    // any field or cleanup is successful. The decoder judges those fields.
    runtime.finish(row,1,0,false);
}
inline bool transport_cleanup(){Lock lock;if(!lock.held)return false;const bool okay=state.cleanup();emit_summary();return okay;}
inline bool copy_facts(LifecycleFacts& out){Lock lock;if(!lock.held)return false;if(state.pipe)state.facts.pipe=state.pipe->facts();state.facts.concurrent=state.concurrent_seen.load();out=state.facts;return true;}

template<class F>std::int64_t invoke(a5startup::u32 op,a5startup::u64 a,a5startup::u64 b,a5startup::u64 c,F body,bool needs_transport=true,bool needs_startup=true,std::int64_t failure_value=-1){
    auto row=runtime.open(op,a,b,c);auto result=State::error(a5startup::operation_unsupported);
    {
        Lock lock;
        if(!lock.held){runtime.fault(row,a5startup::reference_uncertain);runtime.reject(row);}
        else if(!runtime.allowed(row)){runtime.fault(row,a5startup::clock_failure);result=State::error(sem::TimedOut);}
        else if(needs_startup&&!runtime.startup().references())result=State::error(a5startup::not_initialized);
        else if(needs_transport&&(!state.facts.configured||state.facts.failed||!state.surface)){runtime.fault(row);result=State::error(a5startup::operation_unsupported);}
        else{
            try{result=body(row);}catch(...){state.fail(10);runtime.fault(row);result=State::error(10055);}
            if(state.surface&&state.surface->qualification_failed())runtime.reject(row);
        }
        if(result.completion==sem::Completion::pending){state.fail(11);runtime.fault(row);result=State::error(sem::TimedOut);}
        if(result.completion==sem::Completion::failed)result.value=failure_value;
        if(result.error_valid)thread_error=result.error;
        runtime.finish(row,result.value,result.error,result.error_valid);
    }
    return result.value;
}
inline bool input(void* destination,const void* source,std::size_t bytes){return source&&a5startup::win::guarded_copy(destination,source,bytes);}
inline bool output(void* destination,const void* source,std::size_t bytes){return destination&&a5startup::win::guarded_copy(destination,source,bytes);}
inline sem::Call unsupported(NativeCall& row,std::uint64_t now){runtime.reject(row);return state.surface->unsupported_api(row.row.raw.export_ordinal,now);}
inline bool sdk_returned(const NativeCall& row){return (row.row.sdk.flags&a5startup::sdk_returned)!=0&&(row.row.sdk.flags&a5startup::sdk_exception)==0;}
inline int event_error(const NativeCall& row,int fallback=10022){
    return sdk_returned(row)&&row.row.sdk.error>0?row.row.sdk.error:fallback;
}
inline bool event_reset(NativeCall& row,std::uint64_t event){
    const bool timely=runtime.primary(row,{332,event,0,0,nullptr,0});
    const bool returned=sdk_returned(row),success=returned&&row.row.sdk.raw_return!=0;
    state.events.reset_result(returned,success);
    if(!success||!timely){runtime.fault(row,a5startup::reference_uncertain);state.fail(22,static_cast<DWORD>(row.row.sdk.error));return false;}
    return true;
}
inline bool event_aux_reset(){
    if(!state.events.signaled())return true;
    NativeCall raw{};const bool timely=runtime.event_auxiliary(332,state.events.handle(),raw);
    const bool returned=sdk_returned(raw),success=returned&&raw.row.sdk.raw_return!=0;
    state.events.reset_result(returned,success);
    if(!success||!timely){state.fail(23,static_cast<DWORD>(raw.row.sdk.error));return false;}return true;
}
inline bool event_refresh(NativeCall& row,std::uint64_t now){
    if(!state.events.live())return true;
    const auto ready=state.surface->core().readiness(now);
    if(ready.exceptional||state.surface->core().failure()){state.fail(24);runtime.fault(row);return false;}
    state.events.observe(ready.connected,ready.readable,ready.writable,state.surface->core().response_eof());
    if(state.events.needs_signal()){
        NativeCall raw{};const bool timely=runtime.event_auxiliary(331,state.events.handle(),raw);
        const bool returned=sdk_returned(raw),success=returned&&raw.row.sdk.raw_return!=0;
        state.events.signal_result(returned,success);
        if(!success||!timely){state.fail(25,static_cast<DWORD>(raw.row.sdk.error));runtime.fault(row,a5startup::reference_uncertain);return false;}
    }
    return true;
}
inline sem::Call name(NativeCall& row,SOCKET socket,sockaddr* target,int* length,bool peer){
    int capacity=0;if(!input(&capacity,length,4))return state.pointer_fault(row);
    std::uint64_t now=0;if(!state.now(row,now))return State::error(sem::TimedOut);
    auto result=state.surface->name(static_cast<std::uint64_t>(socket),peer,capacity,now);
    if(result.completion==sem::Completion::returned){const int used=16;
        if(result.bytes.size()!=16||!output(target,result.bytes.data(),16)||!output(length,&used,4))return state.pointer_fault(row);}
    return result;
}
} // namespace a5_http_glue

extern "C" WSAEVENT WSAAPI a5_WSACreateEvent(void){
    const auto result=a5_http_glue::invoke(50,0,0,0,[&](auto& row){
        auto& state=a5_http_glue::state;
        if(!state.events.begin_create()){runtime.reject(row);return a5_http_glue::State::error(10022);}
        const bool timely=runtime.primary(row,{330,0,0,0,nullptr,0});
        const bool returned=a5_http_glue::sdk_returned(row);
        const auto raw=static_cast<std::uint64_t>(row.row.sdk.raw_return);
        const bool adopted=state.events.created(returned,raw);
        if(!returned||state.events.unknown()){state.fail(26);runtime.fault(row,a5startup::reference_uncertain);}
        if(!timely){state.fail(27);runtime.fault(row);}
        if(!adopted||!timely)return a5_http_glue::State::error(a5_http_glue::event_error(row,10055));
        return a5_http_glue::State::okay(static_cast<std::int64_t>(raw));
    },true,true,0);
    return reinterpret_cast<WSAEVENT>(static_cast<std::uintptr_t>(result));
}
extern "C" BOOL WSAAPI a5_WSACloseEvent(WSAEVENT event){
    auto row=runtime.open(45,arg(event));a5_http_glue::Lock lock;BOOL delivered=FALSE;int error=10022;
    if(!lock.held){runtime.fault(row,a5startup::reference_uncertain);runtime.reject(row);}
    else if(!a5_http_glue::state.events.begin_close(arg(event))){runtime.reject(row);}
    else{
        // Known ownership is consumed before the actual once-close. A late
        // returned TRUE stays physical TRUE while the trace remains partial.
        const bool timely=runtime.primary(row,{334,arg(event),0,0,nullptr,0});
        const bool returned=a5_http_glue::sdk_returned(row);
        const bool success=a5_http_glue::state.events.closed(returned,row.row.sdk.raw_return!=0);
        delivered=success?TRUE:FALSE;error=a5_http_glue::event_error(row);
        if(!success){a5_http_glue::state.facts.close_unknown=true;a5_http_glue::state.fail(28);runtime.fault(row,a5startup::reference_uncertain);}
        if(!timely){a5_http_glue::state.fail(29);runtime.fault(row);}
    }
    if(!delivered)thread_error=error;runtime.finish(row,delivered,delivered?0:error,delivered==FALSE);return delivered;
}
extern "C" BOOL WSAAPI a5_WSAResetEvent(WSAEVENT event){
    return static_cast<BOOL>(a5_http_glue::invoke(95,arg(event),0,0,[&](auto& row){
        if(!a5_http_glue::state.events.owns(arg(event))){runtime.reject(row);return a5_http_glue::State::error(10022);}
        if(!a5_http_glue::event_reset(row,arg(event)))return a5_http_glue::State::error(a5_http_glue::event_error(row));
        return a5_http_glue::State::okay(1);
    },true,true,0));
}
extern "C" int WSAAPI a5_WSAEventSelect(SOCKET socket,WSAEVENT event,long mask){
    return static_cast<int>(a5_http_glue::invoke(67,arg(socket),arg(event),arg(mask),[&](auto& row){
        auto& state=a5_http_glue::state;std::uint64_t now=0;
        if(!state.now(row,now))return a5_http_glue::State::error(lpac_curl_http_surface::TimedOut);
        if(socket!=lpac_curl_http::VirtualSocket||mask<0
            ||!state.events.select(arg(event),static_cast<std::uint32_t>(mask))){runtime.reject(row);return a5_http_glue::State::error(10022);}
        // EventSelect always makes the socket nonblocking. Canceling interest
        // with mask0 does not restore blocking mode.
        auto nonblocking=state.surface->ioctl(socket,lpac_curl_http_surface::Fionbio,1,now);
        if(nonblocking.completion!=lpac_curl_http_surface::Completion::returned)return nonblocking;
        if(!a5_http_glue::event_aux_reset())return a5_http_glue::State::error(10022);
        if(mask&&!a5_http_glue::event_refresh(row,now))return a5_http_glue::State::error(10054);
        return a5_http_glue::State::okay();
    }));
}
extern "C" int WSAAPI a5_WSAEnumNetworkEvents(SOCKET socket,WSAEVENT event,LPWSANETWORKEVENTS target){
    return static_cast<int>(a5_http_glue::invoke(64,arg(socket),arg(event),arg(target),[&](auto& row){
        auto& state=a5_http_glue::state;std::uint64_t now=0;
        if(socket!=lpac_curl_http::VirtualSocket||!state.events.live()||(event&&!state.events.owns(arg(event)))){
            runtime.reject(row);return a5_http_glue::State::error(10022);}
        if(!state.now(row,now))return a5_http_glue::State::error(lpac_curl_http_surface::TimedOut);
        if(!a5_http_glue::event_refresh(row,now))return a5_http_glue::State::error(10054);
        const auto owned=state.events.peek();
        if(!a5_http_glue::output(target,&owned,sizeof(owned)))return state.pointer_fault(row);
        (void)state.events.enumerate();
        row.row.input_kind=11;row.row.captured_bytes=44;std::memcpy(row.row.name_or_WSADATA,&owned,44);row.row.raw.flags|=a5startup::capture_complete;
        runtime.sync(row);
        // curl passes NULL here: clear only the network record. Its explicit
        // subsequent WSAResetEvent owns the separate kernel reset operation.
        if(event&&!a5_http_glue::event_reset(row,arg(event)))return a5_http_glue::State::error(a5_http_glue::event_error(row));
        return a5_http_glue::State::okay();
    }));
}
extern "C" DWORD WSAAPI a5_WSAWaitForMultipleEvents(DWORD count,const WSAEVENT* events,BOOL all,DWORD milliseconds,BOOL alertable){
    return static_cast<DWORD>(a5_http_glue::invoke(124,arg(count),arg(events),arg(all),[&](auto& row){
        auto& state=a5_http_glue::state;WSAEVENT owned=nullptr;
        if(count!=1||all!=FALSE||alertable!=FALSE||milliseconds>8000){runtime.reject(row);return a5_http_glue::State::error(10022);}
        if(!a5_http_glue::input(&owned,events,sizeof(owned)))return state.pointer_fault(row);
        if(!state.events.owns(arg(owned))){runtime.reject(row);return a5_http_glue::State::error(10022);}
        const a5startup::events::WaitInput24 input{arg(owned),milliseconds,0,0,0};
        row.row.input_kind=12;row.row.captured_bytes=24;std::memcpy(row.row.name_or_WSADATA,&input,24);row.row.raw.flags|=a5startup::capture_complete;runtime.sync(row);
        std::uint64_t now=0;if(!state.now(row,now))return a5_http_glue::State::error(lpac_curl_http_surface::TimedOut);
        const auto frequency=runtime.config().frequency;
        const auto whole=static_cast<std::uint64_t>(milliseconds/1000),part=static_cast<std::uint64_t>(milliseconds%1000);
        const auto fraction=(frequency/1000)*part+((frequency%1000)*part+999)/1000;
        const auto duration=whole*frequency+fraction;
        const auto stop=now+(std::min)(duration,state.end-now);
        for(;;){
            // A timeout0 still makes one bounded progress attempt but cannot
            // Sleep. All positive waits retain the original Config deadline.
            if(!state.pump(row,false)||!state.now(row,now)||!a5_http_glue::event_refresh(row,now))return a5_http_glue::State::error(10054);
            if(state.events.signaled()||now>=stop)break;
            Sleep(1);
        }
        // Exactly one real kernel observation, not one SDK row per pump.
        const bool timely=runtime.primary(row,{333,arg(owned),0,0,nullptr,0});
        if(!timely||!a5_http_glue::sdk_returned(row))return a5_http_glue::State::error(a5_http_glue::event_error(row));
        const auto result=static_cast<std::uint64_t>(row.row.sdk.raw_return);
        if(result!=WAIT_OBJECT_0&&result!=WAIT_TIMEOUT)return a5_http_glue::State::error(a5_http_glue::event_error(row));
        if((result==WAIT_OBJECT_0)!=state.events.signaled()){state.fail(30);runtime.fault(row);return a5_http_glue::State::error(10022);}
        return a5_http_glue::State::okay(static_cast<std::int64_t>(result));
    },true,true,0xffffffffLL));
}
extern "C" int WSAAPI a5_WSAIoctl(SOCKET socket,DWORD code,LPVOID input,DWORD input_bytes,LPVOID output,DWORD output_bytes,
    LPDWORD returned_bytes,LPWSAOVERLAPPED overlapped,LPWSAOVERLAPPED_COMPLETION_ROUTINE completion){
    return static_cast<int>(a5_http_glue::invoke(78,arg(socket),arg(code),arg(input),[&](auto& row){
        const a5startup::events::BacklogInput48 owned{arg(input),input_bytes,output_bytes,arg(output),arg(returned_bytes),arg(overlapped),
            static_cast<std::uint64_t>(reinterpret_cast<std::uintptr_t>(completion))};
        row.row.input_kind=13;row.row.captured_bytes=48;std::memcpy(row.row.name_or_WSADATA,&owned,48);
        row.row.raw.flags|=a5startup::capture_complete;runtime.sync(row);
        std::uint64_t now=0;if(!a5_http_glue::state.now(row,now))return a5_http_glue::State::error(lpac_curl_http_surface::TimedOut);
        if(!a5startup::events::backlog_probe(socket,lpac_curl_http::VirtualSocket,code,owned))return a5_http_glue::unsupported(row,now);
        // curl ignores failure of this optional send-buffer optimization. This
        // adapter has no TCP-provider backlog value: leave both output buffers
        // untouched and return the accurate supported-operation failure.
        return a5_http_glue::state.surface->query_send_backlog(socket,now);
    }));
}

extern "C" SOCKET WSAAPI a5_socket(int af,int type,int protocol){
    const auto result=a5_http_glue::invoke(23,arg(af),arg(type),arg(protocol),[&](auto& row){
        // Official curl Curl_probeipv6 capability query. It creates nothing,
        // consumes no IPv4 socket slot and is not a claimed OS denial.
        if(a5startup::events::ipv6_capability_probe(af,type,protocol))return a5_http_glue::State::error(10047);
        std::uint64_t now=0;if(!a5_http_glue::state.now(row,now))return a5_http_glue::State::error(lpac_curl_http_surface::TimedOut);
        return a5_http_glue::state.surface->create(af,type,protocol,now);});
    return static_cast<SOCKET>(result);
}
extern "C" int WSAAPI a5_ioctlsocket(SOCKET socket,long command,u_long* value){
    return static_cast<int>(a5_http_glue::invoke(10,arg(socket),arg(command),arg(value),[&](auto& row){
        std::uint32_t owned=0;if(!a5_http_glue::input(&owned,value,4))return a5_http_glue::state.pointer_fault(row);
        std::uint64_t now=0;if(!a5_http_glue::state.now(row,now))return a5_http_glue::State::error(lpac_curl_http_surface::TimedOut);
        return a5_http_glue::state.surface->ioctl(socket,static_cast<std::uint32_t>(command),owned,now);}));
}
extern "C" int WSAAPI a5_connect(SOCKET socket,const sockaddr* target,int length){
    return static_cast<int>(a5_http_glue::invoke(4,arg(socket),arg(target),arg(length),[&](auto& row){
        std::uint64_t now=0;if(!a5_http_glue::state.now(row,now))return a5_http_glue::State::error(lpac_curl_http_surface::TimedOut);
        if(length!=16)return a5_http_glue::unsupported(row,now);
        lpac_curl_http_surface::SockaddrIn16 address{};if(!a5_http_glue::input(&address,target,16))return a5_http_glue::state.pointer_fault(row);
        auto result=a5_http_glue::state.surface->connect(socket,address,length,now);
        if(result.completion==lpac_curl_http_surface::Completion::failed&&result.error==lpac_curl_http_surface::WouldBlock){
            if(!a5_http_glue::state.pump(row,false))return a5_http_glue::State::error(10054);
        }
        return a5_http_glue::state.await(result,row,[&](auto tick){return a5_http_glue::state.surface->poll_connect(socket,tick);});}));
}
extern "C" int WSAAPI a5_getpeername(SOCKET socket,sockaddr* target,int* length){
    return static_cast<int>(a5_http_glue::invoke(5,arg(socket),arg(target),arg(length),[&](auto& row){return a5_http_glue::name(row,socket,target,length,true);}));
}
extern "C" int WSAAPI a5_getsockname(SOCKET socket,sockaddr* target,int* length){
    return static_cast<int>(a5_http_glue::invoke(6,arg(socket),arg(target),arg(length),[&](auto& row){return a5_http_glue::name(row,socket,target,length,false);}));
}
extern "C" int WSAAPI a5_setsockopt(SOCKET socket,int level,int name,const char* value,int length){
    return static_cast<int>(a5_http_glue::invoke(21,arg(socket),arg(level),arg(name),[&](auto& row){
        std::uint64_t now=0;if(!a5_http_glue::state.now(row,now))return a5_http_glue::State::error(lpac_curl_http_surface::TimedOut);
        if(length!=4)return a5_http_glue::unsupported(row,now);
        std::int32_t owned=0;if(!a5_http_glue::input(&owned,value,4))return a5_http_glue::state.pointer_fault(row);
        return a5_http_glue::state.surface->set_option(socket,level,name,owned,length,now);}));
}
extern "C" int WSAAPI a5_getsockopt(SOCKET socket,int level,int name,char* value,int* length){
    return static_cast<int>(a5_http_glue::invoke(7,arg(socket),arg(level),arg(name),[&](auto& row){
        int capacity=0;if(!a5_http_glue::input(&capacity,length,4))return a5_http_glue::state.pointer_fault(row);
        std::uint64_t now=0;if(!a5_http_glue::state.now(row,now))return a5_http_glue::State::error(lpac_curl_http_surface::TimedOut);
        auto result=a5_http_glue::state.surface->get_option(socket,level,name,capacity,now);
        if(result.completion==lpac_curl_http_surface::Completion::returned){const int used=4;
            if(result.bytes.size()!=4||!a5_http_glue::output(value,result.bytes.data(),4)||!a5_http_glue::output(length,&used,4))return a5_http_glue::state.pointer_fault(row);}
        return result;}));
}
extern "C" int WSAAPI a5_send(SOCKET socket,const char* buffer,int length,int flags){
    return static_cast<int>(a5_http_glue::invoke(19,arg(socket),arg(buffer),arg(length),[&](auto& row){
        std::uint64_t now=0;if(!a5_http_glue::state.now(row,now))return a5_http_glue::State::error(lpac_curl_http_surface::TimedOut);
        if(length<0||length>65536||flags)return a5_http_glue::unsupported(row,now);
        std::vector<std::uint8_t> owned(static_cast<std::size_t>(length));
        if(length&&!a5_http_glue::input(owned.data(),buffer,owned.size()))return a5_http_glue::state.pointer_fault(row);
        if(socket==lpac_curl_http::VirtualSocket&&a5_http_glue::state.surface->nonblocking()&&!a5_http_glue::state.facts.cleanup_called){
            if(!a5_http_glue::state.pump(row,false))return a5_http_glue::State::error(10054);
            if(!a5_http_glue::state.now(row,now))return a5_http_glue::State::error(lpac_curl_http_surface::TimedOut);
        }
        auto action=[&](auto tick){return a5_http_glue::state.surface->send(socket,owned.data(),owned.size(),flags,tick);};
        auto result=a5_http_glue::state.await(action(now),row,action);
        a5_http_glue::state.events.after_send();return result;}));
}
extern "C" int WSAAPI a5_recv(SOCKET socket,char* buffer,int length,int flags){
    return static_cast<int>(a5_http_glue::invoke(16,arg(socket),arg(buffer),arg(length),[&](auto& row){
        std::uint64_t now=0;if(!a5_http_glue::state.now(row,now))return a5_http_glue::State::error(lpac_curl_http_surface::TimedOut);
        if(length<=0||length>1024*1024||flags)return a5_http_glue::unsupported(row,now);
        if(socket==lpac_curl_http::VirtualSocket&&a5_http_glue::state.surface->nonblocking()&&!a5_http_glue::state.facts.cleanup_called){
            if(!a5_http_glue::state.pump(row,false))return a5_http_glue::State::error(10054);
            if(!a5_http_glue::state.now(row,now))return a5_http_glue::State::error(lpac_curl_http_surface::TimedOut);
        }
        auto action=[&](auto tick){return a5_http_glue::state.surface->recv(socket,static_cast<std::size_t>(length),flags,tick);};
        auto result=a5_http_glue::state.await(action(now),row,action);
        a5_http_glue::state.events.after_recv();
        // If delivery faults, consumed stream bytes remain consumed. No false
        // retry/rollback or successful byte count is manufactured.
        if(result.completion==lpac_curl_http_surface::Completion::returned&&!result.bytes.empty()
            &&!a5_http_glue::output(buffer,result.bytes.data(),result.bytes.size()))return a5_http_glue::state.pointer_fault(row);
        return result;}));
}
extern "C" int WSAAPI a5_closesocket(SOCKET socket){
    return static_cast<int>(a5_http_glue::invoke(3,arg(socket),0,0,[&](auto& row){
        std::uint64_t now=0;if(!a5_http_glue::state.now(row,now))return a5_http_glue::State::error(lpac_curl_http_surface::TimedOut);
        const auto result=a5_http_glue::state.await(a5_http_glue::state.surface->close(socket,now),row,[&](auto tick){return a5_http_glue::state.surface->poll_close(socket,tick);});
        if(result.completion==lpac_curl_http_surface::Completion::returned){
            // Pipe cleanup is immediate. The multi's real event remains owned
            // until WSACloseEvent/WSACleanup; summary is emitted at WSACleanup.
            const bool clean=a5_http_glue::state.cleanup_pipes();
            if(!clean){runtime.fault(row,a5startup::reference_uncertain);return a5_http_glue::State::error(10038);}}
        return result;}));
}
extern "C" int WSAAPI a5_select(int nfds,fd_set* reads,fd_set* writes,fd_set* excepts,const timeval* timeout){
    return static_cast<int>(a5_http_glue::invoke(18,arg(nfds),arg(reads),arg(writes),[&](auto& row){
        lpac_curl_http_surface::SelectRequest request;request.read=reads!=nullptr;request.write=writes!=nullptr;request.except=excepts!=nullptr;
        if((reads&&!a5_http_glue::input(&request.reads,reads,sizeof(request.reads)))
            ||(writes&&!a5_http_glue::input(&request.writes,writes,sizeof(request.writes)))
            ||(excepts&&!a5_http_glue::input(&request.excepts,excepts,sizeof(request.excepts)))
            ||!a5_http_glue::input(&request.timeout,timeout,sizeof(request.timeout)))return a5_http_glue::state.pointer_fault(row);
        std::uint64_t now=0;if(!a5_http_glue::state.now(row,now))return a5_http_glue::State::error(lpac_curl_http_surface::TimedOut);
        const auto valid_set=[](bool present,const auto& set){return !present||set.count==0||(set.count==1&&set.sockets[0]==lpac_curl_http::VirtualSocket);};
        const auto active=(request.read?request.reads.count:0U)+(request.write?request.writes.count:0U)+(request.except?request.excepts.count:0U);
        const bool valid=valid_set(request.read,request.reads)&&valid_set(request.write,request.writes)&&valid_set(request.except,request.excepts)
            &&active>0&&request.timeout.seconds>=0&&request.timeout.seconds<=8&&request.timeout.microseconds>=0&&request.timeout.microseconds<=999999;
        if(valid&&!a5_http_glue::state.facts.cleanup_called){
            // Every zero-timeout poll can progress one already-authorized RPS1
            // exchange. No idle Sleep, new window, target or background thread.
            // The inherited synchronous WriteFile remains guard-bounded, not a
            // general nonblocking host-socket guarantee.
            if(!a5_http_glue::state.pump(row,false))return a5_http_glue::State::error(10054);
            if(!a5_http_glue::state.now(row,now))return a5_http_glue::State::error(lpac_curl_http_surface::TimedOut);
        }
        auto selected=a5_http_glue::state.surface->select_begin(request,now);const auto ticket=selected.ticket;
        while(selected.call.completion==lpac_curl_http_surface::Completion::pending){
            if(!a5_http_glue::state.pump(row)||!a5_http_glue::state.now(row,now))return a5_http_glue::State::error(lpac_curl_http_surface::TimedOut);
            selected=a5_http_glue::state.surface->select_poll(ticket,now);
        }
        if(selected.call.completion==lpac_curl_http_surface::Completion::returned){
            if((reads&&!a5_http_glue::output(reads,&selected.reads,sizeof(selected.reads)))
                ||(writes&&!a5_http_glue::output(writes,&selected.writes,sizeof(selected.writes)))
                ||(excepts&&!a5_http_glue::output(excepts,&selected.excepts,sizeof(selected.excepts))))return a5_http_glue::state.pointer_fault(row);
        }
        return selected.call;}));
}
extern "C" int WSAAPI a5___WSAFDIsSet(SOCKET socket,fd_set* set){
    return static_cast<int>(a5_http_glue::invoke(151,arg(socket),arg(set),0,[&](auto& row){
        lpac_curl_http_surface::FdSet520 owned{};if(!a5_http_glue::input(&owned,set,sizeof(owned)))return a5_http_glue::state.pointer_fault(row);
        std::uint64_t now=0;if(!a5_http_glue::state.now(row,now))return a5_http_glue::State::error(lpac_curl_http_surface::TimedOut);
        return a5_http_glue::state.surface->fd_is_set(socket,owned,now);}));
}
extern "C" u_long WSAAPI a5_htonl(u_long value){
    return static_cast<u_long>(a5_http_glue::invoke(8,arg(value),0,0,[&](auto&){return a5_http_glue::State::okay(lpac_curl_http_surface::htonl(value));},false,false));
}
extern "C" u_short WSAAPI a5_htons(u_short value){
    return static_cast<u_short>(a5_http_glue::invoke(9,arg(value),0,0,[&](auto&){return a5_http_glue::State::okay(lpac_curl_http_surface::htons(value));},false,false));
}
extern "C" u_short WSAAPI a5_ntohs(u_short value){
    return static_cast<u_short>(a5_http_glue::invoke(15,arg(value),0,0,[&](auto&){return a5_http_glue::State::okay(lpac_curl_http_surface::ntohs(value));},false,false));
}
