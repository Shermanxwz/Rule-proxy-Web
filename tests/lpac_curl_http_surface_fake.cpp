// Production Surface -> SocketCore -> original production Node, no Win32.
#ifdef RULEPROXY_LPAC_STREAM_WINDOWS_HELPERS
#error portable fake only
#endif
#include "../.github/native/windows_identity_lpac_curl_http_surface.hpp"
#include "../.github/native/windows_identity_lpac_curl_a5_startup_events.hpp"
#include <iostream>
#include <stdexcept>
#include <vector>
namespace h=lpac_curl_http;
namespace w=lpac_curl_http_surface;
unsigned checks=0;
void check(bool good){++checks;if(!good)throw std::runtime_error("surface assertion");}
h::Config config(){
    h::Config c;c.stream.front=true;c.stream.run.fill(1);c.stream.case_id.fill(2);
    c.stream.send=8193;c.stream.receive=12289;c.target={{127,0,0,1},51001};
    c.frequency=1000000;c.start=1000;c.end=c.start+8*c.frequency;
    c.target_path="/ruleproxy-a2/"+h::id(c.stream.case_id);
    for(unsigned which=0;which<2;++which){
        const auto total=which?c.stream.receive:c.stream.send;std::uint32_t body=total;
        for(unsigned turn=0;turn<8;++turn){
            const auto text=which?"HTTP/1.1 200 OK\r\nContent-Length: "+std::to_string(body)+"\r\nConnection: close\r\nX-RuleProxy-Case: "+h::id(c.stream.case_id)+"\r\n\r\n":
                "POST "+c.target_path+" HTTP/1.1\r\nHost: 127.0.0.1:"+std::to_string(c.target.port)+"\r\nContent-Length: "+std::to_string(body)+"\r\nConnection: close\r\n\r\n";
            const auto next=total-static_cast<std::uint32_t>(text.size());
            if(next==body){if(which){c.response_header=text;c.response_body=body;}else{c.request_header=text;c.request_body=body;}break;}body=next;
        }
    }
    return c;
}
std::vector<std::uint8_t> challenge(const std::string& header,std::uint32_t total,unsigned seed){
    std::vector<std::uint8_t> v(header.begin(),header.end());
    while(v.size()<total)v.push_back(static_cast<std::uint8_t>((v.size()*73+seed)%256));
    return v;
}
lpac_stream::Config relay_config(const h::Config& c){auto x=c.stream;x.front=false;std::swap(x.send,x.receive);return x;}
struct Pair {
    h::Config c=config();w::Surface surface{c,{{127,0,0,1},51002}};
    lpac_stream::Node relay{relay_config(c)};
    std::vector<std::uint8_t> request=challenge(c.request_header,c.stream.send,17),response=challenge(c.response_header,c.stream.receive,211),request_sink,response_sink;
    std::uint64_t now=c.start;std::size_t sent=0,reply_sent=0;
    bool front_closed=false,relay_closed=false,relay_eof=false;
    Pair(){
        const auto created=surface.create(2,1,0,++now);check(created.completion==w::Completion::returned&&created.value==static_cast<std::int64_t>(h::VirtualSocket));
        check(surface.ioctl(h::VirtualSocket,w::Fionbio,1,++now).value==0);
        const auto connecting=surface.connect(h::VirtualSocket,w::address(c.target),16,++now);
        check(connecting.completion==w::Completion::failed&&connecting.error==w::WouldBlock&&!surface.qualification_failed());
    }
    void transfer(std::size_t fragment){
        auto& core=surface.core();
        if(const auto* bytes=core.pipe_output(++now)){
            const auto n=std::min(fragment,core.pipe_output_size());check(relay.feed(bytes,n));check(core.pipe_written(n,++now));
        }
        if(relay.needs_connect())relay.connected();
        if(const auto* bytes=relay.output()){
            const auto n=std::min(fragment,relay.output_size());check(core.pipe_feed(bytes,n,++now));relay.written(n);
        }
    }
    void opened(){
        w::SelectRequest request_select;request_select.read=true;request_select.except=true; // non-NULL, empty sets are valid alongside an active set
        request_select.write=true;request_select.writes.count=1;request_select.writes.sockets[0]=h::VirtualSocket;
        request_select.writes.padding=0xa5a5a5a5U;request_select.writes.sockets[63]=999; // ignored unused SDK storage
        request_select.timeout.seconds=2;
        auto selected=surface.select_begin(request_select,++now);check(selected.call.completion==w::Completion::pending);
        const auto ticket=selected.ticket;
        for(unsigned i=0;i<200&&selected.call.completion==w::Completion::pending;++i){transfer(7);selected=surface.select_poll(ticket,++now);}
        check(selected.call.completion==w::Completion::returned&&selected.call.value==1&&selected.writes.count==1);
        check(surface.poll_connect(h::VirtualSocket,++now).value==0);
        const auto error=surface.get_option(h::VirtualSocket,w::SolSocket,w::SoError,4,++now);
        std::int32_t value=-1;check(error.completion==w::Completion::returned&&error.bytes.size()==4);std::memcpy(&value,error.bytes.data(),4);check(value==0);
        const auto local=surface.name(h::VirtualSocket,false,16,++now),peer=surface.name(h::VirtualSocket,true,16,++now);
        w::SockaddrIn16 la{},pa{};check(local.bytes.size()==16&&peer.bytes.size()==16);std::memcpy(&la,local.bytes.data(),16);std::memcpy(&pa,peer.bytes.data(),16);
        check(w::equal_address(la,{{127,0,0,1},51002})&&w::equal_address(pa,c.target));
    }
    void run(std::size_t fragment,std::size_t capacity,bool already_opened=false){
        if(!already_opened)opened();bool close_started=false;unsigned would_block=0;
        for(unsigned turn=0;turn<100000&&!surface.complete();++turn){
            if(sent<request.size()){
                const auto out=surface.send(h::VirtualSocket,request.data()+sent,request.size()-sent,0,++now);
                if(out.completion==w::Completion::failed){check(out.error==w::WouldBlock&&!surface.qualification_failed());++would_block;}
                else{check(out.completion==w::Completion::returned&&out.value>0);sent+=static_cast<std::size_t>(out.value);}
            }
            transfer(fragment);
            if(relay.sink_size()){
                const auto n=std::min<std::size_t>(29,relay.sink_size());request_sink.insert(request_sink.end(),relay.sink_data(),relay.sink_data()+n);relay.sink_used(n);
            }
            if(relay.needs_finish())relay.finished();
            if(request_sink.size()==request.size()&&reply_sent<response.size()&&relay.source_room()){
                const auto n=std::min<std::size_t>({1024,relay.source_room(),response.size()-reply_sent});check(relay.source(response.data()+reply_sent,n));reply_sent+=n;
            }
            if(reply_sent==response.size()&&!relay.local_eof())relay.source_eof();
            if(response_sink.size()<response.size()){
                const auto out=surface.recv(h::VirtualSocket,capacity,0,++now);
                if(out.completion==w::Completion::failed)check(out.error==w::WouldBlock&&!surface.qualification_failed());
                else{check(out.completion==w::Completion::returned&&out.value>0&&out.value<=4096&&out.bytes.size()==static_cast<std::size_t>(out.value));response_sink.insert(response_sink.end(),out.bytes.begin(),out.bytes.end());}
            }
            if(response_sink.size()==response.size()&&!close_started){
                const auto eof=surface.recv(h::VirtualSocket,1,0,++now);
                if(eof.completion==w::Completion::failed)check(eof.error==w::WouldBlock&&!surface.qualification_failed());
                else{
                    check(eof.completion==w::Completion::returned&&eof.value==0);
                    const auto out=surface.close(h::VirtualSocket,++now);check(out.completion==w::Completion::pending||out.value==0);close_started=true;
                }
            }
            auto& core=surface.core();
            if(!front_closed&&core.pipe_writer_can_close(++now)){check(core.pipe_writer_closed(++now));front_closed=true;}
            if(front_closed&&!relay_eof){relay.peer_eof();relay_eof=true;}
            if(!relay_closed&&relay.can_close()){relay.writer_closed();relay_closed=true;check(core.pipe_peer_eof(++now));}
            if(close_started&&!surface.complete()){const auto out=surface.poll_close(h::VirtualSocket,++now);check(out.completion==w::Completion::pending||out.value==0);}
            check(!surface.qualification_failed()&&!relay.failure());
        }
        check(surface.complete()&&relay.complete()&&request_sink==request&&response_sink==response&&would_block>0);
    }
};
void shapes_and_options(){
    check(w::htons(0x1234)==0x3412&&w::ntohs(0x3412)==0x1234);
    check(w::htonl(0x12345678)==0x78563412&&w::ntohl(0x78563412)==0x12345678);
    Pair p;
    for(const auto& option:std::vector<std::array<int,3>>{{w::IpProtoTcp,w::TcpNoDelay,1},{w::SolSocket,w::SoKeepAlive,1},{w::IpProtoTcp,w::TcpKeepIdle,60},{w::IpProtoTcp,w::TcpKeepInterval,60},{w::IpProtoTcp,w::TcpKeepCount,9}}){
        check(p.surface.set_option(h::VirtualSocket,option[0],option[1],option[2],4,++p.now).value==0);
        const auto got=p.surface.get_option(h::VirtualSocket,option[0],option[1],4,++p.now);std::int32_t n=0;
        check(got.bytes.size()==4);std::memcpy(&n,got.bytes.data(),4);check(n==option[2]);
    }
    check(p.surface.options().no_delay==1&&p.surface.options().keepalive==1);
    w::FdSet520 set;check(p.surface.fd_is_set(h::VirtualSocket,set,++p.now).value==0);set.count=1;set.sockets[0]=h::VirtualSocket;
    check(p.surface.fd_is_set(h::VirtualSocket,set,++p.now).value==1);
    p.opened();check(p.surface.ioctl(h::VirtualSocket,w::Fionbio,0,++p.now).value==0);
    const auto blocked=p.surface.recv(h::VirtualSocket,16,0,++p.now);
    check(blocked.completion==w::Completion::pending&&!blocked.error_valid&&!p.surface.qualification_failed());
}
void zero_timeout_polls_need_bounded_transport_progress(){
    Pair p;w::SelectRequest poll;poll.write=true;poll.writes.count=1;poll.writes.sockets[0]=h::VirtualSocket;
    // Without any transport, repeated zero-timeout queries cannot fake OPEN_OK.
    for(unsigned i=0;i<4;++i){const auto result=p.surface.select_begin(poll,++p.now);check(result.call.completion==w::Completion::returned&&result.call.value==0);}
    bool connected=false;
    for(unsigned i=0;i<200&&!connected;++i){
        p.transfer(7); // same one bounded production-Node exchange as the glue's pre-poll pump
        const auto result=p.surface.select_begin(poll,++p.now);
        check(result.call.completion==w::Completion::returned);connected=result.call.value==1;
    }
    check(connected&&!p.surface.qualification_failed()&&p.surface.deadline()==p.c.end);
}
void zero_send_during_pending_connect_is_not_stream_failure(){
    Pair p;
    const auto pending=p.surface.send(h::VirtualSocket,nullptr,0,0,++p.now);
    check(pending.completion==w::Completion::failed&&pending.error==w::NotConnected);
    check(!p.surface.qualification_failed()&&p.surface.core().request_accepted()==0);
    p.opened();const auto connected=p.surface.send(h::VirtualSocket,nullptr,0,0,++p.now);
    check(connected.completion==w::Completion::returned&&connected.value==0);
    check(!p.surface.qualification_failed()&&p.surface.core().request_accepted()==0);
}
void curl_pending_name_options_events_then_HTTP(){
    Pair p; // actual observed socket/ioctl/connect -> WSAEWOULDBLOCK order
    auto local=p.surface.name(h::VirtualSocket,false,128,++p.now);
    check(local.completion==w::Completion::returned&&local.bytes.size()==16);
    w::SockaddrIn16 value{};std::memcpy(&value,local.bytes.data(),16);
    check(w::equal_address(value,{{127,0,0,1},51002}));
    check(p.surface.name(h::VirtualSocket,true,128,++p.now).error==w::NotConnected);
    check(p.surface.name(h::VirtualSocket,false,15,++p.now).error==w::Fault);
    check(p.surface.name(h::VirtualSocket,true,15,++p.now).error==w::Fault);
    check(p.surface.get_option(h::VirtualSocket,w::SolSocket,w::SoType,3,++p.now).error==w::Fault);
    const auto type=p.surface.get_option(h::VirtualSocket,w::SolSocket,w::SoType,4,++p.now);
    std::int32_t kind=0;check(type.bytes.size()==4);std::memcpy(&kind,type.bytes.data(),4);check(kind==w::SockStream);
    std::uint8_t unused=1;check(p.surface.send(h::VirtualSocket,&unused,1,0,++p.now).error==w::NotConnected);
    check(p.surface.recv(h::VirtualSocket,4096,0,++p.now).error==w::NotConnected);
    check(p.surface.query_send_backlog(h::VirtualSocket,++p.now).error==w::NotConnected);
    check(!p.surface.qualification_failed()&&p.surface.core().request_accepted()==0);
    a5startup::events::OneLive event;check(event.begin_create());check(event.created(true,64));
    check(event.select(64,0x32)); // production EventSelect's client write mask
    check(p.surface.ioctl(h::VirtualSocket,w::Fionbio,1,++p.now).value==0);
    check(p.surface.send(h::VirtualSocket,nullptr,0,0,++p.now).error==w::NotConnected);
    for(unsigned i=0;i<200&&!(event.latched()&a5startup::events::Connect);++i){
        p.transfer(7);const auto ready=p.surface.core().readiness(++p.now);
        event.observe(ready.connected,ready.readable,ready.writable,p.surface.core().response_eof());
    }
    check((event.latched()&0x12)==0x12); // OPEN_OK survives all earlier query errors
    const auto error=p.surface.get_option(h::VirtualSocket,w::SolSocket,w::SoError,4,++p.now);
    std::int32_t status=-1;check(error.bytes.size()==4);std::memcpy(&status,error.bytes.data(),4);check(status==0);
    check(p.surface.name(h::VirtualSocket,true,128,++p.now).completion==w::Completion::returned);
    check(p.surface.query_send_backlog(h::VirtualSocket,++p.now).error==w::Unsupported);
    check(!p.surface.qualification_failed());
    p.run(257,100U*1024U,true); // complete actual production Node byte/FIN exchange
}
void rejects_and_original_deadline(){
    Pair second;check(second.surface.create(2,1,6,++second.now).completion==w::Completion::failed&&second.surface.qualification_failed());
    Pair wrong;auto destination=w::address(wrong.c.target);destination.port=w::htons(51003);
    check(wrong.surface.connect(h::VirtualSocket,destination,16,++wrong.now).completion==w::Completion::failed);
    Pair option;check(option.surface.set_option(h::VirtualSocket,w::SolSocket,0x1001,4096,4,++option.now).completion==w::Completion::failed&&option.surface.qualification_failed());
    Pair timer;w::SelectRequest wait;wait.read=true;wait.reads.count=1;wait.reads.sockets[0]=h::VirtualSocket;wait.timeout.microseconds=10;
    auto pending=timer.surface.select_begin(wait,++timer.now);check(pending.call.completion==w::Completion::pending);const auto ticket=pending.ticket;
    const auto done=timer.surface.select_poll(ticket,timer.now+10);check(done.call.completion==w::Completion::returned&&done.call.value==0);
    check(timer.surface.deadline()==timer.c.end);
    const auto stale=timer.surface.select_poll(ticket,timer.now+11);check(stale.call.completion==w::Completion::failed&&timer.surface.qualification_failed());
    Pair deadline;check(deadline.surface.poll_connect(h::VirtualSocket,deadline.c.end).error==w::TimedOut&&deadline.surface.qualification_failed());
    Pair malformed;w::SelectRequest bad;bad.read=true;bad.reads.count=2;bad.reads.sockets[0]=h::VirtualSocket;bad.reads.sockets[1]=h::VirtualSocket;
    check(malformed.surface.select_begin(bad,++malformed.now).call.completion==w::Completion::failed);
    Pair empty;w::SelectRequest all_empty;all_empty.read=true;all_empty.write=true;all_empty.except=true;
    const auto invalid=empty.surface.select_begin(all_empty,++empty.now);check(invalid.call.completion==w::Completion::failed&&invalid.call.error==w::Invalid);
    check(empty.surface.get_option(h::VirtualSocket,w::SolSocket,w::SoError,4,++empty.now).error==w::Invalid);
    check(empty.surface.ioctl(h::VirtualSocket,w::Fionbio,1,++empty.now).error==w::Invalid&&empty.surface.qualification_failed());
    Pair foreign;w::FdSet520 set;set.count=1;set.sockets[0]=1;check(foreign.surface.fd_is_set(h::VirtualSocket,set,++foreign.now).completion==w::Completion::failed);
    Pair oversized;oversized.opened();check(oversized.surface.recv(h::VirtualSocket,1024U*1024U+1U,0,++oversized.now).completion==w::Completion::failed&&oversized.surface.qualification_failed());
    Pair events;check(events.surface.unsupported_api(1,++events.now).completion==w::Completion::failed&&events.surface.qualification_failed());
}
int main(){
    try{shapes_and_options();zero_timeout_polls_need_bounded_transport_progress();zero_send_during_pending_connect_is_not_stream_failure();curl_pending_name_options_events_then_HTTP();rejects_and_original_deadline();for(auto n:{1u,11u,257u}){Pair p;p.run(n,n==1?100U*1024U:(n==11?1024U*1024U:17U));}
        std::cout<<"curl-http-surface assertions: "<<checks<<"\n";return 0;
    }catch(const std::exception& e){std::cerr<<e.what()<<" at "<<checks<<"\n";return 1;}
}
