// Production SocketCore + immutable production RPS1 Node. No Windows APIs.
#ifdef RULEPROXY_LPAC_STREAM_WINDOWS_HELPERS
#error This harness must compile only the portable production core.
#endif
#include "../.github/native/windows_identity_lpac_curl_http_adapter.hpp"
#include <iostream>
#include <stdexcept>
#include <vector>
using namespace lpac_curl_http;
unsigned assertions=0;
void check(bool okay){++assertions;if(!okay)throw std::runtime_error("pure assertion");}
std::string header(bool response,const Config& c,std::uint32_t total){
    std::uint32_t body=total;
    for(unsigned i=0;i<8;++i){
        std::string h=response?"HTTP/1.1 200 OK\r\nContent-Length: "+std::to_string(body)+"\r\nConnection: close\r\nX-RuleProxy-Case: "+id(c.stream.case_id)+"\r\n\r\n":
            "POST "+c.target_path+" HTTP/1.1\r\nHost: 127.0.0.1:"+std::to_string(c.target.port)+"\r\nContent-Length: "+std::to_string(body)+"\r\nConnection: close\r\n\r\n";
        const auto next=total-static_cast<std::uint32_t>(h.size());if(next==body)return h;body=next;
    }
    throw std::runtime_error("fixture header");
}
Config config(){
    Config c;c.stream.front=true;c.stream.run.fill(1);c.stream.case_id.fill(2);
    c.stream.send=8193;c.stream.receive=12289;c.target={{127,0,0,1},51001};
    c.frequency=1000000;c.start=1000;c.end=c.start+8*c.frequency;c.target_path="/ruleproxy-a2/"+id(c.stream.case_id);
    c.request_header=header(false,c,c.stream.send);c.response_header=header(true,c,c.stream.receive);
    c.request_body=c.stream.send-static_cast<std::uint32_t>(c.request_header.size());
    c.response_body=c.stream.receive-static_cast<std::uint32_t>(c.response_header.size());return c;
}
std::vector<std::uint8_t> challenge(const std::string& head,std::size_t total,unsigned seed){
    std::vector<std::uint8_t> value(head.begin(),head.end());
    while(value.size()<total)value.push_back(static_cast<std::uint8_t>((value.size()*73+seed)%256));
    return value;
}
lpac_stream::Config relay_config(const Config& c){auto w=c.stream;w.front=false;std::swap(w.send,w.receive);return w;}
struct Pair {
    Config c=config();SocketCore front{c};lpac_stream::Node relay{relay_config(c)};
    std::vector<std::uint8_t> request=challenge(c.request_header,c.stream.send,17),response=challenge(c.response_header,c.stream.receive,211);
    std::vector<std::uint8_t> request_sink,response_sink;
    std::uint64_t now=c.start;std::size_t app_sent=0,relay_sent=0;unsigned blocked=0;
    bool close_requested=false,front_writer=false,relay_writer=false,relay_input_eof=false;
    explicit Pair(){check(front.create(2,1,6,++now).state==State::okay);check(front.begin_connect(VirtualSocket,c.target,++now).state==State::pending);}
    void transfer(std::size_t fragment){
        if(const auto* p=front.pipe_output(++now)){
            const auto n=std::min(fragment,front.pipe_output_size());check(relay.feed(p,n));check(front.pipe_written(n,++now));
        }
        if(relay.needs_connect())relay.connected();
        if(const auto* p=relay.output()){
            const auto n=std::min(fragment,relay.output_size());check(front.pipe_feed(p,n,++now));relay.written(n);
        }
    }
    void opened(){
        for(unsigned i=0;i<200&&!front.readiness(++now).connected;++i)transfer(7);
        check(front.readiness(++now).connected);
    }
    void run(std::size_t fragment){
        for(unsigned turn=0;turn<100000&&!front.close_ready();++turn){
            const auto ready=front.readiness(++now);
            if(ready.connected&&app_sent<request.size()){
                const auto out=front.send(VirtualSocket,request.data()+app_sent,request.size()-app_sent,0,++now);
                if(out.state==State::pending){check(out.bytes==0);++blocked;}
                else {check(out.state==State::okay&&out.bytes>0);app_sent+=out.bytes;}
            }
            transfer(fragment);
            if(relay.sink_size()){
                const auto n=std::min<std::size_t>(29,relay.sink_size());
                request_sink.insert(request_sink.end(),relay.sink_data(),relay.sink_data()+n);relay.sink_used(n);
            }
            if(relay.needs_finish())relay.finished();
            if(request_sink.size()==request.size()&&relay.source_room()&&relay_sent<response.size()){
                const auto n=std::min<std::size_t>({1024,relay.source_room(),response.size()-relay_sent});
                check(relay.source(response.data()+relay_sent,n));relay_sent+=n;
            }
            if(relay_sent==response.size()&&!relay.local_eof())relay.source_eof();
            if(front.readiness(++now).readable&&response_sink.size()<response.size()){
                std::array<std::uint8_t,17> bytes{};const auto v=front.recv(VirtualSocket,bytes.data(),bytes.size(),0,++now);
                check(v.state==State::okay||v.state==State::pending);
                if(v.state==State::okay){check(v.bytes>0&&v.bytes<=bytes.size());response_sink.insert(response_sink.end(),bytes.begin(),bytes.begin()+v.bytes);}
            }
            if(response_sink.size()==response.size()&&!close_requested){
                const auto out=front.close_request(VirtualSocket,++now);check(out.state==State::pending||out.state==State::okay);close_requested=true;
            }
            if(!front_writer&&front.pipe_writer_can_close(++now)){check(front.pipe_writer_closed(++now));front_writer=true;}
            if(front_writer&&!relay_input_eof){relay.peer_eof();relay_input_eof=true;}
            if(!relay_writer&&relay.can_close()){relay.writer_closed();relay_writer=true;check(front.pipe_peer_eof(++now));}
            check(!front.failure()&&!relay.failure());
        }
        check(front.close_ready()&&front.transport_complete()&&relay.complete());
        check(request_sink==request&&response_sink==response);check(blocked>0);
        check(front.request_accepted()==8193&&front.response_delivered()==12289);
    }
};
void config_rejects(){
    const auto good=config();check(!SocketCore(good).failure());
    for(unsigned which=0;which<8;++which){
        auto bad=good;
        if(which==0)bad.target.address={127,0,0,2};
        if(which==1)bad.target.port=80;
        if(which==2)bad.end+=1;
        if(which==3)bad.stream.send-=1;
        if(which==4)bad.request_body+=1;
        if(which==5)bad.request_header.insert(bad.request_header.size()-2,"Transfer-Encoding: chunked\r\n");
        if(which==6)bad.response_header.replace(9,3,"404");
        if(which==7)bad.stream.run=bad.stream.case_id;
        check(SocketCore(bad).failure()!=nullptr);
    }
}
void fail_closed(){
    auto c=config();SocketCore core(c);check(core.create(23,1,6,c.start+1).state==State::failed);
    check(core.create(2,1,6,c.start+2).state==State::failed); // Sticky, not fallback.
    SocketCore second(c);check(second.create(2,1,6,c.start+1).state==State::okay);
    check(second.create(2,1,6,c.start+2).state==State::failed);
    SocketCore target(c);check(target.create(2,1,6,c.start+1).state==State::okay);auto wrong=c.target;wrong.port+=1;
    check(target.begin_connect(VirtualSocket,wrong,c.start+2).state==State::failed);
    SocketCore deadline(c);check(deadline.create(2,1,6,c.end).error==Error::timeout);
    Pair before;const std::uint8_t b=1;check(before.front.send(VirtualSocket,&b,1,0,++before.now).error==Error::not_connected);
    Pair header_bad;header_bad.opened();auto bad=header_bad.request;bad[0]^=1;
    check(header_bad.front.send(VirtualSocket,bad.data(),bad.size(),0,++header_bad.now).state==State::failed);
    check(header_bad.front.request_accepted()==0);
    Pair flags;flags.opened();check(flags.front.send(VirtualSocket,flags.request.data(),1,1,++flags.now).state==State::failed);
    Pair unsupported;unsupported.opened();check(unsupported.front.unsupported(192,++unsupported.now).state==State::failed);
    check(unsupported.front.pipe_output(++unsupported.now)==nullptr);
    Pair early;early.opened();check(!early.front.pipe_peer_eof(++early.now));
    Pair early_close;early_close.opened();check(early_close.front.close_request(VirtualSocket,++early_close.now).state==State::failed);
    Pair count;count.opened();check(!count.front.pipe_written(65536,++count.now));
}
int main(){
    try {config_rejects();fail_closed();for(auto fragment:{1u,11u,257u}){Pair pair;pair.run(fragment);}
        std::cout<<"curl-http-adapter assertions: "<<assertions<<"\n";return 0;
    }catch(const std::exception& e){std::cerr<<e.what()<<" at "<<assertions<<"\n";return 1;}
}
