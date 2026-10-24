// Portable production ownership/notification model only. No Windows headers,
// handle/API allocation, loader, socket or process is executed by this harness.
#include "../.github/native/windows_identity_lpac_curl_a5_startup_events.hpp"
#include <iostream>
#include <stdexcept>
namespace e=a5startup::events;
unsigned checks=0;
void check(bool value){++checks;if(!value)throw std::runtime_error("event predicate");}
int main(){try{
    check(e::ipv6_capability_probe(23,2,0));check(!e::ipv6_capability_probe(2,2,0));check(!e::ipv6_capability_probe(23,1,0));check(!e::ipv6_capability_probe(23,2,6));
    e::BacklogInput48 backlog{0,0,4,0x1000,0x2000,0,0};
    check(e::backlog_probe(64,64,0x4004747b,backlog));
    check(!e::backlog_probe(65,64,0x4004747b,backlog));check(!e::backlog_probe(64,64,0x4004747a,backlog));
    for(unsigned i=0;i<7;++i){auto bad=backlog;
        if(i==0)bad.input=1;if(i==1)bad.input_bytes=1;if(i==2)bad.output_bytes=8;
        if(i==3)bad.output=0;if(i==4)bad.returned_bytes=0;if(i==5)bad.overlapped=1;if(i==6)bad.completion=1;
        check(!e::backlog_probe(64,64,0x4004747b,bad));}
    e::OneLive slot;check(slot.closed_all());check(slot.begin_create());check(!slot.begin_create());
    check(slot.created(true,64));check(slot.generation()==1&&slot.created_count()==1&&slot.owns(64));
    check(!slot.begin_create()&&!slot.owns(65));check(!slot.select(65,e::Read));
    check(!slot.select(64,64));check(slot.select(64,0x3b));
    slot.observe(true,true,true,false);check(slot.latched()==(e::Read|e::Write|e::Connect));
    check(slot.needs_signal());slot.signal_result(true,true);check(slot.signaled()&&!slot.needs_signal());
    const auto out=slot.enumerate();check(out.bits==(e::Read|e::Write|e::Connect));
    for(auto error:out.errors)check(error==0);
    check(slot.latched()==0&&slot.signaled()); // Enum(NULL) does not reset kernel event
    slot.reset_result(true,true);check(!slot.signaled());
    slot.observe(true,true,true,false);check(slot.latched()==0); // no reenable yet
    slot.after_send();slot.after_recv();slot.observe(true,true,true,false);
    check(slot.latched()==(e::Read|e::Write));(void)slot.enumerate();
    check(slot.select(0xffffffffffffffffULL,0)); // ignored cancel argument
    check(slot.select(64,0x3b));slot.observe(true,true,true,true);
    check(slot.latched()==(e::Read|e::Write|e::Close)); // CONNECT is not replayed
    (void)slot.enumerate();check(slot.select(64,0x3b));slot.observe(true,true,true,true);
    check(slot.latched()==(e::Read|e::Write)); // CLOSE is not replayed
    check(!slot.begin_close(65));check(slot.begin_close(64));check(!slot.begin_close(64));
    check(slot.consumed()==64&&!slot.live());check(slot.closed(true,true));check(slot.closed_all());
    check(slot.begin_create());check(slot.created(true,64)); // legal raw HANDLE reuse
    check(slot.generation()==2&&slot.created_count()==2);check(slot.begin_close(64));check(slot.closed(true,true));
    check(slot.closed_count()==2&&slot.closed_all());
    e::OneLive failed;check(failed.begin_create());check(!failed.created(true,0));check(failed.closed_all()&&!failed.unknown());
    e::OneLive unknown;check(unknown.begin_create());check(!unknown.created(false,88));check(unknown.unknown()&&!unknown.begin_create());
    e::OneLive closing;check(closing.begin_create());check(closing.created(true,88));check(closing.begin_close(88));
    check(!closing.closed(true,false));check(closing.unknown()&&!closing.closed_all()&&!closing.begin_close(88));
    e::OneLive late;check(late.begin_create());check(late.created(true,96)); // postclock cannot erase this authority
    check(late.begin_close(96));check(!late.closed(false,true));check(late.unknown()&&!late.begin_close(96));
    e::OneLive bounded;for(unsigned i=0;i<16;++i){check(bounded.begin_create());check(bounded.created(true,104));check(bounded.begin_close(104));check(bounded.closed(true,true));}
    check(!bounded.begin_create()&&bounded.closed_all());
    std::cout<<"curl-http-events assertions: "<<checks<<"\n";return 0;
}catch(const std::exception& error){std::cerr<<error.what()<<" at "<<checks<<"\n";return 1;}}
