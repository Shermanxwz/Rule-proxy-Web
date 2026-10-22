// Compiled-in synthetic model corpus only. This executable is not a runtime bridge.
#include "windows_identity_proxy_bridge_core.hpp"
#include "windows_identity_proxy_bridge_cases.h"
#include <cstdio>

namespace {
bool corpus_valid() {
    constexpr std::size_t MaxCases=1024,MaxEventsPerCase=256,MaxEvents=32768,MaxBytes=2*1024*1024;
    if(rpb_fixture::CaseCount==0||rpb_fixture::CaseCount>MaxCases)return false;
    std::array<bool,MaxCases> ids{};std::size_t events=0,bytes=0;
    for(std::size_t i=0;i<rpb_fixture::CaseCount;++i) {
        const rpb::Case& item=rpb_fixture::Cases[i];
        if(item.id>=MaxCases||ids[item.id]||item.count>MaxEventsPerCase
            ||item.count>MaxEvents-events||(item.count&&!item.events))return false;
        ids[item.id]=true;events+=item.count;
        for(std::size_t j=0;j<item.count;++j) {
            const auto& event=item.events[j];
            if(event.target>1||event.kind>8||event.bytes.size>MaxBytes-bytes||(event.bytes.size&&!event.bytes.data))return false;
            if((event.kind!=1&&event.kind!=2&&event.kind!=4&&event.bytes.size)
                ||(event.kind==4&&event.bytes.size&&event.bytes.size!=event.value)
                ||(event.kind==4?event.selector>1:event.kind==6?event.selector>5:event.selector!=0)
                ||(event.kind==6?event.value>1:event.kind==8?(event.value<1||event.value>4):event.kind!=4&&event.value!=0))return false;
            bytes+=event.bytes.size;
        }
    }
    return true;
}
bool number(rpb::Buffer<65536>& out,std::uint32_t value) {
    if(value>65535)return false;
    return rpb::append_decimal(out,static_cast<std::uint16_t>(value));
}
}
int main(int argc,char**) {
    if(argc!=1)return 2; // No stdin, file, environment or command-line corpus.
    if(!corpus_valid())return 2;
    rpb::Buffer<65536> output;
    if(!rpb::append_literal(output,"{\"schema_version\":1,\"model_only\":true,\"runtime_acceptance\":false,\"cases\":["))return 3;
    for(std::size_t i=0;i<rpb_fixture::CaseCount;++i) {
        const rpb::Case& item=rpb_fixture::Cases[i];rpb::Frontend frontend(item.config);rpb::Relay relay(item.config);
        for(std::size_t j=0;j<item.count;++j) {
            const auto& event=item.events[j];
            rpb::LocalReducer& reducer=event.target==0?static_cast<rpb::LocalReducer&>(frontend):static_cast<rpb::LocalReducer&>(relay);
            auto applied=event;
            if(event.kind==4) {
                const auto pending=reducer.pending_output(event.selector);
                if(event.bytes.size) {
                    if(event.value>pending.size||!rpb::equal(event.bytes,{pending.data,event.value}))return 3;
                } else if(event.value&&event.value<=pending.size)return 3;
                applied.bytes={nullptr,0};
            }
            reducer.apply(applied);
            if(reducer.snapshot().failure!=rpb::Failure::None
                &&(reducer.pending_output(0).size||reducer.pending_output(1).size))return 3;
        }
        const auto front=frontend.snapshot(),back=relay.snapshot();
        const std::array<std::uint32_t,7> row={item.id,static_cast<std::uint32_t>(front.failure),static_cast<std::uint32_t>(back.failure),
            static_cast<std::uint32_t>(front.observations|back.observations),static_cast<std::uint32_t>(front.requested|back.requested),
            static_cast<std::uint32_t>(front.confirmed|back.confirmed),static_cast<std::uint32_t>(front.uncertain|back.uncertain)};
        if(row[1]>11||row[2]>11||row[3]>255||row[4]>63||row[5]>63||row[6]>63||(row[5]&row[6]))return 3;
        if(i&&!rpb::append_literal(output,","))return 3;
        if(!rpb::append_literal(output,"["))return 3;
        for(std::size_t column=0;column<row.size();++column){
            if(column&&!rpb::append_literal(output,","))return 3;
            if(!number(output,row[column]))return 3;
        }
        if(!rpb::append_literal(output,"]"))return 3;
    }
    if(!rpb::append_literal(output,"]}\n"))return 3;
    // Reserve one byte for a Windows CRT terminal LF-to-CRLF translation.
    if(output.size>65535)return 3;
    if(std::fwrite(output.data.data(),1,output.size,stdout)!=output.size)return 3;
    return std::fflush(stdout)==0?0:3;
}
