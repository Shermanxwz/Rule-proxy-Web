// RPS1 bounded single-stream production codec. No OS/network APIs in this part.
#pragma once
#include <array>
#include <algorithm>
#include <cstdint>
#include <cstddef>
#include <cstring>
#include <string>
#include <vector>

namespace lpac_stream {
constexpr std::size_t Header=64, Payload=1024, Window=4096, Total=65536, Frames=256;
enum class Kind : std::uint8_t {open=1,opened=2,data=3,fin=4,reset=5,credit=6};
struct Config {bool front=false;std::array<std::uint8_t,16> run{},case_id{};std::uint32_t send=0,receive=0;};
inline void put32(std::uint8_t* p,std::uint32_t v){for(unsigned i=0;i<4;++i)p[i]=static_cast<std::uint8_t>(v>>(8*i));}
inline std::uint32_t get32(const std::uint8_t* p){std::uint32_t v=0;for(unsigned i=0;i<4;++i)v|=std::uint32_t(p[i])<<(8*i);return v;}
struct Bytes {
    std::array<std::uint8_t,Window> value{};std::size_t size=0;
    bool append(const std::uint8_t* p,std::size_t n){if(n>Window-size)return false;std::memcpy(value.data()+size,p,n);size+=n;return true;}
    void consume(std::size_t n){if(n>size)return;std::memmove(value.data(),value.data()+n,size-n);size-=n;}
};
class Node {
    Config c_;Bytes outgoing_,incoming_;
    std::array<std::uint8_t,Header+Payload> output_{},input_{};
    std::size_t output_size_=0,output_at_=0,input_at_=0,input_need_=Header;
    Kind output_kind_=Kind::reset;std::uint32_t output_credit_=0,output_payload_=0;
    std::uint32_t pending_credit_=0;bool open_seen_=false,open_sent_=false,connected_=false,local_eof_=false;
    bool opened_=false,local_fin_=false,peer_fin_=false,handled_=false,eof_=false,closed_=false;
    const char* failure_=nullptr;
    std::uint32_t tx_frames_=0,rx_frames_=0,tx_payload_=0,rx_payload_=0,source_=0,sink_=0;
    std::uint32_t tx_out_=0,rx_out_=0,tx_credit_=Window,credit_received_=0,credit_sent_=0;
    bool decoded(){
        const auto* p=input_.data();const auto kind=static_cast<Kind>(p[5]);const auto length=get32(p+44),credit=get32(p+52);
        if(std::memcmp(p,"RPS1",4)||p[4]!=1||p[6]||p[7]||std::memcmp(p+8,c_.run.data(),16)||std::memcmp(p+24,c_.case_id.data(),16)
           ||get32(p+40)!=rx_frames_+1||get32(p+48)!=1||rx_frames_>=Frames){fail("frame");return false;}
        for(unsigned i=56;i<64;++i)if(p[i]){fail("frame");return false;}
        if(length>Payload||static_cast<unsigned>(kind)<1||static_cast<unsigned>(kind)>6
           ||(kind==Kind::data?(length==0||credit!=0):(length!=0))
           ||(kind==Kind::credit?(credit==0||credit>Window):(credit!=0))){fail("frame");return false;}
        if(input_at_==Header&&length){input_need_=Header+length;return true;}
        ++rx_frames_;
        if(kind==Kind::open){if(c_.front||open_seen_||opened_||rx_frames_!=1){fail("order");return false;}open_seen_=true;}
        else if(kind==Kind::opened){if(!c_.front||!open_sent_||opened_||rx_frames_!=1){fail("order");return false;}opened_=true;}
        else if(!opened_){fail("order");return false;}
        else if(kind==Kind::reset){fail("peer_reset");return false;}
        else if(kind==Kind::data){
            if(peer_fin_||length>Window-rx_out_||length>c_.receive-rx_payload_||!incoming_.append(p+Header,length)){fail("bound");return false;}
            rx_out_+=length;rx_payload_+=length;
        }else if(kind==Kind::credit){
            if(credit>tx_out_||credit>Window-tx_credit_){fail("credit");return false;}
            tx_out_-=credit;tx_credit_+=credit;credit_received_+=credit;
        }else if(kind==Kind::fin){if(peer_fin_||rx_payload_!=c_.receive){fail("bound");return false;}peer_fin_=true;}
        input_at_=0;input_need_=Header;return true;
    }
    void frame(Kind kind,std::uint32_t length=0,std::uint32_t credit=0){
        if(tx_frames_>=Frames){fail("bound");return;}output_.fill(0);auto* p=output_.data();std::memcpy(p,"RPS1",4);p[4]=1;p[5]=static_cast<std::uint8_t>(kind);
        std::memcpy(p+8,c_.run.data(),16);std::memcpy(p+24,c_.case_id.data(),16);put32(p+40,tx_frames_+1);put32(p+44,length);put32(p+48,1);put32(p+52,credit);
        if(length)std::memcpy(p+Header,outgoing_.value.data(),length);
        output_size_=Header+length;output_at_=0;output_kind_=kind;output_payload_=length;output_credit_=credit;
    }
public:
    explicit Node(Config c):c_(c){if(c.send==0||c.receive==0||c.send>Total||c.receive>Total)fail("config");}
    void fail(const char* why){if(!failure_)failure_=why;}
    const char* failure()const{return failure_;}
    bool needs_connect()const{return !c_.front&&open_seen_&&!connected_&&!failure_;}
    void connected(){if(!needs_connect()){fail("order");return;}connected_=true;}
    bool opened()const{return opened_;}bool local_eof()const{return local_eof_;}
    std::size_t source_room()const{return opened_&&!local_eof_&&!failure_?std::min<std::size_t>(Window-outgoing_.size,tx_credit_-outgoing_.size):0;}
    std::uint32_t source_bytes()const{return source_;}
    bool source(const std::uint8_t* p,std::size_t n){if(!n||n>source_room()||n>c_.send-source_){fail("bound");return false;}outgoing_.append(p,n);source_+=static_cast<std::uint32_t>(n);return true;}
    void source_eof(){if(local_eof_||source_!=c_.send){fail("bound");return;}local_eof_=true;}
    const std::uint8_t* sink_data()const{return incoming_.value.data();}std::size_t sink_size()const{return incoming_.size;}
    void sink_used(std::size_t n){if(!n||n>incoming_.size){fail("bound");return;}incoming_.consume(n);sink_+=static_cast<std::uint32_t>(n);pending_credit_+=static_cast<std::uint32_t>(n);}
    bool needs_finish()const{return peer_fin_&&!handled_&&incoming_.size==0&&!failure_;}
    void finished(){if(!needs_finish()){fail("order");return;}handled_=true;}
    bool feed(const std::uint8_t* p,std::size_t n){
        if(failure_||eof_||!n){fail("eof");return false;}
        while(n&&!failure_){const auto amount=std::min(n,input_need_-input_at_);std::memcpy(input_.data()+input_at_,p,amount);input_at_+=amount;p+=amount;n-=amount;
            if(input_at_==input_need_&&!decoded())return false;}
        return !failure_;
    }
    const std::uint8_t* output(){
        if(failure_)return nullptr;
        if(output_at_<output_size_)return output_.data()+output_at_;
        output_at_=output_size_=0;
        if(c_.front&&!open_sent_)frame(Kind::open);
        else if(!c_.front&&connected_&&!opened_)frame(Kind::opened);
        else if(opened_){
            if(pending_credit_&&(pending_credit_>=Payload||(peer_fin_&&incoming_.size==0)))frame(Kind::credit,0,pending_credit_);
            else if(outgoing_.size)frame(Kind::data,static_cast<std::uint32_t>(std::min<std::size_t>(Payload,outgoing_.size)));
            else if(local_eof_&&!local_fin_)frame(Kind::fin);
        }
        return output_size_&&!failure_?output_.data():nullptr;
    }
    std::size_t output_size()const{return output_size_-output_at_;}
    void written(std::size_t n){
        if(!n||n>output_size()){fail("bound");return;}output_at_+=n;if(output_at_!=output_size_)return;++tx_frames_;
        if(output_kind_==Kind::open)open_sent_=true;
        else if(output_kind_==Kind::opened)opened_=true;
        else if(output_kind_==Kind::data){outgoing_.consume(output_payload_);tx_credit_-=output_payload_;tx_out_+=output_payload_;tx_payload_+=output_payload_;}
        else if(output_kind_==Kind::credit){pending_credit_-=output_credit_;rx_out_-=output_credit_;credit_sent_+=output_credit_;}
        else if(output_kind_==Kind::fin)local_fin_=true;
        output_at_=output_size_=0;
    }
    bool drained()const{return opened_&&local_eof_&&local_fin_&&peer_fin_&&handled_&&source_==c_.send&&sink_==c_.receive
        &&!outgoing_.size&&!incoming_.size&&!output_size_&&!input_at_&&!pending_credit_&&!tx_out_&&!rx_out_&&!failure_;}
    bool can_close()const{return !closed_&&drained()&&(c_.front||eof_);}
    void writer_closed(){if(!can_close()){fail("order");return;}closed_=true;}
    void peer_eof(){if(eof_||!drained()){fail("eof");return;}eof_=true;}
    bool complete()const{return drained()&&closed_&&eof_;}
    std::string json()const{
        auto b=[](bool v){return v?"true":"false";};auto n=[](std::size_t v){return std::to_string(v);};
        return std::string("{\"opened\":")+b(opened_)+",\"local_fin_sent\":"+b(local_fin_)+",\"peer_fin_received\":"+b(peer_fin_)+",\"peer_fin_handled\":"+b(handled_)
        +",\"peer_pipe_eof\":"+b(eof_)+",\"writer_closed\":"+b(closed_)+",\"protocol_complete\":"+b(complete())+",\"tx_frames\":"+n(tx_frames_)+",\"rx_frames\":"+n(rx_frames_)
        +",\"tx_payload_bytes\":"+n(tx_payload_)+",\"rx_payload_bytes\":"+n(rx_payload_)+",\"local_source_bytes\":"+n(source_)+",\"local_sink_bytes\":"+n(sink_)
        +",\"tx_credit_received\":"+n(credit_received_)+",\"rx_credit_sent\":"+n(credit_sent_)+",\"tx_outstanding\":"+n(tx_out_)+",\"rx_outstanding\":"+n(rx_out_)
        +",\"tx_window_available\":"+n(tx_credit_)+",\"local_buffered\":"+n(outgoing_.size)+",\"peer_buffered\":"+n(incoming_.size)+",\"partial_frame_bytes\":"+n(input_at_)
        +",\"pending_frame_bytes\":"+n(output_size())+",\"failure\":"+(failure_?"\""+std::string(failure_)+"\"":"null")+"}";
    }
};
enum class IOState {idle,progress,eof,error};
struct IO {IOState state=IOState::idle;std::size_t bytes=0;};
// Both actors and the fake partial-I/O scheduler use this exact driver.
template<class API> bool step(Node& node,API& api){
    if(node.failure()||node.complete())return false;
    if(!api.sample()){node.fail("external");return false;}bool changed=false;std::array<std::uint8_t,Payload> buf{};
    auto read=api.pipe_read(buf.data(),buf.size());if(read.state==IOState::error){node.fail("external");return false;}
    if(read.state==IOState::progress){if(!read.bytes||read.bytes>buf.size()||!node.feed(buf.data(),read.bytes))return false;changed=true;}
    else if(read.state==IOState::eof){node.peer_eof();changed=true;}
    if(node.failure())return false;
    if(node.needs_connect()){auto v=api.connect();if(v==IOState::error){node.fail("external");return false;}if(v==IOState::progress){node.connected();changed=true;}}
    if(node.sink_size()){auto v=api.consume(node.sink_data(),node.sink_size());if(v.state==IOState::error){node.fail("external");return false;}
        if(v.state==IOState::progress){node.sink_used(v.bytes);changed=true;}}
    if(node.needs_finish()){auto v=api.finish_inbound();if(v==IOState::error){node.fail("external");return false;}if(v==IOState::progress){node.finished();changed=true;}}
    if(node.source_room()){
        auto v=api.produce(buf.data(),std::min(buf.size(),node.source_room()));if(v.state==IOState::error){node.fail("external");return false;}
        if(v.state==IOState::progress){if(!v.bytes||v.bytes>buf.size()||!node.source(buf.data(),v.bytes))return false;changed=true;}
        else if(v.state==IOState::eof){node.source_eof();changed=true;}
    }
    if(const auto* out=node.output()){
        auto v=api.pipe_write(out,node.output_size());if(v.state==IOState::error){node.fail("external");return false;}
        if(v.state==IOState::progress){node.written(v.bytes);changed=true;}
    }
    if(node.can_close()){if(!api.close_writer()){node.fail("external");return false;}node.writer_closed();changed=true;}
    if(!api.sample()){node.fail("external");return false;}
    return changed;
}
} // namespace lpac_stream

// The selected actor defines this only AFTER the immutable identity observer.
// Portable harnesses never compile this region or include Windows headers.
#ifdef RULEPROXY_LPAC_STREAM_WINDOWS_HELPERS
#include <filesystem>
#include <limits>
namespace lpac_stream {
inline std::string boolean(bool v){return v?"true":"false";}
inline std::string quoted(const char* v){return v?"\""+std::string(v)+"\"":"null";}
inline std::string number(const std::optional<DWORD>& n){return n?std::to_string(*n):"null";}
struct Plan {
    std::string run,case_id,user,package;std::wstring role,report,ready;
    std::filesystem::path root;
    std::uint64_t reader=0,writer=0,start=0,frequency=0,end=0;
    std::uint32_t request=0,response=0;std::uint16_t port=0;Config config;
};
inline bool decimal(const std::wstring& text,std::uint64_t max,std::uint64_t& out){
    if(text.empty()||text.size()>20||text[0]==L'0')return false;std::uint64_t value=0;
    for(auto c:text){if(c<L'0'||c>L'9')return false;const auto d=static_cast<std::uint64_t>(c-L'0');if(value>(max-d)/10)return false;value=value*10+d;}out=value;return true;
}
inline bool text_sid(const std::wstring& w,std::string& out){out.clear();if(w.size()<5||w.size()>255||w[0]!=L'S'||w[1]!=L'-')return false;
    for(std::size_t i=0;i<w.size();++i){if(i&&w[i]!=L'-'&&(w[i]<L'0'||w[i]>L'9'))return false;out+=static_cast<char>(w[i]);}return true;}
inline bool hex(const std::wstring& w,std::string& out,std::array<std::uint8_t,16>& bytes){
    if(w.size()!=32)return false;out.clear();unsigned value=0;
    for(unsigned i=0;i<32;++i){const auto c=w[i];unsigned n=0;if(c>=L'0'&&c<=L'9')n=static_cast<unsigned>(c-L'0');else if(c>=L'a'&&c<=L'f')n=static_cast<unsigned>(c-L'a'+10);else return false;
        out+=static_cast<char>(c);value=(value<<4)|n;if(i%2)bytes[i/2]=static_cast<std::uint8_t>(value);}return true;
}
inline bool arguments(const wchar_t* p,std::vector<std::wstring>& out){
    if(!p)return false;std::size_t total=0;
    while(*p){while(*p==L' '||*p==L'\t')++p;if(!*p)break;std::wstring value;const bool q=*p==L'"';if(q)++p;
        while(*p&&!(q?*p==L'"':(*p==L' '||*p==L'\t'))){if(*p<32||(!q&&*p==L'"'))return false;value+=*p++;if(++total>16000||value.size()>4096)return false;}
        if(q){if(*p!=L'"')return false;++p;if(*p&&*p!=L' '&&*p!=L'\t')return false;}if(value.empty()||out.size()>=15)return false;out.push_back(std::move(value));
    }return out.size()==15||out.size()==12;
}
inline bool parse_plan(const std::vector<std::wstring>& a,Plan& p){
    if((a.size()!=15&&a.size()!=12)||a[1]!=L"stream-front"&&a[1]!=L"stream-relay"&&a[1]!=L"stream-origin")return false;
    p.role=a[1];const bool origin=p.role==L"stream-origin",front=p.role==L"stream-front";
    if((origin&&a.size()!=12)||(!origin&&a.size()!=15))return false;
    if(!hex(a[2],p.run,p.config.run)||!hex(a[3],p.case_id,p.config.case_id)||!ReadReportPath(a[4].c_str(),p.report))return false;
    const std::filesystem::path path(p.report);const auto directory=origin?L"origin-report":front?L"selected-report":L"relay-report";
    if(path.filename()!=L"actor.json"||path.parent_path().filename()!=directory)return false;p.root=path.parent_path().parent_path();
    constexpr auto maximum=0x7fffffffffffffffULL;std::uint64_t request=0,response=0,port=0;
    if(origin){
        if(!ReadReportPath(a[5].c_str(),p.ready)||std::filesystem::path(p.ready)!=path.parent_path()/L"ready.json"
            ||!decimal(a[6],maximum,p.start)||!decimal(a[7],1000000000ULL,p.frequency)||!decimal(a[8],maximum,p.end)
            ||!text_sid(a[9],p.user)||!decimal(a[10],Total,request)||!decimal(a[11],Total,response))return false;p.package="none";
    }else{
        if(!decimal(a[5],maximum,p.reader)||!decimal(a[6],maximum,p.writer)||p.reader==p.writer
           ||!decimal(a[7],maximum,p.start)||!decimal(a[8],1000000000ULL,p.frequency)||!decimal(a[9],maximum,p.end)
           ||!text_sid(a[10],p.user)||!decimal(a[12],Total,request)||!decimal(a[13],Total,response)
           ||!decimal(a[14],65535,port)||port<49153)return false;
        if(front){if(!text_sid(a[11],p.package))return false;}else{if(a[11]!=L"none")return false;p.package="none";}
        p.port=static_cast<std::uint16_t>(port);
    }
    const std::uint64_t seconds=origin?85:10;if(p.frequency>(maximum-p.start)/seconds||p.end!=p.start+seconds*p.frequency)return false;
    p.request=static_cast<std::uint32_t>(request);p.response=static_cast<std::uint32_t>(response);p.config.front=front;
    p.config.send=front?p.request:p.response;p.config.receive=front?p.response:p.request;return true;
}
struct Clock {
    std::uint64_t frequency=0,start=0,end=0,last=0;const char* failure=nullptr;
    std::optional<DWORD> error,wsa_error;
    explicit Clock(const Plan& p):start(p.start),end(p.end){LARGE_INTEGER f{};if(!QueryPerformanceFrequency(&f)||f.QuadPart<=0||static_cast<std::uint64_t>(f.QuadPart)!=p.frequency)fail("qpc");else frequency=static_cast<std::uint64_t>(f.QuadPart);}
    void fail(const char* reason,DWORD e=0){if(!failure){failure=reason;if(e)error=e;}}
    void wfail(const char* reason,int e){if(!failure){failure=reason;if(e)wsa_error=static_cast<DWORD>(e);}}
    bool sample(){LARGE_INTEGER q{};if(!QueryPerformanceCounter(&q)||q.QuadPart<=0){fail("qpc");return false;}
        const auto now=static_cast<std::uint64_t>(q.QuadPart);if(now<start||now<last){fail("qpc");return false;}last=now;if(now>=end){fail("deadline");return false;}return !failure;}
};
struct Slot {
    HANDLE value=nullptr;const char* closed="not_attempted";
    bool valid()const{return value&&value!=INVALID_HANDLE_VALUE;}
    bool close(Clock& clock){if(!valid())return std::string(closed)!="uncertain";const auto owned=value;value=nullptr;closed="uncertain";
        const BOOL ok=CloseHandle(owned);const DWORD e=ok?0:GetLastError();if(ok)closed="confirmed";else clock.fail("close",e);clock.sample();return ok!=FALSE;}
};
struct File {
    Slot handle;bool attempted=false,opened=false,flushed=false;std::uint64_t bytes=0;bool writing=false;
    bool open(Clock& clock,const std::filesystem::path& path,bool output,std::uint32_t expected=0){
        writing=output;if(!clock.sample())return false;attempted=true;
        handle.value=CreateFileW(path.c_str(),output?(GENERIC_WRITE|FILE_READ_ATTRIBUTES):GENERIC_READ,0,nullptr,output?CREATE_NEW:OPEN_EXISTING,FILE_ATTRIBUTE_NORMAL|FILE_FLAG_OPEN_REPARSE_POINT,nullptr);
        const DWORD e=handle.value==INVALID_HANDLE_VALUE?GetLastError():0;if(handle.value==INVALID_HANDLE_VALUE)handle.value=nullptr;opened=handle.valid();const bool timely=clock.sample();
        if(!opened){clock.fail("file_open",e);return false;}if(!timely)return false;
        FILE_ATTRIBUTE_TAG_INFO tag{};if(!GetFileInformationByHandleEx(handle.value,FileAttributeTagInfo,&tag,sizeof(tag))){const auto err=GetLastError();clock.fail("file_open",err);return false;}
        if(!clock.sample()||(tag.FileAttributes&(FILE_ATTRIBUTE_REPARSE_POINT|FILE_ATTRIBUTE_DIRECTORY))){clock.fail("file_open");return false;}
        if(!output){LARGE_INTEGER size{};const BOOL ok=GetFileSizeEx(handle.value,&size);const DWORD err=ok?0:GetLastError();const bool time=clock.sample();
            if(!ok){clock.fail("file_read",err);return false;}if(!time||size.QuadPart<0||static_cast<std::uint64_t>(size.QuadPart)!=expected){clock.fail("file_read");return false;}}
        return true;
    }
    IO read(Clock& clock,std::uint8_t* data,std::size_t size){if(!clock.sample())return {IOState::error,0};DWORD n=0;const BOOL ok=ReadFile(handle.value,data,static_cast<DWORD>(size),&n,nullptr);const DWORD e=ok?0:GetLastError();bytes+=n;
        const bool time=clock.sample();if(!ok){clock.fail("file_read",e);return {IOState::error,n};}if(n>size){clock.fail("file_read");return {IOState::error,n};}if(!time)return {IOState::error,n};return {n?IOState::progress:IOState::eof,n};}
    IO write(Clock& clock,const std::uint8_t* data,std::size_t size){if(!clock.sample())return {IOState::error,0};DWORD n=0;const BOOL ok=WriteFile(handle.value,data,static_cast<DWORD>(size),&n,nullptr);const DWORD e=ok?0:GetLastError();bytes+=n;
        const bool time=clock.sample();if(!ok||!n||n>size){clock.fail("file_write",e);return {IOState::error,n};}return {time?IOState::progress:IOState::error,n};}
    bool flush(Clock& clock){if(flushed)return true;if(!clock.sample())return false;const BOOL ok=FlushFileBuffers(handle.value);const DWORD e=ok?0:GetLastError();flushed=ok!=FALSE;const bool time=clock.sample();if(!ok)clock.fail("file_flush",e);return ok&&time;}
    void cleanup(Clock& clock){if(writing&&handle.valid()&&!flushed&&!clock.failure)flush(clock);handle.close(clock);}
    std::string json()const{return "{\"attempted\":"+boolean(attempted)+",\"opened\":"+boolean(opened)+",\"bytes\":"+std::to_string(bytes)+",\"flushed\":"+boolean(flushed)+",\"close\":"+quoted(handle.closed)+"}";}
};
struct Pipes {
    Slot reader,writer;bool inherited_read=false,inherited_write=false,eof=false;std::uint64_t admitted=0,read_bytes=0,write_bytes=0,read_calls=0,write_calls=0,peek_calls=0;
    explicit Pipes(const Plan& p){reader.value=reinterpret_cast<HANDLE>(static_cast<std::uintptr_t>(p.reader));writer.value=reinterpret_cast<HANDLE>(static_cast<std::uintptr_t>(p.writer));}
    bool prepare(Clock& clock){for(auto* slot:{&reader,&writer}){
        if(!clock.sample())return false;const auto type=GetFileType(slot->value);const DWORD e=type==FILE_TYPE_UNKNOWN?GetLastError():0;if(!clock.sample()||type!=FILE_TYPE_PIPE){clock.fail("pipe_type",e);return false;}
        const BOOL changed=SetHandleInformation(slot->value,HANDLE_FLAG_INHERIT,0);const DWORD ce=changed?0:GetLastError();if(!clock.sample()||!changed){clock.fail("inheritance",ce);return false;}
        DWORD flags=0;const BOOL ok=GetHandleInformation(slot->value,&flags);const DWORD ge=ok?0:GetLastError();const bool time=clock.sample();const bool clean=ok&&(flags&HANDLE_FLAG_INHERIT)==0;
        if(slot==&reader)inherited_read=clean;else inherited_write=clean;if(!time||!clean){clock.fail("inheritance",ge);return false;}}
        admitted=clock.last;return true;}
    IO read(Clock& clock,std::uint8_t* data,std::size_t size){if(eof)return {};if(!clock.sample())return {IOState::error,0};DWORD available=0;++peek_calls;
        const BOOL peek=PeekNamedPipe(reader.value,nullptr,0,nullptr,&available,nullptr);const DWORD pe=peek?0:GetLastError();if(!clock.sample())return {IOState::error,0};
        if(!peek&&pe!=ERROR_BROKEN_PIPE){clock.fail("pipe_read",pe);return {IOState::error,0};}if(peek&&!available)return {};
        const auto wanted=peek?std::min<std::size_t>(size,available):1;DWORD n=0;++read_calls;
        const BOOL ok=ReadFile(reader.value,data,static_cast<DWORD>(wanted),&n,nullptr);const DWORD e=ok?0:GetLastError();read_bytes+=n;const bool time=clock.sample();
        if(n>wanted){clock.fail("pipe_read");return {IOState::error,n};}
        if((ok&&!n)||(!ok&&e==ERROR_BROKEN_PIPE&&!n)){eof=true;return {time?IOState::eof:IOState::error,0};}
        if(!ok){clock.fail("pipe_read",e);return {IOState::error,n};}return {time?IOState::progress:IOState::error,n};}
    IO write(Clock& clock,const std::uint8_t* data,std::size_t size){if(!clock.sample())return {IOState::error,0};DWORD n=0;++write_calls;
        const BOOL ok=WriteFile(writer.value,data,static_cast<DWORD>(std::min<std::size_t>(size,1088)),&n,nullptr);const DWORD e=ok?0:GetLastError();write_bytes+=n;const bool time=clock.sample();
        if(!ok||!n||n>size){clock.fail("pipe_write",e);return {IOState::error,n};}return {time?IOState::progress:IOState::error,n};}
    void cleanup(Clock& clock){writer.close(clock);reader.close(clock);}
    std::string json()const{return "{\"read_bytes\":"+std::to_string(read_bytes)+",\"write_bytes\":"+std::to_string(write_bytes)+",\"read_calls\":"+std::to_string(read_calls)+",\"write_calls\":"+std::to_string(write_calls)+",\"peek_calls\":"+std::to_string(peek_calls)+",\"eof_observed\":"+boolean(eof)+",\"reader_close\":"+quoted(reader.closed)+",\"writer_close\":"+quoted(writer.closed)+",\"inheritance_cleared\":"+boolean(inherited_read&&inherited_write)+"}";}
};
inline bool admitted(const Observations& o,const Plan& p){const bool front=p.role==L"stream-front";
    return o.errors.empty()&&o.tokenUserSid==std::optional<std::string>(p.user)&&o.tokenIsAppContainer==std::optional<bool>(front)
       &&o.tokenElevated==std::optional<bool>(false)&&o.isProcessInJob==std::optional<bool>(true)&&o.tokenCapabilities.empty()
       &&(front?o.tokenAppContainerSid==std::optional<std::string>(p.package):!o.tokenAppContainerSid.has_value());}
inline std::string report(const Plan& p,Clock& clock,const Observations& identity,const Node* node,const Pipes* pipes,const File* source,const File* request,const File* response,const std::string& network,bool tested){
    auto identity_json=MakeReport("actor",p.run,identity,std::nullopt,std::nullopt);while(!identity_json.empty()&&(identity_json.back()=='\n'||identity_json.back()=='\r'))identity_json.pop_back();
    const std::string role=p.role==L"stream-front"?"stream-front":p.role==L"stream-relay"?"stream-relay":"stream-origin";
    return "{\"schema_version\":1,\"stage\":\"lpac-stream-actor\",\"role\":\""+role+"\",\"run_id\":\""+p.run+"\",\"case_id\":\""+p.case_id+"\",\"pid\":"+std::to_string(identity.pid)
      +",\"identity\":"+identity_json+",\"qpc\":["+std::to_string(clock.frequency)+","+std::to_string(p.start)+","+std::to_string(p.end)+","+std::to_string(clock.last)+"]"
      +",\"limits\":{\"payload_max\":1024,\"window\":4096,\"total_max\":65536,\"frames_max\":256,\"request_bytes\":"+std::to_string(p.request)+",\"response_bytes\":"+std::to_string(p.response)+"}"
      +",\"files\":{\"source\":"+(source?source->json():"null")+",\"request_sink\":"+(request?request->json():"null")+",\"response_sink\":"+(response?response->json():"null")+"}"
      +",\"stream\":"+(node?node->json():"null")+",\"pipe\":"+(pipes?pipes->json():"null")+",\"network\":"+network
      +",\"admitted_qpc\":"+(pipes&&pipes->admitted?std::to_string(pipes->admitted):"null")+",\"read_handle_inherit_cleared\":"+boolean(pipes&&pipes->inherited_read)
      +",\"write_handle_inherit_cleared\":"+boolean(pipes&&pipes->inherited_write)+",\"failure\":"+quoted(clock.failure)+",\"win32_error\":"+number(clock.error)+",\"wsa_error\":"+number(clock.wsa_error)
      +",\"selected_socket_api_tested\":false,\"network_tested\":"+boolean(tested)+",\"proxy_tested\":false,\"product_acceptance\":false}\n";
}
inline bool write_report(Slot& output,Clock& clock,const std::string& body){bool written=false;try{written=WriteReport(output.value,body);}catch(...){written=false;}const bool closed=output.close(clock);return written&&closed;}
} // namespace lpac_stream
#endif
