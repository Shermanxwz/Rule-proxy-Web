// Standalone inherited-pipe mechanics only. HTTP bytes/resources are synthetic.
// Synchronous pipe calls require the controller's absolute Job watchdog.
#define RULEPROXY_IDENTITY_ONLY 1
#define wmain UnusedIdentityEntry
#include "windows_identity_actor.cpp"
#undef wmain
#include "windows_identity_proxy_bridge_core.hpp"

namespace bridge_pipe {
constexpr std::uint64_t MaxSigned=static_cast<std::uint64_t>((std::numeric_limits<std::int64_t>::max)());
struct Slot {
    Slot()=default;
    Slot(const Slot&)=delete;
    Slot& operator=(const Slot&)=delete;
    HANDLE value=nullptr;
    const char* receipt="not_attempted";
    bool close(DWORD& error) noexcept {
        if(!value)return false;
        const HANDLE owned=value;value=nullptr; // Consume before one CloseHandle; no destructor retry.
        const BOOL result=CloseHandle(owned);error=result?ERROR_SUCCESS:GetLastError();
        receipt=result?"confirmed":"uncertain";return result!=FALSE;
    }
};
bool decimal(const wchar_t* text,std::uint64_t maximum,std::uint64_t& out) {
    if(!text||!text[0]||text[0]==L'0')return false;
    std::uint64_t value=0;std::size_t count=0;
    while(text[count]) {
        if(count>=20||text[count]<L'0'||text[count]>L'9')return false;
        const auto digit=static_cast<std::uint64_t>(text[count]-L'0');
        if(value>(maximum-digit)/10)return false;
        value=value*10+digit;++count;
    }
    if(!value||value>maximum)return false;
    out=value;return true;
}
bool sid_text(const wchar_t* text,std::string& out) {
    if(!text||text[0]!=L'S'||text[1]!=L'-')return false;
    for(std::size_t i=0;i<256;++i){const wchar_t c=text[i];if(!c)return i>2;
        if(i>0&&c!=L'-'&&(c<L'0'||c>L'9'))return false;
        out.push_back(static_cast<char>(c));}
    return false;
}
std::array<std::uint8_t,16> id_bytes(const std::string& text) {
    std::array<std::uint8_t,16> result{};
    auto digit=[](char c)->unsigned{return c>='0'&&c<='9'?static_cast<unsigned>(c-'0'):static_cast<unsigned>(c-'a'+10);};
    for(std::size_t i=0;i<16;++i)result[i]=static_cast<std::uint8_t>((digit(text[2*i])<<4)|digit(text[2*i+1]));
    return result;
}
struct Facts {
    const char* failure=nullptr;std::optional<DWORD> error;
    std::uint64_t frequency=0,start=0,end=0,last=0;
    DWORD read_bytes=0,write_bytes=0,read_frames=0,write_frames=0;
    bool inheritance=false,eof=false,request_checked=false,response_checked=false,client_checked=false;
};
class Probe {
    bool front_;rpb::Config config_;rpb::LocalReducer core_;std::uint64_t elapsed_=0;
public:
    Slot reader,writer;Facts facts;
    Probe(bool front,const std::string& run,const std::string& item,HANDLE read,HANDLE write,
          std::uint64_t start,std::uint64_t frequency,std::uint64_t end,std::uint16_t relay_port=49153,
          rpb::OriginAuthority authority=rpb::OriginAuthority::GuestFixture)
      :front_(front),config_{id_bytes(run),id_bytes(item),49152,relay_port,0,10000,authority},core_(config_,front) {
        reader.value=read;writer.value=write;facts.start=start;facts.frequency=frequency;facts.end=end;
    }
    void fail(const char* label,std::optional<DWORD> error=std::nullopt) {
        if(!facts.failure){facts.failure=label;facts.error=error;}
    }
    bool sample() {
        if(!facts.frequency||facts.frequency>1000000000ULL||facts.start>MaxSigned
            ||facts.frequency>(MaxSigned-facts.start)/10||facts.end!=facts.start+10*facts.frequency){fail("qpc");return false;}
        LARGE_INTEGER now{};
        if(!QueryPerformanceCounter(&now)){fail("qpc",GetLastError());return false;}
        if(now.QuadPart<0){fail("qpc");return false;}
        const auto tick=static_cast<std::uint64_t>(now.QuadPart);
        if(tick<facts.start||(facts.last&&tick<facts.last)){fail("qpc");return false;}
        facts.last=tick;
        if(tick>=facts.end){elapsed_=10000;core_.apply({0,0,0,10000,{nullptr,0},0});fail("qpc");return false;}
        const auto delta=tick-facts.start;
        elapsed_=(delta/facts.frequency)*1000+((delta%facts.frequency)*1000)/facts.frequency;
        core_.apply({0,0,0,elapsed_,{nullptr,0},0});
        if(core_.snapshot().failure!=rpb::Failure::None){fail("core");return false;}
        return true;
    }
    bool event(std::uint8_t kind,std::uint8_t selector=0,rpb::ByteView bytes={nullptr,0},std::uint32_t value=0) {
        if(!sample())return false;
        core_.apply({0,kind,selector,elapsed_,bytes,value});
        if(core_.snapshot().failure!=rpb::Failure::None){fail("core");return false;}return true;
    }
    bool admitted(const Observations& identity,const std::string& user,const std::string& ac,bool elevated) {
        const bool container=ac!="none";
        if(!identity.errors.empty()||identity.tokenUserSid!=std::optional<std::string>(user)
            ||identity.tokenElevated!=std::optional<bool>(elevated)
            ||identity.tokenIsAppContainer!=std::optional<bool>(container)
            ||identity.isProcessInJob!=std::optional<bool>(true)||!identity.tokenCapabilities.empty()
            ||(container?identity.tokenAppContainerSid!=std::optional<std::string>(ac):identity.tokenAppContainerSid.has_value())
            ||(!front_&&container)){fail("identity");return false;}
        LARGE_INTEGER frequency{};
        if(!QueryPerformanceFrequency(&frequency)){fail("qpc",GetLastError());return false;}
        if(frequency.QuadPart<=0||static_cast<std::uint64_t>(frequency.QuadPart)!=facts.frequency
            ||facts.frequency>1000000000ULL||facts.frequency>(MaxSigned-facts.start)/10
            ||facts.end!=facts.start+10*facts.frequency){fail("qpc");return false;}
        if(!sample())return false;
        SetLastError(ERROR_SUCCESS);const DWORD read_type=GetFileType(reader.value);
        const DWORD read_error=read_type==FILE_TYPE_UNKNOWN?GetLastError():ERROR_SUCCESS;
        SetLastError(ERROR_SUCCESS);const DWORD write_type=GetFileType(writer.value);
        const DWORD write_error=write_type==FILE_TYPE_UNKNOWN?GetLastError():ERROR_SUCCESS;
        if(read_type!=FILE_TYPE_PIPE||write_type!=FILE_TYPE_PIPE){
            const DWORD error=read_type!=FILE_TYPE_PIPE?read_error:write_error;
            fail("pipe_type",error?std::optional<DWORD>(error):std::nullopt);return false;
        }
        const BOOL read_clear=SetHandleInformation(reader.value,HANDLE_FLAG_INHERIT,0);const DWORD read_clear_error=read_clear?0:GetLastError();
        const BOOL write_clear=SetHandleInformation(writer.value,HANDLE_FLAG_INHERIT,0);const DWORD write_clear_error=write_clear?0:GetLastError();
        facts.inheritance=read_clear&&write_clear;
        if(!facts.inheritance){fail("inheritance",!read_clear?read_clear_error:write_clear_error);return false;}
        return sample();
    }
    bool read_frame() {
        std::array<std::uint8_t,48> bytes{};DWORD offset=0;
        while(offset<48) {
            if(!sample())return false;
            DWORD count=0;const BOOL ok=ReadFile(reader.value,bytes.data()+offset,48-offset,&count,nullptr);
            const DWORD error=ok?0:GetLastError();
            if(count<=48-offset)facts.read_bytes+=count;
            const bool in_time=sample();
            if(!ok||!count||count>48-offset){fail("pipe_read",ok?std::nullopt:std::optional<DWORD>(error));return false;}
            if(!in_time)return false;
            core_.apply({0,1,0,elapsed_,{bytes.data()+offset,count},0});offset+=count;
            if(core_.snapshot().failure!=rpb::Failure::None){fail("core");return false;}
        }
        ++facts.read_frames;return true;
    }
    bool write_frame() {
        auto pending=core_.pending_output(0);
        if(pending.size!=48){fail("core");return false;}
        while(pending.size) {
            if(!sample())return false;
            DWORD count=0;const BOOL ok=WriteFile(writer.value,pending.data,static_cast<DWORD>(pending.size),&count,nullptr);
            const DWORD error=ok?0:GetLastError();
            if(count<=pending.size)facts.write_bytes+=count;
            const bool in_time=sample();
            if(!ok||!count||count>pending.size){fail("pipe_write",ok?std::nullopt:std::optional<DWORD>(error));return false;}
            if(!in_time)return false;
            core_.apply({0,4,0,elapsed_,{nullptr,0},count});
            if(core_.snapshot().failure!=rpb::Failure::None){fail("core");return false;}
            pending=core_.pending_output(0);
        }
        ++facts.write_frames;return true;
    }
    bool read_eof() {
        if(!sample())return false;
        std::uint8_t byte=0;DWORD count=0;const BOOL ok=ReadFile(reader.value,&byte,1,&count,nullptr);
        const DWORD error=ok?0:GetLastError();if(count<=1)facts.read_bytes+=count;
        const bool in_time=sample();
        facts.eof=(ok&&count==0)||(!ok&&error==ERROR_BROKEN_PIPE&&count==0);
        if(!facts.eof){fail("eof",ok?std::nullopt:std::optional<DWORD>(error));return false;}
        if(!in_time)return false;
        return event(5);
    }
    bool close_pipe(bool write) {
        Slot& slot=write?writer:reader;if(!slot.value)return false;
        const bool before=sample();DWORD error=0;const bool closed=slot.close(error);const bool after=sample();
        if(!closed)fail("close",error);
        const auto resource=static_cast<std::uint8_t>(front_?(write?1u:0u):(write?4u:3u));
        if(core_.snapshot().requested&(1u<<resource))core_.apply({0,6,resource,elapsed_,{nullptr,0},closed?1u:0u});
        return before&&after&&closed&&!facts.failure;
    }
    bool synthetic_request() {
        rpb::Buffer<256> request;
        rpb::append_literal(request,"GET http://ruleproxy-identity-proof.invalid/");rpb::append_hex(request,config_.case_id);
        rpb::append_literal(request," HTTP/1.1\r\nHost: ruleproxy-identity-proof.invalid\r\n\r\n");
        facts.request_checked=rpb::parse_request(config_,request.view())==rpb::Failure::None;
        return facts.request_checked&&event(2,0,request.view())&&event(3);
    }
    bool synthetic_origin() {
        const auto request=rpb::relay_request(config_);const auto pending=core_.pending_output(1);
        facts.request_checked=rpb::equal(pending,request.view());if(!facts.request_checked){fail("core");return false;}
        if(!event(4,1,{nullptr,0},static_cast<std::uint32_t>(pending.size)))return false;
        const auto response=rpb::expected_response(config_);facts.response_checked=true;
        return event(2,0,response.view())&&event(3)&&event(6,5,{nullptr,0},1);
    }
    bool synthetic_sink() {
        const auto response=rpb::expected_response(config_);const auto pending=core_.pending_output(1);
        facts.response_checked=rpb::equal(pending,response.view());if(!facts.response_checked){fail("core");return false;}
        if(!event(4,1,{nullptr,0},static_cast<std::uint32_t>(pending.size)))return false;
        facts.client_checked=true;return event(6,2,{nullptr,0},1);
    }
    void run() {
        if(front_) {
            if(!read_frame()||!write_frame()||!synthetic_request()||!write_frame()||!read_frame()
                ||!read_eof()||!close_pipe(false)||!synthetic_sink()||!write_frame()||!close_pipe(true))return;
        } else {
            if(!write_frame()||!read_frame()||!read_frame()||!synthetic_origin()||!write_frame()
                ||!close_pipe(true)||!read_frame()||!read_eof()||!close_pipe(false))return;
        }
    }
    void cleanup() noexcept {
        // Independent attempts even on expiry/failure. No raw handle is retried.
        for(Slot* slot:std::array<Slot*,2>{&reader,&writer})if(slot->value){
            (void)sample();DWORD error=0;const bool ok=slot->close(error);(void)sample();
            if(!ok)fail("close",error);
            const auto resource=static_cast<std::uint8_t>(front_?(slot==&writer?1u:0u):(slot==&writer?4u:3u));
            if(core_.snapshot().requested&(1u<<resource))core_.apply({0,6,resource,elapsed_,{nullptr,0},ok?1u:0u});
        }
    }
    rpb::Snapshot snapshot()const{return core_.snapshot();}
    rpb::ByteView pending_http()const{return core_.pending_output(1);}
};
const char* boolean(bool value){return value?"true":"false";}
std::string report(Probe& probe,const Observations& identity,bool front,const std::string& run,const std::string& item) {
    std::string native=MakeReport("actor",run,identity,std::nullopt,std::nullopt);
    while(!native.empty()&&(native.back()=='\n'||native.back()=='\r'))native.pop_back();
    const auto& f=probe.facts;const auto c=probe.snapshot();
    std::string out="{\"schema_version\":1,\"stage\":\"bridge-pipe-test\",\"role\":\"";
    out+=front?"pipe-front":"pipe-relay";
    out+="\",\"run_id\":\""+run+"\",\"case_id\":\""+item+"\",\"pid\":"+std::to_string(identity.pid)+",\"identity\":"+native;
    out+=",\"qpc\":["+std::to_string(f.frequency)+","+std::to_string(f.start)+","+std::to_string(f.end)+","+std::to_string(f.last)+"]";
    out+=",\"pipe\":{\"read_bytes\":"+std::to_string(f.read_bytes)+",\"write_bytes\":"+std::to_string(f.write_bytes);
    out+=",\"read_frames\":"+std::to_string(f.read_frames)+",\"write_frames\":"+std::to_string(f.write_frames);
    out+=",\"inheritance_cleared\":"+std::string(boolean(f.inheritance))+",\"eof_observed\":"+boolean(f.eof);
    out+=",\"reader_close\":\""+std::string(probe.reader.receipt)+"\",\"writer_close\":\""+probe.writer.receipt+"\",\"requires_controller_timeout\":true}";
    out+=",\"core\":{\"failure\":"+std::to_string(static_cast<unsigned>(c.failure))+",\"observations\":"+std::to_string(c.observations);
    out+=",\"requested\":"+std::to_string(c.requested)+",\"confirmed\":"+std::to_string(c.confirmed)+",\"uncertain\":"+std::to_string(c.uncertain)+"}";
    out+=",\"synthetic_http\":{\"request_checked\":"+std::string(boolean(f.request_checked))+",\"response_checked\":"+boolean(f.response_checked)+",\"client_sink_checked\":"+boolean(f.client_checked)+"}";
    out+=",\"failure\":"+(f.failure?"\""+std::string(f.failure)+"\"":"null")+",\"win32_error\":"+(f.error?std::to_string(*f.error):"null");
    out+=",\"network_tested\":false,\"proxy_tested\":false,\"product_acceptance\":false}\n";return out;
}
int run(int argc,wchar_t** argv) {
    if(argc!=13)return 2;
    const bool front=std::wstring(argv[1])==L"pipe-front";
    if(!front&&std::wstring(argv[1])!=L"pipe-relay")return 2;
    std::string run_id,case_id,user,ac;std::wstring path;
    std::uint64_t read=0,write=0,start=0,frequency=0,end=0;
    if(!ReadNonce(argv[2],run_id)||!ReadNonce(argv[3],case_id)||!ReadReportPath(argv[4],path)
        ||!decimal(argv[5],static_cast<std::uint64_t>((std::numeric_limits<std::intptr_t>::max)()),read)
        ||!decimal(argv[6],static_cast<std::uint64_t>((std::numeric_limits<std::intptr_t>::max)()),write)||read==write
        ||!decimal(argv[7],MaxSigned,start)||!decimal(argv[8],1000000000ULL,frequency)||!decimal(argv[9],MaxSigned,end)
        ||!sid_text(argv[10],user))return 2;
    if(std::wstring(argv[11])==L"none")ac="none";else if(!sid_text(argv[11],ac))return 2;
    const std::wstring elevation(argv[12]);if(elevation!=L"0"&&elevation!=L"1")return 2;
    Probe probe(front,run_id,case_id,reinterpret_cast<HANDLE>(static_cast<std::uintptr_t>(read)),reinterpret_cast<HANDLE>(static_cast<std::uintptr_t>(write)),start,frequency,end);
    Slot output;output.value=CreateFileW(path.c_str(),GENERIC_WRITE,0,nullptr,CREATE_NEW,FILE_ATTRIBUTE_NORMAL,nullptr);
    if(output.value==INVALID_HANDLE_VALUE){output.value=nullptr;probe.cleanup();return 3;}
    Observations identity;
    try {identity=ObserveNativeIdentity();if(probe.admitted(identity,user,ac,elevation==L"1"))probe.run();}
    catch(...){probe.fail("configuration");}
    probe.cleanup();bool written=false;
    try {written=WriteReport(output.value,report(probe,identity,front,run_id,case_id));}catch(...){written=false;}
    DWORD close_error=0;const bool closed=output.close(close_error);
    if(!written||!closed)return 3;
    return probe.facts.failure?5:0;
}
} // namespace bridge_pipe
#ifndef RULEPROXY_PROXY_PIPE_LIBRARY
int wmain(int argc,wchar_t* argv[]) {try{return bridge_pipe::run(argc,argv);}catch(...){return 6;}}
#endif
