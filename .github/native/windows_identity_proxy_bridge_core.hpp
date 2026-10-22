#ifndef WINDOWS_IDENTITY_PROXY_BRIDGE_CORE_HPP
#define WINDOWS_IDENTITY_PROXY_BRIDGE_CORE_HPP
// Transport-free deterministic protocol core. Every observation is caller supplied.
// No clocks, I/O, allocation, callbacks, OS/network/security APIs or runtime proof.
#include <array>
#include <cstddef>
#include <cstdint>
#include <limits>

namespace rpb {
struct ByteView { const std::uint8_t* data; std::size_t size; };
struct Config {
    std::array<std::uint8_t,16> run_id,case_id;
    std::uint16_t frontend_port,relay_port;
    std::uint64_t start_tick,deadline_tick;
};
struct Event {
    std::uint8_t target,kind,selector;
    std::uint64_t tick;
    ByteView bytes;
    std::uint32_t value;
};
struct Case { std::uint32_t id; Config config; const Event* events; std::size_t count; };
enum class Failure : std::uint8_t { None=0,Config=1,Frame=2,Order=3,Http=4,Response=5,Write=6,Eof=7,Clock=8,Deadline=9,Close=10,Bound=11 };
constexpr std::size_t FrameSize=48,MaxRequest=8192,MaxResponse=256,MaxHeaders=32,MaxLine=1024;
constexpr std::uint64_t Budget=10000;
constexpr char Authority[]="ruleproxy-identity-proof.invalid";
inline bool valid_config(const Config& c) {
    return c.frontend_port>=49152 && c.relay_port>=49152 && c.frontend_port!=c.relay_port
        && c.start_tick<=std::numeric_limits<std::uint64_t>::max()-Budget
        && c.deadline_tick==c.start_tick+Budget;
}
template<std::size_t N> struct Buffer {
    std::array<std::uint8_t,N> data{}; std::size_t size=0;
    bool append(ByteView value) {
        if ((value.size && !value.data) || value.size>N-size) return false;
        for(std::size_t i=0;i<value.size;++i)data[size+i]=value.data[i];
        size+=value.size;return true;
    }
    ByteView view() const { return {data.data(),size}; }
    void clear(){size=0;}
};
inline bool equal(ByteView a,ByteView b) {
    if(a.size!=b.size || (a.size && (!a.data||!b.data)))return false;
    for(std::size_t i=0;i<a.size;++i)if(a.data[i]!=b.data[i])return false;
    return true;
}
template<std::size_t N> inline ByteView literal(const char (&text)[N]) {
    // Not used for object representation or wire integer access.
    return {reinterpret_cast<const std::uint8_t*>(text),N-1};
}
template<std::size_t N,std::size_t M> inline bool append_literal(Buffer<N>& out,const char (&text)[M]) {
    return out.append(literal(text));
}
template<std::size_t N> inline bool append_hex(Buffer<N>& out,const std::array<std::uint8_t,16>& id) {
    constexpr char hex[]="0123456789abcdef";
    if(32>N-out.size)return false;
    for(auto byte:id){out.data[out.size++]=static_cast<std::uint8_t>(hex[byte>>4]);out.data[out.size++]=static_cast<std::uint8_t>(hex[byte&15]);}
    return true;
}
template<std::size_t N> inline bool append_decimal(Buffer<N>& out,std::uint16_t value) {
    std::array<std::uint8_t,5> reverse{};std::size_t size=0;
    do {reverse[size++]=static_cast<std::uint8_t>('0'+value%10);value=static_cast<std::uint16_t>(value/10);} while(value);
    if(size>N-out.size)return false;
    while(size){out.data[out.size++]=reverse[--size];}
    return true;
}
inline std::uint32_t read_le32(const std::uint8_t* bytes) {
    return std::uint32_t(bytes[0])|(std::uint32_t(bytes[1])<<8)|(std::uint32_t(bytes[2])<<16)|(std::uint32_t(bytes[3])<<24);
}
inline void write_le32(std::uint8_t* bytes,std::uint32_t value) {
    for(unsigned i=0;i<4;++i)bytes[i]=static_cast<std::uint8_t>((value>>(8*i))&255u);
}
inline Buffer<FrameSize> encode_frame(const Config& c,std::uint8_t kind,std::uint32_t status=0) {
    Buffer<FrameSize> out;
    if(!valid_config(c)||kind<1||kind>5||status>(kind==4?4u:0u))return out;
    out.size=FrameSize;out.data[0]='R';out.data[1]='P';out.data[2]='B';out.data[3]='1';out.data[4]=kind;
    for(std::size_t i=0;i<16;++i){out.data[8+i]=c.run_id[i];out.data[24+i]=c.case_id[i];}
    write_le32(out.data.data()+40,kind-1u);write_le32(out.data.data()+44,status);return out;
}
inline bool decode_frame(const Config& c,ByteView bytes,std::uint8_t& kind,std::uint32_t& status) {
    if(bytes.size!=FrameSize||!bytes.data)return false;
    kind=bytes.data[4];status=read_le32(bytes.data+44);
    const auto expected=encode_frame(c,kind,status);
    return expected.size==FrameSize && equal(bytes,expected.view());
}
inline Buffer<MaxResponse> relay_request(const Config& c) {
    Buffer<MaxResponse> out;
    append_literal(out,"GET /p1/");append_hex(out,c.case_id);
    append_literal(out," HTTP/1.1\r\nHost: 10.0.2.2:");append_decimal(out,c.relay_port);
    append_literal(out,"\r\nConnection: close\r\n\r\n");return out;
}
inline Buffer<MaxResponse> expected_response(const Config& c) {
    Buffer<MaxResponse> out;
    append_literal(out,"HTTP/1.1 200 OK\r\nContent-Length: 32\r\nConnection: close\r\n\r\n");
    append_hex(out,c.case_id);return out;
}
inline std::uint8_t lower(std::uint8_t c){return c>='A'&&c<='Z'?static_cast<std::uint8_t>(c+('a'-'A')):c;}
template<std::size_t N> inline bool lower_equal(ByteView value,const char (&text)[N]) {
    if(value.size!=N-1)return false;
    for(std::size_t i=0;i<value.size;++i)if(lower(value.data[i])!=static_cast<std::uint8_t>(text[i]))return false;
    return true;
}
inline bool token(std::uint8_t c) {
    if((c>='a'&&c<='z')||(c>='A'&&c<='Z')||(c>='0'&&c<='9'))return true;
    constexpr char symbols[]="!#$%&'*+.^_`|~-";
    for(char allowed:symbols)if(allowed && c==static_cast<std::uint8_t>(allowed))return true;
    return false;
}
inline bool authority(ByteView value) {
    if(equal(value,literal(Authority)))return true;
    Buffer<64> optional;append_literal(optional,Authority);append_literal(optional,":80");return equal(value,optional.view());
}
inline bool request_line(const Config& c,ByteView line) {
    for(bool with_port:std::array<bool,2>{false,true}) {
        Buffer<256> expected;append_literal(expected,"GET http://");append_literal(expected,Authority);
        if(with_port){append_literal(expected,":80");}
        append_literal(expected,"/");append_hex(expected,c.case_id);
        append_literal(expected," HTTP/1.1");if(equal(line,expected.view()))return true;
    }
    return false;
}
inline Failure parse_request(const Config& c,ByteView bytes) {
    if(bytes.size>MaxRequest)return Failure::Bound;
    if(!bytes.size||!bytes.data)return Failure::Http;
    std::size_t start=0,headers=0;bool first=true,host=false,content_length=false;
    while(start<bytes.size) {
        std::size_t end=start;
        while(end<bytes.size && bytes.data[end]!='\r' && bytes.data[end]!='\n')++end;
        if(end+1>=bytes.size || bytes.data[end]!='\r'||bytes.data[end+1]!='\n')return Failure::Http;
        const std::size_t length=end-start;
        if(length+2>MaxLine)return Failure::Bound;
        for(std::size_t i=start;i<end;++i)if(bytes.data[i]>126||(bytes.data[i]<32&&bytes.data[i]!=9))return Failure::Http;
        const ByteView line{bytes.data+start,length};start=end+2;
        if(first){first=false;if(!request_line(c,line))return Failure::Http;continue;}
        if(!length)return start==bytes.size&&host?Failure::None:Failure::Http;
        if(++headers>MaxHeaders)return Failure::Bound;
        std::size_t colon=0;while(colon<length&&line.data[colon]!=':')++colon;
        if(colon==0||colon==length)return Failure::Http;
        for(std::size_t i=0;i<colon;++i)if(!token(line.data[i]))return Failure::Http;
        const ByteView name{line.data,colon};std::size_t left=colon+1,right=length;
        while(left<right&&(line.data[left]==' '||line.data[left]=='\t'))++left;
        while(right>left&&(line.data[right-1]==' '||line.data[right-1]=='\t'))--right;
        const ByteView value{line.data+left,right-left};
        if(lower_equal(name,"transfer-encoding")||lower_equal(name,"authorization")||lower_equal(name,"proxy-authorization")
            ||lower_equal(name,"cookie")||lower_equal(name,"set-cookie")||lower_equal(name,"upgrade"))return Failure::Http;
        if(lower_equal(name,"host")){if(host||!authority(value))return Failure::Http;host=true;}
        else if(lower_equal(name,"content-length")){if(content_length||!equal(value,literal("0")))return Failure::Http;content_length=true;}
    }
    return Failure::Http;
}

struct Snapshot { Failure failure;std::uint8_t observations,requested,confirmed,uncertain; };
struct Output {
    Buffer<MaxResponse> bytes;std::size_t offset=0;std::uint8_t kind=0;
    bool active()const{return offset<bytes.size;}
    void cancel(){bytes.clear();offset=0;kind=0;}
    ByteView pending()const{return {bytes.data.data()+offset,bytes.size-offset};}
};
class LocalReducer {
    Config config_;bool frontend_;std::uint64_t now_;
    Failure failure_=Failure::None;
    std::uint8_t observations_=0,requested_=0,confirmed_=0,uncertain_=0;
    Buffer<FrameSize> frame_;Buffer<MaxRequest> request_;Buffer<MaxResponse> response_;
    Output pipe_,http_;
    bool init_=false,ready_written_=false,ready_=false,request_submitted_=false,request_written_=false;
    bool request_received_=false,upstream_written_=false,response_verified_=false,response_received_=false;
    bool response_written_=false,pipe_eof_=false,client_written_=false,done_received_=false,error_draining_=false;
    std::uint32_t response_status_=0;
    std::uint8_t owned()const{return frontend_?7u:56u;}
    void fail(Failure reason){if(failure_==Failure::None)failure_=reason;requested_|=owned();}
    bool clock(std::uint64_t tick) {
        if(tick<now_){fail(Failure::Clock);return false;}
        now_=tick;if(tick>=config_.deadline_tick)fail(Failure::Deadline);
        return failure_==Failure::None;
    }
    bool queue(Output& output,ByteView bytes,std::uint8_t kind) {
        if(output.active()){fail(Failure::Order);return false;}
        output.cancel();if(!output.bytes.append(bytes)){fail(Failure::Bound);return false;}
        output.kind=kind;return true;
    }
    void queue_frame(std::uint8_t kind,std::uint32_t status=0){const auto bytes=encode_frame(config_,kind,status);queue(pipe_,bytes.view(),kind);}
    void receive_frame(ByteView bytes) {
        if(!bytes.size||!bytes.data){fail(Failure::Frame);return;}
        if(!frame_.append(bytes)){fail(Failure::Bound);return;}
        if(frame_.size!=FrameSize)return;
        std::uint8_t kind=0;std::uint32_t status=0;
        if(!decode_frame(config_,frame_.view(),kind,status)){fail(Failure::Frame);return;}
        frame_.clear();
        if(frontend_) {
            if(kind==1&&!init_){init_=true;observations_|=1u;queue_frame(2);}
            else if(kind==4&&request_written_&&!response_received_){response_received_=true;response_status_=status;if(status)fail(Failure::Response);}
            else fail(Failure::Order);
        } else {
            if(kind==2&&init_&&!ready_){ready_=true;observations_|=2u;}
            else if(kind==3&&ready_&&!request_received_){request_received_=true;observations_|=4u;const auto request=relay_request(config_);queue(http_,request.view(),6);}
            else if(kind==5&&response_written_&&(confirmed_&16u)&&!done_received_&&!error_draining_){done_received_=true;}
            else fail(Failure::Order);
        }
    }
    void feed_http(ByteView bytes) {
        if(frontend_) {
            if(!ready_written_||request_submitted_){fail(Failure::Order);return;}
            if(!bytes.size||!bytes.data){fail(Failure::Http);return;}
            if(!request_.append(bytes))fail(Failure::Bound);
        } else {
            if(!upstream_written_||response_verified_||error_draining_){fail(Failure::Order);return;}
            if(!bytes.size||!bytes.data){fail(Failure::Response);return;}
            if(!response_.append(bytes))fail(Failure::Bound);
        }
    }
    void finish_http() {
        if(frontend_) {
            if(!ready_written_||request_submitted_){fail(Failure::Order);return;}
            const auto parsed=parse_request(config_,request_.view());if(parsed!=Failure::None){fail(parsed);return;}
            request_submitted_=true;queue_frame(3);
        } else {
            if(!upstream_written_||response_verified_||error_draining_){fail(Failure::Order);return;}
            const auto expected=expected_response(config_);
            if(!equal(response_.view(),expected.view())){fail(Failure::Response);return;}
            response_verified_=true;observations_|=8u;requested_|=32u;response_status_=0;queue_frame(4);
        }
    }
    void write(std::uint8_t channel,std::uint32_t count) {
        if(channel>1){fail(Failure::Write);return;}
        Output& output=channel?http_:pipe_;
        if(error_draining_&&channel!=0){fail(Failure::Order);return;}
        if(!count||!output.active()||count>output.bytes.size-output.offset){fail(Failure::Write);return;}
        output.offset+=count;if(output.active())return;
        const auto kind=output.kind;output.cancel();
        if(frontend_) {
            if(kind==2)ready_written_=true;
            else if(kind==3)request_written_=true;
            else if(kind==7){client_written_=true;observations_|=32u;requested_|=4u;}
            else if(kind==5){observations_|=128u;requested_|=2u;}
            else fail(Failure::Order);
        } else {
            if(kind==1)init_=true;
            else if(kind==6)upstream_written_=true;
            else if(kind==4){response_written_=true;requested_|=16u;if(error_draining_)fail(Failure::Response);}
            else fail(Failure::Order);
        }
    }
    void pipe_eof() {
        if(frame_.size||pipe_eof_){fail(Failure::Eof);return;}
        if(frontend_) {
            if(!response_received_||response_status_!=0){fail(Failure::Eof);return;}
            pipe_eof_=true;observations_|=16u;requested_|=1u;const auto response=expected_response(config_);queue(http_,response.view(),7);
        } else {
            if(!done_received_){fail(Failure::Eof);return;}
            pipe_eof_=true;observations_|=64u;requested_|=owned();
        }
    }
    void close(std::uint8_t resource,std::uint32_t confirmed,bool healthy) {
        if(resource>5||confirmed>1){fail(Failure::Close);return;}
        const auto bit=static_cast<std::uint8_t>(1u<<resource);
        if(!(owned()&bit)||!(requested_&bit)||((confirmed_|uncertain_)&bit)){fail(Failure::Close);return;}
        if(!confirmed){uncertain_|=bit;fail(Failure::Close);return;}
        confirmed_|=bit;
        if(healthy&&frontend_&&resource==2) {
            if(!client_written_||!pipe_eof_){fail(Failure::Order);return;}
            queue_frame(5);
        }
    }
    void relay_failure(std::uint32_t status) {
        if(frontend_||status<1||status>4||!request_received_||response_verified_||error_draining_||response_written_){fail(Failure::Order);return;}
        error_draining_=true;response_status_=status;http_.cancel();requested_|=32u;queue_frame(4,status);
    }
public:
    LocalReducer(const Config& config,bool frontend):config_(config),frontend_(frontend),now_(config.start_tick) {
        if(!valid_config(config_))fail(Failure::Config);else if(!frontend_)queue_frame(1);
    }
    ByteView pending_output(std::uint8_t channel)const {
        if(failure_!=Failure::None||channel>1||(error_draining_&&channel!=0))return {nullptr,0};
        return channel?http_.pending():pipe_.pending();
    }
    Snapshot snapshot()const{return {failure_,observations_,requested_,confirmed_,uncertain_};}
    void apply(const Event& event) {
        const bool healthy=clock(event.tick);
        if(event.kind==6){
            if(event.bytes.size){fail(Failure::Close);return;}
            close(event.selector,event.value,healthy);return;
        }
        if(!healthy)return;
        if(event.kind>8 || (event.kind!=1&&event.kind!=2&&event.bytes.size)
            || (event.kind!=4&&event.kind!=6&&event.selector)
            || (event.kind!=4&&event.kind!=6&&event.kind!=8&&event.value)){fail(Failure::Order);return;}
        if(error_draining_&&event.kind!=0&&event.kind!=4){fail(Failure::Order);return;}
        switch(event.kind){
        case 0:break;
        case 1:receive_frame(event.bytes);break;
        case 2:feed_http(event.bytes);break;
        case 3:finish_http();break;
        case 4:write(event.selector,event.value);break;
        case 5:pipe_eof();break;
        case 7:fail(Failure::Write);break;
        case 8:relay_failure(event.value);break;
        default:fail(Failure::Order);break;
        }
    }
};
class Frontend final:public LocalReducer {public:explicit Frontend(const Config& c):LocalReducer(c,true){}};
class Relay final:public LocalReducer {public:explicit Relay(const Config& c):LocalReducer(c,false){}};
} // namespace rpb
#endif
