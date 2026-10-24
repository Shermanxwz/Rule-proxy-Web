// Pure single-connection fixed-curl byte adapter. Not a Winsock implementation.
// No Windows includes, host socket, handles, clock queries or owner authority.
#pragma once
#include "windows_identity_lpac_stream_contract.hpp"
#include <limits>
#include <utility>

namespace lpac_curl_http {
constexpr bool PureImplementationAuthorized=true, ActualReady=false, ActualCurlQualified=false, LinuxEquivalent=false;
constexpr std::uint64_t VirtualSocket=0x525053314355524cULL;
constexpr std::size_t HeaderLimit=4096;
enum class State {okay,pending,eof,failed};
enum class Error : int {none=0,invalid=10022,would_block=10035,unsupported=10045,
                        not_connected=10057,reset=10054,timeout=10060};
struct Result {State state=State::failed;std::size_t bytes=0;Error error=Error::invalid;};
struct Endpoint {std::array<std::uint8_t,4> address{};std::uint16_t port=0;};
struct Config {
    lpac_stream::Config stream;
    Endpoint target;
    std::uint64_t frequency=0,start=0,end=0;
    // Independently frozen by the future owner, never learned from selected.
    // The fixed curl ordinary HTTP/CLI calibration is not implemented here.
    std::string target_path,request_header,response_header;
    std::uint32_t request_body=0,response_body=0;
};
struct Ready {bool connected=false,readable=false,writable=false,exceptional=false,close_ready=false;};

inline std::string lower(std::string s){
    for(char& c:s)if(c>='A'&&c<='Z')c=static_cast<char>(c-'A'+'a');
    return s;
}
inline std::string id(const std::array<std::uint8_t,16>& bytes){
    const char* digits="0123456789abcdef";std::string value;
    for(auto b:bytes){value+=digits[b>>4];value+=digits[b&15];}
    return value;
}
inline bool bounded_decimal(const std::string& text,std::uint32_t& value){
    if(text.empty()||text.size()>5)return false;
    value=0;
    for(char c:text){if(c<'0'||c>'9')return false;value=value*10+static_cast<unsigned>(c-'0');}
    return value<=lpac_stream::Total;
}
inline bool header_shape(const Config& c,bool response){
    const auto& h=response?c.response_header:c.request_header;
    const auto body=response?c.response_body:c.request_body;
    if(h.empty()||h.size()>HeaderLimit||h.size()<4||h.substr(h.size()-4)!="\r\n\r\n"
       ||h.find("\r\n\r\n")!=h.size()-4)return false;
    const auto first=h.find("\r\n");if(first==std::string::npos)return false;
    const std::string expected=response?"HTTP/1.1 200 OK":"POST "+c.target_path+" HTTP/1.1";
    if(h.substr(0,first)!=expected)return false;
    bool length=false,connection=false,host=false;std::vector<std::string> names;
    std::size_t at=first+2;
    while(at<h.size()-2){
        const auto end=h.find("\r\n",at);if(end==std::string::npos||end==at)return false;
        const auto line=h.substr(at,end-at);const auto colon=line.find(": ");
        if(colon==std::string::npos||!colon)return false;
        auto name=lower(line.substr(0,colon));const auto value=line.substr(colon+2);
        if(value.empty()||std::find(names.begin(),names.end(),name)!=names.end())return false;
        for(char ch:name)if(!((ch>='a'&&ch<='z')||ch=='-'))return false;
        for(unsigned char ch:value)if(ch<32||ch>126)return false;
        names.push_back(name);
        if(name=="content-length"){
            std::uint32_t n=0;if(!bounded_decimal(value,n)||n!=body)return false;length=true;
        }else if(name=="connection"){
            if(lower(value)!="close")return false;
            connection=true;
        }else if(name=="host"){
            if(response||value!="127.0.0.1:"+std::to_string(c.target.port))return false;
            host=true;
        }else if(name=="x-ruleproxy-case"){
            if(value!=id(c.stream.case_id))return false;
        }else if(name=="user-agent"||name=="accept"||name=="content-type"){
            if(response)return false;
        }else return false; // No TE, upgrade, auth, redirects or implicit DNS.
        at=end+2;
    }
    return at==h.size()-2&&length&&connection&&(response||host);
}

class SocketCore {
    Config c_;lpac_stream::Node node_;lpac_stream::Bytes pending_;
    std::uint64_t last_=0;std::uint32_t accepted_=0,delivered_=0;
    bool created_=false,connect_started_=false,source_fin_=false,inbound_fin_=false,closing_=false;
    const char* failure_=nullptr;Error error_=Error::none;
    Result fail(const char* text,Error error=Error::unsupported){
        if(!failure_){failure_=text;error_=error;node_.fail(text);}
        return {State::failed,0,error_};
    }
    bool tick(std::uint64_t now){
        if(failure_)return false;
        if(now<last_||now<c_.start){fail("clock",Error::timeout);return false;}
        last_=now;
        if(now>=c_.end){fail("deadline",Error::timeout);return false;}
        if(node_.failure()){fail(node_.failure(),Error::reset);return false;}
        return true;
    }
    bool socket(std::uint64_t value){
        if(value!=VirtualSocket||!created_||closing_){fail("virtual_socket",Error::invalid);return false;}
        return true;
    }
    bool prefix(const std::uint8_t* bytes,std::size_t count,std::uint32_t offset,const std::string& header){
        for(std::size_t i=0;i<count&&offset+i<header.size();++i)
            if(bytes[i]!=static_cast<std::uint8_t>(header[offset+i]))return false;
        return true;
    }
    void advance(){
        if(failure_)return;
        if(node_.failure()){fail(node_.failure(),Error::reset);return;}
        if(node_.opened()&&pending_.size){
            const auto count=std::min(pending_.size,node_.source_room());
            if(count){if(!node_.source(pending_.value.data(),count)){fail(node_.failure(),Error::reset);return;}pending_.consume(count);}
        }
        if(accepted_==c_.stream.send&&!pending_.size&&!source_fin_){node_.source_eof();source_fin_=true;}
        if(node_.needs_finish()){node_.finished();inbound_fin_=true;}
        if(node_.failure())fail(node_.failure(),Error::reset);
    }
public:
    explicit SocketCore(Config c):c_(std::move(c)),node_(c_.stream),last_(c_.start){
        const auto max=static_cast<std::uint64_t>((std::numeric_limits<std::int64_t>::max)());
        const auto path_good=!c_.target_path.empty()&&c_.target_path.size()<=256&&c_.target_path[0]=='/'
            &&std::all_of(c_.target_path.begin(),c_.target_path.end(),[](unsigned char b){return b>=33&&b<=126&&b!='#';});
        const auto nonzero=[](const auto& b){return std::any_of(b.begin(),b.end(),[](std::uint8_t n){return n!=0;});};
        if(!c_.stream.front||!nonzero(c_.stream.run)||!nonzero(c_.stream.case_id)||c_.stream.run==c_.stream.case_id
           ||c_.target.address!=std::array<std::uint8_t,4>{127,0,0,1}||c_.target.port<49153
           ||!c_.frequency||c_.frequency>max/8||!c_.start||c_.end>max||c_.end<=c_.start||c_.end-c_.start>8*c_.frequency
           ||!path_good||!header_shape(c_,false)||!header_shape(c_,true)
           ||c_.request_header.size()+c_.request_body!=c_.stream.send
           ||c_.response_header.size()+c_.response_body!=c_.stream.receive||node_.failure())fail("configuration",Error::invalid);
    }
    const char* failure()const{return failure_;}
    std::uint32_t request_accepted()const{return accepted_;}
    std::uint32_t response_delivered()const{return delivered_;}
    std::uint64_t original_deadline()const{return c_.end;}
    bool transport_complete()const{return !failure_&&node_.complete();}
    bool close_ready()const{return closing_&&transport_complete();}
    const lpac_stream::Node& protocol()const{return node_;}
    Result create(int family,int type,int protocol,std::uint64_t now){
        if(!tick(now))return {State::failed,0,error_};
        if(created_||family!=2||type!=1||protocol!=6)return fail("socket_signature");
        created_=true;return {State::okay,0,Error::none};
    }
    Result begin_connect(std::uint64_t value,Endpoint target,std::uint64_t now){
        if(!tick(now)||!socket(value))return {State::failed,0,error_};
        if(connect_started_||target.address!=c_.target.address||target.port!=c_.target.port)return fail("connect_target");
        connect_started_=true;return {State::pending,0,Error::would_block};
    }
    Ready readiness(std::uint64_t now){
        if(!tick(now))return {false,false,false,true,false};
        advance();const bool connected=connect_started_&&node_.opened()&&!failure_;
        return {connected,connected&&(node_.sink_size()!=0||inbound_fin_),
            connected&&!closing_&&accepted_<c_.stream.send&&pending_.size<lpac_stream::Window,
            failure_!=nullptr,close_ready()};
    }
    Result send(std::uint64_t value,const std::uint8_t* data,std::size_t size,int flags,std::uint64_t now){
        if(!tick(now)||!socket(value))return {State::failed,0,error_};
        if(!connect_started_||!node_.opened())return fail("send_before_connected",Error::not_connected);
        if(flags||!data||!size||size>c_.stream.send-accepted_)return fail("send_signature");
        advance();if(failure_)return {State::failed,0,error_};
        const auto count=std::min(size,lpac_stream::Window-pending_.size);
        if(!count)return {State::pending,0,Error::would_block};
        if(!prefix(data,count,accepted_,c_.request_header))return fail("request_header");
        if(!pending_.append(data,count))return fail("request_buffer",Error::invalid);
        accepted_+=static_cast<std::uint32_t>(count);advance();
        return failure_?Result{State::failed,count,error_}:Result{State::okay,count,Error::none};
    }
    Result recv(std::uint64_t value,std::uint8_t* data,std::size_t capacity,int flags,std::uint64_t now){
        if(!tick(now)||!socket(value))return {State::failed,0,error_};
        if(!connect_started_||!node_.opened())return fail("recv_before_connected",Error::not_connected);
        if(flags||!data||!capacity)return fail("recv_signature");
        advance();if(failure_)return {State::failed,0,error_};
        const auto count=std::min(capacity,node_.sink_size());
        if(!count)return inbound_fin_?Result{State::eof,0,Error::none}:Result{State::pending,0,Error::would_block};
        if(!prefix(node_.sink_data(),count,delivered_,c_.response_header))return fail("response_header");
        std::memcpy(data,node_.sink_data(),count);node_.sink_used(count);delivered_+=static_cast<std::uint32_t>(count);advance();
        return failure_?Result{State::failed,count,error_}:Result{State::okay,count,Error::none};
    }
    Result close_request(std::uint64_t value,std::uint64_t now){
        if(!tick(now)||!socket(value))return {State::failed,0,error_};
        closing_=true;
        if(accepted_!=c_.stream.send||delivered_!=c_.stream.receive||pending_.size)return fail("early_application_close");
        advance();return close_ready()?Result{State::okay,0,Error::none}:Result{State::pending,0,Error::would_block};
    }
    Result unsupported(std::uint32_t operation,std::uint64_t now){
        (void)operation;if(!tick(now))return {State::failed,0,error_};return fail("unsupported_API");
    }
    // The future OS adapter supplies only physically returned pipe bytes/counts.
    // These callbacks never assert held identity, permission, or known cleanup.
    const std::uint8_t* pipe_output(std::uint64_t now){
        if(!tick(now)||!connect_started_)return nullptr;
        advance();return failure_?nullptr:node_.output();
    }
    std::size_t pipe_output_size()const{return node_.output_size();}
    bool pipe_written(std::size_t count,std::uint64_t now){
        if(!tick(now)||!connect_started_)return false;
        if(!count||count>node_.output_size()){fail("pipe_write_count",Error::invalid);return false;}
        node_.written(count);advance();return !failure_;
    }
    bool pipe_feed(const std::uint8_t* data,std::size_t count,std::uint64_t now){
        if(!tick(now))return false;
        if(!connect_started_||!data||!count||count>lpac_stream::Payload){fail("pipe_read_signature",Error::invalid);return false;}
        if(!node_.feed(data,count)){fail(node_.failure(),Error::reset);return false;}advance();return !failure_;
    }
    bool pipe_writer_can_close(std::uint64_t now){if(!tick(now))return false;advance();return !failure_&&node_.can_close();}
    bool pipe_writer_closed(std::uint64_t now){
        if(!tick(now))return false;
        node_.writer_closed();if(node_.failure())fail(node_.failure(),Error::reset);return !failure_;
    }
    bool pipe_peer_eof(std::uint64_t now){
        if(!tick(now))return false;
        node_.peer_eof();if(node_.failure())fail(node_.failure(),Error::reset);return !failure_;
    }
};
} // namespace lpac_curl_http
