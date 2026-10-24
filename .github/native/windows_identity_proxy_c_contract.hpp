// Portable C command admission only: no OS, clock, socket or security mutation.
#pragma once
#include <array>
#include <cstdint>
#include <cstddef>
#include <string>
namespace rpc {
using Id=std::array<std::uint8_t,16>;
struct Binding {Id run{},admission{};std::uint64_t frequency=0,deadline=0;std::uint16_t p=0,q=0,o=0;};
struct Command {std::uint8_t operation=0;std::uint32_t sequence=0;Id item{};std::uint64_t phase_deadline=0;};
inline std::uint64_t le(const std::uint8_t* p,std::size_t count){std::uint64_t n=0;for(std::size_t i=0;i<count;++i)n|=std::uint64_t(p[i])<<(8*i);return n;}
inline bool same(const std::uint8_t* p,const Id& id){for(std::size_t i=0;i<16;++i)if(p[i]!=id[i])return false;return true;}
inline bool high(std::uint16_t n){return n>=49153;}
inline bool valid_binding(const Binding& b,bool fixture=false){
    if(!b.frequency||b.frequency>1000000000ULL||!b.deadline)return false;
    return fixture?b.p==0&&b.q==0&&b.o==0:high(b.p)&&high(b.q)&&high(b.o)&&b.p!=b.q&&b.p!=b.o&&b.q!=b.o;
}
inline bool decode(const std::uint8_t* bytes,std::size_t count,const Binding& binding,std::uint32_t next,
                   std::uint64_t now,Command& command,bool fixture=false){
    if(!bytes||count!=128||!valid_binding(binding,fixture)||!next||next>16||now>=binding.deadline)return false;
    if(bytes[0]!='R'||bytes[1]!='P'||bytes[2]!='C'||bytes[3]!='1'||bytes[4]!=1)return false;
    const auto op=bytes[5];if((fixture?op!=255:!(op>=1&&op<=7)&&op!=255)||le(bytes+8,4)!=next)return false;
    for(std::size_t i=0;i<128;++i)if((i==6||i==7||(i>=12&&i<16)||(i>=70&&i<72)||i>=96)&&bytes[i])return false;
    if(!same(bytes+16,binding.run)||le(bytes+48,8)!=binding.frequency||le(bytes+56,8)!=binding.deadline
       ||le(bytes+64,2)!=binding.p||le(bytes+66,2)!=binding.q||le(bytes+68,2)!=binding.o||!same(bytes+72,binding.admission))return false;
    const auto end=le(bytes+88,8);if(end<=now||end>binding.deadline)return false;
    command.operation=op;command.sequence=next;command.phase_deadline=end;
    for(std::size_t i=0;i<16;++i)command.item[i]=bytes[32+i];
    return !fixture||(command.item==binding.admission&&end==binding.deadline&&next==1);
}
// Separate immutable release authority. Neither normal GO nor fixture Finish
// accepts this opcode; every byte retains the existing closed 128-byte layout.
inline bool decode_release(const std::uint8_t* bytes,std::size_t count,const Binding& binding,
                           std::uint64_t now,Command& command){
    if(!bytes||count!=128||bytes[5]!=254)return false;
    std::array<std::uint8_t,128> normalized{};
    for(std::size_t i=0;i<normalized.size();++i)normalized[i]=bytes[i];
    normalized[5]=255;
    if(!decode(normalized.data(),normalized.size(),binding,1,now,command,true))return false;
    command.operation=254;return true;
}
struct WithholdGate {
    bool held=false,released=false,closed=false;
    bool begin(const Binding& binding,const Id& item,bool exact,bool eof,std::uint32_t response_bytes,std::uint64_t now){
        if(held||released||closed||!valid_binding(binding,true)||item!=binding.admission||!exact||!eof||response_bytes||now>=binding.deadline)return false;
        held=true;return true;
    }
    bool release(const Binding& binding,const Command& command,std::uint64_t now){
        if(!held||released||closed||command.operation!=254||command.sequence!=1||command.item!=binding.admission
           ||command.phase_deadline!=binding.deadline||now>=binding.deadline)return false;
        released=true;return true;
    }
    bool consume_close(bool confirmed){
        if(!held||!released||closed)return false;
        held=false;closed=true;return confirmed;
    }
};
inline const char* operation_name(std::uint8_t op){switch(op){case 1:return "proxy-get";case 2:return "direct-tcp";
    case 3:return "wrong-port";case 4:return "wrong-peer";case 5:return "proxy-after-death";case 6:return "dns-query";case 7:return "dns-raw-udp";case 255:return "finish";default:return "invalid";}}
inline std::uint16_t target(const Binding& b,std::uint8_t op){return (op==6||op==7)?53:op==2?b.o:op==3?b.q:b.p;}
inline std::string hex(const Id& id){static const char digits[]="0123456789abcdef";std::string out;
    for(auto b:id){out.push_back(digits[b>>4]);out.push_back(digits[b&15]);}return out;}
} // namespace rpc
