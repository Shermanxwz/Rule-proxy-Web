// New finite control domain. No Windows API is called by this header.
#pragma once
#include <array>
#include <cstddef>
#include <cstdint>
#include <string>
#include <vector>
#include <utility>
namespace lpac_pipe_dns {
using Id=std::array<std::uint8_t,16>;
struct Binding {Id run{},http{},dns{};std::uint64_t frequency=0,end=0;};
struct Command {std::uint8_t operation=0;std::uint32_t sequence=0;std::uint64_t deadline=0;};
inline std::uint64_t le(const std::uint8_t* p,std::size_t n){std::uint64_t v=0;for(std::size_t i=0;i<n;++i)v|=std::uint64_t(p[i])<<(8*i);return v;}
inline bool same(const std::uint8_t* p,const Id& id){for(std::size_t i=0;i<16;++i)if(p[i]!=id[i])return false;return true;}
inline bool parse_id(const std::string& text,Id& id){
    if(text.size()!=32)return false;
    auto digit=[](char c)->int{return c>='0'&&c<='9'?c-'0':c>='a'&&c<='f'?c-'a'+10:-1;};
    for(std::size_t i=0;i<16;++i){const int a=digit(text[2*i]),b=digit(text[2*i+1]);if(a<0||b<0)return false;id[i]=static_cast<std::uint8_t>(a*16+b);}return true;
}
inline bool decode(const std::uint8_t* bytes,std::size_t size,const Binding& b,std::uint32_t next,std::uint64_t now,Command& out){
    if(!bytes||size!=128||!b.frequency||b.frequency>1000000000ULL||!b.end||now>=b.end||(next!=1&&next!=2))return false;
    if(bytes[0]!='L'||bytes[1]!='P'||bytes[2]!='D'||bytes[3]!='1'||bytes[4]!=1)return false;
    const auto op=next==1?6u:255u;if(bytes[5]!=op||le(bytes+8,4)!=next)return false;
    for(std::size_t i=0;i<128;++i)if((i==6||i==7||(i>=12&&i<16)||(i>=64&&i<72)||i>=96)&&bytes[i])return false;
    if(!same(bytes+16,b.run)||!same(bytes+32,next==1?b.dns:b.http)||!same(bytes+72,b.http)
       ||le(bytes+48,8)!=b.frequency||le(bytes+56,8)!=b.end)return false;
    const auto end=le(bytes+88,8);if(end<=now||end>b.end||(next==2&&end!=b.end))return false;
    if(next==1&&end-now>2*b.frequency)return false;
    out.operation=static_cast<std::uint8_t>(op);out.sequence=next;out.deadline=end;return true;
}
constexpr std::uint64_t MaxSigned=0x7fffffffffffffffULL;
struct Plan {std::string run,http,dns,user,package;std::uint64_t reader=0,writer=0,start=0,frequency=0,end=0;std::uint16_t port=0;Binding binding{};};
inline bool decimal(const std::wstring& text,std::uint64_t max,std::uint64_t& out){
    if(text.empty()||text.size()>20||text[0]==L'0')return false;
    out=0;
    for(auto c:text){if(c<L'0'||c>L'9')return false;const auto n=static_cast<std::uint64_t>(c-L'0');if(out>(max-n)/10)return false;out=out*10+n;}return true;
}
inline bool ascii(const std::wstring& text,std::string& out,bool is_sid=false){
    if(text.empty()||text.size()>(is_sid?255u:32u))return false;
    out.clear();
    for(auto c:text){if(c>127||c<32)return false;out+=static_cast<char>(c);}
    if(!is_sid){Id id{};return parse_id(out,id);}
    if(out.size()<5||out.substr(0,2)!="S-")return false;
    for(std::size_t i=1;i<out.size();++i){if(out[i]!='-'&&(out[i]<'0'||out[i]>'9'))return false;}
    return true;
}
inline bool arguments(const wchar_t* p,std::vector<std::wstring>& out){
    if(!p)return false;
    std::size_t total=0;
    while(*p){while(*p==L' '||*p==L'\t')++p;if(!*p)break;std::wstring value;const bool quoted=*p==L'"';if(quoted)++p;
        while(*p&&!(quoted?*p==L'"':(*p==L' '||*p==L'\t'))){if(*p<32||(!quoted&&*p==L'"'))return false;value+=*p++;if(++total>16000||value.size()>4096)return false;}
        if(quoted){if(*p!=L'"')return false;++p;if(*p&&*p!=L' '&&*p!=L'\t')return false;}if(value.empty()||out.size()>=19)return false;out.push_back(std::move(value));
    }return out.size()==19;
}
inline bool plan(const std::vector<std::wstring>& a,Plan& p){
    if(a.size()!=19||a[1]!=L"pipe-dns-front"||a[12]!=L"0")return false;
    std::uint64_t port=0;
    if(!ascii(a[2],p.run)||!ascii(a[3],p.http)||!ascii(a[14],p.dns)||p.run==p.http||p.run==p.dns||p.http==p.dns
       ||!ascii(a[10],p.user,true)||!ascii(a[11],p.package,true)||!decimal(a[5],MaxSigned,p.reader)||!decimal(a[6],MaxSigned,p.writer)||p.reader==p.writer
       ||!decimal(a[7],MaxSigned,p.start)||!decimal(a[8],1000000000ULL,p.frequency)||!decimal(a[9],MaxSigned,p.end)
       ||p.frequency>(MaxSigned-p.start)/10||p.end!=p.start+10*p.frequency||!decimal(a[13],65535,port)||port<49153)return false;
    p.port=static_cast<std::uint16_t>(port);p.binding.frequency=p.frequency;p.binding.end=p.end;
    return parse_id(p.run,p.binding.run)&&parse_id(p.http,p.binding.http)&&parse_id(p.dns,p.binding.dns);
}

// Small portable SHA-256 for original report-byte commitments, no provider/heap
// ownership crosses an API boundary. Tested against fixed published vectors.
inline std::string sha256(const std::string& input){
    constexpr std::uint32_t k[64]={0x428a2f98,0x71374491,0xb5c0fbcf,0xe9b5dba5,0x3956c25b,0x59f111f1,0x923f82a4,0xab1c5ed5,
        0xd807aa98,0x12835b01,0x243185be,0x550c7dc3,0x72be5d74,0x80deb1fe,0x9bdc06a7,0xc19bf174,0xe49b69c1,0xefbe4786,0x0fc19dc6,0x240ca1cc,
        0x2de92c6f,0x4a7484aa,0x5cb0a9dc,0x76f988da,0x983e5152,0xa831c66d,0xb00327c8,0xbf597fc7,0xc6e00bf3,0xd5a79147,0x06ca6351,0x14292967,
        0x27b70a85,0x2e1b2138,0x4d2c6dfc,0x53380d13,0x650a7354,0x766a0abb,0x81c2c92e,0x92722c85,0xa2bfe8a1,0xa81a664b,0xc24b8b70,0xc76c51a3,
        0xd192e819,0xd6990624,0xf40e3585,0x106aa070,0x19a4c116,0x1e376c08,0x2748774c,0x34b0bcb5,0x391c0cb3,0x4ed8aa4a,0x5b9cca4f,0x682e6ff3,
        0x748f82ee,0x78a5636f,0x84c87814,0x8cc70208,0x90befffa,0xa4506ceb,0xbef9a3f7,0xc67178f2};
    std::array<std::uint32_t,8> h={0x6a09e667,0xbb67ae85,0x3c6ef372,0xa54ff53a,0x510e527f,0x9b05688c,0x1f83d9ab,0x5be0cd19};
    auto rotr=[](std::uint32_t x,unsigned n){return (x>>n)|(x<<(32-n));};
    std::vector<std::uint8_t> data(input.begin(),input.end());const auto bits=std::uint64_t(data.size())*8;data.push_back(128);
    while(data.size()%64!=56){data.push_back(0);}
    for(int i=7;i>=0;--i)data.push_back(static_cast<std::uint8_t>(bits>>(8*i)));
    for(std::size_t at=0;at<data.size();at+=64){std::uint32_t w[64]{};
        for(unsigned i=0;i<16;++i)for(unsigned j=0;j<4;++j)w[i]=(w[i]<<8)|data[at+4*i+j];
        for(unsigned i=16;i<64;++i){const auto a=rotr(w[i-15],7)^rotr(w[i-15],18)^(w[i-15]>>3),b=rotr(w[i-2],17)^rotr(w[i-2],19)^(w[i-2]>>10);w[i]=w[i-16]+a+w[i-7]+b;}
        auto a=h[0],b=h[1],c=h[2],d=h[3],e=h[4],f=h[5],g=h[6],z=h[7];
        for(unsigned i=0;i<64;++i){const auto s1=rotr(e,6)^rotr(e,11)^rotr(e,25),ch=(e&f)^(~e&g),t1=z+s1+ch+k[i]+w[i];
            const auto s0=rotr(a,2)^rotr(a,13)^rotr(a,22),maj=(a&b)^(a&c)^(b&c),t2=s0+maj;z=g;g=f;f=e;e=d+t1;d=c;c=b;b=a;a=t1+t2;}
        h[0]+=a;h[1]+=b;h[2]+=c;h[3]+=d;h[4]+=e;h[5]+=f;h[6]+=g;h[7]+=z;
    }
    constexpr char digits[]="0123456789abcdef";std::string out;out.reserve(64);
    for(auto value:h){for(int shift=28;shift>=0;shift-=4)out+=digits[(value>>shift)&15];}
    return out;
}
} // namespace lpac_pipe_dns
