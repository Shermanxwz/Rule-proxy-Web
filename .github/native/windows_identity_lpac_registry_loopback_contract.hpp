// Fixed trusted-actor loopback mechanism. No socket, token or Windows calls.
#pragma once
#include <array>
#include <cstddef>
#include <cstdint>
#include <limits>
#include <string>
namespace rlp {
using Id=std::array<std::uint8_t,16>;
using Packet=std::array<std::uint8_t,64>;
using Command=std::array<std::uint8_t,128>;
enum class Role:std::uint32_t {Front=1,Selected=2,OrdinaryListener=3,OrdinaryClient=4};
// Fixed OS named-capability catalog value, independently derived by the
// external owner. Research receipt SHA256 485b023e693ac77a7e8f5ba759ba378633fb61f16934722f8bdc8dbd2535adca.
// Chromium's uppercase UTF-16LE SHA256 algorithm agrees with the local OS
// derivation; the native actor never adapts this constant to an observed token.
constexpr std::array<std::uint8_t,48> RegistryReadSid{1,10,0,0,0,0,0,15,3,0,0,0,0,4,0,0,176,49,128,63,108,188,99,76,60,224,80,209,151,12,161,98,15,1,203,25,126,122,166,192,250,230,151,241,25,163,12,206};
inline bool registry_sid_extent(std::uintptr_t begin,std::size_t returned,std::uintptr_t sid){
 return begin!=0&&sid>=begin&&sid-begin<=returned&&RegistryReadSid.size()<=returned-(sid-begin);
}
inline bool admitted_capabilities(Role role,std::uint32_t count,const std::uint8_t* sid,
 std::size_t bytes,std::uint32_t attributes){
 if(role!=Role::Selected)return (role==Role::Front||role==Role::OrdinaryListener||role==Role::OrdinaryClient)&&count==0;
 if(count!=1||sid==nullptr||bytes!=RegistryReadSid.size()||attributes!=4)return false;
 for(std::size_t i=0;i<RegistryReadSid.size();++i)if(sid[i]!=RegistryReadSid[i])return false;
 return true;
}
inline bool listener(Role r){return r==Role::Front||r==Role::OrdinaryListener;}
inline bool ordinary(Role r){return r==Role::OrdinaryListener||r==Role::OrdinaryClient;}
inline const char* name(Role r){switch(r){case Role::Front:return "front-listener";
 case Role::Selected:return "selected-client";case Role::OrdinaryListener:return "ordinary-listener";
 case Role::OrdinaryClient:return "ordinary-client";}return "invalid";}
inline int digit(char c){return c>='0'&&c<='9'?c-'0':c>='a'&&c<='f'?c-'a'+10:-1;}
inline bool id(const std::string& s,Id& out){if(s.size()!=32)return false;
 for(std::size_t i=0;i<16;++i){const auto a=digit(s[2*i]),b=digit(s[2*i+1]);
  if(a<0||b<0)return false;out[i]=static_cast<std::uint8_t>((a<<4)|b);}return true;}
inline std::string hex(const Id& v){constexpr char x[]="0123456789abcdef";std::string r;
 for(auto b:v){r+=x[b>>4];r+=x[b&15];}return r;}
inline std::uint64_t get(const std::uint8_t* b,std::size_t n){std::uint64_t v=0;
 for(std::size_t i=0;i<n;++i)v|=std::uint64_t(b[i])<<(8*i);return v;}
inline void put(std::uint8_t* b,std::uint64_t v,std::size_t n){
 for(std::size_t i=0;i<n;++i)b[i]=static_cast<std::uint8_t>(v>>(8*i));}
inline bool zero(const std::uint8_t* b,std::size_t n){for(std::size_t i=0;i<n;++i)if(b[i])return false;return true;}
struct Plan {Role role=Role::Front;Id run{},boot{},before{},selected{},after{};
 std::uint64_t frequency=0,start=0,deadline=0;std::uint16_t frontend=0,origin=0;};
inline bool valid(const Plan& p){if(p.frequency==0||p.frequency>std::numeric_limits<std::uint64_t>::max()/120
 ||p.start==0||p.deadline<=p.start||p.deadline-p.start>120*p.frequency
 ||p.deadline-p.start<=40*p.frequency||p.frontend<49153||p.origin<49153||p.frontend==p.origin)return false;
 if(static_cast<unsigned>(p.role)<1||static_cast<unsigned>(p.role)>4)return false;
 const std::array<Id,5> ids{p.run,p.boot,p.before,p.selected,p.after};
 for(std::size_t i=0;i<ids.size();++i)for(std::size_t j=i+1;j<ids.size();++j)if(ids[i]==ids[j])return false;
 return true;}
inline const Id& item(const Plan& p,std::uint32_t seq){return ordinary(p.role)?(seq==1?p.before:p.after):p.selected;}
inline Packet packet(const Plan& p,const Id& c,bool response){Packet b{};
 b[0]='R';b[1]='L';b[2]='P';b[3]='1';put(b.data()+4,1,2);put(b.data()+6,response?2:1,2);
 for(std::size_t i=0;i<16;++i){b[8+i]=c[i];b[24+i]=p.run[i];}return b;}
inline bool matches(const std::uint8_t* b,std::size_t n,const Plan& p,const Id& c,bool response){
 if(n!=64||b==nullptr)return false;const auto expected=packet(p,c,response);
 for(std::size_t i=0;i<64;++i)if(b[i]!=expected[i])return false;return true;}
struct Ticket {std::uint32_t sequence=0;std::uint64_t issued=0,deadline=0;Id case_id{};};
inline bool command(const Command& b,const Plan& p,std::uint32_t seq,std::uint64_t now,Ticket& out,
 const Ticket* release=nullptr){
 if(!valid(p)||now<p.start||now>=p.deadline||seq<1||seq>(ordinary(p.role)?2u:1u))return false;
 if(b[0]!='R'||b[1]!='C'||b[2]!='L'||b[3]!='1'||get(b.data()+4,2)!=1
 ||get(b.data()+6,2)!=(release?2u:1u)||get(b.data()+8,4)!=seq
 ||get(b.data()+12,4)!=static_cast<std::uint32_t>(p.role))return false;
 for(std::size_t i=0;i<16;++i)if(b[16+i]!=p.run[i]||b[32+i]!=p.boot[i]||b[48+i]!=item(p,seq)[i])return false;
 const auto d=get(b.data()+80,8),issued=get(b.data()+96,8);
 if(get(b.data()+64,8)!=p.frequency||get(b.data()+72,8)!=p.deadline
 ||get(b.data()+88,2)!=p.frontend||get(b.data()+90,2)!=p.origin
 ||!zero(b.data()+92,4)||!zero(b.data()+104,24)||issued<p.start||issued>now||now>=d
 ||d>p.deadline-35*p.frequency||d<=issued||d-issued>8*p.frequency)return false;
 if(release&&(p.role!=Role::Front||seq!=1||d!=release->deadline||issued<release->issued
 ||release->case_id!=p.selected||release->sequence!=1))return false;
 out=Ticket{seq,issued,d,item(p,seq)};return true;
}
// TOKEN_GROUPS can legitimately return just a DWORD when count is zero. Do not
// read Groups[0] or demand its x64 offset until the count is known nonzero.
inline bool capabilities_extent(std::size_t bytes,std::uint32_t count,std::size_t offset,
 std::size_t entry){if(bytes<4||count>64)return false;if(count==0)return true;
 return entry!=0&&offset>=4&&offset<=bytes&&count<=(bytes-offset)/entry;}
} // namespace rlp
