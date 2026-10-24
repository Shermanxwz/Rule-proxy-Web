#pragma once
// New bounded readonly parser for the fixed Detours payload framing. It never
// calls vendor DetourFindPayloadEx, enumerates via loader lists, loads a DLL,
// changes protection, allocates, waits or performs a network operation.
// API supplies query/read/QPC. Concrete Win32 glue is a separately reviewed
// layer; raw per-region query history is not claimed to be persisted here.
#include "windows_identity_lpac_curl_ws2_startup_core.hpp"
#include <limits>
namespace a4startup {
struct ScanRegion {u64 base,bytes,allocation;u32 state,protect;};
struct FindResult {Config2048 config;u64 allocation,payload,framing_bytes,first_qpc,last_qpc;u32 regions,candidates,records;bool found;std::uint8_t framing[456];};
inline u16 scan16(const std::uint8_t* p){return static_cast<u16>(p[0]|static_cast<u16>(p[1])<<8);}
inline u32 scan32(const std::uint8_t* p){return static_cast<u32>(p[0])|static_cast<u32>(p[1])<<8|static_cast<u32>(p[2])<<16|static_cast<u32>(p[3])<<24;}
inline bool any(const void* p,u32 bytes){const auto* b=static_cast<const std::uint8_t*>(p);for(u32 i=0;i<bytes;++i)if(b[i])return true;return false;}
inline bool config_path(const Config2048& c){
 if(c.private_path_bytes<4||c.private_path_bytes>=1024||c.private_path[c.private_path_bytes]||c.private_path[1]!=':'||c.private_path[2]!='\\')return false;
 const auto drive=c.private_path[0];if(!((drive>='A'&&drive<='Z')||(drive>='a'&&drive<='z')))return false;
 u32 segment=3,last=3;
 for(u32 i=3;i<c.private_path_bytes;++i){const unsigned char ch=static_cast<unsigned char>(c.private_path[i]);
  if(ch<32||ch>126||ch=='/'||ch==':'||ch=='?'||ch=='*'||ch=='"'||ch=='<'||ch=='>'||ch=='|')return false;
  if(ch=='\\'){if(i==segment||c.private_path[i-1]=='.'||c.private_path[i-1]==' ')return false;
   if((i-segment==1&&c.private_path[segment]=='.')||(i-segment==2&&c.private_path[segment]=='.'&&c.private_path[segment+1]=='.'))return false;segment=last=i+1;}}
 const char expected[]="windows_identity_lpac_curl_ws2_shim.dll";
 return c.private_path_bytes-last==sizeof(expected)-1&&std::memcmp(c.private_path+last,expected,sizeof(expected)-1)==0
  &&!any(c.private_path+c.private_path_bytes+1,1023-c.private_path_bytes);
}
inline bool config_shape(const Config2048& c,u64 frequency,u64 now){
 const u64 max=static_cast<u64>(std::numeric_limits<std::int64_t>::max());
 if(std::memcmp(c.magic,"A4P1",4)||c.version!=1||c.size!=2048||!frequency||c.frequency!=frequency||frequency>max/120
  ||c.root_start>max-120*frequency||c.root_deadline!=c.root_start+120*frequency||c.work_deadline!=c.root_start+85*frequency
  ||c.window_start<c.root_start||c.window_start>max-8*frequency||!c.target_pid||!c.target_creation||c.reserved0
  ||!c.trace_handle||c.trace_handle==~u64{0}||c.trace_bytes!=trace_bytes||c.capacity!=trace_capacity)return false;
 const u64 normal=c.window_start+8*frequency,end=normal<c.work_deadline?normal:c.work_deadline;
 if(c.window_end!=end||c.window_start>=end||now<c.window_start||now>=end||any(c.reserved,sizeof(c.reserved)))return false;
 if(!any(c.run,16)||!any(c.source_sha256,32)||!any(c.config_sha256,32)||!any(c.target_sha256,32)||!any(c.shim_sha256,32)||!any(c.trace_nonce,16)||!config_path(c))return false;
 if(c.system_ws2_chars<4||c.system_ws2_chars>=260||c.system_ws2_path[c.system_ws2_chars]||c.system_ws2_path[1]!=':'||c.system_ws2_path[2]!='\\')return false;
 const char basename[]="WS2_32.dll";u32 begin=0;
 for(u32 i=0;i<c.system_ws2_chars;++i){const u16 ch=c.system_ws2_path[i];if(ch<32||ch>126||ch=='/'||(ch==':'&&i!=1))return false;if(ch=='\\')begin=i+1;}
 return ascii_equal(c.system_ws2_path+begin,c.system_ws2_chars-begin,basename)&&!any(c.system_ws2_path+c.system_ws2_chars+1,(259-c.system_ws2_chars)*2);
}
template<class API>class PayloadFinder {
 API& api_;u64 frequency_,last_=0,local_end_=0;FindResult result_{};
 bool clock(){u64 q=0;if(!api_.clock(q)||q<last_||q>=local_end_)return false;last_=q;return true;}
 bool read(u64 address,void* out,u32 bytes){return clock()&&api_.read(address,out,bytes)&&clock();}
 bool within(const ScanRegion& r,u64 offset,u64 bytes){return offset<=r.bytes&&bytes<=r.bytes-offset&&r.base<=~u64{0}-offset;}
 bool candidate(const ScanRegion& r){
  std::uint8_t dos[64]{};if(!within(r,0,64)||!read(r.base,dos,64))return false;
  if(dos[0]!='M'||dos[1]!='Z')return true;
  if(++result_.candidates>256)return false;
  const u32 nt=scan32(dos+60);if(nt<64||nt>4096-264||!within(r,nt,264))return true;
  std::uint8_t header[264]{};if(!read(r.base+nt,header,264))return false;
  if(std::memcmp(header,"PE\0\0",4)||scan16(header+20)!=240||scan16(header+24)!=0x20b)return true;
  const u32 sections=scan16(header+6);if(sections<1||sections>32)return true;
  for(u32 i=0;i<sections;++i){const u64 at=static_cast<u64>(nt)+264+40*i;
   if(!within(r,at,40))return false;std::uint8_t section[40]{};if(!read(r.base+at,section,40))return false;
   const char name[8]={'.','d','e','t','o','u','r',0};if(std::memcmp(section,name,8))continue;
   const u32 offset=scan32(section+12),extent=scan32(section+16);
   if(extent<64||extent>4096||!within(r,offset,extent))return false;
   std::uint8_t dsh[64]{};if(!read(r.base+offset,dsh,64))return false;
   const u32 head=scan32(dsh),signature=scan32(dsh+4),data=scan32(dsh+8),bytes=scan32(dsh+12);
   if(head!=64||signature!=0x00727444||data<head||data>bytes||bytes>extent||any(dsh+16,48))return false;
   u32 cursor=data;
   while(cursor<bytes){if(++result_.records>64||bytes-cursor<24)return false;std::uint8_t record[24]{};
    if(!read(r.base+offset+cursor,record,24))return false;const u32 step=scan32(record);
    if(step<24||step>bytes-cursor||scan32(record+4)!=0)return false;
    if(std::memcmp(record+8,payload_guid,16)==0){
     if(step!=24+2048||r.allocation!=r.base||r.protect!=2)return false;
     // The parent uses the fixed source-bound DetourCopyPayloadToProcessEx
     // framing: DOS64+NT264+section40+DSH64+record24, then Config2048.
     // First matching GUID malformed => stop, never search for a replacement.
     if(nt!=64||sections!=1||offset!=368||extent!=2136||data!=64||cursor!=64||bytes!=2136)return false;
     Config2048 cfg{};const u64 payload=r.base+offset+cursor+24;
     if(!read(payload,&cfg,2048)||!config_shape(cfg,frequency_,last_))return false;
     if(!read(r.base,result_.framing,456))return false;
     result_.config=cfg;result_.allocation=r.base;result_.payload=payload;result_.framing_bytes=offset+bytes;result_.found=true;
     return true;
    }
    cursor+=step;
   }
  }
  return true;
 }
public:
 PayloadFinder(API& api,u64 frequency):api_(api),frequency_(frequency){}
 bool find(FindResult& out){
  // Local work cap is not an authorization window. The authoritative original
  // epoch is accepted only after Config is found/validated; root watchdog is
  // still the external bound before that. No API is internally cancellable.
  u64 q=0;if(!frequency_||!api_.clock(q)||q>~u64{0}-frequency_)return false;last_=q;result_.first_qpc=q;local_end_=q+frequency_;
  u64 address=0x10000;constexpr u64 maximum=(1ull<<47);
  while(address<maximum){if(++result_.regions>4096||!clock())return false;ScanRegion r{};
   if(!api_.query(address,r)||!clock()||r.base>address||!r.bytes||r.bytes>maximum||r.base>maximum-r.bytes)return false;
   const u64 next=r.base+r.bytes;if(next<=address)return false;
   const u32 base=r.protect&255u;const bool readable=(base==2||base==4||base==8||base==0x20||base==0x40||base==0x80)&&!(r.protect&0x100);
   if(r.state==0x1000&&readable&&!candidate(r)){result_.last_qpc=last_;out=result_;return false;}
   if(result_.found){
    const bool okay=clock()&&config_shape(result_.config,frequency_,result_.first_qpc)&&config_shape(result_.config,frequency_,last_);
    result_.last_qpc=last_;out=result_;return okay;
   }
   address=next;
  }
  result_.last_qpc=last_;out=result_;return false;
 }
};
}
