// Inert production-helper fake SOURCE. Not compiled/run by the author.
#include "../.github/native/windows_identity_lpac_curl_ws2_startup_find.hpp"
#include "../.github/native/windows_identity_lpac_curl_ws2_startup_refs.hpp"
#include <array>
#include <cstdlib>
#include <iostream>
using namespace a4startup;
static u32 assertions=0;
static void check(bool value){++assertions;if(!value)std::abort();}
static void put16(std::uint8_t* p,u16 v){p[0]=static_cast<std::uint8_t>(v);p[1]=static_cast<std::uint8_t>(v>>8);}
static void put32(std::uint8_t* p,u32 v){for(u32 i=0;i<4;++i)p[i]=static_cast<std::uint8_t>(v>>(8*i));}
struct API {
 std::array<std::uint8_t,4096> bytes{};u64 tick=1200;u32 queries=0,reads=0;u32 protect=2;
 API(){Config2048 c{};std::memcpy(c.magic,"A4P1",4);c.version=1;c.size=2048;c.frequency=100;c.root_start=1000;c.root_deadline=13000;c.work_deadline=9500;c.window_start=1100;c.window_end=1900;c.target_pid=7;c.target_creation=8;c.trace_handle=9;c.trace_bytes=trace_bytes;c.capacity=256;
  c.run[0]=c.source_sha256[0]=c.config_sha256[0]=c.target_sha256[0]=c.shim_sha256[0]=c.trace_nonce[0]=1;
  const char fixture_private_path[]="C:\\private\\windows_identity_lpac_curl_ws2_shim.dll",fixture_system_ws2[]="C:\\Windows\\System32\\WS2_32.dll";
  c.private_path_bytes=sizeof(fixture_private_path)-1;std::memcpy(c.private_path,fixture_private_path,sizeof(fixture_private_path));c.system_ws2_chars=sizeof(fixture_system_ws2)-1;for(u32 i=0;i<sizeof(fixture_system_ws2);++i)c.system_ws2_path[i]=static_cast<u16>(fixture_system_ws2[i]);
  bytes[0]='M';bytes[1]='Z';put32(bytes.data()+60,64);std::memcpy(bytes.data()+64,"PE\0\0",4);put16(bytes.data()+70,1);put16(bytes.data()+84,240);put16(bytes.data()+88,0x20b);
  const char section[8]={'.','d','e','t','o','u','r',0};std::memcpy(bytes.data()+328,section,8);put32(bytes.data()+340,368);put32(bytes.data()+344,2136);
  put32(bytes.data()+368,64);put32(bytes.data()+372,0x00727444);put32(bytes.data()+376,64);put32(bytes.data()+380,2136);
  put32(bytes.data()+432,2072);std::memcpy(bytes.data()+440,payload_guid,16);std::memcpy(bytes.data()+456,&c,2048);
 }
 bool clock(u64& out){out=tick++;return true;}
 bool query(u64 address,ScanRegion& out){++queries;if(address!=0x10000||queries!=1)return false;out={0x10000,4096,0x10000,0x1000,protect};return true;}
 bool read(u64 address,void* out,u32 count){++reads;if(address<0x10000||address-0x10000>4096||count>4096-(address-0x10000))return false;std::memcpy(out,bytes.data()+address-0x10000,count);return true;}
};
static void finder_tests(){
 API good;PayloadFinder<API> finder(good,100);FindResult result{};
 check(finder.find(result));check(result.found&&result.regions==1&&good.queries==1);check(result.payload==0x10000+456&&result.framing_bytes==2504);
 check(std::memcmp(result.framing,good.bytes.data(),456)==0&&result.first_qpc>=result.config.window_start&&result.last_qpc<result.config.window_end);
 // The fake rejects any second query. Success proves production finder stops
 // at its first complete bound candidate, not a whole-space duplicate claim.
 API length;put32(length.bytes.data()+432,2071);PayloadFinder<API> wrong_length(length,100);FindResult missing{};check(!wrong_length.find(missing)&&length.queries==1);
 API zero;put32(zero.bytes.data()+432,0);PayloadFinder<API> zero_step(zero,100);check(!zero_step.find(missing)&&zero.queries==1);
 API writable;writable.protect=4;PayloadFinder<API> wrong_protect(writable,100);check(!wrong_protect.find(missing)&&writable.queries==1);
 API epoch;Config2048 c{};std::memcpy(&c,epoch.bytes.data()+456,2048);c.window_start=1250;c.window_end=2050;std::memcpy(epoch.bytes.data()+456,&c,2048);PayloadFinder<API> started_before_window(epoch,100);check(!started_before_window.find(missing));
 API reserved;reserved.bytes[456+1800]=1;PayloadFinder<API> dirty(reserved,100);check(!dirty.find(missing));
}
static void references_tests(){
 PrivateReferences refs;check(refs.returned_load(100,true,true));check(refs.returned_load(100,true,true));check(refs.outstanding()==2);
 u32 first=99,second=99;check(refs.take_release(100,first));check(!refs.returned_release(first,true,false)&&refs.uncertain());
 // Unknown first close is consumed, never retried; another actually-known
 // acquisition still has one close obligation even after global uncertainty.
 check(refs.take_release(100,second)&&second!=first);check(refs.returned_release(second,true,true));
 check(!refs.take_release(100,second));check(!refs.returned_release(first,true,true));check(refs.outstanding()==1);
 PrivateReferences null_failure;check(null_failure.returned_load(0,true,false)&&!null_failure.uncertain()&&null_failure.outstanding()==0);
 PrivateReferences mismatch;check(!mismatch.returned_load(100,true,false)&&mismatch.uncertain());
 PrivateReferences fixture_late_ref;check(fixture_late_ref.returned_load(100,true,true)&&fixture_late_ref.outstanding()==1);check(fixture_late_ref.take_release(100,first)&&fixture_late_ref.returned_release(first,true,true)&&fixture_late_ref.outstanding()==0);
}
int main(){finder_tests();references_tests();std::cout<<"A4_BOOTSTRAP_PRODUCTION_ASSERTIONS "<<assertions<<"\n";return 0;}
