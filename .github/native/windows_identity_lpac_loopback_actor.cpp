// Trusted fixed actors: zero-cap same-SID loopback mechanism, never a proxy or
// adversarial same-SID boundary. The external held owner is identity authority.
#define WIN32_LEAN_AND_MEAN
#define NOMINMAX
#include <winsock2.h>
#include <windows.h>
#include <ws2tcpip.h>
#include "windows_identity_lpac_loopback_contract.hpp"
#include <algorithm>
#include <cstring>
#include <sstream>
#include <string>
#include <vector>

namespace {
using zlp::Id;using zlp::Role;using zlp::Ticket;
struct Issue {const char* failure=nullptr;DWORD wsa=0,win=0;bool has_wsa=false,has_win=false;
 void fail(const char* value){if(!failure)failure=value;}
 void winsock(const char* value,int error){if(!failure){failure=value;wsa=static_cast<DWORD>(error);has_wsa=true;}}
 void windows(const char* value,DWORD error){if(!failure){failure=value;win=error;has_win=true;}}
};
inline const char* boolean(bool x){return x?"true":"false";}
inline std::string quoted(const char* x){return x?std::string("\"")+x+"\"":"null";}
inline std::string optional(DWORD x,bool present){return present?std::to_string(x):"null";}
inline std::string port_json(std::uint16_t x){return x?std::to_string(x):"null";}
inline std::wstring numbered(const wchar_t* prefix,unsigned n,const wchar_t* extension){
 return std::wstring(prefix)+(n<10?L"0":L"")+std::to_wstring(n)+extension;}
inline std::wstring parent(const std::wstring& p){return p.substr(0,p.find_last_of(L"\\/"));}
inline bool absolute(const std::wstring& p){if(p.size()<4||p.size()>1024||p[1]!=L':'||p[2]!=L'\\'
 ||!((p[0]>=L'A'&&p[0]<=L'Z')||(p[0]>=L'a'&&p[0]<=L'z'))||p.back()==L'\\')return false;
 for(std::size_t i=2;i<p.size();++i)if(p[i]<32||p[i]==L'"'||p[i]==L':'||p[i]==L'/')return false;
 return p.find(L"\\..\\")==std::wstring::npos&&p.find(L"\\.\\")==std::wstring::npos;}
// No Shell32/User32 loader dependency. Only the owner's fixed quoted argv is
// accepted: quotes delimit a whole argument, no escapes or embedded quotes.
bool arguments(std::vector<std::wstring>& a){const wchar_t* p=GetCommandLineW();
 if(!p)return false;std::size_t total=0;
 while(*p){while(*p==L' '||*p==L'\t')++p;if(!*p)break;
  std::wstring s;const bool q=*p==L'"';if(q)++p;
  while(*p&&!(q?*p==L'"':(*p==L' '||*p==L'\t'))){if(*p<32||(!q&&*p==L'"'))return false;
   s+=*p++;if(++total>10000||s.size()>2048)return false;}
  if(q){if(*p!=L'"')return false;++p;if(*p&&*p!=L' '&&*p!=L'\t')return false;}
  if(s.empty()||a.size()>=15)return false;a.push_back(s);
 }return a.size()==15;}
bool number(const std::wstring& s,std::uint64_t& out){if(s.empty()||s.size()>20)return false;out=0;
 for(auto c:s){if(c<L'0'||c>L'9')return false;const auto d=static_cast<std::uint64_t>(c-L'0');
  if(out>(UINT64_MAX-d)/10)return false;out=out*10+d;}return true;}
bool hex_id(const std::wstring& s,Id& out){std::string text;
 for(auto c:s){if(c>127)return false;text+=static_cast<char>(c);}return zlp::id(text,out);}
struct Clock {const zlp::Plan& p;std::uint64_t last=0;bool within=true;
 bool sample(std::uint64_t d,Issue& issue){LARGE_INTEGER tick{};
  if(!QueryPerformanceCounter(&tick)||tick.QuadPart<=0){within=false;issue.fail("qpc");return false;}
  last=static_cast<std::uint64_t>(tick.QuadPart);
  if(last<p.start||last>=d){within=false;issue.fail("deadline");return false;}return true;}
};
struct Token {bool valid=false,ac=false,primary=false,elevated=false,ui=false;
 DWORD caps=0,integrity=0,session=0;std::uint64_t id=0,auth=0;};
std::uint64_t luid(const LUID& x){return(std::uint64_t(static_cast<DWORD>(x.HighPart))<<32)|x.LowPart;}
struct Phase {Ticket ticket{};std::uint64_t start=0,last=0;std::uint16_t local=0;
 bool connect_attempted=false,connected=false,send_attempted=false,request_exact=false,shutdown=false;
 DWORD request_bytes=0,response_bytes=0;bool response_exact=false,response_eof=false,within=true;
 const char* close="not-created";const char* wsa="not-started";Issue issue;};
struct Receipt {Ticket ticket{};unsigned index=0;std::uint64_t accepted=0,eof_tick=0,last=0,release=0;
 std::uint16_t peer=0;DWORD request_bytes=0,response_bytes=0;bool request_exact=false,eof=false,
 complete=false,shutdown=false,withheld=false,held=false,released=false,within=true;
 const char* close="not-created";Issue issue;};
class Actor {
 zlp::Plan p;std::wstring report,ready,control;Clock clock;Token token;
 Issue issue;bool token_closed=true,control_closed=true,socket_uncertain=false,wsa_uncertain=false,
 tested=false,started=false,listening=false;SOCKET server=INVALID_SOCKET;
 const char* server_close="not-created";const char* server_wsa="not-started";
 unsigned accepted_count=0,receipts=0,phases=0;std::uint64_t initial=0;
 std::uint64_t work()const{return p.deadline-35*p.frequency;}
 std::uint64_t cleanup()const{return p.deadline-5*p.frequency;}
 bool tick(std::uint64_t d,Issue& i,bool& within){const bool ok=clock.sample(d,i);if(!ok)within=false;return ok;}
 void merge(const Issue& i){if(!issue.failure&&i.failure)issue=i;}
 std::string common(const char* stage)const{std::ostringstream o;
  o<<"{\"schema_version\":1,\"stage\":"<<quoted(stage)<<",\"role\":"<<quoted(zlp::name(p.role))
   <<",\"run_id\":\""<<zlp::hex(p.run)<<"\",\"boot_case_id\":\""<<zlp::hex(p.boot)
   <<"\",\"pid\":"<<GetCurrentProcessId()<<",\"token\":";
  if(!token.valid)o<<"null";else o<<"{\"is_appcontainer\":"<<boolean(token.ac)
   <<",\"capability_count\":"<<token.caps<<",\"integrity_rid\":"<<token.integrity
   <<",\"session_id\":"<<token.session<<",\"primary\":"<<boolean(token.primary)
   <<",\"elevated\":"<<boolean(token.elevated)<<",\"ui_access\":"<<boolean(token.ui)
   <<",\"token_id\":"<<token.id<<",\"authentication_id\":"<<token.auth<<"}";
  o<<",\"root_qpc\":["<<p.frequency<<","<<p.start<<","<<p.deadline<<"]";return o.str();}
 std::string ports()const{return "{\"frontend\":"+std::to_string(p.frontend)+",\"ordinary\":"+std::to_string(p.origin)+"}";}
 std::string cases()const{return "{\"before\":\""+zlp::hex(p.before)+"\",\"selected\":\""+zlp::hex(p.selected)
  +"\",\"after\":\""+zlp::hex(p.after)+"\"}";}
 std::string errors(const Issue& i)const{return ",\"failure\":"+quoted(i.failure)+",\"wsa_error\":"
  +optional(i.wsa,i.has_wsa)+",\"win32_error\":"+optional(i.win,i.has_win);}
 bool close_file(HANDLE& h,const char* failure,Issue& i,bool& state){if(h==INVALID_HANDLE_VALUE)return true;
  const auto value=h;h=INVALID_HANDLE_VALUE;clock.sample(p.deadline,i);
  const BOOL ok=CloseHandle(value);const DWORD error=ok?0:GetLastError();
  clock.sample(p.deadline,i);if(!ok){state=false;i.windows(failure,error);}return ok!=FALSE;}
 bool write(const std::wstring& path,const std::string& text){if(text.size()>65536){issue.fail("report");return false;}
  if(!clock.sample(cleanup(),issue))return false;
  HANDLE h=CreateFileW(path.c_str(),GENERIC_WRITE,0,nullptr,CREATE_NEW,FILE_ATTRIBUTE_NORMAL,nullptr);
  const DWORD open_error=h==INVALID_HANDLE_VALUE?GetLastError():0;clock.sample(cleanup(),issue);
  if(h==INVALID_HANDLE_VALUE){issue.windows("report",open_error);return false;}
  DWORD n=0;const BOOL wrote=WriteFile(h,text.data(),static_cast<DWORD>(text.size()),&n,nullptr);
  const DWORD write_error=wrote?0:GetLastError();clock.sample(cleanup(),issue);
  bool ok=wrote&&n==text.size();if(!ok){if(!wrote)issue.windows("report",write_error);else issue.fail("report");}
  if(ok){const BOOL flushed=FlushFileBuffers(h);const DWORD e=flushed?0:GetLastError();clock.sample(cleanup(),issue);
   if(!flushed){issue.windows("report",e);ok=false;}}
  bool closed=true;if(!close_file(h,"report",issue,closed))ok=false;return ok;}
 template<class T>bool scalar(HANDLE h,TOKEN_INFORMATION_CLASS cls,T& out){DWORD n=0;
  if(!clock.sample(work(),issue))return false;const BOOL ok=GetTokenInformation(h,cls,&out,sizeof(T),&n);
  const DWORD error=ok?0:GetLastError();const bool timely=clock.sample(work(),issue);
  if(!ok){issue.windows("identity",error);return false;}if(n!=sizeof(T)){issue.fail("identity");return false;}return timely;}
 bool variable(HANDLE h,TOKEN_INFORMATION_CLASS cls,std::vector<std::uint64_t>& bytes,DWORD& count){DWORD n=0;
  if(!clock.sample(work(),issue))return false;const BOOL first=GetTokenInformation(h,cls,nullptr,0,&n);
  const DWORD error=first?0:GetLastError();if(!clock.sample(work(),issue))return false;
  if(first||error!=ERROR_INSUFFICIENT_BUFFER||n<4||n>32768){issue.fail("identity");return false;}
  bytes.assign((n+7u)/8u,0);count=n;DWORD returned=0;
  const BOOL ok=GetTokenInformation(h,cls,bytes.data(),n,&returned);const DWORD e=ok?0:GetLastError();
  const bool timely=clock.sample(work(),issue);if(!ok){issue.windows("identity",e);return false;}
  if(returned<4||returned>count){issue.fail("identity");return false;}count=returned;return timely;}
 bool identity(){HANDLE h=INVALID_HANDLE_VALUE;BOOL owned=FALSE;
  if(!clock.sample(work(),issue))return false;
  const BOOL in_job=IsProcessInJob(GetCurrentProcess(),nullptr,&owned);const DWORD job_error=in_job?0:GetLastError();
  if(!clock.sample(work(),issue))return false;if(!in_job||!owned){if(!in_job)issue.windows("identity",job_error);
   else issue.fail("identity");return false;}
  const BOOL opened=OpenProcessToken(GetCurrentProcess(),TOKEN_QUERY,&h);const DWORD e=opened?0:GetLastError();
  clock.sample(work(),issue);if(!opened){issue.windows("identity",e);return false;}token_closed=false;
  DWORD ac=0,elev=0,ui=0,session=0;TOKEN_TYPE type{};TOKEN_STATISTICS stats{};
  bool ok=scalar(h,TokenIsAppContainer,ac)&&scalar(h,TokenSessionId,session)&&scalar(h,TokenType,type)
   &&scalar(h,TokenElevation,elev)&&scalar(h,TokenUIAccess,ui)&&scalar(h,TokenStatistics,stats);
  std::vector<std::uint64_t> buffer;DWORD n=0;
  if(ok&&variable(h,TokenCapabilities,buffer,n)){DWORD caps=0;std::memcpy(&caps,buffer.data(),sizeof caps);
   ok=zlp::capabilities_extent(n,caps,offsetof(TOKEN_GROUPS,Groups),sizeof(SID_AND_ATTRIBUTES))&&caps==0;
   token.caps=caps;if(!ok)issue.fail("identity");}else ok=false;
  if(ok&&variable(h,TokenIntegrityLevel,buffer,n)){
   if(n<sizeof(TOKEN_MANDATORY_LABEL)){ok=false;issue.fail("identity");}
   else {const auto* label=reinterpret_cast<const TOKEN_MANDATORY_LABEL*>(buffer.data());
    const auto begin=reinterpret_cast<std::uintptr_t>(buffer.data()),sid=reinterpret_cast<std::uintptr_t>(label->Label.Sid);
    if(sid<begin||sid-begin>n||n-(sid-begin)<8){ok=false;issue.fail("identity");}
    else {const auto available=n-static_cast<std::size_t>(sid-begin);const auto* raw=reinterpret_cast<const BYTE*>(sid);
     const auto count=raw[1];const auto length=std::size_t(8)+std::size_t(count)*4;
     if(count==0||count>15||length>available||!IsValidSid(label->Label.Sid)||GetLengthSid(label->Label.Sid)!=length){
      ok=false;issue.fail("identity");}else token.integrity=*GetSidSubAuthority(label->Label.Sid,count-1);}}
  }else ok=false;
  token.ac=ac!=0;token.primary=type==TokenPrimary;token.elevated=elev!=0;token.ui=ui!=0;
  token.session=session;token.id=luid(stats.TokenId);token.auth=luid(stats.AuthenticationId);
  ok=ok&&token.ac!=zlp::ordinary(p.role)&&token.primary&&!token.elevated&&!token.ui
   &&token.integrity==(zlp::ordinary(p.role)?8192u:4096u)&&token.id!=0&&token.auth!=0;
  if(!ok)issue.fail("identity");token_closed=close_file(h,"identity-close",issue,token_closed);
  token.valid=ok&&token_closed&&!issue.failure;return token.valid;}
 bool command(const std::wstring& file,unsigned seq,Ticket& t,const Ticket* release=nullptr){
  const auto d=release?release->deadline:work();
  for(;;){if(!clock.sample(d,issue))return false;
   HANDLE h=CreateFileW(file.c_str(),GENERIC_READ,0,nullptr,OPEN_EXISTING,
    FILE_ATTRIBUTE_NORMAL|FILE_FLAG_OPEN_REPARSE_POINT,nullptr);
   const DWORD e=h==INVALID_HANDLE_VALUE?GetLastError():0;clock.sample(d,issue);
   if(h==INVALID_HANDLE_VALUE){if(e==ERROR_FILE_NOT_FOUND){Sleep(2);continue;}
    issue.windows("control-open",e);return false;}
   control_closed=false;zlp::Command bytes{};LARGE_INTEGER size{};FILE_ATTRIBUTE_TAG_INFO info{};
   const BOOL sized=GetFileSizeEx(h,&size);const DWORD size_error=sized?0:GetLastError();clock.sample(d,issue);
   bool good=sized&&size.QuadPart==128;
   if(!sized)issue.windows("control-read",size_error);else if(!good)issue.fail("control");
   if(good){const BOOL got=GetFileInformationByHandleEx(h,FileAttributeTagInfo,&info,sizeof info);
    const DWORD er=got?0:GetLastError();clock.sample(d,issue);good=got&&(info.FileAttributes&FILE_ATTRIBUTE_REPARSE_POINT)==0;
    if(!got)issue.windows("control-read",er);else if(!good)issue.fail("control");}
   DWORD read=0;if(good){const BOOL got=ReadFile(h,bytes.data(),static_cast<DWORD>(bytes.size()),&read,nullptr);
    const DWORD er=got?0:GetLastError();clock.sample(d,issue);good=got&&read==bytes.size();
    if(!got)issue.windows("control-read",er);else if(!good)issue.fail("control");}
   bool closed=true;const bool close_ok=close_file(h,"control-close",issue,closed);
   control_closed=closed;if(!good||!close_ok||!clock.sample(d,issue))return false;
   if(!zlp::command(bytes,p,seq,clock.last,t,release)){issue.fail("control");return false;}return true;
  }}
 bool startup(Issue& i,bool& within,const char*& result,std::uint64_t d){if(!tick(d,i,within))return false;
  WSADATA data{};const int code=WSAStartup(MAKEWORD(2,2),&data);if(code==0)result="uncertain";
  if(code)i.winsock("wsa-startup",code);const bool timely=tick(d,i,within);
  if(code)return false;if(data.wVersion!=MAKEWORD(2,2)){i.fail("wsa-startup");return false;}return timely;}
 void wsa_close(Issue& i,bool& within,const char*& result){if(std::strcmp(result,"not-started")==0)return;
  tick(p.deadline,i,within);const int code=WSACleanup();const int e=code==SOCKET_ERROR?WSAGetLastError():0;
  result=code==0?"confirmed":"uncertain";if(code){wsa_uncertain=true;i.winsock("wsa-cleanup",e);}tick(p.deadline,i,within);}
 void socket_close(SOCKET& s,Issue& i,bool& within,const char*& result){if(s==INVALID_SOCKET)return;
  const auto held=s;s=INVALID_SOCKET;tick(p.deadline,i,within);const int code=closesocket(held);
  const int e=code==SOCKET_ERROR?WSAGetLastError():0;result=code==0?"confirmed":"uncertain";
  if(code){socket_uncertain=true;i.winsock("socket-close",e);}tick(p.deadline,i,within);}
 bool configure(SOCKET s,Issue& i,bool& within,std::uint64_t d){if(!tick(d,i,within))return false;
  DWORD flags=0;const BOOL got=GetHandleInformation(reinterpret_cast<HANDLE>(s),&flags);
  const DWORD e=got?0:GetLastError();tick(d,i,within);if(!got){i.windows("socket-inheritance",e);return false;}
  if(flags&HANDLE_FLAG_INHERIT){i.fail("socket-inheritance");return false;}
  u_long nonblock=1;const int code=ioctlsocket(s,FIONBIO,&nonblock);const int er=code?WSAGetLastError():0;
  if(code)i.winsock("socket-setup",er);return tick(d,i,within)&&code==0;}
 SOCKET create(Issue& i,bool& within,std::uint64_t d){if(!tick(d,i,within))return INVALID_SOCKET;
  const auto s=WSASocketW(AF_INET,SOCK_STREAM,IPPROTO_TCP,nullptr,0,WSA_FLAG_NO_HANDLE_INHERIT);
  const int e=s==INVALID_SOCKET?WSAGetLastError():0;if(s==INVALID_SOCKET)i.winsock("socket",e);
  tick(d,i,within);return s;}
 bool wait(SOCKET s,bool writing,Issue& i,bool& within,std::uint64_t d){for(;;){if(!tick(d,i,within))return false;
  fd_set set;FD_ZERO(&set);FD_SET(s,&set);timeval timeout{0,20000};
  const int code=select(0,writing?nullptr:&set,writing?&set:nullptr,nullptr,&timeout);
  const int e=code==SOCKET_ERROR?WSAGetLastError():0;if(code==SOCKET_ERROR)i.winsock("select",e);
  if(!tick(d,i,within)||code==SOCKET_ERROR)return false;if(code>0)return true;}}
 bool send_packet(SOCKET s,const zlp::Packet& bytes,DWORD& count,Issue& i,bool& within,std::uint64_t d){
  while(count<bytes.size()){if(!tick(d,i,within))return false;
   const int n=send(s,reinterpret_cast<const char*>(bytes.data())+count,static_cast<int>(bytes.size()-count),0);
   const int e=n==SOCKET_ERROR?WSAGetLastError():0;if(n>0)count+=static_cast<DWORD>(n);
   if(n==SOCKET_ERROR&&e!=WSAEWOULDBLOCK)i.winsock("send",e);else if(n==0)i.fail("send");
   if(!tick(d,i,within)||n==0||(n==SOCKET_ERROR&&e!=WSAEWOULDBLOCK))return false;
   if(n==SOCKET_ERROR&&!wait(s,true,i,within,d))return false;}return true;}
 bool halfclose(SOCKET s,Issue& i,bool& within,std::uint64_t d,bool& done){if(!tick(d,i,within))return false;
  const int code=shutdown(s,SD_SEND);const int e=code?WSAGetLastError():0;if(!code)done=true;
  else i.winsock("shutdown",e);return tick(d,i,within)&&code==0;}
 bool receive(SOCKET s,const Id& c,bool response,DWORD& count,bool& exact,bool& eof,Issue& i,bool& within,std::uint64_t d){
  std::array<std::uint8_t,65> bytes{};
  for(;;){if(!tick(d,i,within))return false;
   const auto room=bytes.size()-count;if(room==0){i.fail(response?"response":"request");return false;}
   const int n=recv(s,reinterpret_cast<char*>(bytes.data())+count,static_cast<int>(room),0);
   const int e=n==SOCKET_ERROR?WSAGetLastError():0;if(n>0)count+=static_cast<DWORD>(n);else if(n==0)eof=true;
   if(n==SOCKET_ERROR&&e!=WSAEWOULDBLOCK)i.winsock("receive",e);
   const bool timely=tick(d,i,within);
   if(eof){exact=zlp::matches(bytes.data(),count,p,c,response);if(!exact)i.fail(response?"response":"request");return timely&&exact;}
   if(!timely||(n==SOCKET_ERROR&&e!=WSAEWOULDBLOCK))return false;
   if(n==SOCKET_ERROR&&!wait(s,false,i,within,d))return false;}}
 bool endpoint(SOCKET s,bool peer,std::uint16_t& port,Issue& i,bool& within,std::uint64_t d){
  if(!tick(d,i,within))return false;sockaddr_in address{};int bytes=sizeof address;
  const int code=peer?getpeername(s,reinterpret_cast<sockaddr*>(&address),&bytes):getsockname(s,reinterpret_cast<sockaddr*>(&address),&bytes);
  const int e=code?WSAGetLastError():0;if(code)i.winsock("socket-setup",e);
  else if(bytes!=sizeof address||address.sin_family!=AF_INET||address.sin_addr.s_addr!=htonl(INADDR_LOOPBACK))i.fail("socket-setup");
  else port=ntohs(address.sin_port);return tick(d,i,within)&&!i.failure&&port!=0;}
 bool listen_start(){bool within=true;
  const bool initialized=startup(issue,within,server_wsa,work());
  if(std::strcmp(server_wsa,"not-started")!=0)started=true;if(!initialized)return false;
  server=create(issue,within,work());
  if(server==INVALID_SOCKET)return false;server_close="uncertain";
  if(issue.failure||!configure(server,issue,within,work()))return false;
  const BOOL exclusive=TRUE;const int configured=setsockopt(server,SOL_SOCKET,SO_EXCLUSIVEADDRUSE,
   reinterpret_cast<const char*>(&exclusive),sizeof exclusive);const int er=configured?WSAGetLastError():0;
  if(configured)issue.winsock("socket-setup",er);if(!tick(work(),issue,within)||configured)return false;
  sockaddr_in address{};address.sin_family=AF_INET;address.sin_addr.s_addr=htonl(INADDR_LOOPBACK);
  address.sin_port=htons(p.role==Role::Front?p.frontend:p.origin);
  const int bound=bind(server,reinterpret_cast<sockaddr*>(&address),sizeof address);const int be=bound?WSAGetLastError():0;
  if(bound)issue.winsock("bind",be);if(!tick(work(),issue,within)||bound)return false;
  const int result=listen(server,1);const int le=result?WSAGetLastError():0;
  if(!result)listening=true;else issue.winsock("listen",le);if(!tick(work(),issue,within)||result)return false;
  std::uint16_t actual=0;return endpoint(server,false,actual,issue,within,work())&&actual==(p.role==Role::Front?p.frontend:p.origin);}
 bool ready_file(){std::ostringstream o;o<<common("zero-cap-loopback-ready")<<",\"ready_qpc\":"<<clock.last
  <<",\"ports\":"<<ports()<<",\"case_ids\":"<<cases()<<",\"listener\":"<<boolean(zlp::listener(p.role))
  <<",\"port\":"<<(zlp::listener(p.role)?std::to_string(p.role==Role::Front?p.frontend:p.origin):"null")
  <<",\"socket_held\":"<<boolean(server!=INVALID_SOCKET)<<",\"wsa_started\":"<<boolean(started)
  <<",\"token_close_confirmed\":"<<boolean(token_closed)<<",\"failure\":null,\"network_tested\":false,\"product_acceptance\":false}\n";
  return write(ready,o.str());}
 std::string phase_json(const Phase& f){std::ostringstream o;o<<common("zero-cap-loopback-client-phase")
  <<",\"sequence\":"<<f.ticket.sequence<<",\"case_id\":\""<<zlp::hex(f.ticket.case_id)
  <<"\",\"phase_deadline_qpc\":"<<f.ticket.deadline<<",\"flow_qpc\":["<<f.start<<","<<f.last
  <<"],\"target_port\":"<<(p.role==Role::Selected?p.frontend:p.origin)<<",\"local_port\":"<<port_json(f.local)
  <<",\"connect_attempted\":"<<boolean(f.connect_attempted)<<",\"connect_completed\":"<<boolean(f.connected)
  <<",\"send_attempted\":"<<boolean(f.send_attempted)<<",\"request_bytes\":"<<f.request_bytes
  <<",\"request_exact\":"<<boolean(f.request_exact)<<",\"send_shutdown\":"<<boolean(f.shutdown)
  <<",\"response_bytes\":"<<f.response_bytes<<",\"response_exact\":"<<boolean(f.response_exact)
  <<",\"response_eof\":"<<boolean(f.response_eof)<<",\"socket_close\":"<<quoted(f.close)
  <<",\"wsa_cleanup\":"<<quoted(f.wsa)<<",\"within_deadline\":"<<boolean(f.within)
  <<errors(f.issue)<<",\"control_close_verified\":"<<boolean(control_closed)
  <<",\"network_tested\":"<<boolean(f.connect_attempted)<<",\"product_acceptance\":false}\n";return o.str();}
 bool client(unsigned seq){Ticket t;if(!command(control+L"\\"+numbered(L"phase-",seq,L".bin"),seq,t))return false;
  Phase f;f.ticket=t;f.start=clock.last;SOCKET s=INVALID_SOCKET;
  const bool ok=[&](){const bool initialized=startup(f.issue,f.within,f.wsa,t.deadline);
   if(std::strcmp(f.wsa,"not-started")!=0)started=true;if(!initialized)return false;
   s=create(f.issue,f.within,t.deadline);if(s==INVALID_SOCKET)return false;f.close="uncertain";
   if(f.issue.failure||!configure(s,f.issue,f.within,t.deadline))return false;
   sockaddr_in target{};target.sin_family=AF_INET;target.sin_addr.s_addr=htonl(INADDR_LOOPBACK);
   target.sin_port=htons(p.role==Role::Selected?p.frontend:p.origin);
   if(!tick(t.deadline,f.issue,f.within))return false;f.connect_attempted=true;tested=true;
   const int result=connect(s,reinterpret_cast<sockaddr*>(&target),sizeof target);
   const int e=result?WSAGetLastError():0;if(!result)f.connected=true;
   else if(e!=WSAEWOULDBLOCK)f.issue.winsock("connect",e);
   if(!tick(t.deadline,f.issue,f.within)||f.issue.failure)return false;
   if(result){if(!wait(s,true,f.issue,f.within,t.deadline))return false;int error=0;int len=sizeof error;
    const int got=getsockopt(s,SOL_SOCKET,SO_ERROR,reinterpret_cast<char*>(&error),&len);
    const int get_error=got?WSAGetLastError():0;if(got)f.issue.winsock("connect",get_error);
    else if(len!=sizeof error)f.issue.fail("connect");else if(error)f.issue.winsock("connect",error);else f.connected=true;
    if(!tick(t.deadline,f.issue,f.within)||!f.connected)return false;}
   std::uint16_t remote=0;if(!endpoint(s,false,f.local,f.issue,f.within,t.deadline)
    ||!endpoint(s,true,remote,f.issue,f.within,t.deadline)||remote!=(p.role==Role::Selected?p.frontend:p.origin))return false;
   const auto bytes=zlp::packet(p,t.case_id,false);f.send_attempted=true;
   if(!send_packet(s,bytes,f.request_bytes,f.issue,f.within,t.deadline))return false;f.request_exact=f.request_bytes==64;
   if(!halfclose(s,f.issue,f.within,t.deadline,f.shutdown))return false;
   return receive(s,t.case_id,true,f.response_bytes,f.response_exact,f.response_eof,f.issue,f.within,t.deadline);
  }();
  socket_close(s,f.issue,f.within,f.close);wsa_close(f.issue,f.within,f.wsa);f.last=clock.last;
  if(f.last>=t.deadline)f.within=false;++phases;merge(f.issue);
  const bool wrote=write(parent(report)+L"\\"+numbered(L"phase-",seq,L".json"),phase_json(f));
  return ok&&wrote&&f.within&&!f.issue.failure;}
 std::string receipt_json(const Receipt& f,bool held){std::ostringstream o;
  o<<common(held?"zero-cap-loopback-received":"zero-cap-loopback-receipt")<<",\"index\":"<<f.index
   <<",\"case_id\":\""<<zlp::hex(f.ticket.case_id)<<"\",\"phase_deadline_qpc\":"<<f.ticket.deadline
   <<",\"flow_qpc\":["<<f.accepted<<","<<f.eof_tick<<","<<f.last<<"],\"port\":"<<(p.role==Role::Front?p.frontend:p.origin)
   <<",\"peer_port\":"<<port_json(f.peer)<<",\"request_bytes\":"<<f.request_bytes
   <<",\"request_exact\":"<<boolean(f.request_exact)<<",\"request_eof\":"<<boolean(f.eof)
   <<",\"response_bytes\":"<<f.response_bytes<<",\"response_complete\":"<<boolean(f.complete)
   <<",\"send_shutdown\":"<<boolean(f.shutdown)<<",\"response_withheld\":"<<boolean(f.withheld)
   <<",\"socket_held\":"<<boolean(f.held)<<",\"connection_close\":"<<quoted(f.close)
   <<",\"release_verified\":"<<boolean(f.released)<<",\"release_qpc\":"<<f.release
   <<",\"within_deadline\":"<<boolean(f.within)<<errors(f.issue)
   <<",\"control_close_verified\":"<<boolean(control_closed)<<",\"network_tested\":"<<boolean(accepted_count!=0)
   <<",\"product_acceptance\":false}\n";return o.str();}
 bool listener_phase(unsigned seq){Ticket t;if(!command(control+L"\\"+numbered(L"phase-",seq,L".bin"),seq,t))return false;
  Receipt f;f.ticket=t;f.index=seq;SOCKET s=INVALID_SOCKET;
  const bool ok=[&](){for(;;){if(!tick(t.deadline,f.issue,f.within))return false;
    sockaddr_in address{};int len=sizeof address;s=accept(server,reinterpret_cast<sockaddr*>(&address),&len);
    const int e=s==INVALID_SOCKET?WSAGetLastError():0;if(s!=INVALID_SOCKET){++accepted_count;tested=true;f.held=true;f.close="held";}
    else if(e!=WSAEWOULDBLOCK)f.issue.winsock("accept",e);
    if(!tick(t.deadline,f.issue,f.within)||f.issue.failure)return false;if(s!=INVALID_SOCKET){f.accepted=clock.last;
     if(len!=sizeof address||address.sin_family!=AF_INET||address.sin_addr.s_addr!=htonl(INADDR_LOOPBACK)){
      f.issue.fail("accept");return false;}f.peer=ntohs(address.sin_port);break;}
    if(!wait(server,false,f.issue,f.within,t.deadline))return false;}
   // accept may create an inheritable socket on old systems. Clear it explicitly
   // before any request is read, then read back. No capability/loopback fallback.
   const BOOL cleared=SetHandleInformation(reinterpret_cast<HANDLE>(s),HANDLE_FLAG_INHERIT,0);
   const DWORD e=cleared?0:GetLastError();if(!cleared)f.issue.windows("socket-inheritance",e);
   if(!tick(t.deadline,f.issue,f.within)||!cleared||!configure(s,f.issue,f.within,t.deadline))return false;
   if(!receive(s,t.case_id,false,f.request_bytes,f.request_exact,f.eof,f.issue,f.within,t.deadline))return false;
   f.eof_tick=clock.last;
   if(p.role==Role::Front){f.withheld=true;f.last=clock.last;
    if(!write(parent(report)+L"\\received.json",receipt_json(f,true)))return false;
    Ticket released;if(!command(control+L"\\release.bin",seq,released,&t))return false;
    f.released=true;f.release=clock.last;}
   const auto bytes=zlp::packet(p,t.case_id,true);
   if(!send_packet(s,bytes,f.response_bytes,f.issue,f.within,t.deadline))return false;f.complete=f.response_bytes==64;
   return halfclose(s,f.issue,f.within,t.deadline,f.shutdown);
  }();
  if(!ok&&!f.issue.failure){if(issue.failure)f.issue=issue;else f.issue.fail("request");}
  socket_close(s,f.issue,f.within,f.close);f.held=false;f.last=clock.last;if(f.last>=t.deadline)f.within=false;
  merge(f.issue);const bool wrote=write(parent(report)+L"\\"+numbered(L"receipt-",seq,L".json"),receipt_json(f,false));
  if(wrote)++receipts;return ok&&wrote&&f.within&&!f.issue.failure;}
 bool final_file(){std::ostringstream o;o<<common("zero-cap-loopback-final")<<",\"flow_qpc\":["<<initial<<","<<clock.last
  <<"],\"ports\":"<<ports()<<",\"case_ids\":"<<cases()<<",\"listening_verified\":"<<boolean(listening)
  <<",\"listen_port\":"<<(listening?std::to_string(p.role==Role::Front?p.frontend:p.origin):"null")
  <<",\"listen_close\":"<<quoted(server_close)<<",\"wsa_started\":"<<boolean(started)
  <<",\"wsa_cleanup\":"<<quoted(zlp::listener(p.role)?server_wsa:(started?(wsa_uncertain?"uncertain":"confirmed"):"not-started"))
  <<",\"token_close_confirmed\":"<<boolean(token_closed)<<",\"control_close_verified\":"<<boolean(control_closed)
  <<",\"socket_resources_closed\":"<<boolean(!socket_uncertain&&server==INVALID_SOCKET)
  <<",\"accepted_count\":"<<accepted_count<<",\"receipt_count\":"<<receipts<<",\"phase_count\":"<<phases
  <<",\"within_deadline\":"<<boolean(clock.within)<<errors(issue)
  <<",\"network_tested\":"<<boolean(tested)<<",\"product_acceptance\":false}\n";return write(report,o.str());}
public:
 Actor(zlp::Plan plan,std::wstring output,std::wstring ready_path,std::wstring control_path):
  p(plan),report(std::move(output)),ready(std::move(ready_path)),control(std::move(control_path)),clock{p}{}
 int run(){LARGE_INTEGER frequency{};if(!QueryPerformanceFrequency(&frequency)||frequency.QuadPart<=0
   ||static_cast<std::uint64_t>(frequency.QuadPart)!=p.frequency)issue.fail("qpc");
  if(!issue.failure)clock.sample(work(),issue);initial=clock.last;
  bool ok=!issue.failure&&identity();if(ok&&zlp::listener(p.role))ok=listen_start();
  if(ok)ok=clock.sample(work(),issue)&&ready_file();
  if(ok){const auto n=zlp::ordinary(p.role)?2u:1u;for(unsigned seq=1;seq<=n;++seq){
    ok=zlp::listener(p.role)?listener_phase(seq):client(seq);if(!ok)break;}}
  bool within=clock.within;socket_close(server,issue,within,server_close);
  wsa_close(issue,within,server_wsa);clock.sample(cleanup(),issue);
  if(!ok&&!issue.failure)issue.fail("control");const bool wrote=final_file();return ok&&wrote&&!issue.failure?0:5;}
};
} // namespace
int WINAPI wWinMain(HINSTANCE,HINSTANCE,PWSTR,int){
 try{std::vector<std::wstring> a;if(!arguments(a))return 2;zlp::Plan p;
  bool role=false;for(unsigned i=1;i<=4;++i){const auto r=static_cast<Role>(i);const auto* n=zlp::name(r);
   if(a[1]==std::wstring(n,n+std::strlen(n))){p.role=r;role=true;}}
  std::uint64_t front=0,origin=0;
  if(!role||!hex_id(a[2],p.run)||!hex_id(a[3],p.boot)||!absolute(a[4])||!absolute(a[5])||!absolute(a[6])
   ||parent(a[4])!=parent(a[5])||!number(a[7],p.frequency)||!number(a[8],p.start)||!number(a[9],p.deadline)
   ||!number(a[10],front)||!number(a[11],origin)||front>65535||origin>65535
   ||!hex_id(a[12],p.before)||!hex_id(a[13],p.selected)||!hex_id(a[14],p.after))return 2;
  p.frontend=static_cast<std::uint16_t>(front);p.origin=static_cast<std::uint16_t>(origin);if(!zlp::valid(p))return 2;
  Actor actor(p,a[4],a[5],a[6]);return actor.run();
 }catch(...){return 2;}
}
