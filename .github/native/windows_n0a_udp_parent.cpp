// Socket-free parent for the separately pinned, unchanged UDP child.
// Private identity and child report commitments MUST NOT be uploaded verbatim.
// Caller/controller authenticates the expected hash; this wrapper verifies it,
// but does not promote an arbitrary caller-supplied hash into a trust root.
#define RULEPROXY_IDENTITY_ONLY 1
#define wmain UnusedIdentityEntry
#include "windows_identity_actor.cpp"
#undef wmain
#include <bcrypt.h>
#include <algorithm>
#include <stdexcept>
#pragma comment(lib,"bcrypt.lib")
namespace udp_parent {
#ifdef N0A_UDP_PARENT_TEST_ONLY
static_assert(N0A_UDP_PARENT_TEST_ONLY==1,"exact fixture marker");
constexpr bool TestOnly=true;
constexpr const wchar_t* ChildName=L"windows_n0a_UDP_TEST_ONLY_fixture.exe";
#else
constexpr bool TestOnly=false;
constexpr const wchar_t* ChildName=L"windows_n0a_udp_actor.exe";
#endif
struct Handle {
 HANDLE value=nullptr;
 bool close() noexcept { const HANDLE old=value; value=nullptr; return !old || old==INVALID_HANDLE_VALUE || CloseHandle(old)!=FALSE; }
 ~Handle() { close(); }
 Handle()=default; Handle(const Handle&)=delete; Handle& operator=(const Handle&)=delete;
};
struct SidArrays final {
    PSID* groups = nullptr;
    DWORD groupCount = 0;
    PSID* capabilities = nullptr;
    DWORD capabilityCount = 0;
    ~SidArrays() {
        if (groups) { for (DWORD i=0; i<groupCount; ++i) LocalFree(groups[i]); LocalFree(groups); }
        if (capabilities) { for (DWORD i=0; i<capabilityCount; ++i) LocalFree(capabilities[i]); LocalFree(capabilities); }
    }
};
bool PackageSid(const std::optional<std::string>& sid) {
    if (!sid || sid->compare(0,8,"S-1-15-2")!=0) return false;
    std::size_t position=8;
    for (int part=0;part<7;++part) {
        if (position>=sid->size() || (*sid)[position++]!='-') return false;
        const std::size_t start=position;
        while (position<sid->size() && (*sid)[position]>='0' && (*sid)[position]<='9') ++position;
        if (position==start || position-start>10) return false;
    }
    return position==sid->size();
}
bool Agentic(const Capability& capability) {
    if (capability.attributes != SE_GROUP_ENABLED) return false;
    const HMODULE module=GetModuleHandleW(L"kernelbase.dll");
    if (!module) return false;
    using Derive=BOOL(WINAPI*)(LPCWSTR,PSID**,DWORD*,PSID**,DWORD*);
    const FARPROC address=GetProcAddress(module,"DeriveCapabilitySidsFromName");
    Derive derive=nullptr; static_assert(sizeof(derive)==sizeof(address),"function pointer size");
    std::memcpy(&derive,&address,sizeof(derive));
    if (!derive) return false;
    SidArrays ids;
    if (!derive(L"AgenticAppContainer",&ids.groups,&ids.groupCount,&ids.capabilities,&ids.capabilityCount)
        || ids.capabilityCount!=1 || !ids.capabilities || !IsValidSid(ids.capabilities[0])) return false;
    PSID actual=nullptr;
    if (!ConvertStringSidToSidA(capability.sid.c_str(),&actual)) return false;
    const bool equal=IsValidSid(actual) && EqualSid(actual,ids.capabilities[0]);
    LocalFree(actual);
    return equal;
}
bool Profile(const Observations& identity, bool contained) {
    if (!identity.errors.empty() || identity.pid==0 || identity.tokenElevated!=false
        || !identity.tokenIsAppContainer.has_value() || !identity.isProcessInJob.has_value()) return false;
    if (!contained) return identity.tokenIsAppContainer==false && !identity.tokenAppContainerSid
        && identity.tokenCapabilities.empty();
    return identity.tokenIsAppContainer==true && identity.isProcessInJob==true
        && PackageSid(identity.tokenAppContainerSid) && identity.tokenCapabilities.size()==1
        && Agentic(identity.tokenCapabilities.front());
}

bool Number(const wchar_t* text,DWORD lo,DWORD hi,DWORD& out) {
 const std::wstring s(text); if(s.empty()||s.size()>5||s[0]==L'0') return false;
 DWORD n=0; for(wchar_t c:s) { if(c<L'0'||c>L'9')return false; n=n*10+static_cast<DWORD>(c-L'0'); }
 if(n<lo||n>hi)return false; out=n; return true;
}
bool HashText(const wchar_t* p,std::string& out) {
 const std::wstring s(p); if(s.size()!=64)return false;
 for(wchar_t c:s) { if(!((c>=L'0'&&c<=L'9')||(c>=L'a'&&c<=L'f')))return false; out.push_back(static_cast<char>(c)); } return true;
}
std::string Sha(const std::vector<unsigned char>& bytes) {
 BCRYPT_ALG_HANDLE alg=nullptr; BCRYPT_HASH_HANDLE hash=nullptr;
 std::vector<unsigned char> object;
 std::array<unsigned char,32> digest{}; DWORD size=0,got=0;
 if(BCryptOpenAlgorithmProvider(&alg,BCRYPT_SHA256_ALGORITHM,nullptr,0)<0)throw std::runtime_error("hash");
 struct Cleanup { BCRYPT_ALG_HANDLE* a; BCRYPT_HASH_HANDLE* h; ~Cleanup(){if(*h)BCryptDestroyHash(*h); if(*a)BCryptCloseAlgorithmProvider(*a,0);} } cleanup{&alg,&hash};
 if(BCryptGetProperty(alg,BCRYPT_OBJECT_LENGTH,reinterpret_cast<PUCHAR>(&size),sizeof(size),&got,0)<0||got!=sizeof(size)||size>65536)throw std::runtime_error("hash");
 object.resize(size);
 if(BCryptCreateHash(alg,&hash,object.data(),size,nullptr,0,0)<0
 ||BCryptHashData(hash,const_cast<PUCHAR>(bytes.data()),static_cast<ULONG>(bytes.size()),0)<0
 ||BCryptFinishHash(hash,digest.data(),static_cast<ULONG>(digest.size()),0)<0)throw std::runtime_error("hash");
 // Destroy hash while its object buffer remains alive.
 BCryptDestroyHash(hash); hash=nullptr;
 const char* digits="0123456789abcdef"; std::string result;
 for(unsigned char c:digest){result+=digits[c>>4];result+=digits[c&15];} return result;
}
bool ReadOwnedFile(HANDLE file,std::size_t limit,std::vector<unsigned char>& bytes) {
 BY_HANDLE_FILE_INFORMATION info{}; LARGE_INTEGER size{};
 if(GetFileType(file)!=FILE_TYPE_DISK||!GetFileInformationByHandle(file,&info)
 ||(info.dwFileAttributes&(FILE_ATTRIBUTE_DIRECTORY|FILE_ATTRIBUTE_REPARSE_POINT))
 ||!GetFileSizeEx(file,&size)||size.QuadPart<=0||static_cast<ULONGLONG>(size.QuadPart)>limit)return false;
 bytes.resize(static_cast<std::size_t>(size.QuadPart)); DWORD read=0;
 if(!ReadFile(file,bytes.data(),static_cast<DWORD>(bytes.size()),&read,nullptr)||read!=bytes.size())return false;
 unsigned char extra=0; return ReadFile(file,&extra,1,&read,nullptr)&&read==0;
}
std::wstring Quote(const std::wstring& value) {
 std::wstring out=L"\""; std::size_t slashes=0;
 for(wchar_t c:value){if(c==L'\\'){++slashes;continue;} if(c==L'\"'){out.append(slashes*2+1,L'\\');out+=c;}else{out.append(slashes,L'\\');out+=c;} slashes=0;}
 out.append(slashes*2,L'\\');out+=L'\"';return out;
}
struct TokenView {
 Handle token; bool ac=false; std::vector<unsigned char> buffer; PSID sid=nullptr;
 bool read(HANDLE process) {
  if(!OpenProcessToken(process,TOKEN_QUERY,&token.value))return false;
  DWORD value=0,got=0;
  if(!GetTokenInformation(token.value,TokenIsAppContainer,&value,sizeof(value),&got)||got!=sizeof(value)||value>1)return false;
  ac=value==1; DWORD needed=0;
  if(GetTokenInformation(token.value,TokenAppContainerSid,nullptr,0,&needed)||GetLastError()!=ERROR_INSUFFICIENT_BUFFER
     ||needed<sizeof(TOKEN_APPCONTAINER_INFORMATION)||needed>65536)return false;
  buffer.resize(needed);
  if(!GetTokenInformation(token.value,TokenAppContainerSid,buffer.data(),needed,&got)||got>needed||got<sizeof(TOKEN_APPCONTAINER_INFORMATION))return false;
  TOKEN_APPCONTAINER_INFORMATION info{}; std::memcpy(&info,buffer.data(),sizeof(info)); sid=info.TokenAppContainer;
  if(!sid)return !ac;
  const auto begin=reinterpret_cast<std::uintptr_t>(buffer.data()),address=reinterpret_cast<std::uintptr_t>(sid);
  constexpr std::size_t header=8;
  if(address%alignof(DWORD)!=0||address<begin||address-begin>got||got-static_cast<std::size_t>(address-begin)<header)return false;
  const auto* raw=reinterpret_cast<const unsigned char*>(sid);
  const unsigned int count=raw[1];
  if(count>SID_MAX_SUB_AUTHORITIES||header+count*sizeof(DWORD)>got-static_cast<std::size_t>(address-begin))return false;
  return ac&&IsValidSid(sid)!=FALSE;
 }
};
struct Facts {
 bool profile=false,hash=false,created=false,queries=false,matched=false,resumeAttempt=false,resumed=false,signaled=false;
 bool timeout=false,terminate=false,terminated=false,cleanup=true,report=false;
 DWORD pid=0; std::optional<bool> parentAc,childAc,equal; std::optional<DWORD> resume,exit;
 std::size_t reportBytes=0; std::optional<std::string> reportHash; const char* failure="none";
};
DWORD Remaining(ULONGLONG deadline) {const auto now=GetTickCount64();return now>=deadline?0:static_cast<DWORD>(deadline-now);}
void ObserveExit(HANDLE process,Facts& f) {
 const DWORD observed=WaitForSingleObject(process,0);
 if(observed==WAIT_FAILED)f.cleanup=false;
 if(observed!=WAIT_OBJECT_0)return;
 f.signaled=true; DWORD code=0; if(GetExitCodeProcess(process,&code))f.exit=code; else f.cleanup=false;
}
std::string Json(const Facts& f,const std::string& phase) {
 auto b=[](bool v){return v?"true":"false";};
 auto n=[](const std::optional<DWORD>& v){return v?std::to_string(*v):"null";};
 std::string s="{\"version\":1,\"testOnly\":"+std::string(b(TestOnly))+",\"phase\":\""+phase+"\"";
 s+=",\"profileMatched\":"+std::string(b(f.profile))+",\"childHashVerified\":"+b(f.hash)+",\"childCreated\":"+b(f.created)+",\"childPid\":"+std::to_string(f.pid);
 s+=",\"tokenQuerySucceeded\":"+std::string(b(f.queries))+",\"parentAppContainer\":"+JsonBoolean(f.parentAc)+",\"childAppContainer\":"+JsonBoolean(f.childAc)+",\"sidEqual\":"+JsonBoolean(f.equal)+",\"sidMatched\":"+b(f.matched);
 s+=",\"resumeAttempted\":"+std::string(b(f.resumeAttempt))+",\"resumeCount\":"+n(f.resume)+",\"resumed\":"+b(f.resumed)+",\"waitSignaled\":"+b(f.signaled)+",\"childExitCode\":"+n(f.exit);
 s+=",\"timedOut\":"+std::string(b(f.timeout))+",\"terminateAttempted\":"+b(f.terminate)+",\"terminationSucceeded\":"+b(f.terminated)+",\"cleanupConfirmed\":"+b(f.cleanup);
 s+=",\"childReportObserved\":"+std::string(b(f.report))+",\"childReportBytes\":"+std::to_string(f.reportBytes)+",\"childReportSha256\":"+JsonSid(f.reportHash)+",\"failure\":\""+f.failure+"\"}";return s;
}
int Run(int argc,wchar_t** argv) {
 bool profileOnly=false,mismatch=false,resumeFail=false,tokenFail=false;
#ifdef N0A_UDP_PARENT_TEST_ONLY
 profileOnly=argc==4&&std::wstring(argv[1])==L"--profile-only";
 mismatch=argc==10&&std::wstring(argv[1])==L"--test-sid-mismatch";
 resumeFail=argc==10&&std::wstring(argv[1])==L"--test-resume-failure";
 tokenFail=argc==10&&std::wstring(argv[1])==L"--test-token-failure";
#endif
 if(!profileOnly&&(argc!=10||(std::wstring(argv[1])!=L"n0a-udp-parent"&&!mismatch&&!resumeFail&&!tokenFail)))return 2;
 std::string nonce;std::wstring reportPath;
 if(!ReadNonce(argv[2],nonce)||!ReadReportPath(argv[3],reportPath))return 2;
 std::wstring childPath,childReport;std::string expected;DWORD port=0,budget=0;std::string phase="profile";
 if(!profileOnly){
  if(!ReadReportPath(argv[4],childPath)||!HashText(argv[5],expected)||!ReadReportPath(argv[6],childReport)
   ||!Number(argv[7],1025,65535,port)||!Number(argv[9],2001,15000,budget))return 2;
  const std::wstring p(argv[8]);if(p!=L"before"&&p!=L"sample"&&p!=L"contained"&&p!=L"after")return 2;
  phase=p==L"before"?"before":p==L"sample"?"sample":p==L"contained"?"contained":"after";if((phase=="before"||phase=="after")&&budget>5000)return 2;
  const auto slash=childPath.find_last_of(L"\\/");if(slash==std::wstring::npos||childPath.substr(slash+1)!=ChildName)return 2;
  std::array<wchar_t,4097> module{};
  const DWORD moduleLength=GetModuleFileNameW(nullptr,module.data(),static_cast<DWORD>(module.size()));
  if(moduleLength==0||moduleLength>=module.size())return 2;
  std::wstring ownPath;
  if(!ReadReportPath(module.data(),ownPath))return 2;
  const auto ownSlash=ownPath.find_last_of(L"\\");
  if(ownSlash==std::wstring::npos||_wcsicmp(ownPath.substr(0,ownSlash).c_str(),childPath.substr(0,slash).c_str())!=0)return 2;
  const auto reportSlash=reportPath.find_last_of(L"\\"),childReportSlash=childReport.find_last_of(L"\\");
  if(_wcsicmp(reportPath.substr(0,reportSlash).c_str(),childReport.substr(0,childReportSlash).c_str())!=0)return 2;
  const DWORD directoryAttributes=GetFileAttributesW(reportPath.substr(0,reportSlash).c_str());
  if(directoryAttributes==INVALID_FILE_ATTRIBUTES||!(directoryAttributes&FILE_ATTRIBUTE_DIRECTORY)
    ||(directoryAttributes&FILE_ATTRIBUTE_REPARSE_POINT))return 2;
  if(reportPath==childReport||childPath==childReport||childPath==reportPath)return 2;
 }
 const ULONGLONG deadline=GetTickCount64()+budget,workDeadline=profileOnly?deadline:deadline-2000;
 Handle output;output.value=CreateFileW(reportPath.c_str(),GENERIC_WRITE,0,nullptr,CREATE_NEW,FILE_ATTRIBUTE_NORMAL,nullptr);
 if(output.value==INVALID_HANDLE_VALUE)return 3;
 const Observations identity=ObserveNativeIdentity();Facts f;f.profile=Profile(identity,phase=="contained");
 Handle process,thread,binary;TokenView parentToken,childToken;
 try {
  if(profileOnly){f.failure="profile_only";}
  else if(!f.profile&&!TestOnly){f.failure="profile";}
  else {
   binary.value=CreateFileW(childPath.c_str(),GENERIC_READ,FILE_SHARE_READ,nullptr,OPEN_EXISTING,FILE_FLAG_OPEN_REPARSE_POINT,nullptr);
   std::vector<unsigned char> bytes;
   if(binary.value==INVALID_HANDLE_VALUE||!ReadOwnedFile(binary.value,64*1024*1024,bytes)||Sha(bytes)!=expected)throw std::runtime_error("child_hash");
   f.hash=true;
   if(GetFileAttributesW(childReport.c_str())!=INVALID_FILE_ATTRIBUTES||GetLastError()!=ERROR_FILE_NOT_FOUND)throw std::runtime_error("child_report_exists");
   if(!Remaining(workDeadline))throw std::runtime_error("deadline");
   std::wstring cmd=Quote(argv[4])+L" n0a-udp "+Quote(argv[2])+L" "+Quote(argv[6])+L" "+Quote(argv[7])+L" "+Quote(argv[8]);
   STARTUPINFOW si{};si.cb=sizeof(si);PROCESS_INFORMATION pi{};
   if(!CreateProcessW(childPath.c_str(),cmd.data(),nullptr,nullptr,FALSE,CREATE_SUSPENDED,nullptr,nullptr,&si,&pi))throw std::runtime_error("create");
   process.value=pi.hProcess;thread.value=pi.hThread;f.created=true;f.pid=pi.dwProcessId;
   if(tokenFail)throw std::runtime_error("token");
   if(!parentToken.read(GetCurrentProcess())||!childToken.read(process.value))throw std::runtime_error("token");
   f.queries=true;f.parentAc=parentToken.ac;f.childAc=childToken.ac;
   if(parentToken.ac&&childToken.ac&&parentToken.sid&&childToken.sid)f.equal=EqualSid(parentToken.sid,childToken.sid)!=FALSE;
   f.matched=phase=="contained"&&!TestOnly ? f.equal==true : (!parentToken.ac&&!childToken.ac&&!parentToken.sid&&!childToken.sid);
   if(mismatch)f.matched=false;
   if(!f.matched)throw std::runtime_error("sid");
   if(!Remaining(workDeadline))throw std::runtime_error("deadline");
   if(resumeFail)throw std::runtime_error("resume_fixture");
   f.resumeAttempt=true;f.resume=ResumeThread(thread.value);
   if(f.resume!=DWORD{1})throw std::runtime_error("resume");f.resumed=true;
   const DWORD wait=WaitForSingleObject(process.value,Remaining(workDeadline));
   if(wait==WAIT_TIMEOUT){f.timeout=true;throw std::runtime_error("timeout");}
   if(wait!=WAIT_OBJECT_0){f.cleanup=false;throw std::runtime_error("wait");}
   ObserveExit(process.value,f);if(!f.exit)throw std::runtime_error("exit");
  }
 } catch(const std::runtime_error& e) {
  // Only fixed literals thrown locally, never system error text.
  const std::string why=e.what();
  for(const char* known:{"child_hash","child_report_exists","deadline","create","token","sid","resume_fixture","resume","timeout","wait","exit","hash"})if(why==known)f.failure=known;
  if(std::string(f.failure)=="none")f.failure="internal";
 } catch(...) {f.failure="internal";}
 if(f.created){
  ObserveExit(process.value,f);
  if(!f.signaled){f.terminate=true;f.terminated=TerminateProcess(process.value,1)!=FALSE;
   if(!f.terminated)f.cleanup=false;
   const DWORD wait=WaitForSingleObject(process.value,Remaining(deadline));
   if(wait!=WAIT_OBJECT_0)f.cleanup=false;
   ObserveExit(process.value,f);}
  if(!f.signaled)f.cleanup=false;
  if(f.signaled){
   Handle childFile;childFile.value=CreateFileW(childReport.c_str(),GENERIC_READ,FILE_SHARE_READ,nullptr,OPEN_EXISTING,FILE_FLAG_OPEN_REPARSE_POINT,nullptr);
   std::vector<unsigned char> bytes;
   try{if(childFile.value!=INVALID_HANDLE_VALUE&&ReadOwnedFile(childFile.value,32768,bytes)){f.reportHash=Sha(bytes);f.reportBytes=bytes.size();f.report=true;}}catch(...){ }
   if(!childFile.close())f.cleanup=false;
  }
 }
 for(Handle* h:{&parentToken.token,&childToken.token,&thread,&process,&binary})if(!h->close())f.cleanup=false;
 std::string report=MakeReport("actor-n0a-udp-parent",nonce,identity,std::nullopt,std::nullopt);
 report.resize(report.size()-2);report+=",\"parent\":"+Json(f,phase)+"}\n";
 if(!WriteReport(output.value,report))return 3;
 if(!output.close())return 3;
 return (profileOnly||std::string(f.failure)=="none")&&f.cleanup?0:5;
}
}
int wmain(int argc,wchar_t** argv){try{return udp_parent::Run(argc,argv);}catch(...){return 6;}}
