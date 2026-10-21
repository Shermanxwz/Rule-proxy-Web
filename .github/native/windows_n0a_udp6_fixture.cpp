// TEST ONLY compile entry. Never deploy this binary or manifest to a guest.
#define N0A_UDP6_TEST_ONLY 1
#define N0A_UDP6_FIXTURE_ENTRY 1
#include "windows_n0a_udp6_actor.cpp"

bool V6OnlyContract() {
    using n0a_udp6::Attempt;
    for(DWORD value:{DWORD{1},DWORD{2},DWORD{0xffffffff}}) {
        Attempt result;
        if(!n0a_udp6::ValidateV6Only(0,0,sizeof(DWORD),value,result)||!result.v6OnlyVerified
            ||result.v6OnlyGetValue!=value||result.v6OnlyGetError.has_value()
            ||std::string(result.v6OnlyGetStage)!="nonzero")return false;
    }
    for(int length:{0,1,3,5,8}) {
        Attempt result;
        if(n0a_udp6::ValidateV6Only(0,0,length,DWORD{1},result)||result.v6OnlyVerified
            ||result.v6OnlyGetValue.has_value()||result.v6OnlyGetError.has_value()
            ||result.win32Error!=0||std::string(result.failure)!="v6only_length")return false;
    }
    Attempt zero,error;
    if(n0a_udp6::ValidateV6Only(0,0,sizeof(DWORD),DWORD{0},zero)||zero.v6OnlyVerified
        ||zero.v6OnlyGetValue!=DWORD{0}||zero.v6OnlyGetError.has_value()
        ||zero.win32Error!=0||std::string(zero.failure)!="v6only_zero")return false;
    if(n0a_udp6::ValidateV6Only(SOCKET_ERROR,WSAEINVAL,sizeof(DWORD),DWORD{1},error)||error.v6OnlyVerified
        ||error.v6OnlyGetValue.has_value()||error.v6OnlyGetError!=DWORD{WSAEINVAL}
        ||error.win32Error!=WSAEINVAL||std::string(error.v6OnlyGetStage)!="api_error")return false;
    return true;
}

int wmain(int argc,wchar_t* argv[]) {
    try {
        if (argc==4 && std::wstring(argv[1])==L"--profile-only") {
            std::string nonce; std::wstring path;
            if (!ReadNonce(argv[2],nonce) || !ReadReportPath(argv[3],path)) return 2;
            UniqueHandle report(CreateFileW(path.c_str(),GENERIC_WRITE,0,nullptr,CREATE_NEW,FILE_ATTRIBUTE_NORMAL,nullptr));
            if (report.get()==INVALID_HANDLE_VALUE) return 3;
            const bool v6Contract=V6OnlyContract();
            const Observations identity=ObserveNativeIdentity();
            const bool ordinary=n0a_udp6::Profile(identity,false),contained=n0a_udp6::Profile(identity,true);
            std::string value=MakeReport("actor-n0a-udp6-profile",nonce,identity,std::nullopt,std::nullopt);
            value.resize(value.size()-2);
            value+=",\"profile\":{\"testOnly\":true,\"ordinaryMatched\":"+n0a_udp6::Bool(ordinary)+
                ",\"containedMatched\":"+n0a_udp6::Bool(contained)+",\"networkApiCalled\":false,\"v6OnlyContractVerified\":"+n0a_udp6::Bool(v6Contract)+"}}\n";
            if (!n0a_udp6::Report(report.get(),value)) return 3;
            return identity.errors.empty()&&v6Contract?0:4;
        }
        return n0a_udp6::Run(argc,argv);
    } catch (...) { return 6; }
}
