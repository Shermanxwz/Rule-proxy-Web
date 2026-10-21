// TEST ONLY compile entry. Never deploy this binary or manifest to a guest.
#define N0A_UDP6_TEST_ONLY 1
#define N0A_UDP6_FIXTURE_ENTRY 1
#include "windows_n0a_udp6_actor.cpp"

bool V6OnlyContract() {
    using n0a_udp6::Attempt;
    for(DWORD value:{DWORD{0},DWORD{1},DWORD{2},DWORD{0xffffffff}}) {
        std::array<unsigned char,sizeof(DWORD)> storage{};
        std::memcpy(storage.data(),&value,sizeof(value));
        Attempt result;
        const bool accepted=n0a_udp6::ValidateV6Only(0,0,sizeof(DWORD),storage,result);
        if(accepted!=(value!=0)||result.v6OnlyVerified!=accepted
            ||result.v6OnlyGetValue!=value||result.v6OnlyGetError.has_value()
            ||std::string(result.v6OnlyGetStage)!=(accepted?"nonzero":"zero"))return false;
    }
    // Poison every unreturned byte: a one-byte zero must not become true.
    for(unsigned char first:{static_cast<unsigned char>(0),static_cast<unsigned char>(1),static_cast<unsigned char>(255)}) {
        const std::array<unsigned char,sizeof(DWORD)> storage={first,0xa5,0xff,0x7e};
        Attempt result;
        const bool accepted=n0a_udp6::ValidateV6Only(0,0,1,storage,result);
        if(accepted!=(first!=0)||result.v6OnlyVerified!=accepted
            ||result.v6OnlyGetValue!=static_cast<DWORD>(first)||result.v6OnlyGetError.has_value()
            ||std::string(result.v6OnlyGetStage)!=(accepted?"nonzero":"zero"))return false;
    }
    const std::array<unsigned char,sizeof(DWORD)> poison={0xff,0xa5,0x7e,0xff};
    for(int length:{-1,0,2,3,5,8,2147483647}) {
        Attempt result;
        if(n0a_udp6::ValidateV6Only(0,0,length,poison,result)||result.v6OnlyVerified
            ||result.v6OnlyGetValue.has_value()||result.v6OnlyGetError.has_value()
            ||result.win32Error!=0||std::string(result.failure)!="v6only_length")return false;
    }
    for(int length:{-1,0,1,4,5}) {
        Attempt error;
        if(n0a_udp6::ValidateV6Only(SOCKET_ERROR,WSAEINVAL,length,poison,error)||error.v6OnlyVerified
            ||error.v6OnlyGetValue.has_value()||error.v6OnlyGetError!=DWORD{WSAEINVAL}
            ||error.win32Error!=WSAEINVAL||std::string(error.v6OnlyGetStage)!="api_error")return false;
    }
    return true;
}

bool EchoPeerContract() {
    using n0a_udp6::Attempt;
    sockaddr_in6 sender{},remote{};
    remote.sin6_port=32123;sender.sin6_port=remote.sin6_port;sender.sin6_family=AF_INET6;
    std::memcpy(&sender.sin6_addr,n0a_udp6::Destination.data(),n0a_udp6::Destination.size());
    const auto unavailable=[](const Attempt& result) {
        return !result.echoPeerFamilyMatched.has_value()&&!result.echoPeerPortMatched.has_value()
            &&!result.echoPeerScopeZero.has_value()&&!result.echoPeerNotV4Mapped.has_value()&&!result.echoPeerAddressMatched.has_value();
    };
    Attempt initial,error;
    if(initial.echoPeerLengthMatched.has_value()||!unavailable(initial))return false;
    n0a_udp6::ObserveEchoPeer(SOCKET_ERROR,sizeof(sender),sender,remote,error);
    if(error.echoPeerLengthMatched.has_value()||!unavailable(error))return false;
    for(int length:{-1,static_cast<int>(sizeof(sender))+1,2147483647}) {
        Attempt result;n0a_udp6::ObserveEchoPeer(1,length,sender,remote,result);
        if(result.echoPeerLengthMatched!=false||!unavailable(result))return false;
    }
    for(int length=0;length<=static_cast<int>(sizeof(sender));++length) {
        Attempt result;n0a_udp6::ObserveEchoPeer(1,length,sender,remote,result);
        const std::size_t available=static_cast<std::size_t>(length);
        if(result.echoPeerLengthMatched!=(length==static_cast<int>(sizeof(sender)))
            ||result.echoPeerFamilyMatched.has_value()!=(available>=offsetof(sockaddr_in6,sin6_family)+sizeof(sender.sin6_family))
            ||result.echoPeerPortMatched.has_value()!=(available>=offsetof(sockaddr_in6,sin6_port)+sizeof(sender.sin6_port))
            ||result.echoPeerScopeZero.has_value()!=(available>=offsetof(sockaddr_in6,sin6_scope_id)+sizeof(sender.sin6_scope_id))
            ||result.echoPeerAddressMatched.has_value()!=(available>=offsetof(sockaddr_in6,sin6_addr)+sizeof(sender.sin6_addr))
            ||result.echoPeerNotV4Mapped.has_value()!=result.echoPeerAddressMatched.has_value())return false;
        for(const auto& value:{result.echoPeerFamilyMatched,result.echoPeerPortMatched,result.echoPeerScopeZero,result.echoPeerNotV4Mapped,result.echoPeerAddressMatched})
            if(value.has_value()&&!*value)return false;
    }
    for(int changed=0;changed<5;++changed) {
        sockaddr_in6 altered=sender;Attempt result;
        if(changed==0)altered.sin6_family=AF_INET;
        if(changed==1)altered.sin6_port=32124;
        if(changed==2)altered.sin6_scope_id=1;
        if(changed==3) {
            const std::array<unsigned char,16> mapped={0,0,0,0,0,0,0,0,0,0,0xff,0xff,127,0,0,1};
            std::memcpy(&altered.sin6_addr,mapped.data(),mapped.size());
        }
        if(changed==4)reinterpret_cast<unsigned char*>(&altered.sin6_addr)[0]^=0x40;
        n0a_udp6::ObserveEchoPeer(1,sizeof(altered),altered,remote,result);
        if(result.echoPeerLengthMatched!=true||result.echoPeerFamilyMatched!=(changed!=0)
            ||result.echoPeerPortMatched!=(changed!=1)||result.echoPeerScopeZero!=(changed!=2)
            ||result.echoPeerNotV4Mapped!=(changed!=3)||result.echoPeerAddressMatched!=(changed!=3&&changed!=4))return false;
    }
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
            const bool peerContract=EchoPeerContract();
            const Observations identity=ObserveNativeIdentity();
            const bool ordinary=n0a_udp6::Profile(identity,false),contained=n0a_udp6::Profile(identity,true);
            std::string value=MakeReport("actor-n0a-udp6-profile",nonce,identity,std::nullopt,std::nullopt);
            value.resize(value.size()-2);
            value+=",\"profile\":{\"testOnly\":true,\"ordinaryMatched\":"+n0a_udp6::Bool(ordinary)+
                ",\"containedMatched\":"+n0a_udp6::Bool(contained)+",\"networkApiCalled\":false,\"v6OnlyContractVerified\":"+n0a_udp6::Bool(v6Contract)+",\"echoPeerContractVerified\":"+n0a_udp6::Bool(peerContract)+"}}\n";
            if (!n0a_udp6::Report(report.get(),value)) return 3;
            return identity.errors.empty()&&v6Contract&&peerContract?0:4;
        }
        return n0a_udp6::Run(argc,argv);
    } catch (...) { return 6; }
}
