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

bool PeerContextContract() {
    using namespace n0a_udp6;
    MIB_IPINTERFACE_ROW ip{};ip.Family=AF_INET6;ip.InterfaceIndex=7;ip.InterfaceLuid.Value=9;
    ip.Connected=TRUE;ip.ZoneIndices[ScopeLevelSite]=3;
    MIB_IF_ROW2 nic{};nic.InterfaceIndex=7;nic.InterfaceLuid.Value=9;nic.OperStatus=IfOperStatusUp;
    nic.Type=IF_TYPE_ETHERNET_CSMACD;nic.PhysicalAddressLength=static_cast<ULONG>(ExpectedMac.size());
    std::memcpy(nic.PhysicalAddress,ExpectedMac.data(),ExpectedMac.size());
    InterfaceContext context;
    if(!InterfaceRows(7,ip,nic,context,false)||context.index!=7||context.luid.Value!=9||context.siteZone!=3)return false;
    for(int changed=0;changed<11;++changed) {
        auto badIp=ip;auto badNic=nic;InterfaceContext ignored;
        if(changed==0)badIp.Family=AF_INET;
        if(changed==1)badIp.InterfaceIndex=8;
        if(changed==2)badNic.InterfaceIndex=8;
        if(changed==3)badIp.InterfaceLuid.Value=0;
        if(changed==4)badNic.InterfaceLuid.Value=10;
        if(changed==5)badIp.Connected=FALSE;
        if(changed==6)badNic.OperStatus=IfOperStatusDown;
        if(changed==7)badNic.Type=IF_TYPE_SOFTWARE_LOOPBACK;
        if(changed==8)badNic.PhysicalAddressLength=5;
        if(changed==9)badNic.PhysicalAddress[0]^=1;
        if(changed==10)badIp.ZoneIndices[ScopeLevelSite]=0;
        if(InterfaceRows(7,badIp,badNic,ignored,false))return false;
    }
    InterfaceContext ignored;
    if(InterfaceRows(0,ip,nic,ignored,false))return false;
    ip.ZoneIndices[ScopeLevelSite]=0x10000000UL;
    if(InterfaceRows(7,ip,nic,ignored,false))return false;
    ip.ZoneIndices[ScopeLevelSite]=3;
    if(InterfaceRows(7,ip,nic,ignored,true))return false;
    nic.Type=IF_TYPE_SOFTWARE_LOOPBACK;
    if(!InterfaceRows(7,ip,nic,ignored,true))return false;
    for(int changed=0;changed<3;++changed) {
        InterfaceContext other=context;
        if(changed==0)++other.index;
        if(changed==1)++other.luid.Value;
        if(changed==2)++other.siteZone;
        if(StableInterface(context,other))return false;
    }
    if(!StableInterface(context,context))return false;
    IN6_ADDR site{};reinterpret_cast<unsigned char*>(&site)[0]=0xfe;reinterpret_cast<unsigned char*>(&site)[1]=0xc0;
    reinterpret_cast<unsigned char*>(&site)[15]=2;
    IN6_ADDR loopback{};reinterpret_cast<unsigned char*>(&loopback)[15]=1;
    if(!PeerScope(site,3,3,false)||!PeerScope(site,0x50000003UL,3,false)
        ||PeerScope(site,0,3,false)||PeerScope(site,4,3,false)||PeerScope(site,0x20000003UL,3,false)
        ||PeerScope(site,3,0,false)||PeerScope(site,3,0x10000000UL,false)
        ||!PeerScope(loopback,0,0,true)||PeerScope(loopback,3,3,true))return false;
    IN6_ADDR local{};
    reinterpret_cast<unsigned char*>(&local)[0]=0xfe;reinterpret_cast<unsigned char*>(&local)[1]=0xc0;
    reinterpret_cast<unsigned char*>(&local)[15]=15;
    if(!PacketDestination(local,false)||PacketDestination(local,true))return false;
    for(int kind=0;kind<4;++kind) {
        IN6_ADDR invalid{};auto* bytes=reinterpret_cast<unsigned char*>(&invalid);
        if(kind==1)bytes[15]=1;
        if(kind==2){bytes[10]=0xff;bytes[11]=0xff;bytes[15]=1;}
        if(kind==3)bytes[0]=0xff;
        if(PacketDestination(invalid,false))return false;
        if(PacketDestination(invalid,true)!=(kind==1))return false;
    }
    ControlStorage storage;storage.bytes.fill(0xa5); // Nonzero alignment padding is allowed.
    WSACMSGHDR header{};header.cmsg_len=WSA_CMSG_LEN(sizeof(IN6_PKTINFO));header.cmsg_level=IPPROTO_IPV6;header.cmsg_type=IPV6_PKTINFO;
    IN6_PKTINFO input{};input.ipi6_addr=local;input.ipi6_ifindex=7;
    std::memcpy(storage.bytes.data(),&header,sizeof(header));
    std::memcpy(storage.bytes.data()+WSA_CMSGDATA_ALIGN(sizeof(WSACMSGHDR)),&input,sizeof(input));
    WSAMSG message{};message.Control.buf=reinterpret_cast<char*>(storage.bytes.data());
    for(ULONG length=static_cast<ULONG>(WSA_CMSG_LEN(sizeof(IN6_PKTINFO)));length<=storage.bytes.size();++length) {
        message.Control.len=length;IN6_PKTINFO output{};
        if(!PacketInfo(message,storage,output)||output.ipi6_ifindex!=7||std::memcmp(&output.ipi6_addr,&local,sizeof(local))!=0)return false;
    }
    for(ULONG length:{ULONG{0},static_cast<ULONG>(sizeof(WSACMSGHDR)-1),static_cast<ULONG>(WSA_CMSG_LEN(sizeof(IN6_PKTINFO))-1),static_cast<ULONG>(ControlSize+1),ULONG{0xffffffff}}) {
        message.Control.len=length;IN6_PKTINFO output{};
        if(PacketInfo(message,storage,output))return false;
    }
    message.Control.len=static_cast<ULONG>(ControlSize);
    for(int changed=0;changed<6;++changed) {
        WSAMSG bad=message;ControlStorage changedStorage=storage;auto badHeader=header;
        bad.Control.buf=reinterpret_cast<char*>(changedStorage.bytes.data());
        if(changed==0)bad.dwFlags=MSG_TRUNC;
        if(changed==1)bad.dwFlags=MSG_CTRUNC;
        if(changed==2)badHeader.cmsg_len+=1;
        if(changed==3)badHeader.cmsg_level=IPPROTO_IP;
        if(changed==4)badHeader.cmsg_type=IPV6_HOPLIMIT;
        if(changed==5)bad.Control.buf=nullptr;
        std::memcpy(changedStorage.bytes.data(),&badHeader,sizeof(badHeader));IN6_PKTINFO output{};
        if(PacketInfo(bad,changedStorage,output))return false;
    }
    // Complete payload is an independent sticky fact, not context/peer proof.
    const std::string frame="fixed";
    for(int length:{-1,0,4,6}) {
        Attempt row;
        if(ObservePayload(length,frame.data(),frame,0,row)||row.nonceMatched)return false;
    }
    for(DWORD flags:{DWORD{MSG_TRUNC},DWORD{MSG_CTRUNC},DWORD{1}}) {
        Attempt row;if(ObservePayload(5,frame.data(),frame,flags,row)||row.nonceMatched)return false;
    }
    Attempt wrong;if(ObservePayload(5,"other",frame,0,wrong)||wrong.nonceMatched)return false;
    Attempt raw;if(!ObservePayload(5,frame.data(),frame,0,raw)||!raw.nonceMatched)return false;
    ContextCheck(raw,7,false);Error(raw,"interface_post",0);raw.closed=false;
    if(!raw.nonceMatched||raw.contextPassed!=0||raw.contextObserved!=128)return false;
    Attempt full;for(unsigned int bit=0;bit<9;++bit)ContextCheck(full,bit,true);
    if(!ContextCheck(full,9,full.contextObserved==511u&&full.contextPassed==511u)||full.contextPassed!=1023||full.contextObserved!=1023)return false;
    for(unsigned int missing=0;missing<9;++missing) {
        Attempt partial;
        for(unsigned int bit=0;bit<9;++bit)if(bit!=missing)ContextCheck(partial,bit,true);
        if(ContextCheck(partial,9,partial.contextObserved==511u&&partial.contextPassed==511u))return false;
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
            const bool contextContract=PeerContextContract();
            const Observations identity=ObserveNativeIdentity();
            const bool ordinary=n0a_udp6::Profile(identity,false),contained=n0a_udp6::Profile(identity,true);
            std::string value=MakeReport("actor-n0a-udp6-profile",nonce,identity,std::nullopt,std::nullopt);
            value.resize(value.size()-2);
            value+=",\"profile\":{\"testOnly\":true,\"ordinaryMatched\":"+n0a_udp6::Bool(ordinary)+
                ",\"containedMatched\":"+n0a_udp6::Bool(contained)+",\"networkApiCalled\":false,\"v6OnlyContractVerified\":"+n0a_udp6::Bool(v6Contract)+",\"echoPeerContractVerified\":"+n0a_udp6::Bool(peerContract)+",\"peerContextContractVerified\":"+n0a_udp6::Bool(contextContract)+"}}\n";
            if (!n0a_udp6::Report(report.get(),value)) return 3;
            return identity.errors.empty()&&v6Contract&&peerContract&&contextContract?0:4;
        }
        return n0a_udp6::Run(argc,argv);
    } catch (...) { return 6; }
}
