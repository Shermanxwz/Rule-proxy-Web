// TEST ONLY compile entry. Never deploy this binary or manifest to a guest.
#define N0A_UDP_TEST_ONLY 1
#define N0A_UDP_FIXTURE_ENTRY 1
#include "windows_n0a_udp_actor.cpp"

int wmain(int argc,wchar_t* argv[]) {
    try {
        if (argc==4 && std::wstring(argv[1])==L"--profile-only") {
            std::string nonce; std::wstring path;
            if (!ReadNonce(argv[2],nonce) || !ReadReportPath(argv[3],path)) return 2;
            UniqueHandle report(CreateFileW(path.c_str(),GENERIC_WRITE,0,nullptr,CREATE_NEW,FILE_ATTRIBUTE_NORMAL,nullptr));
            if (report.get()==INVALID_HANDLE_VALUE) return 3;
            const Observations identity=ObserveNativeIdentity();
            const bool ordinary=n0a_udp::Profile(identity,false),contained=n0a_udp::Profile(identity,true);
            std::string value=MakeReport("actor-n0a-udp-profile",nonce,identity,std::nullopt,std::nullopt);
            value.resize(value.size()-2);
            value+=",\"profile\":{\"testOnly\":true,\"ordinaryMatched\":"+n0a_udp::Bool(ordinary)+
                ",\"containedMatched\":"+n0a_udp::Bool(contained)+",\"networkApiCalled\":false}}\n";
            if (!n0a_udp::Report(report.get(),value)) return 3;
            return identity.errors.empty()?0:4;
        }
        return n0a_udp::Run(argc,argv);
    } catch (...) { return 6; }
}
