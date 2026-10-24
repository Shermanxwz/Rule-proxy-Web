// TEST ONLY: direct call to the production socket primitive, not identity/isolation proof.
// This binary is never copied to a guest payload or invoked by the production actor.
#define RULEPROXY_N0A_FIXTURE 1
#include "windows_n0a_actor.cpp"
#include <cstdio>
int wmain(int argc,wchar_t* argv[]) {
    try {
        if (argc==2 && std::wstring(argv[1])==L"--profile-contract") {
            const HMODULE module=GetModuleHandleW(L"kernelbase.dll");
            if (!module) return 4;
            using Derive=BOOL(WINAPI*)(LPCWSTR,PSID**,DWORD*,PSID**,DWORD*);
            const FARPROC address=GetProcAddress(module,"DeriveCapabilitySidsFromName");
            Derive derive=nullptr; static_assert(sizeof(derive)==sizeof(address),"function pointer size");
            std::memcpy(&derive,&address,sizeof(derive)); if (!derive) return 4;
            n0a::SidArrays ids;
            if (!derive(L"AgenticAppContainer",&ids.groups,&ids.groupCount,&ids.capabilities,&ids.capabilityCount)
                || ids.capabilityCount!=1 || !ids.capabilities) return 4;
            LPSTR text=nullptr; if (!ConvertSidToStringSidA(ids.capabilities[0],&text)) return 4;
            const std::string sid(text); LocalFree(text);
            Observations value; value.pid=1; value.tokenIsAppContainer=true;
            value.tokenAppContainerSid="S-1-15-2-1-2-3-4-5-6-7";
            value.tokenElevated=false; value.isProcessInJob=true;
            value.tokenCapabilities={Capability{sid,4}};
            unsigned int checks=0;
            if (!n0a::Profile(value,true)) return 5; ++checks;
            for (DWORD mask: {0UL,2UL,6UL,16UL,0xffffffffUL}) {
                value.tokenCapabilities[0].attributes=mask;
                if (n0a::Profile(value,true)) return 5; ++checks;
            }
            value.tokenCapabilities={Capability{sid,4},Capability{sid,4}};
            if (n0a::Profile(value,true)) return 5; ++checks;
            value.tokenCapabilities={Capability{"S-1-15-3-1",4}};
            if (n0a::Profile(value,true)) return 5; ++checks;
            value.tokenCapabilities={Capability{sid,4}}; value.tokenElevated=true;
            if (n0a::Profile(value,true)) return 5; ++checks;
            value.tokenElevated=false; value.isProcessInJob=false;
            if (n0a::Profile(value,true)) return 5; ++checks;
            value.isProcessInJob=true; value.tokenIsAppContainer=false;
            value.tokenAppContainerSid=std::nullopt; value.tokenCapabilities.clear();
            if (!n0a::Profile(value,false) || n0a::Profile(value,true)) return 5; ++checks;
            value.errors.push_back(QueryError{"TokenCapabilities",5});
            if (n0a::Profile(value,false)) return 5; ++checks;
            const std::string output="{\"profile_checks\":"+std::to_string(checks)+",\"synthetic_identity\":true}";
            if (std::fwrite(output.data(),1,output.size(),stdout)!=output.size()) return 3;
            return 0;
        }
        if (argc==2 && std::wstring(argv[1])==L"--report-shape") {
            Observations identity=ObserveNativeIdentity();
            // Composition stress only: maximum legacy SID text/count bounds,
            // not a token observation and never used for profile acceptance.
            identity.tokenUserSid=std::string(kMaxSidText,'9');
            identity.tokenAppContainerSid=std::string(kMaxSidText,'9');
            identity.tokenCapabilities.assign(kMaxCapabilities,Capability{std::string(kMaxSidText,'9'),0xffffffffUL});
            std::vector<n0a::Attempt> attempts(40);
            for (unsigned int i=0;i<40;++i) {
                auto& a=attempts[i]; a.index=i; a.attempted=true; a.bindSucceeded=true;
                a.localPort=65535; a.localIpv4=0xffffffffUL;
                a.connectStartQpc=9223372036854775805LL; a.connectEndQpc=9223372036854775806LL;
                a.exchangeEndQpc=9223372036854775807LL; a.win32Error=10013; a.failure="getsockopt_error";
            }
            const std::string output=n0a::MakeN0aReport(identity,"0123456789abcdef0123456789abcdef",false,false,true,65535,false,10013,1000000000,1,9223372036854775807LL,attempts);
            if (output.size()>n0a::MaxReport || std::fwrite(output.data(),1,output.size(),stdout)!=output.size()) return 3;
            return 0;
        }
        if (argc!=3 || std::wstring(argv[1])!=L"--owned-loopback-fixture") return 2;
        unsigned int port=0; if (!n0a::Port(argv[2],port)) return 2;
        n0a::Wsa wsa; WSADATA data{}; if (WSAStartup(MAKEWORD(2,2),&data)!=0) return 4; wsa.active=true;
        const std::string frame="N0A1 0123456789abcdef0123456789abcdef guest ordinary\n";
        const auto result=n0a::Probe(0,false,port,frame,GetTickCount64()+1000);
        const Observations identity=ObserveNativeIdentity();
        const std::string output=n0a::MakeN0aReport(identity,"0123456789abcdef0123456789abcdef",false,false,false,port,false,0,
            n0a::Frequency(),result.connectStartQpc,result.exchangeEndQpc,std::vector<n0a::Attempt>{result});
        if (std::fwrite(output.data(),1,output.size(),stdout)!=output.size()) return 3;
        return 0;
    } catch (...) { return 6; }
}
