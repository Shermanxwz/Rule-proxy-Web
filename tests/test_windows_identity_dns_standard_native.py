"""Standard DNS native constructor/fake API only; never calls DnsQueryEx."""
import hashlib
import os
from pathlib import Path
import shutil
import subprocess
import tempfile
import unittest

ROOT=Path(__file__).resolve().parents[1]
NATIVE=ROOT/'.github/native'
HARNESS=r'''
#include "windows_identity_dns_standard_probe.hpp"
#include <array>
#include <cstdio>
#include <cwchar>
#include <vector>
using namespace ruleproxy_dns_standard;
unsigned scenarios=0;
bool require(bool good,const char* label){++scenarios;if(!good)std::printf("FAIL %s\n",label);return good;}
struct Fake {
    std::uint64_t actual=10;bool frequency_ok=true;int fail_tick=-1;unsigned ticks_read=0,calls=0,frees=0;
    std::vector<std::uint64_t> ticks{100,101,102};DWORD status=0,query_status=0;unsigned records=1;
    bool alias=false,wrong_ip=false,wrong_type=false;std::array<DNS_RECORD,17> rows{};
    std::wstring name=std::wstring(32,L'a')+L".n0a.invalid";
    DNS_QUERY_REQUEST* request_seen=nullptr;DNS_QUERY_RESULT* result_seen=nullptr;
    bool frequency(std::uint64_t& value){value=actual;return frequency_ok;}
    bool qpc(std::uint64_t& value){const auto index=ticks_read++;if(static_cast<int>(index)==fail_tick)return false;
        if(index>=ticks.size())return false;value=ticks[index];return true;}
    DNS_STATUS call(DNS_QUERY_REQUEST& request,DNS_QUERY_RESULT& result){
        ++calls;request_seen=&request;result_seen=&result;result.QueryStatus=query_status;
        for(unsigned i=0;i<records&&i<rows.size();++i){auto& row=rows[i];row.pName=const_cast<PWSTR>(alias?L"wrong.n0a.invalid":name.c_str());
            row.wType=wrong_type?DNS_TYPE_CNAME:DNS_TYPE_A;row.wDataLength=sizeof(DNS_A_DATA);
            const unsigned char address[4]={192,0,2,static_cast<unsigned char>(wrong_ip?124:123)};
            std::memcpy(&row.Data.A.IpAddress,address,4);row.pNext=i+1<records?&rows[i+1]:nullptr;}
        result.pQueryRecords=records?rows.data():nullptr;return static_cast<DNS_STATUS>(status);
    }
    void free_records(PDNS_RECORD value)noexcept{if(value==rows.data())++frees;}
    bool equal_name(PCWSTR left,PCWSTR right){return std::wcscmp(left,right)==0;}
};
int main(){bool good=true;const std::string id(32,'a');
    Context context;std::memset(&context.servers,0xa5,sizeof(context.servers));
    good=require(configure(context,id),"fixed-constructor")&&good;
    DNS_ADDR_ARRAY expected{};std::memset(&expected,0,sizeof(expected));expected.MaxCount=1;expected.AddrCount=1;
    sockaddr_in address{};address.sin_family=AF_INET;const unsigned char loopback[4]={127,0,0,1};
    std::memcpy(&address.sin_addr,loopback,4);std::memcpy(expected.AddrArray[0].MaxSa,&address,sizeof(address));
    good=require(std::memcmp(&context.servers,&expected,sizeof(expected))==0,"all-array-family-port-reserved-bytes")&&good;
    DNS_QUERY_REQUEST expected_request{};std::memset(&expected_request,0,sizeof(expected_request));
    expected_request.Version=DNS_QUERY_REQUEST_VERSION1;expected_request.QueryName=context.name.c_str();expected_request.QueryType=DNS_TYPE_A;
    expected_request.QueryOptions=DNS_QUERY_BYPASS_CACHE|DNS_QUERY_NO_HOSTS_FILE|DNS_QUERY_NO_LOCAL_NAME|
        DNS_QUERY_NO_NETBT|DNS_QUERY_WIRE_ONLY|DNS_QUERY_NO_MULTICAST|DNS_QUERY_TREAT_AS_FQDN;
    expected_request.pDnsServerList=&context.servers;
    good=require(std::memcmp(&context.request,&expected_request,sizeof(expected_request))==0,"all-request-pointer-callback-options-bytes")&&good;
    DNS_QUERY_RESULT expected_result{};std::memset(&expected_result,0,sizeof(expected_result));expected_result.Version=DNS_QUERY_RESULTS_VERSION1;
    good=require(std::memcmp(&context.response,&expected_result,sizeof(expected_result))==0,"all-result-initialization-bytes")&&good;
    for(unsigned i=0;i<32;++i){auto bad=id;bad[i]='g';Fake api;const auto result=query_with_api(api,bad,10,1100);
        good=require(!result.configured&&!result.called&&api.calls==0,"invalid-nonce-never-call")&&good;}
    for(const auto frequency:std::array<std::uint64_t,3>{0,11,1000000001ULL}){Fake api;
        const auto result=query_with_api(api,id,frequency,1100);good=require(!result.called&&api.calls==0,"frequency-no-call")&&good;}
    for(const auto deadline:std::array<std::uint64_t,4>{0,100,1301,0xffffffffffffffffULL}){Fake api;
        const auto result=query_with_api(api,id,10,deadline);good=require(!result.called&&api.calls==0,"deadline-no-renewal")&&good;}
    for(int index=0;index<2;++index){Fake api;api.fail_tick=index;const auto result=query_with_api(api,id,10,1100);
        good=require(!result.called&&api.calls==0,"precall-clock-failure")&&good;}
    {Fake api;api.ticks={100,99,102};const auto result=query_with_api(api,id,10,1100);
        good=require(result.configured&&!result.called&&api.calls==0,"precall-backward-no-call")&&good;}
    {Fake api;const auto result=query_with_api(api,id,10,1100);
        good=require(result.configured&&result.called&&result.completed&&!result.pending&&result.answer_match
            &&result.records_released&&!result.context_retained&&result.within_deadline&&result.record_count==1
            &&api.calls==1&&api.frees==1,"one-canonical-answer-single-free")&&good;}
    for(unsigned condition=0;condition<6;++condition){Fake api;
        if(condition==0)api.alias=true;if(condition==1)api.wrong_ip=true;if(condition==2)api.wrong_type=true;
        if(condition==3)api.records=0;if(condition==4)api.records=2;if(condition==5)api.records=17;
        const auto result=query_with_api(api,id,10,1100);
        good=require(result.called&&result.completed&&!result.answer_match&&result.records_released
            &&result.record_count<=16&&api.calls==1&&api.frees==(api.records?1u:0u),"noncanonical-bounded-free")&&good;}
    {Fake api;api.status=87;api.query_status=9003;api.records=0;const auto result=query_with_api(api,id,10,1100);
        good=require(result.called&&result.completed&&!result.answer_match&&result.api_status==87&&result.query_status==9003
            &&result.records_released&&api.calls==1,"api-failure-is-observation-no-retry")&&good;}
    for(unsigned condition=0;condition<3;++condition){Fake api;
        if(condition==0)api.ticks={100,101,1100};if(condition==1)api.ticks={100,101,99};if(condition==2)api.fail_tick=2;
        const auto result=query_with_api(api,id,10,1100);
        good=require(result.called&&result.completed&&result.answer_match&&!result.within_deadline&&result.records_released
            &&api.calls==1&&api.frees==1,"late-or-unknown-clock-keeps-actual-answer")&&good;}
    for(unsigned condition=0;condition<2;++condition){Fake api;api.status=DNS_REQUEST_PENDING;api.query_status=1234;
        if(condition)api.fail_tick=2;const auto result=query_with_api(api,id,10,1100);
        good=require(result.called&&!result.completed&&result.pending&&!result.answer_match&&!result.records_released
            &&result.context_retained&&result.query_status==0&&result.record_count==0&&api.calls==1&&api.frees==0
            &&api.request_seen&&api.result_seen&&api.request_seen->pDnsServerList->MaxCount==1
            &&api.request_seen->pDnsServerList->Family==0&&api.request_seen->pQueryCompletionCallback==nullptr
            &&api.request_seen->pQueryContext==nullptr&&api.request_seen->QueryName
            &&std::wcscmp(api.request_seen->QueryName,api.name.c_str())==0&&api.result_seen->Version==DNS_QUERY_RESULTS_VERSION1,
            "pending-retains-entire-live-context-no-record-free-or-retry")&&good;
        // Deliberately retained until fake process exit, just like unknown native pending.
    }
    std::printf("DNS_STANDARD_FAKE_SCENARIOS %u\n",scenarios);return good?0:1;
}
'''


class StandardDnsNativeTests(unittest.TestCase):
    def test_compiled_official_constructor_fake_clock_api_and_complete_pending_lifetime(self):
        self.assertEqual(os.name,'nt','Windows SDK struct layout is required; no DNS call is made')
        compiler=shutil.which('cl.exe');self.assertIsNotNone(compiler,'use installed x64 developer compiler shell')
        with tempfile.TemporaryDirectory() as directory:
            root=Path(directory);source=root/'standard-dns-fake.cpp';source.write_text(HARNESS,encoding='utf-8')
            executable=root/'standard-dns-fake.exe'
            command=[compiler,'/nologo','/W4','/WX','/std:c++17','/EHsc','/MT','/O2','/I'+str(NATIVE),
                '/Fo'+str(root/'standard-dns-fake.obj'),'/Fe'+str(executable),str(source)]
            built=subprocess.run(command,cwd=root,capture_output=True,text=True,timeout=60)
            self.assertEqual(built.returncode,0,built.stdout+built.stderr)
            ran=subprocess.run([str(executable)],cwd=root,capture_output=True,text=True,timeout=15)
            self.assertEqual(ran.returncode,0,ran.stdout+ran.stderr)
            self.assertIn('DNS_STANDARD_FAKE_SCENARIOS 59',ran.stdout)

    def test_actor_has_no_port_argument_and_fixed_distinct_stage(self):
        source=(NATIVE/'windows_identity_dns_standard_actor.cpp').read_text()
        self.assertIn('if(argc!=4)return 2;',source)
        self.assertNotIn('argv[4]',source)
        self.assertIn('dns-standard-native',source)
        self.assertIn('server_constructor',source)
        self.assertIn('tokenCapabilities.empty()',source)
        self.assertIn('identity.isProcessInJob!=std::optional<bool>(true)',source)
        probe=(NATIVE/'windows_identity_dns_standard_probe.hpp').read_text()
        self.assertIn('official-v1-zero-port',probe)
        self.assertNotIn('context.servers.Family=',probe)
        self.assertNotIn('htons(',probe)
        self.assertNotIn('49153',probe)
        self.assertIn('DnsQueryEx(&request,&response,nullptr)',probe)
        self.assertNotIn('DnsCancelQuery(',probe)

    def test_manifest_pins_only_new_profile_and_identity_and_never_executes_actor(self):
        helper=(ROOT/'.github/build_windows_identity_dns_standard_actor.ps1').read_text()
        for name in ('windows_identity_dns_standard_actor.cpp','windows_identity_dns_standard_probe.hpp','windows_identity_actor.cpp'):
            self.assertIn(name,helper)
        for flag in ('/W4','/WX','/MT','/guard:cf'):
            self.assertIn(flag,helper)
        self.assertIn('identity-dns-standard-manifest.json',helper)
        self.assertIn('compileOnly=$true;runtimeAcceptance=$false',helper)
        self.assertNotIn('& $exe',helper)


if __name__=='__main__':unittest.main()
