"""Work-only C DNS candidate: fake SDK calls and static barrier/schema checks."""
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import shutil
import subprocess
import tempfile
import unittest

ROOT=Path(__file__).resolve().parents[1]
NATIVE=ROOT/'.github/native'
spec=importlib.util.spec_from_file_location('standard_dns_candidate_fake',ROOT/'tests/test_windows_identity_dns_standard_native.py')
standard=importlib.util.module_from_spec(spec);spec.loader.exec_module(standard)


def compile_fake(source_text):
    compiler=shutil.which('cl.exe')
    if os.name!='nt' or not compiler:raise AssertionError('Windows SDK developer compiler required; no DNS call is made')
    with tempfile.TemporaryDirectory() as directory:
        work=Path(directory);source=work/'dns-fake.cpp';source.write_text(source_text,encoding='utf-8')
        executable=work/'dns-fake.exe'
        built=subprocess.run([compiler,'/nologo','/W4','/WX','/std:c++17','/EHsc','/MT','/O2','/I'+str(NATIVE),
            '/Fo'+str(work/'dns-fake.obj'),'/Fe'+str(executable),str(source)],cwd=work,capture_output=True,text=True,timeout=60)
        if built.returncode:raise AssertionError(built.stdout+built.stderr)
        ran=subprocess.run([str(executable)],cwd=work,capture_output=True,text=True,timeout=15)
        if ran.returncode:raise AssertionError(ran.stdout+ran.stderr)
        return ran.stdout


class DnsCandidateTests(unittest.TestCase):
    def test_same_official_constructor_and_fake_pending_lifetime_59_cases(self):
        self.assertIn('DNS_STANDARD_FAKE_SCENARIOS 59',compile_fake(standard.HARNESS))

    def test_phase_dns_closed_schema_keeps_success_error_pending_and_late_facts(self):
        actor=(NATIVE/'windows_identity_proxy_c_actor.cpp').read_text(encoding='utf-8')
        serializer=actor.split('// DNS_PHASE_REPORT_BEGIN:',1)[1]
        serializer=serializer[serializer.index('std::string dns_report('):serializer.index('// DNS_PHASE_REPORT_END')]
        source=standard.HARNESS.split('int main(){',1)[0]+'\nconst char* boolean(bool value){return value?"true":"false";}\n'+serializer+r'''
int main(){const std::string id(32,'a');Context configured;if(!configure(configured,id))return 1;
    std::printf("%llu\n",static_cast<unsigned long long>(configured.request.QueryOptions));
    {Fake api;std::puts(dns_report(id,query_with_api(api,id,10,1100)).c_str());}
    {Fake api;api.status=87;api.query_status=9003;api.records=0;std::puts(dns_report(id,query_with_api(api,id,10,1100)).c_str());}
    {Fake api;api.status=DNS_REQUEST_PENDING;std::puts(dns_report(id,query_with_api(api,id,10,1100)).c_str());}
    {Fake api;api.ticks={100,101,1100};std::puts(dns_report(id,query_with_api(api,id,10,1100)).c_str());}
    {Fake api;std::puts(dns_report(id,query_with_api(api,id,11,1100)).c_str());}
    return 0;
}
'''
        lines=compile_fake(source).splitlines();self.assertEqual(len(lines),6)
        options=int(lines[0]);rows=[json.loads(line) for line in lines[1:]]
        metadata={'server_constructor','server_address','server_port','query_name','query_type','query_options','result'}
        result_keys={'configured','called','completed','pending','answer_match','records_released','context_retained',
                     'within_deadline','api_status','query_status','record_count','start_qpc','end_qpc'}
        for row in rows:
            self.assertEqual(set(row),metadata);self.assertEqual(set(row['result']),result_keys)
            self.assertEqual(row['server_constructor'],'official-v1-zero-port')
            self.assertEqual((row['server_address'],row['server_port']),('127.0.0.1',53))
            self.assertEqual(row['query_name'],'a'*32+'.n0a.invalid');self.assertEqual(row['query_type'],1)
            self.assertEqual(row['query_options'],options)
        success,error,pending,late,uncalled=[row['result'] for row in rows]
        self.assertTrue(success['answer_match'] and success['within_deadline'] and success['records_released'])
        self.assertTrue(error['called'] and error['completed']);self.assertFalse(error['answer_match'])
        self.assertEqual((error['api_status'],error['query_status']),(87,9003))
        self.assertTrue(pending['pending'] and pending['context_retained']);self.assertFalse(pending['completed'] or pending['records_released'])
        self.assertTrue(late['answer_match'] and late['called'] and late['records_released']);self.assertFalse(late['within_deadline'])
        self.assertFalse(uncalled['called'] or uncalled['configured'])

    def test_dns_only_after_go_same_phase_deadline_and_no_ambient_fallback(self):
        source=(NATIVE/'windows_identity_proxy_c_actor.cpp').read_text(encoding='utf-8')
        client=source[source.index('int client('):source.index('struct ListenerFacts')]
        before,after=client.split('const auto state=command_file(',1)
        self.assertNotIn('ruleproxy_dns_standard::query(',before)
        self.assertLess(after.index('if(profile=="agentic-only")'),after.index('if(command.operation==6)'))
        self.assertLess(after.index('if(!fresh)'),after.index('if(command.operation==6)'))
        dns_branch=after.split('if(command.operation==6){',1)[1].split('}else{',1)[0]
        self.assertIn('query(item,clock.frequency,command.phase_deadline)',dns_branch)
        self.assertNotIn('Session ',dns_branch);self.assertNotIn('SocketAPI ',dns_branch)
        self.assertIn('dns.pending',dns_branch);self.assertIn('failure="dns-pending"',dns_branch)
        self.assertIn('failure="dns-config"',dns_branch)
        self.assertNotIn('answer_match',dns_branch)
        self.assertIn('observation=",\\"dns\\":"+dns_report(item,dns)',dns_branch)
        for forbidden in ('DnsCancelQuery(', 'DnsQuery_W(', 'SetInterfaceDnsSettings(', 'DnsQueryEx('):
            self.assertNotIn(forbidden,client)
        self.assertEqual(hashlib.sha256((NATIVE/'windows_identity_dns_standard_probe.hpp').read_bytes()).hexdigest(),
                         'bce69ff57a173525a9cff2731f4d05fe34b5144daeaa465b0d8bb5181432d28c')

    def test_build_closure_adds_exact_probe_pin_and_retains_compile_only(self):
        helper=(ROOT/'.github/build_windows_identity_proxy_c_actor.ps1').read_text(encoding='utf-8')
        self.assertIn('ExpectedDnsStandardProbeSha256',helper)
        self.assertIn("'windows_identity_dns_standard_probe.hpp'",helper)
        self.assertIn('dnsStandardProbeSha256=$hashes[7]',helper)
        self.assertIn('compileOnly=$true;runtimeAcceptance=$false',helper)
        self.assertIn('#pragma comment(lib,"dnsapi.lib")',(NATIVE/'windows_identity_dns_standard_probe.hpp').read_text())
        self.assertNotIn('& $exe',helper)


if __name__=='__main__':unittest.main()
