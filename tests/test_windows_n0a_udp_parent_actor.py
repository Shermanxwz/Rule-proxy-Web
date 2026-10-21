"""Source contracts for socket-free native parent. Native Windows gate is separate."""
import hashlib
from pathlib import Path
import re
import unittest

ROOT=Path(__file__).resolve().parents[1]
NATIVE=ROOT/'.github/native'
SOURCE=(NATIVE/'windows_n0a_udp_parent.cpp').read_text()
CHILD=(NATIVE/'windows_n0a_udp_actor.cpp').read_text()
IDENTITY=(NATIVE/'windows_identity_actor.cpp').read_text()

class ParentSource(unittest.TestCase):
    def test_child_and_identity_unchanged(self):
        for name,digest in [('windows_n0a_udp_actor.cpp','dea64f0f25d60930be13c4f9e24b41f7535d1021476e6180d6bfe3361b40d0f2'),('windows_identity_actor.cpp','530482aae4c94707ae4da25c1c3e84d8da929a021fc23b09e59fec17fe28d553')]:
            self.assertEqual(hashlib.sha256((NATIVE/name).read_bytes()).hexdigest(),digest)
    def test_profile_exact_shared_semantics(self):
        def section(s):return s[s.index('bool PackageSid('):s.index('struct Attempt {') if 'struct Attempt {' in s else s.index('bool Number(')].strip()
        self.assertEqual(section(SOURCE),section(CHILD))
        self.assertIn('#define RULEPROXY_IDENTITY_ONLY 1',SOURCE)
    def test_socket_free_and_no_privilege_or_breakaway(self):
        for name in ['WSAStartup(', 'socket(', 'sendto(', 'recvfrom(', 'DnsQueryEx(', 'CreateProcessAsUser', 'CreateProcessWithToken', 'CREATE_BREAKAWAY_FROM_JOB', 'AssignProcessToJobObject', 'OpenProcess(']:
            self.assertNotIn(name,SOURCE)
    def test_strict_profile_before_creation(self):
        self.assertLess(SOURCE.index('f.profile=Profile('),SOURCE.index('CreateProcessW('))
        self.assertIn('else if(!f.profile&&!TestOnly)',SOURCE)
        self.assertIn('FALSE,CREATE_SUSPENDED,nullptr,nullptr',SOURCE)
        self.assertLess(SOURCE.index('process.value=pi.hProcess;thread.value=pi.hThread'),SOURCE.index('parentToken.read('))
    def test_sid_bounds_precede_validation_and_equal(self):
        read=SOURCE[SOURCE.index('struct TokenView'):SOURCE.index('struct Facts')]
        for text in ['needed>65536','got>needed','address<begin','got-static_cast<std::size_t>(address-begin)<header','count>SID_MAX_SUB_AUTHORITIES','header+count*sizeof(DWORD)>got','address%alignof(DWORD)']:
            self.assertIn(text,read)
            self.assertLess(read.index(text),read.index('IsValidSid(sid)'))
        self.assertIn('parentToken.ac&&childToken.ac&&parentToken.sid&&childToken.sid',SOURCE)
        self.assertIn('!parentToken.ac&&!childToken.ac&&!parentToken.sid&&!childToken.sid',SOURCE)
    def test_phase_mapping_and_resume_types_are_explicit(self):
        self.assertNotIn('phase.assign(p.begin()',SOURCE)
        self.assertIn('phase=p==L"before"?"before":p==L"sample"?"sample":p==L"contained"?"contained":"after";',SOURCE)
        self.assertIn('p!=L"before"&&p!=L"sample"&&p!=L"contained"&&p!=L"after"',SOURCE)
        self.assertIn('f.resume!=DWORD{1}',SOURCE)
    def test_one_resume_and_signaled_exit(self):
        self.assertEqual(SOURCE.count('ResumeThread('),1)
        self.assertIn('if(f.resume!=DWORD{1})',SOURCE)
        fn=SOURCE[SOURCE.index('void ObserveExit'):SOURCE.index('std::string Json(')]
        self.assertLess(fn.index('WAIT_OBJECT_0'),fn.index('GetExitCodeProcess'))
        self.assertNotIn('STILL_ACTIVE',SOURCE)
        self.assertIn('std::optional<DWORD> resume,exit',SOURCE)
    def test_deadlines_cleanup_and_no_bare_retry(self):
        self.assertIn('workDeadline=profileOnly?deadline:deadline-2000',SOURCE)
        self.assertIn('Number(argv[9],2001,15000,budget)',SOURCE)
        self.assertIn('budget>5000',SOURCE)
        self.assertIn('WaitForSingleObject(process.value,Remaining(workDeadline))',SOURCE)
        self.assertIn('WaitForSingleObject(process.value,Remaining(deadline))',SOURCE)
        self.assertEqual(SOURCE.count('TerminateProcess('),1)
        self.assertIn('const HANDLE old=value; value=nullptr;',SOURCE)
        self.assertIn('if(!f.signaled)f.cleanup=false',SOURCE)
        self.assertIn('if(observed==WAIT_FAILED)f.cleanup=false',SOURCE)
        self.assertIn('if(!f.terminated)f.cleanup=false',SOURCE)
        self.assertIn('if(wait!=WAIT_OBJECT_0)f.cleanup=false',SOURCE)
    def test_report_snapshot_bound_after_exit(self):
        self.assertIn('if(f.signaled){\n   Handle childFile',SOURCE)
        self.assertIn('ReadOwnedFile(childFile.value,32768,bytes)',SOURCE)
        self.assertIn('f.reportHash=Sha(bytes);f.reportBytes=bytes.size()',SOURCE)
        self.assertIn('FILE_FLAG_OPEN_REPARSE_POINT',SOURCE)
        self.assertIn('FILE_ATTRIBUTE_DIRECTORY|FILE_ATTRIBUTE_REPARSE_POINT',SOURCE)
        self.assertIn('CREATE_NEW',SOURCE)
        self.assertNotIn('childExitCode==0',SOURCE)
    def test_actual_child_cli_path_composition(self):
        # Identity validator prepends the extended prefix for I/O, which must not
        # be passed back to unchanged child's drive-letter-only CLI validator.
        self.assertIn('argument[1] != L\':\'',IDENTITY)
        self.assertIn(r'result.assign(L"\\\\?\\");',IDENTITY)
        self.assertIn('if(!ReadReportPath(module.data(),ownPath))return 2',SOURCE)
        self.assertIn('Quote(argv[4])+L" n0a-udp "+Quote(argv[2])+L" "+Quote(argv[6])',SOURCE)
        self.assertNotIn('Quote(childReport)',SOURCE)
    def test_child_fixed_sibling_and_report_directory(self):
        self.assertIn('childPath.substr(slash+1)!=ChildName',SOURCE)
        self.assertIn('GetModuleFileNameW(nullptr',SOURCE)
        self.assertIn('ownPath.substr(0,ownSlash)',SOURCE)
        self.assertIn('childPath.substr(0,slash)',SOURCE)
        self.assertIn('reportPath.substr(0,reportSlash).c_str(),childReport.substr(0,childReportSlash)',SOURCE)
        self.assertIn('FILE_SHARE_READ,nullptr,OPEN_EXISTING',SOURCE)
        self.assertIn('caller-supplied hash into a trust root',SOURCE)
    def test_fixture_seams_compile_only(self):
        conditional=SOURCE[SOURCE.index('#ifdef N0A_UDP_PARENT_TEST_ONLY',SOURCE.index('int Run(')):SOURCE.index('#endif',SOURCE.index('int Run('))]
        for option in ['--profile-only','--test-sid-mismatch','--test-resume-failure','--test-token-failure']:
            self.assertIn(option,conditional)
        self.assertIn('if(profileOnly){f.failure="profile_only";}',SOURCE)
        self.assertIn('if(resumeFail)throw std::runtime_error("resume_fixture")',SOURCE)
        self.assertIn('if(tokenFail)throw std::runtime_error("token")',SOURCE)
        self.assertEqual((NATIVE/'windows_n0a_udp_parent_fixture.cpp').read_text(),'#define N0A_UDP_PARENT_TEST_ONLY 1\n#include "windows_n0a_udp_parent.cpp"\n')
    def test_build_separation_pins_and_no_artifact(self):
        for fixture in [False,True]:
            suffix='_fixture' if fixture else ''
            s=(ROOT/f'.github/build_windows_n0a_udp_parent{suffix}.ps1').read_text()
            for field in ['ExpectedParentSha256','ExpectedChildSourceSha256','ExpectedIdentitySha256','parentSourceSha256','childActorSourceSha256','identitySourceSha256','executableSha256']:
                self.assertIn(field,s)
            self.assertIn("'/UN0A_UDP_PARENT_TEST_ONLY'",s)
            self.assertIn('Source changed during compilation',s)
            self.assertIn('Output directory must be new',s)
            self.assertNotIn('GITHUB_OUTPUT',s)
            self.assertNotIn('upload-artifact',s)
            if fixture:
                self.assertIn('testOnly=$true; deployable=$false',s)
                self.assertIn('PARENT-TEST-ONLY-manifest.json',s)
            else:
                self.assertIn('testOnly=$false; deployable=$true',s)
                self.assertIn('N0A-UDP-PARENT-manifest.json',s)

if __name__=='__main__': unittest.main()
