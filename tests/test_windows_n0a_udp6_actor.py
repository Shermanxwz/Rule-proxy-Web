"""Source/binding guards only; actual Winsock semantics require the Windows gate."""
import hashlib
import pathlib
import re
import unittest

ROOT = pathlib.Path(__file__).resolve().parents[1]
ACTOR = ROOT / '.github/native/windows_n0a_udp6_actor.cpp'
IDENTITY_HASH = '530482aae4c94707ae4da25c1c3e84d8da929a021fc23b09e59fec17fe28d553'


def function(source, name):
    match = re.search(r'\b' + name + r'\([^;]*?\)\s*\{', source)
    if not match:
        raise AssertionError(name)
    begin = match.end() - 1
    depth = 0
    for index in range(begin, len(source)):
        depth += (source[index] == '{') - (source[index] == '}')
        if not depth:
            return source[match.start():index + 1]
    raise AssertionError('unclosed')


class Udp6ActorSourceTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.source = ACTOR.read_text()

    def test_unchanged_identity_and_profile(self):
        identity = ROOT / '.github/native/windows_identity_actor.cpp'
        self.assertEqual(hashlib.sha256(identity.read_bytes()).hexdigest(), IDENTITY_HASH)
        tcp = (ROOT / '.github/native/windows_n0a_actor.cpp').read_text()
        for name in ('Port', 'PackageSid', 'Agentic', 'Profile'):
            self.assertEqual(function(self.source, name), function(tcp, name))

    def test_fixed_endpoint_no_dns_or_proxy(self):
        self.assertIn('Destination = {0xfe,0xc0,0,0,0,0,0,0,0,0,0,0,0,0,0,2}', self.source)
        self.assertIn('Destination = {0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,1}', self.source)
        self.assertIn('std::memcpy(&remote.sin6_addr,Destination.data(),Destination.size())', self.source)
        self.assertNotIn('socket(AF_INET,',self.source)
        self.assertNotIn('sockaddr_in ',self.source)
        self.assertIn('socket(AF_INET6,SOCK_DGRAM,IPPROTO_UDP)',self.source)
        for forbidden in ('DnsQuery', 'getaddrinfo(', 'gethostbyname(', 'SO_BROADCAST', 'SO_REUSEADDR', 'connect('):
            self.assertNotIn(forbidden, self.source)
        self.assertIn('argc!=6', self.source)

    def test_production_guard_before_network(self):
        run = function(self.source, 'Run')
        self.assertLess(run.index('ObserveNativeIdentity()'), run.index('Profile(identity,contained)'))
        self.assertLess(run.index('if (profile || TestOnly)'), run.index('WSAStartup('))
        self.assertLess(run.index('WSAStartup('), run.index('Probe('))
        self.assertNotIn('fixture', run.split('UniqueHandle report')[0])

    def test_test_only_entry_is_separate(self):
        fixture = (ROOT / '.github/native/windows_n0a_udp6_fixture.cpp').read_text()
        self.assertIn('#define N0A_UDP6_TEST_ONLY 1', fixture)
        self.assertIn('#include "windows_n0a_udp6_actor.cpp"', fixture)
        self.assertNotIn('#define N0A_UDP6_TEST_ONLY', self.source)
        self.assertIn('"fixture-loopback-v6":"runner-v6"', self.source)

    def test_fixture_profile_only_never_enters_network_run(self):
        fixture = (ROOT / '.github/native/windows_n0a_udp6_fixture.cpp').read_text()
        profile = fixture.split('if (argc==4')[1].split('return n0a_udp6::Run')[0]
        self.assertIn('ObserveNativeIdentity()', profile)
        self.assertIn('n0a_udp6::Profile(identity,false)', profile)
        self.assertIn('n0a_udp6::Profile(identity,true)', profile)
        self.assertIn('return identity.errors.empty()&&v6Contract&&peerContract?0:4;', profile)
        for forbidden in ('WSAStartup(', 'socket(', 'Probe(', 'n0a_udp6::Run('):
            self.assertNotIn(forbidden, profile)
        self.assertNotIn('--profile-only', self.source)
        self.assertIn('#ifndef N0A_UDP6_FIXTURE_ENTRY', self.source)

    def test_single_datagram_no_stream_accumulation(self):
        probe = function(self.source, 'Probe')
        receive = function(self.source, 'Receive')
        self.assertEqual(probe.count('sendto('), 1)
        self.assertEqual(receive.count('recvfrom('), 1)
        self.assertNotIn('while (', receive)
        self.assertNotIn('send(', self.source)
        self.assertNotIn('recv(', self.source)
        self.assertLess(probe.index('sent!=static_cast<int>(frame.size())'), probe.index('result.sendAccepted=true'))
        self.assertIn('Error(result,"sendto",sendError)', probe)
        self.assertIn('Error(result,"short_send",0)', probe)

    def test_exact_datagram_peer_payload(self):
        receive = function(self.source, 'Receive')
        for required in ('sender.sin6_family!=AF_INET6', 'sender.sin6_port!=remote.sin6_port',
                         'sender.sin6_scope_id!=0', 'IN6_IS_ADDR_V4MAPPED(&sender.sin6_addr)',
                         'std::memcmp(&sender.sin6_addr,Destination.data(),Destination.size())!=0', 'count!=static_cast<int>(frame.size())',
                         'std::memcmp(buffer.data(),frame.data(),frame.size())!=0'):
            self.assertIn(required, receive)
        self.assertLess(receive.index('echo_peer'), receive.index('nonceMatched=true'))
        self.assertLess(receive.index('echo_payload'), receive.index('nonceMatched=true'))

    def test_exclusive_bind_and_observed_port_before_send(self):
        probe = function(self.source, 'Probe')
        self.assertLess(probe.index('SO_EXCLUSIVEADDRUSE'), probe.index('bind('))
        self.assertLess(probe.index('getsockname('), probe.index('result.attempted=true'))
        self.assertIn('local.sin6_port=0', probe)
        self.assertIn('std::memcpy(result.localIpv6.data(),&local.sin6_addr,result.localIpv6.size())', probe)
        self.assertNotIn('owned.close()', probe)

    def test_v6only_set_and_native_readback_before_bind(self):
        probe=function(self.source,'Probe')
        self.assertIn('const DWORD v6Only=1',probe)
        self.assertIn('setsockopt(owned.value,IPPROTO_IPV6,IPV6_V6ONLY',probe)
        self.assertIn('getsockopt(owned.value,IPPROTO_IPV6,IPV6_V6ONLY',probe)
        self.assertIn('ValidateV6Only(optionReturn,optionError,optionLength,observedV6Only,result)',probe)
        self.assertLess(probe.index('ValidateV6Only('),probe.index('bind('))
        self.assertLess(probe.index('result.v6OnlySet=true'),probe.index('getsockopt('))
        self.assertIn('Error(result,"v6only_set",WSAGetLastError())',probe)
        self.assertIn('const int optionError=optionReturn!=0?WSAGetLastError():0;',probe)
        self.assertIn('local.sin6_scope_id!=0',probe)
        self.assertIn('IN6_IS_ADDR_V4MAPPED(&local.sin6_addr)',probe)

    def test_v6only_native_boolean_and_closed_observation(self):
        helper=function(self.source,'ValidateV6Only')
        self.assertIn('if (returned!=0)',helper)
        self.assertIn('length!=static_cast<int>(sizeof(DWORD))',helper)
        self.assertIn('if (value==0)',helper)
        self.assertNotIn('value!=1',helper)
        self.assertIn('if (length==1) value=storage[0];',helper)
        self.assertIn('else std::memcpy(&value,storage.data(),sizeof(value));',helper)
        self.assertLess(helper.index('length!=1 &&'),helper.index('storage[0]'))
        self.assertIn('std::array<unsigned char,sizeof(DWORD)> observedV6Only{};',self.source)
        self.assertIn('optionLength=static_cast<int>(observedV6Only.size())',self.source)
        self.assertLess(helper.index('length!=1 && length!=static_cast'),helper.index('result.v6OnlyGetValue=value'))
        self.assertLess(helper.index('returned!=0'),helper.index('result.v6OnlyGetValue=value'))
        self.assertIn('Error(result,"v6only_length",0)',helper)
        self.assertIn('Error(result,"v6only_zero",0)',helper)
        self.assertNotIn('WSAEINVAL',helper)
        for field in ('v6OnlyGetReturn','v6OnlyGetError','v6OnlyGetLength','v6OnlyGetValue','v6OnlyGetStage'):
            self.assertIn(field,function(self.source,'Serialize'))
        self.assertEqual(function(self.source,'Probe').count('getsockopt('),1)
        self.assertIn('const DWORD v6Only=1',function(self.source,'Probe'))

    def test_actual_fixture_calls_shared_helper_with_fixed_cases(self):
        fixture=(ROOT/'.github/native/windows_n0a_udp6_fixture.cpp').read_text()
        contract=function(fixture,'V6OnlyContract')
        for value in ('DWORD{0}','DWORD{1}','DWORD{2}','DWORD{0xffffffff}','{-1,0,2,3,5,8,2147483647}','SOCKET_ERROR,WSAEINVAL'):
            self.assertIn(value,contract)
        for forbidden in ('socket(','getsockopt(','setsockopt(','WSAStartup(','Probe('):
            self.assertNotIn(forbidden,contract)
        self.assertIn('storage={first,0xa5,0xff,0x7e}',contract)
        self.assertIn('static_cast<unsigned char>(255)',contract)
        self.assertIn('{-1,0,1,4,5}',contract)
        self.assertIn('const bool v6Contract=V6OnlyContract();',fixture)
        self.assertIn('v6OnlyContractVerified',fixture)
        self.assertIn('n0a_udp6::Bool(v6Contract)',fixture)

    def test_peer_observation_does_not_change_receive_acceptance(self):
        receive=function(self.source,'Receive')
        line='    ObserveEchoPeer(count,senderLength,sender,remote,result);\n'
        self.assertEqual(receive.count(line),1)
        self.assertEqual(hashlib.sha256(receive.replace(line,'').encode()).hexdigest(),
                         'e58278b055088b072cd84c188136a3f8ab79d6f0771d8d265cfadf17560ab1a6')
        self.assertLess(receive.index('if (count==SOCKET_ERROR)'),receive.index('ObserveEchoPeer('))
        self.assertLess(receive.index('ObserveEchoPeer('),receive.index('if (senderLength!='))
    def test_peer_fields_are_nullable_and_returned_length_bounded(self):
        helper=function(self.source,'ObserveEchoPeer')
        self.assertIn('if (count<0) return;',helper)
        self.assertIn('if (length<0 || length>static_cast<int>(sizeof(sender))) return;',helper)
        for field in ('sin6_family','sin6_port','sin6_scope_id','sin6_addr'):
            self.assertIn('offsetof(sockaddr_in6,'+field+')+sizeof(sender.'+field+')',helper)
        self.assertLess(helper.index('if (length<0'),helper.index('const std::size_t available'))
        for name in ('LengthMatched','FamilyMatched','PortMatched','ScopeZero','NotV4Mapped','AddressMatched'):
            self.assertIn('OptionalBool(a.echoPeer'+name+')',function(self.source,'Serialize'))
        self.assertIn('value.has_value()?Bool(*value):"null"',function(self.source,'OptionalBool'))
        for forbidden in ('Error(', 'recvfrom(', 'sendto(', 'WSAGetLastError(', 'nonceMatched=', 'failure='):
            self.assertNotIn(forbidden,helper)
    def test_fixture_peer_contract_is_shared_pure_and_fixed(self):
        fixture=(ROOT/'.github/native/windows_n0a_udp6_fixture.cpp').read_text()
        contract=function(fixture,'EchoPeerContract')
        for text in ('SOCKET_ERROR','2147483647','length=0','changed<5','AF_INET','sin6_scope_id=1','mapped=',
                     'ObserveEchoPeer(', 'has_value()'):
            self.assertIn(text,contract)
        for forbidden in ('socket(', 'recvfrom(', 'sendto(', 'WSAStartup('):self.assertNotIn(forbidden,contract)
        self.assertIn('const bool peerContract=EchoPeerContract();',fixture)
        self.assertIn('echoPeerContractVerified',fixture)
        self.assertIn('identity.errors.empty()&&v6Contract&&peerContract?0:4',fixture)
    def test_ipv6_wire_domain_is_separate(self):
        self.assertIn(r'\"udp6\":',self.source)
        self.assertNotIn(r'\"udp\":',self.source)
        self.assertIn('localIpv6{}',self.source)
        self.assertIn('localScopeId=0',self.source)
        self.assertIn('digits="0123456789abcdef"',function(self.source,'AddressHex'))
        self.assertIn('result.reserve(32)',function(self.source,'AddressHex'))
        for key in ('localIpv6','localScopeId','v6OnlySet','v6OnlyVerified'):
            self.assertIn(key,function(self.source,'Serialize'))
        self.assertNotIn('localIpv4',self.source)

    def test_old_ipv4_source_unchanged(self):
        self.assertEqual(hashlib.sha256((ROOT/'.github/native/windows_n0a_udp_actor.cpp').read_bytes()).hexdigest(),
                         'dea64f0f25d60930be13c4f9e24b41f7535d1021476e6180d6bfe3361b40d0f2')

    def test_fixed_window_and_held_socket_cleanup(self):
        run = function(self.source, 'Run')
        self.assertIn('ContainedBudget = 3000', self.source)
        self.assertIn('SampleBudget = 10000', self.source)
        self.assertIn('MaxSamples = 40', self.source)
        self.assertIn('start+(sample?SampleBudget:ContainedBudget)', run)
        self.assertIn('std::min(deadline,now+(sample?200:800))', run)
        self.assertLess(run.index('attempts.back().exchangeEndQpc'), run.index('sockets[index].close()'))
        self.assertLess(run.index('Wsa wsa'), run.index('std::array<Socket,MaxSamples> sockets'))
        self.assertIn('closeError=attempt.closed?0:WSAGetLastError()', run)

    def test_close_is_one_shot_with_sticky_report(self):
        close = function(self.source, 'close')
        self.assertLess(close.index('value = INVALID_SOCKET'), close.index('closesocket(owned)'))
        self.assertEqual(close.count('closesocket('), 1)
        run = function(self.source, 'Run')
        self.assertIn('cleanup=cleanup&&attempt.closed', run)
        self.assertIn('attempt.closeError=attempt.closed?0:WSAGetLastError()', run)

    def test_private_frame_phase_and_attempt_are_bound(self):
        self.assertIn('"N0AU6 "+nonce+" "+phase+" "+std::to_string(index)+"\\n"', self.source)
        for phase in ('before', 'sample', 'contained', 'after'):
            self.assertIn('L"' + phase + '"', self.source)
        self.assertIn('MakeReport("actor-n0a-udp6"', self.source)
        self.assertIn('CREATE_NEW', self.source)
        self.assertIn('MaxReport = 32768', self.source)

    def test_separate_pinned_builds(self):
        for kind, exe, manifest in (
            ('actor', 'windows_n0a_udp6_actor', 'N0A-UDP6-manifest.json'),
            ('fixture', 'windows_n0a_UDP6_TEST_ONLY_fixture', 'UDP6-TEST-ONLY-manifest.json'),
        ):
            build = (ROOT / f'.github/build_windows_n0a_udp6_{kind}.ps1').read_text()
            self.assertIn("'/UN0A_UDP6_TEST_ONLY'", build)
            self.assertIn('ExpectedActorSha256', build)
            self.assertIn('ExpectedIdentitySha256', build)
            self.assertIn(exe + '.exe', build)
            self.assertIn(manifest, build)
            self.assertIn('Source changed during compilation.', build)
            self.assertIn("$env:VSCMD_ARG_TGT_ARCH -cne 'x64'", build)
            self.assertNotIn('GITHUB_OUTPUT', build)
            self.assertNotIn('ExecutablePath=', build)
        fixture = (ROOT / '.github/build_windows_n0a_udp6_fixture.ps1').read_text()
        self.assertIn('testOnly=$true; deployable=$false', fixture)
        self.assertIn('ExpectedFixtureSha256', fixture)


if __name__ == '__main__':
    unittest.main()
