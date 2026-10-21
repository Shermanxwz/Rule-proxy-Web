"""Source/binding guards only; actual Winsock semantics require the Windows gate."""
import hashlib
import pathlib
import re
import unittest

ROOT = pathlib.Path(__file__).resolve().parents[1]
ACTOR = ROOT / '.github/native/windows_n0a_udp_actor.cpp'
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


class UdpActorSourceTests(unittest.TestCase):
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
        self.assertIn('constexpr ULONG Destination = 0x0a000202UL;', self.source)
        self.assertIn('constexpr ULONG Destination = INADDR_LOOPBACK;', self.source)
        self.assertIn('remote.sin_addr.s_addr=htonl(Destination)', self.source)
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
        fixture = (ROOT / '.github/native/windows_n0a_udp_fixture.cpp').read_text()
        self.assertIn('#define N0A_UDP_TEST_ONLY 1', fixture)
        self.assertIn('#include "windows_n0a_udp_actor.cpp"', fixture)
        self.assertNotIn('#define N0A_UDP_TEST_ONLY', self.source)
        self.assertIn('"fixture-loopback":"runner"', self.source)

    def test_fixture_profile_only_never_enters_network_run(self):
        fixture = (ROOT / '.github/native/windows_n0a_udp_fixture.cpp').read_text()
        profile = fixture.split('if (argc==4')[1].split('return n0a_udp::Run')[0]
        self.assertIn('ObserveNativeIdentity()', profile)
        self.assertIn('n0a_udp::Profile(identity,false)', profile)
        self.assertIn('n0a_udp::Profile(identity,true)', profile)
        self.assertIn('return identity.errors.empty()?0:4;', profile)
        for forbidden in ('WSAStartup(', 'socket(', 'Probe(', 'n0a_udp::Run('):
            self.assertNotIn(forbidden, profile)
        self.assertNotIn('--profile-only', self.source)
        self.assertIn('#ifndef N0A_UDP_FIXTURE_ENTRY', self.source)

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
        for required in ('sender.sin_family!=AF_INET', 'sender.sin_port!=remote.sin_port',
                         'sender.sin_addr.s_addr!=remote.sin_addr.s_addr', 'count!=static_cast<int>(frame.size())',
                         'std::memcmp(buffer.data(),frame.data(),frame.size())!=0'):
            self.assertIn(required, receive)
        self.assertLess(receive.index('echo_peer'), receive.index('nonceMatched=true'))
        self.assertLess(receive.index('echo_payload'), receive.index('nonceMatched=true'))

    def test_exclusive_bind_and_observed_port_before_send(self):
        probe = function(self.source, 'Probe')
        self.assertLess(probe.index('SO_EXCLUSIVEADDRUSE'), probe.index('bind('))
        self.assertLess(probe.index('getsockname('), probe.index('result.attempted=true'))
        self.assertIn('local.sin_port=0', probe)
        self.assertIn('result.localIpv4=ntohl(local.sin_addr.s_addr)', probe)
        self.assertNotIn('owned.close()', probe)

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
        self.assertIn('"N0AU1 "+nonce+" "+phase+" "+std::to_string(index)+"\\n"', self.source)
        for phase in ('before', 'sample', 'contained', 'after'):
            self.assertIn('L"' + phase + '"', self.source)
        self.assertIn('MakeReport("actor-n0a-udp"', self.source)
        self.assertIn('CREATE_NEW', self.source)
        self.assertIn('MaxReport = 32768', self.source)

    def test_separate_pinned_builds(self):
        for kind, exe, manifest in (
            ('actor', 'windows_n0a_udp_actor', 'N0A-UDP-manifest.json'),
            ('fixture', 'windows_n0a_UDP_TEST_ONLY_fixture', 'UDP-TEST-ONLY-manifest.json'),
        ):
            build = (ROOT / f'.github/build_windows_n0a_udp_{kind}.ps1').read_text()
            self.assertIn("'/UN0A_UDP_TEST_ONLY'", build)
            self.assertIn('ExpectedActorSha256', build)
            self.assertIn('ExpectedIdentitySha256', build)
            self.assertIn(exe + '.exe', build)
            self.assertIn(manifest, build)
            self.assertIn('Source changed during compilation.', build)
            self.assertIn("$env:VSCMD_ARG_TGT_ARCH -cne 'x64'", build)
            self.assertNotIn('GITHUB_OUTPUT', build)
            self.assertNotIn('ExecutablePath=', build)
        fixture = (ROOT / '.github/build_windows_n0a_udp_fixture.ps1').read_text()
        self.assertIn('testOnly=$true; deployable=$false', fixture)
        self.assertIn('ExpectedFixtureSha256', fixture)


if __name__ == '__main__':
    unittest.main()
