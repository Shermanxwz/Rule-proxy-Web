"""Protocol checks for isolated fixtures; the source-address probe is loopback only."""
import importlib.util
import io
import ipaddress
from pathlib import Path
import socket
import struct
import sys
import threading
import unittest
from unittest.mock import patch


@unittest.skipUnless(sys.platform=='linux','Linux-only network fixture imports')
class CoreFixtureProtocolTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        path=Path(__file__).parent/'fixtures/linux_global_core_netns.py'
        spec=importlib.util.spec_from_file_location('ruleproxy_core_netns_fixture',path)
        cls.fixture=importlib.util.module_from_spec(spec);spec.loader.exec_module(cls.fixture)

    def test_synthetic_node_passes_public_ip_validation_without_external_lookup(self):
        self.assertTrue(ipaddress.ip_address(self.fixture.NODE4).is_global)
        self.assertTrue(ipaddress.ip_address(self.fixture.NODE6).is_global)

    def test_udp_address_parses_both_families_and_rejects_fragmentation(self):
        for family,address,kind in ((socket.AF_INET,self.fixture.TARGET4,1),(socket.AF_INET6,self.fixture.TARGET6,4)):
            raw=b'\x00\x00\x00'+bytes([kind])+socket.inet_pton(family,address)+struct.pack('!H',18880)+b'fixture'
            self.assertEqual(self.fixture.udp_address(raw)[:3],(address,18880,b'fixture'))
            with self.assertRaises(OSError):self.fixture.udp_address(b'\x00\x00\x01'+raw[3:])

    def test_exact_udp_echo_bind_preserves_requested_alias_as_reply_source(self):
        address='127.0.0.2'
        listener=self.fixture.echo_server(socket.AF_INET,socket.SOCK_DGRAM,address,0)
        self.addCleanup(listener.close)
        destination=(address,listener.getsockname()[1])
        with socket.socket(socket.AF_INET,socket.SOCK_DGRAM) as peer:
            peer.settimeout(1);peer.sendto(b'alias-source',destination)
            data,origin=peer.recvfrom(1024)
            self.assertEqual(data,b'alias-source');self.assertEqual(origin,destination)
        with socket.socket(socket.AF_INET,socket.SOCK_DGRAM) as peer:
            peer.settimeout(1);peer.connect(destination);peer.sendall(b'connected')
            self.assertEqual(peer.recv(1024),b'connected')

    def test_node_rejects_every_nonfixture_target_without_connecting(self):
        class Peer:
            def __init__(self,raw):self.raw=io.BytesIO(raw);self.sent=bytearray()
            def __enter__(self):return self
            def __exit__(self,*args):pass
            def settimeout(self,value):pass
            def recv(self,size):return self.raw.read(size)
            def sendall(self,data):self.sent.extend(data)
        for address,port,dns in (('1.1.1.1',443,1),('8.8.8.8',80,0),('127.0.0.1',22,0)):
            node=object.__new__(self.fixture.SocksNode)
            node.lock=threading.Lock();node.counts={'dns_doh_rejected':0}
            peer=Peer(b'\x05\x01\x00\x05\x01\x00\x01'+socket.inet_aton(address)+struct.pack('!H',port))
            with patch.object(self.fixture.socket,'create_connection') as connect:
                node.serve(peer)
            connect.assert_not_called();self.assertEqual(node.counts['dns_doh_rejected'],dns)
            self.assertEqual(peer.sent[:4],b'\x05\x00\x05\x05')


if __name__=='__main__':unittest.main()
