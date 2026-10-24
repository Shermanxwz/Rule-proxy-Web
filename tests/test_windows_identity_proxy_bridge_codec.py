"""Pure fixtures only: no listeners, security APIs, subprocesses, or network I/O."""
import dataclasses
import importlib.util
from pathlib import Path
import struct
import sys
import unittest

PATH = Path(__file__).resolve().parents[1] / '.github/windows_identity_proxy_bridge_codec.py'
spec = importlib.util.spec_from_file_location('identity_proxy_bridge_codec_test', PATH)
c = importlib.util.module_from_spec(spec)
sys.modules[spec.name] = c
spec.loader.exec_module(c)


def config():
    return c.BridgeConfig(bytes(range(16)), bytes(range(16, 32)), 50000, 50001, 1000)


def request(target_authority=c.AUTHORITY, host=c.AUTHORITY, headers=()):
    return (b'GET http://' + target_authority + b'/' + config().case_id.hex().encode() +
            b' HTTP/1.1\r\nHost: ' + host + b'\r\n' + b''.join(x+b'\r\n' for x in headers) + b'\r\n')


class ConfigTests(unittest.TestCase):
    def test_frozen_numeric_endpoints(self):
        value = config()
        self.assertEqual((value.frontend_host, value.relay_host), ('127.0.0.1', '10.0.2.2'))
        with self.assertRaises(dataclasses.FrozenInstanceError):
            value.relay_port = 60000

    def test_strict_configuration_types_bounds(self):
        for key, values in {'run_id': [b'', b'x'*15, b'x'*17, bytearray(16), 'x'*16],
                            'case_id': [None, b''], 'frontend_port': [True, 49151, 65536, '50000'],
                            'relay_port': [50000, False], 'deadline': [-1, True, 1.5]}.items():
            for value in values:
                with self.subTest(key=key, value_type=type(value).__name__):
                    with self.assertRaises(c.BridgeProtocolError):
                        dataclasses.replace(config(), **{key: value})
        with self.assertRaises(c.BridgeProtocolError):
            c.encode_frame({}, 1)


class FrameTests(unittest.TestCase):
    def test_exact_offsets_and_every_type_status(self):
        for kind in range(1, 6):
            for status in range(5 if kind == 4 else 1):
                data = c.encode_frame(config(), kind, status)
                self.assertEqual(len(data), 48)
                self.assertEqual(data[:8], b'RPB1'+bytes([kind])+b'\0'*3)
                self.assertEqual(data[8:24], config().run_id)
                self.assertEqual(data[24:40], config().case_id)
                self.assertEqual(data[40:], struct.pack('<II', kind-1, status))
                self.assertEqual(c.decode_frame(config(), data), c.Frame(kind, kind-1, status))

    def test_all_frame_split_points_and_bytewise(self):
        for kind in range(1, 6):
            data = c.encode_frame(config(), kind)
            for split in range(49):
                buffer = c.FrameBuffer(config())
                buffer.feed(data[:split]); buffer.feed(data[split:])
                self.assertEqual(buffer.finish().frame_type, kind)
            buffer = c.FrameBuffer(config())
            for byte in data:
                buffer.feed(bytes([byte]))
            self.assertEqual(buffer.finish().sequence, kind-1)

    def test_corrupt_fields_stale_and_surplus(self):
        data = c.encode_frame(config(), 1)
        for offset in (0, 4, 5, 6, 7, 8, 24, 40, 44):
            bad = bytearray(data); bad[offset] ^= 0x80
            with self.assertRaises(c.BridgeProtocolError):
                c.decode_frame(config(), bytes(bad))
        for bad in (data[:-1], data+b'\0', data+data, bytearray(data)):
            with self.assertRaises(c.BridgeProtocolError):
                c.decode_frame(config(), bad)
        for kind, status in ((True,0),(0,0),(6,0),(1,1),(4,5),(4,-1),(4,True)):
            with self.assertRaises(c.BridgeProtocolError):
                c.encode_frame(config(),kind,status)

    def test_every_partial_eof_rejected(self):
        data = c.encode_frame(config(), 4)
        for end in range(48):
            buffer = c.FrameBuffer(config()); buffer.feed(data[:end])
            with self.assertRaises(c.BridgeProtocolError):
                buffer.finish()


class HttpTests(unittest.TestCase):
    def test_independent_optional_port_normalization(self):
        for target in (c.AUTHORITY,c.AUTHORITY+b':80'):
            for host in (c.AUTHORITY,c.AUTHORITY+b':80'):
                self.assertEqual(c.parse_proxy_request(config(),request(target,host)), c.relay_request(config()))
        canonical = c.relay_request(config())
        self.assertEqual(canonical, b'GET /p1/'+config().case_id.hex().encode()+
                         b' HTTP/1.1\r\nHost: 10.0.2.2:50001\r\nConnection: close\r\n\r\n')

    def test_valid_headers_discarded_and_trim(self):
        data = request(headers=(b'cOnTeNt-LeNgTh:\t 0 \t', b'X-Ignore: \tvalue with spaces\t',
                                b'Connection: keep-alive'))
        data = data.replace(b'Host: ', b'hOsT:\t ')
        self.assertEqual(c.parse_proxy_request(config(),data),c.relay_request(config()))

    def test_all_request_splitpoints(self):
        data=request(headers=(b'Content-Length: 0',))
        for split in range(len(data)+1):
            buffer=c.RequestBuffer(config()); buffer.feed(data[:split]); buffer.feed(data[split:])
            self.assertEqual(buffer.finish(),c.relay_request(config()))

    def test_bad_target_authority_and_method(self):
        good=request()
        alternatives=(b'https://', b'HTTP://', b'http://user@', b'http://127.0.0.1/')
        bad=[good.replace(b'http://',x,1) for x in alternatives]
        bad += [request(x) for x in (c.AUTHORITY.upper(),c.AUTHORITY+b':080',c.AUTHORITY+b':81',
                                     c.AUTHORITY+b'.', b'other.invalid')]
        bad += [good.replace(b'GET ',x,1) for x in (b'CONNECT ',b'POST ',b'get ',b'GET\t')]
        bad += [good.replace(b' HTTP/1.1',x,1) for x in (b'?x HTTP/1.1',b'#x HTTP/1.1',b' HTTP/1.0')]
        bad += [good.replace(config().case_id.hex().encode(),b'%31'+config().case_id.hex().encode()[1:],1)]
        for value in bad:
            with self.assertRaises(c.BridgeProtocolError):
                c.parse_proxy_request(config(),value)

    def test_forbidden_duplicate_and_invalid_headers(self):
        headers=(b'Host: '+c.AUTHORITY,b'Host : '+c.AUTHORITY,b' Host: '+c.AUTHORITY,
                 b'Content-Length: 1',b'Content-Length: +0',b'Content-Length: 00',
                 b'Content-Length: 0, 0',b'Transfer-Encoding: identity',b'Authorization: x',
                 b'Proxy-Authorization: x',b'Cookie: x',b'Set-Cookie: x',b'Upgrade: x',
                 b' folded',b'X@: x',b'X:\x00',b'X:\x7f',b'X:\x80',b'X:\x0b')
        for header in headers:
            with self.assertRaises(c.BridgeProtocolError):
                c.parse_proxy_request(config(),request(headers=(header,)))
        with self.assertRaises(c.BridgeProtocolError):
            c.parse_proxy_request(config(),request(headers=(b'Content-Length: 0',)*2))
        with self.assertRaises(c.BridgeProtocolError):
            c.parse_proxy_request(config(),request().replace(b'Host: '+c.AUTHORITY+b'\r\n',b''))
        with self.assertRaises(c.BridgeProtocolError):
            c.parse_proxy_request(config(),request(host=c.AUTHORITY.upper()))

    def test_crlf_only_no_body_or_pipeline(self):
        data=request()
        for bad in (data.replace(b'\r\n',b'\n'),data.replace(b'\r\n',b'\r'),data+b'x',data+data,
                    data[:-1],data.replace(b'Host:',b'X:\nHost:')):
            with self.assertRaises(c.BridgeProtocolError):
                c.parse_proxy_request(config(),bad)

    def test_exact_header_line_and_total_limits(self):
        self.assertEqual(c.parse_proxy_request(config(),request(headers=(b'X: x',)*31)),c.relay_request(config()))
        with self.assertRaises(c.BridgeProtocolError):
            c.parse_proxy_request(config(),request(headers=(b'X: x',)*32))
        self.assertEqual(c.parse_proxy_request(config(),request(headers=(b'X:'+b'a'*1020,))),c.relay_request(config()))
        with self.assertRaises(c.BridgeProtocolError):
            c.parse_proxy_request(config(),request(headers=(b'X:'+b'a'*1021,)))
        base=request(); room=8192-len(base)
        lines=[]
        while room:
            size=min(1024,room)
            if room-size in (1,2,3):
                size-=4-(room-size)
            lines.append(b'X:'+b'a'*(size-4));room-=size
        exact=request(headers=tuple(lines)); self.assertEqual(len(exact),8192)
        c.parse_proxy_request(config(),exact)
        with self.assertRaises(c.BridgeProtocolError):
            c.parse_proxy_request(config(),exact[:-2]+b'x\r\n')

    def test_response_exact_with_eof_all_splitpoints(self):
        data=c.expected_response(config())
        self.assertLessEqual(len(data),256)
        for split in range(len(data)+1):
            buffer=c.ResponseBuffer(config());buffer.feed(data[:split]);buffer.feed(data[split:]);buffer.finish(True)
        for bad in (data[:-1],data+b'x',data.replace(b'200 OK',b'201 OK'),data.replace(b'32',b'032',1),data+data):
            with self.assertRaises(c.BridgeProtocolError):
                c.validate_response(config(),bad,True)
        for eof in (False,1,None):
            with self.assertRaises(c.BridgeProtocolError):
                c.validate_response(config(),data,eof)

    def test_response_buffer_requires_explicit_eof(self):
        buffer=c.ResponseBuffer(config()); buffer.feed(c.expected_response(config()))
        with self.assertRaises(c.BridgeProtocolError):
            buffer.finish()

    def test_buffers_terminal_no_retry_or_surplus(self):
        for cls,data in ((c.FrameBuffer,c.encode_frame(config(),1)),(c.RequestBuffer,request()),
                         (c.ResponseBuffer,c.expected_response(config()))):
            buffer=cls(config());buffer.feed(data)
            buffer.finish(True) if cls is c.ResponseBuffer else buffer.finish()
            for operation in (lambda:buffer.feed(b''),buffer.finish):
                with self.assertRaises(c.BridgeProtocolError): operation()
            buffer=cls(config())
            with self.assertRaises(c.BridgeProtocolError):buffer.feed(b'x'*(buffer.limit+1))
            with self.assertRaises(c.BridgeProtocolError):buffer.finish()


if __name__ == '__main__':
    unittest.main()
