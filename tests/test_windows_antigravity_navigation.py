"""Protocol tests use fake sockets only: no apps, external networking, or profiles."""
import base64
import hashlib
import json
import struct
import unittest
from unittest.mock import patch

from ruleproxy.windows_antigravity_navigation import NavigationClient, FrameSession, NavigationError, LIMIT


class FakeSocket:
    def __init__(self, wire=b''):
        self.wire, self.sent, self.closed, self.timeouts = wire, [], False, []
    def settimeout(self, value):
        self.timeouts.append(value)
    def recv(self, count):
        result, self.wire = self.wire[:count], self.wire[count:]
        return result
    def sendall(self, value):
        self.sent.append(value)
    def close(self):
        self.closed = True


def frame(value, first=0x81):
    raw = value if isinstance(value, bytes) else json.dumps(value).encode()
    n = len(raw)
    prefix = bytes((first, n)) if n < 126 else bytes((first, 126)) + struct.pack('!H', n)
    return prefix + raw


def response(body, status=200, headers=b''):
    if not isinstance(body, bytes):
        body = json.dumps(body).encode()
    return b'HTTP/1.1 ' + str(status).encode() + b' Test\r\nContent-Length: ' + str(len(body)).encode() + b'\r\n' + headers + b'\r\n' + body


def upgrade(extra=b'', accept=None):
    key = base64.b64encode(b'x' * 16).decode()
    expected = base64.b64encode(hashlib.sha1((key + '258EAFA5-E914-47DA-95CA-C5AB0DC85B11').encode()).digest())
    return b'HTTP/1.1 101 Switching Protocols\r\nUpgrade: websocket\r\nConnection: Upgrade\r\nSec-WebSocket-Accept: ' + (expected if accept is None else accept) + b'\r\n' + extra + b'\r\n'


def unpack_client(wire):
    assert wire[1] & 128
    size, mask, data = wire[1] & 127, wire[2:6], wire[6:]
    assert size == len(data)
    return wire[0] & 15, bytes(v ^ mask[i % 4] for i, v in enumerate(data))


class NavigationTests(unittest.TestCase):
    def client(self, **kwargs):
        return NavigationClient(22095, 10, clock=kwargs.get('clock', lambda: 0))

    def session(self, wire):
        sock = FakeSocket(wire)
        return FrameSession(self.client(), sock), sock

    def test_invalid_port_before_network(self):
        with patch('socket.create_connection') as opened:
            for port in (True, False, 0, 80, 1024, 65536, '22095', 1.0):
                with self.subTest(port=port), self.assertRaises(NavigationError):
                    NavigationClient(port, 10)
            opened.assert_not_called()

    def test_invalid_deadline(self):
        for value in (True, None, '10', float('inf'), float('nan')):
            with self.subTest(value=value), self.assertRaises(NavigationError):
                NavigationClient(22095, value)

    def test_expired_never_connects(self):
        with patch('socket.create_connection') as opened, self.assertRaises(NavigationError):
            NavigationClient(22095, 0, clock=lambda: 1).targets()
        opened.assert_not_called()

    def test_targets_are_minimal_direct_and_closed(self):
        value = [{'id': 'A', 'type': 'page', 'url': 'https://127.0.0.1:22097/',
                  'webSocketDebuggerUrl': 'ws://127.0.0.1:22095/devtools/page/A', 'title': 'private'}]
        sock = FakeSocket(response(value))
        with patch('socket.create_connection', return_value=sock) as opened:
            found = self.client().targets()
        opened.assert_called_once_with(('127.0.0.1', 22095), 2.)
        self.assertEqual(set(found[0]), {'id', 'type', 'url', 'webSocketDebuggerUrl'})
        self.assertTrue(sock.closed)
        self.assertNotIn(b'Cookie', sock.sent[0])
        self.assertNotIn(b'Origin', sock.sent[0])
        self.assertTrue(sock.sent[0].startswith(b'GET /json/list HTTP/1.1\r\n'))

    def test_http_rejections_close(self):
        cases = [response([], 302), response([], headers=b'Transfer-Encoding: chunked\r\n'),
                 response({}, 200), response([None]), response([{}] * 65), response(b'{'),
                 response([{'url': 'x' * 8193}]),
                 b'HTTP/1.1 200 OK\r\nContent-Length: 262145\r\n\r\n',
                 b'HTTP/1.1 200 OK\r\nContent-Length: 2\r\nContent-Length: 2\r\n\r\n[]',
                 b'HTTP/1.1 200 OK\r\nX: ' + b'x' * 16384,
                 b'HTTP/1.1 200 OK\r\n\r\n[]']
        for wire in cases:
            sock = FakeSocket(wire)
            with self.subTest(wire=wire[:40]), patch('socket.create_connection', return_value=sock), self.assertRaises(NavigationError):
                self.client().targets()
            self.assertTrue(sock.closed)

    def test_absolute_deadline_in_header_trickle(self):
        ticks = iter(i / 100 for i in range(2000))
        sock = FakeSocket(response([]))
        with patch('socket.create_connection', return_value=sock), self.assertRaises(NavigationError):
            NavigationClient(22095, .1, clock=lambda: next(ticks)).targets()
        self.assertTrue(sock.closed)

    def test_endpoint_rejected_before_network(self):
        endpoints = ['ws://localhost:22095/devtools/page/A', 'wss://127.0.0.1:22095/devtools/page/A',
                     'ws://127.0.0.1:22096/devtools/page/A', 'ws://user@127.0.0.1:22095/devtools/page/A',
                     'ws://127.0.0.1:22095/devtools/page/A?q=1', 'ws://127.0.0.1:22095/devtools/page/A#x',
                     'ws://127.0.0.1:22095/devtools/browser/A', 'ws://127.0.0.1:22095/devtools/page/A/B',
                     'ws://127.0.0.1:022095/devtools/page/A', ' ws://127.0.0.1:22095/devtools/page/A',
                     'ws://127.0.0.1:22095/devtools/page/%41', None]
        with patch('socket.create_connection') as opened:
            for endpoint in endpoints:
                with self.subTest(endpoint=endpoint), self.assertRaises(NavigationError):
                    self.client().connect(endpoint)
            opened.assert_not_called()

    def test_valid_handshake_and_context_close(self):
        sock = FakeSocket(upgrade())
        with patch('socket.create_connection', return_value=sock), patch('os.urandom', side_effect=lambda n: b'x' * n):
            with self.client().connect('ws://127.0.0.1:22095/devtools/page/A'):
                self.assertFalse(sock.closed)
        self.assertTrue(sock.closed)
        self.assertNotIn(b'Origin:', sock.sent[0])
        self.assertNotIn(b'Cookie:', sock.sent[0])
        self.assertNotIn(b'Sec-WebSocket-Extensions:', sock.sent[0])

    def test_handshake_rejection_closes(self):
        for wire in (upgrade(accept=b'wrong'), response([], 302), upgrade(b'Sec-WebSocket-Extensions: permessage-deflate\r\n'), upgrade(b'Sec-WebSocket-Protocol: custom\r\n'), upgrade().replace(b'Upgrade: websocket', b'Upgrade: other')):
            sock = FakeSocket(wire)
            with self.subTest(wire=wire[:40]), patch('socket.create_connection', return_value=sock), patch('os.urandom', side_effect=lambda n: b'x' * n), self.assertRaises(NavigationError):
                self.client().connect('ws://127.0.0.1:22095/devtools/page/A')
            self.assertTrue(sock.closed)

    def test_frame_fields_and_exact_methods(self):
        data = {'id': 'FRAME', 'loaderId': 'LOADER', 'url': 'chrome-error://chromewebdata/', 'unreachableUrl': 'https://127.0.0.1:22097/', 'secret_extra': 'not_returned'}
        session, sock = self.session(frame({'id': 1, 'result': {'frameTree': {'frame': data, 'childFrames': []}}}) + frame({'id': 2, 'result': {}}))
        with session:
            result = session.frame()
            session.reload()
        self.assertEqual(set(result), {'id', 'loaderId', 'url', 'unreachableUrl'})
        sent = [json.loads(unpack_client(v)[1]) for v in sock.sent]
        self.assertEqual(sent, [{'id': 1, 'method': 'Page.getFrameTree'}, {'id': 2, 'method': 'Page.reload'}])
        self.assertTrue(sock.closed)

    def test_rpc_rejects_other_methods_without_sending(self):
        session, sock = self.session(b'')
        with session, self.assertRaises(NavigationError):
            session._rpc('Runtime.evaluate')
        self.assertEqual(sock.sent, [])

    def test_frames_rejected(self):
        cases = [b'\x01\x00', b'\xc1\x00', b'\x81\x80', b'\x82\x00', b'\x88\x00',
                 b'\x81\x7f' + struct.pack('!Q', LIMIT + 1), b'\x81\x7e\x00\x01x',
                 b'\x89\x7e', frame(b'not-json'), frame([]), frame({'id': 1, 'error': {'message': 'do_not_echo'}})]
        for wire in cases:
            session, sock = self.session(wire)
            with self.subTest(wire=wire[:20]), session, self.assertRaises(NavigationError):
                session.frame()
            self.assertTrue(sock.closed)

    def test_ping_is_masked_pong(self):
        session, sock = self.session(frame(b'ping', 0x89) + frame({'id': 1, 'result': {}}))
        with session:
            session.reload()
        self.assertEqual(unpack_client(sock.sent[1]), (10, b'ping'))

    def test_events_and_wrong_ids_are_bounded(self):
        for event in ({'method': 'Page.event'}, {'id': 99, 'result': {}}, {'id': True, 'result': {}}):
            session, sock = self.session(frame(event) * 32 + frame({'id': 1, 'result': {}}))
            with self.subTest(event=event), session, self.assertRaises(NavigationError):
                session.reload()
            self.assertTrue(sock.wire)

    def test_event_then_result(self):
        session, sock = self.session(frame({'method': 'Page.event'}) + frame({'id': 1, 'result': {}}))
        with session:
            session.reload()

    def test_invalid_frame_shape(self):
        for result in ({}, {'frameTree': None}, {'frameTree': {'frame': {}}}, {'frameTree': {'frame': {'id': 1}}}):
            session, sock = self.session(frame({'id': 1, 'result': result}))
            with self.subTest(result=result), session, self.assertRaises(NavigationError):
                session.frame()

    def test_socket_error_has_fixed_exception(self):
        with patch('socket.create_connection', side_effect=OSError('private endpoint')):
            with self.assertRaisesRegex(NavigationError, '^connection$'):
                self.client().targets()

    def test_close_idempotent_and_closed_send(self):
        session, sock = self.session(b'')
        session.close()
        session.close()
        with self.assertRaises(NavigationError):
            session.reload()


if __name__ == '__main__':
    unittest.main()
