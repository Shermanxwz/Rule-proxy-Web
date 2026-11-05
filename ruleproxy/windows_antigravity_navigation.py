"""Bounded client for an application's existing local navigation endpoint.

No process discovery, enabling debugging, script execution, cookies, or profiles.
The caller must verify held process identities and readiness before connecting.
Only an explicitly validated page endpoint and two fixed CDP methods are used.
"""
import base64
import hashlib
import json
import math
import os
import re
import socket
import struct
import time
from urllib.parse import urlsplit

LIMIT = 256 * 1024


class NavigationError(ValueError):
    pass


def _fail(code):
    raise NavigationError(code) from None


class NavigationClient:
    def __init__(self, port, deadline, *, clock=time.monotonic):
        if type(port) is not int or not 1025 <= port <= 65535:
            _fail('invalid_port')
        if type(deadline) not in (int, float) or not math.isfinite(deadline):
            _fail('invalid_deadline')
        self.port, self.deadline, self.clock = port, deadline, clock

    def _budget(self):
        remaining = self.deadline - self.clock()
        if remaining <= 0:
            _fail('deadline')
        return min(2., remaining)

    def _open(self):
        try:
            return socket.create_connection(('127.0.0.1', self.port), self._budget())
        except (OSError, TimeoutError):
            _fail('connection')

    def _send(self, sock, data):
        try:
            sock.settimeout(self._budget())
            sock.sendall(data)
        except (OSError, TimeoutError):
            _fail('send')

    def _read(self, sock, count):
        chunks, size = [], 0
        if not 0 <= count <= LIMIT:
            _fail('size')
        while size < count:
            try:
                sock.settimeout(self._budget())
                chunk = sock.recv(min(count - size, 16384))
            except (OSError, TimeoutError):
                _fail('receive')
            if not chunk:
                _fail('closed')
            chunks.append(chunk)
            size += len(chunk)
        return b''.join(chunks)

    def _headers(self, sock):
        # Byte-wise header reading keeps both framing and absolute time bounded.
        # It also leaves the first WebSocket frame untouched in the socket.
        data = bytearray()
        while not data.endswith(b'\r\n\r\n'):
            if len(data) >= 16384:
                _fail('headers_size')
            data.extend(self._read(sock, 1))
        try:
            lines = data.decode('ascii').split('\r\n')
            if not re.fullmatch(r'HTTP/1\.[01] [0-9]{3}(?: [\x20-\x7e]*)?', lines[0]):
                _fail('status')
            headers = {}
            for line in lines[1:-2]:
                key, value = line.split(':', 1)
                key = key.lower()
                if not re.fullmatch(r'[a-z0-9-]+', key) or key in headers:
                    _fail('headers')
                value = value.strip(' \t')
                if any(ord(c) < 32 and c != '\t' for c in value):
                    _fail('headers')
                headers[key] = value
            return int(lines[0][9:12]), headers
        except (UnicodeError, ValueError):
            _fail('headers')

    def targets(self):
        sock = self._open()
        try:
            request = ('GET /json/list HTTP/1.1\r\nHost: 127.0.0.1:%d\r\n'
                       'Accept: application/json\r\nConnection: close\r\n\r\n') % self.port
            self._send(sock, request.encode('ascii'))
            status, headers = self._headers(sock)
            length = headers.get('content-length', '')
            if status != 200 or 'transfer-encoding' in headers or not re.fullmatch(r'[0-9]{1,6}', length):
                _fail('http_response')
            if int(length) > LIMIT:
                _fail('size')
            raw = self._read(sock, int(length))
            try:
                values = json.loads(raw)
            except (ValueError, UnicodeError, RecursionError):
                _fail('json')
            if not isinstance(values, list) or len(values) > 64:
                _fail('targets')
            result = []
            for value in values:
                if not isinstance(value, dict):
                    _fail('target')
                selected = {}
                for key, maximum in (('id', 128), ('type', 32), ('url', 8192), ('webSocketDebuggerUrl', 1024)):
                    text = value.get(key, '')
                    if not isinstance(text, str) or len(text) > maximum:
                        _fail('target_field')
                    selected[key] = text
                result.append(selected)
            return result
        finally:
            sock.close()

    def connect(self, endpoint):
        try:
            if not isinstance(endpoint, str) or len(endpoint) > 1024:
                _fail('endpoint')
            u = urlsplit(endpoint)
            if (u.scheme != 'ws' or u.hostname != '127.0.0.1' or u.port != self.port
                    or u.username is not None or u.password is not None or u.query or u.fragment
                    or not re.fullmatch(r'/devtools/page/[A-Za-z0-9-]{1,128}', u.path)
                    or endpoint != 'ws://127.0.0.1:%d%s' % (self.port, u.path)):
                _fail('endpoint')
        except ValueError:
            _fail('endpoint')
        sock = self._open()
        try:
            key = base64.b64encode(os.urandom(16)).decode('ascii')
            request = ('GET %s HTTP/1.1\r\nHost: 127.0.0.1:%d\r\nUpgrade: websocket\r\n'
                       'Connection: Upgrade\r\nSec-WebSocket-Version: 13\r\n'
                       'Sec-WebSocket-Key: %s\r\n\r\n') % (u.path, self.port, key)
            self._send(sock, request.encode('ascii'))
            status, headers = self._headers(sock)
            accept = base64.b64encode(hashlib.sha1((key + '258EAFA5-E914-47DA-95CA-C5AB0DC85B11').encode('ascii')).digest()).decode('ascii')
            if (status != 101 or headers.get('upgrade', '').lower() != 'websocket'
                    or 'upgrade' not in [v.strip().lower() for v in headers.get('connection', '').split(',')]
                    or headers.get('sec-websocket-accept') != accept
                    or 'sec-websocket-extensions' in headers or 'sec-websocket-protocol' in headers):
                _fail('upgrade')
            return FrameSession(self, sock)
        except BaseException:
            sock.close()
            raise


class FrameSession:
    def __init__(self, client, sock):
        self.client, self.sock, self.sequence = client, sock, 0

    def __enter__(self):
        return self

    def __exit__(self, *args):
        self.close()

    def close(self):
        if self.sock is not None:
            self.sock.close()
            self.sock = None

    def _send_frame(self, payload, opcode=1):
        if self.sock is None:
            _fail('closed')
        if len(payload) > 125 or opcode not in (1, 10):
            _fail('outbound_frame')
        mask = os.urandom(4)
        wire = bytes((0x80 | opcode, 0x80 | len(payload))) + mask
        wire += bytes(v ^ mask[i % 4] for i, v in enumerate(payload))
        self.client._send(self.sock, wire)

    def _rpc(self, method):
        if method not in ('Page.getFrameTree', 'Page.reload'):
            _fail('method')
        self.sequence += 1
        self._send_frame(json.dumps({'id': self.sequence, 'method': method}, separators=(',', ':')).encode('ascii'))
        for _ in range(32):
            first, second = self.client._read(self.sock, 2)
            opcode, size = first & 15, second & 127
            if not first & 128 or first & 112 or second & 128 or opcode not in (1, 9, 10):
                _fail('inbound_frame')
            if opcode in (9, 10) and size > 125:
                _fail('control_frame')
            if size == 126:
                size = struct.unpack('!H', self.client._read(self.sock, 2))[0]
                if size < 126:
                    _fail('frame_length')
            elif size == 127:
                size = struct.unpack('!Q', self.client._read(self.sock, 8))[0]
                if size < 65536:
                    _fail('frame_length')
            payload = self.client._read(self.sock, size)
            if opcode == 9:
                self._send_frame(payload, 10)
                continue
            if opcode == 10:
                continue
            try:
                reply = json.loads(payload.decode('utf8'))
            except (ValueError, UnicodeError, RecursionError):
                _fail('json')
            if not isinstance(reply, dict):
                _fail('reply')
            if reply.get('id') != self.sequence or type(reply.get('id')) is not int:
                continue
            if 'error' in reply or not isinstance(reply.get('result'), dict):
                _fail('rpc')
            return reply['result']
        _fail('message_limit')

    def frame(self):
        result = self._rpc('Page.getFrameTree')
        tree = result.get('frameTree')
        frame = tree.get('frame') if isinstance(tree, dict) else None
        if not isinstance(frame, dict):
            _fail('frame')
        selected = {}
        for key, maximum in (('id', 128), ('loaderId', 128), ('url', 8192), ('unreachableUrl', 8192)):
            text = frame.get(key, '')
            if not isinstance(text, str) or len(text) > maximum or (key in ('id', 'loaderId', 'url') and not text):
                _fail('frame_field')
            selected[key] = text
        return selected

    def reload(self):
        self._rpc('Page.reload')
