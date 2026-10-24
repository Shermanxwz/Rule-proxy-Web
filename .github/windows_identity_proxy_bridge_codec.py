"""Inactive identity-proxy-bridge-v1 pure byte contract; no transport or clock I/O.

Limits include CRLF bytes in each line and the complete request in MAX_REQUEST.
Parsers do not authorize endpoints: both numeric endpoints are immutable config.
Ports 49152..65535 are a conservative fixture choice, not an allocation guarantee
or universal port requirement. Deadline is caller-supplied monotonic milliseconds;
this module does not read a clock.
"""
from dataclasses import dataclass
import re
import struct

MAX_REQUEST = 8192
MAX_HEADERS = 32
MAX_LINE = 1024
MAX_RESPONSE = 256
FRAME_SIZE = 48
AUTHORITY = b'ruleproxy-identity-proof.invalid'
TOKEN = re.compile(rb"[!#$%&'*+.^_`|~0-9A-Za-z-]+\Z")
FORBIDDEN = frozenset((b'transfer-encoding', b'authorization', b'proxy-authorization',
                       b'cookie', b'set-cookie', b'upgrade'))


class BridgeProtocolError(ValueError):
    """Closed protocol label only; never incorporates private input bytes."""


@dataclass(frozen=True)
class BridgeConfig:
    run_id: bytes
    case_id: bytes
    frontend_port: int
    relay_port: int
    deadline: int

    def __post_init__(self):
        if any(type(x) is not bytes or len(x) != 16 for x in (self.run_id, self.case_id)):
            raise BridgeProtocolError('identity')
        if any(type(x) is not int or not 49152 <= x <= 65535
               for x in (self.frontend_port, self.relay_port)):
            raise BridgeProtocolError('port')
        if self.frontend_port == self.relay_port:
            raise BridgeProtocolError('port_collision')
        if type(self.deadline) is not int or self.deadline < 0:
            raise BridgeProtocolError('deadline')

    @property
    def frontend_host(self):
        return '127.0.0.1'

    @property
    def relay_host(self):
        return '10.0.2.2'


def _config(config):
    if type(config) is not BridgeConfig:
        raise BridgeProtocolError('configuration')


@dataclass(frozen=True)
class Frame:
    frame_type: int
    sequence: int
    status: int


def encode_frame(config, frame_type, status=0):
    _config(config)
    if type(frame_type) is not int or not 1 <= frame_type <= 5:
        raise BridgeProtocolError('frame_type')
    if type(status) is not int or not 0 <= status <= (4 if frame_type == 4 else 0):
        raise BridgeProtocolError('frame_status')
    return struct.pack('<4sB3s16s16sII', b'RPB1', frame_type, b'\0'*3,
                       config.run_id, config.case_id, frame_type - 1, status)


def decode_frame(config, data):
    _config(config)
    if type(data) is not bytes or len(data) != FRAME_SIZE:
        raise BridgeProtocolError('frame_length')
    magic, kind, reserved, run, case, sequence, status = struct.unpack('<4sB3s16s16sII', data)
    if magic != b'RPB1' or reserved != b'\0'*3:
        raise BridgeProtocolError('frame_header')
    if run != config.run_id or case != config.case_id:
        raise BridgeProtocolError('frame_identity')
    if data != encode_frame(config, kind, status) or sequence != kind - 1:
        raise BridgeProtocolError('frame_sequence')
    return Frame(kind, sequence, status)


def relay_request(config):
    _config(config)
    return (b'GET /p1/' + config.case_id.hex().encode('ascii') + b' HTTP/1.1\r\nHost: ' +
            config.relay_host.encode('ascii') + b':' + str(config.relay_port).encode('ascii') +
            b'\r\nConnection: close\r\n\r\n')


def _authority(value):
    if value not in (AUTHORITY, AUTHORITY + b':80'):
        raise BridgeProtocolError('authority')
    return AUTHORITY


def parse_proxy_request(config, data):
    _config(config)
    if type(data) is not bytes or not 1 <= len(data) <= MAX_REQUEST:
        raise BridgeProtocolError('request_bound')
    if not data.endswith(b'\r\n\r\n') or data.count(b'\r\n\r\n') != 1:
        raise BridgeProtocolError('request_framing')
    lines = data[:-2].split(b'\r\n')
    if any(len(line) + 2 > MAX_LINE for line in lines):
        raise BridgeProtocolError('line_bound')
    if any(any(c > 126 or c < 32 and c != 9 for c in line) for line in lines):
        raise BridgeProtocolError('ascii_control')
    if len(lines) - 2 > MAX_HEADERS:
        raise BridgeProtocolError('header_count')
    parts = lines[0].split(b' ')
    if len(parts) != 3 or parts[0] != b'GET' or parts[2] != b'HTTP/1.1':
        raise BridgeProtocolError('request_line')
    expected_path = b'/' + config.case_id.hex().encode('ascii')
    target = parts[1]
    if not target.startswith(b'http://') or not target.endswith(expected_path):
        raise BridgeProtocolError('target')
    authority = target[7:-len(expected_path)]
    _authority(authority)
    host = None
    content_length = None
    for line in lines[1:-1]:
        name, sep, value = line.partition(b':')
        if not sep or not TOKEN.fullmatch(name):
            raise BridgeProtocolError('header_name')
        name = name.lower()
        value = value.strip(b' \t')
        if name in FORBIDDEN:
            raise BridgeProtocolError('forbidden_header')
        if name == b'host':
            if host is not None:
                raise BridgeProtocolError('duplicate_host')
            host = _authority(value)
        elif name == b'content-length':
            if content_length is not None or value != b'0':
                raise BridgeProtocolError('content_length')
            content_length = value
    if host != _authority(authority):
        raise BridgeProtocolError('host')
    return relay_request(config)


def expected_response(config):
    _config(config)
    return (b'HTTP/1.1 200 OK\r\nContent-Length: 32\r\nConnection: close\r\n\r\n' +
            config.case_id.hex().encode('ascii'))


def validate_response(config, data, eof):
    _config(config)
    if type(eof) is not bool or not eof:
        raise BridgeProtocolError('response_eof')
    if type(data) is not bytes or len(data) > MAX_RESPONSE or data != expected_response(config):
        raise BridgeProtocolError('response')


class _Buffer:
    """Bounded split-point accumulator; finalization is single-use even on failure."""
    limit = 0

    def __init__(self, config):
        _config(config)
        self.config = config
        self._data = bytearray()
        self._finished = False

    def feed(self, chunk):
        if self._finished or type(chunk) is not bytes:
            raise BridgeProtocolError('buffer_state')
        if len(self._data) + len(chunk) > self.limit:
            self._finished = True
            raise BridgeProtocolError('buffer_bound')
        self._data.extend(chunk)

    def _take(self):
        if self._finished:
            raise BridgeProtocolError('buffer_state')
        self._finished = True
        return bytes(self._data)


class RequestBuffer(_Buffer):
    limit = MAX_REQUEST

    def finish(self):
        return parse_proxy_request(self.config, self._take())


class ResponseBuffer(_Buffer):
    limit = MAX_RESPONSE

    def finish(self, eof=False):
        return validate_response(self.config, self._take(), eof)


class FrameBuffer(_Buffer):
    limit = FRAME_SIZE

    def finish(self):
        return decode_frame(self.config, self._take())
