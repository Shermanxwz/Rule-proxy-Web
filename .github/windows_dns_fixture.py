"""Bounded localhost DNS mechanism fixture, never a system resolver or forwarder.

Only one fresh nonce A/IN question is answered. Raw packets, query names, peer
ports and paths stay private. Observation is not isolation/egress evidence.
"""
import re
import socket
import struct
import threading
import time

MAX_DATAGRAM = 1232
MAX_DATAGRAMS = 32
MAX_BYTES = 65536
ANSWER = bytes((192, 0, 2, 123))
SUFFIX = '.n0a.invalid'


def query_name(nonce):
    if type(nonce) is not str or re.fullmatch('[0-9a-f]{32}', nonce) is None:
        raise ValueError('fixture nonce')
    return nonce + SUFFIX


def answer_query(raw, expected_name):
    """Strict single-question DNS, optional empty EDNS0 OPT. No arbitrary names.

    Compression is not needed for the sole query question and is rejected.
    OPT must be the sole additional record, root name, version0, no options.
    Unsupported input is inconclusive fixture input, never evidence of blocking.
    """
    if type(raw) is not bytes or not 12 <= len(raw) <= MAX_DATAGRAM:
        raise ValueError('bound')
    if type(expected_name) is not str or re.fullmatch('[0-9a-f]{32}\\.n0a\\.invalid', expected_name) is None:
        raise ValueError('name')
    transaction, flags, qd, an, ns, ar = struct.unpack('!6H', raw[:12])
    if flags & ~0x0130 or qd != 1 or an != 0 or ns != 0 or ar not in (0, 1):
        raise ValueError('header')
    offset = 12; labels = []
    while True:
        if offset >= len(raw): raise ValueError('question')
        length = raw[offset]; offset += 1
        if length == 0: break
        if length > 63 or offset + length > len(raw): raise ValueError('question')
        label = raw[offset:offset+length]; offset += length
        if re.fullmatch(b'[a-zA-Z0-9-]+', label) is None: raise ValueError('question')
        labels.append(label)
        if len(labels) > 3: raise ValueError('question')
    if b'.'.join(labels).lower() != expected_name.encode('ascii'):
        raise ValueError('name')
    if offset + 4 > len(raw) or raw[offset:offset+4] != b'\x00\x01\x00\x01':
        raise ValueError('question')
    offset += 4; question = raw[12:offset]
    if ar:
        if len(raw)-offset != 11 or raw[offset] != 0:
            raise ValueError('edns')
        kind, udp_size, ttl, length = struct.unpack('!HHIH', raw[offset+1:])
        if kind != 41 or not 512 <= udp_size <= 65535 or ttl & ~0x8000 or length != 0:
            raise ValueError('edns')
        offset += 11
    if offset != len(raw): raise ValueError('trailing')
    response_flags = 0x8400 | (flags & 0x0110)  # QR, authoritative; RD/CD echoed, no RA/AD assertion.
    opt = b'\0' + struct.pack('!HHIH', 41, MAX_DATAGRAM, ttl & 0x8000, 0) if ar else b''
    return (struct.pack('!6H', transaction, response_flags, 1, 1, 0, ar) + question
            + b'\xc0\x0c' + struct.pack('!HHIH', 1, 1, 0, 4) + ANSWER + opt)


class DnsFixture:
    """One owned socket/thread. Closing it cannot prove DNS broker cancellation."""
    def __init__(self, nonce, *, deadline):
        self.name = query_name(nonce)
        if type(deadline) not in (int, float) or not time.monotonic() < deadline <= time.monotonic()+120:
            raise ValueError('fixture deadline')
        self.deadline = deadline
        self.socket = None; self.thread = None
        self.stop = threading.Event(); self.ready = threading.Event()
        self.query_observed = threading.Event()
        self.observation_lock = threading.Lock()
        self.counts = dict(datagrams=0, bytes=0, matched_queries=0, answers_sent=0,
                           rejected=0, oversized=0, send_failed=0)
        self.error = 'none'; self.closed = False; self.close_uncertain = False
        self.mode = 'answer'; self.bind_port = 0
        self.bind_address='127.0.0.1';self.allowed_peers=('127.0.0.1',)

    @classmethod
    def for_test(cls, nonce, *, deadline, mode):
        if mode not in ('answer', 'wrong_address', 'rcode', 'drop'): raise ValueError('fixture mode')
        result = cls(nonce, deadline=deadline); result.mode = mode; return result

    @classmethod
    def for_port53(cls, nonce, *, deadline):
        result=cls(nonce,deadline=deadline);result.bind_port=53;return result

    @classmethod
    def for_loopback2(cls, nonce, *, deadline, standard_port=False):
        if type(standard_port) is not bool:raise ValueError('fixture mode')
        result=cls(nonce,deadline=deadline)
        result.bind_address='127.0.0.2';result.allowed_peers=('127.0.0.1','127.0.0.2')
        result.bind_port=53 if standard_port else 0
        return result

    def start(self):
        if self.socket is not None or self.thread is not None: raise ValueError('fixture started')
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM); self.socket = sock
        if self.bind_port==53 or self.bind_address=='127.0.0.2':
            if not hasattr(socket,'SO_EXCLUSIVEADDRUSE'):raise ValueError('exclusive unavailable')
            sock.setsockopt(socket.SOL_SOCKET,socket.SO_EXCLUSIVEADDRUSE,1)
        sock.bind((self.bind_address, self.bind_port)); sock.settimeout(.1)
        port = sock.getsockname()[1]
        if type(port) is not int or not (port==53 if self.bind_port==53 else 1025<=port<=65535): raise ValueError('fixture port')
        self.thread = threading.Thread(target=self._serve, daemon=True)
        self.thread.start()
        if not self.ready.wait(max(0, min(1, self.deadline-time.monotonic()))):
            raise TimeoutError('fixture ready')
        return port

    def _serve(self):
        self.ready.set()
        try:
            while not self.stop.is_set() and time.monotonic() < self.deadline:
                if self.counts['datagrams'] >= MAX_DATAGRAMS or self.counts['bytes'] >= MAX_BYTES:
                    self.error = 'bound'; return
                try: raw, peer = self.socket.recvfrom(MAX_DATAGRAM+1)
                except socket.timeout: continue
                except OSError as exc:
                    if self.stop.is_set(): return
                    if getattr(exc, 'winerror', None) == 10040:
                        with self.observation_lock:
                            self.counts['datagrams'] += 1; self.counts['oversized'] += 1
                            self.counts['bytes'] = min(MAX_BYTES, self.counts['bytes']+MAX_DATAGRAM+1)
                        continue
                    self.error = 'receive'; return
                with self.observation_lock:
                    self.counts['datagrams'] += 1
                    self.counts['bytes'] = min(MAX_BYTES, self.counts['bytes']+len(raw))
                    if len(raw) > MAX_DATAGRAM:
                        self.counts['oversized'] += 1; continue
                    if peer[0] not in self.allowed_peers:
                        self.counts['rejected'] += 1; continue
                    try: response = answer_query(raw, self.name)
                    except ValueError:
                        self.counts['rejected'] += 1; continue
                    self.counts['matched_queries'] += 1
                    self.query_observed.set()
                    if self.mode == 'drop': continue
                    opt_size = 11 if struct.unpack('!H', response[10:12])[0] else 0
                    answer_end = len(response)-opt_size
                    if self.mode == 'wrong_address': response = response[:answer_end-4] + bytes((192, 0, 2, 124)) + response[answer_end:]
                    if self.mode == 'rcode':
                        response = response[:2] + struct.pack('!H', struct.unpack('!H', response[2:4])[0] | 3) + response[4:6] + b'\0\0' + response[8:answer_end-16] + response[answer_end:]
                    if self.stop.is_set() or time.monotonic() >= self.deadline:
                        self.error = 'deadline'; return
                    try:
                        self.socket.settimeout(max(0, min(.1, self.deadline-time.monotonic())))
                        if self.socket.sendto(response, peer) != len(response): raise OSError('short datagram')
                        self.counts['answers_sent'] += 1
                    except OSError:
                        self.counts['send_failed'] += 1; self.error = 'send'; return
            if not self.stop.is_set(): self.error = 'deadline'
        except Exception:
            self.error = 'operation'

    def snapshot(self, *, deadline):
        # Excludes datagram processing/send and its counter commit, not idle receive. This is a
        # temporal observation, not attribution of a late broker datagram.
        if not self.observation_lock.acquire(timeout=max(0,min(.5,deadline-time.monotonic()))):
            raise TimeoutError('fixture snapshot')
        try:return dict(self.counts)
        finally:self.observation_lock.release()

    def finish(self, *, deadline):
        deadline = min(deadline, self.deadline)
        self.stop.set(); close_ok = not self.close_uncertain
        if self.socket is not None:
            try: self.socket.close()
            except OSError: self.close_uncertain = True; close_ok = False
        stopped = self.thread is None
        if self.thread is not None:
            try: self.thread.join(max(0, deadline-time.monotonic()))
            except RuntimeError: pass
            stopped = not self.thread.is_alive()
        if self.socket is not None:
            try: close_ok = close_ok and self.socket.fileno() == -1
            except Exception: close_ok = False; self.close_uncertain = True
        self.closed = close_ok and stopped
        return dict(ready=self.ready.is_set(), socket_closed=close_ok,
                    thread_stopped=stopped, cleanup_confirmed=self.closed,
                    error=self.error, counts=dict(self.counts) if stopped else None,
                    query_observed=self.query_observed.is_set(),
                    byte_count_is_observed_lower_bound=True,
                    broker_cancellation_proven=False)
