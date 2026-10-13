"""Protocol/transport checks with real TCP peers, not kernel redirect proof."""
import asyncio
from contextlib import contextmanager
import importlib.util
import ipaddress
import os
from pathlib import Path
import socket
import struct
import subprocess
import sys
import threading
import time
import unittest

import ruleproxy

SOURCE = Path(ruleproxy.__file__).resolve().parent.parent / 'native' / 'windows' / 'relay.py'
if not SOURCE.is_file():
    raise unittest.SkipTest('ALE development foundation is excluded from the product package')
spec = importlib.util.spec_from_file_location('ruleproxy_ale_relay_tests', SOURCE)
relay = importlib.util.module_from_spec(spec)
sys.modules[spec.name] = relay
spec.loader.exec_module(relay)
GENERATION = bytes(range(16))
SESSIONS = frozenset({7})


def context(**changes):
    values = {'magic': relay.MAGIC, 'version': 1, 'size': 64, 'family': 2, 'port': 443,
              'session': 7, 'pid': 42, 'generation': GENERATION,
              'address': ipaddress.ip_address('192.0.2.25').packed + bytes(12)}
    values.update(changes)
    return relay.CONTEXT.pack(*values.values())


def exact(peer, size):
    data = bytearray()
    while len(data) < size:
        part = peer.recv(size - len(data))
        if not part:
            raise EOFError('test peer disconnected')
        data.extend(part)
    return bytes(data)


@contextmanager
def witness(reply=b'\x05\x00\x00\x01' + bytes(6), method=b'\x05\x00', delay=0):
    server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server.bind(('127.0.0.1', 0))
    server.listen(2)
    server.settimeout(0.2)
    records = {'requests': [], 'deliveries': [], 'errors': []}
    stopped = threading.Event()

    def work():
        while not stopped.is_set():
            try:
                peer, _ = server.accept()
            except TimeoutError:
                continue
            except OSError:
                return
            try:
                with peer:
                    peer.settimeout(2)
                    if exact(peer, 3) != b'\x05\x01\x00':
                        raise ValueError('incorrect SOCKS greeting')
                    for byte in method:
                        peer.sendall(bytes([byte]))
                    if method != b'\x05\x00':
                        continue
                    request = exact(peer, 4)
                    length = 4 if request[3] == 1 else 16
                    request += exact(peer, length + 2)
                    records['requests'].append(request)
                    for byte in reply:
                        if delay:
                            time.sleep(delay)
                        peer.sendall(bytes([byte]))
                    if not reply.startswith(b'\x05\x00\x00'):
                        continue
                    payload = peer.recv(65536)
                    if payload:
                        records['deliveries'].append(payload)
                        peer.sendall(payload)
            except (OSError, EOFError):
                pass
            except BaseException as exc:
                records['errors'].append(str(exc))
    worker = threading.Thread(target=work, daemon=True)
    worker.start()
    try:
        yield server.getsockname()[1], records
    finally:
        stopped.set()
        server.close()
        worker.join(3)
        if worker.is_alive():
            raise AssertionError('test witness did not stop')
        if records['errors']:
            raise AssertionError(records['errors'])


class RedirectContextTests(unittest.TestCase):
    def test_versioned_context_and_numeric_connect(self):
        result = relay.Destination.parse(context(), GENERATION, SESSIONS)
        self.assertEqual(result.request(), b'\x05\x01\x00\x01\xc0\x00\x02\x19\x01\xbb')
        ipv6 = ipaddress.ip_address('2001:db8::25').packed
        result = relay.Destination.parse(context(family=23, address=ipv6), GENERATION, SESSIONS)
        self.assertEqual(result.request(), b'\x05\x01\x00\x04' + ipv6 + b'\x01\xbb')

    def test_context_identity_and_canonical_length_required(self):
        cases = [context(magic=0), context(version=2), context(size=65), context(family=10),
                 context(port=0), context(session=8), context(session=0), context(pid=0),
                 context(generation=bytes(16)), context(address=bytes([192, 0, 2, 25, 1]) + bytes(11)),
                 context()[:-1], context() + b'x']
        for data in cases:
            with self.subTest(data=data[:16]), self.assertRaises(relay.Refused):
                relay.Destination.parse(data, GENERATION, SESSIONS)
        with self.assertRaises(relay.Refused):
            relay.Destination.parse(context(), bytes(16), SESSIONS)

    def test_unrepresentable_or_local_destinations_refused(self):
        for address in ['0.0.0.0', '127.0.0.1', '224.0.0.1', '169.254.1.1', '255.255.255.255',
                        '::', '::1', 'ff02::1', 'fe80::1', '::ffff:192.0.2.25']:
            ip = ipaddress.ip_address(address)
            data = context(family=2 if ip.version == 4 else 23, address=ip.packed + bytes(16 - len(ip.packed)))
            with self.subTest(address=address), self.assertRaises(relay.Refused):
                relay.Destination.parse(data, GENERATION, SESSIONS)

    def test_local_listener_port_validation(self):
        for value in [True, False, 0, 1024, 65536, '1080', None]:
            with self.subTest(value=value), self.assertRaises(ValueError):
                relay.port(value)
        self.assertEqual(relay.port(1025), 1025)


class SocksTransportTests(unittest.TestCase):
    def test_fragmented_replies_all_bound_address_families(self):
        replies = [b'\x05\x00\x00\x01' + bytes(6), b'\x05\x00\x00\x04' + bytes(18),
                   b'\x05\x00\x00\x03\x03abc\x00\x50']
        destination = relay.Destination.parse(context(), GENERATION, SESSIONS)
        for reply in replies:
            with self.subTest(reply=reply), witness(reply) as (socks_port, records):
                associations = []
                def associate(sock):
                    with self.assertRaises(OSError):
                        sock.getpeername()
                    associations.append(sock.fileno())
                with relay.socks_connect(destination, socks_port, associate) as peer:
                    peer.settimeout(2)
                    peer.sendall(b'real-TCP-echo')
                    self.assertEqual(exact(peer, 13), b'real-TCP-echo')
                self.assertEqual(records['requests'], [destination.request()])
                self.assertEqual(records['deliveries'], [b'real-TCP-echo'])
                self.assertEqual(len(associations), 1)

    def test_ipv6_original_destination_is_sent_to_socks(self):
        destination = relay.Destination.parse(context(family=23, address=ipaddress.ip_address('2001:db8::25').packed), GENERATION, SESSIONS)
        with witness() as (socks_port, records):
            with relay.socks_connect(destination, socks_port, lambda _: None):
                pass
            self.assertEqual(records['requests'], [destination.request()])

    def test_refused_or_malformed_reply_never_delivers_payload(self):
        destination = relay.Destination.parse(context(), GENERATION, SESSIONS)
        replies = [b'\x05\x05\x00\x01', b'\x04\x00\x00\x01', b'\x05\x00\x01\x01',
                   b'\x05\x00\x00\x09', b'\x05\x00\x00\x03\x00']
        for reply in replies:
            with self.subTest(reply=reply), witness(reply) as (socks_port, records):
                with self.assertRaises(relay.Refused):
                    relay.socks_connect(destination, socks_port, lambda _: None)
                self.assertEqual(records['deliveries'], [])

    def test_authentication_method_change_refused(self):
        destination = relay.Destination.parse(context(), GENERATION, SESSIONS)
        with witness(method=b'\x05\x02') as (socks_port, records):
            with self.assertRaises(relay.Refused):
                relay.socks_connect(destination, socks_port, lambda _: None)
            self.assertEqual(records['requests'], [])

    def test_kernel_association_failure_precedes_any_connect(self):
        destination = relay.Destination.parse(context(), GENERATION, SESSIONS)
        with witness() as (socks_port, records):
            def denied(_):
                raise relay.Refused('kernel association refused')
            with self.assertRaises(relay.Refused):
                relay.socks_connect(destination, socks_port, denied)
            self.assertEqual(records['requests'], [])

    def test_absolute_deadline_bounds_trickled_reply(self):
        destination = relay.Destination.parse(context(), GENERATION, SESSIONS)
        with witness(delay=0.07) as (socks_port, records):
            started = time.monotonic()
            with self.assertRaises(TimeoutError):
                relay.socks_connect(destination, socks_port, lambda _: None, timeout=0.25)
            self.assertLess(time.monotonic() - started, 1.5)
            self.assertEqual(records['deliveries'], [])

    @unittest.skipUnless(os.name == 'nt', 'actual Winsock redirect metadata requires Windows')
    def test_real_unredirected_socket_has_no_authorized_metadata(self):
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as listener:
            listener.bind(('127.0.0.1', 0))
            listener.listen(1)
            with socket.create_connection(listener.getsockname(), timeout=2) as client:
                peer, _ = listener.accept()
                with peer, self.assertRaises(relay.Refused):
                    relay.WinsockMetadata().query(peer)


class AsyncPumpTests(unittest.IsolatedAsyncioTestCase):
    async def test_backpressure_and_half_close_keep_response(self):
        payload = b'01234567' * 32768
        results = []

        async def server(reader, writer):
            try:
                # Copy client bytes back in bounded chunks, then half-close.
                await relay.pump(reader, writer)
            finally:
                writer.close()
                await writer.wait_closed()
                results.append(True)
        listener = await asyncio.start_server(server, '127.0.0.1', 0, limit=relay.BUFFER_BYTES)
        try:
            reader, writer = await asyncio.open_connection('127.0.0.1', listener.sockets[0].getsockname()[1])
            writer.write(payload)
            await writer.drain()
            writer.write_eof()
            self.assertEqual(await asyncio.wait_for(reader.readexactly(len(payload)), 3), payload)
            self.assertEqual(await asyncio.wait_for(reader.read(1), 3), b'')
            writer.close()
            await writer.wait_closed()
            await asyncio.sleep(0)
            self.assertEqual(results, [True])
        finally:
            listener.close()
            await listener.wait_closed()


@unittest.skipUnless(os.name == 'nt', 'actual process references and TCP peer ownership require Windows')
class NativeCoreOwnershipTests(unittest.TestCase):
    def created(self, pid):
        import ctypes
        kernel = ctypes.WinDLL('kernel32', use_last_error=True)
        kernel.OpenProcess.argtypes = [ctypes.c_ulong, ctypes.c_int, ctypes.c_ulong]
        kernel.OpenProcess.restype = ctypes.c_void_p
        kernel.GetProcessTimes.argtypes = [ctypes.c_void_p, *([ctypes.POINTER(ctypes.c_ulonglong)] * 4)]
        kernel.GetProcessTimes.restype = ctypes.c_int
        kernel.CloseHandle.argtypes = [ctypes.c_void_p]
        kernel.CloseHandle.restype = ctypes.c_int
        handle = kernel.OpenProcess(0x101000, False, pid)
        if not handle:
            raise ctypes.WinError(ctypes.get_last_error())
        try:
            times = [ctypes.c_ulonglong() for _ in range(4)]
            if not kernel.GetProcessTimes(handle, *(ctypes.byref(value) for value in times)):
                raise ctypes.WinError(ctypes.get_last_error())
            return times[0].value
        finally:
            kernel.CloseHandle(handle)

    def test_actual_tcp_peer_owns_admitted_core_identity(self):
        core = relay.CoreProcess(os.getpid(), self.created(os.getpid()))
        try:
            destination = relay.Destination.parse(context(), GENERATION, SESSIONS)
            with witness() as (socks_port, records):
                with relay.socks_connect(destination, socks_port, lambda _: None, verify_peer=core.verify_peer) as peer:
                    peer.settimeout(2)
                    peer.sendall(b'owner-pinned')
                    self.assertEqual(exact(peer, 12), b'owner-pinned')
                self.assertEqual(records['requests'], [destination.request()])
        finally:
            core.close()

    def test_same_pid_with_wrong_creation_time_is_refused(self):
        with self.assertRaises(relay.Refused):
            relay.CoreProcess(os.getpid(), self.created(os.getpid()) + 1)

    def test_another_actual_process_cannot_replace_core_at_the_port(self):
        child = subprocess.Popen([sys.executable, '-c', 'import time; time.sleep(20)'],
                                 stdin=subprocess.DEVNULL, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        core = None
        try:
            core = relay.CoreProcess(child.pid, self.created(child.pid))
            destination = relay.Destination.parse(context(), GENERATION, SESSIONS)
            with witness() as (socks_port, records):
                with self.assertRaises(relay.Refused):
                    relay.socks_connect(destination, socks_port, lambda _: None, verify_peer=core.verify_peer)
                core.alive()
                self.assertEqual(records['requests'], [])
                self.assertEqual(records['deliveries'], [])
        finally:
            if core:
                core.close()
            child.kill()
            child.wait(timeout=3)

    def test_dead_held_core_is_refused_before_socks_payload(self):
        child = subprocess.Popen([sys.executable, '-c', 'import time; time.sleep(20)'],
                                 stdin=subprocess.DEVNULL, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        core = None
        try:
            core = relay.CoreProcess(child.pid, self.created(child.pid))
            child.kill()
            child.wait(timeout=3)
            destination = relay.Destination.parse(context(), GENERATION, SESSIONS)
            with witness() as (socks_port, records):
                with self.assertRaises(relay.Refused):
                    relay.socks_connect(destination, socks_port, lambda _: None, verify_peer=core.verify_peer)
                self.assertEqual(records['requests'], [])
                self.assertEqual(records['deliveries'], [])
        finally:
            if core:
                core.close()
            if child.poll() is None:
                child.kill()
                child.wait(timeout=3)


if __name__ == '__main__':
    unittest.main()
