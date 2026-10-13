"""ALE relay foundation, excluded from the product package and launch path.

Only Winsock's kernel-supplied redirect context/records identify a destination.
Client payload is never a destination header. The only outbound connect this
module performs is to a numeric 127.0.0.1 SOCKS listener. No direct retry exists.
Compiling the companion unsigned driver does not make this a working backend.
"""
from __future__ import annotations

import argparse
import asyncio
import ctypes
from dataclasses import dataclass
import ipaddress
import os
import socket
import struct
import time
from typing import Callable

ABI = 1
MAGIC = 0x52505244
CONTEXT = struct.Struct("<IIIHHQQ16s16s")
MAX_RECORDS = 65536
HANDSHAKE_SECONDS = 5.0
BUFFER_BYTES = 65536
MAX_CONNECTIONS = 128
IDLE_SECONDS = 300.0
# Windows SDK shared/mstcpip.h: _WSAIOW(IOC_VENDOR, 220/221/222).
QUERY_RECORDS = 0x980000DC
QUERY_CONTEXT = 0x980000DD
SET_RECORDS = 0x980000DE


class Refused(ConnectionError):
    """No authorized, kernel-redirected route was established."""


def port(value: int) -> int:
    if isinstance(value, bool) or not isinstance(value, int) or not 1025 <= value <= 65535:
        raise ValueError("the local relay/SOCKS port must be from 1025 through 65535")
    return value


@dataclass(frozen=True)
class Destination:
    family: int
    address: bytes
    port: int
    session: int
    process_id: int

    @classmethod
    def parse(cls, data: bytes, generation: bytes, sessions: frozenset[int]) -> Destination:
        if len(generation) != 16 or not any(generation) or len(data) != CONTEXT.size:
            raise Refused("invalid redirect generation or context length")
        magic, version, size, family, remote_port, session, pid, observed, address = CONTEXT.unpack(data)
        if (magic != MAGIC or version != ABI or size != CONTEXT.size or observed != generation
                or session == 0 or session not in sessions or pid == 0 or remote_port == 0):
            raise Refused("redirect context does not match the admitted relay/session")
        if family == 2:
            if any(address[4:]):
                raise Refused("noncanonical IPv4 redirect context")
            address = address[:4]
        elif family != 23:
            raise Refused("unsupported redirect address family")
        ip = ipaddress.ip_address(address)
        if (ip.is_unspecified or ip.is_loopback or ip.is_multicast or ip.is_link_local
                or str(ip) == "255.255.255.255" or getattr(ip, "ipv4_mapped", None) is not None):
            raise Refused("the destination cannot be safely represented by this relay")
        return cls(family, address, remote_port, session, pid)

    def request(self) -> bytes:
        return b"\x05\x01\x00" + (b"\x01" if self.family == 2 else b"\x04") + self.address + struct.pack("!H", self.port)


class WinsockMetadata:
    """Actual Winsock ioctls. Their failure never falls back to client data."""

    def __init__(self):
        if os.name != "nt":
            raise OSError("Winsock redirect metadata requires native Windows")
        self.ws = ctypes.WinDLL("ws2_32", use_last_error=True)
        self.ws.WSAIoctl.argtypes = [ctypes.c_size_t, ctypes.c_ulong, ctypes.c_void_p, ctypes.c_ulong,
                                    ctypes.c_void_p, ctypes.c_ulong, ctypes.POINTER(ctypes.c_ulong),
                                    ctypes.c_void_p, ctypes.c_void_p]
        self.ws.WSAIoctl.restype = ctypes.c_int
        self.ws.WSAGetLastError.argtypes = []
        self.ws.WSAGetLastError.restype = ctypes.c_int

    def query(self, peer: socket.socket) -> tuple[bytes, bytes]:
        def read(code: int, size: int) -> bytes:
            output = ctypes.create_string_buffer(size)
            used = ctypes.c_ulong()
            if self.ws.WSAIoctl(peer.fileno(), code, None, 0, output, size, ctypes.byref(used), None, None) != 0:
                raise Refused(f"Winsock redirect query refused: {self.ws.WSAGetLastError()}")
            if not 0 < used.value <= size:
                raise Refused("empty or oversized kernel redirect metadata")
            return output.raw[:used.value]
        # Fixed versioned context first; then opaque OS records. Never parse the
        # latter or let the application provide/replace either buffer.
        return read(QUERY_CONTEXT, CONTEXT.size), read(QUERY_RECORDS, MAX_RECORDS)

    def set_records(self, upstream: socket.socket, records: bytes) -> None:
        if not 0 < len(records) <= MAX_RECORDS:
            raise Refused("invalid redirect record size")
        data = ctypes.create_string_buffer(records)
        used = ctypes.c_ulong()
        if self.ws.WSAIoctl(upstream.fileno(), SET_RECORDS, data, len(records), None, 0,
                            ctypes.byref(used), None, None) != 0:
            raise Refused(f"Winsock redirect association refused: {self.ws.WSAGetLastError()}")


def socks_connect(destination: Destination, socks_port: int,
                  associate: Callable[[socket.socket], None], timeout: float = HANDSHAKE_SECONDS) -> socket.socket:
    """Associate WFP records, then CONNECT via the one configured local core."""
    port(socks_port)
    if timeout <= 0:
        raise ValueError("a positive SOCKS handshake deadline is required")
    upstream = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    deadline = time.monotonic() + timeout

    def limit() -> None:
        remaining = deadline - time.monotonic()
        if remaining <= 0:
            raise TimeoutError("SOCKS handshake deadline exceeded")
        upstream.settimeout(remaining)

    def exact(count: int) -> bytes:
        chunks = bytearray()
        while len(chunks) < count:
            limit()
            data = upstream.recv(count - len(chunks))
            if not data:
                raise Refused("SOCKS listener closed during handshake")
            chunks.extend(data)
        return bytes(chunks)

    try:
        associate(upstream)  # Required before the outbound connect.
        limit()
        upstream.connect(("127.0.0.1", socks_port))
        limit()
        upstream.sendall(b"\x05\x01\x00")
        if exact(2) != b"\x05\x00":
            raise Refused("SOCKS listener did not select no-authentication")
        limit()
        upstream.sendall(destination.request())
        header = exact(4)
        if header[:3] != b"\x05\x00\x00":
            raise Refused("SOCKS CONNECT refused")
        if header[3] == 1:
            exact(6)
        elif header[3] == 4:
            exact(18)
        elif header[3] == 3:
            length = exact(1)[0]
            if length == 0:
                raise Refused("empty SOCKS bound domain")
            exact(length + 2)
        else:
            raise Refused("unknown SOCKS bound address type")
        upstream.settimeout(None)
        return upstream
    except BaseException:
        upstream.close()
        raise


async def pump(reader: asyncio.StreamReader, writer: asyncio.StreamWriter) -> None:
    """Bounded buffers, backpressure and half-close; no alternate connection."""
    while True:
        data = await asyncio.wait_for(reader.read(BUFFER_BYTES), IDLE_SECONDS)
        if not data:
            if writer.can_write_eof():
                writer.write_eof()
                await asyncio.wait_for(writer.drain(), IDLE_SECONDS)
            return
        writer.write(data)
        await asyncio.wait_for(writer.drain(), IDLE_SECONDS)


class Relay:
    def __init__(self, socks_port: int, generation: bytes, sessions: frozenset[int]):
        self.socks_port = port(socks_port)
        if (len(generation) != 16 or not any(generation) or not 1 <= len(sessions) <= 128
                or any(isinstance(s, bool) or not isinstance(s, int) or not 0 < s < 2**64 for s in sessions)):
            raise ValueError("one relay generation and 1 through 128 admitted session IDs are required")
        self.generation, self.sessions = generation, sessions
        self.metadata = WinsockMetadata()
        self.active = 0

    async def handle(self, reader: asyncio.StreamReader, writer: asyncio.StreamWriter) -> None:
        upstream_writer = None
        tasks: list[asyncio.Task] = []
        counted = False
        try:
            if self.active >= MAX_CONNECTIONS:
                raise Refused("relay connection capacity exceeded")
            self.active += 1
            counted = True
            context, records = self.metadata.query(writer.get_extra_info("socket"))
            destination = Destination.parse(context, self.generation, self.sessions)
            connecting = asyncio.create_task(asyncio.to_thread(
                socks_connect, destination, self.socks_port,
                lambda sock: self.metadata.set_records(sock, records)))
            try:
                raw = await asyncio.shield(connecting)
            except BaseException:
                # A cancelled coroutine does not stop its blocking thread.
                # Reap its bounded handshake and close any socket it returns.
                try:
                    orphan = await connecting
                    orphan.close()
                except (OSError, ValueError, TimeoutError):
                    pass
                raise
            try:
                raw.setblocking(False)
                upstream_reader, upstream_writer = await asyncio.open_connection(sock=raw, limit=BUFFER_BYTES)
            except BaseException:
                raw.close()
                raise
            tasks = [asyncio.create_task(pump(reader, upstream_writer)), asyncio.create_task(pump(upstream_reader, writer))]
            await asyncio.gather(*tasks)
        except (OSError, ValueError, TimeoutError):
            # Do not disclose original destinations, session IDs or payload.
            pass
        finally:
            for task in tasks:
                task.cancel()
            if tasks:
                await asyncio.gather(*tasks, return_exceptions=True)
            if counted:
                self.active -= 1
            for stream in [upstream_writer, writer]:
                if stream is not None:
                    stream.close()
                    try:
                        await asyncio.wait_for(stream.wait_closed(), 2)
                    except (OSError, TimeoutError):
                        pass


async def serve(args) -> None:
    relay = Relay(args.socks_port, bytes.fromhex(args.generation), frozenset(args.session))
    # Separate explicit numeric listeners; no wildcard bind or socket reuse.
    sockets = []
    servers = []
    try:
        for family, host in [(socket.AF_INET, "127.0.0.1"), (socket.AF_INET6, "::1")]:
            listener = socket.socket(family, socket.SOCK_STREAM)
            sockets.append(listener)
            listener.setsockopt(socket.SOL_SOCKET, socket.SO_EXCLUSIVEADDRUSE, 1)
            if family == socket.AF_INET6:
                listener.setsockopt(socket.IPPROTO_IPV6, socket.IPV6_V6ONLY, 1)
            listener.bind((host, port(args.listen_port)))
            listener.listen(64)
            listener.setblocking(False)
            servers.append(await asyncio.start_server(relay.handle, sock=listener, limit=BUFFER_BYTES))
        await asyncio.gather(*(server.serve_forever() for server in servers))
    finally:
        for server in servers:
            server.close()
            await server.wait_closed()
        for listener in sockets:
            listener.close()


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--socks-port", type=int, required=True)
    parser.add_argument("--listen-port", type=int, required=True)
    parser.add_argument("--generation", required=True)
    parser.add_argument("--session", type=int, action="append", required=True)
    args = parser.parse_args()
    asyncio.run(serve(args))


if __name__ == "__main__":
    main()
