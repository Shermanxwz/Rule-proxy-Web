"""Bounded pcapng reader for private CI evidence; never return option strings.

Format: https://www.ietf.org/archive/id/draft-ietf-opsawg-pcapng-05.html
Only full Ethernet Enhanced Packet Blocks have sufficient identity and time.
Unknown blocks are counted; unsupported packet blocks fail rather than vanish.
"""
import hashlib
import struct

MAX_BYTES = 512 * 1024 * 1024
MAX_BLOCK = 2 * 1024 * 1024
MAX_BLOCKS = 5_000_000


class CaptureError(ValueError):
    """Only fixed error codes may leave a parser or native capture boundary."""


def options(raw, endian):
    values, offset = {}, 0
    while offset < len(raw):
        if len(raw) - offset < 4:
            raise CaptureError("pcapng_option_truncated")
        code, size = struct.unpack_from(endian + "HH", raw, offset)
        offset += 4
        end = offset + ((size + 3) & ~3)
        if end > len(raw):
            raise CaptureError("pcapng_option_truncated")
        if code == 0:
            if size or end != len(raw):
                raise CaptureError("pcapng_option_end_invalid")
            break
        values.setdefault(code, []).append(raw[offset:offset + size])
        offset = end
    return values


def single(values, code, size, default):
    if code not in values:
        return default
    found = values[code]
    if len(found) != 1 or len(found[0]) != size:
        raise CaptureError("pcapng_option_invalid")
    return found[0]


class Reader:
    def __init__(self, stream):
        self.stream, self.bytes, self.blocks, self.records = stream, 0, 0, 0
        self.sections, self.interfaces, self.unknown_blocks = 0, 0, 0
        self.digest = hashlib.sha256()
        self.reported_drop_count = 0
        self.first_ns = self.last_ns = None

    def read(self, length, optional=False):
        raw = self.stream.read(length)
        self.bytes += len(raw)
        self.digest.update(raw)
        if self.bytes > MAX_BYTES:
            raise CaptureError("capture_size_limit")
        if not raw and optional:
            return None
        if len(raw) != length:
            raise CaptureError("pcapng_block_truncated")
        return raw

    def frames(self):
        endian, interfaces, section_end = None, [], None
        while True:
            start = self.bytes
            header = self.read(12, optional=True)
            if header is None:
                if not self.sections or section_end is not None and self.bytes != section_end:
                    raise CaptureError("pcapng_section_incomplete")
                return
            self.blocks += 1
            if self.blocks > MAX_BLOCKS:
                raise CaptureError("capture_record_limit")
            is_section = header[:4] == b"\x0a\x0d\x0d\x0a"
            if is_section:
                if section_end is not None and start != section_end:
                    raise CaptureError("pcapng_section_length_invalid")
                endian = {b"\x4d\x3c\x2b\x1a": "<", b"\x1a\x2b\x3c\x4d": ">"}.get(header[8:12])
                if endian is None:
                    raise CaptureError("pcapng_byte_order_invalid")
            elif endian is None:
                raise CaptureError("pcapng_section_missing")
            kind, size = struct.unpack_from(endian + "II", header)
            if not 12 <= size <= MAX_BLOCK or size % 4:
                raise CaptureError("pcapng_block_size_invalid")
            rest = self.read(size - 12)
            block = header + rest
            if struct.unpack_from(endian + "I", block, len(block) - 4)[0] != size:
                raise CaptureError("pcapng_block_trailer_invalid")
            body = block[8:-4]
            if is_section:
                if len(body) < 16:
                    raise CaptureError("pcapng_section_truncated")
                major, minor, length = struct.unpack_from(endian + "HHq", body, 4)
                if (major, minor) != (1, 0) or length < -1:
                    raise CaptureError("pcapng_section_version_invalid")
                options(body[16:], endian)
                self.sections += 1
                interfaces = []
                section_end = None if length == -1 else self.bytes + length
                continue
            if section_end is not None and self.bytes > section_end:
                raise CaptureError("pcapng_section_overflow")
            if kind == 1:
                if len(body) < 8 or len(interfaces) >= 1024:
                    raise CaptureError("pcapng_interface_invalid")
                link, reserved, snap = struct.unpack_from(endian + "HHI", body)
                if link != 1 or reserved or snap > MAX_BLOCK:
                    raise CaptureError("pcapng_unsupported_linktype")
                values = options(body[8:], endian)
                resolution = single(values, 9, 1, b"\x06")[0]
                power = resolution & 127
                if power > (63 if resolution & 128 else 18):
                    raise CaptureError("pcapng_timestamp_resolution_invalid")
                divisor = (2 if resolution & 128 else 10) ** power
                offset = struct.unpack(endian + "q", single(values, 14, 8, b"\0" * 8))[0]
                interfaces.append((snap, divisor, offset))
                self.interfaces += 1
            elif kind == 6:
                if len(body) < 20:
                    raise CaptureError("pcapng_packet_truncated")
                index, high, low, captured, original = struct.unpack_from(endian + "IIIII", body)
                if index >= len(interfaces):
                    raise CaptureError("pcapng_interface_missing")
                snap, divisor, offset = interfaces[index]
                if captured != original or captured < 14 or (snap and captured > snap):
                    raise CaptureError("pcapng_packet_truncated")
                end = 20 + ((captured + 3) & ~3)
                if end > len(body):
                    raise CaptureError("pcapng_packet_truncated")
                values = options(body[end:], endian)
                flags = struct.unpack(endian + "I", single(values, 2, 4, b"\0" * 4))[0]
                if flags & 3 == 3:
                    raise CaptureError("pcapng_direction_invalid")
                dropped = struct.unpack(endian + "Q", single(values, 4, 8, b"\0" * 8))[0]
                self.reported_drop_count += dropped
                timestamp = (((high << 32) | low) * 1_000_000_000) // divisor + offset * 1_000_000_000
                if not 0 <= timestamp < 2**63:
                    raise CaptureError("pcapng_timestamp_invalid")
                self.first_ns = timestamp if self.first_ns is None else min(self.first_ns, timestamp)
                self.last_ns = timestamp if self.last_ns is None else max(self.last_ns, timestamp)
                self.records += 1
                yield timestamp, flags & 3, body[20:20 + captured]
            elif kind == 5:
                if len(body) < 12 or struct.unpack_from(endian + "I", body)[0] >= len(interfaces):
                    raise CaptureError("pcapng_statistics_invalid")
                values = options(body[12:], endian)
                # ISB counters are totals; retain a conservative positive signal.
                for code in (5, 7):
                    self.reported_drop_count += struct.unpack(endian + "Q", single(values, code, 8, b"\0" * 8))[0]
            elif kind in (2, 3):
                raise CaptureError("pcapng_unsupported_packet_block")
            else:
                self.unknown_blocks += 1

    def facts(self):
        return {"sha256": self.digest.hexdigest(), "bytes": self.bytes, "blocks": self.blocks,
                "records": self.records, "sections": self.sections, "interfaces": self.interfaces,
                "unknown_blocks": self.unknown_blocks, "reported_drop_count": self.reported_drop_count,
                "first_packet_unix_ns": self.first_ns, "last_packet_unix_ns": self.last_ns}
