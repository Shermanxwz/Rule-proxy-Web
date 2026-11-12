"""Synthetic LevelDB files: no browser/profile, native library, or protobufs."""
from __future__ import annotations

from pathlib import Path
from contextlib import contextmanager
import ctypes
import os
import stat
import struct
import sys
import tempfile
from types import SimpleNamespace
import unittest
from unittest.mock import patch

from ruleproxy import web_app_leveldb as reader


KEY_A = b'web_apps-dt-' + b'a' * 32
KEY_M = b'web_apps-dt-' + b'm' * 32
KEY_P = b'web_apps-dt-' + b'p' * 32


def varint(value):
    output = bytearray()
    while value >= 128:
        output.append((value & 127) | 128)
        value >>= 7
    output.append(value)
    return bytes(output)


def string(value):
    return varint(len(value)) + value


def crc32c(value):
    # Independent bitwise oracle, not the implementation's lookup table.
    result = 0xFFFFFFFF
    for byte in value:
        result ^= byte
        for _ in range(8):
            result = (result >> 1) ^ (0x82F63B78 if result & 1 else 0)
    return result ^ 0xFFFFFFFF


def masked(value):
    checksum = crc32c(value)
    return (((checksum >> 15) | (checksum << 17)) + 0xA282EAD8) & 0xFFFFFFFF


def physical(value, kind=1):
    return struct.pack('<IHB', masked(bytes((kind,)) + value), len(value), kind) + value


def log_records(records):
    output = bytearray()
    for record in records:
        pos, first = 0, True
        while first or pos < len(record):
            left = 32768 - len(output) % 32768
            if left < 7:
                output.extend(bytes(left))
                left = 32768
            amount = min(left - 7, len(record) - pos)
            last = pos + amount == len(record)
            kind = (1 if last else 2) if first else (4 if last else 3)
            output.extend(physical(record[pos:pos + amount], kind))
            first = False
            pos += amount
    return bytes(output)


def batch(sequence, operations):
    output = struct.pack('<QI', sequence, len(operations))
    for key, value in operations:
        output += bytes((0 if value is None else 1,)) + string(key)
        if value is not None:
            output += string(value)
    return output


def internal(key, sequence=1, kind=1):
    return key + struct.pack('<Q', sequence << 8 | kind)


def block(entries, restart_every=2):
    output, restarts, previous = bytearray(), [], b''
    for index, (key, value) in enumerate(entries):
        shared = 0
        if index % restart_every == 0:
            restarts.append(len(output))
        else:
            while shared < min(len(key), len(previous)) and key[shared] == previous[shared]:
                shared += 1
        output.extend(varint(shared) + varint(len(key) - shared) + varint(len(value)))
        output.extend(key[shared:] + value)
        previous = key
    if not restarts:
        restarts = [0]
    return bytes(output) + struct.pack('<' + 'I' * (len(restarts) + 1), *restarts, len(restarts))


def literal(value):
    if not value:
        return b''
    length = len(value) - 1
    if length < 60:
        return bytes((length << 2,)) + value
    width = max(1, (length.bit_length() + 7) // 8)
    return bytes(((59 + width) << 2,)) + length.to_bytes(width, 'little') + value


def snappy(value, copy_run=False):
    if copy_run:
        position = value.index(b'A' * 65) + 1
        # COPY_2, length=64, offset=1: an overlapping copy.
        encoded = literal(value[:position]) + b'\xfe\x01\x00' + literal(value[position + 64:])
    else:
        encoded = literal(value)
    return varint(len(value)) + encoded


def stored_block(value, compression=0):
    payload = snappy(value, copy_run=compression == 2) if compression else value
    kind = bytes((1 if compression else 0,))
    return payload + kind + struct.pack('<I', masked(payload + kind))


def table_bytes(groups, compression=0, separators=None, transform=None):
    output, index_entries, handles = bytearray(), [], []
    for index, entries in enumerate(groups):
        data = block(entries)
        if transform is not None:
            data = transform(data)
        stored = stored_block(data, compression)
        handle = (len(output), len(stored) - 5)
        handles.append(handle)
        output.extend(stored)
        separator = separators[index] if separators else entries[-1][0]
        index_entries.append((separator, varint(handle[0]) + varint(handle[1])))
    meta = stored_block(block([]))
    meta_handle = varint(len(output)) + varint(len(meta) - 5)
    output.extend(meta)
    index = stored_block(block(index_entries))
    index_handle = varint(len(output)) + varint(len(index) - 5)
    output.extend(index)
    footer = meta_handle + index_handle
    output.extend(footer + bytes(40 - len(footer)) + struct.pack('<Q', 0xDB4775248B80FB57))
    return bytes(output), handles


def new_file(number, data, smallest, largest, level=0):
    return (varint(7) + varint(level) + varint(number) + varint(len(data))
            + string(smallest) + string(largest))


def manifest_header(log=10, previous_log=0, sequence=100, next_file=1000,
                    comparator=b'leveldb.BytewiseComparator'):
    return (b'\x01' + string(comparator) + b'\x02' + varint(log)
            + b'\x03' + varint(next_file) + b'\x04' + varint(sequence)
            + b'\x09' + varint(previous_log))


@contextmanager
def windows_api(attributes=0x10, query_ok=True, drive_type=3, crt_fails=False,
                last_write=100, change_time=200):
    """Check the native call contract without running Windows or a device."""
    calls, closed = [], []

    class Function:
        def __init__(self, implementation):
            self.implementation = implementation

        def __call__(self, *args):
            return self.implementation(*args)

    def create_root(name, access, sharing, security, disposition, flags, template):
        calls.append(('root', name, access, sharing, disposition, flags))
        return 100

    def create_relative(handle, access, object_attributes, io_status, allocation,
                        file_attributes, sharing, disposition, options, ea_buffer, ea_length):
        attributes_value = object_attributes._obj
        calls.append(('relative', attributes_value.ObjectName.contents.Buffer,
                      attributes_value.RootDirectory, access, sharing, disposition, options))
        handle._obj.value = 101
        return 0

    def query(handle, info_class, output, size):
        if info_class == 9:
            output._obj.Attributes = attributes
        elif info_class == 18:
            output._obj.VolumeSerialNumber = 17
            output._obj.FileId[:] = range(16)
        elif info_class == 0:
            output._obj.CreationTime = 10
            output._obj.LastWriteTime = last_write() if callable(last_write) else last_write
            output._obj.ChangeTime = change_time() if callable(change_time) else change_time
            output._obj.FileAttributes = attributes
        elif info_class == 1:
            output._obj.EndOfFile = 16
            output._obj.Directory = int(bool(attributes & 0x10))
        else:
            raise AssertionError('Unexpected file information class')
        return query_ok

    def to_fd(handle, flags):
        calls.append(('fd', handle, flags))
        if crt_fails:
            raise OSError('CRT fixture failure')
        return 900

    kernel = SimpleNamespace(
        GetDriveTypeW=Function(lambda name: drive_type),
        CreateFileW=Function(create_root),
        GetFileInformationByHandleEx=Function(query),
        CloseHandle=Function(lambda handle: closed.append(getattr(handle, 'value', handle)) or 1),
    )
    native = SimpleNamespace(NtCreateFile=Function(create_relative))
    with patch.object(ctypes, 'WinDLL', lambda name, **kwargs: kernel if name == 'kernel32' else native,
                      create=True), \
            patch.object(ctypes, 'get_last_error', return_value=5, create=True), \
            patch.object(reader.os, 'O_BINARY', 0x8000, create=True), \
            patch.dict(sys.modules, {'msvcrt': SimpleNamespace(open_osfhandle=to_fd,
                                                              get_osfhandle=lambda fd: 101)}):
        yield calls, closed


class LevelDBTests(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        # On macOS tempfile's /var may itself be a symlink; the fixture path
        # explicitly chooses the real directory, not a path the reader resolves.
        self.root = Path(self.temporary.name).resolve()
        self.header = manifest_header()
        self.edits = []
        (self.root / 'CURRENT').write_bytes(b'MANIFEST-000001\n')
        (self.root / '000010.log').write_bytes(b'')
        self.manifest()

    def manifest(self, edits=None):
        (self.root / 'MANIFEST-000001').write_bytes(log_records(
            [self.header] + (self.edits if edits is None else edits)))

    def wal(self, operations, sequence=101, number=10):
        (self.root / f'{number:06}.log').write_bytes(log_records([batch(sequence, operations)]))

    def table(self, number, groups, level=0, extension='ldb', **options):
        data, handles = table_bytes(groups, **options)
        name = f'{number:06}.{extension}'
        (self.root / name).write_bytes(data)
        self.edits.append(new_file(number, data, groups[0][0][0], groups[-1][-1][0], level))
        self.manifest()
        return name, handles

    def read(self, keys=None):
        return reader.read_values(self.root, {KEY_A} if keys is None else keys)

    def test_empty_keys_do_not_open_files(self):
        with patch.object(reader.os, 'open', side_effect=AssertionError('No I/O')):
            self.assertEqual(reader.read_values(self.root / 'missing', set()), {})

    def test_empty_database_without_logs(self):
        self.header = manifest_header(log=0, sequence=0)
        self.manifest()
        (self.root / '000010.log').unlink()
        self.assertEqual(self.read(), {})

    def test_empty_wal_writebatch(self):
        self.wal([], sequence=0)
        self.assertEqual(self.read(), {})

    def test_wal_selects_only_exact_keys_and_opaque_values(self):
        opaque = b'\x00\xff\x80https://example.invalid/\x00'
        self.wal([(b'other', KEY_A + b' fake-url'), (KEY_A, opaque), (KEY_M, b'not requested')])
        self.assertEqual(self.read(), {KEY_A: opaque})
        self.assertEqual(self.read({KEY_P}), {})

    def test_wal_sequence_increments_for_unselected_operations(self):
        self.wal([(KEY_A, b'first'), (b'ignored', b''), (KEY_A, b'last')], 20)
        self.wal([(KEY_A, b'older')], 21, number=11)
        self.assertEqual(self.read(), {KEY_A: b'last'})

    def test_wal_current_previous_newer_ignore_old_logs(self):
        self.header = manifest_header(log=10, previous_log=8)
        self.manifest()
        self.wal([(KEY_A, b'previous')], 101, 8)
        self.wal([(KEY_M, b'current')], 102, 10)
        self.wal([(KEY_P, b'newer')], 103, 11)
        (self.root / '000007.log').write_bytes(b'invalid old log ' + KEY_A)
        self.assertEqual(self.read({KEY_A, KEY_M, KEY_P}),
                         {KEY_A: b'previous', KEY_M: b'current', KEY_P: b'newer'})

    def test_wal_tombstone_hides_sst_then_later_put_restores(self):
        self.table(2, [[(internal(KEY_A, 2), b'sst')]])
        self.wal([(KEY_A, None)], 3)
        self.assertEqual(self.read(), {})
        self.wal([(KEY_A, None), (KEY_A, b'restored')], 3)
        self.assertEqual(self.read(), {KEY_A: b'restored'})

    def test_sst_sequence_and_tombstone_not_filename_order(self):
        self.table(2, [[(internal(KEY_A, 9, 0), b'')]])
        self.table(3, [[(internal(KEY_A, 7), b'old')]])
        self.wal([(KEY_A, b'older WAL')], 8)
        self.assertEqual(self.read(), {})
        self.table(4, [[(internal(KEY_A, 10), b'new')]])
        self.assertEqual(self.read(), {KEY_A: b'new'})

    def test_sst_versions_across_blocks_and_levels(self):
        self.table(2, [[(internal(KEY_A, 20), b'new')], [(internal(KEY_A, 19), b'old')]], level=1)
        self.table(3, [[(internal(KEY_A, 18), b'older')]], level=1, extension='sst')
        self.assertEqual(self.read(), {KEY_A: b'new'})

    def test_manifest_deleted_sst_and_orphans_never_open(self):
        old, _ = self.table(2, [[(internal(KEY_A, 99), b'stale')]])
        data, _ = table_bytes([[(internal(KEY_A, 3), b'live')]])
        (self.root / '000003.ldb').write_bytes(data)
        # Add before delete in wire order, as VersionEdit ordering is semantic.
        edit = new_file(3, data, internal(KEY_A, 3), internal(KEY_A, 3)) + b'\x06\x00\x02'
        edit += b'\x05\x00' + string(internal(KEY_A, 99))  # compact pointer
        self.edits.append(edit)
        self.manifest()
        (self.root / old).write_bytes(b'corrupt retired file ' + KEY_A)
        (self.root / '000999.sst').write_bytes(KEY_A + b'https://stale.invalid/')
        opened = []
        original = reader._Directory.file

        def observe(owner, name, maximum):
            opened.append(name)
            return original(owner, name, maximum)

        with patch.object(reader._Directory, 'file', observe):
            self.assertEqual(self.read(), {KEY_A: b'live'})
        self.assertNotIn(old, opened)
        self.assertNotIn('000999.sst', opened)

    def test_manifest_moves_same_file_between_levels(self):
        self.table(2, [[(internal(KEY_A, 1), b'value')]])
        data = (self.root / '000002.ldb').read_bytes()
        self.edits.append(new_file(2, data, internal(KEY_A, 1), internal(KEY_A, 1), level=1)
                          + b'\x06\x00\x02')
        self.manifest()
        self.assertEqual(self.read(), {KEY_A: b'value'})

    def test_table_index_skips_unrelated_data_blocks(self):
        name, handles = self.table(2, [[(internal(KEY_A, 1), b'unrelated')],
                                       [(internal(KEY_M, 1), b'chosen')],
                                       [(internal(KEY_P, 1), b'unrelated')]])
        raw = bytearray((self.root / name).read_bytes())
        raw[handles[0][0]] ^= 0x80  # Even its bad CRC is outside the selected range.
        (self.root / name).write_bytes(raw)
        reads = []
        original = reader._File.read

        def observe(source, offset, length):
            reads.append((source.name, offset, length))
            return original(source, offset, length)

        with patch.object(reader._File, 'read', observe):
            self.assertEqual(self.read({KEY_M}), {KEY_M: b'chosen'})
        for number in (0, 2):
            self.assertNotIn((name, handles[number][0], handles[number][1] + 5), reads)
        self.assertIn((name, handles[1][0], handles[1][1] + 5), reads)

    def test_shortened_separator_does_not_invent_key_from_value(self):
        # The first separator is between actual users A and P; M is absent.
        self.table(2, [[(internal(KEY_A), KEY_M + b'fake URL')],
                       [(internal(KEY_P), b'other')]],
                   separators=[internal(KEY_M, reader._MAX_SEQUENCE), internal(KEY_P)])
        self.assertEqual(self.read({KEY_M}), {})

    def test_manifest_range_skips_unrelated_entire_table(self):
        name, _ = self.table(2, [[(internal(KEY_P, 1), b'irrelevant')]])
        size = (self.root / name).stat().st_size
        (self.root / name).write_bytes(b'x' * size)
        self.wal([(KEY_A, b'chosen')])
        self.assertEqual(self.read(), {KEY_A: b'chosen'})

    def test_snappy_compressed_sst_including_overlapping_copy(self):
        self.table(2, [[(internal(KEY_A, 1), b'A' * 80)]], compression=2)
        self.assertEqual(self.read(), {KEY_A: b'A' * 80})

    def test_snappy_all_copy_types_and_long_literal(self):
        fixtures = [
            (varint(11) + literal(b'a') + bytes((1 | (6 << 2), 1)), b'a' * 11),
            (varint(67) + literal(b'abc') + bytes((2 | (63 << 2), 3, 0)), (b'abc' * 23)[:67]),
            (varint(8) + literal(b'ab') + bytes((3 | (5 << 2), 2, 0, 0, 0)), b'abababab'),
            (snappy(bytes(range(256)) * 4), bytes(range(256)) * 4),
        ]
        for encoded, expected in fixtures:
            with self.subTest(encoded=encoded[:16]):
                self.assertEqual(reader._snappy(encoded, reader._Budget()), expected)

    def test_snappy_copy_offsets_above_byte_and_uint16(self):
        prefix = bytes(range(256)) * 274
        fixtures = [
            (prefix[:512], 257, 7, bytes((0x20 | (3 << 2) | 1, 1))),
            (prefix, 65537, 8, bytes(((7 << 2) | 3,)) + struct.pack('<I', 65537)),
        ]
        for initial, offset, length, copy in fixtures:
            encoded = varint(len(initial) + length) + literal(initial) + copy
            expected = initial + initial[len(initial) - offset:len(initial) - offset + length]
            with self.subTest(offset=offset):
                self.assertEqual(reader._snappy(encoded, reader._Budget()), expected)

    def test_crc32c_standard_vectors_and_incremental(self):
        self.assertEqual(reader._crc32c(b''), 0)
        self.assertEqual(reader._crc32c(b'123456789'), 0xE3069283)
        self.assertEqual(reader._crc32c(bytes(32)), 0x8A9136AA)
        self.assertEqual(reader._crc32c(b'456789', reader._crc32c(b'123')), 0xE3069283)
        self.assertEqual(reader._masked_crc(b'123456789'), masked(b'123456789'))

    def test_fragmented_wal_records_and_block_trailers(self):
        large = b'x' * 70000
        records = [batch(101, [(b'other', large), (KEY_A, b'value')]),
                   batch(103, [(KEY_M, b'next')])]
        (self.root / '000010.log').write_bytes(log_records(records))
        self.assertEqual(self.read({KEY_A, KEY_M}), {KEY_A: b'value', KEY_M: b'next'})

    def test_empty_first_fragment_at_exact_seven_byte_boundary(self):
        # A complete first record leaves precisely seven bytes in its block.
        first = batch(1, [(b'k', b'x' * 32736)])
        self.assertEqual(len(first), 32754)
        (self.root / '000010.log').write_bytes(log_records([first, batch(2, [(KEY_A, b'ok')])]))
        self.assertEqual(self.read(), {KEY_A: b'ok'})

    def test_zero_preallocated_tail_is_accepted(self):
        data = log_records([batch(101, [(KEY_A, b'value')])])
        (self.root / '000010.log').write_bytes(data + bytes(65536 - len(data)))
        self.assertEqual(self.read(), {KEY_A: b'value'})

    def test_zero_tail_with_later_nonzero_data_fails(self):
        (self.root / '000010.log').write_bytes(bytes(32768) + log_records([batch(101, [(KEY_A, b'bad')])]))
        with self.assertRaisesRegex(ValueError, 'preallocated'):
            self.read()

    def test_manifest_and_wal_crc_corruption(self):
        self.wal([(KEY_A, b'value')])
        for name in ('MANIFEST-000001', '000010.log'):
            path = self.root / name
            original = path.read_bytes()
            corrupt = bytearray(original)
            corrupt[0] ^= 1
            path.write_bytes(corrupt)
            with self.subTest(name=name), self.assertRaisesRegex(ValueError, 'CRC32C'):
                self.read()
            path.write_bytes(original)

    def test_data_and_index_block_crc_corruption(self):
        name, handles = self.table(2, [[(internal(KEY_A, 1), b'value')]])
        path = self.root / name
        original = path.read_bytes()
        footer = reader._Cursor(original[-48:-8])
        reader._handle(footer, len(original) - 48)
        index_handle = reader._handle(footer, len(original) - 48)
        for handle in [handles[0], index_handle]:
            corrupt = bytearray(original)
            corrupt[handle[0] + handle[1] + 1] ^= 1
            path.write_bytes(corrupt)
            with self.subTest(handle=handle), self.assertRaisesRegex(ValueError, 'CRC32C'):
                self.read()
        path.write_bytes(original)

    def test_current_is_exact_manifest_name_and_newline(self):
        for value in (b'MANIFEST-000001', b'MANIFEST-000001\r\n', b'MANIFEST-000001\n\n',
                      b'../MANIFEST-000001\n', b'/MANIFEST-000001\n', b'MANIFEST-0\n',
                      b'MANIFEST-18446744073709551616\n', b'MANIFEST-1\nextra', b'\xff\n'):
            (self.root / 'CURRENT').write_bytes(value)
            with self.subTest(value=value), self.assertRaises(ValueError):
                self.read()

    def test_manifest_unknown_tags_comparator_missing_and_bad_numbers(self):
        records = [b'\x08', manifest_header(comparator=b'custom'), b'\x02\x0a',
                   manifest_header(next_file=10), manifest_header(previous_log=11),
                   manifest_header(sequence=reader._MAX_SEQUENCE + 1),
                   self.header + b'\x02\x0a', self.header + b'\x05\x07' + string(internal(KEY_A))]
        for record in records:
            (self.root / 'MANIFEST-000001').write_bytes(log_records([record]))
            with self.subTest(record=record[:24]), self.assertRaises(ValueError):
                self.read()

    def test_missing_live_files_and_manifest_size_mismatch(self):
        name, _ = self.table(2, [[(internal(KEY_A), b'value')]])
        original = (self.root / name).read_bytes()
        (self.root / name).unlink()
        with self.assertRaisesRegex(ValueError, 'Missing'):
            self.read()
        (self.root / name).write_bytes(original + b'x')
        with self.assertRaisesRegex(ValueError, 'size'):
            self.read()
        (self.root / name).write_bytes(original)
        (self.root / '000010.log').unlink()
        with self.assertRaisesRegex(ValueError, 'Missing'):
            self.read()

    def test_duplicate_file_number_aliases_fail(self):
        name, _ = self.table(2, [[(internal(KEY_A), b'value')]])
        alias = self.root / '000002.sst'
        alias.write_bytes((self.root / name).read_bytes())
        with self.assertRaisesRegex(ValueError, 'Ambiguous'):
            self.read()
        alias.unlink()
        (self.root / '10.log').write_bytes(b'')
        with self.assertRaisesRegex(ValueError, 'Ambiguous'):
            self.read()

    def test_overflowing_file_number_fails(self):
        (self.root / '18446744073709551616.log').write_bytes(b'')
        with self.assertRaisesRegex(ValueError, 'Overflowing'):
            self.read()

    def test_wal_malformed_truncated_fragment_and_operation_records(self):
        cases = [b'\x01', physical(b'', 3), physical(b'abc', 2), physical(b'', 5),
                 physical(b'', 4), physical(b'abc', 2) + physical(b'xyz', 1),
                 physical(b'abc', 2) + bytes(32768 - 10),
                 physical(b'bad header'), physical(batch(101, [(KEY_A, b'value')])[:-1]),
                 physical(struct.pack('<QI', 101, 2) + b'\x00' + string(KEY_A)),
                 physical(struct.pack('<QI', 101, 1) + b'\x02' + string(KEY_A)),
                 physical(batch(101, [(KEY_A, b'value')]) + b'junk'),
                 physical(struct.pack('<QI', reader._MAX_SEQUENCE, 2)
                          + b'\x00' + string(KEY_A) + b'\x00' + string(KEY_M))]
        for data in cases:
            (self.root / '000010.log').write_bytes(data)
            with self.subTest(data=data[:24]), self.assertRaises(ValueError):
                self.read()

    def test_physical_record_cannot_cross_block_boundary(self):
        # CRC is valid for the nominal payload, but length crosses 32KiB.
        (self.root / '000010.log').write_bytes(physical(b'x' * 32762))
        with self.assertRaises(ValueError):
            self.read()

    def test_valid_zero_trailer_and_nonzero_trailer_failure(self):
        first = batch(1, [(b'k', b'x' * 32737)])
        self.assertEqual(len(first), 32755)
        data = log_records([first, batch(2, [(KEY_A, b'value')])])
        self.assertEqual(data[32762:32768], bytes(6))
        (self.root / '000010.log').write_bytes(data)
        self.assertEqual(self.read(), {KEY_A: b'value'})
        broken = bytearray(data)
        broken[32765] = 1
        (self.root / '000010.log').write_bytes(broken)
        with self.assertRaises(ValueError):
            self.read()

    def test_snappy_invalid_and_truncated_inputs(self):
        cases = [b'', b'\x80', b'\x80\x00', varint(4) + b'\x01\x00',
                 varint(4) + b'\x01\x01', varint(1) + literal(b'ab'),
                 varint(2) + literal(b'a'), varint(4) + b'\xf0',
                 varint(4) + literal(b'a') + b'\xfe\x01',
                 varint(reader._MAX_BLOCK_BYTES + 1)]
        for encoded in cases:
            with self.subTest(encoded=encoded), self.assertRaises(ValueError):
                reader._snappy(encoded, reader._Budget())

    def test_table_invalid_restart_prefix_internal_key_and_order(self):
        bad_entries = [
            [(b'short', b'')], [(internal(KEY_A, 1, 2), b'value')],
            [(internal(KEY_M), b'1'), (internal(KEY_A), b'2')],
            [(internal(KEY_A), b'1'), (internal(KEY_A), b'2')],
            [(internal(KEY_A, 101), b'ahead')], [(internal(KEY_A, 1, 0), b'not empty')],
        ]
        for entries in bad_entries:
            self.edits = []
            self.table(2, [entries])
            with self.subTest(entries=entries), self.assertRaises(ValueError):
                self.read({KEY_A, KEY_M, b'short'})
        transforms = [lambda data: data[:-4] + bytes(4),
                      lambda data: data[:-8] + struct.pack('<II', 1, 1),
                      lambda data: b'\x01' + data[1:],
                      lambda data: data[:-4] + struct.pack('<I', 0xFFFFFFFF)]
        for transform in transforms:
            self.edits = []
            self.table(2, [[(internal(KEY_A), b'value')]], transform=transform)
            with self.subTest(transform=transform), self.assertRaises(ValueError):
                self.read()

    def test_table_bad_magic_padding_handle_and_compression(self):
        name, handles = self.table(2, [[(internal(KEY_A), b'value')]])
        path = self.root / name
        original = path.read_bytes()
        bad_magic = bytearray(original)
        bad_magic[-1] ^= 1
        bad_padding = bytearray(original)
        bad_padding[-9] = 1
        bad_handle = bytearray(original)
        bad_handle[-48:-38] = b'\xff' * 10
        bad_compression = bytearray(original)
        offset, size = handles[0]
        bad_compression[offset + size] = 2
        bad_compression[offset + size + 1:offset + size + 5] = struct.pack(
            '<I', masked(bad_compression[offset:offset + size + 1]))
        for data in (bad_magic, bad_padding, bad_handle, bad_compression):
            path.write_bytes(data)
            with self.subTest(data=bytes(data[-48:])), self.assertRaises(ValueError):
                self.read()

    def test_all_nonempty_truncated_wal_prefixes_fail_closed(self):
        complete = log_records([batch(101, [(KEY_A, b'opaque-value')])])
        for length in range(1, len(complete)):
            (self.root / '000010.log').write_bytes(complete[:length])
            with self.subTest(length=length), self.assertRaises(ValueError):
                self.read()

    def test_malformed_restart_offsets_never_treat_values_as_entries(self):
        valid = block([(internal(KEY_A), b'value'), (internal(KEY_M), b'other')], restart_every=1)
        end = len(valid) - 12
        for offsets in ((0, 0), (0, 1), (0, end), (1, end - 1)):
            malformed = valid[:end] + struct.pack('<III', *offsets, 2)
            with self.subTest(offsets=offsets), self.assertRaises(ValueError):
                list(reader._entries(malformed, reader._Budget()))

    def test_sequence_duplicate_identical_allowed_conflicting_rejected(self):
        self.table(2, [[(internal(KEY_A, 5), b'value')]])
        self.wal([(KEY_A, b'value')], 5)
        self.assertEqual(self.read(), {KEY_A: b'value'})
        for value in (b'different', None):
            self.wal([(KEY_A, value)], 5)
            with self.subTest(value=value), self.assertRaisesRegex(ValueError, 'Conflicting'):
                self.read()

    def test_snapshot_detects_wal_append_and_manifest_change(self):
        self.wal([(KEY_A, b'value')])
        original_read = reader._File.read
        for name in ('000010.log', 'MANIFEST-000001'):
            path = self.root / name
            data = path.read_bytes()
            changed = False

            def change(source, offset, length):
                nonlocal changed
                output = original_read(source, offset, length)
                if source.name == name and not changed:
                    changed = True
                    path.write_bytes(data + b'\x00')
                return output

            with self.subTest(name=name), patch.object(reader._File, 'read', change), \
                    self.assertRaisesRegex(ValueError, 'changed'):
                self.read()
            path.write_bytes(data)

    def test_snapshot_detects_current_swap_new_log_and_unselected_table_change(self):
        name, _ = self.table(2, [[(internal(KEY_P), b'unselected')]])
        self.wal([(KEY_A, b'value')])
        original_read = reader._File.read
        current = self.root / 'CURRENT'
        for target in ('CURRENT', 'new log', 'unselected'):
            changed = False

            def change(source, offset, length):
                nonlocal changed
                output = original_read(source, offset, length)
                if source.name == '000010.log' and not changed:
                    changed = True
                    if target == 'CURRENT':
                        current.write_bytes(b'MANIFEST-000002\n')
                    elif target == 'new log':
                        (self.root / '000011.log').write_bytes(b'')
                    else:
                        path = self.root / name
                        before = path.stat()
                        os.utime(path, ns=(before.st_atime_ns, before.st_mtime_ns + 1_000_000))
                return output

            with self.subTest(target=target), patch.object(reader._File, 'read', change), \
                    self.assertRaisesRegex(ValueError, 'changed'):
                self.read()
            current.write_bytes(b'MANIFEST-000001\n')
            if (self.root / '000011.log').exists():
                (self.root / '000011.log').unlink()

    @unittest.skipUnless(hasattr(os, 'symlink'), 'Symlinks unavailable')
    def test_symlink_files_and_ancestor_are_rejected(self):
        self.wal([(KEY_A, b'value')])
        self.table(2, [[(internal(KEY_A), b'value')]])
        for name in ('CURRENT', 'MANIFEST-000001', '000010.log', '000002.ldb'):
            path, target = self.root / name, self.root / 'other'
            path.rename(target)
            try:
                path.symlink_to(target)
            except OSError as exc:
                target.rename(path)
                self.skipTest(str(exc))
            try:
                with self.subTest(name=name), self.assertRaises(ValueError):
                    self.read()
            finally:
                path.unlink()
                target.rename(path)
        link = self.root / 'link'
        link.symlink_to(self.root, target_is_directory=True)
        with self.assertRaises(ValueError):
            reader.read_values(link, {KEY_A})
        nested = self.root / 'nested'
        nested.mkdir()
        with self.assertRaises(ValueError):
            reader.read_values(link / 'nested', {KEY_A})

    def test_unc_traversal_reparse_and_special_files_rejected(self):
        for path in (Path('//server/share/db'), Path(r'\\server\share\db'),
                     self.root / '..' / self.root.name, Path(r'\\?\C:\db')):
            with self.subTest(path=path), self.assertRaises(ValueError):
                reader.read_values(path, {KEY_A})
        for mode, attributes in ((stat.S_IFREG, 0x400), (stat.S_IFIFO, 0), (stat.S_IFLNK, 0)):
            with self.subTest(mode=mode), self.assertRaises(ValueError):
                reader._plain(SimpleNamespace(st_mode=mode, st_file_attributes=attributes))

    def test_only_expected_files_are_opened_read_only(self):
        self.wal([(KEY_A, b'value')])
        for name in ('Cookies', 'History', 'Login Data', 'LOCK'):
            (self.root / name).write_bytes(KEY_A + b' irrelevant')
        original = reader.os.open
        calls = []

        def observe(path, flags, *args, **kwargs):
            calls.append(str(path))
            self.assertEqual(flags & os.O_ACCMODE, os.O_RDONLY)
            self.assertFalse(flags & (os.O_CREAT | os.O_TRUNC | os.O_APPEND))
            return original(path, flags, *args, **kwargs)

        with patch.object(reader.os, 'open', observe):
            self.assertEqual(self.read(), {KEY_A: b'value'})
        self.assertFalse(set(calls) & {'Cookies', 'History', 'Login Data', 'LOCK'})

    def test_hard_limits_for_files_reads_records_keys_values_and_time(self):
        self.table(2, [[(internal(KEY_A), b'A' * 80)]], compression=2)
        self.wal([(KEY_M, b'B' * 80)])
        limits = {
            '_MAX_DIRECTORY_ENTRIES': 1, '_MAX_FILES': 2, '_MAX_FILE_BYTES': 10,
            '_MAX_MANIFEST_BYTES': 1, '_MAX_LOG_BYTES': 1, '_MAX_READ_BYTES': 20,
            '_MAX_DECOMPRESSED_BYTES': 1, '_MAX_BLOCK_BYTES': 1,
            '_MAX_RECORD_BYTES': 1, '_MAX_RECORDS': 1, '_MAX_KEYS': 1,
            '_MAX_KEY_BYTES': 1, '_MAX_VALUE_BYTES': 20, '_MAX_RESULT_BYTES': 100,
            '_MAX_SECONDS': 0,
        }
        for name, value in limits.items():
            with self.subTest(limit=name), patch.object(reader, name, value), self.assertRaises(ValueError):
                self.read({KEY_A, KEY_M})

    def test_snappy_declared_size_is_checked_before_allocation(self):
        with patch.object(reader, '_MAX_BLOCK_BYTES', 16), self.assertRaisesRegex(ValueError, 'limit'):
            reader._snappy(varint(1_000_000_000), reader._Budget())

    def test_time_limit_is_checked_inside_crc_and_decoder(self):
        budget = reader._Budget()
        budget.deadline = 10
        with patch.object(reader.time, 'monotonic', return_value=11), self.assertRaisesRegex(ValueError, 'time'):
            reader._crc32c(b'payload', budget=budget)
        with patch.object(reader.time, 'monotonic', return_value=11), self.assertRaisesRegex(ValueError, 'time'):
            reader._snappy(snappy(b'payload'), budget)

    def test_windows_relative_open_is_read_only_shared_and_no_reparse(self):
        with windows_api(attributes=0x10) as (calls, closed):
            self.assertEqual(reader._windows_open('C:\\', directory=True), 100)
            self.assertEqual(calls, [('root', 'C:\\', 0x1200A9, 7, 3, 0x02200000)])
            self.assertEqual(closed, [])
        with windows_api(attributes=0x80) as (calls, closed):
            self.assertEqual(reader._windows_open('CURRENT', parent=100), 900)
            self.assertEqual(calls[0], ('relative', 'CURRENT', 100, 0x120089, 7, 1, 0x00200060))
            self.assertEqual(calls[1], ('fd', 101, os.O_RDONLY | 0x8000))
            self.assertEqual(closed, [])  # Descriptor, not CloseHandle, owns it.

    def test_windows_handle_errors_close_once_and_remote_drives_fail(self):
        for options, exception in (({'attributes': 0x410}, ValueError),
                                   ({'query_ok': False}, OSError)):
            with self.subTest(options=options), windows_api(**options) as (_, closed):
                with self.assertRaises(exception):
                    reader._windows_open('C:\\', directory=True)
                self.assertEqual(closed, [100])
        with windows_api(attributes=0x80, crt_fails=True) as (_, closed):
            with self.assertRaises(OSError):
                reader._windows_open('CURRENT', parent=100)
            self.assertEqual(closed, [101])
        with windows_api(drive_type=4) as (calls, closed):
            with self.assertRaisesRegex(ValueError, 'local'):
                reader._windows_open('Z:\\', directory=True)
            self.assertEqual(calls, [])
            self.assertEqual(closed, [])

    def test_windows_path_ctime_and_crt_ctime_use_native_change_time(self):
        # Regression for an observed Python/Windows CURRENT metadata pair:
        # lstat reports creation-time ctime; fstat reports native change time.
        path_stat = SimpleNamespace(st_dev=8238449528074270901, st_ino=42221246506638041,
                                    st_mode=33206, st_size=16, st_mtime_ns=1794156658764781100,
                                    st_ctime_ns=1794156658764781100)
        fd_stat = SimpleNamespace(**vars(path_stat))
        fd_stat.st_ctime_ns = 1794156658766813800
        self.assertNotEqual(reader._signature(path_stat), reader._signature(fd_stat))
        with windows_api(attributes=0x80), patch.object(reader.os, 'name', 'nt'), \
                patch.object(reader.os, 'fstat', side_effect=AssertionError('Mixed CRT stat')):
            signature = reader._file_signature(900)
            self.assertEqual(signature, (17, bytes(range(16)), 0x80, 16, 100, 200))
            self.assertEqual(reader._file_signature(900), signature)
        for last_write, change_time in ((101, 200), (100, 201)):
            with windows_api(attributes=0x80, last_write=last_write, change_time=change_time), \
                    patch.object(reader.os, 'name', 'nt'):
                self.assertNotEqual(reader._file_signature(900), signature)

    def test_windows_native_stat_checks_type_reparse_and_query_errors(self):
        for options, directory, error in (({'attributes': 0x410}, True, ValueError),
                                          ({'attributes': 0x10}, False, ValueError),
                                          ({'query_ok': False}, True, OSError)):
            with self.subTest(options=options), windows_api(**options), self.assertRaises(error):
                reader._windows_signature(100, directory=directory)

    def test_windows_watch_and_file_use_same_native_signature_and_detect_changes(self):
        # A fake path lstat deliberately exposes a different ctime convention.
        path_stat = SimpleNamespace(st_dev=17, st_ino=22, st_mode=33206, st_size=16,
                                    st_mtime_ns=100, st_ctime_ns=10, st_file_attributes=0x80)

        class FakePath:
            def __truediv__(self, name):
                return SimpleNamespace(lstat=lambda: path_stat)

        owner = reader._Directory(FakePath(), reader._Budget())
        owner.names = ('CURRENT',)
        owner.handle = 100
        owner._check_path = lambda: None
        change_time = [200]
        with windows_api(attributes=0x80, change_time=lambda: change_time[0]), \
                patch.object(reader.os, 'name', 'nt'), patch.object(reader.os, 'close') as close, \
                patch.object(reader.os, 'fstat', side_effect=AssertionError('Mixed CRT stat')):
            with owner.file('CURRENT', 64):
                pass
            self.assertEqual(owner.watched['CURRENT'], (17, bytes(range(16)), 0x80, 16, 100, 200))
            with self.assertRaisesRegex(ValueError, 'changed while reading'):
                with owner.file('CURRENT', 64):
                    change_time[0] = 201
            self.assertEqual(close.call_count, 4)

    def test_metadata_reader_accepts_only_preferences_without_directory_scan(self):
        for name in ('Preferences', 'Secure Preferences'):
            (self.root / name).write_bytes(b'opaque metadata bytes')
            with self.subTest(name=name), \
                    patch.object(Path, 'open', side_effect=AssertionError('No path-based file open')), \
                    patch.object(reader.os, 'scandir', side_effect=AssertionError('No profile scan')):
                self.assertEqual(reader.read_metadata_file(self.root, name), b'opaque metadata bytes')
        for name in ('Cookies', 'History', 'Login Data', '../Preferences', 'preferences',
                     'Preferences:stream', 'CURRENT', '', None):
            with self.subTest(name=name), self.assertRaises(ValueError):
                reader.read_metadata_file(self.root, name)

    def test_metadata_missing_file_limits_and_changes(self):
        with self.assertRaises(FileNotFoundError):
            reader.read_metadata_file(self.root, 'Preferences')
        path = self.root / 'Preferences'
        path.write_bytes(b'original')
        with patch.object(reader, '_MAX_METADATA_BYTES', 4), self.assertRaises(ValueError):
            reader.read_metadata_file(self.root, 'Preferences')
        with patch.object(reader, '_MAX_SECONDS', 0), self.assertRaises(ValueError):
            reader.read_metadata_file(self.root, 'Preferences')
        original_read = reader._File.read

        def mutate(source, offset, length):
            result = original_read(source, offset, length)
            path.write_bytes(b'changed length')
            return result

        with patch.object(reader._File, 'read', mutate), self.assertRaisesRegex(ValueError, 'changed'):
            reader.read_metadata_file(self.root, 'Preferences')

    @unittest.skipUnless(hasattr(os, 'symlink'), 'Symlinks unavailable')
    def test_metadata_file_directory_and_ancestor_symlink_races_never_read_outside(self):
        original_watch, original_read = reader._Directory.watch, reader.os.read
        for kind in ('file', 'directory', 'ancestor'):
            base = self.root / ('race-' + kind)
            parent, outside_parent = base / 'parent', base / 'outside'
            profile, outside_profile = parent / 'profile', outside_parent / 'profile'
            profile.mkdir(parents=True)
            outside_profile.mkdir(parents=True)
            inside, outside = profile / 'Preferences', outside_profile / 'Preferences'
            inside.write_bytes(b'{"url":"https://inside.invalid/"}'.ljust(64))
            outside.write_bytes(b'{"url":"https://outside.invalid/"}'.ljust(64))
            original_stat = inside.stat()
            os.utime(outside, ns=(original_stat.st_atime_ns, original_stat.st_mtime_ns))
            outside_stat = outside.stat()
            self.assertEqual(original_stat.st_size, outside_stat.st_size)
            self.assertEqual(original_stat.st_mtime_ns, outside_stat.st_mtime_ns)
            outside_identity = (outside_stat.st_dev, outside_stat.st_ino)
            probe = base / 'probe-link'
            try:
                probe.symlink_to(outside_profile, target_is_directory=True)
            except OSError as exc:
                self.skipTest(str(exc))
            probe.unlink()
            swapped, read_identities = False, []

            def swap_after_watch(owner, name):
                nonlocal swapped
                signature = original_watch(owner, name)
                if name == 'Preferences' and not swapped:
                    swapped = True
                    if kind == 'file':
                        inside.unlink()
                        inside.symlink_to(outside)
                    elif kind == 'directory':
                        profile.rename(parent / 'held-profile')
                        profile.symlink_to(outside_profile, target_is_directory=True)
                    else:
                        parent.rename(base / 'held-parent')
                        parent.symlink_to(outside_parent, target_is_directory=True)
                return signature

            def assert_inside_only(fd, length):
                opened = os.fstat(fd)
                identity = (opened.st_dev, opened.st_ino)
                read_identities.append(identity)
                self.assertNotEqual(identity, outside_identity, 'External content must never be read')
                return original_read(fd, length)

            with self.subTest(kind=kind), patch.object(reader._Directory, 'watch', swap_after_watch), \
                    patch.object(reader.os, 'read', assert_inside_only), self.assertRaises(ValueError):
                reader.read_metadata_file(profile, 'Preferences')
            self.assertTrue(swapped)
            self.assertNotIn(outside_identity, read_identities)
            if kind == 'file':
                self.assertEqual(read_identities, [], 'O_NOFOLLOW/reparse check must precede reading')

    def test_invalid_api_inputs_and_varints(self):
        for keys in ([KEY_A], {123}, {'text'}, None):
            with self.subTest(keys=keys), self.assertRaises(ValueError):
                reader.read_values(self.root, keys)
        with self.assertRaises(ValueError):
            reader.read_values(str(self.root), {KEY_A})
        for value in (b'\x80', b'\x80\x00', b'\xff' * 10 + b'\x01', b'\xff' * 9 + b'\x02'):
            with self.subTest(value=value), self.assertRaises(ValueError):
                reader._Cursor(value).varint()


if __name__ == '__main__':
    unittest.main()
