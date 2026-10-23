"""Pure bytes/struct fixtures only; does not import any repository owner/API."""
import ast
import copy
import hashlib
import importlib.util
from pathlib import Path
import struct
import unittest

SOURCE = Path(__file__).resolve().parents[1] / ".github/windows_identity_lpac_curl_mm_binary_reader.py"
spec = importlib.util.spec_from_file_location("independent_cmm_reader", SOURCE)
m = importlib.util.module_from_spec(spec)
spec.loader.exec_module(m)


def put(b, offset, value, kind="I"):
    struct.pack_into("<" + kind, b, offset, value)


def utf16(b, offset, text):
    encoded = text.encode("utf-16-le")
    b[offset:offset + len(encoded)] = encoded


def raw_call(operation=0, kind=1, success=True, entered=1101, returned=1102, requested=0, observed=0):
    return struct.pack("<IIIiIIIIQQQQ", operation, 1, 1, int(success), 0, int(not success), kind, 0, entered, returned, requested, observed)


def expected():
    p, i, s, initial = bytearray(512), bytearray(256), bytearray(1024), bytearray(320)
    put(p, 0, 512); put(p, 4, 2)
    for off, value in ((8, 1000), (16, 100000), (24, 220000), (32, 110000), (40, 118000), (56, 133000000000000000)):
        put(p, off, value, "Q")
    put(p, 48, 42)
    for n in range(9):
        put(p, 64 + 8 * n, 100 + n, "Q")
    commitments = {"run": b"R" * 16, "config_sha256": b"C" * 32, "source_sha256": b"S" * 32, "target_sha256": b"T" * 32, "marker_sha256": b"M" * 32}
    for name, off in (("run", 136), ("config_sha256", 152), ("source_sha256", 184), ("target_sha256", 216), ("marker_sha256", 248)):
        p[off:off + len(commitments[name])] = commitments[name]
    target, nt, marker_path = "C:\\Windows\\System32\\curl.exe", "\\Device\\HarddiskVolume1\\fixed\\marker.dll", "C:\\fixed\\marker.dll"
    for off, val in ((288, len(target)), (304, len(nt)), (320, len(marker_path)), (336, 256), (352, 1024)):
        put(p, off, val)
    p[360:384], p[384:408] = b"t" * 24, b"m" * 24
    for off, dll in ((408, 0), (440, 1)):
        struct.pack_into("<8I", p, off, 32, 0x8664, 123, 0x1000, 0x4000, 512, 2, dll)
    p[472:488] = bytes.fromhex("526462b45933344b9a97dd85e4b79f2c")
    put(p, 488, 818512, "Q"); put(p, 496, 142336, "Q")
    put(i, 0, 256); put(i, 4, 2)
    user, package = bytes.fromhex("010100000000000515000000"), bytes.fromhex("010200000000000f0200000001000000")
    put(i, 8, len(user)); put(i, 12, len(package))
    i[16:16 + len(user)], i[84:84 + len(package)] = user, package
    struct.pack_into("<8IQQ", i, 152, 1, 1, 0xFFFFFFFF, 4096, 1, 0, 0, 0, 12345, 456)
    put(s, 0, 1024); put(s, 4, 2)
    a, b = "D:P(A;;GA;;;SY)(A;;0x1fffff;;;S-1-5-21)", "D:P(A;;0x1fffff;;;SY)(A;;GA;;;S-1-5-21)"
    put(s, 8, len(a)); put(s, 12, len(b)); utf16(s, 16, a); utf16(s, 512, b)
    initial[:8] = b"CMM2\x02\0\x40\x01"
    for name, off in (("run", 8), ("config_sha256", 24), ("source_sha256", 56), ("marker_sha256", 88)):
        initial[off:off + len(commitments[name])] = commitments[name]
    initial[120:160] = p[8:48]
    put(initial, 160, 42); put(initial, 168, 133000000000000000, "Q")
    put(initial, 176, 201, "Q"); put(initial, 184, 202, "Q"); put(initial, 192, 128); put(initial, 196, 2)
    return {"plan512": bytes(p), "identity256": bytes(i), "security1024": bytes(s), "initial_marker320": bytes(initial), "target_path": target, "marker_nt_path": nt, "marker_ascii_path": marker_path, "commitments": commitments}


def partial(calls=()):
    b = bytearray(24576)
    for o, v in ((0, 256), (4, 2), (8, 4), (12, 1), (112, len(calls))):
        put(b, o, v)
    for n, c in enumerate(calls):
        o = 256 + 64 * n if n < 64 else 16960 + 64 * (n - 64)
        b[o:o + 64] = c
    return b


def typed_complete(e):
    b = partial()
    put(b, 12, 7)
    put(b, 16, 110001, "Q"); put(b, 24, 110500, "Q")
    for off in (*range(32, 92, 4), 96, 100, 104):
        put(b, off, 1)
    put(b, 52, 0)
    for off, value in ((92, 2), (112, 2), (116, 2), (120, 2)):
        put(b, off, value)
    for index in range(2):
        b[4352 + index * 256:4608 + index * 256] = e["identity256"]
        b[4864 + index * 1024:5888 + index * 1024] = e["security1024"]
        h = bytearray(192)
        struct.pack_into("<4IQ2I", h, 0, 192, 2, 42, 42, 133000000000000000, 1, 0)
        for off in (32, 40, 48, 56, 72, 80, 96, 168):
            put(h, off, 1)
        put(h, 60, 0x2000); put(h, 84, 0x2000)
        h[104:128], h[128:152], h[152:168] = e["plan512"][360:384], e["plan512"][384:408], e["plan512"][488:504]
        b[16512 + index * 192:16704 + index * 192] = h
        image = bytearray(608)
        q = raw_call(entered=110010 + index * 100, returned=110011 + index * 100, requested=260, observed=len(e["target_path"]))
        image[:64] = q; utf16(image, 64, e["target_path"]); put(image, 584, len(e["target_path"]))
        b[21056 + index * 608:21664 + index * 608] = image
        b[256 + index * 64:320 + index * 64] = q
    g = bytearray(64)
    struct.pack_into("<4IQ2I", g, 0, 64, 2, 42, 42, 133000000000000000, 1, 0)
    for off in (32, 40, 44, 52, 56):
        put(g, off, 1)
    b[16896:16960] = g
    marker = bytearray(e["initial_marker320"])
    for off, value in ((200, 6143), (208, 1), (216, 1), (224, 1), (240, 42), (264, 1)):
        put(marker, off, value)
    put(marker, 232, 110100, "Q"); put(marker, 248, 20, "Q"); put(marker, 256, 0x180000000, "Q")
    for index in (2, 3):
        b[6912 + index * 320:7232 + index * 320] = marker
    region = bytearray(64)
    struct.pack_into("<IIQQQIIIIQII", region, 0, 64, 2, 0x180000000, 0x180000000, 4096, 4, 0x1000, 4, 0x1000000, 48, 0, 0)
    b[8192:8256] = b[8256:8320] = region
    utf16(b, 8320, e["marker_nt_path"]); utf16(b, 10368, e["marker_nt_path"])
    pe = bytearray(4096); pe[:2] = b"MZ"; put(pe, 60, 128); pe[128:132] = b"PE\0\0"
    put(pe, 132, 0x8664, "H"); put(pe, 136, 123); put(pe, 148, 240, "H"); put(pe, 150, 0x2000, "H")
    put(pe, 152, 0x20B, "H"); put(pe, 168, 0x1000); put(pe, 208, 0x4000); put(pe, 212, 512); put(pe, 220, 2, "H")
    b[12416:16512] = pe
    return b


def complete_trace(e, delayed=False):
    """Independent schema01 fixture, all109/115 physical rows populated."""
    b = typed_complete(e)
    rows, now = [], 110001
    full = list(range(100, 105)) + list(range(110, 127)) + list(range(130, 138)) + list(range(140, 148)) + list(range(150, 158))

    def emit(op, requested, observed=0, kind=1, success=True, error=0):
        nonlocal now
        bool_value = int(success) if kind == 1 else 0
        valid = int((kind == 1 and not success) or (kind == 7 and error != 0) or (kind in (2, 8) and error != 0))
        if kind == 7:
            bool_value = error
        c = struct.pack("<IIIiIIIIQQQQ", op, 1, 1, bool_value, error, valid, kind, 0, now, now + 1, requested, observed)
        now += 2; rows.append(c)
        return c

    def full_rows(index):
        token, sd, tx, td, tt = (300 + index * 100 + n for n in range(5))
        probes = {116: 28, 118: 28, 120: 4, 122: 24, 124: 56}
        for op in full:
            if op in (100, 103):
                emit(op, 100 if op == 100 else 101, 42, 2)
            elif op == 101:
                emit(op, 100, 133000000000000000)
            elif op == 102:
                emit(op, 0, 258, 3)
            elif op == 104:
                q = emit(op, 260, len(e["target_path"]))
                b[21056 + index * 608:21120 + index * 608] = q
            elif op == 110:
                emit(op, 100, token)
            elif op in range(111, 116):
                emit(op, 4, 4 | ({111: 1, 112: 1, 113: 1, 114: 0, 115: 0}[op] << 32))
            elif op in probes:
                emit(op, 0, probes[op], success=False, error=122)
            elif op in (117, 119, 121, 123, 125):
                n = probes[op - 1]
                emit(op, n, n | ((1 if op == 125 else 0) << 32))
            elif op == 126:
                emit(op, token)
            elif op in (130, 134):
                emit(op, 100 if op == 130 else 101, sd if op == 130 else td, 7)
            elif op in (131, 135):
                emit(op, sd if op == 131 else td, tx if op == 131 else tt)
            elif op in (132, 133, 136, 137):
                emit(op, {132: tx, 133: sd, 136: tt, 137: td}[op], 0, 8)
            elif op in (140, 144):
                emit(op, 103 if op == 140 else 104, 1)
            elif op in (141, 145, 150, 154):
                emit(op, {141: 103, 145: 104, 150: 107, 154: 108}[op])
            elif op in (142, 146):
                emit(op, 9 | (144 << 32), 144 | (0x2000 << 32))
            elif op in (143, 147):
                emit(op, 4 | (4 << 32), 4)
            elif op in (151, 155):
                emit(op, 8, 0x80)
            elif op in (152, 156):
                emit(op, 24)
            elif op in (153, 157):
                emit(op, 24, 818512 if op == 153 else 142336)

    full_rows(0)
    emit(160, 7000, 1, 3)
    for op in (162, 163, 164):
        emit(op, 0, 258 if op == 162 or (op == 164 and delayed) else 0, 3)
    if delayed:
        emit(180, 320, 320); emit(181, 320, 320)
        emit(161, 7000, 1, 3)
        for op in (162, 163, 164):
            emit(op, 0, 258 if op == 162 else 0, 3)
        put(b, 92, 4)
        for index in (0, 1):
            b[6912 + index * 320:7232 + index * 320] = e["initial_marker320"]
        put(b, 6912 + 248, 1, "Q")  # real progress can race the writer
    for op in range(170, 176):
        if op in (170, 173):
            emit(op, 100 if op == 170 else 101, 42, 2)
        elif op == 171:
            emit(op, 100, 133000000000000000)
        elif op == 172:
            emit(op, 0, 258, 3)
        else:
            emit(op, 103 if op == 174 else 104, 1)
    emit(182, 320, 320); emit(183, 320, 320)
    emit(190, 48, 48, 2); emit(191, 1024, len(e["marker_nt_path"]), 2)
    emit(192, 4096, 4096); emit(193, 48, 48, 2); emit(194, 1024, len(e["marker_nt_path"]), 2)
    full_rows(1)
    b[256:4352] = bytes(4096); b[16960:21056] = bytes(4096)
    for index, row in enumerate(rows):
        off = 256 + index * 64 if index < 64 else 16960 + (index - 64) * 64
        b[off:off + 64] = row
    put(b, 112, len(rows)); put(b, 16, m.call(rows[45])["entered_qpc"], "Q"); put(b, 24, now - 1, "Q")
    return b, rows


def change_row(b, index, field, value):
    off = 256 + index * 64 if index < 64 else 16960 + (index - 64) * 64
    offsets = {"operation": (0, "I"), "raw_bool": (12, "i"), "error": (16, "I"), "error_valid": (20, "I"), "kind": (24, "I"), "entered_qpc": (32, "Q"), "returned_qpc": (40, "Q"), "requested": (48, "Q"), "observed": (56, "Q")}
    pos, fmt = offsets[field]
    put(b, off + pos, value, fmt)


class BinaryReaderTests(unittest.TestCase):
    def test_source_has_only_stdlib_struct_hashlib_and_no_OS_calls(self):
        tree = ast.parse(SOURCE.read_text())
        imports = {n.names[0].name for n in tree.body if isinstance(n, ast.Import)}
        self.assertEqual(imports, {"struct", "hashlib"})
        self.assertFalse(any(isinstance(n, (ast.ImportFrom, ast.With, ast.AsyncWith)) for n in ast.walk(tree)))

    def test_independent_expected_and_empty_partial_are_valid(self):
        e, raw = expected(), bytes(partial())
        v = m.review(raw, e)
        self.assertEqual(v["status"], "partial")
        self.assertFalse(v["inner_observation_complete"])
        self.assertEqual(v["binary_sha256"], hashlib.sha256(raw).hexdigest())
        self.assertTrue(all(value is False for value in v["fixed_false_claims"].values()))

    def test_raw_exact_immutable_extent(self):
        for bad in (b"", bytes(24575), bytes(24577), bytearray(24576), memoryview(bytes(24576))):
            with self.subTest(type=type(bad).__name__, length=len(bad)), self.assertRaises(m.ReaderError):
                m.decode_output(bad)

    def test_all_128_rows_use_noncontiguous_slots(self):
        calls = [raw_call(n) for n in range(128)]
        raw = partial(calls)
        put(raw, 12, 24)
        d = m.decode_output(bytes(raw))
        self.assertEqual([c["operation"] for c in d["calls"]], list(range(128)))
        self.assertTrue(all(not any(b) for b in d["identities"]))
        self.assertEqual(d["calls"][64]["raw"], bytes(raw[16960:17024]))

    def test_counts_and_reserved_reject(self):
        for offset, value in ((112, 129), (116, 3), (92, 5), (120, 3), (124, 1), (200, 1), (22272, 1), (4352 + 200, 1), (4864 + 1008, 1), (16512 + 176, 1), (21056 + 588, 1), (6912 + 268, 1), (8192 + 60, 1)):
            with self.subTest(offset=offset), self.assertRaises(m.ReaderError):
                b = partial(); put(b, offset, value); m.decode_output(bytes(b))

    def test_unused_trace_is_not_ignored(self):
        b = partial(); b[16960:17024] = raw_call()
        with self.assertRaisesRegex(m.ReaderError, "unused_trace"):
            m.decode_output(bytes(b))

    def test_expected_commitment_change_does_not_refresh_baseline(self):
        e = expected(); e["commitments"]["source_sha256"] = b"x" * 32
        with self.assertRaisesRegex(m.ReaderError, "plan_commitment"):
            m.review(bytes(partial()), e)

    def test_epoch_tamper_and_BOOL_schema_reject(self):
        for offset, value in ((8, 0), (24, 220001), (32, 119000), (40, 118001), (52, 1)):
            e = expected(); p = bytearray(e["plan512"]); put(p, offset, value, "I" if offset == 52 else "Q"); e["plan512"] = bytes(p)
            with self.subTest(offset=offset), self.assertRaises(m.ReaderError):
                m.expected_inputs(e)
        b = partial(); put(b, 32, 2)
        with self.assertRaisesRegex(m.ReaderError, "result_flags"):
            m.decode_output(bytes(b))

    def test_exact_zero_cap_identity_SID_and_privateSD(self):
        e = expected(); m.expected_inputs(e)
        for offset, value in ((180, 1), (164, 8192), (8, 69), (16, 2), (156, 2)):
            bad = copy.deepcopy(e); b = bytearray(bad["identity256"]); put(b, offset, value); bad["identity256"] = bytes(b)
            with self.subTest(offset=offset), self.assertRaises(m.ReaderError):
                m.expected_inputs(bad)
        bad = copy.deepcopy(e); b = bytearray(bad["security1024"]); b[16:18] = b"X\0"; bad["security1024"] = bytes(b)
        with self.assertRaises(m.ReaderError):
            m.expected_inputs(bad)

    def test_false_error_zero_is_distinct_from_unobserved_zero(self):
        c = m.call(raw_call(success=False)); m.raw_shape(c)
        self.assertEqual((c["raw_bool"], c["error_valid"], c["error"]), (0, 1, 0))
        c["error_valid"] = 0
        with self.assertRaisesRegex(m.ReaderError, "BOOL_error_valid"):
            m.raw_shape(c)

    def test_count_and_wait_do_not_become_BOOL(self):
        c = m.call(raw_call(kind=2));
        with self.assertRaisesRegex(m.ReaderError, "COUNT"):
            m.raw_shape(c)
        c = m.call(raw_call(kind=3)); c.update(raw_bool=0, observed=0xFFFFFFFF, error_valid=0)
        with self.assertRaisesRegex(m.ReaderError, "WAIT"):
            m.raw_shape(c)

    def test_events_and_typed_complete_do_not_qualify_without_full_trace(self):
        e = expected(); b = typed_complete(e)
        with self.assertRaises(m.ReaderError):
            m.review(bytes(b), e)

    def test_typed_complete_mutations_reject_before_trace(self):
        e = expected()
        for offset, value, kind in ((52, 1, "I"), (24, 118000, "Q"), (16512 + 60, 0, "I"), (4352 + 184, 12346, "Q"), (16896 + 40, 0, "I"), (6912 + 3 * 320 + 248, 21, "Q"), (6912 + 3 * 320 + 232, 110501, "Q"), (8192 + 40, 0x10, "I"), (8256 + 24, 8192, "Q"), (12416 + 168, 0x2000, "I")):
            with self.subTest(offset=offset), self.assertRaises(m.ReaderError):
                b, _ = complete_trace(e); put(b, offset, value, kind); m.review(bytes(b), e)

    def test_image_must_be_a_unique_physical_record(self):
        e = expected(); b, _ = complete_trace(e)
        b[256:320] = raw_call(entered=110009, returned=110011, requested=260, observed=len(e["target_path"]))
        with self.assertRaises(m.ReaderError):
            m.review(bytes(b), e)

    def test_fast_and_long_complete_physical_traces(self):
        e = expected()
        for delayed, count in ((False, 109), (True, 115)):
            with self.subTest(delayed=delayed):
                b, rows = complete_trace(e, delayed)
                v = m.review(bytes(b), e)
                self.assertEqual(len(rows), count)
                self.assertTrue(v["inner_observation_complete"])
                self.assertTrue(all(v["gates"].values()))
                self.assertEqual(v["trace"]["known_close_obligations"], 0)
                self.assertTrue(all(x is False for x in v["fixed_false_claims"].values()))

    def test_trace_order_encoding_handles_cap_lengths_and_closes(self):
        e = expected(); base, rows = complete_trace(e)
        index = {m.call(c)["operation"]: n for n, c in enumerate(rows[:46])}
        mutations = [(100, "requested", 999), (111, "observed", 8 | (1 << 32)), (116, "observed", 4097), (117, "requested", 29), (121, "observed", 4 | (1 << 32)), (124, "observed", 64), (126, "requested", 999), (130, "kind", 1), (132, "requested", 301), (142, "observed", 143 | (0x2000 << 32)), (143, "observed", 4 | (1 << 32)), (153, "requested", 24 | (1 << 32)), (104, "operation", 221)]
        for op, field, value in mutations:
            with self.subTest(op=op, field=field), self.assertRaises(m.ReaderError):
                b = bytearray(base); change_row(b, index[op], field, value); m.review(bytes(b), e)

    def test_partial_failure_unwinds_known_allocations_once_and_error0(self):
        e = expected(); original, full = complete_trace(e)
        # Open query token then scalar API FALSE/error0; no later getter.
        rows = full[:7]
        c = bytearray(rows[-1]); put(c, 12, 0, "i"); put(c, 20, 1); rows[-1] = bytes(c)
        close = bytearray(full[21]); put(close, 32, 110015, "Q"); put(close, 40, 110016, "Q"); rows.append(bytes(close))
        b = partial(rows); put(b, 12, 18); put(b, 104, 1)
        # Image query is physically populated even though full slot failed.
        b[21056:21664] = original[21056:21664]
        v = m.review(bytes(b), e)
        self.assertEqual(v["trace"]["failure"]["operation"], 111)
        self.assertEqual(v["trace"]["failure"]["error"], 0)
        self.assertTrue(v["gates"]["resources"])
        self.assertFalse(v["inner_observation_complete"])
        rows.append(bytes(close))
        with self.assertRaises(m.ReaderError):
            m.review(bytes(partial(rows)), e)

    def test_resource_unknown_is_not_washed_by_later_typed_clean(self):
        e = expected(); original, rows = complete_trace(e)
        prefix = rows[:6]
        bad = bytearray(prefix[-1]); put(bad, 12, 0, "i"); put(bad, 20, 1); prefix[-1] = bytes(bad)
        b = partial(prefix); put(b, 12, 18); b[21056:21664] = original[21056:21664]
        v = m.review(bytes(b), e)
        self.assertTrue(v["trace"]["resource_uncertain"])
        put(b, 104, 1)
        with self.assertRaisesRegex(m.ReaderError, "resources_not_self_asserted"):
            m.review(bytes(b), e)

    def test_original_trace_clock_and_marker_RPM_causality(self):
        e = expected(); base, rows = complete_trace(e)
        for index, field, value in ((1, "returned_qpc", 110000), (1, "entered_qpc", 118000), (50, "returned_qpc", 110099)):
            with self.subTest(index=index), self.assertRaises(m.ReaderError):
                b = bytearray(base); change_row(b, index, field, value); m.review(bytes(b), e)
        b = bytearray(base)
        rpm = next(m.call(c) for c in rows if m.call(c)["operation"] == 182)
        for index in (2, 3):
            put(b, 6912 + index * 320 + 232, rpm["returned_qpc"] + 1, "Q")
        with self.assertRaises(m.ReaderError):
            m.review(bytes(b), e)

    def test_decode_result_uses_operation_names_and_primary_physical_return(self):
        b = bytearray(256); put(b, 0, 256); put(b, 4, 2); put(b, 8, 2); put(b, 12, 11)
        put(b, 16, 110001, "Q"); put(b, 24, 110010, "Q")
        for off in (32, 36, 40, 44, 64, 104):
            put(b, off, 1)
        b[136:200] = raw_call(220, entered=110002, returned=110009, requested=100)
        r = m.decode_result(bytes(b), "update", (110000, 118000))
        self.assertEqual(r["result_class"], 11)
        put(b, 136 + 40, 110011, "Q")
        with self.assertRaises(m.ReaderError):
            m.decode_result(bytes(b), "update", (110000, 118000))
        with self.assertRaises(m.ReaderError):
            m.decode_result(bytes(b), "install", (110000, 118000))

    def test_native_result_clock_is_first_full_terminal_not_first_query(self):
        e = expected(); b, rows = complete_trace(e)
        v = m.decode_output(bytes(b), e)
        self.assertEqual(v["result"]["entered_qpc"], m.call(rows[45])["entered_qpc"])
        self.assertTrue(v["gates"]["inner_complete"])
        put(b, 16, m.call(rows[0])["entered_qpc"], "Q")
        with self.assertRaisesRegex(m.ReaderError, "result_trace_clock"):
            m.review(bytes(b), e)

    def test_raw_full_flags_and_resource_flag_need_their_own_evidence(self):
        e = expected(); b = partial(); put(b, 68, 1)
        with self.assertRaisesRegex(m.ReaderError, "full_flags_together"):
            m.review(bytes(b), e)
        b = partial(); put(b, 56, 1)
        with self.assertRaisesRegex(m.ReaderError, "ENTERED_raw_binding"):
            m.review(bytes(b), e)
        v = m.review(bytes(partial()), e)
        self.assertTrue(v["trace"]["resources_clean"])
        self.assertFalse(v["gates"]["resources"])

    def test_observe_primary_call_is_not_a_copy_or_last_close_proxy(self):
        e = expected(); b, rows = complete_trace(e)
        b[136:200] = rows[-1]
        with self.assertRaisesRegex(m.ReaderError, "observe_primary_call"):
            m.review(bytes(b), e)

    def test_partial_RPM_FALSE_error0_late_is_preserved_and_not_complete(self):
        e = expected(); original, full = complete_trace(e)
        at = next(n for n, c in enumerate(full) if m.call(c)["operation"] == 182)
        rows = list(full[:at + 1]); bad = bytearray(rows[-1]); put(bad, 12, 0, "i"); put(bad, 20, 1); put(bad, 40, 0, "Q"); put(bad, 56, 0, "Q"); rows[-1] = bytes(bad)
        b = partial(rows); put(b, 12, 12); put(b, 56, 1); put(b, 60, 1); put(b, 104, 1)
        b[21056:21664] = original[21056:21664]
        v = m.review(bytes(b), e)
        self.assertFalse(v["inner_observation_complete"])
        self.assertEqual(v["trace"]["failure"]["operation"], 182)
        self.assertEqual(v["trace"]["failure"]["error"], 0)
        self.assertTrue(v["trace"]["failure"]["error_valid"])
        put(b, 12, 13)
        with self.assertRaisesRegex(m.ReaderError, "RPM_failure_class_binding"):
            m.review(bytes(b), e)

    def test_install_primary_pointer_status_error_and_alignment(self):
        b = bytearray(256)
        for off, value in ((0, 256), (4, 2), (8, 3), (12, 5), (32, 1), (36, 1), (40, 1), (44, 1), (64, 1), (104, 1)):
            put(b, off, value)
        put(b, 16, 110001, "Q"); put(b, 24, 110010, "Q")
        b[136:200] = struct.pack("<IIIiIIIIQQQQ", 221, 1, 1, 0, 0, 0, 8, 0, 110002, 110009, 320, 0x180002000)
        self.assertEqual(m.decode_result(bytes(b), "install", (110000, 118000))["result_class"], 5)
        for off, value, kind in ((136 + 56, 0x180002001, "Q"), (136 + 20, 1, "I"), (136 + 40, 110011, "Q")):
            with self.subTest(off=off), self.assertRaises(m.ReaderError):
                bad = bytearray(b); put(bad, off, value, kind); m.decode_result(bytes(bad), "install", (110000, 118000))

    def test_second_sample_requires_current_ENTERED_not_sticky_bit(self):
        e = expected(); b, rows = complete_trace(e, True)
        indices = [n for n, row in enumerate(rows) if m.call(row)["operation"] == 163]
        self.assertEqual(len(indices), 2)
        change_row(b, indices[1], "observed", 258)
        with self.assertRaises(m.ReaderError):
            m.review(bytes(b), e)

    def test_retained_changed_current_token_is_predicate_failure_then_close(self):
        e = expected(); original, full = complete_trace(e)
        rows = full[:22]  # through Stats and consumed query-token close
        b = partial(rows); put(b, 12, 18); put(b, 104, 1); put(b, 116, 1)
        b[4352:4608] = e["identity256"]; put(b, 4352 + 184, 12346, "Q")
        b[21056:21664] = original[21056:21664]
        v = m.review(bytes(b), e)
        self.assertEqual(v["trace"]["failure"]["operation"], 125)
        self.assertFalse(v["trace"]["failure"]["API_return_failed"])
        self.assertTrue(v["gates"]["resources"])
        self.assertFalse(v["inner_observation_complete"])
        wrong = dict(e); wrong["plan"] = wrong.pop("plan512")
        with self.assertRaisesRegex(m.ReaderError, "expected_keys"):
            m.validate_inputs(wrong)

    def test_unentered_next_getter_can_only_unwind_known_close(self):
        e = expected(); original, full = complete_trace(e)
        rows = list(full[:6])  # physical GetProcess... then OpenToken TRUE
        close = bytearray(full[21])
        put(close, 32, m.call(rows[-1])["returned_qpc"] + 1, "Q")
        put(close, 40, m.call(rows[-1])["returned_qpc"] + 2, "Q")
        rows.append(bytes(close))
        b = partial(rows); put(b, 12, 4); put(b, 104, 1)
        b[21056:21664] = original[21056:21664]
        v = m.review(bytes(b), e)
        failure = v["trace"]["failure"]
        self.assertEqual(failure["category"], "prefix_boundary")
        self.assertIsNone(failure["operation"])
        self.assertTrue(failure["unentered_gate"])
        self.assertFalse(failure["API_return_failed"])
        self.assertFalse(failure["error_valid"])
        self.assertIsNone(failure["error"])
        self.assertEqual(v["trace"]["known_close_obligations"], 0)
        self.assertTrue(v["gates"]["resources"])
        self.assertFalse(v["inner_observation_complete"])
        for field, value in (("requested", 999), ("operation", 132)):
            with self.subTest(field=field), self.assertRaises(m.ReaderError):
                bad = bytearray(b); change_row(bad, 6, field, value); m.review(bytes(bad), e)
        put(b, 12, 7)
        with self.assertRaises(m.ReaderError):
            m.review(bytes(b), e)

    def test_BODY_and_MM_survive_later_full_after_token_failure(self):
        e = expected(); original, all_rows = complete_trace(e)
        second_start = 63  # 46full +4wait/probes +6middle +2BODY +5MM
        self.assertEqual(m.call(all_rows[second_start])["operation"], 100)
        rows = all_rows[:second_start + 22]  # second Stats mismatch + close
        b = bytearray(original)
        b[256:4352] = bytes(4096); b[16960:21056] = bytes(4096)
        for n, row in enumerate(rows):
            off = 256 + n * 64 if n < 64 else 16960 + (n - 64) * 64
            b[off:off + 64] = row
        put(b, 112, len(rows)); put(b, 12, 18)
        put(b, 24, m.call(rows[-1])["returned_qpc"], "Q")
        for off in (32, 64, 72, 80, 88, 96, 100):
            put(b, off, 0)
        put(b, 4352 + 256 + 184, 12346, "Q")
        b[5888:6912] = bytes(1024)  # no after-SD getter was entered
        b[16704:16896] = bytes(192)
        v = m.review(bytes(b), e)
        self.assertEqual(v["trace"]["failure"]["operation"], 125)
        self.assertFalse(v["trace"]["failure"]["API_return_failed"])
        self.assertTrue(v["gates"]["coherent_marker"])
        self.assertTrue(v["gates"]["memory_mapping"])
        self.assertTrue(v["gates"]["resources"])
        self.assertFalse(v["gates"]["inner_complete"])
        self.assertFalse(v["gates"]["trace_complete"])
        bad_pair = bytearray(b); put(bad_pair, 6912 + 3 * 320 + 248, 22, "Q")
        bad = m.review(bytes(bad_pair), e)
        self.assertFalse(bad["gates"]["coherent_marker"])
        self.assertFalse(bad["gates"]["memory_mapping"])
        bad_mapping = bytearray(b); put(bad_mapping, 8256 + 24, 8192, "Q")
        bad = m.review(bytes(bad_mapping), e)
        self.assertTrue(bad["gates"]["coherent_marker"])
        self.assertFalse(bad["gates"]["memory_mapping"])

    def test_each_known_success_rejects_remote_unknown_but_forget_retains_it(self):
        window = (110000, 118000)
        for operation, op, klass in (("begin", 1, 9), ("update", 2, 11), ("install", 3, 5), ("observe", 4, 7)):
            b = bytearray(256)
            for off, value in ((0, 256), (4, 2), (8, op), (12, klass), (32, 1), (36, 1), (40, 1), (44, 1), (64, 1), (104, 1)):
                put(b, off, value)
            put(b, 16, 110001, "Q"); put(b, 24, 110010, "Q")
            if operation == "update":
                b[136:200] = raw_call(220, entered=110002, returned=110009, requested=100)
            elif operation == "install":
                b[136:200] = struct.pack("<IIIiIIIIQQQQ", 221, 1, 1, 0, 0, 0, 8, 0, 110002, 110009, 320, 0x180002000)
            elif operation == "observe":
                put(b, 96, 1); put(b, 100, 1)
            self.assertEqual(m.decode_result(bytes(b), operation, window)["result_class"], klass)
            put(b, 52, 1)
            with self.subTest(operation=operation), self.assertRaisesRegex(m.ReaderError, "operation_success_tuple"):
                m.decode_result(bytes(b), operation, window)
        b = bytearray(256)
        for off, value in ((0, 256), (4, 2), (8, 5), (12, 10), (52, 1)):
            put(b, off, value)
        self.assertEqual(m.decode_result(bytes(b), "forget", window)["remote_outcome_unknown"], 1)

    def test_safe_projection_contains_no_identifiers_or_raw_buffers(self):
        e = expected(); v = m.review(bytes(partial()), e)
        encoded = repr(v)
        for token in (e["target_path"], e["marker_nt_path"], "S-1-5-21", "133000000000000000", "110000"):
            self.assertNotIn(token, encoded)


if __name__ == "__main__":
    unittest.main()
