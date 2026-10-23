"""Independent CMM24576 byte reader. No OS, native module or baseline queries.

The literal layouts below are reviewed against ABI06. A complete inner claim
also needs the separately pinned primitive schema; typed summaries are never
a substitute for those physical rows or the owner's external lifecycle gates.
"""
import hashlib
import struct

ACTUAL_READY = False
OUTPUT_BYTES = 24576
ABI_VERSION = 2
ABI06_SHA256 = "62543e42b30a5beae845946bfb3daf153ac0044c29c015981b9618aa05411a28"
PRIMITIVE_SCHEMA_SHA256 = "0f2a97c41a31a8c387b18cc498b5bd5f2d6f4ed6c3106d454a9f70daca791245"
FULL_OPS = tuple(range(100, 105)) + tuple(range(110, 127)) + tuple(range(130, 138)) + tuple(range(140, 148)) + tuple(range(150, 158))
MIDDLE_OPS = tuple(range(170, 176))
OP_KINDS = {n: 1 for n in FULL_OPS + MIDDLE_OPS + tuple(range(180, 184)) + (192,)}
OP_KINDS.update({n: 2 for n in (100, 103, 170, 173, 190, 191, 193, 194)})
OP_KINDS.update({n: 3 for n in (102, 160, 161, 162, 163, 164, 172)})
OP_KINDS.update({130: 7, 134: 7, 132: 8, 133: 8, 136: 8, 137: 8})
PROBES = (116, 118, 120, 122, 124)
CLOSES = (126, 132, 133, 136, 137)
ALLOCS = (110, 130, 131, 134, 135)
CALL = struct.Struct("<IIIiIIIIQQQQ")
CALL_KEYS = ("operation", "entered", "returned", "raw_bool", "error", "error_valid", "kind", "reserved", "entered_qpc", "returned_qpc", "requested", "observed")
U64_MAX = (1 << 64) - 1
I64_MAX = (1 << 63) - 1
USER_TOP = 1 << 47
RESULT_FLAGS = ("validation_passed", "return_clock_known", "within_window", "context_known", "remote_mutation_possible", "remote_outcome_unknown", "entered_observed", "body_observed", "target_alive", "identity_before", "identity_after", "jobs_before", "jobs_after", "leases_before", "leases_after", "mapping_qualified", "observation_complete", "resources_clean")
RESULT_OFFSETS = dict(zip(RESULT_FLAGS[:15], range(32, 92, 4)))
RESULT_OFFSETS.update(mapping_qualified=96, observation_complete=100, resources_clean=104)
REGIONS = {"result": (0, 256), "identities": (4352, 256, 2), "security": (4864, 1024, 2), "markers": (6912, 320, 4), "regions": (8192, 64, 2), "mapped_names": (8320, 2048, 2), "pe_header": (12416, 4096), "held": (16512, 192, 2), "generation": (16896, 64), "images": (21056, 608, 2)}
FALSE_CLAIMS = ("external_controls_qualified", "physical_resume_qualified", "natural_exit_qualified", "full_cleanup_qualified", "DllMain_return_proved", "whole_mapped_image_integrity", "selected_version_positive", "arbitrary_application_compatibility", "hostile_same_sid_boundary", "A4", "network", "DNS", "Linux")


class ReaderError(ValueError):
    """A fixed safe error code, never private bytes or identifiers."""


def need(condition, code):
    if not condition:
        raise ReaderError(code)


def u32(b, o):
    return struct.unpack_from("<I", b, o)[0]


def u64(b, o):
    return struct.unpack_from("<Q", b, o)[0]


def fixed(b, size, code):
    need(type(b) is bytes and len(b) == size, code)
    return b


def zero(b):
    return not any(b)


def handle(v):
    return 0 < v < U64_MAX


def call(b):
    fixed(b, 64, "call_extent")
    x = dict(zip(CALL_KEYS, CALL.unpack(b)))
    x["raw"] = b
    return x


def text16(b, chars, capacity):
    need(type(chars) is int and 0 < chars < capacity and len(b) == capacity * 2, "utf16_extent")
    need(b[chars * 2:chars * 2 + 2] == b"\0\0", "utf16_terminator")
    try:
        s = b[:chars * 2].decode("utf-16-le", errors="strict")
    except UnicodeError:
        raise ReaderError("utf16_encoding") from None
    need("\0" not in s, "utf16_embedded_nul")
    return s


def dos_path(s, capacity=260):
    need(type(s) is str and 4 <= len(s) < capacity and s[0].isascii() and s[0].isalpha() and s[1:3] == ":\\", "DOS_path")
    need(all(32 <= ord(c) <= 126 and c not in '/?*"<>|' and (c != ":" or i == 1) for i, c in enumerate(s)), "DOS_path_char")
    need(".." not in s[3:].split("\\"), "DOS_path_parent")
    return s.lower()


def units16(s):
    need(type(s) is str, "UTF16_expected_type")
    try:
        return len(s.encode("utf-16-le", errors="strict")) // 2
    except UnicodeError:
        raise ReaderError("UTF16_expected_encoding") from None


def sid(b):
    need(type(b) is bytes and 8 <= len(b) <= 68 and b[0] == 1 and b[1] <= 15 and len(b) == 8 + 4 * b[1], "SID_shape")
    authority = int.from_bytes(b[2:8], "big")
    rids = struct.unpack("<" + "I" * b[1], b[8:])
    return "S-1-" + str(authority) + "".join("-" + str(n) for n in rids)


def identity(b):
    fixed(b, 256, "identity_extent")
    need(u32(b, 0) == 256 and u32(b, 4) == 2 and zero(b[200:]), "identity_header_reserved")
    un, an = u32(b, 8), u32(b, 12)
    need(8 <= un <= 68 and 8 <= an <= 68 and zero(b[16 + un:84]) and zero(b[84 + an:152]), "identity_SID_extent")
    user, package = b[16:16 + un], b[84:84 + an]
    user_text = sid(user)
    sid(package)
    fields = dict(zip(("session_id", "token_type", "impersonation_level", "integrity_rid", "is_appcontainer", "elevated", "ui_access", "capability_count"), struct.unpack_from("<8I", b, 152)))
    need((fields["token_type"], fields["impersonation_level"], fields["integrity_rid"], fields["is_appcontainer"], fields["elevated"], fields["ui_access"], fields["capability_count"]) == (1, 0xFFFFFFFF, 4096, 1, 0, 0, 0), "identity_policy")
    need(u64(b, 184) != 0 and u64(b, 192) != 0, "identity_token_ids")
    return dict(fields, user_sid=user, appcontainer_sid=package, user_text=user_text, token_id=u64(b, 184), authentication_id=u64(b, 192), raw=b)


def security(b, expected_id):
    fixed(b, 1024, "security_extent")
    need(u32(b, 0) == 1024 and u32(b, 4) == 2 and zero(b[1008:]), "security_header_reserved")
    values = (text16(b[16:512], u32(b, 8), 248), text16(b[512:1008], u32(b, 12), 248))
    allowed = {"D:P(A;;" + a + ";;;SY)(A;;" + c + ";;;" + expected_id["user_text"] + ")" for a in ("GA", "0x1fffff") for c in ("GA", "0x1fffff")}
    need(all(s in allowed for s in values), "security_exact_private_layout")
    return values


def pe(b, is_dll):
    fixed(b, 32, "PE_extent")
    v = struct.unpack("<8I", b)
    need(v[0] == 32 and v[1] == 0x8664 and v[7] == int(is_dll) and 0 < v[3] < v[4] <= 64 * 1024 * 1024 and 512 <= v[5] <= 4096, "PE_shape")
    return dict(zip(("size", "machine", "timestamp", "entry_rva", "image_bytes", "header_bytes", "subsystem", "is_dll"), v))


def expected_inputs(public):
    need(type(public) is dict and set(public) == {"plan512", "identity256", "security1024", "initial_marker320", "target_path", "marker_nt_path", "marker_ascii_path", "commitments"}, "expected_keys")
    e = {"plan": public["plan512"], "identity": public["identity256"], "security": public["security1024"], "initial_marker": public["initial_marker320"], **{k: public[k] for k in ("target_path", "marker_nt_path", "marker_ascii_path", "commitments")}}
    p = fixed(e["plan"], 512, "plan_extent")
    need(u32(p, 0) == 512 and u32(p, 4) == 2 and all(zero(p[a:a + n]) for a, n in ((52, 4), (292, 4), (308, 4), (324, 4), (340, 4), (356, 4), (504, 8))), "plan_header_reserved")
    f, t0, d, ws, we = struct.unpack_from("<5Q", p, 8)
    need(0 < f <= I64_MAX // 120 and t0 <= I64_MAX - 120 * f and d == t0 + 120 * f and t0 <= ws <= I64_MAX - 8 * f and ws < we == min(ws + 8 * f, d - 35 * f), "original_epoch")
    hs = struct.unpack_from("<9Q", p, 64)
    need(all(handle(x) for x in hs) and len(set(hs)) == 9 and u32(p, 48) != 0 and u64(p, 56) != 0, "borrowed_handles_generation")
    need((u32(p, 336), u32(p, 352)) == (256, 1024) and u64(p, 488) > 0 and u64(p, 496) > 0 and not zero(p[360:384]) and not zero(p[384:408]), "plan_lengths_ids")
    need(p[472:488] == bytes.fromhex("526462b45933344b9a97dd85e4b79f2c"), "payload_GUID")
    need(type(e["target_path"]) is str and len(e["target_path"]) == u32(p, 288), "target_path_length")
    dos_path(e["target_path"])
    nt = e["marker_nt_path"]
    need(type(nt) is str and 0 < units16(nt) == u32(p, 304) < 1024 and nt.startswith("\\Device\\") and "\0" not in nt, "marker_NT_path")
    ascii_path = e["marker_ascii_path"]
    need(type(ascii_path) is str and 0 < len(ascii_path) == u32(p, 320) < 1024 and all(32 <= ord(c) <= 126 for c in ascii_path) and "\0" not in ascii_path, "marker_ASCII_path")
    dos_path(ascii_path, 1024)
    c = e["commitments"]
    offsets = {"run": (136, 16), "config_sha256": (152, 32), "source_sha256": (184, 32), "target_sha256": (216, 32), "marker_sha256": (248, 32)}
    need(type(c) is dict and set(c) == set(offsets), "commitment_keys")
    for name, (o, n) in offsets.items():
        need(type(c[name]) is bytes and len(c[name]) == n and not zero(c[name]) and p[o:o + n] == c[name], "plan_commitment")
    i = identity(e["identity"])
    security(e["security"], i)
    m = fixed(e["initial_marker"], 320, "initial_marker_extent")
    need(m[:8] == b"CMM2\x02\0\x40\x01" and m[8:24] == c["run"] and m[24:56] == c["config_sha256"] and m[56:88] == c["source_sha256"] and m[88:120] == c["marker_sha256"], "marker_commitment")
    need(m[120:160] == p[8:48] and u32(m, 160) == u32(p, 48) and u32(m, 164) == 0 and u64(m, 168) == u64(p, 56), "marker_epoch_generation")
    signals = struct.unpack_from("<2Q", m, 176)
    need(all(handle(x) for x in signals) and signals[0] != signals[1] and u32(m, 192) == 128 and u32(m, 196) == 2 and zero(m[200:]), "initial_marker_status")
    return dict(plan=p, frequency=f, root_start=t0, root_deadline=d, start=ws, end=we, pid=u32(p, 48), creation=u64(p, 56), borrowed=hs, identity=i, target_pe=pe(p[408:440], False), marker_pe=pe(p[440:472], True), raw=e)


def result(b, operation=4):
    fixed(b, 256, "result_extent")
    need((u32(b, 0), u32(b, 4), u32(b, 8)) == (256, 2, operation) and u32(b, 12) <= 25 and u32(b, 124) == 0 and zero(b[200:]), "result_header_reserved")
    r = {k: u32(b, o) for k, o in RESULT_OFFSETS.items()}
    need(all(v in (0, 1) for v in r.values()), "result_flags")
    r.update(result_class=u32(b, 12), entered_qpc=u64(b, 16), returned_qpc=u64(b, 24), snapshot_count=u32(b, 92), exception_code=u32(b, 108), call_count=u32(b, 112), held_count=u32(b, 116), mapping_count=u32(b, 120), context_generation=u64(b, 128), primary_call=call(b[136:200]))
    need(r["call_count"] <= 128 and r["held_count"] <= 2 and r["snapshot_count"] <= 4 and r["mapping_count"] <= 2, "result_counts")
    return r


def decode_output(raw, expected=None):
    """Return private decoded fields; no qualification or external lookup."""
    fixed(raw, OUTPUT_BYTES, "output_extent")
    need(zero(raw[22272:]), "output_reserved")
    r = result(raw[:256])
    all_calls = [call(raw[(256 + 64 * n if n < 64 else 16960 + 64 * (n - 64)):(256 + 64 * n if n < 64 else 16960 + 64 * (n - 64)) + 64]) for n in range(128)]
    need(all(zero(c["raw"]) for c in all_calls[r["call_count"]:]), "unused_trace_nonzero")
    d = {"raw": raw, "result": r, "calls": all_calls[:r["call_count"]]}
    for name, extent in REGIONS.items():
        if name == "result":
            continue
        o, n, *count = extent
        d[name] = [raw[o + n * j:o + n * (j + 1)] for j in range(count[0])] if count else raw[o:o + n]
    for b in d["identities"]:
        need(zero(b[200:]), "identity_reserved")
    for b in d["security"]:
        need(zero(b[1008:]), "security_reserved")
    for b in d["held"]:
        need(zero(b[176:]), "held_reserved")
    for b in d["images"]:
        need(zero(b[588:]), "image_reserved")
    for b in d["markers"]:
        need(u32(b, 164) == 0 and u32(b, 268) == 0 and zero(b[272:]), "marker_reserved")
    for b in d["regions"]:
        need(u32(b, 60) == 0, "memory_reserved")
    if expected is not None:
        d.update(_analyze(d, expected_inputs(expected)))
    return d


def within(q, e):
    return e["start"] <= q < e["end"]


def raw_shape(c):
    need(c["reserved"] == 0 and c["entered"] in (0, 1) and c["returned"] in (0, 1) and c["error_valid"] in (0, 1) and 1 <= c["kind"] <= 8, "raw_shape")
    need(c["entered"] == 1 and (c["error_valid"] or c["error"] == 0), "raw_entered_error")
    if c["kind"] == 1 and c["returned"]:
        need((c["raw_bool"] != 0 and c["error_valid"] == 0) or (c["raw_bool"] == 0 and c["error_valid"] == 1), "BOOL_error_valid")
    if c["kind"] == 2:
        need(c["raw_bool"] == 0, "COUNT_not_BOOL")
    if c["kind"] == 3 and c["returned"]:
        need(c["observed"] <= 0xFFFFFFFF and c["error_valid"] == int(c["observed"] == 0xFFFFFFFF), "WAIT_error_valid")
    if c["kind"] in (2, 3, 8):
        need(c["raw_bool"] == 0, "nonBOOL_raw_bool")
    if c["kind"] == 7 and c["returned"]:
        status = c["raw_bool"] & 0xFFFFFFFF
        need(c["error_valid"] == int(status != 0) and c["error"] == status, "STATUS_returned_error")


def _qualified_round(d, index, e):
    b, h, image = d["identities"][index], d["held"][index], d["images"][index]
    identity(b)
    security(d["security"][index], e["identity"])
    need(b == e["raw"]["identity"] and d["security"][index] == e["raw"]["security"], "full_expected_tuple")
    need((u32(h, 0), u32(h, 4), u32(h, 8), u32(h, 12), u64(h, 16), u32(h, 24), u32(h, 28)) == (192, 2, e["pid"], e["pid"], e["creation"], 1, 0), "held_generation")
    need(all(u32(h, o) != 0 for o in (32, 40, 48, 72, 96)) and all(u32(h, o) == 0 for o in (36, 44, 52, 76, 100, 172)) and u32(h, 168) == 1, "held_API_resources")
    need(all(u32(h, o) == 1 for o in (56, 80)) and all(u32(h, o) == 0x2000 for o in (60, 84)) and all(u32(h, o) == 0 for o in (64, 68, 88, 92)), "held_Jobs")
    p = e["plan"]
    need(h[104:128] == p[360:384] and h[128:152] == p[384:408] and h[152:168] == p[488:504], "held_leases")
    q = call(image[:64])
    raw_shape(q)
    need(q["kind"] == 1 and q["returned"] == 1 and q["raw_bool"] != 0 and q["requested"] == 260 and q["observed"] == u32(image, 584), "image_raw")
    path = text16(image[64:584], u32(image, 584), 260)
    need(dos_path(path) == dos_path(e["raw"]["target_path"]) and sum(c["raw"] == q["raw"] for c in d["calls"]) == 1, "image_unique_physical")
    need(within(q["entered_qpc"], e) and q["entered_qpc"] <= q["returned_qpc"] < e["end"], "image_clock")


def _marker(m, e, returned_qpc, complete):
    need(m[:192] == e["raw"]["initial_marker"][:192] and (u32(m, 192), u32(m, 196)) == (128, 2), "marker_immutable")
    seq, base = u64(m, 248), u64(m, 256)
    need(seq != 0 and seq % 2 == 0 and u32(m, 264) == 1 and 0x10000 <= base <= USER_TOP - 4096 and base % 65536 == 0 and u32(m, 240) == e["pid"] and u32(m, 204) <= 11 and u32(m, 200) & ~0x3FFF == 0, "marker_coherence_shape")
    need(within(u64(m, 232), e) and u64(m, 232) <= returned_qpc, "marker_clock_causality")
    if complete:
        need(u32(m, 200) == 6143 and u32(m, 204) == 0 and all(u32(m, o) != 0 for o in (208, 216, 224)) and all(u32(m, o) == 0 for o in (212, 220, 228, 244)), "marker_success")
    return base


def _mapping(d, e, base):
    values = []
    for b in d["regions"]:
        need((u32(b, 0), u32(b, 4), u64(b, 8), u64(b, 16), u64(b, 48), u32(b, 56)) == (64, 2, base, base, 48, 0), "MM_extent_base")
        n, state, protect, kind = u64(b, 24), u32(b, 36), u32(b, 40), u32(b, 44)
        need(4096 <= n <= USER_TOP - base and state == 0x1000 and kind == 0x1000000 and protect & ~0x6FF == 0 and protect & 0x100 == 0 and protect & 0xFF in (2, 4, 8, 0x20, 0x40, 0x80), "MM_readable_image")
        values.append(b)
    need(values[0] == values[1], "MM_brackets")
    for b in d["mapped_names"]:
        need(text16(b, units16(e["raw"]["marker_nt_path"]), 1024) == e["raw"]["marker_nt_path"], "mapped_NT_name")
    b, p = d["pe_header"], e["marker_pe"]
    n = u32(b, 60)
    need(b[:2] == b"MZ" and 64 <= n <= 4096 - 264 and b[n:n + 4] == b"PE\0\0", "mapped_PE_header")
    f, o = n + 4, n + 24
    need(struct.unpack_from("<H", b, f)[0] == 0x8664 and u32(b, f + 4) == p["timestamp"] and struct.unpack_from("<H", b, f + 16)[0] == 240 and struct.unpack_from("<H", b, f + 18)[0] & 0x2000 and struct.unpack_from("<H", b, o)[0] == 0x20B and u32(b, o + 16) == p["entry_rva"] and u32(b, o + 56) == p["image_bytes"] and u32(b, o + 60) == p["header_bytes"] and struct.unpack_from("<H", b, o + 68)[0] == p["subsystem"], "mapped_PE_expected")


def _complete_typed(d, e):
    r = d["result"]
    required = set(RESULT_FLAGS) - {"remote_outcome_unknown"}
    need(r["result_class"] == 7 and all(r[k] == 1 for k in required) and r["remote_outcome_unknown"] == 0 and r["exception_code"] == 0 and r["held_count"] == 2 and r["snapshot_count"] in (2, 4) and r["mapping_count"] == 2, "complete_result_tuple")
    need(within(r["entered_qpc"], e) and r["entered_qpc"] <= r["returned_qpc"] < e["end"], "complete_original_window")
    for i in range(2):
        _qualified_round(d, i, e)
    g = d["generation"]
    need((u32(g, 0), u32(g, 4), u32(g, 8), u32(g, 12), u64(g, 16), u32(g, 24), u32(g, 28)) == (64, 2, e["pid"], e["pid"], e["creation"], 1, 0), "middle_generation")
    need(all(u32(g, o) != 0 for o in (32, 44)) and all(u32(g, o) == 0 for o in (36, 48, 60)) and all(u32(g, o) == 1 for o in (40, 52, 56)), "middle_Jobs_clean")
    if r["snapshot_count"] == 2:
        need(all(zero(b) for b in d["markers"][:2]), "fast_unused_progress")
    else:
        # A progress read may race a writer. Only the independent BODY pair
        # qualifies; diagnostic progress incoherence is retained, not promoted.
        pass
    need(d["markers"][2][192:] == d["markers"][3][192:], "BODY_pair_coherence")
    base = _marker(d["markers"][2], e, r["returned_qpc"], True)
    _marker(d["markers"][3], e, r["returned_qpc"], True)
    _mapping(d, e, base)


def packed(low, high):
    return low | (high << 32)


class _Trace:
    """Independent fixed finite grammar and allocation ledger, schema01."""
    def __init__(self, d, e):
        self.d, self.e, self.rows = d, e, d["calls"]
        self.pos, self.last = 0, 0
        self.known, self.labels, self.sizes = {}, {}, {}
        self.uncertain, self.failure, self.exited = False, None, False
        self.entered, self.body, self.progress, self.round = False, False, False, 0
        self.after_failure = 0
        self.exit_call = None
        self.entered_sample, self.body_sample = None, None

    def fail(self, c, category):
        if self.failure is None:
            api_failed = bool(c["returned"] and ((c["kind"] == 1 and c["raw_bool"] == 0 and not (c["operation"] in PROBES and c["error"] == 122)) or (c["kind"] == 2 and c["observed"] == 0) or (c["kind"] == 3 and c["observed"] == 0xFFFFFFFF) or (c["kind"] == 7 and c["raw_bool"] != 0) or (c["kind"] == 8 and c["observed"] != 0)))
            self.failure = {"operation": c["operation"], "category": category, "returned": bool(c["returned"]), "API_return_failed": api_failed, "error_valid": bool(c["error_valid"]), "error": c["error"] if c["error_valid"] else None}

    def canonical(self, op):
        """Check only retained canonical fields, never invent original buffers."""
        e = self.e
        b = self.d["identities"][self.round]
        if op in (117, 119, 123, 125) and not zero(b):
            if op in (117, 123):
                n, start, expected = (u32(b, 8), 16, e["identity"]["user_sid"]) if op == 117 else (u32(b, 12), 84, e["identity"]["appcontainer_sid"])
                if not 8 <= n <= 68:
                    return False
                try:
                    sid(b[start:start + n])
                except ReaderError:
                    return False
                return b[start:start + n] == expected
            if op == 119:
                return u32(b, 164) == 4096
            return u64(b, 184) == e["identity"]["token_id"] and u64(b, 192) == e["identity"]["authentication_id"]
        if op in (131, 135):
            s = self.d["security"][self.round]
            if not zero(s):
                start, end, chars = (16, 512, u32(s, 8)) if op == 131 else (512, 1008, u32(s, 12))
                try:
                    actual = text16(s[start:end], chars, 248)
                    expected = text16(e["raw"]["security"][start:end], u32(e["raw"]["security"], 8 if op == 131 else 12), 248)
                except ReaderError:
                    return False
                return actual == expected
        if op in (152, 156):
            h = self.d["held"][self.round]
            if not zero(h):
                start, plan_start = (104, 360) if op == 152 else (128, 384)
                return h[start:start + 24] == e["plan"][plan_start:plan_start + 24]
        return True

    def one(self, op):
        if self.pos == len(self.rows):
            return None
        c = self.rows[self.pos]
        if c["operation"] != op:
            # Partial failure may unwind known resources instead of entering
            # the next getter. The suffix is separately checked below.
            partial = not self.d["result"]["observation_complete"] and self.d["result"]["result_class"] not in (5, 7, 9, 10, 11)
            if self.failure is None and partial and self.known and c["operation"] in CLOSES:
                # Admission/parse/pre-QPC may reject before another API was
                # entered. No new row exists, so no physical API FALSE/error
                # is invented. Only the already-known reverse closes follow.
                self.failure = {"operation": None, "category": "prefix_boundary", "returned": False, "API_return_failed": False, "error_valid": False, "error": None, "unentered_gate": True}
                return None
            if self.failure is not None and c["operation"] in CLOSES:
                return None
            need(False, "primitive_order")
        self.pos += 1
        raw_shape(c)
        need(c["kind"] == OP_KINDS[op], "primitive_kind")
        reserve = len(self.known) + (0 if op in CLOSES else 1 + int(op in ALLOCS))
        need(self.pos - 1 + reserve <= 128, "raw_close_capacity_reserve")
        if self.failure is not None:
            self.after_failure += 1
        if not c["returned"]:
            self.fail(c, "unreturned")
        if not (within(c["entered_qpc"], self.e) and c["entered_qpc"] <= c["returned_qpc"] < self.e["end"] and c["entered_qpc"] >= self.last):
            self.fail(c, "original_clock")
        if c["returned_qpc"] and c["returned_qpc"] >= c["entered_qpc"]:
            self.last = max(self.last, c["returned_qpc"])
        good = self.value(c)
        if not good:
            self.fail(c, "API_or_predicate")
        return c

    def value(self, c):
        op, req, obs, b = c["operation"], c["requested"], c["observed"], c["raw_bool"]
        e, p, i = self.e, self.e["plan"], self.e["identity"]
        h = e["borrowed"]
        bool_ok = c["returned"] == 1 and b != 0
        if op in (100, 170, 103, 173):
            need(req == h[0 if op in (100, 170) else 1], "PID_handle_binding")
            need(obs <= 0xFFFFFFFF, "PID_DWORD")
            need(c["error_valid"] == int(obs == 0) if c["returned"] else True, "COUNT_error_valid")
            return c["returned"] == 1 and obs == e["pid"]
        if op in (101, 171):
            need(req == h[0], "times_handle_binding")
            return bool_ok and obs == e["creation"]
        if op in (102, 162, 163, 164, 172):
            need(req == 0, "wait0_timeout")
            if not c["returned"]:
                return False
            if op in (102, 162, 172) and obs == 0:
                self.exited = True
                self.exit_call = c
            if op == 163 and obs == 0:
                self.entered = True
            if op == 164 and obs == 0:
                self.body = True
            if op == 163:
                self.entered_sample = obs
            if op == 164:
                self.body_sample = obs
            return obs == 258 if op in (102, 172) else obs in (0, 258)
        if op in (160, 161):
            need(req <= 8000 and req != 0xFFFFFFFF, "finite_wait_timeout")
            if within(c["entered_qpc"], e):
                need(req <= (e["end"] - c["entered_qpc"]) * 1000 // e["frequency"], "wait_original_remaining")
            if obs == 0:
                self.exited = True
                self.exit_call = c
            return c["returned"] == 1 and 0 <= obs <= (2 if op == 160 else 1)
        if op == 104:
            image = self.d["images"][self.round]
            need(req == 260, "image_capacity")
            if not zero(image):
                need(c["raw"] == image[:64], "image_round_physical_binding")
            return bool_ok and 0 < obs < 260
        if op in ALLOCS:
            if op in (110, 130, 134):
                need(req == h[1 if op == 134 else 0], "allocation_source_handle")
            else:
                need(req == self.labels.get(130 if op == 131 else 134), "SD_converter_source")
            success = c["returned"] == 1 and (b != 0 if op != 130 and op != 134 else (b & 0xFFFFFFFF) == 0)
            if not success or not handle(obs) or obs in h or obs in self.known:
                self.uncertain = True
                return False
            self.known[obs] = op
            self.labels[op] = obs
            return self.canonical(op)
        if op in CLOSES:
            source = {126: 110, 132: 131, 133: 130, 136: 135, 137: 134}[op]
            need(req in self.known and self.known[req] == source and self.labels.get(source) == req, "close_known_once_binding")
            need(req == next(reversed(self.known)), "close_reverse_order")
            del self.known[req]
            success = c["returned"] == 1 and (b != 0 if op == 126 else obs == 0)
            if op == 126:
                need(obs == 0, "close_unused_output")
            elif c["returned"]:
                need(c["error_valid"] == int(obs != 0), "LocalFree_error_valid")
            if not success:
                self.uncertain = True
            return success
        if op in (111, 112, 113, 114, 115):
            need(req == 4, "scalar_direct4")
            value = {111: 1, 112: i["session_id"], 113: 1, 114: 0, 115: 0}[op]
            return bool_ok and obs == packed(4, value)
        if op in PROBES:
            need(req == 0, "token_probe_zero_capacity")
            good = c["returned"] == 1 and b == 0 and c["error_valid"] == 1 and c["error"] == 122 and 0 < obs <= 4096 and (op != 124 or obs == 56)
            if good:
                self.sizes[op + 1] = obs
            return good
        if op in (117, 119, 121, 123, 125):
            need(req == self.sizes.get(op) and 0 < req <= 4096, "token_fill_probe_binding")
            actual = obs & 0xFFFFFFFF if op in (121, 125) else obs
            minimum = {117: max(16, len(i["user_sid"])), 119: 16, 121: 4, 123: max(8, len(i["appcontainer_sid"])), 125: 56}[op]
            good = bool_ok and minimum <= actual <= req
            if op == 121:
                good = good and obs >> 32 == 0
            if op == 125:
                good = good and obs == packed(56, 1)
            return good and self.canonical(op)
        if op in (140, 144, 174, 175):
            need(req == h[3 if op in (140, 174) else 4], "exact_Job_binding")
            return bool_ok and obs == 1
        if op in (141, 145, 150, 154):
            need(req == h[{141: 3, 145: 4, 150: 7, 154: 8}[op]], "flags_handle_binding")
            return bool_ok and obs == 0
        if op in (142, 146, 143, 147):
            cap, cls, value = (144, 9, 0x2000) if op in (142, 146) else (4, 4, 0)
            need(req == packed(cls, cap), "QIJob_class_capacity")
            return bool_ok and obs == packed(cap, value)
        if op in (151, 155):
            need(req == 8, "attribute_tag_capacity")
            return bool_ok and obs & 0x410 == 0
        if op in (152, 156):
            need(req == 24 and obs == 0, "fileID_capacity_unused")
            return bool_ok and self.canonical(op)
        if op in (153, 157):
            need(req & 0xFFFFFFFF == 24 and req >> 48 == 0, "FileStandard_encoding")
            return bool_ok and req == 24 and obs == u64(p, 488 if op == 153 else 496)
        if op in (180, 181, 182, 183):
            need(req == 320, "marker_RPM_capacity")
            if bool_ok and obs == 320 and op in (182, 183):
                try:
                    _marker(self.d["markers"][op - 180], e, c["returned_qpc"], True)
                except ReaderError:
                    return False
            return bool_ok and obs == 320
        if op in (190, 193):
            need(req == 48, "VQ_capacity")
            region = self.d["regions"][0 if op == 190 else 1]
            if not zero(region):
                need(obs == u64(region, 48), "VQ_physical_count")
            if c["returned"] and not zero(region):
                need(c["error_valid"] == int(obs == 0) and c["error"] == u32(region, 56), "VQ_error_binding")
            return c["returned"] == 1 and obs == 48
        if op in (191, 194):
            need(req == 1024, "mapped_name_capacity")
            need(c["error_valid"] == int(obs == 0 or obs >= 1024) if c["returned"] else True, "mapped_name_error_valid")
            return c["returned"] == 1 and obs == units16(e["raw"]["marker_nt_path"])
        if op == 192:
            need(req == 4096, "PE_RPM_capacity")
            return bool_ok and obs == 4096
        need(False, "unknown_primitive")

    def group(self, ops):
        for op in ops:
            if self.one(op) is None:
                return False
            if self.failure is not None:
                return False
        return True

    def suffix(self):
        while self.pos < len(self.rows):
            c = self.rows[self.pos]
            need(self.failure is not None and c["operation"] in CLOSES, "failure_suffix_only_known_close")
            need(self.one(c["operation"]) is not None, "close_suffix_missing")

def validate_primitive_trace(d, e):
    t = _Trace(d, e)
    finished = False
    body_calls_verified, mapping_calls_verified = False, False
    full_before_complete = t.group(FULL_OPS) and t.failure is None
    if full_before_complete:
        if t.group((160, 162, 163, 164)):
            if t.entered_sample == 0 and not t.exited:
                delayed = t.body_sample != 0
                if delayed:
                    t.progress = True
                    ready = t.group((180, 181, 161, 162, 163, 164))
                else:
                    ready = True
                if ready and t.failure is None and t.entered_sample == t.body_sample == 0 and not t.exited and t.group(MIDDLE_OPS) and t.failure is None:
                    body_calls_verified = t.group((182, 183)) and t.failure is None
                    if body_calls_verified:
                        mapping_calls_verified = t.group((190, 191, 192, 193, 194)) and t.failure is None
                        if mapping_calls_verified:
                            t.round = 1
                            finished = t.group(FULL_OPS) and t.failure is None
            elif t.exited:
                t.fail(t.exit_call, "process_exit")
            elif not t.entered:
                t.fail(d["calls"][t.pos - 1], "ENTERED_absent")
    t.suffix()
    need(t.pos == len(t.rows), "trace_unconsumed")
    if finished:
        need(len(t.rows) == (115 if t.progress else 109), "finite_trace_count")
        need(d["result"]["snapshot_count"] == (4 if t.progress else 2), "snapshot_trace_count")
    return {"verified": True, "status": "finite-complete" if finished else "bounded-partial", "finished": bool(finished), "full_before_complete": full_before_complete, "body_calls_verified": body_calls_verified, "mapping_calls_verified": mapping_calls_verified, "resources_clean": not t.known and not t.uncertain, "known_close_obligations": len(t.known), "resource_uncertain": t.uncertain, "failure": t.failure, "calls_after_first_failure": t.after_failure, "events": bool(t.entered and t.body and not t.exited), "process_exit_seen": t.exited, "progress_pair_used": t.progress}


def validate_inputs(expected):
    return expected_inputs(expected)


def decode_result(raw256, operation, window):
    """Decode an operation's own Result256, keeping original field names."""
    operations = {"begin": (1, 9), "update": (2, 11), "install": (3, 5), "observe": (4, 7), "forget": (5, 10)}
    need(type(operation) is str and operation in operations and type(window) is tuple and len(window) == 2 and all(type(q) is int for q in window) and 0 <= window[0] < window[1] <= I64_MAX, "result_operation_window")
    op, success_class = operations[operation]
    r = result(raw256, op)
    c = r["primary_call"]
    if not zero(c["raw"]):
        raw_shape(c)
    if r["result_class"] == success_class:
        if operation != "forget":
            need(all(r[k] == 1 for k in ("validation_passed", "return_clock_known", "within_window", "context_known", "target_alive", "resources_clean")) and r["remote_outcome_unknown"] == 0 and window[0] <= r["entered_qpc"] <= r["returned_qpc"] < window[1], "operation_success_tuple")
        if operation in ("update", "install"):
            need(c["operation"] == (220 if operation == "update" else 221) and c["entered"] == c["returned"] == 1 and window[0] <= c["entered_qpc"] <= c["returned_qpc"] <= r["returned_qpc"], "primary_call_causality")
            if operation == "update":
                need(c["kind"] == 1 and c["raw_bool"] != 0 and c["observed"] == 0 and c["error_valid"] == 0 and c["error"] == 0, "update_primary_TRUE")
            else:
                need(c["kind"] == 8 and c["requested"] == 320 and handle(c["observed"]) and c["observed"] % 8 == 0 and c["error_valid"] == 0 and c["error"] == 0, "install_primary_aligned")
        if operation == "observe":
            need(r["observation_complete"] == r["mapping_qualified"] == 1 and r["remote_outcome_unknown"] == 0, "observe_success_stage")
        if operation == "forget":
            need(r["observation_complete"] == 0 and r["mapping_qualified"] == 0, "forget_not_observe_success")
    return r


def _analyze(d, e):
    r = d["result"]
    for c in d["calls"]:
        need(c["operation"] in OP_KINDS, "unknown_or_nonobserve_primitive")
        raw_shape(c)
    if not zero(r["primary_call"]["raw"]):
        raw_shape(r["primary_call"])
    trace = validate_primitive_trace(d, e)
    typed = bool(r["observation_complete"])
    if typed:
        _complete_typed(d, e)
        need(trace["finished"] and trace["resources_clean"] and trace["failure"] is None, "complete_requires_physical_trace")
        need(d["calls"][45]["entered_qpc"] == r["entered_qpc"] and d["calls"][-1]["returned_qpc"] == r["returned_qpc"], "result_trace_clock")
    need(not (r["resources_clean"] and not trace["resources_clean"]), "resources_not_self_asserted")
    need(bool(r["entered_observed"]) == bool(trace["events"] or any(c["operation"] == 163 and c["returned"] and c["observed"] == 0 for c in d["calls"])), "ENTERED_raw_binding")
    need(bool(r["body_observed"]) == bool(any(c["operation"] == 164 and c["returned"] and c["observed"] == 0 for c in d["calls"])), "BODY_raw_binding")
    need(zero(r["primary_call"]["raw"]), "observe_primary_call_must_be_zero")
    if r["result_class"] in (12, 13):
        failed = d["calls"][-1] if d["calls"] else None
        need(failed is not None and failed["operation"] in ((180, 182) if r["result_class"] == 12 else (181, 183)) and failed["kind"] == 1 and failed["returned"] == 1 and failed["raw_bool"] == 0 and failed["error_valid"] == 1, "RPM_failure_class_binding")
    for index, names in enumerate((("identity_before", "jobs_before", "leases_before"), ("identity_after", "jobs_after", "leases_after"))):
        values = tuple(r[n] for n in names)
        need(values in ((0, 0, 0), (1, 1, 1)), "full_flags_together")
        if values[0]:
            need(trace["full_before_complete"] if index == 0 else trace["finished"], "full_flags_need_trace")
            _qualified_round(d, index, e)
    resources = bool(r["resources_clean"] and trace["resources_clean"])
    coherent, mapping = _historical_body_mapping(d, e, trace)
    return {"trace": trace, "gates": {"inner_complete": typed and trace["finished"] and resources, "coherent_marker": coherent, "memory_mapping": mapping, "events": trace["events"], "resources": resources, "trace_complete": trace["finished"]}}


def _historical_body_mapping(d, e, trace):
    """Qualified earlier BODY/MM facts survive a later full-after failure."""
    coherent, mapping, base = False, False, None
    if trace["body_calls_verified"] and d["result"]["snapshot_count"] == (4 if trace["progress_pair_used"] else 2):
        pairs = [[c for c in d["calls"] if c["operation"] == op] for op in (182, 183)]
        if all(len(rows) == 1 for rows in pairs):
            try:
                need(d["markers"][2][192:320] == d["markers"][3][192:320], "historical_BODY_pair")
                for slot, rows in zip((2, 3), pairs):
                    c = rows[0]
                    need(c["kind"] == 1 and c["entered"] == c["returned"] == 1 and c["raw_bool"] != 0 and c["error_valid"] == c["error"] == 0 and c["requested"] == c["observed"] == 320 and within(c["entered_qpc"], e) and c["entered_qpc"] <= c["returned_qpc"] < e["end"], "historical_BODY_physical")
                    base = _marker(d["markers"][slot], e, c["returned_qpc"], True)
                coherent = True
            except ReaderError:
                coherent = False
    if coherent and trace["mapping_calls_verified"] and d["result"]["mapping_count"] == 2:
        try:
            _mapping(d, e, base)
            mapping = True
        except ReaderError:
            mapping = False
    return coherent, mapping


def review(raw, expected):
    """Safe source-bound interpretation; external lifecycle remains separate."""
    e = expected_inputs(expected)
    d = decode_output(raw)
    r = d["result"]
    analyzed = _analyze(d, e)
    qualified = analyzed["gates"]["inner_complete"]
    return {"schema_version": 1, "stage": "independent-CMM24576-byte-review", "binary_bytes": len(raw), "binary_sha256": hashlib.sha256(raw).hexdigest(), "source_sha256": expected["commitments"]["source_sha256"].hex(), "status": "inner-observed" if qualified else "partial", "result_class": r["result_class"], "counts": {k: r[k] for k in ("call_count", "held_count", "snapshot_count", "mapping_count")}, "entered_event_observed": bool(r["entered_observed"]), "BODY_event_observed": bool(r["body_observed"]), "typed_inner_complete_claimed": bool(r["observation_complete"]), "inner_observation_complete": qualified, "trace": analyzed["trace"], "gates": analyzed["gates"], "fixed_false_claims": dict.fromkeys(FALSE_CLAIMS, False)}
