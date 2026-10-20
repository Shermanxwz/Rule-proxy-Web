"""Packet-level DNS diagnostic for zero-capability AppContainers (disposable Windows runners only).

Five bounded probe processes run in order: m1 outside, m2 zero capabilities, m3 zero
capabilities with package WFP filters and loopback exemption, m4 internetClient positive
control, m5 outside. Each probe resolves a distinct nonce name per API while pktmon captures
UDP/53 on the NICs. The report holds counts and short excerpts only; raw captures stay on the
runner. Exit status is 0 unless the harness itself fails; an invalid experiment is reported
in the verdict, not in the exit status.
"""

from __future__ import annotations

import argparse
import contextlib
import ctypes as C
import hashlib
import io
import json
import os
import re
import secrets
import struct
import subprocess
import sys
import time
import traceback
from collections import namedtuple
from datetime import datetime, timezone
from pathlib import Path

HERE = Path(__file__).resolve().parent
REPO = HERE.parent
lab = None  # windows_appcontainer_lab, imported in main() once sys.path is set up

PKTMON = Path(os.environ.get('SystemRoot', r'C:\Windows')) / 'System32' / 'pktmon.exe'
DUMMY_PROXY_PORT = 9  # PackageFilters permits only 127.0.0.1 and ::1 on this port; nothing listens there
BROKER_SETTLE_SECONDS = 6
PROBE_TIMEOUT_SECONDS = 45
CREATE_SUSPENDED = 0x4
KILL_ON_JOB_CLOSE = 0x2000
SE_GROUP_ENABLED = 0x4
WAIT_TIMEOUT = 0x102
INTERNET_CLIENT = 'S-1-15-3-1'
DNS_SUFFIX = '.example.com'
APIS = ('getaddrinfo', 'gethostbyname', 'dnsquery_a', 'dnsquery_aaaa', 'resolve_dnsname', 'net_dns', 'nslookup')
Mode = namedtuple('Mode', 'name number contained capabilities filters exemption')
MODES = (
    Mode('m1_outside_before', 1, False, (), False, False),
    Mode('m2_ac_zero', 2, True, (), False, False),
    Mode('m3_ac_zero_wfp', 3, True, (), True, True),
    Mode('m4_ac_internet', 4, True, (INTERNET_CLIENT,), False, False),
    Mode('m5_outside_after', 5, False, (), False, False),
)
EMPTY_PCAP = {'sent': 0, 'responses': 0, 'unparsed': 0, 'sent_excerpts': []}
EMPTY_TXT = {'dropped': 0, 'txt_records': 0, 'filter_word_without_drop': 0, 'drop_excerpts': []}
PAYLOAD_HEX = re.compile(r'(?:\b[0-9a-f]{2}\b[ \t,:]+){15}\b[0-9a-f]{2}\b', re.IGNORECASE)
LIMITATIONS = (
    'A zero NIC count is not proof that a packet was never built: ALE connect-layer WFP blocks happen before any packet exists.',
    "NIC frames are not attributed to a process; a nonce on the wire may have been sent by the Dnscache broker on the probe's behalf.",
    'nic_frames_sent counts UDP/53 query frames in the converted capture; if etl2pcap also emits drop events, sent is overcounted.',
    'nic_frames_dropped counts txt records that contain the word drop and the nonce (ASCII or hex); drop reason and component are not parsed.',
    'The word Filter is not a drop marker; such records are counted in filter_word_without_drop.',
    'pktmon syntax beyond the repo-verified calls is unverified; every attempt is listed in pcap_conversions and txt_conversions.',
    'DNS over TCP/53 is not parsed; nonce-bearing frames that do not parse are counted in pcap_unparsed.',
    'capture_valid also requires every mode to have produced probe results; a mode that did not run makes the experiment invalid.',
)

# Runs inside the AppContainer (or outside, for m1 and m5) as: python -I probe.py <config.json>
PROBE = r'''
import ctypes
import json
import os
import socket
import subprocess
import sys
import threading
import time
from ctypes import wintypes

CAP_SECONDS = 20.0
CHILD_SECONDS = 15.0
CREATE_NO_WINDOW = 0x08000000
KEYS = ("getaddrinfo", "gethostbyname", "dnsquery_a", "dnsquery_aaaa",
        "resolve_dnsname", "net_dns", "nslookup")


def describe(error):
    return (type(error).__name__ + ": " + str(error))[:200]


def run_child(argv):
    try:
        done = subprocess.run(argv, capture_output=True, timeout=CHILD_SECONDS,
                              creationflags=CREATE_NO_WINDOW)
    except subprocess.TimeoutExpired:
        return "timeout"
    except OSError as error:
        return "exception: " + describe(error)
    if done.returncode != 0:
        return "child_exit_code: %d" % done.returncode
    return "ok"


def dns_query(name, record_type):
    dnsapi = ctypes.WinDLL("dnsapi")
    query = dnsapi.DnsQuery_W
    query.argtypes = [wintypes.LPCWSTR, wintypes.WORD, wintypes.DWORD, ctypes.c_void_p,
                      ctypes.POINTER(ctypes.c_void_p), ctypes.c_void_p]
    query.restype = wintypes.DWORD
    results = ctypes.c_void_p()
    status = query(name, record_type, 0, None, ctypes.byref(results), None)  # DNS_QUERY_STANDARD = 0 (unverified)
    if results.value:
        try:
            free = dnsapi.DnsRecordListFree
            free.argtypes = [ctypes.c_void_p, ctypes.c_int]
            free.restype = None
            free(results, 1)  # DnsFreeRecordList
        except AttributeError:
            pass
    if status:
        raise OSError("DnsQuery_W status %d" % status)
    return "ok"


def get_addr_info(name):
    return "ok" if socket.getaddrinfo(name, 443, socket.AF_UNSPEC) else "empty"


def get_host_by_name(name):
    socket.gethostbyname(name)
    return "ok"


def query_a(name):
    return dns_query(name, 1)


def query_aaaa(name):
    return dns_query(name, 28)


def resolve_dns_name(name):
    return run_child(["powershell.exe", "-NoProfile", "-Command", "Resolve-DnsName " + name])


def net_dns(name):
    return run_child(["powershell.exe", "-NoProfile", "-Command",
                      "[Net.Dns]::GetHostAddresses('" + name + "')"])


def nslookup(name):
    return run_child(["nslookup.exe", name])


ACTIONS = {"getaddrinfo": get_addr_info, "gethostbyname": get_host_by_name, "dnsquery_a": query_a,
           "dnsquery_aaaa": query_aaaa, "resolve_dnsname": resolve_dns_name, "net_dns": net_dns,
           "nslookup": nslookup}


def main():
    with open(sys.argv[1], encoding="utf-8") as handle:
        config = json.load(handle)
    names = config["names"]
    lock = threading.Lock()
    outcomes = {}

    def record(key, value):
        with lock:
            outcomes.setdefault(key, value)

    def work(key):
        try:
            record(key, ACTIONS[key](names[key]))
        except Exception as error:
            record(key, "exception: " + describe(error))

    started = time.monotonic()
    threads = []
    for key in KEYS:
        thread = threading.Thread(target=work, args=(key,), daemon=True)
        thread.start()
        threads.append(thread)
    deadline = started + CAP_SECONDS
    for thread in threads:
        thread.join(max(0.0, deadline - time.monotonic()))
    with lock:
        snapshot = {key: outcomes.get(key, "timeout") for key in KEYS}
    body = {"mode": config["mode"], "outcomes": snapshot, "elapsed": round(time.monotonic() - started, 2)}
    with open(config["result"], "w", encoding="utf-8") as handle:
        json.dump(body, handle, sort_keys=True)
    os._exit(0)


main()
'''


class Notices:
    """At most 8 ::notice lines; the last slot is reserved for the verdict."""

    def __init__(self):
        self.count = 0

    def emit(self, body, *, final=False):
        if self.count >= (8 if final else 7):
            return
        self.count += 1
        text = ' '.join(str(body).split())[:2900]
        text = text.replace('%', '%25')
        print(f'::notice title=dns-capture::{text}', flush=True)


def utc_now() -> str:
    return datetime.now(timezone.utc).isoformat(timespec='seconds')


def describe(error: BaseException) -> str:
    return (type(error).__name__ + ': ' + str(error))[:300]


def collapse(text: str, limit: int = 300) -> str:
    return ' '.join(text.split())[:limit]


def read_json(path: Path):
    try:
        return json.loads(path.read_text(encoding='utf-8'))
    except (OSError, ValueError):
        return None


def make_plan():
    plan = []
    for mode in MODES:
        for index, api in enumerate(APIS, start=1):
            nonce = f'rp{mode.number}{index}{secrets.token_hex(5)}'
            plan.append({'mode': mode.name, 'api': api, 'nonce': nonce, 'name': nonce + DNS_SUFFIX})
    return plan


# AppContainer creation extends the child's environment block; the first run of this lab proved that the
# reduced block below starts uncontained processes but fails contained ones with ERROR_ENVVAR_NOT_FOUND (203).
# The base rung mirrors windows_appcontainer_compat.safe_environment (known to launch contained browsers on
# this runner image); the second rung only adds plain machine/user identity names, never tokens or secrets.
BASE_ENV_KEYS = ('SYSTEMROOT', 'WINDIR', 'PATH', 'COMSPEC', 'PATHEXT', 'PROGRAMFILES', 'PROGRAMFILES(X86)',
                 'PROGRAMW6432', 'COMMONPROGRAMFILES', 'COMMONPROGRAMFILES(X86)', 'COMMONPROGRAMW6432',
                 'OS', 'NUMBER_OF_PROCESSORS', 'PROCESSOR_ARCHITECTURE', 'PROCESSOR_LEVEL', 'PROCESSOR_REVISION')
EXTRA_ENV_KEYS = ('ALLUSERSPROFILE', 'PROGRAMDATA', 'PUBLIC', 'SYSTEMDRIVE', 'COMPUTERNAME', 'USERNAME',
                  'USERDOMAIN', 'HOMEDRIVE', 'HOMEPATH', 'SESSIONNAME', 'PROCESSOR_IDENTIFIER')
ERROR_ENVVAR_NOT_FOUND = 203


def safe_environments(work: Path):
    """Ordered (rung, environment) pairs; a contained launch that returns 203 is retried on the next rung."""
    upper = {key.upper(): value for key, value in os.environ.items()}
    base = {key: upper[key] for key in BASE_ENV_KEYS if key in upper}
    base.update(TEMP=str(work / 'tmp'), TMP=str(work / 'tmp'), HOME=str(work / 'home'),
                USERPROFILE=str(work / 'home'), LOCALAPPDATA=str(work / 'local'), APPDATA=str(work / 'roaming'))
    extra = {key: upper[key] for key in EXTRA_ENV_KEYS if key in upper}
    return [('compat_base', base), ('compat_base_plus_identity', {**base, **extra})]


def pktmon(*args: str, timeout: int = 120) -> dict:
    try:
        done = subprocess.run([str(PKTMON), *args], capture_output=True, text=True, errors='replace',
                              timeout=timeout)
    except (OSError, subprocess.TimeoutExpired) as error:
        return {'argv': list(args), 'rc': None, 'output': describe(error)}
    output = (done.stdout or '') + (done.stderr or '')
    return {'argv': list(args), 'rc': done.returncode, 'output': output[-300:]}


def capture_start(work: Path, report: dict) -> None:
    steps = report['capture']['steps']
    # Stale-state cleanup is best effort; a fresh runner has no session to stop.
    for args in (('stop',), ('filter', 'remove'), ('reset',)):
        steps.append(pktmon(*args, timeout=60))
    steps.append(pktmon('filter', 'add', 'dns', '-p', '53', timeout=60))
    steps.append(pktmon('start', '--capture', '--type', 'all', '--comp', 'nics', '--pkt-size', '0',
                        '--file-name', str(work / 'cap.etl'), timeout=120))


def capture_stop(report: dict) -> None:
    report['capture']['steps'].append(pktmon('stop', timeout=120))


def convert(variants, attempts: list):
    """Try each (label, args, output) until one writes a non-empty file."""
    for label, args, output in variants:
        with contextlib.suppress(FileNotFoundError):
            output.unlink()
        result = pktmon(*args, timeout=600)
        size = output.stat().st_size if output.is_file() else 0
        result.update(label=label, output_bytes=size, ok=result['rc'] == 0 and size > 0)
        attempts.append(result)
        if result['ok']:
            return output
    return None


def decode_text(raw: bytes) -> str:
    if raw.startswith((b'\xff\xfe', b'\xfe\xff')):
        return raw.decode('utf-16', errors='replace')
    if raw.count(b'\x00') > len(raw) // 4:
        return raw.decode('utf-16-le', errors='replace')
    return raw.decode('utf-8', errors='replace')


def read_frames(path: Path):
    """Return (format, linktype, [(timestamp, frame_bytes)]) for classic pcap or pcapng."""
    import windows_pcapng  # pure Python, shipped beside this file

    data = path.read_bytes()
    if data[:4] == b'\x0a\x0d\x0d\x0a':
        frames = [(stamp, frame) for stamp, _direction, frame in windows_pcapng.Reader(io.BytesIO(data)).frames()]
        return 'pcapng', 1, frames
    layouts = {b'\xd4\xc3\xb2\xa1': ('<', False), b'\xa1\xb2\xc3\xd4': ('>', False),
               b'\x4d\x3c\xb2\xa1': ('<', True), b'\xa1\xb2\x3c\x4d': ('>', True)}
    if data[:4] not in layouts:
        raise ValueError('not a pcap or pcapng file')
    order, nanos = layouts[data[:4]]
    linktype = struct.unpack(order + 'I', data[20:24])[0]
    frames, offset = [], 24
    while offset + 16 <= len(data):
        seconds, fraction, captured, _original = struct.unpack(order + 'IIII', data[offset:offset + 16])
        offset += 16
        frame = data[offset:offset + captured]
        offset += captured
        if len(frame) != captured:
            break
        frames.append((seconds + fraction / (1e9 if nanos else 1e6), frame))
    return 'pcap', linktype, frames


def dns_question(frame: bytes, linktype: int):
    """Return qr/qname/ports/qtype for a UDP/53 DNS message in an Ethernet frame, else None."""
    if linktype != 1 or len(frame) < 14:
        return None
    offset, ethertype = 14, int.from_bytes(frame[12:14], 'big')
    if ethertype == 0x8100 and len(frame) >= 18:
        offset, ethertype = 18, int.from_bytes(frame[16:18], 'big')
    if ethertype == 0x0800 and len(frame) >= offset + 20:
        header = (frame[offset] & 0x0F) * 4
        if header < 20:
            return None
        protocol, udp = frame[offset + 9], offset + header
    elif ethertype == 0x86DD and len(frame) >= offset + 40:
        protocol, udp = frame[offset + 6], offset + 40
    else:
        return None
    if protocol != 17 or len(frame) < udp + 8:
        return None
    sport, dport = struct.unpack('!HH', frame[udp:udp + 4])
    if 53 not in (sport, dport):
        return None
    message = frame[udp + 8:]
    if len(message) < 12:
        return None
    qr = message[2] >> 7
    position, labels = 12, []
    while True:
        if position >= len(message) or len(labels) > 127:
            return None
        length = message[position]
        if length == 0:
            position += 1
            break
        if length & 0xC0:
            return None
        labels.append(message[position + 1:position + 1 + length].decode('ascii', 'replace').lower())
        position += 1 + length
    qtype = int.from_bytes(message[position:position + 2], 'big') if len(message) >= position + 2 else None
    return {'qr': qr, 'qname': '.'.join(labels), 'sport': sport, 'dport': dport, 'qtype': qtype}


def names_match(qname: str, name: str) -> bool:
    """The client may append a search suffix; that is still a query for this nonce."""
    return qname == name or qname.startswith(name + '.')


def count_capture(plan, frames, linktype):
    counts = {entry['name']: {'sent': 0, 'responses': 0, 'unparsed': 0, 'sent_excerpts': []} for entry in plan}
    needles = [(entry, entry['nonce'].encode('ascii')) for entry in plan]
    for stamp, frame in frames:
        lowered = frame.lower()
        hits = [entry for entry, needle in needles if needle in lowered]
        if not hits:
            continue
        parsed = dns_question(frame, linktype)
        for entry in hits:
            row = counts[entry['name']]
            if parsed is None or not names_match(parsed['qname'], entry['name']):
                row['unparsed'] += 1
            elif parsed['qr'] == 0 and parsed['dport'] == 53:
                row['sent'] += 1
                if len(row['sent_excerpts']) < 3:
                    row['sent_excerpts'].append(collapse(
                        f"pcap t={stamp:.6f} DNS query qtype={parsed['qtype']} qname={parsed['qname']} "
                        f"sport={parsed['sport']} bytes={len(frame)}"))
            elif parsed['qr'] == 1:
                row['responses'] += 1
            else:
                row['unparsed'] += 1
    return counts


def text_records(text: str):
    """Split pktmon text into records at blank lines; fall back to lines if there is no separation."""
    lines = text.splitlines()
    chunks, current = [], []
    for line in lines:
        if line.strip():
            current.append(line)
        elif current:
            chunks.append(current)
            current = []
    if current:
        chunks.append(current)
    if len(chunks) <= 1 and len(lines) > 20:
        return 'line', [line for line in lines if line.strip()]
    return 'blank-lines', ['\n'.join(chunk) for chunk in chunks]


def count_text(plan, records):
    counts = {entry['name']: {'dropped': 0, 'txt_records': 0, 'filter_word_without_drop': 0,
                              'drop_excerpts': []} for entry in plan}
    for record in records:
        lowered = record.lower()
        compact = re.sub(r'\s+', '', lowered)
        dropped = 'drop' in lowered
        filtered = 'filter' in lowered
        for entry in plan:
            label = entry['nonce']
            if label not in lowered and label.encode('ascii').hex() not in compact:
                continue
            row = counts[entry['name']]
            row['txt_records'] += 1
            if dropped:
                row['dropped'] += 1
                if len(row['drop_excerpts']) < 5:
                    row['drop_excerpts'].append(collapse(record))
            elif filtered:
                row['filter_word_without_drop'] += 1
    return counts


def analyse_capture(work: Path, plan, report: dict):
    capture = report['capture']
    etl = work / 'cap.etl'
    capture['etl_bytes'] = etl.stat().st_size if etl.is_file() else 0
    frames, linktype, form, pcap = [], None, None, None
    for variant in (
        ('pcapng -o', ['pcapng', str(etl), '-o', str(work / 'cap.pcapng')], work / 'cap.pcapng'),
        ('etl2pcap --out', ['etl2pcap', str(etl), '--out', str(work / 'cap.pcap')], work / 'cap.pcap'),
        ('etl2pcap -o', ['etl2pcap', str(etl), '-o', str(work / 'cap.pcap')], work / 'cap.pcap'),
    ):
        produced = convert([variant], capture['pcap_conversions'])
        if produced is None:
            continue
        try:
            form, linktype, frames = read_frames(produced)
        except Exception as error:  # e.g. a link type the reader refuses: try the next converter
            capture.setdefault('pcap_errors', []).append(f'{variant[0]}: {describe(error)}')
            continue
        pcap = produced
        break
    if pcap is None:
        capture['notes'].append('no readable pcap: every sent count is zero by absence, not by observation')
    capture['pcap'] = {'file': pcap.name if pcap else None, 'format': form, 'linktype': linktype,
                       'frames': len(frames)}
    txt = convert([
        ('etl2txt -o', ['etl2txt', str(etl), '-o', str(work / 'cap.txt')], work / 'cap.txt'),
        ('etl2txt --out', ['etl2txt', str(etl), '--out', str(work / 'cap.txt')], work / 'cap.txt'),
    ], capture['txt_conversions'])
    text = decode_text(txt.read_bytes()) if txt else ''
    if not PAYLOAD_HEX.search(text):
        verbose = convert([
            ('etl2txt -o -v 3', ['etl2txt', str(etl), '-o', str(work / 'cap-verbose.txt'), '-v', '3'],
             work / 'cap-verbose.txt'),
            ('etl2txt -o -v', ['etl2txt', str(etl), '-o', str(work / 'cap-verbose.txt'), '-v'],
             work / 'cap-verbose.txt'),
        ], capture['txt_conversions'])
        if verbose is not None:
            candidate = decode_text(verbose.read_bytes())
            if PAYLOAD_HEX.search(candidate):
                text, txt = candidate, verbose
    if txt is None:
        capture['notes'].append('no txt produced: drop counts are zero by absence, not by observation')
    segmentation, records = text_records(text)
    capture['txt'] = {'file': txt.name if txt else None, 'chars': len(text), 'records': len(records),
                      'segmentation': segmentation, 'payload_hex_seen': bool(PAYLOAD_HEX.search(text))}
    return count_capture(plan, frames, linktype), count_text(plan, records)


def run_launch(argv, *, sid, capabilities, cwd: Path, env, log: Path) -> dict:
    """Start argv suspended in a kill-on-close Job, optionally inside the AppContainer with the given
    capability SIDs. The Job stays open for the broker settle window, then is closed."""
    import msvcrt
    from ruleproxy.windows_app_process import _get_api

    api = _get_api()
    job = api.create_job()
    process = lab.PROCESS_INFORMATION()
    attributes, cap_sids = None, []
    try:
        api.configure_job(job, KILL_ON_JOB_CLOSE)
        with log.open('wb') as stream:
            handle = msvcrt.get_osfhandle(stream.fileno())
            os.set_handle_inheritable(handle, True)
            try:
                info = lab.STARTUPINFOEXW()
                info.StartupInfo.cb = C.sizeof(info)
                info.StartupInfo.dwFlags = lab.STARTF_USESTDHANDLES
                info.StartupInfo.hStdOutput = info.StartupInfo.hStdError = handle
                size = C.c_size_t()
                lab.kernel.InitializeProcThreadAttributeList(None, 1, 0, C.byref(size))
                attributes = C.create_string_buffer(size.value)
                if not lab.kernel.InitializeProcThreadAttributeList(attributes, 1, 0, C.byref(size)):
                    raise C.WinError(C.get_last_error())
                capability_array = None
                if sid is not None:
                    for name in capabilities:
                        out = C.c_void_p()
                        if not lab.advapi.ConvertStringSidToSidW(name, C.byref(out)):
                            raise C.WinError(C.get_last_error())
                        cap_sids.append(out)
                    if cap_sids:
                        capability_array = (lab.SID_AND_ATTRIBUTES * len(cap_sids))(
                            *[lab.SID_AND_ATTRIBUTES(item.value, SE_GROUP_ENABLED) for item in cap_sids])
                    caps = lab.SECURITY_CAPABILITIES(
                        sid.value,
                        C.cast(capability_array, C.POINTER(lab.SID_AND_ATTRIBUTES))
                        if capability_array is not None else None,
                        len(cap_sids), 0)
                    if not lab.kernel.UpdateProcThreadAttribute(
                            attributes, 0, lab.PROC_THREAD_ATTRIBUTE_SECURITY_CAPABILITIES,
                            C.byref(caps), C.sizeof(caps), None, None):
                        raise C.WinError(C.get_last_error())
                    info.lpAttributeList = C.cast(attributes, C.c_void_p)
                flags = (lab.EXTENDED_STARTUPINFO_PRESENT | lab.CREATE_NO_WINDOW
                         | lab.CREATE_UNICODE_ENVIRONMENT | CREATE_SUSPENDED)
                started = time.monotonic()
                if not lab.kernel.CreateProcessW(
                        None, C.create_unicode_buffer(subprocess.list2cmdline(argv)), None, None, True, flags,
                        lab.environment_block(env), str(cwd), C.byref(info), C.byref(process)):
                    return {'started': False, 'error_code': C.get_last_error()}
                api.assign_job(job, process.hProcess)
                api.resume_thread(process.hThread)
                timed_out = lab.kernel.WaitForSingleObject(process.hProcess, PROBE_TIMEOUT_SECONDS * 1000) == WAIT_TIMEOUT
                if timed_out:
                    api.terminate_job(job)
                    lab.kernel.WaitForSingleObject(process.hProcess, 5000)
                code = lab.W.DWORD()
                if not lab.kernel.GetExitCodeProcess(process.hProcess, C.byref(code)):
                    raise C.WinError(C.get_last_error())
                outcome = {'started': True, 'exit_code': code.value, 'timed_out': timed_out,
                           'seconds': round(time.monotonic() - started, 2)}
                # The Job stays open through the settle window so stragglers keep running during it.
                time.sleep(BROKER_SETTLE_SECONDS)
                return outcome
            finally:
                os.set_handle_inheritable(handle, False)
    finally:
        if process.hThread:
            api.close_handle(process.hThread)
        if process.hProcess:
            api.close_handle(process.hProcess)
        if attributes is not None:
            lab.kernel.DeleteProcThreadAttributeList(attributes)
        for item in cap_sids:
            lab.kernel.LocalFree(item)
        api.close_handle(job)  # KILL_ON_JOB_CLOSE ends any surviving descendants


def run_mode(mode: Mode, sid, by_key, work: Path, rungs) -> dict:
    record = {'mode': mode.name, 'contained': mode.contained, 'capabilities': list(mode.capabilities),
              'package_filters': mode.filters, 'loopback_exemption': mode.exemption,
              'started_utc': utc_now(), 'ran': False, 'error': None, 'probe': None,
              'probe_outcomes': {}, 'elapsed': None, 'env_rung': None, 'env_attempts': []}
    names = {api: by_key[(mode.name, api)]['name'] for api in APIS}
    result_path = work / 'results' / f'{mode.name}.json'
    config_path = work / f'{mode.name}.config.json'
    config_path.write_text(json.dumps({'mode': mode.name, 'names': names, 'result': str(result_path)}),
                           encoding='utf-8')
    argv = [sys.executable, '-I', str(work / 'probe.py'), str(config_path)]
    try:
        with contextlib.ExitStack() as stack:
            if mode.exemption:
                lab.exemption(sid, True)
                stack.callback(lab.exemption, sid, False)
            if mode.filters:
                stack.enter_context(lab.PackageFilters(sid, DUMMY_PROXY_PORT))
            for rung, env in rungs:
                record['probe'] = run_launch(argv, sid=sid if mode.contained else None,
                                             capabilities=mode.capabilities, cwd=work, env=env,
                                             log=work / f'{mode.name}.probe.log')
                record['env_attempts'].append({'rung': rung, 'keys': sorted(env),
                                               'error_code': record['probe'].get('error_code')})
                record['env_rung'] = rung
                if record['probe'].get('error_code') != ERROR_ENVVAR_NOT_FOUND:
                    break
    except Exception as error:
        record['error'] = describe(error)
    body = read_json(result_path)
    if isinstance(body, dict) and isinstance(body.get('outcomes'), dict):
        record['probe_outcomes'] = body['outcomes']
        record['elapsed'] = body.get('elapsed')
        record['ran'] = True
    elif record['error'] is None:
        record['error'] = 'probe produced no result file; launch=' + json.dumps(record['probe'])[:300]
    record['finished_utc'] = utc_now()
    return record


def run_harness(work: Path, report: dict, ctx: dict) -> None:
    sid = lab.container_sid()
    ctx['sid'] = sid
    report['package_sid'] = lab.sid_text(sid)
    (work / 'probe.py').write_text(PROBE, encoding='utf-8')
    # The container needs read and execute on the interpreter, and modify on the work directory only.
    for path, right in ((Path(sys.base_prefix), '(OI)(CI)(RX)'), (work, '(OI)(CI)(M)')):
        grant = subprocess.run(['icacls', str(path), '/grant', f"*{report['package_sid']}:{right}", '/T', '/Q', '/C'],
                               capture_output=True, text=True, errors='replace', timeout=600)
        report['notes'].append(f'icacls {path}: exit {grant.returncode}')
    rungs = safe_environments(work)
    report['plan'] = make_plan()
    by_key = {(entry['mode'], entry['api']): entry for entry in report['plan']}
    capture_start(work, report)
    try:
        for mode in MODES:
            report['runs'].append(run_mode(mode, sid, by_key, work, rungs))
    finally:
        capture_stop(report)
    ctx['analysis'] = analyse_capture(work, report['plan'], report)


def cleanup(ctx: dict, report: dict) -> None:
    steps = report['capture']['steps']
    steps.append({'cleanup': pktmon('stop', timeout=120)})
    steps.append({'cleanup': pktmon('reset', timeout=60)})
    sid = ctx.get('sid')
    if sid is not None:
        try:
            lab.exemption(sid, False)
        except Exception as error:
            report['notes'].append('cleanup exemption: ' + describe(error))
        code = lab.userenv.DeleteAppContainerProfile(lab.PROFILE)
        report['notes'].append(f'DeleteAppContainerProfile returned 0x{code & 0xFFFFFFFF:08x}')


def build_verdict(report: dict, ctx: dict) -> dict:
    analysis = ctx.get('analysis')
    sent_counts, text_counts = analysis if analysis else ({}, {})
    by_key = {(entry['mode'], entry['api']): entry for entry in report['plan']}
    runs = {run['mode']: run for run in report['runs']}
    modes = {}
    for mode in MODES:
        run = runs.get(mode.name, {})
        outcomes = run.get('probe_outcomes') or {}
        rows = []
        for api in APIS:
            entry = by_key.get((mode.name, api))
            if entry is None:
                continue
            pcap = sent_counts.get(entry['name'], EMPTY_PCAP)
            txt = text_counts.get(entry['name'], EMPTY_TXT)
            rows.append({'api': api, 'nonce': entry['nonce'], 'name': entry['name'],
                         'probe_outcome': outcomes.get(api) or 'not_run: ' + (run.get('error') or 'no run record'),
                         'nic_frames_sent': pcap['sent'], 'nic_frames_dropped': txt['dropped'],
                         'pcap_responses': pcap['responses'], 'pcap_unparsed': pcap['unparsed'],
                         'txt_records': txt['txt_records'],
                         'filter_word_without_drop': txt['filter_word_without_drop'],
                         'excerpts': (pcap['sent_excerpts'] + txt['drop_excerpts'])[:5]})
        modes[mode.name] = rows

    def sent(name):
        return any(row['nic_frames_sent'] > 0 for row in modes.get(name, []))

    def dropped(names):
        return any(row['nic_frames_dropped'] > 0 for name in names for row in modes.get(name, []))

    all_ran = len(runs) == len(MODES) and all(run.get('ran') for run in runs.values())
    frames = report['capture'].get('pcap', {}).get('frames', 0)
    capture_valid = bool(all_ran and frames > 0 and sent('m1_outside_before') and sent('m5_outside_after'))
    positive = sent('m4_ac_internet')
    zero = sent('m2_ac_zero')
    wfp = sent('m3_ac_zero_wfp')
    dropped_zero = dropped(('m2_ac_zero', 'm3_ac_zero_wfp'))
    if not (capture_valid and positive):
        conclusion = 'invalid_experiment'
    elif zero or wfp:
        conclusion = 'hypothesis_refuted'
    elif dropped_zero:
        conclusion = 'hypothesis_supported'
    else:
        conclusion = 'hypothesis_partially_supported'
    return {'capture_valid': capture_valid, 'container_positive_control_seen': positive,
            'zero_cap_dns_reached_nic': zero, 'zero_cap_wfp_dns_reached_nic': wfp,
            'zero_cap_dns_dropped_by_wfp': dropped_zero, 'conclusion': conclusion, 'modes': modes}


def emit_notices(report: dict, notices: Notices, work: Path) -> None:
    capture = report['capture']
    pcap, txt = capture.get('pcap', {}), capture.get('txt', {})
    status = 'frames present' if pcap.get('frames') else 'NO FRAMES: capture invalid'
    notices.emit(f"capture etl_bytes={capture.get('etl_bytes')} pcap={pcap.get('format')} "
                 f"frames={pcap.get('frames')} txt_records={txt.get('records')} "
                 f"segmentation={txt.get('segmentation')} payload_hex_seen={txt.get('payload_hex_seen')} ({status})")
    verdict = report['verdict']
    for mode in MODES:
        rows = verdict['modes'].get(mode.name, [])
        sent = sum(row['nic_frames_sent'] for row in rows)
        dropped = sum(row['nic_frames_dropped'] for row in rows)
        probes = '; '.join(f"{row['api']}={row['probe_outcome']}" for row in rows)
        excerpts = ' || '.join(text for row in rows for text in row['excerpts'])
        notices.emit(f"{mode.name} sent={sent} dropped={dropped} probes: {probes} excerpts: {excerpts[:1500]}")
    notices.emit(f"harness_error={report['harness_error']} notes={'; '.join(report['notes'])[:600]} "
                 f"limitations: {' '.join(LIMITATIONS)}")
    notices.emit(f"conclusion={verdict['conclusion']} capture_valid={verdict['capture_valid']} "
                 f"positive_control_seen={verdict['container_positive_control_seen']} "
                 f"zero_cap_reached_nic={verdict['zero_cap_dns_reached_nic']} "
                 f"zero_cap_wfp_reached_nic={verdict['zero_cap_wfp_dns_reached_nic']} "
                 f"zero_cap_dropped_by_wfp={verdict['zero_cap_dns_dropped_by_wfp']} "
                 f"report={work / 'dns-capture-report.json'}", final=True)


def main() -> int:
    global lab
    parser = argparse.ArgumentParser(description='AppContainer DNS capture diagnostic (disposable runner only)')
    parser.add_argument('--work', type=Path, required=True)
    work = parser.parse_args().work.resolve()
    if os.name != 'nt' or os.environ.get('GITHUB_ACTIONS') != 'true':
        raise RuntimeError('requires a disposable Windows GitHub Actions runner')
    if work.exists():
        raise RuntimeError('work directory already exists; pass a fresh path')
    sys.path[:0] = [str(HERE), str(REPO)]
    from ruleproxy.windows_app_process import _get_api
    if not _get_api().is_elevated():
        raise RuntimeError('pktmon and WFP filters need an elevated runner')
    import windows_appcontainer_lab
    lab = windows_appcontainer_lab
    work.mkdir(parents=True)
    for name in ('tmp', 'home', 'local', 'roaming', 'results'):
        (work / name).mkdir()
    report = {'schema': 'windows-diag-dns/1', 'source_commit': os.environ.get('GITHUB_SHA'),
              'harness_sha256': hashlib.sha256(Path(__file__).read_bytes()).hexdigest(),
              'windows': list(sys.getwindowsversion()[:4]), 'started_utc': utc_now(), 'finished_utc': None,
              'package_sid': None, 'capture': {'steps': [], 'pcap_conversions': [], 'txt_conversions': [],
                                               'notes': []},
              'plan': [], 'runs': [], 'notes': [], 'limitations': list(LIMITATIONS),
              'harness_error': None, 'verdict': None}
    ctx = {'sid': None, 'analysis': None}
    notices = Notices()
    status = 0
    try:
        run_harness(work, report, ctx)
    except Exception as error:
        status = 1
        report['harness_error'] = describe(error) + ' | ' + traceback.format_exc()[-1200:]
    finally:
        try:
            cleanup(ctx, report)
        except Exception as error:
            status = 1
            report['notes'].append('cleanup failed: ' + describe(error))
        report['verdict'] = build_verdict(report, ctx)
        report['finished_utc'] = utc_now()
        (work / 'dns-capture-report.json').write_text(json.dumps(report, indent=2, sort_keys=True), encoding='utf-8')
        emit_notices(report, notices, work)
    return status


if __name__ == '__main__':
    raise SystemExit(main())
