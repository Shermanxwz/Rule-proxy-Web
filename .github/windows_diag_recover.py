"""Disposable-runner lab: does the upstream recovery script find and remove PRODUCT-made objects?

scripts/windows-network-recover.ps1 is already verified upstream against hand-built
fixtures (tests/test_windows_network_recover_script.py and
.github/test_network_recovery_native.ps1). This lab answers the one open question:
objects written by the product's own code, ruleproxy.windows_global_guard.Guard
(persistent provider with service name, sublayer weight 65535, data blobs, filter
conditions and flags) and the product's NRPT naming (ruleproxy.windows_global_dns),
are found, reported and removed by the script run under Windows PowerShell 5.1 -Json.

Hard safety rules (the runner must keep its network):
- every synthetic WFP filter is PERMIT with no conditions; this file never builds a deny action;
- the root DNS namespace is never used; NRPT namespaces are random rp-diag-/rp-ctl-*.invalid;
- every created object is removed in a finally block; HKCU proxy values are restored
  exactly, including "value absent".

Exit codes: 0 means the lab ran to completion and cleaned up (script misbehaviour is
recorded as data in recover-report.json). 1 means harness failure: the lab could not
run, or could not verify its own cleanup.
"""
from __future__ import annotations

import argparse
import base64
import ctypes as C
from contextlib import contextmanager
import hashlib
import json
import os
from pathlib import Path
import platform
import re
import secrets
import shutil
import subprocess
import sys
import time
import traceback

REPO = Path(__file__).resolve().parent.parent
SCRIPT = REPO / 'scripts' / 'windows-network-recover.ps1'
GUARD_SOURCE = REPO / 'ruleproxy' / 'windows_global_guard.py'
DNS_SOURCE = REPO / 'ruleproxy' / 'windows_global_dns.py'
LAB_ROOT = Path(r'C:\RuleProxyDiag')
FAKE_ROOT = str(LAB_ROOT / 'fake-install')        # root of the owned product guard
FOREIGN_ROOT = str(LAB_ROOT / 'foreign-install')  # negative control: different root => different keys
DNS_ROOT = str(LAB_ROOT / 'dns-identity')         # identity input for the NRPT marker and display
FOREIGN_MARKER = 'OtherVendor:diag'
PEERS = ('198.18.0.2', 'fdfe:dcba:8879::2')       # same peers as the product's global DNS rule
CONTROL_SERVER = '192.0.2.53'                     # documentation range, never a peer
PROXY_KEY = r'Software\Microsoft\Windows\CurrentVersion\Internet Settings'
DEAD_PROXY = '127.0.0.1:1'                        # nothing listens on port 1
BUDGET_SECONDS = 720                              # workflow step is 18 min; cleanup needs the rest
CHILD_TIMEOUT = 240
CLEANUP_TIMEOUT = 90
RESULT_CAP = 20000
NOTICE_CAP = 3000
NOTICE_PREFIX = '::notice title=recover-lab::'
REPORT_PATH = None  # set by main(); every finished step is persisted so a kill still leaves evidence
NRPT_NAME = re.compile(r'\{?[0-9a-fA-F-]{8,40}\}?\Z')
NRPT_NAMESPACE = re.compile(r'rp-(?:diag|ctl)-[0-9a-f]{8}\.invalid\Z')

# Windows PowerShell 5.1 snippets. Each prints one JSON document. Placeholders are
# replaced by fill(); every value is validated before it is interpolated.
VERSION_PS = """
$ErrorActionPreference = 'Stop'
$os = Get-CimInstance -ClassName Win32_OperatingSystem
ConvertTo-Json -InputObject ([ordered]@{ powershell = $PSVersionTable.PSVersion.ToString(); edition = [string]$PSVersionTable.PSEdition; caption = [string]$os.Caption; build = [string]$os.BuildNumber; version = [string]$os.Version; is64bit_process = [Environment]::Is64BitProcess }) -Compress
"""
CREATE_NRPT_PS = """
$ErrorActionPreference = 'Stop'
Add-DnsClientNrptRule -Namespace '@NS@' -NameServers @('@P0@','@P1@') -DisplayName '@DISPLAY@' -Comment '@COMMENT@' | Out-Null
Add-DnsClientNrptRule -Namespace '@CTL@' -NameServers @('@CTLSERVER@') -DisplayName 'diag control' | Out-Null
$names = @(Get-DnsClientNrptRule | Where-Object { (@($_.Namespace) -contains '@NS@') -or (@($_.Namespace) -contains '@CTL@') } | ForEach-Object { [string]$_.Name })
ConvertTo-Json -InputObject ([ordered]@{ names = $names }) -Compress
"""
QUERY_NRPT_PS = """
$ErrorActionPreference = 'Stop'
$rules = @(Get-DnsClientNrptRule | Where-Object { (@($_.Namespace) -contains '@NS@') -or (@($_.Namespace) -contains '@CTL@') })
$rows = @()
foreach ($rule in $rules) {
    $row = [ordered]@{}
    foreach ($prop in $rule.PSObject.Properties) {
        $value = $null
        try { $value = $prop.Value } catch { $value = '<unreadable>' }
        if ($value -is [array]) { $row[$prop.Name] = (@($value | ForEach-Object { [string]$_ })) -join ' | ' } else { $row[$prop.Name] = [string]$value }
    }
    $rows += [pscustomobject]$row
}
$listing = ($rules | Format-List * | Out-String -Width 300)
ConvertTo-Json -InputObject ([ordered]@{ rules = @($rows); format_list = $listing }) -Depth 4 -Compress
"""
REMOVE_NRPT_PS = """
$ErrorActionPreference = 'Stop'
$names = @(@NAMES@)
$targets = @(Get-DnsClientNrptRule | Where-Object { ((@($_.Namespace) -contains '@NS@') -or (@($_.Namespace) -contains '@CTL@')) -or ([string]$_.Name -in $names) })
$removed = @()
foreach ($target in $targets) { Remove-DnsClientNrptRule -Name ([string]$target.Name) -Force; $removed += [string]$target.Name }
$left = @(Get-DnsClientNrptRule | Where-Object { ((@($_.Namespace) -contains '@NS@') -or (@($_.Namespace) -contains '@CTL@')) -or ([string]$_.Name -in $names) })
ConvertTo-Json -InputObject ([ordered]@{ removed = @($removed); left = $left.Count }) -Compress
"""


def text(data):
    return (data or b'').decode('utf-8', errors='replace')


def sha256_file(path):
    digest = hashlib.sha256()
    with Path(path).open('rb') as stream:
        for block in iter(lambda: stream.read(1024 * 1024), b''):
            digest.update(block)
    return digest.hexdigest()


def windows_powershell():
    # Upstream contract: 64-bit Windows PowerShell 5.1 only. Never pwsh.
    root = os.environ.get('SystemRoot', r'C:\Windows')
    return str(Path(root) / 'System32' / 'WindowsPowerShell' / 'v1.0' / 'powershell.exe')


def fill(template, **values):
    out = template
    for key, value in values.items():
        out = out.replace('@' + key + '@', value)
    return out


def parse_json(raw):
    """Return (document, parsed_ok). Anything that is not one JSON document is data, not a crash."""
    try:
        return json.loads(raw.strip().lstrip('\ufeff')), True
    except ValueError:
        return None, False


def doc_of(run):
    doc = run.get('doc')
    return doc if isinstance(doc, dict) else {}


def run_blockers(run):
    blockers = doc_of(run).get('blockers')
    return [str(item) for item in blockers] if isinstance(blockers, list) else []


def run_changed(run):
    changed = doc_of(run).get('changed')
    return [str(item) for item in changed] if isinstance(changed, list) else []


def run_notes(run):
    notes = doc_of(run).get('notes')
    return [str(item) for item in notes] if isinstance(notes, list) else []


def run_parsed(run):
    return run.get('json_parsed') is True and run.get('json_exit_matches_process') is True


class Budget:
    """Bounds every child process so the job cannot hang; cleanup uses its own caps."""

    def __init__(self, seconds):
        self.deadline = time.monotonic() + seconds

    def left(self):
        return self.deadline - time.monotonic()

    def cap(self, seconds):
        return max(5.0, min(float(seconds), self.left()))


def run_child(argv, timeout):
    """One bounded child process. Timeouts and launch failures become recorded data."""
    started = time.monotonic()
    entry = {'program': Path(argv[0]).name, 'timeout_s': round(timeout, 1)}
    out, err = '', ''
    try:
        done = subprocess.run(argv, capture_output=True, timeout=timeout, check=False)
        entry.update(exit_code=done.returncode, timed_out=False)
        out, err = text(done.stdout), text(done.stderr)
    except subprocess.TimeoutExpired as exc:
        entry.update(exit_code=None, timed_out=True)
        out, err = text(exc.stdout), text(exc.stderr)
    except OSError as exc:
        entry.update(exit_code=None, timed_out=False, error=f'{type(exc).__name__}: {exc}'[:500])
    entry['seconds'] = round(time.monotonic() - started, 2)
    return entry, out, err


def ps_json(script, timeout):
    """Run a short Windows PowerShell 5.1 snippet that must print exactly one JSON document."""
    encoded = base64.b64encode(script.encode('utf-16-le')).decode('ascii')
    argv = [windows_powershell(), '-NoLogo', '-NoProfile', '-NonInteractive', '-ExecutionPolicy', 'Bypass',
            '-EncodedCommand', encoded]
    entry, out, err = run_child(argv, timeout)
    entry['value'], entry['parse_ok'] = parse_json(out)
    entry['stdout_tail'] = out[-3000:]
    entry['stderr_tail'] = err[-1500:]
    return entry


def run_recover(label, budget, *, apply=False, reset_dead_proxy=False):
    """Run the upstream script exactly as an operator would, 5.1 with -Json."""
    argv = [windows_powershell(), '-NoLogo', '-NoProfile', '-NonInteractive', '-ExecutionPolicy', 'Bypass',
            '-File', str(SCRIPT)]
    if apply:
        argv.append('-Apply')
    if reset_dead_proxy:
        argv.append('-ResetDeadLoopbackProxy')
    argv.append('-Json')
    entry, out, err = run_child(argv, budget.cap(CHILD_TIMEOUT))
    doc, parsed = parse_json(out)
    run = {'label': label, 'mode': 'apply' if apply else 'dry-run', 'reset_dead_proxy': reset_dead_proxy,
           'flags': ' '.join(argv[argv.index('-File') + 2:]), 'process': entry,
           'exit_code': entry.get('exit_code'), 'json_parsed': parsed,
           'doc': doc if isinstance(doc, dict) else None,
           'stdout_tail': out[-3000:], 'stderr_tail': err[-1500:]}
    if isinstance(doc, dict):
        run['json_exit_matches_process'] = doc.get('exit_code') == entry.get('exit_code')
    return run


def read_result_json(log_directory):
    """The script writes result.json under log_directory on -Apply. Copy it, capped."""
    if not log_directory:
        return {'present': False, 'reason': 'no log_directory in -Json output'}
    path = Path(str(log_directory)) / 'result.json'
    try:
        raw = path.read_bytes()[:2 * 1024 * 1024]
    except OSError as exc:
        return {'present': False, 'path': str(path), 'error': f'{type(exc).__name__}: {exc}'[:300]}
    body = raw.decode('utf-8-sig', errors='replace')
    parsed, ok = parse_json(body)
    return {'present': True, 'path': str(path), 'bytes': len(raw), 'parsed_ok': ok,
            'parsed': parsed if isinstance(parsed, dict) else None,
            'parsed_exit_code': parsed.get('exit_code') if isinstance(parsed, dict) else None,
            'text': body[:RESULT_CAP], 'truncated': len(body) > RESULT_CAP}


def windows_summary():
    info = sys.getwindowsversion()
    return {'major': info.major, 'minor': info.minor, 'build': info.build,
            'product_type': info.product_type, 'platform_version': platform.version()}


def persist(report):
    """Write the report now. A later hang or kill still leaves the steps completed so far."""
    if REPORT_PATH is None:
        return
    try:
        Path(REPORT_PATH).write_text(json.dumps(report, ensure_ascii=False, indent=2, default=str), encoding='utf-8')
    except OSError:
        pass  # the final write in main() reports the failure through the exit code


@contextmanager
def step(report, name):
    """Record {name, ok, details}. The body sets entry['ok'] and entry['details'].

    An exception in the body is data (for example a BFE HRESULT), so it is recorded and the
    lab continues to the next step and to cleanup.
    """
    entry = {'name': name, 'ok': False, 'details': {}}
    report['steps'].append(entry)
    try:
        yield entry
    except Exception as exc:
        entry['ok'] = False
        entry['details']['exception'] = f'{type(exc).__name__}: {exc}'[:1500]
        entry['details']['traceback_tail'] = traceback.format_exc()[-2500:]
    finally:
        persist(report)


def require(condition, message):
    if not condition:
        raise RuntimeError(message)


def load_product():
    """Import the product's own guard. Nothing in the import path touches WFP or the registry."""
    sys.path.insert(0, str(REPO))
    from ruleproxy import windows_global_guard as guard_module
    from ruleproxy.windows_proxy_client import current_user_sid
    return guard_module, current_user_sid


def permit_rules(g):
    """One PERMIT rule per product rule name, with no conditions. No deny action is ever built."""
    rules = tuple(g._Rule(name, family, g._PERMIT, 0, ()) for family, name in g._ALL_RULES)
    require(rules and all(rule.action == g._PERMIT for rule in rules), 'refusing a non-PERMIT rule set')
    return rules


def new_guard(g, owner_sid, root, marker=None):
    guard = g.Guard({'root': root, 'owner_sid': owner_sid})
    if marker is not None:
        guard.marker = marker  # foreign negative control: a marker the script must not treat as ours
    return guard


def create_objects(g, guard, rules):
    with g._Engine() as engine:
        with engine.transaction():
            guard._replace(engine, rules)


def enumerate_guard(g, guard):
    """The product's own identity-checked lookup, by exact derived key (not by marker text)."""
    with g._Engine() as engine:
        filters = guard._filters(engine)
        provider = guard._owned_provider(engine)
        sublayer = guard._owned_sublayer(engine)
    return {'filter_keys': sorted(f'{family}/{name}' for family, name in filters),
            'filter_count': len(filters), 'provider_present': bool(provider),
            'sublayer_present': bool(sublayer), 'provider_key': str(guard.provider),
            'sublayer_key': str(guard.sublayer)}


def raw_snapshot(g, guard):
    """Identity-agnostic read by exact derived key: what is stored, without the product's ownership verdict.
    The first CI run used the product's identity-checked lookup for the foreign control and it raised a
    sublayer identity conflict; this reader never raises on identity and keeps the raw fields as evidence."""
    out = {'provider': None, 'sublayer': None, 'filters': {}}
    with g._Engine() as engine:
        with engine.get('Provider', guard.provider, g._Provider) as value:
            if value is not None:
                out['provider'] = {'description': value.display.description, 'flags': int(value.flags),
                                   'service': value.service}
        with engine.get('SubLayer', guard.sublayer, g._Sublayer) as value:
            if value is not None:
                out['sublayer'] = {'description': value.display.description, 'flags': int(value.flags),
                                   'weight': int(value.weight),
                                   'provider': value.provider.contents.text() if value.provider else None}
        for family, name in g._ALL_RULES:
            with engine.get('Filter', guard._rule_key(family, name), g._Filter) as value:
                if value is not None:
                    out['filters'][f'{family}/{name}'] = {'description': value.display.description,
                                                          'flags': int(value.flags)}
    out['filter_count'] = len(out['filters'])
    out['provider_present'] = out['provider'] is not None
    out['sublayer_present'] = out['sublayer'] is not None
    out['provider_key'], out['sublayer_key'] = str(guard.provider), str(guard.sublayer)
    return out


def remove_raw_objects(g, guard, label):
    """Delete a guard's objects by exact derived key in ONE transaction, filters first, then sublayer, then
    provider (a provider or sublayer that still has children is refused with FWP_E_IN_USE 0x8032000a).
    Used for the foreign control, whose marker the product's own identity check rejects."""
    out = {'label': label, 'method': 'raw exact-key delete in one transaction'}
    try:
        with g._Engine() as engine:
            for kind in ('SubLayer', 'Provider'):
                function = getattr(engine.api, 'Fwpm' + kind + 'DeleteByKey0')
                function.argtypes, function.restype = [g._P, C.POINTER(g._GUID)], g._U32
            deleted = 0
            with engine.transaction():
                for family, name in g._ALL_RULES:
                    code = engine.api.FwpmFilterDeleteByKey0(engine.handle,
                                                             C.byref(g._GUID.of(guard._rule_key(family, name))))
                    if code == 0:
                        deleted += 1
                    elif code != g._NOT_FOUND['Filter']:
                        raise RuntimeError(f'FwpmFilterDeleteByKey0 0x{code:08x}')
                for kind, key in (('SubLayer', guard.sublayer), ('Provider', guard.provider)):
                    code = getattr(engine.api, 'Fwpm' + kind + 'DeleteByKey0')(engine.handle,
                                                                                C.byref(g._GUID.of(key)))
                    if code not in (0, g._NOT_FOUND[kind]):
                        raise RuntimeError(f'Fwpm{kind}DeleteByKey0 0x{code:08x}')
            out['filters_deleted'] = deleted
    except Exception as exc:
        out['error'] = f'{type(exc).__name__}: {exc}'[:500]
    try:
        out['after'] = raw_snapshot(g, guard)
    except Exception as exc:
        out['after_error'] = f'{type(exc).__name__}: {exc}'[:500]
    return out


def is_absent(enum):
    return (isinstance(enum, dict) and enum.get('filter_count') == 0
            and enum.get('provider_present') is False and enum.get('sublayer_present') is False)


def foreign_present(enum, rule_count):
    return (isinstance(enum, dict) and enum.get('filter_count') == rule_count
            and enum.get('provider_present') is True and enum.get('sublayer_present') is True)


def compact_status(status):
    keys = ('supported', 'active', 'persistent', 'code', 'detail', 'rule_count', 'state', 'native_qualified')
    return {key: status[key] for key in keys if key in status}


def status_unpatched(guard):
    return compact_status(guard.status())


def status_with_expected_rules(g, guard, rules):
    """guard.status() compares the live set with the full product plan (which includes a deny
    rule), so a PERMIT-only set can only be judged by substituting our expected rule list for
    _plan. The substitution exists only in this lab process, is restored in finally, and is
    recorded as a method in the report."""
    saved = g._plan
    g._plan = lambda *_args, **_kwargs: rules
    try:
        return compact_status(guard.status())
    finally:
        g._plan = saved


def ensure_core_file():
    """status() needs a file at <root>/bin/windows-amd64/mihomo.exe for the app identity.
    A copy of cmd.exe is used; it is only read, never executed."""
    core = Path(FAKE_ROOT) / 'bin' / 'windows-amd64' / 'mihomo.exe'
    core.parent.mkdir(parents=True, exist_ok=True)
    shutil.copyfile(Path(os.environ.get('SystemRoot', r'C:\Windows')) / 'System32' / 'cmd.exe', core)
    return core


def delete_container(g, guard, kind):
    """Delete this guard's own sublayer or provider by exact key. Identity is re-checked first."""
    with g._Engine() as engine:
        present = guard._owned_sublayer(engine) if kind == 'SubLayer' else guard._owned_provider(engine)
        if not present:
            return 'absent'
        key = guard.sublayer if kind == 'SubLayer' else guard.provider
        function = getattr(engine.api, 'Fwpm' + kind + 'DeleteByKey0')
        function.argtypes, function.restype = [g._P, C.POINTER(g._GUID)], g._U32
        with engine.transaction():
            code = function(engine.handle, C.byref(g._GUID.of(key)))
            if code:
                raise RuntimeError(f'Fwpm{kind}DeleteByKey0 0x{code:08x}')
        return 'deleted'


def delete_remaining_filters(g, guard):
    """Exact-key removal of any filter still carrying this guard's identity. _filters() re-checks identity."""
    with g._Engine() as engine:
        remaining = guard._filters(engine)
        if not remaining:
            return 0
        if not (guard._owned_provider(engine) and guard._owned_sublayer(engine)):
            raise RuntimeError('filters present but owned containers cannot be verified; nothing deleted')
        with engine.transaction():
            for family, name in remaining:
                code = engine.api.FwpmFilterDeleteByKey0(engine.handle,
                                                         C.byref(g._GUID.of(guard._rule_key(family, name))))
                if code:
                    raise RuntimeError(f'FwpmFilterDeleteByKey0 0x{code:08x}')
        return len(remaining)


def remove_guard_objects(g, guard, label):
    """Product's normal_stop for filters, exact-key filter fallback, then manual sublayer and provider removal."""
    out = {'label': label}
    try:
        out['normal_stop'] = compact_status(guard.normal_stop())
    except Exception as exc:
        out['normal_stop_error'] = f'{type(exc).__name__}: {exc}'[:500]
    try:
        out['filters_deleted_by_key'] = delete_remaining_filters(g, guard)
    except Exception as exc:
        out['filters_error'] = f'{type(exc).__name__}: {exc}'[:500]
    for kind in ('SubLayer', 'Provider'):
        try:
            out[kind.lower() + '_delete'] = delete_container(g, guard, kind)
        except Exception as exc:
            out[kind.lower() + '_error'] = f'{type(exc).__name__}: {exc}'[:500]
    try:
        out['after'] = enumerate_guard(g, guard)
    except Exception as exc:
        out['after_error'] = f'{type(exc).__name__}: {exc}'[:500]
    return out


# Windows HKCU proxy values and WinINet flags. Writes use winreg and WinINet directly.
class _ConnOptionValue(C.Union):
    _fields_ = [('dwValue', C.c_uint32), ('pszValue', C.c_void_p), ('ftValue', C.c_uint64)]


class _ConnOption(C.Structure):
    _fields_ = [('dwOption', C.c_uint32), ('value', _ConnOptionValue)]


class _ConnOptionList(C.Structure):
    _fields_ = [('dwSize', C.c_uint32), ('pszConnection', C.c_void_p), ('dwOptionCount', C.c_uint32),
                ('dwOptionError', C.c_uint32), ('pOptions', C.POINTER(_ConnOption))]


def wininet_notify():
    wininet = C.WinDLL('wininet.dll', use_last_error=True)
    for option_id in (39, 37):  # SETTINGS_CHANGED, REFRESH
        if not wininet.InternetSetOptionW(None, option_id, None, 0):
            raise C.WinError(C.get_last_error())


def wininet_flags_get():
    wininet = C.WinDLL('wininet.dll', use_last_error=True)
    option = _ConnOption()
    option.dwOption = 1  # INTERNET_PER_CONN_FLAGS
    options = _ConnOptionList()
    options.dwSize, options.dwOptionCount, options.pOptions = C.sizeof(_ConnOptionList), 1, C.pointer(option)
    size = C.c_uint32(C.sizeof(_ConnOptionList))
    if not wininet.InternetQueryOptionW(None, 75, C.byref(options), C.byref(size)):
        raise C.WinError(C.get_last_error())
    return int(option.value.dwValue)


def wininet_flags_set(value):
    wininet = C.WinDLL('wininet.dll', use_last_error=True)
    option = _ConnOption()
    option.dwOption, option.value.dwValue = 1, value
    options = _ConnOptionList()
    options.dwSize, options.dwOptionCount, options.pOptions = C.sizeof(_ConnOptionList), 1, C.pointer(option)
    if not wininet.InternetSetOptionW(None, 75, C.byref(options), C.sizeof(_ConnOptionList)):
        raise C.WinError(C.get_last_error())
    wininet_notify()


def proxy_read():
    import winreg
    values = {}
    with winreg.OpenKey(winreg.HKEY_CURRENT_USER, PROXY_KEY, 0, winreg.KEY_QUERY_VALUE) as key:
        for name in ('ProxyEnable', 'ProxyServer'):
            try:
                value, kind = winreg.QueryValueEx(key, name)
                values[name] = [value, kind]
            except FileNotFoundError:
                values[name] = None  # absent is a state, distinct from any value
    return values


def proxy_write(values):
    import winreg
    with winreg.OpenKey(winreg.HKEY_CURRENT_USER, PROXY_KEY, 0,
                        winreg.KEY_SET_VALUE | winreg.KEY_QUERY_VALUE) as key:
        for name, item in values.items():
            if item is None:
                try:
                    winreg.DeleteValue(key, name)
                except FileNotFoundError:
                    pass
            else:
                winreg.SetValueEx(key, name, 0, item[1], item[0])


def restore_proxy(snapshot):
    """Flags first (WinINet may rewrite the legacy values), then the exact registry state."""
    flags_error = None
    try:
        wininet_flags_set(snapshot['flags'])
    except OSError as exc:
        flags_error = f'{type(exc).__name__}: {exc}'[:300]
    proxy_write(snapshot['values'])
    wininet_notify()
    values_now = proxy_read()
    return {'values_exact': values_now == snapshot['values'], 'values_now': values_now,
            'flags_original': snapshot['flags'], 'flags_now': wininet_flags_get(), 'flags_error': flags_error}


def nrpt_query(ns, ctl, budget):
    """Rows for our two namespaces only, plus the Format-List listing for the report."""
    result = ps_json(fill(QUERY_NRPT_PS, NS=ns, CTL=ctl), budget.cap(CLEANUP_TIMEOUT))
    value = result.get('value') if isinstance(result.get('value'), dict) else {}
    rows = value.get('rules') if isinstance(value.get('rules'), list) else []
    return {'rows': rows, 'format_list': str(value.get('format_list', ''))[:6000],
            'parse_ok': result.get('parse_ok') is True, 'exit_code': result.get('exit_code')}


def row_for(rows, namespace):
    for row in rows:
        if isinstance(row, dict) and namespace in str(row.get('Namespace', '')):
            return row
    return None


def run_steps(report, work, budget, ctx):
    g, owner_sid, facts = ctx['g'], ctx['owner_sid'], report['facts']

    with step(report, 'S0-environment') as entry:
        probe = ps_json(VERSION_PS, budget.cap(90))
        value = probe.get('value') if isinstance(probe.get('value'), dict) else {}
        report['versions'] = {'windows': windows_summary(), 'python': sys.version.split()[0], 'powershell': value}
        entry['details'] = {'probe_exit_code': probe.get('exit_code'), 'value': value}
        entry['ok'] = probe.get('exit_code') == 0 and str(value.get('powershell', '')).startswith('5.1')

    with step(report, 'S0-dry-run-baseline') as entry:
        run = run_recover('S0', budget)
        report['runs']['S0'] = run
        blockers = run_blockers(run)
        residue = [b for b in blockers if any(token in b for token in ('WFP', 'DNS', 'RuleProxy', 'TUN'))]
        entry['details'] = {'exit_code': run['exit_code'], 'blockers': blockers, 'rule_proxy_residue': residue,
                            'changed': run_changed(run), 'notes': doc_of(run).get('notes')}
        entry['ok'] = run_parsed(run) and run['exit_code'] in (0, 1) and not residue

    with step(report, 'S1-create-owned-product-objects') as entry:
        rules = permit_rules(g)
        ctx['rules'] = rules
        owned = new_guard(g, owner_sid, FAKE_ROOT)
        ctx['owned'] = owned  # set before any WFP call so cleanup always runs
        core = ensure_core_file()
        create_objects(g, owned, rules)
        enum = enumerate_guard(g, owned)
        facts['owned_after_create'] = enum
        entry['details'] = {'rule_count': len(rules), 'enumeration': enum, 'core_copy': str(core),
                            'marker_prefix': owned.marker[:20] + '...'}
        entry['ok'] = enum['filter_count'] == len(rules) and enum['provider_present'] and enum['sublayer_present']

    with step(report, 'S2-product-status') as entry:
        require(ctx.get('owned') is not None, 'S1 did not create the owned guard; S2 skipped')
        owned, rules = ctx['owned'], ctx['rules']
        unpatched = status_unpatched(owned)
        substituted = status_with_expected_rules(g, owned, rules)
        entry['details'] = {'status_unpatched': unpatched, 'status_with_expected_rules': substituted,
                            'method': 'status() with g._plan replaced by the PERMIT rule list (lab process only)'}
        entry['ok'] = substituted.get('active') is True and substituted.get('persistent') is True

    with step(report, 'S6-foreign-negative-control-create') as entry:
        require(rules, 'no rules; negative control skipped')
        foreign = new_guard(g, owner_sid, FOREIGN_ROOT, marker=FOREIGN_MARKER)
        ctx['foreign'] = foreign
        create_objects(g, foreign, rules)
        enum = raw_snapshot(g, foreign)
        facts['foreign_before'] = enum
        facts['rule_count'] = len(rules)
        entry['details'] = {'marker': FOREIGN_MARKER, 'root': FOREIGN_ROOT, 'enumeration': enum}
        entry['ok'] = foreign_present(enum, len(rules))

    with step(report, 'S3-dry-run-expect-findings') as entry:
        require(ctx.get('owned') is not None, 'owned guard missing; S3 skipped')
        run = run_recover('S3', budget)
        report['runs']['S3'] = run
        blockers = run_blockers(run)
        expected = f'Owned WFP filters: {len(rules)}'
        enum = enumerate_guard(g, ctx['owned'])
        entry['details'] = {'exit_code': run['exit_code'], 'expected_blocker': expected, 'blockers': blockers,
                            'changed': run_changed(run), 'enumeration_after_dry_run': enum}
        entry['ok'] = (run_parsed(run) and run['exit_code'] == 1 and expected in blockers
                       and not run_changed(run) and enum == facts.get('owned_after_create'))

    with step(report, 'S4-apply') as entry:
        run = run_recover('S4', budget, apply=True)
        report['runs']['S4'] = run
        result = read_result_json(doc_of(run).get('log_directory'))
        entry['details'] = {'exit_code': run['exit_code'], 'changed': run_changed(run),
                            'notes': doc_of(run).get('notes'), 'blockers': run_blockers(run),
                            'error': doc_of(run).get('error'), 'log_directory': doc_of(run).get('log_directory'),
                            'result_json': result}
        entry['ok'] = (run_parsed(run) and run['exit_code'] == 0 and result.get('parsed_exit_code') == 0)

    with step(report, 'S4-verify-product-objects-gone') as entry:
        require(ctx.get('owned') is not None, 'owned guard missing; S4 verification skipped')
        enum = enumerate_guard(g, ctx['owned'])
        status = status_unpatched(ctx['owned'])
        facts['owned_after_s4'] = enum
        entry['details'] = {'enumeration': enum, 'status_unpatched': status}
        entry['ok'] = is_absent(enum) and status.get('active') is False

    with step(report, 'S4-verify-foreign-intact') as entry:
        require(ctx.get('foreign') is not None, 'foreign guard missing; check skipped')
        enum = raw_snapshot(g, ctx['foreign'])
        facts['foreign_after_s4'] = enum
        entry['details'] = {'enumeration': enum, 'equal_to_before': enum == facts.get('foreign_before')}
        entry['ok'] = enum == facts.get('foreign_before') and foreign_present(enum, len(rules))

    with step(report, 'S5-second-apply-idempotent') as entry:
        run = run_recover('S5', budget, apply=True)
        report['runs']['S5'] = run
        enum = enumerate_guard(g, ctx['owned'])
        unchanged = enum == facts.get('owned_after_s4')
        facts['s5_unchanged'] = unchanged
        entry['details'] = {'exit_code': run['exit_code'], 'changed': run_changed(run),
                            'notes': doc_of(run).get('notes'), 'blockers': run_blockers(run),
                            'enumeration_unchanged_from_s4': unchanged}
        entry['ok'] = run_parsed(run) and run['exit_code'] == 0 and unchanged

    with step(report, 'S6-foreign-survived-second-apply') as entry:
        enum = raw_snapshot(g, ctx['foreign'])
        facts['foreign_after_s5'] = enum
        needles = [str(ctx['foreign'].provider).lower(), str(ctx['foreign'].sublayer).lower()]
        mentions = []
        for name in ('S3', 'S4', 'S5'):
            run = report['runs'].get(name, {})
            for line in run_changed(run) + run_notes(run) + run_blockers(run):
                if any(needle in line.lower() for needle in needles):
                    mentions.append(name + ': ' + line[:300])
        facts['foreign_mentions'] = mentions
        entry['details'] = {'enumeration': enum, 'equal_to_before': enum == facts.get('foreign_before'),
                            'script_lines_mentioning_foreign_keys': mentions}
        entry['ok'] = enum == facts.get('foreign_before') and foreign_present(enum, len(rules)) and not mentions

    with step(report, 'S7-nrpt-create') as entry:
        dns_identity = hashlib.sha256((owner_sid + '\0' + DNS_ROOT.casefold()).encode()).hexdigest()
        display = 'RuleProxy global DNS ' + dns_identity[:16]
        comment = 'RuleProxyDNS-v1:' + dns_identity
        ns = 'rp-diag-' + secrets.token_hex(4) + '.invalid'
        ctl = 'rp-ctl-' + secrets.token_hex(4) + '.invalid'
        require(NRPT_NAMESPACE.match(ns) and NRPT_NAMESPACE.match(ctl), 'bad lab namespace')
        ctx['nrpt_namespaces'] = [ns, ctl]  # recorded before the call so cleanup removes partial creates
        created = ps_json(fill(CREATE_NRPT_PS, NS=ns, CTL=ctl, P0=PEERS[0], P1=PEERS[1],
                               CTLSERVER=CONTROL_SERVER, DISPLAY=display, COMMENT=comment), budget.cap(CLEANUP_TIMEOUT))
        names = created.get('value', {}).get('names') if isinstance(created.get('value'), dict) else None
        names = [str(n) for n in names] if isinstance(names, list) else []
        require(all(NRPT_NAME.match(n) for n in names), 'unexpected NRPT name shape')
        ctx['nrpt_names'] = names
        ctx['nrpt_expect'] = {'display': display, 'comment': comment}
        entry['details'] = {'namespace': ns, 'control_namespace': ctl, 'display_name': display,
                            'comment_prefix': 'RuleProxyDNS-v1:', 'names': names, 'create_exit': created.get('exit_code'),
                            'stderr_tail': created.get('stderr_tail')}
        entry['ok'] = created.get('exit_code') == 0 and len(names) == 2

    with step(report, 'S7-nrpt-properties') as entry:
        query = nrpt_query(ctx['nrpt_namespaces'][0], ctx['nrpt_namespaces'][1], budget)
        rp_row = row_for(query['rows'], ctx['nrpt_namespaces'][0])
        ctl_row = row_for(query['rows'], ctx['nrpt_namespaces'][1])
        entry['details'] = {'rp_diag_rule_properties': rp_row, 'control_rule_properties': ctl_row,
                            'format_list': query['format_list']}
        expect = ctx.get('nrpt_expect', {})
        entry['ok'] = (rp_row is not None and ctl_row is not None
                       and rp_row.get('Namespace') == ctx['nrpt_namespaces'][0]
                       and rp_row.get('Comment') == expect.get('comment')
                       and rp_row.get('DisplayName') == expect.get('display')
                       and all(peer in str(rp_row.get('NameServers', '')) for peer in PEERS))

    with step(report, 'S7-dry-run') as entry:
        run = run_recover('S7-dry', budget)
        report['runs']['S7-dry'] = run
        blockers = run_blockers(run)
        dns_blockers = [b for b in blockers if 'DNS' in b]
        facts['nrpt_dns_residue_reported'] = bool(dns_blockers)
        entry['details'] = {'exit_code': run['exit_code'], 'blockers': blockers,
                            'note': 'the script only treats the root namespace as a candidate; the rp-diag rule is reported as residue'}
        entry['ok'] = run_parsed(run) and run['exit_code'] == 1 and bool(dns_blockers)

    with step(report, 'S7-apply') as entry:
        run = run_recover('S7-apply', budget, apply=True)
        report['runs']['S7-apply'] = run
        query = nrpt_query(ctx['nrpt_namespaces'][0], ctx['nrpt_namespaces'][1], budget)
        rp_present = row_for(query['rows'], ctx['nrpt_namespaces'][0]) is not None
        ctl_present = row_for(query['rows'], ctx['nrpt_namespaces'][1]) is not None
        facts.update({'nrpt_control_untouched': ctl_present, 'nrpt_rp_diag_removed': not rp_present})
        entry['details'] = {'exit_code': run['exit_code'], 'changed': run_changed(run),
                            'blockers': run_blockers(run), 'error': doc_of(run).get('error'),
                            'rp_diag_rule_still_present': rp_present, 'control_still_present': ctl_present,
                            'expectation_mismatch': ('dry-run lists the rp-diag rule as residue but -Apply does not '
                                                     'remove it: the script removes only root-namespace candidates')
                            if rp_present else None}
        entry['ok'] = ctl_present and rp_present  # consistent with the script's own predicate

    with step(report, 'S7-remove-lab-nrpt') as entry:
        removed = ps_json(fill(REMOVE_NRPT_PS, NS=ctx['nrpt_namespaces'][0], CTL=ctx['nrpt_namespaces'][1],
                               NAMES=','.join("'" + n + "'" for n in ctx.get('nrpt_names', []))),
                          budget.cap(CLEANUP_TIMEOUT))
        value = removed.get('value') if isinstance(removed.get('value'), dict) else {}
        ctx['nrpt_removed_explicitly'] = True
        entry['details'] = {'removed': value.get('removed'), 'left': value.get('left')}
        entry['ok'] = value.get('left') == 0

    with step(report, 'S8-dead-proxy-setup-and-dry-run') as entry:
        import winreg
        original_values = proxy_read()
        original_flags = wininet_flags_get()
        ctx['proxy_snapshot'] = {'values': original_values, 'flags': original_flags}  # before any write
        proxy_write({'ProxyEnable': [1, winreg.REG_DWORD], 'ProxyServer': [DEAD_PROXY, winreg.REG_SZ]})
        wininet_flags_set(3)  # PROXY|DIRECT: the script only inspects a manual proxy when bit 2 is set
        flags_now = wininet_flags_get()
        run = run_recover('S8-dry', budget, reset_dead_proxy=True)
        report['runs']['S8-dry'] = run
        blockers = run_blockers(run)
        entry['details'] = {'original_values': original_values, 'original_flags': original_flags,
                            'flags_after_setup': flags_now, 'exit_code': run['exit_code'], 'blockers': blockers,
                            'registry_after_dry_run': proxy_read()}
        entry['ok'] = (flags_now == 3 and any('Dead loopback' in b for b in blockers)
                       and proxy_read()['ProxyEnable'] == [1, winreg.REG_DWORD])

    with step(report, 'S8-apply-reset-dead-proxy') as entry:
        import winreg
        run = run_recover('S8', budget, apply=True, reset_dead_proxy=True)
        report['runs']['S8'] = run
        values = proxy_read()
        flags_after = wininet_flags_get()
        enable_zero = values['ProxyEnable'] == [0, winreg.REG_DWORD]
        server_same = values['ProxyServer'] == [DEAD_PROXY, winreg.REG_SZ]
        facts.update({'proxy_apply_exit': run['exit_code'], 'proxy_enable_after': values['ProxyEnable'],
                      'proxy_server_after': values['ProxyServer'], 'proxy_flags_after': flags_after,
                      'proxy_ok_behaviour': run['exit_code'] == 0 and enable_zero and server_same})
        entry['details'] = {'exit_code': run['exit_code'], 'changed': run_changed(run), 'blockers': run_blockers(run),
                            'error': doc_of(run).get('error'), 'values_after': values, 'flags_after': flags_after,
                            'proxy_enable_became_zero': enable_zero, 'proxy_server_untouched': server_same}
        entry['ok'] = facts['proxy_ok_behaviour'] is True


def run_cleanup(report, ctx):
    """Runs in finally. Everything the lab created is removed and then verified absent."""
    cleanup, g, errors = report['cleanup'], ctx['g'], []
    snapshot = ctx.get('proxy_snapshot')
    if snapshot is not None:
        try:
            cleanup['proxy'] = restore_proxy(snapshot)
        except Exception as exc:
            errors.append('proxy restore: ' + f'{type(exc).__name__}: {exc}'[:300])
    if ctx.get('nrpt_namespaces'):
        try:
            names = ctx.get('nrpt_names', [])
            removal = ps_json(fill(REMOVE_NRPT_PS, NS=ctx['nrpt_namespaces'][0], CTL=ctx['nrpt_namespaces'][1],
                                   NAMES=','.join("'" + n + "'" for n in names)), CLEANUP_TIMEOUT)
            value = removal.get('value') if isinstance(removal.get('value'), dict) else {}
            cleanup['nrpt'] = {'removed': value.get('removed'), 'left': value.get('left')}
        except Exception as exc:
            errors.append('nrpt: ' + f'{type(exc).__name__}: {exc}'[:300])
    for label, guard in (('foreign', ctx.get('foreign')), ('owned', ctx.get('owned'))):
        if guard is None:
            continue
        try:
            cleanup[label] = (remove_raw_objects(g, guard, label) if label == 'foreign'
                              else remove_guard_objects(g, guard, label))
        except Exception as exc:
            errors.append(label + ': ' + f'{type(exc).__name__}: {exc}'[:300])
    shutil.rmtree(LAB_ROOT, ignore_errors=True)
    cleanup['lab_root_removed'] = not LAB_ROOT.exists()
    cleanup['errors'] = errors
    checks = []
    if snapshot is not None:
        checks.append(cleanup.get('proxy', {}).get('values_exact') is True)
    if ctx.get('nrpt_namespaces'):
        checks.append(cleanup.get('nrpt', {}).get('left') == 0)
    for label in ('foreign', 'owned'):
        if ctx.get(label) is not None:
            checks.append(is_absent(cleanup.get(label, {}).get('after'))
                          and not cleanup.get(label, {}).get('error'))
    cleanup['cleanup_ok'] = not errors and all(checks)


def build_verdict(report):
    facts, runs = report.get('facts', {}), report.get('runs', {})
    cleanup = report.get('cleanup', {})
    report['verdict'] = {
        'wfp_product_objects_removed': is_absent(facts.get('owned_after_s4')),
        'foreign_untouched': bool(facts.get('foreign_before') is not None
                                  and facts.get('foreign_after_s4') == facts.get('foreign_before')
                                  and facts.get('foreign_after_s5') == facts.get('foreign_before')
                                  and foreign_present(facts.get('foreign_after_s5'), facts.get('rule_count', -1))
                                  and facts.get('foreign_mentions') == []),
        'nrpt_ok': bool(facts.get('nrpt_control_untouched') is True and facts.get('nrpt_dns_residue_reported') is True),
        'nrpt_positive_removal_tested': False,
        'proxy_ok': facts.get('proxy_ok_behaviour') is True,
        'idempotent': bool(facts.get('s5_unchanged') is True and runs.get('S5', {}).get('exit_code') == 0),
        'raw_exit_codes': {label: run.get('exit_code') for label, run in runs.items()},
        'cleanup_ok': cleanup.get('cleanup_ok') is True,
        'lab_completed': report.get('lab_completed') is True,
    }


def run_lab(report, work, budget):
    g, current_user_sid = load_product()
    ctx = {'g': g, 'owner_sid': current_user_sid(), 'owned': None, 'foreign': None, 'rules': (),
           'nrpt_namespaces': [], 'nrpt_names': [], 'proxy_snapshot': None}
    try:
        run_steps(report, work, budget, ctx)
    finally:
        run_cleanup(report, ctx)


def gha_escape(message):
    return message.replace('%', '%25').replace('\r', '%0D').replace('\n', '%0A')


def emit_notices(report):
    """At most 8 ::notice lines, each <= NOTICE_CAP characters, because job logs are not readable."""
    def short(value, limit):
        return json.dumps(value, ensure_ascii=True, default=str)[:limit]
    verdict = report.get('verdict', {})
    runs = report.get('runs', {})
    facts = report.get('facts', {})
    lines = [
        'verdict ' + short({k: v for k, v in verdict.items() if k != 'raw_exit_codes'}, 1200),
        'versions ' + short(report.get('versions', {}), 800),
        'S0 ' + short({'exit': runs.get('S0', {}).get('exit_code'), 'blockers': run_blockers(runs.get('S0', {}))}, 600),
        'S2 status_unpatched=' + short(next((s['details'].get('status_unpatched') for s in report['steps']
                                              if s['name'] == 'S2-product-status'), None), 500)
        + ' status_expected_rules=' + short(next((s['details'].get('status_with_expected_rules') for s in report['steps']
                                                   if s['name'] == 'S2-product-status'), None), 500),
        'S3 exit=' + str(runs.get('S3', {}).get('exit_code')) + ' blockers=' + short(run_blockers(runs.get('S3', {})), 900),
        'S4 exit=' + str(runs.get('S4', {}).get('exit_code')) + ' changed=' + short(run_changed(runs.get('S4', {})), 500)
        + ' notes=' + short(doc_of(runs.get('S4', {})).get('notes'), 600),
        'S5 exit=' + str(runs.get('S5', {}).get('exit_code')) + ' foreign_untouched=' + str(verdict.get('foreign_untouched'))
        + ' owned_after_s4=' + short(facts.get('owned_after_s4'), 400),
        'S7 dry=' + str(runs.get('S7-dry', {}).get('exit_code')) + ' apply=' + str(runs.get('S7-apply', {}).get('exit_code'))
        + ' control_untouched=' + str(facts.get('nrpt_control_untouched')) + ' rp_diag_removed='
        + str(facts.get('nrpt_rp_diag_removed')) + ' S8 apply=' + str(runs.get('S8', {}).get('exit_code'))
        + ' proxy_ok=' + str(verdict.get('proxy_ok')) + ' cleanup_ok=' + str(verdict.get('cleanup_ok'))
        + ' harness_error=' + str(report.get('harness_error')),
    ]
    for line in lines[:8]:
        message = gha_escape(line[:NOTICE_CAP])
        print(NOTICE_PREFIX + message[:NOTICE_CAP - len(NOTICE_PREFIX)], flush=True)


def new_report(work):
    def digest(path):
        try:
            return sha256_file(path)
        except OSError as exc:
            return f'unavailable: {exc}'[:200]
    return {'schema': 'windows-diag-recover/2', 'work': str(work), 'source_commit': os.environ.get('GITHUB_SHA'),
            'hashes': {'lab_sha256': digest(Path(__file__)), 'script_sha256': digest(SCRIPT),
                       'guard_sha256': digest(GUARD_SOURCE), 'dns_sha256': digest(DNS_SOURCE)},
            'versions': {}, 'steps': [], 'runs': {}, 'facts': {}, 'cleanup': {}, 'verdict': {},
            'lab_completed': False, 'harness_error': None, 'harness_traceback': None}


def main() -> int:
    global REPORT_PATH
    parser = argparse.ArgumentParser()
    parser.add_argument('--work', type=Path, required=True)
    work = parser.parse_args().work.resolve()
    # Mirror of the guard in windows_appcontainer_compat.py: refuse anywhere but a disposable Actions runner.
    if os.name != 'nt' or os.environ.get('GITHUB_ACTIONS') != 'true':
        raise RuntimeError('requires a disposable Windows GitHub Actions runner')
    if work.exists():
        raise RuntimeError('recover work directory already exists')
    work.mkdir(parents=True)
    report = new_report(work)
    REPORT_PATH = str(work / 'recover-report.json')
    budget = Budget(BUDGET_SECONDS)
    try:
        run_lab(report, work, budget)
        report['lab_completed'] = True
    except BaseException as exc:  # the report is written even when the harness itself fails
        report['harness_error'] = f'{type(exc).__name__}: {exc}'[:1500]
        report['harness_traceback'] = traceback.format_exc()[-4000:]
    try:
        build_verdict(report)
    except Exception as exc:
        report['harness_error'] = (report.get('harness_error') or '') + f' | verdict: {exc}'[:500]
    (work / 'recover-report.json').write_text(json.dumps(report, ensure_ascii=False, indent=2, default=str),
                                              encoding='utf-8')
    emit_notices(report)
    ok = report['lab_completed'] and report.get('cleanup', {}).get('cleanup_ok') is True
    return 0 if ok else 1


if __name__ == '__main__':
    raise SystemExit(main())
