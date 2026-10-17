"""Explicit disposable-Windows experiment; never run on a user's desktop.

Uses real production WFP guard/SCM global core and a synthetic loopback SOCKS
echo node. Physical IPv4 evidence is captured at one identified NIC component,
with positive TCP/UDP controls before and after the guarded probes. IPv6 public
egress is NOT qualified by a scoped ::1 action test. No result enables strict
product protection automatically. Raw ETL/PCAP/state remain private locally.

Run from the installing desktop owner's elevated account after installing the
candidate package::
    python .github/check_windows_global_capture.py --ack-disposable-windows \
        --installed-root "C:\\Program Files\\RuleProxy-Web" --output summary.json

An independent SYSTEM scheduled recovery task is registered before any route,
WFP or TUN mutation. It stops the fixed service/core, restores only owned NRPT
and guard rules, and removes the exact test route. Every normal/failed run also
executes recovery. The hard recovery deadline is 180 seconds.
"""
from __future__ import annotations

import argparse
import base64
import ctypes
import hashlib
import ipaddress
import json
import ntpath
import os
import re
from pathlib import Path
import secrets
import select
import shutil
import socket
import stat
import struct
import subprocess
import sys
import threading
import time
import uuid


DEST4 = '203.0.113.77'
CAPTURE_FILTER = 'RuleProxyCaptureDest'
TUN4, TUN6 = '198.51.100.88', '2001:db8::88'
TCP_PORT, UDP_PORT = 18080, 39177
MAX_CAPTURE = 64 * 1024 * 1024
MAX_CAPTURE_COMPONENTS = 4
FIXTURE_SERVER = '127.0.0.1.sslip.io'
RECOVERY_DEADLINE_SECONDS = 180
EXPERIMENT_BUDGET_SECONDS = 135
# After the SYSTEM watchdog's 180 s trigger and 240 s task limit: a wedged
# orchestrator still emits a bounded digest and exits non-zero before the job timeout.
HARD_DEADLINE_SECONDS = 480
_ACTIVE_BUDGET = None
# Stage names only: these become public GitHub notices, so no evidence payloads.
_CI_MILESTONES = frozenset(('fixture_dns_preflight', 'physical_positive_before', 'global_start',
                            'core_terminate', 'explicit_global_stop', 'final_recovery'))


class ExperimentBudget:
    """Stop scheduling new work before the independent SYSTEM recovery fires.

    This bounds cooperative harness operations, not a hung broker/native call;
    the separate 180-second task remains the hard network-recovery backstop.
    """
    def __init__(self):
        self.started = time.monotonic()
        self.deadline = self.started + EXPERIMENT_BUDGET_SECONDS
        self.stages = []

    def stage(self, name):
        elapsed = time.monotonic() - self.started
        if self.stages and 'elapsed_seconds' not in self.stages[-1]:
            previous = self.stages[-1]
            previous['elapsed_seconds'] = round(elapsed - previous['started_seconds'], 3)
        if name is not None:
            self.stages.append({'stage': name, 'started_seconds': round(elapsed, 3)})
            if name in _CI_MILESTONES:
                _ci_annotation('notice', 'Global capture stage', name + ' t=' + format(elapsed, '.1f'))

    def timeout(self, maximum, *, reserve=0):
        remaining = self.deadline - time.monotonic() - reserve
        if remaining <= 0:
            raise RuntimeError('experiment_time_budget_exhausted')
        return min(maximum, remaining)

    def require(self, seconds):
        if self.deadline - time.monotonic() < seconds:
            raise RuntimeError('experiment_time_budget_insufficient')


def operation_timeout(maximum):
    return _ACTIVE_BUDGET.timeout(maximum) if _ACTIVE_BUDGET is not None else maximum


def fixture_source(port):
    """Public DNS spelling accepted by the unchanged production compiler."""
    source = json.dumps({'proxies': [{'name': 'CaptureEcho', 'type': 'socks5',
        'server': FIXTURE_SERVER, 'port': port, 'udp': True}], 'rules': ['MATCH,CaptureEcho']})
    from ruleproxy.config import compile_config
    compiled = compile_config(source, secret='fixture-preflight', capture_mode='global',
                              selected_node='CaptureEcho')
    if compiled.config['proxies'][0]['server'] != FIXTURE_SERVER:
        raise RuntimeError('fixture_compiler_changed_node')
    return source


def fixture_dns_preflight():
    # Same fixed IP DoH bootstrap as generated global config; no adapter or
    # hosts changes. This third-party DNS dependency is explicitly scoped.
    import urllib.request
    request = urllib.request.Request('https://1.1.1.1/dns-query?name=' + FIXTURE_SERVER + '&type=A',
                                     headers={'Accept': 'application/dns-json'})
    opener = urllib.request.build_opener(urllib.request.ProxyHandler({}))
    with opener.open(request, timeout=5) as response:
        data = response.read(16385)
    if len(data) > 16384:
        raise ValueError('fixture_dns_response_bound')
    value = json.loads(data)
    addresses = {item.get('data') for item in value.get('Answer', []) if item.get('type') == 1}
    if value.get('Status') != 0 or addresses != {'127.0.0.1'}:
        raise RuntimeError('fixture_dns_loopback_control_missing')
    return {'resolver': 'cloudflare_ip_doh', 'server_name': FIXTURE_SERVER,
            'only_ipv4_answer_loopback': True, 'external_dns_dependency': True}


def read_json(path):
    path = Path(path)
    if path.stat().st_size > 256 * 1024:
        raise ValueError('state_size_bound')
    return json.loads(path.read_text(encoding='utf-8-sig'))


def write_json(path, value):
    path = Path(path)
    temporary = path.with_suffix(path.suffix + '.tmp')
    temporary.write_text(json.dumps(value, ensure_ascii=True, indent=2), encoding='utf-8')
    os.replace(temporary, path)


def _ci_annotation(level, title, payload):
    """GitHub turns these stdout lines into public annotations; never include secrets.

    A disposable VM guest has no Actions runner: there the same bounded line is
    appended to RULEPROXY_CAPTURE_PROGRESS, which the guest relays over the VM
    serial console so progress stays visible after guest networking is lost.
    """
    actions = os.environ.get('GITHUB_ACTIONS') == 'true'
    progress = os.environ.get('RULEPROXY_CAPTURE_PROGRESS')
    if not actions and not progress:
        return
    text = payload if isinstance(payload, str) else json.dumps(payload, separators=(',', ':'), sort_keys=True)
    text = text[:1800].replace('%', '%25').replace('\r', '%0D').replace('\n', '%0A')
    line = '::' + level + ' title=' + title + '::' + text
    if actions:
        print(line, flush=True)
    if progress:
        try:
            with open(progress, 'a', encoding='ascii', errors='replace') as stream:
                stream.write(line + '\n')
        except OSError:
            pass  # Progress relay is diagnostic only.


def _ci_text(value, limit, private=()):
    """Bounded text for public annotations: run-private values, paths and token-like strings removed."""
    text = str(value)
    for item in private:
        if item:
            text = text.replace(str(item), '<private>')
    text = re.sub(r'(?<![A-Za-z])[A-Za-z]:[\\/][^\'"\r\n]*', '<path>', text)
    text = re.sub(r'\\\\[^\s\'"<>|]+', '<path>', text)
    text = re.sub(r'[A-Za-z0-9_-]{32,}', '<token>', text)
    return text[:limit]


def _ci_capture_digest(evidence):
    """Numbers only from capture failure evidence: file sizes, pktmon counters, component count."""
    if not isinstance(evidence, dict):
        return None
    def numeric(meta):
        if not isinstance(meta, dict):
            return None
        return {key: value for key, value in sorted(meta.items())[:24] if isinstance(key, str)
                and (type(value) in (int, bool) or isinstance(value, str)
                     and re.fullmatch(r'[0-9][0-9,.]{0,24}(?:\s*(?:bytes|B|KB|MB|GB))?', value, re.IGNORECASE))}
    inventory = evidence.get('inventory_after_flush_wait') or evidence.get('inventory_after_stop')
    files = inventory.get('files') if isinstance(inventory, dict) else None
    components = evidence.get('declared_components')
    return {'components': len(components) if isinstance(components, list) else None,
            'filter_confirmed': (evidence.get('filter') or {}).get('confirmed') is True,
            'etl_file_bytes': [item.get('bytes') for item in files if isinstance(item, dict)
                               and item.get('matches_expected_capture_glob') and type(item.get('bytes')) is int][:8]
                              if isinstance(files, list) else None,
            'matching_etl_bytes': inventory.get('matching_etl_bytes') if isinstance(inventory, dict) else None,
            'start': numeric(evidence.get('start')), 'buffer_info': numeric(evidence.get('buffer_info'))}


def _ci_summary(report, budget, private=()):
    """Fixed-shape digest for the public summary annotation: no paths, nonces, tokens or evidence."""
    def recovery(value):
        value = value if isinstance(value, dict) else {}
        return {'recovered': value.get('recovered'),
                'errors': [_ci_text(item, 200, private) for item in value.get('errors', [])[:2]]}
    capture = report.get('capture_failure')
    code = capture.get('code', capture.get('reason')) if isinstance(capture, dict) else None
    summary = {'passed': report.get('passed'), 'startup_smoke_passed': report.get('startup_smoke_passed'),
               'failed_stage': report.get('failed_stage'),
               'error': _ci_text(report['error'], 300, private) if report.get('error') else None,
               'stages': [item['stage'] for item in budget.stages], 'recovery': recovery(report.get('recovery'))}
    if 'dns_smoke_passed' in report:
        summary['dns_smoke_passed'] = report['dns_smoke_passed']
    if budget.stages and 'elapsed_seconds' in budget.stages[-1]:
        summary['last_stage_elapsed'] = budget.stages[-1]['elapsed_seconds']
    if 'ci_network_reclaim' in report:
        summary['ci_network_reclaim'] = recovery(report['ci_network_reclaim'])
    if isinstance(code, str):
        summary['capture_failure_code'] = _ci_text(code, 200, private)
    if isinstance(capture, dict):
        summary['capture'] = _ci_capture_digest(capture)
    return summary


def _hang_frames(thread_id, limit=16):
    """Innermost-first basename:function:line of one thread; no locals, arguments or paths."""
    frame = sys._current_frames().get(thread_id)
    frames = []
    while frame is not None and len(frames) < limit:
        code = frame.f_code
        frames.append(os.path.basename(code.co_filename)[:48] + ':' + code.co_name[:48] + ':' + str(frame.f_lineno))
        frame = frame.f_back
    return frames


def _watchdog_digest(work, private=()):
    """Bounded digest of the independent recovery results already written to the run directory."""
    def recovery(value):
        value = value if isinstance(value, dict) else {}
        return {'recovered': value.get('recovered'), 'mutex_bypassed': value.get('mutex_bypassed'),
                'errors': [_ci_text(item, 160, private) for item in value.get('errors', [])[:2]]}
    digest = {}
    for name, key in (('recover.result.json', 'watchdog'), ('recovery-result.json', 'strict_file'),
                      ('ci-network-reclaim-result.json', 'reclaim_file')):
        try:
            value = read_json(Path(work) / name)
        except (OSError, ValueError):
            continue
        if not isinstance(value, dict):
            continue
        if key != 'watchdog':
            digest[key] = recovery(value)
            continue
        result = value.get('result') if isinstance(value.get('result'), dict) else {}
        digest[key] = {'ok': value.get('ok'), **recovery(result),
                       'error': _ci_text(value['error'], 160, private) if value.get('error') else None}
        if 'ci_network_reclaim' in result:
            digest[key]['ci_network_reclaim'] = recovery(result['ci_network_reclaim'])
    return digest


def _hard_deadline(finished, report, budget, private, work, output, thread_id):
    """Bounded public digest, then exit, if the orchestrator outlives HARD_DEADLINE_SECONDS.

    The process exits non-zero; this path never sets passed or recovered.
    """
    if finished.wait(HARD_DEADLINE_SECONDS):
        return
    try:
        stage = budget.stages[-1]['stage'] if budget.stages else 'unknown'
        _ci_annotation('error', 'Global capture hard deadline',
                       {'stage': stage, 'frames': [_ci_text(item, 120, private) for item in _hang_frames(thread_id)]})
        _ci_annotation('error', 'Global capture watchdog', _watchdog_digest(work, private))
        report.update(passed=False, hard_deadline_exceeded=True, failed_stage=stage,
                      error=report.get('error') or 'RuntimeError:orchestrator_hard_deadline')
        for key in ('startup_smoke_passed', 'dns_smoke_passed'):
            if key in report:
                report[key] = False
        _ci_annotation('error', 'Global capture summary', _ci_summary(report, budget, private))
        output.parent.mkdir(parents=True, exist_ok=True)
        write_json(output, report)
    except BaseException:
        pass  # Diagnostics must never extend the hang; exit below regardless.
    finally:
        os._exit(3)


def ps(script, environment=None, timeout=25):
    from ruleproxy.windows_store_apps import _system_powershell
    executable = _system_powershell()
    prefix = "$ErrorActionPreference='Stop';$ProgressPreference='SilentlyContinue';$env:PSModulePath=Join-Path $PSHOME 'Modules';"
    suffix = ";$bytes=[Text.Encoding]::UTF8.GetBytes([string]$result);$s=[Console]::OpenStandardOutput();$s.Write($bytes,0,$bytes.Length)"
    command = [str(executable), '-NoLogo', '-NoProfile', '-NonInteractive', '-EncodedCommand',
        base64.b64encode((prefix + script + suffix).encode('utf-16-le')).decode('ascii')]
    result = subprocess.run(command, stdin=subprocess.DEVNULL, stdout=subprocess.PIPE,
        stderr=subprocess.PIPE, timeout=operation_timeout(timeout), env={**os.environ, **(environment or {})},
        creationflags=getattr(subprocess, 'CREATE_NO_WINDOW', 0), check=False)
    if result.returncode or len(result.stdout) > 2 * 1024 * 1024:
        raise RuntimeError('powershell_operation_failed:' + result.stderr.decode('utf-8', 'replace')[-700:])
    return result.stdout.decode('utf-8-sig').strip()


def pktmon(*arguments):
    from ruleproxy.windows_store_apps import _system_powershell
    executable = _system_powershell().parents[2] / 'pktmon.exe'
    result = subprocess.run([str(executable), *map(str, arguments)], stdin=subprocess.DEVNULL,
        stdout=subprocess.PIPE, stderr=subprocess.STDOUT, timeout=operation_timeout(20),
        creationflags=getattr(subprocess, 'CREATE_NO_WINDOW', 0), check=False)
    if result.returncode or len(result.stdout) > 2 * 1024 * 1024:
        raise RuntimeError('pktmon_operation_failed:' + result.stdout.decode('utf-8', 'replace')[-700:])
    return result.stdout.decode('utf-8-sig', 'replace')


def _field_name(value):
    return re.sub(r'[\s_-]', '', value.casefold())


def _mac(value):
    if not isinstance(value, str):
        return None
    if not re.fullmatch(r'(?:[0-9a-fA-F]{12}|(?:[0-9a-fA-F]{2}-){5}[0-9a-fA-F]{2}|(?:[0-9a-fA-F]{2}:){5}[0-9a-fA-F]{2})', value):
        return None
    return value.replace('-', '').replace(':', '').casefold()


def _index(value):
    if type(value) is int:
        return value if 0 < value <= 0xffffffff else None
    if isinstance(value, str) and re.fullmatch(r'[1-9][0-9]{0,9}', value):
        return _index(int(value))
    return None


def _component_records(document):
    # Properties belong to their enclosing component. Recursing into their
    # Name/Value rows (or Counters) loses that association and floods evidence.
    pending, visited = [('$', document)], 0
    while pending:
        path, value = pending.pop()
        visited += 1
        if visited > 10000:
            raise ValueError('component_list_bound')
        if isinstance(value, list):
            pending.extend((path + '[' + str(index) + ']', item)
                           for index, item in reversed(list(enumerate(value))))
        elif isinstance(value, dict):
            fields = {}
            for key, item in value.items():
                if not isinstance(key, str):
                    raise ValueError('component_keys_schema')
                normalized = _field_name(key)
                if normalized in fields:
                    raise ValueError('component_fields_ambiguous')
                fields[normalized] = item
            if 'id' in fields or 'componentid' in fields:
                yield path, value, fields
            pending.extend((path + '.' + str(key)[:60], item) for key, item in reversed(list(value.items()))
                           if isinstance(key, str) and _field_name(key) not in {'properties', 'counters'})


_MAC_FIELDS = {'mac', 'macaddress'}
_INDEX_FIELDS = {'ifindex', 'interfaceindex', 'miniportifindex'}


def _component_identity(fields):
    macs = [item for key, item in fields.items() if key in _MAC_FIELDS]
    indexes = [item for key, item in fields.items() if key in _INDEX_FIELDS]
    properties = fields.get('properties', [])
    if not isinstance(properties, list) or len(properties) > 64:
        raise ValueError('component_properties_schema')
    for prop in properties:
        if not isinstance(prop, dict) or not isinstance(prop.get('Name'), str) or 'Value' not in prop:
            raise ValueError('component_properties_schema')
        key = _field_name(prop['Name'])
        if key in _MAC_FIELDS:
            macs.append(prop['Value'])
        elif key in _INDEX_FIELDS:
            indexes.append(prop['Value'])
    normalized_macs, normalized_indexes = {_mac(item) for item in macs}, {_index(item) for item in indexes}
    if (None in normalized_macs or None in normalized_indexes
            or len(normalized_macs) > 1 or len(normalized_indexes) > 1):
        raise ValueError('component_identity_conflict')
    return next(iter(normalized_macs), None), next(iter(normalized_indexes), None)


def component_id(document, mac, description, interface_index=None):
    """Bind exactly one Miniport to Get-NetAdapter identity, never its name.

    Server 2025 emits Properties:[{Name,Value}], with a driver component name
    different from InterfaceDescription. Require its exact ifIndex when the
    caller supplies one; any available MAC must also agree. Names are diagnostic.
    """
    expected_mac = _mac(mac)
    if expected_mac is None:
        raise ValueError('physical_mac_required')
    if interface_index is not None and _index(interface_index) != interface_index:
        raise ValueError('physical_index_required')
    found = []
    for _path, _value, fields in _component_records(document):
        if ('type' in fields and 'componenttype' in fields and fields['type'] != fields['componenttype']
                or 'id' in fields and 'componentid' in fields and fields['id'] != fields['componentid']):
            raise ValueError('component_fields_ambiguous')
        if fields.get('type', fields.get('componenttype')) != 'Miniport':
            continue
        candidate_mac, candidate_index = _component_identity(fields)
        same_mac, same_index = candidate_mac == expected_mac, candidate_index == interface_index
        # SR-IOV VF and synthetic NetVsc miniports can legitimately share a
        # MAC while having different ifIndexes. The live ifIndex identifies
        # our candidate; only that candidate's optional MAC must agree.
        if interface_index is not None and same_index and candidate_mac is not None and not same_mac:
            raise ValueError('component_identity_conflict')
        matches = same_index if interface_index is not None else same_mac
        identity = fields.get('id', fields.get('componentid'))
        if matches:
            if type(identity) is not int or not 0 < identity <= 0xffffffff:
                raise ValueError('physical_component_id_invalid')
            found.append(identity)
    if len(found) != 1:
        raise ValueError('physical_component_not_unique')
    return found[0]


def capture_component_ids(document, mac, description, interface_index, logical_component):
    """Freeze the exact-MAC Miniport set before the product creates its TUN.

    Windows SR-IOV may send through the VF rather than the logical NetVsc
    miniport. Observe both known paths, retaining the original ifIndex check.
    https://learn.microsoft.com/en-us/windows-hardware/drivers/network/overview-of-sr-iov-data-paths
    """
    if component_id(document, mac, description, interface_index) != logical_component:
        raise ValueError('logical_component_identity_changed')
    expected, found, indexes = _mac(mac), [], set()
    for _path, _value, fields in _component_records(document):
        if fields.get('type', fields.get('componenttype')) != 'Miniport':
            continue
        candidate_mac, candidate_index = _component_identity(fields)
        if candidate_mac != expected:
            continue
        identity = fields.get('id', fields.get('componentid'))
        if type(identity) is not int or not 0 < identity <= 0xffffffff or candidate_index is None:
            raise ValueError('capture_component_identity_unconfirmed')
        if identity in found or candidate_index in indexes:
            raise ValueError('capture_component_identity_ambiguous')
        found.append(identity)
        indexes.add(candidate_index)
        if len(found) > MAX_CAPTURE_COMPONENTS:
            raise ValueError('capture_component_set_bound')
    if logical_component not in found:
        raise ValueError('logical_component_mac_unconfirmed')
    return sorted(found)


def _capture_set(value):
    values = [value] if type(value) is int else value
    if (not isinstance(values, (list, tuple)) or not 1 <= len(values) <= MAX_CAPTURE_COMPONENTS
            or any(type(item) is not int or not 0 < item <= 0xffffffff for item in values)
            or len(set(values)) != len(values)):
        raise ValueError('capture_component_set_invalid')
    return sorted(values)


def aggregate_capture_components(declared, values, etl_count):
    components = _capture_set(declared)
    if (type(etl_count) is not int or not 1 <= etl_count <= 4 or not isinstance(values, dict)
            or set(values) != {str(component) for component in components}):
        raise ValueError('capture_component_conversion_incomplete')
    counts = {'tcp_syn': 0, 'udp_marker': 0, 'packets_parsed': 0, 'captures': [],
              'declared_components': components, 'components': values, 'etl_count': etl_count}
    for component in components:
        value = values[str(component)]
        if (not isinstance(value, dict) or not isinstance(value.get('captures'), list)
                or len(value['captures']) != etl_count
                or any(type(value.get(key)) is not int or value[key] < 0
                       for key in ('tcp_syn', 'udp_marker', 'packets_parsed'))
                or any(not isinstance(item, dict) or type(item.get('bytes')) is not int or item['bytes'] <= 0
                       or not isinstance(item.get('sha256'), str) or not re.fullmatch(r'[a-f0-9]{64}', item['sha256'])
                       for item in value['captures'])):
            raise ValueError('capture_component_conversion_incomplete')
        for key in ('tcp_syn', 'udp_marker', 'packets_parsed'):
            counts[key] += value[key]
        counts['captures'].extend({'component': component, **item} for item in value['captures'])
    return counts


def protected_components_clear(value, declared):
    try:
        if value.get('capture_loss_verified') is not True or not capture_loss_verified(value.get('capture_diagnostics')):
            return False
        components = _capture_set(declared)
        if value.get('declared_components') != components:
            return False
        checked = aggregate_capture_components(components, value.get('components'), value.get('etl_count'))
        return all(type(value.get(key)) is int and value[key] == checked[key] == 0
                   for key in ('tcp_syn', 'udp_marker'))
    except (AttributeError, TypeError, ValueError):
        return False


def record_physical_control(report, phase):
    value = report['phases']['outside_' + phase]
    if value.get('capture_loss_verified') is not True or not capture_loss_verified(value.get('capture_diagnostics')):
        raise RuntimeError('capture_loss_unverified')
    valid = all(type(value.get(key)) is int and value[key] > 0 for key in ('tcp_syn', 'udp_marker'))
    report['physical_positive_' + phase + '_valid'] = valid
    if not valid:
        report.setdefault('evidence_gaps', []).append('physical_positive_' + phase + '_missing')
    return valid


def component_diagnostics(document, mac, description, interface_index=None):
    # Bounded component rows, with Miniports and exact identity matches first.
    # Only MAC/ifIndex property values are exported; pointers/IPs/paths stay local.
    rows, total, matching_mac, matching_index, matching_description = [], 0, 0, 0, 0
    expected = _mac(mac)
    fields_wanted = {'id', 'componentid', 'secondaryid', 'mac', 'macaddress', 'name', 'description',
                     'type', 'componenttype', 'mediatype', *_INDEX_FIELDS}
    def safe(value):
        if isinstance(value, str):
            if ':\\' in value or value.startswith(('\\\\', '/')):
                return '<path omitted>'
            return ''.join(c for c in value if ord(c) >= 32)[:160]
        if value is None or type(value) in (int, bool):
            return value
        return '<' + type(value).__name__ + '>'
    traversal_error = None
    try:
        for path, value, fields in _component_records(document):
            total += 1
            row = {'json_path': path[:200], 'keys': [safe(str(key)) for key in list(value)[:20]],
                'fields': {key: safe(item) for key, item in fields.items() if key in fields_wanted},
                'field_types': {key: type(item).__name__ for key, item in fields.items() if key in fields_wanted}}
            try:
                candidate_mac, candidate_index = _component_identity(fields)
            except ValueError as error:
                candidate_mac, candidate_index = None, None
                row['identity_error'] = str(error)
            same_mac, same_index = candidate_mac == expected, interface_index is not None and candidate_index == interface_index
            same_description = fields.get('name') == description or fields.get('description') == description
            matching_mac += int(same_mac)
            matching_index += int(same_index)
            matching_description += int(same_description)
            row.update(exact_mac_match=same_mac, exact_index_match=same_index, exact_description_match=same_description)
            properties = fields.get('properties', [])
            if isinstance(properties, list):
                row['property_count'] = len(properties)
                row['properties'] = [{'name': safe(prop.get('Name')), 'value_type': type(prop.get('Value')).__name__,
                    **({'value': safe(prop.get('Value'))} if isinstance(prop.get('Name'), str)
                       and _field_name(prop['Name']) in _MAC_FIELDS | _INDEX_FIELDS else {})}
                    for prop in properties[:64] if isinstance(prop, dict)]
            priority = (same_index or same_mac, fields.get('type') == 'Miniport')
            rows.append((priority, total, row))
            rows.sort(key=lambda item: (not item[0][0], not item[0][1], item[1]))
            del rows[96:]
    except ValueError as error:
        traversal_error = str(error)
    return {'top_type': type(document).__name__, 'rows': [row for _, _, row in rows],
            'component_count': total, 'rows_bound_reached': total > 96,
            'traversal_incomplete': traversal_error is not None, 'traversal_error': traversal_error,
            'exact_mac_match_count': matching_mac, 'exact_index_match_count': matching_index,
            'exact_description_match_count': matching_description}


def default_nic():
    return json.loads(ps("$r=@(Get-NetRoute -DestinationPrefix '0.0.0.0/0' -PolicyStore ActiveStore|Sort-Object RouteMetric);"
        "if(-not $r.Count){throw 'no physical default route'};$a=Get-NetAdapter -InterfaceIndex $r[0].InterfaceIndex;"
        "if($a.Status -ne 'Up'){throw 'adapter down'};$ip=@(Get-NetIPAddress -InterfaceIndex $a.ifIndex -AddressFamily IPv4|"
        "Where-Object {$_.AddressState -eq 'Preferred' -and -not $_.SkipAsSource})[0];"
        "$result=@{index=[int]$a.ifIndex;mac=[string]$a.MacAddress;description=[string]$a.InterfaceDescription;"
        "source=[string]$ip.IPAddress;gateway=[string]$r[0].NextHop;alias=[string]$a.Name}|ConvertTo-Json -Compress", timeout=8))


def nic_components():
    nic = default_nic()
    document = json.loads(pktmon('list', '--json'))
    evidence = component_diagnostics(document, nic['mac'], nic['description'], nic['index'])
    evidence['nic'] = {key: nic[key] for key in ('index', 'mac', 'description')}
    component = None
    try:
        component = component_id(document, nic['mac'], nic['description'], nic['index'])
        evidence['capture_components'] = capture_component_ids(document, nic['mac'], nic['description'], nic['index'], component)
    except ValueError as error:
        evidence['selection_error'] = str(error)
        component = None
    evidence['logical_interface_component'] = component
    evidence['selected_component'] = component
    return nic, component, evidence


def tun_identity_receipt(started):
    """Read actual adapter identity without PowerShell or changing interfaces."""
    from ruleproxy import windows_global_guard as guard
    api = ctypes.WinDLL('iphlpapi.dll', use_last_error=True)
    api.ConvertInterfaceAliasToLuid.argtypes = [ctypes.c_wchar_p, ctypes.POINTER(ctypes.c_uint64)]
    api.ConvertInterfaceAliasToLuid.restype = ctypes.c_uint32
    api.ConvertInterfaceLuidToGuid.argtypes = [ctypes.POINTER(ctypes.c_uint64), ctypes.POINTER(guard._GUID)]
    api.ConvertInterfaceLuidToGuid.restype = ctypes.c_uint32
    api.ConvertInterfaceLuidToIndex.argtypes = [ctypes.POINTER(ctypes.c_uint64), ctypes.POINTER(ctypes.c_uint32)]
    api.ConvertInterfaceLuidToIndex.restype = ctypes.c_uint32
    luid, identity, index = ctypes.c_uint64(), guard._GUID(), ctypes.c_uint32()
    for operation, arguments in (
        (api.ConvertInterfaceAliasToLuid, (guard._TUN_NAME, ctypes.byref(luid))),
        (api.ConvertInterfaceLuidToGuid, (ctypes.byref(luid), ctypes.byref(identity))),
        (api.ConvertInterfaceLuidToIndex, (ctypes.byref(luid), ctypes.byref(index)))):
        code = operation(*arguments)
        if code:
            raise OSError(code, 'tun_identity_readback_failed')
    expected = str(uuid.UUID(bytes_le=hashlib.md5(('wintun' + guard._TUN_NAME).encode()).digest()))
    verified_luid = guard._tun_luid()
    return {'alias': guard._TUN_NAME, 'interface_guid': identity.text(), 'interface_index': index.value,
        'luid': luid.value, 'expected_guid': expected,
        'identity_matches': bool(luid.value and index.value and identity.text() == expected and verified_luid == luid.value),
        'start_guard_tun_ready': started.get('guard', {}).get('tun_ready') is True,
        'native_qualified': False}


def ethernet_probe(frame, marker):
    if len(frame) < 14:
        raise ValueError('short_ethernet')
    offset, kind = 14, struct.unpack_from('!H', frame, 12)[0]
    for _ in range(4):
        if kind not in (0x8100, 0x88a8, 0x9100):
            break
        if len(frame) < offset + 4:
            raise ValueError('short_vlan')
        kind = struct.unpack_from('!H', frame, offset + 2)[0]
        offset += 4
    if kind != 0x0800:
        return (0, 0)
    if len(frame) < offset + 20 or frame[offset] >> 4 != 4:
        raise ValueError('invalid_ipv4')
    length = struct.unpack_from('!H', frame, offset + 2)[0]
    header = (frame[offset] & 15) * 4
    if header < 20 or length < header or len(frame) < offset + length:
        raise ValueError('truncated_ipv4')
    if frame[offset + 16:offset + 20] != ipaddress.IPv4Address(DEST4).packed:
        return (0, 0)
    if struct.unpack_from('!H', frame, offset + 6)[0] & 0x3fff:
        raise ValueError('fragmented_watched_probe')
    protocol, start, end = frame[offset + 9], offset + header, offset + length
    if protocol == 6:
        if end - start < 20:
            raise ValueError('short_tcp')
        port, flags = struct.unpack_from('!H', frame, start + 2)[0], frame[start + 13]
        return (int(port == TCP_PORT and flags & 2 != 0 and flags & 16 == 0), 0)
    if protocol == 17:
        if end - start < 8:
            raise ValueError('short_udp')
        port, size = struct.unpack_from('!HH', frame, start + 2)
        if size < 8 or start + size > end:
            raise ValueError('invalid_udp')
        return (0, int(port == UDP_PORT and frame[start + 8:start + size] == marker))
    return (0, 0)


def pcapng_counts(path, marker):
    """Strict bounded Ethernet EPB reader; capture truncation never means zero."""
    with Path(path).open('rb') as stream:
        data = stream.read(MAX_CAPTURE + 1)
    if len(data) > MAX_CAPTURE:
        raise ValueError('capture_size_bound')
    offset, endian, links, tcp, udp, packets = 0, None, [], 0, 0, 0
    while offset < len(data):
        if len(data) - offset < 12:
            raise ValueError('partial_pcapng_block')
        if data[offset:offset + 4] == b'\x0a\x0d\x0d\x0a':
            magic = data[offset + 8:offset + 12]
            endian = '<' if magic == b'\x4d\x3c\x2b\x1a' else '>' if magic == b'\x1a\x2b\x3c\x4d' else None
            if endian is None:
                raise ValueError('invalid_pcapng_magic')
            links = []
        if endian is None:
            raise ValueError('missing_pcapng_section')
        kind, size = struct.unpack_from(endian + 'II', data, offset)
        if size < 12 or size % 4 or offset + size > len(data) or struct.unpack_from(endian + 'I', data, offset + size - 4)[0] != size:
            raise ValueError('invalid_pcapng_length')
        body = data[offset + 8:offset + size - 4]
        if kind == 0x0a0d0d0a:
            if len(body) < 16 or struct.unpack_from(endian + 'HH', body, 4) != (1, 0):
                raise ValueError('unsupported_pcapng_section')
        elif kind == 1:
            if len(body) < 8:
                raise ValueError('short_interface_block')
            links.append(struct.unpack_from(endian + 'H', body)[0])
        elif kind == 6:
            if len(body) < 20:
                raise ValueError('short_packet_block')
            interface, _hi, _lo, captured, original = struct.unpack_from(endian + '5I', body)
            if interface >= len(links) or links[interface] != 1 or captured != original or len(body) < 20 + captured:
                raise ValueError('unsupported_or_truncated_packet')
            one, two = ethernet_probe(body[20:20 + captured], marker)
            tcp, udp, packets = tcp + one, udp + two, packets + 1
        elif kind in (2, 3):
            raise ValueError('unsupported_packet_block')
        offset += size
    if not links:
        raise ValueError('missing_capture_interface')
    return {'tcp_syn': tcp, 'udp_marker': udp, 'packets_parsed': packets,
            'sha256': hashlib.sha256(data).hexdigest(), 'bytes': len(data)}


def exact(connection, length):
    result = bytearray()
    while len(result) < length:
        chunk = connection.recv(length - len(result))
        if not chunk:
            raise EOFError('short_fixture_stream')
        result.extend(chunk)
    return bytes(result)


def socks_address(connection):
    kind = exact(connection, 1)[0]
    if kind not in (1, 4):
        raise ValueError('fixture_ip_literals_only')
    address = str(ipaddress.ip_address(exact(connection, 4 if kind == 1 else 16)))
    return address, struct.unpack('!H', exact(connection, 2))[0]


def encode_address(host, port):
    address = ipaddress.ip_address(host)
    return bytes([1 if address.version == 4 else 4]) + address.packed + struct.pack('!H', port)


class EchoNode:
    """Synthetic SOCKS echo only; never forwards to any Internet destination."""
    def __init__(self):
        self.socket = socket.socket()
        self.socket.bind(('127.0.0.1', 0))
        self.socket.listen(16)
        self.socket.settimeout(.2)
        self.port = self.socket.getsockname()[1]
        self.stop = threading.Event()
        self.counts = {'tcp4': 0, 'tcp6': 0, 'udp4': 0, 'udp6': 0}
        self.lock = threading.Lock()
        self.doh_relay = None
        self.clients = set()
        threading.Thread(target=self.accept, daemon=True).start()

    def accept(self):
        while not self.stop.is_set():
            try:
                connection, _ = self.socket.accept()
            except socket.timeout:
                continue
            except OSError:
                return
            with self.lock:
                if self.stop.is_set():
                    connection.close()
                    return
                self.clients.add(connection)
            threading.Thread(target=self.serve, args=(connection,), daemon=True).start()

    def serve(self, connection):
        try:
            connection.settimeout(5)
            version, count = exact(connection, 2)
            if version != 5 or 0 not in exact(connection, count):
                return
            connection.sendall(b'\x05\x00')
            version, command, reserved = exact(connection, 3)
            host, port = socks_address(connection)
            if (version, reserved) != (5, 0):
                return
            if command == 3:
                self.udp(connection)
                return
            if command == 1 and self.doh_relay is not None and (host, port) == ('1.1.1.1', 443):
                self.doh_relay.handle(connection, host, port,
                    on_ready=lambda stream: stream.sendall(b'\x05\x00\x00' + encode_address('127.0.0.1', 0)))
                return
            if command != 1 or host not in (TUN4, TUN6) or port != TCP_PORT:
                connection.sendall(b'\x05\x02\x00' + encode_address('127.0.0.1', 0))
                return
            connection.sendall(b'\x05\x00\x00' + encode_address('127.0.0.1', 0))
            data = connection.recv(512)
            if not data.startswith(b'RuleProxyCapture:'):
                return
            with self.lock:
                self.counts['tcp' + str(ipaddress.ip_address(host).version)] += 1
            connection.sendall(data)
        except (OSError, EOFError, ValueError):
            pass
        finally:
            with self.lock:
                self.clients.discard(connection)
            connection.close()

    def udp(self, control):
        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as relay:
            relay.bind(('127.0.0.1', 0))
            relay.setblocking(False)
            control.sendall(b'\x05\x00\x00' + encode_address('127.0.0.1', relay.getsockname()[1]))
            while not self.stop.is_set():
                ready, _, _ = select.select((relay, control), (), (), .2)
                if control in ready and not control.recv(1):
                    return
                if relay not in ready:
                    continue
                data, peer = relay.recvfrom(2048)
                if data[:3] != b'\0\0\0' or data[3:4] not in (b'\x01', b'\x04'):
                    continue
                width = 4 if data[3] == 1 else 16
                if len(data) < 6 + width:
                    continue
                host = str(ipaddress.ip_address(data[4:4 + width]))
                port = struct.unpack_from('!H', data, 4 + width)[0]
                payload = data[6 + width:]
                if host not in (TUN4, TUN6) or port != UDP_PORT or not payload.startswith(b'RuleProxyCapture:'):
                    continue
                with self.lock:
                    self.counts['udp' + str(ipaddress.ip_address(host).version)] += 1
                relay.sendto(data, peer)

    def close(self):
        self.stop.set()
        if self.doh_relay is not None:
            self.doh_relay.close()
        with self.lock:
            clients = list(self.clients)
        for connection in clients:
            try:
                connection.shutdown(socket.SHUT_RDWR)
            except OSError:
                pass
            connection.close()
        self.socket.close()


class LocalEcho6:
    def __init__(self):
        self.stop = threading.Event()
        self.counts = {'tcp': 0, 'udp': 0}
        self.tcp = socket.socket(socket.AF_INET6, socket.SOCK_STREAM)
        self.udp = socket.socket(socket.AF_INET6, socket.SOCK_DGRAM)
        for stream in (self.tcp, self.udp):
            stream.bind(('::1', 0))
            stream.settimeout(.2)
        self.tcp.listen(4)
        self.tcp_port, self.udp_port = self.tcp.getsockname()[1], self.udp.getsockname()[1]
        for protocol in ('tcp', 'udp'):
            threading.Thread(target=self.serve, args=(protocol,), daemon=True).start()

    def serve(self, protocol):
        while not self.stop.is_set():
            try:
                if protocol == 'tcp':
                    connection, _ = self.tcp.accept()
                    with connection:
                        connection.settimeout(.5)
                        payload = connection.recv(512)
                        if payload.startswith(b'RuleProxyCapture:'):
                            self.counts['tcp'] += 1
                            connection.sendall(payload)
                else:
                    payload, peer = self.udp.recvfrom(512)
                    if payload.startswith(b'RuleProxyCapture:'):
                        self.counts['udp'] += 1
                        self.udp.sendto(payload, peer)
            except socket.timeout:
                continue
            except OSError:
                return

    def close(self):
        self.stop.set()
        self.tcp.close()
        self.udp.close()


def actor(value):
    marker = value['marker'].encode('ascii')
    host, family = value['host'], value['family']
    kind = socket.AF_INET if family == 4 else socket.AF_INET6
    results = {}
    for protocol, port in (('tcp', value['tcp_port']), ('udp', value['udp_port'])):
        stage = 'socket'
        try:
            with socket.socket(kind, socket.SOCK_STREAM if protocol == 'tcp' else socket.SOCK_DGRAM) as stream:
                stream.settimeout(1.2)
                if value.get('source'):
                    stage = 'bind'
                    stream.bind((value['source'], 0))
                if protocol == 'tcp':
                    stage = 'connect'
                    stream.connect((host, port))
                    stage = 'send'
                    stream.sendall(marker)
                    received = stream.recv(len(marker)) == marker if value.get('echo') else False
                else:
                    stage = 'send'
                    for _ in range(3 if not value.get('echo') else 1):
                        stream.sendto(marker, (host, port))
                    received = stream.recvfrom(2048)[0] == marker if value.get('echo') else False
                results[protocol] = {'executed': True, 'received_echo': received, 'socket_ok': True, 'stage': stage}
        except OSError as error:
            results[protocol] = {'executed': stage in ('connect', 'send'), 'received_echo': False,
                                 'socket_ok': False, 'stage': stage, 'error': (getattr(error, 'winerror', None)
                                     or error.errno or (10060 if isinstance(error, TimeoutError) else None))}
    return results


def valid_physical_attempt(result):
    # Timeout/refused/unreachable after connect/send are valid attempted probes;
    # socket creation, bind, protocol/address errors never establish blocking.
    allowed_errors = {13, 110, 111, 10013, 10060, 10061}
    return all(isinstance(result.get(kind), dict)
        and result[kind].get('executed') is True
        and result[kind].get('stage') in ('connect', 'send')
        and (result[kind].get('socket_ok') is True or result[kind].get('error') in allowed_errors)
        for kind in ('tcp', 'udp'))


class CaptureEvidenceError(RuntimeError):
    def __init__(self, code, evidence):
        super().__init__(code)
        self.evidence = evidence


def capture_idle(value):
    return bool(re.search(r'^\s*(?:Packet Monitor|PktMon)(?: (?:driver|trace))? is not running\.?\s*$',
                          value, re.IGNORECASE | re.MULTILINE))


def capture_cli_metadata(value, base):
    """Whitelist counters/configuration only, never export complete CLI text."""
    result = {'idle_reported': capture_idle(value), 'loss_counters_reported': False}
    counters = {'events lost', 'buffers lost', 'packets lost', 'events dropped', 'packets dropped',
                'events logged', 'packets captured', 'buffers written', 'events captured', 'buffers free',
                'buffers available', 'buffers allocated', 'number of buffers', 'free buffers'}
    sizes = {'maximum file size', 'max file size', 'file size', 'buffer size', 'packet size'}
    for line in value.splitlines()[:256]:
        match = re.fullmatch(r'\s*([A-Za-z ]{1,48}):\s*(.*?)\s*', line)
        if not match:
            continue
        label, item = match[1].casefold(), match[2]
        key = label.replace(' ', '_')
        if label == 'log file':
            if item.endswith(' (No events lost)'):
                item = item[:-len(' (No events lost)')]
                result['final_events_lost'] = 0
            location = item.strip('"').replace('/', '\\')
            name = ntpath.basename(location)
            result['log_basename'] = name if re.fullmatch(r'[A-Za-z0-9_.%() -]{1,160}', name) else '<unrecognized basename>'
            result['log_parent_is_private_run_directory'] = (
                ntpath.normcase(ntpath.dirname(location)) == ntpath.normcase(str(base.parent).replace('/', '\\')))
            result['log_matches_owned_prefix'] = bool(re.fullmatch(re.escape(str(base).replace('/', '\\'))
                + r'(?:[_.-]?\d+)?\.etl', location, re.IGNORECASE))
        elif label in counters and re.fullmatch(r'[0-9][0-9,]{0,24}', item):
            result[key] = int(item.replace(',', ''))
            if label.endswith((' lost', ' dropped')):
                result['loss_counters_reported'] = True
        elif label in sizes and re.fullmatch(r'[0-9][0-9,.]{0,24}(?:\s*(?:bytes|B|KB|MB|GB))?', item, re.IGNORECASE):
            result[key] = item
        elif label in {'logging mode', 'log mode'} and item.casefold() in {'multi-file', 'circular', 'memory', 'real-time'}:
            result['logging_mode'] = item.casefold()
    return result


def capture_loss_verified(evidence):
    """Require observed zero ETW loss and an owned post-stop zero-loss receipt."""
    try:
        buffer = evidence['buffer_info']
        restoration = evidence['restore']
        stop = restoration['cli_metadata']['stop']
        required = (buffer.get('events_lost'), buffer.get('buffers_lost'), stop.get('final_events_lost'))
        if (any(type(item) is not int or item != 0 for item in required)
                or restoration.get('stopped') is not True
                or stop.get('log_parent_is_private_run_directory') is not True
                or stop.get('log_matches_owned_prefix') is not True):
            return False
        snapshots = (buffer, *restoration['cli_metadata'].values())
        return all(type(value[key]) is int and value[key] == 0 for value in snapshots if isinstance(value, dict)
                   for key in ('events_lost', 'buffers_lost') if key in value)
    except (AttributeError, KeyError, TypeError):
        return False


def capture_inventory(work, base):
    """Inspect only capture filenames in this private run directory."""
    rows, matching_count, matching_bytes, scanned = [], 0, 0, 0
    for path in sorted(work.iterdir()):
        scanned += 1
        if scanned > 256:
            raise RuntimeError('capture_directory_inventory_bound')
        name = path.name
        if '.etl' not in name.casefold() and not name.casefold().endswith('.pcapng'):
            continue
        info = path.stat(follow_symlinks=False)
        reparse = bool(getattr(info, 'st_file_attributes', 0) & 0x400) or path.is_symlink()
        regular = stat.S_ISREG(info.st_mode) and not reparse
        matches = bool(re.fullmatch(re.escape(base.name) + r'.*\.etl', name, re.IGNORECASE))
        matching_count += int(matches)
        matching_bytes += info.st_size if matches else 0
        rows.append({'basename': name if re.fullmatch(r'[A-Za-z0-9_.%() -]{1,160}', name) else '<unrecognized basename>',
                     'bytes': info.st_size, 'regular_file': regular, 'reparse_point': reparse,
                     'matches_expected_capture_glob': matches})
    rows.sort(key=lambda item: not item['matches_expected_capture_glob'])
    return {'scope': 'private_run_directory_only', 'capture_file_count': len(rows), 'files': rows[:32],
            'rows_truncated': len(rows) > 32, 'matching_etl_count': matching_count,
            'matching_etl_bytes': matching_bytes, 'etl_logical_event_bytes_verified': False}


def install_capture_filter(evidence):
    """Report only frames to/from the single physical test destination.

    The matcher counts only DEST4 frames, so other frames never influenced a
    gate; positive controls pass through the same filter, so zero counts in
    blocked phases cannot become vacuous. IP-only (no port) keeps non-initial
    fragments visible. pktmon filters are global: this disposable harness
    already owns the single pktmon session, and the prior listing is retained.
    """
    try:
        evidence['filter_before'] = pktmon('filter', 'list')[-2000:]
    except RuntimeError as error:
        # The exit status of an empty listing is undocumented; keep the output.
        evidence['filter_before'] = ('listing_failed:' + str(error))[-2000:]
    try:
        pktmon('filter', 'remove')
    except RuntimeError:
        pass  # Exit status with no filters is undocumented; presence is checked below.
    pktmon('filter', 'add', CAPTURE_FILTER, '-i', DEST4)
    listing = pktmon('filter', 'list')
    if CAPTURE_FILTER not in listing or DEST4 not in listing:
        raise RuntimeError('capture_filter_unconfirmed')
    evidence['filter'] = {'name': CAPTURE_FILTER, 'ip': DEST4, 'confirmed': True}


def remove_capture_filter():
    try:
        pktmon('filter', 'remove')
    except RuntimeError:
        pass
    try:
        listing = pktmon('filter', 'list')
    except RuntimeError as error:
        # An empty listing may exit non-zero; its bounded output still names any
        # remaining filter, so the absence check below keeps its meaning.
        listing = str(error)
    if CAPTURE_FILTER in listing:
        raise RuntimeError('capture_filter_remove_unconfirmed')
    return True


def restore_capture(state_path):
    state = read_json(state_path)
    lease = state.get('capture')
    if not lease:
        return {'stopped': True, 'owned_capture_created': False}
    base = Path(lease['base'])
    status = pktmon('status')
    evidence = {'status_before': capture_cli_metadata(status, base)}
    if not capture_idle(status):
        # CI is explicitly English Windows. Unknown/localized status fails
        # closed; no global stop without the exact private per-run log marker.
        expression = (r'^\s*Log file:\s*"?' + re.escape(str(base).replace('/', '\\'))
                      + r'(?:[_.-]?\d+)?\.etl"?\s*$')
        if not re.search(expression, status.replace('/', '\\'), re.IGNORECASE | re.MULTILINE):
            raise RuntimeError('capture_session_ownership_unconfirmed')
        evidence['stop'] = capture_cli_metadata(pktmon('stop'), base)
        status = pktmon('status')
        evidence['status_after'] = capture_cli_metadata(status, base)
        if not capture_idle(status):
            raise RuntimeError('owned_capture_stop_unconfirmed')
    if lease.get('filter'):
        evidence['filter_removed'] = remove_capture_filter()
    state['capture']['stopped'] = True
    write_json(state_path, state)
    return {'stopped': True, 'owned_capture_created': True, 'cli_metadata': evidence}


def scope_filter_diagnostics(owned, engine):
    # Only deterministic keys in this random per-run scope. No enumeration,
    # AppId blobs, security descriptors, filesystem paths or packet contents.
    from ruleproxy import windows_global_guard as guard
    records = []
    for family, name in guard._ALL_RULES:
        with engine.get('Filter', owned._rule_key(family, name), guard._Filter) as value:
            if value is None:
                continue
            records.append({'key': value.key.text(), 'family': family, 'name': name,
                'marker_matches': value.display.description == owned.marker,
                'provider_matches': bool(value.provider) and value.provider.contents.text() == str(owned.provider),
                'sublayer_matches': value.sublayer.text() == str(owned.sublayer),
                'layer_matches': value.layer.text() == guard._LAYERS[family],
                'flags': int(value.flags), 'expected_flags': guard._PERSISTENT,
                'condition_count': int(value.count)})
            if len(records) == 2:
                break
    return records


def scoped_guard(metadata, nonce):
    from ruleproxy import windows_global_guard as guard
    class Scoped(guard.Guard):
        def __init__(self, deployment):
            super().__init__(deployment)
            self.identity = hashlib.sha256((self.identity + '/native-scope/' + nonce).encode()).hexdigest()
            self.provider, self.sublayer = self._key('provider'), self._key('sublayer')
            self.marker = 'RuleProxyGuard-v1:' + self.identity

        def _filters(self, engine):
            try:
                return super()._filters(engine)
            except guard.ProxyError as error:
                detail = scope_filter_diagnostics(self, engine)
                raise guard.ProxyError(getattr(error, 'code', 'global_guard_conflict'),
                    'scope_filter_readback:' + json.dumps(detail, separators=(',', ':'))) from error
    return Scoped(metadata)


def pid_identity(pid):
    """Hold a process while reading its image/creation time to prevent PID reuse."""
    kernel = ctypes.WinDLL('kernel32', use_last_error=True)
    kernel.OpenProcess.argtypes, kernel.OpenProcess.restype = [ctypes.c_uint32, ctypes.c_int, ctypes.c_uint32], ctypes.c_void_p
    kernel.CloseHandle.argtypes = [ctypes.c_void_p]
    kernel.QueryFullProcessImageNameW.argtypes = [ctypes.c_void_p, ctypes.c_uint32, ctypes.c_wchar_p, ctypes.POINTER(ctypes.c_uint32)]
    kernel.GetProcessTimes.argtypes = [ctypes.c_void_p, *([ctypes.POINTER(ctypes.c_uint64)] * 4)]
    handle = kernel.OpenProcess(0x1000 | 1 | 0x100000, False, pid)
    if not handle:
        return None
    try:
        image, size = ctypes.create_unicode_buffer(32768), ctypes.c_uint32(32768)
        creation, end, kern, user = (ctypes.c_uint64() for _ in range(4))
        if not kernel.QueryFullProcessImageNameW(handle, 0, image, ctypes.byref(size)):
            raise ctypes.WinError(ctypes.get_last_error())
        if not kernel.GetProcessTimes(handle, *map(ctypes.byref, (creation, end, kern, user))):
            raise ctypes.WinError(ctypes.get_last_error())
        return {'pid': pid, 'image': image.value, 'creation': creation.value}
    finally:
        kernel.CloseHandle(handle)


def require_owned_identity(pid, fixed_core):
    record = pid_identity(pid)
    if not record or os.path.normcase(record['image']) != os.path.normcase(str(fixed_core)):
        raise RuntimeError('fixed_core_process_identity_unconfirmed')
    return record


def terminate_owned(record, fixed_core):
    if not record:
        return
    kernel = ctypes.WinDLL('kernel32', use_last_error=True)
    kernel.OpenProcess.argtypes, kernel.OpenProcess.restype = [ctypes.c_uint32, ctypes.c_int, ctypes.c_uint32], ctypes.c_void_p
    kernel.CloseHandle.argtypes = [ctypes.c_void_p]
    kernel.QueryFullProcessImageNameW.argtypes = [ctypes.c_void_p, ctypes.c_uint32, ctypes.c_wchar_p, ctypes.POINTER(ctypes.c_uint32)]
    kernel.GetProcessTimes.argtypes = [ctypes.c_void_p, *([ctypes.POINTER(ctypes.c_uint64)] * 4)]
    kernel.TerminateProcess.argtypes, kernel.TerminateProcess.restype = [ctypes.c_void_p, ctypes.c_uint32], ctypes.c_int
    kernel.WaitForSingleObject.argtypes, kernel.WaitForSingleObject.restype = [ctypes.c_void_p, ctypes.c_uint32], ctypes.c_uint32
    handle = kernel.OpenProcess(0x1000 | 1 | 0x100000, False, record['pid'])
    if not handle:
        error = ctypes.get_last_error()
        if error == 87:  # ERROR_INVALID_PARAMETER: process no longer exists.
            return
        raise ctypes.WinError(error)  # Access/query failure is not proof of exit.
    try:
        image, size = ctypes.create_unicode_buffer(32768), ctypes.c_uint32(32768)
        creation, end, kern, user = (ctypes.c_uint64() for _ in range(4))
        if not kernel.QueryFullProcessImageNameW(handle, 0, image, ctypes.byref(size)) or not kernel.GetProcessTimes(
                handle, *map(ctypes.byref, (creation, end, kern, user))):
            raise ctypes.WinError(ctypes.get_last_error())
        if creation.value != record['creation']:
            return
        if os.path.normcase(image.value) != os.path.normcase(str(fixed_core)) or image.value != record['image']:
            raise ValueError('owned_process_image_changed')
        if not kernel.TerminateProcess(handle, 93):
            raise ctypes.WinError(ctypes.get_last_error())
        if kernel.WaitForSingleObject(handle, 5000) != 0:
            raise RuntimeError('owned_process_exit_unconfirmed')
    finally:
        kernel.CloseHandle(handle)


def service_state(metadata, running):
    from ruleproxy.windows_proxy_service import ServiceControl
    ServiceControl().verify(metadata)
    operation = 'Start-Service' if running else 'Stop-Service'
    desired = 'Running' if running else 'Stopped'
    ps(f"{operation} -Name RuleProxyControl -ErrorAction Stop;"
       f"(Get-Service RuleProxyControl).WaitForStatus('{desired}',[TimeSpan]::FromSeconds(20));$result='ok'", timeout=24)


def _recover_locked(state_path, best_effort=False):
    state = read_json(state_path)
    root, work = Path(state['root']), Path(state_path).parent
    sys.path.insert(0, str(root))
    from ruleproxy.windows_proxy_service import load_deployment, protected_path
    from ruleproxy.windows_global_guard import Guard
    from ruleproxy.windows_global_dns import DnsLease
    protected_path(work, private=True)
    metadata = load_deployment(root)
    result = {'schema_version': 1, 'recovered': False, 'errors': []}
    if best_effort:
        result['best_effort'] = True

    def terminate_cores():
        for name in ('core-owned.json', 'carrier-owned.json'):
            if (work / name).is_file():
                terminate_owned(read_json(work / name), root / 'bin/windows-amd64/mihomo.exe')

    def restore_dns():
        dns = DnsLease(metadata).normal_stop()
        if dns.get('active') is not False or dns.get('supported') is not True:
            raise RuntimeError('owned_dns_restore_unconfirmed')

    def restore_guard():
        guard = Guard(metadata).normal_stop()
        if guard.get('active') is not False:
            raise RuntimeError('owned_guard_restore_unconfirmed')

    def remove_route():
        ps("$s=Get-Content -LiteralPath $env:RP_CAPTURE_STATE -Raw|ConvertFrom-Json;"
           "$r=@(Get-NetRoute -DestinationPrefix '203.0.113.77/32' -InterfaceIndex $s.nic.index -PolicyStore ActiveStore -ErrorAction SilentlyContinue);"
           "foreach($x in $r){if($x.NextHop -ne $s.nic.gateway -or $x.RouteMetric -ne 1){throw 'test route identity changed'};"
           "$x|Remove-NetRoute -Confirm:$false -ErrorAction Stop};$result='ok'",
           {'RP_CAPTURE_STATE': str(state_path)})

    def restore_capture_checked():
        result['capture'] = restore_capture(state_path)
        if result['capture'].get('stopped') is not True:
            raise RuntimeError('owned_capture_restore_unconfirmed')

    # Strict mode keeps the first-failure evidence contract. Best-effort (CI reclaim)
    # attempts every step and reports recovered only when no step failed.
    steps = [lambda: service_state(metadata, False), terminate_cores, restore_dns]
    if not state.get('startup_smoke_only'):
        steps.append(lambda: scoped_guard(metadata, state['nonce']).normal_stop())
    steps.append(restore_guard)
    if state.get('route_created'):
        steps.append(remove_route)
    steps += [lambda: service_state(metadata, True), restore_capture_checked]
    try:
        for step in steps:
            try:
                step()
            except BaseException as error:
                if not best_effort:
                    raise
                result['errors'].append(type(error).__name__ + ':' + str(error)[:600])
        result['recovered'] = not result['errors']
    except BaseException as error:
        result['errors'].append(type(error).__name__ + ':' + str(error)[:600])
    write_json(work / ('ci-network-reclaim-result.json' if best_effort else 'recovery-result.json'), result)
    return result


def recover(state_path, best_effort=False):
    """A kernel mutex permits recovery after the orchestrator is abandoned.

    Best-effort CI reclaim proceeds without the mutex after the bounded wait:
    a wedged orchestrator holding it must not keep the runner offline.
    """
    state = read_json(state_path)
    kernel = ctypes.WinDLL('kernel32', use_last_error=True)
    kernel.CreateMutexW.argtypes, kernel.CreateMutexW.restype = [ctypes.c_void_p, ctypes.c_int, ctypes.c_wchar_p], ctypes.c_void_p
    kernel.WaitForSingleObject.argtypes, kernel.WaitForSingleObject.restype = [ctypes.c_void_p, ctypes.c_uint32], ctypes.c_uint32
    kernel.ReleaseMutex.argtypes, kernel.CloseHandle.argtypes = [ctypes.c_void_p], [ctypes.c_void_p]
    handle = kernel.CreateMutexW(None, False, 'Global\\RuleProxyCaptureRecovery-' + state['nonce'])
    if not handle:
        raise ctypes.WinError(ctypes.get_last_error())
    acquired = False
    try:
        # WAIT_ABANDONED is successful ownership after a crashed recovery worker.
        acquired = kernel.WaitForSingleObject(handle, 30000) in (0, 0x80)
        if not acquired and not best_effort:
            raise RuntimeError('recovery_mutex_timeout')
        result = _recover_locked(state_path, best_effort=best_effort)
        if not acquired:
            result['mutex_bypassed'] = True
        return result
    finally:
        if acquired:
            kernel.ReleaseMutex(handle)
        kernel.CloseHandle(handle)


def system_operation(state_path, operation):
    state, work = read_json(state_path), Path(state_path).parent
    if operation not in ('recover', 'scope-stop') and time.time() >= state.get('experiment_expires_unix', 0):
        raise RuntimeError('experiment_time_budget_exhausted')
    root = Path(state['root'])
    sys.path.insert(0, str(root))
    from ruleproxy.windows_proxy_service import load_deployment, protected_path
    from ruleproxy import windows_global_guard as guard
    protected_path(work, private=True)
    metadata = load_deployment(root)
    value = scoped_guard(metadata, state['nonce'])
    if operation == 'recover':
        reclaim = state.get('ci_network_reclaim') is True
        try:
            value = recover(state_path)
        except BaseException as error:
            if not reclaim:
                raise
            # A strict failure (e.g. mutex timeout) must not skip the CI reclaim below.
            value = {'recovered': False, 'errors': [type(error).__name__ + ':' + str(error)[:600]]}
        if value.get('recovered') is not True and reclaim:
            try:
                value['ci_network_reclaim'] = recover(state_path, best_effort=True)
            except BaseException as error:
                value['ci_network_reclaim'] = {'recovered': False, 'errors': [type(error).__name__ + ':' + str(error)[:600]]}
        return value
    if operation == 'scope-stop':
        return value.normal_stop()
    if operation == 'scope-apply':
        value._system_only()
        with guard._Engine() as engine:
            rules = (guard._Rule('block', 6, guard._BLOCK, 0,
                      (('app', 0, 12, engine.app_id(work / 'actor/python.exe')),)),)
            with engine.transaction():
                value._replace(engine, rules)
            if value._filters(engine) != value._expected(rules):
                raise RuntimeError('scoped_filter_readback_failed')
        return {'active': True, 'scope': 'test_actor_ipv6_loopback_action_only', 'native_qualified': False}
    if operation in ('carrier', 'dns-carrier'):
        config = {'mixed-port': state['carrier_port'], 'bind-address': '127.0.0.1', 'allow-lan': False,
            'mode': 'rule', 'log-level': 'error', 'interface-name': state['nic']['alias'],
            'tun': {'enable': False}, 'dns': {'enable': False},
            'rules': ['MATCH,DIRECT']}
        if operation == 'dns-carrier':
            config['rules'] = ['AND,((IP-CIDR,1.1.1.1/32,no-resolve),(DST-PORT,443)),DIRECT', 'MATCH,REJECT']
        path = work / 'carrier.json'
        write_json(path, config)
        if operation == 'dns-carrier':
            checked = subprocess.run([str(root / 'bin/windows-amd64/mihomo.exe'), '-t', '-d', str(work), '-f', str(path)],
                stdin=subprocess.DEVNULL, stdout=subprocess.DEVNULL, stderr=subprocess.STDOUT,
                timeout=5, creationflags=getattr(subprocess, 'CREATE_NO_WINDOW', 0), check=False)
            if checked.returncode:
                raise RuntimeError('dns_carrier_config_invalid')
        with (work / 'carrier-private.log').open('wb') as log:
            process = subprocess.Popen([str(root / 'bin/windows-amd64/mihomo.exe'), '-d', str(work), '-f', str(path)],
                stdin=subprocess.DEVNULL, stdout=log, stderr=subprocess.STDOUT,
                creationflags=getattr(subprocess, 'CREATE_NO_WINDOW', 0))
            write_json(work / 'carrier-owned.json', require_owned_identity(process.pid, root / 'bin/windows-amd64/mihomo.exe'))
            try:
                deadline = time.monotonic() + 160
                while process.poll() is None and time.monotonic() < deadline and not (work / 'carrier-stop').exists():
                    time.sleep(.2)
            finally:
                if process.poll() is None:
                    process.terminate()
                    process.wait(timeout=5)
        return {'completed': True}
    raise ValueError('unknown_system_operation')


def task(state_path, operation, *, wait=True, watchdog=False):
    state = read_json(state_path)
    work, root = Path(state_path).parent, Path(state['root'])
    name = 'RuleProxy-Capture-' + state['nonce'] + '-' + operation
    arguments = subprocess.list2cmdline(['-I', '-S', str(work / 'capture.py'), '--system-operation', operation,
                                       '--state', str(state_path)])
    script = ("Import-Module ScheduledTasks;"
        "$a=New-ScheduledTaskAction -Execute $env:RP_CAPTURE_PYTHON -Argument $env:RP_CAPTURE_ARGS;"
        "$p=New-ScheduledTaskPrincipal -UserId SYSTEM -LogonType ServiceAccount -RunLevel Highest;"
        "$s=New-ScheduledTaskSettingsSet -ExecutionTimeLimit (New-TimeSpan -Seconds 240) -StartWhenAvailable -MultipleInstances IgnoreNew;"
        "$t=New-ScheduledTaskTrigger -Once -At ((Get-Date).AddSeconds(" + (str(RECOVERY_DEADLINE_SECONDS) if watchdog else '31536000') + "));"
        "Register-ScheduledTask -TaskName $env:RP_CAPTURE_TASK -Action $a -Principal $p -Settings $s -Trigger $t -Force|Out-Null;"
        + ('' if watchdog else "Start-ScheduledTask -TaskName $env:RP_CAPTURE_TASK;") + "$result='ok'")
    (work / (operation + '.result.json')).unlink(missing_ok=True)
    ps(script, {'RP_CAPTURE_PYTHON': str(root / 'python/python.exe'), 'RP_CAPTURE_ARGS': arguments, 'RP_CAPTURE_TASK': name})
    if watchdog or not wait:
        return name
    result = work / (operation + '.result.json')
    deadline = time.monotonic() + operation_timeout(25)
    while not result.is_file() and time.monotonic() < deadline:
        time.sleep(.1)
    if not result.is_file():
        raise RuntimeError('system_operation_timeout:' + operation)
    value = read_json(result)
    if not value.get('ok'):
        raise RuntimeError('system_operation_failed:' + value.get('error', 'unknown'))
    return value['result']


def capture_probe(work, component, phase, run_actor):
    evidence = {'phase': phase}
    try:
        return _capture_probe(work, component, phase, run_actor, evidence)
    except BaseException as error:
        code = str(error).split(':', 1)[0]
        if not re.fullmatch(r'[a-z_]{1,80}', code):
            code = 'capture_operation_failed'
        evidence['error_type'] = type(error).__name__
        raise CaptureEvidenceError(code, evidence) from error


def _capture_probe(work, component, phase, run_actor, evidence):
    components = _capture_set(component)
    evidence['declared_components'] = components
    marker = ('RuleProxyCapture:' + phase + ':' + secrets.token_hex(8)).encode('ascii')
    base = work / ('wire-' + phase)
    started = False
    filtered = False
    state_path = work / 'state.json'
    state = read_json(state_path)
    state['capture'] = {'base': str(base), 'stopped': False, 'filter': CAPTURE_FILTER}
    write_json(state_path, state)
    try:
        install_capture_filter(evidence)
        filtered = True
        output = pktmon('start', '--capture', '--comp', ','.join(map(str, components)), '--pkt-size', 0,
                        '--file-name', str(base) + '.etl', '--file-size', 16, '--log-mode', 'multi-file')
        evidence['start'] = capture_cli_metadata(output, base)
        started = True
        result = run_actor(marker.decode('ascii'))
        evidence['actor'] = result
        time.sleep(.5)
        try:
            evidence['buffer_info'] = capture_cli_metadata(pktmon('status', '--buffer-info'), base)
        except Exception as error:
            # Optional diagnostics must never decide whether recovery runs.
            evidence['buffer_info'] = {'available': False, 'error_type': type(error).__name__}
    finally:
        if started:
            try:
                evidence['inventory_before_stop'] = capture_inventory(work, base)
            finally:
                evidence['restore'] = restore_capture(state_path)
            evidence['inventory_after_stop'] = capture_inventory(work, base)
        elif filtered:
            evidence['restore'] = restore_capture(state_path)
    time.sleep(.2)  # One bounded observation of post-stop filesystem visibility.
    inventory = evidence['inventory_after_flush_wait'] = capture_inventory(work, base)
    sources = sorted(work.glob(base.name + '*.etl'))
    if not sources:
        raise RuntimeError('capture_files_missing')
    if len(sources) > 4:
        raise RuntimeError('capture_file_count_exceeded')
    if inventory['matching_etl_bytes'] > MAX_CAPTURE:
        raise RuntimeError('capture_total_bytes_exceeded')
    if any(not item['regular_file'] for item in inventory['files'] if item['matches_expected_capture_glob']):
        raise RuntimeError('capture_file_not_regular')
    values = evidence['component_results'] = {}
    for identity in components:
        value = values[str(identity)] = {'tcp_syn': 0, 'udp_marker': 0, 'packets_parsed': 0, 'captures': []}
        evidence['conversion_component'] = identity
        for source in sources:
            pcap = source.with_name(source.stem + '.component-' + str(identity) + '.pcapng')
            pktmon('etl2pcap', source, '--component-id', identity, '--out', pcap)
            summary = pcapng_counts(pcap, marker)
            for key in ('tcp_syn', 'udp_marker', 'packets_parsed'):
                value[key] += summary[key]
            value['captures'].append({'sha256': summary['sha256'], 'bytes': summary['bytes']})
    counts = aggregate_capture_components(components, values, len(sources))
    evidence.pop('conversion_component', None)
    counts['actor'] = result
    counts['capture_diagnostics'] = evidence
    counts['capture_loss_verified'] = evidence['capture_loss_verified'] = capture_loss_verified(evidence)
    if not counts['capture_loss_verified']:
        raise RuntimeError('capture_loss_unverified')
    return counts


def unused_port():
    with socket.socket() as stream:
        stream.bind(('127.0.0.1', 0))
        return stream.getsockname()[1]


def run_actor(work, request):
    process = subprocess.run([str(work / 'actor/python.exe'), '-I', '-S', str(work / 'capture.py'),
        '--actor-json', json.dumps(request)], stdin=subprocess.DEVNULL, stdout=subprocess.PIPE,
        stderr=subprocess.PIPE, timeout=operation_timeout(6), creationflags=getattr(subprocess, 'CREATE_NO_WINDOW', 0))
    if process.returncode or len(process.stdout) > 16384:
        raise RuntimeError('actor_process_failed')
    return json.loads(process.stdout.decode('utf-8'))


def scoped_ipv6_preflight(work, state_path):
    echo = LocalEcho6()
    request = {'marker': 'RuleProxyCapture:ipv6-scope:' + secrets.token_hex(8), 'host': '::1', 'family': 6,
               'tcp_port': echo.tcp_port, 'udp_port': echo.udp_port, 'echo': True}
    result = {'scope': 'actor_appid_ipv6_loopback_wfp_action_only', 'public_ipv6_proof': False}
    try:
        result['before'] = run_actor(work, request)
        if not all(result['before'][kind]['received_echo'] for kind in ('tcp', 'udp')):
            raise RuntimeError('ipv6_loopback_positive_control_missing')
        result['filter'] = task(state_path, 'scope-apply')
        before = dict(echo.counts)
        result['guarded'] = run_actor(work, request)
        result['fixture_unchanged'] = echo.counts == before
        if any(result['guarded'][kind]['received_echo'] for kind in ('tcp', 'udp')) or not result['fixture_unchanged']:
            raise RuntimeError('scoped_ipv6_filter_did_not_block')
    finally:
        task(state_path, 'scope-stop')
        echo.close()
    echo = LocalEcho6()
    try:
        request['tcp_port'], request['udp_port'] = echo.tcp_port, echo.udp_port
        result['after'] = run_actor(work, request)
        result['passed'] = all(result['after'][kind]['received_echo'] for kind in ('tcp', 'udp'))
    finally:
        echo.close()
    return result


def carrier_control(port, address):
    with socket.create_connection(('127.0.0.1', port), timeout=operation_timeout(3)) as connection:
        connection.settimeout(operation_timeout(3))
        connection.sendall(b'\x05\x01\x00')
        if exact(connection, 2) != b'\x05\x00':
            raise RuntimeError('carrier_socks_greeting')
        connection.sendall(b'\x05\x01\x00' + encode_address(address, 80))
        if exact(connection, 3) != b'\x05\x00\x00':
            raise RuntimeError('carrier_connect_failed')
        socks_address(connection)
        connection.sendall(b'GET / HTTP/1.1\r\nHost: example.com\r\nConnection: close\r\n\r\n')
        data = bytearray()
        while len(data) < 65536:
            connection.settimeout(operation_timeout(3))
            chunk = connection.recv(4096)
            if not chunk:
                break
            data.extend(chunk)
        return b'Example Domain' in data and data.startswith(b'HTTP/1.')


def private_acl_script():
    # SID strings select the account-name overload and fail translation. Pass
    # real SecurityIdentifier objects to the IdentityReference overload.
    return ("$acl=New-Object Security.AccessControl.DirectorySecurity;"
        "$acl.SetOwner((New-Object Security.Principal.SecurityIdentifier('S-1-5-32-544')));"
        "$acl.SetAccessRuleProtection($true,$false);foreach($sid in @('S-1-5-18','S-1-5-32-544')){"
        "$identity=New-Object Security.Principal.SecurityIdentifier($sid);"
        "$acl.AddAccessRule((New-Object Security.AccessControl.FileSystemAccessRule($identity,'FullControl',"
        "'ContainerInherit,ObjectInherit','None','Allow')))};")


def native_ipv6_diagnostics():
    """Bounded read-only address/route facts; never export host IP inventories."""
    script = r"""
function Is-Unicast6($text) {
  $ip=[Net.IPAddress]::Parse([string]$text)
  # Mihomo tests Unmap().Is6() before IsGlobalUnicast(): mapped IPv4 is excluded.
  return ($ip.AddressFamily -eq [Net.Sockets.AddressFamily]::InterNetworkV6 -and
    -not $ip.IsIPv6Multicast -and -not $ip.IsIPv6LinkLocal -and -not $ip.IsIPv4MappedToIPv6 -and
    -not $ip.Equals([Net.IPAddress]::IPv6Any) -and -not $ip.Equals([Net.IPAddress]::IPv6Loopback))
}
$addresses=@(Get-NetIPAddress -AddressFamily IPv6 -PolicyStore ActiveStore -ErrorAction Stop)
$tun=@(Get-NetAdapter -Name 'RuleProxyTun' -ErrorAction SilentlyContinue)
if($tun.Count -gt 1){throw 'ambiguous fixed tun'}
$tunIndex=if($tun.Count -eq 1){[int]$tun[0].ifIndex}else{-1}
$global=@($addresses|Where-Object {Is-Unicast6 $_.IPAddress})
$tunAddresses=@($addresses|Where-Object {$_.InterfaceIndex -eq $tunIndex})
$fixed=@($tunAddresses|Where-Object {$_.IPAddress -eq 'fdfe:dcba:8879::1'})
$routes=@(Get-NetRoute -AddressFamily IPv6 -PolicyStore ActiveStore -ErrorAction Stop|
  Where-Object {$_.DestinationPrefix -in @('::/0','::/1','8000::/1')})
$routeRows=@($routes|Sort-Object DestinationPrefix,InterfaceIndex,RouteMetric|Select-Object -First 8|ForEach-Object {
  $next=[Net.IPAddress]::Parse([string]$_.NextHop)
  $kind=if($next.Equals([Net.IPAddress]::IPv6Any)){'on_link'}elseif($next.IsIPv6LinkLocal){'link_local'}else{'other'}
  @{prefix=[string]$_.DestinationPrefix;interface_index=[int]$_.InterfaceIndex;is_tun=($_.InterfaceIndex -eq $tunIndex);
    metric=[int]$_.RouteMetric;next_hop_kind=$kind}
})
$wanted=@($routes|ForEach-Object {[int]$_.InterfaceIndex})+@($tunIndex)
$interfaces=@(Get-NetIPInterface -AddressFamily IPv6 -PolicyStore ActiveStore -ErrorAction Stop|
  Where-Object {$_.InterfaceIndex -in $wanted})
$interfaceRows=@($interfaces|Sort-Object InterfaceIndex|Select-Object -First 8|ForEach-Object {
  @{interface_index=[int]$_.InterfaceIndex;is_tun=($_.InterfaceIndex -eq $tunIndex);
    connected=($_.ConnectionState -eq 'Connected');mtu=[int]$_.NlMtu;metric=[int]$_.InterfaceMetric}
})
$registry=Get-Item -LiteralPath 'HKLM:\SYSTEM\CurrentControlSet\Services\Tcpip6\Parameters' -ErrorAction Stop
$present=(@($registry.GetValueNames()) -contains 'DisabledComponents')
$disabled=@{present=$present;dword=$null}
if($present){
  if($registry.GetValueKind('DisabledComponents') -ne [Microsoft.Win32.RegistryValueKind]::DWord){throw 'unexpected IPv6 registry type'}
  $disabled.dword=[long]$registry.GetValue('DisabledComponents') -band 4294967295L
}
$result=@{available=$true;active_ipv6_address_count=$addresses.Count;global_unicast_ipv6_count=$global.Count;
  non_tun_global_unicast_ipv6_count=@($global|Where-Object {$_.InterfaceIndex -ne $tunIndex}).Count;
  tun_present=($tunIndex -gt 0);tun_ipv6_address_count=$tunAddresses.Count;fixed_tun_ipv6_present=($fixed.Count -eq 1);
  fixed_tun_ipv6_preferred=(@($fixed|Where-Object {$_.AddressState -eq 'Preferred'}).Count -eq 1);
  fixed_tun_ipv6_prefix_126=(@($fixed|Where-Object {$_.PrefixLength -eq 126}).Count -eq 1);
  default_route_count=$routes.Count;tun_default_route_count=@($routes|Where-Object {$_.InterfaceIndex -eq $tunIndex}).Count;
  default_routes=$routeRows;route_rows_truncated=($routes.Count -gt 8);interfaces=$interfaceRows;
  interface_rows_truncated=($interfaces.Count -gt 8);disabled_components=$disabled}|ConvertTo-Json -Depth 5 -Compress
"""
    try:
        value = json.loads(ps(script, timeout=8))
        if not isinstance(value, dict) or value.get('available') is not True:
            raise ValueError('ipv6_diagnostic_schema')
        return value
    except Exception as error:
        return {'available': False, 'code': 'native_ipv6_diagnostics_unavailable', 'error_type': type(error).__name__}


def prepare_dns_smoke(work, state_path, fixture, report, budget, names):
    import importlib.util
    from ruleproxy.windows_proxy_service import _tcp_connections
    budget.stage('dns_carrier_prepare')
    budget.require(105)
    helper = work / 'dns-fixture.py'
    shutil.copy2(Path(__file__).with_name('windows_global_dns_fixture.py'), helper)
    digest = hashlib.sha256(helper.read_bytes()).hexdigest()
    if digest != 'ea4e180ea6f02912341aa81041fdc71e663bb6095aeefaa9b5fe1733ea57ca7d':
        raise RuntimeError('dns_fixture_source_changed')
    spec = importlib.util.spec_from_file_location('ruleproxy_dns_smoke_fixture', helper)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    state = read_json(state_path)
    state['nic'] = default_nic()  # Read-only underlay binding, no test route.
    write_json(state_path, state)
    relay = module.DohRelay(state['carrier_port'], timeout=10)
    fixture.doh_relay = relay
    names.append(task(state_path, 'dns-carrier', wait=False))
    deadline = time.monotonic() + operation_timeout(3)
    ready = False
    while time.monotonic() < deadline:
        try:
            with socket.create_connection(('127.0.0.1', state['carrier_port']), timeout=.1) as connection:
                if (work / 'carrier-owned.json').is_file():
                    record = read_json(work / 'carrier-owned.json')
                    held = require_owned_identity(record['pid'], Path(state['root']) / 'bin/windows-amd64/mihomo.exe')
                    peer = connection.getsockname()
                    ready = held == record and any(row['state'] == 5 and row['pid'] == record['pid']
                        and row['local'] == '127.0.0.1' and row['local_port'] == state['carrier_port']
                        and row['remote'] == peer[0] and row['remote_port'] == peer[1]
                        for row in _tcp_connections(socket.AF_INET))
        except OSError:
            pass
        if ready:
            break
        time.sleep(.05)
    if not ready:
        raise RuntimeError('dns_carrier_not_ready')
    report['dns_carrier'] = {'scope': 'fixed_SYSTEM_core_bound_underlay_doh_only',
        'underlay_interface_index': state['nic']['index'], 'allowed_forward': '1.1.1.1:443',
        'fixture_sha256': digest, 'connection_process_identity_verified': True}
    report['dns_fixture_sha256'] = digest
    return {'module': module, 'relay': relay}


def run_dns_smoke(context, report, budget):
    module, relay = context['module'], context['relay']
    budget.require(35)  # Queries <=19 seconds, then owned carrier/core cleanup.
    value = report['dns_smoke'] = {'passed': False, 'queries': {}, 'scope': 'real_doh_selected_node_and_nrpt_smoke_only'}
    value['before'] = relay.snapshot()
    expected = '1.2.3.4'
    name = module.query_name(expected)
    value['queries']['system_default'] = module.system_dns_query(name, expected, timeout=3)
    for peer, family in (('198.18.0.2', '4'), ('fdfe:dcba:8879::2', '6')):
        for protocol in ('udp', 'tcp'):
            value['queries'][protocol + family] = module.raw_dns_query(peer, name=module.query_name(expected),
                expected_ip=expected, protocol=protocol, timeout=2.5)
    value['positive'] = relay.snapshot()
    positive_queries = list(value['queries'].values())
    if (len(positive_queries) != 5
            or any(item.get('validated') is not True or item.get('addresses') != [expected] for item in positive_queries)
            or len({item.get('query_name') for item in positive_queries}) != 5):
        raise RuntimeError('dns_positive_response_or_uniqueness_invalid')
    # DoH legitimately reuses an already admitted HTTP/2 TLS connection. The
    # fresh DNS names and byte deltas prove work, not a new TLS admission count.
    if not (value['positive']['accepted'] > 0 and value['positive']['accepted'] >= value['before']['accepted']
            and all(value['positive'][key] > value['before'][key] for key in ('bytes_to_resolver', 'bytes_to_client'))):
        raise RuntimeError('dns_positive_selected_node_unobserved')
    value['disabled'] = relay.disable()
    if value['disabled']['active'] != 0:
        raise RuntimeError('dns_relay_close_unconfirmed')
    name = module.query_name(expected)
    failed = False
    try:
        module.system_dns_query(name, expected, timeout=3)
    except module.FixtureError as error:
        if error.code != 'system_dns_child_failed':
            raise
        failed = True
    except subprocess.TimeoutExpired:
        failed = True
    value['negative'] = {'unique_query_name': name, 'failed': failed, 'relay': relay.snapshot()}
    if not failed or value['negative']['relay']['rejected'] <= value['disabled']['rejected']:
        raise RuntimeError('dns_disabled_control_not_observed')
    relay.enable()
    value['queries']['system_restored'] = module.system_dns_query(module.query_name(expected), expected, timeout=3)
    value['restored'] = relay.snapshot()
    if not (value['restored']['accepted'] > value['disabled']['accepted']
            and all(value['restored'][key] > value['disabled'][key] for key in ('bytes_to_resolver', 'bytes_to_client'))):
        raise RuntimeError('dns_restored_selected_node_unobserved')
    results = list(value['queries'].values())
    if (any(item.get('validated') is not True or item.get('addresses') != [expected] for item in results)
            or len({item.get('query_name') for item in results} | {name}) != 7):
        raise RuntimeError('dns_smoke_response_or_uniqueness_invalid')
    value['passed'] = True
    report['dns_smoke_passed'] = True


def startup_smoke(root, native, metadata, source, fixture, work, report, budget, *, dns_context=None):
    """Real TUN startup/echo lifecycle only; never a physical no-leak proof."""
    from ruleproxy.windows_global_guard import Guard
    from ruleproxy.windows_global_dns import DnsLease
    budget.stage('ipv6_native_before_core')
    report['native_ipv6_before_core'] = native_ipv6_diagnostics()
    budget.stage('global_start')
    budget.require(90)
    started = native.start(source, secrets.token_urlsafe(24), unused_port(), unused_port(),
                           'CaptureEcho', require_strict=False)
    if started.get('running') is not True:
        raise RuntimeError('real_global_core_not_running')
    report['core_started'] = True
    core = root / 'bin/windows-amd64/mihomo.exe'
    identity = require_owned_identity(started['pid'], core)
    write_json(work / 'core-owned.json', identity)
    budget.require(1)
    budget.stage('ipv6_native_after_start')
    report['native_ipv6_after_start'] = native_ipv6_diagnostics()
    budget.stage('tun_identity_readback')
    report['tun_identity'] = tun_identity_receipt(started)
    if not (report['tun_identity']['identity_matches'] and report['tun_identity']['start_guard_tun_ready']):
        raise RuntimeError('tun_identity_unconfirmed')
    report['tun_echo'] = {}
    for family, host in ((4, TUN4), (6, TUN6)):
        budget.stage('tun_echo_ipv' + str(family))
        budget.require(3)
        report['tun_echo'][str(family)] = actor({'marker': 'RuleProxyCapture:startup:' + secrets.token_hex(8),
            'host': host, 'family': family, 'tcp_port': TCP_PORT, 'udp_port': UDP_PORT, 'echo': True})
    report['synthetic_node_counts'] = dict(fixture.counts)
    echo = all(report['tun_echo'][str(family)][protocol].get('received_echo') is True
               and report['tun_echo'][str(family)][protocol].get('socket_ok') is True
               for family in (4, 6) for protocol in ('tcp', 'udp'))
    received = all(type(fixture.counts.get(key)) is int and fixture.counts[key] > 0
                   for key in ('tcp4', 'tcp6', 'udp4', 'udp6'))
    report['tun_tcp_udp_v4_v6_passed'] = echo and received
    if dns_context is not None:
        budget.stage('dns_smoke_queries')
        try:
            run_dns_smoke(dns_context, report, budget)
        except Exception as error:
            code = getattr(error, 'code', str(error).split(':', 1)[0])
            report.setdefault('dns_smoke', {})['error'] = code if re.fullmatch(r'[a-z_]{1,80}', code) else 'dns_smoke_operation_failed'
            report['dns_smoke_passed'] = False
        finally:
            closed = dns_context['relay'].close()
            report.setdefault('dns_smoke', {})['closed'] = closed
            if closed.get('active') != 0 or closed.get('closed') is not True:
                raise RuntimeError('dns_relay_close_unconfirmed')
            (work / 'carrier-stop').touch()
            terminate_owned(read_json(work / 'carrier-owned.json'), core)
            report['dns_carrier_closed_before_core_death'] = True
    budget.stage('core_terminate')
    terminate_owned(identity, core)
    report['owned_core_terminated'] = True
    budget.stage('core_dead_state_readback')
    guard, dns = Guard(metadata).status(), DnsLease(metadata).status(refresh=True)
    report['guard_after_core_death'] = {key: guard.get(key) for key in ('supported', 'active', 'persistent', 'tun_ready')}
    report['dns_after_core_death'] = {key: dns.get(key) for key in ('supported', 'active', 'effective', 'fresh', 'state')}
    retained = (guard.get('supported') is True and guard.get('active') is True and guard.get('persistent') is True
                and dns.get('supported') is True and dns.get('active') is True and dns.get('fresh') is True)
    report['state_retained_after_core_death'] = retained
    report['packet_fail_closed_proven'] = False
    budget.stage('explicit_global_stop')
    native.stop()
    guard, dns = Guard(metadata).status(), DnsLease(metadata).status(refresh=True)
    report['explicit_global_stop'] = (guard.get('supported') is True and guard.get('active') is False
                                      and dns.get('supported') is True and dns.get('active') is False)
    if not report['explicit_global_stop']:
        raise RuntimeError('explicit_global_stop_not_restored')
    report['startup_smoke_passed'] = (echo and received and retained
                                    and (dns_context is None or report.get('dns_smoke_passed') is True))
    if not report['startup_smoke_passed']:
        raise RuntimeError('startup_smoke_checks_failed')


def run(arguments):
    global _ACTIVE_BUDGET
    run_started = time.monotonic()
    if os.name != 'nt' or not arguments.ack_disposable_windows:
        raise RuntimeError('explicit_disposable_windows_ack_required')
    root = arguments.installed_root.resolve(strict=True)
    sys.path.insert(0, str(root))
    from ruleproxy.windows_proxy_service import load_deployment, protected_path
    from ruleproxy.windows_app_process import _get_api
    from ruleproxy.windows_global_runtime import Runtime
    from ruleproxy.windows_proxy_client import current_user_sid
    from ruleproxy.windows_global_guard import Guard
    from ruleproxy.windows_global_dns import DnsLease
    metadata = load_deployment(root)
    if current_user_sid() != metadata['owner_sid']:
        raise RuntimeError('run_as_installing_desktop_owner_not_system')
    smoke_only = getattr(arguments, 'startup_smoke_only', False)
    dns_requested = getattr(arguments, 'dns_smoke', False)
    if dns_requested and not smoke_only:
        raise RuntimeError('dns_smoke_requires_startup_smoke_only')
    if smoke_only:
        if arguments.read_only_components:
            raise RuntimeError('startup_smoke_mode_conflict')
        # The service no longer needs an elevated caller, but this harness registers its
        # own SYSTEM recovery tasks, so its own token must still be elevated.
        if _get_api().is_elevated() is not True:
            raise RuntimeError('startup_smoke_requires_actual_elevation')
    if arguments.read_only_components:
        _nic, _component, evidence = nic_components()
        arguments.output.parent.mkdir(parents=True, exist_ok=True)
        write_json(arguments.output, {'schema_version': 1, 'read_only_components': True,
            'network_modified': False, 'strict_qualified': False, 'components': evidence})
        return 0
    guard_initial, dns_initial = Guard(metadata).status(), DnsLease(metadata).status(refresh=True)
    if (guard_initial.get('active') or dns_initial.get('active')
            or smoke_only and (guard_initial.get('supported') is not True or guard_initial.get('active') is not False
                               or dns_initial.get('supported') is not True or dns_initial.get('active') is not False)):
        raise RuntimeError('existing_guard_or_dns_lease_refused')
    native = Runtime(root)
    initial = native.status()
    if initial.get('supported') is not True:
        raise RuntimeError('installed_global_service_not_supported')
    if initial.get('running'):
        raise RuntimeError('existing_global_core_refused')
    nonce = secrets.token_hex(8)
    work = Path(os.environ['ProgramData']) / 'RuleProxy-Web' / ('capture-' + nonce)
    work.mkdir()
    ps(private_acl_script() + "Set-Acl -LiteralPath $env:RP_CAPTURE_WORK -AclObject $acl;$result='ok'",
       {'RP_CAPTURE_WORK': str(work)})
    protected_path(work, private=True)
    shutil.copy2(__file__, work / 'capture.py')
    shutil.copytree(root / 'python', work / 'actor')
    # Private embedded interpreter is a distinct WFP AppId for scoped preflight.
    state_path = work / 'state.json'
    state = {'schema_version': 1, 'root': str(root), 'nonce': nonce, 'route_created': False,
             'carrier_port': unused_port()}
    if smoke_only:
        state['startup_smoke_only'] = True
    # Read by the SYSTEM watchdog, which runs without the GitHub environment.
    state['ci_network_reclaim'] = os.environ.get('GITHUB_ACTIONS') == 'true'
    write_json(state_path, state)
    report = {'schema_version': 1, 'mode': 'disposable_windows_native_capture',
        'strict_qualified': False, 'ipv6_public_egress_qualified': False,
        'dns_qualified': False, 'rdp_qualified': False, 'phases': {}, 'passed': False,
        'raw_capture_exported': False, 'proxy_node_synthetic_only': True,
        'carrier_scope': 'read_only_example_com_http_over_fixed_system_core_bound_physical_interface',
        'service_death_scope': 'real_scm_stop_after_actual_core_termination',
        'fixed_core_sha256': metadata['files']['bin/windows-amd64/mihomo.exe'],
        'guard_source_sha256': hashlib.sha256((root / 'ruleproxy/windows_global_guard.py').read_bytes()).hexdigest(),
        'windows_build': list(sys.getwindowsversion()[:3])}
    if smoke_only:
        report.update(mode='disposable_windows_tun_startup_smoke', startup_smoke_passed=False,
            ipv4_physical_scope_passed=False, physical_qualified=False, packet_fail_closed_proven=False,
            carrier_scope='not_exercised', service_death_scope='not_exercised',
            scope='synthetic_loopback_node_tun_startup_identity_and_state_readback_only')
        if dns_requested:
            report.update(dns_smoke_requested=True, dns_smoke_passed=False)
    fixture, names = None, []
    budget = ExperimentBudget()
    state['experiment_expires_unix'] = time.time() + EXPERIMENT_BUDGET_SECONDS
    write_json(state_path, state)
    _ACTIVE_BUDGET = budget
    report['time_budget'] = {'cooperative_experiment_seconds': EXPERIMENT_BUDGET_SECONDS,
        'independent_system_recovery_trigger_seconds': RECOVERY_DEADLINE_SECONDS,
        'orchestrator_hard_deadline_seconds': HARD_DEADLINE_SECONDS,
        'broker_calls_hard_interrupted': False, 'stages': budget.stages}
    finished = threading.Event()
    threading.Thread(target=_hard_deadline, daemon=True, args=(finished, report, budget,
        (str(work), str(root), nonce), work, arguments.output, threading.get_ident())).start()
    try:
        budget.stage('register_independent_recovery')
        names.append(task(state_path, 'recover', wait=False, watchdog=True))
        budget.stage('fixture_prepare')
        fixture = EchoNode()
        source = fixture_source(fixture.port)
        budget.stage('fixture_dns_preflight')
        report['fixture_dns'] = fixture_dns_preflight()
        if smoke_only:
            dns_context = prepare_dns_smoke(work, state_path, fixture, report, budget, names) if dns_requested else None
            startup_smoke(root, native, metadata, source, fixture, work, report, budget, dns_context=dns_context)
        else:
            budget.stage('physical_component_identity')
            nic, component, evidence = nic_components()
            report['components'] = evidence
            if component is None:
                raise ValueError(evidence['selection_error'])
            capture_components = evidence['capture_components']
            state['nic'] = nic
            budget.stage('scoped_ipv6_action')
            report['ipv6_scoped_action'] = scoped_ipv6_preflight(work, state_path)
            if not report['ipv6_scoped_action']['passed']:
                raise RuntimeError('scoped_ipv6_restore_failed')
            budget.stage('physical_route_prepare')
            ps("if(@(Get-NetRoute -DestinationPrefix '203.0.113.77/32' -ErrorAction SilentlyContinue).Count){throw 'test prefix already owned'};$result='ok'")
            state['route_created'] = True  # watchdog covers a crash immediately after route creation
            write_json(state_path, state)
            ps("$s=Get-Content -LiteralPath $env:RP_CAPTURE_STATE -Raw|ConvertFrom-Json;"
               "New-NetRoute -DestinationPrefix '203.0.113.77/32' -InterfaceIndex $s.nic.index -NextHop $s.nic.gateway "
               "-RouteMetric 1 -PolicyStore ActiveStore -ErrorAction Stop|Out-Null;$result='ok'", {'RP_CAPTURE_STATE': str(state_path)})
            carrier_address = socket.getaddrinfo('example.com', 80, socket.AF_INET, socket.SOCK_STREAM)[0][4][0]
            budget.stage('system_carrier_start')
            names.append(task(state_path, 'carrier', wait=False))
            deadline = time.monotonic() + 10
            while not (work / 'carrier-owned.json').is_file() and time.monotonic() < deadline:
                time.sleep(.1)
            # A fresh actor process is used for each capture: no cached ALE flow.
            def physical(marker):
                request = {'marker': marker, 'host': DEST4, 'family': 4, 'source': nic['source'],
                           'tcp_port': TCP_PORT, 'udp_port': UDP_PORT, 'echo': False}
                return run_actor(work, request)
            budget.stage('physical_positive_before')
            report['phases']['outside_before'] = capture_probe(work, capture_components, 'before', physical)
            # Missing wire positives invalidate physical evidence, but a complete,
            # loss-free capture can still precede this bounded TUN/GUID experiment.
            # It can never produce passed=True without both physical controls.
            record_physical_control(report, 'before')
            # The broker's fixed global_start response wait is 90 seconds. Do not
            # begin it if the remaining cooperative budget cannot cover that wait.
            budget.stage('global_start')
            budget.require(90)
            started = native.start(source, secrets.token_urlsafe(24), unused_port(), unused_port(), 'CaptureEcho', require_strict=False)
            budget.require(1)
            if not started.get('running'):
                raise RuntimeError('real_global_core_not_running')
            write_json(work / 'core-owned.json', require_owned_identity(started['pid'], root / 'bin/windows-amd64/mihomo.exe'))
            budget.stage('tun_identity_readback')
            report['tun_identity'] = tun_identity_receipt(started)
            if not (report['tun_identity']['identity_matches'] and report['tun_identity']['start_guard_tun_ready']):
                raise RuntimeError('tun_identity_unconfirmed')
            budget.stage('physical_running_guard')
            report['phases']['running_guard'] = capture_probe(work, capture_components, 'running', physical)
            budget.stage('system_carrier_http')
            report['system_core_carrier_http'] = carrier_control(state['carrier_port'], carrier_address)
            # No second privileged Mihomo is left alive during the core-death proof.
            terminate_owned(read_json(work / 'carrier-owned.json'), root / 'bin/windows-amd64/mihomo.exe')
            report['tun_echo'] = {}
            for family, host in ((4, TUN4), (6, TUN6)):
                budget.stage('tun_echo_ipv' + str(family))
                budget.require(3)
                result = actor({'marker': 'RuleProxyCapture:tun:' + nonce, 'host': host, 'family': family,
                                'tcp_port': TCP_PORT, 'udp_port': UDP_PORT, 'echo': True})
                report['tun_echo'][str(family)] = result
            report['synthetic_node_counts'] = dict(fixture.counts)
            budget.stage('core_terminate')
            terminate_owned(read_json(work / 'core-owned.json'), root / 'bin/windows-amd64/mihomo.exe')
            time.sleep(.5)
            budget.stage('physical_core_dead')
            report['phases']['core_dead'] = capture_probe(work, capture_components, 'coredead', physical)
            budget.stage('service_stop')
            service_state(metadata, False)
            budget.stage('physical_service_stopped')
            report['phases']['service_stopped'] = capture_probe(work, capture_components, 'servicedead', physical)
            report['guard_after_service_death'] = {key: value for key, value in Guard(metadata).status().items()
                if key in ('active', 'persistent', 'native_qualified', 'strict_isolation')}
            # Restart the actual broker and exercise its user-visible explicit
            # global_stop protocol before emergency watchdog cleanup is invoked.
            budget.stage('service_restart')
            service_state(metadata, True)
            budget.stage('explicit_global_stop')
            native.stop()
            stopped_guard, stopped_dns = Guard(metadata).status(), DnsLease(metadata).status(refresh=True)
            report['explicit_global_stop'] = (stopped_guard.get('active') is False
                                              and stopped_dns.get('active') is False)
            if not report['explicit_global_stop']:
                raise RuntimeError('explicit_global_stop_not_restored')
            budget.stage('explicit_recovery')
            restoration = recover(state_path)
            report['recovery'] = restoration
            if not restoration.get('recovered'):
                raise RuntimeError('precise_restore_failed')
            budget.stage('physical_positive_after')
            report['phases']['outside_after'] = capture_probe(work, capture_components, 'after', physical)
            denied = (all(protected_components_clear(report['phases'][phase], capture_components)
                          for phase in ('running_guard', 'core_dead', 'service_stopped'))
                      and all(valid_physical_attempt(report['phases'][phase]['actor'])
                          for phase in ('running_guard', 'core_dead', 'service_stopped')))
            after_control = record_physical_control(report, 'after')
            controls = report.get('physical_positive_before_valid') is True and after_control
            tun = all(report['tun_echo'][str(family)][protocol]['received_echo']
                      for family in (4, 6) for protocol in ('tcp', 'udp'))
            report['ipv4_physical_scope_passed'] = controls and denied
            report['tun_tcp_udp_v4_v6_passed'] = tun
            guard_owned = (report['guard_after_service_death'].get('active') is True
                           and report['guard_after_service_death'].get('persistent') is True)
            report['passed'] = (controls and denied and tun and guard_owned
                and report['system_core_carrier_http'] and report['ipv6_scoped_action']['passed'])
    except BaseException as error:
        report['failed_stage'] = budget.stages[-1]['stage'] if budget.stages else 'unknown'
        if isinstance(error, CaptureEvidenceError):
            report['capture_failure'] = error.evidence
        report['error'] = type(error).__name__ + ':' + str(error)[:900]
    finally:
        # Cleanup must remain possible after the experiment budget expires.
        # The independent SYSTEM task never inherits this in-process budget.
        _ACTIVE_BUDGET = None
        report['time_budget']['experiment_elapsed_seconds'] = round(time.monotonic() - budget.started, 3)
        budget.stage('final_recovery')
        (work / 'carrier-stop').touch()
        if fixture is not None:
            fixture.close()
        try:
            restoration = recover(state_path)
        except BaseException as error:
            restoration = {'recovered': False, 'errors': [type(error).__name__ + ':' + str(error)[:600]]}
        report['recovery'] = restoration
        if restoration.get('recovered') is not True and state.get('ci_network_reclaim') is True:
            # Best-effort reclaim is diagnostic only: it never sets recovered, passed or the exit code.
            try:
                report['ci_network_reclaim'] = recover(state_path, best_effort=True)
            except BaseException as error:
                report['ci_network_reclaim'] = {'recovered': False, 'errors': [type(error).__name__ + ':' + str(error)[:600]]}
        if restoration.get('recovered'):
            # Watchdog is removed only after independently verified restoration.
            names += ['RuleProxy-Capture-' + nonce + '-' + op for op in ('scope-apply', 'scope-stop')]
            for name in names:
                try:
                    ps("Unregister-ScheduledTask -TaskName $env:RP_CAPTURE_TASK -Confirm:$false -ErrorAction SilentlyContinue;$result='ok'",
                       {'RP_CAPTURE_TASK': name})
                except BaseException as error:
                    report.setdefault('task_cleanup_errors', []).append(type(error).__name__ + ':' + str(error)[:300])
        else:
            report['passed'] = False
            if smoke_only:
                report['startup_smoke_passed'] = False
                if dns_requested:
                    report['dns_smoke_passed'] = False
        arguments.output.parent.mkdir(parents=True, exist_ok=True)
        budget.stage(None)
        report['time_budget']['total_elapsed_seconds'] = round(time.monotonic() - run_started, 3)
        write_json(arguments.output, report)
        finished.set()
    accepted = report.get('startup_smoke_passed') is True if smoke_only else report['passed']
    _ci_annotation('notice' if accepted and report['recovery'].get('recovered') else 'error', 'Global capture summary',
                   _ci_summary(report, budget, (str(work), str(root), nonce)))
    print(json.dumps({'passed': report['passed'], 'startup_smoke_passed': report.get('startup_smoke_passed'), 'strict_qualified': False,
                      'recovered': report['recovery'].get('recovered'), 'summary': str(arguments.output)}))
    return 0 if accepted and report['recovery'].get('recovered') else 1


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--ack-disposable-windows', action='store_true')
    parser.add_argument('--read-only-components', action='store_true')
    parser.add_argument('--startup-smoke-only', action='store_true',
                        help='Bounded TUN startup/echo/state readback only; never physical no-leak acceptance')
    parser.add_argument('--dns-smoke', action='store_true',
                        help='Opt-in genuine DoH/NRPT smoke; requires --startup-smoke-only')
    parser.add_argument('--installed-root', type=Path)
    parser.add_argument('--output', type=Path)
    parser.add_argument('--state', type=Path)
    parser.add_argument('--system-operation', choices=('scope-apply', 'scope-stop', 'carrier', 'dns-carrier', 'recover'))
    parser.add_argument('--actor-json')
    args = parser.parse_args()
    if args.actor_json:
        print(json.dumps(actor(json.loads(args.actor_json))))
        return 0
    if args.system_operation:
        try:
            result = system_operation(args.state, args.system_operation)
            write_json(args.state.parent / (args.system_operation + '.result.json'), {'ok': True, 'result': result})
            return 0
        except BaseException as error:
            write_json(args.state.parent / (args.system_operation + '.result.json'),
                       {'ok': False, 'error': type(error).__name__ + ':' + str(error)[:900]})
            return 1
    if args.installed_root is None or args.output is None:
        parser.error('--installed-root and --output required')
    return run(args)


if __name__ == '__main__':
    raise SystemExit(main())
