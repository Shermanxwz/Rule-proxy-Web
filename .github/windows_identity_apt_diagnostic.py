"""Bounded, closed APT-plan evidence; never an alternative Stage0 acceptance gate.

Only the orchestrator's one fixed apt-get update mutates package indexes. No
installation, recovery, package download, guest, credential or VM operation is
available. Raw command output exists only in bounded process memory.
"""
from __future__ import annotations
import argparse
import hashlib
import json
import os
from pathlib import Path
import re
import selectors
import signal
import subprocess
import sys
import time
from types import ModuleType, SimpleNamespace

ROOT = Path(__file__).resolve().parents[1]
STOCK_SHA256 = 'f24f413caccc2619182e76ad22b385e134e7403bc9614d3b927812b1ea410e62'
IMAGE_VERSION = '20261012.334.1'
MAX_ROWS = 256  # Observation limit only. Acceptance remains at 23 packages.
MAX_RECORDS = 16
MAX_STREAM = 512 * 1024
MAX_CAPTURE = 8 * 1024**2
MAX_REPORT = 4 * 1024**2
MAX_RELATIONSHIPS = 1024
MAX_ROW_RELATIONSHIPS = 128
DEPENDENCY_FIELDS = ('Depends', 'Pre-Depends', 'Provides')
MAX_NUMBER = 2**63 - 1
ABSOLUTE_SECONDS = 480
PHASES = ('before_refresh', 'after_refresh')
FIELDS = ('Package', 'Version', 'Architecture', 'Size', 'Installed-Size')
SIMULATION = ('apt-get', '-s', '--no-install-recommends', '--no-remove', 'install',
              'qemu-system-x86', 'qemu-utils', 'ovmf', 'swtpm', 'xorriso', 'curl', '7zip')
DPKG_FORMAT = '-f=${db:Status-Status}\\n${Installed-Size}\\n${Version}\\n'
GATE_ERRORS = {
    'bounded no-removal APT plan required': 'simulation_removal_or_bound',
    'unambiguous no-removal APT summary required': 'simulation_summary',
    'unambiguous versioned APT input required': 'simulation_row',
    'APT package count differs': 'simulation_count',
    'APT plan metadata unavailable': 'command_result',
    'duplicate APT metadata field': 'metadata_duplicate_field',
    'exact APT package metadata required': 'metadata_required_fields',
    'ambiguous APT package sizes': 'metadata_size_disagreement',
    'installed APT package changed since simulation': 'installed_version_or_size',
    'installed APT metadata unavailable': 'installed_metadata',
    'APT plan exceeds reviewed preparation ceilings': 'numeric_ceiling',
}
STOP_REASONS = frozenset({'time_bound', 'output_bound', 'capture_bound', 'command_launch',
                          'command_encoding', 'command_allowlist', 'command_timeout', 'unexpected_error'})


class Stopped(Exception):
    def __init__(self, reason):
        self.reason = reason if reason in STOP_REASONS else 'unexpected_error'
        super().__init__(self.reason)


def number(value):
    return int(value) if isinstance(value, str) and value.isdecimal() and len(value) <= 19 and int(value) <= MAX_NUMBER else None


def command_fact(result=None, reason=None):
    return {'status': reason or ('completed' if result is not None else 'not_started'),
            'return_code': result.returncode if result is not None and -2**31 <= result.returncode < 2**31 else None,
            'stdout_bytes': getattr(result, 'stdout_bytes', len(result.stdout.encode('utf-8'))) if result is not None else None,
            'stderr_bytes': getattr(result, 'stderr_bytes', len(result.stderr.encode('utf-8'))) if result is not None else None}


def bounded_command(argv, *, deadline, timeout=30, capture_remaining=MAX_CAPTURE):
    """Drain both pipes while enforcing limits; no communicate()/unbounded read."""
    end = min(deadline - 2, time.monotonic() + timeout)
    if end <= time.monotonic():
        raise Stopped('time_bound')
    buffers = [bytearray(), bytearray()]
    process = None
    try:
        process = subprocess.Popen(argv, stdin=subprocess.DEVNULL, stdout=subprocess.PIPE,
                                   stderr=subprocess.PIPE, env=dict(os.environ, LC_ALL='C'),
                                   start_new_session=True)
        with selectors.DefaultSelector() as selector:
            selector.register(process.stdout, selectors.EVENT_READ, 0)
            selector.register(process.stderr, selectors.EVENT_READ, 1)
            while selector.get_map() or process.poll() is None:
                remaining = end - time.monotonic()
                if remaining <= 0:
                    raise Stopped('time_bound' if time.monotonic() >= deadline - 2 else 'command_timeout')
                for key, _ in selector.select(min(remaining, 0.1)):
                    data = os.read(key.fileobj.fileno(), 65536)
                    if not data:
                        selector.unregister(key.fileobj)
                        continue
                    slot = buffers[key.data]
                    if len(slot) + len(data) > MAX_STREAM:
                        raise Stopped('output_bound')
                    if sum(map(len, buffers)) + len(data) > capture_remaining:
                        raise Stopped('capture_bound')
                    slot.extend(data)
        try:
            # Match subprocess.run(text=True)'s universal-newline behavior,
            # while retaining actual byte counts for capture accounting.
            text = [data.decode('utf-8').replace('\r\n', '\n').replace('\r', '\n') for data in buffers]
            return SimpleNamespace(returncode=process.returncode, stdout=text[0], stderr=text[1],
                                   stdout_bytes=len(buffers[0]), stderr_bytes=len(buffers[1]))
        except UnicodeError:
            raise Stopped('command_encoding') from None
    except OSError:
        raise Stopped('command_launch') from None
    finally:
        if process is not None:
            if process.poll() is None:
                # Only the command's own new session. The privileged refresh has
                # its own root-owned timeout, so killing this waiter cannot leave
                # an unbounded apt-get child behind.
                try:
                    os.killpg(process.pid, signal.SIGTERM)
                except ProcessLookupError:
                    pass
                try:
                    process.wait(timeout=1)
                except subprocess.TimeoutExpired:
                    try:
                        os.killpg(process.pid, signal.SIGKILL)
                    except ProcessLookupError:
                        pass
                    process.wait(timeout=1)
            for stream in (process.stdout, process.stderr):
                stream.close()


def safe_package(name):
    return len(name) <= 256 and re.fullmatch(r'[a-z0-9][a-z0-9+.-]*(?::[a-z0-9-]+)?', name) is not None


def safe_version(version):
    return len(version) <= 256 and re.fullmatch(r'[A-Za-z0-9.+:~_-]+', version) is not None


class Recorder:
    """One immutable result per exact query, shared by frozen and diagnostic parsers."""
    def __init__(self, deadline, executor=bounded_command):
        self.deadline, self.executor = deadline, executor
        self.cache, self.facts = {}, {}
        self.captured = 0
        self.last_stage = 'simulation'
        self.last_name = None

    def __call__(self, argv, **_):
        key = tuple(argv)
        if key == SIMULATION:
            self.last_stage, self.last_name = 'simulation', None
        elif (len(key) == 3 and key[:2] == ('apt-cache', 'show') and key[2].count('=') == 1
              and safe_package(key[2].split('=')[0]) and safe_version(key[2].split('=')[1])):
            self.last_stage, self.last_name = 'metadata', key[2].split('=')[0]
        elif len(key) == 4 and key[:3] == ('dpkg-query', '-W', DPKG_FORMAT) and safe_package(key[3]):
            self.last_stage, self.last_name = 'installed', key[3]
        else:
            raise Stopped('command_allowlist')
        if key in self.cache:
            result = self.cache[key]
            if isinstance(result, Stopped):
                raise result
            return result
        try:
            result = self.executor(['/usr/bin/' + argv[0], *argv[1:]], deadline=self.deadline,
                                   capture_remaining=MAX_CAPTURE - self.captured)
            self.captured += command_fact(result)['stdout_bytes'] + command_fact(result)['stderr_bytes']
            self.cache[key] = result
            self.facts[key] = command_fact(result)
            return result
        except Stopped as exc:
            self.cache[key] = exc
            self.facts[key] = command_fact(reason=exc.reason)
            raise


def simulation_facts(text):
    summaries = re.findall(r'^(\d+) upgraded, (\d+) newly installed, (\d+) to remove and (\d+) not upgraded\.$',
                           text, re.MULTILINE)
    selected = [line for line in text.splitlines() if line.startswith('Inst ')]
    rows = []
    for index, line in enumerate(selected[:MAX_ROWS]):
        match = re.match(r'^Inst ([a-z0-9][a-z0-9+.-]*(?::[a-z0-9-]+)?)(?: \[([^\]]+)\])? \(([^ ]+) ', line)
        entry = match.groups() if match else None
        safe = entry is not None and safe_package(entry[0]) and safe_version(entry[2]) and (entry[1] is None or safe_version(entry[1]))
        rows.append((index, entry if safe else None))
    counts = [number(item) for item in summaries[0]] if len(summaries) == 1 else [None] * 4
    all_parsed = len(rows) == len(selected) and all(entry is not None for _, entry in rows)
    unique = len({entry[0] for _, entry in rows if entry is not None})
    facts = {'summary_count': len(summaries), 'upgraded_count': counts[0], 'new_count': counts[1],
             'remove_count': counts[2], 'not_upgraded_count': counts[3],
             'removal_line_count': len(re.findall(r'^(?:Remv|Purg)\s', text, re.MULTILINE)),
             'selected_line_count': len(selected), 'observed_row_count': len(rows),
             'safe_parsed_row_count': sum(entry is not None for _, entry in rows),
             'unique_safe_name_count': unique, 'all_rows_safely_parsed': all_parsed,
             'row_observation_bound_exceeded': len(selected) > MAX_ROWS,
             'summary_matches_selected_count': counts[0] is not None and counts[1] is not None and counts[0] + counts[1] == len(selected),
             'unique_selected_names': all_parsed and unique == len(selected)}
    return facts, rows


def metadata_facts(text, name, version):
    paragraphs = re.split(r'\n\s*\n', text.strip())
    result = {'record_count': len(paragraphs), 'record_observation_bound_exceeded': len(paragraphs) > MAX_RECORDS,
              'records': [], 'all_records_valid': False, 'sizes_agree': False,
              'download_bytes': None, 'installed_bytes': None}
    sizes = []
    for paragraph in paragraphs[:MAX_RECORDS]:
        fields, counts = {}, {}
        duplicates = malformed = 0
        for line in paragraph.splitlines():
            if not line or line[0].isspace():
                continue
            if ': ' not in line:
                malformed += 1
                continue
            key, value = line.split(': ', 1)
            duplicates += key in fields
            counts[key] = counts.get(key, 0) + 1
            fields[key] = value
        archive = number(fields.get('Size'))
        installed_kib = number(fields.get('Installed-Size'))
        installed = installed_kib * 1024 if installed_kib is not None and installed_kib <= MAX_NUMBER // 1024 else None
        architecture = fields.get('Architecture')
        record = {'required_field_counts': {key: counts.get(key, 0) for key in FIELDS},
                  'duplicate_field_count': duplicates, 'malformed_field_line_count': malformed,
                  'package_matches': fields.get('Package') == name.split(':', 1)[0],
                  'version_matches': fields.get('Version') == version,
                  'architecture': architecture if architecture in ('amd64', 'all') else ('missing' if architecture is None else 'other'),
                  'archive_size_decimal': fields.get('Size', '').isdecimal(),
                  'installed_size_decimal': fields.get('Installed-Size', '').isdecimal(),
                  'numeric_sizes_in_observation_range': archive is not None and installed is not None,
                  'download_bytes': archive, 'installed_bytes': installed}
        # Match the frozen parser's validity, including its treatment of ignored
        # non-field lines. The numeric observation bound adds no acceptance.
        record['valid'] = (duplicates == 0 and record['package_matches'] and record['version_matches']
                           and architecture in ('amd64', 'all') and archive is not None and installed is not None)
        result['records'].append(record)
        if record['valid']:
            sizes.append((archive, installed))
    result['all_records_valid'] = len(paragraphs) <= MAX_RECORDS and len(sizes) == len(paragraphs)
    result['sizes_agree'] = bool(sizes) and len(set(sizes)) == 1
    if result['all_records_valid'] and result['sizes_agree']:
        result['download_bytes'], result['installed_bytes'] = sizes[0]
    return result


def dependency_facts(text, budget):
    """Project only ordinary public Debian package relationships, never raw fields.

    This describes declared metadata, not solver causality or a proof that an
    alternative/virtual dependency was selected. Constraints remain explicit
    for review; they are not silently treated as verified.
    """
    result = {'status': 'complete', 'all_records_parsed': True, 'records_agree': False,
              'distinct_record_count': 0, 'records': [], 'relationships_exported': 0,
              'virtual_providers_resolved': False}
    signatures = []
    paragraphs = re.split(r'\n\s*\n', text.strip())
    if len(paragraphs) > MAX_RECORDS:
        result.update(status='record_bound', all_records_parsed=False)
    for paragraph in paragraphs[:MAX_RECORDS]:
        fields = {}
        current = None
        for line in paragraph.splitlines():
            if line and line[0].isspace():
                if current in DEPENDENCY_FIELDS:
                    fields[current] += ' ' + line.strip()
                continue
            current = None
            header = re.match(r'^(Depends|Pre-Depends|Provides)(?:$|[:\s])', line)
            if header is None:
                continue
            key = header[1]
            if not line.startswith(key + ':') or not line[len(key) + 1:].strip():
                result.update(status='unsupported_relationship_syntax', all_records_parsed=False)
                continue
            value = line[len(key) + 1:].strip()
            if key in fields:
                result.update(status='duplicate_dependency_field', all_records_parsed=False)
            fields[key] = value
            current = key
        signature = tuple(fields.get(key, '') for key in DEPENDENCY_FIELDS)
        if signature not in signatures:
            signatures.append(signature)
    result['distinct_record_count'] = len(signatures)
    result['records_agree'] = len(signatures) == 1 and len(paragraphs) <= MAX_RECORDS
    row_remaining = MAX_ROW_RELATIONSHIPS
    for signature in signatures:
        record = {key: [] for key in DEPENDENCY_FIELDS}
        result['records'].append(record)
        for kind, value in zip(DEPENDENCY_FIELDS, signature):
            if not value:
                continue
            for group in value.split(','):
                alternatives = group.split('|')
                if len(alternatives) > 8:
                    result.update(status='relationship_bound', all_records_parsed=False)
                    return result
                projected = []
                for alternative in alternatives:
                    match = re.fullmatch(r'\s*([a-z0-9][a-z0-9+.-]*)(?::([a-z0-9-]+))?'
                        r'(?:\s+\((<<|<=|=|>=|>>)\s+([A-Za-z0-9.+:~_-]+)\))?\s*', alternative)
                    if (match is None or len(match[1]) > 256
                            or (match[2] is not None and len(match[2]) > 32)
                            or (match[4] is not None and not safe_version(match[4]))
                            or (kind == 'Provides' and (len(alternatives) != 1 or match[3] not in (None, '=')))):
                        result.update(status='unsupported_relationship_syntax', all_records_parsed=False)
                        continue
                    if row_remaining <= 0 or budget[0] <= 0:
                        result.update(status='relationship_bound', all_records_parsed=False)
                        return result
                    projected.append({'package': match[1], 'architecture_qualifier': match[2],
                                      'operator': match[3], 'version': match[4]})
                    row_remaining -= 1
                    budget[0] -= 1
                    result['relationships_exported'] += 1
                record[kind].append({'alternative_count': len(alternatives), 'alternatives': projected,
                                     'complete': len(projected) == len(alternatives)})
    return result


def installed_facts(completed, old):
    fields = completed.stdout.splitlines()
    installed = completed.returncode == 0 and len(fields) == 3 and fields[0] == 'installed'
    size = number(fields[1]) if len(fields) == 3 else None
    previous = size * 1024 if size is not None and size <= MAX_NUMBER // 1024 else None
    version_match = len(fields) == 3 and old == fields[2]
    valid = (completed.returncode in (0, 1) and
             ((installed and previous is not None and version_match) or (not installed and old is None)))
    state = fields[0] if fields else None
    return {'line_count': len(fields), 'installed_state': installed,
            'state': state if state in ('installed', 'config-files', 'not-installed') else ('missing' if state is None else 'other'),
            'version_field_present': len(fields) == 3 and bool(fields[2]), 'old_version_in_simulation': old is not None,
            'version_matches_simulated_old': version_match, 'size_decimal': len(fields) == 3 and fields[1].isdecimal(),
            'installed_bytes': previous if installed else None, 'valid': valid,
            'previous_bytes_for_growth': (previous if installed else 0) if valid else None}


def blank_phase(phase):
    return {'schema_version': 1, 'phase': phase, 'status': 'not_started', 'stop_reason': None,
            'exact_image_verified': False, 'stock_source_verified': False, 'stock_source_sha256': STOCK_SHA256,
            'frozen_gate_accepted': False, 'frozen_gate_completed': False, 'frozen_gate_error': 'not_run', 'frozen_gate_stage': None,
            'frozen_gate_row_index': None, 'simulation': None, 'rows': [],
            'totals_complete': False, 'download_bytes': None, 'positive_installed_growth_bytes': None,
            'partial_download_bytes': 0, 'partial_positive_installed_growth_bytes': 0, 'complete_size_row_count': 0,
            'ceiling_verdicts': {'package_count': None, 'download_bytes': None, 'positive_installed_growth_bytes': None},
            'ceilings': {'package_count': 23, 'download_bytes': 25315786, 'positive_installed_growth_bytes': 115948544},
            'observation_limits': {'rows': MAX_ROWS, 'records_per_row': MAX_RECORDS, 'bytes_per_stream': MAX_STREAM,
                                   'captured_bytes_per_phase': MAX_CAPTURE, 'absolute_seconds': ABSOLUTE_SECONDS,
                                   'public_relationships_per_phase': MAX_RELATIONSHIPS,
                                   'public_relationships_per_row': MAX_ROW_RELATIONSHIPS, 'report_bytes': MAX_REPORT},
            'refresh': {'attempted': False, 'completed': False, 'all_sources_refreshed_verified': False, 'command': command_fact()},
            'public_package_names_versions_exported': True, 'dependency_solver_causality_proven': False,
            'dependency_version_constraints_evaluated': False,
            'raw_output_exported': False, 'packages_installed': False, 'recovery_attempted': False,
            'vm_created': False, 'acceptance_policy_changed': False, 'atomic_package_snapshot': False}


def probe(stock, phase, *, deadline, executor=bounded_command):
    result = blank_phase(phase)
    result.update(exact_image_verified=True, stock_source_verified=True, status='observed')
    recorder = Recorder(deadline, executor)
    failed_name = None
    relationship_budget = [MAX_RELATIONSHIPS]
    try:
        stock.reviewed_apt_plan(runner=recorder)
        result['frozen_gate_accepted'] = True
        result['frozen_gate_completed'] = True
        result['frozen_gate_error'] = None
    except Stopped as exc:
        result['frozen_gate_error'] = exc.reason
    except ValueError as exc:
        result['frozen_gate_error'] = GATE_ERRORS.get(str(exc), 'unexpected_validation_error')
        result['frozen_gate_completed'] = str(exc) in GATE_ERRORS
    except Exception:
        result['frozen_gate_error'] = 'unexpected_validation_error'
    if not result['frozen_gate_accepted']:
        result['frozen_gate_stage'], failed_name = recorder.last_stage, recorder.last_name
    try:
        completed = recorder(SIMULATION)
        simulation, selected = simulation_facts(completed.stdout)
        simulation['command'] = recorder.facts[SIMULATION]
        result['simulation'] = simulation
        if failed_name is not None:
            result['frozen_gate_row_index'] = next((i for i, entry in selected if entry is not None and entry[0] == failed_name), None)
        complete = (completed.returncode == 0 and simulation['all_rows_safely_parsed']
                    and simulation['summary_matches_selected_count'] and simulation['unique_selected_names'])
        result['ceiling_verdicts']['package_count'] = simulation['selected_line_count'] <= stock.APT_PACKAGE_CEILING
        if simulation['row_observation_bound_exceeded']:
            result.update(status='partial', stop_reason='row_bound')
        for index, entry in selected:
            if time.monotonic() >= deadline:
                raise Stopped('time_bound')
            row = {'index': index, 'safe_simulation_row': entry is not None, 'metadata': None, 'installed': None,
                   'metadata_command': command_fact(), 'installed_command': command_fact(), 'complete_sizes': False,
                   'package': None, 'dependencies': None, 'stop_reasons': []}
            result['rows'].append(row)
            if entry is None:
                complete = False
                continue
            name, old, version = entry
            row['package'] = {'name': name, 'selected_version': version, 'simulated_old_version': old,
                              'directly_requested': name.split(':', 1)[0] in stock.VM_PACKAGES}
            metadata_key = ('apt-cache', 'show', name + '=' + version)
            installed_key = ('dpkg-query', '-W', DPKG_FORMAT, name)
            for key, kind in ((metadata_key, 'metadata'), (installed_key, 'installed')):
                try:
                    value = recorder(key)
                    row[kind] = metadata_facts(value.stdout, name, version) if kind == 'metadata' else installed_facts(value, old)
                    if kind == 'metadata':
                        row['dependencies'] = dependency_facts(value.stdout, relationship_budget)
                        if not row['dependencies']['all_records_parsed']:
                            result.update(status='partial', stop_reason='dependency_observation_incomplete')
                except Stopped as exc:
                    row['stop_reasons'].append(exc.reason)
                    result.update(status='partial', stop_reason=result['stop_reason'] or exc.reason)
                    if exc.reason in ('time_bound', 'capture_bound'):
                        raise
                finally:
                    row[kind + '_command'] = recorder.facts.get(key, command_fact())
            meta, current = row['metadata'], row['installed']
            if meta is None or current is None:
                complete = False
                continue
            if meta['record_observation_bound_exceeded']:
                result.update(status='partial', stop_reason='record_bound')
            row['complete_sizes'] = (row['metadata_command']['return_code'] == 0 and meta['all_records_valid']
                                     and meta['sizes_agree'] and current['valid'])
            complete = complete and row['complete_sizes']
            if row['complete_sizes']:
                result['complete_size_row_count'] += 1
                result['partial_download_bytes'] += meta['download_bytes']
                result['partial_positive_installed_growth_bytes'] += max(0, meta['installed_bytes'] - current['previous_bytes_for_growth'])
        result['totals_complete'] = complete
        if complete:
            result['download_bytes'] = result['partial_download_bytes']
            result['positive_installed_growth_bytes'] = result['partial_positive_installed_growth_bytes']
        for field in ('download_bytes', 'positive_installed_growth_bytes'):
            partial = result['partial_' + field]
            result['ceiling_verdicts'][field] = (partial <= result['ceilings'][field] if complete else
                                                False if partial > result['ceilings'][field] else None)
    except Stopped as exc:
        result.update(status='partial', stop_reason=exc.reason)
    except Exception:
        result.update(status='partial', stop_reason='unexpected_error')
    # A lower-bound partial sum can disprove a ceiling, never prove it.
    if not result['totals_complete']:
        for field in ('download_bytes', 'positive_installed_growth_bytes'):
            result['ceiling_verdicts'][field] = False if result['partial_' + field] > result['ceilings'][field] else None
    return result


def reviewed_environment(environment=None):
    environment = os.environ if environment is None else environment
    expected = {'ImageOS': 'ubuntu24', 'ImageVersion': IMAGE_VERSION, 'GITHUB_ACTIONS': 'true',
                'RUNNER_ENVIRONMENT': 'github-hosted', 'RUNNER_OS': 'Linux', 'RUNNER_ARCH': 'X64'}
    return sys.platform == 'linux' and sys.version_info[:2] == (3, 12) and all(environment.get(k) == v for k, v in expected.items())


def load_frozen_stock():
    path = ROOT / '.github/windows_identity_stock_stage0.py'
    data = path.read_bytes()
    if len(data) > 128 * 1024 or hashlib.sha256(data).hexdigest() != STOCK_SHA256:
        raise ValueError('stock_source_mismatch')
    module = ModuleType('frozen_stock_apt_plan')
    module.__file__ = str(path)
    exec(compile(data, str(path), 'exec'), module.__dict__)
    return module


def save(output, value):
    # Every report is constructed from fixed keys/enums, bounded numbers and
    # booleans plus explicitly validated public package names/versions above.
    # No raw argv, output, exceptions, account identities or paths are copied.
    if value.get('phase') not in PHASES:
        raise ValueError('closed_phase_required')
    data = json.dumps(value, sort_keys=True, ensure_ascii=True) + '\n'
    if len(data) > MAX_REPORT:
        raise ValueError('report_bound')
    path = output / (value['phase'] + '.json')
    if path.is_symlink():
        raise ValueError('output_link')
    path.write_text(data, encoding='ascii')


def diagnose(output, deadline_epoch, *, executor=bounded_command):
    output.mkdir(parents=True, exist_ok=True)
    reports = [blank_phase(phase) for phase in PHASES]
    for report in reports:
        save(output, report)
    remaining = deadline_epoch - time.time()
    if not reviewed_environment() or not 10 <= remaining <= ABSOLUTE_SECONDS:
        for report in reports:
            report.update(status='blocked', stop_reason='environment_or_deadline')
            save(output, report)
        return 1
    deadline = time.monotonic() + remaining - 5  # Report-write reserve, not new time.
    try:
        stock = load_frozen_stock()
    except Exception:
        for report in reports:
            report.update(status='blocked', stop_reason='stock_source_mismatch', exact_image_verified=True)
            save(output, report)
        return 1
    reports[0] = probe(stock, PHASES[0], deadline=min(deadline, time.monotonic() + 120), executor=executor)
    save(output, reports[0])
    refresh = {'attempted': False, 'completed': False, 'all_sources_refreshed_verified': False, 'command': command_fact()}
    try:
        # Same index-refresh operation as stock Stage0. Root-owned timeout also
        # bounds apt children if this unprivileged diagnostic is interrupted.
        seconds = min(110, int(deadline - time.monotonic()) - 70)
        if seconds < 1:
            raise Stopped('time_bound')
        refresh['attempted'] = True
        completed = executor(['/usr/bin/sudo', '-n', '/usr/bin/timeout', '--signal=TERM', '--kill-after=5s',
                              str(seconds) + 's', '/usr/bin/apt-get', 'update'],
                             deadline=deadline, timeout=seconds + 7, capture_remaining=MAX_CAPTURE)
        refresh['command'] = command_fact(completed)
        refresh['completed'] = completed.returncode == 0
        if refresh['completed']:
            reports[1] = probe(stock, PHASES[1], deadline=deadline, executor=executor)
        else:
            reports[1].update(status='blocked', stop_reason='refresh_nonzero', exact_image_verified=True, stock_source_verified=True)
    except Stopped as exc:
        refresh['command'] = command_fact(reason=exc.reason)
        reports[1].update(status='blocked', stop_reason=exc.reason, exact_image_verified=True, stock_source_verified=True)
    except Exception:
        reports[1].update(status='blocked', stop_reason='unexpected_error', exact_image_verified=True, stock_source_verified=True)
    for report in reports:
        report['refresh'] = dict(refresh)
        save(output, report)
    return 0 if all(report['status'] == 'observed' for report in reports) else 1


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--output-dir', type=Path, required=True)
    parser.add_argument('--deadline-epoch', type=int, required=True)
    args = parser.parse_args()
    return diagnose(args.output_dir, args.deadline_epoch)


if __name__ == '__main__':
    raise SystemExit(main())
