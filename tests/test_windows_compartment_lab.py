"""Compartment evidence must not promote incomplete probes into qualification."""
import copy
import importlib.util
import json
from pathlib import Path
import sys
import tempfile
import threading
import unittest
from unittest import mock
import urllib.request


SOURCE = Path(__file__).resolve().parents[1] / '.github' / 'windows_compartment_lab.py'
SPEC = importlib.util.spec_from_file_location('windows_compartment_lab', SOURCE)
lab = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(lab)


class AtomicJsonTests(unittest.TestCase):
    @staticmethod
    def windows_error(code):
        error = PermissionError('fixture sharing/access failure')
        error.winerror = code
        return error

    def test_transient_replace_failure_preserves_old_document_until_publish(self):
        for code in (5, 32, 33):
            with self.subTest(winerror=code), tempfile.TemporaryDirectory() as directory:
                path = Path(directory) / 'controller-health.json'
                path.write_text('{"stage":"old","complete":true}', encoding='utf-8')
                previous = path.read_bytes()
                value = {'stage': 'new', 'rows': list(range(100))}
                replace = lab.os.replace
                attempts = []

                def sharing_then_publish(source, destination):
                    attempts.append(source)
                    self.assertEqual(path.read_bytes(), previous)
                    self.assertEqual(json.loads(source.read_text(encoding='utf-8')), value)
                    if len(attempts) <= 2:
                        raise self.windows_error(code)
                    replace(source, destination)

                with mock.patch.object(lab.sys, 'platform', 'win32'), \
                        mock.patch.object(lab.os, 'replace', side_effect=sharing_then_publish), \
                        mock.patch.object(lab.time, 'sleep') as sleep:
                    lab.write_json(path, value)
                self.assertEqual(len(attempts), 3)
                self.assertEqual(sleep.call_count, 2)
                self.assertEqual(json.loads(path.read_text(encoding='utf-8')), value)
                self.assertEqual(list(Path(directory).iterdir()), [path])

    def test_permanent_failure_is_bounded_and_removes_only_its_temporary_file(self):
        for platform, code, expected_attempts in (('win32', 5, 21), ('win32', 32, 21),
                                                   ('win32', 2, 1), ('linux', 5, 1)):
            with self.subTest(platform=platform, winerror=code), tempfile.TemporaryDirectory() as directory:
                path = Path(directory) / 'controller-health.json'
                path.write_text('{"stage":"old"}', encoding='utf-8')
                previous = path.read_bytes()
                foreign = path.with_name(path.name + '.tmp')
                foreign.write_bytes(b'belongs to another writer')
                error = self.windows_error(code)
                with mock.patch.object(lab.sys, 'platform', platform), \
                        mock.patch.object(lab.os, 'replace', side_effect=error) as replace, \
                        mock.patch.object(lab.time, 'monotonic', return_value=10), \
                        mock.patch.object(lab.time, 'sleep') as sleep:
                    with self.assertRaises(OSError) as caught:
                        lab.write_json(path, {'stage': 'new'})
                self.assertIs(caught.exception, error)
                self.assertEqual(replace.call_count, expected_attempts)
                self.assertLessEqual(sum(call.args[0] for call in sleep.call_args_list), 1.01)
                self.assertEqual(path.read_bytes(), previous)
                self.assertEqual(foreign.read_bytes(), b'belongs to another writer')
                self.assertEqual(set(Path(directory).iterdir()), {path, foreign})

    def test_concurrent_publishers_use_distinct_complete_temporary_files(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / 'controller-health.json'
            values = [{'writer': index, 'rows': [index] * 1000} for index in range(2)]
            barrier = threading.Barrier(2)
            sources, errors = [], []
            source_lock = threading.Lock()
            replace = lab.os.replace

            def concurrent_replace(source, destination):
                with source_lock:
                    first_attempt = source not in sources
                    sources.append(source)
                self.assertIn(json.loads(source.read_text(encoding='utf-8')), values)
                if first_attempt:
                    barrier.wait(timeout=2)
                replace(source, destination)

            def publish(value):
                try:
                    lab.write_json(path, value)
                except BaseException as exc:
                    errors.append(exc)

            with mock.patch.object(lab.os, 'replace', side_effect=concurrent_replace):
                writers = [threading.Thread(target=publish, args=(value,)) for value in values]
                for writer in writers:
                    writer.start()
                for writer in writers:
                    writer.join(timeout=3)
                self.assertTrue(all(not writer.is_alive() for writer in writers))
            self.assertEqual(errors, [])
            self.assertEqual(len(set(sources)), 2)
            self.assertIn(json.loads(path.read_text(encoding='utf-8')), values)
            self.assertEqual(list(Path(directory).iterdir()), [path])

    @unittest.skipUnless(sys.platform == 'win32', 'requires real Windows file sharing')
    def test_windows_reader_without_delete_sharing_can_release_before_deadline(self):
        kernel = lab.C.WinDLL('kernel32', use_last_error=True)
        kernel.CreateFileW.argtypes = [lab.W.LPCWSTR, lab.W.DWORD, lab.W.DWORD, lab.C.c_void_p,
                                      lab.W.DWORD, lab.W.DWORD, lab.W.HANDLE]
        kernel.CreateFileW.restype = lab.W.HANDLE
        kernel.CloseHandle.argtypes = [lab.W.HANDLE]
        kernel.CloseHandle.restype = lab.W.BOOL
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / 'controller-health.json'
            path.write_text('{"stage":"old"}', encoding='utf-8')
            # Read/write sharing permits ordinary readers, but withholding
            # FILE_SHARE_DELETE reproduces the actual Windows rename failure.
            handle = kernel.CreateFileW(str(path), 0x80000000, 3, None, 3, 0x80, None)
            if handle == lab.C.c_void_p(-1).value:
                raise lab.C.WinError(lab.C.get_last_error())
            blocked, errors = threading.Event(), []
            replace = lab.os.replace

            def observe_real_replace(source, destination):
                try:
                    return replace(source, destination)
                except OSError as exc:
                    if getattr(exc, 'winerror', None) in (5, 32, 33):
                        blocked.set()
                    raise

            def publish():
                try:
                    lab.write_json(path, {'stage': 'new'})
                except BaseException as exc:
                    errors.append(exc)

            writer = threading.Thread(target=publish)
            try:
                with mock.patch.object(lab.os, 'replace', side_effect=observe_real_replace):
                    writer.start()
                    try:
                        self.assertTrue(blocked.wait(timeout=2), 'the real rename was never blocked')
                        self.assertEqual(json.loads(path.read_text(encoding='utf-8')), {'stage': 'old'})
                    finally:
                        self.assertTrue(kernel.CloseHandle(handle))
                        handle = None
                        writer.join(timeout=3)
                    self.assertFalse(writer.is_alive())
                self.assertEqual(errors, [])
                self.assertEqual(json.loads(path.read_text(encoding='utf-8')), {'stage': 'new'})
                self.assertEqual(list(Path(directory).iterdir()), [path])
            finally:
                if handle is not None:
                    kernel.CloseHandle(handle)


class AssessmentTests(unittest.TestCase):
    sid = 'S-1-5-21-1-2-3-1001'

    def actor(self, allowed, compartment, *, proxy=True):
        def member():
            return {'exit_code': 0, 'compartment': compartment,
                    'identity': {'sid': self.sid, 'elevated': False},
                    'rows': {key: {'ok': allowed} for key in lab.ROW_KEYS}, 'proxy': {'ok': proxy}}
        return dict(member(), child=member(), nested=member())

    def report(self):
        outside, inside = self.actor(True, 1), self.actor(False, 2)
        launcher = {'identity': {'sid': self.sid, 'elevated': False},
                    'user-outside': outside, 'user-inside': inside}
        live = {'exit_code': 0, 'compartment': 2, 'pid': 44, 'released': True,
                'before': {'proxy': {'ok': True}},
                'after': {'proxy': {'ok': False}, 'rows': {key: {'ok': False} for key in lab.ROW_KEYS}}}
        report = {'nonce': 'n', 'binds': {'A': {'compartment_id': 2}},
                  'phases': {'outside': outside, 'inside': inside, 'relay-live-inside': live,
                             'relay-stopped-inside': self.actor(False, 2, proxy=False)},
                  'relay_failure_ready': {'pid': 44, 'before': {'proxy': {'ok': True}}},
                  'user_flow': {'exit_code': 0, 'timed_out': False,
                                'identity': {'sid': self.sid, 'elevated': False}, 'launcher': launcher},
                  'user_launcher': launcher, 'dns_matrix': {}, 'broker_matrix': {},
                  'cleanup_result': {'deletes': {'2': 1359}}}
        keys = ('getaddrinfo:0', 'DnsQuery_W:0', 'DnsQuery_W:264', 'DnsQueryEx:0', 'DnsQueryEx:264',
                'DnsQuery_W:0:restricted', 'DnsQueryEx:0:restricted', 'Resolve-DnsName:0')
        index = 0
        for scope in ('outside_before', 'inside', 'outside_after'):
            entries = report['dns_matrix'][scope] = {}
            for key in keys:
                index += 1
                entries[key] = {'name': f'{index:032x}.1.2.3.4.sslip.io', 'execution': {'timed_out': False},
                                'result': {'completed': True, 'addresses': [] if scope == 'inside' else ['1.2.3.4']}}
        for scope in ('outside', 'inside'):
            report['broker_matrix'][scope] = {
                'wmi': {'execution': {'timed_out': False}, 'invocation': {'return_value': 5},
                        'child': None, 'fixture_hits': 0},
                'bits': {'execution': {'timed_out': False}, 'result': {'supported': False}, 'fixture_hits': 0}}
        return report

    def test_successful_socket_and_api_denials_never_qualify_product_or_wire_denial(self):
        checks = lab.qualification_checks(self.report())
        self.assertTrue(checks['required_observations_complete'])
        self.assertTrue(checks['ordinary_user_flow'])
        self.assertTrue(checks['relay_stop_live_and_new_processes'])
        for key in ('dns_no_egress_proven', 'real_mihomo_https_tested', 'browser_sandbox_state_verified',
                    'primary_restricted_token_tested', 'hcn_dns_remediation_tested', 'compartment_cleanup_complete'):
            self.assertIs(checks[key], False, key)
        self.assertEqual(lab.experiment_decision(checks), 'poc_only_requires_wire_evidence_and_product_acceptance')

    def test_missing_positive_control_and_elevated_descendant_are_not_ordinary_success(self):
        report = self.report()
        report['user_launcher']['user-outside']['rows']['tcp6_loopback']['ok'] = False
        self.assertFalse(lab.qualification_checks(report)['ordinary_user_flow'])
        report = self.report()
        report['user_launcher']['user-inside']['nested']['identity']['elevated'] = True
        self.assertFalse(lab.qualification_checks(report)['ordinary_user_flow'])

    def test_relay_probe_requires_same_process_before_and_after_and_new_denial(self):
        report = self.report()
        report['relay_failure_ready']['pid'] = 45
        self.assertFalse(lab.qualification_checks(report)['relay_stop_live_and_new_processes'])
        report = self.report()
        report['phases']['relay-stopped-inside']['child']['proxy']['ok'] = True
        self.assertFalse(lab.qualification_checks(report)['relay_stop_live_and_new_processes'])

    def test_dns_timeout_missing_result_or_reused_name_remains_incomplete(self):
        report = self.report()
        report['dns_matrix']['inside']['DnsQueryEx:0']['execution']['timed_out'] = True
        self.assertFalse(lab.qualification_checks(report)['required_observations_complete'])
        report = self.report()
        report['dns_matrix']['inside']['DnsQuery_W:0']['result'] = None
        self.assertFalse(lab.qualification_checks(report)['dns_matrix_complete_and_names_unique'])
        report = self.report()
        report['dns_matrix']['inside']['DnsQuery_W:0']['name'] = report['dns_matrix']['inside']['getaddrinfo:0']['name']
        self.assertFalse(lab.qualification_checks(report)['dns_matrix_complete_and_names_unique'])

    def test_inside_dns_answer_is_no_go_even_if_other_probe_missing(self):
        report = self.report()
        report['dns_matrix']['inside']['Resolve-DnsName:0']['result']['addresses'] = ['1.2.3.5']
        report['user_flow']['exit_code'] = 1
        checks = lab.qualification_checks(report)
        self.assertTrue(checks['dns_answer_inside_observed'])
        self.assertEqual(lab.experiment_decision(checks), 'no_go_dns_broker_bypass')

    def test_wmi_bypass_requires_receipt_receiver_and_pid_binding(self):
        report = self.report()
        row = report['broker_matrix']['inside']['wmi']
        row.update(fixture_hits=1, invocation={'return_value': 0, 'child_pid': 101},
                   child={'direct_http': True, 'compartment': 1, 'identity': {'pid': 101},
                          'marker': 'RuleProxyFixture:n:wmi_inside'})
        checks = lab.qualification_checks(report)
        self.assertTrue(checks['wmi_broker_bypass_observed'])
        self.assertEqual(lab.experiment_decision(checks), 'no_go_local_broker_bypass')
        for key, replacement in (('fixture_hits', 0), ('invocation', {'child_pid': 102})):
            changed = copy.deepcopy(report)
            changed['broker_matrix']['inside']['wmi'][key] = replacement
            self.assertFalse(lab.qualification_checks(changed)['wmi_broker_bypass_observed'])

    def test_bits_unavailable_is_not_a_positive_control_or_bypass(self):
        checks = lab.qualification_checks(self.report())
        self.assertFalse(checks['broker_positive_controls'])
        self.assertFalse(checks['bits_broker_bypass_observed'])
        report = self.report()
        report['broker_matrix']['inside']['bits'].update(fixture_hits=1, result={'marker_matches': True})
        self.assertTrue(lab.qualification_checks(report)['bits_broker_bypass_observed'])

    def test_empty_report_is_incomplete_and_never_passes_a_probe(self):
        checks = lab.qualification_checks({})
        self.assertFalse(any(checks.values()))
        self.assertEqual(lab.experiment_decision(checks), 'incomplete_experiment')


class FixtureTests(unittest.TestCase):
    def test_bits_head_range_and_get_are_real_receiver_controls(self):
        fixture = lab.Fixture('nonce', direct=True)
        opener = urllib.request.build_opener(urllib.request.ProxyHandler({}))
        url = f'http://127.0.0.1:{fixture.port}/nonce/bits_inside'
        try:
            with opener.open(urllib.request.Request(url, method='HEAD'), timeout=3) as response:
                length = int(response.headers['Content-Length'])
                self.assertEqual(response.headers['Accept-Ranges'], 'bytes')
                self.assertEqual(response.read(), b'')
            self.assertEqual(fixture.count('bits_inside'), 0)
            with opener.open(urllib.request.Request(url, headers={'Range': 'bytes=0-'}), timeout=3) as response:
                self.assertEqual(response.status, 206)
                body = response.read()
                self.assertEqual(len(body), length)
                self.assertIn(fixture.marker('bits_inside').encode(), body)
            self.assertEqual(fixture.count('bits_inside'), 1)
        finally:
            fixture.close()

    def test_standalone_workers_compile(self):
        for name in ('ACTOR', 'LAUNCHER', 'DNS_PROBE', 'BROKER_CHILD'):
            with self.subTest(name=name):
                compile(getattr(lab, name), name + '.py', 'exec')


if __name__ == '__main__':
    unittest.main()
