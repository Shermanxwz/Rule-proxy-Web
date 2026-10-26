"""Guard evidence boundaries and final artifact verification before native CI."""
import hashlib
import copy
import ctypes
import errno
import importlib.util
import io
import json
import os
from pathlib import Path
import struct
import sys
import tempfile
import threading
import time
import unittest
from unittest import mock
import zipfile
import zlib


SCRIPT = Path(__file__).resolve().parents[1] / ".github/windows_proxifyre_product_acceptance.py"
SPEC = importlib.util.spec_from_file_location("windows_product_acceptance", SCRIPT)
acceptance = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(acceptance)


class ProductArtifactTests(unittest.TestCase):
    def package(self, directory, members=None, manifest_path="ruleproxy/manager.py"):
        package = directory / "final.zip"
        payload = b"final product implementation\n"
        manifest = {"version": "0.3.0", "files": {manifest_path: hashlib.sha256(payload).hexdigest()}}
        with zipfile.ZipFile(package, "w") as archive:
            archive.writestr("RuleProxy-Web/package-manifest.json", json.dumps(manifest))
            archive.writestr("RuleProxy-Web/ruleproxy/manager.py", payload)
            for name, value in members or []:
                archive.writestr(name, value)
        (directory / "SHA256SUMS.txt").write_text(acceptance.digest(package) + "  final.zip\n")
        return package

    def test_final_package_verifies_manifest_and_exact_zip(self):
        with tempfile.TemporaryDirectory() as value:
            directory = Path(value)
            self.package(directory)
            root, facts = acceptance.unpack_package(directory, directory / "unpacked")
            self.assertEqual((root / "ruleproxy/manager.py").read_bytes(), b"final product implementation\n")
            self.assertTrue(facts["manifest_verified"])
            self.assertEqual(facts["files_verified"], 1)

    def test_modified_zip_cannot_pass_checksum(self):
        with tempfile.TemporaryDirectory() as value:
            directory = Path(value)
            package = self.package(directory)
            with package.open("ab") as stream:
                stream.write(b"changed")
            with self.assertRaisesRegex(ValueError, "digest"):
                acceptance.unpack_package(directory, directory / "unpacked")

    def test_zip_traversal_rejected(self):
        with tempfile.TemporaryDirectory() as value:
            directory = Path(value)
            self.package(directory, [("../outside.txt", "escape")])
            with self.assertRaisesRegex(ValueError, "Unsafe"):
                acceptance.unpack_package(directory, directory / "unpacked")
            self.assertFalse((directory / "outside.txt").exists())

    def test_manifest_traversal_rejected(self):
        with tempfile.TemporaryDirectory() as value:
            directory = Path(value)
            self.package(directory, manifest_path="../outside.txt")
            with self.assertRaisesRegex(ValueError, "Unsafe manifest"):
                acceptance.unpack_package(directory, directory / "unpacked")


class AtomicReportTests(unittest.TestCase):
    def test_report_creation_and_replacement_publish_complete_json(self):
        with tempfile.TemporaryDirectory() as temporary:
            path = Path(temporary) / "actors/report.json"
            acceptance.write(path, {"status": "running"})
            self.assertEqual(json.loads(path.read_text()), {"status": "running"})
            final = {"status": "passed", "checks": {"ordinary": True}, "payload": "x" * 8192}
            acceptance.write(path, final)
            self.assertEqual(json.loads(path.read_text()), final)
            self.assertFalse(path.with_suffix(".json.tmp").exists())

    def test_unrelated_replace_error_is_not_retried_and_preserves_original(self):
        with tempfile.TemporaryDirectory() as temporary:
            path = Path(temporary) / "report.json"
            acceptance.write(path, {"status": "original"})
            original = path.read_bytes()
            error = OSError(errno.EIO, "unrelated storage error")
            with mock.patch.object(acceptance.os, "replace", side_effect=error) as replace, \
                    mock.patch.object(acceptance.time, "sleep") as sleep:
                with self.assertRaises(OSError) as caught:
                    acceptance.write(path, {"status": "new"})
                self.assertIs(caught.exception, error)
                replace.assert_called_once()
                sleep.assert_not_called()
            self.assertEqual(path.read_bytes(), original)

    @staticmethod
    def reader_without_delete_sharing(path):
        kernel = ctypes.WinDLL("kernel32", use_last_error=True)
        kernel.CreateFileW.argtypes = [ctypes.c_wchar_p, ctypes.c_uint32, ctypes.c_uint32,
                                      ctypes.c_void_p, ctypes.c_uint32, ctypes.c_uint32, ctypes.c_void_p]
        kernel.CreateFileW.restype = ctypes.c_void_p
        kernel.CloseHandle.argtypes = [ctypes.c_void_p]
        kernel.CloseHandle.restype = ctypes.c_int
        # READ|WRITE sharing intentionally omits FILE_SHARE_DELETE, matching
        # the relevant Windows reader/atomic-rename conflict without an ACL edit.
        handle = kernel.CreateFileW(str(path), 0x80000000, 3, None, 3, 0x80, None)
        if handle == ctypes.c_void_p(-1).value:
            raise ctypes.WinError(ctypes.get_last_error())
        return kernel, handle

    @unittest.skipUnless(os.name == "nt", "requires Windows file-sharing semantics")
    def test_windows_report_replace_retries_real_reader_conflict_until_release(self):
        with tempfile.TemporaryDirectory() as temporary:
            path = Path(temporary) / "report.json"
            acceptance.write(path, {"status": "old"})
            kernel, handle = self.reader_without_delete_sharing(path)
            conflict, errors = threading.Event(), []
            real_replace = os.replace
            final = {"status": "complete", "checks": {"ordinary": True}, "payload": "x" * 8192}
            def replace(*args):
                try:
                    return real_replace(*args)
                except OSError as exc:
                    if getattr(exc, "winerror", None) in {5, 32, 33}:
                        conflict.set()
                    raise
            def publish():
                try:
                    acceptance.write(path, final)
                except BaseException as exc:
                    errors.append(exc)
            worker = threading.Thread(target=publish, daemon=True)
            try:
                with mock.patch.object(acceptance.os, "replace", side_effect=replace) as observed:
                    worker.start()
                    self.assertTrue(conflict.wait(1), "held Windows read handle did not exercise replace conflict")
                    self.assertTrue(kernel.CloseHandle(handle))
                    handle = None
                    worker.join(3)
                    self.assertFalse(worker.is_alive(), "replacement exceeded its bounded retry")
                    self.assertFalse(errors, repr(errors))
                    self.assertGreaterEqual(observed.call_count, 2)
                self.assertEqual(json.loads(path.read_text()), final)
                self.assertFalse(path.with_suffix(".json.tmp").exists())
            finally:
                if handle is not None:
                    kernel.CloseHandle(handle)
                if worker.ident is not None:
                    worker.join(3)

    @unittest.skipUnless(os.name == "nt", "requires Windows file-sharing semantics")
    def test_windows_persistent_reader_lock_expires_without_changing_original(self):
        with tempfile.TemporaryDirectory() as temporary:
            path = Path(temporary) / "report.json"
            acceptance.write(path, {"status": "old"})
            original = path.read_bytes()
            kernel, handle = self.reader_without_delete_sharing(path)
            real_replace = os.replace
            try:
                started = time.monotonic()
                with mock.patch.object(acceptance.os, "replace", wraps=real_replace) as observed:
                    with self.assertRaises(OSError) as caught:
                        acceptance.write(path, {"status": "new"}, replace_timeout=.12)
                    self.assertIn(caught.exception.winerror, {5, 32, 33})
                    self.assertGreaterEqual(observed.call_count, 2)
                self.assertLess(time.monotonic() - started, 2)
                self.assertEqual(path.read_bytes(), original)
            finally:
                kernel.CloseHandle(handle)
            acceptance.write(path, {"status": "after release"})
            self.assertEqual(json.loads(path.read_text()), {"status": "after release"})


class BackgroundEntryTests(unittest.TestCase):
    def test_short_lived_launcher_returns_while_descendant_retains_output(self):
        with tempfile.TemporaryDirectory(prefix="ruleproxy-background-entry-") as temporary:
            root = Path(temporary)
            ready, release, finished = (root / name for name in ("ready", "release", "finished"))
            child = (
                "import os,sys,time; from pathlib import Path\n"
                f"ready,release,finished=map(Path,{[str(ready), str(release), str(finished)]!r})\n"
                "print('descendant holds output', flush=True)\n"
                "ready.write_text('ready')\n"
                "deadline=time.monotonic()+10\n"
                "while not release.exists() and time.monotonic()<deadline: time.sleep(.02)\n"
                "for fd in (1,2):\n"
                " try: os.close(fd)\n"
                " except OSError: pass\n"
                "finished.write_text('finished')\n"
                "os._exit(0)\n"
            )
            parent = (
                "import os,subprocess,sys,time; from pathlib import Path\n"
                f"subprocess.Popen([sys.executable,'-c',{child!r}],close_fds=False)\n"
                f"ready=Path({str(ready)!r})\n"
                "deadline=time.monotonic()+5\n"
                "while not ready.exists() and time.monotonic()<deadline: time.sleep(.02)\n"
                "print('launcher exiting',flush=True)\n"
                "os._exit(0 if ready.exists() else 2)\n"
            )
            log = root / "entry.log"
            try:
                result = acceptance.run_background_entry([sys.executable, "-c", parent],
                                                        cwd=root, log_path=log, timeout=3)
                self.assertEqual(result.returncode, 0)
                self.assertTrue(ready.exists())
                self.assertFalse(finished.exists(), "launcher waited for background output EOF")
                self.assertIn("descendant holds output", log.read_text())
                self.assertIn("launcher exiting", log.read_text())
            finally:
                release.write_text("release")
                deadline = time.monotonic() + 5
                while ready.exists() and not finished.exists() and time.monotonic() < deadline:
                    time.sleep(.02)


class ReceiverEvidenceTests(unittest.TestCase):
    def phase(self, node="A"):
        return {"label": "raw socket", "token": "unique-phase-token", "expected_node": node,
                "actor": {"rows": [{}, {}]}}

    def transaction(self, *, node="A", role="actor", protocol="tcp_http_response"):
        return {"node": node, "evidence_role": role, "protocol": protocol,
                "request_target": "/nonce/unique-phase-token-0"}

    def verified(self, phase, rows):
        return acceptance.receiver_evidence([phase], {"transactions": rows})[0]

    def test_two_independent_matching_responses_qualify(self):
        value = self.verified(self.phase(), [self.transaction(), self.transaction(protocol="udp_dns")])
        self.assertTrue(value["passed"])
        self.assertEqual(value["receiver_node_counts"], {"A": 2, "B": 0})

    def test_explicit_health_cannot_qualify_transparent_actor(self):
        value = self.verified(self.phase(), [self.transaction(role="health"), self.transaction(role="health")])
        self.assertFalse(value["passed"])

    def test_wrong_node_or_missing_response_cannot_qualify(self):
        self.assertFalse(self.verified(self.phase(), [self.transaction()])["passed"])
        rows = [self.transaction(), self.transaction(), self.transaction(node="B")]
        self.assertFalse(self.verified(self.phase(), rows)["passed"])

    def test_unselected_control_must_never_reach_fixture(self):
        self.assertTrue(self.verified(self.phase(None), [self.transaction(role="health")])["passed"])
        self.assertFalse(self.verified(self.phase(None), [self.transaction()])["passed"])

    def test_browser_single_navigation_requires_independent_selected_b_response(self):
        phase = {"label": "system_edge", "token": "browser-navigation-token", "expected_node": "B",
                 "actor": {"rows": [{"browser": "system_edge"}]}}
        transaction = {"node": "B", "evidence_role": "actor", "protocol": "tcp_http_response",
                       "request_target": "/nonce/browser-navigation-token"}
        value = self.verified(phase, [transaction])
        self.assertTrue(value["passed"])
        self.assertEqual(value["attempts"], 1)
        self.assertEqual(value["receiver_node_counts"], {"A": 0, "B": 1})
        for rows in ([], [{**transaction, "node": "A"}], [{**transaction, "evidence_role": "health"}],
                     [{**transaction, "request_target": "/unrelated-navigation"}]):
            with self.subTest(rows=rows):
                self.assertFalse(self.verified(phase, rows)["passed"])


class NativeProxyEnvironmentEvidenceTests(unittest.TestCase):
    owner = "S-1-5-21-101-202-303-1001"

    def receipt(self, root):
        launcher = str((root / "ruleproxy/windows_app_process.py").resolve())
        nonce = "a1" * 16
        targets = [f"http://{nonce}.invalid/{nonce}/{role}" for role in ("child", "grandchild")]
        environment = {"HTTP_PROXY": "http://127.0.0.1:18809", "HTTPS_PROXY": "http://127.0.0.1:18809",
                       "ALL_PROXY": "http://127.0.0.1:18809", "NO_PROXY": "localhost,127.0.0.1,::1",
                       "NODE_USE_ENV_PROXY": "1"}
        parent = {"sid": self.owner, "elevated": False, "pid": os.getpid()}
        child_pid, grandchild_pid = os.getpid() + 10000, os.getpid() + 10001
        def actor(pid, ppid, target):
            return {"sid": self.owner, "elevated": False, "pid": pid, "ppid": ppid,
                    "launcher_file": launcher, "proxy_environment": dict(environment),
                    "target": target, "response": "proxy-fixture:" + nonce}
        return {"parent_token": parent, "child": {**actor(child_pid, parent["pid"], targets[0]), "grandchild_exit_code": 0},
                "grandchild": actor(grandchild_pid, child_pid, targets[1]),
                "expected_targets": targets, "received_targets": list(targets), "exit_code": 0,
                "launcher_file": launcher, "launched_pid": child_pid, "proxy_port": 18809,
                "probe_scope": "windows-native-launcher-child-grandchild-loopback"}

    def test_matching_ordinary_tokens_and_both_receiver_markers_are_required(self):
        root = Path("installed-product").resolve()
        receipt = self.receipt(root)
        self.assertTrue(acceptance.native_proxy_receipt_valid(receipt, self.owner, root))
        for role in ("parent_token", "child", "grandchild"):
            for key, value in (("sid", "S-1-5-18"), ("elevated", True), ("elevated", 0), ("pid", True)):
                changed = copy.deepcopy(receipt)
                changed[role][key] = value
                with self.subTest(role=role, key=key, value=value):
                    self.assertFalse(acceptance.native_proxy_receipt_valid(changed, self.owner, root))
        for received in ([], receipt["received_targets"][:1], receipt["received_targets"] * 2,
                         list(reversed(receipt["received_targets"])), ["/not-an-explicit-proxy-target"] * 2):
            changed = copy.deepcopy(receipt)
            changed["received_targets"] = received
            self.assertFalse(acceptance.native_proxy_receipt_valid(changed, self.owner, root))

    def test_checkout_launcher_changed_environment_and_unrelated_child_cannot_qualify(self):
        root = Path("installed-product").resolve()
        receipt = self.receipt(root)
        for role, field, value in (
                ("child", "launcher_file", str(root / "checkout/windows_app_process.py")),
                ("grandchild", "ppid", receipt["parent_token"]["pid"]),
                ("child", "response", "unrelated-success"), ("grandchild", "error", "failure"),
                ("child", "grandchild_exit_code", False)):
            changed = copy.deepcopy(receipt)
            changed[role][field] = value
            self.assertFalse(acceptance.native_proxy_receipt_valid(changed, self.owner, root))
        for key, value in (("NO_PROXY", "*"), ("CUSTOM_PROXY", "http://127.0.0.1:18809"),
                           ("HTTPS_PROXY", "http://untrusted.invalid:9")):
            changed = copy.deepcopy(receipt)
            changed["child"]["proxy_environment"][key] = value
            self.assertFalse(acceptance.native_proxy_receipt_valid(changed, self.owner, root))
        for key, value in (("exit_code", False), ("proxy_port", True), ("launched_pid", True),
                           ("probe_scope", "transparent_proxy_qualified")):
            changed = copy.deepcopy(receipt)
            changed[key] = value
            self.assertFalse(acceptance.native_proxy_receipt_valid(changed, self.owner, root))

    def test_exact_helper_copy_is_checked_before_running_shared_probe(self):
        from types import SimpleNamespace
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            helper = root / "native-proxy-probe.py"
            helper.write_bytes(b"fixed checked fixture source")
            spec = {"owner_sid": self.owner, "native_proxy_fixture_sha256": acceptance.digest(helper)}
            receipt = self.receipt(root / "installed")
            probe = mock.Mock(return_value=receipt)
            with mock.patch.object(acceptance, "LAB", root), \
                    mock.patch.object(acceptance, "INSTALLED", root / "installed"), \
                    mock.patch.object(acceptance, "module", return_value=SimpleNamespace(native_launcher_proxy_probe=probe)) as load:
                facts = acceptance.native_proxy_environment_probe(spec)
                self.assertTrue(facts["passed"])
                self.assertEqual(facts["receipt"], receipt)
                self.assertEqual(facts["fixture_sha256"], spec["native_proxy_fixture_sha256"])
                probe.assert_called_once_with(root / "actors")
                helper.write_bytes(b"replaced fixture")
                load.reset_mock()
                with self.assertRaisesRegex(RuntimeError, "source differs"):
                    acceptance.native_proxy_environment_probe(spec)
                load.assert_not_called()

    def test_shared_probe_parent_must_be_the_actual_ordinary_suite_process(self):
        from types import SimpleNamespace
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            helper = root / "native-proxy-probe.py"
            helper.write_bytes(b"fixed checked fixture source")
            receipt = self.receipt(root / "installed")
            receipt["parent_token"]["pid"] += 1
            receipt["child"]["ppid"] = receipt["parent_token"]["pid"]
            spec = {"owner_sid": self.owner, "native_proxy_fixture_sha256": acceptance.digest(helper)}
            with mock.patch.object(acceptance, "LAB", root), \
                    mock.patch.object(acceptance, "INSTALLED", root / "installed"), \
                    mock.patch.object(acceptance, "module", return_value=SimpleNamespace(native_launcher_proxy_probe=lambda _: receipt)):
                with self.assertRaisesRegex(RuntimeError, "ordinary token"):
                    acceptance.native_proxy_environment_probe(spec)


class CompartmentRelayEvidenceTests(unittest.TestCase):
    owner = 'S-1-5-21-101-202-303-1001'
    compartment = 7
    nonce, marker = 'a' * 32, 'b' * 16
    executable = str(Path('contained.exe').resolve())
    executable_sha256 = 'c' * 64

    def receipt(self):
        environment = {key: 'http://127.0.0.1:20809' for key in ('HTTP_PROXY', 'HTTPS_PROXY', 'ALL_PROXY')}
        environment.update(NO_PROXY='localhost,127.0.0.1,::1', NODE_USE_ENV_PROXY='1')
        def actor(role, pid, parent):
            path = f'/ruleproxy-compare/{self.nonce}/{self.marker}/{role}'
            return {'role': role, 'sid': self.owner, 'elevated': False, 'is_appcontainer': False,
                    'compartment_id': self.compartment, 'pid': pid, 'ppid': parent,
                    'executable': self.executable, 'executable_sha256': self.executable_sha256,
                    'proxy_environment': dict(environment), 'target': 'http://1.1.1.1' + path,
                    'direct': {'connected': False, 'error': 'OSError', 'winerror': 10051, 'elapsed_ms': 1},
                    'response': {'node': 'B', 'nonce': self.nonce, 'request_target': path,
                                 'origin_kind': 'controlled_synthetic_stub'}}
        return {**actor('child', 202, 101), 'grandchild': actor('grandchild', 303, 202), 'grandchild_exit_code': 0}

    def valid(self, receipt, compartment=None):
        return acceptance.compartment_receipt_valid(
            receipt, owner_sid=self.owner, compartment_id=self.compartment if compartment is None else compartment,
            panel_pid=101, launched_pid=202, executable=self.executable, executable_sha256=self.executable_sha256,
            nonce=self.nonce, marker=self.marker, proxy_port=20809)

    def test_both_contained_ordinary_processes_and_distinct_parent_chain_are_required(self):
        receipt = self.receipt()
        self.assertTrue(self.valid(receipt))
        for role in ('child', 'grandchild'):
            for key, value in (('sid', 'S-1-5-18'), ('elevated', True), ('elevated', 0),
                               ('is_appcontainer', True), ('is_appcontainer', 0), ('compartment_id', 1),
                               ('compartment_id', self.compartment + 1), ('compartment_id', True),
                               ('pid', True), ('ppid', 404), ('role', 'other'),
                               ('executable', str(Path('outside.exe').resolve())),
                               ('executable_sha256', 'd' * 64)):
                changed = copy.deepcopy(receipt)
                (changed if role == 'child' else changed['grandchild'])[key] = value
                with self.subTest(role=role, key=key, value=value):
                    self.assertFalse(self.valid(changed))

    def test_default_compartment_or_unbound_readback_never_qualifies(self):
        receipt = self.receipt()
        for compartment in (1, 0, True, '7'):
            with self.subTest(compartment=compartment):
                self.assertFalse(self.valid(receipt, compartment))
        for actor in (receipt, receipt['grandchild']):
            actor['compartment_id'] = 1
        self.assertFalse(self.valid(receipt, 1))

    def test_direct_egress_inside_the_compartment_must_fail(self):
        for role in ('child', 'grandchild'):
            for direct in ({'connected': True}, {}, None, {'connected': 0}):
                changed = self.receipt()
                (changed if role == 'child' else changed['grandchild'])['direct'] = direct
                with self.subTest(role=role, direct=direct):
                    self.assertFalse(self.valid(changed))

    def test_wrong_response_or_untrusted_environment_cannot_qualify(self):
        receipt = self.receipt()
        for role in ('child', 'grandchild'):
            for key, value in (('target', 'http://1.1.1.1/wrong'), ('error', 'probe failed'),
                               ('proxy_environment', {'HTTP_PROXY': 'http://untrusted.invalid:80'}),
                               ('response', {'node': 'B'})):
                changed = copy.deepcopy(receipt)
                (changed if role == 'child' else changed['grandchild'])[key] = value
                self.assertFalse(self.valid(changed))
        receipt['grandchild_exit_code'] = False
        self.assertFalse(self.valid(receipt))

    def test_missing_or_failed_actor_never_counts(self):
        self.assertFalse(self.valid(None))
        self.assertFalse(self.valid({'error': 'OSError: [WinError 122]'}))
        changed = self.receipt()
        changed['grandchild'].pop('compartment_id')
        self.assertFalse(self.valid(changed))

    def test_independent_receivers_require_one_exact_completed_path_per_descendant(self):
        facts = {'nonce': self.nonce, 'marker': self.marker}
        def row(role):
            return {'request_target': f'/ruleproxy-compare/{self.nonce}/{self.marker}/{role}',
                    'protocol': 'tcp_http_response', 'evidence_role': 'actor', 'node': 'B', 'response_complete': True}
        child, grandchild = row('child'), row('grandchild')
        def passed(rows):
            return all(item['passed'] for item in acceptance.contained_receiver_evidence(facts, {'transactions': rows}))
        self.assertTrue(passed([child, grandchild]))
        for rows in ([child, child], [], [child, {**grandchild, 'node': 'A'}],
                     [child, {**grandchild, 'evidence_role': 'health'}],
                     [child, {**grandchild, 'response_complete': False}],
                     [child, {**grandchild, 'request_target': grandchild['request_target'] + '-other'}]):
            self.assertFalse(passed(rows))

    def test_journal_readbacks_bind_exact_app_bound_then_sealed(self):
        app_id = 'c' * 32
        name = acceptance.compartment_namespace(app_id)
        facts = {'app_id': app_id, 'namespace': name,
                 'active_gate': {'namespace': name, 'compartment_id': 3, 'phase': 'dirty'},
                 'revoked_gate': {'namespace': name, 'compartment_id': 3, 'phase': 'clean'}}
        self.assertTrue(acceptance.compartment_gate_readbacks_valid(facts))
        for label, key, value in (('active_gate', 'phase', 'clean'), ('revoked_gate', 'phase', 'dirty'),
                                  ('revoked_gate', 'compartment_id', 4), ('active_gate', 'compartment_id', 1),
                                  ('active_gate', 'compartment_id', True),
                                  ('revoked_gate', 'namespace', 'RuleProxyNS.' + '0' * 20)):
            changed = copy.deepcopy(facts)
            changed[label][key] = value
            if label == 'active_gate' and key == 'compartment_id':
                changed['revoked_gate'][key] = value
            with self.subTest(label=label, key=key, value=value):
                self.assertFalse(acceptance.compartment_gate_readbacks_valid(changed))
        for broken in ({**facts, 'namespace': 'RuleProxyNS.' + '0' * 20}, {**facts, 'app_id': 'C' * 32},
                       {**facts, 'active_gate': None}, {k: v for k, v in facts.items() if k != 'revoked_gate'}):
            self.assertFalse(acceptance.compartment_gate_readbacks_valid(broken))

    def test_namespace_matches_the_product_label(self):
        from ruleproxy.windows_compartment import namespace_name
        for app_id in ('c' * 32, '0123456789abcdef0123456789abcdef'):
            self.assertEqual(acceptance.compartment_namespace(app_id), namespace_name(app_id))

    def test_controller_reads_only_the_installed_journal_record(self):
        app_id = 'c' * 32
        name = acceptance.compartment_namespace(app_id)
        with tempfile.TemporaryDirectory() as value:
            state = Path(value) / 'compartments'
            state.mkdir()
            journal = {'version': 1, 'identity': 'x', 'boot_id': 'y',
                       'compartments': {name: {'cid': 5, 'guid': 'z', 'phase': 'dirty'}}}
            (state / 'compartments.json').write_text(json.dumps(journal), encoding='ascii')
            metadata = {'owner_sid': 'owner', 'namespace_state_dir': str(state)}
            with mock.patch.object(acceptance, 'INSTALLED', Path(__file__).resolve().parents[1]), \
                    mock.patch('ruleproxy.windows_proxy_service.load_deployment', return_value=metadata):
                self.assertEqual(acceptance.inspect_compartment_gate(app_id, 'owner'),
                                 {'namespace': name, 'compartment_id': 5, 'phase': 'dirty'})
                with self.assertRaisesRegex(RuntimeError, 'owner changed'):
                    acceptance.inspect_compartment_gate(app_id, 'other')
                with self.assertRaises(KeyError):
                    acceptance.inspect_compartment_gate('d' * 32, 'owner')
                with self.assertRaises(ValueError):
                    acceptance.inspect_compartment_gate('../escape', 'owner')

    def test_standalone_actor_is_valid_and_reports_its_actual_compartment(self):
        compile(acceptance.COMPARTMENT_ACTOR, 'compartment-actor.py', 'exec')
        self.assertIn('GetCurrentThreadCompartmentId', acceptance.COMPARTMENT_ACTOR)
        self.assertIn("'is_appcontainer': bool(integer(29))", acceptance.COMPARTMENT_ACTOR)
        self.assertNotIn('sid(31)', acceptance.COMPARTMENT_ACTOR)  # no AppContainer package SID query
        self.assertNotIn('import ruleproxy', acceptance.COMPARTMENT_ACTOR)

    def test_compared_sources_match_native_vm_identities(self):
        import ast
        tree = ast.parse(SCRIPT.read_text(encoding='utf-8'))
        controller = next(node for node in tree.body if isinstance(node, ast.FunctionDef) and node.name == 'controller')
        compared = next(ast.literal_eval(node.value) for node in ast.walk(controller)
                        if isinstance(node, ast.Assign) and any(getattr(target, 'id', None) == 'compared'
                                                                for target in node.targets))
        spec = importlib.util.spec_from_file_location('product_native_vm_identities',
                                                      SCRIPT.parent / 'windows_proxifyre_vm.py')
        vm = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(vm)
        self.assertEqual(set(compared), vm.SOURCE_IDENTITIES)
        self.assertIn('windows_compartment.py', compared)


class FixtureRuntimeManifestTests(unittest.TestCase):
    def runtime(self, root):
        source, runtime = root / 'bundle/RuleProxy-Web/python', root / 'runtime'
        source.mkdir(parents=True)
        for name in ('python.exe', 'python314.zip', 'python314._pth', 'DLLs/ssl.pyd'):
            path = source / name
            path.parent.mkdir(exist_ok=True)
            path.write_bytes(('fixed ' + name).encode())
        import shutil
        shutil.copytree(source, runtime)
        for alias in ('selected', 'helper', 'outside', 'contained'):
            (runtime / (alias + '.exe')).write_bytes((source / 'python.exe').read_bytes())
        return source, runtime

    def test_inventory_binds_all_copied_files_and_aliases_to_final_source(self):
        with tempfile.TemporaryDirectory() as value:
            source, runtime = self.runtime(Path(value))
            files = acceptance.fixture_runtime_manifest(runtime, source)
            self.assertEqual(len(files), 8)
            self.assertEqual(files['contained.exe'], acceptance.digest(source / 'python.exe'))
            (runtime / 'python314.zip').write_bytes(b'tampered')
            with self.assertRaisesRegex(RuntimeError, 'differs'):
                acceptance.fixture_runtime_manifest(runtime, source)

    def test_extra_missing_source_self_or_linked_runtime_are_rejected(self):
        with tempfile.TemporaryDirectory() as value:
            root = Path(value)
            source, runtime = self.runtime(root)
            with self.assertRaisesRegex(RuntimeError, 'separate'):
                acceptance.fixture_runtime_manifest(source, source)
            (runtime / 'secret.txt').write_text('never bind unrelated files')
            with self.assertRaisesRegex(RuntimeError, 'inventory differs'):
                acceptance.fixture_runtime_manifest(runtime, source)
            (runtime / 'secret.txt').unlink()
            (runtime / 'python314.zip').unlink()
            try:
                (runtime / 'python314.zip').symlink_to(source / 'python314.zip')
            except OSError:
                return  # Windows unprivileged symlink creation can be disabled.
            with self.assertRaisesRegex(RuntimeError, 'reparse'):
                acceptance.fixture_runtime_manifest(runtime, source)


class PngDimensionsTests(unittest.TestCase):
    @staticmethod
    def png(width=1, height=1):
        def chunk(kind, data):
            return struct.pack(">I", len(data)) + kind + data + struct.pack(">I", zlib.crc32(kind + data) & 0xFFFFFFFF)
        header = struct.pack(">IIBBBBB", width, height, 8, 6, 0, 0, 0)
        # A complete valid 1x1 RGBA image; alternate dimensions exercise the
        # metadata boundary without allocating their decoded pixel buffers.
        return (b"\x89PNG\r\n\x1a\n" + chunk(b"IHDR", header)
                + chunk(b"IDAT", zlib.compress(b"\x00\x00\x00\x00\xff")) + chunk(b"IEND", b""))

    def dimensions(self, raw):
        with tempfile.TemporaryDirectory() as temporary:
            path = Path(temporary) / "browser-screenshot.png"
            path.write_bytes(raw)
            return acceptance.png_dimensions(path)

    def test_valid_one_pixel_and_maximum_header_dimensions(self):
        self.assertEqual(self.dimensions(self.png()), (1, 1))
        self.assertEqual(self.dimensions(self.png(16384, 16384)), (16384, 16384))

    def test_zero_or_oversized_dimensions_are_rejected(self):
        for width, height in ((0, 1), (1, 0), (0, 0), (16385, 1), (1, 16385), (0xFFFFFFFF, 1)):
            with self.subTest(width=width, height=height), self.assertRaises(ValueError):
                self.dimensions(self.png(width, height))

    def test_signature_and_truncated_headers_are_rejected(self):
        valid = self.png()
        for raw in (b"not a PNG" + valid[9:], valid[:0], valid[:8], valid[:24], valid[:32]):
            with self.subTest(raw=raw), self.assertRaises(ValueError):
                self.dimensions(raw)

    def test_only_the_33_byte_header_is_read(self):
        class HeaderStream(io.BytesIO):
            def __init__(self, raw):
                super().__init__(raw)
                self.read_sizes = []

            def read(self, size=-1):
                self.read_sizes.append(size)
                if size != 33 or len(self.read_sizes) != 1:
                    raise AssertionError("Screenshot inspection must read only its first 33 bytes")
                return super().read(size)

        stream = HeaderStream(self.png())
        with mock.patch.object(Path, "open", return_value=stream), \
                mock.patch.object(Path, "read_bytes", side_effect=AssertionError("Unbounded screenshot read")):
            self.assertEqual(acceptance.png_dimensions(Path("screenshot.png")), (1, 1))
        self.assertEqual(stream.read_sizes, [33])


if __name__ == "__main__":
    unittest.main()
