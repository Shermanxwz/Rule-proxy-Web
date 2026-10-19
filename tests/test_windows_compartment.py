"""Pure and seam-level tests for the Windows network-compartment isolation.

The privileged compartment calls only run on Windows; here the gate, relay
bookkeeping, request policy, broker dispatch and panel launch flow are exercised
on any host with injected fakes, mirroring tests/test_windows_appcontainer.py.
"""
import socket
import threading
import time
from types import SimpleNamespace
import unittest
from unittest import mock
import uuid
import json
import os
from pathlib import Path
import tempfile

from ruleproxy import windows_app_process as app_process
from ruleproxy import windows_compartment as ns
from ruleproxy import windows_proxy_policy as policy
from ruleproxy import windows_proxy_service as service


OWNER = "S-1-5-21-1-2-3-1001"
NAME = ns.namespace_name("app-1")
META = {"root": r"C:\RuleProxy", "owner_sid": OWNER}
BOOT_ID = "3a57d15b-d13b-4934-bbc4-7f7ef68902fb"


@unittest.skipUnless(os.name == "nt", "requires the real Windows registry APIs")
class NativeBootIdentityTests(unittest.TestCase):
    """Only redirect the parent key; create/query/set/close are real native APIs."""

    def setUp(self):
        import winreg
        self.registry = winreg
        self.path = r"Software\RuleProxyBootIdentityTest-" + uuid.uuid4().hex
        self.access = winreg.KEY_READ | winreg.KEY_WRITE | winreg.KEY_WOW64_64KEY
        with winreg.CreateKeyEx(winreg.HKEY_CURRENT_USER, self.path, 0, self.access):
            pass
        self.addCleanup(self.remove_keys)
        native_open = winreg.OpenKey
        def open_parent(root, path, reserved=0, access=winreg.KEY_READ):
            if root == winreg.HKEY_LOCAL_MACHINE and path == r"SYSTEM\CurrentControlSet\Services\RuleProxyControl":
                return native_open(winreg.HKEY_CURRENT_USER, self.path, reserved, access)
            return native_open(root, path, reserved, access)
        patch = mock.patch.object(winreg, "OpenKey", side_effect=open_parent)
        patch.start()
        self.addCleanup(patch.stop)

    def remove_keys(self):
        for path in (self.path + r"\CompartmentBoot", self.path):
            try:
                self.registry.DeleteKeyEx(self.registry.HKEY_CURRENT_USER, path)
            except FileNotFoundError:
                pass

    def assert_closed(self, handle):
        self.assertIs(type(handle), int)
        with self.assertRaises(OSError) as caught:
            self.registry.QueryValueEx(handle, "BootId")
        self.assertEqual(caught.exception.winerror, 6)  # ERROR_INVALID_HANDLE

    def test_actual_native_boot_identity_is_stable_and_owns_its_raw_handle(self):
        with mock.patch.object(self.registry, "QueryValueEx", wraps=self.registry.QueryValueEx) as query:
            first = ns._boot_identity()
            first_handle = query.call_args.args[0]
        self.assertEqual(str(uuid.UUID(first)), first)
        self.assert_closed(first_handle)
        with mock.patch.object(self.registry, "QueryValueEx", wraps=self.registry.QueryValueEx) as query:
            second = ns._boot_identity()
            second_handle = query.call_args.args[0]
        self.assertEqual(second, first)
        self.assert_closed(second_handle)

    def test_actual_native_key_is_closed_when_existing_identity_is_invalid(self):
        ns._boot_identity()
        for kind, value in ((self.registry.REG_SZ, "invalid UUID"), (self.registry.REG_DWORD, 7)):
            with self.subTest(kind=kind):
                with self.registry.OpenKey(self.registry.HKEY_CURRENT_USER,
                        self.path + r"\CompartmentBoot", 0, self.access) as key:
                    self.registry.SetValueEx(key, "BootId", 0, kind, value)
                with mock.patch.object(self.registry, "QueryValueEx", wraps=self.registry.QueryValueEx) as query:
                    with self.assertRaises(ns.ProxyError) as caught:
                        ns._boot_identity()
                    handle = query.call_args.args[0]
                self.assertEqual(caught.exception.code, "namespace_unsupported")
                self.assert_closed(handle)


class FakeCompartmentAPI:
    """Records the privileged calls a real _CompartmentAPI would make."""

    def __init__(self, *, bind_error=None):
        self.calls = []
        self.default = 1
        self._next = 2
        self.bind_error = bind_error
        self.open_jobs = []
        self.rows = {}

    def create(self, guid, description):
        cid = self._next
        self._next += 1
        self.calls.append(("create", cid))
        self.rows[cid] = {"CompartmentId": cid, "CompartmentGuid": guid,
                          "CompartmentDescription": description}
        return cid

    def inspect(self, cid=None):
        if cid is None:
            return list(self.rows.values())
        return {"compartments": list(self.rows.values()), "interfaces": [{"InterfaceIndex": 1}],
                "addresses": [{"InterfaceIndex": 1, "IPAddress": "127.0.0.1"}],
                "routes": [{"DestinationPrefix": "127.0.0.0/8", "NextHop": "0.0.0.0"}]}

    def terminate_job(self, job):
        self.calls.append(("terminate", job))

    def bind_job(self, pid, handle, cid):
        self.calls.append(("bind_job", pid, handle, cid))
        if self.bind_error is not None:
            raise self.bind_error
        token = ("job", pid, handle, cid)
        self.open_jobs.append(token)
        return token

    def delete(self, cid):
        self.calls.append(("delete", cid))
        return 0

    def close(self, handle):
        self.calls.append(("close", handle))
        if handle in self.open_jobs:
            self.open_jobs.remove(handle)


class FakeRelay:
    instances = []

    def __init__(self, api, cid, proxy_port, upstream_port=None, *, expected_core_pid, core_alive):
        self.api, self.cid, self.proxy_port = api, cid, proxy_port
        self.expected_core_pid, self.core_alive = expected_core_pid, core_alive
        self.started = self.stopped = 0
        self.start_error = None
        FakeRelay.instances.append(self)

    def start(self):
        self.started += 1
        if self.start_error is not None:
            raise self.start_error
        return ["127.0.0.1", "::1"]

    def stop(self):
        self.stopped += 1


class NameTests(unittest.TestCase):
    def test_namespace_name_is_stable_opaque_and_valid(self):
        self.assertTrue(ns.NAMESPACE_RE.fullmatch(NAME))
        self.assertEqual(NAME, ns.namespace_name("app-1"))
        self.assertNotEqual(NAME, ns.namespace_name("app-2"))
        self.assertNotIn("app-1", NAME)

    def test_namespace_name_rejects_invalid_identities(self):
        for bad in ("", "has\0null", 123, None):
            with self.assertRaises(policy.ProxyError):
                ns.namespace_name(bad)


class GateTests(unittest.TestCase):
    def setUp(self):
        FakeRelay.instances = []
        directory = tempfile.TemporaryDirectory()
        self.addCleanup(directory.cleanup)
        self.metadata = {**META, "namespace_state_dir": directory.name, "namespace_backend_version": 1}
        # These journal/Job tests inject the native API and run as an ordinary
        # Windows CI user. The SYSTEM-only directory ACL is tested separately.
        protection = mock.patch.object(service, "protected_path")
        protection.start()
        self.addCleanup(protection.stop)

    def allow(self, gate, *args):
        return gate.allow(*args, core_pid=4322, core_alive=lambda: True)

    def gate(self, **kwargs):
        api = FakeCompartmentAPI(**kwargs)
        gate = ns.NamespaceGate(self.metadata, api=api, relay_factory=FakeRelay, boot_id=BOOT_ID)
        return gate, api

    def test_allow_creates_binds_and_opens_the_only_relay(self):
        gate, api = self.gate()
        result = self.allow(gate, NAME, 7890, 4321, 555)
        self.assertEqual(result, {"container": NAME, "compartment_id": 2, "proxy_port": 7890, "active": True})
        self.assertEqual([c[0] for c in api.calls], ["create", "bind_job"])
        self.assertEqual(api.calls[1], ("bind_job", 4321, 555, 2))
        relay = FakeRelay.instances[-1]
        self.assertEqual(relay.expected_core_pid, 4322)
        self.assertTrue(relay.core_alive())
        self.assertEqual((relay.cid, relay.proxy_port, relay.started), (2, 7890, 1))

    def test_restart_reuses_the_same_compartment_and_replaces_job_and_relay(self):
        gate, api = self.gate()
        self.allow(gate, NAME, 7890, 4321, 555)
        first_relay = FakeRelay.instances[-1]
        self.allow(gate, NAME, 7890, 4321, 777)
        # Only one compartment ever created for this app; the prior relay stopped
        # and the prior Job handle closed before the new bind.
        self.assertEqual([c for c in api.calls if c[0] == "create"], [("create", 2)])
        self.assertEqual(first_relay.stopped, 1)
        self.assertIn(("close", ("job", 4321, 555, 2)), api.calls)
        self.assertEqual(api.calls[-1], ("bind_job", 4321, 777, 2))

    def test_distinct_apps_get_distinct_compartments(self):
        gate, api = self.gate()
        self.allow(gate, NAME, 7890, 4321, 555)
        other = ns.namespace_name("app-2")
        self.allow(gate, other, 7890, 4321, 556)
        self.assertEqual([c for c in api.calls if c[0] == "create"], [("create", 2), ("create", 3)])

    def test_bind_failure_opens_no_relay_and_leaks_no_handle(self):
        gate, api = self.gate(bind_error=policy.ProxyError("namespace_failed", "bind denied"))
        with self.assertRaises(policy.ProxyError):
            self.allow(gate, NAME, 7890, 4321, 555)
        self.assertEqual(FakeRelay.instances, [])
        self.assertNotIn("close", [c[0] for c in api.calls])
        self.assertFalse(gate.active[NAME]["open"])

    def test_relay_start_failure_closes_the_bound_job(self):
        gate, api = self.gate()
        original = FakeRelay.start
        def boom(self):
            self.started += 1
            raise OSError("listen failed")
        with mock.patch.object(FakeRelay, "start", boom):
            with self.assertRaises(OSError):
                self.allow(gate, NAME, 7890, 4321, 555)
        self.assertIn(("close", ("job", 4321, 555, 2)), api.calls)
        self.assertFalse(gate.active[NAME]["open"])

    def test_revoke_stops_relay_closes_job_and_keeps_compartment(self):
        gate, api = self.gate()
        self.allow(gate, NAME, 7890, 4321, 555)
        relay = FakeRelay.instances[-1]
        result = gate.revoke(NAME)
        self.assertEqual(result, {"container": NAME, "active": False})
        self.assertEqual(relay.stopped, 1)
        self.assertIn(("close", ("job", 4321, 555, 2)), api.calls)
        # Compartment id retained for reuse (a bound compartment cannot be deleted).
        self.assertEqual(gate.active[NAME]["cid"], 2)
        self.assertFalse(gate.active[NAME]["open"])
        # A second allow reuses it without creating another compartment.
        self.allow(gate, NAME, 7890, 4321, 558)
        self.assertEqual([c for c in api.calls if c[0] == "create"], [("create", 2)])

    def test_revoke_unknown_name_is_a_safe_no_op(self):
        gate, api = self.gate()
        self.assertEqual(gate.revoke(NAME), {"container": NAME, "active": False})
        self.assertEqual(api.calls, [])

    def test_purge_seals_everything_and_reports_inactive(self):
        gate, api = self.gate()
        self.allow(gate, NAME, 7890, 4321, 555)
        other = ns.namespace_name("app-2")
        self.allow(gate, other, 7890, 4321, 556)
        result = gate.purge()
        self.assertEqual(result, {"active": False, "purged": sorted([NAME, other])})
        self.assertEqual(set(gate.active), {NAME, other})
        self.assertTrue(all(record["phase"] == "clean" for record in gate.active.values()))
        self.assertEqual(sum(1 for r in FakeRelay.instances if r.stopped), 2)
        self.assertEqual([c for c in api.calls if c[0] == "delete"], [])

    def test_clean_compartment_reused_after_service_reconstruction(self):
        gate, api = self.gate()
        self.allow(gate, NAME, 7890, 4321, 555)
        gate.purge()
        recovered = ns.NamespaceGate(self.metadata, api=api, relay_factory=FakeRelay, boot_id=BOOT_ID)
        self.allow(recovered, NAME, 7890, 4321, 556)
        self.assertEqual([c for c in api.calls if c[0] == "create"], [("create", 2)])

    def test_crashed_open_compartment_cannot_be_reopened(self):
        gate, api = self.gate()
        self.allow(gate, NAME, 7890, 4321, 555)
        recovered = ns.NamespaceGate(self.metadata, api=api, relay_factory=FakeRelay, boot_id=BOOT_ID)
        recovered.purge()
        before = len(FakeRelay.instances)
        with self.assertRaises(policy.ProxyError) as caught:
            self.allow(recovered, NAME, 7890, 4321, 556)
        self.assertEqual(caught.exception.code, "namespace_reboot_required")
        self.assertEqual(len(FakeRelay.instances), before)

    def test_unconfirmed_job_termination_keeps_dirty_journal_and_no_replacement(self):
        gate, api = self.gate()
        self.allow(gate, NAME, 7890, 4321, 555)
        with mock.patch.object(api, "terminate_job", side_effect=OSError("still running")):
            with self.assertRaises(OSError):
                self.allow(gate, NAME, 7890, 4321, 556)
        saved = json.loads(gate.path.read_text())
        self.assertEqual(saved["compartments"][NAME]["phase"], "dirty")
        self.assertEqual(len(FakeRelay.instances), 1)

    def test_new_boot_resets_quota_only_when_old_compartments_are_gone(self):
        gate, api = self.gate()
        self.allow(gate, NAME, 7890, 4321, 555)
        next_boot = str(uuid.uuid4())
        recovered = ns.NamespaceGate(self.metadata, api=api, relay_factory=FakeRelay, boot_id=next_boot)
        with self.assertRaises(policy.ProxyError):
            self.allow(recovered, NAME, 7890, 4321, 556)
        api.rows.clear()
        self.allow(recovered, NAME, 7890, 4321, 556)
        self.assertEqual(recovered.active[NAME]["cid"], 3)

    def test_quota_retains_stopped_app_records(self):
        gate, api = self.gate()
        gate.MAX_COMPARTMENTS = 2
        for i in range(2):
            name = ns.namespace_name(str(i))
            self.allow(gate, name, 7890, 4321, 555 + i)
            gate.revoke(name)
        with self.assertRaises(policy.ProxyError) as caught:
            self.allow(gate, NAME, 7890, 4321, 558)
        self.assertEqual(caught.exception.code, "namespace_quota")
        self.assertEqual(len(api.rows), 2)

    def test_changed_os_identity_or_network_refuses_reuse(self):
        for change in ("guid", "description", "external_route", "external_interface"):
            with self.subTest(change=change):
                gate, api = self.gate()
                # Each subtest starts with a fresh protected journal.
                gate.path.unlink(missing_ok=True)
                self.allow(gate, NAME, 7890, 4321, 555)
                gate.revoke(NAME)
                if change == "guid":
                    api.rows[2]["CompartmentGuid"] = str(uuid.uuid4())
                elif change == "description":
                    api.rows[2]["CompartmentDescription"] = "foreign"
                else:
                    observation = api.inspect(2)
                    if change == "external_route":
                        observation["routes"].append({"DestinationPrefix": "0.0.0.0/0", "NextHop": "10.0.0.1"})
                    else:
                        observation["interfaces"].append({"InterfaceIndex": 25})
                    api.inspect = lambda cid=None: observation
                with self.assertRaises(policy.ProxyError):
                    self.allow(gate, NAME, 7890, 4321, 556)

    def test_incomplete_creation_is_recovered_by_recorded_guid(self):
        gate, api = self.gate()
        self.allow(gate, NAME, 7890, 4321, 555)
        gate.revoke(NAME)
        saved = json.loads(gate.path.read_text())
        saved["compartments"][NAME].update(cid=None, phase="creating")
        gate.path.write_text(json.dumps(saved))
        recovered = ns.NamespaceGate(self.metadata, api=api, relay_factory=FakeRelay, boot_id=BOOT_ID)
        self.allow(recovered, NAME, 7890, 4321, 556)
        self.assertEqual(len(api.rows), 1)

    def test_lost_or_malformed_journal_does_not_allocate_more_compartments(self):
        gate, api = self.gate()
        self.allow(gate, NAME, 7890, 4321, 555)
        gate.purge()
        for raw in (None, "{}", "[1]"):
            if raw is None:
                gate.path.unlink(missing_ok=True)
            else:
                gate.path.write_text(raw)
            recovered = ns.NamespaceGate(self.metadata, api=api, relay_factory=FakeRelay, boot_id=BOOT_ID)
            with self.assertRaises(policy.ProxyError):
                self.allow(recovered, NAME, 7890, 4321, 556)
            self.assertEqual(len(api.rows), 1)

    def test_journal_failure_before_binding_never_opens_network(self):
        gate, api = self.gate()
        with mock.patch.object(ns.os, "replace", side_effect=OSError("disk full")):
            with self.assertRaises(policy.ProxyError):
                self.allow(gate, NAME, 7890, 4321, 555)
        self.assertEqual(api.calls, [])
        self.assertEqual(FakeRelay.instances, [])

    def test_old_installation_requires_repair_only_for_namespace_start(self):
        gate = ns.NamespaceGate(META, api=FakeCompartmentAPI(), boot_id=BOOT_ID)
        self.assertFalse(gate.purge()["active"])
        with self.assertRaises(policy.ProxyError) as caught:
            self.allow(gate, NAME, 7890, 4321, 555)
        self.assertEqual(caught.exception.code, "setup_required")

    def test_invalid_arguments_raise_before_any_privileged_call(self):
        gate, api = self.gate()
        for args in ((NAME, 53, 4321, 555), (NAME, 7890, 0, 555), (NAME, 7890, 4321, 0),
                     ("RuleProxy.0123456789abcdef0123", 7890, 4321, 555),
                     (NAME, 7890, 4321, True), (NAME, True, 4321, 555)):
            with self.subTest(args=args), self.assertRaises(policy.ProxyError):
                self.allow(gate, *args)
        self.assertEqual(api.calls, [])

    def test_core_identity_is_required_before_any_privileged_call(self):
        gate, api = self.gate()
        for pid, alive in ((True, lambda: True), (0, lambda: True), (2**32, lambda: True),
                           (4322, None), (4322, lambda: False)):
            with self.subTest(pid=pid), self.assertRaises(ns.ProxyError):
                gate.allow(NAME, 7890, 4321, 555, core_pid=pid, core_alive=alive)
        self.assertEqual(api.calls, [])
        self.assertEqual(FakeRelay.instances, [])

    def test_unprotected_state_directory_refuses_native_allocation(self):
        gate, api = self.gate()
        with mock.patch.object(ns.os, "name", "nt"), \
                mock.patch.object(service, "protected_path", side_effect=ns.ProxyError("unsafe_installation", "ACL")):
            with self.assertRaisesRegex(ns.ProxyError, "ACL"):
                self.allow(gate, NAME, 7890, 4321, 555)
        self.assertEqual(api.calls, [])
        self.assertEqual(FakeRelay.instances, [])


def _free_port():
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as probe:
        probe.bind(("127.0.0.1", 0))
        return probe.getsockname()[1]


class RelayTests(unittest.TestCase):
    """The real relay on a single-compartment host: switches are stubbed, the
    upstream points at a distinct port, so forwarding is verified end to end."""

    def make_relay(self, *args, **kwargs):
        kwargs.setdefault("expected_core_pid", 4322)
        kwargs.setdefault("core_alive", lambda: True)
        kwargs.setdefault("peer_verifier", lambda sock, pid: True)
        return ns._Relay(*args, **kwargs)

    def _echo_server(self):
        server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        server.bind(("127.0.0.1", 0))
        server.listen(8)
        port = server.getsockname()[1]
        def serve():
            try:
                while True:
                    conn, _ = server.accept()
                    data = conn.recv(65536)
                    conn.sendall(b"echo:" + data)
                    conn.close()
            except OSError:
                pass
        threading.Thread(target=serve, daemon=True).start()
        self.addCleanup(server.close)
        return port

    def _api(self, cid):
        switched = []
        api = SimpleNamespace(default=cid)
        api.i = SimpleNamespace(
            SetCurrentThreadCompartmentId=lambda value: switched.append(int(value.value)) or 0,
            GetCurrentThreadCompartmentId=lambda: cid)
        api.switched = switched
        return api

    def test_relay_forwards_the_proxy_port_and_stops_cleanly(self):
        upstream = self._echo_server()
        listen = _free_port()
        api = self._api(2)
        relay = self.make_relay(api, 2, listen, upstream_port=upstream)
        bound = relay.start()
        self.addCleanup(relay.stop)
        self.assertIn("127.0.0.1", bound)
        with socket.create_connection(("127.0.0.1", listen), timeout=5) as client:
            client.settimeout(5)
            client.sendall(b"ping")
            received = b""
            while True:
                chunk = client.recv(65536)
                if not chunk:
                    break
                received += chunk
        self.assertEqual(received, b"echo:ping")
        self.assertEqual(relay.accepted, 1)
        # The listener thread entered the compartment; a worker dialed upstream
        # from the default compartment.
        self.assertIn(2, api.switched)
        listener = relay.listeners[0]
        relay.stop()
        time.sleep(0.1)
        # Stop seals the relay: the loop ends and every tracked socket is closed.
        self.assertTrue(relay.stopping.is_set())
        self.assertEqual(relay.listeners, [])
        self.assertEqual(relay.connections, set())
        self.assertEqual(listener.fileno(), -1)

    def test_relay_reports_failure_when_nothing_binds(self):
        busy = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        busy.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        busy.bind(("127.0.0.1", 0))
        busy.listen(1)
        self.addCleanup(busy.close)
        port = busy.getsockname()[1]
        api = self._api(2)
        # The advertised endpoint is IPv4; an IPv6-only bind is not success.
        relay = self.make_relay(api, 2, port, upstream_port=port)
        with self.assertRaises(ns.ProxyError):
            relay.start()
        self.assertEqual(relay.listeners, [])

    def test_listener_thread_start_failure_leaves_an_idempotently_sealed_relay(self):
        relay = self.make_relay(self._api(2), 2, _free_port())
        with mock.patch.object(threading.Thread, "start", side_effect=RuntimeError("thread quota exhausted")):
            with self.assertRaisesRegex(RuntimeError, "quota"):
                relay.start()
        relay.stop()
        relay.stop()
        self.assertIsNone(relay._listener)
        self.assertTrue(relay.stopping.is_set())
        self.assertEqual(relay.listeners, [])
        self.assertEqual(relay.connections, set())
        with self.assertRaises(ns.ProxyError):
            relay.start()

    def _one_connection_server(self, handler):
        server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        server.bind(("127.0.0.1", 0))
        server.listen(8)
        server.settimeout(5)
        errors = []
        def serve():
            try:
                conn, _ = server.accept()
                with conn:
                    conn.settimeout(5)
                    handler(conn)
            except Exception as exc:
                errors.append(exc)
            finally:
                server.close()
        thread = threading.Thread(target=serve, daemon=True)
        thread.start()
        self.addCleanup(lambda: thread.join(6))
        self.addCleanup(server.close)
        return server.getsockname()[1], thread, errors

    def _relay(self, upstream):
        relay = self.make_relay(self._api(2), 2, _free_port(), upstream_port=upstream)
        relay.start()
        self.addCleanup(relay.stop)
        return relay

    def test_client_half_close_preserves_large_reverse_response_and_backpressure(self):
        payload = b"request" * 100000
        response = b"response" * 100000
        received = bytearray()
        def serve(conn):
            while True:
                chunk = conn.recv(32768)
                if not chunk:
                    break
                received.extend(chunk)
            conn.sendall(response)
            conn.shutdown(socket.SHUT_WR)
        upstream, thread, errors = self._one_connection_server(serve)
        relay = self._relay(upstream)
        with socket.create_connection(("127.0.0.1", relay.proxy_port), timeout=5) as client:
            client.sendall(payload)
            client.shutdown(socket.SHUT_WR)
            result = bytearray()
            while True:
                chunk = client.recv(8192)
                if not chunk:
                    break
                result.extend(chunk)
        thread.join(5)
        relay.stop()
        self.assertEqual(errors, [])
        self.assertEqual(received, payload)
        self.assertEqual(result, response)
        self.assertEqual(relay.connections, set())
        self.assertEqual(relay._workers, set())

    def test_upstream_half_close_still_allows_later_client_request(self):
        received = bytearray()
        def serve(conn):
            conn.sendall(b"ready")
            conn.shutdown(socket.SHUT_WR)
            while True:
                data = conn.recv(65536)
                if not data:
                    break
                received.extend(data)
        upstream, thread, errors = self._one_connection_server(serve)
        relay = self._relay(upstream)
        with socket.create_connection(("127.0.0.1", relay.proxy_port), timeout=5) as client:
            response = bytearray()
            while True:
                data = client.recv(65536)
                if not data:
                    break
                response.extend(data)
            client.sendall(b"late request")
            client.shutdown(socket.SHUT_WR)
        thread.join(5)
        self.assertEqual(response, b"ready")
        self.assertEqual(received, b"late request")
        self.assertEqual(errors, [])

    def test_many_finished_connections_do_not_retain_sockets_or_workers(self):
        relay = self._relay(self._echo_server())
        for _ in range(25):
            with socket.create_connection(("127.0.0.1", relay.proxy_port), timeout=5) as client:
                client.sendall(b"x")
                client.shutdown(socket.SHUT_WR)
                while client.recv(1024):
                    pass
        deadline = time.monotonic() + 2
        while relay._workers and time.monotonic() < deadline:
            time.sleep(0.01)
        self.assertEqual(relay.connections, set())
        self.assertEqual(relay._workers, set())

    def test_worker_quota_closes_excess_clients_and_stop_joins_active_workers(self):
        entered, release = threading.Event(), threading.Event()
        def serve(conn):
            entered.set()
            release.wait(5)
        upstream, thread, errors = self._one_connection_server(serve)
        relay = self._relay(upstream)
        relay.MAX_CONNECTIONS = 1
        self.addCleanup(release.set)
        with socket.create_connection(("127.0.0.1", relay.proxy_port), timeout=5) as first:
            self.assertTrue(entered.wait(3))
            with socket.create_connection(("127.0.0.1", relay.proxy_port), timeout=5) as extra:
                self.assertEqual(extra.recv(1), b"")
            self.assertEqual(len(relay._workers), 1)
            self.assertEqual(relay.accepted, 1)
            relay.stop()
            self.assertEqual(first.recv(1), b"")
        self.assertEqual(relay._workers, set())
        release.set()
        thread.join(5)

    def test_stop_during_bind_cannot_publish_a_late_listener(self):
        entered = threading.Event()
        relay = self.make_relay(self._api(2), 2, _free_port(), upstream_port=12345)
        real_socket = socket.socket
        class LateBind(real_socket):
            def bind(self, address):
                if address[0] == "127.0.0.1":
                    entered.set()
                    relay.stopping.wait(3)
                return super().bind(address)
        failures = []
        def start():
            try:
                relay.start()
            except ns.ProxyError as exc:
                failures.append(exc)
        with mock.patch.object(ns.socket, "socket", LateBind):
            starter = threading.Thread(target=start)
            starter.start()
            self.assertTrue(entered.wait(3))
            relay.stop()
            starter.join(5)
        self.assertFalse(starter.is_alive())
        self.assertEqual(len(failures), 1)
        self.assertEqual(relay.listeners, [])
        with real_socket(socket.AF_INET, socket.SOCK_STREAM) as probe:
            probe.bind(("127.0.0.1", relay.proxy_port))

    def test_default_compartment_switch_failure_never_dials_upstream(self):
        relay = self._relay(self._echo_server())
        relay.api.i.SetCurrentThreadCompartmentId = lambda value: 5
        with socket.create_connection(("127.0.0.1", relay.proxy_port), timeout=5) as client:
            self.assertEqual(client.recv(1), b"")
        relay.stop()
        self.assertTrue(any("switch failed" in error for error in relay.errors))

    def test_peer_identity_requires_the_exact_established_server_tuple(self):
        upstream = mock.Mock()
        upstream.getsockname.return_value = ("127.0.0.1", 50001)
        upstream.getpeername.return_value = ("127.0.0.1", 7890)
        owned = {"state": 5, "pid": 4322, "local": "127.0.0.1", "local_port": 7890,
                 "remote": "127.0.0.1", "remote_port": 50001}
        with mock.patch.object(service, "_tcp_connections", return_value=[owned]) as snapshot:
            self.assertTrue(ns._Relay._peer_owned(upstream, 4322))
            snapshot.assert_called_once_with(socket.AF_INET)
        for key, wrong in (("pid", 999), ("state", 2), ("local", "127.0.0.2"), ("local_port", 7891),
                           ("remote", "127.0.0.2"), ("remote_port", 50002)):
            with self.subTest(key=key), mock.patch.object(service, "_tcp_connections", return_value=[{**owned, key: wrong}]):
                self.assertFalse(ns._Relay._peer_owned(upstream, 4322))

    def test_rejected_peer_never_receives_proxy_bytes(self):
        for reason in ("foreign owner", "snapshot failed", "core exited", "core exited during snapshot"):
            with self.subTest(reason=reason):
                received = []
                upstream, thread, errors = self._one_connection_server(lambda conn: received.append(conn.recv(100)))
                alive = mock.Mock(return_value=True)
                verifier = mock.Mock(return_value=True)
                if reason == "foreign owner":
                    verifier.return_value = False
                elif reason == "snapshot failed":
                    verifier.side_effect = ns.ProxyError("network_state_unavailable", "snapshot failed")
                elif reason == "core exited":
                    alive.return_value = False
                else:
                    alive.side_effect = [True, False]
                relay = self.make_relay(self._api(2), 2, _free_port(), upstream_port=upstream,
                    core_alive=alive, peer_verifier=verifier)
                relay.start()
                self.addCleanup(relay.stop)
                with socket.create_connection(("127.0.0.1", relay.proxy_port), timeout=5) as client:
                    try:
                        client.sendall(b"CONNECT private.example:443 HTTP/1.1\r\n\r\n")
                        self.assertEqual(client.recv(1), b"")
                    except (ConnectionResetError, ConnectionAbortedError):
                        # Windows can abort the local side while the relay
                        # closes an unread request; upstream must still see EOF.
                        pass
                thread.join(5)
                relay.stop()
                self.assertFalse(thread.is_alive())
                self.assertEqual(errors, [])
                self.assertEqual(received, [b""])
                self.assertTrue(relay.errors)

    def test_verified_established_owner_can_receive_proxy_bytes(self):
        expected = b"CONNECT allowed.example:443 HTTP/1.1\r\n\r\n"
        received = []
        def serve(conn):
            received.append(conn.recv(100))
            conn.sendall(b"OK")
        upstream, thread, errors = self._one_connection_server(serve)
        def verify(connected, pid):
            local, remote = connected.getsockname(), connected.getpeername()
            row = {"state": 5, "pid": 4322, "local": remote[0], "local_port": remote[1],
                   "remote": local[0], "remote_port": local[1]}
            with mock.patch.object(service, "_tcp_connections", return_value=[row]):
                return ns._Relay._peer_owned(connected, pid)
        relay = self.make_relay(self._api(2), 2, _free_port(), upstream_port=upstream, peer_verifier=verify)
        relay.start()
        self.addCleanup(relay.stop)
        with socket.create_connection(("127.0.0.1", relay.proxy_port), timeout=5) as client:
            client.sendall(expected)
            self.assertEqual(client.recv(2), b"OK")
        thread.join(5)
        relay.stop()
        self.assertEqual(received, [expected])
        self.assertEqual(errors, [])


class BrokerDispatchTests(unittest.TestCase):
    def broker(self):
        gate = mock.Mock()
        gate.allow.return_value = {"active": True}
        gate.revoke.return_value = {"active": False}
        factory = mock.Mock(return_value=gate)
        broker = service.Broker(META, mock.Mock(), mock.Mock(), mock.Mock(), namespace_factory=factory)
        return broker, gate, factory

    def test_namespace_allow_requires_the_held_panel_core_and_port(self):
        broker, gate, factory = self.broker()
        request = {"op": "namespace_allow", "client_pid": 101, "container": NAME,
                   "proxy_port": 7890, "job_handle": 555}
        for pid, sid in ((102, OWNER), (101, OWNER + "1")):
            with self.assertRaises(policy.ProxyError):
                broker.handle(request, pid, sid)
        factory.assert_not_called()
        broker.panel = mock.Mock(pid=101)
        broker.core = mock.Mock(pid=102)
        broker.port = 1234  # mismatched port is refused before any gate call
        with self.assertRaises(policy.ProxyError):
            broker.handle(request, 101, OWNER)
        gate.allow.assert_not_called()
        broker.port = 7890
        self.assertEqual(broker.handle(request, 101, OWNER), {"active": True})
        gate.allow.assert_called_once_with(NAME, 7890, 101, 555, core_pid=102, core_alive=mock.ANY)
        self.assertIn(NAME, broker.namespaces)

    def test_namespace_revoke_dispatches_and_forgets_the_name(self):
        broker, gate, factory = self.broker()
        broker.panel = mock.Mock(pid=101)
        broker.core = mock.Mock(pid=102)
        broker.port = 7890
        broker.handle({"op": "namespace_allow", "client_pid": 101, "container": NAME,
                       "proxy_port": 7890, "job_handle": 555}, 101, OWNER)
        broker.handle({"op": "namespace_revoke", "client_pid": 101, "container": NAME}, 101, OWNER)
        gate.revoke.assert_called_once_with(NAME)
        self.assertNotIn(NAME, broker.namespaces)

    def test_namespace_allow_without_a_panel_is_an_instance_conflict(self):
        broker, gate, factory = self.broker()
        request = {"op": "namespace_allow", "client_pid": 101, "container": NAME,
                   "proxy_port": 7890, "job_handle": 555}
        with self.assertRaises(policy.ProxyError):
            broker.handle(request, 101, OWNER)
        gate.allow.assert_not_called()


class LaunchFlowTests(unittest.TestCase):
    def flow(self, *, launch_error=None, fire_hook=True):
        events = self.events = []
        backend = mock.Mock()
        backend.namespace_allow.side_effect = lambda *a: events.append(("allow", *a))
        backend.namespace_revoke.side_effect = lambda *a: events.append(("revoke", *a))

        def launch(command, env, **options):
            events.append(("launch", options.get("native_proxy_port"), callable(options.get("prepare_job"))))
            if fire_hook:
                options["prepare_job"](555)
            if launch_error:
                raise launch_error
            return "process"

        return backend, ns.start_namespaced(backend, "app-1", ["app.exe"], {"PATH": "x"},
                                            proxy_port=7890, launch=launch), events

    def test_gate_opens_through_the_hook_before_launch_returns(self):
        backend, (process, lease), events = self.flow()
        self.assertEqual(process, "process")
        self.assertEqual(events[0], ("launch", 7890, True))
        self.assertEqual(events[1], ("allow", NAME, 7890, 555))
        self.assertEqual(lease.name, NAME)
        lease.close()
        lease.close()
        self.assertEqual(events[-1], ("revoke", NAME))
        self.assertEqual(sum(1 for e in events if e[0] == "revoke"), 1)

    def test_failed_launch_after_the_hook_revokes_once(self):
        with self.assertRaises(OSError):
            self.flow(launch_error=OSError("denied"))
        self.assertEqual(self.events[-1], ("revoke", NAME))
        self.assertEqual(sum(1 for e in self.events if e[0] == "allow"), 1)
        self.assertEqual(sum(1 for e in self.events if e[0] == "revoke"), 1)

    def test_failed_launch_before_the_hook_still_revokes_intent(self):
        with self.assertRaises(OSError):
            self.flow(launch_error=OSError("denied"), fire_hook=False)
        self.assertNotIn("allow", [e[0] for e in self.events])
        self.assertEqual(self.events[-1], ("revoke", NAME))


class _HookAPI:
    def __init__(self):
        self.calls = []
        self.environment = None
    def record(self, *item):
        self.calls.append(item)
    def is_elevated(self):
        self.record("elevation"); return False
    def create_job(self):
        self.record("create_job"); return 101
    def configure_job(self, job, flags):
        self.record("configure_job", job)
    def create_process(self, command, environment, cwd, info):
        info.hProcess, info.hThread, info.dwProcessId = 201, 202, 987
        self.environment = environment
        self.record("create_process")
    def assign_job(self, job, process):
        self.record("assign_job")
    def resume_thread(self, thread):
        self.record("resume_thread")
    def terminate_process(self, process):
        self.record("terminate_process")
    def terminate_job(self, job):
        self.record("terminate_job")
    def wait_process(self, process, milliseconds):
        self.record("wait_process"); return app_process._WAIT_OBJECT_0
    def exit_code(self, process):
        return 0
    def close_handle(self, handle):
        self.record("close_handle", handle)


class LaunchHookTests(unittest.TestCase):
    command = [r"C:\Program Files\Example\app.exe"]

    def test_prepare_job_runs_after_configure_and_before_create_process(self):
        api = _HookAPI()
        seen = []
        with mock.patch.object(app_process, "_get_api", return_value=api):
            app_process.launch(self.command, {"PATH": "x"}, native_proxy_port=7890,
                               prepare_job=lambda job: seen.append(job))
        self.assertEqual(seen, [101])
        actions = [c[0] for c in api.calls]
        self.assertLess(actions.index("configure_job"), actions.index("create_process"))
        # The hook fired between configuring the Job and creating the process.
        self.assertEqual(api.calls[api.calls.index(("configure_job", 101)) + 1][0], "create_process")

    def test_prepare_job_and_container_sid_are_mutually_exclusive(self):
        with mock.patch.object(app_process, "_get_api") as get_api:
            with self.assertRaises(ValueError):
                app_process.launch(self.command, {}, prepare_job=lambda job: None,
                                   container_sid="S-1-15-2-1-2-3-4-5-6-7")
            get_api.assert_not_called()

    def test_non_callable_prepare_job_is_rejected(self):
        with mock.patch.object(app_process, "_get_api") as get_api:
            with self.assertRaises(TypeError):
                app_process.launch(self.command, {}, prepare_job=123)
            get_api.assert_not_called()

    def test_prepare_job_failure_aborts_before_creating_the_process(self):
        api = _HookAPI()
        def boom(job):
            raise ns.ProxyError("namespace_failed", "service refused")
        with mock.patch.object(app_process, "_get_api", return_value=api):
            with self.assertRaises(ns.ProxyError):
                app_process.launch(self.command, {"PATH": "x"}, native_proxy_port=7890, prepare_job=boom)
        actions = [c[0] for c in api.calls]
        self.assertNotIn("create_process", actions)
        self.assertEqual(api.calls[-1], ("close_handle", 101))


if __name__ == "__main__":
    unittest.main()
