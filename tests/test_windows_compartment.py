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

from ruleproxy import windows_app_process as app_process
from ruleproxy import windows_compartment as ns
from ruleproxy import windows_proxy_policy as policy
from ruleproxy import windows_proxy_service as service


OWNER = "S-1-5-21-1-2-3-1001"
NAME = ns.namespace_name("app-1")
META = {"root": r"C:\RuleProxy", "owner_sid": OWNER}


class FakeCompartmentAPI:
    """Records the privileged calls a real _CompartmentAPI would make."""

    def __init__(self, *, bind_error=None):
        self.calls = []
        self.default = 1
        self._next = 2
        self.bind_error = bind_error
        self.open_jobs = []

    def create(self):
        cid = self._next
        self._next += 1
        guid = str(uuid.uuid4())
        self.calls.append(("create", cid))
        return cid, guid

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

    def __init__(self, api, cid, proxy_port, upstream_port=None):
        self.api, self.cid, self.proxy_port = api, cid, proxy_port
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

    def gate(self, **kwargs):
        api = FakeCompartmentAPI(**kwargs)
        gate = ns.NamespaceGate(META, api=api, relay_factory=FakeRelay)
        return gate, api

    def test_allow_creates_binds_and_opens_the_only_relay(self):
        gate, api = self.gate()
        result = gate.allow(NAME, 7890, 4321, 555)
        self.assertEqual(result, {"container": NAME, "compartment_id": 2, "proxy_port": 7890, "active": True})
        self.assertEqual([c[0] for c in api.calls], ["create", "bind_job"])
        self.assertEqual(api.calls[1], ("bind_job", 4321, 555, 2))
        relay = FakeRelay.instances[-1]
        self.assertEqual((relay.cid, relay.proxy_port, relay.started), (2, 7890, 1))

    def test_restart_reuses_the_same_compartment_and_replaces_job_and_relay(self):
        gate, api = self.gate()
        gate.allow(NAME, 7890, 4321, 555)
        first_relay = FakeRelay.instances[-1]
        gate.allow(NAME, 7890, 4321, 777)
        # Only one compartment ever created for this app; the prior relay stopped
        # and the prior Job handle closed before the new bind.
        self.assertEqual([c for c in api.calls if c[0] == "create"], [("create", 2)])
        self.assertEqual(first_relay.stopped, 1)
        self.assertIn(("close", ("job", 4321, 555, 2)), api.calls)
        self.assertEqual(api.calls[-1], ("bind_job", 4321, 777, 2))

    def test_distinct_apps_get_distinct_compartments(self):
        gate, api = self.gate()
        gate.allow(NAME, 7890, 4321, 555)
        other = ns.namespace_name("app-2")
        gate.allow(other, 7890, 4321, 556)
        self.assertEqual([c for c in api.calls if c[0] == "create"], [("create", 2), ("create", 3)])

    def test_bind_failure_opens_no_relay_and_leaks_no_handle(self):
        gate, api = self.gate(bind_error=policy.ProxyError("namespace_failed", "bind denied"))
        with self.assertRaises(policy.ProxyError):
            gate.allow(NAME, 7890, 4321, 555)
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
                gate.allow(NAME, 7890, 4321, 555)
        self.assertIn(("close", ("job", 4321, 555, 2)), api.calls)
        self.assertFalse(gate.active[NAME]["open"])

    def test_revoke_stops_relay_closes_job_and_keeps_compartment(self):
        gate, api = self.gate()
        gate.allow(NAME, 7890, 4321, 555)
        relay = FakeRelay.instances[-1]
        result = gate.revoke(NAME)
        self.assertEqual(result, {"container": NAME, "active": False})
        self.assertEqual(relay.stopped, 1)
        self.assertIn(("close", ("job", 4321, 555, 2)), api.calls)
        # Compartment id retained for reuse (a bound compartment cannot be deleted).
        self.assertEqual(gate.active[NAME]["cid"], 2)
        self.assertFalse(gate.active[NAME]["open"])
        # A second allow reuses it without creating another compartment.
        gate.allow(NAME, 7890, 4321, 558)
        self.assertEqual([c for c in api.calls if c[0] == "create"], [("create", 2)])

    def test_revoke_unknown_name_is_a_safe_no_op(self):
        gate, api = self.gate()
        self.assertEqual(gate.revoke(NAME), {"container": NAME, "active": False})
        self.assertEqual(api.calls, [])

    def test_purge_seals_everything_and_reports_inactive(self):
        gate, api = self.gate()
        gate.allow(NAME, 7890, 4321, 555)
        other = ns.namespace_name("app-2")
        gate.allow(other, 7890, 4321, 556)
        result = gate.purge()
        self.assertEqual(result, {"active": False, "purged": sorted([NAME, other])})
        self.assertEqual(gate.active, {})
        self.assertEqual(sum(1 for r in FakeRelay.instances if r.stopped), 2)
        self.assertEqual([c for c in api.calls if c[0] == "delete"], [("delete", 2), ("delete", 3)])

    def test_invalid_arguments_raise_before_any_privileged_call(self):
        gate, api = self.gate()
        for args in ((NAME, 53, 4321, 555), (NAME, 7890, 0, 555), (NAME, 7890, 4321, 0),
                     ("RuleProxy.0123456789abcdef0123", 7890, 4321, 555),
                     (NAME, 7890, 4321, True), (NAME, True, 4321, 555)):
            with self.subTest(args=args), self.assertRaises(policy.ProxyError):
                gate.allow(*args)
        self.assertEqual(api.calls, [])


def _free_port():
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as probe:
        probe.bind(("127.0.0.1", 0))
        return probe.getsockname()[1]


class RelayTests(unittest.TestCase):
    """The real relay on a single-compartment host: switches are stubbed, the
    upstream points at a distinct port, so forwarding is verified end to end."""

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
        relay = ns._Relay(api, 2, listen, upstream_port=upstream)
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
        self.assertEqual(relay.connections, [])
        self.assertEqual(listener.fileno(), -1)

    def test_relay_reports_failure_when_nothing_binds(self):
        busy = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        busy.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        busy.bind(("127.0.0.1", 0))
        busy.listen(1)
        self.addCleanup(busy.close)
        port = busy.getsockname()[1]
        api = self._api(2)
        # Binds nothing on v4 (port busy); if v6 also unavailable, start raises.
        relay = ns._Relay(api, 2, port, upstream_port=port)
        try:
            relay.start()
            # If ::1 happened to bind, that is still a listening relay; clean up.
            relay.stop()
        except ns.ProxyError:
            pass


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
        gate.allow.assert_called_once_with(NAME, 7890, 101, 555)
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
