"""Exercise IPC lifecycle races without requiring Windows or an installed driver."""
import ctypes
import json
import threading
from types import SimpleNamespace
import unittest
from unittest import mock

from ruleproxy import windows_proxy_client as client
from ruleproxy import windows_proxy_policy as policy
from ruleproxy import windows_proxy_service as service


SERVER_HANDLE = 0x100000789
OWNER_SID = "S-1-5-21-1-2-3-1000"
INVALID_HANDLE = ctypes.c_void_p(-1).value


class Function:
    """Callable accepting ctypes signature attributes like a DLL function."""
    def __init__(self, callback):
        self.callback = callback

    def __call__(self, *args):
        return self.callback(*args)


class Clock:
    def __init__(self):
        self.now = 0.0

    def monotonic(self):
        return self.now

    def sleep(self, seconds):
        self.now += seconds


class ConnectionAPI:
    def __init__(self, waits, opens, clock):
        self.waits = list(waits)
        self.opens = list(opens)
        self.clock = clock
        self.error = 0
        self.wait_calls = []
        self.open_calls = []
        self.closed = []
        self.kernel = SimpleNamespace(
            WaitNamedPipeW=Function(self.wait),
            CreateFileW=Function(self.open),
            CloseHandle=Function(lambda handle: self.closed.append(handle) or True),
            SetNamedPipeHandleState=Function(lambda *_args: True),
            GetNamedPipeServerProcessId=Function(self.server_pid),
        )

    def wait(self, name, milliseconds):
        self.wait_calls.append(milliseconds)
        # A faulty implementation that resets its deadline must fail the test,
        # rather than keep the test runner in an unbounded loop.
        if len(self.wait_calls) > 30:
            raise AssertionError("connection retries did not respect one deadline")
        self.clock.now += min(milliseconds / 1000, 0.1)
        self.error = self.waits.pop(0) if len(self.waits) > 1 else self.waits[0]
        return self.error == 0

    def open(self, *args):
        self.open_calls.append(args)
        value = self.opens.pop(0) if len(self.opens) > 1 else self.opens[0]
        if value in (2, 3, 5, 231):
            self.error = value
            return INVALID_HANDLE
        return value

    @staticmethod
    def server_pid(_handle, pointer):
        pointer._obj.value = 987
        return True


class WindowsProxyPipeTests(unittest.TestCase):
    def test_server_reuses_first_instance_while_acknowledged_client_handle_lingers(self):
        stopping = threading.Event()
        calls = []
        responses = []
        requests = [
            {"schema_version": 1, "request_id": str(index) * 32,
             "op": "status", "client_pid": 123}
            for index in (1, 2)
        ]
        broker = SimpleNamespace(
            metadata={"owner_sid": OWNER_SID, "pipe_name": policy.pipe_name(OWNER_SID)},
            panel=None, lock=threading.RLock(),
            handle=mock.Mock(return_value={"state": "idle", "generation": 0}),
        )

        class API:
            def __init__(self):
                self.created = False
                self.current = 0
                self.kernel = SimpleNamespace(
                    CreateNamedPipeW=Function(self.create),
                    DisconnectNamedPipe=Function(lambda handle: calls.append(("disconnect", handle)) or True),
                    CloseHandle=Function(lambda handle: calls.append(("close", handle)) or True),
                    LocalFree=Function(lambda pointer: calls.append(("free", pointer))),
                )
                self.advapi = SimpleNamespace(
                    ConvertStringSecurityDescriptorToSecurityDescriptorW=Function(self.descriptor),
                )

            @staticmethod
            def descriptor(_text, _revision, pointer, _length):
                pointer._obj.value = 456
                return True

            def create(self, _name, mode, *_args):
                # The previous client's ACK has arrived, but it deliberately
                # retains its own handle. FIRST_PIPE_INSTANCE cannot be created
                # again while that old instance still exists.
                if self.created:
                    raise AssertionError("server recreated a pipe while its old client handle was open")
                self.created = True
                self_test.assertTrue(mode & 0x80000)
                calls.append(("create", SERVER_HANDLE))
                return SERVER_HANDLE

            def operation(self, handle, operation, *, buffer=None, **_kwargs):
                self_test.assertEqual(handle, SERVER_HANDLE)
                calls.append((operation, handle))
                if operation == "connect":
                    return 0
                if operation == "write":
                    responses.append(json.loads(buffer.raw.decode("ascii")))
                    return len(buffer)
                if len(buffer) == 1:
                    buffer[0] = b"1"
                    self.current += 1
                    if self.current == 2:
                        stopping.set()
                    return 1
                raw = json.dumps(requests[self.current]).encode("ascii")
                ctypes.memmove(buffer, raw, len(raw))
                return len(raw)

            @staticmethod
            def caller(_handle):
                return 123, OWNER_SID

        self_test = self
        api = API()
        with mock.patch.object(service, "PipeAPI", return_value=api), \
                mock.patch.object(service.threading, "Thread") as worker:
            service.serve(broker, stopping)
        self.assertEqual(broker.handle.call_count, 2)
        self.assertEqual([row["request_id"] for row in responses], ["1" * 32, "2" * 32])
        self.assertTrue(all(row["ok"] for row in responses))
        self.assertEqual(calls.count(("create", SERVER_HANDLE)), 1)
        self.assertEqual(calls.count(("disconnect", SERVER_HANDLE)), 2)
        self.assertEqual(calls.count(("close", SERVER_HANDLE)), 1)
        self.assertGreater(calls.index(("close", SERVER_HANDLE)),
                           max(index for index, call in enumerate(calls) if call[0] == "disconnect"))
        worker.return_value.join.assert_called_once()

    def test_open_retries_missing_paths_and_busy_create_before_sending(self):
        clock = Clock()
        api = ConnectionAPI([2, 3, 0, 0], [231, SERVER_HANDLE], clock)
        connection = client.Client(policy.pipe_name(OWNER_SID))
        with mock.patch.object(client, "time", clock, create=True), \
                mock.patch.object(service, "ServiceControl") as control, \
                mock.patch.object(ctypes, "get_last_error", lambda: api.error, create=True):
            control.return_value.status.return_value = {"state": 4}
            handle = connection._open_pipe(api, timeout=1)
        self.assertEqual(handle, SERVER_HANDLE)
        self.assertEqual(len(api.wait_calls), 4)
        self.assertEqual(len(api.open_calls), 2)
        self.assertEqual(api.closed, [])
        self.assertLess(clock.now, 1)

    def test_open_retries_share_one_total_deadline(self):
        clock = Clock()
        api = ConnectionAPI([2], [SERVER_HANDLE], clock)
        connection = client.Client(policy.pipe_name(OWNER_SID))
        with mock.patch.object(client, "time", clock, create=True), \
                mock.patch.object(service, "ServiceControl") as control, \
                mock.patch.object(ctypes, "get_last_error", lambda: api.error, create=True):
            control.return_value.status.return_value = {"state": 4}
            with self.assertRaises(policy.ProxyError):
                connection._open_pipe(api, timeout=0.4)
        self.assertLessEqual(clock.now, 0.6)
        self.assertLess(len(api.wait_calls), 8)
        self.assertEqual(api.open_calls, [])

    def test_missing_pipe_does_not_wait_for_stopped_stopping_or_missing_service(self):
        for state in (1, 3, None):
            with self.subTest(state=state):
                clock = Clock()
                api = ConnectionAPI([2], [SERVER_HANDLE], clock)
                connection = client.Client(policy.pipe_name(OWNER_SID))
                with mock.patch.object(client, "time", clock, create=True), \
                        mock.patch.object(clock, "sleep", wraps=clock.sleep) as pause, \
                        mock.patch.object(service, "ServiceControl") as control, \
                        mock.patch.object(ctypes, "get_last_error", lambda: api.error, create=True):
                    if state is None:
                        control.return_value.status.side_effect = OSError("service does not exist")
                    else:
                        control.return_value.status.return_value = {"state": state}
                    with self.assertRaises(policy.ProxyError):
                        connection._open_pipe(api, timeout=45)
                pause.assert_not_called()
                self.assertEqual(api.open_calls, [])
                self.assertEqual(len(api.wait_calls), 1)

    def test_busy_wait_timeout_can_retry_when_service_is_running(self):
        clock = Clock()
        api = ConnectionAPI([121, 0], [SERVER_HANDLE], clock)
        connection = client.Client(policy.pipe_name(OWNER_SID))
        with mock.patch.object(client, "time", clock, create=True), \
                mock.patch.object(service, "ServiceControl") as control, \
                mock.patch.object(ctypes, "get_last_error", lambda: api.error, create=True):
            control.return_value.status.return_value = {"state": 4}
            self.assertEqual(connection._open_pipe(api, timeout=1), SERVER_HANDLE)
        self.assertEqual(len(api.wait_calls), 2)

    def test_sent_apply_is_never_replayed_after_response_disconnect(self):
        clock = Clock()
        api = ConnectionAPI([0], [SERVER_HANDLE], clock)
        writes = []

        def operation(_handle, name, *, buffer=None, **_kwargs):
            if name == "write":
                writes.append(json.loads(buffer.raw.decode("ascii")))
                return len(buffer)
            # The request may already have changed privileged state. Retrying
            # it after a broken response could apply the mutation twice.
            raise OSError("response pipe disconnected after apply")

        api.operation = operation
        connection = client.Client(policy.pipe_name(OWNER_SID))
        with mock.patch.object(client, "os", SimpleNamespace(name="nt", getpid=lambda: 123)), \
                mock.patch.object(service, "PipeAPI", return_value=api) as factory, \
                mock.patch.object(service, "ServiceControl") as control, \
                mock.patch.object(connection, "_open_pipe", return_value=SERVER_HANDLE) as opened:
            control.return_value.status.return_value = {"state": 4, "pid": 987}
            with self.assertRaises(OSError):
                connection.request("apply", paths=[r"C:\Apps\Example.exe"], proxy_port=10809,
                                   mihomo_pid=456, generation=1)
        factory.assert_called_once()
        opened.assert_called_once()
        self.assertEqual(len(writes), 1)
        self.assertEqual(writes[0]["op"], "apply")
        self.assertEqual(api.closed, [SERVER_HANDLE])


if __name__ == "__main__":
    unittest.main()
