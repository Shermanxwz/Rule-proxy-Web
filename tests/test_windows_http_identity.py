"""An elevated local HTTP endpoint must authenticate the connecting account."""
import ctypes
import http.client
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
import os
import socket
import threading
import unittest
from unittest.mock import Mock, patch

from ruleproxy import windows_http_identity as identity


SID = 'S-1-5-21-10-20-30-1000'


class FakeAPI:
    def __init__(self):
        self.row = Mock(return_value=(42, 200))
        self.open = Mock(return_value=123)
        self.created = Mock(return_value=100)
        self.alive = Mock(return_value=True)
        self.sid = Mock(return_value=SID)
        self.close = Mock()

    def current_sid(self):
        return SID


def fake_connection():
    return Mock(family=socket.AF_INET, getpeername=Mock(return_value=('127.0.0.1', 40500)),
                getsockname=Mock(return_value=('127.0.0.1', 8879)))


class WindowsHTTPIdentityTests(unittest.TestCase):
    def test_owner_module_layout_and_port_order_match_windows_sdk(self):
        self.assertEqual(ctypes.sizeof(identity._TcpRow), 160)
        self.assertEqual(identity._TcpRow.created.offset, 24)
        self.assertEqual(identity._TcpTable.rows.offset, 8)
        row = identity._TcpRow(state=5, local_address=int.from_bytes(socket.inet_aton('127.0.0.1'), 'little'),
            remote_address=int.from_bytes(socket.inet_aton('127.0.0.1'), 'little'),
            local_port=socket.htons(40500), remote_port=socket.htons(8879), pid=42, created=200)
        data = (1).to_bytes(4, 'little') + bytes(4) + bytes(row)
        self.assertEqual(identity._matching_row(data, ('127.0.0.1', 40500), ('127.0.0.1', 8879)), (42, 200))
        for malformed in (data[:7], data[:-1], (2).to_bytes(4, 'little') + data[4:],
                          (2).to_bytes(4, 'little') + bytes(4) + bytes(row) + bytes(row)):
            with self.assertRaises(OSError):
                identity._matching_row(malformed, ('127.0.0.1', 40500), ('127.0.0.1', 8879))

    def test_account_match_requires_two_identical_rows_and_a_held_live_handle(self):
        api = FakeAPI()
        self.assertTrue(identity.WindowsHTTPIdentity(api=api).authorize(fake_connection()))
        self.assertEqual(api.row.call_count, 2)
        api.open.assert_called_once_with(42)
        api.sid.assert_called_once_with(123)
        self.assertEqual(api.alive.call_count, 2)
        api.close.assert_called_once_with(123)

    def test_wrong_account_token_error_and_closed_handle_fail_closed(self):
        for mode in ('wrong_sid', 'token_error', 'dead_process', 'close_error', 'pid_reused', 'changed_row'):
            api = FakeAPI()
            if mode == 'wrong_sid':
                api.sid.return_value = SID + '1'
            elif mode == 'token_error':
                api.sid.side_effect = OSError('token query failed')
            elif mode == 'dead_process':
                api.alive.return_value = False
            elif mode == 'close_error':
                api.close.side_effect = OSError('handle close failed')
            elif mode == 'pid_reused':
                api.created.return_value = 201  # process appeared after this connection
            elif mode == 'changed_row':
                api.row.side_effect = [(42, 200), (42, 201)]
            with self.subTest(mode=mode):
                self.assertFalse(identity.WindowsHTTPIdentity(api=api).authorize(fake_connection()))
                api.close.assert_called_once_with(123)

    def test_nonloopback_or_ambiguous_owner_never_opens_a_process(self):
        api = FakeAPI()
        connection = fake_connection()
        connection.getpeername.return_value = ('192.0.2.1', 40500)
        self.assertFalse(identity.WindowsHTTPIdentity(api=api).authorize(connection))
        api.open.assert_not_called()
        api.row.side_effect = OSError('ambiguous ownership')
        self.assertFalse(identity.WindowsHTTPIdentity(api=api).authorize(fake_connection()))
        api.open.assert_not_called()


@unittest.skipUnless(os.name == 'nt', 'Real Windows TCP ownership and process tokens')
class NativeWindowsHTTPIdentityTests(unittest.TestCase):
    def test_real_http_connection_accepts_own_sid_rejects_other_sid_and_token_errors(self):
        guard = identity.WindowsHTTPIdentity()
        class Handler(BaseHTTPRequestHandler):
            def do_GET(self):
                allowed = guard.authorize(self.connection)
                self.send_response(200 if allowed else 403)
                self.send_header('Content-Length', '0')
                self.end_headers()
            def log_message(self, *_args):
                pass
        server = ThreadingHTTPServer(('127.0.0.1', 0), Handler)
        serving = threading.Thread(target=server.serve_forever, kwargs={'poll_interval': 0.05}, daemon=True)
        serving.start()
        def status():
            client = http.client.HTTPConnection('127.0.0.1', server.server_port, timeout=3)
            try:
                client.request('GET', '/')
                response = client.getresponse()
                response.read()
                return response.status
            finally:
                client.close()
        try:
            self.assertEqual(status(), 200)
            with patch.object(guard, 'expected_sid', 'S-1-5-21-99-98-97-4294967294'):
                self.assertEqual(status(), 403)
            with patch.object(guard.api, 'sid', side_effect=OSError('injected token failure')):
                self.assertEqual(status(), 403)
            actual_row = guard.api.row
            def stale_row(client, destination):
                pid, _timestamp = actual_row(client, destination)
                handle = guard.api.open(pid)
                try:
                    return pid, guard.api.created(handle) - 1
                finally:
                    guard.api.close(handle)
            with patch.object(guard.api, 'row', side_effect=stale_row):
                self.assertEqual(status(), 403)
        finally:
            server.shutdown()
            server.server_close()
            serving.join(timeout=3)


if __name__ == '__main__':
    unittest.main()
