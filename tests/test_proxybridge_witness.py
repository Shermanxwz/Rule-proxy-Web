"""Exercise the SOCKS wire exchange used by the Windows kernel experiment."""

import json
import socket
import tempfile
import threading
import unittest
from pathlib import Path

from scripts.windows.proxybridge_witness import _handle


class WitnessTests(unittest.TestCase):
    def test_connect_records_destination_and_replies_without_dialling(self):
        with tempfile.TemporaryDirectory() as folder:
            log = Path(folder) / "requests.jsonl"
            client, server = socket.socketpair()
            worker = threading.Thread(target=_handle, args=(server, log), daemon=True)
            worker.start()
            try:
                client.settimeout(3)
                client.sendall(b"\x05\x01\x00")
                self.assertEqual(client.recv(2), b"\x05\x00")
                client.sendall(b"\x05\x01\x00\x01\x01\x01\x01\x01\x00\x50")
                self.assertEqual(client.recv(10), b"\x05\x00\x00\x01\x7f\x00\x00\x01\x00\x00")
                client.sendall(b"GET / HTTP/1.1\r\n\r\n")
                self.assertIn(b"200 OK", client.recv(128))
                worker.join(3)
                self.assertFalse(worker.is_alive())
                self.assertEqual(json.loads(log.read_text()), {"address": "1.1.1.1", "port": 80})
            finally:
                client.close()


if __name__ == "__main__":
    unittest.main()
