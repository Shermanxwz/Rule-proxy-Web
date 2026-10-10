"""Live, local-only containment checks. No external packets or user apps."""
import json
import os
from pathlib import Path
import socket
import sys
import tempfile
import threading
import unittest

from ruleproxy.linux_runtime import launch, probe


@unittest.skipUnless(sys.platform == "linux", "Linux network namespaces required")
class LinuxContainmentTests(unittest.TestCase):
    def test_proxy_bridge_and_direct_ipv4_ipv6_dns_udp_children_are_isolated(self):
        if not probe()["supported"]:
            self.skipTest("user/network namespaces unavailable")
        before_interfaces = socket.if_nameindex()
        before_routes = Path("/proc/net/route").read_bytes()
        host = socket.socket()
        host.bind(("127.0.0.1", 0))
        host.listen(4)
        proxy_port = host.getsockname()[1]
        unrelated = socket.socket()
        unrelated.bind(("127.0.0.1", 0))
        unrelated.listen(4)
        other_port = unrelated.getsockname()[1]

        def echo():
            peer, _ = host.accept()
            with peer:
                peer.sendall(peer.recv(128))
        thread = threading.Thread(target=echo, daemon=True)
        thread.start()
        with tempfile.TemporaryDirectory(prefix="ruleproxy-test-") as temp:
            profile = Path(temp) / "app"
            profile.mkdir()
            code = r'''
import socket, json, subprocess, sys
from pathlib import Path
report = {}
report["only_loopback"] = {name for _,name in socket.if_nameindex()} == {"lo"}
s = socket.create_connection(("127.0.0.1", PROXY), timeout=2)
s.sendall(b"proxy-only"); report["proxy"] = s.recv(128) == b"proxy-only"; s.close()
for key, family, address, kind in (
    ("other_host_loopback", socket.AF_INET, ("127.0.0.1", OTHER), socket.SOCK_STREAM),
    ("ipv4_tcp", socket.AF_INET, ("192.0.2.1", 443), socket.SOCK_STREAM),
    ("ipv6_tcp", socket.AF_INET6, ("2001:db8::1", 443), socket.SOCK_STREAM),
    ("dns_udp", socket.AF_INET, ("192.0.2.1", 53), socket.SOCK_DGRAM),
    ("ipv6_udp", socket.AF_INET6, ("2001:db8::1", 53), socket.SOCK_DGRAM),
):
    try:
        s = socket.socket(family, kind)
    except OSError:
        report[key] = True  # family unusable here: nothing can leave on it
        continue
    s.settimeout(1)
    try:
        if kind == socket.SOCK_DGRAM: s.sendto(b"local-isolation-test", address)
        else: s.connect(address)
        report[key] = False
    except OSError: report[key] = True
    finally: s.close()
try:
    socket.getaddrinfo("example.com", 443)
    report["name_resolution_blocked"] = False
except OSError: report["name_resolution_blocked"] = True
child = subprocess.check_output([sys.executable, "-c", "import socket; print([n for _,n in socket.if_nameindex()])"], text=True)
report["child_isolated"] = child.strip() == "['lo']"
report["no_host_broker"] = not Path('/run/dbus/system_bus_socket').exists()
Path('report.json').write_text(json.dumps(report))
'''.replace("PROXY", str(proxy_port)).replace("OTHER", str(other_port))
            env = {k: v for k, v in os.environ.items() if k not in {"DISPLAY", "WAYLAND_DISPLAY"}}
            process, resource = launch([sys.executable, "-c", code], env, profile, proxy_port)
            try:
                self.assertEqual(process.wait(timeout=10), 0)
                report = json.loads((profile / "report.json").read_text())
                self.assertTrue(all(report.values()), report)
            finally:
                if process.poll() is None:
                    process.kill()
                resource.close()
        # A process outside the selected app can still use host networking.
        with socket.create_connection(("127.0.0.1", other_port), timeout=1):
            pass
        host.close()
        unrelated.close()
        self.assertEqual(socket.if_nameindex(), before_interfaces)
        self.assertEqual(Path("/proc/net/route").read_bytes(), before_routes)


if __name__ == "__main__":
    unittest.main()
