"""Live, local-only containment checks. No external packets or user apps."""
import json
import os
from pathlib import Path
import socket
import sys
import tempfile
import threading
import time
import unittest
from unittest.mock import patch

from ruleproxy.linux_runtime import build_command, downloads_folder, launch, probe, stop


def require_isolation(test):
    """Skip without namespace isolation, unless the run demands it (CI sets RULEPROXY_REQUIRE_ISOLATION=1)."""
    if probe()["supported"]:
        return
    if os.environ.get("RULEPROXY_REQUIRE_ISOLATION") == "1":
        test.fail("namespace isolation is required for this run but unavailable: " + probe()["detail"])
    test.skipTest("namespace isolation unavailable")


@unittest.skipUnless(sys.platform == "linux", "Linux network namespaces required")
class LinuxContainmentTests(unittest.TestCase):
    def test_proxy_bridge_and_direct_ipv4_ipv6_dns_udp_children_are_isolated(self):
        require_isolation(self)
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

    def test_stop_sends_sigint_so_the_app_can_flush_its_profile(self):
        require_isolation(self)
        host = socket.socket()
        host.bind(("127.0.0.1", 0))
        host.listen(4)
        proxy_port = host.getsockname()[1]
        code = r'''
import signal, sys, time
from pathlib import Path
def flush(signum, frame):
    Path("flushed.txt").write_text(signal.Signals(signum).name)
    sys.exit(0)
signal.signal(signal.SIGINT, flush)
print("ready", flush=True)
while True:
    time.sleep(0.1)
'''
        with tempfile.TemporaryDirectory(prefix="ruleproxy-test-") as temp:
            profile = Path(temp) / "app"
            profile.mkdir()
            env = {k: v for k, v in os.environ.items() if k not in {"DISPLAY", "WAYLAND_DISPLAY"}}
            process, resource = launch([sys.executable, "-c", code], env, profile, proxy_port)
            try:
                log = profile / "runtime.log"
                deadline = time.monotonic() + 10
                while time.monotonic() < deadline and "ready" not in (log.read_text() if log.exists() else ""):
                    time.sleep(0.05)
                stop(process)
                self.assertEqual(process.returncode, 0)
                self.assertEqual((profile / "flushed.txt").read_text(), "SIGINT")
            finally:
                if process.poll() is None:
                    process.kill()
                resource.close()
                host.close()

    def test_the_app_sees_its_downloads_folder_and_no_other_home_files(self):
        require_isolation(self)
        code = r'''
import json, os
from pathlib import Path
downloads = Path(DOWNLOADS)
(downloads / "saved-in-sandbox.txt").write_text("ok")
report = {
    "downloads_readable": (downloads / "from-host.txt").read_text() == "host",
    "home_file_hidden": not Path(SECRET).exists(),
    "download_dir_configured": DOWNLOADS in (Path(os.environ["XDG_CONFIG_HOME"]) / "user-dirs.dirs").read_text(),
}
Path("report.json").write_text(json.dumps(report))
'''
        with tempfile.TemporaryDirectory(prefix="ruleproxy-test-") as temp:
            home = Path(temp) / "home"
            downloads = home / "Downloads"
            downloads.mkdir(parents=True)
            (downloads / "from-host.txt").write_text("host")
            secret = home / "Documents" / "private.txt"
            secret.parent.mkdir()
            secret.write_text("not for the app")
            profile = home / ".local/share/ruleproxy-web-safe/profiles/app"
            profile.mkdir(parents=True)
            env = {k: v for k, v in os.environ.items() if k not in {"DISPLAY", "WAYLAND_DISPLAY"}}
            code = code.replace("DOWNLOADS", repr(str(downloads))).replace("SECRET", repr(str(secret)))
            # The app never uses the proxy here; any unprivileged port works inside its namespace.
            process, resource = launch([sys.executable, "-c", code], env, profile, 18099, (downloads.resolve(), downloads))
            try:
                self.assertEqual(process.wait(timeout=10), 0, (profile / "runtime.log").read_text() if (profile / "runtime.log").exists() else "")
                report = json.loads((profile / "report.json").read_text())
                self.assertTrue(all(report.values()), report)
                self.assertEqual((downloads / "saved-in-sandbox.txt").read_text(), "ok")
            finally:
                if process.poll() is None:
                    process.kill()
                resource.close()


@unittest.skipUnless(sys.platform == "linux", "XDG folders are Linux-only here")
class DownloadsFolderTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.home = Path(self.temp.name) / "home"
        self.state = self.home / ".local/share/ruleproxy-web-safe"
        self.state.mkdir(parents=True)
        environment = patch.dict(os.environ, {"HOME": str(self.home), "XDG_CONFIG_HOME": str(self.home / ".config")})
        environment.start()
        self.addCleanup(environment.stop)

    def configure(self, value):
        config = self.home / ".config" / "user-dirs.dirs"
        config.parent.mkdir(parents=True, exist_ok=True)
        config.write_text(f'# comment\nXDG_DESKTOP_DIR="$HOME/Desktop"\nXDG_DOWNLOAD_DIR="{value}"\n', encoding="utf-8")

    def test_defaults_to_home_downloads_and_creates_it(self):
        self.assertEqual(downloads_folder(self.state), ((self.home / "Downloads").resolve(), self.home / "Downloads"))
        self.assertTrue((self.home / "Downloads").is_dir())

    def test_follows_the_configured_folder(self):
        (self.home / "Incoming").mkdir()
        self.configure("$HOME/Incoming")
        self.assertEqual(downloads_folder(self.state)[1], self.home / "Incoming")
        outside = Path(self.temp.name) / "data" / "dl"
        outside.mkdir(parents=True)
        self.configure(str(outside))
        self.assertEqual(downloads_folder(self.state), (outside.resolve(), outside))

    def test_a_configured_folder_that_is_missing_is_not_created(self):
        self.configure("$HOME/Nowhere")
        self.assertIsNone(downloads_folder(self.state))
        self.assertFalse((self.home / "Nowhere").exists())

    def test_never_shares_home_its_parents_or_panel_data(self):
        for value in ("$HOME", str(Path(self.temp.name)), "$HOME/.local", "$HOME/.local/share/ruleproxy-web-safe"):
            with self.subTest(value=value):
                self.configure(value)
                self.assertIsNone(downloads_folder(self.state))
        inside = self.state / "profiles"
        inside.mkdir()
        self.configure(str(inside))
        self.assertIsNone(downloads_folder(self.state))

    def test_a_symlinked_folder_is_shared_at_the_path_apps_know(self):
        real = Path(self.temp.name) / "disk" / "downloads"
        real.mkdir(parents=True)
        self.home.mkdir(exist_ok=True)
        (self.home / "Downloads").symlink_to(real)
        self.assertEqual(downloads_folder(self.state), (real.resolve(), self.home / "Downloads"))

    @unittest.skipUnless(hasattr(os, "geteuid") and os.geteuid() == 0, "needs root to hand the folder to another user")
    def test_a_folder_owned_by_someone_else_is_not_shared(self):
        (self.home / "Downloads").mkdir(parents=True)
        try:
            os.chown(self.home / "Downloads", 65534, 65534)
        except OSError as exc:
            # Container root may have no mapping for this UID/GID. The real
            # ownership fixture cannot be created on that host.
            if exc.errno not in (1, 22):
                raise
            self.skipTest(f"host cannot assign the foreign UID/GID: {exc}")
        self.assertIsNone(downloads_folder(self.state))

    def test_the_sandbox_binds_it_and_apps_save_there(self):
        profile = self.state / "profiles" / "app"
        profile.mkdir(parents=True)
        folder = downloads_folder(self.state)
        with patch("ruleproxy.linux_runtime.bwrap_executable", return_value="/usr/bin/bwrap"):
            args, _ = build_command([sys.executable], {}, profile, "/tmp/bridge.sock", folder)
        bind = args.index(str(folder[0]))
        self.assertEqual(args[bind - 1:bind + 2], ["--bind", str(folder[0]), str(folder[1])])
        config = (profile / ".config" / "user-dirs.dirs").read_text(encoding="utf-8")
        self.assertIn(f'XDG_DOWNLOAD_DIR="{folder[1]}"', config)
        # Without a folder the file written here is removed, so apps fall back to the profile.
        with patch("ruleproxy.linux_runtime.bwrap_executable", return_value="/usr/bin/bwrap"):
            args, _ = build_command([sys.executable], {}, profile, "/tmp/bridge.sock", None)
        self.assertNotIn(str(folder[0]), args)
        self.assertFalse((profile / ".config" / "user-dirs.dirs").exists())

    def test_a_user_dirs_file_the_app_wrote_is_left_alone(self):
        profile = self.state / "profiles" / "app"
        (profile / ".config").mkdir(parents=True)
        (profile / ".config" / "user-dirs.dirs").write_text('XDG_DOWNLOAD_DIR="$HOME/Mine"\n', encoding="utf-8")
        with patch("ruleproxy.linux_runtime.bwrap_executable", return_value="/usr/bin/bwrap"):
            build_command([sys.executable], {}, profile, "/tmp/bridge.sock", None)
        self.assertIn("Mine", (profile / ".config" / "user-dirs.dirs").read_text(encoding="utf-8"))


if __name__ == "__main__":
    unittest.main()
