import os
import stat
import tempfile
import unittest
from pathlib import Path
from unittest import mock

from ruleproxy import launcher


class LauncherTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        self.executable = self.root / "browser"
        self.executable.write_text("", encoding="utf-8")
        self.executable.chmod(self.executable.stat().st_mode | stat.S_IXUSR)

    def app_for(self, adapter="chromium", **extra):
        return {
            "id": "saved-app-1",
            "label": "Browser",
            "path": str(self.executable),
            "adapter": adapter,
            **extra,
        }

    def test_validate_normalizes_and_preserves_argument_list(self):
        result = launcher.validate_app(
            self.app_for(args=["--new-window", "https://example.test"])
        )
        self.assertEqual(
            result,
            {
                "label": "Browser",
                "path": str(self.executable.resolve()),
                "adapter": "chromium",
                "args": ["--new-window", "https://example.test"],
            },
        )

    def test_validate_rejects_invalid_selection(self):
        invalid_selections = [
            self.app_for(path="/definitely/missing/executable"),
            self.app_for(adapter="unknown"),
            self.app_for(args="--flag"),
            self.app_for(args=["bad\0arg"]),
            self.app_for(args=["x" * 4097]),
            self.app_for(args=["x"] * 65),
        ]
        for selection in invalid_selections:
            with self.subTest(selection=selection):
                with self.assertRaises(ValueError):
                    launcher.validate_app(selection)

    def test_prepare_chromium_uses_profile_proxy_and_webrtc_restrictions(self):
        command, env, detail = launcher.prepare_app(
            self.app_for(args=["https://example.test"]), 8899, self.root / "profiles"
        )
        self.assertEqual(command[0], str(self.executable.resolve()))
        self.assertEqual(command[1], "https://example.test")
        self.assertIn(f"--user-data-dir={self.root / 'profiles' / 'saved-app-1'}", command)
        self.assertIn("--proxy-server=http://127.0.0.1:8899", command)
        self.assertIn("--proxy-bypass-list=<-loopback>", command)
        self.assertIn("--disable-quic", command)
        self.assertIn("--disable-background-networking", command)
        self.assertIn(
            "--host-resolver-rules=MAP * ~NOTFOUND, EXCLUDE 127.0.0.1", command
        )
        self.assertIn(
            "--force-webrtc-ip-handling-policy=disable_non_proxied_udp", command
        )
        self.assertEqual(env["HTTP_PROXY"], "http://127.0.0.1:8899")
        self.assertEqual(env["DISPLAY"], os.environ.get("DISPLAY"))
        self.assertIn("blocks direct egress", detail)
        self.assertFalse(hasattr(launcher, "launch_app"))

    def test_prepare_rejects_user_proxy_profile_or_subprocess_switches(self):
        for args in (
            ["--proxy-server=direct://"],
            ["--user-data-dir=C:\\other"],
            ["--renderer-cmd-prefix=cmd.exe"],
            ["--"],
        ):
            with self.subTest(args=args), self.assertRaises(ValueError):
                launcher.prepare_app(self.app_for(args=args), 8899, self.root / "profiles")
        with self.assertRaises(ValueError):
            launcher.prepare_app(
                self.app_for("firefox", args=["-profile", "C:\\other"]),
                8899,
                self.root / "profiles",
            )

    def test_prepare_firefox_uses_socks_remote_dns_and_disables_prefetch(self):
        command, env, _ = launcher.prepare_app(
            self.app_for("firefox"), 7777, self.root / "profiles"
        )
        profile = self.root / "profiles" / "saved-app-1"
        prefs = (profile / "user.js").read_text(encoding="utf-8")
        self.assertIn('user_pref("network.proxy.socks_version", 5);', prefs)
        self.assertIn('user_pref("network.proxy.socks_remote_dns", true);', prefs)
        self.assertIn('user_pref("network.proxy.socks5_remote_dns", true);', prefs)
        self.assertIn('user_pref("network.proxy.allow_hijacking_localhost", true);', prefs)
        self.assertIn('user_pref("network.dns.disablePrefetch", true);', prefs)
        self.assertIn('user_pref("network.prefetch-next", false);', prefs)
        self.assertIn("-no-remote", command)
        self.assertEqual(command[-2:], ["-profile", str(profile)])
        self.assertEqual(env["HTTP_PROXY"], "http://127.0.0.1:7777")

    def test_prepare_environment_adapter_sets_child_only_proxy_variables(self):
        before = os.environ.get("HTTP_PROXY")
        command, env, detail = launcher.prepare_app(
            self.app_for("environment"), 8888, self.root / "profiles"
        )
        self.assertEqual(command, [str(self.executable.resolve())])
        self.assertEqual(env["HTTP_PROXY"], "http://127.0.0.1:8888")
        self.assertEqual(env["HTTPS_PROXY"], env["HTTP_PROXY"])
        self.assertEqual(env["ALL_PROXY"], env["HTTP_PROXY"])
        self.assertEqual(env["http_proxy"], env["HTTP_PROXY"])
        self.assertEqual(env["NO_PROXY"], "")
        self.assertEqual(os.environ.get("HTTP_PROXY"), before)
        self.assertIn("fail to connect", detail)

    def test_environment_adapter_rejects_shell_executables(self):
        shell = self.root / "powershell.exe"
        shell.write_text("", encoding="utf-8")
        shell.chmod(shell.stat().st_mode | stat.S_IXUSR)
        selection = self.app_for("environment", path=str(shell))
        with self.assertRaisesRegex(ValueError, "shell executables"):
            launcher.prepare_app(selection, 8888, self.root / "profiles")

    def test_prepare_rejects_unsafe_profile_identifier_and_port(self):
        with self.assertRaisesRegex(ValueError, "safe id"):
            launcher.prepare_app(self.app_for(id="../other"), 8000, self.root)
        with self.assertRaisesRegex(ValueError, "proxy_port"):
            launcher.prepare_app(self.app_for(), 0, self.root)

    def test_discover_apps_uses_path_lookup_without_executing(self):
        firefox = self.root / "firefox"
        firefox.write_text("", encoding="utf-8")
        with mock.patch.object(launcher.sys, "platform", "linux"), mock.patch.object(
            launcher.shutil, "which", side_effect=lambda name: str(firefox) if name == "firefox" else None
        ):
            found = launcher.discover_apps()
        entry = next(app for app in found if app["path"] == str(firefox.resolve()))
        self.assertEqual(entry["label"], "Mozilla Firefox")
        self.assertEqual(entry["adapter"], "firefox")
        self.assertEqual(entry["args"], [])
        self.assertEqual(entry["category"], "browser")
        self.assertIn("fails closed", entry["compatibility"])


if __name__ == "__main__":
    unittest.main()
