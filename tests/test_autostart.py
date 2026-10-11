"""Starting the panel at login: a per-user entry that runs it without a window."""
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest
from unittest import mock
import uuid

from ruleproxy import autostart
from ruleproxy.shortcuts import ROOT, _desktop_exec

PORTS = (8879, 10809, 19097)


class CommandTests(unittest.TestCase):
    def test_the_panel_starts_quietly_on_its_own_ports_and_data(self):
        state_dir = Path(tempfile.gettempdir()) / "ruleproxy-state"
        argv = autostart.command(state_dir, PORTS)
        self.assertEqual(argv[1:], [
            str(ROOT / "Run-RuleProxy.py"), "--no-browser", "--state-dir", str(state_dir),
            "--port", "8879", "--proxy-port", "10809", "--controller-port", "19097",
        ])
        if sys.platform == "win32" and Path(sys.executable).with_name("pythonw.exe").is_file():
            self.assertEqual(Path(argv[0]).name.lower(), "pythonw.exe", "no console window at login")

    def test_other_systems_say_unsupported(self):
        with mock.patch.object(autostart, "supported", return_value=False):
            self.assertEqual(autostart.status(Path("state"), PORTS), "unsupported")
            with self.assertRaises(ValueError):
                autostart.enable(Path("state"), PORTS)


@unittest.skipUnless(sys.platform.startswith("linux"), "XDG autostart entries are Linux-only")
class LinuxAutostartTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        patcher = mock.patch.dict(os.environ, {"XDG_CONFIG_HOME": self.temp.name})
        patcher.start()
        self.addCleanup(patcher.stop)
        self.state_dir = Path(self.temp.name) / "state"
        self.entry = Path(self.temp.name) / "autostart" / autostart.DESKTOP_FILE

    def test_enable_writes_an_entry_that_runs_this_panel(self):
        self.assertEqual(autostart.status(self.state_dir, PORTS), "off")
        autostart.enable(self.state_dir, PORTS)
        lines = self.entry.read_text(encoding="utf-8").splitlines()
        self.assertIn("Exec=" + _desktop_exec(autostart.command(self.state_dir, PORTS)), lines)
        self.assertIn("Terminal=false", lines)
        self.assertEqual(autostart.status(self.state_dir, PORTS), "on")
        autostart.disable()
        self.assertFalse(self.entry.exists())
        self.assertEqual(autostart.status(self.state_dir, PORTS), "off")

    def test_an_entry_for_other_ports_or_another_copy_is_stale(self):
        autostart.enable(self.state_dir, PORTS)
        self.assertEqual(autostart.status(self.state_dir, (8880, 10809, 19097)), "stale")
        self.assertEqual(autostart.status(Path(self.temp.name) / "elsewhere", PORTS), "stale")

    def test_an_entry_the_desktop_switched_off_reads_as_off(self):
        autostart.enable(self.state_dir, PORTS)
        text = self.entry.read_text(encoding="utf-8").replace("X-GNOME-Autostart-enabled=true", "X-GNOME-Autostart-enabled=false")
        self.entry.write_text(text, encoding="utf-8")
        self.assertEqual(autostart.status(self.state_dir, PORTS), "off")
        autostart.enable(self.state_dir, PORTS)
        self.assertEqual(autostart.status(self.state_dir, PORTS), "on")

    def test_a_file_that_is_not_ours_is_left_alone(self):
        self.entry.parent.mkdir(parents=True)
        self.entry.write_text("[Desktop Entry]\nType=Application\nExec=other\n", encoding="utf-8")
        self.assertEqual(autostart.status(self.state_dir, PORTS), "off")
        autostart.disable()
        self.assertTrue(self.entry.exists())


@unittest.skipUnless(sys.platform == "win32", "the Run key is Windows-only")
class WindowsAutostartTests(unittest.TestCase):
    def setUp(self):
        import winreg

        self.winreg = winreg
        # A value name of its own, so the test never touches a real RuleProxy entry.
        patcher = mock.patch.object(autostart, "RUN_VALUE", f"RuleProxy Web test {uuid.uuid4().hex[:8]}")
        patcher.start()
        self.addCleanup(patcher.stop)
        self.addCleanup(autostart.disable)
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.state_dir = Path(self.temp.name) / "数据 目录"

    def run_value(self):
        try:
            with self.winreg.OpenKey(self.winreg.HKEY_CURRENT_USER, autostart.RUN_KEY) as key:
                return self.winreg.QueryValueEx(key, autostart.RUN_VALUE)[0]
        except FileNotFoundError:
            return None

    def switch_off_in_task_manager(self):
        with self.winreg.CreateKeyEx(self.winreg.HKEY_CURRENT_USER, autostart.APPROVED_KEY, 0, self.winreg.KEY_SET_VALUE) as key:
            self.winreg.SetValueEx(key, autostart.RUN_VALUE, 0, self.winreg.REG_BINARY, b"\x03" + bytes(11))

    def test_enable_writes_the_run_value_and_disable_removes_it(self):
        self.assertEqual(autostart.status(self.state_dir, PORTS), "off")
        autostart.enable(self.state_dir, PORTS)
        self.assertEqual(self.run_value(), subprocess.list2cmdline(autostart.command(self.state_dir, PORTS)))
        self.assertEqual(autostart.status(self.state_dir, PORTS), "on")
        self.assertEqual(autostart.status(self.state_dir, (8880, 10809, 19097)), "stale")
        autostart.disable()
        self.assertIsNone(self.run_value())
        self.assertEqual(autostart.status(self.state_dir, PORTS), "off")

    def test_task_manager_switching_it_off_reads_as_off_until_enabled_again(self):
        autostart.enable(self.state_dir, PORTS)
        self.switch_off_in_task_manager()
        self.assertEqual(autostart.status(self.state_dir, PORTS), "off")
        autostart.enable(self.state_dir, PORTS)
        self.assertEqual(autostart.status(self.state_dir, PORTS), "on")


if __name__ == "__main__":
    unittest.main()
