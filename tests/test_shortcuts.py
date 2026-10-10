"""Launcher files: Desktop Entry quoting, Windows .lnk arguments, and cleanup."""
import base64
import os
from pathlib import Path
import stat
import sys
import tempfile
import unittest
from unittest.mock import Mock, patch

from ruleproxy.shortcuts import ROOT, create_shortcut_files, remove_shortcut_files, runner_argv


def desktop_value(text: str, key: str) -> str:
    prefix = key + "="
    return next(line[len(prefix):] for line in text.splitlines() if line.startswith(prefix))


def desktop_argv(exec_value: str) -> list[str]:
    """Undo the file-level escaping, then split Exec the way a launcher does."""
    string_escapes = {"\\": "\\", "s": " ", "n": "\n", "t": "\t", "r": "\r"}
    text, index = [], 0
    while index < len(exec_value):
        char = exec_value[index]
        if char == "\\" and index + 1 < len(exec_value):
            text.append(string_escapes.get(exec_value[index + 1], "\\" + exec_value[index + 1]))
            index += 2
            continue
        text.append(char)
        index += 1
    exec_text = "".join(text)
    tokens, current, in_quotes, index = [], None, False, 0
    while index < len(exec_text):
        char = exec_text[index]
        if in_quotes:
            if char == "\\" and index + 1 < len(exec_text) and exec_text[index + 1] in '"`$\\':
                current += exec_text[index + 1]
                index += 2
                continue
            if char == '"':
                in_quotes = False
            else:
                current += char
            index += 1
            continue
        if char == '"':
            in_quotes = True
            current = current or ""
        elif char == " ":
            if current is not None:
                tokens.append(current)
            current = None
        else:
            current = (current or "") + char
        index += 1
    if current is not None:
        tokens.append(current)
    return [token.replace("%%", "%") for token in tokens]


@unittest.skipUnless(sys.platform.startswith("linux"), "Desktop Entry files are Linux-only")
class LinuxShortcutTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.root = Path(self.temp.name)
        self.data = self.root / "data"
        self.home = self.root / "home"
        self.home.mkdir()
        self.env = patch.dict(os.environ, {"XDG_DATA_HOME": str(self.data), "HOME": str(self.home)})
        self.env.start()
        self.addCleanup(self.env.stop)
        self.addCleanup(self.temp.cleanup)

    def test_desktop_entry_starts_the_headless_runner_with_the_panel_ports(self):
        app = {"id": "abc123", "label": "ChatGPT", "path": "/usr/lib/chatgpt/ChatGPT"}
        created = create_shortcut_files(app, state_dir=self.data / "ruleproxy-web-safe", ports=(8879, 10809, 19097))
        menu = self.data / "applications" / "ruleproxy-abc123.desktop"
        self.assertEqual(created, [menu])
        text = menu.read_text(encoding="utf-8")
        self.assertEqual(desktop_value(text, "Name"), "ChatGPT (RuleProxy)")
        self.assertEqual(desktop_value(text, "Terminal"), "false")
        self.assertEqual(desktop_value(text, "Path"), str(ROOT))
        self.assertEqual(desktop_argv(desktop_value(text, "Exec")), [
            sys.executable, str(ROOT / "Run-RuleProxy.py"), "--launch-app", "abc123",
            "--state-dir", str(self.data / "ruleproxy-web-safe"),
            "--port", "8879", "--proxy-port", "10809", "--controller-port", "19097",
        ])
        self.assertEqual(stat.S_IMODE(menu.stat().st_mode), 0o644)

    def test_exec_quoting_round_trips_awkward_paths(self):
        awkward = self.root / 'state dir "quoted" $HOME `tick` back\\slash 100%'
        app = {"id": "odd-1", "label": "Odd", "path": "/usr/bin/odd"}
        created = create_shortcut_files(app, state_dir=awkward, ports=(8879, 10809, 19097))
        text = created[0].read_text(encoding="utf-8")
        self.assertEqual(desktop_argv(desktop_value(text, "Exec")), runner_argv("odd-1", awkward, (8879, 10809, 19097)))

    def test_a_desktop_copy_is_added_when_the_desktop_folder_exists(self):
        (self.home / "Desktop").mkdir()
        app = {"id": "desk-1", "label": "Desk", "path": "/usr/bin/desk"}
        created = create_shortcut_files(app, state_dir=self.data / "state", ports=(8879, 10809, 19097))
        self.assertEqual(len(created), 2)
        copy = self.home / "Desktop" / "ruleproxy-desk-1.desktop"
        self.assertIn(copy, created)
        self.assertEqual(stat.S_IMODE(copy.stat().st_mode), 0o755)

    def test_invalid_app_ids_are_refused(self):
        for bad in ("../escape", "", "has space"):
            with self.subTest(app_id=bad), self.assertRaises(ValueError):
                create_shortcut_files({"id": bad, "label": "X"}, state_dir=self.data, ports=(8879, 10809, 19097))

    def installed_entry(self, name, exec_line, icon, filename=None):
        applications = self.data / "applications"
        applications.mkdir(parents=True, exist_ok=True)
        entry = applications / (filename or f"{name.lower().replace(' ', '-')}.desktop")
        entry.write_text(f"[Desktop Entry]\nType=Application\nName={name}\nExec={exec_line}\nIcon={icon}\n", encoding="utf-8")

    def shortcut_text(self, app):
        with patch.dict(os.environ, {"XDG_DATA_DIRS": str(self.root / "no-system-entries")}):
            created = create_shortcut_files(app, state_dir=self.data / "state", ports=(8879, 10809, 19097))
        return created[0].read_text(encoding="utf-8")

    def test_the_shortcut_uses_the_installed_apps_icon(self):
        # Packaged apps often start through a wrapper script, so the name decides.
        self.installed_entry("ChatGPT", "/opt/missing/chatgpt-wrapper %U", "chatgpt")
        text = self.shortcut_text({"id": "gpt-1", "label": "ChatGPT", "path": "/usr/lib/chatgpt/ChatGPT"})
        self.assertEqual(desktop_value(text, "Icon"), "chatgpt")

    def test_an_entry_running_the_same_program_wins_over_a_name_match(self):
        program = self.root / "bin" / "app"
        program.parent.mkdir()
        program.write_bytes(b"\x7fELF")
        program.chmod(0o755)
        icon = self.root / "app.png"
        icon.write_bytes(b"png")
        self.installed_entry("Same Label", "/opt/missing/other", "by-name")
        self.installed_entry("Vendor Name", f"{program} %U", str(icon))
        text = self.shortcut_text({"id": "app-1", "label": "Same Label", "path": str(program)})
        self.assertEqual(desktop_value(text, "Icon"), str(icon))

    def test_no_icon_without_a_matching_entry_and_never_from_our_own_launchers(self):
        self.installed_entry("Thing (RuleProxy)", "/usr/bin/python3", "ours", filename="ruleproxy-old.desktop")
        self.installed_entry("Thing", "/usr/bin/python3", "/missing/icon.png")
        text = self.shortcut_text({"id": "thing-1", "label": "Thing", "path": "/usr/bin/thing"})
        self.assertNotIn("Icon=", text)

    def test_removal_deletes_only_files_this_module_names(self):
        app = {"id": "keep-1", "label": "Keep", "path": "/usr/bin/keep"}
        ours = create_shortcut_files(app, state_dir=self.data / "state", ports=(8879, 10809, 19097))[0]
        foreign = self.root / "foreign.desktop"
        foreign.write_text("[Desktop Entry]\n", encoding="utf-8")
        remove_shortcut_files({"shortcuts": [str(ours), str(foreign)]})
        self.assertFalse(ours.exists())
        self.assertTrue(foreign.exists())


class WindowsShortcutTests(unittest.TestCase):
    def test_values_reach_powershell_through_the_environment(self):
        output = "C:\\Users\\me\\Desktop\\ChatGPT (RuleProxy).lnk\nC:\\Users\\me\\Start Menu\\RuleProxy Web\\ChatGPT (RuleProxy).lnk\n"
        with patch("ruleproxy.shortcuts.sys.platform", "win32"), patch("ruleproxy.shortcuts.subprocess.run", return_value=Mock(returncode=0, stdout=output, stderr="")) as run:
            created = create_shortcut_files(
                {"id": "w-1", "label": "ChatGPT", "path": "C:\\Program Files\\ChatGPT\\ChatGPT.exe"},
                state_dir=Path("C:/RuleProxy State"), ports=(8879, 10809, 19097),
            )
        command, kwargs = run.call_args.args[0], run.call_args.kwargs
        self.assertEqual(command[0], "powershell.exe")
        script = base64.b64decode(command[command.index("-EncodedCommand") + 1]).decode("utf-16-le")
        self.assertIn("WScript.Shell", script)
        env = kwargs["env"]
        self.assertEqual(env["RULEPROXY_SHORTCUT_NAME"], "ChatGPT (RuleProxy)")
        self.assertEqual(env["RULEPROXY_SHORTCUT_TARGET"], sys.executable)
        self.assertIn("--launch-app w-1", env["RULEPROXY_SHORTCUT_ARGUMENTS"])
        self.assertIn("--controller-port 19097", env["RULEPROXY_SHORTCUT_ARGUMENTS"])
        self.assertEqual(env["RULEPROXY_SHORTCUT_ICON"], "C:\\Program Files\\ChatGPT\\ChatGPT.exe,0")
        self.assertEqual(env["RULEPROXY_SHORTCUT_WORKDIR"], str(ROOT))
        self.assertEqual(len(created), 2)

    def test_powershell_failure_is_reported(self):
        with patch("ruleproxy.shortcuts.sys.platform", "win32"), patch("ruleproxy.shortcuts.subprocess.run", return_value=Mock(returncode=1, stdout="", stderr="denied")):
            with self.assertRaisesRegex(ValueError, "无法创建 Windows 快捷方式"):
                create_shortcut_files({"id": "w-2", "label": "X", "path": ""}, state_dir=Path("C:/s"), ports=(8879, 10809, 19097))


if __name__ == "__main__":
    unittest.main()
