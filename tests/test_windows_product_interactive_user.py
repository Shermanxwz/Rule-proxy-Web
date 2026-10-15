"""Real-session launcher rejects wrong tokens before resuming user code."""
import importlib.util
from pathlib import Path
import subprocess
import unittest
from unittest import mock


ROOT = Path(__file__).resolve().parents[1]
SPEC = importlib.util.spec_from_file_location(
    "windows_product_interactive_user_test", ROOT / ".github/windows_product_interactive_user.py")
launcher = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(launcher)
SID = "S-1-5-21-1-2-3-1000"


class FakeAPI:
    def __init__(self):
        self.events = []
        self.owner = {"sid": SID, "session_id": 3, "elevated": False}
        self.child = dict(self.owner)
        self.caller_identity = {"sid": "S-1-5-18"}
        self.active = [{"active": True, "session_id": 3, "username": "RuleProxyCI"}]
        self.completed = False
        self.environment_error = False
        self.process = 0x100000123

    def caller(self):
        return self.caller_identity

    def sessions(self):
        return self.active

    def user_token(self, session):
        self.events.append(("token", session))
        return 101

    def identity(self, token):
        self.events.append(("identity", token))
        return self.owner if token == 101 else self.child

    def process_token(self, process):
        self.events.append(("process_token", process))
        return 102

    def environment(self, token):
        self.events.append(("environment", token))
        return 201

    def free_environment(self, environment):
        self.events.append(("free_environment", environment))
        if self.environment_error:
            raise OSError("environment cleanup failed")

    def create(self, token, command, cwd, environment):
        self.events.append(("create", token, command, cwd, environment))
        return self.process, 301, 456

    def resume(self, thread):
        self.events.append(("resume", thread))

    def close(self, handle):
        self.events.append(("close", handle))

    def terminate(self, handle):
        self.events.append(("terminate", handle))
        self.completed = True

    def wait(self, handle, milliseconds):
        self.events.append(("wait", handle, milliseconds))
        return 0 if self.completed else 258

    def exit_code(self, handle):
        self.events.append(("exit_code", handle))
        return 125


class InteractiveLaunchTests(unittest.TestCase):
    def launch(self, api):
        with mock.patch.object(launcher, "_get_api", return_value=api):
            return launcher.launch_user([r"C:\Product\python.exe", "actor.py"], SID, 3, r"C:\Product")

    def test_verifies_both_tokens_before_resume_and_retains_exact_handle(self):
        api = FakeAPI()
        process = self.launch(api)
        events = api.events
        self.assertLess(events.index(("identity", 102)), events.index(("resume", 301)))
        self.assertLess(events.index(("free_environment", 201)), events.index(("resume", 301)))
        self.assertEqual((process.pid, process.handle, process.session_id), (456, 0x100000123, 3))
        self.assertEqual(process.caller_sid, "S-1-5-18")
        self.assertEqual(process.launch_method, "WTSQueryUserToken+CreateProcessAsUserW")
        self.assertNotIn(("close", api.process), events)
        self.assertIsNone(process.poll())
        with self.assertRaises(subprocess.TimeoutExpired):
            process.wait(0.25)
        self.assertIn(("wait", api.process, 250), events)
        process.terminate()
        self.assertEqual(process.wait(0), 125)
        process.close()
        process.close()
        self.assertEqual(events.count(("close", api.process)), 1)

    def test_changed_child_sid_session_or_elevation_is_killed_before_resume(self):
        for changed in ({"sid": SID + "1"}, {"session_id": 4}, {"elevated": True}):
            with self.subTest(changed=changed):
                api = FakeAPI()
                api.child.update(changed)
                with self.assertRaises(PermissionError):
                    self.launch(api)
                self.assertNotIn(("resume", 301), api.events)
                self.assertIn(("terminate", api.process), api.events)
                for handle in (101, 102, 301, api.process):
                    self.assertEqual(api.events.count(("close", handle)), 1)
                self.assertIn(("free_environment", 201), api.events)

    def test_cleanup_failure_keeps_child_suspended_and_closes_all_handles(self):
        api = FakeAPI()
        api.environment_error = True
        with self.assertRaises(OSError):
            self.launch(api)
        self.assertNotIn(("resume", 301), api.events)
        self.assertIn(("terminate", api.process), api.events)
        for handle in (101, 102, 301, api.process):
            self.assertEqual(api.events.count(("close", handle)), 1)

    def test_system_caller_and_exact_active_fixture_are_required(self):
        for change in ("caller", "inactive", "other_user", "other_session", "elevated_owner"):
            with self.subTest(change=change):
                api = FakeAPI()
                if change == "caller":
                    api.caller_identity["sid"] = SID
                elif change == "inactive":
                    api.active[0]["active"] = False
                elif change == "other_user":
                    api.active[0]["username"] = "defaultuser0"
                elif change == "other_session":
                    api.active[0]["session_id"] = 4
                else:
                    api.owner["elevated"] = True
                with self.assertRaises(PermissionError):
                    self.launch(api)
                self.assertFalse(any(event[0] == "create" for event in api.events))
                if change == "elevated_owner":
                    self.assertIn(("close", 101), api.events)

    def test_bootstrap_gates_before_claim_and_keeps_session_after_cleanup(self):
        script = (ROOT / ".github/windows-proxifyre-vm-run.ps1").read_text(encoding="utf-8")
        setup = (ROOT / ".github/windows-proxifyre-vm-setup.ps1").read_text(encoding="utf-8")
        self.assertIn("-MultipleInstances Queue", setup)
        self.assertNotIn("-MultipleInstances IgnoreNew", setup)
        self.assertLess(script.index("GetOwnerSid"), script.index("FileMode]::CreateNew"))
        self.assertLess(script.index("if ($null -eq $actorSession) { exit 0 }"),
                        script.index("FileMode]::CreateNew"))
        self.assertIn("$result.actor_session_id = [int]$actorSession", script)
        self.assertIn("$env:RULEPROXY_TEST_INTERACTIVE_SESSION = [string]$actorSession", script)
        self.assertNotIn("New-LocalUser", script)
        self.assertIn("Fixture account SID changed; cleanup refused", script)
        self.assertLess(script.index("AutoAdminLogon -Value '0'"), script.index("::WTSLogoffSession([IntPtr]::Zero"))
        self.assertLess(script.index("::WTSLogoffSession([IntPtr]::Zero"), script.index("Remove-LocalUser"))

    def test_win32_creation_uses_existing_desktop_user_environment_no_inherited_handles(self):
        api = object.__new__(launcher.WindowsAPI)
        api.advapi = mock.Mock()

        def create(token, app, command, process_attributes, thread_attributes, inherit, flags,
                   environment, cwd, startup, info):
            self.assertEqual(startup._obj.desktop, r"winsta0\default")
            self.assertFalse(inherit)
            self.assertEqual(flags, 0x08000000 | 0x400 | 4)
            self.assertEqual(environment, 201)
            info._obj.process, info._obj.thread, info._obj.pid = 0x100000123, 301, 456
            return True

        api.advapi.CreateProcessAsUserW.side_effect = create
        self.assertEqual(api.create(101, [r"C:\Product\python.exe", "actor.py"], None, 201),
                         (0x100000123, 301, 456))
        api.userenv = mock.Mock()

        def environment(pointer, token, inherit):
            self.assertFalse(inherit)
            pointer._obj.value = 201
            return True

        api.userenv.CreateEnvironmentBlock.side_effect = environment
        self.assertEqual(api.environment(101), 201)


if __name__ == "__main__":
    unittest.main()
