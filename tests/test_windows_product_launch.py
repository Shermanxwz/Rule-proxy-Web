"""The disposable controller uses one authenticated ordinary-user launch path."""
import importlib.util
from pathlib import Path
import unittest
from unittest import mock


SCRIPT = Path(__file__).resolve().parents[1] / ".github/windows_proxifyre_product_acceptance.py"
SPEC = importlib.util.spec_from_file_location("windows_product_launch_acceptance", SCRIPT)
acceptance = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(acceptance)


class OrdinaryLaunchTests(unittest.TestCase):
    def test_system_and_administrator_use_authenticated_token_profile_and_close_handles(self):
        owner = "S-1-5-21-1-2-3-1000"
        for caller_sid in ("S-1-5-18", "S-1-5-21-1-2-3-500"):
            with self.subTest(caller_sid=caller_sid):
                api, kernel = mock.Mock(), mock.Mock()
                closed, launches = [], []
                opened = iter((101, 102))
                process_handle, thread_handle = 0x100000789, 0x100000790
                kernel.GetCurrentProcess.return_value = 1
                kernel.CloseHandle.side_effect = lambda handle: closed.append(
                    handle.value if hasattr(handle, "value") else handle) or True

                def open_token(_process, _rights, result):
                    result._obj.value = next(opened)
                    return True

                def logon(_username, _domain, _password, kind, provider, result):
                    self.assertEqual((kind, provider), (2, 0))
                    result._obj.value = 201
                    return True

                def create(token, flags, _application, _command, creation, environment,
                           _directory, startup, information):
                    self.assertEqual(token.value, 201)
                    self.assertEqual(flags, 1)  # LOGON_WITH_PROFILE
                    self.assertIsNone(environment)
                    self.assertIsNone(startup._obj.desktop)
                    launches.append(creation)
                    information._obj.process = process_handle
                    information._obj.thread = thread_handle
                    information._obj.pid = 456
                    return True

                api.OpenProcessToken.side_effect = open_token
                api.LogonUserW.side_effect = logon
                api.CreateProcessWithTokenW.side_effect = create
                api.CreateProcessWithLogonW.side_effect = AssertionError("wrong desktop-permission API")
                with mock.patch.object(acceptance.ctypes, "WinDLL", create=True,
                                       side_effect=lambda name, **_kwargs: api if name == "advapi32" else kernel), \
                        mock.patch.object(acceptance, "token_user_sid", side_effect=(caller_sid, owner, owner)):
                    process = acceptance.launch_user([r"C:\RuleProxy\python.exe", "suite.py"],
                                                     "ordinary-test-user", "fixture-secret", owner)
                self.assertEqual(process.caller_sid, caller_sid)
                self.assertEqual(process.launch_method, "LogonUserW+CreateProcessWithTokenW")
                self.assertEqual(process.handle, process_handle)
                self.assertEqual(process.pid, 456)
                self.assertEqual(len(launches), 1)
                api.CreateProcessWithLogonW.assert_not_called()
                self.assertEqual(closed, [101, 201, 102, thread_handle])
                process.close()
                self.assertEqual(closed[-1], process_handle)


if __name__ == "__main__":
    unittest.main()
