"""The disposable controller uses one authenticated ordinary-user launch path."""
import importlib.util
import io
from pathlib import Path
import tempfile
import unittest
from unittest import mock


SCRIPT = Path(__file__).resolve().parents[1] / ".github/windows_proxifyre_product_acceptance.py"
SPEC = importlib.util.spec_from_file_location("windows_product_launch_acceptance", SCRIPT)
acceptance = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(acceptance)


class OrdinaryLaunchTests(unittest.TestCase):
    def test_exit_diagnostics_preserve_windows_crash_code_and_only_last_64k(self):
        process = mock.Mock()
        process.poll.return_value = 0xC0000142

        class BoundedStream(io.BytesIO):
            def read(self, size=-1):
                self_test.assertEqual(size, 65536)
                return super().read(size)

        self_test = self
        stream = BoundedStream(b"discarded prefix" + b"x" * 65535 + b"\xff")
        with mock.patch.object(Path, "open", return_value=stream):
            facts = acceptance.ordinary_exit_evidence(process, Path("stdio.log"))
        self.assertEqual(facts["exit_code"], 3221225794)
        self.assertEqual(facts["exit_code_hex"], "0xC0000142")
        self.assertEqual(facts["stdio_tail"], "x" * 65535 + "\ufffd")

    def test_zero_exit_without_stdio_is_diagnostic_evidence_not_a_pass(self):
        process = mock.Mock()
        process.poll.return_value = 0
        with tempfile.TemporaryDirectory() as temporary:
            facts = acceptance.ordinary_exit_evidence(process, Path(temporary) / "missing.log")
        self.assertEqual(facts["exit_code"], 0)
        self.assertEqual(facts["exit_code_hex"], "0x00000000")
        self.assertIsNone(facts["stdio_tail"])
        self.assertEqual(facts["stdio_read_error"]["type"], "FileNotFoundError")
        self.assertNotIn("status", facts)

    def test_ordinary_stdio_is_opened_before_optional_module_imports(self):
        prefix = SCRIPT.read_text(encoding="utf-8").split("import argparse", 1)[0]
        output = io.StringIO()
        with mock.patch.object(acceptance.sys, "argv", ["acceptance.py", "--ordinary-suite", "suite.json"]), \
                mock.patch.object(acceptance.sys, "stdout"), \
                mock.patch.object(acceptance.sys, "stderr"), \
                mock.patch("builtins.open", return_value=output) as opened:
            exec(compile(prefix, str(SCRIPT), "exec"), {"__name__": "__main__"})
            self.assertIs(acceptance.sys.stdout, output)
            self.assertIs(acceptance.sys.stderr, output)
            print("import diagnostics captured")
        opened.assert_called_once_with(r"C:\RuleProxyProduct\actors\ordinary-stdio.log", "a",
                                       encoding="utf-8", buffering=1)
        self.assertEqual(output.getvalue(), "ordinary bootstrap executable: " + acceptance.sys.executable
                         + "\nimport diagnostics captured\n")

    def test_system_token_and_server_logon_defaults_preserve_identity_and_handles(self):
        owner = "S-1-5-21-1-2-3-1000"
        for caller_sid, token_path in (("S-1-5-18", True), ("S-1-5-21-1-2-3-500", False)):
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

                def create_with_logon(_username, _domain, _password, flags, application,
                                      command, creation, environment, directory, startup, information):
                    # The same profile/desktop/environment and output-handle
                    # contract is retained for the old successful Server API.
                    return create(acceptance.wintypes.HANDLE(201), flags, application, command,
                                  creation, environment, directory, startup, information)

                api.OpenProcessToken.side_effect = open_token
                api.LogonUserW.side_effect = logon
                api.CreateProcessWithTokenW.side_effect = create
                api.CreateProcessWithLogonW.side_effect = create_with_logon
                identities = (caller_sid, owner, owner) if token_path else (caller_sid, owner)
                with mock.patch.object(acceptance.ctypes, "WinDLL", create=True,
                                       side_effect=lambda name, **_kwargs: api if name == "advapi32" else kernel), \
                        mock.patch.object(acceptance, "token_user_sid", side_effect=identities):
                    process = acceptance.launch_user([r"C:\RuleProxy\python.exe", "suite.py"],
                                                     "ordinary-test-user", "fixture-secret", owner)
                self.assertEqual(process.caller_sid, caller_sid)
                self.assertEqual(process.launch_method, "LogonUserW+CreateProcessWithTokenW" if token_path
                                 else "CreateProcessWithLogonW")
                self.assertEqual(process.handle, process_handle)
                self.assertEqual(process.pid, 456)
                self.assertEqual(len(launches), 1)
                if token_path:
                    api.CreateProcessWithLogonW.assert_not_called()
                else:
                    api.CreateProcessWithTokenW.assert_not_called()
                    api.LogonUserW.assert_not_called()
                self.assertEqual(closed, [101, 201, 102, thread_handle] if token_path
                                 else [101, 102, thread_handle])
                process.close()
                self.assertEqual(closed[-1], process_handle)


if __name__ == "__main__":
    unittest.main()
