"""Pure tests only: no Windows API, account, token, or process is created."""
import copy
import hashlib
import importlib.util
from pathlib import Path
import tempfile
from types import SimpleNamespace
import unittest
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[1]
SPEC = importlib.util.spec_from_file_location(
    "identity_ordinary_launcher", ROOT / ".github/windows_identity_ordinary_launcher.py")
launcher = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(launcher)


def ordinary(**changes):
    result = {
        "sid": "S-1-5-21-1-2-3-1001", "session_id": 1, "token_type": 1,
        "elevation_type": 1, "elevated": False, "integrity_rid": 8192,
        "admin_attributes": None, "appcontainer": False, "appcontainer_sid": None,
        "capability_count": 0, "ui_access": False,
    }
    result.update(changes)
    return result


def limited(**changes):
    return ordinary(**dict(elevation_type=3, admin_attributes=0x10, **changes))


def elevated():
    return ordinary(elevated=True, elevation_type=2, integrity_rid=12288, admin_attributes=0x7)


class TokenGateTests(unittest.TestCase):
    def test_standard_account_and_existing_limited_token_are_ordinary(self):
        self.assertTrue(launcher.token_is_ordinary(ordinary()))
        self.assertTrue(launcher.token_is_ordinary(limited(), require_limited=True))
        self.assertEqual(launcher.choose_mode(ordinary(), 1), "current_ordinary_token")

    def test_missing_any_native_observation_fails_closed(self):
        for key in ordinary():
            identity = ordinary()
            del identity[key]
            with self.subTest(key=key):
                self.assertFalse(launcher.token_is_ordinary(identity))

    def test_bad_observations_fail_closed(self):
        for key, value in (
            ("sid", None), ("session_id", True), ("token_type", True), ("token_type", 2),
            ("elevation_type", True), ("elevation_type", 2), ("elevated", 0), ("elevated", True),
            ("integrity_rid", 4096), ("integrity_rid", 8193), ("integrity_rid", 12288),
            ("admin_attributes", 0x4), ("admin_attributes", 0x14), ("admin_attributes", 0),
            ("appcontainer", True), ("appcontainer", 0), ("appcontainer_sid", "S-1-15-2-1"),
            ("capability_count", True), ("capability_count", 1), ("ui_access", True),
        ):
            with self.subTest(key=key, value=value):
                self.assertFalse(launcher.token_is_ordinary(ordinary(**{key: value})))

    def test_limited_path_requires_limited_type_and_deny_only_admin_group(self):
        for identity in (ordinary(), ordinary(elevation_type=3), ordinary(admin_attributes=0x10)):
            self.assertFalse(launcher.token_is_ordinary(identity, require_limited=True))

    def test_linked_token_must_match_user_and_session(self):
        launcher.validate_linked(limited(), elevated())
        for identity in (limited(sid="S-1-5-21-9-9-9-1001"), limited(session_id=2), ordinary()):
            with self.assertRaises(launcher.GateFailure):
                launcher.validate_linked(identity, elevated())

    def test_only_default_compartment_allowed(self):
        for compartment in (0, 2, True, None):
            with self.assertRaises(launcher.GateFailure):
                launcher.choose_mode(ordinary(), compartment)

    def test_elevated_host_can_only_attempt_existing_linked_token(self):
        self.assertEqual(launcher.choose_mode(elevated(), 1), "existing_linked_limited_token")
        # A non-split elevated host may report a native missing-linked-token
        # error, but can never be treated as a standard user.
        value = elevated()
        value["elevation_type"] = 1
        self.assertEqual(launcher.choose_mode(value, 1), "existing_linked_limited_token")
        with self.assertRaises(launcher.GateFailure):
            launcher.choose_mode(ordinary(integrity_rid=4096), 1)

    def test_safe_identity_excludes_sid_and_arbitrary_input(self):
        value = elevated()
        value["secret_environment"] = "not for publication"
        safe = launcher.safe_identity(value, value)
        self.assertNotIn("sid", safe)
        self.assertNotIn("secret_environment", safe)
        self.assertTrue(safe["same_user"])
        self.assertTrue(safe["same_session"])


class FakeAPI:
    def __init__(self, fail=None, child=None, timeout=False):
        self.events = []
        self.fail = fail
        self.child = child or limited()
        self.timeout = timeout
        self.next_handle = 20

    def event(self, name, *args):
        self.events.append((name, *args))
        if self.fail == name:
            raise launcher.NativeFailure(name, 1314)

    def process_info(self):
        return SimpleNamespace(hProcess=None, hThread=None, dwProcessId=0)

    def create_job(self):
        self.event("create_job")
        return 10

    def open_stdio_file(self, path, read=False):
        self.event("open_stdio_file", path.name, read)
        self.next_handle += 1
        return self.next_handle

    def create_suspended(self, info, command, work, stdio, token):
        self.event("create_suspended", token)
        info.hProcess, info.hThread, info.dwProcessId = 30, 31, 32

    def assign_job(self, *args):
        self.event("assign_job", *args)

    def verify_job(self, *args):
        self.event("verify_job", *args)

    def verify_image(self, *args):
        self.event("verify_image", *args)

    def child_identity(self, process):
        self.event("child_identity", process)
        return copy.deepcopy(self.child)

    def resume(self, thread):
        self.event("resume", thread)

    def wait(self, process, milliseconds):
        self.event("wait", process, milliseconds)
        return not self.timeout or milliseconds != launcher.RUN_MILLISECONDS

    def exit_code(self, process):
        self.event("exit_code", process)
        return 0

    def terminate_job(self, job):
        self.event("terminate_job", job)

    def terminate_process(self, process):
        self.event("terminate_process", process)

    def close(self, handle):
        self.event("close", handle)


class LifecycleTests(unittest.TestCase):
    def launch(self, api, token=99):
        return launcher.launch_owned(api, ["python.exe", "fixed_probe.py"], Path("owned"),
                                     limited() if token is not None else ordinary(), elevated(), token=token)

    def test_suspended_assignment_and_native_verification_precede_resume(self):
        api = FakeAPI()
        result = self.launch(api)
        self.assertNotIn("error", result)
        names = [event[0] for event in api.events]
        self.assertLess(names.index("create_suspended"), names.index("assign_job"))
        self.assertLess(names.index("assign_job"), names.index("child_identity"))
        self.assertLess(names.index("verify_job"), names.index("resume"))
        self.assertLess(names.index("verify_image"), names.index("resume"))
        self.assertLess(names.index("child_identity"), names.index("resume"))
        self.assertIn(("wait", 30, 120000), api.events)
        # Only the real Stage 0b report can subsequently clear this flag.
        self.assertTrue(result["nested_resource_cleanup_incomplete"])
        self.assertTrue(result["cleanup"]["job_closed"])
        self.assertTrue(result["cleanup"]["handles_closed"])

    def test_current_ordinary_mode_uses_no_alternate_token(self):
        api = FakeAPI(child=ordinary())
        result = self.launch(api, token=None)
        self.assertNotIn("error", result)
        self.assertIn(("create_suspended", None), api.events)

    def test_create_1314_is_terminal_without_resume_or_fallback(self):
        api = FakeAPI(fail="create_suspended")
        result = self.launch(api)
        self.assertEqual(result["error"], {"operation": "create_suspended", "winerror": 1314})
        self.assertFalse(result["started"])
        self.assertFalse(result["resumed"])
        self.assertEqual(sum(event[0] == "create_suspended" for event in api.events), 1)
        self.assertEqual([e for e in api.events if e[0] == "close"], [
            ("close", 10), ("close", 23), ("close", 22), ("close", 21)])

    def test_assign_failure_terminates_suspended_process_before_closing_handles(self):
        api = FakeAPI(fail="assign_job")
        result = self.launch(api)
        self.assertFalse(result["resumed"])
        events = api.events
        self.assertLess(events.index(("terminate_process", 30)), events.index(("wait", 30, 5000)))
        self.assertLess(events.index(("wait", 30, 5000)), events.index(("close", 30)))
        self.assertNotIn(("terminate_job", 10), events)

    def test_identity_mismatch_never_resumes_and_kills_owned_job(self):
        for identity in (elevated(), limited(session_id=2), limited(sid="S-1-5-21-9-9-9-1001")):
            with self.subTest(identity=identity):
                api = FakeAPI(child=identity)
                result = self.launch(api)
                self.assertEqual(result["error"]["reason"], "child_token_mismatch_before_resume")
                self.assertFalse(result["resumed"])
                self.assertIn(("terminate_job", 10), api.events)
                self.assertLess(api.events.index(("close", 10)), api.events.index(("close", 30)))

    def test_failed_job_verification_never_resumes(self):
        for operation in ("verify_job", "verify_image", "child_identity"):
            with self.subTest(operation=operation):
                api = FakeAPI(fail=operation)
                result = self.launch(api)
                self.assertFalse(result["resumed"])
                self.assertIn(("terminate_job", 10), api.events)

    def test_timeout_terminates_job_before_process_handles_close(self):
        api = FakeAPI(timeout=True)
        result = self.launch(api)
        self.assertTrue(result["timed_out"])
        self.assertTrue(result["nested_resource_cleanup_incomplete"])
        self.assertLess(api.events.index(("terminate_job", 10)), api.events.index(("close", 10)))
        self.assertLess(api.events.index(("close", 10)), api.events.index(("wait", 30, 5000)))
        self.assertLess(api.events.index(("wait", 30, 5000)), api.events.index(("close", 30)))

    def test_termination_error_still_closes_kill_on_close_job(self):
        api = FakeAPI(fail="terminate_job")
        result = self.launch(api)
        self.assertTrue(result["cleanup"]["errors"])
        self.assertTrue(result["cleanup"]["job_closed"])
        self.assertIn(("close", 10), api.events)
        self.assertIn(("wait", 30, 5000), api.events)

    def test_resume_failure_preserves_nested_cleanup_uncertainty(self):
        api = FakeAPI(fail="resume")
        result = self.launch(api)
        self.assertTrue(result["nested_resource_cleanup_incomplete"])
        self.assertIn(("terminate_job", 10), api.events)

    def test_partial_stdio_failure_closes_job_without_process_creation(self):
        api = FakeAPI(fail="open_stdio_file")
        result = self.launch(api)
        self.assertFalse(result["started"])
        self.assertFalse(result["nested_resource_cleanup_incomplete"])
        self.assertEqual([e for e in api.events if e[0] == "close"], [("close", 10)])


class InputTests(unittest.TestCase):
    def fixture(self, root):
        for directory in (".github", "ruleproxy", "runtime", "build"):
            (root / directory).mkdir()
        for relative in (
            ".github/windows_identity_pipe_probe.py", ".github/windows_identity_proof.py",
            ".github/windows_psec_compartment_smoke.py", "ruleproxy/windows_app_process.py",
            "runtime/python.exe",
        ):
            (root / relative).write_text("placeholder")
        actor = root / "build/windows_identity_actor.exe"
        actor.write_bytes(b"MZ" + b"\0" * 510)
        return SimpleNamespace(actor=actor, actor_sha256=hashlib.sha256(actor.read_bytes()).hexdigest(),
                               work=root / "new", report=root / "new/report.json")

    def test_input_paths_digest_and_fresh_directory_are_checked(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            args = self.fixture(root)
            with patch.object(launcher, "ROOT", root), \
                    patch.object(launcher, "PROBE", root / ".github/windows_identity_pipe_probe.py"), \
                    patch.object(launcher.sys, "base_prefix", str(root / "runtime")), \
                    patch.object(launcher.sys, "executable", str(root / "runtime/python.exe")):
                python, script, actor, work = launcher.validate_inputs(args)
                self.assertEqual(work, root.resolve() / "new")
                self.assertEqual(actor, args.actor.resolve())
                bad = copy.copy(args)
                bad.actor_sha256 = "0" * 64
                with self.assertRaisesRegex(launcher.GateFailure, "digest_mismatch"):
                    launcher.validate_inputs(bad)
                bad = copy.copy(args)
                bad.report = root / "report.json"
                with self.assertRaisesRegex(launcher.GateFailure, "report_must"):
                    launcher.validate_inputs(bad)
                args.work.mkdir()
                with self.assertRaisesRegex(launcher.GateFailure, "fresh_owned"):
                    launcher.validate_inputs(args)

    def test_fresh_work_uses_validated_canonical_parent_spelling(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary).resolve()
            args = self.fixture(root)
            # Simulate Windows expanding an existing 8.3 parent name. This
            # is not a symlink and must still go through checked_path.
            short_parent = root.parent / (root.name + "~1")
            args.work = short_parent / "new"
            args.report = args.work / "report.json"
            original_checked = launcher.checked_path
            parent_checks = []

            def checked(path, **kwargs):
                if Path(path) == short_parent:
                    parent_checks.append(kwargs)
                    return original_checked(root, **kwargs)
                return original_checked(path, **kwargs)

            with patch.object(launcher, "ROOT", root), \
                    patch.object(launcher, "PROBE", root / ".github/windows_identity_pipe_probe.py"), \
                    patch.object(launcher.sys, "base_prefix", str(root / "runtime")), \
                    patch.object(launcher.sys, "executable", str(root / "runtime/python.exe")), \
                    patch.object(launcher, "checked_path", side_effect=checked):
                self.assertEqual(launcher.validate_inputs(args)[3], root / "new")
                self.assertEqual(parent_checks, [{"inside": root, "is_file": False}])
                bad = copy.copy(args)
                bad.report = root / "new/report.json"
                with self.assertRaisesRegex(launcher.GateFailure, "report_must"):
                    launcher.validate_inputs(bad)
                (root / "new").mkdir()
                with self.assertRaisesRegex(launcher.GateFailure, "fresh_owned"):
                    launcher.validate_inputs(args)

    def test_command_is_fixed_probe_with_isolated_python(self):
        command = launcher.fixed_command(Path("python.exe"), launcher.PROBE, Path("actor.exe"),
                                         "a" * 64, Path("new"))
        self.assertEqual(command[:5], ["python.exe", "-I", "-S", "-B", str(launcher.PROBE)])
        self.assertNotIn("-c", command)
        self.assertEqual(command[-4:], ["--work", str(Path("new/probe")),
                                      "--report", str(Path("new/probe/report.json"))])

    def test_runtime_requires_permission_and_windows(self):
        with self.assertRaises(PermissionError):
            launcher.run(SimpleNamespace(disposable_ci=False, approved_security_test=False))

    def test_native_blocker_excludes_arbitrary_error_text(self):
        self.assertEqual(launcher.failure(launcher.NativeFailure("CreateProcessAsUserW", 1314)),
                         {"operation": "CreateProcessAsUserW", "winerror": 1314})
        self.assertEqual(launcher.failure(OSError("a private path or secret")),
                         {"operation": "launcher", "type": "OSError"})

    def test_symlink_and_outside_root_are_rejected(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            target = root / "owned"
            target.mkdir()
            file = target / "input"
            file.write_text("data")
            alias = root / "alias"
            try:
                alias.symlink_to(target, target_is_directory=True)
            except OSError:
                self.skipTest("unprivileged symlink creation unavailable")
            with self.assertRaises(launcher.GateFailure):
                launcher.checked_path(alias / "input", inside=target)
            with self.assertRaises(launcher.GateFailure):
                launcher.checked_path(file, inside=root / "different")


if __name__ == "__main__":
    unittest.main()
