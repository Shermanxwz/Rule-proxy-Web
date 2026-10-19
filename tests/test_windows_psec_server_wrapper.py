"""Exercise the actual bounded Server bootstrap without creating accounts."""
from __future__ import annotations

import io
import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import types
import unittest
from unittest import mock
import zipfile

ROOT = Path(__file__).resolve().parent.parent
SCRIPT = ROOT / ".github/run_windows_psec_smoke.ps1"


def bootstrap_module():
    source = SCRIPT.read_text(encoding="utf-8").split("$bootstrap = @'\n", 1)[1].split("\n'@", 1)[0]
    module = types.ModuleType("psec_server_bootstrap_test")
    exec(compile(source, str(SCRIPT) + ":bootstrap", "exec"), module.__dict__)
    return module


class ServerBootstrapTests(unittest.TestCase):
    def setUp(self):
        self.bootstrap = bootstrap_module()
        self.temporary = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        self.directory = Path(self.temporary.name)
        self.config = {"repository": str(ROOT), "launch": str(self.directory),
                       "work": str(self.directory / "new-work"), "browser": "fixed-edge.exe",
                       "bundle": str(self.directory / "bundle.zip"), "source_commit": "a" * 40}

    def test_bad_bundle_cannot_download_or_create_a_runtime(self):
        import install_runtime
        Path(self.config["bundle"]).write_bytes(b"not the fixed G bundle")
        with mock.patch.object(install_runtime, "fetch", side_effect=AssertionError("network forbidden")), \
                mock.patch.dict(os.environ, {"RULEPROXY_PINNED_G_BUNDLE": "untrusted-cache"}):
            with self.assertRaisesRegex(ValueError, "digest mismatch"):
                self.bootstrap.prepare_runtime(self.config)
        self.assertFalse((self.directory / "fixed-runtime").exists())

    def test_verified_manifest_is_retained_after_general_extraction(self):
        import install_runtime
        manifest = b'{"fixed":"manifest from already verified bundle"}'
        archive = io.BytesIO()
        with zipfile.ZipFile(archive, "w") as stream:
            stream.writestr("build-manifest.json", manifest)
        with mock.patch.object(install_runtime, "_g_bundle_bytes", return_value=archive.getvalue()) as verify, \
                mock.patch.object(install_runtime, "_extract_g_bundle") as extract:
            runtime = self.bootstrap.prepare_runtime(self.config)
        verify.assert_called_once_with(Path(self.config["bundle"]), allow_env_cache=False)
        extract.assert_called_once_with(archive.getvalue(), runtime)
        self.assertEqual((runtime / "build-manifest.json").read_bytes(), manifest)

    def test_timeout_kills_only_the_retained_child_and_never_claims_cleanup(self):
        child = mock.Mock()
        child.wait.side_effect = [subprocess.TimeoutExpired("own controller", 660), 125]
        child.poll.return_value = 125
        with mock.patch.object(self.bootstrap.subprocess, "Popen", return_value=child) as start, \
                mock.patch.dict(os.environ, {"GITHUB_TOKEN": "must-not-forward", "GITHUB_SHA": "b" * 40}):
            report = self.bootstrap.run_controller(self.config, self.directory)
        child.kill.assert_called_once_with()
        self.assertEqual(child.wait.call_args_list, [mock.call(timeout=660), mock.call(timeout=15)])
        self.assertTrue(report["timed_out"])
        self.assertTrue(report["cleanup_unconfirmed"])
        self.assertFalse(report["completed"])
        self.assertFalse(report["functionality_passed"])
        environment = start.call_args.kwargs["env"]
        self.assertEqual(environment["GITHUB_SHA"], self.config["source_commit"])
        self.assertNotIn("GITHUB_TOKEN", environment)
        for name in ("stdin", "stdout", "stderr"):
            self.assertEqual(start.call_args.kwargs[name], subprocess.DEVNULL)

    def test_failure_preserves_smoke_report_and_requires_all_cleanup_evidence(self):
        evidence = {"functionality_passed": False,
                    "checks": {name: True for name in
                               ("account_cleanup", "fixture_cleanup", "outer_job_empty", "case_cleanup")},
                    "baseline": {"checks": {"outer_job_empty": True, "case_cleanup": True}}}
        path = self.directory / "smoke-report.json"
        child = mock.Mock()
        child.wait.return_value = child.poll.return_value = 1
        for confirmed in (True, False):
            with self.subTest(cleanup_confirmed=confirmed):
                evidence["baseline"]["checks"]["outer_job_empty"] = confirmed
                raw = json.dumps(evidence).encode()
                path.write_bytes(raw)
                with mock.patch.object(self.bootstrap.subprocess, "Popen", return_value=child):
                    result = self.bootstrap.run_controller(self.config, self.directory)
                self.assertEqual(path.read_bytes(), raw)
                self.assertTrue(result["completed"])
                self.assertEqual(result["cleanup_unconfirmed"], not confirmed)
                self.assertFalse(result["functionality_passed"])
                self.assertFalse(result["windows_11_verified"])
                self.assertFalse(result["privacy_qualified"])
                self.assertFalse(result["product_acceptance"])
        child.kill.assert_not_called()


@unittest.skipUnless(os.name == "nt", "requires the native Windows PowerShell parser and CI guard")
class ServerWrapperWindowsTests(unittest.TestCase):
    def test_ps51_parses_and_rejects_non_ci_before_creating_files(self):
        powershell = Path(os.environ["SystemRoot"]) / "System32/WindowsPowerShell/v1.0/powershell.exe"
        with tempfile.TemporaryDirectory() as temporary:
            output = Path(temporary) / "must-not-be-created"
            script = Path(temporary) / "guard.ps1"
            quote = lambda value: "'" + str(value).replace("'", "''") + "'"
            script.write_text(
                "$ErrorActionPreference='Stop'\n"
                "$tokens=$null; $errors=$null\n"
                "[Management.Automation.Language.Parser]::ParseFile(" + quote(SCRIPT) +
                ",[ref]$tokens,[ref]$errors) | Out-Null\n"
                "if ($errors.Count) { throw 'Wrapper parse failed' }\n"
                "$env:GITHUB_ACTIONS='false'; $env:RUNNER_OS='Windows'\n"
                "try { & " + quote(SCRIPT) + " -BundleZip absent.zip -Output " + quote(output) +
                "; throw 'Guard failed' } catch {\n"
                "  if ($_.Exception.Message -ne 'This experiment requires a disposable Windows GitHub Actions runner')"
                " { throw }\n}\n", encoding="utf-8-sig")
            result = subprocess.run([str(powershell), "-NoProfile", "-NonInteractive", "-File", str(script)],
                                    capture_output=True, text=True, timeout=30, check=False)
            self.assertEqual(result.returncode, 0, result.stderr)
            self.assertFalse(output.exists())


if __name__ == "__main__":
    unittest.main()
