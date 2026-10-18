"""The normal checks must not revive retired MXC runs or publish releases."""

import hashlib
from pathlib import Path
import unittest

import yaml


ROOT = Path(__file__).resolve().parent.parent
ARCHIVE = ROOT / ".github/legacy/check-mxc.yml"


def read_workflow(path):
    return yaml.safe_load(path.read_text(encoding="utf-8"))


class DefaultWorkflowTests(unittest.TestCase):
    def setUp(self):
        self.workflow = read_workflow(ROOT / ".github/workflows/check.yml")

    def test_default_checks_keep_retired_and_release_operations_disabled(self):
        trigger = self.workflow.get("on", self.workflow.get(True))
        self.assertEqual(set(trigger), {"push", "pull_request", "workflow_dispatch"})
        self.assertIsNone(trigger["workflow_dispatch"])
        self.assertEqual(set(self.workflow["jobs"]), {"linux", "linux-system", "unit"})
        self.assertEqual(self.workflow["permissions"], {"contents": "read"})
        for name, job in self.workflow["jobs"].items():
            with self.subTest(job=name):
                self.assertNotIn("needs", job)
                self.assertNotEqual(job.get("permissions", self.workflow["permissions"]).get("contents"), "write")
                for step in job["steps"]:
                    self.assertFalse(step.get("uses", "").startswith("actions/download-artifact@"))
                    command = step.get("run", "").lower()
                    for retired_operation in ("gh release", "windows_vm_test.py",
                                               "build_windows_package.py", "mxc", "psec"):
                        self.assertNotIn(retired_operation, command)
                    self.assertNotIn("install_runtime.py", command)

    def test_original_four_linux_combinations_keep_their_full_checks(self):
        archived = read_workflow(ARCHIVE)
        for name in ("linux", "linux-system"):
            self.assertEqual(self.workflow["jobs"][name], archived["jobs"][name])
        linux = self.workflow["jobs"]["linux"]
        self.assertEqual(linux["runs-on"], "ubuntu-24.04")
        self.assertEqual(linux["strategy"]["matrix"]["python"], ["3.10", "3.14"])
        system = self.workflow["jobs"]["linux-system"]
        self.assertEqual(system["strategy"]["matrix"]["ubuntu"], ["22.04", "24.04"])
        for name in ("linux", "linux-system"):
            steps = self.workflow["jobs"][name]["steps"]
            tests = next(step for step in steps if ".github/run_tests.py" in step.get("run", ""))
            self.assertEqual(tests["env"]["RULEPROXY_REQUIRE_ISOLATION"], "1")
            self.assertTrue(any(".github/smoke_panel.py" in step.get("run", "") for step in steps))

    def test_all_units_run_on_supported_python_versions_on_both_platforms(self):
        unit = self.workflow["jobs"]["unit"]
        self.assertEqual(set(unit["strategy"]["matrix"]["os"]), {"ubuntu-24.04", "windows-2025"})
        self.assertEqual(set(unit["strategy"]["matrix"]["python"]), {"3.10", "3.14"})
        self.assertEqual(unit["runs-on"], "${{ matrix.os }}")
        setup = next(step for step in unit["steps"] if step.get("uses", "").startswith("actions/setup-python@"))
        self.assertEqual(setup["with"]["python-version"], "${{ matrix.python }}")
        self.assertTrue(any("pip install -r requirements.txt" in step.get("run", "") for step in unit["steps"]))
        tests = next(step for step in unit["steps"] if ".github/run_tests.py" in step.get("run", ""))
        self.assertNotIn("if", tests)
        self.assertEqual(tests["run"], "python -B .github/run_tests.py")

    def test_windows_deployment_parser_fails_on_syntax_errors(self):
        parser = next(step for step in self.workflow["jobs"]["unit"]["steps"]
                      if "Language.Parser]::ParseFile" in step.get("run", ""))
        self.assertEqual(parser["if"], "runner.os == 'Windows'")
        self.assertEqual(parser["shell"], "pwsh")
        self.assertIn("Get-ChildItem scripts", parser["run"])
        self.assertIn("-Filter '*.ps1'", parser["run"])
        self.assertIn("$errors.Count", parser["run"])
        self.assertIn("throw", parser["run"])

    def test_original_workflow_is_preserved_verbatim_outside_discovery(self):
        self.assertEqual(ARCHIVE.parent, ROOT / ".github/legacy")
        self.assertFalse(ARCHIVE.is_relative_to(ROOT / ".github/workflows"))
        self.assertEqual(hashlib.sha256(ARCHIVE.read_bytes()).hexdigest(),
                         "4ba0b1929ce7274a100aef893918be2ffcdca1b61109158f1526db3c3e462f5e")
        archived = read_workflow(ARCHIVE)
        trigger = archived.get("on", archived.get(True))
        self.assertIn("capability_executor_diagnostic", trigger["workflow_dispatch"]["inputs"])
        self.assertIn("pinned-mxc-g-bundle", archived["jobs"])
        self.assertIn("windows-11-x64", archived["jobs"])
        self.assertIn("release", archived["jobs"])


if __name__ == "__main__":
    unittest.main()
