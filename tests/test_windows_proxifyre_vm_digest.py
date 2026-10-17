"""Public CI annotation digest for the Windows 11 global guest result."""
import contextlib
import importlib.util
import io
import json
from pathlib import Path
import unittest
from unittest import mock


ROOT = Path(__file__).resolve().parent.parent
SPEC = importlib.util.spec_from_file_location("ruleproxy_proxifyre_native_vm_digest", ROOT / ".github/windows_proxifyre_vm.py")
vm = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(vm)


def failed_global_result():
    """Failed capture whose guest cleanup succeeded; excluded fields carry sentinels so any leak is visible."""
    return {"schema_version": 2, "status": "failed", "suite": "global-capture", "phase": "global_capture_running",
        "error_type": "BootstrapIncomplete", "error_code": 0, "exit_code": 1,
        "user_cleanup_confirmed": True, "task_cleanup_confirmed": True, "installation_cleanup_confirmed": True,
        "fixture_trust": {"python_initial": False, "os_fetch": True, "root_list_imported": False,
            "python_final": True, "note": "not a bool"},
        "steps": [{"phase": "global_configuration", "utc": "2026-10-17T01:00:00Z"},
                  {"phase": "global_install", "utc": "2026-10-17T01:00:05Z"},
                  {"phase": "global_capture_running", "utc": "2026-10-17T01:00:09Z"}],
        "errors": [{"phase": "global_capture_running", "utc": "2026-10-17T01:04:00Z",
                    "type": "System.Management.Automation.RuntimeException", "hresult": -2146233088,
                    "id": "RuntimeException", "message": "Capture or recovery incomplete",
                    "stack": "at <ScriptBlock>, C:\\RuleProxyProductBootstrap\\ruleproxy-vm-run.ps1: line 349"}],
        "logs": {"tests": "SENTINEL-FULL-LOG", "supervisor": "SENTINEL-FULL-LOG"},
        "os": {"build": 26100, "ubr": 1, "product_type": "WinNT", "native_architecture": "AMD64"},
        "owner": {"sid": "S-1-5-21-111-222-333-1001", "elevated": True, "sid_matches_installation": True},
        "actor_sid": "S-1-5-21-111-222-333-1002",
        "package": {"manifest_verified": True, "sha256": "a" * 64, "fixed_core_sha256": "b" * 64},
        "source_identity": {"tested_source_commit": "c" * 40, "source_sha256": {"ruleproxy/x.py": "d" * 64},
                            "harness_sha256": "e" * 64},
        "reports": {"global_capture": {"schema_version": 1, "passed": False, "failed_stage": "explicit_recovery",
            "error": "RuntimeError:precise_restore_failed",
            "time_budget": {"cooperative_experiment_seconds": 150, "stages": [
                {"stage": "register_independent_recovery", "started_seconds": 0.0, "elapsed_seconds": 0.1},
                {"stage": "explicit_recovery", "started_seconds": 9.9}]},
            "recovery": {"recovered": False, "errors": ["OSError:cannot restore C:\\ProgramData\\RuleProxy-Web\\state.json"]},
            "components": {"capture_components": [1, 2], "nic": {"index": 7, "source": "10.0.2.15"}},
            "tun_identity": {"alias": "RuleProxyTun", "luid": 42, "interface_guid": "00000000-0000-0000-0000-000000000000"},
            "fixed_core_sha256": "b" * 64}}}


EXPECTED_FAILED_DIGEST = {
    "guest": {"status": "failed", "phase": "global_capture_running", "error_type": "BootstrapIncomplete",
              "error_code": 0, "exit_code": 1, "user_cleanup_confirmed": True, "task_cleanup_confirmed": True,
              "installation_cleanup_confirmed": True,
              "fixture_trust": {"python_initial": False, "os_fetch": True, "root_list_imported": False,
                                "python_final": True},
              "step_phases": ["global_configuration", "global_install", "global_capture_running"],
              "last_error": {"phase": "global_capture_running", "type": "System.Management.Automation.RuntimeException",
                             "message": "Capture or recovery incomplete"}},
    "harness": {"passed": False, "failed_stage": "explicit_recovery", "error": "RuntimeError:precise_restore_failed",
                "stages": ["register_independent_recovery", "explicit_recovery"],
                "recovery": {"recovered": False, "errors": ["OSError:cannot restore [PATH REDACTED]"]}},
}


class GlobalGuestDigestTests(unittest.TestCase):
    def test_digest_is_exactly_the_bounded_triage_view(self):
        self.assertEqual(vm.global_guest_digest(failed_global_result()), EXPECTED_FAILED_DIGEST)

    def test_identity_logs_paths_and_hashes_outside_the_view_never_appear(self):
        text = json.dumps(vm.global_guest_digest(failed_global_result()), sort_keys=True)
        for sentinel in ("S-1-5-21", "SENTINEL-FULL-LOG", "RuleProxyProductBootstrap", "ProgramData", "RuleProxy-Web",
                         "10.0.2.15", "RuleProxyTun", "00000000-0000", "a" * 16, "b" * 16, "c" * 16, "d" * 16, "e" * 16,
                         '"os":', '"owner":', '"actor_sid":', '"logs":', '"package":', '"source_identity":',
                         '"components":', '"tun_identity":', '"fixed_core_sha256":', '"stack"', '"hresult"', '"utc"', '"id"'):
            with self.subTest(sentinel=sentinel):
                self.assertNotIn(sentinel, text)

    def test_free_text_drops_urls_windows_paths_and_sids(self):
        result = failed_global_result()
        result["errors"][-1]["message"] = ("fetch https://10.0.2.2:12345/cap-token failed at C:\\RuleProxy\\x.json "
                                           "for S-1-5-21-111-222-333-1001 and ftp://mirror/x")
        self.assertEqual(vm.global_guest_digest(result)["guest"]["last_error"]["message"],
                         "fetch [URL REDACTED] failed at [PATH REDACTED] for [SID REDACTED] and [URL REDACTED]")

    def test_every_free_text_field_and_list_is_bounded(self):
        result = failed_global_result()
        result["steps"] = [{"phase": "q" * 1000}] + [{"phase": f"p{index}"} for index in range(50)]
        result["errors"][-1]["message"] = "m" * 1000
        report = result["reports"]["global_capture"]
        report["error"] = "e" * 1000
        report["time_budget"]["stages"] = [{"stage": f"s{index}"} for index in range(60)]
        report["recovery"]["errors"] = ["r" * 500, "x" * 500, "y" * 500]
        report["ci_network_reclaim"] = {"recovered": True, "errors": ["z" * 500] * 3}
        digest = vm.global_guest_digest(result)
        self.assertEqual(digest["guest"]["step_phases"], ["q" * 200] + [f"p{index}" for index in range(29)])
        self.assertEqual(len(digest["guest"]["last_error"]["message"]), 300)
        self.assertEqual(len(digest["harness"]["error"]), 300)
        self.assertEqual(digest["harness"]["stages"], [f"s{index}" for index in range(40)])
        self.assertEqual([len(text) for text in digest["harness"]["recovery"]["errors"]], [200, 200])
        self.assertEqual([len(text) for text in digest["harness"]["ci_network_reclaim"]["errors"]], [200, 200])

    def test_settle_view_keeps_bounded_scalars_and_process_names(self):
        result = failed_global_result()
        result["settle"] = {"settled": False, "probes": 41, "first_seconds": 11.2, "last_seconds": 6.4,
                            "waited_seconds": 603, "streak": 9,
                            "busy_processes": ["MsMpEng=1.21"] + ["x" * 99] * 9 + [3]}
        self.assertEqual(vm.global_guest_digest(result)["guest"]["settle"],
                         {"settled": False, "probes": 41, "first_seconds": 11.2, "last_seconds": 6.4,
                          "waited_seconds": 603, "busy_processes": ["MsMpEng=1.21"] + ["x" * 60] * 5})
        self.assertNotIn("settle", vm.global_guest_digest(failed_global_result())["guest"])
        self.assertEqual(vm.global_guest_digest({"settle": {"probes": [1], "busy_processes": "MsMpEng"}})["guest"]["settle"],
                         {"settled": None, "probes": None, "first_seconds": None, "last_seconds": None,
                          "waited_seconds": None, "busy_processes": []})

    def test_non_dict_results_are_described_not_raised(self):
        for value in (None, "text", 7, 1.5, True, [], ["global_capture"]):
            with self.subTest(value=value):
                self.assertEqual(vm.global_guest_digest(value), {"result_type": type(value).__name__})

    def test_partially_malformed_results_never_raise_and_keep_only_valid_fields(self):
        digest = vm.global_guest_digest({})
        self.assertEqual(digest["guest"]["step_phases"], [])
        self.assertIsNone(digest["guest"]["last_error"])
        self.assertNotIn("fixture_trust", digest["guest"])
        self.assertNotIn("harness", digest)

        digest = vm.global_guest_digest({"steps": [None, 3, {"phase": 7}, {"phase": "kept"}], "errors": [None],
                                         "status": {"nested": "dropped"}, "reports": {"global_capture": "text"}})
        self.assertEqual(digest["guest"]["step_phases"], ["kept"])
        self.assertIsNone(digest["guest"]["status"])
        self.assertIsNone(digest["guest"]["last_error"])
        self.assertNotIn("harness", digest)

        digest = vm.global_guest_digest({"errors": [{"phase": "p", "type": ["t"], "message": {"m": 1}}],
                                         "fixture_trust": {1: True, "ok": False, "bad": "yes"}})
        self.assertEqual(digest["guest"]["last_error"], {"phase": "p", "type": None, "message": None})
        self.assertEqual(digest["guest"]["fixture_trust"], {"ok": False})

        digest = vm.global_guest_digest({"reports": {"global_capture": {
            "time_budget": "x", "recovery": ["r"], "ci_network_reclaim": "no", "passed": None,
            "failed_stage": ["x"], "error": ["e"]}}})
        self.assertEqual(digest["harness"], {"passed": None, "failed_stage": None, "error": None,
                                             "stages": [], "recovery": None})

        digest = vm.global_guest_digest({"reports": {"global_capture": {
            "time_budget": {"stages": [None, {"stage": 9}, {"stage": "kept"}]},
            "recovery": {"recovered": True, "errors": "not-a-list"}}}})
        self.assertEqual(digest["harness"]["stages"], ["kept"])
        self.assertEqual(digest["harness"]["recovery"], {"recovered": True, "errors": []})


class CiAnnotationTests(unittest.TestCase):
    def printed(self, *args):
        output = io.StringIO()
        with contextlib.redirect_stdout(output):
            vm.print_ci_annotation(*args)
        return output.getvalue()

    def test_percent_and_line_breaks_stay_escaped_on_one_workflow_line(self):
        line = self.printed("notice", "Title", {"text": "100% done\r\nline two %0A"})
        self.assertEqual(line, '::notice title=Title::{"text":"100%25 done\\r\\nline two %250A"}\n')

    def test_annotation_body_is_truncated_to_1800_characters(self):
        self.assertEqual(self.printed("error", "T", "x" * 5000), "::error title=T::" + '"' + "x" * 1799 + "\n")


class GlobalGuestAnnotationTests(unittest.TestCase):
    def test_helper_annotates_only_an_existing_guest_result(self):
        output = io.StringIO()
        with contextlib.redirect_stdout(output):
            vm.print_global_guest_digest("error", mock.Mock(result={"status": "failed"}))
            vm.print_global_guest_digest("notice", None)
            vm.print_global_guest_digest("error", mock.Mock(result=None))
        lines = output.getvalue().splitlines()
        self.assertEqual(len(lines), 1)
        self.assertTrue(lines[0].startswith('::error title=Win11 global guest digest::{"guest":{'))

    def test_helper_swallows_digest_and_print_failures(self):
        output = io.StringIO()
        with contextlib.redirect_stdout(output):
            with mock.patch.object(vm, "global_guest_digest", side_effect=RuntimeError("digest bug")):
                vm.print_global_guest_digest("error", mock.Mock(result={"status": "failed"}))
            with mock.patch.object(vm, "print_ci_annotation", side_effect=OSError("stdout closed")):
                vm.print_global_guest_digest("notice", mock.Mock(result={"status": "passed"}))
        self.assertEqual(output.getvalue(), "")

if __name__ == "__main__":
    unittest.main()
