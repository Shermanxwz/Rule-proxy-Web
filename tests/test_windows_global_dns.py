"""NRPT ownership/policy contracts, without touching machine DNS or routes."""
import base64
import os
from pathlib import Path
import re
import subprocess
import sys
import threading
import unittest
from unittest import mock

from ruleproxy import windows_global_dns as dns
from ruleproxy import windows_global_guard as guard
from ruleproxy import windows_proxy_service as service
from ruleproxy.windows_proxy_policy import ProxyError

ROOT = Path(__file__).resolve().parent.parent
METADATA = {"root": r"C:\Program Files\RuleProxy-Web", "owner_sid": "S-1-5-21-1-2-3-1000",
            "global_backend_version": 1}
GUID = "{12345678-1234-1234-1234-123456789abc}"


class DnsLeaseTests(unittest.TestCase):
    def test_qualified_capability_does_not_replace_fresh_effective_dns_state(self):
        self.lease.qualification = {**self.lease.qualification, "native_qualified": True}
        refresh = mock.patch.object(dns, "load_qualification", return_value=self.lease.qualification)
        refresh.start()
        self.addCleanup(refresh.stop)
        clock = [0]
        self.lease._clock = lambda: clock[0]
        self.runner.return_value = self.snapshot()
        idle = self.lease.status(refresh=True)
        self.assertIs(idle["native_qualified"], True)
        self.assertIs(idle["strict_isolation"], False)
        self.runner.return_value = self.snapshot([self.owned()], [self.effective()])
        active = self.lease.apply()
        self.assertIs(active["strict_isolation"], True)
        self.assertIs(active["fresh"], True)
        self.assertIs(self.lease.status()["strict_isolation"], True)
        clock[0] = 3
        with mock.patch.object(dns.threading, "Thread"):
            pending = self.lease.status()
        self.assertIs(pending["native_qualified"], True)
        self.assertIs(pending["strict_isolation"], False)
        self.assertIs(pending["fresh"], False)
        self.runner.return_value = self.snapshot([self.owned()], [])
        conflict = self.lease.status(refresh=True)
        self.assertIs(conflict["native_qualified"], True)
        self.assertIs(conflict["strict_isolation"], False)

    def setUp(self):
        self.runner = mock.Mock()
        self.lease = dns.DnsLease(METADATA, runner=self.runner)
        self.authority = mock.patch.object(dns.DnsLease, "_authority")
        self.authority.start()
        self.addCleanup(self.authority.stop)

    def owned(self, **changes):
        return {"name": GUID, "comment": self.lease.marker, "display_name": self.lease.display,
                "namespace": ["."], "nameservers": list(dns.PEERS), "overrides": False, **changes}

    def effective(self, **changes):
        return {"namespace": ["."], "nameservers": list(dns.PEERS), "overrides": False, **changes}

    def snapshot(self, rules=None, effective=None):
        return {"ok": True, "rules": rules or [], "effective": effective or []}

    def test_empty_nrpt_is_available_but_not_active_or_qualified(self):
        self.runner.return_value = self.snapshot()
        result = self.lease.status(refresh=True)
        self.assertTrue(result["supported"])
        self.assertFalse(result["active"])
        self.assertFalse(result["effective"])
        self.assertFalse(result["native_qualified"])
        self.assertEqual(result["owned_rule_names"], [])
        self.runner.assert_called_once_with("inspect")

    def test_exact_rule_and_full_effective_policy_are_required_to_apply(self):
        self.runner.return_value = self.snapshot([self.owned()], [self.effective()])
        result = self.lease.apply()
        self.assertTrue(result["active"])
        self.assertTrue(result["effective"])
        self.assertFalse(result["native_qualified"])
        self.assertEqual(result["owned_rule_names"], [GUID])
        self.runner.assert_called_once_with("apply")

    def test_more_specific_or_root_foreign_rules_block_whole_machine_claim(self):
        foreign = self.owned(name="{87654321-1234-1234-1234-123456789abc}",
                             comment="Other product", display_name="Other product", namespace=[".corp.test"])
        for rules, policies in (([foreign], []), ([self.owned(), foreign], [self.effective()]),
                                ([self.owned()], [self.effective(), self.effective(namespace=[".corp.test"])]),
                                ([], [self.effective()])):
            with self.subTest(rules=rules, policies=policies):
                self.runner.return_value = self.snapshot(rules, policies)
                with self.assertRaises(ProxyError):
                    self.lease.apply()

    def test_similar_marker_changed_rule_or_multiple_ownership_is_not_adopted(self):
        for rules in ([self.owned(comment=self.lease.marker + "x")],
                      [self.owned(nameservers=["1.1.1.1"])],
                      [self.owned(namespace=[".corp.test"])],
                      [self.owned(overrides=True)],
                      [self.owned(name="*")],
                      [self.owned(), self.owned()]):
            with self.subTest(rules=rules), self.assertRaises(ProxyError):
                self.lease._snapshot(self.snapshot(rules, [self.effective()]))

    def test_effective_mismatch_cannot_count_as_applied(self):
        for policies in ([], [self.effective(nameservers=["1.1.1.1"])],
                         [self.effective(overrides=True)]):
            self.runner.return_value = self.snapshot([self.owned()], policies)
            with self.subTest(policies=policies), self.assertRaises(ProxyError):
                self.lease.apply()

    def test_normal_stop_can_preserve_unrelated_policy_and_uses_only_remove_operation(self):
        foreign = self.owned(comment="Other", display_name="Other", namespace=[".corp.test"],
                             nameservers=["192.0.2.53"])
        self.runner.return_value = self.snapshot([foreign], [self.effective(namespace=[".corp.test"],
                                                                          nameservers=["192.0.2.53"])])
        result = self.lease.normal_stop()
        self.assertFalse(result["active"])
        self.assertTrue(result["stopped"])
        self.assertEqual(result["foreign_rule_count"], 1)
        self.runner.assert_called_once_with("remove")

    def test_foreign_effective_policy_still_using_virtual_dns_blocks_restore_confirmation(self):
        self.lease._sleep = mock.Mock()
        self.runner.return_value = self.snapshot([], [self.effective()])
        with self.assertRaises(ProxyError) as caught:
            self.lease.normal_stop()
        self.assertEqual(caught.exception.code, "global_dns_restore_incomplete")

    def test_normal_stop_retries_transient_unavailable_then_restores(self):
        self.lease._sleep = mock.Mock()
        self.runner.side_effect = [ProxyError("global_dns_unavailable", "timeout"), self.snapshot()]
        result = self.lease.normal_stop()
        self.assertTrue(result["stopped"])
        self.assertFalse(result["active"])
        self.assertEqual(self.runner.call_args_list, [mock.call("remove"), mock.call("remove")])
        self.lease._sleep.assert_called_once_with(dns._RESTORE_BACKOFF_SECONDS)

    def test_normal_stop_retry_is_bounded(self):
        self.lease._sleep = mock.Mock()
        self.runner.side_effect = ProxyError("global_dns_unavailable", "timeout")
        with self.assertRaises(ProxyError) as caught:
            self.lease.normal_stop()
        self.assertEqual(caught.exception.code, "global_dns_unavailable")
        self.assertEqual(self.runner.call_count, dns._RESTORE_ATTEMPTS)
        self.assertEqual(self.lease._sleep.call_count, dns._RESTORE_ATTEMPTS - 1)

    def test_normal_stop_does_not_retry_policy_conflict(self):
        self.lease._sleep = mock.Mock()
        self.runner.side_effect = ProxyError("global_dns_conflict", "conflict")
        with self.assertRaises(ProxyError) as caught:
            self.lease.normal_stop()
        self.assertEqual(caught.exception.code, "global_dns_conflict")
        self.runner.assert_called_once_with("remove")
        self.lease._sleep.assert_not_called()

    def test_normal_stop_retries_effective_policy_lag(self):
        self.lease._sleep = mock.Mock()
        self.runner.side_effect = [self.snapshot([], [self.effective()]), self.snapshot()]
        result = self.lease.normal_stop()
        self.assertTrue(result["stopped"])
        self.assertFalse(result["active"])
        self.assertEqual(self.runner.call_count, 2)
        self.lease._sleep.assert_called_once_with(dns._RESTORE_BACKOFF_SECONDS)

    def test_crash_keep_does_not_run_remove_or_apply(self):
        self.runner.return_value = self.snapshot([self.owned()], [self.effective()])
        self.lease.status(refresh=True)
        self.runner.reset_mock()
        result = self.lease.crash_keep()
        self.assertTrue(result["retained_after_failure"])
        self.runner.assert_not_called()

    def test_crash_without_fresh_cache_does_not_start_or_wait_for_a_query(self):
        with mock.patch.object(dns.threading, "Thread") as thread:
            result = self.lease.crash_keep()
        thread.assert_not_called()
        self.runner.assert_not_called()
        self.assertIsNone(result["active"])
        self.assertFalse(result["effective"])
        self.assertFalse(result["restore_attempted"])

    def test_unavailable_query_is_unknown_and_not_a_false_inactive_success(self):
        self.runner.side_effect = ProxyError("global_dns_unavailable", "query unavailable")
        result = self.lease.status(refresh=True)
        self.assertFalse(result["supported"])
        self.assertIsNone(result["active"])
        self.assertFalse(result["effective"])

    def test_initial_and_expired_status_return_immediately_with_only_one_background_inspect(self):
        entered, release, finished = threading.Event(), threading.Event(), threading.Event()
        def slow_inspect(operation):
            self.assertEqual(operation, "inspect")
            entered.set()
            release.wait(2)
            finished.set()
            return self.snapshot()
        self.runner.side_effect = slow_inspect
        try:
            first = self.lease.status()
            self.assertTrue(entered.wait(1))
            self.assertEqual(first["state"], "checking")
            self.assertFalse(first["effective"])
            self.assertIsNone(first["active"])
            self.assertFalse(first["fresh"])
            self.assertTrue(first["component_available"])
            for _ in range(8):
                pending = self.lease.status()
                self.assertEqual(pending["state"], "checking")
                self.assertFalse(pending["strict_isolation"])
            self.runner.assert_called_once_with("inspect")
        finally:
            release.set()
            self.assertTrue(finished.wait(1))
            # Synchronize with the completed inspect without starting a second
            # process. It may still be committing its small cache here.
            with self.lease._query_lock:
                pass

    def test_stale_confirmed_effectiveness_is_not_reused_while_refresh_is_pending(self):
        clock = [1.0]
        self.lease._clock = lambda: clock[0]
        self.runner.return_value = self.snapshot([self.owned()], [self.effective()])
        self.lease.status(refresh=True)
        clock[0] = 4.0
        with mock.patch.object(dns.threading, "Thread") as thread:
            result = self.lease.status()
            self.lease.status()
        self.assertEqual(result["state"], "checking")
        self.assertTrue(result["last_observed_active"])
        self.assertIsNone(result["active"])
        self.assertFalse(result["effective"])
        self.assertFalse(result["strict_isolation"])
        self.assertEqual(result["last_verified_age_seconds"], 3.0)
        self.assertEqual(thread.call_count, 1)

    def test_rule_identity_tracks_installed_owner_and_root_without_interpolating_raw_text(self):
        other = dns.DnsLease({**METADATA, "owner_sid": "S-1-5-21-1-2-3-1001"}, runner=self.runner)
        self.assertNotEqual(self.lease.marker, other.marker)
        self.assertRegex(self.lease.marker, r"\ARuleProxyDNS-v1:[a-f0-9]{64}\Z")
        self.assertNotIn(METADATA["owner_sid"], self.lease.marker)

    def test_nrpt_address_forms_are_normalized_as_ips_without_commands(self):
        rule = self.owned(nameservers="198.18.0.2; FDFE:DCBA:8879:0:0:0:0:2")
        result = self.lease._snapshot(self.snapshot([rule], [self.effective()]))
        self.assertTrue(result["effective"])
        for value in (["dns.example"], ["198.18.0.2; Invoke-Expression evil"]):
            with self.subTest(value=value), self.assertRaises(ProxyError):
                dns._servers(value)


class UninstallRecoveryCodeTests(unittest.TestCase):
    def setUp(self):
        source = (ROOT / "scripts/windows-uninstall.ps1").read_text()
        self.code = re.search(r"\$code = @'\n(.*?)\n'@", source, re.S).group(1)

    def run_recovery(self, *, running=False, dns_result=None, dns_error=None, metadata=None):
        events = []
        control = mock.Mock()
        control.status.return_value = {"state": 4 if running else 1}
        lease = mock.Mock()
        def restore_dns():
            events.append("dns")
            if dns_error:
                raise dns_error
            return dns_result or {"supported": True, "active": False}
        lease.normal_stop.side_effect = restore_dns
        owned_guard = mock.Mock()
        def restore_guard():
            events.append("guard")
            return {"supported": True, "active": False}
        owned_guard.normal_stop.side_effect = restore_guard
        gate = mock.Mock()
        gate.purge.side_effect = lambda: events.append("containers") or {"active": False, "purged_sids": []}
        with mock.patch.object(sys, "argv", ["restore", str(ROOT)]), \
                mock.patch.object(service, "load_deployment", return_value=metadata or METADATA), \
                mock.patch.object(service, "ServiceControl", return_value=control), \
                mock.patch.object(dns, "DnsLease", return_value=lease), \
                mock.patch.object(guard, "Guard", return_value=owned_guard), \
                mock.patch("ruleproxy.windows_appcontainer.ContainerGate", return_value=gate), \
                mock.patch("builtins.print"):
            exec(compile(self.code, "<fixed-uninstall-global-restore>", "exec"), {})
        return events

    def test_actual_admin_restore_code_restores_dns_before_releasing_guard(self):
        self.assertEqual(self.run_recovery(), ["dns", "guard", "containers"])

    def test_running_service_is_rejected_before_any_restore(self):
        with self.assertRaises(RuntimeError):
            self.run_recovery(running=True)

    def test_dns_failure_or_unconfirmed_restore_never_withdraws_guard(self):
        for result, error in (({"supported": True, "active": True}, None),
                              ({"supported": False, "active": False}, None),
                              (None, ProxyError("global_dns_unavailable", "unavailable"))):
            with self.subTest(result=result), self.assertRaises((RuntimeError, ProxyError)):
                self.run_recovery(dns_result=result, dns_error=error)

    def test_legacy_non_global_install_does_not_invent_a_dns_lease(self):
        self.assertEqual(self.run_recovery(metadata={**METADATA, "global_backend_version": None}), ["containers"])


@unittest.skipUnless(os.name == "nt", "requires native PowerShell parser; performs no DNS mutations")
class NativeScriptSyntaxTests(unittest.TestCase):
    def test_complete_fixed_nrpt_program_parses_without_running_it(self):
        payload = base64.b64encode(dns._SCRIPT.encode("utf-8")).decode("ascii")
        script = ("$t=$null;$e=$null;$s=[Text.Encoding]::UTF8.GetString([Convert]::FromBase64String('" + payload + "'));"
                  "[void][Management.Automation.Language.Parser]::ParseInput($s,[ref]$t,[ref]$e);"
                  "if($e.Count){[Console]::Error.WriteLine(($e.ErrorId -join ','));exit 17};exit 0")
        executable = Path(os.environ["SystemRoot"]) / "System32/WindowsPowerShell/v1.0/powershell.exe"
        encoded = base64.b64encode(script.encode("utf-16-le")).decode("ascii")
        result = subprocess.run([str(executable), "-NoProfile", "-NonInteractive", "-EncodedCommand", encoded],
                                text=True, capture_output=True, timeout=8)
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)


if __name__ == "__main__":
    unittest.main()
