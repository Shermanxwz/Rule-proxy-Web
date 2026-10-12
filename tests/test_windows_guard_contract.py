"""Contract tests: no transparent-proxy launch may bypass isolation proof."""
import unittest
from ruleproxy.windows_guard_contract import (
    GuardEvidence, IsolationNotProven, UnimplementedWfpGuard, require_guard
)


class GuardContractTests(unittest.TestCase):
    def full_evidence(self, **changes):
        fields = dict(
            target_identity="test-app-123", provider="independent-wfp",
            fail_closed_on_redirector_stop=True, blocks_ipv4=True,
            blocks_ipv6=True, blocks_udp=True, blocks_dns_bypass=True,
            blocks_other_loopback=True, verified_by_independent_probe=True,
        )
        fields.update(changes)
        return GuardEvidence(**fields)

    def test_not_implemented_must_refuse(self):
        with self.assertRaises(IsolationNotProven):
            UnimplementedWfpGuard().install_before_launch("test-app-123")

    def test_valid_evidence_only(self):
        require_guard(self.full_evidence(), "test-app-123")

    def test_wrong_identity_refused(self):
        with self.assertRaises(IsolationNotProven):
            require_guard(self.full_evidence(), "other-app")

    def test_missing_evidence_is_refused(self):
        fields = (
            "fail_closed_on_redirector_stop", "blocks_ipv4", "blocks_ipv6",
            "blocks_udp", "blocks_dns_bypass", "blocks_other_loopback",
            "verified_by_independent_probe",
        )
        for field in fields:
            with self.subTest(field=field):
                with self.assertRaises(IsolationNotProven):
                    require_guard(self.full_evidence(**{field: False}), "test-app-123")

    def test_redirector_is_not_a_guard(self):
        with self.assertRaises(IsolationNotProven):
            require_guard(self.full_evidence(provider="proxybridge"), "test-app-123")


if __name__ == "__main__":
    unittest.main()
