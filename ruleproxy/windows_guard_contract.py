"""Fail-closed contract for an experimental Windows transparent-proxy backend.

This module intentionally does NOT install WFP rules and MUST NOT be mistaken
for an implemented kill switch. A third-party packet redirector such as
ProxyBridge/WinDivert is not an independent network isolation boundary.

Only a future privileged, independently verifiable WFP guard may satisfy
this contract. Until that adapter is implemented and tested on Windows,
launch authorization is always denied.
"""
from __future__ import annotations

from dataclasses import dataclass
from typing import Protocol


class IsolationNotProven(RuntimeError):
    """Refuse a protected launch until kernel isolation has been proven."""


@dataclass(frozen=True)
class GuardEvidence:
    """Snapshot of independent OS-enforced isolation for one protected app."""

    target_identity: str
    provider: str
    fail_closed_on_redirector_stop: bool
    blocks_ipv4: bool
    blocks_ipv6: bool
    blocks_udp: bool
    blocks_dns_bypass: bool
    blocks_other_loopback: bool
    verified_by_independent_probe: bool


class WindowsGuard(Protocol):
    def install_before_launch(self, identity: str) -> GuardEvidence:
        """Install an independent persistent OS guard BEFORE launching the app."""
        ...


class UnimplementedWfpGuard:
    """Safety default while designing the WFP/WinDivert boundary."""

    def install_before_launch(self, identity: str) -> GuardEvidence:
        raise IsolationNotProven(
            "Windows transparent proxy requires an independently proven WFP "
            "kill switch; ProxyBridge redirection alone fails open."
        )


def require_guard(evidence: GuardEvidence, expected_identity: str) -> None:
    """Reject incomplete, stale or redirector-dependent evidence."""
    if not expected_identity or evidence.target_identity != expected_identity:
        raise IsolationNotProven("Guard identity mismatch")
    if evidence.provider != "independent-wfp":
        raise IsolationNotProven("Guard does not use independent WFP enforcement")
    requirements = (
        evidence.fail_closed_on_redirector_stop,
        evidence.blocks_ipv4,
        evidence.blocks_ipv6,
        evidence.blocks_udp,
        evidence.blocks_dns_bypass,
        evidence.blocks_other_loopback,
        evidence.verified_by_independent_probe,
    )
    if not all(value is True for value in requirements):
        raise IsolationNotProven("Network isolation proof is incomplete")
