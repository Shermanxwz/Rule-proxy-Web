"""Fail the draft Windows security gate and retain a machine-readable CI record.

A green unit test does not prove WFP/WinDivert ordering or leak resistance.
Only an implemented, independently measured Windows test may ever replace this
gate. Keep this separate from the existing MXC and Linux checks.
"""

import json
from pathlib import Path
import platform
import sys


CHECKS = {
    "signed_wfp_guard_and_process_tree_identity": "not implemented",
    "transparent_tcp_redirect_while_wfp_guard_is_active": "not demonstrated",
    "ipv4_ipv6_dns_udp_webrtc_no_direct_packets": "not demonstrated",
    "proxybridge_and_mihomo_failure_keeps_block": "not demonstrated",
    "chrome_edge_firefox_login_cookie_relaunch": "not demonstrated",
    "install_uninstall_and_reboot_recovery": "not demonstrated",
    "unprotected_app_network_unchanged": "not demonstrated",
}


def main(argv: list[str]) -> int:
    if len(argv) != 1:
        raise SystemExit("usage: windows_candidate_gate.py OUTPUT.json")
    path = Path(argv[0])
    path.parent.mkdir(parents=True, exist_ok=True)
    checks = CHECKS.copy()
    observed = None
    experiment_path = Path('candidate-evidence/experiment.json')
    if experiment_path.is_file():
        try:
            sample = json.loads(experiment_path.read_text(encoding='utf-8-sig'))
            observed = {
                'environment': sample.get('environment'),
                'status': sample.get('status'),
                'error': sample.get('error'),
                'no_wfp': sample.get('no_wfp'),
                'with_wfp': sample.get('with_wfp'),
                'same_name_other': sample.get('same_name_other'),
                'same_name_other_with_wfp': sample.get('same_name_other_with_wfp'),
                'after_cli_kill': sample.get('after_cli_kill'),
                'firewall_rule_removed': sample.get('firewall_rule_removed'),
                'driver_removed': sample.get('driver_removed'),
            }
            unguarded = sample.get('no_wfp') or {}
            guarded = sample.get('with_wfp') or {}
            if unguarded.get('socks_connects', 0) > 0 and guarded.get('socks_connects') == 0:
                checks['transparent_tcp_redirect_while_wfp_guard_is_active'] = (
                    'FAILED on Windows VM: program WFP block prevented ProxyBridge SOCKS CONNECT'
                )
            other = sample.get('same_name_other') or {}
            if other.get('socks_connects', 0) > 0:
                checks['unprotected_app_network_unchanged'] = (
                    'FAILED on Windows VM: a different executable with the same basename was also redirected'
                )
        except (OSError, ValueError, TypeError, AttributeError) as exc:
            observed = {'error': f'could not read Windows experiment: {exc}'}
    report = {
        "backend": "ProxyBridge/WinDivert + independent WFP",
        "platform": platform.platform(),
        "accepted": False,
        "checks": checks,
        "windows_vm_observations": observed,
        "reason": "No guarded launch is available. A Windows runner unit test is not a physical Windows leak test.",
    }
    path.write_text(json.dumps(report, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
    print(f"::error title=Windows isolation acceptance::BLOCKED; see {path}")
    return 1


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
