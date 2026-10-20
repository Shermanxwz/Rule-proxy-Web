"""Direct exploratory guest source contracts; actual PS execution is a CI gate."""
from pathlib import Path
import unittest
import importlib.util
import re
import contextlib
import io
import json
import sys
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[1]
GITHUB = ROOT / '.github'
RUN = (GITHUB / 'windows-identity-direct-stage0-run.ps1').read_text()
SETUP = (GITHUB / 'windows-identity-direct-stage0-setup.ps1').read_text()
GATE = (GITHUB / 'test-windows-identity-direct-gates.ps1').read_text()


class DirectGuestTests(unittest.TestCase):
    def test_setup_is_existing_stock_semantics(self):
        stock = (GITHUB / 'windows-identity-stock-stage0-setup.ps1').read_text()
        self.assertEqual(SETUP.splitlines()[1:], stock.splitlines()[1:])
        self.assertEqual(SETUP.count('reg.exe add'), 2)
        for forbidden in ('Register-ScheduledTask', 'New-LocalUser', 'RuleProxyCIUpdates'):
            self.assertNotIn(forbidden, SETUP)

    def test_exact_exploratory_build_before_beacon(self):
        beacon = RUN.index('RPBEACON identity-ordinary-ready')
        for item in ("$gates.build_26300=([string]$Facts.build -ceq '26300')",
                     "$gates.ubr_direct=([string]$Facts.ubr -ceq '9457')",
                     "'fixed_drive','build_26300','ubr_direct'", "AddSeconds(120)",
                     "'installed_setup_deadline'", "'IMAGE_STATE_COMPLETE'"):
            self.assertLess(RUN.index(item), beacon)
        self.assertNotIn('-ge 9457', RUN)
        self.assertLess(beacon, RUN.index("$phase='claim'"))
        self.assertEqual(RUN.count('RPBEACON identity-ordinary-ready'), 1)

    def test_same_ordinary_identity_and_no_service(self):
        for marker in ("'RULEPROXY-VM\\RuleProxyCI'", 'WindowsBuiltInRole]::Administrator',
                       'SessionId -le 0', 'StringComparison]::OrdinalIgnoreCase'):
            self.assertIn(marker, RUN)
        for forbidden in ('servicing_verified', 'servicing_diagnostic', 'update-state.json',
                          'Register-ScheduledTask', 'DISM', 'Restart-Computer', 'RuleProxyCIUpdates',
                          '26200', '6584', '9711', 'servicing_wait'):
            self.assertNotIn(forbidden, RUN)

    def test_exploratory_labels_forced_even_after_child_report(self):
        for marker in ("Set-ClosedResultField 'exploratory_stage0' $true",
                       "Set-ClosedResultField 'product_acceptance' $false",
                       "Set-ClosedResultField 'documented_support_floor' '26300.9550'"):
            self.assertGreater(RUN.index(marker), RUN.index('$result = $candidate'))
        self.assertIn('-NotePropertyName direct_build_verified -NotePropertyValue $true', RUN)
        self.assertNotIn("'product_acceptance' $true", RUN)

    def test_unchanged_bounded_extraction_and_payload(self):
        stock = (GITHUB / 'windows-identity-stock-stage0-run.ps1').read_text()
        def extraction(value):
            start = value.index('function Expand-CheckedStage0Zip')
            return value[start:value.index('\ntry {\n    $configuration', start)]
        self.assertEqual(extraction(RUN), extraction(stock))
        self.assertIn('windows_identity_direct_stage0.py', RUN)
        self.assertNotIn('windows_identity_serviced_stage0.py', RUN)
        self.assertIn('-MemberCount 10', RUN)
        self.assertIn('WaitForExit(120000)', RUN)
        self.assertIn('ConvertTo-Json -Depth 10 -Compress', RUN)

    def test_closed_early_wire_and_real_ps_test(self):
        self.assertIn('ASCII.GetByteCount($json) -gt 2048', RUN)
        self.assertIn('if ($failed -and -not $earlyBootGateCompleted)', RUN)
        self.assertIn('windows-identity-direct-stage0-run.ps1', GATE)
        self.assertIn('windows_identity_direct_stage0.py', GATE)
        self.assertNotIn('serviced', GATE)
        self.assertIn("build='26300';ubr=9457", GATE)
        self.assertIn("@('build','26200'),@('ubr',9550)", GATE)
        self.assertIn('Set-StrictMode -Version Latest', GATE)
        self.assertIn('-HResult ([int]-2146233087)', GATE)
        self.assertIn('rows=json.load(wire_file)', GATE)
        self.assertIn('assert len(rows)==11', GATE)
        self.assertIn('runtime_acceptance=$false', GATE)

    def test_early_wire_enum_and_gate_contract_matches_direct_host(self):
        spec = importlib.util.spec_from_file_location('direct_guest_contract_host', GITHUB / 'windows_identity_direct_stage0.py')
        host = importlib.util.module_from_spec(spec); spec.loader.exec_module(host)
        for source, target in (('phases', 'LAUNCHER_PHASES'), ('categories', 'LAUNCHER_FAILURES'), ('operations', 'EARLY_OPERATIONS')):
            values = set(re.findall(r"'([^']+)'", re.search(r'\$' + source + r'=@\((.*?)\)', RUN, re.S).group(1)))
            self.assertTrue(values.issubset(set(getattr(host, target))))
        gates = re.search(r'\$gates=\[ordered\]@\{(.*?)\}', RUN, re.S).group(1)
        self.assertEqual(set(re.findall(r'(\w+)=\$null', gates)), set(host.EARLY_GATES))

    def test_windows_environment_gate_targets_actual_proof_and_deny_policy(self):
        for marker in ('proof.validate_required_environment(valid,native)',
                       'proof.observe_required_environment()',
                       'required_environment=required',
                       'config["process"]["inheritDefaultEnv"] is False',
                       '"hostLoopback":"deny"', '"allowDaclMutation":False',
                       "'windows_identity_proof.py')"):
            self.assertIn(marker, GATE)
        self.assertNotIn('print(observed)', GATE)
        self.assertNotIn('print(native)', GATE)
        self.assertIn('if runner_environment != "validated":\n    raise SystemExit(1)', GATE)

    def test_embedded_python_synthetic_environment_cases_execute(self):
        # Executes real validator/policy with synthetic Windows strings here.
        # Native Windows observation remains diagnostic, not a local CI claim.
        embedded = GATE.split("$parityCode=@'", 1)[1].split("\n'@", 1)[0]
        code = embedded[embedded.index('# Execute the actual proof validator'):]
        output = io.StringIO()
        argv = ['test', '', '', str(GITHUB / 'windows_identity_proof.py')]
        exit_code = 0
        with patch.object(sys, 'argv', argv), contextlib.redirect_stdout(output):
            try:
                exec(compile(code, '<direct-environment-regression>', 'exec'), {'rows':[None]*11, 'sys':sys, 'json':json, 'importlib':__import__('importlib')})
            except SystemExit as exc:
                exit_code = exc.code
        result = json.loads(output.getvalue())
        self.assertEqual(result['synthetic_environment_cases_passed'], 17)
        self.assertTrue(result['deny_only_policy_unchanged'])
        self.assertEqual(result['policy_environment_negatives_passed'], 3)
        self.assertIn(result['runner_environment_error_class'], ('none', 'PermissionError', 'ValueError', 'OSError', 'unclassified'))
        self.assertFalse(result['runtime_acceptance'])
        self.assertIn(result['runner_environment'], ('validated', 'rejected'))
        self.assertEqual(exit_code, 0 if result['runner_environment'] == 'validated' else 1)
        self.assertNotIn('FixtureUser', output.getvalue())
        self.assertNotIn('PRIVATE_SENTINEL', output.getvalue())


if __name__ == '__main__': unittest.main()
