"""The host must not turn a functional smoke into privacy/product acceptance."""
import copy
import importlib.util
from pathlib import Path
import tempfile
import unittest

from ruleproxy import windows_runtime_pins as pins

ROOT = Path(__file__).resolve().parents[1]


def load(name, path):
    spec = importlib.util.spec_from_file_location(name, path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


vm = load("psec_vm", ROOT / ".github/windows_proxifyre_vm.py")
fixtures = load("psec_test_fixtures", ROOT / "tests/test_windows_psec_compartment_smoke.py")


def result():
    report = fixtures.passing_report()
    report.update(source_commit="a" * 40, functionality_passed=True,
                  privacy_qualified=False, product_acceptance=False,
                  os={"architecture": "AMD64", "python_pointer_bits": 64, "build": 26200, "ubr": 9711},
                  provenance={"executor_sha256": pins.MXC_G_EXECUTOR_SHA256,
                              "upstream_commit": pins.MXC_G_BUILD_MANIFEST["upstream_commit"],
                              "g_patch_applies_to_model2": False})
    report["checks"] = fixtures.smoke.checks(report)
    return {"suite": "psec-compartment-smoke", "status": "passed", "exit_code": 0,
            "package_sha256": "b" * 64, "reports": {"psec_smoke": report},
            "os": {"product_type": "WinNT", "native_architecture": "AMD64", "build": 26200, "ubr": 9711}}


class PsecVmTests(unittest.TestCase):
    def verify(self, value):
        return vm.verify_psec_smoke_result(value, package_sha256="b" * 64, source_commit="a" * 40)

    def test_functionality_does_not_establish_privacy_or_product_acceptance(self):
        report = self.verify(result())
        self.assertFalse(report["privacy_qualified"])
        self.assertFalse(report["product_acceptance"])
        for key in ("privacy_qualified", "product_acceptance"):
            for value in (None, True, 0):
                changed = result()
                changed["reports"]["psec_smoke"][key] = value
                with self.subTest(key=key, value=value), self.assertRaises(RuntimeError):
                    self.verify(changed)

    def test_stale_success_flags_do_not_hide_failed_observations(self):
        original = result()
        for mutation in ("cid", "source", "browser", "executor", "cleanup"):
            changed = copy.deepcopy(original)
            report = changed["reports"]["psec_smoke"]
            if mutation == "cid":
                report["launcher"]["actor"]["identity"]["cid"] = 1
            elif mutation == "source":
                report["source_commit"] = "c" * 40
            elif mutation == "browser":
                report["launcher"]["actor"]["browser"]["dom_marker_matched"] = False
            elif mutation == "executor":
                report["provenance"]["executor_sha256"] = "c" * 64
            else:
                report["cleanup"]["account"]["profile_deleted"] = False
            with self.subTest(mutation=mutation), self.assertRaises(RuntimeError):
                self.verify(changed)

    def test_mismatched_psec_bundle_is_rejected_before_payload_creation(self):
        with tempfile.TemporaryDirectory() as temporary:
            directory = Path(temporary)
            package, bundle, destination = [directory / name for name in ("package.zip", "bundle.zip", "payload.zip")]
            package.write_bytes(b"placeholder")
            bundle.write_bytes(b"unverified runtime")
            with self.assertRaises(ValueError):
                vm.make_payload(package, destination, psec_bundle=bundle)
            self.assertFalse(destination.exists())


if __name__ == "__main__":
    unittest.main()
