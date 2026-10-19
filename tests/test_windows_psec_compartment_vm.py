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
            "official_update": {"status": "completed", "completed": True, "packages_verified": True,
                                "task_unregistered": True, "reboot_required": False,
                                "actual_build": 26200, "actual_ubr": 9711},
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

    def test_unserviced_or_pending_reboot_guest_cannot_pass(self):
        for field, value in (("completed", False), ("packages_verified", False),
                             ("task_unregistered", False), ("reboot_required", True),
                             ("actual_ubr", 6584)):
            changed = result()
            changed["official_update"][field] = value
            with self.subTest(field=field), self.assertRaises(RuntimeError):
                self.verify(changed)

    def test_fixed_26h2_profile_requires_matching_installed_os_and_probe(self):
        value = result()
        value.pop("official_update")
        value["os"].update(build=26300, ubr=9457)
        value["reports"]["psec_smoke"]["os"].update(build=26300, ubr=9457)
        value["install_media"] = {"profile": "26h2", "iso_sha256": vm.PSEC_26H2_MEDIA["sha256"],
                                  "actual_build": 26300, "actual_ubr": 9457}
        def verify(candidate):
            return vm.verify_psec_smoke_result(candidate, package_sha256="b" * 64,
                                              source_commit="a" * 40, psec_media="26h2")
        self.assertFalse(verify(value)["product_acceptance"])
        # A newer build with a lower revision is a separately pinned baseline,
        # not an exception that permits any unserviced or self-declared build.
        for mutation in ("hash", "build", "revision", "receipt", "update", "probe", "actor"):
            changed = copy.deepcopy(value)
            if mutation == "hash":
                changed["install_media"]["iso_sha256"] = "c" * 64
            elif mutation == "build":
                changed["os"]["build"] = 26200
            elif mutation == "revision":
                changed["install_media"]["actual_ubr"] = 9456
            elif mutation == "receipt":
                changed.pop("install_media")
            elif mutation == "update":
                changed["official_update"] = result()["official_update"]
            elif mutation == "probe":
                changed["reports"]["psec_smoke"]["launcher"]["probe"]["tier"] = "appcontainer"
            else:
                changed["reports"]["psec_smoke"]["launcher"].pop("actor")
            with self.subTest(mutation=mutation), self.assertRaises(RuntimeError):
                verify(changed)
        with self.assertRaises(RuntimeError):
            self.verify(value)
        with self.assertRaises(RuntimeError):
            verify(result())

    def test_experimental_media_cannot_change_other_suites(self):
        for suite in ("product", "global-capture", "compartment-lab"):
            selected = vm.selected_install_media(suite, "serviced-25h2")
            self.assertEqual(selected["sha256"], vm.media.ISO_SHA256)
            with self.subTest(suite=suite), self.assertRaises(ValueError):
                vm.selected_install_media(suite, "26h2")
        self.assertEqual(vm.selected_install_media("psec-compartment-smoke", "26h2")["sha256"],
                         vm.PSEC_26H2_MEDIA["sha256"])
        with self.assertRaises(ValueError):
            vm.selected_install_media("psec-compartment-smoke", "unpinned")


if __name__ == "__main__":
    unittest.main()
