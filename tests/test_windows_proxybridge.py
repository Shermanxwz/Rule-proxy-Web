"""Portable contract tests: no claim of real Windows WFP/WinDivert coverage."""
import dataclasses
import unittest

from ruleproxy.windows_proxybridge import (
    FenceReceipt,
    FenceSpec,
    ProtectionError,
    StrictWindowsSession,
    production_probe,
    validate_receipt,
)


def spec():
    return FenceSpec(r"C:\Program Files\Google\Chrome\Application\chrome.exe", "127.0.0.1", 10809)


def receipt(target=None, **changes):
    obj = target or spec()
    fields = dict(
        executable=obj.executable, proxy_host=obj.proxy_host, proxy_port=obj.proxy_port,
        kernel_wfp=True, durable=True, ipv4=True, ipv6=True, tcp=True,
        udp=True, descendants=True, default_deny=True, no_direct_fallback=True,
    )
    fields.update(changes)
    return FenceReceipt(**fields)


class FakeFence:
    def __init__(self, events, returned=None):
        self.events = events
        self.receipt = returned if returned is not None else receipt()
        self.good = True
        self.fail_install = False
        self.fail_release = False
        self.verify_count = 0
        self.fail_verify_at = -1

    def install(self, value):
        self.events.append("fence.install")
        if self.fail_install:
            raise RuntimeError("install failed")
        return self.receipt

    def verify(self, value):
        self.events.append("fence.verify")
        self.verify_count += 1
        return self.good and self.verify_count != self.fail_verify_at

    def release(self, value):
        self.events.append("fence.release")
        if self.fail_release:
            raise RuntimeError("release failed")


class FakeRedirector:
    def __init__(self, events):
        self.events = events
        self.good = True
        self.fail_start = False
        self.fail_stop = False

    def start(self, value):
        self.events.append("redirector.start")
        if self.fail_start:
            raise RuntimeError("start failed")

    def ready(self, value):
        self.events.append("redirector.ready")
        return self.good

    def stop(self):
        self.events.append("redirector.stop")
        if self.fail_stop:
            raise RuntimeError("stop failed")


class FakeProcess:
    def __init__(self, events):
        self.events = events
        self.alive = True
        self.can_stop = True

    def poll(self):
        return None if self.alive else 0

    def terminate_tree_and_verify(self):
        self.events.append("process.terminate_tree")
        if self.can_stop:
            self.alive = False
        return self.can_stop


class StrictWindowsSessionTests(unittest.TestCase):
    def setUp(self):
        self.events = []
        self.fence = FakeFence(self.events)
        self.redirector = FakeRedirector(self.events)
        self.process = FakeProcess(self.events)
        self.spawn_count = 0

        def spawn():
            self.events.append("process.spawn")
            self.spawn_count += 1
            return self.process

        self.spawn = spawn
        self.session = StrictWindowsSession(spec(), self.fence, self.redirector, spawn)

    def test_strict_order_and_clean_stop(self):
        self.assertIs(self.session.start(), self.process)
        self.assertEqual(self.events[:7], [
            "fence.install", "fence.verify", "redirector.start", "redirector.ready",
            "fence.verify", "process.spawn", "fence.verify",
        ])
        self.session.stop()
        self.assertLess(self.events.index("process.terminate_tree"), self.events.index("redirector.stop"))
        self.assertLess(self.events.index("redirector.stop"), self.events.index("fence.release"))
        self.assertTrue(self.session.closed)
        self.session.stop()
        self.assertEqual(self.events.count("fence.release"), 1)

    def test_no_redirector_or_process_when_fence_install_fails(self):
        self.fence.fail_install = True
        with self.assertRaises(ProtectionError):
            self.session.start()
        self.assertEqual(self.events, ["fence.install"])
        self.assertEqual(self.spawn_count, 0)

    def test_unverified_fence_never_starts_redirector(self):
        self.fence.good = False
        with self.assertRaises(ProtectionError):
            self.session.start()
        self.assertEqual(self.events, ["fence.install", "fence.verify"])
        self.assertIsNotNone(self.session.receipt)
        self.assertEqual(self.spawn_count, 0)
        self.assertNotIn("fence.release", self.events)

    def test_each_missing_security_property_is_rejected_before_app_spawn(self):
        for field in (
            "kernel_wfp", "durable", "ipv4", "ipv6", "tcp", "udp",
            "descendants", "default_deny", "no_direct_fallback",
        ):
            with self.subTest(field=field):
                events = []
                session = StrictWindowsSession(
                    spec(), FakeFence(events, dataclasses.replace(receipt(), **{field: False})),
                    FakeRedirector(events), lambda: self.fail("spawner must never run"),
                )
                with self.assertRaises(ProtectionError):
                    session.start()
                self.assertEqual(events, ["fence.install"])

    def test_mismatched_executable_or_port_deny_app_launch(self):
        for override in (
            {"executable": r"C:\other.exe"},
            {"proxy_host": "::1"},
            {"proxy_port": 10810},
        ):
            with self.subTest(override=override):
                events = []
                session = StrictWindowsSession(
                    spec(), FakeFence(events, receipt(**override)),
                    FakeRedirector(events), lambda: self.fail("spawner must never run"),
                )
                with self.assertRaises(ProtectionError):
                    session.start()
                self.assertEqual(events, ["fence.install"])

    def test_redirection_start_failure_keeps_kernel_fence(self):
        self.redirector.fail_start = True
        with self.assertRaises(ProtectionError):
            self.session.start()
        self.assertEqual(self.spawn_count, 0)
        self.assertIn("redirector.stop", self.events)
        self.assertNotIn("fence.release", self.events)

    def test_redirection_not_ready_keeps_kernel_fence(self):
        self.redirector.good = False
        with self.assertRaises(ProtectionError):
            self.session.start()
        self.assertEqual(self.spawn_count, 0)
        self.assertNotIn("fence.release", self.events)

    def test_process_spawn_failure_keeps_kernel_fence(self):
        self.session.spawn = lambda: (_ for _ in ()).throw(RuntimeError("spawn failed"))
        with self.assertRaises(ProtectionError):
            self.session.start()
        self.assertNotIn("fence.release", self.events)

    def test_verification_after_spawn_failure_kills_app_and_keeps_fence(self):
        self.fence.fail_verify_at = 3
        with self.assertRaises(ProtectionError):
            self.session.start()
        self.assertEqual(self.spawn_count, 1)
        self.assertIn("process.terminate_tree", self.events)
        self.assertFalse(self.process.alive)
        self.assertIsNotNone(self.session.receipt)
        self.assertNotIn("fence.release", self.events)

    def test_failed_termination_does_not_stop_redirector_or_release_fence(self):
        self.session.start()
        self.process.can_stop = False
        with self.assertRaises(ProtectionError):
            self.session.stop()
        self.assertNotIn("redirector.stop", self.events)
        self.assertNotIn("fence.release", self.events)

    def test_failed_redirector_stop_does_not_release_fence(self):
        self.session.start()
        self.redirector.fail_stop = True
        with self.assertRaises(ProtectionError):
            self.session.stop()
        self.assertNotIn("fence.release", self.events)

    def test_fence_verification_failure_during_stop_kills_owned_app_and_blocks_release(self):
        self.session.start()
        self.fence.good = False
        with self.assertRaises(ProtectionError):
            self.session.stop()
        self.assertIn("process.terminate_tree", self.events)
        self.assertFalse(self.process.alive)
        self.assertNotIn("fence.release", self.events)

    def test_release_failure_keeps_receipt_for_recovery(self):
        self.session.start()
        self.fence.fail_release = True
        with self.assertRaises(ProtectionError):
            self.session.stop()
        self.assertIsNotNone(self.session.receipt)
        self.assertFalse(self.session.closed)

    def test_duplicate_start_rejected(self):
        self.session.start()
        with self.assertRaises(ProtectionError):
            self.session.start()
        self.assertEqual(self.spawn_count, 1)

    def test_process_exited_can_cleanup_only_after_descendant_proof(self):
        self.session.start()
        self.process.alive = False
        self.session.stop()
        self.assertIn("process.terminate_tree", self.events)
        self.assertIn("fence.release", self.events)

    def test_parent_exited_but_descendant_unverified_keeps_fence(self):
        self.session.start()
        self.process.alive = False
        self.process.can_stop = False
        with self.assertRaises(ProtectionError):
            self.session.stop()
        self.assertNotIn("fence.release", self.events)

    def test_bad_proxy_spec_is_rejected(self):
        for host, port in [("0.0.0.0", 10809), ("::1", 10809), ("127.0.0.1", 80), ("127.0.0.1", True)]:
            with self.subTest(host=host, port=port):
                with self.assertRaises(ValueError):
                    FenceSpec(r"C:\app.exe", host, port)
        with self.assertRaises(ValueError):
            FenceSpec("chrome.exe", "127.0.0.1", 10809)

    def test_candidate_is_not_advertised_as_supported(self):
        self.assertIs(production_probe()["supported"], False)
        self.assertIn("not implemented", production_probe()["detail"])


if __name__ == "__main__":
    unittest.main()
