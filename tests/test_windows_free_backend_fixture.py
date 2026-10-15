import importlib.util
import os
from pathlib import Path
import tempfile
import time
import unittest


ROOT = Path(__file__).resolve().parent.parent
SPEC = importlib.util.spec_from_file_location("free_backend_fixture", ROOT / ".github/windows_free_backend_fixture.py")
fixture = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(fixture)


class FreeBackendFixtureTests(unittest.TestCase):
    @unittest.skipUnless(os.environ.get("RULEPROXY_TEST_MIHOMO"), "Requires explicitly selected real fixture Mihomo")
    def test_real_mihomo_domain_http_socks_receiver_controls_and_core_loss(self):
        with tempfile.TemporaryDirectory() as directory:
            with fixture.Fixture(Path(os.environ["RULEPROXY_TEST_MIHOMO"]), Path(directory)) as control:
                self.assertTrue(fixture.http_probe(control.spec)["ok"])
                self.assertTrue(fixture.http_probe(control.spec, socks=True)["ok"])
                self.assertTrue(fixture.direct_probe(control.spec)["connected"])
                self.assertTrue(fixture.udp_probe(control.spec, "udp4", "outside_before")["send_ok"])
                deadline = time.monotonic() + 2
                while control.snapshot()["udp4_received"] == 0 and time.monotonic() < deadline:
                    time.sleep(.01)
                counts = control.snapshot()
                self.assertEqual(counts["proxy_requests"], 2)
                self.assertEqual(counts["origin_requests"], 2)
                self.assertEqual(counts["direct_connections"], 1)
                self.assertEqual(counts["udp4_by_role"], {"outside_before": 1})
                self.assertEqual(counts["errors"], [])
                self.assertTrue(control.stop_proxy()["exited"])
                self.assertFalse(fixture.http_probe(control.spec)["ok"])
                self.assertFalse(fixture.http_probe(control.spec, socks=True)["ok"])
                self.assertTrue(fixture.direct_probe(control.spec)["connected"])
            self.assertTrue(all(not thread.is_alive() for thread in control.threads))


if __name__ == "__main__":
    unittest.main()
