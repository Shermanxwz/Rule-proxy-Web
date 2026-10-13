import unittest

from ruleproxy.proxybridge_candidate import candidate_profile, candidate_status


class CandidateProfileTests(unittest.TestCase):
    def test_profile_targets_only_the_local_mihomo_listener(self):
        profile = candidate_profile([r"C:\Program Files\Mozilla Firefox\firefox.exe"], 10809)
        self.assertEqual(profile["ProxyConfigs"], [{
            "Id": 1, "Type": "socks5", "Host": "127.0.0.1", "Port": "10809",
            "Username": "", "Password": "", "SendDomainToProxy": True,
        }])
        self.assertFalse(profile["LocalhostViaProxy"])
        self.assertEqual([(rule["ProcessName"], rule["Protocol"], rule["Action"])
                          for rule in profile["ProxyRules"]], [
            ("firefox.exe", "TCP", "PROXY"), ("firefox.exe", "UDP", "BLOCK"),
        ])
        self.assertTrue(all(rule["IsEnabled"] and rule["TargetHosts"] == "*"
                            for rule in profile["ProxyRules"]))

    def test_explicit_children_get_rules_but_no_implicit_inheritance_is_claimed(self):
        profile = candidate_profile([r"C:\Apps\app.exe", r"C:\Apps\helper.exe"], 10809)
        self.assertEqual(len(profile["ProxyRules"]), 4)
        self.assertEqual({rule["ProcessName"] for rule in profile["ProxyRules"]},
                         {"app.exe", "helper.exe"})

    def test_invalid_scope_and_ports_are_rejected(self):
        cases = [
            ([], 10809), ([r"C:\Apps\app.exe"], 0),
            ([r"C:\Apps\app.exe"], True), ([r"C:\Apps\app.exe"], 65536),
            (["app.exe"], 10809), ([r"C:\Apps\*.exe"], 10809),
            ([r"\\server\share\app.exe"], 10809),
            ([r"C:\Apps\mihomo.exe"], 10809),
            ([r"C:\A\app.exe", r"D:\B\APP.EXE"], 10809),
            ([r"C:\A\app.exe"] * 129, 10809),
        ]
        for paths, port in cases:
            with self.subTest(paths=paths, port=port), self.assertRaises(ValueError):
                candidate_profile(paths, port)

    def test_candidate_cannot_claim_runtime_support(self):
        status = candidate_status()
        self.assertFalse(status["supported"])
        self.assertIsNone(status["backend"])
        self.assertIn("未启用", status["detail"])


if __name__ == "__main__":
    unittest.main()
