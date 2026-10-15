import json
import unittest

from ruleproxy import windows_proxy_policy as policy


class PolicyTests(unittest.TestCase):
    def test_explicit_paths_and_loopback_only(self):
        value = policy.build_policy([r"C:\Apps\Tool.exe", r"c:\apps\tool.exe"], 10809)
        self.assertEqual(value["proxies"][0]["appNames"], [r"C:\Apps\Tool.exe"])
        self.assertEqual(value["proxies"][0]["socks5ProxyEndpoint"], "127.0.0.1:10809")
        self.assertEqual(value["proxies"][0]["supportedProtocols"], ["TCP", "UDP"])
        self.assertEqual(value["excludes"], [])

    def test_reject_ambiguous_or_sensitive_targets(self):
        for target in ("", "tool.exe", r"C:\Apps\*.exe", r"\\server\x.exe", r"C:\Apps\..\x.exe",
                       r"C:\Apps\svchost.exe", r"C:\Windows\System32\services.exe",
                       r"C:\Program Files\RuleProxy-Web\python\python.exe",
                       r"C:\Program Files\ProxiFyre\ProxiFyre.exe", r"C:\Apps\x.exe:evil.exe"):
            with self.subTest(target=target), self.assertRaises(policy.ProxyError):
                policy.build_policy([target], 10809)

    def test_native_curl_is_selectable(self):
        policy.build_policy([r"C:\Windows\System32\curl.exe"], 10809)

    def test_request_allowlist_and_duplicate_keys(self):
        base = {"schema_version": 1, "request_id": "a" * 32, "op": "status", "client_pid": 100}
        self.assertEqual(policy.decode_request(json.dumps(base).encode()), base)
        for value in ({**base, "command": "whoami"}, {**base, "op": "exec"}, {**base, "client_pid": True}):
            with self.assertRaises(policy.ProxyError):
                policy.decode_request(json.dumps(value).encode())
        with self.assertRaises(policy.ProxyError):
            policy.decode_request(b'{"op":"status","op":"stop"}')
        with self.assertRaises(policy.ProxyError):
            policy.decode_request(b"x" * (policy.MAX_MESSAGE + 1))

    def test_pipe_is_bound_to_owner_sid(self):
        self.assertNotEqual(policy.pipe_name("S-1-5-21-1-2-3-1000"), policy.pipe_name("S-1-5-21-1-2-3-1001"))


if __name__ == "__main__":
    unittest.main()
