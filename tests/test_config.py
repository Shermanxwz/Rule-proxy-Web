import unittest

import yaml

from ruleproxy.config import APP_GROUP, APP_LISTENER, MAX_SOURCE_BYTES, compile_config


class CompileConfigTests(unittest.TestCase):
    def setUp(self):
        self.source = """
proxies:
  - name: Alpha
    type: vless
    server: alpha.example.test
    port: 443
    uuid: 00000000-0000-0000-0000-000000000001
    tls: true
  - name: Beta
    type: vless
    server: beta.example.test
    port: 443
    uuid: 00000000-0000-0000-0000-000000000002
    tls: true
  - name: dns-out
    type: dns
proxy-groups:
  - name: Proxy
    type: select
    proxies: [Beta, DIRECT, Alpha, dns-out]
rules:
  - DOMAIN-SUFFIX,amazon.com,DIRECT
  - AND,((NETWORK,UDP),(DST-PORT,53)),dns-out
  - MATCH,Proxy
"""

    def test_app_listener_and_selector_are_pinned_to_real_proxy_leaf(self):
        result = compile_config(self.source, secret="local-secret", selected_node="Alpha")
        config = result.config
        self.assertEqual(result.primary_group, APP_GROUP)
        self.assertEqual(result.selected_node, "Alpha")
        self.assertEqual(result.nodes, [{"name": "Alpha", "type": "vless"}, {"name": "Beta", "type": "vless"}])
        selector = next(group for group in config["proxy-groups"] if group["name"] == APP_GROUP)
        self.assertEqual(selector["type"], "select")
        self.assertEqual(selector["proxies"], ["Alpha", "Beta"])
        self.assertEqual(selector["default-selected"], "Alpha")
        listener = config["listeners"][0]
        self.assertEqual(listener["name"], APP_LISTENER)
        self.assertEqual(listener["type"], "mixed")
        self.assertEqual(listener["listen"], "127.0.0.1")
        self.assertEqual(listener["proxy"], APP_GROUP)
        self.assertEqual(listener["port"], 10809)
        self.assertFalse(listener["udp"])
        self.assertEqual(config["mixed-port"], 0)
        self.assertEqual(config["allow-lan"], False)
        self.assertEqual(config["bind-address"], "127.0.0.1")
        self.assertEqual(config["mode"], "rule")
        self.assertEqual(config["external-controller"], "127.0.0.1:19097")
        self.assertEqual(config["secret"], "local-secret")
        self.assertEqual(config["tun"], {"enable": False})
        # Imported rules/groups may still contain DIRECT, but this listener's
        # explicit proxy field bypasses them and cannot select those entries.
        self.assertEqual(config["proxy-groups"][0]["proxies"], ["Beta", "DIRECT", "Alpha", "dns-out"])
        self.assertEqual(
            config["rules"],
            [
                "DOMAIN-SUFFIX,amazon.com,DIRECT",
                "AND,((NETWORK,UDP),(DST-PORT,53)),dns-out",
                "MATCH,Proxy",
            ],
        )
        self.assertEqual(yaml.safe_load(result.text), config)

    def test_destination_dns_uses_selected_proxy_doh_and_keeps_ipv6(self):
        result = compile_config(self.source, secret="s")
        dns = result.config["dns"]
        self.assertNotIn("listen", dns)
        self.assertTrue(dns["ipv6"])
        self.assertEqual(dns["nameserver"], [f"https://1.1.1.1/dns-query#{APP_GROUP}"])
        self.assertEqual(dns["proxy-server-nameserver"], ["system"])
        self.assertEqual(dns["default-nameserver"], ["1.1.1.1"])
        self.assertTrue(any("only that server's bootstrap" in item for item in result.warnings))

    def test_imported_dns_is_replaced_without_os_changes(self):
        source = self.source + """
dns:
  enable: false
  listen: 0.0.0.0:53
  ipv6: false
  nameserver: [system]
  enhanced-mode: fake-ip
"""
        result = compile_config(source, secret="s")
        dns = result.config["dns"]
        self.assertNotIn("listen", dns)
        self.assertTrue(dns["ipv6"])
        self.assertEqual(dns["nameserver"], [f"https://1.1.1.1/dns-query#{APP_GROUP}"])
        self.assertTrue(any("Imported DNS settings were replaced" in item for item in result.warnings))

    def test_imported_global_and_tun_settings_are_ignored(self):
        source = self.source + """
port: 7890
socks-port: 7891
redir-port: 7892
tproxy-port: 7893
allow-lan: true
bind-address: '*'
external-controller: 0.0.0.0:9090
secret: imported-secret
tun:
  enable: true
  auto-route: true
sniffer:
  enable: true
ntp:
  enable: true
"""
        config = compile_config(source, secret="fresh-secret").config
        self.assertEqual(config["allow-lan"], False)
        self.assertEqual(config["bind-address"], "127.0.0.1")
        self.assertEqual(config["external-controller"], "127.0.0.1:19097")
        self.assertEqual(config["secret"], "fresh-secret")
        self.assertEqual(config["tun"], {"enable": False})
        self.assertEqual(config["mixed-port"], 0)
        self.assertNotIn("redir-port", config)
        self.assertNotIn("sniffer", config)
        self.assertNotIn("ntp", config)

    def test_imported_listeners_are_replaced_by_generated_app_listener(self):
        source = self.source + """
listeners:
  - name: public
    type: mixed
    listen: 0.0.0.0
    port: 7777
    path: /tmp/socket
"""
        result = compile_config(source, secret="s")
        self.assertEqual(len(result.config["listeners"]), 1)
        self.assertEqual(result.config["listeners"][0]["name"], APP_LISTENER)
        self.assertEqual(result.config["listeners"][0]["listen"], "127.0.0.1")
        self.assertTrue(any("Imported listeners were discarded" in warning for warning in result.warnings))

    def test_providers_are_disabled_in_first_version(self):
        cases = (
            "proxy-providers:\n  nodes:\n    type: http\n    url: https://example.test/nodes.yaml\n",
            "rule-providers:\n  local:\n    type: file\n    path: /tmp/rules.yaml\n",
        )
        for fragment in cases:
            with self.subTest(fragment=fragment), self.assertRaisesRegex(ValueError, "not supported"):
                compile_config(self.source + fragment, secret="s")

    def test_rule_set_requires_disabled_rule_provider_support(self):
        source = self.source.replace("MATCH,Proxy", "RULE-SET,geo,Proxy")
        with self.assertRaisesRegex(ValueError, "RULE-SET rules need rule-providers"):
            compile_config(source, secret="s")

    def test_special_exit_nodes_are_never_selectable(self):
        result = compile_config(self.source, secret="s")
        self.assertNotIn("dns-out", [node["name"] for node in result.nodes])
        selector = result.config["proxy-groups"][-1]
        self.assertNotIn("DIRECT", selector["proxies"])
        self.assertNotIn("dns-out", selector["proxies"])
        only_special = "proxies:\n  - {name: direct-out, type: direct}\n  - {name: dns-out, type: dns}\nrules: [MATCH,DIRECT]\n"
        with self.assertRaisesRegex(ValueError, "at least one supported real proxy node"):
            compile_config(only_special, secret="s")
        with self.assertRaisesRegex(ValueError, "selected_node"):
            compile_config(self.source, secret="s", selected_node="dns-out")

    def test_unknown_protocol_and_local_endpoint_are_rejected(self):
        unknown = self.source.replace("type: vless", "type: plugin-exec", 1)
        with self.assertRaisesRegex(ValueError, "unsupported type"):
            compile_config(unknown, secret="s")
        local = self.source.replace("alpha.example.test", "127.0.0.1", 1)
        with self.assertRaisesRegex(ValueError, "private, reserved, or local"):
            compile_config(local, secret="s")

    def test_official_socks5_protocol_is_accepted(self):
        source = """proxies:
  - name: Socks-Exit
    type: socks5
    server: socks.example.test
    port: 1080
rules:
  - MATCH,DIRECT
"""
        result = compile_config(source, secret="s")
        self.assertEqual(result.nodes, [{"name": "Socks-Exit", "type": "socks5"}])
        for alias in ("socks", "shadowsocks"):
            invalid = source.replace("type: socks5", f"type: {alias}")
            with self.subTest(alias=alias), self.assertRaisesRegex(ValueError, "unsupported type"):
                compile_config(invalid, secret="s")

    def test_proxy_and_group_names_cannot_shadow_builtin_outbounds(self):
        reserved = ("DIRECT", "REJECT", "REJECT-DROP", "PASS", "PASS-RULE", "COMPATIBLE", "GLOBAL")
        for name in reserved:
            proxy = f"""proxies:
  - name: {name}
    type: vless
    server: exit.example.test
    port: 443
    uuid: 00000000-0000-0000-0000-000000000001
"""
            with self.subTest(proxy=name), self.assertRaisesRegex(ValueError, "built-in"):
                compile_config(proxy, secret="s")

            group = self.source.replace("name: Proxy", f"name: {name}")
            with self.subTest(group=name), self.assertRaisesRegex(ValueError, "built-in"):
                compile_config(group, secret="s")

        # The name check is case-insensitive so aliases cannot shadow built-ins.
        with self.assertRaisesRegex(ValueError, "built-in"):
            compile_config(self.source.replace("name: Alpha", "name: direct"), secret="s")

    def test_unvalidated_chains_and_local_socket_controls_are_rejected(self):
        chained = self.source.replace("    tls: true", "    tls: true\n    dialer-proxy: local-hop", 1)
        with self.assertRaisesRegex(ValueError, "chain setting"):
            compile_config(chained, secret="s")
        socket = self.source.replace("    tls: true", "    tls: true\n    socket-path: /tmp/outbound.sock", 1)
        with self.assertRaisesRegex(ValueError, "local/chain setting"):
            compile_config(socket, secret="s")
        local_path = self.source.replace("    tls: true", "    tls: true\n    path: /etc/private-key", 1)
        with self.assertRaisesRegex(ValueError, "local/chain setting"):
            compile_config(local_path, secret="s")
        plugin = self.source.replace("    tls: true", "    tls: true\n    plugin: v2ray-plugin", 1)
        with self.assertRaisesRegex(ValueError, "local/chain setting"):
            compile_config(plugin, secret="s")

    def test_websocket_path_remains_a_transport_path(self):
        source = self.source.replace(
            "    tls: true",
            "    tls: true\n    network: ws\n    ws-opts:\n      path: /tunnel\n      headers:\n        Host: edge.example.test",
            1,
        )
        result = compile_config(source, secret="s")
        self.assertEqual(result.config["proxies"][0]["ws-opts"]["path"], "/tunnel")

    def test_unsupported_script_and_subrule_features_are_rejected(self):
        for fragment in ("script:\n  code: return true\n", "sub-rules: {}\n", "tunnels: []\n"):
            with self.subTest(fragment=fragment), self.assertRaisesRegex(ValueError, "unsupported local/script"):
                compile_config(self.source + fragment, secret="s")
        with self.assertRaisesRegex(ValueError, "SCRIPT or SUB-RULE"):
            compile_config(self.source.replace("MATCH,Proxy", "SCRIPT,abc,Proxy"), secret="s")

    def test_size_ports_and_selection_are_validated(self):
        with self.assertRaisesRegex(ValueError, "2 MiB"):
            compile_config("x" * (MAX_SOURCE_BYTES + 1), secret="s")
        with self.assertRaisesRegex(ValueError, "differ"):
            compile_config(self.source, mixed_port=12345, controller_port=12345, secret="s")
        with self.assertRaisesRegex(ValueError, "selected_node"):
            compile_config(self.source, selected_node="missing", secret="s")

    def test_unsafe_yaml_tags_and_alias_cycles_are_rejected(self):
        with self.assertRaises(ValueError):
            compile_config("!!python/object/apply:os.system ['echo nope']", secret="s")
        with self.assertRaisesRegex(ValueError, "recursive YAML aliases"):
            compile_config("x: &x [*x]\nproxies: []", secret="s")


if __name__ == "__main__":
    unittest.main()
