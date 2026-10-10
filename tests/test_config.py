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
        self.assertNotIn("proxy", listener)
        self.assertEqual(listener["port"], 10809)
        self.assertFalse(listener["udp"])
        self.assertEqual(config["mixed-port"], 0)
        self.assertEqual(config["allow-lan"], False)
        self.assertEqual(config["bind-address"], "127.0.0.1")
        self.assertEqual(config["mode"], "rule")
        self.assertEqual(config["external-controller"], "127.0.0.1:19097")
        self.assertEqual(config["secret"], "local-secret")
        self.assertEqual(config["tun"], {"enable": False})
        # Imported group definitions remain available, but every route action
        # goes through the protected selector after rule compilation.
        self.assertEqual(config["proxy-groups"][0]["proxies"], ["Beta", "DIRECT", "Alpha", "dns-out"])
        self.assertEqual(
            config["rules"],
            [
                f"DOMAIN-SUFFIX,amazon.com,{APP_GROUP}",
                f"AND,((NETWORK,UDP),(DST-PORT,53)),{APP_GROUP}",
                f"MATCH,{APP_GROUP}",
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
        self.assertTrue(any("只有解析该服务器地址时使用系统 DNS" in item for item in result.warnings))

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
        self.assertTrue(any("导入的 DNS 设置已替换" in item for item in result.warnings))

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
        self.assertTrue(any("导入的监听器已丢弃" in warning for warning in result.warnings))

    def test_providers_are_disabled_in_first_version(self):
        cases = (
            "proxy-providers:\n  nodes:\n    type: http\n    url: https://example.test/nodes.yaml\n",
            "rule-providers:\n  local:\n    type: file\n    path: /tmp/rules.yaml\n",
        )
        for fragment in cases:
            with self.subTest(fragment=fragment), self.assertRaisesRegex(ValueError, "此版本不支持"):
                compile_config(self.source + fragment, secret="s")

    def test_rule_set_requires_disabled_rule_provider_support(self):
        source = self.source.replace("MATCH,Proxy", "RULE-SET,geo,Proxy")
        with self.assertRaisesRegex(ValueError, "RULE-SET 规则需要 rule-providers"):
            compile_config(source, secret="s")

    def test_rule_actions_are_rewritten_but_reject_and_no_resolve_are_preserved(self):
        source = self.source.replace(
            "  - DOMAIN-SUFFIX,amazon.com,DIRECT\n  - AND,((NETWORK,UDP),(DST-PORT,53)),dns-out\n  - MATCH,Proxy",
            "  - DOMAIN-SUFFIX,amazon.com,DIRECT\n"
            "  - IP-CIDR,192.0.2.0/24,Proxy,no-resolve\n"
            "  - IP-CIDR6,2001:db8::/32,Alpha,no-resolve\n"
            "  - DOMAIN,blocked.example,REJECT\n"
            "  - DOMAIN,blocked-too.example,REJECT-DROP\n"
            "  - DOMAIN,passed.example,PASS\n"
            "  - MATCH,Proxy",
        )
        result = compile_config(source, secret="s")
        self.assertEqual(
            result.config["rules"],
            [
                f"DOMAIN-SUFFIX,amazon.com,{APP_GROUP}",
                f"IP-CIDR,192.0.2.0/24,{APP_GROUP},no-resolve",
                f"IP-CIDR6,2001:db8::/32,{APP_GROUP},no-resolve",
                "DOMAIN,blocked.example,REJECT",
                "DOMAIN,blocked-too.example,REJECT-DROP",
                f"DOMAIN,passed.example,{APP_GROUP}",
                f"MATCH,{APP_GROUP}",
            ],
        )

    def test_missing_match_gets_proxy_match_and_reject_match_stays_blocked(self):
        source = self.source.replace("  - MATCH,Proxy\n", "")
        result = compile_config(source, secret="s")
        self.assertEqual(result.config["rules"][-1], f"MATCH,{APP_GROUP}")

        source = self.source.replace("  - MATCH,Proxy", "  - MATCH,REJECT")
        result = compile_config(source, secret="s")
        self.assertEqual(result.config["rules"][-1], "MATCH,REJECT")

    def test_process_identity_and_unparseable_rules_are_rejected(self):
        for rule in (
            "PROCESS-NAME,chrome.exe,DIRECT",
            "PROCESS-PATH,/usr/bin/browser,Proxy",
            "PROCESS-NAME-REGEX,.*browser.*,Proxy",
            "UID,1000,DIRECT",
        ):
            with self.subTest(rule=rule), self.assertRaisesRegex(ValueError, "无法识别原始应用"):
                compile_config(self.source.replace("MATCH,Proxy", rule), secret="s")
        for rule in (
            "SOMETHING-NEW,payload,DIRECT",
            "DOMAIN-SUFFIX,example.com",
            "IP-CIDR,192.0.2.0/24,DIRECT,unknown-option",
            "AND,((NETWORK,UDP),(DST-PORT,53),Proxy",
        ):
            with self.subTest(rule=rule), self.assertRaises(ValueError):
                compile_config(self.source.replace("MATCH,Proxy", rule), secret="s")

    def test_special_exit_nodes_are_never_selectable(self):
        result = compile_config(self.source, secret="s")
        self.assertNotIn("dns-out", [node["name"] for node in result.nodes])
        selector = result.config["proxy-groups"][-1]
        self.assertNotIn("DIRECT", selector["proxies"])
        self.assertNotIn("dns-out", selector["proxies"])
        only_special = "proxies:\n  - {name: direct-out, type: direct}\n  - {name: dns-out, type: dns}\nrules: [MATCH,DIRECT]\n"
        with self.assertRaisesRegex(ValueError, "至少需要一个受支持的真实代理节点"):
            compile_config(only_special, secret="s")
        with self.assertRaisesRegex(ValueError, "所选节点"):
            compile_config(self.source, secret="s", selected_node="dns-out")

    def test_unknown_protocol_and_local_endpoint_are_rejected(self):
        unknown = self.source.replace("type: vless", "type: plugin-exec", 1)
        with self.assertRaisesRegex(ValueError, "不受支持"):
            compile_config(unknown, secret="s")
        local = self.source.replace("alpha.example.test", "127.0.0.1", 1)
        with self.assertRaisesRegex(ValueError, "私有、保留或本地"):
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
            with self.subTest(alias=alias), self.assertRaisesRegex(ValueError, "不受支持"):
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
            with self.subTest(proxy=name), self.assertRaisesRegex(ValueError, "内置出口"):
                compile_config(proxy, secret="s")

            group = self.source.replace("name: Proxy", f"name: {name}")
            with self.subTest(group=name), self.assertRaisesRegex(ValueError, "内置出口"):
                compile_config(group, secret="s")

        # The name check is case-insensitive so aliases cannot shadow built-ins.
        with self.assertRaisesRegex(ValueError, "内置出口"):
            compile_config(self.source.replace("name: Alpha", "name: direct"), secret="s")

    def test_unvalidated_chains_and_local_socket_controls_are_rejected(self):
        chained = self.source.replace("    tls: true", "    tls: true\n    dialer-proxy: local-hop", 1)
        with self.assertRaisesRegex(ValueError, "本地或链式设置"):
            compile_config(chained, secret="s")
        socket = self.source.replace("    tls: true", "    tls: true\n    socket-path: /tmp/outbound.sock", 1)
        with self.assertRaisesRegex(ValueError, "本地或链式设置"):
            compile_config(socket, secret="s")
        local_path = self.source.replace("    tls: true", "    tls: true\n    path: /etc/private-key", 1)
        with self.assertRaisesRegex(ValueError, "本地或链式设置"):
            compile_config(local_path, secret="s")
        plugin = self.source.replace("    tls: true", "    tls: true\n    plugin: v2ray-plugin", 1)
        with self.assertRaisesRegex(ValueError, "本地或链式设置"):
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
            with self.subTest(fragment=fragment), self.assertRaisesRegex(ValueError, "不支持的本地或脚本功能"):
                compile_config(self.source + fragment, secret="s")
        with self.assertRaisesRegex(ValueError, "SCRIPT 或 SUB-RULE"):
            compile_config(self.source.replace("MATCH,Proxy", "SCRIPT,abc,Proxy"), secret="s")

    def test_size_ports_and_selection_are_validated(self):
        with self.assertRaisesRegex(ValueError, "2 MiB"):
            compile_config("x" * (MAX_SOURCE_BYTES + 1), secret="s")
        with self.assertRaisesRegex(ValueError, "differ"):
            compile_config(self.source, mixed_port=12345, controller_port=12345, secret="s")
        with self.assertRaisesRegex(ValueError, "所选节点"):
            compile_config(self.source, selected_node="missing", secret="s")

    def test_unsafe_yaml_tags_and_alias_cycles_are_rejected(self):
        with self.assertRaises(ValueError):
            compile_config("!!python/object/apply:os.system ['echo nope']", secret="s")
        with self.assertRaisesRegex(ValueError, "递归引用的 YAML 别名"):
            compile_config("x: &x [*x]\nproxies: []", secret="s")


if __name__ == "__main__":
    unittest.main()
