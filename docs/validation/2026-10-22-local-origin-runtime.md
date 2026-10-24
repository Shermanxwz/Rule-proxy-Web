# 本机 B：AC pipe 到真实 owned origin 首次成功

2026-10-22，源提交 `8a42ced7fcfcf5c506d8fd7c3a2122ba7841e3e3` 在 ordinary Windows 11 `26200.9711` / Python `3.12.10` 首次运行通过。实现、manifest 和 Python source closure 由[版本绑定摘要](../../verification/windows-2026-10-22/local-origin-01-summary.json)固定；[只读 preflight](../../verification/windows-2026-10-22/local-origin-01-preflight.json)与[闭合公开结果](../../verification/windows-2026-10-22/local-origin-01-public.json)保留原始结果。native ABI、编译历史和纯测试见[实现说明](2026-10-22-native-fixed-origin-http.md)。

真实执行链为 zero-cap AC frontend → 48-byte anonymous pipe → ordinary native relay → 独立 ordinary native origin，仅使用数字 `127.0.0.1` 和新鲜高端口。relay 实际发出 95 字节固定 GET，半关闭发送；origin 独立核对精确 nonce/request/EOF 后返回 90 字节 canonical response。relay 核对精确 response 与真实 EOF。两端端口元组反向绑定，三进程 held identity/image、独立报告、Job、退出、socket/pipe/handle 清理、精确 ACE 移除、profile 删除均通过。

入口仍默认只读；实际运行通过 `.github/windows_identity_proxy_origin_probe.py --run-local-origin-pair --approved-local-security-test`，并提供固定 actor/manifest、二者 SHA256、`--work-parent` 和 device/source/artifact 绑定的私有 recovery plan。入口从同一原始 QPC 截止分配准备、运行、报告和清理，不重置计时。guard 在创建 controller 时通过 JOB_LIST 原子附加，第三 origin 使用同一 held ledger 并纳入统一清理。公开 JSON 不含 raw PID、SID、端口、nonce、设备名称或本机路径；私有目录在已核验清理后仍保留。没有全局网络设置或防火墙规则变更。

frontend 请求与客户端 sink 仍由 native 内部生成；pipe 不转发任意应用字节。该结果仅验收固定 relay→owned origin transport。`network_tested=true`，`selected_application_tested=false`、`proxy_tested=false`、`product_acceptance=false`。真实 selected 客户端、身份绑定代理入口、OS direct 拒绝、错误 peer/port、代理死亡、DNS/UDP/IPv6/后代/broker/浏览器均须继续独立验证。原 Stage0 的历史失败保持不变。

运行前已通过 22 项 B Python 测试、4 项 native pure 测试中的 390 个 compiled fake transport 场景，以及 77 项默认 A 回归，均零失败、零错误、零跳过。首次真实运行没有失败后重试；编译失败与旧编译版本仍在 compile/pure 归档保留。
