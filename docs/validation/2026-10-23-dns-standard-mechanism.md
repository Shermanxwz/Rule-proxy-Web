# Windows ordinary DNS 同 API 机制：2026-10-23

`dns-standard-local-02` 已完成真实 `DnsQueryEx` VERSION1 同步调用与专用接收端的查询、答案核对。该结果解决 ordinary 调用机制，不代表 selected 应用、默认 resolver、系统 broker、DNS 隔离或产品验收通过。历史 REQUEST3 与高端口 VERSION1 的失败结果保留，未重写。

受测提交为 `21cbfe2ee466ea4ec0f6237ae29a8509ef13f618`，15 文件源码闭包为 `5206fd171b4fc7c44717d71a5dc654ca47a80c59d93df9e314c915b253532d9f`。原生构造固定为 `official-v1-zero-port`：单个 DNS server 的 sockaddr 为 numeric IPv4 loopback，端口留零；不提供高端口参数、不改系统 DNS、不回退到默认 resolver。实际监听由所有者在普通身份下短暂独占 `127.0.0.1:53/UDP`，只回答本次新鲜 nonce 的 `.n0a.invalid` 查询。

监听前先持有、监督普通 PowerShell 只读检查，枚举 DNS server、有效 NRPT、UDP/TCP 的 53 端口占用。任意 loopback DNS（含 IPv4-mapped IPv6）、任意有效 NRPT、端口已占、查询未知或证据超过 5 秒均停止，不创建接收端或运行 native caller。拒绝所有非空有效 NRPT 是保守门，不声称每条策略均匹配测试 namespace。实际 bind 前和持有 native 线程 resume 前均重新验证原快照新鲜度。

实际结果见[公开报告](../../verification/windows-2026-10-22/dns-standard-local-02-public.json)及[独立安全投影](../../verification/windows-2026-10-22/dns-standard-local-02-component-projection.json)：API status 和 query status 均为 0，返回一个名称、类型和地址均匹配的记录，记录内存已释放，未出现 pending，调用在原 deadline 内。独立接收端看到一条匹配查询、成功发送一个答案，拒绝与发送失败均为零；实际收到 62 字节查询，该值是接收观察下界。所有 identity、原 QPC、held process/Job、接收线程与 socket 清理检查为 true，无需恢复。

`dns-standard-local-01` 在 staging 阶段停止，尚未产生 config、guard、inventory 或 native 调用。旧时钟检查沿用了 uint32 上限，本机 QPC ticks 已大于该值；这是代码与保留树支持的根因推断，原失败报告未包含异常详情。独立修复将时钟限制为 signed 64-bit，并增加真实长 uptime 范围的回归测试。新尝试保留原 120 秒根 deadline、原监督入口及清理保留，未放宽超时。

[证据索引](../../verification/windows-2026-10-22/dns-standard-local-01-02-evidence-index.json)绑定两次原 preflight/public、逐字节 runner、摘要与脱敏投影。归档分别核对 15 份 staged 源码与各自受测 git blob、编译 manifest 和实际 private worker/native/inventory 输出承诺。02 的 public SHA256 为 `9a72bc097f1842a0656051f59b092600b640b3ed1e5ad60483a4ae301db5d11e`，1864 字节。

[运行后全局只读比较](../../verification/windows-2026-10-22/dns-standard-after02-global-projection.json)与首次本机 baseline 的防火墙 profiles、DNS、路由、用户代理配置 JSON 对象完全一致；此次原始字节亦相同。原始配置、用户/SID/PID、端口元组、路径、机器标识和随机 nonce 没有公开。点时快照相等及 ordinary 机制成功均不能提升 DNS 隔离资格；`selected_application_tested`、`default_resolver_tested`、`broker_cancellation_proven`、`dns_isolation_qualified`、`product_acceptance` 仍为 false。
