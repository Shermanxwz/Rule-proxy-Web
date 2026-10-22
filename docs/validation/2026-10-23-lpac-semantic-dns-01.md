# Semantic-LPAC DNS01：普通前测阳性后因快照接口错误停止

**selected DNS 尚未调用，本轮 inconclusive。** 新独立入口已完成受持有 LPAC token 的授权矩阵准入，成功启动 selected 和普通 health 原生进程。普通 before 的 DnsQueryEx API/query 均为 0，匹配一个 A 记录，受控接收端也记录查询 1、回答 1。随后复用的旧 Owner.execute 调用 `fixture.snapshot()` 漏传必需的 keyword-only `deadline`，出现 TypeError，未进入 selected 或 after 查询。

受测源码为 `ba0954a6496a6ced2c5197d57ebc14155b998753`，35 文件闭包为 `3f5e3fc55043103ab0bcf8144085a936e4374e69d54f3bf83e0c8f5aa7a1987e`。[原 public](../../verification/windows-2026-10-22/lpac-semantic-dns-local-01-public.json) 为 1573 字节，SHA256 `0909bb6ffd4024883f5c2fa2c8ad36e83867be598d6970c6e511aada4e8ef414`。原报告的 ordinary_before 标记尚未赋值，仍为 false；后续只读分析分别保留原生报告和接收端的真实阳性，不把原标记补成 true。

本轮使用已通过[匹配 AC/LPAC 身份实测](2026-10-23-lpac-identity-matrix.md)的四授权矩阵方法。selected 的 owner-held QUERY token 先独立读取完整身份和 TokenStatistics，观察器另开 QUERY|DUP token 并复制为 Identification token。4 次矩阵检查及其资源清理通过，selected 获得 READY 并恢复过线程；没有查询 class46，也没有伪填它的值。原 class46/87 入口源码不变。

[组件投影](../../verification/windows-2026-10-22/lpac-semantic-dns-local-01-component-projection.json)和[证据索引](../../verification/windows-2026-10-22/lpac-semantic-dns-local-01-evidence-index.json)核对受测 Git blob/LF 源码 35 份、native source pins 9 项、manifest 13 个字段、原报告与计划、4 份 semantic 意图和 proof、3 份原生报告、1 个 GO，以及普通所有权意图和 stdio。库存仅通过 bind/before 两个原 5 秒新鲜度门；未发布 selected/after GO。接收端仅有 before 查询，selected 无命中在这里不能算阻断，因为 selected 没有调用 DNS API。

selected 和 health 最终均由专用 Job 清理确认退出 1，不是自然退出成功。四个 grant 工具、库存工具及 remove 工具自然退出 0；fixture socket/thread、工作进程、Job、句柄、精确 SID ACE 和 fresh profile 均自动清理，原 public 的 `recovery_required=false`。无需独立恢复，也没有伪造补测或修改原失败。

独立 after 快照为 7378 字节、SHA256 `f05d91ee76ee8a97ae5ab3bfa092167a8ee560c083255f142e6c453f2edf7ab3`，与最初 baseline 字节相同。快照仅比较 firewall profiles、DNS、routes、user proxy，不含 NRPT；本轮库存另读得 effective NRPT 0。没有更改全局网络配置。

21 项新增纯测试及 825 项身份相关完整纯测试（47.978 秒，2 项原有本机 symlink skips）通过；源码[自动 CI](https://github.com/Shermanxwz/Rule-proxy-Web/actions/runs/39865683458)为 825 项、34.453 秒、零 skips，gated runtime 5–9 均跳过。该接口错误说明原 fake fixture 没有约束真实 `snapshot(*, deadline)` 签名；候选修补需要保留原参数要求并走完整 before/selected/after 流程，不能以这些旧纯测试替代真实执行。

[原 G/PSEC DNS API 泄漏](2026-10-23-selected-dns-standard53.md)仍成立。当前没有 LPAC DNS 明确拒绝结果；默认 resolver、PSEC 代理组合、完整 DNS 隔离和 Linux 等效均未验收。
