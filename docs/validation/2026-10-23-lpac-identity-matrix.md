# AC/LPAC 身份授权对照：首次本机观察通过

**独立身份对照通过，DNS 尚未调用。** 本轮在同一个 fresh AppContainer profile 下创建 AC 与 LPAC 两个进程，始终保持暂停。四组内存授权描述符的 AccessCheck 结果分别符合预声明矩阵；进程、Job、句柄、专用 ACE 和 profile 全部自动清理完成。该结果不改写 [class46 查询错误 87](2026-10-23-lpac-token-inspection.md)，也没有抵消 [G/PSEC 的 DNS API 泄漏](2026-10-23-selected-dns-standard53.md)。

受测源码为 `ff08ccab07d0b07a5d7ef77e0e2c834858f73793`；34 文件运行时闭包为 `c4b7bd94a98cb81a71b2f45a1660f216a2d0025037628238cc81edd07aa276f8`。原 [public](../../verification/windows-2026-10-22/lpac-identity-local-01-public.json) 为 1571 字节，SHA256 `86bf9b51fa2160c9ab54f7370fcb135b5f65b1d3772c580c47cd2643e394a7f8`，状态为 `observed`、`observation_complete=true`、`recovery_required=false`。

两臂使用相同 profile SID、精确 AgenticAppContainer 与 privateNetworkClientServer capabilities（均为 attributes 4）、原 native07 映像、单参数命令行、工作目录、两键环境及原子 Job 构造，仅 ALL_APPLICATION_PACKAGES_POLICY 的 DWORD 为 0/1。原始 owner 独立持有 QUERY token，读取完整身份、capabilities 与 TokenStatistics，再由独立观察器重新打开 QUERY|DUP token、复制为 Identification impersonation token。没有向进程或线程安装 impersonation 身份。观察前后均重新检查代际、映像、两层 Job 和原始 token 绑定。

| 内存描述符（World 允许 3） | AC 授权 mask | LPAC 授权 mask |
| --- | --- | --- |
| 加 AAP 允许 1、ARAP 允许 2 | 3 | 2 |
| 仅 World | 0 | 0 |
| 加 AAP 允许 1 | 1 | 0 |
| 加 ARAP 允许 2 | 2 | 2 |

八次 AccessCheck API 本身均成功，privilege count 均为 0。mask 0 对应成功调用后的 `AccessStatus=false`，不是把 API 错误转成拒绝。每个描述符都核对 owner/group、控制位、ACE 类型、顺序、mask、SID 与内存边界；每个复制 token 和描述符都确认关闭。combined 描述符以固定 [Chromium CheckLpacToken](https://github.com/chromium/chromium/blob/fedbb89ecd801ed0ad1d34eb5784c3bb03a8534e/sandbox/win/src/app_container_test.cc#L109) 为参考，其余三项是本项目的预声明控制。这是一项有限授权语义观察，不是 Microsoft 专用 IsLPAC 查询契约的替代保证。

两个 actor 从未恢复线程，没有 native READY、GO、socket、DNS receiver、库存或 DNS API。所有者停止专用 Job 后，两个暂停进程均确认退出 1；三个普通 ACL 工具经过持有身份、映像及双 Job 准入后自然退出 0。随后精确删除本轮 SID 的 ACE、全树读回确认不存在、删除 fresh profile 并释放 SID。原 root 120 秒、worker 115 秒以及清理 reserve 均未延长；没有独立恢复或自动重试。

[证据索引](../../verification/windows-2026-10-22/lpac-identity-local-01-evidence-index.json)和[组件投影](../../verification/windows-2026-10-22/lpac-identity-local-01-component-projection.json)逐字节核对 34 份 staged 源码与受测 Git blob、9 个 native source pins、13 个 manifest 字段、原报告、两份授权 proof、意图及 stdio。归档仅做读取、纯验证及脱敏复制。outer 持有准入、退出及清理事实来自原 source-bound public checks；原入口没有另存一份 outer launch ledger，归档没有伪造该 ledger 以声称重新执行过 kernel 检查。

单独的 after 配置快照为 7378 字节、SHA256 `f05d91ee76ee8a97ae5ab3bfa092167a8ee560c083255f142e6c453f2edf7ab3`，与最初 baseline 字节相同。比较范围为 firewall profiles、DNS、routes、user proxy；不含 NRPT，也不是整段运行期间所有系统状态的连续审计。本轮没有网络配置或全局权限修改。

47 项候选纯测试通过；完整身份相关纯测试为 804 项、37.816 秒、零失败，2 项原有本机 symlink skips。受测源码的[自动 CI](https://github.com/Shermanxwz/Rule-proxy-Web/actions/runs/39863618110)为 804 项、39.418 秒、零 skips；5–9 号 gated runtime steps 均跳过，基础 actor 仅编译，没有执行本轮身份实验或 DNS。

下一步是新的独立 semantic-LPAC DNS 入口：每次恢复或发布 GO 前重新验证同一 held token 的授权矩阵，并完成标准 53 库存、普通同 API 前后正控及明确拒绝/泄漏判读。原 class46 入口继续错误即停止。当前 `dns_isolation_qualified`、`g_psec_tested`、`proxy_tested`、`product_acceptance` 仍为 false；LPAC 与 PSEC 代理链组合、默认 resolver 和 Linux 等效边界尚未验证。
