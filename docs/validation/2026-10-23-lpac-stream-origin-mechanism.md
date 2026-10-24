# 零能力 LPAC 经继承流到普通 origin：有限字节传输实测

本轮 Stream01 **完成有限机制传输**，原始状态 observed、failure=null、recovery_required=false。受测提交 [`3d538a89328072186f1db50f5fce7cc39611b44f`](https://github.com/Shermanxwz/Rule-proxy-Web/commit/3d538a89328072186f1db50f5fce7cc39611b44f) 的45文件闭包为 `ccc4008de826faf35eb5c7ea8df47ecdfe54fe0fbf3c31c854d764bbd51899be`。见[原始公报](../../verification/windows-2026-10-22/lpac-stream-origin-local-01-public.json)、[安全汇总](../../verification/windows-2026-10-22/lpac-stream-origin-actual-01/summary.json)和[可审计索引](../../verification/windows-2026-10-22/lpac-stream-origin-actual-01/index.json)。

请求原文件为8193字节、响应原文件为12289字节；每份声明挑战含全部256种字节和 RPS1 标记、越过单帧/窗口边界，并以独立不可预测字节填充，没有向 selected 提供 response 原文件或种子。原始输入及五个物理 sink 均经 held-exit 后读取完整字节、长度和 SHA256 交叉核验；不是仅比较原生自述计数或自述哈希。selected-response、relay-request/response、origin-request/response 五 sink 均精确相同于各自的声明挑战，见[薄载荷收据](../../verification/windows-2026-10-22/lpac-stream-origin-actual-01/payloads.json)。这些 sink 不作为公开载荷另行复制，完整原件在私有证据中保留。

selected 使用 fresh profile SID，能力精确为空，并取得 genuine semantic LPAC 语义证明，外部持有 generation、image、普通用户/session、低完整性和两个 Job；原四描述符 AccessCheck 矩阵为 `[2,0,0,2]`，四次调用和六个 observer 资源均闭合，不查询 class46。普通 relay、独立普通 origin 保持 ordinary 身份。父进程在双方 Resume 前关闭全部四端，每个孩子只继承精确两端；selected 没有获得 socket。三个 actor 均自然退出0，22份 intent、5份原始返回收据、原 outer/worker/forensic 绑定和全部十项作用域清理均由独立 file-only 读取器复核。端口 tuple 是两个受源码/held身份绑定的普通原生报告交叉关系，**不是实时内核 TCP 表观测**。

这是新 RPS1 有限 request-then-response 字节路径，selected 读取真实声明请求文件，将真实响应字节写入 sink；普通 relay 才经 Winsock 与 owned origin 收发。它扩展了此前固定48字节 RPB1 映射的有限实测范围，仍是合作原生适配器。没有透明 socket 语义、持续或并发双工、任意未修改应用、浏览器、真实 Mihomo/core、命名管道获取/恶意同 SID 认证、PSEC/G 支持或 Linux 等效验收。direct、DNS、UDP、IPv6、代理资格及产品验收等广义 flags 均为 false。API错误、超时、缺失或坏报告都不能充当网络拒绝证明。

创建与清理受原 root120/worker115/work85 截止约束；从 pair 创建起的 held身份、矩阵、关闭父端、Resume、传输和自然退出，都消耗同一原 pair10 的 QPC 区间。Low-MIC 仅在 fresh owned selected-report 子树修改，workload/Job/句柄资源闭合后恢复其 mandatory-label ACE absence 并读回；再撤销精确 SID ACE、闭合普通清理工具、删除 fresh profile。这里没有承诺整个旧 SACL 字节恢复或外部 broker 消失。

**本轮** before/after 两份四对象快照均为7645字节、SHA256 `96ba4618bdcee58d28de676038b661681b955502799cdce7aae5fa24d61e8f95`，原字节相同；范围只有 firewall profiles、DNS、routes、user proxy，未包含 NRPT，不能扩张为全部全局配置不变。原始7378字节基线与这两份快照的 routes 仍不一致。此前 IPC01 新增两条 IPv6 /128 路由的写入者和时刻未知，历史 after 原件及归因未知保留，没有删除或“修复”路由。本轮相同不回写旧差异。见[本轮全局比较](../../verification/windows-2026-10-22/lpac-stream-origin-actual-01/global-comparison.json)及[此前精确路由记录](2026-10-23-lpac-pipe-origin-mechanism.md)。

本机整套纯测1096项/172.701秒，0失败、2项既有 symlink skip；自动 [CI run39921159655](https://github.com/Shermanxwz/Rule-proxy-Web/actions/runs/39921159655) 在同一源提交完成1096项/208.633秒、无skip，步骤5–9 runtime全部skipped。RPS1的54313项是一个便携生产契约测试内的断言，不能算作54313项独立测试；其余33项新 Python 纯测也是注入假API/actor报告。compile-only、PE静态核验、纯测、自动CI和本机实测相互区分，不以CI代替运行结果。CI保存的是 connector decoded UTF8文本和 normalized jobs JSON，非原ZIP或raw HTTP。

开发记录保留 native/ABI、False01/02/03、源文件 share=0 生命周期修订、独审、Ready04及 reader 初始 fake 清理字段不完整而失败的历史。读取器没有通过 forensic 补齐缺失 worker；有效 worker 时要求 forensic 原字节相同。两个新 artifact 各有精确三源 manifest，共享四个 precompile snapshot 源；manifest、编译脚本、driver、file-only reader和源码提交链接均列入[源码与构建索引](../../verification/windows-2026-10-22/lpac-stream-origin-source-review-01/index.json)。

此前 atomic01 的 unknown/recovery、G/PSEC DNS 泄漏、LPAC 显式DNS的独立窄结论、loopback 的既有失败，以及旧 IPC01 的路由差异保持原件和原值。本轮没有执行这些实验或宣称它们已恢复。后续同进程 IPC＋DNS候选仍应取得自己的运行证据，不能从本轮 DNS=false 推出 DNS 已被阻断。
