# 同 held selected 的原始 UDP53 差分

当前结论仍是 **DNS 应用隔离失败，不能验收为 Linux 等效**。[API DNS01](2026-10-23-selected-dns-standard53.md)已经给出 selected `DnsQueryEx` 精确答案与独立 receiver 命中的明确反例。下面两个原始 UDP 尝试保持各自的 `inconclusive`，不会抵消该阳性，也没有定位实际发包 PID。

## 两次实际尝试

| 尝试 | 受测源码 | 普通前后控制 | selected 事实 | 结论 |
|---|---|---|---|---|
| rawDNS01 | `0b9df64beb111ac8cb02ad6a4db41bbbeffbd9dd` | before 成功；after 在 GO 前被库存五秒门停止 | UDP connect 完成；本地接受一次62字节 send；receiver 无对应查询；deadline，无 Winsock 错误 | incomplete / inconclusive |
| rawDNS02 | `962231bf9b07f2fb109d5e6343e3b7c5cea2397c` | before、after 成功；四个库存门与完整观察成立 | 同样 connect/send 本地接受、receiver 无对应查询、deadline，无 Winsock 错误 | complete observation / inconclusive |

[raw01 原结果](../../verification/windows-2026-10-22/model2-raw-dns-01-public.json)、[摘要](../../verification/windows-2026-10-22/model2-raw-dns-01-summary.json)与[索引](../../verification/windows-2026-10-22/model2-raw-dns-01-evidence-index.json)保留原始不完整控制。public 为3504字节，SHA256 `2680cf87b8fafbcaef0084c3fa5376f34ea0b65717fcbbe362658786cc594b17`。selected 阶段约1.988秒，结束时比固定 phase deadline 晚约0.002秒；after 的冗余防火墙状态读取使唯一库存过期。控制器确切 invariant 为 `dns_inventory_freshness`，after GO 不存在。13个内部任务中五个仍存活角色由清理终止为1，其余自然0，不能统称全部自然0；维护进程0。所有清理确认、无需恢复。

[raw02 原结果](../../verification/windows-2026-10-22/model2-raw-dns-02-public.json)、[摘要](../../verification/windows-2026-10-22/model2-raw-dns-02-summary.json)与[索引](../../verification/windows-2026-10-22/model2-raw-dns-02-evidence-index.json)独立绑定新 epoch、case 和计划。源码闭包为 `fa8772ee1e6d2e816ec898221af80ed170bf75316b9aed43ba5b017960da7b25`；public 为3498字节，SHA256 `50e9142854e8738fafa768a4c72d4a6b489c2710f269ca4bac6e73efd2302d40`。`inventory_before_each_query`、`ordinary_before_verified`、`ordinary_after_verified`、`receiver_complete`、`observation_complete` 为 true，但 `completed`、`diagnostic_completed`、`dns_isolation_qualified` 和产品验收均为 false。失败投影来自 selected 的有界超时，不是访问拒绝。 独立核对的 bind/before/selected/after 库存年龄分别约0.078、0.079、1.428、3.462秒，均低于原五秒门；before/after 各自一问一答、send62/recv78。13个内部任务与维护进程均自然退出0，原 origin 后控、selected/health/origin finish 全部完成。 外层 worker 因 `inconclusive` 结果失败退出，未称其为0。

两次所有 owned receiver/socket、ACL、精确规则、profile、SID、held process、Job 和维护资源清理均确认，`recovery_required=false`。两次运行后的只读全局快照均为7378字节，与首次 baseline 字节相同；快照独立比较的四类为 `firewall_profiles`、`dns`、`routes`、`user_proxy`。NRPT 另由本次准入库存确认有效条目为0；入口没有 NRPT 写操作，不称快照包含 NRPT 前后比较。没有更改这些全局网络设置。三个防火墙 profiles 原本关闭，原 Stage0、strict Full 和产品资格始终为 false。

## 最小控制器修复

raw01 原件未修改。随后仅删除 raw profile 普通 before/after 阶段中重复的 `refresh_profiles()`：普通控制进程不受 selected package 的精确规则约束。selected 仍先刷新，原 `publish_phase` 的防火墙新鲜度门保持；每轮 family/task liveness、每个 DNS GO 的同一库存≤5秒门、原绝对 root/phase deadline 全保留。API6 仍进行三次刷新，没有改变原有行为或权限。

[纯测试记录](../../verification/windows-2026-10-22/model2-raw-dns-timing-fix-pure-tests.json)包含先复现失败再修复的耗时回归、API6 三刷新及过期库存拒 GO 反例。31项 focused 测试零跳过；完整本机720项无失败，2项原有符号链接权限跳过。[受测 raw01 源的自动 CI](https://github.com/Shermanxwz/Rule-proxy-Web/actions/runs/39844113677)为717项零跳过、仅编译和纯测试，runtime 全跳过；它不代表任何 DNS 隔离通过。 raw02 同受测源 `962231b` 的[后续自动 CI 39845952394](https://github.com/Shermanxwz/Rule-proxy-Web/actions/runs/39845952394)为720项、17.258秒、零 skip，仍仅编译与纯测试、runtime 全跳过；[日志承诺](../../verification/windows-2026-10-22/model2-raw-dns-source-pure-ci-02.json)单独归档。

## 方法和边界

独立 profile 为 `same-selected-raw-standard53-dns-v1`，method 是 **Winsock UDP connect → send → recvfrom**。沿用同 held selected、Agentic+PNCS、pinned G/PSEC、原始 Jobs、P/Q/O 和一次性原 QPC 预算。受监督只读库存先确认未配置 loopback DNS、有效 NRPT 为空、UDP/TCP53 无占用，再由 ordinary receiver 独占自有 `127.0.0.1:53`。三个新预声明 case 分别用于普通 before、selected、普通 after；不转发上游，不改系统 resolver。使用同一 native07，manifest/source pins 均在任何网络 GO 前核对。

每 case 仅一次非阻塞 connect/send/recvfrom 序列。`connect_completed` 和 `send_complete` 只是本地 Winsock 事实；交付必须由独立 receiver 证明。这里没有 selected query 命中，也没有明确 `10013`，有限超时不能当成拒绝。只有闭合 socket/WSA 状态已确认的 typed timeout 才允许继续采集原先声明的 ordinary after；不延长任何时间，也不使 timeout 合格。

本实验没有测试未 connect 的 `sendto`、所有 UDP、任意 IPv6、默认 resolver、WinHTTP 或真实浏览器。API6 与 raw07 是分开的运行；它们的差异提示需要继续检查 DNS API 路径，但不能据此断言 Dnscache 是实际发包者，不能全局封 DNS 服务，也不能用合作式 DNS hook 宣称任意应用完整隔离。DNS Client 的本机 TDH/provider 元数据仅被只读检查，尚未启动 ETW 事件跟踪。
