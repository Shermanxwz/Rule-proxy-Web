# DNS 历史复核：2026-10-23

最近的失败记录仍然成立：REQUEST3 没有跑通自有接收端交换，本机高端口 VERSION1 也返回了 87。新 `dns-standard-local-02` 则已跑通 **ordinary VERSION1、标准 UDP53、自有接收端**的一次精确查询和答案核对。它支持继续建立 selected 测试的健康正控；当前 Model2 selected DNS、默认 resolver、系统 broker 隔离及产品验收仍未运行或未通过。

“这个项目以前的 DNS 从未成功”不符合保留记录。历史上既有成功解析，也有不该出站的 DNS 被观察到，还有不同策略下有限范围的零查询观察。必须同时看 API、包或接收端证据、调用者身份、策略和清理，不能用 CI 颜色概括。

本次只读复核的脱敏来源和摘要见[机器索引](../../verification/windows-2026-10-22/dns-history-review-index.json)。没有重新调用 DNS、启动实验、重跑 CI 或修改网络设置。

**范围与数据完整性。** 本地来源是非浅克隆中当前 refs 可达的 562 个提交，审计快照为 `f4a0df3be0d0fa2d84d5bc974573c5dbd4dfd4d0`；机器解析了 942 份 JSON，建立 590 条 DNS 相关文件承诺，并确认 226 个 DNS 命名历史路径仍在树中。旧 compartment manifest 的 569 个条目逐字节数、SHA256 和 Git blob 核对通过；这是完整性核验，不表示逐项语义审阅了 archive 的全部 DNS 内容。另校验了历史工作树归档分片，工作区源码快照不作为实际执行证据。

GitHub 侧未按分支过滤，读取了当前可访问的 842 次运行元数据、56 份相关完整 job 日志和 6 份实际 artifact ZIP。56 份日志包括 7 份 REQUEST3、46 份其他历史日志及 3 份近期纯测试日志。这个范围不等于所有远端实验分支、全部 842 份 job 日志或曾经存在的所有原始数据；已删除或未导出的 PCAP、过期附件和当时机器状态没有重建。日志摘要绑定连接器返回的完整 UTF-8 文本，不能称为原始压缩日志 ZIP 的摘要。

**按受测提交区分历史结果。** 表中的日期用于串联记录，完整索引保留确切受测提交；提交时间不等于实验运行时间。

| 时间与受测来源 | 实际证据 | 可支持的结论与边界 |
|---|---|---|
| 10/15，`12acab8`、`7235c03`，旧 PSEC/默认 resolver | 记录了 contained parent/child 的匹配 DNS 出站记录；两轮各有 8 条。前一轮整体分析不完整，后一轮 DNS 记录解析完整。 | 匹配 DNS 出站阳性；仅此不证明收到答案。整体不完整不能抹去已匹配的阳性。[早期来源](../../verification/windows-2026-10-15/12acab8/native/source.json)、[后轮结果](../../verification/windows-2026-10-15/7235c03/official-native/observations.json)、[CI 38677202716](https://github.com/Shermanxwz/Rule-proxy-Web/actions/runs/38677202716)。 |
| 10/15，`b4b6c38`、`f48239a`、`ebb3c1c`，其他明确策略 | 有完整正控和捕获的 selected DNS 分组，未见对应查询；`f48239a` 的父子 API 返回为 getaddrinfo 11001、A/AAAA 5，代理往返仍为零。 | 保留这些有限负结果；它们未建立通用内核拒绝或产品通过，也不是当前 Agentic+PNCS Model2 的实测。[26200.9711 结果](../../verification/windows-2026-10-15/f48239a/psec11-network-native/observations.json)、[CI 38694937889](https://github.com/Shermanxwz/Rule-proxy-Web/actions/runs/38694937889)。 |
| 10/16，Clew/ProxiFyre 对照 | 自有合成 DNS 的 raw UDP 接收计数为 16/6，另一目标均为零。 | raw UDP 正控成立；未测试系统 DNS broker 或全面 DNS 防泄漏。[对照摘要](../../verification/windows-2026-10-16/proxy-compare/comparison-summary.json)。 |
| 10/16，Linux global | 真实内核实验观察到经 fixture SOCKS 的 DoH，直接 UDP53 sink 未到达；fixture 主动拒绝上游 DoH。 | 证明所测载体与有限防直出观察，未证明成功上游解析。[归档](../../verification/linux-global-2026-10-16/native-qualification.json)、[CI 38914464955](https://github.com/Shermanxwz/Rule-proxy-Web/actions/runs/38914464955)。 |
| 10/17，`24c000e`、`c31de51`，Windows global TUN/NRPT/DoH | 系统默认 Winsock，以及 UDP/TCP IPv4/IPv6 查询均得到并核对答案；关闭 carrier 后新查询失败，恢复后再次成功，恢复检查通过。 | 历史上真实 DNS 解析成功。该 disposable global 烟测使用 TUN/NRPT 与独立载体，`dns_qualified`、strict 和应用隔离资格仍为 false。[归档](../../verification/windows-global-2026-10-17/native-qualification.json)、[CI 38948255233](https://github.com/Shermanxwz/Rule-proxy-Web/actions/runs/38948255233)、[CI 38951969738](https://github.com/Shermanxwz/Rule-proxy-Web/actions/runs/38951969738)。 |
| 10/19，旧 compartment 与 ordinary primary-token 对照 | 有 inside DnsQuery_W/DnsQueryEx 返回 0 并匹配出站查询；ordinary 对照的部分 API 失败仍伴随出站记录。ABI 修复后，六类 ordinary inside 查询各仍有匹配记录。受限变体没有完成可用 actor 初始化。 | 旧后端存在 DNS/broker 边界缺口；API 失败和受限 actor 零包均不能充当隔离通过。NIC 记录可能重复，未证明发送进程归属。[初始 API/wire 对照](../../verification/windows-2026-10-19/compartment/native-first/windows11-dns-api-wire-join.json)、[ordinary 结果](../../verification/windows-2026-10-19/compartment/primary-token-server/assessment.json)、[ABI 修复后结果](../../verification/windows-2026-10-19/compartment/primary-abi-fixed/assessment.json)、[CI 39206919590](https://github.com/Shermanxwz/Rule-proxy-Web/actions/runs/39206919590)。 |
| 10/20，`5d4cafe`、`1b1384b`，zero-cap AC capture lab | 首轮 AC 启动 203、未运行，报告为 `invalid_experiment`，但 CI 仍绿。后轮有 outside/internetClient 帧正控、zero-cap 零匹配帧；同时保留 API87 和部分调用超时。 | 首轮无隔离证据；后轮是有限 NIC 非观察，不是健康同 API 机制通过或已证 WFP drop。[首轮](../../verification/windows-2026-10-20/diagnostics/runs/dns-39350432490-1/dns-capture-report.json)、[后轮](../../verification/windows-2026-10-20/diagnostics/runs/dns-39352260335-1/dns-capture-report.json)、[CI 39352260335](https://github.com/Shermanxwz/Rule-proxy-Web/actions/runs/39352260335)。 |
| 10/21，REQUEST3 | 编译失败之后，实际 high-port 调用、取消指针对照、固定另一个 loopback 的 high/53 对照均未得到成功交换。 | API87 原因仍未知；详细七轮见下表。[原说明](2026-10-21-dns-request3-mechanism.md)。 |
| 10/22，`cee0724`，本机 ordinary VERSION1 高端口 | API/query status 均 87，自有 query/answer 均零，14 项监督与清理检查通过。 | 这是机制失败，不能写成 DNS 拒绝或 wire 阻断。[原结果](../../verification/windows-2026-10-22/dns-v1-local-01-public.json)、[摘要](../../verification/windows-2026-10-22/dns-v1-local-01-summary.json)。 |
| 10/23，`4bd68e8`、`21cbfe2`，本机 ordinary 标准53 | 01 在 staging 停止，没有 config 或 actor/inventory 执行；02 实际 API/query status 均 0，一个精确 A 记录，自有 receiver 看到 1 个匹配 query、发送 1 个答案，观察到 62 字节，全部监督、清理及全局配置比较通过。 | 当前普通身份的同 API 健康机制成立。01 时钟范围根因只标为源码和保留树支持的推断；新成功不改写原失败。selected、默认 resolver、broker、DNS 隔离资格均为 false。[独立检查点](2026-10-23-dns-standard-mechanism.md)、[02 原报告](../../verification/windows-2026-10-22/dns-standard-local-02-public.json)、[证据索引](../../verification/windows-2026-10-22/dns-standard-local-01-02-evidence-index.json)。 |

**REQUEST3 七轮不能按 CI 绿灯计为 DNS 成功。** 已读取这七份完整 native job 日志，并核对保留结果摘要；两轮绿色分别是无查询诊断和只读端口 inventory。

| CI | 实际阶段 | 结果 |
|---|---|---|
| [39595518393](https://github.com/Shermanxwz/Rule-proxy-Web/actions/runs/39595518393) | 编译 | 原 header 顺序未暴露 `DNS_CUSTOM_SERVER::ServerAddr`，未调用 API。 |
| [39596064259](https://github.com/Shermanxwz/Rule-proxy-Web/actions/runs/39596064259) | 首次实际 REQUEST3 | API87，接收端零查询。 |
| [39597168358](https://github.com/Shermanxwz/Rule-proxy-Web/actions/runs/39597168358) | 非空/空取消指针对照 | 两者均 API87，接收端零查询，清理确认。 |
| [39598090604](https://github.com/Shermanxwz/Rule-proxy-Web/actions/runs/39598090604) | 无查询 layout/version 诊断 | CI 成功；`api_called=false`，未建立 DNS 交换。 |
| [39599559399](https://github.com/Shermanxwz/Rule-proxy-Web/actions/runs/39599559399) | high/53 对照准入 | inventory 未确认空闲，未 bind、未调用 API，原因当时未区分。 |
| [39600454533](https://github.com/Shermanxwz/Rule-proxy-Web/actions/runs/39600454533) | 只读 UDP53 inventory | CI 成功；看到一个端点，未 bind、未调用 API；不能回溯证明上一轮原因。 |
| [39602167378](https://github.com/Shermanxwz/Rule-proxy-Web/actions/runs/39602167378) | 固定 alternate loopback 的 high/53 对照 | 两者均 API87，所有 receiver 计数为零，pair 与清理完成；后续 Windows 单测未因失败而执行。 |

表中保留结果见[REQUEST3 初始摘要](../../verification/windows-2026-10-20/identity-proof/dns-request3-mechanism-01-summary.json)、[端口准入失败](../../verification/windows-2026-10-20/identity-proof/dns-request3-port-pair-01-summary.json)、[只读 inventory](../../verification/windows-2026-10-20/identity-proof/dns-port-inventory-01-summary.json)及[alternate loopback 摘要](../../verification/windows-2026-10-20/identity-proof/dns-request3-loopback2-pair-01-summary.json)。`result_status=0` 的初始化值和注入 pending 清理控制，都没有成功解析或 broker 取消的含义。

**新成功改变了什么，尚不能解释什么。** 旧本机 VERSION1 使用 `DNS_ADDR_ARRAY.Family=AF_INET` 和显式高端口；新构造沿用官方 sample 的零初始化 array、`MaxCount=AddrCount=1`、bare IPv4 sockaddr，Family 和 sockaddr port 留零，实际自有 receiver 固定标准53。请求、结果与名称的存储、actor 构建、受监督 inventory/owner 路径也有变化。REQUEST3 还使用另一版本结构，早期试验运行于不同 Server 环境。因此没有单变量对照证明 Family、port 或某一处初始化是 API87 的唯一原因；新标准53机制也没有证明 REQUEST3 已修复。

`0904d2d` 的历史修正针对 console trust 被污染时撤销 DNS 的 actor attestation，同时保留包/API 计数。它不能回溯抹除之后 `b4b6c38`、`f48239a` 等来源独立、范围有限的负结果。另一方面，这些旧结果也不能替代当前 Model2 selected DNS 的新鲜同 API 前后正控、身份/策略绑定、receiver 观察和完整清理。

近期三个红色 CI 是 gated runtime 之前的纯测试回归，不能计成新的 DNS API 失败：[39801145227](https://github.com/Shermanxwz/Rule-proxy-Web/actions/runs/39801145227)、[39823448696](https://github.com/Shermanxwz/Rule-proxy-Web/actions/runs/39823448696)、[39827099007](https://github.com/Shermanxwz/Rule-proxy-Web/actions/runs/39827099007)。此前 global 首轮 [38947189564](https://github.com/Shermanxwz/Rule-proxy-Web/actions/runs/38947189564)虽有五个正向答案，仍因 carrier 观察判据失败而保留失败，后续成功没有改写它。

审计快照之后的独立修复复核：`6aa32557dc92fa548c1215820f05f0cefe11517f` 的 [CI 39834757571](https://github.com/Shermanxwz/Rule-proxy-Web/actions/runs/39834757571) 已通过 680 项纯测试，20.712 秒、零 skip；native actor 仅编译，runtime 阶段全部跳过，没有新 DNS 或虚机实测。这条后续记录不加入上述 842 次元数据或 56 份历史日志计数，不改变两份完整审计快照及其摘要。

**审计原件承诺。** 完整审计 JSON 留在工作目录，没有整包公开；本页和公开索引仅投影结论、来源与摘要，不复制旧身份、请求标记、机器路径、本机配置或历史对话。`dns_history_local_audit.json` 为 263,912 字节，SHA256 `aaf0fc78b1c5c35a1754c50aacbc76a6bd7ecfedf4c2d0e37b0cf780e763bcd6`；`dns_history_ci_audit.json` 为 715,155 字节，SHA256 `ce62e89d9b2b6535d01564f999692c6bf0a35092b019666b806241db8fe3f689`。这些是本次只读审计来源承诺，不能补回未保留的原始实验数据。
