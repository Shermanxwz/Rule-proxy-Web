# 同 held selected 的标准53 DNS 诊断

本入口将已成功的 [ordinary 同 API 机制](2026-10-23-dns-standard-mechanism.md)接入当前 Model2 生命周期。独立 profile 为 `same-selected-standard53-dns-v1`，仅允许显式 `profiles-off-diagnostic`。首次实测 DNS01 已发现明确 DNS 绕代理反例，整体为 **failed**；当前受测后端不能满足全部 DNS 不绕代理的要求。原 Stage0、严格 Full、默认 resolver、系统 broker 或产品的验收结论均未改为通过。[历史复核](2026-10-23-dns-history-review.md)中的旧失败和有限负结果继续保留。

## DNS01 实际结果：查询与答案成功，隔离失败

受测提交 `6e87e6a3dc30def12d1ec76a8e8b077a101ebee0`，28文件源码闭包 SHA256 `da01640fd39da54d6f0e5da7425fdb4591902c65033aa6726a49ff22bd43d912`。[原公开结果](../../verification/windows-2026-10-22/model2-dns-01-public.json)、[版本摘要](../../verification/windows-2026-10-22/model2-dns-01-summary.json)、[组件投影](../../verification/windows-2026-10-22/model2-dns-01-component-projection.json)及[证据索引](../../verification/windows-2026-10-22/model2-dns-01-evidence-index.json)确认：

- 主代理 HTTP 129→95字节请求、90字节响应、同 held selected 的固定 origin direct `10013`、origin 前中后健康控制和实际 `base-container` tier 仍成立。旧 main direct 发生在 front/relay 退出后，未验证活代理期间直连。
- 在同一 selected、G/PSEC、身份、Jobs 和原 QPC 预算中，selected 的 `DnsQueryEx` VERSION1 实际返回 API/query status **0/0**，一个精确匹配的 A 答案，非 pending、准时、记录已释放。它不是 API87、超时、缺报告或初始化零值。
- 独立 receiver 记录 selected case **一次匹配查询、一次答案**；ordinary before/after 各自也完成同 API 0/0、精确答案及一问一答。总共3个 datagram、186个查询字节、零拒收和发送失败。每 case 的62字节由闭合 parser 的最小合法问题长度和总量推出，未保留逐包 raw capture，不冒充逐包取证。
- 13个内部持有任务和维护进程全部自然退出0；外层 worker 按失败结果退出，退出与清理均被确认，不称 worker 为0。所有 finish、ACL/profile/rule/Job/handle/receiver 清理通过，无需恢复。[运行后的全局只读比较](../../verification/windows-2026-10-22/model2-dns-after01-global-projection.json)与首次 baseline 的7378字节原件完全相等。

`selected_dns_query_observed=true` 是保留到外层结果的 sticky violation，`selected_access_denial_observed=false`、`diagnostic_completed=false`。原 public 为3060字节，SHA256 `51d8c38a9acd79c8dee629782b1e091a56bb7ccd6d2209cf28852396401b08b5`。归档只读核对28份 staged 源与受测 Git blob、8个 native pin、12字段 manifest、G artifacts、13个唯一 nonce、11条 GO、28份实际报告描述符（上限32）及40份 stdout/stderr 的整体承诺；没有重跑测试。

这否定的是本机 profiles-off、Agentic+PNCS、pinned G/PSEC 与这一具体策略下“DNS 全部不绕代理”的命题，不证明所有 Windows/AppContainer/其他配置均不可能隔离。当前反例是显式 server 到 owned loopback53；没有测试默认 resolver，也没有证明实际发包 PID 是 Dnscache 或其他 broker。下一步需分清 raw UDP 路径和 DNS API 路径，再做有身份绑定的归因与约束；不能据此全局封锁 DNS 服务，或用应用内 hook 宣称任意应用都被隔离。

第一次 wrapper 调用在任何 plan/QPC epoch/actor 前，被 Git blob 字节门拦下：两个 Python 工作文件是 CRLF，提交为 LF。仅将这两文件写回已提交原始字节，重新逐字节核对全部源码后才进入上述首次实际运行。[独立 pre-plan 记录](../../verification/windows-2026-10-22/model2-dns-01-preplan-byte-gate.json)保留该次拦截，没有绕过门或续期原运行时钟。

本机完整纯测试696项无失败（2项原有符号链接权限跳过）；同受测提交的[自动 CI 39838348066](https://github.com/Shermanxwz/Rule-proxy-Web/actions/runs/39838348066)为696项、零跳过，actor 仅编译、受控 runtime 全跳过。绿色 CI 不是上述实际泄漏测试的通过结果。

## 顺序与身份

先完成原代理正向、同 held selected 的固定 origin direct 及 ordinary origin 健康控制。随后保持同一 selected HANDLE/generation、G/PSEC、A 身份、精确 Jobs 和 P/Q/O 绑定，执行 ordinary 同 API before、selected 同 API、ordinary 同 API after。三次均调用同一 pinned actor 的 `DnsQueryEx` VERSION1、同一官方零端口构造和固定 loopback UDP53，使用相互不同的预声明新 case。之后完成 selected/health/origin finish、origin 后控、实际 tier 与清理。

新增 op6 继续使用原128字节 GO、run/admission、原始 QPC epoch 与绝对 deadline；只在完整 GO 准入和命令句柄关闭后调用 DNS。P/Q/O 高端口绑定不变，op6 的目标另固定为53。每个查询的 phase 预算在原 root 预算内，不能续期；同步 API 阻塞最终由既有 outer Job/watchdog 限制。pending 存储保留至进程结束，没有取消成功、重试或回退到系统默认 DNS 的声明。

## 本机影响与准入

一次测试只创建原 Model2 专用 AppContainer、精确身份/映像/P 规则和源/结果目录 ACE；维护进程仅管理这条精确规则。它们与所有持有进程、Job 和句柄一并清理。不为 DNS 新增放行规则或 capability，不更改系统防火墙 profiles、默认策略、DNS、NRPT、代理或路由。

一个独立受监督 ordinary PowerShell 进程只读检查 DNS server、有效 NRPT、UDP/TCP53 占用，报告绑定其 held PID、原 QPC 和源码 hash。任何本机 DNS 指向 loopback、非空 NRPT、已有53端点、未知数据或读取失败均停止。库存仅一次，必须在唯一 bind 和每个 DNS GO 前均不超过5秒；不会自动重读并更换准入时间。

通过后，一个 ordinary receiver 独占绑定 `127.0.0.1:53`，只接受来自 `127.0.0.1`、匹配三个新 case 的严格 A/IN 查询并返回固定测试地址。它不转发上游，也不接管系统 DNS。新鲜端口检查仍不能消除检查与 bind 之间的竞争，因此独占 bind 失败也会停止。

## 观察与结论边界

- ordinary before/after 必须各完成准时、非 pending 的 API/query status 0、一个精确 A 记录、内存释放，并由 receiver 独立确认匹配 query 和已发送答案。绿色测试、初始化的 status 0 或 raw UDP 正控不能替代这些条件。
- selected 只有实际调用完成、准时、非 pending、记录释放、API status 5 且无答案时，才记录为 typed access-denial observation。API87、超时、pending、晚到报告和缺失报告均不计为拒绝。还必须具有完整前后正控、receiver 观察、同 held 身份和清理，才允许该诊断完成。
- receiver 对 selected case 的命中是独立 sticky 阳性，在发答案前置位。它在 native 解析、退出或后续清理失败后仍须保留；未知计数不能把已观察的阳性改为零。阳性禁止诊断通过，但 nonce 匹配不提供 DNS Client 服务或实际发包进程的 PID 归属。
- receiver 完成观察的窗口是有限的。任何零查询结果都不能证明任意 DNS、默认 resolver、所有系统代办、跨窗口晚到查询或 broker 取消；相应资格字段固定为 false。

原始私有树保留 source closure、manifest、held identity、GO、原报告、库存和 receiver 记录；公开投影仅给出布尔、计数、错误与 SHA，不公开身份、请求标记或本机配置。运行结果将在新的独立证据中追加，不能用计划或纯测试填写实际结果。
