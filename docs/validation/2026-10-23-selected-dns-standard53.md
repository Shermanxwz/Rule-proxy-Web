# 同 held selected 的标准53 DNS 诊断

本入口将已成功的 [ordinary 同 API 机制](2026-10-23-dns-standard-mechanism.md)接入当前 Model2 生命周期。独立 profile 为 `same-selected-standard53-dns-v1`，仅允许显式 `profiles-off-diagnostic`；本文建立时尚未运行该 selected 实验。它不更改原 Stage0、严格 Full、默认 resolver、系统 broker 或产品的验收结论。[历史复核](2026-10-23-dns-history-review.md)中的旧失败和有限负结果继续保留。

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
