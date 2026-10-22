# PSEC + LPAC identity01：报告失败，原未知状态保留

**本轮为 `inconclusive`，没有最终 worker report，也没有 AC/LPAC 四矩阵验收结果。** 原 public 的 `failure=report`、`broker_outcome_unknown=true`、`recovery_required=true` 保持不变。外层进程和 Job 清理完成不等于 opaque CPSE 环境已不存在。本轮没有运行 actor 代码或网络，不能当作代理或 DNS 隔离通过。

受测源码是 `1c83029245e889b2c950ca5dbaa0da675a287c09`，36 文件运行时闭包为 `7dd12aaf5c8727c325e184f69393072e13e0b1772aa1be03318adf7e1d77951a`。[原 public](../../verification/windows-2026-10-22/psec-lpac-identity-local-01-public.json) 为 1660 字节、SHA256 `cc562d1b045fea336c4257051faa52e63aa415d91556a4ea84f18aa363652f9c`；[原件索引](../../verification/windows-2026-10-22/psec-lpac-identity-local-01-evidence-index.json)绑定 plan/spec、staged Git blob/LF 源码、两份 manifest、原始 outer launch 与私有日志的字节和摘要。

## 实际看到了什么

worker 以退出码 1 结束，外层 Job 空、Job 和句柄关闭、进程退出确认均成立。`worker-report.json` 缺失；stderr 的固定错误为 `ValueError: cpse_task_number`，发生在 `Cell.execute()` 及其 cleanup 已返回后的结果校验。源码把实际 FILETIME 代际值用默认 DWORD 上限校验，因而报告器拒绝它。这解释最终报告失败，**不能解释更早的首个 AC admission 为何未进入第二臂**；本轮没有保留下该早期失败的最终私有结果，具体原因仍未知。

磁盘上只有六份按顺序闭合的意图：`bind`、`create`、`ac`、`stop`、`close`、`unbind`。它们已与 config SHA、fresh run、原 F/D 和文件名绑定。[组件投影](../../verification/windows-2026-10-22/psec-lpac-identity-local-01-component-projection.json)明确将这些记录标为 intent-only；它们不是原始 API 返回、PI、held token 或 AccessCheck 证明。缺失的 task/proof 不补齐，关闭调用与正常返回次数记为未知，不能用 0 冒充未调用。

依照冻结源码的清理分支，能走到 `unbind` 意图，条件性地说明此前代码接受了 `close` 的正常返回字段。这个结论是[独立只读审查](../../verification/windows-2026-10-22/psec-lpac-identity-source-review-01/actual01-independent-review.json)的**源码控制流推断**，不是保存下来的 raw close receipt，更不是环境 absence、broker cancellation 或一次独立恢复完成的证明。原 public 的未知和恢复要求不会被这一推断回写消除。

before/after 两份全局快照均为 7378 字节、SHA256 `f05d91ee76ee8a97ae5ab3bfa092167a8ee560c083255f142e6c453f2edf7ab3`，原始字节及 JSON 对象相等。该比较只覆盖 firewall profiles、DNS、routes、user proxy 四类对象，不含 NRPT，不证明完整或持续的全局状态不存在变化。原始快照和私有日志未公开。

## 本轮命题与可追溯构建

这是独立的 `identity-only-deny-all-v1`：PSEC schema 1.1，显式 PNCS capability、Agentic 由 OS 身份观测，inputs 只读，其余文件范围为空，egress/ingress/host-loopback 默认拒绝，无 proxy/peer。预声明一份 CPSE 环境、同映像/cwd/environment/inner+outer Jobs，两臂只改变 AAP policy 0/1，均 `CREATE_SUSPENDED` 且永不 resume；不另加 `SECURITY_CAPABILITIES` 身份源，不创建 standalone profile 或补 ACL。原 120 秒 root / 115 秒 worker 预算不续期。**本轮尚未取得两臂完整观察，也没有复刻 Model2 的代理策略。**

[源码审查索引](../../verification/windows-2026-10-22/psec-lpac-identity-source-review-01/index.json)保存原 Python、native03 和纯测试 portability patches/freezes、独立审查、依赖 pins、编译/静态 PE 读者及测试证据。compile02 在编译前冻结 6 个 native source 与 31 个依赖；`/MT` x64 DLL 为 214016 字节、SHA256 `9574f93eb562a858b207412f9f538b15bfbf329b1df284b3266496b4c2cf2ba5`，仅静态导入 KERNEL32，8 个闭合 exports。DLL binary 与可能携带用户路径的 raw 编译日志不公开。更早 compile01 是 mutable WIP 失败，没有被追认成最终源码的精确构建。

本机身份相关纯测试为 857 项、48.776 秒、零失败、2 个原有 symlink 权限 skips；新测试未 skip。native pure 包括 327 个生产状态/spec 断言及 4 个 Python 原始 spec 字节到官方生成 C++ 验证器的交叉检查。[受测源码自动 CI](https://github.com/Shermanxwz/Rule-proxy-Web/actions/runs/39872306319)为 857 项、59.713 秒、零 skips；5–9 号 gated runtime 步骤均跳过。纯测试、编译和 CI 成功均不抵消本轮实际报告失败。未在本机运行 Linux 测试。部分日志和补丁提供脱敏公开视图，原始与公开摘要分别记录；可执行源码以受测提交的 Git blob 为准。

## 下一步与仍然成立的边界

策略允许使用另行审查和提交的新源码，修正 FILETIME/HANDLE 宽度并增加每次返回 receipt 与校验前的 forensic 保留，然后以新 plan、nonce、stage、spec 和原始预算进行单次独立 02 诊断。forensic 文件只用于诊断，不能绕过最终 validator 或资格门；不重用、重开、数字重放或重试关闭旧 opaque 值，不自动重试，不启动 actor、网络、driver、服务重启或全局配置变更。01 的历史未知始终保留；02 若产生新证据也不能倒推 01 已恢复。

[standalone semantic-LPAC DNS02](2026-10-23-lpac-semantic-dns-02.md)的 API/query `5/5` 与前后正控成功仍是独立结果；[原 G/PSEC DNS API 泄漏](2026-10-23-selected-dns-standard53.md)也仍成立。PSEC+LPAC 的完整身份组合、相同代理策略、真实代理链与 DNS 矩阵尚未验收，`model2_policy_compared`、`proxy_tested`、`dns_tested`、`product_acceptance` 均为 false。
