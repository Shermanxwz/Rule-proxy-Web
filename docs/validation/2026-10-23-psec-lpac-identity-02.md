# PSEC + LPAC identity02：创建返回成功，Job 准入未通过

**本轮仍为 `inconclusive / admission`。** CPSE 环境创建返回 `S_OK`，policy 0 首臂创建返回完整 PI；随后一个 exact Job 的 membership 检查为 false，准入正确停止。原件不能区分失败的是 inner Job 还是 named outer Job。没有读取首臂 primary token，没有尝试 LPAC 第二臂，没有 AccessCheck 矩阵，也没有 actor resume、DNS、网络或代理验收。

受测源码为 `b269c78eef15b6f71bdae5a5ee631a4e8a34ce9e`，36 文件闭包为 `7de9968d0984cc7304951ba220d806fea74e998c0a623beddd870a0eb1e0f0ba`。[原 public](../../verification/windows-2026-10-22/psec-lpac-identity-local-02-public.json)为 2083 字节、SHA256 `100dc78f9af83445829a9f8ddf03ebe1f6bb5fc3af8f1a694e43bb78229daba2`。[证据索引](../../verification/windows-2026-10-22/psec-lpac-identity-local-02-evidence-index.json)和[组件投影](../../verification/windows-2026-10-22/psec-lpac-identity-local-02-component-projection.json)绑定原 public、plan/spec、Git blob/LF 源码、构建、worker/outer 报告及私有材料摘要。

## 本轮实际记录与未取得的证据

源码02修复了 FILETIME/HANDLE 的 64 位校验，PID/TID/exit code 仍为 DWORD；没有改 DLL、原 native07 actor 或 deny-all 策略。新增五份原始返回收据：`bind`、`create`、`ac`、`close`、`unbind`，均在语义校验前保存原 function status、native snapshot、PI 和 intent/config/F/D 绑定。六份意图仍是 `bind/create/ac/stop/close/unbind`；意图与返回收据分开核验。

`worker-result-forensic.json` 与经过源码校验的最终 worker result 逐字节相符。forensic 单独存在时只属未验证取证材料，不能替代 held worker report 或补出资格。此次 worker 报告存在且与普通 held worker、配置和 outer launch 绑定，worker 自然退出0；stdout/stderr 均为空。首臂创建返回的两个句柄与两个 ID 完整，创建时间确实超出 DWORD 范围；这证明本轮报告器修复已覆盖真实数据，**不等于首臂 AC 身份已被核验**。

保留下来的原失败是 `GateFailure: child_not_in_owned_job`。源码在 `IsProcessInJob` API 调用成功、membership 输出为 false 后抛出此标签；API 成功与 membership 为 true 是两件事。inner 与 named outer 检查共用该错误标签，而且 `assigned` 仅在两项都通过后设置，因此 `assigned=false` 不能识别哪项失败。最早失败门发生在 token/能力和完整 held identity 准入前；没有第二臂或 proof，不能把缺失字段补成通过。

此次首臂 held exit1 已确认，已知 child/Job/句柄与 observer 资源清理闭合；opaque close 的原收据记录消费一次并正常返回，unbind 正常完成。原 public 的 `recovery_required=false / broker_outcome_unknown=false` 只说明**本轮已知调用者资源义务闭合**。`CloseProcessSecurityEnvironment` 是 [VOID 接口](https://learn.microsoft.com/en-us/windows/win32/api/processmodel/nf-processmodel-closeprocesssecurityenvironment)，没有可虚构的 HRESULT；正常返回不证明外部环境 absence、broker cancellation 或调用者崩溃时的自动清理。本轮不是进程崩溃机制试验。

[identity01](2026-10-23-psec-lpac-identity-01.md)原 public 的未知和恢复要求完整保留。02 的新收据不能逆向填补 01 丢失的结果，也没有重开、重放或重试关闭旧 opaque 值。

## Job 契约边界与下一步

[独立实际审查](../../verification/windows-2026-10-22/psec-lpac-identity-source-review-02/actual02-independent-review.json)、[Job 约束审查](../../verification/windows-2026-10-22/psec-lpac-identity-source-review-02/psec_lpac_joblist_constraints_02.json)及[只读 query 契约](../../verification/windows-2026-10-22/psec-lpac-identity-source-review-02/psec_lpac_job_query_contract_03.json)分别记录实际事实、官方契约和未实测的观察方案。通用 [JOB_LIST 文档](https://learn.microsoft.com/en-us/windows/win32/api/processthreadsapi/nf-processthreadsapi-updateprocthreadattribute)与 [IsProcessInJob 文档](https://learn.microsoft.com/en-us/windows/win32/api/jobapi/nf-jobapi-isprocessinjob)不构成本轮 CPSE 组合已保留全部属性的证明。[固定 G 源码](https://github.com/microsoft/mxc/blob/7bf210247986cb73b1b314df60c2f1109c479c0b/src/mxc-sdk/src/backends/process_container/common/base_container_runner.rs#L938)采用创建后、恢复前的 Job assignment；它不能证明本项目要求的 atomic JOB_LIST 行为，不能据此替换当前准入门，也不能推断所有 attributes 都被忽略。

正常退出路径上持有进程句柄并明确停止子进程，不证明调用者在创建或句柄交接期间崩溃时，未入 Job 的子进程会自动停止。后续构造前必须先审查这个可能的监督空档；最小观察方案是独立保存 exact inner/outer 查询的 API success、membership、error、held generation/image、原 F/T0/D 与临时 QUERY handle 单次关闭，再保留原两项都 true 的准入要求。不能改为 any-Job、自动 post-assign、恢复 actor、放宽能力、猜 flag、重启服务或续预算。这份文档及发布脚本没有授权或执行新的构造。

## 构建、纯测试、CI 与历史结果

[source-review02 索引](../../verification/windows-2026-10-22/psec-lpac-identity-source-review-02/index.json)保存四文件增量 patch/freeze、33 项 targeted pure、独立源码审查和实际审查。本机完整身份纯测试为 863 项、49.893 秒、零失败、2 个原有 symlink 权限 skips；[该源码自动 CI](https://github.com/Shermanxwz/Rule-proxy-Web/actions/runs/39873635408)为 863 项、55.383 秒、零 skips，5–9 号 gated runtime 步骤均跳过。纯测试和 CI 不抵消真实 Job 准入失败，未在本机执行 Linux 验证。

native/DLL 仍是 [source-review01](../../verification/windows-2026-10-22/psec-lpac-identity-source-review-01/index.json)的编译前 6 source + 31 dependency 快照：x64 `/MT` DLL SHA256 `9574f93eb562a858b207412f9f538b15bfbf329b1df284b3266496b4c2cf2ba5`，静态 imports 仅 KERNEL32、8 exports。本轮仅改变 Python 观察与报告，未把旧编译失败追认成成功。公开日志/patch 若需脱敏或 LF 视图，原始与公开 bytes/SHA 及差异会分别列出；可执行源码仍以受测提交为准。

before/after02 两份全局快照均为 7378 字节、SHA256 `f05d91ee76ee8a97ae5ab3bfa092167a8ee560c083255f142e6c453f2edf7ab3`，四对象及原字节相同，仅覆盖 firewall profiles、DNS、routes、user proxy，不含 NRPT，也不证明持续或全面 absence。

这是独立 `identity-only-deny-all-v1`，无 proxy/peer，两臂预期只改 AAP policy 0/1，原 root120/worker115，不另加 SECURITY_CAPABILITIES；本轮只走到首臂 Job 拒绝。[standalone semantic-LPAC DNS02](2026-10-23-lpac-semantic-dns-02.md)的 API/query `5/5` 和前后正控成功保持独立，[原 G/PSEC DNS API 泄漏](2026-10-23-selected-dns-standard53.md)也仍成立。PSEC+LPAC 完整身份组合、相同代理策略及真实代理/DNS 矩阵仍未验收，`model2_policy_compared / proxy_tested / dns_tested / product_acceptance` 均为 false。
