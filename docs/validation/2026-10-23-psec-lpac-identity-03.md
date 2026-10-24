# PSEC + LPAC identity03：outer 成员关系成立，inner 成员关系未成立

**本轮仍为 `inconclusive / admission`。** 首臂 policy 0 创建返回完整 PI；随后两个独立 `IsProcessInJob` 调用都返回 API success，inner membership 为 **false**，named outer membership 为 **true**。准入正确停止。尚未读取首臂 primary token，没有尝试 LPAC 第二臂，没有 AccessCheck proof，也没有 actor resume、DNS、网络或代理验收。

受测源码为 `4c5878ba0ffa6f4b938e26bf5c8c016b7042b333`，36 文件闭包为 `cf09c9c86adf9f7af3fb3d71bdde6cd1fd4fa7000a8eb01cc5ebc71b3ea5d682`。[原 public](../../verification/windows-2026-10-22/psec-lpac-identity-local-03-public.json)为 2083 字节、SHA256 `75f3198b40afc5b9919fd862b66ab14b023b4b30e4ab979b742cf3e315e734f6`。[证据索引](../../verification/windows-2026-10-22/psec-lpac-identity-local-03-evidence-index.json)、[组件投影](../../verification/windows-2026-10-22/psec-lpac-identity-local-03-component-projection.json)及[Job 准入投影](../../verification/windows-2026-10-22/psec-lpac-identity-local-03-job-admissions-projection.json)绑定原报告与磁盘收据。

## 本轮取得的证据

源码03只修改 Python core 与其纯测试，运行源码其余35文件及 bridge 的6 source、31 dependency 保持不变。此次增加独立 inner/outer 查询记录，保留两项 exact membership 都为 true 的原准入门，没有 assignment、fallback、恢复 actor 或新窗口。

唯一初始 Job 观察以 held 进程 generation、精确 actor image/hash 前后夹持。两次查询的 API success、membership、立即 Win32 error 和原预算时限分别保存：inner 为 `true / false / 0`，outer 为 `true / true / 0`。两端 generation/image 均核验，查询均在原 work cutoff 前。named outer 只以 QUERY 权限打开；临时句柄与已知持有句柄无别名，单次消费关闭正常，查询资源清理已确认。磁盘原始 Job 收据为2285字节、SHA256 `bb4682cb27f869e49051c813525f8abf2690edee4b7a88d08a2c05d7bd50d68e`；公开投影不包含 HANDLE、PID、SID、Job 名称、创建时间、绝对路径或原 QPC。

原失败标签为 `cpse_exact_jobs_not_admitted`。API 成功只说明调用成功，不代表 membership=true。此轮足以区分两个 Job：inner 未满足，outer 满足；这没有逆向补写 [identity02](2026-10-23-psec-lpac-identity-02.md)原件中“不能区分 inner/outer”的历史事实。

`bind/create/ac/close/unbind` 五份原始返回收据、`bind/create/ac/stop/close/unbind` 六份意图、一个 Job 收据和零份 proof 均已核验。forensic result 与有效 worker result 逐字节相同；单独的 forensic 文件不提供 held worker 资格。worker 自然退出0，首臂 held exit1已确认；首臂 `assigned/admitted/primary_snapshot_available` 均为 false。没有 LPAC 第二臂或身份矩阵，不将缺失字段补成通过。

已知 child、Job、HANDLE、查询和 observer 资源清理闭合，VOID close 消费一次并正常返回，unbind 正常完成。原 public 的 `recovery_required=false / broker_outcome_unknown=false` 仅描述本轮已知调用者资源义务闭合。[VOID close 契约](https://learn.microsoft.com/en-us/windows/win32/api/processmodel/nf-processmodel-closeprocesssecurityenvironment)不提供可虚构的 HRESULT，正常返回不证明外部环境 absence、broker cancellation 或调用者崩溃时等价清理。旧 [identity01](2026-10-23-psec-lpac-identity-01.md)未知及恢复要求完整保留，不能由03收据清除。

## 属性与监督边界

构造源码声明了 SE_ENV、JOB_LIST、AAP policy 三项属性。此轮的 exact inner membership=false 表明所需 inner Job 准入未成立；它不能解释原因，也不能推出全部属性均被忽略。没有把 outer=true 偷换成双 Job 准入成功。通用 [JOB_LIST 文档](https://learn.microsoft.com/en-us/windows/win32/api/processthreadsapi/nf-processthreadsapi-updateprocthreadattribute)和 [IsProcessInJob 契约](https://learn.microsoft.com/en-us/windows/win32/api/jobapi/nf-jobapi-isprocessinjob)不替代组合实测。

此轮观察的是正常、持有句柄的路径，并非调用者崩溃试验；outer membership=true 也不构成创建/交接全过程无监督空档的证明。本轮没有执行新的 post-assign 构造，不授权在原 variant 中自动替换或降级。后续任何不同 constructor 应使用独立预声明 scope、保留原120秒根预算和准入/清理门，重新审查其崩溃与 opaque 资源边界。

## 纯测试、CI 与全局快照

[source-review03 索引](../../verification/windows-2026-10-22/psec-lpac-identity-source-review-03/index.json)保存两文件增量 patch/freeze、ABI、独立源码审查、实际审查及测试原件。本机完整身份纯测试为872项、50.703秒、零失败、2个原有 symlink 权限 skips；targeted 为42项、零失败/零skip。targeted **原始日志报告6.219秒，freeze 元数据写6.218秒**，两份原件分别保留，差异明确记录为0.001秒，未修改旧 freeze 或日志。纯测试通过不抵消实际准入失败，未在本机执行 Linux 验证。

[该源码自动 CI](https://github.com/Shermanxwz/Rule-proxy-Web/actions/runs/39876964598)已独立读取：run `39876964598`、job `120164793726`，状态 completed/success；872项、104.933秒、零失败/零skip。5–9号 gated runtime 步骤均跳过，本次只执行 actor compile-only 和 pure；没有 dispatch/rerun，也没有 isolated runtime 或 CPSE 身份实验成功的含义。原 decoded 日志为207436字节、SHA256 `026733c942fab57d2eec4e71113149b189156dad734cd5ab0e2803600e36c478`，是带UTF-8 BOM及CRLF的 decoded 文本，不冒称 raw ZIP；公开脱敏/LF视图及两套摘要由source-review索引分别承诺。旧源码CI仍只属于各自提交。

DLL 仍为 [source-review01](../../verification/windows-2026-10-22/psec-lpac-identity-source-review-01/index.json)的编译前快照：x64 `/MT`、SHA256 `9574f93eb562a858b207412f9f538b15bfbf329b1df284b3266496b4c2cf2ba5`、静态 imports 仅 KERNEL32、8 exports。原 native07 actor 与其9 source/13键 manifest 不变。公开文本若需要脱敏或 LF 视图，其原始和公开 bytes/SHA 及差异分别列出；可执行源码以受测提交的 Git blob 为准。

before/after03 全局快照各7378字节、SHA256 `f05d91ee76ee8a97ae5ab3bfa092167a8ee560c083255f142e6c453f2edf7ab3`，与最初 baseline 原字节相同。仅覆盖 firewall profiles、DNS、routes、user proxy 四对象，不含 NRPT，也不证明持续或全面 absence。

本轮仍是独立 `identity-only-deny-all-v1`，无 proxy/peer；两臂预期只改 AAP policy0/1，但实际仅走到首臂准入失败。[standalone semantic-LPAC DNS02](2026-10-23-lpac-semantic-dns-02.md)的 API/query `5/5` 与前后正控成功保持独立，[原 G/PSEC DNS API 泄漏](2026-10-23-selected-dns-standard53.md)仍成立。完整 PSEC+LPAC 身份组合、相同代理策略及真实代理/DNS 矩阵仍未验收，`model2_policy_compared / proxy_tested / dns_tested / product_acceptance` 均为 false。
