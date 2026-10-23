# PSEC + LPAC postassign01：Job 转移通过，LPAC 首项访问结果不符

**本轮为 `inconclusive / accesscheck`。** 独立 post-assign constructor 已完成两臂创建、受持有的 outer-only 前门、各一次 inner Job assignment、后续双 Job 与 primary 身份准入。AC 四项 AccessCheck 为 `[3,0,1,2]`，通过预声明矩阵；LPAC 只执行第一项 `combined`，API成功、AccessStatus=true、GrantedAccess=3、PrivilegeCount=0，预期应为2，因 `mask` 停止。后三项未执行，**没有完整 LPAC 向量**，不能填成 `[3,0,1,2]` 或其他矩阵。

这是新 scope `one-local-cpse-deny-all-outer-guarded-postassign-identity-v1`，constructor policy 为 `outer-guarded-held-explicit-inner-assignment-v1`。受测提交 `953de0a2374aff89959957da4b5641ce5aaff8a1`，36文件运行闭包 `d625a45670dc4b544c73e7dfb0acb55f483064dca23495e5e12f9dcbf8705f9f`。[原 public](../../verification/windows-2026-10-22/psec-lpac-postassign-identity-local-01-public.json)为2408字节，SHA256 `3862644d9d75b0e44a52c4bf2e0be063314dd6418e9e2fff6d5acca1fdaf0bd0`；[证据索引](../../verification/windows-2026-10-22/psec-lpac-postassign-identity-local-01-evidence-index.json)绑定15份原始 public、manifest、构建快照、归档器和安全投影。

## 本轮真实链路与部分 proof

新 DLL constructor 明确只设置 SE_ENV 与 AAP policy 两项属性，省略 JOB_LIST，也不追加 SECURITY_CAPABILITIES；Python owner 在独立门内做显式 assignment。这与旧 atomic constructor 是不同路径，没有在旧 scope 中 fallback，也没有回写旧测试结果。

两个原始 pretransfer 观察都记录 inner membership=false、named outer membership=true；每项 API均成功、立即error=0。held generation 与 image/hash 前后核验后，临时 QUERY 句柄已单次消费关闭、无 protected alias，才持久写 assignment intent 并调用一次 `AssignProcessToJobObject`。两臂原 BOOL均为1、立即error=0，处于原 work cutoff 内；随后13份 exact Job 观察均为 inner=true、outer=true，身份准入通过。原始 PI、query、intent、BOOL、配置、原F/D及磁盘原字节分别绑定。[转移投影](../../verification/windows-2026-10-22/psec-lpac-postassign-identity-local-01-inner-transfers-projection.json)与[后置 Job 投影](../../verification/windows-2026-10-22/psec-lpac-postassign-identity-local-01-job-admissions-projection.json)保留这些事实，不公开 HANDLE、PID、SID、Job 名称、创建时间或原QPC。

[组件投影](../../verification/windows-2026-10-22/psec-lpac-postassign-identity-local-01-component-projection.json)保存两份 proof：AC有四个实际调用、qualified=true；LPAC原件只有一个实际调用、qualified=false、failure=mask。LPAC的 `observed_matrix` 为null，`world/aap/arap` 明确列为未执行；expected matrix仅说明预声明目标，不是观测数据。此结果不等于 Win32 API报错或访问被拒绝，也不支持把完整 LPAC 身份、AAP policy被忽略的原因、或整个 PSEC 属性处理方式定论化。

六份 native返回收据对应 `bind/create/ac/lpac/close/unbind`；九份调用者意图、两份 pretransfer 收据、四份 assignment意图/返回收据及13份后置 Job 收据均核对。forensic result与有效 worker result逐字节一致，且原件与独立实际审查的八项私有摘要相符；forensic单独存在不能提供 held worker资格。所有 actor始终 suspended，没有 Resume、GO、DNS、网络或代理测试。

## 清理与尚未证明的边界

worker自然退出0，两臂 held exit1均确认；已知 child、Job、句柄、observer和查询资源清理闭合。原 VOID close消费一次并正常返回，unbind正常完成。本轮 `recovery_required=false / broker_outcome_unknown=false` 描述已知调用者资源义务，不证明外部环境 absence、broker cancellation或调用者崩溃时等价清理。

原 public 中 `atomic_inner_creation_proven`、`continuous_outer_supervision_proven`、`creation_transfer_crash_gap_resolved` 始终为false。离散的 pre/post membership观察不证明创建/交接全程连续监督，也没有演示 caller死亡机制；[VOID close契约](https://learn.microsoft.com/en-us/windows/win32/api/processmodel/nf-processmodel-closeprocesssecurityenvironment)没有可虚构的 HRESULT。这些门没有因本轮正常清理而提升。

[旧 identity03](2026-10-23-psec-lpac-identity-03.md)仍是原 atomic路径 inner=false、outer=true；[identity02](2026-10-23-psec-lpac-identity-02.md)仍保留未分离 inner/outer的历史。旧 [identity01](2026-10-23-psec-lpac-identity-01.md)的原 unknown/recovery要求保持，不由新 scope 的成功清理清除，也没有重开、重放或重复关闭旧 opaque值。

## 源码、编译、纯测试与CI

[source-review索引](../../verification/windows-2026-10-22/psec-lpac-postassign-identity-source-review-01/index.json)保留 native增量、Python初始 ACTUAL_READY=false 的四文件 patch/freeze/ABI和纯日志，以及根明确授权的promotion02原件；promotion只把就绪标记改true，仍需独立 CLI opt-in、原 source/device/artifact/spec/plan、held guard/worker与root120/worker115。没有把“source ready”当成实际实验成功。

此轮只新增五个源码/测试文件。新运行闭包为34个共享文件加2个新模块；原36 runtime、原37 native及既有 tests/archives保持。新native闭包为5个共享source、新cpp和31个dependency。新DLL为x64 `/MT`、214528字节、SHA256 `5db0d4db168074a64b3c042b1be86954edaf7138e643c01fdd3625264a8b8f64`；library ABI2、payload布局V1，manifest闭合15键，静态 imports仅 KERNEL32、8 exports。compile-only构建及独立PE审查本身没有加载DLL或执行CPSE，真实运行证据独立归档。

promotion02作者纯测试50项、12.045秒、零失败/零skip；两份新测试文件的AST方法数为34+16，因此全量预期由旧872+新增50得到922，没有把旧327条 compiled fake断言重复算作测试。根本机完整纯测试实际922项、68.700秒、零失败、2个原有 symlink权限skip，独立审查另行保存。本机未执行Linux验证。

归档器自身的work-only纯日志另存：初期一次字段投影自测失败与修正后5项通过，均为文件/fake校验，不是实际机制失败或重跑，也不计入上述922项。

[该源码自动CI](https://github.com/Shermanxwz/Rule-proxy-Web/actions/runs/39880370248)为run `39880370248` / job `120176045759`，completed/success：922项、53.368秒、零失败/零skip，5–9号gated runtime步骤均跳过。它只提供 compile/pure证据，没有实际PSEC/LPAC、isolated runtime或网络验收，也没有dispatch/rerun。原decoded日志219702字节、SHA256 `550479f04800ce614650f78d477a407b8fa5cd1e86e6e935f0f556b33f2dcc22`，为UTF-8 BOM/CRLF文本，不冒称raw ZIP；公开视图与原件分别承诺。

before/after快照各7378字节、SHA256 `f05d91ee76ee8a97ae5ab3bfa092167a8ee560c083255f142e6c453f2edf7ab3`，与初始baseline原字节一致。只覆盖firewall profiles、DNS、routes、user proxy四对象，不含NRPT，也不证明持续或全面 absence。

本 scope仍是独立 `identity-only-deny-all-v1`，无proxy/peer；不是原Model2代理策略的相同配置比较。[standalone semantic-LPAC DNS02](2026-10-23-lpac-semantic-dns-02.md)的API/query `5/5`及前后正控保持独立，[原G/PSEC DNS API泄漏](2026-10-23-selected-dns-standard53.md)仍成立。`network_tested / dns_tested / proxy_tested / model2_policy_compared / product_acceptance` 均为false，完整PSEC+LPAC身份、代理和DNS矩阵尚未验收。
