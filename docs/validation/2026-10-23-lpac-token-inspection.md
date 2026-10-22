# LPAC03/04：203 创建失败与 class46 查询未知

**LPAC DNS 仍未实际调用。** LPAC04 已创建并持有进程，但身份查询返回 Win32 错误 87，因此没有准入、恢复 actor 线程或发布查询。专用 profile、ACE、Job 和持有句柄均已自动清理。此前 [G/PSEC DNS01 的明确泄漏](2026-10-23-selected-dns-standard53.md)仍成立；当前不能验收为 Linux 等效。

这两轮接续 [LPAC01/02](2026-10-23-lpac-dns-mechanism.md)。原失败和独立恢复历史不改，03/04 均无需另做恢复。

| 项目 | LPAC03 | LPAC04 |
| --- | --- | --- |
| 受测源码提交 | `88db09f422e069ecd8dae78a4b2676c592e08fb2` | `61fb136c320e94299d716f0a66da603e2776bcb2` |
| 31 源闭包 | `390056b6964a75bda0f22e4840efbbe445786be2272d96f4a3b5f3a158be9db9` | `b56c2f2da311585b8fbc6098168f4a83109bfe750eaf2b779a68e4e23445778c` |
| 原公开结果 | [public03](../../verification/windows-2026-10-22/lpac-dns-local-03-public.json) | [public04](../../verification/windows-2026-10-22/lpac-dns-local-04-public.json) |
| 原结果 SHA256 | `29842bfff9e8f81912aef8d0aa974e664ad7563b47de8810d0a8613b5ab19e49` | `84bc181c0711d70526b585591d5ab575b513542b0447476d8a57281971a285f1` |
| 原结果字节 | 1342 | 1342 |
| 状态 | inconclusive / setup | inconclusive / setup |
| selected 创建 | API 返回 FALSE，错误 203，PROCESS_INFORMATION 四项全零 | API 返回 TRUE，PROCESS_INFORMATION 非零，获得持有进程及代际 |
| selected 退出 | 未创建，不伪造退出码 | 所有者清理确认退出 1；未执行 actor 协议 |
| LPAC 身份 | 未查询 | class46 查询错误 87，无有效 payload，仍为 unknown |

## LPAC03 的精确创建返回

04/05 源码修补增加创建状态、紧邻 API 返回取得的 Win32 错误、PROCESS_INFORMATION 状态和原时限内观察 QPC。Python 调用异常和被 finally 二次异常覆盖的原始原因只存入有界私有诊断，不进入公开输出。[04/05 审查归档](../../verification/windows-2026-10-22/lpac-dns-diagnostic-review-04-05/receipt.json)保留两个补丁及纯测试记录；04 版本未实际运行，05 对应实际 LPAC03。

LPAC03 的 selected API 明确返回 FALSE、错误 203；本机 SDK `winerror.h` 将其定义为 `ERROR_ENVVAR_NOT_FOUND`。仅当非零错误、四个 PROCESS_INFORMATION 输出全零、原 work cutoff 内有可信观察、没有 PID/句柄所有权/准入/恢复/退出/GO 时，新 owner 才把它判作已知未创建，并从需要停止的内部 child view 排除。原始行仍为 `attempted=true`、`exited=false`、`exit_code=null`；没有伪造进程退出。异常、错误 0、任何部分返回、迟到、未知时钟或关闭不确定均继续保守处理。

[03 组件投影](../../verification/windows-2026-10-22/lpac-dns-local-03-component-projection.json)和[证据索引](../../verification/windows-2026-10-22/lpac-dns-local-03-evidence-index.json)核对 31 份 Git blob/LF 源码、原始报告、10 份意图和 18 个 stdio 文件。四个 grant 工具及一个 remove 工具都经过 held ordinary 准入并自然退出 0。没有 selected actor、health actor、READY、GO、库存、receiver 或 DNS 查询。

203 只属于本轮保留下来的返回值，不回推 LPAC02 也曾返回 203，也不证明唯一根因。

## LPAC04 接回既有环境契约

新入口此前给 selected 使用普通进程的四键环境，遗漏了项目早先 AC 入口中经过验证的 KnownFolder 流程。06 修补在 Job/profile/ACL 设置之前，复用既有 `local_appdata` 与 `front_environment`：在原 QPC budget 下初始化 COM、解析并检查 LocalAppData 路径、释放结果、完成 COM 清理，再构建仅含 `SystemRoot/LOCALAPPDATA` 的子环境。普通工具继续使用 `SystemRoot/WINDIR/TEMP/TMP`；没有继承整份环境、猜测路径、读取注册表作为替代，也没有修改系统或用户环境变量。

LPAC04 的私有环境 metadata 为 `ready`、HRESULT0、COM `[true,0,true,true]`，释放、原 deadline 和精确两键检查均通过。selected 随后创建成功，持有进程的 Job/映像/代际检查进入 token 准入步骤。这是本轮构造成功的事实，不把跨轮变化升级成唯一原因或可移植性保证。

准入在 `GetTokenInformation(TokenIsLessPrivilegedAppContainer)` class46 返回 87 时停止。**这里的 87 来自 token 查询，与历史 `DnsQueryEx` 错误 87 是不同调用。** 失败查询没有有效 payload，不能解释成 LPAC=false，也不能根据请求过 OPT_OUT 就自行认定身份。selected 未准入、未恢复线程；已有原始行的 identity/capabilities/lpac 三元组尚未成功赋值，不能把它们补成已验证身份。

[04 组件投影](../../verification/windows-2026-10-22/lpac-dns-local-04-component-projection.json)和[证据索引](../../verification/windows-2026-10-22/lpac-dns-local-04-evidence-index.json)保留真实创建、查询失败和退出语义。held selected 被精确清理为 1，四个 grant 与 remove 工具自然退出 0；没有 health、native READY、GO、DNS 库存、fixture 或查询。

## 清理与测试

两轮的 workload/fixture/ACL/tools/profile/SID 与 outer cleanup 均闭合，`recovery_required=false`。没有另造恢复证据。两轮 after 快照都为 7378 字节、SHA256 `f05d91ee76ee8a97ae5ab3bfa092167a8ee560c083255f142e6c453f2edf7ab3`，与最初 baseline 字节相同；比较对象是 firewall profiles、DNS、routes、user proxy，快照不含 NRPT。没有防火墙、DNS、代理、NRPT、路由、组成员或祖先 ACL 修改。

两轮继续使用原 native07 actor、9 个 native source pins、13 个 manifest 字段；没有重编译 native actor。root 仍为原始 120 秒、worker reserve 5 秒；没有给原运行续期或自动 fallback。

05 源码完整纯测试为 754 项、33.283 秒、零失败、2 项原有本机 symlink skips；其[自动 CI](https://github.com/Shermanxwz/Rule-proxy-Web/actions/runs/39859244375)为 754 项、25.412 秒、零 skips。06 的 37 项 targeted 测试及 757 项完整纯测试（33.785 秒、零失败、2 项原有 skips）通过；其[自动 CI](https://github.com/Shermanxwz/Rule-proxy-Web/actions/runs/39860248347)为 757 项、37.480 秒、零 skips。两次 CI 的 5–9 号 gated runtime steps 均跳过，编译的是基础 identity actor；没有执行 LPAC 或 DNS。

## 独立身份方法的后续范围

原 class46 入口保持失败即停止。另一个无网络候选采用受持有 token 的四个内存授权描述符，比较同一 fresh package、相同精确 capabilities、环境和原子 Job 构造的 AC/LPAC 两臂；两者均不恢复线程。候选使用文档化的 token duplicate 与 AccessCheck，并以固定 [Chromium CheckLpacToken](https://github.com/chromium/chromium/blob/fedbb89ecd801ed0ad1d34eb5784c3bb03a8534e/sandbox/win/src/app_container_test.cc#L109)为 combined 描述符参考。其余控制矩阵是本项目预声明的实验，不能说成 Chromium 已实测。

必须先确认 API 本身成功、完整 held 身份/精确 capability catalog/映像/Job/代际绑定、两臂预声明矩阵及所有资源清理，再讨论有限授权语义；API 失败或纯 fake 测试均不能作身份通过。该独立候选目前没有实际结果，不是 Microsoft 专用 IsLPAC 契约的保证，也没有修复 PSEC 代理链或 DNS。

当前 `g_psec_tested`、`proxy_tested`、`default_resolver_tested`、`dns_isolation_qualified`、`product_acceptance` 仍全部为 false。
