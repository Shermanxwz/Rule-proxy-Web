# Standalone LPAC DNS：创建阶段的两次停止与独立恢复

截至本检查点，**LPAC DNS 尚未实际调用，不能计为 DNS 阻断成功**。两次入口都在 DNS 库存、receiver bind、查询 GO 之前停止。此前 [G/PSEC DNS01 的明确泄漏](2026-10-23-selected-dns-standard53.md)仍成立；本页没有提供 Linux 等效或代理修复的验收。

## 入口与判定范围

新入口 `.github/windows_identity_lpac_dns_local.py` 默认只做只读 preflight。实际执行需要显式 opt-in，以及绑定本设备、31 份源码闭包、原生 actor、manifest 的恢复计划。工作进程处于外层原子 Job，每个内部进程在创建时加入内部 Job；映像、进程代际、持有 token、Job、原始 QPC 时限均需检查。

受测构造使用 fresh profile、精确 `AgenticAppContainer + privateNetworkClientServer` 两个 capability、`ALL_APPLICATION_PACKAGES_POLICY=OPT_OUT`。只允许本轮专用目录中该 profile SID 的 ACE。没有扩大祖先目录 ACL，没有增加 capability，没有调用 G/PSEC，也没有建立代理链。只有身份检查成功，才允许恢复 actor，再运行 ordinary 同 API 前后正控及专用 `127.0.0.1:53` UDP receiver；两轮均未到达该处。

构造事实、身份观察、API 状态与 receiver 观察分别保存。API 错误 87、超时、接收端静默和未启动进程均不能转成访问拒绝。`DnsQueryEx` 原生结构的 raw QueryStatus 在错误返回时可能仍为初始 0；成功资格同时要求 API 与 QueryStatus 为 0，不从单个 0 推断成功。

## 实际尝试

| 项目 | LPAC01 | LPAC02 |
| --- | --- | --- |
| 受测源码提交 | `de69fa49b5766d8a7a5bb61567e52410759df089` | `524638057f1b60a3292964162fe70305fbea8e3e` |
| 31 源闭包 | `a1b924f5edee5b0e279fa14f35319ad9ee835c243696526e13e72a80b62bc792` | `96e1b3c439c7b33c7b01820f65c411558b1e5685b994cc09c2cf174b14e483d1` |
| 原公开结果 | [public01](../../verification/windows-2026-10-22/lpac-dns-local-01-public.json) | [public02](../../verification/windows-2026-10-22/lpac-dns-local-02-public.json) |
| 原结果 SHA256 | `a815d1b6a321e98c06048d95d983c845b7cc995e1fb216dfe1afe810ff2d75f6` | `648a28df4868236ecc179b1a410b8c8539290577bc9677e0aa78f1cb7abe3b91` |
| 原结果字节数 | 1343 | 1345 |
| 原状态 | inconclusive / setup / recovery_required=true | inconclusive / setup / recovery_required=true |
| selected 准入、恢复线程、DNS 查询 | 均未发生 | 均未发生 |

LPAC01 已创建专用 profile，但首个 grant 工具及后续 remove 工具都未通过 held admission，线程未恢复，随后各被所有者终止为 1。源码把普通工具也送入 class46 查询。单独的[本机普通 token 只读观察](../../verification/windows-2026-10-22/lpac-dns-ordinary-token-readonly.json)返回 WinError87，并确认查询 token 已关闭；它与失败位置相符。原 worker 未保存更细的异常码，因此不能从这份事后观察排除实际路径中其他较早检查失败。

03 修补先检查普通 token 的非 AppContainer、零 capability、同用户/session、primary、非提升等事实，普通工具的 `lpac=null` 明确表示**未查询**，不伪造读回 0。selected 的原 class46/4-byte/值 1 门仍保留；查询错误仍禁止 resume 和 GO。

LPAC02 的四个 grant 工具都经过 held ordinary、双 Job、映像和代际检查，正常恢复并自然退出 0。接着 selected 到达创建边界，记录为 `attempted=true`、`process_returned=false`，未返回 PID、代际或持有进程。该版没有保存紧邻 CreateProcess 返回的状态及 Win32 错误，**无法从原件区分 native 返回 FALSE 与调用过程异常，也不能归因 class46、ACL 或某个特定错误码**。没有 selected/health 原生报告，没有库存、receiver、GO 或 DNS 调用。

两次都保留了原始 120 秒 root epoch，未给原实验续期。两次使用相同 native07 actor（SHA256 `0a9e867cce846b366693e8662034db8c0c4646bd312a6143c367da2c36fb557a`）、9 个 native source pins 和 13 个 manifest 字段；没有重编译或替换 actor 来追求成功。

## 独立恢复

[recovery01](../../verification/windows-2026-10-22/lpac-dns-local-01-recovery-public.json)和[recovery02](../../verification/windows-2026-10-22/lpac-dns-local-02-recovery-public.json)均实际通过。它们是新的、独立受监督的恢复操作；原 public 中的失败、cleanup 和 recovery_required 字段没有重写。

恢复在导入 staged Python 之前用 stdlib 校验固定原 report、config、31 份源码及闭包，并绑定原设备、计划、profile name/SID。LPAC01 确认两个旧工具从未恢复、旧 Job 不存在、全树没有该 SID 的 ACE，持久化并读回精确删除意图后，仅删除该 fresh profile。

LPAC02 保留原 unknown-create 状态；恢复依据固定源码中的原子 JOB_LIST、KILL_ON_CLOSE、CREATE_SUSPENDED、没有 resume/fallback，以及已确认的 worker 退出和原 Job-empty 收据，再核旧 outer Job 不存在、四个旧工具代际已退出、两次受界限精确 actor 映像 census 无存活命中。未知查询不被当作不存在。仅在原精确 SID ACE scope 全树一致后，启动新的 held ordinary、原子 Job 受监督 `icacls /remove:g`，只移除该 SID；退出 0、工具和外层清理确认、全树 ACE 为空之后，才持久化删除意图并删除精确 profile。没有按裸 PID 杀进程。

两次恢复后的只读全局快照均为 7378 字节、SHA256 `f05d91ee76ee8a97ae5ab3bfa092167a8ee560c083255f142e6c453f2edf7ab3`，与最初 baseline 字节相同。比较对象为 firewall profiles、DNS、routes、user proxy；**该快照不包含 NRPT**。本轮没有运行 DNS 库存，不宣称新鲜 NRPT=0。没有进行防火墙、系统 DNS、代理、NRPT、路由、组成员或权限提升设置变更。

## 审查与纯测试

[初版审查历史](../../verification/windows-2026-10-22/lpac-dns-candidate-review/receipt.json)保留初版完整 patch、ABI、freeze，以及四个被独立探针接受的无效证据组合。最初 737 项纯测试通过仍不足以覆盖它们；实际运行前已修复 public 完整承诺、profile/ACL 意图、外部可信 capability catalog 和 phase 不早于 GO 四道门。修补后独立四探针全部拒绝，741 项完整纯测试零失败，2 项为原有本机 symlink skips。

[普通查询适用性修补收据](../../verification/windows-2026-10-22/lpac-dns-owner-ordinary-fix-03-pure-tests.json)绑定 24 项 targeted 测试及 744 项完整纯测试（32.428 秒、零失败、2 项原有 symlink skips）。对应源码的[自动 push CI](https://github.com/Shermanxwz/Rule-proxy-Web/actions/runs/39855754660)也通过，744 项、36.710 秒、零 skips。该 CI 仅编译基础 identity actor 并运行纯测试；5–9 号 gated runtime steps 均跳过，没有运行 LPAC 或 DNS。CI 成功不是实际隔离结果。

## 下一步

先给创建调用增加闭合的原始返回值、紧邻错误码、PROCESS_INFORMATION 状态及异常观察，保留部分创建与未知状态，不猜测历史错误。当前 class46 的用户态适用性也尚未实证；Microsoft 的 [Win32 enum](https://learn.microsoft.com/en-us/windows/win32/api/winnt/ne-winnt-token_information_class)说明 LPAC 忽略 ALL_APPLICATION_PACKAGES，但没有给出该项与 TokenIsAppContainer 同等明确的输出描述。

后续候选可用文档化 [DuplicateTokenEx](https://learn.microsoft.com/en-us/windows/win32/api/securitybaseapi/nf-securitybaseapi-duplicatetokenex) 和 [AccessCheck](https://learn.microsoft.com/en-us/windows/win32/api/securitybaseapi/nf-securitybaseapi-accesscheck)检查 held token 的授权语义；Chromium 固定源中的 [CheckLpacToken](https://github.com/chromium/chromium/blob/fedbb89ecd801ed0ad1d34eb5784c3bb03a8534e/sandbox/win/src/app_container_test.cc#L109)提供实现参考。必须先做同构造 AC/LPAC 无网络对照、检查 API 本身成功与资源关闭，不能把 class46 错误改成 false 或直接绕过身份门。该候选尚未实际运行，也不是 Microsoft 专用 IsLPAC API 的契约保证。

即便 standalone LPAC 后续出现有限 API5 观察，仍需证明 G/PSEC 网络策略、真实代理正向、direct/wrong-port/wrong-peer/death 及 DNS 前后正控能在同一受测构造中同时成立。当前 `g_psec_tested`、`proxy_tested`、`default_resolver_tested`、`dns_isolation_qualified`、`product_acceptance` 全部为 false。
