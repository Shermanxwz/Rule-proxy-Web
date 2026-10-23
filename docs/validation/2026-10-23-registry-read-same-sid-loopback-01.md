# registryRead LPAC 同 SID loopback01：初始化成功，socket 创建 10013

**本轮仍为 `inconclusive / loopback`：selected 的 `WSAStartup` 成功，但 `WSASocketW` 创建 socket 返回 `10013`，connect/send 均未尝试。** 这是 socket 创建阶段的 access-denied 观察，不能写成某个 peer/端口的连接拒绝、send 拒绝、主 pair 连通或任意直接出站已隔离。前端零 cap AC 真正监听成功，普通同 API 前后控制都成功，不能替代未发生的 selected 连接。

本次是独立显式 `one-local-registry-read-same-sid-loopback-v1` / `same-sid-registry-read-lpac-loopback-mechanism-v1`，受测提交 `d309ae322cca84360923d6bc51013057991a4218`；37 项源码闭包 SHA256 `069d9f2702e235f03603d11b5962f320fe0f077cd81ccfabafefd48cbd11dfb6`。仅有一次本机 actual，未 rerun。selected 是同一 fresh profile 的 LPAC primary，精确一个 `registryRead` capability、attributes4；前端 AC 与普通两个角色仍零 capability。这是能力不对称的新 scope，**不是 matched-capabilities 或 AAP-only 比较**，也没有添加 PNCS、InternetClient、Agentic 或运行时 fallback。

## 原始观察与边界

| 项目 | 本轮实际结果 |
|---|---|
| 外部 held 身份、原映像/hash/generation、精确 inner/outer Jobs | 已核验 |
| AC / LPAC 的四描述符 AccessCheck | `[3,0,1,2]` / `[2,0,0,2]`，真实资源闭合 |
| 零 cap AC front 的 bind/listen、独立 kernel listener PID | 成功 |
| 独立 ordinary before/after | 各64字节精确请求/响应及 EOF 成功 |
| selected | READY未启动WSA；读取GO后WSA成功；socket `10013`；未创建socket、未connect/send |
| 主 withheld 请求、双向半关闭 tuple、release、主响应 | 均未发生 |
| 原状态与资格 | inconclusive；reachability=false；全部广义资格false |

[原 public](../../verification/windows-2026-10-22/registry-read-loopback-local-01-public.json)为3038字节，SHA256 `641ea1db8e80b19da7778ad2180c83a6d63c2c0fc421276922f36e390da5b65f`。[证据索引](../../verification/windows-2026-10-22/registry-read-loopback-local-01-evidence-index.json)绑定原 preflight、公报、逐字节 runner、组件/矩阵/协议/全局/源码投影；独立文件复核为42527字节、SHA256 `7b1606aa434d5da2d78836dce65541b566e41571efc63539bfe44b7c43332e5f`。编译、pure、文件审计都没有被当成网络 actual。

selected 的闭合 phase 是 `failure=socket / WSA error10013`、`socket_close=not-created`、`connect_attempted=false`、`send_attempted=false`、WSA cleanup confirmed。前端等待本次未到达的请求至原 phase deadline，自然 typed failure；front/selected 都自然退出5，ordinary 两角色退出0，`workload_stop=false`，不能从非0退出推断 Job kill。ordinary worker 退出0只代表产生/验证失败报告，不代表实验成功。

native `network_tested` 仍只表示 connect-attempt/accepted-flow；selected 为false不抹去已实际调用 WSAStartup/WSASocketW 的事实。全局该 flag 为true来自普通正控。独立 TCP 原表只观察到前端 LISTEN，没有主 pair withheld 双向元组；公开只给 bytes/SHA 和核验布尔，不发布 PID、端口或原表。

## 为什么是独立 registryRead scope

此前[零 cap 两轮](2026-10-23-zero-cap-same-sid-loopback-01-02.md)分别停在控制文件 sharing32（01）和 WSAStartup10107（02）。两份原源码、公报及结论保持不变。本轮 WSAStartup 成功，是另一次不同声明能力/源码/actor 的观察，不能仅凭这组前后记录证明旧10107唯一由 catalog 访问造成，也不能把旧02回写为网络拒绝。

[研究收据](../../verification/windows-2026-10-22/registry-read-loopback-source-review-01/lpac-registry-read-winsock-research-01.json)保留只读能力派生、系统 catalog ACL 和 primary source 线索：`10107` 是通用系统调用失败，未做失败调用 trace 或 effective-access 归因。已读 catalog 根含 `registryRead` 与 AAP ReadKey ACE，系统 DLL 另含 ARAP ReadAndExecute；没有据此证明网络授权。`registryRead` 可使 token 读取**其他原本带此 capability ACE 的 registry 对象**，范围不限 Winsock catalog，因此已通过独立 scope/plan ack 明示影响；没有更改任何这些 registry DACL 或全局配置。任意 `lpacNetworking` / `lpacNetwork` 名称都能派生 SID，不能仅凭名称把它当可行修补。

本轮 socket10013 的具体拒绝来源未归因；没有 WFP drop、broker sender 或 endpoint trace。不得自动追加能力、取消 LPAC、设置 loopback exemption，或把 socket 创建失败扩大为 Windows 整体网络隔离结论。

后续[primary-source 研究](../../verification/windows-2026-10-22/registry-read-loopback-source-review-01/lpac-socket-primary-research-findings-01.json)没有建立一个“仅 loopback”的 LPAC socket capability；PNCS 的声明覆盖家庭/工作网络入站与出站，范围更宽，Chromium 的 Network LPAC 是多能力组合，不能拆出一个已证最小 AFD 前提。当前也未诊断出导致10013的精确 AFD 对象/ACE，尚未运行任何据此产生的新能力方案。

[broker transport 可行性](../../verification/windows-2026-10-22/registry-read-loopback-source-review-01/lpac_brokered_transport_feasibility_01.json)区分合作传输与隔离保证：[WSADuplicateSocket](https://learn.microsoft.com/en-us/windows/win32/api/winsock2/nf-winsock2-wsaduplicatesocketa)传递可重建、共享状态的 socket 描述，不提供 send/receive-only 或 immutable-peer 合同；[DisconnectEx 的 TF_REUSE_SOCKET](https://learn.microsoft.com/en-us/windows/win32/api/mswsock/nc-mswsock-lpfn_disconnectex)还允许之后通过 AcceptEx/ConnectEx 重用。不能把“当前已连接一个 peer”写成永远不能换目标，也未验证本 LPAC 能成功导入该 socket。保留所有 raw socket 在 ordinary broker、只交固定有界 IPC channel 是一个可独立验证的合作机制方向；它需要应用/协议适配，不能透明替代任意应用的 TCP proxy，更不是 Linux 等效、DNS修复或强制所有API都经该broker。研究及其10份大型 primary blob 仅公开有界 findings/index、原件hash与URL，不整包复制；没有运行新IPC/socket传递实验。

## 监督与已知清理

原 root120秒/worker115秒、有限 phase 与 reserve 保持。四 actor 任何 Resume 前都经外部 held primary、role-specific capability、同 user/session、映像/hash/generation 与精确双 Job；真实 AC/LPAC 矩阵及 observer token/descriptor 资源先闭合。没有 class46 查询，没有以 actor 自述或观测自适应放行。

仅两处 fresh 输出子树取得该 profile 的 Modify 与 Low mandatory label，inputs/control 保持只读。已知 workload 退出、Job empty、句柄和 observer 清理确认后，先恢复两子树 mandatory-label ACE absence 并读回，再撤销该 profile 的精确 ACE 并读回，最后删除 exact owned profile/释放 SID。此处是 mandatory-label ACE absence 恢复，**不是完整原 SACL/SD 字节恢复**。本轮全部已知清理通过、`recovery_required=false`，私有原件保留；不能据此清除其他试次 unknown 或声称外部 broker 全部取消。

before/after各7378字节，均与原 baseline SHA256 `f05d91ee76ee8a97ae5ab3bfa092167a8ee560c083255f142e6c453f2edf7ab3` 原字节相等；只涵盖 firewall profiles、DNS、routes、user proxy 四对象，不含 NRPT，也不是全部机器配置不变证明。原三个 firewall profiles 仍关闭，不能由 capability 列表直接推导任意 egress 资格。

## 源码、编译和测试历史

[source-review 索引](../../verification/windows-2026-10-22/registry-read-loopback-source-review-01/index.json)记录 research、两份新 native source 的独立审查、ABI RLP1/RCL1、compile/static、False/ready-only Python、driver、reader、测试和 CI 资料的原件/视图独立哈希。

native actor只做 compile/static 验证后才由根单次运行：产物SHA256 `ff5ce2453d91902b516eed4d9266735579c3ee7fd936b4fbdf915ce086b531f0`，7键manifest SHA256 `72679ffee1c1e110730207b9cae747385afb8a0f4a6a65f5fe78e6b2b76758a1`。独立 compile 收据保留两个非runtime历史故障：preparer的独占 helper 创建遇已存在文件，根报告 FileExistsError，该失败准备路径未编译；之后使用现存 helper 实际编译。初版静态 reader 因 `utf8-sig` codec 名称发生 LookupError，fresh reader02只改为 `utf-8-sig` 后完成，未重编译。这两处没有原始失败日志，仅根报告与现存文件/源码可核，不能伪造成 raw exception trace 或 actor 失败。

作者早期33项 pure、16.807秒零skip，随后增加真实 ctypes-shaped 非零 capability parser/bounds 回归，最终34项、16.547秒、零skip；False冻结/独审后只晋级 ready flag。根完整 identity suite 为1025项、141.372秒、零失败、2个原有 symlink skip，即旧988加34个新Python方法和3个新native方法；compiled assertions不额外加测试项，没有 Linux 本机实跑。

[自动 push CI39899744500](https://github.com/Shermanxwz/Rule-proxy-Web/actions/runs/39899744500) / [job120238333961](https://github.com/Shermanxwz/Rule-proxy-Web/actions/runs/39899744500/job/120238333961)在同一 d309 源码通过1025项、148.731秒、零skip。runtime steps5–9全skipped，没有手工 dispatch/rerun；这只是 hosted pure/compile 复核，不是本机 runtime 验收，也不是原交接两端1016项的测试集合。[CI安全投影](../../verification/windows-2026-10-22/registry-read-loopback-source-review-01/ci-summary.json)记录 connector-decoded UTF8 BOM/CRLF job text 与 API decoded metadata 的原 bytes/SHA、视图 bytes/SHA 和实际转换；它们不是 ZIP 原字节。

## 保留的缺口

主 same-SID reachability、direct隔离、默认resolver/DNS、IPv6、UDP、服务broker、代理/产品/Linux等效、同SID篡改/注入/pipe盗取均未证明，全部固定false。selected registryRead 与前端零cap的不对称也不构成 AAP-only 对照。

[原G/PSEC DNS泄漏](2026-10-23-selected-dns-standard53.md)、[rawUDP未定论](2026-10-23-selected-dns-raw-udp.md)、[standalone semantic-LPAC DNS02有限5/5](2026-10-23-lpac-semantic-dns-02.md)、[atomic01 unknown](2026-10-23-psec-lpac-identity-01.md)以及 postassign/matchedcaps 的部分 proof 均保持原值，不由本次已知清理或 socket10013 覆盖。后续路线仍需要新明确 scope 和真实证据。


AFD 控制对象另做过一次受监督的 ordinary 只读诊断（[安全投影与来源索引](../../verification/windows-2026-10-22/afd-device-readonly-01/index.json)）：固定 `\Device\Afd` 仅请求 `READ_CONTROL|SYNCHRONIZE`，无 EA、IOCTL、SOCKET 或权限写；原 root20秒/work15秒同一绝对 QPC、原子 Job、恢复执行前映像/普通身份及一次清理均闭合。读得140字节 SD，四条 basic allow ACE 分别为 world `0x001201bf`、SYSTEM/Administrators 各 `0x001f01ff`、未识别12字节 SID `0x001200a9`；本描述符未识别出 AAP/ARAP 或 helper 固定名单中的网络/registryRead ACE。它不是 AFD endpoint SD、held LPAC effective-access 计算或 socket10013 的唯一原因证明；父监督器导入可能初始化 WSA，不能称整个运行无 Winsock 初始化，也未证明 driver 内部无 endpoint。[后续 IPC 契约](../../verification/windows-2026-10-22/afd-device-readonly-01/lpac-ipc-origin-scope-contract-01.txt)是独立零cap LPAC→固定继承管道→ordinary relay→owned origin 单轮正向设计；契约冻结时未实现，当前 WORK 候选实现推进中、仍未验证。此处不包含候选的编译、本机运行或应用适配验收证据，也不改变本轮结果、DNS反例或任何隔离/应用适配/产品资格。
