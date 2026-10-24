# 零 capability、同 SID loopback：01 控制文件竞争，02 Winsock 初始化失败

**两轮均为 `inconclusive / loopback`，尚无主 pair 连通或网络拒绝结论。** 01 的 selected 在 `control-open` 观察到 Win32 `32`，尚未启动 Winsock；02 已读取 GO 并产出 phase，但 `WSAStartup` 返回 `10107`，socket 未创建，connect/send 均未尝试。这两类失败分别保留，不能写成 `10013`、loopback 拒绝或任意直接出站已经隔离。

本页是两次独立实际尝试的归档检查点，不是后续研究或候选实现的成功记录。两轮同属 `one-local-zero-cap-same-sid-loopback-v1` / `same-sid-zero-cap-loopback-mechanism-v1`：fresh profile 中 AC 前端与 LPAC selected 共享 SID、能力列表精确为空；普通 listener/client 是另两枚 held ordinary primary。没有添加 PNCS/Agentic/其他 capability，没有 loopback exemption、WFP、全局防火墙、代理、DNS 或路由变更，也没有 PSEC 网络策略比较。

## 两轮确实观察到了什么

| 项目 | 01 | 02 |
|---|---|---|
| 受测提交 | `07146b7118c345e4a1046fe9066ba2f26b37cf3a` | `c7145b9d50dc99c14f11764a03ad23f31ce3e638` |
| 37 项源码闭包 | `3df55cdbc317522d74a3f6cc8f0f68258aa73da0b1d5cd8ae811aebf7ab9342f` | `b726d48d6dddfed2533168ac0921add834488f333931f08b75dc6195cd9fc4ac` |
| 外部 held 身份、双 Job、原 QPC/映像核验 | 通过 | 通过 |
| AC / LPAC 实际 AccessCheck 四矩阵 | `[3,0,1,2]` / `[2,0,0,2]` | 同样通过 |
| 普通同 API 前后 64 字节请求/响应、EOF | 均成功 | 均成功 |
| 零 cap AC front bind/listen 与独立 kernel listener PID | 通过 | 通过 |
| selected 网络进展 | 控制文件 open `32`；无 phase、Winsock 未启动 | GO 已读，phase `wsa-startup / 10107`；无 socket/connect/send |
| 主 withheld 请求/双向 half-closed tuple/release/响应 | 均未发生 | 均未发生 |
| 原始状态/资格 | inconclusive，reachability=false | inconclusive，reachability=false |

[01 原 public](../../verification/windows-2026-10-22/zero-cap-loopback-local-01-public.json)为2731字节、SHA256 `a4502dda11fbc39567e53c909ca2e4d8b9c5b5825e92e056fea46fd8cb396b18`；[02 原 public](../../verification/windows-2026-10-22/zero-cap-loopback-local-02-public.json)为2731字节、SHA256 `457c26fdf13707807a5412ff81951bba7b4112129c472c6f09804c073a6813ed`。各轮[01 证据索引](../../verification/windows-2026-10-22/zero-cap-loopback-local-01-evidence-index.json)与[02 证据索引](../../verification/windows-2026-10-22/zero-cap-loopback-local-02-evidence-index.json)保留原 preflight/public、逐字节 runner、组件/矩阵/协议/全局/源码投影；没有重跑 actor 或网络。

两轮 ordinary worker 都正常退出0，只代表已生成和验证失败报告，不代表主连接成功。front 与 selected 均自然以 typed failure 退出5，ordinary 两角色退出0；`workload_stop=false`，不能改写成 owner Job kill。源验证器记录各轮6条原期限 GO；01有13份实际 native 报告，02有14份（新增 selected phase）。每轮只有一个成功的独立 LISTEN 表观察，没有主 pair 的 withheld 双向元组。原 TCP 表只保留在私有证据中，公开仅 bytes/SHA 和身份/状态绑定布尔。

## 01 的机械竞争与 02 的独立初始化失败

01 的发布函数先 rename 控制票，再由 parent reopen/readback；native 以 share=0 独占读取。selected 的真实 `control-open / Win32 32` 与这处自竞争一致，源码存在可触发的顺序缺陷；没有采集 opener PID 或调度 trace，不能把推论写成独立证明了哪个句柄先打开。01 的原源码、公报与失败始终保留。

02 只改发布顺序：在 private pending 文件关闭后完成精确 bytes 读回，再一次 rename，发布后不再 reopen；worker/外层在已知退出后的物理 GO 验证仍保留，未放宽身份、原绝对期限或清理门。02 已从 selected 的闭合 phase 证实 GO 被读取，随后 `WSAStartup=10107`、`socket_close=not-created`、connect/send 未尝试。其原因未证明，不能归因于某个能力、服务、provider 或“Windows 不支持 LPAC 网络”，也不能自动补 cap、取消 LPAC 或沿用原失败为新通过。

`network_tested` 的 native 含义限于 connect-attempt/accepted-flow。本轮总体为true来自 ordinary 前后控制；selected 的这两轮没有连接尝试。该窄 flag 为false也不表示一个进程完全没有调用过 socket/bind/listen API，例如前端实际已成功监听。

## 监督、ACL、label 与已知清理边界

四个角色在任何 Resume 前均由外部 held HANDLE 核验 primary、零 cap、同 user/session、映像/hash、generation 与精确 outer/inner Jobs；AC/LPAC 的四个 AccessCheck 描述符及 duplicate/token 资源先闭合。没有 TokenInformationClass46 查询，没有由 actor 自述或观测自适应授权。

只有两处 fresh report 子树取得该 profile 的 Modify 与 Low mandatory label，inputs/control 仍只读。所有 workload 已知退出、Job empty、句柄与 observer 清理确认后，先恢复两子树 mandatory-label ACE absence 并读回，再撤销该 profile 的精确 ACE 并读回，最后删除 exact owned profile、释放 SID。**这不是整个原 SACL 或 SD 字节恢复保证。** 两轮全部已知清理确认、`recovery_required=false`，私有树保留作证；不证明旧 opaque environment absence 或外部 broker 取消。

两轮 before/after 快照各7378字节、SHA256 `f05d91ee76ee8a97ae5ab3bfa092167a8ee560c083255f142e6c453f2edf7ab3`，均与最初 baseline 原字节相等。范围仅 firewall profiles、DNS、routes、user proxy 四类对象，不含 NRPT，不是全面系统状态不变证明。防火墙 profiles 本来关闭，因此不能仅由 cap=[] 推导任意直接出站被阻断。

## 源码、失败历史、编译与纯测试

[source-review 索引](../../verification/windows-2026-10-22/zero-cap-loopback-source-review-01-02/index.json)保留两个实际源码版本、native/ABI/compile/static/独审、driver、readers、归档器与其修订。初始 False01 的26项 pure 已绿，但独审发现报告可早于 GO/回填 release 时钟而 BLOCKED；False02补齐 issued-time/response 因果门，28项、13.978秒、零skip；True03只晋级 ACTUAL_READY。原 False01 补丁、日志、BLOCKED 收据不被后续覆盖。

native 两份 source 与产物两轮复用：x64 GUI actor298496字节、SHA256 `5015367a6edeaefd1830f5a6584024894070926ea5012c343534e43054b0461d`，闭合7键 manifest，imports为 KERNEL32/ADVAPI32/WS2_32，无 shell32 argv helper。只有编译/静态/portable fake 资料不能充当实际连通证据。首版全量986项、106.104秒、零失败、2个原有 symlink 权限 skip；计数为旧955加28个新 Python 方法和3个 native 方法，compiled assertions不另加测试项。

发布顺序修复先有8项 focused 中1个测试假设失败：测试误以为 pending 只读一次，实际 durable_private 也会做关闭后读回；生产修复未变，只校正测试允许全部读在 pending、禁止发布后读。修正后8项、6.952秒、零skip；独审另2项通过。True02只改 ready flag，根全量988项、103.628秒、零失败、2个原有 skip，即986加2个新方法；没有本机 Linux 实跑。

两个源码自动 push CI 随后均成功；没有手工 dispatch 或 rerun。下表是 hosted runner 的 identity pure suite，runtime steps 5–9 全部 skipped，不能当本机实际连通/隔离验收，也不是旧交接中两端各1016项的集合。

| 源码 | 自动 CI / job | pure 结果 | runtime |
|---|---|---|---|
| `07146b7118c345e4a1046fe9066ba2f26b37cf3a` | [39893448693](https://github.com/Shermanxwz/Rule-proxy-Web/actions/runs/39893448693) / [120218292888](https://github.com/Shermanxwz/Rule-proxy-Web/actions/runs/39893448693/job/120218292888) | 986项，122.903秒，零skip | steps 5–9 skipped |
| `c7145b9d50dc99c14f11764a03ad23f31ce3e638` | [39895061571](https://github.com/Shermanxwz/Rule-proxy-Web/actions/runs/39895061571) / [120223460816](https://github.com/Shermanxwz/Rule-proxy-Web/actions/runs/39895061571/job/120223460816) | 988项，105.194秒，零skip | steps 5–9 skipped |

[CI 安全投影](../../verification/windows-2026-10-22/zero-cap-loopback-source-review-01-02/ci-summary.json)绑定六份 connector-decoded 输入：两份 UTF-8 BOM/CRLF job 日志和四份 API decoded run/job metadata。它们不是下载 ZIP 的原字节；公开视图逐项记录原 bytes/SHA、视图 bytes/SHA，以及 BOM、换行、路径等实际转换，原件保留 WORK。

首次归档器的 verdict 字面门由根静态审查发现，未执行；保留后新builder02第一次 dry 在 intent 投影把 str 传给要求 bytes 的源 decoder，`ValueError(report)` 停止，Archive写入0。builder03仅补ASCII编码，根 dry 与01 Archive随后成功；这两处是文件归档工具故障，没有重跑实际实验或更改原公报。02 使用 fresh 独立归档，31份新文件，01的22份保持不变。

## 不能推出的结论

这些是固定可信 actor 的有限机制观察。共享 SID 的路径/对象篡改、注入、pipe 盗取都未证明；主 same-SID reachability、selected 对健康 ordinary origin 的 direct 拒绝尚未验证，更无默认 resolver、DNS、IPv6、UDP、服务 broker、代理或产品资格。所有这些固定false，Linux等效仍false。

[原 G/PSEC DNS API 泄漏](2026-10-23-selected-dns-standard53.md)与[raw UDP 未定论](2026-10-23-selected-dns-raw-udp.md)继续保留；[standalone semantic-LPAC DNS02](2026-10-23-lpac-semantic-dns-02.md)的有限 API/query5/5 不被本轮改写，也不与本轮不同配置混成因果证明。[旧 atomic01](2026-10-23-psec-lpac-identity-01.md)的 unknown/recovery_required、[postassign](2026-10-23-psec-lpac-postassign-identity-01.md)和[matchedcaps](2026-10-23-psec-lpac-matchedcaps-identity-01.md)的部分 proof 均保留。后续 registryRead/LPAC networking 研究或候选尚不构成这里的实际成功。
