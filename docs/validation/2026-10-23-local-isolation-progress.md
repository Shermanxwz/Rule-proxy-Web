# Windows 本机应用级代理隔离：2026-10-23 检查点

本页记录已经运行的本机证据与尚未验收的范围。当前已完成首次真实网络的 **profiles-off diagnostic**、同身份错端口诊断，以及真实在途请求被精确 relay 死亡中断、同 held selected 事后 fresh direct 返回 `10013` 的 death01 诊断；错误 peer 的第二次尝试虽完成前后健康控制和清理，但 selected 连接超时，结论仍为 **inconclusive**。严格隔离和产品验收仍为 **false**。系统三个防火墙 profiles 原本关闭，本实验没有为得到成功而启用它们，也没有改全局代理、DNS 或路由。`effective_full_verified=false` 不能由精确规则存在、HTTP 正向成功或清理成功替代。

**最新 DNS01 为 failed：** 同 held selected 通过 `DnsQueryEx` 获得匹配答案，独立 owned UDP53 receiver 收到对应新 case。ordinary 前后控制、原代理/TCP direct 观察和全部清理完成，反例仍成立。完整事实与限制见[标准53 selected 结果](2026-10-23-selected-dns-standard53.md)；当前受测 Model2 不具备完整 DNS 防泄漏，不能验收为 Linux 等效。

**后续原始 UDP 差分：** [rawDNS01/02](2026-10-23-selected-dns-raw-udp.md)保留两轮实际结果。raw02 已补齐普通前后正控及全部观察；selected 的 send 被本地接受、receiver 无对应查询、超时且无明确拒绝错误，仍为 `inconclusive`。该有限负观察不能抵消 API DNS01 的明确泄漏。全部清理完成，全局配置未变。

**后续观测候选尚未运行：** [ETW owner 源码归档](../../verification/windows-2026-10-22/dns-etw-owner-candidate-index.json)保留11个未安装的新源文件、SDK编译收据和14项假 API 测试。真实 owner/recovery CLI、RunAs 与 native journal 接线、ordinary actor/receiver driver 尚缺，`actual_ready=false`；没有开启 trace、读取事件或形成归因成功证据。这些候选不能替代上面的本机 DNS 实测。

## 首次完整诊断：diagnostic09

受测源码为 `bee54d78b7ab3c823f5ddecbbffcca04f99abf2e`，源码闭包 SHA256 为 `f318b600bd00115afd3e7fdd5cbc67af08be96f671c0d55b07ae1eb8aaf1754d`。[公开结果](../../verification/windows-2026-10-22/model2-diagnostic-09-public.json)、[版本摘要](../../verification/windows-2026-10-22/model2-diagnostic-09-summary.json)与[安全组件投影](../../verification/windows-2026-10-22/model2-diagnostic-09-component-projection.json)记录：

- 同一受持有原生 selected 客户端经 PNCS AppContainer 前端、48-byte 受持有管道、ordinary relay 到自有 numeric-loopback origin，完成真实 HTTP 请求及响应。客户端绝对形式请求为 129 字节，relay 的规范 origin 请求为 95 字节，响应为 90 字节；正文、EOF、预声明 case 与私有连接元组绑定均核对。
- 同一 selected 进程在同一 PSEC 生命周期中直接连接固定 origin，`connect_attempted=true`、`connect_completed=false`，Winsock 错误为 `10013`；socket close 和 WSACleanup 均确认。独立 ordinary origin 的 before、during、after 三次正向健康控制成功，完整收据中没有 forbidden case。
- 实际 G 日志唯一解析为 `base-container`。selected、G、系统 conhost、front、relay、origin、health 及维护角色均正常退出 0；held 进程、Job、ACL、profile 和 SID 清理全部确认，`recovery_required=false`。
- [全局只读比较](../../verification/windows-2026-10-22/model2-after09-global-projection.json)确认前后防火墙 profiles、DNS、路由与用户代理配置的 JSON 对象完全相等。两份原始快照的排版字节不同；原始快照没有公开。

该次状态为 `diagnostic-observed`、`diagnostic_completed=true`。`first_chain_verified`、`direct_deny_verified`、`local_c_qualified`、`product_acceptance` 和原始 `Stage0` 均为 false。公开结果 SHA256 为 `173646e89bb291f81be3613d8aeab0b40cb44b74fab873e38b17f5a89794d162`，2447 字节。[06–09 证据索引](../../verification/windows-2026-10-22/model2-diagnostic-06-09-evidence-index.json)保留此前失败及组件事实，未重写历史结果。

## 错端口扩展：wrong-port01 未定论

受测源码为 `9b6226b35d92a16a8dc66fd92afa00ad81a3fe1f`，源码闭包 SHA256 为 `52e1d7b6ee6f9242bcd8bb33860ad9acec5aedf864c57bdddf7b45ef43da2208`。[公开结果](../../verification/windows-2026-10-22/model2-wrong-port-01-public.json)、[版本摘要](../../verification/windows-2026-10-22/model2-wrong-port-01-summary.json)及[安全投影](../../verification/windows-2026-10-22/model2-wrong-port-01-component-projection.json)保留主代理正向及同 held selected 的 direct `10013` 观察。

同一前端身份、不同端口 Q 的 PNCS listener 已 READY。ordinary Q 健康客户端先执行固定 op3，连接未完成：transport `failure=deadline`、`wsa_error=null`，socket close 与 WSACleanup 已确认。控制器因此在 `wrong_port_before_health` 停止；selected 的错端口 op3 **没有发布 GO，也没有执行**。这次不能证明错端口隔离通过，也不能证明 selected 发生泄漏；健康控制失败的根因尚未证明。

整体为 `inconclusive`，所有 cleanup 为 true、无需恢复。front/relay 正常退出 0；仍存活的 selected/G/conhost、origin/health 与 Q 角色由所有者清理终止为 1。该次没有完成原 origin 的 after 健康控制，也未完成诊断总验收。[证据索引](../../verification/windows-2026-10-22/model2-wrong-port-01-evidence-index.json)绑定原 preflight/public、逐字节 runner 和脱敏摘要。

## 错端口扩展：wrong-port02 诊断完成

受测源码为 `755a1ca3f51261c44995072ccf1a12ab4e8b8c05`，源码闭包 SHA256 为 `c4394edfa067a7b21e654b7a011ca45a6d8759f56691626b0545c8ef6a56a93a`。[公开结果](../../verification/windows-2026-10-22/model2-wrong-port-02-public.json)、[版本摘要](../../verification/windows-2026-10-22/model2-wrong-port-02-summary.json)及[安全组件投影](../../verification/windows-2026-10-22/model2-wrong-port-02-component-projection.json)将此新 profile `same-peer-wrong-port-psec-control-v1` 与 wrong-port01 的 ordinary 正控失败分开记录。

主代理 HTTP 129→95 字节请求/90 字节响应、同 held selected 的 origin direct `10013` 及 origin 前中后健康控制均再次完成。Q receiver 与主 front 使用同一精确 PNCS AppContainer 身份、同一 pinned actor 映像和不同固定端口。新的独立 PSEC 控制族绑定该 receiver 和 Q，前后各完成 129 字节真实 HTTP 请求、90 字节响应、正文、EOF、预声明 nonce 与私有连接元组核对；控制族的 held G/actor/conhost、精确 Jobs、generation 与首次网络 GO 均独立准入。

在上述健康控制之间，主 selected 保持同一 held 进程和 PSEC，向同一 receiver 身份的错端口 Q 发出固定 op3：连接尝试已发生、连接未完成，`failure=connect`、Winsock `10013`，socket close 和 WSACleanup 均确认。Q receiver 完整收据只有预声明的 before/after 两个控制 case，没有 forbidden case。两族实际 G 日志均唯一解析为 `base-container`；所有任务、两族 conhost 及维护进程退出 0，全部清理确认，无需恢复。

该次 `diagnostic_completed=true`，错端口 extension 的 `completed`、`healthy_before`、`healthy_after`、`denied_by_access` 和 `observation_complete` 均为 true，整体为 `diagnostic-observed`。严格 `checks.wrong_port`、`firewall_exact`、`effective_full_verified`、`first_chain_verified`、`direct_deny_verified`、`local_c_qualified`、`product_acceptance` 仍为 false。该次没有执行错误 peer 或 proxy death；后续错误 peer 的未定论尝试见下文，不能由错端口诊断外推。

[证据索引](../../verification/windows-2026-10-22/model2-wrong-port-02-evidence-index.json)绑定2669字节原 public（SHA256 `d83eb60d36570a2a7b65c8e55c48b6753a17c9ead0cc28a2d5946806915af416`）、原 preflight、逐字节 runner 及脱敏投影。独立归档核对23份 staged 源码与受测 git blob、15个唯一 nonce 的绑定、13条 GO、36份实际报告描述符的 bytes/SHA；报告契约上限为46，不能称实际产生46份。另对42份 stdout/stderr 文件记录不公开原文的整体承诺。

## 错误 peer：wrong-peer01 保留首次未定论

受测源码为 `bdb9de16255af8ee8ecd906426ed89fdf6453aa5`。[公开结果](../../verification/windows-2026-10-22/model2-wrong-peer-01-public.json)、[摘要](../../verification/windows-2026-10-22/model2-wrong-peer-01-summary.json)和[证据索引](../../verification/windows-2026-10-22/model2-wrong-peer-01-evidence-index.json)保留原始尝试：主代理正向与同 held selected 的 origin direct `10013` 已完成，A listener 退出并关闭后，身份不同的自有 PNCS profile B 在原 P 独占监听，其独立 PSEC 前控完成精确 HTTP。

主 selected 向同 P、不同 peer B 的固定 op4 已执行，连接未完成，transport `failure=deadline`、`wsa_error=null`、socket close 和 WSACleanup 确认。旧控制器在 `wrong_port_observation` 的准时门停止，尚未执行 B 后控与完整 finish/原 origin 后控，因此错误 peer 隔离与泄漏均未得到证明。所有权清理完成，无需恢复；该次记录没有因后续改动而重写。

## 错误 peer：wrong-peer02 完整观察仍未定论

受测源码为 `b0e88e456965174cee3227c5c82c5fd228ce35e3`，源码闭包 SHA256 为 `f4d8f5641ea26ebe1db3e945d112f15d552a224b0e5cb8027f201fef2589048d`。[公开结果](../../verification/windows-2026-10-22/model2-wrong-peer-02-public.json)、[摘要](../../verification/windows-2026-10-22/model2-wrong-peer-02-summary.json)及[安全组件投影](../../verification/windows-2026-10-22/model2-wrong-peer-02-component-projection.json)记录主代理真实 HTTP、同 held selected 的 origin direct `10013`，以及原 origin before/during/after 健康控制均完成。

原 A front/relay 已持有观察退出 0、socket 已关闭后，新的自有 B profile 以不同精确 SID、同一 pinned actor 和 PNCS capabilities 在同一 P 独占绑定。独立 B PSEC 控制族在主 op4 前后均完成 129 字节绝对形式请求、90 字节响应、正文、EOF、独立 nonce 与私有连接元组核对。主 selected、G、PSEC 和原 P/Q/O 绑定保持不变。

主 op4 仍然超时：`connect_attempted=true`、`connect_completed=false`、transport `failure=deadline`、`wsa_error=null`，没有 request/response 字节或已连接元组，socket close 与 WSACleanup 确认。原 phase/root deadline 未延长；仅严格绑定的有界失败允许控制器继续采集 B 后控和 finish。该次 `timed_out=true`、`observation_complete=true`，但 `denied_by_access=false`、extension `completed=false`、`diagnostic_completed=false`，nested failure 为 `wrong-peer`，整体仍为 `inconclusive`。B 完整收据没有 forbidden nonce；这既不是 `10013` 拒绝证明，也不是泄漏证明，不能解释超时根因。

主族、B 控制族、两族 conhost、所有工具及维护角色均退出 0；所有 finish、实际 `base-container` 日志、held/Job/handle、A/B 精确 ACE 撤销、两 profile 删除及 SID 释放均核对，全部 cleanup 为 true、`recovery_required=false`。严格 `checks.wrong_peer`、Full、首链资格、严格隔离与产品验收仍为 false。

[证据索引](../../verification/windows-2026-10-22/model2-wrong-peer-02-evidence-index.json)绑定原 preflight、2687 字节原 public（SHA256 `c0ead40c489c36cf4d5f83f5d6d9d450a7a4e9ee0bc4d592d0ed5952d375266d`）、逐字节 runner、摘要与脱敏投影。独立只读归档核对23份 staged 源码与受测 git blob、15个唯一 nonce、13条 GO、36份实际报告描述符的 bytes/SHA、native/G artifacts 与历史闭合 validators；另读取50份 stdout/stderr 共6700字节，仅公开整体 SHA 承诺。私有树继续保留，归档没有再次执行任何 actor 或网络测试。

## 在途 relay 死亡：death01 诊断完成

受测源码为 `3d64b13c7563facf09a9758ba0854cb6c6b1704e`，源码闭包 SHA256 为 `4d7d5fdc29843737139739354d02e8e76383c13e4f97eadaf061b0ca289761f1`。[公开结果](../../verification/windows-2026-10-22/model2-death-01-public.json)、[版本摘要](../../verification/windows-2026-10-22/model2-death-01-summary.json)及[安全组件投影](../../verification/windows-2026-10-22/model2-death-01-component-projection.json)绑定独立 profile `same-selected-live-proxy-death-v1`。原 main 正向 HTTP、direct `10013` 和 ordinary origin 控制再次完成；main direct 发生在原 front/relay 退出之后，不能称为活代理期间的直连测试。

同一 held selected、A 身份、固定 P/O 和原 QPC epoch 保持不变。新 death-front 与 death-relay 在原绝对预算内使用固定 10 秒 pair；selected 先向仍活着的 relay 发出真实 129 字节代理请求，原 ordinary origin 独立确认规范 95 字节请求与 EOF，保持 accepted socket 且发送 0 字节响应。所有者核对该 held origin 的 ACK、relay generation、精确 workload/outer Jobs 与连接元组；实际 relay TCP 状态为 `FIN_WAIT2`（已完成 `SD_SEND` 后的半关闭），并非声称仍为 ESTABLISHED。

持久化并读回 stop intent 后，所有者仅终止该 held relay，持有观察退出 1。death-front 自然退出 5、`pipe_read` / Win32 `109`，response 0 字节；同 selected 的在途请求得到空响应 EOF、transport `failure=response`、无 Winsock 错误，socket、pipe 和 WSA 关闭均确认。这两个非零退出码是该 cell 预声明且证据绑定的例外，其他角色和维护进程均退出 0。被杀 relay 留下 0 字节 final 占位文件，未生成可用 JSON 报告；没有补造报告。

随后所有者发布精确 release，确认同 held origin 的 release ACK，再由同 held selected 对同一仍健康 O 发起 fresh case direct：已尝试、未连接，Winsock `10013`，未收到 forbidden nonce。普通 origin 的第三次 after 正向控制通过；完整五份收据含一份 death 专用 0 响应收据，其余正常响应。该次证明的是“在途请求被 relay 死亡中断”和“同 held selected 事后 fresh direct 拒绝”，op5 的历史标签 `proxy-after-death` 不改变真实发起早于 kill 的顺序。

所有 death required facts、`death_extension.completed` 与 `diagnostic_completed` 均为 true，整体 `diagnostic-observed`，全部 cleanup 为 true、无需恢复；私有树保留。严格 `checks.proxy_death`、Full、`first_chain_verified`、`direct_deny_verified`、`local_c_qualified`、`product_acceptance` 仍为 false，浏览器、WinHTTP、真实应用及 selected DNS 均未由该次验证。[证据索引](../../verification/windows-2026-10-22/model2-death-01-evidence-index.json)绑定2954字节原 public（SHA256 `c7074aa14e13f42c81ed659a0556666624041146a74051bd7e1cef7d3daa68c6`）、原 preflight、逐字节 runner、摘要与安全投影。归档只读核对23份 staged 源码与受测 git、11个唯一 nonce、11条 GO、30份实际报告描述符（契约上限34）及36份 stdout/stderr 共3346字节的整体承诺，没有再次运行 actor 或网络。

death01 完成后的[全局只读比较](../../verification/windows-2026-10-22/model2-death-after01-global-projection.json)与[取证脚本索引](../../verification/windows-2026-10-22/model2-death-after01-global-evidence-index.json)确认，防火墙 profiles、DNS、路由及用户代理的完整 JSON 与首次 baseline 相等，原始字节也相等（均7378字节，SHA256 `f05d91ee76ee8a97ae5ab3bfa092167a8ee560c083255f142e6c453f2edf7ab3`）。该比较是两个时间点的配置观察，不代替运行期间隔离证明；原始配置未公开。

## ordinary DNS 同 API 机制已运行

`dns-standard-local-02` 已在普通身份下完成真实 `DnsQueryEx` VERSION1 调用、专用 loopback UDP53 接收端的一次查询和答案匹配，API/query status 均为 0，记录内存、socket、线程和 held Job 清理均确认。运行前的受监督只读 DNS/有效 NRPT/53 端口占用门及两次新鲜度门均通过；运行后全局配置与原 baseline 完全相等。该结果仅建立 ordinary 同 API 正控；随后[同 selected 的 DNS01](2026-10-23-selected-dns-standard53.md)确认该路径绕代理成功，整体隔离失败。默认 resolver 和系统 broker 隔离仍未验证。首次 staging 时钟范围失败历史及完整证据见[独立 DNS 检查点](2026-10-23-dns-standard-mechanism.md)。

## 后续必须完成的范围

| 范围 | 本页检查点状态 |
|---|---|
| 真实 selected → PNCS front → pipe → ordinary relay → owned origin | diagnostic09 已运行成功；仅固定单请求和原生客户端 |
| 同 selected 固定 origin direct 尝试与前中后健康控制 | diagnostic09 已完成观察，10013；严格资格仍为 false |
| 严格防火墙 Full 生效条件 | 未通过；本机 profiles 原本关闭，当前仅显式诊断 |
| 同身份错端口 | wrong-port01 正控失败保留；wrong-port02 独立 PSEC 前后正控及同 held selected `10013` 已完成诊断，严格资格仍为 false |
| 错误 peer | wrong-peer01 首次超时保留；wrong-peer02 前后健康与完整 finish/清理均完成，但主连接仍超时，隔离与泄漏均未定论 |
| 在途 relay 死亡与事后 fresh direct | death01 独立诊断已完成：精确 held relay 停止、前端/客户端空响应失败、同 O 释放恢复后 fresh direct `10013`；严格资格仍为 false |
| DNS | ordinary 同 API 前后正控成功；selected DNS01 获得精确答案且 receiver 命中，当前隔离明确失败；默认 resolver 与 broker 归因/隔离未完成 |
| UDP/IPv6、系统代办、真实浏览器、WinHTTP 与应用适配 | 本检查点未验证，不能由上述 HTTP、direct TCP 或 ordinary DNS 外推 |

继续实现应保留身份、原 QPC deadline、held Job、健康控制与清理门。不能用 listener READY、单次 connect timeout、组件 positive 或已有纯测试把未运行项改为通过。证据公开投影只保留布尔、字节数、错误与 SHA；私有用户/SID/PID、端口、路径、设备标识、creation 和 nonce 值继续留在私有树。
