# Windows 本机应用级代理隔离：2026-10-23 检查点

本页记录已经运行的本机证据与尚未验收的范围。当前已完成首次真实网络的 **profiles-off diagnostic**；严格隔离和产品验收仍为 **false**。系统三个防火墙 profiles 原本关闭，本实验没有为得到成功而启用它们，也没有改全局代理、DNS 或路由。`effective_full_verified=false` 不能由精确规则存在、HTTP 正向成功或清理成功替代。

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

## 后续必须完成的范围

| 范围 | 本页检查点状态 |
|---|---|
| 真实 selected → PNCS front → pipe → ordinary relay → owned origin | diagnostic09 已运行成功；仅固定单请求和原生客户端 |
| 同 selected 固定 origin direct 尝试与前中后健康控制 | diagnostic09 已完成观察，10013；严格资格仍为 false |
| 严格防火墙 Full 生效条件 | 未通过；本机 profiles 原本关闭，当前仅显式诊断 |
| 同身份错端口 | wrong-port01 的 ordinary 正控未过，selected 操作未执行 |
| 错误 peer、代理进程死亡后的 fail-closed | 尚未完成验收 |
| DNS、UDP/IPv6、系统代办、真实浏览器、WinHTTP 与应用适配 | 本检查点未验证，不能由上述 HTTP 和 direct TCP 外推 |

继续实现应保留身份、原 QPC deadline、held Job、健康控制与清理门。不能用 listener READY、单次 connect timeout、组件 positive 或已有纯测试把未运行项改为通过。证据公开投影只保留布尔、字节数、错误与 SHA；私有用户/SID/PID、端口、路径、设备标识、creation 和 nonce 值继续留在私有树。
