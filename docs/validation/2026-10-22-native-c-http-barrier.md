# Native C：真实 TCP 前端与 identity-first 客户端

日期：2026-10-22。新文件为 [C actor](../../.github/native/windows_identity_proxy_c_actor.cpp)、[portable command contract](../../.github/native/windows_identity_proxy_c_contract.hpp)、[compile-only helper](../../.github/build_windows_identity_proxy_c_actor.ps1) 与 [pure tests](../../tests/test_windows_identity_proxy_c_native.py)。[本次 compile/pure 记录](../../verification/windows-2026-10-22/native-c-compile-pure-01.json)只证明构建和纯契约；该记录没有执行 Windows actor、创建 profile、添加 ACL/规则或运行网络 fixture。

本页是 native ABI，不能代替持有者。下面的参数只能由具有 atomic outer Job、held image/token/generation 校验、固定 staging、实际权限/策略与清理账本的 C owner 使用。READY 自报 PID 不构成授权；selected 进程必须等 owner 从 held G 的真实 direct child 独立验证后才收到 GO。

## 命题及边界

`pipe-live-front` 在 fresh PNCS AppContainer 内监听固定 numeric `127.0.0.1:P`。客户端真实发送 absolute-form 固定 GET 与 request EOF，frontend 将实际读到的 bytes 送入原 core，经原 48-byte held pipes 触发 ordinary relay，relay 对 owned origin 的固定端口 O 执行真实 HTTP。frontend 只把 core 已核验的响应实际写到 TCP socket 并 shutdown/close，全部写入与关闭均计入账本。

请求方法、authority、case、origin Host、响应与 EOF 都受固定契约约束，没有 CONNECT、任意 URL/地址、凭证或 redirect 参数。当前客户端是 raw Winsock HTTP；WinHTTP、浏览器和应用适配未测试。48-byte REQUEST/RESPONSE 仍只描述一个固定 nonce 请求，不承载任意代理流量。嵌套 `ipc_mechanics` 保留旧 A schema 的原始字段名，但包含实际 PNCS identity；它只是机械投影，不能套用旧 A 零 capability 合格门。C 自己的 HTTP 边界是 `real-client-request-and-response-socket`。

首轮命题只覆盖真实 positive chain 与同一个 selected/G/PSEC 存活期间的 direct-O 操作。wrong-peer、wrong-port、转发活跃期间杀 relay、DNS/UDP/IPv6/broker、故障恢复和产品集成仍须各自证据，不能因这份 native 实现而标为通过。每个 native report 都保留 `proxy_tested=false`、`product_acceptance=false`；完整 C qualification 由独立 owner 证据决定。

默认 A、实际 B binary/manifest 和冻结证据均未改写。C 通过新 `wWinMain` 与 `/SUBSYSTEM:WINDOWS` 复用冻结 B translation unit；不创建窗口、请求 UIAccess 或增加 UI/capability fallback。`CommandLineToArgvW` 的内存先复制并单次 `LocalFree` 确认，再 dispatch。C manifest 额外绑定 C source/contract 和全部 B/A/core/identity include 源。

## 身份和首次网络门

frontend/PNCS health listener 的 capability 必须恰为 `privateNetworkClientServer`（`S-1-15-3-3`，attributes=4）。native 对固定 catalog 名称调用只读 `DeriveCapabilitySidsFromName`，PNCS 另与 `CreateWellKnownSid(87)` 交叉核对；已分配的 SID/数组单次消费和释放。未知 capability、重复项、错误 attributes、未知 cleanup 均拒绝。

selected-client 先只查询真实 identity、核对预声明 profile、发布 READY 并读控制文件。`Session`/WSA/socket 只出现在完整 GO 验证且控制文件 close 确认之后。`agentic-pncs` 要求固定 `AgenticAppContainer` 和 PNCS 两个 SID，均 attributes=4；不能根据 observed capabilities 修改预期。`agentic-only` 只允许 identity READY 与 finish，任何网络 GO 在 WSA 前拒绝。`ordinary` 只允许 health-client，要求非 AC、零 capability。全部角色要求非 elevated、预声明 user 和真实 Job；held 外部校验仍不可省略。

不假设 ordinary host 能连接 PNCS AC loopback。AC receiver 的健康控制应由独立 G/PSEC health-client 精确绑定那个 receiver identity/port；不得增加 CheckNetIsolation 或 networkLoopback exemption 来使控制通过。

## 固定 argv

以下 argc 包含 executable。所有 nonce 为 32 个小写 hex；所有路径是 staging 内绝对路径；全部 QPC 值在同一个实际 frequency/epoch 下。pair 保留原 core 的恰好 10 秒 `pairEnd=pairT0+10F`，它必须收缩到 owner 原始绝对 root deadline 内。

    c-actor.exe pipe-live-front                                      # argc 17
      run case report read_handle write_handle pairT0 F pairEnd
      expectedUser expectedAcSid 0 originO listenP readyPath controlDir

    c-actor.exe selected-client|health-client                         # argc 16
      run bootCase readyPath resultDir controlDir F originalT0 rootD
      P Q O expectedUser agentic-pncs|agentic-only|ordinary admissionNonce

    c-actor.exe health-origin|health-listener                         # argc 14
      run bootCase report ready controlDir F originalT0 rootD
      requestedPort expectedUser expectedAcSid_or_none maxAccept

客户端 P/Q/O 均为 49153–65535 且互不相同。frontend P/O 为不同高端口。health listener 的 requestedPort 可为 0（内核选择后报告实际高端口）或固定高端口，maxAccept 为 1–8。origin 为 ordinary/none；PNCS listener 必须给确切 AC SID。所有 listener 使用 exclusive bind、不使用 SO_REUSEADDR、不改父 ACL 或系统网络设置。

C 还允许 frozen B 的 `pipe-relay`（原 argc 14）和 `origin-fixture`（原 argc 9）dispatcher，以相同 C executable/manifest 持有。C 不允许 B generated `pipe-front` 入口冒充真实 frontend。

## GO 128-byte 小端协议

client 控制文件为 `controlDir/phase-0001.bin` 至 `phase-0016.bin`，必须依序出现；没有任意 command、URL、凭证或目标。owner 应原子发布 immutable 文件。native 只读恰好 128 bytes、验证文件 EOF、单次关闭控制文件、再核对当前绝对时间，任何未知 close 都拒绝执行。

| offset | bytes | 固定内容 |
|---|---:|---|
| 0 | 4 | ASCII RPC1 |
| 4 | 1 | version=1 |
| 5 | 1 | opcode |
| 6 | 2 | zero |
| 8 | 4 | sequence 1..16，小端 |
| 12 | 4 | zero |
| 16 | 16 | run raw bytes |
| 32 | 16 | fresh phase case raw bytes |
| 48 | 8 | 原始 F |
| 56 | 8 | 原始 rootD |
| 64 | 2 | P |
| 66 | 2 | Q |
| 68 | 2 | O |
| 70 | 2 | zero |
| 72 | 16 | 外部 admissionNonce raw bytes |
| 88 | 8 | phaseD，actualNow < phaseD ≤ rootD |
| 96 | 32 | zero |

opcode 1=`proxy-get`→P，2=`direct-tcp`→O，3=`wrong-port`→Q，4=`wrong-peer`→P，5=`proxy-after-death`→P，255=`finish`（无网络）。非 finish 的 case 须彼此不同且不同于 bootCase。op2 发送固定 relative GET，其余发送固定 absolute GET；target 永远是 argv 已绑定的 numeric loopback port。即使 HTTP 解析失败，`connect_completed=true` 仍是实际连通事实，不能当拒绝。transport timeout、缺报告或坏 HTTP 不能替代有健康 receiver 支持的明确拒绝证据。

每次操作的 phaseD 是原 D 的绝对收缩，不是 `now+timeout`。原始 T0/F/D 不续期；network observer 在每次 socket I/O 前后采样，partial send/receive、shutdown、exact body、实际 EOF 和单次 close 均沿用 frozen B driver。同步身份/文件/pipe API 本身不可取消，必须依赖外部绝对 Job watchdog；该 native 文件不声称消除同步调用阻塞。

## multiaccept origin 与独立健康证据

singleaccept B origin 会在 positive 后退出，因此后来的 direct connect refused 不足以证明隔离。`health-origin` 在同一个 O 持续监听，依次服务独立普通 health case、relay positive case 和后续普通 health case，直到明确 finish 或绝对截止。每次接受实际连接后，独立记录 peer tuple、case、QPC、request EOF、实际响应和 connection close；owner 必须与事先声明的 case 列表逐项比对，不能把随意 observed nonce 自洽当正控。

每次连接单独发布 `report.parent/receipt-0001.json` 至 8。无效/重复 case、格式错误、未知 close 或收发失败会写失败 receipt 并让 fixture 失败。达到 maxAccept 而尚未收到 finish 会失败 `accept-limit`，不是隐式继续或自动成功。建议首轮 maxAccept=8，留出预声明 before/during/after 正控。

fixture 的 `controlDir/finish.bin` 也是上表 128 bytes，但只允许 op255、seq1，P/Q/O=0、case=bootCase、admissionNonce=bootCase、phaseD=rootD；其余 run/F/D/reserved 严格绑定。它不接受任何网络 command。

## 闭合报告 keys

JSON 使用 CreateNew、禁止 share-write，单次 close；写入失败/未知 close 通过非零退出体现，不能靠同文件尚未发生的未来 close 自证。owner 还须独立观察 held process 退出和清理。

client READY keys：schema_version, stage=`proxy-c-client-ready`, role, run_id, boot_case_id, pid, identity, capability_profile, capability_profile_verified, catalog_cleanup_verified, qpc=[F,T0,D,last], admission_nonce, ready, network_initialized=false, failure。

client phase keys：schema_version, stage=`proxy-c-client-phase`, role, run_id, boot_case_id, pid, identity, case_id, sequence, operation, target_port, admission_nonce, root_qpc=[F,T0,D], phase_qpc=[observedStart,phaseD,last], command_close_verified, network, failure, proxy_tested=false, product_acceptance=false。network 与 frozen B `transport_report` 的 20 个 keys 完全相同，transport failure 保留在 network 中；phase.failure=null 只表示完成观测，不等于已拒绝。

client final keys：schema_version, stage=`proxy-c-client-final`, role, run_id, boot_case_id, pid, identity, capability_profile, capability_profile_verified, catalog_cleanup_verified, qpc, phase_count, finished, network_initialized_before_go=false, network_initialized, command_close_verified, failure, proxy_tested=false, product_acceptance=false。phase reports 为 resultDir/phase-NNNN.json，final 为 resultDir/final.json。

listener READY keys：schema_version, stage=`proxy-c-listener-ready`, role, run_id, boot_case_id, pid, identity, capability_profile, capability_profile_verified, catalog_cleanup_verified, qpc, port, ready, network_initialized, failure。frontend 的 boot_case_id 为其 pair case。

health listener final keys：schema_version, stage=`proxy-c-listener-final`, role, run_id, boot_case_id, pid, identity, capability_profile, capability_profile_verified, catalog_cleanup_verified, qpc, port, accepted_count, receipt_count, finished, listener_close, wsa_startup, wsa_cleanup, command_close_verified, failure, wsa_error。

receipt keys：schema_version, stage=`proxy-c-listener-receipt`, role, run_id, boot_case_id, case_id（无合法 nonce 则 null）, pid, index, port, peer_port, qpc=[F,observedAccept,D,last], request_bytes, request_exact, request_eof, response_bytes, response_complete, send_shutdown, connection_close, failure, wsa_error。

frontend final keys：schema_version, stage=`proxy-c-live-front`, role, run_id, case_id, pid, identity, capability_profile, capability_profile_verified, catalog_cleanup_verified, ipc_mechanics, listener, client, wsa_startup, wsa_cleanup, failure, wsa_error, http_boundary, network_tested, proxy_tested=false, product_acceptance=false。

frontend listener keys：port, listener_created, inheritance_cleared, exclusive, bind_loopback, accepted, peer_loopback, peer_port, listener_close。client keys：request_bytes, request_exact, request_eof, response_bytes, response_complete, send_shutdown, connection_close。

Native failure labels cover configuration, identity, capability, qpc/deadline, command, report, close, socket, bind, listen, accept, accept-limit, request, send, shutdown；frontend also保留 Probe 的 pipe_type/inheritance/pipe_read/pipe_write/eof/core。socket close 为 not_attempted/confirmed/uncertain；没有真实 WSA code 则 wsa_error=null，不伪造系统拒绝码。

## 构建与纯测事实

compile01 因 profile 的 wchar→char 隐式转换触发 /WX C4244，未生成合格 artifact；改为闭合枚举转换。compile02 成功后被 identity-only 网络门、phase case 去重及 cleanup 后采样修正 supersede。当前 compile03：MSVC 19.44.35229.0、SDK 10.0.26100.0、x64 /W4 /WX /MT /O2 /guard:cf，exe SHA256 `b5fda518d9b621ecf86899eff5aa2a1f33f1c313305542fcde26832ac0065be7`。C manifest 精确 11 keys，完整 pin 7 源。

`python -m unittest tests.test_windows_identity_proxy_c_native tests.test_windows_identity_proxy_origin_native -v` 在 x64 developer shell 实际跑 8 项，零 failures/errors/skips。C compiled fake 为 1,358 个闭合命令、reserved-bit、run/admission、sequence、target、绝对 deadline、fixture finish 场景；B compiled fake 390 个实际驱动 partial I/O/EOF/close/deadline 场景。测试 executable 不包含 actor 或 Win32/Winsock 调用入口，不能证明本机真实 listener/PSEC 网络兼容性。
