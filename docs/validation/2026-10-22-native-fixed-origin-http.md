# Native B：固定 loopback origin 的 HTTP transport

日期：2026-10-22。实现为 [origin actor](../../.github/native/windows_identity_proxy_origin_actor.cpp)、[portable transport driver](../../.github/native/windows_identity_proxy_origin_transport.hpp)，复用 [pipe Probe](../../.github/native/windows_identity_proxy_pipe_actor.cpp) 与 [core](../../.github/native/windows_identity_proxy_bridge_core.hpp)。构建入口是 [compile-only helper](../../.github/build_windows_identity_proxy_origin_actor.ps1)，测试是 [native pure suite](../../tests/test_windows_identity_proxy_origin_native.py)。

本页定义 native B ABI，不是独立 runtime 启动入口。实际运行必须由 B owner 对 origin、relay、AC frontend 全部 held admission、Job supervision 和清理；不能直接复制下面的 argv 启动。真实运行结果另行归档。[compile/pure 记录](../../verification/windows-2026-10-22/native-origin-compile-pure-01.json)没有执行 actor、没有测试真实网络。

## 准确命题和混合边界

AC frontend 内部生成固定逻辑 GET，经原 48-byte pipe 协议触发 ordinary relay。relay 只连接 127.0.0.1 的 fresh owned origin 高端口，发送 core 的固定 HTTP request，实际 shutdown(SD_SEND)，读取精确 canonical response 与真实 TCP EOF。独立 ordinary origin 只接受一次连接，先观察精确 GET 和 request EOF，才返回该 case 的精确响应。

frontend 请求输入和客户端 sink 仍为内部生成；48-byte REQUEST/RESPONSE 不承载任意浏览器流量。B 只可能支持这一固定 GET 的 relay→owned origin 正向机制。它不是外部客户端代理、identity-bound selected proxy、透明转发、OS 阻止直连、代理死亡失败关闭或 DNS/UDP/IPv6/broker 隔离证据。proxy_tested=false、product_acceptance=false。

http_boundary 固定为 generated-front-and-sink-native-relay-origin。不靠独立 schema 直接写 synthetic_http_only=false。network_tested 只记录相应真实 API/接收路径是否已经尝试；完整通过仍需三方 held 报告、nonce/tuple 绑定、EOF、退出和清理。

## 默认 A 不变的共享 seam

core Config 末尾增加闭合 OriginAuthority，默认 GuestFixture=0；B 显式 LocalLoopback=1，未知值拒绝。默认 A Host 仍是 10.0.2.2，B Host 固定为 127.0.0.1。Probe 构造末尾增加默认 relay_port=49153、默认 GuestFixture；只读 pending_http() 用于核对实际待发送 bytes。

定义 RULEPROXY_PROXY_PIPE_LIBRARY 时只省略 A standalone wmain，B 复用同一 Probe；A 默认 13-argc ABI、schema 和 synthetic 路径不变。48-byte wire 不添加 origin 字段。共享源 hash 因明确 seam 变化，B manifest 绑定真实新 hash；旧 A binary/manifest、438 项 source manifest、实际 A 归档不重写。

## 固定 HTTP 字节

端口来自 held ordinary fixture 的 fresh ready 文件，只接受 49153–65535，排除 core frontend 标识端口 49152。不接收 hostname、任意 IP/URL、方法、凭证、CONNECT 或 redirect 参数；不进行 DNS 或 WinHTTP/system-proxy 请求。

请求 byte-exact 为：

    GET /p1/<32 lowercase case hex> HTTP/1.1\r\n
    Host: 127.0.0.1:<origin port>\r\n
    Connection: close\r\n
    \r\n

响应是既有 canonical HTTP/1.1 200 OK、Content-Length: 32、Connection: close 与 32 字符 case hex。字段、CRLF、正文和实际 EOF 均须匹配。请求/响应各最多 256 bytes；额外一 byte、错误 nonce、仅匹配前缀、缺 EOF 都失败。

## Native ABI

pair 角色仍 pipe-front/pipe-relay，原 A 参数后追加 origin port，共 14 个 argc：

    origin-actor.exe pipe-front|pipe-relay
      run_nonce case_nonce report_path read_handle write_handle
      pair_start_qpc qpc_frequency pair_end_qpc
      expected_user_sid expected_ac_sid_or_none 0 origin_port

pair end 必须恰为 start+10F。frontend 使用 fresh 精确 AC SID，relay 为 none；两者都需非 elevated、零 capabilities、真实 Job 和上层 held identity/image admission。

fixture 共 9 个 argc：

    origin-actor.exe origin-fixture
      run_nonce case_nonce report_path ready_path
      qpc_frequency original_fixture_deadline_qpc expected_user_sid

fixture 必须先由 owner 验证 held ordinary token、image、Job，之后才 resume。native 再核对当前身份、actual F 和原绝对截止，初始剩余不超过 120 秒；不续期。owner 应在同一原截止内给准备、10-second pair 和 cleanup 留 reserve。

ready 是 CREATE_NEW/share-mode 0 文件，上限 4096 bytes。闭合字段为：

    schema_version=1, stage=bridge-origin-ready,
    run_id, case_id, pid, port, qpc_frequency, deadline_qpc,
    loopback_ipv4=true

reader 必须绑定 held PID、nonce、F、原 fixture deadline 和 fresh 路径。ready 只说明 listener 准备，不是最终 HTTP 或 cleanup 证明。

## Socket、截止和清理

fixture 仅创建 AF_INET/SOCK_STREAM/IPPROTO_TCP listener，WSA_FLAG_NO_HANDLE_INHERIT 加 clear/readback，SO_EXCLUSIVEADDRUSE，仅 bind 127.0.0.1:0。系统选端口后核验范围，不 retry 或使用 SO_REUSEADDR。accepted socket 同样清除继承标志。

relay nonblocking connect 后经 readiness、SO_ERROR 和真实 local/peer loopback tuple 核验。记录实际 send/recv 正进度；发送完实际半关闭，origin 观察 request EOF 后才响应。relay 只有完整实际 response EOF 后才向 core 供给响应并进入 RESPONSE 0。

每次 readiness wait 向剩余绝对预算缩短、最多 100 ms，前后采同一 QPC。同步 pipe/系统调用仍需外层 Job watchdog，不能承诺可取消。closesocket 前消费 slot，失败不析构重试；WSACleanup 也只尝试一次。connect、完整 send、响应/EOF 的正向观察在后续超时或 close 失败后仍保留。

connect/IO/response/deadline 失败只尝试有界非零 RESPONSE drain，之后 cleanup，不等待 DONE。不增加 capability、放宽父目录 ACL、改 DNS/代理路径、换身份或重跑 listener。

## 闭合报告

pair outer 精确字段：

    schema_version stage role run_id case_id pid ipc_mechanics origin
    http_boundary network_tested proxy_tested product_acceptance

stage=bridge-origin-pipe-test。ipc_mechanics 是既有 A schema 的明确 IPC 投影；其 network_tested=false 只描述此投影，不覆盖 B 的独立 origin 事实。frontend origin=null；relay origin 精确字段：

    port wsa_startup wsa_cleanup inheritance_cleared socket_created
    connect_attempted connect_completed peer_loopback local_port peer_port
    request_bytes request_complete send_shutdown response_bytes response_exact
    response_eof socket_close failure wsa_error

close 仅 not_attempted/confirmed/uncertain；failure 仅 null/setup/connect/io/response/deadline/close。wsa_error 为实际 Winsock code 或 null，不为内部断言猜造错误码。pair network_tested 等于 relay 实际 connect_attempted；frontend 为 false。relay positive 另需所有相关 boolean、精确 byte counts/ports、close confirmed、failure/error null。

fixture outer 精确字段：

    schema_version stage run_id case_id pid identity qpc socket ready_published
    failure wsa_error network_scope network_tested proxy_tested product_acceptance

stage=bridge-origin-fixture；network_scope=ordinary-loopback-origin；qpc=[F, observed_start, original_deadline, last]。socket 精确字段：

    wsa_startup wsa_cleanup listener_created inheritance_cleared exclusive
    bind_loopback port accepted peer_loopback peer_port request_bytes
    request_exact request_eof response_bytes response_complete send_shutdown
    listener_close connection_close

fixture failure 为 null/configuration/identity/qpc/socket/bind/listen/accept/request/send/shutdown/close/report/deadline。network_tested 等于实际 accepted，仍不等于通过。独立 positive 需所有相关 boolean、精确 bytes/nonce、两个 close confirmed、failure/error null，并与 held relay local/peer tuple 反向绑定。

上层必须验证 B outer 与两个独立 network reports，不能仅通过 legacy IPC 投影。native/ready 含 raw PID/SID/nonce/port，只留私有 staging，公开不得复制。

## 构建和纯测试

独立 artifact 为 windows_identity_proxy_origin_actor.exe、identity-proxy-origin-manifest.json。manifest 精确九键：

    schemaVersion compileOnly runtimeAcceptance actorSourceSha256
    identitySourceSha256 coreSha256 pipeHelperSha256 originTransportSha256
    executableSha256

五个 source pin 绑定 origin actor、identity actor、core、A pipe helper、新 transport driver。helper 使用 /W4 /WX /std:c++17 /EHsc /MT /O2 /guard:cf，编译前后复核 source；compileOnly=true、runtimeAcceptance=false，从不执行 EXE。

[归档 JSON](../../verification/windows-2026-10-22/native-origin-compile-pure-01.json)记录 source hash、manifest、4 项纯测试和 390 个 compiled fake scenarios：全部 partial send/recv 分块、每个响应截断/错误 byte、缺 EOF、溢出、connect/IO/close 失败、截止与 sticky facts、单次清理、默认 A authority/wire 和闭合 authority。fake executable 无 Win32/Winsock 调用。首次 NOMINMAX include 顺序编译失败、修正成功及后续源修订重编译也保留 history。

这些不是实际 B runtime 或网络证据；本 compile/pure 记录的 network_tested、proxy_tested、runtime qualification、product acceptance 全部为 false。
