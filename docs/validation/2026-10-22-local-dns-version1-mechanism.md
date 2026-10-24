# DNS VERSION1：独立 ordinary 机制

首次真实运行（源 `cee07246b6d73d2da5934f0891d017a8617b510a`）未通过机制：API/result 均返回 87，自有 responder 的 query/answer 计数均为零。14 项监督、held 身份、Job 和 fixture 清理检查全部通过；没有 retry 或 resolver 设置变更。[公开结果](../../verification/windows-2026-10-22/dns-v1-local-01-public.json)和[摘要](../../verification/windows-2026-10-22/dns-v1-local-01-summary.json)保留失败。错误原因未确定，不把它解释为 API denial、wire absence 或 DNS 隔离。

新增[header](../../.github/native/windows_identity_dns_v1_probe.hpp)、[ordinary actor](../../.github/native/windows_identity_dns_v1_actor.cpp)、[compile-only helper](../../.github/build_windows_identity_dns_v1_actor.ps1)、[受监督入口](../../.github/windows_identity_dns_v1_local.py)和[纯测试](../../tests/test_windows_identity_dns_v1_local.py)。本页先描述实现；实际调用另行归档，编译和 fake 测试不能建立 API 或隔离通过。

这是单独的 `DNS_QUERY_REQUEST_VERSION1` 契约，不重跑已停下的 REQUEST3 参数路线。请求使用官方 `DNS_ADDR_ARRAY`，只指定数字 `127.0.0.1` 的一个 owned 高端口和新鲜 `<nonce>.n0a.invalid` A/IN 问题；固定 bypass-cache、wire-only、no-hosts/no-local/no-NetBT/no-multicast、FQDN 选项，不配置 default resolver、不写 NRPT、不清全局缓存、不安装规则。端口是否被系统 API 实际采用，只能由独立 responder 收到精确问题来确定；不能从结构字段或 API 返回值推断。

入口默认 preflight。实际 opt-in 为 `--run-local-mechanism --approved-local-security-test`，另需 actor/manifest、二者 SHA256、repo/private 内的 work-parent，以及设备、source closure、artifact 绑定的 recovery plan。guard 从开始采样一个 120 秒 QPC 截止，原子 JOB_LIST 创建普通 worker；worker 同样 held-before-resume、原子 Job 创建普通 native actor，所有 setup/fixture/API/wait/report/cleanup 均消耗同一原始预算。没有 AppContainer、UAC 或全局网络变更。

worker 只拥有单个有界 loopback responder。现有 responder 严格校验问题、nonce、类型/类和有限 EDNS，回复唯一 `192.0.2.123` A 记录，并独立计数。native 核对实际返回记录、精确名称与答案，释放记录。机制通过需 native API 完成和精确 answer、responder 精确问题/应答、双方 held identity/image、正常退出、零 timeout/error、两个 Job 与 socket/thread/handles 清理全部通过。`network_tested` 只由 responder 的实际 query observation 设置；`api.called` 独立记录 API 入口，包括 87 等失败，不表示 wire 或拒绝证明。仅在 completed=true 时解释 query_status；未完成时的零初值没有成功含义。

DnsQueryEx 无 callback 时使用同步调用。调用前后的 QPC 检查不能取消阻塞；外层 held Job 才是超时边界。意外 PENDING 会保留 request/result/name/server-array 的完整 heap context 至进程死亡，拒绝机制通过；不声称 DNS broker 已取消。native 非 ASCII、错误 JSON、身份/截止不匹配或后来 cleanup 失败，均保留已独立观察到的 receiver 正向事实。

21 项 fake 测试覆盖 malformed/non-ASCII、PID/SID/schema/type、actor/worker timeout、非零退出、API87 与实际 wire 分离、pending context、partial receiver snapshot 和 scope 造假；测试不调用 DNS、socket、process 或 security API。native 通过 MSVC 19.44 / SDK 26100 `/W4 /WX` 编译；独立 invalid-admission executable 没有 DNS 调用。证据见[compile/pure 归档](../../verification/windows-2026-10-22/dns-v1-compile-pure-01.json)。

无论 ordinary 机制是否通过，default resolver、selected PSEC 客户端、DNS 服务/broker 隔离、浏览器、产品验收都保持 false。下一步 selected 测试必须复用相同 API 与健康 responder，不能以 raw UDP、API 87 或包缺失替代。

依据：[官方 VERSION1 请求](https://learn.microsoft.com/windows/win32/api/windns/ns-windns-dns_query_request)、[DnsQueryEx 同步/异步和存储寿命](https://learn.microsoft.com/windows/win32/api/windns/nf-windns-dnsqueryex)、[微软 DNSAsyncQuery sample 的 server array 初始化](https://github.com/microsoft/Windows-classic-samples/blob/main/Samples/DNSAsyncQuery/cpp/DnsQueryEx.cpp)、[DNS query options](https://learn.microsoft.com/windows/win32/dns/dns-constants)。
