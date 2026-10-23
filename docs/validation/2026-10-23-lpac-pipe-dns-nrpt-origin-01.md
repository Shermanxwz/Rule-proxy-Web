# 同一 LPAC 进程 IPC＋显式 DNS：NRPT exact-FQDN 新作用域 01

受测源码 `c9633b2cbb82f9a3c47ac5b8624d3cc1a1b39ce0`，47 文件闭包 `b9043b7ec45fd50bb72ba95e300c8dcb7f97a4afa3599899a87d83a57207a1fe`。原 public 的状态为 `inconclusive`、failure 为 `protocol`，完成标记 `false`，恢复标记 `false`。本页按原值记录，不将缺失、超时或零收包补成访问拒绝。

策略模式为 `effective-exact-fqdn-nonmatch-only-v1`：单次有效库存完整保留 16 个 CIM 语义字段，只允许可识别、互异且与三个预声明查询均不匹配的 exact FQDN；原有效规则数为 `2`。suffix/root/wildcard/IP/未知/匹配或 DirectAccess 等不安全形态仍停止。每个授权门复读同一物理 stdout、重算同 SHA，保持原 5F 时效和 root120/worker115/work85/pair10，不重收库存或续期。

selected DNS API tested=`true`，独立 receiver selected hit=`false`；原安全 API 结果为 `{"answer_match": false, "api_status": 87, "called": true, "completed": true, "context_retained": false, "pending": false, "query_status": 87, "query_status_success_verified": false, "record_count": 0, "records_released": true, "within_deadline": true}`。IPC/同 PID 身份、两次语义 proof、ordinary 前后正控、四门与完整清理是否成立均见[摘要](../../verification/windows-2026-10-22/lpac-pipe-dns-nrpt-origin-actual-01/summary.json)及[组件](../../verification/windows-2026-10-22/lpac-pipe-dns-nrpt-origin-actual-01/components.json)。只有原绑定的完整 API5 路径可记录窄范围访问拒绝；其他错误、pending、迟到或未知均不能升级。

前后四对象的实际字节/逐对象比较见摘要；NRPT 是单独运行时库存，不在这四对象快照内。旧 IPC 两条 IPv6 route 增加的创建者/时点仍未知，不删除、不归因；旧 atomic01 unknown 与旧 strict-count-zero DNS01 库存门失败原件均保持。作用域已知清理不证明广义机器状态或崩溃安全。

首次 full01 22 项 portable 编译测试因 shell 无 cl.exe 失败，原日志保留；加载工具链后 full02 在相同源码上通过。较早自动 CI 39941906069 达八分钟 job 预算后取消，末段 KeyboardInterrupt 且没有 Ran 总结，不能填完整套数或计为 DNS API 失败；仅 CI workflow 预算改为十二分钟，本机所有原期限不变。后续自动 CI 与本机实验分别记录，五个运行时步骤跳过，不将 CI 绿色当作隔离实测。见[纯测试与 CI](../../verification/windows-2026-10-22/lpac-pipe-dns-nrpt-origin-actual-01/pure-CI-summary.json)。

未声称默认解析器、全部 DNS/UDP/IPv6、broker PID 或取消、PSEC/G、浏览器/任意应用、Mihomo、Linux 等效或产品验收；所有广义资格保持 false。
