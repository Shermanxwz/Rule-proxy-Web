# Windows 应用隔离：暂停交接（2026-10-24）

按用户要求，当前停止新增实现、编译及实测，仅完成本次文档和证据归档。恢复工作须等待用户明确要求。项目仍处于工程验证阶段，Linux 等效与产品验收均未完成。

## 当前真实进展

受测源码提交：`1363b4d787d7ae6b89f3a4cb5120f227ba0bd549`。本次归档是其后的文档/证据提交，不改变受测代码，也不宣称对归档提交重跑实测。

**A5 actual03 首次完成真实 curl 在零网络 capability LPAC 中的有限 HTTP 收发。** 两份 LPAC 语义证明在恢复线程前通过；实际请求 8193 字节、响应 12289 字节、stdout 正文 12176 字节精确匹配，curl 自然退出 0。557312 字节 trace 包含 144 条已提交记录，原始窗口内稳定读取并与 Config、传输及四份字节落盘交叉核对。独立审计仅使用原始文件、JSON、struct 和哈希，未重跑目标或用新报告替换原报告，没有发现影响该有限成功结论的问题。

路径为固定 curl → 私有 Winsock 适配层 → 匿名管道 RPS1 → 普通转发进程 → 固定 Mihomo → 本轮自有 loopback HTTP 服务。目标是固定数值地址，Mihomo 对该 origin 使用 DIRECT，DNS 关闭。因此这次证明应用字节能经过受控桥接链路，不证明远端代理、域名解析、TLS 或任意应用可用。普通前后控制是 `curl --version`，不是同轮普通 HTTP 对照；先前普通 HTTP 校准单独保留。

本机测试共发现 1545 项，1543 通过、2 项既有无权限 symlink 检查跳过；CI 1545 项全部通过、零跳过，固定 PE fixture 的 20 个方法均执行。CI 是源码/纯测试检查，runtime 步骤未执行。详见 [CI 40073727632](https://github.com/Shermanxwz/Rule-proxy-Web/actions/runs/40073727632)。

受监督运行的 115 个源文件与冻结清单一致；受测 Git 提交全部 3026 个已跟踪文件已核对，提交内容全部匹配，其中 3 个 CMD 文件按仓库声明以 CRLF 检出。该清单包含文档/证据，不能称作 3026 个源码文件。

## 清理及证据边界

本轮 14 项已知作用域清理及 outer 清理均通过，原始 `recovery_required=false`，没有本轮待执行恢复。四项全局配置快照本轮前后逐字节一致；其中不含 NRPT，不能据此声称所有全局配置均已核对。更早 DNS/路由基线差异仍未归因，不自动恢复。已知清理成功不等于独立外部 profile absence 查询、显式 unmap 的全部证明或 root 崩溃安全。

四个 closed loader probe 仍保留，完整启动诊断为 false；不将 shim 拒绝解释为 Windows 网络拒绝。原 actual01/02 失败报告、缺报告、旧 recovery 标志和 unknown 不回写。

## DNS 到底成功过什么

- 旧 G/PSEC 路径曾出现明确 DNS API 泄漏，此反例保留。
- semantic DNS02 在 **2 capabilities（AgenticAppContainer + privateNetworkClientServer）** 下，显式标准端口 DnsQueryEx 得到 5/5，普通前后同 API 与接收端正控成功；它不是零 capability 的结果，也不是默认 resolver 全面证明。
- 零 capability、同 held LPAC 的 pipe-DNS-NRPT actual01 得到 **87/87、无接收端命中**，结论是未知，不能记作 DNS 被阻断。另一轮在 NRPT 库存门停止，selected 查询未开始。
- 当前 A5 HTTP 不进行 DNS。固定 curl 的 getaddrinfo/freeaddrinfo 已找到接缝，但仍是不支持入口。历史 NRPT 两条规则没有受控 namespace/resolver/receiver 绑定，默认 DNS 仍缺受控且实际可达的接收端及普通同 API 正控。

## 能否完成：工程判断

现有结果说明“真实程序在零 capability LPAC 内，经普通进程代理桥传输实际数据”这条路线可以继续。针对明确列出的应用和受支持 API，逐步完成可用隔离方案有技术可行性。

对任意 Windows 应用、浏览器及子进程，达到 Linux 方案要求的整体隔离与透明兼容，现有证据不足以保证。主要未决问题包括解析/broker 路径、动态调用绕过、通用 socket 行为、浏览器沙箱及子进程、故障时禁止回退。不能给出有证据支撑的完成概率或工期，也不能把有限 HTTP 成功换算成项目完成百分比。

## 恢复后按依赖顺序推进

1. 复核分支、源清单、冻结产物及本机环境；继续使用已建立的普通 owner、身份/双 Job/原始超时/清理体系。
2. 将固定 HTTP 长度状态机扩展为有界通用双向字节流，保留原始绝对 deadline、背压、半关闭与失败状态。RPS2 目前只有设计草案，未创建新 header/fake、未编译或测试；候选目录只有原 RPS1 依赖副本。
3. 核对固定 curl 的 getaddrinfo/freeaddrinfo hints、service、线程和生命周期，再实现不可变 domain+port 绑定和代理端解析；同一真实 curl 验证域名 HTTP、TLS。虚拟地址/API 替代成功与 DNS 隔离证明分别记录。
4. 对最终同一 held 身份做 TCP/UDP、IPv4/IPv6、direct/wrong-peer、默认 DNS 的有正控防绕过测试；旧不同身份组合的成功不直接继承。
5. 在最终链路做 relay/Mihomo 在途死亡、无直连回退、普通同程序 HTTP/DNS 共存、子进程、多连接及产品/browser 集成，再判定验收。

加速方向是集中完成通用流和真实域名/TLS 这条依赖链，复用 owner，不再重复已通过的同一有限 HTTP 试次。后续本机权限或网络规则变更仍须先说明具体影响；不重装系统。

## 文件位置与完整性

- [actual03 安全摘要](../../verification/windows-2026-10-22/lpac-curl-a5-http-03/summary.json)、[证据及哈希索引](../../verification/windows-2026-10-22/lpac-curl-a5-http-03/index.json)、[独立物理审计](../../verification/windows-2026-10-22/lpac-curl-a5-http-03/lpac-curl-A5-actual03-independent-file-review-01.json)。
- [actual02 失败与修复前诊断](../../verification/windows-2026-10-22/lpac-curl-a5-http-02/index.json)、[actual01 原失败](../../verification/windows-2026-10-22/lpac-curl-a5-http-01/index.json)。actual02 的新 consumer 文件回放是独立诊断，不替代缺失的原 worker 报告。
- [完整受测提交文件核对清单](../../verification/windows-2026-10-22/lpac-curl-a5-http-03/windows-isolation-source-manifest-1363b4d.json)。原历史完整公开清单仍按其原归档范围解释；本次索引增量追加。
- 本机 `work/` 保留原始 private/a5-h01、a5-h02、a5-h03 证据树、构建06、metadata04、Ready03、根入口和收据，未删除或移动。当前有用生产源码已提交；未完成 RPS2 与 DNS 说明只作续接草案保存。
- 本机 `outputs/` 保存用户报告、当前状态 JSON、源码 manifest、受测提交源码 ZIP 和续接文件哈希目录。私有原始身份、句柄和日志不上传公共仓库。

此交接保存原始事实和下一步，不提供绕过审核的一键重跑入口。暂停后不自动恢复、排队新 CI 或建立自动任务。
