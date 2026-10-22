# Semantic-LPAC DNS02：标准 53 显式 DNS 明确拒绝

**本轮实际观察完整，LPAC 的 DnsQueryEx 返回 API/query `5/5`，记录为 0；普通同 API 前后控制均成功。** 接收端前后各记录查询 1、答复 1，selected 查询和答复均为 0。全部身份授权检查、自然退出和自动清理通过。该结果只证明这一个 standalone LPAC 显式服务器调用路径；[原 G/PSEC DNS API 泄漏](2026-10-23-selected-dns-standard53.md)仍成立，代理组合和完整 DNS 隔离尚未验收。

受测源码为 `9c5e56ace7e4f2a039d3e078bcb81082e44b60df`，35 文件运行时闭包为 `a0859d431fe25f8cb93f7d4c4381785770670087f857604073c4b80c92641081`。[原 public](../../verification/windows-2026-10-22/lpac-semantic-dns-local-02-public.json) 为 1805 字节、SHA256 `757ad3b8c48f7f4d6e4d6aab9feaef4915dc54b39cf1977484eed6119fcc744f`，状态 `observed`、`observation_complete=true`、`access_denial_observed=true`、`recovery_required=false`。

| 实际同 API 调用 | API / query | A 记录数 | 接收端查询 / 答复 |
| --- | --- | --- | --- |
| ordinary before | 0 / 0 | 1，精确匹配 | 1 / 1 |
| held LPAC selected | 5 / 5 | 0，无匹配答案 | 0 / 0 |
| ordinary after | 0 / 0 | 1，精确匹配 | 1 / 1 |

三个调用都使用原 native07 的 DnsQueryEx VERSION1、official-v1-zero-port 构造、显式 `127.0.0.1:53`、预声明 A 查询及各自新 nonce 名。selected 调用确实执行、完成且未 pending，在原 phase deadline 内返回，records/context 清理字段闭合；这里的 5 是实际拒绝访问，不是把 87、超时或 receiver 静默改算成拒绝。receiver 共接收 2 个 datagrams、124 字节；这是该 fixture 的接收字节下界，不是全机逐包捕获或 sender/broker PID 归因。

selected 仍有精确 AgenticAppContainer 与 privateNetworkClientServer capabilities，attributes 均为 4。每次恢复或发布 DNS GO 前，owner-held QUERY token 的完整身份与 TokenStatistics 先独立核验，随后独立 QUERY|DUP/Identification token 的四个 AccessCheck 描述符必须得到 LPAC `[2,0,0,2]`，并重新核对映像、代际和两层 Job。本轮 11 次检查全部通过，66 个 observer 资源均按一次关闭规则闭合；没有查询或伪填 class46，没有把请求过 OPT_OUT 自行当作证明。

[01 的 snapshot 接口错误](2026-10-23-lpac-semantic-dns-01.md)保留。02 仅在新 semantic Owner 中显式执行三阶段，并给 snapshot 传入从原 QPC budget 投影的 deadline，调用前后都检查原 cutoff；fixture 自己仍夹紧其初始 deadline。新增 StrictFixture 的 constructor/snapshot/finish 签名与真实接口直接比对，缺参仍会 TypeError，跨越原 cutoff 不会发布 selected GO。原 class46 入口、native07、其余 34 份运行时源码均未改，未给旧运行续期或自动 fallback。

本轮只执行一次标准 53 库存。bind、before、selected、after 四个门相对库存结束的年龄分别为 0.066918、0.1024355、0.1787631、0.2336346 秒，均小于原 5 秒限制；有效 NRPT 数为 0，绑定前 UDP/TCP53 库存为空。没有改系统 DNS 或缓存策略。默认 resolver、其他服务器、其他 DNS 方法和服务 broker 不在本轮结论内。

四个 grant 工具、selected、health、库存工具和 remove 工具共 8 个子任务均自然退出 0；没有用清理终止代替自然成功。fixture socket/thread、Job、进程/线程/token 句柄、精确 SID ACE 与 fresh profile 全部清理，无独立恢复。after 配置快照为 7378 字节、SHA256 `f05d91ee76ee8a97ae5ab3bfa092167a8ee560c083255f142e6c453f2edf7ab3`，与最初 baseline 字节相同；快照只包含 firewall profiles、DNS、routes、user proxy，不含 NRPT。

[证据索引](../../verification/windows-2026-10-22/lpac-semantic-dns-local-02-evidence-index.json)和[组件投影](../../verification/windows-2026-10-22/lpac-semantic-dns-local-02-component-projection.json)逐字节核对 35 份受测 Git blob/LF 源码、9 个 native pins、13 个 manifest 字段、7 份原生报告、5 个 GO、11 份 semantic 意图、17 份普通所有权意图及原始 stdio。独立 file-only 审查重新解析全部原始证据并重投影 public。outer heldworker/guard/exit 事实沿用原 source-bound public checks；原入口未单存 outer launch ledger，归档没有伪造一份。

23 项新入口纯测试通过；完整身份相关纯测试为 827 项、47.484 秒、零失败、2 项原有本机 symlink skips。受测源码[自动 CI](https://github.com/Shermanxwz/Rule-proxy-Web/actions/runs/39866557169)为 827 项、47.929 秒、零 skips，5–9 号 gated runtime 均跳过。CI 仅编译基础 actor，真实 DNS 结果来自上述独立本机运行。尚未在本机运行 Linux 测试，纯测试 fake 的跨平台兼容性另行审查。

接下来需另建受监督的 PSEC+LPAC 无网络构造/身份实验，再验证同一组合中的真实代理链、直连、DNS、错误端口/peer 和代理死亡边界。当前 `g_psec_tested`、`proxy_tested`、`default_resolver_tested`、`dns_isolation_qualified`、`product_acceptance` 均为 false；本轮不构成 Linux 等效验收。
