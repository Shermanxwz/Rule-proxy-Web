# 零能力 LPAC 经受监督 Mihomo 的有限 HTTP 消息交换 A2-01

受测源码 `99ae5695d3cfb66edaeff79074bca4c305014f5d`，49 文件闭包 `73e02a396c3b9bf698d00ab1280c80b4d4889e3aaf0c62d818afd885034dd28a`。原 public 状态为 `inconclusive`、failure=`core-check`、完成=`false`；独立薄证据完整确认=`false`。缺失、部分或无效记录保持未知，不补自然退出、TCP 关系、sink 或成功结果。

作用域是同一真实零 capability LPAC 的继承双管道/RPS1 → ordinary relay → ordinary held Mihomo SOCKS5 → owned HTTP origin。selected 原有三个源码、RPS1 和原 selected artifact 不变；不给 selected socket，不增加 PNCS、registryRead 或其他网络 capability，不以 fallback 重试。

原 public 的挑战长度为 `{"request": 8193, "response": 12289}`；五个物理 HTTP sink 完整核对=`false`，barrier 期间四条 established TCP 原始行及 held 前后关系核对=`false`。SOCKS 握手字节与 HTTP payload 分开计数；OPEN_OK 仅是握手结果。Content-Length 完整请求触发 origin ACK，owner 在原 pair10 内取得两 hop 四行与 held 证据后才发布 release，响应完成和真实 proxy EOF 后才做发送关闭；这不是透明 TCP FIN 或全双工转发。详见[组件](../../verification/windows-2026-10-22/lpac-stream-mihomo-origin-actual-01/components.json)。

三个 native actor 自然 0=`false`；独立 Mihomo `-t` config-check 自然 0=`false`。长寿 Mihomo 的固定 held controlled-stop 是另一类生命周期结果，不能写成自然 0；租用端口、stdio 与清理事实按原 ledger 分开保留。root120/worker115/work85/pair10 和 barrier≤2F 不续期。

Mihomo 使用固定普通身份私有 sibling bundle；二进制 vcs.modified=true，精确 tag 源码等价和实际监听器 SO_EXCLUSIVE 选项未证明，也未排除所有启动时额外外联。前后 firewall/DNS/routes/user_proxy 四对象按实际快照比较；历史两条 IPv6 route 增加的创建者/时点仍未知，不删除或归因。旧 atomic01 unknown、旧 DNS 泄漏、API87 及 strict NRPT 停止记录全部保留。

暂停时 full01 是用户要求休息而中断，既不算完整通过，也不算断言失败。完成的全量测试、自动 source CI 与实际 assay 分开记录；compiled assertions 不充作新增 unittest 数，CI 五个运行时步骤跳过。见[纯测试与 CI](../../verification/windows-2026-10-22/lpac-stream-mihomo-origin-actual-01/pure-CI-summary.json)。

未声称任意应用/浏览器适配、透明双向 TCP、直接网络/DNS/UDP/IPv6 拒绝、broker 归因或取消、hostile same-SID 安全、PSEC/G、Linux 等效或产品验收；所有广义资格保持 false。
