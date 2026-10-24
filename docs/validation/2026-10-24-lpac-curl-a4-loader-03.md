# A4 actual03：真实版本启动与完整 trace，封闭加载策略仍拒绝四次调用

固定 System32 curl 第二次在零能力 LPAC 中执行 `--disable --version` 并自然退出 0。输出为 366 字节，SHA256 `462db4e956d97703eae92a1863090a26987ab7b9bc55c43b4e11565918cc56a4`，stderr 为空；普通前后版本正控均通过。实际源提交为 `0d024290b4f86a3aae042b8b2c5499687fc93928`，90 文件闭包 SHA256 为 `c10559be677975f49baf7f2ddd21e9c370fc17eade2f7b05976f4356b6e7da7f`。私有内存序列、Config payload 只读读回、两份 `[2,0,0,2]` LPAC 证明及一次 raw count=1 的 Resume 均有原始收据；12 份 held 快照绑定同一进程代际、当前 primary 和双 Job。

本次已真实保存 557312 字节 trace，SHA256 `6274f3dcdcf27c78c063f9dad49d8c80faecfecaa74bb58f46f49c92f50a12d6`。Header 绑定、稳定读回、bootstrap 与 34 行提交均通过，未使用行全零，前后两次映像租约的 FileID、尺寸和哈希一致。但完整 A4 判定仍是 `inconclusive/trace`，`startup_diagnostic_observed=false`。原始原因保留为 `closed_gateway_failed_delivery`、`sticky_failure_or_unsupported`、`unsupported_loader_input`、`unsupported_procedure_observed`。

四条负向记录都具有捕获完整的自有输入与独立 SDK 收据：

| slot | 调用与捕获输入 | delivery | 对应 SDK |
|---|---|---|---|
| 22 | `LoadLibraryExW("api-ms-win-core-synch-l1-2-0")` | NULL / 126 | 未调用 |
| 23 | `LoadLibraryExW("kernel32")` | NULL / 126 | 未调用 |
| 24 | `LoadLibraryExW("api-ms-win-core-fibers-l1-1-1")` | NULL / 126 | 未调用 |
| 28 | ntdll `GetProcAddress("wine_get_version")` | NULL / 127 | 未调用 |

三次 Load 的 hFile 均为 NULL、flags 均为 `0x800`。这些是封闭 shim 的拒绝返回，不能写成系统 DLL 或函数不存在，也不能为取得通过而清除 unsupported 位或放开动态加载。`WSAStartup` 与 `WSACleanup` 各一次返回 0，来自本 shim 的诊断实现，对应真实 Winsock SDK 未调用；不是网络启动或连通证据。module 与 startup 引用计数均已知平衡，没有 overflow、input fault 或未知引用状态。

decoder 原样保留 `retained_view_count=1`、`all_resources_closed_or_empty=false`：目标内映射 view 按进程寿命保留，decoder 自身不证明其回收。另有精确目标自然退出 0，以及父 view、mapping、两个文件租约、observer、Job、标签、ACE、profile 等 14 项限定清理和 outer 清理全部通过的外层证据；`recovery_required=false`。不能把这两层事实合并成 decoder 已独立证明所有资源关闭。

本次前后 firewall、DNS、routes、user_proxy 四对象快照逐字节相同，均 8364 字节，SHA256 `8668bdf4b3802e415b53f95b88e322b804ef0f035463fdd5c5cad7e8f08ea4c3`，也与 actual02 快照相同。此前试次间 DNS/路由变化仍未归因；旧 actual01 失败和独立恢复、actual02 容量失败及更早 DNS/route/unknown 历史均保留。

本机 1423 项纯测试通过（353.246 秒、2 项既有环境 skip）；[源 CI](https://github.com/Shermanxwz/Rule-proxy-Web/actions/runs/40063419546) 同为 1423 项通过（214.376 秒、0 skip），20 项固定 PE 方法两端均执行，CI 运行时步骤全部跳过。测试与 CI 不授予实际验收。

这些事实支持另行设计窄 HTTP 适配试次，但没有执行或证明 HTTP、socket/connect/send/recv、DNS、TLS、代理、恶意同 SID 边界、root 崩溃连续性、完整应用兼容或 Linux 等效。A4 完整资格和产品验收均为 false；后续适配必须保留这里的四次拒绝与原始 trace。

[安全摘要](../../verification/windows-2026-10-22/lpac-curl-a4-loader-actual-03/summary.json) · [原始公报](../../verification/windows-2026-10-22/lpac-curl-a4-loader-local-03-public.json) · [原始预检](../../verification/windows-2026-10-22/lpac-curl-a4-loader-local-03-preflight.json) · [actual02](2026-10-24-lpac-curl-a4-loader-02.md) · [actual01 与独立恢复](2026-10-24-lpac-curl-a4-loader-01.md)。
