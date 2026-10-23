# CMM curl loader actual01：install 前置校验拒绝，未 Resume

本轮源码固定为 `9d0b20eed652f9e0da7d47f2a918a63ea2e7ea25`，70 项运行输入闭包为 `e5c0287b08bfb32bbe040c2b1a7299a01f563daf33aaa1e1ff741e6e06196fbf`。原始公报维持 `inconclusive / payload`、`observation_complete=false`、`recovery_required=false`。这次没有取得完整 loader/MM 机制资格。

普通 curl 前后两次 `--disable --version` 正控均自然退出0。selected 已创建并保持挂起；第一份 before-update LPAC AccessCheck 矩阵为 `[2,0,0,2]`，其观察资源已闭合。第二份证明尚未执行，因此原公报 `lpac_identity_verified=false` 保持不变。

| 原生操作 | 实测返回类别 | 本轮含义 |
| --- | --- | --- |
| begin | 9 | 只读 context 绑定完成 |
| update | 11 | 原调用返回 TRUE；可能已发生远端修改 |
| install | 1 | 前置校验拒绝；primary copy 调用未进入 |
| forget | 10 | 已退出后的 context 释放；物理 context 为零 |

selected 没有 Resume，也没有 observe、marker 事件或 MM 映射观测；随后受控停止并确认退出码1，不能记为自然退出。update TRUE 也不能推导完整保护恢复或远端 payload 缺失。

文件与源码独审定位了 native10 的跨句柄表数值比较：worker 关闭已继承 signal 的本地副本后，再打开 primary token，本地句柄数值可以复用；目标进程中保留的继承 event 位于另一张句柄表。原生 install 把目标 signal 数值与当前 worker 九个借用句柄逐数值比较，因而拒绝了这种合法复用。Python 显式继承列表和关闭时序一致，无需延后关闭或增加数值黑名单。本轮未执行目标 SetEvent，不能宣称目标事件可用性已实证。相关[句柄继承合同](https://learn.microsoft.com/en-us/windows/win32/sysinfo/handle-inheritance)与[同步对象继承合同](https://learn.microsoft.com/en-us/windows/win32/sync/object-inheritance)仅作合同佐证，不替代本轮来源链审查。

原生/目标、两 Job、借用查询、文件租约、事件与 stdio、观察资源、标签、精确 ACE、profile/SID 的14项限定清理谓词均为真，outer 清理通过。14项是谓词数量，不是创建了14个对象；profile 删除 API 正常返回也不是独立外部 absence 证明。

本轮前后四类全局对象（防火墙 profile、DNS、路由、用户代理）逐字节相同，均为7655字节、SHA256 `e2628e54697b73876c68b6ad3a055f407b8518023f42f239e1668599eba9b1e0`。更早7378字节 baseline 的两条路由差异仍保留，创建者与时间未归因；没有删除路由或重写 baseline。

本机完整纯回归为1350项、344.570秒、0失败/错误、2项旧 skip；自动 push [CI](https://github.com/Shermanxwz/Rule-proxy-Web/actions/runs/40037880515/job/120701707521) 为1350项、461.234秒、0失败/错误/skip，运行时步骤5–9均跳过。这些构建和纯测试结果不提供真实目标资格。

本页只记录 actual01/native10 与其对应测试；后续修订及试次须独立记录。网络、DNS、代理、产品接受、Linux 等效、恶意同 SID 边界、整个映射映像完整性、section HANDLE 关联和 DllMain 返回证明均未取得。既有 A3、DNS、PSEC 未知状态及其历史索引保持原样。

[脱敏实测摘要](../../verification/windows-2026-10-22/lpac-curl-mm-loader-actual-01/summary.json) · [源码与证据承诺索引](../../verification/windows-2026-10-22/lpac-curl-mm-loader-actual-01/index.json) · [原始公报](../../verification/windows-2026-10-22/lpac-curl-mm-loader-local-01-public.json) · [原始预检](../../verification/windows-2026-10-22/lpac-curl-mm-loader-local-01-preflight.json)。索引只提供必要原件哈希，不公开 private 路径、SID、PID、句柄、原始时钟、stdout 或完整私密审计。
