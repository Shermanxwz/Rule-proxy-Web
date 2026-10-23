# CMM curl loader actual02：有限机制观测完成，curl 初始化仍失败

本轮首次取得新 CMM scope 的完整有限机制实测：原始公报为 `observed`、`observation_complete=true`、`recovery_required=false`。源码固定为 `464b2ddb200d2d711a82ccf7fe04c33464f640a4`，70 项运行输入闭包为 `8effea4db1dd12447a262c53cb4bede81ce2aebbefbf6396d1475a4ac78cdb96`，使用 Ready02、native11/build03。此前 actual01 仍保持未完成，原件不改。

普通 curl 前后版本正控均自然退出0。selected 的 before-update 与 before-resume 两份 LPAC AccessCheck 矩阵均为 `[2,0,0,2]`，各自身份、代际和观察资源闭合，并且都在原 Resume 之前。Resume 原返回计数为1，随后进入唯一预分配 native observe，没有延长原 root120 / worker115 / work85 / 最长8秒观察窗口。

| 操作 | 返回类别 | 已取得的事实 |
| --- | --- | --- |
| begin | 9 | context 与原输入绑定 |
| update | 11 | 原 update 调用返回 TRUE |
| install | 5 | marker payload copy 返回非空且符合原门 |
| observe | 7 | 109条 trace、2份完整 held、2份 marker 快照与2份 MM 观测；6项 inner gate 全真 |
| forget | 10 | 退出后的 context 释放，物理 context 为零 |

ENTERED 与 BODY 事件、coherent Marker320、MM 映射关联、原始调用 trace 和 native 资源闭合均通过；外层另核了普通正控、两份 LPAC 证明、真实 Resume、后续自然退出与全部清理。inner binary 的成功本身不能代替这些外层门。

selected 自然退出码为2，并未被受控停止；`selected_version_positive` 与 `version_behavior_observed` 仍为 false。私有 stdio 已直接核对：stdout 为0字节，stderr 为39字节，唯一诊断行为 `curl: error initializing curl library`，以 CRLF 结束。该文本没有 Winsock 错误码，不能据此归因 WSA10107 或任一具体初始化原因。有限 loader/MM 机制成功与应用版本行为失败是独立结论。

MM 关联不是 section HANDLE 身份证明，也不是整个映射映像的完整性验证；事件不证明 DllMain 返回或 curl 入口执行。完整还原、payload 缺失、恶意同 SID 边界、网络/DNS/代理、产品接受、崩溃安全监督和 Linux 等效资格均未取得。

14项限定清理谓词与 outer 清理均为真，没有待恢复状态。14项是谓词数量，不是14个实际对象；profile 删除 API 正常返回也不是独立外部 absence 证明。本轮四类全局对象前后逐字节相同，均为7655字节、SHA256 `e2628e54697b73876c68b6ad3a055f407b8518023f42f239e1668599eba9b1e0`。更早 baseline 的两条路由差异及未知创建者/时间继续保留。

本机纯回归为1350项、361.219秒、0失败/错误、2项旧 skip；本轮自动 push [CI](https://github.com/Shermanxwz/Rule-proxy-Web/actions/runs/40040676265/job/120710760563) 为1350项、216.378秒、0失败/错误/skip，运行时步骤5–9全部跳过。前一 source commit 的新 CMM 路径没有命中旧 workflow paths，不能沿用旧 CI 成功。后续只新增三个触发路径（CMM Python、CMM native、C++ fake），未改步骤、超时或运行时条件，也未改本机安全约束；修复后新 head 的 CI 成功另行绑定。

[脱敏摘要](../../verification/windows-2026-10-22/lpac-curl-mm-loader-actual-02/summary.json) · [源码/证据承诺索引](../../verification/windows-2026-10-22/lpac-curl-mm-loader-actual-02/index.json) · [原始公报](../../verification/windows-2026-10-22/lpac-curl-mm-loader-local-02-public.json) · [原始预检](../../verification/windows-2026-10-22/lpac-curl-mm-loader-local-02-preflight.json) · [actual01 历史](2026-10-24-lpac-curl-mm-loader-01.md)。只公开脱敏事实与哈希，不复制完整私密审计、private 路径、身份、句柄、原始时钟、二进制或 stdio 文件。
