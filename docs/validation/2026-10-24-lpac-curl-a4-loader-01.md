# A4 actual01：映像头校验停止，独立恢复完成

A4 actual01 在 base_probe 阶段停止。选中 curl 仍处于挂起状态，未 Resume，未加载私有 shim/carrier，也未进入远程导入修改或 Config GUID 注入。PBI、PEB、内存区域查询及 1024 字节头读取均成功；内存头与固定磁盘头仅 ImageBase 字段不同，且内存值精确等于 PEB 给出的实际映射基址。原模型直接比较磁盘头，未反映该 ASLR 基线差异，因此触发 a4_base_header。这是模型输入不匹配，不能解释为 LPAC 网络拒绝或 shim 启动结果。

原清理工具正常退出并报告处理 267 项，但随后的 ACL 逐节点证明仍调用旧 256 节点遍历，必然超界；因此 acl_removed/profile_deleted 未获确认，profile 删除未进入。原公报保持 inconclusive、recovery_required=true，原报告与 forensic 字节相同，均不因后续恢复而改写。当前树共 270 节点，另 3 项是清理后写入的报告文件。

独立 recovery01 由新的普通 worker 与 outer Job 监督：重新绑定原源码、设备、旧代际与原 SID，记录整树 270 节点的该 SID ACE 为空、4 个输出节点的 mandatory-label ACE 不存在，再对精确原 profile 名执行一次删除 helper。其正常返回、11 项 scoped facts、worker 绑定及显式 outer process/Job/handle 清理均获记录。该证据支持这次限定恢复正常返回；不等于另行查询确认外部 profile 已不存在。恢复未运行 curl、私有 DLL、icacls 或 label 写入。

实际试次与独立恢复各自的前后四项全局快照均逐字相同（firewall_profiles、DNS、routes、user_proxy）。这不抹去更早两条路由变化的未归因历史。当前没有获得选中 curl 启动、真实 Winsock、DNS、代理链、TLS 或 Linux 等价资格；revision02 应作为新的独立试次记录。


源码为 `10ac2233d03bb63fe45dbbcfe5a02043c452fe25`。后续修复源为 `ebc2c6dac85975bf692abd08e76bd83d1d37947a`，修复结果需由独立 actual02 证明。

[原失败公报](../../verification/windows-2026-10-22/lpac-curl-a4-loader-local-01-public.json) · [原预检](../../verification/windows-2026-10-22/lpac-curl-a4-loader-local-01-preflight.json) · [独立恢复公报](../../verification/windows-2026-10-22/lpac-curl-a4-loader-local-01-recovery01-public.json) · [独立恢复安全投影](../../verification/windows-2026-10-22/lpac-curl-a4-recovery01-safe-review.json)。
