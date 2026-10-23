# A3 System32 curl loader 首次试次：在普通前控创建前停止

受测源码 `d7ec75b4b743311c7e9ffd3116aa9fd19cfed665`；62 文件原始字节闭包 `0c993f0f8507d27826cebc5abf66b70c99407ee43d4fdcabf14f7e98dd776642`。原 public 为 `inconclusive / ordinary_before`，完成 false、恢复要求 false。源码绑定的独立纯文件审计确认 worker schema、outer 绑定、public 重投影和安全组件投影均有效。

唯一 task 是 before，attempted/process_returned/admitted/resumed/exited 均 false。原安全错误为 `ValueError / ordinary_before / loader_constructor_inputs`：curl 的 Windows CreateProcessW 未进入，不能写成 Windows 拒绝、curl 退出失败、LPAC 或 DLL 兼容性反例；底层唯一原因尚未证明。普通 before/after 控制收据均缺失，不能用空 stdout 补成阴性或成功。

ordinary_before 先于 setup_profile，因此本次未创建 LPAC profile，未修改该 profile 的 ACL 或 mandatory label，未创建 selected target、marker 事件、loader context、mapping 或 loader window，也未加载 wrapper/marker DLL。普通私有 artifact 父目录及受 outer Job 监督的 ordinary worker 确实存在。十一项 scoped cleanup 均 true，包含未创建资源的 no-op；这不是十一项资源已分配并释放，也不清理旧试次的未知资源。

原设计保留 root120/worker115/work85/max8 loader 窗口上限，本次没有窗口准入。即使后续观察到事件，也不证明 DllMain 已返回或 curl 入口；映射关联是路径与 retained-file identity 相关性，不是 section HANDLE 直接证明；Detours helper TRUE 不证明完整保护/分配恢复。无 URL 的版本参数也不能推出 Winsock 不存在或所有初始化无网络活动。

两个 DLL 仅完成编译与静态检查：原始 precompile26 为六新 native 输入与二十固定 Detours raw 文件，保留两个 vendor 文件的 CR 字节。十七个工具命令退出 0；两个 C4005 宏重定义 warning 保留，CFG flag 为 false，ASLR/NX/high-entropy 为 true。静态 CRT 文件/加载库/锁辅助导入和官方 OutputDebugString 诊断并未被说成不存在。native-pure01/02 的测试 harness 失败、pure03 两方法通过、早期 core decoder/假链失败、设计与 driver/reader 修订及 staged EOF 停止均在[准备历史](../../verification/windows-2026-10-22/lpac-curl-loader-actual-01/preparation-history.json)按原 commitment 保存；这些都不是执行目标的证据。

实际源码完整纯套为 1260 tests / 273.694s / 2 旧 symlink skips，0 failures/errors；旧 Ready01 的1260/267.087s单列，不转嫁。自动 source CI [40013724752](https://github.com/Shermanxwz/Rule-proxy-Web/actions/runs/40013724752)为1260/265.719s/0skip/OK，五个 runtime 步骤均 skipped。原 decoded UTF8 BOM/CRLF CI log 只承诺298056字节与哈希，未公开原始日志；API结论来自 root 的单独安全收据。

本轮 before/after 四对象快照均7655字节、逐字节相同；firewall、DNS、routes、user_proxy 均相等。与最早7378字节基线相比，DNS/firewall/user_proxy 相同，routes 仍有原有两条差异，创建者和时间归因未知；原 after 不改写，不删路由。旧 atomic01 unknown、DNS 泄漏及所有此前结果原样保留。

恢复完整性、hostile same-SID、网络适配、DNS/PSEC、Linux 等效及产品验收资格均 false。后续修订/重试必须有独立源码与新证据，不覆盖本次停止记录。详见[本轮索引](../../verification/windows-2026-10-22/lpac-curl-loader-actual-01/index.json)。
