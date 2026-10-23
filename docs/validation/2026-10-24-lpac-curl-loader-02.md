# A3 curl loader 第二次试次：普通进程已创建，在 SD 校验处停止

实际源码 `8d949542795540d45440afc563d80ae51dd146d4`，62 文件闭包 `2fef7a151e8bf6693e54e98b08b39901a71705f666745db1d16d0202bbdfe062`。原状态为 `inconclusive / ordinary_before`，完成 false、恢复要求 false；独立纯文件审计的 worker schema、outer 绑定、public 重投影及安全组件投影均有效。

before task 的 attempted/process_returned 为 true，物理返回为 TRUE、PI 完整且 PID 与持有对象一致。随后在 `ValueError / ordinary_before / loader_process_thread_SD` 停止；尚未通过 admission，也未 Resume。ordinary 子进程由明确 workload-stop 监督停止，exit1，不能称自然退出或版本命令失败。before/after 控制收据仍缺失，空 stdout 不构成版本阴性。

SD invariant 是原进程/线程安全描述符读回的严格校验门。root 的独立物理文件补证核对 process/thread 各为两个 protected allow ACE，trustee 精确为 SYSTEM 与记录中的原普通父身份，mask 均为 0x1fffff；本归档不公开原 SID/SD，也不由这份文件读取证明其与 ALL_ACCESS 语义等价。本归档不放行 DACL、不把 source GA 与 OS numeric mask 的表现差异当成 OS 拒绝，也不从缺失的普通控制结果推断 LPAC 行为。后续源码修订必须用新试次，不覆盖这一停止点。

ordinary_before 仍早于 setup_profile。本轮未创建 LPAC profile，未改其 ACL/mandatory label，未创建 selected、marker lease/events、wrapper context、mapping 或 loader window，也未加载两个已编译 DLL。普通私有 artifact 父目录、outer ordinary guard/worker 及已创建后受控停止的 before 子进程确实存在。十一项 scoped cleanup 都 true，包含未创建资源的 no-op，不能写成十一项资源均分配后释放。

本轮仅修改固定三字符串 argv 的路径相等性验证，保留 DOS absolute bounds、原请求 argv、字节 pin、原120/115/85/max8上限、Job/身份/PI/清理门。新5项惰性 fake 与完整1265/277.114s/2旧symlink skips通过，0 failures/errors；这是纯测试。当前源码自动CI为1265/255.044s/0skip/OK，run40016869400，五个runtime步骤skipped。见[独立摘要](../../verification/windows-2026-10-22/lpac-curl-loader-actual-02/pure-CI-summary.json)。

原 DLL 的26 precompile原始输入、两个 C4005 warnings、CFG=false、静态 CRT/import/helper 恢复限制全部引用[01静态记录](../../verification/windows-2026-10-22/lpac-curl-loader-actual-01/native-static-view.json)，不重编、不把编译当加载。01的未调用CreateProcessW、早期测试/reader/preparer修订均引用原档，旧 LPAC_CURL_LOADER 不改。

本轮前后7655字节全局快照相同，四对象均相等；与最早7378字节基线的两条旧route差异及创建者/时点未知继续保留，不删除或归因。事件不证明DllMain返回，mapping不证明section HANDLE，helper TRUE不证明完整恢复；Winsock absence、网络/DNS/PSEC/Linux、hostile same-SID及产品资格保持false。

见[本轮索引](../../verification/windows-2026-10-22/lpac-curl-loader-actual-02/index.json)。原 public/preflight 原字节只被列入暂存计划，不由发布器改写。
