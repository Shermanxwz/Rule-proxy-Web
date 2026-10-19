# Windows 离线网络恢复

用于恢复 RuleProxy 旧版全局 TUN 遗留的断网，不是 Windows 万能网络重置器。
Windows 原生 64 位 PowerShell 5.1，无需网络、Python、旧安装账户资料或重新安装 RuleProxy。

## 一键使用

在能上网的电脑下载仓库 ZIP，或在 GitHub Actions 的 **Windows offline network recovery** 成功任务下载 `RuleProxy-Network-Recovery` 附件。把解压后的文件拷到断网电脑：

```text
Recover-Windows-Network.cmd
scripts/windows-network-recover.ps1
```

使用受影响的 Windows 账户，双击 `Recover-Windows-Network.cmd`，确认 UAC。无需保持原安装路径。
入口执行 `-Apply -CheckInternet`，完成后显示结果并等待回车。UAC 如果切换成另一个 Windows 账户，会拒绝修改，避免恢复错用户的代理。
完成后先不要再打开旧面板；已停用的控制服务和本项目登录自启需要后续安装修复才重新启用。

## 只读检查 / 命令行

管理员 PowerShell：

```powershell
powershell -NoProfile -ExecutionPolicy Bypass -File .\scripts\windows-network-recover.ps1 -Json
powershell -NoProfile -ExecutionPolicy Bypass -File .\scripts\windows-network-recover.ps1 -Apply -CheckInternet
```

默认仅检查，不修改网络。`-CheckInternet` 自愿向微软、百度发起各最多约 8 秒的 HTTP 请求；普通检查不访问外网。
代理的实际连通性也可能受站点策略影响；检测失败不自动扩大清理范围。

## 会处理什么

- 通过固定服务命令行、安装路径确认的 RuleProxy 控制服务、面板与核心；服务停用、进程退出、同路径登录自启撤销。
- 通过官方 WFP API 枚举，不依赖 `netsh` 的 XML 格式。完整标记、由产品算法导出的 UUID、提供程序关联、子层及连接层都匹配后，才删除自己的过滤器。事务内再次确认对象未变。
- 过滤器独立提交；空的子层、提供程序尽力清理，不因无阻断能力的空容器无法删除而回滚过滤器。
- 完整标记、根命名空间、两台固定虚拟 DNS 都匹配的 NRPT 规则。复查有效策略，清 DNS 缓存；读取失败不算干净。
- 名称和产品确定性 Wintun GUID 同时匹配的网卡：停用该虚拟网卡，移除其上的手动路由；保留物理网卡及共享驱动。
- 当前用户的 `RuleProxyWebSafe/system-proxy.json` 恢复记录：检查冲突后还原原系统代理及 WinINet 连接标志；保留记录，供原面板确认恢复。

修改前把诊断及设置保存到仅管理员和 SYSTEM 可访问的 `%ProgramData%\RuleProxy-Network-Recovery\<时间-随机值>`。`before.clixml` 与 `result.json` 用于诊断，**不是完整自动回滚保证**：例如进程终止和 WFP 原过滤条件不能凭它完整重建。

## 无法确认归属的代理

没有有效 RuleProxy 恢复记录时，默认不关闭其他软件的本机代理。确认本机回环代理 / PAC 已经废弃后，可明确选择：

```powershell
powershell -NoProfile -ExecutionPolicy Bypass -File .\scripts\windows-network-recover.ps1 -Apply -ResetDeadLoopbackProxy -CheckInternet
```

该开关可能影响**其他软件**暂时未启动的本机代理：仅当配置全为回环地址且端口全部没有监听时，关闭当前用户手动代理、失效的回环 PAC，或机器 WinHTTP 静态回环代理。不修改远程代理、组策略、其他用户代理或正常监听中的代理。

## 结果与边界

| 退出码 | 含义 |
|---|---|
| 0 | 未检测到剩余阻断项；并不等于已证明能上网 |
| 1 | 有残留、其他账户待恢复，或指定的外网探测未通过 |
| 2 | 未提升权限，或 UAC 切换账户；未修复网络 |
| 3 | 预检 / 执行 / 校验失败；看报告中的 `changed` 判断已经完成的修改 |

完整预检失败不会开始修改网络。执行阶段一旦报错，停止后续修复，已提交的修改不会被说成“完全没改过”。脚本可重复运行。

不会清空全机防火墙、重置所有网卡、删除第三方 VPN、卸载共享 NDIS/Wintun 驱动，或强制改掉企业 DNS / 代理策略。域策略、未知版本标记、没有归属证据的残留、其他 Windows 账户、物理网络故障需要针对性处理。Windows 只显示“无 Internet”而浏览器实际正常，也可能是 NCSI 探测失败，不应据此扩大清理。

自动化包含 PowerShell 解析、C# 互操作编译、模拟故障流程，以及一次性 Windows runner 上真实创建/删除自己的 WFP、NRPT 并保留外来规则。通过 CI 仍不代表已经在你的断网电脑上恢复成功。
