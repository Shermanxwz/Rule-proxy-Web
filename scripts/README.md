# 安装与验证脚本

Windows 0.3.0 使用 ProxiFyre 2.6.4 + Mihomo 1.19.32，不启用 TUN。正式用户入口是仓库或完整个人离线包中的 `Setup-Windows.cmd`，随后以原用户普通权限运行 `Start-Windows.cmd`。

- `windows-setup.ps1`：安装入口的实现。先记录未提升用户 SID；源码入口下载固定资产并暂存，完整离线包直接使用本地资产。UAC 后部署受保护的 Program Files 程序、归属记录与控制服务，校验依赖及驱动签名。返回 `3010` 时重启后重复同一安装入口续装。
- `windows-uninstall.ps1`：从已安装位置运行，必要时请求 UAC。只处理归属已确认的安装及指向它的用户快捷方式/启动项；保留用户数据、共享 NDIS 驱动和 VC 运行库。调用示例见 [README](../README.md#windows-更新与卸载)。
- `setup-linux-apparmor.sh` / `remove-linux-apparmor.sh`：Linux 专用 bubblewrap 副本和 AppArmor 策略的安装/撤销；由 Linux 准备入口按需使用，不属于 Windows 安装流程。

Windows 产品验收入口为 `.github/windows_proxifyre_product_acceptance.py`。它针对实际 ZIP，通过 Web API 检查 YAML 导入、节点切换、`related_paths` 保存及启停规则，并从生产入口 `Start-Windows.cmd` 核对面板的普通用户身份；TCP 和非 53 端口 UDP 流量与独立接收记录交叉核对。安装、重复安装/修复、卸载、卸载后重新安装、共享依赖保留及异常退出清理也分别记录。

Server、Windows 11 原生和可见 GUI 的验收结论分别以[当前验收状态](../verification/windows-2026-10-16/proxifyre-product/current-status.json)及其原始报告为准，必须与所用 ZIP 的 SHA-256 一致。脚本覆盖某项检查不代表该项已经通过；局部通过也不能替代完整验收。真实公网出口、实际断网安装、登录 Cookie 持久化和下载须有各自的明确证据，不能从本机接收记录或无头浏览器截图推导。DNS、IPv6 与故障期间的直连边界见 [README](../README.md#windows-应用规则与边界)。

`scripts/windows-acceptance.py`、`.github/windows_browser_check.py` 与原 MXC/PSEC 专用流程保留作历史复现。它们针对旧隔离体系，不是 0.3.0 的支持探测或安装入口；历史运行方式与结果见 [旧产品说明](../verification/windows-2026-10-15/mxc-0.2.2-readme.md)。

更多当前功能、Windows 路径匹配/DNS/故障边界，以及 Linux 隔离说明见 [README](../README.md)。
