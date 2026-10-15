# 安装与验证脚本

Windows 0.3.0 使用 ProxiFyre 2.6.4 + Mihomo 1.19.32，不启用 TUN。正式用户入口是仓库或完整个人离线包中的 `Setup-Windows.cmd`，随后以原用户普通权限运行 `Start-Windows.cmd`。

- `windows-setup.ps1`：安装入口的实现。先记录未提升用户 SID；源码入口下载固定资产并暂存，完整离线包直接使用本地资产。UAC 后部署受保护的 Program Files 程序、归属记录与控制服务，校验依赖及驱动签名。返回 `3010` 时重启后重复同一安装入口续装。
- `windows-uninstall.ps1`：从已安装位置运行，必要时请求 UAC。只处理归属已确认的安装及指向它的用户快捷方式/启动项；保留用户数据、共享 NDIS 驱动和 VC 运行库。调用示例见 [README](../README.md#windows-更新与卸载)。
- `setup-linux-apparmor.sh` / `remove-linux-apparmor.sh`：Linux 专用 bubblewrap 副本和 AppArmor 策略的安装/撤销；由 Linux 准备入口按需使用，不属于 Windows 安装流程。

新的 Windows 产品验收入口为 `.github/windows_proxifyre_product_acceptance.py`。它应针对构建完成的实际 ZIP 检查安装、普通用户运行、控制服务身份、透明转发、重复安装、卸载与清理；当前最终包及 Windows 11 产品验收尚未完成。候选引擎 TCP/UDP 对照不能代替这个验收，也不能推导公网、DNS、IPv6 或故障隔离已经通过。

`scripts/windows-acceptance.py`、`.github/windows_browser_check.py` 与原 MXC/PSEC 专用流程保留作历史复现。它们针对旧隔离体系，不是 0.3.0 的支持探测或安装入口；历史运行方式与结果见 [旧产品说明](../verification/windows-2026-10-15/mxc-0.2.2-readme.md)。

更多当前功能、Windows 路径匹配/DNS/故障边界，以及 Linux 隔离说明见 [README](../README.md)。
