# Windows 启动检查

严格检查已整合在应用启动流程中。只有容器内代理通道与阻断检查通过，真实应用才会启动。

`windows-acceptance.py` 提供独立能力检查及完整验收入口。完整模式需要自己的可用代理 YAML，验证真实代理、父子进程 IPv4/IPv6 阻断、双向回环隔离、正常停止、核心故障清理和宿主网络设置未变。运行方式及报告字段见 [README](../README.md#Windows-11-独立验收)。

`--transport-fixture` 使用固定本机字节检查真实 PSEC 通道及进程阻断，不需要代理凭据。`.github/windows_browser_check.py` 另用真实 Edge 验证渲染和持久 Cookie；`.github/windows_vm_test.py` 在 Linux KVM 中安装固定官方 Windows 11 评估镜像，以普通用户验证原生 x64 运行包。各模式仅声称实际完成的检查，固定数据检查不等于完整真实节点验收。

仅能力检查通过时报告 `acceptance_passed: false`，不能当作完整验收。目标 Windows 设备仍需确认实际浏览器兼容性、流量及异常退出行为；当前结果以对应提交的 CI 日志和验收报告为准。
