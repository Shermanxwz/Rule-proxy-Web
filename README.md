# RuleProxy Web

Windows / Linux 本机 Web 面板：导入 Mihomo YAML、选择代理节点、添加应用，从面板启动受保护实例。

**当前版本 0.1.0。只保护从面板启动的实例。已打开的普通实例不会自动接管，请先自行关闭。**

选中应用的代理入口强制使用所选节点。无法经过代理的流量阻断，不自动直连。不修改系统代理、网卡 DNS、全机默认路由，不创建系统启动任务。

## 开始使用

### Windows

要求 Python 3.10+、x64 Windows 11，以及系统实际支持 Microsoft MXC 的 BaseContainer 代理隔离能力。Windows 10 和旧版 Windows 11 的严格模式不可用。系统版本符合最低条件也可能缺少所需更新，面板会检查并拒绝不支持的启动。

官方 MXC 的系统支持表列出 Windows 11 24H2 的 `26100.9278`、25H2 的 `26200.9278` 等更新版本；最终以本机请求级能力检查为准：[系统支持表](https://github.com/microsoft/mxc/blob/v1.0.0/docs/backends/process-container/os-version-support.md)。

1. 解压整个运行包。
2. 双击 `Start-Windows.cmd`。无需以管理员身份运行。
3. 在面板导入自己的 YAML，选择节点，启动核心。
4. 添加应用路径和对应启动方式，点击“启动隔离实例”。

从 GitHub 下载源码时，先双击 `Setup-Windows.cmd`，下载经过固定校验值验证的本地运行组件和 Python 依赖，再双击启动文件。所有文件只安装在项目目录下。

### Linux

要求 Python 3.10+、bubblewrap，以及可用的用户和网络命名空间。运行包已带核心；源码使用下面的准备步骤：

```sh
# 在项目目录下；这些步骤不更改网卡配置。
python3 -m pip install --target vendor -r requirements.txt
python3 install_runtime.py --platform linux-amd64
sh start-linux.sh
```

发行版未安装 bubblewrap 时，通过发行版的软件管理器安装它。用登录桌面的普通用户启动面板。不要用 sudo 启动浏览器。

面板默认地址：`http://127.0.0.1:8879`。关闭启动终端或在面板点击停止，会先关闭本工具启动的应用，再停止本工具的核心。

## 应用支持范围

| 启动方式 | 行为 |
|---|---|
| Chrome / Edge / Brave | 使用独立浏览器配置、本地 HTTP 代理，禁止 QUIC 和非代理 WebRTC UDP |
| Firefox | 使用独立配置、SOCKS5 远端 DNS，关闭预取 |
| 遵循代理环境变量的应用 | 启动时设置 HTTP(S)/ALL_PROXY；忽略代理的连接会被隔离边界阻断 |

这版提供 TCP HTTP / SOCKS 代理通道。UDP、需要额外桌面服务或不兼容隔离的软件可能无法使用；失败不会退回直连。IPv6 目的地可通过代理访问，应用直接建立 IPv6 连接会受隔离限制。无法承诺任意软件都能兼容，尤其是自带后台服务、驱动、外部登录器或通过宿主进程代发网络请求的软件。

Linux 未开放 D-Bus、桌面门户和音频服务，仅按需开放直接的 X11/Wayland 显示连接。保护范围是隔离内的应用及其子进程；不包含隔离外原先运行的服务，也不是用于防御恶意软件利用桌面 IPC 的安全产品。

## YAML 导入

支持当前版本的内联代理节点，例如 VLESS、VMess、Trojan、SS。参考配置在 `examples/ruleproxy.example.yaml`，示例节点需要替换为自己的节点。

导入时重建本机入口：

- TUN 关闭；只监听 `127.0.0.1`。
- 应用入口固定到 `RuleProxySelected`，只能选择实际代理节点。
- `DIRECT`、`dns-out` 等不会进入可选节点；导入规则中的直连例外不适用于受保护入口。
- 目的地解析使用经所选节点发送的 DoH。代理服务器自身是域名时，仅节点服务器的引导解析使用系统 DNS；不改变系统 DNS。
- 导入的监听器、系统网络设置不生效。第一版不导入 `proxy-providers`、`rule-providers`、脚本、插件或本地证书文件引用；不支持时明确报错。

节点名称会显示在面板，服务器、UUID、密码等不会通过状态 API 返回。导入内容只保存在本机。**不要把包含真实节点凭据的 YAML 推到公共仓库。**

## 隔离设计

Linux：每次启动创建独立网络和进程命名空间，没有上联网卡。仅通过专用 Unix socket 将隔离内的回环 TCP 入口连接到宿主 Mihomo。应用无法访问宿主 IP 网络；子进程继承隔离。没有 veth、NAT、宿主防火墙变更或全机 TUN。

Windows：使用固定版本 Microsoft MXC 1.0.0，请求级检查必须返回 `base-container` 和 identity-less loopback proxy 支持。策略只允许连接指定代理地址/端口，并默认拒绝外部 IPv4/IPv6 出站；不接受 AppContainer 的弱化回退。策略作用于新容器及子进程。生命周期由 MXC / 系统管理；本工具不安装旧版的全机 WFP 断网守卫。

正常停止会关闭已核对身份的应用进程，让 MXC 自行完成清理；不会强杀 MXC 守卫进程。若无法确认或完成关闭，保留守卫和核心并显示错误，请自行关闭对应隔离窗口，再重试停止。

参考：[MXC 网络策略](https://github.com/microsoft/mxc/blob/v1.0.0/docs/backends/process-container/networking.md)、[Mihomo 监听器](https://wiki.metacubex.one/en/config/inbound/listeners/)、[Mihomo DNS](https://wiki.metacubex.one/en/config/dns/)。

## 检查与当前验证范围

```sh
python3 -B -m unittest discover -s tests -v
```

已在 Linux 实际检查代理通道、直连 IPv4/IPv6、DNS/UDP、子进程继承隔离，以及主机接口/路由未变；并用固定 Mihomo 校验参考 YAML。Web 导入、启动核心、应用管理、停止流程经过本机检查。

Windows 的策略和拒绝回退逻辑有模拟检查，**尚未在目标 Windows 设备验证应用兼容性、出站阻断及异常退出清理，因此不能称为已实测零泄漏**。随包提供 `scripts/verify-windows.py`，需要在核心运行时于目标 Windows 检查。它不更改全机网络配置；详见脚本说明。

在解压目录打开 PowerShell，保持面板核心运行，然后执行：

```powershell
py -3 .\scripts\verify-windows.py --runtime .\bin\windows-amd64\wxc-exec.exe --profile .\work\verification --proxy-port 10809
```

检查通过也不代表任意应用都没有泄漏；直接 TCP 超时可能仅因测试地址不可达。应用兼容性、子进程与实际外部 IPv4/IPv6 阻断仍需要在目标设备确认。

本机数据独立于旧版目录：Windows `%LOCALAPPDATA%\RuleProxyWebSafe`；Linux `$XDG_DATA_HOME/ruleproxy-web-safe`（默认 `~/.local/share/ruleproxy-web-safe`）。核心日志为该目录的 `core.log`，Linux 应用错误为对应 `profiles/<id>/runtime.log`。删除项目程序不会留下全机断网规则；删除数据前先正常关闭面板。

## 固定运行组件

- Mihomo `v1.19.32`：按官方 GitHub 资源 SHA-256 验证下载。
- Microsoft MXC `1.0.0`：按 npm 官方包公开 SHA-512 integrity 验证下载。
- `install_runtime.py` 只下载和写入项目的 `bin/`，不会执行下载的 Windows 文件或修改系统网络。

组件许可和对应源码参见 `THIRD-PARTY.md`。
