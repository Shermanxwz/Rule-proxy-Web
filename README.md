# RuleProxy Web

本机 Web 面板：导入自己的 Mihomo YAML、选择节点、自定义应用。Windows 通过 ProxiFyre 按程序路径透明转发；Linux 继续使用网络命名空间隔离。

**版本 0.3.0。Windows 使用 ProxiFyre 2.6.4 + Mihomo 1.19.32，不使用 TUN。安装前请核对[产品验收记录](https://github.com/Shermanxwz/Rule-proxy-Web/tree/main/verification/windows-2026-10-16/proxifyre-product)中与离线 ZIP 的 SHA-256 一致的报告；只有报告实际通过的项目属于已验证范围。**

Windows 的目标是让自定义应用走所选代理节点。它不能提供 Linux 同等的 DNS、子进程和故障隔离；具体边界见下文。Linux 功能保持原有实现。

## Windows 开始使用

要求 Windows 11 x64。此版本没有完成 ARM64、x86 或 Windows Server 产品认证；系统需保留正常的驱动签名验证与 .NET Framework 4.7.2 以上组件。

1. 取得本次个人离线包 `RuleProxy-Web-0.3.0-windows-x64-personal.zip`，核对随包提供的 `SHA256SUMS.txt`，解压。
2. 从日常登录账户双击 `Setup-Windows.cmd`，允许一次 UAC 安装。包内已包含固定版本的 Python、PyYAML、Mihomo、ProxiFyre MSI、NDIS 驱动 MSI 和 VC 运行库，完整离线包使用原版官方 Setup 与按其 Burn manifest 精确命名的本地 VC/NDIS 载荷；无需临时下载的实际断网验收仍待完成。
3. 如果安装返回 `3010`，先重启，再从同一离线包运行 `Setup-Windows.cmd` 续装。
4. 安装成功后，以同一用户正常打开 `Start-Windows.cmd`；不要选择“以管理员身份运行”。面板默认地址为 `http://127.0.0.1:8879`。
5. 在 Web 面板导入自己的 YAML，选择真实代理节点，添加应用并启用其代理开关，再启动核心和应用。

安装包没有预装任何用户 YAML、订阅或节点凭证。[示例 YAML](https://github.com/Shermanxwz/Rule-proxy-Web/blob/main/examples/ruleproxy.example.yaml) 仅供源码阅读，需要换成自己的节点后导入。

安装会拒绝接管另一个来源的既有 ProxiFyre。已有共享 NDIS/VC 组件只有符合兼容与签名检查时才复用。程序、服务入口和固定依赖放在受保护的 `%ProgramFiles%\RuleProxy-Web`；官方引擎位于 `%ProgramFiles%\ProxiFyre`。普通用户只能读取代码，无法通过面板修改服务命令或执行任意管理员命令。

| 组件 | 职责与权限 |
|---|---|
| 普通用户面板与 Mihomo | 读取用户 YAML、管理节点、启动用户应用；使用当前桌面用户权限 |
| `RuleProxyControl` | 固定入口的 SYSTEM 服务；验证安装身份、请求结构、路径和核心进程，再写入规则、控制官方引擎 |
| `ProxiFyreService` | 官方 LocalSystem 服务，手动启动；把匹配应用的受支持流量交给本机 Mihomo SOCKS 入口 |
| 用户状态 | `%LOCALAPPDATA%\RuleProxyWebSafe`：导入配置、设置、日志和浏览器私有配置 |
| 安装状态与日志 | `%ProgramData%\RuleProxy-Web`：归属、续装状态和安装日志 |

控制服务不负责启动应用窗口。应用由普通用户面板创建，并放入本工具持有的 Windows Job 中；不会注入代理环境变量或浏览器代理参数。浏览器仍使用各应用独立的私有配置，以保留登录状态。

从源码使用时也可双击 `Setup-Windows.cmd`。它先以普通用户下载并校验固定资产、生成本地离线载荷，然后请求 UAC 安装；不依赖全局 Python 或 pip。下载缓存位于源码下的 `.windows-cache`。这一步需要联网，完成后的离线包才可离线部署。

## Windows 应用规则与边界

核心运行时，应用代理开关会同步所有已启用应用的主 exe 和“相关程序路径”。每个应用最多填写 16 个相关路径，所有启用项去重后合计最多 128 个路径；不接受通配符、系统服务程序或代理组件本身。添加应用时可搜索本机清单，也可手动填写本地 exe 的绝对路径。

**规则按程序路径作用，不能只限定面板启动的某一个 PID。** 同路径的其他实例也会受影响；已有连接可能要重启应用后才按新规则建立。上游对含目录分隔符的条目使用完整路径文本的“包含匹配”，因此少数包含同样文本的相似路径也可能命中。[官方匹配规则](https://github.com/wiresock/proxifyre/blob/v2.6.4/docs/configuration.md#application-matching-and-rule-order)

同 exe 的新实例使用同一路径规则。不同 exe 的联网子进程、更新器或启动器需要手动加入“相关程序路径”；Job 管理进程生命周期不代表路由规则会自动继承。通过既有系统服务代发的流量也不能可靠归属于所选应用。

| 范围 | 当前行为与限制 |
|---|---|
| TCP / 一般 UDP | 配置为经本机 Mihomo SOCKS 转发；UDP 还依赖所选节点及其协议支持。实际通过范围以对应 ZIP 的产品验收报告为准 |
| UDP 53 | ProxiFyre 2.6.4 源码直接放行该端口；不提供 DNS 防泄漏保证 |
| 系统 DNS | 系统解析服务代发的查询无法可靠按原始应用归因，不由本工具全面接管 |
| IPv6 | 配置启用，但尚无本项目完整原生实证；上游明确允许 IPv6 分片直通，不能保证没有直连 |
| 引擎退出或驱动故障 | 可能恢复直连；不能保证故障期间持续阻断 |
| 未选应用 | 不配置全机默认代理、TUN 或全机断网规则；路径包含匹配的额外命中仍需留意 |

上游的 [IPv6 与分片说明](https://github.com/wiresock/proxifyre/blob/v2.6.4/docs/configuration.md#protocols-and-address-families) 和 [UDP 53 处理源码](https://github.com/wiresock/proxifyre/blob/v2.6.4/netlib/src/proxy/socks_local_router.h) 是这些限制的依据。本项目的监视器会尝试处理核心或后端退出，Job 会管理自身创建的进程；两者都不等于持久的网络拒绝边界。

正常停止顺序是：先关闭本工具启动的应用，再停止 ProxiFyre 引擎，最后停止自己的 Mihomo。其他已存在实例不会被本工具强杀，但路径规则撤销后它们可能恢复直连。关闭浏览器页面不会停止面板；“退出面板”会执行应用和核心的停止流程。

## Linux 开始使用

要求 x86-64、Python 3.10+、bubblewrap，以及可用的用户和网络命名空间。在 Ubuntu 22.04 / 24.04 上：

```sh
sudo apt install -y git
git clone https://github.com/Shermanxwz/Rule-proxy-Web.git
cd Rule-proxy-Web
sh start-linux.sh
```

请用登录桌面的普通用户运行。面板拒绝以 root 运行；不会通过 `--no-sandbox` 启动浏览器。

首次启动会执行 `setup-linux.sh`，仅在需要时请求 sudo：安装缺少的 bubblewrap/PyYAML，准备 Ubuntu 专用 AppArmor 策略，下载固定 Mihomo，并检查隔离是否可用。pyenv、conda 等非 apt Python 会把 PyYAML 装入项目 `vendor`；没有 apt 的发行版需先用本机包管理器安装依赖。检查失败会说明原因并停止。

之后运行 `sh start-linux.sh` 即可。更新源码后，下次启动会补齐所需组件；也可单独执行 `sh setup-linux.sh`。Ubuntu 升级 bubblewrap 后应重新执行准备脚本，刷新项目专用副本。

每个 Linux 应用及子进程进入独立网络和进程命名空间，网络只有 loopback，通过专用 Unix socket 把 TCP 代理通道交给宿主 Mihomo。没有 veth、NAT、全机 TUN 或宿主防火墙规则。忽略代理设置的直连流量无法使用上联网卡；本版本的 Linux 应用通道主要提供 TCP HTTP/SOCKS，不承诺 UDP 应用兼容。

Linux Chromium 保留自己的 user namespace 与 seccomp 沙箱；仅禁用与外层运行方式不兼容的旧 SUID helper 路径。沙箱无法启动时会失败，不回退到无沙箱模式。Ubuntu 上使用项目专用、root 所有的 bubblewrap 副本及 AppArmor 策略，原 `/usr/bin/bwrap` 和全机 user namespace 限制保持原样。撤销专用配置：

```sh
sudo sh scripts/remove-linux-apparmor.sh
```

策略来源与背景见 [Ubuntu AppArmor 权限限制](https://documentation.ubuntu.com/security/security-features/privilege-restriction/apparmor/)。不开放 D-Bus、桌面门户或音频服务，只按需开放直接的 X11/Wayland 显示连接；隔离外既有服务不在保护范围内。

隔离应用可读写当前用户的“下载”文件夹，默认 `~/Downloads`，也读取 `user-dirs.dirs` 设置。上传文件请先放到该目录。家目录的其他文件不向隔离应用开放；下载目录若与家目录、面板数据或所有权边界冲突，则拒绝共享。面板会显示实际开放目录。

## YAML、节点与本地数据

Web 面板支持内联的真实代理节点，包括当前编译器支持的 VLESS、VMess、Trojan、SS 等。导入会重新编译本机配置：

- 关闭 TUN，只监听 `127.0.0.1`；导入的系统网络设置与额外监听器不生效。
- 保留支持的规则匹配条件和顺序；`REJECT` / `REJECT-DROP` 继续拒绝。
- 所有放行动作，包括原 `DIRECT`，统一改为所选真实节点；未匹配的流量也走该节点。不能选择 `DIRECT`、`dns-out` 等特殊出口。
- `proxy-providers`、`rule-providers`、脚本、插件、本地证书文件引用，以及进程/UID 分流规则不支持时明确报错，不静默换成另一种行为。
- Mihomo 收到域名目标时，目标解析使用经所选节点发送的 DoH；节点服务器本身的域名引导解析使用系统 DNS。这不覆盖 Windows 应用先交给系统解析器的查询，也不会修改网卡 DNS。

导入后会显示改写与忽略设置的说明。源 YAML、节点凭证只保存在本机用户状态目录；状态 API 不返回服务器、UUID 或密码。请勿将真实节点 YAML 提交到仓库或 CI 产物。

每个浏览器应用使用数据目录下的 `profiles/<id>` 私有配置。首次在此配置中登录后，再从面板或快捷方式启动会保留登录；与原浏览器窗口的配置分开。Windows 普通应用仍按其自身方式访问用户文件，不提供 Linux 的文件系统隔离。

配置损坏、过大或不再受支持时，面板仍会打开并提示重新导入。暂时不存在的 exe 会保留列表与登录数据，在启动时说明原因。无效设置首次保存前会另存为 `settings.recovery-<标识>.json`。最多保存 128 个应用；Windows 还需满足启用路径的总数上限。

## 快捷方式与后台运行

在应用行创建快捷方式后，可直接请求面板启动核心和应用。Windows 使用受保护安装中的私有 Python，并在桌面及“开始菜单 → RuleProxy Web”生成 `.lnk`；Linux 写入应用菜单，若存在桌面目录也会放置一份。删除应用会清理其快捷方式。

面板已经运行时复用同一实例；未运行时，应用快捷方式可启动后台面板。快捷方式写入创建时的端口和数据目录，更改后需要重新创建。后台面板在所有应用与页面关闭后约 10 秒可自动退出。

“登录后在后台运行”只登记当前用户的登录启动项，不需要 UAC：Windows 使用用户 Run 项，Linux 使用 `~/.config/autostart/ruleproxy-web.desktop`。登录后不自动打开页面、不自动启动核心。Windows 后台输出写入 `%LOCALAPPDATA%\RuleProxyWebSafe\panel.log`。

端口参数为 `--port`（默认 `8879`）、`--proxy-port`（`10809`）、`--controller-port`（`19097`）；必须互不相同且位于 `1025`–`65535`。默认不自动启动核心，显式 `--start-core` 需要已有可用 YAML。

## Windows 更新与卸载

更新或修复时，从新的完整个人离线包运行 `Setup-Windows.cmd`。安装会核对归属和固定组件，关闭本安装中该用户的旧面板/核心，替换受保护程序，保留用户数据。中断或 `3010` 后按提示续装。同一组固定引擎/驱动依赖下，程序目录替换失败会尝试恢复旧程序；不承诺未来版本的 ProxiFyre MSI 或共享驱动可以降级回滚。

完整卸载入口是已安装的脚本。在原安装用户的普通 PowerShell 中执行，它会按需请求 UAC：

```powershell
powershell.exe -NoProfile -ExecutionPolicy Bypass -File "$env:ProgramFiles\RuleProxy-Web\scripts\windows-uninstall.ps1"
```

卸载只处理归属已验证的控制服务、官方 ProxiFyre 安装、程序文件及指向本安装的用户快捷方式/启动项。保留共享 NDIS 驱动、VC 运行库及用户数据。先停止本安装的应用与面板有助于正常关闭；若共享组件要求重启，会返回 `3010`。不要直接删除 Program Files 目录来代替卸载。

## 构建与验证状态

```sh
python3 -B -m unittest discover -s tests -v
python3 -B .github/build_windows_package.py /tmp/ruleproxy-personal-package --asset-cache /tmp/ruleproxy-pinned-assets
```

构建器只收集程序文件，拒绝在非空暂存目录中混入旧文件；固定资产下载后校验 SHA-256，生成含逐文件摘要的 `package-manifest.json`。包中包含 ProxiFyre AGPL 许可及依赖说明。完整依赖与来源见 [THIRD-PARTY.md](THIRD-PARTY.md)，资产固定在 [windows_proxy_pins.py](ruleproxy/windows_proxy_pins.py)。Linux 保留自己的安装和测试流程。

0.3.0 的 Python 代码、打包与固定资产检查已可本地执行。新的产品验收入口为 `.github/windows_proxifyre_product_acceptance.py`，必须针对最终 ZIP 检查普通用户权限、安装/重复安装/卸载、服务身份、透明流量及异常清理；Windows 11 本机、真实节点、浏览器登录和下载仍需对应证据。

之前的 Windows Server 候选比较（包括运行 `38770720406`）仅证明其报告实际完成的候选路径，不代表这个最终产品包已通过。旧 MXC/PSEC 脚本与报告保留供历史复现，不是当前 Windows 默认入口；旧产品说明见 [0.2.2 历史文档](https://github.com/Shermanxwz/Rule-proxy-Web/blob/main/verification/windows-2026-10-15/mxc-0.2.2-readme.md)。

本次离线包用于个人自用。Windows Packet Filter 官方为个人/学术非商业使用提供永久免费许可，但这不等于获得商业分发权；无需为本次个人安装新增付费或许可确认步骤。[官方许可](https://www.ntkernel.com/windows-packet-filter/licensing/)

公开源码与个人离线载荷分别管理。当前不会自动把捆绑 NDIS/VC 的个人二进制包发布到公共 Release；公开分发需要另行满足各组件的许可和源码提供条件。
