# RuleProxy Web

本机 Web 面板：导入自己的 Mihomo YAML、选择节点、自定义应用。按应用模式下，Windows 使用 ProxiFyre 按程序路径转发，Linux 使用网络命名空间隔离。全局模式使用系统代理，不使用 TUN。

**版本 0.3.0。Windows 按应用模式使用 ProxiFyre 2.6.4 + Mihomo 1.19.32，关闭 TUN。安装前请核对[产品验收记录](https://github.com/Shermanxwz/Rule-proxy-Web/tree/main/verification/windows-2026-10-16/proxifyre-product)中与离线 ZIP 的 SHA-256 一致的报告；只有报告实际通过的项目属于已验证范围。**

Windows 的目标是让自定义应用走所选代理节点。它不能提供 Linux 同等的 DNS、子进程和故障隔离；具体边界见下文。Linux 按应用功能保持原有实现。

## 选择接管范围

面板提供“按应用”和“全局”两种模式，默认按应用；停止核心和本工具启动的应用后才能切换。配置导入、节点选择和应用清单按原方式保留。全局模式下遵循系统代理的程序都会经过规则，应用开关只决定启动清单。

全局模式只把当前用户的系统代理指向本机核心（Windows：WinINet 系统代理；Linux：GNOME 兼容桌面的 gsettings），不安装 TUN，不改防火墙、路由和 DNS，不需要额外权限组件。开启前保存原系统代理，停止或核心退出时恢复；独立的同用户恢复进程会在面板意外退出后尝试还原，恢复失败时保留记录供重试。系统代理指向不可用端口期间，遵循系统代理的程序可能暂时无法联网。不读取系统代理的程序会直连。

Linux 按应用模式继续使用网络命名空间隔离。Windows 的“AppContainer（实验）”已在 Windows Server 2025 验证受控 CLI，以及普通用户 Web 面板至 SYSTEM 服务的子孙进程链路；这不代表任意用户软件已通过兼容验收。当前安装包的实际通过范围仍须核对对应 SHA-256 的验收记录。[浏览器对照](https://github.com/Shermanxwz/Rule-proxy-Web/blob/main/verification/windows-2026-10-19/appcontainer-browser-experiment.json)中 Edge、Chrome、Firefox 在容器外正常、容器内均未完成渲染，该实验选项当前不支持这些浏览器。商店应用与共用原应用资料模式也不支持。

Windows 卸载前请先用原安装账户停止全局代理；如果改用其他管理员账户且原连接标志尚未恢复，卸载会保留恢复组件并提示先完成恢复。恢复检测到设置冲突时也会保留记录，不覆盖无法确认归属的设置。

从 0.3.0-rc.14 及更早版本升级：面板会检查旧版全局 TUN 遗留的自有阻断规则和 DNS 策略。恢复未能确认时应先完成恢复，再启动新的代理；卸载也必须先恢复网络状态，再删除恢复组件。

## Windows 开始使用

目标系统为 Windows 11 x64；ARM64、x86 未验证，Windows Server 仅作为自动化对照环境。系统需保留正常的驱动签名验证与 .NET Framework 4.7.2 以上组件。

1. 在 [GitHub Releases](https://github.com/Shermanxwz/Rule-proxy-Web/releases) 下载 `RuleProxy-Web-0.3.0-windows-x64-online-setup.zip`，核对同一发布页的 `SHA256SUMS.txt`，完整解压到可写目录。
2. 从日常登录账户双击 `Setup-Windows.cmd`。首次联网下载并校验固定版本的 Python、PyYAML、Mihomo、ProxiFyre、NDIS 驱动和 VC 运行库，无需预装 Python；准备完成后按需允许 UAC 安装。支持以该账户的管理员权限启动安装。固定许可证原文已随包附带，无需访问 GitHub 原始文件站点。
3. 下载失败时，保留 `.windows-cache`，从同一目录再次运行 `Setup-Windows.cmd`，可复用已经校验的依赖。临时连接中断会有界重试，校验不通过会停止。如果安装返回 `3010`，先重启，再运行同一安装入口续装。
4. 安装成功后会在后台启动，安装窗口保留结果供查看。需要操作时，以同一安装账户双击桌面的 `RuleProxy Web` 快捷方式，或 `%ProgramFiles%\RuleProxy-Web\Start-Windows.lnk`，即可打开 Web 面板，不弹 CMD、PowerShell 或 Mihomo 控制台。也可手动访问 `http://127.0.0.1:8879`。
5. 在 Web 面板导入自己的 YAML，选择真实代理节点，添加应用并启用其代理开关，再启动核心和应用。

安装包没有预装任何用户 YAML、订阅或节点凭证。[示例 YAML](https://github.com/Shermanxwz/Rule-proxy-Web/blob/main/examples/ruleproxy.example.yaml) 仅供源码阅读，需要换成自己的节点后导入。

登录后自启动可在 Web 面板中开启，静默运行，不自动打开浏览器；安装结束后的后台启动也不会打开浏览器。后台启动错误写入 `%LOCALAPPDATA%\RuleProxyWebSafe\panel.log`，核心日志为同目录的 `core.log`。`Start-Windows.cmd` 保留为兼容入口；直接双击 CMD 本身可能短暂显示命令行窗口，日常请使用上述快捷方式。首次安装仍会显示准备进度并请求 UAC 授权。

面板支持普通权限和当前安装账户的管理员权限，也支持 UAC 已关闭的环境，无需为启动 RuleProxy 改动 UAC 设置。面板、Mihomo 和所选应用沿用当前进程的权限；管理员运行时面板会显示权限继承提示。高权限面板根据真实本机 TCP 连接、进程令牌和 Windows 账户 SID 校验每个请求，允许同账户访问，拒绝其他账户；这是账户级校验，不区分同账户下的不同程序。

安装会拒绝接管另一个来源的既有 ProxiFyre。已有共享 NDIS/VC 组件只有符合兼容与签名检查时才复用。程序、服务入口和固定依赖放在受保护的 `%ProgramFiles%\RuleProxy-Web`；官方引擎位于 `%ProgramFiles%\ProxiFyre`。普通用户只能读取代码；控制服务协议只处理固定引擎和应用路径规则，不提供任意管理员命令执行接口。

| 组件 | 职责与权限 |
|---|---|
| 当前账户面板与按应用 Mihomo | 读取用户 YAML、管理节点、启动用户应用；沿用当前账户的实际启动权限 |
| 全局 Mihomo | 与按应用模式相同的本机用户核心，只监听 127.0.0.1；系统代理指向它，停止后恢复 |
| `RuleProxyControl` | 固定入口的 SYSTEM 服务；验证安装身份、请求结构、路径和核心进程，再写入规则、控制官方引擎 |
| `ProxiFyreService` | 官方 LocalSystem 服务，手动启动；把匹配应用的受支持流量交给本机 Mihomo SOCKS 入口 |
| 用户状态 | `%LOCALAPPDATA%\RuleProxyWebSafe`：导入配置、设置、日志和浏览器私有配置 |
| 安装状态与日志 | `%ProgramData%\RuleProxy-Web`：归属、续装状态和安装日志 |

控制服务不负责启动应用窗口。应用由面板在当前权限下创建，并放入本工具持有的 Windows Job 中。按应用启动时同时设置指向本机 HTTP 代理的环境变量，供支持代理的 CLI 及其子进程继承；Chromium 另外使用显式代理、关闭 QUIC 及限制非代理 WebRTC UDP。忽略这些设置的应用仍依赖路径转发。浏览器默认使用各应用独立的私有配置，也可选择下文的原应用数据模式。

从源码使用时也可双击 `Setup-Windows.cmd`，采用相同的联网准备流程，下载缓存位于源码下的 `.windows-cache`。依赖准备在发起安装的账户下完成，失败时尚未执行系统安装。已准备的个人离线包 `RuleProxy-Web-0.3.0-windows-x64-personal.zip` 含完整固定依赖，直接进入安装；完整断网安装验收仍待完成，公开发布附件为联网安装包。

## Windows 应用规则与边界

核心运行时，应用代理开关会同步所有已启用应用的主 exe 和“相关程序路径”。每个应用最多填写 16 个相关路径，所有启用项去重后合计最多 128 个路径；不接受通配符、系统服务程序或代理组件本身。添加应用时可搜索本机清单，也可手动填写本地 exe 的绝对路径。

Windows 应用清单读取当前账户的 Appx/MSIX 注册信息，识别具有独立 exe 入口的商店桌面应用。新条目保存软件包家族与应用身份，在启动或同步规则前重新读取本机注册路径，并将当前软件包内经过验证的 exe 一并加入规则，覆盖异名辅助程序。包内其他入口、更新器也可能受影响；这是整个软件包的范围。缺少注册信息、出现歧义、遇到重解析目录或超出扫描上限时拒绝启动，不猜测路径或扫描整个 WindowsApps。UWP、宿主应用和需要系统激活的入口不在此范围。历史条目只在旧路径仍能对应唯一当前注册入口时自动迁移，否则请重新添加当前清单条目。

**规则按程序路径作用，不能只限定面板启动的某一个 PID。** 同路径的其他实例也会受影响；已有连接可能要重启应用后才按新规则建立。上游对含目录分隔符的条目使用完整路径文本的“包含匹配”，因此少数包含同样文本的相似路径也可能命中。[官方匹配规则](https://github.com/wiresock/proxifyre/blob/v2.6.4/docs/configuration.md#application-matching-and-rule-order)

同 exe 的新实例使用同一路径规则。已识别商店软件包内的辅助 exe 自动纳入；包外或普通安装程序的异名辅助 exe 仍需加入“相关程序路径”。Job 管理进程生命周期不代表路由规则会自动继承。通过既有系统服务代发的流量也不能可靠归属于所选应用。

| 范围 | 当前行为与限制 |
|---|---|
| TCP / 一般 UDP | 配置为经本机 Mihomo SOCKS 转发；UDP 还依赖所选节点及其协议支持。实际通过范围以对应 ZIP 的产品验收报告为准 |
| UDP 53 | ProxiFyre 2.6.4 源码直接放行该端口；不提供 DNS 防泄漏保证 |
| 系统 DNS | 系统解析服务代发的查询无法可靠按原始应用归因，不由本工具全面接管 |
| IPv6 | 配置启用，但尚无本项目完整原生实证；上游明确允许 IPv6 分片直通，不能保证没有直连 |
| 引擎退出或驱动故障 | 可能恢复直连；不能保证故障期间持续阻断 |
| 未选应用 | 不配置全机默认代理、TUN 或全机断网规则；路径包含匹配的额外命中仍需留意 |

另一个[专用低权限账户原生实验](https://github.com/Shermanxwz/Rule-proxy-Web/actions/runs/39155586929)中，按账户 SID 设置 WFP 规则后，直接 TCP/UDP socket 被阻断，但系统解析器仍成功解析全新的 DNS 名。该路线已停止，不作为产品隔离方案。Linux 按应用模式继续使用下文的独立网络命名空间。

当前未完成 ChatGPT/Claude 登录流程、真实互联网出口或平台风控结果的验收，不能据此保证登录成功或账户使用结果。

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

策略来源与背景见 [Ubuntu AppArmor 权限限制](https://documentation.ubuntu.com/security/security-features/privilege-restriction/apparmor/)。默认不开放 D-Bus、桌面门户或音频服务，只按需开放直接的 X11/Wayland 显示连接；选择原应用数据时仅为 Chromium 提供受限的桌面密钥服务连接，不开放完整会话总线。隔离外既有服务不在保护范围内。

隔离应用可读写当前用户的“下载”文件夹，默认 `~/Downloads`，也读取 `user-dirs.dirs` 设置。上传文件请先放到该目录。家目录的其他文件不向隔离应用开放；下载目录若与家目录、面板数据或所有权边界冲突，则拒绝共享。面板会显示实际开放目录。

## YAML、节点与本地数据

Web 面板支持内联的真实代理节点，包括当前编译器支持的 VLESS、VMess、Trojan、SS 等。导入会重新编译本机配置：

- 关闭 TUN，只监听 `127.0.0.1`；导入的系统网络设置与额外监听器不生效。
- 保留支持的规则匹配条件和顺序；`REJECT` / `REJECT-DROP` 继续拒绝。
- 所有放行动作，包括原 `DIRECT`，统一改为所选真实节点；未匹配的流量也走该节点。不能选择 `DIRECT`、`dns-out` 等特殊出口。
- `proxy-providers`、`rule-providers`、脚本、插件、本地证书文件引用，以及进程/UID 分流规则不支持时明确报错，不静默换成另一种行为。
- Mihomo 收到域名目标时，目标解析使用经所选节点发送的 DoH；节点服务器本身的域名引导解析使用系统 DNS。这不覆盖 Windows 应用先交给系统解析器的查询，也不会修改网卡 DNS。

导入后会显示改写与忽略设置的说明。源 YAML、节点凭证只保存在本机用户状态目录；状态 API 不返回服务器、UUID 或密码。请勿将真实节点 YAML 提交到仓库或 CI 产物。

浏览器默认使用数据目录下的 `profiles/<id>` 独立配置，之后会保留该配置中的登录状态。Windows 和 Linux 的浏览器应用行都可在“创建快捷方式”旁开启 **使用原应用数据**：直接共用原资料，书签、历史和设置的修改会同步，不复制一份新资料。选项按应用保存，已有应用快捷方式也会使用当前选择；切换前需关闭此工具启动的实例。

Windows 开启后由应用选择原生资料目录，已有窗口可能被复用；面板不会接管或关闭这些原有进程。普通 Windows 应用本来就沿用自身数据，不额外显示这个浏览器选项。

Linux 共用时，请先完全关闭原应用。支持自动识别的 Chrome、Chromium、Edge、Brave、Firefox 及部分常见 Electron 应用；找不到唯一、已初始化且未被占用的资料目录时会明确提示，不猜测其他目录。只额外开放该应用的原资料目录，网络、进程和家目录隔离继续生效。Chromium 已有登录资料需要原桌面的密钥服务；通过受限连接访问密钥服务，缺少服务时停止启动，不切换密码存储。Firefox 的代理设置通过隔离环境内的临时策略生效，不替换原配置文件。特殊安装、多默认配置或未识别的应用可能仍需使用独立资料。

配置损坏、过大或不再受支持时，面板仍会打开并提示重新导入。暂时不存在的 exe 会保留列表与登录数据，在启动时说明原因。无效设置首次保存前会另存为 `settings.recovery-<标识>.json`。最多保存 128 个应用；Windows 还需满足启用路径的总数上限。

## 快捷方式与后台运行

在应用行创建快捷方式后，可直接请求面板启动核心和应用。Windows 使用受保护安装中的私有 Python，并在桌面及“开始菜单 → RuleProxy Web”生成 `.lnk`；Linux 写入应用菜单，若存在桌面目录也会放置一份。删除应用会清理其快捷方式。

面板已经运行时复用同一实例；未运行时，应用快捷方式可启动后台面板。快捷方式写入创建时的端口和数据目录，更改后需要重新创建。后台面板在所有应用与页面关闭后约 10 秒可自动退出。

“登录后在后台运行”只登记当前用户的登录启动项，不需要 UAC：Windows 使用用户 Run 项，Linux 使用 `~/.config/autostart/ruleproxy-web.desktop`。登录后不自动打开页面、不自动启动核心。Windows 后台输出写入 `%LOCALAPPDATA%\RuleProxyWebSafe\panel.log`。

端口参数为 `--port`（默认 `8879`）、`--proxy-port`（`10809`）、`--controller-port`（`19097`）；必须互不相同且位于 `1025`–`65535`。默认不自动启动核心，显式 `--start-core` 需要已有可用 YAML。

## Windows 更新与卸载

更新或修复时，从新的完整联网安装包或个人离线包运行 `Setup-Windows.cmd`。安装会核对归属和固定组件，关闭本安装中该用户的旧面板/核心，替换受保护程序，保留用户数据。若已完成的旧部署、文件摘要、服务注册、安装器固定版本、VC 组件和已签名驱动全部通过检查，则复用这些组件，跳过官方组件与网络驱动的修复；否则进入原有安装或修复流程。安装日志会说明采用哪条路径。中断或 `3010` 后按提示续装。同一组固定引擎/驱动依赖下，程序目录替换失败会尝试恢复旧程序；不承诺未来版本的 ProxiFyre MSI 或共享驱动可以降级回滚。

安装会检查后台面板是否实际响应。若程序已装好但面板未能启动，安装窗口会保留失败原因并指向当前用户的 `panel.log`；详细安装会话日志位于 `%ProgramData%\RuleProxy-Web\setup-logs`。

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

常规 CI 检查 Linux 隔离、面板启动和跨平台单元测试。产品验收入口 `.github/windows_proxifyre_product_acceptance.py` 针对实际 ZIP 检查安装、重复安装、卸载后重装、普通用户权限、服务身份、Web 导入、相关程序路径、节点切换、生产启动入口和异常清理。Windows Server 对照与 Windows 11 原生验收分别记录；可见窗口、真实互联网出口、浏览器登录和下载也分别标识。请以[当前验收状态](https://github.com/Shermanxwz/Rule-proxy-Web/blob/main/verification/windows-2026-10-16/proxifyre-product/current-status.json)中与 ZIP SHA-256 相同的证据为准，脚本存在不代表相应项目已经通过。

之前的 Windows Server 候选比较（包括运行 `38770720406`）仅证明其报告实际完成的候选路径，不代表这个最终产品包已通过。旧 MXC/PSEC 脚本与报告保留供历史复现，不是当前 Windows 默认入口；旧产品说明见 [0.2.2 历史文档](https://github.com/Shermanxwz/Rule-proxy-Web/blob/main/verification/windows-2026-10-15/mxc-0.2.2-readme.md)。

本次离线包用于个人自用。Windows Packet Filter 官方为个人/学术非商业使用提供永久免费许可，但这不等于获得商业分发权；无需为本次个人安装新增付费或许可确认步骤。[官方许可](https://www.ntkernel.com/windows-packet-filter/licensing/)

公开源码与个人离线载荷分别管理。当前不会自动把捆绑 NDIS/VC 的个人二进制包发布到公共 Release；公开分发需要另行满足各组件的许可和源码提供条件。
