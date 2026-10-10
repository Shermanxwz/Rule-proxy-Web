# RuleProxy Web

Windows / Linux 本机 Web 面板：导入 Mihomo YAML、选择代理节点、添加应用，从面板启动受保护实例。

**当前版本 0.1.0。只保护从面板或本工具的快捷方式启动的实例。已打开的普通实例不会自动接管，请先自行关闭。**

选中应用的代理入口强制使用所选节点。无法经过代理的流量阻断，不自动直连。不修改系统代理、网卡 DNS、全机默认路由，不创建系统启动任务。

## 开始使用

### Windows

要求 Python 3.10+、x64 Windows 11，以及系统实际支持 Microsoft MXC 的 BaseContainer 全拒绝网络隔离能力。Windows 10 和旧版 Windows 11 的严格模式不可用。系统版本符合最低条件也可能缺少所需更新，面板会检查并拒绝不支持的启动。

官方 MXC 的系统支持表列出 Windows 11 24H2 的 `26100.9278`、25H2 的 `26200.9278` 等更新版本；最终以本机请求级能力检查为准：[系统支持表](https://github.com/microsoft/mxc/blob/v1.0.0/docs/backends/process-container/os-version-support.md)。

1. 解压整个运行包。
2. 双击 `Start-Windows.cmd`。无需以管理员身份运行。
3. 在面板导入自己的 YAML，选择节点，启动核心。
4. 在“添加已安装应用”中搜索名称，点击“添加”，再点击“启动隔离实例”。程序路径和启动方式自动填写；找不到的应用可展开“手动添加”。

从 GitHub 下载源码时，先双击 `Setup-Windows.cmd`，下载经过固定校验值验证的本地运行组件和 Python 依赖，再双击启动文件。所有文件只安装在项目目录下。

### Linux

要求 Python 3.10+、Ubuntu 软件包提供的 bubblewrap，以及可用的用户和网络命名空间。第一次使用前，在项目目录执行一次：

```sh
sudo sh scripts/setup-linux-apparmor.sh
```

该脚本把 Ubuntu 的 bubblewrap 复制到两个项目专用的 root 所有路径，并加载 Ubuntu `bwrap-userns-restrict` 策略的本地配置。普通应用进入拒绝 capabilities 的子策略。已识别的 Chromium 系程序使用单独子策略，允许其嵌套 user namespace 沙箱所需的 `CAP_SYS_ADMIN` 和 `CAP_SYS_CHROOT`；外层网络命名空间已先行建立并丢弃 capabilities，应用网络仍只看得到 loopback。原版 `/usr/bin/bwrap` 和全机 user namespace 开关不变。更新 Ubuntu bubblewrap 软件包后请重新运行脚本。要撤销此专用配置，执行 `sudo sh scripts/remove-linux-apparmor.sh`。

运行包已带核心；源码首次准备使用下面的步骤：

```sh
# 在项目目录下；这些步骤不更改网卡配置。
python3 -m pip install --target vendor -r requirements.txt
python3 install_runtime.py --platform linux-amd64
sh start-linux.sh
```

发行版未安装 bubblewrap 时，通过发行版的软件管理器安装它，再运行上面的准备脚本。随后以登录桌面的普通用户重新打开面板。不要用 sudo 启动面板或浏览器。若状态仍显示隔离不可用，请关闭并重新打开面板，让它重新检查 AppArmor 策略。

应用列表会自动读取本机已安装的应用，支持搜索和一键添加。“重新扫描”会立即重新读取清单。添加只保存启动清单；只有从面板或快捷方式启动并显示“隔离中运行”的实例才受保护，现有窗口不会自动接管。

Ubuntu 的 AppArmor 会限制未授权程序使用 user namespace。上面的准备脚本只给 RuleProxy 专用 bwrap 副本加载隔离策略；全机 user namespace 限制保持开启，也不会用 `--no-sandbox` 绕过浏览器沙箱。[Ubuntu 权限限制说明](https://documentation.ubuntu.com/security/security-features/privilege-restriction/apparmor/)

面板默认地址：`http://127.0.0.1:8879`。在面板点击停止，会先关闭本工具启动的应用，再停止本工具的核心。退出面板使用 Ctrl+C；Windows 直接关闭终端的清理行为尚未实测。面板持有的快捷方式实例在面板关闭时同样会停止。

端口可通过启动参数调整：`--port` 是面板端口（默认 `8879`），`--proxy-port` 是本机 Mihomo 混合代理端口（默认 `10809`），`--controller-port` 是本机控制器端口（默认 `19097`）。三个端口必须互不相同并处于 `1025`–`65535`。例如，要让面板的本机代理入口使用 `127.0.0.1:7890`，启动时指定 `--proxy-port 7890`；当前占用的端口不会被面板停止或替换。

默认启动面板时不会自动启动核心。添加 `--start-core` 后，面板会加载已有状态目录中的 YAML 并启动本工具自己的核心；没有已保存配置或启动失败时会关闭面板，不会留下本工具启动的核心进程。

## 快捷方式

在应用行点击“创建快捷方式”，之后不需要打开面板也能启动这个隔离实例。

- Linux：在应用菜单生成 `ruleproxy-<id>.desktop`（目录为 `$XDG_DATA_HOME/applications`，默认 `~/.local/share/applications`）；若存在 `~/Desktop`，同时放一份到桌面。
- Windows：在桌面和“开始菜单 → RuleProxy Web”生成 `.lnk`，图标取自应用程序。Windows 版尚未在目标设备上实测。
- 快捷方式运行 `Run-RuleProxy.py --launch-app <id>`，并写入创建时的面板端口、代理端口、控制器端口和状态目录。更改这些设置或移动项目目录后，请在面板中重新创建快捷方式。
- 面板正在运行：快捷方式请求面板启动核心（若未启动）和应用，随后退出；隔离实例仍由面板持有。
- 面板未运行：快捷方式自行启动核心和应用；应用关闭后停止核心并退出。启动失败时会通过系统通知或对话框说明原因。
- 删除应用时，会一并删除它创建的快捷方式文件。

## 登录状态与文件

每个应用使用面板私有的配置目录（数据目录下的 `profiles/<id>`），不与普通浏览器、root 或其他用户共用：Chrome 系程序同一配置目录只运行一个实例，共用会让新窗口交给另一个实例打开，绕过隔离。第一次启动后在隔离实例里登录一次，之后从面板或快捷方式启动都会保持登录。ChatGPT 这类账号数据存在服务器上的应用，登录后看到的内容与原来一致。

隔离实例只看得到自己的配置目录，看不到家目录里的其他文件。要上传文件，先把它放进这个目录；下载的文件也保存在这个目录里（通常是其中的 `Downloads`）。

## 应用支持范围

| 启动方式 | 行为 |
|---|---|
| Chrome / Edge / Brave | 使用独立浏览器配置、本地 HTTP 代理，禁止 QUIC 和非代理 WebRTC UDP；Linux 使用浏览器 user namespace 与 seccomp 沙箱 |
| Firefox | 使用独立配置、SOCKS5 远端 DNS，关闭预取 |
| 遵循代理环境变量的应用 | 启动时设置 HTTP(S)/ALL_PROXY；忽略代理的连接会被隔离边界阻断 |

这版提供 TCP HTTP / SOCKS 代理通道。UDP、需要额外桌面服务或不兼容隔离的软件可能无法使用；失败不会退回直连。IPv6 目的地可通过代理访问，应用直接建立 IPv6 连接会受隔离限制。无法承诺任意软件都能兼容，尤其是自带后台服务、驱动、外部登录器或通过宿主进程代发网络请求的软件。

Linux 未开放 D-Bus、桌面门户和音频服务，仅按需开放直接的 X11/Wayland 显示连接。保护范围是隔离内的应用及其子进程；不包含隔离外原先运行的服务，也不是用于防御恶意软件利用桌面 IPC 的安全产品。

## YAML 导入

支持当前版本的内联代理节点，例如 VLESS、VMess、Trojan、SS。参考配置在 `examples/ruleproxy.example.yaml`，示例节点需要替换为自己的节点。

导入时重建本机入口：

- TUN 关闭；只监听 `127.0.0.1`。
- 保留支持的规则匹配条件和顺序；`REJECT` / `REJECT-DROP` 继续阻断。
- 所有放行规则的目标统一改为 `RuleProxySelected`，只能选择实际代理节点；未匹配的流量也走该节点。
- `DIRECT`、`dns-out` 等不会进入可选节点；导入规则中的直连例外改为代理。
- 目的地解析使用经所选节点发送的 DoH。代理服务器自身是域名时，仅节点服务器的引导解析使用系统 DNS；不改变系统 DNS。
- 导入的监听器、系统网络设置不生效。第一版不导入 `proxy-providers`、`rule-providers`、脚本、插件或本地证书文件引用；不支持时明确报错。
- 通过中继无法可靠识别原始应用，所以不支持 `PROCESS-*` / `UID` 规则。应用选择由面板的隔离启动完成。

节点名称会显示在面板，服务器、UUID、密码等不会通过状态 API 返回。导入内容只保存在本机。**不要把包含真实节点凭据的 YAML 推到公共仓库。**

## 隔离设计

Linux：每次启动创建独立网络和进程命名空间，没有上联网卡。仅通过专用 Unix socket 将隔离内的回环 TCP 入口连接到宿主 Mihomo。应用无法访问宿主 IP 网络；子进程继承隔离。没有 veth、NAT、宿主防火墙变更或全机 TUN。

Ubuntu 专用 bwrap 使用官方 `bwrap-userns-restrict` 思路。Chromium 系应用在 Linux 启动时禁用与外层 `no_new_privs` 不兼容的 SUID helper 路径，保留浏览器自己的 user namespace 与 seccomp 沙箱；禁止 `--no-sandbox` 参数。浏览器内部沙箱若不能启动，应用启动失败，不会退回无沙箱模式。

Windows：使用固定版本 Microsoft MXC 1.0.0，请求级检查必须返回 `base-container`。采用 Model 3：外部出站、入站以及宿主回环全部拒绝，没有运行时网络代理例外，也不接受其他隔离层级的回退。应用和代理中继运行在同一容器内，仅容器内部回环可用。中继通过有大小与连接数限制的文件通道交换字节，宿主中继只能连接固定的本机 Mihomo 入口。

真实应用启动前，先用隔离内的测试子进程检查内部代理通道、直连与宿主回环阻断；宿主还会检查无法连入容器监听器。检查失败就拒绝启动，不回退。这个通道不提供任意目的地址、宿主命令执行或系统网络设置接口；吞吐可能低于普通代理。

策略只作用于新容器及子进程。生命周期由 MXC / 系统管理；本工具不安装旧版的全机 WFP 断网守卫。MXC 自带的运行时恢复机制属于该组件的生命周期管理。

正常停止会关闭已核对身份的应用进程，让 MXC 自行完成清理；不会强杀 MXC 守卫进程。若无法确认或完成关闭，保留守卫和核心并显示错误，请自行关闭对应隔离窗口，再重试停止。

参考：[MXC 网络策略](https://github.com/microsoft/mxc/blob/v1.0.0/docs/backends/process-container/networking.md)、[Mihomo 监听器](https://wiki.metacubex.one/en/config/inbound/listeners/)、[Mihomo 规则](https://wiki.metacubex.one/en/config/rules/)、[Mihomo DNS](https://wiki.metacubex.one/en/config/dns/)。

## 检查与当前验证范围

```sh
python3 -B -m unittest discover -s tests -v
```

已在 Linux 实际检查代理通道、直连 IPv4/IPv6、DNS/UDP、子进程继承隔离，以及主机接口/路由未变；并用固定 Mihomo 校验参考 YAML。Web 导入、启动核心、应用管理、停止流程经过本机检查。

登录保持与快捷方式：在 Linux 上用真实 Chromium 检查了隔离实例经面板关闭后，登录 Cookie 仍保存在私有配置中、再次启动时继续携带，以及快捷方式的 `Exec` 在面板运行时委托启动、面板关闭后独立启动两种路径。Windows 快捷方式只完成了参数和脚本的静态测试，尚未在 Windows 设备上创建或运行。

最新 Windows 文件中继与启动门控、规则目标重写只完成静态审查，未运行更新后的测试套件。**尚未在目标 Windows 设备实测应用兼容性、实际网络阻断及异常退出清理，因此不能称为已实测零泄漏**。启动流程内置必要的运行时检查，但仍不能替代目标设备上的独立抓包与故障检查。首次使用请先选择一个浏览器，确认正常停止及其他普通应用的联网。

本机数据独立于旧版目录：Windows `%LOCALAPPDATA%\RuleProxyWebSafe`；Linux `$XDG_DATA_HOME/ruleproxy-web-safe`（默认 `~/.local/share/ruleproxy-web-safe`）。核心日志为该目录的 `core.log`，Linux 应用错误为对应 `profiles/<id>/runtime.log`。删除项目程序不会留下全机断网规则；删除数据前先正常关闭面板。

## 固定运行组件

- Mihomo `v1.19.32`：按官方 GitHub 资源 SHA-256 验证下载。
- Microsoft MXC `1.0.0`：按 npm 官方包公开 SHA-512 integrity 验证下载。
- `install_runtime.py` 只下载和写入项目的 `bin/`，不会执行下载的 Windows 文件或修改系统网络。

组件许可和对应源码参见 `THIRD-PARTY.md`。
