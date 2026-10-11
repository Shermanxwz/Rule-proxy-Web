# Windows 0.3.0-rc1 验证与归档记录

当前为修复候选版。底层通信实测通过；Windows 浏览器兼容未解决，不能作为产品封存版本。

## 固定实现

- 应用运行在原生 BaseContainer；请求不能满足时拒绝启动，不接受 AppContainer / DACL 回退。
- 唯一代理为面板管理的 `127.0.0.1:<混合端口>`；内核代理策略限制出站，应用和子进程使用相同端点。
- MXC 源码：`microsoft/mxc@c6f301d53a1430c4c921a05c57af838f7392348f`。
- 构建：Rust 1.93、上游 Cargo.lock、x86_64-pc-windows-msvc、静态 CRT、上游保护选项，不启用其他后端。
- 运行组件归档 SHA-256：`84bcb10b1f7ffd62f8fc8356e94e4c0a42684ce68515b68dfdcce4bb6c0757ef`。
- `wxc-exec.exe` SHA-256：`e7527dfda680608442ecbd06222bf6bccd88e9205d80436d547afb2ca074fab7`。
- `winhttp-proxy-shim.exe` SHA-256：`a90c902de8a37782947a9034eca8b4f7b03f154a0381fb57a8f3dc70037340c1`。
- 原始构建：[38134137607](https://github.com/Shermanxwz/Rule-proxy-Web/actions/runs/38134137607)。发布后的归档应保持这些字节，不以一次新编译替换。

这是本项目构建并验证的微软源码组件，包含官方 npm 1.0.0 尚未提供的 PSEC 1.0 回环代理兼容修复，不是微软新发行的正式 SDK 版本。

## 验收范围

| 环境或行为 | 当前结论 |
|---|---|
| Windows 11 25H2 ARM64，26200.9457，Python ARM64 | 真实应用代理数据与阻断通过 |
| 同一 Windows 11，x64 Python / x64 MXC 模拟执行 | 真实应用代理数据与阻断通过 |
| Windows Server 2025 x64，26100.33438 | 缺少接口，正确拒绝应用启动 |
| 非代理 IPv4 TCP、IPv4/IPv6 回环 TCP | 启动子进程返回明确拒绝；受控端口未被连接 |
| IPv4/IPv6 回环 UDP | 非空测试数据未到达受控接收器 |
| 外部 IPv6 | CI 没有 IPv6 路由，不据此宣称已实测阻断 |
| 正常停止、MXC 守卫异常退出 | 应用及测试子进程均退出，普通宿主进程继续运行 |
| Mihomo 核心异常退出 | 应用直连仍被拒绝，随后正常清理整个作业 |
| 坏代理 | 拒绝启动，应用执行标记未出现 |
| Edge 154.0.4258.53 ARM64 | 容器内 0xc0000005 崩溃，页面与 Cookie 验收未通过 |
| Chrome 155.0.8059.39 x64 | 容器内 0xc0000022，浏览器验收未通过 |
| Firefox 157.0.1 x64 / ARM64 | 容器内 0xc0000022，浏览器验收未通过 |
| 普通用户，非管理员 | 普通应用代理通信通过；Chrome 超时，浏览器未通过 |
| 完整运行包 | 新增 Windows 11 实机发行门槛；以最后一次 Check 的运行包报告为准 |
| Windows 11 原生 x64 CPU | 当前没有可用的该类 CI 主机，不冒充已测 |

验证运行：[38138494180](https://github.com/Shermanxwz/Rule-proxy-Web/actions/runs/38138494180)。原始 JSON（含失败结果）、固定运行组件与校验值长期保存在 [不可变归档](https://github.com/Shermanxwz/Rule-proxy-Web/tree/139653ceb36e0597050d9a166f9bca6249248f81)。安装地址固定到该提交，不依赖会过期的 Actions 附件。

测试仅使用本地受控代理目标与合成 Cookie，不使用真实节点凭据。保留 JSON 报告和每次运行链接；“应用进程创建成功”不能替代“应用数据能经代理往返”。无路由、普通超时、零长度 UDP 发送结果不能替代阻断的证据。

扩大卷根读取权限的诊断方案会让未授权文件可读，且仍未解决浏览器启动，已经撤回；生产策略不开放卷根。诊断中关闭浏览器沙箱也无效，生产启动不采用该参数。

## 使用边界

需要 Windows 11 24H2 / 25H2 等已提供原生接口的版本，并安装所需更新，最终以实际请求探测和启动自检为准。Windows 10 不受支持。x64 运行包在 ARM64 上依赖 Windows 的 x64 模拟支持。

未打包的 Mihomo 没有容器或包身份绑定，必须采用微软的 identity-less loopback proxy 映射；它不提供完整双向宿主回环隔离，也不防御同一用户下恶意替换代理的攻击。保护对象是启动的容器实例及其子进程的正常套接字出站，不包括容器外服务、驱动和通过恶意 IPC 诱导宿主代发的请求。其他普通实例不会自动接管。

## 复现和发行

安装固定运行组件后，在真实 Windows 执行：

```powershell
python -B .github/windows_native_validation.py --output native-results
python -B .github/windows_fault_validation.py --output native-results
python -B .github/windows_browser_validation.py --output native-results
```

源码重建由 `.github/workflows/build-mxc-runtime.yml` 定义。允许重建并重新验证，不声称逐字节可重现；若改变组件字节，必须重新固定校验值并完成验收。

发行必须通过真正 Windows 客户端上的运行包浏览器渲染和 Cookie 保持；任何失败都会阻止应用发行。还必须同时通过 Linux 原有检查、Windows 单元测试、Windows 11 应用与故障检查，以及解压后运行包检查。发行工作流不能把不支持的 Windows Server 上的拒绝结果算作 Windows 11 应用可用性的验收。
