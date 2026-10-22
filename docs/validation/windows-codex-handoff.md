# Windows Codex 交接：先验证身份绑定 IPC，再完成应用级代理隔离

> **当前本机检查点，2026-10-23：** [最新运行进展与边界](2026-10-23-local-isolation-progress.md)记录 diagnostic09 首次完整 profiles-off 真实网络诊断：HTTP 129→95 字节请求/90 字节响应、同 held selected direct `10013`、前中后 origin 健康、实际 `base-container` tier 与清理均通过。wrong-port02 又完成独立 Q PSEC 前后 exact HTTP/nonce/tuple/EOF 健康控制，同一主 selected 对同身份不同端口返回 `10013`，receiver 无 forbidden nonce；两族 actual tier 和全部清理均通过。wrong-port01 的 ordinary 正控超时历史保留。`strict Full`、`checks.wrong_port`、`first_chain_verified`、`local_c_qualified`、`product_acceptance` 仍为 false；错误 peer、proxy death、DNS/浏览器/WinHTTP 等尚未验收。以下旧交接及 A/B 记录按各自受测版本保留，当前状态以此链接的独立证据为准。

> **本机 B 新增证据，2026-10-22：** 源提交 `8a42ced7fcfcf5c506d8fd7c3a2122ba7841e3e3` 的[受监督固定 origin 入口](2026-10-22-local-origin-runtime.md)首次真实运行成功：zero-cap AC frontend → pipe → ordinary relay → owned loopback origin 的精确 HTTP、双向 EOF、held identity/tuple 和清理均通过。[公开结果](../../verification/windows-2026-10-22/local-origin-01-public.json)与[版本摘要](../../verification/windows-2026-10-22/local-origin-01-summary.json)明确 frontend 请求和 sink 仍为内部生成；`network_tested=true`，`proxy_tested=false`、`product_acceptance=false`。真实 selected 应用的身份代理与隔离尚未验收。

> **本机接手后的新增证据，2026-10-22：** 提交 `c12dd0bf70fed256af00da56c4d246afdb9dca63` 的独立[本机受监督入口](2026-10-22-local-ac-ipc-owner.md)已在 ordinary Windows 11 `26200.9711`、Python `3.12.10` 上首次运行成功。[闭合结果](../../verification/windows-2026-10-22/local-ac-pair-01-public.json)及[版本绑定摘要](../../verification/windows-2026-10-22/local-ac-pair-01-summary.json)记录 zero-cap AC frontend / ordinary relay 的 48-byte IPC、EOF、held identity、Job 清空、ACL 移除和 profile 删除。本机 profile 与原 CI pinned Python/VM qualification 分开；这是第 9 节 A 的局部运行证据，`network_tested=false`、`proxy_tested=false`、`product_acceptance=false`。以下原交接记录及历史运行结论仍按各自受测版本解释；后续 B/C 尚未验收。

> **交接日期：2026-10-22。产品尚未完成，不是“Windows 隔离已通过”。**
> **最后短 CI 已验证，但真实 AC pair 未运行。** 受测源为 `7c7a839a8acef8a92fbc0bbd0505c0342065bda5`，[run 39777404738](https://github.com/Shermanxwz/Rule-proxy-Web/actions/runs/39777404738) 双端各 54 required suites、1,016 tests、零 skips；这不是代理网络验收。
> 本文是仓库内的接手入口；可用代码、公开脱敏证据和下一步边界均指向 GitHub 文件，不依赖前一会话、临时目录或内部笔记。用户准备让自己设备上的 Windows Codex 继续开发；这不授权前一执行方连接设备，也不授权重装 Linux。
>
> **没有现成且已验证的 Windows 本机一键 AC 入口。** CI guest 的固定 `C:\RuleProxyCI` 配置路径和原 QPC deadline 不能盲跑；Linux QEMU host 脚本也不是本机入口。接手首项是[第 6 节的最小 local owned adapter](#6-本机第一项开发任务最小受监督-ac-ipc-入口)：复用全部 supervision/identity/cleanup，绝不能绕开 outer Job。

## 1. 三分钟内必须知道的事实

1. 工作分支是 **`dot/windows-isolation-proof`**，不是主线。先核对 `git rev-parse HEAD`、工作树差异和[公开证据索引](windows-isolation-evidence-index.md)及其[机器可读版本](windows-isolation-evidence-index.json)。测试源 commit、证据归档 commit 和当前交接 commit 是三种不同身份，不能互换。
2. 真正 Windows 11 上的旧 Stage0b **32 字节 inherited-pipe** 已有一次完整成功证据；新的 native **48 字节双管道协议**只在 hosted、非 AppContainer 环境完成真实管道机制测试。
3. 新的“零 capability AppContainer frontend + ordinary relay”激活接线已通过最后短 CI 的纯测试、源码/传输和既有机制检查；**真实 AC pair 仍未运行**。新 runtime bridge build 分支仅经结构测试，未在该短 CI 执行。它仍是内存 HTTP，不开 socket，不是可用代理。
4. 原始 PSEC Stage0 的 `tokenCapabilities == []` 门槛仍失败，`Stage0=false`、`product_acceptance=false` 没有改成通过。单独命名的 Agentic-only 观察 profile 不是原始零 capability profile，也不是网络授权。
5. 已有 TCP/UDP/UDP6 和后代实验只支持各自固定端点、精确 payload、有限观察窗口的结论。特别是 UDP `sendto` 成功不等于包离开；固定端点包缺失不等于 DNS、broker、任意 IPv6 或代理失败关闭已证明。
6. 下一步应收敛到 **真实 AC 48 字节 IPC → 身份绑定代理正向 → 独立 raw-direct/错误 peer/代理死亡负向**。不要继续堆相似 direct UDP 变体，也不要把已停下的 REQUEST3 87 问题串行猜参数重跑。

### 接手不是授权转移

过去允许的安全变更限定在一次性 GitHub 测试 VM：专用 AppContainer、特定 capability、精确 SID ACL、精确 peer/端口规则、结束自己持有的代理进程。**这不自动授权在用户日常 Windows 上做相同变更。** 接手 Codex 应先解释本机影响范围、备份/快照和清理方案，再取得适用于该设备的确认。

不修改全局防火墙/系统代理/DNS/路由，不关闭浏览器 sandbox，不启用已退休 TUN 方案，不增加驱动签名或付费资源，不触碰生产节点、真实代理凭证或其他设备。不要运行 `Setup-Windows.cmd`、`Recover-Windows-Network.cmd` 等广义安装/恢复入口来绕过本实验的精确边界。

## 2. 不能缩小的产品目标

目标对齐本项目已有 Linux 核心效果：

- 指定应用及其后代只能经所选代理联网；不选中的应用不受影响。
- 直接 TCP/UDP、IPv4/IPv6、DNS 和系统代办不能绕出；代理异常/崩溃后不能恢复直连。
- 保留浏览器 sandbox，逐步验证真实浏览器及其网络服务/多进程兼容性。
- 显式给第一个浏览器配置代理可以作为兼容性起点；但这**不证明**任意 socket 的透明转发、UDP 转发，或 OS 已阻止 fallback。

不要求凭空承诺所有 Windows 版本/所有应用零损失。先证明一个目标应用完整隔离，再扩大支持范围；不以编译、CI 绿灯、HTTP 经代理成功或程序自身拒绝直连代替 OS 执行证据。

## 3. 已知证据与未完成项

最终文件/hash/归档目录以[证据索引](windows-isolation-evidence-index.json)为准；下面给出不能混淆的关键运行。

| 证据 | 真正支持的结论 | 不支持的结论 |
|---|---|---|
| [TCP capture 39590250893](https://github.com/Shermanxwz/Rule-proxy-Web/actions/runs/39590250893) | 固定 runner TCP tuple 的完整 capture/ordinary positive 与 contained 拒绝 | loopback 的 NIC 包结论、代理可用、DNS/broker 隔离 |
| [UDP4 39618679419](https://github.com/Shermanxwz/Rule-proxy-Web/actions/runs/39618679419) | 对应固定 UDP fixture 的窄边界 | 任意 UDP、透明代理 |
| [后代 UDP 39655961428](https://github.com/Shermanxwz/Rule-proxy-Web/actions/runs/39655961428) | 四条新鲜 parent-child chain/profile：仅一条 selected、三条 ordinary controls；三次 selected child send 被接受但选定 receiver/capture 无命中 | 任意后代/broker 都安全 |
| [UDP6 runtime08 39724691639](https://github.com/Shermanxwz/Rule-proxy-Web/actions/runs/39724691639) | theorem A：固定 guest-MAC/端点/端口/三种精确 payload 的 outer UDP 缺失；B=`[true,0,true]` | 任意 IPv6 无外发；共享 case nonce 的 true 来自合法 ordinary 数据，不能叫 selected leak |
| [Stage0b03 39754568079](https://github.com/Shermanxwz/Rule-proxy-Web/actions/runs/39754568079) | 真 Win11、current ordinary、fresh zero-cap AC、32-byte echo/EOF/exit/cleanup；单独 IPC qualified | 原 Stage0 pass；新 bridge executable/48-byte 协议合格；网络隔离 |
| [native core 39761410816](https://github.com/Shermanxwz/Rule-proxy-Web/actions/runs/39761410816) | Linux/MSVC 各 63 pure tests + 428 hash-bound compiled cases | 实际管道、身份、网络 |
| [hosted dual-pipe 39766674740](https://github.com/Shermanxwz/Rule-proxy-Web/actions/runs/39766674740) | 实际 48-byte pipe/EOF；成功、错误 case、watchdog 三例清理；hosted elevated/non-AC | ordinary Win11 AC frontend；真实 HTTP origin/proxy |
| [AC prerequisite 39772363906](https://github.com/Shermanxwz/Rule-proxy-Web/actions/runs/39772363906) | 54 suites/1,013 tests/零 skips、PowerShell/schema/17-member ZIP gates；Windows attempt1，Linux attempt2 | 新 AC pair 运行；attempt1 Linux 被取消不得隐藏 |
| [最终交接 short gate 39777404738](https://github.com/Shermanxwz/Rule-proxy-Web/actions/runs/39777404738) | 同一受测源上 Linux/Windows 各 54 required suites、1,016 tests、零 skips；PS/八模式 ZIP/既有机制及清理通过，433 项 sidecar 核对 | 新 runtime bridge build 分支的实际执行、AC pair、代理网络或产品完成 |

### 可复核的版本锚点

- 默认关闭 AC 集成的受测源：[`d9ad11ee2492f51d6d54224197ea442d2c5eecfd`](https://github.com/Shermanxwz/Rule-proxy-Web/tree/d9ad11ee2492f51d6d54224197ea442d2c5eecfd)，438 source pins；freeze SHA256 `87c8f7c42834e1bd6a212a4ab529027895f636e16e91415353d352883baba2a7`。归档 `0336310f` 不代表运行了激活后的代码。
- 真 Stage0b03 源：[`258c44547f5c40121db4a2465a6186169b5957bc`](https://github.com/Shermanxwz/Rule-proxy-Web/tree/258c44547f5c40121db4a2465a6186169b5957bc)；运行 head `024a84d5`；归档 `88f1b4e`。
- hosted dual-pipe 源：[`7b6e31a90d69e40b51a4c6bb4d19141adbd3aad8`](https://github.com/Shermanxwz/Rule-proxy-Web/tree/7b6e31a90d69e40b51a4c6bb4d19141adbd3aad8)；归档 `ac4903c67b20cb72002e3e94f8935c897a08e559`。
- 最后短 CI 受测源：[`7c7a839a8acef8a92fbc0bbd0505c0342065bda5`](https://github.com/Shermanxwz/Rule-proxy-Web/tree/7c7a839a8acef8a92fbc0bbd0505c0342065bda5)，运行 [`39777404738`](https://github.com/Shermanxwz/Rule-proxy-Web/actions/runs/39777404738)。结果已独立审计，归档 commit `d73e0152fb7ba90afb797cbc23b051520cbfaa9c`：[永久 summary](https://github.com/Shermanxwz/Rule-proxy-Web/blob/d73e0152fb7ba90afb797cbc23b051520cbfaa9c/verification/windows-2026-10-20/identity-proof/windows-codex-handoff-short-01-summary.json)、[永久 result](https://github.com/Shermanxwz/Rule-proxy-Web/blob/d73e0152fb7ba90afb797cbc23b051520cbfaa9c/verification/windows-2026-10-20/identity-proof/windows-codex-handoff-short-01-result.json)。该源包含 flag 激活和互斥接线；短 CI 通过不等于真实 AC pair 或新 runtime build 路径执行。
- 最终交付文档可在后续 docs-only commit 补充上述结果；它不是另一个受测源码 commit。运行前核对实际 HEAD 与 source manifest 的源绑定，不用旧 freeze 或未来文档 hash 冒充 runtime 证据。

历史设计文件中的“runtime unobserved/default-OFF”描述代表当时阶段；后续事实以**不可变原始结果 + 本索引**补充，不改写失败为成功。

### 完整交接清单及独立校验

- [source manifest](windows-isolation-source-manifest.json)：438 个 Windows proof source 文件的准确 path/bytes/Git blob/SHA256，及 activation 差异列表；不是整个应用仓库的清单。完整应用源码仍在同一 Git commit。
- [public archive inventory](windows-isolation-public-archive-inventory.json)：归档 `0336310f388de4ed25c1e8757d8b5bf25a079e48` 下本轮 identity-proof 目录的全部 253 个公开 JSON，含准确 path/blob/bytes/不可变 URL。八条里程碑索引只是精选，不代替该全目录；更早公开材料仍在 `verification/` Git 历史。
- manifest 的源 snapshot 是**首次加入该 manifest 的 commit**，避免在文件里填写它自身尚不存在的 commit hash。需要完整 Git 历史；浅克隆先按仓库下载许可 `git fetch --unshallow origin`，不要拿浅克隆中可见的第一个 commit 冒充首次加入版本。

```powershell
git rev-parse --is-shallow-repository
git log --diff-filter=A --format=%H -- docs/validation/windows-isolation-source-manifest.json
```

核对该 commit 的文件和 manifest，而不是把后续仅文档 commit 当受测源。当前工作树的独立 byte 校验示例（只读，不执行源码）：

```powershell
$verify = @'
import hashlib, json, pathlib
m=json.loads(pathlib.Path('docs/validation/windows-isolation-source-manifest.json').read_text(encoding='utf-8'))
rows=m['source_files']; assert len(rows)==m['source_file_count']==438
assert len({r['path'] for r in rows})==438
for r in rows:
    p=pathlib.Path(r['path']); assert p.is_file() and not p.is_symlink()
    b=p.read_bytes()
    assert len(b)==r['bytes'] and hashlib.sha256(b).hexdigest()==r['sha256'], r['path']
print('SOURCE_FILES_VERIFIED',len(rows))
'@
python -B -c $verify
if ($LASTEXITCODE -ne 0) { throw 'source_snapshot_mismatch' }
```

若源码已继续改动，校验失败是预期需要解释的差异，不应更新 hash 以掩盖它。验证历史 snapshot 时使用单独 checkout/worktree，勿覆盖用户未提交工作。后续新 short-gate 结果应追加独立归档，不改此 manifest 创建时的状态或旧历史。

## 4. 环境、工具和角色

### Windows 版本不是一个“11”标签

先私下记录：x64 client/server、build+UBR、补丁/重启状态、Python/PowerShell/MSVC/SDK 版本、实际 current token 和 compartment。只公开闭合版本/布尔信息，勿上传用户名、SID、完整环境或注册表转储。

- 多次真实 direct 实验用 **Windows 11 26300.9457**，低于当时 MXC 文档的 26H2 Process Isolation floor **26300.9550**；属于探索性结果，不是受支持版本承诺。
- 另一路目标 **26200.9711**；当时文档记录 25H2 Process Isolation floor **26200.9278**，Session Isolation 是另一个契约。版本号和 API 存在本身都不能证明 feature rollout/所请求 backend 可用。接手时重新核对[上游支持表](https://github.com/microsoft/mxc/blob/main/docs/backends/process-container/os-version-support.md)，保留引用版本，不凭推测更新系统。
- hosted `windows-2025` 是 Server 机制/编译环境，不替代普通 Win11。模拟降权 token 的旧 loader 失败也不是普通 Win11 的运行证明。
- 零 capability Win32 AppContainer IPC 与 MXC/PSEC backend 是不同前提；不要把前者的成功或 MXC support floor 混成彼此的运行资格。

### 角色必须分开

| 角色 | 本阶段要求 |
|---|---|
| 本机接手者 | 先做环境/权限/源码核查；不得因为有 admin 就以 admin 运行 ordinary assay |
| ordinary controller/relay | current primary token，非 elevated、非 AC、零 capabilities、默认 compartment；同用户/session 的 held-token 证据 |
| AC frontend | fresh profile 的精确 SID、actual zero capability、非 elevated/no UIAccess、held image/Job/token 全部重验 |
| admin 安装/规则维护 | 仅在以后明确需要且本机单独批准时；不得让它污染 ordinary 正负控身份 |
| 原 GitHub Linux host | QEMU/安装/外围收尾；其命令不是 Windows 本机运行入口 |

可读环境查询示例（不输出用户身份）：

```powershell
git status --short
git rev-parse HEAD
$v = Get-ItemProperty 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion'
[pscustomobject]@{ Build=$v.CurrentBuildNumber; UBR=$v.UBR; Edition=$v.EditionID }
[pscustomobject]@{ OS64=[Environment]::Is64BitOperatingSystem; Process64=[Environment]::Is64BitProcess; PowerShell=$PSVersionTable.PSVersion.ToString() }
python --version
```

这不是 token qualification。使用已审查的 native/held-token 谓词；不要用窗口标题、账户名称、`whoami` 的一行文字代替。

### 工具链与依赖

- 原 guest 使用 pinned **CPython 3.14.8 embed amd64**；37 members，解压 24,405,990 bytes，源码中检查准确 SHA256、目录和 `_pth`。见 [direct host](../../.github/windows_identity_direct_stage0.py)。本机任意 Python 版本不是该运行 pin 的替代证据。
- 测试使用 Python stdlib/unittest + **PyYAML 6.0.3**。安装依赖会访问包源，应按本机许可处理；不要继承 arbitrary env/secrets 给 actor。
- Native bridge：MSVC **x64** + Windows SDK、C++17，`/W4 /WX /MT /O2 /guard:cf`，PowerShell helper 要求 ≥5.1。仓库没有宣称任意 SDK/编译器版本都能通过；记录实际版本并让编译 fail closed，不自造 ABI。
- pinned G/MXC upstream：`7bf210247986cb73b1b314df60c2f1109c479c0b`，Rust build manifest `1.93`，target `x86_64-pc-windows-msvc`。当前 IPC bridge **不需要重新构建或修改 MXC**。
- [runtime pins](../../ruleproxy/windows_runtime_pins.py) 固定 G bundle SHA256 `89a9390d9db7f65c82c52ac8c545bff88d6e7577998bea9e5ab93d86f2be90a0`、executor `cd32e225fb858161b66bc23e9d2415843de348edf2cfdfb05cee0e7535dca1a7`；不得下载未核验“最新”二进制替换它。

## 5. 接手后的安全第一轮：读源码、纯测试、只编译

在仓库根目录执行；下面不是 AC/runtime 授权。先看 diff，确认工作树没有其他人的未提交改动。可在已经配置好的独立 Python 测试环境安装 `PyYAML==6.0.3`，不要把安装命令混进 actor 环境。

以下按当前 workflow 提取**明确的 54 个 required suite**，不会因为 broad discovery 空结果而假绿；不调用 workflow 中实际 QEMU/UDP/native steps：

```powershell
python -m pip install --disable-pip-version-check 'PyYAML==6.0.3'
if ($LASTEXITCODE -ne 0) { throw 'dependency_install_failed' }
$program = @'
import ast, pathlib, re, unittest, yaml
p=pathlib.Path('.github/workflows/windows-n0a-udp6-gates.yml')
w=yaml.safe_load(p.read_text(encoding='utf-8'))
s=[x for x in w['jobs']['pure']['steps'] if x.get('name')=='Required UDP6 and unchanged regression contracts']
assert len(s)==1
m=re.search(r'names=(\([^;\r\n]+\)); assert',s[0]['run']); assert m
names=ast.literal_eval(m.group(1))
assert type(names) is tuple and len(names)==54 and len(set(names))==54
assert all((pathlib.Path('tests')/n).is_file() for n in names)
parts=[unittest.defaultTestLoader.discover('tests',pattern=n) for n in names]
assert all(x.countTestCases()>0 for x in parts)
r=unittest.TextTestRunner(verbosity=2).run(unittest.TestSuite(parts))
raise SystemExit(not r.wasSuccessful() or bool(r.skipped))
'@
python -B -c $program
if ($LASTEXITCODE -ne 0) { throw 'required_contracts_failed' }
```

当前 54 中包括 AC controller/guest/transport 三个 suite。1,013 是历史测试数，不是应硬凑的未来目标。Native core 的独立三套纯测试还可分别运行：

```powershell
python -B -m unittest discover -s tests -p test_windows_identity_proxy_bridge_codec.py
python -B -m unittest discover -s tests -p test_windows_identity_proxy_bridge_model.py
python -B -m unittest discover -s tests -p test_windows_identity_proxy_bridge_native.py
```

逐项检查退出码。不要加 `--run-hosted`、`--run-actual-windows`、`--run-actual-qemu`；那是不同机制权限。Seven PS parity helpers 是现有 [short workflow](../../.github/workflows/windows-n0a-udp6-gates.yml) 中的明确列表；运行前确认它们仍是 fixture/mock/extraction，而非随手执行整个 workflow。

### 原样的 compile-only bridge 命令

先进入已安装的 MSVC x64 developer shell；以下与现有 workflow/helper 一致，输出目录必须不存在：

```powershell
$vswhere = "${env:ProgramFiles(x86)}\Microsoft Visual Studio\Installer\vswhere.exe"
$vs = & $vswhere -latest -products '*' -requires Microsoft.VisualStudio.Component.VC.Tools.x86.x64 -property installationPath
if (-not $vs) { throw 'Installed MSVC unavailable' }
Import-Module "$vs\Common7\Tools\Microsoft.VisualStudio.DevShell.dll"
Enter-VsDevShell -VsInstallPath $vs -SkipAutomaticLocation -DevCmdArguments '-arch=x64 -host_arch=x64'
./.github/build_windows_identity_proxy_pipe_actor.ps1 `
  -OutputDirectory "$PWD/proxy-pipe-production-build" `
  -ExpectedActorSha256 b26997e8110a7f57066b037a13b41ca34d67b665972ca780d3f52ff7e8f02c4d `
  -ExpectedIdentitySha256 530482aae4c94707ae4da25c1c3e84d8da929a021fc23b09e59fec17fe28d553 `
  -ExpectedCoreSha256 cc3d6a72e54b92ad8d854e9bd50b4237cc7e295d6b0df72a3732d2a9f62e0309
if ($LASTEXITCODE -ne 0) { throw 'compile_failed' }
```

只产生 `windows_identity_proxy_pipe_actor.exe` 和 `identity-proxy-pipe-manifest.json`（另有编译中间文件）；不是执行它们。生产发布 artifact 只取这两个文件，EXE 512 bytes–8 MiB、manifest ≤8 KiB。`compileOnly=true` 表示 helper 没执行，不是“可跳过后续 runtime admission”。编译器不同可能产生不同 EXE digest，必须使用新 manifest 的真实 hash，不复用旧 b153… binary hash。

## 6. 本机第一项开发任务：最小受监督 AC IPC 入口

**目前没有受验证的 Windows 本机一键 AC runtime 命令。** 不要把 Linux QEMU host 脚本当成本机入口，也不要绕开 owner 直接粘贴底层 controller CLI。

现有链路：

```text
Linux direct host / 固定 guest PS
  → windows_identity_proxy_pipe_ac_guest.py（outer owner）
  → ordinary launcher 的 suspended+owned Job/image/token admission
  → windows_identity_proxy_pipe_probe.py --run-ac-pair（profile/pair owner）
  → 同一 pinned native image 的 pipe-front / pipe-relay
```

底层实际接口如下，仅为接手核对参数，**不是独立安全启动命令**：

```text
python.exe -I -S -B .github/windows_identity_proxy_pipe_probe.py --run-ac-pair
  --actor <fixed bridge executable> --manifest <fixed manifest>
  --expected-manifest-sha256 <64hex> --expected-actor-sha256 <64hex>
  --work <fresh owned directory> --run-nonce <32hex> --case-nonce <32hex>
  --deadline-qpc <original D> --qpc-frequency <actual F>
```

现有 guest adapter CLI 是 `--config --deadline-qpc --qpc-frequency`；配置路径严格固定为 `C:\RuleProxyCI\ruleproxy-vm-config.json`，actor 在包内 `bridge/`，它不是任意路径 local launcher。配置的 `proxy_pipe_ac` 只有 `enabled/run_nonce/case_nonce/actor_sha256/manifest_sha256` 五键。

**推荐接手实现一个最小、另命名、本机 opt-in owner/adaptor，而不是放宽这个固定 guest 入口：**

1. 先提交只读环境/资源 preflight 与 pure fake-clock/Win32 tests；复用现有 `NativeAPI`、`QpcBudget`、`launch_owned` 和严格 report validators，不另造进程清理框架。
2. 在所有本机 setup 之前取一次 actual QPC `F/D`，原有最多 120 秒预算/分段 reserve 不续期；保留 exact pinned image/manifest、fresh private work、fresh case/run nonce。
3. 必须在 controller 第一次 resume **以前**赋予 outer kill-on-close non-breakaway Job、核验 held image/current ordinary identity。直接 `Popen` 后 timeout/按名字 kill 不等价。
4. 本机没有“销毁 VM”最后兜底；先确定隔离副本/快照、必要的外层持有者和失败恢复。不得伪造 `vm_destroyed=true` 或重用 host qualification；给本机 owner 单独闭合 schema 与真实 cleanup 语义。
5. 当前 source 的 pure tests 绿后，提交本机 runtime 计划，说明会创建哪个 fresh profile/哪些 owned ACL/怎样退出；待本机用户确认后只跑一个 pair。失败保留原因/已验证正向，不自动 retry、不增加 capability、不换身份。

精确复用 seam（先读这些定义，不复制出第二套所有权框架）：

| 模块/函数 | 可复用边界 |
|---|---|
| `windows_identity_ordinary_launcher.py::NativeAPI`、`QpcBudget(api, D, F)` | held Win32 identity/process/Job、同一 QPC domain 与 cutoff；不是替本机创建角色或提升权限 |
| 同模块 `token_is_ordinary`、`same_identity`、`launch_owned(..., qpc_budget=..., work_cutoff=..., cleanup_cutoff=...)` | current ordinary gate、suspended creation→assign/verify→resume、one-shot cleanup；必须先有 outer owner |
| `windows_identity_proxy_pipe_ac_guest.py::valid_config/execute/fixed_command/bind_controller/validate_public` | 五键 config、严格 child argv、outer held evidence 绑定和 closed projection；`configuration()` 固定 CI 路径不能当通用 local loader |
| `windows_identity_proxy_pipe_probe.py::verify_ac_artifact/run_ac_pair/validate_private_report` | manifest/image绑定，单 pair profile/ACL/children所有权，私有报告重算；不直接绕过上层 `execute` 的 supervision |

本机新入口可设计不同配置位置，但应另名/version，并在评审中明确怎样绑定 root/输入/角色/外层截止/失败恢复；不临时拼一个未经验证的启动脚本让用户试。现有 `execute(..., root=..., api=...)` 是复用 seam，**不是已通过本机运行的承诺**。

### 不能丢的所有权和 QPC 规则

- 两个 child 都 suspended 创建，显式两 handle list、disjoint endpoints；两者 held image/token/Job 均验证后才允许任何 resume。
- parent 的四个 data endpoint 都先消耗 ledger 并 close；任一 uncertain 就不 resume。关闭尝试只一次，不能在 finally 因裸 handle 数字复用而重试。
- `Tb=T0+10F` 必须装进 `D−30F`；pair/ACL/profile cleanup 到 `D−10F`；controller exit 到 `D−5F`；outer cleanup 到 `D`。D 是原 guest/work cutoff，baseline/setup 用掉的时间算在内；不是每层再给 120 秒。
- 各 phase cap 只可向剩余绝对预算缩小。同步 API 不保证可取消；超时/未知 CreateProcess/close/exit 不能被 cleanup 布尔掩盖。
- controller 单独拥有 fresh profile、exact SID ACL 与 pair Job；只有两个 held exit + Job empty + handle cleanup 后才移除精确 ACE/readback/delete profile。adapter 不接管 uncertain controller 的 profile cleanup。
- 已验证 echo/EOF 等正向证据要 sticky，但绝不能把 missing report/无输出当成没有进程、没有网络包或成功清理。
- child env：frontend 只有 `SystemRoot/LOCALAPPDATA`；LOCALAPPDATA 来自 same-current-user known-folder，COM/init/free/deadline 分别留证。caller/relay 仍是既有四键 `SystemRoot/WINDIR/TEMP/TMP`，不继承任意环境/secret。

## 7. 17-member 包、资源和公开结果

当前 GitHub AC 集成的**精确 17 项**，不要用等数量替代项蒙混：

```text
python-embed.zip
actor.exe
stage0-input.json
g/build-manifest.json
g/wxc-exec.exe
g/MXC-LICENSE.md
.github/windows_identity_direct_stage0.py
.github/windows_identity_proof.py
.github/windows_psec_compartment_smoke.py
ruleproxy/windows_runtime_pins.py
.github/windows_identity_ordinary_launcher.py
.github/windows_identity_pipe_probe.py
ruleproxy/windows_app_process.py
.github/windows_identity_proxy_pipe_probe.py
.github/windows_identity_proxy_pipe_ac_guest.py
bridge/windows_identity_proxy_pipe_actor.exe
bridge/identity-proxy-pipe-manifest.json
```

`actor.exe` 是旧 baseline IdentityOnly，不是 bridge 替代。依赖 closure 依靠明确路径加载，不把 C++ sources/TEST_ONLY/capture/旧 Stage0b adapter 偷塞到生产 ZIP。

磁盘规划：`P + expandedZIP + 24,405,990 + A0 + E + B + 1 MiB <= 128 MiB`。P 是实际 ZIP；A0/E 是 baseline retained actor/executor copies；B 是两个 bridge children 共享的一份新 copy。必须从真实成员 bytes 得出，检查 fresh free space，不把上限当估计值。**128 MiB 是保守 staging admission，不是 RAM/文件系统硬 quota；65 MiB capture reserve 不是可借的空闲 RAM。** 本 IPC 模式不 capture。

private native report ≤8 KiB，aggregate ≤128 KiB，public/完整 transport ≤4096 bytes。只公开闭合布尔、枚举、计数、source/artifact hash/nonce commitment；不上传 raw SID/PID/handle/path/env/argv/nonce、原始错误文本或 PCAP。历史 raw PCAP 已删除不是交接缺失，不能补造；公开 sanitized counts 只能支持它们实际记录的结论。

`ac_pipe_passed` 需要所有十二 facts、bound native pair、实际 pipe EOF/exit/cleanup；host 的 `proxy_pipe_ac_ipc_qualified` 另外需要 launcher/transport/VM cleanup。`synthetic_http_only=true`，`network_tested=false`、`proxy_tested=false`、`product_acceptance=false`。基线整体失败继续如实退出失败，不能 `continue-on-error`/`exit 0` 美化。

## 8. GitHub 现有运行入口：仅供核对，不在交接时触发

已通过最后短 CI 的 activation 接线在 [direct workflow](../../.github/workflows/windows-identity-direct-stage0.yml) 增加第八互斥 marker **`[identity-proxy-pipe-ac-runtime]`**；该 runtime 分支仍未实际执行。只有工作分支 push、8 个 runtime marker 恰好一个、compile/host-unit prerequisites 通过才可能进入 native job。提交交接/文档时不要无意带这个 marker。

专用编译 artifact `identity-proxy-pipe-production-actor` 必须 same-run 下载，和 `client-stage0-actor` 分离。现有 Linux host 新增的实际参数仅为：

```text
--proxy-pipe-ac
--proxy-pipe-ac-actor <proxy-pipe-production-build/windows_identity_proxy_pipe_actor.exe>
--proxy-pipe-ac-manifest <proxy-pipe-production-build/identity-proxy-pipe-manifest.json>
```

source SHA 经严格 40-hex 且等于 `GITHUB_SHA` 校验后传入；旧变量名 `CAPTURE_SOURCE_COMMIT` 在这里不表示开启 capture。job 120 分钟、6900 秒初始绝对截止、host 6600 秒及既有 cleanup reserves 均不扩张。公开 artifact 只有 `identity-proxy-pipe-ac-ipc-public` 的 `client-stage0-public/proxy-pipe-ac-public.json`，旧 baseline/preparation evidence 独立保留。

当前 enabled flag 是唯一权威 switch。off-entry tests 显式 patchFalse 才调用入口；不能让 activation 后的“纯测试”误执行 native API。旧七种 runtime argv/default、host/guest/native ABI 不应随此次激活修改。独立 gate workflow 的历史 source pins 属于其受测版本，不能在新 HEAD 上为求绿盲目重写。

## 9. 后续代理工程：最小里程碑，不跳步骤

| 次序 | 最小工作/证据 | 必须保留的反例与边界 |
|---|---|---|
| A | 新 binary 在真 ordinary Win11 的 zero-cap AC frontend/ordinary relay 完成 48-byte IPC | 新 token/image/nonce/EOF/owner 重验；旧32byte或hosted成功不代替 |
| B | 给现有 native pipe core 接真实的**固定自有 HTTP GET**前端/relay；先机制/正向 fixture | 单 inflight、fresh nonce、固定 numeric origin，无 CONNECT/任意 URL/凭证；synthetic flags 不伪装网络 |
| C | 单独设计并审核实际 proxy identity/profile 与精确 peer/WFP policy | privateNetworkClientServer、ingress allow、new proxy SID/peer rules 是新安全契约，不能复用 Agentic-only 或 zero-cap 标签 |
| D | ordinary before/during/after 正控；selected 显式代理实际 nonce roundtrip | 同时 raw direct 与 wrong peer/port/control local service 必须实际 attempted 且有健康正控；仅显式 WinHTTP proxy 成功不证明 OS enforced |
| E | 活代理期间及关闭前/中/后 direct、DNS/UDP/IPv6 负向；精确持有代理进程终止 | 不以进程名杀、不启全局 firewall、失败不能 fallback；capture/receiver正向 sticky，unknown→inconclusive |
| F | DNS API/default resolver/broker、child family、浏览器 sandbox/网络服务与未选 app | 每个路径先有相同 API 的实际正控；未测明确列未测，不以一次 TCP/UDP absence 替代 |

普通 Python proxy 没有所需 AppContainer 身份，不是 identity-bound proxy 的实现。旧 `hostLoopback=allow` 在更高政策契约下被拒过；历史 model2 `allowedProxyPeer`/hostLoopback deny 是已有路线，不要重新包装为新发现。读现有 [Windows runtime](../../ruleproxy/windows_runtime.py)、[proxy policy](../../ruleproxy/windows_proxy_policy.py)、[proxy runtime](../../ruleproxy/windows_proxy_runtime.py) 及历史证据再改动；模块存在/单测通过不证明当前路线已完成。

如果为了可达代理放开所有 loopback/local services，即使代理 HTTP 成功，也违背“只能通过选定代理”边界。必须说明具体 identity/capability/ingress/peer-port 变化、何种 OS 层执行，证明 wrong peer/port 与其他 local service 仍拒绝；没有这种边界就停止并报告，而不是偷偷扩大 allow。

## 10. 已知失败、禁止假绿和诊断纪律

- **原 PSEC Stage0**：fresh actor 实际出现 Agentic singleton capability，其他身份条件可通过但 empty-cap gate 失败。单独观察 profile 不说明此 capability 安全，不能改掉历史 acceptance。
- **Stage0b02 CreateProcessW 203**：caller/child env 依赖当时未证因果。后来 single child-block variant 加 verified current-user LOCALAPPDATA 的 Stage0b03 成功；这是非同时对照，不证明唯一原因，也不能混同 MXC SDK launch validator 与裸 CreateProcessW 契约。
- **DNS REQUEST3**：实际 Server2025 中 NULL/non-NULL cancellation、高端口/53 均 87、零 datagrams、owned cleanup 完整。布局/init/backing version 已查，停止 speculative variants；不能把 raw Winsock UDP 控制当作 DnsQueryEx 或 broker positive。
- **UDP6 历史 decoder**：先遇到 scope 非零，再补 actual `IPV6_PKTINFO` ingress-interface/zone 验证；后遇 NH58 NS/NA，最终把明确 terminal ICMPv6 与“固定 endpoint outer UDP absence”定理分离。不是把某个包类型跳过求绿。当前 B whole-record exact selected-frame/shared nonce 观察和 A 不相互覆盖。
- **capture**：完整性/ordinary packet positives/terminal positive/overflow/no-truncation/owned QEMU退出都需要；guest NIC 看不到 loopback。tuple冲突/端口复用不能归因 actor leak；确切 selected bytes 观察不能被 timeout/cleanup 失败抹掉。
- **错误不是拒绝证明**：无报告、loader失败、API unsupported、fixture不可达、timeout、未知 spawn/exit/close、ACL readback失败，都不是网络阻断 pass。HTTP非200/读取失败也不能抹去已完成 TCP connect 或接收端/packet正向。
- **不确定清理不重试裸资源**：不凭 PID/name 或 numeric handle 猜所有权；不删除仍可能被活进程引用的 profile/tree；不将 terminate Job 的期望当 held process exit 观察。

每次改动先写精确可证命题、允许变化、固定对照、上限/截止、清理所有者、通过/失败/不确定条件，再 code-only/pure tests/实际机制/目标系统分级验证。一次新失败先归档、读已有 source/证据、选择有区分力的一项变化；不是无限 observation→猜参→新 VM。

## 11. 代码地图与资料保存规则

| 内容 | 入口 |
|---|---|
| 产品 Linux 参照 | [linux_runtime.py](../../ruleproxy/linux_runtime.py)、[linux_core_process.py](../../ruleproxy/linux_core_process.py)、[Linux verification](../../verification/linux-global-2026-10-16) |
| 原 Windows product 路径/系统代理边界 | [windows_runtime.py](../../ruleproxy/windows_runtime.py)、[system_proxy.py](../../ruleproxy/system_proxy.py)；本分支不得偷改主线行为 |
| pinned identity/PSEC baseline | [windows_identity_proof.py](../../.github/windows_identity_proof.py)、[native identity actor](../../.github/native/windows_identity_actor.cpp)、[runtime pins](../../ruleproxy/windows_runtime_pins.py) |
| 已证32byte IPC/lifecycle/env | [pipe probe](../../.github/windows_identity_pipe_probe.py)、[ordinary launcher](../../.github/windows_identity_ordinary_launcher.py)、[Stage0b guide](2026-10-22-stage0b-minimum-integration.md) |
| native48byte reducer/纯模型 | [core](../../.github/native/windows_identity_proxy_bridge_core.hpp)、[codec](../../.github/windows_identity_proxy_bridge_codec.py)、[model](../../.github/windows_identity_proxy_bridge_model.py)、[协议](2026-10-22-identity-proxy-bridge-contract.md) |
| actual pipe actor/hosted机制 | [native](../../.github/native/windows_identity_proxy_pipe_actor.cpp)、[controller](../../.github/windows_identity_proxy_pipe_probe.py)、[机制文档](2026-10-22-native-proxy-pipe-mechanics.md) |
| 下一 AC pair | [guest owner](../../.github/windows_identity_proxy_pipe_ac_guest.py)、[契约](2026-10-22-proxy-pipe-ac-prerequisite.md)、[direct host](../../.github/windows_identity_direct_stage0.py)、[guest PS](../../.github/windows-identity-direct-stage0-run.ps1) |
| 历史结果全集 | [verification/](../../verification)、[本交接索引](windows-isolation-evidence-index.md)；不要只看绿色摘要 |

Native local reducers 只能看到自身收写/EOF/close；Python全局 model 有 omniscient harness 状态。不要要求 native 知道 remote consumed/closed，或把 RESPONSE0 当远端真实 HTTP 事实；差分只在可实现观测边界比较，另有独立 goldens 防共同 bug。

公开保存源、manifest、冻结 hash、闭合 JSON、run/source/archive链接和失败解释。临时私密原始数据无须公开；若未来需要保留，应本地私有/限期并得到许可。Actions artifact 有保留期，关键脱敏 JSON 必须进入 Git 历史；索引 hash 与可下载文件逐一校验，缺失就标 missing，不补造事实。

## 12. 可直接交给本机 Windows Codex 的提示词

```text
仓库 https://github.com/Shermanxwz/Rule-proxy-Web ，分支 dot/windows-isolation-proof。
最后短 CI 受测源 7c7a839a8acef8a92fbc0bbd0505c0342065bda5，run 39777404738，
结果归档 d73e0152fb7ba90afb797cbc23b051520cbfaa9c。双端各1,016测试零skip，但真实AC pair未运行。
源 pin 同时按 windows-isolation-source-manifest.json 首次加入的 commit 和完整历史步骤核验；
最终交付文档可能位于后续docs-only commit，不要把文档commit当另一份受测源码或自填未来hash。
请先完整阅读 docs/validation/windows-codex-handoff.md 和 windows-isolation-evidence-index.md/json，
核对本次 Git commit、已归档源和当前未验证改动。不要依赖前一聊天或 /tmp。

目标是指定 Windows 应用及后代只能经选定代理联网，DNS/系统代办不能绕出，代理崩溃不直连，
未选应用不受影响，并保留浏览器 sandbox；不要把固定 UDP absence 或显式 proxy HTTP 成功当完成。

先只读核查这台机器的 Windows build/UBR、client/server、Python/MSVC/SDK、ordinary/admin 边界，
运行明确 pure tests 和 compile-only（安装依赖前按本机权限确认）。给我当前差距和最小计划。
已有真 Win11 Stage0b32byte成功、hosted48byte双管道成功；新 zero-cap AC frontend/ordinary relay
尚无真实运行证据。先复用原 owned Job/QPC/image/token/knownfolder/cleanup，设计本机最小安全入口，
不要绕过 outer owner 或伪造 vm_destroyed。任何本机profile/ACL/network规则/终止进程等操作先说明
精确影响并取得本机确认；此前GitHub VM许可不自动适用本机。不要全局改DNS/防火墙/代理/路由，
不要关闭sandbox、用真实节点凭证、重装系统或连接其他设备。

按 AC IPC→固定自有endpoint身份代理正向→独立raw-direct/错误peer/代理死亡负向→DNS/broker/后代/
browser 的顺序推进。REQUEST3=87路线已停，不做猜参数重试。原Stage0false/productfalse保持，
每一项都保留正控、完整packet/receiver边界和owned cleanup；missing/timeout/unknown是inconclusive。
所有有用代码和脱敏证据继续提交该实验分支，不改写历史失败，不把CI绿色当产品完成。
```

**交接验收条件：** 新接手者只靠此仓库即可找到源、测试、证据、明确的下一步与停止条件；本机安全执行计划仍由接手者在核实环境后提出并确认。没有此步骤，不应直接开始安全状态变更。
