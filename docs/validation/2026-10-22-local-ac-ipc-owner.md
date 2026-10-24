# Windows 本机 AC IPC owner：guard、worker 与单 pair 边界

日期：2026-10-22。入口是 [windows_identity_proxy_pipe_ac_local.py](../../.github/windows_identity_proxy_pipe_ac_local.py)，纯测试是 [test_windows_identity_proxy_pipe_ac_local.py](../../tests/test_windows_identity_proxy_pipe_ac_local.py)。这是 [交接文档第 6 节](windows-codex-handoff.md#6-本机第一项开发任务最小受监督-ac-ipc-入口)要求的独立本机适配层；不放宽固定 `C:\RuleProxyCI` guest loader，不改写旧 source manifest、CI 运行结果或失败历史。

本页描述实现契约与纯测试边界。真实机制结果须有独立的 source/artifact 绑定记录，不能从本页或纯测试推导。`synthetic_http_only=true`、`network_tested=false`、`proxy_tested=false`、`product_acceptance=false` 始终保留；即使 `local_ipc_qualified=true`，也只表示这个本机 profile 的一次受监督 48-byte pipe pair，不表示代理网络或产品隔离完成。

## 入口与只读 preflight

从仓库根目录、当前普通用户的 x64 Python 运行。入口默认只读：读取现有源码、manifest、EXE、恢复计划、磁盘空间、原生架构和当前 held token/compartment，并关闭查询 token。不创建工作目录、Job、AppContainer profile、actor 或 ACL，不安装依赖，不发起网络请求。

```powershell
python -I -S -B .github/windows_identity_proxy_pipe_ac_local.py
```

没有 artifact/计划时，保留已经观察到的闭合 preflight facts，并以 `status=inconclusive`、具体 failure 枚举及非零退出结束；这不是运行 actor。完整参数如下，hash 必须来自本次真实字节，不能复制旧 binary hash：

```powershell
$actor = '<existing-directory>\windows_identity_proxy_pipe_actor.exe'
$manifest = '<same-existing-directory>\identity-proxy-pipe-manifest.json'
$actorHash = '<64-lowercase-hex SHA256 of the actual EXE>'
$manifestHash = '<64-lowercase-hex SHA256 of the actual manifest bytes>'
$plan = "$PWD\private\local-ac-recovery-plan.json"

python -I -S -B .github/windows_identity_proxy_pipe_ac_local.py `
  --actor $actor --manifest $manifest `
  --expected-actor-sha256 $actorHash `
  --expected-manifest-sha256 $manifestHash `
  --work-parent "$PWD" --recovery-plan $plan
```

`--work-parent` 必须是本 checkout 内已存在、逐层无 reparse/symlink 的目录，默认为 checkout 根。`ready` 的含义是全部六项 preflight checks 及其承诺齐备，尚未执行任何安全状态变更。

真实运行还需要同时给出以下两个显式标志；缺任意运行请求/opt-in，不会进入运行路径。标志只记录调用者意图，恢复计划只记录恢复安排，都不等于代码自己授予权限；设备所有者对该精确范围的许可应已在操作会话中成立。

```powershell
python -I -S -B .github/windows_identity_proxy_pipe_ac_local.py `
  --run-local-pair --approved-local-security-test `
  --actor $actor --manifest $manifest `
  --expected-actor-sha256 $actorHash `
  --expected-manifest-sha256 $manifestHash `
  --work-parent "$PWD" --recovery-plan $plan
```

公开闭合 JSON 写到 stdout，最大 4096 bytes。`ready` 或完整 `passed` 返回 0，其他状态返回 1。内部 `--owned-worker --worker-config` 不是独立安全启动命令：普通 checkout 会被拒绝；不能通过直接调用它绕开 guard。

## 私有恢复计划的完整 schema

计划为 UTF-8 JSON、最大 8192 bytes；拒绝重复键、非有限数字和未列出的键。恰好包含以下八个字段：

| 字段 | 精确要求 |
|---|---|
| `schema_version` | integer `1`，不接受 boolean |
| `scope` | `one-local-zero-cap-pair-no-network-v1` |
| `device_sha256` | 当前原生 `GetComputerNameW` 结果 casefold 后按 UTF-16LE 编码的 SHA256；64 个小写 hex，仅留私有 |
| `actor_sha256` | 本次 EXE 字节 SHA256，64 个小写 hex |
| `manifest_sha256` | 本次 manifest 原始字节 SHA256，64 个小写 hex |
| `source_sha256` | 本文固定八项 Python closure 的 canonical hash map 承诺，见下节 |
| `recovery_reference` | 1–512 字符，无 U+0000–U+001F；记录实际可用的备份/隔离副本参照和失败后精确 owner journal 检查安排 |
| `residue_review_acknowledged` | boolean `true` |

以下仅为结构示例，所有尖括号值均须替换；它不是可运行计划，也没有真实设备 hash：

```json
{
  "schema_version": 1,
  "scope": "one-local-zero-cap-pair-no-network-v1",
  "device_sha256": "<PRIVATE_DEVICE_SHA256_64_LOWERCASE_HEX>",
  "actor_sha256": "<ACTUAL_EXE_SHA256_64_LOWERCASE_HEX>",
  "manifest_sha256": "<ACTUAL_MANIFEST_BYTES_SHA256_64_LOWERCASE_HEX>",
  "source_sha256": "<CURRENT_FIXED_PYTHON_CLOSURE_SHA256_64_LOWERCASE_HEX>",
  "recovery_reference": "<actual backup or isolated copy reference; stop and review exact owned journals on unknown cleanup>",
  "residue_review_acknowledged": true
}
```

这是设备、源码、artifact 绑定的人类恢复安排记录，不是已验证系统快照，不是 `vm_destroyed` 证明。程序不创建/恢复系统快照。复制计划时重读并核对已验证 raw bytes hash；worker 在安全状态变更前再次核对私有计划 hash、设备、source/artifact 承诺和 fresh stage。

完整计算机名或稳定设备 hash 不进入公开报告；公开只保留 `device_bound` 布尔。SID、PID、handles、原始 nonce、路径、argv、环境和原生私有报告也不进入公开结果。

## 固定源码、artifact 与容量绑定

staging 恰好复制以下八个 Python 文件，不复制任意模块目录、不继承 `PYTHONPATH`：

```text
.github/windows_identity_proxy_pipe_ac_local.py
.github/windows_identity_proxy_pipe_ac_guest.py
.github/windows_identity_proxy_pipe_probe.py
.github/windows_identity_ordinary_launcher.py
.github/windows_identity_pipe_probe.py
.github/windows_identity_proof.py
.github/windows_psec_compartment_smoke.py
ruleproxy/windows_app_process.py
```

每项读取上限 256 KiB、校验每层既有路径无 alias/reparse，并在 staging 写入后重读 SHA256。`source_sha256` 是 `SHA256(encode({relative_path: sha256, ...}))`；`encode` 使用 ASCII JSON、`sort_keys=True`、`separators=(',', ':')`、`ensure_ascii=True`，最后一个换行也参与 hash。worker 重算同一 closure；源码变动应使旧计划失效，不能为了运行重用旧 pin。

EXE 与 manifest 必须同目录，文件名分别固定为 `windows_identity_proxy_pipe_actor.exe`、`identity-proxy-pipe-manifest.json`。复用 `verify_ac_artifact` 校验 EXE 大小/PE header/真实 digest、manifest 的七键闭合 schema、`compileOnly=true`、`runtimeAcceptance=false` 和精确 raw manifest hash。另核对下列三个 source 字段等于本 checkout 真实源字节的 SHA256，避免把其他源码生成的自洽 artifact 当成本次构建：

| manifest 字段 | 本 checkout 源 |
|---|---|
| `actorSourceSha256` | `.github/native/windows_identity_proxy_pipe_actor.cpp` |
| `identitySourceSha256` | `.github/native/windows_identity_actor.cpp` |
| `coreSha256` | `.github/native/windows_identity_proxy_bridge_core.hpp` |

容量 admission 使用真实 Python bytes、两份 actor copy、8192-byte manifest 上限、三份 128-KiB report allowance 和 1-MiB reserve；总量不得超过 128 MiB，并检查 fresh free space。两份 actor 是 guard staging copy 与 pair 共享的一份 inputs copy。这是磁盘 planning admission，不是文件系统或 RAM 硬 quota；本机路径不用 CI 17-member ZIP，也不 capture。

## 原子 guard Job 与持有身份

链路是：

```text
local guard (current ordinary)
  → CreateProcessW(JOB_LIST + HANDLE_LIST, suspended)
  → exact Job / held Python image / same-current-token admission
  → worker first resume
  → existing guest.execute + launch_owned
  → controller
  → zero-capability AC pipe-front + ordinary pipe-relay
```

guard 创建 fresh `Local\RuleProxy.LocalGuard.<run_nonce>` 命名 Job，SDDL 为 protected 当前用户与 SYSTEM generic-all。`CreateJobObjectW` 之前清 last error，返回后立即保存；若是 `ERROR_ALREADY_EXISTS`，只关闭返回的 handle，不修改或终止既有 Job。fresh Job 的 limits 必须回读为精确 `KILL_ON_JOB_CLOSE`，无 breakaway/silent-breakaway。

worker 在 `CreateProcessW` 时通过 `PROC_THREAD_ATTRIBUTE_JOB_LIST` 原子加入该 Job；不是先创建再补 Assign。`launch_owned` 的 assign seam 在本机 subclass 中仅验证既有精确成员关系，不提供 fallback。JOB_LIST 不支持、创建未知或身份不符均拒绝 resume。沿用 suspended creation、held image/current ordinary token、same user/session、默认 compartment 和既有单次清理 lifecycle。

guard 的 Job handle 设为 non-inheritable，且不进入 HANDLE_LIST。HANDLE_LIST 只有三个 fresh stdio files；JOB_LIST 是进程创建属性，不表示把 Job handle 交给 worker。worker 和内部 controller/actors 的环境沿用四键 `SystemRoot/WINDIR/TEMP/TMP`，AC frontend 另用经 known-folder 核验的 `SystemRoot/LOCALAPPDATA`。原两条 actor data endpoint/显式 handle list 协议保持不变。

worker 不能以“处于某个 ambient Job”作为 admission。它先校验 fresh `local-ac-<run_nonce>` stage 名、固定 config/source、设备/恢复计划和 stage DACL，然后 `OpenJobObjectW(QUERY, noninherit, exact_name)`，核验当前进程在该精确 Job、limits 仍精确 KOC，最后只尝试一次关闭 query handle。任何 query/close 不确定都发生在 profile/AC ACE 创建之前，并阻止 `guest.execute`。guard 若在查询期间退出，worker 关闭最后 query handle 时 KOC 生效；worker不会带着 Job handle继续安全 setup。

内部 controller 与 actors 在已加入的 guard Job chain 内创建，因此内部 CreateProcess→nested Job assign 之间仍受继承的 guard Job 约束。命名 Job 在当前 Windows session 可按名称查询；fresh 128-bit nonce 和当前用户/SYSTEM DACL限定该对象边界。这不宣称抵御同用户恶意代码或 SYSTEM。

## 同一 QPC 域和真实 reserve

NativeAPI 装载成功后，guard 在 preflight、staging 和安全 setup 之前读取 actual `F` 和 `Tguard`，只定义一次：

```text
Droot   = Tguard + 120*F
Dworker = Droot  -   5*F
```

后续 `QpcBudget` 重新读取 QPC 是验证同一域、单调性和剩余量，不重设起点。所有 deadline 和 `F` 均绑定到私有 worker report；公开保留固定 clock contract，不泄露 raw QPC/nonce/身份。

| 边界 | 绝对 cutoff |
|---|---|
| 本地 staging 开始 admission | `Droot−45F` 前仍有预算 |
| 每个 staged source 和 guard 启动前 admission | `Droot−40F` 前仍有预算 |
| worker 安全 setup admission | `Droot−35F` 前仍有预算 |
| 原 pair 10-second protocol end `Tb` | `Tb <= Dworker−30F = Droot−35F` |
| 原 pair/ACL/profile cleanup | `Dworker−10F = Droot−15F` |
| controller 私有报告/退出 cutoff | `Dworker−5F = Droot−10F` |
| guest 对 controller 的 outer cleanup | `Dworker = Droot−5F` |
| worker report 完成、guard held worker wait | `Droot−3F` |
| guard outer cleanup 与最终 deadline 验证 | `Droot` |

setup 花费计入原总预算，不能容纳下一阶段则停止；不是每层各得 120 秒。同步 Win32/文件系统调用并不保证可取消，故上述是 admission/观察截止，不是同步 API 必然在墙钟 120 秒内返回的承诺。超时或未知返回不能被 cleanup 布尔覆盖。

## 一次运行的精确状态变更与退出

一条调用只请求一个 fresh pair，无自动 retry。变化限于：

1. 在指定 checkout 内创建 fresh `local-ac-<run_nonce>` staging，原子附 protected 当前用户/SYSTEM file DACL，立即回读；写固定 sources、artifact、stdio 与私有 journals。
2. 创建上述 fresh guard Job；worker/controller/pair 均由 held owner 监督。只终止自己持有的 Job/进程，不按 PID 或进程名猜所有权。
3. controller 创建 fresh `RuleProxy.ProxyPipe.<case_nonce>` AppContainer profile，零 capability；重验实际 held token、image、两子进程 Job 和双管道端点后才 resume。
4. 仅给该精确 fresh profile SID 添加 controller 自有树内 ACE：`private-proxy-pipe-ac/controller` 为 RX、`inputs` 为 `(OI)(CI)(RX)`、`frontend-output` 为 `(OI)(CI)(M)`，并核验 scope。不给 relay-output 或既有 checkout/祖先目录增加 AC allow。
5. pair 两 held exits、Job empty、handles cleanup 完整后，controller 才移除该精确 SID 的 ACE、回读并删除其 fresh profile；guard/adapter不接管未知 controller 的 profile cleanup。

本 IPC 模式不开 socket，不改全局 firewall、系统代理、DNS、路由，不启 TUN、不关闭浏览器 sandbox、不使用真实节点凭证。若私有祖先目录导致 AC loader/访问失败，应保留失败；不可自动放宽更高父目录 ACL。

本机没有销毁 VM 的兜底。guard 的 KOC 能约束 Job 进程生命周期，不能证明 profile/ACE 已移除。missing report、held exit 未知、Close/ACL readback 不确定时保留 fresh 私有树并报告 `recovery_required=true`，等待依据精确 ownership/config/profile journals 的人工检查；不重试消耗过的裸 handle、不按名字杀进程、不删除仍可能被活进程引用的 profile/tree。已绑定 echo/EOF 等正向仍保留，最终状态继续 inconclusive。

成功也保留私有树供本机审计，`tree_retained=true` 与 `recovery_required=false` 可以同时成立；这不是资源清理失败的伪装。报告是否清理的是 held processes/Jobs/handles、精确 AC ACE/profile，私有证据文件保留是显式契约。

`.gitignore` 的 `local-ac-*/` 覆盖默认和允许的 checkout 子目录中的 fresh stage，`private/` 覆盖私有原计划。它们包含 raw nonce、SID、设备绑定、原生报告和路径，不得提交或公开。Git ignore 不替代 DACL、授权或审阅暂存区；公开只保存经闭合 validator 的 JSON 和源码/hash。

## Python profile 与验证证据

本机观察工具链的 Python 3.12.10 记录在独立 local profile `local-guard-worker-zero-cap-pipe-v1` 及公开 `python_version` 中。它不是 CI pinned CPython 3.14.8 embed 资格，不继承 CI host/VM qualification，也不证明 pinned MXC/PSEC backend 可用。ordinary controller 不使用 admin/linked-token fallback；原 PSEC `Stage0=false` 和 `product_acceptance=false` 历史保持。

纯测试使用 fake Win32、fake QPC 与临时 fixture 文件，不创建真实 native actor、AppContainer profile/ACE，不测网络。最终结果和受测新文件 SHA256 见 [local-owner-pure-tests.json](../../verification/windows-2026-10-22/local-owner-pure-tests.json)。该记录区分早先完整 25 项、随后 3/7 项定向修订验证与最终源码上的完整重跑；只能按各记录的源身份解释。

覆盖重点包括 creation-time JOB_LIST 无事后 assign fallback、Job handle 不继承、既有同名 Job 不修改、held worker 报告绑定、exact guardian query close 先于 guest setup、wrong membership/breakaway/unknown close 不执行 guest、Droot/Dworker 不续期、setup 用尽预算不创建 worker、私有 DACL 原子创建/回读、计划变化拒绝、闭合公开 schema 与失败后 sticky positives/recovery。

Windows 契约参考：[UpdateProcThreadAttribute / JOB_LIST](https://learn.microsoft.com/en-us/windows/win32/api/processthreadsapi/nf-processthreadsapi-updateprocthreadattribute)、[Nested jobs](https://learn.microsoft.com/en-us/windows/win32/procthread/nested-jobs)、[Job objects](https://learn.microsoft.com/en-us/windows/win32/procthread/job-objects)。这些 API 契约与 mock 测试不能代替目标设备的真实机制运行。
