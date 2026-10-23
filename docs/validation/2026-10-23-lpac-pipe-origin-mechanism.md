# 零能力 LPAC 经继承管道访问受持有普通 origin：有限机制实验

本轮结论：**有限合作原生链路完成**。原始状态为 `observed`，失败字段为 `None`；恢复要求为 `False`。这次实验只评估合作原生请求生成器、两个继承管道端点、普通转发进程及独立普通 origin 的固定映射，项目和 Linux 等效资格仍为 false。

**重要限制：routes 前后不一致。** 原50条路由保留，新增2条 IPv6 /128 路由；其他三个记录对象相同。原始 after 快照为7645字节，SHA256 `96ba4618bdcee58d28de676038b661681b955502799cdce7aae5fa24d61e8f95`，不能改写为此前7378字节快照。快照未标识写入者和发生时刻，新增路由暂不能归因于实验或后台变化；本轮作用域资源清理闭合不证明全局配置未变。见[精确差异安全投影](../../verification/windows-2026-10-22/lpac-pipe-origin-actual-01/route-difference-review.json)。

后续独立只读查询中，每条新增路由都匹配一个当前本地 IPv6 地址，属性为 PrefixOrigin=RouterAdvertisement、SuffixOrigin=Random、Preferred、Unicast。已安装 Windows SDK `shared/nldef.h` 的数值定义是 `RouteProtocolLocal=2`。这些是当前属性/数值锚点，不是写入者或创建时间的追踪证据，不能据此唯一归因或回写原 after 快照；没有删除这些路由。见[地址属性投影](../../verification/windows-2026-10-22/lpac-pipe-origin-actual-01/route-address-followup.json)及[SDK 锚点](../../verification/windows-2026-10-22/lpac-pipe-origin-actual-01/route-protocol-SDK-anchor.json)。

实际受测提交为 [`42064e8cbfc3263cb1352f923ab8e269d490b078`](https://github.com/Shermanxwz/Rule-proxy-Web/commit/42064e8cbfc3263cb1352f923ab8e269d490b078)，40 文件源码闭包 SHA256 为 `d136e22b2dfbdb991cfbef06d5dd7a54d687135bedbff653ada5e4d01ab88a61`。结果来自本机原件与独立只读重验，[实际安全汇总](../../verification/windows-2026-10-22/lpac-pipe-origin-actual-01/summary.json)和[原始公报](../../verification/windows-2026-10-22/lpac-pipe-origin-local-01-public.json)分别保留。

selected 的外部持有主令牌要求 fresh profile SID、能力列表精确为空、低完整性、同一普通用户/session，并在原 inner/outer Job 中；不查询 class46。四固定描述符的 AccessCheck 矩阵为 `[2, 0, 0, 2]（完整且合格）`。自述 token 报告不能替代外部身份和资源闭合证据。

实际闭合观测为：selected 管道 read=96、write=144 字节，read/write 帧数=2/3，EOF=True；普通 relay 的真实 request/response=95/90 字节；三个 held actor 已观测退出码=[0, 0, 0]，workload_stop=False，native 交叉 tuple 绑定=True。 这些字节数是受源码/held 身份绑定的原生报告观测，不是逐包抓包记录；选定 actor 没有获得 socket 或协议复制信息。10项作用域清理门和外层原报告闭合都由独立读取器复核，不能用这一点抹去 routes 差异。

新 selected 可执行文件的静态直接导入只有 KERNEL32/ADVAPI32，未编入 B 的 Winsock 转发单元。selected 生成并检查固定请求/sink，48 字节 RPB1 帧不传任意 HTTP 字节；真实 socket 仅由独立普通 relay 和 origin 持有。它们的端口关系是两个受持有原生报告的交叉绑定，不是独立的实时内核 TCP 表观测。selected socket、DNS、任意应用适配器、浏览器集成、恶意同 SID 认证、PSEC 网络保留、全部协议隔离、Linux 等效及产品验收均不因此成立。

原 root120 秒、worker115 秒与 pair10 秒使用同一个 QPC 域；pair 创建、身份/矩阵、关闭父端、Resume、协议、三个正常退出均消耗原 pair 区间。父进程必须一次关闭全部四个数据端，任一不确定都禁止 pair Resume。只有成功且完整非 alias 的创建输出提供句柄清理权限；失败 CreatePipe 即使输出看似双0也保留分配未知，不盲关原始数值。成功但晚归的进程仍保留清理责任，不取得准入资格。

清理先确认所有已知 workload 退出、Job 空及句柄/observer 闭合，再恢复唯一 selected-report 子树的 mandatory-label ACE absence 并读回，撤销该 profile 精确 ACE 并读回，闭合清理工具后删除 fresh profile、释放 SID。只声明该 label ACE 缺省恢复，不声明整个原 SACL 字节恢复。四个已记录全局对象的前后比较为 `{'dns': True, 'firewall_profiles': True, 'routes': False, 'user_proxy': True}`；范围限 firewall profiles、DNS、routes、user proxy，不扩张成全部机器配置或历史 broker 取消证明。

开发失败历史保留：[source-review 索引](../../verification/windows-2026-10-22/lpac-pipe-origin-source-review-01/index.json)。False01 的31项纯测之后，独审发现9类仍可被错误接受的报告变异；False02 的32项纯测后又发现退出因果门缺口，两版都 BLOCKED，均未作为可运行版本。False03 的33项纯测和独立修订审查通过。首次 driver 输入校验又因清单 BOM 停在创建 actor 前；False04 只修一次 BOM 解析并保留原始清单哈希。源提交 bf4dcc 的自动 CI 在未规范化测试临时根的 containment 门得到 GateFailure；路径 alias/case 的解释是推论，日志没有记录实际临时根别名，不能认作唯一根因。False05 仅规范化测试临时根并断言精确 readiness 错误，生产路径边界不变。此前 PowerShell 整套测试 wrapper 把正常 unittest stderr 当错误中断、留下0字节日志，属于 harness 中断，不能写成测试断言失败。所有原件、修订 patch、纯测日志承诺和独审结论均留存。

本轮整套纯测由独立提供的冻结收据记录：`lpac-pipe-origin-integrated-suite-receipt-03.json`（SHA256 `c21a924967811dff17b04f1ceac4c89843419e84389f182be278a9ae3ad125cb`）：1062项，157.802秒，0失败、2项既有 Windows symlink skip。纯测/compile-only/static PE 和本机 runtime 是不同证据。[本轮自动 CI](https://github.com/Shermanxwz/Rule-proxy-Web/actions/runs/39910769791) 也完成1062项/190.980秒/0skip，runtime步骤5–9全部skipped；不把它当本机运行或隔离验收。

B 普通程序复用既有 compile03 原 executable/manifest 与旧公开 compile 记录，五个当前源码 pin 可核；该旧目录没有原始 src snapshot，未补造“原始构建输入”。新 selected 有独立的四源 precompile snapshot 和9键 manifest，两份 artifact 不混用。

原 atomic01 的未知/recovery 状态、G/PSEC DNS 泄漏以及零能力/registryRead loopback 的既有失败记录保留原值，本轮清理不能覆盖它们。失败、超时、坏报告、未连接或缺失收据都不构成 selected 网络拒绝证明。
