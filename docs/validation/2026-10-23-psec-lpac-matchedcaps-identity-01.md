# PSEC + LPAC matchedcaps01：相同 SC 输入完成创建，LPAC 首项 mask 仍不符

**本轮仍为 `inconclusive / accesscheck`。** 同一个 CPSE 先创建始终 suspended 的 bootstrap，外部 owner 从 held primary token 取得实际 AppContainer SID 与精确两项 enabled capability，再将同一份 SECURITY_CAPABILITIES（SC）输入用于 AC、LPAC 两测量臂。三个进程均完成创建、各一次 inner Job assignment、后置双 Job 与 primary 身份准入。AC 四项 AccessCheck 为 `[3,0,1,2]`；LPAC 原件只执行 `combined` 一项，API成功、AccessStatus=true、GrantedAccess=3、PrivilegeCount=0，预期应为2，因 `mask` 停止。`world/aap/arap` 没有执行，**完整 LPAC 向量为null，不能补成任何矩阵**。

这是独立 scope `one-local-cpse-deny-all-outer-guarded-matched-secaps-identity-v1`，constructor policy 为 `bootstrap-held-primary-matched-security-capabilities-aap-only-v1`。受测提交 `ec45dffb66cc88bb48578101afb93ce7044a6521`，36文件运行闭包 `f77fdff1de75ba53d6dca04d65659deb43fd6bdc91c2feaf1c6a03ade7c008db`。[原 public](../../verification/windows-2026-10-22/psec-lpac-matchedcaps-identity-local-01-public.json)为2658字节，SHA256 `6acc10b614f5c35c56ed2adf4e648a7b0f4ea3a74ddbdf3f3e7fb595c9a103b4`；[证据索引](../../verification/windows-2026-10-22/psec-lpac-matchedcaps-identity-local-01-evidence-index.json)绑定16份原始文件和安全投影。

## 三个 held 角色与相同 SC 输入

bootstrap 只声明 SE_ENV 与 AAP0，不传 SC。外部 owner 核对其 held generation、image/hash、精确 outer/inner Job、同user/session、primary/低IL4096、非elevated/非UIAccess，以及当前OS固定 catalog 的 AgenticAppContainer、privateNetworkClientServer 两项 capability，attributes均为4。第一次实际 held AppContainer SID固定后，后续两臂必须相等；不是由 actor 自报身份。

bootstrap 的 primary、原PI返回收据、held Job收据、原source/config/F/D绑定到物理 `held-bootstrap` SC收据。Python将 SID规范二进制和精确attributes构成指针无关摘要；ABI3的64字节输入仅借用调用期buffer，native在构造属性前复制SID字节，第二测量臂再逐字节比较。AC、LPAC 使用同一 actor、CPSE、spec、环境、SC和端点目录，声明的差异只有AAP0/1；每次测量臂Create与primary观察前重新核bootstrap，observer前后再核全部三个held角色。

本次两个 measured CreateProcess 均返回成功且PI完整，外部身份和相同SC输入绑定通过。这仅证明本轮构造调用和所记录身份事实；**不证明每项策略语义均被执行，不证明SC保留PSEC的网络/文件系统关联，也不确定LPAC mask不符的具体原因**。不能据此断言全部属性被忽略，或断言某一属性是唯一原因。`psec_network_preservation_proven` 在原public与各投影中始终为false。

[SC安全投影](../../verification/windows-2026-10-22/psec-lpac-matchedcaps-identity-local-01-security-capabilities-projection.json)只公开catalog符号、字节数、SHA和关联核验布尔，不公开SID或原SC字节。[转移投影](../../verification/windows-2026-10-22/psec-lpac-matchedcaps-identity-local-01-inner-transfers-projection.json)记录3个outer-only前门及3次原BOOL1、立即error0、及时的一次assignment；[后置Job投影](../../verification/windows-2026-10-22/psec-lpac-matchedcaps-identity-local-01-job-admissions-projection.json)记录24次精确双Job通过（bootstrap11、AC7、LPAC6）。9份pretransfer/assignment物理收据、24份后置Job物理收据均独立绑定，临时query句柄单次关闭且无protected alias。API成功与membership值分别保留。

[组件投影](../../verification/windows-2026-10-22/psec-lpac-matchedcaps-identity-local-01-component-projection.json)保留7份native返回、10份调用者意图、三角色准入和两个proof。AC有4个真实调用且qualified=true；LPAC仅1个真实调用、qualified=false、observed_matrix=null、failure=mask。不是访问被拒绝或Win32错误，未调用的后三项不提供任何观测结论。

## 已知清理与历史边界

ordinary worker自然退出0；三个held actor在从未Resume的状态下被清理，held exit1确认。forensic原字节等于有效worker result；外层held worker、原source/device/artifact/spec/plan、原root120/worker115及物理收据重投影均核对。已知child、Job、句柄、observer和query资源清理闭合；VOID close消费一次并正常返回，unbind完成。本轮recovery_required=false、broker_outcome_unknown=false不证明external absence、broker cancellation或worker死亡后的等价清理。

`atomic_inner_creation_proven`、`continuous_outer_supervision_proven`、`creation_transfer_crash_gap_resolved` 始终为false。有限的前后Job观察不能证明整个创建和交接期间连续监督。全部三个actor始终suspended，没有Resume、GO、DNS、网络或代理测试。

[postassign01](2026-10-23-psec-lpac-postassign-identity-01.md)继续保留其两臂无SC输入、13次后置Job和LPAC首项grant3的原结果；[atomic03](2026-10-23-psec-lpac-identity-03.md)仍是inner=false、outer=true，[atomic02](2026-10-23-psec-lpac-identity-02.md)仍保留未分离which-Job的历史。[atomic01](2026-10-23-psec-lpac-identity-01.md)的原unknown/recovery要求不由本轮正常清理消除，不重放或补造旧opaque close。

## 源码、编译、纯测试和CI

[source-review索引](../../verification/windows-2026-10-22/psec-lpac-matchedcaps-identity-source-review-01/index.json)保存nativefreeze01、源码patch/ABI、Python初始False候选01/02、原纯日志、独审以及根明确授权的True promotion03。promotion只改ACTUAL_READY标记，独立CLI opt-in与source/device/spec/plan/held guard门均保留。初始候选01测试中的late状态分类随后对齐native typed10；02保留late=10且within_deadline=false，不是重跑实际实验。typed10明确表示Create前属性准备失败，不伪造Create API entry或进程exit。

本轮只新增8个源码/测试文件：3个native文件、2个Python模块、3个测试文件。runtime36是34共享文件加2新模块；native37是6source加31dependency，其中3个新native替换本scope对应输入，旧scope源码不动。x64 `/MT` DLL为217088字节，SHA256 `91e9fdc092943ac3a3b47c9f5ad394f4aacb522d105aa802c47b74d5c4f702b1`，library ABI3、payload V1，manifest闭合15键，静态imports仅KERNEL32、8exports。构建和静态源码审查与实际运行分开；根运行前核查driver，另存独立file-only driver复核，不将这些资料替代实际记录。

Python作者False02纯测试30项、11.789秒、零失败/零skip；另3个native测试在根全量中实际执行，其中154条role/state和100条SC检查合计254条compiled checks。**254是断言检查数，不是254个新增测试**；全量955来自旧922加30个Python方法和3个native测试。根本机全量955项、83.640秒、零失败、2个原有symlink权限skip；没有本机Linux实跑。各独立窄审和归档器的6项file/fake检查另列，不累加为产品测试或机制成功。

首次file-only审计器reader01因旧DNS public的product_acceptance位于`result`而非top层发生schema失配，停止且未输出审计收据。原reader和失败副本保持；新reader02仅按各历史source闭合schema读取field位置，明确保留present/value、缺失为null，5项synthetic pure通过后根重新运行文件审计成功。这不是native/身份实验失败，不改变任何原public、实际source或私有原件，也没有重跑实际实验。

[受测源码自动CI](https://github.com/Shermanxwz/Rule-proxy-Web/actions/runs/39885821454)为run39885821454 / job120193628680，completed/success：955项、76.405秒、零失败/零skip；5–9号gated runtime步骤跳过，只有compile/pure证据，无dispatch/rerun或CI实际隔离验收。原decoded日志228205字节、SHA256 `5f3f4413c8c45bbdaea90becfe18024ef6ddf58db07b090474ed48ea91d60539`，是UTF-8 BOM/CRLF文本，非raw ZIP；公开脱敏视图与原件分别记录SHA和转换。

before/after四对象快照各7378字节、SHA256 `f05d91ee76ee8a97ae5ab3bfa092167a8ee560c083255f142e6c453f2edf7ab3`，与初始baseline原字节相同。范围仅firewall profiles、DNS、routes、user proxy，不含NRPT，不证明持续或全面absence。

本scope仍是独立identity-only-deny-all-v1，无proxy/peer，不是既有Model2代理策略的相同配置比较。[standalone semantic-LPAC DNS02](2026-10-23-lpac-semantic-dns-02.md)的API/query5/5与前后控制保留；[原G/PSEC显式DNS API泄漏](2026-10-23-selected-dns-standard53.md)仍成立。`network_tested / dns_tested / proxy_tested / product_acceptance / model2_policy_compared / psec_network_preservation_proven / linux_equivalence_proven` 均为false，项目应用级代理隔离尚未完成。
