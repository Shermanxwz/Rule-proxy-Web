"""File-only matchedcaps01 publication preparation; --publish is root-only.

Default validates and plans without writing repository or outputs. No native,
API, experiment, network, source implementation or recovery entry is imported.
"""
from __future__ import annotations
import argparse
import copy
import hashlib
import json
import os
from pathlib import Path
import re
import stat

BASE=Path(__file__).resolve().parent
REPO=BASE/'Rule-proxy-Web'
OUT=REPO/'verification/windows-2026-10-22'
OUTPUT=BASE.parent/'outputs/windows-isolation-progress.json'
FOLDER=OUT/'psec-lpac-matchedcaps-identity-source-review-01'
COMMIT='ec45dffb66cc88bb48578101afb93ce7044a6521'
CLOSURE='f77fdff1de75ba53d6dca04d65659deb43fd6bdc91c2feaf1c6a03ade7c008db'
PUBLIC_BYTES=2658
PUBLIC_SHA='6acc10b614f5c35c56ed2adf4e648a7b0f4ea3a74ddbdf3f3e7fb595c9a103b4'
SCOPE='one-local-cpse-deny-all-outer-guarded-matched-secaps-identity-v1'
POLICY='bootstrap-held-primary-matched-security-capabilities-aap-only-v1'
INPUTS={'psec-lpac-matchedcaps-native-freeze-01.json': {'public_name': 'native-freeze01.json', 'bytes': 13151, 'sha256': '7e702eac67a463682878c9d40ee1d8665d30a2f596a9ebf1edf1b2801de3fc1f'}, 'psec-lpac-matchedcaps-native-01.patch': {'public_name': 'native01.patch', 'bytes': 41278, 'sha256': '2a6d13cfb1f99b4e100ac41d4586ae5ccc18adf1e6261e42314855b381d12b44'}, 'psec-lpac-matchedcaps-native-diff-01.txt': {'public_name': 'native01-diff.txt', 'bytes': 17409, 'sha256': 'c3d154907ceba1e302358569a18fa964a1068c5b1467018caadd794bcaa296b9'}, 'psec-lpac-matchedcaps-native-abi-01.json': {'public_name': 'native-abi01.json', 'bytes': 5533, 'sha256': '27a6206495831269c207242f07a589591ee23a3594335e0edf18d9efff62ecce'}, 'psec-lpac-matchedcaps-native-independent-review-01.json': {'public_name': 'native-independent-review.json', 'bytes': 5557, 'sha256': 'fc1a72f40e98a4dd70ba99832e2f3a131c89da5b1262403e91c967a521e4e878'}, 'compile_psec_lpac_matchedcaps_bridge_01.ps1': {'public_name': 'compile01.ps1', 'bytes': 5004, 'sha256': '196ab8c0d7ac2eecce845cf533146d6978dc43387ddb83439da46547b147f0a5'}, 'inspect_psec_lpac_matchedcaps_bridge_compile_01.py': {'public_name': 'compile-static-inspect.py', 'bytes': 7983, 'sha256': 'c6b0de07555906d5d4c802c0dace04257ae8c9f2d99f0097135f9403adb3d043'}, 'review_psec_lpac_matchedcaps_compile_01.py': {'public_name': 'compile-independent-reader.py', 'bytes': 13261, 'sha256': '03bee4608dbe83b0d51506af555aa0a332f60ed6c119c5898dae5dfda4c13a76'}, 'psec-lpac-matchedcaps-compile-independent-review-01.json': {'public_name': 'compile-independent-review.json', 'bytes': 20599, 'sha256': 'e611aff79dc2fb26992e8fa78862509612cb704f4f2cec48c1a08bfe8b6068c7'}, 'psec-lpac-matchedcaps-bridge-compile-01/static-pe-review.json': {'public_name': 'static-pe-review.json', 'bytes': 2153, 'sha256': '2b8c3d42d89fa6305357b3af638abe47349c76b6445f6321ad7368a3c7ad76e5'}, 'psec-lpac-matchedcaps-bridge-compile-01/toolchain.json': {'public_name': 'toolchain.json', 'bytes': 344, 'sha256': '796cd755464544645ce142c58d8dbfc113ff301034803dd4705d17894f47bb07'}, 'test_psec_lpac_matchedcaps_native_01.ps1': {'public_name': 'native-pure-driver.ps1', 'bytes': 2603, 'sha256': '6ea019386463abefc54e5fc5f1a9ace3aec41830da6b48810e5d717d7304f6df'}, 'psec-lpac-matchedcaps-python-candidate-01.patch': {'public_name': 'python-false01.patch', 'bytes': 168517, 'sha256': 'ed31150d96a1d9938bba1f17355975065dc025a51e683c9c6b93b3c4b38006f9'}, 'psec-lpac-matchedcaps-python-candidate-freeze-01.json': {'public_name': 'python-false-freeze01.json', 'bytes': 9463, 'sha256': '51ec283dd66cfa762dcf1b7e2eeffc204e18280b4005dd0b0af3ca4a4423825d'}, 'psec-lpac-matchedcaps-python-candidate-abi-01.json': {'public_name': 'python-false-abi01.json', 'bytes': 2509, 'sha256': '7a9d2c54bae6b1f006d4c0e18ec8c7c44a0e2ebca1479899c1b5ad7024a5322e'}, 'psec-lpac-matchedcaps-python-pure-01.log': {'public_name': 'python-false01-pure.log', 'bytes': 6829, 'sha256': '313f3760950f64b6d5340bdb998e6bdee86ba7f2d1371a8f636c63dab98ae610'}, 'psec-lpac-matchedcaps-python-candidate-02.patch': {'public_name': 'python-false02.patch', 'bytes': 168653, 'sha256': '286b18f7f64442127f296c900c1c320855dbd951a09edb1907f4ba26ef3f3315'}, 'psec-lpac-matchedcaps-python-candidate-freeze-02.json': {'public_name': 'python-false-freeze02.json', 'bytes': 9463, 'sha256': '3d5ac7715ee8effdc7a9e816defba096892ce33a3e5027aea8ed6654580268b8'}, 'psec-lpac-matchedcaps-python-candidate-abi-02.json': {'public_name': 'python-false-abi02.json', 'bytes': 2509, 'sha256': '7a9d2c54bae6b1f006d4c0e18ec8c7c44a0e2ebca1479899c1b5ad7024a5322e'}, 'psec-lpac-matchedcaps-python-pure-02.log': {'public_name': 'python-false02-pure.log', 'bytes': 6829, 'sha256': 'f07dc8979d255359a9521867ee836a6e6f3b2a6b748ce313f6535e1395e3b7ff'}, 'psec-lpac-matchedcaps-python-candidate-03.patch': {'public_name': 'python-true03.patch', 'bytes': 168016, 'sha256': 'c8f035b29d19de1a22eb1c87dc7ac6ae33003fd0471f9a538bf56621cb7a1685'}, 'psec-lpac-matchedcaps-python-candidate-freeze-03.json': {'public_name': 'python-true-freeze03.json', 'bytes': 15023, 'sha256': 'dfdfcf9a9afd67fc9f15e0a252fdfcd672f3bcfd07417ba3a23e259a4537e762'}, 'promote_psec_lpac_matchedcaps_source_03.py': {'public_name': 'promotion03.py', 'bytes': 5788, 'sha256': 'd70a78604ca3b6c49d3d4b62b0c91ce4f781bb6a5b7b29b81909819572377d4e'}, 'psec-lpac-matchedcaps-python-independent-review-02.json': {'public_name': 'python-independent-review02.json', 'bytes': 5667, 'sha256': 'edd3c3a63b406e7bdbd45ef906b5e97d0bf776a057e4f6e562546c47807d8d79'}, 'psec-lpac-matchedcaps-python-abi-independent-review-02.json': {'public_name': 'python-abi-independent-review02.json', 'bytes': 3896, 'sha256': 'd7d383044da861825aef7677d9801d52b0f09e44253f57be5d90a6dd0e3bd6a8'}, 'psec-lpac-matchedcaps-python-independent-pure-02.log': {'public_name': 'python-abi-independent-pure02.log', 'bytes': 484, 'sha256': 'a1731af7d729d84256fb26c5d454375a9e5895544e9ad2b663cc8a334e65d003'}, 'psec-lpac-matchedcaps-source-closure-independent-review-02.json': {'public_name': 'source-closure-independent-review02.json', 'bytes': 25987, 'sha256': '2a428287c002adf43f2f45331e09ab1fa0f6f421f752d7bd19d6071e6088292a'}, 'psec-lpac-matchedcaps-integrated-pure-01.json': {'public_name': 'integrated-pure01.json', 'bytes': 3379, 'sha256': 'e778f2fe7883fbd57349fb65c948b88b3481b0064d7537769b996caca315f15c'}, 'psec-lpac-matchedcaps-main-pure-01.log': {'public_name': 'integrated-pure01.log', 'bytes': 179734, 'sha256': 'a573b78178d9afd550026a9a85db817d9f7781583568d8fac2e3f2b19e06af3c'}, 'test_psec_lpac_matchedcaps_integrated_01.ps1': {'public_name': 'integrated-pure-driver01.ps1', 'bytes': 884, 'sha256': '92fa6684498e66dac617877871a831580535833f932ff35245bfa77731931031'}, 'stage_psec_lpac_matchedcaps_source_03.py': {'public_name': 'source-stager03.py', 'bytes': 4610, 'sha256': 'a54159c83212667e28e962d97cdb6bff22dfc07e08a3c26d754860da01b1cede'}, 'review_psec_lpac_matchedcaps_driver_01.py': {'public_name': 'actual-driver-reviewer.py', 'bytes': 6273, 'sha256': 'ed6824a2ecef41f5a95237154ec747c7c39622a6bc9bffd578f8543f16b5d65e'}, 'psec-lpac-matchedcaps-driver-independent-review-01.json': {'public_name': 'actual-driver-independent-review.json', 'bytes': 2300, 'sha256': '740ca19e31e0232e07d00a74534ac0b12023352615396416333f389aab034a1c'}, 'verify_psec_lpac_matchedcaps_actual_01.py': {'public_name': 'actual-reader01.py', 'bytes': 38801, 'sha256': '0621557f94e4fcae0e59bf320f7be63a810917a7afb88965afb7688be995c515'}, 'verify_psec_lpac_matchedcaps_actual_01_failed-reader-01.py': {'public_name': 'actual-reader01-failed-copy.py', 'bytes': 38801, 'sha256': '0621557f94e4fcae0e59bf320f7be63a810917a7afb88965afb7688be995c515'}, 'verify_psec_lpac_matchedcaps_actual_01_reader02.py': {'public_name': 'actual-reader02.py', 'bytes': 39820, 'sha256': '5d8fc85cf1a0dff4ece5b6f2bea66fcde712f5fd5b604c496368f964231b06b4'}, 'psec-lpac-matchedcaps-file-reader02.diff': {'public_name': 'actual-reader02.diff', 'bytes': 2421, 'sha256': '7eab2b2541821124680737cf2ebae57e62aaa8f8d8503ff9073eba1a8df2c5f1'}, 'psec-lpac-matchedcaps-file-reader-freeze-02.json': {'public_name': 'actual-reader-freeze02.json', 'bytes': 2348, 'sha256': 'bf3a7c5f7e88c98802d8306881d34f45fa0ce4c16bc1fb1d6d2a7cdc8e37293c'}, 'psec-lpac-matchedcaps-file-reader02-pure.log': {'public_name': 'actual-reader02-pure.log', 'bytes': 976, 'sha256': '293b2374e45b6633b0c7503a4c1a385ba1f447511583541dd5219e667bffa7b9'}, 'test_matchedcaps_file_reader02.py': {'public_name': 'actual-reader02-pure.py', 'bytes': 2665, 'sha256': '0dde17ca098d1fdb2ea5dd7755bb41db38740663725685632da443fd613ea6c9'}, 'psec-lpac-matchedcaps-identity-actual-01-independent-review.json': {'public_name': 'actual-independent-review.json', 'bytes': 83295, 'sha256': 'cbb62758368cb3e3e67ba6bd96619f2774c9c179e0d11ca2d771cc6032a45f52'}, 'psec-lpac-matchedcaps-actual-01-extra-raw-review.json': {'public_name': 'actual-extra-raw-review.json', 'bytes': 23616, 'sha256': '5eb82868d9f6d58a3fd591dd4dd6e601635f83b645287dcab3c268d802206dbb'}, 'archive_psec_lpac_matchedcaps_identity_01_readiness.json': {'public_name': 'archive-readiness.json', 'bytes': 6200, 'sha256': '5371dd848b53386970f20e00bc3734f786a627d81f48f730c7f193afdc42f784'}, 'archive_psec_lpac_matchedcaps_identity_01_preactual.py': {'public_name': 'archive-preactual.py', 'bytes': 77703, 'sha256': 'e706d82ce56dacd8361edc65158a476694d10f1ae64d50b58879cc26823fe65a'}, 'psec-lpac-matchedcaps-archive-reader-preactual-01.json': {'public_name': 'archive-preactual-receipt.json', 'bytes': 2100, 'sha256': 'e76e24f59f5e22b6641ec499e2d8bc51e97ae3e19d98d8195c37b4cfd3145d07'}, 'test_archive_psec_lpac_matchedcaps_identity_01.py': {'public_name': 'archive-pure.py', 'bytes': 6562, 'sha256': 'b4ff1a6ebc76c3c7f58f6a8042e13282dc8af33a2f4fc4b318c9eead54f07a58'}, 'ci-psec-matchedcaps-identity-39885821454-full.txt': {'public_name': 'automatic-ci-decoded.log', 'bytes': 228205, 'sha256': '5f3f4413c8c45bbdaea90becfe18024ef6ddf58db07b090474ed48ea91d60539'}}
DOCUMENT='# PSEC + LPAC matchedcaps01：相同 SC 输入完成创建，LPAC 首项 mask 仍不符\n\n**本轮仍为 `inconclusive / accesscheck`。** 同一个 CPSE 先创建始终 suspended 的 bootstrap，外部 owner 从 held primary token 取得实际 AppContainer SID 与精确两项 enabled capability，再将同一份 SECURITY_CAPABILITIES（SC）输入用于 AC、LPAC 两测量臂。三个进程均完成创建、各一次 inner Job assignment、后置双 Job 与 primary 身份准入。AC 四项 AccessCheck 为 `[3,0,1,2]`；LPAC 原件只执行 `combined` 一项，API成功、AccessStatus=true、GrantedAccess=3、PrivilegeCount=0，预期应为2，因 `mask` 停止。`world/aap/arap` 没有执行，**完整 LPAC 向量为null，不能补成任何矩阵**。\n\n这是独立 scope `one-local-cpse-deny-all-outer-guarded-matched-secaps-identity-v1`，constructor policy 为 `bootstrap-held-primary-matched-security-capabilities-aap-only-v1`。受测提交 `ec45dffb66cc88bb48578101afb93ce7044a6521`，36文件运行闭包 `f77fdff1de75ba53d6dca04d65659deb43fd6bdc91c2feaf1c6a03ade7c008db`。[原 public](../../verification/windows-2026-10-22/psec-lpac-matchedcaps-identity-local-01-public.json)为2658字节，SHA256 `6acc10b614f5c35c56ed2adf4e648a7b0f4ea3a74ddbdf3f3e7fb595c9a103b4`；[证据索引](../../verification/windows-2026-10-22/psec-lpac-matchedcaps-identity-local-01-evidence-index.json)绑定16份原始文件和安全投影。\n\n## 三个 held 角色与相同 SC 输入\n\nbootstrap 只声明 SE_ENV 与 AAP0，不传 SC。外部 owner 核对其 held generation、image/hash、精确 outer/inner Job、同user/session、primary/低IL4096、非elevated/非UIAccess，以及当前OS固定 catalog 的 AgenticAppContainer、privateNetworkClientServer 两项 capability，attributes均为4。第一次实际 held AppContainer SID固定后，后续两臂必须相等；不是由 actor 自报身份。\n\nbootstrap 的 primary、原PI返回收据、held Job收据、原source/config/F/D绑定到物理 `held-bootstrap` SC收据。Python将 SID规范二进制和精确attributes构成指针无关摘要；ABI3的64字节输入仅借用调用期buffer，native在构造属性前复制SID字节，第二测量臂再逐字节比较。AC、LPAC 使用同一 actor、CPSE、spec、环境、SC和端点目录，声明的差异只有AAP0/1；每次测量臂Create与primary观察前重新核bootstrap，observer前后再核全部三个held角色。\n\n本次两个 measured CreateProcess 均返回成功且PI完整，外部身份和相同SC输入绑定通过。这仅证明本轮构造调用和所记录身份事实；**不证明每项策略语义均被执行，不证明SC保留PSEC的网络/文件系统关联，也不确定LPAC mask不符的具体原因**。不能据此断言全部属性被忽略，或断言某一属性是唯一原因。`psec_network_preservation_proven` 在原public与各投影中始终为false。\n\n[SC安全投影](../../verification/windows-2026-10-22/psec-lpac-matchedcaps-identity-local-01-security-capabilities-projection.json)只公开catalog符号、字节数、SHA和关联核验布尔，不公开SID或原SC字节。[转移投影](../../verification/windows-2026-10-22/psec-lpac-matchedcaps-identity-local-01-inner-transfers-projection.json)记录3个outer-only前门及3次原BOOL1、立即error0、及时的一次assignment；[后置Job投影](../../verification/windows-2026-10-22/psec-lpac-matchedcaps-identity-local-01-job-admissions-projection.json)记录24次精确双Job通过（bootstrap11、AC7、LPAC6）。9份pretransfer/assignment物理收据、24份后置Job物理收据均独立绑定，临时query句柄单次关闭且无protected alias。API成功与membership值分别保留。\n\n[组件投影](../../verification/windows-2026-10-22/psec-lpac-matchedcaps-identity-local-01-component-projection.json)保留7份native返回、10份调用者意图、三角色准入和两个proof。AC有4个真实调用且qualified=true；LPAC仅1个真实调用、qualified=false、observed_matrix=null、failure=mask。不是访问被拒绝或Win32错误，未调用的后三项不提供任何观测结论。\n\n## 已知清理与历史边界\n\nordinary worker自然退出0；三个held actor在从未Resume的状态下被清理，held exit1确认。forensic原字节等于有效worker result；外层held worker、原source/device/artifact/spec/plan、原root120/worker115及物理收据重投影均核对。已知child、Job、句柄、observer和query资源清理闭合；VOID close消费一次并正常返回，unbind完成。本轮recovery_required=false、broker_outcome_unknown=false不证明external absence、broker cancellation或worker死亡后的等价清理。\n\n`atomic_inner_creation_proven`、`continuous_outer_supervision_proven`、`creation_transfer_crash_gap_resolved` 始终为false。有限的前后Job观察不能证明整个创建和交接期间连续监督。全部三个actor始终suspended，没有Resume、GO、DNS、网络或代理测试。\n\n[postassign01](2026-10-23-psec-lpac-postassign-identity-01.md)继续保留其两臂无SC输入、13次后置Job和LPAC首项grant3的原结果；[atomic03](2026-10-23-psec-lpac-identity-03.md)仍是inner=false、outer=true，[atomic02](2026-10-23-psec-lpac-identity-02.md)仍保留未分离which-Job的历史。[atomic01](2026-10-23-psec-lpac-identity-01.md)的原unknown/recovery要求不由本轮正常清理消除，不重放或补造旧opaque close。\n\n## 源码、编译、纯测试和CI\n\n[source-review索引](../../verification/windows-2026-10-22/psec-lpac-matchedcaps-identity-source-review-01/index.json)保存nativefreeze01、源码patch/ABI、Python初始False候选01/02、原纯日志、独审以及根明确授权的True promotion03。promotion只改ACTUAL_READY标记，独立CLI opt-in与source/device/spec/plan/held guard门均保留。初始候选01测试中的late状态分类随后对齐native typed10；02保留late=10且within_deadline=false，不是重跑实际实验。typed10明确表示Create前属性准备失败，不伪造Create API entry或进程exit。\n\n本轮只新增8个源码/测试文件：3个native文件、2个Python模块、3个测试文件。runtime36是34共享文件加2新模块；native37是6source加31dependency，其中3个新native替换本scope对应输入，旧scope源码不动。x64 `/MT` DLL为217088字节，SHA256 `91e9fdc092943ac3a3b47c9f5ad394f4aacb522d105aa802c47b74d5c4f702b1`，library ABI3、payload V1，manifest闭合15键，静态imports仅KERNEL32、8exports。构建和静态源码审查与实际运行分开；根运行前核查driver，另存独立file-only driver复核，不将这些资料替代实际记录。\n\nPython作者False02纯测试30项、11.789秒、零失败/零skip；另3个native测试在根全量中实际执行，其中154条role/state和100条SC检查合计254条compiled checks。**254是断言检查数，不是254个新增测试**；全量955来自旧922加30个Python方法和3个native测试。根本机全量955项、83.640秒、零失败、2个原有symlink权限skip；没有本机Linux实跑。各独立窄审和归档器的6项file/fake检查另列，不累加为产品测试或机制成功。\n\n首次file-only审计器reader01因旧DNS public的product_acceptance位于`result`而非top层发生schema失配，停止且未输出审计收据。原reader和失败副本保持；新reader02仅按各历史source闭合schema读取field位置，明确保留present/value、缺失为null，5项synthetic pure通过后根重新运行文件审计成功。这不是native/身份实验失败，不改变任何原public、实际source或私有原件，也没有重跑实际实验。\n\n[受测源码自动CI](https://github.com/Shermanxwz/Rule-proxy-Web/actions/runs/39885821454)为run39885821454 / job120193628680，completed/success：955项、76.405秒、零失败/零skip；5–9号gated runtime步骤跳过，只有compile/pure证据，无dispatch/rerun或CI实际隔离验收。原decoded日志228205字节、SHA256 `5f3f4413c8c45bbdaea90becfe18024ef6ddf58db07b090474ed48ea91d60539`，是UTF-8 BOM/CRLF文本，非raw ZIP；公开脱敏视图与原件分别记录SHA和转换。\n\nbefore/after四对象快照各7378字节、SHA256 `f05d91ee76ee8a97ae5ab3bfa092167a8ee560c083255f142e6c453f2edf7ab3`，与初始baseline原字节相同。范围仅firewall profiles、DNS、routes、user proxy，不含NRPT，不证明持续或全面absence。\n\n本scope仍是独立identity-only-deny-all-v1，无proxy/peer，不是既有Model2代理策略的相同配置比较。[standalone semantic-LPAC DNS02](2026-10-23-lpac-semantic-dns-02.md)的API/query5/5与前后控制保留；[原G/PSEC显式DNS API泄漏](2026-10-23-selected-dns-standard53.md)仍成立。`network_tested / dns_tested / proxy_tested / product_acceptance / model2_policy_compared / psec_network_preservation_proven / linux_equivalence_proven` 均为false，项目应用级代理隔离尚未完成。\n'
HANDOFF_PREFIX='**PSEC matchedcaps01（2026-10-23，新scope）**：[三held与相同SC输入实测](2026-10-23-psec-lpac-matchedcaps-identity-01.md)记录三次assignment、24次后置双Job和相同SC输入通过创建；AC四项通过，LPAC仅combined grant3（预期2）即停，后三项未执行，仍inconclusive/accesscheck。未Resume/网络测试，PSEC网络保留与Linux等价均未证明；旧unknown、postassign和DNS历史保留。\n\n'

def need(ok,label):
    if not ok:raise ValueError(label)

def sha(raw):return hashlib.sha256(raw).hexdigest()

def encode(value):return (json.dumps(value,sort_keys=True,indent=2,ensure_ascii=False,allow_nan=False)+'\n').encode('utf8')

def metadata(raw):return dict(bytes=len(raw),sha256=sha(raw))

def read(path,limit=2*1024*1024):
    path=Path(path).absolute()
    for part in (path,*path.parents):
        info=part.lstat();need(not stat.S_ISLNK(info.st_mode) and not getattr(info,'st_file_attributes',0)&0x400,'no_reparse_input')
    info=path.stat();need(stat.S_ISREG(info.st_mode) and 0<=info.st_size<=limit,'input_bound')
    raw=path.read_bytes();need(len(raw)==info.st_size,'stable_input');return raw

def decode(raw):
    def pairs(rows):
        value={}
        for key,item in rows:need(key not in value,'duplicate_json_key');value[key]=item
        return value
    return json.loads(raw,object_pairs_hook=pairs,parse_constant=lambda x:(_ for _ in ()).throw(ValueError('nonfinite_json')))

def repo_ref(path,raw):return dict(path=path.relative_to(REPO).as_posix(),**metadata(raw))

def public_text(raw):
    """A view may differ from private raw bytes; record every such change."""
    try:text=raw.decode('utf8');replacement_decode=False
    except UnicodeDecodeError:text=raw.decode('utf8',errors='replace');replacement_decode=True
    edits=[]
    if text.startswith('\ufeff'):text=text[1:];edits.append('utf8-bom-removed-in-public-view')
    if replacement_decode:edits.append('invalid-utf8-replaced-in-public-view')
    # Match both plain Windows paths and their JSON-escaped spelling.
    variants={str(BASE.parent),str(BASE.parent).replace('\\','/'),str(BASE.parent).replace('\\','\\\\')}
    for value in sorted(variants,key=len,reverse=True):
        if value in text:text=text.replace(value,'<workspace>');edits.append('absolute-workspace-prefix-redacted')
    text,count=re.subn(r'(?i)[A-Z]:[\\/]+Users[\\/]+[^\\/\s"\x27<>]+','<user-home>',text)
    if count:edits.append('absolute-user-home-prefix-redacted')
    if '\r' in text:text=text.replace('\r\n','\n').replace('\r','\n');edits.append('line-endings-normalized-to-lf')
    # No real account SID is admitted; tiny synthetic test fixtures are source.
    need(not re.search(r'\bS-1-5-21-\d{5,}-\d{5,}-\d{5,}-\d+\b',text,re.I),'possible_private_account_sid')
    need(not re.search(r'(?i)[A-Z]:[\\/]+Users[\\/]',''.join(text)),'remaining_absolute_user_path')
    data=text.encode('utf8');return data,sorted(set(edits))

def prepare():
    for name,pin in INPUTS.items():
        need(metadata(read(BASE/name))=={key:pin[key] for key in ('bytes','sha256')},'publication_input_pin')
    public_path=OUT/'psec-lpac-matchedcaps-identity-local-01-public.json';public_raw=read(public_path,8192);public=decode(public_raw)
    need(metadata(public_raw)==dict(bytes=PUBLIC_BYTES,sha256=PUBLIC_SHA) and public['scope']==SCOPE and public['constructor_policy']==POLICY
        and public['status']=='inconclusive' and public['failure']=='accesscheck' and public['checks']['worker_bound'] is True
        and public['observation_complete'] is public['recovery_required'] is public['broker_outcome_unknown'] is False,'original_matchedcaps_public')
    false_claims=('atomic_inner_creation_proven','continuous_outer_supervision_proven','creation_transfer_crash_gap_resolved',
        'psec_network_preservation_proven','linux_equivalence_proven','network_tested','dns_tested','proxy_tested','product_acceptance','model2_policy_compared')
    need(all(public[key] is False for key in false_claims),'original_unproven_claims_false')
    promoted=decode(read(BASE/'psec-lpac-matchedcaps-python-candidate-freeze-03.json'))
    false02=decode(read(BASE/'psec-lpac-matchedcaps-python-candidate-freeze-02.json'))
    false01=decode(read(BASE/'psec-lpac-matchedcaps-python-candidate-freeze-01.json'))
    native=decode(read(BASE/'psec-lpac-matchedcaps-native-freeze-01.json'))
    need(promoted['actual_ready'] is True and false02['actual_ready'] is false01['actual_ready'] is False
        and promoted['scope']==SCOPE and promoted['constructor_policy']==POLICY and promoted['runtime_source_count']==36
        and promoted['shared_runtime_count']==34 and promoted['source_sha256']==CLOSURE,'source_promotion_scope')
    need(promoted['new_test_method_count']==30 and promoted['new_native_test_method_count']==3
        and promoted['baseline_full_test_count']==922 and promoted['expected_full_test_count']==955
        and sum(promoted['all_new_test_method_counts'].values())==33,'source_test_count_not_assertions')
    canonical=(json.dumps(promoted['source_hashes'],sort_keys=True,separators=(',',':'),ensure_ascii=True)+'\n').encode('ascii')
    need(len(promoted['source_hashes'])==36 and sha(canonical)==CLOSURE and len(promoted['native_pins'])==37,'runtime_native_closure')
    for name,digest in promoted['source_hashes'].items():need(sha(read(REPO/name))==digest,'installed_runtime_frozen_bytes')
    for name,digest in promoted['native_pins'].items():need(sha(read(REPO/name))==digest,'installed_native_frozen_bytes')
    for name,row in promoted['files'].items():need(metadata(read(REPO/name))=={key:row[key] for key in ('bytes','sha256')},'installed_python_four')
    core='.github/windows_identity_psec_lpac_matchedcaps_bridge.py';core_raw=read(REPO/core)
    need(core_raw.count(b'ACTUAL_READY=True')==1 and metadata(core_raw.replace(b'ACTUAL_READY=True',b'ACTUAL_READY=False',1))==false02['files'][core]
        and all(promoted['files'][name]==row for name,row in false02['files'].items() if name!=core),'promotion_only_ready_literal')
    need(native['compile_input_count']==37 and native['native_source_count']==6 and native['dependency_count']==31
        and len(native['files'])==4 and native['actual_ready'] is False and native['old_inputs_verified_against_main'] is True,'native_frozen_scope')
    for name,row in native['files'].items():need(metadata(read(REPO/name))=={key:row[key] for key in ('bytes','sha256')},'native_three_and_test_exact')
    need(false02['pure']['tests']==30 and false02['pure']['seconds']=='11.789' and false02['pure']['exit_code']==0
        and false02['pure']['skip_count']==0,'author_false02_pure')
    need(re.findall(rb'Ran ([0-9]+) tests in ([0-9.]+)s',read(BASE/'psec-lpac-matchedcaps-python-pure-02.log'))==[(b'30',b'11.789')],'author_pure_log')
    independent=decode(read(BASE/'psec-lpac-matchedcaps-python-independent-review-02.json'))
    need(independent['decision']=='GO-for-root-review-and-separate-promotion-only' and independent['runtime_source_sha256']==false02['source_sha256']
        and len(independent['independent_checks'])==15 and independent['actual_ready'] is False,'independent_false_review')
    integrated=decode(read(BASE/'psec-lpac-matchedcaps-integrated-pure-01.json'));tests=integrated['tests']
    need(integrated['source_sha256']==CLOSURE and integrated['runtime_source_count']==36 and integrated['runtime_shared_count']==34
        and integrated['baseline_tests']==922 and integrated['new_python_tests']==30 and integrated['new_native_tests']==3
        and integrated['full_expected']==955 and integrated['native_compiled_assertions']==254
        and integrated['native_compiled_assertions_are_in_three_tests'] is integrated['old_327_assertions_not_added_as_new_tests'] is True
        and tests['tests']==955 and tests['seconds']==83.64 and tests['failures']==tests['errors']==0 and tests['skips']==2
        and tests['existing_symlink_skips'] is True and tests['linux_executed'] is False,'root_integrated955')
    need(metadata(read(BASE/'psec-lpac-matchedcaps-main-pure-01.log'))==dict(bytes=tests['log_bytes'],sha256=tests['log_sha256']),'root_full_log')
    eight=integrated['new_source_and_test_files'];need(len(eight)==8,'closed_eight_new_source_test_files')
    for name,row in eight.items():need(metadata(read(REPO/name))=={key:row[key] for key in ('bytes','sha256')},'installed_eight_exact')
    actual_index_path=OUT/'psec-lpac-matchedcaps-identity-local-01-evidence-index.json'
    actual_index_raw=read(actual_index_path);actual_index=decode(actual_index_raw)
    need(actual_index['source_commit']==COMMIT and actual_index['source_sha256']==CLOSURE
        and actual_index['original_public_sha256']==PUBLIC_SHA and len(actual_index['files'])==15,'actual16_index')
    component=decode(read(OUT/'psec-lpac-matchedcaps-identity-local-01-component-projection.json'))
    sc=decode(read(OUT/'psec-lpac-matchedcaps-identity-local-01-security-capabilities-projection.json'))
    transfers=decode(read(OUT/'psec-lpac-matchedcaps-identity-local-01-inner-transfers-projection.json'))
    jobs=decode(read(OUT/'psec-lpac-matchedcaps-identity-local-01-job-admissions-projection.json'))
    globals_value=decode(read(OUT/'psec-lpac-matchedcaps-identity-local-01-global-projection.json'))
    need(component['worker_result_validated'] is component['worker_report_held_bound'] is component['automatic_cleanup_confirmed'] is True
        and component['outer_launch']['normal_zero_exit'] is True and [row['role'] for row in component['task_observations']]==['bootstrap','ac','lpac'],'actual_three_known_held')
    need(all(row['held_admitted'] and row['assigned'] and row['never_resumed'] and row['exited'] and row['exit_code']==1
        and row['exact_catalog'] is True and row['integrity_rid']==4096 for row in component['task_observations']),'three_primary_admitted_never_resumed')
    need([row['operation'] for row in component['operations']]==['bind','create','bootstrap','ac','lpac','close','unbind']
        and all(row['returned_function_status']==row['wrapper_status']==0 and row['api_entered'] and row['api_returned'] for row in component['operations'])
        and len(component['intents'])==10 and component['void_close_invoked_count']==component['void_close_returned_normally_count']==1,'seven_returns_ten_intents_void_once')
    need(sc['security_capabilities_verified'] is sc['external_held_primary_source_bound'] is sc['same_input_for_all_recorded_measured_arms'] is True
        and sc['physical_receipt_count']==sc['physical_held_bound_receipt_count']==1 and sc['abi_security_input_bytes']==64
        and sc['abi_library_version']==sc['abi_security_input_version']==3 and len(sc['measured_arms'])==2
        and all(row['same_frozen_sc_input'] and row['bootstrap_rechecked_before_create'] and row['bootstrap_rechecked_before_primary'] for row in sc['measured_arms'])
        and sc['psec_network_preservation_proven'] is sc['linux_equivalence_proven'] is False,'held_primary_same_sc_physical_binding')
    need([row['principal'] for row in sc['input_sid_byte_metadata']]==['held-bootstrap-AppContainer','AgenticAppContainer','privateNetworkClientServer']
        and [row['attributes'] for row in sc['input_sid_byte_metadata']]==[None,4,4],'symbolic_catalog_and_attributes')
    need(transfers['verified_transfer_count']==transfers['assign_attempted_count']==transfers['pretransfer_record_count']==3
        and transfers['physical_receipt_count']==transfers['held_bound_physical_receipt_count']==9,'three_once_physical_transfers')
    for row in transfers['records']:
        guard=row['pretransfer_guard'];raw=row['raw_assign_observation']
        need(guard['inner_query']['api_success'] is True and guard['inner_query']['membership'] is False
            and guard['outer_query']['api_success'] is guard['outer_query']['membership'] is True
            and guard['exact_outer_true_inner_false_verified'] is True and guard['query_resources']['protected_handle_alias'] is False
            and raw['return_value']==1 and raw['api_success'] is raw['within_original_work_deadline'] is True
            and raw['immediate_win32_error']==0 and row['transfer_verified'] is True,'original_pretransfer_and_bool')
    need(jobs['job_admission_record_count']==jobs['physical_receipt_count']==24 and all(row['admission_verified'] for row in jobs['records'])
        and {role:sum(row['role']==role for row in jobs['records']) for role in ('bootstrap','ac','lpac')}==dict(bootstrap=11,ac=7,lpac=6),'twentyfour_exact_post_jobs')
    proofs={row['role']:row for row in component['proofs']};need(set(proofs)=={'ac','lpac'},'both_actual_proofs')
    ac,lpac=proofs['ac'],proofs['lpac'];first=lpac['observed_calls'][0]
    need(ac['qualified'] is True and ac['observed_matrix']==[3,0,1,2] and ac['attempted_call_count']==4,'ac_four_actual_masks')
    need(lpac['qualified'] is False and lpac['observed_matrix'] is None and lpac['attempted_call_count']==len(lpac['calls'])==1
        and lpac['failure']=='mask' and lpac['unattempted_call_labels']==['world','aap','arap'] and first['label']=='combined'
        and first['api_success'] is first['access_status'] is True and first['granted_access']==3
        and first['privilege_count']==0 and first['win32_error'] is None,'lpac_only_first_actual_call_no_full_vector')
    need(all(component[key] is False for key in false_claims),'component_false_claims')
    need(globals_value['observed'] is globals_value['raw_bytes_identical'] is globals_value['whole_json_objects_equal'] is True
        and globals_value['before']==globals_value['after']==dict(bytes=7378,sha256='f05d91ee76ee8a97ae5ab3bfa092167a8ee560c083255f142e6c453f2edf7ab3'),'four_object_snapshots_original_bytes')
    manifest_raw=read(OUT/'psec-lpac-matchedcaps-identity-local-01-bridge-manifest.json');manifest=decode(manifest_raw)
    need(len(manifest)==15 and manifest['abi_version']==3 and manifest['constructor_policy']==POLICY and manifest['compile_only'] is True
        and manifest['runtime_acceptance'] is False and manifest['imports']==['KERNEL32.dll'] and len(manifest['exports'])==8
        and manifest['dll_bytes']==217088 and manifest['dll_sha256']=='91e9fdc092943ac3a3b47c9f5ad394f4aacb522d105aa802c47b74d5c4f702b1'
        and manifest['sources']|manifest['dependencies']==promoted['native_pins'],'compiled_abi3_native37_binding')
    compile_review=decode(read(BASE/'psec-lpac-matchedcaps-compile-independent-review-01.json'))
    need(compile_review['runtime_source_sha256']==CLOSURE and compile_review['snapshot_count']==37
        and compile_review['verdict'].startswith('GO') and compile_review['execution']['DLL_loaded'] is compile_review['execution']['native_API_called'] is False,'compile_independent_no_runtime')
    driver=decode(read(BASE/'psec-lpac-matchedcaps-driver-independent-review-01.json'))
    need(driver['source_commit']==COMMIT and driver['verdict'].startswith('GO') and driver['driver']==dict(bytes=5733,name='run_psec_lpac_matchedcaps_identity_01.py',sha256='925ee06bf2f0e0e525e14c31a901166b471349158808315b42cba64b1b60579b')
        and driver['actions']['driver_executed'] is False,'source_bound_driver_review_not_actual')
    repair=decode(read(BASE/'psec-lpac-matchedcaps-file-reader-freeze-02.json'))
    need(repair['original_failure_label']=='audit_prior_evidence_not_product_acceptance' and repair['pure']['tests']==5
        and repair['pure']['exit_code']==repair['pure']['skip_count']==0 and repair['change_scope'].startswith('Only historical')
        and repair['actual_experiment_repeated'] is repair['actual_source_or_private_evidence_modified'] is False,'reader_schema_repair_separate_from_actual')
    need(read(BASE/'verify_psec_lpac_matchedcaps_actual_01.py')==read(BASE/'verify_psec_lpac_matchedcaps_actual_01_failed-reader-01.py'),'failed_reader_original_preserved')
    actual_review=decode(read(BASE/'psec-lpac-matchedcaps-identity-actual-01-independent-review.json'))
    need(actual_review['source_commit']==COMMIT,'fresh_reader_actual_source')
    ci_raw=read(BASE/'ci-psec-matchedcaps-identity-39885821454-full.txt')
    need(COMMIT.encode() in ci_raw and ci_raw.startswith(b'\xef\xbb\xbf') and re.findall(rb'Ran ([0-9]+) tests in ([0-9.]+)s',ci_raw)==[(b'955',b'76.405')]
        and re.search(rb'(?m)^.*Z OK\r?$',ci_raw) is not None,'source_auto_ci_decoded_log')
    ci=dict(run_id=39885821454,job_id=120193628680,source_commit=COMMIT,status='completed',conclusion='success',tests=955,seconds=76.405,
        failures=0,errors=0,skips=0,gated_runtime_steps_5_to_9='skipped',runtime_skip_basis='Root separately inspected GitHub job metadata; gated steps have no execution log.',
        decoded_log_original=metadata(ci_raw),decoded_text_encoding='UTF-8 BOM / CRLF',raw_zip=False,compile_and_pure_only=True,
        actual_runtime_qualification=False,dispatch_or_rerun=False,url='https://github.com/Shermanxwz/Rule-proxy-Web/actions/runs/39885821454')
    immutable={};handoff_path=REPO/'docs/validation/windows-codex-handoff.md';historical_mutable_refs=[]
    def remember(path):
        path=Path(path);raw=read(path,4*1024*1024)
        if path in immutable:need(immutable[path]==raw,'immutable_duplicate')
        immutable[path]=raw;return raw
    def member(name):
        need(type(name) is str and '\\' not in name and not Path(name).is_absolute() and '..' not in Path(name).parts,'index_relative_path')
        path=REPO/name;need(REPO.resolve() in path.resolve().parents,'index_inside_repo');return path
    def remember_index(path):
        raw=remember(path)
        for row in decode(raw)['files']:
            target=member(row['path'])
            if target==handoff_path:
                current=read(target);need(metadata(current)=={key:row[key] for key in ('bytes','sha256')},'historical_mutable_handoff_current_exact')
                historical_mutable_refs.append(dict(index=path.relative_to(REPO).as_posix(),original_reference=row,current_bytes_verified_before_prefix=True));continue
            value=remember(target);need(metadata(value)=={key:row[key] for key in ('bytes','sha256')},'immutable_index_member')
        return raw
    for attempt in ('01','02','03'):
        for suffix in ('evidence-index.json','publication-index.json'):remember_index(OUT/('psec-lpac-identity-local-'+attempt+'-'+suffix))
        remember_index(OUT/('psec-lpac-identity-source-review-'+attempt)/'index.json')
        remember(OUT/('psec-lpac-identity-local-'+attempt+'-checkpoint.json'))
        remember(REPO/('docs/validation/2026-10-23-psec-lpac-identity-'+attempt+'.md'))
    for suffix in ('evidence-index.json','publication-index.json'):remember_index(OUT/('psec-lpac-postassign-identity-local-01-'+suffix))
    remember_index(OUT/'psec-lpac-postassign-identity-source-review-01/index.json')
    postassign_checkpoint_path=OUT/'psec-lpac-postassign-identity-local-01-checkpoint.json';remember(postassign_checkpoint_path)
    remember(REPO/'docs/validation/2026-10-23-psec-lpac-postassign-identity-01.md')
    remember_index(OUT/'lpac-semantic-dns-local-02-evidence-index.json')
    remember(OUT/'lpac-semantic-dns-local-02-checkpoint.json');remember(REPO/'docs/validation/2026-10-23-lpac-semantic-dns-02.md')
    remember_index(actual_index_path);actual_paths=[member(row['path']) for row in actual_index['files']]+[actual_index_path];need(len(actual_paths)==16,'actual16_members')
    old01_raw=immutable[OUT/'psec-lpac-identity-local-01-public.json'];old01=decode(old01_raw)
    need(sha(old01_raw)=='cc562d1b045fea336c4257051faa52e63aa415d91556a4ea84f18aa363652f9c'
        and old01['broker_outcome_unknown'] is old01['recovery_required'] is True,'original_atomic01_unknown_not_cleared')
    old_progress_raw=read(OUTPUT);before=decode(old_progress_raw);progress=copy.deepcopy(before)
    old_postassign=copy.deepcopy(before['PSEC_LPAC_POSTASSIGN最新实测']);old_atomic=copy.deepcopy(before['PSEC_LPAC最新实测'])
    need(old_postassign['source_commit']=='953de0a2374aff89959957da4b5641ce5aaff8a1'
        and old_atomic['source_commit']=='4c5878ba0ffa6f4b938e26bf5c8c016b7042b333','prior_latest_scope_values')
    old_handoff=read(handoff_path);handoff_prefix=HANDOFF_PREFIX.encode('utf8')
    need(len(HANDOFF_PREFIX.splitlines())==2 and not old_handoff.startswith(handoff_prefix),'fresh_two_line_handoff_prefix')
    handoff_raw=handoff_prefix+old_handoff;need(handoff_raw[len(handoff_prefix):]==old_handoff,'handoff_all_original_bytes_preserved')
    planned={};copies=[]
    def add(path,raw):
        need(path not in planned,'publication_path_once');planned[path]=raw
    for name,pin in INPUTS.items():
        raw=read(BASE/name);view,edits=public_text(raw)
        if name in ('psec-lpac-matchedcaps-identity-actual-01-independent-review.json','psec-lpac-matchedcaps-actual-01-extra-raw-review.json'):
            value=decode(view)
            def clean(item):
                if type(item) is dict:return {key:clean(value) for key,value in item.items() if key!='message'}
                if type(item) is list:return [clean(value) for value in item]
                return item
            cleaned=clean(value)
            if cleaned!=value:view=encode(cleaned);edits.append('freeform-message-fields-removed')
        target=FOLDER/pin['public_name'];add(target,view)
        copies.append(dict(artifact_name=name,public_name=pin['public_name'],path=target.relative_to(REPO).as_posix(),
            raw_original=metadata(raw),public_view=metadata(view),byte_exact_copy=raw==view,transformations=sorted(set(edits)),
            unmodified_raw_metadata_only=raw!=view,raw_private_values_not_published=True,
            evidence_phase='reader-schema-history' if 'reader' in pin['public_name'] else 'compile-or-source-or-review-or-pure-evidence'))
    add(FOLDER/'automatic-ci-summary.json',encode(ci))
    helper_raw=read(Path(__file__));view,edits=public_text(helper_raw);need(view==helper_raw and not edits,'publication_helper_safe_exact_source')
    add(FOLDER/'publication.py',helper_raw)
    source_index_path=FOLDER/'index.json'
    add(source_index_path,encode(dict(schema_version=1,stage='matchedcaps01-source-review-index',scope=SCOPE,constructor_policy=POLICY,
        source_commit=COMMIT,source_sha256=CLOSURE,runtime_source_count=36,runtime_shared_count=34,native_source_count=6,native_dependency_count=31,
        new_source_test_files=eight,closed_new_source_test_count=8,initial_false01_and_false02_preserved=True,root_explicit_true_promotion03=True,
        promotion_only_ready_literal=True,original_logs_and_false_freezes_unchanged=True,files=[repo_ref(path,raw) for path,raw in planned.items()],
        artifact_copies=copies,all_raw_and_safe_view_hashes_separate=True,root_integrated_pure=tests,source_automatic_ci=ci,
        new_python_test_methods=30,new_native_test_methods=3,native_compiled_checks=254,compiled_checks_are_not_additional_tests=True,
        reader01_failed_before_receipt=True,reader02_schema_repair_pure=repair['pure'],reader02_actual_experiment_repeated=False,
        authoring_archive_pure=dict(tests=6,seconds=0.805,failures=0,errors=0,skips=0,separate_raw_log_available=False,source='Completed exec tool output; no fabricated raw log.'),
        actual_archive_index=repo_ref(actual_index_path,actual_index_raw),index_self_hash_excluded=True,
        no_new_actual_native_or_network_run=True,old_atomic_unknowns_not_reinterpreted=True,psec_network_preservation_proven=False,linux_equivalence_proven=False)))
    doc_path=REPO/'docs/validation/2026-10-23-psec-lpac-matchedcaps-identity-01.md';doc_raw=DOCUMENT.encode('utf8');view,edits=public_text(doc_raw)
    need(view==doc_raw and not edits,'new_document_safe');add(doc_path,doc_raw)
    checkpoint_path=OUT/'psec-lpac-matchedcaps-identity-local-01-checkpoint.json'
    checkpoint=dict(schema_version=1,stage='matchedcaps01-three-held-partial-lpac-mask-checkpoint',scope=SCOPE,constructor_policy=POLICY,
        source_commit=COMMIT,source_sha256=CLOSURE,original_public=repo_ref(public_path,public_raw),document=repo_ref(doc_path,doc_raw),
        evidence_index=repo_ref(actual_index_path,actual_index_raw),source_review_index=repo_ref(source_index_path,planned[source_index_path]),
        status='inconclusive',failure='accesscheck',observation_complete=False,roles=['bootstrap','ac','lpac'],actor_never_resumed=True,
        worker_bound=True,worker_exit_code=0,actor_held_exit_codes=[1,1,1],all_three_primary_admitted=True,
        security_capabilities_verified=True,security_capabilities_physical_receipt_count=1,security_capabilities_abi_bytes=64,
        same_measured_security_capabilities_input=True,bootstrap_source='External held primary token and physical generation/Job/PI-bound receipt',
        once_assignment_verified_roles=3,original_assignment_bools=[1,1,1],original_assignment_win32_errors=[0,0,0],assignments_timely=True,
        post_assignment_exact_job_count=24,post_assignment_counts=dict(bootstrap=11,ac=7,lpac=6),all_recorded_post_jobs_verified=True,
        native_return_count=7,caller_intent_count=10,pretransfer_and_assignment_physical_receipt_count=9,
        ac_observed_matrix=[3,0,1,2],ac_accesscheck_qualified=True,ac_actual_call_count=4,
        lpac_actual_call_count=1,lpac_observed_access_prefix=[3],lpac_complete_observed_matrix=None,lpac_accesscheck_qualified=False,
        lpac_first_call=dict(label='combined',api_success=True,access_status=True,granted_access=3,expected_granted_access=2,privilege_count=0,win32_error=None),
        lpac_failure='mask',lpac_unattempted_labels=['world','aap','arap'],unattempted_calls_not_filled=True,lpac_semantic_identity_qualified=False,
        known_caller_resource_cleanup_confirmed=True,void_close_invoked_once=True,void_close_returned_normally=True,module_unbind_confirmed=True,
        recovery_required=False,broker_outcome_unknown=False,external_environment_absence_verified=False,broker_cancellation_proven=False,
        atomic_inner_creation_proven=False,continuous_outer_supervision_proven=False,creation_transfer_crash_gap_resolved=False,
        psec_network_preservation_proven=False,linux_equivalence_proven=False,model2_policy_compared=False,network_tested=False,dns_tested=False,proxy_tested=False,product_acceptance=False,
        independent_deny_all_scope_not_proxy_policy_comparison=True,reason_for_mask_failure_determined=False,all_attributes_ignored_proven=False,
        old_postassign_checkpoint=repo_ref(postassign_checkpoint_path,immutable[postassign_checkpoint_path]),old_scope_results_not_rewritten=True,
        original_atomic01_broker_unknown_preserved=True,original_atomic01_recovery_required_preserved=True,
        existing_g_psec_api_dns_leak_remains_true=True,standalone_semantic_dns02_api_query5_5_preserved=True,
        global_snapshot_bytes=7378,global_snapshot_sha256='f05d91ee76ee8a97ae5ab3bfa092167a8ee560c083255f142e6c453f2edf7ab3',global_before_after_byte_equal=True,
        snapshot_objects=['firewall_profiles','dns','routes','user_proxy'],nrpt_in_snapshot=False,
        author_false02_pure=false02['pure'],root_integrated_pure=tests,source_automatic_ci=ci,
        native_compiled_checks=254,compiled_checks_not_new_tests=True,reader01_schema_mismatch_preserved=True,reader02_schema_repair_actual_rerun=False)
    add(checkpoint_path,encode(checkpoint));planned[handoff_path]=handoff_raw
    history='此前PSEC_LPAC_POSTASSIGN01实测';new='PSEC_LPAC_MATCHEDCAPS最新实测'
    need(history not in progress or progress[history]==old_postassign,'old_postassign_history_consistency');need(new not in progress,'fresh_matchedcaps_latest')
    progress[history]=copy.deepcopy(old_postassign);progress[new]=copy.deepcopy(checkpoint);progress[new]['checkpoint']=repo_ref(checkpoint_path,planned[checkpoint_path])
    progress['最新尝试']={'名称':'psec-lpac-matchedcaps-identity-local-01','scope':SCOPE,'constructor_policy':POLICY,'源码提交':COMMIT,
        '原public':repo_ref(public_path,public_raw),'状态':'inconclusive','失败门':'accesscheck / LPAC combined mask',
        'held角色':['bootstrap','ac','lpac'],'相同SC输入绑定':True,'三次原assignmentBOOL':[1,1,1],'立即error':[0,0,0],'后置双Job观察数':24,
        '三角色primary准入':True,'AC实际矩阵':[3,0,1,2],'ACqualified':True,'LPAC实际调用数':1,'LPAC首项grant':3,'LPAC首项预期':2,
        'LPAC完整矩阵':None,'LPAC后三项未执行':['world','aap','arap'],'LPACqualified':False,'worker退出码':0,'held退出码':[1,1,1],
        '本轮已知清理完成':True,'本轮需要恢复':False,'旧atomic01unknown仍保留':True,'actor恢复':False,'网络测试':False,'产品验收':False,
        'psec_network_preservation_proven':False,'linux_equivalence_proven':False,'atomic_inner_creation_proven':False,
        'continuous_outer_supervision_proven':False,'creation_transfer_crash_gap_resolved':False}
    progress['最新尝试归档索引']=repo_ref(actual_index_path,actual_index_raw)
    progress['当前阻断']='新matchedcaps scope的三held、相同SC输入、3次assignment及24次后置双Job通过；AC四项匹配，LPAC仅combined返回grant3而预期2即停，后三项未执行。未确定原因、未证明PSEC网络保留或Linux等价；旧atomic01 unknown、postassign和原G/PSEC DNS泄漏保持。'
    progress['状态']='matchedcaps01 为inconclusive/accesscheck：LPAC首项mask仍不符，未Resume actor或测试网络；原postassign/atomic/DNS检查点分别保留。'
    progress['源码提交']=COMMIT;progress['日期']='2026-10-23'
    allowed={history,new,'最新尝试','最新尝试归档索引','当前阻断','状态','源码提交','日期'}
    untouched={key:sha(encode(value)) for key,value in before.items() if key not in allowed}
    need(all(encode(progress[key])==encode(before[key]) for key in untouched) and progress['PSEC_LPAC_POSTASSIGN最新实测']==old_postassign
        and progress['PSEC_LPAC最新实测']==old_atomic,'all_other_outputs_including_both_old_latest_and_dns_byte_equivalent')
    progress_raw=encode(progress);view,edits=public_text(progress_raw);need(view==progress_raw and not edits,'safe_progress')
    for link in re.findall(r'\]\(([^)]+)\)',DOCUMENT):
        if link.startswith('https://'):continue
        target=(doc_path.parent/link).resolve();need(target in planned or target.is_file(),'new_document_link:'+link)
    publication_index_path=OUT/'psec-lpac-matchedcaps-identity-local-01-publication-index.json'
    add(publication_index_path,encode(dict(schema_version=1,stage='matchedcaps01-publication-index',source_commit=COMMIT,scope=SCOPE,
        original_actual_index=repo_ref(actual_index_path,actual_index_raw),files=[repo_ref(path,raw) for path,raw in planned.items()],index_self_hash_excluded=True,
        outputs_progress=dict(path='outputs/windows-isolation-progress.json',before=metadata(old_progress_raw),after=metadata(progress_raw),allowed_changed_fields=sorted(allowed),
            untouched_field_sha256=untouched,all_other_field_values_byte_equivalent=True,original_atomic_and_postassign_latest_keys_unchanged=True),
        handoff_update=dict(path=handoff_path.relative_to(REPO).as_posix(),before=metadata(old_handoff),after=metadata(handoff_raw),prefix=metadata(handoff_prefix),
            added_lines=2,all_original_bytes_preserved=True),historical_handoff_references_preserved=historical_mutable_refs,
        immutable_older_and_actual_files=[repo_ref(path,raw) for path,raw in immutable.items()],
        original_partial_lpac_not_completed=True,old_unknowns_not_reinterpreted=True,source_or_runtime_or_recovery_run=False)))
    for path in planned:
        if path!=handoff_path:need(not path.exists(),'fresh_matchedcaps_publication_target')
    need(not FOLDER.exists(),'fresh_matchedcaps_source_review_directory')
    need(all(read(path,4*1024*1024)==raw for path,raw in immutable.items()) and read(OUTPUT)==old_progress_raw and read(handoff_path)==old_handoff,'original_inputs_unchanged')
    paths=sorted({*actual_paths,*planned})
    result=dict(planned_repository_files=len(planned),preserved_actual_archive_files=16,source_review_copies=len(copies),public_views_changed=sum(not row['byte_exact_copy'] for row in copies),
        source_commit=COMMIT,status='inconclusive',failure='accesscheck',roles=['bootstrap','ac','lpac'],security_capabilities_verified=True,
        ac_matrix=[3,0,1,2],lpac_observed_prefix=[3],lpac_complete_matrix=None,old_atomic_and_postassign_latest_preserved=True,all_dns_fields_preserved=True,
        handoff_original_bytes_preserved=True,publication_written=False,native_or_network_or_recovery_run=False)
    return planned,progress_raw,old_progress_raw,immutable,paths,handoff_path,old_handoff,result

def main(argv=None):
    parser=argparse.ArgumentParser(description=__doc__);parser.add_argument('--publish',action='store_true');args=parser.parse_args(argv)
    planned,progress,old_progress,immutable,paths,handoff_path,old_handoff,result=prepare()
    if args.publish:
        for path in planned:
            if path!=handoff_path:path.parent.mkdir(parents=True,exist_ok=True)
        for path,raw in planned.items():
            if path==handoff_path:continue
            with path.open('xb') as stream:need(stream.write(raw)==len(raw),'fresh_publication_write')
            need(read(path,4*1024*1024)==raw,'publication_readback')
        need(read(handoff_path)==old_handoff and read(OUTPUT)==old_progress,'mutable_inputs_still_original')
        temporary=handoff_path.with_name('.windows-codex-handoff-matchedcaps01.tmp');need(not temporary.exists(),'fresh_handoff_temporary')
        with temporary.open('xb') as stream:need(stream.write(planned[handoff_path])==len(planned[handoff_path]),'handoff_prefix_write')
        os.replace(temporary,handoff_path);need(read(handoff_path)==planned[handoff_path],'handoff_readback')
        need(OUTPUT.parent.resolve()==(BASE.parent/'outputs').resolve(),'fixed_outputs_directory')
        temporary=OUTPUT.with_name('.windows-isolation-progress-matchedcaps01.tmp');need(not temporary.exists(),'fresh_outputs_temporary')
        with temporary.open('xb') as stream:need(stream.write(progress)==len(progress),'outputs_write')
        os.replace(temporary,OUTPUT);need(read(OUTPUT)==progress,'outputs_readback')
        need(all(read(path,4*1024*1024)==raw for path,raw in immutable.items()),'older_history_and_actuals_unchanged')
        listing=BASE/'stage_psec_lpac_matchedcaps_identity_publication_01_paths.txt';raw=''.join(path.relative_to(REPO).as_posix()+'\n' for path in paths).encode('ascii')
        if listing.exists():need(read(listing)==raw,'explicit_pathlist_unchanged')
        else:
            with listing.open('xb') as stream:need(stream.write(raw)==len(raw),'explicit_pathlist_write')
        result['publication_written']=True
    print(json.dumps(result,sort_keys=True,ensure_ascii=True))
if __name__=='__main__':main()
