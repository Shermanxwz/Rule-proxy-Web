"""Prepare/publish only file evidence and documentation for PSEC postassign identity01.

Default is read-only planning. --publish is for the reviewing root only.
No source implementation, experiment, API, network, CI, cleanup or recovery
entry is imported or executed. All old atomic attempts/DNS evidence and the new postassign actual archive remain immutable.
"""
from __future__ import annotations
import argparse
import copy
import hashlib
import json
from pathlib import Path
import re
import stat
import os

BASE=Path(__file__).resolve().parent
REPO=BASE/'Rule-proxy-Web'
OUT=REPO/'verification/windows-2026-10-22'
OUTPUT=BASE.parent/'outputs/windows-isolation-progress.json'
FOLDER=OUT/'psec-lpac-postassign-identity-source-review-01'
COMMIT='953de0a2374aff89959957da4b5641ce5aaff8a1'
CLOSURE='d625a45670dc4b544c73e7dfb0acb55f483064dca23495e5e12f9dcbf8705f9f'
PUBLIC_SHA='3862644d9d75b0e44a52c4bf2e0be063314dd6418e9e2fff6d5acca1fdaf0bd0'
PUBLIC_BYTES=2408
INPUTS={'psec-lpac-postassign-native-freeze-01.json': {'bytes': 9090, 'sha256': 'f7d62220f30d11ad245ab7de859bd4c93ca4bee13294c1c8b64e5db5aad4b981'}, 'psec-lpac-postassign-native-01.patch': {'bytes': 14841, 'sha256': 'aead170fc2ef4f1dc6f6f42dc3111e43bebcd6efddbc4be24257d09cb0cf1dd6'}, 'psec-lpac-postassign-native-diff-01.txt': {'bytes': 2927, 'sha256': '4306c652f04ba6be0bd2384c3407938469b3044003b610612b7e0ab8b8cb6d3d'}, 'psec-lpac-postassign-compile-independent-review-01.json': {'bytes': 14631, 'sha256': 'cd4250a587d24ec61751960e64450111a7cb5b57994091573a7421ba079ca882'}, 'compile_psec_lpac_postassign_bridge_01.ps1': {'bytes': 4635, 'sha256': '7f94684dc612b20c3cb034700cd6b9d157c27d2edb22a7496814ba957b15c58d'}, 'inspect_psec_lpac_postassign_bridge_compile_01.py': {'bytes': 7046, 'sha256': '64ac422501a5f2984f07ea641d887064c340f7b7e67782a6b040ac1e769137e5'}, 'review_psec_lpac_postassign_compile_01.py': {'bytes': 11560, 'sha256': '71d418c5e8a7cc12f281c6cf4b2af1ef9a2168cf216244a017d2f06a8937439e'}, 'psec-lpac-postassign-bridge-compile-01/static-pe-review.json': {'bytes': 2031, 'sha256': '8927e621edc51235f70670fb90ee294d525760bf684166afc3372a2162431a6d'}, 'psec-lpac-postassign-bridge-compile-01/toolchain.json': {'bytes': 344, 'sha256': '796cd755464544645ce142c58d8dbfc113ff301034803dd4705d17894f47bb07'}, 'psec-lpac-postassign-python-candidate-01.patch': {'bytes': 174674, 'sha256': '8d95e281f737d3ba87e893c6f76ddfd4a6d8590df966e1925ffd9e3d85c29b23'}, 'psec-lpac-postassign-python-candidate-freeze-01.json': {'bytes': 17024, 'sha256': '73d0432dd1fc2437cb04981359af10c890dd5c12c99cc68e7198520f56506d0b'}, 'psec-lpac-postassign-python-candidate-abi-01.json': {'bytes': 2650, 'sha256': '7299214878dd7d9cadbf6681f138eb30360f11df0e4a357ac0a0f332bc5a88e6'}, 'psec-lpac-postassign-python-pure-01.log': {'bytes': 10927, 'sha256': '27e621e3e4376a02b3e8301fdc51e399cdff57eacefaa59f5d403a80a05c29c7'}, 'psec-lpac-postassign-python-candidate-02.patch': {'bytes': 174673, 'sha256': '05e8973be1ed967880139d63cac287485d33f43ad1b60e906b5f0434d08c5b5b'}, 'psec-lpac-postassign-python-candidate-freeze-02.json': {'bytes': 18818, 'sha256': '5a7b92ab97c472333ed28f9888ffec99dd4f4ec1018a721bfd1858a0d896ab06'}, 'psec-lpac-postassign-python-candidate-abi-02.json': {'bytes': 2905, 'sha256': 'f6259b645cbf92060f14b27916f66ce8789521613be231af92a094b5ae591799'}, 'psec-lpac-postassign-python-pure-02.log': {'bytes': 10927, 'sha256': '4d4122eea5c3c0c00bfbed7d801a88566caad57b916282c44c044068d8fa42cd'}, 'psec-lpac-postassign-python-independent-review-02.json': {'bytes': 4578, 'sha256': 'd1c8e0b59854b45f2ca03932b96882b727deebd003e02300e8ceb032ec23ce8a'}, 'psec-lpac-postassign-python-independent-pure-02.log': {'bytes': 3172, 'sha256': 'c3f5256387dd18f544759f01260065e3ef457a5c9991b11006936b7a41148cde'}, 'psec-lpac-postassign-integrated-pure-01.json': {'bytes': 2783, 'sha256': '04ced4bc5881aff5ff82b26b80fa2783a5630825a9c6bf9ae994017779073100'}, 'psec-lpac-postassign-main-pure-01.log': {'bytes': 172246, 'sha256': 'aee3aae8e1da63c1366eae6e84f4ddd864e29d475a8f0eb5d6e1f836bf574d24'}, 'test_psec_lpac_postassign_integrated_01.ps1': {'bytes': 868, 'sha256': '93d2195a7b761c9db880df5ce16b1a86d147c6ad3ee19f674789c166e598ad4c'}, 'stage_psec_lpac_postassign_source_01.py': {'bytes': 15903, 'sha256': '1c648e521e480d9062e5acb57fb85eb24178f06458d14cfa4a7cff07aa588634'}, 'psec-lpac-postassign-identity-actual-01-independent-review.json': {'bytes': 54321, 'sha256': '8bb68ed9ba06f85e178939ca3e713c7b084d7d06dadeef440839b4f63f8f7d66'}, 'psec-lpac-postassign-identity-actual-01-proof-review.json': {'bytes': 15597, 'sha256': '52fd5a7a8ec4b1739ef4116df16616af3923755639c7b831c9bdce3707a106ad'}, 'archive_psec_lpac_postassign_identity_01_readiness.json': {'bytes': 2799, 'sha256': '6bb3efacec49dadb605cdcb7468969090298be331c26a32fa7a5e4e445a294c0'}, 'archive_psec_lpac_postassign_identity_01_pure_01.log': {'bytes': 1767, 'sha256': '7977c03880a8792371db33cbd166e4c0cfc497b914daac1f6b8c01a80c9ecd6c'}, 'archive_psec_lpac_postassign_identity_01_pure_03.log': {'bytes': 846, 'sha256': '5abd0cfbb186ce0c3453f79bed964557f6b31b3deae6e9e11938f40913edab49'}, 'test_archive_psec_lpac_postassign_identity_01.py': {'bytes': 4618, 'sha256': 'd2b2e06f28f462c70e3a88780ec559e472e3d396ddb2b708404b6c8dd2be9f0f'}, 'ci-psec-postassign-identity-39880370248-full.txt': {'bytes': 219702, 'sha256': '550479f04800ce614650f78d477a407b8fa5cd1e86e6e935f0f556b33f2dcc22'}}

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


SCOPE='one-local-cpse-deny-all-outer-guarded-postassign-identity-v1'
POLICY='outer-guarded-held-explicit-inner-assignment-v1'
DOCUMENT='# PSEC + LPAC postassign01：Job 转移通过，LPAC 首项访问结果不符\n\n**本轮为 `inconclusive / accesscheck`。** 独立 post-assign constructor 已完成两臂创建、受持有的 outer-only 前门、各一次 inner Job assignment、后续双 Job 与 primary 身份准入。AC 四项 AccessCheck 为 `[3,0,1,2]`，通过预声明矩阵；LPAC 只执行第一项 `combined`，API成功、AccessStatus=true、GrantedAccess=3、PrivilegeCount=0，预期应为2，因 `mask` 停止。后三项未执行，**没有完整 LPAC 向量**，不能填成 `[3,0,1,2]` 或其他矩阵。\n\n这是新 scope `one-local-cpse-deny-all-outer-guarded-postassign-identity-v1`，constructor policy 为 `outer-guarded-held-explicit-inner-assignment-v1`。受测提交 `953de0a2374aff89959957da4b5641ce5aaff8a1`，36文件运行闭包 `d625a45670dc4b544c73e7dfb0acb55f483064dca23495e5e12f9dcbf8705f9f`。[原 public](../../verification/windows-2026-10-22/psec-lpac-postassign-identity-local-01-public.json)为2408字节，SHA256 `3862644d9d75b0e44a52c4bf2e0be063314dd6418e9e2fff6d5acca1fdaf0bd0`；[证据索引](../../verification/windows-2026-10-22/psec-lpac-postassign-identity-local-01-evidence-index.json)绑定15份原始 public、manifest、构建快照、归档器和安全投影。\n\n## 本轮真实链路与部分 proof\n\n新 DLL constructor 明确只设置 SE_ENV 与 AAP policy 两项属性，省略 JOB_LIST，也不追加 SECURITY_CAPABILITIES；Python owner 在独立门内做显式 assignment。这与旧 atomic constructor 是不同路径，没有在旧 scope 中 fallback，也没有回写旧测试结果。\n\n两个原始 pretransfer 观察都记录 inner membership=false、named outer membership=true；每项 API均成功、立即error=0。held generation 与 image/hash 前后核验后，临时 QUERY 句柄已单次消费关闭、无 protected alias，才持久写 assignment intent 并调用一次 `AssignProcessToJobObject`。两臂原 BOOL均为1、立即error=0，处于原 work cutoff 内；随后13份 exact Job 观察均为 inner=true、outer=true，身份准入通过。原始 PI、query、intent、BOOL、配置、原F/D及磁盘原字节分别绑定。[转移投影](../../verification/windows-2026-10-22/psec-lpac-postassign-identity-local-01-inner-transfers-projection.json)与[后置 Job 投影](../../verification/windows-2026-10-22/psec-lpac-postassign-identity-local-01-job-admissions-projection.json)保留这些事实，不公开 HANDLE、PID、SID、Job 名称、创建时间或原QPC。\n\n[组件投影](../../verification/windows-2026-10-22/psec-lpac-postassign-identity-local-01-component-projection.json)保存两份 proof：AC有四个实际调用、qualified=true；LPAC原件只有一个实际调用、qualified=false、failure=mask。LPAC的 `observed_matrix` 为null，`world/aap/arap` 明确列为未执行；expected matrix仅说明预声明目标，不是观测数据。此结果不等于 Win32 API报错或访问被拒绝，也不支持把完整 LPAC 身份、AAP policy被忽略的原因、或整个 PSEC 属性处理方式定论化。\n\n六份 native返回收据对应 `bind/create/ac/lpac/close/unbind`；九份调用者意图、两份 pretransfer 收据、四份 assignment意图/返回收据及13份后置 Job 收据均核对。forensic result与有效 worker result逐字节一致，且原件与独立实际审查的八项私有摘要相符；forensic单独存在不能提供 held worker资格。所有 actor始终 suspended，没有 Resume、GO、DNS、网络或代理测试。\n\n## 清理与尚未证明的边界\n\nworker自然退出0，两臂 held exit1均确认；已知 child、Job、句柄、observer和查询资源清理闭合。原 VOID close消费一次并正常返回，unbind正常完成。本轮 `recovery_required=false / broker_outcome_unknown=false` 描述已知调用者资源义务，不证明外部环境 absence、broker cancellation或调用者崩溃时等价清理。\n\n原 public 中 `atomic_inner_creation_proven`、`continuous_outer_supervision_proven`、`creation_transfer_crash_gap_resolved` 始终为false。离散的 pre/post membership观察不证明创建/交接全程连续监督，也没有演示 caller死亡机制；[VOID close契约](https://learn.microsoft.com/en-us/windows/win32/api/processmodel/nf-processmodel-closeprocesssecurityenvironment)没有可虚构的 HRESULT。这些门没有因本轮正常清理而提升。\n\n[旧 identity03](2026-10-23-psec-lpac-identity-03.md)仍是原 atomic路径 inner=false、outer=true；[identity02](2026-10-23-psec-lpac-identity-02.md)仍保留未分离 inner/outer的历史。旧 [identity01](2026-10-23-psec-lpac-identity-01.md)的原 unknown/recovery要求保持，不由新 scope 的成功清理清除，也没有重开、重放或重复关闭旧 opaque值。\n\n## 源码、编译、纯测试与CI\n\n[source-review索引](../../verification/windows-2026-10-22/psec-lpac-postassign-identity-source-review-01/index.json)保留 native增量、Python初始 ACTUAL_READY=false 的四文件 patch/freeze/ABI和纯日志，以及根明确授权的promotion02原件；promotion只把就绪标记改true，仍需独立 CLI opt-in、原 source/device/artifact/spec/plan、held guard/worker与root120/worker115。没有把“source ready”当成实际实验成功。\n\n此轮只新增五个源码/测试文件。新运行闭包为34个共享文件加2个新模块；原36 runtime、原37 native及既有 tests/archives保持。新native闭包为5个共享source、新cpp和31个dependency。新DLL为x64 `/MT`、214528字节、SHA256 `5db0d4db168074a64b3c042b1be86954edaf7138e643c01fdd3625264a8b8f64`；library ABI2、payload布局V1，manifest闭合15键，静态 imports仅 KERNEL32、8 exports。compile-only构建及独立PE审查本身没有加载DLL或执行CPSE，真实运行证据独立归档。\n\npromotion02作者纯测试50项、12.045秒、零失败/零skip；两份新测试文件的AST方法数为34+16，因此全量预期由旧872+新增50得到922，没有把旧327条 compiled fake断言重复算作测试。根本机完整纯测试实际922项、68.700秒、零失败、2个原有 symlink权限skip，独立审查另行保存。本机未执行Linux验证。\n\n归档器自身的work-only纯日志另存：初期一次字段投影自测失败与修正后5项通过，均为文件/fake校验，不是实际机制失败或重跑，也不计入上述922项。\n\n[该源码自动CI](https://github.com/Shermanxwz/Rule-proxy-Web/actions/runs/39880370248)为run `39880370248` / job `120176045759`，completed/success：922项、53.368秒、零失败/零skip，5–9号gated runtime步骤均跳过。它只提供 compile/pure证据，没有实际PSEC/LPAC、isolated runtime或网络验收，也没有dispatch/rerun。原decoded日志219702字节、SHA256 `550479f04800ce614650f78d477a407b8fa5cd1e86e6e935f0f556b33f2dcc22`，为UTF-8 BOM/CRLF文本，不冒称raw ZIP；公开视图与原件分别承诺。\n\nbefore/after快照各7378字节、SHA256 `f05d91ee76ee8a97ae5ab3bfa092167a8ee560c083255f142e6c453f2edf7ab3`，与初始baseline原字节一致。只覆盖firewall profiles、DNS、routes、user proxy四对象，不含NRPT，也不证明持续或全面 absence。\n\n本 scope仍是独立 `identity-only-deny-all-v1`，无proxy/peer；不是原Model2代理策略的相同配置比较。[standalone semantic-LPAC DNS02](2026-10-23-lpac-semantic-dns-02.md)的API/query `5/5`及前后正控保持独立，[原G/PSEC DNS API泄漏](2026-10-23-selected-dns-standard53.md)仍成立。`network_tested / dns_tested / proxy_tested / model2_policy_compared / product_acceptance` 均为false，完整PSEC+LPAC身份、代理和DNS矩阵尚未验收。\n'
HANDOFF_PREFIX='**PSEC postassign01（2026-10-23，新scope）**：[真实转移及部分身份proof](2026-10-23-psec-lpac-postassign-identity-01.md)记录两臂一次assignment、13次后置双Job通过；AC四项通过，LPAC仅combined grant3（预期2）即停，后三项未执行，仍为inconclusive/accesscheck。未恢复actor/测试网络；正常已知清理不证明连续监督或崩溃等价，旧01 unknown及原DNS泄漏保留。\n\n'

def prepare():
    public_path=OUT/'psec-lpac-postassign-identity-local-01-public.json';public_raw=read(public_path,8192);public=decode(public_raw)
    need(metadata(public_raw)==dict(bytes=PUBLIC_BYTES,sha256=PUBLIC_SHA) and public['scope']==SCOPE
        and public['constructor_policy']==POLICY and public['status']=='inconclusive' and public['failure']=='accesscheck'
        and public['checks']['worker_bound'] is True and public['observation_complete'] is public['recovery_required'] is public['broker_outcome_unknown'] is False,'actual_postassign01_public')
    false_claims=('atomic_inner_creation_proven','continuous_outer_supervision_proven','creation_transfer_crash_gap_resolved')
    need(all(public[key] is False for key in false_claims),'original_unproven_claims_false')
    for name,pin in INPUTS.items():need(metadata(read(BASE/name))==pin,'publication_input_pin')
    freeze=decode(read(BASE/'psec-lpac-postassign-python-candidate-freeze-02.json'))
    initial=decode(read(BASE/'psec-lpac-postassign-python-candidate-freeze-01.json'))
    native=decode(read(BASE/'psec-lpac-postassign-native-freeze-01.json'))
    need(freeze['actual_ready'] is True and initial['actual_ready'] is False and freeze['source_count']==36 and freeze['source_sha256']==CLOSURE
        and freeze['scope']==SCOPE and freeze['constructor_policy']==POLICY and len(freeze['files'])==4
        and freeze['new_test_method_count']==50 and freeze['baseline_full_count']==872 and freeze['expected_full_count']==922,'promoted_source_scope_and_counts')
    canonical=(json.dumps(freeze['source_hashes'],sort_keys=True,separators=(',',':'),ensure_ascii=True)+'\n').encode('ascii')
    need(sha(canonical)==CLOSURE and len(freeze['source_hashes'])==36 and freeze['unchanged_shared_runtime_count']==34,'runtime_shared34_new2_closure')
    for name,digest in freeze['source_hashes'].items():need(sha(read(REPO/name))==digest,'installed_runtime36_frozen_byte')
    for name,digest in freeze['native_pins'].items():need(sha(read(REPO/name))==digest,'native37_frozen_byte')
    for name,row in freeze['files'].items():need(metadata(read(REPO/name))==dict(bytes=row['bytes'],sha256=row['sha256']),'installed_python_four_frozen_files')
    core='.github/windows_identity_psec_lpac_postassign_bridge.py';raw_core=read(REPO/core)
    need(raw_core.count(b'ACTUAL_READY=True')==1 and metadata(raw_core.replace(b'ACTUAL_READY=True',b'ACTUAL_READY=False',1))==initial['files'][core]
        and all(initial['files'][name]==row for name,row in freeze['files'].items() if name!=core),'promotion_only_ready_literal')
    need(native['constructor']['attribute_count']==2 and native['constructor']['job_list_requested'] is False
        and native['constructor']['security_capabilities_requested'] is False and len(native['files'])==1,'new_native_explicit_two_attributes')
    for name,row in native['files'].items():need(metadata(read(REPO/name))==dict(bytes=row['bytes'],sha256=row['sha256']),'new_native_cpp_frozen_byte')
    need(freeze['pure']['tests']==50 and freeze['pure']['wall_seconds']==12.045
        and freeze['pure']['failures']==freeze['pure']['errors']==freeze['pure']['skipped']==0,'author_promotion50_pure')
    need(re.findall(rb'Ran ([0-9]+) tests in ([0-9.]+)s',read(BASE/'psec-lpac-postassign-python-pure-02.log'))==[(b'50',b'12.045')],'author50_original_log')
    independent=decode(read(BASE/'psec-lpac-postassign-python-independent-review-02.json'))
    need(independent['verdict']=='GO-no-identified-code-blocker' and independent['source_sha256']==CLOSURE
        and independent['focused_pure']['tests']==16 and independent['focused_pure']['failures']==independent['focused_pure']['errors']==0,'independent_source_review')
    integrated=decode(read(BASE/'psec-lpac-postassign-integrated-pure-01.json'));tests=integrated['tests']
    need(integrated['runtime_source_sha256']==CLOSURE and integrated['runtime_source_count']==36 and integrated['runtime_shared_count']==34
        and integrated['new_test_method_count']==50 and integrated['baseline_test_count']==872
        and integrated['old_runtime36_unchanged'] is integrated['old_native37_unchanged'] is True
        and integrated['existing_327_native_assertions_not_added_to_test_count'] is True
        and tests['tests']==922 and tests['duration_seconds']==68.7 and tests['failures']==tests['errors']==0
        and tests['skipped']==2 and tests['linux_executed'] is False,'actual_full922_receipt')
    need(metadata(read(BASE/'psec-lpac-postassign-main-pure-01.log'))==dict(bytes=tests['log_bytes'],sha256=tests['log_sha256']),'root_full922_log')
    actual_index_path=OUT/'psec-lpac-postassign-identity-local-01-evidence-index.json';actual_index_raw=read(actual_index_path);actual_index=decode(actual_index_raw)
    need(actual_index['source_commit']==COMMIT and actual_index['source_sha256']==CLOSURE
        and actual_index['original_public_sha256']==PUBLIC_SHA and len(actual_index['files'])==14,'actual15_index')
    component=decode(read(OUT/'psec-lpac-postassign-identity-local-01-component-projection.json'))
    transfers=decode(read(OUT/'psec-lpac-postassign-identity-local-01-inner-transfers-projection.json'))
    jobs=decode(read(OUT/'psec-lpac-postassign-identity-local-01-job-admissions-projection.json'))
    global_value=decode(read(OUT/'psec-lpac-postassign-identity-local-01-global-projection.json'))
    need(component['worker_result_validated'] is component['worker_report_held_bound'] is component['automatic_cleanup_confirmed'] is True
        and component['outer_launch']['normal_zero_exit'] is True and len(component['task_observations'])==2,'actual_known_worker_bound_cleanup')
    need(all(row['held_admitted'] and row['assigned'] and row['never_resumed'] and row['exited'] and row['exit_code']==1
        for row in component['task_observations']),'both_held_admitted_never_resumed_exit1')
    need(len(component['operations'])==6 and [row['operation'] for row in component['operations']]==['bind','create','ac','lpac','close','unbind']
        and all(row['returned_function_status']==row['wrapper_status']==0 and row['api_entered'] and row['api_returned'] for row in component['operations'])
        and len(component['intents'])==9 and component['void_close_invoked_count']==component['void_close_returned_normally_count']==1,'six_returns_nine_intents_void_once')
    need(transfers['verified_transfer_count']==transfers['assign_attempted_count']==transfers['pretransfer_record_count']==2
        and transfers['physical_receipt_count']==transfers['held_bound_physical_receipt_count']==6,'two_physical_transfers')
    for row in transfers['records']:
        guard=row['pretransfer_guard'];raw=row['raw_assign_observation']
        need(guard['inner_query']['api_success'] is True and guard['inner_query']['membership'] is False
            and guard['outer_query']['api_success'] is guard['outer_query']['membership'] is True
            and guard['exact_outer_true_inner_false_verified'] is True and guard['query_resources']['protected_handle_alias'] is False
            and raw['return_value']==1 and raw['api_success'] is raw['within_original_work_deadline'] is True
            and raw['immediate_win32_error']==0 and row['transfer_verified'] is True,'original_pretransfer_and_bool')
    need(jobs['job_admission_record_count']==jobs['physical_receipt_count']==13 and all(row['admission_verified'] for row in jobs['records']),'thirteen_post_jobs_both_true')
    proofs={row['role']:row for row in component['proofs']};need(set(proofs)=={'ac','lpac'},'both_actual_proofs_present')
    ac,lpac=proofs['ac'],proofs['lpac'];first=lpac['observed_calls'][0]
    need(ac['qualified'] is True and ac['observed_matrix']==[3,0,1,2] and ac['attempted_call_count']==4,'ac_full_matrix')
    need(lpac['qualified'] is False and lpac['observed_matrix'] is None and lpac['attempted_call_count']==len(lpac['calls'])==1
        and lpac['failure']=='mask' and lpac['unattempted_call_labels']==['world','aap','arap']
        and first['label']=='combined' and first['api_success'] is first['access_status'] is True
        and first['granted_access']==3 and first['privilege_count']==0,'lpac_only_observed_first_call_no_synthetic_vector')
    need(all(component[key] is False and transfers[key] is False for key in false_claims),'archive_unproven_claims_false')
    need(global_value['observed'] is global_value['raw_bytes_identical'] is global_value['whole_json_objects_equal'] is True
        and global_value['before']==global_value['after']==dict(bytes=7378,sha256='f05d91ee76ee8a97ae5ab3bfa092167a8ee560c083255f142e6c453f2edf7ab3'),'global_four_objects_original_bytes')
    compile_review=decode(read(BASE/'psec-lpac-postassign-compile-independent-review-01.json'))
    manifest_raw=read(OUT/'psec-lpac-postassign-identity-local-01-bridge-manifest.json');manifest=decode(manifest_raw)
    need(len(manifest)==15 and manifest['abi_version']==2 and manifest['constructor_policy']==POLICY and manifest['compile_only'] is True
        and manifest['runtime_acceptance'] is False and manifest['imports']==['KERNEL32.dll'] and len(manifest['exports'])==8
        and manifest['dll_bytes']==214528 and manifest['dll_sha256']=='5db0d4db168074a64b3c042b1be86954edaf7138e643c01fdd3625264a8b8f64'
        and {**manifest['sources'],**manifest['dependencies']}==freeze['native_pins'],'new15_manifest_native37')
    need(compile_review['review']=='GO-no-compile-evidence-blocker' and compile_review['input_verification']['count']==37
        and compile_review['abi']['library_version']==2 and compile_review['abi']['payload_version']==1
        and compile_review['actions']['dll_loaded'] is compile_review['actions']['native_api_called'] is False,'compile_review_separate_no_runtime')
    ci_raw=read(BASE/'ci-psec-postassign-identity-39880370248-full.txt')
    need(COMMIT.encode('ascii') in ci_raw and ci_raw.startswith(b'\xef\xbb\xbf')
        and re.findall(rb'Ran ([0-9]+) tests in ([0-9.]+)s',ci_raw)==[(b'922',b'53.368')]
        and re.search(rb'(?m)^.*Z OK\r?$',ci_raw) is not None,'ci_source922_original_decoded_log')
    immutable={}
    def remember(path):
        path=Path(path);raw=read(path,4*1024*1024)
        if path in immutable:need(immutable[path]==raw,'immutable_duplicate_consistency')
        immutable[path]=raw;return raw
    def repo_member(name):
        need(type(name) is str and '\\' not in name and not Path(name).is_absolute() and '..' not in Path(name).parts,'index_relative_repo_path')
        path=REPO/name;need(REPO.resolve() in path.resolve().parents,'index_inside_repo');return path
    def remember_index(path):
        raw=remember(path)
        for row in decode(raw)['files']:
            value=remember(repo_member(row['path']));need(metadata(value)==dict(bytes=row['bytes'],sha256=row['sha256']),'immutable_index_member')
        return raw
    for attempt in ('01','02','03'):
        for suffix in ('evidence-index.json','publication-index.json'):remember_index(OUT/('psec-lpac-identity-local-'+attempt+'-'+suffix))
        remember_index(OUT/('psec-lpac-identity-source-review-'+attempt)/'index.json')
        remember(OUT/('psec-lpac-identity-local-'+attempt+'-checkpoint.json'))
        remember(REPO/('docs/validation/2026-10-23-psec-lpac-identity-'+attempt+'.md'))
    remember_index(actual_index_path);actual_paths=[repo_member(row['path']) for row in actual_index['files']]+[actual_index_path]
    need(len(actual_paths)==15,'actual15_members')
    old01=decode(immutable[OUT/'psec-lpac-identity-local-01-public.json'])
    need(old01['broker_outcome_unknown'] is old01['recovery_required'] is True
        and sha(immutable[OUT/'psec-lpac-identity-local-01-public.json'])=='cc562d1b045fea336c4257051faa52e63aa415d91556a4ea84f18aa363652f9c','old_atomic01_unknown_not_replaced')
    old03_path=OUT/'psec-lpac-identity-local-03-checkpoint.json';old03=decode(immutable[old03_path])
    need(old03['source_commit']=='4c5878ba0ffa6f4b938e26bf5c8c016b7042b333' and old03['inner_membership'] is False
        and old03['outer_membership'] is True,'old_atomic03_record_kept')
    remember_index(OUT/'lpac-semantic-dns-local-02-evidence-index.json')
    remember(OUT/'lpac-semantic-dns-local-02-checkpoint.json');remember(REPO/'docs/validation/2026-10-23-lpac-semantic-dns-02.md')
    need(sha(remember(OUT/'lpac-semantic-dns-local-02-public.json'))=='757ad3b8c48f7f4d6e4d6aab9feaef4915dc54b39cf1977484eed6119fcc744f','dns02_original_public')
    old_progress_raw=read(OUTPUT);progress=decode(old_progress_raw);before=copy.deepcopy(progress)
    old_psec=copy.deepcopy(progress['PSEC_LPAC最新实测'])
    need(old_psec['original_public']['sha256']=='75f3198b40afc5b9919fd862b66ab14b023b4b30e4ab979b742cf3e315e734f6','outputs_atomic03_current_record')
    need(progress['此前PSEC_LPAC01实测']['broker_outcome_unknown'] is progress['此前PSEC_LPAC01实测']['recovery_required'] is True,'outputs_atomic01_unknown_kept')
    dns=progress['DNS最新实测'];need(dns['selected_api']['api_status']==dns['selected_api']['query_status']==5
        and dns['existing_g_psec_dns_api_leak_remains_true'] is True,'dns5_5_and_old_g_leak_kept')
    handoff_path=REPO/'docs/validation/windows-codex-handoff.md';old_handoff=read(handoff_path)
    handoff_prefix=HANDOFF_PREFIX.encode('utf8');need(len(handoff_prefix.splitlines())==2,'handoff_exact_two_line_prefix')
    handoff_raw=handoff_prefix+old_handoff;need(handoff_raw[len(handoff_prefix):]==old_handoff and handoff_path not in immutable,'handoff_old_segments_byte_exact')
    planned={};copies=[]
    def add(path,raw):
        need(path not in planned,'unique_publication_target');view,edits=public_text(raw);need(view==raw and not edits,'generated_safe_lf');planned[path]=raw
    def strip_messages(value):
        if type(value) is dict:return {key:strip_messages(item) for key,item in value.items() if key!='message'}
        if type(value) is list:return [strip_messages(item) for item in value]
        return value
    for name,pin in INPUTS.items():
        raw=read(BASE/name);need(metadata(raw)==pin,'frozen_copy_input');material=raw;extra=[]
        if name in ('psec-lpac-postassign-identity-actual-01-independent-review.json','psec-lpac-postassign-identity-actual-01-proof-review.json'):
            value=decode(raw);stripped=strip_messages(value)
            if stripped!=value:material=encode(stripped);extra.append('freeform-message-fields-omitted')
        view,edits=public_text(material);edits=sorted(set(extra+edits));target_name=Path(name).name
        if name.endswith('/static-pe-review.json'):target_name='compile01-static-pe-review.json'
        if name.endswith('/toolchain.json'):target_name='compile01-toolchain.json'
        if name=='ci-psec-postassign-identity-39880370248-full.txt':target_name='ci-39880370248-decoded.log'
        if edits:
            item=Path(target_name);target_name=item.stem+'-public-view'+item.suffix
        target=FOLDER/target_name;need(target not in planned,'unique_copy_target');planned[target]=view
        copies.append(dict(source_work_path='work/'+name,public_path=target.relative_to(REPO).as_posix(),raw_original=metadata(raw),public_copy=metadata(view),
            byte_exact_copy=view==raw,view_changes=edits,raw_private_runtime_log_published=False,
            evidence_phase=('archiver-file-fake-authoring-only' if 'archive_' in name else
                'automatic-compile-pure' if name.startswith('ci-') else 'actual-file-only-review' if '-actual-' in name else
                'compile-only' if 'compile' in name or 'native' in name else 'source-and-pure')))
    ci_copy=next(row for row in copies if row['source_work_path']=='work/ci-psec-postassign-identity-39880370248-full.txt')
    ci=dict(schema_version=1,stage='read-only-postassign-source953-auto-ci-summary',source_commit=COMMIT,verified=True,run_id=39880370248,job_id=120176045759,
        url='https://github.com/Shermanxwz/Rule-proxy-Web/actions/runs/39880370248',event='push',status='completed',conclusion='success',
        tests_run=922,seconds=53.368,failures=0,errors=0,skips=0,gated_runtime_steps_skipped=[5,6,7,8,9],
        step_skip_basis='Root independently read GitHub job metadata; skipped step bodies are absent from decoded log.',
        compile_only_actor_step_executed=True,isolated_runtime_qualified=False,native_actor_executed=False,cpse_experiment_executed=False,
        network_experiment_executed=False,workflow_dispatched=False,workflow_rerun=False,
        decoded_original=dict(**metadata(ci_raw),encoding='UTF-8 BOM',line_endings='CRLF',not_raw_zip=True,kept_in_work=True),
        public_log_view=dict(path=ci_copy['public_path'],**ci_copy['public_copy']),actual_result_remains_inconclusive_accesscheck=True)
    add(FOLDER/'ci-39880370248-summary.json',encode(ci));add(FOLDER/'publication.py',read(Path(__file__),128*1024))
    review_index=dict(schema_version=1,stage='psec-lpac-postassign-source-review01-index',source_commit=COMMIT,scope=SCOPE,constructor_policy=POLICY,
        runtime_source_count=36,runtime_source_sha256=CLOSURE,runtime_shared_count=34,new_python_module_count=2,new_test_file_count=2,new_native_cpp_count=1,
        bridge_native_source_count=6,bridge_dependency_count=31,bridge_manifest_key_count=15,library_abi_version=2,payload_version=1,
        native37_old_inputs_preserved=True,old_runtime36_preserved=True,actual_index=repo_ref(actual_index_path,actual_index_raw),
        files=[repo_ref(path,raw) for path,raw in planned.items()],original_copy_provenance=copies,index_self_hash_excluded=True,automatic_ci=ci,
        false_candidate_and_promotion_both_retained=True,initial_false_candidate_not_installed_as_actual=True,
        archiver_authoring_logs_include_initial_failure_and_corrected_pure=True,archiver_tests_not_added_to_identity922_count=True,
        pure_source_ready_not_runtime_acceptance=True,lpac_partial_observation_not_completed=True,old_atomic01_unknown_not_repaired=True,
        atomic_inner_creation_proven=False,continuous_outer_supervision_proven=False,creation_transfer_crash_gap_resolved=False,
        runtime_or_native_or_recovery_called_by_publication=False)
    add(FOLDER/'index.json',encode(review_index))
    doc_path=REPO/'docs/validation/2026-10-23-psec-lpac-postassign-identity-01.md';doc_raw=DOCUMENT.encode('utf8');add(doc_path,doc_raw)
    checkpoint_path=OUT/'psec-lpac-postassign-identity-local-01-checkpoint.json'
    checkpoint=dict(schema_version=1,stage='postassign01-partial-lpac-mask-observation-checkpoint',source_commit=COMMIT,source_sha256=CLOSURE,scope=SCOPE,constructor_policy=POLICY,
        original_public=repo_ref(public_path,public_raw),document=repo_ref(doc_path,doc_raw),evidence_index=repo_ref(actual_index_path,actual_index_raw),
        source_review_index=repo_ref(FOLDER/'index.json',planned[FOLDER/'index.json']),status='inconclusive',failure='accesscheck',observation_complete=False,
        actor_never_resumed=True,worker_bound=True,worker_exit_code=0,both_arm_held_exit_codes=[1,1],both_arm_primary_admitted=True,
        pretransfer_outer_only_guards_verified=2,assign_process_once_per_arm=True,assign_return_values=[1,1],assign_win32_errors=[0,0],assignments_within_original_deadline=True,
        post_assignment_exact_job_observation_count=13,post_assignment_all_inner_and_outer_true=True,
        original_native_returned_receipt_count=6,caller_intent_count=9,pretransfer_physical_receipt_count=2,assignment_intent_and_return_receipt_count=4,
        ac_observed_matrix=[3,0,1,2],ac_accesscheck_qualified=True,ac_observed_call_count=4,
        lpac_observed_call_count=1,lpac_observed_access_prefix=[3],lpac_complete_observed_matrix=None,lpac_accesscheck_qualified=False,
        lpac_first_call=dict(label='combined',api_success=True,access_status=True,granted_access=3,expected_granted_access=2,privilege_count=0,win32_error=None),
        lpac_failure='mask',lpac_unattempted_labels=['world','aap','arap'],unattempted_calls_not_filled=True,lpac_semantic_identity_qualified=False,
        known_caller_resource_cleanup_confirmed=True,void_close_invoked_once=True,void_close_returned_normally=True,module_unbind_confirmed=True,
        recovery_required=False,broker_outcome_unknown=False,external_environment_absence_verified=False,broker_cancellation_proven=False,
        atomic_inner_creation_proven=False,continuous_outer_supervision_proven=False,creation_transfer_crash_gap_resolved=False,
        old_atomic03_checkpoint=repo_ref(old03_path,immutable[old03_path]),old_atomic03_result_not_rewritten=True,
        original_atomic01_broker_unknown_preserved=True,original_atomic01_recovery_required_preserved=True,
        independent_deny_all_scope_not_proxy_policy_comparison=True,model2_policy_compared=False,network_tested=False,dns_tested=False,proxy_tested=False,product_acceptance=False,
        existing_g_psec_api_dns_leak_remains_true=True,standalone_semantic_dns02_api_query5_5_preserved=True,linux_equivalence_qualified=False,
        global_snapshot_bytes=7378,global_snapshot_sha256='f05d91ee76ee8a97ae5ab3bfa092167a8ee560c083255f142e6c453f2edf7ab3',
        global_before_after_byte_equal=True,snapshot_objects=['firewall_profiles','dns','routes','user_proxy'],nrpt_in_snapshot=False,
        author_promotion_pure=dict(tests=50,seconds=12.045,failures=0,errors=0,skips=0),root_full_pure=tests,source_automatic_ci=ci)
    add(checkpoint_path,encode(checkpoint));planned[handoff_path]=handoff_raw
    history='此前PSEC_LPAC03实测';new='PSEC_LPAC_POSTASSIGN最新实测'
    need(history not in progress or progress[history]==old_psec,'old03_history_consistency');need(new not in progress,'fresh_postassign_outputs_key')
    progress[history]=copy.deepcopy(old_psec);progress[new]=copy.deepcopy(checkpoint);progress[new]['checkpoint']=repo_ref(checkpoint_path,planned[checkpoint_path])
    progress['最新尝试']={'名称':'psec-lpac-postassign-identity-local-01','scope':SCOPE,'constructor_policy':POLICY,'源码提交':COMMIT,
        '原public':repo_ref(public_path,public_raw),'状态':'inconclusive','失败门':'accesscheck / LPAC combined mask',
        '两臂一次显式assignment':True,'原BOOL':[1,1],'立即error':[0,0],'后置双Job观察数':13,'两臂primary准入':True,
        'AC实际矩阵':[3,0,1,2],'ACqualified':True,'LPAC实际调用数':1,'LPAC首项grant':3,'LPAC首项预期':2,'LPAC完整矩阵':None,
        'LPAC后三项未执行':['world','aap','arap'],'LPACqualified':False,'worker退出码':0,'两臂held退出码':[1,1],
        '本轮已知资源清理完成':True,'本轮需要恢复':False,'旧atomic01unknown仍保留':True,
        'atomic_inner_creation_proven':False,'continuous_outer_supervision_proven':False,'creation_transfer_crash_gap_resolved':False,
        'actor恢复':False,'网络测试':False,'产品验收':False}
    progress['最新尝试归档索引']=repo_ref(actual_index_path,actual_index_raw)
    progress['当前阻断']='新postassign scope的两臂一次assignment、13次后置双Job与primary准入已通过；AC四项匹配，LPAC仅combined返回grant3而预期2即停，后三项未执行，完整LPAC身份未验收。正常已知清理不证明原子inner、连续outer或崩溃空档已解；旧atomic01unknown和原G/PSEC DNS泄漏保留。'
    progress['状态']='postassign01 为inconclusive/accesscheck：LPAC首项mask不符，未恢复actor或测试网络；旧atomic03与DNS检查点分别保留。'
    progress['源码提交']=COMMIT;progress['日期']='2026-10-23'
    allowed={history,new,'最新尝试','最新尝试归档索引','当前阻断','状态','源码提交','日期'}
    untouched={key:sha(encode(value)) for key,value in before.items() if key not in allowed}
    need(all(encode(progress[key])==encode(before[key]) for key in untouched)
        and progress['PSEC_LPAC最新实测']==old_psec,'all_other_outputs_including_atomic_latest_and_dns_byte_equivalent')
    progress_raw=encode(progress);view,edits=public_text(progress_raw);need(view==progress_raw and not edits,'safe_progress_output')
    for link in re.findall(r'\]\(([^)]+)\)',DOCUMENT):
        if link.startswith('https://'):continue
        target=(doc_path.parent/link).resolve();need(target in planned or target.is_file(),'new_postassign_document_link:'+link)
    publication_index_path=OUT/'psec-lpac-postassign-identity-local-01-publication-index.json'
    add(publication_index_path,encode(dict(schema_version=1,stage='postassign01-publication-index',source_commit=COMMIT,scope=SCOPE,
        original_actual_index=repo_ref(actual_index_path,actual_index_raw),files=[repo_ref(path,raw) for path,raw in planned.items()],index_self_hash_excluded=True,
        outputs_progress=dict(path='outputs/windows-isolation-progress.json',before=metadata(old_progress_raw),after=metadata(progress_raw),allowed_changed_fields=sorted(allowed),
            untouched_field_sha256=untouched,all_other_field_values_byte_equivalent=True,original_atomic_latest_key_unchanged=True),
        handoff_update=dict(path=handoff_path.relative_to(REPO).as_posix(),before=metadata(old_handoff),after=metadata(handoff_raw),
            prefix=metadata(handoff_prefix),added_lines=2,all_original_bytes_preserved=True),
        immutable_older_and_actual_files=[repo_ref(path,raw) for path,raw in immutable.items()],
        original_failed_partial_lpac_not_completed=True,old_unknowns_not_reinterpreted=True,source_or_runtime_or_recovery_run=False)))
    for path in planned:
        if path!=handoff_path:need(not path.exists(),'fresh_postassign_publication_target')
    need(not FOLDER.exists(),'fresh_postassign_source_review_folder')
    need(all(read(path,4*1024*1024)==raw for path,raw in immutable.items()) and read(OUTPUT)==old_progress_raw and read(handoff_path)==old_handoff,'inputs_unchanged')
    paths=sorted({*actual_paths,*planned})
    result=dict(planned_repository_files=len(planned),preserved_actual_archive_files=15,source_review_copies=len(copies),public_views_changed=sum(not row['byte_exact_copy'] for row in copies),
        source_commit=COMMIT,status='inconclusive',failure='accesscheck',ac_matrix=[3,0,1,2],lpac_observed_prefix=[3],lpac_complete_matrix=None,
        old_atomic_latest_preserved=True,all_dns_fields_preserved=True,handoff_original_bytes_preserved=True,publication_written=False,native_or_network_or_recovery_run=False)
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
        handoff_temp=handoff_path.with_name('.windows-codex-handoff-postassign01.tmp');need(not handoff_temp.exists(),'fresh_handoff_temporary')
        with handoff_temp.open('xb') as stream:need(stream.write(planned[handoff_path])==len(planned[handoff_path]),'handoff_prefix_write')
        os.replace(handoff_temp,handoff_path);need(read(handoff_path)==planned[handoff_path],'handoff_readback')
        need(OUTPUT.parent.resolve()==(BASE.parent/'outputs').resolve(),'fixed_outputs_directory')
        temp=OUTPUT.with_name('.windows-isolation-progress-postassign01.tmp');need(not temp.exists(),'fresh_outputs_temporary')
        with temp.open('xb') as stream:need(stream.write(progress)==len(progress),'outputs_write')
        os.replace(temp,OUTPUT);need(read(OUTPUT)==progress,'outputs_readback')
        need(all(read(path,4*1024*1024)==raw for path,raw in immutable.items()),'all_prior_history_and_actuals_unchanged')
        listing=BASE/'stage_psec_lpac_postassign_identity_publication_01_paths.txt';raw=''.join(path.relative_to(REPO).as_posix()+'\n' for path in paths).encode('ascii')
        if listing.exists():need(read(listing)==raw,'explicit_pathlist_unchanged')
        else:
            with listing.open('xb') as stream:need(stream.write(raw)==len(raw),'explicit_pathlist_write')
        result['publication_written']=True
    print(json.dumps(result,sort_keys=True,ensure_ascii=True))
if __name__=='__main__':main()
