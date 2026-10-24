"""Prepare/publish only file evidence and documentation for PSEC identity02.

Default is read-only planning. --publish is for the reviewing root only.
No source implementation, experiment, API, network, CI, cleanup or recovery
entry is imported or executed. Existing actual01 and DNS02 evidence is frozen; actual02 is also immutable.
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
FOLDER=OUT/'psec-lpac-identity-source-review-02'
COMMIT='b269c78eef15b6f71bdae5a5ee631a4e8a34ce9e'
CLOSURE='7de9968d0984cc7304951ba220d806fea74e998c0a623beddd870a0eb1e0f0ba'
PUBLIC_SHA='100dc78f9af83445829a9f8ddf03ebe1f6bb5fc3af8f1a694e43bb78229daba2'
PUBLIC_BYTES=2083
ACTUAL_REVIEW_SHA='dff1ffa8c745683ddc14dd68c3e8fb509a6d558fee73814a330c3e5c3e6f8672'
CI_SHA='04d6f0af7799e61e52364256272bc56e5c20095fdab589bc085680a048f9b034'
CI_BYTES=205350

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


DOCUMENT='''# PSEC + LPAC identity02：创建返回成功，Job 准入未通过

**本轮仍为 `inconclusive / admission`。** CPSE 环境创建返回 `S_OK`，policy 0 首臂创建返回完整 PI；随后一个 exact Job 的 membership 检查为 false，准入正确停止。原件不能区分失败的是 inner Job 还是 named outer Job。没有读取首臂 primary token，没有尝试 LPAC 第二臂，没有 AccessCheck 矩阵，也没有 actor resume、DNS、网络或代理验收。

受测源码为 `b269c78eef15b6f71bdae5a5ee631a4e8a34ce9e`，36 文件闭包为 `7de9968d0984cc7304951ba220d806fea74e998c0a623beddd870a0eb1e0f0ba`。[原 public](../../verification/windows-2026-10-22/psec-lpac-identity-local-02-public.json)为 2083 字节、SHA256 `100dc78f9af83445829a9f8ddf03ebe1f6bb5fc3af8f1a694e43bb78229daba2`。[证据索引](../../verification/windows-2026-10-22/psec-lpac-identity-local-02-evidence-index.json)和[组件投影](../../verification/windows-2026-10-22/psec-lpac-identity-local-02-component-projection.json)绑定原 public、plan/spec、Git blob/LF 源码、构建、worker/outer 报告及私有材料摘要。

## 本轮实际记录与未取得的证据

源码02修复了 FILETIME/HANDLE 的 64 位校验，PID/TID/exit code 仍为 DWORD；没有改 DLL、原 native07 actor 或 deny-all 策略。新增五份原始返回收据：`bind`、`create`、`ac`、`close`、`unbind`，均在语义校验前保存原 function status、native snapshot、PI 和 intent/config/F/D 绑定。六份意图仍是 `bind/create/ac/stop/close/unbind`；意图与返回收据分开核验。

`worker-result-forensic.json` 与经过源码校验的最终 worker result 逐字节相符。forensic 单独存在时只属未验证取证材料，不能替代 held worker report 或补出资格。此次 worker 报告存在且与普通 held worker、配置和 outer launch 绑定，worker 自然退出0；stdout/stderr 均为空。首臂创建返回的两个句柄与两个 ID 完整，创建时间确实超出 DWORD 范围；这证明本轮报告器修复已覆盖真实数据，**不等于首臂 AC 身份已被核验**。

保留下来的原失败是 `GateFailure: child_not_in_owned_job`。源码在 `IsProcessInJob` API 调用成功、membership 输出为 false 后抛出此标签；API 成功与 membership 为 true 是两件事。inner 与 named outer 检查共用该错误标签，而且 `assigned` 仅在两项都通过后设置，因此 `assigned=false` 不能识别哪项失败。最早失败门发生在 token/能力和完整 held identity 准入前；没有第二臂或 proof，不能把缺失字段补成通过。

此次首臂 held exit1 已确认，已知 child/Job/句柄与 observer 资源清理闭合；opaque close 的原收据记录消费一次并正常返回，unbind 正常完成。原 public 的 `recovery_required=false / broker_outcome_unknown=false` 只说明**本轮已知调用者资源义务闭合**。`CloseProcessSecurityEnvironment` 是 [VOID 接口](https://learn.microsoft.com/en-us/windows/win32/api/processmodel/nf-processmodel-closeprocesssecurityenvironment)，没有可虚构的 HRESULT；正常返回不证明外部环境 absence、broker cancellation 或调用者崩溃时的自动清理。本轮不是进程崩溃机制试验。

[identity01](2026-10-23-psec-lpac-identity-01.md)原 public 的未知和恢复要求完整保留。02 的新收据不能逆向填补 01 丢失的结果，也没有重开、重放或重试关闭旧 opaque 值。

## Job 契约边界与下一步

[独立实际审查](../../verification/windows-2026-10-22/psec-lpac-identity-source-review-02/actual02-independent-review.json)、[Job 约束审查](../../verification/windows-2026-10-22/psec-lpac-identity-source-review-02/psec_lpac_joblist_constraints_02.json)及[只读 query 契约](../../verification/windows-2026-10-22/psec-lpac-identity-source-review-02/psec_lpac_job_query_contract_03.json)分别记录实际事实、官方契约和未实测的观察方案。通用 [JOB_LIST 文档](https://learn.microsoft.com/en-us/windows/win32/api/processthreadsapi/nf-processthreadsapi-updateprocthreadattribute)与 [IsProcessInJob 文档](https://learn.microsoft.com/en-us/windows/win32/api/jobapi/nf-jobapi-isprocessinjob)不构成本轮 CPSE 组合已保留全部属性的证明。[固定 G 源码](https://github.com/microsoft/mxc/blob/7bf210247986cb73b1b314df60c2f1109c479c0b/src/mxc-sdk/src/backends/process_container/common/base_container_runner.rs#L938)采用创建后、恢复前的 Job assignment；它不能证明本项目要求的 atomic JOB_LIST 行为，不能据此替换当前准入门，也不能推断所有 attributes 都被忽略。

正常退出路径上持有进程句柄并明确停止子进程，不证明调用者在创建或句柄交接期间崩溃时，未入 Job 的子进程会自动停止。后续构造前必须先审查这个可能的监督空档；最小观察方案是独立保存 exact inner/outer 查询的 API success、membership、error、held generation/image、原 F/T0/D 与临时 QUERY handle 单次关闭，再保留原两项都 true 的准入要求。不能改为 any-Job、自动 post-assign、恢复 actor、放宽能力、猜 flag、重启服务或续预算。这份文档及发布脚本没有授权或执行新的构造。

## 构建、纯测试、CI 与历史结果

[source-review02 索引](../../verification/windows-2026-10-22/psec-lpac-identity-source-review-02/index.json)保存四文件增量 patch/freeze、33 项 targeted pure、独立源码审查和实际审查。本机完整身份纯测试为 863 项、49.893 秒、零失败、2 个原有 symlink 权限 skips；[该源码自动 CI](https://github.com/Shermanxwz/Rule-proxy-Web/actions/runs/39873635408)为 863 项、55.383 秒、零 skips，5–9 号 gated runtime 步骤均跳过。纯测试和 CI 不抵消真实 Job 准入失败，未在本机执行 Linux 验证。

native/DLL 仍是 [source-review01](../../verification/windows-2026-10-22/psec-lpac-identity-source-review-01/index.json)的编译前 6 source + 31 dependency 快照：x64 `/MT` DLL SHA256 `9574f93eb562a858b207412f9f538b15bfbf329b1df284b3266496b4c2cf2ba5`，静态 imports 仅 KERNEL32、8 exports。本轮仅改变 Python 观察与报告，未把旧编译失败追认成成功。公开日志/patch 若需脱敏或 LF 视图，原始与公开 bytes/SHA 及差异会分别列出；可执行源码仍以受测提交为准。

before/after02 两份全局快照均为 7378 字节、SHA256 `f05d91ee76ee8a97ae5ab3bfa092167a8ee560c083255f142e6c453f2edf7ab3`，四对象及原字节相同，仅覆盖 firewall profiles、DNS、routes、user proxy，不含 NRPT，也不证明持续或全面 absence。

这是独立 `identity-only-deny-all-v1`，无 proxy/peer，两臂预期只改 AAP policy 0/1，原 root120/worker115，不另加 SECURITY_CAPABILITIES；本轮只走到首臂 Job 拒绝。[standalone semantic-LPAC DNS02](2026-10-23-lpac-semantic-dns-02.md)的 API/query `5/5` 和前后正控成功保持独立，[原 G/PSEC DNS API 泄漏](2026-10-23-selected-dns-standard53.md)也仍成立。PSEC+LPAC 完整身份组合、相同代理策略及真实代理/DNS 矩阵仍未验收，`model2_policy_compared / proxy_tested / dns_tested / product_acceptance` 均为 false。
'''


def prepare():
    public_path=OUT/'psec-lpac-identity-local-02-public.json';public_raw=read(public_path,8192)
    need(len(public_raw)==PUBLIC_BYTES and sha(public_raw)==PUBLIC_SHA,'original02_public_pin');public=decode(public_raw)
    need(public['status']=='inconclusive' and public['failure']=='admission' and public['checks']['worker_bound'] is True
        and public['broker_outcome_unknown'] is False and public['recovery_required'] is False
        and public['observation_complete'] is False,'original02_admission_failure_preserved')
    actual_index_path=OUT/'psec-lpac-identity-local-02-evidence-index.json';actual_index_raw=read(actual_index_path);actual_index=decode(actual_index_raw)
    need(actual_index['source_commit']==COMMIT and actual_index['source_sha256']==CLOSURE,'actual02_source_binding')
    actual_paths=[]
    for row in actual_index['files']:
        path=REPO/row['path'];raw=read(path,4*1024*1024);need(metadata(raw)=={'bytes':row['bytes'],'sha256':row['sha256']},'frozen02_actual_member');actual_paths.append(path)
    actual_paths.append(actual_index_path);need(len(actual_paths)==13,'exact13_actual02_archive_files')
    component=decode(read(OUT/'psec-lpac-identity-local-02-component-projection.json'));global_value=decode(read(OUT/'psec-lpac-identity-local-02-global-projection.json'))
    need(component['worker_result_validated'] is component['worker_report_held_bound'] is True and component['proofs']==[]
        and len(component['task_observations'])==1 and component['automatic_cleanup_confirmed'] is True,'actual02_known_result')
    task=component['task_observations'][0]
    need(task['role']=='ac' and task['assigned'] is task['held_admitted'] is task['primary_snapshot_available'] is False
        and task['constructor_attempted'] is task['native_receipt_available'] is task['generation_available'] is task['exited'] is task['never_resumed'] is True
        and task['exit_code']==1 and all(task['process_information'].values()),'first_arm_created_not_identity_admitted')
    need([row['operation'] for row in component['operations']]==['bind','create','ac','close','unbind']
        and all(row['receipt_available'] and row['durable_returned_receipt_available'] and row['returned_function_status']==row['wrapper_status']==0
            and row['api_entered'] and row['api_returned'] and row['within_deadline'] for row in component['operations']),'five_original_return_tuples')
    need([row['action'] for row in component['intents']]==['bind','create','ac','stop','close','unbind']
        and component['void_close_invoked_count']==component['void_close_returned_normally_count']==1
        and component['returned_receipt_count']==component['validated_held_bound_returned_receipt_count']==5,'intents_vs_returned_facts')
    need(component['forensic_result']['equals_original_validated_report_result'] is True
        and component['forensic_result']['used_for_public_qualification'] is False
        and component['outer_launch']['normal_zero_exit'] is True,'forensic_not_fallback_and_worker0')
    need(global_value['observed'] is True and global_value['raw_bytes_identical'] is True and global_value['whole_json_objects_equal'] is True
        and global_value['before']==global_value['after']==dict(bytes=7378,sha256='f05d91ee76ee8a97ae5ab3bfa092167a8ee560c083255f142e6c453f2edf7ab3'),'global02_snapshot_pin')
    review_raw=read(BASE/'psec-lpac-identity-actual-02-independent-review.json');need(len(review_raw)==27938 and sha(review_raw)==ACTUAL_REVIEW_SHA,'actual02_review_pin')
    review=decode(review_raw);need(review['observed']['safe_failure_label']=='child_not_in_owned_job'
        and review['job_failure_boundary']['failed_job']=='unknown-inner-or-named-outer'
        and review['job_failure_boundary']['isprocessinjob_call_succeeded_but_result_false'] is True,'job_failure_not_which_job')
    ci_raw=read(BASE/'ci-psec-identity-39873635408-full.txt');need(len(ci_raw)==CI_BYTES and sha(ci_raw)==CI_SHA,'decoded02_ci_log_pin')
    pure=decode(read(BASE/'psec-lpac-integrated-pure-02.json'));tests=pure['tests']
    need(pure['runtime_source_sha256']==CLOSURE and pure['runtime_source_count']==36 and tests['tests']==863
        and tests['duration_seconds']==49.893 and tests['failures']==tests['errors']==0 and tests['skipped']==2 and tests['linux_executed'] is False,'integrated863_receipt')
    pure_raw=read(BASE/'psec-lpac-main-pure-02.log');need(metadata(pure_raw)==dict(bytes=tests['log_bytes'],sha256=tests['log_sha256']),'integrated863_log_pin')
    pins={
        'psec-lpac-python-candidate-02.patch':'b51897eff725c22f84e0863988936099d581462cb0dd16bf31d56a594ab39842',
        'psec-lpac-python-candidate-freeze-02.json':'41b431c5001fe393a395c18024f2fc15dd89458b07e9d1c038d62d763e9fe96e',
        'psec-lpac-python-source-closure-02.json':CLOSURE,
        'psec-lpac-python-pure-03.log':'8ddd49b49f8c343681da56181099c43a232c5c5005b0a73d761dde26af805417',
        'psec-lpac-source02-independent-review-01.json':'6ae7e211e2d5c694c237b01dfdf4afa64ed598a50a3706f54866bb3e680bebcc',
        'psec-lpac-identity-actual-02-independent-review.json':ACTUAL_REVIEW_SHA,
        'psec_lpac_joblist_constraints_02.json':'bf4cdb39c309eb67a243aeffe9f508d7e71c96e4087ed135d82933c7b932b8cf',
        'psec_lpac_job_query_contract_03.json':'08916f690e3dcb76c80faac935280f1a5774b272e8c2f161b4773f836132bcdc',
        'psec-lpac-integrated-pure-02.json':'c344aee51ab13d93700d08f6b615e15012ffd2933e5f2d653fbfc145523d42e8'}
    for name,digest in pins.items():need(sha(read(BASE/name))==digest,'review02_input_pin')
    freeze=decode(read(BASE/'psec-lpac-python-candidate-freeze-02.json'));need(freeze['source_sha256']==CLOSURE
        and freeze['pure']['tests']==33 and freeze['pure']['failures']==freeze['pure']['errors']==freeze['pure']['skipped']==0,'targeted33_receipt')
    for name,row in freeze['files'].items():need(metadata(read(REPO/name))==dict(bytes=row['bytes'],sha256=row['sha256']),'installed_source02_frozen_byte')
    # Protect every existing01 publication and both original actual archives;
    # a source02 cleanup receipt never repairs or rewrites the old unknown.
    immutable={}
    def remember(path):
        path=Path(path);raw=read(path,4*1024*1024)
        if path in immutable:need(immutable[path]==raw,'immutable_duplicate_consistency')
        immutable[path]=raw;return raw
    for index_name in ('psec-lpac-identity-local-01-evidence-index.json','psec-lpac-identity-local-01-publication-index.json'):
        raw=remember(OUT/index_name)
        for row in decode(raw)['files']:
            blob=remember(REPO/row['path']);need(metadata(blob)==dict(bytes=row['bytes'],sha256=row['sha256']),'immutable01_index_members')
    old_checkpoint_path=OUT/'psec-lpac-identity-local-01-checkpoint.json';old_checkpoint=decode(remember(old_checkpoint_path))
    need(old_checkpoint['broker_outcome_unknown'] is old_checkpoint['recovery_required'] is True
        and old_checkpoint['worker_report_available'] is False,'old01_unknown_preserved')
    old01_public=remember(OUT/'psec-lpac-identity-local-01-public.json');need(sha(old01_public)=='cc562d1b045fea336c4257051faa52e63aa415d91556a4ea84f18aa363652f9c','old01_public_pin')
    old_review_index_path=OUT/'psec-lpac-identity-source-review-01/index.json';old_review_index=remember(old_review_index_path)
    for row in decode(old_review_index)['files']:
        blob=remember(REPO/row['path']);need(metadata(blob)==dict(bytes=row['bytes'],sha256=row['sha256']),'old_review01_index_member')
    for path in actual_paths:remember(path)
    dns_doc=REPO/'docs/validation/2026-10-23-lpac-semantic-dns-02.md';dns_public=OUT/'lpac-semantic-dns-local-02-public.json'
    need(sha(remember(dns_doc))=='a4c4ca167fab7bf2e5071f0b676d45b2eaf68380146d5ce22ccce26c9306b759'
        and sha(remember(dns_public))=='757ad3b8c48f7f4d6e4d6aab9feaef4915dc54b39cf1977484eed6119fcc744f','immutable_dns02_pins')
    remember(OUT/'lpac-semantic-dns-local-02-checkpoint.json');remember(REPO/'docs/validation/2026-10-23-psec-lpac-identity-01.md')
    old_progress_raw=read(OUTPUT);progress=decode(old_progress_raw);dns_checkpoint=copy.deepcopy(progress['DNS最新实测'])
    old_psec=copy.deepcopy(progress['PSEC_LPAC最新实测'])
    need(old_psec['original_public']['sha256']==sha(old01_public) and old_psec['broker_outcome_unknown'] is old_psec['recovery_required'] is True,'outputs01_original_preserved')
    need(dns_checkpoint['original_status']=='observed' and dns_checkpoint['selected_api']['api_status']==dns_checkpoint['selected_api']['query_status']==5
        and dns_checkpoint['existing_g_psec_dns_api_leak_remains_true'] is True,'existing_dns02_and_old_g_leak')
    planned={};copies=[]
    def add(path,raw):
        need(path not in planned,'duplicate_publication_target');view,edits=public_text(raw);need(view==raw and not edits,'generated_safe_lf');planned[path]=raw
    def copy_file(name,destination=None,pinned=None):
        raw=read(BASE/name);need(pinned is None or sha(raw)==pinned,'copy02_pin');view,edits=public_text(raw)
        target_name=destination or Path(name).name
        if edits:
            p=Path(target_name);target_name=p.stem+'-public-view'+p.suffix
        target=FOLDER/target_name;need(target not in planned,'duplicate_source_review_copy');planned[target]=view
        copies.append(dict(source_work_path='work/'+name,public_path=target.relative_to(REPO).as_posix(),raw_original=metadata(raw),
            public_copy=metadata(view),byte_exact_copy=view==raw,view_changes=edits,raw_private_log_published=False,
            copy_category='public-text-view' if edits else 'byte-exact-safe-artifact'))
        return target,view
    selected=list(pins)+['run_psec_python_pure_03.py','review_psec_lpac_source02_01.py','psec-lpac-main-pure-02.log',
        'test_psec_lpac_integrated_02.ps1','verify_psec_lpac_actual_02.py','psec-lpac-identity-02-archiver-reader-check.json','stage_psec_lpac_source_02.py']
    for name in selected:copy_file(name,'actual02-independent-review.json' if name=='psec-lpac-identity-actual-02-independent-review.json' else None,pins.get(name))
    ci_path,ci_view=copy_file('ci-psec-identity-39873635408-full.txt','ci-39873635408-decoded.log',CI_SHA)
    ci=dict(schema_version=1,stage='read-only-psec-identity-source02-auto-ci-summary',source_commit=COMMIT,run_id=39873635408,
        job_id=120153800366,url='https://github.com/Shermanxwz/Rule-proxy-Web/actions/runs/39873635408',event='push',status='completed',conclusion='success',
        tests_run=863,seconds=55.383,failures=0,errors=0,skips=0,gated_runtime_steps_skipped=[5,6,7,8,9],
        native_actor_executed=False,cpse_experiment_executed=False,workflow_dispatched=False,workflow_rerun=False,
        decoded_original=dict(bytes=CI_BYTES,sha256=CI_SHA,kept_in_work=True),published_view=repo_ref(ci_path,ci_view),
        actual02_result_is_separate_and_inconclusive=True,pure_or_ci_success_is_not_runtime_acceptance=True)
    add(FOLDER/'ci-39873635408-summary.json',encode(ci));add(FOLDER/'publication.py',read(Path(__file__),128*1024))
    review_index=dict(schema_version=1,stage='psec-lpac-identity-source-review-02-index',source_commit=COMMIT,runtime_source_sha256=CLOSURE,
        runtime_source_count=36,incremental_source_file_count=4,bridge_native_source_count=6,bridge_dependency_count=31,native_or_dll_rebuilt=False,
        unchanged_shared_native_build_review=repo_ref(old_review_index_path,old_review_index),actual_index=repo_ref(actual_index_path,actual_index_raw),
        files=[repo_ref(p,r) for p,r in planned.items()],original_copy_provenance=copies,index_self_hash_excluded=True,
        source_review_does_not_override_actual_failure=True,forensic_alone_is_unvalidated=True,old01_unknown_not_repaired=True,
        job_membership_false_role_unknown=True,all_attributes_ignored_not_inferred=True,
        raw_dll_binary_or_private_identity_published=False,main_source_or_native_api_or_experiment_run=False)
    add(FOLDER/'index.json',encode(review_index))
    doc_path=REPO/'docs/validation/2026-10-23-psec-lpac-identity-02.md';doc_raw=DOCUMENT.encode('utf8');add(doc_path,doc_raw)
    checkpoint_path=OUT/'psec-lpac-identity-local-02-checkpoint.json'
    checkpoint=dict(schema_version=1,stage='psec-lpac-identity02-known-cleanup-job-admission-failure-checkpoint',source_commit=COMMIT,source_sha256=CLOSURE,
        original_public=repo_ref(public_path,public_raw),document=repo_ref(doc_path,doc_raw),source_review_index=repo_ref(FOLDER/'index.json',planned[FOLDER/'index.json']),
        evidence_index=repo_ref(actual_index_path,actual_index_raw),status='inconclusive',failure='admission',worker_report_available=True,
        worker_bound=True,worker_exit_code=0,outer_kernel_cleanup_confirmed=True,known_caller_resource_cleanup_confirmed=True,
        cpse_create_hresult=0,first_constructor_complete_pi=True,first_constructor_return_status=0,first_arm_primary_observed=False,
        first_arm_identity_admitted=False,first_arm_assigned=False,first_arm_held_exit_code=1,first_arm_never_resumed=True,
        failed_gate_label='child_not_in_owned_job',job_query_api_success=True,job_membership=False,failed_job='unknown-inner-or-named-outer',
        job_query_conclusion_basis='Source-bound GateFailure branch; separate per-Job query tuple not saved.',
        job_checks_not_separately_recorded=True,atomic_job_predicate_unchanged=True,post_assignment_substitution_authorized=False,
        all_attributes_ignored_not_inferred=True,original_returned_receipt_count=5,durable_intent_count=6,
        forensic_equals_original_valid_result=True,forensic_alone_is_unvalidated=True,forensic_used_for_public_qualification=False,
        accesscheck_proof_count=0,lpac_second_arm_attempted=False,ac_lpac_four_matrix_pair_qualified=False,
        void_close_raw_receipt_available=True,void_close_invoked_once=True,void_close_returned_normally=True,module_unbind_confirmed=True,
        observation_complete=False,broker_outcome_unknown=False,recovery_required=False,external_environment_absence_verified=False,
        broker_cancellation_proven=False,caller_crash_cleanup_equivalence_tested=False,creation_transfer_crash_gap_resolved=False,
        old01_checkpoint=repo_ref(old_checkpoint_path,immutable[old_checkpoint_path]),old01_broker_outcome_unknown=True,old01_recovery_required=True,
        old01_unknown_not_reinterpreted=True,old_opaque_reopen_replay_or_retry_close_authorized=False,
        global_snapshot_bytes=7378,global_snapshot_sha256='f05d91ee76ee8a97ae5ab3bfa092167a8ee560c083255f142e6c453f2edf7ab3',
        global_before_after_byte_equal=True,snapshot_objects=['firewall_profiles','dns','routes','user_proxy'],nrpt_in_snapshot=False,
        model2_policy_compared=False,network_tested=False,dns_tested=False,proxy_tested=False,product_acceptance=False,linux_equivalence_qualified=False,
        existing_g_psec_api_dns_leak_remains_true=True,standalone_semantic_dns02_success_preserved=True,source_automatic_ci=ci)
    add(checkpoint_path,encode(checkpoint))
    history_key='此前PSEC_LPAC01实测'
    need(history_key not in progress or progress[history_key]==old_psec,'existing_old01_history_consistency')
    progress[history_key]=copy.deepcopy(old_psec)
    progress['PSEC_LPAC最新实测']=copy.deepcopy(checkpoint);progress['PSEC_LPAC最新实测']['checkpoint']=repo_ref(checkpoint_path,planned[checkpoint_path])
    progress['最新尝试']={'名称':'psec-lpac-identity-local-02','源码提交':COMMIT,'状态':'inconclusive','失败门':'admission / child_not_in_owned_job',
        'CPSE创建S_OK':True,'首臂创建完整PI':True,'失败Job':'未知：inner 或 named outer，原件未分离查询结果',
        'primary身份已观察':False,'LPAC第二臂已尝试':False,'矩阵proof数':0,'原始返回收据数':5,'原始意图数':6,
        'worker退出码':0,'首臂held退出码':1,'本轮已知资源清理完成':True,'VOIDclose单次正常返回':True,
        '本轮opaque结果未知':False,'本轮需要恢复':False,'外部环境absence已证明':False,'caller崩溃等价清理已证明':False,
        '旧01opaque未知仍保留':True,'旧01恢复要求仍保留':True,'全局四对象baseline字节相等':True,
        '两臂身份验收':False,'网络测试':False,'产品验收':False,'原G_PSEC_API_DNS泄漏仍成立':True,'standalone_DNS02_API_query5_5保持独立':True}
    progress['当前阻断']='PSEC+LPAC identity02 的 CPSE/首臂创建返回成功，但 exact Job membership 为 false；尚不能区分 inner/outer。未进入 primary/LPAC/矩阵，原 atomic 门不放宽；潜在创建交接崩溃监督空档仍需先审查。旧01未知/恢复及原 G/PSEC DNS API 泄漏均保留。'
    progress['状态']='PSEC+LPAC identity02 在 Job 准入停止，已知本轮资源闭合；旧01仍未知。standalone DNS02 的 API/query5/5 独立成立，原 G/PSEC DNS API 泄漏未修复。'
    progress['源码提交']=COMMIT
    allowed_changes={'PSEC_LPAC最新实测',history_key,'最新尝试','当前阻断','状态','源码提交'};before=decode(old_progress_raw)
    need(all(progress[k]==value for k,value in before.items() if k not in allowed_changes) and progress['DNS最新实测']==dns_checkpoint,'all_other_progress_fields_preserved')
    progress_raw=encode(progress);view,edits=public_text(progress_raw);need(view==progress_raw and not edits,'safe_outputs_progress')
    for link in re.findall(r'\]\(([^)]+)\)',DOCUMENT):
        if link.startswith('https://'):continue
        target=(doc_path.parent/link).resolve();need(target in planned or target.is_file(),'new_doc_link:'+link)
    publication_index_path=OUT/'psec-lpac-identity-local-02-publication-index.json'
    add(publication_index_path,encode(dict(schema_version=1,stage='psec-identity02-publication-index',source_commit=COMMIT,
        original_actual_index=repo_ref(actual_index_path,actual_index_raw),files=[repo_ref(p,r) for p,r in planned.items()],
        outputs_progress=dict(path='outputs/windows-isolation-progress.json',before=metadata(old_progress_raw),after=metadata(progress_raw)),
        immutable_older_and_actual_files=[repo_ref(p,r) for p,r in immutable.items()],index_self_hash_excluded=True,
        actual02_failure_and_old01_unknown_preserved=True,no_source_or_runtime_or_recovery_execution=True)))
    for path in planned:need(not path.exists(),'fresh02_publication_target')
    need(not FOLDER.exists(),'fresh02_source_review_folder')
    need(all(read(path,4*1024*1024)==raw for path,raw in immutable.items()) and read(OUTPUT)==old_progress_raw,'unchanged_existing_inputs')
    paths=sorted({*actual_paths,*planned})
    return planned,progress_raw,old_progress_raw,immutable,paths,dict(planned_repository_files=len(planned),actual_archive_files_preserved=len(actual_paths),
        source_review_copies=len(copies),views_changed=sum(not x['byte_exact_copy'] for x in copies),source_commit=COMMIT,
        original02_admission_failure=True,original02_known_cleanup=True,old01_unknown_preserved=True,
        immutable_dns02_preserved=True,publication_written=False,native_or_experiment_or_cleanup_run=False)


def main(argv=None):
    parser=argparse.ArgumentParser(description=__doc__);parser.add_argument('--publish',action='store_true');a=parser.parse_args(argv)
    planned,progress,old_progress,immutable,paths,result=prepare()
    if a.publish:
        need(OUTPUT.parent.resolve()==(BASE.parent/'outputs').resolve(),'fixed_outputs_directory')
        for path in planned:path.parent.mkdir(parents=True,exist_ok=True)
        for path,raw in planned.items():
            with path.open('xb') as stream:need(stream.write(raw)==len(raw),'publication_write')
            need(read(path,4*1024*1024)==raw,'publication_readback')
        need(read(OUTPUT)==old_progress,'outputs_progress_changed')
        temp=OUTPUT.with_name('.windows-isolation-progress-psec02.tmp');need(not temp.exists(),'fresh02_output_temporary')
        with temp.open('xb') as stream:need(stream.write(progress)==len(progress),'progress_write')
        os.replace(temp,OUTPUT);need(read(OUTPUT)==progress,'progress_readback')
        need(all(read(path,4*1024*1024)==raw for path,raw in immutable.items()),'immutable01_dns_actuals_unchanged')
        listing=BASE/'stage_psec_lpac_identity_publication_02_paths.txt';raw=''.join(p.relative_to(REPO).as_posix()+'\n' for p in paths).encode('ascii')
        with listing.open('xb') as stream:need(stream.write(raw)==len(raw),'explicit_stage_path_list')
        result['publication_written']=True
    print(json.dumps(result,sort_keys=True,ensure_ascii=True))
if __name__=='__main__':main()


