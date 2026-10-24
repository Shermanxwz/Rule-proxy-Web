"""Prepare/publish only file evidence and documentation for PSEC identity01.

Default is read-only planning. --publish is for the reviewing root only.
No source implementation, experiment, API, network, CI, cleanup or recovery
entry is imported or executed. Existing actual01 and DNS02 evidence is frozen.
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
FOLDER=OUT/'psec-lpac-identity-source-review-01'
COMMIT='1c83029245e889b2c950ca5dbaa0da675a287c09'
CLOSURE='7dd12aaf5c8727c325e184f69393072e13e0b1772aa1be03318adf7e1d77951a'
PUBLIC_SHA='cc562d1b045fea336c4257051faa52e63aa415d91556a4ea84f18aa363652f9c'
PUBLIC_BYTES=1660
ACTUAL_REVIEW_SHA='94836bd02cb67e2082ac1f00c1b600fc933c2dc464a125bc19cf9c79b99f6165'
CI_SHA='787bd9011f2b4894c14950ba8d29f03bf9955fda2e926dfe9d8e88bd91877735'
CI_BYTES=203905

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


DOCUMENT='''# PSEC + LPAC identity01：报告失败，原未知状态保留

**本轮为 `inconclusive`，没有最终 worker report，也没有 AC/LPAC 四矩阵验收结果。** 原 public 的 `failure=report`、`broker_outcome_unknown=true`、`recovery_required=true` 保持不变。外层进程和 Job 清理完成不等于 opaque CPSE 环境已不存在。本轮没有运行 actor 代码或网络，不能当作代理或 DNS 隔离通过。

受测源码是 `1c83029245e889b2c950ca5dbaa0da675a287c09`，36 文件运行时闭包为 `7dd12aaf5c8727c325e184f69393072e13e0b1772aa1be03318adf7e1d77951a`。[原 public](../../verification/windows-2026-10-22/psec-lpac-identity-local-01-public.json) 为 1660 字节、SHA256 `cc562d1b045fea336c4257051faa52e63aa415d91556a4ea84f18aa363652f9c`；[原件索引](../../verification/windows-2026-10-22/psec-lpac-identity-local-01-evidence-index.json)绑定 plan/spec、staged Git blob/LF 源码、两份 manifest、原始 outer launch 与私有日志的字节和摘要。

## 实际看到了什么

worker 以退出码 1 结束，外层 Job 空、Job 和句柄关闭、进程退出确认均成立。`worker-report.json` 缺失；stderr 的固定错误为 `ValueError: cpse_task_number`，发生在 `Cell.execute()` 及其 cleanup 已返回后的结果校验。源码把实际 FILETIME 代际值用默认 DWORD 上限校验，因而报告器拒绝它。这解释最终报告失败，**不能解释更早的首个 AC admission 为何未进入第二臂**；本轮没有保留下该早期失败的最终私有结果，具体原因仍未知。

磁盘上只有六份按顺序闭合的意图：`bind`、`create`、`ac`、`stop`、`close`、`unbind`。它们已与 config SHA、fresh run、原 F/D 和文件名绑定。[组件投影](../../verification/windows-2026-10-22/psec-lpac-identity-local-01-component-projection.json)明确将这些记录标为 intent-only；它们不是原始 API 返回、PI、held token 或 AccessCheck 证明。缺失的 task/proof 不补齐，关闭调用与正常返回次数记为未知，不能用 0 冒充未调用。

依照冻结源码的清理分支，能走到 `unbind` 意图，条件性地说明此前代码接受了 `close` 的正常返回字段。这个结论是[独立只读审查](../../verification/windows-2026-10-22/psec-lpac-identity-source-review-01/actual01-independent-review.json)的**源码控制流推断**，不是保存下来的 raw close receipt，更不是环境 absence、broker cancellation 或一次独立恢复完成的证明。原 public 的未知和恢复要求不会被这一推断回写消除。

before/after 两份全局快照均为 7378 字节、SHA256 `f05d91ee76ee8a97ae5ab3bfa092167a8ee560c083255f142e6c453f2edf7ab3`，原始字节及 JSON 对象相等。该比较只覆盖 firewall profiles、DNS、routes、user proxy 四类对象，不含 NRPT，不证明完整或持续的全局状态不存在变化。原始快照和私有日志未公开。

## 本轮命题与可追溯构建

这是独立的 `identity-only-deny-all-v1`：PSEC schema 1.1，显式 PNCS capability、Agentic 由 OS 身份观测，inputs 只读，其余文件范围为空，egress/ingress/host-loopback 默认拒绝，无 proxy/peer。预声明一份 CPSE 环境、同映像/cwd/environment/inner+outer Jobs，两臂只改变 AAP policy 0/1，均 `CREATE_SUSPENDED` 且永不 resume；不另加 `SECURITY_CAPABILITIES` 身份源，不创建 standalone profile 或补 ACL。原 120 秒 root / 115 秒 worker 预算不续期。**本轮尚未取得两臂完整观察，也没有复刻 Model2 的代理策略。**

[源码审查索引](../../verification/windows-2026-10-22/psec-lpac-identity-source-review-01/index.json)保存原 Python、native03 和纯测试 portability patches/freezes、独立审查、依赖 pins、编译/静态 PE 读者及测试证据。compile02 在编译前冻结 6 个 native source 与 31 个依赖；`/MT` x64 DLL 为 214016 字节、SHA256 `9574f93eb562a858b207412f9f538b15bfbf329b1df284b3266496b4c2cf2ba5`，仅静态导入 KERNEL32，8 个闭合 exports。DLL binary 与可能携带用户路径的 raw 编译日志不公开。更早 compile01 是 mutable WIP 失败，没有被追认成最终源码的精确构建。

本机身份相关纯测试为 857 项、48.776 秒、零失败、2 个原有 symlink 权限 skips；新测试未 skip。native pure 包括 327 个生产状态/spec 断言及 4 个 Python 原始 spec 字节到官方生成 C++ 验证器的交叉检查。[受测源码自动 CI](https://github.com/Shermanxwz/Rule-proxy-Web/actions/runs/39872306319)为 857 项、59.713 秒、零 skips；5–9 号 gated runtime 步骤均跳过。纯测试、编译和 CI 成功均不抵消本轮实际报告失败。未在本机运行 Linux 测试。部分日志和补丁提供脱敏公开视图，原始与公开摘要分别记录；可执行源码以受测提交的 Git blob 为准。

## 下一步与仍然成立的边界

策略允许使用另行审查和提交的新源码，修正 FILETIME/HANDLE 宽度并增加每次返回 receipt 与校验前的 forensic 保留，然后以新 plan、nonce、stage、spec 和原始预算进行单次独立 02 诊断。forensic 文件只用于诊断，不能绕过最终 validator 或资格门；不重用、重开、数字重放或重试关闭旧 opaque 值，不自动重试，不启动 actor、网络、driver、服务重启或全局配置变更。01 的历史未知始终保留；02 若产生新证据也不能倒推 01 已恢复。

[standalone semantic-LPAC DNS02](2026-10-23-lpac-semantic-dns-02.md)的 API/query `5/5` 与前后正控成功仍是独立结果；[原 G/PSEC DNS API 泄漏](2026-10-23-selected-dns-standard53.md)也仍成立。PSEC+LPAC 的完整身份组合、相同代理策略、真实代理链与 DNS 矩阵尚未验收，`model2_policy_compared`、`proxy_tested`、`dns_tested`、`product_acceptance` 均为 false。
'''


def prepare():
    public_path=OUT/'psec-lpac-identity-local-01-public.json';public_raw=read(public_path,8192)
    need(len(public_raw)==PUBLIC_BYTES and sha(public_raw)==PUBLIC_SHA,'original_public_pin')
    public=decode(public_raw)
    need(public['status']=='inconclusive' and public['failure']=='report' and public['identity_observation'] is None
        and public['broker_outcome_unknown'] is True and public['recovery_required'] is True
        and public['observation_complete'] is False,'original_unknown_preserved')
    actual_index_path=OUT/'psec-lpac-identity-local-01-evidence-index.json';actual_index_raw=read(actual_index_path)
    actual_index=decode(actual_index_raw);need(actual_index['source_commit']==COMMIT and actual_index['source_sha256']==CLOSURE,'actual_source_binding')
    actual_paths=[]
    for row in actual_index['files']:
        path=REPO/row['path'];raw=read(path,4*1024*1024)
        need(len(raw)==row['bytes'] and sha(raw)==row['sha256'],'frozen_actual_archive_member');actual_paths.append(path)
    actual_paths.append(actual_index_path)
    need(len(actual_paths)==13,'exact13_actual_archive_files')
    component=decode(read(OUT/'psec-lpac-identity-local-01-component-projection.json'))
    global_value=decode(read(OUT/'psec-lpac-identity-local-01-global-projection.json'))
    need(component['worker_report_absence_preserved'] is True and component['worker_report_available'] is False
        and component['operations']==[] and component['proofs']==[] and component['task_observations']==[]
        and component['void_close_invoked_count'] is component['void_close_returned_normally_count'] is None,'no_missing_result_fabricated')
    need([row['action'] for row in component['intents']]==['bind','create','ac','stop','close','unbind']
        and all(row['intent_only'] is True and row['api_entry_or_return_receipt_available'] is False for row in component['intents']),'six_intents_not_returns')
    need(component['outer_launch']['exit_code']==1 and component['outer_launch']['cleanup_error_count']==0
        and all(component['outer_launch']['cleanup'][k] is True for k in ('job_closed','handles_closed','job_empty','process_exit_confirmed')),'outer_kernel_cleanup')
    need(global_value['observed'] is True and global_value['raw_bytes_identical'] is True and global_value['whole_json_objects_equal'] is True
        and global_value['before']==global_value['after']==dict(bytes=7378,sha256='f05d91ee76ee8a97ae5ab3bfa092167a8ee560c083255f142e6c453f2edf7ab3'),'global_snapshot_pin')
    actual_review=read(BASE/'psec-lpac-identity-actual-01-independent-review.json')
    need(len(actual_review)==29404 and sha(actual_review)==ACTUAL_REVIEW_SHA,'independent_actual_review_pin')
    ci_raw=read(BASE/'ci-psec-identity-39872306319-full.txt')
    need(len(ci_raw)==CI_BYTES and sha(ci_raw)==CI_SHA,'decoded_ci_log_pin')
    pure=decode(read(BASE/'psec-lpac-integrated-pure-01.json'));tests=pure['tests']
    need(pure['runtime_source_sha256']==CLOSURE and pure['runtime_source_count']==36 and tests['tests']==857
        and tests['duration_seconds']==48.776 and tests['failures']==tests['errors']==0 and tests['skipped']==2,'integrated857_receipt')
    pure_raw=read(BASE/'psec-lpac-main-pure-01.log')
    need(len(pure_raw)==tests['log_bytes'] and sha(pure_raw)==tests['log_sha256'],'integrated_raw_log_commitment')
    patch_pins={
        'psec-lpac-python-candidate-01.patch':'98a0883d76eb65b240e8063391665d8888b05bc8746a93b144fc0f06fc259d1b',
        'psec-lpac-native-candidate-03.patch':'eb392776f656c556adf2b504771ddeba0f45a0fb864cdee4dbf2ca8bf4d81683',
        'lpac-tests-portability-01.patch':'e4b8c71eceb10c07e14c9ea8ebfd094ed447281e15a718ef4d9be22ecd4eadd7'}
    for name,digest in patch_pins.items():need(sha(read(BASE/name))==digest,'original_patch_pin')
    immutable_paths=[REPO/'docs/validation/2026-10-23-lpac-semantic-dns-02.md',
        OUT/'lpac-semantic-dns-local-02-checkpoint.json',OUT/'lpac-semantic-dns-local-02-public.json']
    immutable={path:read(path) for path in immutable_paths}
    need(sha(immutable[immutable_paths[0]])=='a4c4ca167fab7bf2e5071f0b676d45b2eaf68380146d5ce22ccce26c9306b759'
        and sha(immutable[immutable_paths[2]])=='757ad3b8c48f7f4d6e4d6aab9feaef4915dc54b39cf1977484eed6119fcc744f','immutable_dns02_pins')
    old_progress_raw=read(OUTPUT);progress=decode(old_progress_raw);dns_checkpoint=copy.deepcopy(progress['DNS最新实测'])
    need(dns_checkpoint['original_status']=='observed' and dns_checkpoint['selected_api']['api_status']==5
        and dns_checkpoint['selected_api']['query_status']==5 and dns_checkpoint['existing_g_psec_dns_api_leak_remains_true'] is True,'existing_dns02_checkpoint')
    planned={};copy_records=[]
    def add(path,raw):
        need(path not in planned,'duplicate_publication_target');view,edits=public_text(raw)
        need(view==raw and not edits,'new_generated_publication_is_already_safe_lf');planned[path]=raw
    def copy_file(relative,destination=None,*,pinned=None):
        path=BASE/relative;raw=read(path);need(pinned is None or sha(raw)==pinned,'selected_copy_pin')
        view,edits=public_text(raw);name=destination or path.name
        if edits:
            p=Path(name);name=p.stem+'-public-view'+p.suffix
        target=FOLDER/name;need(target not in planned,'duplicate_review_copy');planned[target]=view
        copy_records.append(dict(source_work_path='work/'+relative,public_path=target.relative_to(REPO).as_posix(),
            raw_original=metadata(raw),public_copy=metadata(view),byte_exact_copy=view==raw,view_changes=edits,
            raw_private_log_published=False,copy_category='public-text-view' if edits else 'byte-exact-safe-artifact'))
        return target,view
    selected=[
        'psec-lpac-python-candidate-01.patch','psec-lpac-python-candidate-freeze-01.json','psec-lpac-python-source-closure-01.json',
        'psec-lpac-native-candidate-03.patch','psec-lpac-native-candidate-freeze-03.json','psec-lpac-native-input-closure-03.json',
        'psec-lpac-identity-bridge-abi-01.json','lpac-tests-portability-01.patch','lpac-tests-portability-freeze-01.json',
        'psec-lpac-native-independent-review-01.json','psec-lpac-final-independent-review-01.json',
        'psec-lpac-dependency-independent-review-01.json','psec-lpac-dependency-primary-01.json',
        'psec-lpac-identity-actual-01-independent-review.json','psec-lpac-integrated-pure-01.json',
        'psec-lpac-python-pure-02.log','psec-lpac-bridge-native-pure-03.log','psec-lpac-main-pure-01.log',
        'lpac-tests-portability-missing-helpers-02.log','lpac-tests-portability-native-host-02.log',
        'psec-lpac-bridge-compile-02/static-pe-review.json','compile_psec_lpac_bridge_02.ps1','inspect_psec_lpac_bridge_compile_02.py',
        'read_processmodel_pe_metadata_01.py','processmodel-pe-static-metadata-01.json','check_psec_python_spec_with_flatc_01.py',
        'download_psec_lpac_flatbuffers_deps.ps1','verify_extract_psec_lpac_flatbuffers_deps.py','psec-lpac-bridge-deps/verification.json',
        'review_psec_lpac_native_01.py','review_psec_lpac_final_01.py','verify_psec_lpac_actual_01.py',
        'test_psec_lpac_integrated_01.ps1','test_psec_lpac_bridge_native_01.ps1','run_psec_python_pure_02.py']
    for relative in selected:
        name=({'psec-lpac-bridge-deps/verification.json':'dependency-extraction-verification.json',
            'psec-lpac-identity-actual-01-independent-review.json':'actual01-independent-review.json'}).get(relative)
        copy_file(relative,name,pinned=patch_pins.get(relative))
    ci_path,ci_view=copy_file('ci-psec-identity-39872306319-full.txt','ci-39872306319-decoded.log',pinned=CI_SHA)
    omitted=[]
    for relative,reason in [('psec-lpac-bridge-compile-01/compile.log','Mutable WIP failed compile; no precompile immutable input snapshot.'),
            ('psec-lpac-python-pure-01.log','Earlier failed ordinary-shell test attempt; compiler environment was unavailable.'),
            ('lpac-tests-portability-baseline-01.log','Intentional Windows simulation with ctypes error helpers removed; failed baseline.')]:
        raw=read(BASE/relative);omitted.append(dict(source_work_path='work/'+relative,**metadata(raw),raw_log_published=False,reason=reason))
    add(FOLDER/'historical-failure-metadata.json',encode(dict(schema_version=1,stage='psec-source-review-omitted-private-failure-logs',
        files=omitted,compile01_final_source_binding_claimed=False,compile02_snapshot_is_separate=True,
        actual01_report_failure_preserved=True,failed_logs_or_dll_binary_published=False)))
    ci=dict(schema_version=1,stage='read-only-psec-identity-source-auto-ci-summary',source_commit=COMMIT,run_id=39872306319,
        job_id=120149423016,url='https://github.com/Shermanxwz/Rule-proxy-Web/actions/runs/39872306319',event='push',
        status='completed',conclusion='success',tests_run=857,seconds=59.713,failures=0,errors=0,skips=0,
        gated_runtime_steps_skipped=[5,6,7,8,9],native_actor_executed=False,cpse_experiment_executed=False,
        workflow_dispatched=False,workflow_rerun=False,decoded_original=dict(bytes=CI_BYTES,sha256=CI_SHA,kept_in_work=True),
        published_view=repo_ref(ci_path,ci_view),actual01_result_is_separate_and_failed=True,
        pure_or_ci_success_is_not_runtime_acceptance=True)
    add(FOLDER/'ci-39872306319-summary.json',encode(ci))
    add(FOLDER/'publication.py',read(Path(__file__),128*1024))
    review_index=dict(schema_version=1,stage='psec-lpac-identity-source-review-01-index',source_commit=COMMIT,runtime_source_sha256=CLOSURE,
        runtime_source_count=36,native_source_count=6,native_dependency_count=31,compile02_dll_sha256='9574f93eb562a858b207412f9f538b15bfbf329b1df284b3266496b4c2cf2ba5',
        actual_index=repo_ref(actual_index_path,actual_index_raw),files=[repo_ref(p,r) for p,r in planned.items()],original_copy_provenance=copy_records,
        omitted_failed_logs=omitted,index_self_hash_excluded=True,source_review_does_not_override_actual_failure=True,
        historical_native_review_test_filename_note='Earlier review receipts retain their reviewed pre-identity-prefix test name; native03 promotion uses test_windows_identity_psec_lpac_bridge_native.py.',
        archive01_reader_scope='Frozen actual01 has zero proof records. Future proof-bearing runs require a separate reader version; do not reuse or edit the archived reader.',
        raw_dll_binary_or_private_identity_published=False,main_source_or_native_api_or_experiment_run=False)
    add(FOLDER/'index.json',encode(review_index))
    doc_path=REPO/'docs/validation/2026-10-23-psec-lpac-identity-01.md';doc_raw=DOCUMENT.encode('utf8');add(doc_path,doc_raw)
    checkpoint_path=OUT/'psec-lpac-identity-local-01-checkpoint.json'
    checkpoint=dict(schema_version=1,stage='psec-lpac-identity01-partial-report-failure-checkpoint',source_commit=COMMIT,source_sha256=CLOSURE,
        original_public=repo_ref(public_path,public_raw),document=repo_ref(doc_path,doc_raw),source_review_index=repo_ref(FOLDER/'index.json',planned[FOLDER/'index.json']),
        evidence_index=repo_ref(actual_index_path,actual_index_raw),status='inconclusive',failure='report',worker_report_available=False,
        worker_exit_code=1,outer_kernel_cleanup_confirmed=True,first_ac_earlier_failure_unknown=True,
        observed_stderr_error='ValueError: cpse_task_number',report_validator_filetime_width_bug=True,final_worker_result_available=False,
        durable_intent_actions=['bind','create','ac','stop','close','unbind'],intent_only_not_api_return=True,
        ac_lpac_four_matrix_pair_qualified=False,lpac_arm_observed=False,network_tested=False,dns_tested=False,proxy_tested=False,
        observation_complete=False,broker_outcome_unknown=True,recovery_required=True,external_environment_absence_verified=False,
        broker_cancellation_proven=False,void_close_raw_receipt_available=False,void_close_source_controlflow_inference_only=True,
        original_unknown_not_reinterpreted=True,next_fresh02_independent_diagnostic_policy_allowed=True,
        old_opaque_reopen_replay_or_retry_close_authorized=False,global_snapshot_bytes=7378,
        global_snapshot_sha256='f05d91ee76ee8a97ae5ab3bfa092167a8ee560c083255f142e6c453f2edf7ab3',global_before_after_byte_equal=True,
        snapshot_objects=['firewall_profiles','dns','routes','user_proxy'],nrpt_in_snapshot=False,model2_policy_compared=False,
        existing_g_psec_api_dns_leak_remains_true=True,standalone_semantic_dns02_success_preserved=True,
        product_acceptance=False,linux_equivalence_qualified=False,source_automatic_ci=ci)
    add(checkpoint_path,encode(checkpoint))
    progress['PSEC_LPAC最新实测']=copy.deepcopy(checkpoint)
    progress['PSEC_LPAC最新实测']['checkpoint']=repo_ref(checkpoint_path,planned[checkpoint_path])
    progress['最新尝试']={'名称':'psec-lpac-identity-local-01','源码提交':COMMIT,'状态':'inconclusive','报告缺失':True,
        '最终报错':'ValueError: cpse_task_number','首个AC更早失败原因':'未知，未保存最终私有结果','原始意图数':6,
        '意图不等于API返回':True,'外层worker退出码':1,'外层内核资源清理完成':True,'全局四配置对象与原baseline字节相等':True,
        'opaque环境结果未知':True,'需要恢复':True,'两臂身份验收':False,'LPAC实测证明':False,'网络测试':False,'产品验收':False,
        '原G_PSEC_API_DNS01明确泄漏仍成立':True,'standalone_DNS02成功仍为独立历史结果':True}
    progress['当前阻断']='PSEC+LPAC identity01 无最终报告；FILETIME 报告校验错误遮蔽首个 AC 的更早失败。原 opaque 未知和恢复要求保留；原 G/PSEC DNS API 泄漏仍未修复。'
    progress['状态']='PSEC+LPAC identity01 报告失败、opaque 未知；standalone DNS02 明确拒绝仍成立，原 G/PSEC DNS API 泄漏仍未修复。'
    progress['源码提交']=COMMIT
    need(progress['DNS最新实测']==dns_checkpoint,'immutable_dns02_checkpoint_field')
    progress_raw=encode(progress);view,edits=public_text(progress_raw);need(view==progress_raw and not edits,'safe_progress_json')
    # Every repository link in the new document resolves to planned or existing evidence.
    for link in re.findall(r'\]\(([^)]+)\)',DOCUMENT):
        if link.startswith('https://'):continue
        target=(doc_path.parent/link).resolve();need(target in planned or target.is_file(),'new_doc_relative_link:'+link)
    publication_index_path=OUT/'psec-lpac-identity-local-01-publication-index.json'
    add(publication_index_path,encode(dict(schema_version=1,stage='psec-identity01-publication-index',source_commit=COMMIT,
        original_actual_index=repo_ref(actual_index_path,actual_index_raw),files=[repo_ref(p,r) for p,r in planned.items()],
        outputs_progress=dict(path='outputs/windows-isolation-progress.json',before=metadata(old_progress_raw),after=metadata(progress_raw)),
        immutable_dns02=[repo_ref(p,r) for p,r in immutable.items()],index_self_hash_excluded=True,
        actual01_unknown_preserved=True,no_source_or_runtime_or_recovery_execution=True)))
    for path in planned:need(not path.exists(),'fresh_publication_target')
    need(not FOLDER.exists(),'fresh_source_review_folder')
    need(all(read(path)==raw for path,raw in immutable.items()) and read(OUTPUT)==old_progress_raw,'unchanged_existing_inputs')
    stage_paths=sorted({*actual_paths,*planned})
    return planned,progress_raw,old_progress_raw,immutable,stage_paths,dict(planned_repository_files=len(planned),
        actual_archive_files_preserved=len(actual_paths),source_review_copies=len(copy_records),views_changed=sum(not r['byte_exact_copy'] for r in copy_records),
        source_commit=COMMIT,original_broker_unknown=True,original_recovery_required=True,publication_written=False,
        immutable_dns02_preserved=True,native_or_experiment_or_cleanup_run=False)


def main(argv=None):
    parser=argparse.ArgumentParser(description=__doc__);parser.add_argument('--publish',action='store_true');a=parser.parse_args(argv)
    planned,progress,old_progress,immutable,stage_paths,result=prepare()
    if a.publish:
        need(OUTPUT.parent.resolve()==(BASE.parent/'outputs').resolve(),'fixed_outputs_directory')
        for path in planned:path.parent.mkdir(parents=True,exist_ok=True)
        for path,raw in planned.items():
            with path.open('xb') as f:need(f.write(raw)==len(raw),'publication_write')
            need(read(path,4*1024*1024)==raw,'publication_readback')
        need(read(OUTPUT)==old_progress,'outputs_progress_changed')
        temporary=OUTPUT.with_name('.windows-isolation-progress-psec01.tmp');need(not temporary.exists(),'fresh_output_temporary')
        with temporary.open('xb') as f:need(f.write(progress)==len(progress),'progress_write')
        os.replace(temporary,OUTPUT);need(read(OUTPUT)==progress,'progress_readback')
        need(all(read(path)==raw for path,raw in immutable.items()),'dns02_unchanged_after_publication')
        listing=BASE/'stage_psec_lpac_identity_publication_01_paths.txt'
        raw=''.join(p.relative_to(REPO).as_posix()+'\n' for p in stage_paths).encode('ascii')
        with listing.open('xb') as f:need(f.write(raw)==len(raw),'explicit_stage_path_list')
        result['publication_written']=True
    print(json.dumps(result,sort_keys=True,ensure_ascii=True))
if __name__=='__main__':main()
