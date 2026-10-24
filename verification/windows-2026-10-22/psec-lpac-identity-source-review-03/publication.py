"""Prepare/publish only file evidence and documentation for PSEC identity03.

Default is read-only planning. --publish is for the reviewing root only.
No source implementation, experiment, API, network, CI, cleanup or recovery
entry is imported or executed. Existing actual01/02, DNS02 and actual03 archives remain immutable.
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
FOLDER=OUT/'psec-lpac-identity-source-review-03'
COMMIT='4c5878ba0ffa6f4b938e26bf5c8c016b7042b333'
CLOSURE='cf09c9c86adf9f7af3fb3d71bdde6cd1fd4fa7000a8eb01cc5ebc71b3ea5d682'
PUBLIC_SHA='75f3198b40afc5b9919fd862b66ab14b023b4b30e4ab979b742cf3e315e734f6'
PUBLIC_BYTES=2083
INPUTS={'archive_psec_lpac_identity_03_pure_01.log': {'bytes': 864, 'sha256': '6006064f703975a0113fd827e2e10d3fe8f634ff81082867d63dae357470fe36'}, 'archive_psec_lpac_identity_03_readiness_02.json': {'bytes': 2541, 'sha256': 'f245efbedba3a680abef8b634c445e512c47954feb411b3993b30bf97adc2717'}, 'psec-lpac-identity-actual-03-independent-review.json': {'bytes': 29753, 'sha256': '9e70ae4ea7651d0c31ebd779dad05171f5cbf76d9d182f0e51ddfd56e4a65d83'}, 'psec-lpac-integrated-pure-03.json': {'bytes': 2255, 'sha256': '719fee52ac2cec526a7078207b43552b02f106c60fa1fa01088f35c727859793'}, 'psec-lpac-main-pure-03.log': {'bytes': 161424, 'sha256': 'ebe5e880950a04034504d353eb3dc9f2d6520c842007277251cfe305a25c03cb'}, 'psec-lpac-python-diagnostic-03.patch': {'bytes': 50091, 'sha256': '45caf7cad081c384b0317236b12839302af1a2c5df292e57015ad50924a936f8'}, 'psec-lpac-python-diagnostic-abi-03.json': {'bytes': 2259, 'sha256': '718aa67c16c07ded40ab0596c4eb0a844233873313b34651146f3464fac58f21'}, 'psec-lpac-python-diagnostic-freeze-03.json': {'bytes': 15196, 'sha256': '0fafbd55ebe54ea9ed13ac7705dec0b7baa8e0cc26f7971290219f8f6683c00d'}, 'psec-lpac-python-diagnostic-pure-03.log': {'bytes': 8558, 'sha256': 'aebb3470ce3854ff581adf9bda3452c66cee429b392bd67a44a550f40c8f9447'}, 'psec-lpac-source03-independent-review-01.json': {'bytes': 5943, 'sha256': '268eea37104b0580fb8f1abf31866e8ab03d6b2761ed689b126c02a1146239ea'}, 'review_psec_lpac_source03_01.py': {'bytes': 7981, 'sha256': 'e290c7f72aef7e4f9bc823482951eb77730bc52e6129a240ef8ff43a92034293'}, 'stage_psec_lpac_source_03.py': {'bytes': 14299, 'sha256': '5129144f079a0bb432588d4dcbac2dc32b953976cff80e732efc5059a59931cd'}, 'test_archive_psec_lpac_identity_03.py': {'bytes': 4456, 'sha256': 'afc57e6680896b059111bccaa0df4a448e8b31acec61641c1635b441848664e6'}, 'test_psec_lpac_integrated_03.ps1': {'bytes': 857, 'sha256': '4f5854d594124fc439803ecdd731781238572b29a6579c2bb7600c4cc49cbe3e'}, 'verify_psec_lpac_actual_03.py': {'bytes': 25076, 'sha256': 'c8294c4b385ed79fb77aa3c709f6a32234eb68d8871085418304c952b20c9d6e'}, 'ci-psec-identity-39876964598-full.txt': {'bytes': 207436, 'sha256': '026733c942fab57d2eec4e71113149b189156dad734cd5ab0e2803600e36c478'}}
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


DOCUMENT='# PSEC + LPAC identity03：outer 成员关系成立，inner 成员关系未成立\n\n**本轮仍为 `inconclusive / admission`。** 首臂 policy 0 创建返回完整 PI；随后两个独立 `IsProcessInJob` 调用都返回 API success，inner membership 为 **false**，named outer membership 为 **true**。准入正确停止。尚未读取首臂 primary token，没有尝试 LPAC 第二臂，没有 AccessCheck proof，也没有 actor resume、DNS、网络或代理验收。\n\n受测源码为 `4c5878ba0ffa6f4b938e26bf5c8c016b7042b333`，36 文件闭包为 `cf09c9c86adf9f7af3fb3d71bdde6cd1fd4fa7000a8eb01cc5ebc71b3ea5d682`。[原 public](../../verification/windows-2026-10-22/psec-lpac-identity-local-03-public.json)为 2083 字节、SHA256 `75f3198b40afc5b9919fd862b66ab14b023b4b30e4ab979b742cf3e315e734f6`。[证据索引](../../verification/windows-2026-10-22/psec-lpac-identity-local-03-evidence-index.json)、[组件投影](../../verification/windows-2026-10-22/psec-lpac-identity-local-03-component-projection.json)及[Job 准入投影](../../verification/windows-2026-10-22/psec-lpac-identity-local-03-job-admissions-projection.json)绑定原报告与磁盘收据。\n\n## 本轮取得的证据\n\n源码03只修改 Python core 与其纯测试，运行源码其余35文件及 bridge 的6 source、31 dependency 保持不变。此次增加独立 inner/outer 查询记录，保留两项 exact membership 都为 true 的原准入门，没有 assignment、fallback、恢复 actor 或新窗口。\n\n唯一初始 Job 观察以 held 进程 generation、精确 actor image/hash 前后夹持。两次查询的 API success、membership、立即 Win32 error 和原预算时限分别保存：inner 为 `true / false / 0`，outer 为 `true / true / 0`。两端 generation/image 均核验，查询均在原 work cutoff 前。named outer 只以 QUERY 权限打开；临时句柄与已知持有句柄无别名，单次消费关闭正常，查询资源清理已确认。磁盘原始 Job 收据为2285字节、SHA256 `bb4682cb27f869e49051c813525f8abf2690edee4b7a88d08a2c05d7bd50d68e`；公开投影不包含 HANDLE、PID、SID、Job 名称、创建时间、绝对路径或原 QPC。\n\n原失败标签为 `cpse_exact_jobs_not_admitted`。API 成功只说明调用成功，不代表 membership=true。此轮足以区分两个 Job：inner 未满足，outer 满足；这没有逆向补写 [identity02](2026-10-23-psec-lpac-identity-02.md)原件中“不能区分 inner/outer”的历史事实。\n\n`bind/create/ac/close/unbind` 五份原始返回收据、`bind/create/ac/stop/close/unbind` 六份意图、一个 Job 收据和零份 proof 均已核验。forensic result 与有效 worker result 逐字节相同；单独的 forensic 文件不提供 held worker 资格。worker 自然退出0，首臂 held exit1已确认；首臂 `assigned/admitted/primary_snapshot_available` 均为 false。没有 LPAC 第二臂或身份矩阵，不将缺失字段补成通过。\n\n已知 child、Job、HANDLE、查询和 observer 资源清理闭合，VOID close 消费一次并正常返回，unbind 正常完成。原 public 的 `recovery_required=false / broker_outcome_unknown=false` 仅描述本轮已知调用者资源义务闭合。[VOID close 契约](https://learn.microsoft.com/en-us/windows/win32/api/processmodel/nf-processmodel-closeprocesssecurityenvironment)不提供可虚构的 HRESULT，正常返回不证明外部环境 absence、broker cancellation 或调用者崩溃时等价清理。旧 [identity01](2026-10-23-psec-lpac-identity-01.md)未知及恢复要求完整保留，不能由03收据清除。\n\n## 属性与监督边界\n\n构造源码声明了 SE_ENV、JOB_LIST、AAP policy 三项属性。此轮的 exact inner membership=false 表明所需 inner Job 准入未成立；它不能解释原因，也不能推出全部属性均被忽略。没有把 outer=true 偷换成双 Job 准入成功。通用 [JOB_LIST 文档](https://learn.microsoft.com/en-us/windows/win32/api/processthreadsapi/nf-processthreadsapi-updateprocthreadattribute)和 [IsProcessInJob 契约](https://learn.microsoft.com/en-us/windows/win32/api/jobapi/nf-jobapi-isprocessinjob)不替代组合实测。\n\n此轮观察的是正常、持有句柄的路径，并非调用者崩溃试验；outer membership=true 也不构成创建/交接全过程无监督空档的证明。本轮没有执行新的 post-assign 构造，不授权在原 variant 中自动替换或降级。后续任何不同 constructor 应使用独立预声明 scope、保留原120秒根预算和准入/清理门，重新审查其崩溃与 opaque 资源边界。\n\n## 纯测试、CI 与全局快照\n\n[source-review03 索引](../../verification/windows-2026-10-22/psec-lpac-identity-source-review-03/index.json)保存两文件增量 patch/freeze、ABI、独立源码审查、实际审查及测试原件。本机完整身份纯测试为872项、50.703秒、零失败、2个原有 symlink 权限 skips；targeted 为42项、零失败/零skip。targeted **原始日志报告6.219秒，freeze 元数据写6.218秒**，两份原件分别保留，差异明确记录为0.001秒，未修改旧 freeze 或日志。纯测试通过不抵消实际准入失败，未在本机执行 Linux 验证。\n\n[该源码自动 CI](https://github.com/Shermanxwz/Rule-proxy-Web/actions/runs/39876964598)已独立读取：run `39876964598`、job `120164793726`，状态 completed/success；872项、104.933秒、零失败/零skip。5–9号 gated runtime 步骤均跳过，本次只执行 actor compile-only 和 pure；没有 dispatch/rerun，也没有 isolated runtime 或 CPSE 身份实验成功的含义。原 decoded 日志为207436字节、SHA256 `026733c942fab57d2eec4e71113149b189156dad734cd5ab0e2803600e36c478`，是带UTF-8 BOM及CRLF的 decoded 文本，不冒称 raw ZIP；公开脱敏/LF视图及两套摘要由source-review索引分别承诺。旧源码CI仍只属于各自提交。\n\nDLL 仍为 [source-review01](../../verification/windows-2026-10-22/psec-lpac-identity-source-review-01/index.json)的编译前快照：x64 `/MT`、SHA256 `9574f93eb562a858b207412f9f538b15bfbf329b1df284b3266496b4c2cf2ba5`、静态 imports 仅 KERNEL32、8 exports。原 native07 actor 与其9 source/13键 manifest 不变。公开文本若需要脱敏或 LF 视图，其原始和公开 bytes/SHA 及差异分别列出；可执行源码以受测提交的 Git blob 为准。\n\nbefore/after03 全局快照各7378字节、SHA256 `f05d91ee76ee8a97ae5ab3bfa092167a8ee560c083255f142e6c453f2edf7ab3`，与最初 baseline 原字节相同。仅覆盖 firewall profiles、DNS、routes、user proxy 四对象，不含 NRPT，也不证明持续或全面 absence。\n\n本轮仍是独立 `identity-only-deny-all-v1`，无 proxy/peer；两臂预期只改 AAP policy0/1，但实际仅走到首臂准入失败。[standalone semantic-LPAC DNS02](2026-10-23-lpac-semantic-dns-02.md)的 API/query `5/5` 与前后正控成功保持独立，[原 G/PSEC DNS API 泄漏](2026-10-23-selected-dns-standard53.md)仍成立。完整 PSEC+LPAC 身份组合、相同代理策略及真实代理/DNS 矩阵仍未验收，`model2_policy_compared / proxy_tested / dns_tested / product_acceptance` 均为 false。\n'

def prepare():
    public_path=OUT/'psec-lpac-identity-local-03-public.json';public_raw=read(public_path,8192)
    need(metadata(public_raw)==dict(bytes=PUBLIC_BYTES,sha256=PUBLIC_SHA),'actual03_original_public_pin');public=decode(public_raw)
    need(public['status']=='inconclusive' and public['failure']=='admission' and public['checks']['worker_bound'] is True
        and public['recovery_required'] is public['broker_outcome_unknown'] is public['observation_complete'] is False,'original03_failure_preserved')
    for name,pin in INPUTS.items():need(metadata(read(BASE/name))==pin,'source_review03_input_pin')
    freeze=decode(read(BASE/'psec-lpac-python-diagnostic-freeze-03.json'))
    need(freeze['source_count']==36 and freeze['source_sha256']==CLOSURE and freeze['unchanged_runtime_count']==35
        and freeze['native_pin_count']==37 and freeze['native_unchanged'] is True and len(freeze['files'])==2,'frozen03_source_scope')
    canonical=(json.dumps(freeze['source_hashes'],sort_keys=True,separators=(',',':'),ensure_ascii=True)+'\n').encode('ascii')
    need(sha(canonical)==CLOSURE and len(freeze['source_hashes'])==36,'runtime36_closure')
    for name,digest in freeze['source_hashes'].items():need(sha(read(REPO/name))==digest,'installed_runtime36_exact_pin')
    for name,digest in freeze['native_pins'].items():need(sha(read(REPO/name))==digest,'unchanged_native37_exact_pin')
    for name,row in freeze['files'].items():need(metadata(read(REPO/name))==dict(bytes=row['bytes'],sha256=row['sha256']),'installed_frozen_core_and_test')
    pure=decode(read(BASE/'psec-lpac-integrated-pure-03.json'));tests=pure['tests']
    need(pure['runtime_source_count']==36 and pure['runtime_source_sha256']==CLOSURE and pure['runtime_unchanged_count']==35
        and tests['tests']==872 and tests['duration_seconds']==50.703 and tests['failures']==tests['errors']==0
        and tests['skipped']==2 and tests['linux_executed'] is False,'actual_full872_receipt')
    need(metadata(read(BASE/'psec-lpac-main-pure-03.log'))==dict(bytes=tests['log_bytes'],sha256=tests['log_sha256']),'actual_full872_log')
    target_raw=read(BASE/'psec-lpac-python-diagnostic-pure-03.log')
    summaries=re.findall(rb'(?m)^Ran ([0-9]+) tests in ([0-9.]+)s\r?$',target_raw)
    need(summaries==[(b'42',b'6.219')] and freeze['pure']['tests']==42 and freeze['pure']['wall_seconds']==6.218
        and freeze['pure']['failures']==freeze['pure']['errors']==freeze['pure']['skipped']==0,'targeted42_raw_vs_metadata_preserved')
    source_review=decode(read(BASE/'psec-lpac-source03-independent-review-01.json'))
    need(source_review['remaining_blockers']==[] and source_review['tests']['original_log_wall_seconds']==6.219
        and source_review['tests']['freeze_reported_wall_seconds']==6.218,'source03_independent_review')
    actual_review=decode(read(BASE/'psec-lpac-identity-actual-03-independent-review.json'));observed=actual_review['observed']
    need(actual_review['source_commit']==COMMIT and observed['result_validated'] is True
        and len(observed['job_admissions'])==1,'actual03_independent_review')
    observed_job=observed['job_admissions'][0]
    need(observed_job['inner']['api_success'] is True and observed_job['inner']['membership'] is False
        and observed_job['outer']['api_success'] is observed_job['outer']['membership'] is True,'independent_inner_false_outer_true')
    ci_raw=read(BASE/'ci-psec-identity-39876964598-full.txt')
    need(COMMIT.encode('ascii') in ci_raw and re.findall(rb'Ran ([0-9]+) tests in ([0-9.]+)s',ci_raw)==[(b'872',b'104.933')]
        and re.search(rb'(?m)^.*Z OK\r?$',ci_raw) is not None and ci_raw.startswith(b'\xef\xbb\xbf'),'actual03_ci_source_count_success')
    actual_index_path=OUT/'psec-lpac-identity-local-03-evidence-index.json';actual_index_raw=read(actual_index_path);actual_index=decode(actual_index_raw)
    need(actual_index['source_commit']==COMMIT and actual_index['source_sha256']==CLOSURE
        and actual_index['original_public_sha256']==PUBLIC_SHA and len(actual_index['files'])==13,'actual03_index_binding')
    component=decode(read(OUT/'psec-lpac-identity-local-03-component-projection.json'))
    jobs=decode(read(OUT/'psec-lpac-identity-local-03-job-admissions-projection.json'))
    global_value=decode(read(OUT/'psec-lpac-identity-local-03-global-projection.json'))
    need(component['worker_result_validated'] is component['worker_report_held_bound'] is component['automatic_cleanup_confirmed'] is True
        and component['proofs']==[] and len(component['task_observations'])==1,'actual03_known_bound_partial_result')
    task=component['task_observations'][0]
    need(task['role']=='ac' and task['assigned'] is task['held_admitted'] is task['primary_snapshot_available'] is False
        and task['constructor_attempted'] is task['native_receipt_available'] is task['generation_available'] is task['exited'] is task['never_resumed'] is True
        and task['exit_code']==1 and all(task['process_information'].values()),'first_arm_complete_pi_not_identity_admitted')
    need([row['operation'] for row in component['operations']]==['bind','create','ac','close','unbind']
        and all(row['receipt_available'] and row['durable_returned_receipt_available'] and row['returned_function_status']==row['wrapper_status']==0
            and row['api_entered'] and row['api_returned'] and row['within_deadline'] for row in component['operations']),'five_original_return_receipts')
    need([row['action'] for row in component['intents']]==['bind','create','ac','stop','close','unbind']
        and component['void_close_invoked_count']==component['void_close_returned_normally_count']==1
        and component['returned_receipt_count']==component['validated_held_bound_returned_receipt_count']==5,'six_intents_five_returned_facts')
    need(component['forensic_result']['equals_original_validated_report_result'] is True
        and component['forensic_result']['used_for_public_qualification'] is False
        and component['outer_launch']['normal_zero_exit'] is True,'forensic_not_fallback_worker_natural0')
    need(jobs['source_commit']==COMMIT and jobs['source_sha256']==CLOSURE and jobs['job_admission_record_count']==jobs['physical_receipt_count']==jobs['held_bound_physical_receipt_count']==1
        and jobs['query_resource_cleanup_verified'] is True and len(jobs['records'])==1,'job_projection_bound_counts')
    job=jobs['records'][0];resource=job['query_resources'];physical=jobs['physical_receipts'][0]
    need(job['role']=='ac' and job['sequence']==1 and job['purpose']=='initial' and job['admission_verified'] is False
        and job['inner_query']['api_success'] is True and job['inner_query']['membership'] is False
        and job['outer_query']['api_success'] is job['outer_query']['membership'] is True
        and job['inner_query']['immediate_win32_error']==job['outer_query']['immediate_win32_error']==0
        and all(job[k]['within_original_work_deadline'] for k in ('inner_query','outer_query')),'exact_inner_false_outer_true')
    need(job['generation_before']['held_generation_verified'] is job['generation_after']['held_generation_verified'] is True
        and resource['close_api_success'] is resource['one_shot_close_source_bound'] is resource['cleanup_verified'] is True
        and resource['protected_handle_alias'] is resource['close_uncertain'] is False
        and physical['bytes']==2285 and physical['sha256']=='bb4682cb27f869e49051c813525f8abf2690edee4b7a88d08a2c05d7bd50d68e','held_generation_scoped_close_and_disk_receipt')
    need(global_value['observed'] is global_value['raw_bytes_identical'] is global_value['whole_json_objects_equal'] is True
        and global_value['before']==global_value['after']==dict(bytes=7378,sha256='f05d91ee76ee8a97ae5ab3bfa092167a8ee560c083255f142e6c453f2edf7ab3'),'original_global03_capture')
    immutable={}
    def remember(path):
        path=Path(path);raw=read(path,4*1024*1024)
        if path in immutable:need(immutable[path]==raw,'immutable_duplicate_consistency')
        immutable[path]=raw;return raw
    def repo_member(name):
        need(type(name) is str and '\\' not in name and not Path(name).is_absolute() and '..' not in Path(name).parts,'index_relative_repo_member')
        path=REPO/name;need(REPO.resolve() in path.resolve().parents,'index_member_inside_repo');return path
    def remember_index(path):
        raw=remember(path);value=decode(raw)
        for row in value['files']:
            blob=remember(repo_member(row['path']));need(metadata(blob)==dict(bytes=row['bytes'],sha256=row['sha256']),'immutable_index_member')
        return raw
    for attempt in ('01','02'):
        for suffix in ('evidence-index.json','publication-index.json'):
            remember_index(OUT/('psec-lpac-identity-local-'+attempt+'-'+suffix))
        remember_index(OUT/('psec-lpac-identity-source-review-'+attempt)/'index.json')
        remember(OUT/('psec-lpac-identity-local-'+attempt+'-checkpoint.json'))
        remember(REPO/('docs/validation/2026-10-23-psec-lpac-identity-'+attempt+'.md'))
    remember_index(actual_index_path)
    actual_paths=[repo_member(row['path']) for row in actual_index['files']]+[actual_index_path]
    need(len(actual_paths)==14,'exact14_actual03_archive_files')
    old01_path=OUT/'psec-lpac-identity-local-01-checkpoint.json';old01=decode(immutable[old01_path])
    old02_path=OUT/'psec-lpac-identity-local-02-checkpoint.json';old02=decode(immutable[old02_path])
    need(old01['broker_outcome_unknown'] is old01['recovery_required'] is True and old01['worker_report_available'] is False,'old01_unknown_kept')
    need(old02['failed_job']=='unknown-inner-or-named-outer' and old02['job_checks_not_separately_recorded'] is True,'old02_unseparated_history_kept')
    need(sha(immutable[OUT/'psec-lpac-identity-local-01-public.json'])=='cc562d1b045fea336c4257051faa52e63aa415d91556a4ea84f18aa363652f9c'
        and sha(immutable[OUT/'psec-lpac-identity-local-02-public.json'])=='100dc78f9af83445829a9f8ddf03ebe1f6bb5fc3af8f1a694e43bb78229daba2','historical_publics_kept')
    dns_doc=REPO/'docs/validation/2026-10-23-lpac-semantic-dns-02.md';dns_public=OUT/'lpac-semantic-dns-local-02-public.json'
    need(sha(remember(dns_doc))=='a4c4ca167fab7bf2e5071f0b676d45b2eaf68380146d5ce22ccce26c9306b759'
        and sha(remember(dns_public))=='757ad3b8c48f7f4d6e4d6aab9feaef4915dc54b39cf1977484eed6119fcc744f','immutable_dns02')
    remember_index(OUT/'lpac-semantic-dns-local-02-evidence-index.json')
    remember(OUT/'lpac-semantic-dns-local-02-checkpoint.json')
    old_progress_raw=read(OUTPUT);progress=decode(old_progress_raw);before=copy.deepcopy(progress)
    old_psec=copy.deepcopy(progress['PSEC_LPAC最新实测']);dns_checkpoint=copy.deepcopy(progress['DNS最新实测'])
    need(old_psec['original_public']['sha256']=='100dc78f9af83445829a9f8ddf03ebe1f6bb5fc3af8f1a694e43bb78229daba2'
        and old_psec['failed_job']=='unknown-inner-or-named-outer','outputs_latest_is_original02')
    need(progress['此前PSEC_LPAC01实测']['broker_outcome_unknown'] is progress['此前PSEC_LPAC01实测']['recovery_required'] is True,'outputs_old01_unknown_kept')
    need(dns_checkpoint['original_status']=='observed' and dns_checkpoint['selected_api']['api_status']==dns_checkpoint['selected_api']['query_status']==5
        and dns_checkpoint['existing_g_psec_dns_api_leak_remains_true'] is True,'outputs_dns5_5_and_old_g_leak_kept')
    planned={};copies=[]
    def add(path,raw):
        need(path not in planned,'duplicate_publication_target');view,edits=public_text(raw);need(view==raw and not edits,'generated_safe_lf');planned[path]=raw
    def copy_file(name,destination=None):
        raw=read(BASE/name);need(metadata(raw)==INPUTS[name],'frozen_copy03_pin');material=raw;extra=[]
        if name=='psec-lpac-identity-actual-03-independent-review.json':
            value=decode(raw);detail=value['observed'].get('failure_detail')
            if type(detail) is dict and 'message' in detail:
                detail.pop('message');material=encode(value);extra.append('freeform-failure-message-omitted')
        view,edits=public_text(material);edits=sorted(set(extra+edits));target_name=destination or name
        if edits:
            item=Path(target_name);target_name=item.stem+'-public-view'+item.suffix
        target=FOLDER/target_name;need(target not in planned,'unique_source_review_copy');planned[target]=view
        copies.append(dict(source_work_path='work/'+name,public_path=target.relative_to(REPO).as_posix(),raw_original=metadata(raw),
            public_copy=metadata(view),byte_exact_copy=view==raw,view_changes=edits,raw_private_log_published=False,
            copy_category='public-text-view' if edits else 'byte-exact-safe-artifact'))
    for name in INPUTS:
        destination='actual03-independent-review.json' if name=='psec-lpac-identity-actual-03-independent-review.json' else (
            'ci-39876964598-decoded.log' if name=='ci-psec-identity-39876964598-full.txt' else None)
        copy_file(name,destination)
    ci_copy=next(row for row in copies if row['source_work_path']=='work/ci-psec-identity-39876964598-full.txt')
    ci=dict(schema_version=1,stage='read-only-psec-identity-source03-auto-ci-summary',source_commit=COMMIT,verified=True,
        run_id=39876964598,job_id=120164793726,url='https://github.com/Shermanxwz/Rule-proxy-Web/actions/runs/39876964598',
        event='push',status='completed',conclusion='success',tests_run=872,seconds=104.933,failures=0,errors=0,skips=0,
        gated_runtime_steps_skipped=[5,6,7,8,9],compile_only_actor_step_executed=True,
        runtime_steps_basis='Root independently read GitHub job step metadata; decoded log does not contain skipped step bodies.',
        isolated_runtime_qualified=False,native_actor_executed=False,cpse_experiment_executed=False,network_experiment_executed=False,
        workflow_dispatched=False,workflow_rerun=False,prior_source_ci_does_not_transfer=True,
        decoded_original=dict(**metadata(ci_raw),encoding='UTF-8 BOM',line_endings='CRLF',not_raw_zip=True,kept_in_work=True),
        public_log_view=dict(path=ci_copy['public_path'],**ci_copy['public_copy']),
        actual03_result_remains_inconclusive=True,pure_or_ci_success_does_not_override_actual03_failure=True)
    timing=dict(targeted_tests=42,raw_log_seconds=6.219,freeze_metadata_seconds=6.218,difference_seconds=0.001,
        both_originals_preserved=True,freeze_or_log_rewritten=False,source_review_also_records_both=True)
    add(FOLDER/'ci-39876964598-summary.json',encode(ci));add(FOLDER/'timing-metadata-discrepancy.json',encode(timing))
    add(FOLDER/'publication.py',read(Path(__file__),128*1024))
    old_native_index_path=OUT/'psec-lpac-identity-source-review-01/index.json'
    review_index=dict(schema_version=1,stage='psec-lpac-identity-source-review-03-index',source_commit=COMMIT,runtime_source_sha256=CLOSURE,
        runtime_source_count=36,incremental_source_file_count=2,runtime_changed_file_count=1,runtime_unchanged_file_count=35,
        bridge_native_source_count=6,bridge_dependency_count=31,native_or_dll_rebuilt=False,
        unchanged_shared_native_build_review=repo_ref(old_native_index_path,immutable[old_native_index_path]),actual_index=repo_ref(actual_index_path,actual_index_raw),
        files=[repo_ref(path,raw) for path,raw in planned.items()],original_copy_provenance=copies,index_self_hash_excluded=True,
        timing_metadata_discrepancy=timing,automatic_ci=ci,inner_membership=False,outer_membership=True,both_query_api_success=True,
        actual_failure_not_overridden=True,old01_unknown_preserved=True,old02_unknown_which_job_not_rewritten=True,
        all_attributes_ignored_not_inferred=True,raw_dll_or_private_identity_published=False,main_source_or_native_api_or_experiment_run=False)
    add(FOLDER/'index.json',encode(review_index))
    doc_path=REPO/'docs/validation/2026-10-23-psec-lpac-identity-03.md';doc_raw=DOCUMENT.encode('utf8');add(doc_path,doc_raw)
    checkpoint_path=OUT/'psec-lpac-identity-local-03-checkpoint.json'
    checkpoint=dict(schema_version=1,stage='psec-lpac-identity03-inner-job-false-outer-true-known-cleanup-checkpoint',source_commit=COMMIT,source_sha256=CLOSURE,
        original_public=repo_ref(public_path,public_raw),document=repo_ref(doc_path,doc_raw),source_review_index=repo_ref(FOLDER/'index.json',planned[FOLDER/'index.json']),
        evidence_index=repo_ref(actual_index_path,actual_index_raw),job_admissions_projection=repo_ref(OUT/'psec-lpac-identity-local-03-job-admissions-projection.json',immutable[OUT/'psec-lpac-identity-local-03-job-admissions-projection.json']),
        status='inconclusive',failure='admission',worker_report_available=True,worker_bound=True,worker_exit_code=0,
        outer_kernel_cleanup_confirmed=True,known_caller_resource_cleanup_confirmed=True,cpse_create_hresult=0,
        first_constructor_complete_pi=True,first_constructor_return_status=0,first_arm_primary_observed=False,first_arm_identity_admitted=False,
        first_arm_assigned=False,first_arm_held_exit_code=1,first_arm_never_resumed=True,
        failed_gate_label='cpse_exact_jobs_not_admitted',failed_job='inner',inner_query_api_success=True,inner_membership=False,
        outer_query_api_success=True,outer_membership=True,immediate_inner_win32_error=0,immediate_outer_win32_error=0,
        job_checks_separately_recorded=True,held_generation_image_brackets_verified=True,original_job_deadlines_verified=True,
        job_query_handle_single_consume_close_verified=True,protected_handle_alias=False,job_query_resources_cleanup_verified=True,
        physical_job_receipt=dict(bytes=2285,sha256=physical['sha256']),original_job_receipt_count=1,
        declared_attribute_count=3,all_attributes_ignored_not_inferred=True,all_attributes_applied_not_qualified=True,
        atomic_job_predicate_unchanged=True,post_assignment_substitution_authorized=False,original_returned_receipt_count=5,durable_intent_count=6,
        forensic_equals_original_valid_result=True,forensic_alone_is_unvalidated=True,forensic_used_for_public_qualification=False,
        accesscheck_proof_count=0,lpac_second_arm_attempted=False,ac_lpac_four_matrix_pair_qualified=False,
        void_close_raw_receipt_available=True,void_close_invoked_once=True,void_close_returned_normally=True,module_unbind_confirmed=True,
        observation_complete=False,broker_outcome_unknown=False,recovery_required=False,external_environment_absence_verified=False,
        broker_cancellation_proven=False,caller_crash_cleanup_equivalence_tested=False,creation_transfer_crash_gap_resolved=False,
        old01_checkpoint=repo_ref(old01_path,immutable[old01_path]),old01_broker_outcome_unknown=True,old01_recovery_required=True,
        old02_checkpoint=repo_ref(old02_path,immutable[old02_path]),old02_failed_job_remains_unknown_inner_or_named_outer=True,
        old_unknowns_not_reinterpreted=True,old_opaque_reopen_replay_or_retry_close_authorized=False,
        global_snapshot_bytes=7378,global_snapshot_sha256='f05d91ee76ee8a97ae5ab3bfa092167a8ee560c083255f142e6c453f2edf7ab3',
        global_before_after_byte_equal=True,snapshot_objects=['firewall_profiles','dns','routes','user_proxy'],nrpt_in_snapshot=False,
        full_identity_pure=tests,targeted_pure_timing=timing,source_automatic_ci=ci,
        model2_policy_compared=False,network_tested=False,dns_tested=False,proxy_tested=False,product_acceptance=False,linux_equivalence_qualified=False,
        existing_g_psec_api_dns_leak_remains_true=True,standalone_semantic_dns02_success_preserved=True)
    add(checkpoint_path,encode(checkpoint))
    history_key='此前PSEC_LPAC02实测';need(history_key not in progress or progress[history_key]==old_psec,'old02_history_consistency')
    progress[history_key]=copy.deepcopy(old_psec)
    progress['PSEC_LPAC最新实测']=copy.deepcopy(checkpoint);progress['PSEC_LPAC最新实测']['checkpoint']=repo_ref(checkpoint_path,planned[checkpoint_path])
    progress['最新尝试']={'名称':'psec-lpac-identity-local-03','源码提交':COMMIT,'状态':'inconclusive','失败门':'admission / cpse_exact_jobs_not_admitted',
        'CPSE创建S_OK':True,'首臂创建完整PI':True,'inner_API成功':True,'inner_membership':False,'outer_API成功':True,'outer_membership':True,
        '失败Job':'inner','原双exactJob准入门保持':True,'primary身份已观察':False,'LPAC第二臂已尝试':False,'矩阵proof数':0,
        '原始返回收据数':5,'原始意图数':6,'原始Job收据数':1,'worker退出码':0,'首臂held退出码':1,
        '本轮已知资源清理完成':True,'VOIDclose单次正常返回':True,'本轮opaque结果未知':False,'本轮需要恢复':False,
        '外部环境absence已证明':False,'caller崩溃等价清理已证明':False,'全部属性被忽略已推断':False,
        '旧01opaque未知仍保留':True,'旧01恢复要求仍保留':True,'旧02失败Job未区分历史保留':True,'全局四对象baseline字节相等':True,
        '两臂身份验收':False,'网络测试':False,'产品验收':False,'原G_PSEC_API_DNS泄漏仍成立':True,'standalone_DNS02_API_query5_5保持独立':True,
        '本源码自动CI结果':'compile/pure成功；872/0skip，runtime5–9跳过，非隔离验收'}
    progress['当前阻断']='PSEC+LPAC identity03 已分离原始查询：inner API成功/member=false，outer API成功/member=true；原双Job准入停止于 primary/LPAC/proof 前。不能推断全部属性被忽略；已知正常清理不证明外部absence或崩溃等价清理。旧01未知、02未分离查询历史及原G/PSEC DNS泄漏保留。'
    progress['状态']='PSEC+LPAC identity03 定位 inner Job membership 未成立，outer=true，本轮已知资源闭合但身份组合未验收。standalone DNS02 API/query5/5独立成立，原G/PSEC DNS API泄漏未修复。'
    progress['源码提交']=COMMIT
    allowed={'PSEC_LPAC最新实测',history_key,'最新尝试','当前阻断','状态','源码提交'}
    untouched={key:sha(encode(value)) for key,value in before.items() if key not in allowed}
    need(all(encode(progress[key])==encode(before[key]) for key in untouched) and progress['DNS最新实测']==dns_checkpoint,'all_other_outputs_fields_byte_equivalent')
    progress_raw=encode(progress);view,edits=public_text(progress_raw);need(view==progress_raw and not edits,'safe_outputs_progress')
    for link in re.findall(r'\]\(([^)]+)\)',DOCUMENT):
        if link.startswith('https://'):continue
        target=(doc_path.parent/link).resolve();need(target in planned or target.is_file(),'new03_document_link:'+link)
    index_path=OUT/'psec-lpac-identity-local-03-publication-index.json'
    add(index_path,encode(dict(schema_version=1,stage='psec-identity03-publication-index',source_commit=COMMIT,
        original_actual_index=repo_ref(actual_index_path,actual_index_raw),files=[repo_ref(path,raw) for path,raw in planned.items()],
        outputs_progress=dict(path='outputs/windows-isolation-progress.json',before=metadata(old_progress_raw),after=metadata(progress_raw),
            allowed_changed_fields=sorted(allowed),all_other_field_value_bytes_preserved=True,untouched_field_sha256=untouched),
        immutable_older_and_actual_files=[repo_ref(path,raw) for path,raw in immutable.items()],index_self_hash_excluded=True,
        original03_inner_false_outer_true_and_failure_preserved=True,old01_unknown_and_old02_history_preserved=True,
        handoff_edit_not_included_preview_only=True,no_source_or_runtime_or_recovery_execution=True)))
    for path in planned:need(not path.exists(),'fresh03_publication_target')
    need(not FOLDER.exists(),'fresh03_source_review_folder')
    need(all(read(path,4*1024*1024)==raw for path,raw in immutable.items()) and read(OUTPUT)==old_progress_raw,'existing_inputs_unchanged')
    paths=sorted({*actual_paths,*planned})
    return planned,progress_raw,old_progress_raw,immutable,paths,dict(planned_repository_files=len(planned),actual_archive_files_preserved=len(actual_paths),
        source_review_copies=len(copies),views_changed=sum(not row['byte_exact_copy'] for row in copies),source_commit=COMMIT,
        inner_api_success=True,inner_membership=False,outer_api_success=True,outer_membership=True,original03_known_cleanup=True,
        old01_unknown_preserved=True,old02_unseparated_history_preserved=True,immutable_dns02_preserved=True,
        targeted_raw_seconds=6.219,freeze_metadata_seconds=6.218,ci_result_verified=True,
        publication_written=False,native_or_experiment_or_cleanup_run=False)


def main(argv=None):
    parser=argparse.ArgumentParser(description=__doc__);parser.add_argument('--publish',action='store_true');args=parser.parse_args(argv)
    planned,progress,old_progress,immutable,paths,result=prepare()
    if args.publish:
        need(OUTPUT.parent.resolve()==(BASE.parent/'outputs').resolve(),'fixed_outputs_directory')
        for path in planned:path.parent.mkdir(parents=True,exist_ok=True)
        for path,raw in planned.items():
            with path.open('xb') as stream:need(stream.write(raw)==len(raw),'fresh_publication_write')
            need(read(path,4*1024*1024)==raw,'publication_readback')
        need(read(OUTPUT)==old_progress,'outputs_still_original')
        temp=OUTPUT.with_name('.windows-isolation-progress-psec03.tmp');need(not temp.exists(),'fresh03_output_temporary')
        with temp.open('xb') as stream:need(stream.write(progress)==len(progress),'progress_write')
        os.replace(temp,OUTPUT);need(read(OUTPUT)==progress,'progress_readback')
        need(all(read(path,4*1024*1024)==raw for path,raw in immutable.items()),'all_history_and_actuals_immutable')
        listing=BASE/'stage_psec_lpac_identity_publication_03_paths.txt';raw=''.join(path.relative_to(REPO).as_posix()+'\n' for path in paths).encode('ascii')
        if listing.exists():need(read(listing)==raw,'explicit_stage_pathlist_unchanged')
        else:
            with listing.open('xb') as stream:need(stream.write(raw)==len(raw),'explicit_stage_pathlist_write')
        result['publication_written']=True
    print(json.dumps(result,sort_keys=True,ensure_ascii=True))
if __name__=='__main__':main()
