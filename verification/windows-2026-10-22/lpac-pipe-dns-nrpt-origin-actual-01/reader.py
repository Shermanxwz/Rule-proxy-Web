"""WORK file-only new exact-NRPT scope reader; default is inert preview.

Root supplies the final source/Ready/public/preflight/driver/capture pins after
the single separately authorized attempt. Only exact Git/LF staged validators
are imported. No NativeAPI, actor, DNS, profile, ACL or cleanup call is made;
imports themselves may initialize libraries. Missing worker data is unknown,
and forensic data never substitutes for a qualifying worker report.
"""
from __future__ import annotations
import argparse
import copy
import hashlib
import importlib.util
import json
import re
import subprocess
import sys
from pathlib import Path

sys.dont_write_bytecode = True
W = Path(__file__).resolve().parent
R = W/'Rule-proxy-Web'
SCOPE = 'one-local-same-zero-cap-lpac-pipe-origin-explicit-dns-exact-nrpt-nonmatch-v1'
PROFILE = 'same-process-zero-cap-lpac-ipc-standard53-exact-nrpt-nonmatch-v1'
POLICY_MODE = 'effective-exact-fqdn-nonmatch-only-v1'
ENTRY = '.github/windows_identity_lpac_pipe_dns_nrpt_origin_local.py'
SOURCE_COUNT = 47
OLD_READER = 'verify_lpac_pipe_dns_origin_actual_01_candidate.py'
OLD_READER_SHA = '787aa85d0903d7fa491a33f7185dbcbdbcf7db6f5b6639f1d4ccaf0696d21285'


def require(ok, label):
    if not ok: raise ValueError(label)


def digest(value, size=64):
    return type(value) is str and re.fullmatch('[0-9a-f]{%d}' % size, value) is not None


def readers():
    # The old reader is a hash-pinned file-only helper, not the old runtime.
    # Reuse its fixed 3-artifact and global comparison functions only; the new
    # source binding, policy decisions and DNS projection are implemented here.
    p = W/OLD_READER
    b = p.read_bytes()
    require(len(b) == 20436 and hashlib.sha256(b).hexdigest() == OLD_READER_SHA, 'NRPT_reader_helper')
    spec = importlib.util.spec_from_file_location('fixed_DNS01_file_helpers_for_NRPT', p)
    old = importlib.util.module_from_spec(spec); spec.loader.exec_module(old)
    return old, old.utilities()


def bind_sources(u, a, pub, pre):
    ready, ready_raw = u.json_file(u.work_name(a.ready_freeze_name), 512*1024, inside=W)
    require(u.sha(ready_raw) == a.ready_freeze_sha256 and ready['actual_ready'] is True
        and ready['source_count'] == SOURCE_COUNT and ready['source_sha256'] == a.source_sha256,
        'NRPT_reader_Ready')
    hashes = ready['source_hashes']
    require(type(hashes) is dict and len(hashes) == SOURCE_COUNT
        and u.sha(u.encode(hashes)) == a.source_sha256, 'NRPT_reader_source_map')
    plan, plan_raw = u.json_file(R/'private'/a.plan_name, 16384)
    require(u.sha(plan_raw) == pub['recovery_plan_sha256'] and digest(plan.get('run'), 32), 'NRPT_reader_plan')
    stage = R/'private'/('local-lpac-pipe-dns-nrpt-origin-'+plan['run'])
    config, config_raw = u.json_file(stage/'worker-config.json', 512*1024)
    require(config['source_hashes'] == hashes and config['source_sha256'] == a.source_sha256
        and config['recovery_plan_sha256'] == u.sha(plan_raw)
        and u.read(stage/'recovery-plan.json', 16384) == plan_raw, 'NRPT_reader_config_plan')
    require(pub['source_sha256'] == pre['source_sha256'] == a.source_sha256, 'NRPT_reader_public_sources')
    commit = subprocess.check_output(['git', 'rev-parse', '--verify', a.source_commit+'^{commit}'], cwd=R).decode('ascii').strip()
    require(commit == a.source_commit, 'NRPT_reader_exact_commit')
    names = sorted(hashes)
    require(ENTRY in hashes and all(re.fullmatch('[A-Za-z0-9_./-]+', n)
        and '..' not in n.split('/') for n in names), 'NRPT_reader_source_names')
    raw = subprocess.run(['git', 'cat-file', '--batch'], cwd=R,
        input=''.join(commit+':'+n+'\n' for n in names).encode(), capture_output=True, check=True).stdout
    offset = 0
    for name in names:
        end = raw.index(b'\n', offset); header = raw[offset:end].split()
        require(len(header) == 3 and header[1] == b'blob', 'NRPT_reader_Git_blob')
        size = int(header[2]); offset = end+1
        blob = raw[offset:offset+size]; offset += size
        require(raw[offset:offset+1] == b'\n', 'NRPT_reader_Git_extent'); offset += 1
        actual = u.read(stage/name, 256*1024)
        require(actual == blob and u.sha(actual) == hashes[name] and b'\r' not in actual, 'NRPT_reader_exact_Git_LF')
    require(offset == len(raw), 'NRPT_reader_Git_complete')
    spec = importlib.util.spec_from_file_location('bound_NRPT_runtime_file_validators', stage/ENTRY)
    module = importlib.util.module_from_spec(spec); spec.loader.exec_module(module)
    require(module.SCOPE == SCOPE and module.core.PROFILE == PROFILE and module.core.POLICY_MODE == POLICY_MODE
        and module.core.ACTUAL_READY is True and module.core.api_version() == 1
        and set(module.SOURCES) == set(hashes), 'NRPT_reader_bound_interface')
    module.core.config_validate(config); module.validate_public(pub); module.validate_public(pre)
    require(pre['mode'] == 'preflight' and pre['status'] == 'ready' and pub['mode'] == 'runtime'
        and pub['policy_mode'] == pre['policy_mode'] == config['policy_mode'] == plan['policy_mode'] == POLICY_MODE,
        'NRPT_reader_explicit_new_scope')
    module.core.validate_plan(plan, device=config['device_sha256'], source=config['source_sha256'],
        actor=config['actor_sha256'], manifest=config['manifest_sha256'],
        origin_actor=config['origin_actor_sha256'], origin_manifest=config['origin_manifest_sha256'],
        control_actor=config['control_actor_sha256'], control_manifest=config['control_manifest_sha256'])
    require(all(plan[k] == config[k] for k in module.core.NONCES)
        and len({config[k] for k in module.core.NONCES}) == 6
        and config['root_deadline_qpc'] == config['start_qpc']+120*config['frequency']
        and config['deadline_qpc'] == config['root_deadline_qpc']-5*config['frequency'], 'NRPT_reader_original_epoch')
    return module, stage, config, plan_raw, config_raw, u.desc(ready_raw)


def policy_review(u, m, stage, c, j, rows):
    record = j['inventory']; raw = None; decisions = []; gates = []
    if record is not None:
        raw = m.core.inventory_raw(record, root=stage)
        require(u.desc(raw) == u.optional(stage/'tools/inventory/stdout', 32768), 'NRPT_inventory_physical')
    for index, item in enumerate(j['policy_decisions']):
        require(raw is not None and item['label'] == ('bind','before','selected','after')[index], 'NRPT_decision_order')
        value = m.core.review_inventory_record(record, c, rows['inventory']['pid'], item['qpc'], root=stage)
        p = value['projection']; require(p == item['projection'], 'NRPT_decision_physical_recompute')
        accepted = m.core.policy.inventory_safe(p)
        decisions.append(dict(label=item['label'], safe_projection=m.core.policy.inventory_public(p),
            inventory_age_seconds=(item['qpc']-value['raw']['end_qpc'])/c['frequency'],
            within_five_seconds=0 <= item['qpc']-value['raw']['end_qpc'] <= 5*c['frequency'],
            semantic_field_count=16, actual_rule_count=len(value['raw']['effective_nrpt_rules']),
            accepted=accepted, same_original_inventory_sha256=p['raw_sha256'] == record['sha256']))
        if accepted: gates.append(dict(label=item['label'], qpc=item['qpc']))
    require(gates == j['inventory_gates'] and j['policy_inventory'] ==
        (j['policy_decisions'][-1]['projection'] if j['policy_decisions'] else m.core.policy.unknown_inventory()),
        'NRPT_decisions_authorization_exact')
    return dict(policy_mode=POLICY_MODE, raw_inventory=None if raw is None else u.desc(raw),
        policy_inventory=m.core.policy.inventory_public(j['policy_inventory']), policy_decisions=decisions,
        accepted_gate_labels=[x['label'] for x in gates],
        four_safe_gates_complete=[x['label'] for x in gates] == ['bind','before','selected','after'],
        all_four_decisions_same_raw_sha256=bool(decisions) and len(decisions) == 4
            and all(x['same_original_inventory_sha256'] for x in decisions),
        actual_rule_count_not_assumed=True, no_namespace_or_server_values_published=True,
        no_policy_write_or_recollection_performed_by_reader=True)


def dns_projection(old, u, m, stage, c, j, parent):
    rows = {r['name']:r for r in (*j['tasks'], *j['cleanup_tasks'])}
    front = m.core.actor_rows(j).get('lpac-pipe-front'); native = {}; raw_views = {}
    for key, name in (('dns_report','dns.json'), ('dns_final','final.json')):
        status = j[key+'_status']; record = j[key]
        view = dict(status=status, commitment=u.optional(stage/'selected-report'/name, m.core.MAX_NATIVE), parsed=False)
        if record is not None:
            raw, commitment = u.physical_bytes(record, stage/'selected-report'/name, m.core.MAX_NATIVE)
            view['commitment'] = commitment
            # Invalid JSON is still an authentic partial physical report; do
            # not decode it or erase independently valid peer observations.
            if status == 'valid':
                validator = m.core.dns_report if key == 'dns_report' else m.core.final_report
                native[key] = validator(u.decode(raw), j, c, parent); view['parsed'] = True
        raw_views[key] = view
    phase, final = native.get('dns_report'), native.get('dns_final')
    api = None if phase is None else {k:v for k,v in phase['dns']['result'].items() if k not in ('start_qpc','end_qpc')}
    controls = {}
    for label, record in j['ordinary_reports'].items():
        raw, commitment = u.physical_bytes(record, stage/'tools'/('dns-'+label)/'stdout')
        v = m.core.control_report(u.decode(raw), rows['dns-'+label], c, label, record['issued_qpc'], record['phase_deadline'])
        controls[label] = dict(commitment=commitment, positive=m.core.api_positive(v['result']),
            api={k:x for k,x in v['result'].items() if k not in ('start_qpc','end_qpc')},
            natural_exit0=rows['dns-'+label]['exited'] and rows['dns-'+label]['exit_code'] == 0)
    gos = []
    for index, go in enumerate(j['dns_go']):
        raw = u.read(stage/('inputs/dns-go.bin' if index == 0 else 'inputs/finish-go.bin'), 128)
        require(raw == m.core.ticket(c,j['pair'],go['operation'],go['phase_deadline'])
            and u.sha(raw) == go['sha256'], 'NRPT_physical_DNS_GO')
        gos.append(dict(sequence=go['sequence'], operation=go['operation'], commitment=u.desc(raw), original_pair_deadline=True))
    receiver = None
    if j['fixture_final'] is not None:
        v = m.core.dns.receiver(j['fixture_final'], final=True)
        receiver = {k:copy.deepcopy(v[k]) for k in ('ready','error','counts','cases','case_query_observed',
            'selected_query_observed','byte_count_is_observed_lower_bound','socket_closed','thread_stopped',
            'socket_close_uncertain','cleanup_confirmed','broker_cancellation_proven')}
    same = front is not None and bool(front['held_checks']) and all(h['primary'] == front['expected_primary']
        and h['token_statistics'] == front['expected_statistics'] for h in front['held_checks'])
    return dict(first_proof=old.proof(j['proof']), second_proof=old.proof(j['dns_proof']),
        same_external_primary_and_full_TokenStatistics_including_ModifiedId=same,
        policy=policy_review(u,m,stage,c,j,rows), ordinary_controls=controls, GO=gos,
        raw_phase=raw_views['dns_report'], raw_final=raw_views['dns_final'], selected_API=api,
        selected_native_failure=None if phase is None else phase['failure'],
        same_selected_PID_phase_final=phase is not None and final is not None and front is not None
            and phase['pid'] == final['pid'] == front['pid'],
        final_original_IPC_and_DNS_hashes_exact=final is not None
            and final['ipc_report_sha256'] == j['reports']['selected']['sha256']
            and final['dns_report_sha256'] == j['dns_report']['sha256'],
        finish_admitted=None if final is None else final['finish_admitted'], receiver=receiver,
        sticky_selected_wire=j['selected_wire_query_observed'],
        sticky_API_lifecycle_unknown=j['api_lifecycle_unknown'], fixture_cleanup=j['fixture_cleanup'])


def result_review(old, u, m, stage, c, pub, outer):
    result = u.result_review(m,stage,c,pub,outer)
    result.update(dns=None,dns_projection_error=None,forensic_matches_worker=None,outer_cleanup_projection_exact=None)
    if not result['worker_result_valid']: return result
    try:
        report, raw = u.json_file(stage/'worker-report.json', m.MAX_REPORT)
        require(u.read(stage/'worker-result-forensic.json', m.MAX_REPORT) == raw, 'NRPT_forensic_exact_not_fallback')
        result['forensic_matches_worker'] = True
        require(pub['checks']['worker_exit'] == (outer.get('cleanup',{}).get('process_exit_confirmed') is True)
            and pub['checks']['outer_cleanup'] == m.local.guest.cleanup_verified(outer), 'NRPT_outer_cleanup_projection')
        result['outer_cleanup_projection_exact'] = True
        if pub['observation_complete']:
            require(outer.get('resumed') is True and outer.get('exit_code') == 0
                and outer.get('timed_out') is not True and 'error' not in outer, 'NRPT_complete_outer_exit')
        result['dns'] = dns_projection(old,u,m,stage,c,report['result'],report['worker_identity'])
    except Exception as error:
        result['dns_projection_error'] = u.safe_error(error)
    return result


def audit(a):
    old, u = readers()
    require(digest(a.source_commit,40) and all(digest(getattr(a,n)) for n in
        ('source_sha256','ready_freeze_sha256','public_sha256','preflight_sha256','driver_sha256','capture_sha256')),
        'NRPT_reader_operator_pins')
    require(re.fullmatch('[a-z0-9-]{1,96}', a.prefix) and a.public_bytes > 0 and a.preflight_bytes > 0,
        'NRPT_reader_public_types')
    for n in ('plan_name','before_snapshot_name','after_snapshot_name'): u.work_name(getattr(a,n))
    pub, public_raw = u.json_file(R/'verification/windows-2026-10-22'/(a.prefix+'-public.json'),16384)
    pre, pre_raw = u.json_file(R/'verification/windows-2026-10-22'/(a.prefix+'-preflight.json'),16384)
    require(u.desc(public_raw) == dict(bytes=a.public_bytes,sha256=a.public_sha256)
        and u.desc(pre_raw) == dict(bytes=a.preflight_bytes,sha256=a.preflight_sha256), 'NRPT_original_public_pins')
    m, stage, c, plan_raw, config_raw, ready = bind_sources(u,a,pub,pre)
    artifacts = old.artifacts(u,m,stage,c,pub,pre)
    path = stage/'outer-launch-report.json'
    outer, outer_raw = u.json_file(path,m.MAX_REPORT) if path.exists() else (None,None)
    require((u.sha(outer_raw) if outer_raw is not None else None) == pub['outer_launch_report_sha256'], 'NRPT_raw_outer_hash')
    driver = u.read(u.work_name(a.driver_name),256*1024,inside=W)
    require(u.sha(driver) == a.driver_sha256,'NRPT_driver_pin')
    groups = {}
    for group, bound in (('journal',48),('returns',8)):
        directory = stage/group; paths = sorted(directory.iterdir()) if directory.exists() else []
        require(len(paths) <= bound,'NRPT_physical_record_count')
        groups[group] = [u.desc(u.read(p,65536)) for p in paths]
    return dict(schema_version=1,stage='lpac-pipe-dns-nrpt-origin-actual-file-review',scope=SCOPE,profile=PROFILE,
        policy_mode=POLICY_MODE,source_commit=a.source_commit,source_sha256=a.source_sha256,source_count=SOURCE_COUNT,
        Ready=ready,public=u.desc(public_raw),preflight=u.desc(pre_raw),original_status=pub['status'],
        original_failure=pub['failure'],original_observation_complete=pub['observation_complete'],
        original_recovery_required=pub['recovery_required'],original_safe_observation=pub['observation'],
        original_policy_inventory=m.core.policy.inventory_public(pub['policy_inventory']),
        fixed_false_claims={k:pub[k] for k in m.core.FALSE_CLAIMS},compiled_artifacts=artifacts,
        private_commitments=dict(plan=u.desc(plan_raw),config=u.desc(config_raw),
            outer_report=None if outer_raw is None else u.desc(outer_raw),
            worker_report=u.optional(stage/'worker-report.json',m.MAX_REPORT),
            forensic=u.optional(stage/'worker-result-forensic.json',m.MAX_REPORT),
            stdout=u.optional(stage/'guard/controller.stdout',2*1024*1024),
            stderr=u.optional(stage/'guard/controller.stderr',2*1024*1024),driver=u.desc(driver)),
        physical_evidence_commitments=groups,result_review=result_review(old,u,m,stage,c,pub,outer),
        globals=old.global_review(u,a),reader_helpers=dict(DNS01=dict(name=OLD_READER,sha256=OLD_READER_SHA),
            IPC=dict(name=old.UTILITY,sha256=old.UTILITY_SHA)),
        reader_actions=dict(file_only=True,production_backend_constructed=False,actor_or_cleanup_called=False,
            configuration_changed=False),limitations=[
            'No positive, denial or NRPT count is preselected. Missing worker-report stays unknown; forensic is not a fallback.',
            'Unsupported/malformed committed data remains partial evidence; independent valid peer facts are retained.',
            'All16 effective semantic fields and actual counts are validated only where a source-bound decision returned. No dropped rows or rewritten policy count.',
            'Five-second sampled freshness is not a policy lock. No suffix/default/subnet/IDN policy evaluation or NRPT write is introduced.',
            'API5 needs both sameAPI positives, receiver zero, original bindings and full known lifecycle. Zero wire, late/pending or timeout is not denial.',
            'Original strict-count-zero DNS01 failure and all previous leaks/unknowns remain unchanged.',
            'Four global objects are compared from original/before/after bytes; NRPT is separate; route writer attribution stays unknown.',
            'No default-resolver/brokerPID/PSEC/G/all-DNS/browser/arbitraryapplication/Mihomo/Linux/product qualification.'])


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--verify-file-only',action='store_true')
    parser.add_argument('--prefix',default='lpac-pipe-dns-nrpt-origin-local-01')
    names = ('source-commit','source-sha256','ready-freeze-name','ready-freeze-sha256',
        'public-sha256','preflight-sha256','driver-name','driver-sha256','capture-name','capture-sha256',
        'plan-name','before-snapshot-name','after-snapshot-name')
    for name in names: parser.add_argument('--'+name)
    parser.add_argument('--public-bytes',type=int); parser.add_argument('--preflight-bytes',type=int)
    parser.add_argument('--output-name',default='lpac-pipe-dns-nrpt-origin-actual-01-independent-review.json')
    args = parser.parse_args(argv)
    if not args.verify_file_only:
        print(json.dumps(dict(stage='NRPT-DNS-file-reader-candidate-preview',scope=SCOPE,
            verification_executed=False,repo_imported=False,actual_files_read=False,files_written=False,
            final_operator_pins_required=True),sort_keys=True))
        return 0
    require(all(getattr(args,n.replace('-','_')) is not None for n in (*names,'public-bytes','preflight-bytes')),
        'NRPT_reader_final_pins_required')
    old, utility = readers(); output = utility.work_name(args.output_name)
    require(not output.exists(),'NRPT_reader_fresh_output')
    value = audit(args); raw = (json.dumps(value,sort_keys=True,indent=2)+'\n').encode('ascii')
    with output.open('xb') as out: require(out.write(raw) == len(raw),'NRPT_reader_exact_write')
    print(json.dumps(dict(review=utility.desc(raw),worker_result_valid=value['result_review']['worker_result_valid'],
        original_status=value['original_status']),sort_keys=True))
    return 0


if __name__ == '__main__': raise SystemExit(main())
