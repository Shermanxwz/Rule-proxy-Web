"""WORK A2 file-only reader; default is an inert preview.

Final source/Ready/public/preflight/driver/capture pins are supplied after the
separately authorized assay. Source49 is bound to exact staged historical Git
bytes before pure validators are imported. No backend, actor, endpoint, profile,
ACL or cleanup is constructed/called. Imports may initialize libraries. Missing
worker reports stay unknown; forensic data never substitutes for a report.
"""
from __future__ import annotations
import argparse
import copy
import hashlib
import importlib.util
import json
from pathlib import Path
import re
import subprocess
import sys

sys.dont_write_bytecode = True
W = Path(__file__).resolve().parent
R = W/'Rule-proxy-Web'
SCOPE = 'one-local-semantic-lpac-inherited-stream-mihomo-http-message-v1'
PROFILE = 'zero-cap-lpac-RPS1-fixed-SOCKS5-Mihomo-owned-HTTP-v1'
ENTRY = '.github/windows_identity_lpac_stream_mihomo_origin_local.py'
COUNT = 49
UTILITY = 'verify_lpac_stream_origin_actual_01_candidate.py'
UTILITY_SHA = '95f0a068e3d90bfefc73b433ac4870667b506585026b5ca3861c1db4eb4ef7e0'
SELECTED_BUILD = 'lpac-stream-native-compile-01'
NETWORK_BUILD = 'lpac-stream-mihomo-native-compile-01'
SNAPSHOTS = {
    SELECTED_BUILD: '1819823e18df4a58c3cb6e304f40141ad2172abd4846e97b6f63fa9365cba317',
    NETWORK_BUILD: 'fb5e00114e4c06b1cdf48db8c6b61876d491e2ca8d479eaf40df2f2f04235e02'}
REVIEWS = {
    SELECTED_BUILD: ('lpac-stream-native-compile-static-review-01.json', '8388a661c10036a7676fc79b3b595a141905e2a87b734a777809878456cf5d35'),
    NETWORK_BUILD: ('lpac-stream-mihomo-native-compile-static-review-01.json', 'ee02b13e2f632c6e299a288183bc020afa19fbd8117b40d703730a6cd5d8eb5b')}
ARTIFACTS = {
    'selected': ('b7327db1d30f4d81f7806b449d191cf7d49e22563c1da0c734f85cd478c9ae2a', '9a9df1de567bc4c6a9d0de334adeed4665fba2ade5ae5b62d26279d37134c4ba'),
    'network': ('ef419337943b8b3acdc538a9c2904ca81cf304b9de0ed8149de23b655ac1b2a7', '41128b9ca698bc84412de280b07a431975f1774671e1617f4273d6946e736685')}
MIHOMO_BYTES = 61276672
MIHOMO_SHA = '04f8d7fc2b314771e1ecbf15951d59f0e1cb7914503c88cfb6972ff6a824e314'


def require(ok, label):
    if not ok: raise ValueError(label)


def digest(value, count=64):
    return type(value) is str and re.fullmatch('[0-9a-f]{%d}' % count, value) is not None


def utility():
    path = W/UTILITY; raw = path.read_bytes()
    require(len(raw) == 24046 and hashlib.sha256(raw).hexdigest() == UTILITY_SHA, 'A2_reader_fixed_file_helper')
    spec = importlib.util.spec_from_file_location('fixed_Amin_file_reader_utilities_for_A2', path)
    module = importlib.util.module_from_spec(spec); spec.loader.exec_module(module)
    return module


def bind_sources(u, a, pub, pre):
    ready, ready_raw = u.json_file(u.work_name(a.ready_freeze_name), 512*1024, inside=W)
    require(u.sha(ready_raw) == a.ready_freeze_sha256 and ready['actual_ready'] is True
        and ready['source_count'] == COUNT and ready['source_sha256'] == a.source_sha256, 'A2_reader_Ready')
    hashes = ready['source_hashes']
    require(type(hashes) is dict and len(hashes) == COUNT and u.sha(u.encode(hashes)) == a.source_sha256, 'A2_reader_source49_map')
    plan, plan_raw = u.json_file(R/'private'/a.plan_name, 16384)
    require(u.sha(plan_raw) == pub['recovery_plan_sha256'] and digest(plan.get('run'), 32), 'A2_reader_plan')
    stage = R/'private'/('local-lpac-stream-mihomo-origin-'+plan['run'])
    c, config_raw = u.json_file(stage/'worker-config.json', 512*1024)
    require(c['source_hashes'] == hashes and c['source_sha256'] == a.source_sha256
        and c['recovery_plan_sha256'] == u.sha(plan_raw)
        and u.read(stage/'recovery-plan.json', 16384) == plan_raw
        and pub['source_sha256'] == pre['source_sha256'] == a.source_sha256, 'A2_reader_config_plan_sources')
    commit = subprocess.check_output(['git', 'rev-parse', '--verify', a.source_commit+'^{commit}'], cwd=R).decode('ascii').strip()
    require(commit == a.source_commit, 'A2_reader_exact_historical_source_commit')
    names = sorted(hashes)
    require(ENTRY in hashes and all(re.fullmatch('[A-Za-z0-9_./-]+', n) and '..' not in n.split('/') for n in names), 'A2_reader_source_names')
    batch = subprocess.run(['git', 'cat-file', '--batch'], cwd=R, capture_output=True, check=True,
        input=''.join(commit+':'+n+'\n' for n in names).encode('ascii')).stdout
    at = 0
    for name in names:
        end = batch.index(b'\n', at); fields = batch[at:end].split()
        require(len(fields) == 3 and fields[1] == b'blob', 'A2_reader_Git_blob')
        size = int(fields[2]); at = end+1; blob = batch[at:at+size]; at += size
        require(batch[at:at+1] == b'\n', 'A2_reader_Git_extent'); at += 1
        raw = u.read(stage/name, 256*1024)
        require(raw == blob and u.sha(raw) == hashes[name] and b'\r' not in raw, 'A2_reader_all49_exact_Git_LF')
    require(at == len(batch), 'A2_reader_complete_Git_batch')
    spec = importlib.util.spec_from_file_location('bound_A2_staged_pure_validators', stage/ENTRY)
    m = importlib.util.module_from_spec(spec); spec.loader.exec_module(m)
    require(m.SCOPE == SCOPE and m.core.PROFILE == PROFILE and m.core.ACTUAL_READY is True
        and m.core.api_version() == 1 and set(m.SOURCES) == set(hashes), 'A2_reader_exact_interface')
    m.core.config_validate(c); m.validate_public(pub); m.validate_public(pre)
    require(pub['mode'] == 'runtime' and pre['mode'] == 'preflight' and pre['status'] == 'ready', 'A2_reader_public_modes')
    configuration = m.encode(m.core.mihomo_configuration(c['ports']))
    m.core.validate_plan(plan, device=c['device_sha256'], source=c['source_sha256'], actor=c['actor_sha256'],
        manifest=c['manifest_sha256'], network_actor=c['network_actor_sha256'], network_manifest=c['network_manifest_sha256'],
        challenges=c['challenges'], declared=c['ports'], configuration=configuration)
    require(all(c[k] == plan[k] for k in m.core.NONCES) and len({c[k] for k in m.core.NONCES}) == 2
        and c['root_deadline_qpc'] == c['start_qpc']+120*c['frequency']
        and c['deadline_qpc'] == c['root_deadline_qpc']-5*c['frequency'], 'A2_reader_original120_115_epoch')
    return m, stage, c, plan_raw, config_raw, u.desc(ready_raw), ready


def artifacts(u, m, stage, c, pub, pre, ready):
    m.core.verify_artifacts(c, stage); out = {}; original_inputs = {}
    for label, build_name, actor, manifest, pins, interface in (
        ('selected', SELECTED_BUILD, m.core.ACTOR, m.core.MANIFEST, m.core.NATIVE_SOURCES, 1),
        ('network', NETWORK_BUILD, m.core.NETWORK_ACTOR, m.core.NETWORK_MANIFEST, m.core.NETWORK_SOURCES, 2)):
        build = W/build_name; snapshot, snapshot_raw = u.json_file(build/'input-snapshot.json', 65536, inside=W)
        require(u.sha(snapshot_raw) == SNAPSHOTS[build_name] and len(snapshot) == (4 if label == 'selected' else 5), 'A2_reader_original_precompile_snapshot')
        for name, commitment in snapshot.items():
            raw = u.read(stage/name, 256*1024)
            require(u.desc(raw) == commitment and raw == u.read(build/'src'/Path(name).name, 256*1024, inside=W)
                and u.sha(raw) == c['source_hashes'][name], 'A2_reader_all_original_snapshot_inputs')
            original_inputs[name] = commitment
        body = u.read(stage/'inputs'/actor, 8*1024*1024); manifest_raw = u.read(stage/'inputs'/manifest, 8192)
        require((u.sha(body), u.sha(manifest_raw)) == ARTIFACTS[label]
            and body == u.read(build/actor, 8*1024*1024, inside=W)
            and manifest_raw == u.read(build/manifest, 8192, inside=W), 'A2_reader_original_artifact_bytes')
        value = u.decode(manifest_raw)
        require(len(pins) == (3 if label == 'selected' else 5) and value['interfaceVersion'] == interface,
            'A2_reader_distinct_native_interfaces')
        for key, name in pins.items(): require(value[key] == c['source_hashes'][name] == original_inputs[name]['sha256'], 'A2_reader_manifest_source')
        for field, pin in ((('actor_sha256' if label == 'selected' else 'network_actor_sha256'), u.sha(body)),
            (('manifest_sha256' if label == 'selected' else 'network_manifest_sha256'), u.sha(manifest_raw))):
            require(c[field] == pub[field] == pre[field] == pin, 'A2_reader_public_artifact_binding')
        review_name, review_hash = REVIEWS[build_name]
        review, review_raw = u.json_file(W/review_name, 65536, inside=W)
        require(u.sha(review_raw) == review_hash and review['passed'] is True, 'A2_reader_static_PE_review')
        expected = dict(build_directory=build_name, executable=dict(name=actor, **u.desc(body)),
            manifest=dict(name=manifest, **u.desc(manifest_raw)), interface_version=interface)
        require(ready['artifacts'][label] == expected, 'A2_reader_Ready_artifact')
        if label == 'selected': require(review['artifacts']['front']['executable'] == u.desc(body), 'A2_reader_original_selected_PE')
        else: require(review['artifact'] == u.desc(body) and review['manifest'] == u.desc(manifest_raw), 'A2_reader_new_network_PE')
        out[label] = dict(actor=u.desc(body), manifest=u.desc(manifest_raw), interface_version=interface, native_pin_count=len(pins),
            original_input_snapshot=u.desc(snapshot_raw), static_PE_review=u.desc(review_raw),
            toolchain=u.desc(u.read(build/'toolchain.json', 65536, inside=W)))
    path = m.core.core_bundle(stage, c)/'mihomo.exe'; raw = u.read(path, 64*1024*1024)
    require(u.desc(raw) == dict(bytes=MIHOMO_BYTES, sha256=MIHOMO_SHA)
        and c['mihomo_sha256'] == pub['mihomo_sha256'] == pre['mihomo_sha256'] == MIHOMO_SHA, 'A2_reader_fixed_large_Mihomo')
    require(ready['artifacts']['Mihomo'] == dict(executable=u.desc(raw), ordinary_private_sibling_bundle_required=True,
        release_reproducible_build=False, mihomo_binary_exact_tag_source_proven=False,
        mihomo_listener_exclusivity_verified=False), 'A2_reader_honest_Mihomo_metadata')
    configuration = m.core.verify_configuration(c, stage)
    require(u.sha(configuration) == c['mihomo_config_sha256'] == pub['mihomo_config_sha256'] == pre['mihomo_config_sha256']
        and u.sha(m.encode(c['ports'])) == pub['ports_sha256'] == pre['ports_sha256'], 'A2_reader_canonical_config_and_ports')
    out['Mihomo'] = dict(executable=u.desc(raw), ordinary_private_sibling_bundle=True, binary_exact_tag_source_proven=False,
        release_reproducible_build=False, actual_listener_exclusivity_verified=False)
    return dict(artifacts=out, canonical_configuration=u.desc(configuration), unique_original_compile_inputs=len(original_inputs),
        original_selected_unchanged=True, precompile_snapshots_not_reconstructed=True)


def payloads(u, m, stage, c, j):
    m.core.validate_sinks(j, c, root=stage); inputs = {}; sinks = {}
    for key, name in m.core.CHALLENGE_PATHS.items():
        raw = u.read(stage/name, 65536); require(u.desc(raw) == c['challenges'][key], 'A2_reader_actual_HTTP_input')
        info = m.core.http_challenge(raw, response=key == 'response', case=c['case'], origin_port=c['ports']['origin_port'])
        require(info == c['challenges'][key], 'A2_reader_HTTP_input_semantics'); inputs[key] = info
    for key, row in j['physical_sinks'].items():
        raw = u.read(stage/m.core.SINK_PATHS[key], 65536)
        require(u.desc(raw) == {k:row[k] for k in ('bytes','sha256')}, 'A2_reader_physical_sink')
        expected = inputs['request' if key in ('relay_request','origin_request') else 'response']
        sinks[key] = dict(**u.desc(raw), full_declared_challenge_exact=u.desc(raw) == expected)
    return dict(inputs=inputs, sinks=sinks, all_five_physical_sinks_exact=set(sinks) == set(m.core.SINK_PATHS)
        and all(v['full_declared_challenge_exact'] for v in sinks.values()), hashes_computed_from_files=True,
        native_hashes_used_for_bytes=False, HTTP_Content_Length_boundary=True, transparent_TCP_FIN=False)


def native_projection(u, m, stage, c, j, parent):
    out = []; valid = {}
    for key, name in m.core.REPORT_PATHS.items():
        row = j['reports'][key]; item = dict(slot=key, status=j['report_status'][key], commitment=u.optional(stage/name, m.core.MAX_NATIVE), parsed=False)
        if row is not None:
            raw, commitment = u.physical(row, stage/name, m.core.MAX_NATIVE); item['commitment'] = commitment
            # Do not decode an authentic malformed JSON report. Its byte/hash
            # commitment does not invalidate independently valid peer evidence.
            if j['report_status'][key] == 'valid': valid[key] = m.core.validate_native(key, u.decode(raw), j, c, parent); item['parsed'] = True
        if key in valid and key != 'ready':
            v = valid[key]
            item.update(failure=v['failure'], win32_error=v['win32_error'], wsa_error=v['wsa_error'],
                network_tested=v['network_tested'], selected_socket_api_tested=v['selected_socket_api_tested'], files=v['files'])
            if v['stream'] is not None:
                st, pipe = v['stream'], v['pipe']; item.update(stream=st, pipe=pipe,
                    dynamic_wire_counts_exact=pipe['write_bytes'] == 64*st['tx_frames']+st['tx_payload_bytes']
                        and pipe['read_bytes'] == 64*st['rx_frames']+st['rx_payload_bytes'])
            if v['network'] is not None: item['network'] = {k:x for k,x in v['network'].items() if k not in ('port','local_port','peer_port')}
            if key in ('relay','origin'): item.update(socks=v['socks'], HTTP=v['http'], message_boundary=v['message_boundary'])
        out.append(item)
    cross = None
    if 'selected' in valid and 'relay' in valid:
        a, b = valid['selected'], valid['relay']
        cross = all(a['stream'][x] == b['stream'][y] for x,y in (('tx_frames','rx_frames'),('rx_frames','tx_frames'),
            ('tx_payload_bytes','rx_payload_bytes'),('rx_payload_bytes','tx_payload_bytes'))) and a['pipe']['read_bytes'] == b['pipe']['write_bytes'] and a['pipe']['write_bytes'] == b['pipe']['read_bytes']
    return dict(reports=out, selected_relay_dynamic_frames_and_payload_cross_equal=cross,
        ordinary_expected_schema_key_count=29, ACK_expected_schema_key_count=22, selected_interface_version=1), valid


def extension_review(u, m, stage, c, j, rows, native):
    lease = j['port_lease']; lease_view = None
    if lease is not None:
        known, succeeded, cleanup = m.core.lease_facts(lease, c); calls = []
        for row in lease['calls']:
            op, value = row['operation'], row['value']; safe = dict(operation=op, returned=row['returned'], exception=row['exception'],
                return_clock_known=row['return_qpc'] is not None, timely_original_work=row['return_qpc'] is not None and row['return_qpc'] < m.core.work_cutoff(c))
            if row['returned'] and type(value) in (tuple,list):
                safe['wsa_error'] = value[1]
                if op.startswith('socket-'):
                    safe.update(socket_valid=value[0] != m.core.LeaseBackend.INVALID, SOCKET_zero_valid=value[0] == 0)
                else: safe['status'] = value[0]
                if op.startswith('read-exclusive-'): safe.update(option_enabled=value[2], option_length=value[3])
                if op.startswith('name-'):
                    key = op.removeprefix('name-')
                    safe['exact_declared_loopback_endpoint'] = value[2] == dict(family=2, port=c['ports'][key], address='7f000001', size=16)
            calls.append(safe)
        closes = []
        for r in lease['closes']:
            pair_typed = type(r['value']) in (tuple,list) and len(r['value']) == 2 and all(type(x) is int for x in r['value'])
            closes.append(dict(port_role=r['port_key'], attempted=r['attempted'], confirmed=r['confirmed'],
                raw_pair_typed=pair_typed, raw_status=r['value'][0] if pair_typed else None,
                wsa_error=r['value'][1] if pair_typed else None, exception=r['exception'], return_clock_known=r['return_qpc'] is not None))
        lease_view = dict(started=lease['started'], unknown=lease['unknown'], cleanup_attempted=lease['cleanup_attempted'],
            cleanup_confirmed=lease['cleanup_confirmed'], source_raw_success_recomputed=succeeded, source_known_cleanup_recomputed=known,
            calls=calls, closes=closes, sampled_socket_values_not_published=True)
    stdio = []
    for row in j['core_stdio']:
        task = rows[row['role']]
        stdio.append(dict(role=row['role'], opened_count=len(row['opened']), unique_opened=len(set(row['opened'])) == len(row['opened']),
            close_count=len(row['closes']), confirmed=row['confirmed'], all_once_closed=all(x['confirmed'] for x in row['closes']),
            exactly_three_inherited=row['opened'] == task['ends'] and len(row['opened']) == 3,
            closed_before_admission=task['admitted'] and all(x['qpc'] is not None and x['qpc'] <= task['admission_qpc'] for x in row['closes']),
            stdout=u.optional(stage/row['role']/'stdout', 2*1024*1024), stderr=u.optional(stage/row['role']/'stderr', 2*1024*1024)))
    pair = j['pair']; commands = {}; ack = None
    if j['barrier_ack'] is not None:
        raw, commitment = u.physical(j['barrier_ack'], stage/m.core.BARRIER_PATHS['ack'], m.core.MAX_NATIVE)
        ack = m.core.validate_ack(u.decode(raw), c, pair, origin_pid=rows[m.core.ROLES[2]]['pid'], arm_issued=j['barrier_commands']['arm']['issued_qpc'])
        ack_view = dict(commitment=commitment, exact_closed_keys=len(ack), accepted_count=ack['accepted_count'], request_bytes=ack['request_bytes'],
            request_message_complete=ack['request_message_complete'], request_eof_observed=ack['request_eof_observed'], response_bytes_sent=ack['response_bytes_sent'],
            socket_held=ack['socket_held'], command_closed=ack['phase_command_close_verified'], original_pair_domain=True,
            wait_at_most_two_seconds=ack['wait_deadline_qpc'] <= min(pair['end'], ack['qpc'][3]+2*c['frequency']))
    else: ack_view = None
    for key, row in j['barrier_commands'].items():
        raw = u.read(stage/row['path'], 128)
        require(raw.hex() == row['hex'] and u.sha(raw) == row['sha256']
            and raw == m.core.barrier_control(c, pair, row['issued_qpc'], release=key == 'release', ack=ack if key == 'release' else None), 'A2_reader_physical_barrier_command')
        commands[key] = dict(commitment=u.desc(raw), published=row['published_qpc'] is not None,
            original_pair_domain=True, exact128=True, response_release_not_REGENERATED_payload=True)
    tcp = {}
    for key, row in j['tcp'].items():
        raw = u.read(stage/'tcp'/row['name'], 1048576)
        if key == 'listeners': parsed = m.core.exact_listeners(raw, proxy_pid=rows[m.core.CORE_ROLES[1]]['pid'], origin_pid=rows[m.core.ROLES[2]]['pid'], declared=c['ports'])
        else:
            parsed = m.core.exact_two_hop(raw, relay_pid=rows[m.core.ROLES[1]]['pid'], proxy_pid=rows[m.core.CORE_ROLES[1]]['pid'],
                origin_pid=rows[m.core.ROLES[2]]['pid'], declared=c['ports'], origin_peer_port=ack['peer_port'])
        m.core.validate_tcp_record(row, root=stage, expected_rows=parsed)
        roles = (m.core.ROLES[2],m.core.CORE_ROLES[1],m.core.ROLES[1]) if key == 'two_hop' else (m.core.ROLES[2],m.core.CORE_ROLES[1])
        bracket = all(any(h['qpc'] <= row['before_qpc'] for h in rows[role]['held_checks'])
            and any(h['qpc'] >= row['after_qpc'] for h in rows[role]['held_checks']) for role in roles)
        tcp[key] = dict(commitment=u.desc(raw), independent_physical_parser_exact=True, held_generation_image_primary_both_jobs_bracket=bracket,
            listener_rows=2, established_rows=4 if key == 'two_hop' else 0, per_process_endpoints_not_published=True)
    barrier = native.get('origin', {}).get('barrier'); barrier_view = None
    if barrier is not None:
        m.core.validate_barrier(barrier, c, pair)
        barrier_view = {k:barrier[k] for k in (*m.core.BARRIER_FLAGS, 'failure','response_bytes_before_release')}
        barrier_view.update(response_started=barrier['response_started_qpc'] is not None,
            response_after_release=barrier['response_started_qpc'] is not None and barrier['release_admitted_qpc'] is not None
                and barrier['response_started_qpc'] >= barrier['release_admitted_qpc'])
    stop = j['core_stop']; stop_view = None
    if stop is not None:
        row = rows[m.core.CORE_ROLES[1]]; value = stop['observation']; commitment = None
        if stop['receipt'] is not None:
            raw, commitment = u.physical(stop['receipt'], stage/'returns'/stop['receipt']['name'], 65536)
            expected = dict(schema_version=1, scope=SCOPE, config_sha256=m.sha(m.encode(c)), role=m.core.CORE_ROLES[1], intent_qpc=stop['intent_qpc'], observation=value)
            require(u.decode(raw) == expected, 'A2_reader_exact_core_stop_return')
        stop_view = dict(receipt=commitment, exact_held_generation_image=[stop[k] for k in ('pid','created','image_sha256')] == [row[k] for k in ('pid','created','image_sha256')],
            completion_before_stop=j['completion_qpc'] is not None and j['completion_qpc'] <= stop['intent_qpc'],
            fresh_held_before_return=value is not None and any(h['qpc'] >= stop['intent_qpc'] and (value['returned_qpc'] is None or h['qpc'] <= value['returned_qpc']) for h in row['held_checks']),
            API_returned=None if value is None else value['returned'], raw_BOOL=None if value is None else value['raw_return'],
            win32_error=None if value is None else value['error'], exception=None if value is None else value['exception'] is not None,
            exit_observed=stop['observed_exit_qpc'] is not None, exit_code=stop['exit_code'], source_confirmed=m.core.controlled_stop_confirmed(j))
    return dict(core_check_completed=j['core_check_completed'], core_stdio=stdio, core_stdio_closed=j['core_stdio_closed'], leases=lease_view,
        port_leases_closed=j['port_leases_closed'], barrier_commands=commands, ACK=ack_view, native_response_barrier=barrier_view,
        physical_TCP=tcp, kernel_TCP_observed=j['kernel_tcp_snapshot_observed'], core_controlled_stop=stop_view,
        finite_core_integration_observed=j['core_integration_observed'], actual_Mihomo_listener_exclusive_option_verified=False)


def result_review(u, m, stage, c, pub, outer):
    path = stage/'worker-report.json'
    result = dict(worker_report_present=path.exists(), worker_result_valid=False, worker_binding_valid=False, public_projection_exact=False,
        safe_projection_complete=False, validation_error=None, binding_error=None, projection_error=None, held_tasks=None, proof=None,
        payload_files=None, native=None, extension=None, pipe=None, journal=None, epoch=None, cleanup=None, optional_projection_errors={})
    if not path.exists():
        require(pub['checks']['worker_bound'] is False and pub['observation'] is None and not pub['observation_complete'], 'A2_reader_missing_worker_unknown')
        return result
    section = 'validation'
    try:
        report, raw = u.json_file(path, m.MAX_REPORT); parent = report['worker_identity']; j = report['result']
        m.core.validate_result(j, c, parent=parent, root=stage); result['worker_result_valid'] = True
        section = 'binding'; require(outer is not None, 'A2_reader_missing_outer')
        require(u.read(stage/'worker-result-forensic.json', m.MAX_REPORT) == raw, 'A2_reader_forensic_exact_not_fallback')
        rebound = copy.deepcopy(pub); m.bind_report(report, c, parent, outer, rebound, root=stage)
        require(rebound['observation'] == pub['observation'] and rebound['checks']['worker_bound'] == pub['checks']['worker_bound']
            and rebound['checks']['mechanism'] == pub['checks']['mechanism'], 'A2_reader_public_projection_exact')
        require(outer['child_identity'] == m.launcher.safe_identity(parent, parent)
            and pub['checks']['worker_exit'] == (outer.get('cleanup', {}).get('process_exit_confirmed') is True)
            and pub['checks']['outer_cleanup'] == m.local.guest.cleanup_verified(outer), 'A2_reader_exact_held_outer')
        if pub['observation_complete']: require(outer.get('resumed') is True and outer.get('timed_out') is not True
            and outer.get('exit_code') == 0 and 'error' not in outer, 'A2_reader_complete_outer0')
        result.update(worker_binding_valid=True, public_projection_exact=True); section = 'projection'
        rows = {r['name']:r for r in j['tasks']}; tasks = []
        for role in (*m.core.ROLES, *m.core.CORE_ROLES):
            if role not in rows: continue
            row = rows[role]
            tasks.append(dict(role=role, attempted=row['attempted'], created=row['process_returned'], admitted=row['admitted'], resumed=row['resumed'],
                exited=row['exited'], exit_code=row['exit_code'], held_snapshot_count=len(row['held_checks']), capabilities_empty=row['capabilities'] == [],
                all_held_generation_image_primary_both_jobs=bool(row['held_checks']) and all(h['pid'] == row['pid'] and h['created'] == row['created']
                    and h['image_sha256'] == row['image_sha256'] and h['primary'] == row['expected_primary'] and h['inner_job'] is h['outer_job'] is True for h in row['held_checks']),
                raw_return_receipt=None if row['receipt'] is None else u.physical(row['receipt'], stage/'returns'/row['receipt']['name'])[1]))
        intents = [u.physical(row, stage/'journal'/row['name'], 4096)[1] for row in j['intents']]
        allocated = []; returns = []
        for row in j['pipe_allocations']:
            if row['adopted']: allocated.extend(row['raw_outputs'])
            if row['receipt'] is not None: returns.append(u.physical(row['receipt'], stage/'returns'/row['receipt']['name'])[1])
        closes = j['parent_pipe_close_attempts']; directions = None
        if len(allocated) == 4 and all(k in rows for k in m.core.ROLES[:2]):
            directions = rows[m.core.ROLES[0]]['ends'] == [allocated[0],allocated[3]] and rows[m.core.ROLES[1]]['ends'] == [allocated[2],allocated[1]]
        native, valid = native_projection(u, m, stage, c, j, parent)
        pair = j['pair']
        result.update(held_tasks=tasks, proof=u.safe_proof(j['proof']), native=native,
            pipe=dict(allocations=len(j['pipe_allocations']), allocation_unknown=j['pipe_allocation_unknown'], return_receipts=returns,
                inherited_exact_two_each_direction=directions, parent_close_count=len(closes), exact_four_once_closed=len(closes) == 4
                    and {x['handle'] for x in closes} == set(allocated) and all(x['confirmed'] for x in closes)),
            journal=dict(intent_count=len(intents), commitments=intents),
            epoch=dict(root120_worker115=True, pair10=pair is not None and pair['end'] == pair['start']+10*c['frequency'],
                original_work85=pair is not None and pair['end'] <= m.core.work_cutoff(c),
                completed_within_pair=j['completion_qpc'] is not None and pair is not None and j['completion_qpc'] < pair['end']),
            three_native_natural0=all(role in rows and rows[role]['resumed'] and rows[role]['exited'] and rows[role]['exit_code'] == 0 for role in m.core.ROLES),
            config_check_natural0=m.core.CORE_ROLES[0] in rows and rows[m.core.CORE_ROLES[0]]['resumed'] and rows[m.core.CORE_ROLES[0]]['exited'] and rows[m.core.CORE_ROLES[0]]['exit_code'] == 0,
            workload_stop=j['workload_stop'], cleanup={k:j[k] for k in m.core.CLEAN_KEYS},
            ordinary_tool_exits=[dict(operation=r['name'], admitted=r['admitted'], resumed=r['resumed'], exited=r['exited'], exit_code=r['exit_code'])
                for r in (*j['tasks'], *j['cleanup_tasks']) if r['role'] not in (*m.core.ROLES, *m.core.CORE_ROLES)])
        # Optional presentation failures do not erase validated peer facts or
        # collapse worker-schema validity into a safe-view completeness flag.
        for name, call in (('payload_files', lambda: payloads(u, m, stage, c, j)),
            ('extension', lambda: extension_review(u, m, stage, c, j, rows, valid))):
            try: result[name] = call()
            except Exception as error: result['optional_projection_errors'][name] = u.error(error)
        result['safe_projection_complete'] = not result['optional_projection_errors']
    except Exception as error: result[{'validation':'validation_error','binding':'binding_error','projection':'projection_error'}[section]] = u.error(error)
    return result


def audit(a):
    u = utility()
    require(digest(a.source_commit, 40) and all(digest(getattr(a, n)) for n in ('source_sha256','ready_freeze_sha256',
        'public_sha256','preflight_sha256','driver_sha256','capture_sha256')), 'A2_reader_operator_pins')
    require(re.fullmatch('[a-z0-9-]{1,96}', a.prefix) and a.public_bytes > 0 and a.preflight_bytes > 0, 'A2_reader_public_pin_types')
    for key in ('plan_name','before_snapshot_name','after_snapshot_name'): u.work_name(getattr(a, key))
    pub, public_raw = u.json_file(R/'verification/windows-2026-10-22'/(a.prefix+'-public.json'), 16384)
    pre, preflight_raw = u.json_file(R/'verification/windows-2026-10-22'/(a.prefix+'-preflight.json'), 16384)
    require(u.desc(public_raw) == dict(bytes=a.public_bytes, sha256=a.public_sha256)
        and u.desc(preflight_raw) == dict(bytes=a.preflight_bytes, sha256=a.preflight_sha256), 'A2_reader_original_public_preflight')
    m, stage, c, plan_raw, config_raw, ready_desc, ready = bind_sources(u, a, pub, pre)
    built = artifacts(u, m, stage, c, pub, pre, ready)
    path = stage/'outer-launch-report.json'; outer, outer_raw = u.json_file(path, m.MAX_REPORT) if path.exists() else (None, None)
    require((u.sha(outer_raw) if outer_raw is not None else None) == pub['outer_launch_report_sha256'], 'A2_reader_raw_outer_hash')
    driver = u.read(u.work_name(a.driver_name), 256*1024, inside=W); require(u.sha(driver) == a.driver_sha256, 'A2_reader_driver_pin')
    groups = {}
    for group, maximum in (('journal',48), ('returns',8)):
        directory = stage/group; paths = sorted(directory.iterdir()) if directory.exists() else []
        require(len(paths) <= maximum, 'A2_reader_bounded_evidence_count')
        groups[group] = [u.desc(u.read(path, 65536)) for path in paths]
    return dict(schema_version=1, stage='lpac-stream-mihomo-origin-actual-file-review', scope=SCOPE, profile=PROFILE,
        source_commit=a.source_commit, source_sha256=a.source_sha256, source_count=COUNT, Ready=ready_desc,
        public=u.desc(public_raw), preflight=u.desc(preflight_raw), original_status=pub['status'], original_failure=pub['failure'],
        original_observation_complete=pub['observation_complete'], original_recovery_required=pub['recovery_required'],
        original_safe_observation=pub['observation'], fixed_false_claims={k:pub[k] for k in m.core.FALSE_CLAIMS}, compiled_artifacts=built,
        private_commitments=dict(plan=u.desc(plan_raw), config=u.desc(config_raw), outer_report=None if outer_raw is None else u.desc(outer_raw),
            worker_report=u.optional(stage/'worker-report.json', m.MAX_REPORT), forensic=u.optional(stage/'worker-result-forensic.json', m.MAX_REPORT),
            stdout=u.optional(stage/'guard/controller.stdout', 2*1024*1024), stderr=u.optional(stage/'guard/controller.stderr', 2*1024*1024), driver=u.desc(driver)),
        physical_evidence_commitments=groups, result_review=result_review(u, m, stage, c, pub, outer), globals=u.globals_review(a),
        reader_helper=dict(name=UTILITY, sha256=UTILITY_SHA), reader_actions=dict(file_only=True, production_backend_constructed=False,
            actor_Mihomo_or_cleanup_called=False, security_or_network_configuration_changed=False), limitations=[
            'No positive, denial or successful full-suite status is preselected. Missing worker stays unknown; forensic never substitutes.',
            'Committed invalid native JSON stays hash-only partial evidence; independently valid ordinary peer facts remain available.',
            'Exact owner/config/source/Jobs/primary/LPAC proof, original120/115/85/10, five physical sinks, closed ACK and raw four TCP rows qualify only this finite HTTP-message exchange.',
            'Core config-check natural0, native3 natural0 and deliberate exact core stop1 are separate outcomes; Job-kill cleanup is not natural completion.',
            'Mihomo61MiB is separately bounded and ordinary-only. Binary vcs.modified=true remains a source-equivalence limit; actual listener exclusivity is unverified.',
            'No transparent TCP FIN/concurrent full-duplex, default DNS, incidental-external-I/O exclusion, arbitrary apps/browser, PSEC/G, Linux or product qualification.',
            'Original/before/after four global objects are actually compared; any route difference retains unknown writer attribution. No capture/route cleanup is executed.'])


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__); parser.add_argument('--verify-file-only', action='store_true')
    parser.add_argument('--prefix', default='lpac-stream-mihomo-origin-local-01')
    names = ('source-commit','source-sha256','ready-freeze-name','ready-freeze-sha256','public-sha256','preflight-sha256',
        'driver-name','driver-sha256','capture-name','capture-sha256','plan-name','before-snapshot-name','after-snapshot-name')
    for name in names: parser.add_argument('--'+name)
    parser.add_argument('--public-bytes', type=int); parser.add_argument('--preflight-bytes', type=int)
    parser.add_argument('--output-name', default='lpac-stream-mihomo-origin-actual-01-independent-review.json')
    a = parser.parse_args(argv)
    if not a.verify_file_only:
        print(json.dumps(dict(stage='A2-file-reader-candidate-preview', scope=SCOPE, verification_executed=False,
            repo_imported=False, actual_files_read=False, files_written=False, final_operator_pins_required=True), sort_keys=True))
        return 0
    require(all(getattr(a, key.replace('-', '_')) is not None for key in (*names,'public-bytes','preflight-bytes')), 'A2_reader_final_pins_required')
    u = utility(); output = u.work_name(a.output_name); require(not output.exists(), 'A2_reader_fresh_output')
    value = audit(a); raw = (json.dumps(value, sort_keys=True, indent=2)+'\n').encode('ascii')
    with output.open('xb') as out: require(out.write(raw) == len(raw), 'A2_reader_exact_output')
    print(json.dumps(dict(review=u.desc(raw), worker_result_valid=value['result_review']['worker_result_valid'], original_status=value['original_status']), sort_keys=True))
    return 0


if __name__ == '__main__': raise SystemExit(main())
