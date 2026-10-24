"""Root-only one-shot finite A2 driver; default is an inert stdlib preview.

The separately reviewed explicit execution launches ordinary config-check/live
Mihomo processes and two bound-only local port leases, then the finite owned
TCP/pipe exchange. It creates only fresh private assay inputs and the owner's
owned profile/ACL/label resources. This is a new finite HTTP-message scope;
incidental external activity, listener exclusivity, transparent FIN, arbitrary
applications, DNS isolation, PSEC and Linux/product qualification remain false.
"""
from __future__ import annotations
import argparse
import hashlib
import json
from pathlib import Path
import re
import stat
import subprocess

W = Path(__file__).resolve().parent
R = W/'Rule-proxy-Web'
ENTRY = '.github/windows_identity_lpac_stream_mihomo_origin_local.py'
CORE = '.github/windows_identity_lpac_stream_mihomo_origin.py'
SCOPE = 'one-local-semantic-lpac-inherited-stream-mihomo-http-message-v1'
PROFILE = 'zero-cap-lpac-RPS1-fixed-SOCKS5-Mihomo-owned-HTTP-v1'
SOURCE_COUNT = 49
# Exact independently tested False->True single-literal view. The final Ready
# name/hash and committed source are separately supplied by root, never guessed.
EXPECTED_SOURCE = '73e02a396c3b9bf698d00ab1280c80b4d4889e3aaf0c62d818afd885034dd28a'
SELECTED_BUILD = W/'lpac-stream-native-compile-01'
NETWORK_BUILD = W/'lpac-stream-mihomo-native-compile-01'
ACTOR = 'windows_identity_lpac_stream_front_actor.exe'
MANIFEST = 'identity-lpac-stream-front-manifest.json'
NETWORK_ACTOR = 'windows_identity_lpac_stream_mihomo_network_actor.exe'
NETWORK_MANIFEST = 'identity-lpac-stream-mihomo-network-manifest.json'
AH = 'b7327db1d30f4d81f7806b449d191cf7d49e22563c1da0c734f85cd478c9ae2a'
MH = '9a9df1de567bc4c6a9d0de334adeed4665fba2ade5ae5b62d26279d37134c4ba'
NH = 'ef419337943b8b3acdc538a9c2904ca81cf304b9de0ed8149de23b655ac1b2a7'
NMH = '41128b9ca698bc84412de280b07a431975f1774671e1617f4273d6946e736685'
NATIVE = {
    'actorSourceSha256': '.github/native/windows_identity_lpac_stream_front_actor.cpp',
    'streamContractSha256': '.github/native/windows_identity_lpac_stream_contract.hpp',
    'identitySourceSha256': '.github/native/windows_identity_actor.cpp'}
NETWORK_NATIVE = {
    'actorSourceSha256': '.github/native/windows_identity_lpac_stream_mihomo_network_actor.cpp',
    'httpContractSha256': '.github/native/windows_identity_lpac_stream_mihomo_http.hpp',
    'networkBaseSourceSha256': '.github/native/windows_identity_lpac_stream_network_actor.cpp',
    'streamContractSha256': '.github/native/windows_identity_lpac_stream_contract.hpp',
    'identitySourceSha256': '.github/native/windows_identity_actor.cpp'}
REVIEWS = (
    ('lpac-stream-native-compile-static-review-01.json', '8388a661c10036a7676fc79b3b595a141905e2a87b734a777809878456cf5d35'),
    ('lpac-stream-mihomo-native-compile-static-review-01.json', 'ee02b13e2f632c6e299a288183bc020afa19fbd8117b40d703730a6cd5d8eb5b'))
MIHOMO = W/'mihomo-fixed-input-01/mihomo.exe'
MIHOMO_BYTES = 61276672
MIHOMO_SHA = '04f8d7fc2b314771e1ecbf15951d59f0e1cb7914503c88cfb6972ff6a824e314'
ACKS = (
    'fresh_profile_owned_acl_acknowledged', 'zero_capabilities_no_fallback_acknowledged',
    'trusted_actor_mechanism_only_acknowledged', 'cooperative_bounded_stream_acknowledged',
    'independent_unpredictable_binary_challenges_acknowledged', 'inherited_pipe_authority_acknowledged',
    'residue_review_acknowledged', 'real_mihomo_ordinary_core_acknowledged',
    'finite_HTTP_message_adapter_acknowledged', 'controlled_core_stop_acknowledged',
    'initial_download_source_review_acknowledged')
NONCES = ('run', 'case')
PRIVATE = R/'private'
EVIDENCE = R/'verification/windows-2026-10-22'
ARTIFACT = PRIVATE/'lpac-stream-mihomo-native02-actual01'
PLAN = PRIVATE/'lpac-stream-mihomo-origin-recovery-plan-01.json'
PUBLIC = EVIDENCE/'lpac-stream-mihomo-origin-local-01-public.json'
PREFLIGHT = EVIDENCE/'lpac-stream-mihomo-origin-local-01-preflight.json'
BEFORE = PRIVATE/'lpac-stream-mihomo-origin-before-mihomo01-global-snapshot.json'


def require(ok, label):
    if not ok: raise ValueError(label)


def sha(raw): return hashlib.sha256(raw).hexdigest()
def digest(value): return type(value) is str and re.fullmatch('[0-9a-f]{64}', value) is not None
def meta(raw): return dict(bytes=len(raw), sha256=sha(raw))


def unique(rows):
    value = {}
    for key, item in rows:
        require(key not in value, 'duplicate JSON key'); value[key] = item
    return value


def decode(raw):
    return json.loads(raw.decode('utf-8-sig', 'strict'), object_pairs_hook=unique,
        parse_constant=lambda _: (_ for _ in ()).throw(ValueError('nonfinite JSON')))


def encode(value):
    return (json.dumps(value, sort_keys=True, separators=(',', ':'))+'\n').encode('ascii')


def bounded(path, limit):
    path = Path(path).absolute(); require(path.is_relative_to(W), 'owned WORK input path'); current = W
    for part in (None, *path.relative_to(W).parts):
        if part is not None: current = current/part
        info = current.lstat()
        require(not stat.S_ISLNK(info.st_mode) and not getattr(info, 'st_file_attributes', 0)&0x400, 'no reparse input')
    require(stat.S_ISREG(info.st_mode) and 0 < info.st_size <= limit, 'bounded regular input')
    raw = path.read_bytes(); require(len(raw) == info.st_size, 'stable input read'); return raw


def work_name(value):
    require(type(value) is str and re.fullmatch('[A-Za-z0-9_.-]{1,128}', value)
        and Path(value).name == value, 'explicit Ready basename')
    return W/value


def put(path, raw):
    import os
    with path.open('xb') as out:
        require(out.write(raw) == len(raw), 'fresh exact output'); out.flush(); os.fsync(out.fileno())


def git(*args): return subprocess.check_output(['git', '-C', str(R), *args])


def artifact(build, actor, manifest, ah, mh, pins, interface, head):
    body = bounded(build/actor, 8*1024*1024); raw = bounded(build/manifest, 8192); value = decode(raw)
    require(meta(body)['sha256'] == ah and sha(raw) == mh, 'original compiled artifact pins')
    require(type(value) is dict and set(value) == {'schemaVersion', 'compileOnly', 'runtimeAcceptance',
        'interfaceVersion', 'executableSha256', *pins}, 'closed native manifest')
    require(type(value['schemaVersion']) is type(value['interfaceVersion']) is int
        and value['schemaVersion'] == 1 and value['interfaceVersion'] == interface
        and value['compileOnly'] is True and value['runtimeAcceptance'] is False
        and value['executableSha256'] == ah, 'compile-only typed interface')
    for key, name in pins.items():
        source = bounded(R/name, 256*1024)
        require(sha(source) == value[key] and source == git('show', head+':'+name)
            == bounded(build/'src'/Path(name).name, 256*1024), 'manifest/Git/original precompile source')
    return body, raw


def actual(args):
    require(args.acknowledge_core_and_port_lease_impact, 'explicit new finite A2 impact acknowledgment')
    require(type(args.source_commit) is str and re.fullmatch('[0-9a-f]{40}', args.source_commit) is not None
        and git('rev-parse', 'HEAD').decode().strip() == args.source_commit, 'explicit exact current source commit')
    require(all(digest(value) for value in (args.source_sha256, args.ready_freeze_sha256, args.before_sha256))
        and args.source_sha256 == EXPECTED_SOURCE, 'explicit reviewed promoted source/Ready/before pins')
    ready_raw = bounded(work_name(args.ready_freeze_name), 256*1024)
    require(sha(ready_raw) == args.ready_freeze_sha256, 'final Ready byte pin'); ready = decode(ready_raw)
    require(ready['actual_ready'] is True and ready['source_count'] == SOURCE_COUNT
        and ready['source_sha256'] == args.source_sha256, 'reviewed promoted A2 source49')
    hashes = ready['source_hashes']
    require(type(hashes) is dict and len(hashes) == SOURCE_COUNT and ENTRY in hashes and CORE in hashes
        and all(digest(value) for value in hashes.values()) and sha(encode(hashes)) == args.source_sha256, 'canonical source49 map')
    for name, pin in hashes.items():
        require(type(name) is str and name.startswith(('.github/', 'ruleproxy/')) and '..' not in Path(name).parts,
            'relative source path')
        raw = bounded(R/name, 256*1024)
        require(b'\r' not in raw and sha(raw) == pin and raw == git('show', args.source_commit+':'+name),
            'all49 exact Git LF bytes before import')
    selected = artifact(SELECTED_BUILD, ACTOR, MANIFEST, AH, MH, NATIVE, 1, args.source_commit)
    network = artifact(NETWORK_BUILD, NETWORK_ACTOR, NETWORK_MANIFEST, NH, NMH, NETWORK_NATIVE, 2, args.source_commit)
    for label, payloads, build, actor, manifest, interface in (
        ('selected', selected, SELECTED_BUILD, ACTOR, MANIFEST, 1),
        ('network', network, NETWORK_BUILD, NETWORK_ACTOR, NETWORK_MANIFEST, 2)):
        require(ready['artifacts'][label] == dict(build_directory=build.name,
            executable=dict(name=actor, **meta(payloads[0])), manifest=dict(name=manifest, **meta(payloads[1])),
            interface_version=interface), 'Ready exact original artifact '+label)
    for name, pin in REVIEWS:
        raw = bounded(W/name, 65536); require(sha(raw) == pin and decode(raw)['passed'] is True, 'original static PE review')
    # The 61 MiB input has a separate role-specific bound. It is not staged in
    # the 24 MiB profile/ACL tree; the guard copies it to an ordinary-only sibling.
    mihomo_raw = bounded(MIHOMO, 64*1024*1024)
    require(meta(mihomo_raw) == dict(bytes=MIHOMO_BYTES, sha256=MIHOMO_SHA)
        and ready['artifacts']['Mihomo'] == dict(executable=meta(mihomo_raw),
            ordinary_private_sibling_bundle_required=True, release_reproducible_build=False,
            mihomo_binary_exact_tag_source_proven=False, mihomo_listener_exclusivity_verified=False), 'fixed Mihomo and honest limits')
    del mihomo_raw
    require(sha(bounded(BEFORE, 256*1024)) == args.before_sha256, 'independent before capture byte pin')
    # Equality to old captures is not required. Root obtains after separately.
    require(PRIVATE.is_dir() and EVIDENCE.is_dir() and all(not path.exists() and not path.is_symlink()
        for path in (ARTIFACT, PLAN, PREFLIGHT, PUBLIC)), 'fresh separate A2 actual01 destinations')
    import importlib.util
    loader = importlib.util.spec_from_file_location('root_finite_A2_actual01', R/ENTRY)
    module = importlib.util.module_from_spec(loader); loader.loader.exec_module(module)
    require(module.SCOPE == SCOPE and module.core.PROFILE == PROFILE and module.core.ACTUAL_READY is True
        and module.core.api_version() == 1, 'new finite scope/Ready/interface')
    require(set(module.SOURCES) == set(hashes) and tuple(module.core.NONCES) == NONCES
        and tuple(module.core.ACKS) == ACKS, 'exact source nonce and eleven acknowledgment ABI')
    require(module.core.NATIVE_SOURCES == NATIVE and module.core.NETWORK_SOURCES == NETWORK_NATIVE
        and (module.core.ACTOR, module.core.MANIFEST, module.core.NETWORK_ACTOR, module.core.NETWORK_MANIFEST)
            == (ACTOR, MANIFEST, NETWORK_ACTOR, NETWORK_MANIFEST)
        and (module.core.MIHOMO_BYTES, module.core.MIHOMO_SHA256) == (MIHOMO_BYTES, MIHOMO_SHA), 'separate fixed artifacts')
    _, observed, source = module.snapshot(R)
    require(observed == hashes and source == args.source_sha256, 'post-import source49 recheck')
    module.core.verify_actor(SELECTED_BUILD/ACTOR, SELECTED_BUILD/MANIFEST, AH, MH, root=R)
    module.core.verify_actor(NETWORK_BUILD/NETWORK_ACTOR, NETWORK_BUILD/NETWORK_MANIFEST, NH, NMH, root=R, network=True)
    module.core.verify_mihomo(MIHOMO, MIHOMO_SHA)
    # First explicit Windows backend below. The default preview never imports
    # project code; imports on this explicit path may initialize libraries/WSA.
    api = module.local.LocalNativeAPI(); parent = module.local.ordinary(api)
    import os
    import secrets
    nonce = {name: secrets.token_hex(16) for name in NONCES}
    require(len(set(nonce.values())) == 2, 'distinct fresh nonce pair')
    require(all(not path.exists() and not path.is_symlink() for path in
        (PRIVATE/module.core.stage_name(nonce['run']), PRIVATE/module.core.bundle_name(nonce['run']))), 'fresh stage and core bundle')
    # Sample once; do not query the current port table, probe a listener or retry
    # another port on collision. The two exact bound-only leases are owner work.
    O, M = secrets.SystemRandom().sample(range(49153, 65536), 2)
    declared = module.core.ports(dict(origin_port=O, proxy_port=M))
    payloads = {}
    for key, response, total in (('request', False, 8193), ('response', True, 12289)):
        header = module.core.canonical_header(response, nonce['case'], O, total)
        prefix = bytes(reversed(range(256))) if response else bytes(range(256))
        body = prefix+b'RPS1'+os.urandom(total-len(header)-260)
        payloads[key] = module.core.build_challenge(body, response=response, case=nonce['case'], origin_port=O)
    require(payloads['request'] != payloads['response'], 'independent binary request and response')
    challenges = {key: meta(raw) for key, raw in payloads.items()}
    module.core.stream.challenge_meta(challenges)
    configuration = module.encode(module.core.mihomo_configuration(declared))
    require(0 < len(configuration) <= 32768, 'bounded predeclared finite core configuration')
    reference = ('Finite A2 HTTP messages via zero-cap LPAC inherited RPS1, ordinary relay, held fixed Mihomo and owned origin. '
        'Original120/115/85/10 deadlines; two fixed bound-only leases, exact held Jobs/token/matrix, ACK0response and four TCP rows before release. '
        'Independent HTTP binary inputs; five physical sinks after holders exit. Only core gets controlled stop1. '
        'Restore owned labels/ACL/profile when known; retain unknown. No FIN transparency, DNS/Linux/PSEC/app/product or incidental-I/O claim.')
    require(len(reference) <= 512, 'bounded new-scope recovery reference')
    plan = dict(schema_version=1, scope=SCOPE, profile=PROFILE, **nonce, device_sha256=api.device_sha256(),
        source_sha256=source, actor_sha256=AH, manifest_sha256=MH, network_actor_sha256=NH, network_manifest_sha256=NMH,
        challenges=challenges, ports=declared, mihomo_sha256=MIHOMO_SHA, mihomo_bytes=MIHOMO_BYTES,
        mihomo_bundle=module.core.bundle_name(nonce['run']), mihomo_config_sha256=sha(configuration),
        **dict.fromkeys(ACKS, True), recovery_reference=reference)
    module.core.validate_plan(plan, device=plan['device_sha256'], source=source, actor=AH, manifest=MH,
        network_actor=NH, network_manifest=NMH, challenges=challenges, declared=declared, configuration=configuration)
    api.private_directory(ARTIFACT, parent['sid'])
    for name, raw in ((ACTOR, selected[0]), (MANIFEST, selected[1]), (NETWORK_ACTOR, network[0]),
        (NETWORK_MANIFEST, network[1]), ('request.bin', payloads['request']), ('response.bin', payloads['response'])):
        put(ARTIFACT/name, raw)
    module.core.challenge_inputs(ARTIFACT/'request.bin', ARTIFACT/'response.bin', challenges, case=nonce['case'], origin_port=O)
    put(PLAN, module.encode(plan))
    call = (ARTIFACT/ACTOR, ARTIFACT/MANIFEST, AH, MH, ARTIFACT/NETWORK_ACTOR, ARTIFACT/NETWORK_MANIFEST, NH, NMH,
        MIHOMO, ARTIFACT/'request.bin', ARTIFACT/'response.bin', PRIVATE, PLAN)
    pre = module.preflight(*call); put(PREFLIGHT, module.encode(pre)); require(pre['status'] == 'ready', 'new-scope preflight qualification')
    result = module.run_local(*call, approved=True); module.validate_public(result)
    require(all(result[key] is False for key in module.core.FALSE_CLAIMS), 'fixed unsupported claims remain false')
    raw = module.encode(result); put(PUBLIC, raw)
    print(json.dumps(dict(source_commit=args.source_commit, source_sha256=source, public_bytes=len(raw),
        public_sha256=sha(raw), result=result), sort_keys=True))
    return 0 if result['status'] == 'observed' else 1


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--execute-root-reviewed', action='store_true')
    parser.add_argument('--acknowledge-core-and-port-lease-impact', action='store_true')
    for name in ('source-commit', 'source-sha256', 'ready-freeze-name', 'ready-freeze-sha256', 'before-sha256'):
        parser.add_argument('--'+name)
    args = parser.parse_args(argv)
    if not args.execute_root_reviewed:
        print(json.dumps(dict(mode='inert-stdlib-preview', scope=SCOPE, profile=PROFILE, source_count=SOURCE_COUNT,
            expected_promoted_source_sha256=EXPECTED_SOURCE, final_source_Ready_before_pins_required=True,
            explicit_new_scope_impact_ack_required=True,
            impact='ordinary config-check/live Mihomo, two bound-only port leases, finite owned TCP/pipe exchange; owned profile/ACL/label lifecycle',
            incidental_external_activity_excluded=False, mihomo_binary_exact_tag_source_proven=False,
            mihomo_listener_exclusivity_verified=False, project_imported=False, randomness_generated=False,
            port_queried=False, files_written=False, native_API_actor_or_Mihomo_called=False, actual_executed=False,
            one_attempt_only=True), sort_keys=True))
        return 0
    return actual(args)


if __name__ == '__main__': raise SystemExit(main())
