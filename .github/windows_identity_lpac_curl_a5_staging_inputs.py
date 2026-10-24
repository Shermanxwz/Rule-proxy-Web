"""Closed A5 file inputs/staging. No native construction or execution on import."""
from pathlib import Path

SOURCE_KEYS=frozenset(('network_actor','network_manifest','mihomo','request_body','response'))
NETWORK_ACTOR='windows_identity_lpac_stream_mihomo_network_actor.exe'
NETWORK_MANIFEST='identity-lpac-stream-mihomo-network-manifest.json'
FIXED={
    'network_actor':dict(bytes=284672,sha256='ef419337943b8b3acdc538a9c2904ca81cf304b9de0ed8149de23b655ac1b2a7'),
    'network_manifest':dict(bytes=672,sha256='41128b9ca698bc84412de280b07a431975f1774671e1617f4273d6946e736685'),
    'mihomo':dict(bytes=61276672,sha256='04f8d7fc2b314771e1ecbf15951d59f0e1cb7914503c88cfb6972ff6a824e314')}
DIRS=('inputs','ordinary-inputs','expected','origin-report','relay-report','core-home','origin-control','tcp',
      'ordinary-origin-fixture','ordinary-pipe-relay','mihomo-config-check','mihomo-core')
TEMPS=('origin-report','relay-report','ordinary-origin-fixture','ordinary-pipe-relay','mihomo-config-check','mihomo-core')

def bundle(root,run):
    if type(run) is not str or len(run)!=32 or any(c not in '0123456789abcdef' for c in run):raise ValueError('a5_bundle_run')
    return Path(root).parent/('mihomo-a5-private-bundle-'+run)

def metadata(m,proxy):
    require=m.require
    require(type(proxy) is dict and set(proxy)=={'ports','virtual_local_port','artifacts','mihomo_config_sha256','challenges','request_body'},'a5_proxy_keys')
    ports=m.proxy_protocol.ports(proxy['ports'])
    require(type(proxy['virtual_local_port']) is int and 49153<=proxy['virtual_local_port']<=65535
            and proxy['virtual_local_port'] not in ports.values(),'a5_virtual_port')
    require(type(proxy['artifacts']) is dict and proxy['artifacts']==FIXED,'a5_proxy_fixed_artifacts')
    require(type(proxy['challenges']) is dict and set(proxy['challenges'])=={'request','response'},'a5_challenge_keys')
    for entry in (*proxy['artifacts'].values(),proxy['request_body'],*proxy['challenges'].values()):
        require(type(entry) is dict and set(entry)=={'bytes','sha256'} and type(entry['bytes']) is int
                and entry['bytes']>0 and m.base.ac.digest(entry['sha256']),'a5_proxy_pin')
    require(set(proxy['challenges'])=={'request','response'} and proxy['challenges']['request']['bytes']==8193
            and proxy['challenges']['response']['bytes']==12289 and proxy['request_body']['bytes']==8065,'a5_proxy_lengths')
    configuration=m.encode(m.proxy_protocol.mihomo_configuration(ports))
    require(m.sha(configuration)==proxy['mihomo_config_sha256'],'a5_proxy_configuration')
    return configuration

def checked(m,paths,proxy,*,case,root):
    configuration=metadata(m,proxy);require=m.require
    require(type(paths) is dict and set(paths)==SOURCE_KEYS,'a5_proxy_source_paths')
    normalized={k:m.launcher.checked_path(Path(v)) for k,v in paths.items()}
    require(all(p.is_absolute() for p in normalized.values()) and len({str(p).casefold() for p in normalized.values()})==5,'a5_proxy_distinct_files')
    require(normalized['network_actor'].name==NETWORK_ACTOR and normalized['network_manifest'].name==NETWORK_MANIFEST
            and normalized['mihomo'].name=='mihomo.exe','a5_proxy_names')
    raw={}
    for role,path in normalized.items():
        limit=64*1024*1024 if role=='mihomo' else 8*1024*1024 if role=='network_actor' else 65536
        raw[role]=m.local.bounded(path,limit)
        expected=proxy['artifacts'][role] if role in FIXED else proxy['request_body'] if role=='request_body' else proxy['challenges']['response']
        require(len(raw[role])==expected['bytes'] and m.sha(raw[role])==expected['sha256'],'a5_proxy_input_bytes')
    m.proxy_protocol.verify_actor(normalized['network_actor'],normalized['network_manifest'],
        FIXED['network_actor']['sha256'],FIXED['network_manifest']['sha256'],root=root,network=True)
    m.proxy_protocol.verify_mihomo(normalized['mihomo'],FIXED['mihomo']['sha256'])
    request=m.proxy_protocol.build_challenge(raw['request_body'],response=False,case=case,origin_port=proxy['ports']['origin_port'])
    require(dict(bytes=len(request),sha256=m.sha(request))==proxy['challenges']['request'],'a5_request_envelope')
    require(m.proxy_protocol.http_challenge(raw['response'],response=True,case=case,origin_port=proxy['ports']['origin_port'])==proxy['challenges']['response'],'a5_response_envelope')
    raw['request']=request;raw['configuration']=configuration;return raw

def stage(m,root,large_bundle,raw,proxy):
    root=Path(root);large_bundle=Path(large_bundle)
    require=m.require
    require(set(raw)==SOURCE_KEYS|{'request','configuration'},'a5_staging_buffer_set')
    for name in DIRS:(root/name).mkdir()
    for name in TEMPS:(root/name/'temp').mkdir()
    rows={root/'inputs'/NETWORK_ACTOR:('network_actor',FIXED['network_actor']),
          root/'inputs'/NETWORK_MANIFEST:('network_manifest',FIXED['network_manifest']),
          large_bundle/'mihomo.exe':('mihomo',FIXED['mihomo']),
          root/'package/request-body.bin':('request_body',proxy['request_body']),
          root/'ordinary-inputs/response.bin':('response',proxy['challenges']['response']),
          root/'expected/request-http.bin':('request',proxy['challenges']['request']),
          root/'core-home/config.json':('configuration',dict(bytes=len(raw['configuration']),sha256=proxy['mihomo_config_sha256']))}
    for path,(key,expected) in rows.items():
        payload=raw[key]
        require(len(payload)==expected['bytes'] and m.sha(payload)==expected['sha256'],'a5_staging_input_changed')
        m.launcher.write_private_bytes(path,payload)
        limit=64*1024*1024 if key=='mihomo' else 8*1024*1024 if key=='network_actor' else 65536
        saved=m.local.bounded(m.launcher.checked_path(path,inside=large_bundle if key=='mihomo' else root),limit)
        require(len(saved)==expected['bytes'] and m.sha(saved)==expected['sha256'],'a5_staging_readback')
