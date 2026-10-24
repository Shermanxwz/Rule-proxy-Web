from pathlib import Path
source=Path(__file__).with_name('run_model2_diagnostic_01.py').read_text(encoding='utf-8')
source=source.replace('import json\n','import json\nimport secrets\n')
source=source.replace('model2-diagnostic-recovery-plan-01','model2-wrong-peer-recovery-plan-02')
source=source.replace('model2-diagnostic-01','model2-wrong-peer-02')
source=source.replace('proxy-c-compile-03','proxy-c-compile-04')
source=source.replace('b5fda518d9b621ecf86899eff5aa2a1f33f1c313305542fcde26832ac0065be7',
    'ffa42e35f5107fd38dcae91e7e9b2c867136033f7a5832e613bf55d9a74584aa')
source=source.replace("mode='profiles-off-diagnostic'", "mode='profiles-off-diagnostic'\npeer_extension=dict(profile='wrong-peer-psec-control-v1',**{key:secrets.token_hex(16) for key in ('listener_boot','control_boot','control_admission','before_case','wrong_case','after_case')})")
source=source.replace('scope=m.DIAGNOSTIC_SCOPE,',
    'scope=m.WRONG_PEER_SCOPE,selected_admission=m.live.system_conhost_record(api),wrong_peer_extension=peer_extension,')
source=source.replace('execution_mode=mode)', 'execution_mode=mode,allow_held_system_conhost=True,test_wrong_peer=True)')
exec(compile(source,str(__file__),'exec'))
