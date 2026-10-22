"""One original-deadline in-flight relay death diagnostic; never strict acceptance."""
from pathlib import Path
source=Path(__file__).with_name('run_model2_diagnostic_01.py').read_text(encoding='utf-8')
source=source.replace('import json\n','import json\nimport secrets\n')
source=source.replace('model2-diagnostic-recovery-plan-01','model2-death-recovery-plan-01')
source=source.replace('model2-diagnostic-01','model2-death-01')
source=source.replace('proxy-c-compile-03','proxy-c-compile-05')
source=source.replace('b5fda518d9b621ecf86899eff5aa2a1f33f1c313305542fcde26832ac0065be7',
    'e50a8186378437638ea13efc20ab6b4f6331594f4d47a4199e04ba4f624a6cf7')
source=source.replace("mode='profiles-off-diagnostic'", "mode='profiles-off-diagnostic'\ndeath_extension=dict(profile='same-selected-live-proxy-death-v1',death_case=secrets.token_hex(16),after_direct_case=secrets.token_hex(16))")
source=source.replace('scope=m.DIAGNOSTIC_SCOPE,',
    'scope=m.DEATH_SCOPE,selected_admission=m.live.system_conhost_record(api),death_extension=death_extension,')
source=source.replace('execution_mode=mode)', 'execution_mode=mode,allow_held_system_conhost=True,test_proxy_death=True)')
reference=('Owner-authorized in-flight relay death diagnostic. Hold original selected, PNCS A/P and ordinary O. '
    'After exact O GET/EOF/zero-response ACK and held-generation/Job/TCP tuple proof, persist stop intent and '
    'terminate only the owned relay. Verify frontend/client failure, release O and repeat fresh direct with '
    'ordinary health controls. Preserve original deadline, profiles-off freshness, exact rule/ACL/profile cleanup. '
    'No global network changes; strict and product qualification stay false.')
assert len(reference)<=512
source='\n'.join(('    recovery_reference='+repr(reference)+')') if line.lstrip().startswith('recovery_reference=') else line for line in source.split('\n'))
exec(compile(source,str(__file__),'exec'))
