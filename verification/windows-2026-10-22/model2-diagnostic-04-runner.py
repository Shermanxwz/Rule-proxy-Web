from pathlib import Path
source=Path(__file__).with_name('run_model2_diagnostic_01.py').read_text(encoding='utf-8')
source=source.replace('model2-diagnostic-recovery-plan-01','model2-diagnostic-recovery-plan-04')
source=source.replace('model2-diagnostic-01','model2-diagnostic-04')
source=source.replace('proxy-c-compile-03','proxy-c-compile-04')
source=source.replace('b5fda518d9b621ecf86899eff5aa2a1f33f1c313305542fcde26832ac0065be7',
    'ffa42e35f5107fd38dcae91e7e9b2c867136033f7a5832e613bf55d9a74584aa')
exec(compile(source,str(__file__),'exec'))
