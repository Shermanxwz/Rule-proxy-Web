from pathlib import Path
source=Path(__file__).with_name('run_model2_diagnostic_08.py').read_text(encoding='utf-8')
source=source.replace('model2-diagnostic-recovery-plan-08','model2-diagnostic-recovery-plan-09')
source=source.replace('model2-diagnostic-08','model2-diagnostic-09')
exec(compile(source,str(__file__),'exec'))
