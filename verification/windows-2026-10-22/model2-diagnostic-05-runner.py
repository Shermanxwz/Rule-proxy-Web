from pathlib import Path
source=Path(__file__).with_name('run_model2_diagnostic_04.py').read_text(encoding='utf-8')
source=source.replace('model2-diagnostic-recovery-plan-04','model2-diagnostic-recovery-plan-05')
source=source.replace('model2-diagnostic-04','model2-diagnostic-05')
exec(compile(source,str(__file__),'exec'))
