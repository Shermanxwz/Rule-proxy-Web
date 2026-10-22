from pathlib import Path
source=Path(__file__).with_name('run_model2_diagnostic_01.py').read_text(encoding='utf-8')
source=source.replace('model2-diagnostic-recovery-plan-01','model2-diagnostic-recovery-plan-02')
source=source.replace('model2-diagnostic-01','model2-diagnostic-02')
exec(compile(source,str(__file__),'exec'))
