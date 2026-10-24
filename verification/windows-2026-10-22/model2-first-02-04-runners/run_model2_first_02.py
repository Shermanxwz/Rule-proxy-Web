from pathlib import Path
source=Path(__file__).with_name('run_model2_first_01.py').read_text(encoding='utf-8')
source=source.replace("head.startswith('3e8e015')","head.startswith('78cc041')")
source=source.replace('model2-first-recovery-plan-01','model2-first-recovery-plan-02')
source=source.replace('model2-first-01','model2-first-02')
exec(compile(source,str(__file__),'exec'))
