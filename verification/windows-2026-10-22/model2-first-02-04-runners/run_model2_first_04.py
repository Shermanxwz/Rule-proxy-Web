from pathlib import Path
source=Path(__file__).with_name('run_model2_first_01.py').read_text(encoding='utf-8')
source=source.replace("head.startswith('3e8e015')","head.startswith('bc0e476')")
source=source.replace('model2-first-recovery-plan-01','model2-first-recovery-plan-04')
source=source.replace('model2-first-01','model2-first-04')
exec(compile(source,str(__file__),'exec'))
