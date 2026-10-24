from pathlib import Path
import subprocess
source=Path(__file__).with_name('run_model2_first_01.py').read_text(encoding='utf-8')
head=subprocess.check_output(['git','rev-parse','HEAD'],cwd=Path(__file__).parent/'Rule-proxy-Web',text=True).strip()
source=source.replace("head.startswith('3e8e015')",'head=='+repr(head))
source=source.replace('model2-first-recovery-plan-01','model2-first-recovery-plan-03')
source=source.replace('model2-first-01','model2-first-03')
exec(compile(source,str(__file__),'exec'))
