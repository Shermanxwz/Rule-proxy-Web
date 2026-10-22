from pathlib import Path
source=Path(__file__).with_name('run_model2_wrong_port_01.py').read_text(encoding='utf-8')
source=source.replace('model2-wrong-port-recovery-plan-01','model2-wrong-port-recovery-plan-02')
source=source.replace('model2-wrong-port-01','model2-wrong-port-02')
source=source.replace('same-peer-wrong-port-v1','same-peer-wrong-port-psec-control-v1')
source=source.replace('scope=m.WRONG_PORT_SCOPE,','scope=m.WRONG_PORT_PSEC_SCOPE,')
exec(compile(source,str(__file__),'exec'))
