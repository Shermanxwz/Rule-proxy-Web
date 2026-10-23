"""Run only the three Python fake/codec suites; native compile suite is separate."""
import importlib.util
from pathlib import Path
import unittest
root=Path(__file__).resolve().parent/'psec-lpac-identity-bridge-candidate-02'
suite=unittest.TestSuite()
for name in ('test_windows_identity_psec_spec','test_windows_identity_psec_lpac_bridge','test_windows_identity_psec_lpac_bridge_local'):
 s=importlib.util.spec_from_file_location(name,root/'tests'/(name+'.py'));m=importlib.util.module_from_spec(s);s.loader.exec_module(m)
 suite.addTests(unittest.defaultTestLoader.loadTestsFromModule(m))
result=unittest.TextTestRunner(verbosity=2).run(suite)
raise SystemExit(0 if result.wasSuccessful() else 1)
