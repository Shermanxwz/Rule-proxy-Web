"""Explicitly opt-in real kernel test; all networking is in disposable netns."""
import json
import os
from pathlib import Path
import subprocess
import sys
import unittest


@unittest.skipUnless(sys.platform=='linux' and os.environ.get('RULEPROXY_REQUIRE_GLOBAL_NETNS')=='1',
                     'requires explicit root/CAP_SYS_ADMIN isolated-network CI job')
class GlobalGuardKernelTests(unittest.TestCase):
    def test_independent_guard_dual_stack_failure_and_recovery(self):
        self.assertEqual(os.geteuid(),0,'This opted-in CI test must run as root')
        fixture=Path(__file__).parent/'fixtures/linux_global_guard_netns.py'
        environment=dict(os.environ,RULEPROXY_PARENT_NETNS=str(os.stat('/proc/self/ns/net').st_ino))
        result=subprocess.run(['unshare','--net','--fork','--kill-child=KILL','--',sys.executable,str(fixture)],
                              env=environment,stdout=subprocess.PIPE,stderr=subprocess.PIPE,
                              text=True,timeout=120)
        self.assertEqual(result.returncode,0,(result.stdout+'\n'+result.stderr)[-8000:])
        proof=json.loads(result.stdout.strip().splitlines()[-1])
        self.assertEqual(proof['guard_probe'],'passed')
        self.assertTrue(proof['tun_disappearance_keeps_block'])
        self.assertTrue(proof['unrelated_table_preserved'])
        print(json.dumps(proof,sort_keys=True),flush=True)


if __name__=='__main__':unittest.main()
