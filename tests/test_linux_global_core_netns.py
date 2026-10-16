"""Explicit opt-in actual pinned Mihomo + production privileged Lease test."""
import json
import os
from pathlib import Path
import subprocess
import sys
import unittest


@unittest.skipUnless(sys.platform=='linux' and os.environ.get('RULEPROXY_REQUIRE_GLOBAL_CORE_NETNS')=='1',
                     'requires explicit isolated-network CI with pinned Linux Mihomo and /dev/net/tun')
class GlobalCoreKernelTests(unittest.TestCase):
    def test_real_core_dual_stack_capture_fault_block_and_recovery(self):
        self.assertEqual(os.geteuid(),0,'This opted-in CI test must run as root')
        fixture=Path(__file__).parent/'fixtures/linux_global_core_netns.py'
        self.assertTrue((fixture.parents[2]/'bin/linux-amd64/mihomo').is_file(),'Run install_runtime.py --if-needed first')
        self.assertTrue(Path('/dev/net/tun').exists(),'CI must provide the TUN device')
        environment=dict(os.environ,RULEPROXY_PARENT_NETNS=str(os.stat('/proc/self/ns/net').st_ino))
        result=subprocess.run(['unshare','--net','--fork','--kill-child=KILL','--',sys.executable,str(fixture)],
                              env=environment,stdout=subprocess.PIPE,stderr=subprocess.PIPE,text=True,timeout=150)
        self.assertEqual(result.returncode,0,(result.stdout+'\n'+result.stderr)[-10000:])
        proof=json.loads(result.stdout.strip().splitlines()[-1]);self.assertEqual(proof['real_core_probe'],'passed')
        self.assertTrue(proof['tcp_udp_via_fixture_socks']);self.assertTrue(proof['core_crash_keeps_independent_guard'])
        self.assertFalse(proof['polkit_dialog_exercised'])
        print(json.dumps(proof,sort_keys=True),flush=True)


if __name__=='__main__':unittest.main()
