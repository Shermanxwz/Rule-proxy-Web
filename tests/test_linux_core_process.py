"""Real harmless Linux descendants; no core downloads or networking."""
import os
from pathlib import Path
import select
import signal
import subprocess
import sys
import time
import unittest

from ruleproxy import linux_core_process


@unittest.skipUnless(sys.platform == 'linux' and hasattr(os, 'pidfd_open'), 'Linux parent-death signal and pidfds')
class LinuxCoreProcessTests(unittest.TestCase):
    def test_request_thread_exit_does_not_kill_core_but_panel_death_does(self):
        root = str(Path(__file__).resolve().parent.parent)
        code = '''
import subprocess, sys, threading, time
from concurrent.futures import ThreadPoolExecutor
sys.path.insert(0, ROOT)
from ruleproxy.linux_core_process import command_for_parent
owner=ThreadPoolExecutor(max_workers=1)
def request():
    command=command_for_parent([sys.executable,'-c','import time; time.sleep(60)'])
    child=owner.submit(subprocess.Popen,command,stdin=subprocess.DEVNULL,
                       stdout=subprocess.DEVNULL,stderr=subprocess.DEVNULL).result()
    print(child.pid,flush=True)
thread=threading.Thread(target=request);thread.start();thread.join()
time.sleep(60)
'''.replace('ROOT', repr(root))
        parent = subprocess.Popen([sys.executable, '-B', '-c', code], stdout=subprocess.PIPE,
                                  stderr=subprocess.PIPE, text=True)
        descriptor = None
        try:
            self.assertTrue(select.select([parent.stdout], [], [], 5)[0], 'Owner did not launch child')
            child_pid = int(parent.stdout.readline().strip())
            descriptor = os.pidfd_open(child_pid)
            # The HTTP-like request thread has exited, but the stable creation
            # thread remains. A direct request-thread launch would die here.
            self.assertFalse(select.select([descriptor], [], [], 0.3)[0])
            parent.kill()
            parent.wait(3)
            self.assertTrue(select.select([descriptor], [], [], 3)[0], 'Owned core survived panel SIGKILL')
        finally:
            if parent.poll() is None:
                parent.kill()
                parent.wait(3)
            if descriptor is not None:
                if not select.select([descriptor], [], [], 0)[0]:
                    signal.pidfd_send_signal(descriptor, signal.SIGKILL)
                os.close(descriptor)
            parent.stdout.close()
            parent.stderr.close()

    def test_already_lost_parent_refuses_to_exec_payload(self):
        command = [sys.executable, '-B', str(Path(linux_core_process.__file__)), str(os.getpid() + 1),
                   sys.executable, '-c', 'raise SystemExit(99)']
        result = subprocess.run(command, capture_output=True, text=True, timeout=5)
        self.assertEqual(result.returncode, 1, result.stderr)


if __name__ == '__main__':
    unittest.main()
