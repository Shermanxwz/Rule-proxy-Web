"""Real panel/shortcut cleanup with real harmless child processes.

Global mode only changes the desktop system proxy, which is patched here.
"""
import argparse
from contextlib import redirect_stdout
import io
import json
import os
from pathlib import Path
import signal
import subprocess
import sys
import tempfile
import threading
import time
import unittest
import urllib.request
from unittest.mock import Mock,patch

from ruleproxy.manager import Manager
from ruleproxy import server,shortcut_launcher


SOURCE='proxies:\n- name: Node\n  type: socks5\n  server: proxy.example.test\n  port: 1080\n'


@unittest.skipUnless(sys.platform=='linux','Real Linux panel/ordinary-child lifecycle')
class GlobalPanelLifecycleTests(unittest.TestCase):
    def setUp(self):
        self.temporary=tempfile.TemporaryDirectory();self.addCleanup(self.temporary.cleanup)
        self.state=Path(self.temporary.name)/'state';self.state.mkdir()
        self.managers=[]
        legacy=Mock();legacy.status.return_value={'supported':False,'running':False}
        for item in (patch.object(Manager,'global_backend',return_value=legacy),
                     patch.object(Manager,'available_apps',return_value=([],False)),
                     patch.object(Manager,'autostart_status',return_value='off'),
                     patch.object(Manager,'files_dir',return_value=None)):
            item.start();self.addCleanup(item.stop)
        self.save([])

    def save(self,apps):
        (self.state/'settings.json').write_text(json.dumps({'capture_mode':'global','apps':apps}),encoding='utf-8')
        (self.state/'source.yaml').write_text(SOURCE,encoding='utf-8')

    def manager(self,directory,port,**options):
        value=Manager(directory,port,**options);self.managers.append(value)
        return value

    def bound_server(self):
        value=server.PanelServer(0);self.addCleanup(value.server_close)
        return value,value.server_address[1]

    def test_global_close_always_restores_the_system_proxy(self):
        manager=self.manager(self.state,18879)
        with patch('ruleproxy.system_proxy.restore') as restore:
            manager.close(restore_global=False)
        restore.assert_called_once_with(self.state)

    def test_application_mode_close_keeps_original_stop_behavior(self):
        (self.state/'settings.json').write_text('{"capture_mode":"applications","apps":[]}',encoding='utf-8')
        manager=self.manager(self.state,18879)
        process=subprocess.Popen([sys.executable,'-I','-S','-c','import time; time.sleep(60)'],start_new_session=True)
        try:
            manager.core=process;manager.close()
            self.assertIsNotNone(process.poll());self.assertIsNone(manager.core)
        finally:
            if process.poll() is None:process.kill();process.wait(timeout=3)


if __name__=='__main__':unittest.main()
