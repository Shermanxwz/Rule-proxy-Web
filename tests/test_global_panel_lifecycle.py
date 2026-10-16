"""Real panel/shortcut cleanup with real harmless child processes.

The privileged backend/guard is represented by an in-memory lease; no proxy
core, root helper, route, TUN, or firewall is started by these tests.
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


class BackendLease:
    def __init__(self):
        self.core=None;self.guard=False;self.stop_calls=0;self.fail_start=False

    def status(self):
        running=bool(self.core and self.core.poll() is None)
        return {'supported':True,'running':running,'pid':self.core.pid if running else None,
                'state':'running' if running else 'blocked' if self.guard else 'idle',
                'protection_active':self.guard,'strict_isolation':self.guard,'limitations':[]}

    def start(self,*_args,**_kwargs):
        self.guard=True
        if self.fail_start:raise ValueError('synthetic startup failure after guard installation')
        self.core=subprocess.Popen([sys.executable,'-I','-S','-c','import time; time.sleep(60)'],
                                   stdout=subprocess.DEVNULL,stderr=subprocess.DEVNULL)
        return self.status()

    def stop(self):
        self.stop_calls+=1;self.cleanup();self.guard=False
        return self.status()

    def cleanup(self):
        if self.core and self.core.poll() is None:
            self.core.terminate()
            try:self.core.wait(timeout=3)
            except subprocess.TimeoutExpired:self.core.kill();self.core.wait(timeout=3)


@unittest.skipUnless(sys.platform=='linux','Real Linux panel/ordinary-child lifecycle')
class GlobalPanelLifecycleTests(unittest.TestCase):
    def setUp(self):
        self.temporary=tempfile.TemporaryDirectory();self.addCleanup(self.temporary.cleanup)
        self.state=Path(self.temporary.name)/'state';self.state.mkdir()
        self.backend=BackendLease();self.addCleanup(self.backend.cleanup)
        self.managers=[]
        for item in (patch.object(Manager,'global_backend',return_value=self.backend),
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

    def test_removed_shortcut_does_not_release_an_existing_fault_guard(self):
        self.backend.guard=True
        panel,port=self.bound_server()
        with patch('ruleproxy.manager.Manager',side_effect=self.manager),patch.object(shortcut_launcher,'_stop_on_signal'):
            with self.assertRaisesRegex(shortcut_launcher.LaunchError,'不在面板'):
                shortcut_launcher._host_panel(panel,'removed',self.state,port,10809,19097)
        self.assertTrue(self.backend.guard);self.assertEqual(self.backend.stop_calls,0)
        self.assertTrue(self.managers[0].closed.is_set())

    def test_successful_global_start_then_missing_app_preserves_core_lease(self):
        missing=Path(self.temporary.name)/'removed-program'
        self.save([{'id':'app','label':'Removed','path':str(missing),'adapter':'environment','args':[],'enabled':True}])
        panel,port=self.bound_server()
        with patch('ruleproxy.manager.Manager',side_effect=self.manager),patch.object(shortcut_launcher,'_stop_on_signal'):
            with self.assertRaisesRegex(ValueError,'找不到这个程序'):
                shortcut_launcher._host_panel(panel,'app',self.state,port,10809,19097)
        self.assertTrue(self.backend.guard);self.assertEqual(self.backend.stop_calls,0)
        self.assertIsNone(self.backend.core.poll(),'exception cleanup must not ask the helper to restore networking')

    def test_explicit_http_quit_stops_owned_app_and_restores_the_global_lease(self):
        self.save([{'id':'app','label':'Harmless child','path':sys.executable,'adapter':'environment',
                    'args':['-I','-S','-c','import time; time.sleep(60)'],'enabled':True}])
        panel,port=self.bound_server();outcome={}
        def host():
            try:shortcut_launcher._host_panel(panel,'app',self.state,port,10809,19097)
            except BaseException as error:outcome['error']=error
        with patch('ruleproxy.manager.Manager',side_effect=self.manager),patch.object(shortcut_launcher,'_stop_on_signal'):
            worker=threading.Thread(target=host,daemon=True);worker.start()
            deadline=time.monotonic()+10
            while time.monotonic()<deadline:
                if self.managers:
                    with self.managers[0].lock:
                        if self.managers[0].active:break
                if outcome:break
                time.sleep(.02)
            self.assertFalse(outcome,outcome)
            manager=self.managers[0]
            with manager.lock:application=manager.active['app'][0]
            request=urllib.request.Request(f'http://127.0.0.1:{port}/api/quit',data=b'{}',method='POST',
                headers={'Content-Type':'application/json','X-RuleProxy-Token':manager.token})
            opener=urllib.request.build_opener(urllib.request.ProxyHandler({}))
            with opener.open(request,timeout=5) as response:self.assertEqual(response.status,200)
            worker.join(10);self.assertFalse(worker.is_alive());self.assertFalse(outcome,outcome)
        self.assertFalse(self.backend.guard);self.assertEqual(self.backend.stop_calls,1)
        self.assertIsNotNone(self.backend.core.poll());self.assertIsNotNone(application.poll())

    def test_server_failed_start_finally_does_not_restore_a_new_guard(self):
        self.backend.fail_start=True
        panel,port=self.bound_server()
        args=argparse.Namespace(launch_app=None,port=port,state_dir=self.state,proxy_port=10809,
                                controller_port=19097,start_core=True,no_browser=True)
        with patch.object(server,'_refuse_root'),patch.object(server,'PanelServer',return_value=panel),\
             patch.object(server.signal,'signal'),redirect_stdout(io.StringIO()):
            with self.assertRaisesRegex(SystemExit,'synthetic startup failure'):
                server._run(args,False)
        self.assertTrue(self.backend.guard);self.assertEqual(self.backend.stop_calls,0)

    def test_ctrl_c_is_explicit_restore_but_sigterm_retains_the_guard(self):
        for number,restored in ((signal.SIGINT,True),(signal.SIGTERM,False)):
            with self.subTest(signal=number):
                self.backend.cleanup();self.backend.guard=False;self.backend.stop_calls=0
                panel=Mock();panel.quit_requested=threading.Event();handlers={}
                def install(signum,handler):handlers[signum]=handler
                panel.serve_forever.side_effect=lambda **_:handlers[number](number,None)
                args=argparse.Namespace(launch_app=None,port=18879,state_dir=self.state,proxy_port=10809,
                                        controller_port=19097,start_core=True,no_browser=True)
                with patch.object(server,'_refuse_root'),patch.object(server,'panel_state',return_value=None),\
                     patch.object(server,'PanelServer',return_value=panel),\
                     patch.object(server.signal,'signal',side_effect=install),redirect_stdout(io.StringIO()):
                    server._run(args,False)
                self.assertEqual(self.backend.stop_calls,1 if restored else 0)
                self.assertEqual(self.backend.guard,not restored)

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
