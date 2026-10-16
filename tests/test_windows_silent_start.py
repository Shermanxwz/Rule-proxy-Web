"""Installed Windows panel/core launchers keep their own UI in the background."""
import base64
from contextlib import redirect_stderr
import io
from pathlib import Path
import socket
import subprocess
import sys
import tempfile
from types import SimpleNamespace
import unittest
from unittest.mock import Mock, patch

from ruleproxy import autostart, manager as manager_module, server, shortcut_launcher, shortcuts


def free_port():
    with socket.socket() as listener:
        listener.bind(('127.0.0.1', 0))
        return listener.getsockname()[1]


class SilentWindowsStartTests(unittest.TestCase):
    def test_windows_default_leaves_browser_closed(self):
        with patch.object(sys, 'platform', 'win32'), patch.object(sys, 'argv', ['Run-RuleProxy.py']), \
                patch.object(server, '_run') as run, patch.object(server.webbrowser, 'open') as browser:
            server.main()
        self.assertTrue(run.call_args.args[0].no_browser)
        browser.assert_not_called()

    def test_linux_browser_default_is_preserved(self):
        with patch.object(sys, 'platform', 'linux'), patch.object(sys, 'argv', ['Run-RuleProxy.py']), \
                patch.object(server, '_run') as run:
            server.main()
        self.assertFalse(run.call_args.args[0].no_browser)

    def test_silent_start_failure_is_written_to_log_without_desktop_notification(self):
        with tempfile.TemporaryDirectory() as directory:
            state = Path(directory) / 'state'
            argv = ['Run-RuleProxy.py', '--state-dir', str(state)]
            with patch.object(sys, 'platform', 'win32'), patch.object(sys, 'argv', argv), \
                    patch.object(sys, 'stdout', None), patch.object(sys, 'stderr', None), \
                    patch.object(server, '_run', side_effect=SystemExit('RuleProxy: startup failed')), \
                    patch.object(shortcut_launcher, '_notify') as notify:
                try:
                    with self.assertRaises(SystemExit):
                        server.main()
                    self.assertIsNotNone(sys.stderr)
                finally:
                    if sys.stderr is not None:
                        sys.stderr.close()
            notify.assert_not_called()
            self.assertIn('RuleProxy: startup failed', (state / 'panel.log').read_text(encoding='utf-8'))

    def test_elevated_windows_panel_is_refused_before_binding_or_spawning(self):
        api = Mock(assert_unelevated=Mock())
        api.assert_unelevated.side_effect = PermissionError('elevated token')
        with patch.object(sys, 'platform', 'win32'), patch.object(sys, 'argv', ['Run-RuleProxy.py']), \
                patch('ruleproxy.windows_app_process._get_api', return_value=api), \
                patch.object(server, 'PanelServer') as listener, \
                patch.object(server, 'Manager') as manager, \
                patch.object(server.webbrowser, 'open') as browser:
            with self.assertRaisesRegex(SystemExit, '桌面普通用户'):
                server.main()
        listener.assert_not_called()
        manager.assert_not_called()
        browser.assert_not_called()

    def test_windows_app_shortcut_error_logs_without_any_notification_program(self):
        messages = io.StringIO()
        with patch.object(sys, 'platform', 'win32'), redirect_stderr(messages), \
                patch.object(shortcut_launcher.shutil, 'which') as desktop_program, \
                patch.object(shortcut_launcher.subprocess, 'run') as child:
            self.assertEqual(shortcut_launcher._report('application is unavailable'), 1)
        self.assertIn('application is unavailable', messages.getvalue())
        desktop_program.assert_not_called()
        child.assert_not_called()

    def test_panel_link_targets_final_root_and_never_saves_installer_state(self):
        with tempfile.TemporaryDirectory() as directory:
            stage = Path(directory) / 'staging tree'
            final = Path(directory) / '安装 root'
            destination = stage / 'Start-Windows.lnk'
            encoded = base64.b64encode(str(destination).encode('utf-8')).decode('ascii') + '\n'
            with patch.object(sys, 'platform', 'win32'), \
                    patch.object(shortcuts.subprocess, 'run', return_value=Mock(
                        returncode=0, stdout=encoded, stderr='')) as create:
                self.assertEqual(shortcuts.create_panel_shortcut(destination, final), destination)
            environment = create.call_args.kwargs['env']
            self.assertEqual(environment['RULEPROXY_SHORTCUT_TARGET'], str(final / 'python/pythonw.exe'))
            self.assertEqual(environment['RULEPROXY_SHORTCUT_ARGUMENTS'], subprocess.list2cmdline(
                ['-I', '-S', str(final / 'Run-RuleProxy.py'), '--no-browser']))
            self.assertEqual(environment['RULEPROXY_SHORTCUT_WORKDIR'], str(final))
            self.assertEqual(environment['RULEPROXY_SHORTCUT_FOLDERS'], str(stage))
            self.assertNotIn('--state-dir', environment['RULEPROXY_SHORTCUT_ARGUMENTS'])
            self.assertFalse(final.exists(), 'first install may not have its final tree yet')

    def test_shortcut_cli_only_creates_link_and_does_not_start_panel(self):
        argv = ['Run-RuleProxy.py', '--create-panel-shortcut', 'staging/Start-Windows.lnk',
                '--shortcut-root', 'installed']
        with patch.object(sys, 'argv', argv), patch.object(shortcuts, 'create_panel_shortcut') as create, \
                patch.object(server, '_run') as panel, patch.object(server.webbrowser, 'open') as browser:
            server.main()
        create.assert_called_once_with(Path('staging/Start-Windows.lnk'), Path('installed'))
        panel.assert_not_called()
        browser.assert_not_called()

    def test_login_and_saved_app_shortcut_use_pythonw_directly(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            python = root / 'python.exe'
            windowless = root / 'pythonw.exe'
            python.touch()
            windowless.touch()
            with patch.object(sys, 'platform', 'win32'), patch.object(sys, 'executable', str(python)):
                login = autostart.command(root / 'state', (8879, 10809, 19097))
                app = shortcuts.runner_argv('saved-app', root / 'state', (8879, 10809, 19097))
            self.assertEqual(login[0], str(windowless))
            self.assertEqual(app[0], str(windowless))
            self.assertIn('--no-browser', login)
            self.assertIn('--launch-app', app)

    def test_core_validation_and_running_core_both_disable_console_creation(self):
        with tempfile.TemporaryDirectory() as directory:
            manager = manager_module.Manager(Path(directory), free_port(),
                mixed_port=free_port(), controller_port=free_port())
            manager.compiled = SimpleNamespace(text='fixed config')
            process = Mock(pid=1234, poll=Mock(return_value=None))
            try:
                with patch.object(manager_module, 'os', SimpleNamespace(name='nt')), \
                        patch.object(sys, 'platform', 'win32'), \
                        patch.object(manager, 'protection', return_value={'supported': True}), \
                        patch.object(manager, '_compile', return_value=manager.compiled), \
                        patch.object(manager, 'core_path', return_value=Path(directory) / 'mihomo.exe'), \
                        patch.object(manager_module, 'write_private'), \
                        patch.object(manager_module.subprocess, 'run', return_value=Mock(returncode=0)) as validate, \
                        patch.object(manager_module.subprocess, 'Popen', return_value=process) as launch, \
                        patch.object(manager, '_controller', return_value={}), \
                        patch.object(manager, '_sync_windows_policy'), \
                        patch('ruleproxy.windows_core_process.CoreJob') as job:
                    manager.start()
                hidden = getattr(subprocess, 'CREATE_NO_WINDOW', 0x08000000)
                group = getattr(subprocess, 'CREATE_NEW_PROCESS_GROUP', 0x00000200)
                self.assertEqual(validate.call_args.kwargs['creationflags'], hidden)
                self.assertEqual(launch.call_args.kwargs['creationflags'], hidden | group)
                self.assertIs(validate.call_args.kwargs['stdout'], manager.core_log)
                self.assertIs(launch.call_args.kwargs['stdout'], manager.core_log)
                self.assertIs(launch.call_args.kwargs['stdin'], subprocess.DEVNULL)
                job.assert_called_once_with(process)
            finally:
                manager.core = None
                manager.close()


if __name__ == '__main__':
    unittest.main()
