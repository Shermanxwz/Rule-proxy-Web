"""Repeat lifecycle contracts on the normally imported Manager, with native boundaries mocked."""
from contextlib import ExitStack
from pathlib import Path
import tempfile
from types import SimpleNamespace
from unittest.mock import Mock, patch

from ruleproxy import manager as manager_module
import test_manager_failure_retention as contracts


class ImportedManagerFailureRetentionTests(contracts.ManagerFailureRetentionTests):
    def setUp(self):
        imports = ExitStack()
        self.addCleanup(imports.close)
        imports.enter_context(patch.object(contracts, 'Manager', manager_module.Manager))
        imports.enter_context(patch.object(manager_module.sys, 'platform', 'win32'))
        imports.enter_context(patch.object(manager_module, 'stop_process'))
        imports.enter_context(patch.object(manager_module, 'close_resource'))
        imports.enter_context(patch.object(manager_module.traceback, 'print_exc'))
        super().setUp()

    # Replace the inherited structural-only check with executed startup failure.
    test_startup_exception_retention_call_structural_only = None

    def test_startup_policy_failure_executes_retained_stop(self):
        self.manager.quitting = False
        self.manager.closed = Mock()
        self.manager.closed.is_set.return_value = False
        self.manager.core = None
        self.manager.compiled = SimpleNamespace(text='fixture config')
        self.manager.source = 'fixture source'
        self.manager.mixed_port, self.manager.controller_port = 18809, 19097
        self.manager._recover_global = Mock()
        self.manager.protection = Mock(return_value={'supported': True})
        self.manager._compile = Mock(return_value=self.manager.compiled)
        self.manager.core_path = Mock(return_value=Path('fixture-core.exe'))
        self.manager._controller = Mock(return_value={'version': 'fixture'})
        self.manager._sync_windows_policy = Mock(side_effect=ValueError('injected startup policy failure'))
        with tempfile.TemporaryDirectory() as directory, \
                patch.object(manager_module.socket, 'socket'), \
                patch.object(manager_module, 'write_private'), \
                patch.object(manager_module.subprocess, 'run', return_value=SimpleNamespace(returncode=0)), \
                patch.object(manager_module.subprocess, 'Popen', return_value=contracts.Core()), \
                patch('ruleproxy.windows_core_process.CoreJob'):
            self.manager.directory = Path(directory)
            with self.assertRaisesRegex(ValueError, 'injected startup policy failure'):
                self.manager.start()
        self.assert_retained()
        self.assertIsNone(self.manager.core)
        self.assertIsNone(self.manager.core_log)
        self.manager._sync_windows_policy.assert_called_once()
        self.restore.assert_called_once()
