"""Unprivileged view of a core owned by the platform's global-network helper.

This object deliberately has no terminate/kill methods: a lost core must not
implicitly release the helper's independent network guard.
"""
from __future__ import annotations

import threading
import time


class ManagedGlobalCore:
    def __init__(self, runtime, status: dict):
        pid = status.get('pid')
        if type(pid) is not int or pid <= 0 or status.get('running') is not True:
            raise ValueError('全局权限组件未返回有效的核心进程。')
        self.pid = pid
        self.runtime = runtime
        self.last_status = dict(status)
        self._checked = time.monotonic()
        self._lock = threading.Lock()

    def poll(self):
        with self._lock:
            if time.monotonic() - self._checked >= 0.5:
                try:
                    status = self.runtime.status()
                    if not isinstance(status, dict):
                        raise ValueError('Invalid global status')
                    self.last_status = status
                except Exception:
                    self.last_status = {'running': False, 'state': 'unreachable'}
                self._checked = time.monotonic()
            return (None if self.last_status.get('running') is True
                    and self.last_status.get('pid') == self.pid else 1)
