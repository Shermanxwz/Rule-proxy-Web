"""Keep the panel-owned Mihomo in a kill-on-close Job as well as its apps."""
from __future__ import annotations

import threading

from .windows_app_process import _get_api


class CoreJob:
    def __init__(self, process):
        self._api = _get_api()
        self._api.is_elevated()
        self._lock = threading.Lock()
        self._job = None
        job = self._api.create_job()
        try:
            self._api.configure_job(job, 0x2000)  # JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE
            self._api.assign_job(job, int(process._handle))
            self._job = job
        except BaseException:
            self._api.close_handle(job)
            raise

    def close(self):
        with self._lock:
            job, self._job = self._job, None
            if job is not None:
                self._api.close_handle(job)

    def __del__(self):
        if getattr(self, "_job", None) is not None:
            try:
                self.close()
            except OSError:
                pass
