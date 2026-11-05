"""Bounded, cancellable startup task; never owns permission or app termination."""
import threading
import time

from .windows_antigravity_peers import NativePeers
from .windows_antigravity_recovery import recover_once


class RecoveryTask:
    def __init__(self, process, path, check, *, peers_factory=NativePeers,
                 recover=recover_once, clock=time.monotonic):
        self.process, self.path, self.check = process, path, check
        self.peers_factory, self.recover, self.clock = peers_factory, recover, clock
        self.deadline = clock() + 20.
        self.cancelled = threading.Event()
        self.result = {'state': 'waiting', 'reload_attempted': False}
        self.thread = threading.Thread(target=self._run, name='antigravity-startup', daemon=True)

    def start(self):
        self.thread.start()

    def cancel(self):
        self.cancelled.set()

    def _ready(self):
        if self.cancelled.is_set() or self.clock() >= self.deadline:
            return False
        result = self.check()
        return False if self.cancelled.is_set() or self.clock() >= self.deadline else result

    def _run(self):
        try:
            if self._ready() is False:
                self.result = {'state': 'cancelled', 'reload_attempted': False}
                return
            with self.peers_factory(self.process, self.path) as peers:
                self.result = self.recover(peers, self._ready, self.deadline,
                                           clock=self.clock, sleep=self.cancelled.wait)
        except Exception:
            # A peer cleanup failure must not erase a reload already attempted.
            attempted = self.result.get('reload_attempted') is True
            self.result = {'state': 'reload_unverified' if attempted else 'unavailable',
                           'reload_attempted': attempted}
