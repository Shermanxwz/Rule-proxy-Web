"""Inactive, Linux-only owned FIFO capture primitive. No packet-isolation verdict.

Callers register the object before start(), and pass immutable absolute deadlines.
Only closed facts leave this module; capture bytes stay in the private owned root.
Waits use absolute deadlines; OS operations such as fsync are not hard-time-bounded.
The existing outer job/process containment remains the ultimate time bound.
"""
from pathlib import Path
import os
import re
import selectors
import signal
import stat
import struct
import subprocess
import threading
import time

CAPTURE_LIMIT = 64 * 1024 * 1024
SNAPLEN = 262144
CHUNK = 65536
ERRORS = frozenset(('creation','spawn','read','write','header','record','early_eof',
                    'overflow','stderr_capture','stderr_unknown','stderr_bound',
                    'deadline','terminate','kill','process_wait','thread','flush','close'))


class PcapStructure:
    """Constant-space classic-PCAP framing check, not a network decoder."""
    def __init__(self):
        self.pending = bytearray()
        self.header = False
        self.remaining = 0
        self.records = 0
        self.error = None
        self.endian = '<'

    def feed(self, data):
        view = memoryview(data)
        while view and self.error is None:
            if self.remaining:
                count = min(self.remaining, len(view))
                self.remaining -= count
                view = view[count:]
                continue
            need = (16 if self.header else 24) - len(self.pending)
            count = min(need, len(view))
            self.pending.extend(view[:count]); view = view[count:]
            if count < need:
                break
            if not self.header:
                magic = bytes(self.pending[:4])
                if magic not in (b'\xd4\xc3\xb2\xa1', b'\xa1\xb2\xc3\xd4'):
                    self.error = 'header'; break
                self.endian = '<' if magic[0] == 0xd4 else '>'
                _, major, minor, zone, precision, snaplen, link = struct.unpack(self.endian+'IHHiIII', self.pending)
                if (major, minor, zone, precision, snaplen, link) != (2, 4, 0, 0, SNAPLEN, 1):
                    self.error = 'header'; break
                self.header = True
            else:
                seconds, micros, included, original = struct.unpack(self.endian+'IIII', self.pending)
                if micros >= 1000000 or included == 0 or included > SNAPLEN or included != original:
                    self.error = 'record'; break
                self.remaining = included
                self.records = min(0xffffffff, self.records + 1)
            self.pending.clear()

    def complete(self):
        return self.header and self.error is None and not self.pending and self.remaining == 0


class CaptureSink:
    def __init__(self, owned_directory, *, deadline):
        if type(deadline) not in (int, float) or not time.monotonic() < deadline < float('inf'):
            raise ValueError('capture deadline')
        self.root = Path(owned_directory)
        self.fifo_path = self.root / 'capture.fifo'
        self.output_path = self.root / 'capture.pcap'
        self.deadline = deadline
        self.limit = CAPTURE_LIMIT
        self.fixture = False
        self.process = None
        self.spawn_attempted = False
        self.started = False
        self.reader = self.stderr_reader = None
        self.read_fd = self.dummy_fd = self.output_fd = None
        self.stderr_fd = None
        self.fifo_identity = self.output_identity = self.root_identity = None
        self.stop = threading.Event()
        self.ready = threading.Event()
        self.header_ready = threading.Event()
        self.overflow_event = threading.Event()
        self.failure_event = threading.Event()
        self.fifo_eof = self.stderr_eof = False
        self.shutdown_requested = False
        self.producer_live_at_shutdown = False
        self.errors = set()
        self.lock = threading.Lock()
        self.structure = PcapStructure()
        self.retained_bytes = self.drained_bytes = self.stderr_bytes = 0
        self.forced_kill = False
        self.output_flushed = False
        self.final = None

    @classmethod
    def for_test(cls, owned_directory, *, deadline, byte_limit):
        if type(byte_limit) is not int or not 24 <= byte_limit <= CAPTURE_LIMIT:
            raise ValueError('fixture bound')
        result = cls(owned_directory, deadline=deadline)
        result.limit = byte_limit; result.fixture = True
        return result

    def fail(self, reason):
        with self.lock:
            self.errors.add(reason if reason in ERRORS else 'read')
        self.failure_event.set()

    def _close(self, name):
        fd = getattr(self, name)
        if fd is None:
            return True
        try:
            os.close(fd)
        except OSError:
            self.fail('close'); return False
        setattr(self, name, None)
        return True

    def start(self):
        if self.started:
            raise ValueError('capture already started')
        self.started = True
        try:
            info = self.root.lstat()
            if (not stat.S_ISDIR(info.st_mode) or info.st_uid != os.getuid()
                    or stat.S_IMODE(info.st_mode) & 0o077 or self.root.resolve() != self.root.absolute()):
                raise ValueError('private capture root')
            if time.monotonic() >= self.deadline:
                raise ValueError('capture deadline')
            self.root_identity = (info.st_dev, info.st_ino)
            self.output_fd = os.open(self.output_path, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
            info = os.fstat(self.output_fd); self.output_identity = (info.st_dev, info.st_ino)
            os.mkfifo(self.fifo_path, 0o600)
            info = self.fifo_path.lstat(); self.fifo_identity = (info.st_dev, info.st_ino)
            self.read_fd = os.open(self.fifo_path, os.O_RDONLY | os.O_NONBLOCK | os.O_NOFOLLOW)
            self.dummy_fd = os.open(self.fifo_path, os.O_WRONLY | os.O_NONBLOCK | os.O_NOFOLLOW)
            self.reader = threading.Thread(target=self._capture, name='owned-capture-reader', daemon=True)
            self.reader.start()
            if not self.ready.wait(max(0, min(1, self.deadline-time.monotonic()))):
                raise RuntimeError('capture not ready')
        except BaseException:
            self.fail('creation')
            raise
        return self

    def spawn(self, argv, *, pass_fds=()):
        if (not self.ready.is_set() or self.spawn_attempted or self.failure_event.is_set()
                or time.monotonic() >= self.deadline):
            raise ValueError('capture spawn admission')
        if (type(pass_fds) is not tuple or len(pass_fds)>4 or len(set(pass_fds))!=len(pass_fds)
                or any(type(fd) is not int or fd<0 for fd in pass_fds)):
            raise ValueError('owned descriptor tuple')
        for fd in pass_fds: os.fstat(fd)
        for path, identity in ((self.root,self.root_identity),(self.fifo_path,self.fifo_identity),(self.output_path,self.output_identity)):
            info=path.lstat()
            if (info.st_dev,info.st_ino)!=identity: raise ValueError('capture path changed')
        self.spawn_attempted = True  # exact owned slot exists before Popen
        try:
            self.process = subprocess.Popen(argv, stdin=subprocess.DEVNULL, stdout=subprocess.DEVNULL,
                                            stderr=subprocess.PIPE, shell=False, close_fds=True, pass_fds=pass_fds)
            self.stderr_fd = self.process.stderr.fileno()
            os.set_blocking(self.stderr_fd, False)
            self.stderr_reader = threading.Thread(target=self._stderr, name='owned-capture-stderr', daemon=True)
            self.stderr_reader.start()
        except BaseException:
            self.fail('spawn'); raise
        return self.process

    def _capture(self):
        try:
            with selectors.DefaultSelector() as selector:
                selector.register(self.read_fd, selectors.EVENT_READ)
                self.ready.set()
                while not self.stop.is_set():
                    if time.monotonic() >= self.deadline and not self.shutdown_requested: self.fail('deadline')
                    if not selector.select(0.05):
                        continue
                    try:
                        data = os.read(self.read_fd, CHUNK)
                    except BlockingIOError:
                        continue
                    if not data:
                        self.fifo_eof = True
                        if not self.shutdown_requested:
                            self.fail('early_eof')
                        break
                    self.drained_bytes = min(0xffffffffffffffff, self.drained_bytes + len(data))
                    room = max(0, self.limit-self.retained_bytes)
                    kept = data[:room]
                    if kept and self.output_fd is not None:
                        try:
                            view = memoryview(kept)
                            while view:
                                count = os.write(self.output_fd, view)
                                if count <= 0: raise OSError('short write')
                                self.retained_bytes += count; view = view[count:]
                        except OSError:
                            self.fail('write')
                    if len(data) > room:
                        self.overflow_event.set(); self.fail('overflow')
                    self.structure.feed(data)
                    if self.structure.error:
                        self.fail(self.structure.error)
                    if self.structure.header and not self.header_ready.is_set():
                        self.header_ready.set()
                        # Do not keep a dummy writer alive: a broken QEMU dump must expose EOF.
                        self._close('dummy_fd')
        except BaseException:
            self.fail('read')

    def _stderr(self):
        pending = bytearray()
        try:
            with selectors.DefaultSelector() as selector:
                selector.register(self.stderr_fd, selectors.EVENT_READ)
                while not self.stop.is_set():
                    if not selector.select(0.05): continue
                    try: data = os.read(self.stderr_fd, CHUNK)
                    except BlockingIOError: continue
                    if not data:
                        if pending: self._stderr_line(bytes(pending))
                        self.stderr_eof = True; break
                    self.stderr_bytes = min(0xffffffff, self.stderr_bytes+len(data))
                    for value in data:
                        if value == 10:
                            self._stderr_line(bytes(pending)); pending.clear()
                        elif len(pending) < 4096:
                            pending.append(value)
                        else:
                            self.fail('stderr_bound')
        except BaseException:
            self.fail('read')

    def _stderr_line(self, line):
        if not line: return
        # Only the normal QEMU SIGTERM notice is benign; all other text is unknown/error.
        if self.shutdown_requested and re.fullmatch(rb'qemu-system-x86_64: terminating on signal 15 from pid [0-9]+(?: \([^\r\n]{1,256}\))?', line):
            return
        lowered = line.lower()
        self.fail('stderr_capture' if any(term in lowered for term in (b'dump', b'pcap', b'write error', b'short write')) else 'stderr_unknown')

    def wait_header(self, deadline):
        deadline = min(deadline, self.deadline)
        while time.monotonic() < deadline:
            if self.failure_event.is_set(): return False
            if self.header_ready.is_set(): return True
            if self.process is not None and self.process.poll() is not None:
                self.fail('header'); return False
            self.header_ready.wait(min(0.05, max(0, deadline-time.monotonic())))
        self.fail('deadline'); return False

    def finish(self, *, cleanup_deadline):
        if self.final is not None: return dict(self.final)
        if not self.shutdown_requested and self.process is not None:
            try: self.producer_live_at_shutdown = self.process.poll() is None
            except BaseException: self.fail('process_wait')
        self.shutdown_requested = True
        process_exit = self.process is None
        exit_code = None
        if self.process is not None:
            def observed_exit():
                try:
                    code = self.process.poll()
                    return code if type(code) is int else None
                except BaseException:
                    self.fail('process_wait'); return None
            exit_code = observed_exit()
            if exit_code is None:
                try: self.process.send_signal(signal.SIGTERM)
                except BaseException: self.fail('terminate')
                try: self.process.wait(timeout=max(0, min(15, cleanup_deadline-time.monotonic())))
                except subprocess.TimeoutExpired: pass
                except BaseException: self.fail('process_wait')
                exit_code = observed_exit()
                # Failed observation is not proof of exit. Keep exact ownership and
                # attempt fallback even when wait raised something other than timeout.
                if exit_code is None:
                    self.forced_kill = True
                    try: self.process.kill()
                    except BaseException: self.fail('kill')
                    try: self.process.wait(timeout=max(0, cleanup_deadline-time.monotonic()))
                    except BaseException: self.fail('process_wait')
                    exit_code = observed_exit()
            process_exit = exit_code is not None
        # Only once the producer is known stopped can our dummy descriptor be released.
        if process_exit: self._close('dummy_fd')
        for thread in (self.reader, self.stderr_reader):
            if thread is not None:
                try: thread.join(max(0, cleanup_deadline-time.monotonic()))
                except RuntimeError: self.fail('thread')
        stopped = all(t is None or not t.is_alive() for t in (self.reader, self.stderr_reader))
        if not stopped:
            self.fail('thread'); self.stop.set()
        # Never close descriptors under a live reader or delete an uncertain owned root.
        if stopped:
            self._close('read_fd'); self._close('dummy_fd')
            if self.process is not None and self.process.stderr is not None:
                try: self.process.stderr.close(); self.stderr_fd = None
                except OSError: self.fail('close')
            if self.output_fd is not None:
                try: os.fsync(self.output_fd); self.output_flushed = True
                except OSError: self.fail('flush')
                self._close('output_fd')
        descriptors_closed = all(getattr(self, name) is None for name in ('read_fd','dummy_fd','output_fd','stderr_fd'))
        cleanup = process_exit and stopped and descriptors_closed
        structural = self.structure.complete()
        complete = (cleanup and self.producer_live_at_shutdown and exit_code == 0 and not self.errors and not self.forced_kill and structural
                    and self.fifo_eof and self.stderr_eof and self.output_flushed and self.spawn_attempted)
        result = dict(schema_version=1, execution_model='owner_threads', fixture=self.fixture, reader_ready=self.ready.is_set(),
            header_verified=self.structure.header, structure_complete=structural, overflow=self.overflow_event.is_set(),
            retained_bytes=self.retained_bytes, drained_bytes=self.drained_bytes, records=self.structure.records,
            stderr_bytes=self.stderr_bytes, fifo_eof=self.fifo_eof, stderr_eof=self.stderr_eof,
            forced_kill=self.forced_kill, producer_live_at_shutdown=self.producer_live_at_shutdown, process_exit_observed=process_exit, process_exit_code=exit_code,
            readers_stopped=stopped, descriptors_closed=descriptors_closed, output_flushed=self.output_flushed,
            cleanup_confirmed=cleanup, drain_complete=complete, errors=sorted(self.errors),
            packet_absence_proven=False, root_removal_attempted=False)
        if cleanup: self.final = result
        return dict(result)
