"""Fixed-target, file-backed TCP relay for an externally isolated guest.

The host owns and creates the fixed-size shared files. The guest can only
exchange framed bytes with this relay; it never receives the Mihomo port or a
destination address. ``wait_ready`` waits for the guest helper's post-probe
GUEST_READY marker, not merely for the bridge listener to bind.

This deliberately favors a small, auditable protocol over throughput. The
bounded queues provide backpressure; a full queue never falls back to a direct
socket connection.
"""
from __future__ import annotations

import hashlib
import json
import mmap
import os
from pathlib import Path
import secrets
import shutil
import socket
import struct
import tempfile
import threading
import time
from typing import Any

try:  # Windows uses byte-range locking; flock is used on Unix.
    import msvcrt  # type: ignore
except ImportError:  # pragma: no cover - platform-specific
    msvcrt = None
try:
    import fcntl  # type: ignore
except ImportError:  # pragma: no cover - platform-specific
    fcntl = None


_MAGIC = b"RPFB0001"
_VERSION = 1
_SLOTS = 64
_PAYLOAD_MAX = 16 * 1024
_FRAME = struct.Struct("!Q16sBQI")  # seq, nonce tag, type, stream id, payload size
_HEADER = struct.Struct("!8sI16sIIQQ")  # magic, version, nonce tag, slots, slot size, head, tail
_HEADER_SIZE = 64
_SLOT_SIZE = _FRAME.size + _PAYLOAD_MAX
_RING_SIZE = _HEADER_SIZE + _SLOTS * _SLOT_SIZE
_FILE_LOCK_SECONDS = 2.0
_QUEUE_WAIT_SECONDS = 20.0
_STREAM_LIMIT = 64
_CONNECT_TIMEOUT = 5.0
_IO_TIMEOUT = 1.0
_CONTROL_MAX = 1024

_TYPES = {
    "READY": 1,
    "BRIDGE_READY": 2,
    "GUEST_READY": 3,
    "APPROVED": 4,
    "REJECTED": 5,
    "OPEN": 6,
    "OPEN_OK": 7,
    "OPEN_ERR": 8,
    "DATA": 9,
    "FIN": 10,
    "RESET": 11,
    "GOAWAY": 12,
}
_TYPE_NAMES = {value: key for key, value in _TYPES.items()}
_ZERO_STREAM_TYPES = {"READY", "BRIDGE_READY", "GUEST_READY", "APPROVED", "REJECTED", "GOAWAY"}
_EMPTY_TYPES = {"OPEN", "OPEN_OK", "FIN", "RESET", "GOAWAY"}


class BridgeError(RuntimeError):
    """Raised when the bounded bridge protocol cannot continue safely."""


def _nonce_tag(nonce: str) -> bytes:
    if not isinstance(nonce, str) or len(nonce) != 64:
        raise BridgeError("invalid bridge nonce")
    try:
        raw = bytes.fromhex(nonce)
    except ValueError as exc:
        raise BridgeError("invalid bridge nonce") from exc
    if len(raw) != 32:
        raise BridgeError("invalid bridge nonce")
    return hashlib.sha256(raw).digest()[:16]


def _atomic_json(path: Path, value: dict[str, Any]) -> None:
    payload = json.dumps(value, separators=(",", ":"), ensure_ascii=True).encode("ascii")
    if len(payload) > _CONTROL_MAX:
        raise BridgeError("bridge control record is too large")
    temp = path.with_name(path.name + ".tmp-" + secrets.token_hex(6))
    try:
        with temp.open("xb") as stream:
            stream.write(payload)
            stream.flush()
            os.fsync(stream.fileno())
        os.replace(temp, path)
    finally:
        try:
            temp.unlink()
        except FileNotFoundError:
            pass


def _read_json(path: Path) -> dict[str, Any] | None:
    try:
        with path.open("rb") as stream:
            raw = stream.read(_CONTROL_MAX + 1)
    except FileNotFoundError:
        return None
    if not raw or len(raw) > _CONTROL_MAX:
        raise BridgeError("invalid bridge control record size")
    try:
        value = json.loads(raw.decode("ascii"))
    except (UnicodeError, json.JSONDecodeError) as exc:
        raise BridgeError("invalid bridge control record") from exc
    if not isinstance(value, dict):
        raise BridgeError("invalid bridge control record")
    return value


def _assert_no_reparse(path: Path) -> os.stat_result:
    info = path.lstat()
    attrs = getattr(info, "st_file_attributes", 0)
    if attrs & 0x400:  # FILE_ATTRIBUTE_REPARSE_POINT
        raise BridgeError("bridge control path is a reparse point")
    if path.is_symlink():
        raise BridgeError("bridge control path is a symbolic link")
    return info


def signal_guest_ready(directory: str | os.PathLike[str], nonce: str) -> None:
    """Publish GUEST_READY after the helper's local proxy roundtrip succeeds."""
    root = Path(directory)
    _validate_directory(root, nonce)
    _atomic_json(root / "guest-status.json", {"nonce": nonce, "state": "GUEST_READY"})


def wait_for_bridge_ready(
    directory: str | os.PathLike[str], nonce: str, timeout: float | None
) -> bool:
    """Wait for run_guest_bridge to bind its listener and initialize its rings."""
    root = Path(directory)
    _validate_directory(root, nonce)
    if timeout is not None and timeout < 0:
        raise ValueError("timeout must be non-negative")
    deadline = None if timeout is None else time.monotonic() + timeout
    marker = root / "bridge-ready.json"
    while True:
        try:
            value = _read_json(marker)
        except (OSError, BridgeError):
            return False
        if value is not None:
            if value.get("nonce") != nonce or value.get("ready") is not True:
                raise BridgeError("bridge-ready marker validation failed")
            return True
        if deadline is not None and time.monotonic() >= deadline:
            return False
        time.sleep(0.05)


def wait_for_decision(
    directory: str | os.PathLike[str], nonce: str, timeout: float | None
) -> str:
    """Wait for host approval or rejection; returns approved/rejected/timeout."""
    root = Path(directory)
    _validate_directory(root, nonce)
    if timeout is not None and timeout < 0:
        raise ValueError("timeout must be non-negative")
    deadline = None if timeout is None else time.monotonic() + timeout
    marker = root / "host-control.json"
    while True:
        value = _read_json(marker)
        if value is not None:
            if value.get("nonce") != nonce:
                raise BridgeError("host control nonce mismatch")
            state = value.get("state")
            if state == "APPROVED":
                return "approved"
            if state == "REJECTED":
                return "rejected"
            raise BridgeError("invalid host control state")
        if deadline is not None and time.monotonic() >= deadline:
            return "timeout"
        time.sleep(0.05)


def _validate_directory(root: Path, nonce: str) -> bytes:
    tag = _nonce_tag(nonce)
    try:
        manifest = _read_json(root / "manifest.json")
    except OSError as exc:
        raise BridgeError("bridge files are unavailable") from exc
    if not manifest or manifest.get("version") != _VERSION or manifest.get("nonce") != nonce:
        raise BridgeError("bridge nonce or manifest mismatch")
    return tag


class _Ring:
    """Fixed-slot single-file ring. OS locking protects indices and slot data."""

    def __init__(self, path: Path, nonce_tag: bytes, *, create: bool = False):
        self.path = path
        self.nonce_tag = nonce_tag
        self._thread_lock = threading.Lock()
        if create:
            fd = os.open(path, os.O_CREAT | os.O_EXCL | os.O_RDWR, 0o600)
            try:
                os.ftruncate(fd, _RING_SIZE)
            except Exception:
                os.close(fd)
                raise
        else:
            fd = os.open(path, os.O_RDWR)
            if os.fstat(fd).st_size != _RING_SIZE:
                os.close(fd)
                raise BridgeError("invalid bridge ring size")
        self.fd = fd
        try:
            self.map = mmap.mmap(fd, _RING_SIZE, access=mmap.ACCESS_WRITE)
            try:
                if create:
                    self.map[:_HEADER_SIZE] = _HEADER.pack(
                        _MAGIC, _VERSION, nonce_tag, _SLOTS, _SLOT_SIZE, 0, 0
                    ) + bytes(_HEADER_SIZE - _HEADER.size)
                    self.map.flush()
                self._check_header()
            except BaseException:
                self.map.close()
                raise
        except BaseException:
            os.close(fd)
            raise

    def _lock(self, deadline: float) -> None:
        while True:
            if self._thread_lock.acquire(timeout=max(0.001, min(0.05, deadline - time.monotonic()))):
                break
            if time.monotonic() >= deadline:
                raise TimeoutError("bridge ring lock timed out")
        try:
            if msvcrt is not None:
                while True:
                    try:
                        os.lseek(self.fd, 0, os.SEEK_SET)
                        msvcrt.locking(self.fd, msvcrt.LK_NBLCK, 1)
                        return
                    except OSError:
                        if time.monotonic() >= deadline:
                            raise TimeoutError("bridge ring lock timed out")
                        time.sleep(0.01)
            elif fcntl is not None:
                while True:
                    try:
                        fcntl.flock(self.fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
                        return
                    except BlockingIOError:
                        if time.monotonic() >= deadline:
                            raise TimeoutError("bridge ring lock timed out")
                        time.sleep(0.01)
            else:  # No unprotected cross-process fallback.
                raise BridgeError("this platform has no supported bridge file lock")
        except Exception:
            self._thread_lock.release()
            raise

    def _unlock(self) -> None:
        try:
            if msvcrt is not None:
                os.lseek(self.fd, 0, os.SEEK_SET)
                msvcrt.locking(self.fd, msvcrt.LK_UNLCK, 1)
            elif fcntl is not None:
                fcntl.flock(self.fd, fcntl.LOCK_UN)
        finally:
            self._thread_lock.release()

    def _check_header(self) -> tuple[int, int]:
        raw = bytes(self.map[:_HEADER.size])
        magic, version, tag, slots, slot_size, head, tail = _HEADER.unpack(raw)
        if (magic != _MAGIC or version != _VERSION or tag != self.nonce_tag
                or slots != _SLOTS or slot_size != _SLOT_SIZE
                or head >= (1 << 63) or tail >= (1 << 63) or tail > head
                or head - tail > _SLOTS):
            raise BridgeError("bridge ring header validation failed")
        return head, tail

    def put(self, kind: str, stream_id: int, payload: bytes, stop: threading.Event) -> None:
        if kind not in _TYPES or len(payload) > _PAYLOAD_MAX:
            raise BridgeError("invalid bridge frame type or length")
        if (kind in _ZERO_STREAM_TYPES) != (stream_id == 0):
            raise BridgeError("invalid bridge stream id")
        if kind in _EMPTY_TYPES and payload:
            raise BridgeError("unexpected bridge frame payload")
        if kind == "DATA" and (stream_id == 0 or not payload):
            raise BridgeError("invalid DATA frame")
        if kind == "OPEN_ERR" and (stream_id == 0 or not payload):
            raise BridgeError("invalid OPEN_ERR frame")
        deadline = time.monotonic() + _QUEUE_WAIT_SECONDS
        while not stop.is_set():
            self._lock(min(deadline, time.monotonic() + _FILE_LOCK_SECONDS))
            try:
                if stop.is_set():
                    raise BridgeError("bridge stopped while writing")
                head, tail = self._check_header()
                if head - tail < _SLOTS:
                    seq = head + 1
                    slot = bytearray(_SLOT_SIZE)
                    slot[:_FRAME.size] = _FRAME.pack(seq, self.nonce_tag, _TYPES[kind], stream_id, len(payload))
                    slot[_FRAME.size:_FRAME.size + len(payload)] = payload
                    offset = _HEADER_SIZE + (head % _SLOTS) * _SLOT_SIZE
                    self.map[offset:offset + _SLOT_SIZE] = slot
                    self.map[:_HEADER.size] = _HEADER.pack(
                        _MAGIC, _VERSION, self.nonce_tag, _SLOTS, _SLOT_SIZE, seq, tail
                    )
                    # Both peers map this same file with ACCESS_WRITE. Shared
                    # views see each other's writes under the OS lock; flushing
                    # the whole ring to disk per frame is not an IPC barrier.
                    return
            finally:
                self._unlock()
            if time.monotonic() >= deadline:
                raise TimeoutError("bridge queue remained full")
            stop.wait(0.01)
        raise BridgeError("bridge stopped while writing")

    def get(self, stop: threading.Event, timeout: float = 0.2) -> tuple[str, int, bytes] | None:
        """Poll an empty queue; contention uses the separate file-lock budget."""
        deadline = time.monotonic() + timeout
        while not stop.is_set():
            # A producer can be descheduled while holding this lock. The short
            # empty-queue polling interval must not classify valid contention
            # as transport failure and tear down every active TCP stream.
            self._lock(time.monotonic() + _FILE_LOCK_SECONDS)
            try:
                head, tail = self._check_header()
                if head > tail:
                    offset = _HEADER_SIZE + (tail % _SLOTS) * _SLOT_SIZE
                    raw = bytes(self.map[offset:offset + _SLOT_SIZE])
                    seq, tag, type_id, stream_id, length = _FRAME.unpack(raw[:_FRAME.size])
                    kind = _TYPE_NAMES.get(type_id)
                    if (seq != tail + 1 or tag != self.nonce_tag or kind is None
                            or length > _PAYLOAD_MAX
                            or (kind in _ZERO_STREAM_TYPES) != (stream_id == 0)
                            or (kind in _EMPTY_TYPES and length != 0)
                            or (kind == "DATA" and (stream_id == 0 or length == 0))
                            or (kind == "OPEN_ERR" and (stream_id == 0 or length == 0))):
                        raise BridgeError("bridge frame validation failed")
                    payload = raw[_FRAME.size:_FRAME.size + length]
                    if any(raw[_FRAME.size + length:]):
                        raise BridgeError("bridge frame padding validation failed")
                    self.map[:_HEADER.size] = _HEADER.pack(
                        _MAGIC, _VERSION, self.nonce_tag, _SLOTS, _SLOT_SIZE, head, tail + 1
                    )
                    return kind, stream_id, payload
            finally:
                self._unlock()
            if time.monotonic() >= deadline:
                return None
            stop.wait(min(0.01, max(0.0, deadline - time.monotonic())))
        return None

    def close(self) -> None:
        try:
            self.map.close()
        finally:
            os.close(self.fd)


class _Stream:
    def __init__(self, sock: socket.socket):
        self.sock = sock
        self.opened = threading.Event()
        self.open_error: str | None = None
        self.closed = threading.Event()
        self.fin_sent = False
        self.fin_received = False
        self.lock = threading.Lock()


class FileProxyBridge:
    """Host side relay with a single hard-coded Mihomo loopback target."""

    def __init__(self, host_proxy_port: int, directory: str | os.PathLike[str]):
        if isinstance(host_proxy_port, bool) or not isinstance(host_proxy_port, int) or not 1 <= host_proxy_port <= 65535:
            raise ValueError("host proxy port must be between 1 and 65535")
        self.host_proxy_port = host_proxy_port
        base = Path(directory)
        base.mkdir(parents=True, exist_ok=True)
        _assert_no_reparse(base)
        self._base_directory = base.resolve()
        base_info = self._base_directory.stat()
        self._base_identity = (base_info.st_dev, base_info.st_ino)
        self.directory = Path(tempfile.mkdtemp(prefix="ruleproxy-bridge-", dir=base))
        try:
            self.directory.chmod(0o700)
        except OSError:
            pass
        self.nonce = secrets.token_hex(32)
        root_info = self.directory.lstat()
        self._root_identity = (root_info.st_dev, root_info.st_ino)
        self._tag = _nonce_tag(self.nonce)
        try:
            _atomic_json(self.directory / "manifest.json", {"version": _VERSION, "nonce": self.nonce})
            self._to_host = _Ring(self.directory / "guest-to-host.ring", self._tag, create=True)
            try:
                self._to_guest = _Ring(self.directory / "host-to-guest.ring", self._tag, create=True)
            except BaseException:
                self._to_host.close()
                raise
        except BaseException:
            # No guest has been launched yet, so partial bridge files can be
            # removed immediately instead of leaving handles and stale runs.
            shutil.rmtree(self.directory, ignore_errors=True)
            raise
        self._stop = threading.Event()
        self._resources_closed = threading.Event()
        self._close_lock = threading.Lock()
        self._ready = threading.Event()
        self._approved = False
        self.last_error: str | None = None
        self._state_lock = threading.RLock()
        self._streams: dict[int, _Stream] = {}
        self._workers: set[threading.Thread] = set()
        self._next_stream = 1
        self._dispatcher = threading.Thread(target=self._dispatch, name="ruleproxy-file-bridge", daemon=True)
        self._dispatcher.start()

    def wait_ready(self, timeout: float | None = None) -> bool:
        """Wait for helper-written GUEST_READY after its contained proxy probe."""
        if timeout is not None and timeout < 0:
            raise ValueError("timeout must be non-negative")
        deadline = None if timeout is None else time.monotonic() + timeout
        while not self._stop.is_set():
            try:
                status = _read_json(self._control_path("guest-status.json", allow_missing=True))
                if status is not None:
                    if status.get("nonce") != self.nonce:
                        raise BridgeError("guest ready nonce mismatch")
                    state = status.get("state")
                    if state == "GUEST_READY":
                        return True
                    if state == "FAILED":
                        detail = status.get("detail")
                        self.last_error = (
                            detail[:500] if isinstance(detail, str) and detail
                            else "Guest bridge startup failed"
                        )
                        return False
                    if state == "REJECTED":
                        return False
                    if state != "BRIDGE_READY":
                        raise BridgeError("invalid guest status")
            except (OSError, BridgeError):
                return False
            if deadline is not None and time.monotonic() >= deadline:
                return False
            self._ready.wait(0.05)
        return False

    def approve(self) -> None:
        with self._state_lock:
            if self._stop.is_set():
                raise BridgeError("bridge is closed")
            if not self.wait_ready(0):
                raise BridgeError("guest self-check is not ready")
            _atomic_json(self._control_path("host-control.json", allow_missing=True), {"nonce": self.nonce, "state": "APPROVED"})
            self._approved = True
            self._ready.set()

    def reject(self, reason: str) -> None:
        safe_reason = str(reason)[:100]
        with self._state_lock:
            if self._stop.is_set():
                return
            _atomic_json(self._control_path("host-control.json", allow_missing=True), {
                "nonce": self.nonce, "state": "REJECTED", "reason": safe_reason,
            })
            self._ready.set()
        self._stop.set()
        self._shutdown_streams()

    def _write_host(self, kind: str, stream_id: int, payload: bytes = b"") -> None:
        if self._resources_closed.is_set():
            raise BridgeError("bridge resources are closed")
        self._to_guest.put(kind, stream_id, payload, self._stop)

    def _control_path(self, name: str, *, allow_missing: bool = False) -> Path:
        if Path(name).name != name:
            raise BridgeError("invalid bridge control filename")
        try:
            base_info = self._base_directory.lstat()
            root_info = self.directory.lstat()
            if (base_info.st_dev, base_info.st_ino) != self._base_identity:
                raise BridgeError("bridge parent directory identity changed")
            if (root_info.st_dev, root_info.st_ino) != self._root_identity:
                raise BridgeError("bridge directory identity changed")
            _assert_no_reparse(self._base_directory)
            _assert_no_reparse(self.directory)
            path = self.directory / name
            try:
                _assert_no_reparse(path)
            except FileNotFoundError:
                if not allow_missing:
                    raise
            return path
        except OSError as exc:
            raise BridgeError("bridge control directory is unavailable") from exc

    def _dispatch(self) -> None:
        try:
            while not self._stop.is_set():
                item = self._to_host.get(self._stop, 0.1)
                if item is None:
                    continue
                kind, stream_id, payload = item
                if kind == "READY":
                    if payload != self.nonce.encode("ascii"):
                        raise BridgeError("guest bridge nonce mismatch")
                    self._write_host("BRIDGE_READY", 0)
                elif kind == "OPEN":
                    self._on_open(stream_id)
                elif kind in ("DATA", "FIN", "RESET"):
                    self._on_stream_frame(kind, stream_id, payload)
                elif kind == "GOAWAY":
                    self._stop.set()
                else:
                    raise BridgeError("unexpected guest bridge frame")
        except (BridgeError, OSError, TimeoutError) as exc:
            self.last_error = str(exc)
        finally:
            self._stop.set()
            self._shutdown_streams()
            self._ready.set()

    def _on_open(self, stream_id: int) -> None:
        if stream_id == 0:
            raise BridgeError("invalid OPEN stream id")
        with self._state_lock:
            if stream_id in self._streams or len(self._streams) >= _STREAM_LIMIT:
                self._write_host("OPEN_ERR", stream_id, b"stream limit or duplicate id")
                return
            stream = _Stream(socket.socket(socket.AF_INET, socket.SOCK_STREAM))
            stream.sock.settimeout(_IO_TIMEOUT)
            self._streams[stream_id] = stream
            worker = threading.Thread(target=self._connect_stream, args=(stream_id, stream), daemon=True)
            self._workers.add(worker)
        worker.start()

    def _connect_stream(self, stream_id: int, stream: _Stream) -> None:
        try:
            # This is the only outbound host socket in this module.
            stream.sock.settimeout(_CONNECT_TIMEOUT)
            stream.sock.connect(("127.0.0.1", self.host_proxy_port))
            stream.sock.settimeout(_IO_TIMEOUT)
            stream.opened.set()
            self._write_host("OPEN_OK", stream_id)
            while not self._stop.is_set() and not stream.closed.is_set():
                try:
                    data = stream.sock.recv(_PAYLOAD_MAX)
                except socket.timeout:
                    continue
                if not data:
                    self._write_host("FIN", stream_id)
                    with stream.lock:
                        stream.fin_sent = True
                        if stream.fin_received:
                            self._drop_stream(stream_id, stream)
                    return
                self._write_host("DATA", stream_id, data)
        except (OSError, BridgeError, TimeoutError) as exc:
            try:
                self._write_host("OPEN_ERR", stream_id, str(exc).encode("utf-8", "replace")[:512])
            except Exception:
                pass
            stream.open_error = str(exc)
            stream.opened.set()
            self._drop_stream(stream_id, stream)
        finally:
            with self._state_lock:
                self._workers.discard(threading.current_thread())

    def _on_stream_frame(self, kind: str, stream_id: int, payload: bytes) -> None:
        with self._state_lock:
            stream = self._streams.get(stream_id)
        if stream is None:
            # TCP shutdown can race with already queued frames. Unknown stream
            # traffic is discarded without creating or connecting any socket.
            return
        if kind == "DATA":
            if not stream.opened.is_set():
                try:
                    self._write_host("RESET", stream_id)
                except (BridgeError, TimeoutError):
                    pass
                self._drop_stream(stream_id, stream)
                return
            try:
                stream.sock.sendall(payload)
            except OSError:
                try:
                    self._write_host("RESET", stream_id)
                except (BridgeError, TimeoutError):
                    pass
                self._drop_stream(stream_id, stream)
        elif kind == "FIN":
            try:
                stream.sock.shutdown(socket.SHUT_WR)
            except OSError:
                pass
            with stream.lock:
                stream.fin_received = True
                if stream.fin_sent:
                    self._drop_stream(stream_id, stream)
        else:
            self._drop_stream(stream_id, stream)

    def _drop_stream(self, stream_id: int, stream: _Stream) -> None:
        with self._state_lock:
            if self._streams.get(stream_id) is stream:
                self._streams.pop(stream_id, None)
        if not stream.closed.is_set():
            stream.closed.set()
            try:
                stream.sock.shutdown(socket.SHUT_RDWR)
            except OSError:
                pass
            stream.sock.close()

    def _shutdown_streams(self) -> None:
        with self._state_lock:
            streams = list(self._streams.items())
        for stream_id, stream in streams:
            self._drop_stream(stream_id, stream)

    def close(self) -> None:
        with self._close_lock:
            if self._resources_closed.is_set():
                return
            self._stop.set()
            self._ready.set()
            try:
                self._shutdown_streams()
                self._dispatcher.join(timeout=3)
                with self._state_lock:
                    workers = tuple(self._workers)
                deadline = time.monotonic() + 4
                for thread in workers:
                    thread.join(timeout=max(0, deadline - time.monotonic()))
            finally:
                self._resources_closed.set()
                self._to_host.close()
                self._to_guest.close()
                # Keep files until the guest helper has exited. The owning launcher
                # removes the private directory after stopping that contained guest.


class _GuestStream:
    def __init__(self, sock: socket.socket):
        self.sock = sock
        self.opened = threading.Event()
        self.open_error: str | None = None
        self.closed = threading.Event()
        self.fin_sent = False
        self.fin_received = False
        self.lock = threading.Lock()


def run_guest_bridge(
    listener_port: int,
    directory: str | os.PathLike[str],
    nonce: str,
    stop_event: threading.Event,
) -> None:
    """Serve raw localhost TCP and forward only through the fixed file relay."""
    if isinstance(listener_port, bool) or not isinstance(listener_port, int) or not 1 <= listener_port <= 65535:
        raise ValueError("listener port must be between 1 and 65535")
    root = Path(directory)
    tag = _validate_directory(root, nonce)
    to_host = _Ring(root / "guest-to-host.ring", tag)
    try:
        to_guest = _Ring(root / "host-to-guest.ring", tag)
    except BaseException:
        to_host.close()
        raise
    closed = threading.Event()
    threads: set[threading.Thread] = set()
    streams: dict[int, _GuestStream] = {}
    lock = threading.RLock()
    dispatcher_error: list[str] = []
    listener: socket.socket | None = None

    def send(kind: str, stream_id: int, payload: bytes = b"") -> None:
        to_host.put(kind, stream_id, payload, closed)

    def drop(stream_id: int, stream: _GuestStream, reset: bool = False) -> None:
        with lock:
            if streams.get(stream_id) is stream:
                streams.pop(stream_id, None)
        if not stream.closed.is_set():
            stream.closed.set()
            if reset:
                try:
                    send("RESET", stream_id)
                except Exception:
                    pass
            try:
                stream.sock.shutdown(socket.SHUT_RDWR)
            except OSError:
                pass
            stream.sock.close()

    def worker(stream_id: int, stream: _GuestStream) -> None:
        try:
            send("OPEN", stream_id)
            while not closed.is_set() and not stream.opened.wait(0.05):
                pass
            if closed.is_set() or stream.closed.is_set() or stream.open_error:
                drop(stream_id, stream)
                return
            stream.sock.settimeout(_IO_TIMEOUT)
            while not closed.is_set() and not stream.closed.is_set():
                try:
                    data = stream.sock.recv(_PAYLOAD_MAX)
                except socket.timeout:
                    continue
                if not data:
                    send("FIN", stream_id)
                    with stream.lock:
                        stream.fin_sent = True
                        if stream.fin_received:
                            drop(stream_id, stream)
                    return
                send("DATA", stream_id, data)
        except (OSError, BridgeError, TimeoutError):
            drop(stream_id, stream, reset=True)
        finally:
            with lock:
                threads.discard(threading.current_thread())

    def dispatcher() -> None:
        try:
            while not closed.is_set():
                item = to_guest.get(closed, 0.1)
                if item is None:
                    continue
                kind, stream_id, payload = item
                if kind == "BRIDGE_READY":
                    if stream_id != 0 or payload:
                        raise BridgeError("invalid bridge-ready frame")
                    continue
                if kind == "OPEN_OK":
                    with lock:
                        stream = streams.get(stream_id)
                    if stream is None:
                        try:
                            send("RESET", stream_id)
                        except (BridgeError, TimeoutError):
                            pass
                    elif not stream.closed.is_set():
                        stream.opened.set()
                elif kind == "OPEN_ERR":
                    with lock:
                        stream = streams.get(stream_id)
                    if stream is not None:
                        stream.open_error = payload.decode("utf-8", "replace")[:512]
                        stream.opened.set()
                        drop(stream_id, stream)
                elif kind in ("DATA", "FIN", "RESET"):
                    with lock:
                        stream = streams.get(stream_id)
                    if stream is None:
                        # Ignore in-flight frames for streams already torn down.
                        continue
                    if kind == "DATA":
                        if not stream.opened.is_set():
                            drop(stream_id, stream, reset=True)
                            continue
                        try:
                            stream.sock.sendall(payload)
                        except OSError:
                            drop(stream_id, stream, reset=True)
                    elif kind == "FIN":
                        try:
                            stream.sock.shutdown(socket.SHUT_WR)
                        except OSError:
                            pass
                        with stream.lock:
                            stream.fin_received = True
                            if stream.fin_sent:
                                drop(stream_id, stream)
                    else:
                        drop(stream_id, stream)
                elif kind == "REJECTED":
                    raise BridgeError("host rejected bridge")
                elif kind in ("APPROVED", "GOAWAY"):
                    if kind == "GOAWAY":
                        raise BridgeError("host closed bridge")
                else:
                    raise BridgeError("unexpected host bridge frame")
        except (BridgeError, OSError, TimeoutError) as exc:
            dispatcher_error.append(str(exc))
            closed.set()

    dispatcher_thread = threading.Thread(target=dispatcher, name="ruleproxy-guest-dispatch", daemon=True)
    try:
        listener = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        listener.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 0)
        listener.bind(("127.0.0.1", listener_port))
        listener.listen(_STREAM_LIMIT)
        listener.settimeout(0.2)
        dispatcher_thread.start()
        _atomic_json(root / "bridge-ready.json", {"nonce": nonce, "ready": True})
        send("READY", 0, nonce.encode("ascii"))
        _atomic_json(root / "guest-status.json", {"nonce": nonce, "state": "BRIDGE_READY"})
        while not closed.is_set() and not stop_event.is_set():
            control = _read_json(root / "host-control.json")
            if control is not None:
                if control.get("nonce") != nonce:
                    raise BridgeError("host control nonce mismatch")
                if control.get("state") == "REJECTED":
                    break
                if control.get("state") not in ("APPROVED",):
                    raise BridgeError("invalid host control state")
            try:
                client, _ = listener.accept()
            except socket.timeout:
                continue
            with lock:
                if len(streams) >= _STREAM_LIMIT:
                    client.close()
                    continue
                stream_id = secrets.randbits(63) or 1
                while stream_id in streams:
                    stream_id = secrets.randbits(63) or 1
                stream = _GuestStream(client)
                stream.sock.settimeout(_IO_TIMEOUT)
                streams[stream_id] = stream
                thread = threading.Thread(target=worker, args=(stream_id, stream), daemon=True)
                threads.add(thread)
                thread.start()
        if dispatcher_error:
            raise BridgeError(dispatcher_error[0])
    except Exception as exc:
        try:
            _atomic_json(root / "guest-status.json", {
                "nonce": nonce, "state": "FAILED", "detail": str(exc)[:700],
            })
        except Exception:
            pass
        raise
    finally:
        closed.set()
        if listener is not None:
            try:
                listener.close()
            except OSError:
                pass
        with lock:
            active = list(streams.items())
        for stream_id, stream in active:
            drop(stream_id, stream)
        if dispatcher_thread.ident is not None:
            dispatcher_thread.join(timeout=2)
        for thread in tuple(threads):
            thread.join(timeout=0.2)
        try:
            to_host.close()
        finally:
            to_guest.close()
