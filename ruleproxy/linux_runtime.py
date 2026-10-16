"""Rootless per-launch network namespaces with a proxy-only Unix socket bridge.

No veth, host route, firewall rule, DNS setting, NAT, or host TUN is created.
An application sees only a fresh loopback interface. Its descendants remain
there. Unsupported direct connections fail, including direct IPv6 and UDP.
"""
from __future__ import annotations

import json
import os
from pathlib import Path
import re
import select
import shutil
import signal
import stat
import socket
import subprocess
import sys
import tempfile
import threading
import uuid


_RULEPROXY_BWRAP = Path("/usr/local/lib/ruleproxy-web/bwrap")
_RULEPROXY_CHROMIUM_BWRAP = Path("/usr/local/lib/ruleproxy-web/bwrap-chromium")
_HELPER_PATH = "/run/ruleproxy_helper.py"  # where the namespace helper runs inside the sandbox
_USER_DIRS_MARK = "# Written by RuleProxy: downloads go to the shared Downloads folder."
_CHROMIUM_SANDBOX_PATHS = frozenset({
    "/opt/google/chrome/chrome",
    "/opt/microsoft/msedge/msedge",
    "/opt/brave.com/brave/brave",
    "/usr/lib/chromium/chromium",
    "/usr/lib/chromium-browser/chromium-browser",
    "/usr/lib/chatgpt/ChatGPT",
})


def _trusted_system_executable(path: Path) -> bool:
    """Use the dedicated AppArmor target only when the user cannot replace it."""
    try:
        resolved = path.resolve(strict=True)
        if resolved != path or not stat.S_ISREG(path.lstat().st_mode):
            return False
        if path.stat().st_uid != 0 or path.stat().st_mode & 0o022:
            return False
        for parent in path.parents:
            info = parent.lstat()
            if not stat.S_ISDIR(info.st_mode) or info.st_uid != 0 or info.st_mode & 0o022:
                return False
        return os.access(path, os.X_OK)
    except OSError:
        return False


def bwrap_executable(*, chromium_sandbox: bool = False) -> str | None:
    if chromium_sandbox and _trusted_system_executable(_RULEPROXY_CHROMIUM_BWRAP):
        return str(_RULEPROXY_CHROMIUM_BWRAP)
    if _trusted_system_executable(_RULEPROXY_BWRAP):
        return str(_RULEPROXY_BWRAP)
    return shutil.which("bwrap")

class ProxyBridge:
    def __init__(self, port: int):
        self.port = port
        # Unix socket paths have a small maximum; do not place it in the state directory.
        self.directory = tempfile.TemporaryDirectory(prefix="ruleproxy-")
        self.path = str(Path(self.directory.name) / "proxy.sock")
        self.listener = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        self.listener.bind(self.path)
        os.chmod(self.path, 0o600)
        self.listener.listen(64)
        self.closed = threading.Event()
        self.connections: set[socket.socket] = set()
        self.lock = threading.Lock()
        threading.Thread(target=self._accept, daemon=True).start()

    def _accept(self):
        while not self.closed.is_set():
            try:
                client, _ = self.listener.accept()
            except OSError:
                return
            threading.Thread(target=self._forward, args=(client,), daemon=True).start()

    def _forward(self, client: socket.socket):
        peer = None
        try:
            peer = socket.create_connection(("127.0.0.1", self.port), timeout=3)
            peer.settimeout(None)
            with self.lock:
                if self.closed.is_set():
                    return
                self.connections.update((client, peer))
            while not self.closed.is_set():
                readable, _, _ = select.select((client, peer), [], [], 1)
                for source in readable:
                    chunk = source.recv(65536)
                    if not chunk:
                        return
                    (peer if source is client else client).sendall(chunk)
        except (OSError, ValueError):
            pass
        finally:
            with self.lock:
                self.connections.discard(client)
                if peer:
                    self.connections.discard(peer)
            client.close()
            if peer:
                peer.close()

    def close(self):
        self.closed.set()
        self.listener.close()
        with self.lock:
            for connection in tuple(self.connections):
                try:
                    connection.shutdown(socket.SHUT_RDWR)
                except OSError:
                    pass
                connection.close()
        self.directory.cleanup()


def probe() -> dict:
    bwrap = bwrap_executable()
    if not bwrap:
        return {"supported": False, "backend": "Linux 网络隔离", "detail": "请安装 bubblewrap 后再启动应用。", "limitations": []}
    permission_denied = False
    try:
        result = subprocess.run(
            [bwrap, "--unshare-user", "--unshare-net", "--unshare-pid", "--ro-bind", "/", "/", "--proc", "/proc", "--dev", "/dev", sys.executable, "-c", "import socket; assert {n for _,n in socket.if_nameindex()} == {'lo'}"],
            capture_output=True, timeout=8,
        )
        supported = result.returncode == 0
        error = result.stderr.decode("utf-8", errors="replace").lower()
        permission_denied = any(message in error for message in ("operation not permitted", "permission denied"))
    except (OSError, subprocess.TimeoutExpired):
        supported = False
    detail = "应用只能连接本地代理，直连 IPv4 / IPv6 和 UDP 被隔离。" if supported else "系统禁止创建网络隔离空间，应用启动已禁用。"
    restriction = Path("/proc/sys/kernel/apparmor_restrict_unprivileged_userns")
    try:
        if not supported and permission_denied and restriction.read_text().strip() == "1":
            detail = "Ubuntu AppArmor 限制了隔离权限。请先运行项目中的 Linux AppArmor 准备脚本；受保护启动已禁用。"
    except OSError:
        pass
    return {"supported": supported, "backend": "Linux 独立网络空间", "detail": detail, "limitations": ["仅从面板或快捷方式启动的实例受保护。", "代理不支持的协议、部分桌面功能可能不可用；连接失败不会直连。"]}


def _xdg_download_dir(home: Path) -> Path:
    """The user's Downloads folder as configured in user-dirs.dirs, else ~/Downloads."""
    config_home = Path(os.environ.get("XDG_CONFIG_HOME") or home / ".config")
    try:
        lines = (config_home / "user-dirs.dirs").read_text(encoding="utf-8").splitlines()
    except (OSError, UnicodeDecodeError):
        lines = []
    for raw in lines:
        line = raw.strip()
        if not line.startswith("XDG_DOWNLOAD_DIR="):
            continue
        value = line.split("=", 1)[1].strip()
        if len(value) >= 2 and value[0] == value[-1] == '"':
            value = re.sub(r"\\(.)", r"\1", value[1:-1])
            if value == "$HOME":
                return home
            if value.startswith("$HOME/"):
                return home / value[len("$HOME/"):]
            if value.startswith("/"):
                return Path(value)
        break
    return home / "Downloads"


def downloads_folder(state_dir: Path) -> tuple[Path, Path] | None:
    """The Downloads folder that isolated apps may read and write, as (real folder, path apps see).

    Like a Flatpak browser's default, apps get this one folder and nothing else from the
    home folder. It must belong to the user, and it may not be the home folder, one of
    its parents, or anything that overlaps the panel's data. None gives apps no host files.
    """
    home = Path.home()
    target = Path(os.path.abspath(_xdg_download_dir(home)))
    try:
        if target == home / "Downloads" and not target.exists():
            target.mkdir()  # the conventional folder, as a browser would create it
        source = target.resolve(strict=True)
        info = source.stat()
    except OSError:
        return None
    if not stat.S_ISDIR(info.st_mode) or info.st_uid != os.getuid() or not os.access(source, os.R_OK | os.W_OK | os.X_OK):
        return None
    state = Path(state_dir).resolve()
    for protected in (home.resolve(), state):
        if source == protected or source in protected.parents:
            return None
    if state in source.parents:
        return None
    return source, target


def _point_downloads(profile: Path, target: Path | None) -> None:
    """Make XDG-aware apps save downloads in the shared folder, or back in the profile."""
    config = profile / ".config" / "user-dirs.dirs"
    # Parsers disagree on escapes, so an unusual path is shared without being made the default.
    if target is not None and not re.search(r'["\\$`\n]', str(target)):
        config.parent.mkdir(parents=True, exist_ok=True)
        config.write_text(f'{_USER_DIRS_MARK}\nXDG_DOWNLOAD_DIR="{target}"\n', encoding="utf-8")
        return
    try:
        if config.read_text(encoding="utf-8").startswith(_USER_DIRS_MARK):
            config.unlink()  # only ever remove the file written here
    except (OSError, UnicodeDecodeError):
        pass


def build_command(command: list[str], env: dict[str, str], profile: Path, bridge_path: str, downloads: tuple[Path, Path] | None = None,
                  *, original_profile: Path | None = None, profile_adapter: str | None = None,
                  keyring_socket: Path | None = None,
                  policy_mounts: list[tuple[Path, Path]] | None = None) -> tuple[list[str], dict[str, str]]:
    try:
        executable_path = str(Path(command[0]).resolve(strict=True))
    except (OSError, RuntimeError, IndexError):
        executable_path = ""
    chromium_sandbox = executable_path in _CHROMIUM_SANDBOX_PATHS
    bwrap = bwrap_executable(chromium_sandbox=chromium_sandbox)
    if not bwrap:
        raise ValueError("bubblewrap is required; direct launch is disabled")
    profile = profile.resolve()
    profile.mkdir(parents=True, exist_ok=True)
    if original_profile is not None:
        from .linux_profile_access import has_saved_chromium_secrets, session_address, shared_profile
        if profile_adapter not in {'chromium', 'firefox'}:
            raise ValueError('只有已识别的浏览器可以共用原应用资料。')
        original_profile = shared_profile(original_profile, profile)
        if profile_adapter == 'firefox' and not policy_mounts:
            raise ValueError('原 Firefox 资料启动需要隔离空间内的临时代理策略。')
        if profile_adapter == 'chromium' and keyring_socket is None:
            if session_address(env) is not None or has_saved_chromium_secrets(original_profile):
                raise ValueError('共用原浏览器资料需要受限的桌面密钥服务连接；未打开原资料。')
    elif profile_adapter is not None or keyring_socket is not None or policy_mounts:
        raise ValueError('原应用资料启动参数不完整。')
    helper = Path(__file__).with_name("namespace_helper.py").resolve()
    args = [bwrap, "--die-with-parent", "--new-session", "--unshare-user", "--unshare-net", "--unshare-pid", "--unshare-ipc", "--unshare-uts", "--cap-drop", "ALL"]
    if original_profile is not None:
        args += ['--hostname', 'rp-' + uuid.uuid4().hex[:16]]
    for system_path in ("/usr", "/bin", "/sbin", "/lib", "/lib64", "/etc"):
        if Path(system_path).exists():
            args += ["--ro-bind", system_path, system_path]
    # A private /proc prevents reaching the host's namespace descriptors.
    args += ["--proc", "/proc", "--dev", "/dev", "--tmpfs", "/tmp", "--tmpfs", "/run", "--tmpfs", "/home", "--dir", "/root"]
    args += ["--bind", str(profile), str(profile), "--ro-bind", str(helper), _HELPER_PATH, "--ro-bind", bridge_path, "/run/ruleproxy.sock"]
    if original_profile is not None:
        args += ['--bind', str(original_profile), str(original_profile)]
    if downloads is not None:
        source, target = downloads
        args += ["--bind", str(source), str(target)]
    _point_downloads(profile, downloads[1] if downloads is not None else None)
    executable = Path(command[0]).resolve()
    if not any(executable.is_relative_to(Path(p)) for p in ("/usr", "/bin", "/sbin")):
        args += ["--ro-bind", str(executable.parent), str(executable.parent)]
    python = Path(sys.executable).resolve()
    if not python.is_relative_to(Path("/usr")):
        # A virtualenv/runtime outside /usr needs its interpreter directory.
        args += ["--ro-bind", str(python.parent.parent), str(python.parent.parent)]
    if policy_mounts:
        from .linux_profile_access import policy_overlay_args
        args += policy_overlay_args(policy_mounts)
    isolated_env = {key: value for key, value in env.items() if key in {"PATH", "LANG", "LC_ALL", "LC_CTYPE", "HTTP_PROXY", "HTTPS_PROXY", "ALL_PROXY", "http_proxy", "https_proxy", "all_proxy", "NO_PROXY", "no_proxy"}}
    isolated_env.update({"HOME": str(profile), "TMPDIR": "/tmp", "XDG_CONFIG_HOME": str(profile / ".config"), "XDG_CACHE_HOME": str(profile / ".cache"), "XDG_DATA_HOME": str(profile / ".local/share"), "XDG_RUNTIME_DIR": f"/run/user/{os.getuid()}"})
    if original_profile is not None:
        isolated_env['HOME'] = str(Path.home())
        isolated_env['XDG_CONFIG_HOME'] = str(original_profile.parent)
        for key in ('XDG_CURRENT_DESKTOP', 'DESKTOP_SESSION'):
            if key in env:
                isolated_env[key] = env[key]
    args += ["--dir", isolated_env["XDG_RUNTIME_DIR"]]
    if keyring_socket is not None:
        if profile_adapter != 'chromium' or not Path(keyring_socket).is_socket():
            raise ValueError('原浏览器资料需要有效的受限密钥服务连接。')
        destination = isolated_env['XDG_RUNTIME_DIR'] + '/bus'
        args += ['--ro-bind', str(keyring_socket), destination]
        isolated_env['DBUS_SESSION_BUS_ADDRESS'] = 'unix:path=' + destination
    # Expose only the chosen GUI transport, not D-Bus, Docker or other host brokers.
    wayland = env.get("WAYLAND_DISPLAY", "")
    runtime = env.get("XDG_RUNTIME_DIR", "")
    if wayland and runtime and "/" not in wayland and (Path(runtime) / wayland).is_socket():
        args += ["--ro-bind", str(Path(runtime) / wayland), isolated_env["XDG_RUNTIME_DIR"] + "/" + wayland]
        isolated_env["WAYLAND_DISPLAY"] = wayland
    display = env.get("DISPLAY", "")
    if display.startswith(":"):
        number = display[1:].split(".")[0]
        if number.isdecimal() and (Path("/tmp/.X11-unix") / ("X" + number)).is_socket():
            args += ["--dir", "/tmp/.X11-unix", "--ro-bind", f"/tmp/.X11-unix/X{number}", f"/tmp/.X11-unix/X{number}"]
            isolated_env["DISPLAY"] = display
            auth = Path(env.get("XAUTHORITY", str(Path.home() / ".Xauthority")))
            if auth.is_file():
                private_auth = profile / ".ruleproxy-Xauthority"
                shutil.copyfile(auth, private_auth)
                private_auth.chmod(0o600)
                args += ["--ro-bind", str(private_auth), "/run/ruleproxy.Xauthority"]
                isolated_env["XAUTHORITY"] = "/run/ruleproxy.Xauthority"
    args += ["--chdir", str(profile), "--", str(python), _HELPER_PATH]
    return args, isolated_env


class _LaunchResources:
    def __init__(self, bridge, keyring=None, policy_directories=()):
        self.bridge, self.keyring = bridge, keyring
        self.policy_directories = tuple(policy_directories)
        self.lock = threading.Lock()

    def close(self):
        with self.lock:
            try:
                if self.keyring is not None:
                    self.keyring.close()
            finally:
                try:
                    self.bridge.close()
                finally:
                    for directory in self.policy_directories:
                        shutil.rmtree(directory, ignore_errors=True)


def launch(command: list[str], env: dict[str, str], profile: Path, port: int, downloads: tuple[Path, Path] | None = None,
           *, original_profile: Path | None = None, profile_adapter: str | None = None):
    proxy_bridge = ProxyBridge(port)
    resource = proxy_bridge
    process = None
    try:
        if original_profile is not None:
            from .linux_profile_access import prepare_keyring, shared_profile
            profile = Path(profile).resolve()
            original_profile = shared_profile(original_profile, profile)
            if profile_adapter not in {'chromium', 'firefox'}:
                raise ValueError('只有已识别的浏览器可以共用原应用资料。')
            profile.mkdir(mode=0o700, parents=True, exist_ok=True)
            resource = _LaunchResources(proxy_bridge)
            resource.keyring = prepare_keyring(env, original_profile, profile_adapter)
            mounts = None
            if profile_adapter == 'firefox':
                from .firefox_profile_policy import prepare_policy_mounts
                mounts = prepare_policy_mounts(Path(command[0]).resolve(strict=True), profile, port)
                resource.policy_directories = tuple({source.parent for source, _target in mounts})
            args, isolated_env = build_command(command, env, profile, proxy_bridge.path, downloads,
                original_profile=original_profile, profile_adapter=profile_adapter,
                keyring_socket=resource.keyring.path if resource.keyring else None, policy_mounts=mounts)
        else:
            if profile_adapter is not None:
                raise ValueError('原应用资料启动参数不完整。')
            args, isolated_env = build_command(command, env, profile, proxy_bridge.path, downloads)
        # Apps may print any bytes; a strict decode would stop the drain thread and let the app block on a full pipe.
        process = subprocess.Popen(args, stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE, start_new_session=True,
                                   encoding="utf-8", errors="replace")
        process.stdin.write(json.dumps({"command": command, "env": isolated_env, "port": port}))
        process.stdin.close()
        process.stdin = None
        ready, _, _ = select.select([process.stdout], [], [], 8)
        if not ready or process.stdout.readline().strip() != "RULEPROXY_NAMESPACE_READY":
            process.kill()
            _, error = process.communicate(timeout=3)
            raise ValueError("应用隔离启动失败；未回退直连。 " + error[-600:])
        # Drain output so verbose applications cannot block on a full pipe.
        log = profile / "runtime.log"
        log.touch(mode=0o600, exist_ok=True)
        log.chmod(0o600)
        def drain(output):
            with output:
                with log.open("a", encoding="utf-8") as saved:
                    for line in output:
                        saved.write(line)
                        saved.flush()
        for stream in (process.stdout, process.stderr):
            threading.Thread(target=drain, args=(stream,), daemon=True).start()
        return process, resource
    except Exception:
        if process and process.poll() is None:
            process.kill()
            process.wait(timeout=3)
        resource.close()
        raise


def _sandbox_helpers(root_pid: int) -> list[int]:
    """Find namespace helpers below a bubblewrap process; bubblewrap forks again inside."""
    children: dict[int, list[int]] = {}
    for entry in Path("/proc").iterdir():
        if not entry.name.isdigit():
            continue
        try:
            ppid = int((entry / "stat").read_text().rsplit(")", 1)[1].split()[1])
        except (OSError, IndexError, ValueError):
            continue
        children.setdefault(ppid, []).append(int(entry.name))
    helpers, pending = [], list(children.get(root_pid, []))
    while pending:
        pid = pending.pop()
        pending.extend(children.get(pid, []))
        try:
            argv = [arg for arg in (Path("/proc") / str(pid) / "cmdline").read_bytes().split(b"\0") if arg]
        except OSError:
            continue
        if len(argv) == 2 and argv[1] == _HELPER_PATH.encode():
            helpers.append(pid)
    return helpers


def stop(process: subprocess.Popen, timeout: float = 15) -> None:
    """Stop a sandboxed app so Chromium can finish a normal shutdown and flush its profile.

    bubblewrap does not forward SIGTERM, so stopping it killed the browser mid-run and
    the cookies from that session were lost. Signal the namespace helper instead: it
    relays SIGINT, which Chromium treats as a normal exit request.
    """
    if process.poll() is None:
        for pid in _sandbox_helpers(process.pid):
            try:
                os.kill(pid, signal.SIGINT)
            except ProcessLookupError:
                pass
    try:
        process.wait(timeout=timeout)
    except subprocess.TimeoutExpired:
        process.kill()
        process.wait(timeout=5)
