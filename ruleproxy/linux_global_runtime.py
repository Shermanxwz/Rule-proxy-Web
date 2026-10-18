"""Privileged, separately installed Linux global capture with an independent guard.

The desktop panel imports only Runtime.  The protected helper re-compiles all
input, runs a fixed core, and owns its nft table and policy-routing lease.  No
network command runs on import, during capability checks, or in unit tests.
"""
from __future__ import annotations

try:
    import fcntl
except ImportError:  # Keep cross-platform test discovery/imports harmless.
    fcntl = None
import hashlib
import http.client
import ctypes
import ipaddress
import json
import os
from pathlib import Path
import select
import secrets
import shutil
import signal
import socket
import stat
import struct
import subprocess
import time
import uuid

INSTALL_ROOT = Path("/usr/local/libexec/ruleproxy-web-global")
RUN_ROOT = Path("/run/ruleproxy-web-global")
HELPER = INSTALL_ROOT / "launch"
CORE = INSTALL_ROOT / "mihomo"
POLICY = Path("/usr/share/polkit-1/actions/io.ruleproxy.global.policy")
CORE_SHA256 = "7a0d59da2e678d56c899a3db996a2ad8963286c4f3634b0451435db248f13fa1"
CORE_SIZE = 62054526
DEVICE = "RuleProxyTun"
ROUTE_TABLE = 27319
RULE_PRIORITY = 27319
ROUTING_MARK = 0x52505747
ROUTING_PROTOCOL = 201
MAX_PEERS = 64
RULE_SPAN = MAX_PEERS + 5
MAX_REQUEST = 6 * 1024 * 1024
MAX_RESPONSE = 256 * 1024
TOOLS = {"nft": "/usr/sbin/nft", "ip": "/usr/sbin/ip", "pkexec": "/usr/bin/pkexec"}
_SYSTEM_ENV = {"PATH": "/usr/sbin:/usr/bin:/sbin:/bin", "LC_ALL": "C"}
# Preserve our fixed TUN IPv6 address even on an IPv4-only underlay. The pinned
# core otherwise removes it before creating the interface. Only the global
# core's validation/launch use this override; network tools retain _SYSTEM_ENV.
# https://github.com/MetaCubeX/mihomo/blob/v1.19.32/config/utils.go#L191-L209
# https://github.com/MetaCubeX/mihomo/blob/v1.19.32/config/config.go#L1587-L1591
_GLOBAL_CORE_ENV = {**_SYSTEM_ENV, "SKIP_SYSTEM_IPV6_CHECK": "true"}
LIMITATIONS = [
    "整机全局接管包括 IPv4、IPv6、TCP、UDP 与进入 TUN 的 DNS；节点自身承载和初始解析需要直接出站。",
    "本地回环、DHCP、IPv6 邻居发现，以及启用前已存在的入站连接回复是明确的直接通信例外。",
    "已有入站管理会话按精确对端地址保留；启用后新建的远程管理会话不保证可用。",
    "与现有入站对端地址相同的新出站连接会被阻断；保活例外只允许原连接回复。",
    "核心或面板故障后独立防火墙保持阻断；点击停止全局接管才恢复普通网络。",
    "全局接管不保护具有管理员网络权限的程序，也不替代其他用户配置的防火墙。",
]


class GlobalRuntimeError(RuntimeError):
    def __init__(self, code, detail):
        super().__init__(detail)
        self.code = code


def _fail(code, detail):
    raise GlobalRuntimeError(code, detail)


def _json(raw, maximum=MAX_REQUEST):
    if len(raw) > maximum:
        _fail("invalid_request", "全局控制请求超过上限。")
    def unique(pairs):
        result = {}
        for key, value in pairs:
            if key in result:
                _fail("invalid_request", "全局控制请求含重复字段。")
            result[key] = value
        return result
    try:
        value = json.loads(raw, object_pairs_hook=unique,
                           parse_constant=lambda value: _fail("invalid_request", "无效 JSON。"))
    except (ValueError, UnicodeError, RecursionError):
        _fail("invalid_request", "无效的全局控制请求。")
    if not isinstance(value, dict):
        _fail("invalid_request", "全局控制请求必须是对象。")
    return value


def _trusted(path, *, executable=False):
    """Reject symlinks and replaceable files anywhere in a privileged path."""
    path = Path(path)
    try:
        for item in (path, *path.parents):
            info = item.lstat()
            if stat.S_ISLNK(info.st_mode) or info.st_uid != 0 or info.st_mode & 0o022:
                return False
        info = path.stat()
        return stat.S_ISREG(info.st_mode) and (not executable or bool(info.st_mode & 0o111))
    except OSError:
        return False


def _identity(pid):
    try:
        root = Path("/proc") / str(pid)
        fields = (root / "stat").read_text().rpartition(")")[2].split()
        return {"uid": root.stat().st_uid, "start": fields[19]}
    except (OSError, IndexError, ValueError):
        return None


def _socket_path(uid):
    return RUN_ROOT / ("control-" + str(uid) + ".sock")


def _base_status(**changes):
    result = {"supported": True, "setup_required": False, "backend": "Mihomo TUN + nftables",
              "state": "idle", "running": False, "pid": None, "strict_isolation": False,
              "protection_active": False, "detail": "Linux 全局接管已安装，尚未启动。",
              "limitations": list(LIMITATIONS), "inbound_peer_exceptions": 0,
              "routing_owned_by_helper": True}
    result.update(changes)
    return result


class Runtime:
    def __init__(self, root=None):
        self._helper_process = None

    def _installation(self):
        required = (HELPER, CORE, INSTALL_ROOT / "entry.py",
                    INSTALL_ROOT / "ruleproxy/linux_global_runtime.py",
                    INSTALL_ROOT / "ruleproxy/config.py", INSTALL_ROOT / "ruleproxy/__init__.py",
                    INSTALL_ROOT / "vendor/yaml/__init__.py", INSTALL_ROOT / "owner.json",
                    INSTALL_ROOT / "manifest.json", POLICY)
        if not all(_trusted(path) for path in required) or not _trusted(HELPER, executable=True):
            _fail("setup_required", "尚未安装受保护的 Linux 全局组件，请运行 sh setup-linux.sh --global。")
        for name in ("pkexec", "ip", "nft"):
            if not _trusted(Path(TOOLS[name]).resolve(), executable=True):
                _fail("setup_required", "Linux 全局接管缺少受保护的 pkexec、iproute2 或 nftables。")
        try:
            owner = _json((INSTALL_ROOT / "owner.json").read_bytes(), 1024)
            if owner != {"owner_uid": os.getuid()}:
                _fail("different_installation_user", "请使用安装全局组件的桌面用户。")
        except OSError:
            _fail("setup_required", "Linux 全局组件安装记录无法读取。")

    def _require_current(self):
        try:
            manifest = _json((INSTALL_ROOT / "manifest.json").read_bytes(), 16384)
            expected = manifest.get("modules")
            if manifest.get("schema") != 1 or not isinstance(expected, dict):
                raise ValueError("invalid helper manifest")
            for name in ("__init__.py", "config.py", "linux_global_runtime.py"):
                current = Path(__file__).resolve().parent / name
                if hashlib.sha256(current.read_bytes()).hexdigest() != expected.get(name):
                    _fail("setup_required", "项目已更新，请重新运行 sh setup-linux.sh --global 更新受保护组件。")
        except (OSError, ValueError):
            _fail("setup_required", "受保护的 Linux 全局组件版本记录无效，请重新安装。")

    def _request(self, operation, **fields):
        path = _socket_path(os.getuid())
        with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as peer:
            peer.settimeout(12 if operation == "stop" else 3)
            peer.connect(str(path))
            _, uid, _ = struct.unpack("3i", peer.getsockopt(socket.SOL_SOCKET, socket.SO_PEERCRED, 12))
            if uid != 0:
                _fail("untrusted_helper", "全局控制端不属于受保护服务。")
            peer.sendall(json.dumps({"operation": operation, **fields}).encode() + b"\n")
            with peer.makefile("rb") as reader:
                response = _json(reader.readline(MAX_RESPONSE + 1), MAX_RESPONSE)
        if not response.get("ok"):
            _fail(str(response.get("code", "backend_error")), str(response.get("detail", "全局控制失败。")))
        return response["status"]

    def status(self):
        try:
            self._installation()
        except GlobalRuntimeError as error:
            return _base_status(supported=False, setup_required=True, state="setup_required",
                                code=error.code, detail=str(error))
        try:
            return self._request("status")
        except FileNotFoundError:
            if (RUN_ROOT / ("lease-" + str(os.getuid()) + ".json")).exists():
                return _base_status(state="blocked", protection_active=True,
                                    detail="上次全局会话未完成清理；点击停止以运行受保护恢复。")
            try:
                self._require_current()
            except GlobalRuntimeError as error:
                return _base_status(supported=False, setup_required=True, state="setup_required", detail=str(error))
            return _base_status()
        except (OSError, GlobalRuntimeError):
            return _base_status(state="unknown", detail="全局控制端无法响应；请点击停止恢复网络。")

    def _launch(self, payload):
        self._installation()
        if payload.get("operation") == "start":
            self._require_current()
        process = subprocess.Popen([TOOLS["pkexec"], str(HELPER)], stdin=subprocess.PIPE,
                                   stdout=subprocess.PIPE, stderr=subprocess.DEVNULL,
                                   cwd="/", env={"PATH": "/usr/sbin:/usr/bin:/sbin:/bin",
                                                **{key: os.environ[key] for key in ("DISPLAY", "XAUTHORITY", "WAYLAND_DISPLAY", "DBUS_SESSION_BUS_ADDRESS") if key in os.environ}},
                                   start_new_session=True)
        self._helper_process = process
        raw = json.dumps(payload, ensure_ascii=False, separators=(",", ":")).encode("utf-8") + b"\n"
        if len(raw) > MAX_REQUEST:
            process.terminate()
            _fail("invalid_request", "全局控制请求超过上限。")
        # The payload can exceed pipe capacity while polkit displays its prompt.
        # Bound writing as well as reading; do not block the panel indefinitely.
        deadline = time.monotonic() + 180
        os.set_blocking(process.stdin.fileno(), False)
        try:
            offset = 0
            while offset < len(raw):
                remaining = deadline - time.monotonic()
                if remaining <= 0 or not select.select([], [process.stdin], [], remaining)[1]:
                    _fail("authorization_timeout", "全局授权超时；请检查授权窗口，再查看面板状态。")
                offset += os.write(process.stdin.fileno(), raw[offset:offset + 16384])
        except (BrokenPipeError, OSError):
            _fail("authorization_failed", "全局授权已取消，或受保护 helper 无法启动。")
        finally:
            process.stdin.close()
        output = bytearray()
        try:
            while not output.endswith(b"\n"):
                remaining = deadline - time.monotonic()
                if remaining <= 0 or not select.select([process.stdout], [], [], remaining)[0]:
                    # A helper might already own the guard; never kill it here.
                    _fail("authorization_timeout", "全局授权或启动超时；请检查授权窗口，再查看面板状态。")
                chunk = os.read(process.stdout.fileno(), min(16384, MAX_RESPONSE + 1 - len(output)))
                if not chunk:
                    _fail("authorization_failed", "全局授权已取消，或受保护 helper 未能响应。")
                output.extend(chunk)
                if len(output) > MAX_RESPONSE:
                    _fail("invalid_response", "全局 helper 返回内容超过上限。")
            response = _json(output, MAX_RESPONSE)
        finally:
            process.stdout.close()
        if not response.get("ok"):
            _fail(str(response.get("code", "backend_error")), str(response.get("detail", "全局接管未能启动。")))
        return response["status"]

    def start(self, source, secret, mixed_port, controller_port, selected_node):
        _fail("global_tun_removed", "全局 TUN 已移除；全局模式改用系统代理。")

    def stop(self):
        self._installation()
        try:
            result = self._request("stop")
            if self._helper_process is not None:
                try:
                    self._helper_process.wait(timeout=2)
                except subprocess.TimeoutExpired:
                    pass
            return result
        except (FileNotFoundError, ConnectionRefusedError):
            if (RUN_ROOT / ("lease-" + str(os.getuid()) + ".json")).exists():
                return self._launch({"operation": "recover-stop"})
            return _base_status()

    def select_node(self, name):
        self._installation()
        return self._request("select_node", name=name)


def _proc_endpoint(text, version):
    address, port = text.split(":")
    raw = bytes.fromhex(address)
    if version == 4:
        raw = raw[::-1]
    else:
        raw = b"".join(raw[index:index + 4][::-1] for index in range(0, 16, 4))
    return ipaddress.ip_address(raw), int(port, 16)


def inbound_peers(proc_root=Path("/proc/net")):
    """Exact current incoming TCP peers, inferred from matching listening endpoints."""
    peers = set()
    for version, name in ((4, "tcp"), (6, "tcp6")):
        try:
            lines = (proc_root / name).read_text(encoding="ascii").splitlines()[1:]
            records = []
            for line in lines:
                fields = line.split()
                if len(fields) < 4:
                    raise ValueError("invalid TCP table")
                if fields[3] not in {"01", "0A"}:
                    continue
                records.append((_proc_endpoint(fields[1], version), _proc_endpoint(fields[2], version), fields[3]))
            listeners = [local for local, _, state in records if state == "0A"]
            for local, remote, state in records:
                if state == "01" and not remote[0].is_loopback and not remote[0].is_unspecified:
                    if any(port == local[1] and (address.is_unspecified or address == local[0]) for address, port in listeners):
                        if remote[0].is_link_local or remote[0].is_multicast:
                            _fail("remote_session_unknown", "无法安全表达当前远程管理连接，请在本地停止该连接后启用。")
                        address = getattr(remote[0], "ipv4_mapped", None) or remote[0]
                        peers.add(str(ipaddress.ip_network(str(address) + ("/32" if address.version == 4 else "/128"))))
        except (OSError, ValueError, IndexError):
            _fail("remote_session_unknown", "无法核实现有入站管理连接，尚未修改网络。")
    if len(peers) > MAX_PEERS:
        _fail("remote_session_unknown", "当前入站连接对端过多，尚未修改网络。")
    return sorted(peers)


def rule_plan(peers):
    """Return exact owned commands; this plan is also the recovery journal."""
    if not isinstance(peers, list) or len(peers) > MAX_PEERS or len(set(peers)) != len(peers):
        _fail("invalid_plan", "路由例外超过上限。")
    for peer in peers:
        network = ipaddress.ip_network(peer)
        if network.prefixlen != network.max_prefixlen:
            _fail("invalid_plan", "仅允许精确入站对端路由例外。")
    result = []
    for version in (4, 6):
        prefix = ["-" + str(version), "rule"]
        result.append(prefix + ["add", "priority", str(RULE_PRIORITY), "protocol", str(ROUTING_PROTOCOL), "fwmark", hex(ROUTING_MARK), "lookup", "main"])
        # These bypass routing only; the nft filter below independently limits
        # what may actually leave. DHCP must renew without entering the tunnel.
        source_port, destination_port = ("68", "67") if version == 4 else ("546", "547")
        result.append(prefix + ["add", "priority", str(RULE_PRIORITY + 1), "protocol", str(ROUTING_PROTOCOL), "ipproto", "udp",
                                "sport", source_port, "dport", destination_port, "lookup", "main"])
        if version == 6:
            result.append(prefix + ["add", "priority", str(RULE_PRIORITY + 2),
                                    "protocol", str(ROUTING_PROTOCOL), "ipproto", "ipv6-icmp", "lookup", "main"])
        for index, peer in enumerate(peers):
            network = ipaddress.ip_network(peer)
            if network.version == version:
                result.append(prefix + ["add", "priority", str(RULE_PRIORITY + 4 + index), "protocol", str(ROUTING_PROTOCOL), "to", str(network), "lookup", "main"])
        result.append(prefix + ["add", "priority", str(RULE_PRIORITY + RULE_SPAN), "protocol", str(ROUTING_PROTOCOL), "lookup", str(ROUTE_TABLE)])
    return result


def nft_guard(uid, lease, peers):
    if type(uid) is not int or uid < 1 or not re_full_hex(lease):
        _fail("invalid_plan", "阻断保护标识无效。")
    lines = [f'table inet ruleproxy_global_{uid} {{', f' comment "RuleProxy lease {lease}"',
             ' chain output {', '  type filter hook output priority -150; policy drop;',
             '  oifname "lo" accept', f'  meta mark {hex(ROUTING_MARK)} accept',
             f'  oifname "{DEVICE}" accept',
             '  meta nfproto ipv4 udp sport 68 udp dport 67 accept',
             '  meta nfproto ipv6 udp sport 546 udp dport 547 accept',
             '  icmpv6 type { 130, 131, 132, 133, 134, 135, 136, 143 } accept']
    for peer in peers:
        network = ipaddress.ip_network(peer)
        if network.prefixlen != network.max_prefixlen:
            _fail("invalid_plan", "仅允许精确入站对端路由例外。")
        family = "ip" if network.version == 4 else "ip6"
        lines.append(f'  {family} daddr {network} ct direction reply ct state established,related accept')
    return "\n".join([*lines, ' }', '}']) + "\n"


def re_full_hex(value):
    return isinstance(value, str) and len(value) == 32 and all(char in "0123456789abcdef" for char in value)


class System:
    def run(self, name, arguments, data=None, check=True):
        path = str(CORE) if name == "core" else str(Path(TOOLS[name]).resolve())
        if not _trusted(path, executable=True):
            _fail("unsafe_component", "受保护的全局组件所有权或权限无效。")
        result = subprocess.run([path, *arguments], input=data, stdout=subprocess.PIPE,
                                stderr=subprocess.PIPE, timeout=15, cwd="/",
                                env=dict(_GLOBAL_CORE_ENV if name == "core" else _SYSTEM_ENV))
        if check and result.returncode:
            _fail("network_command_failed", "受保护的网络操作失败；阻断保护如已建立将保持。")
        return result

    def json(self, name, arguments):
        result = self.run(name, arguments)
        try:
            value = json.loads(result.stdout)
            if not isinstance(value, list):
                raise ValueError("invalid command output")
            return value
        except ValueError:
            _fail("network_query_failed", "无法验证系统网络状态。")


def preflight(system):
    links = system.json("ip", ["-j", "link", "show"])
    if any(row.get("ifname") == DEVICE for row in links):
        _fail("network_conflict", "同名 TUN 接口已存在，未接管或删除该接口。")
    for version in (4, 6):
        rules = system.json("ip", ["-j", "-" + str(version), "rule", "show"])
        if any(RULE_PRIORITY <= int(row.get("priority", -1)) <= RULE_PRIORITY + RULE_SPAN for row in rules):
            _fail("network_conflict", "全局接管保留的策略路由优先级已被占用。")
        routes = system.json("ip", ["-j", "-" + str(version), "route", "show", "table", "all"])
        if any(str(row.get("table", "")) == str(ROUTE_TABLE) for row in routes):
            _fail("network_conflict", "全局接管保留的路由表已被占用。")
        # A custom /etc/iproute2/rt_tables alias can hide the numeric table ID
        # in "table all" JSON. Query the reserved number independently.
        reserved = system.run("ip", ["-j", "-" + str(version), "route", "show", "table", str(ROUTE_TABLE)], check=False)
        if reserved.returncode:
            if b"FIB table does not exist" not in reserved.stderr:
                _fail("network_query_failed", "无法核实保留路由表，尚未修改网络。")
        else:
            try:
                contents = json.loads(reserved.stdout)
                if not isinstance(contents, list):
                    raise ValueError("invalid route table")
            except ValueError:
                _fail("network_query_failed", "无法读取保留路由表，尚未修改网络。")
            if contents:
                _fail("network_conflict", "全局接管保留的路由表已被占用。")


class Lease:
    """Stateful root helper. All mutations below are confined to this lease."""
    def __init__(self, uid, system=None):
        self.uid, self.system = uid, system or System()
        self.lease = uuid.uuid4().hex
        self.peers = []
        self.applied = []
        self.guard = False
        self.guard_fingerprint = None
        self.core = None
        self.core_identity = None
        self.owner_pid = None
        self.owner_start = None
        self.controller_secret = None
        self.node_names = set()
        self.selected_node = None
        self.state = "idle"
        self.detail = "Linux 全局接管尚未启动。"
        self.directory = RUN_ROOT / ("state-" + str(uid))
        self.journal = RUN_ROOT / ("lease-" + str(uid) + ".json")

    def persist(self):
        value = {"schema": 1, "uid": self.uid, "lease": self.lease,
                 "peers": self.peers, "applied": self.applied, "guard": self.guard,
                 "guard_fingerprint": self.guard_fingerprint,
                 "core_pid": self.core.pid if self.core else None, "core_identity": self.core_identity}
        temporary = self.journal.with_suffix(".tmp")
        with temporary.open("w", encoding="utf-8") as output:
            os.chmod(temporary, 0o600)
            json.dump(value, output)
            output.flush(); os.fsync(output.fileno())
        temporary.replace(self.journal)

    def snapshot(self):
        alive = bool(self.core and self.core.poll() is None)
        verified = self.guard and self._guard_exists()
        return _base_status(state=self.state, running=alive and self.state == "running",
                            pid=self.core.pid if alive else None, protection_active=self.guard,
                            strict_isolation=verified, detail=self.detail,
                            inbound_peer_exceptions=len(self.peers))

    def _compile(self, payload):
        expected = {"operation", "source", "secret", "mixed_port", "controller_port", "selected_node", "owner_pid", "owner_start"}
        if set(payload) != expected or payload.get("operation") != "start":
            _fail("invalid_request", "全局启动字段无效。")
        pid, started = payload["owner_pid"], payload["owner_start"]
        identity = _identity(pid) if type(pid) is int and pid > 0 else None
        if not identity or identity != {"uid": self.uid, "start": started}:
            _fail("invalid_owner", "全局启动者身份已变化。")
        from .config import compile_config
        self.controller_secret = secrets.token_urlsafe(48)
        try:
            compiled = compile_config(payload["source"], secret=self.controller_secret,
                                      mixed_port=payload["mixed_port"], controller_port=payload["controller_port"],
                                      selected_node=payload["selected_node"], allow_udp=True,
                                      capture_mode="global")
        except (TypeError, ValueError, RecursionError):
            _fail("invalid_config", "配置未通过受保护的全局编译校验。")
        config = compiled.config
        # A root core's general controller is a privilege boundary. Keep it in
        # the root-only runtime directory, with a root-only secret; the desktop
        # can request only the closed node-selection operation below.
        config["external-controller"] = ""
        config["external-controller-unix"] = str(self.directory / "controller.sock")
        config["routing-mark"] = ROUTING_MARK
        config["tun"].update({"device": DEVICE, "auto-route": False, "auto-redirect": False})
        self.owner_pid, self.owner_start = pid, started
        self.node_names = {item["name"] for item in compiled.nodes}
        self.selected_node = compiled.selected_node
        return config

    def _controller(self, method, path, data=None):
        if not self.core or self.core.poll() is not None:
            _fail("core_unavailable", "全局核心未运行。")
        peer = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        peer.settimeout(2)
        try:
            peer.connect(str(self.directory / "controller.sock"))
            pid, uid, _ = struct.unpack("3i", peer.getsockopt(socket.SOL_SOCKET, socket.SO_PEERCRED, 12))
            if uid != 0 or pid != self.core.pid:
                _fail("untrusted_controller", "全局控制器进程身份不匹配。")
            connection = http.client.HTTPConnection("localhost", timeout=2)
            connection.sock = peer
            body = json.dumps(data).encode() if data is not None else None
            connection.request(method, path, body, {"Authorization": "Bearer " + self.controller_secret,
                                                     "Content-Type": "application/json"})
            response = connection.getresponse()
            raw = response.read(MAX_RESPONSE + 1)
            if not 200 <= response.status < 300 or len(raw) > MAX_RESPONSE:
                _fail("controller_failed", "全局核心没有确认该操作。")
            return json.loads(raw) if raw else None
        finally:
            peer.close()

    def select_node(self, name):
        if self.state != "running" or not isinstance(name, str) or name not in self.node_names:
            _fail("invalid_node", "请选择已编译全局配置中的有效节点。")
        self._controller("PUT", "/proxies/RuleProxySelected", {"name": name})
        self.selected_node = name
        return self.snapshot()

    def _guard_text_fingerprint(self):
        result = self.system.run("nft", ["-s", "list", "table", "inet", "ruleproxy_global_" + str(self.uid)], check=False)
        if result.returncode:
            return None
        return hashlib.sha256(result.stdout).hexdigest()

    def _guard_exists(self, check_rules=True):
        result = self.system.run("nft", ["-j", "list", "table", "inet", "ruleproxy_global_" + str(self.uid)], check=False)
        if result.returncode:
            return False
        try:
            tables = [item["table"] for item in json.loads(result.stdout).get("nftables", []) if "table" in item]
            owned = len(tables) == 1 and tables[0].get("comment") == "RuleProxy lease " + self.lease
            return owned and (not check_rules or not self.guard_fingerprint or
                              self._guard_text_fingerprint() == self.guard_fingerprint)
        except (ValueError, TypeError, KeyError):
            return False

    def start(self, payload):
        if self.journal.exists():
            _fail("stale_lease", "上次全局会话需要先点击停止恢复，未修改网络。")
        config = self._compile(payload)
        if CORE.stat().st_size != CORE_SIZE or hashlib.sha256(CORE.read_bytes()).hexdigest() != CORE_SHA256:
            _fail("unsafe_component", "固定 Mihomo 校验失败，请重新安装全局组件。")
        preflight(self.system)
        self.peers = inbound_peers()
        existing = self.system.run("nft", ["list", "table", "inet", "ruleproxy_global_" + str(self.uid)], check=False)
        if existing.returncode == 0:
            _fail("network_conflict", "全局阻断表已存在，未接管其他会话。")
        self.directory.mkdir(mode=0o700)
        import yaml
        config_path = self.directory / "config.yaml"
        config_path.write_text(yaml.safe_dump(config, allow_unicode=True, sort_keys=False), encoding="utf-8")
        config_path.chmod(0o600)
        self.system.run("core", ["-t", "-d", str(self.directory), "-f", str(config_path)])
        guard_text = nft_guard(self.uid, self.lease, self.peers).encode()
        self.system.run("nft", ["--check", "--file", "-"], data=guard_text)
        self.guard = True  # conservative until an attempted nft transaction is resolved
        self.persist()
        try:
            self.system.run("nft", ["--file", "-"], data=guard_text)
            self.guard_fingerprint = self._guard_text_fingerprint()
            if self.guard_fingerprint is None:
                _fail("blocked", "无法核实独立阻断状态，请点击停止恢复。")
        except BaseException:
            # A timeout can occur after nft committed. Keep the recovery journal
            # unless absence is positively established by the authenticated helper.
            self.state = "blocked"
            self.persist()
            raise
        self.state, self.detail = "blocked", "正在建立双栈全局路由；独立阻断已启用。"
        self.persist()
        try:
            log = (self.directory / "core.log").open("wb")
            parent_pid = os.getpid()
            def parent_death_signal():
                # The helper is single-threaded. Kill the fixed core even if
                # its privileged owner is SIGKILLed; nft remains independent.
                libc = ctypes.CDLL(None, use_errno=True)
                if libc.prctl(1, signal.SIGKILL, 0, 0, 0) != 0 or os.getppid() != parent_pid:
                    os._exit(126)
            try:
                self.core = subprocess.Popen([str(CORE), "-d", str(self.directory), "-f", str(config_path)],
                                             stdin=subprocess.DEVNULL, stdout=log, stderr=log,
                                             cwd="/", env=dict(_GLOBAL_CORE_ENV),
                                             start_new_session=True, preexec_fn=parent_death_signal)
            finally:
                log.close()
            self.core_identity = _identity(self.core.pid)
            self.persist()
            deadline = time.monotonic() + 10
            while time.monotonic() < deadline:
                if self.core.poll() is not None:
                    _fail("blocked", "Mihomo 未能启动；独立阻断仍在，点击停止可恢复网络。")
                links = self.system.json("ip", ["-j", "address", "show"])
                target = next((row for row in links if row.get("ifname") == DEVICE), None)
                families = {item.get("family") for item in (target or {}).get("addr_info", [])}
                expected_v6 = {str(ipaddress.ip_interface(item).ip) for item in config["tun"].get("inet6-address", [])}
                actual_v6 = {item.get("local") for item in (target or {}).get("addr_info", []) if item.get("family") == "inet6"}
                if target and "UP" in target.get("flags", []) and {"inet", "inet6"} <= families and expected_v6 and expected_v6 <= actual_v6:
                    try:
                        self._controller("GET", "/version")
                        break
                    except (OSError, http.client.HTTPException):
                        pass
                time.sleep(0.1)
            else:
                _fail("blocked", "TUN 双栈接口未就绪；独立阻断仍在，点击停止可恢复网络。")
            # Record before execution: a crash between command and journal write
            # must never leave an unrecorded route or rule.
            commands = []
            for version in (4, 6):
                commands.append(["-" + str(version), "route", "add", "table", str(ROUTE_TABLE),
                                 "default", "dev", DEVICE, "metric", "8879", "proto", str(ROUTING_PROTOCOL)])
            commands.extend(rule_plan(self.peers))
            for command in commands:
                self.applied.append(command); self.persist()
                try:
                    self.system.run("ip", command)
                except (GlobalRuntimeError, OSError):
                    # A known failed netlink command did not create a resource;
                    # do not delete a concurrently added administrator resource.
                    self.applied.pop(); self.persist()
                    raise
            self.state, self.detail = "running", "Linux 整机双栈接管与独立故障阻断已启用。"
            self.persist()
            return self.snapshot()
        except BaseException:
            self.state, self.detail = "blocked", "全局核心或路由启动失败；独立阻断仍在，点击停止可恢复网络。"
            self._stop_core()
            self.persist()
            raise

    def _stop_core(self):
        if self.core and self.core.poll() is None:
            self.core.terminate()
            try:
                self.core.wait(timeout=5)
            except subprocess.TimeoutExpired:
                self.core.kill(); self.core.wait(timeout=3)

    def watch(self):
        if self.state != "running":
            return
        owner = _identity(self.owner_pid)
        if self.core.poll() is not None or owner != {"uid": self.uid, "start": self.owner_start}:
            self._stop_core()
            self.state, self.detail = "blocked", "核心或面板已退出；独立阻断保持，点击停止恢复网络。"
        elif not self._guard_exists():
            self._stop_core()
            self.state, self.detail = "failed", "独立阻断规则被外部移除，已停止全局核心；请停止并检查其他网络工具。"

    def stop(self):
        self._stop_core()
        missing = (b"No such process", b"No such file", b"Cannot find device", b"FIB table does not exist")
        for command in reversed(self.applied):
            deletion = list(command); deletion[2] = "del"
            result = self.system.run("ip", deletion, check=False)
            if result.returncode and not any(item in result.stderr for item in missing):
                _fail("cleanup_failed", "自有路由清理失败，阻断保护保持；请再次点击停止。")
        self.applied = []; self.persist()
        if self.guard:
            if not self._guard_exists(check_rules=False):
                tables = self.system.run("nft", ["-j", "list", "tables"])
                try:
                    records = json.loads(tables.stdout).get("nftables", [])
                    exists = any(row.get("table", {}).get("family") == "inet" and
                                 row.get("table", {}).get("name") == "ruleproxy_global_" + str(self.uid)
                                 for row in records)
                except (ValueError, TypeError, AttributeError):
                    _fail("cleanup_failed", "无法验证阻断表清理状态，恢复记录保留。")
                if exists:
                    _fail("cleanup_failed", "阻断表身份发生变化，未删除其他程序的规则。")
            else:
                self.system.run("nft", ["delete", "table", "inet", "ruleproxy_global_" + str(self.uid)])
            self.guard = False
        self.state, self.detail = "idle", "全局接管已停止，普通网络已恢复。"
        self.journal.unlink(missing_ok=True)
        if self.directory.exists():
            shutil.rmtree(self.directory)
        return self.snapshot()


def _recover(lease):
    """Recover only a root-authored journal and the exact recorded lease resources."""
    if not lease.journal.exists():
        return lease.snapshot()
    if not _trusted(lease.journal):
        _fail("cleanup_failed", "全局恢复记录权限无效。")
    data = _json(lease.journal.read_bytes(), MAX_RESPONSE)
    if data.get("schema") != 1 or data.get("uid") != lease.uid or not re_full_hex(data.get("lease")):
        _fail("cleanup_failed", "全局恢复记录无效。")
    peers = data.get("peers")
    if not isinstance(peers, list) or len(peers) > MAX_PEERS:
        _fail("cleanup_failed", "全局恢复路由例外无效。")
    planned = [["-" + str(version), "route", "add", "table", str(ROUTE_TABLE), "default", "dev", DEVICE,
                "metric", "8879", "proto", str(ROUTING_PROTOCOL)] for version in (4, 6)] + rule_plan(peers)
    applied = data.get("applied")
    if not isinstance(applied, list) or applied != planned[:len(applied)]:
        _fail("cleanup_failed", "全局恢复操作记录无效。")
    lease.lease, lease.peers, lease.applied = data["lease"], peers, applied
    lease.guard = bool(data.get("guard"))
    lease.guard_fingerprint = data.get("guard_fingerprint")
    # A crash may occur immediately after nft commits but before guard=true is
    # journalled. The lease comment is the recovery authority, not that boolean.
    lease.guard = lease._guard_exists(check_rules=False) or lease.guard
    pid, identity = data.get("core_pid"), data.get("core_identity")
    if type(pid) is int and pid > 0 and identity and _identity(pid) == identity:
        try:
            if Path("/proc", str(pid), "exe").resolve() != CORE:
                _fail("cleanup_failed", "恢复记录中的核心进程身份发生变化。")
            if not hasattr(os, "pidfd_open") or not hasattr(signal, "pidfd_send_signal"):
                _fail("cleanup_failed", "本机缺少安全进程恢复支持，请先由管理员停止固定核心。")
            descriptor = os.pidfd_open(pid)
            try:
                if _identity(pid) != identity:
                    _fail("cleanup_failed", "恢复中的核心进程身份已变化。")
                signal.pidfd_send_signal(descriptor, signal.SIGTERM)
                if not select.select([descriptor], [], [], 5)[0]:
                    signal.pidfd_send_signal(descriptor, signal.SIGKILL)
                    if not select.select([descriptor], [], [], 3)[0]:
                        _fail("cleanup_failed", "固定核心未能结束，阻断保护保持。")
            finally:
                os.close(descriptor)
        except ProcessLookupError:
            pass
    return lease.stop()


def _root_directory(path, mode=0o755):
    if not path.exists():
        path.mkdir(mode=mode)
        path.chmod(mode)
    info = path.lstat()
    if not stat.S_ISDIR(info.st_mode) or info.st_uid != 0 or info.st_mode & 0o022:
        _fail("unsafe_component", "受保护运行目录权限无效。")


def helper_main():
    """Fixed pkexec entry; never execute this from the desktop panel directly."""
    import sys
    answer = None
    lock = None
    server = None
    lease = None
    sock_path = None
    initial_answered = False
    try:
        if os.geteuid() != 0:
            _fail("permission_required", "全局 helper 必须通过安装的授权入口启动。")
        owner = _json((INSTALL_ROOT / "owner.json").read_bytes(), 1024)
        uid = owner.get("owner_uid")
        if type(uid) is not int or uid < 1 or str(uid) != os.environ.get("PKEXEC_UID"):
            _fail("invalid_owner", "全局授权账户不匹配。")
        _root_directory(RUN_ROOT)
        lock = (RUN_ROOT / "global.lock").open("a+b")
        os.chmod(RUN_ROOT / "global.lock", 0o600)
        try:
            fcntl.flock(lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
        except BlockingIOError:
            _fail("global_busy", "已有用户正在管理整机全局接管。")
        raw = sys.stdin.buffer.readline(MAX_REQUEST + 1)
        if not raw.endswith(b"\n"):
            _fail("invalid_request", "全局请求未完整传送。")
        payload = _json(raw)
        # The TUN start was removed; only recovery of older sessions remains.
        if payload.get("operation") != "recover-stop":
            _fail("global_tun_removed", "全局 TUN 已移除；全局模式改用系统代理。")
        lease = Lease(uid)
        if payload["operation"] == "recover-stop":
            if set(payload) != {"operation"}:
                _fail("invalid_request", "恢复请求字段无效。")
            answer = {"ok": True, "status": _recover(lease)}
            return
        sock_path = _socket_path(uid)
        if sock_path.exists():
            if not stat.S_ISSOCK(sock_path.lstat().st_mode):
                _fail("unsafe_component", "全局控制套接字位置已被占用。")
            sock_path.unlink()  # global exclusive lock proves no live helper owns it
        server = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        server.bind(str(sock_path)); os.chown(sock_path, uid, -1); os.chmod(sock_path, 0o600)
        server.listen(4); server.settimeout(0.5)
        try:
            status = lease.start(payload)
            answer = {"ok": True, "status": status}
        except Exception as error:
            answer = {"ok": False, "code": getattr(error, "code", "start_failed"),
                      "detail": str(error) if isinstance(error, GlobalRuntimeError) else "全局启动失败。"}
            if not lease.guard:
                if lease.journal.exists(): lease.journal.unlink()
                if lease.directory.exists(): shutil.rmtree(lease.directory)
                return
            answer["code"] = "blocked"
            answer["detail"] = "全局启动未完成；独立阻断保持，点击停止恢复网络。"
        try:
            print(json.dumps(answer, ensure_ascii=True), flush=True)
        except BrokenPipeError:
            # The initiating panel can disappear while polkit is showing its
            # prompt. Keep the owner watcher/guard alive until explicit stop.
            pass
        initial_answered = True
        while True:
            lease.watch()
            try:
                peer, _ = server.accept()
            except socket.timeout:
                continue
            stop = False
            with peer:
                peer.settimeout(3)
                try:
                    _, peer_uid, _ = struct.unpack("3i", peer.getsockopt(socket.SOL_SOCKET, socket.SO_PEERCRED, 12))
                    if peer_uid != uid:
                        _fail("access_denied", "全局控制账户不匹配。")
                    with peer.makefile("rb") as reader:
                        request = _json(reader.readline(4097), 4096)
                    operation = request.get("operation")
                    expected = {"operation", "name"} if operation == "select_node" else {"operation"}
                    if set(request) != expected or operation not in {"status", "stop", "select_node"}:
                        _fail("invalid_request", "全局控制操作无效。")
                    if operation == "stop":
                        status = lease.stop(); stop = True
                    elif operation == "select_node":
                        status = lease.select_node(request["name"])
                    else:
                        status = lease.snapshot()
                    reply = {"ok": True, "status": status}
                except Exception as error:
                    reply = {"ok": False, "code": getattr(error, "code", "backend_error"),
                             "detail": str(error) if isinstance(error, GlobalRuntimeError) else "全局控制未完成。"}
                try:
                    peer.sendall(json.dumps(reply, ensure_ascii=True).encode() + b"\n")
                except OSError:
                    pass
            if stop:
                break
    except Exception as error:
        answer = {"ok": False, "code": getattr(error, "code", "helper_failed"),
                  "detail": str(error) if isinstance(error, GlobalRuntimeError) else "受保护的全局 helper 未能启动。"}
    finally:
        if not initial_answered and answer is not None:
            print(json.dumps(answer, ensure_ascii=True), flush=True)
        if server is not None: server.close()
        if sock_path is not None and sock_path.exists(): sock_path.unlink()
        if lock is not None: lock.close()
