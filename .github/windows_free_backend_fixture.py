"""Disposable fixed-byte controls shared by the two free Windows backend trials.

Only local synthetic HTTP/SOCKS data and a separately owned Mihomo are used.
Socket return values are observations: UDP denial and DNS privacy require NIC
evidence. This helper neither installs components nor grants product acceptance.
"""
from __future__ import annotations

import argparse
import ipaddress
import json
import os
from pathlib import Path
import secrets
import socket
import struct
import subprocess
import sys
import threading
import time
from urllib.parse import parse_qs, urlsplit
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer


def write_json(path, value):
    path = Path(path)
    path.parent.mkdir(parents=True, exist_ok=True)
    temporary = path.with_suffix(path.suffix + ".tmp")
    temporary.write_text(json.dumps(value, ensure_ascii=True, indent=2) + "\n", encoding="ascii")
    os.replace(temporary, path)


def read_exact(connection, length):
    result = b""
    while len(result) < length:
        chunk = connection.recv(length - len(result))
        if not chunk:
            raise EOFError("fixed control stream closed")
        result += chunk
    return result


def error_facts(exc):
    value = {"error_type": type(exc).__name__}
    for name in ("errno", "winerror"):
        number = getattr(exc, name, None)
        if type(number) is int:
            value[name] = number
    return value


def unused_port():
    with socket.socket() as connection:
        connection.bind(("127.0.0.1", 0))
        return connection.getsockname()[1]


class Fixture:
    def __init__(self, mihomo_path: Path, directory: Path):
        self.mihomo_path = Path(mihomo_path).resolve()
        self.directory = Path(directory).resolve()
        self.directory.mkdir(parents=True, exist_ok=True)
        self.lock = threading.Lock()
        self.stop = threading.Event()
        self.process = None
        self.log = None
        self.threads = []
        self.listeners = []
        self.connections = set()
        self.counts = dict(proxy_requests=0, origin_requests=0, direct_connections=0,
                           udp4_received=0, udp6_received=0, udp4_by_role={}, udp6_by_role={}, errors=[],
                           gui_first_page_requests=0, gui_second_page_requests=0,
                           gui_first_beacon_requests=0, gui_second_beacon_requests=0,
                           gui_first_cookie_valid=0, gui_second_cookie_valid=0)
        self.spec = {"schema_version": 1, "nonce": secrets.token_hex(16),
                     "proxy_host": "127.0.0.1", "origin_host": "ruleproxy-fixture.invalid",
                     "http_origin_host": "127.0.0.1", "blocked_tcp_host": "127.0.0.1",
                     "udp4_host": "127.0.0.1", "udp6_host": "::1",
                     "public_udp4_host": "198.51.100.17", "public_udp6_host": "2001:db8::17",
                     "public_udp_port": 39017}
        self.http = None

    def _thread(self, function, *args):
        thread = threading.Thread(target=function, args=args, daemon=True)
        self.threads.append(thread)
        thread.start()

    def _increment(self, key):
        with self.lock:
            self.counts[key] += 1

    def gui_response(self, request_path, cookie_header):
        """Return one bounded GUI fixture response, or None for other paths."""
        parsed = urlsplit(request_path)
        nonce = self.spec["nonce"]
        prefix = f"/gui/{nonce}/"
        expected_cookie = f"RuleProxyGuiSession={nonce}"
        if parsed.path in (prefix + "first", prefix + "second"):
            stage = parsed.path[len(prefix):]
            key = "gui_first_page_requests" if stage == "first" else "gui_second_page_requests"
            with self.lock:
                self.counts["origin_requests"] += 1
                self.counts[key] += 1
            title = "RuleProxy GUI FIRST" if stage == "first" else "RuleProxy GUI SECOND"
            beacon = prefix + "beacon?stage=" + stage
            script = ("document.title=" + json.dumps(title) + ";"
                      "fetch(" + json.dumps(beacon) + ",{credentials:'same-origin',cache:'no-store'})"
                      ".then(r=>r.text()).then(t=>document.body.dataset.beacon=t);")
            content = ("<!doctype html><html><head><title>loading</title></head>"
                       "<body id=proof><script>" + script + "</script></body></html>").encode("ascii")
            headers = {"Content-Type": "text/html; charset=ascii", "Cache-Control": "no-store"}
            if stage == "first":
                headers["Set-Cookie"] = (expected_cookie + "; Max-Age=86400; HttpOnly; "
                                         "SameSite=Lax; Path=" + prefix)
            return 200, headers, content
        if parsed.path == prefix + "beacon":
            stage_values = parse_qs(parsed.query).get("stage", [])
            if len(stage_values) != 1 or stage_values[0] not in ("first", "second"):
                return 400, {"Content-Type": "text/plain"}, b"invalid"
            stage = stage_values[0]
            valid_cookie = type(cookie_header) is str and expected_cookie in [
                value.strip() for value in cookie_header.split(";")]
            with self.lock:
                self.counts["origin_requests"] += 1
                self.counts["gui_" + stage + "_beacon_requests"] += 1
                if valid_cookie:
                    self.counts["gui_" + stage + "_cookie_valid"] += 1
            return 200, {"Content-Type": "text/plain", "Cache-Control": "no-store"}, b"ok"
        return None

    def gui_evidence(self):
        counts = self.snapshot()
        return {
            "first_beacon_observed": counts["gui_first_beacon_requests"] > 0,
            "first_cookie_seen": counts["gui_first_cookie_valid"] > 0,
            "second_beacon_observed": counts["gui_second_beacon_requests"] > 0,
            "second_cookie_valid": counts["gui_second_cookie_valid"] > 0,
            "cookie_max_age_seconds": 86400,
        }

    def _listen(self, family=socket.AF_INET, kind=socket.SOCK_STREAM):
        listener = socket.socket(family, kind)
        if family == socket.AF_INET6:
            listener.setsockopt(socket.IPPROTO_IPV6, socket.IPV6_V6ONLY, 1)
        listener.bind(("::1" if family == socket.AF_INET6 else "127.0.0.1", 0))
        listener.settimeout(.2)
        if kind == socket.SOCK_STREAM:
            listener.listen(16)
        self.listeners.append(listener)
        return listener

    def __enter__(self):
        try:
            return self.start()
        except BaseException:
            self.close()
            raise

    def __exit__(self, *ignored):
        self.close()

    def start(self):
        fixture = self

        class Handler(BaseHTTPRequestHandler):
            def setup(self):
                self.request.settimeout(2)
                super().setup()

            def do_GET(self):
                if self.path.split("?", 1)[0] != "/" + fixture.spec["nonce"]:
                    gui = fixture.gui_response(self.path, self.headers.get("Cookie"))
                    if gui is None:
                        self.send_error(404)
                        return
                    status, headers, content = gui
                    self.send_response(status)
                    for name, value in headers.items():
                        self.send_header(name, value)
                    self.send_header("Content-Length", str(len(content)))
                    self.end_headers()
                    self.wfile.write(content)
                    return
                fixture._increment("origin_requests")
                content = ("<!doctype html><title>RuleProxy free backend control</title>"
                           "<body id=proof>" + fixture.spec["nonce"] + "</body>").encode("ascii")
                self.send_response(200)
                self.send_header("Content-Length", str(len(content)))
                self.send_header("Content-Type", "text/html; charset=ascii")
                self.end_headers()
                self.wfile.write(content)

            def log_message(self, *args):
                pass

        self.http = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
        self.http.daemon_threads = True
        self._thread(self.http.serve_forever)
        port = self.http.server_address[1]
        self.spec.update(origin_port=port, http_origin_port=port,
                         origin_url=f"http://ruleproxy-fixture.invalid:{port}/{self.spec['nonce']}")
        upstream = self._listen()
        self._thread(self._accept, upstream, self._socks)
        direct = self._listen()
        self.spec["blocked_tcp_port"] = direct.getsockname()[1]
        self._thread(self._accept, direct, self._direct)
        udp4 = self._listen(kind=socket.SOCK_DGRAM)
        self.spec["udp4_port"] = udp4.getsockname()[1]
        self._thread(self._udp, udp4, "udp4")
        try:
            udp6 = self._listen(socket.AF_INET6, socket.SOCK_DGRAM)
        except OSError:
            self.spec["udp6_port"] = None
        else:
            self.spec["udp6_port"] = udp6.getsockname()[1]
            self._thread(self._udp, udp6, "udp6")
        self.spec["proxy_port"] = unused_port()
        controller_port = unused_port()
        while controller_port == self.spec["proxy_port"]:
            controller_port = unused_port()
        config = {"mixed-port": self.spec["proxy_port"], "bind-address": "127.0.0.1",
                  "allow-lan": False, "mode": "rule", "log-level": "warning", "ipv6": True,
                  "external-controller": f"127.0.0.1:{controller_port}", "secret": self.spec["nonce"],
                  "proxies": [{"name": "FixedFixture", "type": "socks5", "server": "127.0.0.1",
                               "port": upstream.getsockname()[1], "udp": False}],
                  "rules": ["MATCH,FixedFixture"]}
        path = self.directory / "mihomo-fixture.json"
        write_json(path, config)
        self.log = (self.directory / "mihomo.log").open("wb")
        self.process = subprocess.Popen([str(self.mihomo_path), "-d", str(self.directory), "-f", str(path)],
                                        stdin=subprocess.DEVNULL, stdout=self.log, stderr=subprocess.STDOUT)
        deadline = time.monotonic() + 15
        while time.monotonic() < deadline:
            if self.process.poll() is not None:
                raise RuntimeError("owned Mihomo exited before control readiness")
            # A listening port alone does not prove the core and its upstream
            # are ready. Verify the exact HTTP and SOCKS fixture before actors.
            if http_probe(self.spec).get("ok") and http_probe(self.spec, socks=True).get("ok"):
                self.readiness = {"http": True, "socks": True, "snapshot": self.snapshot()}
                write_json(self.directory / "readiness.json", self.readiness)
                return self
            time.sleep(.1)
        raise TimeoutError("owned Mihomo readiness timeout")

    def _accept(self, listener, handler):
        while not self.stop.is_set():
            try:
                connection, _ = listener.accept()
            except socket.timeout:
                continue
            except OSError:
                return
            connection.settimeout(5)
            with self.lock:
                self.connections.add(connection)
            self._thread(self._handle, handler, connection)

    def _handle(self, handler, connection):
        try:
            handler(connection)
        except (OSError, EOFError, ValueError) as exc:
            if not self.stop.is_set():
                with self.lock:
                    if len(self.counts["errors"]) < 32:
                        self.counts["errors"].append(type(exc).__name__)
        finally:
            with self.lock:
                self.connections.discard(connection)
            connection.close()

    def _direct(self, connection):
        self._increment("direct_connections")
        connection.recv(256)
        connection.sendall(b"DIRECT-CONTROL")

    def _socks(self, connection):
        import select
        greeting = read_exact(connection, 2)
        if greeting[0] != 5 or not 1 <= greeting[1] <= 16:
            raise ValueError("unexpected SOCKS greeting")
        if 0 not in read_exact(connection, greeting[1]):
            raise ValueError("unsupported SOCKS authentication")
        connection.sendall(b"\x05\x00")
        request = read_exact(connection, 4)
        if request[:3] != b"\x05\x01\x00":
            raise ValueError("control only permits SOCKS CONNECT")
        if request[3] == 3:
            host = read_exact(connection, read_exact(connection, 1)[0]).decode("ascii")
        elif request[3] == 1:
            host = socket.inet_ntop(socket.AF_INET, read_exact(connection, 4))
        elif request[3] == 4:
            host = socket.inet_ntop(socket.AF_INET6, read_exact(connection, 16))
        else:
            raise ValueError("unsupported SOCKS address")
        port = struct.unpack("!H", read_exact(connection, 2))[0]
        if host not in (self.spec["origin_host"], "127.0.0.1", "::1") or port != self.spec["origin_port"]:
            connection.sendall(b"\x05\x02\x00\x01" + b"\0" * 6)
            return
        self._increment("proxy_requests")
        with socket.create_connection(("127.0.0.1", self.spec["origin_port"]), timeout=3) as peer:
            peer.settimeout(3)
            connection.sendall(b"\x05\x00\x00\x01\x7f\0\0\x01\0\0")
            deadline = time.monotonic() + 15
            while not self.stop.is_set() and time.monotonic() < deadline:
                ready, _, _ = select.select((connection, peer), [], [], .2)
                for source in ready:
                    chunk = source.recv(16384)
                    if not chunk:
                        return
                    (peer if source is connection else connection).sendall(chunk)

    def _udp(self, listener, label):
        prefix = ("RPWFREE:" + self.spec["nonce"] + ":").encode("ascii")
        while not self.stop.is_set():
            try:
                payload, _ = listener.recvfrom(4096)
            except socket.timeout:
                continue
            except OSError:
                return
            if payload.startswith(prefix):
                role = payload[len(prefix):].decode("ascii", errors="replace")[:32]
                with self.lock:
                    self.counts[label + "_received"] += 1
                    roles = self.counts[label + "_by_role"]
                    roles[role] = roles.get(role, 0) + 1

    def write_spec(self):
        path = self.directory / "fixture-spec.json"
        write_json(path, self.spec)
        return path

    def snapshot(self):
        with self.lock:
            return json.loads(json.dumps(self.counts))

    def stop_proxy(self):
        if self.process is None:
            return {"owned_process_started": False, "exited": False}
        if self.process.poll() is None:
            self.process.terminate()
            try:
                self.process.wait(timeout=5)
            except subprocess.TimeoutExpired:
                self.process.kill()
                self.process.wait(timeout=5)
        return {"owned_process_started": True, "exited": self.process.poll() is not None,
                "exit_code": self.process.returncode}

    def close(self):
        self.stop_proxy()
        self.stop.set()
        for listener in self.listeners:
            listener.close()
        with self.lock:
            connections = tuple(self.connections)
        for connection in connections:
            try:
                connection.shutdown(socket.SHUT_RDWR)
            except OSError:
                pass
            connection.close()
        if self.http is not None:
            self.http.shutdown()
            self.http.server_close()
        deadline = time.monotonic() + 5
        for thread in tuple(self.threads):
            thread.join(timeout=max(0, deadline - time.monotonic()))
        if self.log is not None:
            self.log.close()


def http_probe(spec, socks=False):
    try:
        with socket.create_connection((spec["proxy_host"], spec["proxy_port"]), timeout=3) as connection:
            connection.settimeout(3)
            if socks:
                connection.sendall(b"\x05\x01\x00")
                if read_exact(connection, 2) != b"\x05\x00":
                    raise ValueError("SOCKS negotiation rejected")
                host = spec["origin_host"].encode("ascii")
                connection.sendall(b"\x05\x01\x00\x03" + bytes([len(host)]) + host + struct.pack("!H", spec["origin_port"]))
                response = read_exact(connection, 4)
                if response[:3] != b"\x05\x00\x00":
                    raise ValueError("SOCKS CONNECT rejected")
                lengths = {1: 4, 4: 16}
                length = read_exact(connection, 1)[0] if response[3] == 3 else lengths[response[3]]
                read_exact(connection, length + 2)
                target = "/" + spec["nonce"]
            else:
                target = spec["origin_url"]
            request = f"GET {target} HTTP/1.1\r\nHost: {spec['origin_host']}:{spec['origin_port']}\r\nConnection: close\r\n\r\n"
            connection.sendall(request.encode("ascii"))
            content = b""
            while len(content) < 65536:
                chunk = connection.recv(4096)
                if not chunk:
                    break
                content += chunk
            return {"ok": b" 200 " in content.split(b"\r\n", 1)[0] and spec["nonce"].encode() in content}
    except (OSError, EOFError, ValueError, KeyError) as exc:
        return {"ok": False, **error_facts(exc)}


def direct_probe(spec):
    try:
        with socket.create_connection((spec["blocked_tcp_host"], spec["blocked_tcp_port"]), timeout=2) as connection:
            connection.settimeout(2)
            connection.sendall(b"fixed-direct-control")
            return {"connected": True, "fixed_response": connection.recv(32) == b"DIRECT-CONTROL"}
    except OSError as exc:
        return {"connected": False, **error_facts(exc)}


def udp_probe(spec, label, role):
    family = socket.AF_INET6 if label.endswith("6") else socket.AF_INET
    family_name = "ipv6" if family == socket.AF_INET6 else "ipv4"
    port = spec["public_udp_port"] if label.startswith("public_") else spec[label + "_port"]
    destination = spec[label + "_host"]
    fields = {"family": family_name, "dest_ip": destination, "dest_port": port,
              "source_ip": None, "source_ip_observed": False, "payload_hex": None,
              "metadata_complete": False, "denial_proven": False, "timeout_ms": 2000}
    if port is None:
        return {"attempted": False, "send_ok": False, "reason": "outside_ipv6_fixture_unavailable",
                **fields}
    payload = ("RPWFREE:" + spec["nonce"] + ":" + role).encode("ascii")
    try:
        with socket.socket(family, socket.SOCK_DGRAM) as connection:
            connection.settimeout(2)
            address = (destination, port, 0, 0) if family == socket.AF_INET6 else (destination, port)
            connection.connect(address)
            source_ip = connection.getsockname()[0]
            try:
                parsed_source = ipaddress.ip_address(source_ip.split("%", 1)[0])
                if not parsed_source.is_unspecified:
                    fields["source_ip"] = source_ip
                    fields["source_ip_observed"] = True
            except ValueError:
                pass
            # Keep the original fixed datagram and sendto call. UDP connect
            # only selects the route/source address for the observation.
            fields["payload_hex"] = payload.hex()
            count = connection.sendto(payload, address)
            fields["metadata_complete"] = fields["source_ip_observed"]
            return {"attempted": True, "send_ok": count == len(payload), **fields}
    except OSError as exc:
        return {"attempted": True, "send_ok": False, **fields, **error_facts(exc)}


def native_dns_probe(spec, role, directory):
    path = Path(__file__).with_name("windows_native_dns_probe.py")
    nonce = spec.get("native_dns_nonce", spec["nonce"])
    if type(nonce) is not str or len(nonce) != 32 or any(char not in "0123456789abcdef" for char in nonce):
        return {"status": "unavailable", "calls": [], "wire_privacy_proven": False,
                "error_type": "InvalidNonce"}
    report = Path(directory) / ("native-dns-" + nonce[:8] + "-" + role + ".json")
    try:
        result = subprocess.run([sys.executable, "-I", "-S", str(path), "--nonce", nonce,
                                 "--role", role, "--report", str(report)],
                                capture_output=True, timeout=45)
        value = json.loads(report.read_text(encoding="utf-8"))
        return {"status": "observed", "exit_code": result.returncode,
                "helper_status": value.get("status"),
                "cleanup_proven": value.get("cleanup_proven") is True,
                "calls": value.get("calls", value.get("observations", [])), "report": value,
                "wire_privacy_proven": False}
    except (OSError, ValueError, subprocess.TimeoutExpired) as exc:
        return {"status": "unavailable", "calls": [], "wire_privacy_proven": False, **error_facts(exc)}


def _native_dns_nonce(spec):
    return spec.get("native_dns_nonce", spec["nonce"])


def worker(spec, role, report, *, collect_native_dns=True, wire_role=None):
    if wire_role not in (None, "outside_before", "outside_after"):
        raise ValueError("invalid wire marker role")
    marker_role = wire_role or role
    result = {"schema_version": 1, "role": role, "parent_pid": os.getpid(),
              "proxy_http": http_probe(spec), "proxy_socks": http_probe(spec, socks=True),
              "direct_tcp": direct_probe(spec), "acceptance_passed": False}
    for label in ("udp4", "udp6", "public_udp4", "public_udp6"):
        result[label] = udp_probe(spec, label, marker_role)
    if collect_native_dns:
        result["native_dns"] = native_dns_probe(spec, role, Path(report).parent)
    else:
        result["native_dns"] = {"status": "not_requested", "calls": [],
                                "wire_privacy_proven": False}
    if role == "parent":
        child_report = Path(report).with_name("child-" + Path(report).name)
        spec_path = Path(report).with_name("worker-spec.json")
        write_json(spec_path, spec)
        try:
            child_args = [sys.executable, "-I", "-S", str(Path(__file__).resolve()),
                          "--worker", "--spec", str(spec_path), "--report", str(child_report),
                          "--role", "child"]
            if not collect_native_dns:
                child_args.append("--skip-native-dns")
            if wire_role is not None:
                child_args.extend(("--wire-role", wire_role))
            child = subprocess.run(child_args, capture_output=True, timeout=60)
            result["child"] = json.loads(child_report.read_text(encoding="ascii"))
            result["child_exit_code"] = child.returncode
        except (OSError, ValueError, subprocess.TimeoutExpired) as exc:
            result["child"] = {"status": "unavailable", **error_facts(exc)}
    write_json(report, result)
    return result


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--worker", action="store_true", required=True)
    parser.add_argument("--spec", type=Path, required=True)
    parser.add_argument("--report", type=Path, required=True)
    parser.add_argument("--role", choices=("parent", "child"), required=True)
    parser.add_argument("--skip-native-dns", action="store_true")
    parser.add_argument("--wire-role", choices=("outside_before", "outside_after"))
    args = parser.parse_args(argv)
    if args.spec.stat().st_size > 16384:
        parser.error("fixed spec too large")
    spec = json.loads(args.spec.read_text(encoding="ascii"))
    if (spec.get("schema_version") != 1 or len(spec.get("nonce", "")) != 32
            or any(char not in "0123456789abcdef" for char in spec["nonce"])
            or ("native_dns_nonce" in spec and (type(spec["native_dns_nonce"]) is not str
                or len(spec["native_dns_nonce"]) != 32
                or any(char not in "0123456789abcdef" for char in spec["native_dns_nonce"])) )):
        parser.error("invalid fixed spec")
    worker(spec, args.role, args.report, collect_native_dns=not args.skip_native_dns,
           wire_role=args.wire_role)
    return 0  # Observations are not an acceptance verdict.


if __name__ == "__main__":
    raise SystemExit(main())
