"""Disposable VM evidence for the installed compartment/Mihomo data path.

Run as SYSTEM or the elevated CI runner after installing the exact package for an ordinary owner:
--root <installed root> --output <new private directory>. Win11 uses its active
RuleProxyCI session; headless Server uses RULEPROXY_TEST_USER/PASSWORD/SID from
the environment, consumed only in memory. This script
uses the installed Runtime, named-pipe service, NamespaceGate and app launcher.
It never grants product/privacy qualification and never changes system trust.
The companion fixture and interactive-user helper must accompany this file.
"""
from __future__ import annotations

import argparse
import base64
import ctypes
import hashlib
import json
import os
from pathlib import Path
import re
import secrets
import select
import shutil
import socket
import ssl
import struct
import subprocess
import sys
import threading
import time
import traceback
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

sys.path.insert(0, str(Path(__file__).resolve().parent))
from windows_free_backend_fixture import Fixture, error_facts, http_probe, read_exact, write_json

HOST = "ruleproxy-fixture.invalid"
EXTERNAL = "www.microsoft.com"
SOURCE_FILES = ("ruleproxy/windows_compartment.py", "ruleproxy/manager.py",
                "ruleproxy/windows_proxy_service.py", "ruleproxy/windows_proxy_runtime.py",
                "ruleproxy/windows_proxy_policy.py", "ruleproxy/windows_app_process.py")
LOCAL_PROXY = ("http_proxy", "connect_tls", "socks_tls")
LOCAL_DIRECT = ("direct_http", "direct_tls")
# TEST ONLY CA, server certificate and public fixture private key are below.
# They authorize only this disposable .invalid endpoint through an explicit
# SSLContext cafile. No certificate is installed into any operating-system store.
CA_PEM = """-----BEGIN CERTIFICATE-----
MIIDYTCCAkmgAwIBAgIUa2JE4YZ3HatAYXWgh39CCSL8/zswDQYJKoZIhvcNAQEL
BQAwJDEiMCAGA1UEAwwZcnVsZXByb3h5LWZpeHR1cmUuaW52YWxpZDAeFw0yNjEw
MTkwNDM2MjRaFw0zNjEwMTYwNDM2MjRaMCQxIjAgBgNVBAMMGXJ1bGVwcm94eS1m
aXh0dXJlLmludmFsaWQwggEiMA0GCSqGSIb3DQEBAQUAA4IBDwAwggEKAoIBAQC+
lj8M6EIIsBdmhcB94KfEHrA77cTOZo8on70UEZJQ1BTZBBmZPXnjXtbu+TFmQqW6
XkWPhf1rlMAN3TYCZVFnZNmkQFBITSAPJhQ2DJ4qEH+U+wg+iqoBRpQzohXJ18NI
SNvYrY5jnPfj2m0wxJ6f/hBctr+pSOnlpu88Eb/OofMnuJvkrLVLsfSZYREdm7Dh
lIYJ7H8OUJmQtRjkW6vtXjahpWFKii7b9BUD4R0zBKLJ1+lA6cO2bQvg2kMyiZpK
CXNVj3iy5AtMmzywKKWMvkZlyzvGmiDykiKYXTn7jIZJ2MDqaKVhNIBPmnQ3qKMf
xRgmpDhw9N147P0mvSftAgMBAAGjgYowgYcwHQYDVR0OBBYEFKwoeZScHYjGqjb3
mpsm6kGDRbETMB8GA1UdIwQYMBaAFKwoeZScHYjGqjb3mpsm6kGDRbETMCQGA1Ud
EQQdMBuCGXJ1bGVwcm94eS1maXh0dXJlLmludmFsaWQwDwYDVR0TAQH/BAUwAwEB
/zAOBgNVHQ8BAf8EBAMCAqQwDQYJKoZIhvcNAQELBQADggEBAEDTm1sPOegEDUQ2
NdjnRoZKGUVxtKTLIBUr8c9vjn5TSqlUcDO2Cc3CcF6N9VnLkaJgE9GmB6id8iHC
1rKLHfKeDNoes5P408MdFfJNC4OkIXAUl87neah5ZG4Ng+e7l2sObwG1/VdbvgqM
RcfIBusEAnPfAdPa3YIoFArAoB0S3wsXJvvWdw7cAB8ouMYu0o9XaSfoXXjS5brr
v0B1+sMNGVZ+31/WGSOAfFSI5mkc1iF67sMy0Y66oTR3uZg5rzTDHO3Z+Ofb6BUH
bE+MOcsWNwrsdSpY1uw6XI6jmmdZPRvGWJc/ZsiIILNWsyqmE3BZxWcvkQylP3rm
Ocig9wM=
-----END CERTIFICATE-----
"""
CERT_PEM = """-----BEGIN CERTIFICATE-----
MIIDczCCAlugAwIBAgIUQ8sUyKxUI73HfoQQHZ8Fwi26EYgwDQYJKoZIhvcNAQEL
BQAwJDEiMCAGA1UEAwwZcnVsZXByb3h5LWZpeHR1cmUuaW52YWxpZDAeFw0yNjEw
MTkwNDM2NDBaFw0zNjEwMTYwNDM2NDBaMCQxIjAgBgNVBAMMGXJ1bGVwcm94eS1m
aXh0dXJlLmludmFsaWQwggEiMA0GCSqGSIb3DQEBAQUAA4IBDwAwggEKAoIBAQCK
7VpvKQ3pVwE5IGZ859Twxk7+1u138CCtqsGUXYgfm5cp7affZNXWW1iN4NpsIc6H
lVFVvkZ6O3XOadsy3Tepcw/HRMTYP0mn9asLzOCnAty0Au2G9Bf3NYojbAuWiFZK
CNeg/mvYh5XcGm2El2OPDy4qf5nw7zQxScUszovA83YMAG9bV8k+KicS5YPuHSUB
ILcycL5wyJo+Y5slAE0HCaiX7U9DmN7atjx7zwvk85P7MqvzPLgl5UYpOWlFhXV0
/j3nNtVp/3b6LmV7QnHV7uH54KpCYtWDxlGIe+sjjtv+GpSnnPgBj1rMFN4YMkYq
1uPQW+4xeTrBVnedh38RAgMBAAGjgZwwgZkwJAYDVR0RBB0wG4IZcnVsZXByb3h5
LWZpeHR1cmUuaW52YWxpZDAMBgNVHRMBAf8EAjAAMA4GA1UdDwEB/wQEAwIFoDAT
BgNVHSUEDDAKBggrBgEFBQcDATAdBgNVHQ4EFgQUDXHo//Jscx8psrOxYfCVefbv
OOQwHwYDVR0jBBgwFoAUrCh5lJwdiMaqNveamybqQYNFsRMwDQYJKoZIhvcNAQEL
BQADggEBAAgmoju1TJU2Fy0eANWikCUzRbWsDzTMkyaUaGKb7TbFOiHsSN4H6Mi+
cvFhOoKWpTbOZvyYqvM47Yh+o7+5XMKdCQ5CSakd6xwnk3OYDVcxav9HKoEMIdXr
NtAf5ssNn8b1OhiUd/HhLuOCgwmmxha/zowtbBqp3DWBwBYq5nZFIhAGDdqvoTIc
wpYjv2xdF91zGx8yWjGUK16JEbdR0yq0GaiIG3NgJpsFja8RgnISJU4hqxhJSCVu
2h2WX42gwiGR5/LK59HJn0inDkCrfI7hq6VZGz9hvALUA52vLXaatSIsF8BykvTV
zm8ESf99tFRoNQD/G/DM6oAtpS0iz/E=
-----END CERTIFICATE-----
"""
KEY_PEM = """-----BEGIN PRIVATE KEY-----
MIIEvQIBADANBgkqhkiG9w0BAQEFAASCBKcwggSjAgEAAoIBAQCK7VpvKQ3pVwE5
IGZ859Twxk7+1u138CCtqsGUXYgfm5cp7affZNXWW1iN4NpsIc6HlVFVvkZ6O3XO
adsy3Tepcw/HRMTYP0mn9asLzOCnAty0Au2G9Bf3NYojbAuWiFZKCNeg/mvYh5Xc
Gm2El2OPDy4qf5nw7zQxScUszovA83YMAG9bV8k+KicS5YPuHSUBILcycL5wyJo+
Y5slAE0HCaiX7U9DmN7atjx7zwvk85P7MqvzPLgl5UYpOWlFhXV0/j3nNtVp/3b6
LmV7QnHV7uH54KpCYtWDxlGIe+sjjtv+GpSnnPgBj1rMFN4YMkYq1uPQW+4xeTrB
Vnedh38RAgMBAAECggEABHlFuQApsZqquv/12kOt6gNSI7yLQO+TjHwhR97mMAcM
NwkEkk9L399Tqp1JHgPNronf/g1GoDozc45ERS71/f0q+X1Xrb4F/W8ODxnNydsF
UpT9404PdSy9HMxmfXZjpEvaGRYFpjShiQkJ1KP6Ya7jtfHOJNcocgY1365BYQPP
OD1bWHSCRlfVNmx47j2jpK4sORVca44mMp4H57k0dVMQAtTUwiALBJePT3KGZ86S
mGRlwY6s/Ca1uqD4vMoQzE6+QkryisPqGfrcNIkLfWDfQ3wb9hGOhT0++QQfR3Sl
17Xargw+VtXHhXsQD0AnZUdCFa87i9w4oJv//KdmsQKBgQC/VcT59w9Hs/giR9Lc
x/82eteebUQRct9WsTaQ8/OK3sYP0yc2DYj0kuappCrs/64Wix0098qAu5l18jdt
LLY8p1TCo32k+EG1480cU1M8jFY6VpmUYx3acjH22RQI1FyzG1X1i4pXF98SCoAv
7LxR8K1Ke7Tt2fLrNeJ4zkFfuQKBgQC54UaEYqc3P+JbNfV3hY3Bw/CeLr+ftY48
VPmLP1cTLyU9ipkLMiTXwVtwEWQmsxhWMMEhjMaG7h5rivSY1El5g4KyZwxP3cbo
mDBl/P48kJsNtiKw4tC9y4E5KePhbjph2tRDQTNnefbW3yDKZTcuofqxBaVD1fXz
k782N2VWGQKBgGA1hpiSjJJngmvqZbMytbf1SRqWotWLR5ZWAbQdlubLYhhu+paJ
c8ZXX7kJnbQSVL1tMkCCIMdejanrI8e35eLV2R8OCo27b39AjtChbYdSocEv7oXY
2RgQt+MCALr33a0KH80aX3OvwzFVKmPuzDr/pIOBdNbs8uMm8zv/qouxAoGAUDcR
cWwJcWRWULpWdf/iju351qmh9FArU4nwLtFkyFieH5LCPPykvZ8p0JEQwUqkg/2C
OvI/clcsNYi/yXxDQPcp3cdunsC8Z//VUw38wTI+V4p0KhWXs3AxEfQr7UreUwBW
fbeTcWJGza94vR800yD/yIkBKucYvsbRy5nYV3ECgYEAmJ8H1WUIDdU//toQqi+E
w2RTl+92M5gwVv7G/y4202sG2zSyRtx6KOvfvs+yoGl2nhefmfXCBGgpmTI2/U5w
cUvlBXQ8vLEWh0i2Hh6skh89tKlL+wWUWW+M+11AoEQWxEcGqmol3yEBKUYr3yPW
FurRXj0P9Yo1bY6AXKczknI=
-----END PRIVATE KEY-----
"""


def digest(path):
    value = hashlib.sha256()
    with Path(path).open("rb") as stream:
        for block in iter(lambda: stream.read(1024 * 1024), b""):
            value.update(block)
    return value.hexdigest()


def failure(exc):
    def details(error):
        return {**error_facts(error), "message": str(error)[:400],
                "frames": [{"file": Path(f.filename).name, "line": f.lineno, "function": f.name}
                           for f in traceback.extract_tb(error.__traceback__)[-8:]]}

    result, seen, current = details(exc), {id(exc)}, exc
    # A native launch error can be followed by a second error during gate
    # revocation. Preserve the first failure without dumping locals or commands.
    chain = []
    for _ in range(4):
        related = current.__cause__
        relation = "cause"
        if related is None and not current.__suppress_context__:
            related, relation = current.__context__, "context"
        if related is None or id(related) in seen:
            break
        seen.add(id(related))
        chain.append({"relation": relation, **details(related)})
        current = related
    if chain:
        result["exception_chain"] = chain
    return result


def read_json(path):
    path = Path(path)
    if not path.is_file() or path.stat().st_size > 2 * 1024**2:
        return None
    try:
        return json.loads(path.read_text(encoding="ascii"))
    except (OSError, ValueError):
        return None


def identity():
    from windows_product_interactive_user import WindowsAPI
    value = WindowsAPI().caller()
    api = ctypes.WinDLL("iphlpapi", use_last_error=True)
    api.GetCurrentThreadCompartmentId.argtypes = []
    api.GetCurrentThreadCompartmentId.restype = ctypes.c_uint32
    return {**value, "pid": os.getpid(), "compartment_id": api.GetCurrentThreadCompartmentId()}


def source_identity(root, metadata, source_commit=None, bundle_sha256=None):
    expected = metadata["files"]
    measured = {name: digest(root / name) for name in expected}
    selected = {name: digest(root / name) for name in SOURCE_FILES}
    canonical = json.dumps(expected, sort_keys=True, separators=(",", ":")).encode("ascii")
    package = root / "package-manifest.json"
    receipt = read_json(package)
    package_files = receipt.get("files") if isinstance(receipt, dict) else None
    package_matches = bool(package_files) and all(measured.get(name) == value for name, value in package_files.items())
    source = Path(__file__).resolve().parent.parent
    source_matches = {name: (source / name).is_file() and digest(source / name) == selected[name]
                      for name in SOURCE_FILES}
    return {"source_commit": source_commit, "declared_bundle_sha256": bundle_sha256,
            "package_manifest_sha256": digest(package) if package.is_file() else None,
            "package_inventory_matches": bool(package_matches),
            "source_matches_bundle": source_matches,
            "installed_files_sha256": selected, "deployment_inventory_sha256": hashlib.sha256(canonical).hexdigest(),
            "deployment_inventory_matches": measured == expected,
            "mismatched_files": sorted(name for name in expected if measured[name] != expected[name]),
            "mihomo_sha256": measured.get("bin/windows-amd64/mihomo.exe"),
            "python_sha256": measured.get("python/python.exe"),
            "probe_sha256": digest(__file__), "fixture_sha256": digest(Path(__file__).with_name("windows_free_backend_fixture.py"))}


class TLSFixture(Fixture):
    """Use the existing real Mihomo fixture; upstream forwards actual TLS bytes."""

    def __init__(self, mihomo_path, directory):
        super().__init__(mihomo_path, directory)
        self.tls = None
        self.tls_started = False
        self.counts.update(tls_requests=[], upstream_connects=[], external_connects=0)

    def start(self):
        self.directory.joinpath("ca.pem").write_text(CA_PEM, encoding="ascii")
        self.directory.joinpath("server.pem").write_text(CERT_PEM, encoding="ascii")
        self.directory.joinpath("server-key.pem").write_text(KEY_PEM, encoding="ascii")
        fixture = self

        class Handler(BaseHTTPRequestHandler):
            def do_GET(self):
                match = re.fullmatch(r"/" + re.escape(fixture.spec["nonce"]) + r"/([a-z0-9_-]{1,100})", self.path)
                if not match:
                    self.send_error(404)
                    return
                tag = match.group(1)
                with fixture.lock:
                    if len(fixture.counts["tls_requests"]) < 512:
                        fixture.counts["tls_requests"].append({"tag": tag, "time_ns": time.monotonic_ns()})
                content = (fixture.spec["nonce"] + ":" + tag).encode("ascii")
                self.send_response(200)
                self.send_header("Content-Length", str(len(content)))
                self.send_header("Connection", "close")
                self.end_headers()
                self.wfile.write(content)

            def log_message(self, *ignored):
                pass

        self.tls = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
        self.tls.daemon_threads = True
        context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        context.minimum_version = ssl.TLSVersion.TLSv1_2
        context.load_cert_chain(str(self.directory / "server.pem"), str(self.directory / "server-key.pem"))
        self.tls.socket = context.wrap_socket(self.tls.socket, server_side=True)
        self.tls.socket.settimeout(3)
        self.spec.update(tls_port=self.tls.server_address[1], cafile=str(self.directory / "ca.pem"))
        self._thread(self.tls.serve_forever)
        self.tls_started = True
        return super().start()

    def _socks(self, connection):
        greeting = read_exact(connection, 2)
        if greeting[0] != 5 or not 1 <= greeting[1] <= 16 or 0 not in read_exact(connection, greeting[1]):
            raise ValueError("unsupported SOCKS greeting")
        connection.sendall(b"\x05\x00")
        request = read_exact(connection, 4)
        if request[:3] != b"\x05\x01\x00":
            raise ValueError("only SOCKS CONNECT is supported")
        if request[3] == 3:
            host = read_exact(connection, read_exact(connection, 1)[0]).decode("ascii")
        elif request[3] in (1, 4):
            host = socket.inet_ntop(socket.AF_INET if request[3] == 1 else socket.AF_INET6,
                                   read_exact(connection, 4 if request[3] == 1 else 16))
        else:
            raise ValueError("invalid SOCKS address type")
        port = struct.unpack("!H", read_exact(connection, 2))[0]
        local = host in (HOST, "127.0.0.1", "::1") and port in (self.spec["origin_port"], self.spec["tls_port"])
        external = host == EXTERNAL and port == 443
        if not local and not external:
            connection.sendall(b"\x05\x02\x00\x01" + b"\0" * 6)
            return
        with self.lock:
            self.counts["proxy_requests"] += 1
            self.counts["external_connects"] += int(external)
            if len(self.counts["upstream_connects"]) < 512:
                self.counts["upstream_connects"].append({"host": host, "port": port, "time_ns": time.monotonic_ns()})
        with socket.create_connection(("127.0.0.1" if local else host, port), timeout=8) as peer:
            peer.settimeout(8)
            connection.sendall(b"\x05\x00\x00\x01\x7f\0\0\x01\0\0")
            deadline = time.monotonic() + 30
            while not self.stop.is_set() and time.monotonic() < deadline:
                ready, _, _ = select.select((connection, peer), [], [], .2)
                for source in ready:
                    payload = source.recv(16384)
                    if not payload:
                        return
                    (peer if source is connection else connection).sendall(payload)

    def close(self):
        if self.tls is not None:
            if self.tls_started:
                self.tls.shutdown()
            self.tls.server_close()
        super().close()


def header(connection, limit=16384):
    value = bytearray()
    while not value.endswith(b"\r\n\r\n"):
        value.extend(read_exact(connection, 1))
        if len(value) > limit:
            raise ValueError("oversized HTTP header")
    return bytes(value)


def socks_connect(connection, host, port):
    connection.sendall(b"\x05\x01\x00")
    if read_exact(connection, 2) != b"\x05\x00":
        raise ValueError("SOCKS authentication rejected")
    encoded = host.encode("ascii")
    connection.sendall(b"\x05\x01\x00\x03" + bytes([len(encoded)]) + encoded + struct.pack("!H", port))
    answer = read_exact(connection, 4)
    if answer[:3] != b"\x05\x00\x00":
        raise OSError("SOCKS connect rejected")
    size = {1: 4, 4: 16}.get(answer[3])
    if answer[3] == 3:
        size = read_exact(connection, 1)[0]
    if size is None:
        raise ValueError("invalid SOCKS response")
    read_exact(connection, size + 2)


def tls_probe(spec, route, tag, *, external=False):
    host, port = (EXTERNAL, 443) if external else (HOST, spec["tls_port"])
    result = {"ok": False, "route": route, "host": host, "tag": tag, "tls_verified": False}
    raw = secure = None
    try:
        endpoint = (host if external else "127.0.0.1", port) if route == "direct" else ("127.0.0.1", spec["proxy_port"])
        raw = socket.create_connection(endpoint, timeout=8 if external else 3)
        raw.settimeout(8 if external else 3)
        if route == "connect":
            raw.sendall(f"CONNECT {host}:{port} HTTP/1.1\r\nHost: {host}:{port}\r\n\r\n".encode("ascii"))
            if header(raw).split(b" ", 2)[1] != b"200":
                raise OSError("HTTP CONNECT rejected")
        elif route == "socks":
            socks_connect(raw, host, port)
        elif route != "direct":
            raise ValueError("invalid proxy route")
        context = ssl.create_default_context() if external else ssl.create_default_context(cafile=spec["cafile"])
        context.minimum_version = ssl.TLSVersion.TLSv1_2
        secure = context.wrap_socket(raw, server_hostname=host)
        raw = None
        result.update(tls_verified=True, tls_version=secure.version(),
                      certificate_sha256=hashlib.sha256(secure.getpeercert(binary_form=True)).hexdigest())
        path = "/" if external else "/" + spec["nonce"] + "/" + tag
        secure.sendall(f"GET {path} HTTP/1.1\r\nHost: {host}\r\nConnection: close\r\n\r\n".encode("ascii"))
        response = header(secure)
        status = int(response.split(b" ", 2)[1])
        result["http_status"] = status
        if external:
            result["ok"] = 200 <= status < 400
        else:
            expected = (spec["nonce"] + ":" + tag).encode("ascii")
            result["ok"] = status == 200 and read_exact(secure, len(expected)) == expected
    except (OSError, ValueError, EOFError) as exc:
        result.update(error_facts(exc))
    finally:
        for connection in (secure, raw):
            if connection is not None:
                connection.close()
    return result


def matrix(spec, prefix, *, external=True):
    direct = {**spec, "proxy_host": "127.0.0.1", "proxy_port": spec["origin_port"],
              "origin_url": "/" + spec["nonce"]}
    values = {"http_proxy": http_probe(spec), "direct_http": http_probe(direct)}
    for key, route in (("direct_tls", "direct"), ("connect_tls", "connect"), ("socks_tls", "socks")):
        values[key] = tls_probe(spec, route, prefix + "-" + key)
    if external:
        values["external_connect_tls"] = tls_probe(spec, "connect", prefix + "-external", external=True)
    return values


def actor(args):
    spec = read_json(args.spec)
    report = {"identity": identity(), "before": matrix(spec, args.tag), "before_complete": True}
    write_json(args.actor_report, report)
    if args.go:
        deadline = time.monotonic() + 180
        while not Path(args.go).exists():
            if time.monotonic() >= deadline:
                raise TimeoutError("actor fault barrier timed out")
            time.sleep(.1)
        report["after"] = matrix(spec, args.tag + "-after", external=False)
        report["after_complete"] = True
        write_json(args.actor_report, report)
    return 0


def wait_report(path, process, key, timeout=120):
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        value = read_json(path)
        if value and value.get(key):
            return value
        if process.poll() is not None:
            raise RuntimeError("actor exited before " + key)
        time.sleep(.1)
    raise TimeoutError("bounded actor report timeout: " + key)


def fault_checks(result):
    plain = result.get("outside", {}).get("before", {})
    confined = result.get("inside", {}).get("before", {})
    before_identity = result.get("inside", {}).get("identity", {})
    outside_identity = result.get("outside", {}).get("identity", {})
    after = result.get("inside", {}).get("after", {})
    complete_after = result.get("inside", {}).get("after_complete") is True
    actor_ended = (type(result.get("actor_exit_code")) is int and result["actor_exit_code"] != 0
                   and result.get("actor_alive_before_fault") is True)
    baseline = lambda name: plain.get(name, {}).get("ok") is True
    return {"plain_same_api_positive": all(baseline(name) for name in LOCAL_PROXY + LOCAL_DIRECT),
            "ordinary_same_identity": before_identity.get("sid") == outside_identity.get("sid") and
                before_identity.get("sid", "").startswith("S-1-5-21-") and before_identity.get("elevated") is False,
            "distinct_compartment": type(before_identity.get("compartment_id")) is int and
                before_identity["compartment_id"] != outside_identity.get("compartment_id"),
            "real_mihomo_local_tls": all(confined.get(name, {}).get("ok") is True for name in LOCAL_PROXY),
            "direct_controls_denied": all(confined.get(name, {}).get("ok") is False for name in LOCAL_DIRECT),
            "fault_injected": result.get("fault", {}).get("injected") is True,
            "post_fault_terminated_or_denied": (actor_ended and not complete_after) or complete_after and
                all(after.get(name, {}).get("ok") is False for name in LOCAL_PROXY + LOCAL_DIRECT),
            "no_post_fault_tls_hit": result.get("post_fault_tls_hits") == [],
            "no_post_fault_http_hit": result.get("post_fault_http_delta") == 0,
            "origin_still_reachable_outside": result.get("outside_after", {}).get("direct_tls", {}).get("ok") is True}


def ordinary(args):
    sys.path.insert(0, str(args.root))
    from ruleproxy.windows_proxy_service import load_deployment
    from ruleproxy.windows_proxy_runtime import Runtime
    from ruleproxy.windows_app_process import launch
    from ruleproxy.windows_compartment import start_namespaced
    metadata = load_deployment(args.root)
    who = identity()
    if who["sid"] != metadata["owner_sid"] or who["elevated"]:
        raise PermissionError("probe launcher must use the unelevated installation owner")
    report = {"product_qualified": False, "privacy_qualified": False, "identity": who, "scenarios": {}}
    write_json(args.output / "ordinary-started.json", report)
    try:
        for kind in ("core", "service"):
            result = report["scenarios"][kind] = {}
            runtime, app, lease = Runtime(args.root), None, None
            if runtime.snapshot().get("state") != "idle":
                raise RuntimeError("the disposable product must be idle before each experiment")
            directory = args.output / kind
            with TLSFixture(args.root / "bin/windows-amd64/mihomo.exe", directory) as fixture:
                spec = fixture.write_spec()
                plain_report, inside_report, go = (directory / name for name in ("outside.json", "inside.json", "fault.go"))
                base = [str(args.root / "python/python.exe"), "-I", "-S", "-B", str(Path(__file__).resolve()),
                        "--role", "actor", "--spec", str(spec)]
                with (directory / "outside.log").open("wb") as log:
                    with subprocess.Popen(base + ["--actor-report", str(plain_report), "--tag", kind + "-outside"],
                                          stdin=subprocess.DEVNULL, stdout=log, stderr=subprocess.STDOUT) as plain:
                        try:
                            result["outside"] = wait_report(plain_report, plain, "before_complete")
                            plain.wait(timeout=10)
                        except BaseException:
                            plain.kill()
                            plain.wait(timeout=10)
                            raise
                try:
                    result["namespace_prepare"] = runtime.namespace_prepare(fixture.spec["proxy_port"], fixture.process.pid)
                    command = base + ["--actor-report", str(inside_report), "--tag", kind + "-inside", "--go", str(go)]
                    app, lease = start_namespaced(runtime, "product-probe-" + kind, command, dict(os.environ),
                                                 proxy_port=fixture.spec["proxy_port"], launch=launch)
                    result["inside"] = wait_report(inside_report, app, "before_complete")
                    result["actor_alive_before_fault"] = app.poll() is None
                    result["before_fault_counts"] = fixture.snapshot()
                    if kind == "core":
                        stopped = fixture.stop_proxy()
                        result["fault"] = {"injected": stopped["exited"], "kind": "owned_mihomo_termination",
                                           "time_ns": time.monotonic_ns(), **stopped}
                    else:
                        write_json(args.output / "service-fault-request.json", {"nonce": args.nonce})
                        deadline = time.monotonic() + 60
                        while time.monotonic() < deadline:
                            fault = read_json(args.output / "service-fault-result.json")
                            if fault:
                                result["fault"] = fault
                                break
                            time.sleep(.1)
                        else:
                            raise TimeoutError("SYSTEM service fault acknowledgement timed out")
                    go.write_text("fresh connections only\n", encoding="ascii")
                    deadline = time.monotonic() + 40
                    while app.poll() is None and time.monotonic() < deadline:
                        current = read_json(inside_report)
                        if current and current.get("after_complete"):
                            break
                        time.sleep(.1)
                    result["inside"] = read_json(inside_report) or result["inside"]
                    result["actor_exit_code"] = app.poll()
                    cutoff = result["fault"]["time_ns"]
                    # Read counts before the outside origin control below.
                    counts = fixture.snapshot()
                    result["post_fault_tls_hits"] = [hit for hit in counts["tls_requests"] if hit["time_ns"] >= cutoff]
                    result["post_fault_http_delta"] = counts["origin_requests"] - result["before_fault_counts"]["origin_requests"]
                    result["outside_after"] = {"direct_tls": tls_probe(fixture.spec, "direct", kind + "-outside-after")}
                    if kind == "service":
                        result["outside_after"]["mihomo_still_works"] = tls_probe(fixture.spec, "connect", "service-outside-core-alive")
                    result["checks"] = fault_checks(result)
                    result["fixture_counts"] = fixture.snapshot()
                finally:
                    if app is not None and app.poll() is None:
                        app.terminate()
                        app.wait(timeout=10)
                    if kind != "service" or not result.get("fault", {}).get("injected"):
                        if lease is not None:
                            lease.close()
                        runtime.stop()
            write_json(args.output / "ordinary-progress.json", report)
    except BaseException as exc:
        report["error"] = failure(exc)
    report["complete"] = True
    report["controlled_chain_checks_passed"] = len(report["scenarios"]) == 2 and all(
        all(value.get("checks", {}).values()) and bool(value.get("checks")) for value in report["scenarios"].values())
    report["external_https_verified"] = len(report["scenarios"]) == 2 and all(
        value.get(scope, {}).get("before", {}).get("external_connect_tls", {}).get("ok") is True
        for value in report["scenarios"].values() for scope in ("outside", "inside"))
    report["external_tls_handshake_verified"] = len(report["scenarios"]) == 2 and all(
        value.get(scope, {}).get("before", {}).get("external_connect_tls", {}).get("tls_verified") is True
        for value in report["scenarios"].values() for scope in ("outside", "inside"))
    write_json(args.output / "ordinary-result.json", report)
    return int("error" in report or not report["controlled_chain_checks_passed"])


def recovery(args):
    """A fresh ordinary client proves the restarted service can build a new gate."""
    sys.path.insert(0, str(args.root))
    from ruleproxy.windows_proxy_service import load_deployment
    from ruleproxy.windows_proxy_runtime import Runtime
    from ruleproxy.windows_app_process import launch
    from ruleproxy.windows_compartment import start_namespaced
    who, metadata = identity(), load_deployment(args.root)
    if who["sid"] != metadata["owner_sid"] or who["elevated"]:
        raise PermissionError("recovery must use the ordinary installation owner")
    runtime, app, lease = Runtime(args.root), None, None
    result = {"product_qualified": False, "privacy_qualified": False, "identity": who}
    try:
        result["initial_status"] = runtime.snapshot()
        if result["initial_status"].get("state") != "idle":
            raise RuntimeError("restarted service is not idle")
        with TLSFixture(args.root / "bin/windows-amd64/mihomo.exe", args.output / "recovery") as fixture:
            result["outside"] = {"identity": who, "before": matrix(fixture.spec, "recovery-outside", external=False)}
            spec, actor_report = fixture.write_spec(), fixture.directory / "actor.json"
            result["namespace_prepare"] = runtime.namespace_prepare(fixture.spec["proxy_port"], fixture.process.pid)
            command = [str(args.root / "python/python.exe"), "-I", "-S", "-B", str(Path(__file__).resolve()),
                       "--role", "actor", "--spec", str(spec), "--actor-report", str(actor_report), "--tag", "recovery-inside"]
            try:
                app, lease = start_namespaced(runtime, "product-probe-recovery", command, dict(os.environ),
                                             proxy_port=fixture.spec["proxy_port"], launch=launch)
                result["inside"] = wait_report(actor_report, app, "before_complete")
                result["actor_exit_code"] = app.wait(timeout=10)
                checks = fault_checks(result)
                result["checks"] = {name: checks[name] for name in (
                    "plain_same_api_positive", "ordinary_same_identity", "distinct_compartment",
                    "real_mihomo_local_tls", "direct_controls_denied")}
                result["checks"]["actor_finished"] = result["actor_exit_code"] == 0
                result["fixture_counts"] = fixture.snapshot()
            finally:
                if app is not None and app.poll() is None:
                    app.terminate()
                    app.wait(timeout=10)
                if lease is not None:
                    lease.close()
                runtime.stop()
    except BaseException as exc:
        result["error"] = failure(exc)
    result["complete"] = True
    result["controlled_chain_checks_passed"] = bool(result.get("checks")) and all(result["checks"].values()) and "error" not in result
    write_json(args.output / "recovery-result.json", result)
    return int(not result["controlled_chain_checks_passed"])


def temporary_debug_privilege(native):
    """Enable SeDebug only for the fixed service fault; return a restoring closer."""
    class Luid(ctypes.Structure):
        _fields_ = [("low", ctypes.c_uint32), ("high", ctypes.c_int32)]
    class Privileges(ctypes.Structure):
        _fields_ = [("count", ctypes.c_uint32), ("luid", Luid), ("attributes", ctypes.c_uint32)]
    advapi = native.advapi
    advapi.LookupPrivilegeValueW.argtypes = [ctypes.c_wchar_p, ctypes.c_wchar_p, ctypes.POINTER(Luid)]
    advapi.LookupPrivilegeValueW.restype = ctypes.c_int
    advapi.AdjustTokenPrivileges.argtypes = [ctypes.c_void_p, ctypes.c_int, ctypes.POINTER(Privileges),
        ctypes.c_uint32, ctypes.POINTER(Privileges), ctypes.POINTER(ctypes.c_uint32)]
    advapi.AdjustTokenPrivileges.restype = ctypes.c_int
    token = ctypes.c_void_p()
    native.checked(advapi.OpenProcessToken(native.kernel.GetCurrentProcess(), 0x20 | 8, ctypes.byref(token)))
    previous, needed = Privileges(), ctypes.c_uint32()
    try:
        enabled = Privileges()
        enabled.count, enabled.attributes = 1, 2
        native.checked(advapi.LookupPrivilegeValueW(None, "SeDebugPrivilege", ctypes.byref(enabled.luid)))
        ctypes.set_last_error(0)
        native.checked(advapi.AdjustTokenPrivileges(token, False, ctypes.byref(enabled), ctypes.sizeof(previous),
                                                  ctypes.byref(previous), ctypes.byref(needed)))
        if ctypes.get_last_error() == 1300:
            raise PermissionError("disposable CI controller lacks SeDebugPrivilege")
    except BaseException:
        native.close(token.value)
        raise
    def restore():
        try:
            native.checked(advapi.AdjustTokenPrivileges(token, False, ctypes.byref(previous), 0, None, None))
        finally:
            native.close(token.value)
    return restore


def open_verified_service(root, *, terminate=False):
    """Retain the installed service's exact process; restore privilege promptly."""
    from ruleproxy.windows_proxy_service import ServiceControl
    from ruleproxy.windows_proxy_policy import SERVICE_NAME
    from windows_product_interactive_user import WindowsAPI
    control, native = ServiceControl(), WindowsAPI()
    before = control.status(SERVICE_NAME)
    if before["state"] != 4 or before["pid"] <= 0:
        raise RuntimeError("RuleProxyControl is not running")
    kernel = native.kernel
    kernel.OpenProcess.argtypes, kernel.OpenProcess.restype = [ctypes.c_uint32, ctypes.c_int, ctypes.c_uint32], ctypes.c_void_p
    kernel.QueryFullProcessImageNameW.argtypes = [ctypes.c_void_p, ctypes.c_uint32, ctypes.c_wchar_p, ctypes.POINTER(ctypes.c_uint32)]
    kernel.QueryFullProcessImageNameW.restype = ctypes.c_int
    handle = None
    restore = temporary_debug_privilege(native)
    try:
        handle = kernel.OpenProcess(0x100000 | 0x1000 | (1 if terminate else 0), False, before["pid"])
        native.checked(handle)
        token = native.process_token(handle)
        try:
            actual = native.identity(token)
        finally:
            native.close(token)
        size, image = ctypes.c_uint32(32768), ctypes.create_unicode_buffer(32768)
        native.checked(kernel.QueryFullProcessImageNameW(handle, 0, image, ctypes.byref(size)))
        expected = root / "python/python.exe"
        if (actual["sid"] != "S-1-5-18" or os.path.normcase(image.value) != os.path.normcase(str(expected))
                or control.status(SERVICE_NAME)["pid"] != before["pid"] or native.wait(handle, 0) != 258):
            raise PermissionError("SCM service process identity changed or did not match the installation")
        restore_now, restore = restore, None
        restore_now()
        result = native, control, handle, before["pid"]
        handle = None
        return result
    finally:
        if handle:
            native.close(handle)
        if restore is not None:
            restore()


def service_state(witness):
    from ruleproxy.windows_proxy_policy import SERVICE_NAME
    native, control, handle, pid = witness
    result = {"pid": pid, "alive": native.wait(handle, 0) == 258,
              "time_ns": time.monotonic_ns(), "scm": control.status(SERVICE_NAME)}
    if not result["alive"]:
        code = native.exit_code(handle)
        result.update(exit_code=code, exit_code_hex=f"0x{code:08X}")
    return result


def service_diagnostics(root, metadata, pid, started):
    """Read only fixed product records and exact-process crash event fields."""
    result = {}
    log = Path(os.environ.get("ProgramData", r"C:\ProgramData")) / "RuleProxy-Web/service.log"
    if log.is_file():
        result["service_log_sha256"] = digest(log)
        with log.open("rb") as stream:
            stream.seek(max(0, log.stat().st_size - 256 * 1024))
            lines = stream.read(256 * 1024).decode("ascii", "replace").splitlines()
        records = []
        for line in lines[-32:]:
            try:
                record = json.loads(line)
            except ValueError:
                continue
            if isinstance(record, dict):
                records.append(record)
        result["service_log_records"] = records
    directory = metadata.get("namespace_state_dir")
    if isinstance(directory, str):
        journal = Path(directory) / "compartments.json"
        value = read_json(journal)
        if value is not None:
            result["namespace_journal"] = value
            result["namespace_journal_sha256"] = digest(journal)
    if type(pid) is int and pid > 0:
        # Event 1000 uses the exact faulting image and PID. Do not export broad
        # Application logs, WER dumps, message text or command-line information.
        image = str(root / "python/python.exe").replace("'", "''")
        command = (
            "$ErrorActionPreference='Stop';[Console]::OutputEncoding=[Text.UTF8Encoding]::new();"
            f"$start=[DateTimeOffset]::FromUnixTimeSeconds({int(started)}).LocalDateTime;"
            "$events=@(Get-WinEvent -FilterHashtable @{LogName='Application';Id=1000;StartTime=$start} "
            "-MaxEvents 50 -ErrorAction SilentlyContinue);$rows=@();foreach($e in $events){"
            "$x=[xml]$e.ToXml();$d=@{};foreach($v in $x.Event.EventData.Data){$d[$v.Name]=[string]$v.'#text'};"
            f"if($d.AppPath -ine '{image}'){{continue}};"
            "$n=0;try{if($d.ProcessId -match '^0x'){$n=[Convert]::ToInt64($d.ProcessId.Substring(2),16)}"
            "else{$n=[int64]$d.ProcessId}}catch{continue};"
            f"if($n -ne {pid}){{continue}};"
            "$r=@{time_utc=$e.TimeCreated.ToUniversalTime().ToString('o');event_id=$e.Id};"
            "foreach($k in @('AppName','AppVersion','ModuleName','ModuleVersion','ExceptionCode',"
            "'FaultingOffset','ProcessId','AppPath','ModulePath','ReportId')){if($d.ContainsKey($k)){$r[$k]=$d[$k]}};"
            "$rows+=$r};ConvertTo-Json -InputObject @($rows | Select-Object -First 5) -Compress -Depth 5")
        encoded = base64.b64encode(command.encode("utf-16-le")).decode("ascii")
        powershell = Path(os.environ.get("SystemRoot", r"C:\Windows")) / "System32/WindowsPowerShell/v1.0/powershell.exe"
        execution = subprocess.run([str(powershell), "-NoProfile", "-NonInteractive", "-EncodedCommand", encoded],
                                   capture_output=True, timeout=15)
        result["crash_event_query_exit_code"] = execution.returncode
        if len(execution.stdout) <= 65536:
            try:
                result["exact_process_crash_events"] = json.loads(execution.stdout.decode("utf-8-sig"))
            except ValueError:
                result["crash_event_json_invalid"] = True
    return result


def kill_verified_service(root):
    """Keep an exact handle and verify its SYSTEM identity/image before faulting."""
    native, control, handle, pid = open_verified_service(root, terminate=True)
    try:
        native.terminate(handle)
        if native.wait(handle, 5000) != 0:
            raise TimeoutError("verified service did not terminate")
        return {"injected": True, "kind": "verified_system_service_handle_termination", "pid": pid,
                "process_sid": "S-1-5-18", "exit_code": native.exit_code(handle), "time_ns": time.monotonic_ns()}
    finally:
        native.close(handle)


def restart_service():
    from ruleproxy.windows_proxy_service import ServiceControl
    from ruleproxy.windows_proxy_policy import SERVICE_NAME
    control = ServiceControl()
    deadline = time.monotonic() + 30
    requested = False
    while time.monotonic() < deadline:
        state = control.status(SERVICE_NAME)
        if state["state"] == 4:
            return {"restored": True, **state}
        if state["state"] == 1 and not requested:
            handle = control._open(SERVICE_NAME, 16)
            try:
                if not control.api.StartServiceW(handle, 0, None):
                    raise ctypes.WinError(ctypes.get_last_error())
            finally:
                control.api.CloseServiceHandle(handle)
            requested = True
        time.sleep(.2)
    return {"restored": False, **control.status(SERVICE_NAME)}


def launch_owned_owner(command, owner_sid, session, directory, credentials=None):
    """Use WTS or the exercised WithTokenW path; assign a Job before resume."""
    from windows_product_interactive_user import WindowsAPI, UserProcess, Startup, Info
    from ruleproxy.windows_app_process import _KernelAPI
    api, jobs = WindowsAPI(), _KernelAPI()
    caller = api.caller()
    token = environment = process = thread = job = None
    try:
        if session is not None:
            token = api.user_token(session)
            method = "WTSQueryUserToken+CreateProcessAsUserW"
        else:
            if not credentials or credentials[2] != owner_sid:
                raise PermissionError("noninteractive owner credentials are missing or SID differs")
            api.advapi.LogonUserW.argtypes = [ctypes.c_wchar_p, ctypes.c_wchar_p, ctypes.c_wchar_p,
                                            ctypes.c_uint32, ctypes.c_uint32, ctypes.POINTER(ctypes.c_void_p)]
            api.advapi.LogonUserW.restype = ctypes.c_int
            logon = ctypes.c_void_p()
            api.checked(api.advapi.LogonUserW(credentials[0], ".", credentials[1], 2, 0, ctypes.byref(logon)))
            token = logon.value
            method = "LogonUserW+CreateProcessWithTokenW" if caller["sid"] == "S-1-5-18" else "CreateProcessWithLogonW"
        expected = api.identity(token)
        if (expected["sid"] != owner_sid or expected["elevated"] or
                session is not None and expected["session_id"] != session):
            raise PermissionError("interactive owner identity does not match deployment")
        environment = api.environment(token)
        job = jobs.create_job()
        jobs.configure_job(job, 0x2000)
        if session is not None:
            process, thread, pid = api.create(token, command, str(directory), environment)
        else:
            startup, info = Startup(), Info()
            startup.cb = ctypes.sizeof(startup)
            text = ctypes.create_unicode_buffer(subprocess.list2cmdline(command))
            if caller["sid"] == "S-1-5-18":
                api.advapi.CreateProcessWithTokenW.argtypes = [ctypes.c_void_p, ctypes.c_uint32, ctypes.c_wchar_p,
                    ctypes.c_wchar_p, ctypes.c_uint32, ctypes.c_void_p, ctypes.c_wchar_p,
                    ctypes.POINTER(Startup), ctypes.POINTER(Info)]
                api.advapi.CreateProcessWithTokenW.restype = ctypes.c_int
                api.checked(api.advapi.CreateProcessWithTokenW(token, 1, command[0], text,
                    0x08000000 | 0x400 | 4, environment, str(directory), ctypes.byref(startup), ctypes.byref(info)))
            else:
                api.advapi.CreateProcessWithLogonW.argtypes = [ctypes.c_wchar_p, ctypes.c_wchar_p, ctypes.c_wchar_p,
                    ctypes.c_uint32, ctypes.c_wchar_p, ctypes.c_wchar_p, ctypes.c_uint32, ctypes.c_void_p,
                    ctypes.c_wchar_p, ctypes.POINTER(Startup), ctypes.POINTER(Info)]
                api.advapi.CreateProcessWithLogonW.restype = ctypes.c_int
                api.checked(api.advapi.CreateProcessWithLogonW(credentials[0], ".", credentials[1], 1,
                    command[0], text, 0x08000000 | 0x400 | 4, environment, str(directory),
                    ctypes.byref(startup), ctypes.byref(info)))
            process, thread, pid = info.process, info.thread, info.pid
        actual = api.process_token(process)
        try:
            actual_identity = api.identity(actual)
            if (actual_identity["sid"] != owner_sid or actual_identity["elevated"] or
                    session is not None and actual_identity["session_id"] != session):
                raise PermissionError("suspended launcher identity changed")
        finally:
            api.close(actual)
        jobs.assign_job(job, process)
        api.free_environment(environment)
        environment = None
        api.close(token)
        token = None
        api.resume(thread)
        child = UserProcess(api, process, pid, command, caller["sid"], actual_identity["session_id"])
        child.launch_method = method
        process = None
        result = child, jobs, job
        job = None
        return result
    finally:
        if process is not None:
            api.terminate(process)
            api.wait(process, 5000)
            api.close(process)
        if thread is not None:
            api.close(thread)
        if environment is not None:
            api.free_environment(environment)
        if token is not None:
            api.close(token)
        if job is not None:
            jobs.close_handle(job)


def verify_service_recovery(args, metadata, session, script, credentials):
    command = [str(args.root / "python/python.exe"), "-I", "-S", "-B", str(script),
               "--role", "recovery", "--root", str(args.root), "--output", str(args.output)]
    child, jobs, job = launch_owned_owner(command, metadata["owner_sid"], session, args.output, credentials)
    try:
        exit_code = child.wait(timeout=180)
        value = read_json(args.output / "recovery-result.json")
        return {"launcher_exit_code": exit_code, "result": value,
                "verified": exit_code == 0 and bool(value and value.get("controlled_chain_checks_passed"))}
    finally:
        try:
            jobs.terminate_job(job)
        finally:
            jobs.close_handle(job)
            child.close()


def driver(args):
    if os.name != "nt" or os.environ.get("GITHUB_ACTIONS") != "true":
        raise PermissionError("this destructive fault experiment requires a disposable Windows CI VM")
    sys.path.insert(0, str(args.root))
    from ruleproxy.windows_proxy_service import load_deployment
    from windows_product_interactive_user import WindowsAPI
    metadata = load_deployment(args.root)
    api = WindowsAPI()
    caller = api.caller()
    if caller["sid"] != "S-1-5-18" and not (caller["elevated"] and ctypes.WinDLL("shell32").IsUserAnAdmin()):
        raise PermissionError("the fault controller must be SYSTEM or the elevated disposable CI administrator")
    credentials = tuple(os.environ.pop(name, None) for name in (
        "RULEPROXY_TEST_USER", "RULEPROXY_TEST_PASSWORD", "RULEPROXY_TEST_SID"))
    requested_session = args.session_id
    if requested_session is None and os.environ.get("RULEPROXY_TEST_INTERACTIVE_SESSION"):
        requested_session = int(os.environ["RULEPROXY_TEST_INTERACTIVE_SESSION"])
    sessions = [value for value in api.sessions() if value["active"] and value["username"].casefold() == "ruleproxyci"
                and (requested_session is None or value["session_id"] == requested_session)]
    if len(sessions) > 1 or requested_session is not None and not sessions:
        raise RuntimeError("requested RuleProxyCI owner session is not unique/active")
    # WTSQueryUserToken requires SYSTEM. The Server administrator uses the
    # already exercised WithLogonW credential path without a SYSTEM password file.
    session = sessions[0]["session_id"] if sessions and caller["sid"] == "S-1-5-18" else None
    if session is None and (not all(credentials) or credentials[2] != metadata["owner_sid"]):
        raise PermissionError("Server requires environment credentials for the installed ordinary owner")
    args.output.mkdir(parents=True, exist_ok=False)
    # Only the CI owner, SYSTEM and administrators may access this disposable work.
    subprocess.run(["icacls.exe", str(args.output), "/inheritance:r", "/grant:r", "*S-1-5-18:(OI)(CI)F",
                    "*S-1-5-32-544:(OI)(CI)F", "*" + metadata["owner_sid"] + ":(OI)(CI)M"],
                   check=True, stdout=subprocess.DEVNULL, stderr=subprocess.PIPE, timeout=15)
    scripts = args.output / "tools"
    scripts.mkdir()
    for name in (Path(__file__).name, "windows_free_backend_fixture.py", "windows_product_interactive_user.py"):
        shutil.copyfile(Path(__file__).with_name(name), scripts / name)
    nonce = secrets.token_hex(16)
    report = {"schema_version": 1, "product_qualified": False, "privacy_qualified": False,
              "scope": "installed production network path, ordinary actor, controlled TLS and owned core/service faults",
              "source_identity": source_identity(args.root, metadata, args.source_commit, args.bundle_sha256),
              "owner_sid": metadata["owner_sid"], "source_is_installed_package": True,
              "controller_identity": caller,
              "tls_trust": "explicit fixture CA file; no system certificate-store changes",
              "dns_packet_evidence": False, "browser_sandbox_qualification": False}
    process, fault, lifetime_api, lifetime_job, witness = None, None, None, None, None
    started = time.time()
    service_fault_attempted = False
    try:
        if not (report["source_identity"]["deployment_inventory_matches"] and
                report["source_identity"]["package_inventory_matches"] and
                all(report["source_identity"]["source_matches_bundle"].values())):
            raise RuntimeError("source, installed files and package/deployment inventories do not match")
        witness = open_verified_service(args.root)
        report["service_at_start"] = service_state(witness)
        command = [str(args.root / "python/python.exe"), "-I", "-S", "-B", str(scripts / Path(__file__).name),
                   "--role", "ordinary", "--root", str(args.root), "--output", str(args.output), "--nonce", nonce]
        process, lifetime_api, lifetime_job = launch_owned_owner(
            command, metadata["owner_sid"], session, args.output, credentials)
        report["ordinary_launch_method"] = process.launch_method
        deadline = time.monotonic() + 420
        while process.poll() is None and time.monotonic() < deadline:
            request = read_json(args.output / "service-fault-request.json")
            if request is not None and fault is None:
                if request != {"nonce": nonce}:
                    raise ValueError("invalid service fault request")
                service_fault_attempted = True
                fault = kill_verified_service(args.root)
                write_json(args.output / "service-fault-result.json", fault)
            time.sleep(.2)
        if process.poll() is None:
            raise TimeoutError("ordinary product probe exceeded 420 seconds")
        report["launcher_exit_code"] = process.poll()
        report["ordinary"] = read_json(args.output / "ordinary-result.json")
        if not report["ordinary"] or not report["ordinary"].get("complete"):
            raise RuntimeError("ordinary launcher did not produce its final report")
    except BaseException as exc:
        report["error"] = failure(exc)
    finally:
        def cleanup(label, action):
            try:
                action()
            except BaseException as exc:
                report.setdefault("cleanup_errors", []).append({"operation": label, "error": failure(exc)})
        if witness is not None:
            try:
                report["service_before_cleanup"] = service_state(witness)
                report["service_diagnostics"] = service_diagnostics(args.root, metadata, witness[3], started)
            except BaseException as exc:
                report["service_diagnostics_error"] = failure(exc)
            finally:
                cleanup("close_service_witness", lambda: witness[0].close(witness[2]))
        if process is not None:
            def stop_launcher():
                if process.poll() is None:
                    process.kill()
                    process.wait(timeout=10)
            cleanup("stop_launcher", stop_launcher)
            cleanup("close_launcher", process.close)
        if lifetime_job is not None:
            # Includes a partially started core if the launcher hit its deadline.
            cleanup("terminate_lifetime_job", lambda: lifetime_api.terminate_job(lifetime_job))
            cleanup("close_lifetime_job", lambda: lifetime_api.close_handle(lifetime_job))
        if service_fault_attempted:
            try:
                report["service_recovery"] = restart_service()
                if report["service_recovery"]["restored"]:
                    report["service_recovery"]["fresh_chain"] = verify_service_recovery(
                        args, metadata, session, scripts / Path(__file__).name, credentials)
            except BaseException as exc:
                report["service_recovery"] = {"restored": False, "error": failure(exc)}
        report["complete"] = True
        write_json(args.output / "report.json", report)
    return int("error" in report or bool(report.get("cleanup_errors")) or report.get("launcher_exit_code") != 0 or
               not report.get("service_recovery", {}).get("fresh_chain", {}).get("verified"))


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--role", choices=("driver", "ordinary", "recovery", "actor"), default="driver")
    parser.add_argument("--root", type=Path)
    parser.add_argument("--output", type=Path)
    parser.add_argument("--session-id", type=int)
    parser.add_argument("--source-commit", default=os.environ.get("GITHUB_SHA"))
    parser.add_argument("--bundle-sha256")
    parser.add_argument("--nonce")
    parser.add_argument("--spec", type=Path)
    parser.add_argument("--actor-report", type=Path)
    parser.add_argument("--go", type=Path)
    parser.add_argument("--tag")
    args = parser.parse_args()
    for name, length in (("source_commit", 40), ("bundle_sha256", 64)):
        value = getattr(args, name)
        if value is not None and not re.fullmatch("[a-f0-9]{" + str(length) + "}", value):
            parser.error("invalid --" + name.replace("_", "-"))
    if args.role != "actor" and (args.root is None or args.output is None):
        parser.error("--root and --output are required")
    if args.role == "actor" and not (args.spec and args.actor_report and args.tag):
        parser.error("actor requires --spec, --actor-report and --tag")
    if args.root is not None:
        args.root = args.root.resolve()
    if args.output is not None:
        args.output = args.output.resolve()
    if args.role in ("ordinary", "recovery", "actor"):
        log_path = args.actor_report.with_suffix(".log") if args.role == "actor" else args.output / (args.role + ".log")
        previous = sys.stdout, sys.stderr
        try:
            with log_path.open("w", encoding="utf-8", buffering=1) as log:
                sys.stdout = sys.stderr = log
                try:
                    return {"ordinary": ordinary, "recovery": recovery, "actor": actor}[args.role](args)
                except BaseException as exc:
                    report = {"complete": True, "product_qualified": False, "error": failure(exc)}
                    write_json(args.actor_report if args.role == "actor" else args.output / (args.role + "-result.json"), report)
                    return 1
        finally:
            sys.stdout, sys.stderr = previous
    return driver(args)


if __name__ == "__main__":
    raise SystemExit(main())
