"""Private, fixed DNS-shaped UDP markers for the disposable test VM only.

These probes never change DNS/proxy/routes. A send return is diagnostic, not
delivery or kernel denial. Only the QEMU host can observe the wire markers.
"""
from __future__ import annotations

import ipaddress
import json
from pathlib import Path
import re
import secrets
import socket
import struct
import urllib.request


SOURCE_MAC = "52:54:00:12:34:56"
DESTINATIONS = (("ipv4", socket.AF_INET, "1.1.1.1"),
                ("ipv6", socket.AF_INET6, "2606:4700:4700::1111"))
ROLES = ("outside_before", "parent", "child", "outside_after")
VARIANTS = ("model3", "model1_internal_ingress_deny", "model1_internal", "model2_host")
EXECUTION_SCHEMA_VERSION = 2


def probe_mode(probe):
    """The fixed ID decides socket mode; no extra manifest authority exists."""
    identifier = probe.get("id")
    if not isinstance(identifier, str):
        raise ValueError("invalid_fixed_probe_identity")
    parts = identifier.split(".")
    if (len(parts) != 3 or parts[0] not in VARIANTS or parts[2] not in ROLES
            or parts[2] != probe.get("role")
            or parts[1] not in ("ipv4", "ipv6", "ipv4_unbound", "ipv6_unbound")
            or parts[1].removesuffix("_unbound") != probe.get("family")):
        raise ValueError("invalid_fixed_probe_identity")
    return "unbound" if parts[1].endswith("_unbound") else "bound"


class NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, request, fp, code, message, headers, newurl):
        return None


def dns_marker(variant, role):
    # RD=0, one IN/A question under .invalid, never user data or a real name.
    labels = (secrets.token_hex(12), variant, role, "invalid")
    if any(not re.fullmatch(r"[a-z0-9_]{1,63}", label) for label in labels):
        raise ValueError("invalid_fixed_probe_label")
    name = b"".join(bytes([len(label)]) + label.encode("ascii") for label in labels) + b"\0"
    return struct.pack("!HHHHHH", secrets.randbelow(65536), 0, 1, 0, 0, 0) + name + b"\0\1\0\1"


def send_probes(probes, role):
    evidence = []
    for probe in probes:
        if probe["role"] != role:
            continue
        record = {"id": probe["id"], "role": role, "attempted": True,
                  "bind_attempted": False, "bind_succeeded": False, "send_attempted": False,
                  "api_accepted": False, "errno": None}
        family = socket.AF_INET if probe["family"] == "ipv4" else socket.AF_INET6
        try:
            mode = probe_mode(probe)
            marker = bytes.fromhex(probe["payload_hex"])
            port = probe["port"]
            destination = ipaddress.ip_address(probe["destination"])
            if (type(port) is not int or not 1 <= port <= 65535
                    or destination.version != (4 if probe["family"] == "ipv4" else 6)):
                raise ValueError("invalid_fixed_probe_address")
            address = (str(destination), port)
            if mode == "bound":
                source = ipaddress.ip_address(probe["source_ip"])
                if source.version != destination.version:
                    raise ValueError("invalid_fixed_probe_source")
                bind_address = (str(source), 0)
            with socket.socket(family, socket.SOCK_DGRAM) as sender:
                sender.settimeout(2)
                if mode == "bound":
                    record["bind_attempted"] = True
                    sender.bind(bind_address)
                    record["bind_succeeded"] = True
                record["send_attempted"] = True
                count = sender.sendto(marker, address)
                record["api_accepted"] = count == len(marker)
        except OSError as exc:
            record["errno"] = getattr(exc, "winerror", None) or exc.errno
        except (ValueError, TypeError, KeyError):
            record["errno"] = -1
        evidence.append(record)
    return evidence


class WireSession:
    def __init__(self, configuration, variants):
        raw = Path(configuration).read_bytes()
        if len(raw) > 65536:
            raise ValueError("private_vm_config_oversized")
        value = json.loads(raw)
        base = value.get("host_url") if isinstance(value, dict) else None
        if not isinstance(base, str) or not re.fullmatch(r"http://10\.0\.2\.2:([0-9]{1,5})/[0-9a-f]{64}", base):
            raise ValueError("private_vm_endpoint_invalid")
        port = int(base.split(":")[2].split("/")[0])
        if not 1 <= port <= 65535:
            raise ValueError("private_vm_endpoint_invalid")
        self.base, self.variants = base, tuple(variants)
        if set(self.variants) != set(VARIANTS) or len(self.variants) != len(VARIANTS):
            raise ValueError("private_vm_variants_invalid")
        self.opener = urllib.request.build_opener(urllib.request.ProxyHandler({}), NoRedirect())
        self.probes, self.execution = [], []
        self.attested = True
        self.started = self.finished = False

    def request(self, endpoint, value):
        data = json.dumps(value, ensure_ascii=True, separators=(",", ":")).encode("ascii")
        if len(data) > 128 * 1024:
            raise ValueError("wire_request_oversized")
        request = urllib.request.Request(self.base + "/capture/" + endpoint, data=data,
                                         headers={"Content-Type": "application/json"}, method="POST")
        # No raw urllib exception or private URL enters a report or log.
        try:
            with self.opener.open(request, timeout=15) as response:
                raw = response.read(64 * 1024 + 1)
                if response.status != 200 or len(raw) > 64 * 1024:
                    raise ValueError()
                result = json.loads(raw)
                if not isinstance(result, dict):
                    raise ValueError()
                return result
        except Exception:
            raise RuntimeError("private_wire_endpoint_failed") from None

    def start(self):
        self.started = True  # A lost reply cannot prove the host did not start.
        result = self.request("start", {})
        if result != {"schema_version": 1, "source_mac": SOURCE_MAC}:
            raise RuntimeError("private_wire_start_invalid")
        sources = {}
        for name, family, destination in DESTINATIONS:
            with socket.socket(family, socket.SOCK_DGRAM) as route:
                route.settimeout(2)
                route.connect((destination, 53))  # Select source; sends no UDP.
                source = ipaddress.ip_address(route.getsockname()[0])
                if source.is_unspecified or source.version != (4 if name == "ipv4" else 6):
                    raise RuntimeError("private_wire_source_unavailable")
                sources[name] = str(source)
        for variant in self.variants:
            for family, _, destination in DESTINATIONS:
                for suffix in ("", "_unbound"):
                    group = variant + "." + family + suffix
                    for role in ROLES:
                        self.probes.append({"id": group + "." + role,
                            "group": group, "role": role, "family": family,
                            "protocol": "udp", "source_mac": SOURCE_MAC,
                            "source_ip": sources[family], "destination": destination, "port": 53,
                            "payload_hex": dns_marker(variant, role).hex()})

    def for_variant(self, variant):
        return [probe for probe in self.probes if probe["group"].startswith(variant + ".")]

    def control(self, variant, role):
        self.execution.extend(send_probes(self.for_variant(variant), role))

    def actors(self, variant):
        if variant.get("process_started") is not True:
            return
        attestation = variant.get("actor_attestation", {})
        self.attested &= attestation.get("attestation_passed") is True
        for actor in variant.get("actors", []):
            self.execution.extend(actor.get("wire_execution", []))

    def finish(self):
        if not self.started or self.finished:
            return None
        payload = {"manifest": {"schema_version": 1, "probes": self.probes},
            "execution": self.execution, "execution_schema_version": EXECUTION_SCHEMA_VERSION,
            "actor_execution_attested": self.attested}
        if hasattr(self, "dns_observation"):
            payload["dns"] = self.dns_observation
        result = self.request("finish", payload)
        self.finished = True
        if result.get("acceptance_passed") is not False or result.get("kernel_denial_proven") is not False:
            raise RuntimeError("wire_endpoint_exceeded_observation_scope")
        return result
