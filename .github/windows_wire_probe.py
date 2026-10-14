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
                  "bind_succeeded": False, "api_accepted": False, "errno": None}
        family = socket.AF_INET if probe["family"] == "ipv4" else socket.AF_INET6
        try:
            with socket.socket(family, socket.SOCK_DGRAM) as sender:
                sender.settimeout(2)
                sender.bind((probe["source_ip"], 0))
                record["bind_succeeded"] = True
                marker = bytes.fromhex(probe["payload_hex"])
                count = sender.sendto(marker, (probe["destination"], probe["port"]))
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
        result = self.request("start", {})
        self.started = True  # Even invalid replies require a finish attempt.
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
                for role in ROLES:
                    self.probes.append({"id": variant + "." + family + "." + role,
                        "group": variant + "." + family, "role": role, "family": family,
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
        result = self.request("finish", {"manifest": {"schema_version": 1, "probes": self.probes},
            "execution": self.execution, "actor_execution_attested": self.attested})
        self.finished = True
        if result.get("acceptance_passed") is not False or result.get("kernel_denial_proven") is not False:
            raise RuntimeError("wire_endpoint_exceeded_observation_scope")
        return result
