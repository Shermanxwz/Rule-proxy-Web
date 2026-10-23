"""Pure, fail-closed effective-NRPT inventory for an explicit new DNS scope.

This module does not collect inventory, bind a socket, query DNS or start a child.
An exact-host nonmatch is a bounded policy observation, never DNS isolation.
The caller owns held-process/source/physical-stdout binding and the original
clock. Each gate must revalidate the same immutable raw bytes and three queries.
"""
from __future__ import annotations

import hashlib
import ipaddress
import json
import re

INVENTORY = '.github/windows_identity_dns_exact_nrpt_inventory.ps1'
STAGE = 'dns-exact-nrpt-readonly-inventory'
POLICY_MODE = 'effective-exact-fqdn-nonmatch-only-v1'
MAX_INVENTORY = 32768
MAX_QPC = 0x7fffffffffffffff
ACTUAL_READY = False
INVENTORY_KEYS = frozenset(('schema_version', 'stage', 'run', 'pid', 'qpc_frequency',
    'start_qpc', 'deadline_qpc', 'begin_qpc', 'end_qpc', 'read_only', 'dns_servers',
    'effective_nrpt_count', 'effective_nrpt_rules', 'udp53_count', 'tcp53_count'))
BOOLEAN_FIELDS = frozenset(('DirectAccessEnabled', 'DnsSecValidationRequired',
    'DnsSecQueryIPsecRequired', 'DirectAccessQueryIPsecRequired'))
ARRAY_FIELDS = frozenset(('DirectAccessDnsServers', 'NameServers'))
STRING_FIELDS = frozenset(('DnsSecIPsecCARestriction', 'DirectAccessIPsecCARestriction',
    'DirectAccessProxyName'))
ENUMS = {
    'QueryPolicy': ('Disable', 'QueryIPv6Only', 'QueryBoth'),
    'SecureNameQueryFallback': ('Disable', 'FallbackSecure', 'FallbackUnsecure', 'FallbackPrivate'),
    'DnsSecQueryIPsecEncryption': ('None', 'Low', 'Medium', 'High'),
    'DirectAccessQueryIPsecEncryption': ('None', 'Low', 'Medium', 'High'),
    'DirectAccessProxyType': ('Direct', 'UseDefault', 'UseProxyName', 'NoProxy'),
    'NameEncoding': ('Disable', 'Utf8WithMapping', 'Utf8WithoutMapping', 'Punycode'),
}
POLICY_FIELDS = frozenset(('Namespace', *BOOLEAN_FIELDS, *ARRAY_FIELDS, *STRING_FIELDS, *ENUMS))
PROJECTION_KEYS = frozenset(('known', 'dns_server_count', 'loopback_dns_present',
    'effective_nrpt_count', 'udp53_count', 'tcp53_count', 'reason', 'raw_sha256',
    'policy_mode', 'exact_nonmatching_rule_count', 'matched_query_count',
    'all_effective_rows_accounted'))
REASONS = ('none', 'unknown', 'policy_match', 'direct_access', 'udp53_occupied',
    'tcp53_occupied', 'stale')


class InventoryError(ValueError):
    """A fixed safe label; raw private values are never interpolated."""


def require(ok, label):
    if not ok:
        raise InventoryError(label)


def api_version():
    return 1


def integer(value, low, high):
    return type(value) is int and low <= value <= high


def digest(value):
    return type(value) is str and re.fullmatch('[0-9a-f]{64}', value) is not None


def _pairs(rows):
    result = {}
    for key, value in rows:
        require(key not in result, 'inventory_duplicate_key')
        result[key] = value
    return result


def parse_raw(raw, *, raw_sha256):
    require(type(raw) is bytes and 1 <= len(raw) <= MAX_INVENTORY, 'inventory_raw_bound')
    require(digest(raw_sha256) and hashlib.sha256(raw).hexdigest() == raw_sha256,
        'inventory_raw_hash')
    try:
        return json.loads(raw.decode('utf-8', 'strict'), object_pairs_hook=_pairs,
            parse_constant=lambda _: (_ for _ in ()).throw(InventoryError('inventory_nonfinite')))
    except (UnicodeError, json.JSONDecodeError) as error:
        raise InventoryError('inventory_json') from error


def exact_host(value):
    """Only a conservative ASCII host subset; never evaluate other NRPT forms."""
    require(type(value) is str and 1 <= len(value) <= 253, 'nrpt_namespace_bound')
    # Raw capture's 253-character limit also applies to the optional terminal dot.
    host = value[:-1] if value.endswith('.') else value
    require(host and not host.endswith('.') and not host.startswith('.'), 'nrpt_namespace_form')
    try:
        ipaddress.ip_address(host)
    except ValueError:
        pass
    else:
        raise InventoryError('nrpt_namespace_IP')
    labels = host.split('.')
    require(len(labels) >= 2 and all(re.fullmatch('[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?',
        label) is not None for label in labels), 'nrpt_namespace_LDH')
    canonical = host.lower()
    require(not canonical.endswith('.arpa') and not any(x.lower().startswith('xn--') for x in labels),
        'nrpt_namespace_unsupported')
    return canonical


def query_names(queries):
    require(type(queries) in (tuple, list) and len(queries) == 3, 'nrpt_three_queries')
    require(all(type(x) is str and re.fullmatch('[0-9a-f]{32}\\.n0a\\.invalid', x)
        is not None for x in queries), 'nrpt_exact_query')
    require(len(set(queries)) == 3, 'nrpt_query_distinct')
    return tuple(queries)


def _server(value):
    require(type(value) is str and 1 <= len(value) <= 96 and value == value.strip()
        and '%' not in value, 'inventory_server_string')
    try:
        address = ipaddress.ip_address(value)
    except ValueError as error:
        raise InventoryError('inventory_server_IP') from error
    for item in (address, address.ipv4_mapped if isinstance(address, ipaddress.IPv6Address) else None):
        if item is not None:
            require(not item.is_loopback and not item.is_unspecified and not item.is_multicast
                and str(item) != '255.255.255.255', 'inventory_server_unsafe')


def _rule(row):
    require(type(row) is dict and set(row) == POLICY_FIELDS, 'nrpt_row_keys')
    name = exact_host(row['Namespace'])
    for field in BOOLEAN_FIELDS:
        require(row[field] is None or type(row[field]) is bool, 'nrpt_boolean')
    for field, allowed in ENUMS.items():
        require(row[field] is None or type(row[field]) is str and row[field] in allowed,
            'nrpt_enum')
    for field in STRING_FIELDS:
        require(row[field] is None or type(row[field]) is str and len(row[field]) <= 1024,
            'nrpt_string')
    for field in ARRAY_FIELDS:
        value = row[field]
        require(value is None or type(value) is list and len(value) <= 64, 'nrpt_server_array')
        if value is not None:
            for server in value:
                _server(server)
    return name


def inventory_projection(value, *, run, pid, frequency, start, deadline, now, raw_sha256, queries):
    """Caller must first bind value to parse_raw(raw) and the held inventory exit.

    No claim is made about the original endpoint or NRPT state after this sampled
    window. In particular, five-second freshness is not a lock against changes.
    """
    names = query_names(queries)
    require(type(value) is dict and set(value) == INVENTORY_KEYS, 'inventory_keys')
    require(type(run) is str and re.fullmatch('[0-9a-f]{32}', run) is not None
        and integer(pid, 1, 0xffffffff) and digest(raw_sha256), 'inventory_expected_identity')
    require(type(value['schema_version']) is int and value['schema_version'] == 1
        and value['stage'] == STAGE and value['run'] == run and type(value['pid']) is int
        and value['pid'] == pid and value['read_only'] is True, 'inventory_identity')
    require(integer(frequency, 1, 1000000000) and integer(start, 1, MAX_QPC)
        and integer(deadline, start + 1, min(MAX_QPC, start + 120 * frequency)), 'inventory_epoch')
    for field, expected in (('qpc_frequency', frequency), ('start_qpc', start), ('deadline_qpc', deadline)):
        require(type(value[field]) is int and value[field] == expected, 'inventory_original_clock')
    require(integer(value['begin_qpc'], start, deadline - 1)
        and integer(value['end_qpc'], value['begin_qpc'], deadline - 1)
        and integer(now, value['end_qpc'], MAX_QPC), 'inventory_clock_order')
    servers = value['dns_servers']
    require(type(servers) is list and len(servers) <= 256, 'inventory_server_bound')
    for server in servers:
        _server(server)
    rows = value['effective_nrpt_rules']
    require(type(rows) is list and len(rows) <= 256 and type(value['effective_nrpt_count']) is int
        and value['effective_nrpt_count'] == len(rows), 'inventory_all_rows')
    canonical = [_rule(row) for row in rows]
    require(len(set(canonical)) == len(canonical), 'nrpt_duplicate_namespace')
    require(all(integer(value[k], 0, 32768) for k in ('udp53_count', 'tcp53_count')),
        'inventory_endpoints')
    matched = sum(name in canonical for name in names)
    matching_rules = sum(name in names for name in canonical)
    reason = ('direct_access' if any(row['DirectAccessEnabled'] is not False for row in rows)
        else 'policy_match' if matched else 'udp53_occupied' if value['udp53_count']
        else 'tcp53_occupied' if value['tcp53_count']
        else 'stale' if now >= deadline or now - value['end_qpc'] > 5 * frequency else 'none')
    return dict(known=True, dns_server_count=len(servers), loopback_dns_present=False,
        effective_nrpt_count=len(rows), udp53_count=value['udp53_count'], tcp53_count=value['tcp53_count'],
        reason=reason, raw_sha256=raw_sha256, policy_mode=POLICY_MODE,
        exact_nonmatching_rule_count=len(rows) - matching_rules, matched_query_count=matched,
        all_effective_rows_accounted=True)


def review_raw(raw, **expected):
    value = parse_raw(raw, raw_sha256=expected['raw_sha256'])
    return dict(raw=value, projection=inventory_projection(value, **expected))


def unknown_inventory():
    return dict(known=False, dns_server_count=None, loopback_dns_present=None,
        effective_nrpt_count=None, udp53_count=None, tcp53_count=None, reason='unknown',
        raw_sha256=None, policy_mode=POLICY_MODE, exact_nonmatching_rule_count=None,
        matched_query_count=None, all_effective_rows_accounted=False)


def inventory_public(value):
    require(type(value) is dict and set(value) == PROJECTION_KEYS
        and value['policy_mode'] == POLICY_MODE and type(value['known']) is bool,
        'inventory_projection_keys')
    if not value['known']:
        require(value == unknown_inventory(), 'inventory_unknown_projection')
        return dict(value)
    require(value['reason'] in REASONS and value['reason'] != 'unknown' and digest(value['raw_sha256'])
        and value['loopback_dns_present'] is False and value['all_effective_rows_accounted'] is True,
        'inventory_projection_facts')
    for key, maximum in (('dns_server_count', 256), ('effective_nrpt_count', 256),
            ('udp53_count', 32768), ('tcp53_count', 32768), ('exact_nonmatching_rule_count', 256),
            ('matched_query_count', 3)):
        require(integer(value[key], 0, maximum), 'inventory_projection_count')
    require(value['exact_nonmatching_rule_count'] + value['matched_query_count'] == value['effective_nrpt_count'],
        'inventory_projection_accounting')
    if value['reason'] == 'none':
        require(value['matched_query_count'] == value['udp53_count'] == value['tcp53_count'] == 0,
            'inventory_projection_admission')
    return dict(value)


def inventory_safe(value):
    return inventory_public(value)['known'] is True and value['reason'] == 'none'
