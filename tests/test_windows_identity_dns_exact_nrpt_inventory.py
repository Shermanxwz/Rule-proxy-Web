"""Inert adversarial inventory data only; never imports a Windows backend."""
from pathlib import Path
import copy
import hashlib
import importlib.util
import json
import unittest

PATH = Path(__file__).resolve().parents[1] / '.github/windows_identity_dns_exact_nrpt_inventory.py'
SPEC = importlib.util.spec_from_file_location('exact_nrpt_under_test', PATH)
m = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(m)
QUERIES = tuple(c * 32 + '.n0a.invalid' for c in '123')
RUN = 'a' * 32
F, T0, D, END = 1000, 100000, 185000, 101000


def row(name='slscr.update.microsoft.com'):
    return dict(Namespace=name, DirectAccessEnabled=False, QueryPolicy='QueryIPv6Only',
        SecureNameQueryFallback='FallbackPrivate', DnsSecIPsecCARestriction=None,
        DnsSecValidationRequired=False, DnsSecQueryIPsecRequired=False,
        DnsSecQueryIPsecEncryption=None, DirectAccessIPsecCARestriction=None,
        DirectAccessQueryIPsecRequired=None, DirectAccessQueryIPsecEncryption=None,
        DirectAccessDnsServers=None, DirectAccessProxyType=None, DirectAccessProxyName=None,
        NameServers=[], NameEncoding=None)


def inventory(rows=None):
    rows = [row(), row('fe3cr.delivery.mp.microsoft.com')] if rows is None else rows
    return dict(schema_version=1, stage=m.STAGE, run=RUN, pid=45, qpc_frequency=F,
        start_qpc=T0, deadline_qpc=D, begin_qpc=T0 + 10, end_qpc=END, read_only=True,
        dns_servers=['192.0.2.53', '2001:db8::53'], effective_nrpt_count=len(rows),
        effective_nrpt_rules=rows, udp53_count=0, tcp53_count=0)


def encode(value):
    return (json.dumps(value, separators=(',', ':'), ensure_ascii=False) + '\n').encode('utf-8')


def review(value, *, now=104000, queries=QUERIES, raw=None, raw_sha256=None, **kwargs):
    raw = encode(value) if raw is None else raw
    expected = dict(run=RUN, pid=45, frequency=F, start=T0, deadline=D, now=now,
        raw_sha256=hashlib.sha256(raw).hexdigest() if raw_sha256 is None else raw_sha256,
        queries=queries)
    expected.update(kwargs)
    return m.review_raw(raw, **expected)


class ExactNrptTests(unittest.TestCase):
    def test_two_realistic_unrelated_hosts_keep_count_and_no_allowlist(self):
        value = inventory()
        result = review(value)
        self.assertEqual(result['raw'], value)
        p = result['projection']
        self.assertTrue(m.inventory_safe(p))
        self.assertEqual(p['effective_nrpt_count'], 2)
        self.assertEqual(p['exact_nonmatching_rule_count'], 2)
        self.assertEqual(p['matched_query_count'], 0)
        self.assertTrue(p['all_effective_rows_accounted'])
        other = review(inventory([row('arbitrary.unrelated.example')]))['projection']
        self.assertTrue(m.inventory_safe(other))
        self.assertEqual(other['effective_nrpt_count'], 1)

    def test_any_of_three_queries_matching_case_or_dot_is_not_admitted(self):
        for query in QUERIES:
            for spelling in (query, query.upper(), query + '.', query.upper() + '.'):
                with self.subTest(spelling=spelling):
                    p = review(inventory([row(spelling)]))['projection']
                    self.assertFalse(m.inventory_safe(p))
                    self.assertEqual((p['reason'], p['matched_query_count'], p['exact_nonmatching_rule_count']),
                        ('policy_match', 1, 0))
        p = review(inventory([row(q) for q in QUERIES]))['projection']
        self.assertEqual(p['matched_query_count'], 3)

    def test_suffix_substring_is_not_used_for_exact_hosts(self):
        query = QUERIES[0]
        p = review(inventory([row('x.' + query), row(query + '.extra')]))['projection']
        self.assertTrue(m.inventory_safe(p))
        self.assertEqual(p['exact_nonmatching_rule_count'], 2)

    def test_all_unsupported_namespace_forms_stop(self):
        bad = ('', '.', '.n0a.invalid', '*.invalid', 'single', '127.0.0.1', '::1',
            '192.0.2.0/24', '1.0.0.127.in-addr.arpa', '0.ip6.arpa', 'a.arpa',
            'x..example', 'a.example..', '-a.example', 'a-.example', 'a_b.example',
            'a\\046example', 'a.example\x00', 'a.example\n', ' a.example', 'a.example ',
            'https://a.example', 'a.example:53', 'é.example', 'xn--plain.example',
            'Xn--plain.example', ['a.example'], None, 1, True, {'value':'a.example'})
        for name in bad:
            with self.subTest(namespace=repr(name)), self.assertRaises(m.InventoryError):
                review(inventory([row(name)]))
        with self.assertRaises(m.InventoryError):
            review(inventory([row('a' * 64 + '.example')]))
        max_host = '.'.join(('a' * 63,) * 3 + ('a' * 61,))
        self.assertEqual(len(max_host), 253)
        self.assertTrue(m.inventory_safe(review(inventory([row(max_host)]))['projection']))
        with self.assertRaises(m.InventoryError):
            review(inventory([row(max_host + '.')]))

    def test_canonical_duplicate_rows_reject_even_if_nonmatching(self):
        for spelling in ('A.Example', 'a.example.', 'A.EXAMPLE.'):
            with self.subTest(alias=spelling), self.assertRaises(m.InventoryError):
                review(inventory([row('a.example'), row(spelling)]))

    def test_all_sixteen_fields_and_actual_count_are_required(self):
        baseline = inventory()
        self.assertEqual(len(m.POLICY_FIELDS), 16)
        for field in m.POLICY_FIELDS:
            v = copy.deepcopy(baseline)
            del v['effective_nrpt_rules'][0][field]
            with self.subTest(field=field), self.assertRaises(m.InventoryError):
                review(v)
        for change in ('hide_row', 'zero_count', 'extra_semantic', 'extra_top', 'rows_tuple'):
            v = copy.deepcopy(baseline)
            if change == 'hide_row': v['effective_nrpt_rules'].pop()
            elif change == 'zero_count': v['effective_nrpt_count'] = 0
            elif change == 'extra_semantic': v['effective_nrpt_rules'][0]['FuturePolicy'] = False
            elif change == 'extra_top': v['namespace_filter'] = 'unrelated.example'
            else: v['effective_nrpt_rules'] = None
            with self.subTest(change=change), self.assertRaises(m.InventoryError): review(v)

    def test_nullable_boolean_enum_and_array_original_types(self):
        baseline = inventory([row('unrelated.example')])
        for field in m.BOOLEAN_FIELDS:
            for wrong in ('False', 0, 1, [], {}):
                v = copy.deepcopy(baseline); v['effective_nrpt_rules'][0][field] = wrong
                with self.subTest(field=field, value=wrong), self.assertRaises(m.InventoryError): review(v)
        for field in m.ENUMS:
            for wrong in ('', 'Unknown', 0, False, []):
                v = copy.deepcopy(baseline); v['effective_nrpt_rules'][0][field] = wrong
                with self.subTest(field=field, value=wrong), self.assertRaises(m.InventoryError): review(v)
        for field in m.ARRAY_FIELDS:
            for wrong in ('192.0.2.53', False, 5, {'address':'192.0.2.53'}, ['192.0.2.53'] * 65):
                v = copy.deepcopy(baseline); v['effective_nrpt_rules'][0][field] = wrong
                with self.subTest(field=field, value=repr(wrong)), self.assertRaises(m.InventoryError): review(v)
        for field in m.STRING_FIELDS:
            for wrong in (False, 1, [], 'x' * 1025):
                v = copy.deepcopy(baseline); v['effective_nrpt_rules'][0][field] = wrong
                with self.subTest(field=field), self.assertRaises(m.InventoryError): review(v)

    def test_direct_access_false_is_required_but_is_not_sufficient(self):
        for enabled in (None, True):
            v = inventory(); v['effective_nrpt_rules'][0]['DirectAccessEnabled'] = enabled
            p = review(v)['projection']
            self.assertEqual(p['reason'], 'direct_access')
            self.assertFalse(m.inventory_safe(p))
        self.assertFalse(m.inventory_safe(review(inventory([row(QUERIES[0])]))['projection']))

    def test_every_server_array_rejects_unsafe_even_unrelated_rule(self):
        bad = ('127.0.0.1', '127.2.3.4', '::1', '::ffff:127.0.0.1', '::ffff:127.2.3.4',
            '0.0.0.0', '::', '::ffff:0.0.0.0', '224.0.0.1', 'ff02::1',
            '::ffff:224.0.0.1', '255.255.255.255', 'dns.example', '192.0.2.1:53',
            'fe80::1%2', '192.0.2.53 ', '', None, 53, False)
        for field in ('dns_servers', *sorted(m.ARRAY_FIELDS)):
            for address in bad:
                v = inventory()
                if field == 'dns_servers': v[field] = [address]
                else: v['effective_nrpt_rules'][0][field] = [address]
                with self.subTest(field=field, address=address), self.assertRaises(m.InventoryError): review(v)

    def test_null_empty_and_single_server_arrays_are_not_collapsed(self):
        for server_array in (None, [], ['192.0.2.53']):
            v = inventory(); v['effective_nrpt_rules'][0]['NameServers'] = server_array
            r = review(v)
            self.assertEqual(r['raw']['effective_nrpt_rules'][0]['NameServers'], server_array)
            self.assertTrue(m.inventory_safe(r['projection']))

    def test_exact_three_sourcebound_queries_not_arbitrary_names(self):
        bad = (QUERIES[:2], QUERIES + ('4' * 32 + '.n0a.invalid',),
            (QUERIES[0], QUERIES[0], QUERIES[2]), (QUERIES[0].upper(), *QUERIES[1:]),
            (QUERIES[0] + '.', *QUERIES[1:]), ('x.n0a.invalid', *QUERIES[1:]), None)
        for queries in bad:
            with self.subTest(queries=queries), self.assertRaises(m.InventoryError):
                review(inventory(), queries=queries)

    def test_four_gates_reuse_original_bytes_and_five_second_boundary(self):
        value = inventory(); raw = encode(value); digest = hashlib.sha256(raw).hexdigest()
        for now in (END, END + 100, END + 4000, END + 5 * F):
            p = review(value, raw=raw, raw_sha256=digest, now=now)['projection']
            self.assertTrue(m.inventory_safe(p))
            self.assertEqual(p['raw_sha256'], digest)
        for now in (END + 5 * F + 1, D, D + 1):
            p = review(value, raw=raw, now=now)['projection']
            self.assertEqual(p['reason'], 'stale'); self.assertFalse(m.inventory_safe(p))
        changed = encode({**value, 'end_qpc': END + 1})
        with self.assertRaises(m.InventoryError): review(value, raw=changed, raw_sha256=digest)

    def test_unknown_clock_identity_and_occupied_ports_never_admit(self):
        for field, wrong in (('pid', 46), ('pid', True), ('qpc_frequency', F + 1),
                ('start_qpc', T0 - 1), ('deadline_qpc', D + 1), ('begin_qpc', END + 1),
                ('end_qpc', D), ('read_only', 1), ('effective_nrpt_count', True),
                ('udp53_count', False), ('tcp53_count', 32769)):
            v = inventory(); v[field] = wrong
            with self.subTest(field=field, value=wrong), self.assertRaises(m.InventoryError): review(v)
        for field, reason in (('udp53_count', 'udp53_occupied'), ('tcp53_count', 'tcp53_occupied')):
            v = inventory(); v[field] = 1
            p = review(v)['projection']; self.assertFalse(m.inventory_safe(p)); self.assertEqual(p['reason'], reason)
        with self.assertRaises(m.InventoryError): review(inventory(), now=END - 1)
        with self.assertRaises(m.InventoryError): review(inventory(), frequency=True)

    def test_duplicate_truncated_nonfinite_and_forged_raw_are_rejected(self):
        raw = encode(inventory())
        for bad in (raw[:-3], b'\xff', b'\xef\xbb\xbf' + raw, raw.replace(b'"pid":45', b'"pid":NaN'),
                raw.replace(b'"pid":45', b'"pid":45,"pid":45'),
                raw.replace(b'"Namespace":', b'"Namespace":"a.example","Namespace":', 1), b' ' * 32769):
            with self.subTest(raw_size=len(bad)), self.assertRaises(m.InventoryError): review(None, raw=bad)
        with self.assertRaises(m.InventoryError): review(inventory(), raw_sha256='0' * 64)

    def test_safe_projection_contains_no_names_servers_or_clock_and_unknown_stays_unknown(self):
        p = review(inventory())['projection']; safe = m.inventory_public(p)
        self.assertEqual(set(safe), m.PROJECTION_KEYS)
        self.assertNotIn(QUERIES[0], json.dumps(safe))
        for secret in ('slscr', '192.0.2.53', 'pid', 'end_qpc', 'Namespace'):
            self.assertNotIn(secret, json.dumps(safe))
        self.assertFalse(m.inventory_safe(m.unknown_inventory()))
        for change in ({'effective_nrpt_count':0}, {'matched_query_count':1}, {'all_effective_rows_accounted':False}):
            damaged = {**p, **change}
            with self.subTest(change=change), self.assertRaises(m.InventoryError): m.inventory_public(damaged)
        self.assertFalse(m.ACTUAL_READY)


if __name__ == '__main__':
    unittest.main()
