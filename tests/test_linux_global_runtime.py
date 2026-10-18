"""Pure/mocked tests: these never execute ip, nft, pkexec, or a proxy core."""
from pathlib import Path
import hashlib
import io
import json
import os
import socket
import subprocess
import sys
import tempfile
import unittest
from unittest.mock import Mock, patch

from ruleproxy import linux_global_runtime as runtime


def endpoint(address, port):
    value = socket.inet_pton(socket.AF_INET6 if ':' in address else socket.AF_INET, address)
    if len(value) == 4:
        value = value[::-1]
    else:
        value = b''.join(value[index:index + 4][::-1] for index in range(0, 16, 4))
    return value.hex().upper() + ':' + format(port, '04X')


def tcp(local, remote, state):
    return '0: ' + endpoint(*local) + ' ' + endpoint(*remote) + ' ' + state + ' 0 0 0 0 0 0\n'


class FakeSystem:
    def __init__(self):
        self.calls = []
        self.guard = False
        self.comment = ''
        self.guard_text = b'owned rules\n'
        self.fail_command = None
        self.links = []
        self.rules = []
        self.routes = []
        self.addresses = [{'ifname': runtime.DEVICE, 'flags':['UP'], 'addr_info':
                           [{'family': 'inet','local':'198.18.0.1'}, {'family': 'inet6','local':'fdfe:dcba:8879::1'}]}]

    def json(self, name, arguments):
        self.calls.append((name, list(arguments), None))
        if arguments == ['-j', 'link', 'show']: return self.links
        if arguments == ['-j', 'address', 'show']: return self.addresses
        if 'rule' in arguments: return self.rules
        if 'route' in arguments: return self.routes
        raise AssertionError(arguments)

    def run(self, name, arguments, data=None, check=True):
        self.calls.append((name, list(arguments), data))
        if self.fail_command is not None and (name, arguments) == self.fail_command:
            raise runtime.GlobalRuntimeError('injected_failure', 'injected failure')
        code, output, error = 0, b'', b''
        if name == 'nft':
            if arguments == ['--file', '-']:
                self.guard = True
                self.comment = data.decode().split('comment "')[1].split('"')[0]
            elif arguments[:3] == ['delete', 'table', 'inet']:
                self.guard = False
            elif arguments == ['-j', 'list', 'tables']:
                output = json.dumps({'nftables': [] if not self.guard else [{'table': {'family': 'inet', 'name': 'ruleproxy_global_1000'}}]}).encode()
            elif arguments[:4] == ['-j', 'list', 'table', 'inet']:
                code = 0 if self.guard else 1
                output = json.dumps({'nftables': [{'table': {'comment': self.comment}}]}).encode()
            elif arguments[:4] == ['-s', 'list', 'table', 'inet']:
                code = 0 if self.guard else 1
                output = self.guard_text
            elif arguments[:3] == ['list', 'table', 'inet']:
                code = 0 if self.guard else 1
        result = subprocess.CompletedProcess([name, *arguments], code, output, error)
        if name=='ip' and arguments[:1]==['-j']:
            result.stdout=b'[]'
        if check and code:
            raise runtime.GlobalRuntimeError('network_command_failed', 'mock command failed')
        return result


class PureGlobalTests(unittest.TestCase):
    def test_json_rejects_duplicate_nonfinite_oversize_and_wrong_shape(self):
        for data in (b'{"a":1,"a":2}', b'{"a":NaN}', b'[]', b'{'):
            with self.subTest(data=data), self.assertRaises(runtime.GlobalRuntimeError):
                runtime._json(data)
        with self.assertRaises(runtime.GlobalRuntimeError): runtime._json(b'{}', 1)

    def test_guard_has_no_blanket_uid_or_established_bypass(self):
        text = runtime.nft_guard(1000, 'a' * 32, ['8.8.8.8/32', '2001:4860::1/128'])
        self.assertIn('policy drop', text)
        self.assertIn('oifname "lo" accept', text)
        self.assertIn('meta mark 0x52505747 accept', text)
        self.assertIn('ip daddr 8.8.8.8/32 ct direction reply', text)
        self.assertIn('ip6 daddr 2001:4860::1/128 ct direction reply', text)
        self.assertNotIn('skuid', text)
        self.assertNotIn('ct state established,related accept\n  }', text)
        self.assertNotIn('flush', text)

    def test_guard_rejects_injection_and_broad_exceptions(self):
        for uid, lease, peers in ((True, 'a'*32, []), (1000, 'x"; flush ruleset', []),
                                  (1000, 'a'*32, ['0.0.0.0/0'])):
            with self.subTest(uid=uid, peers=peers), self.assertRaises((runtime.GlobalRuntimeError, ValueError)):
                runtime.nft_guard(uid, lease, peers)

    def test_rule_plan_is_dual_stack_and_exactly_owned(self):
        plan = runtime.rule_plan(['8.8.8.8/32', '2001:4860::1/128'])
        self.assertEqual(len(plan), 9)
        for version in ('-4', '-6'):
            records = [row for row in plan if row[0] == version]
            self.assertEqual(records[0][-3:], ['0x52505747', 'lookup', 'main'])
            self.assertEqual(records[-1][-2:], ['lookup', str(runtime.ROUTE_TABLE)])
        with self.assertRaises(runtime.GlobalRuntimeError): runtime.rule_plan(['10.0.0.0/8'])
        with self.assertRaises(runtime.GlobalRuntimeError): runtime.rule_plan(['8.8.8.8/32'] * 2)

    def test_exact_inbound_peers_excludes_outgoing_and_handles_mapped_ipv4(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            (root/'tcp').write_text('header\n' + tcp(('0.0.0.0',22),('0.0.0.0',0),'0A')
                + tcp(('10.0.0.2',22),('8.8.8.8',45000),'01')
                + tcp(('10.0.0.2',45001),('8.8.4.4',443),'01'))
            (root/'tcp6').write_text('header\n' + tcp(('::',3389),('::',0),'0A')
                + tcp(('::ffff:10.0.0.2',3389),('::ffff:9.9.9.9',45002),'01')
                + tcp(('2001:4860::2',3389),('2001:4860::3',45003),'01'))
            self.assertEqual(runtime.inbound_peers(root), ['2001:4860::3/128', '8.8.8.8/32', '9.9.9.9/32'])

    def test_unreadable_tcp_table_fails_before_any_network_change(self):
        with tempfile.TemporaryDirectory() as directory:
            with self.assertRaisesRegex(runtime.GlobalRuntimeError, '尚未修改网络'):
                runtime.inbound_peers(Path(directory))

    def test_conflicting_interface_rule_and_route_are_never_adopted(self):
        for field, value in (('links',[{'ifname':runtime.DEVICE}]),
                             ('rules',[{'priority':runtime.RULE_PRIORITY}]),
                             ('routes',[{'table':runtime.ROUTE_TABLE}])):
            system=FakeSystem();setattr(system,field,value)
            with self.subTest(field=field),self.assertRaises(runtime.GlobalRuntimeError):
                runtime.preflight(system)
            self.assertFalse(any('add' in args or 'delete' in args for _,args,_ in system.calls))

    def test_missing_installation_does_not_run_any_network_command(self):
        with patch.object(runtime, '_trusted', return_value=False), patch.object(runtime.subprocess,'run') as run:
            status=runtime.Runtime().status()
            self.assertTrue(status['setup_required']);self.assertFalse(status['supported']);run.assert_not_called()

    def test_core_validation_preserves_fixed_ipv6_without_giving_override_to_network_tools(self):
        fixed = {"PATH": "/usr/sbin:/usr/bin:/sbin:/bin", "LC_ALL": "C"}
        with patch.dict(runtime.os.environ, {"SKIP_SYSTEM_IPV6_CHECK": "false", "RULEPROXY_ENV_FIXTURE": "ignored"}), \
                patch.object(runtime, '_trusted', return_value=True), \
                patch.object(runtime.subprocess, 'run', return_value=subprocess.CompletedProcess([], 0, b'', b'')) as run:
            system = runtime.System()
            system.run('core', ['-t', '-f', '/fixed/config.yaml'])
            self.assertEqual(run.call_args.kwargs['env'], {**fixed, 'SKIP_SYSTEM_IPV6_CHECK': 'true'})
            system.run('ip', ['-j', 'link', 'show'])
            self.assertEqual(run.call_args.kwargs['env'], fixed)
            self.assertEqual(runtime.os.environ['SKIP_SYSTEM_IPV6_CHECK'], 'false')


class LeaseTests(unittest.TestCase):
    def setUp(self):
        self.temporary=tempfile.TemporaryDirectory();self.addCleanup(self.temporary.cleanup)
        self.root=Path(self.temporary.name);self.core=self.root/'fixed-core';self.core.write_bytes(b'fixed core')
        self.system=FakeSystem();self.lease=runtime.Lease(1000,self.system)
        self.lease.directory=self.root/'state';self.lease.journal=self.root/'lease.json'
        self.process=Mock(pid=321);self.process.poll.return_value=None
        self.process.terminate.side_effect=lambda:self.process.poll.configure_mock(return_value=0)
        self.process.wait.return_value=0
        self.payload={'operation':'start','source':'proxies:\n- name: test\n  type: socks5\n  server: 8.8.8.8\n  port: 1080\n',
                      'secret':'test-only-not-output','mixed_port':10809,'controller_port':19097,
                      'selected_node':'test','owner_pid':123,'owner_start':'456'}
        self.patches=[patch.object(runtime,'CORE',self.core),patch.object(runtime,'CORE_SIZE',len(b'fixed core')),
                      patch.object(runtime,'CORE_SHA256',hashlib.sha256(b'fixed core').hexdigest()),
                      patch.object(runtime,'inbound_peers',return_value=['8.8.4.4/32']),
                      patch.object(runtime,'_identity',return_value={'uid':1000,'start':'456'}),
                      patch.object(runtime.Lease,'_controller',return_value={'version':'test'}),
                      patch.object(runtime.subprocess,'Popen',return_value=self.process)]
        for item in self.patches:item.start();self.addCleanup(item.stop)

    def test_uncertain_nft_commit_keeps_recovery_and_explicit_stop_handles_absence(self):
        self.system.fail_command=('nft',['--file','-'])
        with self.assertRaises(runtime.GlobalRuntimeError):self.lease.start(self.payload)
        self.assertTrue(self.lease.guard);self.assertTrue(self.lease.journal.exists())
        self.assertEqual(self.lease.state,'blocked')
        self.system.fail_command=None
        self.assertEqual(self.lease.stop()['state'],'idle')

    def test_bad_owner_rejected_before_firewall_or_core(self):
        self.payload['owner_start']='reused'
        with self.assertRaises(runtime.GlobalRuntimeError):self.lease.start(self.payload)
        self.assertEqual(self.system.calls,[])

    def test_core_hash_failure_rejected_before_network(self):
        self.core.write_bytes(b'corrupted')
        with self.assertRaises(runtime.GlobalRuntimeError):self.lease.start(self.payload)
        self.assertEqual(self.system.calls,[])

    def test_link_local_only_ipv6_is_not_claimed_as_dual_stack_ready(self):
        self.system.addresses[0]['addr_info'][1]['local']='fe80::1'
        with patch.object(runtime.time,'monotonic',side_effect=[0,0,11]),patch.object(runtime.time,'sleep'):
            with self.assertRaises(runtime.GlobalRuntimeError):self.lease.start(self.payload)
        self.assertEqual(self.lease.state,'blocked');self.assertTrue(self.system.guard)
        self.assertFalse(self.lease.applied)

    def test_untrusted_tun_and_mark_are_overwritten(self):
        self.payload['source']+='tun: {enable: true, device: injected}\nrouting-mark: 2\n'
        config=self.lease._compile(self.payload)
        self.assertEqual(config['routing-mark'],runtime.ROUTING_MARK)
        self.assertEqual(config['tun']['device'],runtime.DEVICE)
        self.assertFalse(config['tun']['auto-route']);self.assertFalse(config['tun']['auto-redirect'])
        self.assertEqual(config['external-controller'],'')
        self.assertEqual(config['external-controller-unix'],str(self.lease.directory/'controller.sock'))
        self.assertNotEqual(config['secret'],self.payload['secret'])

if __name__=='__main__':unittest.main()
