"""Original profiles expose only a filtered keyring, never desktop portals."""
from contextlib import contextmanager
import json
import os
from pathlib import Path
import select
import shutil
import signal
import socket
import stat
import subprocess
import sys
import tempfile
import time
import unittest
from unittest.mock import Mock, patch
from xml.sax.saxutils import escape

from ruleproxy import linux_profile_access as access


@contextmanager
def private_bus(services=()):
    with tempfile.TemporaryDirectory(prefix='ruleproxy-bus-test-') as directory:
        root = Path(directory)
        service_dir = root / 'services'
        service_dir.mkdir()
        for name in services:
            (service_dir / (name + '.service')).write_text(
                '[D-BUS Service]\nName=' + name + '\nExec=/bin/false\n')
        configuration = root / 'bus.conf'
        configuration.write_text('<busconfig><type>session</type><listen>unix:path=' + escape(str(root / 'host-bus'))
            + '</listen><auth>EXTERNAL</auth><servicedir>' + escape(str(service_dir)) + '</servicedir>'
            '<policy context="default"><allow send_destination="*"/><allow receive_sender="*"/>'
            '<allow own="*"/></policy></busconfig>')
        daemon = subprocess.Popen(['dbus-daemon', '--config-file=' + str(configuration), '--nofork',
                                   '--nopidfile', '--print-address=1'], stdout=subprocess.PIPE,
                                   stderr=subprocess.DEVNULL, text=True)
        try:
            ready, _, _ = select.select([daemon.stdout], [], [], 3)
            if not ready:
                raise AssertionError('Private test bus did not become ready')
            address = daemon.stdout.readline().strip()
            if not address:
                raise AssertionError('Private test bus exited before readiness')
            yield address
        finally:
            if daemon.poll() is None:
                daemon.terminate()
            daemon.wait(timeout=3)
            daemon.stdout.close()


@unittest.skipUnless(sys.platform == 'linux', 'Linux profile sharing only')
class LinuxProfileAccessTests(unittest.TestCase):
    def test_session_address_accepts_only_a_single_local_unix_bus(self):
        self.assertIsNone(access.session_address({}))
        for value in ('tcp:host=localhost,port=1234', 'unix:path=/a;unix:path=/b',
                      'unix:path=relative', 'unix:path=/a,path=/b', 'unix:path=/a,abstract=b',
                      'unix:unknown=x', 'unix:path=/a%00b'):
            with self.subTest(value=value), self.assertRaises(ValueError):
                access.session_address({'DBUS_SESSION_BUS_ADDRESS': value})
        for value in ('unix:path=/run/user/123/bus,guid=abc', 'unix:abstract=/tmp/bus-test'):
            self.assertEqual(access.session_address({'DBUS_SESSION_BUS_ADDRESS': value}), value)

    def test_saved_login_store_requires_a_desktop_keyring_without_basic_fallback(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            self.assertIsNone(access.prepare_keyring({}, root, 'chromium'))
            (root / 'Default/Network').mkdir(parents=True)
            (root / 'Default/Network/Cookies').write_bytes(b'untouched cookie database fixture')
            with patch.object(access, 'FilteredKeyringProxy') as proxy, self.assertRaisesRegex(ValueError, '桌面密钥服务'):
                access.prepare_keyring({}, root, 'chromium')
            proxy.assert_not_called()
            self.assertEqual((root / 'Default/Network/Cookies').read_bytes(), b'untouched cookie database fixture')
            self.assertIsNone(access.prepare_keyring({}, root, 'firefox'))

    def test_wallet_provider_check_rejects_a_wrong_desktop_and_is_bounded(self):
        reply = Mock(returncode=0, stdout='array [\n string "org.kde.kwalletd6"\n]\n')
        with patch.object(access.shutil, 'which', return_value='/usr/bin/dbus-send'), \
                patch.object(access.subprocess, 'run', return_value=reply) as request:
            with self.assertRaisesRegex(ValueError, '密钥服务不存在'):
                access.require_wallet_provider({'XDG_CURRENT_DESKTOP': 'GNOME'}, 'unix:path=/filtered')
            access.require_wallet_provider({'XDG_CURRENT_DESKTOP': 'KDE'}, 'unix:path=/filtered')
        self.assertEqual(request.call_count, 4)
        for call in request.call_args_list:
            self.assertEqual(call.kwargs['timeout'], 3)
            self.assertIn('--reply-timeout=2000', call.args[0])
            self.assertIn(call.args[0][-1], ['org.freedesktop.DBus.ListNames', 'org.freedesktop.DBus.ListActivatableNames'])

    def test_failed_proxy_start_cleans_lifeline_process_and_socket_directory(self):
        process = Mock(poll=Mock(return_value=None))
        with patch.object(access.shutil, 'which', return_value='/usr/bin/xdg-dbus-proxy'), \
                patch.object(access.subprocess, 'Popen', return_value=process) as launch, \
                patch.object(access.select, 'select', return_value=([], [], [])), \
                self.assertRaisesRegex(ValueError, '无法建立'):
            access.FilteredKeyringProxy('unix:path=/private-test-bus')
        process.wait.assert_called_once_with(timeout=3)
        args = launch.call_args.args[0]
        self.assertIn('--filter', args)
        self.assertEqual({item for item in args if item.startswith('--talk=')},
                         {'--talk=' + name for name in access.KEYRING_NAMES})
        self.assertFalse(any('*' in item or 'portal' in item or '--own=' in item for item in args))
        socket_path = Path(args[3])
        self.assertFalse(socket_path.parent.exists())
        for descriptor in launch.call_args.kwargs['pass_fds']:
            with self.assertRaises(OSError):
                os.fstat(descriptor)

    def test_shared_directory_rejects_links_foreign_roots_and_workspace_overlap(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            original, workspace = root / 'original', root / 'workspace'
            original.mkdir()
            workspace.mkdir()
            self.assertEqual(access.shared_profile(original, workspace), original)
            link = root / 'link'
            link.symlink_to(original)
            for value in (link, root, workspace, Path.home(), Path('/tmp')):
                with self.subTest(path=value), self.assertRaises(ValueError):
                    access.shared_profile(value, workspace)

    def test_policy_overlays_group_missing_and_nested_parents_without_clobbering(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            host, sources = root / 'host-etc', root / 'private'
            host.mkdir()
            sources.mkdir()
            (host / 'preserved.conf').write_text('keep')
            (host / 'firefox').mkdir()
            (host / 'firefox/existing.conf').write_text('keep firefox')
            targets = [host / 'firefox/policies', host / 'firefox-esr/policies']
            mounts = []
            for index, target in enumerate(targets):
                source = sources / str(index)
                source.mkdir()
                (source / 'policies.json').write_text('{}')
                mounts.append((source, target))
            args = access.policy_overlay_args(mounts)
            self.assertEqual([args[index + 1] for index, item in enumerate(args) if item == '--tmpfs'], [str(host)])
            for source, target in mounts:
                index = args.index(str(source))
                self.assertEqual(args[index - 1:index + 2], ['--ro-bind', str(source), str(target)])
            self.assertIn(str(host / 'preserved.conf'), args)
            self.assertIn(str(host / 'firefox/existing.conf'), args)
            self.assertFalse(any(target.exists() for target in targets))

    def test_shared_profile_rejects_host_ipc_nodes_without_changing_them(self):
        with tempfile.TemporaryDirectory(prefix='rp-ipc-') as directory:
            root = Path(directory)
            original, workspace = root / 'original', root / 'workspace'
            original.mkdir()
            workspace.mkdir()
            marker = original / 'Bookmarks'
            marker.write_bytes(b'preserved original bookmarks')
            endpoint = socket.socket(socket.AF_UNIX)
            socket_path = original / 'host-bridge.sock'
            try:
                endpoint.bind(str(socket_path))
                with self.assertRaisesRegex(ValueError, '套接字、管道或设备'):
                    access.shared_profile(original, workspace)
                self.assertTrue(socket_path.is_socket())
            finally:
                endpoint.close()
                socket_path.unlink()
            fifo = original / 'host-control.pipe'
            os.mkfifo(fifo)
            with self.assertRaisesRegex(ValueError, '套接字、管道或设备'):
                access.shared_profile(original, workspace)
            self.assertTrue(stat.S_ISFIFO(fifo.lstat().st_mode))
            self.assertEqual(marker.read_bytes(), b'preserved original bookmarks')

    def test_profile_metadata_scan_is_bounded_and_does_not_follow_symlinks(self):
        with tempfile.TemporaryDirectory(prefix='rp-budget-') as directory:
            root = Path(directory)
            original, workspace, outside = root / 'original', root / 'workspace', root / 'outside'
            for path in (original, workspace, outside):
                path.mkdir()
            os.mkfifo(outside / 'inaccessible-outside-pipe')
            (original / 'external-link').symlink_to(outside, target_is_directory=True)
            self.assertEqual(access.shared_profile(original, workspace), original)
            (original / 'Bookmarks').write_bytes(b'keep')
            with patch.object(access, 'MAX_PROFILE_ENTRIES', 1), self.assertRaisesRegex(ValueError, '数量或时间'):
                access.shared_profile(original, workspace)
            (original / 'nested').mkdir()
            with patch.object(access, 'MAX_PROFILE_DEPTH', 0), self.assertRaisesRegex(ValueError, '层次或时间'):
                access.shared_profile(original, workspace)
            with patch.object(access.time, 'monotonic', side_effect=[0, 6]), self.assertRaisesRegex(ValueError, '层次或时间'):
                access.shared_profile(original, workspace)
            self.assertEqual((original / 'Bookmarks').read_bytes(), b'keep')
            self.assertTrue((original / 'external-link').is_symlink())


@unittest.skipUnless(sys.platform == 'linux' and all(shutil.which(name) for name in
    ('dbus-daemon', 'dbus-send', 'xdg-dbus-proxy')), 'Native local D-Bus tools required')
class LiveFilteredKeyringTests(unittest.TestCase):
    def test_real_filter_exposes_only_wallet_names_and_lifeline_closes_proxy(self):
        with private_bus(('org.freedesktop.secrets', 'org.freedesktop.portal.Desktop')) as address:
            proxy = access.FilteredKeyringProxy(address)
            try:
                filtered = 'unix:path=' + str(proxy.path)
                access.require_wallet_provider({'XDG_CURRENT_DESKTOP': 'GNOME'}, filtered)
                reply = subprocess.run(['dbus-send', '--bus=' + filtered, '--print-reply', '--reply-timeout=2000',
                    '--dest=org.freedesktop.DBus', '/org/freedesktop/DBus', 'org.freedesktop.DBus.ListActivatableNames'],
                    capture_output=True, text=True, timeout=3)
                self.assertEqual(reply.returncode, 0, reply.stderr)
                self.assertIn('org.freedesktop.secrets', reply.stdout)
                self.assertNotIn('org.freedesktop.portal.Desktop', reply.stdout)
                denied = subprocess.run(['dbus-send', '--bus=' + filtered, '--print-reply', '--reply-timeout=2000',
                    '--dest=org.freedesktop.DBus', '/org/freedesktop/DBus', 'org.freedesktop.DBus.StartServiceByName',
                    'string:org.freedesktop.portal.Desktop', 'uint32:0'], capture_output=True, text=True, timeout=3)
                self.assertNotEqual(denied.returncode, 0)
                self.assertTrue('AccessDenied' in denied.stderr or 'ServiceUnknown' in denied.stderr, denied.stderr)
                # The same service is activatable on the host bus. A direct
                # call executes its harmless /bin/false fixture and therefore
                # has a different failure from the proxy's hidden service.
                host_call = subprocess.run(['dbus-send', '--bus=' + address, '--print-reply', '--reply-timeout=2000',
                    '--dest=org.freedesktop.DBus', '/org/freedesktop/DBus', 'org.freedesktop.DBus.StartServiceByName',
                    'string:org.freedesktop.portal.Desktop', 'uint32:0'], capture_output=True, text=True, timeout=3)
                self.assertIn('Spawn.ChildExited', host_call.stderr)
                process, path = proxy.process, proxy.path
            finally:
                proxy.close()
            self.assertEqual(process.returncode, 0)
            self.assertFalse(path.parent.exists())
            proxy.close()

    def test_bare_bus_with_existing_login_store_is_rejected_before_browser_launch(self):
        with private_bus() as address, tempfile.TemporaryDirectory() as directory:
            profile = Path(directory)
            (profile / 'Cookies').write_bytes(b'preserved original data')
            with self.assertRaisesRegex(ValueError, '密钥服务不存在'):
                access.prepare_keyring({'DBUS_SESSION_BUS_ADDRESS': address}, profile, 'chromium')
            self.assertEqual((profile / 'Cookies').read_bytes(), b'preserved original data')

    def test_proxy_exits_if_panel_process_crashes(self):
        with private_bus() as address:
            script = ('import json,sys,time; from ruleproxy.linux_profile_access import FilteredKeyringProxy; '
                'p=FilteredKeyringProxy(sys.argv[1]); '
                'print(json.dumps({"pid":p.process.pid,"path":str(p.path)}),flush=True); time.sleep(20)')
            child = subprocess.Popen([sys.executable, '-B', '-c', script, address], stdout=subprocess.PIPE,
                                     stderr=subprocess.PIPE, text=True)
            report = None
            try:
                ready, _, _ = select.select([child.stdout], [], [], 5)
                self.assertTrue(ready, 'Proxy parent did not become ready')
                report = json.loads(child.stdout.readline())
                child.kill()
                child.wait(timeout=3)
                deadline = time.monotonic() + 3
                exited = False
                while time.monotonic() < deadline:
                    try:
                        state = (Path('/proc') / str(report['pid']) / 'stat').read_text().rsplit(')', 1)[1].split()[0]
                        exited = state == 'Z'
                    except FileNotFoundError:
                        exited = True
                    if exited:
                        break
                    time.sleep(0.03)
                self.assertTrue(exited, 'Filtered host proxy survived its panel lifeline')
            finally:
                if child.poll() is None:
                    child.kill()
                    child.wait(timeout=3)
                child.stdout.close()
                child.stderr.close()
                if report:
                    shutil.rmtree(Path(report['path']).parent, ignore_errors=True)


if __name__ == '__main__':
    unittest.main()
