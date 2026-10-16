"""Windows setup downloads survive interruptions without weakening fixed pins."""
from __future__ import annotations

import hashlib
import io
from pathlib import Path
import socket
import ssl
import tempfile
import unittest
import urllib.error
from unittest.mock import call, patch

from ruleproxy import windows_proxy_pins as pins


class InterruptedResponse(io.BytesIO):
    def read(self, _limit=-1):
        raise ConnectionResetError(10054, 'remote host closed the connection')


class WindowsProxyDownloadTests(unittest.TestCase):
    def setUp(self):
        self.payload = b'verified official asset'
        self.asset = {'name': 'fixed.bin', 'url': 'https://example.invalid/fixed.bin',
                      'size': len(self.payload), 'sha256': hashlib.sha256(self.payload).hexdigest()}
        self.messages = io.StringIO()
        self.stderr = patch.object(pins.sys, 'stderr', self.messages)
        self.stderr.start()
        self.addCleanup(self.stderr.stop)
        self.sleep = patch.object(pins.time, 'sleep').start()
        self.addCleanup(patch.stopall)

    def test_windows_reset_during_connect_retries_with_asset_context(self):
        failure = OSError('remote host reset connection')
        failure.winerror = 10054
        with patch.object(pins.urllib.request, 'urlopen',
                          side_effect=[failure, io.BytesIO(self.payload)]) as network:
            self.assertEqual(pins.fetch_asset(self.asset), self.payload)
        self.assertEqual(network.call_count, 2)
        self.sleep.assert_called_once_with(1)
        self.assertIn('fixed.bin (attempt 2/3)', self.messages.getvalue())
        self.assertIn(self.asset['url'], self.messages.getvalue())
        self.assertIn('Retrying in 1 second', self.messages.getvalue())
        for entry in network.call_args_list:
            self.assertEqual(entry.kwargs, {'timeout': 90})
            self.assertEqual(entry.args[0].full_url, self.asset['url'])

    def test_reset_during_read_closes_response_and_caches_only_verified_retry(self):
        interrupted = InterruptedResponse()
        with tempfile.TemporaryDirectory() as directory:
            cache = Path(directory)
            with patch.object(pins.urllib.request, 'urlopen',
                              side_effect=[interrupted, io.BytesIO(self.payload)]):
                self.assertEqual(pins.fetch_asset(self.asset, cache), self.payload)
            self.assertTrue(interrupted.closed)
            self.assertEqual((cache / self.asset['name']).read_bytes(), self.payload)
            self.assertEqual([path.name for path in cache.iterdir()], [self.asset['name']])

    def test_repeated_resets_stop_after_three_attempts_and_preserve_other_cache(self):
        with tempfile.TemporaryDirectory() as directory:
            cache = Path(directory)
            previous = cache / 'previous-verified.bin'
            previous.write_bytes(b'keep this')
            with patch.object(pins.urllib.request, 'urlopen',
                              side_effect=ConnectionResetError(10054, 'reset')) as network:
                with self.assertRaisesRegex(RuntimeError, 'fixed.bin.*https://.*after 3 attempt'):
                    pins.fetch_asset(self.asset, cache)
            self.assertEqual(network.call_count, 3)
            self.assertEqual(self.sleep.call_args_list, [call(1), call(2)])
            self.assertEqual(previous.read_bytes(), b'keep this')
            self.assertEqual(list(cache.iterdir()), [previous])

    def test_wrapped_timeout_and_temporary_dns_failure_retry(self):
        for error in (TimeoutError('timed out'), socket.gaierror(socket.EAI_AGAIN, 'try again')):
            with self.subTest(error=error), patch.object(pins.urllib.request, 'urlopen',
                    side_effect=[urllib.error.URLError(error), io.BytesIO(self.payload)]) as network:
                self.assertEqual(pins.fetch_asset(self.asset), self.payload)
                self.assertEqual(network.call_count, 2)

    def test_temporary_http_error_retries(self):
        error = urllib.error.HTTPError(self.asset['url'], 503, 'Unavailable', {}, None)
        with patch.object(pins.urllib.request, 'urlopen',
                          side_effect=[error, io.BytesIO(self.payload)]) as network:
            self.assertEqual(pins.fetch_asset(self.asset), self.payload)
        self.assertEqual(network.call_count, 2)

    def test_permanent_http_dns_and_tls_errors_fail_without_retry(self):
        errors = (urllib.error.HTTPError(self.asset['url'], 404, 'Not Found', {}, None),
                  urllib.error.URLError(socket.gaierror(socket.EAI_NONAME, 'unknown host')),
                  urllib.error.URLError(ssl.SSLCertVerificationError(1, 'bad certificate')))
        for error in errors:
            with self.subTest(error=error), patch.object(pins.urllib.request, 'urlopen',
                                                       side_effect=error) as network:
                with self.assertRaisesRegex(RuntimeError, 'fixed.bin.*after 1 attempt'):
                    pins.fetch_asset(self.asset)
                network.assert_called_once()
        self.sleep.assert_not_called()

    def test_incomplete_http_response_retries(self):
        error = pins.http.client.IncompleteRead(b'partial', len(self.payload))
        with patch.object(pins.urllib.request, 'urlopen',
                          side_effect=[error, io.BytesIO(self.payload)]) as network:
            self.assertEqual(pins.fetch_asset(self.asset), self.payload)
        self.assertEqual(network.call_count, 2)

    def test_wrong_digest_or_size_is_never_retried_or_cached(self):
        for payload in (b'X' + self.payload[1:], self.payload[:-1]):
            with self.subTest(payload=payload), tempfile.TemporaryDirectory() as directory:
                cache = Path(directory)
                with patch.object(pins.urllib.request, 'urlopen',
                                  return_value=io.BytesIO(payload)) as network:
                    with self.assertRaisesRegex(ValueError, 'size/SHA-256.*fixed.bin'):
                        pins.fetch_asset(self.asset, cache)
                network.assert_called_once()
                self.assertEqual(list(cache.iterdir()), [])
        self.sleep.assert_not_called()

    def test_valid_cache_requires_neither_network_nor_cache_write(self):
        with tempfile.TemporaryDirectory() as directory:
            cache = Path(directory)
            (cache / self.asset['name']).write_bytes(self.payload)
            with patch.object(pins.urllib.request, 'urlopen') as network, \
                    patch.object(pins.tempfile, 'NamedTemporaryFile') as temporary:
                self.assertEqual(pins.fetch_asset(self.asset, cache), self.payload)
            network.assert_not_called()
            temporary.assert_not_called()

    def test_corrupt_cache_fails_closed_without_replacing_or_redownloading(self):
        with tempfile.TemporaryDirectory() as directory:
            cache = Path(directory)
            target = cache / self.asset['name']
            target.write_bytes(b'tampered')
            with patch.object(pins.urllib.request, 'urlopen') as network:
                with self.assertRaisesRegex(ValueError, 'size/SHA-256.*fixed.bin'):
                    pins.fetch_asset(self.asset, cache)
            network.assert_not_called()
            self.assertEqual(target.read_bytes(), b'tampered')

    def test_existing_partial_link_is_not_followed_or_overwritten(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            cache = root / 'cache'
            cache.mkdir()
            foreign = root / 'foreign.bin'
            foreign.write_bytes(b'leave intact')
            link = cache / (self.asset['name'] + '.partial')
            try:
                link.symlink_to(foreign)
            except OSError as error:
                self.skipTest(str(error))
            with patch.object(pins.urllib.request, 'urlopen', return_value=io.BytesIO(self.payload)):
                self.assertEqual(pins.fetch_asset(self.asset, cache), self.payload)
            self.assertEqual(foreign.read_bytes(), b'leave intact')
            self.assertTrue(link.is_symlink())
            self.assertEqual((cache / self.asset['name']).read_bytes(), self.payload)

    def test_failed_cache_publish_cleans_temporary_file(self):
        with tempfile.TemporaryDirectory() as directory:
            cache = Path(directory)
            with patch.object(pins.urllib.request, 'urlopen', return_value=io.BytesIO(self.payload)), \
                    patch.object(Path, 'replace', side_effect=OSError('disk write failed')):
                with self.assertRaisesRegex(OSError, 'disk write failed'):
                    pins.fetch_asset(self.asset, cache)
            self.assertEqual(list(cache.iterdir()), [])

    def test_all_pinned_licenses_are_bundled_and_verified_without_network(self):
        with patch.object(pins.urllib.request, 'urlopen') as network:
            for key in ('mihomo_license', 'proxifyre_license', 'ndisapi_license'):
                with self.subTest(key=key):
                    asset = pins.ASSETS[key]
                    data = pins.fetch_asset(dict(asset))
                    self.assertEqual(hashlib.sha256(data).hexdigest(), asset['sha256'])
            network.assert_not_called()

    def test_missing_or_tampered_bundled_license_has_no_network_or_cache_fallback(self):
        asset = pins.ASSETS['proxifyre_license']
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            licenses = root / 'licenses'
            licenses.mkdir()
            cache = root / 'cache'
            cache.mkdir()
            (cache / asset['name']).write_bytes(b'no fallback to cache')
            with patch.object(pins, '__file__', str(root / 'windows_proxy_pins.py')), \
                    patch.object(pins.urllib.request, 'urlopen') as network:
                with self.assertRaisesRegex(ValueError, 'Bundled Windows license is missing'):
                    pins.fetch_asset(asset, cache)
                (licenses / asset['name']).write_bytes(b'modified bundled license')
                with self.assertRaisesRegex(ValueError, 'size/SHA-256.*PROXIFYRE-LICENSE'):
                    pins.fetch_asset(asset, cache)
                network.assert_not_called()


if __name__ == '__main__':
    unittest.main()
