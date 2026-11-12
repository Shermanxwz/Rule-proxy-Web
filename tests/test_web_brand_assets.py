"""Brand assets through the real loopback HTTP handler; no Manager or native constructor."""
import http.client
from http.server import ThreadingHTTPServer
from html.parser import HTMLParser
import importlib.util
from pathlib import Path
import re
import struct
import threading
import unittest
from unittest.mock import Mock, patch
import xml.etree.ElementTree as ET
import zlib

from ruleproxy.server import Handler


ROOT = Path(__file__).resolve().parents[1]
ASSETS = {
    '/favicon.ico': ('favicon.ico', 'image/x-icon'),
    '/web/favicon.ico': ('favicon.ico', 'image/x-icon'),
    '/web/favicon.svg': ('favicon.svg', 'image/svg+xml'),
    '/web/favicon-32.png': ('favicon-32.png', 'image/png'),
    '/web/apple-touch-icon.png': ('apple-touch-icon.png', 'image/png'),
}


def load_module(name, path):
    spec = importlib.util.spec_from_file_location(name, path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


class Links(HTMLParser):
    def __init__(self, html):
        super().__init__()
        self.links = []
        self.feed(html)

    def handle_starttag(self, tag, attrs):
        if tag == 'link':
            self.links.append(dict(attrs))


class BrandAssetHTTPTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        # PanelServer.__init__ may inspect native Windows account identity.
        # Only exercise Handler/static routes on a plain ephemeral loopback server.
        cls.server = ThreadingHTTPServer(('127.0.0.1', 0), Handler)
        cls.server.client_identity = None
        cls.server.manager = Mock(spec=[])
        cls.worker = threading.Thread(target=cls.server.serve_forever,
                                      kwargs={'poll_interval': 0.01}, daemon=True)
        cls.worker.start()
        cls.addClassCleanup(cls.shutdown_server)

    @classmethod
    def shutdown_server(cls):
        cls.server.shutdown()
        cls.worker.join(timeout=5)
        cls.server.server_close()
        if cls.worker.is_alive():
            raise AssertionError('fixture HTTP server did not stop')

    def request(self, path, *, headers=None):
        host, port = self.server.server_address
        connection = http.client.HTTPConnection(host, port, timeout=5)
        try:
            connection.request('GET', path, headers={
                'Origin': f'http://{host}:{port}', 'Sec-Fetch-Site': 'same-origin', **(headers or {})})
            response = connection.getresponse()
            body = response.read()
            return response.status, dict(response.getheaders()), body
        finally:
            connection.close()

    def test_icon_routes_return_exact_bytes_mime_and_protection_headers(self):
        for route, (name, mime) in ASSETS.items():
            with self.subTest(route=route):
                status, headers, body = self.request(route)
                self.assertEqual(status, 200)
                self.assertEqual(body, (ROOT / 'web' / name).read_bytes())
                self.assertEqual(headers['Content-Type'], mime)
                self.assertNotIn('charset', headers['Content-Type'])
                self.assertEqual(int(headers['Content-Length']), len(body))
                self.assertEqual(headers['X-Content-Type-Options'], 'nosniff')
                self.assertEqual(headers['Cache-Control'], 'no-store')
                csp = headers['Content-Security-Policy']
                self.assertIn("default-src 'self'", csp)
                self.assertIn("img-src 'self' data:", csp)
                self.assertIn("frame-ancestors 'none'", csp)
                self.assertIn("base-uri 'none'", csp)
        self.assertEqual(self.server.manager.mock_calls, [])

    def test_favicon_alias_and_query_return_same_ico(self):
        expected = (ROOT / 'web/favicon.ico').read_bytes()
        for route in ('/favicon.ico', '/web/favicon.ico', '/favicon.ico?v=brand', '/web/favicon.ico?v=brand'):
            with self.subTest(route=route):
                status, headers, body = self.request(route)
                self.assertEqual(status, 200)
                self.assertEqual(headers['Content-Type'], 'image/x-icon')
                self.assertEqual(body, expected)

    def test_served_html_links_all_supported_brand_icons(self):
        status, headers, body = self.request('/')
        self.assertEqual(status, 200)
        self.assertIn('text/html', headers['Content-Type'])
        self.assertEqual(body, (ROOT / 'web/index.html').read_bytes())
        links = Links(body.decode('utf-8')).links
        icons = {link['href']: link for link in links if link.get('rel') in {'icon', 'apple-touch-icon'}}
        self.assertIn('/favicon.ico', icons)
        self.assertEqual(icons['/favicon.ico'].get('sizes'), '32x32')
        self.assertEqual(icons['/web/favicon.svg'].get('type'), 'image/svg+xml')
        self.assertEqual(icons['/web/apple-touch-icon.png']['rel'], 'apple-touch-icon')
        for route in icons:
            with self.subTest(route=route):
                self.assertIn(route, ASSETS)
                self.assertEqual(self.request(route)[0], 200)

    def test_unlisted_and_traversal_paths_return_404_without_file_reads(self):
        paths = ('/web/../ruleproxy/manager.py', '/web/../../LICENSE',
                 '/web/%2e%2e/ruleproxy/server.py', '/web/%2e%2e%2fruleproxy/server.py',
                 '/favicon.ico/../server.py', '/web/favicon.svg/../../README.md',
                 '/web/favicon-32.png%00.html', '/web/unlisted.png')
        with patch.object(Path, 'read_bytes', side_effect=AssertionError('unlisted static file read')):
            for path in paths:
                with self.subTest(path=path):
                    status, headers, body = self.request(path)
                    self.assertEqual(status, 404)
                    self.assertEqual(headers['X-Content-Type-Options'], 'nosniff')
                    self.assertNotIn(b'Own only this panel', body)

    def test_cross_site_or_foreign_host_cannot_read_brand_assets(self):
        for route in ASSETS:
            for headers in ({'Host': 'other.example'}, {'Origin': 'http://other.example'},
                            {'Sec-Fetch-Site': 'cross-site'}):
                with self.subTest(route=route, headers=headers):
                    status, response_headers, body = self.request(route, headers=headers)
                    self.assertEqual(status, 403)
                    self.assertIn('application/json', response_headers['Content-Type'])
                    self.assertNotEqual(body, (ROOT / 'web' / ASSETS[route][0]).read_bytes())


class BrandAssetFormatTests(unittest.TestCase):
    def parse_png(self, data, size):
        self.assertEqual(data[:8], b'\x89PNG\r\n\x1a\n')
        offset, chunks = 8, []
        while offset < len(data):
            self.assertGreaterEqual(len(data) - offset, 12)
            length, kind = struct.unpack_from('!I4s', data, offset)
            payload = data[offset + 8:offset + 8 + length]
            self.assertEqual(len(payload), length)
            checksum, = struct.unpack_from('!I', data, offset + 8 + length)
            self.assertEqual(checksum, zlib.crc32(kind + payload))
            chunks.append((kind, payload))
            offset += length + 12
        self.assertEqual(offset, len(data))
        self.assertEqual(chunks[0][0], b'IHDR')
        self.assertEqual(struct.unpack('!2I5B', chunks[0][1]), (size, size, 8, 6, 0, 0, 0))
        self.assertEqual(chunks[-1], (b'IEND', b''))
        raw = zlib.decompress(b''.join(payload for kind, payload in chunks if kind == b'IDAT'))
        stride = size * 4 + 1
        self.assertEqual(len(raw), size * stride)
        self.assertTrue(all(raw[y * stride] == 0 for y in range(size)))
        alphas = {raw[y * stride + 1 + x * 4 + 3] for y in range(size) for x in range(size)}
        self.assertIn(0, alphas)
        self.assertIn(255, alphas)
        return raw

    def test_png_headers_dimensions_alpha_and_chunk_checksums(self):
        for name, size in (('favicon-32.png', 32), ('apple-touch-icon.png', 180)):
            with self.subTest(name=name):
                self.parse_png((ROOT / 'web' / name).read_bytes(), size)

    def test_ico_directory_points_to_exact_32_pixel_png(self):
        data = (ROOT / 'web/favicon.ico').read_bytes()
        self.assertEqual(struct.unpack_from('<3H', data), (0, 1, 1))
        width, height, colors, reserved, planes, depth, length, offset = struct.unpack_from('<4B2H2I', data, 6)
        self.assertEqual((width, height, colors, reserved, planes, depth), (32, 32, 0, 0, 1, 32))
        self.assertEqual(offset, 22)
        self.assertEqual(offset + length, len(data))
        self.assertEqual(data[offset:], (ROOT / 'web/favicon-32.png').read_bytes())
        self.parse_png(data[offset:], 32)

    def test_svg_is_self_contained_brand_geometry(self):
        svg = ET.fromstring((ROOT / 'web/favicon.svg').read_text(encoding='utf-8'))
        self.assertEqual(svg.tag, '{http://www.w3.org/2000/svg}svg')
        self.assertEqual(svg.attrib['viewBox'], '-3 -3 31 31')
        rects = list(svg.iter('{http://www.w3.org/2000/svg}rect'))
        self.assertEqual(len(rects), 4)
        self.assertEqual(rects[0].attrib['fill'], '#167d61')
        for node in svg.iter():
            self.assertIn(node.tag.rsplit('}', 1)[-1], {'svg', 'rect', 'g'})
            self.assertFalse(any(key.rsplit('}', 1)[-1] == 'href' for key in node.attrib))

    def test_generator_is_pure_and_reproducible(self):
        with patch.object(Path, 'write_bytes', side_effect=AssertionError('generator wrote during import')):
            generator = load_module('_brand_icon_generator', ROOT / 'scripts/generate_web_icons.py')
            self.assertEqual(generator.colour(-4, -4), (0, 0, 0, 0))
            self.assertEqual(generator.colour(12.5, 12.5), (255, 255, 255, 255))
            self.assertEqual(generator.colour(2, 12.5), (*generator.GREEN, 255))
            first = generator.png(32)
            second = generator.png(32)
        self.assertEqual(first, second)
        self.assertEqual(first, (ROOT / 'web/favicon-32.png').read_bytes())
        self.parse_png(first, 32)

    def test_packaging_includes_all_brand_assets_without_downloads(self):
        builder = load_module('_brand_asset_package_builder', ROOT / '.github/build_windows_package.py')
        with patch.object(builder, 'download', side_effect=AssertionError('asset enumeration downloaded')):
            files = builder.project_files()
        for name in {name for name, _ in ASSETS.values()} | {'index.html', 'app.js', 'style.css'}:
            with self.subTest(name=name):
                self.assertIn('web/' + name, files)

    def test_setup_requires_all_brand_assets_and_new_runtime_modules_before_dependencies(self):
        # Static only: never execute PowerShell, installation or native checks.
        source = (ROOT / 'scripts/windows-setup.ps1').read_text(encoding='utf-8')
        check = re.search(r"    foreach \(\$required in @\((.*?)\)\) \{\n.*?\n    \}", source, re.S)
        self.assertIsNotNone(check, 'Windows setup must retain the required-product-file gate')
        required = set(re.findall(r"'([^']+)'", check.group(1)))
        for name in (r'web\favicon.ico', r'web\favicon.svg', r'web\favicon-32.png',
                     r'web\apple-touch-icon.png', r'ruleproxy\windows_local_ipc.py',
                     r'ruleproxy\windows_web_apps.py', r'ruleproxy\web_app_leveldb.py'):
            with self.subTest(name=name):
                self.assertIn(name, required)
        self.assertIn('Test-Path -LiteralPath (Join-Path $stage $required) -PathType Leaf', check.group())
        self.assertIn("throw ('Required product file missing: ' + $required)", check.group())
        self.assertLess(check.end(), source.index("$setupPhase = 'dependencies'"))


if __name__ == '__main__':
    unittest.main()
