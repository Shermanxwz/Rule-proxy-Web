"""Render the existing CSS brand mark as PNG/ICO, with no imaging dependency.

Geometry and colours match web/favicon.svg and the original .brand-mark CSS.
Run from any directory; generated files belong in web/ alongside the SVG.
"""
import math
from pathlib import Path
import struct
import zlib

ROOT = Path(__file__).resolve().parents[1]
GREEN = (22, 125, 97)


def rounded(x, y, left, top, width, height, radius):
    dx = max(left + radius - x, 0, x - (left + width - radius))
    dy = max(top + radius - y, 0, y - (top + height - radius))
    return dx * dx + dy * dy <= radius * radius


def colour(x, y):
    angle = math.radians(5)
    c, s = math.cos(angle), math.sin(angle)
    dx, dy = x - 12.5, y - 12.5
    bx, by = c * dx - s * dy + 12.5, s * dx + c * dy + 12.5
    if not rounded(bx, by, 0, 0, 25, 25, 8):
        return (0, 0, 0, 0)
    for cx, height, opacity in ((7.5, 8, .7), (12.5, 13, 1), (17.5, 9, .8)):
        # CSS counter-rotates each bar so the three strokes stay upright.
        px = (cx - 12.5) * c + 12.5
        py = -(cx - 12.5) * s + 12.5
        if rounded(x, y, px - 1.5, py - height / 2, 3, height, 1.5):
            return tuple(round(v * (1 - opacity) + 255 * opacity) for v in GREEN) + (255,)
    return GREEN + (255,)


def png(size):
    samples = 4
    raw = bytearray()
    for y in range(size):
        raw.append(0)
        for x in range(size):
            pixels = [colour((x + (sx + .5) / samples) * 31 / size - 3,
                             (y + (sy + .5) / samples) * 31 / size - 3)
                      for sy in range(samples) for sx in range(samples)]
            alpha = sum(p[3] for p in pixels)
            raw.extend(round(sum(p[i] * p[3] for p in pixels) / alpha) if alpha else 0
                       for i in range(3))
            raw.append(round(alpha / (samples * samples)))

    def chunk(kind, data):
        return struct.pack('!I', len(data)) + kind + data + struct.pack('!I', zlib.crc32(kind + data))

    return (b'\x89PNG\r\n\x1a\n' + chunk(b'IHDR', struct.pack('!2I5B', size, size, 8, 6, 0, 0, 0))
            + chunk(b'IDAT', zlib.compress(raw, 9)) + chunk(b'IEND', b''))


if __name__ == '__main__':
    small = png(32)
    (ROOT / 'web/favicon-32.png').write_bytes(small)
    (ROOT / 'web/apple-touch-icon.png').write_bytes(png(180))
    icon = struct.pack('<3H', 0, 1, 1) + struct.pack('<4B2H2I', 32, 32, 0, 0, 1, 32, len(small), 22) + small
    (ROOT / 'web/favicon.ico').write_bytes(icon)
