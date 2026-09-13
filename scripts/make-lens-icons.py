#!/usr/bin/env python3
"""Render the Lens PWA icons from static/lens-icon.svg's geometry, with no dependencies.

Home SOC vendors no image library and no external assets, so the PNGs in ``homesoc/web/static``
are drawn here with ``zlib`` and ``struct`` and checked in. Run this only when the artwork
changes:

    python scripts/make-lens-icons.py

It writes ``lens-icon-192.png``, ``lens-icon-512.png`` and ``lens-icon-maskable-512.png``. The
maskable one is the same glyph inside the 80% safe zone Android's adaptive-icon mask needs, on a
full-bleed background: a ``purpose: "any"`` icon whose artwork reaches the edges (as the rounded
square in lens-icon.svg does) gets cropped or letterboxed once the launcher applies its mask.
"""

from __future__ import annotations

import math
import struct
import zlib
from pathlib import Path

STATIC = Path(__file__).resolve().parent.parent / "homesoc" / "web" / "static"

BG = (0x0B, 0x0D, 0x13)
INK = (0xF3, 0xF5, 0xFB)
ACCENT = (0x6B, 0x8A, 0xFD)

SS = 3  # supersampling factor; the glyph is all curves and thin strokes


def _rounded_square(x: float, y: float, size: int, radius: float) -> bool:
    """Inside the rounded square [0,size]^2 with corner radius ``radius``?"""
    cx = min(max(x, radius), size - radius)
    cy = min(max(y, radius), size - radius)
    return (x - cx) ** 2 + (y - cy) ** 2 <= radius**2


def _on_segment(x: float, y: float, x0: float, y0: float, x1: float, y1: float, half: float) -> bool:
    dx, dy = x1 - x0, y1 - y0
    length_sq = dx * dx + dy * dy
    t = 0.0 if length_sq == 0 else max(0.0, min(1.0, ((x - x0) * dx + (y - y0) * dy) / length_sq))
    px, py = x0 + t * dx, y0 + t * dy
    return (x - px) ** 2 + (y - py) ** 2 <= half * half


def _glyph_shapes(scale: float, ox: float, oy: float) -> tuple[list, list, tuple]:
    """The reticle in lens-icon.svg's 192-unit space, mapped by ``scale`` and offset."""

    def pt(x: float, y: float) -> tuple[float, float]:
        return (ox + x * scale, oy + y * scale)

    bracket_half = 9 * scale / 2
    brackets = [
        (pt(33, 66), pt(33, 33)), (pt(33, 33), pt(66, 33)),
        (pt(126, 33), pt(159, 33)), (pt(159, 33), pt(159, 66)),
        (pt(159, 126), pt(159, 159)), (pt(159, 159), pt(126, 159)),
        (pt(66, 159), pt(33, 159)), (pt(33, 159), pt(33, 126)),
    ]
    centre = pt(96, 96)
    ring = (centre, 55 * scale, 10 * scale / 2)
    dot = (centre, 14 * scale)
    return [(a, b, bracket_half) for a, b in brackets], [ring], dot


def render(size: int, *, maskable: bool) -> bytes:
    """Return PNG bytes for one icon."""
    # A maskable icon keeps the whole glyph inside the central 80%; a plain one fills the canvas
    # the way the SVG does.
    inset = 0.10 * size if maskable else 0.0
    span = size - 2 * inset
    scale = span / 192.0
    brackets, rings, dot = _glyph_shapes(scale, inset, inset)
    (dot_c, dot_r) = dot
    radius = 0.0 if maskable else 42.0 * (size / 192.0)

    rows = []
    for py in range(size):
        row = bytearray()
        for px in range(size):
            r_acc = g_acc = b_acc = 0
            for sy in range(SS):
                for sx in range(SS):
                    x = px + (sx + 0.5) / SS
                    y = py + (sy + 0.5) / SS
                    if not maskable and not _rounded_square(x, y, size, radius):
                        colour = (0, 0, 0)  # outside the rounded square: transparent-looking black
                    else:
                        colour = BG
                        if any(_on_segment(x, y, a[0], a[1], b[0], b[1], half) for a, b, half in brackets):
                            colour = INK
                        else:
                            for (cx, cy), rad, half in rings:
                                if abs(math.hypot(x - cx, y - cy) - rad) <= half:
                                    colour = ACCENT
                                    break
                            if (x - dot_c[0]) ** 2 + (y - dot_c[1]) ** 2 <= dot_r * dot_r:
                                colour = INK
                    r_acc += colour[0]
                    g_acc += colour[1]
                    b_acc += colour[2]
            n = SS * SS
            row += bytes((r_acc // n, g_acc // n, b_acc // n))
        rows.append(bytes(row))

    raw = b"".join(b"\x00" + r for r in rows)

    def chunk(tag: bytes, data: bytes) -> bytes:
        return (struct.pack(">I", len(data)) + tag + data
                + struct.pack(">I", zlib.crc32(tag + data) & 0xFFFFFFFF))

    header = struct.pack(">IIBBBBB", size, size, 8, 2, 0, 0, 0)  # 8-bit truecolour
    return (b"\x89PNG\r\n\x1a\n" + chunk(b"IHDR", header)
            + chunk(b"IDAT", zlib.compress(raw, 9)) + chunk(b"IEND", b""))


def main() -> None:
    # Only the maskable variant is generated here. lens-icon-192.png and lens-icon-512.png are
    # the existing `purpose: "any"` artwork and are left exactly as they are.
    target = STATIC / "lens-icon-maskable-512.png"
    target.write_bytes(render(512, maskable=True))
    print(f"wrote {target} ({target.stat().st_size:,} bytes)")


if __name__ == "__main__":
    main()
