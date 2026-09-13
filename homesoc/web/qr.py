"""A small, dependency-free QR encoder (SPEC addendum B4).

Lens needs a QR code on the pairing screen and on printed stickers, and the project
may not add runtime dependencies or load anything from a CDN, so the encoder lives
here. Scope is deliberately the smallest thing that serves those two jobs:

* **byte mode** only (the payloads are ASCII URLs and ``hs1:`` sticker tokens),
* **error correction level M** (~15% recovery — the level ISO recommends for print),
* **versions 1-10** (up to 213 bytes at level M, comfortably more than a
  ``https://192.168.x.x:8443/lens/claim#c=XXXXXXXX`` URL needs).

Everything else is the real thing: Reed-Solomon error correction over GF(256),
block interleaving, all eight data masks scored by the standard penalty rules,
and the full function, format and version information patterns. The output is a
plain matrix of booleans (``True`` = dark), rendered as SVG for the browser and
as text for the terminal.

Coordinates are ``(row, column)`` with the origin at the top-left, matching the
way the matrix is indexed and printed.

The module is pure: no I/O, no clock, no randomness. The same payload always
produces the same matrix, which is what makes ``tests/test_qr.py`` able to
compare against fixed known-good fixtures.
"""

from __future__ import annotations

import logging
from dataclasses import dataclass
from typing import Iterable, Sequence

logger = logging.getLogger(__name__)

#: Supported version range (a version's side length is ``4 * version + 17`` modules).
MIN_VERSION = 1
MAX_VERSION = 10

#: Error correction level. Only M is implemented; the constant exists so the format
#: information bits below are not a bare magic number.
EC_LEVEL = "M"
_EC_FORMAT_BITS = 0b00  # L=01, M=00, Q=11, H=10 (ISO/IEC 18004 table 12)

_BYTE_MODE = 0b0100

# Total codewords (data + error correction) per version, ISO/IEC 18004 table 1.
_TOTAL_CODEWORDS: dict[int, int] = {
    1: 26, 2: 44, 3: 70, 4: 100, 5: 134, 6: 172, 7: 196, 8: 242, 9: 292, 10: 346,
}

# Level-M block structure per version: (ec codewords per block, [(block count, data codewords), ...]).
# ISO/IEC 18004 table 13-22. Two group sizes appear from version 8 onwards.
_EC_BLOCKS_M: dict[int, tuple[int, tuple[tuple[int, int], ...]]] = {
    1: (10, ((1, 16),)),
    2: (16, ((1, 28),)),
    3: (26, ((1, 44),)),
    4: (18, ((2, 32),)),
    5: (24, ((2, 43),)),
    6: (16, ((4, 27),)),
    7: (18, ((4, 31),)),
    8: (22, ((2, 38), (2, 39))),
    9: (22, ((3, 36), (2, 37))),
    10: (26, ((4, 43), (1, 44))),
}

# Centre coordinates of the alignment patterns, ISO/IEC 18004 annex E. Every
# combination of two coordinates carries a pattern except the three that would
# collide with a finder pattern.
_ALIGNMENT_POSITIONS: dict[int, tuple[int, ...]] = {
    1: (),
    2: (6, 18),
    3: (6, 22),
    4: (6, 26),
    5: (6, 30),
    6: (6, 34),
    7: (6, 22, 38),
    8: (6, 24, 42),
    9: (6, 26, 46),
    10: (6, 28, 50),
}

# Bits left over after the last codeword, ISO/IEC 18004 table 1. They are always zero.
_REMAINDER_BITS: dict[int, int] = {1: 0, 2: 7, 3: 7, 4: 7, 5: 7, 6: 7, 7: 0, 8: 0, 9: 0, 10: 0}

# Penalty weights for mask selection, ISO/IEC 18004 table 24.
_PENALTY_N1 = 3
_PENALTY_N2 = 3
_PENALTY_N3 = 40
_PENALTY_N4 = 10

_PAD_BYTES = (0xEC, 0x11)


class QrError(ValueError):
    """The payload does not fit in a version 1-10 level-M byte-mode code."""


# ------------------------------------------------------------------ GF(256)

# Arithmetic for Reed-Solomon, over GF(2^8) with the QR primitive polynomial
# x^8 + x^4 + x^3 + x^2 + 1 (0x11D) and generator 2.
_GF_EXP: list[int] = [0] * 512
_GF_LOG: list[int] = [0] * 256


def _init_gf() -> None:
    value = 1
    for power in range(255):
        _GF_EXP[power] = value
        _GF_LOG[value] = power
        value <<= 1
        if value & 0x100:
            value ^= 0x11D
    for power in range(255, 512):
        _GF_EXP[power] = _GF_EXP[power - 255]


_init_gf()


def _gf_mul(a: int, b: int) -> int:
    if a == 0 or b == 0:
        return 0
    return _GF_EXP[_GF_LOG[a] + _GF_LOG[b]]


def _rs_generator(degree: int) -> list[int]:
    """Coefficients (highest power first) of the generator polynomial of ``degree``."""
    poly = [1]
    for power in range(degree):
        nxt = [0] * (len(poly) + 1)
        for i, coeff in enumerate(poly):
            nxt[i] ^= coeff
            nxt[i + 1] ^= _gf_mul(coeff, _GF_EXP[power])
        poly = nxt
    return poly


def rs_encode(data: Sequence[int], ec_codewords: int) -> list[int]:
    """Reed-Solomon error correction codewords for one block.

    Exposed (rather than private) because it is the piece with the least forgiving
    arithmetic: ``tests/test_qr.py`` checks it against the worked example in the
    ISO specification before trusting anything built on top of it.
    """
    generator = _rs_generator(ec_codewords)
    remainder = [0] * ec_codewords
    for byte in data:
        factor = byte ^ remainder[0]
        remainder = remainder[1:] + [0]
        if factor:
            log_factor = _GF_LOG[factor]
            for i, coeff in enumerate(generator[1:]):
                if coeff:
                    remainder[i] ^= _GF_EXP[log_factor + _GF_LOG[coeff]]
    return remainder


# ------------------------------------------------------------------ capacity


def _count_bits(version: int) -> int:
    """Width of the byte-mode character count indicator (8 bits below version 10)."""
    return 8 if version < 10 else 16


def data_codewords(version: int) -> int:
    ec_per_block, groups = _EC_BLOCKS_M[version]
    return sum(count * size for count, size in groups)


def capacity_bytes(version: int) -> int:
    """How many payload bytes fit in ``version`` at level M."""
    usable_bits = data_codewords(version) * 8 - 4 - _count_bits(version)
    return usable_bits // 8


def _choose_version(length: int, min_version: int, max_version: int) -> int:
    for version in range(max(MIN_VERSION, min_version), min(MAX_VERSION, max_version) + 1):
        if length <= capacity_bytes(version):
            return version
    raise QrError(
        f"{length} bytes do not fit in a version {min_version}-{max_version} level-{EC_LEVEL} QR code "
        f"(maximum {capacity_bytes(min(MAX_VERSION, max_version))} bytes)"
    )


# ------------------------------------------------------------------ bit stream


def _bit_stream(payload: bytes, version: int) -> list[int]:
    """Mode indicator, length, data, terminator and padding — the data codeword bits."""
    bits: list[int] = []

    def push(value: int, width: int) -> None:
        for shift in range(width - 1, -1, -1):
            bits.append((value >> shift) & 1)

    push(_BYTE_MODE, 4)
    push(len(payload), _count_bits(version))
    for byte in payload:
        push(byte, 8)
    capacity = data_codewords(version) * 8
    push(0, min(4, capacity - len(bits)))  # terminator
    if len(bits) % 8:
        push(0, 8 - len(bits) % 8)
    for index in range((capacity - len(bits)) // 8):
        push(_PAD_BYTES[index % 2], 8)
    return bits


def _bits_to_codewords(bits: Sequence[int]) -> list[int]:
    return [int("".join(str(b) for b in bits[i:i + 8]), 2) for i in range(0, len(bits), 8)]


def _interleave(codewords: Sequence[int], version: int) -> list[int]:
    """Split into blocks, add error correction, and interleave as ISO section 8.6 requires."""
    ec_per_block, groups = _EC_BLOCKS_M[version]
    blocks: list[list[int]] = []
    ec_blocks: list[list[int]] = []
    offset = 0
    for count, size in groups:
        for _ in range(count):
            block = list(codewords[offset:offset + size])
            offset += size
            blocks.append(block)
            ec_blocks.append(rs_encode(block, ec_per_block))
    out: list[int] = []
    for index in range(max(len(b) for b in blocks)):
        for block in blocks:
            if index < len(block):
                out.append(block[index])
    for index in range(ec_per_block):
        for block in ec_blocks:
            out.append(block[index])
    return out


# ------------------------------------------------------------------ matrix


class _Canvas:
    """Mutable module grid plus the mask of function (non-data) modules."""

    __slots__ = ("version", "size", "modules", "reserved")

    def __init__(self, version: int) -> None:
        self.version = version
        self.size = version * 4 + 17
        self.modules: list[list[bool]] = [[False] * self.size for _ in range(self.size)]
        self.reserved: list[list[bool]] = [[False] * self.size for _ in range(self.size)]

    def set_function(self, row: int, col: int, dark: bool) -> None:
        if 0 <= row < self.size and 0 <= col < self.size:
            self.modules[row][col] = dark
            self.reserved[row][col] = True

    def reserve(self, row: int, col: int) -> None:
        if 0 <= row < self.size and 0 <= col < self.size:
            self.reserved[row][col] = True

    # ------------------------------------------------------------ patterns

    def draw_function_patterns(self) -> None:
        for i in range(self.size):
            dark = i % 2 == 0
            self.set_function(6, i, dark)
            self.set_function(i, 6, dark)
        # The finders (and their separators) are drawn second: they legitimately
        # overwrite the ends of both timing patterns.
        for row, col in ((3, 3), (3, self.size - 4), (self.size - 4, 3)):
            self._finder(row, col)
        positions = _ALIGNMENT_POSITIONS[self.version]
        corners = {(positions[0], positions[0]), (positions[0], positions[-1]),
                   (positions[-1], positions[0])} if positions else set()
        for row in positions:
            for col in positions:
                if (row, col) not in corners:
                    self._alignment(row, col)
        self._reserve_format_areas()
        if self.version >= 7:
            self._version_info()

    def _finder(self, row: int, col: int) -> None:
        """The 7x7 finder plus its one-module light separator."""
        for d_row in range(-4, 5):
            for d_col in range(-4, 5):
                distance = max(abs(d_row), abs(d_col))
                self.set_function(row + d_row, col + d_col, distance not in (2, 4))

    def _alignment(self, row: int, col: int) -> None:
        for d_row in range(-2, 3):
            for d_col in range(-2, 3):
                self.set_function(row + d_row, col + d_col, max(abs(d_row), abs(d_col)) != 1)

    def _reserve_format_areas(self) -> None:
        """Keep the 31 format-information modules (plus the dark module) out of the data flow."""
        for i in range(9):
            self.reserve(8, i)
            self.reserve(i, 8)
        for i in range(8):
            self.reserve(8, self.size - 1 - i)
            self.reserve(self.size - 1 - i, 8)
        self.set_function(self.size - 8, 8, True)  # the always-dark module

    def _version_info(self) -> None:
        remainder = self.version
        for _ in range(12):
            remainder = (remainder << 1) ^ ((remainder >> 11) * 0x1F25)
        bits = (self.version << 12) | remainder
        for i in range(18):
            dark = bool((bits >> i) & 1)
            far = self.size - 11 + i % 3
            near = i // 3
            self.set_function(near, far, dark)
            self.set_function(far, near, dark)

    def draw_format_info(self, mask: int) -> None:
        data = (_EC_FORMAT_BITS << 3) | mask
        remainder = data
        for _ in range(10):
            remainder = (remainder << 1) ^ ((remainder >> 9) * 0x537)
        bits = ((data << 10) | remainder) ^ 0b101010000010010
        for i in range(6):
            self.modules[i][8] = bool((bits >> i) & 1)
        self.modules[7][8] = bool((bits >> 6) & 1)
        self.modules[8][8] = bool((bits >> 7) & 1)
        self.modules[8][7] = bool((bits >> 8) & 1)
        for i in range(9, 15):
            self.modules[8][14 - i] = bool((bits >> i) & 1)
        for i in range(8):
            self.modules[8][self.size - 1 - i] = bool((bits >> i) & 1)
        for i in range(8, 15):
            self.modules[self.size - 15 + i][8] = bool((bits >> i) & 1)

    # ---------------------------------------------------------------- data

    def draw_codewords(self, codewords: Sequence[int]) -> None:
        """Zigzag placement: two-module columns, right to left, skipping the timing column."""
        bit_index = 0
        total_bits = len(codewords) * 8
        for right in range(self.size - 1, 0, -2):
            if right <= 6:
                right -= 1  # step over column 6, the vertical timing pattern
            upward = ((right + 1) & 2) == 0
            for step in range(self.size):
                for offset in range(2):
                    col = right - offset
                    row = (self.size - 1 - step) if upward else step
                    if not self.reserved[row][col] and bit_index < total_bits:
                        self.modules[row][col] = bool((codewords[bit_index >> 3] >> (7 - (bit_index & 7))) & 1)
                        bit_index += 1

    def apply_mask(self, mask: int) -> None:
        """XOR the mask over every data module (masking is its own inverse)."""
        condition = _MASKS[mask]
        for row in range(self.size):
            for col in range(self.size):
                if not self.reserved[row][col] and condition(row, col):
                    self.modules[row][col] = not self.modules[row][col]


#: The eight data mask conditions (ISO/IEC 18004 table 23); the module is inverted when true.
_MASKS: tuple = (
    lambda row, col: (row + col) % 2 == 0,
    lambda row, col: row % 2 == 0,
    lambda row, col: col % 3 == 0,
    lambda row, col: (row + col) % 3 == 0,
    lambda row, col: (row // 2 + col // 3) % 2 == 0,
    lambda row, col: (row * col) % 2 + (row * col) % 3 == 0,
    lambda row, col: ((row * col) % 2 + (row * col) % 3) % 2 == 0,
    lambda row, col: ((row + col) % 2 + (row * col) % 3) % 2 == 0,
)


# ------------------------------------------------------------------ penalties


def _finder_like(history: Sequence[int]) -> int:
    """How many 1:1:3:1:1 finder-lookalikes end at this point in the run history."""
    middle = history[1]
    core = (
        middle > 0
        and history[2] == middle
        and history[3] == middle * 3
        and history[4] == middle
        and history[5] == middle
    )
    if not core:
        return 0
    return int(history[0] >= middle * 4 and history[6] >= middle) + int(
        history[6] >= middle * 4 and history[0] >= middle
    )


def _push_run(history: list[int], length: int, size: int) -> None:
    if history[0] == 0:
        length += size  # the quiet zone counts as light modules before the first run
    history.pop()
    history.insert(0, length)


def _finish_run(history: list[int], dark_run: bool, length: int, size: int) -> int:
    if dark_run:
        _push_run(history, length, size)
        length = 0
    length += size  # and after the last one
    _push_run(history, length, size)
    return _finder_like(history)


def penalty(modules: Sequence[Sequence[bool]]) -> int:
    """Total mask penalty by the four rules of ISO/IEC 18004 section 8.8.2.

    Rule 3 follows the 2015 edition: a 1:1:3:1:1 finder lookalike counts when the four
    light modules beside it may run into the quiet zone, not only when they are inside
    the symbol (the 2006 edition's literal 11-module sequence). Encoders differ here,
    so a code from another library may pick a different mask for the same payload.
    Both readings produce valid, scannable symbols — the penalty only decides which of
    the eight equally valid masks is used, and a cross-check against ZBar confirmed it:
    every one of the eight masks decoded back to the payload for every version 1-10.
    Force ``mask=`` if you ever need to reproduce another encoder's choice exactly.
    """
    size = len(modules)
    score = 0
    for outer in range(size):
        for axis in (0, 1):
            run_dark = False
            run_length = 0
            history = [0] * 7
            for inner in range(size):
                cell = modules[outer][inner] if axis == 0 else modules[inner][outer]
                if cell == run_dark:
                    run_length += 1
                    if run_length == 5:
                        score += _PENALTY_N1
                    elif run_length > 5:
                        score += 1
                else:
                    _push_run(history, run_length, size)
                    if not run_dark:
                        score += _finder_like(history) * _PENALTY_N3
                    run_dark = cell
                    run_length = 1
            score += _finish_run(history, run_dark, run_length, size) * _PENALTY_N3
    for row in range(size - 1):
        for col in range(size - 1):
            cell = modules[row][col]
            if cell == modules[row][col + 1] == modules[row + 1][col] == modules[row + 1][col + 1]:
                score += _PENALTY_N2
    dark = sum(1 for row in modules for cell in row if cell)
    total = size * size
    steps = (abs(dark * 20 - total * 10) + total - 1) // total - 1
    return score + steps * _PENALTY_N4


# ------------------------------------------------------------------ public API


@dataclass(frozen=True)
class QrCode:
    """An encoded code: the chosen version and mask plus the finished module grid."""

    version: int
    mask: int
    modules: tuple[tuple[bool, ...], ...]

    @property
    def size(self) -> int:
        return len(self.modules)

    def to_matrix(self) -> list[list[bool]]:
        """A mutable copy of the grid; ``True`` is a dark module."""
        return [list(row) for row in self.modules]

    def to_svg(self, scale: int = 4, quiet_zone: int = 4) -> str:
        return _render_svg(self.modules, scale=scale, quiet_zone=quiet_zone)

    def to_ascii(self, quiet_zone: int = 2, dark: str = "██", light: str = "  ") -> str:
        return _render_ascii(self.modules, quiet_zone=quiet_zone, dark=dark, light=light)

    def to_text(self, quiet_zone: int = 0, dark: str = "#", light: str = ".") -> str:
        """One character per module — the form the test fixtures are written in."""
        return _render_ascii(self.modules, quiet_zone=quiet_zone, dark=dark, light=light)


def encode(data: str | bytes, *, min_version: int = MIN_VERSION, max_version: int = MAX_VERSION,
           mask: int | None = None) -> QrCode:
    """Encode ``data`` as a level-M byte-mode QR code.

    ``mask`` forces one of the eight data masks; by default all eight are scored by the
    standard penalty rules and the lowest-scoring one wins (ties go to the lower index,
    as the specification requires).
    """
    payload = data.encode("utf-8") if isinstance(data, str) else bytes(data)
    if mask is not None and not 0 <= mask <= 7:
        raise ValueError(f"mask must be 0-7, got {mask}")
    version = _choose_version(len(payload), min_version, max_version)
    codewords = _interleave(_bits_to_codewords(_bit_stream(payload, version)), version)

    best_score = -1
    best_mask = 0
    best_modules: list[list[bool]] = []
    for candidate in range(8) if mask is None else (mask,):
        canvas = _Canvas(version)
        canvas.draw_function_patterns()
        canvas.draw_codewords(codewords)
        canvas.apply_mask(candidate)
        canvas.draw_format_info(candidate)
        score = penalty(canvas.modules)
        if best_score < 0 or score < best_score:
            best_score, best_mask, best_modules = score, candidate, canvas.modules
    logger.debug("encoded %d bytes as QR version %d mask %d", len(payload), version, best_mask)
    return QrCode(version=version, mask=best_mask, modules=tuple(tuple(row) for row in best_modules))


def to_matrix(data: str | bytes, **kwargs) -> list[list[bool]]:
    """Convenience wrapper: the module grid for ``data``."""
    return encode(data, **kwargs).to_matrix()


def to_svg(data: str | bytes, scale: int = 4, quiet_zone: int = 4, **kwargs) -> str:
    """Convenience wrapper: a self-contained SVG document for ``data``."""
    return encode(data, **kwargs).to_svg(scale=scale, quiet_zone=quiet_zone)


def to_ascii(data: str | bytes, quiet_zone: int = 2, **kwargs) -> str:
    """Convenience wrapper: a terminal rendering of ``data``."""
    return encode(data, **kwargs).to_ascii(quiet_zone=quiet_zone)


# ------------------------------------------------------------------ renderers


def _render_svg(modules: Sequence[Sequence[bool]], *, scale: int, quiet_zone: int) -> str:
    """SVG with one path for every dark module.

    No CSS, no script, no external reference: it is inlined into a page whose CSP is
    ``default-src 'self'``. Light modules are the white background rectangle, which
    scanners need as the quiet zone.
    """
    if scale < 1:
        raise ValueError("scale must be at least 1")
    if quiet_zone < 0:
        raise ValueError("quiet_zone cannot be negative")
    size = len(modules)
    side = (size + quiet_zone * 2) * scale
    parts: list[str] = []
    for row_index, row in enumerate(modules):
        col_index = 0
        while col_index < size:
            if not row[col_index]:
                col_index += 1
                continue
            run = col_index
            while run < size and row[run]:
                run += 1
            x = (col_index + quiet_zone) * scale
            y = (row_index + quiet_zone) * scale
            parts.append(f"M{x} {y}h{(run - col_index) * scale}v{scale}h-{(run - col_index) * scale}z")
            col_index = run
    path = "".join(parts)
    return (
        f'<svg xmlns="http://www.w3.org/2000/svg" width="{side}" height="{side}" '
        f'viewBox="0 0 {side} {side}" shape-rendering="crispEdges" role="img" '
        f'aria-label="QR code">'
        f'<rect width="{side}" height="{side}" fill="#ffffff"/>'
        f'<path d="{path}" fill="#000000"/>'
        f"</svg>"
    )


def _render_ascii(modules: Sequence[Sequence[bool]], *, quiet_zone: int, dark: str, light: str) -> str:
    """Text rendering. The default two-cell blocks keep the code square in a terminal
    whose character cells are roughly half as wide as they are tall."""
    if quiet_zone < 0:
        raise ValueError("quiet_zone cannot be negative")
    width = len(modules) + quiet_zone * 2
    blank = light * width
    lines: list[str] = [blank] * quiet_zone
    for row in modules:
        lines.append(light * quiet_zone + "".join(dark if cell else light for cell in row) + light * quiet_zone)
    lines.extend([blank] * quiet_zone)
    return "\n".join(lines)


def matrix_text(modules: Iterable[Iterable[bool]]) -> str:
    """``#``/``.`` text of any matrix — used by the tests and by ``lens cert`` debugging."""
    return "\n".join("".join("#" if cell else "." for cell in row) for row in modules)


# A wrong block table would produce codes that look right and never scan, so the
# arithmetic is checked once at import (microseconds, and it can only ever fail
# during development).
for _version, (_ec, _groups) in _EC_BLOCKS_M.items():
    _blocks = sum(count for count, _ in _groups)
    if sum(count * size for count, size in _groups) + _ec * _blocks != _TOTAL_CODEWORDS[_version]:
        raise RuntimeError(f"qr: inconsistent block table for version {_version}")


__all__ = [
    "MIN_VERSION",
    "MAX_VERSION",
    "EC_LEVEL",
    "QrCode",
    "QrError",
    "encode",
    "to_matrix",
    "to_svg",
    "to_ascii",
    "capacity_bytes",
    "data_codewords",
    "penalty",
    "rs_encode",
    "matrix_text",
]
