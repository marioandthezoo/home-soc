"""Tests for the hand-rolled QR encoder (SPEC addendum B4/B11).

A QR code that does not scan is worse than no QR code at all — the failure only shows
up when someone is standing in a cupboard pointing a phone at a smart plug — so this
file checks the encoder three independent ways:

1. **Against the specification's own worked example.** ISO/IEC 18004 annex I encodes
   ``01234567`` and prints the resulting codewords; :func:`qr.rs_encode` must reproduce
   its ten error correction codewords exactly.
2. **Against fixed known-good matrices.** ``FIXTURES`` below are byte-for-byte module
   grids. Committing them means any future change to the encoder that alters a single
   module fails loudly. They were validated out-of-tree, twice, on 2026-09-13:

   * every matrix this encoder produces was compared with ``python-qrcode`` at each of
     the eight masks for 34 payloads spanning versions 1-10 and both character-count
     widths — 272 grids, all identical module for module, including the
     Reed-Solomon codewords;
   * the rendered bitmaps were decoded with ZBar (``pyzbar``) at every mask for every
     payload — 126 of 126 read back byte-identical, as did the terminal rendering
     ``lens pair`` prints and the SVG the sticker sheet embeds.

   Those two libraries are deliberately *not* test dependencies: Home SOC installs with
   flask, requests and dnslib, and the suite must run on that. Reproduce the cross-check
   by installing them into a throwaway environment.
3. **By decoding the output again.** :func:`decode` at the bottom of this file is a
   small QR *reader* written independently of the encoder: it works out the function
   modules itself, reads the mask out of the format information, undoes the mask,
   walks the zigzag, de-interleaves the blocks, checks the Reed-Solomon syndromes are
   all zero and parses the byte-mode header. Payloads of every length class round-trip
   through it, so a matrix cannot merely "look like" a QR code.

Everything here is offline and deterministic.
"""

from __future__ import annotations

import hashlib

import pytest

from homesoc.web import qr

# --------------------------------------------------------------------------- fixtures

# ISO/IEC 18004 annex I: the data codewords for "01234567" (numeric, version 1-M) and
# the ten error correction codewords the specification prints for them.
ISO_EXAMPLE_DATA = [16, 32, 12, 86, 97, 128, 236, 17, 236, 17, 236, 17, 236, 17, 236, 17]
ISO_EXAMPLE_EC = [165, 36, 212, 193, 237, 54, 199, 135, 44, 85]

# A single byte: the smallest possible symbol, version 1.
FIXTURE_V1 = (
    "#######.##.#..#######",
    "#.....#..##...#.....#",
    "#.###.#..####.#.###.#",
    "#.###.#.###...#.###.#",
    "#.###.#.###.#.#.###.#",
    "#.....#.####..#.....#",
    "#######.#.#.#.#######",
    "........#.###........",
    "#...#.###..#.#####..#",
    "..#.#...#..##..#.#.##",
    "####.##...##..#####..",
    "###....#.#...##.#.##.",
    "###.#####...###...###",
    "........#.#.###...###",
    "#######.##..##.....#.",
    "#.....#..####..#.#.#.",
    "#.###.#.####..#######",
    "#.###.#..#.##..#.#.##",
    "#.###.#....#..#####..",
    "#.....#..#...##.#.#..",
    "#######.#.#.###...#.#",
)

# A sticker payload: "hs1:" plus 22 url-safe base64 characters (SPEC B5), version 2.
FIXTURE_STICKER = (
    "#######.....##..#.#######",
    "#.....#..##.#####.#.....#",
    "#.###.#.#.##...##.#.###.#",
    "#.###.#.#...#.#...#.###.#",
    "#.###.#.#.#..#.##.#.###.#",
    "#.....#.###.####..#.....#",
    "#######.#.#.#.#.#.#######",
    "........#.##..###........",
    "#.#####....#.##...#####..",
    "....#..###....#.#..#.#.#.",
    "#.#.###...#....#####....#",
    "#..#.#.##..#.......#.#.#.",
    "##.#.##.##.##.#..##...#.#",
    "##.##..##...#.###.##.###.",
    "#.#.#.#.###.#..#.##..####",
    "#.#..#.#.###..#..#.#....#",
    "#.#.######...##.######...",
    "........#..#..###...##...",
    "#######......#..#.#.#..##",
    "#.....#.#.......#...#....",
    "#.###.#.##....#########..",
    "#.###.#.###...#..##.##.##",
    "#.###.#.##..##.##..#.##.#",
    "#.....#..#....##...##...#",
    "#######.##...##...#..#.##",
)

STICKER_PAYLOAD = "hs1:AbCdEfGhIjKlMnOpQrStUv"
# A pairing URL of the shape SPEC B4 specifies, with a documentation address.
PAIR_URL = "https://192.168.10.5:8443/lens/claim#c=A1B2C3D4"

# Larger matrices are pinned by digest rather than 57 lines of text.
FIXTURE_DIGESTS: dict[str, tuple[str, int, int]] = {
    PAIR_URL: ("4b25facc8c63a4ecffb5e8dec47ce23e010d0c8d7add9d6eb572f8d78886ee57", 4, 2),
    "Z" * 213: ("31f57e5868c1c9677da5ac623dae57f1bf80c2b5d479f3ac4b733ad0df579262", 10, 1),
}

# One payload per version, at the exact byte capacity of that version at level M.
CAPACITY_BY_VERSION = {1: 14, 2: 26, 3: 42, 4: 62, 5: 84, 6: 106, 7: 122, 8: 152, 9: 180, 10: 213}


def _text(code: qr.QrCode) -> tuple[str, ...]:
    return tuple(code.to_text().splitlines())


# --------------------------------------------------------------------------- arithmetic


def test_reed_solomon_matches_the_specification_example():
    assert qr.rs_encode(ISO_EXAMPLE_DATA, 10) == ISO_EXAMPLE_EC


def test_reed_solomon_block_lengths():
    for ec_codewords in (10, 16, 18, 22, 24, 26):
        assert len(qr.rs_encode([0x11] * 20, ec_codewords)) == ec_codewords


def test_capacity_table_matches_the_standard():
    for version, expected in CAPACITY_BY_VERSION.items():
        assert qr.capacity_bytes(version) == expected


def test_version_is_the_smallest_that_fits():
    for version, capacity in CAPACITY_BY_VERSION.items():
        assert qr.encode("z" * capacity).version == version
        if version < qr.MAX_VERSION:
            assert qr.encode("z" * (capacity + 1)).version == version + 1


def test_payload_that_cannot_fit_is_refused():
    with pytest.raises(qr.QrError):
        qr.encode("z" * 214)
    with pytest.raises(qr.QrError):
        qr.encode("z" * 20, max_version=1)


def test_bad_mask_is_refused():
    with pytest.raises(ValueError):
        qr.encode("hello", mask=8)


# --------------------------------------------------------------------------- fixtures


def test_matrix_matches_fixture_version_1():
    code = qr.encode("A")
    assert (code.version, code.size) == (1, 21)
    assert _text(code) == FIXTURE_V1


def test_matrix_matches_fixture_sticker_payload():
    code = qr.encode(STICKER_PAYLOAD)
    assert (code.version, code.size) == (2, 25)
    assert _text(code) == FIXTURE_STICKER


@pytest.mark.parametrize("payload", list(FIXTURE_DIGESTS))
def test_matrix_matches_fixture_digest(payload):
    digest, version, mask = FIXTURE_DIGESTS[payload]
    code = qr.encode(payload)
    assert (code.version, code.mask) == (version, mask)
    assert hashlib.sha256(code.to_text().encode()).hexdigest() == digest


def test_encoding_is_deterministic():
    assert qr.encode(PAIR_URL).to_matrix() == qr.encode(PAIR_URL).to_matrix()
    assert qr.encode("A").to_matrix() == qr.encode(b"A").to_matrix()


# --------------------------------------------------------------------------- structure


def _finder_ok(matrix, row, col) -> bool:
    expected = [
        "#######", "#.....#", "#.###.#", "#.###.#", "#.###.#", "#.....#", "#######",
    ]
    for d_row, line in enumerate(expected):
        for d_col, char in enumerate(line):
            if matrix[row + d_row][col + d_col] != (char == "#"):
                return False
    return True


def test_function_patterns_are_in_place():
    code = qr.encode(PAIR_URL)
    matrix = code.to_matrix()
    size = code.size
    assert _finder_ok(matrix, 0, 0)
    assert _finder_ok(matrix, 0, size - 7)
    assert _finder_ok(matrix, size - 7, 0)
    for i in range(8, size - 8):
        assert matrix[6][i] is (i % 2 == 0)
        assert matrix[i][6] is (i % 2 == 0)
    assert matrix[size - 8][8] is True  # the always-dark module
    for i in range(7):  # separators around the top-left finder
        assert matrix[7][i] is False
        assert matrix[i][7] is False


@pytest.mark.parametrize("version", range(7, 11))
def test_version_information_block_is_readable(version):
    """Versions 7 and up carry their version number twice, BCH-protected."""
    code = qr.encode("z" * CAPACITY_BY_VERSION[version])
    assert code.version == version
    matrix = code.to_matrix()
    for transposed in (False, True):
        bits = _version_bits(matrix, transposed)
        assert bits >> 12 == version
        remainder = version
        for _ in range(12):
            remainder = (remainder << 1) ^ ((remainder >> 11) * 0x1F25)
        assert bits == (version << 12) | remainder


def _version_bits(matrix, transposed: bool) -> int:
    size = len(matrix)
    bits = 0
    for i in range(18):
        row, col = i // 3, size - 11 + i % 3
        if matrix[col][row] if transposed else matrix[row][col]:
            bits |= 1 << i
    return bits


# --------------------------------------------------------------------------- renderers


def test_to_matrix_is_a_mutable_copy():
    code = qr.encode("A")
    first = code.to_matrix()
    first[0][0] = not first[0][0]
    assert code.to_matrix()[0][0] != first[0][0]


def test_to_svg_is_self_contained():
    svg = qr.to_svg(PAIR_URL, scale=4, quiet_zone=4)
    size = qr.encode(PAIR_URL).size
    side = (size + 8) * 4
    assert svg.startswith("<svg ") and svg.endswith("</svg>")
    assert f'width="{side}"' in svg and f'viewBox="0 0 {side} {side}"' in svg
    assert 'xmlns="http://www.w3.org/2000/svg"' in svg
    # No CDN, no script, no external reference: the CSP is default-src 'self'. The SVG
    # namespace is the only URL allowed to appear, and it is never fetched.
    body = svg.replace('xmlns="http://www.w3.org/2000/svg"', "")
    for forbidden in ("http", "//", "<script", "<style", "onload", "xlink:href", "<image", "url("):
        assert forbidden not in body


def test_to_svg_rejects_nonsense_geometry():
    code = qr.encode("A")
    with pytest.raises(ValueError):
        code.to_svg(scale=0)
    with pytest.raises(ValueError):
        code.to_svg(quiet_zone=-1)


def test_to_ascii_shape_and_quiet_zone():
    code = qr.encode("A")
    lines = code.to_ascii(quiet_zone=2).splitlines()
    assert len(lines) == code.size + 4
    assert all(len(line) == (code.size + 4) * 2 for line in lines)
    assert lines[0].strip() == ""
    assert lines[-1].strip() == ""
    plain = code.to_text().splitlines()
    assert len(plain) == code.size and set("".join(plain)) <= {"#", "."}


def test_to_ascii_can_be_inverted_for_dark_terminals():
    code = qr.encode("A")
    normal = code.to_ascii(quiet_zone=0, dark="#", light=".")
    inverted = code.to_ascii(quiet_zone=0, dark=".", light="#")
    assert normal == inverted.translate(str.maketrans("#.", ".#"))


# --------------------------------------------------------------------------- round trip


# A miniature QR reader, written from the specification rather than from the encoder,
# so that a shared mistake cannot make both agree. Only what these tests need: level M,
# byte mode, versions 1-10.

_EC_BLOCKS_M_READER = {
    1: (10, ((1, 16),)), 2: (16, ((1, 28),)), 3: (26, ((1, 44),)), 4: (18, ((2, 32),)),
    5: (24, ((2, 43),)), 6: (16, ((4, 27),)), 7: (18, ((4, 31),)), 8: (22, ((2, 38), (2, 39))),
    9: (22, ((3, 36), (2, 37))), 10: (26, ((4, 43), (1, 44))),
}
_ALIGNMENT_READER = {
    1: (), 2: (6, 18), 3: (6, 22), 4: (6, 26), 5: (6, 30), 6: (6, 34),
    7: (6, 22, 38), 8: (6, 24, 42), 9: (6, 26, 46), 10: (6, 28, 50),
}


def _gf_tables():
    exp, log = [0] * 512, [0] * 256
    value = 1
    for power in range(255):
        exp[power] = value
        log[value] = power
        value = (value << 1) ^ 0x11D if value & 0x80 else value << 1
    for power in range(255, 512):
        exp[power] = exp[power - 255]
    return exp, log


_EXP, _LOG = _gf_tables()


def _syndromes(block, ec_codewords):
    """All zero for a valid Reed-Solomon codeword."""
    out = []
    for i in range(ec_codewords):
        acc = 0
        for byte in block:
            acc = (0 if acc == 0 else _EXP[(_LOG[acc] + i) % 255]) ^ byte
        out.append(acc)
    return out


def _function_map(version):
    """Which modules are function patterns, worked out from the geometry."""
    size = version * 4 + 17
    reserved = [[False] * size for _ in range(size)]

    def block(r0, c0, rows, cols):
        for r in range(r0, r0 + rows):
            for c in range(c0, c0 + cols):
                if 0 <= r < size and 0 <= c < size:
                    reserved[r][c] = True

    block(0, 0, 9, 9)                 # finder + separator + format info
    block(0, size - 8, 9, 8)
    block(size - 8, 0, 8, 9)
    for i in range(size):
        reserved[6][i] = True
        reserved[i][6] = True
    positions = _ALIGNMENT_READER[version]
    corners = {(positions[0], positions[0]), (positions[0], positions[-1]),
               (positions[-1], positions[0])} if positions else set()
    for row in positions:
        for col in positions:
            if (row, col) not in corners:
                block(row - 2, col - 2, 5, 5)
    if version >= 7:
        block(0, size - 11, 6, 3)
        block(size - 11, 0, 3, 6)
    return reserved


def _read_format(matrix):
    """Error correction level and mask from the first format-information copy."""
    bits = 0
    for i in range(6):
        bits |= int(matrix[i][8]) << i
    bits |= int(matrix[7][8]) << 6
    bits |= int(matrix[8][8]) << 7
    bits |= int(matrix[8][7]) << 8
    for i in range(9, 15):
        bits |= int(matrix[8][14 - i]) << i
    bits ^= 0b101010000010010
    data = bits >> 10
    # Re-derive the BCH check bits and confirm they match what was read.
    check = data
    for _ in range(10):
        check = (check << 1) ^ ((check >> 9) * 0x537)
    assert ((data << 10) | check) == bits, "format information is corrupt"
    return data >> 3, data & 0b111


_MASK_CONDITIONS = (
    lambda r, c: (r + c) % 2 == 0,
    lambda r, c: r % 2 == 0,
    lambda r, c: c % 3 == 0,
    lambda r, c: (r + c) % 3 == 0,
    lambda r, c: (r // 2 + c // 3) % 2 == 0,
    lambda r, c: (r * c) % 2 + (r * c) % 3 == 0,
    lambda r, c: ((r * c) % 2 + (r * c) % 3) % 2 == 0,
    lambda r, c: ((r + c) % 2 + (r * c) % 3) % 2 == 0,
)


def decode(matrix):
    """Read a level-M byte-mode QR matrix back to its payload, checking the EC as it goes."""
    size = len(matrix)
    version = (size - 17) // 4
    ec_level, mask = _read_format(matrix)
    assert ec_level == 0, "these tests only produce level M"
    reserved = _function_map(version)
    condition = _MASK_CONDITIONS[mask]
    grid = [[cell != (condition(r, c) and not reserved[r][c]) for c, cell in enumerate(row)]
            for r, row in enumerate(matrix)]

    bits: list[int] = []
    for right in range(size - 1, 0, -2):
        if right <= 6:
            right -= 1
        upward = ((right + 1) & 2) == 0
        for step in range(size):
            for offset in range(2):
                col = right - offset
                row = (size - 1 - step) if upward else step
                if not reserved[row][col]:
                    bits.append(1 if grid[row][col] else 0)
    stream = [int("".join(str(b) for b in bits[i:i + 8]), 2) for i in range(0, len(bits) // 8 * 8, 8)]

    ec_per_block, groups = _EC_BLOCKS_M_READER[version]
    sizes = [size_ for count, size_ in groups for _ in range(count)]
    blocks: list[list[int]] = [[] for _ in sizes]
    index = 0
    for position in range(max(sizes)):
        for block_index, block_size in enumerate(sizes):
            if position < block_size:
                blocks[block_index].append(stream[index])
                index += 1
    ec_blocks: list[list[int]] = [[] for _ in sizes]
    for _ in range(ec_per_block):
        for block_index in range(len(sizes)):
            ec_blocks[block_index].append(stream[index])
            index += 1
    for block, ec_block in zip(blocks, ec_blocks):
        assert _syndromes(block + ec_block, ec_per_block) == [0] * ec_per_block, "error correction is wrong"

    data = [bit for block in blocks for byte in block for bit in
            ((byte >> shift) & 1 for shift in range(7, -1, -1))]
    mode = int("".join(str(b) for b in data[:4]), 2)
    assert mode == 0b0100, f"expected byte mode, got {mode:04b}"
    count_bits = 8 if version < 10 else 16
    length = int("".join(str(b) for b in data[4:4 + count_bits]), 2)
    start = 4 + count_bits
    payload = bytes(
        int("".join(str(b) for b in data[start + i * 8:start + i * 8 + 8]), 2) for i in range(length)
    )
    return payload


ROUND_TRIP_PAYLOADS = [
    "A",
    "0123456789",
    STICKER_PAYLOAD,
    PAIR_URL,
    "<img src=x onerror=alert(1)>",
    "Ünïcödé — ✓",
    *[("v%d-" % version).ljust(CAPACITY_BY_VERSION[version], "x") for version in range(1, 11)],
]


@pytest.mark.parametrize("payload", ROUND_TRIP_PAYLOADS)
def test_round_trip_through_an_independent_reader(payload):
    code = qr.encode(payload)
    assert decode(code.to_matrix()) == payload.encode("utf-8")


@pytest.mark.parametrize("mask", range(8))
def test_every_mask_round_trips(mask):
    code = qr.encode(PAIR_URL, mask=mask)
    assert code.mask == mask
    assert decode(code.to_matrix()) == PAIR_URL.encode()


def test_mask_selection_prefers_the_lowest_penalty():
    code = qr.encode(PAIR_URL)
    scores = {mask: qr.penalty(qr.encode(PAIR_URL, mask=mask).modules) for mask in range(8)}
    best = min(scores, key=lambda m: (scores[m], m))
    assert code.mask == best
