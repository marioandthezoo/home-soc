"""CPE parsing, product-name guessing and tolerant version comparison.

nmap emits CPE 2.2 URIs (``cpe:/a:vendor:product:version``) while NVD and KEV speak
CPE 2.3 (``cpe:2.3:a:vendor:product:version:*:...``). Everything downstream wants one
shape, so both are normalised into :class:`CPE`. Version strings in the wild are
messy (``9.2p1``, ``1.4.69``, ``2.4.41a``, ``v3.0-rc1``); the comparison here is
deliberately forgiving rather than PEP 440-strict, because a wrong "not vulnerable"
answer is worse than an occasional conservative match.
"""

from __future__ import annotations

import logging
import re
from dataclasses import dataclass
from urllib.parse import unquote

logger = logging.getLogger(__name__)

# Alias table: a lowercase fragment of the nmap ``product`` string -> (vendor, product)
# as NVD names them. Longest fragment wins so "apache httpd" beats "apache".
# SPEC-GAP: NVD has renamed several vendors over the years (nginx -> f5, redis ->
# redislabs -> redis). The names below are the ones current NVD CPE names use; KEV
# search is expected to be tolerant of vendor spelling (see matcher).
_ALIASES: dict[str, tuple[str, str]] = {
    "lighttpd": ("lighttpd", "lighttpd"),
    "unbound": ("nlnetlabs", "unbound"),
    "openssh": ("openbsd", "openssh"),
    "nginx": ("f5", "nginx"),
    "apache httpd": ("apache", "http_server"),
    "apache http server": ("apache", "http_server"),
    "dropbear": ("dropbear_ssh_project", "dropbear_ssh"),
    "busybox": ("busybox", "busybox"),
    "samba": ("samba", "samba"),
    "vsftpd": ("vsftpd_project", "vsftpd"),
    "proftpd": ("proftpd", "proftpd"),
    "mysql": ("oracle", "mysql"),
    "mariadb": ("mariadb", "mariadb"),
    "postgresql": ("postgresql", "postgresql"),
    "redis": ("redis", "redis"),
    "mongodb": ("mongodb", "mongodb"),
    "hikvision": ("hikvision", "hikvision"),
    "dahua": ("dahua", "dahua"),
    "miniupnpd": ("miniupnp_project", "miniupnpd"),
    "miniupnp": ("miniupnp_project", "miniupnpd"),
    "dnsmasq": ("thekelleys", "dnsmasq"),
    "libupnp": ("libupnp_project", "libupnp"),
    "portable sdk for upnp": ("libupnp_project", "libupnp"),
    # SPEC-GAP: a bare "upnp" banner gives no vendor; libupnp is the most common
    # embedded stack, so we guess it and let the version/keyword search sort it out.
    "upnp": ("libupnp_project", "libupnp"),
    "cups": ("apple", "cups"),
    "avahi": ("avahi", "avahi"),
    "microsoft iis": ("microsoft", "internet_information_services"),
    "iis": ("microsoft", "internet_information_services"),
    "terminal services": ("microsoft", "remote_desktop_services"),
    "ms-wbt-server": ("microsoft", "remote_desktop_services"),
    "rdp": ("microsoft", "remote_desktop_services"),
}
# "rtsp" alone is a protocol, not a product; camera vendors above cover the useful cases.
_ALIAS_KEYS = sorted(_ALIASES, key=len, reverse=True)

_EMPTY_VERSION = {"", "*", "-", "unknown", "any"}
_VERSION_TOKEN = re.compile(r"\d+|[A-Za-z]+")
_PRERELEASE = {"alpha", "a", "beta", "b", "rc", "pre", "dev", "snapshot", "preview"}
_VERSION_IN_TEXT = re.compile(r"(?<![\w.])v?(\d+(?:\.\d+)+(?:[A-Za-z]+\d*)?)(?![\w.])")
_CLEAN_VERSION = re.compile(r"v?(\d[\w.+-]*)", re.IGNORECASE)


@dataclass(frozen=True)
class CPE:
    """One normalised CPE. ``version`` is None when unknown or wildcard."""

    part: str
    vendor: str
    product: str
    version: str | None = None

    def nvd_name(self) -> str:
        """CPE 2.3 formatted string as NVD's ``cpeName`` parameter expects it."""
        version = self.version if self.version else "*"
        return f"cpe:2.3:{self.part}:{self.vendor}:{self.product}:{version}:*:*:*:*:*:*:*"

    def label(self) -> str:
        """Human-friendly ``vendor/product version`` for finding text."""
        base = f"{self.vendor}/{self.product}" if self.vendor != self.product else self.product
        return f"{base} {self.version}" if self.version else base


def parse_cpe(cpe: str) -> CPE:
    """Accept nmap's 2.2 URI form and the 2.3 formatted-string form.

    Raises ValueError for anything that is not a CPE, so callers can fall back to
    :func:`guess_cpe` instead of silently matching the wrong product.
    """
    text = (cpe or "").strip()
    if text.lower().startswith("cpe:2.3:"):
        fields = _split_23(text[len("cpe:2.3:"):])
    elif text.lower().startswith("cpe:/"):
        fields = text[len("cpe:/"):].split(":")
    else:
        raise ValueError(f"not a CPE: {cpe!r}")
    fields = [unquote(f).strip() for f in fields]
    if len(fields) < 3 or not fields[0] or not fields[1] or not fields[2]:
        raise ValueError(f"incomplete CPE: {cpe!r}")
    part = fields[0].lower()
    if part not in {"a", "o", "h"}:
        raise ValueError(f"bad CPE part {part!r} in {cpe!r}")
    version = fields[3] if len(fields) > 3 else ""
    return CPE(part, fields[1].lower(), fields[2].lower(), _none_if_empty(version))


def _split_23(body: str) -> list[str]:
    """Split a 2.3 body on unescaped colons (2.3 allows ``\\:`` inside fields)."""
    out: list[str] = []
    cur: list[str] = []
    escaped = False
    for ch in body:
        if escaped:
            cur.append(ch)
            escaped = False
        elif ch == "\\":
            escaped = True
        elif ch == ":":
            out.append("".join(cur))
            cur = []
        else:
            cur.append(ch)
    out.append("".join(cur))
    return out


def _none_if_empty(version: str) -> str | None:
    v = version.strip()
    return None if v.lower() in _EMPTY_VERSION else v


def guess_cpe(product: str, version: str | None) -> CPE | None:
    """Map an nmap product banner to a CPE via the alias table.

    Returns None when the product is not in the table; matching against NVD with a
    guessed vendor would produce confident-looking noise.
    """
    text = (product or "").strip().lower()
    if not text:
        return None
    for key in _ALIAS_KEYS:
        if key in text:
            vendor, prod = _ALIASES[key]
            return CPE("a", vendor, prod, clean_version(version))
    return None


def clean_version(version: str | None) -> str | None:
    """Reduce ``"v1.4.69 (Debian)"`` to ``"1.4.69"``; None when there is no number."""
    if not version:
        return None
    m = _CLEAN_VERSION.search(version)
    if not m:
        return None
    cleaned = m.group(1).rstrip(".-+")
    return _none_if_empty(cleaned)


def version_key(version: str | None) -> tuple:
    """Sortable key: numbers compare numerically, pre-release words sort below a
    release, other letter suffixes (``p1``, ``a``) sort above it."""
    parts: list[tuple[int, int, str]] = []
    tokens = _VERSION_TOKEN.findall(version or "")
    for i, tok in enumerate(tokens):
        low = tok.lower()
        followed_by_digit = i + 1 < len(tokens) and tokens[i + 1].isdigit()
        if tok.isdigit():
            parts.append((1, int(tok), ""))
        elif low in _PRERELEASE and (len(low) > 1 or followed_by_digit):
            # "1.0a1" is an alpha; a bare trailing letter ("2.4.41a", "1.0.2u") is a patch.
            parts.append((0, 0, low))
        else:
            parts.append((2, 0, low))
    return tuple(parts)


def compare_versions(a: str | None, b: str | None) -> int:
    """-1, 0, 1 like ``cmp``; missing trailing components count as zero so
    ``1.4 == 1.4.0`` and ``1.4 < 1.4p1``."""
    ka, kb = list(version_key(a)), list(version_key(b))
    pad = (1, 0, "")
    n = max(len(ka), len(kb))
    ka += [pad] * (n - len(ka))
    kb += [pad] * (n - len(kb))
    return (ka > kb) - (ka < kb)


def version_le(a: str | None, b: str | None) -> bool:
    return compare_versions(a, b) <= 0


def extract_versions(text: str | None) -> list[str]:
    """Version-looking tokens (at least one dot) in free text such as a KEV
    vulnerabilityName or notes field. CVE ids and years never match."""
    if not text:
        return []
    return [m.group(1) for m in _VERSION_IN_TEXT.finditer(text)]


def max_version(versions: list[str]) -> str | None:
    best: str | None = None
    for v in versions:
        if best is None or compare_versions(v, best) > 0:
            best = v
    return best
