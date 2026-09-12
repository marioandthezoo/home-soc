"""Feed registry and cached loaders.

`FEEDS` is the single source of truth for what Home SOC downloads (URLs are
the verified ones from SPEC §7). The `load_*` helpers read the on-disk copies
and cache the parsed result in-process, re-reading only when the file's mtime
or size changes, so the DNS policy and the vuln matcher can call them freely
without re-parsing multi-megabyte lists on every query.
"""

from __future__ import annotations

import ipaddress
import logging
import re
import sqlite3
import threading
from collections.abc import Callable, Iterator
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from homesoc.feeds import parsers

logger = logging.getLogger(__name__)

Parser = Callable[[str], Any]


@dataclass(frozen=True)
class FeedSpec:
    name: str
    url: str
    kind: str  # kev | epss | oui | hosts | domains | adblock | ip | json
    parser: Parser | None
    hours: int
    license_note: str = ""
    enabled_default: bool = True


def _spec(name: str, url: str, kind: str, parser: Parser | None, hours: int, note: str, enabled: bool = True) -> FeedSpec:
    return FeedSpec(name=name, url=url, kind=kind, parser=parser, hours=hours, license_note=note, enabled_default=enabled)


FEEDS: dict[str, FeedSpec] = {
    s.name: s
    for s in (
        _spec("kev", "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json",
              "kev", parsers.parse_kev, 6, "CISA KEV, public domain (US Government work)"),
        _spec("epss", "https://epss.empiricalsecurity.com/epss_scores-current.csv.gz",
              "epss", parsers.parse_epss, 24, "FIRST EPSS, free for non-commercial use with attribution"),
        _spec("oui", "https://www.wireshark.org/download/automated/data/manuf",
              "oui", parsers.parse_oui, 168, "Wireshark manuf (IEEE OUI data), GPLv2 data file"),
        _spec("oisd_small", "https://small.oisd.nl", "domains", parsers.parse_adblock, 12,
              "oisd, CC BY-SA 4.0"),
        _spec("oisd_big", "https://big.oisd.nl", "domains", parsers.parse_adblock, 12,
              "oisd, CC BY-SA 4.0", enabled=False),
        _spec("hagezi_pro", "https://raw.githubusercontent.com/hagezi/dns-blocklists/main/wildcard/pro-onlydomains.txt",
              "domains", parsers.parse_wildcard, 12, "HaGeZi DNS blocklists, GPLv3"),
        _spec("stevenblack", "https://raw.githubusercontent.com/StevenBlack/hosts/master/hosts",
              "hosts", parsers.parse_hosts, 24, "StevenBlack unified hosts, MIT", enabled=False),
        _spec("adguard_dns", "https://adguardteam.github.io/HostlistsRegistry/assets/filter_1.txt",
              "adblock", parsers.parse_adblock, 12, "AdGuard DNS filter, GPLv3", enabled=False),
        _spec("urlhaus", "https://urlhaus.abuse.ch/downloads/hostfile/",
              "hosts", parsers.parse_hosts, 6, "abuse.ch URLhaus, CC0"),
        _spec("urlhaus_filter", "https://malware-filter.gitlab.io/malware-filter/urlhaus-filter-hosts.txt",
              "hosts", parsers.parse_hosts, 6, "malware-filter URLhaus filter, CC0"),
        _spec("threatfox", "https://threatfox.abuse.ch/downloads/hostfile/",
              "hosts", parsers.parse_hosts, 6, "abuse.ch ThreatFox, CC0"),
        _spec("phishing_army", "https://phishing.army/download/phishing_army_blocklist.txt",
              "domains", parsers.parse_domains, 6, "Phishing Army, CC BY-NC 4.0"),
        _spec("openphish", "https://openphish.com/feed.txt",
              "domains", parsers.parse_urls, 6, "OpenPhish community feed, non-commercial use"),
        _spec("feodo_ips", "https://feodotracker.abuse.ch/downloads/ipblocklist.json",
              "ip", parsers.parse_feodo, 6, "abuse.ch Feodo Tracker, CC0"),
        _spec("spamhaus_drop", "https://www.spamhaus.org/drop/drop.txt",
              "ip", parsers.parse_ips, 24, "Spamhaus DROP, free for non-commercial use"),
    )
}

DOMAIN_KINDS = frozenset({"hosts", "domains", "adblock"})
IP_KINDS = frozenset({"ip"})


# ------------------------------------------------------------------ cache ---


@dataclass
class _CacheEntry:
    signature: tuple[int, int]  # (mtime_ns, size)
    value: Any


_cache: dict[str, _CacheEntry] = {}
_cache_lock = threading.Lock()


def _signature(path: Path) -> tuple[int, int] | None:
    try:
        st = path.stat()
    except OSError:
        return None
    return (st.st_mtime_ns, st.st_size)


def _cached(name: str, path: Path, loader: Callable[[str], Any], empty: Callable[[], Any]) -> Any:
    """Return loader(text) for `path`, reusing the previous result while the file is unchanged.

    A missing file yields `empty()` (also cached under a sentinel signature)
    so callers get a consistent type before the first feed update completes.
    """
    sig = _signature(path) or (-1, -1)
    with _cache_lock:
        entry = _cache.get(name)
        if entry is not None and entry.signature == sig:
            return entry.value
    if sig == (-1, -1):
        value = empty()
    else:
        try:
            text = path.read_text(encoding="utf-8", errors="replace")
            value = loader(text)
        except OSError as exc:
            logger.warning("cannot read feed file %s: %s", path, exc)
            value = empty()
    with _cache_lock:
        _cache[name] = _CacheEntry(signature=sig, value=value)
    return value


def clear_cache(name: str | None = None) -> None:
    """Forget cached parses (all, or one feed). Mainly for tests and the settings UI."""
    with _cache_lock:
        if name is None:
            _cache.clear()
        else:
            _cache.pop(name, None)


def _path(name: str) -> Path:
    from homesoc.feeds.updater import feed_path  # lazy: updater imports this module

    return feed_path(name)


# -------------------------------------------------------------------- KEV ---

_NON_ALNUM = re.compile(r"[^a-z0-9]+")

# Product names as seen in service banners/CPEs that KEV spells differently.
_PRODUCT_ALIASES: dict[str, tuple[str, ...]] = {
    "httpd": ("http server", "apache http server"),
    "apache httpd": ("http server", "apache http server"),
    "apache": ("http server",),
    "iis": ("internet information services", "iis"),
    "microsoft iis": ("internet information services",),
    "ms-wbt-server": ("remote desktop services", "windows"),
    "rdp": ("remote desktop services",),
    "microsoft-ds": ("windows", "smb"),
    "smb": ("windows", "server message block"),
    "ssh": ("openssh",),
    "openssh": ("openssh",),
    "mysql": ("mysql", "mysql server"),
    "mariadb": ("mariadb", "mariadb server"),
    "postgresql": ("postgresql",),
    "exchange": ("exchange server",),
    "sharepoint": ("sharepoint server", "sharepoint"),
    "vcenter": ("vcenter server",),
    "esxi": ("esxi",),
    "confluence": ("confluence server and data center", "confluence data center and server", "confluence"),
    "jira": ("jira server and data center", "jira"),
    "gitlab": ("gitlab ce/ee", "gitlab"),
    "jenkins": ("jenkins",),
    "tomcat": ("tomcat",),
    "webmin": ("webmin",),
    "openwrt": ("openwrt",),
    "dd-wrt": ("dd-wrt",),
    "nginx": ("nginx",),
}


def _tokens(value: str | None) -> tuple[str, ...]:
    if not value:
        return ()
    return tuple(t for t in _NON_ALNUM.sub(" ", value.lower()).split() if t)


def _matches(query: tuple[str, ...], target: tuple[str, ...]) -> bool:
    """A query matches when it equals the target or all its tokens appear in it."""
    if not query or not target:
        return False
    if query == target:
        return True
    return set(query).issubset(target)


def _is_vendor_word_only(query: tuple[str, ...], e_vend: tuple[str, ...], e_prod: tuple[str, ...]) -> bool:
    """True when `query` says nothing beyond the entry's vendor name.

    "microsoft" against Microsoft/Windows, "apple" against Apple/Multiple Products
    and "cisco" against Cisco/IOS are all vendor words: accepting them would expand
    a single banner into that vendor's whole KEV catalog (170 entries for Windows
    alone). A query that also *equals* the product column is not a vendor word --
    KEV files some projects under both columns (e.g. lighttpd/lighttpd).
    """
    if not query or not e_vend:
        return False
    return set(query).issubset(set(e_vend)) and set(query) != set(e_prod)


@dataclass
class KevCatalog:
    entries: list[dict[str, Any]] = field(default_factory=list)
    date_released: str = ""
    catalog_version: str = ""
    by_cve: dict[str, dict[str, Any]] = field(init=False, default_factory=dict)

    def __post_init__(self) -> None:
        self.by_cve = {e["cveID"]: e for e in self.entries if e.get("cveID")}

    @property
    def count(self) -> int:
        return len(self.entries)

    def search(self, vendor: str | None, product: str | None) -> list[dict[str, Any]]:
        """Entries whose *product* matches, case-insensitively and alias-tolerant.

        Three rules keep this from degenerating into "every CVE this vendor ever had":

        1. a candidate must match the ``product`` column, or the vendor+product
           columns taken together ("microsoft windows" -> Microsoft / Windows);
        2. a candidate that is nothing but the entry's vendor name ("microsoft",
           "apple", "cisco") never matches -- see :func:`_is_vendor_word_only`;
        3. a vendor supplied by the caller narrows further: it must not contradict
           the entry.

        Callers still have to decide what a match is worth: a product name that
        matches 170 entries (Microsoft/Windows) identifies a family, not a build.
        """
        p_tokens = _tokens(product)
        v_tokens = _tokens(vendor)
        candidates: list[tuple[str, ...]] = []
        if p_tokens:
            candidates.append(p_tokens)
            for alias in _PRODUCT_ALIASES.get(" ".join(p_tokens), ()):
                candidates.append(_tokens(alias))
        if not candidates:
            return []

        results: list[dict[str, Any]] = []
        for entry in self.entries:
            e_prod = _tokens(entry.get("product"))
            e_vend = _tokens(entry.get("vendorProject"))
            if not e_prod and not e_vend:
                continue
            both = e_vend + e_prod
            hit = False
            for cand in candidates:
                if not cand or _is_vendor_word_only(cand, e_vend, e_prod):
                    continue
                if _matches(cand, e_prod) or _matches(cand, both):
                    hit = True
                    break
            if not hit:
                continue
            if v_tokens and not (
                _matches(v_tokens, e_vend) or _matches(e_vend, v_tokens) or _matches(v_tokens, e_prod)
            ):
                continue
            results.append(entry)
        return results


def load_kev() -> KevCatalog:
    """The on-disk KEV catalog (empty catalog until the first successful update)."""

    def loader(text: str) -> KevCatalog:
        meta, entries = parsers.kev_document(text)
        return KevCatalog(entries=entries, date_released=meta.get("dateReleased", ""),
                          catalog_version=meta.get("catalogVersion", ""))

    return _cached("kev", _path("kev"), loader, KevCatalog)


# ------------------------------------------------------------------- EPSS ---


def load_epss() -> dict[str, float]:
    return _cached("epss", _path("epss"), parsers.parse_epss, dict)


# -------------------------------------------------------------------- OUI ---


def load_oui() -> dict[str, str]:
    return _cached("oui", _path("oui"), parsers.parse_oui, dict)


def _mac_hex(mac: str) -> str | None:
    """Reduce any common MAC spelling (aa:bb:cc, AA-BB-CC, aabb.ccdd, raw hex) to uppercase hex digits."""
    if not mac:
        return None
    hexdigits = re.sub(r"[^0-9A-Fa-f]", "", mac).upper()
    if len(hexdigits) < 6 or len(hexdigits) > 12:
        return None
    return hexdigits


def lookup_vendor(mac: str) -> str | None:
    """Vendor for a MAC or prefix, trying the most specific registered block first (36 > 28 > 24 bit)."""
    hexdigits = _mac_hex(mac)
    if hexdigits is None:
        return None
    table = load_oui()
    if not table:
        return None
    keys: list[str] = []
    if len(hexdigits) >= 9:
        k = parsers.normalize_oui_prefix(hexdigits[:9] + "0/36")
        if k:
            keys.append(k)
    if len(hexdigits) >= 7:
        k = parsers.normalize_oui_prefix(hexdigits[:7] + "0/28")
        if k:
            keys.append(k)
    keys.append(":".join(hexdigits[i : i + 2] for i in range(0, 6, 2)))
    for key in keys:
        vendor = table.get(key)
        if vendor:
            return vendor
    return None


# ------------------------------------------------------------- blocklists ---


def load_blocklist(name: str) -> set[str]:
    """Lowercase, trailing-dot-free domains of a list feed (empty set if unknown/missing)."""
    spec = FEEDS.get(name)
    if spec is None or spec.kind not in DOMAIN_KINDS or spec.parser is None:
        logger.debug("load_blocklist(%r): not a domain feed", name)
        return set()

    def loader(text: str) -> set[str]:
        return set(spec.parser(text))  # type: ignore[misc]

    return _cached(name, _path(name), loader, set)


def load_ipset(name: str) -> list[ipaddress.IPv4Network]:
    spec = FEEDS.get(name)
    if spec is None or spec.kind not in IP_KINDS or spec.parser is None:
        logger.debug("load_ipset(%r): not an ip feed", name)
        return []

    def loader(text: str) -> list[ipaddress.IPv4Network]:
        return list(spec.parser(text))  # type: ignore[misc]

    return _cached(name, _path(name), loader, list)


def iter_domain_feeds() -> Iterator[FeedSpec]:
    """Domain-type feeds in registry order (what the DNS policy can subscribe to)."""
    return (s for s in FEEDS.values() if s.kind in DOMAIN_KINDS)


# ------------------------------------------------------------- dashboard ---


def feed_status(conn: sqlite3.Connection) -> list[dict[str, Any]]:
    """One row per registered feed merging the DB record with on-disk reality, for the dashboard."""
    from homesoc.feeds import updater  # lazy to avoid the import cycle

    rows: dict[str, dict[str, Any]] = {}
    try:
        cur = conn.execute("SELECT * FROM feeds")
        cols = [d[0] for d in cur.description]
        for raw in cur.fetchall():
            rec = dict(zip(cols, tuple(raw)))
            rows[str(rec.get("name"))] = rec
    except sqlite3.Error as exc:
        logger.warning("feed_status: cannot read feeds table: %s", exc)
    out: list[dict[str, Any]] = []
    for spec in FEEDS.values():
        row = rows.get(spec.name)
        path = _path(spec.name)
        sig = _signature(path)

        def col(key: str, default: Any = None) -> Any:
            if row is None:
                return default
            value = row.get(key)
            return default if value is None else value

        enabled = bool(col("enabled", 1 if spec.enabled_default else 0))
        out.append(
            {
                "name": spec.name,
                "kind": spec.kind,
                "url": spec.url,
                "hours": spec.hours,
                "license_note": spec.license_note,
                "enabled": enabled,
                "status": col("status", "never"),
                "last_checked": col("last_checked"),
                "last_updated": col("last_updated"),
                "bytes": col("bytes"),
                "entries": col("entries"),
                "error": col("error"),
                "etag": col("etag"),
                "file_exists": sig is not None,
                "file_bytes": sig[1] if sig else 0,
                "stale": enabled and updater.is_stale(conn, spec.name, spec.hours),
            }
        )
    return out
