"""Pure parsers for feed/blocklist file formats.

Everything here treats its input as hostile: feed files are downloaded from
third parties and may contain junk, CRLF line endings, inline comments,
oversized lines or unexpected syntax. Each parser tolerates what it can and
silently drops the rest, so a single malformed line never poisons a list.
No parser touches the network, the database or the filesystem.
"""

from __future__ import annotations

import csv
import ipaddress
import io
import json
import logging
import re
from collections.abc import Iterator
from typing import Any
from urllib.parse import urlsplit

logger = logging.getLogger(__name__)

# Labels: letters, digits, hyphen and underscore (some trackers use "_" labels);
# punycode "xn--" labels are covered. Length limits follow RFC 1035.
_LABEL_RE = re.compile(r"^[a-z0-9_](?:[a-z0-9_-]{0,61}[a-z0-9_])?$")
_MAX_DOMAIN_LEN = 253

# Names that hosts files legitimately map to loopback; never blocklist material.
_HOSTS_NOISE = frozenset(
    {
        "localhost",
        "localhost.localdomain",
        "local",
        "broadcasthost",
        "ip6-localhost",
        "ip6-loopback",
        "ip6-localnet",
        "ip6-mcastprefix",
        "ip6-allnodes",
        "ip6-allrouters",
        "ip6-allhosts",
        "0.0.0.0",
    }
)

_COMMENT_PREFIXES = ("#", "!", ";", "//")


def _lines(text: str) -> Iterator[str]:
    """Yield trimmed, non-empty, non-comment lines regardless of line endings."""
    for raw in text.splitlines():
        line = raw.strip()
        if not line or line.startswith(_COMMENT_PREFIXES):
            continue
        yield line


def _strip_inline_comment(line: str) -> str:
    """Drop trailing '# ...' / '; ...' comments that many lists append to entries."""
    for marker in (" #", "\t#", " ;", "\t;"):
        idx = line.find(marker)
        if idx != -1:
            line = line[:idx]
    return line.strip()


def normalize_domain(value: str) -> str | None:
    """Return a lowercase, trailing-dot-free domain or None when the value is not one.

    Rejects single-label names, IP literals and anything with characters that
    could not be a DNS name, because those would never match a query anyway
    and some of them (spaces, slashes) indicate a mis-parsed line.
    """
    if not value:
        return None
    dom = value.strip().strip(".").lower()
    if not dom or len(dom) > _MAX_DOMAIN_LEN:
        return None
    if not dom.isascii():
        try:
            dom = dom.encode("idna").decode("ascii")
        except (UnicodeError, ValueError):
            return None
    labels = dom.split(".")
    if len(labels) < 2:
        return None
    if all(label.isdigit() for label in labels):
        return None
    for label in labels:
        if not _LABEL_RE.match(label):
            return None
    return dom


def _is_ip(token: str) -> bool:
    """True for IPv4/IPv6 literals, including scoped ones like fe80::1%lo0."""
    candidate = token.split("%", 1)[0]
    try:
        ipaddress.ip_address(candidate)
    except ValueError:
        return False
    return True


def parse_hosts(text: str) -> Iterator[str]:
    """Yield domains from hosts-file lines ("0.0.0.0 host [host ...]").

    IPv6 sink addresses (::, ::1) and scoped link-local addresses are accepted
    as the leading token; bare-domain lines are tolerated because a few
    "hostfile" feeds mix both styles.
    """
    seen: set[str] = set()
    for line in _lines(text):
        line = _strip_inline_comment(line)
        tokens = line.split()
        if not tokens:
            continue
        names = tokens[1:] if _is_ip(tokens[0]) else tokens[:1]
        for name in names:
            if name.lower() in _HOSTS_NOISE:
                continue
            dom = normalize_domain(name)
            if dom and dom not in seen:
                seen.add(dom)
                yield dom


def parse_domains(text: str) -> Iterator[str]:
    """Yield domains from a plain one-per-line list.

    Lenient on purpose: a "plain" list in the wild often carries stray
    hosts-style, wildcard or ABP lines, so those forms are unwrapped too.
    """
    seen: set[str] = set()
    for line in _lines(text):
        line = _strip_inline_comment(line)
        if line.startswith("@@"):
            continue
        if line.startswith("||"):
            dom = _adblock_domain(line)
        else:
            tokens = line.split()
            if not tokens:
                continue
            token = tokens[1] if (_is_ip(tokens[0]) and len(tokens) > 1) else tokens[0]
            if token.startswith("*."):
                token = token[2:]
            dom = normalize_domain(token)
        if dom and dom.lower() not in _HOSTS_NOISE and dom not in seen:
            seen.add(dom)
            yield dom


def _adblock_domain(rule: str) -> str | None:
    """Extract the domain from a DNS-level ABP rule ("||domain^" with optional $modifiers).

    Rules with paths, wildcards or regexes cannot be expressed as a DNS block
    and are ignored rather than approximated.
    """
    if not rule.startswith("||"):
        return None
    body = rule[2:]
    body = body.split("$", 1)[0]
    if body.endswith("^"):
        body = body[:-1]
    elif body.endswith("|"):
        body = body[:-1]
    if not body or any(ch in body for ch in "/*^|?=&"):
        return None
    return normalize_domain(body)


def parse_adblock(text: str) -> Iterator[str]:
    """Yield domains from an Adblock-Plus-style list (oisd, AdGuard DNS filter).

    Exceptions ("@@..."), cosmetic rules ("##"), regex rules and rules with
    paths are skipped. Plain-domain and hosts-style lines that appear in
    mixed lists are accepted.
    """
    seen: set[str] = set()
    for line in _lines(text):
        if line.startswith("[") or line.startswith("@@"):
            continue
        if "##" in line or "#@#" in line or "#?#" in line:
            continue
        if line.startswith("/") and line.endswith("/"):
            continue
        line = _strip_inline_comment(line)
        if line.startswith("||"):
            dom = _adblock_domain(line)
        elif line.startswith("|") or "$" in line or "*" in line or "/" in line:
            dom = None
        else:
            tokens = line.split()
            if not tokens:
                continue
            token = tokens[1] if (_is_ip(tokens[0]) and len(tokens) > 1) else tokens[0]
            dom = normalize_domain(token)
        if dom and dom not in _HOSTS_NOISE and dom not in seen:
            seen.add(dom)
            yield dom


def parse_wildcard(text: str) -> Iterator[str]:
    """Yield domains from a "*.domain" wildcard list (hagezi onlydomains style).

    The wildcard prefix is dropped; the DNS policy applies suffix matching to
    every blocklist entry anyway, so "*.x.com" and "x.com" mean the same thing.
    """
    seen: set[str] = set()
    for line in _lines(text):
        line = _strip_inline_comment(line)
        token = line.split()[0] if line.split() else ""
        if token.startswith("*."):
            token = token[2:]
        elif token.startswith("."):
            token = token[1:]
        dom = normalize_domain(token)
        if dom and dom not in seen:
            seen.add(dom)
            yield dom


def parse_urls(text: str) -> Iterator[str]:
    """Yield the host part of URL lines (OpenPhish). IP-literal hosts are dropped.

    A DNS filter can only act on names, so a phishing URL served straight from
    an IP address has no useful representation here.
    """
    seen: set[str] = set()
    for line in _lines(text):
        line = _strip_inline_comment(line).split()[0] if line.split() else ""
        if "://" not in line:
            line = "http://" + line
        try:
            host = urlsplit(line).hostname
        except ValueError:
            continue
        if not host or _is_ip(host):
            continue
        dom = normalize_domain(host)
        if dom and dom not in seen:
            seen.add(dom)
            yield dom


def parse_ips(text: str) -> Iterator[ipaddress.IPv4Network]:
    """Yield IPv4 networks from a DROP-style list ("1.2.3.0/24 ; SBL123") or plain IPs.

    Only IPv4 is kept because the discovery/exposure code compares IPv4
    addresses; IPv6 entries are logged at debug level and skipped.
    """
    seen: set[ipaddress.IPv4Network] = set()
    for line in _lines(text):
        line = _strip_inline_comment(line)
        token = line.split()[0] if line.split() else ""
        token = token.split(";", 1)[0].split("#", 1)[0].strip()
        if not token:
            continue
        try:
            net = ipaddress.ip_network(token, strict=False)
        except ValueError:
            continue
        if not isinstance(net, ipaddress.IPv4Network):
            logger.debug("skipping non-IPv4 entry %s", token)
            continue
        if net not in seen:
            seen.add(net)
            yield net


def parse_feodo(json_text: str) -> Iterator[ipaddress.IPv4Network]:
    """Yield /32 networks from the Feodo Tracker JSON blocklist.

    The feed is a JSON array of objects with an "ip_address" key; anything
    else in the object is informational and ignored.
    """
    try:
        data = json.loads(json_text)
    except (ValueError, TypeError):
        logger.warning("feodo json unparsable")
        return
    if not isinstance(data, list):
        return
    seen: set[ipaddress.IPv4Network] = set()
    for item in data:
        if not isinstance(item, dict):
            continue
        ip = item.get("ip_address")
        if not isinstance(ip, str):
            continue
        try:
            net = ipaddress.ip_network(ip.strip(), strict=False)
        except ValueError:
            continue
        if isinstance(net, ipaddress.IPv4Network) and net not in seen:
            seen.add(net)
            yield net


_KEV_FIELDS = (
    "cveID",
    "vendorProject",
    "product",
    "vulnerabilityName",
    "dateAdded",
    "shortDescription",
    "requiredAction",
    "dueDate",
    "knownRansomwareCampaignUse",
    "notes",
    "cwes",
)


def kev_document(json_text: str) -> tuple[dict[str, Any], list[dict[str, Any]]]:
    """Split a KEV catalog into (metadata, entries) so loaders get the header for free.

    Metadata keys: title, catalogVersion, dateReleased, count. Entries are
    normalized to the documented KEV field names with string defaults, which
    lets callers index them without per-key None checks.
    """
    try:
        data = json.loads(json_text)
    except (ValueError, TypeError):
        logger.warning("KEV json unparsable")
        return {}, []
    if not isinstance(data, dict):
        return {}, []
    meta = {
        "title": str(data.get("title") or ""),
        "catalogVersion": str(data.get("catalogVersion") or ""),
        "dateReleased": str(data.get("dateReleased") or ""),
        "count": data.get("count") if isinstance(data.get("count"), int) else 0,
    }
    entries: list[dict[str, Any]] = []
    raw = data.get("vulnerabilities")
    if not isinstance(raw, list):
        return meta, entries
    for item in raw:
        if not isinstance(item, dict):
            continue
        cve = item.get("cveID")
        if not isinstance(cve, str) or not cve.upper().startswith("CVE-"):
            continue
        entry: dict[str, Any] = {}
        for key in _KEV_FIELDS:
            value = item.get(key)
            if key == "cwes":
                entry[key] = [str(c) for c in value] if isinstance(value, list) else []
            else:
                entry[key] = str(value) if value is not None else ""
        entry["cveID"] = cve.strip().upper()
        entries.append(entry)
    return meta, entries


def parse_kev(json_text: str) -> list[dict[str, Any]]:
    """Return the KEV vulnerability entries as a list of normalized dicts."""
    return kev_document(json_text)[1]


def parse_epss(csv_text: str) -> dict[str, float]:
    """Return {CVE: epss score} from the EPSS CSV (leading '#model_version' line tolerated).

    Percentile is discarded: the matcher only thresholds on the probability.
    """
    scores: dict[str, float] = {}
    body = "\n".join(line for line in csv_text.splitlines() if not line.startswith("#"))
    reader = csv.reader(io.StringIO(body))
    for row in reader:
        if len(row) < 2:
            continue
        cve = row[0].strip().upper()
        if not cve.startswith("CVE-"):
            continue
        try:
            score = float(row[1].strip())
        except ValueError:
            continue
        if 0.0 <= score <= 1.0:
            scores[cve] = score
    return scores


_HEX_RE = re.compile(r"^[0-9A-F]{2}(?::[0-9A-F]{2}){2,5}$")


def normalize_oui_prefix(prefix: str) -> str | None:
    """Canonicalize a Wireshark manuf prefix to "AA:BB:CC" or "AA:BB:CC:D0/28" / ".../36".

    Wireshark writes /24 prefixes bare and longer ones with an explicit mask;
    lookup_vendor builds keys in exactly this shape, so both sides agree.
    """
    prefix = prefix.strip().upper()
    if not prefix:
        return None
    bits = 24
    if "/" in prefix:
        prefix, mask = prefix.split("/", 1)
        try:
            bits = int(mask)
        except ValueError:
            return None
    prefix = prefix.replace("-", ":").replace(".", "")
    if ":" not in prefix and len(prefix) in (6, 8, 10, 12):
        prefix = ":".join(prefix[i : i + 2] for i in range(0, len(prefix), 2))
    if not _HEX_RE.match(prefix):
        return None
    hexdigits = prefix.replace(":", "")
    if bits == 24:
        return ":".join(hexdigits[i : i + 2] for i in range(0, 6, 2))
    if bits not in (28, 36):
        return None
    nibbles = bits // 4  # 7 for /28, 9 for /36
    if len(hexdigits) < nibbles:
        return None
    kept = hexdigits[:nibbles]
    if len(kept) % 2:
        kept += "0"  # pad the half byte so the key is still whole octets
    return ":".join(kept[i : i + 2] for i in range(0, len(kept), 2)) + f"/{bits}"


def parse_oui(text: str) -> dict[str, str]:
    """Return {normalized prefix: vendor} from the Wireshark "manuf" file.

    Columns are tab-separated: prefix, short name, long name. The long name is
    preferred because the short name is an abbreviation like "AppleInc".
    """
    table: dict[str, str] = {}
    for line in _lines(text):
        parts = [p.strip() for p in line.split("\t")]
        if len(parts) < 2:
            parts = line.split(None, 2)
            if len(parts) < 2:
                continue
        key = normalize_oui_prefix(parts[0])
        if key is None:
            continue
        vendor = parts[2] if len(parts) > 2 and parts[2] else parts[1]
        vendor = _strip_inline_comment(vendor).strip()
        if vendor:
            table[key] = vendor
    return table
