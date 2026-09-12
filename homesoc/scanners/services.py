"""Rules that turn a device's open services into ``NET-SVC-*`` findings.

The rules live apart from ``ports.py`` so they can be unit-tested against
hand-built service lists and so the vulnerability matcher and dashboard can
share the device-kind heuristics.  Everything here is pure: no I/O, no DB.

Device kind matters because the same open port means different things on
different boxes - SMB on a Windows PC is normal, SMB on a camera is not, and a
router's plain-HTTP admin page deserves a nudge while a laptop's dev server
does not.  We only have vendor strings, hostnames and banners to go on, so the
heuristics are keyword tables rather than anything clever.
"""

from __future__ import annotations

import logging
import re
from typing import Any, Iterable

from homesoc.models import FindingDraft

logger = logging.getLogger(__name__)

__all__ = ["evaluate", "device_kind", "is_fragile", "wants_gentle", "KIND_KEYWORDS"]

# Keyword tables are lower-case tokens matched against vendor + hostname on
# token boundaries (so "nas" does not match "nasa" and "cam" does not match
# "camry").  Order matters: the first kind whose keyword matches wins, so the
# more specific families (printer/camera) come before the catch-all "iot".
KIND_KEYWORDS: list[tuple[str, tuple[str, ...]]] = [
    ("printer", ("epson", "brother", "canon", "hewlett", "hp", "lexmark", "xerox",
                 "kyocera", "ricoh", "konica", "printer", "jetdirect")),
    ("camera", ("hikvision", "dahua", "axis", "reolink", "wyze", "arlo", "amcrest", "foscam",
                "unifi video", "nest cam", "ring", "eufy", "camera", "ipcam", "cam")),
    ("router", ("nokia", "arris", "sagemcom", "technicolor", "netgear", "tp-link", "tplink", "asus",
                "ubiquiti", "mikrotik", "linksys", "eero", "d-link", "zyxel", "actiontec", "pace",
                "humax", "dsl", "modem", "gateway", "router", "fritz", "openwrt", "calix")),
    ("nas", ("synology", "qnap", "western digital", "wd my", "diskstation", "nas", "truenas", "freenas")),
    ("android", ("android", "galaxy", "pixel", "oneplus", "motorola")),
    ("iot", ("sonos", "philips", "hue", "signify", "nest", "ecobee", "roku", "tuya", "espressif",
             "shelly", "amazon", "google", "wemo", "belkin", "lifx", "xiaomi", "wiz", "chromecast",
             "smartthings", "samsung electronics", "lg electronics", "vizio", "tcl", "hisense",
             "raspberry", "particle", "wyzecam", "echo", "thermostat", "doorbell", "smart", "iot",
             "tasmota", "esp-", "esp_")),
    ("apple", ("apple", "macbook", "iphone", "ipad", "imac", "mac-", "watch", "appletv", "apple-tv")),
    ("windows", ("microsoft", "desktop-", "laptop-", "win-", "surface", "xbox")),
    ("linux", ("linux", "ubuntu", "debian", "fedora", "proxmox", "docker")),
]


def _keyword_regex(keyword: str) -> re.Pattern[str]:
    """Token-boundary match; a keyword ending in '-'/'_' is an open prefix (e.g. "desktop-")."""
    pat = re.escape(keyword)
    if keyword[0].isalnum():
        pat = r"(?<![a-z0-9])" + pat
    if keyword[-1].isalnum():
        pat = pat + r"(?![a-z0-9])"
    return re.compile(pat)


_KIND_PATTERNS: list[tuple[str, list[re.Pattern[str]]]] = [
    (kind, [_keyword_regex(w) for w in words]) for kind, words in KIND_KEYWORDS
]

# Port-based fallbacks used only when vendor/hostname say nothing.
_PORT_KIND_HINTS: list[tuple[str, frozenset[int]]] = [
    ("printer", frozenset({9100, 631, 515})),
    ("camera", frozenset({554, 8554, 37777})),
]

_DB_PORTS: dict[int, str] = {
    1433: "ms-sql-s", 1521: "oracle", 3306: "mysql", 3307: "mysql", 5432: "postgresql",
    5984: "couchdb", 6379: "redis", 9200: "elasticsearch", 9300: "elasticsearch",
    11211: "memcached", 27017: "mongodb", 27018: "mongodb", 28017: "mongodb", 8086: "influxdb",
    7474: "neo4j", 9042: "cassandra",
}
_DB_NAMES = frozenset({"ms-sql-s", "oracle", "mysql", "mariadb", "postgresql", "couchdb", "redis",
                       "elasticsearch", "memcached", "mongodb", "influxdb", "neo4j", "cassandra",
                       "oracle-tns", "wap-wsp"})

_MODEL_RE = re.compile(
    r"\b(epson|brother|canon|hp|hewlett|lexmark|xerox|kyocera|synology|qnap|hikvision|dahua|axis|"
    r"reolink|sonos|roku|philips|samsung|lg|sony|tp-link|netgear|asus|ubiquiti|nokia|arris|"
    r"technicolor|sagemcom|mikrotik|d-link|zyxel|linksys|apple|raspberry)\b|"
    r"\b[a-z]{1,4}-?\d{3,5}[a-z]{0,3}\b|\bmodel\b",
    re.IGNORECASE,
)

# The SSH thresholds are conservative: OpenSSH < 8.0 (2019) and Dropbear
# < 2020.80 both predate several widely-published auth bypasses.
_OPENSSH_MIN = (8, 0)
_DROPBEAR_MIN = (2020, 80)


# --------------------------------------------------------------------------- helpers

def _attr(obj: Any, name: str, default: Any = None) -> Any:
    """Read an attribute or dict key; scanners pass dataclasses, tests may pass dicts."""
    if isinstance(obj, dict):
        return obj.get(name, default)
    return getattr(obj, name, default)


def _text(obj: Any, *names: str) -> str:
    return " ".join(str(_attr(obj, n) or "") for n in names).lower()


def _open(services: Iterable[Any]) -> list[Any]:
    return [s for s in services if (_attr(s, "state") or "open") == "open"]


def _version_tuple(version: str | None) -> tuple[int, ...] | None:
    if not version:
        return None
    m = re.search(r"(\d+)(?:\.(\d+))?(?:\.(\d+))?", version)
    if not m:
        return None
    return tuple(int(g) for g in m.groups() if g is not None)


def _subject(device: Any, port: int | None = None) -> str:
    mac = _attr(device, "mac") or f"ip:{_attr(device, 'ip')}"
    return f"device:{mac}" if port is None else f"device:{mac}:{port}"


def _draft(fid: str, device: Any, svc: Any | None, **extra: Any) -> FindingDraft:
    port = _attr(svc, "port") if svc is not None else None
    evidence: dict[str, Any] = {"ip": _attr(device, "ip"), "hostname": _attr(device, "hostname"),
                                "vendor": _attr(device, "vendor")}
    if svc is not None:
        evidence.update({
            "port": port,
            "proto": _attr(svc, "proto") or "tcp",
            "service": _attr(svc, "name"),
            "product": _attr(svc, "product"),
            "version": _attr(svc, "version"),
            "extrainfo": _attr(svc, "extrainfo"),
        })
    evidence.update(extra)
    return FindingDraft(finding_id=fid, subject=_subject(device, port), evidence=evidence,
                        device_id=_attr(device, "id"))


# --------------------------------------------------------------------------- device kind

def device_kind(device: Any, services: Iterable[Any] = ()) -> str:
    """Best-effort family of a device: router/printer/camera/nas/iot/apple/windows/... or "unknown".

    An explicit ``device.kind`` set by discovery (e.g. "router" for the
    gateway) wins; "randomized" is only a MAC hint and is not a kind.
    """
    explicit = (_attr(device, "kind") or "").lower()
    if explicit and explicit not in ("randomized", "unknown"):
        return explicit
    hay = _text(device, "vendor", "hostname", "nickname")
    open_svcs = _open(services)
    for kind, patterns in _KIND_PATTERNS:
        if any(p.search(hay) for p in patterns):
            return kind
    banners = " ".join(_text(s, "product", "extrainfo") for s in open_svcs)
    if "windows" in banners or "microsoft" in banners:
        return "windows"
    for kind, patterns in _KIND_PATTERNS:
        if kind in ("printer", "camera", "router", "nas") and any(p.search(banners) for p in patterns):
            return kind
    open_ports = {_attr(s, "port") for s in open_svcs}
    for kind, ports in _PORT_KIND_HINTS:
        if open_ports & ports:
            return kind
    if {135, 445} <= open_ports:
        return "windows"
    return "unknown"


def is_fragile(device: Any, fragile_vendors: Iterable[str]) -> bool:
    """True when the vendor/hostname matches ``network.fragile_vendors`` (case-insensitive, token-bounded)."""
    hay = _text(device, "vendor", "hostname")
    return any(_keyword_regex(v.lower()).search(hay) for v in fragile_vendors if v)


def wants_gentle(device: Any, fragile_vendors: Iterable[str], services: Iterable[Any] = ()) -> bool:
    """Gentle profile for fragile vendors plus anything that smells like a printer/camera/IoT.

    Cheap embedded stacks fall over under version probes; a missed banner is
    far better than a printer that needs a power cycle.
    """
    if is_fragile(device, fragile_vendors):
        return True
    return device_kind(device, services) in ("printer", "camera", "iot")


def _is_windows(device: Any, services: list[Any]) -> bool:
    return device_kind(device, services) == "windows"


# --------------------------------------------------------------------------- rules

def _rule_telnet(device, svc):
    if _attr(svc, "port") == 23 or _attr(svc, "name") == "telnet":
        return _draft("NET-SVC-001", device, svc)
    return None


def _rule_ftp(device, svc):
    if _attr(svc, "port") == 21 or _attr(svc, "name") == "ftp":
        return _draft("NET-SVC-002", device, svc)
    return None


def _rule_rdp_vnc(device, svc):
    port = _attr(svc, "port") or 0
    name = (_attr(svc, "name") or "").lower()
    if port == 3389 or name in ("ms-wbt-server", "rdp"):
        return _draft("NET-SVC-004", device, svc, protocol="rdp")
    if 5900 <= port <= 5909 or name.startswith("vnc"):
        return _draft("NET-SVC-004", device, svc, protocol="vnc")
    return None


def _rule_upnp(device, svc):
    port = _attr(svc, "port") or 0
    name = (_attr(svc, "name") or "").lower()
    banner = _text(svc, "product", "extrainfo")
    if port == 1900 or name == "upnp" or "upnp" in banner or "miniupnp" in banner:
        return _draft("NET-SVC-006", device, svc)
    return None


def _rule_database(device, svc):
    port = _attr(svc, "port") or 0
    name = (_attr(svc, "name") or "").lower()
    if port in _DB_PORTS or name in _DB_NAMES:
        return _draft("NET-SVC-007", device, svc, database=_DB_PORTS.get(port, name))
    return None


def _rule_printer(device, svc):
    port = _attr(svc, "port") or 0
    name = (_attr(svc, "name") or "").lower()
    if port == 9100 or name == "jetdirect":
        return _draft("NET-SVC-008", device, svc, protocol="raw9100")
    if port == 631 or name == "ipp":
        return _draft("NET-SVC-008", device, svc, protocol="ipp")
    return None


def _rule_snmp(device, svc):
    # Only meaningful when nmap actually probed SNMP and saw the community
    # string; a TCP connect scan never will, so this stays quiet in practice.
    if (_attr(svc, "name") or "").lower() != "snmp":
        return None
    if "public" in _text(svc, "product", "version", "extrainfo"):
        return _draft("NET-SVC-009", device, svc, community="public")
    return None


def _rule_rtsp(device, svc):
    port = _attr(svc, "port") or 0
    if port in (554, 8554) or (_attr(svc, "name") or "").lower() == "rtsp":
        return _draft("NET-SVC-010", device, svc)
    return None


def _rule_ssh_outdated(device, svc):
    if (_attr(svc, "name") or "").lower() != "ssh":
        return None
    product = (_attr(svc, "product") or "").lower()
    ver = _version_tuple(_attr(svc, "version"))
    if ver is None:
        return None
    if "openssh" in product and ver < _OPENSSH_MIN:
        return _draft("NET-SVC-011", device, svc, minimum="OpenSSH 8.0")
    if "dropbear" in product and ver < _DROPBEAR_MIN:
        return _draft("NET-SVC-011", device, svc, minimum="Dropbear 2020.80")
    return None


_PER_PORT_RULES = (
    _rule_telnet, _rule_ftp, _rule_rdp_vnc, _rule_upnp, _rule_database,
    _rule_printer, _rule_snmp, _rule_rtsp, _rule_ssh_outdated,
)


def _rule_smb(device, open_svcs):
    if _is_windows(device, open_svcs):
        return []
    out = []
    for svc in open_svcs:
        port = _attr(svc, "port")
        name = (_attr(svc, "name") or "").lower()
        if port in (139, 445) or name in ("microsoft-ds", "netbios-ssn", "smb"):
            out.append(_draft("NET-SVC-003", device, svc, device_kind=device_kind(device, open_svcs)))
    return out


def _rule_http_no_https(device, open_svcs):
    kind = device_kind(device, open_svcs)
    if kind not in ("router", "iot", "printer", "camera", "nas"):
        return []
    has_tls = any(
        (_attr(s, "tunnel") or "").lower() == "ssl" or _attr(s, "port") in (443, 8443)
        or (_attr(s, "name") or "").lower() in ("https", "https-alt", "ssl/http")
        for s in open_svcs
    )
    if has_tls:
        return []
    out = []
    for svc in open_svcs:
        name = (_attr(svc, "name") or ("http" if _attr(svc, "port") in (80, 8080, 8000) else "")).lower()
        plain_http = name.startswith("http") and not name.startswith("https") and (_attr(svc, "tunnel") or "").lower() != "ssl"
        if plain_http:
            out.append(_draft("NET-SVC-005", device, svc, device_kind=kind))
    return out


def _rule_model_exposed(device, open_svcs):
    hits = []
    for svc in open_svcs:
        product = _attr(svc, "product") or ""
        extra = _attr(svc, "extrainfo") or ""
        if not (product or extra):
            continue
        blob = f"{product} {extra}"
        if _MODEL_RE.search(blob):
            hits.append({"port": _attr(svc, "port"), "banner": blob.strip()[:120]})
    if not hits:
        return []
    return [_draft("NET-SVC-012", device, None, exposed=hits)]


def evaluate(device: Any, services: Iterable[Any]) -> list[FindingDraft]:
    """Apply every NET-SVC rule (SPEC section 9) to one device's services.

    Per-port rules emit ``device:<mac>:<port>`` subjects so the findings engine
    dedupes per service; device-wide rules (model exposure) use ``device:<mac>``.
    Closed services are ignored - they are kept in the DB only for history.
    """
    svcs = list(services)
    open_svcs = _open(svcs)
    drafts: list[FindingDraft] = []
    for svc in open_svcs:
        for rule in _PER_PORT_RULES:
            try:
                d = rule(device, svc)
            except Exception:  # a bad banner must never abort the whole evaluation
                logger.exception("service rule %s failed", rule.__name__)
                continue
            if d is not None:
                drafts.append(d)
    drafts.extend(_rule_smb(device, open_svcs))
    drafts.extend(_rule_http_no_https(device, open_svcs))
    drafts.extend(_rule_model_exposed(device, open_svcs))
    return drafts
