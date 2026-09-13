"""Configuration: TOML file, deep-merged over defaults, then over dashboard overrides.

Three layers, lowest priority first:

1. ``DEFAULTS`` (the values in ``config.example.toml``),
2. ``config.toml`` (``paths.config_path()``), parsed with ``tomllib``,
3. rows in the SQLite ``settings`` table whose key is a dotted config key
   (``dns.enabled``) — what the dashboard's settings page writes.

The result is a tree of frozen dataclasses: frozen so a scan thread can never
see a half-updated config, dataclasses so ``cfg.dns.port`` is attribute access
with type hints rather than dictionary spelunking.
"""

from __future__ import annotations

import dataclasses
import json
import logging
import sqlite3
import tomllib
from dataclasses import dataclass, field, fields
from pathlib import Path
from typing import Any

from homesoc import db, paths, util

logger = logging.getLogger(__name__)

# Text of config.example.toml. The file in the repository is generated from this
# constant (write_example) so the two can never drift apart.
EXAMPLE_TOML = '''# Home SOC configuration. Copy to config.toml (python -m homesoc init does this).
# Every key is listed with its default. Storage timestamps are always UTC ISO-8601.

[general]
name = "Home SOC"
timezone = "local"                 # display only; storage is UTC ISO-8601
log_level = "INFO"

[web]
host = "127.0.0.1"                 # set 0.0.0.0 to reach the dashboard from other devices (then set token!)
port = 8787
token = ""                         # if non-empty, required as ?token= or X-Token header / login cookie
refresh_seconds = 15

[network]
cidr = "auto"                      # "auto" = the /24 of the default interface, or e.g. "192.168.1.0/24"
gateway = "auto"
exclude = []                       # IPs never to port-scan (fragile devices)
fragile_vendors = ["Sonos", "Philips", "Hue", "Ring", "Nest", "Ecobee", "Roku", "Epson", "Brother", "Canon", "HP"]
                                   # devices whose vendor matches are scanned with the gentle profile only
discovery_ports = [80, 443, 22, 445, 139, 8080, 62078, 7000, 9100, 1900, 5353, 8443, 3389, 23, 21, 53]
discovery_threads = 128
discovery_timeout = 0.4

[scan]
use_nmap = true                    # falls back to the python scanner when nmap is missing
nmap_top_ports = 100
nmap_timing = "T3"                 # never faster than T3 on home networks
version_detection = true
gentle_top_ports = 25              # for fragile devices
per_host_timeout_sec = 180
max_parallel_hosts = 3
scan_gateway = true

[host]
posture = true
persistence_baseline = true        # alert on NEW autostart entries after the first baseline
files_check = true                 # hash new files in Downloads (last 24h) and look them up (VirusTotal key required)
files_dirs = ["~/Downloads"]

[vulns]
kev = true
nvd_enrich = true                  # per-service NVD 2.0 lookups, rate-limited (5 req / 30 s without key)
nvd_api_key = ""
epss = true
min_cvss_report = 7.0

[feeds]
enabled = true
kev_hours = 6
epss_hours = 24
oui_hours = 168
blocklists_hours = 12
threatintel_hours = 6
max_download_mb = 64

[dns]
enabled = false                    # turn on to run the LAN-wide resolver
listen = "0.0.0.0"
port = 53
upstreams = ["1.1.1.2", "9.9.9.9"] # UDP upstreams; 1.1.1.2 = Cloudflare malware-blocking, 9.9.9.9 = Quad9
doh_upstream = "https://cloudflare-dns.com/dns-query"   # used when udp upstreams fail; "" disables
block_mode = "null"                # "null" -> 0.0.0.0 / :: with TTL 60 ; "nxdomain"
cache_max_entries = 20000
lists = ["oisd_small", "hagezi_pro", "urlhaus", "threatfox", "phishing_army", "openphish"]   # names from feeds registry
log_queries = true
log_retention_days = 14
virustotal_api_key = ""
virustotal_daily_budget = 400      # free tier is 500/day, 4/min; keep headroom
urlhaus_auth_key = ""              # optional abuse.ch Auth-Key for URLhaus reputation lookups
reputation_min_malicious_votes = 2
reputation_ttl_hours = 72

[notify]
min_severity = "high"              # notify on new findings at/above this
ntfy_url = ""                      # e.g. https://ntfy.sh/your-secret-topic
discord_webhook = ""
webhook_url = ""                   # generic JSON POST
windows_toast = true
digest_hour = 8                    # daily digest local hour (-1 disables)

[schedule]
discovery_minutes = 10
services_hours = 24
host_hours = 6
exposure_hours = 12
feeds_hours = 6

[lens]                             # point your phone at a device (see docs/LENS_SETUP.md)
enabled = false                    # master switch; when false /lens and /api/lens/* return 404
require_https = true               # refuse to serve Lens over plain HTTP (except from localhost)
tag_learning = true                # allow unknown codes to be bound to a device from the phone
allow_actions = false              # when true, a paired phone may trigger a rescan / acknowledge a finding
token_ttl_days = 90                # paired-phone tokens expire after this; 0 = never
max_tokens = 10                    # how many phones may be paired at once
'''

# Parsed once at import: DEFAULTS is the single source of truth for keys and types.
DEFAULTS: dict[str, dict[str, Any]] = tomllib.loads(EXAMPLE_TOML)


# ------------------------------------------------------------------ sections


@dataclass(frozen=True)
class General:
    name: str = "Home SOC"
    timezone: str = "local"
    log_level: str = "INFO"


@dataclass(frozen=True)
class Web:
    host: str = "127.0.0.1"
    port: int = 8787
    token: str = ""
    refresh_seconds: int = 15

    @property
    def exposed(self) -> bool:
        """True when the dashboard listens beyond loopback — the SOC-SYS-003 condition when no token is set."""
        return self.host not in ("127.0.0.1", "localhost", "::1")


@dataclass(frozen=True)
class Network:
    cidr: str = "auto"
    gateway: str = "auto"
    exclude: tuple[str, ...] = ()
    fragile_vendors: tuple[str, ...] = ()
    discovery_ports: tuple[int, ...] = ()
    discovery_threads: int = 128
    discovery_timeout: float = 0.4

    def resolved_cidr(self) -> str:
        return util.default_cidr() if self.cidr.strip().lower() == "auto" else self.cidr.strip()

    def resolved_gateway(self) -> str:
        return util.default_gateway() if self.gateway.strip().lower() == "auto" else self.gateway.strip()

    def is_excluded(self, ip: str) -> bool:
        return ip in self.exclude

    def is_fragile_vendor(self, vendor: str | None) -> bool:
        if not vendor:
            return False
        low = vendor.lower()
        return any(v.lower() in low for v in self.fragile_vendors)


@dataclass(frozen=True)
class Scan:
    use_nmap: bool = True
    nmap_top_ports: int = 100
    nmap_timing: str = "T3"
    version_detection: bool = True
    gentle_top_ports: int = 25
    per_host_timeout_sec: int = 180
    max_parallel_hosts: int = 3
    scan_gateway: bool = True


@dataclass(frozen=True)
class Host:
    posture: bool = True
    persistence_baseline: bool = True
    files_check: bool = True
    files_dirs: tuple[str, ...] = ("~/Downloads",)


@dataclass(frozen=True)
class Vulns:
    kev: bool = True
    nvd_enrich: bool = True
    nvd_api_key: str = ""
    epss: bool = True
    min_cvss_report: float = 7.0


@dataclass(frozen=True)
class Feeds:
    enabled: bool = True
    kev_hours: int = 6
    epss_hours: int = 24
    oui_hours: int = 168
    blocklists_hours: int = 12
    threatintel_hours: int = 6
    max_download_mb: int = 64


@dataclass(frozen=True)
class Dns:
    enabled: bool = False
    listen: str = "0.0.0.0"
    port: int = 53
    upstreams: tuple[str, ...] = ("1.1.1.2", "9.9.9.9")
    doh_upstream: str = "https://cloudflare-dns.com/dns-query"
    block_mode: str = "null"
    cache_max_entries: int = 20000
    lists: tuple[str, ...] = ()
    log_queries: bool = True
    log_retention_days: int = 14
    virustotal_api_key: str = ""
    virustotal_daily_budget: int = 400
    urlhaus_auth_key: str = ""  # SPEC-GAP: not in the spec's TOML; dnsfilter.reputation reads it
    reputation_min_malicious_votes: int = 2
    reputation_ttl_hours: int = 72


@dataclass(frozen=True)
class Notify:
    min_severity: str = "high"
    ntfy_url: str = ""
    discord_webhook: str = ""
    webhook_url: str = ""
    windows_toast: bool = True
    digest_hour: int = 8


@dataclass(frozen=True)
class Schedule:
    discovery_minutes: int = 10
    services_hours: int = 24
    host_hours: int = 6
    exposure_hours: int = 12
    feeds_hours: int = 6


@dataclass(frozen=True)
class Lens:
    """SPEC addendum B3. Off by default: Lens widens the attack surface from loopback
    to the whole LAN, so turning it on is a decision the owner makes deliberately."""

    enabled: bool = False
    require_https: bool = True
    tag_learning: bool = True
    allow_actions: bool = False
    token_ttl_days: int = 90
    max_tokens: int = 10

    @property
    def ttl_days(self) -> int:
        """Token lifetime, floored at 0 (= never expires); a negative value is a typo, not a policy."""
        return max(0, self.token_ttl_days)

    @property
    def token_ceiling(self) -> int:
        """How many phones may be paired; at least one, or pairing could never succeed."""
        return max(1, self.max_tokens)

    def insecure_on_lan(self, web: "Web", *, tls: bool = False) -> bool:
        """The SOC-LENS-001 condition: enabled, reachable off this machine, and no TLS."""
        return bool(self.enabled) and web.exposed and not tls


@dataclass(frozen=True)
class Config:
    general: General = field(default_factory=General)
    web: Web = field(default_factory=Web)
    network: Network = field(default_factory=Network)
    scan: Scan = field(default_factory=Scan)
    host: Host = field(default_factory=Host)
    vulns: Vulns = field(default_factory=Vulns)
    feeds: Feeds = field(default_factory=Feeds)
    dns: Dns = field(default_factory=Dns)
    notify: Notify = field(default_factory=Notify)
    schedule: Schedule = field(default_factory=Schedule)
    lens: Lens = field(default_factory=Lens)
    source_path: str | None = None

    def get(self, dotted: str) -> Any:
        """``cfg.get("dns.port")`` for code that works with key names (settings page, CLI)."""
        section, _, key = dotted.partition(".")
        return getattr(getattr(self, section), key)

    def to_dict(self) -> dict[str, dict[str, Any]]:
        out: dict[str, dict[str, Any]] = {}
        for section in SECTIONS:
            values = dataclasses.asdict(getattr(self, section))
            out[section] = {k: (list(v) if isinstance(v, tuple) else v) for k, v in values.items()}
        return out

    def flat(self) -> dict[str, Any]:
        return {f"{s}.{k}": v for s, sec in self.to_dict().items() for k, v in sec.items()}


SECTION_TYPES: dict[str, type] = {
    "general": General,
    "web": Web,
    "network": Network,
    "scan": Scan,
    "host": Host,
    "vulns": Vulns,
    "feeds": Feeds,
    "dns": Dns,
    "notify": Notify,
    "schedule": Schedule,
    "lens": Lens,
}
SECTIONS: tuple[str, ...] = tuple(SECTION_TYPES)

# Keys that hold secrets: never echoed in logs, exports or the support bundle.
SECRET_KEYS: frozenset[str] = frozenset({
    "web.token", "vulns.nvd_api_key", "dns.virustotal_api_key", "dns.urlhaus_auth_key",
    # Webhook URLs embed the credential (Discord token, ntfy secret topic), so they are secrets too.
    "notify.ntfy_url", "notify.discord_webhook", "notify.webhook_url",
})


# ----------------------------------------------------------------- loading


def load(conn: sqlite3.Connection | None = None, path: Path | None = None) -> Config:
    """Build the effective Config (defaults < config.toml < settings-table overrides)."""
    merged: dict[str, dict[str, Any]] = {s: dict(v) for s, v in DEFAULTS.items()}
    cfg_path = path or paths.config_path()
    file_data = _read_toml(cfg_path)
    _deep_merge(merged, file_data, origin=str(cfg_path))
    if conn is not None:
        _deep_merge(merged, _overrides_from_db(conn), origin="settings table")
    return build(merged, source_path=str(cfg_path) if file_data else None)


def build(data: dict[str, dict[str, Any]], source_path: str | None = None) -> Config:
    """Turn a merged mapping into dataclasses, coercing every value to the DEFAULTS type."""
    kwargs: dict[str, Any] = {}
    for section, cls in SECTION_TYPES.items():
        values: dict[str, Any] = {}
        section_data = data.get(section, {}) or {}
        for f in fields(cls):
            default = DEFAULTS[section][f.name]
            raw = section_data.get(f.name, default)
            values[f.name] = coerce(f"{section}.{f.name}", raw)
        kwargs[section] = cls(**values)
    return Config(source_path=source_path, **kwargs)


def with_overrides(cfg: Config, overrides: dict[str, Any]) -> Config:
    """Return a copy with dotted keys replaced — used by ``dns --port`` / ``serve --host``."""
    data = cfg.to_dict()
    for dotted, value in overrides.items():
        section, _, key = dotted.partition(".")
        if section not in data or key not in data[section]:
            raise KeyError(f"unknown config key {dotted!r}")
        data[section][key] = value
    return build(data, source_path=cfg.source_path)


def _read_toml(path: Path) -> dict[str, Any]:
    if not path.is_file():
        logger.debug("no config file at %s; using defaults", path)
        return {}
    try:
        with open(path, "rb") as handle:
            data = tomllib.load(handle)
    except (OSError, tomllib.TOMLDecodeError) as exc:
        logger.error("cannot read %s (%s); using defaults", path, exc)
        return {}
    return data if isinstance(data, dict) else {}


def _overrides_from_db(conn: sqlite3.Connection) -> dict[str, dict[str, Any]]:
    """Settings rows that name a real config key. Other packages keep unrelated state
    in the same table (``exposure.public_ip``, ``vt.budget.<date>``); those are ignored."""
    out: dict[str, dict[str, Any]] = {}
    try:
        rows = db.query(conn, "SELECT key, value FROM settings")
    except sqlite3.Error as exc:
        logger.warning("cannot read settings overrides: %s", exc)
        return out
    for row in rows:
        key = str(row["key"])
        if not is_config_key(key):
            continue
        section, _, name = key.partition(".")
        try:
            out.setdefault(section, {})[name] = coerce(key, str(row["value"]))
        except ValueError as exc:
            logger.warning("ignoring bad settings override %s=%r: %s", key, row["value"], exc)
    return out


def _deep_merge(base: dict[str, dict[str, Any]], incoming: dict[str, Any], origin: str) -> None:
    for section, values in incoming.items():
        if section not in base or not isinstance(values, dict):
            logger.warning("%s: unknown config section [%s] ignored", origin, section)
            continue
        for key, value in values.items():
            if key not in base[section]:
                logger.warning("%s: unknown key %s.%s ignored", origin, section, key)
                continue
            base[section][key] = value


# ----------------------------------------------------------------- coercion


def is_config_key(dotted: str) -> bool:
    section, _, key = dotted.partition(".")
    return section in DEFAULTS and key in DEFAULTS[section]


def coerce(dotted: str, raw: Any) -> Any:
    """Convert ``raw`` (TOML value or settings-table text) to the type of the default.

    Overrides arrive as strings from the dashboard, so ``"true"``, ``"8787"`` and
    ``"[80, 443]"`` / ``"80,443"`` must all round-trip. Raises ValueError when the
    value cannot represent the key's type — callers decide whether to warn or fail.
    """
    if not is_config_key(dotted):
        raise ValueError(f"unknown config key {dotted!r}")
    section, _, key = dotted.partition(".")
    default = DEFAULTS[section][key]
    if isinstance(default, bool):
        return _to_bool(raw, dotted)
    if isinstance(default, int):
        return _to_int(raw, dotted)
    if isinstance(default, float):
        return _to_float(raw, dotted)
    if isinstance(default, list):
        return _to_tuple(raw, dotted, default)
    if isinstance(default, str):
        if isinstance(raw, (list, tuple, dict)):
            raise ValueError(f"{dotted}: expected text")
        return "" if raw is None else str(raw)
    return raw


def _to_bool(raw: Any, dotted: str) -> bool:
    if isinstance(raw, bool):
        return raw
    if isinstance(raw, (int, float)):
        return bool(raw)
    text = str(raw).strip().lower()
    if text in ("1", "true", "yes", "on"):
        return True
    if text in ("0", "false", "no", "off", ""):
        return False
    raise ValueError(f"{dotted}: not a boolean: {raw!r}")


def _to_int(raw: Any, dotted: str) -> int:
    if isinstance(raw, bool):
        return int(raw)
    if isinstance(raw, int):
        return raw
    if isinstance(raw, float) and raw.is_integer():
        return int(raw)
    try:
        return int(str(raw).strip())
    except ValueError:
        raise ValueError(f"{dotted}: not an integer: {raw!r}") from None


def _to_float(raw: Any, dotted: str) -> float:
    if isinstance(raw, bool):
        return float(raw)
    if isinstance(raw, (int, float)):
        return float(raw)
    try:
        return float(str(raw).strip())
    except ValueError:
        raise ValueError(f"{dotted}: not a number: {raw!r}") from None


def _to_tuple(raw: Any, dotted: str, default: list[Any]) -> tuple[Any, ...]:
    if isinstance(raw, (list, tuple)):
        items = list(raw)
    elif raw is None:
        items = []
    else:
        text = str(raw).strip()
        if text.startswith("["):
            parsed = util.safe_json_loads(text, default=None)
            if not isinstance(parsed, list):
                raise ValueError(f"{dotted}: not a JSON list: {raw!r}")
            items = parsed
        else:
            items = [part.strip() for part in text.split(",") if part.strip()]
    element_is_int = bool(default) and isinstance(default[0], int) and not isinstance(default[0], bool)
    if element_is_int:
        return tuple(_to_int(item, dotted) for item in items)
    return tuple(str(item).strip() for item in items)


# ----------------------------------------------------------------- writing


def write_example(path: Path) -> None:
    """Write ``config.example.toml`` content (also used by ``init`` to seed config.toml)."""
    util.atomic_write_text(Path(path), EXAMPLE_TOML)


def set_override(conn: sqlite3.Connection, key: str, value: str) -> None:
    """Persist a dashboard override for a dotted key, validating type first so a typo
    never silently breaks the next config load."""
    normalized = coerce(key, value)  # raises ValueError for unknown key / bad value
    if isinstance(normalized, tuple):
        stored = json.dumps(list(normalized))
    elif isinstance(normalized, bool):
        stored = "true" if normalized else "false"
    else:
        stored = str(normalized)
    db.set_setting(conn, key, stored)
    logger.info("config override %s set%s", key, "" if key in SECRET_KEYS else f" to {stored!r}")
    if key == "lens.enabled" and normalized is False:
        # SPEC addendum B10: outstanding pairing codes are invalidated the moment Lens is
        # switched off, so a code left on a screen cannot pair a phone after the fact.
        cleared = db.lens_clear_pairing_codes(conn)
        if cleared:
            logger.info("lens disabled: invalidated %d outstanding pairing code(s)", cleared)


def clear_override(conn: sqlite3.Connection, key: str) -> None:
    db.delete_setting(conn, key)


def overrides(conn: sqlite3.Connection) -> dict[str, str]:
    """Current dashboard overrides (dotted key -> stored text)."""
    rows = db.query(conn, "SELECT key, value FROM settings ORDER BY key")
    return {str(r["key"]): str(r["value"]) for r in rows if is_config_key(str(r["key"]))}


def redacted(cfg: Config) -> dict[str, dict[str, Any]]:
    """Config as a dict with secrets masked — for the support bundle and logs."""
    out = cfg.to_dict()
    for dotted in SECRET_KEYS:
        section, _, key = dotted.partition(".")
        if out[section].get(key):
            out[section][key] = "***"
    return out


__all__ = [
    "EXAMPLE_TOML",
    "DEFAULTS",
    "SECTIONS",
    "SECRET_KEYS",
    "Config",
    "General",
    "Web",
    "Network",
    "Scan",
    "Host",
    "Vulns",
    "Feeds",
    "Dns",
    "Notify",
    "Schedule",
    "Lens",
    "load",
    "build",
    "with_overrides",
    "is_config_key",
    "coerce",
    "write_example",
    "set_override",
    "clear_override",
    "overrides",
    "redacted",
]
